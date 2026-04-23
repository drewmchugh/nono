//! nono-shim: universal command proxy for nono mediation.
//!
//! This binary is invoked in place of a real command (via a shim symlink in the
//! sandbox PATH). It operates in one of two modes:
//!
//! **Mediated mode** (command listed in `NONO_MEDIATED_COMMANDS`):
//! Forwards the invocation to the nono mediation server running in the
//! unsandboxed parent process, which applies policy and either returns a
//! configured response or execs the real binary.
//!
//! **Audit mode** (all other commands):
//! Sends a fire-and-forget audit event via datagram to the audit socket,
//! then resolves the real binary (skipping the shim directory) and `execve`s
//! it directly. The command runs inside the sandbox with no mediation overhead.
//!
//! Protocol (mediated mode): length-prefixed JSON over a Unix stream socket.
//!   Request:  u32 (big-endian length) || JSON {"command":..., "args":..., "stdin":...}
//!   Response: u32 (big-endian length) || JSON {"stdout":..., "stderr":..., "exit_code":...}
//!
//! The shim reads its own name from argv[0] to determine which command it represents.
//! The socket path is passed via NONO_MEDIATION_SOCKET.
//! Zero tool-specific logic lives here — all policy is in the mediation server.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

#[derive(Serialize)]
struct ShimRequest {
    command: String,
    args: Vec<String>,
    stdin: String,
    session_token: String,
    env: HashMap<String, String>,
    /// PID of this shim process — used by the server as `command_pid` in audit logs.
    pid: u32,
}

#[derive(Deserialize)]
struct ShimResponse {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

/// Fire-and-forget audit event (matches server-side `AuditEvent`).
#[derive(Serialize)]
struct AuditEvent {
    command: String,
    args: Vec<String>,
    ts: u64,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_type: Option<String>,
    /// PID of this shim process — the process that executed the logged command.
    command_pid: u32,
}

/// Read piped stdin without blocking indefinitely.
///
/// Spawns a background thread that performs the blocking `read_to_end`, then
/// waits for it with a timeout.  If no data arrives within 50ms we assume
/// the pipe is idle (e.g. Node.js `spawn()` with default stdio) and proceed
/// with empty stdin.  Real piped input (e.g. `echo data | cmd`) will be fully
/// available well within that window.
fn read_stdin_nonblocking() -> String {
    use std::sync::mpsc;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut buf);
        let _ = tx.send(buf);
    });

    match rx.recv_timeout(Duration::from_millis(50)) {
        Ok(buf) => String::from_utf8_lossy(&buf).into_owned(),
        Err(_) => String::new(),
    }
}

fn main() {
    let code = run();
    std::process::exit(code);
}

/// Derive the command name from argv[0] (basename only).
fn command_name() -> String {
    std::env::args()
        .next()
        .as_deref()
        .map(|a| {
            Path::new(a)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(a)
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Check whether a command is in the mediated commands list.
fn is_mediated(name: &str) -> bool {
    if let Ok(list) = std::env::var("NONO_MEDIATED_COMMANDS") {
        list.split(',').any(|c| c == name)
    } else {
        // If the env var isn't set, fall back to treating everything as mediated
        // for backward compatibility with older nono versions.
        true
    }
}

fn run() -> i32 {
    let name = command_name();
    let args: Vec<String> = std::env::args().skip(1).collect();

    if is_mediated(&name) {
        run_mediated(&name, &args)
    } else {
        run_audit(&name, &args)
    }
}

/// Mediated mode: full request-response flow via the mediation server.
fn run_mediated(command_name: &str, args: &[String]) -> i32 {
    let socket_path = match std::env::var("NONO_MEDIATION_SOCKET") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("nono-shim: NONO_MEDIATION_SOCKET not set");
            return 127;
        }
    };

    let session_token = match std::env::var("NONO_SESSION_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            eprintln!("nono-shim: NONO_SESSION_TOKEN not set");
            return 127;
        }
    };

    // Read stdin only when data is being piped in.  A TTY means interactive
    // use — no data to forward.  A pipe *might* carry data (e.g. `echo x |
    // ddtool …`), but it might also be an open pipe from a parent process that
    // never intends to write (e.g. Node.js `spawn()` with default stdio).
    // Blocking on `read_to_end` in that case hangs the shim forever.
    //
    // Strategy: set a short read timeout on stdin.  If nothing arrives within
    // 50 ms we treat stdin as empty and proceed.  Real piped input (even large
    // payloads) will arrive well within that window because the writer has
    // already buffered everything before exec-ing the shim.
    let stdin = if std::io::stdin().is_terminal() {
        String::new()
    } else {
        read_stdin_nonblocking()
    };

    let env: HashMap<String, String> = std::env::vars().collect();

    let request = ShimRequest {
        command: command_name.to_string(),
        args: args.to_vec(),
        stdin,
        session_token,
        env,
        pid: std::process::id(),
    };

    let request_bytes = match serde_json::to_vec(&request) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("nono-shim: failed to serialize request: {}", e);
            return 127;
        }
    };

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nono-shim: failed to connect to {}: {}", socket_path, e);
            return 127;
        }
    };

    // Send length-prefixed request
    let len = request_bytes.len() as u32;
    if stream.write_all(&len.to_be_bytes()).is_err() || stream.write_all(&request_bytes).is_err() {
        eprintln!("nono-shim: failed to send request");
        return 127;
    }

    // Read length-prefixed response
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        eprintln!("nono-shim: failed to read response length");
        return 127;
    }
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    if stream.read_exact(&mut resp_buf).is_err() {
        eprintln!("nono-shim: failed to read response body");
        return 127;
    }

    let response: ShimResponse = match serde_json::from_slice(&resp_buf) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("nono-shim: failed to parse response: {}", e);
            return 127;
        }
    };

    let _ = std::io::stdout().write_all(response.stdout.as_bytes());
    let _ = std::io::stderr().write_all(response.stderr.as_bytes());

    response.exit_code
}

/// Audit mode: fork+wait the real binary, then send completion audit event.
fn run_audit(command_name: &str, args: &[String]) -> i32 {
    // Resolve the real binary
    let real_binary = match resolve_real_binary(command_name) {
        Some(p) => p,
        None => {
            eprintln!("nono-shim: {}: command not found", command_name);
            return 127;
        }
    };

    // Fork+wait so we can capture the exit code for audit logging
    let exit_code = match std::process::Command::new(&real_binary).args(args).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!(
                "nono-shim: exec failed for {}: {}",
                real_binary.display(),
                e
            );
            127
        }
    };

    // Send audit event with exit code (best-effort, non-blocking)
    send_audit_event(command_name, args, exit_code);

    exit_code
}

/// Send a fire-and-forget audit event via datagram socket.
fn send_audit_event(command_name: &str, args: &[String], exit_code: i32) {
    let audit_socket = match std::env::var("NONO_AUDIT_SOCKET") {
        Ok(p) => p,
        Err(_) => return, // No audit socket — silently skip
    };

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let event = AuditEvent {
        command: command_name.to_string(),
        args: args.to_vec(),
        ts,
        exit_code,
        action_type: None,
        command_pid: std::process::id(),
    };

    let bytes = match serde_json::to_vec(&event) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Connect + send (fire-and-forget, no response expected)
    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = sock.send_to(&bytes, &audit_socket);
    }
}

/// Resolve the real binary by searching PATH, skipping the shim directory.
fn resolve_real_binary(command_name: &str) -> Option<std::path::PathBuf> {
    let shim_dir = std::env::var("NONO_SHIM_DIR").ok();
    let path_var = std::env::var("PATH").ok()?;

    for dir in path_var.split(':') {
        // Skip the shim directory to avoid infinite recursion
        if let Some(ref sd) = shim_dir {
            if dir == sd.as_str() {
                continue;
            }
        }

        let candidate = Path::new(dir).join(command_name);
        if candidate.is_file() {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = candidate.metadata() {
                if meta.permissions().mode() & 0o111 != 0 {
                    return Some(candidate);
                }
            }
        }
    }

    None
}
