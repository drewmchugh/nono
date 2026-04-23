//! Async Unix socket server for the mediation layer.
//!
//! Listens on a Unix socket in the unsandboxed parent process. Each connection
//! from a shim binary is handled concurrently: the framed JSON request is read,
//! dispatched to `policy::apply`, and the framed JSON response is written back.
//!
//! Protocol (same as nono-shim):
//!   Request:  u32 big-endian length || JSON payload
//!   Response: u32 big-endian length || JSON payload

use super::admin::AdminModeStatus;
use super::approval::ApprovalGate;
use super::broker::TokenBroker;
use super::policy::{admin_passthrough, apply, ShimRequest, ShimResponse};
use super::session::ResolvedCommand;
use super::{AuditEvent, SessionAuditInfo};
use nix::libc;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, warn};

/// Maximum request size: 1 MiB. Prevents a rogue same-user process from causing
/// a large allocation before the session token check can reject it.
const MAX_REQUEST_SIZE: u32 = 1024 * 1024;

/// Run the mediation server.
///
/// Binds to `socket_path` and accepts connections indefinitely. Each connection
/// is handled in its own `tokio::spawn` task. This function only returns if the
/// listener fails to bind or accept.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    socket_path: PathBuf,
    commands: Vec<ResolvedCommand>,
    broker: Arc<TokenBroker>,
    session_token: Arc<str>,
    shim_dir: PathBuf,
    admin_state: super::admin::AdminState,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
    audit_socket_path: PathBuf,
    audit_log_dir: PathBuf,
    workdir: PathBuf,
    audit_info: Arc<SessionAuditInfo>,
) -> std::io::Result<()> {
    // Remove stale socket file if present
    let _ = std::fs::remove_file(&socket_path);

    let listener = bind_socket_owner_only(&socket_path)?;
    debug!("Mediation server listening on {}", socket_path.display());

    // Wrap audit_log_dir so both the audit receiver and connection handler can share it.
    let audit_log_dir = Arc::new(audit_log_dir);

    // Bind audit datagram socket for fire-and-forget command logging
    let _ = std::fs::remove_file(&audit_socket_path);
    match bind_dgram_owner_only(&audit_socket_path) {
        Ok(audit_socket) => {
            let audit_log_dir_arc = Arc::clone(&audit_log_dir);
            let audit_info_arc = Arc::clone(&audit_info);
            tokio::spawn(async move {
                run_audit_receiver(audit_socket, audit_log_dir_arc, audit_info_arc).await;
            });
            debug!(
                "Audit datagram socket listening on {}",
                audit_socket_path.display()
            );
        }
        Err(e) => {
            warn!(
                "Failed to bind audit socket: {} — audit logging disabled",
                e
            );
        }
    }

    let commands = Arc::new(commands);
    let shim_dir = Arc::new(shim_dir);
    let socket_path = Arc::new(socket_path);
    let workdir = Arc::new(workdir);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let cmds = Arc::clone(&commands);
                let broker = Arc::clone(&broker);
                let token = Arc::clone(&session_token);
                let sd = Arc::clone(&shim_dir);
                let sp = Arc::clone(&socket_path);
                let wd = Arc::clone(&workdir);
                let sess_dir = Arc::clone(&audit_log_dir);
                let admin_rx = admin_state.subscribe();
                let gate = Arc::clone(&approval);
                let stamp = Arc::clone(&audit_info);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(
                        stream,
                        &cmds,
                        broker,
                        token.clone(),
                        &sd,
                        &sp,
                        admin_rx,
                        gate,
                        &sess_dir,
                        &wd,
                        &stamp,
                    )
                    .await
                    {
                        warn!("mediation: connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("mediation: accept error: {}", e);
                return Err(e);
            }
        }
    }
}

/// Handle a single shim connection: read request, apply policy, write response.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    commands: &[ResolvedCommand],
    broker: Arc<TokenBroker>,
    session_token: Arc<str>,
    shim_dir: &std::path::Path,
    socket_path: &std::path::Path,
    admin_receiver: tokio::sync::watch::Receiver<AdminModeStatus>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
    audit_log_dir: &Path,
    workdir: &std::path::Path,
    audit_info: &SessionAuditInfo,
) -> std::io::Result<()> {
    // Read length-prefixed request. Reject oversized payloads before allocating
    // to prevent a rogue same-user process from causing a large allocation.
    let len = stream.read_u32().await?;
    if len > MAX_REQUEST_SIZE {
        warn!(
            "mediation: rejected oversized request ({} bytes > {} limit)",
            len, MAX_REQUEST_SIZE
        );
        return Ok(());
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    let request: ShimRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            warn!("mediation: failed to parse request: {}", e);
            let err_resp = ShimResponse {
                stdout: String::new(),
                stderr: format!("nono-mediation: invalid request: {}\n", e),
                exit_code: 127,
            };
            write_response(&mut stream, &err_resp).await?;
            return Ok(());
        }
    };

    // Verify session token before processing. Silent reject — no response sent.
    // This blocks same-user rogue processes that can reach the socket but don't
    // know the session token injected into the child environment.
    if request.session_token != session_token.as_ref() {
        warn!("mediation: rejected connection with invalid session token");
        return Ok(());
    }

    debug!(
        "mediation: request command='{}' args={:?}",
        request.command, request.args
    );

    // Check admin mode — bypass all policy if active
    if admin_receiver.borrow().is_active() {
        warn!(
            "admin mode: passthrough command='{}' args={:?} session_pid={}",
            request.command,
            request.args,
            std::process::id()
        );
        let command_pid = request.pid;
        let (response, action_type) = admin_passthrough(&request, commands).await;
        write_response(&mut stream, &response).await?;
        log_mediated_audit(
            audit_log_dir,
            &request.command,
            &request.args,
            &response,
            action_type,
            Some(command_pid),
            audit_info,
        );
        return Ok(());
    }

    let command_name = request.command.clone();
    let args = request.args.clone();
    let command_pid = request.pid;
    let ctx = super::policy::SessionCtx {
        shim_dir,
        socket_path,
        session_token: &session_token,
        workdir,
    };
    let (response, action_type) = apply(request, commands, broker, &ctx, approval).await;

    write_response(&mut stream, &response).await?;
    log_mediated_audit(audit_log_dir, &command_name, &args, &response, action_type, Some(command_pid), audit_info);
    Ok(())
}

/// Log an audit event for a mediated command response.
fn log_mediated_audit(
    audit_log_dir: &Path,
    command: &str,
    args: &[String],
    response: &ShimResponse,
    action_type: &str,
    command_pid: Option<u32>,
    audit_info: &SessionAuditInfo,
) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    append_audit_log(
        audit_log_dir,
        &AuditEvent {
            command: command.to_string(),
            args: scrub_args(args),
            ts,
            exit_code: response.exit_code,
            action_type: Some(action_type.to_string()),
            session_id: audit_info.session_id.clone(),
            session_name: audit_info.session_name.clone(),
            nono_pid: audit_info.nono_pid,
            sandboxed_pid: audit_info.sandboxed_pid.get().copied(),
            command_pid,
        },
    );
}

/// Write a length-prefixed JSON response.
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    response: &ShimResponse,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(response).map_err(std::io::Error::other)?;

    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Bind a Unix socket with restrictive permissions from creation time (0o600).
///
/// Acquires a process-wide umask lock, sets umask to 0o077, binds the socket,
/// then restores the previous umask. This avoids a TOCTOU window where a freshly
/// bound socket could be accessible to other users before `set_permissions` runs.
fn bind_socket_owner_only(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    let lock = umask_guard();
    let _guard = lock.lock().map_err(|_| {
        std::io::Error::other("mediation: failed to acquire umask synchronization lock")
    })?;

    let old_umask = unsafe { libc::umask(0o077) };
    let std_listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| {
        unsafe { libc::umask(old_umask) };
        e
    });
    unsafe { libc::umask(old_umask) };

    let std_listener = std_listener?;
    std_listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(std_listener)
}

fn umask_guard() -> &'static Mutex<()> {
    static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    UMASK_LOCK.get_or_init(|| Mutex::new(()))
}

/// Bind a Unix datagram socket with restrictive permissions (0o600).
fn bind_dgram_owner_only(path: &Path) -> std::io::Result<tokio::net::UnixDatagram> {
    let lock = umask_guard();
    let _guard = lock.lock().map_err(|_| {
        std::io::Error::other("mediation: failed to acquire umask synchronization lock")
    })?;

    let old_umask = unsafe { libc::umask(0o077) };
    let std_sock = std::os::unix::net::UnixDatagram::bind(path).map_err(|e| {
        unsafe { libc::umask(old_umask) };
        e
    });
    unsafe { libc::umask(old_umask) };

    let std_sock = std_sock?;
    std_sock.set_nonblocking(true)?;
    tokio::net::UnixDatagram::from_std(std_sock)
}

/// Receive audit events from shims and append them to `audit.jsonl`.
///
/// Shim-originated events do not carry session context (the shim has no
/// access to it). The server stamps each received event with the session
/// fields before writing to disk.
async fn run_audit_receiver(
    socket: tokio::net::UnixDatagram,
    audit_log_dir: Arc<PathBuf>,
    audit_info: Arc<SessionAuditInfo>,
) {
    let mut buf = vec![0u8; 8192];
    loop {
        match socket.recv(&mut buf).await {
            Ok(n) => {
                if let Ok(mut event) = serde_json::from_slice::<AuditEvent>(&buf[..n]) {
                    event.args = scrub_args(&event.args);
                    event.session_id = audit_info.session_id.clone();
                    event.session_name = audit_info.session_name.clone();
                    event.nono_pid = audit_info.nono_pid;
                    event.sandboxed_pid = audit_info.sandboxed_pid.get().copied();
                    append_audit_log(&audit_log_dir, &event);
                } else {
                    warn!("audit socket: failed to parse event");
                }
            }
            Err(e) => {
                warn!("audit socket recv error: {}", e);
                break;
            }
        }
    }
}

/// Append a single audit event as a JSON line to `audit.jsonl`.
fn append_audit_log(audit_log_dir: &Path, event: &AuditEvent) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let log_path = audit_log_dir.join("audit.jsonl");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)
    {
        if let Ok(line) = serde_json::to_string(event) {
            let _ = writeln!(f, "{}", line);
        }
    }
}

/// Scrub sensitive values from command-line arguments before writing to the audit log.
pub(super) fn scrub_args(args: &[String]) -> Vec<String> {
    const SECRET_FLAGS: &[&str] = &[
        "--token",
        "--password",
        "--secret",
        "--api-key",
        "--api-token",
        "--auth",
        "-p",
    ];

    let mut result: Vec<String> = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        if SECRET_FLAGS.contains(&arg.as_str()) {
            result.push(arg.clone());
            if i + 1 < args.len() {
                result.push("<redacted>".to_string());
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

        if arg == "-H" {
            result.push(arg.clone());
            if i + 1 < args.len() {
                result.push(scrub_header_value(&args[i + 1]));
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

        result.push(scrub_value(arg));
        i += 1;
    }
    result
}

fn scrub_header_value(value: &str) -> String {
    let lower = value.to_lowercase();
    if let Some(colon_pos) = lower.find("authorization:") {
        let prefix_end = colon_pos + "authorization:".len();
        let prefix = &value[..prefix_end];
        let after_colon = value[prefix_end..].trim_start();
        if let Some(space_pos) = after_colon.find(' ') {
            let scheme = &after_colon[..space_pos];
            return format!("{} {} <redacted>", prefix, scheme);
        }
        if !after_colon.is_empty() {
            return format!("{} <redacted>", prefix);
        }
    }
    value.to_string()
}

fn scrub_value(value: &str) -> String {
    let value = scrub_nono_tokens(value);
    scrub_url_credentials(&value)
}

fn scrub_nono_tokens(s: &str) -> String {
    const PREFIX: &str = "nono_";
    const MIN_HEX_LEN: usize = 40;

    let mut result = String::with_capacity(s.len());
    let mut remaining = s;
    while let Some(pos) = remaining.find(PREFIX) {
        result.push_str(&remaining[..pos]);
        let after = &remaining[pos + PREFIX.len()..];
        let hex_len = after.bytes().take_while(|b| b.is_ascii_hexdigit()).count();
        if hex_len >= MIN_HEX_LEN {
            result.push_str("<redacted>");
            remaining = &remaining[pos + PREFIX.len() + hex_len..];
        } else {
            result.push_str(PREFIX);
            remaining = after;
        }
    }
    result.push_str(remaining);
    result
}

fn scrub_url_credentials(value: &str) -> String {
    if let Ok(mut u) = url::Url::parse(value) {
        if u.password().is_some() {
            let _ = u.set_password(Some("[redacted]"));
            return u.to_string();
        }
    }
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_args_secret_flags() {
        let args = ["--token", "abc123", "other"].map(String::from).to_vec();
        assert_eq!(scrub_args(&args), vec!["--token", "<redacted>", "other"]);
    }

    #[test]
    fn test_scrub_args_authorization_header() {
        let args = ["-H", "Authorization: Bearer ghp_ABCDEFG"]
            .map(String::from)
            .to_vec();
        assert_eq!(
            scrub_args(&args),
            vec!["-H", "Authorization: Bearer <redacted>"]
        );
    }

    #[test]
    fn test_scrub_args_url_credentials() {
        let args = vec!["https://user:ghp_xyz@github.com/foo/bar".to_string()];
        let scrubbed = scrub_args(&args);
        assert!(
            !scrubbed[0].contains("ghp_xyz"),
            "raw token still present: {}",
            scrubbed[0]
        );
        assert!(
            scrubbed[0].starts_with("https://user:"),
            "URL structure mangled: {}",
            scrubbed[0]
        );
    }

    #[test]
    fn test_scrub_args_nono_token() {
        let token = format!("nono_{}", "a".repeat(40));
        assert_eq!(scrub_args(&[token]), vec!["<redacted>"]);
    }

    #[test]
    fn test_scrub_args_passthrough() {
        let args = ["ls", "-la", "/tmp"].map(String::from).to_vec();
        assert_eq!(scrub_args(&args), args);
    }

    #[test]
    fn test_scrub_args_secret_flag_at_end() {
        let args = vec!["--token".to_string()];
        assert_eq!(scrub_args(&args), vec!["--token"]);
    }
}
