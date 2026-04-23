//! Pre-sandbox session setup for command mediation.
//!
//! `setup()` is called before the sandbox is applied. It:
//! 1. Resolves each configured command name to an absolute path via `which`.
//! 2. Creates `/tmp/nono-session-{pid}/shims/` and symlinks `nono-shim` for each command.
//! 3. Starts the mediation server on a Unix socket.
//! 4. Returns a `SessionHandle` that keeps the server alive and exposes the
//!    paths/env needed by the rest of the startup sequence.

use super::admin::AdminState;
use super::approval::NativeApprovalGate;
use super::broker::TokenBroker;
use super::{CommandEntry, CommandSandbox, InterceptAction, MediationConfig, SessionAuditInfo};
use nix::libc;
use nono::{NonoError, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tracing::{debug, info};
use zeroize::Zeroizing;

/// The action stored in a resolved intercept rule.
#[derive(Clone, Debug)]
pub enum ResolvedAction {
    Respond { stdout: String },
    Capture { script: Option<String> },
    Approve { script: Option<String> },
}

/// A resolved intercept rule ready for the mediation server.
#[derive(Clone, Debug)]
pub struct ResolvedIntercept {
    pub args_prefix: Vec<String>,
    pub action: ResolvedAction,
    pub exit_code: i32,
    /// If true, requires user authentication before the action executes.
    pub admin: bool,
}

/// A fully resolved command entry ready for the mediation server.
#[derive(Clone)]
pub struct ResolvedCommand {
    pub name: String,
    /// Absolute path to the real binary (to exec on passthrough).
    pub real_path: PathBuf,
    pub intercepts: Vec<ResolvedIntercept>,
    /// Optional sandbox profile to apply when exec-ing the real binary.
    pub sandbox: Option<CommandSandbox>,
}

/// Handle returned by `setup()`. Dropping this shuts down the runtime.
pub struct SessionHandle {
    /// Directory containing shim symlinks (must be prepended to child PATH).
    pub shim_dir: PathBuf,
    /// Real path of the nono-shim binary (needed for sandbox file-read allow rules).
    pub shim_binary: PathBuf,
    /// Path of the Unix socket the mediation server listens on.
    pub socket_path: PathBuf,
    /// Session temp directory (cleaned up on drop).
    pub session_dir: PathBuf,
    /// Resolved real paths of mediated commands (for seatbelt deny rules).
    pub blocked_binaries: Vec<PathBuf>,
    /// Env vars to strip from the child environment (from `mediation.env.block`).
    pub env_block: Vec<String>,
    /// 256-bit random session authentication token (hex). Injected into the child
    /// as `NONO_SESSION_TOKEN`; shims must include it in every request.
    pub session_token: Zeroizing<String>,
    /// Path of the control socket (used by external admin CLI/menu bar app).
    #[allow(dead_code)]
    pub control_socket_path: PathBuf,
    /// Shared admin mode state (for passing to admin_commands query).
    pub admin_state: AdminState,
    /// Command names that use full request-response mediation (vs audit-only).
    pub mediated_commands: Vec<String>,
    /// Path to the audit datagram socket for fire-and-forget command logging.
    pub audit_socket_path: PathBuf,
    /// Latch set to the sandboxed process PID after the sandboxed process is forked.
    /// Callers must call `latch.set(sandboxed_pid)` in their post-fork callback.
    pub sandboxed_pid_latch: Arc<OnceLock<u32>>,
    // Tokio runtime kept alive so the server task continues running in the parent.
    _runtime: tokio::runtime::Runtime,
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        // Log if admin mode was active when the session ended.
        if self.admin_state.subscribe().borrow().is_active() {
            tracing::warn!("admin mode was active when mediation session ended");
        }
        // Clean up the session directory on parent exit.
        let _ = std::fs::remove_dir_all(&self.session_dir);
        debug!(
            "Mediation session directory removed: {}",
            self.session_dir.display()
        );
        // Clean up the admin directory (contains session.json with control_token).
        let admin_dir = session_admin_dir_path(std::process::id());
        let _ = std::fs::remove_dir_all(&admin_dir);
        debug!("Mediation admin directory removed: {}", admin_dir.display());
    }
}

/// Set up a mediation session.
///
/// Returns `None` when `config.is_active()` is false (nothing to do).
///
/// # Errors
/// Returns an error if a command cannot be resolved, or the session directory /
/// symlinks cannot be created.
pub fn setup(
    config: &MediationConfig,
    workdir: PathBuf,
    audit_info: SessionAuditInfo,
) -> Result<Option<SessionHandle>> {
    if !config.is_active() {
        return Ok(None);
    }
    let sandboxed_pid_latch = Arc::clone(&audit_info.sandboxed_pid);
    let audit_info_arc = Arc::new(audit_info);

    cleanup_orphaned_sessions();

    // Find nono-shim next to the running nono binary.
    let shim_binary = find_shim_binary()?;

    let session_dir = session_dir_path();
    let shim_dir = session_dir.join("shims");
    let socket_path = session_dir.join("mediation.sock");
    let control_socket_path = session_dir.join("control.sock");
    let audit_socket_path = session_dir.join("audit.sock");

    std::fs::create_dir_all(&shim_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to create shim dir {}: {}",
            shim_dir.display(),
            e
        ))
    })?;

    // Restrict session directory to owner-only so other local users cannot reach the socket.
    std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700)).map_err(
        |e| {
            NonoError::SandboxInit(format!(
                "mediation: failed to set session dir permissions {}: {}",
                session_dir.display(),
                e
            ))
        },
    )?;

    // -------------------------------------------------------------------------
    // Resolve commands
    // -------------------------------------------------------------------------
    let mut resolved_commands: Vec<ResolvedCommand> = Vec::new();
    let mut blocked_binaries: Vec<PathBuf> = Vec::new();

    let command_names: Vec<&str> = config.commands.iter().map(|c| c.name.as_str()).collect();

    for entry in &config.commands {
        // Validate allow_commands references
        if let Some(ref sb) = entry.sandbox {
            for allowed in &sb.allow_commands {
                if allowed == &entry.name {
                    return Err(NonoError::SandboxInit(format!(
                        "mediation: command '{}' lists itself in allow_commands",
                        entry.name
                    )));
                }
                if !command_names.contains(&allowed.as_str()) {
                    tracing::warn!(
                        "mediation: command '{}' lists '{}' in allow_commands but '{}' is not a mediated command",
                        entry.name, allowed, allowed
                    );
                }
            }
        }

        let Some(resolved) = resolve_command(entry, &shim_dir, &shim_binary, &workdir)? else {
            continue;
        };
        blocked_binaries.push(resolved.real_path.clone());
        resolved_commands.push(resolved);
    }

    // -------------------------------------------------------------------------
    // Universal audit shims: symlink all PATH executables not already mediated
    // -------------------------------------------------------------------------
    let mediated_commands: Vec<String> = resolved_commands.iter().map(|c| c.name.clone()).collect();

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let dir_path = Path::new(dir);
            if !dir_path.is_dir() {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(dir_path) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let shim_path = shim_dir.join(&name);
                    // Already shimmed (mediated command or earlier PATH entry)
                    if shim_path.exists() || shim_path.symlink_metadata().is_ok() {
                        continue;
                    }
                    if let Ok(meta) = entry.metadata() {
                        if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                            let _ = std::os::unix::fs::symlink(&shim_binary, &shim_path);
                        }
                    }
                }
            }
        }
    }
    debug!(
        "Mediation: created universal audit shims in {}",
        shim_dir.display()
    );

    // -------------------------------------------------------------------------
    // Generate session authentication token and control token
    // -------------------------------------------------------------------------
    let session_token = {
        use rand::RngExt;
        let bytes: [u8; 32] = rand::rng().random();
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        Zeroizing::new(hex)
    };

    let control_token = super::control::generate_token();

    // -------------------------------------------------------------------------
    // Create token broker (session-scoped)
    // -------------------------------------------------------------------------
    let broker = Arc::new(TokenBroker::new());

    // -------------------------------------------------------------------------
    // Create admin state
    // -------------------------------------------------------------------------
    let admin_state = AdminState::new();

    // -------------------------------------------------------------------------
    // Write session.json (mode 0600) to admin dir outside sandbox-accessible path.
    // The child process can read the session dir (shims, sockets), so we keep
    // the control_token in a separate directory that is never in the sandbox's
    // fs_read allow list.
    // -------------------------------------------------------------------------
    let admin_dir = session_admin_dir_path(std::process::id());
    std::fs::create_dir_all(&admin_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to create admin dir {}: {}",
            admin_dir.display(),
            e
        ))
    })?;
    std::fs::set_permissions(&admin_dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to set admin dir permissions {}: {}",
            admin_dir.display(),
            e
        ))
    })?;
    let session_json_path = admin_dir.join("session.json");
    let started_at = chrono::Utc::now().to_rfc3339();
    let session_info = serde_json::json!({
        "pid": std::process::id(),
        "control_socket": control_socket_path.to_string_lossy(),
        "control_token": control_token,
        "started_at": started_at,
    });
    let session_json_bytes = serde_json::to_vec(&session_info).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to serialize session.json: {}",
            e
        ))
    })?;
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&session_json_path)
            .and_then(|mut f| f.write_all(&session_json_bytes))
            .map_err(|e| {
                NonoError::SandboxInit(format!("mediation: failed to write session.json: {}", e))
            })?;
    }

    // -------------------------------------------------------------------------
    // Start the mediation server
    // -------------------------------------------------------------------------
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("nono-mediation")
        .build()
        .map_err(|e| {
            NonoError::SandboxInit(format!("mediation: failed to start runtime: {}", e))
        })?;

    let approval_gate: Arc<dyn super::approval::ApprovalGate + Send + Sync> =
        Arc::new(NativeApprovalGate);

    let sock = socket_path.clone();
    let cmds = resolved_commands.clone();
    let broker_clone = Arc::clone(&broker);
    let token_arc: Arc<str> = Arc::from(session_token.as_str());
    let shim_dir_clone = shim_dir.clone();
    let admin_clone = admin_state.clone();
    let gate_clone = Arc::clone(&approval_gate);
    let audit_sock = audit_socket_path.clone();
    let audit_log_dir = crate::session::ensure_sessions_dir()?;
    let audit_info_for_server = Arc::clone(&audit_info_arc);
    runtime.spawn(async move {
        if let Err(e) = super::server::run(
            sock,
            cmds,
            broker_clone,
            token_arc,
            shim_dir_clone,
            admin_clone,
            gate_clone,
            audit_sock,
            audit_log_dir,
            workdir,
            audit_info_for_server,
        )
        .await
        {
            tracing::error!("mediation server error: {}", e);
        }
    });

    // -------------------------------------------------------------------------
    // Start the control socket server
    // -------------------------------------------------------------------------
    let ctrl_sock = control_socket_path.clone();
    let ctrl_token = control_token;
    let ctrl_admin = admin_state.clone();
    let ctrl_sdir = session_dir.clone();
    runtime.spawn(async move {
        if let Err(e) =
            super::control::run_control_server(ctrl_sock, ctrl_token, ctrl_admin, ctrl_sdir).await
        {
            tracing::error!("control server error: {}", e);
        }
    });

    info!(
        "Mediation session started: socket={}, shims={}",
        socket_path.display(),
        shim_dir.display()
    );

    Ok(Some(SessionHandle {
        shim_dir,
        shim_binary,
        socket_path,
        session_dir,
        blocked_binaries,
        env_block: config.env.block.clone(),
        session_token,
        control_socket_path,
        admin_state,
        mediated_commands,
        audit_socket_path,
        sandboxed_pid_latch,
        _runtime: runtime,
    }))
}

/// Resolve a command entry: find the real binary, create the shim symlink.
///
/// Returns `Ok(None)` when the command is not found on PATH and no explicit
/// `binary_path` was given. This lets callers silently skip entries for tools
/// that are not installed on this device.
fn resolve_command(
    entry: &CommandEntry,
    shim_dir: &Path,
    shim_binary: &Path,
    workdir: &Path,
) -> Result<Option<ResolvedCommand>> {
    let real_path = if let Some(ref bp) = entry.binary_path {
        // Expand `$VAR` / `~` tokens so profiles can point at user-specific
        // binaries (e.g. `$HOME/.local/bin/tool`) without hard-coding paths.
        let p = crate::profile::expand_vars(bp, workdir)?;
        if !p.is_file() {
            return Err(NonoError::SandboxInit(format!(
                "mediation: binary_path for '{}' does not exist or is not a file: {}",
                entry.name,
                p.display()
            )));
        }
        p
    } else {
        match which::which(&entry.name) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    "mediation: command '{}' not found on PATH, skipping",
                    entry.name
                );
                return Ok(None);
            }
        }
    };
    debug!(
        "Mediation: resolved '{}' -> {}",
        entry.name,
        real_path.display()
    );

    // Create shim symlink (remove stale link if present)
    let shim_path = shim_dir.join(&entry.name);
    if shim_path.exists() || shim_path.symlink_metadata().is_ok() {
        std::fs::remove_file(&shim_path).map_err(|e| {
            NonoError::SandboxInit(format!(
                "mediation: failed to remove stale shim {}: {}",
                shim_path.display(),
                e
            ))
        })?;
    }
    std::os::unix::fs::symlink(shim_binary, &shim_path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to create shim symlink {}: {}",
            shim_path.display(),
            e
        ))
    })?;

    // Convert intercept rules, expanding env-var tokens in `args_prefix`
    // entries at profile-load time so matchers like
    // `["find-generic-password", "$USER", "Claude Code-credentials"]`
    // resolve to the current console user instead of requiring profile
    // authors to pre-substitute placeholders at install time.
    let intercepts: Vec<ResolvedIntercept> = entry
        .intercept
        .iter()
        .map(|rule| {
            let args_prefix = rule
                .args_prefix
                .iter()
                .map(|arg| crate::profile::expand_str(arg, workdir))
                .collect::<Result<Vec<String>>>()?;
            let (action, exit_code) = match &rule.action {
                InterceptAction::Respond { stdout, exit_code } => (
                    ResolvedAction::Respond {
                        stdout: stdout.clone(),
                    },
                    *exit_code,
                ),
                InterceptAction::Capture { script } => (
                    ResolvedAction::Capture {
                        script: script.clone(),
                    },
                    0,
                ),
                InterceptAction::Approve { script } => (
                    ResolvedAction::Approve {
                        script: script.clone(),
                    },
                    0,
                ),
            };
            Ok(ResolvedIntercept {
                args_prefix,
                action,
                exit_code,
                admin: rule.admin,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Some(ResolvedCommand {
        name: entry.name.clone(),
        real_path,
        intercepts,
        sandbox: entry.sandbox.clone(),
    }))
}

/// Find the nono-shim binary.
///
/// Looks next to the running `nono` executable first, then falls back to PATH.
fn find_shim_binary() -> Result<PathBuf> {
    // 1. Look next to current exe
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.with_file_name("nono-shim");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // 2. Try PATH
    which::which("nono-shim").map_err(|_| {
        NonoError::SandboxInit(
            "mediation: nono-shim binary not found next to nono or on PATH. \
             Ensure nono-shim is installed alongside nono."
                .to_string(),
        )
    })
}

/// Remove session and admin directories left behind by crashed/killed nono processes.
///
/// Scans the temp directories for `nono-session-{pid}` and `nono-admin-{pid}`
/// entries. Any entry whose PID is no longer alive (checked via `kill(pid, 0)`)
/// is removed. The current process's directories are always skipped.
fn cleanup_orphaned_sessions() {
    let current_pid = std::process::id();

    #[cfg(target_os = "macos")]
    let session_tmp = PathBuf::from("/private/tmp");
    #[cfg(not(target_os = "macos"))]
    let session_tmp = std::env::temp_dir();

    cleanup_dirs_in(&session_tmp, "nono-session-", current_pid);

    let admin_tmp = std::env::var("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    cleanup_dirs_in(&admin_tmp, "nono-admin-", current_pid);
}

/// Scan `dir` for entries matching `{prefix}{pid}` and remove those whose PID
/// is no longer alive.
fn cleanup_dirs_in(dir: &Path, prefix: &str, current_pid: u32) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Some(pid_str) = name_str.strip_prefix(prefix) else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == current_pid {
            continue;
        }
        // kill(pid, 0) returns 0 if process is alive, -1 with ESRCH if not.
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        if !alive {
            let _ = std::fs::remove_dir_all(entry.path());
            debug!(
                "Removed orphaned {} dir for dead pid {}",
                prefix.trim_end_matches('-'),
                pid
            );
        }
    }
}

/// Compute the session directory path for this process.
fn session_dir_path() -> PathBuf {
    // Use /private/tmp on macOS (canonical form of /tmp symlink) so Seatbelt
    // rules that use literal paths match correctly.
    #[cfg(target_os = "macos")]
    let tmp = PathBuf::from("/private/tmp");
    #[cfg(not(target_os = "macos"))]
    let tmp = std::env::temp_dir();

    tmp.join(format!("nono-session-{}", std::process::id()))
}

/// Compute the admin directory path for a given PID.
///
/// The admin dir lives in `$TMPDIR` (on macOS: `/var/folders/.../T/`) rather
/// than `/private/tmp`, so it is never covered by the sandbox's `fs_read`
/// allow list and cannot be read by the child process.
pub fn session_admin_dir_path(pid: u32) -> PathBuf {
    // $TMPDIR on macOS expands to a user-specific temp dir under /var/folders,
    // which is not included in any profile's fs_read allow list.
    // Fall back to /tmp only if $TMPDIR is unset (non-macOS or unusual env).
    let tmp = std::env::var("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    tmp.join(format!("nono-admin-{}", pid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::admin::AdminModeStatus;

    #[test]
    fn test_cleanup_orphaned_sessions_skips_live_pid() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let current_pid = std::process::id();

        // Create a dir for the current (live) PID — must not be removed.
        let live_dir = tmp.path().join(format!("nono-session-{}", current_pid));
        std::fs::create_dir_all(&live_dir).expect("create live dir");

        // Create a dir for a PID that is certainly dead.
        // i32::MAX as u32 stays positive when cast back to pid_t, so kill(pid, 0)
        // returns ESRCH — no process can ever have such a high PID.
        let dead_pid: u32 = i32::MAX as u32;
        let dead_dir = tmp.path().join(format!("nono-session-{}", dead_pid));
        std::fs::create_dir_all(&dead_dir).expect("create dead dir");

        cleanup_dirs_in(tmp.path(), "nono-session-", current_pid);

        assert!(live_dir.exists(), "live PID dir must not be removed");
        assert!(!dead_dir.exists(), "dead PID dir must be removed");
    }

    #[test]
    fn test_session_admin_dir_path_has_pid() {
        let pid = std::process::id();
        let path = session_admin_dir_path(pid);
        assert!(path.to_string_lossy().contains(&pid.to_string()));
        assert!(path.to_string_lossy().contains("nono-admin-"));
    }

    #[test]
    fn test_admin_dir_differs_from_session_dir() {
        let pid = std::process::id();
        let session_dir = session_dir_path();
        let admin_dir = session_admin_dir_path(pid);
        assert_ne!(
            session_dir, admin_dir,
            "admin dir must not be the same as session dir"
        );
        // Admin dir must not be under the session dir.
        assert!(
            !admin_dir.starts_with(&session_dir),
            "admin dir must not be inside session dir"
        );
    }

    #[test]
    fn test_setup_returns_none_when_inactive() {
        let config = MediationConfig::default();
        let dummy_audit = crate::mediation::SessionAuditInfo {
            session_id: String::new(),
            session_name: None,
            nono_pid: std::process::id(),
            sandboxed_pid: std::sync::Arc::new(std::sync::OnceLock::new()),
        };
        let result = setup(&config, PathBuf::from("/tmp"), dummy_audit)
            .expect("setup should not fail for inactive config");
        assert!(result.is_none());
    }

    #[test]
    fn test_session_dir_path_has_pid() {
        let path = session_dir_path();
        assert!(path
            .to_string_lossy()
            .contains(&std::process::id().to_string()));
    }

    #[test]
    fn test_admin_state_initial_disabled() {
        // Verify a freshly constructed AdminState starts in Disabled mode.
        let state = AdminState::new();
        let rx = state.subscribe();
        assert!(
            !rx.borrow().is_active(),
            "admin mode should be disabled by default"
        );
        assert!(matches!(*rx.borrow(), AdminModeStatus::Disabled));
    }

    #[test]
    fn test_resolve_command_expands_env_vars_in_args_prefix_and_binary_path() {
        use crate::mediation::{CommandEntry, InterceptAction, InterceptRule};

        let tmp = tempfile::tempdir().expect("tmpdir");

        // Create a real binary file so `is_file()` succeeds after expansion.
        let fake_binary = tmp.path().join("fake-cmd");
        std::fs::write(&fake_binary, b"#!/bin/sh\nexit 0\n").expect("write binary");
        let binary_env_var = "NONO_TEST_RESOLVE_CMD_BINARY";

        // Create shim dir and a fake shim target next to it so symlink creation
        // succeeds without needing to spin up the real nono-shim binary.
        let shim_dir = tmp.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("shim dir");
        let fake_shim_binary = tmp.path().join("fake-shim");
        std::fs::write(&fake_shim_binary, b"").expect("write shim");

        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            (binary_env_var, fake_binary.to_str().expect("utf8")),
            ("NONO_TEST_RESOLVE_CMD_USER", "test-user"),
        ]);

        let entry = CommandEntry {
            name: "fake-cmd".to_string(),
            binary_path: Some(format!("${}", binary_env_var)),
            intercept: vec![InterceptRule {
                args_prefix: vec![
                    "find-generic-password".to_string(),
                    "$NONO_TEST_RESOLVE_CMD_USER".to_string(),
                    "Claude Code-credentials".to_string(),
                ],
                admin: false,
                action: InterceptAction::Respond {
                    stdout: String::new(),
                    exit_code: 0,
                },
            }],
            sandbox: None,
        };

        let workdir = tmp.path();
        let resolved = resolve_command(&entry, &shim_dir, &fake_shim_binary, workdir)
            .expect("resolve")
            .expect("command resolved");

        assert_eq!(resolved.real_path, fake_binary);
        let args = &resolved.intercepts[0].args_prefix;
        assert_eq!(
            args,
            &vec![
                "find-generic-password".to_string(),
                "test-user".to_string(),
                "Claude Code-credentials".to_string(),
            ],
            "env-var tokens in args_prefix must be expanded at profile-load time"
        );
    }

    #[test]
    fn test_control_socket_path_in_session_dir() {
        // The control socket path should be derived from the session directory.
        let session_dir = session_dir_path();
        let expected = session_dir.join("control.sock");
        // Re-derive using the same logic as setup()
        let derived = session_dir_path().join("control.sock");
        assert_eq!(expected, derived);
    }
}
