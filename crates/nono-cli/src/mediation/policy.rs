//! Policy engine for the mediation server.
//!
//! For each incoming `ShimRequest`, this module:
//! 1. Finds the matching `ResolvedCommand` entry.
//! 2. Checks `intercept` rules in order (positional subcommand match).
//! 3. If matched with `Respond`: returns the configured `ShimResponse` without calling the binary.
//! 4. If matched with `Capture`: runs the real binary (or a script), stores output in the broker,
//!    returns a `nono_<hex>` nonce to the sandbox.
//! 5. If not matched: execs the real binary. Nonce-bearing env vars from the sandbox are promoted
//!    (replaced with real values); all other sandbox env vars are discarded.

use super::approval::ApprovalGate;
use super::broker::TokenBroker;
use super::session::{ResolvedAction, ResolvedCommand};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Request forwarded from the shim binary to the mediation server.
#[derive(Debug, Default, Deserialize)]
pub struct ShimRequest {
    pub command: String,
    pub args: Vec<String>,
    pub stdin: String,
    /// Session authentication token. Must match the token injected via
    /// `NONO_SESSION_TOKEN`. Requests with a missing or wrong token are
    /// silently rejected. Old shims missing this field fail deserialization
    /// and receive a 127 error — the correct security behaviour.
    pub session_token: String,
    /// Environment variables from the sandbox at invocation time.
    /// Used only for nonce promotion — all non-nonce vars are discarded.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// PID of the shim process itself — the process that ran this command.
    /// Used to populate `command_pid` in the audit log.
    #[serde(default)]
    pub pid: u32,
}

/// Response the mediation server sends back to the shim binary.
#[derive(Debug, Serialize)]
pub struct ShimResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Mediation session context passed to policy functions.
///
/// Bundles the per-session paths and token needed by `apply` and `exec_passthrough`.
pub struct SessionCtx<'a> {
    pub shim_dir: &'a std::path::Path,
    pub socket_path: &'a std::path::Path,
    pub session_token: &'a str,
    /// Working directory of the nono session (the parent launch cwd or
    /// `--workdir`). Threaded into `expand_vars` so `$WORKDIR` in mediated
    /// sandbox paths resolves consistently across the main and per-command
    /// sandboxes.
    pub workdir: &'a std::path::Path,
}

/// Env var names that must never receive a nonce-promoted value, even if a
/// nonce-bearing var with this name appears in the sandbox env.
static DANGEROUS_ENV_VAR_NAMES: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FORCE_FLAT_NAMESPACE",
    "NONO_SANDBOX_CONTEXT",
];

/// Apply policy to a shim request and produce a response.
///
/// - If the command is unknown: returns an error response (not found).
/// - If an intercept rule matches with `Respond`: returns the pre-resolved output.
/// - If an intercept rule matches with `Capture`: runs the binary/script, issues a nonce.
/// - Otherwise: execs the real binary with strict env filtering.
pub async fn apply(
    request: ShimRequest,
    commands: &[ResolvedCommand],
    broker: Arc<TokenBroker>,
    ctx: &SessionCtx<'_>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
) -> (ShimResponse, &'static str) {
    // Find matching command entry
    let Some(cmd) = commands.iter().find(|c| c.name == request.command) else {
        warn!("mediation: unknown command '{}'", request.command);
        return (
            ShimResponse {
                stdout: String::new(),
                stderr: format!(
                    "nono-mediation: command '{}' not configured\n",
                    request.command
                ),
                exit_code: 127,
            },
            "unknown",
        );
    };

    // If the request comes from within a per-command sandbox (via allow_commands),
    // skip intercepts — credentials flow between trusted sub-processes, not to the agent.
    // The sandbox context nonce is unforgeable (only the server can issue valid nonces).
    if let Some(ctx_nonce) = request.env.get("NONO_SANDBOX_CONTEXT") {
        if let Some(parent_name) = broker.resolve(ctx_nonce) {
            if let Some(parent_cmd) = commands.iter().find(|c| c.name == **parent_name) {
                if let Some(ref sb) = parent_cmd.sandbox {
                    if sb.allow_commands.contains(&request.command) {
                        debug!(
                            "mediation: skipping intercepts for '{}' (called from '{}' via allow_commands)",
                            request.command, &**parent_name
                        );
                        // No per-command sandbox — same as the capture path.
                        // The real binary needs full access to system resources
                        // (e.g. Keychain, vault) to fetch credentials. Security
                        // comes from the parent's sandbox, not the child's.
                        let result = exec_passthrough(
                            cmd,
                            &request.args,
                            &request.stdin,
                            &request.env,
                            &broker,
                            None,
                            ctx,
                            commands,
                        )
                        .await;
                        return (result, "passthrough");
                    }
                }
            }
        }
    }

    // Check intercept rules in order
    for rule in &cmd.intercepts {
        if subcommand_matches(&rule.args_prefix, &request.args) {
            debug!(
                "mediation: intercepting '{}' with prefix {:?}",
                request.command, rule.args_prefix
            );

            // Admin gate: require user authentication before executing this rule.
            if rule.admin {
                let command = request.command.clone();
                let args = request.args.clone();
                let approval_clone = Arc::clone(&approval);
                let allowed =
                    tokio::task::spawn_blocking(move || approval_clone.approve(&command, &args))
                        .await
                        .unwrap_or(false);
                if !allowed {
                    let invocation = if request.args.is_empty() {
                        request.command.clone()
                    } else {
                        format!("{} {}", request.command, request.args.join(" "))
                    };
                    let action_type = match &rule.action {
                        ResolvedAction::Respond { .. } => "respond",
                        ResolvedAction::Capture { .. } => "capture",
                        ResolvedAction::Approve { .. } => "approve",
                    };
                    return (
                        ShimResponse {
                            stdout: String::new(),
                            stderr: format!("nono: '{}' was not approved\n", invocation),
                            exit_code: 126,
                        },
                        action_type,
                    );
                }
            }

            return match &rule.action {
                ResolvedAction::Respond { stdout } => (
                    ShimResponse {
                        stdout: stdout.clone(),
                        stderr: String::new(),
                        exit_code: rule.exit_code,
                    },
                    "respond",
                ),
                ResolvedAction::Capture { script } => {
                    let result = match script {
                        Some(sh) => exec_script(sh, &request.env, &broker).await,
                        None => {
                            // No per-command sandbox during capture — the real binary needs
                            // full access to system resources (e.g. Keychain) to fetch the credential.
                            exec_passthrough(
                                cmd,
                                &request.args,
                                &request.stdin,
                                &request.env,
                                &broker,
                                None,
                                ctx,
                                commands,
                            )
                            .await
                        }
                    };
                    if result.exit_code != 0 {
                        return (result, "capture");
                    }
                    let nonce = broker.issue(Zeroizing::new(result.stdout.trim().to_string()));
                    (
                        ShimResponse {
                            stdout: format!("{}\n", nonce),
                            stderr: String::new(),
                            exit_code: 0,
                        },
                        "capture",
                    )
                }
                ResolvedAction::Approve { script } => {
                    // Run the real binary (or script) and return the actual output.
                    // Typically used with admin: true to gate behind approval.
                    //
                    // No per-command sandbox is applied (None). The real binary
                    // needs unrestricted access to system resources (e.g. macOS
                    // Keychain via mach-lookup to securityd) that a Seatbelt
                    // sandbox would block. Protection comes from the profile
                    // author's deliberate choice of which commands get `approve`.
                    let resp = match script {
                        Some(sh) => exec_script(sh, &request.env, &broker).await,
                        None => {
                            exec_passthrough(
                                cmd,
                                &request.args,
                                &request.stdin,
                                &request.env,
                                &broker,
                                None,
                                ctx,
                                commands,
                            )
                            .await
                        }
                    };
                    (resp, "approve")
                }
            };
        }
    }

    // No intercept matched — pass through to the real binary
    debug!(
        "mediation: passthrough '{}' {:?} -> {}",
        request.command,
        request.args,
        cmd.real_path.display()
    );
    let resp = exec_passthrough(
        cmd,
        &request.args,
        &request.stdin,
        &request.env,
        &broker,
        cmd.sandbox.clone(),
        ctx,
        commands,
    )
    .await;
    (resp, "passthrough")
}

/// Execute the real binary without any mediation — no intercept rules, no env
/// var filtering, no nonce promotion. Used when admin mode is active.
///
/// This is an intentional bypass. The operator explicitly granted admin mode
/// via biometric or password auth. All calls are logged at WARN level.
pub async fn admin_passthrough(
    request: &ShimRequest,
    commands: &[ResolvedCommand],
) -> (ShimResponse, &'static str) {
    let Some(cmd) = commands.iter().find(|c| c.name == request.command) else {
        warn!("admin passthrough: unknown command '{}'", request.command);
        return (
            ShimResponse {
                stdout: String::new(),
                stderr: format!(
                    "nono-mediation: command '{}' not configured\n",
                    request.command
                ),
                exit_code: 127,
            },
            "admin_passthrough",
        );
    };

    // Build env from parent process — no filtering, no nonce promotion.
    let env: HashMap<String, String> = std::env::vars().collect();
    let args = request.args.clone();
    let stdin_data = request.stdin.clone();
    let real_path = cmd.real_path.clone();

    let result = tokio::task::spawn_blocking(move || -> nono::Result<ShimResponse> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut cmd_builder = Command::new(&real_path);
        cmd_builder
            .args(&args)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd_builder
            .spawn()
            .map_err(nono::NonoError::CommandExecution)?;

        if !stdin_data.is_empty() {
            if let Some(mut si) = child.stdin.take() {
                let _ = si.write_all(stdin_data.as_bytes());
            }
        }

        let output = child
            .wait_with_output()
            .map_err(nono::NonoError::CommandExecution)?;

        Ok(ShimResponse {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(1),
        })
    })
    .await;

    let resp = match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: admin passthrough exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    };
    (resp, "admin_passthrough")
}

/// Check if the invocation's positional args start with the given prefix.
///
/// Flags (args starting with `-`) are ignored, allowing matches regardless of
/// flag placement. E.g. `["auth", "github", "token"]` matches both
/// `ddtool auth github token` and `ddtool --debug auth github token`.
pub fn subcommand_matches(prefix: &[String], args: &[String]) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if prefix.len() > positional.len() {
        return false;
    }
    prefix.iter().zip(positional.iter()).all(|(p, a)| p == *a)
}

/// Execute a shell script and collect its output.
///
/// Uses the same strict env-building as `exec_passthrough`: starts from the
/// trusted parent env, promotes nonce-bearing sandbox vars, blocks dangerous names.
async fn exec_script(
    script: &str,
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
) -> ShimResponse {
    let env = build_exec_env(sandbox_env, broker);
    let script = script.to_string();

    let result = tokio::task::spawn_blocking(move || -> Result<ShimResponse> {
        use std::process::{Command, Stdio};

        let child = Command::new("sh")
            .args(["-c", &script])
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(NonoError::CommandExecution)?;

        let output = child
            .wait_with_output()
            .map_err(NonoError::CommandExecution)?;
        Ok(ShimResponse {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(1),
        })
    })
    .await;

    match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: script exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    }
}

/// Atomic counter for generating unique filtered shim directory names.
static FILTERED_SHIM_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Execute the real binary and collect its output.
///
/// Env building:
/// - Starts from the trusted parent (mediation server) environment.
/// - Prepends `shim_dir` to PATH so subprocess invocations of mediated commands
///   route through the mediation server instead of running directly inside the
///   per-command sandbox (where network is restricted).
/// - From the sandbox env, promotes only nonce-bearing vars (`nono_` prefix).
///   All other sandbox env vars are discarded to prevent sandbox injection.
/// - Dangerous var names (PATH, LD_PRELOAD, etc.) are blocked even with valid nonces.
/// - Arg nonces: any arg starting with `nono_` is replaced with the real value.
///
/// When `allow_commands` is non-empty on the sandbox, a filtered shim directory is
/// created containing symlinks only for commands NOT in the allow list. Allowed
/// commands run directly (real binary) inside the per-command sandbox.
#[allow(clippy::too_many_arguments)]
async fn exec_passthrough(
    cmd: &ResolvedCommand,
    args: &[String],
    stdin_data: &str,
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
    sandbox: Option<super::CommandSandbox>,
    ctx: &SessionCtx<'_>,
    all_commands: &[ResolvedCommand],
) -> ShimResponse {
    let mut env = build_exec_env(sandbox_env, broker);

    // Build the effective shim directory and PATH.
    // When allow_commands is set, create a filtered shim dir that excludes allowed
    // commands so they resolve to their real binaries instead of routing through mediation.
    let allow_commands = sandbox
        .as_ref()
        .map(|sb| &sb.allow_commands)
        .filter(|ac| !ac.is_empty());

    let (effective_shim_dir, _filtered_dir_guard) = if let Some(allow_cmds) = allow_commands {
        match build_filtered_shim_dir(ctx.shim_dir, allow_cmds, all_commands) {
            Ok((dir, guard)) => (dir, Some(guard)),
            Err(e) => {
                return ShimResponse {
                    stdout: String::new(),
                    stderr: format!(
                        "nono-mediation: failed to create filtered shim dir: {}\n",
                        e
                    ),
                    exit_code: 1,
                };
            }
        }
    } else {
        (ctx.shim_dir.to_path_buf(), None)
    };

    let shim_dir_str = effective_shim_dir.to_string_lossy().to_string();
    let parent_path = env
        .get("PATH")
        .cloned()
        .unwrap_or_else(|| "/usr/bin:/bin".to_string());

    // For allowed commands, prepend their real binary directories after the shim dir
    // so they resolve to the real binary (which won't have a shim in the filtered dir).
    let mut path_parts = vec![shim_dir_str.clone()];
    if let Some(allow_cmds) = allow_commands {
        let mut seen_dirs: HashSet<String> = HashSet::new();
        for allowed_name in allow_cmds {
            if let Some(allowed_cmd) = all_commands.iter().find(|c| c.name == *allowed_name) {
                // Only add real binary dirs for commands without their own mediation.
                // Commands with intercepts or sandbox keep their shim and route through
                // the mediation server, so they don't need the real binary on PATH.
                let has_mediation =
                    !allowed_cmd.intercepts.is_empty() || allowed_cmd.sandbox.is_some();
                if has_mediation {
                    continue;
                }
                if let Some(parent) = allowed_cmd.real_path.parent() {
                    let dir_str = parent.to_string_lossy().to_string();
                    if seen_dirs.insert(dir_str.clone()) {
                        path_parts.push(dir_str);
                    }
                }
            }
        }
    }
    path_parts.push(parent_path);
    env.insert("PATH".to_string(), path_parts.join(":"));

    // Update NONO_SHIM_DIR to point to the effective shim dir (which may be a
    // filtered shim dir when allow_commands is set). The nono-shim binary uses
    // this to skip its own directory when resolving the real binary. Without
    // this, shims in the filtered dir would skip the wrong directory and find
    // themselves again, causing infinite exec recursion (EAGAIN).
    env.insert("NONO_SHIM_DIR".to_string(), shim_dir_str.clone());

    // Inject mediation socket path and session token so the shim binaries
    // invoked by the exec'd command can authenticate to the mediation server.
    // This allows exec plugins (e.g. kubectl's credential plugin) to route
    // through mediation rather than running directly in the per-command sandbox.
    env.insert(
        "NONO_MEDIATION_SOCKET".to_string(),
        ctx.socket_path.to_string_lossy().to_string(),
    );
    env.insert(
        "NONO_SESSION_TOKEN".to_string(),
        ctx.session_token.to_string(),
    );

    // Inject a sandbox context nonce so the mediation server can identify
    // shim requests originating from within this per-command sandbox.
    // This allows the server to skip intercepts for allow_commands calls
    // (credentials flow between trusted sub-processes, not to the agent).
    // The nonce is unforgeable — only the server can issue valid nonces.
    let sandbox_context_nonce = broker.issue(Zeroizing::new(cmd.name.clone()));
    env.insert("NONO_SANDBOX_CONTEXT".to_string(), sandbox_context_nonce);

    // Promote nonce values in args
    let args: Vec<String> = args
        .iter()
        .map(|a| {
            if a.starts_with("nono_") {
                broker
                    .resolve(a)
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_else(|| a.clone())
            } else {
                a.clone()
            }
        })
        .collect();

    let real_path = cmd.real_path.clone();
    let cmd_name = cmd.name.clone();
    let stdin_data = stdin_data.to_string();
    // Owned shim paths for use in spawn_blocking (which requires 'static captures).
    let shim_dir_buf = effective_shim_dir.clone();
    let real_shim_binary = std::fs::canonicalize(ctx.shim_dir.join(&cmd.name)).ok();
    // Own the session workdir for use inside spawn_blocking (profile::expand_vars
    // borrows it).
    let workdir_buf = ctx.workdir.to_path_buf();

    // Collect allowed command binary directories for sandbox read capabilities.
    let allowed_binary_dirs: Vec<std::path::PathBuf> = sandbox
        .as_ref()
        .map(|sb| &sb.allow_commands)
        .filter(|ac| !ac.is_empty())
        .map(|allow_cmds| {
            allow_cmds
                .iter()
                .filter_map(|name| {
                    all_commands
                        .iter()
                        .find(|c| c.name == *name)
                        .and_then(|c| c.real_path.parent())
                        .filter(|p| p.exists())
                        .map(|p| p.to_path_buf())
                })
                .collect()
        })
        .unwrap_or_default();

    // Start a per-command proxy if allowed_hosts is configured (and block is not set).
    let mut proxy_handle: Option<nono_proxy::ProxyHandle> = None;
    let mut proxy_port: Option<u16> = None;

    if let Some(ref sb) = sandbox {
        if !sb.network.allowed_hosts.is_empty() && !sb.network.block {
            let proxy_config = nono_proxy::ProxyConfig {
                allowed_hosts: sb.network.allowed_hosts.clone(),
                ..Default::default()
            };
            match nono_proxy::start(proxy_config).await {
                Ok(handle) => {
                    for (k, v) in handle.env_vars() {
                        env.insert(k, v);
                    }
                    proxy_port = Some(handle.port);
                    proxy_handle = Some(handle);
                }
                Err(e) => {
                    return ShimResponse {
                        stdout: String::new(),
                        stderr: format!("nono-mediation: failed to start network proxy: {}\n", e),
                        exit_code: 1,
                    };
                }
            }
        }
    }

    let maybe_sandbox = sandbox;

    let result = tokio::task::spawn_blocking(move || -> Result<ShimResponse> {
        use std::io::Write;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let mut cmd_builder = Command::new(&real_path);
        cmd_builder
            .args(&args)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(sb) = maybe_sandbox {
            let mut caps = nono::CapabilitySet::new();

            // Apply platform system read+write paths so the binary can actually exec
            // and use standard devices (e.g. /dev/null). Mirrors the system groups
            // applied to the main sandbox.
            if let Ok(policy) = crate::policy::load_embedded_policy() {
                let (read_group, write_group) = if cfg!(target_os = "macos") {
                    ("system_read_macos", "system_write_macos")
                } else {
                    ("system_read_linux", "system_write_linux")
                };
                let _ = crate::policy::resolve_groups(
                    &policy,
                    &[read_group.to_string(), write_group.to_string()],
                    &mut caps,
                );
            }

            // Also allow the binary's own directory, in case it lives outside the standard
            // system paths (e.g. ~/dd/devtools/bin/gh). Use the ORIGINAL (pre-canonicalize)
            // parent so FsCapability emits Seatbelt rules for both the symlink path and the
            // resolved canonical path — Seatbelt checks paths as-accessed (pre-resolution).
            if let Some(parent) = real_path.parent() {
                if parent.exists() {
                    caps = caps.allow_path(parent, nono::AccessMode::Read)?;
                }
            }

            // Allow the shim directory and the nono-shim binary so that subprocesses
            // of the exec'd command (e.g. kubectl's exec credential plugin) can exec
            // the shim binaries and route through the mediation server.
            caps = caps.allow_path(&shim_dir_buf, nono::AccessMode::Read)?;
            if let Some(ref real_shim) = real_shim_binary {
                caps = caps.allow_file(real_shim, nono::AccessMode::Read)?;
            }

            // Allow read access to directories of allowed commands so they can exec
            // their real binaries directly (bypassing the shim).
            for dir in &allowed_binary_dirs {
                caps = caps.allow_path(dir, nono::AccessMode::Read)?;
            }

            // Add command-specific configured paths. `~` and `$VAR` tokens
            // (including $WORKDIR, $HOME, XDG dirs, and any env var set at
            // launch time such as $GIT_ROOT) are resolved via `expand_vars`
            // so they behave identically to top-level sandbox paths.
            for path in &sb.fs_read {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_dir(caps, &expanded, nono::AccessMode::Read, &cmd_name)?;
            }
            for path in &sb.fs_read_file {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_file(caps, &expanded, nono::AccessMode::Read, &cmd_name)?;
            }
            for path in &sb.fs_write {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_dir(caps, &expanded, nono::AccessMode::Write, &cmd_name)?;
            }
            for path in &sb.fs_write_file {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_file(caps, &expanded, nono::AccessMode::Write, &cmd_name)?;
            }
            // macOS Keychain access: grant read to keychain DB files so the
            // Seatbelt profile skips its mach-lookup denies for security daemons.
            // This allows the command to retrieve credentials from the system
            // keychain without exposing them to the agent (the token flows through
            // the command's internal auth, not stdout).
            #[cfg(target_os = "macos")]
            if sb.keychain_access {
                if let Ok(home) = std::env::var("HOME") {
                    let login = format!("{}/Library/Keychains/login.keychain-db", home);
                    let metadata = format!("{}/Library/Keychains/metadata.keychain-db", home);
                    caps = add_sandbox_file(caps, &login, nono::AccessMode::Read, &cmd_name)?;
                    caps = add_sandbox_file(caps, &metadata, nono::AccessMode::Read, &cmd_name)?;
                }
            }

            if sb.network.block {
                caps = caps.block_network();
            } else if let Some(port) = proxy_port {
                caps = caps.proxy_only(port);
            }

            // Nono is responsible for ensuring sandboxed child processes can always
            // reach the mediation server via its Unix domain socket, regardless of
            // network mode. The shim injected into PATH needs AF_UNIX socket creation
            // (system-socket) and the ability to connect to a unix-socket path
            // (network-outbound). Without these, nested nono-mediated commands (e.g.
            // `git remote -v` called from a git hook) cannot reach the mediation server
            // even under AllowAll network mode, because (deny default) blocks
            // system-socket() calls unless explicitly allowed.
            for rule in [
                "(allow system-socket (socket-domain AF_UNIX))",
                "(allow network-outbound (remote unix-socket))",
            ] {
                if let Err(e) = caps.add_platform_rule(rule) {
                    warn!("mediation: failed to add mediation socket rule: {}", e);
                }
            }
            unsafe {
                cmd_builder.pre_exec(move || {
                    nono::Sandbox::apply(&caps).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string())
                    })
                });
            }
        }

        let mut child = cmd_builder.spawn().map_err(NonoError::CommandExecution)?;

        if !stdin_data.is_empty() {
            if let Some(mut si) = child.stdin.take() {
                let _ = si.write_all(stdin_data.as_bytes());
            }
        }

        let output = child
            .wait_with_output()
            .map_err(NonoError::CommandExecution)?;

        Ok(ShimResponse {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(1),
        })
    })
    .await;

    if let Some(handle) = proxy_handle {
        handle.shutdown();
    }

    match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    }
}

/// Build a filtered shim directory containing symlinks only for commands NOT
/// in the `allow_commands` list. Returns the path and a guard that cleans up
/// on drop. The directory is created under the session dir (derived from the
/// shim_dir's parent) so `SessionHandle::drop` also cleans it up.
fn build_filtered_shim_dir(
    shim_dir: &std::path::Path,
    allow_commands: &[String],
    all_commands: &[ResolvedCommand],
) -> Result<(std::path::PathBuf, FilteredShimDirGuard)> {
    let allow_set: HashSet<&str> = allow_commands.iter().map(|s| s.as_str()).collect();

    // Derive directory under the session dir for automatic cleanup.
    let session_dir = shim_dir
        .parent()
        .ok_or_else(|| NonoError::SandboxInit("mediation: shim_dir has no parent".to_string()))?;
    let counter = FILTERED_SHIM_COUNTER.fetch_add(1, Ordering::Relaxed);
    let filtered_dir = session_dir.join(format!("filtered-shims-{}", counter));

    std::fs::create_dir_all(&filtered_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to create filtered shim dir {}: {}",
            filtered_dir.display(),
            e
        ))
    })?;

    // For each shim in the original shim_dir, symlink it into the filtered dir
    // unless the command is in the allow list.
    let entries = std::fs::read_dir(shim_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to read shim dir {}: {}",
            shim_dir.display(),
            e
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            NonoError::SandboxInit(format!("mediation: failed to read shim dir entry: {}", e))
        })?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if allow_set.contains(name_str.as_ref()) {
            // If the allowed command has its own mediation rules (intercepts or sandbox),
            // keep the shim so it routes through the mediation server. Only exclude
            // commands that have no mediation and should resolve to real binaries directly.
            let has_mediation = all_commands
                .iter()
                .any(|c| c.name == name_str && (!c.intercepts.is_empty() || c.sandbox.is_some()));
            if has_mediation {
                debug!(
                    "mediation: keeping shim for '{}' in filtered dir (has own mediation rules)",
                    name_str
                );
            } else {
                debug!(
                    "mediation: allowing direct exec for '{}' (excluded from filtered shim dir)",
                    name_str
                );
                continue;
            }
        }

        // Symlink the original shim (which itself points to nono-shim)
        let src = entry.path();
        let dst = filtered_dir.join(&name);
        std::os::unix::fs::symlink(&src, &dst).map_err(|e| {
            NonoError::SandboxInit(format!(
                "mediation: failed to symlink {} -> {}: {}",
                dst.display(),
                src.display(),
                e
            ))
        })?;
    }

    // Log the allowed commands and their real paths for auditability.
    for allowed_name in allow_commands {
        if let Some(cmd) = all_commands.iter().find(|c| c.name == *allowed_name) {
            debug!(
                "mediation: allow_commands '{}' -> {} (direct exec in per-command sandbox)",
                allowed_name,
                cmd.real_path.display()
            );
        }
    }

    let guard = FilteredShimDirGuard {
        path: filtered_dir.clone(),
    };
    Ok((filtered_dir, guard))
}

/// RAII guard that removes the filtered shim directory on drop.
/// The session dir cleanup also handles this, but this ensures prompt cleanup
/// when the exec_passthrough call completes.
struct FilteredShimDirGuard {
    path: std::path::PathBuf,
}

impl Drop for FilteredShimDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Expand `~` and `$VAR` / `${VAR}` tokens in a per-command sandbox path.
///
/// Delegates to `crate::profile::expand_vars`, which matches the main-sandbox
/// expansion (supports `$WORKDIR`, `$HOME`, XDG vars, `$TMPDIR`, `$UID`, and
/// generic env vars). On failure (e.g. invalid `$HOME`), falls back to the
/// raw path — `add_sandbox_*` will then log "does not exist, skipping" which
/// is the same outcome as an unset variable. This preserves robustness: a
/// misconfigured env var in one entry never aborts the whole session.
fn expand_sandbox_path(path: &str, workdir: &std::path::Path, cmd_name: &str) -> String {
    match crate::profile::expand_vars(path, workdir) {
        Ok(buf) => buf.to_string_lossy().into_owned(),
        Err(e) => {
            warn!(
                "mediation: command '{}' failed to expand sandbox path '{}': {}",
                cmd_name, path, e
            );
            path.to_string()
        }
    }
}

/// Add a directory capability to the sandbox.
/// Warns and skips on non-existent paths.
fn add_sandbox_dir(
    caps: nono::CapabilitySet,
    path: &str,
    access: nono::AccessMode,
    command_name: &str,
) -> Result<nono::CapabilitySet> {
    match nono::FsCapability::new_dir(path, access) {
        Ok(cap) => {
            let mut caps = caps;
            caps.add_fs(cap);
            Ok(caps)
        }
        Err(NonoError::PathNotFound(_)) => {
            warn!(
                "mediation: command '{}' sandbox dir '{}' does not exist, skipping",
                command_name, path
            );
            Ok(caps)
        }
        Err(e) => Err(e),
    }
}

/// Add a file capability to the sandbox.
/// Warns and skips on non-existent paths.
fn add_sandbox_file(
    caps: nono::CapabilitySet,
    path: &str,
    access: nono::AccessMode,
    command_name: &str,
) -> Result<nono::CapabilitySet> {
    match nono::FsCapability::new_file(path, access) {
        Ok(cap) => {
            let mut caps = caps;
            caps.add_fs(cap);
            Ok(caps)
        }
        Err(NonoError::PathNotFound(_)) => {
            warn!(
                "mediation: command '{}' sandbox file '{}' does not exist, skipping",
                command_name, path
            );
            Ok(caps)
        }
        Err(e) => Err(e),
    }
}

/// Build the environment map for an exec'd child.
///
/// Starts from the trusted parent env, then promotes nonce-bearing sandbox vars.
/// Non-nonce sandbox vars and dangerous var names are silently discarded.
fn build_exec_env(
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
) -> HashMap<String, String> {
    // Start from parent (trusted) env
    let mut env: HashMap<String, String> = std::env::vars().collect();

    // From sandbox env: promote nonce-bearing vars and forward all other non-dangerous
    // vars. If a var was not blocked by the profile's `env.block` list it is permitted
    // to flow through to mediated commands. System execution vars (PATH, LD_PRELOAD,
    // etc.) are always blocked as defense-in-depth regardless of profile configuration.
    for (key, value) in sandbox_env {
        if DANGEROUS_ENV_VAR_NAMES.contains(&key.as_str()) {
            warn!("mediation: blocked dangerous var {} from sandbox env", key);
            continue;
        }
        if value.starts_with("nono_") {
            if let Some(real) = broker.resolve(value) {
                env.insert(key.clone(), real.as_str().to_string());
            }
            // Unknown nonce: silently discard — don't let sandbox probe broker contents.
        } else {
            env.insert(key.clone(), value.clone());
        }
    }

    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::approval::{AlwaysAllow, AlwaysDeny};
    use crate::mediation::session::{ResolvedCommand, ResolvedIntercept};
    use std::path::PathBuf;

    fn make_broker() -> Arc<TokenBroker> {
        Arc::new(TokenBroker::new())
    }

    fn always_allow() -> Arc<dyn ApprovalGate + Send + Sync> {
        Arc::new(AlwaysAllow)
    }

    fn always_deny() -> Arc<dyn ApprovalGate + Send + Sync> {
        Arc::new(AlwaysDeny)
    }

    fn make_cmd(intercepts: Vec<ResolvedIntercept>) -> ResolvedCommand {
        ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            intercepts,
            sandbox: None,
        }
    }

    #[tokio::test]
    async fn test_unknown_command_returns_127() {
        let req = ShimRequest {
            command: "doesnotexist".to_string(),
            args: vec![],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply(
            req,
            &[],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 127);
    }

    #[tokio::test]
    async fn test_intercept_respond_exact_prefix_match() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec![
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ],
            action: ResolvedAction::Respond {
                stdout: "static_output\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "static_output\n");
    }

    #[tokio::test]
    async fn test_intercept_prefix_matches_longer_args() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            action: ResolvedAction::Respond {
                stdout: "matched\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string(), "github".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "matched\n");
    }

    #[tokio::test]
    async fn test_no_intercept_match_falls_through() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string(), "github".to_string()],
            action: ResolvedAction::Respond {
                stdout: "secret\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["status".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };
        // Falls through to passthrough exec of /usr/bin/true
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
    }

    #[tokio::test]
    async fn test_admin_rule_allow_proceeds() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["repo".to_string(), "delete".to_string()],
            action: ResolvedAction::Respond {
                stdout: "deleted\n".to_string(),
            },
            exit_code: 0,
            admin: true,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["repo".to_string(), "delete".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "deleted\n");
    }

    #[tokio::test]
    async fn test_admin_rule_deny_blocks() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["repo".to_string(), "delete".to_string()],
            action: ResolvedAction::Respond {
                stdout: "deleted\n".to_string(),
            },
            exit_code: 0,
            admin: true,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["repo".to_string(), "delete".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_deny(),
        )
        .await;
        assert_eq!(resp.exit_code, 126);
        assert!(resp.stderr.contains("was not approved"));
    }

    #[tokio::test]
    async fn test_non_admin_rule_skips_gate() {
        // admin=false rule with AlwaysDeny gate — gate must NOT be called, action executes.
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["status".to_string()],
            action: ResolvedAction::Respond {
                stdout: "ok\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["status".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_deny(),
        )
        .await;
        // Gate not consulted; action executes normally.
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "ok\n");
    }

    // --- subcommand_matches tests ---

    #[test]
    fn test_subcommand_matches_basic() {
        assert!(subcommand_matches(
            &["a".to_string(), "b".to_string()],
            &["a".to_string(), "b".to_string(), "c".to_string()]
        ));
        assert!(subcommand_matches(&[], &["a".to_string()]));
        assert!(!subcommand_matches(
            &["a".to_string(), "b".to_string()],
            &["a".to_string()]
        ));
        assert!(!subcommand_matches(&["a".to_string()], &["b".to_string()]));
    }

    #[test]
    fn test_subcommand_matches_ignores_leading_flags() {
        // --debug before positional args should not break matching
        assert!(subcommand_matches(
            &[
                "auth".to_string(),
                "github".to_string(),
                "token".to_string()
            ],
            &[
                "--debug".to_string(),
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ]
        ));
    }

    #[test]
    fn test_subcommand_matches_ignores_interleaved_flags() {
        // flags between subcommands should be ignored
        assert!(subcommand_matches(
            &["auth".to_string(), "github".to_string()],
            &[
                "auth".to_string(),
                "--verbose".to_string(),
                "github".to_string(),
            ]
        ));
    }

    #[test]
    fn test_subcommand_matches_empty_prefix_matches_anything() {
        assert!(subcommand_matches(&[], &[]));
        assert!(subcommand_matches(&[], &["anything".to_string()]));
    }

    #[test]
    fn test_subcommand_matches_flag_value_injection_does_not_defeat_prefix() {
        // Inserting a flag+value pair inserts an extra positional ("kipz"),
        // which shifts real positionals and defeats a prefix that relied on
        // their positions. This test documents the known limitation:
        // profiles must not rely on a value arg appearing at a specific
        // positional index — use a catch-all prefix for the subcommand instead.
        assert!(!subcommand_matches(
            &[
                "find-generic-password".to_string(),
                "gh:github.com".to_string(),
            ],
            &[
                "find-generic-password".to_string(),
                "-a".to_string(),
                "kipz".to_string(), // injected positional shifts "gh:github.com"
                "-s".to_string(),
                "gh:github.com".to_string(),
                "-w".to_string(),
            ]
        ));
    }

    // --- Capture tests ---

    #[tokio::test]
    async fn test_capture_runs_real_binary_and_returns_nonce() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            action: ResolvedAction::Capture { script: None },
            exit_code: 0,
            admin: false,
        }]);
        // Use a command that outputs something: `echo hello` → "hello"
        let cmd = ResolvedCommand {
            real_path: PathBuf::from("/bin/echo"),
            ..cmd
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            // args passed to echo: "auth" "hello" → output "auth hello"
            args: vec!["auth".to_string(), "hello".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };
        let broker = make_broker();
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert!(
            resp.stdout.trim().starts_with("nono_"),
            "stdout was: {}",
            resp.stdout
        );
        // The nonce resolves to the trimmed stdout of `echo auth hello`
        let nonce = resp.stdout.trim();
        let resolved = broker.resolve(nonce).expect("nonce should be in broker");
        assert_eq!(resolved.as_str(), "auth hello");
    }

    #[tokio::test]
    async fn test_capture_script_returns_nonce() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            action: ResolvedAction::Capture {
                script: Some("echo my_secret_token".to_string()),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };
        let broker = make_broker();
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        let nonce = resp.stdout.trim();
        assert!(nonce.starts_with("nono_"), "expected nonce, got: {}", nonce);
        let resolved = broker.resolve(nonce).expect("nonce should be in broker");
        assert_eq!(resolved.as_str(), "my_secret_token");
    }

    // --- Env filtering tests ---

    #[test]
    fn test_build_exec_env_forwards_context_vars_and_blocks_dangerous() {
        let broker = make_broker();
        let mut sandbox_env = HashMap::new();
        // Dangerous vars must never be forwarded.
        sandbox_env.insert("PATH".to_string(), "/evil".to_string());
        sandbox_env.insert("LD_PRELOAD".to_string(), "/evil.so".to_string());
        // Non-dangerous context vars (e.g. from kubectl exec plugin config) should
        // be forwarded when not already in the parent env. Use an unlikely-to-exist key.
        sandbox_env.insert(
            "NONO_TEST_CONTEXT_12345".to_string(),
            "context_value".to_string(),
        );

        let env = build_exec_env(&sandbox_env, &broker);

        // Dangerous vars must not be injected from sandbox.
        assert_ne!(env.get("PATH").map(|s| s.as_str()), Some("/evil"));
        assert_ne!(env.get("LD_PRELOAD").map(|s| s.as_str()), Some("/evil.so"));
        // Non-dangerous context var should be forwarded.
        assert_eq!(
            env.get("NONO_TEST_CONTEXT_12345").map(|s| s.as_str()),
            Some("context_value")
        );
    }

    #[test]
    fn test_build_exec_env_promotes_valid_nonce() {
        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("real_credential".to_string()));

        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("GH_TOKEN".to_string(), nonce.clone());

        let env = build_exec_env(&sandbox_env, &broker);
        assert_eq!(
            env.get("GH_TOKEN").map(|s| s.as_str()),
            Some("real_credential")
        );
    }

    #[test]
    fn test_build_exec_env_blocks_dangerous_var_even_with_valid_nonce() {
        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("/evil/path".to_string()));

        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("PATH".to_string(), nonce.clone());
        sandbox_env.insert("LD_PRELOAD".to_string(), nonce.clone());

        let env = build_exec_env(&sandbox_env, &broker);
        // PATH from sandbox must not be the injected value (parent PATH is used instead)
        assert_ne!(env.get("PATH").map(|s| s.as_str()), Some("/evil/path"));
        // LD_PRELOAD should not have been injected
        assert_ne!(
            env.get("LD_PRELOAD").map(|s| s.as_str()),
            Some("/evil/path")
        );
    }

    #[test]
    fn test_build_exec_env_discards_unknown_nonce() {
        let broker = make_broker();
        let mut sandbox_env = HashMap::new();
        // A nonce-like value that was never issued
        sandbox_env.insert(
            "MY_TOKEN".to_string(),
            "nono_0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        let env = build_exec_env(&sandbox_env, &broker);
        // Unknown nonce: var should not be set to any nonce value
        assert_ne!(
            env.get("MY_TOKEN").map(|s| s.as_str()),
            Some("nono_0000000000000000000000000000000000000000000000000000000000000000")
        );
    }

    // --- Filtered shim dir tests ---

    #[test]
    fn test_filtered_shim_dir_excludes_allowed_commands() {
        // Create a temporary shim directory with some shim files
        let session_dir = tempfile::tempdir().expect("create temp dir");
        let shim_dir = session_dir.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("create shim dir");

        // Create fake shim files
        for name in &["gh", "ddtool", "kubectl"] {
            std::fs::write(shim_dir.join(name), "fake-shim").expect("write shim");
        }

        let commands = vec![
            ResolvedCommand {
                name: "gh".to_string(),
                real_path: PathBuf::from("/usr/bin/gh"),
                intercepts: vec![],
                sandbox: None,
            },
            ResolvedCommand {
                name: "ddtool".to_string(),
                real_path: PathBuf::from("/opt/homebrew/bin/ddtool"),
                intercepts: vec![],
                sandbox: None,
            },
            ResolvedCommand {
                name: "kubectl".to_string(),
                real_path: PathBuf::from("/usr/local/bin/kubectl"),
                intercepts: vec![],
                sandbox: None,
            },
        ];

        let allow_commands = vec!["ddtool".to_string()];

        let (filtered_dir, _guard) = build_filtered_shim_dir(&shim_dir, &allow_commands, &commands)
            .expect("build filtered shim dir");

        // ddtool should NOT be in the filtered dir (it's allowed)
        assert!(
            !filtered_dir.join("ddtool").exists(),
            "ddtool should be excluded from filtered shim dir"
        );
        // gh and kubectl should be symlinked
        assert!(
            filtered_dir.join("gh").exists(),
            "gh should be in filtered shim dir"
        );
        assert!(
            filtered_dir.join("kubectl").exists(),
            "kubectl should be in filtered shim dir"
        );
    }

    #[test]
    fn test_filtered_shim_dir_empty_allow_commands_copies_all() {
        let session_dir = tempfile::tempdir().expect("create temp dir");
        let shim_dir = session_dir.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("create shim dir");

        for name in &["gh", "ddtool"] {
            std::fs::write(shim_dir.join(name), "fake-shim").expect("write shim");
        }

        let commands = vec![];
        // This function should not normally be called with empty allow_commands,
        // but if it is, all shims should be present.
        let allow_commands: Vec<String> = vec![];
        let (filtered_dir, _guard) = build_filtered_shim_dir(&shim_dir, &allow_commands, &commands)
            .expect("build filtered shim dir");

        assert!(filtered_dir.join("gh").exists());
        assert!(filtered_dir.join("ddtool").exists());
    }

    /// When `allow_commands` is set, `exec_passthrough` creates a filtered shim dir
    /// and sets NONO_SHIM_DIR to that dir. This ensures nono-shim's
    /// `resolve_real_binary` skips the correct directory and doesn't exec itself
    /// recursively (which would cause EAGAIN).
    #[tokio::test]
    async fn test_allow_commands_sets_nono_shim_dir_to_filtered_dir() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;
        use std::os::unix::fs::PermissionsExt;

        let session_dir = tempfile::tempdir().expect("create temp dir");
        let shim_dir = session_dir.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("create shim dir");

        // Create fake shim files (need to exist for build_filtered_shim_dir)
        for name in &["gh", "ddtool"] {
            let p = shim_dir.join(name);
            std::fs::write(&p, "fake-shim").expect("write shim");
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
                .expect("chmod shim");
        }

        let cmd = ResolvedCommand {
            name: "gh".to_string(),
            // Use /usr/bin/env so the child process prints its own environment.
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig::default(),
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec!["ddtool".to_string()],
                keychain_access: false,
            }),
        };

        // Provide a ddtool entry so build_filtered_shim_dir can find its real path.
        let ddtool_cmd = ResolvedCommand {
            name: "ddtool".to_string(),
            real_path: PathBuf::from("/opt/homebrew/bin/ddtool"),
            intercepts: vec![],
            sandbox: None,
        };

        let req = ShimRequest {
            command: "gh".to_string(),
            args: vec![],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };

        let broker = make_broker();
        let (resp, _action_type) = apply(
            req,
            &[cmd, ddtool_cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: &shim_dir,
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);

        // Extract the value of NONO_SHIM_DIR from the child's printed environment.
        let shim_dir_line = resp
            .stdout
            .lines()
            .find(|l| l.starts_with("NONO_SHIM_DIR="))
            .expect("NONO_SHIM_DIR not found in env output");
        let child_shim_dir = shim_dir_line.trim_start_matches("NONO_SHIM_DIR=");

        // NONO_SHIM_DIR must NOT be the original shims/ directory — it should
        // be the filtered shim dir created by exec_passthrough.
        assert_ne!(
            child_shim_dir,
            shim_dir.to_string_lossy().as_ref(),
            "NONO_SHIM_DIR should be the filtered dir, not the original shim dir"
        );

        // NONO_SHIM_DIR must also be at the front of PATH so resolve_real_binary
        // in the shim finds it first when skipping its own directory.
        let path_line = resp
            .stdout
            .lines()
            .find(|l| l.starts_with("PATH="))
            .expect("PATH not found in env output");
        let child_path = path_line.trim_start_matches("PATH=");
        assert!(
            child_path.starts_with(child_shim_dir),
            "PATH should start with NONO_SHIM_DIR ({}), got: {}",
            child_shim_dir,
            child_path
        );
    }

    // --- Per-command proxy tests ---

    /// When `allowed_hosts` is configured, exec_passthrough injects HTTPS_PROXY
    /// pointing to 127.0.0.1 into the environment passed to the command.
    #[tokio::test]
    async fn test_allowed_hosts_injects_https_proxy() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            }),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            // `env` prints its own environment; grep output for HTTPS_PROXY
            args: vec![],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };

        let broker = make_broker();
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        // The command ran (exit 0) and output should contain HTTPS_PROXY pointing to 127.0.0.1
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "HTTPS_PROXY not found in env output: {}",
            resp.stdout
        );
        assert!(
            resp.stdout.contains("127.0.0.1"),
            "proxy addr not 127.0.0.1: {}",
            resp.stdout
        );
    }

    /// When `block: true` and `allowed_hosts` is also set, `block` takes
    /// precedence: no proxy is started, network is blocked at OS level.
    /// We verify this by checking the env printed by the child does NOT
    /// contain an HTTPS_PROXY entry.
    #[tokio::test]
    async fn test_block_takes_precedence_over_allowed_hosts() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec!["github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            }),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            stdin: String::new(),
            session_token: String::new(),
            ..Default::default()
        };

        let broker = make_broker();
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;
        // Command may fail due to sandbox (network block applies via pre_exec),
        // but crucially HTTPS_PROXY must NOT have been injected.
        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "HTTPS_PROXY should not be set when block=true, got: {}",
            resp.stdout
        );
    }

    /// Approve action does NOT apply the per-command sandbox. The real binary
    /// needs unrestricted access to system resources (e.g. macOS Keychain via
    /// mach-lookup to securityd). Protection comes from the profile author's
    /// deliberate choice of which commands get `approve`.
    ///
    /// We verify by checking that HTTPS_PROXY is NOT injected even when the
    /// command has `allowed_hosts` configured, proving the sandbox was skipped.
    #[tokio::test]
    async fn test_approve_does_not_apply_per_command_sandbox() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![ResolvedIntercept {
                args_prefix: vec![],
                action: ResolvedAction::Approve { script: None },
                exit_code: 0,
                admin: false,
            }],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["api.github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            }),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };

        let broker = make_broker();
        let (resp, action_type) = apply(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "approve");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        // HTTPS_PROXY must NOT be present — approve runs without per-command sandbox.
        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "Approve action should NOT apply per-command sandbox, but HTTPS_PROXY found: {}",
            resp.stdout
        );
    }

    // --- keychain_access tests ---

    /// Passthrough with `keychain_access: true` and `allowed_hosts` runs
    /// successfully and still applies network restrictions (HTTPS_PROXY).
    /// Proves keychain_access doesn't break the sandbox or disable network filtering.
    #[tokio::test]
    async fn test_passthrough_keychain_access_with_allowed_hosts() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["api.github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: true,
            }),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };

        let broker = make_broker();
        let (resp, action_type) = apply(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "passthrough");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "keychain_access should not disable network restrictions, HTTPS_PROXY missing: {}",
            resp.stdout
        );
    }

    /// Passthrough with `keychain_access: false` (default) and `allowed_hosts`
    /// preserves existing behavior: runs successfully with network restrictions.
    #[tokio::test]
    async fn test_passthrough_keychain_access_false_default() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["api.github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: false,
            }),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };

        let broker = make_broker();
        let (resp, action_type) = apply(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "passthrough");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "Default keychain_access=false should still apply network restrictions: {}",
            resp.stdout
        );
    }

    /// `keychain_access: true` with `network.block: true` — block takes
    /// precedence, no proxy started, HTTPS_PROXY not injected.
    /// Proves keychain_access doesn't interfere with network block mode.
    #[tokio::test]
    async fn test_keychain_access_does_not_disable_network_block() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec!["github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                allow_commands: vec![],
                keychain_access: true,
            }),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };

        let broker = make_broker();
        let (resp, _action_type) = apply(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
            },
            always_allow(),
        )
        .await;

        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "keychain_access should not override network block, but HTTPS_PROXY found: {}",
            resp.stdout
        );
    }
}
