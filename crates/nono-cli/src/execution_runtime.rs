use crate::launch_runtime::{select_threading_context, LaunchPlan};
use crate::proxy_runtime::start_proxy_runtime;
use crate::supervised_runtime::{execute_supervised_runtime, SupervisedRuntimeContext};
use crate::{command_blocking_deprecation, config, exec_strategy, output, sandbox_state, session};
use nono::{CapabilitySet, NonoError, Result, Sandbox};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{error, info};

const PROFILE_HINT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

fn apply_pre_fork_sandbox(
    strategy: exec_strategy::ExecStrategy,
    caps: &CapabilitySet,
    silent: bool,
) -> Result<()> {
    if matches!(strategy, exec_strategy::ExecStrategy::Direct) {
        output::print_applying_sandbox(silent);

        #[cfg(target_os = "linux")]
        {
            let detected = Sandbox::detect_abi()?;
            info!("Direct mode: detected {}", detected);
            Sandbox::apply_with_abi(caps, &detected)?;
        }

        #[cfg(not(target_os = "linux"))]
        {
            Sandbox::apply(caps)?;
        }

        output::print_sandbox_active(silent);
    }
    Ok(())
}

fn cleanup_capability_state_file(cap_file_path: &std::path::Path) {
    if cap_file_path.exists() {
        let _ = std::fs::remove_file(cap_file_path);
    }
}

fn next_capability_state_file_path() -> std::path::PathBuf {
    use rand::RngExt;

    let mut rng = rand::rng();
    let bytes: [u8; 8] = rng.random();
    let suffix = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    std::env::temp_dir().join(format!(".nono-{suffix}.json"))
}

pub(crate) fn execution_start_dir(
    workdir: &std::path::Path,
    caps: &CapabilitySet,
) -> Result<std::path::PathBuf> {
    let workdir_canonical =
        workdir
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: workdir.to_path_buf(),
                source: e,
            })?;

    if caps.path_covered(&workdir_canonical) {
        Ok(workdir_canonical)
    } else {
        Ok(std::path::PathBuf::from("/"))
    }
}

fn recommended_builtin_profile(program: &Path) -> Option<&'static str> {
    let name = program.file_name()?.to_str()?;
    match name {
        "claude" => Some("claude-code"),
        "codex" => Some("codex"),
        "opencode" => Some("opencode"),
        "openclaw" => Some("openclaw"),
        "swival" => Some("swival"),
        _ => None,
    }
}

fn should_apply_startup_timeout(
    recommended_profile: Option<&str>,
    cmd_args: &[impl AsRef<std::ffi::OsStr>],
) -> bool {
    recommended_profile.is_some() && cmd_args.is_empty()
}

pub(crate) fn execute_sandboxed(plan: LaunchPlan) -> Result<()> {
    let LaunchPlan {
        program,
        cmd_args,
        mut caps,
        loaded_secrets,
        flags,
    } = plan;
    let rollback = &flags.rollback;
    let trust = &flags.trust;
    let proxy = &flags.proxy;
    let session = &flags.session;

    if let Some(blocked) =
        config::check_blocked_command(&program, caps.allowed_commands(), caps.blocked_commands())?
    {
        return Err(NonoError::BlockedCommand {
            command: blocked,
            reason: command_blocking_deprecation::BLOCKED_COMMAND_REASON.to_string(),
        });
    }

    let command: Vec<String> = std::iter::once(program.to_string_lossy().into_owned())
        .chain(
            cmd_args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned()),
        )
        .collect();

    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let resolved_program = exec_strategy::resolve_program(&command[0])?;
    let recommended_profile = if flags.session.profile_name.is_none() {
        recommended_builtin_profile(&resolved_program)
    } else {
        None
    };

    let recommended_program_name = resolved_program
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&command[0]);

    if let Some(profile) = recommended_profile {
        output::print_profile_hint(recommended_program_name, profile, flags.silent);
    }
    let cap_file = write_capability_state_file(&caps, &flags.override_deny_paths, flags.silent);
    let cap_file_path = cap_file.unwrap_or_else(|| std::path::PathBuf::from("/dev/null"));

    for secret in &loaded_secrets {
        if exec_strategy::is_dangerous_env_var(&secret.env_var) {
            return Err(NonoError::ConfigParse(format!(
                "secret mapping targets dangerous environment variable: {}",
                secret.env_var
            )));
        }
    }

    let strategy = flags.strategy;

    if matches!(strategy, exec_strategy::ExecStrategy::Supervised) {
        output::print_supervised_info(flags.silent, rollback.requested, proxy.active);
    }

    let active_proxy = start_proxy_runtime(proxy, &mut caps, &flags.workdir)?;
    let proxy_env_vars = active_proxy.env_vars;
    let proxy_handle = active_proxy.handle;

    // Build session audit context before mediation setup.
    // session_id and session_name must be consistent between the mediation audit
    // log and the session record written by supervised_runtime.
    let mediation_session_id = std::env::var(crate::DETACHED_SESSION_ID_ENV)
        .ok()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(session::generate_session_id);
    let mediation_session_name = flags
        .session
        .session_name
        .clone()
        .unwrap_or_else(session::generate_random_name);
    let sandboxed_pid_latch: Arc<OnceLock<u32>> = Arc::new(OnceLock::new());
    let audit_info = crate::mediation::SessionAuditInfo {
        session_id: mediation_session_id.clone(),
        session_name: Some(mediation_session_name.clone()),
        nono_pid: std::process::id(),
        sandboxed_pid: Arc::clone(&sandboxed_pid_latch),
    };

    // Set up command mediation (shim dir, server, env blocking) before sandbox.
    // The workdir is threaded through so per-command sandbox paths that
    // reference `$WORKDIR` / `$VAR` resolve against the same directory the
    // main sandbox uses. `audit_info` stamps session/PID context on every
    // audit entry.
    let mediation_handle =
        crate::mediation::session::setup(&flags.mediation, flags.workdir.clone(), audit_info)?;

    // If mediation is active, add shim directory and binary to sandbox rules.
    let mediation_path_str;
    let mediation_socket_str;
    let mediation_token_str;
    let mut mediation_env_block: Vec<String> = Vec::new();
    if let Some(ref handle) = mediation_handle {
        // Prepend shim dir to PATH so the agent calls our shims instead of real binaries.
        mediation_path_str = handle.shim_dir.display().to_string();
        mediation_socket_str = handle.socket_path.display().to_string();
        mediation_token_str = handle.session_token.to_string();
        mediation_env_block = handle.env_block.clone();

        // Allow sandbox to read the shim binary and session directory.
        caps.add_fs(
            nono::FsCapability::new_dir(&handle.shim_dir, nono::AccessMode::Read)
                .map_err(|e| nono::NonoError::SandboxInit(format!("mediation shim dir: {e}")))?,
        );
        caps.add_fs(
            nono::FsCapability::new_file(&handle.shim_binary, nono::AccessMode::Read)
                .map_err(|e| nono::NonoError::SandboxInit(format!("mediation shim binary: {e}")))?,
        );
        // Allow sandbox to access the session directory (contains the mediation
        // and audit sockets, created asynchronously by the server).
        caps.add_fs(
            nono::FsCapability::new_dir(&handle.session_dir, nono::AccessMode::ReadWrite)
                .map_err(|e| nono::NonoError::SandboxInit(format!("mediation session dir: {e}")))?,
        );

        info!(
            "Mediation session active: {} commands mediated, shim_dir={}",
            handle.mediated_commands.len(),
            handle.shim_dir.display()
        );
    } else {
        mediation_path_str = String::new();
        mediation_socket_str = String::new();
        mediation_token_str = String::new();
    }

    let current_dir = execution_start_dir(&flags.workdir, &caps)?;
    apply_pre_fork_sandbox(strategy, &caps, flags.silent)?;

    let mut env_vars: Vec<(&str, &str)> = loaded_secrets
        .iter()
        .map(|secret| (secret.env_var.as_str(), secret.value.as_str()))
        .collect();
    for (key, value) in &proxy_env_vars {
        env_vars.push((key.as_str(), value.as_str()));
    }

    // Inject mediation env vars: session token, socket path, and prepend shim dir to PATH.
    let mediation_path_value;
    let mediation_commands_str;
    let mediation_audit_socket_str;
    if let Some(ref handle) = mediation_handle {
        env_vars.push(("NONO_SESSION_TOKEN", &mediation_token_str));
        env_vars.push(("NONO_MEDIATION_SOCKET", &mediation_socket_str));
        env_vars.push(("NONO_SHIM_DIR", &mediation_path_str));
        // Tell shims which commands use full mediation vs audit-only passthrough.
        mediation_commands_str = handle.mediated_commands.join(",");
        env_vars.push(("NONO_MEDIATED_COMMANDS", &mediation_commands_str));
        // Audit socket for fire-and-forget command logging.
        mediation_audit_socket_str = handle.audit_socket_path.display().to_string();
        env_vars.push(("NONO_AUDIT_SOCKET", &mediation_audit_socket_str));
        // Prepend the mediation shim directory to PATH so the agent resolves
        // mediated commands to our shims instead of the real binaries.
        let current_path = std::env::var("PATH").unwrap_or_default();
        mediation_path_value = format!("{}:{current_path}", mediation_path_str);
        env_vars.push(("PATH", &mediation_path_value));
    }

    let threading = select_threading_context(
        !loaded_secrets.is_empty(),
        proxy.active,
        trust.scan_performed,
        trust.interception_active,
    );

    info!(
        "Executing with strategy: {:?}, threading: {:?}",
        strategy, threading
    );

    #[cfg(target_os = "linux")]
    let seccomp_proxy_fallback = {
        let needs_proxy = matches!(caps.network_mode(), nono::NetworkMode::ProxyOnly { .. });
        if needs_proxy && nono::is_wsl2() {
            let needs_seccomp_fallback = !Sandbox::detect_abi()
                .ok()
                .is_some_and(|abi| abi.has_network());
            if needs_seccomp_fallback {
                match flags.wsl2_proxy_policy {
                    crate::profile::Wsl2ProxyPolicy::Error => {
                        return Err(NonoError::SandboxInit(
                            "WSL2: proxy-only network mode cannot be kernel-enforced. \
                             seccomp user notification returns EBUSY on WSL2 and Landlock V4 \
                             (per-port TCP filtering) is not available on this kernel.\n\n\
                             The sandboxed process would be able to bypass the credential proxy \
                             and open arbitrary outbound connections.\n\n\
                             To allow degraded execution (credential proxy without network lockdown), \
                             set wsl2_proxy_policy: \"insecure_proxy\" in your profile's security config.\n\n\
                             See: https://nono.sh/docs/cli/internals/wsl2"
                                .to_string(),
                        ));
                    }
                    crate::profile::Wsl2ProxyPolicy::InsecureProxy => {
                        eprintln!(
                            "  [nono] WARNING: WSL2 insecure proxy mode — credential proxy active \
                             but network is NOT kernel-enforced. The sandboxed process can bypass \
                             the proxy and open arbitrary outbound connections."
                        );
                    }
                }
            }
            false
        } else if needs_proxy {
            !Sandbox::detect_abi()
                .ok()
                .is_some_and(|abi| abi.has_network())
        } else {
            false
        }
    };

    let config = exec_strategy::ExecConfig {
        command: &command,
        resolved_program: &resolved_program,
        caps: &caps,
        env_vars,
        cap_file: &cap_file_path,
        current_dir: &current_dir,
        no_diagnostics: flags.no_diagnostics || flags.silent,
        threading,
        protected_paths: &trust.protected_paths,
        startup_timeout: if should_apply_startup_timeout(recommended_profile, &cmd_args) {
            recommended_profile.map(|profile| exec_strategy::StartupTimeoutConfig {
                timeout: PROFILE_HINT_STARTUP_TIMEOUT,
                program: recommended_program_name,
                profile,
            })
        } else {
            None
        },
        capability_elevation: flags.capability_elevation,
        #[cfg(target_os = "linux")]
        seccomp_proxy_fallback,
        allowed_env_vars: flags.allowed_env_vars,
        extra_blocked_env: &mediation_env_block,
    };

    match strategy {
        exec_strategy::ExecStrategy::Direct => {
            exec_strategy::execute_direct(&config)?;
            unreachable!("execute_direct only returns on error");
        }
        exec_strategy::ExecStrategy::Supervised => {
            let exit_code = execute_supervised_runtime(SupervisedRuntimeContext {
                config: &config,
                caps: &caps,
                command: &command,
                session,
                rollback,
                trust,
                proxy,
                proxy_handle: proxy_handle.as_ref(),
                silent: flags.silent,
                pre_session_id: Some(mediation_session_id),
                pre_session_name: Some(mediation_session_name),
                mediation_sandboxed_pid_latch: mediation_handle
                    .as_ref()
                    .map(|_| Arc::clone(&sandboxed_pid_latch)),
            })?;

            cleanup_capability_state_file(&cap_file_path);
            drop(config);
            drop(loaded_secrets);
            std::process::exit(exit_code);
        }
    }
}

fn write_capability_state_file(
    caps: &CapabilitySet,
    override_deny_paths: &[std::path::PathBuf],
    silent: bool,
) -> Option<std::path::PathBuf> {
    let state = sandbox_state::SandboxState::from_caps(caps, override_deny_paths);

    for _ in 0..8 {
        let cap_file = next_capability_state_file_path();
        match state.write_to_file(&cap_file) {
            Ok(()) => return Some(cap_file),
            Err(NonoError::ConfigWrite { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                continue;
            }
            Err(e) => {
                error!(
                    "Failed to write capability state file: {}. \
                     Sandboxed processes will not be able to query their own capabilities using 'nono why --self'.",
                    e
                );
                if !silent {
                    eprintln!(
                        "  WARNING: Capability state file could not be written.\n  \
                         The sandbox is active, but 'nono why --self' will not work inside this sandbox."
                    );
                }
                return None;
            }
        }
    }

    error!(
        "Failed to allocate a unique capability state file after repeated collisions. \
         Sandboxed processes will not be able to query their own capabilities using 'nono why --self'."
    );
    if !silent {
        eprintln!(
            "  WARNING: Capability state file could not be written.\n  \
             The sandbox is active, but 'nono why --self' will not work inside this sandbox."
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{recommended_builtin_profile, should_apply_startup_timeout};
    use std::path::Path;

    #[test]
    fn recommended_builtin_profile_matches_known_agent_commands() {
        assert_eq!(
            recommended_builtin_profile(Path::new("/usr/local/bin/claude")),
            Some("claude-code")
        );
        assert_eq!(
            recommended_builtin_profile(Path::new("/usr/local/bin/codex")),
            Some("codex")
        );
    }

    #[test]
    fn recommended_builtin_profile_ignores_unknown_commands() {
        assert_eq!(recommended_builtin_profile(Path::new("/usr/bin/env")), None);
    }

    #[test]
    fn startup_timeout_applies_only_to_bare_interactive_profiled_tools() {
        let no_args: [&str; 0] = [];
        assert!(should_apply_startup_timeout(Some("claude-code"), &no_args));
        assert!(!should_apply_startup_timeout(
            Some("claude-code"),
            &["--version"]
        ));
        assert!(!should_apply_startup_timeout(None, &no_args));
    }
}
