use crate::launch_runtime::{
    ProxyLaunchOptions, RollbackLaunchOptions, SessionLaunchOptions, TrustLaunchOptions,
};
use crate::rollback_runtime::{
    create_audit_state, finalize_supervised_exit, initialize_rollback_state,
    warn_if_rollback_flags_ignored, AuditState, RollbackExitContext,
};
use std::sync::{Arc, OnceLock};

use crate::{
    exec_strategy, output, protected_paths, pty_proxy, session, terminal_approval, trust_intercept,
    DETACHED_SESSION_ID_ENV,
};
use colored::Colorize;
use nono::{CapabilitySet, Result};

struct SessionRuntimeState {
    started: String,
    short_session_id: String,
    session_guard: Option<session::SessionGuard>,
    pty_pair: Option<pty_proxy::PtyPair>,
}

pub(crate) struct SupervisedRuntimeContext<'a> {
    pub(crate) config: &'a exec_strategy::ExecConfig<'a>,
    pub(crate) caps: &'a CapabilitySet,
    pub(crate) command: &'a [String],
    pub(crate) session: &'a SessionLaunchOptions,
    pub(crate) rollback: &'a RollbackLaunchOptions,
    pub(crate) trust: &'a TrustLaunchOptions,
    pub(crate) proxy: &'a ProxyLaunchOptions,
    pub(crate) proxy_handle: Option<&'a nono_proxy::server::ProxyHandle>,
    pub(crate) silent: bool,
    /// Pre-generated session ID from execution_runtime, shared with the mediation audit log.
    pub(crate) pre_session_id: Option<String>,
    /// Pre-generated session name from execution_runtime, shared with the mediation audit log.
    pub(crate) pre_session_name: Option<String>,
    /// Latch to fill in with the sandboxed process PID once forked; shared with the mediation server.
    pub(crate) mediation_sandboxed_pid_latch: Option<Arc<OnceLock<u32>>>,
}

fn build_supervisor_session_id(audit_state: Option<&AuditState>) -> String {
    audit_state
        .map(|state| state.session_id.clone())
        .unwrap_or_else(|| {
            format!(
                "supervised-{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
            )
        })
}

fn create_trust_interceptor(
    trust: &TrustLaunchOptions,
) -> Option<trust_intercept::TrustInterceptor> {
    if !trust.interception_active {
        return None;
    }

    match trust.policy.clone() {
        Some(policy) => {
            match trust_intercept::TrustInterceptor::new(policy, trust.scan_root.clone()) {
                Ok(interceptor) => Some(interceptor),
                Err(e) => {
                    tracing::warn!("Trust interceptor pattern compilation failed: {e}");
                    eprintln!(
                        "  {}",
                        format!(
                            "WARNING: Runtime instruction file verification disabled \
                         (pattern error: {e})"
                        )
                        .yellow()
                    );
                    None
                }
            }
        }
        None => None,
    }
}

fn create_session_runtime_state(
    command: &[String],
    caps: &CapabilitySet,
    session: &SessionLaunchOptions,
    audit_state: Option<&AuditState>,
    pre_session_id: Option<String>,
    pre_session_name: Option<String>,
) -> Result<SessionRuntimeState> {
    let started = chrono::Local::now().to_rfc3339();
    // Use pre-generated ID when available (shares the value with the mediation
    // audit log). Fall back to DETACHED env var or a fresh random ID.
    let short_session_id = pre_session_id.unwrap_or_else(|| {
        std::env::var(DETACHED_SESSION_ID_ENV)
            .ok()
            .filter(|id| !id.is_empty())
            .unwrap_or_else(session::generate_session_id)
    });
    // Use pre-generated name when available; it was already resolved from
    // session.session_name with the same fallback logic.
    let resolved_name = pre_session_name.unwrap_or_else(|| {
        session
            .session_name
            .clone()
            .unwrap_or_else(session::generate_random_name)
    });
    let session_record = session::SessionRecord {
        session_id: short_session_id.clone(),
        name: Some(resolved_name),
        supervisor_pid: std::process::id(),
        child_pid: 0,
        started: started.clone(),
        started_epoch: session::current_process_start_epoch(),
        status: session::SessionStatus::Running,
        attachment: if session.detached_start {
            session::SessionAttachment::Detached
        } else {
            session::SessionAttachment::Attached
        },
        exit_code: None,
        command: command.to_vec(),
        profile: session.profile_name.clone(),
        workdir: std::env::current_dir().unwrap_or_default(),
        network: match caps.network_mode() {
            nono::NetworkMode::Blocked => "blocked".to_string(),
            nono::NetworkMode::AllowAll => "allowed".to_string(),
            nono::NetworkMode::ProxyOnly { port, .. } => format!("proxy (localhost:{port})"),
        },
        rollback_session: audit_state.map(|state| state.session_id.clone()),
    };
    let session_guard = Some(session::SessionGuard::new(session_record)?);
    let pty_pair = if session.detached_start {
        Some(pty_proxy::open_pty()?)
    } else {
        None
    };

    Ok(SessionRuntimeState {
        started,
        short_session_id,
        session_guard,
        pty_pair,
    })
}

pub(crate) fn execute_supervised_runtime(ctx: SupervisedRuntimeContext<'_>) -> Result<i32> {
    let SupervisedRuntimeContext {
        config,
        caps,
        command,
        session,
        rollback,
        trust,
        proxy,
        proxy_handle,
        silent,
        pre_session_id,
        pre_session_name,
        mediation_sandboxed_pid_latch,
    } = ctx;

    output::print_applying_sandbox(silent);

    let audit_state = create_audit_state(rollback.audit_disabled, rollback.destination.as_ref())?;
    warn_if_rollback_flags_ignored(rollback, silent);

    // Create the session guard (writes session file) and PTY pair BEFORE
    // rollback initialization.  Rollback's baseline snapshot can take many
    // seconds on large repos.  In detached mode the launcher is polling for
    // the session file and attach socket — if we delay session registration
    // until after the baseline walk, the 30-second startup timeout can fire
    // before the session becomes attachable.
    let trust_interceptor = create_trust_interceptor(trust);
    let session_runtime = create_session_runtime_state(
        command,
        caps,
        session,
        audit_state.as_ref(),
        pre_session_id,
        pre_session_name,
    )?;
    let SessionRuntimeState {
        started,
        short_session_id,
        mut session_guard,
        pty_pair,
    } = session_runtime;

    let rollback_state = initialize_rollback_state(rollback, caps, audit_state.as_ref(), silent)?;

    let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
    let approval_backend = terminal_approval::TerminalApproval;
    let supervisor_session_id = build_supervisor_session_id(audit_state.as_ref());
    let supervisor_cfg = exec_strategy::SupervisorConfig {
        protected_roots: protected_roots.as_paths(),
        approval_backend: &approval_backend,
        session_id: &supervisor_session_id,
        attach_initial_client: !session.detached_start,
        detach_sequence: session.detach_sequence.as_deref(),
        open_url_origins: &proxy.open_url_origins,
        open_url_allow_localhost: proxy.open_url_allow_localhost,
        allow_launch_services_active: proxy.allow_launch_services_active,
        #[cfg(target_os = "linux")]
        proxy_port: match caps.network_mode() {
            nono::NetworkMode::ProxyOnly { port, .. } => *port,
            _ => 0,
        },
        #[cfg(target_os = "linux")]
        proxy_bind_ports: match caps.network_mode() {
            nono::NetworkMode::ProxyOnly { bind_ports, .. } => bind_ports.clone(),
            _ => Vec::new(),
        },
    };

    if !session.detached_start {
        output::finish_status_line_for_handoff(silent);
    }

    let exit_code = {
        let mut on_fork = |child_pid: u32| {
            if let Some(ref mut guard) = session_guard {
                guard.set_child_pid(child_pid);
            }
            if let Some(ref latch) = mediation_sandboxed_pid_latch {
                let _ = latch.set(child_pid);
            }
        };
        exec_strategy::execute_supervised(
            config,
            Some(&supervisor_cfg),
            trust_interceptor,
            None, // no skill interceptor
            Some(&mut on_fork),
            pty_pair,
            Some(&short_session_id),
        )?
    };
    if let Some(ref mut guard) = session_guard {
        guard.set_exited(exit_code);
    }
    let ended = chrono::Local::now().to_rfc3339();
    finalize_supervised_exit(RollbackExitContext {
        audit_state: audit_state.as_ref(),
        rollback_state,
        proxy_handle,
        started: &started,
        ended: &ended,
        command,
        exit_code,
        silent,
        rollback_prompt_disabled: rollback.prompt_disabled,
    })?;

    Ok(exit_code)
}
