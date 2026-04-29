//! Passthrough shepherd for the seccomp exec filter listener fd.
//!
//! ## Why this exists
//!
//! The seccomp exec filter is installed in the sandboxed child process and
//! inherited by every descendant via fork+exec. Long-lived daemons spawned
//! by the user's command — most notably `bazel-server`, which `bzl` daemonizes
//! via double-fork — outlive the nono session that created them.
//!
//! When the supervisor's listener fd (`exec_notify_fd`) is closed at session
//! exit, the kernel's `seccomp_notify_release` runs `seccomp_notify_detach`,
//! which sets `filter->notif = NULL`. From that point on, every `execve` /
//! `execveat` from any task that inherited the filter traps and the kernel
//! returns `-ENOSYS` directly from `seccomp_do_user_notification`
//! (`kernel/seccomp.c` line 1116-1118). The trapped task sees
//! `posix_spawn failed, error: 38 (Function not implemented)`.
//!
//! This module's `spawn` keeps the listener fd alive past the supervisor
//! by handing it off to a tiny detached process whose only job is to
//! `respond CONTINUE` to every notification. The kernel raises `EPOLLHUP`
//! on the listener when `filter->users` reaches zero — i.e., when no live
//! task has the filter installed any more — and the shepherd exits cleanly
//! at that point.
//!
//! ## Trade-off
//!
//! Post-session the shepherd allows every exec without classification, so
//! a daemon (like `bazel-server`) that survives a session is no longer
//! mediated for direct-path deny-set bypasses. This matches the pre-PR
//! baseline (no exec filter at all) for cross-session daemon descendants;
//! direct user commands in any subsequent nono session still get a fresh
//! filter and full mediation. See `docs/jvm-enosys-investigation.md` for
//! the detailed analysis.

use nix::libc;
use nix::sys::wait::waitpid;
use nix::unistd::{fork, ForkResult};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

/// Hand `exec_notify_fd` off to a detached shepherd process and return.
///
/// On the call-site path: the supervisor has finished the user command and
/// is about to drop `exec_notify_fd`, which would close the listener and
/// orphan-trap any inherited filter. We `fork()` (which dups the fd into
/// the child), then in the child do a daemonize double-fork to reparent
/// the inner shepherd to init. The middle process exits immediately;
/// `waitpid` on it from the supervisor avoids leaving a zombie.
///
/// The supervisor caller then drops its own copy of `exec_notify_fd` as
/// usual; the kernel keeps the underlying file alive because the inner
/// shepherd holds a reference.
///
/// Failures are non-fatal — log and return. Worst case, we revert to the
/// buggy pre-fix behavior for this session.
pub(super) fn spawn(exec_notify_fd: &OwnedFd) {
    // SAFETY: fork() duplicates the open fd table. Both parent and child
    // see exec_notify_fd as live; the child takes ownership by dropping
    // everything else.
    let outer = match unsafe { fork() } {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                "exec filter shepherd: outer fork failed: {} \
                 (post-session daemons may see ENOSYS on exec)",
                e
            );
            return;
        }
    };

    match outer {
        ForkResult::Parent { child: outer_pid } => {
            // Reap the middle process synchronously so it doesn't linger
            // as a zombie. The middle process exits immediately after
            // its own fork.
            //
            // Use blocking waitpid — middle exits within microseconds.
            let _ = waitpid(outer_pid, None);
        }
        ForkResult::Child => {
            // Middle of the daemonize sandwich. Detach from the
            // supervisor's session so the inner shepherd is reparented
            // to init even if the supervisor process dies. setsid()
            // also strips any controlling terminal — important so a
            // SIGHUP on the user's terminal doesn't take down the
            // shepherd.
            //
            // SAFETY: setsid is async-signal-safe and operates only on
            // the current process.
            unsafe { libc::setsid() };

            let inner = match unsafe { fork() } {
                Ok(r) => r,
                Err(_) => {
                    // Inner fork failed; bail without doing anything.
                    // SAFETY: _exit is async-signal-safe.
                    unsafe { libc::_exit(127) };
                }
            };

            match inner {
                ForkResult::Parent { .. } => {
                    // Middle exits; the inner becomes init's child.
                    // SAFETY: _exit is async-signal-safe.
                    unsafe { libc::_exit(0) };
                }
                ForkResult::Child => {
                    // We are the long-lived shepherd. Take over.
                    redirect_std_to_devnull();
                    set_proc_name();
                    let raw_fd = exec_notify_fd.as_raw_fd();
                    shepherd_loop(raw_fd);
                    // SAFETY: _exit is async-signal-safe.
                    unsafe { libc::_exit(0) };
                }
            }
        }
    }
}

/// Rename the process to `nono-shepherd` so users grepping `ps aux`
/// for stray nono processes can tell what they are at a glance.
/// `prctl(PR_SET_NAME)` updates `/proc/<pid>/comm` (visible as the
/// `comm` column in `ps -o pid,comm`); the original argv stays put,
/// which is fine — we only care about disambiguation.
fn set_proc_name() {
    // SAFETY: prctl(PR_SET_NAME) is async-signal-safe. The kernel
    // copies up to 16 bytes from the buffer.
    unsafe {
        let name = b"nono-shepherd\0";
        libc::prctl(libc::PR_SET_NAME, name.as_ptr().cast::<libc::c_void>());
    }
}

/// Reopen stdin/stdout/stderr to /dev/null. The shepherd has nothing to
/// say; leaving them attached to the user's terminal would let stray
/// debug output garble the user's shell after the session ends.
fn redirect_std_to_devnull() {
    // SAFETY: open and dup2 are async-signal-safe. fd handling uses
    // raw libc since we are post-fork and pre-cleanup.
    unsafe {
        let null = libc::open(
            b"/dev/null\0".as_ptr().cast::<libc::c_char>(),
            libc::O_RDWR | libc::O_CLOEXEC,
        );
        if null < 0 {
            return;
        }
        libc::dup2(null, libc::STDIN_FILENO);
        libc::dup2(null, libc::STDOUT_FILENO);
        libc::dup2(null, libc::STDERR_FILENO);
        if null > 2 {
            libc::close(null);
        }
    }
}

/// Loop until the listener fd hangs up.
///
/// On `POLLIN`: drain one notification and respond `CONTINUE` (allow the
/// trapped exec without classification). On `POLLHUP`: every task with the
/// filter installed has exited — we're done. On `POLLERR` (or any other
/// unexpected condition): exit defensively rather than spin.
fn shepherd_loop(notify_fd: RawFd) {
    use nono::sandbox::{continue_notif, recv_notif};

    loop {
        let mut pfd = libc::pollfd {
            fd: notify_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        // No timeout — wait forever for either a notification or POLLHUP.
        // SAFETY: poll is async-signal-safe; pfd is a stack value valid
        // for the syscall duration.
        let ret = unsafe { libc::poll(&mut pfd, 1, -1) };

        if ret < 0 {
            // Interrupted? retry. Otherwise bail.
            let errno = std::io::Error::last_os_error();
            if errno.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }

        if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            // POLLHUP: filter->users hit zero — last task with the
            // filter has exited. POLLERR/NVAL: kernel told us the fd
            // is unusable. Either way, our work is done.
            return;
        }

        if pfd.revents & libc::POLLIN == 0 {
            continue;
        }

        // Drain one notification. recv_notif may return an error if the
        // listener was already closed — log and bail.
        let notif = match recv_notif(notify_fd) {
            Ok(n) => n,
            Err(_) => return,
        };

        // Respond CONTINUE: the kernel re-runs the syscall as if no
        // filter were attached. This is the unmediated post-session
        // behavior; see module-level docs for the trade-off.
        let _ = continue_notif(notify_fd, notif.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Smoke test: shepherd spawn returns without panicking when given a
    /// pipe-end stand-in for a listener fd. The shepherd will see POLLHUP
    /// immediately when the other end closes and exit cleanly.
    #[test]
    fn spawn_returns_immediately_on_already_hung_up_fd() {
        let (r, w) = nix::unistd::pipe().expect("pipe");
        drop(w); // raises POLLHUP on `r`
        let t0 = Instant::now();
        spawn(&r);
        // spawn() does fork+waitpid on the middle process and then returns.
        // The middle exits in microseconds; this should be fast.
        assert!(
            t0.elapsed() < Duration::from_secs(2),
            "spawn() blocked too long"
        );
    }

    /// Verify that an actual seccomp listener — not a pipe — is held alive
    /// by the shepherd: install the filter in a forked child, send the
    /// listener fd back to this test process, hand it to the shepherd,
    /// then drop our local copy. Have the child do an `execve` and
    /// confirm the trap is *not* converted to ENOSYS — i.e., the shepherd
    /// kept the filter's `notif` alive and responded `CONTINUE`.
    ///
    /// Skipped if the kernel doesn't support unprivileged seccomp user
    /// notification (sandbox not available — common in CI containers).
    #[test]
    fn shepherd_keeps_listener_alive_so_orphan_execs_succeed() {
        // SAFETY: standard pipe construction, no unsafe needed.
        use nix::libc;
        use nix::sys::wait::{waitpid, WaitStatus};
        use nix::unistd::{fork, ForkResult};
        use std::io::{Read, Write};
        use std::os::fd::{AsRawFd, OwnedFd};

        // socketpair for SCM_RIGHTS handoff.
        let (parent_sock, child_sock) =
            match nono::SupervisorSocket::pair() {
                Ok(p) => p,
                Err(_) => return, // env doesn't support — skip.
            };
        let child_sock_raw = child_sock.as_raw_fd();
        // Synchronization pipe: parent writes a byte to tell child to do
        // its execve attempt; child writes its result byte back.
        let (sync_r, sync_w) = nix::unistd::pipe().expect("sync pipe");

        // SAFETY: fork from a single-threaded test runner is safe; child
        // restricts itself to async-signal-safe operations + sandbox
        // installation which itself is documented as fork-safe in this
        // codebase.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                drop(parent_sock);
                drop(sync_w);
                let listener = match nono::sandbox::install_seccomp_exec_filter() {
                    Ok(fd) => fd,
                    Err(_) => unsafe { libc::_exit(70) },
                };
                if let Err(_e) = nono::supervisor::socket::send_fd_via_socket(
                    child_sock_raw,
                    listener.as_raw_fd(),
                ) {
                    unsafe { libc::_exit(71) };
                }
                drop(listener);
                drop(child_sock);
                // Wait for parent to say "go".
                let mut go = [0u8; 1];
                if std::fs::File::from(sync_r).read_exact(&mut go).is_err() {
                    unsafe { libc::_exit(72) };
                }
                // Try execve("/bin/true"). If the listener is dead the
                // kernel returns ENOSYS here.
                let path = b"/bin/true\0";
                let argv = [path.as_ptr().cast::<libc::c_char>(), std::ptr::null()];
                let envp = [std::ptr::null::<libc::c_char>()];
                unsafe {
                    libc::execve(
                        path.as_ptr().cast::<libc::c_char>(),
                        argv.as_ptr(),
                        envp.as_ptr(),
                    );
                    let errno = *libc::__errno_location();
                    libc::_exit(errno.clamp(0, 99));
                }
            }
            ForkResult::Parent { child } => {
                drop(child_sock);
                drop(sync_r);

                // Receive the listener fd from the child.
                let listener_fd: OwnedFd = match parent_sock.recv_fd() {
                    Ok(fd) => fd,
                    Err(_) => {
                        let _ = waitpid(child, None);
                        return; // env doesn't support — skip.
                    }
                };

                // Hand off to the shepherd. After this both we and the
                // shepherd hold the fd; we drop ours immediately so the
                // shepherd is the sole keeper.
                spawn(&listener_fd);
                drop(listener_fd);

                // Tell the child to attempt its execve.
                std::fs::File::from(sync_w).write_all(&[1]).expect("sync");

                // Reap the child and inspect.
                let status = waitpid(child, None).expect("waitpid");
                match status {
                    WaitStatus::Exited(_, code) => {
                        // execve("/bin/true") succeeds and the new image
                        // is /bin/true which exits 0. So a successful
                        // shepherd path yields exit code 0.
                        // If the listener died, the kernel returns
                        // ENOSYS (38), and the child's _exit(38) gives
                        // us a non-zero code.
                        assert_eq!(
                            code, 0,
                            "child exit code {code}: shepherd failed to keep \
                             listener alive — kernel returned errno from execve"
                        );
                    }
                    WaitStatus::Signaled(_, sig, _) => {
                        panic!("child killed by signal {sig:?}");
                    }
                    other => panic!("unexpected wait status: {other:?}"),
                }
            }
        }
    }
}
