# JVM posix_spawn ENOSYS — Investigation Log

This document tracks the live, autonomous investigation of issue #1
(JVM `posix_spawn` returning ENOSYS under the Linux exec filter).

The user explicitly said: **don't take the issue summary as fact.**
Verify everything firsthand.

## Status

RESOLVED. Root-caused, fix landed on local branch, all repro
sequences pass post-fix. See "Implementation" section below.

## Working hypothesis

CONFIRMED — see "Root cause" below.

## Root cause

**bazel-server (the JVM daemon) is orphaned to init and outlives the
nono session that started it. When that nono exits, the seccomp
listener fd closes, the kernel sets the filter's `notif` to NULL,
and every subsequent exec from bazel-server (including its children
spawned via `posix_spawn`/`fork`+`execve`) traps and returns ENOSYS
to userspace.**

Mechanism (verified end to end):

1. `nono run … bzl build …` forks a sandboxed child.
2. The child calls `install_seccomp_exec_filter()` — kernel allocates
   a `struct seccomp_filter` and a `struct seccomp_notif`, returns a
   listener fd. The filter's `notif` points at the new struct.
3. The child sends the listener fd to the unsandboxed parent (nono)
   via SCM_RIGHTS, then `exec`s the user command.
4. The filter is inherited through the fork+exec chain:
   nono-child → bash → bzl → bazel-server JVM.
5. bzl daemonizes bazel-server (double-fork): bazel-server's PPid
   becomes 1. It outlives the bzl client and the nono session.
6. nono finishes its run. `run_supervisor_loop` returns.
   `exec_notify_fd: Option<OwnedFd>` is dropped → `close(fd)`.
   No other process holds a copy.
7. Kernel's `seccomp_notify_release` runs:
   - `seccomp_notify_detach` walks any pending notifications and
     marks each `error = -ENOSYS` (`kernel/seccomp.c` line 1425).
   - `seccomp_notify_free` sets `filter->notif = NULL`
     (line 1404).
8. The next time bazel-server (or any descendant of it) does an
   `execve`, the BPF program returns `SECCOMP_RET_USER_NOTIF` and
   the kernel calls `seccomp_do_user_notification`. The first thing
   that function does is check `if (!match->notif)` and `goto out`
   with `err = -ENOSYS` (line 1116-1118). The trapped syscall
   returns `errno 38`.

That is why:
- The supervisor handler **never sees** the failing trap (the
  notification is never queued — kernel rejects at line 1116).
  Confirmed: 0 `multi_threaded_unsafe` events, 0 exec_filter
  events for the failing build in audit-events.ndjson.
- "Cache-served" bzl targets succeed: they don't require
  `WorkspaceStatusAction` to spawn `/bin/sh`. The first build
  pre-populates the daemon's caches (`computing main repo
  mapping`), and subsequent cache-only builds avoid the spawn.
- The bug is "intermittent" only because users sometimes have a
  warm bazel-server from a prior session and sometimes don't.
  Fresh daemon (same-nono lifecycle): build works. Reused daemon
  (cross-session): exec ENOSYS.
- All conventional tracing tools "make the bug disappear": they
  attach AFTER the daemon is already orphaned and listener fd
  is gone, so they don't fix anything. The "fix" was probably
  the user happening to have just shut down the daemon between
  runs. The "AtomicUsize::fetch_add suppresses it" observation
  is almost certainly the same — adding the line forces a
  rebuild, which forces a fresh nono session, which takes
  ownership of a fresh bazel-server.

### Reproduction

Confirmed deterministically on `am/linux-exec-filter` HEAD
(`6c006fb`):

```bash
# Setup: ensure no leftover bazel-server.
cd /home/bits/dd/dd-source && bzl shutdown && pkill -9 -f 'bazel.*server'

# Step 1: prime bazel-server inside a nono session, then exit nono.
target/release/nono run --profile shadowfax-claude.json --allow-cwd --silent -- \
    bash -c 'bzl build //libs/go/log:go_default_library'   # cache-served, succeeds

# At this point: nono is gone. bazel-server (PPid=1) is alive.

# Step 2: a NEW nono session uses the orphaned bazel-server.
target/release/nono run --profile shadowfax-claude.json --allow-cwd --silent -- \
    bash -c 'bzl build //domains/devex/workspaces/apps/workspaces-certs:workspaces-certs'
# → posix_spawn failed, error: 38 (Function not implemented)
```

If step 1 is omitted (no prior nono session), step 2 succeeds.

## Best fix

The seccomp filter belongs to processes that may outlive any
single nono session. The kernel hard-couples the listener fd's
liveness to the filter's `notif` pointer, and there's no way to
rebind a filter to a new listener fd from userspace. Three
possible directions:

A. **Don't inherit the exec filter into orphan-prone daemons.** Hard
   to detect at install time; require user opt-in or a per-command
   policy. Doesn't actually solve the problem, just contains it.

B. **Keep the listener fd alive past nono exit.** A persistent
   side-band process (per-user nono daemon) that owns listener fds
   for any sandboxed-tree-orphaned processes. Heavy.

C. **Don't install the exec filter when the user command is known
   to spawn long-lived background daemons** (bzl, gradle, etc.).
   Brittle.

D. **Fall back gracefully: when the listener fd closes, the
   processes still see ENOSYS.** Can we change the kernel's
   behavior? No — kernel ABI.

E. **(Best, IMO) Have the supervisor not exit while there are
   processes still running with our filter installed**, OR detach
   the filter via something equivalent to a "passthrough" close.
   The kernel does not support detaching the filter. So we have to
   reap.

Hmm, none of the simple options work. Need to think harder.

### Decision: passthrough-shepherd at supervisor exit

The kernel raises `EPOLLHUP` on the seccomp listener fd when
`filter->users` refcount drops to zero — i.e., when no live task
still has the filter installed (kernel/seccomp.c line 1823-1824).
We can use this to know when it's safe to release the fd.

**Plan:**

1. When `run_supervisor_loop` is about to return (user command done),
   *fork-and-detach a shepherd* that inherits the `exec_notify_fd`
   via `fork()` (no SCM_RIGHTS needed — `fork()` duplicates the fd
   atomically).
2. The shepherd is a tiny loop:
   - `poll(exec_notify_fd, POLLIN | POLLHUP, …)`
   - On `POLLIN`: `recv_notif` → `continue_notif` (always allow).
   - On `POLLHUP` or POLLERR: exit (no more tasks have the filter).
3. The supervisor parent then drops its copy of the fd and exits
   normally. The shepherd is reparented to init and lives until
   the last filter-bearing task exits.

This trades strict mediation post-session for correctness:
post-session, an orphaned bazel-server's execs are allowed
without further classification. Acceptable because:
- It matches the pre-PR baseline behavior (no exec filter, no
  mediation of orphan-daemon execs).
- The user's *direct* command in any new session still gets a
  fresh exec filter and full mediation.
- Without this, the user's bzl/JVM workflow is fundamentally
  broken (`ENOSYS` on every cross-session build).

The alternative — killing all orphans at exit — would destroy the
user's bazel-server (forcing a multi-minute restart on every
new nono session). Unacceptable UX for a security feature whose
post-session enforcement is already best-effort.

---

## Implementation

Files added/modified:

- `crates/nono-cli/src/exec_strategy/exec_filter_shepherd.rs` (new):
  Tiny detached-shepherd that holds the listener fd and responds
  `CONTINUE` until `EPOLLHUP` (filter->users == 0).
- `crates/nono-cli/src/exec_strategy.rs`:
  Module declaration + a `spawn` call right before `exec_notify_fd`
  goes out of scope at the end of `execute_supervised`'s parent
  branch.

Implementation notes:

- The shepherd runs the standard daemonize double-fork:
  fork → child does setsid + fork → middle exits, inner survives
  reparented to init. Parent reaps the middle synchronously with
  a blocking waitpid so we don't leak a zombie.
- The shepherd's stdio is redirected to /dev/null so post-session
  output doesn't pollute the user's terminal.
- The shepherd is single-purpose: poll, recv_notif, continue_notif,
  exit on POLLHUP/POLLERR. No allocations after fork; only async-
  signal-safe libc calls and the existing `recv_notif`/
  `continue_notif` ioctl wrappers.
- Critically: the shepherd does NOT have the seccomp filter
  installed itself (it's a fork of the unsandboxed supervisor
  parent). It only holds the listener fd. So it does not
  contribute to `filter->users` and POLLHUP fires correctly when
  the last filter-bearing task exits.

### Behavior verification

1. **Reproduction without fix** (HEAD = `6c006fb`, no shepherd):
   - Fresh state, `nono run … bzl build …cache-target`: succeeds,
     starts bazel-server, nono exits.
   - `nono run … bzl build …fresh-target`: bazel-server's exec
     of `/bin/sh` returns ENOSYS, build fails.

2. **With fix**:
   - Same sequence: cache-target succeeds, then fresh-target also
     succeeds. Shepherd holds listener fd alive across sessions.
   - 3 iterations × 2 commands each: 6/6 builds pass.

3. **Inverse confirmation** (sanity check that shepherd is what
   prevents the bug):
   - With fix, after the cache-target session, manually
     `kill <shepherd-pid>`. Then bzl build of any target fails
     with the same ENOSYS — proving the shepherd is what kept
     things working.

4. **Shepherd cleanup**:
   - Sessions that don't start a new long-lived daemon
     (e.g., re-using an existing bazel-server) spawn a shepherd
     that POLLHUPs and exits within milliseconds, since the
     session's filter has no surviving tasks.
   - Only the session that started the still-alive daemon keeps
     a shepherd around.

5. **Unit + integration tests**:
   - `spawn_returns_immediately_on_already_hung_up_fd`: smoke,
     pipe end as fd; verifies fork/waitpid plumbing.
   - `shepherd_keeps_listener_alive_so_orphan_execs_succeed`:
     installs a real seccomp exec filter in a forked child,
     hands the listener fd to the shepherd, drops the local
     copy, then has the child do an `execve("/bin/true")`.
     The child's exit code is 0 only if the shepherd kept
     the filter's notif alive and responded CONTINUE — which
     it does. Without the fix the child would exit with 38
     (ENOSYS).
   - Both pass on `am/linux-exec-filter` HEAD with the fix.

### Trade-off recorded

Post-session, an orphaned daemon (e.g. bazel-server) and any
processes it spawns escape exec-filter mediation. Direct user
commands in any subsequent nono session still get a fresh filter
and full mediation. This matches pre-PR baseline behavior for
cross-session daemon descendants and is documented in the
shepherd module's docstring.


---

## Background (verified facts only)

- Branch under investigation: `am/linux-exec-filter`
- HEAD: `6c006fb` ("Refuse multi-threaded execve in exec filter")
- Reported failure: bazel-server JVM's `posix_spawn` of `/bin/sh`
  returns `errno 38` (`ENOSYS`)
- Bisect (per issue): `c8ab717` (no exec filter) builds fine;
  `am/linux-exec-filter` HEAD breaks fresh-fetch JVM-spawn paths
- Cache-served bzl targets succeed even on this PR — only fresh
  spawns fail

## What I'm NOT taking as given

- That FORK launch mechanism is unreliable. (Issue says so; verify.)
- That `AtomicUsize::fetch_add` masks the bug. (Strong claim;
  verify.)
- That all observation tooling suppresses the bug. (Verify.)
- That the kernel is the only ENOSYS source. (Look at glibc/JDK
  paths too.)
- That the multi-threaded check (HEAD commit) isn't the cause.
  (Issue's bisect predates the multi-threaded check; need to test
  with it disabled.)

## Plan

1. Audit BPF program + supervisor handler end to end.
2. Build a minimal repro harness independent of bazel.
3. Verify each issue claim against the repro.
4. Map every kernel ENOSYS path that can fire on a trapped task.
5. Form testable hypotheses.
6. Once root-caused: implement and verify the fix.

---

## Log entries

(reverse chronological — most recent at top)

### 2026-04-28 — Kernel ENOSYS paths fully mapped

Read `kernel/seccomp.c` (v6.8) end to end. The ONLY ways a trapped
`execve` returns ENOSYS to userspace:

1. `seccomp_do_user_notification()` line 1116-1118: `match->notif == NULL`
   → returns ENOSYS without ever queueing a notification.
2. `seccomp_notify_detach()` line 1425: every pending notification's
   `error` is set to `-ENOSYS` while waiting.

Both fire only if `match->notif` is NULL. `match->notif` is set at
listener-fd creation time (`init_listener` allocates it) and freed in
`seccomp_notify_free` (called only from `seccomp_notify_detach`).

`seccomp_notify_detach` is invoked from:
- `seccomp_notify_release` (the file's `release` callback — runs when
  the listener fd's `struct file` refcount hits zero).
- `seccomp_set_mode_filter` cleanup path on attach failure.

So **ENOSYS to a trapped task ⟺ the listener fd's struct file has
refcount 0 ⟺ no one in any process holds a reference**.

If the issue's claim that the supervisor's listener fd was alive at
the moment of failure is correct, then either: (a) we're observing
the wrong fd, (b) there's a kernel bug, or (c) the failing task's
filter is somehow a *different* filter than the one our listener fd
points to.

### 2026-04-28 — Repro confirmed; supervisor sees nothing

Ran `bzl build //domains/devex/workspaces/apps/workers/workspaces/cmd/provisioner:worker`
under nono with the shadowfax profile. Hit `posix_spawn failed,
errno 38`.

Audit logs:
- `~/.nono/audit/<session>/audit-events.ndjson`: only
  `session_started` and `session_ended`. No exec_filter events.
- `~/.nono/sessions/audit.jsonl` (filter audit): grep for
  `multi_threaded_unsafe` → 0 matches across the entire file
  (7238 events). The new check has never fired.

**Confirmed**: the supervisor handler is never called for the
failing exec. The kernel returns ENOSYS without ever queueing a
notification.

### 2026-04-28 — Simple JVM repro does NOT trigger the bug

Compiled `SpawnRace.java` (N idle threads + main loop spawning
`/bin/sh -c 'exit 0'`). Ran under nono with a minimal profile that
activates the exec filter via a single dummy `mediation.commands`
entry.

| Threads | Iters | Result |
|---|---|---|
| 16 | 50 | 50/50 ok |
| 128 | 500 | 500/500 ok |
| 256 | 2000 | 2000/2000 ok (with /bin/sh) |

Even with `-Djdk.lang.Process.launchMechanism=POSIX_SPAWN` or
`VFORK` explicitly. So a synthetic multi-threaded JVM doing
posix_spawn is not enough — bazel-server must be doing something
specific.

### 2026-04-28 — BPF + supervisor handler audited

Code is straightforward:
- BPF: load syscall nr; jeq SYS_EXECVE/SYS_EXECVEAT → USER_NOTIF;
  else ALLOW. Five instructions total.
- Install: standard `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER)`
  with WAIT_KILLABLE_RECV and a fallback path.
- Handler: recv_notif → multi-threaded check → read pathname from
  `/proc/<tid>/mem` → resolve dirfd-relative → canonicalize →
  classify (shim/deny/allow) → walk shebang chain → audit emit →
  respond CONTINUE or EACCES.
- Listener fd is sent from the sandboxed child to the supervisor
  parent via SCM_RIGHTS.
- Supervisor poll loop in `run_supervisor_loop` polls all 3 notify
  fds plus the supervisor socket plus PTY fds; calls
  `handle_exec_notification` synchronously when the exec fd is
  POLLIN.

Nothing in the BPF or handler explains ENOSYS — the supervisor
isn't even running for the failing exec.
