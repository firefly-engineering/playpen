//! The supervisor's half of process transparency ([spec §11.6]): catchable signals sent to playpen
//! are forwarded to the child, and playpen exits with the child's status.
//!
//! The child stays in playpen's process group, which is the caller's job: the terminal's Ctrl-C
//! and Ctrl-Z reach every process in the job, a pipeline around playpen keeps the terminal, and
//! playpen never touches the foreground. A signal the terminal generated has therefore reached the
//! child already, and is not forwarded a second time (`from_the_terminal`).
//!
//! The supervisor stays single-threaded: signals are blocked before the fork and taken
//! synchronously with `sigwait`, so nothing runs in a signal handler. A thread started before the
//! fork would not have them blocked, and would swallow them.
//!
//! [spec §11.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#116-process-transparency

use std::mem::MaybeUninit;

use libc::{c_int, pid_t, sigset_t};

use crate::code::Code;
use crate::fault::Fault;
use crate::refusal::Refusal;

/// The signals forwarded to the child. Excluded: the uncatchable `SIGKILL` and `SIGSTOP`;
/// `SIGCHLD`, which is the supervisor's own; `SIGPIPE`, which the Rust runtime ignores; and the
/// synchronous fault signals, which blocking would turn into undefined behaviour on a real fault.
fn forwardable() -> Vec<c_int> {
    #[allow(unused_mut)] // extended per platform
    let mut signals = vec![
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGABRT,
        libc::SIGALRM,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
        libc::SIGCONT,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
        libc::SIGURG,
        libc::SIGXCPU,
        libc::SIGXFSZ,
        libc::SIGVTALRM,
        libc::SIGPROF,
        libc::SIGWINCH,
        libc::SIGIO,
    ];
    #[cfg(target_os = "macos")]
    signals.push(libc::SIGINFO);
    #[cfg(target_os = "linux")]
    {
        signals.push(libc::SIGPWR);
        signals.extend(libc::SIGRTMIN()..=libc::SIGRTMAX());
    }
    signals
}

/// The signals a terminal sends to its whole foreground process group.
fn is_terminal_generated(sig: c_int) -> bool {
    matches!(
        sig,
        libc::SIGINT | libc::SIGQUIT | libc::SIGTSTP | libc::SIGWINCH
    )
}

/// The stops after which the caller's shell expects the whole job to be stopped.
fn is_job_stop(sig: c_int) -> bool {
    matches!(sig, libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU)
}

/// The signals held for the supervisor, from before the fork until it exits.
pub struct HeldSignals {
    /// What the supervisor waits on: `SIGCHLD` and every forwardable signal the caller did not
    /// ignore. An ignored one stays ignored, and the child inherits that, as `nohup` relies on.
    held: Vec<c_int>,
    set: sigset_t,
    /// The mask the caller gave playpen, restored in the child before `exec`.
    caller_mask: sigset_t,
}

extern "C" fn ignore(_: c_int) {}

impl HeldSignals {
    /// Block every signal the supervisor waits on. Called before the fork, so a signal that
    /// arrives at any point from here on is held for the supervisor rather than lost.
    ///
    /// A failure here is reported as `refusal.process.fork`: playpen could not prepare the fork.
    pub fn block() -> Result<Self, Refusal> {
        let mut held = vec![libc::SIGCHLD];
        held.extend(
            forwardable()
                .into_iter()
                .filter(|&sig| !caller_ignores(sig)),
        );
        let mut set = empty_set();
        for &sig in &held {
            // SAFETY: `set` was initialised by sigemptyset; `sig` is a valid signal number.
            unsafe { libc::sigaddset(&mut set, sig) };
            // A signal whose default action is to be ignored may be discarded on arrival even
            // while blocked, on macOS. A handler makes every one of them pending until taken;
            // it never runs, since the signal stays blocked, and the child resets it.
            // SAFETY: a zeroed sigaction is valid; the handler is a plain `extern "C" fn`.
            let failed = unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = ignore as extern "C" fn(c_int) as libc::sighandler_t;
                action.sa_flags = libc::SA_RESTART;
                libc::sigaction(sig, &action, std::ptr::null_mut()) != 0
            };
            if failed {
                return Err(setup_refusal(
                    &format!("sigaction({sig})"),
                    std::io::Error::last_os_error(),
                ));
            }
        }
        let mut caller_mask = empty_set();
        // SAFETY: both sets are initialised and valid for the call.
        let err = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut caller_mask) };
        if err != 0 {
            return Err(setup_refusal(
                "pthread_sigmask",
                std::io::Error::from_raw_os_error(err),
            ));
        }
        Ok(Self {
            held,
            set,
            caller_mask,
        })
    }

    /// In the child, before anything else: hand every held signal back to its default action
    /// under the caller's mask, so one forwarded before `exec` acts on the child as it would on
    /// the target.
    pub fn release_in_child(&self) {
        for &sig in &self.held {
            // SAFETY: async-signal-safe; `sig` is a valid signal number.
            unsafe { libc::signal(sig, libc::SIG_DFL) };
        }
        // SAFETY: async-signal-safe; the mask is initialised.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.caller_mask, std::ptr::null_mut())
        };
    }

    /// Supervise `child` until it exits: forward signals, stop with it as a job, and return the
    /// status playpen exits with — the child's own, or `128+N` when it died by signal N.
    ///
    /// The error is a [`Fault`] rather than a refusal: by the time this is supervising, the child
    /// has run, so there is no honest way to say it did not ([ADR 0024]).
    ///
    /// [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
    pub fn supervise(&self, child: pid_t) -> Result<i32, Fault> {
        loop {
            let mut sig = 0;
            // SAFETY: `self.set` is initialised and every member is blocked.
            if unsafe { libc::sigwait(&self.set, &mut sig) } != 0 {
                continue;
            }
            if sig == libc::SIGCHLD {
                if let Some(status) = reap(child)? {
                    return Ok(status);
                }
                continue;
            }
            if !(is_terminal_generated(sig) && from_the_terminal()) {
                // A child already gone has nobody left to tell; its exit arrives as SIGCHLD.
                // SAFETY: kill has no memory preconditions.
                unsafe { libc::kill(child, sig) };
            }
            if is_job_stop(sig) {
                // The handler replaced the default stop, so stop as the rest of the job does: the
                // caller's shell waits for every process in it. Its `SIGCONT` resumes us.
                // SAFETY: stopping ourselves; SIGSTOP cannot be blocked or caught.
                unsafe { libc::kill(libc::getpid(), libc::SIGSTOP) };
            }
        }
    }
}

fn caller_ignores(sig: c_int) -> bool {
    let mut current = MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: a null new action only queries; `current` is a valid out-pointer, read only once
    // sigaction has filled it.
    unsafe {
        libc::sigaction(sig, std::ptr::null(), current.as_mut_ptr()) == 0
            && current.assume_init().sa_sigaction == libc::SIG_IGN
    }
}

/// Whether a terminal-generated signal can have come from the terminal: playpen's group holds the
/// foreground of its controlling terminal. The terminal then delivered it to the child too. The
/// signal carries no reliable sign of its sender — on macOS a `kill` and a keypress arrive
/// alike — so a direct `kill -INT` to a foreground playpen is not forwarded either.
fn from_the_terminal() -> bool {
    // SAFETY: getpgrp has no preconditions.
    let group = unsafe { libc::getpgrp() };
    // SAFETY: tcgetpgrp fails cleanly on a descriptor that is not the controlling terminal.
    (0..3).any(|fd| unsafe { libc::tcgetpgrp(fd) } == group)
}

fn empty_set() -> sigset_t {
    let mut set = MaybeUninit::<sigset_t>::uninit();
    // SAFETY: sigemptyset initialises the whole set.
    unsafe {
        libc::sigemptyset(set.as_mut_ptr());
        set.assume_init()
    }
}

fn setup_refusal(call: &str, err: std::io::Error) -> Refusal {
    Refusal::new(
        Code::ProcessFork,
        format!("cannot hold signals for the child: {call}: {err}"),
    )
}

/// Collect `child` if it has exited.
///
/// A `waitpid` that fails is a **fault** and never a refusal ([ADR 0024]): the child has run by
/// now, perhaps for hours, so `125` — "playpen did not run the agent" — would be a lie. On our own
/// unreaped child the call can realistically fail only with `EINTR`, which is retried below.
///
/// [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
fn reap(child: pid_t) -> Result<Option<i32>, Fault> {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer for the duration of the call.
        match unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } {
            0 => return Ok(None),
            -1 => {
                let err = std::io::Error::last_os_error();
                if err.kind() != std::io::ErrorKind::Interrupted {
                    return Err(wait_fault(child, err));
                }
            }
            _ if libc::WIFSIGNALED(status) => return Ok(Some(128 + libc::WTERMSIG(status))),
            _ => return Ok(Some(libc::WEXITSTATUS(status))),
        }
    }
}

/// The fault a failed `waitpid` on the agent is. `ECHILD` means the kernel has no such child of
/// ours, so something reaped it behind the supervisor's back; anything else means the call itself
/// is wrong, which is a different defect and so a different code.
fn wait_fault(child: pid_t, err: std::io::Error) -> Fault {
    let code = match err.raw_os_error() {
        Some(libc::ECHILD) => Code::BugStatusNoChild,
        _ => Code::BugStatusUnreadable,
    };
    Fault::new(
        code,
        format!("cannot learn the status of agent {child}: waitpid failed: {err}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncatchable_and_own_signals_are_never_forwarded() {
        let signals = forwardable();
        for sig in [libc::SIGKILL, libc::SIGSTOP, libc::SIGCHLD, libc::SIGPIPE] {
            assert!(!signals.contains(&sig), "signal {sig} is forwarded");
        }
    }

    #[test]
    fn the_usual_termination_signals_are_forwarded() {
        let signals = forwardable();
        for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGQUIT] {
            assert!(signals.contains(&sig), "signal {sig} is not forwarded");
        }
    }

    /// Nothing can provoke a failed `waitpid` on our own unreaped child, so the test covers the
    /// branch rather than the condition ([ADR 0024]).
    ///
    /// [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
    #[test]
    fn a_failed_wait_is_a_fault_naming_why() {
        let fault = |errno| wait_fault(4242, std::io::Error::from_raw_os_error(errno));
        // Something reaped the agent behind the supervisor's back.
        assert_eq!(fault(libc::ECHILD).code, Code::BugStatusNoChild);
        // The call itself is wrong, which is a different defect.
        assert_eq!(fault(libc::EINVAL).code, Code::BugStatusUnreadable);
        assert!(
            fault(libc::ECHILD).message().contains("4242"),
            "the fault names the agent"
        );
        // Never a refusal: the agent has run, so `125` would say it had not.
        assert!(!fault(libc::ECHILD).code.as_str().starts_with("refusal."));
    }

    #[test]
    fn a_hangup_or_a_termination_is_never_taken_for_the_terminals() {
        // Either would be lost if wrongly withheld, so only keyboard and resize signals are.
        assert!(!is_terminal_generated(libc::SIGHUP));
        assert!(!is_terminal_generated(libc::SIGTERM));
        assert!(is_terminal_generated(libc::SIGINT));
    }
}
