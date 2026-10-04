//! A fault: playpen reached a state its contract has no vocabulary for ([ADR 0024]).
//!
//! [Spec §11.6] admits two outcomes once the agent has run — the agent's own status, or `128+N`
//! when it died by a signal — and reserves `125` for the launch refusals, which are the cases
//! where there is no agent to have a status. "The agent ran and playpen cannot say what happened"
//! is none of these. Rather than borrow the closest code and lie, playpen states the fault on
//! stderr, kills the agent so the outcome is at least deterministic, records it, and dies by
//! `SIGABRT`.
//!
//! A fault is a defect, not a contract case: nothing a caller does can provoke one, and a
//! consumer has nothing to handle. The code exists so that a caller meeting a crash can branch on
//! *why*, as [spec §14.3]'s rule requires — consumers branch on the code and never on the prose.
//!
//! [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
//! [spec §11.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#116-process-transparency
//! [spec §14.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#143-the-refusal-line

use std::fmt;
use std::io::Write;

use crate::code::Code;
use crate::record::RunId;
use crate::refusal::OneLine;

/// playpen is broken, for one stable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub code: Code,
    message: String,
}

impl Fault {
    /// A fault carrying a human sentence that names what playpen could not do.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The human sentence, without the prefix or the code.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The fault line of run `run`, shaped like a refusal line so that one reader parses both.
    pub fn line(&self, run: &RunId) -> String {
        format!("{self} — run {run}")
    }

    /// State the fault on stderr, kill the agent, and record it.
    ///
    /// The agent dies before the record is written, so the record cannot claim an end time while
    /// the agent is still running. `record` is the caller's record write, which owns the run's
    /// record; a failure to write it changes nothing, since playpen is about to abort either way.
    ///
    /// Everything [`Fault::abort`] does that a caller can observe happens here, so a test can
    /// assert the line, the kill and the record without dying.
    fn declare(&self, run: &RunId, agent: libc::pid_t, record: impl FnOnce(&Fault)) {
        let line = format!("{}\n", self.line(run));
        // Nothing useful can be done if stderr itself is gone.
        let _ = std::io::stderr().write_all(line.as_bytes());
        // A supervisor that cannot learn the agent's status has lost supervision entirely, and
        // leaving the agent alive reparents a confined process to init, still holding the
        // terminal. `SIGKILL`, because there is nobody left to climb the usual ladder.
        // SAFETY: kill has no memory preconditions.
        unsafe { libc::kill(agent, libc::SIGKILL) };
        record(self);
    }

    /// Declare the fault, then die by `SIGABRT`.
    ///
    /// A signal death reads as a crash, where an ordinary exit status reads as a value the agent
    /// might have returned. `panic!` would do neither: the crate unwinds, so it would exit `101`
    /// and run destructors on a process that has just declared itself broken.
    pub fn abort(&self, run: &RunId, agent: libc::pid_t, record: impl FnOnce(&Fault)) -> ! {
        self.declare(run, agent, record);
        // The supervisor holds every signal it waits on and installs a handler for each, so
        // `SIGABRT` is both blocked and caught here. Reset it and unblock it rather than trusting
        // `abort` to override both.
        // SAFETY: a zeroed sigaction with `SIG_DFL` is valid; the set is initialised before use.
        unsafe {
            let mut default: libc::sigaction = std::mem::zeroed();
            default.sa_sigaction = libc::SIG_DFL;
            libc::sigaction(libc::SIGABRT, &default, std::ptr::null_mut());
            let mut set = std::mem::zeroed::<libc::sigset_t>();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGABRT);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            libc::raise(libc::SIGABRT);
            // `SIGABRT` at its default action, unblocked, does not return.
            libc::_exit(134)
        }
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "playpen: {}: {}", self.code, OneLine(&self.message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fault() -> Fault {
        Fault::new(
            Code::BugStatusNoChild,
            "waitpid on the agent failed: ECHILD",
        )
    }

    #[test]
    fn renders_prefix_code_and_message_like_a_refusal_line() {
        assert_eq!(
            fault().to_string(),
            "playpen: bug.status.no-child: waitpid on the agent failed: ECHILD"
        );
    }

    #[test]
    fn the_line_ends_with_the_run_id() {
        let run = RunId::allocate().expect("id");
        assert_eq!(fault().line(&run), format!("{} — run {run}", fault()));
    }

    #[test]
    fn control_characters_never_break_the_line() {
        let fault = Fault::new(Code::BugStatusUnreadable, "waitpid failed: a\nb\tc");
        let line = fault.to_string();
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert!(line.ends_with(r"waitpid failed: a\nb\tc"));
    }

    /// The condition cannot be provoked, so the test covers what the branch does: the agent is
    /// killed and the record is written.
    #[test]
    fn declaring_a_fault_kills_the_agent_and_records_it() {
        // A child that would outlive the supervisor by hours if nothing killed it.
        let mut agent = std::process::Command::new("sleep")
            .arg("600")
            .spawn()
            .expect("spawn an agent to strand");
        let pid = agent.id() as libc::pid_t;
        let mut recorded = None;
        fault().declare(&RunId::allocate().expect("id"), pid, |f| {
            recorded = Some(f.clone());
        });

        assert_eq!(recorded, Some(fault()), "the fault reached the record");
        let status = agent.wait().expect("reap the agent");
        assert_eq!(
            status.code(),
            None,
            "the agent died by a signal rather than exiting: {status:?}"
        );
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }
}
