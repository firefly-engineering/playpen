//! The macOS denial trace: Seatbelt's denials, read out of the unified log.
//!
//! There are no preconditions to refuse on ([spec §14.5]). The kernel already logs every denial
//! in the confined tree under the run's **denial tag** ([`crate::backend::denial_tag`]), so the
//! trace is `log stream` filtered on that tag, writing straight into the file. The stream starts
//! when the trace is opened, before the fork, because `log stream` shows nothing logged before it
//! attached: started any later, the child's first denials would be lost to the race.
//!
//! [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};

use crate::code::Code;
use crate::record::RunId;
use crate::refusal::Refusal;

/// How long the stream is left to deliver after the agent exits. A denial reaches `log stream`
/// within milliseconds of being made, measured on macOS 26.
// ponytail: a fixed settle rather than a marker the stream must echo, and no wait for the stream to
// attach at open either: https://github.com/firefly-engineering/playpen/issues/150
const SETTLE: Duration = Duration::from_millis(250);

/// One run's denial trace: the file, and the `log stream` writing into it.
#[derive(Debug)]
pub struct Tracing {
    /// The file the operator named.
    file: PathBuf,
    /// The live stream, or why there is none.
    stream: Result<Child, String>,
}

/// Open the trace for `run`, created empty so an operator reading it sees this run's denials and
/// never the last run's, and start streaming the run's denials into it. Refused only when the
/// file itself cannot be written: the flag's operand is unusable, which is the invocation's
/// problem, and no `refusal.trace.*` code would be true of it.
pub fn open(file: &Path, _workspace: &Path, run: &RunId) -> Result<Tracing, Refusal> {
    let created = std::fs::File::create(file).map_err(|err| {
        Refusal::new(
            Code::InvocationUsage,
            format!("--trace-denials cannot write {}: {err}", file.display()),
        )
    })?;
    // The tag the backend attaches to this run's default deny, taken from the backend so the two
    // cannot drift. It is a run id behind a fixed prefix, so it needs no quoting in a predicate.
    //
    // `/usr/bin/log` by path, because `log` alone is a zsh builtin. Its stderr goes nowhere: the
    // flag never writes to stderr.
    let stream = crate::backend::denial_tag(run)
        .ok_or_else(|| "the run has no denial tag to stream".to_string())
        .and_then(|tag| {
            Command::new("/usr/bin/log")
                .args(["stream", "--style", "compact", "--predicate"])
                .arg(format!(
                    "sender == \"Sandbox\" AND eventMessage CONTAINS \"{tag}\""
                ))
                .stdin(Stdio::null())
                .stdout(created)
                .stderr(Stdio::null())
                .spawn()
                .map_err(|err| format!("the unified log could not be streamed: {err}"))
        });
    Ok(Tracing {
        file: file.to_owned(),
        stream,
    })
}

impl Tracing {
    /// The file this run is traced into, for the record to name.
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Nothing to start: the stream has run since [`open`], and it filters on the run's tag, which
    /// covers the whole confined tree rather than one pid.
    pub fn follow(&mut self, _pid: libc::pid_t, _since: SystemTime) {}

    /// Stop the stream. Returns why the trace is **unverified**, where it is: a stream that never
    /// started, or that ended before the run did, may have missed denials, and a trace that cannot
    /// be vouched for is said to be so rather than presented as complete.
    pub fn stop(&mut self) -> Option<String> {
        let why = match &mut self.stream {
            Err(why) => why.clone(),
            Ok(stream) => {
                std::thread::sleep(SETTLE);
                let ended = match stream.try_wait() {
                    Ok(None) => None,
                    Ok(Some(status)) => Some(format!("the log stream ended mid-run ({status})")),
                    Err(err) => Some(format!("the log stream could not be checked: {err}")),
                };
                let _ = stream.kill();
                let _ = stream.wait();
                ended?
            }
        };
        // In the trace itself, marked so it cannot be read as a kernel log line: the operator may
        // never read the run record, and a file that ends without this reads as complete.
        let noted = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.file)
            .and_then(|mut file| writeln!(file, "# playpen: unverified: {why}"));
        let _ = noted;
        Some(why)
    }

    /// The Landlock domain this run was confined by, which macOS has none of.
    pub fn domain(&self) -> Option<&str> {
        None
    }
}

/// A trace dropped without [`Tracing::stop`] — the run was refused after it opened — takes its
/// stream with it: a std `Child` is not killed on drop, and an orphaned `log stream` would run on
/// past playpen, holding the file open.
impl Drop for Tracing {
    fn drop(&mut self) {
        if let Ok(stream) = &mut self.stream {
            let _ = stream.kill();
            let _ = stream.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run refused after the trace opened drops it unstopped, and the stream must go with it
    /// rather than outlive playpen holding the file open.
    #[test]
    fn a_dropped_trace_takes_its_stream_with_it() {
        let dir = tempfile::TempDir::new().expect("dir");
        let run = RunId::allocate().expect("id");
        let tracing = open(&dir.path().join("trace"), dir.path(), &run).expect("opened");
        let pid = tracing.stream.as_ref().expect("streaming").id() as libc::pid_t;
        drop(tracing);
        // SAFETY: signal 0 only asks whether `pid` exists.
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "the stream outlived its trace"
        );
    }
}
