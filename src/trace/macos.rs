//! The macOS denial trace: Seatbelt's denials, read out of the unified log.
//!
//! There are no preconditions to refuse on ([spec §14.5]). The kernel already logs every denial
//! in the confined tree under the run's **denial tag** ([`crate::backend::denial_tag`]), so the
//! trace is `log stream` filtered on that tag, drained through playpen into the file. The stream
//! starts when the trace is opened, before the fork, because `log stream` shows nothing logged
//! before it attached.
//!
//! Neither its attaching nor its draining is taken on trust. playpen provokes a denial of its own
//! under the run's tag, a **mark**, and waits to see it come through: at open, so the child's
//! first denials cannot be lost to the race, and at stop, so the last are not cut off. A mark
//! that never comes marks the trace **unverified**. Marks are told apart from the agent's denials
//! by the message the kernel appends, which is the profile's and never the agent's to choose.
//!
//! [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials

use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use crate::code::Code;
use crate::record::RunId;
use crate::refusal::Refusal;

/// How long a mark may take to come through before the stream is taken not to have attached, or
/// not to have drained. A denial reaches `log stream` within milliseconds, measured on macOS 26.
const MARK_BUDGET: Duration = Duration::from_secs(2);

/// How often a mark is provoked again while waiting for one: one provoked before the stream
/// attached is never shown, so it is repeated until one is.
const MARK_EVERY: Duration = Duration::from_millis(100);

/// One run's denial trace: the file, and the `log stream` draining into it.
#[derive(Debug)]
pub struct Tracing {
    /// The file the operator named.
    file: PathBuf,
    /// The live stream, or why there is none or it was not seen to attach.
    stream: Result<Stream, String>,
}

/// A `log stream` seen to attach. Read on the supervisor's own thread until the fork, because the
/// supervisor must be single-threaded through it ([`crate::supervisor`]), and by a drain thread
/// from then on, as the Linux trace's journal is.
#[derive(Debug)]
struct Stream {
    child: Child,
    tag: String,
    /// Until the drain starts: the stream's stdout, what was read of it past the open mark, and
    /// the file.
    pending: Option<(ChildStdout, Vec<u8>, File)>,
    /// Once it has: the thread writing each denial into the file, and the marks it saw instead.
    drain: Option<(JoinHandle<()>, Receiver<Mark>)>,
}

/// Which of playpen's own denials came through.
#[derive(Debug, PartialEq)]
enum Mark {
    Open,
    Stop,
}

impl Mark {
    /// The message the mark's denial carries, as its last line: the run's tag, so the stream's
    /// filter passes it, and a word the agent's denials, which carry the bare tag, never end with.
    fn message(&self, tag: &str) -> String {
        match self {
            Mark::Open => format!("{tag} mark open"),
            Mark::Stop => format!("{tag} mark stop"),
        }
    }

    /// Provoke the mark: a throwaway sandbox under the run's tag, denied the one exec it makes.
    /// Written as a profile here rather than built through the backend: nono compiles a
    /// capability set, and has no way to ask for one denial and nothing else.
    fn provoke(&self, tag: &str) -> Result<(), String> {
        let profile = format!(
            "(version 1)(allow default)(deny process-exec (literal \"/usr/bin/true\") (with message \"{}\"))",
            self.message(tag)
        );
        Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/usr/bin/true"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(drop)
            .map_err(|err| format!("the mark could not be provoked: {err}"))
    }
}

/// Sort one line of the stream: a mark is returned, a denial is written into `file` as one line,
/// and anything else, the stream's banner among it, is dropped. The kernel puts the profile's
/// message on the denial's last line, so a mark is told by that line alone, which the agent
/// cannot choose. A newline the agent put in a denied path is escaped, so it cannot forge a line.
fn sort(line: &str, tag: &str, file: &mut File) -> Option<Mark> {
    let entry: serde_json::Value = serde_json::from_str(line).ok()?;
    let (at, message) = (
        entry["timestamp"].as_str()?,
        entry["eventMessage"].as_str()?,
    );
    let (denial, last) = message.rsplit_once('\n').unwrap_or((message, ""));
    for mark in [Mark::Open, Mark::Stop] {
        if last == mark.message(tag) {
            return Some(mark);
        }
    }
    let _ = writeln!(file, "{at} {}", denial.replace('\n', "\\n"));
    None
}

/// Open the trace for `run`, created empty so an operator reading it sees this run's denials and
/// never the last run's, and start streaming the run's denials into it. Refused only when the
/// file itself cannot be written: the flag's operand is unusable, which is the invocation's
/// problem, and no `refusal.trace.*` code would be true of it.
pub fn open(file: &Path, _workspace: &Path, run: &RunId) -> Result<Tracing, Refusal> {
    let created = File::create(file).map_err(|err| {
        Refusal::new(
            Code::InvocationUsage,
            format!("--trace-denials cannot write {}: {err}", file.display()),
        )
    })?;
    // The tag the backend attaches to this run's default deny, taken from the backend so the two
    // cannot drift. It is a run id behind a fixed prefix, so it needs no quoting in a predicate.
    let stream = crate::backend::denial_tag(run)
        .ok_or_else(|| "the run has no denial tag to stream".to_string())
        .and_then(|tag| stream(created, tag));
    Ok(Tracing {
        file: file.to_owned(),
        stream,
    })
}

/// Start `log stream` on `tag`'s denials and wait, on this thread, for it to attach.
fn stream(mut file: File, tag: String) -> Result<Stream, String> {
    // `/usr/bin/log` by path, because `log` alone is a zsh builtin. Its stderr goes nowhere: the
    // flag never writes to stderr. One JSON object per line, so a denial is read by field rather
    // than picked out of text, and the stream's banner, which is not JSON, falls away.
    let mut child = Command::new("/usr/bin/log")
        .args(["stream", "--style", "ndjson", "--predicate"])
        .arg(format!(
            "sender == \"Sandbox\" AND eventMessage CONTAINS \"{tag}\""
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("the unified log could not be streamed: {err}"))?;
    let out = child.stdout.take().ok_or("the log stream has no stdout")?;
    // Held by the stream from here, so a failure below kills the child as it drops.
    let mut stream = Stream {
        child,
        tag,
        pending: None,
        drain: None,
    };
    let past = attach(&out, &mut file, &stream.tag)
        .map_err(|why| format!("the log stream was not seen to attach: {why}"))?;
    stream.pending = Some((out, past, file));
    Ok(stream)
}

/// Provoke the open mark every [`MARK_EVERY`] until it comes through: one made before the stream
/// attached is never shown. No thread: the pipe is polled. Returns what was read past the mark.
fn attach(out: &ChildStdout, file: &mut File, tag: &str) -> Result<Vec<u8>, String> {
    let fd = out.as_raw_fd();
    let deadline = Instant::now() + MARK_BUDGET;
    let mut read = Vec::new();
    loop {
        Mark::Open.provoke(tag)?;
        let mut ready = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid `pollfd`, on a descriptor `out` holds open.
        let polled = unsafe { libc::poll(&mut ready, 1, MARK_EVERY.as_millis() as libc::c_int) };
        if polled > 0 {
            let mut chunk = [0; 8192];
            // SAFETY: `chunk` is writable for its length, and `fd` is held open by `out`. One
            // read, which `poll` said will not block; a partial line waits for the next.
            let got = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
            match got {
                0 => return Err("the stream ended".into()),
                n if n < 0 => return Err(std::io::Error::last_os_error().to_string()),
                n => read.extend_from_slice(&chunk[..n as usize]),
            }
        }
        while let Some(end) = read.iter().position(|&byte| byte == b'\n') {
            let line: Vec<u8> = read.drain(..=end).collect();
            if sort(&String::from_utf8_lossy(&line), tag, file) == Some(Mark::Open) {
                return Ok(read);
            }
        }
        if Instant::now() > deadline {
            return Err(format!("no mark within {MARK_BUDGET:?}"));
        }
    }
}

impl Stream {
    /// Hand the stream to a drain thread, if it has not been already. Only after the fork.
    fn drain(&mut self) -> &Receiver<Mark> {
        if let Some((out, past, mut file)) = self.pending.take() {
            let (send, marks) = channel();
            let tag = self.tag.clone();
            let drain = std::thread::spawn(move || {
                let lines = BufReader::new(Cursor::new(past).chain(out)).lines();
                for line in lines.map_while(Result::ok) {
                    if let Some(mark) = sort(&line, &tag, &mut file) {
                        let _ = send.send(mark);
                    }
                }
            });
            self.drain = Some((drain, marks));
        }
        let Some((_, marks)) = &self.drain else {
            unreachable!("pending until drained, and drained from then on")
        };
        marks
    }

    /// Provoke the stop mark and wait for it to come through, after every denial before it.
    // ponytail: assumes `log stream` delivers the kernel's denials in the order they were made,
    // which holds on macOS 26 but is not documented.
    fn drained(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + MARK_BUDGET;
        let tag = self.tag.clone();
        loop {
            Mark::Stop.provoke(&tag)?;
            match self.drain().recv_timeout(MARK_EVERY) {
                Ok(Mark::Stop) => return Ok(()),
                // A late copy of an open mark.
                Ok(Mark::Open) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err("the stream ended".into()),
            }
            if Instant::now() > deadline {
                return Err(format!("no mark within {MARK_BUDGET:?}"));
            }
        }
    }
}

impl Tracing {
    /// The file this run is traced into, for the record to name.
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Start draining, now the fork is past. The stream has run since [`open`], and it filters on
    /// the run's tag, which covers the whole confined tree rather than one pid.
    pub fn follow(&mut self, _pid: libc::pid_t, _since: SystemTime) {
        if let Ok(stream) = &mut self.stream {
            stream.drain();
        }
    }

    /// Wait for the stream to drain, then stop it. Returns why the trace is **unverified**, where
    /// it is: a stream that never attached, that ended before the run did, or that was not seen to
    /// drain may have missed denials, and a trace that cannot be vouched for is said to be so
    /// rather than presented as complete.
    pub fn stop(&mut self) -> Option<String> {
        let why = match &mut self.stream {
            Err(why) => why.clone(),
            Ok(stream) => {
                let ended = match stream.child.try_wait() {
                    Ok(None) => stream
                        .drained()
                        .err()
                        .map(|why| format!("the log stream was not seen to drain: {why}")),
                    Ok(Some(status)) => Some(format!("the log stream ended mid-run ({status})")),
                    Err(err) => Some(format!("the log stream could not be checked: {err}")),
                };
                // Killed, and the drain joined, before anything is appended after it.
                self.stream = Err("the trace was stopped".into());
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

/// A stream is killed when dropped, whether stopped or not — the run was refused after the trace
/// opened: a std `Child` is not killed on drop, and an orphaned `log stream` would run on past
/// playpen. The drain is waited for, so what it had is in the file before anything follows it.
impl Drop for Stream {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some((drain, _)) = self.drain.take() {
            let _ = drain.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run that made no denial is traced to an empty file, vouched for: the stream was seen to
    /// attach and to drain, and neither its banner nor playpen's own marks are written as if
    /// they were the kernel's.
    #[test]
    fn a_run_without_denials_is_traced_empty_and_verified() {
        let dir = tempfile::TempDir::new().expect("dir");
        let run = RunId::allocate().expect("id");
        let file = dir.path().join("trace");
        let mut tracing = open(&file, dir.path(), &run).expect("opened");
        assert_eq!(tracing.stop(), None);
        assert_eq!(std::fs::read_to_string(&file).expect("the trace"), "");
    }

    /// Only the agent's denials reach the file, one line each: a mark and the stream's banner are
    /// not denials, and a newline in a denied path, which the agent chooses, cannot forge a line.
    #[test]
    fn a_denial_is_one_line_and_a_mark_is_none() {
        let dir = tempfile::TempDir::new().expect("dir");
        let path = dir.path().join("trace");
        let mut file = File::create(&path).expect("file");
        let entry = |message: &str| {
            serde_json::json!({"timestamp": "T", "eventMessage": message}).to_string()
        };
        let tag = "playpen-run-X";
        let forged = format!("Sandbox: sh(1) deny(1) file-read-data /a\nT forged\n{tag}");
        assert_eq!(sort(&entry(&forged), tag, &mut file), None);
        let open = format!(
            "Sandbox: sandbox-exec(2) deny(1) process-exec* /usr/bin/true\n{tag} mark open"
        );
        assert_eq!(sort(&entry(&open), tag, &mut file), Some(Mark::Open));
        let stop = format!(
            "Sandbox: sandbox-exec(3) deny(1) process-exec* /usr/bin/true\n{tag} mark stop"
        );
        assert_eq!(sort(&entry(&stop), tag, &mut file), Some(Mark::Stop));
        assert_eq!(sort("Filtering the log data using …", tag, &mut file), None);
        assert_eq!(
            std::fs::read_to_string(&path).expect("the trace"),
            "T Sandbox: sh(1) deny(1) file-read-data /a\\nT forged\n"
        );
    }

    /// A stream that ended before the run did may have missed denials, and the trace says so.
    #[test]
    fn a_stream_that_ended_mid_run_leaves_the_trace_unverified() {
        let dir = tempfile::TempDir::new().expect("dir");
        let run = RunId::allocate().expect("id");
        let file = dir.path().join("trace");
        let mut tracing = open(&file, dir.path(), &run).expect("opened");
        tracing.follow(0, SystemTime::now());
        let stream = tracing.stream.as_mut().expect("streaming");
        stream.child.kill().expect("killed");
        stream.child.wait().expect("reaped");
        let why = tracing.stop().expect("unverified");
        assert!(why.contains("ended mid-run"), "{why}");
        let written = std::fs::read_to_string(&file).expect("the trace");
        assert_eq!(written, format!("# playpen: unverified: {why}\n"));
    }

    /// A run refused after the trace opened drops it unstopped, and the stream must go with it
    /// rather than outlive playpen holding the file open.
    #[test]
    fn a_dropped_trace_takes_its_stream_with_it() {
        let dir = tempfile::TempDir::new().expect("dir");
        let run = RunId::allocate().expect("id");
        let tracing = open(&dir.path().join("trace"), dir.path(), &run).expect("opened");
        let pid = tracing.stream.as_ref().expect("streaming").child.id() as libc::pid_t;
        drop(tracing);
        // SAFETY: signal 0 only asks whether `pid` exists.
        assert_ne!(
            unsafe { libc::kill(pid, 0) },
            0,
            "the stream outlived its trace"
        );
    }
}
