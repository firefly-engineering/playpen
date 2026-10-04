//! Process transparency ([spec §11.6]): stdio inherited untouched, signals forwarded to the
//! child's process group, the child's status returned, and nothing written on success.
//!
//! [spec §11.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#116-process-transparency

mod common;

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tempfile::TempDir;

use common::{Fixture, os_bin};

/// The (device, inode) of an open file, as the probe's `stdio` action reports it.
fn identity(file: &File) -> Value {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().expect("fstat");
    json!([meta.dev(), meta.ino()])
}

#[test]
fn a_piped_run_passes_bytes_through_untouched() {
    let fx = Fixture::new();
    let mut playpen = fx
        .run(&[&os_bin("cat")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("playpen");
    // Not text, not line-terminated, and with the bytes a terminal layer would rewrite.
    let input: Vec<u8> = (0..=255u8).chain(*b"\r\n\x03\x04\x1a").collect();
    playpen
        .stdin
        .take()
        .expect("stdin")
        .write_all(&input)
        .expect("write");
    let output = playpen.wait_with_output().expect("wait");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, input);
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn the_child_holds_the_callers_own_stdio_objects() {
    let fx = Fixture::new();
    let scratch = TempDir::new().expect("scratch");
    let open = |name: &str| {
        File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(scratch.path().join(name))
            .expect("stdio file")
    };
    let (stdin, stdout, stderr) = (open("in"), open("out"), open("err"));
    let expected = json!([identity(&stdin), identity(&stdout), identity(&stderr)]);

    let probe = fx.probe();
    let status = fx
        .run(&[probe.to_str().unwrap(), "stdio"])
        .stdin(stdin.try_clone().expect("dup"))
        .stdout(stdout.try_clone().expect("dup"))
        .stderr(stderr.try_clone().expect("dup"))
        .status()
        .expect("playpen");
    assert!(status.success());

    let seen: Value =
        serde_json::from_slice(&std::fs::read(scratch.path().join("out")).expect("read"))
            .expect("verdict");
    assert_eq!(
        seen["stdio"], expected,
        "the child's 0, 1 and 2 are not the caller's: no PTY, no pipe in between"
    );
    assert!(
        std::fs::read(scratch.path().join("err"))
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_child_killed_by_signal_n_exits_128_plus_n() {
    let fx = Fixture::new();
    for (signal, name) in [(libc::SIGTERM, "TERM"), (libc::SIGKILL, "KILL")] {
        let output = fx
            .run(&[&os_bin("sh"), "-c", &format!("kill -{name} $$")])
            .output()
            .expect("playpen");
        assert_eq!(output.status.code(), Some(128 + signal), "{output:?}");
        assert!(
            output.stdout.is_empty() && output.stderr.is_empty(),
            "a child's death is not playpen's to report: {output:?}"
        );
    }
}

#[test]
fn a_signal_the_caller_ignores_stays_ignored_in_the_child() {
    let fx = Fixture::new();
    // The child hangs itself up: it survives only if it inherited the caller's `nohup`.
    let mut command = fx.run(&[&os_bin("sh"), "-c", "kill -HUP $$; exit 7"]);
    // SAFETY: signal is async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            Ok(())
        });
    }
    let output = command.output().expect("playpen");
    assert_eq!(output.status.code(), Some(7), "{output:?}");
}

/// A running process whose confined probe waits for a signal, with its report readable line by
/// line. A watchdog kills the probe and the spawned process if a test stalls, so a missed signal
/// fails instead of hanging.
struct Waiting {
    spawned: Child,
    stdout: BufReader<ChildStdout>,
    /// The probe's first verdict: its pid, its process group and its terminal's foreground group.
    ready: Value,
    done: Arc<AtomicBool>,
}

impl Waiting {
    fn spawn(mut command: Command) -> Self {
        let mut spawned = command
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn playpen");
        let mut stdout = BufReader::new(spawned.stdout.take().expect("stdout"));
        let ready = read_verdict(&mut stdout);
        if !ready["pid"].is_i64() {
            // The probe never ran, so there is nothing to wait for. Stop the spawned process
            // here: a `Waiting` without a probe pid could not clean up after itself.
            let _ = spawned.kill();
            let _ = spawned.wait();
            panic!("the probe never reported ready; first line: {ready}");
        }
        let run = Self {
            spawned,
            stdout,
            ready,
            done: Arc::new(AtomicBool::new(false)),
        };
        let (probe, pid, done) = (run.probe_pid(), run.pid(), Arc::clone(&run.done));
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(10));
            kill_unless_done(&done, probe, pid);
        });
        run
    }

    fn pid(&self) -> libc::pid_t {
        self.spawned.id() as libc::pid_t
    }

    fn probe_pid(&self) -> libc::pid_t {
        self.ready["pid"].as_i64().expect("pid") as libc::pid_t
    }

    /// The process group the confined probe runs in.
    fn child_group(&self) -> libc::pid_t {
        self.ready["pgrp"].as_i64().expect("pgrp") as libc::pid_t
    }

    fn signal(&self, signal: libc::c_int) {
        // SAFETY: kill has no memory preconditions.
        assert_eq!(unsafe { libc::kill(self.pid(), signal) }, 0, "kill");
    }

    fn line(&mut self) -> Value {
        read_verdict(&mut self.stdout)
    }

    /// The rest of stdout and the spawned process's exit status.
    fn finish(mut self) -> (Vec<Value>, Option<i32>) {
        let mut rest = String::new();
        self.stdout.read_to_string(&mut rest).expect("read");
        let lines = rest
            .lines()
            .map(|l| serde_json::from_str(l).expect("verdict"))
            .collect();
        let status = self.spawned.wait().expect("wait").code();
        self.done.store(true, Ordering::SeqCst);
        (lines, status)
    }
}

fn read_verdict(stdout: &mut BufReader<ChildStdout>) -> Value {
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read");
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"))
}

/// A failed assertion must not leave the run behind holding the test's stderr open.
impl Drop for Waiting {
    fn drop(&mut self) {
        kill_unless_done(&self.done, self.probe_pid(), self.pid());
    }
}

fn kill_unless_done(done: &AtomicBool, probe: libc::pid_t, spawned: libc::pid_t) {
    if !done.swap(true, Ordering::SeqCst) {
        // SAFETY: kill has no memory preconditions. Neither pid can have been reused: the spawned
        // process is unreaped, and it outlives the probe it waits for.
        unsafe {
            libc::kill(probe, libc::SIGKILL);
            libc::kill(spawned, libc::SIGKILL);
        }
    }
}

/// The standard signals the probe's `wait-signal` waits for. It also waits for the first realtime
/// signal on Linux, which only the doubling test needs.
const WAITED: [libc::c_int; 5] = [
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

#[test]
fn catchable_signals_sent_to_playpen_reach_the_child_once() {
    let fx = Fixture::new();
    let probe = fx.probe();
    for signal in WAITED {
        // playpen runs as a job of its own, as a shell would start it. Left in the test's group,
        // it would hold the terminal's foreground whenever the suite runs from one, and a direct
        // `SIGINT` would then be taken for the terminal's and not forwarded (#112).
        let mut command = fx.run(&[probe.to_str().unwrap(), "wait-signal"]);
        command.process_group(0);
        let run = Waiting::spawn(command);
        assert_eq!(
            run.child_group(),
            run.pid(),
            "the child stays in playpen's job"
        );
        run.signal(signal);
        let (lines, status) = run.finish();
        assert_eq!(lines, [json!({"signal": signal, "count": 1})]);
        assert_eq!(status, Some(0), "playpen exits with the child's status");
    }
}

/// Whether `pid` still exists. The agent is playpen's child and not this process's, so once
/// playpen is gone there is no zombie of it to confuse the answer: the kernel reaps the orphan,
/// and signal 0 then fails with `ESRCH`.
fn alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 performs the permission and existence check and delivers nothing.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// **Named asymmetry #6** ([ADR 0025]): on Linux the agent cannot outlive its supervisor by any
/// route, `SIGKILL` of playpen included. That is the route [ADR 0010]'s orphan residual cites and
/// the one no handler can catch, so it is the one worth asserting. `n/a` on macOS, which has no
/// parent-death signal and no userspace stand-in that works after `exec`.
///
/// [ADR 0025]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0025-the-agent-does-not-outlive-its-supervisor-where-the-kernel-can-say-so.md
/// [ADR 0010]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0010-concurrency-is-a-property-of-a-provisioned-area.md
#[test]
#[cfg(target_os = "linux")]
fn the_agent_does_not_outlive_a_killed_supervisor() {
    let fx = Fixture::new();
    let probe = fx.probe();
    let mut command = fx.run(&[probe.to_str().unwrap(), "wait-signal"]);
    command.process_group(0);
    let run = Waiting::spawn(command);
    let agent = run.probe_pid();
    assert!(alive(agent), "the agent is running before the kill");

    run.signal(libc::SIGKILL);

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while alive(agent) {
        assert!(
            std::time::Instant::now() < deadline,
            "the agent {agent} outlived its killed supervisor: it is confined, holds the \
             caller's terminal, has no credentials and cannot be signalled by the caller"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let (_, status) = run.finish();
    assert_eq!(
        status, None,
        "playpen died by the signal rather than exiting with a status"
    );
}

/// A new pseudo-terminal: the master, and the slave as a file.
fn pty() -> (OwnedFd, File) {
    // SAFETY: posix_openpt has no memory preconditions.
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
    assert!(master >= 0, "posix_openpt");
    // SAFETY: `master` is a fresh descriptor nothing else owns.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    // SAFETY: grantpt and unlockpt act on the master descriptor only.
    unsafe {
        assert_eq!(libc::grantpt(master.as_raw_fd()), 0, "grantpt");
        assert_eq!(libc::unlockpt(master.as_raw_fd()), 0, "unlockpt");
    }
    // SAFETY: ptsname returns null or a NUL-terminated string, read before any other pty call.
    let name = unsafe {
        let name = libc::ptsname(master.as_raw_fd());
        assert!(!name.is_null(), "ptsname");
        std::ffi::CStr::from_ptr(name)
            .to_str()
            .expect("utf-8")
            .to_owned()
    };
    let slave = File::options()
        .read(true)
        .write(true)
        .open(name)
        .expect("open slave");
    (master, slave)
}

/// Run `command` as the leader of a new session whose controlling terminal is `slave`, on stdin.
fn with_controlling_terminal(command: &mut Command, slave: &File) {
    command.stdin(slave.try_clone().expect("dup"));
    // SAFETY: setsid and ioctl are async-signal-safe.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn foreground(master: &OwnedFd) -> libc::pid_t {
    // SAFETY: tcgetpgrp has no memory preconditions.
    unsafe { libc::tcgetpgrp(master.as_raw_fd()) }
}

/// Type `keys` at the terminal.
fn type_keys(master: &OwnedFd, keys: &[u8]) {
    // SAFETY: `keys` is valid for its length.
    let written = unsafe { libc::write(master.as_raw_fd(), keys.as_ptr().cast(), keys.len()) };
    assert_eq!(written, keys.len() as isize, "write to the terminal");
}

/// **Named asymmetry #7** ([ADR 0026]): signal origin is readable on Linux, so a `kill -INT` sent
/// straight to playpen while playpen's group holds the terminal's foreground is forwarded. It
/// arrives as `SI_USER`, where a keypress arrives as `SI_KERNEL`. macOS reports `0` for both and
/// drops it, which is the asymmetry's live consequence.
///
/// [ADR 0026]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0026-signal-origin-is-readable-on-linux-and-the-kill-target-is-readable-nowhere.md
#[test]
#[cfg(target_os = "linux")]
fn a_signal_sent_straight_to_a_foreground_playpen_is_forwarded() {
    let fx = Fixture::new();
    let probe = fx.probe();
    let (master, slave) = pty();
    let mut command = fx.run(&[probe.to_str().unwrap(), "wait-signal"]);
    // setsid plus TIOCSCTTY makes playpen's own group the terminal's foreground group, which is
    // exactly the condition under which the old predicate withheld the forward.
    with_controlling_terminal(&mut command, &slave);
    let mut screen = File::from(master.try_clone().expect("dup"));
    std::thread::spawn(move || std::io::copy(&mut screen, &mut std::io::sink()));
    let run = Waiting::spawn(command);
    drop(slave);

    let job = run.child_group();
    assert_eq!(
        run.ready["foreground"],
        json!(job),
        "the precondition: playpen's job holds the terminal's foreground: {}",
        run.ready
    );

    // Addressed to playpen alone, so the only copy the child can get is the forwarded one.
    run.signal(libc::SIGINT);
    let (lines, status) = run.finish();
    assert_eq!(
        lines,
        [json!({"signal": libc::SIGINT, "count": 1})],
        "a sent signal is not a keypress, and withholding it drops it entirely"
    );
    assert_eq!(status, Some(0));
    drop(master);
}

/// The twelfth **named residual** ([ADR 0026]), pinned by asserting the doubling it causes.
///
/// It reads oddly on purpose. A receiver learns a signal's *sender* and never its *target*, so
/// playpen cannot know the child already holds a copy of a group-directed signal, and the
/// doubling is unclosable rather than unclosed. This is the only thing that will notice if
/// someone later closes it with a heuristic — and a silent change in signal delivery surfaces
/// months later as an agent exiting on one Ctrl-C.
///
/// A **realtime** signal, because only its deliveries are queued. A standard signal delivered
/// twice while the first is still pending arrives once, and playpen's forward races the kernel's
/// direct copy closely enough that it often does — which would make this assert a coin flip
/// about *observability* rather than a fact about delivery. The residual itself is open on both
/// platforms ([spec §18](../docs/spec.md)); macOS has no queued signal to measure it with.
///
/// [ADR 0026]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0026-signal-origin-is-readable-on-linux-and-the-kill-target-is-readable-nowhere.md
#[test]
#[cfg(target_os = "linux")]
fn a_signal_addressed_to_the_whole_job_reaches_the_agent_twice() {
    let fx = Fixture::new();
    let probe = fx.probe();
    let mut command = fx.run(&[probe.to_str().unwrap(), "wait-signal"]);
    // A job of its own, so the kill below reaches playpen and the child and nothing of the suite.
    command.process_group(0);
    let run = Waiting::spawn(command);
    let job = run.pid();
    assert_eq!(run.child_group(), job, "the child is in playpen's job");

    // Addressed to the whole job: the kernel delivers one copy to the child directly, and playpen
    // forwards a second. Not tty-generated, so no origin test suppresses it — and `SI_USER` is
    // what a group kill and a process kill both report, which is the whole point.
    let queued = libc::SIGRTMIN();
    // SAFETY: kill has no memory preconditions.
    assert_eq!(unsafe { libc::kill(-job, queued) }, 0, "kill the job");

    let (lines, status) = run.finish();
    assert_eq!(
        lines,
        [json!({"signal": queued, "count": 2})],
        "if this now reads 1, the suppression predicate has grown a heuristic that guesses a \
         signal's target; the kernel does not report one (ADR 0026)"
    );
    assert_eq!(status, Some(0));
}

#[test]
fn at_an_interactive_shell_ctrl_c_arrives_once_and_ctrl_z_stops_the_whole_job() {
    let fx = Fixture::new();
    let probe = fx.probe();
    let (master, slave) = pty();
    // A job-control shell runs playpen as a foreground job, reports when the job stops, and
    // resumes it with `fg`. dash, because a non-interactive bash never returns from a stopped job.
    //
    // By name, not by path: this shell runs outside the boundary, as part of the harness rather
    // than as a confined target, so it is a host tool like the C toolchain and the dev shell
    // supplies it. A host that keeps it somewhere other than `/bin` then needs no special case.
    let mut command = Command::new("dash");
    command
        .args([
            "-c",
            r#"set -m; "$@"; echo '{"stopped":true}'; fg >/dev/null"#,
            "sh",
        ])
        .arg(fx.run(&[]).get_program())
        .args(fx.run(&[probe.to_str().unwrap(), "wait-signal"]).get_args())
        .env("XDG_STATE_HOME", fx.state_home())
        .current_dir(fx.root())
        .stderr(slave.try_clone().expect("dup"));
    with_controlling_terminal(&mut command, &slave);
    // Read the terminal's echo and the shell's job messages from the start, so the shell's exit
    // never waits on them, even when the run fails before the probe is ready.
    let mut screen = File::from(master.try_clone().expect("dup"));
    std::thread::spawn(move || std::io::copy(&mut screen, &mut std::io::sink()));
    let mut run = Waiting::spawn(command);
    drop(slave);

    // The child is in the foreground job, where a TUI may read its terminal.
    let job = run.child_group();
    assert_eq!(run.ready["foreground"], json!(job), "{}", run.ready);

    // Ctrl-Z stops the child and playpen alike, so the shell sees the whole job stopped.
    type_keys(&master, b"\x1a");
    assert_eq!(run.line(), json!({"stopped": true}));

    // Once `fg` has given the job the terminal back, Ctrl-C reaches the child exactly once.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while foreground(&master) != job {
        assert!(
            std::time::Instant::now() < deadline,
            "the job never resumed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    type_keys(&master, b"\x03");
    let (lines, status) = run.finish();
    assert_eq!(lines, [json!({"signal": libc::SIGINT, "count": 1})]);
    assert_eq!(status, Some(0));
}
