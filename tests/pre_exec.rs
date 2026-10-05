//! Signals while the child is still before `exec` ([spec §11.6]): the supervisor called as a
//! library, with the child held in that window by the `prepare` hook until a signal reaches it.
//! The window is normally microseconds, so holding it open is the only way to test it rather
//! than race it ([#117](https://github.com/firefly-engineering/playpen/issues/117)).
//!
//! Not under the libtest harness: the supervisor forks and blocks signals process-wide, which is
//! sound only in a single-threaded process.
//!
//! [spec §11.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#116-process-transparency

mod common;

use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use playpen::child;
use playpen::record::RunId;

use common::{os_bin, pty};

/// The argument that makes this test run as the job: playpen's supervisor in a process of its
/// own, so the signals it holds for the rest of its life are never the test's. Followed by the
/// signal the held child counts and the descriptor that says it is in the window.
const AS_JOB: &str = "--as-job";

fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some(AS_JOB) {
        let mut number = || args.next().and_then(|n| n.parse().ok()).expect("a number");
        let (counted, ready) = (number(), number());
        std::process::exit(supervise_held_child(ready, counted));
    }
    let tests: &[(&str, fn())] = &[
        (
            "a_signal_sent_to_playpen_in_the_window_reaches_the_child",
            a_signal_sent_to_playpen_in_the_window_reaches_the_child,
        ),
        (
            "a_terminal_signal_in_the_window_reaches_the_child_once",
            a_terminal_signal_in_the_window_reaches_the_child_once,
        ),
    ];
    for (name, test) in tests {
        test();
        eprintln!("test {name} ... ok");
    }
}

/// Signals of `counted` the held child received.
static COUNTED: AtomicI32 = AtomicI32::new(0);

extern "C" fn count(_: libc::c_int) {
    COUNTED.fetch_add(1, Ordering::SeqCst);
}

/// How long the held child waits for a second copy of a signal once the first has arrived.
const GRACE: Duration = Duration::from_millis(300);

/// Supervise a child that, before `exec`, writes a line to the descriptor `ready`, then waits for
/// `counted` and exits with how many arrived. A child the signal never reaches is ended by
/// `SIGALRM` instead, so a failure reports rather than hangs. Returns playpen's exit status.
fn supervise_held_child(ready: libc::c_int, counted: libc::c_int) -> i32 {
    let caps = playpen::floor::floor().expect("the floor");
    let run = RunId::allocate().expect("a run id");
    let argv = [OsString::from(os_bin("true"))];
    let hold = || {
        // SAFETY: the child is single-threaded after the fork. The handler only counts, and
        // `ready` is open in it, inherited across the fork.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = count as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigaction(counted, &action, std::ptr::null_mut());
            libc::alarm(5);
            libc::write(ready, b"\n".as_ptr().cast(), 1);
            while COUNTED.load(Ordering::SeqCst) == 0 {
                libc::pause();
            }
        }
        std::thread::sleep(GRACE);
        // SAFETY: `_exit` skips the parent's atexit handlers, which must not run twice.
        unsafe { libc::_exit(COUNTED.load(Ordering::SeqCst)) }
    };
    child::run_confined(
        &caps,
        &argv,
        &run,
        hold,
        |_| {},
        |fault| panic!("a fault: {fault:?}"),
    )
    .expect("a launch")
}

/// A pipe as (read end, write end), both close-on-exec.
fn pipe() -> (File, File) {
    let mut fds = [0; 2];
    // SAFETY: `fds` is valid for two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    for fd in fds {
        // SAFETY: both descriptors were just opened.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    // SAFETY: both descriptors were just opened and are owned here alone.
    unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
}

/// The job, counting `counted`, started by `command` once the job's arguments are added; with
/// the read end of its ready pipe, returned once its child has reached the window.
fn spawn_job(mut command: Command, counted: libc::c_int) -> (Child, File) {
    let (mut ready, signalled) = pipe();
    let fd = signalled.as_raw_fd();
    command.args([AS_JOB, &counted.to_string(), &fd.to_string()]);
    // SAFETY: fcntl is async-signal-safe; the descriptor is open in the forked child.
    unsafe {
        command.pre_exec(move || match libc::fcntl(fd, libc::F_SETFD, 0) {
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
    let job = command.spawn().expect("spawn the job");
    drop(signalled);
    let mut line = [0u8; 1];
    ready
        .read_exact(&mut line)
        .expect("the child reached the window");
    (job, ready)
}

/// The job's exit status, killing it if it has not exited within a deadline.
fn finish(mut job: Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = job.try_wait().expect("wait") {
            return status;
        }
        if Instant::now() > deadline {
            let _ = job.kill();
            panic!("the job never ended");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn this_test() -> Command {
    Command::new(std::env::current_exe().expect("this test"))
}

/// `kill <playpen>` while the child is held before `exec`: playpen must forward it, as it would
/// once the child had `exec`ed. Not a terminal's, so nothing suppresses it.
fn a_signal_sent_to_playpen_in_the_window_reaches_the_child() {
    let mut command = this_test();
    // A job of its own, as a shell would start it, so the signal below reaches playpen alone.
    command.process_group(0);
    let (job, _ready) = spawn_job(command, libc::SIGUSR1);
    // SAFETY: kill has no memory preconditions; the job is unreaped, so the pid is its own.
    assert_eq!(
        unsafe { libc::kill(job.id() as libc::pid_t, libc::SIGUSR1) },
        0
    );
    let status = finish(job);
    assert_eq!(
        status.code(),
        Some(1),
        "{status}: the child should count one SIGUSR1 (an exit of {} is the alarm: never forwarded)",
        128 + libc::SIGALRM
    );
}

/// Ctrl-C while the child is held before `exec`: the terminal delivers it to the child itself,
/// so playpen must not forward a second copy. The job runs in a session of its own, at a pty.
fn a_terminal_signal_in_the_window_reaches_the_child_once() {
    let (master, slave) = pty();
    let mut command = this_test();
    command
        .stdin(slave.try_clone().expect("dup"))
        .stdout(slave.try_clone().expect("dup"));
    // SAFETY: setsid and ioctl are async-signal-safe; stdin is the slave in the forked child.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let (job, _ready) = spawn_job(command, libc::SIGINT);
    drop(slave);
    // Drain the terminal, so nothing the job writes to it ever blocks.
    let mut screen = File::from(master.try_clone().expect("dup"));
    std::thread::spawn(move || std::io::copy(&mut screen, &mut std::io::sink()));
    File::from(master).write_all(b"\x03").expect("Ctrl-C");
    let status = finish(job);
    assert_eq!(
        status.code(),
        Some(1),
        "{status}: the child should count one SIGINT"
    );
}
