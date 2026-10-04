//! `playpen-probe`: the shipped actor for boundary assertions. It performs one action and writes
//! its verdict as one JSON object per line on stdout. Its exit status carries one bit: the probe
//! ran (0) or the probe broke (non-zero).

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// The closed set of actions. A new kind of check is a new variant.
enum Action {
    /// Open the path and read it to the end.
    Read(String),
    /// Create or truncate the path and write a byte to it.
    Write(String),
    /// List the descriptors above stderr held by this process.
    Fds,
    /// Report the identity (device, inode) of descriptors 0, 1 and 2.
    Stdio,
    /// Report this process's id, its group and its terminal's foreground group, then wait for
    /// one of [`WAITED`] and report it with how many arrived. Two verdicts, one per line.
    WaitSignal,
}

/// The signals `wait-signal` waits for: ones whose default action would terminate the probe.
const WAITED: &[libc::c_int] = &[
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGUSR1,
    libc::SIGUSR2,
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let action = match args.as_slice() {
        [verb, path] if verb == "read" => Action::Read(path.clone()),
        [verb, path] if verb == "write" => Action::Write(path.clone()),
        [verb] if verb == "fds" => Action::Fds,
        [verb] if verb == "stdio" => Action::Stdio,
        [verb] if verb == "wait-signal" => Action::WaitSignal,
        _ => {
            eprintln!(
                "usage: playpen-probe (read <path> | write <path> | fds | stdio | wait-signal)"
            );
            return ExitCode::from(2);
        }
    };
    match action {
        Action::WaitSignal => wait_signal(),
        action => {
            println!("{}", verdict(&action));
            ExitCode::SUCCESS
        }
    }
}

fn verdict(action: &Action) -> String {
    match action {
        Action::Read(path) => {
            io_verdict(File::open(path).and_then(|mut f| f.read_to_end(&mut Vec::new())))
        }
        Action::Write(path) => io_verdict(
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)
                .and_then(|mut f| f.write_all(b"x")),
        ),
        Action::Fds => {
            let fds: Vec<String> = held_fds().iter().map(|fd| fd.to_string()).collect();
            format!(r#"{{"fds":[{}]}}"#, fds.join(","))
        }
        Action::Stdio => {
            let ids: Vec<String> = (0..3)
                .map(|fd| match identity(fd) {
                    Some((dev, ino)) => format!("[{dev},{ino}]"),
                    None => "null".to_string(),
                })
                .collect();
            format!(r#"{{"stdio":[{}]}}"#, ids.join(","))
        }
        Action::WaitSignal => unreachable!("wait-signal writes its own verdicts"),
    }
}

/// The (device, inode) of an open descriptor, which names the object behind it.
fn identity(fd: libc::c_int) -> Option<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` is a valid out-pointer; fstat fails cleanly on a closed descriptor.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: fstat succeeded, so it initialised `stat`.
    let stat = unsafe { stat.assume_init() };
    #[allow(clippy::unnecessary_cast)] // the field widths differ by platform
    Some((stat.st_dev as u64, stat.st_ino as u64))
}

/// The first signal `wait-signal` took, or 0 while it waits.
static FIRST: AtomicI32 = AtomicI32::new(0);
/// How many waited signals arrived in all.
static COUNT: AtomicI32 = AtomicI32::new(0);

/// How long `wait-signal` keeps counting after the first signal, to catch a second delivery.
const GRACE: Duration = Duration::from_millis(300);

extern "C" fn record(sig: libc::c_int) {
    let _ = FIRST.compare_exchange(0, sig, Ordering::SeqCst, Ordering::SeqCst);
    COUNT.fetch_add(1, Ordering::SeqCst);
}

/// Waits in `sigsuspend` rather than `sigwait`: on macOS a thread inside `sigwait` is not stopped
/// by `SIGTSTP`, and the probe must stop like any job.
fn wait_signal() -> ExitCode {
    // SAFETY: a zeroed sigset_t is valid storage, initialised by sigemptyset.
    let (mut set, mut unblocked): (libc::sigset_t, libc::sigset_t) =
        unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    // SAFETY: `set` is valid storage.
    unsafe { libc::sigemptyset(&mut set) };
    // SAFETY: a zeroed sigaction is valid; the handler only touches atomics.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = record as extern "C" fn(libc::c_int) as libc::sighandler_t;
    for &sig in WAITED {
        // SAFETY: `set` and `action` are initialised; `sig` is a valid signal number.
        if unsafe { libc::sigaddset(&mut set, sig) } != 0
            || unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) } != 0
        {
            return ExitCode::from(1);
        }
    }
    // Blocking before reporting ready leaves no window in which a waited signal could be missed.
    // SAFETY: both sets are valid for the call.
    if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut unblocked) } != 0 {
        return ExitCode::from(1);
    }
    // SAFETY: none of these has preconditions; tcgetpgrp is -1 without a terminal.
    let (pid, pgrp, foreground) = unsafe { (libc::getpid(), libc::getpgrp(), libc::tcgetpgrp(0)) };
    println!(r#"{{"pid":{pid},"pgrp":{pgrp},"foreground":{foreground}}}"#);
    while FIRST.load(Ordering::SeqCst) == 0 {
        // SAFETY: `unblocked` is the initialised mask from before blocking.
        unsafe { libc::sigsuspend(&unblocked) };
    }
    // SAFETY: as above; the waited signals stay handled, so further ones are only counted.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &unblocked, std::ptr::null_mut()) };
    std::thread::sleep(GRACE);
    println!(
        r#"{{"signal":{},"count":{}}}"#,
        FIRST.load(Ordering::SeqCst),
        COUNT.load(Ordering::SeqCst)
    );
    ExitCode::SUCCESS
}

fn io_verdict<T>(result: std::io::Result<T>) -> String {
    match result {
        Ok(_) => r#"{"ok":true}"#.to_string(),
        Err(err) => {
            let errno = err.raw_os_error().unwrap_or(-1);
            let enoent = err.kind() == ErrorKind::NotFound;
            format!(r#"{{"ok":false,"errno":{errno},"enoent":{enoent}}}"#)
        }
    }
}

/// Descriptors above 2, found by asking the kernel about each one rather than by listing a
/// directory, which would itself open a descriptor and need a grant.
fn held_fds() -> Vec<i32> {
    // SAFETY: getdtablesize has no preconditions.
    let limit = unsafe { libc::getdtablesize() };
    // SAFETY: F_GETFD on any integer is harmless; it fails with EBADF when the fd is not open.
    (3..limit)
        .filter(|&fd| unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1)
        .collect()
}
