//! The confined child ([spec §4.1]): closes every descriptor above 2, applies the capability set
//! to itself, and `exec`s the target. The supervisor stays the child's direct parent, forwards
//! signals to it, and exits with its status ([`crate::supervisor`]).
//!
//! [spec §4.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#41-processes

use std::ffi::OsString;
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::backend;
use crate::capability::CapabilitySet;
use crate::code::Code;
use crate::record::RunId;
use crate::refusal::{EXIT_REFUSED, Refusal};
use crate::supervisor::HeldSignals;

/// Fork, confine the child under `caps`, `exec` `argv` in the inherited CWD, and wait for it.
/// `on_exec` receives the child's pid once the target has been `exec`ed. Returns the status the
/// supervisor exits with. `run` names the run on a refusal line the child has to write itself.
///
/// The supervisor must still be single-threaded here: the child allocates between `fork` and
/// `exec`, which is sound only when no other thread can hold the allocator's lock.
pub fn run_confined(
    caps: &CapabilitySet,
    argv: &[OsString],
    run: &RunId,
    on_exec: impl FnOnce(libc::pid_t),
) -> Result<i32, Refusal> {
    let (target, args) = argv
        .split_first()
        .ok_or_else(|| Refusal::new(Code::InvocationUsage, "no target after `--`"))?;
    let mut command = Command::new(target);
    command.args(args);

    let held = HeldSignals::block()?;
    let started = spawn_confined(caps, &mut command, Some(run), || {
        held.release_in_child();
        Ok(())
    })?;
    match started {
        Started::Exec(pid) => {
            on_exec(pid);
            held.supervise(pid)
        }
        Started::Refused(refusal) => Err(refusal),
    }
}

/// How a confined child started.
pub(crate) enum Started {
    /// The target was `exec`ed in the child with this pid; the caller reaps it.
    Exec(libc::pid_t),
    /// The child refused before `exec`, and has been reaped.
    Refused(Refusal),
}

/// Fork a child that runs `prepare`, closes every descriptor above 2, applies `caps` to itself
/// and `exec`s `command`, and wait until it has `exec`ed or refused.
///
/// The child never writes a refusal line itself: it reports the refusal to the supervisor over a
/// close-on-exec pipe, which `exec` closes empty, so the supervisor records the code and writes
/// the line with the run id. `prepare` runs between `fork` and `exec`, so it is bound by the same
/// single-threaded rule. `run` names the run should the report itself fail and the child have
/// to write the line.
pub(crate) fn spawn_confined(
    caps: &CapabilitySet,
    command: &mut Command,
    run: Option<&RunId>,
    prepare: impl FnOnce() -> Result<(), Refusal>,
) -> Result<Started, Refusal> {
    let pipe_refusal = |e: std::io::Error| {
        Refusal::new(
            Code::ProcessFork,
            format!("cannot open the child's report pipe: {e}"),
        )
    };
    let (report, first) = std::io::pipe().map_err(pipe_refusal)?;
    // std duplicates close-on-exec and onto a descriptor above 2, so the report end never reaches
    // the target, and a caller that closed its stdio cannot have it land where `prepare` redirects.
    let reporter = PipeWriter::from(first.as_fd().try_clone_to_owned().map_err(pipe_refusal)?);
    drop(first);
    // SAFETY: plain fork; the child only runs `prepare` and `confine_and_exec`, never returning.
    let pid = match unsafe { libc::fork() } {
        -1 => {
            return Err(Refusal::new(
                Code::ProcessFork,
                format!("fork failed: {}", std::io::Error::last_os_error()),
            ));
        }
        0 => confine_and_exec(caps, command, reporter, run, prepare),
        pid => pid,
    };
    // The child holds the only other write end; the read below ends at its `exec` or its exit.
    // Signals stay held, not forwarded, until then
    // ([#117](https://github.com/firefly-engineering/playpen/issues/117)).
    drop(reporter);
    match read_report(report) {
        None => Ok(Started::Exec(pid)),
        Some(refusal) => {
            reap(pid);
            Ok(Started::Refused(refusal))
        }
    }
}

fn confine_and_exec(
    caps: &CapabilitySet,
    command: &mut Command,
    mut reporter: PipeWriter,
    run: Option<&RunId>,
    prepare: impl FnOnce() -> Result<(), Refusal>,
) -> ! {
    let confined = prepare()
        .and_then(|()| close_inherited_fds(reporter.as_raw_fd()))
        .and_then(|()| backend::apply(caps));
    let refusal = match confined {
        Ok(()) => {
            let err = command.exec();
            Refusal::new(
                Code::TargetExec,
                format!("cannot exec {}: {err}", command.get_program().display()),
            )
        }
        Err(refusal) => refusal,
    };
    if reporter.write_all(&encode_report(&refusal)).is_err() {
        // The supervisor cannot hear it, so the line is all that is left.
        refusal.emit(run);
    }
    // SAFETY: `_exit` skips the parent's atexit handlers, which must not run twice.
    unsafe { libc::_exit(EXIT_REFUSED) }
}

/// A refusal on the report pipe: the code's index in the registry, then the message. Both ends
/// are this one binary, so the index names the same code on either side.
fn encode_report(refusal: &Refusal) -> Vec<u8> {
    let index = Code::ALL
        .iter()
        .position(|&code| code == refusal.code)
        .map_or(u16::MAX, |i| i as u16);
    let mut bytes = index.to_le_bytes().to_vec();
    bytes.extend_from_slice(refusal.message().as_bytes());
    bytes
}

/// The child's refusal, or `None` once it has `exec`ed: `exec` closes the pipe with nothing on it.
fn read_report(mut report: PipeReader) -> Option<Refusal> {
    let mut bytes = Vec::new();
    // A pipe that fails mid-read is taken for what it delivered; the wait reports the rest.
    let _ = report.read_to_end(&mut bytes);
    if bytes.is_empty() {
        return None;
    }
    let decoded = bytes.split_first_chunk::<2>().and_then(|(index, message)| {
        let code = *Code::ALL.get(usize::from(u16::from_le_bytes(*index)))?;
        Some(Refusal::new(code, String::from_utf8_lossy(message)))
    });
    // The child died part-way through its report: it refused, but its reason is lost.
    Some(decoded.unwrap_or_else(|| {
        Refusal::new(
            Code::ProcessFork,
            "the child refused before exec, and its report was cut short",
        )
    }))
}

/// Collect a child that has refused. Its status is already known to be `125`, so a wait that
/// fails — the caller ignored `SIGCHLD` and the kernel reaped it — changes nothing.
fn reap(pid: libc::pid_t) {
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out-pointer for the duration of the call.
        if unsafe { libc::waitpid(pid, &mut status, 0) } != -1
            || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            return;
        }
    }
}

/// The sandbox gates acquiring a descriptor, not using one already open, so nothing inherited
/// above stderr may survive into the target ([spec §8.7]). `keep` is the report pipe, which is
/// close-on-exec and so does not survive either.
///
/// [spec §8.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#87-file-descriptors
fn close_inherited_fds(keep: libc::c_int) -> Result<(), Refusal> {
    for fd in open_fds()? {
        if fd > 2 && fd != keep {
            // SAFETY: closing a descriptor this process holds; none is in use by Rust code here.
            unsafe { libc::close(fd) };
        }
    }
    Ok(())
}

fn fd_refusal(err: std::io::Error) -> Refusal {
    Refusal::new(
        Code::MechanismUnavailable,
        format!("cannot enumerate inherited descriptors: {err}"),
    )
}

#[cfg(target_os = "macos")]
fn open_fds() -> Result<Vec<libc::c_int>, Refusal> {
    use std::mem::size_of;

    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() };
    let entry = size_of::<libc::proc_fdinfo>() as libc::c_int;
    // SAFETY: a null buffer asks proc_pidinfo for the size it needs.
    let needed =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if needed <= 0 {
        return Err(fd_refusal(std::io::Error::last_os_error()));
    }
    // Room for descriptors opened between the two calls; none are, but the call must not truncate.
    let capacity = needed as usize / entry as usize + 16;
    let mut buf: Vec<libc::proc_fdinfo> = Vec::with_capacity(capacity);
    // SAFETY: the buffer holds `capacity` entries and its byte size is passed alongside it.
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast(),
            capacity as libc::c_int * entry,
        )
    };
    if written <= 0 {
        return Err(fd_refusal(std::io::Error::last_os_error()));
    }
    // SAFETY: proc_pidinfo initialised `written` bytes of whole entries.
    unsafe { buf.set_len(written as usize / entry as usize) };
    Ok(buf.iter().map(|info| info.proc_fd).collect())
}

#[cfg(target_os = "linux")]
fn open_fds() -> Result<Vec<libc::c_int>, Refusal> {
    // Collect first, then close: closing while iterating would close the directory's own fd.
    let mut fds = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fd").map_err(fd_refusal)? {
        let name = entry.map_err(fd_refusal)?.file_name();
        if let Some(fd) = name.to_str().and_then(|s| s.parse().ok()) {
            fds.push(fd);
        }
    }
    Ok(fds)
}
