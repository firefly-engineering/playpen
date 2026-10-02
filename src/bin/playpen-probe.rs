//! `playpen-probe`: the shipped actor for boundary assertions. It performs one action and writes
//! its verdict as one JSON object on stdout. Its exit status carries one bit: the probe ran (0) or
//! the probe broke (non-zero).

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::process::ExitCode;

/// The closed set of actions. A new kind of check is a new variant.
enum Action {
    /// Open the path and read it to the end.
    Read(String),
    /// Create or truncate the path and write a byte to it.
    Write(String),
    /// List the descriptors above stderr held by this process.
    Fds,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let action = match args.as_slice() {
        [verb, path] if verb == "read" => Action::Read(path.clone()),
        [verb, path] if verb == "write" => Action::Write(path.clone()),
        [verb] if verb == "fds" => Action::Fds,
        _ => {
            eprintln!("usage: playpen-probe (read <path> | write <path> | fds)");
            return ExitCode::from(2);
        }
    };
    println!("{}", verdict(&action));
    ExitCode::SUCCESS
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
    }
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
