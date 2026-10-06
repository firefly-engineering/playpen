//! Every platform but Linux, which today means macOS: the flag is refused, because the macOS
//! trace is [#97](https://github.com/firefly-engineering/playpen/issues/97) and is not built yet.
//!
//! It is refused as an **invocation** rather than under a `refusal.trace.*` code: all six of
//! those name a Linux precondition, and macOS has none at all — its denials are already in the
//! kernel log under the run's denial tag. Saying "this playpen does not serve the flag here" is
//! the one thing that is true.

use std::path::Path;
use std::time::SystemTime;

use crate::code::Code;
use crate::refusal::Refusal;

/// One run's denial trace. Uninhabited here, which is the type saying what the module above does:
/// [`open`] always refuses, so nothing ever holds one of these.
#[derive(Debug)]
pub enum Tracing {}

/// Refuse the flag, naming the platform and the ticket that closes it.
pub fn open(_file: &Path, _workspace: &Path) -> Result<Tracing, Refusal> {
    Err(Refusal::new(
        Code::InvocationUsage,
        "--trace-denials is not implemented on this platform yet \
         (https://github.com/firefly-engineering/playpen/issues/97); a macOS run's denials are in \
         the kernel log under the tag `playpen explain --run` prints"
            .to_string(),
    ))
}

impl Tracing {
    /// The file this run is traced into.
    pub fn file(&self) -> &Path {
        match *self {}
    }

    /// Start tailing for the tree under `pid`.
    pub fn follow(&mut self, _pid: libc::pid_t, _since: SystemTime) {
        match *self {}
    }

    /// Stop the tail, and say why the trace is unverified if it is.
    pub fn stop(&mut self) -> Option<String> {
        match *self {}
    }

    /// The Landlock domain this run was confined by, which no platform here has.
    pub fn domain(&self) -> Option<&str> {
        match *self {}
    }
}
