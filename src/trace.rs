//! `--trace-denials` ([spec §14.5]): the kernel's own account of what it denied this run, tailed
//! into a file the operator named. It never writes to stderr, and it never weakens the boundary —
//! there is **no permissive-with-logging mode**.
//!
//! Where the platform cannot provide a trace, the **flag** is refused before launch, under a code
//! naming *which* precondition failed. That refusal is scoped to the flag and not to the run:
//! dropping the flag leaves a run playpen would have launched.
//!
//! On Linux the trace is Landlock's audit records, read out of the journal behind a ladder of
//! preconditions. macOS has none: its denials are already in the kernel log under the run's
//! **denial tag** ([spec §14.2]), so the trace is that log, streamed.
//!
//! [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
//! [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{Channel, Facts, LOGGING_ABI, SelfTest, Tracing, open, open_with};

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use macos::{Tracing, open};
