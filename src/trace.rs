//! `--trace-denials` ([spec §14.5]): the kernel's own account of what it denied this run, tailed
//! into a file the operator named. It never writes to stderr, and it never weakens the boundary —
//! there is **no permissive-with-logging mode**.
//!
//! Where the platform cannot provide a trace, the **flag** is refused before launch, under a code
//! naming *which* precondition failed. That refusal is scoped to the flag and not to the run:
//! dropping the flag leaves a run playpen would have launched.
//!
//! Only the Linux half is built. macOS has no preconditions at all — its denials are already in
//! the kernel log, under the run's **denial tag** ([spec §14.2]) — and is
//! [#97](https://github.com/firefly-engineering/playpen/issues/97). Until that lands the flag is
//! refused there as an invocation this playpen cannot serve, rather than under a `refusal.trace.*`
//! code that would not be true of it: every one of the six names a Linux precondition.
//!
//! [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
//! [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::{Channel, Facts, LOGGING_ABI, SelfTest, Tracing, open, open_with};

#[cfg(not(target_os = "linux"))]
mod elsewhere;

#[cfg(not(target_os = "linux"))]
pub use elsewhere::{Tracing, open};
