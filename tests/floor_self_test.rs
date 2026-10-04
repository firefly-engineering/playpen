//! The floor self-test ([spec §8.6]) called as a library, the way the suite's `P-canary` row calls
//! it: one implementation, two callers.
//!
//! Not under the libtest harness. The self-test forks, and its child allocates before `exec`, which
//! is sound only in a single-threaded process; libtest runs every test on a thread of its own.
//!
//! [spec §8.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#86-the-floor-self-test

use std::process::Command;

use playpen::capability::{Access, CapabilitySet, PathGrant, Scope};
use playpen::code::Code;
use playpen::self_test::{self, canary_path};

fn main() {
    let tests: &[(&str, fn())] = &[
        (
            "the_canary_exits_zero_outside",
            the_canary_exits_zero_outside,
        ),
        (
            "the_bare_floor_passes_the_self_test",
            the_bare_floor_passes_the_self_test,
        ),
        (
            "a_canary_that_cannot_be_confined_fails_the_self_test",
            a_canary_that_cannot_be_confined_fails_the_self_test,
        ),
        (
            "every_call_runs_the_canary_afresh",
            every_call_runs_the_canary_afresh,
        ),
    ];
    // In order, on this one thread; the first failure panics and fails the suite.
    for (name, test) in tests {
        test();
        eprintln!("test {name} ... ok");
    }
}

fn the_canary_exits_zero_outside() {
    let canary = canary_path();
    let status = Command::new(&canary).status().expect("run the canary");
    assert!(
        status.success(),
        "{} fails outside: {status}",
        canary.display()
    );
}

fn the_bare_floor_passes_the_self_test() {
    if let Err(refusal) = self_test::floor() {
        panic!("the floor self-test failed: {refusal}");
    }
}

/// A set the backend cannot apply: the throwaway child refuses before `exec`. Nothing can be taken
/// away from the floor through a capability set, and on macOS nono's base profile alone lets an OS
/// binary exit 0, so this is how a failure is provoked on both platforms.
fn unappliable() -> CapabilitySet {
    CapabilitySet {
        paths: vec![PathGrant {
            path: "/nonexistent/playpen-self-test".into(),
            access: Access::Read,
            scope: Scope::Subtree,
            from: "test".into(),
            state_derived: false,
        }],
        mach_services: vec![],
    }
}

fn a_canary_that_cannot_be_confined_fails_the_self_test() {
    let refusal = self_test::canary(&unappliable()).expect_err("the child cannot confine itself");
    assert_eq!(refusal.code, Code::FloorSelfTest, "{refusal}");
    let line = refusal.to_string();
    let canary = canary_path();
    assert!(
        line.contains(&*canary.to_string_lossy()),
        "the canary is named: {line}"
    );
    assert!(
        line.contains("/nonexistent/playpen-self-test"),
        "the child's own reason is carried: {line}"
    );
}

/// A pass, a failure, then a pass: no verdict is carried from one call to the next.
fn every_call_runs_the_canary_afresh() {
    assert!(self_test::floor().is_ok());
    assert!(self_test::canary(&unappliable()).is_err());
    assert!(self_test::floor().is_ok());
}
