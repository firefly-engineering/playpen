//! The enforcement suite ([spec §17]): the backend's definition, so an assertion that can pass
//! vacuously is a defect ([ADR 0016]). The rows are data in [`rows`]; this runner checks its own
//! judging first, then runs every row and reports each one as *runs*, *`n/a`* or *skipped*.
//!
//! Not under the libtest harness: `P-canary` is the floor self-test itself, which forks, and its
//! child allocates before `exec`, which is sound only in a single-threaded process.
//!
//! [spec §17]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#17-the-enforcement-suite
//! [ADR 0016]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md

#[path = "../common/mod.rs"]
mod common;
mod row;
mod rows;
mod run;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use row::{
    Action, Asymmetry, BOTH, Class, Expected, Fixture, Os, Outcome, Platform, Row, Scope, Seen,
    Target, Verdict, judge,
};
use rows::ROWS;

fn main() {
    let checks: &[(&str, fn())] = &[
        ("row_ids_are_unique", row_ids_are_unique),
        (
            "every_expectation_belongs_to_its_rows_class",
            every_expectation_belongs_to_its_rows_class,
        ),
        (
            "every_action_runs_under_its_rows_fixture",
            every_action_runs_under_its_rows_fixture,
        ),
        (
            "a_negative_whose_target_is_absent_outside_is_a_setup_failure",
            a_negative_whose_target_is_absent_outside_is_a_setup_failure,
        ),
        (
            "enoent_inside_is_a_failed_negative",
            enoent_inside_is_a_failed_negative,
        ),
        (
            "a_negative_passes_only_on_a_denial_errno",
            a_negative_passes_only_on_a_denial_errno,
        ),
        (
            "a_positive_that_fails_outside_is_a_setup_failure",
            a_positive_that_fails_outside_is_a_setup_failure,
        ),
        (
            "a_row_scoped_to_the_other_platform_is_na_and_never_runs",
            a_row_scoped_to_the_other_platform_is_na_and_never_runs,
        ),
    ];
    for (name, check) in checks {
        check();
        eprintln!("harness {name} ... ok");
    }

    // Read once, here, and handed to the rows that need it.
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME names the caller's home"));
    let outcomes = run::run(ROWS, &home);
    for (row, outcome) in ROWS.iter().zip(&outcomes) {
        let from: Vec<String> = row.from.iter().map(ToString::to_string).collect();
        eprintln!(
            "row {} ({:?}; {}) ... {outcome}",
            row.id,
            row.class,
            from.join(", ")
        );
    }
    let count = |f: fn(&Outcome) -> bool| outcomes.iter().filter(|o| f(o)).count();
    let failed = count(Outcome::failed);
    eprintln!(
        "enforcement: {} run, {} n/a, {} skipped; {failed} failed",
        count(|o| matches!(o, Outcome::Runs(_))),
        count(|o| matches!(o, Outcome::NotApplicable(_))),
        count(|o| matches!(o, Outcome::Skipped(_))),
    );
    assert_eq!(failed, 0, "{failed} enforcement rows failed");
}

fn row_ids_are_unique() {
    let ids: HashSet<_> = ROWS.iter().map(|row| row.id).collect();
    assert_eq!(ids.len(), ROWS.len());
}

fn every_expectation_belongs_to_its_rows_class() {
    for row in ROWS {
        assert_eq!(row.expected.class(), row.class, "{}", row.id);
    }
}

fn every_action_runs_under_its_rows_fixture() {
    for row in ROWS {
        assert_eq!(row.action.fixture(), row.fixture, "{}", row.id);
    }
}

fn failed(errno: i32) -> Seen {
    Seen::Failed {
        errno: Some(errno),
        detail: format!("errno {errno}"),
    }
}

fn a_negative_whose_target_is_absent_outside_is_a_setup_failure() {
    // Whatever happens inside: the inside proves nothing about a target that is not there.
    for inside in [Seen::Succeeded, failed(common::DENIAL_ERRNOS[0])] {
        let verdict = judge(Expected::Denial, &failed(libc::ENOENT), &inside);
        assert!(matches!(verdict, Verdict::Setup(_)), "{verdict:?}");
    }
}

fn enoent_inside_is_a_failed_negative() {
    let verdict = judge(Expected::Denial, &Seen::Succeeded, &failed(libc::ENOENT));
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
}

fn a_negative_passes_only_on_a_denial_errno() {
    for &errno in common::DENIAL_ERRNOS {
        assert_eq!(
            judge(Expected::Denial, &Seen::Succeeded, &failed(errno)),
            Verdict::Pass
        );
    }
    for inside in [Seen::Succeeded, failed(libc::EBADF), failed(libc::EIO)] {
        let verdict = judge(Expected::Denial, &Seen::Succeeded, &inside);
        assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
    }
}

fn a_positive_that_fails_outside_is_a_setup_failure() {
    let verdict = judge(Expected::Succeeds, &failed(libc::EPERM), &Seen::Succeeded);
    assert!(matches!(verdict, Verdict::Setup(_)), "{verdict:?}");
    let verdict = judge(Expected::Succeeds, &Seen::Succeeded, &failed(libc::EPERM));
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
}

/// Under a home that does not exist the row could only be a setup failure if it ran, so `n/a` is
/// proof it did not.
fn a_row_scoped_to_the_other_platform_is_na_and_never_runs() {
    let elsewhere = match Os::HERE {
        Os::MacOs => Os::Linux,
        Os::Linux => Os::MacOs,
    };
    for &asymmetry in Asymmetry::ALL {
        let row = Row {
            id: "N-elsewhere",
            class: Class::Negative,
            platform: Platform {
                scope: Scope::Only(elsewhere, asymmetry),
                ..BOTH
            },
            fixture: Fixture::ProbeRoot,
            action: Action::Read(Target::SshKey),
            expected: Expected::Denial,
            from: &[],
        };
        let outcomes = run::run(&[row], Path::new("/nonexistent/playpen-home"));
        assert_eq!(outcomes, [Outcome::NotApplicable(asymmetry)]);
    }
}
