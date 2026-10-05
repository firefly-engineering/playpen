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
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use playpen::code::Code;
use row::{
    Action, Asymmetry, BOTH, Cause, Class, Declined, Expected, Fixture, Os, Outcome, Platform,
    Precondition, Row, Scope, Seen, Target, Verdict, judge, judge_refusal,
};
use rows::ROWS;
use run::{DECOY, DECOY_MARKER, SSH_KEY_DECOY};
use tempfile::TempDir;

fn main() {
    // Re-run by `R-missing-cap` as playpen: its inputs are read here, as `src/main.rs` reads them.
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() == Some(OsStr::new(run::AS_PLAYPEN_OFFERING_NOTHING)) {
        let status = run::as_playpen_offering_nothing(args, std::env::current_dir());
        std::process::exit(status);
    }
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
            "a_mach_negative_passes_only_when_the_lookup_is_not_privileged",
            a_mach_negative_passes_only_when_the_lookup_is_not_privileged,
        ),
        (
            "a_closed_descriptor_negative_passes_only_on_ebadf",
            a_closed_descriptor_negative_passes_only_on_ebadf,
        ),
        (
            "a_positive_that_fails_outside_is_a_setup_failure",
            a_positive_that_fails_outside_is_a_setup_failure,
        ),
        (
            "a_recorded_refusal_needs_the_exit_the_code_and_the_record",
            a_recorded_refusal_needs_the_exit_the_code_and_the_record,
        ),
        (
            "a_row_scoped_to_the_other_platform_is_na_and_never_runs",
            a_row_scoped_to_the_other_platform_is_na_and_never_runs,
        ),
        (
            "decoys_a_killed_run_left_are_reclaimed_and_the_rows_run",
            decoys_a_killed_run_left_are_reclaimed_and_the_rows_run,
        ),
        (
            "a_file_that_merely_contains_the_decoy_line_is_the_hosts",
            a_file_that_merely_contains_the_decoy_line_is_the_hosts,
        ),
        (
            "a_decoy_directory_holding_anything_else_is_the_hosts",
            a_decoy_directory_holding_anything_else_is_the_hosts,
        ),
        (
            "a_non_empty_ssh_directory_is_the_hosts",
            a_non_empty_ssh_directory_is_the_hosts,
        ),
        (
            "a_host_with_a_key_of_its_own_is_left_untouched",
            a_host_with_a_key_of_its_own_is_left_untouched,
        ),
        (
            "an_unwritable_home_skips_the_rows_that_write_there",
            an_unwritable_home_skips_the_rows_that_write_there,
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
        assert!(row.action.admits(row.fixture), "{}", row.id);
    }
}

fn failed(errno: i32) -> Seen {
    Seen::Failed {
        cause: Some(Cause::Errno(errno)),
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

/// A sandbox denies a lookup as not privileged; an unknown service is what absence reads as, so
/// it fails the row as `ENOENT` does. On Linux no lookup is a denial.
fn a_mach_negative_passes_only_when_the_lookup_is_not_privileged() {
    let looked_up = |kr: i32| Seen::Failed {
        cause: Some(Cause::Bootstrap(kr)),
        detail: format!("kr {kr}"),
    };
    #[cfg(target_os = "macos")]
    {
        use mach2::bootstrap::{BOOTSTRAP_NOT_PRIVILEGED, BOOTSTRAP_UNKNOWN_SERVICE};
        let inside = looked_up(BOOTSTRAP_NOT_PRIVILEGED);
        assert_eq!(
            judge(Expected::Denial, &Seen::Succeeded, &inside),
            Verdict::Pass
        );
        let verdict = judge(
            Expected::Denial,
            &Seen::Succeeded,
            &looked_up(BOOTSTRAP_UNKNOWN_SERVICE),
        );
        assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
    }
    // The errno that shares the number never stands in for the kern_return_t.
    let verdict = judge(Expected::Denial, &Seen::Succeeded, &looked_up(libc::EPERM));
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
}

fn a_closed_descriptor_negative_passes_only_on_ebadf() {
    assert_eq!(
        judge(Expected::Closed, &Seen::Succeeded, &failed(libc::EBADF)),
        Verdict::Pass
    );
    // A kernel denial is not playpen closing the descriptor.
    for inside in [Seen::Succeeded, failed(common::DENIAL_ERRNOS[0])] {
        let verdict = judge(Expected::Closed, &Seen::Succeeded, &inside);
        assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
    }
    let verdict = judge(Expected::Closed, &failed(libc::EBADF), &failed(libc::EBADF));
    assert!(matches!(verdict, Verdict::Setup(_)), "{verdict:?}");
}

fn a_positive_that_fails_outside_is_a_setup_failure() {
    let verdict = judge(Expected::Succeeds, &failed(libc::EPERM), &Seen::Succeeded);
    assert!(matches!(verdict, Verdict::Setup(_)), "{verdict:?}");
    let verdict = judge(Expected::Succeeds, &Seen::Succeeded, &failed(libc::EPERM));
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
}

fn a_recorded_refusal_needs_the_exit_the_code_and_the_record() {
    let code = Code::InvocationUsage;
    let expected = Expected::Recorded(code);
    let declined = Declined {
        status: Some(playpen::refusal::EXIT_REFUSED),
        line: Some((code.to_string(), "01J9".into())),
        recorded: Some(Some(code.to_string())),
        detail: String::new(),
    };
    assert_eq!(judge_refusal(expected, &declined), Verdict::Pass);
    let other = Code::KindUnknown.to_string();
    for broken in [
        // A run that launched leaves a record too.
        Declined {
            status: Some(0),
            ..declined.clone()
        },
        Declined {
            line: None,
            ..declined.clone()
        },
        Declined {
            line: Some((other.clone(), "01J9".into())),
            ..declined.clone()
        },
        Declined {
            recorded: None,
            ..declined.clone()
        },
        Declined {
            recorded: Some(None),
            ..declined.clone()
        },
        Declined {
            recorded: Some(Some(other)),
            ..declined.clone()
        },
    ] {
        let verdict = judge_refusal(expected, &broken);
        assert!(
            matches!(verdict, Verdict::Fail(_)),
            "{broken:?}: {verdict:?}"
        );
    }
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

/// The rows that put a decoy in the caller's home when the host lacks the real target: those that
/// need it writable. `ids` narrows them; empty, it takes them all.
fn in_home(ids: &[&str]) -> Vec<Row> {
    let rows: Vec<Row> = ROWS
        .iter()
        .filter(|row| row.platform.requires.contains(&Precondition::HomeWritable))
        .filter(|row| ids.is_empty() || ids.contains(&row.id))
        .copied()
        .collect();
    // Every id asked for names a row that writes in the home.
    assert!(ids.is_empty() || rows.len() == ids.len(), "{ids:?}");
    rows
}

/// A home of the check's own holding `files`, each at a path relative to it.
fn home_with(files: &[(&str, &str)]) -> TempDir {
    let home = TempDir::new().expect("home");
    for (path, content) in files {
        let path = home.path().join(path);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
        std::fs::write(path, content).expect("plant");
    }
    home
}

/// Every path under `home`, relative to it, with a file's content.
fn contents(home: &Path) -> Vec<(PathBuf, Option<String>)> {
    let mut seen = Vec::new();
    let mut pending = vec![home.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("list") {
            let path = entry.expect("entry").path();
            let relative = path.strip_prefix(home).expect("under home").to_path_buf();
            if path.is_dir() {
                seen.push((relative, None));
                pending.push(path);
            } else {
                seen.push((
                    relative,
                    Some(std::fs::read_to_string(&path).expect("read")),
                ));
            }
        }
    }
    seen.sort();
    seen
}

/// A run killed before its teardown leaves every decoy behind. The next run reclaims each one
/// rather than take it for the host's, asserts against a fresh decoy, and tears that down.
fn decoys_a_killed_run_left_are_reclaimed_and_the_rows_run() {
    let home = home_with(&[
        (&format!(".ssh/{SSH_KEY_DECOY}"), DECOY),
        (".ssh/config", DECOY),
        (".npmrc", DECOY),
        (&format!(".aws/{DECOY_MARKER}"), DECOY),
    ]);
    let outcomes = run::run(&in_home(&[]), home.path());
    assert!(
        outcomes.iter().all(|o| *o == Outcome::Runs(Verdict::Pass)),
        "{outcomes:?}"
    );
    assert_eq!(contents(home.path()), [], "a decoy outlived the run");
}

/// Content is the discriminator, and only an exact match: a host file the decoy line was once
/// appended to, or that quotes it, is the host's.
fn a_file_that_merely_contains_the_decoy_line_is_the_hosts() {
    let npmrc = format!("registry=https://example.invalid/\n{DECOY}");
    let home = home_with(&[(".npmrc", &npmrc)]);
    let before = contents(home.path());
    run::run(&in_home(&["N-npmrc"]), home.path());
    assert_eq!(contents(home.path()), before);
}

/// A decoy directory that has since gained anything of the host's is the host's, whole: removal is
/// never recursive.
fn a_decoy_directory_holding_anything_else_is_the_hosts() {
    let home = home_with(&[
        (&format!(".aws/{DECOY_MARKER}"), DECOY),
        (".aws/credentials", "[default]\n"),
    ]);
    let before = contents(home.path());
    run::run(&in_home(&["N-aws"]), home.path());
    assert_eq!(contents(home.path()), before);
}

/// `~/.ssh` is reclaimed only when empty, so the host's own files in it survive every run.
fn a_non_empty_ssh_directory_is_the_hosts() {
    let home = home_with(&[(".ssh/known_hosts", "example.invalid ssh-ed25519 AAAA\n")]);
    let before = contents(home.path());
    run::run(&in_home(&["N-ssh-key", "N-ssh-config"]), home.path());
    assert_eq!(contents(home.path()), before, "only the decoys went");
}

/// A host key is what the row reads, so nothing is written, and a stale decoy beside it is not
/// this row's to reclaim.
fn a_host_with_a_key_of_its_own_is_left_untouched() {
    let home = home_with(&[
        (".ssh/id_ed25519", "not a real key\n"),
        (&format!(".ssh/{SSH_KEY_DECOY}"), DECOY),
    ]);
    let before = contents(home.path());
    let outcomes = run::run(&in_home(&["N-ssh-key"]), home.path());
    assert_eq!(outcomes, [Outcome::Runs(Verdict::Pass)]);
    assert_eq!(contents(home.path()), before);
}

/// Never a setup failure, which would read like a boundary regression, and never a synthetic
/// home, which would assert less than the spec says.
fn an_unwritable_home_skips_the_rows_that_write_there() {
    use std::os::unix::fs::PermissionsExt;
    let home = home_with(&[]);
    let mode = |mode| {
        std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(mode)).expect("chmod")
    };
    mode(0o500);
    let outcomes = run::run(&in_home(&[]), home.path());
    mode(0o700);
    assert_eq!(
        outcomes,
        vec![Outcome::Skipped(Precondition::HomeWritable); in_home(&[]).len()]
    );
}
