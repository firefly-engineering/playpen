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
mod live;
mod row;
mod rows;
mod run;

use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use playpen::code::Code;
use row::{
    Action, Asymmetry, BOTH, Cause, Checked, Class, Declined, Exchange, Exchanged, Expected,
    Fixture, Os, Outcome, Platform, Precondition, Row, Scope, Seen, Substitution, Target, Verdict,
    judge, judge_refusal, judge_request, judge_unexamined,
};
use rows::ROWS;
use run::{DECOY, DECOY_MARKER, SSH_KEY_DECOY};
use tempfile::TempDir;

fn main() {
    // Re-run by `R-missing-cap` as playpen: its inputs are read here, as `src/main.rs` reads them.
    let mut args = std::env::args_os().skip(1);
    match args.next() {
        Some(arg) if arg == OsStr::new(run::AS_PLAYPEN_OFFERING_NOTHING) => {
            let status = run::as_playpen_offering_nothing(args, std::env::current_dir());
            std::process::exit(status);
        }
        // Re-run by the `R-trace-denials` rows as playpen, with the denial trace's ladder reading
        // the facts the row names.
        #[cfg(target_os = "linux")]
        Some(arg) if arg == OsStr::new(run::AS_PLAYPEN_TRACING) => {
            let status = run::as_playpen_tracing(args, std::env::current_dir());
            std::process::exit(status);
        }
        _ => {}
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
            "an_unrecorded_refusal_names_no_run_and_leaves_the_ring_empty",
            an_unrecorded_refusal_names_no_run_and_leaves_the_ring_empty,
        ),
        (
            "a_spanned_refusal_needs_every_site_on_its_line",
            a_spanned_refusal_needs_every_site_on_its_line,
        ),
        (
            "an_unexamined_check_needs_the_examined_one_to_refuse",
            an_unexamined_check_needs_the_examined_one_to_refuse,
        ),
        (
            "an_authenticated_request_needs_the_secret_in_the_header_the_phantom_came_in",
            an_authenticated_request_needs_the_secret_in_the_header_the_phantom_came_in,
        ),
        (
            "the_bypass_pair_needs_both_legs_and_judges_each",
            the_bypass_pair_needs_both_legs_and_judges_each,
        ),
        (
            "a_brokered_denial_needs_the_status_the_header_and_the_code",
            a_brokered_denial_needs_the_status_the_header_and_the_code,
        ),
        (
            "no_upstream_leg_needs_the_request_to_have_been_refused",
            no_upstream_leg_needs_the_request_to_have_been_refused,
        ),
        (
            "a_command_that_fails_is_an_error_not_empty_output",
            a_command_that_fails_is_an_error_not_empty_output,
        ),
        (
            "a_command_past_its_deadline_is_killed_and_named",
            a_command_past_its_deadline_is_killed_and_named,
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

/// A command `P-denial-tree` runs that fails has said nothing about the log: read as empty output,
/// a `log show` that cannot run would be polled to its deadline and reported as a denial the log
/// never showed ([#142](https://github.com/firefly-engineering/playpen/issues/142)).
fn a_command_that_fails_is_an_error_not_empty_output() {
    // Spelled so the command's own text holds neither the stderr word nor the status the error
    // must carry, nor anything of stdout.
    let failed = run::shell(
        "echo p''artial; echo w''hy >&2; exit 7",
        run::SHELL_DEADLINE,
    )
    .expect("not wedged")
    .expect_err("exit 7 is an error");
    assert!(failed.contains("why"), "{failed}");
    assert!(failed.contains("exit status: 7"), "{failed}");
    assert!(!failed.contains("partial"), "{failed}");
    assert_eq!(
        run::shell("echo said", run::SHELL_DEADLINE),
        Ok(Ok("said\n".to_owned()))
    );
}

/// A wedged `log show` must end the row as a setup failure naming it, not hang the suite until
/// CI's own timeout ([#147](https://github.com/firefly-engineering/playpen/issues/147)). Its whole
/// tree goes with it: a grandchild left running would outlive the row.
fn a_command_past_its_deadline_is_killed_and_named() {
    let dir = TempDir::new().expect("dir");
    let survived = dir.path().join("survived");
    let command = format!("(sleep 1; touch '{}') & wait", survived.display());
    let started = std::time::Instant::now();
    let wedged =
        run::shell(&command, std::time::Duration::from_millis(100)).expect_err("past its deadline");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "{wedged}"
    );
    assert!(wedged.contains(&command), "{wedged}");
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert!(!survived.exists(), "a grandchild outlived the deadline");
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
        line: Some((code.to_string(), Some("01J9".into()))),
        text: format!("playpen: {code}: /p/policy.yaml:8:13 (defined at /p/policy.yaml:4:5): x"),
        recorded: Some(Some(code.to_string())),
        ring: 1,
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
            line: Some((other.clone(), Some("01J9".into()))),
            ..declined.clone()
        },
        // A line naming no run names no record, whatever the ring holds.
        Declined {
            line: Some((code.to_string(), None)),
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

/// A command that launches nothing is held to the converse of a launch's refusal: its line names
/// no run, and the ring stays empty. Either half alone passes on a build the other catches — a
/// line that merely omits its id, and a record opened for an `explain`.
fn an_unrecorded_refusal_names_no_run_and_leaves_the_ring_empty() {
    let code = Code::RunUnknown;
    let expected = Expected::Unrecorded(code);
    let declined = Declined {
        status: Some(playpen::refusal::EXIT_REFUSED),
        line: Some((code.to_string(), None)),
        text: format!("playpen: {code}: no record of run 01J9"),
        recorded: None,
        ring: 0,
        detail: String::new(),
    };
    assert_eq!(judge_refusal(expected, &declined), Verdict::Pass);
    for broken in [
        Declined {
            status: Some(0),
            ..declined.clone()
        },
        Declined {
            line: Some((Code::StateIo.to_string(), None)),
            ..declined.clone()
        },
        Declined {
            line: Some((code.to_string(), Some("01J9".into()))),
            recorded: Some(Some(code.to_string())),
            ring: 1,
            ..declined.clone()
        },
        Declined {
            ring: 1,
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

fn a_spanned_refusal_needs_every_site_on_its_line() {
    let code = Code::PolicyUnknownField;
    let declined = Declined {
        status: Some(playpen::refusal::EXIT_REFUSED),
        line: Some((code.to_string(), Some("01J9".into()))),
        text: format!("playpen: {code}: /p/policy.yaml:8:13 (defined at /p/policy.yaml:4:5): x"),
        recorded: Some(Some(code.to_string())),
        ring: 1,
        detail: String::new(),
    };
    let expected = Expected::RecordedAt(code, &[(8, 13), (4, 5)]);
    assert_eq!(judge_refusal(expected, &declined), Verdict::Pass);
    let verdict = judge_refusal(Expected::RecordedAt(code, &[(8, 13), (4, 6)]), &declined);
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
    // The code alone is not the assertion.
    let unplaced = Declined {
        text: format!("playpen: {code}: /p/policy.yaml: x"),
        ..declined
    };
    let verdict = judge_refusal(expected, &unplaced);
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
}

fn an_unexamined_check_needs_the_examined_one_to_refuse() {
    let code = Code::RootMissing;
    let expected = Expected::Unexamined(code);
    let checked = Checked {
        examined: Some(code.to_string()),
        unexamined_silent_success: true,
        detail: String::new(),
    };
    assert_eq!(judge_unexamined(expected, &checked), Verdict::Pass);
    // A check that never looks at the filesystem would pass the second half alone.
    for examined in [None, Some(Code::PolicySyntax.to_string())] {
        let verdict = judge_unexamined(
            expected,
            &Checked {
                examined,
                ..checked.clone()
            },
        );
        assert!(matches!(verdict, Verdict::Setup(_)), "{verdict:?}");
    }
    let verdict = judge_unexamined(
        expected,
        &Checked {
            unexamined_silent_success: false,
            ..checked
        },
    );
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

/// What the credential-route checks judge against.
const SECRET: &str = "the-real-secret";
const HEADER: &str = "x-api-key";
/// A value shaped like a session phantom: 64 lowercase hex digits ([spec §7.3]). The checks never
/// need a real one, because that is the whole shape the judging recognises.
///
/// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
const PHANTOM: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn substitution() -> Substitution<'static> {
    Substitution {
        secret: SECRET,
        header: HEADER,
    }
}

/// A leg that reached the destination with `arrived` as its head, answered `200`.
fn reached(arrived: &str) -> Exchange {
    Exchange {
        answer: Ok("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".into()),
        arrived: Some(arrived.to_owned()),
    }
}

/// The denial the broker answers, and no leg to the destination.
fn refused() -> Exchange {
    Exchange {
        answer: Ok(format!(
            "HTTP/1.1 403 Forbidden\r\nX-Playpen-Denied: localhost\r\n\r\n{}",
            Code::BrokerEndpointDenied
        )),
        arrived: None,
    }
}

fn exchanged(proxied: Exchange, unbrokered: Option<Exchange>) -> Exchanged {
    Exchanged {
        proxied,
        unbrokered,
        detail: String::new(),
    }
}

/// Substitution is **in place**: the secret has to arrive as the whole of the header the phantom
/// came in. A secret in some other header, or beside something else in this one, is a proxy that
/// did not do this.
fn an_authenticated_request_needs_the_secret_in_the_header_the_phantom_came_in() {
    let judged = |seen: &Exchanged| {
        judge_request(
            Expected::Authenticated,
            substitution(),
            &Seen::Succeeded,
            seen,
        )
    };
    let good = exchanged(
        reached(&format!(
            "GET /v1/messages HTTP/1.1\r\nHost: localhost\r\n{HEADER}: {SECRET}\r\n\r\n"
        )),
        None,
    );
    assert_eq!(judged(&good), Verdict::Pass);
    for broken in [
        // Nothing arrived at all, which is what a 502 upstream looks like from here.
        exchanged(
            Exchange {
                answer: Ok("HTTP/1.1 502 Bad Gateway\r\n\r\n".into()),
                arrived: None,
            },
            None,
        ),
        // The phantom was never replaced.
        exchanged(
            reached(&format!(
                "GET /v1/messages HTTP/1.1\r\n{HEADER}: {PHANTOM}\r\n\r\n"
            )),
            None,
        ),
        // Replaced, but not in the header it came in.
        exchanged(
            reached(&format!(
                "GET /v1/messages HTTP/1.1\r\nAuthorization: Bearer {SECRET}\r\n{HEADER}: \r\n\r\n"
            )),
            None,
        ),
        // The phantom left beside the secret in the same header, which a `contains` on the value
        // alone would admit.
        exchanged(
            reached(&format!(
                "GET /v1/messages HTTP/1.1\r\n{HEADER}: {SECRET} {PHANTOM}\r\n\r\n"
            )),
            None,
        ),
        // Substituted in place, and the phantom *also* copied into a second header. An assertion
        // about the one header's value cannot see this, which is why the phantom is recognised by
        // its shape anywhere in the head.
        exchanged(
            reached(&format!(
                "GET /v1/messages HTTP/1.1\r\n{HEADER}: {SECRET}\r\n\
                 X-Forwarded-Authorization: {PHANTOM}\r\n\r\n"
            )),
            None,
        ),
    ] {
        let verdict = judged(&broken);
        assert!(
            matches!(verdict, Verdict::Fail(_)),
            "{broken:?}: {verdict:?}"
        );
    }
    // A destination that is down outside proves nothing about the inside.
    let outside = Seen::Failed {
        cause: None,
        detail: "connection refused".into(),
    };
    let verdict = judge_request(
        Expected::Authenticated,
        substitution(),
        &outside,
        &exchanged(reached("GET /v1/messages HTTP/1.1\r\n\r\n"), None),
    );
    assert!(matches!(verdict, Verdict::Setup(_)), "{verdict:?}");
}

/// The pair is the assertion: the proxied leg authenticated and the bypassing one not. Either half
/// alone passes on a build the other catches — injecting into nothing, and the real secret having
/// reached the child's environment.
fn the_bypass_pair_needs_both_legs_and_judges_each() {
    let authenticated =
        format!("GET /v1/messages HTTP/1.1\r\nHost: localhost\r\n{HEADER}: {SECRET}\r\n\r\n");
    // The unbrokered leg arrives carrying the phantom, by construction: both legs present the
    // same request and nothing on this one strips it.
    let unauthenticated =
        format!("GET /v1/bypassed HTTP/1.1\r\nHost: localhost\r\n{HEADER}: {PHANTOM}\r\n\r\n");
    let judged = |seen: &Exchanged| {
        judge_request(
            Expected::OnlyThroughTheProxy,
            substitution(),
            &Seen::Succeeded,
            seen,
        )
    };
    let good = exchanged(reached(&authenticated), Some(reached(&unauthenticated)));
    assert_eq!(judged(&good), Verdict::Pass);
    // A build that injected into everything: the bypassing leg arrived authenticated.
    let leaked = exchanged(
        reached(&authenticated),
        Some(reached(
            &authenticated.replace("/v1/messages", "/v1/bypassed"),
        )),
    );
    assert!(matches!(judged(&leaked), Verdict::Fail(_)), "{leaked:?}");
    // A build that injected into nothing fails on the proxied half, not on the bypass half.
    let inert = exchanged(
        reached(&unauthenticated.replace("/v1/bypassed", "/v1/messages")),
        Some(reached(&unauthenticated)),
    );
    assert!(matches!(judged(&inert), Verdict::Fail(_)), "{inert:?}");
    // A row that drove no bypassing leg at all is a harness fault, not a verdict on the boundary.
    let alone = exchanged(reached(&authenticated), None);
    let verdict = judged(&alone);
    assert!(matches!(verdict, Verdict::Setup(_)), "{verdict:?}");
    // A bypassing leg that could not reach the destination *is* the boundary's: the outside half
    // already showed this host reaches it, so the child's own trust store having stopped naming
    // the roots it trusts reads as the regression it is, never as a host condition.
    let unreached = exchanged(
        reached(&authenticated),
        Some(Exchange {
            answer: Err("invalid peer certificate: UnknownIssuer".into()),
            arrived: None,
        }),
    );
    let verdict = judged(&unreached);
    assert!(matches!(verdict, Verdict::Fail(_)), "{verdict:?}");
}

/// The broker *answers* a denial rather than dropping the connection, and the answer carries both
/// the header the manifest states and the code consumers branch on ([spec §6.4]).
///
/// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
fn a_brokered_denial_needs_the_status_the_header_and_the_code() {
    let expected = Expected::Brokered(Code::BrokerEndpointDenied);
    let judged = |seen: &Exchanged| judge_request(expected, substitution(), &Seen::Succeeded, seen);
    assert_eq!(judged(&exchanged(refused(), None)), Verdict::Pass);
    let answered = |answer: &str| {
        exchanged(
            Exchange {
                answer: Ok(answer.to_owned()),
                arrived: None,
            },
            None,
        )
    };
    for broken in [
        // A dropped connection is not an answer.
        exchanged(
            Exchange {
                answer: Err("the peer closed".into()),
                arrived: None,
            },
            None,
        ),
        // The origin's own 403 would be a 403 with neither the header nor the code.
        answered("HTTP/1.1 403 Forbidden\r\n\r\n"),
        answered(&format!(
            "HTTP/1.1 403 Forbidden\r\n\r\n{}",
            Code::BrokerEndpointDenied
        )),
        answered("HTTP/1.1 403 Forbidden\r\nX-Playpen-Denied: localhost\r\n\r\nrefused"),
        // Not a denial at all.
        answered("HTTP/1.1 200 OK\r\n\r\nok"),
    ] {
        let verdict = judged(&broken);
        assert!(
            matches!(verdict, Verdict::Fail(_)),
            "{broken:?}: {verdict:?}"
        );
    }
}

/// "No upstream leg occurred" is about *that request*, so the request has to have been made and
/// refused. A destination records nothing just as readily from a launch that never ran.
fn no_upstream_leg_needs_the_request_to_have_been_refused() {
    let judged = |seen: &Exchanged| {
        judge_request(
            Expected::NoUpstreamLeg,
            substitution(),
            &Seen::Succeeded,
            seen,
        )
    };
    assert_eq!(judged(&exchanged(refused(), None)), Verdict::Pass);
    for broken in [
        // The launch never ran, so nothing was refused and nothing arrived.
        exchanged(
            Exchange {
                answer: Err("HTTPS_PROXY names no proxy".into()),
                arrived: None,
            },
            None,
        ),
        // Refused, and the secret had already gone out.
        exchanged(
            Exchange {
                arrived: Some(format!(
                    "GET /v1/messages HTTP/1.1\r\n{HEADER}: {SECRET}\r\n\r\n"
                )),
                ..refused()
            },
            None,
        ),
    ] {
        let verdict = judged(&broken);
        assert!(
            matches!(verdict, Verdict::Fail(_)),
            "{broken:?}: {verdict:?}"
        );
    }
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
