//! The liveness suite ([spec §17.2], last paragraph): the enforcement suite's runner and row form,
//! over one row per kind that launches the real agent confined. It gates only an agent-version or
//! kind-table change, never a playpen change, and a hosted CI runner skips every row as
//! `skip.suite.liveness-not-on-ci`.
//!
//! Everything it takes from the host is read once, here:
//!
//! - `PATH` finds each agent, and an interpreter one names. An agent installed somewhere of its
//!   own is put on it for the run: `PATH=$PWD/target/liveness/omp/node_modules/.bin:$PATH`.
//! - `PLAYPEN_LIVENESS_MINTER` names the `playpen-minter-anthropic` subcommand the task mints
//!   with, `setup-token` or `host-login`. Unset, every row is skipped as
//!   `skip.host.no-anthropic-minter`: which of the operator's credentials is read is theirs to say.
//! - `HOME` is where that minter finds the operator's keystore; the agent itself gets a synthetic
//!   one.
//! - `GITHUB_ACTIONS=true` is a hosted runner.
//!
//! Not under the libtest harness, as the enforcement suite is not: the runner is single-threaded.
//!
//! [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows

#[path = "../common/mod.rs"]
mod common;
#[path = "../enforcement/live.rs"]
mod live;
#[path = "../enforcement/row.rs"]
#[allow(dead_code)] // the enforcement suite's form, of which these rows use a part
mod row;
mod rows;
#[path = "../enforcement/run.rs"]
#[allow(dead_code)] // likewise its runner
mod run;

use std::collections::HashSet;
use std::path::PathBuf;

use row::{Fixture, Host, MINTER_ENV, Outcome, Precondition};
use rows::ROWS;

fn main() {
    let checks: &[(&str, fn())] = &[
        ("row_ids_are_unique", row_ids_are_unique),
        (
            "every_row_is_an_agent_launch_skipped_first_on_hosted_ci",
            every_row_is_an_agent_launch_skipped_first_on_hosted_ci,
        ),
        (
            "a_hosted_runner_skips_every_row_by_the_suites_name",
            a_hosted_runner_skips_every_row_by_the_suites_name,
        ),
    ];
    for (name, check) in checks {
        check();
        eprintln!("harness {name} ... ok");
    }

    let var = std::env::var_os;
    let host = Host {
        home: PathBuf::from(var("HOME").expect("HOME names the caller's home")),
        path: var("PATH"),
        hosted_ci: var("GITHUB_ACTIONS").is_some_and(|value| value == "true"),
        minter: var(MINTER_ENV).and_then(|value| value.into_string().ok()),
    };
    let outcomes = run::run_on(ROWS, &host);
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
        "liveness: {} run, {} n/a, {} skipped; {failed} failed",
        count(|o| matches!(o, Outcome::Runs(_))),
        count(|o| matches!(o, Outcome::NotApplicable(_))),
        count(|o| matches!(o, Outcome::Skipped(_))),
    );
    assert_eq!(failed, 0, "{failed} liveness rows failed");
}

fn row_ids_are_unique() {
    let ids: HashSet<_> = ROWS.iter().map(|row| row.id).collect();
    assert_eq!(ids.len(), ROWS.len());
}

/// Every row launches an agent, one per kind, and asks first whether it is on a hosted runner,
/// so that is the name it is skipped under there whatever else the host lacks.
fn every_row_is_an_agent_launch_skipped_first_on_hosted_ci() {
    for row in ROWS {
        assert_eq!(row.fixture, Fixture::Agent, "{}", row.id);
        assert!(row.action.admits(row.fixture), "{}", row.id);
        assert_eq!(row.expected.class(), row.class, "{}", row.id);
        assert_eq!(
            row.platform.requires.first(),
            Some(&Precondition::OffHostedCi),
            "{}",
            row.id
        );
    }
    let kinds: HashSet<_> = ROWS
        .iter()
        .filter_map(|row| match row.action {
            row::Action::Live(agent) => Some(agent.kind().name),
            _ => None,
        })
        .collect();
    let table: HashSet<_> = playpen::kind::KINDS.iter().map(|kind| kind.name).collect();
    assert_eq!(kinds, table, "one row per kind in the table");
}

/// On a hosted runner nothing is launched and nothing is probed: every row is skipped as
/// `skip.suite.liveness-not-on-ci`, even with an agent and a minter at hand.
fn a_hosted_runner_skips_every_row_by_the_suites_name() {
    let host = Host {
        home: PathBuf::from("/nonexistent/playpen-home"),
        path: Some(PathBuf::from(common::os_bin("sh")).into_os_string()),
        hosted_ci: true,
        minter: Some("host-login".into()),
    };
    let outcomes = run::run_on(ROWS, &host);
    assert_eq!(
        outcomes,
        vec![Outcome::Skipped(Precondition::OffHostedCi); ROWS.len()]
    );
    assert_eq!(
        Precondition::OffHostedCi.skip(),
        "skip.suite.liveness-not-on-ci"
    );
}
