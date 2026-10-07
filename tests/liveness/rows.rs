//! The liveness rows ([spec §17.2], last paragraph): `L-<kind>`, one per kind, in the enforcement
//! suite's own row form.
//!
//! [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows

use crate::row::{
    Action, Agent, Class, Decision, Expected, Fixture, Platform, Precondition, Row, Scope,
};

/// Off hosted CI first, so a hosted runner skips every row by the suite's own name before it
/// probes anything of the host's; then the agent, then the operator's choice of minter.
const fn live(agent: Agent) -> Platform {
    Platform {
        scope: Scope::Both,
        requires: match agent {
            Agent::Claude => &[
                Precondition::OffHostedCi,
                Precondition::Agent(Agent::Claude),
                Precondition::AnthropicMinter,
            ],
            Agent::Omp => &[
                Precondition::OffHostedCi,
                Precondition::Agent(Agent::Omp),
                Precondition::AnthropicMinter,
            ],
        },
    }
}

pub const ROWS: &[Row] = &[
    Row {
        id: "L-claude",
        class: Class::Positive,
        platform: live(Agent::Claude),
        fixture: Fixture::Agent,
        action: Action::Live(Agent::Claude),
        expected: Expected::Succeeds,
        from: &[Decision::Adr(16), Decision::Issue(106)],
    },
    Row {
        id: "L-omp",
        class: Class::Positive,
        platform: live(Agent::Omp),
        fixture: Fixture::Agent,
        action: Action::Live(Agent::Omp),
        expected: Expected::Succeeds,
        from: &[Decision::Adr(16), Decision::Issue(107)],
    },
];
