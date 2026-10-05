//! The rows ([spec §17.2]). Ids are the spec's; a row is data, and nothing outside this table
//! knows which rows exist.
//!
//! [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows

use playpen::code::Code;

use crate::row::{
    Action, Asymmetry, BOTH, Class, Decision, Expected, Fixture, Invocation, Os, Platform, Row,
    Scope, Services, Target,
};

pub const ROWS: &[Row] = &[
    Row {
        id: "P-canary",
        class: Class::Positive,
        platform: BOTH,
        fixture: Fixture::BareFloor,
        action: Action::Canary,
        expected: Expected::Succeeds,
        from: &[
            Decision::Adr(6),
            Decision::Adr(14),
            Decision::Adr(16),
            Decision::Issue(50),
        ],
    },
    // What keeps `P-canary` from passing vacuously: if the canary ran with nothing granted, it
    // would run whatever the floor held, and a tidied floor would go unnoticed.
    Row {
        id: "N-nothing-granted",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::NothingGranted,
        action: Action::Canary,
        expected: Expected::Denial,
        from: &[Decision::Adr(29), Decision::Adr(16), Decision::Issue(114)],
    },
    Row {
        id: "N-ssh-key",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::ProbeRoot,
        action: Action::Read(Target::SshKey),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(53)],
    },
    Row {
        id: "N-ssh-config",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::ProbeRoot,
        action: Action::Read(Target::SshConfig),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(54)],
    },
    Row {
        id: "N-aws",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::ProbeRoot,
        action: Action::List(Target::Aws),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(54)],
    },
    Row {
        id: "N-npmrc",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::ProbeRoot,
        action: Action::Read(Target::Npmrc),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(54)],
    },
    Row {
        id: "N-hosttemp",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::ProbeRoot,
        action: Action::Read(Target::HostTemp),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(54)],
    },
    Row {
        id: "N-keychain",
        class: Class::Negative,
        platform: Platform {
            scope: Scope::Only(Os::MacOs, Asymmetry::Keychain),
            ..BOTH
        },
        fixture: Fixture::ProbeRoot,
        action: Action::LookUp(Services::Keychain),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(54)],
    },
    Row {
        id: "N-fd",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::ProbeRoot,
        action: Action::ReadInherited,
        expected: Expected::Closed,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(54)],
    },
    // The file does not exist yet, so a mechanism that hid the directory rather than denying it
    // would answer `ENOENT`: the sharpest instance of the law.
    Row {
        id: "N-errno-law",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::ProbeRoot,
        action: Action::Create(Target::DecoyDir),
        expected: Expected::Denial,
        from: &[Decision::Adr(7), Decision::Adr(16), Decision::Issue(53)],
    },
    Row {
        id: "R-record",
        class: Class::Refusal,
        platform: BOTH,
        fixture: Fixture::Outside,
        action: Action::Refuse(Invocation::Usage),
        expected: Expected::Recorded(Code::InvocationUsage),
        from: &[Decision::Adr(7), Decision::Adr(16), Decision::Issue(54)],
    },
    Row {
        id: "R-state-reachable",
        class: Class::Refusal,
        platform: BOTH,
        fixture: Fixture::Outside,
        action: Action::Refuse(Invocation::StateReachable),
        expected: Expected::Recorded(Code::StateReachable),
        from: &[Decision::Adr(27), Decision::Adr(16), Decision::Issue(116)],
    },
    Row {
        id: "R-missing-cap",
        class: Class::Refusal,
        platform: BOTH,
        fixture: Fixture::Outside,
        action: Action::Refuse(Invocation::MissingCapability),
        expected: Expected::Recorded(Code::MechanismUnavailable),
        from: &[Decision::Adr(3), Decision::Adr(16), Decision::Issue(55)],
    },
];
