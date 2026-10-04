//! The rows ([spec §17.2]). Ids are the spec's; a row is data, and nothing outside this table
//! knows which rows exist.
//!
//! [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows

use crate::row::{Action, BOTH, Class, Decision, Expected, Fixture, Row, Target};

pub const ROWS: &[Row] = &[
    // On macOS this cannot yet catch a floor whose content regressed:
    // https://github.com/firefly-engineering/playpen/issues/114
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
    Row {
        id: "N-ssh-key",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::ProbeRoot,
        action: Action::Read(Target::SshKey),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(53)],
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
];
