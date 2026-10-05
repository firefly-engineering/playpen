//! The rows ([spec §17.2]). Ids are the spec's; a row is data, and nothing outside this table
//! knows which rows exist.
//!
//! [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows

use playpen::code::Code;

use crate::row::{
    Action, Asymmetry, BOTH, Class, Decision, Expected, Fixture, Invocation, Listening, Os,
    POLICY_SPAN_SITES, Platform, Precondition, Row, Scope, Services, Signalled, Target,
};

/// Both platforms, for a row that puts a decoy in the caller's home when the host lacks the real
/// target.
const IN_HOME: Platform = Platform {
    scope: Scope::Both,
    requires: &[Precondition::HomeWritable],
};

pub const ROWS: &[Row] = &[
    // "The manifest is true", filesystem half: what the agent is told and what the kernel
    // enforces are one resolution pass, and this is what holds them to it.
    Row {
        id: "P-manifest",
        class: Class::Positive,
        platform: BOTH,
        fixture: Fixture::Manifest,
        action: Action::ManifestIsTrue,
        expected: Expected::Succeeds,
        from: &[Decision::Adr(11), Decision::Adr(16), Decision::Issue(78)],
    },
    // playpen reads no argument anywhere, so what it injects and what the child gets are held
    // together by one function and nothing else.
    Row {
        id: "P-argv",
        class: Class::Positive,
        platform: BOTH,
        fixture: Fixture::Shim,
        action: Action::ArgvMatches,
        expected: Expected::Succeeds,
        from: &[Decision::Adr(2), Decision::Adr(16), Decision::Issue(82)],
    },
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
        platform: IN_HOME,
        fixture: Fixture::ProbeRoot,
        action: Action::Read(Target::SshKey),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(53)],
    },
    Row {
        id: "N-ssh-config",
        class: Class::Negative,
        platform: IN_HOME,
        fixture: Fixture::ProbeRoot,
        action: Action::Read(Target::SshConfig),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(54)],
    },
    Row {
        id: "N-aws",
        class: Class::Negative,
        platform: IN_HOME,
        fixture: Fixture::ProbeRoot,
        action: Action::List(Target::Aws),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(54)],
    },
    Row {
        id: "N-npmrc",
        class: Class::Negative,
        platform: IN_HOME,
        fixture: Fixture::ProbeRoot,
        action: Action::Read(Target::Npmrc),
        expected: Expected::Denial,
        from: &[Decision::Adr(6), Decision::Adr(16), Decision::Issue(54)],
    },
    Row {
        id: "N-symlink",
        class: Class::Negative,
        platform: IN_HOME,
        fixture: Fixture::ProbeRoot,
        action: Action::Read(Target::LinkedCredentials),
        expected: Expected::Denial,
        from: &[Decision::Adr(14), Decision::Adr(16), Decision::Issue(64)],
    },
    Row {
        id: "N-store-stale",
        class: Class::Negative,
        platform: Platform {
            scope: Scope::Both,
            requires: &[Precondition::Nix],
        },
        fixture: Fixture::Toolchain,
        action: Action::Read(Target::StaleStorePath),
        expected: Expected::Denial,
        from: &[Decision::Adr(14), Decision::Adr(16), Decision::Issue(65)],
    },
    Row {
        id: "N-keg-decoy",
        class: Class::Negative,
        platform: Platform {
            scope: Scope::Both,
            requires: &[Precondition::Homebrew],
        },
        fixture: Fixture::Toolchain,
        action: Action::Read(Target::DecoyKeg),
        expected: Expected::Denial,
        from: &[Decision::Adr(19), Decision::Adr(16), Decision::Issue(65)],
    },
    Row {
        id: "N-exclusion",
        class: Class::Negative,
        platform: Platform {
            scope: Scope::Only(Os::MacOs, Asymmetry::Exclusions),
            ..BOTH
        },
        fixture: Fixture::Excluded,
        action: Action::Read(Target::ExcludedDecoy),
        expected: Expected::Denial,
        from: &[Decision::Adr(16), Decision::Issue(63), Decision::Issue(127)],
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
    // Process scoping, which every profile requires: asserted from inside, so a backend that stopped
    // applying it fails here rather than passing on the strength of the request alone.
    Row {
        id: "N-signal",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::ProbeRoot,
        action: Action::Signal(Signalled::DecoyProcess),
        expected: Expected::Denial,
        from: &[Decision::Adr(16), Decision::Issue(55), Decision::Issue(121)],
    },
    Row {
        id: "N-abstract-socket",
        class: Class::Negative,
        platform: Platform {
            scope: Scope::Only(Os::Linux, Asymmetry::AbstractSockets),
            ..BOTH
        },
        fixture: Fixture::ProbeRoot,
        action: Action::Connect(Listening::DecoyAbstractSocket),
        expected: Expected::Denial,
        from: &[Decision::Adr(16), Decision::Issue(55), Decision::Issue(121)],
    },
    // A denial by any process in the run's tree is found by the command `explain --run` prints,
    // not only the confined child's own.
    Row {
        id: "P-denial-tree",
        class: Class::Positive,
        platform: Platform {
            scope: Scope::Only(Os::MacOs, Asymmetry::DenialVisibility),
            ..BOTH
        },
        fixture: Fixture::DescendantDenied,
        action: Action::PullDenials,
        expected: Expected::Succeeds,
        from: &[Decision::Adr(7), Decision::Adr(16), Decision::Issue(124)],
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
    Row {
        id: "R-policy-span",
        class: Class::Refusal,
        platform: BOTH,
        fixture: Fixture::Outside,
        action: Action::Refuse(Invocation::MergedTypo),
        expected: Expected::RecordedAt(Code::PolicyUnknownField, POLICY_SPAN_SITES),
        from: &[Decision::Adr(9), Decision::Adr(16), Decision::Issue(56)],
    },
    Row {
        id: "R-no-filesystem",
        class: Class::Refusal,
        platform: BOTH,
        fixture: Fixture::Outside,
        action: Action::CheckDocument,
        expected: Expected::Unexamined(Code::RootMissing),
        from: &[Decision::Adr(9), Decision::Adr(16), Decision::Issue(56)],
    },
    Row {
        id: "R-incoherent-ws",
        class: Class::Refusal,
        platform: BOTH,
        fixture: Fixture::Outside,
        action: Action::Refuse(Invocation::IncoherentWorkspace),
        expected: Expected::Recorded(Code::WorkspaceUnknown),
        from: &[Decision::Adr(9), Decision::Adr(16), Decision::Issue(59)],
    },
    Row {
        id: "R-integrity",
        class: Class::Refusal,
        platform: BOTH,
        fixture: Fixture::Outside,
        action: Action::Refuse(Invocation::WritablePolicy),
        expected: Expected::Recorded(Code::IntegrityWritable),
        from: &[Decision::Adr(16), Decision::Issue(66)],
    },
    Row {
        id: "R-ceiling",
        class: Class::Refusal,
        platform: Platform {
            scope: Scope::Only(Os::MacOs, Asymmetry::CompiledProfileCeiling),
            ..BOTH
        },
        fixture: Fixture::Outside,
        action: Action::Refuse(Invocation::OverCeiling),
        expected: Expected::Recorded(Code::BudgetExceeded),
        from: &[Decision::Adr(16), Decision::Issue(67)],
    },
];
