//! The rows ([spec §17.2]). Ids are the spec's; a row is data, and nothing outside this table
//! knows which rows exist.
//!
//! [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows

use playpen::code::Code;

use crate::row::{
    Action, Asymmetry, BOTH, Class, Decision, DedicatedFloor, Expected, Fixture, Invocation, Legs,
    Listening, Location, Os, Platform, Precondition, Row, Rung, Scope, Services, Signalled, Target,
};

/// Linux only, under the denial-visibility asymmetry: macOS yields a trace with zero
/// preconditions, where Linux has three and a channel self-test. Partly permanent — macOS's
/// channel is certifiable *a priori* and Linux's only *a posteriori* ([spec §15.4] item 4).
///
/// [spec §15.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#154-named-asymmetries
const TRACING: Platform = Platform {
    scope: Scope::Only(Os::Linux, Asymmetry::DenialVisibility),
    requires: &[],
};

/// What every `R-trace-denials` row rests on.
const TRACE_FROM: &[Decision] = &[
    Decision::Adr(7),
    Decision::Adr(16),
    Decision::Issue(32),
    Decision::Issue(34),
    Decision::Issue(98),
    Decision::Issue(99),
];

/// One refusal row per rung of the ladder, each naming the precondition that failed: "the kernel
/// is too old", "the backend does not ask for logging" and "you are not in `wheel`" are three
/// different things an operator acts on differently, so one row asserting "it refused somehow"
/// would be the collapse the codes exist to prevent.
///
/// The code comes from the rung rather than from a literal beside it, so the two cannot drift —
/// and a rung that refuses nothing cannot be written as a refusal row at all.
const fn rung(rung: Rung) -> Row {
    let Some(code) = rung.code() else {
        panic!("a refusal row's rung refuses under a code")
    };
    Row {
        id: rung.row(),
        class: Class::Refusal,
        platform: TRACING,
        fixture: Fixture::Outside,
        action: Action::Refuse(Invocation::TraceDenials(rung)),
        expected: Expected::Recorded(code),
        from: TRACE_FROM,
    }
}

/// Both platforms, for a row that puts a decoy in the caller's home when the host lacks the real
/// target.
const IN_HOME: Platform = Platform {
    scope: Scope::Both,
    requires: &[Precondition::HomeWritable],
};

/// A refusal row that runs on both platforms, from outside, and is judged by its exit, its line
/// and its record: the shape of every row that exists to produce one code.
const fn refused(
    id: &'static str,
    invocation: Invocation,
    code: Code,
    from: &'static [Decision],
) -> Row {
    Row {
        id,
        class: Class::Refusal,
        platform: BOTH,
        fixture: Fixture::Outside,
        action: Action::Refuse(invocation),
        expected: Expected::Recorded(code),
        from,
    }
}

/// A key misspelt inside `definitions:`, arriving through a merge key ([spec §10.2]).
///
/// [spec §10.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#102-syntax-and-strictness
const MERGED_TYPO: &str = "\
version: 1
definitions:
  root: &root
    mdoe: read
workspaces:
  w:
    roots:
      - <<: *root
        path: \"{root}\"
        mode: read
profiles:
  p: { workspaces: [w], toolchain: [] }
";

/// Where [`MERGED_TYPO`]'s misspelt key is used, and where it is defined.
const POLICY_SPAN_SITES: &[(u32, u32)] = &[(8, 13), (4, 5)];

/// A flow sequence never closed.
const UNCLOSED: &str = "version: [1\n";

/// A version this playpen does not read.
const NEXT_VERSION: &str = "version: 2\n";

/// An explicit YAML tag that is not `!area`.
const TAGGED: &str = "version: !!int 1\n";

/// `profiles` as a sequence, where it is a map.
const MISTYPED: &str = "version: 1\nprofiles: []\n";

/// A profile naming a workspace the policy does not declare.
const UNDECLARED_WORKSPACE: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p: { workspaces: [w, undeclared], toolchain: [] }
";

// Every coherence document below is one entry away from the coherent shape: one workspace over the
// fixture's root, and profile `p` selecting it. Spelt out in each, so a row reads whole.

/// A second brought root whose path is not absolute.
const RELATIVE_ROOT: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }, { path: relative/root, mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [] }
";

/// A profile listing an env fragment the policy does not declare.
const UNDECLARED_FRAGMENT: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [], env: { fragments: [undeclared] } }
";

/// `SSH_AUTH_SOCK` passed through: a credential oracle the proxy cannot see.
const FORBIDDEN_NAME: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [], env: { allow: [SSH_AUTH_SOCK] } }
";

/// `TMPDIR` set, which playpen writes.
const RESERVED_NAME: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [], env: { set: { TMPDIR: /tmp } } }
";

/// One name both passed through and set by the one profile.
const TWO_AUTHORS: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [], env: { allow: [CARGO_HOME], set: { CARGO_HOME: /c } } }
";

/// An `!area` reference to an area the workspace does not declare.
const DANGLING_AREA: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }], areas: { a: { lifetime: ephemeral } } }
profiles:
  p: { workspaces: [w], toolchain: [], env: { set: { X: !area w/undeclared } } }
";

/// A route naming a minter the policy does not declare.
const UNDECLARED_MINTER: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p:
    workspaces: [w]
    toolchain: []
    credentials:
      - { host: api.example, path_prefix: /, minter: undeclared, delivery: { env: SUITE_TOKEN } }
";

/// Two routes on one host, neither prefix extending the other.
const TIED_ROUTES: &str = "\
version: 1
minters:
  m: { command: [\"{sh}\", -c, 'exit 3'] }
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p:
    workspaces: [w]
    toolchain: []
    credentials:
      - { host: api.example, path_prefix: /a/, minter: m, delivery: { env: SUITE_A } }
      - { host: api.example, path_prefix: /b/, minter: m, delivery: { env: SUITE_B } }
";

/// A route naming an endpoint rule set the policy does not declare.
const UNDECLARED_RULE_SET: &str = "\
version: 1
minters:
  m: { command: [\"{sh}\", -c, 'exit 3'] }
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p:
    workspaces: [w]
    toolchain: []
    credentials:
      - host: api.example
        path_prefix: /
        minter: m
        delivery: { env: SUITE_TOKEN }
        endpoints: [undeclared]
";

/// A rule set no path under its route's prefix can match.
const UNSATISFIABLE_RULE_SET: &str = "\
version: 1
minters:
  m: { command: [\"{sh}\", -c, 'exit 3'] }
fragments:
  endpoints:
    inference: [{ method: POST, path: /v1/messages }]
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p:
    workspaces: [w]
    toolchain: []
    credentials:
      - host: api.example
        path_prefix: /repos/
        minter: m
        delivery: { env: SUITE_TOKEN }
        endpoints: [inference]
";

/// No profile `p`, which the invocation names.
const NO_PROFILE_P: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  q: { workspaces: [w], toolchain: [] }
";

/// An exclusion of a path that is not there.
const ABSENT_EXCLUSION: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read, exclude: [{ path: \"{root}/absent\" }] }] }
profiles:
  p: { workspaces: [w], toolchain: [] }
";

/// A profile route whose minter exits non-zero.
const MINTER_EXITS: &str = "\
version: 1
minters:
  m: { command: [\"{sh}\", -c, 'exit 3'] }
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p:
    workspaces: [w]
    toolchain: []
    credentials:
      - { host: api.example, path_prefix: /, minter: m, delivery: { env: SUITE_TOKEN } }
";

/// A profile route whose minter answers something that is not `{token, expires_at}`.
const MINTER_MUMBLES: &str = "\
version: 1
minters:
  m: { command: [\"{sh}\", -c, 'echo not-json'] }
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p:
    workspaces: [w]
    toolchain: []
    credentials:
      - { host: api.example, path_prefix: /, minter: m, delivery: { env: SUITE_TOKEN } }
";

/// A profile route whose minter outlives its one-second `timeout`.
const MINTER_HANGS: &str = "\
version: 1
minters:
  m: { command: [\"{sh}\", -c, 'sleep 30'], timeout: 1 }
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p:
    workspaces: [w]
    toolchain: []
    credentials:
      - { host: api.example, path_prefix: /, minter: m, delivery: { env: SUITE_TOKEN } }
";

/// A policy declaring a shim, but not the one playpen is invoked as.
const OTHER_SHIM: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [], prefixes: [\"{root}\"] }
shims:
  other: { target: \"{canary}\", kind: claude }
";

/// The shim invoked, stating a kind this playpen does not know.
const UNKNOWN_KIND: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [], prefixes: [\"{root}\"] }
shims:
  tool: { target: \"{canary}\", kind: not-a-kind }
";

/// The shim invoked unpinned, from a directory no profile's prefixes contain.
const NO_PREFIX: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [], prefixes: [] }
shims:
  tool: { target: \"{canary}\", kind: claude }
";

/// The shim invoked unpinned, from a directory two profiles' equally long prefixes contain.
const TIED_PREFIXES: &str = "\
version: 1
workspaces:
  w: { roots: [{ path: \"{root}\", mode: read }] }
profiles:
  p: { workspaces: [w], toolchain: [], prefixes: [\"{root}\"] }
  q: { workspaces: [w], toolchain: [], prefixes: [\"{root}\"] }
shims:
  tool: { target: \"{canary}\", kind: claude }
";

/// What every row whose document the parser refuses rests on.
const PARSER: &[Decision] = &[Decision::Adr(9), Decision::Adr(16), Decision::Issue(56)];

/// What every row of a refusal about a minter rests on.
const MINTERS: &[Decision] = &[Decision::Adr(8), Decision::Adr(16), Decision::Issue(85)];

pub const ROWS: &[Row] = &[
    // "The manifest is true": what the agent is told and what the kernel enforces are one
    // resolution pass, and this is what holds them to it. The route half is the same statement
    // about the route table — every input to its requests is read from the manifest, so a table
    // stated wrong sends a request no route authenticates.
    Row {
        id: "P-manifest",
        class: Class::Positive,
        platform: BOTH,
        fixture: Fixture::Manifest,
        action: Action::ManifestIsTrue,
        expected: Expected::Succeeds,
        from: &[
            Decision::Adr(11),
            Decision::Adr(16),
            Decision::Issue(78),
            Decision::Issue(90),
        ],
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
    // A unix-socket **credential oracle** performs a credentialed operation for whoever reaches
    // it, so the means escapes with no secret crossing the boundary ([spec §6.3]). On Linux this
    // is Landlock's `FS_RESOLVE_UNIX` right, which the fork's probe negotiates from ABI 9; below
    // it the surface is unenforceable and the row is skipped by name. On macOS it is the fork's
    // IP-only `AllowAll`, with a writable area's sockets granted explicitly.
    Row {
        id: "N-unix-socket",
        class: Class::Negative,
        platform: Platform {
            scope: Scope::Both,
            requires: &[Precondition::LandlockResolveUnix],
        },
        fixture: Fixture::ProbeRoot,
        action: Action::Connect(Listening::DecoyUnixSocket),
        expected: Expected::Denial,
        from: &[
            Decision::Adr(16),
            Decision::Adr(22),
            // A blanket socket allowance the backend emits on its own initiative is a violation
            // of the seam rather than a property of the platform, which is what both halves of
            // this row's fork change are correcting.
            Decision::Adr(29),
            Decision::Issue(95),
            Decision::Issue(96),
        ],
    },
    // `--trace-denials` refuses the **flag** and not the run, naming which precondition failed
    // ([spec §14.5]). The ladder is the shipped one; what the row replaces is the facts it reads,
    // because a host with all four preconditions can provoke none of these.
    rung(Rung::KernelAbi),
    rung(Rung::LandlockInactive),
    rung(Rung::BackendNoLogging),
    rung(Rung::NoJournalAccess),
    rung(Rung::ChannelSilent),
    rung(Rung::ChannelLossy),
    // And the half that is not a refusal: a channel that delivered before the launch and is
    // silent after it marks the trace unverified rather than presenting it as complete.
    Row {
        id: Rung::SilentAfterTheRun.row(),
        class: Class::Positive,
        platform: TRACING,
        fixture: Fixture::Outside,
        action: Action::TraceBrackets,
        expected: Expected::TraceBracketed,
        from: TRACE_FROM,
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
    // The credential path, against a live confined launch. The unit tests in `src/proxy.rs` assert
    // the same substitution, and cannot catch the regression these exist for: a proxy that is
    // correct while the launch never wires the child to it.
    Row {
        id: "P-endpoint",
        class: Class::Positive,
        platform: BOTH,
        fixture: Fixture::CredentialRoute,
        action: Action::Request(Legs::Proxied),
        expected: Expected::Authenticated,
        // ADR 0030 because this row *is* that residual's assertion: it points `SSL_CERT_FILE` at
        // the destination's root on its own launch, and passes only if the ambient variable was
        // honoured.
        from: &[
            Decision::Adr(16),
            Decision::Adr(30),
            Decision::Issue(87),
            Decision::Issue(139),
        ],
    },
    // Asserted as a pair against one destination: a build that injected into everything passes
    // the bypass half alone, and one that injected into nothing passes the proxied half alone.
    Row {
        id: "P-open-bypass",
        class: Class::Positive,
        platform: BOTH,
        fixture: Fixture::CredentialRoute,
        action: Action::Request(Legs::ProxiedAndBypassing),
        expected: Expected::OnlyThroughTheProxy,
        from: &[
            Decision::Adr(16),
            Decision::Adr(20),
            Decision::Issue(86),
            Decision::Issue(139),
        ],
    },
    // The other side of "TLS is terminated only for a routed host": the same listener, reached
    // under the name no route carries, gets an opaque `CONNECT` and presents its own certificate —
    // which the child verifies against a host root out of the bundle `SSL_CERT_FILE` names. That
    // combination is what the bare session CA broke, and nothing asserted it from inside a launch.
    Row {
        id: "P-tunnel",
        class: Class::Positive,
        platform: BOTH,
        fixture: Fixture::CredentialRoute,
        action: Action::Request(Legs::ProxiedAndTunnelled),
        expected: Expected::OnlyThroughTheProxy,
        from: &[Decision::Adr(13), Decision::Adr(16), Decision::Issue(140)],
    },
    Row {
        id: "N-endpoint",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::RestrictedRoute,
        action: Action::Request(Legs::Proxied),
        expected: Expected::Brokered(Code::BrokerEndpointDenied),
        from: &[
            Decision::Adr(16),
            Decision::Adr(17),
            Decision::Issue(94),
            Decision::Issue(139),
        ],
    },
    // The other half of the same event, and a row of its own because it is the half that matters:
    // a `403` the destination saw the secret before is not a denial.
    Row {
        id: "N-endpoint-no-leg",
        class: Class::Negative,
        platform: BOTH,
        fixture: Fixture::RestrictedRoute,
        action: Action::Request(Legs::Proxied),
        expected: Expected::NoUpstreamLeg,
        from: &[
            Decision::Adr(16),
            Decision::Adr(17),
            Decision::Issue(94),
            Decision::Issue(139),
        ],
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
        action: Action::Refuse(Invocation::Policy(MERGED_TYPO)),
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
        action: Action::Refuse(Invocation::Policy(UNDECLARED_WORKSPACE)),
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
    // One row per code from here on, each provoking exactly its own: `R-code-coverage` asks every
    // `refusal.*` code for a row that produces it, and a row passing on some other code would be
    // the vacuous pass ADR 0016 denies.
    //
    // The policy's location ([spec §10.1]).
    refused(
        "R-policy-not-found",
        Invocation::Locate(Location::Absent),
        Code::PolicyNotFound,
        &[Decision::Adr(16), Decision::Issue(57)],
    ),
    refused(
        "R-policy-unreadable",
        Invocation::Locate(Location::Directory),
        Code::PolicyUnreadable,
        &[Decision::Adr(16), Decision::Issue(57)],
    ),
    refused(
        "R-policy-ambiguous",
        Invocation::Locate(Location::BothFormats),
        Code::PolicyAmbiguousLocation,
        &[Decision::Adr(16), Decision::Issue(57)],
    ),
    // The parser-contract tier ([spec §10.2]).
    refused(
        "R-policy-syntax",
        Invocation::Policy(UNCLOSED),
        Code::PolicySyntax,
        PARSER,
    ),
    refused(
        "R-policy-version",
        Invocation::Policy(NEXT_VERSION),
        Code::PolicyVersion,
        PARSER,
    ),
    refused(
        "R-policy-tag",
        Invocation::Policy(TAGGED),
        Code::PolicyTag,
        PARSER,
    ),
    refused(
        "R-policy-type",
        Invocation::Policy(MISTYPED),
        Code::PolicyType,
        PARSER,
    ),
    // The coherence tier ([spec §10.5]).
    refused(
        "R-root-relative",
        Invocation::Policy(RELATIVE_ROOT),
        Code::RootRelative,
        &[
            Decision::Adr(9),
            Decision::Adr(16),
            Decision::Issue(59),
            Decision::Issue(65),
        ],
    ),
    refused(
        "R-fragment-unknown",
        Invocation::Policy(UNDECLARED_FRAGMENT),
        Code::FragmentUnknown,
        &[Decision::Adr(12), Decision::Adr(16), Decision::Issue(68)],
    ),
    refused(
        "R-env-forbidden",
        Invocation::Policy(FORBIDDEN_NAME),
        Code::EnvForbidden,
        &[Decision::Adr(12), Decision::Adr(16), Decision::Issue(69)],
    ),
    refused(
        "R-env-reserved",
        Invocation::Policy(RESERVED_NAME),
        Code::EnvReserved,
        &[Decision::Adr(12), Decision::Adr(16), Decision::Issue(69)],
    ),
    refused(
        "R-env-duplicate",
        Invocation::Policy(TWO_AUTHORS),
        Code::EnvDuplicate,
        &[Decision::Adr(12), Decision::Adr(16), Decision::Issue(130)],
    ),
    refused(
        "R-area-unknown",
        Invocation::Policy(DANGLING_AREA),
        Code::AreaUnknown,
        &[Decision::Adr(10), Decision::Adr(16), Decision::Issue(73)],
    ),
    refused(
        "R-minter-unknown",
        Invocation::Policy(UNDECLARED_MINTER),
        Code::MinterUnknown,
        MINTERS,
    ),
    refused(
        "R-route-ambiguous",
        Invocation::Policy(TIED_ROUTES),
        Code::RouteAmbiguous,
        &[Decision::Adr(16), Decision::Issue(89)],
    ),
    refused(
        "R-endpoint-unknown",
        Invocation::Policy(UNDECLARED_RULE_SET),
        Code::EndpointUnknown,
        &[Decision::Adr(16), Decision::Adr(17), Decision::Issue(94)],
    ),
    refused(
        "R-endpoint-unsatisfiable",
        Invocation::Policy(UNSATISFIABLE_RULE_SET),
        Code::EndpointUnsatisfiable,
        &[Decision::Adr(16), Decision::Adr(17), Decision::Issue(94)],
    ),
    // Invocation and selection ([spec §11]).
    refused(
        "R-unknown-profile",
        Invocation::Policy(NO_PROFILE_P),
        Code::SelectionUnknownProfile,
        &[Decision::Adr(16), Decision::Issue(60)],
    ),
    refused(
        "R-shim-unknown",
        Invocation::Shim(OTHER_SHIM),
        Code::ShimUnknown,
        &[Decision::Adr(16), Decision::Adr(19), Decision::Issue(81)],
    ),
    refused(
        "R-kind-unknown",
        Invocation::Shim(UNKNOWN_KIND),
        Code::KindUnknown,
        &[Decision::Adr(16), Decision::Issue(75)],
    ),
    refused(
        "R-selection-no-match",
        Invocation::Shim(NO_PREFIX),
        Code::SelectionNoMatch,
        &[Decision::Adr(16), Decision::Issue(60)],
    ),
    refused(
        "R-selection-ambiguous",
        Invocation::Shim(TIED_PREFIXES),
        Code::SelectionAmbiguous,
        &[Decision::Adr(16), Decision::Issue(60)],
    ),
    Row {
        id: "R-run-unknown",
        class: Class::Refusal,
        platform: BOTH,
        fixture: Fixture::Outside,
        action: Action::Refuse(Invocation::UnknownRun),
        expected: Expected::Unrecorded(Code::RunUnknown),
        from: &[Decision::Adr(16), Decision::Issue(52)],
    },
    // Host state ([spec §11.5], [spec §11.7], [spec §5]).
    refused(
        "R-exclusion-missing",
        Invocation::Policy(ABSENT_EXCLUSION),
        Code::ExclusionMissing,
        &[Decision::Adr(16), Decision::Issue(63)],
    ),
    refused(
        "R-integrity-unresolvable",
        Invocation::UnfoundLink,
        Code::IntegrityUnresolvable,
        &[
            Decision::Adr(16),
            Decision::Issue(66),
            Decision::Issue(81),
            Decision::Issue(108),
        ],
    ),
    refused(
        "R-cwd-ungranted",
        Invocation::CwdOutside,
        Code::CwdUngranted,
        &[Decision::Adr(16), Decision::Issue(48)],
    ),
    refused(
        "R-area-busy",
        Invocation::HeldArea,
        Code::AreaBusy,
        &[Decision::Adr(10), Decision::Adr(16), Decision::Issue(72)],
    ),
    refused(
        "R-state-io",
        Invocation::ScratchBlocked,
        Code::StateIo,
        &[Decision::Adr(16), Decision::Issue(70)],
    ),
    refused(
        "R-process-fork",
        Invocation::NoProcesses,
        Code::ProcessFork,
        &[Decision::Adr(16), Decision::Issue(50)],
    ),
    // The mechanism ([spec §8.2], [spec §8.6]).
    refused(
        "R-floor-unavailable",
        Invocation::Floor(DedicatedFloor::Undeclared),
        Code::FloorUnavailable,
        &[Decision::Adr(16), Decision::Adr(23), Decision::Issue(134)],
    ),
    refused(
        "R-floor-self-test",
        Invocation::Floor(DedicatedFloor::CanaryUnrunnable),
        Code::FloorSelfTest,
        &[
            Decision::Adr(6),
            Decision::Adr(16),
            Decision::Adr(23),
            Decision::Issue(50),
        ],
    ),
    refused(
        "R-target-exec",
        Invocation::AbsentTarget,
        Code::TargetExec,
        &[Decision::Adr(16), Decision::Issue(51)],
    ),
    // Credentials and the proxy ([spec §7.2], [spec §6.2]).
    refused(
        "R-minter-failed",
        Invocation::Policy(MINTER_EXITS),
        Code::MinterFailed,
        MINTERS,
    ),
    refused(
        "R-minter-malformed",
        Invocation::Policy(MINTER_MUMBLES),
        Code::MinterMalformed,
        MINTERS,
    ),
    refused(
        "R-minter-timeout",
        Invocation::Policy(MINTER_HANGS),
        Code::MinterTimeout,
        MINTERS,
    ),
    refused(
        "R-proxy-ca",
        Invocation::NoTrustedRoots,
        Code::ProxyCa,
        &[Decision::Adr(16), Decision::Adr(30), Decision::Issue(86)],
    ),
];
