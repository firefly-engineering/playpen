//! The row form ([spec §17.1]): `{id, class, platform, fixture, action, expected, from}`, every
//! field a closed type. Adding an instance of an existing check is a row in [`crate::rows`];
//! adding a new kind of check is one variant of [`Action`].
//!
//! [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form

use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use playpen::code::Code;
use playpen::refusal::EXIT_REFUSED;

use crate::common::DENIAL_ERRNOS;

/// One assertion of the suite.
#[derive(Clone, Copy)]
pub struct Row {
    /// Stable, and the name a report and a reverse query use.
    pub id: &'static str,
    pub class: Class,
    pub platform: Platform,
    pub fixture: Fixture,
    pub action: Action,
    pub expected: Expected,
    /// The decisions this row encodes: which rows die if one of them is revisited.
    pub from: &'static [Decision],
}

/// What a row asserts, and from where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// From inside, the action must fail with a denial.
    Negative,
    /// From inside, the action must succeed. Admissible only if the regression it catches is
    /// silent.
    Positive,
    /// From outside, with no sandbox at all: playpen declines to launch, with exit `125` and a
    /// code.
    Refusal,
}

/// Where a row applies, and what it needs of the host there.
#[derive(Clone, Copy)]
pub struct Platform {
    pub scope: Scope,
    /// Probed before the row runs; the first that does not hold skips the row by its name.
    pub requires: &'static [Precondition],
}

/// Both platforms, with no host precondition.
pub const BOTH: Platform = Platform {
    scope: Scope::Both,
    requires: &[],
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Both,
    /// One platform only, which costs the named asymmetry it encodes. On the other platform the
    /// row is `n/a`, never skipped.
    Only(Os, Asymmetry),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    MacOs,
    Linux,
}

impl Os {
    #[cfg(target_os = "macos")]
    pub const HERE: Os = Os::MacOs;
    #[cfg(target_os = "linux")]
    pub const HERE: Os = Os::Linux;
}

macro_rules! ledger {
    ($($variant:ident => $name:literal,)*) => {
        /// The named-asymmetry ledger ([spec §15.4]). A row scoped to one platform cites one.
        ///
        /// [spec §15.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#154-named-asymmetries
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Asymmetry {
            $($variant,)*
        }

        impl Asymmetry {
            /// Every entry, in ledger order.
            pub const ALL: &[Asymmetry] = &[$(Asymmetry::$variant,)*];

            pub fn name(self) -> &'static str {
                match self {
                    $(Asymmetry::$variant => $name,)*
                }
            }
        }
    };
}

ledger! {
    UnixSocket => "unix-socket credential oracles",
    DeprecationClock => "the mechanism's deprecation clock",
    CompiledProfileCeiling => "the compiled-profile ceiling",
    DenialVisibility => "denial visibility",
    UserNamespaces => "user namespaces",
    // Recorded beneath the ledger's table rather than numbered in it: Linux has no
    // mechanism-native Keychain, so `N-keychain` is `n/a` there.
    Keychain => "a mechanism-native Keychain",
    // Likewise: macOS has no abstract unix sockets, so `N-abstract-socket` is `n/a` there.
    AbstractSockets => "abstract unix sockets",
    // Spec §15.4, item 8: Landlock cannot subtract a subpath from a grant (#127).
    Exclusions => "subtracting a subpath from a grant",
}

/// A host precondition a row needs, each probed explicitly and skipping by its own stable name
/// (`skip.host.no-nix`, …). A skip is never inferred from a failure: [`judge`] has no skip to
/// return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precondition {
    /// The caller's home directory can be written, so a row whose real target the host lacks can
    /// put a decoy there. Without it such a row would fail for a reason about the host that reads
    /// like a boundary regression, and a synthetic home would assert less than [spec §17.2] says.
    ///
    /// [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
    HomeWritable,
    /// `nix-store` runs, so a store path can be made to stand outside a declared closure.
    Nix,
    /// `brew --prefix` names a prefix whose `Cellar` and `opt` can be written, so a keg can be
    /// manufactured beside another.
    Homebrew,
    /// The kernel offers the Landlock right that gates a pathname-socket `connect()`
    /// (`FS_RESOLVE_UNIX`, ABI 9). Below it the surface is unenforceable and a **named residual**
    /// ([spec §6.3]), so the row is skipped by name rather than moved somewhere weaker.
    ///
    /// [spec §6.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#63-credential-oracles
    LandlockResolveUnix,
    /// Not a hosted CI runner. The liveness suite is skipped there by policy ([spec §17.2]): it
    /// launches a real agent against a real provider, and gates only an agent-version or
    /// kind-table change.
    ///
    /// [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
    #[allow(dead_code)] // constructed by the liveness suite, which shares this form
    OffHostedCi,
    /// The agent's binary is on the search path the runner was started with.
    #[allow(dead_code)] // constructed by the liveness suite, which shares this form
    Agent(Agent),
    /// The operator named which reference minter for Anthropic a liveness task mints with
    /// ([`MINTER_ENV`]): a choice of theirs, since `setup-token` needs a grant they stored and
    /// `host-login` reads their own login, and never one the suite makes for them.
    #[allow(dead_code)] // constructed by the liveness suite, which shares this form
    AnthropicMinter,
}

/// The variable naming the subcommand of `playpen-minter-anthropic` a liveness task mints with:
/// `setup-token` or `host-login` ([spec §7.5]). Read once, in `main`.
///
/// [spec §7.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#75-subscription-logins
#[allow(dead_code)] // read by the liveness suite's `main`
pub const MINTER_ENV: &str = "PLAYPEN_LIVENESS_MINTER";

/// What a runner reads of its own environment, once, in `main`, and hands to the rows: nothing
/// below it reads the environment ([#134](https://github.com/firefly-engineering/playpen/issues/134)).
pub struct Host {
    /// The caller's home directory, where the credential targets live, and the operator's own
    /// keystore is found from.
    pub home: PathBuf,
    /// The search path an agent is found on.
    pub path: Option<OsString>,
    /// `GITHUB_ACTIONS=true`, which every hosted GitHub runner sets.
    pub hosted_ci: bool,
    /// [`MINTER_ENV`], where it names anything.
    pub minter: Option<String>,
}

impl Host {
    /// A host that is only a home: what the enforcement suite reads, and nothing it does not.
    pub fn at(home: &Path) -> Self {
        Self {
            home: home.to_owned(),
            path: None,
            hosted_ci: false,
            minter: None,
        }
    }

    /// `name`, found on [`Host::path`] as a shell would, and resolved: the link a package manager
    /// puts on the search path is not what a toolchain root grants.
    pub fn find(&self, name: &str) -> Option<PathBuf> {
        std::env::split_paths(self.path.as_ref()?)
            .map(|dir| dir.join(name))
            .find(|path| executable(path))
            .and_then(|path| path.canonicalize().ok())
    }
}

/// Whether `path` names something this process may execute, probed without running it.
fn executable(path: &Path) -> bool {
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `path` is NUL-terminated and outlives the call.
    unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
}

/// An agent kind the liveness suite launches ([spec §12]): one row each.
///
/// [spec §12]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#12-the-kind-table
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // constructed by the liveness suite, which shares this form
pub enum Agent {
    Claude,
    Omp,
}

impl Agent {
    /// The kind it is launched as, which is also the name its binary goes by.
    pub fn kind(self) -> &'static playpen::kind::Kind {
        let name = match self {
            Agent::Claude => "claude",
            Agent::Omp => "omp",
        };
        playpen::kind::get(name).expect("every liveness agent is a kind in the table")
    }
}

impl Precondition {
    /// The stable name the row is skipped under when this does not hold.
    pub fn skip(self) -> &'static str {
        match self {
            Precondition::HomeWritable => "skip.host.home-not-writable",
            Precondition::Nix => "skip.host.no-nix",
            Precondition::Homebrew => "skip.host.no-homebrew",
            Precondition::LandlockResolveUnix => "skip.host.landlock-below-abi-9",
            Precondition::OffHostedCi => "skip.suite.liveness-not-on-ci",
            Precondition::Agent(Agent::Claude) => "skip.host.no-claude",
            Precondition::Agent(Agent::Omp) => "skip.host.no-omp",
            Precondition::AnthropicMinter => "skip.host.no-anthropic-minter",
        }
    }

    /// Probed without writing anything: a probe that wrote would need the reclamation it guards.
    pub fn holds(self, host: &Host) -> bool {
        match self {
            Precondition::HomeWritable => writable(&host.home),
            Precondition::Nix => std::process::Command::new("nix-store")
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success()),
            Precondition::Homebrew => homebrew_prefix().is_some_and(|prefix| {
                writable(&prefix.join("Cellar")) && writable(&prefix.join("opt"))
            }),
            // playpen's own probe, which is the one a launch makes: the backend's stops at an ABI
            // it knows.
            #[cfg(target_os = "linux")]
            Precondition::LandlockResolveUnix => {
                playpen::mechanism::landlock_abi().is_ok_and(|abi| abi >= RESOLVE_UNIX_ABI)
            }
            // Vacuous off Linux: there is no Landlock to be below an ABI of, and Seatbelt denies
            // the surface on every macOS version.
            #[cfg(not(target_os = "linux"))]
            Precondition::LandlockResolveUnix => true,
            Precondition::OffHostedCi => !host.hosted_ci,
            Precondition::Agent(agent) => host.find(agent.kind().name).is_some(),
            Precondition::AnthropicMinter => host.minter.as_deref().is_some_and(|m| !m.is_empty()),
        }
    }
}

/// The Landlock ABI that first offers `FS_RESOLVE_UNIX`, which is what gates a pathname-socket
/// `connect()` ([spec §6.3]).
///
/// [spec §6.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#63-credential-oracles
#[cfg(target_os = "linux")]
pub const RESOLVE_UNIX_ABI: libc::c_long = 9;

/// Homebrew's prefix, as `brew` reports it.
pub fn homebrew_prefix() -> Option<std::path::PathBuf> {
    let output = std::process::Command::new("brew")
        .arg("--prefix")
        .output()
        .ok()
        .filter(|output| output.status.success())?;
    let prefix = String::from_utf8(output.stdout).ok()?;
    Some(prefix.trim().into())
}

/// Whether `path` can be written, probed without writing anything.
fn writable(path: &Path) -> bool {
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `path` is NUL-terminated and outlives the call.
    unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
}

/// What a row runs against. Rows sharing a policy fixture share one confined launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fixture {
    /// No policy and no launch: the floor alone, applied to a throwaway child by the floor
    /// self-test. Only OS-owned binaries can run here.
    BareFloor,
    /// A policy document whose one profile grants a single read-only root holding the probe, so
    /// every negative made under it reads "unreachable even with the probe's root present".
    ProbeRoot,
    /// No sandbox at all: playpen is invoked so that it declines to launch, under a state
    /// directory of the row's own.
    Outside,
    /// No grant at all, not even the floor: the backend applied to an empty capability set, in a
    /// throwaway child the suite forks itself. Only the canary is run here, to show it cannot
    /// run ([ADR 0029]).
    ///
    /// [ADR 0029]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0029-the-backend-grants-only-what-the-policy-asked-for.md
    NothingGranted,
    /// One confined launch of a shell that forks the probe, so that every denial is a
    /// descendant's; then the run's denials, pulled from the platform's log outside.
    DescendantDenied,
    /// One launch per row, under a profile whose toolchain is a single root the row makes beside
    /// its target: a closure path beside a stale store path, a keg beside a decoy keg
    /// ([spec §8.3]). The neighbour must be readable inside, or the toolchain was not applied and
    /// the negative would prove nothing.
    ///
    /// [spec §8.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#83-toolchain
    Toolchain,
    /// One launch per row, under a profile whose one root is the probe's, with a subdirectory
    /// excluded ([spec §8.4]). A file the root still grants must be readable inside, or the root
    /// was not applied and the negative would prove nothing.
    ///
    /// [spec §8.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#84-exclusions
    Excluded,
    /// One launch per row, under a profile with a `readwrite` root, a `read` root, a persistent
    /// area and an ephemeral one, and a decoy outside every grant: enough shape that the manifest
    /// has something to be wrong about ([spec §13]).
    ///
    /// [spec §13]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#13-the-manifest
    Manifest,
    /// A shim installed as a symlink to the playpen binary, with a policy where the search path
    /// finds it, whose target prints its own argv ([spec §11.3]).
    ///
    /// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
    Shim,
    /// One launch per row, under a policy with a **credential route** on a loopback TLS destination
    /// the harness stands up **outside** the launch and reclaims with the fixture ([spec §7]).
    ///
    /// The destination is outside because [ADR 0016]'s two-part form wants what arrived observable
    /// from outside: a listener inside the sandbox reporting on itself is the probe grading its own
    /// homework. It answers as `localhost`, because route matching is an exact compare on the
    /// authority the `CONNECT` named and nothing in the proxy can make a name resolve.
    ///
    /// The proxy is made to trust the destination's root by setting `SSL_CERT_FILE` on **that one
    /// launch** — the supervisor's environment, which is what "the host's own trust store" means
    /// ([ADR 0030]). Never on the suite: a per-suite store would narrow every other row's upstream
    /// trust and make one row's failure read as another's. It is *replaced* rather than extended,
    /// which is what a row wants — a proxy trusting only this root cannot pass by having reached
    /// something else. The child's own store is built from the same read, so the probe inside
    /// verifies the destination on either leg from `SSL_CERT_FILE` alone
    /// ([#140](https://github.com/firefly-engineering/playpen/issues/140)).
    ///
    /// It reaches neither `Broker::trusting` nor any policy field, flag or cargo feature.
    ///
    /// [spec §7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#7-enforcement-surface-credentials
    /// [ADR 0016]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md
    /// [ADR 0030]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0030-the-hosts-own-trust-store-is-what-the-host-says-it-is.md
    CredentialRoute,
    /// [`Fixture::CredentialRoute`] with an **endpoint rule set** on the route, allowing one method
    /// on the path the row then asks for with another ([spec §7.6]). A fixture of its own rather
    /// than a flag on the action, so the row table says which rows run against a restricted
    /// credential and which against an unrestricted one.
    ///
    /// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
    RestrictedRoute,
    /// One launch per row of a **real agent**, confined under a profile whose toolchain is the
    /// agent's own package and nothing beside it, with one profile route for `api.anthropic.com`
    /// minted by `playpen-minter-anthropic` and restricted by the shipped
    /// `anthropic-inference-only` set, and a share entry naming the kind's instruction entry
    /// point ([spec §17.2], liveness).
    ///
    /// The caller's home is a synthetic one the fixture makes, so the share entry is a file of the
    /// fixture's and never the operator's own instructions; the minter alone is handed the real
    /// home, which is where its keystore is found.
    ///
    /// [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
    Agent,
}

/// The closed set of checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The floor self-test's canary: under the bare floor through the self-test's own
    /// implementation ([spec §8.6]), and under nothing granted by an `exec` whose errno is the
    /// kernel's, not playpen's translation of it.
    ///
    /// [spec §8.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#86-the-floor-self-test
    Canary,
    /// The probe opens the target and reads it to the end.
    Read(Target),
    /// The probe creates a file that does not exist yet inside the target directory.
    Create(Target),
    /// The probe lists the target directory: what reading a directory means.
    List(Target),
    /// The probe reads to the end a descriptor it inherited, open on a decoy credential: the
    /// same open file outside, and passed to playpen inside ([spec §8.7]).
    ///
    /// [spec §8.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#87-file-descriptors
    ReadInherited,
    /// The probe looks up each of the services by name in its bootstrap namespace (macOS).
    LookUp(Services),
    /// The probe sends signal 0 to the process: the permission check alone.
    Signal(Signalled),
    /// The probe connects to the socket.
    Connect(Listening),
    /// playpen is invoked so that it refuses, and leaves what it leaves behind.
    Refuse(Invocation),
    /// Two traced launches, asserted as a **pair**: one whose channel self-test passes on both
    /// passes, whose trace is vouched for, and one whose second pass is silent, whose trace is
    /// marked unverified ([spec §14.5]).
    ///
    /// The pair is what keeps it from being vacuous. "The record says unverified" alone would
    /// pass on a build that marked every trace unverified, which is the trace nobody would read.
    ///
    /// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
    TraceBrackets,
    /// `playpen check` of a policy whose one root is absent: first with the filesystem, then with
    /// `--no-filesystem` ([spec §10.5]).
    ///
    /// [spec §10.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#105-validation-tiers
    CheckDocument,
    /// The command `explain --run` prints is run, and must return the denial of a read the probe,
    /// forked by the confined child rather than being it, made of a decoy outside every grant
    /// ([spec §14.2]).
    ///
    /// [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
    PullDenials,
    /// "The manifest is true", filesystem half: every path the manifest states is reachable from
    /// inside the run it describes, at the mode it states, and a decoy outside every grant is not
    /// ([spec §13]). A manifest that described a boundary the kernel did not build would mislead
    /// the agent silently, which is what makes this a positive worth having.
    ///
    /// The route half joins it with the route table
    /// ([#90](https://github.com/firefly-engineering/playpen/issues/90)).
    ///
    /// [spec §13]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#13-the-manifest
    ManifestIsTrue,
    /// The injected argv `explain --shim --json` states is the argv the child received
    /// ([spec §11.3]). playpen reads no argument anywhere, so the only thing holding the two
    /// together is that one function builds both — and nothing in a launch would complain if it
    /// stopped, which is what makes this a positive worth having.
    ///
    /// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
    ArgvMatches,
    /// The probe, inside a live confined launch, issues an HTTPS request to the fixture's loopback
    /// destination on each of `legs`; the row is judged by **what arrived there**, read from
    /// outside, as well as by what came back ([spec §7.3], [spec §7.6]).
    ///
    /// One variant rather than several: every check here is the same kind — issue a request from
    /// inside and observe what the destination the harness controls received. Which leg, and what
    /// is asserted of it, are the row's own fields.
    ///
    /// What this adds over the unit tests in `src/proxy.rs` is the thing a unit test structurally
    /// cannot catch: it runs against a **live confined launch**, so it fails if the proxy is
    /// correct but the launch never wires the child to it.
    ///
    /// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
    /// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
    Request(Legs),
    /// The agent, confined, exits `0` on a trivial invocation that needs no network, then
    /// completes one task through the proxy whose answer only its instruction entry point could
    /// have told it ([spec §17.2], liveness). See [`crate::live`].
    ///
    /// [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
    #[allow(dead_code)] // constructed by the liveness suite, which shares this form
    Live(Agent),
    /// Every `refusal.*` code in the registry is what at least one refusal row of the table
    /// expects ([spec §17.2], [spec Appendix A]). A check over the rows, which are data, so it
    /// runs nothing: whether each row really produces its code is that row's own assertion.
    ///
    /// [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
    /// [spec Appendix A]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#appendix-a--code-registry
    CoverCodes,
}

/// Which leg or legs of the proxy a [`Action::Request`] row drives. **Chosen explicitly, never
/// inferred**: `NO_PROXY` holds `localhost`, so a probe that let its client decide would take the
/// bypassing leg both times. That is a probe argument, not a host fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Legs {
    /// Through the proxy alone: the credential path.
    Proxied,
    /// Both, against **one** destination, asserted as a pair: the proxied request is authenticated
    /// and the bypassing one is not. The pair is what keeps the bypass half from being vacuous —
    /// "the bypassing request had no credential" would pass on a build where the proxy injected
    /// into everything ([#86](https://github.com/firefly-engineering/playpen/issues/86)).
    ///
    /// The bypassing request **does** arrive carrying the phantom, because both legs present the
    /// same request and nothing on this one strips it. That is not a leak, and asserting otherwise
    /// would mean driving the two legs with different requests, which is the vacuity the pair
    /// exists to rule out. See [`Expected::OnlyThroughTheProxy`].
    ProxiedAndBypassing,
    /// The proxied leg, paired with one **through** the proxy to a **non-routed** authority, where
    /// the proxy opens an opaque `CONNECT` and reads nothing of it ([spec §6.2]).
    ///
    /// The same destination, reached as `127.0.0.1` rather than as the route's `localhost`, so one
    /// listener is routed under one name and not under the other. It answers with its own real
    /// certificate, which the child verifies against a **host root** out of the bundle
    /// `SSL_CERT_FILE` names — the combination
    /// [#140](https://github.com/firefly-engineering/playpen/issues/140) is about, and the one the
    /// bare session CA broke. The tunnelled request arrives unauthenticated, because a tunnel the
    /// proxy cannot read is a tunnel it does not inject into.
    ///
    /// [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
    ProxiedAndTunnelled,
}

impl Action {
    /// Whether this action can run under `fixture`: the canary admits no grant beside the floor,
    /// and runs under nothing granted too; a refusal admits no sandbox at all; everything else
    /// needs the probe's root.
    pub fn admits(self, fixture: Fixture) -> bool {
        match self {
            Action::Canary => matches!(fixture, Fixture::BareFloor | Fixture::NothingGranted),
            Action::Read(Target::StaleStorePath | Target::DecoyKeg) => {
                fixture == Fixture::Toolchain
            }
            Action::Read(Target::ExcludedDecoy) => fixture == Fixture::Excluded,
            Action::Read(_)
            | Action::Create(_)
            | Action::List(_)
            | Action::ReadInherited
            | Action::LookUp(_)
            | Action::Signal(_)
            | Action::Connect(_) => fixture == Fixture::ProbeRoot,
            Action::Refuse(_)
            | Action::CheckDocument
            | Action::TraceBrackets
            | Action::CoverCodes => fixture == Fixture::Outside,
            Action::PullDenials => fixture == Fixture::DescendantDenied,
            Action::ManifestIsTrue => fixture == Fixture::Manifest,
            Action::ArgvMatches => fixture == Fixture::Shim,
            Action::Request(_) => {
                matches!(fixture, Fixture::CredentialRoute | Fixture::RestrictedRoute)
            }
            Action::Live(_) => fixture == Fixture::Agent,
        }
    }
}

/// Paths the fixture establishes outside before the row runs. A credential the host lacks is
/// replaced by a decoy at its real path, so the row exercises the same path resolution on a
/// fresh runner; a decoy is removed when the row is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A private key `~/.ssh/id_*`: the host's own if it has one, else a decoy created there.
    SshKey,
    /// `~/.ssh/config`.
    SshConfig,
    /// The `~/.aws` directory; its decoy is empty.
    Aws,
    /// `~/.npmrc`.
    Npmrc,
    /// A fresh decoy file in each of the host's temp directories: `/tmp`, `/var/tmp`, and on
    /// macOS the per-user `/var/folders/…` directory that `confstr` reports.
    HostTemp,
    /// A fresh directory outside every grant.
    DecoyDir,
    /// [`Target::SshKey`], [`Target::SshConfig`] and [`Target::Npmrc`], each reached through a
    /// symlink inside the probe's own granted root: the link is granted, its target is not, and
    /// the mechanism decides on the resolved path ([spec §8.5]).
    ///
    /// [spec §8.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#85-symlinks
    LinkedCredentials,
    /// `.ssh/config` in a store path named `…-home-manager-files`, outside the declared closure:
    /// the stale generation a coarse store root would leak ([spec §8.3]).
    ///
    /// [spec §8.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#83-toolchain
    StaleStorePath,
    /// The marker of a manufactured keg in Homebrew's prefix, beside a manufactured keg the
    /// toolchain grants through its `opt` link.
    DecoyKeg,
    /// A decoy in a subdirectory excluded from the probe's own granted root.
    ExcludedDecoy,
}

/// Mach services, named by what they serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Services {
    /// The Keychain's: `com.apple.SecurityServer` (file-based keychains, served by `securityd`)
    /// and the `com.apple.securityd.*` services of the data-protection keychain, served by
    /// `secd`, the XPC variant among them. The floor names none of them ([spec §8.2]).
    ///
    /// [spec §8.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#82-the-floor
    Keychain,
}

/// A process running outside every boundary, which process scoping keeps out of reach: started by
/// the fixture before the row runs, and stopped when it is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signalled {
    /// A process of the suite's own, which only waits.
    DecoyProcess,
}

/// A socket listening outside every boundary, which process scoping keeps out of reach: bound by
/// the fixture before the row runs, and closed when it is done. Never anything in the caller's
/// home.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listening {
    /// An abstract unix socket the suite listens on, under a name of its own (Linux).
    DecoyAbstractSocket,
    /// A **pathname** unix socket the suite listens on, in a directory of its own outside every
    /// grant: the shape every unix-socket **credential oracle** is reached by — `ssh-agent`,
    /// `gpg-agent`, a password manager's agent, `docker.sock` ([spec §6.3]).
    ///
    /// [spec §6.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#63-credential-oracles
    DecoyUnixSocket,
}

impl Listening {
    /// The probe verb that reaches it. A pathname socket and an abstract one are different
    /// address families to the kernel and different verbs to the probe, so the row's own value
    /// decides rather than the fixture guessing.
    pub fn verb(self) -> &'static str {
        match self {
            Listening::DecoyAbstractSocket => "connect-abstract",
            Listening::DecoyUnixSocket => "connect-unix",
        }
    }
}

/// An invocation playpen refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invocation {
    /// `playpen run` and nothing else: refused at parsing, the earliest refusal after the run
    /// record is opened, so it is the one a record opened any later would miss.
    Usage,
    /// `playpen run` of the canary, on a mechanism that offers none of the capabilities every
    /// profile requires. No host the suite runs on lacks one, so the probe is the one thing
    /// replaced: the suite re-runs itself as playpen with [`playpen::launch::main`] given a probe
    /// that offers nothing ([spec §4.2], step 7).
    ///
    /// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
    MissingCapability,
    /// `playpen run` with `XDG_STATE_HOME` inside the brought root, so the profile's grant is an
    /// ancestor of playpen's own state directory and every run record is reachable from inside
    /// ([ADR 0027]). The state directory is synthetic, as every row's is: the check compares
    /// resolved paths and does not care whose home it is, so naming the real `$HOME` would buy no
    /// realism and would leave a decoy behind if the suite were killed
    /// ([#118](https://github.com/firefly-engineering/playpen/issues/118)).
    ///
    /// [ADR 0027]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md
    StateReachable,
    /// `playpen run` of profile `p` as `claude`, from inside the fixture's root, under this YAML
    /// policy document and nothing else about the host. Every refusal a document alone provokes —
    /// the parser's and the coherence tier's, a dangling exclusion, a minter that fails — is an
    /// instance of this one check, so a new one is a row and a document, never a variant
    /// ([spec §17.1]).
    ///
    /// The document is written as it is spelt, with three names substituted: [`ROOT`], the
    /// fixture's one root; [`SH`], the floor's own shell, for a minter's command; and [`CANARY`],
    /// the floor's canary, for a shim's target. Substitution is of the whole placeholder only, so
    /// a line and column the row asserts stay where the document puts them.
    ///
    /// [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form
    Policy(&'static str),
    /// `playpen run` under a policy file that lies inside the profile's own read-write root, so the
    /// confined tree could rewrite the boundary of the next launch ([spec §11.7]).
    ///
    /// [spec §11.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#117-self-integrity
    WritablePolicy,
    /// `playpen run --trace-denials <file>` on a denial-trace ladder made to fail at this rung
    /// ([spec §14.5]). The flag is refused and the run is not: dropping it would leave a run
    /// playpen launches.
    ///
    /// The ladder itself is the shipped one. What is replaced is the facts it reads — the suite
    /// re-runs itself as playpen with [`playpen::trace::open_with`] — because a host with all
    /// four preconditions can provoke none of the six refusals, and a row that cannot run is not
    /// an assertion ([ADR 0016]).
    ///
    /// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
    /// [ADR 0016]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md
    TraceDenials(Rung),
    /// `playpen run` under a profile whose toolchain is [`OVER_CEILING`] roots, which compiles to
    /// a Seatbelt profile over macOS's ceiling ([spec §15.3]). The count is generous, never the
    /// assertion: a macOS that raised the ceiling would launch, and the row would fail saying so.
    ///
    /// [spec §15.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#153-the-compiled-profile-ceiling
    OverCeiling,
    /// `playpen run` of a policy that is where `location` puts it ([spec §10.1]).
    ///
    /// [spec §10.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#101-location
    Locate(Location),
    /// playpen invoked as a **shim** named [`SHIM`], through a link to the binary in a directory of
    /// its own, with this YAML document where the search path finds it ([spec §11.3]). Substituted
    /// as [`Invocation::Policy`]'s is. Everything a shim decides from the document alone — whether
    /// it declares the name, the kind it states, the profile the chain selects — is an instance of
    /// this one check.
    ///
    /// The chain is left to the working directory: `PLAYPEN_PROFILE` is removed on that launch,
    /// and the shim runs from inside the fixture's root ([spec §11.4]).
    ///
    /// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
    /// [spec §11.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#114-profile-selection
    Shim(&'static str),
    /// The shim of [`Invocation::Shim`], invoked by its **bare name** as a `PATH` lookup leaves
    /// `argv[0]`, with a `PATH` that holds no entry leading to it. The link playpen was reached
    /// through cannot be found, so it cannot be shown unwritable ([spec §11.7]).
    ///
    /// A host fact on that one launch, rather than the re-run's injected executable that
    /// `R-missing-cap` uses: the shipped `main` is what reads both `argv[0]` and `PATH`.
    ///
    /// [spec §11.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#117-self-integrity
    UnfoundLink,
    /// `playpen run` from a working directory outside every granted root: the fixture's policy
    /// directory, which the policy does not grant ([spec §11.5]).
    ///
    /// [spec §11.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#115-working-directory
    CwdOutside,
    /// `playpen run` of a target that does not exist, inside the one root the profile grants, so
    /// the `exec` that fails is the confined child's and not a path the boundary hid
    /// ([spec Appendix C], item C9).
    ///
    /// [spec Appendix C]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#appendix-c--assembly-choices
    AbsentTarget,
    /// `playpen run` of a profile with one `exclusive` area while another run of it holds that
    /// area: a run of the suite's own, launched first and held until the refusal is in
    /// ([spec §5.4]).
    ///
    /// [spec §5.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#54-provisioned-areas
    HeldArea,
    /// `playpen run` under a state directory where the run scratch's parent is a regular file, so
    /// the scratch cannot be created ([spec §5.7]). The record lives beside it and is untouched,
    /// which is what makes this the refusal and not the record's own failure to open.
    ///
    /// [spec §5.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#57-run-scratch
    ScratchBlocked,
    /// `playpen run` with `RLIMIT_NPROC` at zero on that one launch, so its first `fork` — the
    /// floor self-test's throwaway child — is refused by the kernel ([spec §8.6]). Ignored for a
    /// caller that is root, which a reference host's suite does not run as.
    ///
    /// [spec §8.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#86-the-floor-self-test
    NoProcesses,
    /// `playpen run` with `PLAYPEN_FLOOR` naming a dedicated floor of the suite's own making on
    /// that one launch, in the state `floor` says ([spec §8.2]).
    ///
    /// [spec §8.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#82-the-floor
    Floor(DedicatedFloor),
    /// `playpen run` of a profile with one credential route whose minter answers, with
    /// `SSL_CERT_FILE` naming an empty file on that one launch: the host's own trust store is what
    /// the host says it is, and this one says nothing ([ADR 0030]). The broker would have nothing to
    /// verify a destination against.
    ///
    /// [ADR 0030]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0030-the-hosts-own-trust-store-is-what-the-host-says-it-is.md
    NoTrustedRoots,
    /// `playpen explain --run` of a well-formed run id the fixture's ring does not hold
    /// ([spec §14.2]).
    ///
    /// [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
    UnknownRun,
}

/// Where [`Invocation::Locate`] puts the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Location {
    /// Nowhere: `--policy` names a path in the fixture's policy directory that does not exist.
    /// Named rather than searched for, so a host's own `/etc/playpen` cannot answer instead.
    Absent,
    /// `--policy` names a directory.
    Directory,
    /// No `--policy`, and the first location of the search path holds both `policy.yaml` and
    /// `policy.json`, each a document that would load. That location is the launch's own
    /// `XDG_CONFIG_HOME`, set on that one launch and never on the suite; being first, it is
    /// refused before any location of the host's is looked at.
    BothFormats,
}

/// The state of a dedicated floor [`Invocation::Floor`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedicatedFloor {
    /// An empty directory: no declared closure at all.
    Undeclared,
    /// A declared closure, and a canary at `bin/true` that is not executable, so it cannot start
    /// when confined.
    CanaryUnrunnable,
}

/// The name [`Invocation::Shim`] and [`Invocation::UnfoundLink`] invoke playpen under.
pub const SHIM: &str = "tool";

/// What [`Invocation::Policy`] and [`Invocation::Shim`] substitute with the fixture's one root.
pub const ROOT: &str = "{root}";
/// What they substitute with the floor's shell.
pub const SH: &str = "{sh}";
/// What they substitute with the floor's canary.
pub const CANARY: &str = "{canary}";

/// Which rung of the denial trace's precondition ladder is made to fail ([spec §14.5]), or made
/// to fail only on the pass that *brackets* the run.
///
/// The rungs are ordered as the ladder is, and each names the one thing an operator would act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    /// Landlock ABI below 7, where a denial is first logged at all.
    KernelAbi,
    /// Landlock compiled in and disabled at boot, which the version query answers `EOPNOTSUPP`
    /// for where absence answers `ENOSYS`.
    LandlockInactive,
    /// A pin that does not pass `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`, which upstream nono is.
    BackendNoLogging,
    /// A journal the invoking user cannot read.
    NoJournalAccess,
    /// The channel self-test's own denial leaves no record at all.
    ChannelSilent,
    /// It leaves one only on `_TRANSPORT=kernel`, the kernel's shared print rate limit.
    ChannelLossy,
    /// The channel delivers before the launch and is silent after it: the run launches, and its
    /// trace is marked **unverified** rather than presented as complete. Not a refusal, so no
    /// code: the row that uses it is a positive.
    SilentAfterTheRun,
}

impl Rung {
    /// Every rung, so that a new one is a row rather than a thing nothing exercises.
    #[cfg(target_os = "linux")]
    pub const ALL: &[Rung] = &[
        Rung::KernelAbi,
        Rung::LandlockInactive,
        Rung::BackendNoLogging,
        Rung::NoJournalAccess,
        Rung::ChannelSilent,
        Rung::ChannelLossy,
        Rung::SilentAfterTheRun,
    ];

    /// The name this rung is passed to the re-run playpen under, and the suffix of its row id.
    pub const fn name(self) -> &'static str {
        match self {
            Rung::KernelAbi => "kernel-abi",
            Rung::LandlockInactive => "landlock-inactive",
            Rung::BackendNoLogging => "backend-no-logging",
            Rung::NoJournalAccess => "no-journal-access",
            Rung::ChannelSilent => "channel-silent",
            Rung::ChannelLossy => "channel-lossy",
            Rung::SilentAfterTheRun => "silent-after-the-run",
        }
    }

    /// The rung of this name, or `None` where nothing goes by it.
    #[cfg(target_os = "linux")]
    pub fn parse(name: &str) -> Option<Rung> {
        Rung::ALL.iter().copied().find(|rung| rung.name() == name)
    }

    /// The code the flag is refused under when this rung fails, and `None` for the one rung that
    /// is not a refusal at all.
    pub const fn code(self) -> Option<Code> {
        match self {
            Rung::KernelAbi => Some(Code::TraceKernelAbi),
            Rung::LandlockInactive => Some(Code::TraceLandlockInactive),
            Rung::BackendNoLogging => Some(Code::TraceBackendNoLogging),
            Rung::NoJournalAccess => Some(Code::TraceNoJournalAccess),
            Rung::ChannelSilent => Some(Code::TraceChannelSilent),
            Rung::ChannelLossy => Some(Code::TraceChannelLossy),
            Rung::SilentAfterTheRun => None,
        }
    }

    /// The row id that asserts it.
    pub const fn row(self) -> &'static str {
        match self {
            Rung::KernelAbi => "R-trace-denials/kernel-abi",
            Rung::LandlockInactive => "R-trace-denials/landlock-inactive",
            Rung::BackendNoLogging => "R-trace-denials/backend-no-logging",
            Rung::NoJournalAccess => "R-trace-denials/no-journal-access",
            Rung::ChannelSilent => "R-trace-denials/channel-silent",
            Rung::ChannelLossy => "R-trace-denials/channel-lossy",
            Rung::SilentAfterTheRun => "R-trace-denials/unverified",
        }
    }
}

/// Roots enough to put a profile over the compiled-profile ceiling, each named by
/// [`over_ceiling_name`]. The ceiling is on the bytes of the granted paths that their neighbours do
/// not share, so long names that differ from their first character cross it with few roots, and
/// few roots compile fast: on macOS 26.6 these come to about 124,000 bytes, near twice the
/// ceiling, refused in under a second. Names differing only at their end cost about ten bytes a
/// root and take the kernel tens of seconds to refuse.
pub const OVER_CEILING: usize = 600;

/// The name of root `i` of [`OVER_CEILING`]: its index, repeated to 200 characters.
pub fn over_ceiling_name(i: usize) -> String {
    format!("{i:05}").repeat(40)
}

/// What the row asserts of the action, outside and then inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    /// Succeeds outside; inside fails with a denial of this platform, never with absence: an
    /// errno in the denial set and never `ENOENT`, or on macOS a Mach lookup that is not
    /// privileged and never an unknown service.
    Denial,
    /// Succeeds outside; inside fails with `EBADF`, because playpen closed the descriptor before
    /// `exec` ([spec §8.7]). Not a kernel denial, so the denial set does not govern it.
    ///
    /// [spec §8.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#87-file-descriptors
    Closed,
    /// Succeeds outside and inside.
    Succeeds,
    /// playpen exits `125` with this code on its refusal line, and the run record the line names
    /// exists afterwards, holding the same code ([spec §14.1]).
    ///
    /// [spec §14.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#141-the-run-record
    Recorded(Code),
    /// As [`Expected::Recorded`], and the refusal line names each `line:column` of the YAML
    /// policy the invocation ran under.
    RecordedAt(Code, &'static [(u32, u32)]),
    /// playpen exits `125` with this code on its refusal line, the line names **no** run, and the
    /// ring holds no record afterwards: the refusal of a command that launches nothing
    /// ([spec §14.2]). The empty ring is the half that keeps it from being any refusal at all — a
    /// build that opened a record for `explain` would push a real run out of the ring.
    ///
    /// [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
    Unrecorded(Code),
    /// `playpen check` refuses the document with this code, which shows the existence check is
    /// there to skip; `check --no-filesystem` of the same document then succeeds, silently.
    Unexamined(Code),
    /// Succeeds outside; inside, the request reaches the destination with the **secret in place of
    /// the phantom, in the header the phantom came in**, and the phantom does not arrive at all
    /// ([spec §7.3]).
    ///
    /// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
    Authenticated,
    /// As [`Expected::Authenticated`] for the proxied leg, and the **bypassing** leg arrives
    /// without the secret. One assertion over a pair, because either half alone would pass on a
    /// build the other catches: injecting into nothing, and a real secret having reached the
    /// child's environment.
    ///
    /// Not "without the phantom" — the bypassing leg carries it by construction, since both legs
    /// present the same request. The phantom is not a secret, and what it buys is use of the
    /// *proxy*, which a destination is not ([spec §7.3]).
    ///
    /// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
    OnlyThroughTheProxy,
    /// Succeeds outside; inside the broker answers `403` with this code and `X-Playpen-Denied`
    /// ([spec §6.4]). A broker denial is a kernel denial's counterpart at L7, so this is a
    /// negative — but it is an HTTP answer and not an errno, so [`DENIAL_ERRNOS`] does not govern
    /// it.
    ///
    /// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
    Brokered(Code),
    /// A traced run whose bracketing self-test passes leaves a trace it vouches for, and one
    /// whose second pass is silent leaves a trace marked unverified — in the run record and in
    /// the trace file itself ([spec §14.5]). Neither launch refuses: the trace is an account of
    /// the run, not a verdict on it.
    ///
    /// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
    TraceBracketed,
    /// Succeeds outside; inside the request **is denied** and the destination records no request at
    /// all, so the secret was never sent to a destination a rule refused ([spec §7.6]).
    ///
    /// The denial is half of this assertion and not a duplicate of [`Expected::Brokered`]'s: "no
    /// upstream leg occurred" is about *that request*, and a destination records nothing just as
    /// readily from a launch that never ran.
    ///
    /// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
    NoUpstreamLeg,
    /// No `refusal.*` code of the registry lacks a producing row: a refusal row whose expected
    /// code it is. Fails naming every one that does. There is no exemption list — a code nothing
    /// can provoke is a fault, and belongs under `bug.*` ([ADR 0024]).
    ///
    /// [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
    Covered,
}

impl Expected {
    /// The class an assertion of this kind belongs to.
    pub fn class(self) -> Class {
        match self {
            Expected::Denial
            | Expected::Closed
            | Expected::Brokered(_)
            | Expected::NoUpstreamLeg => Class::Negative,
            Expected::Succeeds
            | Expected::Authenticated
            | Expected::OnlyThroughTheProxy
            | Expected::TraceBracketed => Class::Positive,
            Expected::Recorded(_)
            | Expected::RecordedAt(..)
            | Expected::Unrecorded(_)
            | Expected::Unexamined(_)
            | Expected::Covered => Class::Refusal,
        }
    }

    /// The code a row expecting this produces, if it expects one to be produced.
    pub fn produces(self) -> Option<Code> {
        match self {
            Expected::Recorded(code)
            | Expected::RecordedAt(code, _)
            | Expected::Unrecorded(code)
            | Expected::Unexamined(code) => Some(code),
            // Enumerated rather than a wildcard: a new way to produce a code must be a compile
            // error here, or `R-code-coverage` would not see it.
            Expected::Denial
            | Expected::Closed
            | Expected::Succeeds
            | Expected::Authenticated
            | Expected::OnlyThroughTheProxy
            | Expected::Brokered(_)
            | Expected::TraceBracketed
            | Expected::NoUpstreamLeg
            | Expected::Covered => None,
        }
    }
}

/// `R-code-coverage`: every `refusal.*` code of the registry is produced by a refusal row of
/// `rows`, or the verdict names each one that is not.
pub fn judge_coverage(expected: Expected, rows: &[Row]) -> Verdict {
    if expected != Expected::Covered {
        return Verdict::Setup(format!("{expected:?} is not a coverage assertion"));
    }
    let missing: Vec<&str> = Code::ALL
        .iter()
        .map(|code| code.as_str())
        .filter(|code| code.starts_with("refusal."))
        .filter(|code| {
            !rows.iter().any(|row| {
                row.class == Class::Refusal
                    && row.expected.produces().map(Code::as_str) == Some(*code)
            })
        })
        .collect();
    match missing.as_slice() {
        [] => Verdict::Pass,
        missing => Verdict::Fail(format!(
            "no row produces {} of the registry's refusal codes: {}",
            missing.len(),
            missing.join(", ")
        )),
    }
}

/// A deciding issue or ADR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Adr(u16),
    Issue(u32),
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::Adr(n) => write!(f, "ADR {n:04}"),
            Decision::Issue(n) => write!(f, "#{n}"),
        }
    }
}

/// What one side of an assertion observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seen {
    Succeeded,
    /// How the call reported the failure, when it was a call's, and what was observed, for the
    /// report.
    Failed {
        cause: Option<Cause>,
        detail: String,
    },
}

/// How a failed call reported its failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// A system call's `errno`.
    Errno(i32),
    /// A Mach bootstrap lookup's `kern_return_t`.
    Bootstrap(i32),
}

/// What a refusing invocation left behind, as seen from outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declined {
    pub status: Option<i32>,
    /// The code on the refusal line, if stderr held exactly one line that reads as one, and the
    /// run id it names, if it names one.
    pub line: Option<(String, Option<String>)>,
    /// That line as written, or empty.
    pub text: String,
    /// The record of that run, if it exists, by the refusal code it stores: the inner `None` is a
    /// record that holds no refusal.
    pub recorded: Option<Option<String>>,
    /// How many records the state directory's ring holds afterwards.
    pub ring: usize,
    /// What was observed, for the report.
    pub detail: String,
}

/// The verdict on a row that ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// The boundary did not behave as the row asserts.
    Fail(String),
    /// The condition did not hold outside, so the inside proves nothing. Never a pass.
    Setup(String),
}

/// What became of a row on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Runs(Verdict),
    /// Scoped to the other platform, under this ledger entry.
    NotApplicable(Asymmetry),
    /// Applies here, and this host lacks a precondition.
    Skipped(Precondition),
}

impl Outcome {
    pub fn failed(&self) -> bool {
        matches!(self, Outcome::Runs(Verdict::Fail(_) | Verdict::Setup(_)))
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Outcome::Runs(Verdict::Pass) => f.write_str("runs: pass"),
            Outcome::Runs(Verdict::Fail(why)) => write!(f, "runs: FAILED: {why}"),
            Outcome::Runs(Verdict::Setup(why)) => write!(f, "runs: SETUP FAILURE: {why}"),
            Outcome::NotApplicable(asymmetry) => write!(f, "n/a: {}", asymmetry.name()),
            Outcome::Skipped(precondition) => write!(f, "skipped: {}", precondition.skip()),
        }
    }
}

/// Whether `platform` lets a row run on `host`, or what it is instead.
pub fn applies(platform: &Platform, host: &Host) -> Result<(), Outcome> {
    if let Scope::Only(os, asymmetry) = platform.scope
        && os != Os::HERE
    {
        return Err(Outcome::NotApplicable(asymmetry));
    }
    match platform.requires.iter().find(|p| !p.holds(host)) {
        Some(&missing) => Err(Outcome::Skipped(missing)),
        None => Ok(()),
    }
}

/// The two-part assertion: the condition first holds outside, then the boundary behaves inside.
pub fn judge(expected: Expected, outside: &Seen, inside: &Seen) -> Verdict {
    if let Seen::Failed { detail, .. } = outside {
        return Verdict::Setup(format!("the condition does not hold outside: {detail}"));
    }
    match (expected, inside) {
        (Expected::Succeeds, Seen::Succeeded) => Verdict::Pass,
        (Expected::Succeeds, Seen::Failed { detail, .. }) => {
            Verdict::Fail(format!("fails inside: {detail}"))
        }
        (Expected::Denial | Expected::Closed, Seen::Succeeded) => {
            Verdict::Fail("reachable inside".into())
        }
        (Expected::Denial, Seen::Failed { cause, detail }) => match cause {
            Some(Cause::Errno(libc::ENOENT)) => Verdict::Fail(format!(
                "ENOENT inside: a denial must never read as absence: {detail}"
            )),
            Some(Cause::Errno(errno)) if DENIAL_ERRNOS.contains(errno) => Verdict::Pass,
            #[cfg(target_os = "macos")]
            Some(Cause::Bootstrap(mach2::bootstrap::BOOTSTRAP_UNKNOWN_SERVICE)) => Verdict::Fail(
                format!("an unknown service inside: a denial must never read as absence: {detail}"),
            ),
            #[cfg(target_os = "macos")]
            Some(Cause::Bootstrap(mach2::bootstrap::BOOTSTRAP_NOT_PRIVILEGED)) => Verdict::Pass,
            _ => Verdict::Fail(format!(
                "not a denial of this platform (errnos {DENIAL_ERRNOS:?}): {detail}"
            )),
        },
        (Expected::Closed, Seen::Failed { cause, detail }) => match cause {
            Some(Cause::Errno(libc::EBADF)) => Verdict::Pass,
            _ => Verdict::Fail(format!("not EBADF: {detail}")),
        },
        (
            Expected::Recorded(_)
            | Expected::RecordedAt(..)
            | Expected::Unrecorded(_)
            | Expected::Unexamined(_),
            _,
        ) => Verdict::Setup(
            "a refusal has no inside: playpen declined to launch, so it is judged by what it left"
                .into(),
        ),
        (
            Expected::Authenticated
            | Expected::OnlyThroughTheProxy
            | Expected::Brokered(_)
            | Expected::NoUpstreamLeg,
            _,
        ) => Verdict::Setup(
            "a credential-route assertion is judged by what arrived at the destination, which an \
             errno cannot carry"
                .into(),
        ),
        (Expected::TraceBracketed, _) => Verdict::Setup(
            "a bracketed trace is judged by what two runs' records hold, not by a call's errno"
                .into(),
        ),
        (Expected::Covered, _) => {
            Verdict::Setup("coverage is judged over the table, not by a call's errno".into())
        }
    }
}

/// What one leg of a credential-route row did: what came back to the probe, and what the
/// destination the harness stood up received of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange {
    /// The answer the probe read, or why it read none.
    pub answer: Result<String, String>,
    /// The request head the destination recorded, or `None` where **no upstream leg occurred**.
    pub arrived: Option<String>,
}

/// What a credential-route row observed, on each leg it drove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchanged {
    pub proxied: Exchange,
    /// The leg the broker does not broker, where the row drove one: direct around the proxy, or
    /// through it to a non-routed authority, where it opens an opaque tunnel and reads nothing.
    pub unbrokered: Option<Exchange>,
    /// What was observed, for the report.
    pub detail: String,
}

/// What a credential-route row is judged against: the secret that must arrive, and the header it
/// must arrive in. The header matters because substitution is **in place** — the secret must arrive
/// in whichever header the phantom came in, so a proxy that moved it has not done this.
///
/// The phantom's own **value** is not here, and does not need to be: it is recognised by
/// [`carries_a_phantom`] by its shape. A harness that had to be told the value could only learn it
/// by having a phantom printed on the suite's stdout.
#[derive(Debug, Clone, Copy)]
pub struct Substitution<'a> {
    pub secret: &'a str,
    pub header: &'a str,
}

/// How many hex digits a session phantom is: `proxy::PHANTOM_BYTES`, doubled ([spec §7.3]).
///
/// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
const PHANTOM_HEX: usize = 64;

/// Whether `head` holds anything shaped like a session phantom: a run of at least [`PHANTOM_HEX`]
/// lowercase hex digits.
///
/// Shape rather than value, and that is what makes it worth having: it catches a phantom
/// **anywhere** in the head, so a broker that substituted in place and *also* copied the phantom
/// into a second header fails — which an assertion about the one header's value cannot see.
///
/// Nothing a passing row sends can be mistaken for one. The probe writes only the request line,
/// `Host`, the delivery header and `Accept`, and the secret these rows inject carries hyphens.
fn carries_a_phantom(head: &str) -> bool {
    head.split(|c: char| !c.is_ascii_hexdigit() || c.is_ascii_uppercase())
        .any(|run| run.len() >= PHANTOM_HEX)
}

/// A credential-route row: the condition first holds outside, then the destination received what
/// the row says it should have ([ADR 0016]).
///
/// Neither the answer nor what arrived is the assertion alone. A `200` says the legs connected; it
/// says nothing about which token went out, and only the destination's own record does.
///
/// [ADR 0016]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md
pub fn judge_request(
    expected: Expected,
    substitution: Substitution<'_>,
    outside: &Seen,
    seen: &Exchanged,
) -> Verdict {
    if let Seen::Failed { detail, .. } = outside {
        return Verdict::Setup(format!("the condition does not hold outside: {detail}"));
    }
    let detail = &seen.detail;
    let Substitution { secret, header } = substitution;
    // The whole header line, terminator included: a value that merely *contains* the secret would
    // also match a phantom left beside it.
    let presented = format!("{header}: {secret}\r\n");
    let authenticated = |exchange: &Exchange| -> Verdict {
        let Some(arrived) = &exchange.arrived else {
            return Verdict::Fail(format!(
                "no request reached the destination, so nothing was authenticated: {detail}"
            ));
        };
        if !arrived.contains(&presented) {
            return Verdict::Fail(format!(
                "the secret did not arrive as the whole of the header the phantom came in \
                 ({header}): {detail}"
            ));
        }
        // And the phantom did not arrive — anywhere, not merely in that header.
        match carries_a_phantom(arrived) {
            false => Verdict::Pass,
            true => Verdict::Fail(format!("the phantom reached the destination: {detail}")),
        }
    };
    match expected {
        Expected::TraceBracketed => Verdict::Setup(
            "a bracketed trace is judged by what two runs' records hold, not by a request".into(),
        ),
        Expected::Authenticated => authenticated(&seen.proxied),
        Expected::OnlyThroughTheProxy => {
            match authenticated(&seen.proxied) {
                Verdict::Pass => {}
                // A build that injected into nothing fails here, which is what keeps the bypass
                // half from passing vacuously.
                failed => return failed,
            }
            let Some(unbrokered) = &seen.unbrokered else {
                return Verdict::Setup(format!(
                    "the row drove no unbrokered leg, and the pair is the assertion: {detail}"
                ));
            };
            // A failure here is the inside's, never the host's: the outside half has already shown
            // this host can reach and verify the destination, so a leg that cannot do it from
            // inside is a boundary regression — the child's own trust store having stopped naming
            // the roots it trusts, for one
            // ([#140](https://github.com/firefly-engineering/playpen/issues/140)).
            let Some(arrived) = &unbrokered.arrived else {
                return Verdict::Fail(format!(
                    "the unbrokered request never reached the destination, which this host reached \
                     outside: {detail}"
                ));
            };
            // Both legs present **whatever the delivery variable holds**, so what this half
            // catches is a real secret having reached that variable: "there is no mode in which a
            // real secret enters the sandbox's environment" ([spec §7.3]) asserted from inside,
            // against a destination that records what it was sent. A build that leaked the secret
            // into the child's environment passes a proxied-only row and fails here.
            //
            // This leg does arrive carrying the phantom, and that is not a leak: the phantom is
            // not a secret, and what it buys is use of the *proxy*, which a destination is not.
            // Driving it with something else to avoid that would make the two legs incomparable,
            // which is the vacuity the pair exists to rule out.
            match arrived.contains(secret) {
                false => Verdict::Pass,
                true => Verdict::Fail(format!(
                    "a request the broker did not broker arrived authenticated: {detail}"
                )),
            }
        }
        Expected::Brokered(code) => {
            match denied(&seen.proxied, detail) {
                Verdict::Pass => {}
                failed => return failed,
            }
            // Unwrapped above.
            let answer = seen.proxied.answer.as_deref().unwrap_or_default();
            if !answer.contains("X-Playpen-Denied:") {
                return Verdict::Fail(format!("no X-Playpen-Denied on the denial: {detail}"));
            }
            match answer.contains(code.as_str()) {
                true => Verdict::Pass,
                false => Verdict::Fail(format!("the denial does not name {code}: {detail}")),
            }
        }
        Expected::NoUpstreamLeg => {
            // The request has to have been made and refused, or "no upstream leg" is what a launch
            // that never ran also shows.
            match denied(&seen.proxied, detail) {
                Verdict::Pass => {}
                failed => return failed,
            }
            match &seen.proxied.arrived {
                None => Verdict::Pass,
                Some(arrived) => Verdict::Fail(format!(
                    "a request reached the destination: {arrived:?}: {detail}"
                )),
            }
        }
        // Enumerated rather than a wildcard: a new `Expected` variant must be a compile error
        // here, not a silent `Setup`. That is the shape of the vacuous pass [ADR 0016] denies.
        //
        // [ADR 0016]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md
        other @ (Expected::Denial
        | Expected::Closed
        | Expected::Succeeds
        | Expected::Recorded(_)
        | Expected::RecordedAt(..)
        | Expected::Unrecorded(_)
        | Expected::Unexamined(_)
        | Expected::Covered) => {
            Verdict::Setup(format!("{other:?} is not a credential route's assertion"))
        }
    }
}

/// Whether the broker refused `exchange` with a `403` it *answered* rather than a connection it
/// dropped ([spec §6.4]).
///
/// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
fn denied(exchange: &Exchange, detail: &str) -> Verdict {
    match &exchange.answer {
        Err(why) => Verdict::Fail(format!(
            "the request was never answered, so nothing was refused: {why}: {detail}"
        )),
        Ok(answer) if answer.starts_with("HTTP/1.1 403 ") => Verdict::Pass,
        Ok(_) => Verdict::Fail(format!("not a 403: {detail}")),
    }
}

/// A refusal row: exit `125` with the expected code, then the record that the line names holds
/// it. Neither half alone is the assertion: a run that launched leaves a record too. A command
/// that launches nothing is held to the converse: its line names no run, and the ring stays empty.
pub fn judge_refusal(expected: Expected, declined: &Declined) -> Verdict {
    let (code, sites, launched) = match expected {
        Expected::Recorded(code) => (code, &[][..], true),
        Expected::RecordedAt(code, sites) => (code, sites, true),
        Expected::Unrecorded(code) => (code, &[][..], false),
        _ => return Verdict::Setup(format!("{expected:?} is not a refusal's assertion")),
    };
    let detail = &declined.detail;
    if declined.status != Some(EXIT_REFUSED) {
        return Verdict::Fail(format!("did not refuse: {detail}"));
    }
    let run = match &declined.line {
        Some((seen, run)) if seen == code.as_str() => run,
        _ => return Verdict::Fail(format!("not one refusal line with {code}: {detail}")),
    };
    if let Some((line, column)) = sites
        .iter()
        .find(|(line, column)| !declined.text.contains(&format!(".yaml:{line}:{column}")))
    {
        return Verdict::Fail(format!(
            "the refusal line does not name {line}:{column} of the policy: {detail}"
        ));
    }
    // A command that launches nothing: the line names no run, and none was recorded.
    if !launched {
        return match (run, declined.ring) {
            (None, 0) => Verdict::Pass,
            (Some(run), _) => Verdict::Fail(format!(
                "the refusal line names run {run}, and nothing was launched: {detail}"
            )),
            (None, ring) => Verdict::Fail(format!(
                "the ring holds {ring} record(s), and nothing was launched: {detail}"
            )),
        };
    }
    if run.is_none() {
        return Verdict::Fail(format!("the refusal line names no run: {detail}"));
    }
    match &declined.recorded {
        None => Verdict::Fail(format!("no run record after the refusal: {detail}")),
        Some(Some(recorded)) if recorded == code.as_str() => Verdict::Pass,
        Some(recorded) => Verdict::Fail(format!(
            "the run record holds refusal {recorded:?}, not {code}: {detail}"
        )),
    }
}

/// What one traced launch left behind, as seen from outside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Traced {
    pub status: Option<i32>,
    /// Whether the run record names a trace file at all.
    pub traced: bool,
    /// Why the record says the trace is unverified, if it says so.
    pub unverified: Option<String>,
    /// Whether the trace file itself says so too: the operator may never read the record.
    pub file_says_unverified: bool,
    /// What was observed, for the report.
    pub detail: String,
}

/// Both halves of the bracketing assertion: a run whose self-test passes twice, and one whose
/// second pass is silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bracketed {
    pub vouched: Traced,
    pub silenced: Traced,
}

/// `R-trace-denials/unverified`: a failed post-run self-test marks the trace unverified, and a
/// passing one does not. Asserted as a pair, because "the record says unverified" alone would
/// pass on a build that said so of every trace ([spec §14.5]).
///
/// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
pub fn judge_bracket(expected: Expected, bracketed: &Bracketed) -> Verdict {
    if expected != Expected::TraceBracketed {
        return Verdict::Setup(format!("{expected:?} is not a bracketed trace's assertion"));
    }
    let Bracketed { vouched, silenced } = bracketed;
    // Outside first: a run whose channel delivers on both passes must launch and be traced, or
    // there is nothing for the other half to differ from.
    for (half, run) in [("vouched", vouched), ("silenced", silenced)] {
        if run.status != Some(0) {
            return Verdict::Setup(format!(
                "the {half} run did not launch and exit 0, so its flag was refused rather \
                 than traced: {}",
                run.detail
            ));
        }
        if !run.traced {
            return Verdict::Setup(format!(
                "the {half} run's record names no trace file: {}",
                run.detail
            ));
        }
    }
    if vouched.unverified.is_some() {
        return Verdict::Fail(format!(
            "a trace whose self-test passed on both passes was still marked unverified: {}",
            vouched.detail
        ));
    }
    match &silenced.unverified {
        None => Verdict::Fail(format!(
            "a trace whose post-run self-test found nothing was presented as complete: {}",
            silenced.detail
        )),
        Some(_) if !silenced.file_says_unverified => Verdict::Fail(format!(
            "the record says the trace is unverified and the trace itself does not: {}",
            silenced.detail
        )),
        Some(_) => Verdict::Pass,
    }
}

/// What `playpen check` did with one document, with the filesystem and without it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    /// The code on the refusal line `check` wrote with the filesystem, if it wrote exactly one.
    pub examined: Option<String>,
    /// Whether `check --no-filesystem` exited 0 having written nothing at all.
    pub unexamined_silent_success: bool,
    /// What was observed, for the report.
    pub detail: String,
}

/// `R-no-filesystem`: without the first half, a `check` that looked at nothing at all would pass.
pub fn judge_unexamined(expected: Expected, checked: &Checked) -> Verdict {
    let Expected::Unexamined(code) = expected else {
        return Verdict::Setup(format!(
            "{expected:?} is not an unexamined check's assertion"
        ));
    };
    let detail = &checked.detail;
    if checked.examined.as_deref() != Some(code.as_str()) {
        return Verdict::Setup(format!(
            "with the filesystem, check did not refuse with {code}, so there is nothing to skip: \
             {detail}"
        ));
    }
    if checked.unexamined_silent_success {
        Verdict::Pass
    } else {
        Verdict::Fail(format!("check --no-filesystem looked: {detail}"))
    }
}
