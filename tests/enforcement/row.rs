//! The row form ([spec §17.1]): `{id, class, platform, fixture, action, expected, from}`, every
//! field a closed type. Adding an instance of an existing check is a row in [`crate::rows`];
//! adding a new kind of check is one variant of [`Action`].
//!
//! [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form

use std::fmt;

use crate::common::DENIAL_ERRNOS;

/// One assertion of the suite.
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

/// The refusal class, asserted from outside with no sandbox at all, arrives with its first row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// From inside, the action must fail with a denial.
    Negative,
    /// From inside, the action must succeed. Admissible only if the regression it catches is
    /// silent.
    Positive,
}

/// Where a row applies, and what it needs of the host there.
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
}

/// A host precondition a row needs, each probed explicitly and skipping by its own stable name
/// (`skip.host.no-nix`, …). A skip is never inferred from a failure: [`judge`] has no skip to
/// return. No row needs one yet; the first that does adds its variant and its probe here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precondition {}

impl Precondition {
    /// The stable name the row is skipped under when this does not hold.
    pub fn skip(self) -> &'static str {
        match self {}
    }

    pub fn holds(self) -> bool {
        match self {}
    }
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
}

/// The closed set of checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The floor self-test's canary, through the self-test's own implementation ([spec §8.6]).
    ///
    /// [spec §8.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#86-the-floor-self-test
    Canary,
    /// The probe opens the target and reads it to the end.
    Read(Target),
    /// The probe creates a file that does not exist yet inside the target directory.
    Create(Target),
}

impl Action {
    /// The only fixture this action can run under: the canary admits no grant beside the floor,
    /// and everything else needs the probe's root.
    pub fn fixture(self) -> Fixture {
        match self {
            Action::Canary => Fixture::BareFloor,
            Action::Read(_) | Action::Create(_) => Fixture::ProbeRoot,
        }
    }
}

/// A path the fixture establishes outside before the row runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A private key `~/.ssh/id_*`: the host's own if it has one, else a decoy created there.
    SshKey,
    /// A fresh directory outside every grant.
    DecoyDir,
}

/// What the row asserts of the action, outside and then inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expected {
    /// Succeeds outside; inside fails with an errno in the platform's denial set, never `ENOENT`.
    Denial,
    /// Succeeds outside and inside.
    Succeeds,
}

impl Expected {
    /// The class an assertion of this kind belongs to.
    pub fn class(self) -> Class {
        match self {
            Expected::Denial => Class::Negative,
            Expected::Succeeds => Class::Positive,
        }
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
    /// `errno` when the failure was a system call's, and what was observed, for the report.
    Failed {
        errno: Option<i32>,
        detail: String,
    },
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

/// Whether `platform` lets a row run on this host, or what it is instead.
pub fn applies(platform: &Platform) -> Result<(), Outcome> {
    if let Scope::Only(os, asymmetry) = platform.scope
        && os != Os::HERE
    {
        return Err(Outcome::NotApplicable(asymmetry));
    }
    match platform.requires.iter().find(|p| !p.holds()) {
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
        (Expected::Denial, Seen::Succeeded) => Verdict::Fail("reachable inside".into()),
        (Expected::Denial, Seen::Failed { errno, detail }) => match errno {
            Some(libc::ENOENT) => Verdict::Fail(format!(
                "ENOENT inside: a denial must never read as absence: {detail}"
            )),
            Some(errno) if DENIAL_ERRNOS.contains(errno) => Verdict::Pass,
            _ => Verdict::Fail(format!(
                "not a denial errno of this platform {DENIAL_ERRNOS:?}: {detail}"
            )),
        },
    }
}
