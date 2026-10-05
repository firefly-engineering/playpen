//! The row form ([spec §17.1]): `{id, class, platform, fixture, action, expected, from}`, every
//! field a closed type. Adding an instance of an existing check is a row in [`crate::rows`];
//! adding a new kind of check is one variant of [`Action`].
//!
//! [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form

use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

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
}

impl Precondition {
    /// The stable name the row is skipped under when this does not hold.
    pub fn skip(self) -> &'static str {
        match self {
            Precondition::HomeWritable => "skip.host.home-not-writable",
            Precondition::Nix => "skip.host.no-nix",
            Precondition::Homebrew => "skip.host.no-homebrew",
        }
    }

    /// Probed without writing anything: a probe that wrote would need the reclamation it guards.
    pub fn holds(self, home: &Path) -> bool {
        match self {
            Precondition::HomeWritable => writable(home),
            Precondition::Nix => std::process::Command::new("nix-store")
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success()),
            Precondition::Homebrew => homebrew_prefix().is_some_and(|prefix| {
                writable(&prefix.join("Cellar")) && writable(&prefix.join("opt"))
            }),
        }
    }
}

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
            Action::Refuse(_) | Action::CheckDocument => fixture == Fixture::Outside,
            Action::PullDenials => fixture == Fixture::DescendantDenied,
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
    /// `playpen run` under a YAML policy whose one root holds a key misspelt inside
    /// `definitions:`, arriving through a merge key ([spec §10.2]). [`POLICY_SPAN_SITES`] are the
    /// use site and the definition site, in that document.
    ///
    /// [spec §10.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#102-syntax-and-strictness
    MergedTypo,
    /// `playpen run` under a policy whose selected profile names a workspace the policy does not
    /// declare: the coherence tier's, at launch step 5 ([spec §10.5]).
    ///
    /// [spec §10.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#105-validation-tiers
    IncoherentWorkspace,
    /// `playpen run` under a policy file that lies inside the profile's own read-write root, so the
    /// confined tree could rewrite the boundary of the next launch ([spec §11.7]).
    ///
    /// [spec §11.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#117-self-integrity
    WritablePolicy,
}

/// The policy [`Invocation::MergedTypo`] runs under, with `{root}` for its one root's path.
pub const MERGED_TYPO: &str = "\
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
pub const POLICY_SPAN_SITES: &[(u32, u32)] = &[(8, 13), (4, 5)];

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
    /// `playpen check` refuses the document with this code, which shows the existence check is
    /// there to skip; `check --no-filesystem` of the same document then succeeds, silently.
    Unexamined(Code),
}

impl Expected {
    /// The class an assertion of this kind belongs to.
    pub fn class(self) -> Class {
        match self {
            Expected::Denial | Expected::Closed => Class::Negative,
            Expected::Succeeds => Class::Positive,
            Expected::Recorded(_) | Expected::RecordedAt(..) | Expected::Unexamined(_) => {
                Class::Refusal
            }
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
    /// The code and run id on the refusal line, if stderr held exactly one line that reads as one.
    pub line: Option<(String, String)>,
    /// That line as written, or empty.
    pub text: String,
    /// The record of that run, if it exists, by the refusal code it stores: the inner `None` is a
    /// record that holds no refusal.
    pub recorded: Option<Option<String>>,
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

/// Whether `platform` lets a row run on this host, whose caller's home is `home`, or what it is
/// instead.
pub fn applies(platform: &Platform, home: &Path) -> Result<(), Outcome> {
    if let Scope::Only(os, asymmetry) = platform.scope
        && os != Os::HERE
    {
        return Err(Outcome::NotApplicable(asymmetry));
    }
    match platform.requires.iter().find(|p| !p.holds(home)) {
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
        (Expected::Recorded(_) | Expected::RecordedAt(..) | Expected::Unexamined(_), _) => {
            Verdict::Setup(
                "a refusal has no inside: playpen declined to launch, so it is judged by what it left"
                    .into(),
            )
        }
    }
}

/// A refusal row: exit `125` with the expected code, then the record that the line names holds
/// it. Neither half alone is the assertion: a run that launched leaves a record too.
pub fn judge_refusal(expected: Expected, declined: &Declined) -> Verdict {
    let (code, sites) = match expected {
        Expected::Recorded(code) => (code, &[][..]),
        Expected::RecordedAt(code, sites) => (code, sites),
        _ => return Verdict::Setup(format!("{expected:?} is not a refusal's assertion")),
    };
    let detail = &declined.detail;
    if declined.status != Some(EXIT_REFUSED) {
        return Verdict::Fail(format!("did not refuse: {detail}"));
    }
    match &declined.line {
        Some((seen, _)) if seen == code.as_str() => {}
        _ => return Verdict::Fail(format!("not one refusal line with {code}: {detail}")),
    }
    if let Some((line, column)) = sites
        .iter()
        .find(|(line, column)| !declined.text.contains(&format!(".yaml:{line}:{column}")))
    {
        return Verdict::Fail(format!(
            "the refusal line does not name {line}:{column} of the policy: {detail}"
        ));
    }
    match &declined.recorded {
        None => Verdict::Fail(format!("no run record after the refusal: {detail}")),
        Some(Some(recorded)) if recorded == code.as_str() => Verdict::Pass,
        Some(recorded) => Verdict::Fail(format!(
            "the run record holds refusal {recorded:?}, not {code}: {detail}"
        )),
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
