//! What playpen provisions for a run under its own state directory: the **run scratch**
//! ([spec §5.7]) and the selected workspaces' **provisioned areas** ([spec §5.4]). Every path here
//! is derived from the state directory, so it is exempt from the state-reachability check
//! ([ADR 0027]) and granted read-write.
//!
//! The paths are a pure function of the state directory, the run and the policy ([`Layout`]), so
//! `explain` states them without creating anything; `run` creates them at launch steps 8 and 9
//! and removes what is the run's own at teardown ([spec §4.2]).
//!
//! playpen arbitrates only what it provisions ([ADR 0010]): an `ephemeral` area is keyed by run, so
//! there is nothing to arbitrate; a `persistent` one is keyed by workspace, and is either `shared`,
//! or `exclusive` under an advisory lock the supervisor holds for the run.
//!
//! The **agent state directory** ([spec §5.6]) lives here too, though it is neither the run's nor a
//! workspace's: it is the *profile*'s, one per kind, shared by every run of that profile at once
//! and never removed ([ADR 0021]).
//!
//! [spec §5.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#57-run-scratch
//! [spec §5.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#54-provisioned-areas
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
//! [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
//! [ADR 0010]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0010-concurrency-is-a-property-of-a-provisioned-area.md
//! [ADR 0021]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0021-agent-state-belongs-to-the-profile.md
//! [ADR 0027]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md

use std::fmt::Write as _;
use std::fs::{DirBuilder, File, TryLockError};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::capability::{Access, PathGrant, Scope};
use crate::code::Code;
use crate::kind::Kind;
use crate::policy::{Area, AreaRef, Concurrency, Policy, Profile};
use crate::record::RunId;
use crate::refusal::Refusal;

/// The provenance of the run scratch.
pub const FROM_SCRATCH: &str = "run-scratch";

/// What `explain` names the run by, since it launches none: the paths it states are those any run
/// would get, with this in place of the run id.
pub const UNLAUNCHED: &str = "<run>";

/// The directory under the state directory holding one scratch per run.
const SCRATCH: &str = "scratch";
/// The directory under the state directory holding the areas.
const AREAS: &str = "areas";
/// Under [`AREAS`]: ephemeral areas, one directory per run.
const EPHEMERAL: &str = "ephemeral";
/// Under [`AREAS`]: persistent areas, one directory per workspace.
const PERSISTENT: &str = "persistent";
/// The directory under the state directory holding the lock file of each `exclusive` area. Beside
/// the areas rather than inside one, so no run is ever granted a lock file ([ADR 0010]).
///
/// [ADR 0010]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0010-concurrency-is-a-property-of-a-provisioned-area.md
const LOCKS: &str = "locks";
/// The directory under the state directory holding one agent state directory per profile × kind.
const AGENTS: &str = "agents";

/// Where a run's provisioned state lives.
#[derive(Debug, Clone)]
pub struct Layout {
    state: PathBuf,
    run: String,
    /// The selected profile's name, which keys the agent state directory.
    profile: String,
    /// The stated kind, which keys the agent state directory beside the profile. `None` where no
    /// kind is stated, as in `explain` of a profile, and then there is no agent state directory:
    /// a kind is never inferred ([spec §11.2]).
    ///
    /// [spec §11.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#112-kind
    kind: Option<&'static Kind>,
    areas: Vec<Planned>,
    /// The profile's share list for that kind, in the order it was written ([spec §5.6]). Each
    /// entry names something in the kind's real agent home and is made visible read-only inside
    /// the agent state directory, **by reference**: playpen confines and never remaps
    /// ([spec §11.6]), so the entry appears inside as a symlink to the real path, and that path is
    /// what is granted — read, never write.
    ///
    /// Default-deny: nothing from the agent home is visible unless it is named here.
    ///
    /// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
    /// [spec §11.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#116-process-transparency
    share: Vec<String>,
    /// The caller's home directory, where the kind's agent home — and so every share entry — is
    /// resolved. `None` where the host names none, which leaves every share entry sourceless and
    /// so refuses rather than sharing nothing.
    home: Option<PathBuf>,
}

/// One area of a selected workspace, as a run gets it.
#[derive(Debug, Clone)]
struct Planned {
    workspace: String,
    name: String,
    area: Area,
}

impl Planned {
    fn from(&self) -> String {
        format!("workspace:{}.areas.{}", self.workspace, self.name)
    }
}

impl Layout {
    /// The layout of run `run` of profile `profile`, `selected` from `policy`, launched as `kind`,
    /// under the state directory `state`, which should be resolved: the mechanism enforces on real
    /// paths.
    pub fn new(
        state: &Path,
        run: &RunId,
        policy: &Policy,
        profile: &str,
        selected: &Profile,
        kind: &'static Kind,
    ) -> Self {
        Self::of(
            state,
            run.to_string(),
            policy,
            profile,
            selected,
            Some(kind),
        )
    }

    /// The layout `explain` states: any run's, under `state`. `kind` is the kind the invocation
    /// named, which is `None` for `explain` of a profile.
    pub fn unlaunched(
        state: &Path,
        policy: &Policy,
        profile: &str,
        selected: &Profile,
        kind: Option<&'static Kind>,
    ) -> Self {
        Self::of(state, UNLAUNCHED.into(), policy, profile, selected, kind)
    }

    /// This layout with `home` as the caller's home directory, where every share entry is
    /// resolved. Separate from construction because the layout's own paths do not depend on it:
    /// only the share list does.
    #[must_use]
    pub fn with_home(mut self, home: Option<&Path>) -> Self {
        self.home = home.map(Path::to_owned);
        self
    }

    fn of(
        state: &Path,
        run: String,
        policy: &Policy,
        profile: &str,
        selected: &Profile,
        kind: Option<&'static Kind>,
    ) -> Self {
        // Areas stay per workspace across a profile's workspaces ([spec §5.5]): each is its own.
        //
        // [spec §5.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#55-profile
        let areas = selected
            .workspaces
            .iter()
            .filter_map(|name| policy.workspaces.get_key_value(&name.value))
            .flat_map(|(workspace, declared)| {
                declared.areas.iter().map(|(name, area)| Planned {
                    workspace: workspace.clone(),
                    name: name.clone(),
                    area: *area,
                })
            })
            .collect();
        // Default-deny: only the stated kind's own list is read, and only what it names.
        let share = kind
            .and_then(|kind| selected.agent_state.get(kind.name))
            .map(|state| state.share.clone())
            .unwrap_or_default();
        Self {
            state: state.to_owned(),
            run,
            profile: profile.to_owned(),
            kind,
            areas,
            share,
            home: None,
        }
    }

    /// Every share entry, as the provenance of where it was written, the name it appears under
    /// inside, and the real path outside — `None` where the host names no home, or the entry is
    /// not one name in that home.
    fn shared(&self) -> impl Iterator<Item = (String, &str, Option<PathBuf>)> {
        let kind = self.kind;
        let agent_home = kind.and_then(|kind| self.home.as_ref().map(|home| home.join(kind.home)));
        self.share.iter().enumerate().map(move |(i, entry)| {
            let from = format!(
                "profile:{}.agent_state.{}.share[{i}]",
                self.profile,
                kind.map_or("", |kind| kind.name)
            );
            // A share entry is one name in the kind's agent home. Anything else — a nested path,
            // `..`, an absolute path — names nothing playpen can share, and so has no source.
            let source = agent_home
                .as_ref()
                .filter(|_| one_name(entry))
                .map(|agent_home| agent_home.join(entry));
            (from, entry.as_str(), source)
        })
    }

    /// The grants the share list adds ([spec §5.6]): each named entry at its real path, read-only,
    /// so it is readable inside and never writable. A source that is missing — or a name that
    /// could never be one — refuses, because a share list that silently shared nothing would read
    /// as a working policy.
    ///
    /// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
    pub fn shares(&self) -> Result<Vec<PathGrant>, Refusal> {
        let mut grants = Vec::new();
        for (from, entry, source) in self.shared() {
            let missing = |detail: String| {
                Refusal::new(
                    Code::RootMissing,
                    format!("{from}: share entry {entry:?} {detail}"),
                )
            };
            let source = source.ok_or_else(|| {
                missing(
                    "is not one name in the kind's agent home, or the host names no home"
                        .to_string(),
                )
            })?;
            let path = source
                .canonicalize()
                .map_err(|e| missing(format!("is unavailable at {}: {e}", source.display())))?;
            grants.push(PathGrant {
                path,
                access: Access::Read,
                scope: Scope::Subtree,
                from,
                // Policy-declared, and outside the state directory: never exempt.
                state_derived: false,
            });
        }
        Ok(grants)
    }

    /// The run scratch: the run's own, and nobody else's.
    pub fn scratch(&self) -> PathBuf {
        self.state.join(SCRATCH).join(&self.run)
    }

    /// Where this run's manifest is written, which `PLAYPEN_MANIFEST` names ([spec §13.1]). In the
    /// scratch, which the run is granted read-write: the manifest describes the boundary and never
    /// constitutes it, so an agent rewriting it moves nothing.
    ///
    /// [spec §13.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#131-form
    pub fn manifest(&self) -> PathBuf {
        self.scratch().join(crate::manifest::FILE)
    }

    /// The agent state directory of this profile and kind ([spec §5.6]): keyed by profile × kind
    /// and never by workspace, so two profiles sharing a workspace do not share the agent's
    /// history, and renaming a profile starts a fresh directory. `None` where the invocation
    /// named no kind.
    ///
    /// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
    pub fn agent_state(&self) -> Option<PathBuf> {
        self.kind.map(|kind| {
            self.state
                .join(AGENTS)
                .join(component(&self.profile))
                .join(component(kind.name))
        })
    }

    /// Every ephemeral area of this run lives under this one directory, keyed by run.
    fn ephemeral(&self) -> PathBuf {
        self.state.join(AREAS).join(EPHEMERAL).join(&self.run)
    }

    fn path(&self, planned: &Planned) -> PathBuf {
        let base = match planned.area {
            Area::Ephemeral {} => self.ephemeral(),
            // Keyed by workspace name, so every run of the workspace finds the same one.
            Area::Persistent { .. } => self.state.join(AREAS).join(PERSISTENT),
        };
        base.join(component(&planned.workspace))
            .join(component(&planned.name))
    }

    /// The path of the area an `!area` reference names, if it names one of this layout's.
    pub fn area(&self, reference: &AreaRef) -> Option<PathBuf> {
        let (workspace, name) = reference.target()?;
        self.areas
            .iter()
            .find(|planned| planned.workspace == workspace && planned.name == name)
            .map(|planned| self.path(planned))
    }

    /// The lock file of an `exclusive` area.
    fn lock(&self, planned: &Planned) -> PathBuf {
        self.state
            .join(LOCKS)
            .join(component(&planned.workspace))
            .join(format!("{}.lock", component(&planned.name)))
    }

    /// Claim every `exclusive` area of this layout ([spec §4.2], step 8): an advisory `flock` on
    /// its lock file, held by the supervisor until it exits, for any reason, which is what
    /// releases it. A held lock refuses at once with `refusal.area.busy`, naming the run that holds
    /// it; launch never queues.
    ///
    /// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
    fn claim(&self) -> Result<Vec<File>, Refusal> {
        let exclusive = self.areas.iter().filter(|planned| {
            planned.area
                == Area::Persistent {
                    concurrency: Concurrency::Exclusive,
                }
        });
        let mut claims = Vec::new();
        for planned in exclusive {
            let path = self.lock(planned);
            let io = |e: std::io::Error| {
                Refusal::new(
                    Code::StateIo,
                    format!(
                        "cannot lock area {} at {}: {e}",
                        planned.from(),
                        path.display()
                    ),
                )
            };
            if let Some(parent) = path.parent() {
                create(
                    parent,
                    &format!("the lock directory of area {}", planned.from()),
                )?;
            }
            let mut file = File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&path)
                .map_err(io)?;
            // `flock`, so a lock follows the open file and the kernel drops it with the process.
            match file.try_lock() {
                Ok(()) => {}
                Err(TryLockError::WouldBlock) => {
                    return Err(Refusal::new(
                        Code::AreaBusy,
                        format!(
                            "area {} is held by {}, and its concurrency is exclusive",
                            planned.from(),
                            holder(&mut file)
                        ),
                    ));
                }
                Err(TryLockError::Error(e)) => return Err(io(e)),
            }
            // The holder's id, for the next run to name, written under the lock and cleared again
            // at teardown. A holder killed before teardown leaves its id behind, which this write
            // replaces: only in the instant between the lock and the write can a reader find it.
            file.set_len(0)
                .and_then(|()| file.write_all(self.run.as_bytes()))
                .map_err(io)?;
            claims.push(file);
        }
        Ok(claims)
    }

    /// The grants a run of this layout holds on what playpen provisions for it: read-write, as
    /// state playpen derived.
    pub fn grants(&self) -> Vec<PathGrant> {
        let grant = |path, from| PathGrant {
            path,
            access: Access::ReadWrite,
            scope: Scope::Subtree,
            from,
            state_derived: true,
        };
        std::iter::once(grant(self.scratch(), FROM_SCRATCH.into()))
            .chain(
                self.agent_state()
                    .into_iter()
                    .zip(self.kind)
                    .map(|(path, kind)| grant(path, kind.from())),
            )
            .chain(
                self.areas
                    .iter()
                    .map(|planned| grant(self.path(planned), planned.from())),
            )
            .collect()
    }

    /// Create the run scratch and every area. What was created for the run alone is removed when
    /// the returned value is dropped, which is teardown, and also any refusal after this point. A
    /// failure is `refusal.state.io`.
    pub fn provision(&self) -> Result<Provisioned, Refusal> {
        // Claimed first, so a run refused for a busy area creates nothing.
        let mut provisioned = Provisioned {
            removed: Vec::new(),
            claims: self.claim()?,
        };
        let scratch = self.scratch();
        create(&scratch, "the run scratch")?;
        provisioned.removed.push(scratch);
        // Created on first use and never removed: it holds the agent's transcripts, history and
        // memory, which outlive the run that wrote them ([spec §5.6]).
        //
        // [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
        if let Some(agent_state) = self.agent_state() {
            create(&agent_state, "the agent state directory")?;
            self.link_shares(&agent_state)?;
        }
        if self
            .areas
            .iter()
            .any(|planned| planned.area == Area::Ephemeral {})
        {
            provisioned.removed.push(self.ephemeral());
        }
        for planned in &self.areas {
            create(&self.path(planned), &format!("area {}", planned.from()))?;
        }
        Ok(provisioned)
    }
}

impl Layout {
    /// Make each share entry visible inside `agent_state`, by reference: a symlink named for the
    /// entry, pointing at the real path, which [`Layout::shares`] has granted read-only. Rewritten
    /// on every launch, so a policy edit shows up at the next one.
    ///
    /// A share entry whose name is already taken by something the agent itself wrote is
    /// `refusal.state.collision`: playpen never deletes the agent's own state to make room.
    fn link_shares(&self, agent_state: &Path) -> Result<(), Refusal> {
        for (from, entry, source) in self.shared() {
            // Sourceless entries have already refused in `shares`, which runs at step 6.
            let Some(source) = source else { continue };
            let at = agent_state.join(entry);
            let io = |e: std::io::Error| {
                Refusal::new(
                    Code::StateIo,
                    format!("{from}: cannot share {entry:?} at {}: {e}", at.display()),
                )
            };
            match at.symlink_metadata() {
                // playpen's own link from a previous launch: repointed, in case the policy moved.
                Ok(meta) if meta.file_type().is_symlink() => {
                    std::fs::remove_file(&at).map_err(io)?;
                }
                Ok(_) => {
                    return Err(Refusal::new(
                        Code::StateCollision,
                        format!(
                            "{from}: share entry {entry:?} collides with the agent's own {}, \
                             which playpen will not replace",
                            at.display()
                        ),
                    ));
                }
                Err(_) => {}
            }
            std::os::unix::fs::symlink(&source, &at).map_err(io)?;
        }
        Ok(())
    }
}

/// Whether `name` is exactly one ordinary path component: not empty, not absolute, not `.` or
/// `..`, and holding no separator.
fn one_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

/// A run's provisioned state, for as long as the run lasts.
#[derive(Debug)]
pub struct Provisioned {
    /// Removed at teardown: the run's own, which nothing after it can refer to.
    removed: Vec<PathBuf>,
    /// The lock file of every `exclusive` area, held for as long as this value exists. Opened
    /// close-on-exec, and the child closes every descriptor above 2 besides, so the lock stays
    /// the supervisor's.
    claims: Vec<File>,
}

impl Drop for Provisioned {
    fn drop(&mut self) {
        // No teardown failure changes the exit status ([spec §4.2]).
        //
        // [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
        for path in &self.removed {
            let _ = std::fs::remove_dir_all(path);
        }
        // Cleared while still held, so a lock file never names a run that has ended in good order.
        for claim in &self.claims {
            let _ = claim.set_len(0);
        }
    }
}

/// Who holds a lock file: the run id it holds, or a sentence saying it cannot be read.
fn holder(file: &mut File) -> String {
    let mut id = String::new();
    match file
        .read_to_string(&mut id)
        .ok()
        .and_then(|_| RunId::parse(id.trim()))
    {
        Some(id) => format!("run {id}"),
        None => "a run whose id is not written yet".into(),
    }
}

/// `name` as one path component of its own. A workspace or area name is any string, and the
/// path it lands on is granted read-write and exempt from the reachability check, so `..` or a
/// `/` in a name must never climb out of where playpen put it. Every byte outside
/// `[A-Za-z0-9_.-]` is percent-encoded, as is a leading `.`, and the empty name is `%`, which no
/// encoding produces.
fn component(name: &str) -> String {
    if name.is_empty() {
        return "%".into();
    }
    let mut out = String::with_capacity(name.len());
    for (i, byte) in name.bytes().enumerate() {
        let plain =
            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' || (byte == b'.' && i > 0);
        if plain {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Create the directory `path`, and its parents, owner-only.
fn create(path: &Path, what: &str) -> Result<(), Refusal> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| {
            Refusal::new(
                Code::StateIo,
                format!("cannot create {what} {}: {e}", path.display()),
            )
        })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn policy(areas: serde_json::Value) -> Policy {
        let text = serde_json::json!({
            "version": 1,
            "workspaces": {
                "w": {"roots": [], "areas": areas},
                "unselected": {"roots": [], "areas": {"x": {"lifetime": "ephemeral"}}},
            },
            "profiles": {
                "p": {"workspaces": ["w"], "toolchain": []},
                // A second profile over the same workspace: it shares the work and not the
                // agent's history ([ADR 0021]).
                "q": {"workspaces": ["w"], "toolchain": []},
            },
        });
        Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses")
    }

    fn claude() -> &'static Kind {
        crate::kind::require("claude").expect("a known kind")
    }

    fn layout_of(state: &Path, policy: &Policy) -> Layout {
        layout_named(state, policy, "p")
    }

    fn layout_named(state: &Path, policy: &Policy, profile: &str) -> Layout {
        let id = RunId::allocate().expect("id");
        Layout::new(
            state,
            &id,
            policy,
            profile,
            &policy.profiles[profile],
            claude(),
        )
    }

    fn layout(state: &Path) -> Layout {
        layout_of(state, &policy(serde_json::json!({})))
    }

    fn area<'a>(grants: &'a [PathGrant], from: &str) -> &'a PathGrant {
        grants
            .iter()
            .find(|grant| grant.from == from)
            .unwrap_or_else(|| panic!("no grant from {from} in {grants:?}"))
    }

    #[test]
    fn the_scratch_is_created_owner_only_and_removed_at_teardown() {
        let state = tempfile::TempDir::new().expect("state");
        let layout = layout(state.path());
        let provisioned = layout.provision().expect("provisioned");
        let scratch = layout.scratch();
        let meta = std::fs::metadata(&scratch).expect("the scratch exists");
        assert!(meta.is_dir());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        std::fs::write(scratch.join("left-behind"), "x").expect("writable");
        drop(provisioned);
        assert!(!scratch.exists(), "the scratch outlived its run");
    }

    #[test]
    fn each_run_gets_its_own_scratch() {
        let state = Path::new("/state");
        assert_ne!(layout(state).scratch(), layout(state).scratch());
    }

    /// Derived from the state directory, so exempt from the reachability check (ADR 0027).
    #[test]
    fn the_scratch_is_granted_read_write_as_derived_state() {
        let layout = layout(Path::new("/state"));
        let grants = layout.grants();
        assert_eq!(
            area(&grants, FROM_SCRATCH),
            &PathGrant {
                path: layout.scratch(),
                access: Access::ReadWrite,
                scope: Scope::Subtree,
                from: FROM_SCRATCH.into(),
                state_derived: true,
            }
        );
        assert!(crate::record::refuse_if_reachable(Some(Path::new("/state")), &grants).is_ok());
    }

    #[test]
    fn a_scratch_that_cannot_be_created_is_refused() {
        let state = tempfile::TempDir::new().expect("state");
        // A file where the scratch directory's parent should be.
        std::fs::write(state.path().join(SCRATCH), "").expect("plant");
        let refusal = layout(state.path()).provision().expect_err("refused");
        assert_eq!(refusal.code, Code::StateIo);
        assert!(refusal.message().contains("run scratch"), "{refusal}");
    }

    #[test]
    fn explain_names_no_run() {
        let policy = policy(serde_json::json!({}));
        let layout = Layout::unlaunched(
            Path::new("/state"),
            &policy,
            "p",
            &policy.profiles["p"],
            None,
        );
        assert_eq!(layout.scratch(), Path::new("/state/scratch/<run>"));
    }

    #[test]
    fn an_ephemeral_area_is_granted_read_write_keyed_by_run() {
        let policy = policy(serde_json::json!({"t": {"lifetime": "ephemeral"}}));
        let state = Path::new("/state");
        let (first, second) = (layout_of(state, &policy), layout_of(state, &policy));
        let grants = first.grants();
        let grant = area(&grants, "workspace:w.areas.t");
        assert_eq!(grant.access, Access::ReadWrite);
        assert_eq!(grant.scope, Scope::Subtree);
        assert!(grant.state_derived);
        assert!(grant.path.starts_with(state));
        assert_ne!(
            grant.path,
            area(&second.grants(), "workspace:w.areas.t").path,
            "two runs share an ephemeral area"
        );
        assert!(
            !grants
                .iter()
                .any(|g| g.from.starts_with("workspace:unselected")),
            "only the selected workspaces' areas are provisioned: {grants:?}"
        );
    }

    #[test]
    fn an_ephemeral_area_exists_for_the_run_and_is_removed_at_teardown() {
        let state = tempfile::TempDir::new().expect("state");
        let policy = policy(serde_json::json!({"t": {"lifetime": "ephemeral"}}));
        let layout = layout_of(state.path(), &policy);
        let provisioned = layout.provision().expect("provisioned");
        let path = area(&layout.grants(), "workspace:w.areas.t").path.clone();
        assert!(path.is_dir(), "{path:?}");
        std::fs::write(path.join("built"), "x").expect("writable");
        drop(provisioned);
        assert!(!path.exists(), "the area outlived its run");
        assert!(
            !state
                .path()
                .join(AREAS)
                .join(EPHEMERAL)
                .read_dir()
                .expect("dir")
                .any(|_| true),
            "the run's directory of ephemeral areas outlived it"
        );
    }

    #[test]
    fn an_area_that_cannot_be_created_is_refused() {
        let state = tempfile::TempDir::new().expect("state");
        std::fs::write(state.path().join(AREAS), "").expect("plant");
        let policy = policy(serde_json::json!({"t": {"lifetime": "ephemeral"}}));
        let refusal = layout_of(state.path(), &policy)
            .provision()
            .expect_err("refused");
        assert_eq!(refusal.code, Code::StateIo);
        assert!(
            refusal.message().contains("workspace:w.areas.t"),
            "{refusal}"
        );
    }

    fn persistent(concurrency: Option<&str>) -> Policy {
        let mut area = serde_json::json!({"lifetime": "persistent"});
        if let Some(concurrency) = concurrency {
            area["concurrency"] = concurrency.into();
        }
        policy(serde_json::json!({"landing": area}))
    }

    #[test]
    fn a_persistent_area_survives_its_run_and_is_found_by_the_next() {
        let state = tempfile::TempDir::new().expect("state");
        let policy = persistent(Some("shared"));
        let first = layout_of(state.path(), &policy);
        let path = area(&first.grants(), "workspace:w.areas.landing")
            .path
            .clone();
        let provisioned = first.provision().expect("provisioned");
        std::fs::write(path.join("cloned"), "x").expect("writable");
        drop(provisioned);
        assert!(
            path.join("cloned").exists(),
            "playpen removed a persistent area"
        );
        let second = layout_of(state.path(), &policy);
        assert_eq!(
            area(&second.grants(), "workspace:w.areas.landing").path,
            path
        );
    }

    /// `exclusive` is the default: a held area refuses at once, naming the run holding it.
    #[test]
    fn a_held_exclusive_area_refuses_naming_its_holder_until_released() {
        let state = tempfile::TempDir::new().expect("state");
        for concurrency in [None, Some("exclusive")] {
            let policy = persistent(concurrency);
            let holder = layout_of(state.path(), &policy);
            let held = holder.provision().expect("the first run claims it");
            let refusal = layout_of(state.path(), &policy)
                .provision()
                .expect_err("the second run is refused");
            assert_eq!(refusal.code, Code::AreaBusy, "{concurrency:?}");
            assert!(refusal.message().contains(&holder.run), "{refusal}");
            assert!(
                refusal.message().contains("workspace:w.areas.landing"),
                "{refusal}"
            );
            drop(held);
            let _again = layout_of(state.path(), &policy)
                .provision()
                .expect("released with its run");
        }
    }

    /// A lock file never names a run that ended in good order.
    #[test]
    fn a_released_claim_names_nobody() {
        let state = tempfile::TempDir::new().expect("state");
        let policy = persistent(None);
        let layout = layout_of(state.path(), &policy);
        let lock = layout.lock(&layout.areas[0]);
        let held = layout.provision().expect("held");
        assert_eq!(std::fs::read_to_string(&lock).expect("lock"), layout.run);
        drop(held);
        assert_eq!(std::fs::read_to_string(&lock).expect("lock"), "");
    }

    #[test]
    fn a_refused_claim_creates_nothing_of_its_own() {
        let state = tempfile::TempDir::new().expect("state");
        let policy = persistent(None);
        let _held = layout_of(state.path(), &policy).provision().expect("held");
        let refused = layout_of(state.path(), &policy);
        refused.provision().expect_err("busy");
        assert!(
            !refused.scratch().exists(),
            "a refused run left its scratch"
        );
    }

    #[test]
    fn two_runs_share_a_shared_area_at_once() {
        let state = tempfile::TempDir::new().expect("state");
        let policy = persistent(Some("shared"));
        let (first, second) = (
            layout_of(state.path(), &policy),
            layout_of(state.path(), &policy),
        );
        let _a = first.provision().expect("first");
        let _b = second.provision().expect("second, concurrently");
        assert_eq!(
            area(&first.grants(), "workspace:w.areas.landing").path,
            area(&second.grants(), "workspace:w.areas.landing").path
        );
    }

    /// The lock file is playpen's, outside every path a run is granted.
    #[test]
    fn the_lock_is_outside_every_grant() {
        let policy = persistent(None);
        let layout = layout_of(Path::new("/state"), &policy);
        let planned = &layout.areas[0];
        let lock = layout.lock(planned);
        assert!(lock.starts_with("/state"));
        assert!(
            !layout
                .grants()
                .iter()
                .any(|grant| lock.starts_with(&grant.path)),
            "{lock:?}"
        );
    }

    #[test]
    fn an_area_reference_resolves_to_the_granted_path() {
        let policy = policy(serde_json::json!({"t": {"lifetime": "ephemeral"}}));
        let layout = layout_of(Path::new("/state"), &policy);
        let granted = area(&layout.grants(), "workspace:w.areas.t").path.clone();
        assert_eq!(layout.area(&AreaRef::Area("w/t".into())), Some(granted));
        assert_eq!(layout.area(&AreaRef::Area("unselected/x".into())), None);
    }

    /// Keyed by profile × kind, never by workspace: two profiles sharing a workspace do not share
    /// the agent's history, and one profile's two kinds keep their own ([spec §5.6]).
    ///
    /// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
    #[test]
    fn the_agent_state_directory_is_keyed_by_profile_and_kind() {
        let policy = policy(serde_json::json!({}));
        let state = Path::new("/state");
        let id = RunId::allocate().expect("id");
        let dir = |profile: &str, kind: &str| {
            Layout::new(
                state,
                &id,
                &policy,
                profile,
                &policy.profiles[profile],
                crate::kind::require(kind).expect("a known kind"),
            )
            .agent_state()
            .expect("a kind was stated")
        };
        assert_ne!(dir("p", "claude"), dir("q", "claude"));
        assert_ne!(dir("p", "claude"), dir("p", "omp"));
        assert!(dir("p", "claude").starts_with(state.join(AGENTS)));
    }

    /// Shared by every run of the profile, concurrently: the directory is the agent's, and the
    /// agent handles its own concurrency, so there is no lock and no `concurrency` field.
    #[test]
    fn concurrent_runs_of_one_profile_share_the_agent_state_directory() {
        let state = tempfile::TempDir::new().expect("state");
        let policy = policy(serde_json::json!({}));
        let (first, second) = (
            layout_of(state.path(), &policy),
            layout_of(state.path(), &policy),
        );
        assert_eq!(first.agent_state(), second.agent_state());
        let _a = first.provision().expect("first");
        let _b = second.provision().expect("second, concurrently");
    }

    /// Created on first use and never removed: it holds the transcripts, history and memory that
    /// outlive the run that wrote them. Granted read-write as derived state, so the reachability
    /// check leaves it be (ADR 0027).
    #[test]
    fn the_agent_state_directory_outlives_its_run_and_is_granted_read_write() {
        let state = tempfile::TempDir::new().expect("state");
        let policy = policy(serde_json::json!({}));
        let layout = layout_of(state.path(), &policy);
        let dir = layout.agent_state().expect("a kind was stated");
        let grants = layout.grants();
        let grant = area(&grants, &claude().from());
        assert_eq!(grant.path, dir);
        assert_eq!(grant.access, Access::ReadWrite);
        assert!(grant.state_derived);
        assert!(crate::record::refuse_if_reachable(Some(state.path()), &grants).is_ok());
        let provisioned = layout.provision().expect("provisioned");
        std::fs::write(dir.join("history.jsonl"), "x").expect("writable");
        drop(provisioned);
        assert!(
            dir.join("history.jsonl").exists(),
            "playpen removed the agent state directory"
        );
        // The next run of the same profile finds it.
        assert_eq!(layout_of(state.path(), &policy).agent_state(), Some(dir));
    }

    /// `explain` of a profile names no kind, and a kind is never inferred, so there is no agent
    /// state directory to state and none is granted.
    #[test]
    fn a_layout_with_no_kind_has_no_agent_state_directory() {
        let policy = policy(serde_json::json!({}));
        let layout = Layout::unlaunched(
            Path::new("/state"),
            &policy,
            "p",
            &policy.profiles["p"],
            None,
        );
        assert_eq!(layout.agent_state(), None);
        assert!(
            !layout
                .grants()
                .iter()
                .any(|grant| grant.from.starts_with("kind:")),
            "{:?}",
            layout.grants()
        );
    }

    /// A share entry is one ordinary name: nothing that could climb out of the kind's agent home.
    #[test]
    fn a_share_entry_is_one_ordinary_name() {
        for name in ["CLAUDE.md", "skills", ".credentials.json"] {
            assert!(one_name(name), "{name:?}");
        }
        for name in ["", ".", "..", "a/b", "../x", "/etc/passwd"] {
            assert!(!one_name(name), "{name:?}");
        }
        // A trailing separator names the same one component, which `Path` already normalises.
        assert!(one_name("skills/"));
    }

    /// A policy sharing `share` into profile `p`'s `claude` state directory.
    fn sharing(share: &[&str]) -> Policy {
        let text = serde_json::json!({
            "version": 1,
            "workspaces": {"w": {"roots": []}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [],
                "agent_state": {"claude": {"share": share}},
            }},
        });
        Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses")
    }

    /// playpen never deletes the agent's own state to make room for a share entry: a name the
    /// agent has taken with a file of its own is a collision.
    #[test]
    fn a_share_entry_colliding_with_the_agents_own_file_refuses() {
        let state = tempfile::TempDir::new().expect("state");
        let home = tempfile::TempDir::new().expect("home");
        std::fs::create_dir(home.path().join(".claude")).expect("mkdir");
        std::fs::write(home.path().join(".claude/settings.json"), "{}").expect("seed");
        let policy = sharing(&["settings.json"]);
        let id = RunId::allocate().expect("id");
        let layout = Layout::new(
            state.path(),
            &id,
            &policy,
            "p",
            &policy.profiles["p"],
            claude(),
        )
        .with_home(Some(home.path()));
        // The first launch makes the link, and the second one finds its own and repoints it.
        let first = layout.provision().expect("provisioned");
        drop(first);
        let _again = layout.provision().expect("the link is playpen's own");
        // The agent's own file in its place is not replaced.
        let at = layout
            .agent_state()
            .expect("a kind was stated")
            .join("settings.json");
        std::fs::remove_file(&at).expect("unlink");
        std::fs::write(&at, "the agent's own").expect("plant");
        let refusal = layout.provision().expect_err("refused");
        assert_eq!(refusal.code, Code::StateCollision);
        assert!(
            refusal
                .message()
                .contains("profile:p.agent_state.claude.share[0]"),
            "{refusal}"
        );
    }

    /// A name is one component, whatever it holds: nothing climbs out of where playpen put it.
    #[test]
    fn a_name_never_leaves_its_component() {
        for name in ["", ".", "..", "a/b", "../../x", "%", ".hidden", "a\0b"] {
            let encoded = component(name);
            assert!(!encoded.is_empty() && !encoded.contains('/'), "{name:?}");
            assert!(!encoded.starts_with('.'), "{name:?} -> {encoded:?}");
        }
        assert_eq!(component("cargo-cache.v2_x"), "cargo-cache.v2_x");
        assert_ne!(component("a/b"), component("a%2Fb"));
    }
}
