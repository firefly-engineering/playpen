//! What playpen provisions for a run under its own state directory: the **run scratch**
//! ([spec §5.7]) and the selected workspaces' **provisioned areas** ([spec §5.4]). Every path here
//! is derived from the state directory, so it is exempt from the state-reachability check
//! ([ADR 0027]) and granted read-write.
//!
//! The paths are a pure function of the state directory, the run and the policy ([`Layout`]), so
//! `explain` states them without creating anything; `run` creates them at launch steps 8 and 9
//! and removes what is the run's own at teardown ([spec §4.2]).
//!
//! [spec §5.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#57-run-scratch
//! [spec §5.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#54-provisioned-areas
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
//! [ADR 0027]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md

use std::fmt::Write as _;
use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::capability::{Access, PathGrant, Scope};
use crate::code::Code;
use crate::policy::{Area, Policy, Profile};
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

/// Where a run's provisioned state lives.
#[derive(Debug, Clone)]
pub struct Layout {
    state: PathBuf,
    run: String,
    areas: Vec<Planned>,
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
    /// The layout of run `run` of profile `selected` from `policy`, under the state directory
    /// `state`, which should be resolved: the mechanism enforces on real paths.
    pub fn new(state: &Path, run: &RunId, policy: &Policy, selected: &Profile) -> Self {
        Self::of(state, run.to_string(), policy, selected)
    }

    /// The layout `explain` states: any run's, under `state`.
    pub fn unlaunched(state: &Path, policy: &Policy, selected: &Profile) -> Self {
        Self::of(state, UNLAUNCHED.into(), policy, selected)
    }

    fn of(state: &Path, run: String, policy: &Policy, selected: &Profile) -> Self {
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
        Self {
            state: state.to_owned(),
            run,
            areas,
        }
    }

    /// The run scratch: the run's own, and nobody else's.
    pub fn scratch(&self) -> PathBuf {
        self.state.join(SCRATCH).join(&self.run)
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
        let mut provisioned = Provisioned {
            removed: Vec::new(),
        };
        let scratch = self.scratch();
        create(&scratch, "the run scratch")?;
        provisioned.removed.push(scratch);
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

/// A run's provisioned state, for as long as the run lasts.
#[derive(Debug)]
pub struct Provisioned {
    /// Removed at teardown: the run's own, which nothing after it can refer to.
    removed: Vec<PathBuf>,
}

impl Drop for Provisioned {
    fn drop(&mut self) {
        // No teardown failure changes the exit status ([spec §4.2]).
        //
        // [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
        for path in &self.removed {
            let _ = std::fs::remove_dir_all(path);
        }
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
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        });
        Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses")
    }

    fn layout_of(state: &Path, policy: &Policy) -> Layout {
        let id = RunId::allocate().expect("id");
        Layout::new(state, &id, policy, &policy.profiles["p"])
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
            grants,
            [PathGrant {
                path: layout.scratch(),
                access: Access::ReadWrite,
                scope: Scope::Subtree,
                from: "run-scratch".into(),
                state_derived: true,
            }]
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
        let layout = Layout::unlaunched(Path::new("/state"), &policy, &policy.profiles["p"]);
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
