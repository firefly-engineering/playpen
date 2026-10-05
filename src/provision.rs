//! What playpen provisions for a run under its own state directory: the **run scratch**
//! ([spec §5.7]). Every path here is derived from the state directory, so it is exempt from the
//! state-reachability check ([ADR 0027]) and granted read-write.
//!
//! The paths are a pure function of the state directory and the run ([`Layout`]), so `explain`
//! states them without creating anything; `run` creates them at launch steps 8 and 9 and removes
//! what is the run's own at teardown ([spec §4.2]).
//!
//! [spec §5.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#57-run-scratch
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
//! [ADR 0027]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md

use std::fs::DirBuilder;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use crate::capability::{Access, PathGrant, Scope};
use crate::code::Code;
use crate::record::RunId;
use crate::refusal::Refusal;

/// The provenance of the run scratch.
pub const FROM_SCRATCH: &str = "run-scratch";

/// What `explain` names the run by, since it launches none: the paths it states are those any run
/// would get, with this in place of the run id.
pub const UNLAUNCHED: &str = "<run>";

/// The directory under the state directory holding one scratch per run.
const SCRATCH: &str = "scratch";

/// Where a run's provisioned state lives.
#[derive(Debug, Clone)]
pub struct Layout {
    state: PathBuf,
    run: String,
}

impl Layout {
    /// The layout of run `run` under the state directory `state`, which should be resolved: the
    /// mechanism enforces on real paths.
    pub fn new(state: &Path, run: &RunId) -> Self {
        Self {
            state: state.to_owned(),
            run: run.to_string(),
        }
    }

    /// The layout `explain` states: any run's, under `state`.
    pub fn unlaunched(state: &Path) -> Self {
        Self {
            state: state.to_owned(),
            run: UNLAUNCHED.into(),
        }
    }

    /// The run scratch: the run's own, and nobody else's.
    pub fn scratch(&self) -> PathBuf {
        self.state.join(SCRATCH).join(&self.run)
    }

    /// The grants a run of this layout holds on what playpen provisions for it.
    pub fn grants(&self) -> Vec<PathGrant> {
        vec![PathGrant {
            path: self.scratch(),
            access: Access::ReadWrite,
            scope: Scope::Subtree,
            from: FROM_SCRATCH.into(),
            state_derived: true,
        }]
    }

    /// Create the run scratch. What was created for the run alone is removed when the returned
    /// value is dropped, which is teardown, and also any refusal after this point. A failure is
    /// `refusal.state.io`.
    pub fn provision(&self) -> Result<Provisioned, Refusal> {
        let scratch = self.scratch();
        create(&scratch, "the run scratch")?;
        Ok(Provisioned {
            removed: vec![scratch],
        })
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

    fn layout(state: &Path) -> Layout {
        Layout::new(state, &RunId::allocate().expect("id"))
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
        let scratch = Layout::unlaunched(Path::new("/state")).scratch();
        assert_eq!(scratch, Path::new("/state/scratch/<run>"));
    }
}
