//! The capability type: playpen's own statement of a boundary, and the only thing a backend
//! receives ([spec §15.1]). It speaks enforcement vocabulary — absolute paths with access classes —
//! and carries no workspaces, profiles or policy names beyond each entry's provenance.
//!
//! [spec §15.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#151-the-backend

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// What a grant allows. Execution follows readability: every readable path is executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    ReadWrite,
}

/// How much of the filesystem a path grant covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// The path and, for a directory, everything beneath it.
    Subtree,
    /// The path itself and nothing beneath it.
    Literal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathGrant {
    pub path: PathBuf,
    pub access: Access,
    pub scope: Scope,
    /// The authored source of this grant (`floor`, `workspace:playpen.roots[0]`, …).
    pub from: String,
    /// Whether playpen **derived** this path from its own state directory, rather than something
    /// having declared a path that happens to lie inside it.
    ///
    /// This is the one exemption from the state-reachability check ([ADR 0027]), and it is
    /// deliberately a property of the grant rather than an enumerated list of tenants: the state
    /// directory is not private in its entirety — agent state directories live inside it and are
    /// granted to the agent by design — so "a granted path inside the state directory" is the
    /// intended arrangement rather than the bug. Derivation is what makes the exemption safe,
    /// because a derived path is inside only because playpen computed it from the directory. A
    /// list would fail open for every tenant nobody remembered to add.
    ///
    /// [ADR 0027]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md
    #[serde(default)]
    pub state_derived: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub paths: Vec<PathGrant>,
    /// macOS Mach services the child may look up; every other service is denied.
    pub mach_services: Vec<String>,
}
