//! From a selected profile to the boundary it builds, and the resolved form that states it
//! ([spec §10.4]).
//!
//! The resolved form is a different object from the policy, not a unioned one: it speaks
//! enforcement vocabulary — absolute paths with access classes, a network mode — and holds no
//! workspaces, lifetimes or profiles beyond the selection that chose it. Every entry carries a
//! `from:` naming its authored source, the only bridge back to the policy.
//!
//! `run` launches from [`capabilities`]'s parts and `explain` renders [`Resolved`] built from the
//! same function, so what `explain` shows is what a launch would grant, never a second reading of
//! the policy.
//!
//! [spec §10.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#104-the-resolved-form

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::{Access, CapabilitySet, PathGrant, Scope};
use crate::code::Code;
use crate::floor::floor;
use crate::policy::{Policy, Profile};
use crate::refusal::Refusal;
use crate::select::Trace;

/// The selected profile's brought roots, canonicalised, as path grants with provenance. The
/// coherence tier has already refused an undeclared workspace and a relative root.
pub fn roots(policy: &Policy, selected: &Profile) -> Result<Vec<PathGrant>, Refusal> {
    let mut grants = Vec::new();
    for name in selected.workspaces.iter().map(|name| &name.value) {
        let Some(workspace) = policy.workspaces.get(name) else {
            continue;
        };
        for (i, root) in workspace.roots.iter().enumerate() {
            let from = format!("workspace:{name}.roots[{i}]");
            let path = root.path.canonicalize().map_err(|e| {
                Refusal::new(
                    Code::RootMissing,
                    format!("{from}: root {} is unavailable: {e}", root.path.display()),
                )
            })?;
            grants.push(PathGrant {
                path,
                access: root.mode.into(),
                scope: Scope::Subtree,
                from,
                // Policy-declared, so never exempt: a brought root of `~` is exactly the breach
                // the state-reachability check exists to refuse (ADR 0027).
                state_derived: false,
            });
        }
    }
    Ok(grants)
}

/// The whole capability set a launch of `selected` applies: the floor, then the profile's roots.
pub fn capabilities(policy: &Policy, selected: &Profile) -> Result<CapabilitySet, Refusal> {
    let mut caps = floor()?;
    caps.paths.extend(roots(policy, selected)?);
    Ok(caps)
}

/// The resolved form: what `explain --json` prints, and what its human form is rendered from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Resolved {
    /// The policy document the boundary was resolved from.
    pub policy: PathBuf,
    /// How the profile was selected: each step up to the one that selected.
    pub selection: Trace,
    pub profile: String,
    pub paths: Vec<ResolvedPath>,
    /// macOS Mach services the child may look up; every other service is denied.
    pub mach_services: Vec<ResolvedService>,
    pub network: ResolvedNetwork,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedPath {
    pub path: PathBuf,
    pub access: Access,
    pub scope: Scope,
    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedService {
    pub name: String,
    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedNetwork {
    pub mode: NetworkMode,
    pub from: String,
}

/// playpen confines no network traffic ([spec §6.1]): the one mode there is.
///
/// [spec §6.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#61-what-is-not-confined
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    AllowAll,
}

/// The provenance of what no policy authors: the network mode, which is the same for every
/// boundary.
pub const BUILT_IN: &str = "built-in";

impl Resolved {
    /// The resolved form of `caps`, selected by `selection` as `profile` from the policy at `policy`.
    pub fn new(policy: PathBuf, selection: Trace, profile: String, caps: &CapabilitySet) -> Self {
        Self {
            policy,
            selection,
            profile,
            paths: caps
                .paths
                .iter()
                .map(|grant| ResolvedPath {
                    path: grant.path.clone(),
                    access: grant.access,
                    scope: grant.scope,
                    from: grant.from.clone(),
                })
                .collect(),
            mach_services: caps
                .mach_services
                .iter()
                .map(|name| ResolvedService {
                    name: name.clone(),
                    from: crate::floor::FROM.into(),
                })
                .collect(),
            network: ResolvedNetwork {
                mode: NetworkMode::AllowAll,
                from: BUILT_IN.into(),
            },
        }
    }
}
