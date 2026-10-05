//! The manifest ([spec §13]): **a generated projection, and playpen states facts, never
//! instructions** ([ADR 0011]).
//!
//! It is a JSON file in the run scratch, named by [`ENV`], written on every run even when nothing
//! is provisioned. It is derived from the same resolution pass as the capability set: the
//! capability set faces outward at the kernel, the manifest inward at the agent.
//!
//! It **describes the boundary and never constitutes it.** It sits in writable scratch, so an
//! agent can rewrite it; nothing moves when it does, and the agent has lied only to itself.
//!
//! What it omits is as deliberate as what it states ([spec §13.2]): exclusions, the environment,
//! the injected argv, the selection trace and all policy provenance. The first maps what is worth
//! attacking; the rest the agent either already holds or has no use for.
//!
//! [spec §13]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#13-the-manifest
//! [spec §13.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#132-content
//! [ADR 0011]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0011-the-manifest-is-a-generated-projection-and-playpen-states-facts-never-instructions.md

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::code::Code;
use crate::kind::Kind;
use crate::policy::{self, Policy, Profile};
use crate::provision::Layout;
use crate::refusal::Refusal;

/// The manifest's own version. Additive changes bump nothing; a removal or a retype bumps this.
pub const VERSION: u32 = 1;

/// The set entry that names the manifest ([spec §9.2]).
///
/// [spec §9.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#92-set-entries
pub const ENV: &str = "PLAYPEN_MANIFEST";

/// What the manifest is called inside the run scratch.
pub const FILE: &str = "manifest.json";

/// The boundary as the agent is told it ([spec §13.2]).
///
/// [spec §13.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#132-content
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Manifest {
    pub manifest_version: u32,
    /// The layout, in workspace vocabulary: the agent reads about its work the way the operator
    /// declared it, not as a flat list of paths.
    pub workspaces: Vec<Workspace>,
    /// The agent's own state directory, which the kind's redirect also names.
    pub agent_state: PathBuf,
    /// The run's writable scratch, which `TMPDIR` also names. It holds this file.
    pub run_scratch: PathBuf,
    pub network: Network,
    pub failure: Failure,
}

/// One selected workspace, with everything it reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Workspace {
    pub name: String,
    pub roots: Vec<Root>,
    pub areas: Vec<Area>,
    /// Which remote repositories this workspace's work may reach, where it declares any. Never
    /// unioned across a profile's workspaces.
    pub forge: Option<Forge>,
}

/// A brought root at the mode it is granted. Exclusions are **not** stated: they map what is
/// worth attacking ([spec §13.2]).
///
/// [spec §13.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#132-content
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Root {
    pub path: PathBuf,
    pub mode: Mode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Read and execute. A readable path is an executable one.
    Read,
    Readwrite,
}

impl From<policy::Mode> for Mode {
    fn from(mode: policy::Mode) -> Self {
        match mode {
            policy::Mode::Read => Self::Read,
            policy::Mode::Readwrite => Self::Readwrite,
        }
    }
}

/// A provisioned area: what it is for is its name, and how long it lasts is its lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Area {
    pub name: String,
    pub lifetime: Lifetime,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Lifetime {
    /// Removed when this run ends.
    Ephemeral,
    /// Kept for the next run of the same workspace.
    Persistent,
}

/// A workspace's forge scope: exactly one of an org or a list of repositories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Forge {
    Org(String),
    Repos(Vec<String>),
}

/// What the agent can know about the network ([spec §6.1], [spec §13.2]). There is no egress
/// setting and no host list to state, so what is stated is the one consequence that matters: the
/// proxy is not the only way out, and a routed destination is authenticated *only* for requests
/// sent through it.
///
/// [spec §6.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#61-what-is-not-confined
/// [spec §13.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#132-content
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Network {
    pub egress: Egress,
    /// Credential routes, each with its destination and delivery variable. Empty where the
    /// profile resolves none, and then there is no proxy at all.
    pub routes: Vec<Route>,
}

/// playpen confines no network traffic: the one mode there is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Egress {
    /// Every destination is reachable, by any means, proxy or not.
    Unconfined,
}

/// One credential route, as the agent is told it: where it goes and which variable carries the
/// phantom. Never the secret, and never the minter that made it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Route {
    pub host: String,
    pub path_prefix: String,
    /// The variable the phantom is delivered in.
    pub delivery_env: String,
    /// The endpoint rule sets this route carries, by name, with their rules. Empty means
    /// unrestricted.
    pub endpoints: Vec<RuleSet>,
}

/// A named, allow-only rule set ([spec §7.6]).
///
/// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RuleSet {
    pub name: String,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Rule {
    pub method: String,
    pub path: String,
}

/// How to read a failure ([spec §13.2]). An agent that cannot tell a denial from an absence
/// retries the wrong thing; this is the half the kernel cannot tell it.
///
/// [spec §13.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#132-content
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Failure {
    /// The errno names that mean the boundary refused, on this platform.
    pub denial_errnos: Vec<String>,
    /// `ENOENT` means absent, and is never a denial.
    pub enoent_means_absent: bool,
    /// The broker's refusal vocabulary, stated **only where a denial can fire**: where some route
    /// carries an endpoint rule set. `null` everywhere else, because a vocabulary for a denial
    /// that cannot happen is noise the agent would reason from.
    pub broker_denial: Option<BrokerDenial>,
    /// The boundary is fixed for the whole session: nothing the agent does widens it, and a retry
    /// after a denial gets the same denial.
    pub boundary_fixed_for_the_session: bool,
}

/// The shape of the one denial the broker makes ([spec §6.4]).
///
/// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BrokerDenial {
    pub status: u16,
    pub header: String,
    pub code: String,
}

/// The errno names a denial arrives as on this platform ([spec §15.2]). `ENOENT` is never one.
///
/// [spec §15.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#152-capability-matrix
#[cfg(target_os = "macos")]
pub const DENIAL_ERRNOS: &[&str] = &["EPERM"];
/// On Linux, `ENOSYS` besides, which is what a dead user-notify supervisor leaves behind.
#[cfg(target_os = "linux")]
pub const DENIAL_ERRNOS: &[&str] = &["EACCES", "EXDEV", "EPERM", "ENOSYS"];

/// The header a broker denial carries, and the code in its body.
const DENIED_HEADER: &str = "X-Playpen-Denied";

impl Manifest {
    /// The manifest of a launch of profile `selected` from `policy` as `kind`, under `layout`. A
    /// pure function of the same inputs the capability set is resolved from, so what the agent is
    /// told and what the kernel enforces cannot drift.
    pub fn new(policy: &Policy, selected: &Profile, kind: &Kind, layout: &Layout) -> Self {
        let workspaces = selected
            .workspaces
            .iter()
            .filter_map(|name| {
                let declared = policy.workspaces.get(&name.value)?;
                Some(Workspace {
                    name: name.value.clone(),
                    roots: declared
                        .roots
                        .iter()
                        .map(|root| Root {
                            path: root.path.clone(),
                            mode: root.mode.into(),
                        })
                        .collect(),
                    areas: declared
                        .areas
                        .iter()
                        .filter_map(|(area, declared)| {
                            Some(Area {
                                name: area.clone(),
                                lifetime: match declared {
                                    policy::Area::Ephemeral {} => Lifetime::Ephemeral,
                                    policy::Area::Persistent { .. } => Lifetime::Persistent,
                                },
                                path: layout.area(&policy::AreaRef::Area(format!(
                                    "{}/{area}",
                                    name.value
                                )))?,
                            })
                        })
                        .collect(),
                    forge: declared.forge.as_ref().map(|forge| match forge {
                        policy::Forge::Org(org) => Forge::Org(org.clone()),
                        policy::Forge::Repos(repos) => Forge::Repos(repos.clone()),
                    }),
                })
            })
            .collect();
        Self {
            manifest_version: VERSION,
            workspaces,
            // A launch always states a kind, so a launch always has one.
            agent_state: layout
                .agent_state()
                .unwrap_or_else(|| PathBuf::from(kind.home)),
            run_scratch: layout.scratch(),
            network: Network {
                egress: Egress::Unconfined,
                // Credential routes join the manifest with the route table (#90).
                routes: Vec::new(),
            },
            failure: Failure {
                denial_errnos: DENIAL_ERRNOS.iter().map(|&e| e.to_owned()).collect(),
                enoent_means_absent: true,
                broker_denial: None,
                boundary_fixed_for_the_session: true,
            },
        }
    }

    /// The broker's refusal vocabulary, where some route carries a rule set and a denial can
    /// therefore fire.
    pub fn with_broker_denial(mut self) -> Self {
        self.failure.broker_denial = Some(BrokerDenial {
            status: 403,
            header: DENIED_HEADER.into(),
            code: Code::BrokerEndpointDenied.as_str().into(),
        });
        self
    }

    /// Write the manifest into the run scratch, at the path [`Layout::manifest`] names. Always
    /// called, even when nothing is provisioned: an absent manifest and an empty one say different
    /// things, and only one of them is true.
    pub fn write(&self, at: &Path) -> Result<(), Refusal> {
        let io = |e: std::io::Error| {
            Refusal::new(
                Code::StateIo,
                format!("cannot write the manifest {}: {e}", at.display()),
            )
        };
        let mut text = serde_json::to_string_pretty(self).unwrap_or_else(|e| {
            // A tree of owned values built in memory; serialising it cannot fail.
            unreachable!("the manifest serialises: {e}")
        });
        text.push('\n');
        std::fs::write(at, text).map_err(io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::RunId;

    fn policy(text: serde_json::Value) -> Policy {
        Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses")
    }

    fn manifest_of(policy: &Policy, state: &Path) -> Manifest {
        let kind = crate::kind::require("claude").expect("a known kind");
        let id = RunId::allocate().expect("id");
        let layout = Layout::new(state, &id, policy, "p", &policy.profiles["p"], kind);
        Manifest::new(policy, &policy.profiles["p"], kind, &layout)
    }

    /// Even with nothing provisioned, the manifest is a whole statement: an absent one and an
    /// empty one say different things.
    #[test]
    fn a_profile_with_nothing_provisioned_still_gets_a_whole_manifest() {
        let policy = policy(serde_json::json!({
            "version": 1,
            "profiles": {"p": {"workspaces": [], "toolchain": []}},
        }));
        let manifest = manifest_of(&policy, Path::new("/state"));
        assert_eq!(manifest.manifest_version, VERSION);
        assert_eq!(manifest.workspaces, Vec::new());
        assert_eq!(manifest.network.egress, Egress::Unconfined);
        assert!(manifest.failure.enoent_means_absent);
        assert!(manifest.failure.boundary_fixed_for_the_session);
        assert!(!manifest.failure.denial_errnos.is_empty());
        assert!(
            !manifest
                .failure
                .denial_errnos
                .contains(&"ENOENT".to_owned()),
            "a denial never reads as absence"
        );
        assert_eq!(
            manifest.run_scratch,
            Path::new("/state/scratch").join(manifest.run_scratch.file_name().expect("a run"))
        );
    }

    /// The layout in workspace vocabulary: roots at their modes, each area's name, lifetime and
    /// real path, and the workspace's own forge scope.
    #[test]
    fn it_states_each_workspaces_roots_areas_and_forge_scope() {
        let policy = policy(serde_json::json!({
            "version": 1,
            "workspaces": {
                "work": {
                    "roots": [
                        {"path": "/src/work", "mode": "readwrite"},
                        {"path": "/notes", "mode": "read"},
                    ],
                    "areas": {"landing": {"lifetime": "persistent"}, "target": {"lifetime": "ephemeral"}},
                    "forge": {"org": "firefly-engineering"},
                },
                "unselected": {"roots": [{"path": "/elsewhere", "mode": "read"}]},
            },
            "profiles": {"p": {"workspaces": ["work"], "toolchain": []}},
        }));
        let manifest = manifest_of(&policy, Path::new("/state"));
        assert_eq!(manifest.workspaces.len(), 1, "{:?}", manifest.workspaces);
        let workspace = &manifest.workspaces[0];
        assert_eq!(workspace.name, "work");
        assert_eq!(
            workspace.roots,
            [
                Root {
                    path: "/src/work".into(),
                    mode: Mode::Readwrite
                },
                Root {
                    path: "/notes".into(),
                    mode: Mode::Read
                },
            ]
        );
        assert_eq!(
            workspace.forge,
            Some(Forge::Org("firefly-engineering".into()))
        );
        let areas: Vec<_> = workspace
            .areas
            .iter()
            .map(|area| (area.name.as_str(), area.lifetime))
            .collect();
        assert_eq!(
            areas,
            [
                ("landing", Lifetime::Persistent),
                ("target", Lifetime::Ephemeral)
            ]
        );
        assert!(
            workspace
                .areas
                .iter()
                .all(|area| area.path.starts_with("/state")),
            "{:?}",
            workspace.areas
        );
    }

    /// The manifest never maps what is worth attacking: an exclusion is for the operator, and the
    /// provenance that would name the policy is not the agent's business either.
    #[test]
    fn it_omits_exclusions_provenance_and_the_environment() {
        let policy = policy(serde_json::json!({
            "version": 1,
            "workspaces": {"w": {"roots": [
                {"path": "/src/w", "mode": "readwrite", "exclude": [{"path": "/src/w/private"}]},
            ]}},
            "profiles": {"p": {
                "workspaces": ["w"],
                "toolchain": [{"path": "/nix/store/x"}],
                "env": {"set": {"GIT_AUTHOR_NAME": "agent"}},
            }},
        }));
        let text = serde_json::to_string(&manifest_of(&policy, Path::new("/state"))).expect("JSON");
        for absent in [
            "private",
            "exclude",
            "from",
            "GIT_AUTHOR_NAME",
            "toolchain",
            "selection",
            "/nix/store/x",
        ] {
            assert!(!text.contains(absent), "{absent} is in {text}");
        }
    }

    /// The `403` vocabulary is stated only where a rule set exists, so a denial that cannot fire
    /// is never described.
    #[test]
    fn the_broker_vocabulary_is_stated_only_where_a_denial_can_fire() {
        let policy = policy(serde_json::json!({
            "version": 1,
            "profiles": {"p": {"workspaces": [], "toolchain": []}},
        }));
        let manifest = manifest_of(&policy, Path::new("/state"));
        assert_eq!(manifest.failure.broker_denial, None);
        let denied = manifest.with_broker_denial();
        let denial = denied.failure.broker_denial.expect("a vocabulary");
        assert_eq!(denial.status, 403);
        assert_eq!(denial.header, DENIED_HEADER);
        assert_eq!(denial.code, "broker.endpoint.denied");
    }

    #[test]
    fn it_round_trips_through_its_own_json() {
        let policy = policy(serde_json::json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": "/src/w", "mode": "read"}],
                                 "forge": {"repos": ["a/b", "c/d"]}}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        }));
        let manifest = manifest_of(&policy, Path::new("/state")).with_broker_denial();
        let text = serde_json::to_string(&manifest).expect("JSON");
        assert_eq!(
            serde_json::from_str::<Manifest>(&text).expect("reads back"),
            manifest
        );
    }

    #[test]
    fn it_is_written_where_the_layout_names_it() {
        let state = tempfile::TempDir::new().expect("state");
        let policy = policy(serde_json::json!({
            "version": 1,
            "profiles": {"p": {"workspaces": [], "toolchain": []}},
        }));
        let kind = crate::kind::require("claude").expect("a known kind");
        let id = RunId::allocate().expect("id");
        let layout = Layout::new(state.path(), &id, &policy, "p", &policy.profiles["p"], kind);
        let _provisioned = layout.provision().expect("provisioned");
        let at = layout.manifest();
        Manifest::new(&policy, &policy.profiles["p"], kind, &layout)
            .write(&at)
            .expect("written");
        assert_eq!(at.parent(), Some(layout.scratch().as_path()));
        let text = std::fs::read_to_string(&at).expect("the manifest");
        assert!(text.ends_with('\n'));
        serde_json::from_str::<Manifest>(&text).expect("the manifest is JSON");
    }
}
