//! From a selected profile to the boundary it builds, and the resolved form that states it
//! ([spec §10.4]).
//!
//! The resolved form is a different object from the policy, not a unioned one: it speaks
//! enforcement vocabulary — absolute paths with access classes, a network mode — and holds no
//! workspaces, lifetimes or profiles beyond the selection that chose it. Every entry carries a
//! `from:` naming its authored source, the only bridge back to the policy.
//!
//! `run` launches from [`capabilities`] and `explain` renders [`Resolved`] built from the same
//! function, so what `explain` shows is what a launch would grant, never a second reading of
//! the policy.
//!
//! [spec §10.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#104-the-resolved-form

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::{Access, CapabilitySet, Class, PathDenial, PathGrant, Scope};
use crate::code::Code;
use crate::environment::{self, Value, Var};
use crate::floor::floor;
use crate::kind::Kind;
use crate::policy::{Policy, Profile};
use crate::provision::{self, Layout};
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
            grants.extend(link(&root.path, &from)?);
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

/// The kernel's own bound on links followed in one lookup (`MAXSYMLINKS` on macOS, Linux's is
/// the same).
const MAX_LINKS: usize = 40;

/// The grants on `named` and every link after it, where `named` is a symlink: read-only, each link
/// alone ([spec §8.5]). The mechanism enforces on the resolved path, which the caller grants, and
/// Seatbelt checks a path against each link it passes on the way, so every link in a chain is
/// granted. Each is located through its resolved parent, since an ancestor can be a link too and
/// the mechanism sees the real path of the link itself.
///
/// [spec §8.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#85-symlinks
fn link(named: &Path, from: &str) -> Result<Vec<PathGrant>, Refusal> {
    let unavailable = |e: std::io::Error| {
        Refusal::new(
            Code::RootMissing,
            format!("{from}: link {} is unavailable: {e}", named.display()),
        )
    };
    let mut grants = Vec::new();
    let mut current = named.to_owned();
    while current
        .symlink_metadata()
        .is_ok_and(|meta| meta.file_type().is_symlink())
    {
        if grants.len() == MAX_LINKS {
            return Err(unavailable(std::io::Error::other(
                "too many levels of links",
            )));
        }
        let (Some(parent), Some(name)) = (current.parent(), current.file_name()) else {
            break;
        };
        let parent = parent.canonicalize().map_err(unavailable)?;
        let next = std::fs::read_link(&current).map_err(unavailable)?;
        grants.push(PathGrant {
            path: parent.join(name),
            access: Access::Read,
            scope: Scope::Literal,
            from: from.to_owned(),
            state_derived: false,
        });
        // A relative target is relative to the link's own directory.
        current = parent.join(next);
    }
    Ok(grants)
}

/// The toolchain of profile `name`: one read-only root per entry, the link too where an entry names
/// one ([spec §8.3]). Read grants execute, and a toolchain root carries no `mode`, so nothing in it
/// is ever writable.
///
/// [spec §8.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#83-toolchain
pub fn toolchain(name: &str, selected: &Profile) -> Result<Vec<PathGrant>, Refusal> {
    let mut grants = Vec::new();
    for (i, root) in selected.toolchain.iter().enumerate() {
        let from = format!("profile:{name}.toolchain[{i}]");
        let path = root.path.canonicalize().map_err(|e| {
            Refusal::new(
                Code::RootMissing,
                format!(
                    "{from}: toolchain root {} is unavailable: {e}",
                    root.path.display()
                ),
            )
        })?;
        grants.extend(link(&root.path, &from)?);
        grants.push(PathGrant {
            path,
            access: Access::Read,
            scope: Scope::Subtree,
            from,
            state_derived: false,
        });
    }
    Ok(grants)
}

/// The whole capability set a launch of profile `name` applies ([spec §8.1]): the floor, the
/// toolchain, the brought roots, then what playpen provisions for the run under `layout`. `run`
/// applies it and `explain` shows it.
///
/// [spec §8.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#81-shape
pub fn capabilities(
    policy: &Policy,
    name: &str,
    layout: &Layout,
) -> Result<CapabilitySet, Refusal> {
    let Some(selected) = policy.profiles.get(name) else {
        return Err(Refusal::new(
            Code::SelectionUnknownProfile,
            format!("profile {name:?} is not in the policy"),
        ));
    };
    let mut caps = floor()?;
    caps.paths.extend(toolchain(name, selected)?);
    caps.paths.extend(roots(policy, selected)?);
    caps.paths.extend(layout.grants());
    caps.paths.extend(layout.shares()?);
    caps.exclusions = exclusions(policy, name, selected)?;
    Ok(caps)
}

/// The environment a launch of profile `name`, `selected` from `policy`, under `layout` constructs
/// on a host whose own is `host` ([spec §9]). `run` hands it to the child and `explain` shows it.
///
/// playpen's own entries are rendered from typed values — a path playpen provisions, the profile's
/// name — and never by string formatting ([spec §9.2]).
///
/// `kind` is the agent kind this launch states, whose suppression entries are written in every run
/// of it ([spec §12]). `explain` without a shim names no kind, and so shows none of them: there is
/// no kind to infer one from.
///
/// [spec §9]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#9-the-environment
/// [spec §9.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#92-set-entries
/// [spec §12]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#12-the-kind-table
pub fn environment(
    policy: &Policy,
    name: &str,
    selected: &Profile,
    host: &[(OsString, OsString)],
    layout: &Layout,
    kind: Option<&Kind>,
    broker: Option<&crate::proxy::Set>,
) -> Vec<Var> {
    let mut written = vec![
        Var {
            name: environment::TMPDIR.into(),
            value: Value::Written(layout.scratch().into_os_string()),
            from: provision::FROM_SCRATCH.into(),
        },
        Var {
            name: environment::PLAYPEN_ACTIVE.into(),
            value: Value::Written(name.into()),
            from: BUILT_IN.into(),
        },
        Var {
            name: crate::manifest::ENV.into(),
            value: Value::Written(layout.manifest().into_os_string()),
            from: provision::FROM_SCRATCH.into(),
        },
    ];
    // The suppression table only ever *sets*: a guest that ignores it breaks, and does not escape
    // ([ADR 0005]).
    //
    // [ADR 0005]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0005-guest-sandboxes-fail-closed-and-playpen-has-no-browser-mode.md
    if let Some(kind) = kind {
        written.extend(kind.suppression.iter().map(|&(name, value)| Var {
            name: name.into(),
            value: Value::Written(value.into()),
            from: kind.from(),
        }));
        // The private redirect is what points the agent at the profile's own state directory, in
        // place of the real `~/.claude` or `~/.omp`, which nothing grants ([spec §5.6]).
        //
        // [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
        if let Some(agent_state) = layout.agent_state() {
            written.push(Var {
                name: kind.redirect.into(),
                value: Value::Written(agent_state.into_os_string()),
                from: kind.from(),
            });
        }
    }
    // The proxy's entries exist iff a credential route resolved, which is iff a proxy does: with
    // no route there is no proxy and no proxy variable ([spec §6.2]).
    //
    // [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
    if let Some(broker) = broker {
        written.extend(broker.entries().into_iter().map(|(name, value)| Var {
            name: name.into(),
            value: Value::Written(value.into()),
            from: crate::proxy::FROM.into(),
        }));
    }
    environment::construct(policy, name, selected, host, written, |reference| {
        layout.area(reference)
    })
}

/// Every exclusion on the selected profile's roots, brought and toolchain alike, at its resolved
/// path ([spec §8.4]). One that does not exist refuses: an exclusion whose path has gone is a leak
/// that reopened silently.
///
/// [spec §8.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#84-exclusions
pub fn exclusions(
    policy: &Policy,
    name: &str,
    selected: &Profile,
) -> Result<Vec<PathDenial>, Refusal> {
    let brought = selected
        .workspaces
        .iter()
        .filter_map(|w| policy.workspaces.get(&w.value).map(|ws| (&w.value, ws)))
        .flat_map(|(w, workspace)| {
            workspace.roots.iter().enumerate().map(move |(i, root)| {
                (format!("workspace:{w}.roots[{i}]"), root.exclude.as_slice())
            })
        });
    let toolchain = selected.toolchain.iter().enumerate().map(|(i, root)| {
        (
            format!("profile:{name}.toolchain[{i}]"),
            root.exclude.as_slice(),
        )
    });
    let mut denials = Vec::new();
    for (root, exclude) in toolchain.chain(brought) {
        for (j, exclusion) in exclude.iter().enumerate() {
            let from = format!("{root}.exclude[{j}]");
            let path = exclusion.path.canonicalize().map_err(|e| {
                Refusal::new(
                    Code::ExclusionMissing,
                    format!(
                        "{from}: exclusion {} is unavailable: {e}",
                        exclusion.path.display()
                    ),
                )
            })?;
            let classes = match &exclusion.classes {
                Some(classes) => classes.iter().map(|&class| class.into()).collect(),
                None => Class::ALL.to_vec(),
            };
            denials.push(PathDenial {
                path,
                classes,
                from,
            });
        }
    }
    Ok(denials)
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
    /// Subtracted from `paths`: these classes are denied at and beneath each path. Stated here,
    /// to the operator, and never inward ([spec §8.4]).
    ///
    /// [spec §8.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#84-exclusions
    pub exclusions: Vec<ResolvedExclusion>,
    /// macOS Mach services the child may look up; every other service is denied.
    pub mach_services: Vec<ResolvedService>,
    pub network: ResolvedNetwork,
    /// The constructed environment, by name ([spec §9.3]): outward only, since the agent can read
    /// its own `environ`.
    ///
    /// [spec §9.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#93-inward-and-outward
    pub env: Vec<ResolvedVar>,
    /// The argv a shim injects ahead of the caller's: the target it resolved, then each literal
    /// flag ([spec §11.3]). Empty where no shim was named. Shown outward only, and never projected
    /// inward — the manifest omits it, because the agent already holds its own argv.
    ///
    /// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
    #[serde(default)]
    pub argv: Vec<InjectedArg>,
}

/// One token a shim puts in front of the caller's argv, with where it was written. playpen reads
/// none of them: a flag can make the agent work or not work, and can never move the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InjectedArg {
    pub value: String,
    pub from: String,
}

/// One variable of the constructed environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedVar {
    pub name: String,
    /// What playpen or the policy wrote, shown lossily where it is not UTF-8. `null` for a name
    /// passed through from the host, whose value playpen never inspects, and so never states.
    pub value: Option<String>,
    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedPath {
    pub path: PathBuf,
    pub access: Access,
    pub scope: Scope,
    pub from: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedExclusion {
    pub path: PathBuf,
    pub classes: Vec<Class>,
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

/// The provenance of what no policy authors and no host decides: the network mode, which is the
/// same for every boundary, and `PLAYPEN_ACTIVE`.
pub const BUILT_IN: &str = "built-in";

impl Resolved {
    /// The resolved form of `caps` and `env`, selected by `selection` as `profile` from the policy
    /// at `policy`.
    pub fn new(
        policy: PathBuf,
        selection: Trace,
        profile: String,
        caps: &CapabilitySet,
        env: &[Var],
    ) -> Self {
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
            exclusions: caps
                .exclusions
                .iter()
                .map(|denial| ResolvedExclusion {
                    path: denial.path.clone(),
                    classes: denial.classes.clone(),
                    from: denial.from.clone(),
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
            env: env
                .iter()
                .map(|var| ResolvedVar {
                    name: var.name.clone(),
                    value: match &var.value {
                        Value::Inherited(_) => None,
                        Value::Written(value) => Some(value.to_string_lossy().into_owned()),
                    },
                    from: var.from.clone(),
                })
                .collect(),
            argv: Vec::new(),
        }
    }

    /// This resolved form with the argv a shim injects. Separate from [`Resolved::new`] because
    /// the capability set and the environment are what a launch resolves; the injected argv is
    /// what the shim front-end put in front of it, and only `explain --shim` has one.
    #[must_use]
    pub fn with_argv(mut self, argv: Vec<InjectedArg>) -> Self {
        self.argv = argv;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(root: &Path) -> Policy {
        let text = serde_json::json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": root, "mode": "readwrite"}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        });
        Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses")
    }

    fn roots_of(root: &Path) -> Vec<PathGrant> {
        let policy = policy(root);
        roots(&policy, &policy.profiles["p"]).expect("resolves")
    }

    #[test]
    fn a_root_is_granted_at_its_resolved_path() {
        let dir = tempfile::TempDir::new().expect("root");
        let grants = roots_of(dir.path());
        let resolved = dir.path().canonicalize().expect("canonical");
        assert_eq!(grants.len(), 1, "{grants:?}");
        assert_eq!(grants[0].path, resolved);
        assert_eq!(grants[0].access, Access::ReadWrite);
        assert_eq!(grants[0].scope, Scope::Subtree);
        assert_eq!(grants[0].from, "workspace:w.roots[0]");
    }

    /// The link itself is granted read-only, alone; its target at the root's mode, as a subtree.
    #[test]
    fn a_root_named_by_a_link_grants_the_link_and_its_target() {
        let target = tempfile::TempDir::new().expect("target");
        let links = tempfile::TempDir::new().expect("links");
        let link = links.path().join("current");
        std::os::unix::fs::symlink(target.path(), &link).expect("symlink");
        let grants = roots_of(&link);
        let resolved = target.path().canonicalize().expect("canonical");
        let named = links
            .path()
            .canonicalize()
            .expect("canonical")
            .join("current");
        assert_eq!(grants.len(), 2, "{grants:?}");
        assert!(grants.iter().any(|g| g.path == resolved
            && g.access == Access::ReadWrite
            && g.scope == Scope::Subtree));
        assert!(
            grants
                .iter()
                .any(|g| g.path == named && g.access == Access::Read && g.scope == Scope::Literal)
        );
        assert!(grants.iter().all(|g| g.from == "workspace:w.roots[0]"));
    }

    /// Seatbelt checks a path against every link it passes, so each link in a chain is granted.
    #[test]
    fn a_root_named_through_a_chain_of_links_grants_every_link() {
        let target = tempfile::TempDir::new().expect("target");
        let links = tempfile::TempDir::new().expect("links");
        let (first, second) = (links.path().join("first"), links.path().join("second"));
        std::os::unix::fs::symlink(target.path(), &second).expect("symlink");
        std::os::unix::fs::symlink(&second, &first).expect("symlink");
        let grants = roots_of(&first);
        let dir = links.path().canonicalize().expect("canonical");
        let literal: Vec<_> = grants
            .iter()
            .filter(|g| g.scope == Scope::Literal)
            .map(|g| g.path.clone())
            .collect();
        assert_eq!(literal, [dir.join("first"), dir.join("second")]);
        assert_eq!(grants.len(), 3, "{grants:?}");
    }

    fn with_toolchain(toolchain: &[&Path]) -> Policy {
        let toolchain: Vec<_> = toolchain
            .iter()
            .map(|path| serde_json::json!({"path": path}))
            .collect();
        let text = serde_json::json!({
            "version": 1,
            "profiles": {"p": {"workspaces": [], "toolchain": toolchain}},
        });
        Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses")
    }

    /// Toolchain roots are read and execute only, each with its own provenance ([spec §8.3]).
    ///
    /// [spec §8.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#83-toolchain
    #[test]
    fn toolchain_roots_are_read_only_with_provenance() {
        let first = tempfile::TempDir::new().expect("first");
        let second = tempfile::TempDir::new().expect("second");
        let policy = with_toolchain(&[first.path(), second.path()]);
        let grants = toolchain("p", &policy.profiles["p"]).expect("resolves");
        let expected: Vec<_> = [&first, &second]
            .iter()
            .enumerate()
            .map(|(i, dir)| PathGrant {
                path: dir.path().canonicalize().expect("canonical"),
                access: Access::Read,
                scope: Scope::Subtree,
                from: format!("profile:p.toolchain[{i}]"),
                state_derived: false,
            })
            .collect();
        assert_eq!(grants, expected);
    }

    /// A keg list names stable per-package links, resolved at launch: link and target are both
    /// granted.
    #[test]
    fn a_toolchain_root_named_by_a_link_grants_the_link_and_its_target() {
        let keg = tempfile::TempDir::new().expect("keg");
        let opt = tempfile::TempDir::new().expect("opt");
        let link = opt.path().join("git");
        std::os::unix::fs::symlink(keg.path(), &link).expect("symlink");
        let policy = with_toolchain(&[&link]);
        let grants = toolchain("p", &policy.profiles["p"]).expect("resolves");
        assert_eq!(grants.len(), 2, "{grants:?}");
        assert!(grants.iter().all(|g| g.access == Access::Read));
        assert!(
            grants
                .iter()
                .any(|g| g.scope == Scope::Literal && g.path.ends_with("git"))
        );
    }

    #[test]
    fn a_missing_toolchain_root_is_refused() {
        let dir = tempfile::TempDir::new().expect("dir");
        let policy = with_toolchain(&[&dir.path().join("gone")]);
        let refusal = toolchain("p", &policy.profiles["p"]).expect_err("refused");
        assert_eq!(refusal.code, Code::RootMissing);
        assert!(
            refusal.message().contains("profile:p.toolchain[0]"),
            "{refusal}"
        );
    }

    /// The capability set is the floor, the toolchain and the brought roots: what `run` applies
    /// and `explain` shows.
    #[test]
    fn the_capability_set_holds_the_toolchain() {
        let tool = tempfile::TempDir::new().expect("tool");
        let policy = with_toolchain(&[tool.path()]);
        let caps = capabilities(
            &policy,
            "p",
            &Layout::unlaunched(
                Path::new("/state"),
                &policy,
                "p",
                &policy.profiles["p"],
                None,
            ),
        )
        .expect("resolves");
        assert!(caps.paths.iter().any(|g| g.from == "floor"));
        assert!(
            caps.paths
                .iter()
                .any(|g| g.from == "profile:p.toolchain[0]")
        );
    }

    fn excluding(root: &Path, exclude: serde_json::Value) -> Policy {
        let text = serde_json::json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": root, "mode": "readwrite", "exclude": exclude}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        });
        Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses")
    }

    /// An exclusion is subtracted at its resolved path, for the classes it names; none named is
    /// all three ([spec §8.4]).
    ///
    /// [spec §8.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#84-exclusions
    #[test]
    fn exclusions_are_subtracted_for_their_classes() {
        let root = tempfile::TempDir::new().expect("root");
        for dir in ["secrets", "hooks"] {
            std::fs::create_dir(root.path().join(dir)).expect("mkdir");
        }
        let policy = excluding(
            root.path(),
            serde_json::json!([
                {"path": root.path().join("secrets")},
                {"path": root.path().join("hooks"), "classes": ["write"]},
            ]),
        );
        let caps = capabilities(
            &policy,
            "p",
            &Layout::unlaunched(
                Path::new("/state"),
                &policy,
                "p",
                &policy.profiles["p"],
                None,
            ),
        )
        .expect("resolves");
        let resolved = root.path().canonicalize().expect("canonical");
        assert_eq!(
            caps.exclusions,
            [
                PathDenial {
                    path: resolved.join("secrets"),
                    classes: Class::ALL.to_vec(),
                    from: "workspace:w.roots[0].exclude[0]".into(),
                },
                PathDenial {
                    path: resolved.join("hooks"),
                    classes: vec![Class::Write],
                    from: "workspace:w.roots[0].exclude[1]".into(),
                },
            ]
        );
    }

    #[test]
    fn a_missing_exclusion_is_refused() {
        let root = tempfile::TempDir::new().expect("root");
        let policy = excluding(
            root.path(),
            serde_json::json!([{"path": root.path().join("gone")}]),
        );
        let refusal = capabilities(
            &policy,
            "p",
            &Layout::unlaunched(
                Path::new("/state"),
                &policy,
                "p",
                &policy.profiles["p"],
                None,
            ),
        )
        .expect_err("refused");
        assert_eq!(refusal.code, Code::ExclusionMissing);
        assert!(
            refusal
                .message()
                .contains("workspace:w.roots[0].exclude[0]"),
            "{refusal}"
        );
    }

    #[test]
    fn a_toolchain_root_carries_its_exclusions() {
        let tool = tempfile::TempDir::new().expect("tool");
        std::fs::create_dir(tool.path().join("etc")).expect("mkdir");
        let text = serde_json::json!({
            "version": 1,
            "profiles": {"p": {"workspaces": [], "toolchain": [
                {"path": tool.path(), "exclude": [{"path": tool.path().join("etc")}]},
            ]}},
        });
        let policy = Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses");
        let caps = capabilities(
            &policy,
            "p",
            &Layout::unlaunched(
                Path::new("/state"),
                &policy,
                "p",
                &policy.profiles["p"],
                None,
            ),
        )
        .expect("resolves");
        assert_eq!(caps.exclusions.len(), 1, "{:?}", caps.exclusions);
        assert_eq!(caps.exclusions[0].from, "profile:p.toolchain[0].exclude[0]");
    }
}
