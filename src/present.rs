//! The presentation adapter ([spec §13.3]): the manifest rendered into the idiom the kind reads,
//! at the kind's instruction entry point inside the profile's agent state directory — for
//! `claude`, `$CLAUDE_CONFIG_DIR/CLAUDE.md`.
//!
//! Two rules shape everything here:
//!
//! - **It states facts, never instructions.** It may state what playpen built; it may never state
//!   what the agent should do about it. Prompt fragments tuned per kind are ruled out permanently
//!   ([ADR 0011]).
//! - **Only facts stable across the profile's runs.** The directory is shared by every run of the
//!   profile, so a path that belongs to one run — the run scratch, an ephemeral area — would be
//!   false for every other run reading the same file. Those live in `$PLAYPEN_MANIFEST`, and that
//!   the layout is there is itself one of the facts stated.
//!
//! It is generated from the manifest's data, never hand-written, and carries no compatibility
//! promise. It is written to a temporary file and renamed into place on every launch, so a policy
//! edited during a live run shows up at the next one and never halfway through this one.
//!
//! [spec §13.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#133-presentation
//! [ADR 0011]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0011-the-manifest-is-a-generated-projection-and-playpen-states-facts-never-instructions.md

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::code::Code;
use crate::kind::Kind;
use crate::manifest::{Lifetime, Manifest};
use crate::refusal::Refusal;

/// What a run renders, and where. `None` where the kind has no known instruction entry point, and
/// then nothing is written at all.
pub struct Rendered {
    /// The file inside the agent state directory.
    pub at: PathBuf,
    pub text: String,
}

/// Render `manifest` as `kind` reads instruction. `imports` are absolute paths composed in by
/// reference — a share entry naming the entry point itself ([spec §5.6]) — each on its own line at
/// the end, in the kind's own import idiom.
///
/// [spec §5.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#56-agent-state-directory
pub fn render(
    manifest: &Manifest,
    kind: &Kind,
    agent_state: &Path,
    imports: &[PathBuf],
) -> Option<Rendered> {
    let presentation = kind.presentation.as_ref()?;
    let mut text = String::new();
    // `writeln!` to a `String` is infallible, so every result here is dropped rather than
    // threaded: there is no failure for a caller to handle.
    let _ = writeln!(
        text,
        "# The boundary this session runs in\n\n\
         playpen generated this file from the boundary it built for this profile as {kind}. It \
         states facts about that boundary and nothing else, and it is rewritten at every launch \
         of the profile.\n\n\
         This run's full layout, including the paths that belong to this run alone, is in the \
         JSON file named by the `{manifest_env}` environment variable. The facts below are those \
         that hold for every run of this profile.",
        kind = kind.name,
        manifest_env = crate::manifest::ENV,
    );
    render_workspaces(manifest, &mut text);
    render_network(manifest, &mut text);
    render_failure(manifest, &mut text);
    for import in imports {
        // A kind with no import mechanism never reaches here: the collision refuses at step 6.
        if let Some(prefix) = presentation.import {
            let _ = writeln!(text, "\n{prefix}{}", import.display());
        }
    }
    Some(Rendered {
        at: agent_state.join(presentation.entry_point),
        text,
    })
}

fn render_workspaces(manifest: &Manifest, text: &mut String) {
    if manifest.workspaces.is_empty() {
        let _ = writeln!(
            text,
            "\n## Workspaces\n\nThis profile declares no workspace, so no root is granted in \
             place."
        );
        return;
    }
    let _ = writeln!(text, "\n## Workspaces");
    for workspace in &manifest.workspaces {
        let _ = writeln!(text, "\n### {}\n\nRoots:\n", workspace.name);
        for root in &workspace.roots {
            let mode = match root.mode {
                crate::manifest::Mode::Read => "read (and execute)",
                crate::manifest::Mode::Readwrite => "read, write and execute",
            };
            let _ = writeln!(text, "- `{}` — {mode}", root.path.display());
        }
        // Only the areas that outlive a run: an ephemeral area's path is this run's alone, and
        // this file is read by every run of the profile.
        let persistent: Vec<_> = workspace
            .areas
            .iter()
            .filter(|area| area.lifetime == Lifetime::Persistent)
            .collect();
        if !persistent.is_empty() {
            let _ = writeln!(
                text,
                "\nAreas playpen keeps for the next run of this workspace:\n"
            );
            for area in persistent {
                let _ = writeln!(text, "- `{}` — `{}`", area.name, area.path.display());
            }
        }
        let forge = match &workspace.forge {
            Some(crate::manifest::Forge::Org(org)) => Some(format!("the `{org}` organisation")),
            Some(crate::manifest::Forge::Repos(repos)) => Some(
                repos
                    .iter()
                    .map(|repo| format!("`{repo}`"))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            None => None,
        };
        if let Some(forge) = forge {
            let _ = writeln!(
                text,
                "\nThe remote scope this workspace's credentials are minted for: {forge}."
            );
        }
    }
}

fn render_network(manifest: &Manifest, text: &mut String) {
    let _ = writeln!(
        text,
        "\n## The network\n\nplaypen confines no network traffic, so the proxy is not the only \
         way out. A destination with a credential route below is authenticated only for requests \
         sent through the proxy; the same request sent any other way arrives unauthenticated."
    );
    if manifest.network.routes.is_empty() {
        let _ = writeln!(
            text,
            "\nNo credential route resolves for this profile, and no proxy runs."
        );
        return;
    }
    let _ = writeln!(text, "\nCredential routes:\n");
    for route in &manifest.network.routes {
        let _ = writeln!(
            text,
            "- `{}{}` — the value in `{}` authenticates it",
            route.host, route.path_prefix, route.delivery_env
        );
        for set in &route.endpoints {
            let rules: Vec<_> = set
                .rules
                .iter()
                .map(|rule| format!("`{} {}`", rule.method, rule.path))
                .collect();
            let _ = writeln!(
                text,
                "  - the rule set `{}` allows only: {}",
                set.name,
                rules.join(", ")
            );
        }
    }
}

fn render_failure(manifest: &Manifest, text: &mut String) {
    let failure = &manifest.failure;
    let _ = writeln!(text, "\n## How a failure reads\n");
    let _ = writeln!(
        text,
        "- The boundary refused, on this platform, when the errno is one of: {}.",
        failure
            .denial_errnos
            .iter()
            .map(|errno| format!("`{errno}`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if failure.enoent_means_absent {
        let _ = writeln!(
            text,
            "- `ENOENT` means the path is absent. It is never how the boundary refuses."
        );
    }
    if let Some(denial) = &failure.broker_denial {
        let _ = writeln!(
            text,
            "- A request a credential route's rule set does not allow comes back as `{}` with the \
             header `{}` and the code `{}`. No request reached the destination.",
            denial.status, denial.header, denial.code
        );
    }
    if failure.boundary_fixed_for_the_session {
        let _ = writeln!(
            text,
            "- The boundary is fixed for this whole session. A refused operation is refused the \
             same way on a retry."
        );
    }
}

impl Rendered {
    /// Write this file into place: to a temporary file beside it, then renamed over it, so a
    /// reader of the entry point sees either the previous launch's file or this one's and never a
    /// half-written one.
    pub fn write(&self) -> Result<(), Refusal> {
        let io = |e: std::io::Error| {
            Refusal::new(
                Code::StateIo,
                format!(
                    "cannot write the rendered manifest {}: {e}",
                    self.at.display()
                ),
            )
        };
        let staging = self.at.with_extension("playpen-staging");
        std::fs::write(&staging, &self.text).map_err(io)?;
        std::fs::rename(&staging, &self.at).map_err(|e| {
            let _ = std::fs::remove_file(&staging);
            io(e)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{Area, BrokerDenial, Forge, Mode, Root, Route, Rule, RuleSet, Workspace};
    use crate::policy::Policy;
    use crate::record::RunId;

    fn claude() -> &'static Kind {
        crate::kind::require("claude").expect("a known kind")
    }

    /// A manifest with one workspace, both kinds of area, a forge scope, a route with a rule set,
    /// and the broker's vocabulary: everything the adapter can render.
    fn full() -> Manifest {
        let text = serde_json::json!({
            "version": 1,
            "workspaces": {"w": {
                "roots": [
                    {"path": "/src/w", "mode": "readwrite"},
                    {"path": "/notes", "mode": "read"},
                ],
                "areas": {"landing": {"lifetime": "persistent"}, "target": {"lifetime": "ephemeral"}},
                "forge": {"org": "firefly-engineering"},
            }},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": []}},
        });
        let policy = Policy::parse(&text.to_string(), Path::new("/p.json")).expect("parses");
        let id = RunId::allocate().expect("id");
        let layout = Layout::new(
            Path::new("/state"),
            &id,
            &policy,
            "p",
            &policy.profiles["p"],
            claude(),
        );
        let mut manifest =
            Manifest::new(&policy, &policy.profiles["p"], claude(), &layout).with_broker_denial();
        manifest.network.routes.push(Route {
            host: "api.github.com".into(),
            path_prefix: "/repos/firefly-engineering/".into(),
            delivery_env: "GH_TOKEN".into(),
            endpoints: vec![RuleSet {
                name: "github-read-only".into(),
                rules: vec![Rule {
                    method: "GET".into(),
                    path: "/repos/*/*/**".into(),
                }],
            }],
        });
        manifest
    }

    use crate::provision::Layout;

    fn rendered(manifest: &Manifest) -> Rendered {
        render(manifest, claude(), Path::new("/state/agents/p/claude"), &[])
            .expect("claude has an entry point")
    }

    /// Generated from the manifest's data: every fact in the file comes from a field of it.
    #[test]
    fn it_is_generated_from_manifest_data() {
        let manifest = full();
        let text = rendered(&manifest).text;
        for stated in [
            "/src/w",
            "/notes",
            "landing",
            "firefly-engineering",
            "api.github.com",
            "GH_TOKEN",
            "github-read-only",
            "/repos/*/*/**",
            "broker.endpoint.denied",
            crate::manifest::ENV,
        ] {
            assert!(stated_in(&text, stated), "{stated} is not in:\n{text}");
        }
        for errno in &manifest.failure.denial_errnos {
            assert!(stated_in(&text, errno), "{errno} is not in:\n{text}");
        }
    }

    fn stated_in(text: &str, what: &str) -> bool {
        text.contains(what)
    }

    /// Only facts stable across the profile's runs: the run scratch and an ephemeral area belong
    /// to one run, and this file is read by every run of the profile.
    #[test]
    fn it_states_only_facts_stable_across_the_profiles_runs() {
        let manifest = full();
        let text = rendered(&manifest).text;
        let scratch = manifest.run_scratch.display().to_string();
        assert!(!text.contains(&scratch), "the run scratch is in:\n{text}");
        let ephemeral = manifest.workspaces[0]
            .areas
            .iter()
            .find(|area| area.lifetime == Lifetime::Ephemeral)
            .expect("an ephemeral area");
        let path = ephemeral.path.display().to_string();
        assert!(
            !text.contains(&path),
            "an ephemeral area's path is in:\n{text}"
        );
        // That this run's full layout is in `$PLAYPEN_MANIFEST` is itself a stable fact.
        assert!(text.contains(crate::manifest::ENV));
    }

    /// It may state what playpen built; it may never state what the agent should do about it.
    #[test]
    fn it_contains_no_instruction_to_the_agent() {
        let text = rendered(&full()).text.to_lowercase();
        for imperative in [
            " you ",
            " your ",
            "you should",
            "you must",
            "please ",
            "make sure",
            "be careful",
            "prefer ",
            "avoid ",
            "do not ",
            "don't ",
        ] {
            assert!(!text.contains(imperative), "{imperative:?} is in:\n{text}");
        }
    }

    /// The entry point is the kind's own, inside the profile's agent state directory.
    #[test]
    fn it_is_written_at_the_kinds_entry_point() {
        let dir = tempfile::TempDir::new().expect("dir");
        let rendered =
            render(&full(), claude(), dir.path(), &[]).expect("claude has an entry point");
        assert_eq!(rendered.at, dir.path().join("CLAUDE.md"));
        rendered.write().expect("written");
        assert_eq!(
            std::fs::read_to_string(&rendered.at).expect("the file"),
            rendered.text
        );
        // Renamed into place, so nothing is left beside it.
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(left, ["CLAUDE.md"]);
    }

    /// Rewritten on every launch: the second launch's facts replace the first's, in one step.
    #[test]
    fn it_is_renamed_into_place_on_every_launch() {
        let dir = tempfile::TempDir::new().expect("dir");
        let first = render(&full(), claude(), dir.path(), &[]).expect("an entry point");
        first.write().expect("written");
        let mut manifest = full();
        manifest.workspaces.push(Workspace {
            name: "added-later".into(),
            roots: vec![Root {
                path: "/src/added".into(),
                mode: Mode::Read,
            }],
            areas: vec![Area {
                name: "cache".into(),
                lifetime: Lifetime::Persistent,
                path: "/state/areas/persistent/added-later/cache".into(),
            }],
            forge: Some(Forge::Repos(vec!["a/b".into()])),
        });
        let second = render(&manifest, claude(), dir.path(), &[]).expect("an entry point");
        second.write().expect("written");
        let text = std::fs::read_to_string(&second.at).expect("the file");
        assert!(text.contains("added-later"), "{text}");
        assert_ne!(text, first.text);
    }

    /// A kind whose instruction entry point playpen does not know renders nothing: a guess would
    /// be a file the agent never opens.
    #[test]
    fn a_kind_with_no_known_entry_point_renders_nothing() {
        let omp = crate::kind::require("omp").expect("a known kind");
        assert!(omp.presentation.is_none());
        assert!(render(&full(), omp, Path::new("/state"), &[]).is_none());
    }

    /// A staging failure never leaves a half-written entry point: the rename is what publishes.
    #[test]
    fn a_write_that_cannot_stage_refuses_and_leaves_the_previous_file() {
        let dir = tempfile::TempDir::new().expect("dir");
        let gone = dir.path().join("gone");
        let rendered = render(&full(), claude(), &gone, &[]).expect("an entry point");
        let refusal = rendered.write().expect_err("refused");
        assert_eq!(refusal.code, Code::StateIo);
        assert!(refusal.message().contains("CLAUDE.md"), "{refusal}");
    }

    #[test]
    fn the_broker_vocabulary_appears_only_where_the_manifest_carries_it() {
        let mut manifest = full();
        manifest.failure.broker_denial = None;
        let text = rendered(&manifest).text;
        assert!(!text.contains("broker.endpoint.denied"), "{text}");
        manifest.failure.broker_denial = Some(BrokerDenial {
            status: 403,
            header: "X-Playpen-Denied".into(),
            code: "broker.endpoint.denied".into(),
        });
        assert!(rendered(&manifest).text.contains("X-Playpen-Denied"));
    }
}
