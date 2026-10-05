//! Profile selection ([spec §11.4]): the chain from an invocation to one profile, first hit wins.
//!
//! 1. **Explicit**: `--profile`, or a shim's pinned profile.
//! 2. **Environment**: `PLAYPEN_PROFILE`.
//! 3. **CWD**: the profile with the longest `prefixes` entry containing the working directory.
//! 4. Otherwise refuse. There is no implicit default; a catch-all is an explicit `prefixes: [/]`.
//!
//! Every input is a parameter: the caller reads the environment and the working directory once.
//! The [`Trace`] says which step selected and why each earlier one did not, and is returned even
//! when selection refuses, so the record of a refused run still says how far it got.
//!
//! [spec §11.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#114-profile-selection

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::code::Code;
use crate::policy::Policy;
use crate::refusal::Refusal;

/// The name of the chain's second step.
pub const ENV: &str = "PLAYPEN_PROFILE";

/// What selection is given: each step's input, if the invocation has one.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a> {
    pub explicit: Option<&'a str>,
    /// `PLAYPEN_PROFILE`, as the environment holds it.
    pub env: Option<&'a OsStr>,
    /// `None` when the working directory could not be read, so the CWD step has nothing to match.
    pub cwd: Option<&'a Path>,
}

/// The steps selection took, in order: every step up to and including the one that selected or
/// refused.
pub type Trace = Vec<Step>;

/// One step of the chain, and what came of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Step {
    pub step: Source,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Explicit,
    Environment,
    Cwd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum Outcome {
    /// The step had no input: no `--profile`, no `PLAYPEN_PROFILE`, or no prefix containing the
    /// working directory.
    Skipped { reason: String },
    /// The step chose `profile`; for the CWD step, by the prefix that matched.
    Selected {
        profile: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix: Option<PathBuf>,
    },
    /// The step had an input and it refused: the refusal's code.
    Refused { code: String },
}

/// Select a profile of `policy` from `inputs`. The trace comes back whatever the result.
pub fn select(policy: &Policy, inputs: Inputs) -> (Trace, Result<String, Refusal>) {
    let mut trace = Trace::new();
    let result = chain(policy, inputs, &mut trace);
    (trace, result)
}

fn chain(policy: &Policy, inputs: Inputs, trace: &mut Trace) -> Result<String, Refusal> {
    let mut step = |step, outcome| trace.push(Step { step, outcome });
    let skipped = |reason: &str| Outcome::Skipped {
        reason: reason.into(),
    };

    match inputs.explicit {
        Some(name) => return named(policy, name, Source::Explicit, "--profile", &mut step),
        None => step(Source::Explicit, skipped("no profile was named explicitly")),
    }
    match inputs.env {
        Some(value) => {
            let name = value.to_string_lossy();
            return named(policy, &name, Source::Environment, ENV, &mut step);
        }
        None => step(Source::Environment, skipped(&format!("{ENV} is not set"))),
    }

    let Some(cwd) = inputs.cwd else {
        step(Source::Cwd, skipped("the working directory is unavailable"));
        return Err(Refusal::new(
            Code::SelectionNoMatch,
            format!(
                "no profile selected: no --profile, {ENV} is not set, and the working directory \
                 is unavailable; known profiles: {}",
                known(policy)
            ),
        ));
    };
    let matches = longest_prefixes(policy, cwd);
    match matches.as_slice() {
        [(profile, prefix)] => {
            step(
                Source::Cwd,
                Outcome::Selected {
                    profile: (*profile).to_owned(),
                    prefix: Some((*prefix).to_owned()),
                },
            );
            Ok((*profile).to_owned())
        }
        [] => {
            step(
                Source::Cwd,
                skipped(&format!("no profile's prefixes contain {}", cwd.display())),
            );
            Err(Refusal::new(
                Code::SelectionNoMatch,
                format!(
                    "no profile selected: no --profile, {ENV} is not set, and no profile's \
                     prefixes contain the working directory {}; known profiles: {}",
                    cwd.display(),
                    known(policy)
                ),
            ))
        }
        tied => {
            let refusal = Refusal::new(
                Code::SelectionAmbiguous,
                format!(
                    "the working directory {} is under equally long prefixes of {}",
                    cwd.display(),
                    tied.iter()
                        .map(|(profile, prefix)| format!("{profile} ({})", prefix.display()))
                        .collect::<Vec<_>>()
                        .join(" and ")
                ),
            );
            step(
                Source::Cwd,
                Outcome::Refused {
                    code: refusal.code.to_string(),
                },
            );
            Err(refusal)
        }
    }
}

/// A step that names its profile: it selects that profile, or refuses if there is none.
fn named(
    policy: &Policy,
    name: &str,
    source: Source,
    via: &str,
    step: &mut impl FnMut(Source, Outcome),
) -> Result<String, Refusal> {
    if policy.profiles.contains_key(name) {
        step(
            source,
            Outcome::Selected {
                profile: name.to_owned(),
                prefix: None,
            },
        );
        return Ok(name.to_owned());
    }
    let refusal = Refusal::new(
        Code::SelectionUnknownProfile,
        format!(
            "{via} names profile {name:?}, which is not in the policy; known profiles: {}",
            known(policy)
        ),
    );
    step(
        source,
        Outcome::Refused {
            code: refusal.code.to_string(),
        },
    );
    Err(refusal)
}

/// Every profile with a prefix containing `cwd` at the greatest length found, each with that
/// prefix. Containment and length are by path component, so `/src/playpen` contains
/// `/src/playpen/a` and not `/src/playpen-old`, and `/` contains everything at length one.
fn longest_prefixes<'a>(policy: &'a Policy, cwd: &Path) -> Vec<(&'a str, &'a Path)> {
    let mut best: Vec<(&str, &Path)> = Vec::new();
    let mut best_len = 0;
    for (name, profile) in &policy.profiles {
        let longest = profile
            .prefixes
            .iter()
            .filter(|prefix| prefix.is_absolute() && cwd.starts_with(prefix))
            .max_by_key(|prefix| prefix.components().count());
        let Some(prefix) = longest else { continue };
        let len = prefix.components().count();
        if len > best_len {
            best.clear();
            best_len = len;
        }
        if len == best_len {
            best.push((name, prefix));
        }
    }
    best
}

fn known(policy: &Policy) -> String {
    let names: Vec<_> = policy.profiles.keys().map(String::as_str).collect();
    if names.is_empty() {
        "none".into()
    } else {
        names.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        let text = "\
version: 1
profiles:
  firefly: { prefixes: [/src/firefly/], workspaces: [], toolchain: [] }
  playpen: { prefixes: [/src/firefly/playpen, /elsewhere], workspaces: [], toolchain: [] }
  catch-all: { prefixes: [/], workspaces: [], toolchain: [] }
  twin: { prefixes: [/src/twin], workspaces: [], toolchain: [] }
  twin-too: { prefixes: [/src/twin/], workspaces: [], toolchain: [] }
";
        Policy::parse(text, Path::new("/p.yaml")).expect("parses")
    }

    fn inputs<'a>(explicit: Option<&'a str>, env: Option<&'a str>, cwd: &'a str) -> Inputs<'a> {
        Inputs {
            explicit,
            env: env.map(OsStr::new),
            cwd: Some(Path::new(cwd)),
        }
    }

    fn selected(trace: &Trace) -> Vec<(Source, &str)> {
        trace
            .iter()
            .map(|step| {
                let what = match &step.outcome {
                    Outcome::Skipped { .. } => "skipped",
                    Outcome::Selected { profile, .. } => profile,
                    Outcome::Refused { code } => code,
                };
                (step.step, what)
            })
            .collect()
    }

    #[test]
    fn explicit_wins_over_everything() {
        let (trace, result) = select(
            &policy(),
            inputs(Some("twin"), Some("firefly"), "/src/firefly/playpen"),
        );
        assert_eq!(result, Ok("twin".into()));
        assert_eq!(selected(&trace), [(Source::Explicit, "twin")]);
    }

    #[test]
    fn the_environment_wins_over_the_cwd() {
        let (trace, result) = select(
            &policy(),
            inputs(None, Some("firefly"), "/src/firefly/playpen"),
        );
        assert_eq!(result, Ok("firefly".into()));
        assert_eq!(
            selected(&trace),
            [
                (Source::Explicit, "skipped"),
                (Source::Environment, "firefly")
            ]
        );
    }

    #[test]
    fn the_longest_prefix_wins() {
        let (trace, result) = select(&policy(), inputs(None, None, "/src/firefly/playpen/src"));
        assert_eq!(result, Ok("playpen".into()));
        assert_eq!(
            trace.last().map(|step| &step.outcome),
            Some(&Outcome::Selected {
                profile: "playpen".into(),
                prefix: Some("/src/firefly/playpen".into()),
            })
        );
        let (_, result) = select(&policy(), inputs(None, None, "/src/firefly/other"));
        assert_eq!(result, Ok("firefly".into()));
    }

    #[test]
    fn a_prefix_contains_by_component_not_by_string() {
        let (_, result) = select(&policy(), inputs(None, None, "/src/firefly/playpen-old"));
        assert_eq!(result, Ok("firefly".into()));
    }

    #[test]
    fn slash_is_an_explicit_catch_all() {
        let (trace, result) = select(&policy(), inputs(None, None, "/tmp"));
        assert_eq!(result, Ok("catch-all".into()));
        assert_eq!(
            selected(&trace),
            [
                (Source::Explicit, "skipped"),
                (Source::Environment, "skipped"),
                (Source::Cwd, "catch-all")
            ]
        );
    }

    #[test]
    fn an_unknown_explicit_profile_is_refused() {
        let (trace, result) = select(&policy(), inputs(Some("nope"), None, "/"));
        let refusal = result.expect_err("refused");
        assert_eq!(refusal.code, Code::SelectionUnknownProfile);
        assert!(refusal.message().contains("--profile"), "{refusal}");
        assert_eq!(
            selected(&trace),
            [(Source::Explicit, "refusal.selection.unknown-profile")]
        );
    }

    /// An unknown profile in the environment is refused, never passed over for the CWD's.
    #[test]
    fn an_unknown_environment_profile_is_refused() {
        let (_, result) = select(&policy(), inputs(None, Some("nope"), "/src/firefly"));
        let refusal = result.expect_err("refused");
        assert_eq!(refusal.code, Code::SelectionUnknownProfile);
        assert!(refusal.message().contains(ENV), "{refusal}");
    }

    #[test]
    fn no_match_is_refused_naming_what_was_tried() {
        let text = "\
version: 1
profiles:
  a: { prefixes: [/src/a], workspaces: [], toolchain: [] }
  b: { workspaces: [], toolchain: [] }
";
        let policy = Policy::parse(text, Path::new("/p.yaml")).expect("parses");
        let (trace, result) = select(&policy, inputs(None, None, "/src/z"));
        let refusal = result.expect_err("refused");
        assert_eq!(refusal.code, Code::SelectionNoMatch);
        for named in ["/src/z", ENV, "known profiles: a, b"] {
            assert!(refusal.message().contains(named), "{named}: {refusal}");
        }
        assert_eq!(trace.len(), 3);
    }

    #[test]
    fn equally_long_prefixes_are_ambiguous() {
        let (trace, result) = select(&policy(), inputs(None, None, "/src/twin/x"));
        let refusal = result.expect_err("refused");
        assert_eq!(refusal.code, Code::SelectionAmbiguous);
        assert!(
            refusal.message().contains("twin (/src/twin)")
                && refusal.message().contains("twin-too (/src/twin/)"),
            "{refusal}"
        );
        assert_eq!(
            selected(&trace).last(),
            Some(&(Source::Cwd, "refusal.selection.ambiguous"))
        );
    }

    #[test]
    fn the_trace_serialises_flat() {
        let step = Step {
            step: Source::Cwd,
            outcome: Outcome::Selected {
                profile: "p".into(),
                prefix: Some("/src".into()),
            },
        };
        assert_eq!(
            serde_json::to_value(&step).expect("json"),
            serde_json::json!({"step": "cwd", "outcome": "selected", "profile": "p", "prefix": "/src"})
        );
    }
}
