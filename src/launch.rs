//! The invocation contract ([spec §11]) and the launch sequence ([spec §4.2]), as far as the
//! walking skeleton goes: parse, read the policy, resolve one profile's roots, check the CWD,
//! compile the floor plus those roots, and run the target confined.
//!
//! [spec §11]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#11-invocation-contract
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::error::{ContextKind, ErrorKind};
use clap::{Parser, Subcommand};

use crate::capability::{PathGrant, Scope};
use crate::child;
use crate::code::Code;
use crate::floor::floor;
use crate::policy::Policy;
use crate::refusal::{EXIT_REFUSED, Refusal};

#[derive(Debug, Parser)]
#[command(name = "playpen")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a target confined under a profile.
    Run {
        #[arg(long)]
        profile: String,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Everything after `--`, passed through verbatim.
        #[arg(last = true, required = true, value_parser = clap::value_parser!(OsString))]
        argv: Vec<OsString>,
    },
}

/// The agent kinds this playpen knows. A kind is always stated, never inferred ([spec §11.2]).
///
/// [spec §11.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#112-kind
const KINDS: &[&str] = &["claude", "omp"];

/// Run playpen with `args` (including `argv[0]`) from the caller's working directory `cwd`.
/// Returns the process exit status; on a refusal, the refusal line has already been written.
pub fn main(args: impl IntoIterator<Item = OsString>, cwd: std::io::Result<PathBuf>) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) if matches!(err.kind(), ErrorKind::DisplayHelp) => {
            // Help was asked for; no agent was going to run. stdout is sacred, so it goes to stderr.
            eprint!("{}", err.render());
            return 0;
        }
        Err(err) => return refuse(usage_refusal(&err)),
    };
    match cli.command {
        Command::Run {
            profile,
            agent,
            policy,
            argv,
        } => match run(&profile, &agent, policy.as_deref(), &argv, cwd) {
            Ok(status) => status,
            Err(refusal) => refuse(refusal),
        },
    }
}

fn refuse(refusal: Refusal) -> i32 {
    refusal.emit();
    EXIT_REFUSED
}

fn usage_refusal(err: &clap::Error) -> Refusal {
    let mut message = err
        .kind()
        .as_str()
        .unwrap_or("invalid command line")
        .to_string();
    if let Some(arg) = err.get(ContextKind::InvalidArg) {
        message.push_str(&format!(": {arg}"));
    }
    Refusal::new(Code::InvocationUsage, message)
}

fn run(
    profile: &str,
    agent: &str,
    policy: Option<&Path>,
    argv: &[OsString],
    cwd: std::io::Result<PathBuf>,
) -> Result<i32, Refusal> {
    if !KINDS.contains(&agent) {
        return Err(Refusal::new(
            Code::KindUnknown,
            format!(
                "unknown agent kind {agent:?}; known kinds: {}",
                KINDS.join(", ")
            ),
        ));
    }
    let policy_path = policy.ok_or_else(|| {
        Refusal::new(
            Code::PolicyNotFound,
            "no policy given; pass --policy <path>",
        )
    })?;
    let policy = Policy::load(policy_path)?;
    let roots = resolve_roots(&policy, profile)?;
    check_cwd(cwd, &roots)?;

    let mut caps = floor();
    caps.paths.extend(roots);
    child::run_confined(&caps, argv)
}

/// The selected profile's brought roots, canonicalised, as path grants with provenance.
fn resolve_roots(policy: &Policy, profile: &str) -> Result<Vec<PathGrant>, Refusal> {
    let selected = policy.profiles.get(profile).ok_or_else(|| {
        let known: Vec<_> = policy.profiles.keys().map(String::as_str).collect();
        Refusal::new(
            Code::SelectionUnknownProfile,
            format!(
                "profile {profile:?} is not in the policy; known profiles: {}",
                known.join(", ")
            ),
        )
    })?;
    let mut grants = Vec::new();
    for name in &selected.workspaces {
        let workspace = policy.workspaces.get(name).ok_or_else(|| {
            Refusal::new(
                Code::WorkspaceUnknown,
                format!("profile {profile:?} names undeclared workspace {name:?}"),
            )
        })?;
        for (i, root) in workspace.roots.iter().enumerate() {
            let from = format!("workspace:{name}.roots[{i}]");
            if !root.path.is_absolute() {
                return Err(Refusal::new(
                    Code::RootRelative,
                    format!(
                        "{from}: root {} is not an absolute path",
                        root.path.display()
                    ),
                ));
            }
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
            });
        }
    }
    Ok(grants)
}

/// The child starts in the caller's CWD, which must lie inside a granted root ([spec §11.5]).
///
/// [spec §11.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#115-working-directory
fn check_cwd(cwd: std::io::Result<PathBuf>, roots: &[PathGrant]) -> Result<(), Refusal> {
    let cwd = cwd.and_then(|cwd| cwd.canonicalize()).map_err(|e| {
        Refusal::new(
            Code::CwdUngranted,
            format!("the working directory is unavailable: {e}"),
        )
    })?;
    if cwd_granted(&cwd, roots) {
        Ok(())
    } else {
        Err(Refusal::new(
            Code::CwdUngranted,
            format!("cwd {} is outside every granted root", cwd.display()),
        ))
    }
}

/// Containment is by path component, so `/src/playpen-old` is not inside `/src/playpen`.
fn cwd_granted(cwd: &Path, roots: &[PathGrant]) -> bool {
    roots.iter().any(|root| cwd.starts_with(&root.path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::Access;

    fn root(path: &str) -> PathGrant {
        PathGrant {
            path: path.into(),
            access: Access::ReadWrite,
            scope: Scope::Subtree,
            from: "workspace:w.roots[0]".into(),
        }
    }

    #[test]
    fn cwd_at_or_below_a_root_is_granted() {
        let roots = [root("/src/playpen")];
        assert!(cwd_granted(Path::new("/src/playpen"), &roots));
        assert!(cwd_granted(Path::new("/src/playpen/crates/a"), &roots));
    }

    #[test]
    fn cwd_sharing_only_a_string_prefix_is_not_granted() {
        let roots = [root("/src/playpen")];
        assert!(!cwd_granted(Path::new("/src/playpen-old"), &roots));
        assert!(!cwd_granted(Path::new("/src"), &roots));
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(args)
    }

    #[test]
    fn everything_after_the_wall_is_opaque() {
        let cli = parse(&[
            "playpen",
            "run",
            "--profile",
            "p",
            "--agent",
            "claude",
            "--",
            "x",
            "--profile",
            "-v",
        ])
        .expect("parses");
        let Command::Run { argv, profile, .. } = cli.command;
        assert_eq!(profile, "p");
        assert_eq!(argv, ["x", "--profile", "-v"]);
    }

    #[test]
    fn profile_and_agent_are_mandatory() {
        let err = parse(&["playpen", "run", "--agent", "claude", "--", "x"]).unwrap_err();
        assert_eq!(usage_refusal(&err).code, Code::InvocationUsage);
        assert!(parse(&["playpen", "run", "--profile", "p", "--", "x"]).is_err());
    }

    #[test]
    fn a_target_requires_the_wall() {
        assert!(parse(&["playpen", "run", "--profile", "p", "--agent", "claude", "x"]).is_err());
    }
}
