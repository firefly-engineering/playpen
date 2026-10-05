//! The invocation contract ([spec §11]) and the launch sequence ([spec §4.2]), as far as the
//! walking skeleton goes: parse, open the run record, read the policy, resolve one profile's
//! roots, check the CWD, self-test the floor, compile the floor plus those roots, complete the
//! record, and run the target confined.
//!
//! [spec §11]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#11-invocation-contract
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::error::{ContextKind, ErrorKind};
use clap::{Parser, Subcommand};

use crate::backend;
use crate::capability::PathGrant;
use crate::check;
use crate::child;
use crate::code::Code;
use crate::environment;
use crate::explain;
use crate::integrity;
use crate::kind::{self, Kind};
use crate::manifest::Manifest;
use crate::mechanism::{self, Mechanism};
use crate::policy::{Policy, SearchPath, coherence};
use crate::provision::Layout;
use crate::record::{self, RunId, RunRecord};
use crate::refusal::{EXIT_REFUSED, Refusal};
use crate::resolve;
use crate::select;
use crate::self_test;

#[derive(Debug, Parser)]
#[command(name = "playpen")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a target confined under a profile.
    Run(RunArgs),
    /// Show the boundary a profile resolves to, replay a stored run record, or list the runs the
    /// ring holds.
    Explain(explain::Args),
    /// Validate a policy without launching anything.
    Check(check::Args),
}

#[derive(Debug, clap::Args)]
struct RunArgs {
    #[arg(long)]
    profile: String,
    #[arg(long)]
    agent: String,
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Everything after `--`, passed through verbatim.
    #[arg(last = true, required = true, value_parser = clap::value_parser!(OsString))]
    argv: Vec<OsString>,
}

/// What playpen takes from the process it runs in, read once by `main` and handed in, so nothing
/// below reads the environment or the working directory for itself.
pub struct Host {
    /// The caller's working directory.
    pub cwd: std::io::Result<PathBuf>,
    /// playpen's state directory, `None` when the environment names none.
    pub state: Option<PathBuf>,
    /// Where to look for the policy when `--policy` is not given.
    pub policies: SearchPath,
    /// `PLAYPEN_PROFILE`, the selection chain's second step. `run` never reads it.
    pub profile: Option<OsString>,
    /// The running playpen executable, which self-integrity requires the profile cannot write.
    pub executable: std::io::Result<PathBuf>,
    /// The caller's environment, which the child's is constructed from by name and never
    /// inherited whole ([spec §9]).
    ///
    /// [spec §9]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#9-the-environment
    pub env: Vec<(OsString, OsString)>,
}

/// Run playpen with `args` (including `argv[0]`) on `host`. Returns the process exit status; on a
/// refusal, the refusal line has already been written.
///
/// `probe` is [`Mechanism::probe`] in every launch; it is a parameter so the suite's
/// `R-missing-cap` row can launch on a mechanism that lacks a capability, which no host it runs
/// on does.
pub fn main(
    args: impl IntoIterator<Item = OsString>,
    host: Host,
    probe: impl FnOnce() -> Mechanism,
) -> i32 {
    // Parsing has no effect, so it can come first. `explain` and `check` launch nothing
    // ([spec §14.2], [spec §10.5]), so they open no record and push no run out of the ring, and nor
    // does a request for help; anything else is a launch, and a command line that does not parse
    // is refused as one.
    //
    // [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
    // [spec §10.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#105-validation-tiers
    let parsed = match Cli::try_parse_from(args) {
        Ok(Cli {
            command: Command::Explain(args),
        }) => {
            return match explain::explain(&args, &host, &mut std::io::stdout().lock()) {
                Ok(()) => 0,
                Err(refusal) => refuse(&refusal, None),
            };
        }
        Ok(Cli {
            command: Command::Check(args),
        }) => {
            return match check::check(&args, &host.policies) {
                Ok(()) => 0,
                Err(refusal) => refuse(&refusal, None),
            };
        }
        Ok(Cli {
            command: Command::Run(args),
        }) => Ok(args),
        Err(err) if matches!(err.kind(), ErrorKind::DisplayHelp) => {
            // No agent was going to run. stdout is sacred, so help goes to stderr.
            eprint!("{}", err.render());
            return 0;
        }
        Err(err) => Err(err),
    };
    // Step 1, before anything that can refuse, so that every refusal leaves a record.
    let run = match RunId::allocate() {
        Ok(run) => run,
        Err(refusal) => return refuse(&refusal, None),
    };
    let mut record = match RunRecord::open(&run, host.state.as_deref()) {
        Ok(record) => record,
        Err(refusal) => return refuse(&refusal, Some(&run)),
    };
    match invoke(parsed, host, &mut record, probe) {
        Ok(status) => {
            record.finish(status);
            status
        }
        Err(refusal) => {
            record.refuse(&refusal);
            refuse(&refusal, Some(&run))
        }
    }
}

fn invoke(
    parsed: Result<RunArgs, clap::Error>,
    host: Host,
    record: &mut RunRecord,
    probe: impl FnOnce() -> Mechanism,
) -> Result<i32, Refusal> {
    // `run` resolves no context of its own, so `PLAYPEN_PROFILE` is not one of its inputs.
    let Host {
        cwd,
        state,
        policies,
        profile: _,
        executable,
        env,
    } = host;
    let RunArgs {
        profile,
        agent,
        policy,
        argv,
    } = parsed.map_err(|err| usage_refusal(&err))?;
    // Step 2 ends with the kind, which is part of the invocation; step 3 locates the policy.
    // A kind is always stated, never inferred ([spec §11.2]).
    //
    // [spec §11.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#112-kind
    let kind = kind::require(&agent)?;
    record.kind(&agent);
    let policy = policies.locate(policy.as_deref())?;
    run(
        &profile,
        kind,
        &policy,
        &argv,
        cwd,
        state.as_deref(),
        executable,
        &env,
        record,
        probe,
        self_test::floor,
    )
}

fn refuse(refusal: &Refusal, run: Option<&RunId>) -> i32 {
    refusal.emit(run);
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

/// `probe` and `floor_self_test` are [`Mechanism::probe`] and [`self_test::floor`] in every
/// launch; they are parameters so a test can show that each one's refusal stops the launch before
/// the real child is forked.
#[expect(
    clippy::too_many_arguments,
    reason = "step 7's two checks are each a seam a test replaces"
)]
fn run(
    profile: &str,
    kind: &'static Kind,
    policy_path: &Path,
    argv: &[OsString],
    cwd: std::io::Result<PathBuf>,
    state: Option<&Path>,
    executable: std::io::Result<PathBuf>,
    env: &[(OsString, OsString)],
    record: &mut RunRecord,
    probe: impl FnOnce() -> Mechanism,
    floor_self_test: impl FnOnce() -> Result<(), Refusal>,
) -> Result<i32, Refusal> {
    // Absolute, so a stored record names the file whatever directory it is read from.
    let policy_file = match &cwd {
        Ok(cwd) => cwd.join(policy_path),
        Err(_) => policy_path.to_owned(),
    };
    record.policy(&policy_file);
    let loaded = Policy::load(policy_path)?;
    // Step 4. `run` takes its profile explicitly and resolves no context of its own, so its chain
    // is the explicit step alone.
    let inputs = select::Inputs {
        explicit: Some(profile),
        env: None,
        cwd: cwd.as_deref().ok(),
    };
    let (trace, selected) = select::select(&loaded.policy, inputs);
    record.selection(&trace, selected.as_deref().ok());
    let selected = selected?;
    let selected = loaded.policy.profiles.get(&selected).ok_or_else(|| {
        Refusal::new(
            Code::SelectionUnknownProfile,
            format!("profile {selected:?} is not in the policy"),
        )
    })?;
    // Step 5.
    coherence::check(&loaded)?;
    // Step 6: everything decidable from this host as it is now. The capability set resolves every
    // root, link and exclusion, refusing any that is missing.
    let roots = resolve::roots(&loaded.policy, selected)?;
    check_cwd(cwd, &roots)?;
    // The record is open, so the state directory exists; resolved, because the mechanism enforces
    // on real paths.
    let layout = state
        .ok_or_else(record::no_state)
        .and_then(|state| {
            state.canonicalize().map_err(|e| {
                Refusal::new(
                    Code::StateIo,
                    format!(
                        "cannot resolve the state directory {}: {e}",
                        state.display()
                    ),
                )
            })
        })
        .map(|state| {
            Layout::new(&state, record.id(), &loaded.policy, profile, selected, kind)
                .with_home(environment::home(env).as_deref())
        })?;
    let caps = resolve::capabilities(&loaded.policy, profile, &layout)?;
    // Nothing that runs unconfined on the next launch is writable from inside this one.
    integrity::check(&caps, &policy_file, &integrity::executable(&executable)?)?;
    // The existence-tier containment check, run once the capability set is complete because the
    // rule is about *every* granted path and the floor is a grant too: on a non-FHS host it is a
    // declared closure read from a `PLAYPEN_FLOOR`-selected directory, so it is neither
    // policy-declared nor state-derived ([ADR 0027]). A compiled-in FHS floor can never trigger it.
    //
    // [ADR 0027]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md
    record::refuse_if_reachable(state, &caps.paths)?;
    // Step 7, on every launch, never from a cached verdict: the mechanism first, so a missing
    // capability is named as such rather than surfacing as a canary that could not be confined.
    probe().require(mechanism::REQUIRED)?;
    floor_self_test()?;
    // Step 9. Removed again when this returns: at teardown, or on any refusal from here on.
    let _provisioned = layout.provision()?;
    // The manifest, written on every run even when nothing is provisioned ([spec §13.1]): it is
    // derived from the same resolution pass as the capability set, so what the agent is told and
    // what the kernel enforces cannot drift.
    //
    // [spec §13.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#131-form
    let manifest = Manifest::new(&loaded.policy, selected, kind, &layout);
    manifest.write(&layout.manifest())?;
    // Step 12: the capability set compiles on this mechanism.
    backend::check(&caps)?;
    // Step 14.
    let env = resolve::environment(&loaded.policy, profile, selected, env, &layout, Some(kind));
    record.launch(&caps, backend::denial_tag(record.id()))?;
    let run = record.id().clone();
    // Both callbacks write the record, and only one of them ever fires, but the borrow checker
    // cannot see that from two closures: a cell is cheaper than a seam for it.
    let record = std::cell::RefCell::new(record);
    child::run_confined(
        &caps,
        argv,
        &env,
        &run,
        || Ok(()),
        |pid| record.borrow_mut().spawned(pid),
        |fault| record.borrow_mut().fault(fault),
    )
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
    use crate::capability::{Access, Scope};

    fn root(path: &str) -> PathGrant {
        PathGrant {
            path: path.into(),
            access: Access::ReadWrite,
            scope: Scope::Subtree,
            from: "workspace:w.roots[0]".into(),
            state_derived: false,
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
        let Command::Run(RunArgs { argv, profile, .. }) = cli.command else {
            panic!("parses as run");
        };
        assert_eq!(profile, "p");
        assert_eq!(argv, ["x", "--profile", "-v"]);
    }

    #[test]
    fn profile_and_agent_are_mandatory() {
        let err = parse(&["playpen", "run", "--agent", "claude", "--", "x"]).unwrap_err();
        assert_eq!(usage_refusal(&err).code, Code::InvocationUsage);
        assert!(parse(&["playpen", "run", "--profile", "p", "--", "x"]).is_err());
    }

    /// Launch profile `p` over a root of its own with no target, under `probe` and
    /// `floor_self_test`, and return the refusal and whether the record was completed. With no
    /// target, forking the real child refuses with `refusal.invocation.usage` before the fork, so
    /// any other code comes from a check run ahead of it, and no test forks.
    fn refuse_without_target(
        probe: impl FnOnce() -> Mechanism,
        floor_self_test: impl FnOnce() -> Result<(), Refusal>,
    ) -> (Refusal, bool) {
        refuse_with_toolchain(serde_json::json!([]), probe, floor_self_test)
    }

    /// As [`refuse_without_target`], with the profile's toolchain `toolchain`.
    fn refuse_with_toolchain(
        toolchain: serde_json::Value,
        probe: impl FnOnce() -> Mechanism,
        floor_self_test: impl FnOnce() -> Result<(), Refusal>,
    ) -> (Refusal, bool) {
        let root = tempfile::TempDir::new().expect("root");
        let policy = root.path().join("policy.json");
        let document = serde_json::json!({
            "version": 1,
            "workspaces": {"w": {"roots": [{"path": root.path(), "mode": "read"}]}},
            "profiles": {"p": {"workspaces": ["w"], "toolchain": toolchain}},
        });
        std::fs::write(&policy, document.to_string()).expect("policy");
        let argv = [];
        let state = tempfile::TempDir::new().expect("state");
        // Never writable: the profile's one root is read-only and holds no playpen.
        let executable = state.path().join("playpen");
        std::fs::write(&executable, "").expect("executable");
        let id = RunId::allocate().expect("id");
        let mut record = RunRecord::open(&id, Some(state.path())).expect("record");
        let refusal = run(
            "p",
            kind::require("claude").expect("a known kind"),
            &policy,
            &argv,
            Ok(root.path().into()),
            Some(state.path()),
            Ok(executable),
            &[],
            &mut record,
            probe,
            floor_self_test,
        )
        .expect_err("the launch refuses");
        (refusal, record.record().capabilities.is_some())
    }

    /// Existence and integrity are step 6, so a missing toolchain root refuses before the mechanism
    /// is probed or the canary confined (spec §4.2).
    #[test]
    fn a_missing_toolchain_root_refuses_before_step_7() {
        let (mut probed, mut self_tested) = (0, 0);
        let (refusal, completed) = refuse_with_toolchain(
            serde_json::json!([{"path": "/nonexistent/playpen-toolchain"}]),
            || {
                probed += 1;
                offering_everything()
            },
            || {
                self_tested += 1;
                Ok(())
            },
        );
        assert_eq!(refusal.code, Code::RootMissing);
        assert_eq!((probed, self_tested), (0, 0), "step 7 ran before step 6");
        assert!(!completed, "the record was not completed");
    }

    fn offering_everything() -> Mechanism {
        Mechanism::new("a mechanism offering everything", mechanism::REQUIRED)
    }

    #[test]
    fn a_failing_floor_self_test_refuses_before_the_real_child_is_forked() {
        let mut ran = 0;
        let (refusal, completed) = refuse_without_target(offering_everything, || {
            ran += 1;
            Err(Refusal::new(Code::FloorSelfTest, "the canary died"))
        });
        assert_eq!(ran, 1);
        assert_eq!(refusal.code, Code::FloorSelfTest);
        assert!(!completed, "the record was not completed");
    }

    #[test]
    fn a_missing_capability_refuses_before_anything_is_applied() {
        let mut probed = 0;
        let mut self_tested = 0;
        let (refusal, completed) = refuse_without_target(
            || {
                probed += 1;
                Mechanism::new("a mechanism offering nothing", &[])
            },
            || {
                self_tested += 1;
                Ok(())
            },
        );
        assert_eq!(probed, 1);
        assert_eq!(
            self_tested, 0,
            "the canary is never confined on a mechanism found wanting"
        );
        assert_eq!(refusal.code, Code::MechanismUnavailable);
        assert!(refusal.message().contains("process scoping"), "{refusal}");
        assert!(!completed, "the record was not completed");
    }

    #[test]
    fn a_target_requires_the_wall() {
        assert!(parse(&["playpen", "run", "--profile", "p", "--agent", "claude", "x"]).is_err());
    }
}
