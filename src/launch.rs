//! The invocation contract ([spec §11]) and the launch sequence ([spec §4.2]), as far as the
//! walking skeleton goes: parse, open the run record, read the policy, resolve one profile's
//! roots, check the CWD, self-test the floor, compile the floor plus those roots, complete the
//! record, and run the target confined.
//!
//! [spec §11]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#11-invocation-contract
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence

use std::ffi::OsString;
use std::os::unix::process::CommandExt;
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
use crate::minter;
use crate::policy::{Policy, SearchPath, coherence, known};
use crate::present;
use crate::provision::Layout;
use crate::proxy;
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
    let args: Vec<OsString> = args.into_iter().collect();
    // Invoked under any name other than `playpen`, the binary is a **shim**: a thin front-end over
    // `run` that reads nothing of the caller's argv ([spec §11.3]).
    //
    // [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
    if let Some(name) = args.first().and_then(shim_name) {
        return shim_main(&name, &args[0], &args[1..], host, probe);
    }
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
    let (policy_file, loaded) = load(&policy, cwd.as_deref().ok(), record)?;
    run(
        Context {
            // `run` takes its profile explicitly and resolves no context of its own, so its chain
            // is the explicit step alone.
            explicit: Some(profile),
            env_profile: None,
            kind,
            shim: None,
        },
        &policy_file,
        &loaded,
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

/// The name playpen was invoked under, where that name is not `playpen` itself ([spec §11.3]).
/// An `argv[0]` with no file name, or one that is not UTF-8, is no shim name: there is nothing to
/// look up in `shims`.
///
/// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
fn shim_name(argv0: &OsString) -> Option<String> {
    let name = Path::new(argv0).file_name()?.to_str()?;
    (name != "playpen").then(|| name.to_owned())
}

/// A shim invocation, from `argv[1]` on: everything the caller passed, opaque, with the shim's own
/// `flags` prepended ([spec §11.3]).
fn shim_main(
    name: &str,
    argv0: &OsString,
    argv: &[OsString],
    host: Host,
    probe: impl FnOnce() -> Mechanism,
) -> i32 {
    // Re-entry comes first, before anything is opened or recorded: inside an existing boundary the
    // shim `exec`s the target and never re-sandboxes, so there is no run of its own to record.
    if host
        .env
        .iter()
        .any(|(var, _)| var == environment::PLAYPEN_ACTIVE)
    {
        let refusal = reenter(name, argv, &host);
        return refuse(&refusal, None);
    }
    let run = match RunId::allocate() {
        Ok(run) => run,
        Err(refusal) => return refuse(&refusal, None),
    };
    let mut record = match RunRecord::open(&run, host.state.as_deref()) {
        Ok(record) => record,
        Err(refusal) => return refuse(&refusal, Some(&run)),
    };
    match shim_invoke(name, argv0, argv, host, &mut record, probe) {
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

fn shim_invoke(
    name: &str,
    argv0: &OsString,
    argv: &[OsString],
    host: Host,
    record: &mut RunRecord,
    probe: impl FnOnce() -> Mechanism,
) -> Result<i32, Refusal> {
    let Host {
        cwd,
        state,
        policies,
        profile,
        executable,
        env,
    } = host;
    // A shim takes no option of playpen's: every argument it was given belongs to the target.
    let policy = policies.locate(None)?;
    let (policy_file, loaded) = load(&policy, cwd.as_deref().ok(), record)?;
    let shim = loaded.policy.shims.get(name).ok_or_else(|| {
        Refusal::new(
            Code::ShimUnknown,
            format!(
                "playpen was invoked as {name:?}, which {} declares no shim for; declared \
                 shims: {}",
                policy_file.display(),
                known(loaded.policy.shims.keys()),
            ),
        )
    })?;
    let kind = kind::require(&shim.kind)?;
    record.kind(&shim.kind);
    // The target is the absolute path in `target`, resolved at launch. playpen never searches
    // `PATH`: a shim on `PATH` that searched `PATH` would find itself.
    let target = resolve_target(name, &shim.target)?;
    // The shim's flags are prepended to the caller's argv, and playpen reads neither.
    let mut full = Vec::with_capacity(1 + shim.flags.len() + argv.len());
    full.push(target.into_os_string());
    full.extend(shim.flags.iter().map(OsString::from));
    full.extend_from_slice(argv);
    run(
        Context {
            // A pinned profile is the chain's explicit step; without one the chain decides.
            explicit: shim.profile.clone(),
            env_profile: profile,
            kind,
            // Self-integrity extends to the link playpen was invoked through ([spec §11.7]): it
            // runs unconfined on the next launch exactly as the executable does.
            //
            // [spec §11.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#117-self-integrity
            shim: Some(invoking_link(
                argv0,
                name,
                &integrity::executable(&executable)?,
                cwd.as_deref().ok(),
                &env,
            )?),
        },
        &policy_file,
        &loaded,
        &full,
        cwd,
        state.as_deref(),
        executable,
        &env,
        record,
        probe,
        self_test::floor,
    )
}

/// The shim's `target`, resolved at launch. Never a `PATH` search ([spec §11.3]).
fn resolve_target(name: &str, target: &Path) -> Result<PathBuf, Refusal> {
    let missing = |detail: String| {
        Refusal::new(
            Code::RootMissing,
            format!("shim:{name}.target is {}, which {detail}", target.display()),
        )
    };
    if !target.is_absolute() {
        return Err(missing(
            "is not an absolute path; playpen never searches PATH for a shim's target".into(),
        ));
    }
    // Resolved only to show it is there: a dangling link refuses. The path handed to `exec` is the
    // one the policy declared, not what it resolved to, because `argv[0]` is the target's own
    // business — a multicall binary reached through a stable link decides what it is from the name
    // it was invoked by ([ADR 0019]).
    //
    // [ADR 0019]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0019-a-homebrew-toolchain-is-a-keg-list-and-a-shim-is-the-playpen-binary.md
    target
        .canonicalize()
        .map_err(|e| missing(format!("is unavailable: {e}")))?;
    Ok(target.to_owned())
}

/// The link playpen was invoked through, for self-integrity ([spec §11.7]).
///
/// It cannot be read back from the running executable: an `exec` of a symlink leaves
/// `/proc/self/exe` — and macOS's equivalent — naming what the link resolved to, never the link.
/// So it is found the way the caller found it. Invoked by a path, `argv[0]` *is* the link. Invoked
/// by a bare name, the caller's `PATH` found it, and the first entry of that `PATH` named `name`
/// which resolves to this executable is the one that ran. That is a `PATH` search for the *link*,
/// which is a different thing from searching `PATH` for a shim's `target` ([spec §11.3]) — the
/// target is always the absolute path the policy declares.
///
/// A link that cannot be found is `refusal.integrity.unresolvable`: integrity that cannot be shown
/// is refused, never assumed.
///
/// [spec §11.7]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#117-self-integrity
/// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
pub fn invoking_link(
    argv0: &OsString,
    name: &str,
    executable: &Path,
    cwd: Option<&Path>,
    env: &[(OsString, OsString)],
) -> Result<PathBuf, Refusal> {
    let unresolvable = |detail: String| {
        Refusal::new(
            Code::IntegrityUnresolvable,
            format!(
                "the shim link playpen was invoked through cannot be found, so it cannot be shown \
                 unwritable: {detail}"
            ),
        )
    };
    let argv0 = Path::new(argv0);
    if argv0.parent().is_some_and(|parent| parent != Path::new("")) {
        return Ok(match cwd {
            Some(cwd) => cwd.join(argv0),
            None => argv0.to_owned(),
        });
    }
    let resolved = executable
        .canonicalize()
        .map_err(|e| unresolvable(format!("{}: {e}", executable.display())))?;
    let path = env
        .iter()
        .rev()
        .find(|(var, _)| var == "PATH")
        .map(|(_, value)| value.clone())
        .ok_or_else(|| unresolvable("the environment names no PATH".into()))?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|link| link.canonicalize().is_ok_and(|target| target == resolved))
        .ok_or_else(|| {
            unresolvable(format!(
                "no PATH entry named {name:?} resolves to {}",
                resolved.display()
            ))
        })
}

/// A shim invoked inside an existing boundary: `exec` the target in place, where the phantom, the
/// proxy and the manifest all still hold ([spec §11.3]). It never re-sandboxes, keeps the outer
/// run's environment, and opens no record of its own.
///
/// Returns only on failure: a successful `exec` replaces this process.
fn reenter(name: &str, argv: &[OsString], host: &Host) -> Refusal {
    // The policy is read again from inside, because a shim's target lives nowhere else. A boundary
    // that grants no read of the policy cannot re-enter, and says so.
    let resolved = host
        .policies
        .locate(None)
        .and_then(|path| Policy::load(&path));
    let loaded = match resolved {
        Ok(loaded) => loaded,
        Err(refusal) => return refusal,
    };
    let Some(shim) = loaded.policy.shims.get(name) else {
        return Refusal::new(
            Code::ShimUnknown,
            format!(
                "playpen was invoked as {name:?} inside a boundary, and {} declares no shim for \
                 it; declared shims: {}",
                loaded.path.display(),
                known(loaded.policy.shims.keys()),
            ),
        );
    };
    let target = match resolve_target(name, &shim.target) {
        Ok(target) => target,
        Err(refusal) => return refusal,
    };
    let mut full: Vec<OsString> = shim.flags.iter().map(OsString::from).collect();
    full.extend_from_slice(argv);
    // The outer run's environment is this process's own, so `exec` keeps it whole: nothing is
    // constructed a second time.
    let error = std::process::Command::new(&target).args(&full).exec();
    Refusal::new(
        Code::TargetExec,
        format!("cannot exec the target {}: {error}", target.display()),
    )
}

/// Read the policy at `path`, recording the absolute path it was read from first, so a stored
/// record names the file whatever directory it is read from.
fn load(
    path: &Path,
    cwd: Option<&Path>,
    record: &mut RunRecord,
) -> Result<(PathBuf, crate::policy::Loaded), Refusal> {
    let policy_file = match cwd {
        Some(cwd) => cwd.join(path),
        None => path.to_owned(),
    };
    record.policy(&policy_file);
    let loaded = Policy::load(path)?;
    Ok((policy_file, loaded))
}

/// What the invocation decided before the launch sequence proper: how the profile is chosen, the
/// stated kind, and the shim link this playpen was reached through, if any.
struct Context {
    /// The chain's explicit step: `--profile`, or a shim's pinned `profile`.
    explicit: Option<String>,
    /// `PLAYPEN_PROFILE`, the chain's second step. `None` for `run`, which resolves no context.
    env_profile: Option<OsString>,
    kind: &'static Kind,
    /// The link playpen was invoked through, which self-integrity holds unwritable beside the
    /// executable and the policy.
    shim: Option<PathBuf>,
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
    context: Context,
    policy_file: &Path,
    loaded: &crate::policy::Loaded,
    argv: &[OsString],
    cwd: std::io::Result<PathBuf>,
    state: Option<&Path>,
    executable: std::io::Result<PathBuf>,
    env: &[(OsString, OsString)],
    record: &mut RunRecord,
    probe: impl FnOnce() -> Mechanism,
    floor_self_test: impl FnOnce() -> Result<(), Refusal>,
) -> Result<i32, Refusal> {
    let Context {
        explicit,
        env_profile,
        kind,
        shim,
    } = context;
    // Step 4.
    let inputs = select::Inputs {
        explicit: explicit.as_deref(),
        env: env_profile.as_deref(),
        cwd: cwd.as_deref().ok(),
    };
    let (trace, selected) = select::select(&loaded.policy, inputs);
    record.selection(&trace, selected.as_deref().ok());
    let profile = selected?;
    let profile = profile.as_str();
    let selected = loaded.policy.profiles.get(profile).ok_or_else(|| {
        Refusal::new(
            Code::SelectionUnknownProfile,
            format!("profile {profile:?} is not in the policy"),
        )
    })?;
    // Step 5.
    coherence::check(loaded)?;
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
    // Nothing that runs unconfined on the next launch is writable from inside this one: the policy,
    // the executable, and the link this playpen was invoked through.
    integrity::check(
        &caps,
        policy_file,
        &integrity::executable(&executable)?,
        shim.as_deref(),
    )?;
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
    let mut provisioned = layout.provision()?;
    // Step 10: every credential this profile's routes resolve, minted unconfined on the host
    // before anything is confined ([spec §7.2]). A failure refuses the whole run: launching
    // without the credential would produce a run that works for ten minutes and then fails at the
    // first push. Held here, in the supervisor, for as long as the run lasts — the proxy is what
    // uses it (#86), and nothing of it crosses the boundary.
    //
    // Before the manifest, as the sequence has it: the manifest states the route table, and a
    // refusal here must not have rewritten the profile's rendered entry point, which outlives the
    // run that wrote it.
    //
    // [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
    let mut credentials = minter::resolve(&loaded.policy, profile, selected)?;
    record.credentials(credentials.iter().map(minter::Minting::recorded).collect());
    // Step 11: the proxy exists **iff at least one credential route resolves** ([spec §6.2]). It
    // binds here, before the fork, so the port the child's environment names is one that already
    // exists; it starts serving once there is a child to tear down if it dies.
    //
    // [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
    //
    // The session CA is generated here too, its certificate written into the run scratch, and the
    // run's one phantom made: the CA's private key never leaves this process ([spec §7.3]).
    //
    // [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
    let (bound, broker) = match credentials.is_empty() {
        true => (None, None),
        false => {
            let bound = proxy::bind()?;
            // Read once, and used twice: the broker verifies destinations against these, and the
            // bundle the child's `SSL_CERT_FILE` names holds them beside the session CA, so what
            // the child trusts cannot drift from what the supervisor does ([#140]).
            //
            // [#140]: https://github.com/firefly-engineering/playpen/issues/140
            let roots = proxy::Roots::host()?;
            // Stated outward, because the launching environment decided it with no policy field
            // and no flag ([ADR 0030], [spec §18]). Taken from the load's own answer rather than
            // from a second look at the environment, which could disagree with it.
            //
            // [ADR 0030]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0030-the-hosts-own-trust-store-is-what-the-host-says-it-is.md
            // [spec §18]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#18-named-residuals
            record.upstream_roots(roots.provenance());
            let ca = proxy::ca()?;
            let certificate = layout.scratch().join(proxy::CA_FILE);
            ca.write(&certificate)?;
            let bundle = layout.scratch().join(proxy::BUNDLE_FILE);
            roots.bundle(&ca, &bundle)?;
            let phantom = proxy::Phantom::random()?;
            let set = proxy::Set {
                addr: bound.addr(),
                ca: certificate,
                bundle,
                phantom: phantom.clone(),
                deliveries: credentials
                    .iter()
                    .map(|minted| minted.delivery.clone())
                    .collect(),
            };
            let routes = credentials.iter().map(minter::Minting::route).collect();
            let serving = std::sync::Arc::new(proxy::Broker::new(ca, phantom, routes, &roots)?);
            (Some((bound, serving)), Some(set))
        }
    };
    // Step 12: the capability set compiles on this mechanism.
    backend::check(&caps)?;
    // Step 13: the manifest, written on every run even when nothing is provisioned
    // ([spec §13.1]). It is derived from the same resolution pass as the capability set, so what
    // the agent is told and what the kernel enforces cannot drift.
    //
    // A launch always states a kind, so it always has an agent state directory to name.
    //
    // [spec §13.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#131-form
    let agent_state = layout.agent_state().ok_or_else(|| {
        Refusal::new(
            Code::StateIo,
            "a launch states a kind, so it has an agent state directory; this one has none"
                .to_string(),
        )
    })?;
    let manifest = Manifest::new(&loaded.policy, profile, selected, &layout, &agent_state);
    manifest.write(&layout.manifest())?;
    // The kind's presentation adapter, rendered into the kind's instruction entry point inside
    // that directory ([spec §13.3]). Nothing is rendered for a kind whose entry point playpen does
    // not know.
    //
    // [spec §13.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#133-presentation
    if let Some(rendered) = present::render(&manifest, kind, &agent_state, &layout.imports()) {
        rendered.write()?;
    }
    // Step 14.
    let env = resolve::environment(
        &loaded.policy,
        profile,
        selected,
        env,
        &layout,
        Some(kind),
        broker.as_ref(),
    );
    record.launch(&caps, backend::denial_tag(record.id()))?;
    let run = record.id().clone();
    // Both callbacks write the record, and only one of them ever fires, but the borrow checker
    // cannot see that from two closures: a cell is cheaper than a seam for it.
    let record = std::cell::RefCell::new(record);
    // The proxy serves from the moment the child exists, which is also the moment there is
    // something to tear down if it stops ([spec §6.2]). Held here, so teardown's own order holds:
    // the proxy stops before the scratch and the ephemeral areas go with `_provisioned`.
    //
    // [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
    let serving = std::cell::RefCell::new(None);
    // Step 17's other half: re-mint near expiry, for as long as the child runs. It replaces each
    // secret in the handle the proxy already holds, so nothing of the child's environment moves —
    // what the child holds is the phantom.
    let renewing = std::cell::RefCell::new(None);
    let status = child::run_confined(
        &caps,
        argv,
        &env,
        &run,
        || Ok(()),
        |pid| {
            record.borrow_mut().spawned(pid);
            if let Some((bound, broker)) = bound {
                *serving.borrow_mut() = Some(bound.serve(broker, pid));
            }
            *renewing.borrow_mut() = Some(minter::renew(&loaded.policy, &credentials));
        },
        |fault| record.borrow_mut().fault(fault),
    );
    // Step 18, in order: the revokers run while the proxy is still up, then the proxy stops, then
    // the scratch and the ephemeral areas go with `_provisioned`. **No teardown failure changes
    // the exit status** — `status` is already decided, and every failure below goes to the record
    // and nowhere else.
    //
    // Renewal stops before the revokers: a credential being revoked must not be re-minted behind
    // the revoker's back. What it did goes into the record, because the record is the only place
    // a credential that lapsed mid-run is ever reported.
    if let Some(mut renewing) = renewing.into_inner() {
        let renewed = renewing.stop();
        let mut record = record.borrow_mut();
        for lapsed in &renewed.lapsed {
            record.lapsed(lapsed.clone());
        }
        // Written again with each credential's expiry as it now stands: the first write named the
        // expiry the launch minted, which a renewal has since replaced.
        if !renewed.expiry.is_empty() {
            renewed.apply(&mut credentials);
            record.credentials(credentials.iter().map(minter::Minting::recorded).collect());
        }
    }
    minter::revoke_all(&loaded.policy, &credentials, &mut record.borrow_mut());
    if let Some(mut serving) = serving.into_inner() {
        serving.stop();
    }
    // Last: the ephemeral areas and the run scratch. Removed here rather than left to the drop at
    // the end of this function, so what could not be removed reaches the record while it is still
    // open — the drop stays as the backstop for every path that returns before teardown.
    for failure in provisioned.remove() {
        record.borrow_mut().torn_down(failure);
    }
    status
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
        let loaded = Policy::load(&policy).expect("the policy parses");
        let refusal = run(
            Context {
                explicit: Some("p".into()),
                env_profile: None,
                kind: kind::require("claude").expect("a known kind"),
                shim: None,
            },
            &policy,
            &loaded,
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
