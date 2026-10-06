//! `playpen explain` ([spec §14.2]). Three questions:
//!
//! - `explain [<profile>] [--cwd <path>] [--policy <path>]`: which profile the selection chain
//!   picks, and the boundary it resolves to — the **resolved form** ([`Resolved`]), every entry
//!   with its provenance. It refuses as `run` would, for the same reasons.
//! - `explain --run <id>`: replay a stored run record.
//! - `explain --list`: the runs the ring holds.
//!
//! `explain` launches nothing, so it opens no record of its own ([spec §4.2]) and takes no place
//! in the ring. It is a report, so it writes to stdout; its refusals are lines on stderr, like a
//! launch's.
//!
//! Each human form is rendered from the same value its `--json` form prints whole: the
//! [`Resolved`] form, or the [`Record`] beside the exact platform command that pulls the run's
//! denials ([`denials`]).
//!
//! [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::capability::{Access, Class, Scope};
use crate::code::Code;
use crate::launch::Host;
use crate::policy::{Policy, coherence};
use crate::provision::Layout;
use crate::proxy;
use crate::record::{self, Record, RunId};
use crate::refusal::{OneLine, Refusal};
use crate::resolve::{self, NetworkMode, Resolved};
use crate::select::{self, Outcome, Source, Step};

/// What `explain` was asked: a profile's boundary by default, or one of `--run` and `--list`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// The profile to resolve. Without one, the selection chain decides: `PLAYPEN_PROFILE`, then
    /// the working directory.
    #[arg(conflicts_with_all = ["run", "list"])]
    profile: Option<String>,
    /// Select as if run from this directory.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["run", "list"])]
    cwd: Option<PathBuf>,
    #[arg(long, value_name = "PATH", conflicts_with_all = ["run", "list"])]
    policy: Option<PathBuf>,
    /// Resolve as the shim of this name would: its kind, its pinned profile if it has one, and
    /// the argv it injects ([spec §11.3]).
    ///
    /// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
    #[arg(long, value_name = "NAME", conflicts_with_all = ["run", "list", "profile"])]
    shim: Option<String>,
    /// Replay the record of one run.
    #[arg(long, value_name = "ID", conflicts_with = "list")]
    run: Option<String>,
    /// List the runs the ring holds, most recent first.
    #[arg(long)]
    list: bool,
    /// Print the JSON form the human one is rendered from.
    #[arg(long)]
    json: bool,
}

/// Answer `args` on `host`, writing the report to `out`. A report that cannot be written has
/// nowhere else to go, so a write error is dropped.
pub fn explain(args: &Args, host: &Host, out: &mut impl Write) -> Result<(), Refusal> {
    let state = host.state.as_deref();
    let written = match &args.run {
        None if !args.list => {
            let resolved = resolve(args, host)?;
            if args.json {
                json(&resolved, out)
            } else {
                render_resolved(&resolved, out)
            }
        }
        Some(id) => {
            let id = RunId::parse(id)
                .ok_or_else(|| Refusal::new(Code::RunUnknown, format!("{id:?} is not a run id")))?;
            let record = record::read(state, &id)?;
            let replay = Replay {
                denials: denials(&record),
                record: &record,
            };
            if args.json {
                json(&replay, out)
            } else {
                render_run(&replay, out)
            }
        }
        None => {
            let records = record::list(state)?;
            if args.json {
                json(&records, out)
            } else {
                records.iter().try_for_each(|r| render_summary(r, out))
            }
        }
    };
    let _ = written.and_then(|()| out.flush());
    Ok(())
}

/// The boundary `args` selects on `host`: the launch sequence's steps 3 to 6 that need no
/// mechanism, run as `run` runs them, so `explain` refuses where `run` would.
fn resolve(args: &Args, host: &Host) -> Result<Resolved, Refusal> {
    let path = host.policies.locate(args.policy.as_deref())?;
    let loaded = Policy::load(&path)?;
    let here = host.cwd.as_deref().ok();
    // A relative `--cwd` or policy is relative to where `explain` was run.
    let absolute = |path: &Path| match here {
        Some(here) => here.join(path),
        None => path.to_owned(),
    };
    let cwd = args.cwd.as_deref().map(absolute);
    // Named with `--shim`, the shim decides what `run` would be given: its kind, its pinned
    // profile if it has one, and the argv it injects ([spec §11.3]).
    //
    // [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
    let shim = match &args.shim {
        Some(name) => Some((name.as_str(), shim_named(&loaded, name)?)),
        None => None,
    };
    let kind = match shim {
        Some((_, shim)) => Some(crate::kind::require(&shim.kind)?),
        None => None,
    };
    let inputs = select::Inputs {
        explicit: args
            .profile
            .as_deref()
            .or_else(|| shim.and_then(|(_, shim)| shim.profile.as_deref())),
        env: host.profile.as_deref(),
        cwd: cwd.as_deref().or(here),
    };
    let (trace, selected) = select::select(&loaded.policy, inputs);
    let name = selected?;
    coherence::check(&loaded)?;
    // `explain` launches nothing, so it states the paths any run would be provisioned.
    let state = host.state.as_deref().ok_or_else(record::no_state)?;
    let selected = &loaded.policy.profiles[&name];
    // Resolved as `run` resolves it. Before any run the directory may not exist, and the first run
    // creates it where it is named, so the path as named is the one that run would resolve.
    let state = state.canonicalize().unwrap_or_else(|_| state.to_owned());
    let layout = Layout::unlaunched(&state, &loaded.policy, &name, selected, kind)
        .with_home(crate::environment::home(&host.env).as_deref());
    let caps = resolve::capabilities(&loaded.policy, &name, &layout)?;
    let executable = crate::integrity::executable(&host.executable)?;
    // The shim link, where `--shim` names one and this host has it installed. `explain` was not
    // invoked through it, so an absent link is not a refusal here, where in a shim launch it is:
    // the link that launch ran through must exist, because it ran.
    let link = shim.and_then(|(name, _)| {
        crate::launch::invoking_link(
            &std::ffi::OsString::from("playpen"),
            name,
            &executable,
            here,
            &host.env,
        )
        .ok()
    });
    crate::integrity::check(&caps, &absolute(&path), &executable, link.as_deref())?;
    record::refuse_if_reachable(host.state.as_deref(), &caps.paths)?;
    // What a run would provision does not exist until a run creates it, and the backend compiles
    // only paths that do, so the budget is checked without it: a handful of entries against a
    // ceiling of thousands, and `run` checks it whole.
    let mut provisioned = caps.clone();
    provisioned
        .paths
        .retain(|grant| !grant.state_derived || grant.path.exists());
    crate::backend::check(&provisioned)?;
    // `explain` of a profile alone names no kind, and a kind is never inferred ([spec §11.2]), so
    // the kind table's entries show only where a shim named one.
    //
    // [spec §11.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#112-kind
    let env = resolve::environment(
        &loaded.policy,
        &name,
        selected,
        &host.env,
        &layout,
        kind,
        None,
    );
    // The injected argv, with provenance, shown outward only: it is never projected inward, and
    // the agent already holds its own argv ([spec §9.3]).
    //
    // [spec §9.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#93-inward-and-outward
    let argv = match shim {
        Some((name, shim)) => {
            let mut argv = vec![resolve::InjectedArg {
                value: shim.target.display().to_string(),
                from: format!("shim:{name}.target"),
            }];
            argv.extend(
                shim.flags
                    .iter()
                    .enumerate()
                    .map(|(i, flag)| resolve::InjectedArg {
                        value: flag.clone(),
                        from: format!("shim:{name}.flags[{i}]"),
                    }),
            );
            argv
        }
        None => Vec::new(),
    };
    // The route table the broker would serve ([spec §14.2]). Read from the policy, never minted:
    // `explain` launches nothing, so it reaches no keystore and states no token.
    //
    // [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
    let routes = resolve::routes(&loaded.policy, &name, selected);
    Ok(Resolved::new(absolute(&path), trace, name, &caps, &env)
        .with_argv(argv)
        .with_routes(routes))
}

/// The shim named `name`, or the refusal that the policy declares none ([spec §11.3]).
///
/// [spec §11.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#113-shims
fn shim_named<'a>(
    loaded: &'a crate::policy::Loaded,
    name: &str,
) -> Result<&'a crate::policy::Shim, Refusal> {
    loaded.policy.shims.get(name).ok_or_else(|| {
        Refusal::new(
            Code::ShimUnknown,
            format!("{} declares no shim named {name:?}", loaded.path.display()),
        )
    })
}

/// The resolved form, section by section: the selection trace, then the capability set.
fn render_resolved(resolved: &Resolved, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "policy    {}",
        OneLine(&resolved.policy.display().to_string())
    )?;
    writeln!(out, "profile   {}", OneLine(&resolved.profile))?;
    render_selection(&resolved.selection, out)?;
    writeln!(out, "paths")?;
    for path in &resolved.paths {
        render_grant(&path.path, path.access, path.scope, &path.from, out)?;
    }
    for exclusion in &resolved.exclusions {
        let classes: Vec<_> = exclusion
            .classes
            .iter()
            .map(|class| match class {
                Class::Read => "read",
                Class::Execute => "execute",
                Class::Write => "write",
            })
            .collect();
        writeln!(
            out,
            "  exclude {} {}  (from {})",
            classes.join(","),
            OneLine(&exclusion.path.display().to_string()),
            OneLine(&exclusion.from)
        )?;
    }
    for service in &resolved.mach_services {
        writeln!(
            out,
            "  mach-lookup       {}  (from {})",
            OneLine(&service.name),
            OneLine(&service.from)
        )?;
    }
    let mode = match resolved.network.mode {
        NetworkMode::AllowAll => "allow-all",
    };
    writeln!(
        out,
        "network   {mode}  (from {})",
        OneLine(&resolved.network.from)
    )?;
    writeln!(out, "env")?;
    for var in &resolved.env {
        let var_line = match &var.value {
            Some(value) => format!("{}={value}", var.name),
            None => format!("{} (inherited)", var.name),
        };
        writeln!(
            out,
            "  {}  (from {})",
            OneLine(&var_line),
            OneLine(&var.from)
        )?;
    }
    if !resolved.argv.is_empty() {
        writeln!(out, "argv")?;
        for arg in &resolved.argv {
            writeln!(
                out,
                "  {}  (from {})",
                OneLine(&arg.value),
                OneLine(&arg.from)
            )?;
        }
    }
    render_routes(
        &resolved.routes,
        resolved.upstream_roots,
        resolved.unix_socket_regime.as_deref(),
        out,
    )
}

/// The resolved route table ([spec §14.2]): each route's destination, the minter that makes its
/// credential and the variable the phantom is delivered in, then each endpoint rule set it
/// carries with its rules. Never a token — there is none in the value this is rendered from.
///
/// The line is always written, even with no route, because "no route resolves, and so no proxy
/// runs" is the answer to a question an operator asks.
///
/// `upstream_roots` is where the broker would verify destinations from ([ADR 0030]). It belongs
/// here rather than beside the capability set because it is the *broker's* trust basis, and the
/// broker exists only where a route does — so with no route there is nothing to state.
///
/// [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
/// [ADR 0030]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0030-the-hosts-own-trust-store-is-what-the-host-says-it-is.md
fn render_routes(
    routes: &[resolve::ResolvedRoute],
    upstream_roots: Option<proxy::Provenance>,
    unix_socket_regime: Option<&str>,
    out: &mut impl Write,
) -> io::Result<()> {
    // Before the routes, and whatever the routes are: a unix-socket credential oracle hands out
    // the means with no secret crossing the boundary, so it is reachable on a profile that
    // resolves no route at all ([spec §6.3]).
    //
    // [spec §6.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#63-credential-oracles
    if let Some(regime) = unix_socket_regime {
        // The same label the replayed form gives it, so one field does not read as two.
        writeln!(out, "regime    {}", OneLine(regime))?;
    }
    writeln!(out, "routes")?;
    if routes.is_empty() {
        return writeln!(out, "  none, so no proxy runs");
    }
    if let Some(provenance) = upstream_roots {
        writeln!(out, "  upstream roots  {}", render_provenance(provenance))?;
    }
    for route in routes {
        let line = format!(
            "{}{}  deliver {}",
            route.host, route.path_prefix, route.delivery_env
        );
        writeln!(out, "  {}  (from {})", OneLine(&line), OneLine(&route.from))?;
        if route.endpoints.is_empty() {
            writeln!(out, "    unrestricted")?;
        }
        for set in &route.endpoints {
            writeln!(
                out,
                "    endpoints {}  (from {})",
                OneLine(&set.name),
                OneLine(&set.from)
            )?;
            for rule in &set.rules {
                let rule = format!("{} {}", rule.method, rule.path);
                writeln!(out, "      allow {}", OneLine(&rule))?;
            }
        }
    }
    Ok(())
}

/// Where the broker's upstream roots came from, as one phrase ([ADR 0030]).
///
/// The variables are **named**, not summarised as "the environment": an operator who has to find
/// out which of the two is set has been told only that something is.
///
/// [ADR 0030]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0030-the-hosts-own-trust-store-is-what-the-host-says-it-is.md
fn render_provenance(provenance: proxy::Provenance) -> String {
    match provenance {
        proxy::Provenance::Platform => "the platform store".to_owned(),
        proxy::Provenance::Environment {
            ssl_cert_file,
            ssl_cert_dir,
        } => {
            let named: Vec<&str> = [
                ("SSL_CERT_FILE", ssl_cert_file),
                ("SSL_CERT_DIR", ssl_cert_dir),
            ]
            .into_iter()
            .filter_map(|(name, set)| set.then_some(name))
            .collect();
            format!("the environment ({})", named.join(", "))
        }
    }
}

/// The selection trace, one step a line.
fn render_selection(trace: &[Step], out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "selection")?;
    for step in trace {
        let source = match step.step {
            Source::Explicit => "explicit",
            Source::Environment => "environment",
            Source::Cwd => "cwd",
        };
        let outcome = match &step.outcome {
            Outcome::Skipped { reason } => format!("skipped   {reason}"),
            Outcome::Selected {
                profile,
                prefix: Some(prefix),
            } => format!("selected  {profile} (prefix {})", prefix.display()),
            Outcome::Selected { profile, .. } => format!("selected  {profile}"),
            Outcome::Refused { code } => format!("refused   {code}"),
        };
        writeln!(out, "  {source:<11} {}", OneLine(&outcome))?;
    }
    Ok(())
}

/// One path grant on one line, whatever bytes its path carries.
fn render_grant(
    path: &Path,
    access: Access,
    scope: Scope,
    from: &str,
    out: &mut impl Write,
) -> io::Result<()> {
    let access = match access {
        Access::Read => "read",
        Access::ReadWrite => "readwrite",
    };
    let scope = match scope {
        Scope::Subtree => "subtree",
        Scope::Literal => "literal",
    };
    writeln!(
        out,
        "  {access:<9} {scope:<7} {}  (from {})",
        OneLine(&path.display().to_string()),
        OneLine(from)
    )
}

/// What `explain --run` reports: the stored record whole, and the command that pulls its denials.
#[derive(serde::Serialize)]
struct Replay<'a> {
    #[serde(flatten)]
    record: &'a Record,
    /// `null` where there is none: a run that never launched, or Linux, until its command is
    /// settled.
    denials: Option<String>,
}

fn json(value: &impl serde::Serialize, out: &mut impl Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value)?;
    writeln!(out)
}

/// One run, field by field. A field the launch never reached is `-`. Every value is shown on one
/// line, whatever bytes it carries.
fn render_run(replay: &Replay, out: &mut impl Write) -> io::Result<()> {
    let record = replay.record;
    let known = |value: Option<String>| value.unwrap_or_else(|| "-".into());
    let fields =
        [
            ("run", record.run.clone()),
            ("started", timestamp(record.started_at_unix_ms)),
            ("kind", known(record.kind.clone())),
            (
                "policy",
                known(record.policy.as_ref().map(|p| p.display().to_string())),
            ),
            ("profile", known(record.profile.clone())),
            ("launched", known(record.launched_at_unix_ms.map(timestamp))),
            ("pid", known(record.pid.map(|pid| pid.to_string()))),
            ("ended", known(record.ended_at_unix_ms.map(timestamp))),
            (
                "status",
                known(record.status.map(|status| status.to_string())),
            ),
            (
                "refusal",
                known(
                    record
                        .refusal
                        .as_ref()
                        .map(|r| format!("{}: {}", r.code, r.message)),
                ),
            ),
            // A crash is not a refusal, and a surface whose job is to state facts must not report it
            // as one ([ADR 0024]).
            //
            // [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
            (
                "fault",
                known(
                    record
                        .fault
                        .as_ref()
                        .map(|f| format!("{}: {}", f.code, f.message)),
                ),
            ),
            ("denials", known(replay.denials.clone())),
            // Which regime denied a unix-socket credential oracle, stated outward only: never in the
            // manifest, because it maps what is worth attacking ([spec §6.3]).
            //
            // [spec §6.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#63-credential-oracles
            ("regime", known(record.unix_socket_regime.clone())),
            (
                "trace",
                known(record.denial_trace.as_ref().map(
                    |file| match &record.denial_trace_unverified {
                        // A trace the bracketing self-test could not vouch for says so here too:
                        // presented as complete, it would read as "nothing was denied"
                        // ([spec §14.5]).
                        //
                        // [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
                        Some(why) => format!("{} (unverified: {why})", file.display()),
                        None => file.display().to_string(),
                    },
                )),
            ),
        ];
    for (name, value) in fields {
        writeln!(out, "{name:<9} {}", OneLine(&value))?;
    }
    // What teardown could not do, one sentence a line ([spec §4.2] step 18). Shown because no
    // teardown failure changes the exit status, so the record is the only place a revoker that
    // did not run is reported — and a credential nobody revoked lives until its TTL.
    //
    // [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
    for failure in &record.teardown {
        writeln!(out, "teardown  {}", OneLine(failure))?;
    }
    // And every credential that lapsed mid-run ([spec §7.2]). A separate line from `teardown`,
    // because a credential that stopped authenticating at minute ten is not a cleanup that
    // stumbled at the end, and the two send a reader to different places.
    //
    // [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
    for lapsed in &record.lapsed {
        writeln!(out, "lapsed    {}", OneLine(lapsed))?;
    }
    // A record written before selection was traced holds none.
    if let Some(trace) = &record.selection {
        render_selection(trace, out)?;
    }
    let Some(caps) = &record.capabilities else {
        return writeln!(out, "capabilities -");
    };
    writeln!(out, "capabilities")?;
    for grant in &caps.paths {
        render_grant(&grant.path, grant.access, grant.scope, &grant.from, out)?;
    }
    for service in &caps.mach_services {
        writeln!(out, "  mach-lookup       {}", OneLine(service))?;
    }
    Ok(())
}

/// How far the denials window reaches past the record's own times, in seconds. The unified log
/// stamps an entry from its own clock, not the wall clock the record reads, and the two disagree:
/// on a `macos-15` CI runner a descendant's denial, made after the record's launch time, was
/// logged at least 52ms before it, outside a window cut at that second
/// ([#142](https://github.com/firefly-engineering/playpen/issues/142)). One sample bounds the skew
/// from below only, so the margin is generous rather than measured. A tagged run's predicate
/// matches that run alone, so it costs `log show` only a little more to read; a pre-tag record's
/// pid filter admits ten more seconds in which another process could have held that pid.
#[cfg(target_os = "macos")]
const LOG_CLOCK_MARGIN_S: u64 = 5;

/// The exact platform command that pulls the denials of the run `record` holds, or `None` for a run
/// that never launched ([spec §14.2]).
///
/// On macOS the query is the run's window, widened to the whole seconds `log show` takes and by
/// [`LOG_CLOCK_MARGIN_S`] either side, filtered to the run's denial tag, which the kernel logs
/// with every denial in the confined tree
/// ([`crate::backend::denial_tag`]). A record written before runs were tagged holds none, and is
/// filtered to the child's pid instead, which misses its descendants' denials
/// ([#124](https://github.com/firefly-engineering/playpen/issues/124)). `/usr/bin/log` by path,
/// because `log` alone is a zsh builtin.
///
/// [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
#[cfg(target_os = "macos")]
fn denials(record: &Record) -> Option<String> {
    let pid = record.pid?;
    let launched = record.launched_at_unix_ms?;
    let start = (launched / 1000).saturating_sub(LOG_CLOCK_MARGIN_S);
    let mut command = format!("/usr/bin/log show --start '{}'", log_time(start));
    if let Some(ended) = record.ended_at_unix_ms {
        let end = ended.div_ceil(1000) + LOG_CLOCK_MARGIN_S;
        command += &format!(" --end '{}'", log_time(end));
    }
    // A tagged run is found by its tag, which its whole tree logs; an older one by the child's pid.
    // The stored tag is printed into a shell command, so it is used only when it is the one this
    // run's id makes: an edited or damaged record falls back to the pid rather than injecting.
    let made = RunId::parse(&record.run).and_then(|run| crate::backend::denial_tag(&run));
    let mark = match (&record.denial_tag, made) {
        (Some(stored), Some(made)) if *stored == made => made,
        _ => format!("({pid})"),
    };
    command +=
        &format!(" --predicate 'sender == \"Sandbox\" AND eventMessage CONTAINS \"{mark}\"'");
    Some(command)
}

/// On Linux the query filters on the Landlock **domain id**, which covers the child's whole tree
/// where a pid does not ([spec §14.2]). The record holds one only for a run that was traced: the
/// id is learned by reading the journal, and a run that asked for no trace never read it, so
/// `null` there is the honest answer rather than a command that would return everything.
///
/// The id is printed into a shell command, so it is used only when it reads as one — a Landlock
/// domain id is hex — and an edited or damaged record yields no command rather than an injection.
///
/// The filter is a **fixed string** the operator runs, which is what macOS's `CONTAINS` predicate
/// is too: the journal has no field holding the domain, so there is nowhere to match on. It is not
/// the tokenizer rule of [`crate::trace`], which governs what *playpen* reads a record with.
///
/// No clock margin, unlike macOS: journald stamps an entry from `CLOCK_REALTIME`, the same clock
/// the record's own timestamps come from, so the window needs no widening
/// ([#142](https://github.com/firefly-engineering/playpen/issues/142) was about the unified log's
/// separate time base).
///
/// [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
#[cfg(target_os = "linux")]
fn denials(record: &Record) -> Option<String> {
    let domain = record.landlock_domain.as_ref()?;
    if domain.is_empty() || !domain.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let launched = record.launched_at_unix_ms?;
    let mut command = format!(
        "journalctl --no-pager -o cat --since=@{} _TRANSPORT=audit",
        launched / 1000
    );
    if let Some(ended) = record.ended_at_unix_ms {
        command += &format!(" --until=@{}", ended.div_ceil(1000));
    }
    command += &format!(" | grep -F 'domain={domain}'");
    Some(command)
}

/// One line per run: its id, when it started, the kind and profile, and how it ended.
fn render_summary(record: &Record, out: &mut impl Write) -> io::Result<()> {
    // A fault first: a run that both ran and crashed has a status that means nothing.
    let outcome = match (&record.fault, &record.refusal, record.status) {
        (Some(fault), ..) => fault.code.clone(),
        (None, Some(refusal), _) => refusal.code.clone(),
        (None, None, Some(status)) => format!("status {status}"),
        // Running, or its playpen died before it could finish the record.
        (None, None, None) => "unfinished".to_string(),
    };
    let line = format!(
        "{}  {}  {}  {}  {outcome}",
        record.run,
        timestamp(record.started_at_unix_ms),
        record.kind.as_deref().unwrap_or("-"),
        record.profile.as_deref().unwrap_or("-"),
    );
    writeln!(out, "{}", OneLine(&line))
}

/// `unix_ms` as an RFC 3339 UTC timestamp, to the millisecond.
pub(crate) fn timestamp(unix_ms: u64) -> String {
    let (year, month, day, ms) = civil(unix_ms);
    let (hour, minute, second, milli) = clock(ms);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{milli:03}Z")
}

/// `unix_s` as `log show` reads a time, in UTC.
#[cfg(target_os = "macos")]
fn log_time(unix_s: u64) -> String {
    let (year, month, day, ms) = civil(unix_s * 1000);
    let (hour, minute, second, _) = clock(ms);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}+0000")
}

/// Milliseconds into a day as hours, minutes, seconds and milliseconds.
fn clock(ms: u64) -> (u64, u64, u64, u64) {
    (
        ms / 3_600_000,
        ms / 60_000 % 60,
        ms / 1_000 % 60,
        ms % 1_000,
    )
}

/// `unix_ms` as a UTC calendar date and the milliseconds into that day.
fn civil(unix_ms: u64) -> (i64, i64, i64, u64) {
    let (days, ms) = (unix_ms / 86_400_000, unix_ms % 86_400_000);
    // Days since 1970-01-01 to a proleptic Gregorian date, by Howard Hinnant's `civil_from_days`,
    // counting from 0000-03-01 so that the leap day ends each 400-year era.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = era * 400 + year_of_era + i64::from(month <= 2);
    (year, month, day, ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record of a run launched at `launched` and, if it has, ended at `ended`, as child `pid`.
    /// Written before denials were tagged, so it holds no tag.
    fn ran(pid: Option<i32>, launched: Option<u64>, ended: Option<u64>) -> Record {
        serde_json::from_value(serde_json::json!({
            "format": 1,
            "run": "01M45GQTY3RF111ZQ8WPJ5SKTY",
            "started_at_unix_ms": 1_791_186_693_000_u64,
            "kind": "claude",
            "policy": null,
            "profile": "p",
            "capabilities": null,
            "launched_at_unix_ms": launched,
            "pid": pid,
            "ended_at_unix_ms": ended,
            "status": null,
            "refusal": null,
        }))
        .expect("a record")
    }

    /// A traced run is queried by its **Landlock domain**, which every process in its tree is
    /// confined by, where a pid is one process ([spec §14.2]).
    ///
    /// [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
    #[test]
    #[cfg(target_os = "linux")]
    fn a_traced_runs_denials_are_queried_by_its_landlock_domain() {
        let mut record = ran(
            Some(82276),
            Some(1_791_186_693_069),
            Some(1_791_186_693_200),
        );
        record.landlock_domain = Some("195ba459b".into());
        let expected = concat!(
            "journalctl --no-pager -o cat --since=@1791186693 _TRANSPORT=audit",
            " --until=@1791186694 | grep -F 'domain=195ba459b'",
        );
        assert_eq!(denials(&record).as_deref(), Some(expected));
    }

    /// A run that asked for no trace never read the journal, so it learnt no domain, and the
    /// honest answer is no command rather than one that would return every run's denials.
    #[test]
    #[cfg(target_os = "linux")]
    fn an_untraced_runs_denials_have_no_command() {
        let record = ran(Some(82276), Some(1_791_186_693_069), None);
        assert_eq!(denials(&record), None);
    }

    /// The domain is printed into a shell command, so a record that does not read as one yields
    /// no command rather than an injection.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_domain_that_is_not_a_domain_yields_no_command() {
        for forged in ["", "'; rm -rf /; '", "195ba459b'"] {
            let mut record = ran(Some(82276), Some(1_791_186_693_069), None);
            record.landlock_domain = Some(forged.into());
            assert_eq!(denials(&record), None, "{forged:?}");
        }
    }

    /// A tagged run is queried by its tag, which every process in its tree logs its denials with,
    /// and not by the child's pid, which only the child does
    /// ([#124](https://github.com/firefly-engineering/playpen/issues/124)).
    #[test]
    #[cfg(target_os = "macos")]
    fn a_tagged_runs_denials_are_queried_by_its_tag() {
        let mut record = ran(
            Some(82276),
            Some(1_791_186_693_069),
            Some(1_791_186_693_200),
        );
        record.denial_tag = Some("playpen-run-01M45GQTY3RF111ZQ8WPJ5SKTY".into());
        assert_eq!(
            denials(&record).as_deref(),
            Some(
                "/usr/bin/log show --start '2026-10-05 07:51:28+0000' \
                 --end '2026-10-05 07:51:39+0000' \
                 --predicate 'sender == \"Sandbox\" AND \
                 eventMessage CONTAINS \"playpen-run-01M45GQTY3RF111ZQ8WPJ5SKTY\"'"
            )
        );
    }

    /// A tag that is not the one the run's id makes is never printed into the command: the record
    /// is a file anyone with the user's rights can edit, and the command is meant to be pasted.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_tag_the_run_id_does_not_make_falls_back_to_the_pid() {
        let mut record = ran(
            Some(82276),
            Some(1_791_186_693_069),
            Some(1_791_186_693_200),
        );
        record.denial_tag = Some("x\"' ; rm -rf ~ ; '".into());
        let command = denials(&record).expect("a command");
        assert!(command.ends_with("CONTAINS \"(82276)\"'"), "{command}");
        assert!(!command.contains("rm -rf"), "{command}");
    }

    /// A record written before denials were tagged is queried by the child's pid, the best it
    /// holds. The window is widened to whole seconds, the precision `log show` takes, and by
    /// [`LOG_CLOCK_MARGIN_S`] either side, and given in UTC so that it means the same instant
    /// wherever the command is pasted.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_denials_command_names_the_runs_window_and_pid() {
        let record = ran(
            Some(82276),
            Some(1_791_186_693_069),
            Some(1_791_186_693_200),
        );
        assert_eq!(
            denials(&record).as_deref(),
            Some(
                "/usr/bin/log show --start '2026-10-05 07:51:28+0000' \
                 --end '2026-10-05 07:51:39+0000' \
                 --predicate 'sender == \"Sandbox\" AND eventMessage CONTAINS \"(82276)\"'"
            )
        );
    }

    /// A run still going, or one that died of a fault, has no end: the query runs up to now.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_run_without_an_end_is_queried_up_to_now() {
        let record = ran(Some(82276), Some(1_791_186_693_069), None);
        let command = denials(&record).expect("a command");
        assert!(!command.contains("--end"), "{command}");
    }

    /// `denials` sits beside the record's own fields in `--json`, so a field of that name in the
    /// record would be silently shadowed.
    #[test]
    fn the_record_has_no_field_of_its_own_named_denials() {
        let record = serde_json::to_value(ran(None, None, None)).expect("JSON");
        assert!(record.get("denials").is_none(), "{record}");
    }

    /// Nothing ran confined, so there is nothing to pull.
    #[test]
    fn a_run_that_never_launched_has_no_denials_command() {
        assert_eq!(denials(&ran(None, None, None)), None);
    }

    /// The Linux command waits on the Landlock domain id, which the record does not hold yet.
    #[test]
    #[cfg(target_os = "linux")]
    fn linux_prints_no_denials_command_yet() {
        let record = ran(
            Some(82276),
            Some(1_791_186_693_069),
            Some(1_791_186_693_200),
        );
        assert_eq!(denials(&record), None);
    }

    #[test]
    fn timestamps_are_rfc_3339_utc() {
        assert_eq!(timestamp(0), "1970-01-01T00:00:00.000Z");
        // The ULID specification's own example time.
        assert_eq!(timestamp(1_469_918_176_385), "2016-07-30T22:36:16.385Z");
        assert_eq!(timestamp(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(timestamp(1_735_689_599_000), "2024-12-31T23:59:59.000Z");
        assert_eq!(timestamp(4_102_444_799_999), "2099-12-31T23:59:59.999Z");
    }
}
