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
    let inputs = select::Inputs {
        explicit: args.profile.as_deref(),
        env: host.profile.as_deref(),
        cwd: cwd.as_deref().or(here),
    };
    let (trace, selected) = select::select(&loaded.policy, inputs);
    let name = selected?;
    coherence::check(&loaded)?;
    let caps = resolve::capabilities(&loaded.policy, &name)?;
    record::refuse_if_reachable(host.state.as_deref(), &caps.paths)?;
    crate::backend::check(&caps)?;
    Ok(Resolved::new(absolute(&path), trace, name, &caps))
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
    )
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
    let fields = [
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
    ];
    for (name, value) in fields {
        writeln!(out, "{name:<9} {}", OneLine(&value))?;
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

/// The exact platform command that pulls the denials of the run `record` holds, or `None` for a run
/// that never launched ([spec §14.2]).
///
/// On macOS the query is the run's window, widened to the whole seconds `log show` takes, filtered
/// to the run's denial tag, which the kernel logs with every denial in the confined tree
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
    let mut command = format!("/usr/bin/log show --start '{}'", log_time(launched / 1000));
    if let Some(ended) = record.ended_at_unix_ms {
        command += &format!(" --end '{}'", log_time(ended.div_ceil(1000)));
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

/// On Linux the query waits on the Landlock domain id, which covers the child's whole tree where a
/// pid does not, and which the record does not hold yet
/// ([#98](https://github.com/firefly-engineering/playpen/issues/98)).
#[cfg(target_os = "linux")]
fn denials(_record: &Record) -> Option<String> {
    None
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
fn timestamp(unix_ms: u64) -> String {
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
                "/usr/bin/log show --start '2026-10-05 07:51:33+0000' \
                 --end '2026-10-05 07:51:34+0000' \
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
    /// holds. The window is widened to whole seconds, the precision `log show` takes, and given in
    /// UTC so that it means the same instant wherever the command is pasted.
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
                "/usr/bin/log show --start '2026-10-05 07:51:33+0000' \
                 --end '2026-10-05 07:51:34+0000' \
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
