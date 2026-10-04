//! `playpen explain --run` and `--list` ([spec §14.2]): replay the run records the ring holds.
//!
//! `explain` launches nothing, so it opens no record of its own ([spec §4.2]) and takes no place
//! in the ring. It is a report, so it writes to stdout; its refusals are lines on stderr, like a
//! launch's.
//!
//! The human form is rendered from the same [`Record`] the `--json` form prints whole. The exact
//! platform command that pulls a run's denials is not printed yet: the spec does not state it
//! ([#52](https://github.com/firefly-engineering/playpen/issues/52#issuecomment-5979991420)).
//!
//! [spec §14.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#142-playpen-explain
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence

use std::io::{self, Write};
use std::path::Path;

use clap::ArgGroup;

use crate::capability::{Access, Scope};
use crate::code::Code;
use crate::record::{self, Record, RunId};
use crate::refusal::{OneLine, Refusal};

/// What `explain` was asked. Exactly one of `--run` and `--list`, until `explain [<profile>]`
/// exists.
#[derive(Debug, clap::Args)]
#[command(group(ArgGroup::new("query").required(true).args(["run", "list"])))]
pub struct Args {
    /// Replay the record of one run.
    #[arg(long, value_name = "ID")]
    run: Option<String>,
    /// List the runs the ring holds, most recent first.
    #[arg(long)]
    list: bool,
    /// Print the JSON form the human one is rendered from.
    #[arg(long)]
    json: bool,
}

/// Answer `args` from the records under the state directory `state`, writing the report to
/// `out`. A report that cannot be written has nowhere else to go, so a write error is dropped.
pub fn explain(args: &Args, state: Option<&Path>, out: &mut impl Write) -> Result<(), Refusal> {
    let written = match &args.run {
        Some(id) => {
            let id = RunId::parse(id)
                .ok_or_else(|| Refusal::new(Code::RunUnknown, format!("{id:?} is not a run id")))?;
            let record = record::read(state, &id)?;
            if args.json {
                json(&record, out)
            } else {
                render_run(&record, out)
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

fn json(value: &impl serde::Serialize, out: &mut impl Write) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value)?;
    writeln!(out)
}

/// One run, field by field. A field the launch never reached is `-`. Every value is shown on one
/// line, whatever bytes it carries.
fn render_run(record: &Record, out: &mut impl Write) -> io::Result<()> {
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
    ];
    for (name, value) in fields {
        writeln!(out, "{name:<9} {}", OneLine(&value))?;
    }
    let Some(caps) = &record.capabilities else {
        return writeln!(out, "capabilities -");
    };
    writeln!(out, "capabilities")?;
    for grant in &caps.paths {
        let access = match grant.access {
            Access::Read => "read",
            Access::ReadWrite => "readwrite",
        };
        let scope = match grant.scope {
            Scope::Subtree => "subtree",
            Scope::Literal => "literal",
        };
        let path = grant.path.display().to_string();
        writeln!(
            out,
            "  {access:<9} {scope:<7} {}  (from {})",
            OneLine(&path),
            OneLine(&grant.from)
        )?;
    }
    for service in &caps.mach_services {
        writeln!(out, "  mach-lookup       {}", OneLine(service))?;
    }
    Ok(())
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
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        ms / 3_600_000,
        ms / 60_000 % 60,
        ms / 1_000 % 60,
        ms % 1_000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
