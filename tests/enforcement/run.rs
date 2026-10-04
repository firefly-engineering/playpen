//! Running rows: the bare floor through the floor self-test itself, and each policy fixture as one
//! confined launch of the probe, with the same actions run outside first ([spec §17.1]).
//!
//! [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form

use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use playpen::self_test::{self, CANARY};
use serde_json::Value;
use tempfile::TempDir;

use crate::common::{self, PROBE};
use crate::row::{Action, Fixture, Outcome, Row, Seen, Target, Verdict, applies, judge};

/// Every row's outcome, in table order. `home` is the caller's home directory, where the
/// credential targets live; it is handed in, never read from the environment here.
///
/// Must be called on the process's only thread: the bare floor's canary forks.
pub fn run(rows: &[Row], home: &Path) -> Vec<Outcome> {
    let mut outcomes: Vec<Option<Outcome>> = rows
        .iter()
        .map(|row| applies(&row.platform).err())
        .collect();
    let mut fixtures: Vec<Fixture> = Vec::new();
    for row in rows {
        if !fixtures.contains(&row.fixture) {
            fixtures.push(row.fixture);
        }
    }
    for fixture in fixtures {
        let batch: Vec<usize> = (0..rows.len())
            .filter(|&i| outcomes[i].is_none() && rows[i].fixture == fixture)
            .collect();
        if batch.is_empty() {
            continue;
        }
        let members: Vec<&Row> = batch.iter().map(|&i| &rows[i]).collect();
        let verdicts = match fixture {
            Fixture::BareFloor => members.iter().map(|row| bare_floor(row)).collect(),
            Fixture::ProbeRoot => probe_root(&members, home),
        };
        for (i, verdict) in batch.into_iter().zip(verdicts) {
            outcomes[i] = Some(Outcome::Runs(verdict));
        }
    }
    outcomes
        .into_iter()
        .map(|outcome| outcome.expect("every row ran or was set aside"))
        .collect()
}

fn bare_floor(row: &Row) -> Verdict {
    match row.action {
        Action::Canary => judge(row.expected, &canary_outside(), &canary_inside()),
        action => Verdict::Setup(format!(
            "{action:?} needs the probe, and the bare floor admits no grant for it"
        )),
    }
}

fn canary_outside() -> Seen {
    let status = Command::new(CANARY)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => Seen::Succeeded,
        Ok(status) => Seen::Failed {
            errno: None,
            detail: format!("{CANARY}: {status}"),
        },
        Err(err) => Seen::Failed {
            errno: err.raw_os_error(),
            detail: format!("{CANARY}: {err}"),
        },
    }
}

/// The floor self-test, called as the launch calls it: one implementation, two callers.
fn canary_inside() -> Seen {
    match self_test::floor() {
        Ok(()) => Seen::Succeeded,
        Err(refusal) => Seen::Failed {
            errno: None,
            detail: refusal.to_string(),
        },
    }
}

/// One row's action made concrete on this host, with whatever the fixture made for it.
struct Prepared {
    /// The probe's verb and operand.
    op: [String; 2],
    /// A file the action creates, which must not survive the inside half.
    created: Option<PathBuf>,
    _made: Made,
    _decoy_dir: Option<TempDir>,
}

/// Paths the fixture made outside, removed in reverse order when the row is done.
#[derive(Default)]
struct Made(Vec<PathBuf>);

impl Drop for Made {
    fn drop(&mut self) {
        for path in self.0.iter().rev() {
            // Best effort: a decoy that cannot be removed is reported by nothing else either.
            let _ = if path.is_dir() {
                fs::remove_dir(path)
            } else {
                fs::remove_file(path)
            };
        }
    }
}

fn prepare(action: Action, home: &Path) -> Result<Prepared, String> {
    let mut made = Made::default();
    let mut decoy_dir = None;
    let mut target = |target: Target| -> Result<PathBuf, String> {
        match target {
            Target::SshKey => ssh_key(home, &mut made),
            Target::DecoyDir => {
                let dir = TempDir::new().map_err(|e| format!("decoy directory: {e}"))?;
                Ok(decoy_dir.insert(dir).path().to_owned())
            }
        }
    };
    let (op, created) = match action {
        Action::Canary => {
            return Err(
                "the canary runs under the bare floor alone, never beside the probe".into(),
            );
        }
        Action::Read(t) => (["read".to_owned(), utf8(&target(t)?)?], None),
        Action::Create(t) => {
            let path = target(t)?.join("planted");
            (["write".to_owned(), utf8(&path)?], Some(path))
        }
    };
    Ok(Prepared {
        op,
        created,
        _made: made,
        _decoy_dir: decoy_dir,
    })
}

fn utf8(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is not UTF-8", path.display()))
}

/// The host's own `~/.ssh/id_*` private key if it has one; else a decoy in its place, so the
/// row exercises the same path resolution on a fresh runner.
fn ssh_key(home: &Path, made: &mut Made) -> Result<PathBuf, String> {
    let ssh = home.join(".ssh");
    if let Ok(entries) = fs::read_dir(&ssh) {
        let mut keys: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| is_private_key(path) && path.is_file())
            .collect();
        keys.sort();
        if let Some(key) = keys.into_iter().next() {
            return Ok(key);
        }
    }
    if !ssh.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&ssh)
            .map_err(|e| format!("decoy {}: {e}", ssh.display()))?;
        made.0.push(ssh.clone());
    }
    let decoy = ssh.join("id_playpen-decoy");
    fs::write(&decoy, "decoy").map_err(|e| format!("decoy {}: {e}", decoy.display()))?;
    made.0.push(decoy.clone());
    Ok(decoy)
}

fn is_private_key(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("id_") && !name.ends_with(".pub"))
}

/// Every row of the probe-root fixture, under one confined launch.
fn probe_root(rows: &[&Row], home: &Path) -> Vec<Verdict> {
    let prepared: Vec<Result<Prepared, String>> =
        rows.iter().map(|row| prepare(row.action, home)).collect();
    let ops: Vec<&String> = prepared.iter().flatten().flat_map(|p| &p.op).collect();
    let ready = prepared.iter().filter(|p| p.is_ok()).count();
    // With no action on its command line the probe would only print its usage.
    if ready == 0 {
        return prepared
            .into_iter()
            .map(|p| Verdict::Setup(p.err().unwrap_or_default()))
            .collect();
    }

    let outside = observe(
        Command::new(PROBE)
            .args(&ops)
            .output()
            .expect("run the probe"),
        ready,
    );
    // The outside half created what it was asked to; the inside half must find it absent.
    for created in prepared.iter().flatten().filter_map(|p| p.created.as_ref()) {
        let _ = fs::remove_file(created);
    }
    // Read-only: the probe's root is a stated perturbation, and the smallest one that runs it.
    let fixture = common::Fixture::with_mode("read");
    let probe = fixture.probe();
    let mut argv = vec![probe.to_str().expect("a UTF-8 probe path")];
    argv.extend(ops.iter().map(|op| op.as_str()));
    let inside = observe(
        fixture
            .run(&argv)
            .stdin(Stdio::null())
            .output()
            .expect("run playpen"),
        ready,
    );

    let mut seen = match (outside, inside) {
        (Ok(outside), Ok(inside)) => outside.into_iter().zip(inside),
        (Err(why), _) => return vec![Verdict::Setup(format!("outside: {why}")); rows.len()],
        (_, Err(why)) => return vec![Verdict::Fail(format!("inside: {why}")); rows.len()],
    };
    rows.iter()
        .zip(&prepared)
        .map(|(row, prepared)| {
            let prepared = match prepared {
                Ok(prepared) => prepared,
                Err(why) => return Verdict::Setup(why.clone()),
            };
            let (outside, inside) = seen.next().expect("one verdict per prepared row");
            match (judge(row.expected, &outside, &inside), &prepared.created) {
                (Verdict::Pass, Some(created)) if created.exists() => {
                    Verdict::Fail(format!("{} was created inside", created.display()))
                }
                (verdict, _) => verdict,
            }
        })
        .collect()
}

/// The probe's verdicts, one per action. A probe that broke voids them all: the exit code says
/// only whether it ran.
fn observe(output: Output, actions: usize) -> Result<Vec<Seen>, String> {
    if !output.status.success() {
        return Err(format!(
            "the probe broke: {}, stderr {:?}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let seen = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(seen)
        .collect::<Result<Vec<_>, _>>()?;
    if seen.len() != actions {
        return Err(format!(
            "{} verdicts for {actions} actions: {seen:?}",
            seen.len()
        ));
    }
    Ok(seen)
}

fn seen(line: &str) -> Result<Seen, String> {
    let verdict: Value =
        serde_json::from_str(line).map_err(|e| format!("verdict {line:?}: {e}"))?;
    match verdict["ok"].as_bool() {
        Some(true) => Ok(Seen::Succeeded),
        Some(false) => Ok(Seen::Failed {
            errno: verdict["errno"]
                .as_i64()
                .and_then(|errno| i32::try_from(errno).ok()),
            detail: line.to_owned(),
        }),
        None => Err(format!("verdict {line:?} has no `ok`")),
    }
}
