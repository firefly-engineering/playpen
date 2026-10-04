//! Running rows: the bare floor through the floor self-test itself, each policy fixture as one
//! confined launch of the probe, with the same actions run outside first, and each refusal as
//! one invocation playpen declines ([spec §17.1]).
//!
//! [spec §17.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#171-form

use std::fs::{self, File};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use playpen::record::Record;
use playpen::self_test::{self, CANARY};
use serde_json::Value;
use tempfile::{NamedTempFile, TempDir};

use crate::common::{self, PROBE};
use crate::row::{
    Action, Cause, Declined, Fixture, Invocation, Outcome, Row, Seen, Services, Target, Verdict,
    applies, judge, judge_refusal,
};

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
            Fixture::Outside => members.iter().map(|row| refusal(row)).collect(),
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

/// A refusal row, under a fixture of its own so its state directory holds this run alone.
fn refusal(row: &Row) -> Verdict {
    match row.action {
        Action::Refuse(invocation) => judge_refusal(row.expected, &decline(invocation)),
        action => Verdict::Setup(format!(
            "{action:?} runs under a boundary, and a refusal has none"
        )),
    }
}

/// Invoke playpen as `invocation` says, with the fixture's own state directory handed to it
/// through its environment, and read back the record its refusal line names.
fn decline(invocation: Invocation) -> Declined {
    let fixture = common::Fixture::with_mode("read");
    let mut command = match invocation {
        Invocation::Usage => fixture.playpen(&["run"]),
    };
    let output = command.stdin(Stdio::null()).output().expect("run playpen");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = match stderr.lines().collect::<Vec<_>>().as_slice() {
        [line] => refusal_line(line),
        _ => None,
    };
    let recorded = line.as_ref().and_then(|(_, run)| {
        let bytes = fs::read(fixture.runs().join(format!("{run}.json"))).ok()?;
        // A record that does not parse as one is no record.
        let record: Record = serde_json::from_slice(&bytes).ok()?;
        Some(record.refusal.map(|refusal| refusal.code))
    });
    Declined {
        status: output.status.code(),
        line,
        recorded,
        detail: format!("{}, stderr {stderr:?}", output.status),
    }
}

/// The code and run id of a refusal line `playpen: <code>: <sentence> — run <id>` ([spec §14.3]).
///
/// [spec §14.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#143-the-refusal-line
fn refusal_line(line: &str) -> Option<(String, String)> {
    let (code, _) = line.strip_prefix("playpen: ")?.split_once(": ")?;
    let (_, run) = line.rsplit_once(" — run ")?;
    Some((code.to_owned(), run.to_owned()))
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
            cause: None,
            detail: format!("{CANARY}: {status}"),
        },
        Err(err) => Seen::Failed {
            cause: err.raw_os_error().map(Cause::Errno),
            detail: format!("{CANARY}: {err}"),
        },
    }
}

/// The floor self-test, called as the launch calls it: one implementation, two callers.
fn canary_inside() -> Seen {
    match self_test::floor() {
        Ok(()) => Seen::Succeeded,
        Err(refusal) => Seen::Failed {
            cause: None,
            detail: refusal.to_string(),
        },
    }
}

/// One row's action made concrete on this host, with whatever the fixture made for it.
struct Prepared {
    /// The probe's verb and operand, once per path the target names; one verdict each.
    ops: Vec<[String; 2]>,
    /// Files the action creates, which must not survive the inside half.
    created: Vec<PathBuf>,
    /// A descriptor both halves inherit, open on a decoy credential.
    inherited: Option<File>,
    _decoys: Vec<NamedTempFile>,
    _decoy_dir: Option<TempDir>,
}

/// Paths the fixture made outside, removed in reverse order when the batch is done. One per batch,
/// so a directory made for one row (`~/.ssh`) outlives the decoys other rows made inside it.
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

/// The number an inherited descriptor is handed over under: high, because a confined child's
/// startup can open descriptors of its own, which take the lowest free numbers and could land on
/// a low one once playpen has closed it.
const INHERITED: RawFd = 99;

/// What a decoy at a real credential path holds: inert in the file's own syntax, and naming its
/// author, should a killed run leave it behind
/// ([#118](https://github.com/firefly-engineering/playpen/issues/118)).
const DECOY: &str = "# playpen enforcement-suite decoy, safe to delete\n";

fn prepare(action: Action, home: &Path, made: &mut Made) -> Result<Prepared, String> {
    let mut decoys = Vec::new();
    let mut decoy_dir = None;
    let mut target = |target: Target| -> Result<Vec<PathBuf>, String> {
        match target {
            Target::SshKey => ssh_key(home, made).map(|key| vec![key]),
            Target::SshConfig => {
                let ssh = ssh_dir(home, made)?;
                decoy_file(&ssh.join("config"), made).map(|config| vec![config])
            }
            Target::Aws => {
                let aws = home.join(".aws");
                if aws.symlink_metadata().is_err() {
                    // Marked, so a decoy a killed run leaves behind names its author.
                    decoy_dir_at(&aws, made)?;
                    decoy_file(&aws.join("playpen-decoy"), made)?;
                }
                Ok(vec![aws])
            }
            Target::Npmrc => decoy_file(&home.join(".npmrc"), made).map(|npmrc| vec![npmrc]),
            Target::HostTemp => host_temp()?
                .into_iter()
                .map(|dir| {
                    let decoy = tempfile::Builder::new()
                        .prefix("playpen-decoy")
                        .tempfile_in(&dir)
                        .map_err(|e| format!("decoy in {}: {e}", dir.display()))?;
                    let path = decoy.path().to_owned();
                    decoys.push(decoy);
                    Ok(path)
                })
                .collect(),
            Target::DecoyDir => {
                let dir = TempDir::new().map_err(|e| format!("decoy directory: {e}"))?;
                Ok(vec![decoy_dir.insert(dir).path().to_owned()])
            }
        }
    };
    let each = |verb: &str, paths: Vec<PathBuf>| -> Result<Vec<[String; 2]>, String> {
        paths
            .iter()
            .map(|path| Ok([verb.to_owned(), utf8(path)?]))
            .collect()
    };
    let mut created = Vec::new();
    let mut inherited = None;
    let ops = match action {
        Action::Canary => {
            return Err(
                "the canary runs under the bare floor alone, never beside the probe".into(),
            );
        }
        Action::Refuse(_) => {
            return Err("a refusal has no boundary for the probe to run under".into());
        }
        Action::Read(t) => each("read", target(t)?)?,
        Action::List(t) => each("list", target(t)?)?,
        Action::Create(t) => {
            created = target(t)?.iter().map(|dir| dir.join("planted")).collect();
            each("write", created.clone())?
        }
        Action::ReadInherited => {
            let credential = NamedTempFile::new()
                .and_then(|mut decoy| {
                    std::io::Write::write_all(&mut decoy, DECOY.as_bytes())?;
                    Ok(decoy)
                })
                .map_err(|e| format!("decoy credential: {e}"))?;
            let fd = credential
                .reopen()
                .map_err(|e| format!("decoy credential: {e}"))?;
            let op = ["read-fd".to_owned(), INHERITED.to_string()];
            inherited = Some(fd);
            decoys.push(credential);
            vec![op]
        }
        Action::LookUp(services) => services_named(services)
            .iter()
            .map(|service| ["look-up".to_owned(), (*service).to_owned()])
            .collect(),
    };
    Ok(Prepared {
        ops,
        created,
        inherited,
        _decoys: decoys,
        _decoy_dir: decoy_dir,
    })
}

fn services_named(services: Services) -> &'static [&'static str] {
    match services {
        // Plain `com.apple.securityd` and `com.apple.SecurityServer.xpc` resolve to no service
        // outside on macOS 26, so naming them would make the row a setup failure.
        Services::Keychain => &[
            "com.apple.SecurityServer",
            "com.apple.securityd.xpc",
            "com.apple.securityd.general",
            "com.apple.securityd.ckks",
            "com.apple.securityd.sos",
            "com.apple.securityd.aps",
        ],
    }
}

fn utf8(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is not UTF-8", path.display()))
}

/// The host's temp directories, each of which must exist: a missing one is a setup failure, not
/// a smaller host temp. Resolved, because the mechanism enforces on the resolved path: through
/// macOS's `/tmp` link a read would also need the link, and a grant of `/private/tmp` alone
/// would go unseen.
fn host_temp() -> Result<Vec<PathBuf>, String> {
    [PathBuf::from("/tmp"), PathBuf::from("/var/tmp")]
        .into_iter()
        .chain(user_temp_dir()?)
        .map(|dir| {
            dir.canonicalize()
                .map_err(|e| format!("host temp {}: {e}", dir.display()))
        })
        .collect()
}

/// macOS's per-user temp under `/var/folders/…`, as `confstr` reports it to every tool that asks.
#[cfg(target_os = "macos")]
fn user_temp_dir() -> Result<Option<PathBuf>, String> {
    use std::os::unix::ffi::OsStrExt;

    let failed = || format!("confstr: {}", std::io::Error::last_os_error());
    // SAFETY: a null buffer of length 0 asks confstr for the size it needs, terminator included.
    let len = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if len == 0 {
        return Err(failed());
    }
    let mut buf = vec![0u8; len];
    // SAFETY: `buf` is valid for writes of `len` bytes, the length passed.
    if unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buf.as_mut_ptr().cast(), len) } == 0 {
        return Err(failed());
    }
    let path = std::ffi::CStr::from_bytes_until_nul(&buf).map_err(|e| format!("confstr: {e}"))?;
    Ok(Some(PathBuf::from(std::ffi::OsStr::from_bytes(
        path.to_bytes(),
    ))))
}

/// Linux has no per-user temp of its own.
#[cfg(target_os = "linux")]
fn user_temp_dir() -> Result<Option<PathBuf>, String> {
    Ok(None)
}

/// `~/.ssh`, made with the mode ssh demands if the host has none.
fn ssh_dir(home: &Path, made: &mut Made) -> Result<PathBuf, String> {
    decoy_dir_at(&home.join(".ssh"), made)
}

/// `path` as the host has it, else a decoy file there. A dangling symlink counts as the host's:
/// it is never written through.
fn decoy_file(path: &Path, made: &mut Made) -> Result<PathBuf, String> {
    if path.symlink_metadata().is_err() {
        File::options()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut decoy| std::io::Write::write_all(&mut decoy, DECOY.as_bytes()))
            .map_err(|e| format!("decoy {}: {e}", path.display()))?;
        made.0.push(path.to_owned());
    }
    Ok(path.to_owned())
}

/// `path` as the host has it, else an empty owner-only decoy directory there: the smallest write
/// a decoy can make, and inert if left behind.
fn decoy_dir_at(path: &Path, made: &mut Made) -> Result<PathBuf, String> {
    if path.symlink_metadata().is_err() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(|e| format!("decoy {}: {e}", path.display()))?;
        made.0.push(path.to_owned());
    }
    Ok(path.to_owned())
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
    let decoy = ssh_dir(home, made)?.join("id_playpen-decoy");
    fs::write(&decoy, DECOY).map_err(|e| format!("decoy {}: {e}", decoy.display()))?;
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
    let mut made = Made::default();
    let prepared: Vec<Result<Prepared, String>> = rows
        .iter()
        .map(|row| prepare(row.action, home, &mut made))
        .collect();
    let ops: Vec<&String> = prepared
        .iter()
        .flatten()
        .flat_map(|p| p.ops.iter().flatten())
        .collect();
    let actions = prepared.iter().flatten().map(|p| p.ops.len()).sum();
    // With no action on its command line the probe would only print its usage.
    if actions == 0 {
        return prepared
            .into_iter()
            .map(|p| Verdict::Setup(p.err().unwrap_or_default()))
            .collect();
    }
    let inherited: Vec<RawFd> = prepared
        .iter()
        .flatten()
        .filter_map(|p| p.inherited.as_ref().map(File::as_raw_fd))
        .collect();
    if inherited.len() > 1 {
        return vec![
            Verdict::Setup(format!("one descriptor is inherited, as {INHERITED}"));
            rows.len()
        ];
    }

    let mut outside = Command::new(PROBE);
    outside.args(&ops);
    inherit(&mut outside, &inherited);
    let outside = observe(outside.output().expect("run the probe"), actions);
    // The outside half created what it was asked to; the inside half must find it absent.
    for created in prepared.iter().flatten().flat_map(|p| &p.created) {
        let _ = fs::remove_file(created);
    }
    // Read-only: the probe's root is a stated perturbation, and the smallest one that runs it.
    let fixture = common::Fixture::with_mode("read");
    let probe = fixture.probe();
    let mut argv = vec![probe.to_str().expect("a UTF-8 probe path")];
    argv.extend(ops.iter().map(|op| op.as_str()));
    let mut inside = fixture.run(&argv);
    inside.stdin(Stdio::null());
    inherit(&mut inside, &inherited);
    let inside = observe(inside.output().expect("run playpen"), actions);

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
            // Every path the target names is judged; the row holds only if each one does.
            let verdicts: Vec<Verdict> = prepared
                .ops
                .iter()
                .map(|_| {
                    let (outside, inside) = seen.next().expect("one verdict per action");
                    judge(row.expected, &outside, &inside)
                })
                .collect();
            if let Some(failed) = verdicts.into_iter().find(|v| *v != Verdict::Pass) {
                return failed;
            }
            match prepared.created.iter().find(|created| created.exists()) {
                Some(created) => Verdict::Fail(format!("{} was created inside", created.display())),
                None => Verdict::Pass,
            }
        })
        .collect()
}

/// Hand the descriptor in `fds`, if any, to the spawned process as [`INHERITED`], without
/// close-on-exec. When it already is that number, `dup2` changes nothing and its close-on-exec
/// flag survives, so it is cleared.
fn inherit(command: &mut Command, fds: &[RawFd]) {
    let Some(&source) = fds.first() else {
        return;
    };
    // SAFETY: dup2 and fcntl are async-signal-safe; the descriptor is open in the forked child.
    unsafe {
        command.pre_exec(move || {
            let done = if source == INHERITED {
                libc::fcntl(INHERITED, libc::F_SETFD, 0)
            } else {
                libc::dup2(source, INHERITED)
            };
            match done {
                -1 => Err(std::io::Error::last_os_error()),
                _ => Ok(()),
            }
        });
    }
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
        Some(false) => {
            let field = |name: &str| verdict[name].as_i64().and_then(|n| i32::try_from(n).ok());
            Ok(Seen::Failed {
                cause: field("errno")
                    .map(Cause::Errno)
                    .or_else(|| field("kr").map(Cause::Bootstrap)),
                detail: line.to_owned(),
            })
        }
        None => Err(format!("verdict {line:?} has no `ok`")),
    }
}
