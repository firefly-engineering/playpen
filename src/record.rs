//! The run record ([spec §14.1]): what playpen knows and the kernel cannot. Every launch
//! allocates a run id and opens its record first ([spec §4.2], step 1), so the run that refuses —
//! the one whose record is most wanted — leaves one. `explain` launches nothing and opens none.
//!
//! The store is a bounded ring, not an audit log: opening a record evicts all but the
//! [`RETAINED`] most recent runs ([spec §14.1]).
//!
//! The record lives in playpen's own state directory, outside every workspace. It is unreachable
//! from inside the boundary because nothing grants it: the floor never reaches under `$HOME`. A
//! brought root that covers it is not yet refused
//! ([#116](https://github.com/firefly-engineering/playpen/issues/116)).
//!
//! [spec §14.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#141-the-run-record
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence

use std::ffi::OsString;
use std::fmt;
use std::fs::{DirBuilder, File};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::capability::CapabilitySet;
use crate::code::Code;
use crate::refusal::Refusal;

/// The record format this playpen writes. A reader branches on it before anything else.
pub const FORMAT: u32 = 1;

/// The directory under the state directory that holds one `<run id>.json` per run.
const RUNS: &str = "runs";

/// How many runs the ring keeps ([spec §14.1]): enough to find the run that just misbehaved, and
/// few enough that the store never needs pruning by hand.
///
/// [spec §14.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#141-the-run-record
pub const RETAINED: usize = 100;

/// The extension of a stored record.
const RECORD_EXT: &str = "json";
/// The extension of the staging file a record is written through.
const STAGING_EXT: &str = "tmp";

/// playpen's state directory ([spec Appendix C], item C7): `$XDG_STATE_HOME/playpen`, else
/// `$HOME/.local/state/playpen`. A relative value is invalid and ignored, as the XDG base
/// directory specification requires. The caller reads the environment once and passes it here.
///
/// [spec Appendix C]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#appendix-c--assembly-choices
pub fn state_dir(xdg_state_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let absolute = |value: Option<OsString>| value.map(PathBuf::from).filter(|p| p.is_absolute());
    absolute(xdg_state_home)
        .or_else(|| absolute(home).map(|home| home.join(".local/state")))
        .map(|base| base.join("playpen"))
}

/// A run id: a ULID, so ids sort by the time their run started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunId(String);

/// Crockford's base 32, the ULID alphabet.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

impl RunId {
    /// A fresh id: the current time in milliseconds, then 80 random bits.
    pub fn allocate() -> Result<Self, Refusal> {
        let mut random = [0; 10];
        File::open("/dev/urandom")
            .and_then(|mut urandom| urandom.read_exact(&mut random))
            .map_err(|e| {
                Refusal::new(
                    Code::StateIo,
                    format!("cannot allocate a run id: /dev/urandom: {e}"),
                )
            })?;
        Ok(Self::encode(now_unix_ms(), random))
    }

    fn encode(unix_ms: u64, random: [u8; 10]) -> Self {
        let mut bits = u128::from(unix_ms & ((1 << 48) - 1)) << 80;
        for (i, byte) in random.iter().enumerate() {
            bits |= u128::from(*byte) << (8 * (9 - i));
        }
        // 26 digits of 5 bits each cover the 128, most significant first.
        let id = (0..26)
            .rev()
            .map(|digit| char::from(ALPHABET[(bits >> (5 * digit)) as usize & 31]))
            .collect();
        Self(id)
    }

    /// `id` if it is a run id as playpen writes them: 26 digits of the ULID alphabet. Nothing
    /// else names a record, so nothing else can reach outside the store.
    pub fn parse(id: &str) -> Option<Self> {
        (id.len() == 26 && id.bytes().all(|b| ALPHABET.contains(&b))).then(|| Self(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a run's record holds, as stored. Fields are filled in as the launch learns them, so a
/// refused run's record holds what was known when it refused, and `null` for the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub format: u32,
    pub run: String,
    pub started_at_unix_ms: u64,
    /// The stated kind, once it is known to this playpen.
    pub kind: Option<String>,
    /// The policy path, once the invocation names one.
    pub policy: Option<PathBuf>,
    /// The resolved profile.
    pub profile: Option<String>,
    /// The capability set the child was confined under.
    pub capabilities: Option<CapabilitySet>,
    pub launched_at_unix_ms: Option<u64>,
    /// The confined child's pid.
    pub pid: Option<libc::pid_t>,
    pub ended_at_unix_ms: Option<u64>,
    /// The status playpen exited with after the child ran.
    pub status: Option<i32>,
    pub refusal: Option<RecordedRefusal>,
}

/// A refusal as recorded: the stable code and the human sentence beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedRefusal {
    pub code: String,
    pub message: String,
}

/// An open run record: the stored [`Record`] and the file it is written to.
#[derive(Debug)]
pub struct RunRecord {
    id: RunId,
    path: PathBuf,
    record: Record,
}

impl RunRecord {
    /// Create the state directory if need be, and the record of run `id` in it. A failure is
    /// `refusal.state.io`; `state` is `None` when the environment names no state directory.
    pub fn open(id: &RunId, state: Option<&Path>) -> Result<Self, Refusal> {
        let runs = runs_dir(state)?;
        // Owner-only: a record names the policy and the paths of every grant.
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&runs)
            .map_err(|e| io_refusal("create the state directory", &runs, e))?;
        let path = record_path(&runs, id);
        let record = Record {
            format: FORMAT,
            run: id.to_string(),
            started_at_unix_ms: now_unix_ms(),
            kind: None,
            policy: None,
            profile: None,
            capabilities: None,
            launched_at_unix_ms: None,
            pid: None,
            ended_at_unix_ms: None,
            status: None,
            refusal: None,
        };
        // Staged whole, then linked into place: a reader never sees half of one, and a link
        // that exists already is a collision, which refuses rather than overwrites another run.
        let staged = path.with_extension(STAGING_EXT);
        let created = encode(&record)
            .and_then(|bytes| write_owner_only(&staged, &bytes))
            .and_then(|()| std::fs::hard_link(&staged, &path));
        let _ = std::fs::remove_file(&staged);
        created.map_err(|e| io_refusal("create the run record", &path, e))?;
        evict(&runs, RETAINED);
        Ok(Self {
            id: id.clone(),
            path,
            record,
        })
    }

    pub fn id(&self) -> &RunId {
        &self.id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The record as last stored, plus whatever the launch has learnt since.
    pub fn record(&self) -> &Record {
        &self.record
    }

    /// The stated kind, once this playpen knows it.
    pub fn kind(&mut self, kind: &str) {
        self.record.kind = Some(kind.to_string());
    }

    /// The policy path, absolute.
    pub fn policy(&mut self, policy: &Path) {
        self.record.policy = Some(policy.to_path_buf());
    }

    /// The resolved profile.
    pub fn profile(&mut self, profile: &str) {
        self.record.profile = Some(profile.to_string());
    }

    /// Complete the record before the fork ([spec §4.2], step 15): the capability set and the
    /// launch time. A failure is `refusal.state.io`, and nothing has been forked.
    ///
    /// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
    pub fn launch(&mut self, caps: &CapabilitySet) -> Result<(), Refusal> {
        self.record.capabilities = Some(caps.clone());
        self.record.launched_at_unix_ms = Some(now_unix_ms());
        self.write()
    }

    /// Record the child's pid, which exists only once the fork has happened. The child is running
    /// by now, so a failure to write cannot refuse it: the record is a debugging aid, and the
    /// final write retries.
    pub fn spawned(&mut self, pid: libc::pid_t) {
        self.record.pid = Some(pid);
        let _ = self.write();
    }

    /// Record the status playpen exits with. No teardown failure changes that status, so a
    /// failure to write is dropped.
    pub fn finish(&mut self, status: i32) {
        self.record.status = Some(status);
        self.end();
    }

    /// Record the refusal playpen is about to emit. playpen is refusing already, so a failure to
    /// write cannot change the outcome and is dropped; the refusal line still carries the code.
    pub fn refuse(&mut self, refusal: &Refusal) {
        self.record.refusal = Some(RecordedRefusal {
            code: refusal.code.to_string(),
            message: refusal.message().to_string(),
        });
        self.end();
    }

    fn end(&mut self) {
        self.record.ended_at_unix_ms = Some(now_unix_ms());
        let _ = self.write();
    }

    /// Replace the stored record whole, by rename, so a reader never sees half of one.
    fn write(&self) -> Result<(), Refusal> {
        let staged = self.path.with_extension(STAGING_EXT);
        encode(&self.record)
            .and_then(|bytes| write_owner_only(&staged, &bytes))
            .and_then(|()| std::fs::rename(&staged, &self.path))
            .map_err(|e| io_refusal("write the run record", &self.path, e))
    }
}

/// The stored record of run `id`. A run the ring has evicted, or never held, is
/// `refusal.run.unknown`; a record this playpen cannot read is `refusal.state.io`.
pub fn read(state: Option<&Path>, id: &RunId) -> Result<Record, Refusal> {
    let path = record_path(&runs_dir(state)?, id);
    let bytes = std::fs::read(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => Refusal::new(
            Code::RunUnknown,
            format!("no record of run {id} in {}", path.display()),
        ),
        _ => io_refusal("read the run record", &path, e),
    })?;
    decode(&bytes).map_err(|e| io_refusal("read the run record", &path, e))
}

/// Every record in the ring, most recent first. A record that cannot be read is left out: the
/// ring is a debugging aid, and one unreadable entry, such as another playpen's format, must not
/// hide the rest. A store not yet created holds no runs.
pub fn list(state: Option<&Path>) -> Result<Vec<Record>, Refusal> {
    let runs = runs_dir(state)?;
    let mut ids = match stored_ids(&runs) {
        Ok(ids) => ids,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(io_refusal("list the run records", &runs, e)),
    };
    ids.sort_by(|a, b| b.as_str().cmp(a.as_str()));
    Ok(ids
        .iter()
        .filter_map(|id| std::fs::read(record_path(&runs, id)).ok())
        .filter_map(|bytes| decode(&bytes).ok())
        .collect())
}

/// Keep the `keep` most recent runs in `runs` and remove every older one, with any staging file a
/// crash left behind for it. A staging file of a run at least as recent as the oldest kept may
/// belong to a playpen writing it right now, so it stays; an older run still going is not told
/// apart yet ([#119](https://github.com/firefly-engineering/playpen/issues/119)). Eviction never
/// refuses: a failure only leaves the ring longer than its bound until the next run tries again.
fn evict(runs: &Path, keep: usize) {
    let Ok(mut ids) = stored_ids(runs) else {
        return;
    };
    if ids.len() <= keep {
        return;
    }
    ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    // Run ids sort by start time, so everything below the oldest kept id is older.
    let oldest_kept = ids[ids.len() - keep].clone();
    let Ok(entries) = std::fs::read_dir(runs) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let older = run_of(&path, &[RECORD_EXT, STAGING_EXT])
            .is_some_and(|id| id.as_str() < oldest_kept.as_str());
        if older {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// The ids of every stored record in `runs`. Staging files, and names that are no run id, are
/// not records.
fn stored_ids(runs: &Path) -> std::io::Result<Vec<RunId>> {
    let mut ids = Vec::new();
    for entry in std::fs::read_dir(runs)? {
        ids.extend(run_of(&entry?.path(), &[RECORD_EXT]));
    }
    Ok(ids)
}

/// The run `path` belongs to, if it is `<run id>.<ext>` for one of `extensions`.
fn run_of(path: &Path, extensions: &[&str]) -> Option<RunId> {
    let extension = path.extension()?.to_str()?;
    if !extensions.contains(&extension) {
        return None;
    }
    RunId::parse(path.file_stem()?.to_str()?)
}

fn runs_dir(state: Option<&Path>) -> Result<PathBuf, Refusal> {
    let state = state.ok_or_else(|| {
        Refusal::new(
            Code::StateIo,
            "no state directory: neither XDG_STATE_HOME nor HOME is an absolute path",
        )
    })?;
    Ok(state.join(RUNS))
}

fn record_path(runs: &Path, id: &RunId) -> PathBuf {
    runs.join(format!("{id}.{RECORD_EXT}"))
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)
}

/// A capability set holding a path that is not UTF-8 cannot be written as JSON, and is an error.
fn encode(record: &Record) -> std::io::Result<Vec<u8>> {
    serde_json::to_vec_pretty(record).map_err(std::io::Error::other)
}

/// A record of another format is an error before its shape is read, so the message names the
/// format rather than whichever field moved.
fn decode(bytes: &[u8]) -> std::io::Result<Record> {
    #[derive(Deserialize)]
    struct Versioned {
        format: u32,
    }
    let Versioned { format } = serde_json::from_slice(bytes).map_err(std::io::Error::other)?;
    if format != FORMAT {
        return Err(std::io::Error::other(format!(
            "record format {format}, and this playpen reads format {FORMAT}"
        )));
    }
    serde_json::from_slice(bytes).map_err(std::io::Error::other)
}

fn io_refusal(what: &str, path: &Path, err: std::io::Error) -> Refusal {
    Refusal::new(
        Code::StateIo,
        format!("cannot {what} {}: {err}", path.display()),
    )
}

fn now_unix_ms() -> u64 {
    // A clock before 1970 is a host fault; the record then says 0 rather than refusing.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{Access, PathGrant, Scope};

    #[test]
    fn the_state_directory_prefers_an_absolute_xdg_state_home() {
        let dir = |xdg: Option<&str>, home: Option<&str>| {
            state_dir(xdg.map(OsString::from), home.map(OsString::from))
        };
        assert_eq!(
            dir(Some("/x/state"), Some("/home/u")),
            Some("/x/state/playpen".into())
        );
        assert_eq!(
            dir(None, Some("/home/u")),
            Some("/home/u/.local/state/playpen".into())
        );
        // A relative or empty XDG value is invalid and ignored.
        assert_eq!(
            dir(Some("state"), Some("/home/u")),
            Some("/home/u/.local/state/playpen".into())
        );
        assert_eq!(
            dir(Some(""), Some("/home/u")),
            Some("/home/u/.local/state/playpen".into())
        );
        assert_eq!(dir(None, Some("home")), None);
        assert_eq!(dir(None, None), None);
    }

    #[test]
    fn a_run_id_is_a_ulid_ordered_by_time() {
        assert_eq!(
            RunId::encode(0, [0; 10]).as_str(),
            "00000000000000000000000000"
        );
        assert_eq!(
            RunId::encode(u64::MAX, [0xff; 10]).as_str(),
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"
        );
        // The ULID specification's own example timestamp.
        assert!(
            RunId::encode(1_469_918_176_385, [0; 10])
                .as_str()
                .starts_with("01ARYZ6S41")
        );
        let earlier = RunId::encode(1_000, [0xff; 10]);
        let later = RunId::encode(1_001, [0; 10]);
        assert!(earlier.as_str() < later.as_str());
    }

    #[test]
    fn two_allocated_ids_differ() {
        let a = RunId::allocate().expect("id");
        let b = RunId::allocate().expect("id");
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 26);
    }

    fn read_back(record: &RunRecord) -> Record {
        serde_json::from_slice(&std::fs::read(record.path()).expect("read")).expect("parse")
    }

    #[test]
    fn the_record_exists_once_opened_and_reads_back_as_written() {
        let state = tempfile::TempDir::new().expect("state");
        let id = RunId::allocate().expect("id");
        let mut record = RunRecord::open(&id, Some(state.path())).expect("open");
        assert_eq!(record.path(), state.path().join(format!("runs/{id}.json")));
        let opened = read_back(&record);
        assert_eq!(opened.run, id.as_str());
        assert_eq!(opened.refusal, None);

        record.profile("p");
        let caps = CapabilitySet {
            paths: vec![PathGrant {
                path: "/src/playpen".into(),
                access: Access::ReadWrite,
                scope: Scope::Subtree,
                from: "workspace:w.roots[0]".into(),
            }],
            mach_services: vec![],
        };
        record.launch(&caps).expect("launch");
        record.spawned(42);
        record.finish(3);
        let stored = read_back(&record);
        assert_eq!(&stored, record.record());
        assert_eq!(stored.capabilities, Some(caps));
        assert_eq!(stored.pid, Some(42));
        assert_eq!(stored.status, Some(3));
        let runs: Vec<_> = std::fs::read_dir(state.path().join("runs"))
            .expect("runs")
            .collect();
        assert_eq!(runs.len(), 1, "no staging file is left behind");
    }

    #[test]
    fn a_refusal_is_recorded_with_its_code() {
        let state = tempfile::TempDir::new().expect("state");
        let id = RunId::allocate().expect("id");
        let mut record = RunRecord::open(&id, Some(state.path())).expect("open");
        record.refuse(&Refusal::new(Code::CwdUngranted, "cwd /tmp is outside"));
        let stored = read_back(&record);
        assert_eq!(
            stored.refusal,
            Some(RecordedRefusal {
                code: "refusal.cwd.ungranted".into(),
                message: "cwd /tmp is outside".into(),
            })
        );
        assert!(stored.ended_at_unix_ms >= Some(stored.started_at_unix_ms));
    }

    #[test]
    fn only_a_run_id_as_playpen_writes_it_parses() {
        let id = RunId::allocate().expect("id");
        assert_eq!(RunId::parse(id.as_str()), Some(id.clone()));
        for not_an_id in [
            "",
            "../../../../etc/passwd",
            &id.as_str()[1..],
            &format!("{id}0"),
            &id.as_str().to_lowercase(),
            // `U` is not in Crockford's alphabet.
            "0000000000000000000000000U",
        ] {
            assert_eq!(RunId::parse(not_an_id), None, "{not_an_id:?}");
        }
    }

    /// A run started at `unix_ms`, so ids sort by the argument.
    fn id_at(unix_ms: u64) -> RunId {
        RunId::encode(unix_ms, [7; 10])
    }

    fn plant(runs: &Path, name: &str) {
        std::fs::write(runs.join(name), "{}").expect("plant");
    }

    fn names(runs: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(runs)
            .expect("runs")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("utf-8")
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn eviction_keeps_the_most_recent_runs_and_sweeps_older_staging_files() {
        let runs = tempfile::TempDir::new().expect("runs");
        let runs = runs.path();
        let ids: Vec<_> = (1..=5).map(id_at).collect();
        for id in &ids {
            plant(runs, &format!("{id}.json"));
        }
        // A crash left the oldest run's staging file; the newest is mid-write.
        plant(runs, &format!("{}.tmp", ids[0]));
        plant(runs, &format!("{}.tmp", ids[4]));
        // Neither is a run's, so neither is the ring's to remove.
        plant(runs, "notes.txt");
        plant(runs, "planted.json");

        evict(runs, 3);

        let mut kept: Vec<_> = ids[2..].iter().map(|id| format!("{id}.json")).collect();
        kept.push(format!("{}.tmp", ids[4]));
        kept.extend(["notes.txt".into(), "planted.json".into()]);
        kept.sort();
        assert_eq!(names(runs), kept);
    }

    #[test]
    fn a_ring_within_its_bound_is_left_alone() {
        let runs = tempfile::TempDir::new().expect("runs");
        let runs = runs.path();
        plant(runs, &format!("{}.json", id_at(1)));
        plant(runs, &format!("{}.tmp", id_at(0)));
        let before = names(runs);
        evict(runs, 1);
        assert_eq!(names(runs), before);
    }

    #[test]
    fn opening_a_record_evicts_beyond_the_bound() {
        let state = tempfile::TempDir::new().expect("state");
        let runs = state.path().join(RUNS);
        std::fs::create_dir(&runs).expect("runs");
        for unix_ms in 0..RETAINED as u64 {
            plant(&runs, &format!("{}.json", id_at(unix_ms)));
        }
        let id = RunId::allocate().expect("id");
        RunRecord::open(&id, Some(state.path())).expect("open");
        let names = names(&runs);
        assert_eq!(names.len(), RETAINED);
        assert!(
            !names.contains(&format!("{}.json", id_at(0))),
            "the oldest went"
        );
        assert!(names.contains(&format!("{}.json", id_at(1))));
        assert!(names.contains(&format!("{id}.json")), "the new run stays");
    }

    #[test]
    fn a_stored_record_reads_back_and_lists_most_recent_first() {
        let state = tempfile::TempDir::new().expect("state");
        assert_eq!(
            list(Some(state.path())).expect("list"),
            vec![],
            "no store yet"
        );
        let mut first = RunRecord::open(&id_at(1), Some(state.path())).expect("open");
        first.finish(0);
        let second = RunRecord::open(&id_at(2), Some(state.path())).expect("open");
        assert_eq!(
            read(Some(state.path()), first.id()).expect("read"),
            *first.record()
        );
        assert_eq!(
            list(Some(state.path())).expect("list"),
            vec![second.record().clone(), first.record().clone()]
        );
    }

    #[test]
    fn a_record_the_ring_does_not_hold_is_an_unknown_run() {
        let state = tempfile::TempDir::new().expect("state");
        let refusal = read(Some(state.path()), &id_at(1)).expect_err("refuses");
        assert_eq!(refusal.code, Code::RunUnknown);
        assert!(refusal.message().contains(id_at(1).as_str()), "{refusal}");
        let refusal = read(None, &id_at(1)).expect_err("refuses");
        assert_eq!(refusal.code, Code::StateIo);
        assert_eq!(list(None).expect_err("refuses").code, Code::StateIo);
    }

    #[test]
    fn an_unreadable_record_refuses_on_read_and_is_left_out_of_the_list() {
        let state = tempfile::TempDir::new().expect("state");
        let kept = RunRecord::open(&id_at(1), Some(state.path())).expect("open");
        let runs = state.path().join(RUNS);
        let newer = format!(r#"{{"format": {}, "run": "x"}}"#, FORMAT + 1);
        std::fs::write(runs.join(format!("{}.json", id_at(2))), newer).expect("plant");
        std::fs::write(runs.join(format!("{}.json", id_at(3))), "not json").expect("plant");

        let refusal = read(Some(state.path()), &id_at(2)).expect_err("refuses");
        assert_eq!(refusal.code, Code::StateIo);
        let named = format!("record format {}", FORMAT + 1);
        assert!(refusal.message().contains(&named), "{refusal}");
        let refusal = read(Some(state.path()), &id_at(3)).expect_err("refuses");
        assert_eq!(refusal.code, Code::StateIo);
        assert_eq!(
            list(Some(state.path())).expect("list"),
            vec![kept.record().clone()]
        );
    }

    #[test]
    fn a_state_directory_that_cannot_be_created_is_state_io() {
        let state = tempfile::NamedTempFile::new().expect("a file where a directory goes");
        let id = RunId::allocate().expect("id");
        let refusal = RunRecord::open(&id, Some(state.path())).expect_err("refuses");
        assert_eq!(refusal.code, Code::StateIo);
        let refusal = RunRecord::open(&id, None).expect_err("refuses");
        assert_eq!(refusal.code, Code::StateIo);
    }
}
