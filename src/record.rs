//! The run record ([spec §14.1]): what playpen knows and the kernel cannot. Every invocation
//! allocates a run id and opens its record first ([spec §4.2], step 1), so the run that refuses —
//! the one whose record is most wanted — leaves one.
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
        let state = state.ok_or_else(|| {
            Refusal::new(
                Code::StateIo,
                "no state directory: neither XDG_STATE_HOME nor HOME is an absolute path",
            )
        })?;
        let runs = state.join(RUNS);
        // Owner-only: a record names the policy and the paths of every grant.
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&runs)
            .map_err(|e| io_refusal("create the state directory", &runs, e))?;
        let path = runs.join(format!("{id}.json"));
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
        let staged = path.with_extension("tmp");
        let created = encode(&record)
            .and_then(|bytes| write_owner_only(&staged, &bytes))
            .and_then(|()| std::fs::hard_link(&staged, &path));
        let _ = std::fs::remove_file(&staged);
        created.map_err(|e| io_refusal("create the run record", &path, e))?;
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
        let staged = self.path.with_extension("tmp");
        encode(&self.record)
            .and_then(|bytes| write_owner_only(&staged, &bytes))
            .and_then(|()| std::fs::rename(&staged, &self.path))
            .map_err(|e| io_refusal("write the run record", &self.path, e))
    }
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

    fn read(record: &RunRecord) -> Record {
        serde_json::from_slice(&std::fs::read(record.path()).expect("read")).expect("parse")
    }

    #[test]
    fn the_record_exists_once_opened_and_reads_back_as_written() {
        let state = tempfile::TempDir::new().expect("state");
        let id = RunId::allocate().expect("id");
        let mut record = RunRecord::open(&id, Some(state.path())).expect("open");
        assert_eq!(record.path(), state.path().join(format!("runs/{id}.json")));
        let opened = read(&record);
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
        let stored = read(&record);
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
        let stored = read(&record);
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
    fn a_state_directory_that_cannot_be_created_is_state_io() {
        let state = tempfile::NamedTempFile::new().expect("a file where a directory goes");
        let id = RunId::allocate().expect("id");
        let refusal = RunRecord::open(&id, Some(state.path())).expect_err("refuses");
        assert_eq!(refusal.code, Code::StateIo);
        let refusal = RunRecord::open(&id, None).expect_err("refuses");
        assert_eq!(refusal.code, Code::StateIo);
    }
}
