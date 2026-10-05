//! The run record ([spec §14.1]): what playpen knows and the kernel cannot. Every launch
//! allocates a run id and opens its record first ([spec §4.2], step 1), so the run that refuses —
//! the one whose record is most wanted — leaves one. `explain` launches nothing and opens none.
//!
//! The store is a bounded ring, not an audit log: opening a record evicts all but the
//! [`RETAINED`] most recent **ended** runs, and never a live one ([spec §14.1]). The bound is on
//! *history*, which is what "a debugging aid, not an audit log" was protecting; live runs are
//! self-limiting because each one is a process. Liveness is an advisory lock on a sidecar
//! ([`LOCK_EXT`]), so there is no age bound to pick.
//!
//! The record lives in playpen's own state directory, beyond every granted path. That is enforced
//! and not merely true of the default policy: a launch whose grants reach the directory refuses
//! ([`refuse_if_reachable`]).
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

use crate::capability::{Access, CapabilitySet, PathGrant, Scope};
use crate::code::Code;
use crate::fault::Fault;
use crate::refusal::Refusal;
use crate::select::Trace;

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
/// The extension of the sidecar a live run holds an advisory lock on ([ADR 0028]).
///
/// A lock follows the inode and every write replaces `<id>.json` by rename, so a record cannot
/// carry its own liveness. The lock is released by the kernel on any death, `SIGKILL` included,
/// which is why there is no age bound anywhere in eviction: the kernel answers the question
/// exactly, where a constant would have to be longer than any agent session and shorter than any
/// tolerable leak.
///
/// [ADR 0028]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0028-the-run-record-ring-evicts-history-and-never-a-live-run.md
const LOCK_EXT: &str = "lock";

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

/// Refuse if any grant in `grants` reaches playpen's state directory `state` ([ADR 0027]).
///
/// [Spec §14.1] requires the run record to be unreachable from inside the boundary, and
/// [Appendix C] item C7 requires the state directory to be beyond every profile's reach. Nothing
/// checked it: the directory was unreachable in practice for one reason only — nothing granted it,
/// because the floor never reaches under `$HOME` — which is a property of the default policy
/// rather than of the model. A brought root of `~` made every record readable and, at
/// `readwrite`, forgeable.
///
/// **Reachability is the breach, not writability**, so the mode does not decide it: a record
/// carries the resolved profile, the selection trace, the capability set and the route table, so a
/// `read` root over the records hands a map of the boundary to the thing being confined. The mode
/// is named in the sentence instead, because the operator's remedy is the same single action
/// either way.
///
/// Refusing rather than carving the directory out of an otherwise-granted root: Seatbelt can
/// express a deny inside an allow, and Landlock is an allow-list with no deny rules. A fix
/// available on one platform is not a fix, and the alternative would have been a named asymmetry
/// in the *reachability of the run record*, which is the last place to accept platform inequality.
///
/// [ADR 0027]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md
/// [spec §14.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#141-the-run-record
/// [Appendix C]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#appendix-c--assembly-choices
pub fn refuse_if_reachable(state: Option<&Path>, grants: &[PathGrant]) -> Result<(), Refusal> {
    // No state directory means no records to reach; `RunRecord::open` has already refused.
    let Some(state) = state else {
        return Ok(());
    };
    // Resolved on both sides, so a grant that reaches the directory through a symlink is caught.
    // A path that cannot be resolved is compared as written: a missing root is refused elsewhere,
    // and a floor path absent on this host grants nothing.
    let resolve = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    let state = resolve(state);
    for grant in grants {
        if grant.state_derived {
            continue;
        }
        let path = resolve(&grant.path);
        let reaches = match grant.scope {
            // A subtree grant reaches the directory from either side: at or above it, everything
            // beneath is granted; at or below it, the grant is inside the directory already.
            Scope::Subtree => state.starts_with(&path) || path.starts_with(&state),
            // A literal grant of an ancestor grants nothing beneath it, so only one direction.
            Scope::Literal => path.starts_with(&state),
        };
        if reaches {
            let mode = match grant.access {
                Access::Read => "read",
                Access::ReadWrite => "readwrite",
            };
            return Err(Refusal::new(
                Code::StateReachable,
                format!(
                    "{}: the {mode} grant of {} reaches playpen's state directory {}, whose run \
                     records must be unreachable from inside the boundary",
                    grant.from,
                    path.display(),
                    state.display()
                ),
            ));
        }
    }
    Ok(())
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
    /// How the profile was selected ([`crate::select`]): each step up to the one that selected or
    /// refused. Additive, so a record written before selection was traced still reads.
    #[serde(default)]
    pub selection: Option<Trace>,
    /// The capability set the child was confined under.
    pub capabilities: Option<CapabilitySet>,
    pub launched_at_unix_ms: Option<u64>,
    /// The confined child's pid.
    pub pid: Option<libc::pid_t>,
    /// The supervisor's own pid, so a stale record is diagnosable by hand once its lock is gone
    /// ([ADR 0028]). Recording the child's pid without its parent's was odd on its own terms.
    /// Liveness is never decided from it: pid reuse makes that wrong precisely on a busy host,
    /// which is when a long session is most likely to be pushed out of the ring.
    ///
    /// [ADR 0028]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0028-the-run-record-ring-evicts-history-and-never-a-live-run.md
    #[serde(default)]
    pub supervisor_pid: Option<libc::pid_t>,
    pub ended_at_unix_ms: Option<u64>,
    /// The tag the child's tree logs its denials with, where the platform logs one
    /// ([`crate::backend::denial_tag`]). Additive, so a record written before runs were tagged
    /// still reads: it holds none, and its denials are found by the child's pid alone.
    #[serde(default)]
    pub denial_tag: Option<String>,
    /// The status playpen exited with after the child ran.
    pub status: Option<i32>,
    pub refusal: Option<RecordedRefusal>,
    /// The fault playpen died of, if it died of one ([ADR 0024]). A field of its own rather than
    /// reuse of `refusal`, because `explain --run` reads it back out and a surface whose job is to
    /// state facts must not report a crash as a refusal. Additive, so a record written before this
    /// field existed still reads: it simply held no fault.
    ///
    /// [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
    #[serde(default)]
    pub fault: Option<RecordedFault>,
}

/// A refusal as recorded: the stable code and the human sentence beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedRefusal {
    pub code: String,
    pub message: String,
}

/// A fault as recorded, in the same shape as a refusal: the stable code and the sentence beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedFault {
    pub code: String,
    pub message: String,
}

/// An open run record: the stored [`Record`], the file it is written to, and the sidecar whose
/// advisory lock marks this run live for as long as this value exists.
#[derive(Debug)]
pub struct RunRecord {
    id: RunId,
    path: PathBuf,
    record: Record,
    /// Dropping it releases the lock and removes the sidecar, after which eviction may take the
    /// record.
    #[expect(
        dead_code,
        reason = "an RAII guard: the run is live for exactly as long as this field exists"
    )]
    lock: Option<Sidecar>,
}

/// The sidecar of a live run: an open, flocked file that is removed when the run ends.
#[derive(Debug)]
struct Sidecar {
    path: PathBuf,
    /// The lock is the open descriptor, so closing this file is what releases it.
    #[expect(
        dead_code,
        reason = "an RAII guard: the lock is held for exactly as long as this descriptor is open"
    )]
    file: File,
}

impl Sidecar {
    /// Create the sidecar of run `id` and take its lock.
    ///
    /// A failure is `refusal.state.io`, which [Appendix A] already defines as playpen being unable
    /// to create its own state, *the lock file included*. Carrying on without the lock was the
    /// alternative and it is not available: §14.1 promises flatly that a live run's record is
    /// never evicted, and a run with no lock reads as dead, so the next hundred runs would evict
    /// it — which is #119 reopened, silently, on the one path nobody would look at. A promise
    /// stated without qualification cannot have an unrecorded failure mode.
    ///
    /// [Appendix A]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#appendix-a--code-registry
    fn take(runs: &Path, id: &RunId) -> Result<Self, Refusal> {
        let path = runs.join(format!("{id}.{LOCK_EXT}"));
        let file = File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|e| io_refusal("create the run record's lock file", &path, e))?;
        if !take_lock(&file) {
            return Err(io_refusal(
                "lock the run record's lock file",
                &path,
                std::io::Error::other("another process holds it, so this run id is not fresh"),
            ));
        }
        Ok(Self { path, file })
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        // The run's own remover, on the normal path. Eviction removes whatever remains, because
        // ADR 0024's fault path ends by `abort` and runs no destructor.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Take `file`'s advisory lock without waiting. Answering "is this run live?" is the only use:
/// the kernel releases the lock on any death, so a lock nobody holds means nobody is running.
fn take_lock(file: &File) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: flock acts on an open descriptor this process owns and touches no memory.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
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
            selection: None,
            capabilities: None,
            launched_at_unix_ms: None,
            pid: None,
            // SAFETY: getpid has no preconditions.
            supervisor_pid: Some(unsafe { libc::getpid() }),
            ended_at_unix_ms: None,
            denial_tag: None,
            status: None,
            refusal: None,
            fault: None,
        };
        // Staged whole, then linked into place: a reader never sees half of one, and a link
        // that exists already is a collision, which refuses rather than overwrites another run.
        let staged = path.with_extension(STAGING_EXT);
        let created = encode(&record)
            .and_then(|bytes| write_owner_only(&staged, &bytes))
            .and_then(|()| std::fs::hard_link(&staged, &path));
        let _ = std::fs::remove_file(&staged);
        created.map_err(|e| io_refusal("create the run record", &path, e))?;
        // Taken before eviction runs, so this run is already live when the ring is swept and
        // cannot evict itself — which is the whole of #119.
        let lock = Some(Sidecar::take(&runs, id)?);
        evict(&runs, RETAINED);
        Ok(Self {
            id: id.clone(),
            path,
            record,
            lock,
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

    /// The selection trace, and the profile it selected if it did.
    pub fn selection(&mut self, trace: &Trace, profile: Option<&str>) {
        self.record.selection = Some(trace.clone());
        self.record.profile = profile.map(str::to_owned);
    }

    /// Complete the record before the fork ([spec §4.2], step 15): the capability set and the
    /// launch time. A failure is `refusal.state.io`, and nothing has been forked.
    ///
    /// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
    pub fn launch(
        &mut self,
        caps: &CapabilitySet,
        denial_tag: Option<String>,
    ) -> Result<(), Refusal> {
        self.record.capabilities = Some(caps.clone());
        self.record.denial_tag = denial_tag;
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

    /// Record the fault playpen is about to abort on ([ADR 0024]). The agent has already been
    /// killed, so the end time this writes is true. playpen is dying either way, so a failure to
    /// write is dropped; the fault line still carries the code.
    ///
    /// [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
    pub fn fault(&mut self, fault: &Fault) {
        self.record.fault = Some(RecordedFault {
            code: fault.code.to_string(),
            message: fault.message().to_string(),
        });
        self.end();
    }

    fn end(&mut self) {
        self.record.ended_at_unix_ms = Some(now_unix_ms());
        let _ = self.write();
    }

    /// Replace the stored record whole, by rename, so a reader never sees half of one.
    ///
    /// A rename that fails `ENOENT` is **deliberately not retried** ([ADR 0028]). Now that
    /// eviction leaves live runs alone, a live run's staging file has no legitimate remover, so
    /// `ENOENT` here means the invariant is broken, and re-staging would convert that into a
    /// successful write.
    ///
    /// What this buys is the *message*, not propagation: only [`RunRecord::launch`] returns this
    /// error, because it is the one write that happens before the fork. Every later write —
    /// `spawned`, `finish`, `refuse`, `fault` — still drops it, since no teardown failure may
    /// change the status playpen exits with. On those paths the breach is diagnosable only from
    /// the record left un-ended, which is the same shape a `SIGKILL` leaves.
    ///
    /// [ADR 0028]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0028-the-run-record-ring-evicts-history-and-never-a-live-run.md
    fn write(&self) -> Result<(), Refusal> {
        let staged = self.path.with_extension(STAGING_EXT);
        encode(&self.record)
            .and_then(|bytes| write_owner_only(&staged, &bytes))
            .and_then(|()| std::fs::rename(&staged, &self.path))
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Refusal::new(
                    Code::StateIo,
                    format!(
                        "the staging file of live run {} went missing under it, which only \
                         eviction could do and eviction does not touch live runs: {}: {e}",
                        self.id,
                        staged.display()
                    ),
                ),
                _ => io_refusal("write the run record", &self.path, e),
            })
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

/// Keep the `keep` most recent **ended** runs in `runs`, plus every live run, and remove the rest
/// along with each removed run's sidecar and any staging file a crash left behind for it
/// ([ADR 0028]).
///
/// Eviction used to order by start time, which is a ULID's key and the opposite of what a
/// debugging aid wants: the longest-running run is the most interesting and was the most certain
/// to be dropped. Shims count as runs, so a long session was guaranteed to evict its own record.
///
/// A run is live exactly when something holds its sidecar's lock. There is no age bound: a missing
/// sidecar beside an un-ended record counts as dead, so a record written by an older playpen is
/// evictable rather than immortal. Eviction never refuses — a failure only leaves the ring longer
/// than its bound until the next run tries again.
///
/// [ADR 0028]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0028-the-run-record-ring-evicts-history-and-never-a-live-run.md
fn evict(runs: &Path, keep: usize) {
    let Ok(ids) = stored_ids(runs) else {
        return;
    };
    // History is what the bound applies to. A live run takes no place in the ring: live runs are
    // self-limiting because each one is a process.
    let mut history: Vec<RunId> = ids.into_iter().filter(|id| !is_live(runs, id)).collect();
    if history.len() <= keep {
        return;
    }
    history.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let evicted: std::collections::HashSet<&str> = history[..history.len() - keep]
        .iter()
        .map(RunId::as_str)
        .collect();
    let Ok(entries) = std::fs::read_dir(runs) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // A live run's staging file has no legitimate remover, so the sweep is scoped to the runs
        // being evicted rather than to everything older than a cutoff.
        let ours = run_of(&path, &[RECORD_EXT, STAGING_EXT, LOCK_EXT])
            .is_some_and(|id| evicted.contains(id.as_str()));
        if ours {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Whether run `id` is still going: something holds its sidecar's lock.
///
/// A sidecar that is absent, or that this process can lock, belongs to no live run — the kernel
/// releases an advisory lock on any death, `SIGKILL` included. Two `flock`s from separate `open`
/// calls conflict even within one process, so a run asking about itself correctly sees itself as
/// live.
fn is_live(runs: &Path, id: &RunId) -> bool {
    let path = runs.join(format!("{id}.{LOCK_EXT}"));
    let Ok(file) = File::open(&path) else {
        return false;
    };
    // Asking the question means taking the lock, so release it again at once: this is a read-only
    // sweep and must leave no lock of its own behind.
    if take_lock(&file) {
        use std::os::fd::AsRawFd;
        // SAFETY: unlocking a descriptor this process just locked.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
        return false;
    }
    true
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
    let state = state.ok_or_else(no_state)?;
    Ok(state.join(RUNS))
}

/// The refusal of a host whose environment names no state directory.
pub fn no_state() -> Refusal {
    Refusal::new(
        Code::StateIo,
        "no state directory: neither XDG_STATE_HOME nor HOME is an absolute path",
    )
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

        let trace = vec![crate::select::Step {
            step: crate::select::Source::Explicit,
            outcome: crate::select::Outcome::Selected {
                profile: "p".into(),
                prefix: None,
            },
        }];
        record.selection(&trace, Some("p"));
        let caps = CapabilitySet {
            paths: vec![PathGrant {
                path: "/src/playpen".into(),
                access: Access::ReadWrite,
                scope: Scope::Subtree,
                from: "workspace:w.roots[0]".into(),
                state_derived: false,
            }],
            mach_services: vec![],
            exclusions: vec![],
        };
        record.launch(&caps, None).expect("launch");
        record.spawned(42);
        record.finish(3);
        let stored = read_back(&record);
        assert_eq!(&stored, record.record());
        assert_eq!(stored.capabilities, Some(caps));
        assert_eq!(stored.pid, Some(42));
        assert_eq!(stored.status, Some(3));
        assert_eq!(
            names(&state.path().join(RUNS)),
            [format!("{id}.json"), format!("{id}.lock")],
            "the record and its sidecar, and no staging file left behind"
        );
        assert_eq!(
            stored.supervisor_pid,
            Some(std::process::id() as libc::pid_t)
        );

        // The run's own remover: once it is dropped, nothing marks it live.
        let runs = state.path().join(RUNS);
        drop(record);
        assert_eq!(
            names(&runs),
            [format!("{id}.json")],
            "ending the run removes its sidecar"
        );
        assert!(!is_live(&runs, &id), "and the run no longer reads as live");
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

    /// A fault is recorded in a field of its own, so `explain` can state a crash as a crash
    /// rather than as a refusal ([ADR 0024]).
    ///
    /// [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
    #[test]
    fn a_fault_is_recorded_apart_from_a_refusal() {
        let state = tempfile::TempDir::new().expect("state");
        let id = RunId::allocate().expect("id");
        let mut record = RunRecord::open(&id, Some(state.path())).expect("open");
        record.fault(&Fault::new(
            Code::BugStatusNoChild,
            "cannot learn the status of agent 42",
        ));
        let stored = read_back(&record);
        assert_eq!(
            stored.fault,
            Some(RecordedFault {
                code: "bug.status.no-child".into(),
                message: "cannot learn the status of agent 42".into(),
            })
        );
        assert_eq!(stored.refusal, None, "a fault is not a refusal");
        assert!(stored.ended_at_unix_ms >= Some(stored.started_at_unix_ms));
    }

    /// The field is additive, so a record written before it existed still reads ([ADR 0024]).
    ///
    /// [ADR 0024]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md
    #[test]
    fn a_record_written_without_a_fault_field_still_reads() {
        let without = format!(
            r#"{{"format": {FORMAT}, "run": "{}", "started_at_unix_ms": 1, "kind": null,
                 "policy": null, "profile": null, "capabilities": null,
                 "launched_at_unix_ms": null, "pid": null, "ended_at_unix_ms": null,
                 "status": null, "refusal": null}}"#,
            id_at(1)
        );
        let record = decode(without.as_bytes()).expect("an older record reads");
        assert_eq!(record.fault, None);
    }

    fn grant(path: &Path, access: Access, scope: Scope) -> PathGrant {
        PathGrant {
            path: path.to_path_buf(),
            access,
            scope,
            from: "workspace:w.roots[0]".into(),
            state_derived: false,
        }
    }

    /// A brought root of `~`, or of any ancestor of the state directory, is the breach #116
    /// reported: it makes every run record readable from inside and, at `readwrite`, forgeable.
    #[test]
    fn a_grant_above_the_state_directory_refuses_naming_both_paths() {
        let home = tempfile::TempDir::new().expect("home");
        let state = home.path().join(".local/state/playpen");
        std::fs::create_dir_all(&state).expect("state");

        for access in [Access::Read, Access::ReadWrite] {
            let grants = [grant(home.path(), access, Scope::Subtree)];
            let refusal = refuse_if_reachable(Some(&state), &grants).expect_err("refuses");
            assert_eq!(refusal.code, Code::StateReachable);
            // Both paths, so the operator can see what to change and what it reached.
            let said = refusal.message();
            let home_resolved = home.path().canonicalize().expect("resolve");
            assert!(
                said.contains(&home_resolved.display().to_string()),
                "{said}"
            );
            assert!(
                said.contains(&state.canonicalize().expect("resolve").display().to_string()),
                "{said}"
            );
            assert!(said.contains("workspace:w.roots[0]"), "{said}");
        }
        // Reachability is the breach, not writability, but the mode is named in the sentence.
        let read_only = [grant(home.path(), Access::Read, Scope::Subtree)];
        let said = refuse_if_reachable(Some(&state), &read_only)
            .expect_err("a read root over the records is a breach too")
            .message()
            .to_string();
        assert!(said.contains("read grant"), "{said}");
    }

    /// The other containment direction, and the one #76 makes the *intended* arrangement: a path
    /// inside the state directory refuses unless playpen derived it from there.
    #[test]
    fn a_grant_inside_the_state_directory_refuses_unless_it_was_derived() {
        let state = tempfile::TempDir::new().expect("state");
        let inside = state.path().join("agents/claude/p");
        std::fs::create_dir_all(&inside).expect("inside");

        let declared = [grant(&inside, Access::ReadWrite, Scope::Subtree)];
        assert_eq!(
            refuse_if_reachable(Some(state.path()), &declared)
                .expect_err("a declared path inside refuses")
                .code,
            Code::StateReachable
        );

        // Derivation is what makes the exemption safe: the path is inside because playpen
        // computed it from the directory, never because something granted a path containing it.
        let derived = [PathGrant {
            state_derived: true,
            ..grant(&inside, Access::ReadWrite, Scope::Subtree)
        }];
        assert!(refuse_if_reachable(Some(state.path()), &derived).is_ok());
    }

    /// Resolved on both sides, so the check cannot be walked around with a symlink.
    #[test]
    fn a_grant_reaching_the_state_directory_through_a_symlink_refuses() {
        let home = tempfile::TempDir::new().expect("home");
        let state = home.path().join("state/playpen");
        std::fs::create_dir_all(&state).expect("state");
        let link = tempfile::TempDir::new().expect("elsewhere");
        let link = link.path().join("link");
        std::os::unix::fs::symlink(home.path(), &link).expect("symlink");

        let grants = [grant(&link, Access::Read, Scope::Subtree)];
        assert_eq!(
            refuse_if_reachable(Some(&state), &grants)
                .expect_err("refuses")
                .code,
            Code::StateReachable
        );
    }

    /// A grant beside the state directory, and a literal grant of an ancestor, reach nothing: the
    /// check must not refuse a launch that was never a breach.
    #[test]
    fn a_grant_that_reaches_nothing_is_allowed() {
        let home = tempfile::TempDir::new().expect("home");
        let state = home.path().join(".local/state/playpen");
        std::fs::create_dir_all(&state).expect("state");
        let elsewhere = home.path().join("src/playpen");
        std::fs::create_dir_all(&elsewhere).expect("elsewhere");

        let beside = [grant(&elsewhere, Access::ReadWrite, Scope::Subtree)];
        assert!(refuse_if_reachable(Some(&state), &beside).is_ok());
        // A literal grant of an ancestor grants nothing beneath it, so it reaches no record.
        let literal = [grant(home.path(), Access::Read, Scope::Literal)];
        assert!(refuse_if_reachable(Some(&state), &literal).is_ok());
        // Nothing to reach without a state directory; `open` has already refused by then.
        assert!(refuse_if_reachable(None, &beside).is_ok());
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
        // One more than the bound, all of them history: none has a sidecar, so none is live.
        for unix_ms in 0..=RETAINED as u64 {
            plant(&runs, &format!("{}.json", id_at(unix_ms)));
        }
        let id = RunId::allocate().expect("id");
        let _run = RunRecord::open(&id, Some(state.path())).expect("open");
        let names = names(&runs);
        assert!(
            !names.contains(&format!("{}.json", id_at(0))),
            "the oldest piece of history went"
        );
        assert!(names.contains(&format!("{}.json", id_at(1))));
        assert!(names.contains(&format!("{id}.json")), "the new run stays");
        assert_eq!(
            names.iter().filter(|n| n.ends_with(".json")).count(),
            RETAINED + 1,
            "the bound's {RETAINED} most recent ended runs, plus the one live run"
        );
    }

    /// The bug #119 reported: a long session's own record was guaranteed to be evicted, because
    /// shims count as runs and the ring ordered by *start* time. `explain --run` then failed for
    /// the one run most worth inspecting ([ADR 0028]).
    ///
    /// [ADR 0028]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0028-the-run-record-ring-evicts-history-and-never-a-live-run.md
    #[test]
    fn a_live_run_survives_any_number_of_runs_started_after_it() {
        let state = tempfile::TempDir::new().expect("state");
        // The long session: the oldest run there is, and still going.
        let session = id_at(1);
        let live = RunRecord::open(&session, Some(state.path())).expect("open");
        let runs = state.path().join(RUNS);
        // Shims, each one a run of its own, more than enough to fill the ring twice over.
        for unix_ms in 2..=(2 * RETAINED as u64 + 2) {
            plant(&runs, &format!("{}.json", id_at(unix_ms)));
            evict(&runs, RETAINED);
        }

        assert!(is_live(&runs, &session), "the session still holds its lock");
        assert_eq!(
            read(Some(state.path()), &session).expect("the live run's record is still readable"),
            *live.record()
        );

        // Once it ends, it is history like any other, and the oldest of it at that.
        drop(live);
        evict(&runs, RETAINED);
        assert_eq!(
            read(Some(state.path()), &session)
                .expect_err("an ended run takes its place in the ring")
                .code,
            Code::RunUnknown
        );
    }

    /// An un-ended record with no sidecar is dead, not immortal: a record a `SIGKILL`ed playpen
    /// left behind, or one written by a playpen from before the sidecar existed, must still be
    /// evictable or the ring would grow without bound ([ADR 0028]).
    ///
    /// [ADR 0028]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0028-the-run-record-ring-evicts-history-and-never-a-live-run.md
    #[test]
    fn an_unended_record_without_a_sidecar_counts_as_dead() {
        let runs = tempfile::TempDir::new().expect("runs");
        let runs = runs.path();
        let zombie = id_at(1);
        plant(runs, &format!("{zombie}.json"));
        plant(runs, &format!("{}.json", id_at(2)));
        assert!(!is_live(runs, &zombie));
        evict(runs, 1);
        assert_eq!(names(runs), [format!("{}.json", id_at(2))]);
    }

    /// A sidecar left beside an ended record — ADR 0024's fault path ends by `abort` and runs no
    /// destructor — is removed by eviction, which is the second of the two removers.
    #[test]
    fn eviction_removes_a_sidecar_the_run_could_not() {
        let runs = tempfile::TempDir::new().expect("runs");
        let runs = runs.path();
        let faulted = id_at(1);
        plant(runs, &format!("{faulted}.json"));
        plant(runs, &format!("{faulted}.lock"));
        plant(runs, &format!("{}.json", id_at(2)));
        // Nothing holds the planted sidecar's lock, so the run reads as dead despite it.
        assert!(!is_live(runs, &faulted));
        evict(runs, 1);
        assert_eq!(names(runs), [format!("{}.json", id_at(2))]);
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
