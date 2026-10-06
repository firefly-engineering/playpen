//! The Linux denial trace: Landlock audit records, read out of the system journal.
//!
//! Four preconditions stand between a kernel that *can* log and a file that *holds* the log, and
//! each refuses **the flag** under its own code rather than refusing the run as "unsupported":
//! "the kernel is too old", "the backend does not ask for logging" and "you are not in `wheel`"
//! are three different things an operator acts on differently, and collapsing them hides the one
//! that is a five-minute fix.
//!
//! The fourth is not a probe but an **observation**. `audit_enabled` cannot be read without
//! `CAP_AUDIT_CONTROL` — Linux offers no read-only counterpart, so reading whether auditing is on
//! needs a strictly stronger capability than reading what it logged — so playpen provokes a denial
//! of its own and looks for the record. That is a fact about the channel rather than an inference
//! about the subsystem behind it ([ADR 0007], [ADR 0016]).
//!
//! [ADR 0007]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0007-playpen-owns-the-half-the-kernel-cannot-know.md
//! [ADR 0016]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use crate::code::Code;
use crate::refusal::Refusal;

/// The Landlock ABI that first logs a denial at all ([spec §14.5]).
///
/// Spelled, where [`crate::mechanism`] reads the `FS_RESOLVE_UNIX` ABI out of the `landlock`
/// crate's own table: that table is of access *rights*, and this is a `restrict_self` **flag**,
/// whose `since()` the crate keeps `pub(crate)`. There is no public expression of it to defer to.
///
/// Public because the suite's `R-trace-denials` rows build their facts around it, and an ABI they
/// spelled themselves could drift from the one the ladder compares against.
///
/// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
pub const LOGGING_ABI: libc::c_long = 7;

/// What both channel refusals print, because both are fixed the same way.
const REMEDY: &str = "the remedy is `systemctl enable systemd-journald-audit.socket`";

/// The self-test's budget. Measured in a VM on kernel 7.0 with Landlock ABI 8
/// ([#34](https://github.com/firefly-engineering/playpen/issues/34)): a delivered record is
/// queryable by polling within 2.9 ms at p99 and 14 ms at the worst of 1,326, and **every** miss
/// was a lost record rather than a late one, so a longer budget buys nothing.
const BUDGET: Duration = Duration::from_secs(1);

/// How long to leave between journal queries. The record is normally there on the first, so this
/// is the cost of a *miss* and not of a hit: a self-test that fails spends its budget on some
/// forty queries, and one that passes on one or two. Polling rather than `sd_journal_wait()`,
/// which journald only wakes on a 250 ms timer, putting a waiting reader at around 500 ms.
const POLL: Duration = Duration::from_millis(25);

/// The groups `journalctl(1)` names as able to read every journal file.
const JOURNAL_GROUPS: [&str; 3] = ["systemd-journal", "adm", "wheel"];

/// One run's denial trace, once every precondition has held. Opened before launch, followed once
/// there is a child to follow, and closed at teardown — where the self-test runs a **second**
/// time, because a denial flood can overrun journald's receive buffer and make it drop its audit
/// input for good, and an agent denying in a tight loop is that flood.
pub struct Tracing {
    /// The file the operator named.
    file: PathBuf,
    /// A directory playpen owns, where the self-test puts the file it is then denied.
    workspace: PathBuf,
    /// The channel self-test, held rather than called twice by name, so the pass that brackets
    /// the run is the same test as the pass that opened the trace.
    self_test: SelfTest,
    /// The domain the self-test's own denial was logged under, which is what keeps it out of the
    /// run's trace — by its id, read off the record, and never by a pattern over the text.
    self_test_domain: String,
    following: Option<Following>,
    /// The Landlock domain this run's child was confined by, learned from its `status=allocated`
    /// record. It is what a later query filters on, because a domain covers the whole confined
    /// tree where a pid covers one process.
    domain: Option<String>,
}

/// The live tail: a `journalctl` of playpen's own, and the thread draining it into the trace.
#[derive(Debug)]
struct Following {
    journal: std::process::Child,
    draining: std::thread::JoinHandle<Drained>,
}

/// What the tail found while it ran.
#[derive(Debug, Default)]
struct Drained {
    /// The confined child's Landlock domain, if its allocation was logged.
    domain: Option<String>,
    /// Why the tail stopped early, if it did.
    failure: Option<String>,
}

/// What the channel self-test observed. An observation, never an inference: "no record appeared"
/// is a fact, where "auditing is off" would be a guess made on the same evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// The record arrived over `_TRANSPORT=audit`, under this Landlock domain: the channel
    /// delivers.
    Delivers { domain: String },
    /// A record arrived, but only through `_TRANSPORT=kernel` — the kernel's shared print rate
    /// limit, which dropped 40–50 % of self-test records against a background denying at 5/s
    /// while the audit subsystem still reported no loss. Accepting it with a warning would hand
    /// back exactly the trace that reads as "nothing was denied".
    Lossy,
    /// No record appeared within the budget.
    Silent,
    /// The self-test could not be **run** at all: the marker could not be written, or the
    /// throwaway domain did not deny the read. That is playpen's own failure and not the
    /// channel's, so it is not `channel-silent` — an operator told to enable journald's audit
    /// socket would be fixing the wrong thing, and nothing was provoked for the channel to have
    /// carried.
    Unprovoked(String),
}

/// The channel self-test, as a value: held by the [`Tracing`] so that the pass bracketing the run
/// is the same test as the pass that opened it, and shared rather than cloned because a self-test
/// that differed between the two passes would make the bracket meaningless.
pub type SelfTest = std::sync::Arc<dyn Fn(&Path) -> Channel + Send + Sync>;

/// What the trace needs of the host and of the backend. [`Facts::probed`] is what every launch
/// uses; it is a value rather than four calls so the suite's `R-trace-denials` row can drive the
/// **real** ladder with facts no host would present — on a host with all four preconditions, none
/// of the six refusals could be provoked otherwise, and a row that cannot run is not an assertion
/// ([ADR 0016]).
///
/// [ADR 0016]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md
pub struct Facts {
    /// The kernel's Landlock version query, with the errno kept: `ENOSYS` and `EOPNOTSUPP` are
    /// two different refusals.
    pub abi: Result<libc::c_long, i32>,
    /// Whether the pinned backend asks for `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`.
    pub backend_logs: bool,
    /// Whether this user can read the journal, attempted rather than inferred.
    pub readable: Box<dyn FnOnce() -> Result<(), String>>,
    /// The channel self-test, run once before the launch and once after the agent exits.
    pub self_test: SelfTest,
}

impl Facts {
    /// This host and this build, each read on playpen's own authority.
    pub fn probed() -> Facts {
        Facts {
            abi: abi(),
            backend_logs: backend_logs(),
            readable: Box::new(journal_readable),
            self_test: std::sync::Arc::new(channel_self_test),
        }
    }
}

/// Open the trace for this run, refusing the flag at the first precondition that does not hold.
/// `workspace` is a directory playpen owns, where the self-test can make the file it is denied.
///
/// This is the one [`crate::launch`] calls on every launch.
pub fn open(file: &Path, workspace: &Path) -> Result<Tracing, Refusal> {
    open_with(Facts::probed(), file, workspace)
}

/// [`open`], with the preconditions handed in rather than probed.
pub fn open_with(facts: Facts, file: &Path, workspace: &Path) -> Result<Tracing, Refusal> {
    let Facts {
        abi,
        backend_logs,
        readable,
        self_test,
    } = facts;
    let test = self_test.clone();
    let domain = ladder(abi, backend_logs, readable, || test(workspace), workspace)?;
    let tracing = Tracing {
        file: file.to_owned(),
        workspace: workspace.to_owned(),
        self_test,
        self_test_domain: domain,
        following: None,
        domain: None,
    };
    tracing.create()?;
    Ok(tracing)
}

/// The preconditions, **in order**, each refusing the flag under its own code. Separated from the
/// probes themselves, so the order is a thing a test can assert on a host that satisfies all
/// four. Returns the domain the self-test's own denial was logged under.
fn ladder(
    abi: Result<libc::c_long, i32>,
    backend_logs: bool,
    readable: impl FnOnce() -> Result<(), String>,
    channel: impl FnOnce() -> Channel,
    workspace: &Path,
) -> Result<String, Refusal> {
    match abi {
        // Compiled in but switched off at boot. Distinct from absence, because the operator's
        // move differs: a boot parameter rather than a kernel.
        Err(libc::EOPNOTSUPP) => {
            return Err(Refusal::new(
                Code::TraceLandlockInactive,
                "--trace-denials needs Landlock, which this kernel has and has disabled: the \
                 version query answered EOPNOTSUPP"
                    .to_string(),
            ));
        }
        Err(errno) => {
            let err = std::io::Error::from_raw_os_error(errno);
            return Err(Refusal::new(
                Code::TraceKernelAbi,
                format!(
                    "--trace-denials needs Landlock ABI {LOGGING_ABI} or above, and this kernel \
                     answered no version at all: {err}"
                ),
            ));
        }
        Ok(abi) if abi < LOGGING_ABI => {
            return Err(Refusal::new(
                Code::TraceKernelAbi,
                format!(
                    "--trace-denials needs Landlock ABI {LOGGING_ABI} or above, which is where a \
                     denial is first logged at all; this kernel offers ABI {abi}"
                ),
            ));
        }
        Ok(_) => {}
    }
    if !backend_logs {
        return Err(Refusal::new(
            Code::TraceBackendNoLogging,
            "--trace-denials needs the backend to pass LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON, \
             without which the kernel logs nothing a confined process does after exec — and \
             after exec is the whole of a run; this pin does not pass it"
                .to_string(),
        ));
    }
    if let Err(cause) = readable() {
        return Err(Refusal::new(
            Code::TraceNoJournalAccess,
            format!(
                "--trace-denials reads the system journal, which this user cannot: {cause}; {} \
                 can read every journal file, and this user is in {}",
                JOURNAL_GROUPS.join(", "),
                groups()
            ),
        ));
    }
    match channel() {
        Channel::Delivers { domain } => Ok(domain),
        Channel::Unprovoked(why) => Err(Refusal::new(
            Code::StateIo,
            format!(
                "--trace-denials could not run its channel self-test under {}, so whether the \
                 channel delivers was never observed: {why}",
                workspace.display()
            ),
        )),
        Channel::Lossy => Err(Refusal::new(
            Code::TraceChannelLossy,
            format!(
                "--trace-denials found the self-test's own denial only on _TRANSPORT=kernel, the \
                 kernel's shared print rate limit, which drops records silently; {REMEDY}"
            ),
        )),
        Channel::Silent => Err(Refusal::new(
            Code::TraceChannelSilent,
            format!(
                "--trace-denials provoked a denial under {} and no record of it reached the \
                 journal within {} ms; {REMEDY}",
                workspace.display(),
                BUDGET.as_millis(),
            ),
        )),
    }
}

/// Everything but the self-test, which is a closure and has nothing to show.
impl std::fmt::Debug for Tracing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tracing")
            .field("file", &self.file)
            .field("workspace", &self.workspace)
            .field("self_test_domain", &self.self_test_domain)
            .field("following", &self.following)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

impl Tracing {
    /// The file, created empty, so an operator reading it sees this run's denials and never the
    /// last run's.
    fn create(&self) -> Result<(), Refusal> {
        std::fs::File::create(&self.file).map(drop).map_err(|err| {
            // The flag's operand is unusable, which is the invocation's problem rather than the
            // channel's: no `refusal.trace.*` code would be true of it.
            Refusal::new(
                Code::InvocationUsage,
                format!(
                    "--trace-denials cannot write {}: {err}",
                    self.file.display()
                ),
            )
        })
    }

    /// The file this run is traced into, for the record to name.
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Start tailing, from `since`, for the tree under `pid`. Called once there is a child, so
    /// that there is something to tear down if the tail dies — and from `since` rather than from
    /// now, so a denial between the fork and this call is in the trace rather than lost to the
    /// race.
    pub fn follow(&mut self, pid: libc::pid_t, since: SystemTime) {
        let spawned = query(since)
            .arg("--follow")
            .stdout(std::process::Stdio::piped())
            .spawn();
        match spawned {
            Ok(mut journal) => match journal.stdout.take() {
                Some(stdout) => {
                    let file = std::fs::OpenOptions::new().append(true).open(&self.file);
                    let exclude = self.self_test_domain.clone();
                    let draining = std::thread::spawn(move || drain(stdout, file, pid, &exclude));
                    self.following = Some(Following { journal, draining });
                }
                None => {
                    let _ = journal.kill();
                    self.note("the journal tail had no output to read");
                }
            },
            Err(err) => self.note(&format!("the journal could not be followed: {err}")),
        }
    }

    /// Stop the tail and bracket the run with a second self-test ([spec §14.5], teardown step
    /// 18.4). Returns why the trace is **unverified**, where it is: a failure here never changes
    /// the run's exit status, and a trace that cannot be vouched for is said to be so rather than
    /// presented as complete.
    ///
    /// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
    pub fn stop(&mut self) -> Option<String> {
        if let Some(following) = self.following.take() {
            let drained = following.stop();
            self.domain = drained.domain;
            if let Some(failure) = drained.failure {
                return Some(self.unverified(failure));
            }
        }
        // Never cached, and never skipped because the first one passed: what this one looks for
        // is a channel that stopped working *during* the run.
        match (self.self_test)(&self.workspace) {
            Channel::Delivers { .. } => None,
            Channel::Lossy => Some(self.unverified(format!(
                "the channel self-test now finds its own denial only on _TRANSPORT=kernel, so \
                 records may have been dropped during the run; {REMEDY}"
            ))),
            Channel::Silent => Some(self.unverified(format!(
                "the channel self-test now finds no record of its own denial at all, so the \
                 journal stopped carrying them during the run; {REMEDY}"
            ))),
            // Teardown refuses nothing, so a self-test that could not be run leaves the trace
            // unverified for the same reason a failing one does: nothing vouched for it.
            Channel::Unprovoked(why) => Some(self.unverified(format!(
                "the channel self-test could not be run after the agent exited, so the trace is \
                 unvouched for rather than complete: {why}"
            ))),
        }
    }

    /// The Landlock domain this run was confined by, once the tail has read its allocation. What
    /// a later query filters on, because a domain covers the whole confined tree where a pid
    /// covers one process.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// Mark the trace unverified in the trace itself, and say why. The operator may never read
    /// the run record, and a file that ends without this reads as a complete account.
    fn unverified(&self, why: String) -> String {
        self.note(&format!("unverified: {why}"));
        why
    }

    /// One playpen sentence in the trace, marked so it cannot be read as a kernel record. There
    /// is nowhere else for it to go: the flag never writes to stderr.
    fn note(&self, what: &str) {
        let appended = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.file)
            .and_then(|mut file| writeln!(file, "# playpen: {what}"));
        let _ = appended;
    }
}

impl Following {
    fn stop(mut self) -> Drained {
        // The thread ends when its pipe does, and the pipe ends when `journalctl --follow` does.
        let killed = self
            .journal
            .kill()
            .and_then(|()| self.journal.wait().map(drop));
        let mut drained = self.draining.join().unwrap_or_else(|_| Drained {
            domain: None,
            failure: Some("the thread draining the journal panicked".to_string()),
        });
        if let Err(err) = killed {
            drained
                .failure
                .get_or_insert(format!("the journal tail could not be stopped: {err}"));
        }
        drained
    }
}

/// Drain `stdout` into `file`, keeping the records of the domain `pid` was confined by and never
/// those of `exclude`, the self-test's own domain.
///
/// The domain is learnt rather than guessed: Landlock logs a `status=allocated` record naming the
/// pid that allocated it, and every denial in the tree beneath carries the same `domain`. Until
/// that record arrives there is nothing of this run to keep, and it arrives first, because a
/// domain denies nothing before it exists.
fn drain(
    stdout: std::process::ChildStdout,
    file: std::io::Result<std::fs::File>,
    pid: libc::pid_t,
    exclude: &str,
) -> Drained {
    let mut drained = Drained::default();
    let mut file = match file {
        Ok(file) => file,
        Err(err) => {
            drained.failure = Some(format!("the trace could not be appended to: {err}"));
            return drained;
        }
    };
    let pid = pid.to_string();
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else {
            drained.failure = Some("the journal stopped being readable mid-run".to_string());
            return drained;
        };
        let Some(entry) = Entry::read(&line) else {
            continue;
        };
        let fields = Fields::of(&entry.message);
        let Some(domain) = fields.get("domain") else {
            continue;
        };
        if domain == exclude {
            continue;
        }
        if drained.domain.is_none()
            && fields.get("status") == Some("allocated")
            && fields.get("pid") == Some(pid.as_str())
        {
            drained.domain = Some(domain.to_owned());
        }
        if drained.domain.as_deref() != Some(domain) {
            continue;
        }
        if writeln!(file, "{}\t{}", entry.transport, entry.message).is_err() {
            drained.failure = Some("the trace could not be written to".to_string());
            return drained;
        }
    }
    drained
}

/// One journal entry, as much of it as a trace needs. An `Entry` and never a `Record`:
/// a **run record** is what that word means here ([`crate::record::Record`]).
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    transport: String,
    message: String,
}

impl Entry {
    /// Read one line of `journalctl -o json`. A real parser over the framing, because a journal
    /// field is arbitrary bytes and journald renders one that is not UTF-8 as an array of them.
    fn read(line: &str) -> Option<Entry> {
        let entry: serde_json::Value = serde_json::from_str(line).ok()?;
        Some(Entry {
            transport: text(entry.get("_TRANSPORT")?)?,
            message: text(entry.get("MESSAGE")?)?,
        })
    }
}

/// A journal field as text: a string, or the bytes journald renders when it is not one.
fn text(field: &serde_json::Value) -> Option<String> {
    match field {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Array(bytes) => {
            let bytes: Vec<u8> = bytes
                .iter()
                .map(|byte| byte.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect::<Option<_>>()?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

/// The `key=value` fields of one audit record, **tokenised** rather than matched ([spec §14.5]).
/// A pattern over the text would find `path=` inside a filename, and audit's own encodings — a
/// quoted value, and a hex-encoded one where the value holds a space or a quote — are lexical
/// facts a pattern has to re-guess at every call site.
///
/// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
#[derive(Debug, Default, PartialEq, Eq)]
struct Fields(Vec<(String, String)>);

impl Fields {
    fn of(message: &str) -> Fields {
        let mut fields = Vec::new();
        let mut rest = message;
        while let Some(equals) = rest.find('=') {
            let (key, after) = rest.split_at(equals);
            // The key is the run of non-space before the `=`, so a value that held one is never
            // mistaken for a key.
            let key = key.rsplit([' ', '\t']).next().unwrap_or(key);
            let after = &after[1..];
            let (value, tail) = match after.strip_prefix('"') {
                // A quoted value runs to the next quote: audit hex-encodes a value holding one,
                // so there is no escape to honour inside.
                Some(quoted) => match quoted.find('"') {
                    Some(end) => (quoted[..end].to_owned(), &quoted[end + 1..]),
                    None => (quoted.to_owned(), ""),
                },
                None => {
                    let end = after.find([' ', '\t']).unwrap_or(after.len());
                    (unhex(key, &after[..end]), &after[end..])
                }
            };
            if !key.is_empty() {
                fields.push((key.to_owned(), value));
            }
            rest = tail;
        }
        Fields(fields)
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

/// Audit's fields whose value is a **string**, and so is either quoted or hex-encoded. Decided by
/// the key and never by the shape of the value: `ino=1234` and `pid=4242` are decimal numbers that
/// are also valid hex, so a value-only rule would decode them into nonsense. Which keys carry a
/// string is a lexical fact about audit's format, and this tokenizer is where it belongs.
const ENCODED_KEYS: [&str; 5] = ["path", "exe", "comm", "cwd", "name"];

/// An unquoted value of a string-valued `key` that is an even run of hex digits decoding to text
/// is the encoding audit uses where the value holds a space or a quote; anything else is itself.
fn unhex(key: &str, value: &str) -> String {
    let encoded = ENCODED_KEYS.contains(&key)
        && value.len() >= 2
        && value.len().is_multiple_of(2)
        && value.bytes().all(|b| b.is_ascii_hexdigit());
    if !encoded {
        return value.to_owned();
    }
    let bytes: Option<Vec<u8>> = (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).ok())
        .collect();
    match bytes.and_then(|bytes| String::from_utf8(bytes).ok()) {
        Some(decoded) => decoded,
        None => value.to_owned(),
    }
}

/// The kernel's own Landlock version query, as [`crate::mechanism`] makes it, with the errno kept
/// rather than the message: `ENOSYS` and `EOPNOTSUPP` are two different refusals of the flag.
fn abi() -> Result<libc::c_long, i32> {
    crate::mechanism::landlock_abi().map_err(|err| err.raw_os_error().unwrap_or(libc::ENOSYS))
}

/// Whether the pinned backend asks the kernel to log a denial made after `exec`. A property of
/// the build and not of the host, so it is read from the backend rather than probed: Landlock
/// logs nothing post-`exec` without `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`, and post-`exec` is
/// exactly playpen's shape. Upstream nono passes flags `0`, so with it this would always refuse.
fn backend_logs() -> bool {
    nono::LANDLOCK_LOG_NEW_EXEC_REQUESTED
}

/// Whether this user can read the journal, **attempted** rather than inferred from group
/// membership: the groups are what names the cause afterwards, not what decides it.
///
/// It asks for **one entry and requires one back**, rather than asking for none. `journalctl -n 0`
/// exits 0 for a user in none of [`JOURNAL_GROUPS`] — it opens no file, says so on stderr, and
/// reports success — so a readability check built on its status alone passes for exactly the user
/// it exists to catch, and the permissions problem then resurfaces as `channel-silent`: the
/// misdiagnosis this rung is here to prevent.
fn journal_readable() -> Result<(), String> {
    let read = std::process::Command::new("journalctl")
        .args(["--quiet", "--no-pager", "-n", "1", "-o", "json"])
        .stdin(std::process::Stdio::null())
        .output();
    match read {
        Err(err) => Err(format!("journalctl could not be run: {err}")),
        Ok(output) if !output.status.success() => Ok(Err(format!(
            "journalctl exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))?),
        // Asking for one entry and getting none means no journal file was opened: a journal this
        // user could read holds at least journald's own account of starting.
        Ok(output) if output.stdout.iter().all(u8::is_ascii_whitespace) => Err(format!(
            "journalctl opened no journal file, so it returned no entry at all{}",
            match String::from_utf8_lossy(&output.stderr).trim() {
                "" => String::new(),
                said => format!(": {said}"),
            }
        )),
        Ok(_) => Ok(()),
    }
}

/// This user's groups, for a refusal to name the cause with. `id -Gn` is what the operator would
/// run themselves, and reading it from the process is the same answer without the process.
fn groups() -> String {
    // SAFETY: the first call asks for the count by passing a zero-length buffer, which `getgroups`
    // answers without writing; the second fills a buffer of exactly that length.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let unreadable = || "no group this call could read".to_string();
    if count < 0 {
        return unreadable();
    }
    let mut gids = vec![0 as libc::gid_t; usize::try_from(count).unwrap_or(0)];
    // SAFETY: as above, and `gids` holds exactly `count` elements.
    if unsafe { libc::getgroups(count, gids.as_mut_ptr()) } < 0 {
        return unreadable();
    }
    let mut named = String::new();
    for gid in gids {
        let separator = if named.is_empty() { "" } else { ", " };
        let _ = write!(named, "{separator}{}", group_name(gid));
    }
    match named.is_empty() {
        true => "no group at all".to_string(),
        false => named,
    }
}

/// The name of group `gid`, or the number where the host knows no name for it.
fn group_name(gid: libc::gid_t) -> String {
    // SAFETY: `getgrgid` returns a pointer into static storage or null, and the name it points at
    // is NUL-terminated and is copied before anything can call `getgrgid` again.
    unsafe {
        let group = libc::getgrgid(gid);
        match group.is_null() || (*group).gr_name.is_null() {
            true => gid.to_string(),
            false => std::ffi::CStr::from_ptr((*group).gr_name)
                .to_string_lossy()
                .into_owned(),
        }
    }
}

/// The channel self-test ([spec §14.5]): provoke a denial playpen knows the shape of, and poll
/// the journal for its record. Never cached — the question is whether the channel delivers *now*.
///
/// [spec §14.5]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#145---trace-denials
fn channel_self_test(workspace: &Path) -> Channel {
    // A path of this run's own, so the record the poll finds is this self-test's and not a
    // concurrent playpen's.
    let marker = workspace.join(format!(
        "trace-self-test-{}-{}",
        std::process::id(),
        now_nanos()
    ));
    if let Err(err) = std::fs::write(&marker, b"playpen denial-channel self-test\n") {
        return Channel::Unprovoked(format!(
            "the marker {} is unwritable: {err}",
            marker.display()
        ));
    }
    // A second back, because `--since` takes whole seconds: without it a record stamped in this
    // same second could fall before a window cut at the next one. Not a skew margin — journald
    // stamps from the clock this reads — but the resolution of the query.
    let since = SystemTime::now() - Duration::from_secs(1);
    let provoked = provoke(&marker);
    let _ = std::fs::remove_file(&marker);
    let pid = match provoked {
        Ok(pid) => pid.to_string(),
        Err(why) => return Channel::Unprovoked(why),
    };
    let wanted = marker.to_string_lossy().into_owned();
    let deadline = Instant::now() + BUDGET;
    let mut lossy = false;
    // The **domain** this self-test's own denial was logged under, learnt from the
    // `status=allocated` record naming the pid that allocated it. Two fields identify the record
    // and not one ([spec §14.5]): the path is unique to this self-test, and the domain is what a
    // *concurrent* playpen's self-test cannot share even if it chose the same path.
    let mut provoker = None;
    loop {
        for entry in since_then(since) {
            let fields = Fields::of(&entry.message);
            if fields.get("status") == Some("allocated") && fields.get("pid") == Some(pid.as_str())
            {
                provoker = fields.get("domain").map(str::to_owned);
            }
            if fields.get("path") != Some(wanted.as_str()) {
                continue;
            }
            // Where the allocation was logged too, the denial must carry the same domain. Where it
            // was not — the record for it can be dropped on its own — the unique path stands
            // alone, because refusing a delivered record for a *missing* second record would
            // report a working channel as a broken one.
            if provoker.is_some() && fields.get("domain") != provoker.as_deref() {
                continue;
            }
            if entry.transport == "audit" {
                return Channel::Delivers {
                    domain: fields.get("domain").unwrap_or_default().to_owned(),
                };
            }
            lossy = true;
        }
        if Instant::now() >= deadline {
            return match lossy {
                true => Channel::Lossy,
                false => Channel::Silent,
            };
        }
        std::thread::sleep(POLL);
    }
}

/// Nanoseconds since the epoch, to make one self-test's marker path its own.
fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0)
}

/// Fork a child into a throwaway Landlock domain that grants nothing, and have it read `marker`.
/// Whether the read is denied is the whole of the child's job; the record it leaves is what the
/// caller is after. Returns the pid that was confined, which is how the domain it allocated is
/// found in the journal.
///
/// The child does nothing between `fork` and `_exit` but system calls on memory the parent laid
/// out first, so this is sound in a process that has threads — which the second, post-run
/// self-test runs in.
fn provoke(marker: &Path) -> Result<libc::pid_t, String> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(marker.as_os_str().as_bytes())
        .map_err(|err| format!("the marker path cannot be a C string: {err}"))?;
    let attr = LandlockRulesetAttr {
        handled_access_fs: LANDLOCK_ACCESS_FS_READ_FILE,
        handled_access_net: 0,
        scoped: 0,
    };
    // SAFETY: `fork` in a process whose child, below, calls nothing but system calls on memory
    // allocated before the fork.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "the self-test could not fork: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        // SAFETY: every call here is async-signal-safe, and `attr` and `path` outlive them all.
        unsafe {
            let ruleset = libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::from_ref(&attr),
                size_of::<LandlockRulesetAttr>(),
                0,
            );
            if ruleset < 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0) != 0
            {
                libc::_exit(2);
            }
            let fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            // Denied is what this child is for; anything else says the domain did not apply, and
            // the poll would then be looking for the record of nothing.
            libc::_exit(if fd < 0 { 0 } else { 3 });
        }
    }
    let mut status = 0;
    // SAFETY: `pid` is this process's own child, and `status` is a local the call fills.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    match (libc::WIFEXITED(status), libc::WEXITSTATUS(status)) {
        (true, 0) => Ok(pid),
        (true, 2) => Err("the throwaway Landlock domain could not be applied".to_string()),
        (true, 3) => Err(format!(
            "the throwaway Landlock domain did not deny reading {}",
            marker.display()
        )),
        _ => Err(format!(
            "the self-test's child did not exit cleanly: {status}"
        )),
    }
}

/// `struct landlock_ruleset_attr` from `include/uapi/linux/landlock.h`. Spelled here because the
/// `landlock` crate's builder allocates, and this one is laid out before a fork and used after it.
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// `LANDLOCK_ACCESS_FS_READ_FILE`, the one right the self-test's domain handles and grants to
/// nothing, so that reading any file at all is a denial.
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;

/// The journal's kernel-facing records since `since`, read once.
fn since_then(since: SystemTime) -> Vec<Entry> {
    let Ok(output) = query(since).output() else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(Entry::read)
        .collect()
}

/// The query both the self-test and the tail make: every record the kernel put in the journal
/// since `since`, on either transport a Landlock denial can arrive by, as JSON.
///
/// Both transports, because telling them apart is the point: the audit one is the channel, and
/// the kernel one is the shared print rate limit that silently drops records.
fn query(since: SystemTime) -> std::process::Command {
    let epoch = since
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    let mut command = std::process::Command::new("journalctl");
    command
        .args(["--quiet", "--no-pager", "-o", "json"])
        .arg(format!("--since=@{epoch}"))
        .args(["_TRANSPORT=audit", "+", "_TRANSPORT=kernel"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOCATED: &str = "LANDLOCK_DOMAIN domain=195ba459b status=allocated mode=enforcing \
                             pid=4242 uid=1000 exe=\"/usr/bin/claude\" comm=\"claude\"";
    const DENIAL: &str = "LANDLOCK_ACCESS domain=195ba459b blockers=fs.read_file \
                          path=\"/home/u/.ssh/id_ed25519\" dev=\"vda2\" ino=1234";

    fn delivers() -> Channel {
        Channel::Delivers {
            domain: "abc".to_string(),
        }
    }

    #[test]
    fn every_precondition_holding_opens_the_trace() {
        let domain = ladder(Ok(9), true, || Ok(()), delivers, Path::new("/state"));
        assert_eq!(domain, Ok("abc".to_string()));
    }

    #[test]
    fn an_abi_below_seven_names_the_kernel_and_the_abi() {
        for abi in 1..LOGGING_ABI {
            let refusal = ladder(
                Ok(abi),
                true,
                || Ok(()),
                || Channel::Silent,
                Path::new("/s"),
            )
            .expect_err("refuses");
            assert_eq!(refusal.code, Code::TraceKernelAbi);
            assert!(
                refusal.message().contains(&format!("ABI {abi}")),
                "{refusal}"
            );
        }
    }

    /// `ENOSYS` and `EOPNOTSUPP` are a kernel without Landlock and a kernel that has it switched
    /// off at boot, and the operator's move differs for each ([spec §14.5]).
    #[test]
    fn landlock_absent_and_landlock_disabled_are_distinct() {
        let refuses = |errno| {
            ladder(
                Err(errno),
                true,
                || Ok(()),
                || Channel::Silent,
                Path::new("/s"),
            )
            .expect_err("refuses")
            .code
        };
        assert_eq!(refuses(libc::ENOSYS), Code::TraceKernelAbi);
        assert_eq!(refuses(libc::EOPNOTSUPP), Code::TraceLandlockInactive);
    }

    #[test]
    fn a_backend_that_does_not_ask_for_logging_refuses_before_the_journal_is_read() {
        let refusal = ladder(
            Ok(9),
            false,
            || panic!("the journal is read only once the backend could log"),
            || panic!("the channel is tested only once the backend could log"),
            Path::new("/s"),
        )
        .expect_err("refuses");
        assert_eq!(refusal.code, Code::TraceBackendNoLogging);
        assert!(refusal.message().contains("LOG_NEW_EXEC_ON"), "{refusal}");
    }

    #[test]
    fn an_unreadable_journal_names_the_cause_and_the_groups() {
        let refusal = ladder(
            Ok(9),
            true,
            || Err("journalctl exited 1: no journal files were opened".to_string()),
            || panic!("the channel is tested only once the journal can be read"),
            Path::new("/s"),
        )
        .expect_err("refuses");
        assert_eq!(refusal.code, Code::TraceNoJournalAccess);
        assert!(
            refusal.message().contains("no journal files were opened")
                && refusal.message().contains("systemd-journal"),
            "{refusal}"
        );
    }

    #[test]
    fn a_silent_channel_and_a_lossy_one_both_print_the_remedy() {
        for (channel, code) in [
            (Channel::Silent, Code::TraceChannelSilent),
            (Channel::Lossy, Code::TraceChannelLossy),
        ] {
            let refusal = ladder(Ok(9), true, || Ok(()), || channel.clone(), Path::new("/s"))
                .expect_err("refuses");
            assert_eq!(refusal.code, code);
            assert!(
                refusal.message().contains("systemd-journald-audit.socket"),
                "{refusal}"
            );
        }
    }

    /// The rungs are ordered, and each test above asserts one by making every rung below it
    /// panic. This one asserts the top: a kernel that cannot log is named as such even on a build
    /// whose backend could not have logged either.
    #[test]
    fn the_ladder_refuses_at_the_first_precondition_that_fails() {
        let refusal = ladder(
            Ok(1),
            false,
            || panic!("the journal is read last but one"),
            || panic!("the channel is tested last"),
            Path::new("/s"),
        )
        .expect_err("refuses");
        assert_eq!(refusal.code, Code::TraceKernelAbi);
    }

    #[test]
    fn a_record_is_read_as_its_fields_and_never_as_text() {
        let fields = Fields::of(DENIAL);
        assert_eq!(fields.get("domain"), Some("195ba459b"));
        assert_eq!(fields.get("blockers"), Some("fs.read_file"));
        assert_eq!(fields.get("path"), Some("/home/u/.ssh/id_ed25519"));
        assert_eq!(fields.get("ino"), Some("1234"));
        assert_eq!(fields.get("status"), None);
    }

    /// Why it is a tokenizer: `path=` occurs inside this filename, and a pattern looking for it
    /// would find the wrong one.
    #[test]
    fn a_key_inside_a_value_is_not_a_field() {
        let fields = Fields::of("LANDLOCK_ACCESS domain=1 path=\"/tmp/path=2\" ino=3");
        assert_eq!(fields.get("path"), Some("/tmp/path=2"));
        assert_eq!(fields.get("ino"), Some("3"));
    }

    /// audit hex-encodes a value holding a space or a quote, and a trace showing the encoding
    /// would hide which file was denied.
    #[test]
    fn a_hex_encoded_value_is_decoded_and_a_plain_one_is_left_alone() {
        assert_eq!(
            Fields::of("LANDLOCK_ACCESS domain=1 path=2F746D702F6120620A63").get("path"),
            Some("/tmp/a b\nc")
        );
        // A path that merely looks like hex, of odd length or holding a non-digit, is itself.
        assert_eq!(Fields::of("path=abc").get("path"), Some("abc"));
        assert_eq!(Fields::of("path=zz").get("path"), Some("zz"));
    }

    /// The reason the decoding is decided by the key: a decimal number is very often valid hex,
    /// and `ino=1234` decoded as one would read as two bytes of nonsense.
    #[test]
    fn a_number_that_is_also_valid_hex_is_left_alone() {
        let fields = Fields::of("LANDLOCK_DOMAIN domain=4242 pid=1234 ino=22 uid=1000");
        assert_eq!(fields.get("pid"), Some("1234"));
        assert_eq!(fields.get("ino"), Some("22"));
        assert_eq!(fields.get("domain"), Some("4242"));
        assert_eq!(fields.get("uid"), Some("1000"));
    }

    #[test]
    fn an_allocation_names_the_pid_that_made_the_domain() {
        let fields = Fields::of(ALLOCATED);
        assert_eq!(fields.get("status"), Some("allocated"));
        assert_eq!(fields.get("pid"), Some("4242"));
        assert_eq!(fields.get("domain"), Some("195ba459b"));
    }

    #[test]
    fn a_journal_entry_is_read_through_a_parser() {
        let line = serde_json::json!({"_TRANSPORT": "audit", "MESSAGE": DENIAL}).to_string();
        assert_eq!(
            Entry::read(&line),
            Some(Entry {
                transport: "audit".to_string(),
                message: DENIAL.to_string(),
            })
        );
        assert_eq!(Entry::read("not json"), None);
        assert_eq!(Entry::read(r#"{"MESSAGE":"no transport"}"#), None);
    }

    /// journald renders a field that is not UTF-8 as the bytes it is, and a trace that dropped
    /// those records would be missing exactly the paths worth looking at.
    #[test]
    fn a_journal_entry_whose_message_is_bytes_is_read_too() {
        let line =
            serde_json::json!({"_TRANSPORT": "kernel", "MESSAGE": [107, 61, 118]}).to_string();
        assert_eq!(
            Entry::read(&line).map(|entry| entry.message),
            Some("k=v".to_string())
        );
    }

    /// The whole of the tail's filtering, driven as the journal would drive it: the allocation
    /// teaches it the domain, a denial under that domain is kept, one under another domain is
    /// not, and the self-test's own domain is excluded by its id.
    #[test]
    fn the_tail_keeps_this_runs_domain_and_nothing_else() {
        let entry = |message: &str| {
            serde_json::json!({"_TRANSPORT": "audit", "MESSAGE": message}).to_string()
        };
        let lines = [
            // Another run's denial, before this one's domain is known.
            entry("LANDLOCK_ACCESS domain=ffff blockers=fs.read_file path=\"/other\""),
            // The self-test's own, which is never this run's business.
            entry("LANDLOCK_ACCESS domain=5e1f blockers=fs.read_file path=\"/self-test\""),
            entry(ALLOCATED),
            entry(DENIAL),
            entry("LANDLOCK_ACCESS domain=ffff blockers=fs.write_file path=\"/other\""),
        ]
        .join("\n");
        let dir = tempdir();
        let trace = dir.join("trace");
        let drained = drain(feed(&lines), std::fs::File::create(&trace), 4242, "5e1f");
        assert_eq!(drained.domain.as_deref(), Some("195ba459b"));
        assert_eq!(drained.failure, None);
        let written = std::fs::read_to_string(&trace).expect("the trace");
        assert_eq!(written.lines().count(), 2, "{written}");
        assert!(written.contains("status=allocated"), "{written}");
        assert!(written.contains("id_ed25519"), "{written}");
        assert!(!written.contains("/other"), "{written}");
        assert!(!written.contains("/self-test"), "{written}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The host this runs on decides what the ladder says, and both answers are correct ones:
    /// what must hold either way is that it answers rather than hangs, and that a refusal is one
    /// of the six the registry holds for this flag.
    #[test]
    fn this_host_answers_the_ladder() {
        let dir = tempdir();
        match open(&dir.join("trace"), &dir) {
            Ok(tracing) => assert!(tracing.file().exists()),
            Err(refusal) => assert!(
                matches!(
                    refusal.code,
                    Code::TraceKernelAbi
                        | Code::TraceLandlockInactive
                        | Code::TraceBackendNoLogging
                        | Code::TraceNoJournalAccess
                        | Code::TraceChannelSilent
                        | Code::TraceChannelLossy
                ),
                "{refusal}"
            ),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The self-test is worth nothing if its own denial does not happen: a child that was not
    /// confined reads the marker, and the poll then looks for the record of nothing.
    #[test]
    fn the_self_tests_child_is_denied_the_marker_it_is_pointed_at() {
        let dir = tempdir();
        let marker = dir.join("marker");
        std::fs::write(&marker, b"x").expect("the marker");
        assert!(
            provoke(&marker).is_ok(),
            "the throwaway domain denied the read"
        );
        // A marker that is not there at all is **still** denied, not `ENOENT`: the domain handles
        // `READ_FILE` and grants it nowhere, so the denial is decided before the path is looked
        // up. That is the never-`ENOENT` law ([spec §14.4]) holding at the self-test's own
        // expense, and it is why the "did not deny" arm of `provoke` cannot be reached by
        // removing the marker — only by a domain that failed to apply.
        std::fs::remove_file(&marker).expect("reclaimed");
        assert!(provoke(&marker).is_ok(), "denied, and never absent");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A directory of this test's own, reclaimed by the test that made it.
    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "playpen-trace-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("a directory of this test's own");
        dir
    }

    /// `lines` on the reading end of a pipe, as `journalctl --follow` would deliver them, closed
    /// so the drain ends.
    fn feed(lines: &str) -> std::process::ChildStdout {
        let mut echo = std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("a pipe to read");
        let mut stdin = echo.stdin.take().expect("the writing end");
        stdin.write_all(lines.as_bytes()).expect("fed");
        drop(stdin);
        let stdout = echo.stdout.take().expect("the reading end");
        // Reaped here: the pipe it wrote is buffered, so the lines survive its exit.
        echo.wait().expect("the feeder exits");
        stdout
    }
}
