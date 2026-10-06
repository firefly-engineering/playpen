//! Minters ([spec §7.2]): **credentials are minted outside the boundary, and only phantoms cross
//! it** ([ADR 0008]).
//!
//! A minter is an operator-declared executable. playpen runs it **unconfined on the host, before
//! the launch**, hands it the route and its scope as versioned JSON on stdin, and reads
//! `{token, expires_at}` from stdout. Nothing about this is per-kind: a minter is chosen per
//! provider ([ADR 0018]).
//!
//! **Stdout is a secret channel.** What comes back is held in [`Zeroizing`] from the moment it is
//! read, is never logged, never shown by `playpen explain`, and never written to the run record —
//! which holds `expires_at` and the route, and nothing else of it. [`Minted`]'s own `Debug` says
//! so rather than printing it.
//!
//! **A failure before launch refuses the whole run.** A minter that hangs must not hang the
//! launch, so it is bounded by `timeout`, default [`DEFAULT_TIMEOUT`]: herdr and buzz expect a
//! process or an error. The timeout decides how long playpen waits, never what is reachable, so it
//! is not a second policy author. Launching without the credential would produce a run that works
//! for ten minutes and then fails at the first push.
//!
//! [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
//! [ADR 0008]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0008-credentials-are-minted-outside-and-only-phantoms-cross-the-boundary.md
//! [ADR 0018]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0018-playpen-authenticates-outside-the-boundary.md

use std::fmt;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::code::Code;
use crate::policy::{Forge, Minter};
use crate::refusal::Refusal;

/// The version of the minter contract: what playpen puts on stdin, so a minter can branch on it
/// rather than guess.
pub const VERSION: u32 = 1;

/// How long playpen waits for a minter that declares no `timeout` ([spec §7.2]).
///
/// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a bounded wait looks at the minter again. Short enough that a fast minter is not
/// waited on needlessly, long enough that a slow one is not spun over.
const POLL: Duration = Duration::from_millis(10);

/// The destination a minter is minting for, as it appears on stdin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Destination {
    pub host: String,
    pub path_prefix: String,
}

/// The scope a minter is handed: the workspace's forge scope for a workspace route, and `null` for
/// a profile route ([spec §7.4]). A profile route is for everything that does not minimize to one
/// workspace — a model API key, a SaaS token.
///
/// [spec §7.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#74-attachment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForgeScope {
    Org(String),
    Repos(Vec<String>),
}

impl From<&Forge> for ForgeScope {
    fn from(forge: &Forge) -> Self {
        match forge {
            Forge::Org(org) => Self::Org(org.clone()),
            Forge::Repos(repos) => Self::Repos(repos.clone()),
        }
    }
}

/// What playpen writes on a minter's stdin. A revoker receives the same ([spec §7.2]).
///
/// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub version: u32,
    pub route: Destination,
    /// `null` for a profile route.
    pub scope: Option<ForgeScope>,
}

impl Request {
    pub fn new(route: Destination, scope: Option<ForgeScope>) -> Self {
        Self {
            version: VERSION,
            route,
            scope,
        }
    }

    /// The one line of JSON the minter reads, followed by end of input.
    fn body(&self) -> String {
        let mut text = serde_json::to_string(self).unwrap_or_else(|e| {
            // Owned strings and integers built in memory; serialising them cannot fail.
            unreachable!("a minter request serialises: {e}")
        });
        text.push('\n');
        text
    }
}

/// What a minter returns, as it comes off stdout. Extra fields are ignored rather than refused:
/// the contract asks for `{token, expires_at}`, and a provider's own `token_type` beside them is
/// not a malformed answer.
#[derive(Deserialize)]
struct Response {
    token: String,
    expires_at: String,
}

/// One minted credential. The token is the secret; everything else about it is not.
pub struct Minted {
    token: Zeroizing<String>,
    /// Required: without it there is nothing to renew against, and a credential of unknown life
    /// is one that lapses without warning.
    pub expires_at: String,
}

impl Minted {
    /// The secret itself, for the one caller that needs it: the proxy, which substitutes it in
    /// place of the phantom. Deliberately awkward to reach, and never `Display`.
    pub fn secret(&self) -> &str {
        &self.token
    }
}

/// Never the token: a `Debug` that printed it would put it in every log line that ever formatted
/// a struct holding one.
impl fmt::Debug for Minted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Minted")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Run `minter` — declared as `name` — for `request`, and return what it minted.
///
/// It runs unconfined, which is the point: it reaches the host's own keystore, which the boundary
/// does not. Its stderr is inherited, so an operator debugging a minter sees it; its stdout is
/// never shown.
pub fn mint(name: &str, minter: &Minter, request: &Request) -> Result<Minted, Refusal> {
    // Every refusal names the minter *and the scope* it was minting for ([spec §7.2]): an operator
    // with four minters and two workspaces needs both to know which call broke.
    let refusal = |code: Code, detail: String| {
        Refusal::new(
            code,
            format!(
                "minter {name:?} for {}{} scoped to {}: {detail}",
                request.route.host,
                request.route.path_prefix,
                match &request.scope {
                    Some(ForgeScope::Org(org)) => format!("org {org}"),
                    Some(ForgeScope::Repos(repos)) => format!("repos {}", repos.join(", ")),
                    None => "the profile, not one workspace".to_string(),
                },
            ),
        )
    };
    let (program, args) = minter.command.split_first().ok_or_else(|| {
        refusal(
            Code::MinterFailed,
            "declares an empty command, so there is nothing to run".into(),
        )
    })?;
    // Its own process group, so a kill reaches everything it started and not just the command
    // itself: a descendant left running holds the minter's stderr, which is playpen's, and whoever
    // reads playpen's output waits on it. A shell does not always `exec` its last command — macOS's
    // forks it — so this is the common case, not an exotic one.
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| refusal(Code::MinterFailed, format!("cannot be run: {e}")))?;
    // One small write, then end of input: the request is far below a pipe's buffer, so this cannot
    // deadlock against a minter that reads its input whole before answering.
    let written = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("no stdin"))
        .and_then(|mut stdin| stdin.write_all(request.body().as_bytes()));
    if let Err(e) = written {
        kill(&mut child);
        return Err(refusal(
            Code::MinterFailed,
            format!("cannot be given its request: {e}"),
        ));
    }
    let timeout = minter.timeout.map_or(DEFAULT_TIMEOUT, Duration::from_secs);
    let status = match wait_bounded(&mut child, timeout) {
        Some(status) => status,
        None => {
            // Killed, so a hung minter never outlives the launch it would have hung.
            kill(&mut child);
            return Err(refusal(
                Code::MinterTimeout,
                format!("did not answer within {}s", timeout.as_secs()),
            ));
        }
    };
    // Read after the wait: the answer is one small object, so it is in the pipe by now, and the
    // bytes are moved straight into zeroizing memory.
    let mut stdout = Zeroizing::new(Vec::new());
    if let Some(mut pipe) = child.stdout.take()
        && let Err(e) = pipe.read_to_end(&mut stdout)
    {
        return Err(refusal(Code::MinterFailed, format!("cannot be read: {e}")));
    }
    if !status.success() {
        return Err(refusal(Code::MinterFailed, format!("exited with {status}")));
    }
    // The error is the serde message alone, never the text it was parsing: that text is the
    // secret channel, and a malformed one can still hold most of a token.
    let response: Response = serde_json::from_slice(&stdout).map_err(|e| {
        refusal(
            Code::MinterMalformed,
            format!("did not return {{token, expires_at}} on stdout: {e}"),
        )
    })?;
    // Moved, never copied: the allocation the parser made becomes the zeroizing one.
    let token = Zeroizing::new(response.token);
    let expires_at = response.expires_at;
    if token.is_empty() {
        return Err(refusal(
            Code::MinterMalformed,
            "returned an empty token".into(),
        ));
    }
    if instant(&expires_at).is_none() {
        return Err(refusal(
            Code::MinterMalformed,
            format!("returned {expires_at:?} as expires_at, which is not an RFC 3339 timestamp"),
        ));
    }
    Ok(Minted { token, expires_at })
}

/// Kill `child`'s process group, which is everything the minter started, and reap the minter. A
/// kill that fails is dropped: the refusal it accompanies is already the outcome.
fn kill(child: &mut Child) {
    // `process_group(0)` made the minter its group's leader, so the group's id is its pid.
    let group = libc::pid_t::try_from(child.id()).expect("a pid fits pid_t");
    // SAFETY: a plain syscall; the group is the minter's own, and the minter is not yet reaped,
    // so its pid, and with it the group id, cannot have been reused.
    unsafe { libc::killpg(group, libc::SIGKILL) };
    let _ = child.wait();
}

/// Run `minter`'s revoker — declared as `name` — for `request`, or say why it did not run
/// ([spec §7.2]).
///
/// **Revocation is an optimization, and the TTL is the guarantee.** A design whose safety depends
/// on a cleanup path running is unsafe under `SIGKILL`, so this is best-effort: it returns the
/// sentence a failure is recorded with rather than a [`Refusal`], and **no teardown failure
/// changes the exit status** ([spec §4.2]).
///
/// `Ok(())` where the minter declares no revoker: there was nothing to run, which is not a
/// failure. A revoker receives the same stdin the minter did, so the two are one contract.
///
/// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
/// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
pub fn revoke(name: &str, minter: &Minter, request: &Request) -> Result<(), String> {
    let Some(argv) = &minter.revoke else {
        return Ok(());
    };
    let failed = |detail: String| {
        Err(format!(
            "the revoker of minter {name:?} for {}{} {detail}",
            request.route.host, request.route.path_prefix,
        ))
    };
    let Some((program, args)) = argv.split_first() else {
        return failed("declares an empty command, so there was nothing to run".into());
    };
    // Stdout is closed rather than inherited: a revoker is not a minter, so whatever it prints is
    // not an answer playpen wants — and it may be a token.
    //
    // Its own process group, for the same reason a minter gets one: a kill must reach everything
    // it started, and teardown must not be held open by a descendant holding playpen's stderr.
    let spawned = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .process_group(0)
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => return failed(format!("cannot be run: {e}")),
    };
    let written = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("no stdin"))
        .and_then(|mut stdin| stdin.write_all(request.body().as_bytes()));
    if let Err(e) = written {
        kill(&mut child);
        return failed(format!("cannot be given its request: {e}"));
    }
    // Bounded by the same `timeout` the minter is: a revoker that hangs would hold teardown open
    // for as long as the provider felt like, and the credential expires on its own either way.
    let timeout = minter.timeout.map_or(DEFAULT_TIMEOUT, Duration::from_secs);
    match wait_bounded(&mut child, timeout) {
        Some(status) if status.success() => Ok(()),
        Some(status) => failed(format!("exited with {status}")),
        None => {
            kill(&mut child);
            failed(format!("did not exit within {}s", timeout.as_secs()))
        }
    }
}

/// Wait for `child` for at most `timeout`, or `None` if it is still running when that runs out.
fn wait_bounded(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            // A wait that cannot be made is not a hang: it is reported as the failure it is, by
            // the caller, which sees no status.
            Err(_) => return None,
            Ok(None) => {}
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
    }
}

/// The instant `text` names, as whole seconds since the epoch, or `None` where it is not an
/// RFC 3339 timestamp: `YYYY-MM-DDTHH:MM:SS`, an optional fractional part, and `Z` or a `±HH:MM`
/// offset.
///
/// A scanner, not a pattern: the layout is fixed, so there is nothing for a grammar to do. It
/// both validates — which is what `refusal.minter.malformed` rests on — and yields the instant,
/// because a credential whose expiry playpen can read but cannot order is one renewal could never
/// act on.
///
/// Every field is held to its range, the month's own length included, so a timestamp this accepts
/// names the instant it reads as and not a neighbouring one: the day arithmetic below would carry
/// `2026-02-30` into March rather than refuse it.
///
/// The fraction is dropped rather than rounded: a credential is never renewed on the strength of
/// a millisecond. A timestamp before the epoch, which no expiry is, reads as `None`.
fn instant(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    let digits = |at: usize, count: usize| {
        (bytes.len() >= at + count && bytes[at..at + count].iter().all(u8::is_ascii_digit))
            .then(|| {
                std::str::from_utf8(&bytes[at..at + count])
                    .ok()?
                    .parse::<i64>()
                    .ok()
            })
            .flatten()
    };
    let at = |pos: usize, c: u8| bytes.get(pos) == Some(&c);
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    if !(at(4, b'-')
        && at(7, b'-')
        && (at(10, b'T') || at(10, b't') || at(10, b' '))
        && at(13, b':')
        && at(16, b':'))
    {
        return None;
    }
    // A leap second is `60`, which RFC 3339 allows and which the day arithmetic below cannot
    // represent; it reads as the last second of the minute rather than refusing a timestamp a
    // provider is entitled to send.
    let second = second.min(59);
    if !((1..=12).contains(&month)
        && (1..=days_in(year, month)).contains(&day)
        && (0..=23).contains(&hour)
        && (0..=59).contains(&minute))
    {
        return None;
    }
    let mut rest = 19;
    if at(rest, b'.') {
        let start = rest + 1;
        let mut end = start;
        while digits(end, 1).is_some() {
            end += 1;
        }
        if end == start {
            return None;
        }
        rest = end;
    }
    // The offset the timestamp is given in, in seconds east of UTC.
    let offset = match bytes.get(rest) {
        Some(b'Z' | b'z') if rest + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) if rest + 6 == bytes.len() && at(rest + 3, b':') => {
            let (hours, minutes) = (digits(rest + 1, 2)?, digits(rest + 4, 2)?);
            if !((0..=23).contains(&hours) && (0..=59).contains(&minutes)) {
                return None;
            }
            let east = hours * 3600 + minutes * 60;
            match sign {
                b'-' => -east,
                _ => east,
            }
        }
        _ => return None,
    };
    // Howard Hinnant's `days_from_civil`, counting from 0000-03-01 so the leap day ends each
    // 400-year era — the inverse of the one `explain` renders a timestamp with.
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_from_march = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_from_march + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(seconds).ok()
}

/// How many days `month` has in `year`, proleptic Gregorian.
fn days_in(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// One route this launch minted a credential for, with the provenance of where the route was
/// written ([spec §7.4]). Workspace routes and profile routes resolve into **one** table, which is
/// what lets `explain` answer why a credential is present.
///
/// [spec §7.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#74-attachment
#[derive(Debug)]
pub struct Minting {
    /// What was put on the minter's stdin, kept because **a revoker receives the same**
    /// ([spec §7.2]). Held rather than rebuilt at teardown, so the two can never be handed
    /// different scopes for one credential.
    ///
    /// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
    pub request: Request,
    pub route: Destination,
    /// The declared minter's name, which every refusal about it names.
    pub minter: String,
    /// The variable the phantom is delivered in ([spec §7.1]). The policy authors it, which is why
    /// the coherence tier holds it against every name playpen writes.
    ///
    /// [spec §7.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#71-credential-route
    pub delivery: String,
    pub from: String,
    /// What this route's endpoint rule sets allow, resolved out of `fragments.endpoints`
    /// ([spec §7.6]).
    ///
    /// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
    pub allowed: crate::proxy::Allowed,
    /// The secret itself, **shared with the proxy that spends it and with the renewal that
    /// replaces it** ([spec §7.2]). One handle rather than a copy each, so there is never a
    /// second token in this process behind the one in use.
    ///
    /// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
    pub secret: crate::proxy::Secret,
    /// When the credential now in `secret` expires, as the minter stated it. Replaced by each
    /// renewal, which is why the run record is written again at teardown.
    pub expires_at: String,
    /// When it was minted, in whole seconds since the epoch. Taken here, at the mint, and not
    /// where renewal starts: renewal is due after a fraction of the credential's **own** life, and
    /// a clock started at step 17 would charge every step between against it.
    pub minted_at: u64,
    /// Every expiry a renewal has given this credential since, in order. The run record holds each
    /// new one, not only the one in force.
    pub renewals: Vec<String>,
}

impl Minting {
    /// This route as the proxy serves it: the destination, what its rule sets allow, and the
    /// secret it puts in place of the phantom. The one place the secret is handed on, and it is
    /// handed to the supervisor's own proxy, in this process.
    pub fn route(&self) -> crate::proxy::Route {
        crate::proxy::Route {
            host: self.route.host.clone(),
            path_prefix: self.route.path_prefix.clone(),
            secret: self.secret.clone(),
            allowed: self.allowed.clone(),
        }
    }

    /// What the run record holds about this credential: never the token.
    pub fn recorded(&self) -> crate::record::RecordedCredential {
        crate::record::RecordedCredential {
            host: self.route.host.clone(),
            path_prefix: self.route.path_prefix.clone(),
            minter: self.minter.clone(),
            expires_at: self.expires_at.clone(),
            renewals: self.renewals.clone(),
            from: self.from.clone(),
        }
    }
}

/// Mint a credential for every route profile `name` resolves ([spec §7.2]), before the launch and
/// unconfined. A failure refuses the whole run.
///
/// The coherence tier has already refused a route naming an undeclared minter, so one that is
/// missing here is a policy that changed under the launch.
///
/// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
pub fn resolve(
    policy: &crate::policy::Policy,
    name: &str,
    selected: &crate::policy::Profile,
) -> Result<Vec<Minting>, Refusal> {
    let mut minted = Vec::new();
    for (from, route, scope) in attached(policy, name, selected) {
        let declared = policy.minters.get(&route.minter).ok_or_else(|| {
            Refusal::new(
                Code::MinterUnknown,
                format!("{from}.minter is {:?}, which is not declared", route.minter),
            )
        })?;
        let destination = Destination {
            host: route.host.clone(),
            path_prefix: route.path_prefix.clone(),
        };
        let request = Request::new(destination.clone(), scope);
        let credential = mint(&route.minter, declared, &request)?;
        minted.push(Minting {
            request,
            route: destination,
            minter: route.minter.clone(),
            delivery: route.delivery.env.clone(),
            from,
            allowed: allowed(policy, route),
            secret: crate::proxy::Secret::new(credential.secret().to_owned()),
            expires_at: credential.expires_at,
            minted_at: now_unix_s(),
            renewals: Vec::new(),
        });
    }
    Ok(minted)
}

/// How much of a credential's own life renewal leaves unspent, as a divisor: a fifth, so a
/// re-mint is due once four fifths have passed and the last fifth is slack for a slow minter.
///
/// A fraction of the life rather than a fixed lead, because playpen does not choose how long a
/// credential lives. A fixed lead of minutes is a lead a five-second credential is already inside
/// the moment it is minted, which would renew it as fast as the minter could run; a fraction
/// renews a short life proportionally often and a long one well before the provider stops taking
/// it.
const SLACK: u64 = 5;

/// The shortest a credential is ever held before being re-minted. A minter answering with an
/// expiry already past would otherwise be re-invoked in a tight loop.
const MIN_LIFE: Duration = Duration::from_secs(1);

/// How often renewal looks at its credentials. Teardown joins this thread, so the tick is also
/// the longest teardown waits on a renewal that has nothing to do.
const RENEW_TICK: Duration = Duration::from_millis(250);

/// One credential renewal keeps alive. Everything is owned, because the thread outlives the
/// borrow of the policy it was built from.
struct Kept {
    /// The declared minter's name, which every sentence about it names.
    name: String,
    minter: Minter,
    request: Request,
    secret: crate::proxy::Secret,
    /// When the credential now in `secret` was minted and when it expires, in whole seconds since
    /// the epoch.
    minted_at: u64,
    expires_at: u64,
    /// Set once a re-mint has failed. **A re-mint failure mid-run cannot be a refusal**: the
    /// credential lapses and the provider's `401` stands ([spec §7.2]). Lapsed is final rather
    /// than retried, because a minter that could not answer is one whose keystore wants an
    /// operator, and retrying every tick would hammer it for the rest of the run.
    ///
    /// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
    lapsed: bool,
}

impl Kept {
    /// When this credential is due to be re-minted, in whole seconds since the epoch.
    fn due(&self) -> u64 {
        let life = self.expires_at.saturating_sub(self.minted_at);
        let after = (life - life / SLACK).max(MIN_LIFE.as_secs());
        self.minted_at.saturating_add(after)
    }
}

/// What renewal did, read once the child has exited and written to the run record.
#[derive(Debug, Default)]
pub struct Renewed {
    /// Each credential's `expires_at` as it now stands, by destination. The run record holds each
    /// new one ([spec §7.2]), so a reader can see the credential was alive when the push failed.
    ///
    /// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
    pub expiry: Vec<(Destination, String)>,
    /// One sentence per re-mint that failed, after which that credential lapsed. Not a refusal
    /// and not a teardown failure: the run stayed alive and this is why its requests stopped
    /// authenticating.
    pub lapsed: Vec<String>,
}

impl Renewed {
    /// Put every expiry a renewal produced back onto `credentials`, in order, so what the run
    /// record is written from is the credential's whole history rather than as the launch minted
    /// it. The last of them is the one in force.
    ///
    /// Matched by destination, which is unique across a run's route table: the coherence tier has
    /// refused two routes on one host whose prefixes are not ordered, and no two routes can share
    /// both a host and a prefix.
    pub fn apply(&self, credentials: &mut [Minting]) {
        for (route, expires_at) in &self.expiry {
            for minted in credentials.iter_mut().filter(|m| m.route == *route) {
                minted.expires_at = expires_at.clone();
                minted.renewals.push(expires_at.clone());
            }
        }
    }
}

/// The renewal of a run's credentials, for as long as the run lasts.
pub struct Renewing {
    stopping: Arc<AtomicBool>,
    renewed: Arc<Mutex<Renewed>>,
    /// `None` where there was nothing to renew, or where the thread could not be spawned — which
    /// [`renew`] has already written a lapse for, because a run whose credentials silently never
    /// renew must not look like a run with none.
    renewing: Option<JoinHandle<()>>,
}

/// Re-mint every credential of `credentials` as it nears expiry, in a thread of the supervisor's
/// own ([spec §4.2] step 17).
///
/// The secret is replaced **in place**, in the handle the proxy already holds, so a request in
/// flight when a renewal lands either sends the old secret or the new one and never half of
/// either — and nothing about the child's environment changes, because what the child holds is
/// the phantom.
///
/// Renewal is not capability expansion: the request handed to the minter is the one the launch
/// handed it, so a renewed credential has exactly the scope the first one did.
///
/// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
pub fn renew(policy: &crate::policy::Policy, credentials: &[Minting]) -> Renewing {
    let mut kept: Vec<Kept> = credentials
        .iter()
        .filter_map(|minted| {
            Some(Kept {
                name: minted.minter.clone(),
                minter: policy.minters.get(&minted.minter)?.clone(),
                request: minted.request.clone(),
                secret: minted.secret.clone(),
                // The instant the launch minted it, carried from there: a minter states when a
                // credential expires and never when it was made, and starting the clock here
                // would spend the steps between on it.
                minted_at: minted.minted_at,
                // An expiry that does not read as an instant cannot happen — the mint refused one
                // — so one here is a credential renewal cannot order, and it is left alone.
                expires_at: instant(&minted.expires_at)?,
                lapsed: false,
            })
        })
        .collect();
    let stopping = Arc::new(AtomicBool::new(false));
    let renewed = Arc::new(Mutex::new(Renewed::default()));
    if kept.is_empty() {
        return Renewing {
            stopping,
            renewed,
            renewing: None,
        };
    }
    let flag = Arc::clone(&stopping);
    let reporting = Arc::clone(&renewed);
    let renewing = std::thread::Builder::new()
        .name("playpen-renewal".into())
        .spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                let now = now_unix_s();
                for keeping in kept.iter_mut().filter(|k| !k.lapsed) {
                    if now < keeping.due() {
                        continue;
                    }
                    // Checked again here: a mint is bounded by its own timeout, and teardown
                    // should not start one it will then wait out.
                    if flag.load(Ordering::SeqCst) {
                        return;
                    }
                    match mint(&keeping.name, &keeping.minter, &keeping.request) {
                        Ok(minted) => {
                            keeping.secret.replace(minted.secret().to_owned());
                            keeping.minted_at = now_unix_s();
                            // The credential is live either way — the secret is already in place —
                            // but an expiry renewal cannot order is one it can never act on again,
                            // so this is the last renewal of it and the record says so rather than
                            // the credential quietly becoming the launch's last one.
                            let unreadable = match instant(&minted.expires_at) {
                                Some(expires_at) => {
                                    keeping.expires_at = expires_at;
                                    false
                                }
                                None => {
                                    keeping.lapsed = true;
                                    true
                                }
                            };
                            report(&reporting, |renewed| {
                                renewed.expiry.push((
                                    keeping.request.route.clone(),
                                    minted.expires_at.clone(),
                                ));
                                if unreadable {
                                    renewed.lapsed.push(format!(
                                        "the credential for {}{} was renewed, but its new expiry \
                                         {:?} is not an instant playpen can order, so it will not \
                                         be renewed again and lapses when the provider stops \
                                         taking it",
                                        keeping.request.route.host,
                                        keeping.request.route.path_prefix,
                                        minted.expires_at,
                                    ));
                                }
                            });
                        }
                        Err(refusal) => {
                            keeping.lapsed = true;
                            report(&reporting, |renewed| {
                                renewed.lapsed.push(format!(
                                    "the credential for {}{} was not renewed, so it lapses and \
                                     the provider's own 401 stands: {refusal}",
                                    keeping.request.route.host, keeping.request.route.path_prefix,
                                ));
                            });
                        }
                    }
                }
                std::thread::sleep(RENEW_TICK);
            }
        });
    // A thread that could not be spawned is written down, because a run whose credentials silently
    // never renew must not look like a run with none to renew. Not a refusal: the credentials are
    // minted and the run works until the first of them expires, which is the same outcome a failed
    // re-mint has.
    if let Err(e) = &renewing {
        report(&renewed, |reported| {
            reported.lapsed.push(format!(
                "no renewal thread could be started, so every credential of this run lapses at \
                 the expiry it was minted with: {e}"
            ));
        });
    }
    Renewing {
        stopping,
        renewed,
        renewing: renewing.ok(),
    }
}

/// What `lock` guards, using a poisoned lock anyway: it guards two lists only ever appended to, so
/// a panic elsewhere in the renewal thread has nothing to do with their contents, and refusing to
/// read them would lose the one record of what renewal did.
fn held<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Append to the shared report.
fn report(renewed: &Mutex<Renewed>, write: impl FnOnce(&mut Renewed)) {
    write(&mut held(renewed));
}

impl Renewing {
    /// Stop renewing and say what renewal did ([spec §4.2] step 18). First in teardown, before
    /// the revokers: a credential being revoked must not be re-minted behind the revoker's back.
    ///
    /// Joined rather than detached, so no minter is still running when the run exits. The wait is
    /// bounded by that minter's own `timeout`, which is the same bound teardown already accepts
    /// for a revoker.
    ///
    /// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
    pub fn stop(&mut self) -> Renewed {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some(renewing) = self.renewing.take() {
            let _ = renewing.join();
        }
        std::mem::take(&mut held(&self.renewed))
    }
}

impl Drop for Renewing {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Now, in whole seconds since the epoch. A clock before 1970 is a host fault, and then every
/// credential reads as due at once, which re-mints rather than hangs.
fn now_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Run every declared revoker of `credentials`, writing each failure to `record`
/// ([spec §4.2] step 18).
///
/// Called **while the proxy is still up**, because a revoker is an ordinary host process that may
/// well reach the provider through it, and in order before anything else teardown removes.
///
/// Every revoker is attempted even after one fails: they are independent credentials, and
/// stopping at the first would leave the rest live for no reason. Nothing here returns a
/// `Result` — the run's status is already decided.
///
/// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
pub fn revoke_all(
    policy: &crate::policy::Policy,
    credentials: &[Minting],
    record: &mut crate::record::RunRecord,
) {
    for minted in credentials {
        let Some(declared) = policy.minters.get(&minted.minter) else {
            // The coherence tier refused an undeclared minter, so this is a policy that changed
            // under the run — recorded rather than passed over, because a credential nobody
            // revoked is one that lives until its TTL.
            record.torn_down(format!(
                "minter {:?} is no longer declared, so its credential for {}{} was not revoked",
                minted.minter, minted.route.host, minted.route.path_prefix,
            ));
            continue;
        };
        if let Err(why) = revoke(&minted.minter, declared, &minted.request) {
            record.torn_down(why);
        }
    }
}

/// What `route` allows ([spec §7.6]): unrestricted where it names no rule set, and otherwise the
/// rules of every set it names, unioned.
///
/// A named set that `fragments.endpoints` does not declare contributes **no rules** rather than
/// being skipped. The coherence tier has already refused one (`refusal.endpoint.unknown`), so a
/// set missing here is a policy that changed under the launch — and the route still reads as
/// restricted, which is the side to fail to.
///
/// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
pub(crate) fn allowed(
    policy: &crate::policy::Policy,
    route: &crate::policy::Route,
) -> crate::proxy::Allowed {
    if route.endpoints.is_empty() {
        return crate::proxy::Allowed::Everything;
    }
    crate::proxy::Allowed::Only(
        route
            .endpoints
            .iter()
            .filter_map(|name| policy.fragments.endpoints.get(name))
            .flatten()
            .map(|rule| crate::proxy::Rule {
                method: rule.method.clone(),
                path: rule.path.clone(),
            })
            .collect(),
    )
}

/// Every route profile `name` resolves ([spec §7.4]): each of its selected workspaces' routes,
/// with that workspace's own forge scope, then the profile's own, with none.
///
/// **Forge scope is never unioned across a profile's workspaces.** The point of a workspace route
/// is that its credential minimizes to that workspace, and a union would hand every workspace's
/// minter the reach of all of them.
///
/// The coherence tier reads the same list ([`crate::policy::coherence`]), so what a profile resolves
/// is decided in one place: a rule about a profile's route *set* must see the set a launch will see.
///
/// [spec §7.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#74-attachment
pub(crate) fn attached<'a>(
    policy: &'a crate::policy::Policy,
    name: &str,
    selected: &'a crate::policy::Profile,
) -> Vec<(String, &'a crate::policy::Route, Option<ForgeScope>)> {
    let mut routes = Vec::new();
    for workspace in selected.workspaces.iter().map(|w| &w.value) {
        let Some(declared) = policy.workspaces.get(workspace) else {
            continue;
        };
        let scope = declared.forge.as_ref().map(ForgeScope::from);
        routes.extend(declared.credentials.iter().enumerate().map(|(i, route)| {
            (
                format!("workspace:{workspace}.credentials[{i}]"),
                route,
                scope.clone(),
            )
        }));
    }
    // A profile route is for everything that does not minimize to one workspace — a model API key,
    // a SaaS token — so its scope is `null`.
    routes.extend(
        selected
            .credentials
            .iter()
            .enumerate()
            .map(|(i, route)| (format!("profile:{name}.credentials[{i}]"), route, None)),
    );
    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minter that is `script`, run by the floor's shell.
    fn minter(script: &str, timeout: Option<u64>) -> Minter {
        let sh = crate::floor::binary("sh")
            .unwrap_or_else(|searched| panic!("the floor holds no `sh`; looked at {searched:?}"));
        serde_json::from_value(serde_json::json!({
            "command": [sh, "-c", script],
            "timeout": timeout,
        }))
        .expect("a minter")
    }

    fn request() -> Request {
        Request::new(
            Destination {
                host: "api.github.com".into(),
                path_prefix: "/repos/firefly-engineering/".into(),
            },
            None,
        )
    }

    /// The contract on stdin: the version, the route, and `null` scope for a profile route.
    #[test]
    fn the_minter_is_handed_the_route_and_a_null_scope() {
        let minted = mint(
            "echo-stdin",
            &minter(
                r#"printf '{"token":"%s","expires_at":"2026-10-05T12:00:00Z"}' "$(cat | tr -d '\n' | tr '\"' '@')""#,
                None,
            ),
            &request(),
        )
        .expect("minted");
        assert_eq!(
            minted.secret(),
            "{@version@:1,@route@:{@host@:@api.github.com@,@path_prefix@:@/repos/firefly-engineering/@},@scope@:null}"
        );
    }

    /// A workspace route's minter receives that workspace's forge scope, never a profile's union
    /// of them.
    #[test]
    fn a_scope_is_the_workspaces_own() {
        let request = Request::new(
            Destination {
                host: "github.com".into(),
                path_prefix: "/firefly-engineering/".into(),
            },
            Some(ForgeScope::Org("firefly-engineering".into())),
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&request.body()).expect("JSON")["scope"],
            serde_json::json!({"org": "firefly-engineering"})
        );
        let repos = Request::new(
            request.route.clone(),
            Some(ForgeScope::Repos(vec!["a/b".into()])),
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&repos.body()).expect("JSON")["scope"],
            serde_json::json!({"repos": ["a/b"]})
        );
    }

    /// The record holds `expires_at`; the token is reachable only through `secret`, and never
    /// through `Debug`.
    #[test]
    fn the_token_is_never_shown() {
        let minted = mint(
            "ok",
            &minter(
                r#"cat >/dev/null; echo '{"token":"s3cret","expires_at":"2026-10-05T12:00:00Z"}'"#,
                None,
            ),
            &request(),
        )
        .expect("minted");
        assert_eq!(minted.secret(), "s3cret");
        assert_eq!(minted.expires_at, "2026-10-05T12:00:00Z");
        let shown = format!("{minted:?}");
        assert!(!shown.contains("s3cret"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
        assert!(shown.contains("2026-10-05T12:00:00Z"), "{shown}");
    }

    /// Each failure has its own code, and every one names the minter and where it was minting for:
    /// an operator with four minters needs to know which broke.
    #[test]
    fn each_failure_has_its_own_code_and_names_the_minter() {
        for (script, timeout, code) in [
            ("cat >/dev/null; exit 3", None, Code::MinterFailed),
            (
                r#"cat >/dev/null; echo 'not json'"#,
                None,
                Code::MinterMalformed,
            ),
            (
                r#"cat >/dev/null; echo '{"token":"s"}'"#,
                None,
                Code::MinterMalformed,
            ),
            (
                r#"cat >/dev/null; echo '{"token":"","expires_at":"2026-10-05T12:00:00Z"}'"#,
                None,
                Code::MinterMalformed,
            ),
            (
                r#"cat >/dev/null; echo '{"token":"s","expires_at":"soon"}'"#,
                None,
                Code::MinterMalformed,
            ),
            ("cat >/dev/null; sleep 30", Some(0), Code::MinterTimeout),
        ] {
            let refusal =
                mint("anthropic", &minter(script, timeout), &request()).expect_err(script);
            assert_eq!(refusal.code, code, "{script}: {refusal}");
            assert!(refusal.message().contains("\"anthropic\""), "{refusal}");
            assert!(refusal.message().contains("api.github.com"), "{refusal}");
        }
    }

    /// A refusal never carries the secret channel's content: a malformed answer can still hold
    /// most of a token.
    #[test]
    fn a_malformed_answer_is_never_quoted_back() {
        let refusal = mint(
            "leaky",
            &minter(
                r#"cat >/dev/null; echo '{"token":"s3cret","expires_at":"soon","extra":1}'"#,
                None,
            ),
            &request(),
        )
        .expect_err("refused");
        assert_eq!(refusal.code, Code::MinterMalformed);
        assert!(!refusal.message().contains("s3cret"), "{refusal}");
    }

    /// A minter that hangs must not hang the launch, and is killed rather than left behind.
    #[test]
    fn a_hanging_minter_is_bounded_and_killed() {
        let started = Instant::now();
        let refusal = mint(
            "slow",
            &minter("cat >/dev/null; sleep 60", Some(1)),
            &request(),
        )
        .expect_err("refused");
        assert_eq!(refusal.code, Code::MinterTimeout);
        assert!(refusal.message().contains("within 1s"), "{refusal}");
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "waited too long"
        );
    }

    /// Killed means the minter and everything it started: a descendant left running holds
    /// whatever playpen handed the minter, its stderr among them, so whoever reads playpen's
    /// output would wait on it — the hang the timeout exists to prevent.
    #[test]
    fn a_hanging_minter_is_killed_with_its_descendants() {
        let dir = tempfile::tempdir().expect("a dir");
        let pid_file = dir.path().join("descendant");
        let refusal = mint(
            "slow",
            &minter(
                &format!(
                    "cat >/dev/null; sleep 60 & echo $! > {}; wait",
                    pid_file.display()
                ),
                Some(1),
            ),
            &request(),
        )
        .expect_err("refused");
        assert_eq!(refusal.code, Code::MinterTimeout);
        let pid: libc::pid_t = std::fs::read_to_string(&pid_file)
            .expect("the descendant's pid")
            .trim()
            .parse()
            .expect("a pid");
        // Gone, or a zombie awaiting a reaper, either of which takes a moment after the kill.
        let deadline = Instant::now() + Duration::from_secs(5);
        while running(pid) {
            assert!(
                Instant::now() < deadline,
                "the minter's descendant {pid} outlived it"
            );
            std::thread::sleep(POLL);
        }
    }

    /// Whether `pid` is still *running*. A process that has been killed and not yet reaped is a
    /// zombie: `kill(pid, 0)` still succeeds on it, but the kill has landed and it holds nothing.
    /// Whoever inherits an orphan normally reaps it at once; a container whose PID 1 is not an
    /// init never does, and there the zombie is as dead as the test can ask for.
    fn running(pid: libc::pid_t) -> bool {
        // SAFETY: signal 0 delivers nothing; it only asks whether `pid` exists.
        let exists = unsafe { libc::kill(pid, 0) } == 0;
        exists && !zombie(pid)
    }

    /// Linux keeps a killed process in state `Z` until someone reaps it, and `/proc/<pid>/stat` is
    /// the only place that state is readable — `kill(pid, 0)` cannot tell a zombie from a running
    /// process. A container whose PID 1 is not an init reaps nothing, so there the zombie stays.
    #[cfg(target_os = "linux")]
    fn zombie(pid: libc::pid_t) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| state_of(&stat))
            // No readable `stat` is a pid that went between the two calls: gone, not running.
            .is_none_or(|state| state == 'Z')
    }

    /// macOS reparents orphans to launchd, which reaps them, and has no `/proc` to consult.
    #[cfg(not(target_os = "linux"))]
    fn zombie(_: libc::pid_t) -> bool {
        false
    }

    /// The process state out of a `/proc/<pid>/stat` line. The second field is the process's
    /// `comm` in parentheses, and `comm` may itself hold spaces and parentheses, so the state is
    /// the first field after the **last** `)` and never the third whitespace-separated token.
    #[cfg(target_os = "linux")]
    fn state_of(stat: &str) -> Option<char> {
        stat.rsplit_once(')')?
            .1
            .split_whitespace()
            .next()?
            .chars()
            .next()
    }

    /// The parse, against a `comm` built to break the naive one — no such process need exist.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_state_is_read_after_the_last_paren() {
        assert_eq!(state_of("7 (sleep) S 1 7 7 0 -1 4194560"), Some('S'));
        assert_eq!(state_of("42 (we (ird) name) Z 1 42 42"), Some('Z'));
        assert_eq!(state_of("truncated before any paren"), None);
    }

    #[test]
    fn a_command_that_cannot_run_is_a_failure() {
        let minter: Minter =
            serde_json::from_value(serde_json::json!({"command": ["/nonexistent/mint"]}))
                .expect("a minter");
        let refusal = mint("gone", &minter, &request()).expect_err("refused");
        assert_eq!(refusal.code, Code::MinterFailed);
    }

    /// A minter with `revoke` as a script run by the floor's shell, and no `command` worth
    /// running: these tests revoke, and nothing mints.
    fn revoker(script: &str, timeout: Option<u64>) -> Minter {
        let sh = crate::floor::binary("sh")
            .unwrap_or_else(|searched| panic!("the floor holds no `sh`; looked at {searched:?}"));
        serde_json::from_value(serde_json::json!({
            "command": ["/unused"],
            "revoke": [sh, "-c", script],
            "timeout": timeout,
        }))
        .expect("a minter")
    }

    /// A revoker **receives the same stdin the minter did** ([spec §7.2]), so the two are one
    /// contract and a revoker can address the credential it is retiring.
    ///
    /// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
    #[test]
    fn a_revoker_receives_the_minters_own_stdin() {
        let seen = tempfile::NamedTempFile::new().expect("a file");
        let script = format!("cat > {}", seen.path().display());
        let request = Request::new(
            Destination {
                host: "github.com".into(),
                path_prefix: "/firefly-engineering/".into(),
            },
            Some(ForgeScope::Org("firefly-engineering".into())),
        );
        revoke("gh-app", &revoker(&script, None), &request).expect("revoked");
        let written = std::fs::read_to_string(seen.path()).expect("the stdin");
        assert_eq!(written, request.body());
    }

    /// Revocation is best-effort: every way a revoker can fail is a sentence naming the minter
    /// and the destination, never a refusal, because **no teardown failure changes the exit
    /// status**.
    #[test]
    fn a_failing_revoker_is_a_sentence_and_never_a_refusal() {
        for (script, timeout, said) in [
            ("cat >/dev/null; exit 7", None, "exited with"),
            ("cat >/dev/null; sleep 30", Some(0), "did not exit within"),
        ] {
            let why = revoke("gh-app", &revoker(script, timeout), &request())
                .expect_err("the revoker failed");
            assert!(why.contains(said), "{why}");
            assert!(why.contains("\"gh-app\""), "{why}");
            assert!(why.contains("api.github.com"), "{why}");
        }
        // A revoker that cannot be run at all is the same kind of answer.
        let gone: Minter = serde_json::from_value(serde_json::json!({
            "command": ["/unused"],
            "revoke": ["/nonexistent/revoke"],
        }))
        .expect("a minter");
        let why = revoke("gone", &gone, &request()).expect_err("cannot be run");
        assert!(why.contains("cannot be run"), "{why}");
    }

    /// A minter that declares no revoker has nothing to run, which is not a failure: revocation
    /// is an optimization and the TTL is the guarantee.
    #[test]
    fn a_minter_with_no_revoker_tears_down_cleanly() {
        let minter = minter("cat >/dev/null", None);
        assert_eq!(revoke("m", &minter, &request()), Ok(()));
    }

    /// A revoker's stdout is never read: it is not a minter, so what it prints is not an answer,
    /// and it may be a token. Closing it means a revoker that writes a lot cannot block on a full
    /// pipe either.
    #[test]
    fn a_revoker_that_writes_to_stdout_is_not_blocked_by_it() {
        let loud = revoker("cat >/dev/null; yes playpen | head -c 200000", None);
        assert_eq!(revoke("loud", &loud, &request()), Ok(()));
    }

    #[test]
    fn the_default_timeout_is_thirty_seconds() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
    }

    /// A credential is re-minted after four fifths of **its own life**, never on a fixed lead: a
    /// lead of minutes is one a five-second credential is already inside the moment it is minted,
    /// and renewing it as fast as the minter could run is not renewal.
    #[test]
    fn a_credential_is_due_after_four_fifths_of_its_own_life() {
        let kept = |minted_at: u64, expires_at: u64| Kept {
            name: "m".into(),
            minter: minter("true", None),
            request: request(),
            secret: crate::proxy::Secret::new("s".into()),
            minted_at,
            expires_at,
            lapsed: false,
        };
        // An hour's life is due after 48 minutes, well before the provider stops taking it.
        assert_eq!(kept(1_000, 1_000 + 3600).due(), 1_000 + 2880);
        // A short life is renewed proportionally often rather than at once and forever.
        assert_eq!(kept(1_000, 1_000 + 100).due(), 1_000 + 80);
        // Below the floor, and for an expiry already past, the credential is held for `MIN_LIFE`
        // rather than re-minted in a tight loop.
        assert_eq!(kept(1_000, 1_001).due(), 1_000 + MIN_LIFE.as_secs());
        assert_eq!(kept(1_000, 1_000).due(), 1_000 + MIN_LIFE.as_secs());
        assert_eq!(kept(1_000, 500).due(), 1_000 + MIN_LIFE.as_secs());
    }

    /// A short-lived credential is **re-minted before it expires, and the secret the proxy holds
    /// is the new one** — replaced in the handle the proxy already has, so nothing of the child's
    /// environment moves.
    #[test]
    fn a_short_lived_credential_is_re_minted_and_the_proxy_sees_the_new_secret() {
        // A minter that answers with a new token each time and a two-second expiry, so the first
        // renewal is due one and a half seconds in.
        let counter = tempfile::NamedTempFile::new().expect("a file");
        let script = format!(
            r#"cat >/dev/null
               n=$(( $(cat {count} 2>/dev/null || echo 0) + 1 ))
               echo "$n" > {count}
               printf '{{"token":"secret-%s","expires_at":"%s"}}' "$n" \
                 "$(TZ=UTC date -u -d '+2 seconds' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
                    || date -u -v+2S '+%Y-%m-%dT%H:%M:%SZ')""#,
            count = counter.path().display(),
        );
        let declared = minter(&script, None);
        let minted = mint("short", &declared, &request()).expect("minted");
        let credentials = vec![Minting {
            request: request(),
            route: request().route,
            minter: "short".into(),
            delivery: "T".into(),
            from: "profile:p.credentials[0]".into(),
            allowed: crate::proxy::Allowed::Everything,
            secret: crate::proxy::Secret::new(minted.secret().to_owned()),
            expires_at: minted.expires_at.clone(),
            minted_at: now_unix_s(),
            renewals: Vec::new(),
        }];
        let held = credentials[0].secret.clone();
        assert_eq!(held.read().as_str(), "secret-1");
        let policy_text = serde_json::json!({
            "version": 1,
            "minters": {"short": {"command": declared.command}},
            "profiles": {},
        });
        let policy =
            crate::policy::Policy::parse(&policy_text.to_string(), std::path::Path::new("/p.json"))
                .expect("a policy");

        let mut renewing = renew(&policy, &credentials);
        // Well inside the credential's own life, so the run never ran unauthenticated.
        let deadline = Instant::now() + Duration::from_secs(10);
        while held.read().as_str() == "secret-1" {
            assert!(
                Instant::now() < deadline,
                "the credential was not re-minted"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        // The secret the proxy holds is the renewed one, in the same handle.
        assert_eq!(held.read().as_str(), "secret-2");
        let renewed = renewing.stop();
        assert!(renewed.lapsed.is_empty(), "{renewed:?}");
        // And the new expiry is reported, so the run record can hold it.
        let (route, expires_at) = renewed.expiry.first().expect("a new expiry");
        assert_eq!(*route, request().route);
        assert!(instant(expires_at).is_some(), "{expires_at}");
        assert_ne!(*expires_at, minted.expires_at);
    }

    /// **A failed re-mint is not a refusal**: the run stays alive, the credential lapses with the
    /// secret it already had, and the provider's own `401` is the answer. It is never retried,
    /// because a keystore that could not answer wants an operator, not a tight loop.
    #[test]
    fn a_failed_re_mint_leaves_the_run_alive_and_the_credential_lapses() {
        let attempts = tempfile::NamedTempFile::new().expect("a file");
        let script = format!(
            "cat >/dev/null; echo x >> {}; exit 4",
            attempts.path().display()
        );
        let declared = minter(&script, None);
        let credentials = vec![Minting {
            request: request(),
            route: request().route,
            minter: "flaky".into(),
            delivery: "T".into(),
            from: "profile:p.credentials[0]".into(),
            allowed: crate::proxy::Allowed::Everything,
            secret: crate::proxy::Secret::new("the-first-secret".into()),
            minted_at: now_unix_s(),
            renewals: Vec::new(),
            // Already expired, so renewal is due at once.
            expires_at: "2020-01-01T00:00:00Z".into(),
        }];
        let held = credentials[0].secret.clone();
        let policy_text = serde_json::json!({
            "version": 1,
            "minters": {"flaky": {"command": declared.command}},
            "profiles": {},
        });
        let policy =
            crate::policy::Policy::parse(&policy_text.to_string(), std::path::Path::new("/p.json"))
                .expect("a policy");

        let mut renewing = renew(&policy, &credentials);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if std::fs::read_to_string(attempts.path()).is_ok_and(|a| a.lines().count() >= 1) {
                break;
            }
            assert!(Instant::now() < deadline, "the re-mint was never attempted");
            std::thread::sleep(Duration::from_millis(50));
        }
        // Lapsed is final: a second tick does not try again.
        std::thread::sleep(RENEW_TICK * 8);
        let renewed = renewing.stop();
        assert_eq!(
            std::fs::read_to_string(attempts.path())
                .expect("the attempts")
                .lines()
                .count(),
            1,
            "a failed re-mint was retried"
        );
        // The credential it already had is untouched: it lapses rather than vanishing, so the
        // provider answers and not the broker.
        assert_eq!(held.read().as_str(), "the-first-secret");
        assert!(renewed.expiry.is_empty(), "{renewed:?}");
        let lapsed = renewed.lapsed.first().expect("a sentence");
        assert!(lapsed.contains("api.github.com"), "{lapsed}");
        assert!(lapsed.contains("lapses"), "{lapsed}");
        assert!(lapsed.contains("401"), "{lapsed}");
    }

    /// Renewal is not capability expansion ([spec §7.2]): the re-mint is handed the request the
    /// launch handed the minter, so a renewed credential has exactly the scope the first one did.
    ///
    /// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
    #[test]
    fn a_renewal_is_handed_the_launchs_own_request() {
        let seen = tempfile::NamedTempFile::new().expect("a file");
        let script = format!(
            r#"cat > {}; printf '{{"token":"renewed","expires_at":"2030-01-01T00:00:00Z"}}'"#,
            seen.path().display(),
        );
        let declared = minter(&script, None);
        let request = Request::new(
            Destination {
                host: "github.com".into(),
                path_prefix: "/firefly-engineering/".into(),
            },
            Some(ForgeScope::Org("firefly-engineering".into())),
        );
        let credentials = vec![Minting {
            request: request.clone(),
            route: request.route.clone(),
            minter: "gh-app".into(),
            delivery: "GH_TOKEN".into(),
            from: "workspace:w.credentials[0]".into(),
            allowed: crate::proxy::Allowed::Everything,
            secret: crate::proxy::Secret::new("the-first-secret".into()),
            minted_at: now_unix_s(),
            renewals: Vec::new(),
            expires_at: "2020-01-01T00:00:00Z".into(),
        }];
        let held = credentials[0].secret.clone();
        let policy_text = serde_json::json!({
            "version": 1,
            "minters": {"gh-app": {"command": declared.command}},
            "profiles": {},
        });
        let policy =
            crate::policy::Policy::parse(&policy_text.to_string(), std::path::Path::new("/p.json"))
                .expect("a policy");

        let mut renewing = renew(&policy, &credentials);
        let deadline = Instant::now() + Duration::from_secs(10);
        while held.read().as_str() == "the-first-secret" {
            assert!(
                Instant::now() < deadline,
                "the credential was not re-minted"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut renewed = renewing.stop();
        assert_eq!(held.read().as_str(), "renewed");
        // The same stdin the launch's own mint would have got, scope included.
        assert_eq!(
            std::fs::read_to_string(seen.path()).expect("the stdin"),
            request.body()
        );
        // And the new expiry lands back on the credential the record is written from.
        let mut credentials = credentials;
        renewed.expiry.truncate(1);
        renewed.apply(&mut credentials);
        assert_eq!(credentials[0].expires_at, "2030-01-01T00:00:00Z");
        assert_eq!(credentials[0].recorded().expires_at, "2030-01-01T00:00:00Z");
    }

    /// A profile with no credential route has nothing to renew, so no thread is started.
    #[test]
    fn a_run_with_no_credential_renews_nothing() {
        let policy =
            crate::policy::Policy::parse(r#"{"version": 1}"#, std::path::Path::new("/p.json"))
                .expect("a policy");
        let mut renewing = renew(&policy, &[]);
        assert!(renewing.renewing.is_none(), "a thread with nothing to do");
        let renewed = renewing.stop();
        assert!(renewed.expiry.is_empty() && renewed.lapsed.is_empty());
    }

    #[test]
    fn rfc_3339_is_recognised_by_its_layout() {
        for good in [
            "2026-10-05T12:00:00Z",
            "2026-10-05t12:00:00z",
            "2026-10-05 12:00:00Z",
            "2026-10-05T12:00:00.123Z",
            "2026-10-05T12:00:00+02:00",
            "2026-10-05T12:00:00.000001-05:00",
        ] {
            assert!(instant(good).is_some(), "{good}");
        }
        for bad in [
            "",
            "soon",
            "2026-10-05",
            "2026-10-05T12:00:00",
            "2026-10-05T12:00:00.Z",
            "2026-10-05T12:00:00+0200",
            "2026-10-05T12:00:00Zz",
            "20261005T120000Z",
            "2026-10-05T12:00:00Z ",
            // Before the epoch, which no expiry is, and which has no instant to order by.
            "1969-12-31T23:59:59Z",
            // Out of range in each field. The day arithmetic would carry each of these into a
            // neighbouring instant rather than refuse it, so the scanner holds the ranges itself.
            "2026-00-05T12:00:00Z",
            "2026-13-05T12:00:00Z",
            "2026-10-00T12:00:00Z",
            "2026-10-32T12:00:00Z",
            "2026-02-30T12:00:00Z",
            "2025-02-29T12:00:00Z",
            "1900-02-29T12:00:00Z",
            "2026-10-05T24:00:00Z",
            "2026-10-05T12:60:00Z",
            "2026-10-05T12:00:00+24:00",
            "2026-10-05T12:00:00+00:60",
        ] {
            assert!(instant(bad).is_none(), "{bad}");
        }
    }

    /// The expiry is read as an instant, not only validated: a credential whose expiry playpen
    /// could read but not order is one renewal could never act on.
    #[test]
    fn an_expiry_reads_as_the_instant_it_names() {
        assert_eq!(instant("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(instant("1970-01-02T00:00:00Z"), Some(86_400));
        // The ULID specification's own example time, to the second.
        assert_eq!(instant("2016-07-30T22:36:16Z"), Some(1_469_918_176));
        // Leap days land where they should, on a leap year and on a century that is one.
        assert_eq!(instant("2000-02-29T00:00:00Z"), Some(951_782_400));
        assert_eq!(instant("2024-12-31T23:59:59Z"), Some(1_735_689_599));
        // An offset moves the instant, and the two spellings of one instant agree.
        assert_eq!(
            instant("2026-10-05T14:00:00+02:00"),
            instant("2026-10-05T12:00:00Z")
        );
        assert_eq!(
            instant("2026-10-05T07:00:00-05:00"),
            instant("2026-10-05T12:00:00Z")
        );
        // A leap day is an instant in a year that has one, and nothing in a year that does not.
        assert!(instant("2024-02-29T00:00:00Z").is_some());
        assert!(instant("2000-02-29T00:00:00Z").is_some());
        assert_eq!(
            instant("2026-12-31T23:59:59Z"),
            instant("2027-01-01T00:00:00Z").map(|t| t - 1)
        );
        // A leap second reads as the last second of its minute, which RFC 3339 allows a provider
        // to send and the day arithmetic cannot represent.
        assert_eq!(
            instant("2016-12-31T23:59:60Z"),
            instant("2016-12-31T23:59:59Z")
        );
        // The fraction is dropped rather than rounded: no credential is renewed on a millisecond.
        assert_eq!(
            instant("2026-10-05T12:00:00.999Z"),
            instant("2026-10-05T12:00:00Z")
        );
        // It is the inverse of what `explain` renders, over a spread of instants.
        for seconds in [0, 1, 86_399, 951_782_400, 1_469_918_176, 4_102_444_799] {
            let rendered = crate::explain::timestamp(seconds * 1000);
            assert_eq!(instant(&rendered), Some(seconds), "{rendered}");
        }
    }
}
