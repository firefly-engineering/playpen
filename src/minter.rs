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
use std::time::{Duration, Instant};

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
    if !is_rfc_3339(&expires_at) {
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

/// Whether `text` is shaped like an RFC 3339 timestamp: `YYYY-MM-DDTHH:MM:SS`, an optional
/// fractional part, and `Z` or a `±HH:MM` offset. A scanner, not a pattern: the layout is fixed,
/// so there is nothing for a grammar to do.
fn is_rfc_3339(text: &str) -> bool {
    let bytes = text.as_bytes();
    let digits = |at: usize, count: usize| {
        bytes.len() >= at + count && bytes[at..at + count].iter().all(u8::is_ascii_digit)
    };
    let at = |pos: usize, c: u8| bytes.get(pos) == Some(&c);
    if !(digits(0, 4)
        && at(4, b'-')
        && digits(5, 2)
        && at(7, b'-')
        && digits(8, 2)
        && (at(10, b'T') || at(10, b't') || at(10, b' '))
        && digits(11, 2)
        && at(13, b':')
        && digits(14, 2)
        && at(16, b':')
        && digits(17, 2))
    {
        return false;
    }
    let mut rest = 19;
    if at(rest, b'.') {
        let start = rest + 1;
        let mut end = start;
        while digits(end, 1) {
            end += 1;
        }
        if end == start {
            return false;
        }
        rest = end;
    }
    match bytes.get(rest) {
        Some(b'Z' | b'z') => rest + 1 == bytes.len(),
        Some(b'+' | b'-') => {
            digits(rest + 1, 2)
                && at(rest + 3, b':')
                && digits(rest + 4, 2)
                && rest + 6 == bytes.len()
        }
        _ => false,
    }
}

/// One route this launch minted a credential for, with the provenance of where the route was
/// written ([spec §7.4]). Workspace routes and profile routes resolve into **one** table, which is
/// what lets `explain` answer why a credential is present.
///
/// [spec §7.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#74-attachment
#[derive(Debug)]
pub struct Minting {
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
    pub credential: Minted,
}

impl Minting {
    /// This route as the proxy serves it: the destination, what its rule sets allow, and the
    /// secret it puts in place of the phantom. The one place the secret is handed on, and it is
    /// handed to the supervisor's own proxy, in this process.
    pub fn route(&self) -> crate::proxy::Route {
        crate::proxy::Route {
            host: self.route.host.clone(),
            path_prefix: self.route.path_prefix.clone(),
            secret: Zeroizing::new(self.credential.secret().to_owned()),
            allowed: self.allowed.clone(),
        }
    }
}

impl Minting {
    /// What the run record holds about this credential: never the token.
    pub fn recorded(&self) -> crate::record::RecordedCredential {
        crate::record::RecordedCredential {
            host: self.route.host.clone(),
            path_prefix: self.route.path_prefix.clone(),
            minter: self.minter.clone(),
            expires_at: self.credential.expires_at.clone(),
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
            route: destination,
            minter: route.minter.clone(),
            delivery: route.delivery.env.clone(),
            from,
            allowed: allowed(policy, route),
            credential,
        });
    }
    Ok(minted)
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
        // Reaped by whoever inherited it, which takes a moment after the kill.
        let deadline = Instant::now() + Duration::from_secs(5);
        // SAFETY: signal 0 delivers nothing; it only asks whether `pid` exists.
        while unsafe { libc::kill(pid, 0) } == 0 {
            assert!(
                Instant::now() < deadline,
                "the minter's descendant {pid} outlived it"
            );
            std::thread::sleep(POLL);
        }
    }

    #[test]
    fn a_command_that_cannot_run_is_a_failure() {
        let minter: Minter =
            serde_json::from_value(serde_json::json!({"command": ["/nonexistent/mint"]}))
                .expect("a minter");
        let refusal = mint("gone", &minter, &request()).expect_err("refused");
        assert_eq!(refusal.code, Code::MinterFailed);
    }

    #[test]
    fn the_default_timeout_is_thirty_seconds() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(30));
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
            assert!(is_rfc_3339(good), "{good}");
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
        ] {
            assert!(!is_rfc_3339(bad), "{bad}");
        }
    }
}
