# Does `nono run` satisfy playpen's process-transparency contract?

Research ticket: [#17](https://github.com/firefly-engineering/playpen/issues/17). Map:
[#1](https://github.com/firefly-engineering/playpen/issues/1). Blocks
[#6](https://github.com/firefly-engineering/playpen/issues/6).

Date: 2026-08-16. Source is `nolabs-ai/nono` at commit
**`149579a7b0753ee413680169fa937eea82da46a0`** (2026-08-13, release `v0.73.0`) — the same
tree read for [`nono-evaluation.md`](nono-evaluation.md). Repo cloned to `/tmp/nono`; all
paths below are relative to that clone unless noted.

Standing laws applied: [ADR 0002](../docs/adr/0002-playpen-does-not-interpret.md)
(stdio inherited untouched, refusals on stderr, `125` reserved, signals forwarded to the
child's process group, `128+N` on signal death) and
[ADR 0003](../docs/adr/0003-nono-is-the-mechanism-backend.md) (the crate is the mechanism;
a live *ancestor* is forbidden, a *sibling* is allowed).

Method: source only. Every claim below is anchored to a file and line. Where the source
does not settle a question it is listed in §7 as unverified rather than guessed.

## TL;DR

`nono run` **fails** the contract, on one decisive point and several smaller ones: whenever
all three of stdin/stdout/stderr are TTYs, the supervisor allocates a PTY unconditionally
and with no flag to refuse it, `dup2`s all three of the child's descriptors onto the slave,
runs a vt100 emulator over the master, and writes the muxed stream plus its own escape
sequences back onto *its* stdout. #10's "unverified" claim was correct in substance and
slightly wrong in shape: the PTY is not unconditional, it is conditional on exactly the
case a TUI agent runs in.

The consequential answer is **yes, and better than hoped**. `nono proxy` is a documented,
first-class standalone command that runs the credential proxy with **no sandboxed child at
all** (`crates/nono-cli/src/proxy_command.rs:1-8`), and `--pass` / `NONO_PROXY_PASS` lets
the caller *pin* the session token, which is also the phantom token
(`server.rs:983-985`, `server.rs:565-613`). Better still, `nono-proxy` is a separate,
publishable crate with a fully public `ProxyConfig` and `server::start*`
(`crates/nono-proxy/src/lib.rs:47-52`, `config.rs:29`, `server.rs:924-967`), so playpen can
link it and run the proxy in a sibling process it owns, without `nono-cli`, without the
profile layer, and without a live ancestor. ADR 0003's mechanism decision and #6's proxy
decision **compose**.

---

## 1. File descriptors

### The PTY is conditional — on precisely the wrong condition

`nono run` always takes the supervised path: `select_exec_strategy` accepts five arguments,
discards all of them, and returns `ExecStrategy::Supervised` unconditionally
(`crates/nono-cli/src/launch_runtime.rs:609-624`). Only `nono wrap` uses
`ExecStrategy::Direct` (`crates/nono-cli/src/command_runtime.rs:401`). The manifest's
`process.exec_strategy` does **not** change this — in the library it is only a validation
constraint on `rollback`/`resources` (`crates/nono/src/manifest.rs:52-90`); nothing in
`nono-cli` reads it to pick a strategy.

The PTY decision is a pure function, and it has no flag:

```rust
// crates/nono-cli/src/supervised_runtime.rs:197-204
fn should_open_supervised_pty(
    detached_start: bool,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
) -> bool {
    detached_start || (stdin_is_terminal && stdout_is_terminal && stderr_is_terminal)
}
```

Called with the live `IsTerminal` probes at `supervised_runtime.rs:130-139`, which then
calls `pty_proxy::open_pty()`. There is no `--interactive`, no `--no-pty`, no env var: the
only ways to avoid it are to not be a terminal, or to not use `nono run`.

So the two cases split exactly opposite to what playpen needs:

- **ACP / piped invocation** (stdout is a pipe): no PTY. The child keeps fds 0/1/2 as
  inherited — `close_inherited_fds(max_fd, &child_keep_fds)` starts its loop at fd 3
  (`crates/nono-cli/src/exec_strategy.rs:2029-2038`, called at `:1308-1309`), and the
  non-PTY child path contains no `dup2` at all before `execve`
  (`exec_strategy.rs:1329-1335`). This case is clean.
- **Interactive TUI** (all three are TTYs): PTY, always.

### What the PTY does to the child

In the child, `setup_child_pty(slave_fd)` runs `setsid()`, `ioctl(TIOCSCTTY)`, then
`dup2(slave_fd, {STDIN,STDOUT,STDERR})` (`crates/nono-cli/src/pty_proxy.rs:304-331`,
invoked at `exec_strategy.rs:944`). The child's stdout and stderr are therefore **the same
pty**, i.e. muxed, and the child is in a new session detached from the caller's terminal.

### What the PTY does to the parent's stdout

The parent's `PtyProxy` attaches the caller's terminal as a client —
`AttachedClient::terminal(libc::STDIN_FILENO, libc::STDOUT_FILENO)`
(`pty_proxy.rs:371-373`) — and relays master output to that write fd
(`proxy_master_to_client_once`, `pty_proxy.rs:703-746`). It also writes its **own** bytes to
fd 1: alternate-screen enter and a scrollback replay on attach (`pty_proxy.rs:502-504`),
terminal restore sequences (`:489`, `:1564`, `:1807-1813`), a bare newline (`:464`), scroll
sequences (`:2328`). It puts the caller's stdin into raw mode via `tcsetattr`
(`set_terminal_raw`, `pty_proxy.rs:1572-1590`) and restores it later (`:898-908`).

And it does not merely relay: every byte is fed through a vt100 screen emulator that
renders, records scrollback and later gets scraped for diagnostics
(`pty_proxy.rs:199-233`, `record_output` `:981`, `screen_plaintext` `:1032`, consumed at
`exec_strategy.rs:1656-1669`).

**Verdict on §1:** disqualifying for ADR 0002 in the TUI case (buffering, muxing,
supervisor-authored bytes on stdout, an interposed terminal), and — only incidentally —
compliant in the piped/ACP case. A contract that holds by accident in one mode and breaks
in the other is not a contract playpen can rely on, especially as the condition is a
runtime probe of the caller's environment rather than anything playpen declares.

---

## 2. Signals

`setup_signal_forwarding(child, pty_master_fd)` is installed after fork
(`exec_strategy.rs:1522-1523`, definition at `:2207-2256`):

- Handlers for **SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1** (`:2235-2245`).
- **SIGWINCH only when a PTY exists** (`:2247-2254`) — and it is not forwarded as a signal;
  the handler reads `TIOCGWINSZ` from the parent's stdout and re-applies it to the master
  with `TIOCSWINSZ` (`forward_signal`, `:2304-2313`). Without a PTY there is no SIGWINCH
  handling at all, which is correct there since the child holds the real terminal.
- SIGUSR1 is intercepted for internal pause signalling and **not** forwarded (`:2314-2320`).
- Everything else is `libc::kill(child_raw, sig)` — **to the child PID, not to the process
  group** (`:2321-2325`). ADR 0002 specifies forwarding to the child's *process group*;
  nono's grandchildren are not signalled directly (on the PTY path they are reached
  indirectly, because the child is a session leader with its own controlling pty and the
  inner line discipline drives its foreground group).
- With no child registered, termination signals are re-raised under `SIG_DFL` rather than
  swallowed (`:2326-2340`) — a good detail.

Foreground-terminal handling: on the PTY path the child gets its own session and
controlling terminal (`pty_proxy.rs:304-315`), and `Ctrl-C` reaches it as a *byte* through
the raw-mode parent terminal, not as a forwarded signal. On the non-PTY path the child is
never `setpgid`'d, so it stays in nono's process group and the caller's foreground group —
job control is preserved by doing nothing, which is the right answer. There is explicit
SIGTSTP/Ctrl-Z machinery for the PTY path (`exec_strategy.rs:2429-2500`).

**Verdict on §2:** adequate but not equal to the contract. Signal delivery is to a PID, not
a process group, and SIGWINCH is translated rather than forwarded.

---

## 3. Exit status

The mapping is faithful (`exec_strategy.rs:1620-1640`):

```rust
WaitStatus::Exited(_, code)      => code,
WaitStatus::Signaled(_, sig, _)  => 128 + sig as i32,
other                            => 1,
```

and that value is the process's own exit status: `std::process::exit(exit_code)` at
`crates/nono-cli/src/execution_runtime.rs:783`. This matches ADR 0002's `128+N` rule
exactly. Note nono exits *with* `128+N` rather than re-raising the signal, so
`WIFSIGNALED` is false for nono itself even when it was true for the child.

Two places where nono substitutes its own status:

1. **Finalization failure downgrades a clean exit to 1**
   (`supervised_runtime.rs:160-176`): if post-exit bookkeeping (rollback review, session
   metadata, attestation) fails, exit 0 becomes 1; any non-zero child status survives
   untouched. The reasoning is written down at `:164-168` and the invariant is tested
   (`:493-500`).
2. **All of nono's own errors exit 1** (`crates/nono-cli/src/main.rs:137-153`). A refusal to
   start is therefore indistinguishable, by exit code alone, from an agent that exited 1.

**`125` is never used.** `grep -w 125` over `crates/nono-cli/src/` returns nothing, so
there is no collision with playpen's reserved refusal code — but note that ADR 0002 makes
translating a backend's failure code into `125` an *obligation*, and nono's failure code is
`1`, which is not translatable without also swallowing legitimate agent exits. Under
`nono run`, playpen could not honour that obligation. (The forked child uses the shell
conventions `126` for pre-exec failures and `127` for a failed `execve`:
`exec_strategy.rs:1294`, `:1325`, `:1335`; `pty_proxy.rs:284-296`.)

---

## 4. Stdout hygiene

**The supervisor's own diagnostics never touch stdout.** `crates/nono-cli/src/output.rs`
contains 72 print statements and every one is `eprintln!`; a `grep` for a non-`e` `println!`
in that file returns nothing. The same holds for `execution_runtime.rs`,
`supervised_runtime.rs`, `startup_prompt.rs`, `launch_runtime.rs` and `sandbox_prepare.rs`
— the only `stdout` reference across all five is the `is_terminal()` probe at
`supervised_runtime.rs:133`.

Specifically, answering #2's open question: **the Landlock degradation banner goes to
stderr.** `print_abi_info` emits the ` kernel ` badge and the
`degraded: … (upgrade kernel for full support)` hint with `eprintln!` at
`output.rs:417` and `output.rs:448`. The exit footer, the "Applying sandbox…" banner
(`output.rs:574`), the capability listing (`:86-286`), warnings (`:686`) and the
`[nono] Session stopped.` line (`exec_strategy.rs:1625`, `:1632`, via
`print_terminal_safe_stderr`, `startup_prompt.rs:5-13`) are all stderr. `--silent` is a
global flag that suppresses them (`cli.rs:76-79`).

Approval and startup prompts are handled with unusual care: `terminal_approval.rs:111-113`
reads `/dev/tty` and says so in a comment — *"not stdin, which belongs to the sandboxed
child"* (`:13`) — and startup-blocked notices prefer `/dev/tty`, falling back to stderr
(`startup_prompt.rs:23-36`). The profile-save prompt likewise uses `/dev/tty`
(`profile_save_runtime.rs:965-980`).

Two exceptions, both **before** fork and both on the profile path rather than the manifest
path: `prompt_cwd_sharing` reads a line from **stdin** when stdin is a TTY, and skips with a
stderr hint when it is not (`output.rs:1257-1270`); the same shape appears in
`migration.rs:242` and `legacy_cleanup.rs:219`.

So the real stdout problem is not diagnostics — it is §1's PTY relay, which is the only
thing that writes to fd 1 on the run path (`exec_strategy.rs:2354` and the `pty_proxy.rs`
sites listed in §1).

---

## 5. Session state written unasked

Supervised mode writes, without being asked:

- **A session file, unconditionally.** `SessionGuard::new(record)` is called with no flag
  guarding it (`supervised_runtime.rs:129`); it creates the sessions dir and writes a JSON
  record (`session.rs:73-81`). The record holds the scrubbed argv, session id, a generated
  random name, supervisor and child pids, start time, profile name, **the working
  directory**, and the network mode (`supervised_runtime.rs:100-128`). It is *updated*
  rather than removed on exit — `Drop` rewrites it with status `Exited`
  (`session.rs:101-112`). Nothing in `crates/nono-cli/src/cli.rs` disables this; there is no
  `--no-session`.
- **An audit session directory and a Merkleized append-only log, by default.**
  `create_audit_state` returns `None` only when `audit_disabled`
  (`rollback_runtime.rs:266-281`), which `--no-audit` sets (`cli.rs:2040-2046`); the
  integrity log has its own `--no-audit-integrity` (`cli.rs:2048-2050`).
- **A TLS-intercept directory whenever a proxy is configured**, even before interception is
  known to be needed: `apply_tls_intercept_config` unconditionally calls
  `prepare_intercept_ca_dir` (`proxy_runtime.rs:2817-2824`), which creates
  `$XDG_STATE_HOME/nono/sessions/intercept-<pid>-<nanos>/` mode `0700`
  (`proxy_runtime.rs:3136-3170`). It is removed by the proxy handle's `Drop`, which
  `execution_runtime.rs:776-782` is careful to fire before `process::exit`.
- Rollback snapshots when rollback is enabled (opt-in; `--no-rollback` warns if rollback
  flags are then passed, `rollback_runtime.rs:283-305`).

**Fully disabled? No.** Audit and rollback can be turned off; the session file cannot.

---

## 6. The consequential one — `nono proxy` as a standalone sibling

**Yes. It is supported, documented in the module header, and structurally independent of
the sandbox.**

### The command

`crates/nono-cli/src/proxy_command.rs:1-8` states the contract outright:

> Runs the network-filtering / credential-injection proxy as a foreground server, **with no
> sandboxed child**. Unlike the `run`/`shell`/`wrap` paths … this command prints the
> connection details (proxy URL, token, env vars) for the user to point their own tools at,
> then blocks until Ctrl-C.

`run_proxy` (`proxy_command.rs:26-152`) builds a `ProxyConfig`, starts the same
`nono_proxy::server::start_with_approval_and_capture_registry` the supervised path uses
(`:106-115`), prints connection info, and blocks on `ctrl_c` (`:127-144`). Nothing about it
touches Seatbelt or Landlock — the sandbox and the proxy are already separate concerns in
nono's own code.

### Config surface (`ProxyArgs`, `cli.rs:1472-1666`)

`--listen` (default `127.0.0.1`), `--port` (`0` = ephemeral), `--no-auth` (refused for
non-loopback binds, `proxy_command.rs:29-35`), `--pass` / `NONO_PROXY_PASS`,
`--max-connections`, `--profile`, `--network-profile`, `--allow-domain`, `--deny-domain`,
`--upstream-proxy` / `--upstream-bypass`, `--allow-http2`, `--proxy-ca-cert` /
`--proxy-ca-key` / `--proxy-ca-validity`, `--trust-proxy-ca` (macOS), `--credential`,
`--allow-endpoint`, `-v`. There is **no `--config <manifest>`** here — the standalone proxy
reads flags and, for custom credential routes / `cmd://` capture, a *profile*
(`build_launch_options`, `proxy_command.rs:196-360`).

Standalone mode hardens two settings relative to the supervised path
(`proxy_command.rs:40-53`): `require_auth = !no_auth`, and `strict_connect_auth = !no_auth`
so an unauthenticated CONNECT gets `407` instead of being tunnelled — precisely because
"there is no OS sandbox behind it" (`:45-48`).

### How a credential is associated with a client

By **bearer token only**. There is no peer-uid, pid or cgroup binding on the proxy socket.
The session token is generated per run *unless the caller supplies one*:

```rust
// crates/nono-proxy/src/server.rs:983-985
let session_token = match config.session_token {
    Some(t) if !t.is_empty() => t,
    _ => token::generate_session_token()?,
};
```

and `--pass` feeds exactly that field (`proxy_command.rs:59-66`; test at
`server.rs:2189-2201`, plus an empty-password rejection at `:2202`). The same token is the
**phantom** handed to the sandboxed client for every credential route
(`ProxyHandle::credential_env_vars`, `server.rs:565-613` — `vars.push((env_var.clone(),
self.token.to_string()))` at `:591`), and the same token appears in the proxy URL userinfo
(`ProxyHandle::env_vars`, `server.rs:494-553`). Requests are authorised by constant-time
comparison against it (`server.rs:1868`).

**This is what makes composition work.** If playpen pins `--port` and `--pass`, then every
value it must inject into the sandbox — `HTTP(S)_PROXY`, `NO_PROXY`, `NONO_PROXY_TOKEN`,
and the phantom credential env vars — is derivable by playpen without parsing anything, and
playpen can grant `NetworkMode::ProxyOnly { port }` on its own authority through the
`nono` crate per ADR 0003. The proxy is then a sibling holding a socket, not an ancestor
holding file descriptors.

Three caveats, all real:

1. **Its stdout is chatty, and the token is on it.** `print_connection_info`
   (`proxy_command.rs:362-420`) uses `println!` throughout — the listening address, the
   token-bearing URL, the raw token, `export HTTPS_PROXY=…` lines, per-route diagnostics,
   and the TLS trust-bundle path. This is a *sibling's* stdout, not the agent's, so ADR
   0002 is untouched; but a token on stdout is a secret in whatever captures it. `--silent`
   suppresses the whole block (`:372-374`).
2. **With `--silent` you lose the only announcement of the ephemeral port and the trust
   bundle path.** The port is solvable (pin `--port`). The trust bundle is not: its
   directory is `intercept-<pid>-<subsec_nanos>` (`proxy_runtime.rs:3155-3160`), so playpen
   cannot compute it and would have to read stdout or glob the sessions dir. Only matters
   if TLS interception is in play.
3. **It re-enters `nono-cli`**, which ADR 0003 puts structurally out of reach. Anything
   beyond `--credential <builtin-service>` and `--allow-domain` (custom credential routes,
   `cmd://` capture, endpoint rules from a profile) arrives through nono's *profile* layer.

### The better option: link `nono-proxy` directly

`nono-proxy` is a separate workspace crate at the same version (`0.73.0`) with **no
`publish = false`**, a crates.io-shaped manifest (`description`, `keywords`, `categories`),
and a fully public surface: `pub use config::ProxyConfig; pub use server::{ProxyHandle,
start};` plus `token::NonceResolver`, `CredentialStore` and the `tls_intercept` module
(`crates/nono-proxy/src/lib.rs:20-52`). `ProxyConfig` is a plain `pub` struct with all
fields public, `Serialize + Deserialize + Default`
(`crates/nono-proxy/src/config.rs:27-239`), and `server::start(config)` is the entry point
(`server.rs:924`, with `start_with_approval*` variants at `:930-967`). Its only nono
dependency is the `nono` crate itself (`crates/nono-proxy/Cargo.toml:20`) — **not**
`nono-cli`.

So playpen can build its own sibling proxy process from `nono-proxy` + a playpen-authored
`ProxyConfig`, keeping the profile layer out entirely, keeping the token pinned by
construction, and keeping stdout silent. That is the shape ADR 0003's last paragraph
already blesses.

---

## Bottom line

**`nono run` does not satisfy the process-transparency contract, and cannot be made to.**
The blocking finding is `supervised_runtime.rs:197-204`: when stdin, stdout and stderr are
all TTYs — the interactive-TUI case — the supervisor allocates a PTY with no flag to
decline, `dup2`s all three child descriptors onto it (`pty_proxy.rs:304-331`), muxes
stdout and stderr into one stream, runs a vt100 emulator over it, and writes both the
relayed bytes and its own escape sequences to fd 1 (`pty_proxy.rs:371-373, 464, 489,
502-504`). It is also the only mode `nono run` has: `select_exec_strategy` returns
`Supervised` unconditionally (`launch_runtime.rs:609-624`) and the manifest cannot override
it.

The rest of the contract it very nearly meets, and deserves credit for it: exit status is
faithful including `128+N` (`exec_strategy.rs:1620-1640`, `execution_runtime.rs:783`), it
never uses `125`, its diagnostics — degradation banner included — are entirely on stderr
(`output.rs:417, 448`), and its approval prompts deliberately read `/dev/tty` rather than
stealing the child's stdin (`terminal_approval.rs:13, 111-113`). The residual gaps are
signals going to a PID rather than a process group (`exec_strategy.rs:2321-2325`), a
session file written unasked with no flag to disable (`supervised_runtime.rs:129`,
`session.rs:73-81`), and nono's own refusals exiting `1` — indistinguishable from an agent
exiting `1`, so playpen's `125` translation obligation could not be met.

**And it does not matter, because the proxy does not need it.** `nono proxy` runs the whole
credential proxy with no sandboxed child (`proxy_command.rs:1-8`), `--pass` pins the session
token that *is* the phantom token (`server.rs:983-985`, `:565-613`), and `nono-proxy` is a
standalone, publishable, `nono-cli`-free library with a public `ProxyConfig` and
`server::start` (`lib.rs:47-52`, `config.rs:27-239`, `server.rs:924`). playpen confines the
agent itself through the `nono` crate per ADR 0003, pins `NetworkMode::ProxyOnly { port }`,
and runs the proxy as a sibling it owns. **The mechanism decision and the proxy decision
compose; #6 does not have to buy `nono run` to get the phantom-token proxy.**

Recommendation for #6: prefer linking `nono-proxy` over spawning `nono proxy`. The CLI
route works and is supported, but it drags the profile layer back in for anything past
`--credential <builtin>`, puts the token on a stdout you must then either read or silence,
and hides the TLS trust-bundle path behind a pid+nanos directory name.

---

## Left unverified

- **Whether `nono-proxy` is actually published on crates.io.** The manifest carries no
  `publish = false` and is fully populated, and the workspace publishes `nono` (v0.73.0) —
  but the crates.io API refused both requests from this environment
  (`data-access policy`), so I did not confirm a published `nono-proxy` artefact exists.
  If it does not, playpen would need a git or vendored dependency.
- **Runtime behaviour.** Nothing here was executed. Every finding is a reading of the
  source at `149579a7`; I did not build nono or observe an actual `nono run` under a pipe or
  a tty.
- **`nono attach` / `nono detach` on a session playpen did not create.** The session file is
  written unconditionally and is world-visible to the same user, which implies a
  third party can attach to a `nono run` session; I traced the attach *listener* into the
  PTY proxy (`pty_proxy.rs:513-676`) but did not read the socket's authentication path, so
  I cannot say what guards it. Moot if playpen never uses `nono run`, but it bears on
  whether nono's own state directory is a boundary.
- **Whether the standalone proxy's L7 endpoint policy can be expressed without a profile.**
  `--allow-endpoint SERVICE:METHOD:PATH` requires the service to be an active credential
  (`proxy_command.rs:292-300`), and richer per-host rules arrive as
  `AllowDomainEntry::WithEndpoints` from a profile (`:269-290`). Constructing the equivalent
  directly on `ProxyConfig` looks possible (the `routes` field is public) but I did not
  trace `EndpointRule` construction end-to-end from a hand-built config.
- **`--pass` and the OAuth-capture phantom.** I confirmed `--pass` pins the *session* token
  and therefore the static-route phantom. OAuth-captured phantoms are a different mechanism
  (`nono_<64hex>` nonces, per-consumer admission) and I did not check whether a pinned
  session token interacts with them.
- **Where the ephemeral CA lands under a pinned `--proxy-ca-cert`/`--proxy-ca-key`.** The
  flags are loaded and validated eagerly (`proxy_command.rs:77-87`, `:162-190`), which would
  give playpen a stable trust bundle across runs, but I did not verify that the bundle file
  path becomes predictable as a result.
