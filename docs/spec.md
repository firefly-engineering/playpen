# playpen — specification

> **Status: final.** Assembled from the resolved tickets of the
> [playpen wayfinding map](https://github.com/firefly-engineering/playpen/issues/1) by
> [Assemble the playpen spec](https://github.com/firefly-engineering/playpen/issues/9). No section
> is blocked, and the reconciliations in [Appendix B](#appendix-b--reconciliations-made-in-assembly)
> and the assembly choices in [Appendix C](#appendix-c--assembly-choices) have been reviewed and
> accepted. Questions that no current workload forces are handed off in
> [§20](#20-handed-off-questions).

This document is the **what**. The **why** lives in the ADRs under [`adr/`](adr/) and in the
resolution comments of the tickets this spec cites. The vocabulary is
[`CONTEXT.md`](../CONTEXT.md)'s. A term in **bold** on first use is defined there, and this
spec never redefines one.

Where the decided record disagreed with itself, this spec states the reconciled form and lists
every such reconciliation in [Appendix B](#appendix-b--reconciliations-made-in-assembly). Where
the spec had to choose something no ticket decided, the choice is listed in
[Appendix C](#appendix-c--assembly-choices). Nothing in either appendix is meant to pass
unreviewed.

---

## Contents

1. [What playpen is](#1-what-playpen-is)
2. [Threat model](#2-threat-model)
3. [Standing laws](#3-standing-laws)
4. [Architecture](#4-architecture)
5. [Workspace and profile model](#5-workspace-and-profile-model)
6. [The network](#6-the-network)
7. [Enforcement surface: credentials](#7-enforcement-surface-credentials)
8. [Enforcement surface: filesystem](#8-enforcement-surface-filesystem)
9. [The environment](#9-the-environment)
10. [The policy document](#10-the-policy-document)
11. [Invocation contract](#11-invocation-contract)
12. [The kind table](#12-the-kind-table)
13. [The manifest](#13-the-manifest)
14. [Diagnostics](#14-diagnostics)
15. [Host mechanism backends](#15-host-mechanism-backends)
16. [Distribution](#16-distribution)
17. [The enforcement suite](#17-the-enforcement-suite)
18. [Named residuals](#18-named-residuals)
19. [Out of scope](#19-out-of-scope)
20. [Handed-off questions](#20-handed-off-questions)
- [Appendix A — code registry](#appendix-a--code-registry)
- [Appendix B — reconciliations made in assembly](#appendix-b--reconciliations-made-in-assembly)
- [Appendix C — assembly choices](#appendix-c--assembly-choices)

---

## 1. What playpen is

playpen is a micro-container around **one coding-agent process tree**: `claude`, `omp`, or any
binary run under a **profile**. It enforces two things on that tree:

- **filesystem confinement**: an allow-list of named workspace roots, a built-in **floor**, and
  a declared toolchain;
- **credential confinement**: real secrets are minted outside the boundary and held by a
  **proxy** that injects them, only a **session phantom** crosses the boundary, and
  **credential oracles** such as `ssh-agent` are unreachable.

The network itself is **not** confined. The agent may reach any host; it simply cannot
authenticate anywhere except through the proxy ([ADR 0020](adr/0020-playpen-claims-credential-confinement-only.md)).

Which confinement applies is chosen by **policy**, a single system-wide document, selected from
invocation context. The two downstream consumers, herdr and buzz, invoke agent binaries directly
and get correct sandboxing with no integration work: a **shim** on `PATH` makes `claude` launch
confined.

The point of the outer boundary is to let agents run **with all their own permissions enabled**.
Per-tool permissioning stays the agent's job. playpen confines the whole process tree.

---

## 2. Threat model

**One invariant: the worst case is complete destruction *inside* the sandbox, and no means of
using a credentialed resource escapes the broker.** Workspace contents leaving the machine is
accepted: playpen protects the *means* to act on the operator's behalf, not the data the agent
was given to work on ([ADR 0020](adr/0020-playpen-claims-credential-confinement-only.md)).

Two tiers, both held by that invariant:

1. **Blast-radius containment.** Prompt injection, or a bad tool call by an agent that is
   otherwise well-behaved.
2. **An actively hostile driver.** A buzz agent takes freeform messages from third parties,
   forwarded to a runtime on the owner's machine.

What is trusted:

- **Selection inputs are owner-controlled.** buzz environment variables are part of the agent
  definition, and herdr's `herdr agent run` is a local process. Either way the sandbox exists
  before any adversary can speak to the agent.
- **The policy and the minters it declares are trusted host code.** A hostile minter is a
  hostile policy ([ADR 0008](adr/0008-credentials-are-minted-outside-and-only-phantoms-cross-the-boundary.md)).
- **The consumers (herdr, buzz) and any ACP client** are trusted to invoke, never to decide
  policy.
- **A process running on the host as the same uid** is outside the threat model. It already
  holds the real credentials and `~/.ssh`
  ([ADR 0013](adr/0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md)).

---

## 3. Standing laws

These hold across every section. Any design change that contradicts one must amend the law
explicitly.

1. **playpen is one layer.** It never gives credit to devbox, a VM, or any layer beneath it.
   Outer layers are the operator's business and invisible to policy.
2. **Refusal, never silent downgrade.** If a required capability is unavailable, playpen
   refuses to launch. A capability that can be enforced only *cooperatively* counts as
   unavailable. The test for whether cooperation is acceptable: the law bites when cooperation
   is the *sole basis of a confinement playpen claims*, and not when honouring it decides only
   whether something works
   ([ADR 0013](adr/0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md)).
3. **Default-deny.** Filesystem access is an allow-list of named workspaces. The environment is
   constructed, never filtered.
4. **The unit of policy is the process tree, never the tool call.**
5. **The policy is one strict document whose data model is JSON**, with YAML 1.2 as the surface
   syntax. It is never merged and never a directory. Nix is a good way to generate it, and never
   a runtime dependency
   ([ADR 0009](adr/0009-the-policy-is-one-strict-document-and-its-schema-is-generated.md)).
6. **No homegrown regex parsers.** Pattern languages are refused wherever a literal will do:
   environment names, `set:` values, injected flags, the query string. Where a
   small grammar is unavoidable (the endpoint path glob), playpen parses it itself as a total
   matcher.
7. **playpen does not interpret. It confines, then gets out of the way**
   ([ADR 0002](adr/0002-playpen-does-not-interpret.md)). It does not parse argv, interpose on
   stdio, remap paths, or interpret the child's exit status.
8. **No runtime capability expansion.** Every capability is fixed at launch, and a missing one
   is a refusal, never a prompt
   ([ADR 0003](adr/0003-nono-is-the-mechanism-backend.md)). Re-minting a credential for a
   route already declared is renewal, not expansion
   ([ADR 0018](adr/0018-playpen-authenticates-outside-the-boundary.md)).
9. **All per-agent knowledge is confined to the kind table** ([§12](#12-the-kind-table)).
10. **One policy author.** playpen ships fragments and merges none by default. The floor is the
    one built-in default, and it earns that exception by deciding whether `exec` returns, never
    what is reachable.
11. **A denial is never `ENOENT`.** A denial is always distinguishable in-band from absence and
    from success, on the filesystem and at the broker alike
    ([ADR 0007](adr/0007-playpen-owns-the-half-the-kernel-cannot-know.md)).

---

## 4. Architecture

### 4.1 Processes

```
 caller (terminal / herdr / buzz / ACP client)
   │  stdio inherited untouched
   ▼
 playpen supervisor ── unconfined ──────────────────────────────┐
   │  holds: flocks, minted secrets (Zeroizing), proxy listener  │
   │  hosts: proxy + credential broker (in-process)              │ 127.0.0.1:<port>
   │  fork                                                       │
   ▼                                                             │
 confined child ── applies capability set to itself, then exec ──┘
   └── agent process tree (MCP servers, shells, tools, …)
```

- The **supervisor** is the playpen process. It stays unconfined and remains the agent's direct
  parent for the whole run. It is *transparent* ([§11.6](#116-process-transparency)).
- The **proxy** runs **in the supervisor**, not as a detached process. It binds `127.0.0.1:0`
  *before* the fork, because the OS-assigned port is part of the **capability set**
  ([ADR 0013](adr/0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md)).
  An orphaned proxy is structurally impossible: killing the supervisor removes the credentials
  from the host and leaves any surviving agent with no credentials.
- The **confined child** closes every file descriptor except 0, 1 and 2, applies the capability
  set to itself through the backend, and `exec`s the target. The backend is linked in-process;
  there is no helper binary ([ADR 0003](adr/0003-nono-is-the-mechanism-backend.md)).

**Minters** are executables the policy names. They run unconfined on the host before launch, and
again during the run when a credential nears expiry.

### 4.2 Launch sequence

Each step either succeeds or refuses with exit `125` and one refusal line
([§14.3](#143-the-refusal-line)). The **run record** is opened first, so every refusal,
including a failure to find a policy or select a profile, leaves a record.

`playpen explain` launches nothing ([§14.2](#142-playpen-explain)), so it runs none of these
steps and opens no record: a command line that parses as `explain` is answered before step 1, and
takes no place in the ring of recent runs. Nor does a request for help. A command line that does
not parse is refused as a launch, with a record ([#52](https://github.com/firefly-engineering/playpen/issues/52)).

1. **Allocate a run id and open the run record** ([§14.1](#141-the-run-record)).
2. **Identify the invocation.** If `argv[0]` is not `playpen`, look it up as `shims.<argv[0]>`
   ([§11.3](#113-shims)). Otherwise parse the `playpen` subcommand.
3. **Locate and parse the policy** ([§10.1](#101-location), [§10.2](#102-syntax-and-strictness)).
4. **Select the profile** ([§11.4](#114-profile-selection)), recording the selection trace.
5. **Coherence checks**: everything decidable from the policy alone
   ([§10.5](#105-validation-tiers)).
6. **Existence and integrity checks**: roots and exclusions exist, symlinks resolve, the shim
   target exists, nothing that runs outside the boundary on the next launch is writable by the
   profile ([§11.7](#117-self-integrity)), and the CWD lies inside a granted root.
7. **Probe the mechanism** for every capability the resolved profile requires, and run the
   **floor self-test** ([§8.6](#86-the-floor-self-test)). If `--trace-denials` was given, run
   the trace self-test ([§14.5](#145---trace-denials)).
8. **Claim `exclusive` areas** with `flock` ([§5.4](#54-provisioned-areas)). A held lock is
   `refusal.area.busy`.
9. **Provision** the run scratch and every area.
10. **Mint** every resolved credential route ([§7.2](#72-minters)).
11. **Start the proxy** iff a credential route resolves ([§6.2](#62-the-broker)): bind, generate
    the ephemeral CA, and write its certificate into the run scratch.
12. **Compile the capability set**, including the proxy port. Check it against the backend's
    budget ([§15.3](#153-the-compiled-profile-ceiling)).
13. **Write the manifest** and render the kind's presentation
    ([§13](#13-the-manifest)).
14. **Construct the environment** ([§9](#9-the-environment)).
15. **Complete the run record** with the capability set and the timestamps.
16. **Fork.** The child closes fds above 2, applies the capability set, and `exec`s. A child that
    refuses before `exec` reports the refusal to the supervisor, which records it and writes the
    line. Once the target is `exec`ed, its pid goes to the run record.
17. **Supervise**: forward signals, serve the proxy, re-mint near expiry, and `wait`.
18. **Tear down**, in order:
    1. run revokers, while the proxy is still up;
    2. stop the proxy;
    3. remove ephemeral areas and the run scratch;
    4. re-run the trace self-test if tracing ([§14.5](#145---trace-denials));
    5. exit with the child's status.

    No teardown failure changes the exit status. Teardown failures go to the run record. Locks
    release when the process exits.

A proxy that stops serving mid-run **tears the run down**, so the agent never runs on with no
exit. A panic in the proxy is caught at the runtime boundary and routed into teardown.

### 4.3 The one network claim

playpen claims **credential confinement** and nothing else about the network
([ADR 0020](adr/0020-playpen-claims-credential-confinement-only.md), which retired the
*traffic confinement* of ADR 0004 and ADR 0013). It is enforced by construction (the environment
is built from nothing, so no real secret is ever written into it) and by the mechanism (credentials
at rest and unix-socket **credential oracles** are unreachable). An agent that bypasses the proxy
reaches the network and merely fails to authenticate.

---

## 5. Workspace and profile model

### 5.1 Workspace

A **workspace** is one named object describing everything a run may reach for one body of work.
It has two halves that are kept apart in its structure, plus playpen-owned areas:

- **brought roots**: filesystem trees that already exist ([§5.2](#52-brought-roots));
- **forge scope**: which remote repositories the work may reach, in forge vocabulary
  ([§5.3](#53-forge-scope));
- **provisioned areas**: writable directories playpen creates ([§5.4](#54-provisioned-areas)).

The workspace's **name** is what keeps the halves in sync. Nothing derives one half from the
other: `~/src/<host>/<org>/<repo>` is the operator's convention, not playpen's, so playpen
never infers an org from a path. A workspace also carries **workspace-attached credential
routes** ([§7.4](#74-attachment)).

### 5.2 Brought roots

- A literal absolute path. No globs.
- A mode of `read` or `readwrite`. `read` grants execute as well, because a writable area could
  host a copied binary anyway
  ([ADR 0014](adr/0014-the-toolchain-is-a-declared-closure.md)).
- Optional **exclusions** ([§8.4](#84-exclusions)).
- The path must exist at launch, or playpen refuses (`refusal.root.missing`).
- **A workspace that declares a worktree area while every source root is `read` is refused at
  launch** (`refusal.workspace.worktree-on-read-root`). A git worktree or jj workspace writes to
  the source's metadata directory on every ref update and index lock, so the shape is broken,
  not hardened ([ADR 0001](adr/0001-read-only-roots-exclude-worktrees.md)). Any workspace whose
  agent uses worktrees must grant its source roots `readwrite`, and the blast radius then
  includes the source repository's history.

### 5.3 Forge scope

Either `org: <name>` or `repos: [<org>/<repo>, …]`. An org-wide scope is a first-class value
because it is the granularity a minted token natively expresses. playpen does not know what a
forge is: the scope is opaque data handed to a minter ([§7.2](#72-minters)).

### 5.4 Provisioned areas

The operator declares that an area must exist and what it is for. The path is playpen's
business: a real host path under playpen's state directory, which the operator can `cd` into
(path identity, [§11.6](#116-process-transparency)). Areas are always writable.

| `lifetime` | Created | Removed | Keyed by | `concurrency` |
|---|---|---|---|---|
| `ephemeral` | at launch | at exit | **run** | not permitted (schema refusal) |
| `persistent` | on first use | never by playpen | **workspace name** | `exclusive` (default) or `shared` |

- **`exclusive`**: at most one live run may hold the area. The claim is an advisory `flock` held
  by the supervisor on a lock file in playpen's own state directory, and it releases when the
  supervisor dies. A held lock refuses immediately with `refusal.area.busy`, naming the holding
  run id. Launch never queues
  ([ADR 0010](adr/0010-concurrency-is-a-property-of-a-provisioned-area.md)).
- **`shared`**: every run gets the same path, and playpen says nothing about the contents. Use
  it for a **cache** whose owning tool does its own locking.
- The default is `exclusive`. A wrongly shared working area corrupts silently, while a wrongly
  exclusive cache merely refuses.
- The **landing zone**, where repositories cloned mid-session land, is an ordinary area named
  explicitly. It gets no special case. Clones inside it are already covered by its grant, so no
  runtime re-granting is needed.
- playpen arbitrates **only what it provisions**. A brought root carries no concurrency, even
  where two worktrees contend on the same source `.git`.

### 5.5 Profile

A **profile** is the unit an invocation selects. It holds:

- `prefixes`: the CWD prefixes it is selected by ([§11.4](#114-profile-selection));
- `workspaces`: a **list** of workspace names;
- `toolchain`: read-only roots for what the agent works *with* ([§8.3](#83-toolchain));
- `env`: allow-list names, **environment fragments**, and literal `set:` values ([§9](#9-the-environment));
- `credentials`: **profile-attached credential routes** ([§7.4](#74-attachment));
- `agent_state`: the per-kind **share list** ([§5.6](#56-agent-state-directory)).

Across a profile's workspaces, **brought roots union, while provisioned areas and forge scope
stay per workspace.** Not unioning forge scope is load-bearing: it stops the multi-workspace
case from silently demanding a credential broader than either workspace justifies.

Toolchain, `set:`, profile-attached routes, agent state and the run scratch attach to the **profile**, never to
a workspace. There is one boundary over one process tree, and no channel through which a request or
a variable could be attributed to a workspace in a way the agent could not forge.

**A profile is purely confinement and does not pin a binary.** Any binary may run under any
profile: `playpen run --profile work --agent claude -- bash` drops a shell into a live
boundary. Where pinning is wanted, it belongs on the shim declaration.

### 5.6 Agent state directory

Each **profile** has its own **agent state directory** for each kind
([ADR 0021](adr/0021-agent-state-belongs-to-the-profile.md)). playpen owns it and creates it under
its state directory on first use, and never removes it. The agent is pointed at it by the kind's
private redirect variable ([§12](#12-the-kind-table)). The real `~/.claude` or `~/.omp` is never
granted.

- **Keyed by profile × kind, never by workspace.** The directory holds transcripts, history and
  memory, which contain whatever the writing run could read. Only runs whose reach is that
  profile's write to it, so it can never carry one workspace's contents to a profile that cannot
  reach them. Two profiles sharing a workspace do not share its agent history. Renaming a profile
  starts a fresh directory.
- **Shared** by every run of the profile, concurrently. The directory is the agent's, and the
  agent handles its own concurrency (ADR 0010's cache case). There is no `concurrency` field.
- **Share list.** Entries named in `profiles.<p>.agent_state.<kind>.share` are made visible
  read-only inside the directory. The list is default-deny: empty unless entries are named.
- **The presentation adapter owns the kind's instruction entry point** ([§13.3](#133-presentation)).
  A share entry naming that same file is **composed by reference**: the rendered file ends with
  the kind's import line pointing at the real file, which is granted read-only. For a kind with
  no import mechanism, the collision is `refusal.state.collision`.

The cost is stated: a first launch under a new profile has no MCP auth and no history.

### 5.7 Run scratch

There is one ephemeral writable directory per run, exposed as `TMPDIR`. It belongs to the run,
not to any workspace, so it is not a provisioned area. It holds the **manifest** and the proxy
CA's certificate. The host's own temp, including macOS's `/var/folders/…` reached through
`confstr`, is unreachable.

---

## 6. The network

### 6.1 What is not confined

playpen confines no network traffic ([ADR 0020](adr/0020-playpen-claims-credential-confinement-only.md)).
The backend's network mode is nono's `AllowAll`, and on Linux no seccomp network filter is
installed, so TCP, UDP, DNS and QUIC all work and the agent resolves names itself. There is no
egress setting, no allow-list and no pin. Loopback is open because nothing is closed.

The retired design is worth one sentence, because it explains what remains: neither platform's
mechanism can express per-host egress, so name-based policy could only ever live in an L7 proxy,
and the proxy survives as the place credentials live.

### 6.2 The broker

The **proxy** exists **iff at least one credential route resolves**. When it exists:

- **Every client is pointed at it.** `HTTPS_PROXY` is global, because `NO_PROXY` can only exclude
  hosts, so there is no standard way to route only credentialed hosts through it.
- **TLS is terminated only for routed hosts.** You cannot strip a phantom through a tunnel you
  cannot read. Every other host gets an **opaque `CONNECT`, with no check**.
- The interception CA is **ephemeral, in-memory, and per-session**. Its private key never leaves
  the supervisor. Its certificate, which is public, is written into the run scratch and named by
  both `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS`.
- **A TLS-interception failure is a refusal**, never a fallback to an opaque tunnel.
- **A dead proxy tears the run down.** Every client points at it, and a loud end beats credentials
  lapsing silently.

A credential works **only over HTTPS through the broker**. Credentialed `git+ssh` is therefore
unavailable: there is no way to inject a secret into a raw TCP stream, and `SSH_AUTH_SOCK` is
forbidden ([§6.3](#63-credential-oracles)).

### 6.3 Credential oracles

A **credential oracle** performs a credentialed operation for whoever reaches it, so the means can
escape with no secret crossing the boundary.

- **Unix-socket oracles** (`ssh-agent`, `gpg-agent`, a password manager's agent, `docker.sock`)
  are **denied by default**. A `connect()` to a pathname socket is refused unless the socket sits
  under a granted writable area, so the agent's own sockets (tmux, language servers) work.
  - **macOS**: Seatbelt treats a unix-socket connect as a network operation. Upstream nono's
    `AllowAll` grants every unix socket. The pinned fork renders `AllowAll` outbound as IP-only and
    sends unix sockets through its explicit-grant path, keeping the `mDNSResponder` grant that DNS
    needs ([ADR 0022](adr/0022-playpen-pins-a-maintained-fork-of-nono.md)).
  - **Linux, Landlock ABI ≥ 9**: enforced by Landlock's `FS_RESOLVE_UNIX` right, which the fork's
    ABI probe negotiates. Upstream nono stops at V6 and could never reach it.
  - **Linux, Landlock ABI < 9**: unenforceable, so this is a **named residual**
    ([§18](#18-named-residuals)). The regime that applied is recorded **outward only**, in the run
    record and `playpen explain`, and never in the manifest, because it maps what is worth
    attacking.
  - Abstract-namespace sockets are covered by the Landlock ABI 6 scoping playpen requests
    explicitly ([ADR 0003](adr/0003-nono-is-the-mechanism-backend.md)).
- **Network-reachable oracles** (a cloud metadata endpoint, a credential service on host loopback)
  are a **named residual** on every platform. Under standing law 1, the layer that exposes one owns
  protecting it.

### 6.4 Broker denial

- **An endpoint rule refusal** ([§7.6](#76-endpoint-rule-sets)) is the only denial the broker
  makes. The proxy *answers* rather than dropping the connection: `403` with
  `X-Playpen-Denied: <host>` and the code `broker.endpoint.denied`.
- **The response body is self-describing**: it names playpen, the code, and the destination.
  Bun's `fetch`, which both flagship agents use, hands a proxy refusal to the application as an
  ordinary `Response`, indistinguishable from an origin `403` by status alone
  ([#24](https://github.com/firefly-engineering/playpen/issues/24)).
- **A genuine upstream failure** is `502`, and carries no code.
- **A missing credential is never a `broker.*` code.** A request to a host with no route goes out
  unauthenticated, and the provider's own `401` is the answer.

---

## 7. Enforcement surface: credentials

**Credentials are minted outside the boundary, and only phantoms cross it**
([ADR 0008](adr/0008-credentials-are-minted-outside-and-only-phantoms-cross-the-boundary.md)).

### 7.1 Credential route

A **credential route** pairs:

- `host`: the destination host;
- `path_prefix`: a literal path prefix, used as a **selector** and never as access control;
- `minter`: the minter that produces the secret;
- `delivery`: how the phantom reaches the agent, today `{env: <NAME>}`;
- `endpoints`: optional names of **endpoint rule sets** ([§7.6](#76-endpoint-rule-sets)).

The proxy matches a request against **host plus literal path prefix**. Because forges and most
SaaS APIs carry the org in the path, this keeps two workspaces' credentials distinct *in use*,
not merely at minting. Two routes on one host where neither prefix strictly extends the other
are **ambiguous**, and playpen refuses (`refusal.route.ambiguous`, naming both routes and the
host). Longest-prefix-wins would silently authenticate a request with the wrong workspace's
credential.

### 7.2 Minters

A **minter** is an operator-declared executable (`command`, as an argv list), optionally paired
with a **revoker** (`revoke`). playpen runs it unconfined, bounded by `timeout` (default 30 s), and
passes the declared scope as JSON on stdin:

```json
{"version": 1,
 "route": {"host": "api.github.com", "path_prefix": "/repos/firefly-engineering/"},
 "scope": {"org": "firefly-engineering"}}
```

`scope` is the workspace's forge scope (`{"org": …}` or `{"repos": […]}`) for a workspace route,
and `null` for a profile route. On stdout the minter returns:

```json
{"token": "<secret>", "expires_at": "<RFC 3339 timestamp>"}
```

`expires_at` is required. A revoker receives the same stdin.

- **Stdout is a secret channel.** It is held in `Zeroizing` memory from the moment it is read,
  never logged, and never shown in `playpen explain`. The run record holds `expires_at` and
  never the token.
- **Failure before launch refuses the whole run**, with `refusal.minter.failed`,
  `refusal.minter.malformed` or `refusal.minter.timeout` naming the minter and the scope. A minter
  that hangs must not hang the launch: herdr and buzz expect a process or an error. The default
  timeout decides how long playpen waits, never what is reachable, so it is not a second policy
  author. Launching without the credential
  would produce a run that works for ten minutes and then fails at the first push.
- **Renewal.** As a credential nears `expires_at`, the supervisor re-invokes its minter. A
  re-mint failure mid-run cannot be a refusal: the credential lapses, and the provider's `401`
  stands.
- **Revocation is an optimization, and the TTL is the guarantee.** Revokers run best-effort at
  teardown, before the proxy stops. A design whose safety depends on a cleanup path running is
  unsafe under `SIGKILL`.
- A keystore lookup is the **trivial minter**. It is not a separate concept.
- The minter is chosen **per provider, never per kind**
  ([ADR 0018](adr/0018-playpen-authenticates-outside-the-boundary.md)).

### 7.3 Session phantom

There is one random bearer token per run, the **session phantom**, delivered into every route's
`delivery` variable. There is one phantom per run rather than one per credential, because
delivery cannot hand one tool a choice between two values. When the agent presents it, the
proxy strips it and injects the route's real secret. **There is no mode in which a real secret
enters the sandbox's environment or filesystem.** nono's `--env-credential` shape is not
offered, even as an opt-in.

The phantom works in both directions:

- **Inward**, it contains exfiltration: a secret that is not present cannot leak through a log
  line or a tool call.
- **Outward**, it authenticates callers of the proxy. A host process can reach the listener but
  cannot present a token it never saw.

**The phantom belongs to the process tree, not to the agent.** Every child, a third-party MCP
server included, inherits it and has full use of every route. This follows from the unit of
policy; it is not a residual. **Endpoint rule sets** bound every holder alike
([ADR 0008](adr/0008-credentials-are-minted-outside-and-only-phantoms-cross-the-boundary.md),
amended by [#30](https://github.com/firefly-engineering/playpen/issues/30)).

**Injection substitutes in place.** The proxy finds the phantom in whichever header the client
sent it in (`Authorization: Bearer`, `x-api-key`, …) and replaces it there with the real secret,
so the request's shape is whatever the harness already sends. A request on a route that carries
no phantom is forwarded unauthenticated. Serving a credential of one shape to a harness
configured for another (an OAuth token to a harness that sends an API key) is **not specified**
([§20](#20-handed-off-questions)).

### 7.4 Attachment

- A **workspace** route is for a credential that minimizes to that workspace's forge scope. The
  minter receives that scope.
- A **profile** route is for everything else, such as a model API key or a SaaS token.
- Both resolve into **one route table**, with provenance retained (`from:`), so
  `playpen explain` can answer why a credential is present.

### 7.5 Subscription logins

The operator logs the agent in **natively, outside the boundary**, where the browser is. A
minter then reads the host's own store: the Keychain on macOS, or the agent's credential file
on Linux. There is no capture, no interception of a token endpoint, and no playpen-owned token
store ([ADR 0018](adr/0018-playpen-authenticates-outside-the-boundary.md), amended by
[#33](https://github.com/firefly-engineering/playpen/issues/33)).

- **The reference minter for Anthropic is a keystore lookup of the dedicated, non-refreshing
  grant** that `claude setup-token` mints: one year long, scoped `user:inference`, and stored in
  the operator's own keystore item. It serves any kind run against Anthropic.
- **The fallback** is a read-only minter that returns the host login's current access token and
  never refreshes.
- **playpen ships no refreshing minter.** Anthropic refresh tokens are single-use, so a refresh
  that does not write back logs the host out within one access-token lifetime. A warning to that
  effect ships with the minter interface.
- A profile with no route for the agent's own model API still launches, and the agent gets the
  provider's `401`.

### 7.6 Endpoint rule sets

**An endpoint rule restricts the credential, and never the agent**
([ADR 0017](adr/0017-an-endpoint-rule-restricts-the-credential-and-never-the-agent.md)).

- A rule set is a **named**, allow-only list of `{method, path}`. It is referenced from a route
  by name and never written inline.
- A rule set exists **only on a credential route**. A host carrying no credential can carry no
  rule. Restricting what the agent may *do* to such a host would rest on cooperation alone,
  because playpen confines no network, so it is unexpressible, permanently.
- `path` is **host-absolute** and matched with a two-token segment glob: `*` matches exactly one
  segment and `**` matches zero or more. playpen parses the glob itself. Anything richer
  (alternation, character classes, anchors) is a parse refusal with file, line and column.
- **The query string is never matched.** **No deny list, no ordering.** An absent `endpoints:`
  means unrestricted, not empty.
- A request matching no rule gets `403` with the code `broker.endpoint.denied`. **No upstream
  leg occurs**, so the secret is never sent to a destination the rule refused. The `403` names
  no rule set, because the manifest already states them.
- Coherence refusals: `refusal.endpoint.unknown` for a reference to a rule set that does not
  exist, and `refusal.endpoint.unsatisfiable` for a rule set that no path under the route's
  prefix can match.
- playpen ships rule sets (for example "read-only GitHub") as data the operator names
  explicitly. A `GET`-only set cannot `clone`, because a git fetch is
  `GET …/info/refs` followed by `POST …/git-upload-pack`.

### 7.7 Consequences

- A credential works **only over the proxy**, which retires `git+ssh` a second time.
- **One logical credential is three policy objects**: a minter, its routes, and their delivery.
  The verbosity is the price of a single policy author.
- The Keychain is unreachable inside the boundary ([§8.2](#82-the-floor)), so
  `git-credential-osxkeychain`, `gh auth`, and npm and docker credential helpers **fail loudly**
  inside it.

---

## 8. Enforcement surface: filesystem

### 8.1 Shape

The filesystem grant is the union of:

- the **floor**;
- the **toolchain**;
- every workspace's **brought roots**, minus their exclusions;
- every **provisioned area** and the **run scratch**;
- the kind's agent state directory, plus its read-only **share list** entries.

Everything else is denied. That includes the agent binary itself, unless a toolchain root
covers it ([Appendix C](#appendix-c--assembly-choices), item C9). Seatbelt and Landlock both confine paths in place, so every path is
the same inside and out ([§11.6](#116-process-transparency)).

### 8.2 The floor

The floor is built in, always applied, and **neither widenable nor narrowable by policy**
([ADR 0014](adr/0014-the-toolchain-is-a-declared-closure.md)). Its content is bounded:

- read and execute only, only under OS-owned paths;
- never anything under `$HOME`, never a package store, never anything writable;
- one exception to read-only: the null device `/dev/null` is read-write. It is a **sink**, not
  storage: a write to it reveals and keeps nothing, and a program that cannot open it for writing
  breaks in ways unrelated to its boundary;
- on macOS, a short enumerated set of Mach services, and nothing else by global or per-user
  lookup: `com.apple.trustd` and `com.apple.trustd.agent` (trust evaluation),
  `com.apple.system.notification_center` (notify), and
  `com.apple.system.opendirectoryd.libinfo` (directory lookup, without which `getpwuid` resolves
  the user to a bare uid). The Keychain's services are therefore denied, with no knob to re-add
  them: `com.apple.SecurityServer` (file-based keychains, served by `securityd`) and the
  data-protection keychain's `com.apple.securityd.xpc`, `com.apple.securityd.general`,
  `com.apple.securityd.ckks`, `com.apple.securityd.sos` and `com.apple.securityd.aps` (served by
  `secd`). That set is what resolves through the bootstrap server on macOS 15 and macOS 26, where
  it was measured; it is not promised for other versions. `N-keychain`
  ([§17.2](#172-rows)) asserts exactly this set and is the live check, so a service a later macOS
  adds, renames or drops surfaces as that row to update. No explicit deny list ships, because
  shipping one would imply the allow-list is permissive.

Amended by [#48](https://github.com/firefly-engineering/playpen/issues/48), which measured what an
ordinary dynamically linked binary needs.

**On a host whose OS is not an FHS tree, the floor is a dedicated one**
([ADR 0023](adr/0023-the-floor-on-a-non-fhs-host-is-a-declared-closure.md)). A list of FHS
directories cannot be that host's floor: a NixOS binary names its interpreter and every library
it needs by store path, so on such a host `/bin` holds a single symlink, `/lib64` holds the loader
stub alone, and no path the list can name is both OS-owned and runnable. A **dedicated floor** is
a generated directory holding the OS's own command binaries and, beside them, the **declared
closure** they need, one store path per line. The floor is then one read-and-execute root per
line — never a coarse `/nix/store` root, which would be the leak [§8.3](#83-toolchain) describes.
The generator is the closure's only author, as for a toolchain closure
([§16.1](#161-nix)), and playpen only ever reads the list, so it keeps **no runtime Nix
dependency**.

A dedicated floor is named by `PLAYPEN_FLOOR`, else taken from the floor the Nix module installed
in the running system generation. That variable states **where this host keeps its OS**; it is not
policy, and no policy document can name or reach it, so the floor stays neither widenable nor
narrowable by policy ([ADR 0014](adr/0014-the-toolchain-is-a-declared-closure.md)): every grant
still comes from the floor's own generated closure, and nothing hand-written can add a path to it.
A host that has neither a dedicated floor nor an FHS canary has no floor to test, which is
`refusal.floor.unavailable`, naming the remedy.

The floor is **one object with per-platform contents**. On macOS it must include
`(allow file-read* (literal "/"))`: without it, every dynamically linked binary aborts with
`rc=134` and empty stderr. It must also include `file-read*` on the literal
`/System/Volumes/Data`: libSystem stats that mount point at startup, and when the stat is denied it
reports the denial over the syslog socket, which the process then holds for its lifetime. On
Linux it includes `/proc`, `/dev`, the loader and its cache. How the floor is spelled never appears in a test; the loader canary and the fd negative must pass on
both platforms.

### 8.3 Toolchain

The toolchain is a profile-level **set** of read-only **toolchain roots**. It takes three shapes,
chosen by the kind of tree:

| Tree | Shape | Exclusions |
|---|---|---|
| content-addressed (Nix store) | **toolchain closure**: one root per store path in the closure of a declared package set | none needed |
| mutable, with stable per-package links (Homebrew) | **keg list**: one root per `/opt/homebrew/opt/<keg>`, resolved at launch | none needed |
| mutable, with no per-package links | coarse root | as needed |

- **A coarse `/nix/store` or `/opt/homebrew` root is a leak.** The store holds every stale
  generation of the operator's dotfiles: 120 `home-manager-files` derivations on the reference
  host, each containing a readable `.ssh/config`. The Homebrew prefix holds SSH host private keys
  under `etc/ssh/`.
- **A closure is a root list**, and the generator is the only author that can write one
  ([§16.1](#161-nix)). playpen does not register GC roots: the generator roots the closure in
  its own generation.
- **The keg list is closed over dependencies by Homebrew's own tooling**
  (`brew deps --installed --union <kegs>`), never by playpen.
- A Nix *profile* cannot be a toolchain root. `home-manager-path/bin/git` is a symlink out to
  the store, so granting the profile grants nothing usable.

### 8.4 Exclusions

An exclusion is a literal subpath subtracted from a brought root or a coarse toolchain root,
with an optional `classes` set drawn from `read`, `execute` and `write`. If `classes` is
omitted, all three are subtracted, so an exclusion written without thinking gets the stronger
subtraction.

- An exclusion **must exist, or playpen refuses** (`refusal.exclusion.missing`). An exclusion
  whose path has gone is a leak that reopened silently.
- Exclusions apply to **mutable** trees only.
- **Exclusions are never stated inward.** The manifest omits them, because an enumeration of
  carve-outs is a map of what is worth attacking.
- **Exclusions are macOS-only for now.** Seatbelt subtracts one with a deny rule placed after the
  allows. Landlock is allow-only, and a grant on a directory covers everything beneath it, so it
  cannot express a subtraction. On Linux a launch whose profile carries an exclusion refuses with
  `refusal.mechanism.unavailable`, naming it, rather than grant what the policy took away. A named
  asymmetry ([§15.4](#154-named-asymmetries), item 8); whether Linux ever gets them is
  [#127](https://github.com/firefly-engineering/playpen/issues/127).

### 8.5 Symlinks

Where policy names a stable symlink, playpen **resolves it at launch and grants both the link and
its target**, because the mechanism enforces on the resolved path. A stale link produces a loud
refusal naming the path (`refusal.root.missing`), never an agent that starts and cannot find its
own binary. Policy names stable links (`/opt/homebrew/bin/claude`) and never versioned paths.

### 8.6 The floor self-test

Before every launch, playpen applies the floor to a throwaway child and asserts that a
dynamically linked OS binary exits 0. A failure is `refusal.floor.self-test`. The result is
**never cached**: every cache key is a guess that fails open and silently. The self-test and the
suite's `P-canary` row are **one implementation with two callers**.

The canary is that binary, and it comes from whatever the floor is on this host: `/usr/bin/true`
or `/bin/true` on an FHS host, and the one the dedicated floor carries where there is one
([§8.2](#82-the-floor)). It is **resolved per call**, never once, for the same reason the verdict
is never cached: which binary the floor can run is a property of the host as it is now. The canary
stays **dynamically linked** on every host, because a static one would exit 0 without ever
exercising the loader, which is the half of `exec` this test exists to prove.

### 8.7 File descriptors

Before `exec`, the child closes every descriptor except 0, 1 and 2. The sandbox gates
*acquisition*, not use of an already-open descriptor, so no allow-list can close this hole.
Supervisor-held descriptors (lock files, the listener) stay in the parent.

### 8.8 Concrete consequences

- `git` inside the boundary has **no user identity** by default. The fix is for the profile to
  state a committer identity, for example through `set:`, not to grant `~/.gitconfig`, which
  can name a credential helper.
- A denied read under `$HOME` returns `EPERM`, which is honest and distinguishable from absence.

---

## 9. The environment

**The environment is constructed, never filtered, and exactly one author writes each name**
([ADR 0012](adr/0012-the-environment-is-constructed-and-exactly-one-author-writes-each-name.md)).
Nothing reaches the child that playpen did not put there, so there is no deny list and nothing to
strip.

### 9.1 Layers

1. **The floor**, passed through from the host: `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`,
   `TERM`, `LANG`, the enumerated `LC_*` family (`LC_ALL`, `LC_CTYPE`, `LC_COLLATE`,
   `LC_MESSAGES`, `LC_MONETARY`, `LC_NUMERIC`, `LC_TIME`, `LC_ADDRESS`, `LC_IDENTIFICATION`,
   `LC_MEASUREMENT`, `LC_NAME`, `LC_PAPER`, `LC_TELEPHONE`), and `TZ`.
2. **playpen's set entries** ([§9.2](#92-set-entries)).
3. **The profile's allow-list**: the names in `env.allow`, plus the names in each env fragment
   listed in `env.fragments`, passed through from the host.
4. **The profile's `set:` table**: literal values, or a typed `!area <workspace>/<area>`
   reference. These win over floor pass-through.

Rules:

- **Names only.** An inherited value is never inspected: a value can only name a path, and the
  mechanism enforces every path regardless. Names are exact, never patterns.
- **An allow-listed name that is absent from the host env is simply absent.** This is the one
  stated exception to refusal-never-silent-downgrade, and it is earned because it fails closed.
- **`HOME` and `PATH` pass through unrewritten by default.** Rewriting `HOME` would be remapping
  in an env-var costume.
- **Fragments carry names, never values.** A value is a fact about one host, so it reaches the
  policy through generation.
- **`SSH_AUTH_SOCK` is permanently forbidden** (`refusal.env.forbidden`). It names a
  **credential oracle** the proxy cannot see. Banning the name is necessary but not sufficient;
  the socket itself is denied by [§6.3](#63-credential-oracles). Path-shaped hazards
  (`NODE_OPTIONS`, `LD_PRELOAD`, `GIT_SSH_COMMAND`, …) are *not* banned: they can only name a
  path, and an unreachable path fails `EPERM`.
- `set:` is **profile-level only**. Per-workspace values would need merging.
- `set:` values are not validated semantically. The single constraint playpen owns is the OS's:
  a value containing NUL is a policy parse failure.

### 9.2 Set entries

Every set entry is **mandatory relative to the boundary actually built**. Its absence within its
condition is a refusal, and with no proxy no proxy variable exists at all. A proxy exists iff a
credential route resolves, and interception happens exactly then, so the proxy and CA entries
share one condition ([ADR 0020](adr/0020-playpen-claims-credential-confinement-only.md)).

| Name | Value | Condition |
|---|---|---|
| `TMPDIR` | the run scratch | always |
| `PLAYPEN_MANIFEST` | the manifest path | always |
| `PLAYPEN_ACTIVE` | the profile name | always |
| `HTTPS_PROXY` | `http://127.0.0.1:<port>` | iff a route resolves |
| `NO_PROXY`, `no_proxy` | `localhost,127.0.0.1,::1` (enumerated, never CIDR) | iff a route resolves |
| `NODE_USE_ENV_PROXY` | `1` | iff a route resolves |
| `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS` | the CA certificate in the run scratch | iff a route resolves |
| each route's `delivery.env` | the session phantom | iff that route resolves |
| the kind's state-dir redirect | the agent state directory | always ([§12](#12-the-kind-table)) |
| the kind's suppression entries | per kind | always ([§12](#12-the-kind-table)) |

- **The CA pair covers two TLS stacks in one boundary.** Both flagship binaries are Bun and
  honour `NODE_EXTRA_CA_CERTS`, while `git` and `curl` read `SSL_CERT_FILE`.
- **`NODE_USE_ENV_PROXY=1`** makes Node-written stdio MCP servers, and children on Bun ≥ 1.4.0,
  proxy their `node:http` and `fetch` traffic. Without it they go direct, bypass the broker, and
  fail to authenticate, while the agent itself works
  ([#24](https://github.com/firefly-engineering/playpen/issues/24)).
- **Correct by construction.** Each value playpen writes is rendered from a typed value (the
  bound socket address, a path playpen just created) through a real URL or path type, never by
  string formatting. The gate on this is playpen's own unit and property tests, not a runtime
  check.

**Reserved names.** Every name in the table above is reserved in every run, whether or not it is
written. A policy `set:` or `env.allow` entry that collides with one is
`refusal.env.reserved`: two authors of one variable is "which rule won" in miniature.

### 9.3 Inward and outward

The manifest does **not** restate the environment, because the agent can read its own
`environ`. `playpen explain --json` shows the constructed environment in full, with fragment
provenance, as part of the capability set.

---

## 10. The policy document

### 10.1 Location

The policy is located by a fixed search path. The first hit wins, and documents are never
merged ([ADR 0015](adr/0015-the-nix-module-is-a-projection-and-home-manager-is-the-primary-tier.md)):

1. `--policy <path>`, if given;
2. `$XDG_CONFIG_HOME/playpen/`;
3. `~/.config/playpen/`;
4. `/etc/playpen/`.

At each directory, `policy.yaml` is looked for before `policy.json`. **Both present at one
location is a refusal** (`refusal.policy.ambiguous-location`); the extension selects the parser
and nothing else. There is **no `PLAYPEN_POLICY` environment variable**. A system document is not
a base layer: it is dead whenever a user document exists. No policy found is
`refusal.policy.not-found`.

### 10.2 Syntax and strictness

- **One YAML 1.2 document**, made of keyed tables. A multi-document stream (`---`) is refused.
  A `.json` file is valid input, because JSON is a subset of YAML 1.2.
- **Strict everywhere.** Each of these is a refusal naming the offending path:
  - an unknown key (`refusal.policy.unknown-field`);
  - an unrecognised `version` (`refusal.policy.version`);
  - an explicit tag other than playpen's own `!area` (`refusal.policy.tag`);
  - a type mismatch or invalid enum variant (`refusal.policy.type`). `mode: no` is an invalid
    variant, not `false`.
- **Anchors, aliases and merge keys are allowed.** They are one author's document, expanded
  before the data model exists.
- `definitions:` is a declared key of free-form type, for holding anchors. A typo inside it is
  still refused at the **use site**.
- **A policy refusal names file, line and column.** Where a key arrived through a merge key, it
  names both the use site and the definition site. This is a requirement on the parser: the
  `Value` → merge → re-deserialise path loses spans, so it does not satisfy it.

### 10.3 Schema

The **Rust serde types are canonical.** The JSON Schema is *generated* from them, committed, and
CI-gated against a fresh generation. Three schemas come from the same machinery:

- the authored **policy**;
- the **resolved form** (`playpen explain --json`);
- the **manifest**.

Tables:

| Key | Holds |
|---|---|
| `version` | integer; `1` |
| `definitions` | free-form anchors |
| `minters` | `<name>: {command: [argv…], revoke?: [argv…], timeout?: <seconds>}` |
| `fragments` | `env: {<name>: [NAME…]}`, `endpoints: {<name>: [{method, path}…]}` |
| `workspaces` | `<name>: {roots, areas, forge?, credentials?}` |
| `profiles` | `<name>: {prefixes?, workspaces, toolchain, env?, credentials?, agent_state?}` |
| `shims` | `<name>: {target, kind, profile?, flags?}` |

A worked example (illustrative values):

```yaml
version: 1

definitions:
  anthropic-route: &anthropic-route
    host: api.anthropic.com
    path_prefix: /
    minter: anthropic-setup-token
    delivery: { env: CLAUDE_CODE_OAUTH_TOKEN }
    endpoints: [anthropic-inference-only]

minters:
  gh-app:
    command: [/etc/playpen/minters/github-app-token]
    revoke: [/etc/playpen/minters/github-app-revoke]
  anthropic-setup-token:
    command: [/etc/playpen/minters/keychain-read, playpen-anthropic-setup-token]

fragments:
  env:
    rust: [CARGO_HOME, RUSTUP_HOME]
  endpoints:
    github-read-only:
      - { method: GET,  path: /*/*/info/refs }
      - { method: POST, path: /*/*/git-upload-pack }
      - { method: GET,  path: /repos/*/*/** }
    anthropic-inference-only:
      - { method: POST, path: /v1/messages }

workspaces:
  playpen:
    roots:
      - { path: /Users/op/src/github.com/firefly-engineering/playpen, mode: readwrite }
    areas:
      landing: { lifetime: persistent }                  # concurrency defaults to exclusive
      cargo-cache: { lifetime: persistent, concurrency: shared }
      target: { lifetime: ephemeral }
    forge: { org: firefly-engineering }
    credentials:
      - host: github.com
        path_prefix: /firefly-engineering/
        minter: gh-app
        delivery: { env: GH_TOKEN }
        endpoints: [github-read-only]
      - host: api.github.com
        path_prefix: /repos/firefly-engineering/
        minter: gh-app
        delivery: { env: GH_TOKEN }
        endpoints: [github-read-only]

  notes:
    roots:
      - path: /Users/op/Documents/notes
        mode: read
        exclude:
          - { path: /Users/op/Documents/notes/private }   # classes default to all

profiles:
  firefly:
    prefixes: [/Users/op/src/github.com/firefly-engineering/]
    workspaces: [playpen, notes]
    toolchain:                       # emitted by playpen.lib.closureRoots on a Nix host
      - { path: /nix/store/…-git-2.51.2 }
      - { path: /nix/store/…-jujutsu-0.33.0 }
      # …one root per store path in the closure
    env:
      fragments: [rust]
      allow: [COLORTERM]
      set:
        CARGO_HOME: !area playpen/cargo-cache
        GIT_AUTHOR_NAME: playpen agent
        GIT_AUTHOR_EMAIL: agent@example.invalid
        GIT_COMMITTER_NAME: playpen agent
        GIT_COMMITTER_EMAIL: agent@example.invalid
    credentials:
      - *anthropic-route
    agent_state:
      claude: { share: [CLAUDE.md, settings.json, skills] }   # CLAUDE.md is imported, not linked
      omp: { share: [] }

  catch-all:
    prefixes: [/]                     # longest prefix wins, so `/` loses to everything
    workspaces: [notes]
    toolchain: []

shims:
  claude:
    target: /opt/homebrew/bin/claude  # stable link; resolved at launch
    kind: claude
    flags: [--dangerously-skip-permissions]
  omp:
    target: /Users/op/.local/bin/omp
    kind: omp
    profile: firefly
```

Field notes:

- `roots[].mode` is `read` or `readwrite`. Toolchain roots are always read and carry no `mode`.
- `areas` is a keyed table. `lifetime` is an internally tagged enum, so `concurrency` exists only
  on the `persistent` variant.
- `forge` is exactly one of `org` or `repos`.
- `flags` is a list of **literal argv tokens**, never a shell string.

### 10.4 The resolved form

The resolved form is **a different object, not a unioned policy**. It speaks enforcement
vocabulary: absolute paths with access classes, a network mode, the constructed environment, the
injected argv and the route table. It contains no workspace names, no lifetimes
and no profiles. **Every entry carries a `from:` provenance string** naming its authored source
(`floor`, `profile:firefly.toolchain[3]`, `workspace:playpen.roots[0].exclude[0]`,
`fragment:github`, `kind:claude`, `run-scratch`). That provenance is the only bridge back to the
policy.

### 10.5 Validation tiers

| Tier | Checks | When |
|---|---|---|
| Parser contract | syntax, unknown fields, types, version, tags, NUL | build time and launch |
| Coherence | cross-table references and constraints ([Appendix A](#appendix-a--code-registry), *coherence*) | build time and launch |
| Existence | roots, exclusions, symlink targets, shim targets, writability, state-directory reachability | launch only |

`playpen check [--policy <f>] [--no-filesystem]` runs the first two tiers, or all three without
`--no-filesystem`. On a Nix host the module runs it in a derivation, so an incoherent policy
fails `home-manager switch`. Existence checks never run at build time: they are facts about this
host at this moment.

---

## 11. Invocation contract

### 11.1 Commands

```
playpen run --profile <name> --agent <kind> [--policy <path>] [--trace-denials <file>] -- <argv…>
playpen explain [<profile>] [--shim <name>] [--cwd <path>] [--policy <path>] [--json]
playpen explain --run <id> [--json]
playpen explain --list [--json]
playpen check [--policy <path>] [--no-filesystem]
```

- `run` takes **`--profile` and `--agent` as mandatory** arguments and performs no context
  resolution of its own. Context resolution belongs to the shim front-end and to `explain`.
- **`--` is a hard wall.** Everything after it is opaque bytes, passed through verbatim.
- On success, `run` writes **nothing** to stdout or stderr. `explain` is a report: it writes
  the report to stdout, and refuses as `run` does, on stderr
  ([#52](https://github.com/firefly-engineering/playpen/issues/52)).

### 11.2 Kind

`--agent <kind>` is always stated and **never inferred** from the binary's name. An
unrecognised kind is a refusal (`refusal.kind.unknown`), because there is nowhere to put what
playpen would need to know about it.

### 11.3 Shims

A **shim** is a **symlink to the playpen binary**, named for its key in `shims`. Invoked as
`claude`, playpen looks up `shims.claude` (an unknown name is `refusal.shim.unknown`) and behaves
as a thin front-end over `run`:

- **Target**: the absolute path in `target`, resolved at launch. playpen never searches `PATH`.
- **Kind**: from `kind`.
- **Profile**: `profile` if the shim pins one. Otherwise the selection chain decides
  ([§11.4](#114-profile-selection)).
- **Injected flags**: `flags`, **prepended** to the caller's argv. playpen never reads them.
- **Re-entry.** If `PLAYPEN_ACTIVE` is set, the shim `exec`s the target directly inside the
  existing boundary, where the phantom, proxy and manifest all still hold. It never attempts to
  re-sandbox (Seatbelt cannot nest anyway).

**Injected flags** can make the agent work or not work, and can never move the boundary
([ADR 0002](adr/0002-playpen-does-not-interpret.md), amended by
[#27](https://github.com/firefly-engineering/playpen/issues/27)). There is no `required` marker
and no contradiction detection: **playpen inspects no argument anywhere.** The honest guarantee
is that a caller who repeats an injected flag overrides it, by last-wins. Across *different*
flags playpen guarantees nothing, because precedence is the agent's own. The injected argv
appears in `explain --json` with provenance, and is never projected inward.

Shim installation: on Nix, per-kind opt-in in the module. Off Nix, the operator's own `ln -s`.
There is no `playpen shim install`.

### 11.4 Profile selection

The chain, first hit wins:

1. **Explicit**: `--profile` (`run`, `explain`), or the shim's pinned `profile`.
2. **`PLAYPEN_PROFILE`** in the environment. This is buzz's channel.
3. **CWD**: the profile whose `prefixes` entry is the **longest** prefix of the CWD. This is
   herdr's channel.
4. **Refuse** (`refusal.selection.no-match`), naming the CWD and environment tried and the
   profiles known.

Rules:

- A profile name that does not exist is `refusal.selection.unknown-profile`.
- An exact tie between two equally long prefixes is `refusal.selection.ambiguous`.
- There is **no implicit default**. A catch-all is an explicit `prefixes: [/]`.

The trace of which step fired, and which steps were skipped, is recorded in the run record and
shown by `explain`.

### 11.5 Working directory

The child starts in the **caller's CWD**. playpen refuses if that CWD is not inside a granted
root (`refusal.cwd.ungranted`).

### 11.6 Process transparency

playpen owes this contract to its callers regardless of backend
([ADR 0002](adr/0002-playpen-does-not-interpret.md)):

- **stdio is inherited untouched.** No PTY, no piping, no interposition.
- **stdout is sacred**: a run never writes to it. Diagnostics go to stderr.
- Catchable **signals are forwarded** to the child, from the moment it exists: a signal sent
  while it is still preparing to `exec` the target reaches it too. The child stays in the
  caller's process group, its job, so a pipeline around playpen keeps the terminal and the
  terminal's own signals reach the child directly. A signal sent to playpen therefore **reaches the agent
  exactly once, where the platform can tell** — which syscall discriminates is a backend matter
  ([§15.4](#154-named-asymmetries)), and the one case no platform can tell is the twelfth named
  residual ([§18](#18-named-residuals)). A job stop stops playpen with the child, by the
  kernel's own rule: in an orphaned process group, where no shell is left to resume a stopped
  job, the kernel discards the stop for playpen as it does for the child, so playpen never
  outlives its shell stopped. A signal the caller ignores stays ignored.
  `SIGKILL`, `SIGSTOP`, `SIGCHLD`, `SIGPIPE` and the synchronous fault signals are not
  forwarded. Blocking a fault signal would make a real fault undefined behaviour, so one sent to
  playpen kills the supervisor; **the agent then dies with it on Linux and survives on macOS**
  ([ADR 0025](adr/0025-the-agent-does-not-outlive-its-supervisor-where-the-kernel-can-say-so.md),
  named asymmetry #6). The same holds for `SIGKILL` of playpen, which no handler could catch.
- playpen **exits with the child's status**, and with `128+N` when the child dies by signal.
- **A status playpen cannot learn is a fault**, which is the third outcome and not a status
  ([ADR 0024](adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md)). playpen
  states on stderr, under a `bug.*` code, that it cannot tell; kills the agent, so the outcome is
  at least deterministic; records it; and dies by `SIGABRT`. A caller reads a signal death as a
  crash, where every ordinary status is one the agent might have returned. It is a defect rather
  than a contract case: nothing a caller does can provoke one.
- There is **no mode flag**. The same behaviour is correct for a TUI, for ACP's JSON-RPC over
  stdio, and for piped or CI use, and playpen does not know which it is in.
- **Path identity.** Every path visible inside is the same absolute path outside. playpen
  confines and never remaps, and this is what keeps ACP's absolute paths, error messages and
  the manifest truthful on both sides.
- **Exit `125`** is reserved for "playpen did not run the agent", and means strictly that: it is
  unreachable once the agent has been `exec`ed. Every backend failure *that refuses the launch* is
  translated into it; a failure after the agent has run is a fault, since `125` would then say the
  agent never ran when it did.

### 11.7 Self-integrity

playpen refuses (`refusal.integrity.writable`, naming the path) if any of these is writable by
the selected profile:

- the resolved policy file, or anything containing it;
- the resolved playpen executable;
- the invoking shim link, or that link's directory.

Each of these runs unconfined on the next launch. The agent binary is deliberately not on the
list: tampering with it lands inside the boundary on the next run.

---

## 12. The kind table

The kind table is playpen-owned and compiled in. It is the **only** place per-agent knowledge
lives. An unrecognised kind is a refusal. A future kind whose binary has no private state-dir
redirect is also a refusal; it never gets an `XDG_CONFIG_HOME` exception, because XDG would
redirect `git`, `gh` and every other XDG-aware tool too.

| | `claude` | `omp` |
|---|---|---|
| State-dir redirect | `CLAUDE_CONFIG_DIR` | `PI_CODING_AGENT_DIR` |
| Suppression table | `CLAUDE_CODE_SANDBOXED=1` | — |
| Presentation adapter | renders the manifest into a file in the agent state directory | same |
| Liveness invocation | trivial no-network invocation, plus one task through the proxy | same |

- **The suppression table only sets entries.** It is cooperative, and that is permitted: if a
  guest ignores it, the guest breaks and does not escape. A guest's nested `sandbox_init`
  returns `EPERM`, so **the failure mode of guest-sandbox collision is a dead agent, never a
  weakened boundary**
  ([ADR 0005](adr/0005-guest-sandboxes-fail-closed-and-playpen-has-no-browser-mode.md)).
- The kind table holds **no flag spellings**. That a flag exists is per-agent knowledge; that
  this host pins it is policy, and lives on the shim.
- The kind table holds **nothing about credentials**. A kind is never a provider.
- **playpen has no browser mode.** It never launches a browser and never sees the browser's
  argv. If a browser distinction is ever wanted, it must take the filesystem form (denying
  `file-map-executable` on the browser binary through an exclusion's `execute` class), never an
  advisory manifest field.

---

## 13. The manifest

**The manifest is a generated projection, and playpen states facts, never instructions**
([ADR 0011](adr/0011-the-manifest-is-a-generated-projection-and-playpen-states-facts-never-instructions.md)).

### 13.1 Form

- It is a JSON file in the run scratch, named by `PLAYPEN_MANIFEST`. It is **always written**,
  even when nothing is provisioned.
- It carries an integer `manifest_version`. The serde type is canonical and the schema is
  generated and CI-gated. Additive changes bump nothing; a removal or retype bumps the version.
- It is derived from the **run record** in the same resolution pass as the capability set:
  the capability set faces outward at the kernel, the manifest inward at the agent.
- It **describes the boundary and never constitutes it.** It sits in writable scratch, so an
  agent can rewrite it. Nothing moves when it does; the agent has lied only to itself.

### 13.2 Content

**Stated:**

- **Layout**, in workspace vocabulary: each workspace's roots and modes, its provisioned areas
  (purpose, lifetime, path), its forge scope, the agent state directory, and the run scratch.
- **That the proxy is not the only way out**, and that a routed destination is authenticated only
  for requests sent through it. There is no egress setting and no host list to state.
- **Each credential route**: its destination (host and prefix), its **delivery variable**, and
  its endpoint rule sets by name together with their rules.
- **Failure interpretation**, per platform in content:
  - the denial errno set: `EPERM` on macOS; `EACCES`, `EXDEV` or `EPERM` on Linux, plus
    `ENOSYS` if a user-notify supervisor has died;
  - that `ENOENT` means absent;
  - the `403` + `X-Playpen-Denied` vocabulary, **stated only where a denial can fire**: when some
    route carries an endpoint rule set;
  - that the boundary is **fixed for the whole session**.

**Omitted:**

- exclusions;
- whether unix-socket credential oracles are reachable ([§6.3](#63-credential-oracles));
- the environment and the injected argv, which the agent already holds;
- the selection trace and all policy provenance;
- any statement about what the agent's children inherit, or about the phantom's inertness.

### 13.3 Presentation

The kind's **presentation adapter** renders the manifest into the idiom that kind reads: the
kind's instruction entry point in the profile's agent state directory (for `claude`,
`$CLAUDE_CONFIG_DIR/CLAUDE.md`).

- That directory is shared by every run of the profile, so the rendered file states **only facts
  stable across those runs**: workspaces, roots and modes, persistent areas, credential routes and
  their delivery variables, endpoint rule sets, and failure interpretation. It states, as a fact,
  that this run's full layout is in the file named by `$PLAYPEN_MANIFEST`.
- It is written to a temporary file and **renamed into place** on every launch. A policy edit made
  during a live run shows up in that run's rendered file at the next launch; `$PLAYPEN_MANIFEST`
  stays true for each run ([ADR 0021](adr/0021-agent-state-belongs-to-the-profile.md)).
- A share entry naming the entry point is composed by reference ([§5.6](#56-agent-state-directory)).

It may state facts about the boundary
playpen built. It may **never** state what the agent should do about them. It is generated from
the manifest's data, never hand-written, and carries no compatibility promise. Prompt fragments
tuned per kind are ruled out permanently.

---

## 14. Diagnostics

**playpen owns the half the kernel cannot know** (which policy produced this boundary), **and
refuses to synthesise the rest**
([ADR 0007](adr/0007-playpen-owns-the-half-the-kernel-cannot-know.md)).

### 14.1 The run record

The run record holds:

- the policy path;
- the resolved profile and the selection trace;
- the capability set;
- the route table, with provenance;
- the unix-socket regime that applied ([§6.3](#63-credential-oracles));
- minted `expires_at` values, never tokens;
- the child's pid, the supervisor's own pid, and timestamps;
- teardown failures.

It is **opened before launch**, because the run that refuses is the one whose record is most
wanted. It lives in playpen's own state directory: outside every workspace, not writable by any
profile, and **unreachable from inside the boundary** — enforced, not merely true of the default
policy: a launch whose grants reach it refuses with `refusal.state.reachable`, because a record
the agent could read is one it could be confused by, and a record carries the resolved profile,
the selection trace, the capability set and the route table. Retention is a bounded ring of recent
runs; it is a debugging aid, not an audit log. The ring holds the **100** most recent **ended**
runs, plus **every live run**. Opening a record removes ended runs beyond those, with the staging
file a crash left behind for one
([#52](https://github.com/firefly-engineering/playpen/issues/52)).

**A live run's record is never evicted**, which is a promise `explain`'s consumers depend on: the
run most worth inspecting is the longest-running one, and shims count as runs, so a long session
would otherwise be certain to evict its own record
([ADR 0028](adr/0028-the-run-record-ring-evicts-history-and-never-a-live-run.md)). The bound is on
*history*, which is what "a debugging aid, not an audit log" protects; live runs are self-limiting
because each one is a process. How liveness is established is an assembly choice
([Appendix C](#appendix-c--assembly-choices), item C11).

A run id is a ULID, so ids sort by the time their run started. The record is one JSON document
per run, carrying its own format version, and holds the refusal's code and sentence when the run
refused. A **fault** is held apart from a refusal, in a field of its own
([ADR 0024](adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md)): `explain`
reads it back out, and a surface whose job is to state facts must not report a crash as a refusal.

### 14.2 `playpen explain`

`playpen explain` has three sections, rendered from one `--json` form:

1. the **selection trace**;
2. the resolved **capability set**: paths, network, environment and injected argv;
3. the resolved **route table**, including endpoint rule sets, with fragment provenance, and the
   unix-socket regime.

`explain` launches nothing. `explain --run <id>` replays a stored record and prints the exact
platform command that pulls that run's denials — every process in its tree, not only the child —
in both forms (`denials`
in `--json`, beside the record's own fields):

- **macOS**: `/usr/bin/log show --start '<launched>' --end '<ended>' --predicate 'sender ==
  "Sandbox" AND eventMessage CONTAINS "playpen-run-<run id>"'`, the window widened to whole
  seconds and given in UTC, and `--end` omitted for a run with no end. The backend attaches the
  run's **denial tag**, `playpen-run-<run id>`, to the profile's default deny, and the kernel logs
  it with every denial in the confined tree, whatever the denied process's pid
  ([#124](https://github.com/firefly-engineering/playpen/issues/124)); the record holds the tag
  (`denial_tag`). A record written before runs were tagged holds none, and its command filters on
  `"(<pid>)"` instead, which matches the child's own denials only. `/usr/bin/log` by path, because
  `log` is a zsh builtin.
- **Linux**: none yet (`null`). The query filters by Landlock domain id, which covers the whole
  tree, and the record does not hold it yet
  ([#98](https://github.com/firefly-engineering/playpen/issues/98)).

A run that never launched has no command. The run id appears on every refusal line, and
`explain --list` lists recent runs, most recent first. A run the ring does not hold, or an id that
is not a run id, is `refusal.run.unknown`
([#52](https://github.com/firefly-engineering/playpen/issues/52)).

### 14.3 The refusal line

A refusal is **one line on stderr**, followed by exit `125`. The line carries the prefix, a
stable code, a human sentence, the offending value, and the run id. `explain` has no run of its
own ([§4.2](#42-launch-sequence)), so its refusal line ends at the offending value:

```
playpen: refusal.area.busy: persistent area playpen/landing is held by another run — run 01J9… (holder 01J8…)
```

Consumers branch on the code, never on the prose.

### 14.4 Codes

There is one namespace with two prefixes:

- `refusal.*`: playpen declined to launch.
- `broker.*`: the broker denied a live agent one request.

The set is **closed and versioned**, and every backend error is translated into a code, never
leaked. The full registry is in [Appendix A](#appendix-a--code-registry).

### 14.5 `--trace-denials`

`--trace-denials <file>` tails the kernel's denial log for this run into a file. It **never
writes to stderr**, and it never weakens the boundary. There is **no permissive-with-logging
mode**.

Where the platform cannot provide a trace, the **flag** is refused before launch, with a code
naming *which* precondition failed. That refusal is scoped to the flag, not to the run.

- **macOS**: there are no preconditions. Denials come from the kernel log
  (`kernel (Sandbox) Sandbox: cat(47295) deny(1) file-read-data …`).
- **Linux**: the trace comes from Landlock audit records in the system journal. Its
  preconditions, in order:

  | Precondition | Probe | Refusal |
  |---|---|---|
  | Landlock ABI ≥ 7 | `landlock_create_ruleset(NULL, 0, VERSION)`. `ENOSYS` and `EOPNOTSUPP` are distinct | `refusal.trace.kernel-abi` / `refusal.trace.landlock-inactive` |
  | the backend passes `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` | a property of the pinned backend | `refusal.trace.backend-no-logging` |
  | the journal is readable | attempt the read; `id -Gn` names the cause | `refusal.trace.no-journal-access` |
  | the channel delivers | **channel self-test** (below) | `refusal.trace.channel-silent` / `refusal.trace.channel-lossy` |

  `audit_enabled` is not probed, because it is unreadable without `CAP_AUDIT_CONTROL`. The
  channel self-test **observes** instead of inferring
  ([ADR 0007](adr/0007-playpen-owns-the-half-the-kernel-cannot-know.md), amended by
  [#32](https://github.com/firefly-engineering/playpen/issues/32) and
  [#34](https://github.com/firefly-engineering/playpen/issues/34)):

  - It provokes a known denial in a throwaway Landlock domain and **polls** the journal for the
    record, with a **1 s** budget. It never relies on `sd_journal_wait()` alone.
  - It passes **only on `_TRANSPORT=audit`**. A record arriving via `_TRANSPORT=kernel` came
    through the shared print rate limit, so that path is refused as
    `refusal.trace.channel-lossy`. No record at all is `refusal.trace.channel-silent`. Both
    print the remedy `systemctl enable systemd-journald-audit.socket`.
  - It **brackets the run**. It re-runs after the agent exits, and if it fails, the trace is
    marked **unverified** rather than presented as complete.
  - The self-test's own record is identified by its Landlock domain id and unique path, filtered
    with a key=value tokenizer, never a pattern. The self-test is never cached.

  Upstream nono passes flags `0` and caps its ABI probe at V6, so with it this refusal would
  always fire. The pinned fork passes the flag and probes further ([ADR 0022](adr/0022-playpen-pins-a-maintained-fork-of-nono.md)), so
  `refusal.trace.backend-no-logging` fires only for a pin that lacks it.

---

## 15. Host mechanism backends

### 15.1 The backend

**nono is the mechanism backend, reached as a library, behind a playpen-owned seam**
([ADR 0003](adr/0003-nono-is-the-mechanism-backend.md)). playpen is **Rust**.

- The dependency is the `nono` crate (`sandbox` and `capability` modules) and the `nono-proxy`
  crate (`ProxyConfig`, `server::start`), both **pinned exactly** to one revision of the
  maintained fork **`firefly-engineering/nono`**, as a
  Cargo `git` dependency with a fixed `rev`, never a branch ([ADR 0022](adr/0022-playpen-pins-a-maintained-fork-of-nono.md)). The fork carries playpen's
  changes on a `playpen` branch, rebased onto upstream tags (cut from `v0.79.0`). Upstreaming is
  optional and later. `nono-cli` is structurally out of reach: its
  profiles, groups, always-merged default, forced denies and `command_policies` never enter the
  picture.
- playpen owns the **capability type**, the only thing a backend receives. playpen also owns the
  **route table**, translated to `nono-proxy` at the boundary. That makes `nono-proxy`'s OAuth
  capture, SPIFFE, JWT phantoms and its persistent 4096-entry, 90-day phantom store
  unreachable by construction.
- **A backend is defined by the enforcement tests it passes** ([§17](#17-the-enforcement-suite)).
  A version bump is a PR that stays red until the suite says otherwise; compiling is not the
  gate.
- **A capability the policy did not grant is not granted by the backend**
  ([ADR 0029](adr/0029-the-backend-grants-only-what-the-policy-asked-for.md)). A rule a backend
  emits on its own initiative — a blanket exec, fork, socket or Mach-service allowance — is a
  violation of this seam, not a property of the platform. `N-nothing-granted` asserts it at its
  sharpest: under an empty capability set the canary cannot run.
- **playpen refuses on its own authority.** It requests process scoping explicitly
  (`SignalMode::AllowSameSandbox`, never the quietly degrading default), so nono's fail-closed path
  fires. It also probes the ABI itself beforehand, so the refusal survives a change in nono's
  defaults. The probe is the kernel's own version query, `landlock_create_ruleset(NULL, 0,
  LANDLOCK_CREATE_RULESET_VERSION)`, not nono's, which stops at the highest ABI nono knows. What
  each ABI offers is read from the `landlock` crate, pinned exactly to the version nono resolves.
  nono has no fail-closed mode for abstract-socket scoping, so for that half the probe is the only
  refusal. Seatbelt has no versions, so on macOS what the mechanism offers is fixed.
- **Every profile requires process scoping** (signals and abstract unix sockets confined to the
  sandbox: Landlock ABI 6). The policy cannot yet require any further capability. A missing one
  is `refusal.mechanism.unavailable`, naming it.
- Every nono denial is an errno, never `SIGSYS`: the crate defines no kill action.

The network mode is `AllowAll` on both platforms
([ADR 0020](adr/0020-playpen-claims-credential-confinement-only.md)), so the dependency surface
stays `sandbox` + `capability`. `ProxyOnly` and its seccomp proxy filter are never used. nono's
sandbox-extension rules stay off.

**The fork's changes** are a deliberate set; each needs a demonstrated need and a suite row:

1. macOS: unix sockets default-deny under `AllowAll`, via the explicit-grant path (`N-unix-socket`).
2. Linux: the ABI probe extends to V9, with pathname-socket `connect()` gated by `FS_RESOLVE_UNIX`
   (`N-unix-socket` on a kernel ≥ 7.1).
3. Linux: `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` passed where ABI 7 is available
   (`R-trace-denials`).
4. macOS: exec is gated on the read-bearing grants, the same path filters as
   `file-map-executable`, rather than allowed unconditionally
   ([ADR 0029](adr/0029-the-backend-grants-only-what-the-policy-asked-for.md);
   `N-nothing-granted`).
5. macOS: an optional message on the default deny, `(deny default (with message "…"))`, which
   the kernel logs with every denial in the sandboxed tree, so a run's denials are found by its
   tag ([#124](https://github.com/firefly-engineering/playpen/issues/124); `P-denial-tree`).

Every rebase of the fork, and every new revision, is a playpen PR that stays red until the
enforcement suite passes.

### 15.2 Capability matrix

Measured on macOS 26.5 and source-read for Linux
([`research/mechanism-capability-matrix.md`](../research/mechanism-capability-matrix.md)):

| Capability | macOS: Seatbelt (`sandbox_init` via FFI) | Linux: Landlock + seccomp |
|---|---|---|
| Confine an arbitrary launched binary, unprivileged | yes: no root, signing or entitlement | yes: `NO_NEW_PRIVS` only |
| Filesystem default-deny with allow-listed roots | yes | yes (rights-based) |
| Read / write / execute distinction | yes | yes |
| Survives `exec`, grandchildren, orphaning | yes; irrevocable | yes; irrevocable |
| Path canonicalization sound (symlink, hardlink, traversal, firmlink) | yes, measured | yes |
| Deny network wholesale | yes | TCP via Landlock ABI ≥ 4; UDP ungated below ABI 10, covered by seccomp's TCP-only baseline |
| Per-host egress | no | no (Landlock network rules see ports, never addresses) |
| Block Keychain / agent sockets | yes (Mach allow-list; unix sockets via the fork) | abstract sockets: ABI 6; pathname sockets: ABI 9 (via the fork) |
| Nestable | **no**: a nested `sandbox_init` returns `EPERM` | stacks (Landlock layers intersect) |
| Denial errno | `EPERM` | `EACCES`, `EXDEV`, `EPERM` (+ `ENOSYS` if a user-notify supervisor dies) |
| Out-of-band denial log | kernel log, free | Landlock audit: ABI 7 (6.15+), with preconditions ([§14.5](#145---trace-denials)) |
| Policy size limit | **65,535 compiled bytes** (~1013 `subpath` rules) | none practical |
| Deprecated | yes, since 2017, with **no supported successor** | no |

macOS has no alternative mechanism. App Sandbox cannot be imposed on a launched binary.
Endpoint Security has no network AUTH event. Network Extension is gated by Apple approval and
applies system-wide.

### 15.3 The compiled-profile ceiling

macOS caps the compiled profile at 65,535 bytes. The limit is reported in `errorbuf` with
**`errno` untouched**, so playpen reads `errorbuf`. Exceeding it is `refusal.budget.exceeded`,
naming the ceiling, the resolved size and the largest-contributing root. On a Nix host the
module checks the closure's size at build time, and the launch-time refusal is the backstop.

### 15.4 Named asymmetries

A **named asymmetry** is a place where the two platforms are not equals, written down rather
than absorbed. Each has a **suite row**, in the enforcement suite or the transparency suite
depending on what it is a property of: the enforcement suite's verbs are about the boundary —
read, create, list, inherited fd, Mach lookup, signal, connect, refuse — so an asymmetry in
process transparency belongs in the transparency suite instead. A `—` in that column means the
asymmetry is *unassertable*, never that its row lives elsewhere.

| # | Asymmetry | Favours | Suite row |
|---|---|---|---|
| 1 | unix-socket credential oracles: denied on every macOS version, on Linux only from Landlock ABI 9 | macOS | `N-unix-socket` (skipped by name on Linux below ABI 9) |
| 2 | the mechanism's deprecation clock | Linux | — |
| 3 | the compiled-profile ceiling | Linux | `R-ceiling` (`n/a` on Linux) |
| 4 | denial visibility: zero preconditions on macOS, four on Linux. Partly permanent: macOS's channel is certifiable *a priori*, Linux's only *a posteriori* | macOS | `R-trace-denials` (`n/a` on macOS); `P-denial-tree` (`n/a` on Linux) |
| 5 | user namespaces (Chromium's nested userns) are Linux's | — | `P-unshare` (`n/a` on macOS) |
| 6 | the parent-death signal that stops an agent outliving its supervisor. Permanent: after `exec` only a kernel mechanism can do this, and macOS has none. Narrows [§18](#18-named-residuals) item 4 to macOS | Linux | `the_agent_does_not_outlive_a_killed_supervisor`, transparency (`n/a` on macOS) |
| 7 | signal **origin** is readable: `sigwaitinfo`'s `si_code` is `SI_KERNEL` for a tty keypress and `SI_USER` for a `kill`, where macOS reports `0` for both with `si_pid` set in both. Two live consequences, both macOS-only: a direct `kill -INT` to a foreground playpen is silently dropped, and `SIGTTIN`/`SIGTTOU` reach the agent twice, because the foreground proxy macOS falls back to is *inverted* for exactly those two — a process receiving one is by definition in a background group | Linux | `a_signal_sent_straight_to_a_foreground_playpen_is_forwarded`, transparency (`n/a` on macOS) |
| 8 | exclusions: Seatbelt subtracts a subpath from a grant with a deny rule, and Landlock, being allow-only and hierarchical, cannot ([#127](https://github.com/firefly-engineering/playpen/issues/127)), so an exclusion refuses on Linux | macOS | `N-exclusion` (`n/a` on Linux) |

Linux's lack of a mechanism-native Keychain is recorded through `N-keychain` being `n/a` on
Linux, and macOS's lack of abstract unix sockets through `N-abstract-socket` being `n/a` on
macOS.

---

## 16. Distribution

### 16.1 Nix

playpen ships a flake ([ADR 0015](adr/0015-the-nix-module-is-a-projection-and-home-manager-is-the-primary-tier.md)):

- The **home-manager module is the primary tier**. NixOS and nix-darwin modules are a secondary
  tier, for hosts with no per-user Nix.
- The module's option tree **mirrors the policy schema one-to-one**, and its emitter is a pure
  projection. **No module-shipped defaults** exist in any tier.
- Knowledge lives in `playpen.lib` helpers that return **values the operator splices in**.
  `playpen.lib.closureRoots` takes a package list and returns root entries.
- The policy is emitted as `xdg.configFile."playpen/policy.yaml"`, so the policy and its closure
  are in the same generation, roll back together, and stay GC-rooted together. The module never
  reads `osConfig`.
- Parse and coherence checks run at build time via `playpen check --no-filesystem`, and the
  closure's size is checked against the ceiling.
- Shim installation is **opt-in per kind**.
- The flake's `floor` package is the **dedicated floor** for a non-FHS host
  ([§8.2](#82-the-floor)): the OS's own command binaries, and the closure they need as a
  `closureInfo` store-path list. The NixOS module installs it inside the system generation, where
  it is the default without any variable set, so the floor rolls back with the system that built
  it. The list is read as plain text and never recomputed at launch: enumerating the system
  closure costs a `nix-store` query and some 3300 roots on the reference host, and the self-test's
  verdict is never cached, so that price would fall on every launch.
- playpen has **no runtime Nix dependency**. The emitted file is indistinguishable from a
  hand-written one, and a dedicated floor is a directory and a text file.

### 16.2 Homebrew

For a host without Nix ([ADR 0019](adr/0019-a-homebrew-toolchain-is-a-keg-list-and-a-shim-is-the-playpen-binary.md)):

- The single channel is a **formula in a project tap**. `sandbox_init()` needs no entitlement,
  so signing matters only to Gatekeeper, which a formula does not trigger. No notarized artifact
  ships in v1. `cargo install` is a development path only.
- The toolchain is a **keg list** ([§8.3](#83-toolchain)).
- **No Homebrew fragment ships.**
- Shims are placed with the operator's `ln -s`.
- `playpen check` with existence checks stands in for the build-time gate.

**Non-Nix Linux:** distro packages live under OS-owned paths the floor already grants.
linuxbrew and `~/.local` follow the keg-list or coarse-root shapes.

---

## 17. The enforcement suite

**The suite is the backend's definition, so an assertion that can pass vacuously is a defect**
([ADR 0016](adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md)).

### 17.1 Form

- **Rows are data**, `{id, class, platform, fixture, action, expected, from}`, and the action is a
  **closed enum**. Adding an instance of an existing check means adding rows; adding a new kind
  of check means adding one enum variant.
- **Three classes:**
  - **negative**: from inside, the action must fail with a denial;
  - **positive**: from inside, the action must succeed. A positive is admissible only if the
    regression it catches is *silent*;
  - **refusal**: from outside, with no sandbox at all, the assertion is exit `125` plus a `code`.
- **Every assertion is two-part.** It first establishes the condition holds *outside*, then
  asserts the boundary's behaviour *inside*. A negative whose target is absent outside is a
  setup failure. The fixture **creates a decoy** where the host lacks a real target. `ENOENT`
  from inside is a **failed** negative.
- **A decoy the fixture writes outside a temp directory is recognisable by its own content and
  is reclaimed at fixture time**, so a run killed before its teardown costs one stale decoy and
  never a permanent one. A file is a decoy only when its entire content is the decoy line; a
  directory only when it holds nothing but its decoy marker, or, for one made only to hold other
  decoys, nothing at all. Where such a write is impossible, the row is skipped by name, never
  moved somewhere weaker.
- **Three outcomes**: *runs*; *`n/a` by platform* (a named asymmetry already on the ledger);
  *skipped* (a precondition missing on this host, always **named**, never inferred).
- **Actors.** The bare-floor canary uses **OS-owned binaries only**. Everything else uses the
  shipped `playpen-probe`, whose own root is a stated perturbation. Every negative it makes reads
  "unreachable *even with* the probe's root present".
- **Batching.** There is one confined launch per **policy fixture**, loaded via `--policy`, with
  verdicts written as JSON on the probe's stdout. The exit code carries one bit: *the probe ran*
  or *the probe broke*.
- **A single-platform assertion costs a named asymmetry.** A `both` assertion that proves
  inexpressible on one platform is a design bug to escalate, never a skip. The debt is owed
  whichever suite the assertion lives in: an asymmetry in process transparency is asserted in the
  transparency suite, since this suite's verbs are about the boundary
  ([§15.4](#154-named-asymmetries)).
- **Gates.** CI may be green with skips. A **release requires the full set green on a reference
  host of each platform.** Runner labels are **pinned**, never `-latest`: use `ubuntu-24.04`,
  and a pinned `macos-*`.

### 17.2 Rows

Row ids are provisional. The implementation owns the final ids.

| Id | Class | Asserts | Platform |
|---|---|---|---|
| `N-ssh-key` | negative | `~/.ssh/id_*` unreadable (decoy) | both; skip `skip.host.home-not-writable` |
| `N-ssh-config` | negative | `~/.ssh/config` unreadable (decoy) | both; skip `skip.host.home-not-writable` |
| `N-aws` | negative | `~/.aws` unreadable (decoy) | both; skip `skip.host.home-not-writable` |
| `N-npmrc` | negative | `~/.npmrc` unreadable (decoy) | both; skip `skip.host.home-not-writable` |
| `N-symlink` | negative | the above unreadable through a resolved symlink | both |
| `N-store-stale` | negative | a store path outside the declared closure (decoy `…-home-manager-files/.ssh/config`) unreachable | both; skip `skip.host.no-nix` |
| `N-keg-decoy` | negative | a manufactured decoy keg beside a granted keg is denied | both; skip `skip.host.no-homebrew` |
| `N-exclusion` | negative | a decoy in a subdirectory excluded from a granted root is denied, while a file the root still grants is readable | macOS (`n/a` Linux) |
| `N-hosttemp` | negative | the host temp is unreachable | both |
| `N-keychain` | negative | Keychain Mach services unreachable | macOS (`n/a` Linux) |
| `N-signal` | negative | signal 0 to a decoy process started outside is denied: process scoping is enforced, not only requested | both |
| `N-abstract-socket` | negative | connecting to a decoy abstract unix socket listening outside is denied | Linux (`n/a` macOS) |
| `N-fd` | negative | an inherited credential fd reads as `EBADF` | both |
| `N-unix-socket` | negative | a decoy unix socket listening outside every grant is refused | both; skip `skip.host.landlock-below-abi-9` |
| `N-errno-law` | negative | a denial errno is in the platform set, never `ENOENT` | both |
| `N-nothing-granted` | negative | under an **empty** capability set — not even the floor — the canary's `exec` is denied with an errno in the platform set, never `ENOENT`. Judged by the kernel's errno, never by a refusal code | both |
| `N-endpoint` | negative | a non-matching request to a credentialed host gets `403` + `broker.endpoint.denied` | both |
| `N-endpoint-no-leg` | negative | for that request, **no upstream leg occurred** (instrumented upstream) | both |
| `P-canary` | positive | a dynamically linked OS binary exits 0 under the bare floor | both |
| `P-denial-tree` | positive | a denial by a process the confined child **forked** is returned by the command `explain --run` prints; checked outside first against the log, found by the decoy's path. A log slower than a deadline is a setup failure | macOS (`n/a` Linux) |
| `P-unshare` | positive | the **nested** `CLONE_NEWUSER` → `CLONE_NEWPID\|CLONE_NEWNET` sequence succeeds inside; checked outside first, else `skip.host.userns-restricted` | Linux (`n/a` macOS) |
| `P-open-bypass` | positive | a request that bypasses the proxy arrives **unauthenticated** | both |
| `P-manifest` | positive | "the manifest is true": every stated route authenticates through the proxy, every path is accessible at its stated mode, and nothing outside them is; skip `skip.host.no-egress` | both |
| `P-argv` | positive | the injected argv in `explain --json` matches the argv the child received | both |
| `P-endpoint` | positive | a matching request reaches upstream authenticated, with the phantom stripped and the secret injected | both |
| `R-missing-cap` | refusal | a missing mechanism capability → `125` + code. No host lacks one, so the launch runs with its probe replaced by one offering nothing | both |
| `R-incoherent-ws` | refusal | an incoherent workspace → `125` + code | both |
| `R-ceiling` | refusal | a policy over the compiled-profile ceiling → `125` + `refusal.budget.exceeded`; asserts the code, never a path count | macOS (`n/a` Linux) |
| `R-record` | refusal | a run record exists **after** a refusal | both |
| `R-state-reachable` | refusal | a root that is an ancestor of playpen's state directory → `125` + `refusal.state.reachable`, naming both paths. The state directory is **synthetic**, not the real `$HOME`: the check compares resolved paths and does not care whose home it is | both |
| `R-integrity` | refusal | a policy file inside the profile's own read-write root → `125` + `refusal.integrity.writable` | both |
| `R-code-coverage` | refusal | every `refusal.*` code in the registry has ≥ 1 producing row | both |
| `R-policy-span` | refusal | a policy refusal names file, line and column, including through a merge key | both |
| `R-no-filesystem` | refusal | `check --no-filesystem` performs no existence check | both |
| `R-trace-denials` | refusal | `--trace-denials` refuses naming the missing precondition, including `channel-lossy`; a failed post-run self-test marks the trace unverified | Linux (`n/a` macOS) |

**Liveness** is a second suite with the same runner and fixture format. It runs `L-<kind>` per
kind: launch the real binary confined, exit 0 on a trivial no-network invocation, plus one task
through the proxy. It **gates only an agent-version or kind-table change**, never a playpen
change, and it is skipped on hosted CI by policy (`skip.suite.liveness-not-on-ci`).

---

## 18. Named residuals

A **named residual** is a reachable surface playpen consciously declines to close. It is written
down rather than inherited silently.

It is not the same ledger as a **named asymmetry** ([§15.4](#154-named-asymmetries)), and the
distinction is load-bearing: an asymmetry is open on *one* platform and closable in principle,
where a residual is open wherever it is open and closed nowhere. Filing one as the other loses
exactly the information both ledgers exist to carry.

1. **ACP client-side execution.** An ACP client outside the boundary may execute file reads and
   terminal commands on the confined agent's behalf. The client is owner-controlled.
2. **Network-reachable credential sources.** A cloud metadata endpoint, or a credential service
   on host loopback, hands out credentials to whatever reaches its address, and playpen confines
   no network. The layer that exposes one owns protecting it. The phantom keeps the proxy's own
   port on loopback from being a leak.
3. **A browser without its own renderer isolation** runs at full workspace privilege. The
   operator's lever is workspace scoping: a buzz-class profile gets a thin workspace.
4. **An orphaned agent holding a released area — on macOS only.** `SIGKILL` the supervisor
   without its process group and the agent keeps writing an area whose lock has released. It has
   lost all credentials. On Linux the agent dies with its supervisor by every route, `SIGKILL`
   included (named asymmetry #6), so only macOS can reach the live orphan; with the agent dead the
   lock's released state is accurate rather than a lie. What survives on **both** platforms is the
   *lock* half of [ADR 0010](adr/0010-concurrency-is-a-property-of-a-provisioned-area.md)'s
   residual: for the child to hold the lock it would need an inherited descriptor, which
   [ADR 0006](adr/0006-the-floor-is-built-in-and-the-toolchain-is-a-coarse-root.md) forbids. A
   supervisor that has merely lost track of the agent's status kills it on either platform
   ([§11.6](#116-process-transparency)), so that route reaches no orphan at all.
5. **The sequential cross-profile channel** a `persistent` area opens. The same channel exists
   through any brought root granted to two profiles.
6. **git push *discovery* succeeds under a read-only rule set.**
   `GET …/info/refs?service=git-receive-pack` matches, because the query string is never matched.
7. **An operator-written refreshing minter racing a host-level agent** over a single-use login.
8. **A Linux audit exclude rule** emptying the denial trace, with rules playpen cannot read.
9. **A profile-writable directory earlier on the host's `PATH`** than the shim can shadow it for
   the next host-side invocation. Keeping `PATH` order safe is the operator's responsibility.
10. **Unix-socket credential oracles on Linux below Landlock ABI 9.** `ssh-agent`, `gpg-agent` and
    kindred sockets are reachable if their path is known. Recorded outward only
    ([§6.3](#63-credential-oracles)); the residual closes as kernels move.
11. **The run scratch and `ephemeral` areas a fault leaves on disk.** A run that ends by `SIGABRT`
    ([§11.6](#116-process-transparency)) runs no teardown. The credential half needs none: the
    proxy is hosted in the supervisor rather than detached, so process death *is* the credential
    teardown ([ADR 0013](adr/0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md)).
    The filesystem half is bounded, inspectable litter, and removing it would mean running the
    most failure-prone code in playpen on a process that has just declared itself broken — a
    teardown that hangs converts a crash into a hang.
12. **A group-directed signal reaches the agent twice**, and this one is **unclosable** rather
    than unclosed. `kill -TERM -<job>` delivers one copy to the agent directly, and playpen
    forwards a second. A receiver learns a signal's *sender* and never its *target*, so playpen
    cannot know the agent already holds a copy: a process-directed `kill` and a group-directed one
    are byte-identical in `siginfo_t`. Comparing the sender's group does not rescue it either — a
    sibling inside the job sending a direct `kill` must be forwarded, a stranger outside it
    sending a group kill must not, and either sender can be inside or outside. A doubled `SIGINT`
    is the one that bites: some agents exit on a second Ctrl-C. Recorded with its reason because
    it is the entry most likely to be mistaken for a bug, and pinned by a test that asserts the
    doubling
    ([ADR 0026](adr/0026-signal-origin-is-readable-on-linux-and-the-kill-target-is-readable-nowhere.md)).

---

## 19. Out of scope

- **VM lifecycle, reset and resource ceilings.** devbox owns these. It is the layer under
  playpen, not an implementation of it.
- **Model spend caps.** These are a property of credential minting, not of the sandbox.
- **Per-tool permissioning.** This is the agent's own job.
- **Defending against a compromised herdr or buzz binary.** Consumers are trusted to invoke,
  never to decide policy.
- **Multi-user tenancy** on a single host.
- **Logging an agent in from inside the sandbox.** This is permanent. The operator logs in
  natively outside the boundary ([§7.5](#75-subscription-logins)).
- **ACP's client-side execution capabilities.** Stripping them would make playpen a JSON-RPC
  proxy. This is named as residual 1.
- **Whether reusing a refresh token revokes the whole login.** This matters only to a minter
  that refreshes, and playpen ships none.

**Traffic confinement**: what the agent may reach on the network, including an egress allow-list,
a `none` setting, a kernel pin to the proxy, and a sandbox with no resolver. Retired by
[ADR 0020](adr/0020-playpen-claims-credential-confinement-only.md): the operator's concern is the
means of using credentialed resources, not where traffic goes.

Ruled out permanently as *shapes*, though inside the domain:

- a permissive-with-logging mode;
- runtime capability expansion and `Approve`-tier rules;
- prompt fragments tuned per kind, and an advisory browser field in the manifest;
- endpoint rules on uncredentialed hosts, and query-string matching;
- `XDG_CONFIG_HOME` as a state-dir redirect;
- a `PLAYPEN_POLICY` variable, a policy directory, and multi-document policy.

---

## 20. Handed-off questions

These are not spec decisions. Each is a question that no current workload forces, or a fact to
establish during implementation. The wayfinding map closed with them handed off here.

**Open design questions** — to decide when a real workload demands one:

- **Non-env credential delivery.** This is for a workload that reads only `~/.netrc` or its own
  config file. The three candidate shapes (a written config file, an injected `PATH` helper, a
  mounted `~/.netrc`) each pull playpen toward knowing file formats. `delivery` is a field, so
  adding a transport will not reopen the route table.
- **Cross-shape injection.** Whether a credential route can carry an injection shape, so that a
  harness configured for one credential kind can be served another through the proxy
  ([§7.3](#73-session-phantom)).

**Needs a confined run or CI:**

- Whether Seatbelt functions inside a Virtualization.framework guest, which affects hosted macOS
  runners. A single 15-line `macos-15` job settles it.
- Whether the hosted `ubuntu-24.04` runner boots with auditing off and the journald audit socket
  disabled. If so, `R-trace-denials` needs a setup step.
- Whether the denial count in `status=deallocated denials=N` can be reconciled against collected
  records to detect trace loss.

**Safe on a real account:**

- Whether a `claude setup-token` grant is independent of the interactive login: mint once, then
  confirm the desktop login survives.
- Whether an access token survives another process's refresh.

**Covered by the liveness probe:**

- That `claude` loads `$CLAUDE_CONFIG_DIR/CLAUDE.md` and follows an absolute `@` import; and which
  instruction entry point `omp` reads, and whether it has an import mechanism
  ([§5.6](#56-agent-state-directory)).

**In the nono fork** ([ADR 0022](adr/0022-playpen-pins-a-maintained-fork-of-nono.md)):

- Writing the three changes listed in [§15.1](#151-the-backend), each with its suite row.
- Upstreaming them is optional, once playpen works.

---

## Appendix A — code registry

The registry is closed and versioned. **Codes marked † were minted by a ticket; the rest are
named here** from refusals the record describes in prose ([Appendix C](#appendix-c--assembly-choices),
item C1). "Tier" is when the refusal can fire ([§10.5](#105-validation-tiers)).

One namespace, **three prefixes**: `refusal.*` for a refusal, `broker.*` for a broker denial, and
`bug.*` for a fault ([§11.6](#116-process-transparency)). Neither of the last two has a tier: a
broker denial fires against a live agent, and a fault at no validation point at all. Only
`refusal.*` is bound by `R-code-coverage`'s requirement that every code have a producing row
([§17.2](#172-rows)) — a fault cannot be provoked by one, which is why it is a separate prefix
rather than a `refusal.*` code needing an exemption from the gate.

### Policy

| Code | Tier | Fires when |
|---|---|---|
| `refusal.policy.not-found` | launch | no policy on the search path |
| `refusal.policy.unreadable` † | launch | the policy is present but cannot be read: permissions, or a directory where the file should be |
| `refusal.policy.ambiguous-location` | launch | `policy.yaml` and `policy.json` at one location |
| `refusal.policy.syntax` | parser | malformed YAML/JSON, or a multi-document stream |
| `refusal.policy.unknown-field` | parser | an undeclared key |
| `refusal.policy.version` | parser | an unrecognised `version` |
| `refusal.policy.tag` | parser | an explicit YAML tag other than `!area` |
| `refusal.policy.type` | parser | a type mismatch, an invalid enum variant, or a NUL in a value |

### Coherence

| Code | Tier | Fires when |
|---|---|---|
| `refusal.workspace.unknown` | coherence | a profile names an undeclared workspace |
| `refusal.fragment.unknown` | coherence | a reference to an undeclared environment fragment |
| `refusal.minter.unknown` | coherence | a route names an undeclared minter |
| `refusal.area.unknown` | coherence | an `!area` reference dangles |
| `refusal.workspace.worktree-on-read-root` | coherence | a worktree area while every source root is `read` |
| `refusal.route.ambiguous` | coherence | two routes on one host, neither prefix extending the other |
| `refusal.endpoint.unknown` † | coherence | a reference to an undeclared endpoint rule set |
| `refusal.endpoint.unsatisfiable` † | coherence | a rule set that no path under the route's prefix can match |
| `refusal.env.reserved` † | coherence | a policy entry collides with a reserved name ([§9.2](#92-set-entries)) |
| `refusal.env.forbidden` | coherence | `SSH_AUTH_SOCK` in `env.allow`, an env fragment, or `set:` |
| `refusal.root.relative` † | coherence | a brought or toolchain root's path is not absolute |

### Invocation and selection

| Code | Tier | Fires when |
|---|---|---|
| `refusal.invocation.usage` † | launch | the command line does not parse: a missing `--profile` or `--agent`, no `--` wall, an unknown subcommand |
| `refusal.shim.unknown` | launch | `argv[0]` is not a key of `shims` |
| `refusal.kind.unknown` | launch | an unrecognised kind |
| `refusal.selection.unknown-profile` | launch | an explicit or `PLAYPEN_PROFILE` profile is not in the policy |
| `refusal.selection.no-match` | launch | no step of the chain selected a profile |
| `refusal.selection.ambiguous` | launch | two equally long matching prefixes |
| `refusal.run.unknown` † | explain | `explain --run` names a run the ring does not hold, or no run id at all |

### Host state

| Code | Tier | Fires when |
|---|---|---|
| `refusal.root.missing` | existence | a brought root, toolchain root, symlink target or shim target is absent |
| `refusal.exclusion.missing` | existence | an exclusion's path is absent |
| `refusal.integrity.writable` | existence | the policy, the playpen executable, the shim link or its directory is profile-writable |
| `refusal.state.reachable` † | existence | a granted path reaches playpen's state directory, in either containment direction, naming both paths and the mode. Checked per grant rather than per declaring construct, so it covers the floor and brought roots today and toolchain roots and exclusions as those arrive; exempt are only subtrees playpen *derived from* that directory ([ADR 0027](adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md)) |
| `refusal.cwd.ungranted` | existence | the CWD is not inside a granted root |
| `refusal.area.busy` † | launch | an `exclusive` area is held; names the holding run id |
| `refusal.state.collision` | coherence | a share entry names the kind's instruction entry point and the kind has no import mechanism |
| `refusal.state.io` | launch | playpen cannot create its own state: run scratch, an area, the manifest, the record or the lock file |
| `refusal.process.fork` † | launch | the supervisor could not fork the child |
| `refusal.process.wait` † | launch | playpen could not wait for the floor self-test's throwaway canary, which is its one caller: a wait that fails after the agent has been `exec`ed is a fault, not a refusal ([ADR 0024](adr/0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md)) |

### Mechanism

| Code | Tier | Fires when |
|---|---|---|
| `refusal.mechanism.unavailable` | launch | a capability the resolved profile requires is missing (names it) |
| `refusal.floor.unavailable` | launch | this host has no floor to test: no dedicated floor and no FHS canary, or a dedicated floor whose declared closure is missing or empty |
| `refusal.floor.self-test` | launch | the floor canary failed |
| `refusal.budget.exceeded` | launch | the compiled profile exceeds the backend budget |
| `refusal.target.exec` † | launch | the target could not be `exec`ed inside the boundary: absent, or not covered by policy ([Appendix C](#appendix-c--assembly-choices), item C9) |

### Credentials and proxy

| Code | Tier | Fires when |
|---|---|---|
| `refusal.minter.failed` † (family) | launch | a minter exited non-zero |
| `refusal.minter.malformed` † (family) | launch | a minter's stdout is not `{token, expires_at}` |
| `refusal.minter.timeout` † (family) | launch | a minter did not exit within its `timeout` |
| `refusal.proxy.bind` † | launch | the listener could not bind |
| `refusal.proxy.ca` | launch | the interception CA could not be created or written |

### Denial trace

These fire before launch and refuse the `--trace-denials` flag, not the run.

| Code | Tier | Fires when |
|---|---|---|
| `refusal.trace.kernel-abi` † | launch | Landlock ABI < 7 |
| `refusal.trace.landlock-inactive` † | launch | Landlock compiled in but disabled |
| `refusal.trace.backend-no-logging` † | launch | the backend does not pass `LOG_NEW_EXEC` |
| `refusal.trace.no-journal-access` † | launch | the journal is unreadable by the invoking user |
| `refusal.trace.channel-silent` † | launch | the self-test's record never appeared |
| `refusal.trace.channel-lossy` † | launch | the record arrived only via `_TRANSPORT=kernel` |

### Broker

| Code | Fires when |
|---|---|
| `broker.endpoint.denied` † | no endpoint rule matched; no upstream leg occurred. Minted as `egress.endpoint.denied` and renamed by ADR 0020 |

### Faults

Not outcomes, and not provokable: each says playpen is broken, and the run ends by `SIGABRT`
rather than with a status ([§11.6](#116-process-transparency)). A code rather than a bare message
because §14.3's rule holds here too — a caller meeting a crash should be able to branch on *why*.

| Code | Fires when |
|---|---|
| `bug.status.no-child` † | the supervisor's wait for the agent failed with `ECHILD`: something reaped it behind playpen's back |
| `bug.status.unreadable` † | that wait failed for any other reason, which means the call itself was wrong |

**Deliberately absent:** `refusal.flag.*` was never minted, and `required` was dropped
([#27](https://github.com/firefly-engineering/playpen/issues/27)). There is no
`refusal.env.*` value-validation code ([#31](https://github.com/firefly-engineering/playpen/issues/31)),
and no catch-all backend code: a backend failure that maps to no listed code is a playpen bug.

---

## Appendix B — reconciliations made in assembly

Places where the decided record disagreed with itself. In each case the spec states the
reconciled form. **Reviewed and accepted** in [#9](https://github.com/firefly-engineering/playpen/issues/9).

- **B1. `NODE_USE_ENV_PROXY=1` is a set entry.**
  [#24](https://github.com/firefly-engineering/playpen/issues/24) decided it is mandatory, and
  the map records that. It never reached ADR 0012, ADR 0013 or `CONTEXT.md`. **Landed** with
  [ADR 0020](adr/0020-playpen-claims-credential-confinement-only.md)'s amendment to ADR 0012 and the
  set-entry glossary entry.
- **B2. The `403` body is self-describing.**
  [#24](https://github.com/firefly-engineering/playpen/issues/24) found that Bun's `fetch`
  surfaces the proxy's refusal as an ordinary `Response`, so a status code alone is ambiguous.
  ADR 0007 specified the status and header only. **Landed** in ADR 0007 with ADR 0020's amendment.
- **B3. The residual count.** ADR 0019 named the `PATH`-shadowing residual, and `CONTEXT.md`'s count
  of eight predated it. **Landed** in `CONTEXT.md`, which now lists ten, including ADR 0020's two.
- **B4. `explain`, not `resolve`.** [#5](https://github.com/firefly-engineering/playpen/issues/5)'s
  `playpen resolve` was folded into `explain` by ADR 0007, and its last mention was retired by
  [#27](https://github.com/firefly-engineering/playpen/issues/27).
- **B5. The search path.** [#5](https://github.com/firefly-engineering/playpen/issues/5)'s
  `$PLAYPEN_POLICY` → `.json` path is superseded by ADR 0015's directory path with `.yaml`
  first and no environment override.
- **B6. "The shim directory is not on `PATH` inside the boundary"**
  ([#5](https://github.com/firefly-engineering/playpen/issues/5)) is superseded by ADR 0012's
  unrewritten-`PATH` default. Re-entry is guarded by `PLAYPEN_ACTIVE` alone.
- **B7. Reserved names include the kind table's entries.** ADR 0012 defines the reserved set as
  playpen's six set entries plus every delivery name. The redirect variable and the suppression
  entries are also written by playpen, so ADR 0012's own one-author law reserves them too.
- **B8. ADR 0012's "No `refusal.env.*` code exists"** (the #31 amendment) refers to
  *value validation*. `refusal.env.reserved` remains minted, and the spec adds
  `refusal.env.forbidden` for `SSH_AUTH_SOCK`.
- **B9. The agent state directory of a multi-workspace profile.** The state directory was per
  workspace ([#4](https://github.com/firefly-engineering/playpen/issues/4)), and a profile names a
  *list* of workspaces. **Resolved** by [ADR 0021](adr/0021-agent-state-belongs-to-the-profile.md)
  ([#36](https://github.com/firefly-engineering/playpen/issues/36)): the directory is keyed by
  profile × kind.
- **B10. The Linux egress pin, loopback, and the network namespace.** ADR 0004 assumed a netns
  and wildcard-open loopback, and the backend chosen in ADR 0003 provides neither. **Resolved by
  deletion**: [ADR 0020](adr/0020-playpen-claims-credential-confinement-only.md) retired traffic
  confinement ([#35](https://github.com/firefly-engineering/playpen/issues/35)).

---

## Appendix C — assembly choices

Choices this spec made that no ticket decided. **Reviewed and accepted** in
[#9](https://github.com/firefly-engineering/playpen/issues/9).

- **C1. Code names.** Every code without † in [Appendix A](#appendix-a--code-registry) was named
  here, following the rules of [#13](https://github.com/firefly-engineering/playpen/issues/13):
  one code per distinct reason, and `refusal.<subject>.<reason>`. Some reasons were merged into
  one code with the offending value carried on the line: every self-integrity path, every
  playpen state-I/O failure, and every missing mechanism capability.
- **C2. The `fragments` table** holds two sub-tables (`env`, `endpoints`). ADR 0009 named
  `fragments` before environment fragments (ADR 0012) and rule sets (ADR 0017) existed, and host
  fragments retired with ADR 0020.
- **C3. `forge` carries no `kind` field.** The prototype's `forge.kind` collided with **Kind**
  in the glossary, and the minter is already named on each route.
- **C4. The minter contract** ([§7.2](#72-minters)): a versioned stdin carrying the route and
  the scope (`null` for a profile route), a required RFC 3339 `expires_at`, and a per-minter
  `timeout` defaulting to 30 s with `refusal.minter.timeout`.
- **C5. `explain` flags.** `--shim`, `--cwd` and `--policy` on `explain` are the surface needed
  to show the selection trace and the injected argv for a given invocation.
- **C6. `refusal.state.io`** for playpen's own state I/O failures. The record requires these to
  refuse, but never named a code.
- **C7. The state directory's location** is left to the implementation. It must be **unreachable
  by any granted path** and a real host path. "Outside every workspace" was the original wording
  and is narrower than the rule's own enforcement: it omits **toolchain roots**, which attach to
  the profile rather than to a workspace, **exclusions**, and **the floor**, which on a non-FHS
  host is a declared closure naming a directory an operator chose. A requirement narrower than
  what it enforces is what makes a reader distrust the document — someone would declare a
  toolchain root over `~` and be refused by a rule the spec does not state. A launch whose grants
  reach the directory is `refusal.state.reachable`
  ([ADR 0027](adr/0027-the-state-directory-is-unreachable-by-refusal-because-a-carve-out-is-not-portable.md)),
  and the only exemption is a subtree playpen *derived from* the directory: agent state
  directories live inside it and are granted by design, so the exemption turns on where a path
  came from rather than on who declared it. The implementation uses
  `$XDG_STATE_HOME/playpen/` when that is an absolute path, else `~/.local/state/playpen/`, on
  both platforms, as [§10.1](#101-location) reads `$XDG_CONFIG_HOME`. A relative value of
  either variable is ignored, as the XDG base directory specification requires. Run records are
  `runs/<run id>.json` beneath it. Neither variable naming an absolute path is
  `refusal.state.io`.
- **C8. Row ids.** These were taken from [#29](https://github.com/firefly-engineering/playpen/issues/29)'s
  report. The rows added by later tickets (`N-keg-decoy`, `N-endpoint`, `N-endpoint-no-leg`,
  `P-argv`, `P-endpoint`, `R-policy-span`, `R-no-filesystem`) were named here.
- **C9. The agent binary is not granted implicitly.** ADRs 0014 and 0019 resolve a stable link
  and grant both link and target *for a toolchain root*. No ticket says whether a shim's
  `target` is granted on its own. The spec requires policy to cover it, so the floor stays the
  only built-in grant. The cost is that a cask-installed `claude` needs its own toolchain root.
- **C10. Injection substitutes in place** ([§7.3](#73-session-phantom)): the real secret replaces
  the phantom in whichever header the client used. Serving a credential across shapes is handed
  off ([§20](#20-handed-off-questions)).
- **C11. A live run is recognised by an advisory lock on a sidecar**
  ([ADR 0028](adr/0028-the-run-record-ring-evicts-history-and-never-a-live-run.md)), decided after
  #9 rather than reviewed in it. §14.1 specifies the invariant and not the mechanism, so a future
  playpen could use a pidfd on Linux and change nothing a caller sees. The run holds the lock on
  `runs/<run id>.lock` for its lifetime; the kernel releases it on any death, `SIGKILL` included,
  so eviction needs **no age bound** — a constant would have to exceed any agent session and
  undercut any tolerable leak, and the first half is not playpen's to guess. It needs a sidecar
  because a lock follows the inode and every record write replaces `<run id>.json` by rename.
  There are **two removers**: the run removes its own on the normal path, and eviction removes
  whatever remains, since a fault ends by `abort` and runs no destructor
  ([§11.6](#116-process-transparency)). A **missing** sidecar beside an un-ended record counts as
  **dead**, so a record written by an older playpen is evictable rather than immortal. A staging
  rename failing `ENOENT` is deliberately **not retried**: a live run's staging file has no
  legitimate remover, so that errno means the invariant is broken, and re-staging would turn a
  broken invariant into a successful write.
