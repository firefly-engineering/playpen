# Credentials are minted outside the boundary, and only phantoms cross it

playpen never lets a real credential enter the sandbox. Credentials are produced **before
launch** by operator-declared **minters** — executables playpen runs unconfined on the host —
and held only in the sibling proxy's memory. What crosses the boundary is a single per-run
**session phantom**: a random bearer token that authenticates the agent to the proxy. The proxy
selects which real credential to inject by matching the request's **destination host and literal
path prefix** against a **route table**, strips the phantom, and injects the secret. There is no
mode in which the real secret is placed in the sandbox's environment or filesystem.

_Amended by [ADR 0013](0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md):
"the sibling proxy" is the **supervisor**, which hosts the proxy in-process. This ADR's guarantee
is named **credential confinement** there and is enforced by construction rather than by the
mechanism, so it holds under every egress setting — including `open`, where an agent may bypass
the proxy entirely and thereby only fails to authenticate._

## Why

**Minting is an exchange, not a lookup, and playpen must not know which forge it is talking to.**
A long-lived PAT read out of a keystore is not a minimized credential — it is scoped to whatever
the human gave it, and calling that "minting" makes the word decorative. A genuinely minimized
credential (a GitHub App installation token scoped to one org, expiring in an hour) requires an
API exchange with the forge. Building that in would put a forge's API treadmill inside the
confinement binary and break the standing rule that playpen models no particular forge. So a
minter is an **operator-declared executable**: handed the declared scope as JSON on stdin,
returning `{token, expires_at}` on stdout. Keystore lookup is then just the trivial minter, not
a separate concept, and the GitHub case ships as a documented **policy artifact** rather than a
built-in `kind` playpen resolves internally.

This deliberately generalizes past forges. An LLM provider key, Linear, Notion — anything the
agent authenticates to during a session — is the same mechanism with a different declared scope.

**Phantom, and no weak mode.** The phantom defends against *exfiltration*, which is the threat
that actually binds: it does nothing to stop an agent misusing a credential it was legitimately
given, but it stops the secret leaving through a channel that is not the proxy — a log line, a
`git config` dump, a tool call that posts the environment to an allow-listed host. Under tier
two that is the difference that matters. The alternative (`nono`'s `--env-credential`, which
nono's own docs label as weak) is not offered even as an opt-in: an env-carried real secret is
observationally identical to a brokered one at launch and differs only in the failure that
matters, which is the exact shape of the no-silent-downgrade law. The accepted cost is that a
credential works **only over the proxy**, which retires `git+ssh` a second time from a new
direction.

**The route selects; the phantom authenticates.** The obvious reading — one phantom per
credential — cannot work, because the delivery transport is an environment variable and `gh`
reads exactly one `GH_TOKEN`. A tool handed two phantoms for one host has no idea a choice
exists. Multiplicity therefore lives in the route table, and the discriminator is available:
`github.com/<org>/<repo>.git` and `api.github.com/repos/<org>/<repo>` both carry the org in the
**path**, as does essentially every SaaS API worth naming. Matching on host **plus literal path
prefix** preserves per-workspace credential separation at *use* time, not merely at mint time,
so the workspace model's refusal to merge forge scope holds end to end and there is no residual
to name. This also retires `nono`'s flagged wart — "the phantom is the same session token for
every route" — as a correct decomposition rather than a weakness.

The phantom then earns its keep twice. Inward it contains exfiltration; outward it authenticates
the proxy's callers, which is what keeps the shared-host-loopback residual on macOS from
becoming a credential leak: a host process can reach the proxy port, but cannot present a token
it never saw.

**Renewal is not expansion.** A session routinely outlives an hour-long token. Minting once
means the agent starts receiving bare `401`s mid-task with no way to distinguish expiry from a
permissions problem. The proxy therefore re-invokes the minter as a credential nears expiry.
This does not collide with the no-runtime-capability-expansion law: re-minting produces a fresh
credential for a scope **already declared at launch**, so nothing widens and the capability set
is untouched — expansion would be a *new* scope appearing mid-session, which stays forbidden.
The mechanism is already blessed, since the transparency law forbids a live *ancestor*, not a
live process. Renewal is also what makes "the TTL is the guarantee" affordable: without it,
operators feel pressure toward long-lived tokens just to survive a session, and the incentive
points exactly the wrong way.

**Revocation is an optimization; the TTL is the guarantee.** The real secret lives only in the
proxy's `Zeroizing` memory, so the proxy's death removes it from the host — but that is
*forgetting*, not revoking, and a token playpen has forgotten is still valid at the forge. Active
revocation needs forge knowledge, which is the wall minting already hit, so it is a symmetric
optional policy-declared `revoke` command run best-effort at exit. A design whose safety depends
on a cleanup path running is unsafe under `SIGKILL`, so playpen states TTL-bounded rather than
implying revoked.

**Minters are trusted host code.** Minting must precede the proxy, which precedes the capability
set, which precedes `exec` — and a minter usually *needs* ambient authority, because the token
exchange is itself a network call that cannot go through the allow-list it is helping build. So
a minter runs unconfined, in the same trust class as the policy that declared it. Under renewal
it runs unconfined *alongside* a live sandbox rather than merely before one. A hostile minter is
a hostile policy, which the threat model already places outside the attack surface — but this is
written down rather than left to be discovered in a source file.

## Consequences

- **`nono-proxy` is linked, behind a playpen-owned interface.** Version 0.73.0 is published on
  crates.io in lockstep with `nono` 0.73.0, with a public `ProxyConfig` and `server::start`. This
  roughly doubles the dependency surface the mechanism ADR cut deliberately narrow, and is taken
  anyway for the same reason that ADR did: this is code that fails *open*, and an ephemeral-CA
  implementation is not what you want to be your own first attempt at. playpen resolves policy
  into **its own** route table and translates at the boundary, which makes the features we do not
  want — OAuth capture, SPIFFE, JWT phantoms, and especially the persistent 4096-entry phantom
  store with its 90-day TTL — unreachable by construction rather than by discipline. Gated on
  enforcement tests, not on compilation.

- **Ambiguous route overlap is a launch-time refusal.** Path granularity works only where the
  path carries the discriminator, and `POST /graphql` is one endpoint for every org GitHub has.
  Longest-prefix-wins would silently authenticate a request with the wrong workspace's credential
  and give no signal. playpen refuses a profile in which two credential routes share a host and
  neither path prefix is a strict extension of the other, naming both routes and the host. This
  is the same statically-checkable-coherence move the egress ADR made for a profile minting for
  an org it cannot reach.

- **Credentials attach at two points and resolve into one table.** Forge credentials stay on the
  **workspace**, because that is where the scope they minimize to is declared; everything else —
  the model API key, a SaaS token — attaches to the **profile**, for the same reason egress does,
  it being the unit that maps 1:1 onto the boundary. Provenance is recorded so `playpen explain`
  can answer why a credential is present.

- **Interception follows the route table.** Injection requires terminating TLS — you cannot strip
  a phantom through a tunnel you cannot read — so every credentialed host is intercepted
  necessarily. Opaque-CONNECT-by-default survives as stated, but now covers only hosts reached
  *without* a credential. The ephemeral CA's certificate is written into the **run scratch** and
  named by `SSL_CERT_FILE` — ~~one variable~~; *corrected by ADR 0012*: **`SSL_CERT_FILE` and
  `NODE_EXTRA_CA_CERTS` both**, since the flagship binaries are Bun and honour the latter while
  the OpenSSL-linked toolchain beside them reads the former. Two disjoint TLS stacks live inside
  one boundary, so naming one of them was a silent half-measure. Either way its lifetime matches
  the session's without anyone enforcing it. The CA certificate is public, not secret; the
  private key never leaves the proxy's memory.

- **Delivery is named by the route, never by the agent kind.** Policy names the variable
  (`{env: "GH_TOKEN"}`) and playpen copies a string into a name it was handed — data, not
  interpretation, on the same footing as `NO_PROXY`. Selecting the variable by agent `kind` would
  leak per-agent knowledge out of the `kind` table into the credential subsystem, so it is
  forbidden. Delivery is a **field** rather than an assumption, leaving room for non-env
  transports without reopening the route table.

- **A missing credential is not an egress decision.** An agent reaching a host the profile never
  credentialed gets the **forge's own `401`**, which is more accurate than anything playpen could
  synthesize — and synthesizing one would require the proxy to recognize that a host *ought* to
  carry auth, which is forge knowledge in the component that must stay forge-agnostic. It must
  never carry an `egress.*` code; those are reserved for a host that was not reachable at all.

- **The failure semantics split on whether the run is live.** A minter failure **before** launch
  refuses the whole run with a `refusal.minter.*` code naming the minter and the scope — not
  "launch without that credential", which is a run that works for ten minutes and then fails at
  the first push. A **re-mint** failure mid-session cannot be a refusal, since the run is already
  live and playpen interprets nothing at that point; the credential simply lapses and the forge's
  `401` stands.

- **The minter's stdout is a secret channel.** `Zeroizing` from the moment it is read, never
  logged, never in `playpen explain`. The run record captures `expires_at` and never the token.

- **One logical credential is four policy objects** — minter, routes, delivery, and a matching
  allow-list fragment, since reachability is an independent list that must agree or playpen
  refuses. This is markedly more verbose than `nono`'s `"env_var": "GH_TOKEN"` one-liner. The
  verbosity is the price of there being exactly one policy author.

- **L7 endpoint rules are deferred, and path prefixes here are selectors, not access control.**
  The route table has a natural slot for method and path restrictions, but deciding the rule
  language is a separate question with its own trap — the never-a-regex law meeting glob syntax.
  Keeping them apart also stops a route selector from quietly becoming a security boundary
  nobody tested.

  _Resolved by [ADR 0017](0017-an-endpoint-rule-restricts-the-credential-and-never-the-agent.md): a
  route references named **endpoint rule sets**, allow-only, host-absolute, in a two-token segment
  glob playpen parses itself. The selector stays a selector — nothing path-shaped is written
  directly on a route — and the rule set exists for the credential a **minter** cannot minimize,
  which the trivial keystore minter blessed above makes the common case rather than an edge one._

- _Amended by [#30](https://github.com/firefly-engineering/playpen/issues/30): **the session
  phantom belongs to the process tree, not to the agent.** [#24](https://github.com/firefly-engineering/playpen/issues/24)
  measured a stdio MCP server inheriting its agent's environment whole, so every third-party
  process the agent spawns holds the phantom and has full use of every credential route. This is
  stated as a consequence of the unit of policy and **not** as a named residual: a residual is a
  surface playpen could close and declines to, and this one cannot be closed at playpen's
  altitude — separating a child from its parent inside one boundary is per-process confinement,
  the tool-call unit the effort rejects. Nor is it wider than what the agent already holds: an
  agent running with every permission enabled can `env | curl` on its own. Outside the boundary
  the phantom is near-inert — it works only through this run's proxy, on loopback, for this run —
  and the one exception, other host processes on macOS, is the shared-loopback residual already
  on the ledger. **Endpoint rule sets** are what bound any holder, agent or child alike. No deny
  side is added to the environment (ADR 0012 stands), and a nested run is not a distinct case: a
  re-entered shim `exec`s inside the same boundary, where the phantom, proxy and manifest are all
  still true. A nested agent of a *different* `kind` gets no suppression entries and no state
  directory, so it may break; it cannot escape, and it is documented rather than engineered._

- _Amended by [ADR 0020](0020-playpen-claims-credential-confinement-only.md) ([#35](https://github.com/firefly-engineering/playpen/issues/35)): this ADR's guarantee — **credential confinement** — is now the only
  network claim playpen makes. Its scope is widened from secrets to **credential oracles**: a unix
  socket that signs or acts for its caller (`ssh-agent`, `gpg-agent`, a password manager's agent,
  `docker.sock`) is default-deny on macOS and on Linux at Landlock ABI ≥ 9, and a named residual on
  Linux below it; a network-reachable oracle (a cloud metadata endpoint, a host-loopback credential
  service) is a named residual. "A missing credential is not an egress decision" now reads "is never
  a `broker.*` code". The shared-loopback residual cited above is subsumed by **network-reachable
  credential sources**, on both platforms._
