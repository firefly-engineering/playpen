# The proxy is the supervisor's, and traffic confinement and credential confinement are independent

The egress/credential proxy is **not a detached sibling**. It runs in-process on the
**supervisor** — the unconfined parent ADR 0010 already established outlives setup and reaps the
run — while the confined agent is the forked child that applies the capability set to itself and
`exec`s. The proxy binds `127.0.0.1:0` before that fork, so the OS-assigned port is known in time
to be compiled *into* the capability set. And the proxy now serves **two independent
confinements**: **traffic confinement**, kernel-pinned and claimed only under `allowlist`, and
**credential confinement**, structural and claimed always. `open` therefore means *no allow-list*,
not *no proxy*.

## Why

**The premise this decision was chartered on had already expired.** ADR 0003 ruled that "nothing
alive between the terminal and the agent — but a sibling is allowed", which forced the proxy to be
detached and its whole lifetime designed from nothing: startup handshake, agent-death detection
with no parent-death signal, stale-orphan reclamation at next launch. ADR 0010 then established
that playpen **cannot be a pure `exec` shim** — an `exclusive` area's claim must be pinned to a
live process, and ephemeral areas must be torn down — so a supervisor exists regardless, is
transparent *by contract* rather than by absence, and already has exactly the lifetime the proxy
needs. ADR 0003's objection was that a supervisor "would hold the file descriptors ADR 0002
protects"; ADR 0010 answered it by making transparency an obligation playpen meets rather than a
property it obtains by not existing.

**Putting the proxy there deletes the problem rather than solving it.** There is nothing to
detach, no reparenting, no parent-death signal — the supervisor already `wait`s on the child and
exits with its status — and **an orphaned proxy becomes structurally impossible**, which was the
worst case this work was chartered to prevent ("a leaked orphan holding real credentials is worse
than a failed launch"). It also strictly improves ADR 0010's orphaned-agent residual: an agent
orphaned by `SIGKILL` of its supervisor loses its egress in the same instant, so it fails closed.

**The port is a capability-set fact, which fixes the startup ordering by construction.** nono
expresses the pin as `NetworkMode::ProxyOnly { port }`, so the port must exist before the sandbox
is compiled. Bind → read the assigned port → compile the capability set → fork → confine and
`exec`. There is no handshake and no race, because the listener is already accepting before the
child exists. A playpen- or policy-pinned port would buy nothing and add a collision mode on a
shared host resolvable only by retry or refusal. The child learns the port through `HTTPS_PROXY`,
which ADR 0012 already made a set entry, so there is no discovery protocol either.

**ADR 0004's "`open` means no proxy" was written when egress was the only thing the proxy did.**
ADR 0008 gave it a second job, and the two are genuinely separable — which is ADR 0004's own "one
process, two lists" decomposition finally paying off. Under `open`, one of the two lists is simply
absent. The proxy stops being an enforcement point and remains a credential broker, and it is the
*only* place a credential exists, so an agent that sidesteps it does not defeat anything — it
merely fails to authenticate, and receives the forge's own `401`, which ADR 0008 already ruled is
more accurate than anything playpen could synthesize.

**Naming the two confinements is what makes that a model rather than a carve-out.** Traffic
confinement is enforced by the kernel and playpen claims it only under `allowlist`. Credential
confinement is enforced by *construction* — ADR 0012's environment is built from nothing, so the
real secret is never placed in the child's environment and no bypass can leak it. They compose
freely, and every cell of the product is coherent: `allowlist` + routes is both, `allowlist`
alone is traffic only, `open` + routes is credential only, `open` alone is neither.

**That also settles which cooperation law applies, without an exception.** ADR 0004 holds that
"cooperative-only counts as unavailable, not degraded"; ADR 0005 holds that cooperation is
acceptable where honouring it "buys only usability, never confinement". The discriminator both
imply, stated once so it stops being per-ADR folklore: **the law bites when cooperation is the
sole basis of a capability playpen claims to enforce, and not when honouring it decides only
whether something works.** Under `open`, playpen claims no traffic confinement, so nothing is
degraded — and the claim it *does* still make, credential confinement, holds without any
cooperation at all.

## Considered Options

**Pinning the proxy under `open` as well** — setting `ProxyOnly { port }` with an allow-list
permitting every host — would give enforcement *and* injection, and make bypass impossible rather
than merely pointless. Rejected because it makes `open` not open: transport is HTTPS-only, so
`git+ssh`, raw TCP, UDP/QUIC and every non-HTTP protocol would die under `open` exactly as they do
under `allowlist`. `open` exists as the escape hatch for the workloads `allowlist` cannot serve;
routing it through the same chokepoint deletes its reason to exist and collapses three modes into
two differing only in list contents — the permissive proxy ADR 0004 rejected, arriving by a
different door.

**Running the proxy as a real child process** would contain a `nono-proxy` panic to its own
address space. Rejected because it hands back precisely the lifetime and orphan problem this
decision deletes — a second process to reap, to detect stale, and to kill on every crash path —
and because a dead proxy ends the run anyway, so the isolation would only convert an immediate
teardown into a slower one.

**Ignoring credential routes under `open`**, or restarting a dead proxy mid-session. The first is
a silent downgrade. The second cannot work: the port is frozen in the capability set and cannot be
re-bound.

## Consequences

- **The proxy exists as a function of both lists, not of the egress mode.** `allowlist` → always,
  since the allow-list itself needs serving. `open` → **iff at least one credential route
  resolves**; with no routes there is no reason to run one and no port to bind. `none` → never,
  since ADR 0009 already made `none` beside a credential route a launch-time refusal for
  incoherence. The asymmetry is deliberate and worth stating because it reads as an
  inconsistency: `none` + route **refuses** while `open` + route **proxies**, because under `none`
  the credential could never be used by anything, and under `open` it works — just without a
  boundary. The supervisor still exists under `none`; it holds the `flock` and reaps ephemeral
  areas, and simply hosts no proxy.

- **Bind failure is a pre-launch refusal; proxy failure mid-session tears the run down.** ADR 0008
  drew this line for minters and the proxy sits on the same timeline. A failed bind happens before
  anything is confined and costs nothing: `refusal.proxy.bind`. A proxy that stops serving leaves
  the agent confined with no exit, and letting it run on is a boundary that has silently stopped
  working in the direction that matters — the agent thrashes against a network that will never
  return, which ADR 0007 already argued is futile work playpen should not manufacture. The panic
  is caught at the runtime boundary and routed into teardown, so the failure is playpen's own exit
  path rather than a bare abort.

- **Teardown order is revoke → stop proxy → remove ephemeral areas → exit.** Revokers run *first,
  while the proxy is still up*, because a revoker is itself a network call that may need the
  allow-list. The `flock` releases implicitly on exit, per ADR 0010. The exit status stays the
  child's throughout and **no teardown failure may change it**, or ADR 0002's transparency
  contract breaks; teardown failures go to the run record.

- **There is no orphan detection, and that is the outcome rather than an omission.** A dead
  supervisor leaves no port held and no credential resident, so there is nothing to reclaim. A
  launch-time orphan scan would be exactly the staleness rule ADR 0010 refused, and would
  reintroduce the "playpen refuses forever" mode that ADR called the worst way a refusal-first
  design can fail.

- **No new named residual; five stands.** A phantom-authenticated relay on macOS's shared loopback
  requires stealing the phantom from the agent's `environ`, which requires the same uid — and a
  same-uid attacker already holds the real credentials and `~/.ssh`, so the proxy grants it
  nothing it lacked. The threat model names a hostile agent *inside* the boundary, not a hostile
  host process. A remote attacker handed an exfiltrated phantom cannot use it at all: the listener
  is bound to `127.0.0.1`.

- **DNS-rebinding immunity is an `allowlist` property, not a playpen-wide invariant.** ADR 0004's
  "the sandbox gets no resolver" holds only where the proxy is the sole exit. Under `open` the
  agent resolves for itself. This is not a regression — it is what `open` means — but it stops
  being stated unconditionally.

- **The manifest states less under `open`, not more.** The resolved-host list is **absent rather
  than empty**, since there is no list and fabricating one would state a fact playpen does not
  own. Routes are still listed as destinations-with-delivery, plus the one new fact: the proxy is
  not the sole exit, and a routed destination is authenticated only for requests sent through it.
  That is a fact about where the secret lives; "use the proxy" would be an instruction, and ADR
  0011's line holds. The `403` + `X-Playpen-Denied` failure vocabulary is **omitted** under `open`
  and `none`, because a manifest that teaches an agent to interpret an event that cannot occur is
  stating something untrue about *this* boundary.

  _Corrected by [ADR 0017](0017-an-endpoint-rule-restricts-the-credential-and-never-the-agent.md),
  one condition finer: the rule is **omitted where no denial can fire**, not omitted under `open`.
  An **endpoint rule set** can refuse a request through the unpinned broker, so under `open` the
  vocabulary is stated iff some resolved route carries one. Under `none` there is no proxy and no
  route, so it stands._

- **ADR 0012's six mandatory set entries regrade into three tiers, each still refusal-if-unset
  within its condition.** Unconditional: `TMPDIR`, `PLAYPEN_MANIFEST`, `PLAYPEN_ACTIVE`. Iff a
  proxy exists: `HTTPS_PROXY` and `NO_PROXY` in both spellings — writing them with no proxy would
  point every client at a closed port. Iff the resolved config **intercepts at least one host**:
  `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS` — a third granularity, since ADR 0004 defaults to
  opaque `CONNECT` and ADR 0008 makes interception follow the route table, so an `allowlist`
  profile with no credential routes runs a proxy and needs no CA at all. The set is mandatory
  **relative to the boundary playpen actually built**, which is the same *absent rather than
  empty* rule arriving in the environment instead of the manifest. Nothing weakens: the
  environment is constructed, so with no proxy no proxy variable exists, `NO_PROXY` is moot rather
  than missing, and policy cannot author one — all six stay reserved under `refusal.env.reserved`.

- ~~**Any L7 endpoint rule forces interception, and therefore the CA pair.**~~ Handed to the open
  endpoint-rules work: a rule that restricts path or method cannot be enforced through an opaque
  `CONNECT`, so inventing one drags `SSL_CERT_FILE` and `NODE_EXTRA_CA_CERTS` into a profile that
  would otherwise have run without a CA in its trust bundle.

  _Dissolved by [ADR 0017](0017-an-endpoint-rule-restricts-the-credential-and-never-the-agent.md):
  an **endpoint rule set** lives only on a **credential route**, and ADR 0008 already intercepts
  every credentialed host necessarily — so a rule adds interception to nothing that was not already
  intercepted, and the CA tier above is untouched._

- _Amended by [ADR 0020](0020-playpen-claims-credential-confinement-only.md) ([#35](https://github.com/firefly-engineering/playpen/issues/35)): **traffic confinement is retired**, leaving credential confinement as
  playpen's only network claim. The product of the two confinements collapses to its `open` +
  routes cell: the proxy runs iff a route resolves, unpinned, with no allow-list. Everything above
  that turns on `allowlist` or `none` — the pin, "the sandbox gets no resolver", DNS-rebinding
  immunity, `none` + route as a refusal — no longer applies. Bind failure as a refusal, teardown on
  proxy death, the teardown order and the absence of orphan detection all stand; teardown on proxy
  death now rests on `HTTPS_PROXY` pointing every client at the dead port._
