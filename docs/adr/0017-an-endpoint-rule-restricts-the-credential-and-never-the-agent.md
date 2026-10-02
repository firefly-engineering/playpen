# An endpoint rule restricts the credential, and never the agent

A **credential route** may reference one or more **endpoint rule sets**, each a named,
allow-only list of `{method, path}` rules matched against the full host-absolute request path.
A rule set exists only on a route: a host carrying no credential can carry no rule. Rules are
referenced by name and never written inline, the path language is a two-token segment glob
(`*` one segment, `**` zero or more) that playpen parses itself, and an absent `endpoints:`
means unrestricted rather than empty. A refused request gets `403` with
`egress.endpoint.denied` and never reaches upstream at all.

## Why

**The gap is the credential that cannot be minimized, and it is the common case for everything
that is not a forge.** ADR 0008 made minting an *exchange*, and where the exchange works — a
GitHub App installation token, one repo, read-only, an hour — an endpoint rule is playpen
re-implementing forge authorization, worse, in the component that must stay forge-agnostic. But
ADR 0008 also blessed keystore lookup as "the trivial minter", and a trivial minter returns
whatever long-lived PAT the human already had, scoped to whatever the human gave it. An LLM
provider key is all-or-nothing by construction; so is a Notion token. For these the rule set is
not a second line of defence, it is the *only* narrowing that exists between "this credential is
present" and "this credential is unlimited".

**Framing it as a restriction on the credential rather than on the agent is what makes it true
under every egress setting.** ADR 0013 established that under `open` the proxy runs unpinned and
an agent may reach the network directly. Any sentence of the form "the agent may not `POST` to
this endpoint" is therefore false under `open`. The sentence that survives is about the secret:
the real credential exists only in the supervisor's memory, so a request that does not match the
rule set never receives it — bypass or no bypass, the agent gets the forge's own `401`. The rule
set is part of **credential confinement**, which ADR 0013 made structural and unconditional, not
part of **traffic confinement**, which is claimed only under `allowlist`.

That is also why a rule may not sit on an uncredentialed host, and the reasoning is ADR 0013's
own cooperation test applied rather than an omission. A rule restricting a host where no secret
is at stake restricts only what the agent may *do*, and under `open` cooperation would be its
sole basis — the first thing in this design to claim a confinement it cannot enforce. The cost
is real and stated: "the agent may read from this public host but not `POST` to it" is
permanently unexpressible, and this is ruled out rather than deferred, so it cannot return as a
small schema addition.

**Both dimensions are load-bearing, and a measurement decided it.** Observed against a real
repository, a `git fetch` over HTTPS is:

```
GET  /org/repo/info/refs?service=git-upload-pack   → 401 → retried with Authorization
POST /org/repo/git-upload-pack
```

So the ticket's own motivating example was half wrong: a credential restricted to `GET` is
indeed weaker than one that can force-push, but a `GET`-only rule set also cannot `clone`, because
the bulk of a read is a `POST`. Path carries the read/write distinction for git, where the
effectful request has its own endpoint (`git-receive-pack`); method carries it for REST, where
`GET` versus `PATCH` versus `DELETE` on one `/repos/org/repo` path *is* the distinction. Neither
dimension alone suffices, and a design that shipped only one would have looked complete.

**The query string is out permanently, and the same measurement is why it can be.** git's
read/write discriminator on the *discovery* request lives nowhere but the query
(`?service=git-upload-pack` versus `?service=git-receive-pack`), so matching it would make "fetch
but not push" exactly expressible. It is refused anyway: a query matcher must define parameter
ordering, repeats and percent-encoding canonicalization, and every one of those failure modes
fails **open** — a rule written against `?a=1&b=2` silently permits `?b=2&a=1` unless playpen
normalizes, and normalizing is a hand-written parser for someone else's URL conventions, which is
the never-a-regex law arriving by a different door. It buys nothing here because the effectful
request has its own path.

**Rule sets are named and shipped, because nobody writes "read-only GitHub" correctly from first
principles.** The measurement is the argument: authoring it by hand requires knowing that
`POST /git-upload-pack` is a read, and getting it wrong fails **open** — a rule set permitting
`POST /**` looks restrictive and restricts nothing. ADR 0004 already settled the shape for
exactly this problem, shipping named allow-list fragments as *data in the policy* that the
operator references explicitly and playpen merges never. The forge knowledge lives in a fragment
an operator names, not in the binary, so the forge-agnostic law binds where it was always meant
to bind. Referencing by name is required rather than merely available: it makes the shipped and
the hand-written case one concept, it gives `playpen explain` something to name as provenance —
"denied by rule 3 of an anonymous inline list" is not provenance — and it keeps the route object's
two path-shaped fields distinguishable by *shape* rather than by careful naming, since `path:` is
a literal selector string and `endpoints:` is a list of names. Nothing path-shaped is ever written
directly on a route, which is a stronger guard against the selector quietly becoming a security
boundary than any amount of documentation.

**Rule paths are host-absolute, which is what keeps a rule set readable alone.** Making them
relative to the route's selector would inherit the org for free, and would make the selector a
component of the access-control decision — precisely the merge ADR 0008 deferred this work to
avoid. The selector's job ends when the route is chosen. A shipped fragment therefore spells the
org as a `*` segment (`GET /repos/*/issues/**`), which is honest about its own generality: it
permits issue reads on *any* repo, and the route decides which repos this credential reaches at
all.

**playpen parses the glob rather than passing the string through.** The two-token segment glob is
a total matcher with no backtracking and no catastrophic case — a grammar, not a regex, and the
no-regex law is aimed at hand-rolled parsers for structured input, which this is not. But ADR 0009
made "a policy refusal must name file, line and column" a parser requirement, and a string handed
to nono unvalidated cannot produce one; worse, its semantics would then be a second policy
author's, which is what ADR 0003 walked away from. Anything richer than the two tokens is refused
at parse — no alternation, no character classes, no anchoring metacharacters — so the syntax
cannot grow into a regex by increments.

**Allow-only, no deny list, no ordering.** nono evaluates deny → approve → allow → default with
first-match-wins. A deny list beside an allow list re-creates "which rule won", which is ADR 0009's
own complaint against a `policy.d/` and the reason ADR 0006's floor is non-subtractable. With
allow-only there is no ordering to specify and therefore none to get wrong, and nono's precedence
chain becomes an implementation detail playpen never exposes. nono's `Approve` action is dead on
arrival under ADR 0003's no-runtime-capability-expansion law: an approval tier is a capability
appearing mid-session.

## Considered Options

**Endpoint rules decoupled from credentials**, as nono has them — its `RouteStore` is deliberately
independent of its `CredentialStore`, so a rule can restrict a host with no secret attached.
Rejected on the cooperation test above, and because it would force TLS interception on hosts that
carry no credential, buying path granularity in the one place ADR 0004 deliberately chose hostname
granularity.

**Not shipping endpoint rules at all**, on the ground that scoping is the minter's job and a minter
that cannot minimize is a policy bug. Rejected because "policy bug" is not available as an answer
for a provider that issues only all-or-nothing keys, which is most of them.

**Inline rules on the route**, alongside references. Rejected: it splits one concept into two code
paths and leaves the most security-relevant object in the policy without a name to cite.

## Consequences

- **ADR 0013's hand-off dissolves rather than resolves.** It warned that "any L7 endpoint rule
  forces interception, and therefore the CA pair, in a profile that would otherwise have run
  without a CA in its trust bundle." Because rules live only on routes, and ADR 0008 already
  intercepts every credentialed host necessarily, a rule set adds interception to nothing that was
  not already intercepted. ADR 0004's opaque-`CONNECT` default is narrowed **not at all** by this
  decision, and the `SSL_CERT_FILE` / `NODE_EXTRA_CA_CERTS` tier ADR 0013 defined is untouched.

- **ADR 0013's `403` omission is corrected, one condition finer.** It omits the `403` +
  `X-Playpen-Denied` vocabulary from the manifest under `open` and `none`, on the ground that no
  denial can fire there. Under `open` a denial now *can* fire — the proxy is running as a broker
  and will refuse a non-matching request — so the rule is not "omitted under `open`" but **omitted
  where no denial can fire**, which under `open` depends on whether any resolved route carries an
  `endpoints:` reference. Under `none` there is no proxy and no route, so it stands.

- **Three new refusal codes, and one that is deliberately not new.** `refusal.endpoint.unknown`
  for a reference to a rule set that does not exist. `refusal.endpoint.unsatisfiable` for a rule
  set that can never match its route's path selector, naming both — the language is small enough
  that "can any path match this literal prefix and this glob" is decidable, and ADR 0008 already
  refuses a profile that mints for an org it cannot reach on exactly this reasoning. Failing closed
  is not a reason to permit it: it is a run that 403s on every authenticated request and that an
  operator will diagnose as a broken credential. A **malformed glob** is a parse refusal carrying
  file, line and column per ADR 0009, never an endpoint code — it is refused before the resolver
  exists.

- **The manifest states rule sets by name plus their rules; the denial carries only a code.** A
  rule set is a positive enumeration of what is permitted, so it is reachable-set vocabulary rather
  than the exclusion vocabulary ADR 0011 withholds, and stating it makes futile work visibly
  futile. The `403` therefore names no rule set: the manifest already told the agent which rule
  sets apply and what they permit, so naming one adds nothing it could not have read before making
  the request — while provenance, *which document produced this*, is the part ADR 0011 keeps out
  of the inward projection deliberately. Outward, `playpen explain --json`'s egress section gains
  the resolved rule sets per route with fragment provenance, generalizing ADR 0004's fragment
  provenance and ADR 0009's `from:`.

- **The enforcement suite asserts from inside a live sandbox, and one of the three assertions needs
  an instrumented upstream.** The positive: a matching request reaches upstream **authenticated**,
  phantom stripped and secret injected. The negative: a non-matching request returns `403` with
  `egress.endpoint.denied`. And the one that is not implied by the negative and is invisible from
  the sandbox's side — **no upstream leg occurred at all**, so the real secret was never sent to
  the destination the rule refused. A proxy that forwards first and refuses second fails open, and
  a matcher is unit-testable in isolation, which is the cheap version that passes while the wiring
  is wrong. Per ADR 0016, the negative's fixture must use a request the *host* allow-list permits,
  or it is `egress.host.*` passing in `egress.endpoint.*`'s clothing — a vacuous pass.

- **A named residual, and it is small: push discovery succeeds.** With the query string out,
  `GET /org/repo/info/refs?service=git-receive-pack` matches a read-only rule set's `info/refs`
  entry, so git learns the remote's refs and then fails at the second request when
  `POST /git-receive-pack` is denied. The leaked information is a ref listing that any permitted
  fetch already discloses, and the failure is a clean `403` rather than a hang — but git probes
  anonymously and retries on `401`, so a denial lands inside that retry dance and the operator sees
  git's own credential-failure wording before playpen's code.

- _Amended by [ADR 0020](0020-playpen-claims-credential-confinement-only.md) ([#35](https://github.com/firefly-engineering/playpen/issues/35)): with traffic confinement retired, "under every egress setting" reads
  "always", and the code is **`broker.endpoint.denied`** — the `egress.*` prefix is renamed
  `broker.*`. The suite negative's fixture no longer needs a host-allow-list carve-out, since there
  is no allow-list to pass for the wrong reason; the no-upstream-leg assertion stands unchanged.
  Ruling rules off uncredentialed hosts is now doubly settled: there is no traffic claim for them to
  belong to._
