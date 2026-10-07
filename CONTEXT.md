# playpen — domain context

Ubiquitous language for playpen. Glossary only — no implementation detail, no spec.

## Workspace

A single named object describing everything one agent run may reach. It has two
structurally separate halves — **brought roots** (filesystem) and **forge scope**
(remote) — plus **provisioned areas** that playpen creates. The name is what keeps
the halves in sync; nothing derives one from the other.

A **profile** references a *list* of workspaces. Brought roots union across them;
provisioned areas and forge scope stay per workspace.

## Brought root

A filesystem tree that already exists, whose path the operator declares. playpen only
grants access to it, never creates it. Carries a mode of `read` or `readwrite`; `read`
grants execute as well, since a writable area can host a copied binary anyway. May carry
**exclusions**.

Contrast **provisioned area**, where playpen owns the path.

## Exclusion

A literal subpath subtracted from a **brought root** or **toolchain root**, with an optional
set of access classes (`read`, `execute`, `write`) defaulting to all of them. Never a pattern.
It is what makes a coarse root safe, and it applies to **mutable** trees only — a
content-addressed tree is narrowed by declaring its **toolchain closure** instead, so there is
nothing to subtract. Must exist or playpen refuses, because an exclusion whose path has gone is
a leak that reopened silently — reasoning that holds for a path that moved and is why the
content-addressed case is excluded from it rather than made an exception to it.

## Floor

The grant playpen always applies and no policy can widen or narrow: read and execute under
OS-owned paths, plus a short enumerated set of Mach services. Never under `$HOME`, never under
a package store, never writable. It is the one built-in default in the model, and it earns the
exception by deciding whether `exec` returns at all rather than what is reachable.

The **environment allow-list** has a floor of its own, held to the same test: the names any
process needs to *start* — `PATH`, `HOME`, `USER`/`LOGNAME`, `SHELL`, `TERM`, `LANG` and the
enumerated `LC_*`, `TZ` — and nothing that is a fact about the **toolchain root** that was
brought rather than about the process.

## Toolchain root

A read-only **brought root** naming what the agent works *with* rather than what it works *on*.
Attached to the **profile**, not to a workspace — every workspace needs it equally. Where policy
names a stable symlink, playpen resolves it and grants both link and target, because the
mechanism enforces on the resolved path. A profile's toolchain is a *set* of these: a coarse
root with **exclusions** where the tree is mutable, a **toolchain closure** where it is
content-addressed, and a **keg list** where a mutable tree offers stable per-package links.

## Toolchain closure

The transitive closure of an operator-declared package set, emitted as one **toolchain root**
per store path. The precise alternative to a coarse root, available wherever the tree is
content-addressed. Because nothing outside the closure is granted, it needs no **exclusions** —
the dotfile leak a coarse store root opens is absent rather than mitigated. Bounded by the
compiled-profile ceiling, which a real toolchain uses about a tenth of; the count is known
before launch, so overflow is caught where the closure is generated.

## Keg list

A **toolchain** written as one **toolchain root** per stable per-package link —
`/opt/homebrew/opt/<keg>` — each resolved at launch so link and target are both granted. To a
mutable package tree what a **toolchain closure** is to a content-addressed one: nothing
outside the listed packages is granted, so no **exclusions** are needed, and an upgrade
re-points the links rather than invalidating the policy. Closed over dependencies by the
package manager's own tooling, never by playpen.
_Avoid_: coarse root (for this shape), keg fragment.

## Run scratch

The single ephemeral writable directory playpen provisions per run and exposes as `TMPDIR`. A
property of the run, not of a workspace, so it is not a **provisioned area** — nothing outside
the run can refer to it. The host's own temp is unreachable. It also holds what playpen writes
for the run and only for the run: the **manifest**, the proxy's ephemeral CA, and the **trust
bundle** derived from the host's own store.

## Trust bundle

The roots a confined process trusts, written into the **run scratch**: the host's own roots
followed by the proxy's ephemeral CA certificate. Derived from the host's store rather than
authored, and built from the same read the **proxy** verifies destinations against, so what the
agent trusts cannot drift from what the supervisor does. It exists because the two names a **set
entry** writes for TLS roots do not mean the same thing — one replaces a client's store and one
adds to it — so the replacing one must name every root, not just the session CA. Only certificates
go in; the CA's private key is still written nowhere.

## Provisioned area

A writable directory playpen creates. The operator declares that one must exist and what it is
*for*; the path is playpen's business. Always writable, and carries a **lifetime** — which also
decides what it is keyed by, and whether it carries a **concurrency**.

## Lifetime

A property of a provisioned area. `ephemeral` — created at launch, removed at exit, keyed by the
**run**, since nothing outside the run can refer to it. `persistent` — created on first use,
keyed by workspace name, and reused by later runs of the same workspace.

## Concurrency

A property of a `persistent` provisioned area, and of no other. `exclusive` — at most one live
run may hold it, and a second is a **refusal**. `shared` — every run gets the same path and
playpen says nothing about the contents. The default is `exclusive`, because a wrongly-shared
working area corrupts silently while a wrongly-exclusive cache merely refuses.

The distinction it draws is between a **cache**, whose owning tool already locks it, and a
*working area* — a **landing zone**, a worktree root, a place an agent works — where two agents
overwrite each other's edits with no error from any tool.

playpen arbitrates only what it *provisions*: a **brought root** carries no concurrency, even
though the sharpest contention lives there.

## Landing zone

The provisioned area a repo cloned mid-session lands in. Named explicitly rather than
inferred, so that its absence is a refusal rather than a surprise.

## Forge scope

The half of a workspace describing which remote repositories the agent may reach. Stated
in *forge* vocabulary — an org, or a list of repos — never in path vocabulary. This is
the granularity a minted credential natively expresses.

## Minter

The thing that produces a credential for a declared scope — an executable the policy names and
playpen runs, outside the boundary and before the sandbox exists. Takes the scope, returns a
secret and an expiry. A **forge scope** is one kind of declared scope; an LLM provider or any
other third-party service is another, so a minter is not a forge concept. playpen models no
particular service, which is why the minter is declared rather than built in.

Trusted host code, in the same class as the **policy** that declared it: it runs unconfined,
because minting is itself usually a network call that cannot pass through the allow-list it
helps build.

May be paired with a **revoker**, run best-effort when the run ends. Revocation is an
optimization; the expiry the minter returned is the guarantee.

Also the whole of playpen's answer to an interactively-obtained credential: the operator logs the
agent in *outside* the boundary, where the browser is, and a minter reads the host's own store.
Renewal is the minter's too — a minter that refreshes performs the exchange itself, since a real
exchange is provider API surface and does not belong in the confinement binary. That a minter may
read and write state a host-level agent instance also owns is the cost, and it is a **named
residual**.

Chosen per **provider**, never per **kind**. Where the provider offers a dedicated grant that
does not refresh, the minter is a keystore lookup of it; otherwise it reads the host login's
current token and never refreshes. A minter that refreshes a shared single-use login without
writing it back logs the host out, so playpen ships none.

## Credential route

The pairing of a destination — a host plus a literal path prefix — with the credential to
present there and the **delivery** that points the agent at it. The unit the **proxy** matches
against, and the reason two workspaces' credentials stay distinct in *use* and not merely at
minting: a forge names the org in the path. Two routes on one host, neither path prefix
extending the other, are ambiguous and playpen refuses.

Attaches to the **workspace** when the credential minimizes to that workspace's **forge scope**,
and to the **profile** otherwise. Both resolve into one table, provenance retained.

May reference **endpoint rule sets**. Its own path prefix is a *selector* and never access
control — the selector's job ends when the route is chosen.

## Endpoint rule set

A named, allow-only list of `{method, path}` rules bounding what a **credential route**'s secret
may be used for. Referenced by name, never written inline, and only ever on a route: a host
carrying no credential can carry no rule, because a rule there would restrict what the agent may
*do*, which playpen does not confine. So a rule set is part of **credential confinement** and
always holds — a request that does not match never receives the secret, and gets the forge's own
`401` instead.

Exists for the credential a **minter** cannot minimize: a keystore lookup returns whatever the
human already had, and a model API key is all-or-nothing. Where minting genuinely minimizes, the
rule set is redundant.

Paths are host-absolute and matched with a two-token segment glob — `*` one segment, `**` zero or
more — which playpen parses itself, so a malformed rule is a **refusal** with a span rather than a
second policy author's semantics. Both dimensions are load-bearing and neither alone suffices:
path carries the read/write distinction for git, method for REST. The query string is matched
never. Absent means unrestricted, not empty; there is no deny list and no ordering. playpen ships
rule sets as data the operator names explicitly, on the same footing as an **environment fragment**
and for the same reason — nobody writes "read-only forge" correctly from first principles, and
getting it wrong fails open.

## Delivery

How a route's **session phantom** reaches the agent — a named environment variable today. Named
by the route, never by the **kind**, so that per-agent knowledge stays in the kind table. A
field rather than an assumption, so another transport can be added without disturbing the route.

## Session phantom

The random bearer token that stands in for every real credential inside the boundary — one per
run, not one per credential, since delivery cannot hand one tool a choice between two. The agent
presents it; the **proxy** strips it and injects the real secret, which never crosses the
boundary.

It faces both ways. Inward it contains exfiltration — a secret that is not present cannot leak
through a log line or a tool call. Outward it authenticates callers of the proxy, which is what
keeps the proxy's port on the shared host loopback from being a credential leak.

It belongs to the process tree, not to the agent: every process the agent spawns — a third-party
MCP server included — inherits it and has full use of every **credential route**. That is a
consequence of the unit of policy rather than a **named residual**, since nothing inside one
boundary can separate a child from its parent; **endpoint rule sets** bound any holder alike.

## Proxy

The credential broker: the listener that serves the **credential routes**, run **outside** the
boundary — in the **supervisor**, not as a separate process — and reached over TCP loopback. Binds
`127.0.0.1` on an OS-assigned port before the confined child is forked. Exists iff a credential
route resolves. Every client is pointed at it; it terminates TLS only for routed hosts, under an
ephemeral per-session CA that never touches disk, and passes everything else through as an opaque
tunnel with no check. It is never the only way out: playpen confines no network.

## Credential confinement

playpen's only network claim: the *means* of using a credentialed resource stays inside the
**proxy**. No real credential is reachable inside the boundary — enforced by construction, since the
**environment allow-list** never builds the name, and by the **mechanism** for credentials at rest
(the floor's Keychain denial, ungranted dotfiles). An agent may reach the network directly and
merely fails to authenticate, because the **session phantom** is the only credential it was given.

Covers **credential oracles** as well as secrets. A unix-socket oracle is denied unless it sits under
a granted writable area — on macOS always, on Linux from Landlock ABI 9; below that it is a **named
residual**, recorded outward and never in the **manifest**. A network-reachable oracle is a named
residual on every platform.

What decides whether cooperation is acceptable: a cooperative arrangement is a silent downgrade
where it is the sole basis of a confinement playpen *claims*, and merely a convenience where
honouring it decides only whether something works.

## Credential oracle

An endpoint that performs a credentialed operation for whoever reaches it, so that no secret has to
cross the boundary for the means to escape: `ssh-agent`, `gpg-agent`, a password manager's agent and
`docker.sock` over unix sockets; a cloud metadata endpoint or a credential service on host loopback
over the network.

## Environment fragment

A named, composable set of environment variable *names* the operator references from a profile —
a `rust` fragment carrying `CARGO_HOME`/`RUSTUP_HOME`, a `nix` fragment carrying `NIX_*` and
`LOCALE_ARCHIVE`. Data in the **policy**, never code. playpen ships fragments but merges none by
default; there is only ever one policy author. A fragment carries names only and never a **set
entry**'s value: a name is host-independent, a value is a fact about one host, and a value reaches
the policy by generation instead.

## Environment allow-list

The set of environment variable *names* passed through from the host into the boundary. Names
only — an inherited **value** is never inspected, because a value can only name a path and every
path is enforced by the **mechanism** regardless. Exact names, never patterns. A **floor** plus
per-**profile** entries, composable from **environment fragments**. A name on the list that is absent from the
host env is simply absent: the one stated exception to **refusal**-never-silent-downgrade, earned
because it fails *closed*.

The child's environment is **constructed, never filtered** — nothing arrives that playpen did not
put there, so there is no deny-list and nothing to strip.

`SSH_AUTH_SOCK` is permanently denied and no policy may add it: unlike the path-shaped hazards
(`NODE_OPTIONS`, `LD_PRELOAD`, `GIT_SSH_COMMAND`), it names a **credential oracle** the **proxy**
cannot see. Banning the name is necessary but not sufficient; the socket itself falls under
**credential confinement**'s unix-socket denial.

## Set entry

An environment variable playpen *writes* rather than passes. Playpen's own are mandatory
**relative to the boundary actually built**, and their absence within that condition is a
**refusal**: `TMPDIR`, `PLAYPEN_MANIFEST` and `PLAYPEN_ACTIVE` unconditionally; and, wherever a
**proxy** exists — iff a **credential route** resolves — `HTTPS_PROXY`, `NO_PROXY` (both
spellings), `NODE_USE_ENV_PROXY`, and the CA pair `SSL_CERT_FILE` + `NODE_EXTRA_CA_CERTS`, a pair
because two disjoint TLS stacks live inside one boundary. The pair names *two* files, because only
one of the two is additive: `NODE_EXTRA_CA_CERTS` adds the session CA to roots the client already
has, so it names the certificate alone, while `SSL_CERT_FILE` replaces them and so names the
**trust bundle**. All are reserved names in every run, whether written or not, as are the
**kind**'s own entries.

**Policy** may author set entries too, with literal values, and they win over floor pass-through.
Attached to the **profile**, never a workspace, since merging per-workspace values would silently
produce one neither workspace justified. A **provisioned area** is named by typed reference
(`!area <workspace>/<area>`) rather than a literal, because playpen owns the path. Any collision
between a policy set entry and one playpen writes — including a **delivery** name — is a
launch-time refusal, because two authors of one variable is "which rule won" in miniature.

## Agent state directory

The directory an agent binary keeps its own state and configuration in. One per **profile** and
**kind**, never per workspace, because it is written only by runs whose reach is that profile's;
keyed any finer, it would carry one workspace's contents to a profile that cannot reach them.
Persistent and shared by every run of the profile, since the agent handles its own concurrency. It
carries an explicit read-only **share list** naming what is carried over from the real one.

## Share list

The entries of the real agent state directory made visible, read-only, inside a
profile's own. Default-deny: empty unless named. An entry naming the file the **presentation
adapter** renders into is composed by reference, never merged.

## Manifest

The canonical description of a workspace's layout, readable from inside the boundary: a JSON
file in the **run scratch**, named by `PLAYPEN_MANIFEST`, always written. Not authored — a
projection of the **run record**, facing inward as the **capability set** faces outward, and
strictly narrower: no selection trace, no policy provenance. playpen owns the facts it states;
how it reaches an agent's attention is a per-harness presentation concern.

It is also the *only* thing playpen tells an agent about its own confinement, and it says so
up front rather than at the moment of failure: alongside the layout it carries the destinations a
**credential route** authenticates and the variable each is **delivered** in, that the **proxy** is
not the only way out, how to read a **denial**, and that the boundary is fixed for the whole session. **Exclusions**
are omitted — enumerating them maps what is worth attacking — and so is whether unix-socket
**credential oracles** are reachable, for the same reason. It is the sole
inward-facing truth — nothing playpen offers inside the boundary may state a fact the manifest
does not.

It **describes** the boundary and never constitutes it. It sits in writable scratch, so an
agent can rewrite it; nothing moves when it does, and the agent has lied only to itself.

## Presentation adapter

The per-**kind** renderer that puts the **manifest**'s facts into the idiom that kind's binary
reads — the kind's instruction entry point in the profile's **agent state directory**, which
playpen owns. That directory is shared by every run of the profile, so the adapter states only
facts stable across them and names `PLAYPEN_MANIFEST` for the rest. Bound
by one law: it may state facts about the boundary playpen built, and may never state what the
agent should do about them. Generated from the manifest's own data, never hand-written prose, and
carrying no compatibility promise — its consumer is a model, not a parser.

_Avoid_: prompt fragment, system prompt injection.

## Profile

The unit an invocation selects. Names the workspaces in play and the confinement to
apply. Selected from invocation context, never chosen by the agent.

## Policy

The document declaring every profile, workspace and shim on a host. Located by a fixed
ordered search path, first hit wins — never merged, so that "which rule won" always has
one answer. Owner-authored; playpen refuses to launch if the policy it read sits inside
anything the selected profile can write.

A *single* document of keyed tables, never a directory — splitting it would give
"which rule won" back to an ordering rule. Its data model is JSON; YAML is the surface
syntax, because JSON is a subset of it and strict parsing leaves JSON no way to carry a
comment. Strictly parsed throughout: an unknown field or version is a **refusal**. Its
authored shape is distinct from the **capability set** it resolves to.

It may be hand-written or generated, and playpen cannot tell which — a property rather than an
accident, since it is what lets a **policy generator** exist without becoming a second author or
a runtime dependency.

## Policy generator

Something that emits a **policy** on the operator's behalf — on a Nix host, a shipped
home-manager module. It is a projection of what the operator declared, never an author: it
contributes no defaults of its own, and any convenience it offers is a value the operator names
explicitly. Its output is an ordinary file on the search path, indistinguishable from a
hand-written one. It is how a **toolchain closure** gets written at all, since no human can
correctly maintain a list of hashed store paths.

## Shim

A stand-in for an agent binary, placed on the operator's PATH so that invoking `claude`
launches it confined. Thin by construction — it supplies a profile, a **kind** and any
**injected flags** to the core CLI, and nothing else. It finds the real binary by an
absolute path the policy declares, never by searching PATH.

Physically a symlink to the playpen binary, named for its key in the policy's `shims` table,
so the shim *is* playpen rather than a second artifact. It runs outside the boundary on the
next launch, which is why playpen refuses when the shim, its directory, or the binary it
resolves to is writable by the selected profile.

## Injected flag

A literal argv token a **shim** declares and playpen prepends to the child's arguments
without reading it. Written as a list of tokens, never a shell string, because splitting
one is a quoting parser. It can make the agent work or not work and can never move the
boundary, so there is no *required* marker and no contradiction detection: prepending
means a caller who repeats the flag overrides it, and across *different* flags playpen
guarantees nothing, since the precedence is the agent's own.

Per-agent knowledge is that a flag *exists*; policy is that this host *pins* it — which is
why injected flags live on the shim declaration and the **kind** table learns no flag
spellings.

## Kind

Which agent **harness** is being wrapped (`claude`, `omp`). Always stated, never inferred from
the invoked name. It selects the agent state directory, the manifest's presentation, and the
**suppression table**; an unrecognised kind is a **refusal**, because there is nowhere to put
what playpen would need to know about it. All per-agent knowledge is confined here.

A kind is never a **provider**. A harness may be tied to one provider and ship that
provider's tooling in the same CLI, as `claude` does, but nothing about credentials is
keyed by kind.
_Avoid_: agent (when the provider is meant).

## Provider

The service whose API a **credential route** authenticates against: the model API, a
forge. What kinds of grant exist, how long they last and whether they refresh are facts
about the provider, never about the harness that happens to mint or use them, so a
**minter** is chosen per provider. `claude setup-token` is an Anthropic grant that the
`claude` CLI happens to mint; an `omp` run against Anthropic can be served by the same minter.

## Suppression table

The per-**kind** set of environment entries playpen sets so that an agent does not try to apply
its own sandbox inside playpen's. Cooperative, and permitted to be: honouring it buys only
usability, never confinement, so a guest that ignores it merely breaks rather than escapes.

It only ever *sets*. The **environment allow-list** is constructed rather than filtered, so
there is nothing to strip; the case that looked like stripping is the **shim** case, where an
outer playpen's entries must not reach a nested invocation — and that falls out of construction.

## Mechanism

The kernel facility that enforces confinement — Seatbelt on macOS, Landlock plus seccomp on
Linux. There is one per platform, so playpen never chooses between siblings; it chooses only
how far above the mechanism it sits.

## Backend

The implementation of a mechanism behind playpen's own interface. A backend is defined by
the **enforcement tests** it passes, not by the API it exposes — which is what makes one
replaceable by another.

## Capability set

The fully-resolved, enforcement-shaped description playpen hands a backend: absolute paths
with access modes, a network mode, an environment allow-list, the **injected flags**.
Nothing above that — no workspace names, no lifetimes, no profiles.

Faces *outward*, at the kernel. Contrast the **manifest**, which faces inward, at the agent.
Dumpable without launching an agent, so that "which rule won" has an answer for the filesystem.
A backend may impose a **budget** the capability set can exceed — macOS caps the compiled
profile at 65535 bytes — and exceeding it is a **refusal** in playpen's own vocabulary, never a
leaked backend error.
_Avoid_: manifest, capability manifest.

## Enforcement test

A single assertion in the contract a backend must satisfy. Three classes: a **negative**,
made from inside a live sandbox, that something is not reachable; a **positive**, likewise
from inside, that something *is* — admissible only where the regression it would catch is
silent, since anything else is an integration test wearing the suite's uniform; and a
**refusal**, made where playpen declined to launch and there is no inside to assert from.

Every assertion is **two-part**, not one: it establishes the condition holds as seen from
*outside* before asserting the boundary's behaviour from inside. For a negative that means the
target exists outside and the read from inside fails with a **denial** — a target that is merely
absent makes the assertion pass for the wrong reason, the boundary that silently stopped being
enforced, certified green, so absence outside is a setup failure. This is what the never-`ENOENT`
law buys beyond its promise to the agent. Positives take the same form: a capability that fails
outside is a host condition, not a red.

It has **three outcomes**, not two. It **runs**; or it is **`n/a` by platform**, which is a
**named asymmetry** already on the ledger rather than a gap; or it is **skipped**, meaning it
applies here and a precondition on *this* host is missing. A skip is always named, never inferred.

The collected set of them *defines* the backend. Each carries the platform it must pass on,
and a single-platform assertion costs a **named asymmetry**.

## Liveness probe

An assertion that a real agent binary, launched confined, still works — the only thing that
catches an agent reintroducing a startup self-sandbox before its users do. Not an
**enforcement test**: it tracks other people's release schedules rather than playpen's, so it
gates an agent-version change and never a playpen one. What it needs to know about each
agent — the binary, the invocation — is per-agent knowledge and so lives in the **kind**
table with the rest, which makes a new kind a row rather than a test.

## Policy fixture

A real **policy** document a suite entry runs against — the unit a confined launch is batched
by, since assertions sharing one **capability set** share one sandbox. Being a real document,
it is incidentally a test of the parser.

## Probe

The binary the suite runs *as* the confined child to make an assertion from inside. It is an
observer that perturbs what it observes: it needs its own path granted, so every negative it
makes reads "unreachable even with the probe's own root present" — the weaker direction, and
therefore the safe one. The one assertion it cannot make is the bare **floor**'s own, which
admits no grant and so is made with OS-owned binaries alone.

## Named asymmetry

A place where the two platforms are not equals, written down rather than absorbed. The
compiled-profile ceiling on macOS, the mechanism's deprecation clock, denial visibility (free on
macOS, four preconditions on Linux), namespaces for bind-mounting on Linux, unix-socket
**credential oracle** denial (every macOS version, Linux only from Landlock ABI 9), the
parent-death signal that stops an agent outliving its **supervisor** (Linux only, and permanently
so — nothing in userspace can watch for a parent's death after `exec`), and the readability of a
signal's origin, which decides whether a signal sent straight to playpen while it holds the
terminal is forwarded or dropped (Linux only: macOS reports a keypress and a `kill` alike) are the
seven so
far. The ledger is kept honest by the suite that can assert the property — the **enforcement
test** set for the boundary, the transparency one for how playpen carries signals and status:
an assertion that runs on only one platform must name the asymmetry it encodes, and a backend
that makes such an assertion inapplicable has retired one rather than passed it.

## Denial

A single access the mechanism refused while a run was already live — the runtime counterpart of
a **refusal**. Observed in-band by the confined process as an errno, and out-of-band by the
operator in the kernel's own log. Always distinguishable from absence and from success:
never `ENOENT`. playpen adds nothing to it at the moment it happens.

A broker denial is the same event at L7 — the **proxy** refusing a request an **endpoint rule
set** does not permit — and is likewise distinguishable in-band from a transport failure.

## Denial trace

The kernel's own out-of-band account of what it denied one run, collected into a file the
operator named. Never written to stderr, and never a reason to weaken the boundary: there is no
permissive-with-logging mode, so a trace is either available or **refused**, and the refusal is
scoped to the request for a trace rather than to the run.

Where the platform can only offer one conditionally, each condition is named separately, because
"your kernel is too old", "the **backend** does not ask for the records" and "you cannot read the
log" are different things to act on. A trace nothing can vouch for — the **channel self-test**
failed after the run on Linux, or the log stream was not seen to attach, last the run and
drain on macOS — is marked
**unverified** rather than presented as complete, since an empty trace otherwise reads as
"nothing was denied" — the silent downgrade the whole surface exists to refuse.

## Mark

A **denial** playpen provokes under a run's **denial tag**, in a throwaway sandbox of its own, to
observe that macOS's log stream has attached before the fork and has drained after the agent
exits. The macOS counterpart of the **channel self-test**: an observation, never a fixed wait. A
mark is told from the agent's denials by the message the kernel appends, which the agent cannot
choose, and is never written into the trace. A mark that never comes leaves the trace
**unverified**.

## Channel self-test

Provoking a **denial** playpen knows the shape of, and looking for its record, to settle whether
the denial channel delivers. An **observation** and never an inference: the alternative is reading
whether the kernel's audit subsystem is switched on, which needs a strictly stronger privilege
than reading what it logged, so there is nothing to read.

It **brackets** the run — once before, once after the agent exits — because the channel can stop
working mid-run, and a flood of denials is what stops it. It is never cached, for the reason the
**floor self-test** is not: the question is whether the channel delivers *now*. A record that
arrived by a lossy path is a failure and not a pass, because accepting it would hand back exactly
the trace that reads as "nothing was denied".

## Unix-socket regime

Which mechanism, on this host, denies a **credential oracle** reached over a unix socket — or the
statement that none can, in which case the surface is a **named residual**. Stated outward only,
in the **run record** and `playpen explain`, and never in the **manifest**: it maps what is worth
attacking, which is the one thing the manifest's audience should not be handed.

## Refusal

playpen declining to launch. The standing alternative to any silent downgrade: where a
required capability is unavailable, or a workspace is incoherent, playpen refuses rather
than running with less than was asked for. A capability that can only be enforced
*cooperatively* counts as unavailable, not as degraded.

## Fault

playpen dying of its own broken invariant, making no claim about the agent. The third outcome
beside a **refusal** and the agent's own status, and the one the other two have no vocabulary
for: a **refusal** says the agent never ran, a returned status says what it returned, and a fault
says playpen cannot tell. It is reserved for a reached state that is not a contract case but a
defect, so it is never a thing an operator can provoke or a consumer should handle — only report.
Narrower than a crash: playpen stopping because it has detected its own bug, not because the host
killed it.

## Code

The stable, enumerated string naming *why* playpen said what it said. One namespace, three
prefixes: `refusal.*` for a **refusal**, `broker.*` for a broker **denial**, `bug.*` for a
**fault** — different events, and conflating them would make "playpen refused" ambiguous to the
consumers the enumeration exists to serve. The set is closed and versioned; consumers branch on
the code, never on the prose beside it. Every backend error is translated into one, never leaked.
Only the `refusal.*` prefix is bound by the release gate's requirement that every code have a
producing **enforcement test**, since a **fault** cannot be provoked by one.

## Run record

What playpen knows and the kernel cannot: which policy produced this boundary. The resolved
profile and the selection trace that chose it, the **capability set**, the **credential route**
table, the agent's pid and the **supervisor**'s own, the timestamps. Written *before* launch, since a run that refuses is the one whose record
is most wanted. Lives beyond every granted path and is unreachable from inside the boundary — a
record the agent could read is one it could be confused by, and that is enforced by a **refusal**
rather than left to the default policy's shape, because carving the directory out of a granted
root is expressible on one platform only. A bounded ring of recent runs: a
debugging aid, not an audit log — bounded in *history*, which is what that distinction protects, so
a run still going is never evicted however many have started since. The longest-running run is the
most interesting one, and was the one the ring was certain to drop.

## Named residual

A reachable surface playpen consciously declines to close, written down rather than
silently inherited. It is not the same as **out of scope**: the surface is inside the
boundary's remit, and the decision is that closing it costs more than it buys. ACP's
client-side execution, network-reachable **credential oracles** (a cloud metadata endpoint, a
credential service on host loopback), unix-socket credential oracles on Linux below Landlock ABI 9,
a browser running without its
own renderer isolation, an agent orphaned by the death of its **supervisor** while still holding
a released **provisioned area** — on macOS only, since Linux closes it by parent-death signal for
every route including `SIGKILL` (**named asymmetry** #6), and since a supervisor that has merely
lost track of the agent's status kills it rather than stranding it on either platform — the
sequential cross-profile channel a `persistent` area
opens, git push *discovery* succeeding under a read-only **endpoint rule set**, an
operator-written refreshing **minter** racing a host-level agent instance over the single-use
login they share, an audit exclude rule on Linux emptying a denial trace that playpen
cannot see the rules behind, a profile-writable directory earlier on the host's `PATH` than a
**shim**, the **run scratch** and `ephemeral` **provisioned areas** a **fault** leaves on
disk, because the alternative is running the most failure-prone code in playpen on a process that
has just declared itself broken, a signal addressed to the whole job reaching the agent twice,
which is unclosable rather than unclosed — a receiver learns a signal's sender and never its
target, so playpen cannot know the agent already has a copy — and the **proxy**'s upstream trust
store, which the launching environment names and whose provenance is stated outward rather than
closed, are the thirteen so far.

## Supervisor

The playpen process that outlives setup and remains the confined agent's direct parent for the
whole run. It exists because playpen cannot be a pure `exec` shim — ephemeral areas must be torn
down and the credential proxy hosted — and it is *transparent*: it inherits stdio untouched,
forwards signals, and exits with the child's status, or with a **fault** where it cannot learn
that status. Its lifetime is what an `exclusive`
**concurrency** claim is pinned to, so a claim cannot outlive the run that took it.

**The thread that forks is the thread that lives for the whole run.** This is a rule of its own,
not a restatement of the single-threaded-at-fork one, and it has its own reason: the agent's
parent-death signal fires on the death of the parent *thread*, not of the parent process, so a
supervisor whose forking thread exits while the process lives would kill the agent for no reason.
The older rule — no thread before the fork, or it would not have the signals blocked — can be
satisfied by starting threads *after* the fork, which is correct for signals and fatal for this
one. Hosting the **proxy** in the supervisor is the most likely thing to break it.

It stays unconfined, in the same trust class as the **minter** — it holds the real credentials the
**proxy** injects — while the confined agent is the forked child that applies the **capability set**
to itself and `exec`s. The **proxy** is hosted in it rather than detached, so the proxy cannot
outlive the run either: killing the supervisor removes the credentials from the host and leaves the
agent, if it survives, with no credentials at all.

## Retired terms

- **Egress setting**, **traffic confinement**, **allow-list fragment**, **host entry** — retired by
  [#35](https://github.com/firefly-engineering/playpen/issues/35): playpen claims nothing about
  what the agent may reach on the network, so the vocabulary for an egress allow-list names nothing.
  The environment's fragments survive as **environment fragment**.
