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
It is what makes a coarse root safe — the precise alternative, one root per closure path, does
not fit the compiled-profile ceiling. Must exist or playpen refuses, because an exclusion whose
path has gone is a leak that reopened silently.

## Floor

The grant playpen always applies and no policy can widen or narrow: read and execute under
OS-owned paths, plus a short enumerated set of Mach services. Never under `$HOME`, never under
a package store, never writable. It is the one built-in default in the model, and it earns the
exception by deciding whether `exec` returns at all rather than what is reachable.

## Toolchain root

A read-only **brought root** naming what the agent works *with* rather than what it works *on*.
Attached to the **profile**, not to a workspace — every workspace needs it equally. Where policy
names a stable symlink, playpen resolves it and grants both link and target, because the
mechanism enforces on the resolved path.

## Run scratch

The single ephemeral writable directory playpen provisions per run and exposes as `TMPDIR`. A
property of the run, not of a workspace, so it is not a **provisioned area** — nothing outside
the run can refer to it. The host's own temp is unreachable.

## Provisioned area

A writable directory playpen creates, keyed by workspace name. The operator declares
that one must exist and what it is *for*; the path is playpen's business. Always
writable, and carries a **lifetime**.

## Lifetime

A property of a provisioned area. `ephemeral` — created at launch, removed at exit.
`persistent` — created on first use and reused by later runs of the same workspace.

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

## Credential route

The pairing of a destination — a host plus a literal path prefix — with the credential to
present there and the **delivery** that points the agent at it. The unit the **proxy** matches
against, and the reason two workspaces' credentials stay distinct in *use* and not merely at
minting: a forge names the org in the path. Two routes on one host, neither path prefix
extending the other, are ambiguous and playpen refuses.

Attaches to the **workspace** when the credential minimizes to that workspace's **forge scope**,
and to the **profile** otherwise. Both resolve into one table, provenance retained.

## Delivery

How a route's **session phantom** reaches the agent — a named environment variable today. Named
by the route, never by the **kind**, so that per-agent knowledge stays in the kind table. A
field rather than an assumption, so another transport can be added without disturbing the route.

## Session phantom

The random bearer token that stands in for every real credential inside the boundary — one per
run, not one per credential, since delivery cannot hand one tool a choice between two. The agent
presents it; the **proxy** strips it and injects the real secret, which never crosses the
boundary in any mode.

It faces both ways. Inward it contains exfiltration — a secret that is not present cannot leak
through a log line or a tool call. Outward it authenticates callers of the proxy, which is what
keeps the shared host loopback on macOS from being a credential leak.

## Egress setting

Which of `none`, `open` or `allowlist` governs a run's outbound network. A property of the
**profile**, never of a workspace — there is one boundary over one process tree, and no
channel by which a connection could be attributed to a workspace that the agent could not
forge. Independent of **forge scope**, which is stated in credential vocabulary; the two
lists can disagree, and playpen refuses rather than reconciling them.

## Proxy

The process that enforces the egress allow-list, run **outside** the boundary as a detached
sibling of the agent and reached over TCP loopback. Exists only under `allowlist` — `open`
has no proxy rather than a permissive one. It is also the sole resolver: the sandbox gets no
DNS. Terminates TLS only for hosts whose rule requires it, under an ephemeral per-session CA
that never touches disk.

The **credential broker** is this same process wearing its other hat: one process, two
lists, because "reachable" and "authenticated" are different facts.

## Allow-list fragment

A named, composable set of **host entries** the operator references from a profile — `npm`,
the forge, the model API. Data in the **policy**, never code, so the resolved allow-list is
readable. playpen ships fragments but merges none by default; there is only ever one policy
author.

## Host entry

One member of an allow-list: an exact hostname, or a left-anchored suffix matched on a label
boundary. Never a regex. Port 443 is implied — transport is HTTPS-only, so an entry names a
host, not a host and port.

## Agent state directory

The directory an agent binary keeps its own state and configuration in. Per workspace,
with an explicit read-only **share list** naming what is carried over from the real one.

## Share list

The entries of the real agent state directory made visible, read-only, inside a
workspace's own. Default-deny: empty unless named.

## Manifest

The canonical description of a workspace's layout, readable from inside the boundary.
playpen owns the facts it states; how it reaches an agent's attention is a per-harness
presentation concern.

It is also the *only* thing playpen tells an agent about its own confinement, and it says so
up front rather than at the moment of failure: alongside the layout it carries how to read a
**denial**, and that the boundary is fixed for the whole session. It is the sole inward-facing
truth — nothing playpen offers inside the boundary may state a fact the manifest does not.

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

## Shim

A stand-in for an agent binary, placed on the operator's PATH so that invoking `claude`
launches it confined. Thin by construction — it supplies a profile and a **kind** to the
core CLI and nothing else. It finds the real binary by an absolute path the policy
declares, never by searching PATH.

## Kind

Which agent binary is being wrapped (`claude`, `omp`). Always stated, never inferred from
the invoked name. It selects the agent state directory, the manifest's presentation, and the
**suppression table**; an unrecognised kind is a **refusal**, because there is nowhere to put
what playpen would need to know about it. All per-agent knowledge is confined here.

## Suppression table

The per-**kind** set of environment entries playpen sets and strips so that an agent does not
try to apply its own sandbox inside playpen's. Cooperative, and permitted to be: honouring it
buys only usability, never confinement, so a guest that ignores it merely breaks rather than
escapes.

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
with access modes, a network mode, an environment allow-list. Nothing above that — no
workspace names, no lifetimes, no profiles.

Faces *outward*, at the kernel. Contrast the **manifest**, which faces inward, at the agent.
Dumpable without launching an agent, so that "which rule won" has an answer for the filesystem.
A backend may impose a **budget** the capability set can exceed — macOS caps the compiled
profile at 65535 bytes — and exceeding it is a **refusal** in playpen's own vocabulary, never a
leaked backend error.
_Avoid_: manifest, capability manifest.

## Enforcement test

An assertion, made from inside a live sandbox, that something is *not* reachable. The
collected set of them is the contract a backend must satisfy — stated as negatives because
the failure that matters is a boundary that silently stopped being enforced.

## Denial

A single access the mechanism refused while a run was already live — the runtime counterpart of
a **refusal**. Observed in-band by the confined process as an errno, and out-of-band by the
operator in the kernel's own log. Always distinguishable from absence and from success:
never `ENOENT`. playpen adds nothing to it at the moment it happens.

An egress denial is the same event at L7 — the **proxy** refusing a host — and is likewise
distinguishable in-band from a transport failure.

## Refusal

playpen declining to launch. The standing alternative to any silent downgrade: where a
required capability is unavailable, or a workspace is incoherent, playpen refuses rather
than running with less than was asked for. A capability that can only be enforced
*cooperatively* counts as unavailable, not as degraded.

## Code

The stable, enumerated string naming *why* playpen said no. One namespace, two prefixes:
`refusal.*` for a **refusal**, `egress.*` for an egress **denial** — different events, and
conflating them would make "playpen refused" ambiguous to the consumers the enumeration exists
to serve. The set is closed and versioned; consumers branch on the code, never on the prose
beside it. Every backend error is translated into one, never leaked.

## Run record

What playpen knows and the kernel cannot: which policy produced this boundary. The resolved
profile and the selection trace that chose it, the **capability set**, the egress list, the
pid, the timestamps. Written *before* launch, since a run that refuses is the one whose record
is most wanted. Lives outside every workspace and is unreachable from inside the boundary — a
record the agent could read is one it could be confused by. A bounded ring of recent runs: a
debugging aid, not an audit log.

## Named residual

A reachable surface playpen consciously declines to close, written down rather than
silently inherited. It is not the same as **out of scope**: the surface is inside the
boundary's remit, and the decision is that closing it costs more than it buys. ACP's
client-side execution, the shared host loopback on macOS, and a browser running without its
own renderer isolation are the three so far.
