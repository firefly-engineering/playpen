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
grants access to it, never creates it. Carries a mode of `read` or `readwrite`.

Contrast **provisioned area**, where playpen owns the path.

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

The thing that produces a credential for a forge scope. Named by an opaque string in the
workspace; playpen does not model any particular forge.

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

## Profile

The unit an invocation selects. Names the workspaces in play and the confinement to
apply. Selected from invocation context, never chosen by the agent.

## Policy

The document declaring every profile, workspace and shim on a host. Located by a fixed
ordered search path, first hit wins — never merged, so that "which rule won" always has
one answer. Owner-authored; playpen refuses to launch if the policy it read sits inside
anything the selected profile can write.

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
_Avoid_: manifest, capability manifest.

## Enforcement test

An assertion, made from inside a live sandbox, that something is *not* reachable. The
collected set of them is the contract a backend must satisfy — stated as negatives because
the failure that matters is a boundary that silently stopped being enforced.

## Refusal

playpen declining to launch. The standing alternative to any silent downgrade: where a
required capability is unavailable, or a workspace is incoherent, playpen refuses rather
than running with less than was asked for. A capability that can only be enforced
*cooperatively* counts as unavailable, not as degraded.

## Named residual

A reachable surface playpen consciously declines to close, written down rather than
silently inherited. It is not the same as **out of scope**: the surface is inside the
boundary's remit, and the decision is that closing it costs more than it buys. ACP's
client-side execution, the shared host loopback on macOS, and a browser running without its
own renderer isolation are the three so far.
