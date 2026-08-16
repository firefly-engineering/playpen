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
the invoked name. It selects the agent state directory, the manifest's presentation, and
how playpen displaces that agent's own native sandboxing; an unrecognised kind is a
**refusal**.

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
than running with less than was asked for.
