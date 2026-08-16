# Concurrency is a property of a provisioned area, and playpen arbitrates only what it provisions

Two concurrent runs of one workspace were handed the *same* provisioned-area path, because ADR
0001's model keys every area by workspace name. The fix is not a locking policy bolted onto the
existing model but a missing field: a `persistent` area declares `concurrency: exclusive |
shared`, defaulting to `exclusive` and enforced by an advisory lock held by playpen's supervisor
process for the life of the run. An `ephemeral` area is re-keyed by **run** rather than by
workspace, which removes the question there entirely. Nothing outside playpen's own provisioned
paths is arbitrated.

## Why

**`lifetime` was carrying two unrelated meanings.** A `persistent` area is either a **cache** —
a cargo or npm or model-weights directory, where concurrent sharing is not merely tolerable but
correct, and where the tool that owns the directory already does its own locking — or a
**working area**: a landing zone, a worktree root, a place an agent *works*. These want opposite
answers to the same question, and `persistent` covered both. Any single global rule was
therefore going to be wrong for half the cases, which is why the ticket's three charted options
(refuse / subdivide / share) all felt unsatisfying: each was a global answer to a question that
is per-area.

**Sharing a working area is not a locking problem that git or jj solve.** Their locks protect
metadata — `index.lock`, ref updates — not two agents' editing intent. Two agents in one jj
working copy overwrite each other's edits with no error from either tool, which is silent
corruption of the flagship case. So "share it and let the tools coordinate" is not a
conservative default; it is the failure mode this project rejects everywhere else, wearing the
clothes of restraint.

**Refusing globally would kill the case herdr exists to serve.** A fleet of agents on one
workspace is the intended workload, not an accident. `exclusive` as a *default* keeps the
accidental collision a refusal while leaving the operator a one-word way to say the area is a
cache.

**Ephemeral areas were broken worse, and by keying rather than by contention.** `ephemeral`
means created at launch and removed at exit; keyed by workspace name, two concurrent runs get
one path and the first to exit deletes it out from under the survivor. That is a *deletion*, not
contention, and its symptom is an `ENOENT` on a path the manifest promised — colliding with ADR
0007's law that a denial is never `ENOENT`. Nothing outside the run can refer to an ephemeral
area, so the workspace name buys it nothing: this is the same argument that already made the
**run scratch** a property of the run.

**Arbitration stops at the boundary of what playpen creates.** The sharpest contention is not in
the area at all — ADR 0001 established that two worktrees write the *source* repo's `.git` or
`.jj/repo` on every ref update, and that source is a **brought root**, a path playpen was handed
and never created. Locking it would mean playpen asserting an exclusive claim over an operator's
tree that every non-playpen process ignores: cooperative enforcement in a new costume, which
ADR 0004 and ADR 0005 have each already rejected. The manifest can state the fact; it cannot
enforce it.

## Consequences

- **The lock is an advisory `flock` held by the supervisor**, on a lock file in playpen's own
  state directory — outside every workspace and unreachable from inside the boundary, on the
  same reasoning that places the run record there (ADR 0007). Crash-safety falls out of the
  kernel rather than from a staleness rule: the supervisor dies for any reason and the lock
  releases, so there is no pid-reuse race, no stale-lock reclamation, and no "playpen refuses
  forever" failure mode — which is the worst way a refusal-first design can fail. The lock fd
  stays in the **parent**; the sandboxed child still closes everything but 0/1/2, so ADR 0006's
  fd law is untouched.

- **A busy exclusive area refuses immediately and never queues.** ADR 0002 fixed refusal as an
  immediate `125` plus one machine-readable line, and a launch that sometimes blocks for an
  unbounded time is a different contract than the one herdr and buzz were handed — both invoke
  expecting a process or an error. The code is `refusal.area.busy` and it names the **holding run
  id**, so `playpen explain --run <id>` turns "busy" into who, since when, and under which
  profile: exactly the half ADR 0007 says playpen owns and the kernel cannot know.

- **`concurrency` is valid only on the `persistent` variant.** ADR 0009 made the areas table a
  strict serde type, so an internally-tagged enum on `lifetime` makes declaring concurrency on
  an `ephemeral` area a schema refusal with file, line and column — rather than a field silently
  ignored on the variant where it means nothing.

- **The landing zone gets no special case.** It is a working area and wants `exclusive`, but
  forcing it would put per-purpose knowledge inside playpen, which is the interpretation ban of
  ADR 0002. The default already lands it in the right place, and an operator who genuinely wants
  a shared drop directory can say so.

- **The answer is profile-independent.** ADR 0009 made the policy one document of keyed tables,
  so workspace `foo` is one object: two profiles referencing it reference the same entry and the
  same path, and there is no disagreement to resolve.

- **Two named residuals, not enforcement.** First, `SIGKILL` the supervisor without its process
  group and the agent is orphaned, still writing the area, while the lock has already released —
  a second run can then acquire an area a live orphan is in. Closing it requires the *child* to
  hold the lock, which needs an inherited fd, which is ADR 0006's law; the blast radius is one
  workspace's area rather than the boundary, so the law wins. Second, a persistent area is a
  **sequential cross-profile channel** — a high-egress profile writes it, a locked-down profile
  reads it on the next run, and nothing in the model notices. The identical channel already
  exists through brought roots granted to both profiles, where it is unambiguously the
  operator's business; singling out provisioned areas would be arbitrary, and enforcing it at all
  would require playpen to model information flow, a vocabulary it does not have and should not
  acquire. The operator's lever is workspace scoping, where ADR 0005 landed the same class of
  problem.
