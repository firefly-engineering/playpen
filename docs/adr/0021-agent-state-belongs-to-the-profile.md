# Agent state belongs to the profile

The **agent state directory** is keyed by **profile × kind**, not by workspace. It is persistent
and `shared`: every run of a profile with a given kind gets the same directory, and playpen says
nothing about its contents. The read-only **share list** moves from the workspace to the profile.
The **presentation adapter** renders only facts that are stable across a profile's runs. If a
share entry names the same file the adapter renders into, the two are composed by reference and
never by content.

## Why

**Keying by workspace leaks across boundaries.** [#4](https://github.com/firefly-engineering/playpen/issues/4)
made the state directory per workspace, before profiles referenced lists of workspaces in
earnest. The directory holds session transcripts, history and memory, and a transcript contains
whatever its run could read. Take profile `P1 = [A, B]` and profile `P2 = [A]`. If `P1` writes into
A's directory, B's contents land where `P2` reads them, although `P2`'s boundary was never granted B.
This is the sequential cross-profile channel ([ADR 0010](0010-concurrency-is-a-property-of-a-provisioned-area.md)),
with one difference: here playpen would have chosen the shared path.

The rule that avoids it: **state is keyed by exactly what bounds the reach of the runs that write
it.** That unit is the profile, the one that maps 1:1 onto the boundary. Toolchain, `set:`,
profile routes and the run scratch already attach to the profile for the same reason. And it
answers the multi-workspace question the way [ADR 0014](0014-the-toolchain-is-a-declared-closure.md)
answered "which workspace's temp is `TMPDIR`?": by moving the thing to the unit that has exactly
one answer.

**The directory is the agent's, so it is `shared`.** herdr's whole point is a fleet of agents on
one profile, so `exclusive` would refuse its intended workload. The agent already runs several
sessions against one config directory outside playpen. That makes this ADR 0010's **cache** case,
where the owning tool handles its own concurrency. No `concurrency` field is added.

**Sharing the directory makes the rendered file shared too, so it says only what every run
shares.** A run's manifest carries facts specific to that run: its scratch path, its ephemeral
areas, its unix-socket regime. Rendered into one shared file, a later run would overwrite them,
and an earlier run's agent would read another run's paths. That is a false statement about its own
boundary, which [ADR 0011](0011-the-manifest-is-a-generated-projection-and-playpen-states-facts-never-instructions.md)
exists to prevent. So the rendered view carries **profile-stable facts only**: the workspaces,
their roots and modes, persistent areas, credential routes and their delivery variables, endpoint
rule sets, and failure interpretation. It also states, as a fact, that this run's full layout is in
the file named by `$PLAYPEN_MANIFEST`. It is written to a temporary file and renamed into place on
every launch, so concurrent writes of identical content are harmless.

**One author per file: compose by reference.** The likeliest share entry of all is the operator's
own `CLAUDE.md`, and the shipped `claude` (2.1.283) loads exactly one user-level instruction file,
`CLAUDE.md` in its config directory, which supports `@path` imports. The adapter owns that entry
point. A share entry naming it is not linked in. Instead, the rendered file ends with the kind's
import line pointing at the real file, and that file is granted read-only. Each file keeps one
author, and no content is merged. Import syntax is per-kind knowledge, so it lives in the
adapter, which belongs to the kind table anyway. For a kind with no import mechanism, the
collision is a refusal, `refusal.state.collision`, never a merge.

## Considered Options

- **Workspace × kind, using the first-listed workspace.** Rejected: it makes list order
  meaningful, which [ADR 0009](0009-the-policy-is-one-strict-document-and-its-schema-is-generated.md)
  avoided, and it keeps the leak.
- **Run × kind, ephemeral.** Rejected: it has no leak and no contention, but no history, memory or
  MCP state survives between runs. Only the share list would carry anything over.
- **The exact workspace set × kind.** Rejected: it is equivalent to the profile whenever two
  profiles name the same set, and it adds an implicit key nobody wrote.
- **The full manifest rendered, last writer wins.** Rejected: it states another run's facts.
- **A rendered file per run, in the run scratch.** Rejected: pointing the agent at it needs a
  per-kind argv flag, and the kind table holds no flag spellings.
- **Refusing a share entry that collides with the rendered file**, or letting the share entry win.
  Rejected: the first costs the operator their global instructions inside every run, and the
  second leaves the manifest silently unread.

## Consequences

- **Schema.** `profiles.<p>.agent_state.<kind>.share` replaces `workspaces.<w>.agent_state`.
- **Lifetime.** The directory is created on first use under playpen's state directory and never
  removed by playpen. Renaming a profile starts a fresh one.
- **Cost.** Two profiles sharing workspace A no longer share A's agent history. That separation is
  exactly what the leak argument requires.
- **Edge case.** A policy edit made while a run is live re-renders the shared file at the next
  launch, so the live run's agent can read facts from the newer policy. This is tolerated: the
  rendered view carries no compatibility promise, and `$PLAYPEN_MANIFEST` stays true for each run.
- **New code.** `refusal.state.collision`.
- **Implementation-time checks**, covered by the liveness probe: that `claude` loads
  `$CLAUDE_CONFIG_DIR/CLAUDE.md` and follows an absolute `@` import, and which entry point `omp`
  reads.
