# Read-only roots and worktree areas are mutually exclusive, and playpen refuses the combination at launch

A workspace grants each brought root a mode of `read` or `readwrite`, which makes an
attractive shape available: declare the source repo `read`, hand the agent a writable
worktree in a provisioned area, and the agent can commit freely without ever being able
to damage the source tree. We are deliberately **not** supporting that shape. Where a
workspace declares a worktree area whose source roots are all `read`, playpen refuses at
launch rather than starting.

## Why

The shape does not work, for a reason that is invisible from the outside: a git worktree
and a jj workspace are not self-contained. Both keep their metadata in the *source*
repository's shared directory and write to it constantly — not only at creation, but on
every ref update and every index lock. Verified locally on macOS (git 2.x, jj):

- `git worktree add`, source `.git` read-only → `fatal: cannot lock ref 'refs/heads/wt'`
- an **already-created** worktree, committing, source `.git` read-only →
  `fatal: Unable to create '.../.git/worktrees/wt2/index.lock'`
- `jj workspace add`, source `.jj` read-only → `Failed to take lock for Git import/export`

So a worktree over a read-only source is not a hardened configuration — it is a broken
one. The write access the agent needs to the source's metadata directory is not optional
and cannot be provisioned elsewhere.

## Consequences

Any workspace whose agent uses worktrees must grant its source roots `readwrite`. The
blast radius therefore always includes the source repository's history, not merely the
worktree — which is a real reduction in containment relative to what the read/write split
appears to offer, and it should be stated plainly rather than discovered.

Refusing at launch rather than at first write is the load-bearing half of this decision.
The condition is statically detectable from the workspace definition, whereas the runtime
failure surfaces to the agent as `index.lock: Permission denied` from deep inside git,
with nothing connecting it to a sandbox policy. Under playpen's standing "refusal, never
silent downgrade" law, a check that can be made before exec belongs before exec.

_Amended by [#74](https://github.com/firefly-engineering/playpen/issues/74): **the launch refusal is dropped, and the
consequence above stands.** The refusal rested on the condition being "statically detectable from the workspace definition",
and it is not. An area declares its `lifetime` and `concurrency`
([ADR 0010](0010-concurrency-is-a-property-of-a-provisioned-area.md)), never what it is for, so
nothing marks one as a worktree area. Nothing ties an area to the root it would be a worktree
*of*, so "every source root is `read`" has no subject: one unrelated `readwrite` root would satisfy
it. And an agent can create a worktree in any writable path, which no launch check sees. Adding a
field to make it detectable would put per-tool knowledge of git and jj into playpen, against
[ADR 0002](0002-playpen-does-not-interpret.md). A worktree over a read-only source still fails, and
fails closed: the agent breaks and nothing escapes. So the shape stays unsupported and stated, not
refused, and `refusal.workspace.worktree-on-read-root` is retired. Letting the operator declare
such relations as checks of their own is
[#135](https://github.com/firefly-engineering/playpen/issues/135)._

## Rejected alternatives

**Grant write to the source's metadata directory only, keeping the working tree read-only.**
This would technically satisfy git, but it protects nothing worth protecting: an agent that
can write refs and the object store can rewrite the entire history, which is strictly worse
than being able to edit files. The apparent safety would be false.

**Detect the failure at runtime and report it well.** Rejected because it cannot be reported
well — playpen is not in the call path of git's lock acquisition and would be inferring the
cause from an exit code.
