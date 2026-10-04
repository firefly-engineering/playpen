# The state directory is unreachable by refusal, because a carve-out is not portable

[Appendix C](../spec.md#appendix-c--assembly-choices) item C7 requires playpen's state directory
to be outside every workspace and not profile-writable, and
[§14.1](../spec.md#141-the-run-record) requires the run record to be unreachable from inside the
boundary — but nothing checked it, so a brought root of `~` made every record readable and, at
`readwrite`, forgeable. A launch refuses when any granted path reaches the state directory, under
a new code `refusal.state.reachable`. Carving the directory out of an otherwise-granted root was
rejected: Seatbelt can deny inside an allowed subtree and Landlock cannot.

## Why

**The requirement already existed; only its enforcement was missing.** C7 and §14.1 both state it.
The directory was unreachable in practice for one reason only — nothing granted it, because the
floor never reaches under `$HOME` — which is a property of the default policy rather than of the
model. This ADR records an enforcement decision, not a new rule, which is why the code is a
refusal and not a change to what playpen promises.

**An exclusion would work on one platform.** The alternative was to grant the root and subtract
the state directory with an exclusion (the feature
[#63](https://github.com/firefly-engineering/playpen/issues/63) builds). Seatbelt can express a
deny inside an allow; Landlock is an allow-list with no deny rules, so there is no way to punch a
hole in a granted subtree. A fix available on one platform is not a fix, and the alternative to
refusing would have been a **named asymmetry** in the *reachability of the run record*, which is
the one place this project should least accept platform inequality. Recording this matters because
#63 will make exclusions a real, familiar feature, and the next reader will reach for one here.

**Reachability is the breach, not writability, so the mode does not enter.** `refusal.integrity.
writable` was the obvious code to widen and its name would have had to become false: a `read` root
over the records is a breach with nothing writable to report. §14.1's own reason is that "a record
the agent could read is one it could be confused by", and a record carries the resolved profile,
the selection trace, the capability set and the route table — a map of the boundary, handed to the
thing being confined. One code for both, with the mode named in the sentence, because the operator's
remedy is the same single action either way and two codes for one remedy is how a registry stops
being branchable.

**The exemption is structural, not a list.** The state directory is not private in its entirety:
[#76](https://github.com/firefly-engineering/playpen/issues/76) puts agent state directories
*inside* it and grants them to the agent by design, so "a granted path inside the state directory"
is the intended arrangement rather than the bug. The rule is therefore not about who declared a
path but about where the path came from: **every** granted path is checked, and only subtrees whose
paths playpen *derived from* the state directory are exempt. Derivation is the thing that makes the
exemption safe — those paths are inside because playpen computed them from the directory, never
because something was granted that happens to contain it. An enumerated exemption list would fail
open for every tenant nobody remembered to add, and #72 and #76 are both arriving.

**It also closes the breach #76 would otherwise have.** A root over the state directory does not
merely expose the records; it exposes *other profiles'* agent state, which is what
[ADR 0021](0021-agent-state-belongs-to-the-profile.md) exists to prevent. The ticket's framing
treated #72's lock files and #76's state directories as the same case; they are not, and the second
is the one that would have been missed.

## Consequences

- **A new code, `refusal.state.reachable`, at the existence tier.** §10.5 already files writability
  under Existence, and a containment check that resolves symlinks is the same kind of fact about
  this host at this moment — so it never runs at build time and is skipped under
  `check --no-filesystem`.

- **C7's wording widens, because the rule is broader than it says.** "Outside every workspace"
  omits **toolchain roots**, which are attached to the profile, and exclusions, and the floor. A
  requirement narrower than its own enforcement is what makes a reader distrust the document:
  someone would declare a toolchain root over `~` and be refused by a rule the spec does not state.

- **The floor is checked too.** On a non-FHS host the floor is a declared closure read from a
  `PLAYPEN_FLOOR`-selected directory ([ADR 0023](0023-the-floor-on-a-non-fhs-host-is-a-declared-closure.md)),
  so it is a grant that is neither policy-declared nor state-derived. ADR 0023's "an operator who
  can set that variable can replace the binary" is sound about trust but is not a reason to skip a
  free check, and a compiled-in FHS floor can never trigger it.

- **No named asymmetry.** The platform difference explains a *rejected* option; the shipped
  behaviour is identical on both. The ledger should not gain an entry for it.

- **The refusal's own record is written into the directory it is refusing about.** The record opens
  before launch — deliberately, since the run that refuses is the one whose record is most wanted —
  and the check needs the resolved profile's grants, which are known only after parsing and
  selection. No agent is ever forked on this path, so the window has no reader. Deleting the record
  on this refusal would make it the only refusal class without one, against §14.1's reasoning.

- **Its suite row uses a synthetic state directory**, not the real `$HOME`.
  [#118](https://github.com/firefly-engineering/playpen/issues/118) is open because suite rows that
  write to the real home leave decoys behind when killed; the check compares resolved paths and does
  not care whose home it is, so the realism buys nothing and the hazard is real.
