# The backend grants only what the policy asked for

*Amends [ADR 0022](0022-playpen-pins-a-maintained-fork-of-nono.md).*

On macOS the floor self-test passed under an **empty** capability set: `/usr/bin/true`, `/bin/ls /`
and `/usr/bin/env true` all exited 0 with nothing granted at all. The cause is in the backend, not
the floor — nono's base profile emits `(allow process-exec*)` unconditionally, immediately after
`(deny default)`, so the capability set's execute dimension was never enforced on macOS. The fork
gains a **fourth change**: exec is emitted with the same path filters that already gate
`file-map-executable`. The spec gains the general rule at the seam: a capability the policy did not
grant is not granted by the backend.

## Why

**The floor was right and the backend was wrong, which is why three of the four obvious fixes are
wrong too.** [Spec §8.6](../spec.md#86-the-floor-self-test) says the canary asserts that a
dynamically linked OS binary exits 0 under the bare floor, and
[ADR 0014](0014-the-toolchain-is-a-declared-closure.md) says the canary exists to catch "someone
tidied the floor". Both statements were true; the assertion underneath them was not, because exec
succeeded whatever the floor contained. Fixing the test would have left the backend granting
execute to everything.

**Choosing a canary that needs a floor path is forbidden by the rule it would break.** ADR 0014
requires the floor to be "one object whose spelling never appears in a test", and
[ADR 0023](0023-the-floor-on-a-non-fhs-host-is-a-declared-closure.md) restates it as "the suite
names binaries, never paths". Picking a binary *because* it must read `/private/var/select/sh`
encodes the floor's content in the test, which is the coupling those rules exist to prevent — and
it would have to be re-chosen every time the floor or macOS changed.

**Calling it a named asymmetry would have put a false entry in the ledger.** An asymmetry records a
place where the platforms are *not equals* — macOS has no parent-death signal, Linux has no
mechanism-native Keychain. macOS is perfectly capable of gating exec per path; SBPL takes a path
filter on `process-exec*` like any other operation. The inequality was between two revisions of a
fork playpen maintains, and the ledger's worth is that its entries are true.

**Asserting empty stderr was the only honest workaround, and it buys a brittle contract.** Under an
empty set `/bin/sh -c :` exits 0 but prints `Error opening /private/var/select/sh: Operation not
permitted`, so stderr does discriminate today. It makes the canary's contract "exits 0 and says
nothing", which any future macOS version can break with a benign diagnostic, and it still leaves
execute unenforced.

**ADR 0022 set the bar for a fourth fork change and this clears it.** "Anything further waits for a
demonstrated need… Adding a change needs a demonstrated need and a suite row that asserts it." The
need is demonstrated by measurement, and under
[ADR 0016](0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md)
an assertion that can pass vacuously is a *defect*, which is the strongest form the need can take.

**The change is small, because the filters already exist.** nono's `AccessMode` is
`Read | Write | ReadWrite` with no execute dimension, so there was a question of what to gate on.
A few lines below the blanket exec rule, `file-map-executable` is already emitted per capability for
read-bearing paths — so exec reuses those filters, and one unconditional line is replaced by a loop
that already exists beside it. No new access class, and nothing is lost: `CONTEXT.md` states that a
brought root's `read` mode "grants execute as well", so read-bearing *is* the execute set today.

**An `Execute` access class was deferred, not rejected.** #63's **exclusions** carry access classes
`read`/`execute`/`write`, and subtracting `execute` alone is inexpressible without it. But #63 is
not implemented, so that need is predicted rather than demonstrated, and ADR 0022's discipline is
what keeps the fork's diff a deliberate set rather than a drift.

**It also halves the hypothesis space of a sibling ticket.** With exec blanket-allowed, read-and-map
was the *sole* gate on executing foreign code inside the boundary — and
[#122](https://github.com/firefly-engineering/playpen/issues/122) reports that gate behaving
non-deterministically. That ticket named "a Seatbelt `file-map-executable` rule in nono's base
profile" as one of two candidate causes; the rule is per-capability and restricted to readable
paths, with an upstream comment about blocking `DYLD_INSERT_LIBRARIES`, so that candidate is
refuted and the dyld launch-closure cache is the live one.

_Since resolved by [#122](https://github.com/firefly-engineering/playpen/issues/122): neither
candidate. The ungranted library is never opened — dyld's `stat` of it is blocked by the sandbox
every time — and when the caller's environment carries `DYLD_FALLBACK_LIBRARY_PATH`, dyld falls
back by leaf name to the OS library of the same name in the shared cache. Read-and-map was never
non-deterministic; the caller's environment was. No row maps an ungranted library: mapping one
needs it opened first, which every read row already asserts is denied, and the backend emits
`file-map-executable` only for readable paths._

## Consequences

- **A new negative row, classified by the kernel's denial and not playpen's translation of it.**
  Under an empty capability set the canary must fail with a platform denial errno, never `ENOENT` —
  which plugs it into `N-errno-law`'s discipline so it cannot pass because the canary merely wasn't
  there. It is deliberately *not* a refusal row: that class is "from outside, with no sandbox at
  all", and the precision of that phrase is what makes a refusal row prove refusals happen before
  confinement.

- **The row gives Linux a stated guarantee it currently has by accident.** Removing the loader paths
  from the floor makes the Linux self-test fail, and nothing asserts it. The row is `both`, and it
  would have caught this on day one.

- **The seam rule goes in the mechanism section, not in §8.2.** The floor is only where this became
  visible; the next instance will be a blanket `process-fork`, a socket rule, or a Mach service the
  base profile adds. Stated at the seam, every future instance is a spec violation rather than a
  surprise. §8.6 and §8.2 need no amendment — the spec was already right.

- **A real exposure the enforcement suite cannot see.** An agent execs helpers constantly, and
  everything it runs must now be under a read-bearing grant. A toolchain root is `read` so an
  agent's own toolchain is covered, and a copied binary in a writable area is covered because
  provisioned areas are readable too — but the thing that would actually prove it is a liveness
  probe, and `L-claude` and `L-omp` are not implemented. The change lands behind the gate ADR 0022
  prescribes, with this recorded for #106 and #107 to confirm. A temporary allowance for common
  helper paths was rejected: a path the backend adds on its own initiative is precisely the defect
  being fixed.
