# The suite defines the backend, and an assertion that can pass vacuously is a defect

The enforcement suite is a table of **data rows** — `{id, class, platform, fixture, action,
expected, from}` — executed by a shipped `playpen-probe` from inside a live sandbox, reporting
JSON on stdout. Assertions come in **three classes**, not one: *negatives* (inside, must fail
with a denial errno), *positives* (inside, must succeed — admissible only where the regression
they catch is silent), and *refusals* (outside, no sandbox at all, asserting exit `125` and a
`code`). A **negative asserts two things**: that its target exists as seen from outside, and
that the read from inside fails. Absence outside is a setup failure, never a pass. Liveness is
a **second suite** with a different cadence and no power to block a playpen change.

## Why

**The suite is the backend's definition, so a vacuous pass is worse than no assertion at all.**
The owed negatives name `~/.ssh/id_*`, `~/.ssh/config`, `~/.aws`, `~/.npmrc`, the Keychain Mach
services, host temp, and a stale `…-home-manager-files/.ssh/config`. On a hosted CI runner most
of those do not exist — so a negative phrased as "the read fails" passes for the wrong reason,
and passes *most reliably* on exactly the machine where the boundary is least exercised. That is
the suite contracting the disease it exists to diagnose: a boundary that silently stopped being
enforced, certified green. Hence the two-part form, with the fixture **creating a decoy** where
the host has no real target — a decoy exercises the same path resolution and is the only form
that works on a fresh runner. ADR 0007's never-`ENOENT` law, sharpened by the Linux errno set,
stops being only a UX promise and becomes the suite's own soundness check: `ENOENT` from inside
is a **failed** negative.

**"An assertion, made from inside a live sandbox, that something is not reachable" had become
false in both halves.** ADR 0003 declared the suite negatives-only, but four positives have since
accrued — the loader canary (ADR 0006), `unshare(CLONE_NEWUSER)` succeeding (the Chromium
investigation), an `open`-mode bypass arriving unauthenticated (ADR 0013), and the per-`kind`
liveness probe (ADR 0005) — and the refusal assertions owed by ADRs 0004, 0006 and 0009 happen
where playpen **declined to launch**, so there is no inside to assert from. Three classes states
what was already true. The **admission rule** is what stops positives eroding into a general
integration suite: a positive earns its place only if its regression is silent. The canary
qualifies (`rc=134`, empty stderr), `unshare` qualifies (a future `nono` gating `clone` kills
browser automation quietly), the unauthenticated bypass qualifies (the regression still *works*,
it just leaks). "The agent starts successfully" does not — that is liveness.

**Two things must run inside, because neither can do the other's job.** The bare-floor canary
must use **OS-owned binaries only** — `/bin/echo` is dynamically linked against
`/usr/lib/libSystem.B.dylib` and needs no grant — because granting a probe its own root means the
floor under test is no longer bare, and ADR 0006's floor admits nothing under `$HOME` and nothing
under a package store, so a built probe has nowhere to live. Everything richer needs the probe:
the shell erases the `EACCES`/`ENOENT` distinction that ADR 0007 made load-bearing, and has no
spelling at all for reading an inherited credential fd or calling `unshare`. The probe's one extra
read+execute root is stated as a known perturbation rather than wished away — every negative it
makes is therefore "unreachable *even with* the probe's own root present", which is the weaker and
so safe direction.

**Batching by capability set, with the exit code carrying one bit.** One confined launch per
distinct **policy fixture**, N assertions inside it, JSON on stdout — "stdout is sacred" (ADR
0002) binds *playpen*, and the probe is the child, so stdout is its own. The exit code says
**the probe ran** or **the probe broke**, never "an assertion failed": conflating those is the
`rc=134`-with-empty-stderr trap wearing the suite's uniform. Fixtures are real policy documents
loaded through `--policy <path>`, which is why ADR 0015 pinned that flag ahead of the search path,
so each fixture is incidentally a parser test.

**Rows are data; the action is a closed enum.** The suite must absorb contributions from tickets
not yet opened without rewriting, and a hand-written function per assertion does not. But a
fully data-driven suite means inventing a language for what the probe does, and this project has
declined a pattern language three times (ADRs 0009, 0011, 0012). Adding an *instance* of an
existing check is rows only; a genuinely new *kind* adds one enum variant. The `from:` field —
generalising the fragment and route provenance of ADRs 0004 and 0009 — carries the deciding issue
and ADR, and buys the reverse query: which assertions die if ADR 0006 is revisited.

**A single-platform assertion costs a named asymmetry.** ADRs 0006 and 0014 both assert the floor
is "one object with per-platform contents", made true by the canary and the fd negative passing on
both. The asymmetry ledger now has five entries, so the honest invariant is not that most tests
run everywhere but that **adding a `macos`-only or `linux`-only assertion requires naming the
asymmetry it encodes** — which keeps the ledger from growing silently. A `both` assertion that
turns out to be *inexpressible* on one platform is a design bug to escalate, never a skip.

## Considered Options

- **One suite covering enforcement and liveness.** Rejected: they have different clocks.
  Enforcement tracks playpen and its pinned `nono`; liveness tracks other people's release
  schedules and needs the real binaries, credentials and live network. One suite means a playpen
  PR going red because someone else shipped. Two suites share one runner and one fixture format;
  enforcement gates every PR and every dependency bump, liveness gates only an agent-version or
  `kind`-table change and opens a triage question rather than blocking a merge.

- **Exit-status-only verdicts, one assertion per `playpen run`.** The purest channel, and rejected
  on cost: dozens of assertions each paying full sandbox setup. Batching per fixture keeps the
  purity where it matters — the code still carries one bit.

- **A `playpen selftest` subcommand shared with the pre-launch floor self-test.** Rejected. ADR
  0006 requires playpen to self-test the floor before *every* launch, and two implementations that
  can disagree is exactly what ADR 0011 killed `explain --self` for — so it is **one
  implementation, two callers**, the runtime self-test *being* the canary. But not a new CLI
  surface: ADR 0011 priced that at playpen's own binary inside every profile's toolchain root, and
  an in-tree suite needs no CLI to reach a library.

- **Admitting a new backend on the `both` set alone.** Rejected: "defined by the tests it passes"
  would degrade to "passes the portable subset", and the platform-specific assertions are
  precisely the ones encoding the asymmetries a new backend might change.

## Consequences

- **The `enforcement test` glossary entry is corrected**, and `liveness probe`, `policy fixture`
  and `probe` join it as distinct terms.

- **The suite contributes two assertions no ticket handed it.** First, that a **run record exists
  after a refusal** — ADR 0007 made "a run that refuses is the one whose record is most wanted"
  load-bearing and nothing checked it. Second, a **coverage assertion over the code registry**:
  every `refusal.*` code in the closed set has at least one row producing it, which is what keeps
  "the set is closed and versioned" from decaying into merely enumerated.

- **"The manifest is true" is an enforcement test**, and the cleanest positive in the suite. For a
  given fixture, every host in the manifest's reachable set is reachable and every path in the
  capability set is accessible at its stated mode — and nothing outside them is. ADR 0011 made the
  manifest a projection that describes without constituting, so drift there is silent by
  construction; three closed decisions each assumed someone else would check it.

- **The fd negative is not a kernel denial and not in the errno set.** The harness opens a
  credential fd outside and launches confined; ADR 0006's law closed everything but 0/1/2 before
  `exec`, so the probe sees **`EBADF`**. It is an enforcement test of a boundary playpen builds
  itself, and the never-`ENOENT` set does not govern it.

- **A skip is not a pass.** Preconditions are probed and a missing one produces a **named** skip
  in the report — never a silent pass, never a hardcoded platform assumption, extending the
  Linux-denial-visibility rule of "probe each precondition and refuse with a distinct code". CI may
  be green with skips; a **release requires the full set green on a reference host of each
  platform**.

  _Amended by [#29](https://github.com/firefly-engineering/playpen/issues/29): **three outcomes,
  not two.** A row **runs**; or it is **`n/a` by platform** — the Keychain Mach negative on Linux,
  the compiled-profile-ceiling refusal on macOS — which is a **named asymmetry already on the
  ledger and not a skip at all**; or it is **skipped**, meaning the row applies on this host and a
  precondition here is missing. Reporting an `n/a` as a skip makes the ledger look like a gap;
  reporting a skip as `n/a` retires an asymmetry that was never retired._

- **A `nono` bump is a PR that is red until the suite says otherwise.** ADR 0003 gated the exact
  pin "not on compilation but on enforcement tests", and the Chromium investigation wanted a future
  `nono` gating `clone` to fail the version bump rather than silently kill browser automation.
  This is the mechanism both assumed and neither specified.

- **A new backend that renders a single-platform assertion inapplicable has not failed it** — it
  has **retired an asymmetry**, which is a ledger edit and a reviewable claim, not a green check.

- **Liveness asserts the narrowest thing that catches a reintroduced startup self-sandbox**: launch
  confined, exit 0 on a trivial no-network invocation, plus one task traversing the proxy. All
  per-`kind` knowledge stays in the `kind` table (ADR 0005), so adding a kind adds a row.

- **Whether the suite can run hermetically on hosted CI runners is an open fact**, not an
  assumption — Landlock availability, `sandbox_init` under a hosted macOS runner, the four
  preconditions the Linux audit trace needs, and Nix for the closure negatives. Graduated as its
  own research ticket rather than guessed at.

  _Answered by [#29](https://github.com/firefly-engineering/playpen/issues/29): **20 of 22 rows run
  on each hosted platform**, and the decoy rule above is what saves them — without it eleven of
  thirteen negatives would be skips on a fresh runner. Three further amendments fall out. **The
  two-part form extends from negatives to positives**: the `unshare(CLONE_NEWUSER)` positive must
  assert the sequence succeeds *outside* before asserting it inside, since Ubuntu 24.04's
  `default_allow` AppArmor profile permits the outer namespace and denies every capability inside
  it — so the row **as specified passes vacuously** and must be strengthened to the nested
  `clone` → `unshare` → `CLONE_NEWPID|CLONE_NEWNET` sequence rather than skipped. **The ceiling row
  asserts playpen's refusal `code`, never a path count**: the limit is on compiled bytes (~64.7 per
  rule, crossing between 1013 and 1014 rules on the reference host), reported in `errorbuf` with
  `errno` **untouched**, so a refusal path reading `errno` gets `0` and has nothing to say. And one
  operational law — **pin the runner label, never follow `-latest`**: the suite's row set is a
  function of the kernel's Landlock ABI, so an unpinned floor is this ADR's forbidden hardcoded
  platform assumption with the sign flipped._
