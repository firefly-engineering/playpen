# playpen pins a maintained fork of nono

playpen depends on **`firefly-engineering/nono`**, a maintained fork of nono in its own repository,
rather than on crates.io releases. The fork carries playpen's changes on a `playpen` branch,
rebased onto upstream tags. playpen pins it as a Cargo `git` dependency with a fixed `rev`, never a
branch, and `nono` and `nono-proxy` come from the **same revision**. Upstreaming is optional and
later: it is not an exit condition.

The fork carries exactly three changes from day one. Anything further waits for a demonstrated
need.

## Why

**Three decisions were parked waiting on an upstream that is not coming soon.**

- [ADR 0020](0020-playpen-claims-credential-confinement-only.md) made unix-socket credential
  oracles default-deny. On macOS, nono's `AllowAll` grants every unix socket, so ADR 0020 had
  playpen refuse on macOS until an upstream release fixed it.
- On Linux, ADR 0020 relies on Landlock's ABI 9 `FS_RESOLVE_UNIX` right. nono's ABI probe stops at
  V6 ([#23](https://github.com/firefly-engineering/playpen/issues/23)), so through upstream nono
  that enforcement could never be negotiated. The Linux half of ADR 0020 was unreachable, which
  ADR 0020 had not noticed.
- [ADR 0007](0007-playpen-owns-the-half-the-kernel-cannot-know.md)'s Linux denial trace needs
  `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON`, which nono never passes.
  [#29](https://github.com/firefly-engineering/playpen/issues/29) called that "a permanent red until
  upstream".

The operator is not willing to go upstream until playpen works. A maintained fork closes all three
now.

**A fork in its own repository is not vendoring.** [#10](https://github.com/firefly-engineering/playpen/issues/10)
rejected vendoring because it copies the dependency into playpen's tree and turns a supply-chain
risk into an untracked maintenance one. A fork keeps nono a separate, versioned dependency with its
own history, so its diff against upstream is visible at any time. [ADR 0003](0003-nono-is-the-mechanism-backend.md)'s
exact pin, its narrow `sandbox` + `capability` surface and its seam are unchanged. Only the source
of the pin changes.

**Each change keeps the logic where ADR 0003 put it.** On macOS the fix is made in nono's rendering
rather than by emitting caller rules last and having playpen write SBPL. That keeps SBPL authoring
inside the backend, and it is the clean semantic fix if it is ever upstreamed.

## The fork's changes

1. **macOS: unix sockets default-deny under `AllowAll`.** Outbound is rendered as IP-only
   (`(remote ip "*:*")`). Unix sockets go through nono's existing explicit-grant path, which keeps
   the `mDNSResponder` rules every macOS DNS lookup needs. playpen grants the sockets under its
   writable areas. Asserted by `N-unix-socket`.
2. **Linux: the ABI probe extends to V9, and pathname-socket `connect()` is gated** by
   `FS_RESOLVE_UNIX` against the filesystem grants. Asserted by `N-unix-socket` on a kernel ≥ 7.1.
3. **Linux: `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` is passed** where the kernel offers ABI 7.
   Asserted by `R-trace-denials`.

## Considered Options

- **Wait for upstream, refusing on macOS meanwhile.** Rejected: it leaves the flagship platform
  unusable, and the Linux ABI-9 gap open, for an unknown time.
- **Emit `platform_rules` after the network section and have playpen write the unix-socket SBPL.**
  Rejected: it is a smaller diff, but it puts SBPL authoring in playpen, against ADR 0003.
- **Vendoring.** Still rejected, for #10's reasons.

## Consequences

- **The macOS refusal in ADR 0020 goes away.** The pin carries the fix.
- **ADR 0020's Linux enforcement becomes reachable** on kernels ≥ 7.1. Below that, the
  named residual stands.
- **`refusal.trace.backend-no-logging` stops being permanent.** It remains in the code registry, as
  the refusal a pin without the flag would produce.
- **Every rebase of the fork, and every new revision, is a playpen PR** that stays red until the
  enforcement suite passes. That is the gate [ADR 0016](0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md)
  already applies to a version bump. Rebasing onto upstream is playpen's own maintenance cost,
  owned and stated.
- **The fork's diff is a deliberate set.** Adding a change needs a demonstrated need and a suite row
  that asserts it.

- _Amended by [ADR 0029](0029-the-backend-grants-only-what-the-policy-asked-for.md): **the set is
  four, and the fourth is the first to clear the bar above.** nono's macOS base profile emits
  `(allow process-exec*)` unconditionally, so the capability set's execute dimension was never
  enforced there and the floor self-test passed under an empty capability set — a vacuous assertion,
  which ADR 0016 calls a defect. Exec is now emitted with the same path filters that already gate
  `file-map-executable`, so the change is one unconditional line replaced by a loop beside it, with
  no new access class in nono. The bar held: the need was measured, and the asserting row is a new
  negative that fails if nothing is granted. An `Execute` access class, which #63's exclusions will
  want, is deferred as predicted rather than demonstrated._
- _Amended by [#124](https://github.com/firefly-engineering/playpen/issues/124): **the set is
  five.** The kernel logs a macOS denial under the denied process's pid, and the log record carries
  nothing the sandboxed tree shares, so `explain --run` could find the child's denials but not its
  descendants', which for an agent are most of them. A message on the default deny is logged with
  every denial in the tree; the fifth change makes it an opt-in on nono's capability set, and
  playpen sets it to the run's tag. The need was measured — a forked process's denial missing from
  the printed command — and `P-denial-tree` asserts it._
