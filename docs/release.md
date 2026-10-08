# Releasing playpen

The enforcement suite is the backend's definition
([ADR 0016](adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md)),
so a release is gated on it rather than on CI alone
([spec §17.1](spec.md#171-form), *Gates*).

## CI is not the gate

CI ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) runs every test, the suite among
them, on `ubuntu-24.04` and `macos-15`. It may be green with **named skips**: its `check` job
installs no Nix, so `N-store-stale` reports `skipped: skip.host.no-nix` and the job still passes.
A skip is never a failure, and never a pass either.

## The gate

A commit is releasable only when, on **one macOS and one Linux reference host**:

1. CI is green on that commit.
2. `cargo test --locked --test enforcement` ends with a summary of **zero skipped and zero
   failed**:

   ```text
   enforcement: <n> run, <m> n/a, 0 skipped; 0 failed
   ```

   `n/a` is fine: it is a row scoped to the other platform under a named asymmetry
   ([spec §15.4](spec.md#154-named-asymmetries)). Every row the platform owes must *run*.
3. `R-code-coverage` is among the rows that ran and passed: every `refusal.*` code in the registry
   ([spec Appendix A](spec.md#appendix-a--code-registry)) has a row that produces it, or is named
   by the unprovoked ledger (`UNPROVOKED` in
   [`tests/enforcement/row.rs`](../tests/enforcement/row.rs), [spec §17.2](spec.md#172-rows)).
   An entry there is a code no environment a row can build provokes, proven by a unit test
   instead, and each is decided in an issue of its own. Any other code no row produces blocks the
   release until it gets a row, is re-cut, or is decided into the ledger.

The release notes name each reference host (OS version, and on Linux the kernel and its Landlock
ABI), the commit, and the two summary lines.

## A reference host

A reference host is one on which no row skips, so it holds every precondition the suite probes
(`Precondition` in [`tests/enforcement/row.rs`](../tests/enforcement/row.rs)):

- the invoking user's home is writable (`skip.host.home-not-writable`);
- `nix-store` runs (`skip.host.no-nix`);
- `brew --prefix` names a prefix whose `Cellar` and `opt` the user can write, on Linux too
  (`skip.host.no-homebrew`);
- on Linux, Landlock offers ABI 9 or later (`skip.host.landlock-below-abi-9`).

The suite runs as an ordinary user, never as root: `R-process-fork` provokes its refusal with
`RLIMIT_NPROC`, which Linux does not enforce for root.
