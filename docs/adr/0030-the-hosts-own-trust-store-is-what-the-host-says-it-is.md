# The host's own trust store is what the host says it is

The broker verifies every upstream destination against "the host's own trust store". That phrase
now has a stated meaning: **the store the host names**, read the way every Unix TLS client reads
it. `SSL_CERT_FILE` or `SSL_CERT_DIR` in the *supervisor's own* environment, when set, **replaces**
the platform search outright; when neither is set, the broker uses the platform store. The launching
environment can therefore decide what the broker trusts upstream, with no policy field, no flag and
no build feature. That lever is kept, and recorded as a **named residual** rather than closed.

Its provenance is **stated**: `playpen explain` and the run record report whether a run's upstream
store came from the environment or from the platform search. The manifest does not.

## Why

**The lever exists, and nothing said so.** `Broker::new` loads its roots with
`rustls_native_certs::load_native_certs()`, which reads `SSL_CERT_FILE` and `SSL_CERT_DIR` *before*
dispatching to any platform loader. This was measured: a loopback TLS destination with a root of its
own, that root in a PEM file, `SSL_CERT_FILE` pointed at it, and a request driven through a
`Broker::new` proxy arrived upstream with the secret injected and the phantom stripped. The commit
that introduced interception,
[4e722ce](https://github.com/firefly-engineering/playpen/commit/4e722ce), made `Broker::trusting`
unreachable from a launch because "a proxy that could be told what to trust is a proxy that can be
told to trust an attacker". The environment could already tell it — and neither the spec nor any ADR
recorded that.

**The launching environment is trusted by construction.** Whoever runs playpen already hands it a
policy, a minter command and the credentials that minter exchanges.
[ADR 0008](0008-credentials-are-minted-outside-and-only-phantoms-cross-the-boundary.md) mints
outside the boundary precisely because the outside is where the operator is, and
[ADR 0020](0020-playpen-claims-credential-confinement-only.md) claims credential confinement only:
playpen keeps the means of using a credential out of the *agent's* reach, and makes no claim against
the operator who launched it. A minter runs with the supervisor's environment inherited, looked up
on its `PATH`, and if its TLS stack reads `SSL_CERT_FILE`, its own exchange with the forge verifies
against the store that variable names. Whoever can set the supervisor's environment already decides
which executable mints every secret the broker holds, and what that executable trusts while minting
it. The broker's upstream store is not the weak point of that position.

**`SSL_CERT_FILE` *is* the host's answer.** openssl, curl, git and `rustls-native-certs` agree that
these variables are how a Unix host — or a container image, or a Nix shell — names the roots it
trusts. They differ in reach — openssl reads each variable in place of its own default, so setting
one leaves the other default searched, where `rustls-native-certs` drops the whole platform search
when either is set — but not in what the variables *mean*. A broker that honours them is not taking
an attacker's instruction; it is asking the host "what do you trust" and taking the host's answer,
which is what the phrase "the host's own trust store" always claimed to do. So
[4e722ce](https://github.com/firefly-engineering/playpen/commit/4e722ce) is right about what it
defended — no *policy field* and no *flag* reaches the upstream store, and none will — and wrong
only in implying that the store is a fixed property of the machine.

**It is not closeable at an acceptable cost.** In `rustls-native-certs` 0.8 the per-platform loader
sits behind a private module alias; the only public entries are `load_native_certs()`, which is
environment-first, and `load_certs_from_paths()`, which takes explicit paths and searches nothing.
On Linux the platform loader *is* `openssl_probe::probe()`, which is itself environment-first, so
behind this dependency there is no environment-free store on Linux at all. Only macOS's
security-framework branch ignores the environment, and the environment check runs above it. This
rests on the crate's layout at 0.8.4, under a `0.8` range; `P-endpoint` is what notices if a release
changes it.

**A residual and not an asymmetry.** The environment check runs above the platform dispatch, so the
lever reads as open on both platforms and closed on neither — measured on Linux, owed on macOS by
`P-endpoint` ([#139](https://github.com/firefly-engineering/playpen/issues/139)). That is what
[§18](../spec.md#18-named-residuals) records, as distinct from the asymmetry ledger
([§15.4](../spec.md#154-named-asymmetries)).

## Considered Options

The question opened as a testing problem — how a suite row observes what reached a host-trusted
destination ([#136](https://github.com/firefly-engineering/playpen/issues/136)) — and the options
for that are what surfaced the lever.

- **A public echo service as the row's destination.** Rejected: a CI gate on a third party's uptime,
  and the row's secret sent to it.
- **A real provider, asserted indirectly** through its own `401` on a deliberately wrong token.
  Rejected: it shows that *something* was substituted, not that the secret arrived in the header the
  phantom came in.
- **Adding the row's root to the host's trust store.** Rejected on its face: a suite that mutates
  the host's trust store is worse than the gap it closes.
- **`Broker::trusting` behind a cargo feature the release build never enables.** Rejected: it is a
  seam in the shipped source whose only purpose is to tell the proxy what to trust, which is the
  object [4e722ce](https://github.com/firefly-engineering/playpen/commit/4e722ce) refused to build.
- **Close the lever**, so the broker ignores the environment. Rejected, for four reasons. The
  library offers no environment-free entry point on Linux. Clearing the variables around the call is
  `unsafe` under edition 2024, process-global, and discards the only way some container images name
  their store. Re-implementing openssl-probe's candidate list means playpen owns a per-distribution
  path list forever, brittle in exactly the place
  [ADR 0023](0023-the-floor-on-a-non-fhs-host-is-a-declared-closure.md) says hosts differ. And it
  would make the broker disagree with every other TLS client on the same host about what that host
  trusts.
- **Keep the lever, name it, state its provenance.** Chosen.

## Consequences

- **A named residual in [§18](../spec.md#18-named-residuals): the broker's upstream roots are the
  host's to name.** The entry names the `P-endpoint` row, and the row's `from:` cites this ADR,
  because that row *is* the residual's assertion: it points `SSL_CERT_FILE` at a harness-side
  loopback destination's root on its own launch, and passes only if the ambient variable was
  honoured. The documentation and the assertion are one observation, and
  [ADR 0016](0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md)'s
  reverse query then answers which assertions die if this decision is revisited. A second row
  asserting the provenance *string* would assert a string where this one asserts the behaviour.
- **The row sets the variable on one launch, never on the suite.** A per-suite store would narrow
  every other row's upstream trust and make one row's failure read as another's. The store is
  *replaced* rather than extended, which is what the row wants: a broker trusting only the row's
  root cannot pass by having reached something else.
- **The row closes the macOS question or escalates it.** The environment check sits above the
  platform dispatch, so it reads as cross-platform, but it has been measured on Linux only. The row
  is `both`; if it proves inexpressible on macOS, that is a design bug to bring back here, never a
  skip.
- **Provenance is stated in `explain` and the run record**
  ([#141](https://github.com/firefly-engineering/playpen/issues/141)), beside the unix-socket regime
  ([§6.3](../spec.md#63-credential-oracles)), which is the same kind of fact: a property of the host
  that decides what a run is exposed to. `explain` is where an operator asks "what will this run
  trust"; the record is where they ask it afterwards.
- **The manifest does not state it.**
  [ADR 0011](0011-the-manifest-is-a-generated-projection-and-playpen-states-facts-never-instructions.md)
  makes the manifest a projection of what the agent can act on, and the agent cannot act on the
  supervisor's upstream trust basis: it cannot change it, reach around it, or observe its effect
  except as a destination that fails to verify.
- **No egress precondition.** With every route-bearing row on a loopback destination, no enforcement
  row needs a real network, so `skip.host.no-egress` leaves [§17.2](../spec.md#172-rows) and no
  `Precondition::Egress` is written. A precondition variant no row references is a dead arm that
  reads like coverage.
- **`Broker::new`'s doc comment says what the code does.** "The host's own trust store" names the
  environment-first read, and `Broker::trusting`'s comment stops implying the store is immutable.
- **The child's own store is a separate question.** playpen writes `SSL_CERT_FILE` into the child as
  the bare session CA; for a Rust tool inside the boundary that same environment-first read loses
  every host root ([#140](https://github.com/firefly-engineering/playpen/issues/140)). This ADR is
  about the supervisor's reading of the variable, not the child's.