# A guest's own sandbox fails closed, and playpen has no browser mode

playpen does not layer over, negotiate with, or verify an agent's built-in sandbox. It
**suppresses** it cooperatively via a per-**kind** signal (`CLAUDE_CODE_SANDBOXED=1` for
`claude`), and where suppression fails the guest's nested `sandbox_init` returns `EPERM` and
the guest dies — a liveness failure, never a weakened boundary. playpen offers **no
browser-enabled versus hardened profile shapes**: it never launches a browser and never sees
its argv, so Chrome's lost renderer isolation is recorded as a **named residual** rather than
modelled as a switch.

## Why

**The premise was wrong, and correcting it collapsed most of the problem.** The question was
framed as "Claude Code ships its own SBPL profile, so playpen must replace it and must be at
least as strict." Reading the shipped binary (`claude` 2.1.224, this host) shows Claude Code
does **not** self-sandbox at startup. Its Seatbelt use is **per-Bash-tool-call**, through a
separately-installed runtime (`/sandbox install`) that builds a child environment prefix —
`SANDBOX_RUNTIME=1`, `TMPDIR=…`, a loopback proxy allow-list — and it is **opt-in and off by
default**. There is no launch-time profile for playpen to be "at least as strict" as. The
collision is narrower than assumed and lands per bash call, not per session.

**And the collision fails in the safe direction.** macOS sandboxes cannot nest — a second
`sandbox_init` inside an existing sandbox returns `EPERM` and the new profile is *ignored*
rather than intersected. Applied here that is a gift: a guest that tries to confine its own
children inside playpen gets an error, and the child either does not run or runs under
playpen's boundary. The one outcome the mechanism cannot produce is a child escaping to a
weaker profile. **The failure mode of guest-sandbox collision is a dead agent, never a weakened
boundary** — which is what demotes this from a security decision to a usability one.

**Suppression is cooperative, and that is permitted here.** `CLAUDE_CODE_SANDBOXED` is read by
Claude Code to mean "I am already confined": it auto-accepts the trust dialog and skips
project-settings gating. Relying on the guest to honour it looks like the standing
no-cooperative-enforcement law, but the law does not bite, because cooperation buys only
*usability*. If the guest ignores the signal, the boundary is still exactly correct — bash
calls merely break. Nothing about confinement is delegated to the guest's good behaviour, which
is the precise thing the law forbids.

**Detecting a self-sandboxing guest at launch was rejected.** Refusing to start when the guest
is *configured* to sandbox itself requires playpen to read and interpret the guest's own
settings files — per-agent interpretation of exactly the kind ADR 0002 forbids — in exchange
for converting a loud runtime failure into a slightly earlier loud failure. Pinning supported
agent versions in policy was rejected on the same balance: it is a maintenance treadmill that
refuses working configurations to guard against a failure that is already fail-closed.

**Browser mode is not playpen's to offer.** Chrome dies inside an outer SBPL profile and runs
only with `--no-sandbox`. But playpen never launches Chrome — the *agent* does, and ADR 0002
puts argv past `--` beyond playpen's reach. A `browser: enabled|denied` field in the manifest
would be advisory: the agent can ignore it, which is cooperative enforcement in a new costume.
The honest options were therefore a filesystem-level denial of the browser binary, or no
switch at all. The residual is smaller than it first appears: Chrome without its own sandbox is
still inside *playpen's* boundary, so the blast radius is the workspace — which is exactly what
the threat model's tier one promises. The operator already has the right lever, and it is
workspace scoping: a buzz-class profile gets a thin workspace.

## Consequences

- **`kind` now selects a fourth thing: the suppression table.** Alongside the agent state
  directory, the manifest presentation and how native sandboxing is displaced, each kind
  carries a small playpen-owned table of environment to set and environment to strip. This is
  stated as a law: **per-agent knowledge is confined to the `kind` table.** It is what gives
  "an unrecognised kind is a refusal" its teeth — an unknown agent cannot be run generically,
  because there is nowhere to put what playpen would need to know about it.

- **The suppression table's entries must survive the environment allow-list.** Default-deny on
  env and a kind table that injects env are the same mechanism seen from two directions; the
  env work owns reconciling them.

- **The enforcement suite gains a per-kind liveness probe.** Distinct from the enforcement
  tests, which assert negatives from inside a live sandbox: this one launches the real agent
  binary confined and asserts it still *works*, run on each agent version bump. It is the only
  thing that catches a future agent reintroducing a startup self-sandbox before users do.

- **Chrome's lost renderer isolation is a named residual** — the third, alongside ACP's
  client-side execution and the shared host loopback on macOS. Untrusted web content parsed
  under `--no-sandbox` executes at full workspace privilege. Written down rather than silently
  inherited, and answered by workspace scoping rather than by a profile flag.

- **If a browser distinction is ever wanted, it must be the filesystem form** — denying
  `file-map-executable` on the browser binary under a hardened profile, so the refusal is
  enforced rather than announced. The advisory-manifest form is ruled out permanently.

- **Chromium's viability on Linux under the chosen backend is unverified.** Chromium needs two
  nested user namespaces; Landlock does not gate them, but whether nono's seccomp filter
  permits `clone(CLONE_NEWUSER)` is unknown. This is a liveness question only — with
  `--no-sandbox` the need disappears — but it decides whether browser automation runs on Linux
  at all.

- _Amended by [ADR 0020](0020-playpen-claims-credential-confinement-only.md) ([#35](https://github.com/firefly-engineering/playpen/issues/35)): the shared host loopback is no longer a macOS-only residual;
  it is subsumed by **network-reachable credential sources**, since playpen confines no network on
  either platform._
