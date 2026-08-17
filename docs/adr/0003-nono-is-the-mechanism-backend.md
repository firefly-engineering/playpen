# nono is the mechanism backend, reached as a library, behind a playpen-owned seam

playpen depends on the `nono` **crate** as its confinement mechanism — linked in-process,
applied to playpen's own process before it `exec`s the agent — rather than shelling out to
the `nono` CLI or generating SBPL and Landlock rulesets itself. The dependency is cut
narrowly: only the `sandbox` and `capability` modules, behind a playpen-owned capability
type that is the sole thing a backend ever receives. This commits playpen to Rust.

## Why

The framing that made this hard was wrong. nono is not a *sibling* of `sandbox-exec` and
Landlock — it is a **layer above** them. Its macOS path *is* Seatbelt, reached by linking
`sandbox_init` directly instead of spawning a helper; its Linux path *is* Landlock plus
seccomp. "nono or sandbox-exec on macOS" is the same mechanism twice, so there was never a
backend to choose — only an altitude to cut at.

Writing the mechanism ourselves was the alternative kept longest on the table, and it is
the one option that buys real independence. It was rejected because it buys independence in
exactly the wrong place: SBPL generation, Landlock ABI probing and hand-assembled
seccomp-BPF are the highest-risk, least-testable code in the project, and a subtle error
there fails *open* and silently. The bus-factor concern that motivates it — a substantial
majority of nono's commits come from one author, pre-1.0 — is real, but the answer to it is
an exit seam and a test suite, not abstention.

The library was chosen over the CLI for three reasons. The crate states it "provides the
mechanism for OS-enforced isolation without imposing any security policy" — all of nono's
group machinery, its always-merged `default` profile and its eight non-excludable deny
groups live in `nono-cli`, so taking the library means there is no second policy author to
defend against. It makes independent verification tractable: probing the Landlock ABI is a
function call rather than text scraped from `-v` output. And its churn arrives at compile
time rather than as a JSON schema drifting under us at runtime.

## Consequences

**The seam exists from day one and is the exit plan.** nono exposes no extension point —
`Sandbox` is a `#[cfg]`-forked unit struct, not a trait — so playpen must own the interface
above it regardless. That obligation is turned into the escape hatch: a playpen-owned
capability type carries resolved absolute paths with access modes, a network mode and an
environment allow-list, and nothing above that. No workspace names, no profiles, no
lifetimes. A direct `sandbox_init`/Landlock implementation could later sit behind it
without touching the policy compiler.

**A backend is defined by what it enforces, not by what it exposes.** The version is pinned
exactly and an upgrade is gated on a suite that asserts the negatives from *inside* a live
sandbox — a read outside the declared roots fails, a write to a `read` root fails, egress
to an unlisted host fails, an inadequate kernel refuses. Compilation is not the gate: the
failure that matters is a version where a rule that used to be enforced silently is not,
and that compiles perfectly. The same suite is what makes the seam cashable, since any
replacement backend must pass it.

**playpen refuses on its own authority, not nono's.** nono is overwhelmingly fail-closed
and states the same law in almost the same words, with one exception: its *default* process
scoping (signal isolation, abstract-UNIX-socket scoping) is applied only where the kernel
offers Landlock V6 and is dropped quietly otherwise, while *explicitly requested* scoping
fails closed. playpen therefore requests scoping explicitly, so nono's fail-closed path
fires, and probes the ABI itself beforehand so the refusal is playpen's own and does not
depend on a default staying put across a minor version.

**No runtime capability expansion.** macOS sandbox extensions and seccomp-notify fd
injection can widen a running sandbox, but both require a live process outside the boundary
that decides — which is interpretation, and which has no asker at all in the unattended case
playpen primarily targets. Every capability is therefore fixed at launch and a missing path
is a refusal rather than a prompt. This makes the manifest true for a whole session rather
than at an instant, and moves the entire cost onto policy authoring, where it belongs. It
also renders the `Approve` tier of any L7 egress policy unusable: egress rules must be pure
allow or deny.

**`nono-cli` is structurally out of reach**, which resolves more than it forbids. Profiles,
groups, packs, the registry namespace and the `~/.nono` forced denies never enter the
picture — and neither does `command_policies`, nono's per-executable child sandboxing, whose
apparent conflict with playpen's law that the unit of policy is the process tree turns out
to be a `nono-cli` feature the library has no notion of.

**Nothing alive between the terminal and the agent — but a sibling is allowed.** The
transparency law forbids a live *ancestor*, not a live *process*. A supervisor in the middle
would hold the file descriptors ADR 0002 protects; a detached sibling holding a credential
socket interprets nothing on the invocation path. This keeps a credential broker reachable
at the cost of a sibling's lifetime no longer being tied to the agent's by the process tree.

_Amended by [ADR 0010](0010-concurrency-is-a-property-of-a-provisioned-area.md) and
[ADR 0013](0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md):
a live ancestor turned out to be unavoidable — an `exclusive` claim must be pinned to a live
process and ephemeral areas must be torn down — so playpen has a **supervisor**, and transparency
became an obligation it meets (stdio inherited untouched, signals forwarded, the child's status
propagated) rather than a property obtained by not existing. With that parent already live, the
proxy runs **in it** rather than detached, and the cost named in the last sentence is not paid._
