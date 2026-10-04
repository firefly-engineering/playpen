# playpen confines and then gets out of the way — it does not interpret

playpen sits between a caller and an agent binary, which puts it in a position to
translate: rewrite arguments, remap paths, allocate a terminal, filter output, decide what
the caller "meant". It does none of these. Everything past the `--` separator is opaque
bytes; stdio file descriptors are inherited untouched; a path inside the boundary is the
same absolute path outside it. playpen decides *what the process may reach* and nothing
else about it.

## Why

The three surfaces where a wrapper is tempted to interpret each have a concrete failure
already visible in the design.

**Arguments.** The agent binaries carry hundreds of flags and change them between
releases. Any parsing playpen does is a second, always-stale copy of someone else's CLI,
and the failure mode is a flag that silently means something different inside playpen than
outside it.

**Stdio.** These agents are interactive TUIs, and where they speak the Agent Client
Protocol the same file descriptors carry JSON-RPC instead. A wrapper that allocates a PTY,
buffers, or writes a diagnostic to stdout corrupts the second case while looking fine in
the first. Inheriting the descriptors untouched is correct for TUI, ACP and plain piped
invocation without playpen needing to know which it is in — and it is the only shape that
does not require a mode flag, which is a thing that can be set wrongly.

**Paths.** ACP messages carry absolute paths across the boundary, between a client outside
and an agent inside. Under any remapping the two sides disagree, and the resulting
breakage presents as an agent bug with nothing pointing at the sandbox. The same holds for
every error message and for the manifest. Path identity is free on the mechanisms playpen
targets — Seatbelt and Landlock are both path-predicate systems that confine in place —
and it is precisely what a bind-mount or `bwrap` approach would have spent.

The general benefit is that the interesting question — *what could this process reach?* —
stays answerable by reading the policy, rather than by reasoning about what playpen did to
the invocation on the way through.

## Consequences

Two exceptions are forced, and both are made loud rather than quiet. Neither is an
exception to *interpretation* — playpen adds argv without reading it, and reports its own
failures without reading the child's.

A shim may **inject** flags, and playpen prepends them without understanding them. An
injected flag is a list of literal argv tokens the operator declares in policy —
`["--permission-mode", "plan"]`, never `"--permission-mode plan"`, because splitting a
string is a shell-quoting parser whose mis-splits reach the agent as extra arguments and
surface as agent errors with nothing pointing at playpen. The `kind` table learns no flag
spellings: that a flag exists is per-agent knowledge, that this host pins it is policy.

**An injected flag can make the agent work or not work, and can never make the boundary
narrower or wider.** argv cannot widen a Seatbelt profile compiled before `exec`, so this
is usability and not security — the same demotion ADR 0005 made for guest sandboxes, and
for the same reason: confinement is the kernel's job.

That is why there is no `required` marker and no contradiction detection. Deciding that a
prepended `--dangerously-skip-permissions` contradicts a caller's `--permission-mode ask`
needs that agent's flag grammar, which is the always-stale second copy this ADR exists to
refuse — and nothing rests on the answer. **playpen does not inspect an argument
anywhere.**

What prepending buys is stated honestly rather than repaired: a caller who repeats an
injected flag overrides it, under the near-universal last-wins convention. Across
*different* flags playpen guarantees nothing, because the precedence is the agent's own
and playpen does not model it. Appending would invert that single guarantee and buy no
more.

Visibility is therefore the whole of what playpen owes here. The injected argv is part of
the **capability set**, so `playpen explain --json` reports it with `from:` provenance like
every other resolved fact — the operator debugging *why is it still asking permission* gets
the exact tokens rather than a guess. Nothing is projected inward: argv arrives in the
process image at `exec`, so the agent already holds it, and a manifest copy could only
disagree.

playpen must **report its own failures**, and it cannot use stdout to do it. Refusals
therefore go to stderr, and the exit code `125` is reserved for "playpen did not run the
agent" — distinct from any status the agent itself produced. Where playpen delegates to a
backend with failure codes of its own, translating them into `125` is an obligation, not a
nicety: without it, a caller cannot tell a refusal from an agent that exited badly.

playpen also stays the parent process rather than `exec`ing, since the credential proxy
lives inside the boundary and ephemeral areas need tearing down. Being a supervisor is
compatible with everything above only because the supervisor is transparent: signals
forwarded to the child, the child's status propagated, `128+N` on signal death. The child stays
in the caller's process group rather than one of its own: a group of its own would have to take
the terminal's foreground for a TUI to read it, which stops every other stage of a pipeline that
reads the terminal, such as `playpen run … | less`.

## Rejected alternatives

**Detect ACP mode and behave accordingly.** Rejected because the detection can be wrong,
and because the behaviour it would select is the behaviour that is correct in every case
anyway. A mode flag here buys nothing and adds a way to fail.

**A `required` marker on an injected flag, degraded to exact-duplicate detection.**
Textually honest and needs no grammar, but it is anti-correlated with the failures it
would be for: repeating a flag is the one case last-wins already handles correctly, so it
would refuse on the input that works and stay silent on every input that breaks.

**A per-`kind` table of contradicting flag pairs.** This is the always-stale second copy
of someone else's CLI, arriving as declared data instead of parsing code — a maintenance
treadmill against other people's release schedules, bought to prevent an outcome that is
merely a broken agent.

**Remap provisioned areas to tidy paths inside the boundary.** Attractive for presenting a
stable layout to the agent, but it forfeits path identity, and a manifest that states
paths the operator cannot `cd` into is worse than one that states awkward real ones.
