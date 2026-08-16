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

Two exceptions are forced, and both are made loud rather than quiet.

playpen must **inject** flags for some kinds, because an agent's own sandbox has to be
displaced (macOS Seatbelt does not nest). Injection is strictly prepending, so under
last-wins parsing the caller's own arguments still win, and every injected flag appears in
`playpen resolve --json`. Where a flag is *required* for the sandbox to function at all,
an explicit contradiction from the caller is a refusal at launch naming the conflict —
this is the one place playpen inspects an argument, and it is narrow, declared in policy,
and fails before exec rather than confusingly after it.

playpen must **report its own failures**, and it cannot use stdout to do it. Refusals
therefore go to stderr, and the exit code `125` is reserved for "playpen did not run the
agent" — distinct from any status the agent itself produced. Where playpen delegates to a
backend with failure codes of its own, translating them into `125` is an obligation, not a
nicety: without it, a caller cannot tell a refusal from an agent that exited badly.

playpen also stays the parent process rather than `exec`ing, since the credential proxy
lives inside the boundary and ephemeral areas need tearing down. Being a supervisor is
compatible with everything above only because the supervisor is transparent: signals
forwarded to the child's process group, the child's status propagated, `128+N` on signal
death.

## Rejected alternatives

**Detect ACP mode and behave accordingly.** Rejected because the detection can be wrong,
and because the behaviour it would select is the behaviour that is correct in every case
anyway. A mode flag here buys nothing and adds a way to fail.

**Remap provisioned areas to tidy paths inside the boundary.** Attractive for presenting a
stable layout to the agent, but it forfeits path identity, and a manifest that states
paths the operator cannot `cd` into is worse than one that states awkward real ones.
