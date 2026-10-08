# A status playpen cannot learn is a fault, and not a refusal

Exit `125` means playpen did not run the agent ([spec §11.6](../spec.md#116-process-transparency)),
and the supervisor was returning it when `waitpid` on the agent failed — by which time the agent
may have run for hours. A **fault** is the third outcome: playpen states on stderr that it cannot
tell, under a code in a new `bug.*` prefix, kills the agent so the outcome is at least
deterministic, records it, and dies by `SIGABRT`. `125` now means strictly "did not run", and
`refusal.process.wait` is left to the one caller it was always true for — the floor self-test's
canary, which is genuinely pre-launch.

## Why

**The transparency contract had no vocabulary for "ran, status unknown", so the code borrowed the
one case that was closest and lied.** §11.6 admits two outcomes: the agent's own status, or `128+N`
when it died by a signal — plus `125` for the launch refusals, which are the cases where there is
no agent to have a status. "The agent ran and playpen cannot say what happened" is none of these,
and every available answer was already spoken for. The ticket called this "stating an honest
contract rather than a frequent failure", which is exactly right: the behaviour is near-unreachable
and the contract was wrong anyway.

**Reserving a second exit status was the obvious move and it buys nothing.** §11.6 makes playpen's
status the agent's status, so every value playpen might reserve is a value the agent can
legitimately return, and a caller cannot tell the two apart. `125` pays that cost deliberately and
once. Paying it again for a rarer case would spend the same ambiguity on less.

**A fault is a defect, not a contract case, and the registry already had the word.** Appendix A's
own prose says "a backend failure that maps to no listed code is a playpen bug", and
`refusal.flag.*` was deliberately never minted — the registry is willing to say a thing is a bug
rather than name it an outcome. On the agent, which is our own unreaped child, `waitpid` can
realistically fail only with `EINTR`, which is retried. The one route that would make `ECHILD`
reachable — a caller that `exec`s playpen with `SIGCHLD` set to `SIG_IGN`, which is inherited
across `exec` and makes the kernel auto-reap — is closed, because the supervisor holds `SIGCHLD`
unconditionally and installs a real handler for every held signal, overriding the inherited
disposition. `EINVAL` would be a wrong argument. So there is no state here an operator can reach
and none a consumer should handle.

**The asymmetry with the self-test's caller is deliberate.** The same `waitpid`-failed reasoning
applies to the floor self-test's wait on its throwaway canary, which closes the same `ECHILD`
route the same way. It stays a refusal regardless, because the pre-`exec` case *has* an honest
answer available: playpen could not test its floor, so it refuses and never runs the agent, which
is precisely what `125` means. Using a correct answer costs nothing even when the underlying cause
is a bug. The post-`exec` case has no correct answer in that vocabulary, and that is the whole
distinction. Appendix A's entry now names the canary so this is visible from the registry rather
than only from here.

**A separate prefix keeps the new code out of the release gate instead of needing an exemption
from it.** `R-code-coverage` ([#108](https://github.com/firefly-engineering/playpen/issues/108))
must fail on any code with no producing row, and has no exemption mechanism — so minting
`refusal.state.unknown` would have obliged a suite row for something no row can provoke. `bug.*`
is a third prefix beside `refusal.*` and `broker.*`, and the gate enumerates `refusal.*` only.
A code rather than a bare message because §14.3's rule holds here too: consumers branch on the
code, never the prose, and a caller meeting a crash should be able to branch on *why*.

**Killing the agent is the only deterministic option left.** A supervisor that cannot learn the
agent's status has lost supervision entirely — it can no longer forward signals meaningfully
either — and leaving the agent alive reparents a confined process to init, still holding the
terminal, which is the stranding failure
[#111](https://github.com/firefly-engineering/playpen/issues/111) describes reached by another
route. The agent dies before the record is written, so the record cannot claim an end time while
the agent is still running.

**Dying by `SIGABRT` rather than panicking, because the crate's panic strategy is unwind.** A
`panic!` here would exit `101` — an ordinary exit status a caller reads as a value, where a signal
death reads as a crash — and unwinding would run destructors on a process that has just declared
itself broken, which is the uncontrolled version of the teardown this ADR deliberately skips.

## Consequences

- **The record distinguishes a fault from a refusal.** A third field rather than reuse of the
  `refusal` one, because `explain --run` reads it back out and a surface whose job is to state
  facts should not report a crash as a refusal. Additive, so no stored record changes meaning.

- **An aborting run leaves the run scratch and `ephemeral` areas on disk**, and that is the
  eleventh **named residual**. The credential half needs nothing: the proxy is hosted in the
  supervisor rather than detached, so process death *is* the credential teardown. The filesystem
  half is bounded, inspectable litter; removing it would mean running the most failure-prone code
  in playpen on a broken process, and a teardown that hangs converts a crash into a hang.

- **There is no suite row.** Nothing can provoke the condition, so the test covers the branch
  rather than the condition: the errno-to-code mapping, the emitted line, the kill, and the
  record write. An injectable seam whose only purpose is a branch that should never fire was
  rejected.

- **The `refusal.process.*` family's producibility problem is untouched.**
  `refusal.process.fork` is near-unproducible on a healthy host, and `refusal.process.wait` now
  only fires from the self-test. How the release gate treats a code no row can produce is #108's
  question, which will surface it as a failing enumeration rather than in the abstract.
- _Amended by [#157](https://github.com/firefly-engineering/playpen/issues/157): **the self-test's
  failed wait is a fault too, and `refusal.process.wait` is retired.** The enumeration surfaced it:
  the self-test resets `SIGCHLD` itself before it waits, and `waitpid` on a child playpen has just
  forked fails only when playpen called it wrong, so no host fact provokes the code. That is this
  ADR's own argument. The canary's wait now maps to `bug.status.no-child` and
  `bug.status.unreadable` exactly as the agent's does, and the run aborts the same way. Exit `125`
  would not have lied there, since the agent never ran; the code is moved because a defect is not
  a refusal, whichever outcome it ends in._
- _Amended by [#145](https://github.com/firefly-engineering/playpen/issues/145): **the gate now has
  one exemption mechanism, the unprovoked ledger.** It names a `refusal.*` code no environment a
  row can build provokes, with a unit test proving the code instead, and fails if a row produces
  the code. Its one entry is `refusal.proxy.bind`. The prefix split above still stands: a fault is
  not a refusal, so the ledger is no place for one, and an entry for a code that is no refusal
  fails the gate._
