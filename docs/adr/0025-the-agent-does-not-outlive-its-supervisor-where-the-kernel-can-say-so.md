# The agent does not outlive its supervisor, where the kernel can say so

*Amends [ADR 0010](0010-concurrency-is-a-property-of-a-provisioned-area.md).*

A fault signal sent to playpen kills the supervisor and leaves the confined agent running
unsupervised, reparented to init, still holding the caller's terminal. The child now sets
`PR_SET_PDEATHSIG` to `SIGKILL` before `exec`, so on Linux the agent cannot outlive its supervisor
by any route, `SIGKILL` of playpen included. macOS has no equivalent and keeps the residual, as
**named asymmetry #6**. The fault signals themselves stay unforwarded with their default action
unchanged.

## Why

**ADR 0010 declined to close this, and its reason was about the lock rather than the agent.** Its
residual reads: "`SIGKILL` the supervisor without its process group and the agent is orphaned,
still writing the area, while the lock has already released… Closing it requires the *child* to
hold the lock, which needs an inherited fd, which is ADR 0006's law; the blast radius is one
workspace's area rather than the boundary, so the law wins." Every word of that stays true — the
*lock* half still needs an inherited fd and ADR 0006 still forbids one. A parent-death signal
addresses the other half, the live orphan, and it was never weighed because the question was
framed as "who holds the lock". With the agent dead, the lock's released state is accurate rather
than a lie, which narrows ADR 0010's residual without touching its argument.

**Only a parent-death signal covers the route ADR 0010 names.** Catching the fault signals and
telling a sent one from a real fault by `si_code` was the ticket's first option, and it narrows
only the *catchable* routes — `SIGKILL` of playpen, which is the case ADR 0010 actually cites,
stays wide open on both platforms. It also cannot be built correctly on macOS for sent signals
([#112](https://github.com/firefly-engineering/playpen/issues/112) measured `si_code` as `0` for
both `kill` and terminal signals there). A mechanism that needs a heuristic to decide whether to
kill the agent is worse than one that needs none.

**Nothing in userspace can do this after `exec`.** A death pipe, a watched descriptor, a
`kqueue`/`NOTE_EXIT` registration — each needs the watcher to run code, and `exec` replaces the
image with an agent that will not poll playpen's private fd. Post-`exec`, a kernel mechanism is the
only kind there is, which is why the option list is three long and why macOS's lack of one is
permanent rather than unimplemented.

**ADR 0002 forecloses the obvious mitigation.** Giving the child its own process group would at
least stop an orphan holding the terminal, but "a group of its own would have to take the
terminal's foreground for a TUI to read it, which stops every other stage of a pipeline that reads
the terminal, such as `playpen run … | less`". So the choice really is between the agent dying with
the supervisor and the agent being stranded in the caller's job.

**It resolves on the same principle as ADR 0024, and that matters more than either case.**
ADR 0024 settled the adjacent failure — playpen cannot learn the agent's status — on the grounds
that an unsupervised confined agent is worse than a dead one, and killed it. Two adjacent
lifecycle failures resolving on opposite principles is how a codebase stops being explainable.
The cost is stated plainly: an agent mid-edit dies because playpen crashed, where today it would
survive. That is accepted, because the agent that survives is confined with no supervision, no
credentials (ADR 0013 makes the proxy die with the supervisor, so it fails closed) and no way for
the caller to signal it.

**`SIGKILL` rather than `SIGTERM`, because there is nobody left to escalate.** The usual
`SIGTERM`-then-`SIGKILL` ladder needs a live process to climb it, and the process that would is
the one that just died. `SIGTERM` alone is a request with no enforcement: an agent that blocks,
ignores or mishandles it is stranded exactly as it is today, so the mechanism would work only for
the agents that least needed it.

## Consequences

- **A standing invariant: the thread that forks is the thread that lives for the whole run.** The
  signal fires on the death of the parent *thread*, not the parent process, so a supervisor whose
  forking thread exits while the process lives kills every agent for no reason.
  [#86](https://github.com/firefly-engineering/playpen/issues/86) puts the proxy inside the
  supervisor and is the most likely thing to break this. The existing single-threaded rule is
  written as a *reason* — a thread started before the fork would not have the signals blocked and
  would swallow them — which a future reader can satisfy by starting proxy threads *after* the
  fork: correct for signals, fatal here. It needs stating as its own rule with its own reason.

- **The `fork`-to-`prctl` window is closed by re-checking `getppid()`.** If playpen dies before the
  child sets the signal, the setting was never made and the child is stranded by the path this
  closes. The child self-terminates if the parent has already changed. A window left open inside
  the mechanism that exists to close a window reads as an oversight.

- **A set-user-ID target silently loses the guarantee**, since the kernel clears the setting when
  exec'ing one. Worth noting rather than guarding: playpen's targets are agents, and the integrity
  checks already stand between the policy and what gets `exec`ed.

- **Named asymmetry #6, with a suite row.** Unlike ADR 0024's fault, this is provokable: launch,
  `SIGKILL` playpen, poll for the child's disappearance within a bound, and fail on the timeout.
  `n/a` on macOS.

- **ADR 0010's orphan residual becomes macOS-only** rather than struck. It stays reachable on one
  platform, which is what the term is for, and the residual and the asymmetry cross-reference so
  the two ledgers cannot drift.

- **The fault-signal exclusions are unchanged, and §11.6 now says what becomes of the agent.**
  Blocking a fault signal would make a real fault undefined behaviour, so the list and its reason
  stay verbatim. What was missing is the consequence a caller needs: the supervisor dies, and the
  agent dies with it on Linux and survives on macOS.
