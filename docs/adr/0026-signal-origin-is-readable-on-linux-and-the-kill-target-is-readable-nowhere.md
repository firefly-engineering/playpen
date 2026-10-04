# Signal origin is readable on Linux, and the kill target is readable nowhere

The child shares the caller's process group ([ADR 0002](0002-playpen-does-not-interpret.md)), so a
signal sent to the whole job reaches it twice unless playpen suppresses its forward — and playpen
was deciding by a heuristic that got two cases wrong. On Linux the forward is now decided by
`sigwaitinfo`'s `si_code`, which is exact for the case it covers. The other case is **not fixable
on any platform**, because `siginfo_t` reports a signal's *sender* and never its *target*. It
becomes a named residual, and macOS's inability to read origin at all becomes **named asymmetry
#7**.

## Why

**Three measurements, taken because the obvious fix is wrong in two ways.** On Linux 7.1.6:

| what was sent | `si_code` | `si_pid` |
|---|---|---|
| tty Ctrl-C | `SI_KERNEL` (128) | 0 |
| `kill(pid, SIGINT)` | `SI_USER` (0) | sender |
| `kill(-pgid, SIGTERM)` | `SI_USER` (0) | sender |
| `alarm()` → `SIGALRM` | `SI_KERNEL` (128) | 0 |

The first two are what the ticket expected and they settle the dropped-signal case exactly. The
last two are the findings worth keeping.

**A group-directed kill is indistinguishable from a process-directed one, so double delivery
cannot be fixed.** Rows two and three are byte-identical. The kernel tells a receiver who sent a
signal, never to whom it was addressed, so playpen cannot know whether the child already has a
copy. sudo's sender-group comparison does not rescue it: a sibling inside the job sending a direct
`kill` is the case that must be forwarded, and a stranger outside it sending a group kill is the
case that must not, and either sender can be inside or outside. The information does not exist to
be read. Recording this is most of the point of this ADR — the next reader of the suppression
predicate will otherwise propose exactly the fix the ticket proposed.

**`SI_KERNEL` does not mean "the group got it", so it cannot be the rule on its own.** Row four is
the trap: an `alarm()`-generated `SIGALRM` is indistinguishable from a tty keypress, and `SIGALRM`,
`SIGXFSZ` and `SIGXCPU` are per-process signals the child never received. A predicate that
suppressed everything kernel-generated would swallow them. So `si_code` refines membership of the
tty-generated set; it does not replace it.

**Within that set, though, `SI_KERNEL` is a proof and not a heuristic.** If a signal is one the tty
generates and the kernel generated this instance, then the tty delivered it to a process group
containing playpen, and the child is in that group — so the child has it, with no need to ask which
group held the foreground. That is why the Linux arm drops the foreground check rather than ANDing
with it: once the code is in hand the check carries no information.

**The old predicate was wrong in two further places the ticket did not name.** Its set held four
signals, but `SIGTTIN` and `SIGTTOU` are tty-generated too and were forwarded unconditionally,
doubling and then stopping playpen with the job on a signal the child had already received twice.
And the foreground condition is *inverted* for exactly those two: a process receiving `SIGTTIN` is
by definition in a **background** group, so adding them to the set while the condition stood would
have changed nothing.

**macOS keeps a structural proxy because it has nothing to read.** `sigwaitinfo` does not exist
there, and `si_code` is `0` for both a keypress and a `kill` even through an `SA_SIGINFO` handler,
with `si_pid` set in both cases — so there is no path, blocked or handled, to the origin. Levelling
Linux down to match would mean knowingly dropping a signal playpen could forward correctly, which
is not how this project handles platform inequality.

## Consequences

- **Named asymmetry #7**, favouring Linux: signal origin is readable there and nowhere else. Its
  live consequence is that a direct `kill -INT` to a foreground playpen is forwarded on Linux and
  silently dropped on macOS.

- **§15.4's wording widens to let a row live in the transparency suite.** The ledger requires a
  suite row per asymmetry, but the enforcement suite's verbs are about the boundary — read, create,
  list, inherited fd, Mach lookup, refuse — and this is a transparency property. Carrying `—`
  instead would be false, since the assertion is cheap and will exist: the transparency suite
  already has the pty helpers. The deprecation clock carries `—` because nothing can assert a
  vendor's timetable; that is a different situation and the column should not blur them.

- **A twelfth named residual: a group-directed signal reaches the agent twice.** It is recorded
  with its reason — unclosable rather than unclosed — because it is the entry most likely to be
  mistaken for a bug. A doubled `SIGINT` is the one that bites: some agents exit on a second Ctrl-C.

- **The residual is pinned by a test that asserts the doubling.** It reads oddly and it is
  deliberate: it is the only thing that will notice if someone later closes error 1 with a
  heuristic, and a silent change in signal delivery surfaces months later as an agent exiting on
  one Ctrl-C.

- **§11.6 states the intent, not the mechanism.** "A signal sent to playpen reaches the agent
  exactly once, where the platform can tell" is what a caller needs; which syscall discriminates
  belongs in §15.4 and here. The old sentence named four signals and a foreground condition, and
  both have now been wrong twice.

- **macOS's dropped direct kill is an asymmetry, not a residual.** It is open on one platform and
  closable in principle; error 1 is open on both and closable nowhere. Filing them in the same
  ledger would lose the distinction that took the measurements to establish.
