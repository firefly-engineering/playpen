# The run record ring evicts history, and never a live run

The ring evicted by start time whenever a record was opened, so a long agent session — whose shim
invocations each count as a run — was guaranteed to evict its own record, and `explain --run` failed
for the one run most worth inspecting. Eviction now applies to **ended** runs only. A live run is
recognised by an advisory lock it holds on a sidecar for its lifetime, released by the kernel on any
death including `SIGKILL`, so an un-ended record is evicted exactly when nobody holds its lock.
There is no age bound anywhere in this.

## Why

**The two reported failures had one victim.** The staging sweep was already guarded for recent runs
— a `.tmp` whose run id is at least as recent as the oldest kept stays, because a playpen may be
writing it — so both the vanishing record and the raced staging write could only strike a run
already pushed out of the ring. One bug, not two.

**Which makes the `launch` refusal near-unreachable and the lost `finish` write routine.** Step 15
runs before the fork, so 100 runs would have to start inside that window. But `finish` fires at the
end of a long session, exactly when that session has been pushed out: it stages its bytes, the
sweep removes the staging file, the rename fails `ENOENT`, and the write is dropped silently —
because a teardown failure cannot change the status playpen exits with. The session's final status
and end time are lost and its record is left permanently un-ended, which is the same zombie a
`SIGKILL` produces.

**The ordering key was the real fault.** A ULID sorts by *start* time, and that is the opposite of
what a debugging aid wants: the longest-running run is the most interesting and the most certain to
be evicted. Shims make runs plentiful inside a single session, so this is the normal shape of a long
session rather than an edge case.

**An age bound was the obvious fix and its constant is unpickable.** "Evict un-ended records older
than X" needs an X that is longer than any agent session and shorter than any tolerable leak, and
the first half of that depends on how long people run agents — which playpen does not know and
should not guess. Too short evicts live sessions, which is the bug; too long leaves the ring
unbounded, which is what the ring exists to prevent. The lock has no constant: the kernel answers
the question exactly.

**A lock needs a sidecar, because the record is replaced by rename.** An advisory lock follows the
inode and every write to a record replaces it, so `<id>.json` cannot carry its own liveness.
[#72](https://github.com/firefly-engineering/playpen/issues/72) is introducing the same idiom for
`exclusive` areas, so the codebase acquires it either way.

**Liveness by pid was rejected.** The record already carries the child's pid, so it looks free — but
pid reuse makes it wrong precisely on a busy host, which is when a long session is most likely to be
pushed out of the ring. The supervisor's own pid is added to the record anyway, because a stale
record should be diagnosable by hand once the lock is gone, and recording the child's pid without
its parent's was odd on its own terms.

**A rename failing `ENOENT` is deliberately not retried.** Once eviction leaves live runs alone, a
live run's staging file has no legitimate remover, so `ENOENT` there means the invariant is broken.
Re-staging would convert a broken invariant into a successful write — which is how the silent drop
hid this bug in the first place.

## Consequences

- **The bound's meaning changes and its number does not.** §14.1 now reads as the 100 most recent
  *ended* runs, plus every live run. The directory cannot grow without bound from *history*, which
  is what "a debugging aid, not an audit log" was protecting; live runs are self-limiting because
  each is a process.

- **The invariant is specified and the mechanism is not.** §14.1 states that a live run's record is
  never evicted, because that is a promise `explain`'s consumers depend on. The sidecar goes in
  Appendix C as an assembly choice, like the state directory's location in C7 — a future playpen
  could use a pidfd on Linux and change nothing a caller sees.

- **Two removers for the sidecar, because the fault path cannot run destructors.**
  [ADR 0024](0024-a-status-playpen-cannot-learn-is-a-fault-and-not-a-refusal.md) ends a fault with
  `abort`, so a faulted run leaves its sidecar beside an ended record. The run removes its own on
  the normal path, and eviction removes whatever remains. A missing sidecar beside an un-ended
  record counts as dead, so a record written by an older playpen is evictable rather than immortal.

- **`explain` gains no new output.** A live run already shows as one with no end time, and testing
  the lock while listing would mean a read-only command acquiring locks on records it is only
  reading — a side effect, and a racing one. How a live run is presented belongs with
  [#79](https://github.com/firefly-engineering/playpen/issues/79).

- **The sidecar needs no exemption work for
  [#116](https://github.com/firefly-engineering/playpen/issues/116).** It is a path playpen derives
  from its own state directory, which is exactly the class that rule exempts.
