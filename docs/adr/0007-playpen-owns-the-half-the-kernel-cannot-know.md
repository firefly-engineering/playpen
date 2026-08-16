# playpen owns the half the kernel cannot know, and refuses to synthesise the rest

The kernel already reports **what** was denied — in-band to the confined process as an errno,
out-of-band to the operator in its own log. What it cannot know is **which policy produced this
boundary**. That gap is the entire scope of playpen's diagnostic surface: a **run record**
written before launch, a selection trace, a closed vocabulary of **codes**, and a **manifest**
that tells the agent up front how to read a **denial**. Everything else a failure-UX design
would reach for — a runtime channel explaining denials to the agent, interpretation of the
child's exit status, a permissive-with-logging mode, tailing the kernel log by default — is
rejected by that same line.

## Why

**The premise this decision started from was wrong, and checking it removed most of the
problem.** ADR-adjacent folklore from the capability survey held that Seatbelt denials surface
as a bare `EACCES` that an agent would misdiagnose as a missing file. Measured on the reference
host, a denied `open()` returns **`EPERM`**, and a missing path under the same denied subpath
returns `ENOENT` — the errno already separates policy from absence. The kernel also logs every
denial with the process, pid, operation and full path
(`kernel (Sandbox) Sandbox: cat(47295) deny(1) file-read-data /private/tmp/pp-secret/f.txt`),
free and without any live process on playpen's side. The diagnostic surface playpen was about
to build mostly existed already; what was missing was never the *what*, only the *why*.

**A runtime explanation channel could only ever say "no, and it will stay no."** ADR 0003 fixed
that no capability expands at runtime, which is what makes the manifest true for a whole
session. So a channel that explained denials as they happened would carry no actionable
information — it would be consolation, not help, and it would be interpretation (ADR 0002) into
the bargain. The honest place to spend that effort is *before* the failure: the manifest states
the boundary, states that `EPERM` means policy and `ENOENT` means absent, and states that the
boundary is fixed — so the correct agent behaviour is to report the boundary rather than thrash
against it. Prevention, delivered up front and pulled by the agent, not pushed at the moment of
failure.

**A permissive-with-logging mode is the no-silent-downgrade law failing in its most plausible
disguise.** It is the single most-requested shape for "help me build an allow-list", and it is
a mode that runs weaker on purpose — which is the mode that gets left on. It is also
unnecessary: the kernel's denial log names the exact path and operation, so the loop is *run
fully confined → hit `EPERM` → read the log → add a root or an exclusion*. Where more comfort
is wanted, the answer is `--trace-denials <file>`, which tails and pretty-prints **without
weakening the boundary**.

**Interpreting the child's exit status would trade a real law for a guess.** A misdeclared
toolchain root still produces `rc=134` with empty stdout *and* stderr. The tempting move is to
catch that and explain it — but playpen cannot distinguish a loader denial from an agent that
genuinely aborted, so the explanation would sometimes be a lie, and it would break the
process-transparency contract ADR 0002 owes regardless of backend. playpen's contribution to
that failure is covered *before* launch by the floor self-test; the operator's contribution is
diagnosed from the kernel log afterwards. The status itself propagates untouched.

## Consequences

- **The run record is written before launch, not at exit.** A run that **refuses** is precisely
  the run whose record is most wanted, and a record written at exit would never exist for one.
  It holds the resolved profile, the selection trace, the capability set, the egress list, the
  pid and timestamps.

- **The run record is unreachable from inside the boundary.** Not because it is secret — the
  agent can probe most of it — but because a record the agent can read is one it can be
  confused by, and inside the boundary it would also be forgeable. It lives in a playpen-owned
  state directory that is no workspace, no brought root, and not writable by the profile, on
  the same reasoning that puts the policy out of reach in ADR 0003. Retention is a bounded ring
  of recent runs.

- **`playpen explain` is one command with three sections and a `--json` form.** The selection
  trace (each step of ADR 0002's chain, which fired, which were skipped), the resolved
  capability set, and the resolved egress list *with fragment provenance*. One command because
  the operator's question is "what would happen if I ran here", and splitting it makes them ask
  twice. `--json` because ADR 0003 and ADR 0006 already promised a dumpable capability set, and
  a dump only human eyes can read is half a promise — the enforcement suite must assert against
  it, and asserting against prose means the regex parsing this project has ruled out.

- **`playpen explain --run <id>` is the one place playpen bridges its half to the kernel's.**
  It replays a stored record and emits the exact platform command to pull that run's denials,
  pid already filled in. The run id appears on the refusal line and via `playpen explain
  --list`. This costs nothing at runtime, which is the point.

- **`--trace-denials` writes to a file, never to stderr, and refuses rather than no-ops.**
  stderr belongs to the agent under the transparency contract. Where a platform cannot provide
  the trace, the flag is refused at parse time — scoped to the flag, not the run — because an
  empty trace file that means "unsupported" reads as "nothing was denied", which is a silent
  downgrade in its purest form. Whether Linux can provide it at all is an open question:
  Landlock's audit records appear to be recent-kernel-only and privileged, and this is
  unverified.

- **The floor self-test runs on every launch and is never cached.** Caching means keying on a
  proxy for "the floor still works" — an OS version, a hash — and every such key is a guess
  that fails **open and silently**, the exact failure class this decision exists to eliminate.
  A `posix_spawn` of a trivial binary costs single-digit milliseconds against a session
  measured in minutes. A test that runs every time cannot go stale.

- **Refusal is one line that is both machine- and human-readable**, on stderr, prefixed
  `playpen: `, exit `125`: a `code` from the closed vocabulary, a human sentence, and the
  offending value. Not two lines — one, so neither audience can be served by a path the other
  never exercises.

- **Egress denial is `403` with `X-Playpen-Denied: <host>`; genuine upstream failure is `502`.**
  The same distinction rides the CONNECT response status for opaque tunnels, which discharges
  the in-band-distinguishability invariant ADR 0004 handed this decision. This is not a
  contradiction of "no runtime explanation channel": the proxy is an ordinary HTTP peer and
  `403` is that layer's own vocabulary, not a playpen side-channel. The sandbox has no
  resolver, so name-resolution failure is not a confusable third mode.

- **"A denial is never `ENOENT`" joins the enforcement suite on both platforms**, stated
  positively: a denial is always distinguishable in-band from absence and from success. It is
  the filesystem twin of the egress invariant above. Seatbelt's `EPERM` is verified; Landlock's
  `EACCES` and seccomp's behaviour are not.

- **The manifest gains a failure-interpretation section, and `playpen explain --self` prints
  nothing but that section back.** No policy read, no privilege, no second code path that could
  disagree with the manifest. How the section is worded per `kind` belongs to the manifest's
  own per-harness presentation, not here.
