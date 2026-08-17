# The floor is built in, and the toolchain is a coarse root with exclusions

> **Status: superseded by [ADR 0014](0014-the-toolchain-is-a-declared-closure.md).**
>
> The floor half of this decision stands and is carried forward verbatim. The toolchain half is
> wrong: the finding that closure-precise granting is "unrepresentable" was measured against the
> operator's entire home-manager profile (1413 store paths) rather than an agent toolchain (108),
> and the compiled-profile ceiling sits between 1000 and 1100 paths — an order of magnitude above
> what a toolchain needs, not below it. The coarse `/nix/store` root it prescribes also leaks
> every stale generation of the operator's dotfiles, which its single exclusion cannot close.
> Read ADR 0014 instead.

playpen always applies a **floor** — a built-in, non-subtractable grant of read and execute
under OS-owned paths, plus a short enumerated set of Mach services — that no policy can widen
or narrow. Everything else arrives as declared policy. The **toolchain** is a profile-level
list of read-only **toolchain roots**, and a root may carry **exclusions**: literal subpaths
subtracted from it, optionally per access class. Nothing under `$HOME` is in the floor, nothing
in the floor is writable, and the run's writable temp is a profile-level **run scratch**
provisioned by playpen.

## Why

**A floor is the one place a built-in default is worth its exception.** The standing law from
ADR 0004 is that playpen ships policy fragments and merges none by default, so there is only
ever one policy author. The floor breaks that law, and it earns the break by being a different
kind of thing: an egress fragment decides *reachability*, which is a security fact the operator
must own, whereas the floor decides whether `exec` returns at all. Omitting
`(allow file-read* (literal "/"))` makes every dynamically-linked binary abort with `SIGABRT`
and **zero diagnostic output** — that is not a policy choice anyone should be able to make. The
exception is bounded by *content* rather than by trust: the floor may grant read and execute
only, only under paths the OS owns, never under `$HOME`, never under a package store, never
anything writable. Every decision that can widen the blast radius stays with the single policy
author.

**Closure-precise granting is not merely expensive on macOS — it is unrepresentable.** The
obvious way to grant a Nix-managed toolchain without the dotfile leak is to grant exactly the
transitive closure of the declared tools. Measured on the reference host, that closure is
**1413 store paths**; rendered as `subpath` rules it is 163 KB of SBPL source that compiles to
**85,963 bytes**, and `sandbox-exec` hard-errors: `data object length 85963 exceeds maximum
(65535)`. The ceiling is on the *compiled* profile, so it bites at roughly a thousand paths —
below what one ordinary user profile needs. Nix's "split the allow-list" source comment was
folklore; it is now a measured wall, and it removes the precise option from the table before
the design gets to prefer it.

**The subtractive shape closes the leak in one line, and an operator can write it.** The two
derivations are disjoint: the toolchain (`home-manager-path`, 1413 paths) does **not** contain
the dotfile derivation (`home-manager-files`), which is what `~/.ssh/config`,
`~/.config/git/config` and the rest symlink into. So:

```scheme
(allow file-read* file-map-executable (subpath "/nix/store"))
(deny  file-read* (subpath "/nix/store/3737apm…-home-manager-files"))
```

Verified on the reference host: `cat ~/.ssh/config` returns `Operation not permitted` while
`ls …-git-2.55.0/bin` works. SBPL is last-match-wins so this composes natively, and Landlock
composes it by simply not granting the excluded path. Critically, the excluded path is one an
**operator can name** — no discovery, no interpretation, no per-host-manager knowledge inside
playpen. The leak stays visible in policy rather than hidden in a built-in default.

**`$HOME` gets no floor exceptions, because every candidate is a credential surface.**
`~/.gitconfig` can name a credential helper, `~/.ssh/config` an `IdentityAgent`, `~/.npmrc`
*is* a credential file. The model already has the right shape for this — the share list for
agent state is default-deny, empty unless named — so user tool config reaches the sandbox only
by being named. The concrete cost is that `git` inside the boundary has **no user identity** by
default. That is the right friction: the fix is for the profile to state a committer identity,
not for playpen to hand over a file that can execute a helper.

**Read implies execute, because denying execute alone buys nothing.** macOS separates
`file-map-executable` from `file-read*` and Landlock separates `LANDLOCK_ACCESS_FS_EXECUTE`, so
the split is available — but the agent has a writable area and can copy a binary into it, so a
read-without-execute root is a speed bump, not a boundary. Keeping two modes is the honest
model: playpen confines *what* the agent reaches, not *which bytes it runs*. ADR 0005 reserved
"deny `file-map-executable` on the browser binary" as the only permitted future form of a
browser distinction, and exclusions carrying an access class preserve that lever without a
third mode.

**Toolchain and scratch attach to the profile, not to a workspace.** Workspaces describe what
the agent works *on*; the toolchain describes what it works *with*, and the run scratch is a
property of the run. A toolchain inside one workspace would be accidental and inside each would
be duplicated; a run scratch as a provisioned area would force a fourth answer to "which
workspace's temp is `TMPDIR`?" that has no good one. Keeping the fields distinct also keeps a
workspace portable between hosts whose toolchain lives somewhere else entirely.

**The fd hole is not closable by any allow-list, so it is a law.** Opening a credential fd
outside the boundary and reading it from inside works — the sandbox gates *acquisition*, not
use of an already-open descriptor, and Apple documents this rather than treating it as a bug.
playpen closes every descriptor except 0, 1 and 2 before `exec`, which is exactly the three the
process-transparency contract of ADR 0002 already promised to inherit untouched.

## Consequences

- **The floor is code, the toolchain is policy, and the resolved capability set is dumpable.**
  Every path, mode, exclusion and Mach entry playpen is about to hand the backend can be
  printed without launching the agent. It is deliberately **not** the manifest: the manifest
  faces inward at the agent, and the agent has no business reasoning about the floor.

- **Exclusions are must-exist-or-refuse, like the roots they subtract from.** An exclusion
  naming a path that has since been garbage-collected is a leak that reopened silently — the
  exact failure class this decision exists to prevent.

- **An exclusion is a literal subpath plus an optional set of access classes**, defaulting to
  *all* when omitted. Classes are the ones both mechanisms express: `read`, `execute`, `write`.
  Default-to-all means an operator writing an exclusion without thinking gets the stronger
  subtraction; the weaker one is reachable only by naming it.

- **Versioned binary paths resolve at launch.** The reference host has `claude` at
  `/opt/homebrew/Caskroom/claude-code/2.1.224/claude` with a stable symlink at
  `/opt/homebrew/bin/claude`, and the sandbox enforces on the resolved vnode — so granting the
  symlink grants nothing. Policy names the stable path and playpen resolves it, granting both
  link and target. Reading a symlink is a filesystem fact, not interpretation of intent, so ADR
  0002 is untouched. An upgrade produces a **loud refusal naming the stale path**, never an
  agent that starts and cannot find its own binary.

- **Keychain isolation must be added, never inherited, and it costs the credential helpers.**
  Claude Code's own shipped profile *allows* `com.apple.SecurityServer`. The floor enumerates a
  short Mach set — `trustd`/`trustd.agent` and the dyld/notify essentials — so `SecurityServer`,
  `securityd` and the XPC variant are already denied by default with no knob to re-add them. No
  explicit deny list is shipped, because shipping one implies the allow list is permissive.
  Consequence inherited by the credential broker: `git-credential-osxkeychain`, `gh auth` and
  npm/docker credential helpers **fail loudly** inside the boundary.

- **The host temp is unreachable and `TMPDIR` must be set, not passed through.** The run scratch
  is always ephemeral, always writable, and its path is playpen's outright — the one place in
  the model where that is uncontroversial, because nothing outside the run can refer to it.
  macOS's real per-user temp under `/var/folders/…`, which many tools reach via `confstr`, is
  therefore unreachable. The environment allow-list owns making `TMPDIR` a set entry.

- **The enforcement suite gains negatives that assert on resolved targets, plus a loader
  canary.** Negatives: `~/.ssh/id_*`, `~/.ssh/config`, `~/.aws`, `~/.npmrc`, the Keychain Mach
  services and the host temp unreachable **through a resolved symlink**, not merely by literal
  path — the store finding means the leak arrives through a link the deny list never mentions.
  Positive: a dynamically-linked binary exits 0 under the bare floor, because that failure
  mode's signature is `rc=134` with empty stderr and it will silently return the day someone
  tidies the floor. And an fd negative no path assertion catches: open a credential fd outside,
  launch confined, assert the read fails.

- **playpen self-tests the floor before each launch.** It applies the floor to a throwaway child
  and asserts the canary before launching the real agent; failure is a refusal naming the
  missing capability, never a dead agent with no output. One extra `exec` per run, against the
  debugging cost of the alternative.

- **The compiled-profile ceiling is a backend budget the capability set can exceed, and playpen
  must own the refusal.** Left alone the operator sees `data object length 85963 exceeds maximum
  (65535)`, which names neither the policy nor the offending root. playpen detects the overflow
  and refuses in its own vocabulary — naming the ceiling, the resolved size, and the
  largest-contributing root — so that "collapse these roots into one with exclusions" is legible
  from the error. This makes the **Linux backend strictly more permissive about policy size than
  macOS**, a third place where the platforms are not equals, alongside the loopback residual and
  the mechanism's deprecation.

- **A closure is not a root list.** The naive Nix generator — one root per closure path —
  produces a policy playpen must reject. The shape that works is one coarse root plus
  exclusions, which is what a human writes and what a mechanical closure-expander does not. The
  shipped Nix integration inherits this as a hard constraint.

- **The floor is one object with per-platform contents.** The capability set stays the
  platform-neutral vocabulary and each backend renders the floor its own way; Linux has no
  `(literal "/")` trap but wants `/proc`, `/dev`, the loader and its cache, and under a mount
  namespace part of "the floor" is a set of mounts rather than a set of grants. What makes them
  the same object is the enforcement suite: the loader canary and the fd negative are written
  once and must pass on both, and how the floor is spelled never appears in a test.
