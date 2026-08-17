# The floor is built in, and the toolchain is a declared closure

*Supersedes [ADR 0006](0006-the-floor-is-built-in-and-the-toolchain-is-a-coarse-root.md).*

playpen always applies a **floor** — a built-in, non-subtractable grant of read and execute
under OS-owned paths, plus a short enumerated set of Mach services — that no policy can widen
or narrow. Everything else arrives as declared policy. The **toolchain** is a profile-level set
of read-only roots. Where the tree is **content-addressed**, the toolchain is the *closure of an
operator-declared package set*, emitted as one root per store path, and there are no exclusions
because nothing else was ever granted. Where the tree is **mutable** — a Homebrew prefix, an
ordinary directory — the toolchain is a coarse root carrying **exclusions**: literal subpaths
subtracted from it, optionally per access class. Nothing under `$HOME` is in the floor, nothing
in the floor is writable, and the run's writable temp is a profile-level **run scratch**
provisioned by playpen.

ADR 0006 held that closure-precise granting was *unrepresentable* and that a coarse `/nix/store`
root with exclusions was the only available shape. That measurement was taken against the wrong
set, and both halves of the conclusion were wrong. This ADR replaces it.

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
author. This is unchanged from ADR 0006 and is the half of it that survives intact.

**Closure-precise granting is representable; ADR 0006 measured the operator's whole profile.**
The 1413 paths that produced 163 KB of SBPL and the `data object length 85963 exceeds maximum
(65535)` hard error were the closure of `home-manager-path` — the operator's *entire* user
environment, which on the reference host includes an editor, a window manager and a music
library manager. An agent executes none of it. Measured against a plausible agent toolchain
(`git`, `jj`, `ripgrep`, `fd`, `bash`, `coreutils`, `curl`) on the same host:

| | store paths | SBPL source | compiles |
|---|---|---|---|
| `home-manager-path` closure | 1413 | 163 KB | **no** — 87,306 > 65,535 |
| agent toolchain closure | **108** | 12.5 KB | **yes** |

Under that 108-path profile `git --version` and `jj --version` both load and run, so dynamic
linking resolves entirely inside the closure. Probing the ceiling: 1000 paths compiles, 1100
overflows at 67,984 bytes, 1413 at 87,306 — roughly 62 compiled bytes per path, putting the wall
**between 1000 and 1100 store paths**. A realistic toolchain uses about a tenth of the budget.
The ceiling is real and still worth owning, but it sits an order of magnitude above what the
toolchain needs rather than below it.

**A coarse `/nix/store` root is not merely imprecise — it leaks the entire history of the
operator's dotfiles.** ADR 0006 closed the `~/.ssh/config` leak with a single exclusion naming
the current `home-manager-files` derivation. On the reference host there are **120
`home-manager-files` derivations and 57 `home-manager-path` derivations** live in the store, and
the stale ones still contain readable copies of every managed dotfile — verified: two
arbitrarily chosen stale generations each yield a 36-line `.ssh/config`. Excluding the current
generation leaves 119 copies of the same secret inside a granted root. Worse, the exclusion is
**not maintainable by hand**: the path changes on every rebuild, and the previous one usually
still exists, so a stale exclusion passes must-exist-or-refuse while the live dotfiles sit
unexcluded — the silently-reopened leak that must-exist exists to prevent, arriving through the
mitigation instead of through its absence. Under a declared closure this whole class is not
mitigated but **absent**: `/nix/store` is never granted, so neither the live nor any stale
generation is reachable. Verified under the 108-path profile — `~/.ssh/config` and a stale
`…-home-manager-files/.ssh/config` both return `Operation not permitted`.

**Relocating the closure into one subtree was considered and does not work.** The attractive
alternative to enumerating 108 roots is to have Nix build a single tree containing the toolchain
— an FHS-style view — so the grant collapses to one rule. It fails for a reason that is not
playpen's: Nix binaries carry **absolute store paths baked in** (`LC_RPATH`, the interpreter,
data references), so a copied `git` still resolves its libraries through `/nix/store/…` paths
that the new grant does not cover. Relocatable Nix closures are a known-unsolved problem.
`buildFHSEnv` sidesteps this by **bind-mounting rather than copying**, which is Linux-only —
macOS has no unprivileged bind mount, and macOS is the platform where the ceiling binds. A
Linux-only bind-mount backend would in fact be correct, and would preserve the invocation
contract's path-identity law by mounting each store path at its own name, but it requires
namespace creation that ADR 0003's narrow surface excludes and that nono does not perform. It
would buy a fifth platform asymmetry while fixing nothing on the platform with the problem.

**Exclusions survive, demoted to the trees whose reasoning actually fits them.** The reference
host's agent binaries are Homebrew — `/opt/homebrew/Caskroom/claude-code/2.1.224/claude` and
`/opt/homebrew/Cellar/omp/17.3.4/bin/omp` — with no closure to expand, so a coarse root with
exclusions is the shape there and will remain so. What changes is that this is now the case for
**mutable** trees rather than the general case. That also restores must-exist-or-refuse to
sound footing: its rationale is that a vanished path is a silently reopened hole, which is true
of a directory that moved and false of a content-addressed path, where deletion means the
content is genuinely gone. Because content-addressed trees are now narrowed by *naming the
closure* rather than by subtraction, the awkward exception that reasoning would have required is
never needed.

**`$HOME` gets no floor exceptions, because every candidate is a credential surface.**
`~/.gitconfig` can name a credential helper, `~/.ssh/config` an `IdentityAgent`, `~/.npmrc`
*is* a credential file; on the reference host `~/.config` also holds `1Password`, `gcloud` and
`cachix`. The model already has the right shape — the share list for agent state is
default-deny, empty unless named — so user tool config reaches the sandbox only by being named.
The concrete cost is that `git` inside the boundary has **no user identity** by default. That is
the right friction: the fix is for the profile to state a committer identity, not for playpen to
hand over a file that can execute a helper. This also absorbs a question the Nix work raised —
a policy document at `~/.config/playpen/policy.yaml` is owned by the same uid the agent runs as,
but a workspace root broad enough to reach it has already surrendered 1Password, so it is not a
new residual and needs no special exclusion.

**Read implies execute, because denying execute alone buys nothing.** macOS separates
`file-map-executable` from `file-read*` and Landlock separates `LANDLOCK_ACCESS_FS_EXECUTE`, so
the split is available — but the agent has a writable area and can copy a binary into it, so a
read-without-execute root is a speed bump, not a boundary. ADR 0005 reserved "deny
`file-map-executable` on the browser binary" as the only permitted future form of a browser
distinction, and exclusions carrying an access class preserve that lever without a third mode.

**Toolchain and scratch attach to the profile, not to a workspace.** Workspaces describe what
the agent works *on*; the toolchain describes what it works *with*, and the run scratch is a
property of the run. A toolchain inside one workspace would be accidental and inside each would
be duplicated; a run scratch as a provisioned area would force a fourth answer to "which
workspace's temp is `TMPDIR`?" that has no good one. Keeping the fields distinct also keeps a
workspace portable between hosts whose toolchain lives somewhere else entirely.

**The fd hole is not closable by any allow-list, so it is a law.** Opening a credential fd
outside the boundary and reading it from inside works — the sandbox gates *acquisition*, not use
of an already-open descriptor, and Apple documents this rather than treating it as a bug.
playpen closes every descriptor except 0, 1 and 2 before `exec`, which is exactly the three the
process-transparency contract of ADR 0002 already promised to inherit untouched.

## Consequences

- **"A closure is not a root list" inverts.** ADR 0006's consequence held that the naive Nix
  generator produces a policy playpen must reject, and that the workable shape "is what a human
  writes and what a mechanical closure-expander does not." Both clauses now read backwards: a
  closure *is* exactly a root list, no human can write 108 hashed store paths correctly, and the
  mechanical expander is the only author that can. The shipped Nix integration inherits this as
  its central job rather than as a hard constraint to work around.

- **The compiled-profile ceiling becomes a build-time check.** The path count of a declared
  closure is known at evaluation time and is host-independent, so a toolchain that will not fit
  can be refused at `home-manager switch` rather than at agent launch. playpen must still own
  the launch-time refusal — naming the ceiling, the resolved size and the largest-contributing
  root, since the raw `data object length … exceeds maximum` names neither the policy nor the
  offending root — but it becomes the backstop rather than the primary signal. Linux remains
  strictly more permissive about policy size than macOS; with the wall an order of magnitude
  above a real toolchain, this is now the least pressing of the platform asymmetries.

- **The toolchain closure must be GC-rooted by whatever generated it.** The policy names store
  paths and exclusions are must-exist-or-refuse, so a `nix-collect-garbage` that removes a
  toolchain path turns into a launch refusal. The generator already produces a generation and
  can root the closure there for free. playpen must **not** register a GC root itself: that
  would be a runtime Nix dependency, which the effort's standing law forbids.

- **Exclusions are must-exist-or-refuse, and that law now applies only where it is sound.**
  Literal subpaths, an optional set of access classes drawn from `read`, `execute` and `write`,
  defaulting to *all* when omitted — so an operator writing an exclusion without thinking gets
  the stronger subtraction. They apply to mutable trees; content-addressed trees are narrowed by
  declaration instead.

- **Versioned binary paths resolve at launch.** `claude` sits at
  `/opt/homebrew/Caskroom/claude-code/2.1.224/claude` with a stable symlink at
  `/opt/homebrew/bin/claude`, and the sandbox enforces on the resolved vnode — so granting the
  symlink grants nothing. Policy names the stable path and playpen resolves it, granting both
  link and target. The same fact is why a Nix *profile* cannot be the toolchain root:
  `home-manager-path/bin/git` is a symlink out to `…-git-2.51.2/bin/git`, so granting the
  profile grants nothing usable and the closure must be named directly.

- **Keychain isolation must be added, never inherited, and it costs the credential helpers.**
  Claude Code's own shipped profile *allows* `com.apple.SecurityServer`. The floor enumerates a
  short Mach set — `trustd`/`trustd.agent` and the dyld/notify essentials — so `SecurityServer`,
  `securityd` and the XPC variant are already denied by default with no knob to re-add them. No
  explicit deny list is shipped, because shipping one implies the allow list is permissive.
  Consequence inherited by the credential broker: `git-credential-osxkeychain`, `gh auth` and
  npm/docker credential helpers **fail loudly** inside the boundary.

- **playpen self-tests the floor before each launch.** It applies the floor to a throwaway child
  and asserts the canary before launching the real agent; failure is a refusal naming the
  missing capability, never a dead agent with no output. One extra `exec` per run, against the
  debugging cost of the alternative.

- **The enforcement suite's negatives change shape.** ADR 0006's negatives asserted on resolved
  targets because a coarse store root leaked through symlinks the deny list never mentioned.
  Under a declared closure the sharper assertion is that **a store path outside the declared
  closure is unreachable** — concretely, a stale `…-home-manager-files/.ssh/config`, which is the
  case a coarse root plus a current-generation exclusion silently permits. The remaining
  negatives stand: `~/.ssh/id_*`, `~/.ssh/config`, `~/.aws`, `~/.npmrc`, the Keychain Mach
  services and the host temp, each through a resolved symlink rather than by literal path. The
  positives stand too: a dynamically-linked binary exits 0 under the bare floor (that failure
  mode's signature is `rc=134` with empty stderr and it will silently return the day someone
  tidies the floor), and the fd negative — open a credential fd outside, launch confined, assert
  the read fails.

- **The floor is one object with per-platform contents.** The capability set stays the
  platform-neutral vocabulary and each backend renders the floor its own way; Linux has no
  `(literal "/")` trap but wants `/proc`, `/dev`, the loader and its cache. What makes them the
  same object is the enforcement suite: the loader canary and the fd negative are written once
  and must pass on both, and how the floor is spelled never appears in a test.
