# A Homebrew toolchain is a keg list, and a shim is the playpen binary

ADR 0015 answered distribution for Nix-managed hosts only. On a macOS host without Nix, the
playpen binary arrives by **one channel, a Homebrew formula in a project tap**; its toolchain is
written as a **keg list** — one toolchain root per `/opt/homebrew/opt/<keg>` stable symlink,
resolved at launch — rather than a coarse `/opt/homebrew` root with exclusions; and a **shim is a
symlink to the playpen binary** named for its `shims` key, which lets playpen refuse to launch
when anything that will run *outside* the boundary on the next launch is writable from inside it.

## Why

**A coarse Homebrew root leaks the same way a coarse store root did.** ADR 0014 left the
mutable-tree case on a coarse root with exclusions, on the reading that Homebrew has no closure
to expand. Measured on the reference host, `/opt/homebrew/etc/ssh/` holds SSH host *private*
keys, mode 600 and owned by the operator's uid — readable under any read grant on the prefix.
Excluding `etc/ssh` closes that one and nothing else: the next formula that writes a secret
under `etc/` or `var/` reopens the leak with no change to the policy, a deny-list inside an
allow-list. It is ADR 0014's `home-manager-files` finding in a different prefix.

**Homebrew already links like a closure.** A bottled binary loads its libraries through
`/opt/homebrew/opt/<dep>/lib/…` — `node` names about twenty kegs and nothing outside them but
`/usr/lib` and `/System`. Those `opt/` links are re-pointed by `brew upgrade` rather than
renamed, so a keg list survives upgrades where a versioned `Cellar/<name>/<version>` path does
not. Granting a keg is the existing stable-symlink rule — resolve, grant link and target — so
a keg list needs **no new schema concept**: it is a set of ordinary toolchain roots with literal
paths. A `kegs: [node, git]` field was rejected because expanding it would teach playpen
Homebrew's layout and bake in a prefix that is a host fact (`/opt/homebrew` against
`/usr/local`).

**Homebrew computes the set; playpen does not.** The operator names the kegs the agent needs and
closes them with `brew deps --installed --union <kegs>`, Homebrew's own command over its own
metadata. This is the off-Nix counterpart of `playpen.lib.closureRoots`, owned by the tool that
owns the format. A playpen subcommand reading Homebrew metadata or Mach-O load commands would be
ADR 0002's always-stale second copy, would make playpen an author, and would still miss
runtime-only dependencies — `dlopen`, interpreter modules, `git` calling `ssh`. An omitted keg
is loud: the never-`ENOENT` law turns it into a denial naming the path.

**No Homebrew fragment ships.** ADR 0012 fixed that a fragment carries names and never values,
because a value is a fact about one host. A toolchain fragment would carry paths, which are
exactly such values; an environment fragment of `HOMEBREW_*` names has no customer, since the
confined agent has no business running `brew`.

**The stale reference paths are the argument for naming stable links.** ADRs 0014 and 0015 cite
`/opt/homebrew/Caskroom/claude-code/2.1.224/claude` and `/opt/homebrew/Cellar/omp/17.3.4/bin/omp`.
Weeks later the cask is `claude-code@latest` at `2.1.283` and `omp` is no longer brewed, so a
policy that pinned either path would now refuse to launch. `/opt/homebrew/bin/claude` survived
both changes.

**A shim is a symlink because then there is only one thing to guard.** playpen already refuses
when the policy it read sits inside anything the selected profile can write. The playpen binary
and the shim are in the same class: they run unconfined on the *next* launch, so a hostile
driver that can rewrite either has escaped one launch later without touching the policy. If the
shim is a generated script, its contents are a second artifact needing the same guard; if it is
a symlink to playpen, looked up as `shims.<argv[0]>`, the guard reduces to three paths. The agent
binary is deliberately left out: tampering with it lands inside the boundary on the next run.

**Signing costs nothing it was feared to.** `sandbox_init()` needs no entitlement and no
hardened-runtime exception, so signing matters only to Gatekeeper's quarantine check on a
downloaded file, which a tap formula does not trigger. A notarized standalone artifact is not
offered in v1, and `cargo install` — which lands the binary under `$HOME` — is a development
path, not a supported install.

## Consequences

- **The self-integrity refusal is extended.** playpen refuses to launch if the resolved playpen
  executable, the invoking shim link, or that link's directory is writable by the selected
  profile — on the same footing as the existing policy-location refusal.

- **Shim placement off Nix is the operator's `ln -s`.** The formula cannot install shims, because
  it cannot see the policy; there is no `playpen shim install`. A documented one-liner per shim
  is the whole surface.

- **One residual is named rather than solved.** A profile-writable directory *earlier on the
  host's PATH* than the shim can shadow it for the next host-side invocation. playpen sees only
  its own invocation's PATH, never a future one's, so ordering PATH stays the operator's
  responsibility.

- **The suite runs on a host with no Nix.** The closure negatives are a named **skip** — a
  precondition missing on this host, not `n/a` by platform. One negative is added: under a
  keg-list fixture, a manufactured decoy keg beside the granted one is denied, two-part per
  ADR 0016's decoy rule. It catches resolution granting the parent `Cellar/<name>`, all of
  `opt/`, or the prefix — a silent regression. The matching positive is inadmissible, since
  broken resolution fails every brewed tool loudly. It runs on hosted macOS, where Homebrew is
  preinstalled, and skips by name where there is no prefix.

- **`--no-filesystem` is a CLI contract, not a Nix feature.** The derivation in ADR 0015 is one
  caller; a non-Nix operator runs the same mode, and a plain `playpen check` with existence
  checks against this host stands in for the build-time gate.

- **Non-Nix Linux is covered without a new rule.** Distro packages live under OS-owned paths the
  floor already grants; linuxbrew and `~/.local` are mutable trees and follow the keg-list or
  coarse-root shapes above.

- **A coarse root with exclusions stays legal.** It remains the shape for a mutable tree with no
  stable per-package links; it is no longer the recommended shape for Homebrew.
