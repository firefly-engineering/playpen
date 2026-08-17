# The Nix module is a projection, and home-manager is the primary tier

playpen ships a flake exposing a **home-manager module** as the primary policy generator, with
NixOS and nix-darwin modules as a secondary tier for hosts that have no per-user Nix. The
module's option tree **mirrors the policy schema one-to-one** and its emitter is a pure
projection: it cannot contribute anything the operator did not write, because it has nowhere to
contribute it from. What knowledge the module holds lives in `playpen.lib` helpers that return
**values** the operator explicitly splices in — never in defaults that merge behind them. The
emitted document is a plain file on playpen's fixed search path, carrying no trace of its
generator.

## Why

**The module must be the same author, and a mirror is what makes that structural.** The whole
idea is in tension with ADR 0004's single-policy-author law: a module that *generates* policy is
an author wearing a hat. The distinction that matters is the one ADR 0003 walked away from in
`nono-cli` — an always-merged `default` profile and non-excludable deny groups, i.e. defaults
that combine with operator input behind their back. A one-to-one mirror cannot do that. The
tempting alternative is a higher-level Nix interface that *lowers* intent into policy
(`workspaces.myrepo.src = ./.;` deriving roots and areas), and it is the trap: the moment the
module derives a root from an intent, "which rule won" needs the module's source to answer.
Helpers keep the module's knowledge reachable without making it implicit — the operator writes
the reference, so it appears in their configuration and in their diff.

**home-manager is the primary tier because the policy is overwhelmingly user-scoped.** Workspaces
name repositories under the operator's home; the toolchain is a closure of packages from their
own profile. A system-level `/etc/playpen/policy.yaml` as the main surface would have the wrong
things in it. This matters more than it looks, because ADR 0009 fixed the policy as **one
document located by a fixed ordered search path, first hit wins, never merged** — so a system
document is not a base layer that a user document refines. It goes entirely dead the moment a
user document exists, including its `shims`. The system tier therefore exists for a specific
case — a host with no per-user Nix, where an agent runs as a service account — and not as a
foundation.

**The module owns the whole document, because owning part of it would produce two.** Scoping the
module to host-installation facts (`shims`, toolchain) and leaving operator policy elsewhere
looks like it protects the single-author law and does the opposite: playpen accepts exactly one
file, so two partial authors have to be reconciled by something, and that something is a merge.
The reference host also removes the argument's factual basis — both agent binaries are Homebrew
(`/opt/homebrew/Caskroom/claude-code/2.1.224/claude`,
`/opt/homebrew/Cellar/omp/17.3.4/bin/omp`), entirely outside Nix, so no tier can *derive* a shim
path. It is a literal the operator writes either way, and the host-fact/operator-policy split
survives as a shape in the option tree rather than as a boundary between modules.

**The module is self-contained and never reads `osConfig`.** On the reference host home-manager
is integrated as a nix-darwin module, so the tiers can see each other; a standalone
home-manager user has no `osConfig` at all. Reading it when present is ADR 0004's second-author
problem wearing a Nix hat — the same configuration would emit different policy depending on how
home-manager happened to be installed, and "which rule won" would become a question about module
plumbing. The cost is repeating two absolute paths that no tier gets for free anyway.

**The generated document must be indistinguishable from a hand-written one.** The effort's
standing law is that Nix is a good way to generate and version the policy but playpen has no Nix
dependency at runtime. What protects that is not a code property but an artifact property:
playpen reads a file at a fixed path and cannot tell whether a human, Nix, or a shell script
wrote it. Pointing playpen at a store path — by env var or by symlink — would break this twice
over, adding a selection input the invocation contract deliberately closed and dragging garbage
collection into the launch path.

**The apparent load-bearing risk resolves by scoping rather than by code.** ADR 0014 makes the
module the only correct author of a toolchain closure, which looks like it makes Nix mandatory.
It does not: a host whose toolchain is not content-addressed has no closure to expand and uses a
coarse root with exclusions, exactly as the Homebrew case on the reference host does. It is not
that playpen requires Nix; it is that **Nix hosts require the module**.

## Consequences

- **The search path is now pinned, having been referenced by three earlier decisions and never
  enumerated.** `$XDG_CONFIG_HOME/playpen/` → `~/.config/playpen/` → `/etc/playpen/`, first hit
  wins, `.yaml` before `.json` at each location, both present at one location a refusal. A
  `--policy <path>` flag precedes all of them, because the enforcement suite must run against a
  policy that is not the host's and would otherwise have to mutate `~/.config` to test. There is
  deliberately **no `PLAYPEN_POLICY` env var**: the invocation contract added `PLAYPEN_PROFILE`
  for buzz and stopped there, and an env-var policy override swaps the whole document rather
  than selecting within it.

- **The policy file is part of the home-manager generation.** Emitted via
  `xdg.configFile."playpen/policy.yaml"`, so `~/.config/playpen/policy.yaml` is a symlink into
  the generation. Policy and toolchain closure are then atomically in sync, and
  `home-manager switch --rollback` restores both together. Under an out-of-store activation
  script a rollback would silently desynchronise the policy from the closure it names — the same
  class of failure ADR 0014 exists to close, in a new disguise. playpen reads policy from
  *outside* the boundary, so nothing here is self-referential.

- **`playpen.lib.closureRoots` is the module's only real knowledge.** It takes a package list and
  returns root entries. It is a pure function of its argument with no host knowledge and no
  baked-in defaults, which is a strictly better fit for the no-implicit-merge law than the
  exclusion helper ADR 0014 removed the need for. The module's remaining knowledge reduces to
  "how to expand a closure and count it," which is not policy at all.

- **Validation splits into three tiers, and the module owns the first two.** Parsing and
  cross-table coherence are host-independent and run in a derivation via a
  `playpen check --policy <f> --no-filesystem` mode, so an incoherent policy fails the rebuild
  rather than the next agent launch. **Existence checks do not run at build time** — the
  toolchain closure may not be realised on the build machine and the Homebrew shim targets
  certainly are not — because they are facts about *this host at this moment*. This maps onto a
  boundary ADR 0009 already drew, extended by one tier: the generated schema is a parser
  contract, coherence is playpen's post-parse check, existence is launch-time. `--no-filesystem`
  is a new CLI surface the enforcement suite must assert on. Making the derivation impure to
  close the gap is rejected: a policy check that fails for reasons unrelated to the
  configuration is worse than no check.

- **The toolchain path count is checked at build time, and the coarse shape stays reachable.**
  Per ADR 0014 the closure size is known at evaluation, so a toolchain that will not fit the
  compiled-profile ceiling is refused at `home-manager switch`. An operator may still declare a
  coarse root with exclusions, which is required for non-content-addressed trees regardless.

- **Shim installation is opt-in per `kind`.** Installing shims onto `PATH` by default would mean
  that enabling the module silently changes what `claude` means in every shell — a behaviour
  change nobody wrote down, which is the second-author problem relocated from the document to
  the environment. But generation-only throws away the one thing Nix is unambiguously good at
  here, and the invocation contract already retired the PATH-ordering hazard by having the shim
  resolve an absolute path from policy. Per-`kind` opt-in keeps the operator's `enable = true`
  the place the decision is visible.

- **No module-shipped defaults, in any tier.** Every option defaults to empty. Convenience is
  reachable only by naming a `playpen.lib` value, which is the Nix-layer restatement of the law
  that playpen ships fragments and merges none.
