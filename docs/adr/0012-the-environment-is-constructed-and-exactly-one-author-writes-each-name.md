# The environment is constructed, never filtered, and exactly one author writes each name

The child's environment is built from nothing rather than inherited and pruned. Three layers
compose it: a non-subtractable **floor** of pass-through names any process needs to start, the
**set** entries playpen writes itself, and a per-profile **allow-list** of additional names to
pass through, composable from named fragments. Policy may additionally **set** literal values,
which win over floor pass-through. Two authors writing one name is a launch-time refusal, not a
precedence rule. Only names are matched; inherited values are never inspected.

## Why

**Default-deny on env is not the same shape as default-deny on the filesystem.** ADR 0006's
floor is a grant against a mechanism that would otherwise deny everything; the environment has
no mechanism at all, so "deny" here means *not constructing an entry*. Once that is said
plainly, the deny-list half of the design disappears: there is nothing to filter, because
nothing arrives. This is why ADR 0005's per-`kind` **suppression table** keeps its "set" half
and loses its "strip" half — the genuine case it was written for is the *shim* case, where an
outer playpen's `PLAYPEN_ACTIVE` and kind vars must not reach a nested invocation, and that
falls out of construction rather than needing a rule.

**The floor earns a built-in default the same way ADR 0006's did, and by the same test.** ADR
0006's line was that the floor decides whether `exec` *returns*, while everything deciding what
is *reachable* stays with the single policy author. The env analogue is exact: `PATH`, `HOME`,
`USER`/`LOGNAME`, `SHELL`, `TERM`, `LANG` and the enumerated `LC_*`, `TZ` are facts about a
*process*, not about what it may reach. The test has teeth — it excludes `LOCALE_ARCHIVE`, which
looks like a startup fact on a NixOS host but is a fact about the **toolchain root** that was
brought, and points into a path the profile granted. That belongs in a shipped fragment, and
keeping it out is what stops the floor's membership from becoming something an operator must
reason about.

**Inspecting an inherited value would be interpretation.** ADR 0002 forbids playpen reading
meaning into what it is handed, and a value check is precisely that. The temptation is a `PATH`
entry pointing back at the shim directory — but ADR 0002's own invocation contract already
retired that, since the shim finds the real binary by an absolute path the policy declares and
`PLAYPEN_ACTIVE` guards re-entry. More generally the check buys nothing the boundary does not
already give: a value can only ever name a path, and every path is enforced by the mechanism
regardless of how the agent came to know it.

**That argument also decides which hazardous names are banned, and it bans far fewer than
expected.** `NODE_OPTIONS`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `GIT_SSH_COMMAND`,
`PI_SHELL_PREFIX` are all *path-shaped*: a `--require` at an unreachable path fails as `EPERM`,
so a permanent ban buys the illusion of protection rather than protection. On macOS the platform
has already closed the dyld case for both flagship binaries anyway — each is signed with
hardened runtime, so dyld strips `DYLD_*` before the process starts. `SSH_AUTH_SOCK` is the one
exception and it is a *different kind of name*: it is a unix socket to an **unconfined signing
oracle**, an egress channel the proxy cannot see and cannot deny. Allow-listing it would silently
reopen everything ADR 0004 closed, in one line an operator would read as innocuous.

**A policy that may only allow-list names cannot express the case that motivated the work.**
Forcing a curated, Nix-managed `PATH` — so that what the agent can *find* matches what the
profile *granted* — requires authoring a value. That is not interpretation, because the author
is the operator, who is trusted host code in the same class as ADR 0008's **minter**. So `set:`
exists, and passing the host `PATH` through is merely the *default*, not the model.

## Consequences

- **Six mandatory set entries, and they are a refusal if unset.** `TMPDIR` (ADR 0006),
  `NO_PROXY` in both spellings (research: proxy env honouring), `HTTPS_PROXY` (ADR 0004),
  `PLAYPEN_MANIFEST` (ADR 0011), `PLAYPEN_ACTIVE` (ADR 0002), and the CA pair **`SSL_CERT_FILE`
  and `NODE_EXTRA_CA_CERTS`**. The pair is not redundancy: measured against the shipped binaries,
  both `claude` and `omp` are Bun and honour `NODE_EXTRA_CA_CERTS`, while `git` and `curl` beside
  them read `SSL_CERT_FILE`. Two TLS stacks inside one boundary is the same fact that already
  forced `NO_PROXY` to carry both spellings. This corrects ADR 0008.

- **Colliding with a name playpen sets is `refusal.env.reserved`.** Not because the value is
  dangerous — because two authors of one variable is ADR 0009's "which rule won" problem in its
  smallest possible package. The reserved set is exactly the six above plus every **delivery**
  name declared by a credential route, which makes the collision detectable at launch from the
  resolved policy alone.

- **Policy `set:` is profile-level only, and may reference a provisioned area by typed
  reference.** `CARGO_HOME: !area <workspace>/<area>` rather than a literal, because playpen owns
  the path and an `ephemeral` area's path does not exist at authoring time. This *resolves* ADR
  0011's deferral rather than reopening it: ADR 0011 refused to auto-export one variable per area
  because they would appear unbidden, whereas here the operator names both the variable and the
  area, and the variable is one a real tool already reads by pre-existing convention — ADR 0011's
  own rule. It is a typed reference and never string interpolation, since `${...}` is a template
  language and this project has ruled out pattern languages three times. An unknown area name is
  a refusal, free from ADR 0009's keyed tables. `set:` is profile-level because a per-workspace
  one would need merging across a profile's workspace list, which is the hazard ADR 0001 named:
  two workspaces disagreeing about `CARGO_HOME` with no signal.

- **Fragments carry names, never values.** A name is host-independent — `CARGO_HOME` means the
  same thing everywhere — while a value is a fact about *this* host. That asymmetry is why a
  store path reaches the policy by **generation** (the Nix integration composes attrsets and
  emits one file, where the merge is visible) rather than by a shipped fragment overriding a
  floor entry from three files away. Fragments merge none by default, as ADR 0004's host-entry
  fragments do, and each surviving name carries the `from:` provenance ADR 0009 generalised.

- **No patterns; `LC_*` is enumerated.** Exact names only, matching ADR 0004's host entries. The
  `LC_*` family is a closed set the C library defines, so enumerating it costs a dozen lines
  once; an operator reaching for a prefix is usually reaching for a *namespace they do not
  control*, which is the leak this decision exists to prevent.

- **An allow-listed name absent from the host env is absent, not a refusal — a stated exception
  to the no-silent-downgrade law.** ADR 0006 made a missing **exclusion** a refusal because a
  vanished exclusion is a leak that reopened silently. An absent env var is the mirror image: it
  *removes* access rather than restoring it, so it fails closed, and refusing would make one
  policy undeployable across a fleet of near-identical hosts for no security gain. Playpen's own
  **set** entries are the opposite and stay a refusal, which is where the law still bites.

- **`HOME` and `PATH` pass through unrewritten by default.** ADR 0002's path-identity law forbids
  remapping, and rewriting `HOME` to a provisioned area is remapping in an env-var costume — it
  would silently redirect `~/.gitconfig`, `~/.ssh` and `~/.cargo` for every tool in one stroke. A
  denied read under `$HOME` is `EPERM`, which ADR 0007 established is honest and distinguishable
  from absence. A `PATH` naming ungranted directories is likewise honest: exec fails `EPERM`, not
  `ENOENT`.

- **The per-`kind` state-directory redirect is uniform after all.** `CLAUDE_CONFIG_DIR` and
  `PI_CODING_AGENT_DIR` are each private to their own binary, so ADR 0001's per-workspace agent
  state directory is delivered the same way for both kinds and nothing touches a shared
  namespace. Setting `XDG_CONFIG_HOME` instead is ruled out **permanently**: it would redirect
  `git`, `gh` and every other XDG-aware tool in the same stroke — a per-kind quirk leaking into a
  shared namespace, the same class of error as ADR 0005's advisory manifest field. A future
  `kind` whose binary has no private redirect is a refusal, not an XDG exception.

- **Inward: nothing. Outward: everything.** The manifest does not restate the environment — an
  agent can read its own `environ`, so it would be the one section adding nothing, and ADR 0011's
  no-second-code-path argument (which withdrew `explain --self`) applies verbatim. The env
  allow-list is part of the **capability set** per ADR 0003, so `playpen explain --json` shows it
  in full with fragment provenance. This is the manifest/capability-set split doing exactly what
  it was built for.
