# The manifest is a generated projection, and playpen states facts and never instructions

The manifest is a JSON file written into the **run scratch** and pointed at by `PLAYPEN_MANIFEST`.
It is not authored: one resolution pass produces the **run record**, and the **capability set** and
the manifest are both derived views of it — outward at the kernel, inward at the agent. A
per-`kind` adapter may render those facts into the idiom that kind reads, and may never say what
the agent should do about them. `playpen explain --self` is withdrawn: the file *is* the document.

## Why

**A file the agent can read beats a command it must run.** ADR 0007 introduced `playpen explain
--self` so that no second code path could disagree with the manifest. Once the manifest is a real
file inside the boundary, the goal is better served by having no second code path than by having
two that agree — and the command's price is putting playpen's own binary into every profile's
toolchain root, so that the confinement binary is reachable by the confined process, in exchange
for printing back a document already at hand.

**The run scratch is the only location that does not fight a decision already made.** ADR 0002
forbids remapping, so there is no tidy `/playpen/manifest.json` to invent; a fixed host path is
shared across concurrent runs, which ADR 0010 spent an entire decision keying away from. The run
scratch is already run-keyed, already holds the ephemeral CA that `SSL_CERT_FILE` points at, and
cannot outlive the boundary it describes.

**An env var must be a name some existing program already looks up.** ADR 0001 deferred the split
to "which facts tools genuinely read", which is a list and not a rule, and a list grows: one
variable per provisioned area per workspace is combinatorial, and playpen would own the naming
scheme forever. The test is not whether a fact is useful to the agent but whether a program that
is *not* the agent reads that exact name by pre-existing convention. Everything workspace-shaped
fails that test and is manifest-only.

**The line playpen must not cross is instruction, not prose.** The per-workspace **agent state
directory** with an empty-by-default share list means playpen owns `~/.claude`, so it *could* drop
a file there that the agent reads as instruction. "Your landing zone is `/x/y`" is a fact about a
boundary playpen built. "Clone repositories into your landing zone" is an instruction, and tuned
per-`kind` prose is ADR 0002's stale-copy-of-someone-else's-CLI argument wearing different
clothes. Rendering generated from the manifest's own data stays on the right side of that line;
hand-written prompt fragments do not.

**Withholding the reachable set buys no confinement.** An agent can enumerate egress by trying,
so stating the mode and the resolved host list costs nothing and saves a round of denials against
hosts that can never be reached. The manifest's job is to make futile work visibly futile.
Exclusions are the exception and are omitted: a subpath carved out of a granted root is
discoverable only on denial, and enumerating those reads as a map of what is worth attacking.

_Extended by [ADR 0013](0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md):
under `open` the resolved host list is **absent rather than empty**, since there is no list and
fabricating one would state a fact playpen does not own. Credential routes are still listed, plus
the fact that the proxy is not the sole exit and a routed destination is authenticated only for
requests sent through it. ADR 0007's `403` + `X-Playpen-Denied` vocabulary is **omitted** under
`open` and `none` — teaching an agent to interpret an event that cannot occur states something
untrue about this boundary, which is the same test that omits exclusions._

**The manifest describes the boundary and never constitutes it.** It sits in writable scratch, so
an agent — or a prompt injection driving one — can rewrite it. Nothing moves when it does: the
kernel's answer to the next `open()` is unchanged, and the agent has lied only to itself. This is
the same shape as the ephemeral CA in the same directory, where corruption breaks the agent's own
TLS and leaves the proxy enforcing. Carving out a read-only sub-path would buy integrity against
an adversary who is already inside and gains nothing from the lie, at the cost of extending ADR
0006's exclusion machinery from brought roots to provisioned areas.

## Consequences

- **`PLAYPEN_MANIFEST` is a mandatory *set* entry**, joining `TMPDIR`, `NO_PROXY`, `HTTPS_PROXY`
  and `SSL_CERT_FILE`. It is the fifth, and the base environment allow-list inherits it.

- **The manifest is always written**, even for a single-workspace profile with nothing
  provisioned. "No manifest" must never be a state an agent has to interpret; `PLAYPEN_ACTIVE`
  answers confined-or-not on its own.

- **Three generated schemas from one resolution pass.** The manifest carries an integer
  `manifest_version`, its Rust serde type is canonical, and its JSON Schema is generated and
  CI-gated exactly as ADR 0009 requires of the policy and the resolved form. Additive changes
  bump nothing; a removal or a retype bumps the version.

- **The rendered view carries no compatibility promise.** Its consumer is a language model, not a
  parser, so it is a view of the JSON and versioned by nothing.

- **The manifest is strictly narrower than the run record.** It drops the selection trace and
  policy provenance — a record the agent can read is one it can be confused by, and provenance is
  the part that tells a hostile agent which document to attack.

- **The failure-interpretation section is per-platform in content and per-`kind` only in
  rendering.** An errno is a kernel fact; the backend supplies the set (`EPERM` on macOS, and on
  Linux the `EACCES`/`EXDEV`/`EPERM`/`ENOSYS` set ADR 0007 records). There is no per-agent
  knowledge in this section at all, which keeps ADR 0005's "all per-agent knowledge is confined to
  the `kind` table" true by making it vacuous here.

- **The landing zone is a convenience with a policy consequence, not an enforcement point.** An
  agent that ignores the manifest and clones into its CWD hits `EPERM` if that root is `read`, and
  simply succeeds if it is `readwrite` — leaving the landing zone's purpose quietly unmet. That
  degrades honestly, because no boundary moved: the clone landed somewhere policy already
  permitted. The alternative would require playpen to infer intent from a `git clone` ADR 0002
  forbids it to see.

- **ADR 0007 is amended** where it introduced `playpen explain --self`. The outward-facing
  `playpen explain` for the operator is untouched.

- **Each credential route names its delivery variable.** _Added by
  [#30](https://github.com/firefly-engineering/playpen/issues/30)._ playpen wrote that variable,
  so its name is a fact playpen owns, and naming it makes the credential recognisable as one —
  less likely to be logged or copied into a config file — without instructing anything. Two
  neighbouring statements are deliberately absent: *"the processes you spawn inherit your
  environment"* is a fact about the agent's behaviour, which playpen neither owns nor can know per
  `kind` without the per-harness knowledge ADR 0002 refuses; and *"the phantom is inert outside
  this run's proxy"* bears on no work the agent does and only invites reasoning about attack.

## Rejected alternatives

**A pointer-only adapter** — the adapter makes the manifest's *location* discoverable and nothing
more. Cleanly inside the line, but it under-delivers precisely where ADR 0006 left the agent with
nothing on first launch, and a bare pointer in a file the agent may not read fails in the same way
an unread manifest does.

**Prompt fragments tuned per `kind`.** Ruled out permanently, not deferred.

**A read-only carve-out for the manifest file.** Rejected above; the integrity it buys is against
an adversary for whom the lie is worthless.

- _Amended by [ADR 0020](0020-playpen-claims-credential-confinement-only.md) ([#35](https://github.com/firefly-engineering/playpen/issues/35)): the manifest states **no egress setting and no host list**. It
  always states that the proxy is not the only way out and that a routed destination is
  authenticated only for requests sent through it; the `403` vocabulary is stated iff some route
  carries an **endpoint rule set**. On Linux below Landlock ABI 9, where unix-socket oracles stay
  reachable, the regime is recorded **outward only** — run record and `playpen explain` — on the
  same reasoning that omits exclusions here._

- _Amended by [ADR 0021](0021-agent-state-belongs-to-the-profile.md) ([#36](https://github.com/firefly-engineering/playpen/issues/36)): the agent state directory is shared by every run of a profile, so the
  rendered view states **profile-stable facts only**, plus the fact that this run's full layout is
  in `$PLAYPEN_MANIFEST`, written to a temporary file and renamed into place on every launch. The
  adapter owns the kind's instruction entry point, and a share entry naming that file is
  **composed by reference** through the kind's import line, never merged._
