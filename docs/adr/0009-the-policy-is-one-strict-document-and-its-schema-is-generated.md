# The policy is one strict document, and its schema is generated from the code that enforces it

The **policy** is a single YAML 1.2 document of keyed tables — `version`, `definitions`,
`minters`, `fragments`, `workspaces`, `profiles`, `shims`. Every field is strictly parsed:
an unknown key, an unknown `version`, or an explicit tag is a **refusal**. The JSON Schema
that describes it is *generated* from playpen's own serde types, never hand-written beside
them. And the **resolved** form is a different schema entirely — the **capability set**, the
selection trace and the egress list, speaking enforcement vocabulary rather than policy
vocabulary.

## Why

**One document, because a directory is merging by the back door.** ADR-adjacent, the
invocation contract fixed that the policy is located by a fixed ordered search path, first hit
wins, never merged — so that "which rule won" always has one answer. A `policy.d/` would give
that answer back to an ordering rule inside the confinement binary. The pressure to split is
real but it is a *generation* problem, not a *format* problem: shim declarations are
host-installation facts while profiles and workspaces are operator policy, and on a Nix host
they come from different modules. Nix already composes modules into one derivation, so the
merge happens in the build system where it is allowed and visible, and playpen receives one
file. The same argument retires multi-document YAML: a `---` stream is concatenable, so
`cat a.yaml b.yaml` would quietly start working.

**Keyed tables rather than arrays of named things, because the name is load-bearing.** A
workspace name is what keeps the filesystem and forge halves in sync, and persistent
**provisioned areas** are keyed by it *across runs*. Under keyed tables a duplicate name is a
parse error. Under an array of `{name, ...}` it is a semantic check somebody has to remember to
write — and the failure it would have caught is two profiles disagreeing about what `playpen`
means while resolving to the same persistent area path. Ordering is not meaningful anywhere
this matters: profile selection is by **longest** CWD prefix, not by position, which is also
why the catch-all is simply `prefixes: ["/"]` and needs no magic string.

**Strict parsing, because a silently ignored field is a leak that never announces itself.**
JSON's and YAML's shared default is to ignore what they do not recognise. A `exclude` typed
`excludes` would be dropped without complaint, and an **exclusion** that stops applying is
precisely the failure the toolchain-floor decision named: a leak that reopened silently. So
unknown fields refuse, with a code naming the offending path. The cost is stated rather than
hidden — a field cannot be forward-declared for a newer playpen — and that is the right trade
for a binary whose job is to be wrong loudly.

**YAML rather than JSON, because strictness made the document uncommentable.** JSON has no
comments; the convention of `"//"` keys is exactly the unknown field that now refuses. That
would leave the most explanation-hungry document in the project with nowhere to put the
explanation. This amends the effort's standing "policy input is a JSON document" law rather
than discarding it: the **data model** is JSON, and YAML 1.2 is the accepted surface syntax
*because JSON is a subset of it*, so a generated `.json` policy remains valid input and the
generated JSON Schema still describes both.

**Anchors, aliases and merge keys are allowed, and this does not contradict the no-merge law.**
That law is about combining multiple policy *sources*. An anchor is one document, one author,
expanded deterministically by the parser before the data model exists; afterwards there is
exactly one data model and `playpen explain` is unaffected. Billion-laughs expansion is not a
threat from a document whose author is already trusted host code, in the same class as a
**minter**. Explicit tags are refused, because unlike anchors they buy nothing — every type is
schema-fixed — while carrying a real parser-hazard class. Banning them also settles YAML's
implicit-typing trap for free: with tags gone and fields schema-typed, `mode: no` refuses as an
invalid enum variant instead of silently becoming `false`.

**The anchor block is the one place playpen deliberately does not interpret.** An anchor must
be defined somewhere, and strict parsing would refuse a top-level block it did not declare.
Defining anchors inline on the first real profile works but couples the base to an arbitrary
profile that can then be deleted out from under it. So `definitions:` is a *declared* key with
a deliberately free-form type — categorically different from tolerating unknown keys, because
strictness survives where it matters: expansion runs first, so a typo inside `definitions` is
still refused at the **use site** where the profile is strict-checked.

**Generated schema, because two hand-maintained descriptions of one format will disagree, and
the schema will be the one that is wrong.** playpen is Rust, so the serde types are what
actually parse the document; the JSON Schema exists for editor completion and for the Nix
module to check against before emitting. Generating it makes disagreement impossible rather
than merely discouraged, and a CI gate asserting the committed schema matches a fresh
generation is what keeps that true.

**The resolved form is a different object, not a unioned policy.** The capability set carries
absolute paths with access modes, a network mode and an environment allow-list — nothing above
that: no workspace names, no lifetimes, no profiles. It faces *outward*, at the kernel, where
the **manifest** faces inward at the agent. If the resolved form were still a policy it would
have to retain workspace names to be re-resolvable, and the one property that makes
`explain --json` worth trusting is that it shows exactly what the backend receives. The bridge
back to the authored document is a `from:` provenance string on every entry, which names the
authored source without importing its vocabulary — and which the egress design already required
for allow-list fragments.

## Consequences

- **The search path gains a second extension.** `policy.yaml` is looked for before
  `policy.json` at each location on the fixed search path, and **both present at one location
  is a refusal**, not a precedence rule. The extension selects the parser and nothing else.
  A silent precedence here would be the easiest possible way to lose "which rule won has one
  answer" at the file level.

- **A policy refusal names file, line and column** — and where a key arrived through a merge
  key, both the use site and the definition site. This is a requirement on the parser, not a
  crate preference, and it is assertable by the enforcement suite. It has teeth: the obvious
  merge-key implementation deserialises to an untyped value, applies the merge, then
  re-deserialises, and an untyped value carries no spans. A document with anchors is exactly
  the document where "which line" is the question, since the offending key may have arrived
  from somewhere else entirely.

- **`version` is refused if unrecognised, never best-effort parsed.** The same law as unknown
  fields, applied to the document as a whole.

- **A profile with `egress.mode: none` and a credential route is incoherent**, and incoherence
  is a launch-time refusal. The schema cannot express this — it is a cross-table constraint —
  which marks the boundary between what the generated schema checks and what playpen checks
  after parsing. The schema is a parser contract, never the whole of policy validation.

- **`agent_state.share` is keyed by `kind`**, which refines rather than breaks the law that all
  per-agent knowledge lives in the `kind` table. That law governs knowledge *playpen* holds;
  what an operator wants shared out of `~/.claude` versus `~/.omp` is a genuinely different
  list — `settings.json` means nothing to `omp` — and one flat list would be shared into
  whichever directory the kind selected, which is a leak rather than a convenience.

- **Writing `flags: [{arg, required}]` down exposed a contradiction this decision does not
  own.** Enforcing that a user cannot contradict a required injected flag needs per-`kind` argv
  grammar, which ADR 0002 forbids and which sits on the wrong side of the invocation contract's
  `--` wall. The schema records the field; what enforcement it carries is a separate decision.

- **Later decisions extend the route object additively.** Endpoint rules and any
  subscription-login state land as new fields on an existing table rather than a new shape,
  because the route table is already the discriminating object.
