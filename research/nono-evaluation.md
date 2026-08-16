# Evaluating `nono` as playpen's mechanism and credential-proxy backend

Research ticket: [#2](https://github.com/firefly-engineering/playpen/issues/2). Map: [#1](https://github.com/firefly-engineering/playpen/issues/1).

Date: 2026-08-16. Sources are `nolabs-ai/nono` at commit `149579a7` (2026-08-13),
release `v0.73.0`, plus its in-repo docs. Repo cloned to `/tmp/nono-eval`; all file
paths below are relative to that clone unless noted.

Method: source over marketing copy. Where the docs and the code disagree, the code wins
and the disagreement is noted.

## TL;DR

`nolabs-ai/nono` is real, serious, and squarely in playpen's domain: ~202k lines of
Rust, Apache-2.0, weekly releases, in nixpkgs, built by the Sigstore founder.

The hypothesis is **half right and mis-framed on the other half**. playpen should
indeed own the mechanism interface — nono exposes no trait to plug into. But nono is
not a *sibling* of `sandbox-exec` and Landlock/bwrap; it is a **layer above them**.
nono's macOS path *is* Seatbelt (via direct `sandbox_init` FFI rather than spawning
`sandbox-exec`), and its Linux path *is* Landlock (plus seccomp, and deliberately not
bwrap). "nono or sandbox-exec on macOS" is the same mechanism twice.

The real decision is **at what altitude playpen cuts the dependency** (§7). The
credential-proxy work in particular (phantom tokens, OAuth capture, ephemeral CA,
L7 method+path policy) is far ahead of anything playpen would plausibly build, and
`nono run|wrap --config manifest.json` is a clean, registry-free, daemon-free seam
that takes exactly the fully-resolved JSON policy document #1 already specifies.

---

## 0. Identity check — is this actually a coding-agent sandbox?

Yes, unambiguously. `nolabs-ai/nono` is a Rust workspace (~202k LOC across
`crates/nono`, `crates/nono-cli`, `crates/nono-proxy`, `crates/nono-test-support`,
`bindings/c`), Apache-2.0, whose `crates/nono/Cargo.toml:10` describes it as a
"Capability-based sandboxing library using Landlock (Linux) and Seatbelt (macOS)".
The README's first-class use cases are Claude Code, Codex, OpenCode, OpenClaw,
Copilot. The `docs/cli/clients/` directory has per-agent pages for `claude`, `codex`,
`opencode`, `openclaw`.

This is the same problem domain as playpen. Proceeding.

---

## 1. Sandboxing mechanism

### macOS — Seatbelt via direct `sandbox_init()` FFI

`nono` does **not** shell out to `/usr/bin/sandbox-exec`. It declares the libSystem
symbols itself and links them directly (`crates/nono/src/sandbox/macos.rs:23-26`):

```rust
unsafe extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
    fn sandbox_free_error(errorbuf: *mut c_char);
}
```

The comment above it (`macos.rs:17-21`) is honest: "These are private APIs but have
been stable for years", citing the reverse-engineered Apple Sandbox Guide.

- It **does** generate SBPL (Scheme). `generate_profile()` emits `(version 1)`,
  `(deny default)`, `(allow process-exec*)`, `(allow process-fork)`, then
  `file-read*` / `file-write*` / `file-map-executable` with `(literal …)`,
  `(subpath …)` and `(regex …)` filters, plus `network-outbound` / `network-bind`
  rules (`macos.rs:456-480, 546-556, 658-728, 809-877`). Applied with flags `0`
  ("raw profile mode", `macos.rs:898-936`).
- **Deprecation is not handled.** Because the symbols are re-declared locally rather
  than imported from `sandbox.h`, Rust never sees the deprecation attribute. There is
  no `dlsym` probe, no OS-version gate, no fallback. `is_supported()` on macOS
  returns `true` unconditionally (`macos.rs:162-165`). This is a real long-term risk
  playpen would inherit — but note it is the *same* risk `sandbox-exec` carries, since
  `docs/cli/internals/seatbelt.mdx:13` correctly observes that `sandbox-exec` uses the
  same underlying mechanism.
- Extra macOS surface playpen would not get from `sandbox-exec`: **sandbox extensions**
  (`sandbox_extension_issue_file` / `_consume` / `_release`, `macos.rs:32-41`) let the
  unsandboxed supervisor mint HMAC-authenticated, path-scoped tokens for runtime
  capability expansion. That is a genuinely useful capability for the "toolchain
  reachability" friction problem in #1.
- Known hard limit encoded in source: Seatbelt cannot filter TCP by port, so per-port
  capabilities are a **hard error** on macOS (`macos.rs:881-889`,
  `NonoError::NetworkFilterUnsupported`). There is also a rule-count guard —
  `sandbox_init` crashes above ~17,770 rules (`macos.rs:538`).

### Linux — Landlock LSM + seccomp-BPF. No bwrap, no namespaces.

`crates/nono/src/sandbox/linux.rs` is 5,802 lines and is the entire story.

- Landlock via the `landlock` crate 0.4. ABI probed highest-first with
  `CompatLevel::HardRequirement`: `ABI_PROBE_ORDER = [V6, V5, V4, V3, V2, V1]`
  (`linux.rs:378`), `detect_abi()` at `linux.rs:391`. Feature predicates `has_refer`
  (V2), `has_truncate` (V3), `has_network` (V4), `has_ioctl_dev` (V5), `has_scoping`
  (V6) at `linux.rs:265-296`.
- If **all** probes fail, `is_supported()` is false and the CLI hard-fails
  (`linux.rs:510-533`; `crates/nono-cli/src/sandbox_prepare.rs:633-635`).
- seccomp is hand-assembled BPF (`SockFilterInsn` arrays at `linux.rs:1861, 1936,
  2847, 3150`) with an arch guard (`seccomp_arch_guard`, `linux.rs:1649`) and
  `prctl(PR_SET_NO_NEW_PRIVS)` rather than `CAP_SYS_ADMIN` (`linux.rs:1793-1804`).
  Full `SECCOMP_USER_NOTIF` machinery including `SECCOMP_IOCTL_NOTIF_ADDFD` fd
  injection (`inject_fd`, `linux.rs:2457`).
- **Mount namespaces / bwrap are deliberately rejected**, not merely absent.
  `docs/cli/internals/security-model.mdx:156-166`: unprivileged user namespaces are
  "disabled by default on Debian, restricted by AppArmor on Ubuntu 23.10+ … Building
  a core security boundary on a mechanism that distro maintainers are actively
  restricting is fragile." Grep confirms zero `unshare` / `CLONE_NEW*` / `bwrap` in
  sandbox code. This is a considered position playpen should weigh against its own
  Landlock/bwrap plan.
- cgroups v2 are used only for resource limits, only in the CLI, not the library
  (`crates/nono-cli/src/resource_cgroup.rs`).
- 9P filesystems are rejected outright because Landlock cannot cover them
  (`linux.rs:611-636, 1246`) — relevant to WSL2 and some VM shares.

### Windows / WSL2

Native Windows is explicitly unsupported (`crates/nono-cli/src/setup.rs:74-77`).
WSL2 is treated as Linux with spoof-resistant detection that reads only
kernel-controlled signals and explicitly refuses to trust `WSL_DISTRO_NAME`
("ignoring env var to prevent security downgrade", `linux.rs:471-508`). WSL2's MS
kernel 6.6 caps at Landlock V3, so per-port TCP filtering is unavailable and the
credential proxy is blocked by default there.

### There is no mechanism *trait*

This matters for the hypothesis. `Sandbox` is a **unit struct with `#[cfg]`-gated
inherent methods**, not a trait (`crates/nono/src/sandbox/mod.rs:76-78`), with
platform selection by `#[cfg(target_os = …)] mod linux; mod macos;`. The per-platform
APIs are not even the same shape: Linux `Sandbox::apply_auto` returns
`Result<linux::SeccompNetFallback>` (`mod.rs:99`) while macOS returns `Result<()>`
(`mod.rs:180`). Linux-only methods (`detect_abi`, `apply_seccomp*`, `restrict_execute`)
leak `linux::` types into the public surface, and `mod.rs:22-42` re-exports ~40
Linux-specific seccomp primitives.

The only two traits in the tree are `ApprovalBackend`
(`crates/nono/src/supervisor/mod.rs:81`) and `CapabilitySetExt`. Neither is a mechanism
abstraction. **A third party cannot add a backend without forking the crate.**

### Privilege model

No daemon, no root, no setuid, no `CAP_SYS_ADMIN`. The "supervisor" is simply the
parent process after `fork()`; the *child* sandboxes itself before `exec`
(`crates/nono-cli/src/exec_strategy.rs:475-479, 522`). The parent sets
`PR_SET_DUMPABLE(0)` / `PT_DENY_ATTACH` and services seccomp notifications. It holds
exactly the invoking user's privileges and nothing more
(`docs/cli/internals/security-model.mdx:318, 356`).

Two execution modes: `nono run` (supervised: fork + supervisor; enables audit,
rollback, capability expansion, proxy) and `nono wrap` (direct: apply sandbox, then
`exec`; nono disappears from the process tree; **no proxy possible**, since the proxy
requires a parent). See `docs/cli/features/execution-modes.mdx:10-13`.

---

## 2. Credential proxy

Yes, and it is the most impressive part of the project. `crates/nono-proxy` has three
modes (`crates/nono-proxy/src/lib.rs:1-18`): CONNECT tunnel, reverse proxy with
credential injection, and chaining through a corporate proxy.

### Placement relative to the boundary

The proxy runs **unsandboxed, in the supervisor process** — outside the boundary
(`lib.rs:17-18`). The sandboxed child is pinned by the kernel to
`NetworkMode::ProxyOnly { port, bind_ports }` (`crates/nono/src/capability.rs:880-888`),
i.e. it can reach `127.0.0.1:<port>` and nothing else. Enforced by Landlock
`NetPort::new(port, AccessNet::ConnectTcp)` on Linux (`linux.rs:1095-1183`) and
Seatbelt `(allow network-outbound (remote tcp "localhost:PORT"))` on macOS.

This is exactly playpen's "loopback stays open unconditionally, the credential proxy
lives inside the boundary" law, implemented.

### How the secret stays out — the phantom-token design

This is the answer to the ticket's central question, and it is better than "the
proxy injects a header":

**(a) Static credential routes.** The env var named by `env_var` in the profile
receives the **proxy session token, not the secret** — verbatim at
`crates/nono-proxy/src/server.rs:587-599`:

```rust
// API key set to session token (phantom token pattern).
if let Some(ref env_var) = route.env_var {
    vars.push((env_var.clone(), self.token.to_string()));
}
```

So a profile saying `"env_var": "GH_TOKEN"` puts a 256-bit random phantom in the
sandbox (`crates/nono-proxy/src/token.rs:35-50`). The agent sends the phantom; the
proxy validates it constant-time (`reverse.rs:1756-1794`, dispatched by location —
header, basic-auth, URL path, or query param — at `reverse.rs:2191-2295`), **strips**
it, and injects the real credential (`inject_credential_for_mode`, `reverse.rs:2630`).
The real value lives only in `Zeroizing<String>` in the supervisor
(`crates/nono-proxy/src/credential.rs:26-59`).

Caveat worth carrying into playpen's design: the phantom is the *same* session token
for every route (`server.rs:591, 598, 604, 615`). It is a bearer capability for the
whole proxy, not a per-route secret. Its blast radius is bounded by L7 endpoint
policy, not by the token itself.

Also: if a credential fails to load, **no** phantom is injected, deliberately, so it
does not shadow a real `gh auth` credential (`server.rs:579-585`).

**(b) OAuth-captured tokens.** Distinct mechanism. The agent performs the login
*inside* the sandbox; the proxy intercepts the provider's token endpoint, keeps the
real token outside, and rewrites the response body so the sandbox receives
`nono_<64hex>` (`crates/nono-proxy/src/oauth_capture/mod.rs:1-7, 164-183`;
`rewrite.rs:127`). Refresh flows swap phantoms back on the way out
(`rewrite.rs:12-125`). Resolution is **per-consumer and fail-closed**: the
`NonceResolver` (`token.rs:27-33`) returns `None` unless
`admitted_consumers.contains(consumer)` (`oauth_capture/mod.rs:223-231`). Phantoms
persist across sessions, capped at 4096 with a 90-day TTL (`mod.rs:47-48, 192-211`).

`jwt_phantom.rs` exists purely to defeat client-side structure checks: it wraps the
nonce as `<b64 header>.<b64 payload>.<nonce>` with `alg:none` and `exp` in 2100, the
nonce occupying the signature segment so substring substitution still resolves it
(`jwt_phantom.rs:18-33`). This is the kind of detail that only shows up after real
production contact.

**(c) SPIFFE.** JWT-SVIDs fetched per-request from the SPIRE Workload API and injected
as bearer (`crates/nono-proxy/src/auth.rs:9-19, 52-71`). No secret in the profile at all.

**(d) The weak mode, clearly labelled.** `--env-credential` / `env_credentials` puts
the real secret in the child's environment. The docs say so plainly
(`docs/cli/features/credential-injection.mdx:9-10`).

### Secret sources

`crates/nono/src/keystore.rs` dispatches by URI scheme: `env://`, `file://`,
`op://` (1Password), `bw://` (Bitwarden), `apple-password://`, `keyring://`, or a bare
name under keyring service `nono`. All return `Zeroizing<String>`. `env://` has a
denylist of forbidden variable names to stop it becoming an injection vector
(`keystore.rs:154-157`).

### TLS interception

Selective, not blanket. Interception triggers only for routes that need L7 visibility —
those with `endpoint_rules`, `credential_key`, or `oauth2`
(`tls_intercept/mod.rs:1-14`, `route.rs:68-73`). Plain host allowlisting stays an
opaque CONNECT tunnel.

The CA is **ephemeral, per-session, ECDSA P-256, 24h, key in `Zeroizing<Vec<u8>>`,
never written to disk** (`tls_intercept/ca.rs:1-38`). Trust reaches the sandbox as a
composed bundle PEM (parent `SSL_CERT_FILE` + host system trust store + ephemeral CA),
written mode `0o400` and pointed at by `SSL_CERT_FILE`-family vars
(`tls_intercept/bundle.rs:1-27`, `server.rs:541-551`), cleaned up on `Drop`
(`server.rs:622-646`). Cert-pinning clients that reject the minted cert are dropped and
audited — no silent fallback to transparent tunnel (`tls_intercept/mod.rs:14-19`).

The escape hatches are where the risk lives: `--trust-proxy-ca` persists the CA into
the macOS Keychain and the *user* trust store (needed because Go tools like `gh` and
`terraform` ignore `SSL_CERT_FILE`), and `--proxy-ca-cert`/`--proxy-ca-key` accept a
long-lived CA. Both widen exposure well beyond the session.

### L7 endpoint policy

Method + path-glob, compiled at startup, **default-deny**.
`EndpointRule { method, path }` (`crates/nono-proxy/src/config.rs:960-973`), `*` =
one segment, `**` = zero or more, method `"*"` = any. Evaluation order is
**deny → approve → allow → default**, first match wins, each returning an audit
label like `endpoint_policy.deny[GET /x]`
(`CompiledEndpointPolicy::evaluate`, `config.rs:1250-1288`). `Approve` routes to a
human approval backend with an optional timeout. `RouteStore` is deliberately
independent of `CredentialStore`, so a route can enforce L7 restrictions with no
secret attached (`route.rs:1-11`).

CLI surface: `--allow-endpoint 'github:GET:/repos/*/issues/**'`.

---

## 3. Default-deny filesystem allow-lists, and per-host egress allow-lists

### Filesystem — yes, genuinely default-deny

`docs/cli/internals/overview.mdx:8-12`: "Deny by default, allow explicitly." On macOS
the generated SBPL literally starts `(deny default)`. On Linux, Landlock's model is
inherently allow-list: anything not granted is denied.

Profile `filesystem` fields (`crates/nono-cli/data/nono-profile.schema.json`,
`$defs.FilesystemConfig`): `allow` (rw dir), `read`, `write`, `allow_file`,
`read_file`, `write_file`, `deny`, `bypass_protection`, `ignore`, plus six
`unix_socket*` variants. All path fields support `*` (one segment) and `**` (any
depth) globs, expanded at sandbox start — added in v0.73.0 (`CHANGELOG.md`, PR #1580).

Note the asymmetry documented on `deny`: "On macOS a runtime regex rule also covers
files created after sandbox start; on Linux only paths present at start time are
covered." A real portability wrinkle.

**On the profile path** there are baked-in protections nono applies on top of the
user's allow-list — and this is the single most important distinction in this report:

- The `default` profile is **always merged**, even with no `extends`
  (`crates/nono-cli/src/profile/mod.rs:3138-3143`), pulling in large system-read
  groups (`/bin`, `/usr`, `/lib`, `/etc/ssl`, `/dev/*`, `/proc/self`, …; on macOS the
  `system_read_macos` group is very broad, including `/nix`, `/Library`, `/Volumes`).
  These *are* removable via `groups.exclude`.
- Eight deny groups are marked `required: true` and **cannot be excluded** —
  `validate_group_exclusions` errors "Cannot exclude required groups: …"
  (`crates/nono-cli/src/policy.rs:1785-1806`). They cover `~/.ssh`, `~/.gnupg`,
  `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker`,
  `~/.git-credentials`, `~/.netrc`, `~/.npmrc`, `~/.vault-token`, `~/.config/op`,
  keychains, browser data, shell history and shell configs. The only escape is
  per-path `bypass_protection` (which removes the deny but does not itself grant).
- nono's own state (`~/.nono`, `$XDG_STATE_HOME/nono`) is force-denied always
  (`crates/nono-cli/src/protected_paths.rs:1-80`).

**On the `--config <manifest>` path, none of that applies.**
`CapabilitySet::try_from(&manifest)` builds *only* what the JSON says
(`crates/nono/src/manifest_convert.rs:21-139`) — no default profile, no groups, no
required denies. The only thing still injected is the `~/.nono` protected-root deny
(`crates/nono-cli/src/sandbox_prepare.rs:1296-1304`). You must grant `/usr`, `/lib`
etc. yourself.

This is decisive for playpen: **the manifest path is a genuine "nothing but what I
wrote" policy surface**, with no second policy author. The profile path is not.

### Network — per-host egress allow-lists, yes; but default is `unrestricted`

The capability manifest's `network.mode` is one of `blocked` / `proxy` /
`unrestricted`, and **the default is `unrestricted`**
(`crates/nono/schema/capability-manifest.schema.json`, `$defs.Network`). Likewise
`docs/cli/internals/overview.mdx:48-50`: "Network is allowed by default."

So it is not all-or-nothing — there are three tiers — but the *default* tier is the
wrong one for playpen, and playpen would have to always pin `mode: "proxy"` (or
`blocked`).

In `proxy` mode you get:

- `allow_domains` — exact hostnames and `*.example.com` wildcard suffixes. Note a
  wildcard does **not** match the bare domain (`crates/nono/src/net_filter.rs:106-265`,
  test at `:318`).
- `endpoints` — per-host method+path L7 rules, `{host: "api.github.com:443",
  rules: [{method, path}]}`, default-deny when `rules` is non-empty (§2)
- `ports` — `network.ports.{connect,bind,localhost}` TCP allow-lists. `connect_port`
  is **Linux Landlock V4+ only and unsupported on macOS**.
- `deny_domain`, evaluated **before** the allow-list, so a domain in both is always
  blocked (`docs/cli/usage/flags.mdx:403`)
- URL-shaped allows, e.g. `--allow-domain 'https://github.com/my-org/**'`
- **No CIDR allow syntax.** IP ranges appear only as a deny dimension.

Hostname enforcement is **L7, in the proxy** (`crates/nono/src/net_filter.rs:1-41`,
`FilterResult::{Allow, DenyHost, DenyLinkLocal, DenyNotAllowed}`, default-deny). The
kernel only pins the child to the proxy port. DNS is resolved *by the proxy*, which
then requires callers to connect to the resolved addresses rather than re-resolving —
a deliberate TOCTOU/rebinding defence (`crates/nono-proxy/src/filter.rs:13-23`).
Link-local ranges (including IPv4-mapped IPv6) and cloud metadata hostnames are
hardcoded non-overridable denies (`net_filter.rs:8-17, 79+`).

Consequence to internalise: **per-host egress is only as strong as the kernel's ability
to force traffic through the proxy.** Where that fails, the whole model degrades — which
is why WSL2 blocks `--credential` by default.

A documented Linux gap, stated candidly in `docs/cli/usage/flags.mdx:617`: Landlock
ABI v4+ enforces connect/bind **by port, not by destination address**. `--open-port
3000` permits connecting to port 3000 on *any* IP. Destination-host enforcement
requires proxy mode. (Port exceptions on kernels without Landlock V4 do fail closed.)

---

## 4. Policy format and CLI shape

### Two layers: profiles (human) and capability manifests (machine)

`docs/cli/internals/capability-manifest.mdx` is explicit about the split:

| | Profile | Manifest |
|---|---|---|
| Audience | Human authors | Machines (K8s operators, CI, policy engines) |
| Composition | `extends`, groups, legacy aliases | **Fully resolved, no composition** |
| Contains | Hooks, inheritance, deprecated fields | Only enforcement-relevant capabilities |

Profiles are **JSONC** (JSON plus `//` and `/* */` comments and trailing commas),
`.json` or `.jsonc`, parsed by `crates/nono-cli/src/jsonc.rs`. Manifests are strict
JSON. Two published JSON Schemas ship in-repo:

- `crates/nono-cli/data/nono-profile.schema.json` — 103 KB,
  `$id: https://nono.sh/schemas/nono-profile.schema.json`, exported via
  `nono profile schema`. No required top-level fields. Top-level keys:
  `extends`, `meta`, `filesystem`, `network`, `environment`, `security`, `linux`,
  `platform_overrides`, `groups`, `packs`, `hooks`, `session_hooks`,
  `command_policies`, `commands`, `credential_providers`, `credential_routes`,
  `env_credentials`, `credential_capture`, `secrets`, `rollback`, `undo`, `workdir`,
  `binary`, `command_args`, `interactive`, `diagnostics`, `open_urls`, `skipdirs`,
  `allow_gpu`, `allow_launch_services`, `allow_parent_of_protected`,
  `unsafe_macos_seatbelt_rules`.
- `crates/nono/schema/capability-manifest.schema.json` — 17 KB, JSON Schema Draft
  2020-12, `$id: https://nono.sh/schemas/capability-manifest.schema.json`. Top-level:
  `version` (the only required field), `filesystem`, `network`, `process`,
  `credentials`, `resources`, `rollback`. Domains modelled on WASI's capability model.
  **The schema is the source of truth** — the Rust types are generated from it by
  typify in `build.rs` (`crates/nono/src/manifest.rs:1-32`). Nested objects are
  `additionalProperties: false`, so a misspelled key is a hard parse error. Cross-field
  rules the schema cannot express live in `CapabilityManifest::validate()`
  (`manifest.rs:49-133`) — e.g. `rollback.enabled` and `resources.*` require
  `process.exec_strategy: "supervised"`.

Profile composition semantics worth knowing if playpen ever *reads* community
profiles (`docs/cli/features/profile-authoring.mdx:36-121`): list fields **union and
dedupe**, so a child can add but can never remove what a base grants; scalars are
overridden child-wins; `network.block` is sticky-true; inheritance depth is capped at
10. The union-only rule for lists is a real hazard — it means `extends` can only ever
widen filesystem access.

### The integration seam playpen would use

**`nono run --config manifest.json -- <cmd>` and `nono wrap --config manifest.json`.**
Confirmed in source at `crates/nono-cli/src/cli.rs:1413` (run) and `:1864` (wrap):
"Capability manifest file (JSON). A fully-resolved sandbox specification — mutually
exclusive with all other sandbox configuration flags", with a `conflicts_with_all`
list covering every other sandbox flag.

This is a clean seam: **no registry, no network fetch, no daemon, no default profile,
no group resolution, no profile inheritance** — one fully-resolved JSON document in,
one confined process out. The manifest path reads the file, `from_json` → `validate()`
→ variable expansion → `CapabilitySet::try_from`, and returns early
(`crates/nono-cli/src/sandbox_prepare.rs:1264-1340`).

Three caveats:

- `--config` takes a **file path only — no `-`/stdin support** (it is a `PathBuf`
  handed straight to `fs::read_to_string`, `sandbox_prepare.rs:1265-1271`). playpen
  would need a temp file, `/dev/stdin`, or process substitution.
- The `~/.nono` / `$XDG_STATE_HOME/nono` protected-root denies are still injected.
- Audit and session state are written under the state dir unless `--no-audit`;
  `nono wrap` skips the supervisor entirely.
- `docs/cli/usage/flags.mdx:1254-1264` still claims "Configuration file support is
  planned for a future release" — stale docs; the code is ahead.

`nono profile show <p> --format manifest` compiles a profile down to a manifest, which
is a useful way to *learn* what the community profiles actually grant.

### CLI subcommands

`setup`, `run`, `shell`, `wrap`, `why`, `proxy`, `rollback`, `audit`, `platform`,
`trust`, `ps`, `stop`, `detach`, `attach`, `logs`, `inspect`, `prune`, `session`,
`profile` (`init|show|list|schema|guide`), `package`/`pack` (`pull|remove|search`),
`completions`. `crates/nono-cli/src/cli.rs` alone is 4,596 lines; `nono run` carries
on the order of a hundred flags.

### Library / FFI surface

`crates/nono` is a real library published to crates.io as `nono` (v0.73.0, 2026-08-10).
Public modules: `capability`, `sandbox`, `supervisor`, `keystore`, `net_filter`,
`manifest`, `audit`, `trust`, `resource`, `state`, `undo`, `path`, `scrub`, `query`,
`diagnostic`. The relevant entry point is `Sandbox::apply_auto(&CapabilitySet)`.
C FFI in `bindings/c` (cbindgen), plus first-party Python (`nono-py`), TypeScript
(`nono-ts`) and Go (`nono-go`) bindings.

---

## 5. Language, distribution, liveness

- **Rust**, Apache-2.0, ~202k LOC.
- **Distribution:** `curl | sh` installer, Homebrew (`brew install nono`), **nixpkgs
  (`pkgs.nono`)**, AUR (`nono-ai-bin`), Debian/Ubuntu, Fedora, RHEL, openSUSE, RPM and
  AUR packaging in-repo, and crates.io for the library. The nixpkgs presence matters
  directly for #1's "how playpen ships to a macOS host and to a NixOS devbox".
- **Liveness:** very much alive. Last commit 2026-08-13, last push 2026-08-15. Monthly
  commit counts Feb–Aug 2026: 131 / 297 / 432 / 411 / 175 / 135 / 44. Release cadence
  is roughly weekly-to-biweekly (v0.64.1 2026-06-20 → v0.73.0 2026-08-10). 3,674 stars,
  241 forks, 146 open issues, 102 contributors, 1,647 issues/PRs filed since January.
  Governance doc, maintainers file, security policy, OpenSSF Best Practices badge,
  Sigstore lineage (Luke Hinds).
- **Bus factor is a real concern:** 1,405 of ~2,100 commits are from one person
  (Luke Hinds); the maintainer council is three people, all at Nolabs, despite
  GOVERNANCE.md's multi-organisation aspirations.
- **Maturity caveat:** pre-1.0, README warns "API changes may still occur". The
  org namespace just migrated (`always-further` → `nolabs-ai`), breaking profile
  references. Open issues include several correctness bugs in exactly the areas
  playpen cares about — e.g. #1632 "network.allow_http2 cannot be disabled by a
  descendant profile (OR-merge up the inheritance chain)", #1643 "macOS proxy CA:
  orphaned trust-settings entry causes silent, unrecoverable TLS failures", #1640
  "v0.72.0 seccomp network baseline breaks JVM NetworkInterface enumeration". These
  read as the normal churn of a young security tool under heavy use, not as neglect,
  but they are the kind of thing that will bite an integrator.

---

## 6. Refusal vs. silent downgrade

**Overwhelmingly refusal.** This is the area where nono is closest to playpen's stated
law, and it is closer than I expected going in.

The strongest single piece of evidence is the WSL2 proxy policy, whose default variant
is literally named `Error` and documented as "refuse to run rather than silently losing
enforcement" (`crates/nono-cli/src/profile/mod.rs:1936-1951`). The error text
(`crates/nono-cli/src/execution_runtime.rs:624-638`) explains that the sandboxed
process would be able to bypass the credential proxy, and requires an explicit
`wsl2_proxy_policy: "insecure_proxy"` opt-in to proceed — which then prints a loud
warning banner.

Equally telling: the Landlock ruleset is built with `CompatLevel::HardRequirement`,
**explicitly not `BestEffort`** (`crates/nono/src/sandbox/linux.rs:977-981`), so a
stale or forged ABI report fails rather than silently dropping enforcement.

Refuses:

- All Landlock probes fail → `SandboxInit` error, CLI exits
  (`linux.rs:510-533`; `sandbox_prepare.rs:633-635`).
- Landlock ruleset comes back `RulesetStatus::NotEnforced` → error
  (`linux.rs:1287-1291`). `restrict_execute` demands `FullyEnforced`
  (`linux.rs:1411-1420`).
- Network filtering requested but ABI < V4 and no seccomp fallback selected → hard
  error with an actionable message: "Network filtering requested but Landlock ABI {:?}
  lacks network support (requires V4+). Use apply_auto to enable seccomp fallback."
  (`linux.rs:816-820`). If neither Landlock nor a seccomp path can enforce, it errors
  rather than running unconfined (`linux.rs:806-815`).
- Per-port TCP capabilities on macOS → `NetworkFilterUnsupported`
  (`macos.rs:881-889`).
- Native Windows → refuses (`crates/nono-cli/src/setup.rs:74-77`).
- An *explicitly requested* process scope that the kernel cannot enforce → refuses.
  `SignalMode::AllowSameSandbox` without Landlock V6 errors with
  "requires Landlock ABI V6+ (LANDLOCK_SCOPE_SIGNAL), but this kernel does not support
  process scoping" (`linux.rs:696-723`).
- Tool-sandbox TCP port rules without Landlock V4 → `UnsupportedPlatform`
  (`crates/nono-cli/src/profile_runtime.rs:1043-1054`).
- A write grant over `/sys/fs/cgroup` while a resource limit is set → refused
  (`sandbox_prepare.rs:605-610`).
- Excluding a `required: true` deny group → refused (`policy.rs:1785-1806`).
- Resource limits with no delegated cgroup v2 subtree → "refusing to run unconfined"
  (`crates/nono-cli/src/supervised_runtime.rs:351`). Resource limits off-Linux → error.
- Paths on 9P filesystems Landlock cannot cover → rejected (`linux.rs:611-636`).
- WSL2 detection deliberately ignores `WSL_DISTRO_NAME` "to prevent security
  downgrade" (`linux.rs:471-508`).
- Docs assert the invariant explicitly: "If sandbox initialization fails, nono exits
  with an error rather than running the command unrestricted"
  (`docs/cli/internals/overview.mdx:105`), and the failure-mode tables in
  `security-model.mdx` are uniformly fail-closed.

Degrades rather than refuses — three cases, of which only one is genuinely quiet:

1. **The default process-scope modes are best-effort, and this is the one real
   silent-downgrade finding.** `SignalMode::Isolated` and `IpcMode::SharedMemoryOnly`
   are the *defaults*, but they are applied only `if abi.has_scoping()` (Landlock V6,
   kernel 6.12+). On an older kernel they are dropped and the run proceeds
   (`linux.rs:696-723`). The divergence is recorded in `LandlockScopePolicy
   { signal_requested, signal_enforced, abstract_unix_socket_requested,
   abstract_unix_socket_enforced }` (`linux.rs:345-369`) — but it is only printed
   under `-v` (`crates/nono-cli/src/output.rs:462-468`). Note the asymmetry: the
   *explicitly requested* `AllowSameSandbox` fails closed, while the *defaults*
   degrade quietly. Given that kernel 6.12 shipped in late 2024, most Linux hosts
   playpen targets today will silently lose signal-scoping and abstract-UNIX-socket
   scoping.
2. **Missing Landlock filesystem features print a yellow banner and continue** —
   "degraded: … (upgrade kernel for full support)" (`output.rs:390-455`). Per-path
   access rights dropped by `access_to_landlock()` (`linux.rs:538-592`) are logged only
   at `debug!` (`linux.rs:1216-1222`), but the aggregate degradation *is* surfaced by
   that banner, so this is visible-but-non-fatal rather than silent. Concretely: below
   kernel 6.2 `Truncate` is unhandled and below 5.19 `Refer` (cross-directory
   rename/link) is unhandled — in Landlock an unhandled right is not restricted at all.
3. **`sandbox_policy: landlock`** opts out of seccomp-notify, and the code notes it
   "leaves ProxyOnly's destination check unenforced" (`execution_runtime.rs:608-618`) —
   an explicitly-chosen weakening, not an accident.

Not a downgrade, despite appearances: the seccomp fallback is a *substitution*. On
kernels lacking Landlock networking, `ProxyOnly`/`Blocked` are enforced by
seccomp-notify instead (`SeccompNetFallback::{BlockAll, ProxyOnly}`,
`linux.rs:2645-2658`), and seccomp-notify is used on V4+ too because Landlock filters
ports only, never destinations (`execution_runtime.rs:645-652`).

**Bottom line against playpen's law** ("Refusal, never silent downgrade"): nono
substantially shares the law and in the WSL2 case states it in almost the same words.
The one place it does not hold is item 1. If playpen depends on nono, it should call
`detect_abi()` / `landlock_scope_policy()` itself and refuse before applying, rather
than trusting nono to refuse on its behalf.

---

## 7. Verdict against the hypothesis

> **Hypothesis:** playpen owns the mechanism interface and nono is ONE BACKEND among
> macOS `sandbox-exec` and Linux Landlock/bwrap — rather than playpen being a thin
> policy layer over nono.

The hypothesis is **half right, and mis-framed on the half it gets wrong.**

**Where it is right:** playpen should own the mechanism interface. nono provides no
such interface to plug into — `Sandbox` is a `#[cfg]`-forked unit struct with
platform-divergent signatures, not a trait, and cannot be extended without a fork
(§1). And nono is emphatically *not* a thin thing to layer over. It is a whole
competing product: registry, packs, signing/trust, audit ledgers with DSSE
attestation, rollback snapshots, session attach/detach, PTY multiplexing, hooks,
per-tool child sandboxes, human approval prompts. Making playpen "a thin policy layer
over nono" would mean adopting nono's entire policy model, its baked-in denylists, its
registry namespace, and its pre-1.0 API churn — and playpen's distinct laws (§3, §6)
do not survive that intact.

**Where it is mis-framed:** the hypothesis treats nono as a *sibling* of `sandbox-exec`
and `Landlock/bwrap` — one backend among peers. It is not a peer; it is a *layer above*
them. nono's macOS path **is** Seatbelt (the same kernel mechanism `sandbox-exec`
wraps, reached by linking `sandbox_init` directly instead of spawning a helper), and
nono's Linux path **is** Landlock (plus seccomp, and deliberately *not* bwrap). There
is no world in which playpen picks "nono" *or* "sandbox-exec" on macOS — that is the
same mechanism twice.

The real choice is therefore not *which backend*, it is **at what altitude playpen cuts
the dependency**, and there are three distinct options the ticket's framing collapses
into one:

1. **Depend on the `nono` crate as the mechanism layer** (`Sandbox::apply_auto(&CapabilitySet)`
   plus `capability::CapabilitySet`). playpen keeps its own policy document, its own
   selection logic, its own refusal semantics, and its own credential broker; it
   simply stops writing SBPL generators and Landlock ABI probes. This is the option
   that best fits the hypothesis's *intent* while respecting what nono actually is —
   and it buys ~6k lines of hard, well-tested, platform-specific code, including the
   macOS sandbox-extension path that `sandbox-exec` cannot offer at all.
2. **Shell out to `nono wrap --config <manifest.json>`** (§4). playpen compiles its
   own JSON policy into a nono capability manifest and execs. Clean seam, no registry,
   no daemon, language-agnostic — playpen need not be Rust. Costs: the manifest schema
   becomes a compatibility surface across a pre-1.0 project, and `wrap` mode forfeits
   the proxy entirely.
3. **Shell out to `nono run --config <manifest.json>`** to get the credential proxy and
   L7 egress too. This is the highest-leverage option and the one where the hypothesis
   is most clearly refuted, because the credential-proxy surface is where nono is
   furthest ahead of anything playpen would plausibly build: phantom tokens, OAuth
   capture with per-consumer fail-closed resolution, JWT-shaped phantoms, ephemeral
   per-session CA, DNS-rebinding defence, method+path L7 policy with a human-approval
   tier. Reimplementing that well is a multi-month effort with real security downside
   if done badly.

**Recommendation for the spec (#1), stated as a position to be grilled, not a
conclusion:** keep the hypothesis's *first* clause — playpen owns the mechanism
interface, the policy document, the selection logic, and the refusal law — and drop the
*second*. Do not model nono as one backend among `sandbox-exec` and bwrap; model it as
the **default implementation of both the macOS and Linux mechanism**, with a
playpen-owned trait behind which a direct `sandbox_init` / Landlock implementation
could later sit if the dependency sours. Then evaluate the credential proxy as a
**separate** adoption decision from the mechanism, because nono cleanly separates them
too (`RouteStore` is independent of `CredentialStore`; `nono wrap` gets the sandbox with
no proxy at all).

Three things playpen must handle explicitly rather than inherit:

- **The `unrestricted` network default** (§3). playpen must always pin `proxy` or
  `blocked` in the manifest it emits.
- **Profile-path vs manifest-path policy ownership** (§3). On the *profile* path nono
  is a second policy author: an always-merged `default` profile, plus eight
  non-excludable deny groups. On the `--config <manifest>` path it is not — the
  manifest is the whole policy. **playpen must use the manifest path, never the
  profile path.** This also means playpen owns the toolchain-reachability allow-list
  (nix store, `~/.cargo`, bun, LSPs) that #1 already flags as the largest source of
  real friction — nono will not supply it for free.
- **Best-effort default process scoping** (§6, item 1). playpen must probe the ABI and
  refuse itself.

## Open questions for follow-up

- **Is the `nono` crate genuinely policy-free?** Evidence says yes:
  `crates/nono/src/lib.rs:8-12` — "provides the mechanism for OS-enforced isolation
  without imposing any security policy. Clients … define their own policies" — and
  `macos.rs:1-6` says the caller is responsible for "implementing any security policy
  (sensitive path blocking, etc.)". All the group/denylist machinery lives in
  `crates/nono-cli`. If that holds under closer reading, option 1 gives playpen exactly
  the deep, policy-free mechanism module it wants, and this becomes the leading option.
- What is the actual stability of the `nono` crate's public API across 0.6x → 0.73?
  The README's pre-1.0 warning is generic; a diff of `sandbox/mod.rs` and
  `capability.rs` across releases would quantify the churn playpen would sign up for.
  The platform-divergent signatures on `apply_auto` (§1) are a smell worth measuring.
- Can the credential proxy be driven independently of the sandbox — is there a
  supported way to run `nono-proxy` under playpen's own supervisor? There is a `nono
  proxy` subcommand; if it can serve a process playpen confined itself, options 1 and
  3 compose rather than compete, which would be the best of both.
- How does nono's per-tool child sandboxing (`command_policies`) interact with
  playpen's law that "the unit of policy is the process tree, never the tool call"?
  These look like directly opposed positions and deserve their own grilling session.
  Note nono's framing is subtly different from per-*tool-call* permissioning — it is
  per-*executable* policy applied to a child process tree — so the conflict may be
  smaller than it first appears.
- `nono wrap --config` forfeits the proxy entirely (the proxy needs a parent). If
  playpen wants both minimal attack surface *and* credential brokering, it must either
  run its own broker or accept nono's supervised mode. Which is it?
