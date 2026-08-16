# Host sandboxing mechanisms — capability matrix

Research output for [#3](https://github.com/firefly-engineering/playpen/issues/3) (parent: [#1](https://github.com/firefly-engineering/playpen/issues/1)).

**Question.** For each host mechanism available to playpen, what can and cannot be enforced
against the three enforcement surfaces — filesystem confinement, network egress control,
credential isolation — and what is the honest enforcement-integrity claim?

**Method.** Primary sources only: Apple man pages and headers *as shipped on this host*,
Apple developer documentation, kernel.org documentation, man7.org, and upstream source
(bubblewrap, Chromium, Nix, nixpkgs). macOS claims were verified by **live experiment on
this host** (macOS 26.5.2, `Darwin 25.5.0`, `xnu-12377.121.10~1/RELEASE_ARM64_T6050`, Apple
silicon, SIP enabled); all experiments were confined to `/tmp/pp-sbx`. Linux claims are
documentary — no Linux box was available, so composed-rule conclusions are marked as
inference.

Provenance tags used throughout:

| Tag | Meaning |
|---|---|
| **[LOCAL]** | Verified by experiment on this macOS host |
| **[DOC]** | Stated in a vendor/kernel primary source |
| **[SRC]** | Read from upstream production source |
| **[INFER]** | My composition of documented rules; not directly verified |
| **[RE]** | Reverse-engineered or community folklore; no authoritative spec exists |

**The two workload shapes** every mechanism is assessed against:

- **`claude`** (Claude Code) — forks real subprocesses (bash, node, ripgrep).
- **`omp`** ([oh-my-pi](https://github.com/can1357/oh-my-pi)) — a single fat process embedding
  `brush` (bash) and **58 CLI utilities in-process**, running persistent Python and Bun kernels
  that call back into the agent's tools **over a loopback bridge**, plus Puppeteer browser
  automation. Confirmed from its README: *"brush is the bash … and 58 command-line utilities
  (ls, sed, sort, xargs, even jq) ported into the builtins crate"*; *"Ours runs persistent
  Python and a Bun worker, and either kernel can call back into the agent's own tools … over a
  loopback bridge."*

---

## 0. Executive summary

**Five findings that constrain playpen's design, in order of how much they cost:**

1. **On macOS, `sandbox-exec` is the only mechanism that can confine an arbitrary binary you
   launch, it is deprecated, and there is no supported successor.** Not App Sandbox (signature-
   and bundle-gated, and its egress policy is *two booleans*), not Endpoint Security (**has no
   network authorization event at all** — verified against this host's SDK headers), not Network
   Extension (Apple-approval-gated, system-wide). Apple's own repo carries an open, unanswered
   issue asking for exactly this replacement. playpen either accepts a deprecated dependency or
   has no macOS story.

2. **No mechanism on either platform can express per-host egress allowlisting.** SBPL's compiler
   hard-errors with `host must be * or localhost in network address` **[LOCAL]**. Landlock's
   `struct landlock_net_port_attr` has **no address field at all** — it gates the TCP *port only*
   **[DOC]**. seccomp cannot dereference a `struct sockaddr` **[DOC]**. nftables/iptables resolve
   hostnames once at rule-load time, which is useless against CDN-fronted registries.
   **Per-host policy must live in an L7 proxy on the far side of the boundary, on both platforms.**
   This is a hard architectural constraint on the egress-allowlist ticket, not a preference.

3. **macOS sandboxes cannot be nested — neither to loosen *nor to tighten*.** A second
   `sandbox_init` inside an existing sandbox returns `EPERM` and the profile is ignored **[LOCAL,
   matches `sandbox.h`]**. Verified consequence: **Chrome's own sandbox dies inside an outer SBPL
   sandbox** (`sandbox initialization failed: Operation not permitted` → `FATAL: GPU process isn't
   usable. Goodbye.`), and works only with `--no-sandbox` **[LOCAL]**. The same applies to Claude
   Code's *own* Seatbelt sandbox, whose SBPL profile is visible in the shipped binary **[LOCAL]**.
   playpen must take over policy from its guest, not layer over it.

4. **Loopback stays open on both platforms, but each needs a specific incantation.** On macOS the
   commonly copy-pasted `(allow network* (local ip "localhost:*"))` **silently permits all
   external egress** — the correct filter is `remote`, and binding a listener additionally needs
   `network-bind` + `network-inbound` **[LOCAL]**. On Linux a fresh netns has `lo`
   administratively **DOWN**; `unshare -n` does not raise it, `bwrap --unshare-net` does **[SRC]**.
   Both facts are load-bearing for `omp`'s Python/Bun bridge.

5. **Neither platform's mechanism can be undone by the confined process — that part is genuinely
   strong.** SBPL is one-shot and inherited; `sandbox_suspend` fails unprivileged **[LOCAL]**.
   Landlock is irrevocable and stackable-only-tighter **[DOC]**. seccomp is irrevocable **[DOC]**.
   `setns()` back to the host netns is blocked by capability rules in the owning userns **[DOC]**.
   The weak flank on both platforms is *everything reached through another process*: Mach/XPC
   services on macOS, and inherited fds / bound sockets everywhere.

**Bottom line per platform.** macOS gets one layer (SBPL) plus a loopback proxy, and playpen
inherits that layer's deprecation risk. Linux gets a four-layer stack — bubblewrap (mount ns)
+ Landlock (irrevocable FS) + netns (unforgeable egress boundary) + L7 proxy (the only place
per-host policy can live) — with seccomp as attack-surface trim and cgroups v2 explicitly *not*
in the security column.

---

## 1. Master matrix

Legend: **Y** yes · **P** partial/conditional · **N** no.

### 1.1 macOS

| | **SBPL / `sandbox-exec`** | **App Sandbox** | **Endpoint Security** | **Network Extension** | **Virtualization / Containerization** |
|---|---|---|---|---|---|
| Confine an arbitrary binary you launch | **Y** [LOCAL] | N — needs signature + entitlements + bundle | N — global monitor, not attached to a process | N — filters flows, doesn't confine | Y, but Linux guests only |
| FS default-deny + allow-list of roots | **Y** [LOCAL] | P — container + App-Review'd temporary exceptions | Y, but as a system-wide daemon | n/a | Y (VM boundary) |
| Read vs write distinction | **Y** [LOCAL] | P — coarse `read-only`/`read-write` | Y | n/a | Y |
| Survives exec / grandchildren / orphans | **Y** [DOC + LOCAL] | Y (inheritance is the default) | n/a | n/a | Y |
| Deny network wholesale | **Y** `(deny network*)` [LOCAL] | Y (omit `network.client`) | **N — no IP AUTH event exists** [LOCAL] | Y | Y |
| Per-host / per-domain egress allow-list | **N** — compiler: `host must be * or localhost` [LOCAL] | **N** — two booleans | **N** | **Y** | Y (own stack) |
| Per-port egress | Y `(remote ip "*:PORT")` [LOCAL] | N | N | Y | Y |
| Loopback open, external denied | **Y** — `(remote ip "localhost:*")` [LOCAL] | N | N | Y | Y |
| Bind a loopback listener inside | Y — needs `network-bind` + `network-inbound` [LOCAL] | P — `network.server` is all-interfaces | N | n/a | Y |
| Block `~/.ssh`, `~/.aws` | **Y** [LOCAL] | Y (container) | Y (globally) | n/a | Y |
| Block Keychain (`SecurityServer` Mach service) | **Y** — targeted `(deny mach-lookup)` [LOCAL] | Y (`keychain-access-groups`) | P (`AUTH_XPC_CONNECT`) | n/a | Y |
| Confined process can self-unconfine | **N** [LOCAL] | N | n/a | n/a | N |
| Nestable / re-appliable | **N — neither loosen nor tighten** [LOCAL] | N | n/a | n/a | Y |
| Gate to use | **none** — no root, no signing, no entitlement [LOCAL] | signing + App Review for exceptions | Apple-approved entitlement + root + FDA + sysext | Apple-enabled capability + Dev ID + notarization + user approval | self-serve entitlement; macOS 26 + Apple silicon |
| Deprecated? | **Yes** since 2017 — still shipping, 511 Apple profiles depend on it | No | No | No | No |

### 1.2 Linux

| | **Landlock** | **bubblewrap** (mount+user ns) | **seccomp-bpf** | **netns** | **cgroups v2** | **cgroup-eBPF** |
|---|---|---|---|---|---|---|
| FS default-deny + allow-list | **Y** (rights-based) | **Y** (built up from empty; unbound paths are *absent*) | **N** — cannot dereference pointers | N | N | N |
| Read vs write distinction | **Y** (+ exec, truncate, dir, create/remove) | Y (`--ro-bind` / `--bind`) | N | — | — | — |
| Survives exec + grandchildren | **Y**, irrevocable | **Y** (mount ns inherited) | **Y**, irrevocable | **Y** | P — process can be moved between cgroups | P — same |
| Works unprivileged | **Y** (needs only `NO_NEW_PRIVS`) | Y (needs unprivileged userns) | **Y** (`NO_NEW_PRIVS`) | Y (with `CLONE_NEWUSER`) | P (delegated subtree) | **N** — `CAP_BPF`+`CAP_NET_ADMIN` |
| Deny network wholesale | P — TCP only, ABI≥4 / k6.7+; **UDP ungated below ABI 10** | **Y** `--unshare-net` | P — block `socket(AF_INET)` | **Y** | N | Y |
| Per-host allow-list | **N — port only, no address field** | N | N | N alone (needs proxy) | N | Y (sees `user_ip4`) |
| Loopback open, external denied | **N** — cannot distinguish `127.0.0.1:P` from `1.2.3.4:P` | **Y** (`lo` brought up automatically) | N | **Y**, and isolated from host loopback | N | Y |
| Blocks `~/.ssh` read | Y (but `stat` still leaks metadata) | **Y** (simply not bound in) | N | — | N | N |
| Blocks ssh-agent socket | P — abstract: ABI 6; pathname: ABI 9 | **Y** (not bound in) | N | P (abstract only) | N | N |
| Broker a proxy socket in | N (cannot *add* paths) | **Y** (`--bind`) | P (unotify `ADDFD`) | — | N | — |
| Confined process can undo it | **N — never** | P — ro flags are locked; nested userns is the surface | **N — never** | **N** (`setns` needs caps in owning userns) | Y (can move itself) | Y (same) |
| Requires root | N | N | N | N | N (delegated) | **Y** |
| `claude` (forking) OK | Y | Y (use `--unshare-pid`) | Y | Y | Y (`pids.max` useful) | Y |
| `omp` (single fat process) OK | Y | P — `--new-session` conflicts with PTY use | Y | Y (`lo` up ⇒ bridge works) | Y | Y |
| Chromium automation survives | Y | P — **only without `--disable-userns`** | P — **only if `clone(CLONE_NEWUSER)` allowed** | Y | Y | Y |

---

## 2. macOS: `sandbox-exec` / Seatbelt

### 2.1 Deprecation status — the load-bearing fact, established exactly

**`man 1 sandbox-exec` on this host** [LOCAL]:

```
NAME
     sandbox-exec —— execute within a sandbox (DEPRECATED)
...
     The sandbox-exec command is DEPRECATED.  Developers who wish to sandbox an
     app should instead adopt the App Sandbox feature described in the App
     Sandbox Design Guide.
Mac OS X                     March 9, 2017
```

**`man 3 sandbox_init` does not exist on this host** [LOCAL] — `No manual entry for sandbox_init
in section 3`. The header survives, at
`/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/usr/include/sandbox.h`, carrying
`API_DEPRECATED("No longer supported", macos(10.5, 10.8), ...)`.

**`man 7 sandbox` is present and is NOT marked deprecated**, and it documents the two properties
playpen's whole design rests on [DOC]:

> New processes inherit the sandbox of their parent. Restrictions are generally enforced upon
> acquisition of operating system resources only. For example, if file system writes are
> restricted, an application will not be able to open(2) a file for writing. However, if the
> application already has a file descriptor opened for writing, it may use that file descriptor
> regardless of restrictions.

**Is it still functional on macOS 26.5? Yes, unambiguously** [LOCAL]. `/usr/bin/sandbox-exec`
exists (102560 bytes, `root:wheel`, 0755) and carries **no entitlements at all** — it needs no
root, no signing identity, no entitlement. Built-in named profiles still work
(`sandbox-exec -n no-internet`, `-n no-network`, `-n no-write`, `-n pure-computation` all behave
as designed). `/System/Library/Sandbox/Profiles` contains **511 profiles**; `/usr/share/sandbox`
contains 59. Apple's own OS depends on this machinery pervasively.

**Is there any supported successor?** For confining an arbitrary third-party binary you launch,
without shipping it as a signed `.app` with entitlements: **no.** Section 4 establishes this per
candidate. Apple's own repo has an open, unanswered issue on exactly this
([apple/containerization#737](https://github.com/apple/containerization/issues/737)), which states:
*"`sandbox-exec(1)` is the only documented mechanism for applying Seatbelt (TrustedBSD MAC)
policies to arbitrary user-space processes on macOS without enrolling in the App Store or using
Xcode entitlements."*

**One removal signal to track.** The current upstream `sandbox_init(3)` man page says of the
named `kSBXProfile*` constants: *"These profiles must not be used when building against macOS SDK
>= 27.0. Processes opting into them will be killed on attempt to do so."* This targets the five
named constants, **not** custom SBPL strings — but it establishes that Apple prunes this surface
by SDK version with kill-on-use enforcement. Treat the whole surface as on a clock.

**Who depends on it in production** [SRC/LOCAL]:

| Project | Mechanism | Posture |
|---|---|---|
| **Claude Code** v2.1.224 (this host) | `/usr/bin/sandbox-exec` + embedded SBPL profile | `(deny default)` |
| **Chromium / Chrome** | `sandbox_compile_string` + `sandbox_apply` (V2 sandbox-at-launch) | `(deny default)` |
| **Nix** (darwin builds) | `sandbox_init_with_parameters` + `posix_spawn(POSIX_SPAWN_SETEXEC)` | `(deny default)` |
| **Bazel**, **Homebrew** | `/usr/bin/sandbox-exec -f` | `(allow default)` denylist |
| **`@anthropic-ai/sandbox-runtime`** | `sandbox-exec` + generated profiles + loopback proxy | `(deny default)` |
| **Apple** | 511 shipped profiles | mixed |

Chromium's `sandbox/mac/seatbelt.cc` re-declares the private symbols itself, with the comment:
*"This function is marked in the SDK as unavailable after macOS 10.8, but there is no
replacement, so ignore the deprecation warning."* That is the industry's collective position.

Note that `sandbox_init_with_parameters`, `sandbox_compile_string`, `sandbox_apply`, and
`sandbox_check` are all **exported from `libsandbox.dylib` on this host** [LOCAL] but appear in
no public header and have no man page. **SBPL itself has no published specification** — the
language is entirely reverse-engineered [RE]. Best available references: fG!'s *Apple Sandbox
Guide v1.0* (2011), Blazakis's Black Hat DC 2011 paper, Levin's *\*OS Internals Vol. III* ch. 8,
[SandBlaster](https://github.com/malus-security/sandblaster), and Nesting's
[May 2026 reference generated from macOS Tahoe 26.4.1's own shipped profiles](https://dnesting.com/2026/macos-sandbox-sbpl-reference/)
— whose author explicitly flags his operation/filter pairings as *observed*, not specified.

### 2.2 FILESYSTEM — **Y**

**Default-deny with an allow-list of roots: yes** [LOCAL]. `(deny default)` plus
`(allow file-read* (subpath ...))` works exactly as needed; reads outside the allow-list return
`Operation not permitted`, including `~/.ssh`.

**Read vs write: yes, and finer than read/write** [LOCAL] — `file-read-data`,
`file-read-metadata`, `file-write-data`, `file-write-metadata`, `file-write-unlink`,
`file-write-mode`, `file-write-owner`, `file-map-executable`, `file-clone`, `file-link`,
`file-mount`, `file-ioctl`, with `file-read*`/`file-write*` globs.

**Survives exec, grandchildren, and orphaning: yes** [LOCAL] — verified to depth 4
(`sh → sh → sh → python3`), through `nohup`, through backgrounding, and through the parent
`sandbox-exec` exiting. A detached grandchild still got `Operation not permitted` on `~/.ssh`.
This matches `sandbox(7)` [DOC].

**Path canonicalization is sound** [LOCAL]. All of these were denied under a profile jailing
reads: symlink out of jail, hardlink creation, relative `../../..` traversal, firmlink aliasing
via `/System/Volumes/Data/`, and case-insensitive APFS aliasing (`/users/YANN/.SSH/`).
Enforcement is at the vnode in `Sandbox.kext` (a TrustedBSD MAC module), not string matching at
`open(2)`.

**Rule precedence is last-match-wins** [LOCAL], so targeted `(deny ...)` lines placed *after*
broad allows are effective. A hybrid "allow-list plus explicit credential denies" profile is
viable — though playpen's standing law says `(deny default)` regardless.

**Four traps worth hard-coding into playpen's base profile:**

1. **`(allow file-read* (literal "/"))` is mandatory.** Without it *every* dynamically-linked
   binary aborts with SIGABRT (rc=134) and **zero diagnostic output**. Found by bisection:
   `(subpath "/")` worked; the union of `/usr /System /bin /dev /private/var /private/etc
   /Library /Applications /opt /nix /cores /Volumes /Users` all failed at rc=134; adding
   `(literal "/")` fixed it instantly. This is the worst debugging trap in the mechanism and
   speaks directly to issue #1's "failure UX" open question.
2. **Symlink components must be individually readable.** `/tmp → private/tmp` means reading
   `/tmp/x/y` needs `(literal "/tmp")` *in addition to* the resolved `(subpath "/private/tmp/x")`.
   Apple's own `bsd.sb` handles this with a blanket `(allow file-read-metadata)` and the comment
   `;; allow processes to traverse symlinks`.
3. **Inherited fds need `file-read-metadata` on their path** for the `fstat`, or you get
   `cat: stdout: Operation not permitted`.
4. **`(subpath ...)` grants leak transitively through symlinks** — see §2.4.

**Undocumented profile-size ceiling.** Nix's source comments that it splits allow-lists *"to
avoid exceeding a limit in the darwin sandbox interpreter… approximately at half the actual
limit, `1 << 16`"* [SRC]. Relevant if playpen generates large path allow-lists — which it will.

**Use parameters, not string splicing** [LOCAL]. `sandbox-exec -D KEY=value` /
`sandbox_init_with_parameters` + `(param "KEY")` works, and is how Chromium and Nix inject dynamic
paths. playpen must never concatenate untrusted paths into SBPL source.

### 2.3 EGRESS — deny-all **Y**, loopback-open **Y**, per-host **N**

**Wholesale denial: yes** [LOCAL]. `(deny network*)` kills both DNS (the mDNSResponder unix
socket) and TCP: `curl: (6) Could not resolve host` and `curl: (7) Failed to connect`.

**Per-host allow-listing: impossible — the compiler hard-errors** [LOCAL]:

```
$ sandbox-exec -p '... (allow network-outbound (remote ip "127.0.0.1:*"))' ...
sandbox-exec: host must be * or localhost in network address
$ ... (remote ip "example.com:443") ...
sandbox-exec: host must be * or localhost in network address
$ ... (remote domain "example.com") ...
sandbox-exec: unbound variable: domain
```

**The host portion of an `ip` filter accepts exactly two values: `*` and `localhost`.** Not even a
literal `127.0.0.1`. SBPL egress policy is therefore *(any host | loopback) × (port | \*)*, plus
`unix-socket` path filters. This is certain — it is a compiler error message, not inference.

**Consequence: domain allow-listing on macOS requires pinning egress to one loopback port and
running a proxy behind it.** This is precisely the shape `@anthropic-ai/sandbox-runtime` uses, and
it is what playpen's egress ticket must build on.

**Loopback open while external denied: yes — with a severe footgun** [LOCAL]. The commonly
copy-pasted idiom **silently allows everything**:

```
PROFILE: (allow network* (local ip "localhost:*"))
  loopback  http=200
  ext-ip    http=301      ← 1.1.1.1 REACHED
```

because the *local* endpoint of an outbound socket matches. The correct filter is `remote`:

```
PROFILE: (allow network* (remote ip "localhost:*"))
  loopback  http=200
  ext-ip    curl: (7) Failed to connect to 1.1.1.1 port 80
  ext-dns   curl: (7) Failed to connect to example.com port 443
```

DNS and TCP egress are independently controllable — allowing
`(allow network-outbound (literal "/private/var/run/mDNSResponder"))` lets resolution succeed
while the TCP connect is still denied [LOCAL].

**Binding a loopback listener inside the sandbox** — the `omp` bridge shape — needs three rules,
and `remote` alone is **not sufficient** [LOCAL]:

```
PROFILE: []                                          → BIND FAILED: [Errno 1] Operation not permitted
PROFILE: (allow network* (remote ip "localhost:*"))  → BIND FAILED: [Errno 1] Operation not permitted
PROFILE: (allow network-bind     (local  ip "localhost:*"))
         (allow network-inbound  (local  ip "localhost:*"))
         (allow network-outbound (remote ip "localhost:*"))
  → BOUND on 127.0.0.1:61354; SELF-CONNECT OK: b'BRIDGE'
  → and external egress stays shut: ext http=000, loop http=200
```

**Unix sockets are a separate channel that is easy to miss.**
`(allow network-outbound (remote unix-socket (path-regex #"^/")))` — which is in Claude Code's
*own* shipped profile [LOCAL] — permits **any** unix socket, including `docker.sock`, SSH agent
sockets, and `IdentityAgent` sockets. Nix's own profile comment concedes: *"if we allow them more
broadly, you could in theory escape the sandbox."*

### 2.4 CREDENTIAL ISOLATION — **Y**, with two documented caveats

**`~/.ssh` and `~/.aws`: reliably blockable** [LOCAL] — both `cat` and `ls` return
`Operation not permitted` under a `(deny default)` allow-list profile.

**Keychain: yes, and the surgical deny is cheap.** The Keychain is reached through
`securityd`/`SecurityServer` over Mach, not through files, so a file allow-list does nothing. With
`(allow mach-lookup)` unrestricted, `security list-keychains` happily enumerates the login and
System keychains [LOCAL]. A targeted deny is sufficient:

```scheme
(deny mach-lookup (global-name "com.apple.SecurityServer")
                  (global-name "com.apple.securityd")
                  (global-name "com.apple.SecurityServer.xpc"))
```

→ `security: SecKeychainCopySearchList: One or more parameters passed to a function were not
valid.` Collateral damage was low in testing (`ls`, `python3` unaffected) [LOCAL], but keep
`com.apple.trustd.agent` **allowed** or TLS trust evaluation breaks. Expect
`git-credential-osxkeychain`, `gh auth`, and npm/docker credential helpers to fail loudly — which
is the desired behaviour, and exactly the friction the credential-broker ticket exists to absorb.

**Note: Claude Code's own shipped profile ALLOWS `com.apple.SecurityServer`** [LOCAL]. If playpen
wants Keychain isolation it must add this deny itself; it cannot inherit it.

**Caveat 1 — the transitive symlink leak, found live.** A profile allow-listing `/nix/store`
(needed on a home-manager machine) **transitively exposed `~/.ssh/config`**, because home-manager
symlinks it into the store [LOCAL]:

```
$ ls -la /Users/yann/.ssh/config
lrwxr-xr-x ... -> /nix/store/3737apmpm...-home-manager-files/.ssh/config
$ sandbox-exec -f std.sb /bin/cat /Users/yann/.ssh/config
Host ash-devbox
  ForwardAgent yes
  IdentityAgent /Users/yann/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
```

Real key files (not symlinks) stayed denied. But **any blanket `/nix/store` grant leaks every
dotfile a dotfile-manager symlinks into it** — including SSH config with agent-forwarding settings
and IdentityAgent socket paths. playpen must narrow to specific store paths, or add explicit
post-hoc denies. This bears directly on issue #1's "toolchain reachability" open question: the
obvious fix (allow-list `/nix/store`) is the one that leaks.

**Caveat 2 — the inherited-fd hole** [LOCAL, and Apple-documented in `sandbox(7)`]:

```
$ bash -c 'exec 9</Users/yann/.ssh/id_ed25519; \
    sandbox-exec -f netbase.sb /bin/sh -c "head -c 40 /dev/fd/9"'
-----BEGIN OPENSSH PRIVATE KEY-----
```

**playpen must close all non-essential fds before exec.** This is the one weakness Apple
documents rather than a bug.

**TCC is orthogonal and adds nothing.** Under a profile allowing `(subpath "/Users")`,
TCC-protected `~/Desktop` was fully readable, because the parent terminal already holds the grant
[LOCAL]. SBPL can *subtract* from TCC but never adds to it.

### 2.5 ENFORCEMENT INTEGRITY — irrevocable, and un-nestable

**A confined process cannot loosen its confinement** [LOCAL], verified with a C probe calling
`sandbox_init_with_parameters` directly:

```
A: outside sandbox, apply deny profile   → rc=0; ~/.ssh open now denied  (self-sandboxing works)
B: inside sandbox, apply (allow default) → rc=-1 EPERM; ~/.ssh still denied   ← CANNOT LOOSEN
C: inside (allow default), apply deny    → rc=-1 EPERM; ~/.ssh still readable ← CANNOT TIGHTEN
D: nested sandbox-exec inside sandbox-exec → sandbox_apply: Operation not permitted (rc=71)
```

This matches `sandbox.h` verbatim: *"If the process is already in a sandbox, the new profile is
ignored and `sandbox_init()` returns an error."* It is **not** monotonic intersection — the second
call simply fails.

`sandbox_suspend` — the obvious self-unconfinement vector, and an exported symbol — **fails for
an unprivileged process** [LOCAL] (`sandbox_suspend(self) -> -1`; the read stayed denied).

`sandbox_check(pid, op, type, path)` is a usable **introspection API for playpen to self-verify at
startup** (returns 1 = denied, 0 = allowed; `sandbox_check(getpid(), NULL, 0)` answers "am I
sandboxed"). Homebrew uses exactly this to detect nesting [SRC].

**Escape attempts tried locally, all failed** [LOCAL] — under `(deny default)` with unrestricted
`mach-lookup`: `/usr/bin/open` (LaunchServices spawn) failed with error -54; `launchctl submit`
failed; `osascript -e 'do shell script'` was denied. Encouraging but **not a strong claim** —
`mach-lookup` unrestricted is a large surface that was only sampled.

**Known escape classes — cite these rather than hand-waving:**

- **`mach-lookup` to a permissive daemon is an escape.** The sandbox does not confine what the
  daemon does on your behalf. Every `(allow mach-lookup (global-name ...))` line delegates trust
  to that daemon's input validation. [RE, universal consensus]
- **Mickey Jin, ["A New Era of macOS Sandbox Escapes"](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)**
  — 10+ CVEs against XPC services visible in the app's PID domain (CVE-2023-27944, -32414,
  -32404, -41077, -42961, -42977, CVE-2024-27864). Core primitive: *"Drop a file/folder without
  being quarantined == Full Sandbox Escape."*
- **Project Zero #1247 / `xpc_data`** — crafted `mach_make_memory_entry_64` flags leave the
  "copied" region writable by the sender: a structural TOCTOU on every XPC-received buffer in
  every privileged daemon.
- **Pillar Security, ["Escaping Antigravity's Allow-Default Seatbelt" (2026)](https://www.pillar.security/blog/escaping-antigravitys-allow-default-seatbelt)**
  — directly relevant, this is an *AI coding agent* sandbox escape. Chain: `(allow default)`
  posture → mount a **devfs** volume in `/tmp` (mounts weren't denied) → devfs has no xattrs, so
  files carry no `com.apple.provenance` → build a fake `.app` there with a symlinked `bash` and an
  `Info.plist` `LSEnvironment` `BASH_ENV` → `open` the bundle → **launchd starts it outside the
  sandbox**. Verdict line: *"the bash process answering for them was never inside the sandbox."*
  Lesson: `(deny default)`, and explicitly deny `file-mount`, `lsopen`, `appleevent-send`.
  **Claude Code's own profile currently allows `lsopen` and `appleevent-send`** [LOCAL].
- **`(with no-sandbox)` on `process-exec`** — an undocumented SBPL modifier letting a named binary
  escape entirely on exec. Present in *both* Bazel's and Homebrew's generated profiles [SRC]. A
  literal escape hatch by design; playpen must never emit it.
- **`(regex #"...")` has no implicit anchoring.** Forgetting `^` is a classic own-goal. [RE]
- **Write access to any directory on a later exec/read path** (shell rc files, `PATH` dirs,
  `~/Library/LaunchAgents`) converts a filesystem grant into code execution.

**Honest strength claim.**

> Seatbelt is a kernel-enforced, irrevocable, inherited MAC policy that reliably blocks
> filesystem reads/writes and IP egress for cooperative *and* uncooperative processes, including
> deep subprocess trees. Its enforcement of file paths and IP/port is sound — symlink, hardlink,
> traversal, firmlink, and case-alias bypasses all failed under test. Its weak flank is
> **everything reached through another process**: `mach-lookup`, XPC, LaunchServices,
> `appleevent-send`, unix sockets, and inherited fds. A profile is only as strong as the daemons
> it can still talk to. Treat it as a **strong containment boundary against a misbehaving or
> prompt-injected agent, and a weak boundary against a determined local attacker with a fresh XPC
> bug.** Apple disclaims the latter in `sandbox(7)`: *"It is not a replacement for other operating
> system access controls."*

That maps cleanly onto issue #1's two threat tiers: SBPL is adequate for tier one (blast-radius
containment) and materially short of tier two (actively hostile driver) without an outer VM.

### 2.6 The two workload shapes on macOS

**`claude` — confinement excellent, but it brings its own sandbox.** Inheritance was verified to
depth 4, through `nohup`, through orphaning [LOCAL]. Per-binary exec allow-listing works
(`(allow process-exec (literal "/bin/echo"))` → `/bin/cat` fails with rc=71) [LOCAL].

**The blocker: Claude Code has its own Seatbelt sandbox.** Its binary contains
`/usr/bin/sandbox-exec` and a complete SBPL profile [LOCAL]. Since nesting fails hard (§2.5),
**playpen must run `claude` with its own sandboxing disabled and take over the policy** — or the
guest's sandbox silently fails, or hangs (Homebrew's source documents nested `sandbox-exec`
*hanging*, and ships a `nested_sandbox?` guard [SRC]; Anthropic ships an `enableWeakerNestedSandbox`
flag for the same reason). playpen's profile should also be *stricter* than the one it replaces:
Claude Code's own profile allows `SecurityServer`, `lsopen`, `appleevent-send`, and unix sockets
on `path-regex #"^/"`.

**`omp` — confines fine; the browser is the blocker.** The fat process itself confines exactly as
any process does, verified with a simulated in-process workload and with the real Bun runtime
[LOCAL]:

```
$ sandbox-exec -f bunprof.sb bun run bunt.js
bun loopback: BUNOK
external blocked: Error: Was there a typo in the url or port?
ssh blocked: Error: EPERM: operation not permitted, open '/Users/yann/.ss…
subproc exit: 1 cat: /Users/yann/.ssh/id_ed25519: Operation not permitted
```

*Does in-process execution defeat per-process policy granularity?* **Only granularity you never
had.** The one dimension genuinely lost is `(allow process-exec (literal ...))`: with 58 utilities
compiled in there are no execs to gate, so you cannot say "`omp` may run `rg` but not `curl`" —
the policy is one union over everything the fat binary can do. Everything else (FS allow-list,
read/write split, egress, credential denies) is unaffected, because SBPL enforces per *process* at
the vnode/syscall level. And since SBPL cannot be re-applied at all, per-subprocess differentiation
was never available even for `claude`. **This is close to a wash** — and it aligns with issue #1's
standing law that the unit of policy is the process tree.

*Does the loopback bridge survive?* **Yes**, with the exact three-rule recipe in §2.3.

*Does browser automation work?* **This is the hard blocker** [LOCAL]. Chrome under an outer SBPL
sandbox with its own sandbox enabled **dies**:

```
sandbox initialization failed: Operation not permitted
Failed to initialize sandbox.
[ERROR] GPU process exited unexpectedly: exit_code=6
[FATAL] GPU process isn't usable. Goodbye.
```

The same outer profile with `--no-sandbox` works (`<html><head></head><body></body></html>`).
So playpen must choose:

- **(a) browser inside with `--no-sandbox`** — the host is protected by playpen's profile, but
  renderer-vs-browser isolation is gone, so a browser RCE gets full playpen-level access. Simpler;
  one trust boundary.
- **(b) browser outside playpen, brokered over the loopback bridge (CDP)** — preserves Chrome's own
  sandbox, but the browser is unconfined w.r.t. the host and playpen must allow-list the CDP port.

**(b) is the better security story** if playpen can control the CDP endpoint: Chrome's own sandbox
is a serious boundary and playpen's outer profile largely duplicates it. Note (b) tensions with
issue #1's standing law that playpen is one layer and never credits a layer beneath it — the
browser would sit *outside* the boundary, which is an operator-visible decision the design must
make explicitly rather than by accident.

Practical: Chrome also needs `(allow network-bind)` for its `SingletonSocket` unix socket, plus
`iokit*`, `ipc*`, readable `/Library` and `/Applications`, and a writable `/private/var/folders`.

### 2.7 macOS profile checklist (drop-in for the implementation ticket)

1. `(deny default)` — never `(allow default)` (Antigravity, §2.5).
2. **Always** include `(allow file-read* (literal "/"))` or every dynamic binary SIGABRTs silently.
3. `(allow file-read-metadata)` broadly (as Apple's `bsd.sb` does) — needed for symlink traversal
   and for `fstat` on inherited fds.
4. Add `(literal "/tmp") (literal "/var") (literal "/etc") (literal "/private")` alongside
   canonical subpaths — symlink components are checked individually.
5. **Egress: `(remote ip "localhost:*")`, never `(local ip "localhost:*")`.**
6. Loopback bridge: `network-bind` + `network-inbound` on `(local ip "localhost:*")`,
   `network-outbound` on `(remote ip "localhost:*")`.
7. Domain allow-listing: no SBPL option. Pin egress to one loopback port and proxy.
8. `(deny mach-lookup (global-name "com.apple.SecurityServer") (global-name "com.apple.securityd"))`
   for Keychain isolation; keep `com.apple.trustd.agent` allowed for TLS.
9. Explicitly deny `file-mount`, `lsopen`, `appleevent-send`; never emit `(with no-sandbox)`.
10. **Close all inherited fds before exec.**
11. Audit `(subpath ...)` grants for transitive symlink leakage — `/nix/store` leaked
    `~/.ssh/config` on this host.
12. Use `-D` / `sandbox_init_with_parameters` parameters; never string-splice paths into SBPL.
13. Assume **no nesting**: disable the guest's own sandbox. Detect with
    `sandbox_check(getpid(), NULL, 0) == 1`.
14. Watch the undocumented profile-size ceiling (~`1<<16` per allow group, per Nix's source).
15. Watch the SDK-27 kill-on-use gate on named profiles.

---

## 3. Linux mechanisms

Target: a NixOS VM. **Kernel version is decisive for Landlock** — see §3.1.1.

### 3.1 Landlock

Sources: [Documentation/userspace-api/landlock.rst](https://docs.kernel.org/userspace-api/landlock.html),
[landlock(7)](https://man7.org/linux/man-pages/man7/landlock.7.html),
[landlock_add_rule(2)](https://man7.org/linux/man-pages/man2/landlock_add_rule.2.html).

#### 3.1.1 ABI → kernel version (check this first)

| ABI | Kernel | Added |
|---|---|---|
| 1 | 5.13 | FS rights: `EXECUTE`, `READ_FILE`, `WRITE_FILE`, `READ_DIR`, `REMOVE_*`, `MAKE_*` |
| 2 | 5.19 | `FS_REFER` (link/rename across directories) |
| 3 | 6.2 | `FS_TRUNCATE` |
| **4** | **6.7** | **`NET_BIND_TCP`, `NET_CONNECT_TCP`** |
| 5 | 6.10 | `FS_IOCTL_DEV` |
| 6 | 6.12 | Scoping: `SCOPE_ABSTRACT_UNIX_SOCKET`, `SCOPE_SIGNAL` |
| 7 | 6.15 | Audit-log control flags |
| 8 | 7.0 | `RESTRICT_SELF_TSYNC` (apply to all threads) |
| 9 | — | `FS_RESOLVE_UNIX` (pathname AF_UNIX sockets) |
| 10 | — | UDP: `NET_BIND_UDP`, `NET_CONNECT_SEND_UDP` |

**On kernel 6.6 there are no Landlock network rules at all** — ABI 4 landed in 6.7. Probe at
runtime with `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, which the docs
explicitly endorse as a *"best-effort security approach"*. **playpen's "refusal, never silent
downgrade" law means playpen must probe and refuse, not degrade.** Also verify
`CONFIG_SECURITY_LANDLOCK=y` **and** `landlock` in the boot LSM list — compiled-in-but-boot-disabled
yields `EOPNOTSUPP`.

#### 3.1.2 Filesystem — **Y**, the strongest FS primitive available

Default-deny by declaring `handled_access_fs` then re-granting via `LANDLOCK_RULE_PATH_BENEATH`
[DOC]. Read/write/exec/truncate/dir/create/remove are all separate rights — a richer model than a
read-only bind mount. **Unprivileged**: needs only `prctl(PR_SET_NO_NEW_PRIVS, 1)`; no root, no
setuid, no namespace.

**Survives exec and grandchildren unconditionally** [DOC]: *"Every new thread resulting from a
`clone(2)` inherits Landlock domain restrictions from its parent"* and *"once a thread is
landlocked, there is no way to remove its security policy; only adding more restrictions is
allowed."*

**Documented gaps** [DOC]: cannot restrict `chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`,
`utime`, `fcntl`, `access` — so `~/.ssh/id_ed25519`'s *existence and size* leak, though its
contents do not. Cannot restrict non-filesystem objects reached via `/proc/<pid>/fd/*`.
**Already-open fds are unaffected** (open-time check) — same hazard as macOS: *close credential fds
before restricting*. `chroot(2)` is not denied, though `mount`/`pivot_root` are. Hard limit of 16
stacked layers (`E2BIG` on the 17th) — budget this if playpen ever nests.

#### 3.1.3 Egress — **N**, and this is decisive

The rule struct, verbatim from `landlock_add_rule(2)`:

```c
struct landlock_net_port_attr {
    __u64 allowed_access;
    __u64 port;            /* "Network port in host endianness", max 65535 */
};
```

**There is no address field.** Consequences:

- **Per-host allow-listing: impossible.** Landlock cannot express "connect to github.com but not
  evil.com."
- **Loopback open while external denied: NO** [INFER, direct corollary of the struct]. Allowing
  `CONNECT_TCP` on `omp`'s bridge port also permits connecting to *any external host* on that port.
- **UDP is entirely ungated below ABI 10.** On any 6.7–6.15 kernel, DNS (UDP/53) and QUIC/HTTP3
  (UDP/443) sail straight past a Landlock net ruleset [DOC, by absence].

**Verdict: Landlock is an excellent FS mechanism and a near-useless egress mechanism.** Do not
build playpen's egress on it.

#### 3.1.4 Credential isolation — **P**

Reliably blocks `open()`-for-read of `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`. But
**pathname AF_UNIX sockets are only gated from ABI 9** — so on a 6.6–6.15 kernel **Landlock alone
does not stop the agent from talking to `$SSH_AUTH_SOCK` or gpg-agent** [DOC]. ABI 6's
`SCOPE_ABSTRACT_UNIX_SOCKET` covers a different namespace. You need a mount namespace (don't bind
it in). Landlock also cannot *add* paths, so the brokered-socket pattern must come from bwrap.

#### 3.1.5 Enforcement integrity — the strongest claim in this document

Irrevocable; stackable only tighter (*"a sandboxed thread can only access a file path if all its
enforced policy layers grant the access"*); `NO_NEW_PRIVS` is itself irrevocable; no namespace to
re-unshare and no capability to reacquire. **There is no known un-landlock primitive.**

> **Honest strength claim: Landlock filesystem confinement is genuinely unescapable by the confined
> process on a non-buggy kernel.** Residual risk is kernel bugs in Landlock itself and the
> documented gaps in §3.1.2 — not policy bypass.

#### 3.1.6 Workloads

- **`claude`**: ideal — fork/exec inheritance covers the whole tree.
- **`omp`**: ideal for FS, and in-process execution is *an advantage* — one domain established once
  in `main()`. Two caveats: the domain must be the union of all 58 utilities' needs (no per-tool
  differentiation), and because Landlock is **per-thread until ABI 8's TSYNC**, a multi-threaded
  Rust binary must **restrict in `main()` before the thread pool starts** [DOC]. That is a concrete
  integration requirement on `omp`.

### 3.2 bubblewrap

Sources: [README](https://github.com/containers/bubblewrap/blob/main/README.md),
[bwrap.xml](https://github.com/containers/bubblewrap/blob/main/bwrap.xml),
[bubblewrap.c](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c),
[network.c](https://github.com/containers/bubblewrap/blob/main/network.c),
[mount_namespaces(7)](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html).

**bwrap is a mechanism, not a policy** — and its README says so, which is a precise statement of
playpen's job [DOC]:

> bubblewrap is a tool for constructing sandbox environments … **not a complete, ready-made sandbox
> with a specific security policy**. The level of protection between the sandboxed processes and
> the host system is **entirely determined by the arguments passed to bubblewrap**. … Whatever
> program constructs the command-line arguments for bubblewrap … is responsible for defining its
> own security model.

**Filesystem — Y, and default-deny by *construction*.** bwrap starts from an empty root; unbound
paths **do not exist**, so `stat("~/.ssh")` returns `ENOENT` rather than leaking metadata (strictly
stronger than Landlock on that axis). `--ro-bind` vs `--bind` gives read/write; `--overlay` gives
copy-on-write. Mount-namespace membership is inherited by every descendant and unchanged by
`execve`.

**Can the payload undo `--ro-bind`? No** [DOC for the rules, INFER for the composition]. bwrap
drops all capabilities, so `mount(2)` is unavailable. If the payload unshares a nested
userns+mountns to regain `CAP_SYS_ADMIN`, `mount_namespaces(7)` applies: `MS_RDONLY` and friends
*"become locked when propagated from a more privileged to a less privileged mount namespace, and
may not be changed"*, and such mounts are *"locked together and may not be separated"* — so they
cannot be unmounted either. (This was once genuinely broken — CVE-2014-5206/5207 — and was fixed by
adding `MNT_LOCK_READONLY`.) **Flagged as the top item to verify empirically on a Linux box.**

**Egress — Y (all-or-nothing).** `--unshare-net` gives total denial. Critically, bwrap's
`loopback_setup()` **brings `lo` up unconditionally** and dies on failure [SRC] — the difference
from bare `unshare -n` (§3.4.1). No per-host support whatsoever.

**Credential isolation — best in class**, because it is *omission* rather than denial: don't bind
`~/.ssh`, `~/.aws`, `~/.gnupg`, `$SSH_AUTH_SOCK`, `$XDG_RUNTIME_DIR`, `/run/user/$UID`. The
brokered path is native: `--bind /run/playpen/broker.sock /run/user/1000/…` puts playpen's proxy
socket exactly where the agent expects the real one. The README's warning applies directly:
*"Everything mounted into the sandbox can potentially be used to escalate privileges"* — its example
is a bound D-Bus socket letting you ask systemd to run commands **outside** the sandbox.

**Integrity — three named hazards, all documented:**

1. **TIOCSTI / CVE-2017-5226** [DOC, verbatim]: *"If you don't use `--new-session`, it is
   recommended to use seccomp to disallow the `TIOCSTI` ioctl, otherwise the application can feed
   keyboard input to the terminal which can e.g. lead to **out-of-sandbox command execution**."*
   Note `--new-session` breaks interactive TTY use — a real conflict with `omp`'s PTY features, so
   plan on the seccomp filter instead.
2. **`--disable-userns`** writes `1` to `user.max_user_namespaces` in the outer userns, then
   descends [SRC]. **The single most valuable hardening flag — and the one that kills Chromium**
   (§3.6).
3. **`--die-with-parent`** SIGKILLs the whole sandbox tree when bwrap's parent dies. Essential, or
   a backgrounded grandchild outlives playpen.

bwrap also **unconditionally sets `PR_SET_NO_NEW_PRIVS`** [SRC]: Landlock's precondition is already
satisfied inside bwrap, and any setuid helper is dead (including Chromium's SUID-sandbox fallback).

**Prefer explicit unshare flags over `--unshare-all`**: the `-try` suffixes inside `--unshare-all`
make it **degrade silently**, which violates playpen's refusal law.

**NixOS specifics** [SRC]: `pkgs.bubblewrap` is a plain meson build with **no setuid wrapper**, and
`security.allowUserNamespaces` defaults **true** (with an assertion that `nix.settings.sandbox`
conflicts with disabling it — Nix's own build sandbox needs userns, so NixOS is structurally
committed). `security.unprivilegedUsernsClone` is **inert on NixOS** — it sets a Debian/Ubuntu
downstream sysctl that does not exist on a vanilla kernel; its docstring is misleading. `profiles/
hardened.nix` has been removed. **Do not gate anything on that option.**

### 3.3 seccomp-bpf

Sources: [seccomp_filter.rst](https://docs.kernel.org/userspace-api/seccomp_filter.html),
[seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html),
[seccomp_unotify(2)](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html).

**The decisive constraint, verbatim** [DOC]:

> **BPF programs may not dereference pointers** which constrains all filters to solely evaluating
> the system call arguments directly.

**Therefore seccomp cannot do path filtering or address filtering — ever.** `open("/home/u/.ssh/
id_rsa")` and `open("/tmp/x")` are indistinguishable to a filter, as are `connect()` to any two
addresses. This is architectural, not a gap. Anyone proposing seccomp for filesystem or per-host
egress policy is wrong.

What it *can* express, since these are scalars: "deny syscall N", "deny `clone` when
`args[0] & CLONE_NEWUSER`", "deny `ioctl` when `args[1] == TIOCSTI`", "deny `socket` when
`args[0] == AF_PACKET`".

**Integrity is strong**: unprivileged with `NO_NEW_PRIVS`, inherited across fork, persists across
`execve`, irrevocable, filters accumulate (children can only add).

**Documented traps**: multiplexed syscalls (`ioctl`, `socketcall`); vDSO bypass of
`clock_gettime`/`gettimeofday`; libc indirection (`open` → `openat`, `fork` → `clone`/`clone3`);
**argument truncation** "after the seccomp check" (the i386-on-x86-64 bypass class); multi-arch
`__X32_SYSCALL_BIT`.

**seccomp user-notify is not a security mechanism** — the man page says so [DOC]:

> **Note well**: this mechanism **must not be used to make security policy decisions** about the
> system call, which would be inherently race-prone.

Writes to target memory are *"never considered safe."* The sound pattern is
**`SECCOMP_IOCTL_NOTIF_ADDFD`**: the supervisor opens the resource *itself* and injects the fd,
which *"leverages existing kernel security mechanisms … and avoids the need to inspect untrusted
memory."* **This is directly relevant to the credential-broker ticket: ADDFD is a legitimate way to
implement brokered credentials; user-notify path/host validation is not.**

**Role in the stack: kernel attack-surface reduction only.** Block `TIOCSTI`, `AF_PACKET`/
`AF_NETLINK`, `bpf`, `io_uring`, `userfaultfd`, `keyctl`, the `fsopen`/`fsconfig`/`move_mount`
family. Blocking `unshare`/`clone(CLONE_NEWUSER)` buys back most of the userns-CVE delta **and
breaks Chromium** (§3.6).

**Workloads**: identical for both. `omp`'s single-process shape means one filter must be the union
of 58 utilities' syscall needs — wider than per-tool filters would be, but neither agent exposes a
per-child hook, so the loss is theoretical.

### 3.4 Network namespaces

Sources: [network_namespaces(7)](https://man7.org/linux/man-pages/man7/network_namespaces.7.html),
[user_namespaces(7)](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
[setns(2)](https://man7.org/linux/man-pages/man2/setns.2.html),
[unshare(2)](https://man7.org/linux/man-pages/man2/unshare.2.html),
[veth(4)](https://man7.org/linux/man-pages/man4/veth.4.html),
[ip-netns(8)](https://man7.org/linux/man-pages/man8/ip-netns.8.html).

#### 3.4.1 The `lo`-is-DOWN gotcha — load-bearing for `omp`

A fresh netns contains exactly one device, `lo`, ifindex 1, **administratively DOWN**:
`loopback_net_init()` calls `register_netdev()` and nothing sets `IFF_UP` [SRC]. **Neither
`unshare -n` nor `ip netns add` brings it up** — util-linux's `unshare.c` has no netlink code at
all, and `ip-netns(8)`'s own examples list `ip link set lo up` as a *separate step* [DOC].

Three independent projects work around this explicitly, which is as strong as documentation gets:
**pasta** (*"it will also ensure that the loopback interface, lo, is brought up. This is needed to
bind ports using the loopback address in the namespace"*), **slirp4netns** (`-c`, since v0.4.0),
and **bubblewrap** (unconditionally, dies on failure).

> **Direct answer for `omp`: a fresh netns keeps the loopback bridge working, but only after `lo` is
> up.** Under `bwrap --unshare-net` this is handled for you. Under bare `unshare -n` it is not.
> Once up, the kernel auto-assigns `127.0.0.1/8 scope host`, so no address config is needed [SRC].

And the loopback is **fully isolated from the host's** — `network_namespaces(7)` lists "port numbers
(sockets)" as isolated [DOC]. That is a security *gain*: `omp`'s kernels cannot be reached from the
host, and cannot reach host services on 127.0.0.1.

**Design note:** filesystem-path AF_UNIX sockets live in the *mount* namespace, not the netns — so
if `omp`'s bridge could use a pathname unix socket instead of loopback TCP, the whole `lo` question
evaporates. **Worth checking against `omp`'s source; its README says only "loopback bridge."**

#### 3.4.2 Privilege, inheritance, escape

`CLONE_NEWNET` alone needs `CAP_SYS_ADMIN`, but combined with `CLONE_NEWUSER` in one call the
userns is created first and *"it is possible for an unprivileged caller to specify this combination
of flags"* [DOC]. So `unshare --user --net` is fully rootless.

**Survives exec and grandchildren unconditionally** [DOC] — *"by default a process inherits its
network namespace from its parent"*, and `execve` is not among the three APIs that change namespace
membership. **This is exactly what makes netns categorically stronger than `HTTPS_PROXY`/
`LD_PRELOAD`/`no_proxy`, all of which a grandchild sheds by simply not honouring them.** It is the
core architectural argument for the whole egress design.

**Escape: no**, for two independent documented reasons: (1) `unshare` only ever moves you into a
*new, empty* namespace — there is no "unshare back"; (2) `setns()` back to the host netns requires
`CAP_SYS_ADMIN` *"both in its own user namespace and in the user namespace that owns the target
namespace"*, and the host netns is owned by the initial userns, in which the payload has no
capabilities. Nesting more userns does not help — setns can only join a *descendant*.

**The one real subversion**: if the payload runs as **uid 0 in the userns owning its netns** (the
common `--map-root-user` shape) it holds `CAP_NET_ADMIN` there forever and **can `nft flush
ruleset` its own firewall** [INFER, high confidence]. → **Put egress policy on the host side of the
boundary, never inside the netns.** bwrap's default (map the real uid, drop all caps) mostly
sidesteps this.

**Threading trap** [DOC]: `CLONE_NEWUSER` *"requires that the calling process is not threaded"*, and
`setns` returns `EINVAL` for a multithreaded caller joining a userns. → **playpen must unshare in a
fresh single-threaded process before `exec`ing the agent**, never from inside an already-threaded
runtime. Directly relevant to `omp` (threaded Rust) — **playpen must be the parent, not a library
called from within.**

#### 3.4.3 Per-host allow-listing needs a proxy

- **nftables/iptables inside the netns**: no hostname support. `iptables(8)` says it outright:
  *"Hostnames will be resolved once only, before the rule is submitted to the kernel. Please note
  that specifying any name to be resolved with a remote query such as DNS is a really bad idea."*
  nft's set element types are `ipv4_addr`/`ipv6_addr`/`ether_addr`/`inet_service`/`inet_proto`/
  `mark` — **no FQDN type** [DOC]. Also flushable by an in-netns-root payload.
- **L7 forward proxy** (squid `acl dstdomain`, tinyproxy, mitmproxy `allow_hosts`): the only place
  name-based policy can live. `HTTPS_PROXY` alone is **cooperative and bypassable** — Node/undici
  historically ignores proxy env vars without an explicit `ProxyAgent`, which matters directly for
  `omp`'s **Bun** kernel.
- **The netns is what converts cooperative into enforced.** Run the proxy in the host netns and give
  the sandbox netns no route to anything else. Env-var-ignoring code then doesn't bypass policy — it
  gets `ECONNREFUSED`.
- **veth needs root** on the host (`rtnl_get_net_ns_capable()` → `-EACCES`) [SRC], so it is off the
  table for a rootless playpen. `pasta` and `slirp4netns` are rootless userspace TCP/IP stacks that
  solve *connectivity* — **neither can do per-host allow-listing** (slirp4netns's own man page says
  *"you may want to set up iptables"*). If used, `slirp4netns --disable-host-loopback` /
  `pasta --map-host-loopback none` is mandatory: the defaults expose the host's `127.0.0.1`.
- **DNS**: a bare netns has no working resolver. Every tool ships an explicit DNS story
  (`/etc/netns/NAME/resolv.conf`, slirp's 10.0.2.3, pasta's `--dns-forward`, Docker's 127.0.0.11).
- **IP allow-listing is a trap for a coding agent**: npm, PyPI, GitHub and crates.io are all
  CDN-fronted, so a pinned edge IP goes stale and widening to CDN prefixes allow-lists most of the
  internet. **Name-based policy must live at L7.** The only sound alternative is a DNS-driven
  firewall (resolver you control installing exactly the IPs it returned into an nft `flags dynamic`
  set) — **no upstream tool does this out of the box** [INFER].

### 3.5 cgroups v2 — a resource mechanism, not a boundary

The v2 controllers are `cpu`, `memory`, `io`, `pids`, `cpuset`, `hugetlb`, `misc`, `rdma` [DOC].
**There is no filesystem-access controller and no network-address controller.** For playpen,
cgroups v2 buys `memory.max`, `pids.max`, `cpu.max`, and — genuinely useful — **`cgroup.kill`** for
race-free termination of the whole tree, complementing `--die-with-parent`. **It does not belong in
the security column.** (Historical note: CVE-2022-0492 was a cgroup-v1 `release_agent` bug giving
host root to anyone with `CAP_SYS_ADMIN` over a cgroupfs mount — cgroupfs must not be writable in
the sandbox.)

**The exception: cgroup-attached eBPF.** `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` at
`BPF_CGROUP_INET4_CONNECT` etc. sees `ctx->user_ip4`/`user_port`, can **return 0 to deny**, and can
**rewrite the destination to transparently redirect to a local proxy** [DOC]. This is genuinely the
most expressive egress mechanism on Linux — it sees the address, unlike Landlock (port only) and
seccomp (no pointers). **But it requires root/`CAP_BPF`+`CAP_NET_ADMIN`**, and
`kernel.unprivileged_bpf_disabled=1` is the distro default. Also note cgroup membership is *not*
like namespace membership — a payload with write access to `cgroup.procs` can move *itself* out of
the filtered cgroup [INFER]. **If playpen may assume a privileged host setup step this is a very
clean design; if it must be rootless, netns+proxy is the answer.**

### 3.6 Chromium nested inside bwrap — the `omp` friction point on Linux

**Chromium consumes ≥2 userns nesting levels below wherever it starts** [SRC]. Its own probe,
`CanCreateProcessInNewUserNS()` in `sandbox/linux/services/credentials.cc`, forks with
`CLONE_NEWUSER` and then does a **second** `unshare(CLONE_NEWUSER)` (*"Ensure we have unprivileged
use of CLONE_NEWUSER"*); at runtime `NamespaceSandbox::LaunchProcess` uses
`CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET` and `EngageNamespaceSandboxInternal` calls
`MoveToNewUserNS()` for another. Failure path is `LOG(FATAL) << "No usable sandbox!"` with
`--no-sandbox` named as the workaround.

**Under plain bwrap this works** [INFER, tightly grounded]: bwrap puts you at depth *n+1*, Chromium
needs *n+3*, the limit is 32 levels, and `max_user_namespaces` is **MAXINT in all descendant
userns** [DOC].

**Under `--disable-userns`, or a seccomp filter blocking `unshare`/`clone(CLONE_NEWUSER)`, it does
not** — and there is no SUID fallback, because bwrap sets `NO_NEW_PRIVS`. **Flatpak proves this is
a deliberate conflict**; its source comment reads: *"Disable recursive userns for all flatpak
processes, as we need this to guarantee that the sandbox can't restructure the filesystem"* [SRC].
That is why [zypak](https://github.com/refi64/zypak) exists. Docker hits the same wall via its
default seccomp profile masking `clone` against `0x7E020000`; Playwright's own docs confirm the fix
is *"a default Docker seccomp profile with extra user namespace cloning permissions."*

**Rules for playpen if `omp` browser automation must work on Linux:**

1. Do **not** pass `--disable-userns` / `--assert-userns-disabled`.
2. Do **not** seccomp-block `unshare` / `clone(CLONE_NEWUSER)` / `clone3`.
3. Do **not** run the browser as uid 0 — `ZygoteHostImpl::Init` hard-exits for root without
   `--no-sandbox`. **`bwrap --uid 0` will trip this.**
4. Mount a real `/proc` and a properly-sized `/dev/shm`. (`--disable-dev-shm-usage` /
   `--shm-size` addresses a *separate* problem — shm exhaustion crashing renderers — that produces
   lookalike symptoms. Do not conflate the two.)

**The honest trade.** Leaving nested userns open re-exposes the userns CVE class to the agent —
Ubuntu's framing is that *"44% of the exploits"* in Google's dataset *"required unprivileged user
namespaces as part of their exploit chain."* Representative CVEs where userns is the reachability
multiplier: CVE-2022-0185 (fs_context heap overflow), CVE-2022-0492 (cgroup-v1 `release_agent`),
CVE-2021-22555 (x_tables OOB write), CVE-2023-0386 (OverlayFS uid mapping), CVE-2023-32233
(nf_tables UAF — Red Hat's mitigation is literally `user.max_user_namespaces=0`), CVE-2024-1086
(netfilter double-free). All but the first are on CISA's KEV list.

> **You cannot have both.** If the threat model is "the agent is trusted, the web pages are not,"
> keep nesting open so Chromium sandboxes its own renderers. If the agent itself is untrusted,
> `--disable-userns` + `--no-sandbox` is a real option and a *worse* one. **This argues for two
> playpen profiles: browser-enabled (permits nesting) and no-browser (hardened).**

### 3.7 Adjacent options, briefly

- **AppArmor / SELinux on NixOS**: neither enabled by default, neither well integrated — the
  `/nix/store` path structure fights both models, and both need root to author policy. **Do not
  design playpen around a MAC LSM.** Landlock, being unprivileged and self-applied, is the right
  answer for NixOS. (Landlock is a *stackable* LSM — `LSM_FLAG_EXCLUSIVE` applies only to
  SELinux/Smack/AppArmor — so it composes with anything.)
- **nsjail**: bundles namespaces + seccomp (Kafel DSL) + rlimits + cgroups with a config format. No
  Landlock support found. bwrap's deliberate "mechanism not policy" stance fits playpen better,
  since playpen wants its own policy engine; nsjail's Kafel policies are worth reading.
- **`systemd-run --user`**: on NixOS it *does* give `ProtectHome=`, `PrivateNetwork=`,
  `SystemCallFilter=` etc. via implicit `PrivateUsers=`. **But systemd documents that these
  features are "gracefully turned off" where unavailable** — silent degradation, which is
  disqualifying under playpen's refusal law. Also, `ProtectHome=` explicitly *"does not affect the
  ability for programs to connect to and communicate with AF_UNIX sockets"* — so it does **not**
  protect `$SSH_AUTH_SOCK`. Useful only as an outer cgroup/lifecycle wrapper.

### 3.8 Recommended Linux shape

```
host netns                              │  sandbox (bwrap: mount+user+pid+ipc+uts+net ns)
                                        │
  allowlisting proxy  ◄─────────────────┤  agent binary (claude | omp)
  (squid/mitmproxy, dstdomain ACL)      │    + Landlock domain (irrevocable FS default-deny)
  ── per-host policy lives HERE ──      │    + seccomp: TIOCSTI, AF_PACKET/AF_NETLINK, bpf,
                                        │      io_uring, userfaultfd, keyctl
  broker.sock ─── bwrap --bind ─────────┤  /run/user/N/…  (credentials, brokered)
                                        │
  cgroup v2: memory.max, pids.max,      │  lo UP ──► omp Python kernel, Bun kernel
             cgroup.kill                │
```

What each layer uniquely contributes, and where they deliberately overlap:

1. **bwrap mount ns** — builds `/` from nothing; credentials are *absent*, not merely unreadable;
   brings `lo` up; `--die-with-parent` for lifecycle. Use explicit unshare flags, not
   `--unshare-all` (silent degradation).
2. **Landlock** — *deliberately overlaps* bwrap on FS. It is the layer that holds if a
   mount-namespace assumption turns out wrong, and the only one whose "cannot be undone" is
   unconditional. It is not namespace-relative, so a mount-ns escape does not shed it [INFER].
   Probe the ABI and **refuse** if it is below what policy requires.
3. **netns** — the only unforgeable egress boundary; converts the proxy from a convention into an
   enforced chokepoint.
4. **L7 proxy in the host netns** — the only place per-host policy can live, and outside the
   payload's `CAP_NET_ADMIN` reach.
5. **seccomp** — attack-surface trim. Keep it small; **do not block `clone(CLONE_NEWUSER)` in the
   browser-enabled profile.**
6. **cgroups v2** — resource caps and `cgroup.kill`. Explicitly not security.

**Do not** put egress policy in Landlock (port-only), in nftables *inside* the netns
(payload-flushable), or in `HTTPS_PROXY` alone (grandchild-sheddable).

---

## 4. macOS alternatives — why none replaces `sandbox-exec`

### 4.1 App Sandbox — cannot be applied to a binary you launch

Activated **only** by the `com.apple.security.app-sandbox` entitlement in a code signature; there is
no runtime API to enable it and **no API to impose it on another process** — `libsystem_secinit`
self-initializes in-process at load time [DOC/RE]. **Unsigned binary ⇒ no entitlements ⇒ no App
Sandbox, full stop.** The container model is bundle-ID-keyed, and Apple DTS treats CLI tools only as
*embedded helpers* of a `.app`; dev tools inside an App Sandbox actively fail
(`xcrun: error: cannot be used within an App Sandbox`).

**Network policy is two booleans** — `com.apple.security.network.client` / `.server`. No host, no
port, no domain. Hard ceiling. Arbitrary FS roots need App-Review-scrutinized *temporary exception*
entitlements — one of which is literally `temporary-exception.sbpl`, i.e. raw SBPL, which tells you
where the real mechanism lives.

Useful correction to a common misreading: `com.apple.security.inherit` does **not** *enable*
inheritance. Per Apple DTS: *"Child processes always inherit their sandbox from their parent. The
`com.apple.security.inherit` entitlement only exists to use in combination with
`com.apple.security.app-sandbox`… If you're not shipping on the Mac App Store you can leave off
both."*

**Verdict: unusable for playpen** — cannot confine a third-party binary, and has no expressible
egress allow-list even if it could.

### 4.2 Endpoint Security — **has no network authorization event at all**

Enumerated from this host's SDK header
`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/ESTypes.h`
[LOCAL]. The AUTH event set covers `AUTH_OPEN`, `AUTH_EXEC`, `AUTH_MOUNT`, `AUTH_LINK`,
`AUTH_RENAME`, `AUTH_SIGNAL`, `AUTH_MMAP`, … and grepping for anything network-shaped across all ES
headers returns **only**:

```
ES_EVENT_TYPE_AUTH_UIPC_BIND      ES_EVENT_TYPE_NOTIFY_UIPC_BIND
ES_EVENT_TYPE_AUTH_UIPC_CONNECT   ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT
                                  ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
```

"UIPC" is **UNIX** IPC. **There is no `AUTH_CONNECT`, no `AUTH_SOCKET`, no `AUTH_SENDTO`, no TCP/IP
or UDP authorization event of any kind. ES cannot block an outbound TCP connection.** Certain.

Additional blockers [DOC]: `com.apple.developer.endpoint-security.client` — *"You must request this
entitlement from Apple"* (community reports of multi-month waits and denials); plus **root**, plus
**TCC Full Disk Access granted interactively**, plus system-extension packaging. And it is
**system-wide by construction** — `es_mute_process` approximates "watch only this tree" but that is
a *filter over a global monitor*, not a confinement primitive: not attached to a process, not
inherited across exec, not applicable by an unprivileged user to their own child. A crash of the ES
daemon is a system-wide availability event.

**Verdict: unusable.** Wrong shape, no egress control, Apple-gated.

### 4.3 Network Extension — right capability, impossible gate

NEFilterDataProvider genuinely can do per-flow, per-app egress decisions
(`NEFilterFlow.sourceAppAuditToken`), which is the one macOS mechanism that *could* express per-host
policy. But: `com.apple.developer.networking.networkextension` with `-systemextension` values
requires a **Developer ID provisioning profile with the capability Apple-enabled on the App ID**;
the sysext must live inside a `.app`, share the Team ID, be **notarized**, and be **user-approved in
System Settings** [DOC]. Confirmed on this host — `systemextensionsctl list` shows activated
extensions carry a real teamID [LOCAL]. It is effectively singular and system-wide: a machine-policy
mechanism (EDR/VPN), not a per-invocation confinement tool.

**Verdict: unusable as shipped tooling.** A `go build` binary cannot install one.

### 4.4 Virtualization.framework / Apple Containerization — different layer

`com.apple.security.virtualization` is **self-serve** (no Apple approval) — the only *strong*
isolation route on macOS not gated on Apple's approval queue.
[apple/containerization](https://github.com/apple/containerization) runs *"each Linux container …
within its own lightweight virtual machine"* with sub-second starts.

**But it runs Linux.** It cannot confine a native darwin/arm64 process and gives no macOS
toolchain. It is a Docker replacement, not a Seatbelt replacement — and per issue #1's standing
laws, VM lifecycle is devbox's layer, *under* playpen, not an implementation of it. Question 3 of
apple/containerization#737 is literally a request for a "lite" mode that sandboxes a darwin/arm64
process without a Linux VM; **unanswered**.

---

## 5. Constraints this imposes on playpen

Ordered by how much design they force.

1. **The egress-allowlist ticket (#7-ish) has exactly one viable shape on both platforms:
   deny-all-except-loopback at the kernel mechanism, plus an L7 proxy reached over loopback.** No
   mechanism surveyed can express per-host policy in-kernel without root (only Linux cgroup-eBPF
   can, and it needs `CAP_BPF`). Issue #1's "loopback stays open unconditionally" law is not merely
   convenient for `omp` — it is **load-bearing**, because loopback is the only channel through which
   per-host policy can be enforced at all.

2. **playpen must own the guest's sandbox, not layer over it.** macOS cannot nest sandboxes in
   either direction [LOCAL]. So playpen must run `claude` with `claude`'s own sandbox disabled, and
   its profile must be *stricter* than the one it replaces (Claude Code's ships with
   `SecurityServer`, `lsopen`, `appleevent-send`, and `unix-socket path-regex #"^/"` all allowed).
   This partially answers issue #1's open question about composing with agents' own isolation:
   **on macOS it is not composition, it is replacement.**

3. **Browser automation forces an explicit, documented trade — on both platforms.** macOS: Chrome
   dies inside an outer sandbox unless run with `--no-sandbox` [LOCAL]. Linux: Chromium needs two
   levels of nested userns, so `--disable-userns` and `clone`-blocking seccomp are off the table
   [SRC]. Either way playpen gives up either the browser's own renderer isolation or its own best
   hardening. **Recommendation: two profiles — browser-enabled and no-browser.** Do not try to have
   both at once, and do not let the choice happen implicitly.

4. **`omp`'s shape is easier than feared for FS, and specific about process topology.**
   In-process execution costs only `process-exec` allow-listing (macOS) and per-child seccomp/cgroup
   differentiation (Linux) — granularity that was largely unavailable anyway. But two concrete
   integration requirements fall out: Landlock must be applied **in `main()` before the thread pool
   starts** (per-thread until ABI 8), and namespace unsharing must happen in a **fresh
   single-threaded process** — so **playpen must be `omp`'s parent, never a library called from
   inside it.**

5. **The credential-broker ticket inherits three concrete holes.** (a) **Inherited fds defeat both
   platforms' path policy** — Apple documents it in `sandbox(7)`, Landlock is an open-time check;
   playpen must close all non-essential fds before exec. (b) **The macOS Keychain is a Mach service,
   not a file** — it needs `(deny mach-lookup (global-name "com.apple.SecurityServer"))`, and Claude
   Code's own profile does not do this. (c) **Agent sockets are not covered by path policy** on
   Linux below Landlock ABI 9 — they must be removed from the mount namespace, which means bwrap is
   not optional. The sound brokering primitives are bwrap `--bind` of a proxy socket, and (Linux)
   seccomp user-notify **`ADDFD` only** — the kernel explicitly forbids using user-notify for policy
   decisions.

6. **Toolchain reachability is confirmed as the largest friction source, and the obvious fix is the
   one that leaks.** Blanket-allowing `/nix/store` on macOS **exposed `~/.ssh/config` transitively
   through home-manager symlinks** [LOCAL]. Allow-lists must be narrowed to specific store paths, or
   paired with explicit post-hoc denies (last-match-wins makes this work). Related: on macOS,
   symlink *components* must each be readable, and omitting `(allow file-read* (literal "/"))` makes
   **every dynamically-linked binary SIGABRT with no diagnostic** — which is directly the "failure
   UX" problem issue #1 flags.

7. **playpen's "refuse, never silently downgrade" law has three named enforcement points.** Probe
   Landlock's ABI and refuse below the required version rather than skipping network rules. Prefer
   explicit bwrap unshare flags over `--unshare-all` (whose `-try` suffixes degrade silently).
   Reject `systemd-run --user` as a confinement layer entirely — systemd documents that its
   sandboxing is *"gracefully turned off"* where unsupported.

8. **The macOS deprecation risk is real but not acute, and should be recorded as an accepted
   decision.** `sandbox-exec` has been deprecated in docs since 2017, is fully functional on macOS
   26.5, underpins 511 Apple-shipped profiles, and is depended on in production by Chrome, Nix,
   Bazel, Homebrew, and Anthropic's own sandbox-runtime. **There is no supported alternative for
   confining an arbitrary binary you launch.** The tracking signal to watch is the SDK-27 kill-on-use
   gate on the named `kSBXProfile*` constants — which does not cover custom SBPL, but shows Apple
   pruning this surface by SDK version.

---

## 6. Open items requiring a Linux host

These could not be settled from documentation and should be verified before the design hardens:

1. That bwrap's `--ro-bind` survives a payload unsharing a fresh userns+mountns (§3.2 — the
   composed-rules argument says yes; confirm empirically).
2. That a payload in a *child* userns genuinely gets `EPERM` from `nft` against a netns owned by the
   parent userns (§3.4.2 mitigation).
3. The exact errno for `connect(127.0.0.1)` with `lo` down (predicted `ENETUNREACH`).
4. The Landlock ABI actually reported by
   `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` on the target NixOS kernel —
   this single number determines whether §3.1.3 is even available.
5. Whether Chromium under bwrap-without-`--disable-userns` actually launches with a working sandbox
   on the target kernel (§3.6 is inference from source).
6. **Whether `omp`'s kernel bridge uses TCP/127.0.0.1, abstract AF_UNIX, or pathname AF_UNIX
   sockets** — this materially changes the netns analysis and is worth reading out of `omp`'s
   source. Its README says only *"loopback bridge."*
7. Bun/undici `HTTPS_PROXY` honouring (relevant only to the cooperative path).

And on macOS, one item deliberately not attempted: whether the Antigravity devfs/`BASH_ENV` escape
chain still works on 26.5. It was not tested, and the recommended mitigations (`(deny default)`,
plus explicit `file-mount`/`lsopen`/`appleevent-send` denies) are prophylactic.
