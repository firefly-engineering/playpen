# Hosted CI hermeticity — which enforcement-suite rows can run on a hosted runner?

Research output for [#29](https://github.com/firefly-engineering/playpen/issues/29)
(parent: [#1](https://github.com/firefly-engineering/playpen/issues/1)).

**Question.** ADR 0016 fixed the *policy* — preconditions are probed, a missing one produces a
**named** skip, CI may be green with skips, a release requires the full set green on a reference
host of each platform — and deliberately left four facts unguessed. Can the enforcement suite run
hermetically on hosted CI runners, and **which rows of the suite table must be skipped where**?

**Method.** Primary sources, fetched 2026-08-17:

- **`actions/runner-images`** — the per-image README manifests under `images/ubuntu/` and
  `images/macos/` are the authoritative statement of the OS and kernel a label ships, and the
  repository README is authoritative for what `-latest` points at.
- **Kernel primary sources** — `man 7 landlock` for the ABI-to-kernel table,
  `docs.kernel.org/userspace-api/landlock.html` for the detection idiom and its errno semantics,
  `docs.kernel.org/admin-guide/LSM/` for `/sys/kernel/security/lsm`, `security/Kconfig` in
  `torvalds/linux` for the upstream `CONFIG_LSM` default, and Launchpad for Ubuntu's.
- **Canonical primary sources** — Launchpad (LP#1953192 for Landlock, LP#2066885 for the flavour
  divergence, LP#2046477 for the user-namespace sysctl), the Ubuntu 24.04 LTS release notes, and the
  23.10 discourse spec for the AppArmor user-namespace restriction.
- **Apple primary sources** — the Xcode-shipped `sandbox_init(3)` and `sandbox-exec(1)` man pages,
  and `/Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/usr/include/sandbox.h` on this host.
- **Nix ecosystem** — the Nix manual's `conf-file` and `profiles` pages,
  `DeterminateSystems/nix-installer{,-action}` including its own CI workflow,
  `cachix/install-nix-action` including its own CI workflow, and `nix-community/home-manager`'s
  activation source.
- **This host, executed.** Unlike [#23](https://github.com/firefly-engineering/playpen/issues/23),
  half of this ticket *is* measurable here, because of the single most useful fact in the report:
  **the hosted `macos-latest` image and this reference host run the same OS build.** Nothing was
  installed and no CI was run.

Provenance tags, as in `linux-denial-visibility.md` and `mechanism-capability-matrix.md`:

| Tag | Meaning |
|---|---|
| **[DOC]** | Stated in a kernel/vendor/first-party primary source |
| **[SRC]** | Read from upstream production source |
| **[LOCAL]** | Executed on this macOS host today |
| **[INFER]** | My composition of documented rules; not directly verified |
| **[RUNNER]** | Settleable only by executing on a runner. Named, never guessed |

---

## 0. Executive summary

**Yes, and more of the suite runs than ADR 0016 feared — but only after two corrections to the
ticket's own premises, and only if the runner label is pinned rather than followed.**

1. **The ticket's sharpest worry is not a worry.** The stale-`…-home-manager-files/.ssh/config`
   negative does **not** need a store with more than one generation. A store path with that name
   can be manufactured directly: `nix store add-path ./decoy --name
   '…-home-manager-files'` produces `/nix/store/<hash>-…-home-manager-files/`, and a read of
   `.ssh/config` inside it returns `Operation not permitted` from inside a Seatbelt profile that
   does not grant it, while the same read outside succeeds. **[LOCAL]** That is exactly ADR 0016's
   decoy discipline, and it collapses the hardest closure negative into a one-line fixture. A
   second `home-manager switch` would in any case *not* reliably produce a second generation —
   home-manager's `writeBoundary` guards `nix-env --set` on `"$oldGenPath" != "$newGenPath"`, so an
   unchanged configuration is a no-op for the profile. **[SRC]**

2. **`macos-latest` is this host.** `images/macos/macos-26-arm64-Readme.md` reports
   `OS Version: macOS 26.5.2 (25F84)`, `Kernel Version: Darwin 25.5.0` **[DOC]**; `sw_vers` and
   `uname` here report **macOS 26.5.2 (25F84), Darwin 25.5.0, arm64** **[LOCAL]**. The SBPL
   compiler is a component of that OS build, so every Seatbelt measurement in this report is a
   measurement of the runner's compiler too, modulo the one thing that differs — the
   Virtualization.framework guest substrate.

3. **`sandbox_init` is a live symbol and the ceiling is where ADR 0006 said, sharpened.**
   `sandbox_init` and `sandbox_init_with_parameters` both resolve out of
   `/usr/lib/libSystem.B.dylib` and both enforce, despite `sandbox.h` carrying
   `API_DEPRECATED("No longer supported", macos(10.5, 10.8))` on every declaration **[LOCAL/DOC]**.
   Called through direct FFI — nono's path — the ceiling is crossed between **1013 and 1014**
   `(allow file-read* (subpath "/nix/store/<name>"))` rules, reporting `data object length 65575
   exceeds maximum (65535)` in `errorbuf` with `rc = -1` and **`errno` untouched** **[LOCAL]**. ADR
   0006's "between 1000 and 1100" is confirmed and narrowed.

4. **Landlock should be live on `ubuntu-24.04` and is definitionally short on `ubuntu-22.04`.**
   The runner images ship **6.17.0-azure** (24.04, x64 and arm) and **6.8.0-azure** (22.04)
   **[DOC]**, which by the `man 7 landlock` table cap at **ABI 7** and **ABI 4** respectively
   **[DOC/INFER]**. Ubuntu has had `landlock` first in `CONFIG_LSM` since Jammy
   (`linux 5.15.0-17.17`, LP#1953192, Fix Released) **[DOC]**, and upstream has had it in the
   `CONFIG_LSM` default since 5.13 **[SRC]** — but the **azure flavour's own `CONFIG_LSM` could not
   be sourced**, and LP#2066885 is proof that Ubuntu flavours do diverge on exactly this. So
   Landlock availability on the runner is **[RUNNER]**, settled by one probe.

5. **One suite row is already broken, and the runner is where it would have been certified green.**
   Ubuntu 24.04 restricts unprivileged user namespaces by default, and its `default_allow` profile
   for unprofiled binaries **permits `unshare(CLONE_NEWUSER)` and then denies every capability inside
   the namespace** **[DOC]**. So `unshare(CLONE_NEWUSER)` **returns 0** while the nested `clone`s
   Chromium actually performs are refused — the assertion as #22 recorded it passes for the wrong
   reason on the very machine where it would run most often. **The fix is to strengthen the row to
   the nested sequence, not to skip it.** §4.2. This is the report's sharpest finding and the one
   change it asks of a landed decision.

6. **The three-outcome correction.** ADR 0016 speaks of runs-or-skips, but a runner produces
   **three** outcomes, and collapsing two of them re-imports the disease. A row can *run*; it can
   be **`n/a` by platform** — the Keychain Mach negative on Linux, the compiled-profile-ceiling
   refusal on macOS — which is a **named asymmetry** already on the ledger and *not* a skip; or it
   can be **skipped**, meaning the row does apply to this platform but a precondition on *this host*
   is missing. Reporting an `n/a` as a skip makes the ledger look like a gap; reporting a skip as
   `n/a` retires an asymmetry that was never retired. **This is the report's one recommended
   amendment to ADR 0016.**

7. **Pin `ubuntu-24.04` and `macos-15`/`macos-26`, never `-latest`.** `ubuntu-latest` follows the
   newest GA image with a 1–2 month announcement **[DOC]**, and Ubuntu 26.04 (kernel 7.0.0-azure,
   ABI 8) is in public preview. A suite whose *row set* is a function of the kernel's Landlock ABI
   must not have its floor move without a commit — that is ADR 0016's "never a hardcoded platform
   assumption" read forward, and following `-latest` is the same sin with the sign flipped: an
   unpinned assumption. Ubuntu 22 begins deprecation **2026-09-17** anyway **[DOC]**. Also avoid
   `ubuntu-slim`: it is **not a VM**, "runs in unprivileged mode", and GitHub states that "accessing
   low-level kernel features" is unsupported there **[DOC]**.

**Bottom line: the enforcement suite runs on hosted CI with two named skips and two `n/a`s per
platform, and every one of them is decided by a cheap probe rather than a platform string.** The
liveness suite does not run on hosted CI at all, and ADR 0016 already said so.

---

## 1. The runner inventory — what the labels actually are

All from the per-image README manifests, which track the *current* image build and therefore change
over time; the values below are the builds dated 2026-08-10 (Ubuntu) and 2026-07-28 (macOS). **[DOC]**

### 1.1 Linux

| Label | OS | Kernel | Max Landlock ABI (from §2.1) |
|---|---|---|---|
| `ubuntu-latest` → 24.04 x64 | 24.04.4 LTS | **6.17.0-1022-azure** | 7 |
| `ubuntu-24.04` | 24.04.4 LTS | 6.17.0-1022-azure | 7 |
| `ubuntu-24.04-arm` | 24.04.4 LTS | 6.17.0-1022-azure | 7 |
| `ubuntu-22.04` | 22.04.5 LTS | **6.8.0-1064-azure** | **4** |
| `ubuntu-26.04` (public preview) | 26.04 LTS | 7.0.0-1011-azure | 8 |

Sources: [`Ubuntu2404-Readme.md`](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md),
[`Ubuntu2404-Arm64-Readme.md`](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Arm64-Readme.md),
[`Ubuntu2204-Readme.md`](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2204-Readme.md),
[`Ubuntu2604-Readme.md`](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2604-Readme.md).
`-latest` mapping and the 1–2 month migration lead time: the
[repo README](https://github.com/actions/runner-images) and
[GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
Ubuntu 26.04 preview: [runner-images#14226](https://github.com/actions/runner-images/issues/14226).
Ubuntu 22 deprecation dates: [runner-images#14254](https://github.com/actions/runner-images/issues/14254).

Note the kernel is a Canonical **`-azure`** flavour, not `-generic`. That is the crack §2.2 falls
through.

### 1.2 macOS

| Label | Arch | OS | Kernel | Status |
|---|---|---|---|---|
| `macos-latest`, `macos-26` | **arm64** | **macOS 26.5.2 (25F84)** | **Darwin 25.5.0** | GA |
| `macos-15` | arm64 | macOS 15.7.7 (24G720) | Darwin 24.6.0 | GA |
| `macos-26-intel`, `macos-latest-large` | x64 | macOS 26 | — | GA |
| `macos-15-intel`, `macos-15-large` | x64 | macOS 15 | — | GA |
| `macos-14`, `macos-14-large` | both | macOS 14 | — | **Deprecated** |

Sources: [runner-images README](https://github.com/actions/runner-images),
[`macos-26-arm64-Readme.md`](https://github.com/actions/runner-images/blob/main/images/macos/macos-26-arm64-Readme.md),
[`macos-15-arm64-Readme.md`](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-arm64-Readme.md).
**`macos-13` no longer exists**, and the naming is inverted from the obvious reading: plain
`macos-NN` and `-xlarge` are **arm64**; `-large` and `-intel` are **x86_64**. **[DOC]**

**This host: macOS 26.5.2, build 25F84, Darwin 25.5.0, arm64. [LOCAL]** The reference host and
`macos-latest` are the same OS build. That is a coincidence with an expiry date — the runner image
will move — but while it holds, every §3 measurement is a measurement of the runner's own SBPL
compiler.

### 1.3 The substrate, and what GitHub does *not* say

Hosted macOS runners are **guest VMs under Apple's Virtualization.framework on Apple silicon**. The
load-bearing sentence is in GitHub's docs source
([`macos-runner-limitations.md`](https://github.com/github/docs/blob/main/data/reusables/actions/macos-runner-limitations.md)),
verbatim: *"Nested-virtualization is not supported due to the limitation of Apple's Virtualization
Framework."* **[DOC]** Both Linux and macOS runners are VMs with **passwordless `sudo`** **[DOC]**.

**GitHub says nothing whatever about Seatbelt.** `sandbox-exec`, `sandbox_init` and Seatbelt appear
nowhere in `runner-images` or in GitHub's docs. The absence is worth stating explicitly, because it
means the macOS half of this ticket cannot be closed from GitHub's own documentation and rests on
§3.3's indirect evidence plus one named experiment.

---

## 2. Landlock on a hosted Linux runner

### 2.1 The ABI table, as a primary source

`man 7 landlock` ships the explicit ABI-to-kernel mapping (the kernel's own
`userspace-api/landlock.html` lists the features per ABI but only dates ABI 1). **[DOC]**

| ABI | Kernel | Addition |
|---|---|---|
| 1 | 5.13 | `LANDLOCK_ACCESS_FS_*` |
| 2 | 5.19 | `FS_REFER` |
| 3 | 6.2 | `FS_TRUNCATE` |
| 4 | 6.7 | `ACCESS_NET_BIND_TCP` / `CONNECT_TCP` |
| 5 | 6.10 | `FS_IOCTL_DEV` |
| 6 | 6.12 | `SCOPE_ABSTRACT_UNIX_SOCKET`, `SCOPE_SIGNAL` — **nono's `ABI_PROBE_ORDER` ceiling** |
| 7 | 6.15 | `RESTRICT_SELF_LOG_*` — the audit flags #23 needs |
| 8 | 7.0 | `RESTRICT_SELF_TSYNC` |
| 9 | 7.1 | `FS_RESOLVE_UNIX` |
| 10 | 7.2 | `NET_BIND_UDP` / `CONNECT_SEND_UDP`, `ADD_RULE_QUIET` |

ABI 9 and 10 are not in the man page's table and were derived from `security/landlock/limits.h`
history against release tags; mainline currently has `const int landlock_abi_version = 10;` in
`security/landlock/syscalls.c` **[SRC]**. This supersedes and completes the partial table in
`linux-denial-visibility.md` §1.1.

**Consequences for the suite.** `ubuntu-24.04`'s 6.17 reaches ABI 7, which is above nono's V6 probe
ceiling — so nono negotiates its maximum and nothing is lost to the kernel. `ubuntu-22.04`'s 6.8
reaches only **ABI 4**, which loses `SCOPE_ABSTRACT_UNIX_SOCKET` and `SCOPE_SIGNAL`: the Linux
counterpart of the Keychain Mach negative and any signal-scoping assertion are **inexpressible**
there. That is not a skip in ADR 0016's sense — the row applies to Linux and the kernel cannot carry
it — and it is the cleanest possible argument for pinning `ubuntu-24.04`. **[DOC/INFER]**

### 2.2 Is it enabled? — and the one link that could not be sourced

- **Upstream: yes since 5.13.** Commit [`385975dca53e`](https://github.com/torvalds/linux/commit/385975dca53e)
  prepends `landlock,` to every `config LSM` default in `security/Kconfig`; master reads
  `default "landlock,lockdown,yama,loadpin,safesetid,apparmor,selinux,smack,tomoyo,ipe,bpf" if
  DEFAULT_SECURITY_APPARMOR`. **[SRC]**
- **Ubuntu sets `CONFIG_LSM` explicitly and originally omitted landlock**, so it was compiled in but
  inert: [LP#1950381](https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1950381), where the
  reporter had to add `lsm=landlock,…` to GRUB. **[DOC]**
- **Fixed in Jammy.** [LP#1953192](https://bugs.launchpad.net/bugs/1953192) "Enable Landlock by
  default" is **Fix Released in `linux 5.15.0-17.17`** (2022-01-13). Ubuntu's resulting generic
  string, quoted in [LP#2066885](https://bugs.launchpad.net/bugs/2066885), is
  `CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"`. **[DOC]**
- **The gap.** LP#2066885 exists precisely because the **raspi** flavour shipped
  `CONFIG_LSM="yama,integrity,apparmor"` — no landlock — and needed a separate
  `[Config] raspi: Enable landlock LSM by default` fix. So Ubuntu flavours *do* diverge here, and
  the **azure flavour's `CONFIG_LSM` could not be read from a primary source**: Launchpad's kernel
  git redirects to OpenID login and the `ubuntu/+source/linux` cgit path 404s. **[RUNNER]**

The engineering consequence is not "find the config" — it is that **the config is the wrong thing to
read**. `lsm=` is a boot-time cmdline parameter, so even if it were wrong there is no in-job repair
(and a fresh VM per job makes a reboot a non-operation). The suite must probe at runtime, which is
what ADR 0016 already requires.

### 2.3 The probe, and its errno vocabulary

The kernel's own documented idiom, verbatim from
[`docs.kernel.org/userspace-api/landlock.html`](https://docs.kernel.org/userspace-api/landlock.html):

```c
abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
if (abi < 0) {
    switch (errno) {
    case ENOSYS:
        printf("Landlock is not supported by the current kernel.\n");
        break;
    case EOPNOTSUPP:
        printf("Landlock is currently disabled.\n");
        break;
```

**A non-negative return *is* the ABI version.** `ENOSYS` means the kernel has no Landlock at all;
`EOPNOTSUPP` means it is compiled in but **not active** — i.e. absent from `CONFIG_LSM`/`lsm=`.
**[DOC]** Those are two different named skips and must not collapse into one, for exactly ADR 0016's
reason: *"kernel too old"* and *"your distro left it out of `lsm=`"* are different facts about the
host with different remedies.

Cross-checks, all unprivileged:

- **`/sys/kernel/security/lsm`** is the list of active LSMs —
  [`docs.kernel.org/admin-guide/LSM/`](https://docs.kernel.org/admin-guide/LSM/), verbatim: *"A list
  of the active security modules can be found by reading ``/sys/kernel/security/lsm``."* **[DOC]**
  **The ticket named `/sys/kernel/security/lockdown`; that is the lockdown LSM's own mode file and
  is unrelated.** Correcting the ticket's own text.
- `dmesg | grep landlock` → `landlock: Up and running.`, and
  `sed -n 's/.*\(\<lsm=\S\+\).*/\1/p' /proc/cmdline`, both suggested by the same kernel doc. **[DOC]**
- `LANDLOCK_CREATE_RULESET_ERRATA` returns an errata bitmask, which is a second reason the syscall
  probe beats reading a config. **[DOC]**

**Landlock needs no privilege.** The kernel doc's own title is *"Landlock: unprivileged access
control"* and its text is *"Landlock empowers any process, including unprivileged ones, to securely
restrict themselves."* `landlock_restrict_self()` requires either `CAP_SYS_ADMIN` **or**
`no_new_privs` — so `PR_SET_NO_NEW_PRIVS` is the whole entry fee. **[DOC]** Nothing about the runner's
privilege model blocks the suite.

---

## 3. Seatbelt on a hosted macOS runner

### 3.1 `sandbox_init` resolves and enforces — measured

`sandbox.h` in the shipped SDK marks **every** declaration
`API_DEPRECATED("No longer supported", macos(10.5, 10.8), ios(2.0, 6.0), …)` and opens with *"This
header is deprecated and may be removed in a future release."* **[DOC]** The man page agrees:
*"sandbox_init, sandbox_free_error — set process sandbox (DEPRECATED)"*, dated 2017-03-09
([`sandbox_init(3)`](https://keith.github.io/xcode-man-pages/sandbox_init.3.html)). **[DOC]**

Measured here anyway, by `dlsym` against `/usr/lib/libSystem.B.dylib`: **[LOCAL]**

```
sandbox_init                 = 0x1972365cc
sandbox_init_with_parameters = 0x1972365d8
sandbox_compile_string       = 0x0        (private, not exported)
```

and calling it with a real SBPL string enforces immediately — a subsequent
`fopen("/etc/hosts")` in the same process returns `Operation not permitted`. **[LOCAL]** So nono's
direct-FFI path is live on macOS 26.5.2 / build 25F84, which is `macos-latest`'s build.

Two deprecation notes worth carrying to ADR 0003's clock rather than to this suite:

- The current man page adds, of the five **named** `kSBXProfile*` constants: *"These profiles must
  not be used when building against macOS SDK >= 27.0. Processes opting into them will be killed on
  attempt to do so."* It sits in `AVAILABLE PROFILES` and speaks to `SANDBOX_NAMED`, **not** to
  custom SBPL strings — which is what playpen uses. **[DOC]** The scope is nonetheless the first
  concrete removal language Apple has published, and the `macos-26` image ships Xcode 26.x with an
  Xcode 27 preview label alongside it.
- [`apple/containerization#737`](https://github.com/apple/containerization/issues/737) asks Apple
  directly for a removal timeline and a non-App-Sandbox replacement. **Open, no response.** **[DOC]**

### 3.2 The compiled-profile ceiling — measured through both doors

Apple documents **no** profile size limit; Chromium's own design note says *"there is no official
OS-provided documentation for the SBPL"*
([Mac Sandbox V2 design](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/mac/seatbelt_sandbox_design.md)).
**[DOC]** The 65535 figure is `libsandbox`'s own error string, and it is reproducible.

Bisected on this host with `(allow file-read* (subpath "/nix/store/<name>"))` rules, one per real
store path: **[LOCAL]**

| Door | Last OK | First failure | Reported |
|---|---|---|---|
| `/usr/bin/sandbox-exec -f` | **1013 rules** | **1014 rules** | `sandbox-exec: data object length 65543 exceeds maximum (65535)`, exit **65** |
| `sandbox_init()` direct FFI | 1013 rules | 1014 rules | `rc = -1`, `errorbuf = "data object length 65575 exceeds maximum (65535)"`, **`errno` = 0** |

Three findings the suite depends on:

1. **The ceiling is on compiled bytes, not on paths.** ≈64.7 compiled bytes per `subpath` rule here,
   so the crossover *count* is a function of the rule text and is **not portable between hosts** —
   a runner's store path names differ from this host's. **The ceiling-refusal row must assert
   playpen's refusal `code`, never a path count**, or it becomes a host-specific magic number.
2. **The FFI door reports through `errorbuf`, and leaves `errno` untouched.** A refusal path that
   reads `errno` gets `0`/`Undefined error: 0` and has nothing to say. ADR 0016's "never a leaked
   backend error" needs playpen to read `errorbuf` and translate; there is no errno to map.
3. **ADR 0006's "between 1000 and 1100" is confirmed and narrowed to 1013/1014** for a
   `subpath`-per-store-path shape, at the reference host's own OS build.

Corroborating third-party reports, for the record: the same message at a different length,
`pattern serialization length 71710 exceeds maximum (65535)`
([NixOS/nix#4119](https://github.com/NixOS/nix/issues/4119)); a **second, distinct** ceiling in the
same compiler — `Assertion failed: (diff <= INSTR_JUMP_NE_MAX_LENGTH), function push_jne_instr` /
`Abort trap: 6` ([NixOS/nix#2311](https://github.com/NixOS/nix/issues/2311)); and Nix's fix, which
splits the allow-list into consecutive s-expressions
([NixOS/nix#12570](https://github.com/NixOS/nix/pull/12570), merged 2025-03-19), whose author found
empirically that *"limiting the size of the s-expression to 256 bytes for each allow-list works but
512 doesn't"*. **[DOC, community-reported]** The bytecode-jump ceiling is worth knowing about because
it is a *different* failure with a *different* signature — `Abort trap: 6`, which is the same
`rc=134`-with-nothing-useful shape the loader canary exists to catch. A policy that trips it would
look like a floor regression.

### 3.3 Does Seatbelt work inside the Virtualization.framework guest?

**No primary source says so, and this is the report's largest inference.** **[INFER]**

The best available evidence is a hosted-runner job in which `sandbox-exec` demonstrably *did*
compile and apply a profile:
[cachix/install-nix-action#15](https://github.com/cachix/install-nix-action/issues/15) records the
failure `sandbox-exec: execvp() of '/nix/store/…-bash-4.4-p23/bin/bash' failed: Operation not
permitted`. The profile was compiled and installed — `sandbox_init` returned 0 — and the *policy*
then denied the `execvp`. That is positive evidence for the mechanism and negative evidence about
Nix's profile. **[DOC, indirect]**

What is **not** available, and I looked: any green-CI artifact of a genuinely Seatbelt-sandboxed Nix
build on a hosted macOS runner. `sandbox = true` for Darwin was added in
[install-nix-action#26](https://github.com/cachix/install-nix-action/pull/26) (2020-02-26) and
**reverted hours later** (`ef735e8`, "Revert 'Enable sandbox on darwin'"); current `lib/install-nix.sh`
sets no `sandbox` value at all. The one CI job that looks like proof runs `sandbox = relaxed`
against a `__noChroot` derivation, which under `relaxed` is *not* sandboxed — so it proves the
escape hatch, not the mechanism. **[SRC]** Meanwhile the Nix manual is explicit that `sandbox`
defaults to **`true` on Linux and `false` on all other platforms**
([conf-file](https://nix.dev/manual/nix/latest/command-ref/conf-file)) **[DOC]** — so a fresh Nix on
a macOS runner is not exercising Seatbelt at all, and cannot be leaned on as evidence.

**This is the one fact that cannot be settled without a runner, and the experiment is cheap** — see
§6.1.

---

## 4. The four open facts, answered

### 4.1 Landlock on hosted Linux

**Expected ABI 7 on `ubuntu-24.04` (kernel 6.17), ABI 4 on `ubuntu-22.04` (kernel 6.8); enabled by
Ubuntu policy since Jammy; detectable in one syscall with two distinguishable failures; unverified
for the `-azure` flavour.** §2. The floor the ticket asked about — ABI ≥ 1 — is almost certainly
met with margin, and nono's V6 probe ceiling is *below* the 24.04 kernel's ABI, so nothing is lost
to the runner. `ubuntu-22.04` is the one label that changes the row set, and it is deprecating.

### 4.2 `unshare(CLONE_NEWUSER)` — the row that passes vacuously, and the sharpest finding here

The suite has a positive, admitted by ADR 0016 because its regression is silent: **`unshare(CLONE_NEWUSER)`
succeeds** inside the sandbox, because a future nono gating `clone` would kill browser automation
without a word. As stated, **that assertion passes vacuously on Ubuntu 24.04 — including the
runner — while the capability it stands proxy for is denied.**

The facts, from Canonical primary sources:

- **Ubuntu 23.10 introduced an AppArmor-backed restriction on unprivileged user-namespace creation**,
  gated by the sysctl **`kernel.apparmor_restrict_unprivileged_userns`**, whose spec states plainly
  that it *"should be changed to be enabled by default (via a default value of 1)"*, and that the
  restriction applies to **unconfined** applications, not only confined ones.
  ([Ubuntu discourse spec](https://discourse.ubuntu.com/t/spec-unprivileged-user-namespace-restrictions-via-apparmor-in-ubuntu-23-10/37626)) **[DOC]**
- **It is enabled by default from 24.04.** The
  [Ubuntu 24.04 LTS release notes](https://documentation.ubuntu.com/release-notes/24.04/) state the
  kernel *"restricts the use of unprivileged user namespaces"* for all unprivileged unconfined
  programs, name the sysctl, and give the escape hatch
  `echo 0 | sudo tee /proc/sys/kernel/apparmor_restrict_unprivileged_userns`. **[DOC]**
- **The mechanism is a userspace package, which is why 22.04 differs.**
  [LP#2046477](https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/2046477) "Enable unprivileged
  user namespace restrictions by default" is **Fix Released in `apparmor 4.0.0~alpha2-0ubuntu7`**, and
  the implementation is a line in the apparmor package's own `sysctl.d` conf setting the value to 1,
  with a guard that disables it if the kernel lacks support. **[DOC]** So the deciding artefact is the
  **apparmor package version**, not the kernel: `ubuntu-22.04` ships apparmor 3.x and therefore does
  *not* set the sysctl, even though its `6.8.0-azure` kernel is from the Noble series and may well
  carry the mediation code. `ubuntu-24.04` ships apparmor 4.x and does.
- **There is a second, related sysctl** — `kernel.apparmor_restrict_unprivileged_unconfined` — which
  is what extends the mediation to processes with no profile at all
  ([Canonical's 23.10 blog post](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)
  names both). A probe that reads only one of the two is reading half the state. **[DOC]**

**And here is the trap.** The 24.04 release notes say that an application with no AppArmor profile
gets a **default profile that permits the user namespace and then denies the subsequent use of any
capabilities within it** — the `default_allow` profile mode exists precisely because writing real
profiles for every affected application was infeasible, and it *"adds a new `userns,` rule to allow
it to use unprivileged user namespaces"* while still denying capabilities inside. **[DOC]** So on a
default Ubuntu 24.04:

> `unshare(CLONE_NEWUSER)` **returns 0**. The nested operations that make a user namespace *useful* —
> a second `unshare(CLONE_NEWUSER)`, `CLONE_NEWPID|CLONE_NEWNET`, the `mount` calls — are **denied**.

That is the exact shape ADR 0016 exists to forbid: an assertion that passes for the wrong reason, on
the machine where the boundary is least exercised. And `chromium-under-seccomp.md` already recorded
what Chromium actually does — `CanCreateProcessInNewUserNS()` performs
`clone(CLONE_NEWUSER|SIGCHLD)` followed by a **nested** `unshare(CLONE_NEWUSER)` in the child, and
`NamespaceSandbox::LaunchProcess` uses `clone(CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET)`. **[SRC]**
The single bare `unshare` the suite would assert on is *not* the thing Chromium needs.

**So this row must be strengthened, not skipped.** Assert the **nested** sequence — outer
`clone`/`unshare(CLONE_NEWUSER)`, then a second `unshare(CLONE_NEWUSER)` and
`CLONE_NEWPID|CLONE_NEWNET` inside it — which is the narrowest thing that both catches a future
nono gating `clone` *and* refuses to pass under the AppArmor default profile. **This is a correction
to #20's assertion as #22 recorded it, not a CI skip.**

Two consequences for the suite's shape:

1. **The row becomes a two-part positive**, mirroring ADR 0016's two-part negative: assert the
   sequence succeeds **outside** the sandbox on this host, and only then that it still succeeds
   inside. Outside-failure is a **named skip** — `skip.host.userns-restricted` — never a red, because
   the host, not the backend, refused. That generalises "absence outside is a setup failure, never a
   pass" from negatives to positives, and it is the second amendment this report recommends to ADR
   0016.
2. **The precondition probe reads both sysctls**, unprivileged, at
   `/proc/sys/kernel/apparmor_restrict_unprivileged_{userns,unconfined}`, and — because the
   `default_allow` profile makes the sysctl value *insufficient* to predict the outcome — the
   authoritative probe is **behavioural**: run the nested sequence outside and look at the result.
   The sysctl values are what let the skip be *named*; the behaviour is what decides it.

**Whether GitHub's `ubuntu-24.04` image overrides the sysctl is unsourced.** A search of
`actions/runner-images` issues for `apparmor_restrict_unprivileged_userns` returns **zero** results,
and no image manifest mentions it. The image preinstalls rootful Docker, which needs no user
namespaces, so there is no obvious reason for GitHub to have turned it off. **[RUNNER — §6.3.]**

### 4.3 #23's four audit preconditions — one is met, two probe cleanly, one does not probe at all

Taking them in order, against a hosted `ubuntu-24.04`:

| # | Precondition | On the runner | Detectable? |
|---|---|---|---|
| 1 | kernel **6.15+** | **Met** — 6.17.0-azure **[DOC]** | **Yes, cleanly.** `landlock_create_ruleset(NULL,0,VERSION) >= 7`. ENOSYS/EOPNOTSUPP name the two failures **[DOC]** |
| 2 | nono passes `LOG_NEW_EXEC` | **Not met** — nono calls `restrict_self(fd, 0)` and never `log_new_exec()` **[SRC, #23]** | **Yes, trivially** — it is a property of the *pin*, not the host. Host-independent, so it fails identically on the reference host |
| 3 | `audit_enabled` | **Unknown.** journald's `Audit=` defaults to `yes` **[DOC]**, but whether `systemd-journald-audit.socket` is enabled on the `-azure` image is unsourced | **This is the one that is not cleanly detectable.** #23 §7.3 already flagged that *no unprivileged read path for `audit_enabled` was established*. It is still open, and it is now blocking two tickets |
| 4 | journal group membership | **Unknown** — the `runner` user's supplementary groups are not in any manifest I could find | **Yes, trivially** — `id -Gn` against `{systemd-journal, adm, wheel}` **[DOC, `journalctl(1)`]** |

**So #23's expectation is confirmed in outcome and corrected in reason.** #23 expected the *kernel
version* to be the thing that fails on a runner; on `ubuntu-24.04` it is the one precondition that
passes with room to spare. What actually fails is **nono's missing flag** — and that fails on every
host including the reference host, so it is not a CI skip at all but a permanent red until the
upstream nono change lands. The genuinely runner-shaped uncertainty is **`audit_enabled`**, and the
gap is not "is it on" but "**can an unprivileged process find out**". Until that read path exists,
the skip for the `--trace-denials` refusal row cannot be *named* on this precondition — it can only
be inferred, which is the thing ADR 0016 forbids. **This is the sharpest open item in the report.**

### 4.4 Nix on the runner

**Nix installs and works on hosted Linux and hosted macOS arm64, and the closure negatives run —
including the sharp one, which turns out not to need generations at all.**

- **Installer support.** `nix-installer-action` supports Linux x86_64/aarch64 and **macOS aarch64
  only**, explicitly on "GitHub Hosted … Actions Runners"; upstream `nix-installer`'s platform table
  has no `x86_64-darwin` row. `install-nix-action` supports Linux and macOS, with the caveat that
  single-user `--no-daemon` mode is **not** supported on macOS runners. **[DOC]** So a
  `macos-15-intel` runner is off the table for the closure rows, and the multi-user daemon is the
  only macOS shape.
- **`/nix` on macOS without a reboot: proven, by the installer's own CI.** The `macos` planner
  applies the synthetic-`/nix` trick by invoking `apfs.util -t -B`
  (`src/action/macos/create_synthetic_objects.rs`), then creates the APFS volume
  (`create_nix_volume.rs`) **[SRC]**. `nix-installer`'s own `.github/workflows/ci.yml` job
  `run-aarch64-darwin` runs on `macos-latest-xlarge` and performs install → uninstall → **reinstall**
  → `nix run nixpkgs#hello` **inside one non-rebootable job**. **[SRC]** That settles it.
- **The stale-`home-manager-files` negative does not need a second generation.** Measured here:
  `nix store add-path ./decoy --name 'zzzzdecoy-home-manager-files'` yields
  `/nix/store/<hash>-zzzzdecoy-home-manager-files`, and under a Seatbelt profile granting the floor
  but not the store, `cat …/.ssh/config` returns **`Operation not permitted`** while the same read
  outside succeeds. **[LOCAL]** Two-part negative satisfied, on a fresh store, in one command.
- **And a second `switch` would not have worked reliably anyway.** home-manager's
  `home.activation.writeBoundary` guards `nix-env --profile … --set "$newGenPath"` on
  `[[ ! -v oldGenPath || "$oldGenPath" != "$newGenPath" ]]` **[SRC]** — an unchanged configuration
  produces **no** new generation. The fixture would have had to mutate the configuration
  meaningfully between switches. The decoy is strictly better: it is deterministic, it is one line,
  and per ADR 0016 it is the *canonical* form for a target the host does not have.
- **The reference host has the real thing, and that is the point of the release gate.** 120
  `*-home-manager-files` and 57 `*-home-manager-path` derivations live in this store, against a
  single surviving profile generation link (`home-manager-351-link`) — 366,891 store paths in total.
  **[LOCAL]** ADR 0014's figures reproduce exactly. So the runner runs the *decoy* form and the
  reference host runs the *real* form; the release gate is what makes the difference matter, and ADR
  0016 already put it there.

---

## 5. The answer that matters — the row table

**Three outcomes, not two** (§0.6): **run**; **`n/a`**, meaning the row is scoped to the other
platform and carries a named asymmetry; **skip**, meaning the row applies here and a precondition on
*this host* is missing. A skip is named and reported. An `n/a` is a ledger entry.

Row ids are mine; the suite's real ones belong to its implementation. `from:` is ADR 0016's
provenance field.

### 5.1 Negatives

| Row | Hosted Linux (`ubuntu-24.04`) | Hosted macOS (`macos-15`/`26`) | Deciding precondition probe |
|---|---|---|---|
| `N-ssh-key` — `~/.ssh/id_*` unreadable | **run**, decoy | **run**, decoy | target exists outside — fixture creates the decoy, so unconditional |
| `N-ssh-config` — `~/.ssh/config` unreadable | **run**, decoy | **run**, decoy | as above |
| `N-aws` — `~/.aws` unreadable | **run**, decoy | **run**, decoy | as above |
| `N-npmrc` — `~/.npmrc` unreadable | **run**, decoy | **run**, decoy | as above |
| `N-symlink` — unreachable *through a resolved symlink* | **run**, decoy | **run**, decoy | `symlink()` in the fixture; no host precondition |
| `N-store-stale` — stale `…-home-manager-files/.ssh/config` | **run** | **run** | `nix store add-path --name '…-home-manager-files'` succeeds. Skip `skip.host.no-nix` if Nix absent. **Not** a generation count |
| `N-hosttemp` — host temp unreachable | **run** (`/tmp`, `$TMPDIR`) | **run** (`/var/folders/…` via `confstr`) | `confstr(_CS_DARWIN_USER_TEMP_DIR)` resolves outside (macOS); `$TMPDIR` set outside (Linux) |
| `N-keychain` — Keychain Mach services unreachable | **`n/a`** — asymmetry: mechanism-native IPC. Linux counterpart needs Landlock **ABI 6** `SCOPE_ABSTRACT_UNIX_SOCKET`, met on 6.17, **inexpressible on `ubuntu-22.04`** | **run**, but see probe | the Mach service resolves outside. **[RUNNER]** — a non-GUI CI session may have no login keychain; standard macOS-CI practice is `security create-keychain`, so the fixture may have to create one. §6.2 |
| `N-fd` — inherited credential fd → **`EBADF`** | **run** | **run** | none. Not a kernel denial; playpen's own boundary (ADR 0016) |
| `N-egress-port` — every port but the proxy's shut | **run** | **run** | proxy binds loopback. macOS retains the loopback residual (asymmetry 1) |
| `N-resolver` — no resolver inside | **run** | **run** | none |
| `N-errno-law` — denial errno in the set, **never `ENOENT`** | **run**; set is `{EACCES, EPERM, EXDEV}` **[SRC, #23]** | **run**; **measured `EPERM`** here **[LOCAL]** | none. This row *is* the soundness check on every other negative |

**Every credential negative runs on both runners, and the reason is ADR 0016's decoy rule** — which
was written for exactly this and is hereby confirmed as the load-bearing decision of the whole
ticket. Without it, eleven of thirteen negatives would be skips on a fresh runner; with it, none is.

### 5.2 Positives

| Row | Hosted Linux | Hosted macOS | Deciding precondition probe |
|---|---|---|---|
| `P-canary` — dynamically-linked OS binary exits 0 under the **bare floor** | **run** | **run** | none. Measured here: `/bin/cat` under a floor without `(allow file-read* (literal "/"))` gives **`rc=134`, empty stderr**, even with `/usr` and `/System` granted; **`(literal "/")` is load-bearing** and with it `rc=0` **[LOCAL]** |
| `P-unshare` — **nested** `CLONE_NEWUSER` + `CLONE_NEWPID\|CLONE_NEWNET` succeeds inside (**strengthened** — §4.2) | **run, conditionally** | **`n/a`** — asymmetry 5, namespaces are Linux's | **behavioural**: the nested sequence succeeds **outside** first. `/proc/sys/kernel/apparmor_restrict_unprivileged_{userns,unconfined}` are read to *name* the skip, not to decide it — the `default_allow` profile makes the sysctl value insufficient. Otherwise `skip.host.userns-restricted` |
| `P-open-bypass` — an `open`-mode bypass arrives **unauthenticated** | **run** | **run** | proxy up |
| `P-manifest` — "the manifest is true": every reachable host reachable, every path at its stated mode, nothing outside | **run** | **run** | outbound egress from the runner for the reachable-host half; else `skip.host.no-egress` |

### 5.3 Refusals — the class that needs no sandbox at all

Refusals happen where playpen **declined to launch**, so they are pure process-exit assertions and
the most portable rows in the suite.

| Row | Hosted Linux | Hosted macOS | Deciding precondition probe |
|---|---|---|---|
| `R-missing-cap` — missing capability → `125` + `code` | **run** | **run** | none |
| `R-incoherent-ws` — incoherent workspace → `125` + `code` | **run** | **run** | none |
| `R-ceiling` — policy over the compiled-profile ceiling → `125` + `code` | **`n/a`** — asymmetry 3, the ceiling is SBPL's | **run** | none, **but assert the `code`, not a path count** — the crossover count is host-specific (§3.2) |
| `R-record` — a run record exists **after** a refusal | **run** | **run** | none |
| `R-code-coverage` — every `refusal.*` code has ≥1 producing row | **run** | **run** | none. A pure registry walk; not even a launch |
| `R-trace-denials` — `--trace-denials` refuses naming *which* precondition is missing | **run, partially** — 1 and 4 probe cleanly, **2 is a permanent red until nono ships the flag**, **3 has no established unprivileged read** (§4.3) | **`n/a`** — asymmetry 4: macOS needs zero preconditions | `landlock ABI >= 7`; nono pin exposes the flag; `audit_enabled`; `id -Gn` ∩ `{systemd-journal, adm, wheel}` |

### 5.4 Liveness — the second suite

| Row | Hosted Linux | Hosted macOS | Why |
|---|---|---|---|
| `L-kind` — real agent binary launched confined, exits 0; plus one task through the proxy | **skip** | **skip** | needs the real agent binaries, real credentials and live network. Not a precondition failure but a **policy** one: ADR 0016 already gave liveness a different cadence and no power to block a playpen change. A hosted runner is the wrong host for it, and `skip.suite.liveness-not-on-ci` should say so rather than the suite quietly having no such row |

### 5.5 The tally

Twenty-two enforcement rows above (twelve negatives, four positives, six refusals); `L-kind` is the
other suite and is excluded.

| | Hosted Linux `ubuntu-24.04` | Hosted macOS `macos-15`/`26` |
|---|---|---|
| **run** | **20 of 22** | **20 of 22** |
| **`n/a`** (named asymmetry) | 2 — `N-keychain`, `R-ceiling` | 2 — `P-unshare`, `R-trace-denials` |
| **conditional** — runs iff its probe passes, else a **named** skip | `P-unshare` (§4.2), `N-store-stale` (Nix present), `P-manifest` (egress) | `N-keychain` (§6.2), `N-store-stale`, `P-manifest` |
| **skip by policy** | `L-kind` | `L-kind` |

The two `n/a`s per platform *are* the asymmetry ledger projected onto the row table — the shared
loopback and the compiled-profile ceiling on macOS, denial visibility, and namespaces on Linux — which
is the operational form of ADR 0016's claim that the suite is what keeps the ledger honest. On
`ubuntu-22.04` add the ABI-6 loss (`N-keychain`'s Linux counterpart becomes inexpressible) and
`R-trace-denials`' first precondition, for no benefit and against a September deprecation date.

---

## 6. What cannot be settled without a runner — and the cheapest experiment for each

Ordered by how much a wrong answer costs.

### 6.1 Does `sandbox_init` work in a Virtualization.framework guest? — **the one that could sink the macOS half**

Nothing in Apple's or GitHub's documentation says either way (§3.3). *Experiment:* one workflow, one
job, ~15 lines, no secrets:

```yaml
runs-on: macos-15
steps:
  - run: sw_vers && uname -m
  - run: |
      printf '(version 1)\n(deny default)\n(allow process-exec*)\n(allow file-read* (literal "/") (subpath "/usr") (subpath "/System") (subpath "/bin"))\n' > f.sb
      /usr/bin/sandbox-exec -f f.sb /bin/cat /etc/hosts   # expect rc=0
      /usr/bin/sandbox-exec -f f.sb /bin/cat "$HOME/.zshrc" || echo "denied as expected: $?"
```

Expect `rc=0` on the first and `Operation not permitted` on the second. That single job settles
`sandbox_init`, the floor's `(literal "/")` requirement and the `EPERM` denial errno at once, and it
is the direct twin of the measurement in §3.1/§5.2. Add a 1014-rule profile to confirm the ceiling
reproduces in the guest.

### 6.2 Is a Keychain Mach service reachable *outside* in a CI session?

The `N-keychain` negative's first half needs the service to resolve before the sandbox is applied,
and a non-GUI runner session may have no login keychain. *Experiment:* in the same job,
`security list-keychains` and `security find-generic-password -s nonexistent` and check the failure
is "not found" rather than "cannot connect"; if the session is bare, `security create-keychain -p x
t.keychain && security list-keychains -s t.keychain` and re-check. Decides whether the fixture must
create a keychain the way every macOS code-signing workflow already does.

### 6.3 Does the *nested* namespace sequence work on `ubuntu-24.04`?

Decides `P-unshare` (§4.2). Reading the sysctls is not enough, because the `default_allow` profile
permits the outer `unshare` and denies what follows — so the experiment must be the behaviour:

```sh
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns \
    /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined
unshare -U true;                    echo "outer: $?"     # expect 0 even when restricted
unshare -U --map-root-user unshare -U -p -n true; echo "nested: $?"  # the one that matters
dmesg | grep -i 'apparmor.*userns'  # expect a DENIED record naming the profile
```

Run on `ubuntu-24.04`, `ubuntu-24.04-arm` and `ubuntu-22.04`. The 22.04 row is the control: its
apparmor 3.x should leave the sysctl unset even though its kernel is Noble-series (§4.2). No build,
no secrets, one job.

### 6.4 What Landlock ABI does the `-azure` kernel actually report?

The `CONFIG_LSM` of the azure flavour is the one unsourced link (§2.2). *Experiment:*
`cat /sys/kernel/security/lsm; dmesg | grep -i landlock` plus a five-line C program calling
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` and printing the return and
`errno`. Run it on `ubuntu-24.04`, `ubuntu-24.04-arm` and `ubuntu-22.04` in one matrix; the 22.04
row is worth having only as the evidence for *not* supporting 22.04.

### 6.5 Is there an unprivileged read path for `audit_enabled`? — **still open, now blocking two tickets**

#23 §7.3 flagged this and it is not closed. It is not a runner question so much as a Linux question
the project keeps deferring, and ADR 0016's rule — a missing precondition produces a **named** skip —
cannot be satisfied for this precondition without it. *Experiment:* on any Linux box, as an
unprivileged user, look for a readable path (`/proc/sys/kernel/*`? an `AUDIT_GET` netlink status
request without `CAP_AUDIT_READ`? `systemctl is-active systemd-journald-audit.socket`, which is
unprivileged-readable and is a *proxy* rather than the fact) and establish which of them is
load-bearing. If no unprivileged read exists, the honest fallback is the behavioural one #23
already floated — emit a known-denial and see whether a record appears — and that is a
*measurement*, not a precondition probe, which changes the row's shape.

### 6.6 The `runner` user's supplementary groups

Decides `R-trace-denials`' fourth precondition. *Experiment:* `id -Gn` on `ubuntu-24.04`. Trivial,
but no manifest I could find states it.

### 6.7 Not investigated

Whether the `-azure` kernel enables `CONFIG_USER_NS` limits beyond AppArmor's
(`user.max_user_namespaces`); whether `ubuntu-slim`'s unprivileged mode has Landlock at all
(GitHub says low-level kernel features are unsupported there, which is reason enough to avoid it,
not a measurement); whether `macos-*-intel` matters at all given `nix-installer` has no
`x86_64-darwin` row; and the interaction between the SBPL bytecode-jump ceiling (§3.2) and the
loader canary, which share the `Abort trap: 6` signature and could in principle be confused by a
report that reads only the exit code.
