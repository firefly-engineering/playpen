# Chromium under nono's seccomp filter on Linux

Research output for [#20](https://github.com/firefly-engineering/playpen/issues/20)
(parent: [#1](https://github.com/firefly-engineering/playpen/issues/1); graduated from
[#11](https://github.com/firefly-engineering/playpen/issues/11); blocks
[#9](https://github.com/firefly-engineering/playpen/issues/9)).

**Question.** Chromium's own sandbox needs **two nested user namespaces**. Landlock does not gate
user namespaces, but nono is playpen's mechanism backend ([ADR 0003](../docs/adr/0003-nono-is-the-mechanism-backend.md))
and is applied **in-process, before `exec`** — so its seccomp filter is inherited by everything the
agent launches, including a browser. Does `clone`/`clone3` with `CLONE_NEWUSER` survive it? Is a
denial loud or silent? Does playpen have any say? Same for `unshare(2)`?

This is a **liveness** question, not a security one.
[ADR 0005](../docs/adr/0005-guest-sandboxes-fail-closed-and-playpen-has-no-browser-mode.md)
established that playpen has no browser mode, never sees the browser's argv, and therefore cannot
pass `--no-sandbox` either way — and with `--no-sandbox` the nested-userns need disappears entirely.
The answer decides whether browser automation (which `omp` does) runs on Linux under playpen at
all, and whether it runs only in the already-degraded form.

**Method.** Primary sources only, and **no experiment was run** — this is a macOS host, so every
Linux claim below is source-derived or documentary. nono was read from a pinned clone; Chromium
from `chromium.googlesource.com/chromium/src/+/main`; kernel behaviour from kernel.org and man7.

**nono pinned at commit `149579a7b0753ee413680169fa937eea82da46a0`**
(`nolabs-ai/nono`, 2026-08-13, *"fix(supervisor): enforce peer-UID check in `SupervisorSocket::bind()` (#1639)"*).
All `crates/nono/...` line numbers below are at that SHA.

Provenance tags, same as [`mechanism-capability-matrix.md`](./mechanism-capability-matrix.md):

| Tag | Meaning |
|---|---|
| **[SRC]** | Read from upstream production source at a pinned revision |
| **[DOC]** | Stated in a vendor/kernel primary source |
| **[INFER]** | My composition of documented rules; not directly verified |
| **[UNVERIFIED]** | Needs a Linux box; see §7 |

---

## 0. Executive summary

1. **`clone`, `clone3` and `unshare` are UNGATED — not denied, not allowed-by-rule, but never
   mentioned.** A repo-wide grep of every `.rs` file in nono for `CLONE_NEWUSER`, `SYS_clone`,
   `clone3`, `SYS_unshare` or `unshare(` returns **zero hits** [SRC]. nono's library gates exactly
   ten syscalls, all of them file-open or socket syscalls. Chromium's userns requirement is
   invisible to it.

2. **Every filter nono builds is default-`SECCOMP_RET_ALLOW`, and the crate contains no kill
   action at all.** The only three actions defined are `SECCOMP_RET_ERRNO`, `SECCOMP_RET_USER_NOTIF`
   and `SECCOMP_RET_ALLOW` (`linux.rs:1527-1529`); `SECCOMP_RET_KILL_PROCESS`,
   `SECCOMP_RET_KILL_THREAD` and `SECCOMP_RET_TRAP` appear **nowhere** in `crates/` [SRC]. So the
   question "kill or `EPERM`" has a third and better answer: **neither** — the syscall is not
   inspected.

3. **playpen has no say, and does not need one.** `SeccompOpts` (`linux.rs:2662-2664`) carries a
   single private field, a four-variant enum about *TCP network* enforcement. There is no syscall
   list, no allow/deny hook, no builder. The filters are private functions returning fixed-size
   arrays. The surface ADR 0003 cuts at (`sandbox` + `capability` + ABI probes) exposes **no way to
   widen or narrow the syscall set** — but since `clone`/`unshare` are already ungated, the
   fixedness is a non-issue for this question.

4. **nono creates no namespaces whatsoever**, so it consumes **zero** of Chromium's nesting budget.
   Unlike bubblewrap (which puts the payload at depth *n+1*), nono only calls `prctl(NO_NEW_PRIVS)`,
   `landlock_restrict_self` and `seccomp(SET_MODE_FILTER)`. The agent runs at exactly the userns
   depth of the invoking shell, with the full 32-level budget below it [SRC + DOC].

5. **The real risk moved: it is Landlock on procfs, not seccomp on `clone`.** Chromium's
   `SetGidAndUidMaps()` **writes** `/proc/self/uid_map`, `/proc/self/gid_map` and
   `/proc/self/setgroups` [SRC, Chromium]. Landlock *does* enforce on procfs regular files —
   nono itself adds `PathBeneath` rules for `/proc` (`capability.rs:1539-1563`) — and per
   [ADR 0006](../docs/adr/0006-the-floor-is-built-in-and-the-toolchain-is-a-coarse-root.md)
   playpen's floor grants **read and execute only, never anything writable**. If `/proc/self` is
   not writable in the capability set, Chromium's userns setup fails at the id-map write rather
   than at the `clone`. **This is the item that needs an experiment**, and it is a *playpen policy*
   question, not a nono one — which means playpen genuinely does have a say, just not where the
   ticket expected.

6. **On Ubuntu 23.10+ the question is largely moot for a different reason.** AppArmor's
   `kernel.apparmor_restrict_unprivileged_userns` denies unprivileged userns creation to any
   binary without an explicit `userns,` permission in its profile [DOC]. Chromium's own fatal
   message names this distro by version. That restriction is applied by the host, above playpen,
   and playpen cannot lift it.

**Bottom line up front: nono's seccomp filter is not the blocker. See §6.**

---

## 1. What nono's seccomp filters actually gate

### 1.1 The complete syscall set

Every syscall number the library's BPF programs compare against, exhaustively
(`crates/nono/src/sandbox/linux.rs`) [SRC]:

| Syscall | Constant | Line | Purpose |
|---|---|---|---|
| `openat` | `SYS_OPENAT` | `1541` (x86_64) / `1547` (aarch64) | FS user-notify (supervisor path) |
| `openat2` | `SYS_OPENAT2` | `1543` / `1549` | same |
| `socket` | `SYS_SOCKET` | `1552` | network family/type/protocol policy |
| `socketpair` | `SYS_SOCKETPAIR` | `1554` | AF_UNIX-only check |
| `io_uring_setup` | `SYS_IO_URING_SETUP` | `1556` | denied (hidden network I/O) |
| `connect` | `SYS_CONNECT` | `1560` | proxy notify |
| `bind` | `SYS_BIND` | `1562` | proxy notify |
| `sendto` | `SYS_SENDTO` | `1567` | AF_UNIX datagram mediation |
| `sendmsg` | `SYS_SENDMSG` | `1569` | same |
| `sendmmsg` | `SYS_SENDMMSG` | `1571` | same |

That is the whole list. Nothing else is compared. `clone`, `clone3`, `unshare`, `setns`,
`ptrace`, `keyctl`, `userfaultfd`, `bpf`, `mount`, `ioctl`/`TIOCSTI` — none appear.

Four filter builders exist, all private:

| Builder | Line | Shape |
|---|---|---|
| `build_seccomp_block_network_filter` | `1861` | 16 insns; deny non-`AF_UNIX` `socket`/`socketpair`, deny `io_uring_setup` |
| `build_seccomp_tcp_only_network_filter` | `1936` | 29 insns; allow `AF_UNIX`, and `AF_INET`/`AF_INET6` only as `SOCK_STREAM` with proto 0 or TCP |
| `build_seccomp_proxy_filter` | `2847` | `connect`/`bind`/`send*` → `SECCOMP_RET_USER_NOTIF` |
| `build_seccomp_af_unix_filter` | `3150` | AF_UNIX socket mediation |

Plus `prepare_seccomp_notify_filter` (`~1746`), which routes `openat`/`openat2` to
`SECCOMP_RET_USER_NOTIF` and, in its own comment, *"allows all other syscalls with
`SECCOMP_RET_ALLOW`"* (`linux.rs:1732-1733`).

### 1.2 Default action is ALLOW, everywhere

Each filter is a short jump table over the syscall number with a terminal
`BPF_RET | BPF_K, k: SECCOMP_RET_ALLOW` on the fall-through path — `linux.rs:1777`, `1893`,
`1923`, `1973`, `2099`, `2971`, `3118`, `3199` [SRC]. There is no default-deny basket. A syscall
the filter does not name is allowed unconditionally.

The one non-obvious wrinkle is the architecture guard (`seccomp_arch_guard`, `linux.rs:1644-1687`),
prepended to every filter by `prepend_seccomp_arch_guard`. It returns `errno_ret` for any
`seccomp_data.arch != NATIVE_AUDIT_ARCH` and for any syscall number carrying `X32_SYSCALL_BIT`.
Its comment states the intent precisely: *"The architecture check closes the compat-ABI path (for
example, i386 `socketcall` from an x86_64 process)."* This is the closest thing to a blanket denial
in the crate, and it fires only on non-native ABIs — a native `x86_64` or `aarch64` `clone` is
untouched.

### 1.3 There is no kill action in the crate

The only actions defined [SRC]:

```rust
const SECCOMP_RET_ERRNO: u32     = 0x0005_0000;   // linux.rs:1527
const SECCOMP_RET_USER_NOTIF: u32= 0x7fc0_0000;   // linux.rs:1528
const SECCOMP_RET_ALLOW: u32     = 0x7fff_0000;   // linux.rs:1529
```

A repo-wide grep across `crates/` and `bindings/` for `SECCOMP_RET_KILL`, `KILL_PROCESS`,
`KILL_THREAD` or `RET_TRAP` returns **zero hits**. The only `SIGSYS` references in the whole repo
are in `nono-cli`'s exit-code *interpreter*
(`crates/nono-cli/src/diagnostic/formatter.rs:1061-1084`), which decodes `128+SIGSYS` from a child
and prints *"SIGSYS typically means a blocked system call"* — i.e. nono anticipates being *nested
under* something that kills, and does not kill itself.

Denials that do occur are `SECCOMP_RET_ERRNO | EPERM` (`linux.rs:1862`, `1937`, `4436`, `4490`) or
`SECCOMP_RET_ERRNO | EACCES` (`linux.rs:2848`). **Every nono seccomp denial is a returned errno, not
a signal** — a syscall failure the caller sees, never a process death with no message. That is
squarely on the right side of playpen's failure-UX law, and it is a property of the crate rather
than of configuration.

### 1.4 What nono does to the process, in full

The library's apply path performs exactly three privileged operations [SRC]:

- `prctl(PR_SET_NO_NEW_PRIVS, 1)` — `linux.rs:205` (Landlock path), `linux.rs:2130` (seccomp path)
- `landlock_create_ruleset` / `landlock_add_rule` / `landlock_restrict_self` — `linux.rs:149`,
  `167`, `189`, `214`
- `seccomp(SECCOMP_SET_MODE_FILTER, …)` — `linux.rs:1817`, `1831`, `2137`

**No `clone`, no `unshare`, no `setns`, no `mount`, no `pivot_root`, no `chroot`.** nono is not a
namespace tool. This is the structural difference from bubblewrap that matters here: §3.6 of the
capability matrix reasoned about Chromium needing depth *n+3* under bwrap's *n+1*; under nono the
payload is still at *n*.

One consequence of `NO_NEW_PRIVS` carries over unchanged: **Chromium's setuid-sandbox fallback is
dead** inside playpen, exactly as it is inside bwrap [DOC]. Chromium therefore has the namespace
sandbox or nothing.

---

## 2. What Chromium actually requires at startup

From `sandbox/linux/services/credentials.cc` and
`content/browser/zygote_host/zygote_host_impl_linux.cc` (`main`) [SRC, Chromium]:

| Step | Mechanism | Gated by nono seccomp? | Gated by Landlock? |
|---|---|---|---|
| `CanCreateProcessInNewUserNS()` probe | `clone(CLONE_NEWUSER \| SIGCHLD)`, then a nested `unshare(CLONE_NEWUSER)` in the child | **No** | No |
| `MoveToNewUserNS()` | `unshare(CLONE_NEWUSER)` | **No** | No |
| `NamespaceSandbox::LaunchProcess` | `clone(CLONE_NEWUSER \| CLONE_NEWPID \| CLONE_NEWNET)` | **No** | No |
| `SetGidAndUidMaps()` | **writes** `/proc/self/uid_map`, `/proc/self/gid_map`, `/proc/self/setgroups` | No | **YES — see §3** |
| `DropFileSystemAccess()` | `chroot()` into `/proc/self/fdinfo/` | No | `chroot` is not restricted by Landlock [DOC]; the `open` of `/proc/self/fdinfo` is |
| renderer seccomp policy | Chromium installs **its own** filter on top | stacks; see §5 | — |

**Confirmed: two nested user namespaces.** The probe alone does `clone(CLONE_NEWUSER)` followed by
a second `unshare(CLONE_NEWUSER)` inside the child, and the runtime path re-enters via
`MoveToNewUserNS()` after `LaunchProcess`'s `CLONE_NEWUSER`. The kernel's nesting limit is 32 and
`max_user_namespaces` is unbounded in descendant namespaces [DOC], so depth is not the constraint.

**The failure is loud, and it is a crash rather than a hang.** When neither the namespace sandbox
nor the SUID sandbox is available, `ZygoteHostImpl` does [SRC, Chromium]:

```cpp
LOG(FATAL)
    << "No usable sandbox! If you are running on Ubuntu 23.10+ or another "
       "Linux distro that has disabled unprivileged user namespaces with "
       "AppArmor, see …  Otherwise see … for more information on developing "
       "with the (older) SUID sandbox. If you want to live dangerously and "
       "need an immediate workaround, you can try using --no-sandbox.";
```

`LOG(FATAL)` aborts the browser process immediately with a printed message. Puppeteer surfaces
this as `Failed to launch chrome! No usable sandbox`. There is a separate, adjacent hard exit for
running as uid 0 without `--no-sandbox` (`GetRESIDs(...) || uid == 0` → `LOG(ERROR)` and abort) —
relevant only if playpen ever runs the guest as root, which it does not.

**So the failure-UX answer, if a denial ever did happen: loud, immediate, self-diagnosing, and
naming its own workaround.** Chromium does not hang on a missing userns.

---

## 3. The blocker that actually exists: Landlock on `/proc/self/uid_map`

Landlock's documented un-restrictable set is narrow [DOC, `landlock.rst`]:

> files that do not come from a user-visible filesystem (e.g. pipe, socket), but can still be
> accessed through `/proc/<pid>/fd/*`, cannot currently be explicitly restricted. Likewise, some
> special kernel filesystems such as nsfs, which can be accessed through `/proc/<pid>/ns/*`,
> cannot currently be explicitly restricted.

`/proc/self/uid_map` is neither of those. It is a procfs regular file with an inode, and by the
structure of that exemption list it **is** restrictable [INFER]. nono's own code settles the point
independently: `CapabilitySet::widen_procfs_self_to_proc` (`capability.rs:1539-1563`) exists
precisely because Landlock rules on `/proc/<pid>` bind to an inode, and a grandchild's `/proc/self`
resolves elsewhere — a problem that only arises if procfs is enforced [SRC].

Two facts then collide:

- nono's procfs widening is explicitly **read-only**: *"Only applies to READ capabilities at the
  `/proc/self` level (not subdirectories like `/proc/self/fd` which may have write access)"*
  (`capability.rs:1548-1549`) [SRC].
- ADR 0006's floor grants *"read and execute only, only under paths the OS owns … never anything
  writable"*.

**Therefore, unless playpen's resolved capability set carries an explicit write grant covering
`/proc/self/uid_map`, `/proc/self/gid_map` and `/proc/self/setgroups`, Chromium's `SetGidAndUidMaps()`
should fail with `EACCES` from Landlock — *after* a successful `clone(CLONE_NEWUSER)`.** [INFER,
UNVERIFIED]

That failure mode is different from, and worse than, the one the ticket anticipated. It happens
inside the cloned child, after the namespace already exists. Chromium's
`CanCreateProcessInNewUserNS()` checks the child's exit status, so a failed id-map write should
still surface as the probe returning false and the same `LOG(FATAL) << "No usable sandbox!"` —
loud, not silent [INFER]. But the diagnostic will point the operator at *user namespaces*, when the
actual denial was a *filesystem write*. **That is a failure-UX hazard worth recording even though
the outcome is fail-loud.**

Note also that ADR 0006's write-nothing-in-the-floor rule is not obviously wrong here. A writable
`/proc/self` grant is a real widening, and the honest framing is: **playpen would have to choose to
grant it, and granting it is a policy decision with its own cost**, not an oversight to fix.

---

## 4. Configurability through the ADR 0003 surface

ADR 0003 cuts the dependency at `sandbox` + `capability` + ABI probes. Within that surface [SRC]:

```rust
pub struct SeccompOpts {                    // linux.rs:2662
    tcp_network: SeccompTcpNetwork,         //   ← single, private field
}
enum SeccompTcpNetwork { Fallback, Baseline, External, … }   // linux.rs:2719
```

Four constructors, all zero-argument: `network_fallback()` (`2670`), `network_baseline()` (`2684`),
`external_tcp()` (`2693`), `preinstalled_tcp_filter()` (`2706`). `Default` is `network_fallback()`
(`2713-2717`).

The public `Sandbox` methods that take it (`sandbox/mod.rs:104`, `114`, `138`, `148`, `158`) accept
`(&CapabilitySet, [&DetectedAbi,] SeccompOpts)` and nothing else. **The filter programs themselves
are private `fn`s returning `[SockFilterInsn; N]` fixed-size arrays.** There is no trait, no
callback, no syscall vector.

**Answer to ticket Q3: the seccomp filter is fixed, not configurable, through the crate surface —
and this is fine.** playpen cannot add a `clone` denial even if it wanted one, and cannot
accidentally inherit one from a nono version bump without that bump changing the hardcoded filter
arrays, which the ADR 0003 enforcement suite would need a new negative to catch. Worth adding: the
suite currently asserts *denials*; nothing asserts the *absence* of a denial. A future nono that
added `clone(CLONE_NEWUSER)` blocking would be a silent liveness regression for browser automation.

Also within reach but out of scope for playpen: `nono-cli`'s supervisor is structurally excluded by
ADR 0003, which is convenient here — its `peer_in_same_user_namespace()` check
(`crates/nono/src/supervisor/socket.rs:495-506`) compares `/proc/self/ns/user` against the peer's
and would reject a connection from any process Chromium had moved into a nested userns [SRC]. That
is a genuine interaction hazard for the seccomp-notify proxy path, and playpen avoids it by not
using the CLI's supervisor.

---

## 5. Filter stacking with Chromium's own seccomp policy

Chromium installs its own seccomp-bpf baseline in renderers, on top of whatever it inherited.
seccomp filters accumulate and the **most severe** action across all filters wins [DOC]:

```
KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > USER_NOTIF > TRACE > ALLOW
```

Consequences [INFER, from documented precedence + §1]:

- nono's `ERRNO(EPERM)` on `socket()` **overrides** Chromium's `ALLOW`. Under
  `NetworkMode::Blocked` (block-all filter, `linux.rs:1861`) a browser inside playpen gets `EPERM`
  on every non-`AF_UNIX` socket. That is the intended egress policy
  ([ADR 0004](../docs/adr/0004-egress-policy-lives-in-a-sibling-proxy.md)), not a bug — but it means
  the browser is reachable only through the sibling proxy.
- Under the TCP-only baseline (`linux.rs:1936`), `AF_UNIX` is allowed, `AF_INET`/`AF_INET6` are
  allowed **only** as `SOCK_STREAM` with protocol 0 or `IPPROTO_TCP`, and everything else is
  `EPERM`. Named casualties for a browser: **QUIC/HTTP3 (UDP) is dead**, **`AF_NETLINK` is dead**
  (so `NetworkChangeNotifierLinux` loses its socket), **mDNS is dead**, and `io_uring_setup` is
  dead. Chromium is expected to degrade to TCP rather than fail — **[UNVERIFIED]**, and it is the
  second most likely source of confusing behaviour after §3.
- `socketpair(AF_UNIX, …)` — which the zygote and the browser↔renderer IPC depend on — is routed
  through the same family check and **allowed** in both filters (`linux.rs:1963-1966`, insn 19-20
  of the TCP-only program) [SRC]. Good: this was a plausible silent killer and it is not one.
- Chromium's own renderer filter is stricter and uses `TRAP`, which outranks all of nono's actions,
  so nono cannot *weaken* Chromium's renderer confinement.

---

## 6. Interaction with distro-level userns restrictions

**Ubuntu 23.10+ is the case that makes the whole question moot on the most common distro** [DOC].
Ubuntu ships `kernel.apparmor_restrict_unprivileged_userns`, an AppArmor-mediated gate where
*"AppArmor policy is used to selectively control access to unprivileged user namespaces on a per
applications basis, and then deny access to all other applications."* A binary needs an explicit
`userns,` permission in an AppArmor profile. Kernel support landed in 6.1; the AppArmor patches in
Ubuntu's 6.2 Lunar kernel.

Chromium's own fatal message names this by version — *"If you are running on Ubuntu 23.10+ or
another Linux distro that has disabled unprivileged user namespaces with AppArmor"* — which is as
strong an upstream acknowledgement as exists.

Two related knobs, deliberately kept distinct:

| Knob | Where it exists | Relevance to playpen |
|---|---|---|
| `kernel.apparmor_restrict_unprivileged_userns` | Ubuntu 23.10+ (AppArmor) | **Real.** Host-level, above playpen, playpen cannot lift it |
| `kernel.unprivileged_userns_clone` | Debian/Ubuntu **downstream patch only** | Not present on a vanilla kernel |
| `user.max_user_namespaces` | vanilla sysctl | Red Hat's documented mitigation for CVE-2023-32233 is to set it to 0 |

The capability-matrix's NixOS finding stands and is worth repeating because it is a common trap:
`security.unprivilegedUsernsClone` on NixOS is **inert** — it sets the Debian downstream sysctl,
which does not exist on a vanilla kernel, and its docstring is misleading. `security.allowUserNamespaces`
defaults **true** on NixOS, and Nix's own build sandbox structurally depends on it. **On the
reference NixOS target, unprivileged userns is available; on an Ubuntu 24.04 CI runner it very
likely is not.**

This is a host fact, and it interacts with playpen's refusal law in an awkward way: playpen has no
browser mode (ADR 0005), so it has nothing to probe and nothing to refuse *on*. The restriction
simply makes the agent's browser tool fail at use time, with Chromium's own message.

---

## 7. Bottom line

**Chromium's user-namespace requirement passes nono's seccomp filter untouched.** [SRC]

Answering the ticket's four questions directly:

1. **`clone` / `clone3` with `CLONE_NEWUSER`: UNGATED.** Not permitted-by-rule and not denied —
   the syscall numbers appear nowhere in nono's source. Every filter is a ten-syscall jump table
   over file-open and socket syscalls with a default `SECCOMP_RET_ALLOW` fall-through.

2. **Denial question is moot, and if it ever became live the answer is `EPERM`, never a kill.**
   nono's crate defines no `SECCOMP_RET_KILL_*` and no `SECCOMP_RET_TRAP`. It cannot produce a
   `SIGSYS`. Separately, Chromium's own response to an unusable sandbox is `LOG(FATAL)` with a
   printed, self-diagnosing message — **loud and immediate, never a hang**. Both halves of the
   failure-UX law are satisfied by accident rather than by design, which is worth knowing when
   pinning a nono version.

3. **playpen has no say over the filter, and does not need one.** `SeccompOpts` exposes a single
   private field with four zero-argument constructors, all about TCP network enforcement; the BPF
   programs are private fixed-size arrays. The seccomp surface is fixed. **playpen's actual lever is
   elsewhere: the Landlock capability set** (§3).

4. **`unshare(2)`: identical — ungated.** Same grep, same absence. nono itself never calls it
   either, so it consumes none of Chromium's nesting budget: unlike bubblewrap, nono creates **no
   namespaces at all**, and the agent runs at the invoking shell's userns depth with the full
   32-level budget below it.

**But the liveness question is not thereby settled "yes".** Two things stand between Chromium and a
working sandbox under playpen on Linux, and neither is the one the ticket named:

- **Landlock write access to `/proc/self/{uid,gid}_map` and `/proc/self/setgroups`** — required by
  `SetGidAndUidMaps()`, procfs is Landlock-enforced, and ADR 0006's floor is deliberately
  read-only. Predicted `EACCES` inside the already-cloned child [INFER, UNVERIFIED]. This is a
  playpen policy decision with a real cost, not an oversight.
- **Ubuntu 23.10+ / AppArmor `userns` restriction** — a host fact above playpen, which Chromium's
  own fatal message names by distro version. Where it applies, nothing playpen does matters.

And a third, lower-severity: **the TCP-only baseline filter kills UDP and `AF_NETLINK`**, so QUIC,
mDNS and network-change notification are unavailable to a browser inside playpen even when its
sandbox comes up.

**Practical reading for [#9](https://github.com/firefly-engineering/playpen/issues/9):** the
"already-degraded `--no-sandbox` form" is *not* forced by nono's seccomp filter. It may still be
forced by procfs write policy or by the host distro. Under ADR 0005 playpen cannot pass
`--no-sandbox` anyway, so in practice: on a permissive kernel with a `/proc/self` write grant,
Chromium's own sandbox should come up and the ADR 0005 residual (untrusted web content at full
workspace privilege) does **not** apply on Linux; without either, the browser tool fails loudly and
the agent's browser automation is simply unavailable — which is a liveness loss, not a boundary
loss.

---

## 8. What remains unverified, and the experiment that settles it

Everything in §1, §2, §4 is source-derived from pinned revisions and I consider it settled.
Everything below needs a Linux box. **No experiment was run for this document.**

| # | Claim | Status |
|---|---|---|
| 1 | Chromium's namespace sandbox comes up under a live nono sandbox at all | **[UNVERIFIED]** — the whole point |
| 2 | Landlock denies `open("/proc/self/uid_map", O_WRONLY)` absent a write grant | **[INFER]** from §3; the highest-value single check |
| 3 | A read-only `/proc` grant is enough for everything *else* Chromium reads there | **[UNVERIFIED]** |
| 4 | Chromium degrades rather than dies when `AF_NETLINK` and UDP return `EPERM` | **[UNVERIFIED]** |
| 5 | The `EACCES` from (2) surfaces as `LOG(FATAL) "No usable sandbox!"` rather than a hang | **[INFER]** |
| 6 | `widen_procfs_self_to_proc` covers Chromium's *grandchild* zygote processes | **[UNVERIFIED]** |

### The experiment

On a NixOS or Debian VM with a Landlock-capable kernel (≥6.7 for ABI 4), unprivileged userns
enabled, and Chromium installed:

**A — isolate the syscall question (5 minutes, settles Q1/Q4 empirically).**
A ~30-line Rust binary linking `nono` at the pinned SHA: build a `CapabilitySet` with a read root
over `/nix/store` (or `/usr`), a write root over a scratch dir, `SeccompOpts::network_baseline()`,
call `Sandbox::apply_seccomp(...)`, then `unshare(CLONE_NEWUSER)` and immediately
`clone(CLONE_NEWUSER|SIGCHLD)` in the child. Expect both to succeed. Print `errno` on failure.
This is the direct falsification test for the whole document and needs no browser.

**B — the procfs write (settles the actual blocker).**
Same harness, then in the cloned child: `open("/proc/self/setgroups", O_WRONLY)` and
`open("/proc/self/uid_map", O_WRONLY)`. Run it twice — once with `/proc/self` granted **read**,
once granted **write**. If the read-only run returns `EACCES` and the write run succeeds, §3 is
confirmed and ADR 0006's floor needs an explicit, documented exception (or an explicit decision
not to make one).

**C — the real thing (settles everything).**
Under the same sandbox, launch `chromium --headless=new --dump-dom about:blank` **without**
`--no-sandbox`, capturing stderr. Three distinguishable outcomes:
- prints the DOM → Chromium's sandbox works under playpen on Linux; the ADR 0005 residual is
  macOS-only;
- `No usable sandbox!` → confirm *why* by `strace -f -e trace=clone,clone3,unshare,openat` and
  check whether the first failure is a `clone` (contradicts this document) or an `openat` on
  `/proc/self/*` (confirms §3);
- anything else → new finding.

Then repeat C on an Ubuntu 24.04 host to characterise §6 as the operator will encounter it.

**D — the regression guard (cheap, and worth adding regardless).**
ADR 0003's enforcement suite asserts negatives. Add one **positive**: assert from inside a live
nono sandbox that `unshare(CLONE_NEWUSER)` succeeds. It is a two-line test that converts a future
silent liveness regression — a nono version that starts blocking `clone` — into a failing version
bump. This is the only durable output of this research that does not depend on running the
experiment first.
