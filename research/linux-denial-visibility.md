# Linux denial visibility — can the kernel surface denials out-of-band?

Research output for [#23](https://github.com/firefly-engineering/playpen/issues/23)
(parent: [#1](https://github.com/firefly-engineering/playpen/issues/1)).

**Question.** macOS gives playpen a denial log for free: the kernel writes every Seatbelt
denial to the unified log with process, pid, operation and full path, readable with no live
process on playpen's side. Does Linux have an equivalent, and can playpen reach it through
the `nono` crate surface ADR 0003 declared narrow?

**Method.** Primary sources only: the Linux kernel tree at `torvalds/linux@master` (fetched
2026-08-16) — `Documentation/userspace-api/landlock.rst`,
`Documentation/admin-guide/LSM/landlock.rst`, `Documentation/userspace-api/seccomp_filter.rst`,
`include/uapi/linux/landlock.h`, `security/landlock/{audit.c,fs.c,syscalls.c,domain.h,cred.c}`,
`kernel/{audit.c,seccomp.c}`, `samples/landlock/sandboxer.c` — plus man7.org, systemd
documentation, and **nono's own source**, read at commit
`149579a7b0753ee413680169fa937eea82da46a0` (2026-08-13, `nolabs-ai/nono`, crate `nono` v0.4.5
of the `landlock` dependency per `Cargo.lock`).

**This is a macOS host. No Linux box was available.** Every Linux claim here is documentary or
source-read; none was executed. Section 7 lists the experiments that would settle each open
point. The macOS facts quoted for contrast are the ones already verified on this host and
recorded in ADR 0007 and `mechanism-capability-matrix.md`.

Provenance tags, same as `mechanism-capability-matrix.md`:

| Tag | Meaning |
|---|---|
| **[DOC]** | Stated in a kernel/vendor primary source |
| **[SRC]** | Read from upstream production source (kernel C, or nono's Rust) |
| **[INFER]** | My composition of documented rules; not directly verified |
| **[LOCAL]** | Verified by experiment on this macOS host (macOS facts only) |

---

## 0. Executive summary

**Linux has the mechanism, and playpen cannot reach it.** That is the whole finding, and the
two halves have to be stated separately because they fail for different reasons.

1. **The kernel-side capability exists and is genuinely comparable to macOS.** Landlock ABI 7
   (**Linux 6.15**) emits an `AUDIT_LANDLOCK_ACCESS` record per denial containing
   **`path=`, `dev=`, `ino=`, `blockers=` (the specific missing right, e.g. `fs.write_file`)**,
   correlated in the same audit event with a `SYSCALL` record carrying `pid`, `comm`, and the
   errno (`exit=-13`). That is *richer* than the Seatbelt line, not poorer. **[DOC/SRC]**

2. **It is off for exec'd children by default, and nono never turns it on.** The kernel's
   default is: log denials from the thread that sandboxed itself *and only while it keeps
   running the same executable code*. After `execve(2)` the denial is silently not logged
   unless `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` was passed. **[SRC, `security/landlock/audit.c:604-613`]**
   playpen's architecture (ADR 0003: apply to playpen's own process, then `exec` the agent) is
   *exactly* the shape that lands on the wrong side of that default. nono calls
   `landlock_restrict_self(fd, 0)` in its raw path **[SRC, `crates/nono/src/sandbox/linux.rs:214`]**
   and bare `.restrict_self()` in its crate path **[SRC, `linux.rs:1274`, `1400`]**, and never
   calls the `landlock` crate's `log_new_exec()` builder. **Every denial by the agent is
   therefore unlogged.**

3. **nono's Landlock ABI probe tops out at V6.** `ABI_PROBE_ORDER: [ABI; 6] = [V6, V5, V4, V3,
   V2, V1]` **[SRC, `linux.rs:378`]** — nono cannot even *report* a 6.15+ kernel as ABI 7, let
   alone use it. The `landlock` crate at the pinned 0.4.5 does know `V7 = Linux 6.15` and does
   expose `log_new_exec(bool)`; the ceiling is nono's, not the crate's. **[DOC/SRC]**

4. **The errno law survives, but not by the errno ADR 0007 guessed.** A Landlock filesystem
   denial returns **`EACCES` (13)**, not `EPERM` — `security/landlock/fs.c` returns `-EACCES`
   from every access hook, `-EXDEV` for a `REFER`-only reparenting failure, and `-EPERM` from
   the mount-topology hooks. **It never returns `ENOENT` for a denial. [SRC]** nono's seccomp
   filters return `SECCOMP_RET_ERRNO | EPERM` (network fallbacks) and `SECCOMP_RET_ERRNO |
   EACCES` (proxy mode) **[SRC]**. So ADR 0007's law holds on Linux — with **two** denial
   errnos to assert, not one, and a third (`EXDEV`) on rename/link.

5. **The asymmetry is real and it points the other way from the first three.** The loopback
   residual, the Seatbelt deprecation clock and the compiled-profile ceiling all favour Linux.
   **Denial visibility favours macOS**, and it does so in nono's *own* surface: nono exposes
   `CapabilitySet::set_seatbelt_debug_deny()`, which emits `(debug deny)` into the SBPL profile
   **[SRC, `capability.rs:1382`, `macos.rs:550`]**, and ships **no Linux counterpart at all**.
   The knob playpen would want exists on exactly one platform.

**Bottom-line answer to the flag question:** `--trace-denials` must be **refused on Linux
against nono as it stands today**, and the refusal is a nono-surface fact, not a kernel fact —
which means it is fixable upstream by a one-line change, and is worth a nono issue rather than
a permanent platform law.

---

## 1. Landlock audit — did it land, in which kernel, and what does a record contain?

### 1.1 Version

`LANDLOCK_RESTRICT_SELF_LOG_*` landed with **Landlock ABI 7 = Linux 6.15**, released
2025-05-25, in Mickaël Salaün's *Landlock audit support* series **[DOC]**. The crate-side
mapping is confirmed by `landlock` 0.4.5's own `enum ABI` docs: *"Seventh Landlock ABI,
introduced with Linux 6.15."*

Corrected/extended ABI table (supersedes the row in `mechanism-capability-matrix.md` §3.1.1 only
in that ABI 7 is now dated):

| ABI | Kernel | Relevant addition |
|---|---|---|
| 6 | 6.12 | `SCOPE_ABSTRACT_UNIX_SOCKET`, `SCOPE_SIGNAL` — **nono's ceiling** |
| **7** | **6.15** | **`RESTRICT_SELF_LOG_SAME_EXEC_OFF` / `LOG_NEW_EXEC_ON` / `LOG_SUBDOMAINS_OFF`** |
| 8 | 7.0 | `RESTRICT_SELF_TSYNC` |
| 10 | — | `LANDLOCK_ADD_RULE_QUIET` (per-object log suppression) |

### 1.2 What a record contains — it names the path

`Documentation/admin-guide/LSM/landlock.rst` defines two record types and gives worked
examples. Verbatim **[DOC]**:

```
type=LANDLOCK_ACCESS msg=audit(1729738800.221:33): domain=1a6fdc679 blockers=fs.write_file path="/dev/tty" dev="devtmpfs" ino=9
type=LANDLOCK_DOMAIN msg=audit(1729738800.221:33): domain=1a6fdc679 status=allocated mode=enforcing pid=289 uid=0 exe="/root/sandboxer" comm="sandboxer"
type=SYSCALL msg=audit(1729738800.221:33): arch=c000003e syscall=257 success=no exit=-13 [...] ppid=272 pid=289 auid=0 uid=0 gid=0 [...] comm="sh" [...]
type=PROCTITLE msg=audit(1729738800.221:33): proctitle=7368002D63006563686F203E202F6574632F706173737764
type=LANDLOCK_ACCESS msg=audit(1729738800.221:34): domain=1a6fdc679 blockers=fs.write_file path="/etc/passwd" dev="vda2" ino=143821
[...]
type=LANDLOCK_DOMAIN msg=audit(1729738800.261:35): domain=1a6fdc679 status=deallocated denials=2
```

Field-by-field against the macOS line ADR 0007 leans on
(`Sandbox: cat(47295) deny(1) file-read-data /private/tmp/pp-secret/f.txt`):

| macOS unified log | Landlock audit | Notes |
|---|---|---|
| process name `cat` | `comm="sh"` on the `SYSCALL` record | equal |
| pid `47295` | `pid=289` on the `SYSCALL` record | equal |
| operation `file-read-data` | `blockers=fs.write_file` | **finer** — names the exact missing right, and comma-joins when several are missing |
| full path | `path="/etc/passwd"` **+ `dev=` + `ino=`** | **richer** — inode identity, not just a string |
| — | `exit=-13` on `SYSCALL` | **the in-band errno is in the out-of-band record**, which macOS does not give |
| — | `domain=`, `exe=`, `mode=enforcing` | **policy provenance** — which ruleset denied it |
| — | `denials=N` on the `deallocated` record | **a total denial count, whether or not each was logged** |

The `blockers` vocabulary is a closed set: `fs.*` (execute, read_file, write_file, read_dir,
remove_*, make_*, refer, truncate, ioctl_dev), `net.*` (bind_tcp, connect_tcp, bind_udp,
connect_send_udp), `scope.*` (abstract_unix_socket, signal) **[DOC]**. That is a
machine-parseable vocabulary of exactly the shape ADR 0007's `code` discipline wants.

**Verdict on capability: Landlock's record is strictly better than Seatbelt's.** Nothing about
the *content* is the problem.

### 1.3 The default that kills it — logging is off after `execve`

`include/uapi/linux/landlock.h`, verbatim **[SRC]**:

> By default, denied accesses originating from programs that sandbox themselves are logged via
> the audit subsystem. Such events typically indicate unexpected behavior, such as bugs or
> exploitation attempts. However, to avoid excessive logging, access requests denied by a domain
> not created by the originating program are not logged by default. The rationale is that
> programs should know their own behavior, but not necessarily the behavior of other programs.

and on the flag that reverses it:

> **%LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON** — Enables logging of denied accesses after an
> `execve(2)` call, providing visibility into unauthorized access attempts by newly executed
> programs within the created Landlock domain.

The enforcement, verbatim from `security/landlock/audit.c` **[SRC]**:

```c
	if (!audit_enabled)
		return;

	/* Checks if the current exec was restricting itself. */
	if (subject->domain_exec & BIT(youngest_layer)) {
		/* Ignores denials for the same execution. */
		if (!youngest_denied->log_same_exec)
			return;
	} else {
		/* Ignores denials after a new execution. */
		if (!youngest_denied->log_new_exec)
			return;
	}
```

`security/landlock/cred.c` clears `domain_exec` in `hook_bprm_creds_for_exec()`, so the
`else` branch is the one every post-`exec` denial takes **[SRC]**.

**This is precisely playpen's shape.** ADR 0003: nono is *"applied to playpen's own process
before it `exec`s the agent."* So every denial that matters — every one the *agent* provokes —
falls into the `log_new_exec` branch and is dropped unless the flag was set at
`landlock_restrict_self()` time.

The kernel's own sample confirms this is the expected experience rather than my inference: both
worked examples in the admin guide are run as `LL_FORCE_LOG=1 ./sandboxer …`, and
`samples/landlock/sandboxer.c` translates that env var into exactly
`set_restrict_flags |= LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` **[SRC]**. Upstream ships an
explicit force-log escape hatch because without it, a sandboxer-then-exec tool sees nothing.

### 1.4 What privilege does a *reader* need?

Three distinct paths, with genuinely different answers. **This was the point the ticket
flagged as potentially decisive, and it turns out not to be the blocker.**

| Path | Reader privilege | Assessment |
|---|---|---|
| `AUDIT_NLGRP_READLOG` netlink multicast, direct | **`CAP_AUDIT_READ`** (since Linux 3.16) **[DOC, `capabilities(7)`]** | Not usable — playpen would need a capability the operator does not have |
| `/var/log/audit/audit.log` via `auditd`/`ausearch` | root (file is `0600 root:root`) | Not usable |
| **`journalctl`** — `systemd-journald-audit.socket` holds the multicast socket, journald has `CAP_AUDIT_READ`, records land in the system journal | **membership in `systemd-journal`, `adm`, or `wheel`** — `journalctl(1)`: *"Members of the groups 'systemd-journal', 'adm', and 'wheel' can read all journal files."* **[DOC]** | **Usable.** On a normal single-operator workstation the operator is in `wheel`. |

So the "trace requires root" fear does **not** hold on a systemd host. The realistic reader
command is `journalctl _TRANSPORT=audit` / `journalctl -k`, filtered by pid or by the `domain=`
id — after the fact, with **no live process on playpen's side**, exactly the property that made
the macOS story cheap. **[INFER — composition of documented rules; see §7.]**

### 1.5 The other gate: `audit_enabled`

`kernel/audit.c` initialises `audit_enabled = AUDIT_OFF` and `audit_default = AUDIT_OFF`
**[SRC]**, and `landlock_log_denial()` returns early on `!audit_enabled` (§1.3). So a kernel
booted without `audit=1` and without anything enabling audit at runtime produces **no Landlock
records at all**, regardless of flags.

Two mitigating facts:

- **systemd turns it on.** `journald.conf`'s `Audit=` *"defaults to 'yes' in the default journal
  namespace"*, and *"if enabled systemd-journald will turn on kernel auditing on start-up"*
  **[DOC]**. On a stock systemd host, `audit_enabled` is 1 without operator action.
- **NixOS's own module does not.** `nixos/modules/security/audit.nix` has
  `security.audit.enable` defaulting to **`false`** **[SRC]**. That module governs `auditctl`
  rule loading, not journald's start-up behaviour, so the two are not in conflict — but it means
  playpen cannot cite the NixOS option as evidence that audit is on. **Unverified which wins on
  a real NixOS VM (§7).**

Note the belt-and-braces fallback in `kernel/audit.c`: when no `auditd` is connected,
`kauditd_hold_skb()` calls `kauditd_printk_skb()`, which `pr_notice()`s the record into the
kernel ring buffer **[SRC]** — so records survive to `dmesg`/`journalctl -k` even without
`auditd`. But it is `printk_ratelimit()`-gated and truncated to the printk buffer, so it is a
**lossy** channel, and silent loss is precisely the failure mode ADR 0007 refuses to ship.

---

## 2. Landlock errno — does a denial ever return `ENOENT`?

Read directly from `security/landlock/fs.c` **[SRC]**:

| Situation | Return | Note |
|---|---|---|
| Filesystem access denied by the ruleset (the common case: `open`, `openat`, `execve`, dir ops) | **`-EACCES`** | five distinct `return -EACCES;` sites in the access hooks |
| Same-directory rename/link denied | `-EACCES` | `current_check_refer_path()` |
| Reparenting rename/link that would grant new rights | **`-EXDEV`** | *"LANDLOCK_ACCESS_FS_REFER alone must return -EXDEV"* |
| `mount`, `move_mount`, `umount`, `remount`, `pivot_root` while landlocked | **`-EPERM`** | unconditional for any landlocked task |
| `landlock_add_rule(LANDLOCK_RULE_PATH_BENEATH)` UNIX-socket resolve denial | `-EACCES` | ABI 9 `FS_RESOLVE_UNIX` |

The documented rationale for the `EACCES`-over-`EXDEV` precedence is in the source comment
**[SRC]**: *"Prioritizing EACCES over EXDEV enables [...]"* — i.e. the kernel deliberately
reports the *policy* error in preference to the *topology* error.

**Does it ever return `ENOENT`?** There are exactly two `return -ENOENT;` sites in `fs.c`, both
inside `current_check_refer_path()` and both guarded by `d_is_negative(...)` **[SRC]**:

```c
	if (unlikely(d_is_negative(old_dentry)))
		return -ENOENT;
	if (exchange) {
		if (unlikely(d_is_negative(new_dentry)))
			return -ENOENT;
	}
```

A negative dentry means the path **genuinely does not exist**. That is Landlock reporting
*absence as absence*, before any policy evaluation — it is the law working, not breaking.

> **ADR 0007's law "a denial is never `ENOENT`" holds on Linux under Landlock.** [SRC]

**But the enforcement suite must be written against three errnos, not one.** ADR 0007's text
says *"Landlock's `EACCES` … [is] not [verified]"* and treats it as the single expected value.
The assertion should be: a denial returns one of `{EACCES, EPERM, EXDEV}` and never `ENOENT`,
with `EACCES` the expected value for a plain read/write denial and `EPERM` the expected value
for a seccomp-blocked syscall (§3). Stating it as a set is also what makes it survive nono
switching a filter from `EPERM` to `EACCES`, which it has already done once per §3.

**Caution — the metadata gap interacts with this.** `mechanism-capability-matrix.md` §3.1.2
records that Landlock cannot restrict `stat`, `access`, `chdir`. So under Landlock alone a
denied-but-present path is *distinguishable* from an absent one — good. Under **bubblewrap**,
an unbound path is genuinely absent and `stat` returns `ENOENT` **by construction**. If playpen
ever composes bwrap under nono, "denied" and "absent" collapse for exactly those paths. That is
not a Landlock defect and not in scope here, but it is the one composition that would break the
law, and the enforcement suite should pin the layer it is asserting against.

---

## 3. seccomp — what nono's filter actually returns

Read from `crates/nono/src/sandbox/linux.rs` at `149579a7b` **[SRC]**. Only four return values
appear anywhere in nono:

```rust
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
```

| Filter | Action on block | Site |
|---|---|---|
| `build_seccomp_block_network_filter` (fallback when Landlock lacks `AccessNet`) | `SECCOMP_RET_ERRNO \| EPERM` | `linux.rs:1862` |
| `build_seccomp_tcp_only_network_filter` (static baseline alongside Landlock TCP rules) | `SECCOMP_RET_ERRNO \| EPERM` | `linux.rs:1937` |
| `build_seccomp_proxy_filter` (proxy-only network mode) | `SECCOMP_RET_ERRNO \| EACCES`, with `connect`/`bind`/`send*` routed to `SECCOMP_RET_USER_NOTIF` for the supervisor to adjudicate | `linux.rs:2848`, `2859` |
| architecture guard (`prepend_seccomp_arch_guard`) | inherits the filter's `errno_ret` | `linux.rs:1926` |

**`SECCOMP_RET_LOG`, `SECCOMP_RET_KILL_PROCESS`, `SECCOMP_RET_KILL_THREAD`, `SECCOMP_RET_TRAP`
and `SECCOMP_RET_TRACE` do not appear in nono at all.** Nor does
`SECCOMP_FILTER_FLAG_LOG` — the only filter flags nono sets are
`SECCOMP_FILTER_FLAG_NEW_LISTENER` and `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`
(`linux.rs:1500-1501`, `1810`, `3293`) **[SRC]**.

### 3.1 Does the seccomp behaviour satisfy the never-`ENOENT` law?

**Yes, and with a caveat that is not nono's.** `EPERM` and `EACCES` are both fine. But
`seccomp_filter.rst` documents two paths where the kernel itself synthesises `ENOSYS`, not
`ENOENT` **[DOC]**:

- `SECCOMP_RET_USER_NOTIF` *"if it is attached, or `-ENOSYS` if it is not"*
- `SECCOMP_RET_TRACE` *"If there is no tracer present, `-ENOSYS` is returned"*

nono uses `USER_NOTIF` heavily in proxy mode. **If the supervisor dies, the guest sees `ENOSYS`
on `connect`/`bind`/`send*`, not a denial errno.** `ENOSYS` is not `ENOENT` so the letter of the
law survives, but it is a *third* meaning ("the adjudicator is gone") that the manifest's
failure-interpretation section should name, because ADR 0007 owes the agent a story for every
in-band signal it can receive. This is a live-supervisor failure mode, and ADR 0003 already
accepted a detached sibling for the credential broker — so it is a real, reachable state.

### 3.2 Is `SECCOMP_RET_LOG` / `actions_logged` a usable out-of-band channel?

**Not as nono is written, and only awkwardly even if it were.** Three requirements, from
`kernel/seccomp.c` and `seccomp_filter.rst` **[SRC/DOC]**:

1. **The filter must be installed with `SECCOMP_FILTER_FLAG_LOG`** (`seccomp.c:950`). nono never
   sets it. Not reachable from the crate surface.
2. **The action must be in the `/proc/sys/kernel/seccomp/actions_logged` sysctl.** The kernel
   default is generous — `seccomp.c:1000-1006` initialises
   `seccomp_actions_logged` to `KILL_PROCESS | KILL_THREAD | TRAP | ERRNO | USER_NOTIF | TRACE |
   LOG`, i.e. **`errno` is logged by default**, so requirement 2 is already satisfied out of the
   box. The gate is entirely requirement 1.
3. Writing that sysctl needs root; reading it does not. Not a blocker given (2).

Note what this would buy even if nono set the flag: `audit_seccomp()` records the **syscall
number and the action**, and nothing more — no path, no address, because *"BPF programs may not
dereference pointers."* It would tell playpen "syscall 41 (`socket`) was blocked", never "the
agent tried to reach `evil.com`." **For playpen's actual diagnostic need — which host, which
path — seccomp logging is close to worthless.** `SECCOMP_RET_LOG` itself is worse than useless
here: it *"results in the system call being executed after it is logged"*, i.e. it is a
permissive-with-logging action, which ADR 0007 rejected by name.

**Landlock audit is the only channel worth pursuing.** seccomp logging is a footnote.

---

## 4. Configurability — can playpen reach any of this through nono's crate surface?

**No.** Established against ADR 0003's declared cut (`sandbox` + `capability` + ABI probes)
**[SRC]**:

- **`Sandbox` is a `#[cfg]`-forked unit struct** (`sandbox/mod.rs:77`), and every entry point —
  `apply_auto`, `apply_landlock`, `apply_landlock_with_abi`, `apply_seccomp*`,
  `restrict_execute` — takes only `&CapabilitySet` (+ `&DetectedAbi`). There is no flags
  parameter and no builder.
- **`CapabilitySet`'s fields are private and there is no logging field** for Linux
  (`capability.rs:927`): `fs`, `unix_sockets`, `network_mode`, `tcp_connect_ports`,
  `tcp_bind_ports`, `localhost_ports`, `localhost_port_ranges`, `allowed_commands`,
  `blocked_commands`, `platform_rules`, `signal_mode`, `process_info_mode`, `ipc_mode`,
  `extensions_enabled`, **`seatbelt_debug_deny`**, `resource_limits`, `path_metadata_dirs`.
- **`seatbelt_debug_deny` is the macOS-only counterpart of what we want.**
  `CapabilitySet::set_seatbelt_debug_deny(true)` (`capability.rs:1382`) causes
  `sandbox/macos.rs:550` to `push_str("(debug deny)\n")` into the generated SBPL. **There is no
  `landlock_log_new_exec` sibling.** nono has already conceded that a denial-logging knob is a
  policy-relevant capability — on one platform.
- **`platform_rules: Vec<String>`** is the only free-form escape hatch, and it is
  SBPL-string-shaped; it cannot carry a `landlock_restrict_self` flag. (Unverified whether the
  Linux path even reads it — see §7.)
- **`crates/nono/src/audit.rs` is a false friend.** It is nono's own append-only NDJSON event
  ledger with Merkle/chain hashing for its supervisor's decisions — nothing to do with the
  kernel audit subsystem.
- **The `landlock` crate is not the constraint.** Pinned at 0.4.5 in nono's `Cargo.lock`, it
  already knows `ABI::V7 = Linux 6.15` and already exposes `log_new_exec(bool)`,
  `log_same_exec(bool)` and `log_subdomains(bool)` as `RestrictSelfAttr` builder methods
  applied before `restrict_self()` **[DOC]**. nono simply does not call them, and caps its own
  probe at `V6` (`linux.rs:378`).

**So the capability is unreachable through playpen's declared-narrow surface, and would remain
unreachable if playpen widened the cut, because the flag is not exposed anywhere in nono's
public API.** The fix is a nono change: probe `V7`, add a capability field, thread it to
`.log_new_exec(true)` and to the raw path's `flags` argument. That is small, mechanical, and
strictly additive — a good upstream issue.

---

## 5. Fallback — is there a channel playpen can obtain without a live supervising process?

Assessed against ADR 0007's constraint that tailing-by-default was rejected *because it costs a
live process*.

| Candidate | Live process? | Verdict |
|---|---|---|
| **Landlock audit → journal**, read after the fact via `journalctl _TRANSPORT=audit` | **No** — the journal is persistent and queryable later, same shape as `log show` on macOS | **The right answer, blocked only by §1.3 and §4** |
| Landlock audit → `dmesg` (no `auditd`, `kauditd_printk_skb` fallback) | No | Works in principle; `printk_ratelimit()`-gated and truncated ⇒ **lossy**, and silent loss is the exact failure ADR 0007 refuses |
| Direct `AUDIT_NLGRP_READLOG` netlink multicast | **Yes** — multicast is not replayable; you must be listening | Also needs `CAP_AUDIT_READ`. Rejected twice over |
| `SECCOMP_RET_LOG` / `FILTER_FLAG_LOG` + audit | No | Unreachable (§3.2), and carries no path/address anyway |
| seccomp user-notify supervisor | **Yes** by construction | Already in nono for proxy mode, but it is an *enforcement* path, not a trace; and `seccomp_unotify(2)` says it *"must not be used to make security policy decisions"* |
| `strace` / `ptrace` the child | **Yes** | Violates the transparency contract (a live ancestor); also defeats seccomp per `seccomp_filter.rst`'s own warning |
| eBPF LSM / `bpftrace` on `landlock_log_denial` | **Yes**, plus `CAP_BPF` | Root-equivalent. Out |
| **`playpen explain --run <id>` emitting the platform command** | **No** | **Already the ADR's design, and it works today** |

**The `--run` path is the one that survives, and ADR 0007 already specified it.** ADR 0007 says
`playpen explain --run <id>` *"replays a stored record and emits the exact platform command to
pull that run's denials, pid already filled in."* On Linux that command is a `journalctl` filter
on `_TRANSPORT=audit` scoped to the run's pid or Landlock `domain=` id. That costs nothing at
runtime and needs no live process — **but it emits a command that returns nothing until nono
sets `LOG_NEW_EXEC_ON`, which is a silent empty result, which is the failure mode the ADR
names.** So even the cheap path must be gated on the same fix.

### 5.1 Recommended disposition for `--trace-denials`

Refuse on Linux, but refuse **specifically**, and probe rather than hardcode the platform:

1. Probe `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) >= 7`.
2. Probe that nono's build threads `LOG_NEW_EXEC_ON` (a pinned-version fact; today: it does not).
3. Probe `audit_enabled` — readable unprivileged from the third field of
   `/proc/self/... ` — **unverified how, see §7** — or by attempting a `journalctl
   _TRANSPORT=audit -n0` and checking for records at all.
4. Probe reader access: is the operator in `systemd-journal`/`adm`/`wheel`?

Refuse at parse time with distinct codes for each, because *"kernel too old"*, *"backend does
not request logging"* and *"you are not in `wheel`"* are three different things the operator can
act on differently, and collapsing them into "unsupported on Linux" hides the one that is a
five-minute fix. This matches ADR 0007's refusal discipline — one line, a `code` from the closed
vocabulary, the offending value.

**Do not hardcode `--trace-denials` as macOS-only.** The kernel capability is real and better
than macOS's; hardcoding would bake a nono-version accident into playpen's CLI contract.

---

## 6. Bottom line

**Answering the ticket directly.**

**Can Linux surface sandbox denials out-of-band, the way the macOS kernel log does?**
**Yes — the kernel can, and playpen cannot get at it.**

- **The mechanism landed in Linux 6.15 (Landlock ABI 7)** and the record is *better* than
  macOS's: it names `path`, `dev`, `ino`, the exact missing right (`blockers=fs.write_file`),
  the denying domain, the creating executable, the pid, the comm, and the resulting errno. **[DOC/SRC]**
- **A reader does not need root.** `CAP_AUDIT_READ` is needed only for the direct netlink path;
  on a systemd host the records land in the system journal, readable by `wheel`/`adm`/
  `systemd-journal`. **The ticket's stated deal-breaker does not fire.** **[DOC/INFER]**
- **The blocker is nono.** Landlock logs nothing after `execve` unless
  `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` is passed; nono passes `0`, never calls the
  `landlock` crate's `log_new_exec()`, and caps its ABI probe at V6. playpen's exec-then-hand-off
  architecture is exactly the case the default excludes. **[SRC]**
- **`--trace-denials` is therefore unavailable on Linux today**, and must refuse — but as a
  *backend-capability* refusal with a specific code, not as a platform law.
- **The never-`ENOENT` law survives on Linux.** Landlock returns `EACCES` (commonly), `EXDEV`
  (REFER reparenting), `EPERM` (mount topology); nono's seccomp returns `EPERM` or `EACCES`.
  `ENOENT` appears only for genuinely absent paths. The enforcement suite (#22) should assert a
  **set** of three errnos plus a never-`ENOENT` negative, and should additionally cover the
  `ENOSYS` that `USER_NOTIF` yields when the supervisor is gone. **[SRC]**

**Which way does the evidence point?**

**Toward macOS being the stronger platform on this axis — but weakly, and by accident rather
than by architecture.** This is the fourth platform asymmetry and the first that does not favour
Linux, so it deserves to be stated. But it is not the same *kind* of asymmetry as the other
three:

| Asymmetry | Nature | Fixable? |
|---|---|---|
| Loopback residual (#7) | Kernel/SBPL semantics | No — inherent |
| Seatbelt deprecation clock (#3) | Vendor policy | No — Apple's to decide |
| Compiled-profile ceiling (#12) | Undocumented SBPL limit | No — inherent |
| **Denial visibility (#23)** | **A default flag nono does not set** | **Yes — a small upstream patch** |

The first three are permanent. This one is a **dependency-version fact with an expiry date**,
and the honest framing is: *on the kernel's own terms Linux is ahead; playpen is behind because
its backend has not caught up.* That belongs in the record as a nono issue and a pinned-version
note in the ADR 0003 upgrade gate — the same gate that already exists to catch "a rule that used
to be enforced silently is not." A capability that used to be *unreachable* becoming reachable is
the happy twin of that failure, and the gate should notice it.

The one place the asymmetry is genuinely structural: on macOS the denial log is on **by
default, for free, for exec'd children**, with no kernel-version floor and no audit subsystem to
enable. Linux needs 6.15+, an explicit flag, `audit_enabled`, and journal group membership —
four conditions to macOS's zero. Even after nono is fixed, **the Linux trace will be
conditional and the macOS trace will not**, and `--trace-denials` will need a real probe on
Linux forever. That much is permanent, and it is the version of this finding that should reach
ADR 0007.

---

## 7. What remains unverified, and the experiment that settles it

Everything below is documentary or source-read; **no Linux experiment was run**. Ordered by how
much a wrong answer would cost.

1. **Does `LOG_NEW_EXEC_ON` actually produce a record for an exec'd grandchild?**
   *Experiment:* on a 6.15+ box, build `samples/landlock/sandboxer.c`, run
   `LL_FS_RO=/ LL_FS_RW=/tmp LL_FORCE_LOG=1 ./sandboxer sh -c 'cat ~/.ssh/id_ed25519'`, then
   `journalctl _TRANSPORT=audit -n50`. Expect a `LANDLOCK_ACCESS` with
   `blockers=fs.read_file path="…/id_ed25519"`. Re-run **without** `LL_FORCE_LOG=1` and confirm
   **zero** `LANDLOCK_ACCESS` records but `denials=1` on the `deallocated` record. This single
   experiment validates §1.3 and §5 together, and the negative half is the load-bearing one.

2. **Can a non-root operator in `wheel` read those records?** *Experiment:* as an unprivileged
   user with no `CAP_AUDIT_READ`, run `journalctl _TRANSPORT=audit -n50` and confirm the records
   are visible; then drop out of `wheel`/`adm`/`systemd-journal` and confirm they are not.
   Currently **[INFER]** — it is the composition of journald holding `CAP_AUDIT_READ` with
   `journalctl(1)`'s documented group rules, and it decides whether §5's recommended design is
   viable at all.

3. **Is `audit_enabled` actually 1 on a stock NixOS VM?** `security.audit.enable` defaults to
   `false` **[SRC]** while journald's `Audit=` defaults to `yes` **[DOC]**; these govern
   different things and I did not verify which state results. *Experiment:*
   `auditctl -s | head -1` (or read `/proc/self/audit_*` if unprivileged-readable — **I did not
   establish an unprivileged read path for `audit_enabled`, which §5.1 step 3 needs**), and
   `systemctl status systemd-journald-audit.socket`.

4. **The exact errno for a plain denied `open()`.** §2 reads `-EACCES` from `fs.c`, and the
   admin guide's example shows `exit=-13` on the `SYSCALL` record — strong, but not executed.
   *Experiment:* under a Landlock ruleset, `open()` a denied path and print `errno`; then
   `open()` a **missing** path under the same denied subpath and confirm `ENOENT`. This is the
   direct Linux twin of the macOS experiment ADR 0007 already ran, and it is what #22 needs.
   Also cover: rename across directories (expect `EXDEV`), `mount` (expect `EPERM`), and a
   nono-seccomp-blocked `socket(AF_INET)` (expect `EPERM`).

5. **Does `USER_NOTIF` really yield `ENOSYS` when nono's supervisor dies?** §3.1 is
   `seccomp_filter.rst`'s general statement applied to nono's proxy mode **[INFER]**.
   *Experiment:* run nono in proxy mode, `kill -9` the supervisor, then `connect()` from inside
   and read `errno`. Note nono sets `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, which changes the
   blocking behaviour and may change the observed result.

6. **Whether `CapabilitySet::platform_rules` is read at all on Linux.** §4 assumes it is
   SBPL-only. *Experiment:* grep nono's Linux path for `platform_rules`; if it is consumed
   there, it may be a (poor) injection point worth knowing about.

7. **The upstream fix.** Confirm that adding `.log_new_exec(true)` to nono's crate path and
   `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` to its raw path, plus extending `ABI_PROBE_ORDER` to
   `V7`, is sufficient — and that the `landlock` crate's `CompatLevel::BestEffort` silently drops
   the flag on <6.15 rather than erroring, which is what would let nono ship it unconditionally.
   *Experiment:* patch a local nono checkout, run on a 6.12 and a 6.15 box.

8. **Not investigated:** `LANDLOCK_ADD_RULE_QUIET` (ABI 10) for suppressing expected denials,
   `auditctl` rule filtering to scope records to playpen's domain, and whether `domain=` ids are
   stable enough to be the correlation key in `playpen explain --run`. All are refinements that
   only matter once (1) and (2) come back positive.
