# `audit_enabled` — is there an unprivileged read path?

Research output for [#32](https://github.com/firefly-engineering/playpen/issues/32)
(graduated from [#29](https://github.com/firefly-engineering/playpen/issues/29); extends
[#23](https://github.com/firefly-engineering/playpen/issues/23) §1.5 and §7.3;
parent: [#1](https://github.com/firefly-engineering/playpen/issues/1)).

**Question.** [ADR 0007](../docs/adr/0007-playpen-owns-the-half-the-kernel-cannot-know.md), as
corrected by #23, requires playpen to **probe each precondition** of the Linux denial-visibility
channel and **refuse with a distinct code**. Three of the four preconditions probe cleanly. The
fourth — `audit_enabled` — has no established read path. Is there one, for an ordinary
unprivileged user? And if not, what does ADR 0007's commitment degrade to, given that
[ADR 0016](../docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md)
forbids a skip that is **inferred rather than named**?

**Method.** Primary sources only, fetched 2026-08-17.

- **Linux kernel at tag `v6.15`**, from `git.kernel.org` cgit `plain/` (the tag matters: 6.15 is
  Landlock ABI 7, the floor the whole channel needs). Files read in full or in the cited region:
  `kernel/audit.c`, `kernel/auditsc.c`, `include/uapi/linux/audit.h`,
  `include/uapi/linux/netlink.h`, `net/netlink/af_netlink.c`, `fs/proc/base.c`,
  `security/inode.c`, `security/security.c`, `security/landlock/audit.c`.
  **All line numbers below are `v6.15` unless stated otherwise.**
- **Cross-checked at tag `v6.17`** (the kernel `actions/runner-images` ships on `ubuntu-24.04`,
  per #29 §1.1): `audit_netlink_ok()` is **byte-identical** between `v6.15` and `v6.17`
  (verified by diffing the extracted function). Nothing in this report turns on the kernel
  version above 6.15.
- **`libaudit` at tag `v4.0.5`** (`linux-audit/audit-userspace`): `lib/libaudit.c`,
  `lib/netlink.c`, and the shipped man pages `docs/audit_is_enabled.3`, `docs/audit_open.3`,
  `docs/audit_request_status.3`.
- **Linux man-pages project git** (`git.kernel.org/pub/scm/docs/man-pages`), master:
  `capabilities(7)`, `netlink(7)`.
- **systemd at tag `v257`**: `src/journal/journald-audit.c`.

**This is a macOS host (Darwin 25.5.0, arm64). No Linux box was available and no probe was
executed.** Every Linux claim here is source-read or documentary. §7 lists the experiments that
would settle what remains, and I have not invented a measurement anywhere. Unlike #29, **none**
of this ticket is measurable here — there is no macOS analogue of the audit subsystem.

Provenance tags, as in `linux-denial-visibility.md` and `hosted-ci-hermeticity.md`:

| Tag | Meaning |
|---|---|
| **[SRC]** | Read from upstream production source at a named tag, with file:line |
| **[DOC]** | Stated in a kernel/vendor/first-party primary source (man page, kernel doc) |
| **[INFER]** | My composition of source-read rules; not directly verified |
| **[UNMEASURED]** | Settleable only by executing on Linux. Named, never guessed |

---

## 0. Bottom line

**No. There is no unprivileged read path to `audit_enabled`, and the reason is worse than "you
need a capability" — the capability that gates it is a *write* capability, `CAP_AUDIT_CONTROL`,
and there is no read-only counterpart at all.** Three findings carry the whole report.

1. **`AUDIT_GET` is gated on `CAP_AUDIT_CONTROL`, not `CAP_AUDIT_READ`.** `audit_netlink_ok()`
   lists `AUDIT_GET` in the same `case` group as `AUDIT_SET`, `AUDIT_ADD_RULE` and
   `AUDIT_SET_FEATURE`, and gates the whole group on `netlink_capable(skb, CAP_AUDIT_CONTROL)`
   **[SRC, `kernel/audit.c:1053-1072`]**. `CAP_AUDIT_READ` appears exactly once in the file, and
   it gates the **multicast log group bind**, not the status request **[SRC,
   `kernel/audit.c:1631-1639`]**. `capabilities(7)` says the same in one line each:
   `CAP_AUDIT_CONTROL` = *"Enable and disable kernel auditing; change auditing filter rules;
   **retrieve auditing status** and filtering rules"*; `CAP_AUDIT_READ` = *"Allow reading the
   audit log via a multicast netlink socket"* **[DOC]**. **Reading the status is a
   control-plane operation in Linux's model.** §1.

2. **libaudit's `audit_is_enabled()` answers "not enabled" for an unprivileged caller — by
   design, and its man page does not say so.** `libaudit.c:416` reads
   `else if (rc == -EPERM && !audit_can_control()) { … return 0; }`, with the comment *"we don't
   have enough privilege to write to the socket … Just act as though auditing is not enabled"*
   **[SRC]**. `audit_is_enabled(3)` documents only *"return 0 if auditing is NOT enabled and 1 if
   enabled, and -1 on error"* **[DOC]**. **Anything playpen builds on libaudit therefore inherits
   an assertion that passes vacuously**, which is precisely ADR 0016's defect class, sitting in a
   dependency. §3.

3. **Nothing else exposes it.** `kernel/audit.c` and `kernel/auditsc.c` contain **zero**
   occurrences of `sysctl`, `proc_create`, `debugfs` or `securityfs` **[SRC]**. `audit_enabled` is
   a plain `u32` with `EXPORT_SYMBOL_GPL` for in-kernel consumers and no userspace surface but
   `AUDIT_GET` **[SRC, `kernel/audit.c:70-73`]**. `/proc/self/loginuid` proves only
   `CONFIG_AUDIT=y` (a **build** fact); `/proc/cmdline` yields `audit_default` (a **boot** fact
   that any later `AUDIT_SET` overrides); `/proc/net/netlink` shows that *someone* joined the
   audit multicast group (a **listener** fact). None of the three is `audit_enabled`. §2.

**Consequently ADR 0007's "probe each precondition and refuse with a distinct code" cannot be
discharged for this precondition, and the ticket's second candidate degradation — document the
Linux channel as best-effort — must be rejected: it is the silent-empty-trace failure ADR 0007
named by name.** The first candidate is right in outcome, and needs one sharpening to be right in
shape. **`audit_enabled` is not an independently observable precondition, but the channel it
gates is observable end-to-end**, because `landlock_log_denial()` early-returns on
`!audit_enabled` **[SRC, `security/landlock/audit.c:436`]** — so a Landlock audit record that
*appears* is a proof that `audit_enabled` was non-zero. The honest degradation is therefore:

> **Three preconditions stay preconditions and refuse with distinct codes. The fourth is folded
> into a *channel self-test* that provokes a known denial and looks for its record — a
> confirm-only oracle, run every time and never cached, exactly as ADR 0006 requires of the floor
> self-test. Its failure produces a code that names the fact actually established — "the channel
> was silent" — never the fact inferred — "auditing is off".**

That satisfies ADR 0016 (the skip is named on an observation) and it **narrows #23**: Linux's
denial channel is not merely conditional where macOS's is unconditional; it is conditional on a
fact playpen **cannot ask about**, so the Linux path can only ever be certified *a posteriori*
while macOS's is certifiable *a priori*. §5, §6.

---

## 1. `AUDIT_GET` over `AF_NETLINK`/`NETLINK_AUDIT` — exactly which door closes, and where

The ticket asks a precise question: `EPERM` on bind, on send, or a reply? **None of the first
two. The refusal arrives as a netlink `NLMSG_ERROR` payload carrying `-EPERM`, after a
`socket()` that succeeds and a `sendto()` that succeeds.** Traced step by step.

### 1.1 `socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT)` — no capability check

`netlink_create()` **[SRC, `net/netlink/af_netlink.c:647-691`]** checks the socket *type*
(`SOCK_RAW` or `SOCK_DGRAM` only, else `-ESOCKTNOSUPPORT`) and the protocol range, requests the
module, and calls `__netlink_create()`. **There is no `capable()` call anywhere in it.**
`NETLINK_AUDIT` is protocol **9** **[SRC, `include/uapi/linux/netlink.h:18`]**.

Worth recording because libaudit's own source comment says otherwise: `audit_open()`'s header
comment reads *"You must be root for the call to succeed"* **[SRC, `lib/netlink.c:44-46`]**, and
that is **false** for the socket itself. `audit_open(3)` is more careful and merely refers to
`socket(2)`'s errors **[DOC]**. The comment is a fossil.

### 1.2 `bind()` — succeeds with `nl_groups = 0`, fails with `-EPERM` on any group

Two independent gates in `netlink_bind()` **[SRC, `af_netlink.c:972-1025`]**:

```c
	/* Only superuser is allowed to listen multicasts */
	if (groups) {
		if (!netlink_allowed(sock, NL_CFG_F_NONROOT_RECV))
			return -EPERM;
```

`netlink_allowed()` is `(nl_table[proto].flags & flag) || ns_capable(…, CAP_NET_ADMIN)`
**[SRC, `af_netlink.c:907-911`]**, and the audit protocol registers with
`.flags = NL_CFG_F_NONROOT_RECV` **[SRC, `kernel/audit.c:1646-1658`]** — so this first gate is
**open** for audit. The second gate is the protocol's own `netlink_bind` callback, invoked per
group **[SRC, `af_netlink.c:1012-1025`]**, which for audit is:

```c
static int audit_multicast_bind(struct net *net, int group)
{
	int err = 0;

	if (!capable(CAP_AUDIT_READ))
		err = -EPERM;
	audit_log_multicast(group, "connect", err);
	return err;
}
```
**[SRC, `kernel/audit.c:1631-1639`]**

So: **`bind()` with `nl_groups = 0` succeeds unprivileged** (and libaudit never binds at all —
`__audit_send()` relies on autobind). **`bind()` with `nl_groups = AUDIT_NLGRP_READLOG`
returns `-EPERM`** without `CAP_AUDIT_READ`, and additionally emits an `AUDIT_EVENT_LISTENER`
record naming your pid, uid, auid, comm and exe **[SRC, `kernel/audit.c:1598-1628`]** — the
attempt is itself audited. `AUDIT_NLGRP_READLOG` is group **1** **[SRC,
`include/uapi/linux/audit.h:464-468`]**.

**This bind is the only thing `CAP_AUDIT_READ` buys, and it buys the log, not the status.** #23
§1.4 already said `CAP_AUDIT_READ` gates the direct netlink multicast path; that is confirmed.
What #23 did not establish, and what this ticket settles, is that the *status* is behind a
strictly stronger gate.

### 1.3 `sendto()` — succeeds unprivileged

`netlink_sendmsg()` **[SRC, `af_netlink.c:1801-1842`]** refuses only when a destination is
addressed:

```c
		dst_portid = addr->nl_pid;
		dst_group = ffs(addr->nl_groups);
		err =  -EPERM;
		if ((dst_group || dst_portid) &&
		    !netlink_allowed(sock, NL_CFG_F_NONROOT_SEND))
			goto out;
```

`NETLINK_AUDIT` does **not** set `NL_CFG_F_NONROOT_SEND` (only `NETLINK_USERSOCK` does
**[SRC, `af_netlink.c:2844`]**), so an unprivileged process cannot send to a *peer* or a
*group*. But messages **to the kernel** carry `nl_pid = 0, nl_groups = 0`, so both operands are
zero and the guard does not fire. libaudit does exactly this:

```c
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;
	addr.nl_groups = 0;
	…
		retval = sendto(fd, &req, req.nlh.nlmsg_len, 0, …);
```
**[SRC, `lib/netlink.c:189-238`, `__audit_send()`]**

**So the `AUDIT_GET` request leaves userspace successfully.**

### 1.4 The kernel's reply — `-EPERM` inside an `NLMSG_ERROR`

`audit_receive()` calls `audit_receive_msg()` and, on any error, `netlink_ack(skb, nlh, err,
NULL)` **[SRC, `kernel/audit.c:1555-1581`]**. `audit_receive_msg()`'s **first** statement is the
permission check, before the `switch` that would service `AUDIT_GET`:

```c
	err = audit_netlink_ok(skb, msg_type);
	if (err)
		return err;
```
**[SRC, `kernel/audit.c:1226-1228`]**

and `audit_netlink_ok()` **[SRC, `kernel/audit.c:1030-1084`]** decides it:

```c
	if (current_user_ns() != &init_user_ns)
		return -ECONNREFUSED;

	switch (msg_type) {
	case AUDIT_LIST:
	case AUDIT_ADD:
	case AUDIT_DEL:
		return -EOPNOTSUPP;
	case AUDIT_GET:
	case AUDIT_SET:
	case AUDIT_GET_FEATURE:
	case AUDIT_SET_FEATURE:
	case AUDIT_LIST_RULES:
	case AUDIT_ADD_RULE:
	case AUDIT_DEL_RULE:
	case AUDIT_SIGNAL_INFO:
	case AUDIT_TTY_GET:
	case AUDIT_TTY_SET:
	case AUDIT_TRIM:
	case AUDIT_MAKE_EQUIV:
		/* Only support auditd and auditctl in initial pid namespace
		 * for now. */
		if (task_active_pid_ns(current) != &init_pid_ns)
			return -EPERM;

		if (!netlink_capable(skb, CAP_AUDIT_CONTROL))
			err = -EPERM;
		break;
```

**Three things are decided here, and all three matter.**

- **`AUDIT_GET` is in the `CAP_AUDIT_CONTROL` group.** So is `AUDIT_GET_FEATURE`, the other
  read-shaped request. There is **no** message type in the audit protocol that returns status
  under a lesser capability. Answering the ticket's "determine exactly WHICH operations are
  gated": `AUDIT_LIST`/`ADD`/`DEL` are dead (`-EOPNOTSUPP`); thirteen types including every
  status read need `CAP_AUDIT_CONTROL`; the `AUDIT_USER*` ranges need `CAP_AUDIT_WRITE`
  **[SRC, `audit.c:1073-1078`]**; anything else is `-EINVAL` **[SRC, `audit.c:1079-1080`]**.
- **A non-initial user namespace gets `-ECONNREFUSED`, deliberately.** The comment above it says
  so in as many words: *"We return ECONNREFUSED because it tricks userspace into thinking that
  audit was not configured into the kernel"* **[SRC, `audit.c:1035-1044`]**. The kernel is
  *intentionally lying* to namespaced callers, for PAM's benefit.
- **A non-initial PID namespace gets `-EPERM` even holding the capability.** Relevant to any
  containerised runner.

`netlink_capable()` resolves to `__netlink_ns_capable()`, which requires the capability **both**
in the credentials the socket's file was opened with **and** in the caller's current credentials
**[SRC, `af_netlink.c:850-889`]** — so passing an fd from a privileged helper does not work
either.

Had the check passed, `AUDIT_GET` would have replied with `struct audit_status` whose first
substantive field is the one wanted:

```c
	case AUDIT_GET: {
		struct audit_status	s;
		memset(&s, 0, sizeof(s));
		s.enabled		   = audit_enabled;
```
**[SRC, `kernel/audit.c:1235-1250`]**, `struct audit_status` at
**[SRC, `include/uapi/linux/audit.h:470`]**, `AUDIT_GET = 1000` at **[SRC, `audit.h:54`]**.

### 1.5 The answer to the bullet, stated flatly

| Step | Unprivileged result |
|---|---|
| `socket(AF_NETLINK, SOCK_RAW\|SOCK_CLOEXEC, NETLINK_AUDIT)` | **succeeds** — no capability check **[SRC]** |
| `bind()` with `nl_groups = 0` | **succeeds** **[SRC]** |
| `bind()` with `nl_groups = AUDIT_NLGRP_READLOG` | **`-EPERM`** (needs `CAP_AUDIT_READ`), and logs an `AUDIT_EVENT_LISTENER` record about you **[SRC]** |
| `sendto()` of an `AUDIT_GET` request to `nl_pid = 0` | **succeeds** **[SRC]** |
| `recvmsg()` | **an `NLMSG_ERROR` reply carrying `error = -EPERM`** (`-ECONNREFUSED` in a user namespace; `-EPERM` in a PID namespace) **[SRC]** |

**No syscall fails. The refusal is a message.** That is the shape playpen would have to read, and
it is also the shape libaudit throws away (§3).

---

## 2. Every procfs / sysfs surface, checked

### 2.1 There is no audit sysctl, procfs or securityfs entry — verified by absence

`grep -n 'sysctl\|proc_create\|debugfs\|securityfs\|seq_file' kernel/audit.c kernel/auditsc.c`
at `v6.15` returns **nothing** **[SRC]**. The variable itself:

```c
u32		audit_enabled = AUDIT_OFF;
bool		audit_ever_enabled = !!AUDIT_OFF;

EXPORT_SYMBOL_GPL(audit_enabled);
```
**[SRC, `kernel/audit.c:70-73`]**

`EXPORT_SYMBOL_GPL` is an *in-kernel* export, for LSMs like Landlock. It is not a userspace
surface. **`AUDIT_GET` is the only one.**

> **This directly corrects #23 §5.1 step 3**, which wrote that `audit_enabled` is *"readable
> unprivileged from the third field of `/proc/self/…` — unverified how"*. **There is no such
> file.** The speculation was almost certainly a half-memory of `/proc/self/loginuid`, which is a
> different thing entirely (§2.2).

### 2.2 `/proc/self/loginuid` and `/proc/self/sessionid` — a build fact, not a runtime fact

Both are registered under `#ifdef CONFIG_AUDIT`, world-readable:

```c
#ifdef CONFIG_AUDIT
	REG("loginuid",   S_IWUSR|S_IRUGO, proc_loginuid_operations),
	REG("sessionid",  S_IRUGO, proc_sessionid_operations),
#endif
```
**[SRC, `fs/proc/base.c:3381-3384` and `:3728-3731`]**, handlers at
**[SRC, `fs/proc/base.c:1305-1391`]**.

So their **existence** is a genuine unprivileged probe of `CONFIG_AUDIT=y` — a necessary
condition for the whole channel, and worth having. Their **values** say nothing about
`audit_enabled`:

- `proc_loginuid_read()` returns `audit_get_loginuid(task)` with no reference to `audit_enabled`
  **[SRC, `base.c:1307-1322`]**.
- `audit_set_loginuid()` assigns a session id from a global counter and stores the loginuid
  **regardless of `audit_enabled`**; only the *record* about the change is suppressed when
  auditing is off **[SRC, `kernel/audit.c:2359-2383`, and `audit_log_set_loginuid()`'s
  `if (!audit_enabled) return;` at `:2330`]**.
- Writing needs `CAP_AUDIT_CONTROL` only if a loginuid is already set
  **[SRC, `kernel/audit.c:2304-2321`]**.

So a host with `pam_loginuid` in the stack has a set `loginuid` whether or not auditing is
enabled. **A necessary-condition probe, never a sufficient one.**

### 2.3 `/proc/net/netlink` — a listener fact, and the best proxy available

Registered per-netns with mode `0` **[SRC, `af_netlink.c:2815`]**, which `proc_create_reg()`
promotes to `0444`; the row format is **[SRC, `af_netlink.c:2677-2700`]**:

```
sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode
```

where `Eth` is `s->sk_protocol` and `Groups` is `nlk->groups[0]`. An unprivileged reader can
therefore see **that a socket exists on protocol 9 with the `0x00000001` group bit set** — i.e.
that some process has joined `AUDIT_NLGRP_READLOG`. (The `sk` column is `%pK` and reads as zeros
under the usual `kptr_restrict=1`; the rest is plain.)

On a systemd host that socket is journald's: `server_open_audit()` creates a `NETLINK_AUDIT`
socket and `bind()`s it with `.nl_groups = AUDIT_NLGRP_READLOG`, then — *only if* `Audit=` is
configured — issues `enable_audit()`, which is an `AUDIT_SET` with
`.mask = AUDIT_STATUS_ENABLED` **[SRC, systemd `v257`, `src/journal/journald-audit.c:457-553`]**.

**So the proxy chain is: socket on proto 9 with group 1 ⇒ journald (or `auditd`) is listening ⇒
journald probably also called `enable_audit(true)`, because `journald.conf`'s `Audit=` defaults
to yes in the default namespace ⇒ `audit_enabled` is probably 1.** Each arrow is a default, and
the second arrow is explicitly conditional in the source (`if (s->set_audit >= 0)`). **This is an
inference through two defaults, which is exactly what ADR 0016 forbids as the basis of a named
skip.** It is a useful diagnostic string to print; it is not a precondition probe.

### 2.4 `/proc/cmdline` — a boot fact that any later write overrides

`audit=` sets `audit_default`, then `audit_set_enabled(audit_default)`
**[SRC, `kernel/audit.c:1729-1755`]**, and `audit_default` is separately `static u32` at
**[SRC, `:76`]**. `/proc/cmdline` is world-readable, so `audit=1` is readable — but it is the
value at boot, and `AUDIT_SET` from journald or `auditctl -e` changes the live value without
touching it. Reading `/proc/cmdline` can prove *nothing* about the current state; the common case
on a systemd host is precisely no `audit=` parameter and `audit_enabled` turned on later.

### 2.5 `dmesg` / `/dev/kmsg` — two messages, both misleading, and one hole

Two printk sites near the boot state:

```c
	pr_info("initializing netlink subsys (%s)\n",
		str_enabled_disabled(audit_default));
```
**[SRC, `kernel/audit.c:1709-1710`]** — reports **`audit_default`**, not `audit_enabled`. And:

```c
	audit_log(NULL, GFP_KERNEL, AUDIT_KERNEL,
		"state=initialized audit_enabled=%u res=1",
		 audit_enabled);
```
**[SRC, `kernel/audit.c:1721-1723`]** — a real audit *record*, which reaches printk only via
`kauditd_printk_skb()`'s no-`auditd` fallback, `printk_ratelimit()`-gated
**[SRC, `kernel/audit.c:534-546`]**, and reports the value **at postcore_initcall time** — before
journald has run.

**And here is the hole.** Later transitions are logged by `audit_do_config_change()`, which
guards the record on the state *before* the change:

```c
	if (audit_enabled != AUDIT_OFF) {
		rc = audit_log_config_change(function_name, new, old, allow_changes);
```
**[SRC, `kernel/audit.c:402-425`, `audit_set_enabled()` at `:442-453`]**

So the **OFF → ON** transition — the one that matters, the one journald performs — emits **no
record at all**, because at the moment of the check `audit_enabled == AUDIT_OFF`. ON → OFF is
logged; OFF → ON is not. There is therefore no "auditing was turned on" record to find, even for
a fully privileged reader of the journal. **[SRC]**

(`dmesg` readability is in any case gated by `kernel.dmesg_restrict`, which Debian- and
Ubuntu-family distributions set to 1.)

### 2.6 `/sys/kernel/security/lsm` — #29's passing claim, re-verified and **confirmed**

The ticket asked for this to be re-checked from source. It holds, exactly as #29 §2.3 stated.

```c
#ifdef CONFIG_SECURITY
static struct dentry *lsm_dentry;
static ssize_t lsm_read(struct file *filp, char __user *buf, size_t count,
			loff_t *ppos)
{
	return simple_read_from_buffer(buf, count, ppos, lsm_names,
		strlen(lsm_names));
}
…
	lsm_dentry = securityfs_create_file("lsm", 0444, NULL, NULL,
						&lsm_ops);
```
**[SRC, `security/inode.c:341-372`]**, with `char *lsm_names;` at
**[SRC, `security/security.c:98`]**, appended per initialised module by `lsm_append()` at
**[SRC, `security/security.c:537`]** and per late-registered module at **[SRC, `:641`]**.

**Verified: the path is `/sys/kernel/security/lsm`, mode `0444`, present iff `CONFIG_SECURITY=y`,
and its content is the list of *active* LSMs.** #29's correction of #32's own ticket text (which
had named `/sys/kernel/security/lockdown`) stands. Note the one caveat #29 did not state:
`securityfs` must be **mounted** at `/sys/kernel/security` for the file to be reachable, which
systemd does but a bare container may not — so "file absent" has two causes and a probe should
distinguish them.

### 2.7 Candidates considered and rejected

| Candidate | Why it fails |
|---|---|
| `AUDIT_GET_FEATURE` | Same `case` group, same `CAP_AUDIT_CONTROL` gate **[SRC, `audit.c:1055`]** |
| `AUDIT_SIGNAL_INFO` | Same group **[SRC, `audit.c:1060`]** |
| Send `AUDIT_USER` and read the reply | Needs `CAP_AUDIT_WRITE` **[SRC, `audit.c:1073-1078`]**, which an ordinary user also lacks |
| Timing side channel on `sendto()` | `audit_receive()` deliberately sleeps the sender when the backlog is over limit **[SRC, `audit.c:1583-1595`]**. A timing oracle for *backlog pressure*, not for `audit_enabled`, and unusable as a refusal basis |
| `/proc/<pid>/status` `CapEff` | Reports *your* capabilities, not the kernel's audit state |
| `systemctl is-active systemd-journald-audit.socket` | Unprivileged-readable over D-Bus, but it is a **unit** fact — a proxy for §2.3's proxy, one link further from the truth, and absent on non-systemd hosts |
| `auditctl -s` | The standard answer, and it is `CAP_AUDIT_CONTROL` by construction — it is `audit_request_status()` |

---

## 3. `libaudit` — what it assumes, and what it does on failure

**This is the most important section for playpen, because it is the thing playpen would
plausibly have reached for.**

`audit_open()` is a bare `socket()` with no privilege of its own
**[SRC, `lib/netlink.c:48-63`]** — its stale header comment claiming root is required is wrong
(§1.1). `audit_request_status()` is a bare `audit_send(fd, AUDIT_GET, NULL, 0)`
**[SRC, `lib/libaudit.c:122-129`]**, and `audit_send()` → `__audit_send()` → `check_ack()`, where
`check_ack()` reads the reply, and on `NLMSG_ERROR` sets `errno = -error` and **returns the
negative errno** **[SRC, `lib/netlink.c:242-297`]**.

Then `audit_is_enabled()` **[SRC, `lib/libaudit.c:374-426`]**:

```c
	if ((rc = audit_request_status(fd)) > 0) {
		…
				/* Found it... */
				return rep.status->enabled;
		…
	}
	if (rc == -ECONNREFUSED) {
		/* This is here to let people that build their own kernel
		   and disable the audit system get in. ECONNREFUSED is
		   issued by the kernel when there is "no on listening". */
		return 0;
	} else if (rc == -EPERM && !audit_can_control()) {
		/* If we get this, then the kernel supports auditing
		 * but we don't have enough privilege to write to the
		 * socket. Therefore, we have already been authenticated
		 * and we are a common user. Just act as though auditing
		 * is not enabled. Any other error we take seriously.
		 * This is here basically to satisfy Xscreensaver. */
		return 0;
	}
	return -1;
```

with `audit_can_control()` = `capng_have_capability(CAPNG_EFFECTIVE, CAP_AUDIT_CONTROL)`, or
`geteuid() == 0` when built without libcap-ng **[SRC, `lib/libaudit.c:2174-2185`]**.

**Three consequences, in ascending order of severity.**

1. **An unprivileged caller gets `0`, meaning "auditing is not enabled", from a kernel where
   auditing is enabled.** The return value is indistinguishable from the true negative. There is
   no third value and no out-of-band signal.
2. **A caller inside a user namespace also gets `0`**, via the `-ECONNREFUSED` branch — and the
   kernel comment at `audit.c:1035-1044` says that lie is *intentional*. So the failure mode
   survives into containers, where a naive reader would be least suspicious.
3. **`audit_is_enabled(3)` documents none of this.** Verbatim, the entire RETURN VALUE section:
   *"This function will return 0 if auditing is NOT enabled and 1 if enabled, and -1 on error."*
   **[DOC, `docs/audit_is_enabled.3`, Red Hat, May 2021]** An implementer reading only the man
   page would ship the vacuous assertion and never know.

> **This is ADR 0016's central defect — "an assertion that can pass vacuously is a defect" —
> instantiated inside a dependency, with a man page that hides it.** Whatever playpen does here,
> it must not be `audit_is_enabled()`. If playpen ever links libaudit for another reason, this
> function needs a comment at the call site and a lint.

Also worth noting for the ticket's "what privilege does *it* assume": libaudit assumes
`CAP_AUDIT_CONTROL` throughout and provides `audit_can_control()`, `audit_can_write()` and
`audit_can_read()` as the three self-checks **[SRC, `lib/libaudit.c:2174-2210`]**. **There is a
self-check for each capability and no way to answer the question without one.** The library's own
structure is the admission.

### 3.1 On `man 7 audit`

The ticket named `man 7 audit`. **It does not exist.** The Linux man-pages project ships no
`audit.7` (fetch of `man/man7/audit.7` from `git.kernel.org/pub/scm/docs/man-pages` at master
returns *Not found*), and `audit-userspace` at `v4.0.5` ships `docs/audit.rules.7` — a *rule file
format* page — plus the section-3 API pages quoted above **[DOC]**. `netlink(7)` mentions
`NETLINK_AUDIT` in one line, *"Auditing."*, immediately followed by the project's own
`.\" FIXME More details on NETLINK_AUDIT needed.` **[SRC, man-pages master, `man/man7/netlink.7:92-94`]**
— the permission model documented in §1 is **not** in any man page. `capabilities(7)` is the only
man page that states it, and it does so correctly and in one line each (§0.1).

---

## 4. Journal-record presence as a proxy — what it costs

**It is a valid oracle in one direction only, and the ticket's characterisation is exactly
right.** The kernel side is unambiguous:

```c
	atomic64_inc(&youngest_denied->num_denials);

	if (!audit_enabled)
		return;
```
**[SRC, `security/landlock/audit.c:434-437`, in `landlock_log_denial()` at `:390`]**

(#23 cited this as `security/landlock/audit.c:604-613`; at `v6.15` it is `:436`. The code is
identical — #23 evidently read master, where the file has grown. Not a contradiction, but the
line reference should not be trusted across tags.)

So:

- **A `LANDLOCK_ACCESS` record that appears proves `audit_enabled != 0`.** Sound, unconditional.
- **No record proves nothing.** The absent-record set is the union of: auditing off; kernel
  < 6.15; `LOG_NEW_EXEC` not passed; a matching `AUDIT_FILTER_EXCLUDE` rule (`audit_log_start()`
  returns `NULL` on `!audit_filter(type, AUDIT_FILTER_EXCLUDE)` **[SRC, `kernel/audit.c:1859-1870`]**);
  backlog overflow (`audit_log_start()` returns `NULL` and calls `audit_log_lost()`
  **[SRC, `kernel/audit.c:1875-1907`]**); the reader not being in `systemd-journal`/`adm`/`wheel`;
  or **the denial simply not having happened**. Six causes, one observation.

**And the sharpest cost is structural, not statistical: the behavioural probe cannot isolate
`audit_enabled`, because it is downstream of every other precondition.** It is a measurement of
the *conjunction*. That is why it cannot be slotted into ADR 0007's per-precondition refusal
scheme as-is — and why §5 relocates it rather than discarding it.

Two secondary costs worth naming:

- **It requires provoking a denial**, i.e. a real `landlock_restrict_self()` in a throwaway
  domain and a deliberate failed `open()`. That is cheap, but it is *not* free of side effects:
  it writes a record to the operator's audit log every time it runs, which on a `-w`-rule host is
  noise the operator did not ask for.
- **The `denials=N` counter on the `deallocated` record is not a way out.**
  `num_denials` is incremented *before* the `audit_enabled` check (quoted above), so the count is
  accurate even when auditing is off — but the record that *carries* it is emitted by a function
  that itself early-returns on `!audit_enabled` **[SRC, `security/landlock/audit.c:483-484`]**.
  The counter that would have told you is behind the same gate.

---

## 5. If there is no unprivileged read path, what does ADR 0007 degrade to?

The ticket offers two candidates. **Take them in reverse order, because the second is the one to
kill.**

### 5.1 Rejected: "document the Linux channel as best-effort rather than probed"

This is the failure ADR 0007 names in its own text, one paragraph away:

> *"an empty trace file that means 'unsupported' reads as 'nothing was denied', which is a silent
> downgrade in its purest form."*

"Best-effort" is that sentence with a documentation fig leaf. It also contradicts ADR 0016's
"a skip is not a pass" and its "never a hardcoded platform assumption", and it would make the
`R-trace-denials` row of #29 §5.3 unassertable — the row exists to check that the refusal *names
which precondition is missing*, and a best-effort channel has no refusal to assert against.
**Reject.**

### 5.2 Accepted, with one sharpening: a new outcome class, realised as a channel self-test

The ticket's first candidate — *"a precondition playpen declares **unprobeable** and reports as
such (honest, and a new outcome class)"* — is right that a new outcome class is required. But
"unprobeable" as a *label on a precondition* is not quite the truth, and stating it that way
would leave `--trace-denials` in the same silent-empty-file position as 5.1, just with a more
honest error message. Two refinements make it correct:

**(a) The precondition is not unprobeable; it is *unaskable*.** `audit_enabled` has an exact
value, it is retrievable in one syscall, and the gate is a capability the operator could in
principle grant (`setcap cap_audit_control=ep`, or run under `auditctl`). Calling it
"unprobeable" reads as a kernel limitation when it is a **privilege-model** fact — and the
distinction is operationally live, because the fix is one `setcap` away, exactly the "five-minute
fix" #23 §5.1 said the distinct codes exist to surface.

**(b) The *channel* is observable even though the *precondition* is not**, by §4's confirm-only
oracle. So the honest design is not to give up on the fourth precondition but to **stop treating
it as a precondition** and fold it into an end-to-end self-test of the thing the four
preconditions were only ever a proxy for.

**The resulting shape:**

| Precondition | Probe | Refusal on failure |
|---|---|---|
| Landlock ABI ≥ 7 | `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`; `ENOSYS` and `EOPNOTSUPP` are distinct **[DOC, #29 §2.3]** | `refusal.trace.kernel-abi` / `refusal.trace.landlock-inactive` |
| nono passes `LOG_NEW_EXEC` | a property of the pin, not the host **[SRC, #23 §1.3]** | `refusal.trace.backend-no-logging` |
| journal readability | attempt the read; `id -Gn` ∩ `{systemd-journal, adm, wheel}` **names** it | `refusal.trace.no-journal-access` |
| `audit_enabled` | **none — folded below** | — |
| **the channel itself** | **provoke a known denial in a throwaway Landlock domain; look for its record** | `refusal.trace.channel-silent` |

and the fifth row's code says the fact that was **observed**:

> `playpen: refusal.trace.channel-silent: the denial-visibility channel produced no record for a
> probe denial; kernel auditing may be disabled (audit_enabled is not readable without
> CAP_AUDIT_CONTROL) — run <id>`

**That is a named skip, not an inferred one**, and the distinction is not a word game: the
sentence asserts "no record appeared", which playpen observed, and *offers* the most likely cause
as a hypothesis with its reason. ADR 0016 forbids a skip whose *basis* is inference. The basis
here is a measurement.

**Three properties this shape inherits from decisions already landed.**

- **It is the ADR 0006 floor-self-test pattern, verbatim.** ADR 0007 already says the floor
  self-test *"runs on every launch and is never cached"* because *"every such key is a guess that
  fails **open and silently**"*. A cached `audit_enabled` — read once at install time when someone
  had privilege, say — is exactly such a key. The channel self-test must run whenever
  `--trace-denials` is requested, and must not be cached, for the same reason and by the same
  argument.
- **It costs nothing when unused.** `--trace-denials` is opt-in; the self-test runs only on that
  path, so the "costs nothing at runtime" property of `playpen explain --run` is preserved.
- **It makes the `R-trace-denials` suite row assertable again.** #29 §5.3 marked it "run,
  partially" with precondition 3 unresolvable. Under this shape the row asserts *four* distinct
  refusal codes plus the channel self-test's own, and the `R-code-coverage` row (#29 §5.3) picks
  up `refusal.trace.channel-silent` for free.

### 5.3 What this narrows in #23 — and it is a real narrowing

#23's headline was that *"on the kernel's own terms Linux is ahead"* on denial visibility, with
the shortfall attributed to nono and given an expiry date. **The content half of that survives
untouched** — the `LANDLOCK_ACCESS` record still names `path`, `dev`, `ino` and `blockers`, and is
still richer than the Seatbelt line.

**The reachability half narrows, permanently.** #23 §6 wrote: *"Linux needs 6.15+, an explicit
flag, `audit_enabled`, and journal group membership — four conditions to macOS's zero."* The
correction is that these four are **not the same kind of thing**. Three are conditions playpen can
*ask about* and refuse on. The fourth is a condition playpen can only *discover it lacked*, after
the fact, by the channel being silent. So:

> **macOS's denial channel is certifiable *a priori*; Linux's is certifiable only *a
> posteriori*.** Even after nono ships `LOG_NEW_EXEC_ON` and the dependency-version asymmetry
> expires, that difference remains — and unlike the flag, it has no expiry date, because it is a
> property of Linux's capability model, not of a default.

That belongs on the asymmetry ledger as a **permanent** entry, alongside the loopback residual and
the compiled-profile ceiling, rather than in the "fixable upstream" column where #23 put denial
visibility (#23 §6's table). **#23's four-way table is right about the *flag* and wrong about the
*asymmetry*: denial visibility has both a fixable component and a permanent one, and #23 recorded
only the fixable one.**

### 5.4 ADR 0007's own sentence needs an amendment

ADR 0007 currently reads: *"macOS yields the trace with zero preconditions and Linux with four,
three of which an operator can fix."* Two things are now wrong with it.

- **"three of which an operator can fix"** implies the fourth cannot be fixed by the operator. It
  can — `audit_enabled` is the *most* operator-fixable of the four (one `auditctl -e 1`). What the
  operator cannot do is let playpen *see* it without also granting `CAP_AUDIT_CONTROL`.
- **"four preconditions"** should become **"three probed preconditions and one channel
  self-test"**, or the ADR's own "probe each precondition and refuse with a distinct code" reads
  as a promise playpen cannot keep.

---

## 6. Verified / inferred / unmeasured

The ticket asked for these to be separated rigorously. They are.

### 6.1 Verified in primary source (**[SRC]** / **[DOC]**)

1. `AUDIT_GET` is gated on `CAP_AUDIT_CONTROL` via `netlink_capable()`; `CAP_AUDIT_READ` gates
   only the multicast group bind. `kernel/audit.c:1053-1072` and `:1631-1639`, `v6.15`; identical
   at `v6.17`.
2. `capabilities(7)` assigns "retrieve auditing status" to `CAP_AUDIT_CONTROL` and "reading the
   audit log via a multicast netlink socket" to `CAP_AUDIT_READ`. man-pages master.
3. `socket()`, `bind(groups=0)` and `sendto(nl_pid=0)` on `NETLINK_AUDIT` all succeed
   unprivileged; the refusal is an `NLMSG_ERROR` reply. `af_netlink.c:647, 972-997, 1801-1842`;
   `audit.c:1226-1228, 1555-1581`.
4. A non-initial **user** namespace gets `-ECONNREFUSED` by deliberate design; a non-initial
   **PID** namespace gets `-EPERM`. `audit.c:1035-1046, 1065-1068`.
5. `kernel/audit.c` and `kernel/auditsc.c` contain no sysctl, procfs, debugfs or securityfs
   registration. `audit_enabled` is exported only via `EXPORT_SYMBOL_GPL`. `audit.c:70-73`.
6. `libaudit`'s `audit_is_enabled()` returns `0` for `-EPERM` without `CAP_AUDIT_CONTROL`, and
   `0` for `-ECONNREFUSED`. `lib/libaudit.c:374-426`, `:2174-2185`, `v4.0.5`.
7. `audit_is_enabled(3)` documents neither behaviour. `docs/audit_is_enabled.3`, `v4.0.5`.
8. `audit_open()` needs no privilege; its own source comment saying otherwise is wrong.
   `lib/netlink.c:44-63`.
9. `/proc/self/loginuid` and `/proc/self/sessionid` exist iff `CONFIG_AUDIT=y`, are
   world-readable, and their values are independent of `audit_enabled`.
   `fs/proc/base.c:1305-1391, 3381-3384, 3728-3731`; `audit.c:2359-2383`.
10. `/proc/net/netlink` is `0444` and exposes protocol number and group bitmask per socket.
    `af_netlink.c:2677-2700, 2815`.
11. `/sys/kernel/security/lsm` is `0444`, present under `CONFIG_SECURITY`, and holds the active
    LSM list. `security/inode.c:341-372`; `security/security.c:98, 537, 641`. **#29's claim
    confirmed.**
12. The **OFF → ON** transition of `audit_enabled` emits **no** audit record.
    `audit.c:402-425, 442-453`.
13. `pr_info("audit: initializing netlink subsys …")` reports `audit_default`, not
    `audit_enabled`. `audit.c:1709-1710`.
14. `landlock_log_denial()` early-returns on `!audit_enabled`, *after* incrementing the denial
    counter. `security/landlock/audit.c:390, 434-437`; the `deallocated` record that carries the
    counter is behind the same gate at `:483-484`.
15. `audit_log_start()` also returns `NULL` on an `AUDIT_FILTER_EXCLUDE` match and on backlog
    overflow — two further causes of an absent record that are unrelated to `audit_enabled`.
    `audit.c:1859-1907`.
16. systemd's journald binds `AUDIT_NLGRP_READLOG` and issues `AUDIT_SET` with
    `AUDIT_STATUS_ENABLED` only when `Audit=` is configured. systemd `v257`,
    `src/journal/journald-audit.c:457-553`.
17. There is no `audit(7)` in the Linux man-pages project, and `netlink(7)` carries an explicit
    `FIXME` where `NETLINK_AUDIT`'s details would be.

### 6.2 Inferred (**[INFER]**) — composition, not verification

1. **The end-to-end channel self-test of §5.2 works as described.** It composes fact 14 (a record
   proves auditing was on) with #23's `LOG_NEW_EXEC` finding and #29's journal-reader finding.
   The composition is sound on paper; the *timing* is not established — how long after the denial
   the record is queryable via `journalctl` — and a self-test that polls too briefly would produce
   a false `channel-silent`. **This is the load-bearing unknown of the recommended design.**
2. **`/proc/net/netlink` showing protocol 9 with group bit 1 implies journald or `auditd` is
   listening.** Follows from fact 10 + fact 16, but nothing forbids a third program from binding
   the group.
3. **On a stock systemd host `audit_enabled` is 1.** From fact 16 plus `journald.conf`'s
   documented `Audit=` default (#23 §1.5). Two defaults chained; explicitly **not** a basis for a
   named skip.
4. **Granting `CAP_AUDIT_CONTROL` to playpen's probe would make `AUDIT_GET` work.** Follows from
   §1 mechanically, but playpen should not want a file capability, and #23 already rejected the
   equivalent for `CAP_AUDIT_READ`.

### 6.3 Unmeasured (**[UNMEASURED]**) — no Linux host was available

1. **The actual `NLMSG_ERROR` an unprivileged `AUDIT_GET` returns.** §1 is a source trace, not an
   execution. *Experiment (~30 lines of C, any Linux box, no root):* `socket`, `sendto` an
   `AUDIT_GET` to `nl_pid=0`, `recvmsg`, print `nlmsghdr.nlmsg_type` and `nlmsgerr.error`. Expect
   `NLMSG_ERROR` / `-EPERM`. Repeat inside `unshare -U` and expect `-ECONNREFUSED`; repeat under
   `setcap cap_audit_control=ep` and expect a `struct audit_status`. Then run
   `auditctl -s | head -1` as root for the ground truth to compare against. **This is the single
   experiment that closes the ticket's first bullet by measurement rather than by reading.**
2. **`audit_is_enabled()`'s observed return for an unprivileged caller on a host where auditing
   *is* on.** Predicted `0`. *Experiment:* four lines against `-laudit`, run as an ordinary user
   on a systemd host, compared with `auditctl -s`. If it returns `0` while `auditctl -s` says
   `enabled 1`, the vacuous-answer finding is demonstrated rather than argued.
3. **The self-test's record latency** (§6.2.1). *Experiment:* on a 6.15+ box with
   `LL_FORCE_LOG=1 ./sandboxer`, timestamp the denial and poll `journalctl _TRANSPORT=audit` until
   the record appears; record the distribution. Decides the self-test's timeout and therefore its
   false-negative rate.
4. **Whether `/proc/net/netlink` on a stock Ubuntu 24.04 runner actually shows a proto-9 group-1
   socket.** Decides whether the diagnostic string of §2.3 is worth printing. Trivial:
   `cat /proc/net/netlink`.
5. **Whether nono's seccomp filters permit `socket(AF_NETLINK, …)` from *inside* the sandbox.**
   Not needed for the probe (which runs outside, before launch) but needed if the *enforcement
   suite's probe binary* ever wants to make this check from inside. #23 §3 lists nono's filters as
   network-oriented; whether `AF_NETLINK` falls under `build_seccomp_block_network_filter`'s
   `socket` gate was not established.
6. **Whether the `-azure` runner kernel mounts `securityfs`** — needed for §2.6's caveat.
7. **Not investigated:** whether any distro ships a `setcap cap_audit_control` on a helper that
   playpen could reuse (almost certainly not, and it would be a supply-chain dependency);
   `AUDIT_TTY_GET` as a status side channel (same `case` group, so no); and whether the
   `AUDIT_EVENT_LISTENER` record emitted on a *failed* `CAP_AUDIT_READ` bind (§1.2) constitutes a
   privacy consideration worth naming in the manifest.

---

## 7. The four bullets, answered directly

**1. Is `AUDIT_GET` over `AF_NETLINK`/`NETLINK_AUDIT` readable without `CAP_AUDIT_READ` or
`CAP_AUDIT_CONTROL`, and what does a non-privileged process get — `EPERM` on bind, on send, or a
reply?**

No. It needs **`CAP_AUDIT_CONTROL`** — `CAP_AUDIT_READ` is not sufficient and is not even
consulted on this path. A non-privileged process gets **no syscall failure at all**: `socket()`
succeeds, `bind(groups=0)` succeeds, `sendto()` succeeds, and the kernel replies with an
**`NLMSG_ERROR` carrying `-EPERM`** (or `-ECONNREFUSED` in a user namespace, deliberately, to
imitate a kernel built without audit). §1.

**2. Does any procfs/sysfs surface expose it?**

No. There is no sysctl, procfs, debugfs or securityfs entry for `audit_enabled` anywhere in
`kernel/audit.c` or `kernel/auditsc.c`. `/proc/self/loginuid` proves `CONFIG_AUDIT=y` and nothing
more; `/proc/cmdline` gives the boot-time default that any later `AUDIT_SET` overrides;
`/proc/net/netlink` reveals that a listener joined the audit multicast group, which is two
defaults away from the fact. **#23 §5.1's guess at a `/proc/self/…` field is corrected: no such
file exists.** #29's `/sys/kernel/security/lsm` claim is **re-verified from source and confirmed**,
with the one added caveat that `securityfs` must be mounted. §2.

**3. Is journal-record presence an acceptable proxy, and what does it cost?**

It is a **sound one-way oracle and an unusable precondition probe**. A record proves
`audit_enabled != 0`, because `landlock_log_denial()` early-returns on `!audit_enabled`. Absence
proves nothing: six distinct causes collapse into it. The deeper cost is structural — the
behavioural probe sits *downstream* of the other three preconditions, so it measures the
conjunction and cannot isolate this term. It also writes to the operator's audit log every time it
runs. §4.

**4. If there is no unprivileged read path, what does ADR 0007's "probe each precondition and
refuse with a distinct code" degrade to?**

To **three probed preconditions plus a channel self-test**, with a new outcome class — the
ticket's first candidate, sharpened. Not to "best-effort", which is ADR 0007's own named failure
(*"an empty trace file that means 'unsupported' reads as 'nothing was denied'"*) and which would
make #29's `R-trace-denials` suite row unassertable. The self-test provokes a known denial and
looks for its record; its failure emits `refusal.trace.channel-silent`, whose basis is an
**observation** ("no record appeared") and not an **inference** ("auditing is off") — which is
what ADR 0016 actually forbids. It runs on every `--trace-denials` and is never cached, by ADR
0006's argument that every cache key is a guess that fails open and silently. And it narrows #23:
denial visibility is **not** purely a fixable dependency-version asymmetry — it has a permanent
component, namely that **macOS's denial channel is certifiable *a priori* and Linux's only *a
posteriori***. §5.
