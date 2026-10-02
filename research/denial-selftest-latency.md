# Denial-channel self-test: latency and false-negative rate

Research output for [#34](https://github.com/firefly-engineering/playpen/issues/34)
(graduated from [#32](https://github.com/firefly-engineering/playpen/issues/32); parent:
[#1](https://github.com/firefly-engineering/playpen/issues/1)).

**Question.** [#32](https://github.com/firefly-engineering/playpen/issues/32) reduced
[ADR 0007](../docs/adr/0007-playpen-owns-the-half-the-kernel-cannot-know.md)'s fourth precondition,
`audit_enabled`, to a **channel self-test**: provoke a known Landlock denial, look for its record,
and emit `refusal.trace.channel-silent` if none appears. That trades an inference for an
observation (the trade [ADR 0016](../docs/adr/0016-the-suite-defines-the-backend-and-an-assertion-that-can-pass-vacuously-is-a-defect.md)
requires), but the observation needs a **timeout**. This report asks four things:

- how long the record takes to become queryable, and what the tail looks like;
- how `auditd` and the kmsg-only path change that;
- whether `AUDIT_FILTER_EXCLUDE` or backlog overflow can silently swallow the record;
- whether the self-test's own denial can be told apart from an agent's.

**Method.** Unlike [#32](https://github.com/firefly-engineering/playpen/issues/32), this ticket was
**measured**:

- **Measurement host.** A throwaway full VM under `tart` 2.32.1 on the macOS research host. The
  image was `ghcr.io/cirruslabs/ubuntu:latest`: Ubuntu **24.04.5 LTS**, kernel
  **`7.0.0-34-generic`** (HWE), aarch64, 4 vCPU and 4 GiB.
- **The VM meets the bar.**
  - `CONFIG_AUDIT=y` and `CONFIG_AUDITSYSCALL=y` (from `/boot/config-*`).
  - `landlock` is active in `/sys/kernel/security/lsm`.
  - `landlock_create_ruleset(NULL, 0, VERSION)` returned **ABI 8**.
  - The probe ran in the **initial user and PID namespaces**, which matters because a container
    breaks audit (#32 §1.4).
- **OrbStack was tried first and rejected.** Its 7.0 kernel has Landlock but **no `CONFIG_AUDIT`**:
  no `CONFIG_AUDIT` line in `/proc/config.gz` and no `/proc/self/loginuid`.
- **Cleanup.** The VM and the pulled image were deleted afterwards.
- **What this VM is not.** It is **not** the hosted `ubuntu-24.04` runner. That ships
  `6.17.0-azure` on x64 ([#29](https://github.com/firefly-engineering/playpen/issues/29) §1.1), and
  its audit and journald configuration were **not** observed (§7).
- **Source read** (fetched 2026-10-02):
  - Linux `kernel/audit.c` at **`v7.0`**. The drop paths below were diffed against **`v6.15`** and
    **`v6.17`** and are semantically identical: only `audit_log_start()`'s timestamp plumbing
    differs, and `v7.0` split the rate check out of `audit_log_end()` into `__audit_log_end()`.
  - Linux `security/landlock/audit.c` and `kernel/printk/printk.c` at `v7.0`.
  - systemd **`v255`** (the version Ubuntu 24.04 ships, `255.4-1ubuntu8.17` in the VM):
    `journald-server.c`, `journald-audit.c`, `sd-event.c` and `journal-file.c`.
  - systemd `main` at `00e99d93`: `journald-manager.c`.
- **Instrument.** The programs are in
  [`research/denial-selftest-latency/`](denial-selftest-latency/), and the raw CSVs are in
  [`data/`](denial-selftest-latency/data/).
  - [`probe.c`](denial-selftest-latency/probe.c) forks a child. The child names itself
    `pp-selftest`, enters a fresh Landlock domain that handles `READ_FILE` with no rules, using
    `restrict_self` flags `0` (ABI ≥ 7 logs same-exec denials by default). It takes a
    `CLOCK_REALTIME` stamp **immediately before** `open()` on a marker file whose name is a
    per-iteration **nonce**, gets `EACCES`, and returns the stamp.
  - The parent then waits for a record carrying the nonce through one of four readers:
    - `jpoll`: `sd_journal_next()` every 1 ms;
    - `journal`: `sd_journal_wait()`, the inotify wake-up;
    - `journalctl`: re-run `journalctl -g NONCE` every 50 ms, the naive implementation;
    - `kmsg`: read `/dev/kmsg`.
  - It records reader-observed latency. For journal readers it also records the entry's own
    `__REALTIME_TIMESTAMP` minus T0, which is the **kernel→journald** leg.
  - [`flood.c`](denial-selftest-latency/flood.c) is the "busy host": *N* processes, each in its own
    domain, hammering denied `open()`s.
  - [`summarize.py`](denial-selftest-latency/summarize.py) produces the tables.

Provenance tags, as in `audit-enabled-probe.md`:

| Tag | Meaning |
|---|---|
| **[MEASURED]** | Executed in the VM described above; numbers are from `data/` |
| **[SRC]** | Read from upstream source at a named tag, with file:line |
| **[DOC]** | Stated in a first-party primary source (unit file, man page) |
| **[INFERRED]** | My composition of measured and source-read facts; not directly verified |
| **[UNMEASURED]** | Not executed; named, never guessed |

---

## 0. Bottom line

**Latency is a non-problem. Loss is the whole problem, and no timeout fixes loss.** When a record
is delivered at all, it is queryable within milliseconds. When it is not, it is gone, often with no
counter recording the drop.

1. **Delivered latency [MEASURED].**
   - **Kernel→journald:** p50 **0.03–0.8 ms**, p99 **≤ 1.7 ms** across every configuration.
   - **Polling reader** (`sd_journal_next()` every 1 ms): 1,326 delivered records, p99
     **≤ 2.9 ms**, worst **13.9 ms**.
   - **`sd_journal_wait()`** (the obvious API): a different shape. Bimodal, with the slow mode at
     **492–504 ms**, because journald debounces its reader wake-ups on a 250 ms timer (§2.2).
   - **Re-running `journalctl` every 50 ms:** worst **9 ms**, so cheap enough.
   - **Recommended timeout: 1 s, polled.** That is 2× the worst inotify case and about 70× the worst
     polled case. Nothing longer buys anything: no delivered record took more than 504 ms, and a
     lost record never arrives.

2. **The kmsg-only path loses records by construction, and silently [MEASURED, SRC].**
   - With `audit_enabled=1` and nothing listening on the audit netlink socket (no `auditd`, and
     journald's audit socket off), records reach the journal only via `printk`.
   - That `printk` is gated on the **kernel-wide `printk_ratelimit()` budget: 10 messages per 5 s**,
     shared with every other caller.
   - Back-to-back self-tests found their record **50–60 %** of the time.
   - A background "agent" making **5 denials/s** cut a spaced self-test to **18/30**.
   - **`auditctl -s` reported `lost 0` throughout.** The only trace is a
     `kauditd_printk_skb: N callbacks suppressed` line in the ring buffer.
   - A self-test that *passes* on this path certifies nothing about the agent's trace, which is
     throttled to about 2 records/s. That is under one denial per second, since each denial emits
     about 3 records.
   - **Recommendation: refuse the kmsg-only path outright with its own code**, rather than time out
     on it (§5.2). The self-test can *observe* which path it is on: the journal entry's
     `_TRANSPORT` is `kernel`, not `audit`.

3. **Ubuntu 24.04's defaults put a stock host on the silent or lossy path [MEASURED].**
   - The image boots with **`audit_enabled=0`** (`audit: initializing netlink subsys (disabled)`)
     and **`systemd-journald-audit.socket` disabled** (journald logs *"Collecting audit messages is
     disabled"*).
   - **Stock host:** the self-test correctly reports `channel-silent` (0/8).
   - **`auditctl -e 1` alone:** the kmsg-only path.
   - **`auditd` installed:** records go **only** to `/var/log/audit/audit.log` (`root:adm 0640`)
     and **never** reach the journal (0/10).
   - **The working configuration is `systemctl enable systemd-journald-audit.socket`.** journald
     then also turns `audit_enabled` on at boot, and with or without `auditd` it gave **500/500**.
   - This **corrects ADR 0007's** *"on a journald host the records reach the ordinary system
     journal"*: true only with that socket unit enabled, which is not the default.

4. **Two further silent-loss mechanisms on the working path [MEASURED, SRC].**
   - **Backlog overflow.**
     - Landlock logs with `GFP_ATOMIC`, so when the kernel queue exceeds `audit_backlog_limit`,
       `audit_log_start()` returns `NULL` without waiting.
     - Under an unthrottled 4-process flood with the kernel default `backlog_limit=64`, the
       self-test found **88/150**.
     - This one *is* counted (`lost=988 459`), but reading that counter needs `CAP_AUDIT_CONTROL`
       (#32).
   - **journald's audit ingest can wedge permanently.**
     - With `auditd` running (`backlog_limit=8192`), the same flood overran journald's netlink
       receive buffer.
     - journald's handler treats the resulting `EPOLLERR` as fatal, and sd-event **disables the
       event source for good**.
     - The self-test then found **0/150 during the flood, 0/5 idle afterwards, and 0/20 after
       `systemctl restart systemd-journald`**: the socket-activated fd comes back still in error.
     - Only recreating `systemd-journald-audit.socket` recovered it (20/20).
     - The code is unchanged on systemd `main`.
   - **`AUDIT_FILTER_EXCLUDE`.**
     - `-a always,exclude -F msgtype=1423` drops the record (0/10), and so does an `exe=` rule
       matching the probe's binary (0/10). Neither touches `lost`.
     - Excluding `msgtype=1424` or an unrelated `exe` does not affect it (10/10 each).
     - An unprivileged user cannot list the rules: `AUDIT_LIST_RULES` needs `CAP_AUDIT_CONTROL`
       (#32), and `/etc/audit` is `0750 root:root`.

5. **The self-test's record is distinguishable from an agent's, structurally rather than by
   pattern [MEASURED].**
   - Every `LANDLOCK_ACCESS` record carries the **domain id** of the domain that denied.
   - The self-test's domain is a fresh one that playpen created, never the agent's.
   - The paired `LANDLOCK_DOMAIN status=allocated` record binds that id to the **pid, exe and
     comm** of the task that called `landlock_restrict_self()`.
   - The access record also carries the nonce path.
   - `--trace-denials` therefore filters on domain id, which needs an audit-record **tokenizer**,
     not a regex (§4).

**What follows for ADR 0007.** The self-test stays, but it needs three changes:

- It must **poll** with a 1 s budget.
- It must **observe the transport** and refuse `kernel`-transport delivery as lossy.
- It must **bracket** the run, re-running after the agent exits, because the channel can die
  mid-run (journald wedge) and a pre-launch pass cannot see that.

That last change is what makes an empty trace honest, and it is the a-posteriori asymmetry
[#32](https://github.com/firefly-engineering/playpen/issues/32) named, now concrete.

---

## 1. The measurement matrix

All figures **[MEASURED]**. "found" is records seen within the timeout (1–5 s per run, given per
row in §2–§3). Latencies are reader-observed and are for **found** records only. Percentiles are
nearest-rank.

| Run (`data/…csv`) | Config | n | found | reader p50 / p90 / p99 / max (ms) | kernel→journald p50 / p99 / max (ms) |
|---|---|---|---|---|---|
| `s1-jpoll-spaced` | S1 kmsg-only, 5.5 s apart | 40 | **40** | 1.32 / 1.52 / 2.45 / 2.45 | 0.77 / 1.36 / 1.36 |
| `s1-jpoll-b2b` | S1, back-to-back | 200 | **120** | 1.31 / 2.26 / 2.40 / 13.92 | 0.69 / 1.33 / 13.49 |
| `s1-journal-b2b` | S1, `sd_journal_wait` | 200 | **100** | 492.16 / 501.03 / 502.35 / 503.26 | 0.73 / 1.66 / 15.62 |
| `s1-load0.5hz` | S1 + agent at 0.5 denial/s | 20 | **20** | 1.37 / 1.48 / 2.55 / 2.55 | 0.85 / 1.36 / 1.36 |
| `s1-load5hz` | S1 + agent at 5 denials/s | 30 | **18** | 1.49 / 1.64 / 2.60 / 2.60 | 0.59 / 1.55 / 1.55 |
| `s2-jpoll-b2b` | S2 journald audit socket, no auditd | 500 | **500** | 0.06 / 0.10 / 1.33 / 1.38 | 0.03 / 0.10 / 0.16 |
| `s2-journal-b2b` | S2, `sd_journal_wait` | 200 | **200** | 0.09 / 0.15 / 346.19 / 494.16 | 0.04 / 0.11 / 0.12 |
| `s2-journalctl-b2b` | S2, `journalctl -g` every 50 ms | 100 | **100** | 7.52 / 8.45 / 8.64 / 9.05 | — |
| `s2-kmsg-b2b` | S2, reading `/dev/kmsg` | 100 | **37** | 0.13 / 0.20 / 0.31 / 0.31 | — |
| `s2-loadmax` | S2 + 4-proc unthrottled flood, backlog 64 | 150 | **88** | 1.38 / 1.60 / 2.84 / 7.08 | 0.72 / 1.42 / 1.64 |
| `s3-jpoll` | S3 auditd, journald audit socket **off** | 10 | **0** | — | — |
| `s3-kmsg` | S3, `/dev/kmsg` | 5 | **0** | — | — |
| `s4-jpoll-b2b` | S4 auditd + journald audit socket | 500 | **500** | 0.08 / 0.13 / 0.22 / 1.36 | 0.03 / 0.09 / 0.17 |
| `s4-journal-b2b` | S4, `sd_journal_wait` | 200 | **200** | 0.16 / 0.30 / 502.10 / 503.87 | 0.06 / 0.18 / 0.30 |
| `s4-loadmax` | S4 + 4-proc unthrottled flood, backlog 8192 | 150 | **0** | — | — |
| `s4-postwedge-idle` | S4 after flood ended, idle | 5 | **0** | — | — |
| `s4-after-journald-restart` | `systemctl restart systemd-journald` | 20 | **0** | — | — |
| `s4-after-socket-restart` | socket unit recreated | 20 | **20** | 0.17 / 1.25 / 1.45 / 1.45 | 0.06 / 0.20 / 0.20 |
| `x-exclude-1423` | S4 + `-a always,exclude -F msgtype=1423` | 10 | **0** | — | — |
| `x-exclude-1424` | S4 + exclude `msgtype=1424` | 10 | **10** | 0.09 / 0.12 / 1.16 / 1.16 | 0.04 / 0.05 / 0.05 |
| `x-exclude-exe-probe` | S4 + exclude `exe=<probe binary>` | 10 | **0** | — | — |
| `x-exclude-exe-other` | S4 + exclude `exe=/usr/bin/true` | 10 | **10** | 0.20 / 1.26 / 1.32 / 1.32 | 0.05 / 0.18 / 0.18 |
| `x-unpriv-reader` | S4, reader not in `systemd-journal`/`adm` | 3 | **0** | — | — |

The stock-image baseline (S0, `audit_enabled=0`) gave 0/5 on `journal` and 0/3 on `kmsg`, with the
denial itself confirmed (`errno=13`). It was run before the CSV directory existed and is reported
from the console.

Configurations, each reached by reboot so the kernel audit state was pristine:

- **S0** stock image: `audit_enabled=0`, no auditd, `systemd-journald-audit.socket` disabled.
- **S1** S0 plus `auditctl -e 1` (`backlog_limit` stays at the kernel default 64; `auditd` installed
  only for the `auditctl` binary, then `disable --now`'d before the reboot).
- **S2** `systemctl enable systemd-journald-audit.socket`, no auditd. After the reboot,
  `audit_enabled=1` was set by journald itself (§3.1).
- **S3** `auditd` enabled (it sets `backlog_limit 8192`), journald audit socket disabled.
- **S4** `auditd` **and** journald audit socket enabled.

---

## 2. Latency

### 2.1 The kernel→journald leg is sub-millisecond on every path that delivers

**[MEASURED]** p50 0.03–0.06 ms via the audit netlink multicast (S2, S4). Via kmsg it is
0.6–0.85 ms (S1); the extra time is `printk` plus journald's `/dev/kmsg` reader. p99 is ≤ 1.7 ms
everywhere. The two outliers above 10 ms (13.5 and 15.6 ms) are both on the kmsg path. Under an
unthrottled flood saturating all four vCPUs, the delivered records' p99 stayed at **1.42 ms**
(`s2-loadmax`).

**[SRC]** The record is built and queued **synchronously inside the denied syscall**.
`landlock_log_denial()` calls `audit_log_start()`/`audit_log_end()` in the hook
(`security/landlock/audit.c:420-428` at `v7.0`). `audit_log_end()` queues the skb and wakes
`kauditd` (`kernel/audit.c:2793-2807`). `kauditd_thread()` multicasts it to
`AUDIT_NLGRP_READLOG` listeners (`kauditd_send_multicast_skb()`, `:847-876`, called from
`:931-934`). So the only latency is one kthread wake-up plus journald's own epoll turn.

### 2.2 The reader is the tail, and `sd_journal_wait()` is the wrong reader

**[MEASURED]** With `sd_journal_wait()` the reader-observed distribution is bimodal:

- **Fast mode, about 0.1 ms:** the record was already written when the reader first looked.
- **Slow mode at 492–504 ms:** the reader slept on inotify first.

On the kmsg path (S1) every sample fell in the slow mode, because the record is about 0.7 ms
behind T0. On the netlink path, 8 of 200 (S2) and 8 of 200 (S4) did.

**[SRC]** journald does not notify readers on every write. It arms a **post-change timer** at
`POST_CHANGE_TIMER_INTERVAL_USEC (250*USEC_PER_MSEC)` (systemd `v255`, `journald-server.c:78`,
armed at `:309`). When the timer fires it `ftruncate()`s the file to its own size purely to
generate an `IN_MODIFY` (`journal-file.c:2400-2406`, comment: *"trigger IN_MODIFY by truncating
the journal file to its current size"*). A sleeping reader is woken by that, not by the write. The
measured ceiling of about 500 ms is two timer periods. **[INFERRED]**: I did not trace why it is two
and not one, and the timer interval is an internal constant, not a documented bound.

**A polling reader avoids it entirely [MEASURED]:** `sd_journal_next()` every 1 ms sees the entry
as soon as journald has appended it to the shared mapping. Over the 1,326 delivered records
measured with `jpoll`:

- p99 ≤ 2.9 ms in every run;
- worst case 13.9 ms, the single kmsg-path outlier above;
- worst case 1.45 ms excluding the kmsg path.

The naive implementation (re-exec `journalctl -g NONCE` every 50 ms) costs about 7.5 ms per
invocation and had a worst case of 9.05 ms.

### 2.3 Recommended timeout: **1 s**, with a polling reader

- **Measured tail.** The worst delivered record took 13.9 ms polled, 503.9 ms on inotify and 9 ms
  on journalctl. A **1 s** budget is about 70× the polled tail and 2× the inotify ceiling, so even
  an implementation that drifts onto `sd_journal_wait()` stays correct.
- **No longer timeout helps.** Every miss in §1 is a *loss* (§3), not a late arrival. The
  mechanisms that drop the record never deliver it later:
  - `printk_ratelimit` discards;
  - `audit_log_start()` returns `NULL`;
  - journald's source is off.

  Doubling the timeout doubles the cost of a true refusal and recovers nothing.
- **Caveat [INFERRED].** This VM is an aarch64 guest on Apple silicon, not an Azure x64 runner.
  The *shape* (sub-ms kernel leg, a reader-dominated tail, loss rather than lateness) comes from
  source-level mechanisms that do not depend on the host. The absolute milliseconds are from one
  host. §7 has the CI job that would repeat them on `ubuntu-24.04`.
- **What a 1 s timeout does not cover.** A self-test that runs *while* the host is under a backlog
  storm can still lose its record (§3.3). Retrying once is cheap, and in `s2-loadmax` the misses
  were periodic rather than consecutive once the initial saturation passed. But retries do not
  change the design conclusion: the cure for loss is choosing a path that does not lose, and
  bracketing the run (§5).

---

## 3. False negatives: every way the record vanishes

### 3.1 The stock configuration: `audit_enabled=0`, so the self-test is *right* to refuse

**[MEASURED]** The image boots with `audit: initializing netlink subsys (disabled)` and
`audit: type=2000 … state=initialized audit_enabled=0`. `systemd-journald[297]` logs *"Collecting
audit messages is disabled."* The probe's `open()` returned `EACCES` and no record appeared on any
reader (0/5 journal, 0/3 kmsg). `landlock_log_denial()` early-returns on `!audit_enabled`
(`security/landlock/audit.c:405`) **[SRC]**.

AppArmor's `type=1400` records *do* appear in the same boot's ring buffer, because AppArmor does
not gate on `audit_enabled`. So "I see audit records in dmesg" is **not** evidence that Landlock's
will appear.

**The unit file explains the default [DOC, MEASURED]:** `systemd-journald-audit.socket`
(`ListenNetlink=audit 1`, `ReceiveBuffer=128M`) is **`disabled`** on this image. When it is enabled,
journald's `server_open_audit()` issues `enable_audit(fd, true)` if `Audit=` is set (`v255`,
`journald-audit.c:544-552`) **[SRC]**. After enabling the unit and rebooting, `auditctl -s` showed
`enabled 1` with `auditd` inactive, and journald logged *"Collecting audit messages is enabled."*
**[MEASURED]**. **One `systemctl enable` is therefore the operator remedy for S0, S1 and S3
together**, and it is the line `refusal.trace.channel-silent` should print.

### 3.2 The kmsg-only path (S1): the shared `printk` budget, silently

**[SRC]** With no `auditd` registered, `kauditd_thread()` passes every record to
`kauditd_hold_skb()` (`kernel/audit.c:931-934` → `:618-653`). That calls `kauditd_printk_skb()`:

```c
	if (nlh->nlmsg_type != AUDIT_EOE && printk_ratelimit())
		pr_notice("type=%d %s\n", nlh->nlmsg_type, data);
```
(`kernel/audit.c:581-588` at `v7.0`, `:540-547` at `v6.15`/`v6.17`, byte-identical)

Then, since `audit_default` is 0 (no `audit=1` on the command line), it drops the skb at
`goto drop` **without calling `audit_log_lost()`** (`:625-626`). `printk_ratelimit()` is the
**global** limiter `DEFINE_RATELIMIT_STATE(printk_ratelimit_state, 5 * HZ, 10)`
(`kernel/printk/printk.c:4735`), shared by every `printk_ratelimit()` caller in the kernel. The VM
reported `kernel.printk_ratelimit=5` and `kernel.printk_ratelimit_burst=10` **[MEASURED]**.

**[MEASURED]**:

- **Each self-test costs about 5 records:** `LANDLOCK_ACCESS`, `LANDLOCK_DOMAIN` allocated,
  `SYSCALL`, `PROCTITLE`, and `LANDLOCK_DOMAIN` deallocated. The `SYSCALL`/`PROCTITLE` pair appears
  because `audit_log_start()` clears the task's dummy context (`kernel/audit.c:1966-1967`).
- **Every `sudo` adds 4–7 PAM records.** So **two self-tests in five seconds can exhaust the
  budget**.
- Back-to-back runs showed a strict periodic pattern: 3 found, 2 missed (`s1-jpoll-b2b`: misses at
  iterations 2,3,7,8,12,13,…). The missed iterations' 3 s timeouts refill the 5 s window.
- With an agent making 5 denials/s: 18/30. At 0.5/s: 20/20.
- **`auditctl -s` showed `lost 0` after every S1 run.** dmesg showed only
  `kauditd_printk_skb: 19 callbacks suppressed` and similar lines.

**[INFERRED]** On this path the self-test's verdict is a coin whose bias depends on the last 5 s of
*unrelated* kernel activity. Worse, a **pass** says nothing about the trace that follows. The
agent's denials share the same 2 records/s budget, so `--trace-denials` would silently lose
everything above about 0.7 denials/s. That is ADR 0007's silent-empty-trace failure in a
partially-empty form. A timeout cannot fix it. See §5.2 for the refusal.

### 3.3 Backlog overflow (`audit_log_start()` → `NULL`)

**[SRC]** Landlock allocates with `GFP_ATOMIC | __GFP_NOWARN` (`security/landlock/audit.c:113` and
`:420`). In `audit_log_start()` the backlog loop sleeps only `if (gfpflags_allow_blocking(gfp_mask)
…)`. For an atomic caller it goes straight to `audit_log_lost("backlog limit exceeded"); return
NULL;` (`kernel/audit.c:1927-1955`). So a Landlock denial **never waits** for the queue to drain.
Every one that lands while `skb_queue_len(&audit_queue) > audit_backlog_limit` is dropped. The
kernel default is `audit_backlog_limit = 64` (`:131`); `auditd`'s shipped rules raise it to 8192
**[MEASURED]**.

**[MEASURED]** In S2 (`backlog_limit 64`), 4 flooding processes made about 54 M denials in 100 s:

- The self-test found **88/150**. The first 18 iterations were all lost while the flood ramped,
  then every third.
- Afterwards `lost 988459`, `backlog_wait_time_actual 100300`, and dmesg showed
  `audit: backlog limit exceeded`.
- **This drop is counted**, unlike §3.2, but the counter is behind `CAP_AUDIT_CONTROL` (#32 §1.4),
  so playpen cannot read it.

### 3.4 journald's audit ingest wedges permanently on overrun (S4)

This was not on the ticket's list, and it is the sharpest finding here.

**[MEASURED]** In S4 (`auditd` + journald audit socket, `backlog_limit 8192`) the same flood:

- About 1 s in, journald logged
  `systemd-journald[300]: Got invalid event from epoll for datagram fd: 9`.
- `/proc/net/netlink` showed journald's audit socket (portid 1, group `00000001`) with
  **`Rmem 268435200`** (the 2 × 128 MiB `ReceiveBuffer=` full) and **29 691 730 `Drops`**.
- Self-test: **0/150 during the flood and 0/5 once idle.**
- **After `systemctl restart systemd-journald`: 0/20.** The new journald logged the same line
  within a second, and `/proc/net/netlink` showed the *same* socket inode (3631) still full.
- Only stopping and restarting **`systemd-journald-audit.socket`** recovered it: new inode 13803,
  20/20.
- Meanwhile `auditd` received the records throughout (137 `ppst-` records in `audit.log`).

**[SRC]** `revents = 9` is `EPOLLIN|EPOLLERR`: netlink raises `ENOBUFS` on the socket when a
multicast is dropped for a full receive buffer. journald's datagram handler rejects anything but a
bare `EPOLLIN`:

```c
        if (revents != EPOLLIN)
                return log_error_errno(SYNTHETIC_ERRNO(EIO),
                                       "Got invalid event from epoll for datagram fd: %" PRIx32,
                                       revents);
```
(systemd `v255` `src/journal/journald-server.c:1447-1450`, and unchanged on `main` at `00e99d93`
in `src/journal/journald-manager.c:1522-1525`)

sd-event's dispatcher disables any source whose callback returns negative:
`else if (r < 0) assert_se(sd_event_source_set_enabled(s, SD_EVENT_OFF) >= 0);` (`v255`
`sd-event.c:4274-4289`). Because the handler never calls `recvmsg()`, the socket's pending error
is never consumed, so a fresh journald handed the same fd by PID 1 trips again immediately.
**[INFERRED]**: `sock_error()` is cleared on receive, and the handler bails before receiving.

A GitHub search of `systemd/systemd` issues for the log string and for "journald audit ENOBUFS"
returned nothing. **Whether this is known upstream is unestablished.**

**Why it matters to playpen [INFERRED].** The wedge can happen **mid-run**: an agent that denies in
a tight loop is the flood. After that every later record is lost, including the agent's, until the
socket unit is recreated, and no counter playpen can read records the loss. A pre-launch self-test
cannot see a failure that begins after launch. **Only a self-test run after the agent exits can.**

S2 did not wedge under the same flood: its 64-entry backlog throttled the kernel side before
journald's buffer filled. **[INFERRED]**: the wedge needs a producer that outruns journald with a
large kernel backlog, which `auditd`'s default `-b 8192` provides.

### 3.5 `AUDIT_FILTER_EXCLUDE`

**[SRC]** `audit_log_start()`'s second statement is
`if (unlikely(!audit_filter(type, AUDIT_FILTER_EXCLUDE))) return NULL;`
(`kernel/audit.c:1914-1915`), with **no** `audit_log_lost()` call.

**[MEASURED]**, in S4:

| Rule | found | `lost` changed? |
|---|---|---|
| `-a always,exclude -F msgtype=1423` | **0/10** | no |
| `-a always,exclude -F msgtype=1424` | 10/10 | — |
| `-a always,exclude -F exe=/home/admin/p/probe` | **0/10** | no |
| `-a always,exclude -F exe=/usr/bin/true` | 10/10 | — |

Two consequences:

- **Type-scoped exclusion** kills the self-test and the agent's trace together. The self-test
  catches it correctly, as `channel-silent`.
- **Process-scoped exclusion is asymmetric.** A rule written against the *agent's* `exe` (say
  `node`) drops the agent's records and not playpen's probe, because the probe's exe is the
  playpen binary. **[INFERRED]** Here a self-test pass can coexist with an empty agent trace, and
  playpen cannot read the rule list to tell: `AUDIT_LIST_RULES` needs `CAP_AUDIT_CONTROL` (#32
  §1.4), and `/etc/audit` is `0750 root:root` **[MEASURED]**.

  This is a **residual**: it belongs on the ledger, not in the self-test. Its likelihood is low
  (an operator deliberately silencing an agent's audit records), but it is not zero.

### 3.6 Reader permissions

**[MEASURED]** Run as the image's `admin` user, which is not in `systemd-journal` or `adm`, the
polling reader found 0/3. `sd_journal_open(SD_JOURNAL_SYSTEM)` opens only what the caller may read,
and `/var/log/journal` is `root:systemd-journal 2755` with an ACL. This is the reader-group
precondition [#23](https://github.com/firefly-engineering/playpen/issues/23) already listed. It is
noted here because it produces the same "no record" observation. **The self-test should check
journal readability first** (open the system journal and confirm it yields *any* kernel-boot
entry), so it does not report `channel-silent` for what is really a permissions problem.

---

## 4. Telling the self-test's denial from an agent's

**[MEASURED]** One self-test in S2 produced, in the journal (`_TRANSPORT=audit`):

```
AUDIT1423 domain=12ce059da blockers=fs.read_file path="/tmp/ppst-879-0-1790958192726245" dev="vda1" ino=3998
```

The same `audit(…:serial)` event also carries the `LANDLOCK_DOMAIN` allocation record, for example
(S1, kmsg transport):

```
audit: type=1424 audit(1790956979.941:137): domain=1c3c1d766 status=allocated mode=enforcing pid=887 uid=0 exe="/home/admin/p/probe" comm="pp-selftest"
```

**[SRC]** That record is written once per domain, on its first logged denial, and binds the domain
id to the restricting task's pid, exe and comm (`security/landlock/audit.c:104-131`). The domain id
is per-domain and assigned by the kernel. The self-test always runs in a **domain playpen just
created and that no agent code ever enters**.

So the self-test is distinguishable in three independent ways:

1. **Domain id.** Structural, and the one to use. The trace keeps only records whose `domain=`
   resolves, through its `status=allocated` record, to the agent's sandbox.
2. **Nonce path.** Useful for the self-test's own search: no parsing beyond a byte match, and a
   unique file per run.
3. **pid / comm.** Corroborating only. Pids recycle and comm is self-chosen.

Three implementation notes:

- **The domain-id route means parsing audit `key=value` records.** Per the house rule, and per
  ADR 0007's *"asserting against prose means the regex parsing this project has ruled out"*, that
  is a tokenizer for the audit record grammar, not a regex.
- **The same record can appear twice in the journal [MEASURED].** In S2, a record that
  `printk_ratelimit()` happened to let through also landed as `_TRANSPORT=kernel` (182 kernel-copy
  `type=1423` lines in that boot), beside the `_TRANSPORT=audit` copy. The trace should read
  `_TRANSPORT=audit` only, or de-duplicate on the `audit(<time>:<serial>)` stamp.
- **The self-test writes about 5 records to the operator's audit log on every launch [MEASURED].**
  That is the cost #32 §4 anticipated, now counted.

---

## 5. What this does to ADR 0007's self-test

### 5.1 The timeout

**1 s, read by polling** (`sd_journal_next()` in a short sleep loop, or re-running `journalctl`),
never `sd_journal_wait()` alone. Reasoning is in §2.3. Treat the 250 ms debounce as an
implementation detail of journald, not a contract, and do not tune against it.

### 5.2 Refuse the kmsg-only path on observation, with its own code

The self-test sees *which transport* delivered its record. The journal stamps `_TRANSPORT=audit`
for the netlink path and `_TRANSPORT=kernel` for the `printk` copy **[MEASURED]**. The
recommendation:

- record via `audit` → **pass**;
- record via `kernel` only → refuse as **lossy**, with a code distinct from `channel-silent`
  (say `refusal.trace.channel-lossy`). The remedy line is the same
  `systemctl enable systemd-journald-audit.socket`;
- no record → `refusal.trace.channel-silent`.

This is an *observation* ("the record arrived through the rate-limited ring buffer"), so it is
admissible under ADR 0016. Timing out on this path instead would make the refusal intermittent,
which is exactly the flake the ticket feared, and would let the lucky passes through to a trace
that drops most denials.

### 5.3 Bracket the run

Run the self-test **again after the agent exits**, and mark the trace as **unverified** if the
closing self-test fails. This is **[INFERRED]** from §3.3 and §3.4: a pre-launch pass proves the
channel *was* working, and the journald wedge shows it can stop working mid-run with no readable
signal. The closing self-test is the only unprivileged observation that covers the run itself. It
is still not proof of completeness. Backlog drops between two passing self-tests are invisible.

### 5.4 A possible completeness check (not measured)

`landlock_log_drop_domain()` emits `status=deallocated denials=N` when a logged domain is freed
(`security/landlock/audit.c:445-470`), and `num_denials` is incremented before every gate, including
`audit_enabled` and the log flags (`:395-403`) **[SRC]**. The probe's own domains showed
`denials=1` **[MEASURED]**.

Comparing *N* against the number of `LANDLOCK_ACCESS` records collected for the agent's domain
would detect loss **a posteriori**, which is stronger than the bracketing self-test. Three gaps:

- the deallocation record is itself subject to §3.2–§3.4;
- `N` also counts denials quieted by `LOG_SAME_EXEC_OFF`/`LOG_NEW_EXEC_ON` settings;
- the agent's domain is nono's, freed when the last task holding it exits.

**[UNMEASURED]**: worth its own ticket.

---

## 6. Verified / inferred / unmeasured

**Verified, measured or in source.**

- Delivered-record latency distribution on four readers (§1, §2).
- The stock Ubuntu 24.04 defaults: `audit_enabled=0` and the journald audit socket disabled (§3.1).
- journald enabling auditing when its socket is enabled (§3.1).
- `printk_ratelimit` loss, with `lost` unchanged (§3.2).
- Backlog loss for atomic callers (§3.3).
- The journald wedge and its recovery requirement (§3.4).
- Exclude-rule loss by type and by exe (§3.5).
- Reader-group gating (§3.6).
- Record shape and distinguishability (§4).

**Inferred.**

- Why the inotify ceiling is about 500 ms rather than 250 ms (§2.2).
- That the absolute figures transfer to an x64 Azure runner (§2.3).
- The mid-run wedge risk and the bracketing remedy (§3.4, §5.3).
- The agent-`exe` exclude residual (§3.5).
- The wedge's dependence on a large kernel backlog (§3.4).

**Unmeasured.**

- Everything on the hosted `ubuntu-24.04` runner. Whether its `audit_enabled` is 0 and its
  journald audit socket is disabled is **not** established: the image build scripts in
  `actions/runner-images` contain no `auditd` install (GitHub code search for `auditd` returned
  nothing), which is suggestive but not a measurement.
- `LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON` records after `execve`, which is the agent's real
  shape. The probe used the same-exec default. The delivery path after `audit_log_start()` is
  identical (`security/landlock/audit.c:409-428`), so the latency should be too, but that was not
  run.
- The `denials=N` completeness check (§5.4).

---

## 7. The CI job that would repeat this on `ubuntu-24.04` (not run)

Per the ticket's constraint, nothing was pushed or run on hosted CI. This is the job that would
repeat §1 on the runner kernel and, first, record the runner's untouched audit state. It assumes
the three files under `research/denial-selftest-latency/` and passwordless `sudo`, which hosted
runners have.

```yaml
name: denial-selftest-latency
on: workflow_dispatch
jobs:
  measure:
    runs-on: ubuntu-24.04            # repeat with ubuntu-24.04-arm
    steps:
      - uses: actions/checkout@v4
      - name: Baseline facts (no changes yet)
        run: |
          uname -r
          cat /sys/kernel/security/lsm; echo
          sudo dmesg | grep -E 'audit: (initializing|type=2000)' || true
          systemctl is-enabled systemd-journald-audit.socket || true
          systemctl is-active auditd || true
          awk '$2==9' /proc/net/netlink
      - name: Build
        working-directory: research/denial-selftest-latency
        run: |
          sudo apt-get install -y -qq libsystemd-dev auditd
          sudo systemctl disable --now auditd
          H=/usr/src/linux-headers-$(uname -r)/include/uapi/linux/landlock.h
          sudo apt-get install -y -qq linux-headers-$(uname -r)
          gcc -O2 -include "$H" -o probe probe.c -lsystemd
          gcc -O2 -include "$H" -o flood flood.c
      - name: S0 stock
        working-directory: research/denial-selftest-latency
        run: sudo ./probe -r jpoll -g 1 -n 5 -t 1000 | tee s0.csv
      - name: S1 kmsg-only
        working-directory: research/denial-selftest-latency
        run: |
          sudo auditctl -e 1 -b 64
          sudo ./probe -r jpoll -g 1 -n 200 -t 3000 > s1-b2b.csv
          sudo ./probe -r jpoll -g 1 -n 40 -s 5500 -t 3000 > s1-spaced.csv
      - name: S2 journald audit socket
        working-directory: research/denial-selftest-latency
        run: |
          sudo systemctl start systemd-journald-audit.socket
          sudo systemctl restart systemd-journald
          sudo ./probe -r jpoll -g 1 -n 1000 -t 3000 > s2-jpoll.csv
          sudo ./probe -r journal -n 300 -t 3000 > s2-journal.csv
          (sudo ./flood 4 60 &) ; sleep 2
          sudo ./probe -r jpoll -g 1 -n 100 -s 500 -t 5000 > s2-load.csv
          sudo auditctl -s; awk '$2==9' /proc/net/netlink
      - name: Summarise
        working-directory: research/denial-selftest-latency
        run: python3 summarize.py *.csv
      - uses: actions/upload-artifact@v4
        with: { name: denial-selftest-latency, path: research/denial-selftest-latency/*.csv }
```

The S2 step restarts journald in place rather than rebooting, which a hosted runner cannot do.
Whether journald then sets `audit_enabled` without a reboot is part of what the job would show.

---

## 8. The four bullets, answered directly

1. **Latency and its distribution.**
   - The kernel→journald leg has p50 under 1 ms and p99 ≤ 1.7 ms.
   - Reader-observed: polled p99 ≤ 2.9 ms (worst 13.9 ms); `sd_journal_wait` worst 504 ms;
     `journalctl` worst 9 ms.
   - **Timeout: 1 s, polled.** Misses are losses, not late arrivals.
2. **`auditd` present or absent, and the kmsg-only path.**
   - The stock Ubuntu image has auditing off and journald not listening.
   - Turning auditing on alone gives the **kmsg-only path, which loses silently** under the shared
     10-per-5 s `printk` budget.
   - `auditd` alone sends records **only** to `audit.log`, and the journal sees none.
   - journald's audit socket, with or without `auditd`, delivers 100 % when idle.
   - Refuse the kmsg path on observation (`_TRANSPORT=kernel`).
3. **`AUDIT_FILTER_EXCLUDE` and backlog overflow.**
   - Both swallow the self-test's record, and exclude rules do so without touching `lost`.
   - Backlog overflow drops atomic Landlock records immediately: 88/150 under flood at the default
     backlog. It *is* counted, in a counter playpen cannot read.
   - A **new third mechanism:** journald's audit ingest **wedges permanently** on receive-buffer
     overrun, and survives a journald restart (0/150, then 0/20). Hence the bracketing self-test.
4. **Distinguishability.** Yes, by **domain id**, joined to the `status=allocated` record's
   pid/exe/comm, with a nonce path for the self-test's own search. The trace should read
   `_TRANSPORT=audit` only, to avoid kmsg duplicates.
