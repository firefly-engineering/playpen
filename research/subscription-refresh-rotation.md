# Subscription refresh tokens: single-use rotation, and what a minter refresh does to a host login

Research output for [#33](https://github.com/firefly-engineering/playpen/issues/33)
(parent: [#1](https://github.com/firefly-engineering/playpen/issues/1)).

**Question.** [ADR 0018](../docs/adr/0018-playpen-authenticates-outside-the-boundary.md) makes
renewal the **minter**'s job: a minter that refreshes reads the host's own credential store,
performs the token exchange, and returns a fresh access token. The minter and a host-level agent
instance share that store. ADR 0018 records the resulting race as the seventh **named residual**
and leaves open whether it is *untidy* (refresh tokens reusable) or *hostile* (refresh tokens
rotated single-use, so a minter refresh without write-back logs the operator out of their own
desktop agent). For Claude Code's subscription login, and separately for `omp`:

1. Does a refresh response return a new `refresh_token`, and does presenting the old one fail?
2. What is the access-token TTL?
3. Are concurrent refreshes from two processes tolerated?
4. So what must a reference minter do about write-back, and does the residual need a shipped
   warning?

**Method, and a hard constraint.** Nothing here was measured against a token endpoint, and that
was deliberate. A refresh against the operator's real login is the exact hazard under study, so
**no token exchange was performed, no OAuth endpoint was called, and no credential was read**:
no Keychain item, no `~/.claude/.credentials.json`, no `~/.omp`. Evidence comes from:

- **The shipped Claude Code binary, 2.1.283**
  (`/opt/homebrew/Caskroom/claude-code@latest/2.1.283/claude`, Mach-O arm64, a Bun single-file
  executable whose JS is embedded as plain text). This was read-only static inspection: the
  binary was read as bytes and the minified JS around the OAuth code was extracted. The locators
  below are **byte offsets into that file**. Minified identifiers (`sce`, `Sa`, `v3n`, `k3n`)
  are given only so a reader can find the code again. They are not stable across versions.
- **Claude Code's first-party `CHANGELOG.md`** at
  [`anthropics/claude-code@52c7644`](https://github.com/anthropics/claude-code/blob/52c76441cae91f6891e4712306bffb057ff6fec5/CHANGELOG.md)
  (head 2.1.287, fetched 2026-10-02), and the
  [authentication docs](https://code.claude.com/docs/en/authentication), fetched 2026-10-02.
- **`omp` (oh-my-pi) source** at tag
  [`v17.3.4`](https://github.com/can1357/oh-my-pi/tree/ffd53ff92a6f575d499730475a73460dd7cc2eea)
  (`ffd53ff`). That is the version the earlier reports in this directory measured
  ([`bun-node-http-proxy.md`](bun-node-http-proxy.md)). It is no longer installed on this host.
  Also its CHANGELOGs and upstream issue
  [can1357/oh-my-pi#5396](https://github.com/can1357/oh-my-pi/issues/5396).
- **OpenAI Codex CLI source**,
  [`openai/codex@84d5437`](https://github.com/openai/codex/tree/84d5437b6e558f5159551949a35aedb84ddb89be),
  `codex-rs/login/src/auth/manager.rs`, because `omp`'s second subscription provider is ChatGPT.
- **RFC 6749 §6** and **RFC 9700 (OAuth 2.0 Security BCP) §2.2.2, §4.14.2**.

| Tag | Meaning |
|---|---|
| **[SRC]** | Read from shipped or published source: the 2.1.283 binary (byte offset), or a repo at a pinned commit (file:line) |
| **[DOC]** | Stated by the vendor in a first-party document: docs page, CHANGELOG, RFC |
| **[REPORTED]** | A third party's recorded production observation (issue body, code comment, changelog entry) that was **not reproduced here** |
| **[INFERRED]** | My composition of the above; not directly verified |
| **[UNMEASURED]** | Settleable only by an exchange against a real grant. Named, never guessed |

No claim in this report is **[MEASURED]**. §6 names the experiment that would settle each
remaining gap, and why it must run against a throwaway account.

---

## 0. Bottom line

**The race is hostile. Anthropic rotates subscription refresh tokens single-use, so a refreshing
minter that does not write back *will* log the operator out of their desktop Claude Code,
deterministically and within one access-token lifetime (~8 h). It is not a probabilistic race.
The reference minter should therefore not refresh the host's interactive login at all.**

1. **Rotation: yes, single-use.** No Anthropic document states it. Two independent clients
   engineer around it, and the vendor's own changelog names it:
   - Claude Code 2.1.283 persists a refresh only by **compare-and-set on the refresh token it
     posted** and adopts a sibling's write otherwise **[SRC]**.
   - On `invalid_grant` it **wipes the stored login** **[SRC]**.
   - Its changelog speaks of a *"freshly-rotated OAuth token"* (2.1.136) and of being
     *"unexpectedly logged out when an older Claude Code build … runs on the same machine"*
     (2.1.277) **[DOC]**.
   - `omp`'s changelog states flatly *"Anthropic rotates refresh tokens on every use"* (ai
     15.0.0) **[REPORTED]**.
   - The reused token's rejection is recorded verbatim as `400
     {"error":"invalid_grant","error_description":"Refresh token not found or invalid"}`
     **[REPORTED, oh-my-pi#5396]**.

   §1.
2. **Access-token TTL is ~8 h, and the grant dies at ~30 days.** Claude Code's changelog says the
   token refreshes *"8 hours after login"* (2.1.86) **[DOC]**. `omp` independently records
   *"healthy 8h rotations"* **[REPORTED]**. It also records an absolute grant lifetime of ~30 days
   that rotation does not extend (`invalid_grant: "Refresh token expired"`) **[REPORTED]**.
   Claude Code reads `refresh_token_expires_in` and warns *"Your login expires in 3 days"*
   **[SRC] [DOC]**. Both clients refresh 5 minutes early **[SRC]**. §2.
3. **Concurrent refreshes are not tolerated. One wins and the loser gets `invalid_grant`.**
   - Claude Code serialises refresh across processes with a lock file, `~/.claude/.oauth_refresh.lock`.
   - Under the lock it re-reads the store and adopts a sibling's refresh instead of exchanging.
   - On a lost race it re-reads before declaring the token dead **[SRC]**.
   - `omp` grew the same machinery (a SQLite lease with re-read and CAS) after concurrent refreshes
     disabled Anthropic credentials "roughly daily" **[REPORTED]**.
   - The **winner's** new token appears to survive the loser's replay, so Anthropic does *not*
     seem to revoke the whole grant family on reuse, which RFC 9700 would permit **[INFERRED]**.

   §3.
4. **For `omp` the answer splits by provider.**
   - `omp`'s Anthropic login uses **Claude Code's own OAuth client id** against the same token
     endpoint path, so the same rotation applies **[SRC]**.
   - Its ChatGPT login rotates single-use too: Codex CLI maps a `refresh_token_reused` error code
     to *"your refresh token was already used"* **[SRC]**. But the access TTL is ~9–10 days
     **[REPORTED] [SRC]**, so the race is rare.
   - `omp` stores credentials in its **own** `~/.omp/agent/agent.db`. An `omp` minter races a
     host `omp`, never Claude Code. Each is a separate grant **[SRC] [INFERRED]**.

   §4.
5. **Write-back is not an optimisation, and "the operator's choice" understates it.** The
   options, in the order this report recommends them (§5):
   - **(a) A dedicated grant.** `claude setup-token` mints a one-year, inference-only token with
     no refresh token **[DOC]**. The minter becomes a trivial keystore lookup and the race
     disappears. As a bonus the token lacks `org:create_api_key`, so ADR 0018's escalation
     endpoint is closed by scope as well as by the endpoint rule.
   - **(b) A read-only minter of the host login that never exchanges.** Reading is safe.
     Renewal is left to the host agent.
   - **(c) A refreshing minter.** It is safe **only** if it takes Claude Code's lock, re-reads
     under it, and CAS-writes back into Claude Code's private store format. That replicates a
     private, unversioned protocol whose concurrency handling has been fixed at least ten times in
     2.1.x (§3.3).

   A refreshing minter **without** write-back is a defect, not a choice. **A shipped warning is
   needed**, and it should be a refusal-grade statement in the reference minter's docs, not a
   footnote.

---

## 1. Q1: Does a refresh return a new `refresh_token`, and does the old one die?

### 1.1 What the standards allow

RFC 6749 §6: *"The authorization server MAY issue a new refresh token, in which case the client
MUST discard the old refresh token and replace it with the new refresh token. The authorization
server MAY revoke the old refresh token after issuing a new refresh token"* **[DOC]**.

RFC 9700 §2.2.2 narrows that for **public** clients: *"Refresh tokens for public clients MUST be
sender-constrained or use refresh token rotation as described in Section 4.14"* **[DOC]**. Claude
Code's subscription login is a public client. It is PKCE with no client secret: the refresh body
is `{grant_type, refresh_token, client_id, scope}` and carries no secret **[SRC, offset
178722339]**. No DPoP or mTLS appears on the refresh request **[SRC, same]**. An RFC
9700-conformant Anthropic therefore *has* to rotate **[INFERRED]**. That is a prior, not evidence.
The evidence follows.

### 1.2 Claude Code 2.1.283 is built around rotation

- **The refresh call** (`sce`, offset 178722339) destructures
  `{access_token, refresh_token: L = e, expires_in}`. It takes the **new** refresh token when one
  is present and falls back to the one it posted otherwise, and it records
  `refresh_token_expires_in` **[SRC]**. The fallback is defensive and proves nothing either way.
- **The save is compare-and-set on the posted refresh token** (`v3n`, offset 178679493). Inside
  `mutate`, it writes only if the stored `claudeAiOauth.refreshToken` is still the one this
  process posted (or `""`). Otherwise it sets `adopted_sibling`, keeps the sibling's credential,
  and emits `tengu_oauth_refresh_save_adopted_newer_write` **[SRC]**. Under reusable refresh
  tokens this CAS would be pointless. Under rotation it is the only thing that stops a slow
  writer from replacing a live refresh token with a dead one.
- **`invalid_grant` wipes the stored login** (`k3n`, offset 178682193). The token is added to an
  in-memory dead set, and **if the stored refresh token still equals the dead one**, the Keychain
  or credentials-file entry is rewritten to `refreshToken: "", accessToken: "", expiresAt: 0`
  (`tengu_oauth_refresh_token_cleared_on_disk`) **[SRC]**. **This is the mechanism by which a
  minter logs the operator out.** The minter never touches the host store. The host's next
  refresh presents the old token, gets `invalid_grant`, and erases its own login.

### 1.3 The vendor's changelog names rotation and the logout

From [`CHANGELOG.md@52c7644`](https://github.com/anthropics/claude-code/blob/52c76441cae91f6891e4712306bffb057ff6fec5/CHANGELOG.md)
**[DOC]**:

| Version | Entry |
|---|---|
| 2.1.81 | *"Fixed multiple concurrent Claude Code sessions requiring repeated re-authentication when one session refreshes its OAuth token"* |
| 2.1.126 | *"Fixed a rare race where a concurrent credential write could clear a valid OAuth refresh token"* |
| 2.1.129 | *"Fixed OAuth refresh race after wake-from-sleep that could log out all running sessions"* |
| 2.1.133 | *"Fixed parallel sessions all dead-ending at 401 after a refresh-token race wiped shared credentials"* |
| 2.1.136 | *"Fixed a rare login loop where a concurrent credential write could overwrite a **freshly-rotated** OAuth token and force re-login"* |
| 2.1.214 / 2.1.216 | *"…after the OAuth token **rotates**"* / *"…expired or **rotated** mid-session"* |
| **2.1.277** | ***"Fixed being unexpectedly logged out when an older Claude Code build (for example an IDE extension's bundled CLI) runs on the same machine as the current one"*** |
| 2.1.282 / 2.1.285 | Lock-holder crash recovery fixes (§3.3) |

The 2.1.277 entry is the closest thing to a published measurement of this ticket's hazard. A
**second refresher that does not follow the current client's protocol** logged the operator out,
and that second refresher was Anthropic's own older build.

### 1.4 The rejection of a reused token, verbatim

[oh-my-pi#5396](https://github.com/can1357/oh-my-pi/issues/5396) (opened against omp 16.1.5,
fixed by #5519) records the production response to a refresh with a token a sibling process had
already rotated **[REPORTED]**:

```
status=400; body={"error":"invalid_grant","error_description":"Refresh token not found or invalid"}
url=https://api.anthropic.com/v1/oauth/token
```

The same issue states: *"Anthropic OAuth refresh tokens are **single-use** (each refresh returns
a new refresh token and invalidates the previous one)."* It contrasts this with
`google-antigravity`'s *"reusable (non-rotating) refresh tokens"* **[REPORTED]**. `omp`'s
`packages/ai/CHANGELOG.md` [15.0.0] says it without hedging: *"Anthropic rotates refresh tokens
on every use, so the loser's `invalid_grant` response previously soft-deleted the row that the
winner just rotated"* **[REPORTED]**.

**Answer to Q1: yes, and yes.** Every refresh returns a new refresh token, and the old one is
rejected afterwards with `invalid_grant`. Anthropic does not document this. It is established by
two independent clients' code, the vendor's changelog, and a third party's verbatim production
error.

---

## 2. Q2: Access-token TTL

- **~8 hours.** Claude Code 2.1.86: *"[VSCode] Fixed extension defaulting Max plan users to Sonnet
  after the OAuth token refreshes (**8 hours after login**)"* **[DOC]**. `omp`'s
  `anthropic-constants.ts` (v17.3.4) cites *"healthy 8h rotations"*, and #5396 says *"Anthropic
  access token TTL ≈ 8h"* **[REPORTED]**. The client never hard-codes it. Both take `expires_in`
  from the response **[SRC]**, so the 8 h figure is server policy and can move.
- **Refresh point: 5 minutes before expiry** in both clients. Claude Code uses
  `EL(e) = now + 300000 >= e` (offset 178726680). `omp` stores `expires_in*1000 - 5*60*1000`
  (`anthropic.ts:332-340`) **[SRC]**. Claude Code also refreshes **reactively on 401**: changelog
  2.1.117 says *"the token is now refreshed reactively on 401"*, and 2.1.118 says *"…when the
  server revokes a token before its local expiry time"* **[DOC]**. So expiry is not the only trigger. The server can end an access
  token early.
- **Grant lifetime ~30 days, not extended by rotation.** `omp`'s `ANTHROPIC_OAUTH_GRANT_TTL_MS`
  doc comment says: *"~30 days after authorization the token endpoint returns `invalid_grant:
  "Refresh token expired"` for the latest rotated token … grants authorized 2026-06-20/06-25 died
  30d later to the hour despite healthy 8h rotations"*. Its changelog [17.1.4] adds *"across four
  production accounts"* **[REPORTED]**. Claude Code reads `refresh_token_expires_in` on both
  exchange and refresh (offsets 178722731, 195238484) **[SRC]**. Its docs promise a startup
  warning *"Your login expires in 3 days · run /login to renew"* **[DOC]**. That is consistent
  with a finite, absolute refresh-token lifetime **[INFERRED]**.
- **`claude setup-token`: one year, no refresh.** *"generate a one-year OAuth token with
  `claude setup-token` … It does not save the token anywhere … It can only make model
  requests"* **[DOC]**. In the binary, a `CLAUDE_CODE_OAUTH_TOKEN` credential is constructed with
  `refreshToken: null, expiresAt: null` and default scopes `["user:inference"]` (`QF`, near
  offset 178682193) **[SRC]**.

**What the TTL buys.** An 8 h access token means a typical run either starts with a valid token
or pays one refresh. It also means a minter refresh is followed by a host refresh **within at
most ~8 h** whenever a host Claude Code is running. The host-side failure in §1.2 is therefore
not rare. It is the expected outcome of every non-write-back minter refresh while the operator
keeps their desktop agent open **[INFERRED]**.

---

## 3. Q3: Concurrent refreshes

### 3.1 Not tolerated

Two processes presenting the same refresh token: the first exchange rotates it, and the second
gets `invalid_grant` (§1.4) **[REPORTED]**. No grace window for a just-rotated token is visible
in either client's handling, since both treat the loser's `invalid_grant` as needing recovery.
Its existence or absence is **[UNMEASURED]**.

### 3.2 Does the loser's replay kill the winner? Apparently not

RFC 9700 §4.14.2 describes reuse detection that *"will revoke the active refresh token"* when an
invalidated one is presented, which would kill the winner too **[DOC]**. Both clients' recovery
paths assume Anthropic does **not** do this:

- Claude Code, after a failed exchange, re-reads the store and, if the access token changed,
  returns `refreshed` (`tengu_oauth_token_refresh_race_recovered`). It continues on the sibling's
  tokens (`Sa`, offset ~178697740) **[SRC]**.
- `omp` [15.0.0] reloads the peer-rotated row and *"the request retries against the fresh token
  instead of disabling the live row"*, and this is shipped as a fix that works **[REPORTED]**.
  #5396 also observes that the stale side's **access** token *"still succeeded"* minutes later
  **[REPORTED]**.

So the observed blast radius of a lost race is **the loser's copy of the refresh token**, not the
grant family **[INFERRED]**. That matters for §5: a minter that loses a race strands only itself,
and the host is hurt only if the host is the loser and finds no newer write to adopt.

### 3.3 What Claude Code itself does

This is the protocol a co-operating refresher would have to join (2.1.283) **[SRC]**:

- **Lock**: `~/.claude/.oauth_refresh.lock`, or under `CLAUDE_SECURESTORAGE_CONFIG_DIR` /
  `CLAUDE_CONFIG_DIR` (`Bw`, `zun`; offsets 177866446, ~178697740). Options are
  `{realpath:false, stale:60000, update:5000, onCompromised}`, which is the `proper-lockfile`
  option shape **[INFERRED]**. There is also a **legacy** lock at `<realpath(dir)>.lock` taken in
  tandem (`UOo`), and an **owner record** (pid, process start time, pid namespace, lock birthtime)
  used for dead-holder takeover (`Mc`/`Ic`). Acquisition retries 5 times at 1–2 s jitter.
- **Under the lock**: it does a strict re-read. If the stored access token differs from the one it
  entered with, it returns `race_resolved` and does **not** exchange. It also checks the dead and
  on-hold sets, and that the lock has not been compromised, before posting.
- **After the exchange**: a CAS save (§1.2), up to 3 attempts. On `invalid_grant`: re-read, adopt
  a sibling's tokens if present, else clear the stored login (`k3n`).
- **Store**: macOS Keychain service `Claude Code-credentials`, suffixed with a sha256 prefix of
  the config dir when `CLAUDE_CONFIG_DIR` is set (`JL`, `hde="-credentials"`). The fallback is
  `~/.claude/.credentials.json` (0600). The key is `claudeAiOauth`, with fields `accessToken`,
  `refreshToken`, `expiresAt`, `refreshTokenExpiresAt`, `scopes`, `subscriptionType`,
  `rateLimitTier`, and `clientId` **[SRC] [DOC]**.

This protocol is **private and moving**. Its cross-process handling has been fixed at least
ten times across 2.1.x (2.1.0, 2.1.81, 2.1.126, 2.1.129, 2.1.133, 2.1.136, 2.1.248, 2.1.277,
2.1.282, 2.1.285), and the last three concern lock recovery alone **[DOC]**. 2.1.277 shows that a refresher speaking an *older* dialect of this same
protocol logs the user out.

---

## 4. `omp`

**What it is.** `omp` is oh-my-pi ([can1357/oh-my-pi](https://github.com/can1357/oh-my-pi)), a
single-file Bun agent ([`mechanism-capability-matrix.md`](mechanism-capability-matrix.md)). It
authenticates against many providers (`packages/ai/src/registry/oauth/`: anthropic,
openai-codex, github-copilot, google-gemini-cli, google-antigravity, cursor, kimi, xai, …). For
this ticket the subscription-login providers that matter are **Anthropic** and **OpenAI
(ChatGPT/Codex)**.

**Where it keeps credentials.** `~/.omp/agent/agent.db` (SQLite), table `auth_credentials`
(`packages/utils/src/dirs.ts:746-748`, `sqlite-credential-store.ts:741`) **[SRC]**. It does not
read or write Claude Code's Keychain item or `.credentials.json`: no reference in
`packages/ai/src` **[SRC]**.

### 4.1 Anthropic via `omp`

- **The same OAuth client as Claude Code.** `CLIENT_ID` is
  base64-decoded to `9d1c250a-e61b-44d9-88ed-5944d1962f5e` (`anthropic.ts:13`), identical to Claude
  Code's `CLIENT_ID` (binary offset 175685563) **[SRC]**. `omp` refreshes against
  `https://api.anthropic.com/v1/oauth/token` (`anthropic.ts:15`), while Claude Code 2.1.283 uses
  `https://platform.claude.com/v1/oauth/token`. Same path, different host **[SRC]**.
- **A separate grant.** `omp`'s `/login` runs its own PKCE authorization (`AnthropicOAuthFlow`), so
  an `omp` login and a Claude Code login are two grants on one client. Rotating one does not touch
  the other **[INFERRED]** (and consistent with §3.2's no-family-revocation reading).
- **Rotation, TTL, and concurrency are all as §1–§3**, since this is the same server and client
  **[REPORTED]** (#5396, ai CHANGELOG 15.0.0, 17.1.4). `refreshAnthropicToken` keeps
  `data.refresh_token || refreshToken` (`anthropic.ts:340`) **[SRC]**.
- **`omp`'s own concurrency protocol** (since #5519, coding-agent 17.0.1) **[SRC] [DOC]**: a
  durable per-credential **lease row** in `auth_credential_refresh_leases`
  (`sqlite-credential-store.ts:570`), with a 15 s TTL renewed every 5 s
  (`auth-storage.ts:726-728`). It re-reads under the lease and adopts a fresh peer copy
  (`refreshStoredOAuthCredential`, `auth-storage.ts:2390`). Persistence is CAS by row id and
  serialized data (`#replaceCredentialById`, `:2258`). This is **a different protocol from Claude
  Code's**, so a minter for `omp` would join a SQLite lease, not a lock file.

### 4.2 OpenAI (ChatGPT) via `omp`

- **Single-use rotation, by error code.** Codex CLI classifies refresh failures with
  `refresh_token_expired`, `refresh_token_reused` and `refresh_token_invalidated`, and maps
  *reused* to *"Your access token could not be refreshed because your refresh token was already
  used. Please log out and sign in again."* (`codex-rs/login/src/auth/manager.rs:207`, `:1688`)
  **[SRC]**. That is OpenAI's first-party client naming single-use reuse as a terminal state.
  `omp` refreshes at `https://auth.openai.com/oauth/token` and keeps
  `tokenData.refresh_token || refreshToken` (`openai-codex.ts:15`, `:379`) **[SRC]**.
- **TTL ~9–10 days.** #5396: *"`openai-codex`: access TTL ~9 days → refreshes rarely →
  effectively never races"* **[REPORTED]**. Codex CLI refreshes when the JWT `exp` is within 5
  minutes or when `last_refresh` is older than `TOKEN_REFRESH_INTERVAL = 8` days
  (`manager.rs:203`, `:3010-3022`) **[SRC]**. That is consistent with a TTL a little over 8 days
  **[INFERRED]**.
- **Implication:** the same hostile shape, but a ~30× rarer trigger. A minter refresh is needed
  only once every ~9 days, so the window is small but **not** zero.

---

## 5. What the reference minter must do

The minter shape in ADR 0018 stands. What changes is the guidance, and one sentence of framing.

**A refreshing minter without write-back is a defect.** Here is the sequence, every step sourced
above:

1. The minter reads host refresh token R0, exchanges it, gets R1, and keeps R1 in memory.
2. R0 is now dead (§1).
3. The minter exits or the run ends, and R1 is lost.
4. Within ≤ ~8 h the host Claude Code nears expiry, takes its lock, re-reads (still R0, so no
   sibling write to adopt), and posts R0.
5. The host gets `invalid_grant` and **clears its own stored login** (`k3n`, §1.2).
6. The operator sees *"Please run /login"*.
7. The next playpen run's minter reads an empty store and fails too.

There is nothing probabilistic in it. ADR 0018's framing, *"whether the write-back happens is
the operator's choice"*, offers a choice between a correct minter and one guaranteed to break the
operator's login.

**Ranked options for the reference minter:**

| | Shape | Race? | Cost |
|---|---|---|---|
| **(a) recommended** | **Dedicated grant.** The operator runs `claude setup-token` once, outside the boundary, and stores the token in *their own* keystore item (not Claude Code's). The minter is ADR 0008's trivial keystore minter and returns `{token, expires_at}` with a one-year expiry. | **None.** No refresh token exists, and the host login is never read. | Inference-only scope **[DOC]**: no Remote Control, no claude.ai connectors. Yearly re-mint. `setup-token` is subject to `forceLoginMethod` but not `forceLoginOrgUUID` **[DOC]**. |
| **(b)** | **Read-only minter of the host login.** It reads `claudeAiOauth.accessToken` and `expiresAt` and returns them as-is. It never exchanges. On re-mint it re-reads, picking up whatever the host refreshed. | **None from the minter.** Reading cannot rotate. | Lapses if the token expires mid-run and no host instance refreshes. With an 8 h TTL, a run started on a fresh token rarely hits this. The minter must fail (`refusal.minter.*`) rather than exchange if the token is already expired at launch. Couples to Claude Code's private store layout (§3.3), read-only. |
| **(c)** | **Refreshing minter, co-operating.** Takes `~/.claude/.oauth_refresh.lock` (plus the legacy lock), re-reads under it and adopts if changed, exchanges, then CAS-writes back into the Keychain/file in Claude Code's schema. | Same as two Claude Code processes: tolerated. | Re-implements a **private, unversioned** protocol whose concurrency handling has been fixed at least ten times in 2.1.x (§3.3). A mismatch is exactly the 2.1.277 *"logged out by an older build"* failure. It would need to be pinned to, and bumped with, the exact Claude Code version. |
| ✗ | Refreshing minter, no write-back | **Hostile**: host logout within ~8 h | Defect. Never ship it, even as an example. |
| ✗ | Refreshing minter, write-back without the lock | Narrow-window race | Can still clear the host login if the host loses the race before the minter's write lands (§3.2). |

Option (a) also **strengthens ADR 0018's own argument**. That ADR rejected passthrough because
the subscription token can call `/oauth/claude_cli/create_api_key`. Option (a)'s token
*"can only make model requests"* **[DOC]**, and Claude Code models it with scope
`["user:inference"]` **[SRC]**. Interactive logins request `org:create_api_key` as a distinct
scope (`omp`'s `anthropic.ts` `SCOPES`, mirroring Claude Code) **[SRC]**. So the escalation is
very likely closed **by scope** before the endpoint rule set is even consulted **[INFERRED]**.
Whether `create_api_key` actually refuses a setup-token is **[UNMEASURED]**, and the endpoint
rule stays as defence in depth.

**For `omp`:** the same ranking applies, against `~/.omp/agent/agent.db` rather than Claude Code's
store. (a) has no `omp` equivalent: `omp` has no `setup-token`. So for `omp` it is (b) a
read-only minter over `auth_credentials`, or (c) one that joins the
`auth_credential_refresh_leases` lease and CAS-writes. For a ChatGPT credential the race window
is ~9 days wide in time but rarely entered. For an Anthropic credential it is §5's sequence
again **[INFERRED]**.

**Does the residual need a shipped warning? Yes.** At minimum:

1. The reference minter documentation states that Anthropic and OpenAI subscription refresh
   tokens are **single-use**. It states that a minter which refreshes a host login and does not
   write back **will** log the operator out of their desktop agent, within ~8 h for Claude Code.
2. The reference minter is option (a) or (b) and **performs no exchange against the host's
   login**.
3. Any example of option (c) carries the Claude Code (or `omp`) version it was written against,
   and a statement that it must be re-verified on every bump.

---

## 6. What remains unmeasured, and how to measure it safely

Every experiment below requires a **throwaway account or a disposable grant**. Running them
against the operator's login is the hazard itself.

1. **Grace window for a just-rotated token** **[UNMEASURED]**. Refresh with R0 (getting R1), then
   immediately refresh with R0 again at t = 0 s, 1 s, 10 s, 60 s. Determines whether two
   near-simultaneous refreshes can both succeed.
2. **No family revocation on reuse** **[UNMEASURED; INFERRED in §3.2]**. After step 1's
   `invalid_grant`, refresh with R1. Success confirms the winner survives the loser's replay.
3. **Access token survives its sibling's refresh** **[UNMEASURED; REPORTED in #5396]**. After
   R0 → R1, call `/v1/messages` with the access token issued alongside R0. This decides whether
   option (b)'s returned token stays valid when the host refreshes mid-run.
4. **`setup-token` is a separate grant** **[UNMEASURED; INFERRED]**. Mint a setup-token, then
   `/logout` (which revokes the interactive refresh token, `Fv`) and confirm the setup-token
   still works. This confirms option (a) is independent of the interactive login's fate.
5. **TTL figures** **[DOC/REPORTED, not MEASURED]**. Read `expires_in` and
   `refresh_token_expires_in` off one exchange on the throwaway account.

---

## 7. Sources

- Claude Code 2.1.283 binary, `/opt/homebrew/Caskroom/claude-code@latest/2.1.283/claude`. Byte
  offsets:
  - 175685563: `TOKEN_URL`, `CLIENT_ID`
  - 177866446: `Bw`, `JL` (Keychain service name)
  - 178679493: `v3n` (CAS save)
  - 178682193: `k3n` (dead-token wipe), `QF` (env-token credential shape)
  - ~178697740: `Sa`, `UOo`, `zun` (refresh under lock)
  - 178722339: `sce` (refresh exchange)
  - 178726680: `EL` (5-minute skew)
  - 178131217: `Mc`/`Ic` (lock owner record)
- [Claude Code `CHANGELOG.md` @ `52c7644`](https://github.com/anthropics/claude-code/blob/52c76441cae91f6891e4712306bffb057ff6fec5/CHANGELOG.md):
  2.1.81, 2.1.86, 2.1.118, 2.1.126, 2.1.129, 2.1.133, 2.1.136, 2.1.214, 2.1.216, 2.1.248, 2.1.277,
  2.1.282, 2.1.285.
- [Claude Code docs, Authentication](https://code.claude.com/docs/en/authentication), sections
  *Credential management*, *Renew an expiring login*, *Generate a long-lived token*.
- [oh-my-pi @ `v17.3.4`](https://github.com/can1357/oh-my-pi/tree/ffd53ff92a6f575d499730475a73460dd7cc2eea):
  - `packages/ai/src/registry/oauth/anthropic.ts`
  - `packages/ai/src/registry/oauth/anthropic-constants.ts`
  - `packages/ai/src/registry/oauth/openai-codex.ts`
  - `packages/ai/src/auth-storage.ts`
  - `packages/ai/src/auth/sqlite-credential-store.ts`
  - `packages/utils/src/dirs.ts`
  - `packages/ai/CHANGELOG.md` [4.0.0], [15.0.0], [16.1.18], [17.1.4]
  - `packages/coding-agent/CHANGELOG.md` [16.4.2], [17.0.1]
  - `docs/provider-quirks.md`
- [can1357/oh-my-pi#5396](https://github.com/can1357/oh-my-pi/issues/5396), with the maintainer
  bot's fix note referencing #5519.
- [openai/codex @ `84d5437`](https://github.com/openai/codex/blob/84d5437b6e558f5159551949a35aedb84ddb89be/codex-rs/login/src/auth/manager.rs),
  `codex-rs/login/src/auth/manager.rs:203-208`, `:1679-1700`, `:2836-2870`, `:3010-3022`.
- [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749#section-6);
  [RFC 9700 §2.2.2, §4.14.2](https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2).
