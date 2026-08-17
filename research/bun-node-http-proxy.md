# Does Bun's `node:http` compat layer proxy — and do MCP servers proxy at all?

Research ticket: [#24](https://github.com/firefly-engineering/playpen/issues/24). Graduated
from [#18](https://github.com/firefly-engineering/playpen/issues/18)
([`research/proxy-env-honouring.md`](proxy-env-honouring.md)). Map:
[#1](https://github.com/firefly-engineering/playpen/issues/1). Bears on
[#7](https://github.com/firefly-engineering/playpen/issues/7) (egress),
[#13](https://github.com/firefly-engineering/playpen/issues/13) (failure UX),
[#16](https://github.com/firefly-engineering/playpen/issues/16) (environment allow-list),
[#19](https://github.com/firefly-engineering/playpen/issues/19) (proxy lifetime). Depends on
ADR 0002 (playpen does not interpret) and ADR 0004 (egress policy lives in a sibling proxy).

Date: 2026-08-17. Host: macOS 15 (Darwin 25.5.0), arm64. Nothing outside `/tmp` was
written; no network configuration was changed; `~/.claude` and `~/.omp` were not touched.

Subjects and versions, all as installed or fetched on this box:

| Subject | Version | Notes |
|---|---|---|
| Claude Code | 2.1.224 (`/opt/homebrew/Caskroom/claude-code/2.1.224/claude`) | single-file **Bun 1.4.0** executable |
| `omp` (oh-my-pi) | 17.3.4 (`/opt/homebrew/Cellar/omp/17.3.4/bin/omp`) | single-file **Bun 1.3.14** executable |
| Bun | **1.3.14** (`/opt/homebrew/bin/bun`), 1.3.13, 1.3.9, 1.3.5 (`/tmp/bun140/`) | released line |
| Bun | **1.4.0-canary.1+5c050bc33** (`/tmp/bun140c/bun-darwin-aarch64/bun`) | GitHub `canary` release asset, built from `main` (`package.json` `"version": "1.4.0"`) |
| Node | v26.7.0 (`/opt/homebrew/bin/node`) | bundled undici |
| Bun source | `oven-sh/bun` `main` @ `8326d1bd`, `/tmp/bunsrc` | version 1.4.0 |

Method, following #18: a logging loopback proxy (`/tmp/pp24/proxy.py`) on `127.0.0.1:8899`
that speaks `CONNECT` and absolute-URI forwarding and logs every request line; a second
instance on `127.0.0.1:8897` in `refuse` mode that answers **every** request with
`403 Forbidden` + body `blocked by pp24 proxy`; a loopback HTTP server on
`127.0.0.1:9080`. Probes: `/tmp/pp24/probe.mjs` (one runtime, one of `fetch` /
`node:http` / `node:https`, one URL) and `/tmp/pp24/mcp-probe.mjs` (a real stdio MCP
server that dumps its environment and probes egress twice — once through `node:https`,
once through global `fetch` — before answering the MCP handshake).

Every claim is tagged **[EXPERIMENT]** (observed at the proxy, or in the probe's own
output) or **[SOURCE]** (read from version-pinned Bun/Node source, or from strings in a
shipped binary). Where they disagree, the experiment wins and the disagreement is stated.

---

## TL;DR

**Yes, the dangerous case is real, and it is new.** On the **whole released Bun 1.3.x
line**, `node:http`/`node:https` proxy from the environment unconditionally. On **Bun
1.4.0** — the line Claude Code ships — they **do not**, unless `NODE_USE_ENV_PROXY=1` is
set, while Bun's native `fetch` still proxies unconditionally. That is exactly the split
#24 feared: one runtime, two HTTP APIs, opposite answers.

But the premise is wrong about *who* it bites. **Claude Code does not run MCP servers
under its embedded Bun.** It `exec`s whatever `command` the MCP config names — `node`,
`npx`, `uvx`, `bunx`, a binary — and supplies no runtime of its own (its Bun is not even
reachable: `BUN_BE_BUN` is stripped from the shipped binary). So the population at risk is
**Node-written MCP servers running under whatever Node/Bun is on `PATH`**, and the answer
there is worse than "Bun 1.4.0 regressed": **Node has never proxied `node:http` by default
and still does not at v26.7.0** (#18 §2). Measured end to end through Claude Code's real
MCP spawn path:

| MCP server runtime | `node:https` | global `fetch` |
|---|---|---|
| Node v26.7.0 | **DIRECT** | **DIRECT** |
| Bun 1.3.14 | PROXIED | PROXIED |
| Bun 1.4.0 | **DIRECT** | PROXIED |

**One environment variable fixes all three: `NODE_USE_ENV_PROXY=1`.** With it set on the
Claude Code parent (which passes its environment to MCP children **unfiltered**), every
cell above becomes PROXIED. It is a mandatory entry in playpen's environment allow-list,
alongside the `NO_PROXY` entry #18 handed to #16 and the `TMPDIR` entry from #12.

Three other results change decisions:

- **stdio and HTTP/SSE MCP transports are on different sides of the boundary.** HTTP/SSE
  MCP is dialled by *Claude Code's own* proxy layer and always proxies (including
  loopback). stdio MCP egress is dialled by the *child's* runtime and obeys none of
  Claude Code's proxy configuration. Under `allowlist`, one class works and the other
  fails, from the same config file.
- **Bun's `fetch` hands a proxy's `403` to the application as an ordinary HTTP
  response** — status *and* body from the proxy, indistinguishable from the origin having
  answered `403`. That is a direct hit on #13's distinguishability law.
- **The four unattributed `CONNECT api.anthropic.com` from #18 are attributed**: they are
  Claude Code's *non-essential* traffic. `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`
  removes them and the Datadog telemetry, leaving exactly one `CONNECT` per run.

---

## 0. Premise correction — nothing puts an MCP server on Bun

**[EXPERIMENT]** Claude Code spawns a stdio MCP server by executing the `command` in the
MCP config, with `args`, with the parent environment plus the config's `env` block merged
in. Configs used:

```json
{"mcpServers":{"pp24node":{"command":"/opt/homebrew/bin/node","args":["/tmp/pp24/mcp-probe.mjs"],"env":{"PP_MCP_TAG":"node-declaredenv"}}}}
```

and the same with `/opt/homebrew/bin/bun` and `/tmp/bun140c/bun-darwin-aarch64/bun`. The
probe reports its own runtime:

```
runtime node v26.7.0 | execPath /opt/homebrew/Cellar/node/26.7.0/bin/node
runtime bun 1.3.14   | execPath /opt/homebrew/Cellar/bun/1.3.14/bin/bun
runtime bun 1.4.0    | execPath /private/tmp/bun140c/bun-darwin-aarch64/bun
```

There is no interposition. A config that says `npx -y @some/mcp-server` runs under the
`node` on `PATH`; a config that says `uvx …` runs under Python. **Claude Code's embedded
Bun 1.4.0 is not offered to children at all** — `BUN_BE_BUN=1` (Bun's documented escape
hatch for treating a compiled executable as the Bun CLI) produces no Bun on the Claude
Code binary, and `strings` finds no `BUN_BE_BUN` in it. It works on `omp`:

```
$ BUN_BE_BUN=1 /opt/homebrew/bin/omp run /tmp/pp-bebun.js
hello from 1.3.14
$ BUN_BE_BUN=1 /opt/homebrew/bin/claude /tmp/pp-bebun.js
(claude answers the path as a prompt)
```

**[SOURCE]** `omp` does use itself as a runtime for children — `Bun.spawn([process.execPath,
"install", …], { env: { …Bun.env, BUN_BE_BUN: "1" } })` for installing an MCP server's
dependencies, and its debug-adapter launcher falls back from `node` to `bun` (itself) when
no `node` is on `PATH`. So under `omp`, a Node-written tool can land on **Bun 1.3.14**,
which is the *safe* side of the split.

Consequence: this ticket's question is not really "does Bun's compat layer proxy". It is
"**does the runtime an arbitrary third-party MCP server happens to run under proxy**", and
the honest answer across today's field is **usually not**.

---

## 1. The matrix. [EXPERIMENT]

Harness: `/tmp/pp24/run.sh <label> <runtime> <mode> <url> [env…]`, which snapshots the
proxy log around one probe run and reports PROXIED/DIRECT from what the proxy actually saw.
Target `https://example.com/` unless stated. `HTTPS_PROXY=http://127.0.0.1:8899` (and
`HTTP_PROXY` likewise for plain-http targets). No `NO_PROXY`.

| Runtime | API | no opt-in | `NODE_USE_ENV_PROXY=1` |
|---|---|---|---|
| Bun 1.3.5 / 1.3.9 / 1.3.13 / 1.3.14 | `node:https` | **PROXIED** | PROXIED |
| Bun 1.3.14 | `node:http` (plain-http target) | **PROXIED** | PROXIED |
| Bun 1.3.14 | `fetch` | PROXIED | PROXIED |
| **Bun 1.4.0-canary.1** | `node:https` | **DIRECT** | **PROXIED** |
| **Bun 1.4.0-canary.1** | `node:http` (plain-http target) | **DIRECT** | **PROXIED** |
| Bun 1.4.0-canary.1 | `fetch` | **PROXIED** | PROXIED |
| Node v26.7.0 | `node:https` | DIRECT | PROXIED |
| Node v26.7.0 | `fetch` | DIRECT | PROXIED |

The Bun 1.4.0 `node:https` DIRECT result was re-run three times, and the proxy log is
empty for those runs — the proxy was never contacted, so this is not a fall-back after a
proxy failure. Every PROXIED https row arrived as `CONNECT example.com:443`; every PROXIED
plain-http row as `GET http://example.com/ HTTP/1.1`.

**So Bun 1.4.0 both fixed and broke something.** It gained Node-compatible, spec-shaped,
`NO_PROXY`-aware proxying in the compat layer *and* adopted Node's opt-in gate, which
means workloads that silently proxied on 1.3.x silently stop on 1.4.0. Under playpen's
`allowlist` — where direct egress is refused by the kernel and the proxy is the only route
out — "silently stops proxying" reads to the operator as "this MCP server is broken".

Two smaller characterisations, both runtimes:

- **Scheme-matched, lowercase-first.** An `https:` target with only `HTTP_PROXY` set goes
  DIRECT on Bun 1.3.14, Bun 1.4.0 and Node 26.7 alike. `https_proxy` alone (lowercase)
  proxies. [EXPERIMENT]
- **`NODE_USE_ENV_PROXY=1` plus a malformed proxy URL is fatal at import time**, not at
  request time: Bun 1.4.0 and Node 26.7 both throw `Invalid URL` out of
  `require("node:http")`. Bun 1.3.14 instead reports `ECONNREFUSED`. Since playpen writes
  the proxy URL itself this is under its control, but it means one bad URL kills every
  Node child in the run, before any request. [EXPERIMENT]

---

## 2. Why — the mechanism, from Bun's own source

**[SOURCE]** On the released 1.3 line the JS compat layer's proxy support is explicitly
switched off. `src/js/node/_http_agent.ts` at tags `bun-v1.3.13` and `bun-v1.3.14`:

```js
    // This normalized from both --use-env-proxy and NODE_USE_ENV_PROXY settings.
    // proxyEnv: getOptionValue("--use-env-proxy") ? filterEnvForProxies(process.env) : undefined,
    proxyEnv: undefined, // TODO:
```

Yet 1.3.14 `node:https` proxies. The reconciliation — which #18 could not make and flagged
as its highest-value gap — is that on 1.3.x the proxying happens **below** the compat
layer, in Bun's native HTTP client, which resolves proxies from the process environment
for anything it dials.

On `main` (1.4.0) that native fall-back is gone from the `node:http` path.
`src/http/lib.rs` defines `ProxySettings::from_env` — the native env-proxy resolver,
lowercase-first, scheme-matched, `NO_PROXY`-aware, re-evaluated per redirect hop — and its
**only** call site in the tree is `src/runtime/webcore/fetch/FetchTasklet.rs:1974`
(plus `from_explicit` at :1968 for `fetch(url, { proxy })`). Nothing in the `node:http`
path reaches it. `node:http`/`node:https` now get proxying only through the JS
`proxyEnv` option, gated at `src/js/node/_http_agent.ts`:

```js
// Like Node.js: NODE_USE_ENV_PROXY opts the global agents into proxying via
// the HTTP_PROXY/HTTPS_PROXY/NO_PROXY environment variables.
function shouldUseEnvProxy() {
  const value = process.env.NODE_USE_ENV_PROXY;
  if (Boolean(value) === false || value === "0") return false;
  …
}
export default {
  Agent,
  globalAgent: new Agent({ …, proxyEnv: shouldUseEnvProxy() ? process.env : undefined }),
```

with the identical gate on `https.globalAgent` (`src/js/node/https.ts:534`). That is the
same string #18 read out of the Claude Code binary, so **Claude Code's embedded Bun 1.4.0
carries this gate** — verified: `strings` on the 2.1.224 binary contains
`let value = process.env.NODE_USE_ENV_PROXY;`.

Bun 1.4.0 also ships a port of Node's `http.setGlobalProxyFromEnv()`
(`src/js/node/http.ts`, header comment: *"Port of Node.js's http.setGlobalProxyFromEnv()
(lib/http.js): https://github.com/nodejs/node/blob/v26.3.0/lib/http.js"*), so a library
that opts in programmatically works on Bun too. Not useful to playpen, which does not
interpret or inject code.

---

## 3. Through Claude Code's real MCP spawn path. [EXPERIMENT]

Not a synthetic runtime test — the actual product spawning the actual server:

```
$ env HTTPS_PROXY=http://127.0.0.1:8899 HTTP_PROXY=http://127.0.0.1:8899 \
    claude --mcp-config /tmp/pp24/<cfg>.json --strict-mcp-config \
    -p 'Reply with exactly the word OK and nothing else.' --output-format text
```

The probe fires both egress attempts at startup, so no model tool-call is required; the
handshake alone triggers it. Proxy log deltas per run, and the probe's own verdicts:

| MCP server runtime | extra env | `CONNECT example.com:443` at proxy | probe result |
|---|---|---|---|
| Node v26.7.0 | — | **0** | `nodehttps HTTP 200`, `fetch HTTP 200` (both direct) |
| Bun 1.3.14 | — | **2** | both proxied |
| Bun 1.4.0 | — | **1** | `fetch` proxied, `node:https` direct |
| Node v26.7.0 | `NODE_USE_ENV_PROXY=1` | **2** | both proxied |
| Bun 1.4.0 | `NODE_USE_ENV_PROXY=1` | **2** | both proxied |

The probes returned `HTTP 200` in every case because on this host direct egress works.
**Under `allowlist` the DIRECT rows are the failure**: the kernel refuses the direct
connect and the MCP server reports a connection error, while the agent that spawned it
keeps talking to the model API perfectly — the partial, per-dependency failure shape #24
predicted.

`NODE_USE_ENV_PROXY=1` on the parent did not disturb Claude Code itself in any run (it
uses its own `configureGlobalAgents` layer regardless, per #18 §1) and did not disturb Bun
1.3.14. It is a safe, additive setting.

---

## 4. Environment inheritance — MCP children get everything. [EXPERIMENT]

The probe dumps `Object.keys(process.env)`. A Claude Code run passed **99 variables** to
the stdio MCP child, including the complete shell environment (`PATH`, `HOME`, `TMPDIR`,
`SSH_AUTH_SOCK`, `KUBECONFIG`, prompt-theme junk, and an unrelated third-party
`ZAI_API_KEY`), plus `HTTP_PROXY` and `HTTPS_PROXY` verbatim, plus the config's `env`
block merged in, plus Claude Code's own additions:

```
CLAUDECODE=1  CLAUDE_CODE_ENTRYPOINT=sdk-cli
CLAUDE_CODE_EXECPATH=/opt/homebrew/Caskroom/claude-code/2.1.224/claude
CLAUDE_CODE_SESSION_ID=<uuid>  CLAUDE_PID=<pid>  CLAUDE_EFFORT=medium
CLAUDE_PROJECT_DIR=/private/tmp/pp24
```

**There is no filtering.** Nothing is stripped, nothing is redacted, and no proxy variable
is injected — in particular **`NODE_USE_ENV_PROXY` is never set by Claude Code**, and
neither is `NO_PROXY`.

Two consequences for #16:

1. Whatever playpen puts in the agent's environment reaches every MCP server, so
   `NODE_USE_ENV_PROXY=1`, `NO_PROXY` and the proxy URLs propagate for free. The allow-list
   is the whole mechanism; nothing else is needed.
2. The pass-through is total in the other direction too. In one run the *outer* session's
   `CLAUDE_CODE_MESSAGING_SOCKET` (from the Claude Code session this research ran inside)
   reached a grandchild MCP server unfiltered. An MCP server is an unreviewed third-party
   process that sees every secret in the agent's environment. That is a #16 question, not
   a proxy question, but it was measured here and is worth recording.

Harness disclosure: because this research ran *inside* a Claude Code session, the parent
environment already contained `CLAUDE*` variables. The values reported above
(`CLAUDE_CODE_EXECPATH`, `CLAUDE_CODE_SESSION_ID`, `CLAUDE_PID`) are the **inner** run's,
confirmed by a second, cleaner dump; the leak noted in (2) is the outer session's variable
surviving two hops, which is the point.

---

## 5. stdio versus HTTP/SSE transports — opposite sides of the boundary. [EXPERIMENT]

With `{"pp24http":{"type":"http","url":"https://pp24-mcp.example.net/mcp"},
"pp24loop":{"type":"http","url":"http://127.0.0.1:9080/mcp"}}` and no `NO_PROXY`:

```
3 REQ CONNECT pp24-mcp.example.net:443 HTTP/1.1
1 REQ POST http://127.0.0.1:9080/mcp HTTP/1.1
3 UPSTREAM-FAIL pp24-mcp.example.net:443 gaierror(8, …)
```

HTTP/SSE-transport MCP is dialled by **Claude Code's own** HTTP stack, so it obeys Claude
Code's proxy layer unconditionally — remote hosts as `CONNECT`, loopback as absolute-URI
forwarding (confirming #18 §4: loopback MCP is proxied unless `NO_PROXY` names it), and it
retries (3 attempts) against the proxy on failure.

stdio-transport MCP has **no such client**: the transport is a pipe, and any network the
server does is its own, dialled by its own runtime, invisible to and unconfigurable by
Claude Code. So the two transports differ categorically:

| | who dials the network | honours proxy env | affected by §1 |
|---|---|---|---|
| HTTP / SSE MCP | Claude Code | always (own resolver) | no |
| stdio MCP | the server process | whatever its runtime does | **yes** |

This is the shape playpen must plan for: from one `.mcp.json`, under `allowlist`, the
`type: http` servers work and the `command:`-spawned Node ones do not, unless
`NODE_USE_ENV_PROXY=1` is in the environment.

---

## 6. `NO_PROXY` on the compat path

**[EXPERIMENT]** Once proxying is on, both Bun paths honour `NO_PROXY`, and identically.
Target `http://127.0.0.1:9080/`, `HTTP_PROXY` set, `NODE_USE_ENV_PROXY=1`:

| `NO_PROXY` | Bun 1.3.14 `fetch` | Bun 1.3.14 `node:http` | Bun 1.4.0 `fetch` | Bun 1.4.0 `node:http` |
|---|---|---|---|---|
| *(unset)* | PROXIED | PROXIED | PROXIED | PROXIED |
| `127.0.0.1` | DIRECT | DIRECT | DIRECT | DIRECT |
| `localhost` | **PROXIED** | **PROXIED** | **PROXIED** | **PROXIED** |
| `*` | DIRECT | DIRECT | DIRECT | DIRECT |

`localhost` still never covers `127.0.0.1` — #18 §4 holds on the compat path too.

Grammar, target `https://example.com/`, all three runtimes:

| `NO_PROXY` entry | Bun 1.3.14 | Bun 1.4.0 | Node 26.7 (`node:https`) |
|---|---|---|---|
| `example.com` | DIRECT | DIRECT | DIRECT |
| `.example.com` | DIRECT | DIRECT | DIRECT |
| `EXAMPLE.COM` | DIRECT | DIRECT | DIRECT (case-insensitive) |
| `*.example.com` | PROXIED | PROXIED | PROXIED (wildcard = subdomains only) |

**CIDR is not supported anywhere.** `NO_PROXY=127.0.0.0/8` with target
`http://127.0.0.1:9080/` came back **PROXIED** on Bun 1.3.14, Bun 1.4.0 and Node 26.7, on
both `fetch` and `node:http`. [SOURCE] confirms it is deliberate — Bun's port of Node's
matcher, `src/js/internal/http.ts`:

```js
      // Handle IP ranges (simple format like 192.168.1.0-192.168.1.255)
      …
      // It might be useful to support CIDR notation, but it's not so widely supported
      // in other tools as a de-facto standard to follow, so we don't implement it for now.
```

This **corrects #18 §4**, which recorded Node core's matcher as supporting "IPv4 ranges"
and CIDR as best-effort. The supported range syntax is the dash form
(`10.0.0.0-10.255.255.255`), not `10.0.0.0/8`. playpen's `NO_PROXY` should therefore be
written in host/suffix form and must not rely on CIDR to cover loopback: enumerate
`localhost`, `127.0.0.1`, `::1` literally.

---

## 7. What a denial looks like from inside — for #13. [EXPERIMENT]

Against the refusing proxy on `127.0.0.1:8897` (every request answered
`403 Forbidden` + `blocked by pp24 proxy`), target `https://example.com/`:

| Runtime / API | what the application sees |
|---|---|
| Bun 1.3.14 `fetch` | `STATUS 403 BODY "blocked by pp24 proxy"` — an ordinary `Response` |
| Bun 1.3.14 `node:https` | same: an ordinary 403 response |
| Bun 1.4.0 `fetch` | `STATUS 403 BODY "blocked by pp24 proxy"` |
| Bun 1.4.0 `node:https` | `ERR Failed to establish tunnel to example.com:443 via http://127.0.0.1:8897: HTTP/1.1 403 Forbidden` |
| Node 26.7 `fetch` | `ERR fetch failed` — cause swallowed |
| Node 26.7 `node:https` | `ERR Failed to establish tunnel to example.com:443 via http://127.0.0.1:8897: HTTP/1.1 403 Forbidden` |

Three distinct legibility regimes from one proxy behaviour:

1. **Bun's `fetch` conflates the proxy with the origin.** A refused `CONNECT` is delivered
   as a normal HTTP response carrying the *proxy's* status and body. An application cannot
   tell "playpen refused this host" from "the host answered 403", and will retry, or log
   the origin's name against playpen's message. This is a real hazard for #13 — **and it
   is also an opportunity**: because the body and headers reach the application intact,
   playpen's denial text is read by the agent verbatim. The design implication is that the
   denial response must be **self-describing** — a distinctive header (e.g.
   `X-Playpen-Denied: <host>`) and a body that names playpen, the host, and the profile —
   because in this regime the body *is* the whole error message, and the status code alone
   is ambiguous.
2. **`node:http`/`node:https` (Node, and Bun 1.4.0) produce the ideal error**: the proxy
   URL, the target, and the proxy's status line, in one sentence. #18's finding stands.
3. **Node's `fetch` produces the worst error**: `fetch failed`, with the cause only on
   `err.cause`. Anything logging `err.message` loses the attribution entirely.

**[SOURCE]** Anthropic hit all of this in their own sandbox and wrote a runbook into the
Claude Code binary. Verbatim from `strings` on 2.1.224:

```
### "405 Method Not Allowed" from the proxy
The tool sent a plain-HTTP (non-CONNECT) request: usually axios older than
1.16.1 (upgrade it) or a tool configured with HTTP_PROXY (unset HTTP_PROXY for
that tool — only HTTPS_PROXY is supported).
### 403 / 407 from the proxy
The destination host is not allowed by your organization's egress policy for
this session. Do not retry or route around it — report the blocked host.
Note: curl hides response bodies on failed CONNECTs; the status endpoint
records the reason.
### Tool ignores the proxy entirely (timeouts with no proxy error)
Some clients do not read HTTPS_PROXY: Node's built-in fetch (run that command
with NODE_USE_ENV_PROXY=1 on Node >= 22.21), aiohttp (pass trust_env=True),
Ruby bundler (reads only HTTP_PROXY, which this proxy does not serve),
hand-rolled Go dialers. Prefer the tool's own proxy option where one exists.
```

That is first-party corroboration of §3's remedy, of the "timeouts with no proxy error"
failure shape, and of the fact that **an operator-facing runbook is part of the deliverable**
— Anthropic ships one *inside the agent*, as text the model can read when a tool fails.
That is a concrete, copyable answer to #13: the denial explanation belongs where the agent
will encounter it.

Same block, on what cannot be proxied at all (input for #7's scope):

```
### Not supported through the proxy (report, do not work around)
gRPC / HTTP/2-only APIs, WebSocket upgrades, client-mTLS, certificate-pinned
clients (e.g. Snowflake, ngrok), non-443 HTTPS ports, raw-TCP databases.
```

and their own `NO_PROXY` default (`vWl` in the binary), notably richer than the one #18
recorded:

```
localhost, 127.0.0.1, ::1, 127.0.0.0/8, 0.0.0.0/8, ::, 169.254.0.0/16,
anthropic.com, .anthropic.com, *.anthropic.com, registry.npmjs.org, jsr.io,
npm.jsr.io, pypi.org, files.pythonhosted.org, index.crates.io,
proxy.golang.org, host.docker.internal
```

plus, in the wider variant, `10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10,
.svc.cluster.local, *.svc.cluster.local`. Note they list all three spellings of a domain
(`anthropic.com`, `.anthropic.com`, `*.anthropic.com`) because no single one covers apex
plus subdomains everywhere — consistent with §6.

---

## 8. The four `CONNECT api.anthropic.com` — attributed. [EXPERIMENT]

#18 left this open: some `api.anthropic.com` connects survive a host-shaped `NO_PROXY`
while still obeying `NO_PROXY=*`. Counts here, one `claude -p` run each, proxy log deltas:

| Run | proxy saw |
|---|---|
| baseline (`HTTPS_PROXY` only) | `api.anthropic.com` ×13, datadog ×1 |
| `ANTHROPIC_BASE_URL=https://pp24-probe.example.net`, `NO_PROXY` = that host | `api.anthropic.com` ×15, `downloads.claude.ai` ×2, datadog ×2 |
| `NO_PROXY=api.anthropic.com` | **`api.anthropic.com` ×7**, datadog ×1 |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` | `api.anthropic.com` ×**1**, datadog **×0** |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` (repeat) | `api.anthropic.com` ×**1**, datadog **×0** |
| `NO_PROXY=api.anthropic.com` + `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` | **nothing at all** |

The last row is decisive. The traffic that ignores a host-shaped `NO_PROXY` is **exactly**
the traffic that `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` removes: Claude Code's
non-essential subsystem — telemetry and feature-flag/remote-settings polling, which
targets `api.anthropic.com` as well as the Datadog intake. With it disabled, a full run
makes exactly **one** outbound connection, the model call itself, and that one honours
`NO_PROXY` normally.

The count varies run to run (4 in #18, 7–15 here); the nature does not. This closes #18's
named gap at subsystem granularity, and hands three facts to #7:

- an `allowlist` fragment for Claude Code can be reduced to essentially **one host** by
  setting `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`;
- that variable is a **policy** choice, not interpretation — same class as `NO_PROXY` —
  but it is a *behavioural* change to the workload, so it belongs to the profile author,
  not to playpen's defaults;
- the non-essential path's proxy resolver does not consult host-shaped `NO_PROXY`, so a
  profile that tries to exempt `api.anthropic.com` will still see those connections at the
  proxy. Harmless (traffic goes *to* the boundary), but do not model `NO_PROXY` as
  uniformly honoured inside one binary.

---

## 9. Bottom line

Answering #24 point by point:

1. **Does `http.request`/`https.request` through Bun's compat layer honour
   `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`, and on which versions?** On **1.3.5 through
   1.3.14: yes, unconditionally** (via the native transport, not the compat layer — the JS
   layer has `proxyEnv: undefined // TODO:`). On **1.4.0: no**, unless
   `NODE_USE_ENV_PROXY=1`; then yes, with full `NO_PROXY` support. So `omp`'s Bun 1.3.14
   is on the safe side and Claude Code's Bun 1.4.0 is on the unsafe side — but see (3).
2. **Does it differ from `fetch`?** Yes, and the dangerous configuration is exactly the
   one Bun 1.4.0 ships: `fetch` proxies unconditionally, `node:http`/`node:https` do not.
   In Bun 1.4.0 the native env-proxy resolver (`ProxySettings::from_env`) is reachable
   **only** from `FetchTasklet`.
3. **Do Node-written MCP servers under Claude Code proxy at all?** **No, by default —
   and not for the reason the ticket assumed.** They do not run under Bun; they run under
   whatever `command` names, overwhelmingly the system `node`, which has never proxied
   `node:http` by default and does not at v26.7.0. Measured through the real spawn path:
   Node child → both `node:https` and `fetch` DIRECT; Bun 1.4.0 child → `node:https`
   DIRECT. **`NODE_USE_ENV_PROXY=1` fixes every case.**
4. **Do MCP servers inherit the environment?** Completely and unfiltered — 99 variables,
   proxy variables included, config `env` merged on top, nothing stripped, nothing
   injected. So the allow-list is a sufficient delivery mechanism.
5. **stdio vs SSE/HTTP?** Categorically different. HTTP/SSE MCP is Claude Code's own
   client and always proxies (loopback included, unless `NO_PROXY` says otherwise). stdio
   MCP egress belongs to the child and is governed only by the child's runtime.
6. **The four unattributed `CONNECT`s?** Claude Code's non-essential traffic; removable
   with `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`.

**What this changes.**

- **#16 gains a second mandatory entry: `NODE_USE_ENV_PROXY=1`.** It sits beside the
  `NO_PROXY` entry #18 handed over. Both are playpen stating facts about the boundary it
  built, in the standard vocabulary the ecosystem already reads — no code injection, no
  `NODE_OPTIONS`, no flag rewriting, so ADR 0002 is untouched. Unlike `NO_PROXY`, this one
  is *load-bearing for correctness of third-party code*: without it, MCP is broken under
  `allowlist` on every current Node and on Bun ≥ 1.4.0.
- **#13 gains a measured requirement**: the denial response must be self-describing in its
  **body and headers**, not merely in its status code, because Bun's `fetch` — the stack
  under both flagship agents — hands the proxy's response to the application as if the
  origin had sent it. And Anthropic's shipped runbook is the model to copy: put the
  explanation where the agent will read it.
- **#7 gains scope facts**: `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` collapses Claude
  Code's egress set to one host; `NO_PROXY` grammar is host/suffix only, no CIDR; and
  gRPC/HTTP-2-only, WebSocket upgrade, mTLS, pinned clients, non-443 HTTPS and raw TCP are
  known-unproxyable classes that a `CONNECT`-relay design cannot serve.
- **#19 (proxy lifetime)** is not contradicted: nothing observed needs the proxy before
  the agent starts or after it exits, and MCP children are ordinary descendants of the
  agent process, inside the same lifetime.
- **ADR 0004 stands.** Opaque `CONNECT` remained sufficient throughout; no interception
  was needed for anything measured here.

---

## 10. What remains unverified

- **macOS only, again.** No Linux, no netns, no `bwrap`. The kernel-refuses-direct-egress
  half of the failure shape was *reasoned*, not exercised: this host allows direct egress,
  so every DIRECT row above still returned `HTTP 200`. What an MCP server prints when the
  direct connect is refused by the boundary was not measured, and that string is exactly
  what #13 needs.
- **Bun 1.4.0 is a canary** (`1.4.0-canary.1+5c050bc33`) built from `main`, not the
  release Claude Code embeds. The gate's *presence* in Claude Code's binary is confirmed by
  `strings`; the *behaviour* is measured on the canary. A shipped 1.4.0 could differ.
- **Python MCP servers were not measured here.** `httpx` — what the official Python MCP
  SDK uses — is not installed on this box. `httpx` defaults to `trust_env=True` and reads
  proxy env vars, and #18 already measured `urllib` proxying by default, so Python servers
  are probably on the *working* side; unconfirmed. `aiohttp` needs `trust_env=True`
  (per Anthropic's runbook, [SOURCE]) and is probably on the broken side.
- **Real third-party MCP servers were not run.** The probe is hand-written. Libraries
  matter: `axios`, `got`, `node-fetch@2` all sit on `node:http` and inherit its answer,
  and Anthropic's runbook notes `axios` < 1.16.1 sends plain-HTTP requests through the
  proxy (405). A survey of the top MCP servers' HTTP clients was not done.
- **Which released Bun version first regressed.** 1.3.14 is the last released tag and it
  proxies; 1.4.0 does not. The exact commit was not bisected — the local `oven-sh/bun`
  clone is shallow (one commit), so no history was available and the change was
  established by comparing tagged sources against `main`.
- **`NODE_USE_ENV_PROXY` on other runtimes.** It is a Node/Bun-specific gate. Deno, Python,
  Go and Rust MCP servers each have their own answer; only Node and Bun were measured.
- **Long sessions.** All Claude Code runs were single `-p` turns. Background agents,
  plugins, LSP sidecars and hooks were not exercised, and each is another child process
  with its own runtime and its own answer to this question.
- **The `omp` side of the MCP question** was not measured at all: whether `omp` spawns
  stdio MCP servers under its embedded Bun 1.3.14 (which would make them proxy for free)
  or under the system `node` (which would not) is unresolved. Its debug-adapter launcher
  falls back to `bun`; whether the MCP launcher does the same was not established.
