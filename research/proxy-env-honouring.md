# Can the flagship agent workloads actually be proxied?

Research ticket: [#18](https://github.com/firefly-engineering/playpen/issues/18). Map:
[#1](https://github.com/firefly-engineering/playpen/issues/1). Blocks
[#9](https://github.com/firefly-engineering/playpen/issues/9). Depends on the standing
laws in ADR 0002 (playpen does not interpret) and ADR 0004 (egress policy lives in a
sibling proxy).

Date: 2026-08-16. Host: macOS 15 (Darwin 25.5.0), arm64.

Subjects and versions, all as installed on this box:

| Subject | Version | Runtime |
|---|---|---|
| Claude Code | 2.1.224 (`/opt/homebrew/Caskroom/claude-code/2.1.224/claude`) | single-file **Bun 1.4.0** executable, 265 MB Mach-O |
| `omp` (oh-my-pi) | 17.3.4 (`/opt/homebrew/Cellar/omp/17.3.4/bin/omp`) | single-file **Bun 1.3.14** executable |
| Bun | 1.3.14+`0d9b296af` (plus 1.3.13, 1.3.9, 1.3.5 fetched to `/tmp`) | — |
| Node | v26.7.0 | bundled undici |
| curl | 8.21.0 | control |

Method: a logging HTTP proxy on `127.0.0.1` (`/tmp/pp-proxy/proxy.py`) that speaks
`CONNECT` and absolute-URI forwarding and records every request line, plus a loopback
HTTP server on `127.0.0.1:9080`. Every behavioural claim below is attributed
**[EXPERIMENT]** (observed at the proxy) or **[SOURCE]** (read out of the binary's
embedded JS, or from upstream primary sources). Where the two disagree, the experiment
wins and the disagreement is noted. Nothing in `$HOME` was modified; all work was done
in `/tmp`.

---

## TL;DR

**The answer is yes, and it is a stronger yes than ADR 0004 assumed.** Both flagship
workloads reach their model API through an unmodified `HTTPS_PROXY`, over an **opaque
`CONNECT` tunnel**, with no flag injection, no `NODE_OPTIONS`, and no `--proxy`
argument. The does-not-interpret law is not threatened by the transport decision.

The premise in the ticket — "Claude Code is Node, and undici ignores proxy env vars" —
is **factually wrong on both halves**, and the reason matters:

1. **Claude Code is not Node.** It is a Bun 1.4.0 compiled binary. Bun's `fetch()`
   honours proxy env vars natively and always has.
2. **It does not rely on the runtime anyway.** Claude Code ships its own proxy layer
   — `getProxyUrl`, `getProxyAgent`, `getProxyFetchOptions`, `configureGlobalAgents`,
   `shouldBypassProxy`, `getWebSocketProxyUrl`, a proxy-auth-helper cache — invoked
   from an `[init] configureGlobalAgents` step at startup. Proxy support is a
   first-class product feature, not an accident of the HTTP stack.
3. **`omp` likewise is not Rust.** It is also a Bun binary, with its own
   `PI_PROXY_<PROVIDER>` → `PI_PROXY` → `HTTPS_PROXY` → `ALL_PROXY` resolution chain.

The real finding — and the one that should change ADR 0004 — is **§4: nothing bypasses
loopback by default.** ADR 0004 requires loopback traffic not to transit the proxy.
That requirement is *not* satisfied by leaving `NO_PROXY` unset; it is satisfied only
by playpen setting `NO_PROXY` explicitly, and setting it with every spelling of
loopback, because in every stack tested `localhost` in `NO_PROXY` does **not** cover
`127.0.0.1`.

---

## 0. Identity check — what is actually running

Both flagship binaries are Bun single-file executables, not what the ticket assumed.

**[EXPERIMENT/SOURCE]** `strings` on the Claude Code binary yields `Bun v1.4.0` /
`bun-v1.4.0` and Bun's whole embedded JS builtin set (`build/release/tmp_modules/node/…`).
`strings` on `omp` yields `bun-v1.3.14`. Neither contains a Rust toolchain marker; `omp`
has no `rustc`/`cargo` version strings at all.

This kills two of the ticket's premises up front. Claude Code's HTTP stack is Bun's,
not Node's; `omp`'s core is Bun's, not Rust's. Node/undici is still worth establishing
(§2) because playpen will meet plenty of Node-based agents and MCP servers, but it is
not the flagship's stack.

There is a bundled undici in Claude Code, but only as **Bun's shim**
(`build/release/tmp_modules/thirdparty/undici.ts`), which re-exports `ProxyAgent` and
`EnvHttpProxyAgent` names over Bun's native client. Claude Code also bundles
`https-proxy-agent` (debug namespaces `https-proxy-agent:parse-proxy-response` are
present) and the AWS and Azure SDKs' own proxy paths — so the binary contains **at
least four independent proxy resolvers**, which explains the one inconsistency in §4.

---

## 1. Claude Code — does it honour `HTTPS_PROXY`?

### Model API: yes. [EXPERIMENT]

Run with `HTTPS_PROXY=http://127.0.0.1:8899` and
`ANTHROPIC_BASE_URL=https://pp-probe-api.example.net`, the proxy logged:

```
REQ CONNECT pp-probe-api.example.net:443 HTTP/1.1 | ['Host: pp-probe-api.example.net:443', 'Proxy-Connection: Keep-Alive']
```

The model API call went to the proxy as a `CONNECT`, addressed by hostname, retried
against the proxy on failure. No `NODE_OPTIONS`, no `NODE_USE_ENV_PROXY`, no flag: a
bare environment variable was sufficient.

Against the *real* endpoint the tunnel is end-to-end functional, not merely attempted —
`omp` under the same proxy got a real HTTP 401 body back from `api.anthropic.com`
through the opaque tunnel (§3), which is the same transport.

### Telemetry: yes, and separately. [EXPERIMENT]

Every run produced, through the same proxy:

```
REQ CONNECT http-intake.logs.us5.datadoghq.com:443
```

Claude Code ships telemetry to a Datadog log intake, and that egress is proxied too.
Worth recording as a policy fact independent of the proxy question: **an
`allowlist` profile that does not include `http-intake.logs.us5.datadoghq.com` will
see Claude Code's telemetry refused at the proxy on every run.**

### Update checks: yes. [EXPERIMENT]

`claude update` under the proxy produced:

```
REQ CONNECT downloads.claude.ai:443
REQ CONNECT formulae.brew.sh:443
REQ CONNECT api.anthropic.com:443
REQ CONNECT http-intake.logs.us5.datadoghq.com:443
```

and reported "Claude is up to date!" — i.e. the check *succeeded* through the tunnel.
Note it consults the Homebrew formula index because this install is a cask.

### MCP: yes, both remote and local. [EXPERIMENT]

With `--mcp-config` + `--strict-mcp-config` pointing at an HTTP MCP server:

- remote `https://pp-probe-mcp.example.net/mcp` → `CONNECT pp-probe-mcp.example.net:443`
  at the proxy.
- **loopback** `http://127.0.0.1:9080/mcp` → `POST http://127.0.0.1:9080/mcp` **at the
  proxy**, in absolute-URI forward form, when `NO_PROXY` is unset. With
  `NO_PROXY=localhost,127.0.0.1` the request went **direct** and the loopback server
  logged the hit itself.

This is the single most load-bearing observation in the report and it is developed in §4.

### It does not need `NODE_USE_ENV_PROXY`. [EXPERIMENT + SOURCE]

Bun 1.4.0's `node:http`/`node:https` global agents are gated behind
`NODE_USE_ENV_PROXY`, exactly as Node's are — the embedded builtin reads:

```js
function shouldUseEnvProxy() {
  let value = process.env.NODE_USE_ENV_PROXY;
  if (Boolean(value) === !1 || value === "0") return !1;
  …
}
…
globalAgent: new Agent({ …, proxyEnv: shouldUseEnvProxy() ? process.env : undefined })
```

But Claude Code never depends on that path: every experiment above ran **without**
`NODE_USE_ENV_PROXY` and was proxied anyway, because `configureGlobalAgents` installs
Claude Code's own agents at init.

### It expects an `http://` proxy URL. [SOURCE]

The binary contains `[agent-proxy] client sent TLS to the relay port (HTTPS_PROXY must
be an http:// URL)`. Consistent with ADR 0004's plan (a loopback CONNECT relay), but
it means an `https://`-scheme proxy URL is not a supported input.

### Aside worth carrying into the design: Anthropic already solved playpen's problem, badly

Claude Code has its own sandbox (`SANDBOX_RUNTIME=1`) with its own egress proxy, and
its answer to "how do child processes learn about the proxy" is **to set twenty-odd
environment variables per ecosystem**. [SOURCE] The binary's env-template block contains,
literally:

```
NO_PROXY=  no_proxy=  HTTP_PROXY=http://  HTTPS_PROXY=http://  http_proxy=http://  https_proxy=http://
ALL_PROXY=  all_proxy=  GRPC_PROXY=  grpc_proxy=  FTP_PROXY=socks5h://  RSYNC_PROXY=localhost:
GIT_CONFIG_PARAMETERS='http.proxyAuthMethod=basic'
GIT_SSH_COMMAND=ssh -o ControlMaster=no -o ControlPath=none -o ProxyCommand='nc -X 5 -x localhost:…'
DOCKER_HTTP_PROXY=  DOCKER_HTTPS_PROXY=  CLOUDSDK_PROXY_TYPE=http  CLOUDSDK_PROXY_ADDRESS=localhost  CLOUDSDK_PROXY_PORT=
YARN_HTTP_PROXY  npm_config_proxy  npm_config_noproxy  GLOBAL_AGENT_*  ELECTRON_GET_USE_PROXY
CLOUDSDK_PROXY_*  -Dhttps.proxyHost=  http.nonProxyHosts  CLAUDE_CODE_HTTP_PROXY  CLAUDE_CODE_HTTPS_PROXY
```

and its `NO_PROXY` default is `localhost,127.0.0.1,169.254.0.0/16,10.0.0.0/8,
172.16.0.0/12,192.168.0.0/16`.

Two lessons. First, **the standard variables alone are not sufficient for the whole
subprocess tree** — `gcloud`, the JVM, Docker and `git+ssh` each need their own
spelling, and Anthropic pays that tax explicitly. Second, note the shape of their
`NO_PROXY` default: they enumerate loopback *and* every RFC1918 range, because nothing
bypasses them for free (§4).

---

## 2. undici and Node — has the historic behaviour changed?

Yes, twice, and both times **opt-in**. All of this is [SOURCE], against
`nodejs/undici` and `nodejs/node`, corroborated by [EXPERIMENT] on Node v26.7.0.

### undici

- `EnvHttpProxyAgent` was added by [undici PR #2994](https://github.com/nodejs/undici/pull/2994)
  (merge `ead42cdb2f9be593ab36e4e3826d18c01a87f71e`, 2024-04-19), shipped in **undici
  v6.14.0**; the doc page carries `<!--introduced_in=v6.14.0-->`. Exposed to Node's
  bundled copy by [PR #3148](https://github.com/nodejs/undici/pull/3148) (v6.16.0);
  lowercase-precedence fix [PR #3152](https://github.com/nodejs/undici/pull/3152)
  (v6.15.0). Marked **Stability 2 — Stable** by
  [PR #4049](https://github.com/nodejs/undici/pull/4049), **undici v7.4.0**.
- **It is never automatic.** It is a plain `Dispatcher` you must construct and pass to
  `setGlobalDispatcher()`. The default global dispatcher remains a plain `Agent`. So
  the ticket's premise — "undici ignores proxy env vars without an explicit
  `ProxyAgent`" — **is still true of undici used standalone**, in 2026, at v7.x.
- `lib/dispatcher/proxy-agent.js:40-42`: `shouldProxyTunnel()` returns true whenever
  `requestProtocol !== 'http:'`, so **https targets are always an opaque `CONNECT`
  tunnel**; plain-http targets are absolute-URI forwarded instead.

### Node core

- `NODE_USE_ENV_PROXY=1` — **added v24.0.0** (and backported to v22.21.0), Stability
  **1.1 Active Development**, `doc/api/cli.md`. Landed by
  [node PR #57165](https://github.com/nodejs/node/pull/57165) (`ada34bd0ea`), and at
  that point it covered **`fetch()` only**.
- `--use-env-proxy` CLI flag — **added v24.5.0**; permitted inside `NODE_OPTIONS`.
- **`node:http` / `node:https` got proxy support only in v24.5.0** (backport
  v22.21.0), by [node PR #58980](https://github.com/nodejs/node/pull/58980)
  (`7f654cee9e`). Before that, the classic core client **never** honoured proxy env
  vars, in any Node version, ever. That is why the entire npm ecosystem grew
  `https-proxy-agent`, `global-agent` and friends.
- `http.setGlobalProxyFromEnv([proxyEnv])` — runtime equivalent, added v25.4.0 /
  v24.14.0.
- **No Node release enables this by default**, through v26. `pre_execution.js`
  `setupHttpProxy()` returns immediately unless `--use-env-proxy` is set, and carries
  an explicit upstream TODO: *"Investigate whether it's possible to enable it by
  default without stepping on other existing libraries that sets the global dispatcher
  or monkey patches the global agent."*
- Note the internal split: `fetch` is served by undici's `EnvHttpProxyAgent`, while
  `node:http`/`https` use a **separately implemented** `ProxyConfig` in
  `lib/internal/http.js` with a `// TODO(joyeecheung): share code with undici.` The two
  have **different `NO_PROXY` grammars** (Node core's supports `*.example.com`
  wildcards and IPv4 ranges; undici's does not).

### Confirmed on this box [EXPERIMENT], Node v26.7.0

| Invocation | Result |
|---|---|
| `HTTPS_PROXY` set, `fetch()` | **DIRECT** — proxy never contacted |
| `HTTPS_PROXY` set, `node:https` | **DIRECT** |
| `NODE_USE_ENV_PROXY=1` + `HTTPS_PROXY`, `fetch()` | **PROXIED** (`CONNECT example.com:443`) |
| `NODE_USE_ENV_PROXY=1` + `HTTPS_PROXY`, `node:https` | **PROXIED**; on a refusing proxy the error is exact: `Failed to establish tunnel to example.com:443 via http://127.0.0.1:8898: HTTP/1.1 403 Forbidden` |
| `NODE_USE_ENV_PROXY=1` + `HTTP_PROXY`, plain-http target | **PROXIED** (absolute-URI form) |

So: **a Node-based agent under playpen's `allowlist` mode fails closed unless something
sets `NODE_USE_ENV_PROXY`.** That is the real exposure the ticket was reaching for —
it just does not land on Claude Code.

### Bun, for contrast [EXPERIMENT + SOURCE]

| Invocation (Bun 1.3.14) | Result |
|---|---|
| `HTTPS_PROXY` set, `fetch()` | **PROXIED**, no opt-in |
| `HTTPS_PROXY` set, `node:https` | **PROXIED** |
| either, with `NODE_USE_ENV_PROXY=1` | unchanged (still proxied) |

Bun's native client resolves proxies from the env whenever no explicit `proxy` option
is given, lowercase-first, **strictly scheme-matched** (`http_proxy` only for `http:`
targets, `https_proxy` only for `https:` — unlike undici, where `HTTP_PROXY` alone
covers both), and tunnels https targets with `CONNECT`. Bun does not read `ALL_PROXY`
in its native fetch path.

Documented caveat, [SOURCE] only: Bun's **`node:http`/`node:https` compat layer** had
`proxyEnv: undefined, // TODO:` hard-coded through the released 1.3.x line, and only
gained `shouldUseEnvProxy()` on the 1.4.0 line — which matches what I read out of the
Claude Code binary. My Bun 1.3.14 `node:https` observation above nevertheless came back
PROXIED, i.e. **the observed behaviour is more permissive than the JS builtin implies**;
the proxying is presumably happening in Bun's native transport below the compat layer.
Flagged in §7 as unresolved.

---

## 3. `omp` — does it honour it?

`omp` **is installed on this box** (17.3.4), so this is experimental rather than
inferred.

### Model API: yes. [EXPERIMENT]

```
$ HTTPS_PROXY=http://127.0.0.1:8899 omp -p "hi" --no-session --no-lsp --no-tools \
    --model anthropic/claude-sonnet-4-5 --api-key sk-ant-bogus-probe-key
401 {"type":"error","error":{"type":"authentication_error","message":"API key is invalid."}}
```

Proxy log for that run:

```
CONNECT api.anthropic.com:443
CONNECT catalog.stencil.so:443
CONNECT zenmux.ai:443
```

Note this is a **complete round trip**: a real HTTP 401 body came back from Anthropic
through the opaque `CONNECT` tunnel. Not just "the connection arrived at the proxy" —
the workload worked. `omp` also reaches a model catalogue (`catalog.stencil.so`) and a
router (`zenmux.ai`) at startup; both are egress an `allowlist` profile must name.

### Its resolution chain is first-party and richer than the runtime's [SOURCE]

```js
function l60(w, u) {                     // resolveProxy(provider, url)
  if (R60(u)) return;                    // bypass?
  const g = u.protocol === "https:" || u.protocol === "wss:"
    ? Bun.env.HTTPS_PROXY || Bun.env.https_proxy
    : Bun.env.HTTP_PROXY  || Bun.env.http_proxy;
  return d60(w) || g || Bun.env.ALL_PROXY || Bun.env.all_proxy || undefined;
}
```

with `d60(provider)` reading `PI_PROXY_<PROVIDER>` then `PI_PROXY`. So the precedence is
**per-provider override → global override → scheme-matched standard var → `ALL_PROXY`**,
and `wss:` is handled alongside `https:` — its changelog records fixing exactly that:
*"Fixed `/live` sideband WebSockets ignoring standard proxy environment variables and
`NO_PROXY`"* (oh-my-pi #6770).

### `omp` is the only subject that bypasses loopback for free [SOURCE + EXPERIMENT]

`R60()` calls `IC0(hostname)` **before** consulting `NO_PROXY`, and `IC0` hard-codes:

- `localhost`, `*.localhost`, **`metadata.google.internal`**
- IPv4 first octet `127`, `10`, `0`; `169.254/16`; `192.168/16`; `172.16–31`
- `::1`, `::`, `fe80::/10` (`/^fe[89ab][0-9a-f]:/`), `fc00::/7` (`/^f[cd][0-9a-f]{2}:/`)

This is a considered, correct bypass list — it is essentially nono's non-overridable
link-local/metadata deny turned inside out — and it means `omp`'s local-model providers
(the binary has built-in endpoints for Ollama `127.0.0.1:11434`, vLLM `127.0.0.1:8000`,
LM Studio `127.0.0.1:1234`, llama.cpp `127.0.0.1:8080`) keep working under a proxy
without playpen doing anything.

[EXPERIMENT] `omp` ran clean with `NO_PROXY=localhost,127.0.0.1` set alongside
`HTTPS_PROXY` — same 401, same single `CONNECT api.anthropic.com:443`.

### The embedded kernels are the interesting part [SOURCE]

ADR 0004's consequence section already names `omp`'s Python and Bun kernels calling back
over a loopback bridge as the reason loopback stays wildcard-open. The bridge is
`PI_TOOL_BRIDGE_URL` / `_TOKEN` / `_SESSION`, injected into each kernel's environment,
and the kernels POST to `<base>/v1/tool`. **`omp` has already hit playpen's exact
problem here and fixed it in-band.** The embedded Python kernel reads:

```python
import urllib.error, urllib.request
# urllib discovers environment and macOS SystemConfiguration proxies. This
# host-owned loopback endpoint must always connect directly.
_BRIDGE_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
```

That comment is a first-party confirmation of §4's finding, written by someone who was
bitten by it. Verified [EXPERIMENT]: with `HTTP_PROXY` set, `urllib`'s **default**
opener sends a loopback request to the proxy, and `build_opener(ProxyHandler({}))` sends
it direct.

The other kernels are not uniformly protected. The Ruby kernel uses
`Net::HTTP.new(host, port)` — which defaults `p_addr` to `:ENV` — but Ruby's
`URI::Generic#find_proxy` exempts `127.0.0.0/8` and `::1`, so it is safe by accident of
stdlib design ([EXPERIMENT]: `HTTP_PROXY` set, Ruby loopback request went **DIRECT**).
The Julia kernel uses `Downloads` (libcurl), which honours env proxies and does **not**
exempt loopback — flagged in §7.

---

## 4. `NO_PROXY` and loopback — the actual finding

ADR 0004 requires that loopback traffic **not** transit the proxy. Two things must hold
for that: loopback must be bypassed, and the bypass must cover every spelling.

### Nothing bypasses loopback by default. [EXPERIMENT]

Target `http://127.0.0.1:9080/`, `HTTP_PROXY=http://127.0.0.1:8899`, verdict read off
the proxy's own log:

| Client | no `NO_PROXY` | `NO_PROXY=127.0.0.1` | `NO_PROXY=localhost` | `NO_PROXY=*` |
|---|---|---|---|---|
| Bun 1.3.14 `fetch` | **PROXIED** | DIRECT | **PROXIED** | DIRECT |
| Node 26.7 `fetch` + `NODE_USE_ENV_PROXY` | **PROXIED** | DIRECT | **PROXIED** | — |
| Python 3 `urllib` default opener | **PROXIED** | — | — | — |
| Claude Code 2.1.224 (MCP over loopback) | **PROXIED** | — | DIRECT (with `localhost,127.0.0.1`) | — |
| `omp` 17.3.4 | DIRECT (built-in bypass, §3) | DIRECT | DIRECT | DIRECT |
| curl 8.21 | DIRECT (`HTTP_PROXY` ignored, see below) | — | — | — |
| Ruby `Net::HTTP` | DIRECT (`find_proxy` loopback exemption) | — | — | — |

`omp` is the exception, not the rule. **Claude Code, Bun, Node/undici and Python all
send loopback traffic to the proxy** when `NO_PROXY` is unset.

### `localhost` never covers `127.0.0.1`. Anywhere. [EXPERIMENT + SOURCE]

Confirmed experimentally for Bun and Node above, and confirmed in source for undici
(`lib/dispatcher/env-http-proxy-agent.js` — lowercase string compare on the URL
hostname, exact or dot-boundary suffix; no IP normalisation, no CIDR), Node core
(`lib/internal/http.js:151-194` — same, plus `*.host` wildcards and IPv4 *ranges*, but
still no name→IP resolution), Bun's native matcher, reqwest/hyper-util
(`NoProxy::contains` routes IP literals to `IpMatcher` and hostnames to `DomainMatcher`
and never crosses over), and ureq. **In not one of these does `NO_PROXY=localhost` cause
`http://127.0.0.1:…` to bypass.**

Corollary for playpen: the `NO_PROXY` playpen sets must enumerate at minimum
`localhost,127.0.0.1,::1`, and — if the boundary ever routes a container/VM bridge —
the RFC1918 ranges too, which is precisely why Anthropic's own default is
`localhost,127.0.0.1,169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`. Note that
CIDR entries are honoured by *some* of these matchers and silently ignored by others
(undici has no CIDR support at all), so the CIDR portion is best-effort.

### Claude Code honours `NO_PROXY` — with one path that does not. [EXPERIMENT]

Reproducible across three runs, `HTTPS_PROXY` set and
`ANTHROPIC_BASE_URL=https://pp-probe5.example.net`:

| `NO_PROXY` | proxy saw |
|---|---|
| *(unset)* | `pp-probe5` ×6, `api.anthropic.com` ×4-10, datadog ×2 |
| `pp-probe3.example.net` (= the base URL) | base URL **absent** ✓, `api.anthropic.com` ×10, datadog ×2 |
| `api.anthropic.com` | `pp-probe5` ×6, **`api.anthropic.com` ×4**, datadog ×2 |
| `.anthropic.com` | `pp-probe5` ×6, **`api.anthropic.com` ×4**, datadog ×2 |
| `api.anthropic.com,http-intake.logs.us5.datadoghq.com` | `pp-probe5` ×6, **`api.anthropic.com` ×4**, datadog **absent** ✓ |
| `*` | **nothing at all** ✓ |
| `localhost,127.0.0.1` (MCP loopback test) | loopback **absent** ✓ |

So `NO_PROXY` works for the model API base URL, for telemetry, for MCP and for
loopback — but **four `CONNECT api.anthropic.com:443` per run survive every host-shaped
`NO_PROXY` entry** while still obeying `NO_PROXY=*`. That is consistent with the §0
observation that the binary carries several independent proxy resolvers: some startup
subsystem (OAuth token refresh and/or feature gating) is on a resolver whose bypass list
is checked differently. It does not affect playpen's decision — the traffic goes *to*
the proxy, which is the safe direction — but it is a caution against assuming `NO_PROXY`
is uniformly honoured within one binary.

### `HTTP_PROXY` uppercase is not universally read. [EXPERIMENT]

curl 8.21 **ignores `HTTP_PROXY`** and honours only lowercase `http_proxy` for
plain-http targets — the httpoxy CGI mitigation — while honouring `HTTPS_PROXY`
uppercase fine. reqwest and hyper-util implement the same safety valve differently
(drop all proxies if `REQUEST_METHOD` is in the environment). **playpen should set both
cases of every variable.**

---

## 5. Opaque `CONNECT` vs the TLS-intercepting path

**Opaque `CONNECT` is sufficient for every subject tested. Nothing required
interception.** [EXPERIMENT]

The proxy used throughout was a blind byte-pump: it answers `200 Connection
Established` and splices sockets, with no CA, no certificate minting, and no visibility
into the TLS stream. Under it:

- Claude Code completed `claude update` ("Claude is up to date!"), reached its MCP
  endpoints, and shipped telemetry.
- `omp` completed a full model-API round trip and got a real 401 JSON body back.
- Bun, Node and curl all fetched `https://example.com` end to end.

Every https request from every subject arrived as `CONNECT host:443`, hostname-addressed
— which is the granularity ADR 0004's allow-list is written in. No client demanded
absolute-URI forwarding for https, and no client failed on the absence of a trusted CA,
because there was nothing to trust. **ADR 0004's "default to opaque, intercept
selectively" is confirmed as the right default**, and interception remains needed only
where credential injection or path/method rules demand L7 visibility.

Two shape notes for the proxy implementation:

- **Plain-http targets are not tunnelled.** Bun, Node and Claude Code's MCP client all
  used absolute-URI forwarding (`POST http://127.0.0.1:9080/mcp HTTP/1.1`) with
  `Proxy-Connection: keep-alive`. playpen's proxy must implement both forms even under
  an HTTPS-only egress policy, if only to *refuse* the http one legibly.
- **A `403` to `CONNECT` propagates as a clean, attributable error**, not as a socket
  drop: Node reported `Failed to establish tunnel to example.com:443 via
  http://127.0.0.1:8898: HTTP/1.1 403 Forbidden`. That is exactly the in-band
  distinguishability ADR 0004 asks for, and it confirms the "answer, don't drop" rule is
  implementable and legible at the client.

---

## 6. Bottom line

**The evidence points clearly toward keeping ADR 0004 as written. Neither transport
(Q4) nor discovery (Q9) is reopened by this ticket, and the does-not-interpret law is
not put under pressure.**

Point by point against the ticket:

1. **Does Claude Code honour `HTTPS_PROXY` for model API traffic?** Yes — observed, on
   2.1.224. Also for telemetry (Datadog), update checks (`downloads.claude.ai`,
   `formulae.brew.sh`) and MCP (both remote https and local http). It ships its own
   proxy layer and does not depend on the runtime's, so it needs no `NODE_OPTIONS` and
   no `NODE_USE_ENV_PROXY`.
2. **Has undici changed?** `EnvHttpProxyAgent` exists since **undici v6.14.0**
   (2024-04), stable at **v7.4.0**, but is **still opt-in** — standalone undici ignores
   proxy env vars to this day. Node wired it behind `NODE_USE_ENV_PROXY` in **v24.0.0**
   (fetch) and **v24.5.0** (`node:http`/`https`, plus the `--use-env-proxy` flag), and
   **no Node release through v26 turns it on by default** — confirmed by experiment on
   v26.7.0 and by the standing TODO in `pre_execution.js`. This is irrelevant to Claude
   Code, which is Bun, but it is exactly right for **any Node-based agent or MCP
   server** playpen might confine.
3. **Does `omp` honour it?** Yes — observed, on 17.3.4, a full 401 round trip through
   the tunnel. It is a Bun binary, not Rust, with its own
   `PI_PROXY_<PROVIDER>`/`PI_PROXY`/standard-var/`ALL_PROXY` chain covering `wss:` too.
4. **Does either honour `NO_PROXY` for loopback?** Both do when told. **Neither
   bypasses loopback for free except `omp`**, which hard-codes a loopback + RFC1918 +
   link-local + `metadata.google.internal` bypass. Claude Code proxies a loopback MCP
   connection unless `NO_PROXY` names it. And `localhost` never implies `127.0.0.1` in
   any stack examined.
5. **Is opaque `CONNECT` enough?** Yes, for every subject. Nothing needed the
   intercepting path.

**The one thing ADR 0004 must change** is a consequence, not a decision. The ADR
currently treats loopback openness as a *kernel* property ("loopback stays
wildcard-open"). That is necessary but not sufficient: the kernel permitting a loopback
connect does not stop the *client* from choosing to route it through the proxy, and by
default it will. Setting `NO_PROXY` is therefore not a nicety — **it is load-bearing for
the `omp` kernel-bridge workload the loopback law exists to protect**, and it must
enumerate `localhost`, `127.0.0.1` and `::1` at minimum. That is still policy data in
the environment, not interpretation of the agent's invocation, so it costs nothing
against ADR 0002.

Two smaller obligations fall out:

- **Set both cases** of every variable (`HTTPS_PROXY`/`https_proxy`,
  `HTTP_PROXY`/`http_proxy`, `NO_PROXY`/`no_proxy`), since curl ignores uppercase
  `HTTP_PROXY` by design and Bun prefers lowercase.
- **`allowlist` fragments for the flagship kinds are not just the model API.** Claude
  Code needs `api.anthropic.com`, `http-intake.logs.us5.datadoghq.com`,
  `downloads.claude.ai` and (cask installs) `formulae.brew.sh`; `omp` needs
  `api.anthropic.com`, `catalog.stencil.so` and `zenmux.ai`. A profile with only the
  model API host will present as a mysteriously slow or partly-broken agent, which is
  exactly the "npm is broken" failure mode ADR 0004's named-fragment consequence exists
  to prevent.

---

## 7. What remains unverified

- **Everything here is macOS-only.** No Linux run. Under `bwrap` + netns the loopback
  situation differs materially (the agent gets its own loopback), and the proxy is
  reached over a netns-local address; none of that was exercised.
- **The residual `api.anthropic.com` traffic that ignores host-shaped `NO_PROXY`** (§4)
  was not attributed to a specific subsystem. I did not disassemble far enough to say
  whether it is OAuth refresh, feature gating, or the bundled `https-proxy-agent` on a
  different bypass list. It obeys `NO_PROXY=*`, so it *is* reading something.
- **Bun's `node:http` compat layer.** Source says `proxyEnv: undefined` on released
  1.3.x and `shouldUseEnvProxy()` on the 1.4.0 line; my experiment showed Bun 1.3.14
  `node:https` proxying anyway. I did not locate where in Bun's native transport that
  happens, so I cannot say which of the two is authoritative for a *library* that uses
  `node:https` under Bun (axios, got, node-fetch). **This is the highest-value gap**: if
  the compat layer is genuinely inert on some Bun versions, then MCP servers and plugins
  written against `node:http` and run under Bun would fail closed under `allowlist`.
- **Bun 1.4.0 could not be tested standalone** — it is not yet a published GitHub
  release (latest tag is `bun-v1.3.14`), so every Bun-1.4.0 claim is read out of the
  Claude Code binary's embedded builtins rather than exercised directly. The
  `NODE_USE_ENV_PROXY` gating difference between 1.3.14 and 1.4.0 is therefore
  source-only.
- **A partial harness error, disclosed for the record.** An earlier pass through this
  matrix used a shell helper that collapsed two `VAR=value` pairs into one malformed
  `HTTPS_PROXY`, and produced a spurious and dramatic "Bun breaks whenever `NO_PROXY` is
  set" result. It was a harness bug, not a Bun bug; every table above was re-run with
  explicit invocations. The only real residue is that **Bun reports a malformed proxy
  URL as `Unable to connect. Is the computer able to access the url?`** — an unhelpful
  error playpen should not let an operator hit.
- **`git+ssh` and non-HTTP transports** were not exercised at all; ADR 0004 already
  rules them out of scope.
- **WebSocket egress** (`wss:`) was not exercised for either agent, though `omp`'s
  source handles it explicitly and its changelog records a fix in that area. Claude
  Code has a `getWebSocketProxyUrl` but it was not reached by any of my probes.
- **Authenticated proxies.** Claude Code has a whole proxy-auth-helper subsystem
  (`getProxyAuthFromHelper`, `prefetchProxyAuthFromHelperIfSafe`,
  `_setProxyAuthHelperConfig`) that was not exercised. Irrelevant to playpen's own
  loopback proxy, but relevant if playpen ever has to chain through a corporate proxy.
- **`omp`'s Julia kernel bridge** uses `Downloads` (libcurl), which honours env proxies
  and does not exempt loopback, unlike the Python kernel's explicit
  `ProxyHandler({})`. Whether that is a live bug in `omp` under a proxy was not tested.
- **The claim that Claude Code's egress host set is complete.** I observed four hosts
  plus whatever the configured base URL is. A longer or differently-configured session
  (plugins, `ultrareview`, background agents, `gateway`) will reach more.
