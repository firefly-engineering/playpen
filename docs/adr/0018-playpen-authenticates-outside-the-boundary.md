# playpen authenticates outside the boundary

A subscription login is not a new mechanism. The operator authenticates the agent **natively,
outside the boundary**, where the browser is; the resulting token rests in the host's own store
— Keychain on macOS, the agent's credential file on Linux — and playpen reaches it through
ADR 0008's **minter**, which already runs pre-launch and unconfined. The sandbox receives a
**session phantom** exactly as it does for an API key. There is no capture, no interception of a
token endpoint, no phantom store, and playpen never writes a real token to disk.

Renewal is the minter's job, not playpen's: a minter that refreshes performs the token exchange
itself and returns the fresh access token, on ADR 0008's own reasoning that a real exchange is
provider API surface which must not sit in the confinement binary.

**Logging in from inside the sandbox is out of scope**, permanently, not deferred.

## Why

**The ticket's premise was false, and correcting it removed the feature rather than designing
it.** Issue #26 was charted on the reading that *"do the login outside and playpen cannot use
it"* is the honest-but-lossy answer, leaving capture-and-rewrite as the only shape that survives.
playpen *can* use it. ADR 0008 established that a minter is trusted host code in the policy
author's own class, run **before the sandbox exists** — so ADR 0006's denial of `SecurityServer`,
which is what makes the Keychain unreachable and credential helpers fail loudly, binds only
*inside* the boundary and never reaches the minter. Reading the host store is the **trivial
keystore minter** ADR 0008 explicitly blessed. Nothing about a subscription token makes it a
different kind of secret; only *where the human put it* differs, and the minter interface exists
precisely so that playpen does not model that.

**A subscription token is not a metered inference capability, so the cheap option was never
available.** The alternative on the table was passthrough — hand the real host token to the
sandbox in `CLAUDE_CODE_OAUTH_TOKEN`, one entry in the **set table**, on the argument that such a
token is abusable only to a capacity that resets every five hours and is periodically invalidated
anyway, so exfiltration is self-healing. Established as fact from the shipped binary
(Claude Code 2.1.224): the OAuth surface includes `/oauth/claude_cli/create_api_key`, alongside
`/oauth/claude_cli/roles` and `/oauth/organizations/`. Both premises fail on that one endpoint —
a minted API key is billed in dollars rather than metered in a resetting window, and it **outlives
the OAuth token and survives re-login**, which converts a time-boxed exfiltration into a permanent
one. The token is an account credential that *contains* an inference capability.

Under the minter shape the escalation is closeable by machinery that already exists: the agent
holds only a phantom, so an **endpoint rule set** on the route denies `create_api_key` under
ADR 0017's law. Under passthrough it is not closeable at all — ADR 0017's rule restricts *the
credential*, and passthrough makes the agent the credential holder, so there is nothing left to
restrict. This is the one place where that law's framing pays a concrete dividend rather than
merely being true.

**Capture's only remaining advantage was logging in from inside, and that path is broken by
construction.** Capture — `nono-proxy`'s `oauth_capture`, which is reachable through the public
`ProxyConfig` and whose 90-day TTL and 4096-entry store fire only when a persist path is set, so
issue #6's stated objection did not actually bind — would have intercepted the token exchange and
rewritten the response. But the step *before* that exchange is a browser. ADR 0006's floor denies
`lsopen`, so nothing opens, and the redirect lands on a **loopback callback**. That inverts the
first **named residual**: on macOS loopback is wildcard-open and shared with the host, so the
operator's own browser can reach the sandbox's callback listener and the flow completes; on Linux
the sandbox has its own netns and the callback is unroutable. Building the flagship credential
path on a mechanism that works on one platform *by way of an acknowledged leak* is the worst
available foundation, and the device-code flow that would be platform-symmetric needs no
cooperation from playpen anyway. So the login goes where the browser already is.

**Four of the ticket's five questions dissolve rather than resolve.** Where a captured phantom
lives is moot — nothing persists, because the persistence already exists on the host and playpen
reads it; a playpen-owned store would have been a **second at-rest copy, in plaintext, of the most
valuable secret on the machine**, which is a security regression dressed as a feature. Whether
refresh flows work is moot — refresh is the minter's, and the proxy holds no state the sandbox
depends on across restarts. Whether capture is reconcilable with the narrow `nono-proxy` surface
is moot — capture is not configured. And the **run record** needs no change: the credential exists
at launch with an `expires_at`, which is ADR 0008's ordinary shape, so the pre-launch record
stays a projection of resolved *policy* and never of outcome.

**A mid-session re-mint is renewal and not expansion, for a reason worth stating once.** The
capability is the *route*; the secret is its contents. A declared route is a reachable,
credentialed destination from the moment policy resolves — the **manifest** can state it before
any token is fetched — so nothing the agent reaches after a re-mint was unreachable before it.
This is the same argument ADR 0008 used for re-minting, generalised rather than repeated, and it
is what would have been needed as an *exception* had capture been adopted.

**On the missing-credential case, playpen says nothing.** A profile that resolves no route for the
agent's own model API launches anyway and the agent gets the provider's `401`. Knowing which host
a **kind** needs a credential for is per-agent knowledge ADR 0005 confined to the kind table, and a
required-credential field there would make launch depend on a fact that changes when a vendor moves
an endpoint. ADR 0008's line generalises: the provider's own `401` is more accurate than anything
playpen could synthesize, and the manifest already states the credential routes, so an agent that
cannot authenticate can see why.

## Costs

**A refreshing minter races the host.** The minter reads, and may write back, state that a
host-level agent instance owns. Not writing back means the host store drifts stale and every run
pays a refresh; writing back means playpen mutates shared host state concurrently with a desktop
agent. Whether the write-back happens is the operator's choice, expressed in their own minter, and
the race is the **seventh named residual**.

**Whether that race is merely untidy or actively hostile is unmeasured.** If the provider rotates
refresh tokens single-use, a minter refresh **invalidates the host instance's login** — an operator
logged out of their own desktop agent by running playpen. This is recorded as an open research
question and it does not change the decision, only the guidance shipped alongside the reference
minter.

**Non-native credential storage is unreached.** A workload whose token lives somewhere the minter
cannot read, or which reads only a config file rather than an environment variable, is the map's
standing non-env-delivery question and is untouched here.
