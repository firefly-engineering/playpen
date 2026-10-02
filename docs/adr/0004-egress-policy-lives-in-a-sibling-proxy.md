# Egress policy lives in a sibling proxy, and the kernel's only job is to make it the sole exit

> **Status: superseded by [ADR 0020](0020-playpen-claims-credential-confinement-only.md) ([#35](https://github.com/firefly-engineering/playpen/issues/35)).**
>
> Traffic confinement is retired: playpen claims nothing about what the agent may reach on the
> network. The proxy survives only as the credential broker of
> [ADR 0008](0008-credentials-are-minted-outside-and-only-phantoms-cross-the-boundary.md), running
> iff a credential route resolves, passing uncredentialed traffic through as opaque `CONNECT`. The
> analysis below — no mechanism expresses per-host egress, so name policy can only live at L7 — still
> stands; what changed is that the operator does not want the claim it would have bought. Read
> ADR 0020 instead.

playpen enforces its egress allow-list in an **L7 proxy running outside the boundary**, spawned
per run as a detached sibling and reached over TCP loopback. The kernel mechanism contributes
exactly one thing: making that proxy the only way out. Egress is a **profile** property with
three settings — `none`, `open`, `allowlist` — of which only `allowlist` has a proxy at all.
Transport is HTTPS-only, the sandbox gets no resolver, and where the kernel cannot pin the exit,
playpen refuses.

_Amended by [ADR 0013](0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md):
the proxy is not a detached sibling but runs in-process on the **supervisor** ADR 0010
established, and `open` means **no allow-list, not no proxy** — it keeps the proxy whenever a
credential route resolves. "The sandbox gets no resolver" holds under `allowlist` only._

## Why

There was no design space here to speak of. **No mechanism on either platform can express
per-host egress.** SBPL's compiler rejects it outright — `host must be * or localhost in network
address`, so the host portion of an `ip` filter accepts two values and a literal `127.0.0.1` is
not one of them. Landlock's `struct landlock_net_port_attr` has no address field; it gates the
TCP port and nothing else. seccomp cannot dereference a `struct sockaddr`. nftables resolves
hostnames once at rule-load time, which is useless against a CDN-fronted registry. Name-based
policy can only live at L7, and an L7 proxy is only *enforcement* rather than *convention* if
the kernel makes bypassing it impossible. Everything below follows from that split.

**Profile, not workspace.** The workspace model keeps forge scope per-workspace, deliberately,
because merging it would demand a broader credential than either workspace justified. Egress
cannot follow that pattern: there is one netns, one SBPL profile, one proxy port over one
process tree, and the kernel cannot attribute a connection to a workspace. Attributing it at L7
would be a fiction — the proxy sees a TCP connection from a process tree, and any workspace
identity the agent supplied would be forgeable from inside. So egress belongs to the profile,
which is the unit that maps 1:1 onto the boundary. The consequence is accepted rather than
papered over: forge scope and egress allow-list are now two independent lists in two
vocabularies that can disagree, and a profile that mints a credential for an org it cannot reach
is a policy bug playpen **refuses** at launch rather than discovering at credential-use time.

**HTTPS-only, and no resolver.** An HTTP proxy is the only place name policy can live, and it
only understands HTTP; `git+ssh` is raw TCP/22 with no CONNECT and no SNI. The alternatives both
fail: permitting raw TCP to the *resolved* addresses of allow-listed hosts reopens the rebinding
hole the proxy exists to close and makes one allow-list mean two different things, and tunnelling
ssh via `ProxyCommand` is cooperative — a grandchild sheds it by not honouring it. Losing
`git+ssh` is a real cost to users and is stated as one, but it is aligned with where the design
was going anyway: a credential can only be injected into a request the proxy can read. Denying
the sandbox a resolver falls out of the same choice, and pays for itself — with the proxy as the
only resolver, DNS rebinding is structurally impossible rather than mitigated.

**Selective TLS interception, defaulting to opaque.** An opaque `CONNECT` tunnel enforces the
allow-list at hostname granularity, which is the granularity the allow-list is written in.
Terminating TLS buys path and method rules and header injection, at the cost of a CA in the
sandbox's trust bundle and a much larger blame surface. Interception is therefore reserved for
hosts whose rule actually needs it, which keeps the CA off the path for most traffic while
leaving credential injection possible at all. The CA is ephemeral, in-memory, per-session, and
never written to disk — nono's `--trust-proxy-ca` and `--proxy-ca-cert` escape hatches persist a
CA well beyond the session and are the specific mistakes not to copy. A TLS-intercept failure is
a refusal, never a fall-back to transparent tunnel.

**One proxy process, two lists.** The egress allow-list and the credential broker share a socket,
a process and the interception apparatus, and differ entirely in what they are for. Splitting
them into chained processes doubles the lifetime and orphan problem for no isolation gain — both
halves are equally trusted and equally outside the boundary. Merging their *configuration* is the
actual trap: it would make "reachable" and "authenticated" the same fact, when a profile
legitimately reaches a package registry with no credential at all, and wants credentials scoped
more narrowly than a host. One process, two lists.

**Per-run sibling over a shared daemon.** A host-wide daemon multiplexing sessions by token is
where one misrouted session leaks a profile's credentials into another profile's sandbox, and it
leaves a standing target running between runs — a bad trade for saving a process spawn. A
brokered unix socket would be tighter on Linux, where bubblewrap can bind one in natively, but it
diverges the platforms' transports and on macOS moves the exit from the network policy into the
filesystem allow-list, splitting the egress story across two mechanisms. Uniform TCP loopback
wins on being one story.

**"Cooperative-only" counts as unavailable.** On a Linux host without unprivileged user
namespaces there is no netns, and without a netns the proxy pin is convention rather than
enforcement — a grandchild that ignores `HTTPS_PROXY` walks straight out. Accepting that
configuration because the environment variables are still set would be the standing
no-silent-downgrade law failing in its most plausible disguise: it is observationally identical
to real enforcement in every respect except the one that matters. playpen probes the required
capabilities before launch, so the refusal names the missing capability rather than the symptom.

## Consequences

- **Loopback stays wildcard-open, and that means different things per platform.** On Linux the
  agent gets its own loopback inside the netns, so it costs nothing. On macOS loopback is shared
  with the host, so the agent can reach the operator's local services. Pinning outbound loopback
  to the proxy port would close this and would also kill the workload the law exists for —
  `omp`'s Python and Bun kernels call back over a loopback bridge, which is a loopback *connect*.
  The macOS host-loopback surface is a named residual, in the same trust class as ACP's
  client-side execution, and it makes Linux the stronger platform rather than an equal one.

- **`open` means no proxy, not a permissive proxy.** A proxy that allows every host is pure
  overhead and one more interception surface. Only `allowlist` has a moving part that can be
  absent, so only `allowlist` can fail to be enforceable.

  _Amended by [ADR 0013](0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md):
  correct about the allow-list, wrong about the process. Written before ADR 0008 gave the proxy a
  second job, so it read "no enforcement" as "no proxy". Under `open` the proxy runs unpinned
  whenever a credential route resolves — not as a permissive allow-list, but as the credential
  broker with its egress list absent._

- **Named allow-list fragments, no built-in base list.** A registry is several CDN-fronted
  hostnames and an operator writing them from scratch debugs the result as "npm is broken". But
  an always-merged default list is what `nono-cli` does and what ADR 0003 walked away from,
  because it creates a second policy author whose decisions are inherited without being stated.
  playpen ships named fragments the operator composes explicitly, as **data in the policy
  document** rather than code, so "which hosts did I allow" is answered by reading the resolved
  policy. Host entries are exact names or left-anchored label-boundary suffixes — never regex —
  and port 443 is implied, since an entry names a host and transport is HTTPS-only.

- **A policy denial is always distinguishable, in-band, from a transport failure.** The proxy
  answers rather than drops, and the answer identifies playpen and names the refused host.
  Dropping the connection makes a policy decision indistinguishable from flaky wifi, which agents
  retry. The wording and the operator-side log belong to the failure-UX work.

- **The credential broker inherits this transport** and decides only minting and injection
  semantics.

- **Orphan cleanup is now certain rather than conditional.** A detached sibling's lifetime is not
  tied to the agent's by the process tree, so exit, crash and orphan cases must be designed.

  _Resolved by [ADR 0013](0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md)
  by deletion: the proxy runs in the supervisor, so an orphaned proxy is structurally impossible
  and there is nothing to detect at next launch._

- **A client that ignores proxy environment variables fails closed.** That is correct behaviour,
  but Claude Code is Node and `undici` has historically ignored proxy environment variables
  without an explicit `ProxyAgent`. Whether the flagship workload can be proxied at all is
  unverified and load-bearing: forcing proxy awareness per agent kind would violate the
  does-not-interpret law, and the answer could reopen both the transport and the discovery
  decision.
