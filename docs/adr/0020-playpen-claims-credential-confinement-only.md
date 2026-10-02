# playpen claims credential confinement only

*Supersedes [ADR 0004](0004-egress-policy-lives-in-a-sibling-proxy.md).*

playpen confines the **means** of using a credentialed resource, and not the network. The proxy is
a credential broker and nothing more: it exists iff a **credential route** resolves, every client
is pointed at it, and it injects secrets for routed destinations and passes everything else
through as an opaque `CONNECT` with no check. **Traffic confinement is retired.** There is no
egress setting, no allow-list, no pin to the proxy, and no claim about what the agent may reach on
the network.

Credential confinement is widened to name what "the means" covers beyond a secret held in a
variable or a file: a **credential oracle**, an endpoint that performs a credentialed operation
for whoever reaches it. A unix-socket oracle (`ssh-agent`, `gpg-agent`, a password manager's
agent, `docker.sock`) is denied by default. A network-reachable one (a cloud metadata endpoint, a
credential service on host loopback) is a **named residual**.

## Why

**The operator's concern was never egress.** The record treated traffic confinement as a first-class
claim and built most of its network design on it: three egress modes, allow-list fragments, a
kernel pin, "no resolver", and refusing hosts without user namespaces. Assembling the spec
([#9](https://github.com/firefly-engineering/playpen/issues/9)) showed that the chosen backend
cannot hold that claim as written:

- nono's `ProxyOnly` pins outbound loopback to the proxy port on both platforms.
- On Linux, nono's pin is a Landlock port rule that cannot see addresses. The only address check
  within reach is a seccomp user-notify `CONTINUE`, and the kernel documents that as unsafe for
  policy because the arguments can be rewritten between the check and the call.
- On macOS, nono always leaves the `mDNSResponder` resolver open and grants bind/inbound on
  every interface.

Repairing all of that would have meant a playpen-created network namespace on Linux, refusing
stock Ubuntu ≥ 23.10, and two upstream patches on macOS. When that was put to the operator, the
answer was that none of it protects anything they care about. What they care about is that the
*means* to use specific cloud resources never sits inside the boundary unchecked. The
authentication is what the proxy must be necessary for, and other traffic is fine.

**Credential confinement already stood on its own.** [ADR 0013](0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md)
separated the two confinements and showed every cell of their product to be coherent. `open`
plus routes was already a supported shape: the real secret is never in the environment, so an
agent that bypasses the proxy merely fails to authenticate. Retiring traffic confinement
promotes that cell to the whole model. It loses nothing the operator wanted and deletes every
open problem in [#35](https://github.com/firefly-engineering/playpen/issues/35).

**Retiring it exposed one channel that *is* a means.** A unix socket can sign, decrypt or act on
the operator's behalf without a secret ever crossing the boundary. [ADR 0012](0012-the-environment-is-constructed-and-exactly-one-author-writes-each-name.md)
bans the *name* `SSH_AUTH_SOCK`, but a `connect()` to the socket needs no name. On macOS a
unix-socket connect is a Seatbelt *network* operation, so it was denied under `ProxyOnly` only as
a side effect of traffic confinement. Under `AllowAll`, nono grants every unix socket on the host.
On Linux, Landlock gates a pathname-socket `connect()` only from ABI 9 (kernel 7.1). So this hole
predates the retirement there.

That is the purest case of the means escaping, so it joins credential confinement rather than
following egress out:

- **macOS:** default-deny, through an upstream nono change so that `AllowAll` stops granting unix
  sockets. playpen pins a nono version with that change and refuses on macOS until one exists.
- **Linux, ABI ≥ 9:** default-deny, enforced by Landlock.
- **Linux, ABI < 9:** a **named residual**, recorded outward (in the run record and
  `playpen explain`) and never in the manifest. Refusing every pre-7.1 kernel would make playpen
  unusable on current distributions, while naming the gap keeps the claim honest and lets it
  close as kernels move.

A connect to a socket under a granted writable area stays permitted, so the agent's own sockets
(tmux, language servers) work. Abstract sockets are already covered by the Landlock ABI 6 scoping
[ADR 0003](0003-nono-is-the-mechanism-backend.md) requests explicitly.

**A network-reachable oracle is a residual, not a surface.** A metadata endpoint or a host-loopback
credential service hands out a credential to anyone who can reach an address. Closing it means
denying addresses, which brings back exactly the sound address-based pin this decision deletes.
Under standing law 1, the layer that exposes such an endpoint owns protecting it. playpen names
the residual rather than crediting that layer.

## Considered Options

**Keep traffic confinement and make it sound.** On Linux this means a user and network namespace
that playpen creates for the child, with the proxy's listening socket created inside that
namespace and passed to the supervisor. It is sound, and it was the recommended repair. It was
rejected because it buys a claim the operator does not want, at the cost of refusing stock
Ubuntu and owning namespace code outside the backend.

**Race-free seccomp emulation**: the supervisor performs each `connect()` and injects the
socket. It works everywhere, but it changes connect semantics under every tool for a claim nobody
needs.

**Keep `none` as the one network setting.** Rejected. It would still be a claim to enforce, and
nono's `Blocked` leaves the macOS resolver open and kills loopback on Linux. An operator who wants
a networkless agent has the layer beneath.

**Treat unix-socket oracles as a residual too.** Rejected, because they are the means in its most
literal form, and on macOS closing them is a small upstream change.

## Consequences

- **The profile has no `egress` field.** `none`, `open` and `allowlist` are gone, and so is
  every refusal that only made sense with them: `refusal.egress.none-with-route`, the
  forge-scope-versus-allow-list check, and the user-namespace precondition.
- **The backend's network mode is `AllowAll`, with no seccomp network filter on Linux.** UDP,
  DNS and QUIC work, which also dissolves [#20](https://github.com/firefly-engineering/playpen/issues/20)'s
  note that nono's TCP-only baseline would starve a browser of QUIC and netlink. nono's sandbox
  extension rules stay off, as [ADR 0003](0003-nono-is-the-mechanism-backend.md) requires.
- **The proxy runs iff a route resolves.** `HTTPS_PROXY` stays global, because `NO_PROXY` can
  only exclude hosts, so there is no standard way to send only credentialed traffic through it.
  Uncredentialed hosts get an opaque `CONNECT`. TLS is terminated for credentialed hosts only. A
  proxy that dies mid-run still tears the run down: every client points at it, and a loud end
  beats credentials lapsing silently.
- **The proxy and CA set entries collapse into one tier.** `HTTPS_PROXY`, `NO_PROXY`/`no_proxy`,
  `NODE_USE_ENV_PROXY` and the pair `SSL_CERT_FILE` + `NODE_EXTRA_CA_CERTS` are written iff a
  route resolves, since interception now happens exactly when a route does.
- **The only broker denial is an endpoint rule's.** The code prefix `egress.*` becomes
  `broker.*`, so the denial is `broker.endpoint.denied`. `403` with `X-Playpen-Denied` stays its
  in-band form.
- **The manifest states no egress setting and no host list.** It always says that the proxy is
  not the only way out, and that a routed destination is authenticated only for requests sent
  through it.
- **Standing law 6, "loopback stays open unconditionally", retires**, because it only ever
  constrained the pin. Loopback is open because nothing confines the network.
- **The ledgers change.** The shared host loopback stops being a macOS-only residual and
  asymmetry: there is no namespace on either platform. It merges into a new residual,
  **network-reachable credential sources**. A second new residual covers **unix-socket oracles on
  Linux below Landlock ABI 9**, and the same fact is a new named asymmetry, since macOS enforces
  unix-socket denial at every version. "No resolver" and DNS-rebinding immunity are no longer
  claimed anywhere.
- **The enforcement suite** loses `N-egress-port` and `N-resolver`. It gains `N-unix-socket`: a
  decoy socket listening outside every grant is reachable from outside and refused from inside.
  It runs on macOS, and on Linux below ABI 9 it is skipped by name, because the precondition is
  missing on that host. `P-open-bypass` stays, as the
  assertion that a request bypassing the proxy arrives unauthenticated.
- **An upstream change is owed to nono**: under `AllowAll`, keep unix sockets default-deny with
  explicit grants. Until a pinned release carries it, playpen refuses on macOS. A refusal costs
  nothing yet, because nothing is implemented.
