//! The broker's proxy ([spec §6.2]): **the proxy is the supervisor's, and the two confinements are
//! independent** ([ADR 0013]).
//!
//! It exists **iff at least one credential route resolves**. It binds `127.0.0.1:0` *before the
//! fork*, so the port the child is pointed at is a port that already exists, and serves in the
//! supervisor's own process — never a sibling to be orphaned, never a port on a wider interface.
//!
//! One thread per connection, blocking. Nothing here holds ten thousand sockets, so an async
//! runtime would buy complexity and no throughput.
//!
//! **Every client is pointed at it**, because `HTTPS_PROXY` is global and `NO_PROXY` can only
//! exclude hosts: there is no standard way to route only credentialed hosts through a proxy. So a
//! host with no route gets an **opaque `CONNECT`, with no check** — playpen confines no network
//! traffic ([spec §6.1]), and a tunnel it cannot read is a tunnel it does not look at.
//!
//! **A dead proxy tears the run down.** Every client points at it, so a proxy that stopped serving
//! would leave the agent making requests that fail in ways it cannot interpret; a loud end beats
//! credentials lapsing silently. A panic in any proxy thread is caught here and routed into
//! teardown the same way ([spec §4.2]).
//!
//! [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
//! [spec §6.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#61-what-is-not-confined
//! [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
//! [ADR 0013]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0013-the-proxy-is-the-supervisors-and-the-two-confinements-are-independent.md

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zeroize::Zeroizing;

use crate::code::Code;
use crate::manifest::DENIED_HEADER;
use crate::refusal::Refusal;

/// The one interface the proxy ever binds. Loopback is open because nothing is closed
/// ([spec §6.1]), and a proxy on a wider interface would be a credential oracle for the host's
/// whole network.
///
/// [spec §6.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#61-what-is-not-confined
const INTERFACE: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// How long a connection waits on a peer that has said nothing. A client that opens a socket and
/// never speaks must not hold a thread for the run's whole life.
const IDLE: std::time::Duration = std::time::Duration::from_secs(120);

/// The most of a request head the proxy will read before giving up on it: a `CONNECT` line and its
/// headers, with room to spare. A peer that sends more than this is not speaking HTTP.
const MAX_HEAD: usize = 64 * 1024;

/// The provenance of everything the broker authors in the child's environment.
pub const FROM: &str = "broker";

/// What the CA certificate is called in the run scratch. Public, because the certificate is: it is
/// the key beside it that never leaves the supervisor.
pub const CA_FILE: &str = "broker-ca.pem";

/// What the trust bundle is called in the run scratch, beside [`CA_FILE`]: the host's own roots
/// followed by the session CA's certificate. Derived from the host's store rather than authored,
/// and public for the same reason the certificate is — every certificate in it is already public,
/// and no key is.
pub const BUNDLE_FILE: &str = "broker-roots.pem";

/// The one protocol the broker speaks. Offered on both legs, so a client that would have chosen
/// HTTP/2 chooses this instead rather than speaking something the broker would mangle.
const ALPN: &[u8] = b"http/1.1";

/// How many bytes of the session phantom. 32 bytes of the kernel's randomness, hex-encoded: long
/// enough that a host process cannot guess it, which is the outward half of what the phantom is
/// for ([spec §7.3]).
///
/// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
const PHANTOM_BYTES: usize = 32;

/// What hosts are never proxied: the agent's own loopback, so a language server, a dev server or
/// an MCP server it started for itself is reached directly. Both spellings of the name are written
/// because clients disagree about which they read ([spec §9.2]).
///
/// It cannot do the thing one would want of it — route only credentialed hosts through the proxy —
/// because `NO_PROXY` can only *exclude*, and that is why `HTTPS_PROXY` is global.
///
/// [spec §9.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#92-set-entries
pub const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// What the broker contributes to the child's environment ([spec §9.2]). There is no such value
/// where no credential route resolved, and then none of these names exists at all.
///
/// [spec §9.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#92-set-entries
pub struct Set {
    /// Where the proxy is listening, which `HTTPS_PROXY` is rendered from.
    pub addr: SocketAddr,
    /// The session CA's certificate in the run scratch, which `NODE_EXTRA_CA_CERTS` names.
    pub ca: PathBuf,
    /// The trust bundle in the run scratch — the host's own roots and the session CA — which
    /// `SSL_CERT_FILE` names.
    pub bundle: PathBuf,
    /// The session phantom, which every route's delivery variable carries. **Never a real
    /// secret**: there is no mode in which one enters the sandbox's environment ([spec §7.3]).
    ///
    /// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
    pub phantom: Phantom,
    /// Every route's delivery variable, each carrying the phantom. One phantom rather than one
    /// per credential, because delivery cannot hand one tool a choice between two values.
    pub deliveries: Vec<String>,
}

impl Set {
    /// The entries the broker writes, by name and value: rendered from the bound address and the
    /// paths playpen made, never formatted from a string the policy supplied.
    pub fn entries(&self) -> Vec<(String, String)> {
        let mut entries = vec![
            ("HTTPS_PROXY".to_owned(), format!("http://{}", self.addr)),
            ("NO_PROXY".to_owned(), NO_PROXY.to_owned()),
            ("no_proxy".to_owned(), NO_PROXY.to_owned()),
            // Bun and Node honour a proxy from the environment only when asked to
            // ([ADR 0012]), and both flagship agents are Bun.
            //
            // [ADR 0012]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0012-the-environment-is-constructed-and-exactly-one-author-writes-each-name.md
            ("NODE_USE_ENV_PROXY".to_owned(), "1".to_owned()),
        ];
        // Both names, because `git` and `curl` read one and Bun reads the other ([ADR 0012]) —
        // and they name **two different files**, because only one of them is additive.
        //
        // `SSL_CERT_FILE` *replaces* the default CA file wherever it is read, and a Rust client on
        // `rustls-native-certs` consults nothing else once it is set, so the bare session CA there
        // would leave such a client unable to verify any host playpen did not route. It names the
        // bundle, which means inside the boundary what it means outside: the roots this process
        // trusts.
        //
        // `NODE_EXTRA_CA_CERTS` is *extra* — the session CA joins Node's own bundled roots — so it
        // names the bare certificate. Pointed at the bundle it would have Node re-add every host
        // root it already has ([spec §9.2]).
        //
        // [spec §9.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#92-set-entries
        entries.push((
            "SSL_CERT_FILE".to_owned(),
            self.bundle.to_string_lossy().into_owned(),
        ));
        entries.push((
            "NODE_EXTRA_CA_CERTS".to_owned(),
            self.ca.to_string_lossy().into_owned(),
        ));
        for delivery in &self.deliveries {
            entries.push((delivery.clone(), self.phantom.as_str().to_owned()));
        }
        entries
    }
}

/// The session phantom ([spec §7.3]): one random bearer token per run, delivered into every
/// route's delivery variable, which the proxy strips and replaces with the real secret.
///
/// It works in both directions. **Inward** it contains exfiltration: a secret that is not present
/// cannot leak through a log line or a tool call. **Outward** it authenticates callers of the
/// proxy — a host process can reach the listener but cannot present a token it never saw.
///
/// It belongs to the process tree, not to the agent: every child, a third-party MCP server
/// included, inherits it and has full use of every route. That follows from the unit of policy,
/// and endpoint rule sets bound every holder alike ([spec §7.6]).
///
/// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
/// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
#[derive(Clone)]
pub struct Phantom(Arc<String>);

impl Phantom {
    /// One phantom, from the kernel's randomness. A failure to get randomness is
    /// `refusal.proxy.ca`: the broker could not be set up, and a guessable phantom would let any
    /// host process spend the run's credentials.
    pub fn random() -> Result<Self, Refusal> {
        let mut bytes = [0u8; PHANTOM_BYTES];
        getrandom::fill(&mut bytes).map_err(|e| {
            Refusal::new(
                Code::ProxyCa,
                format!("the broker cannot make a session phantom: {e}"),
            )
        })?;
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(hex, "{byte:02x}");
        }
        Ok(Self(Arc::new(hex)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Never the phantom's value in a `Debug`: it is not a secret, but it spends the run's credentials
/// for anyone who has it, so it is treated like one everywhere but the child's environment.
impl std::fmt::Debug for Phantom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Phantom(<redacted>)")
    }
}

/// The interception CA ([spec §6.2]): **ephemeral, in-memory, and per-session.** Its private key
/// never leaves the supervisor — it is never written anywhere, and dies with the process. Its
/// certificate, which is public, goes into the run scratch.
///
/// A leaf is minted per host on first use and kept for the run, because a handshake must not wait
/// on a key generation it has already done once.
///
/// [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
pub struct Ca {
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    /// The certificate, PEM, which is what a client is told to trust.
    pem: String,
    certificate: CertificateDer<'static>,
    leaves: Mutex<HashMap<String, Arc<Leaf>>>,
}

/// The roots the run trusts upstream: **what the host says it trusts** ([ADR 0030]).
///
/// Read once per launch and used twice, so the two can never disagree: the broker verifies every
/// destination against them, and the bundle the child's `SSL_CERT_FILE` names is built from them.
/// A run whose supervisor was pointed at a different store gets a child consistent with what the
/// broker itself trusts.
///
/// [ADR 0030]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0030-the-hosts-own-trust-store-is-what-the-host-says-it-is.md
pub struct Roots(Vec<CertificateDer<'static>>);

impl Roots {
    /// The host's own, read the way every Unix TLS client reads them: `SSL_CERT_FILE` or
    /// `SSL_CERT_DIR` in the *supervisor's* environment **replaces** the platform search, and the
    /// platform store answers where neither is set. That lever is the launching environment's, and
    /// a named residual ([ADR 0030]).
    ///
    /// A host with no usable roots is `refusal.proxy.ca`: there would be nothing to verify a
    /// destination against, and the alternative is trusting whatever answers.
    ///
    /// [ADR 0030]: https://github.com/firefly-engineering/playpen/blob/main/docs/adr/0030-the-hosts-own-trust-store-is-what-the-host-says-it-is.md
    pub fn host() -> Result<Self, Refusal> {
        let native = rustls_native_certs::load_native_certs();
        if native.certs.is_empty() {
            return Err(Refusal::new(
                Code::ProxyCa,
                format!(
                    "the broker cannot verify destinations: this host offers no trusted roots \
                     ({} errors loading them)",
                    native.errors.len()
                ),
            ));
        }
        Ok(Self(native.certs))
    }

    /// These roots as a store for upstream verification. A certificate the store will not take is
    /// dropped rather than refused: the host named it, and one root it cannot parse is not a reason
    /// to decline a run the rest can verify.
    fn store(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in &self.0 {
            let _ = roots.add(certificate.clone());
        }
        roots
    }

    /// Roots of a test's own naming, for one that stands up a destination with a root of its own.
    /// Never a launch's: [`Roots::host`] is the only thing a launch builds one from.
    #[cfg(test)]
    fn of(certificates: Vec<CertificateDer<'static>>) -> Self {
        Self(certificates)
    }

    /// Write the bundle `SSL_CERT_FILE` names: these roots, then `ca`'s certificate.
    ///
    /// The host's half is **encoded**, not copied. A root comes out of the platform store as DER —
    /// on macOS there is no PEM file to concatenate at all — so the bundle has to be built on both
    /// platforms or the variable would mean two different things again.
    ///
    /// Only certificates go in. The session CA's private key is still written nowhere
    /// ([spec §6.2]).
    ///
    /// [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
    pub fn bundle(&self, ca: &Ca, at: &Path) -> Result<(), Refusal> {
        let mut bundle = String::new();
        for certificate in &self.0 {
            bundle.push_str(&pem::encode_config(
                &pem::Pem::new("CERTIFICATE", certificate.as_ref()),
                pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            ));
        }
        bundle.push_str(&ca.pem);
        std::fs::write(at, &bundle).map_err(|e| {
            Refusal::new(
                Code::ProxyCa,
                format!(
                    "the broker cannot write its trust bundle {}: {e}",
                    at.display()
                ),
            )
        })
    }
}

/// One host's leaf: the chain a client is served, and the key that proves it.
struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    /// PKCS#8 DER. Held as bytes because a `PrivateKeyDer` is not `Clone`, and a config is built
    /// per connection.
    key: Vec<u8>,
}

/// Generate the session CA. A failure is `refusal.proxy.ca`: a route resolved, and **a
/// TLS-interception failure is a refusal, never a fallback to an opaque tunnel** — a tunnel would
/// carry the phantom to the destination unexamined.
pub fn ca() -> Result<Ca, Refusal> {
    let failed = |what: &str, e: rcgen::Error| {
        Refusal::new(
            Code::ProxyCa,
            format!("the broker cannot {what} for this session: {e}"),
        )
    };
    let key = rcgen::KeyPair::generate().map_err(|e| failed("make a CA key", e))?;
    let mut params =
        rcgen::CertificateParams::new(Vec::new()).map_err(|e| failed("describe its CA", e))?;
    // Path length zero: this CA signs end-entity certificates and nothing else.
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "playpen session CA");
    let certificate = params
        .self_signed(&key)
        .map_err(|e| failed("sign its CA", e))?;
    Ok(Ca {
        pem: certificate.pem(),
        certificate: certificate.der().clone(),
        issuer: rcgen::Issuer::new(params, key),
        leaves: Mutex::new(HashMap::new()),
    })
}

impl Ca {
    /// Write the certificate — and only the certificate — where both certificate variables name
    /// it. The key is not written, here or anywhere.
    pub fn write(&self, at: &Path) -> Result<(), Refusal> {
        std::fs::write(at, &self.pem).map_err(|e| {
            Refusal::new(
                Code::ProxyCa,
                format!(
                    "the broker cannot write its CA certificate {}: {e}",
                    at.display()
                ),
            )
        })
    }

    /// The leaf for `host`, minted on first use and kept for the run.
    fn leaf(&self, host: &str) -> Result<Arc<Leaf>, rcgen::Error> {
        if let Some(found) = self
            .leaves
            .lock()
            .ok()
            .and_then(|leaves| leaves.get(host).cloned())
        {
            return Ok(found);
        }
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec![host.to_owned()])?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        let certificate = params.signed_by(&key, &self.issuer)?;
        let leaf = Arc::new(Leaf {
            // The CA beside the leaf, so a client that was given the certificate to trust can
            // build the chain without having to have cached it.
            chain: vec![certificate.der().clone(), self.certificate.clone()],
            key: key.serialize_der(),
        });
        if let Ok(mut leaves) = self.leaves.lock() {
            leaves.insert(host.to_owned(), Arc::clone(&leaf));
        }
        Ok(leaf)
    }
}

/// One credential route the proxy can authenticate ([spec §7.1]): where it goes, and the secret it
/// puts in place of the phantom.
///
/// `path_prefix` is **a selector and never access control**: it decides *which* credential a
/// request gets, not whether the request may be made. What a credential may reach is an endpoint
/// rule set's business ([spec §7.6]).
///
/// [spec §7.1]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#71-credential-route
/// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
pub struct Route {
    pub host: String,
    pub path_prefix: String,
    pub secret: Secret,
    pub allowed: Allowed,
}

/// One route's real secret, held so that **renewal can replace it in place** ([spec §7.2]): the
/// proxy reads it on every request and the supervisor's renewal writes it between two of them,
/// so it is behind a lock and shared rather than owned by either.
///
/// Zeroized on every write and on the last drop, so a token that has been renewed away does not
/// stay in this process's memory behind the one that replaced it.
///
/// [spec §7.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#72-minters
#[derive(Clone)]
pub struct Secret(Arc<Mutex<Zeroizing<String>>>);

impl Secret {
    pub fn new(secret: String) -> Self {
        Self(Arc::new(Mutex::new(Zeroizing::new(secret))))
    }

    /// Put `secret` in place of what this held, which is zeroized as it goes.
    pub fn replace(&self, secret: String) {
        *self.held() = Zeroizing::new(secret);
    }

    /// The secret as it stands, copied. A copy rather than a guard because the caller goes on to
    /// talk to upstream, and a request must not hold this lock while it does: renewal would wait
    /// on the slowest destination.
    pub(crate) fn read(&self) -> Zeroizing<String> {
        self.held().clone()
    }

    /// A poisoned lock is used anyway: what it guards is one string replaced whole, never left
    /// half-written, and a panic in a proxy thread has already torn the run down.
    fn held(&self) -> std::sync::MutexGuard<'_, Zeroizing<String>> {
        self.0.lock().unwrap_or_else(|held| held.into_inner())
    }
}

/// Never the secret: a `Debug` that printed it would put it in every log line that formatted a
/// route.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// What a credential route allows ([spec §7.6]).
///
/// A two-case type rather than a list whose emptiness means something, because the two meanings
/// an empty list would carry are opposites: **an absent `endpoints:` means unrestricted, not
/// empty.** Anything that cannot name which it holds eventually picks the wrong one, and the
/// wrong one here is a credential spent on a request the operator restricted.
///
/// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
#[derive(Debug, Clone)]
pub enum Allowed {
    /// The route carries no endpoint rule set, so the credential is unrestricted: what a route's
    /// prefix decides is *which* credential a request gets, never whether it may be made.
    Everything,
    /// The rules of every rule set the route carries, **unioned**: a set is a list of what is
    /// allowed and nothing else, so two of them on one route allow each other's rules, and there
    /// is no ordering for one to overrule the other with. A list that allows nothing denies
    /// everything, which is what makes a rule set playpen could not resolve safe.
    Only(Vec<Rule>),
}

/// One allow-only endpoint rule ([spec §7.6]): a method and a host-absolute path glob.
///
/// The method is matched **exactly**. HTTP methods are case-sensitive, and a client that sent
/// `get` where the operator wrote `GET` is denied rather than quietly allowed.
///
/// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
#[derive(Debug, Clone)]
pub struct Rule {
    pub method: String,
    pub path: crate::endpoint::Glob,
}

impl Route {
    /// Whether this route allows `method` on `path`, which carries no query string
    /// ([spec §7.6]).
    ///
    /// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
    fn allows(&self, method: &str, path: &str) -> bool {
        match &self.allowed {
            Allowed::Everything => true,
            Allowed::Only(rules) => rules
                .iter()
                .any(|rule| rule.method == method && rule.path.matches(path)),
        }
    }
}

/// Everything the proxy needs to serve, shared by every connection thread.
pub struct Broker {
    ca: Ca,
    phantom: Phantom,
    routes: Vec<Route>,
    upstream: Arc<rustls::ClientConfig>,
}

impl Broker {
    /// The broker of a run with `routes`, delivering `phantom`, intercepting under `ca`, verifying
    /// every destination against `roots`.
    ///
    /// Upstream verification is the host's own trust store: playpen intercepts the agent's TLS and
    /// must not weaken its own. [`Roots::host`] is the only thing that makes one, and what "the
    /// host's own" means is stated there. The roots are handed in rather than loaded here because
    /// the bundle the child is pointed at is built from the same read ([#140]).
    ///
    /// [#140]: https://github.com/firefly-engineering/playpen/issues/140
    pub fn new(
        ca: Ca,
        phantom: Phantom,
        routes: Vec<Route>,
        roots: &Roots,
    ) -> Result<Self, Refusal> {
        Self::trusting(ca, phantom, routes, roots.store())
    }

    /// As [`Broker::new`], against a store built here rather than from [`Roots`].
    ///
    /// A seam, so a test can stand up a destination of its own and show that a request reaches it
    /// with the phantom stripped and the secret injected. Every launch uses [`Broker::new`]: there
    /// is no policy field and no flag that reaches this. The launching environment can still name
    /// the store [`Roots::host`] reads, which is the host answering, not the policy.
    pub fn trusting(
        ca: Ca,
        phantom: Phantom,
        routes: Vec<Route>,
        roots: rustls::RootCertStore,
    ) -> Result<Self, Refusal> {
        let failed = |detail: String| {
            Refusal::new(
                Code::ProxyCa,
                format!("the broker cannot verify destinations: {detail}"),
            )
        };
        let mut upstream = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| failed(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        upstream.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Self {
            ca,
            phantom,
            routes,
            upstream: Arc::new(upstream),
        })
    }

    /// Whether any route names `host`. TLS is terminated **only** for a routed host: you cannot
    /// strip a phantom through a tunnel you cannot read, and reading one you have no credential
    /// for would buy nothing and cost the agent its own trust chain.
    fn routed(&self, host: &str) -> bool {
        self.routes.iter().any(|route| route.host == host)
    }

    /// The route a request to `host` for `path` is authenticated with, if one matches. A request
    /// on a routed host matching no prefix goes out unauthenticated, which is what the provider's
    /// own `401` is for.
    fn route(&self, host: &str, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|route| route.host == host && path.starts_with(&route.path_prefix))
            // The longest prefix among those that match. The coherence tier has already refused a
            // profile with two routes on one host whose prefixes are not ordered by strict
            // extension, so among what is left there is exactly one longest and no tie to break.
            .max_by_key(|route| route.path_prefix.len())
    }
}

/// The crypto provider for both legs. Named rather than taken from process-global state, so there
/// is one provider in the proxy and no way for two halves of it to disagree.
fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// A listener bound before the fork, not yet serving ([spec §4.2] step 11).
///
/// Bound first and served later because the child's environment must name the port, and the
/// environment is constructed before the fork: a proxy that bound after it would be pointed at
/// from a variable written before it existed.
///
/// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
pub struct Bound {
    listener: TcpListener,
    addr: SocketAddr,
}

/// Bind the proxy's listener on loopback, at a port the kernel picks ([spec §6.2]). A failure is
/// `refusal.proxy.bind`: a route resolved, so there is a credential to serve and nothing to serve
/// it from.
///
/// [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
pub fn bind() -> Result<Bound, Refusal> {
    let bind_failed = |what: &str, e: std::io::Error| {
        Refusal::new(
            Code::ProxyBind,
            format!("the broker cannot {what} on {INTERFACE}: {e}"),
        )
    };
    let listener = TcpListener::bind((INTERFACE, 0)).map_err(|e| bind_failed("bind", e))?;
    let addr = listener
        .local_addr()
        .map_err(|e| bind_failed("read back the address it bound", e))?;
    Ok(Bound { listener, addr })
}

impl Bound {
    /// Where the child is pointed, which the proxy set entries are rendered from.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Serve until [`Serving`] is dropped, which is teardown.
    ///
    /// `child` is the confined child, killed if the proxy ever stops before teardown does: that is
    /// what "a dead proxy tears the run down" means in one process, where the proxy cannot exit on
    /// its own without taking the run with it.
    pub fn serve(self, broker: Arc<Broker>, child: libc::pid_t) -> Serving {
        let stopping = Arc::new(AtomicBool::new(false));
        let accepting = Arc::clone(&stopping);
        // A second descriptor on the same socket, kept here so the socket stays listening at
        // `addr` until teardown has woken the accept loop by connecting to it.
        //
        // Held, not just the address: the moment the loop returns and drops its descriptor the
        // kernel is free to hand the port to the next socket anyone binds, and a wake-up connect
        // after the fact would reach into whatever had since taken it.
        let addr = self.addr;
        let (listener, served) = match self.listener.try_clone() {
            Ok(held) => {
                let served = std::thread::Builder::new()
                    .name("playpen-broker".into())
                    .spawn(move || accept_loop(self.listener, &broker, &accepting, child))
                    .ok();
                (Some(held), served)
            }
            // Nothing is serving, which is a dead proxy, which tears the run down.
            Err(_) => {
                tear_down(child);
                (None, None)
            }
        };
        Serving {
            stopping,
            addr,
            listener,
            served,
        }
    }
}

/// The proxy, for as long as the run lasts.
pub struct Serving {
    stopping: Arc<AtomicBool>,
    /// Where the listening socket is, which stopping connects to.
    addr: SocketAddr,
    /// A descriptor on the listening socket, held for this value's whole life so that stopping
    /// connects to a socket that still exists.
    listener: Option<TcpListener>,
    /// `None` where the thread could not be spawned, which has already torn the run down.
    served: Option<std::thread::JoinHandle<()>>,
}

impl Serving {
    /// Stop serving, in teardown's own order: after the revokers, which need the proxy up, and
    /// before the scratch goes ([spec §4.2] step 18).
    ///
    /// [spec §4.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#42-launch-sequence
    pub fn stop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        // Wakes the accept loop with a connection of its own, which it accepts, sees the flag, and
        // returns. Not `shutdown` on the listener: Linux wakes a blocked `accept` for that, but
        // Darwin refuses it with `ENOTCONN` and leaves `accept` blocked. Where the loop has already
        // returned the connection waits in the backlog of the socket held here, unread. No teardown
        // failure changes the exit status, so a connect that fails is dropped.
        if self.listener.is_some() {
            let _ = TcpStream::connect(self.addr);
        }
        if let Some(served) = self.served.take() {
            let _ = served.join();
        }
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Accept until told to stop. Anything that ends this loop early tears the run down, because every
/// client is pointed here and a silent end is the one failure the agent cannot interpret.
fn accept_loop(
    listener: TcpListener,
    broker: &Arc<Broker>,
    stopping: &AtomicBool,
    child: libc::pid_t,
) {
    loop {
        match listener.accept() {
            Ok((client, _)) => {
                if stopping.load(Ordering::SeqCst) {
                    return;
                }
                // One thread per connection, detached: a connection that outlives its usefulness
                // is bounded by `IDLE` rather than by anything this loop does.
                let serving = Arc::clone(broker);
                let _ = std::thread::Builder::new()
                    .name("playpen-broker-connection".into())
                    .spawn(move || {
                        // A panic in a connection is a panic in the proxy, which tears the run
                        // down ([spec §4.2]): it means the credential path is broken, and the
                        // agent must not run on against a broker that half works.
                        let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            serve_connection(client, &serving);
                        }));
                        if served.is_err() {
                            tear_down(child);
                        }
                    });
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            // Broken. Stop, and tear the run down unless teardown was already stopping the proxy.
            Err(_) => {
                if !stopping.load(Ordering::SeqCst) {
                    tear_down(child);
                }
                return;
            }
        }
        if stopping.load(Ordering::SeqCst) {
            return;
        }
    }
}

/// End the run, loudly. `SIGTERM` first, so the agent can exit as it would for any caller; the
/// supervisor reaps it and exits with its status, and the caller sees a death rather than a run
/// that quietly stopped authenticating.
fn tear_down(child: libc::pid_t) {
    // SAFETY: kill has no memory preconditions. A pid that has already been reaped simply fails.
    unsafe { libc::kill(child, libc::SIGTERM) };
}

/// Serve one client connection ([spec §6.2]).
fn serve_connection(mut client: TcpStream, broker: &Broker) {
    let _ = client.set_read_timeout(Some(IDLE));
    let _ = client.set_write_timeout(Some(IDLE));
    let Some(head) = read_head(&mut client) else {
        return;
    };
    match connect_target(&head) {
        // TLS is terminated only for a routed host; every other host gets an opaque tunnel, with
        // no check. playpen confines no network traffic, and a host with no credential route has
        // nothing for the broker to do.
        Some(target) if broker.routed(authority_host(&target)) => {
            intercept(client, &target, broker)
        }
        Some(target) => tunnel(client, &target),
        // Only `HTTPS_PROXY` points here, so everything that arrives is a `CONNECT`. Anything else
        // is answered rather than dropped, and carries no `broker.*` code: the one denial the
        // broker makes is an endpoint rule's, and this is not one.
        None => {
            let _ = client.write_all(
                b"HTTP/1.1 501 Not Implemented\r\n\
                  Content-Type: text/plain\r\n\
                  Connection: close\r\n\
                  Content-Length: 78\r\n\
                  \r\n\
                  playpen's broker proxies CONNECT only; this request was not a CONNECT.\r\n",
            );
        }
    }
}

/// Read a request head — everything up to the blank line — or `None` if the peer sent no head
/// worth parsing. Bounded by [`MAX_HEAD`] and by [`IDLE`].
fn read_head(client: &mut impl Read) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while head.len() < MAX_HEAD {
        match client.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => head.push(byte[0]),
            Err(_) => return None,
        }
        if head.ends_with(b"\r\n\r\n") {
            return Some(head);
        }
    }
    None
}

/// The `host:port` a `CONNECT` request names, or `None` where `head` is not a `CONNECT`.
///
/// Parsed by `httparse`, never by a pattern over the bytes: a request line is a grammar, and a
/// pattern that matched most of one would differ from it exactly where an attacker looked.
fn connect_target(head: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    // A head that does not parse names nothing, and a partial one cannot happen: `read_head`
    // returns only on the blank line that ends it.
    request.parse(head).ok()?;
    if !request.method.is_some_and(|method| method == "CONNECT") {
        return None;
    }
    // In a `CONNECT`, the target *is* the authority: `CONNECT host:port HTTP/1.1`.
    let authority = request.path?;
    // A target with no port is not one a tunnel can be opened to, and a `CONNECT` is required to
    // carry one.
    authority.rsplit_once(':').map(|_| authority.to_owned())
}

/// Open a tunnel to `target` and copy bytes both ways until either end closes ([spec §6.2]):
/// opaque, with no check, and nothing of it read.
fn tunnel(mut client: TcpStream, target: &str) {
    let upstream = TcpStream::connect(target);
    let Ok(upstream) = upstream else {
        // A destination playpen could not reach is an upstream failure, which is `502` and carries
        // no code ([spec §6.4]).
        let _ = client.write_all(
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        );
        return;
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    // No timeouts on a tunnel: a long-lived stream — an SSE subscription, a held connection — is
    // exactly what an agent's client does, and `IDLE` is about a peer that never spoke.
    let _ = client.set_read_timeout(None);
    let _ = client.set_write_timeout(None);
    splice(client, upstream);
}

/// The host of a `host:port` authority, without the port.
fn authority_host(authority: &str) -> &str {
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

/// Terminate TLS for a routed host, substitute the phantom for the real secret, and forward
/// ([spec §7.3]).
///
/// **An interception failure never falls back to a tunnel.** A tunnel would carry the phantom to
/// the destination unread, which is the one thing the phantom exists to prevent; so a failure here
/// answers `502` and closes.
///
/// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
fn intercept(mut client: TcpStream, target: &str, broker: &Broker) {
    let host = authority_host(target).to_owned();
    let Ok(leaf) = broker.ca.leaf(&host) else {
        return bad_gateway(&mut client);
    };
    let certified = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .and_then(|builder| {
            builder.with_no_client_auth().with_single_cert(
                leaf.chain.clone(),
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.key.clone())),
            )
        });
    let Ok(mut config) = certified else {
        return bad_gateway(&mut client);
    };
    config.alpn_protocols = vec![ALPN.to_vec()];
    // The tunnel is established before the handshake, because the client speaks TLS only once it
    // believes it has one.
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let accepted = rustls::ServerConnection::new(Arc::new(config));
    let Ok(accepted) = accepted else {
        return;
    };
    let mut inside = rustls::StreamOwned::new(accepted, client);
    // The agent's request, in plaintext, for the first time.
    let Some(head) = read_head(&mut inside) else {
        return;
    };
    let rewritten = match decide(&head, &host, broker) {
        Some(Decision::Forward(rewritten)) => rewritten,
        // **No upstream leg occurs** ([spec §7.6]): the answer is written and the connection
        // closed before anything is opened to the destination, so the secret is never sent to a
        // destination a rule refused.
        Some(Decision::Denied) => {
            let _ = inside.write_all(denial(&host).as_bytes());
            let _ = inside.flush();
            return;
        }
        None => {
            let _ = inside.write_all(
                b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            );
            return;
        }
    };
    // Upstream: the real host, verified against the host's own roots.
    let Ok(server_name) = rustls::pki_types::ServerName::try_from(host.clone()) else {
        let _ = inside.write_all(
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        );
        return;
    };
    let upstream = TcpStream::connect(target).ok().and_then(|socket| {
        let session =
            rustls::ClientConnection::new(Arc::clone(&broker.upstream), server_name).ok()?;
        Some(rustls::StreamOwned::new(session, socket))
    });
    let Some(mut upstream) = upstream else {
        let _ = inside.write_all(
            b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        );
        return;
    };
    if upstream.write_all(&rewritten.head).is_err() {
        return;
    }
    // The body, verbatim, for exactly as long as the head said it would be. Reading until the
    // client closed instead would stall every request that has no body at all — which is every
    // `GET` — until the idle timeout.
    //
    // One request per connection: the head is the only thing rewritten, so a second request on the
    // same connection would go out carrying the phantom. `Connection: close` is forced on the
    // forwarded head, and the client reconnects, which is a cost stated rather than a risk taken.
    if forward_body(&mut inside, &mut upstream, rewritten.body).is_err() {
        return;
    }
    let _ = upstream.flush();
    // The response, verbatim and to the end: `Connection: close` means upstream closes when it is
    // done, so end of stream is end of response.
    let mut answer = Vec::new();
    let _ = upstream.read_to_end(&mut answer);
    let _ = inside.write_all(&answer);
    let _ = inside.flush();
}

/// How much body follows a request head ([RFC 9112 §6]). A request with neither framing header has
/// no body, which is what makes a `GET` answerable without waiting on the client to close.
///
/// [RFC 9112 §6]: https://www.rfc-editor.org/rfc/rfc9112.html#name-message-body-length
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Body {
    None,
    Length(u64),
    Chunked,
}

/// A head rewritten for upstream, and the body the original said would follow it.
struct Rewritten {
    head: Vec<u8>,
    body: Body,
}

/// What the broker does with one request head.
enum Decision {
    /// Send this upstream in place of what arrived.
    Forward(Rewritten),
    /// The route this request selected carries endpoint rule sets, and none of their rules allows
    /// it: `403`, and no upstream leg ([spec §7.6]).
    ///
    /// [spec §7.6]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#76-endpoint-rule-sets
    Denied,
}

/// Copy `body` from `from` to `to`, exactly as framed and no further.
fn forward_body(from: &mut impl Read, to: &mut impl Write, body: Body) -> std::io::Result<()> {
    match body {
        Body::None => Ok(()),
        Body::Length(length) => {
            std::io::copy(&mut from.take(length), to)?;
            Ok(())
        }
        // Chunk by chunk, so the end of the body is read from the body itself rather than from the
        // client closing: a size line, that many bytes and their terminator, until the zero chunk,
        // then whatever trailers follow up to the blank line. Everything is passed on byte for
        // byte; only the framing is read.
        Body::Chunked => {
            loop {
                let line = read_line(from)?;
                to.write_all(&line)?;
                let size = std::str::from_utf8(&line)
                    .ok()
                    .map(|line| line.trim_end())
                    // A chunk size may carry extensions after a `;`, which are not the size.
                    .map(|line| line.split(';').next().unwrap_or_default())
                    .and_then(|size| u64::from_str_radix(size.trim(), 16).ok())
                    .ok_or_else(|| std::io::Error::other("a chunk size that is not one"))?;
                if size == 0 {
                    break;
                }
                std::io::copy(&mut from.take(size), to)?;
                // The chunk's own terminator.
                to.write_all(&read_line(from)?)?;
            }
            // Trailers, up to and including the blank line that ends them.
            loop {
                let line = read_line(from)?;
                to.write_all(&line)?;
                if line == b"\r\n" || line.is_empty() {
                    return Ok(());
                }
            }
        }
    }
}

/// One CRLF-terminated line, terminator included. Bounded, because a peer that sends no newline
/// must not be able to grow this without limit.
fn read_line(from: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < MAX_HEAD {
        match from.read(&mut byte)? {
            0 => return Ok(line),
            _ => line.push(byte[0]),
        }
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
    Err(std::io::Error::other("a line with no end"))
}

/// What to do with `head`, addressed to `host`: deny it where the route it selects allows nothing
/// matching it ([spec §7.6]), and otherwise forward it with the phantom replaced by the route's
/// real secret, in whichever header carried it ([spec §7.3]), and `Connection: close` forced.
///
/// `None` where the head does not parse as a request, which is not something to forward.
///
/// **The query string is never matched** ([spec §7.6]): both the route's prefix and the rules see
/// the path alone. The forwarded request line still carries the path as it arrived — playpen
/// decides what a request may reach, and never what it says.
///
/// Substitution is **in place**: the proxy finds the phantom in whichever header the client sent
/// it in — `Authorization: Bearer`, `x-api-key`, whatever the harness already sends — and replaces
/// it there, so the request's shape stays the harness's own. The head is rebuilt from the parse
/// rather than edited as bytes, so a phantom that appeared in a path or a body is left alone: only
/// a header value is a place a credential is presented.
///
/// A request whose host has a route but whose path matches no prefix goes out **unauthenticated**,
/// and with the phantom still stripped: the provider's own `401` is the answer, and a destination
/// playpen did not mean to authenticate should not learn the run's phantom either.
///
/// [spec §7.3]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#73-session-phantom
fn decide(head: &[u8], host: &str, broker: &Broker) -> Option<Decision> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    request.parse(head).ok()?;
    let method = request.method?;
    let path = request.path?;
    // Everything policy is decided on is the path alone, query string stripped.
    let matched = path.split_once('?').map_or(path, |(before, _)| before);
    let phantom = broker.phantom.as_str();
    let route = broker.route(host, matched);
    if route.is_some_and(|route| !route.allows(method, matched)) {
        return Some(Decision::Denied);
    }
    let secret = route.map(|route| route.secret.read());
    let mut body = Body::None;
    let mut out = Vec::with_capacity(head.len() + 64);
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    for header in request.headers.iter() {
        let name = header.name;
        // Read the framing as it is passed on, so the body that follows is read to the length the
        // head it came with declared. Chunked wins, as the standard has it.
        if name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(header.value)
                .is_ok_and(|value| value.to_ascii_lowercase().contains("chunked"))
        {
            body = Body::Chunked;
        } else if name.eq_ignore_ascii_case("content-length")
            && body != Body::Chunked
            && let Some(length) = std::str::from_utf8(header.value)
                .ok()
                .and_then(|value| value.trim().parse().ok())
        {
            body = Body::Length(length);
        }
        // The broker's own hop-by-hop headers, and the one it is about to author itself.
        if name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        let value = header.value;
        let carries = std::str::from_utf8(value).is_ok_and(|value| value.contains(phantom));
        if carries {
            // A value is UTF-8 here, because that is what carrying the phantom required.
            let value = std::str::from_utf8(value).unwrap_or_default();
            let replaced = match secret {
                Some(ref secret) => value.replace(phantom, secret.as_str()),
                // Stripped rather than forwarded: the phantom is not a secret, but it spends this
                // run's credentials for anyone who learns it.
                None => value.replace(phantom, ""),
            };
            out.extend_from_slice(format!("{name}: {replaced}\r\n").as_bytes());
        } else {
            out.extend_from_slice(format!("{name}: ").as_bytes());
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    Some(Decision::Forward(Rewritten { head: out, body }))
}

/// The one denial the broker makes ([spec §6.4]): `403`, the destination in `X-Playpen-Denied`,
/// and a body that **names playpen, the code and the destination**.
///
/// The proxy *answers* rather than dropping the connection, because Bun's `fetch` — which both
/// flagship agents use — hands a proxy refusal to the application as an ordinary `Response`,
/// indistinguishable from an origin `403` by status alone. The body is what tells the agent which
/// of the two it met.
///
/// It names no rule set: the manifest already states them, and the agent reads that.
///
/// `host` is the authority the child's own `CONNECT` named, so it is written into a header only
/// when it holds nothing that could end one. A destination playpen cannot state is stated as
/// unprintable rather than echoed.
///
/// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
fn denial(host: &str) -> String {
    // Graphic ASCII only, and no `:`, so nothing here can end the header line it is written into
    // or start another.
    let named = if host.bytes().all(|b| b.is_ascii_graphic() && b != b':') {
        host
    } else {
        "a destination whose name is unprintable"
    };
    let code = Code::BrokerEndpointDenied.as_str();
    let body = format!(
        "playpen's broker refused this request: {code}\n\
         No endpoint rule on the credential route for {named} allows it, so playpen sent nothing \
         to {named}. The endpoint rule sets this run's routes carry are stated in the manifest \
         named by $PLAYPEN_MANIFEST.\n"
    );
    format!(
        "HTTP/1.1 403 Forbidden\r\n\
         {DENIED_HEADER}: {named}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Connection: close\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

/// A destination the broker could not reach or could not intercept: `502`, and no code
/// ([spec §6.4]).
///
/// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
fn bad_gateway(client: &mut TcpStream) {
    let _ = client
        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
}

/// Copy between two streams in both directions until either closes.
fn splice(client: TcpStream, upstream: TcpStream) {
    let Ok(client_back) = client.try_clone() else {
        return;
    };
    let Ok(upstream_back) = upstream.try_clone() else {
        return;
    };
    let outbound = std::thread::Builder::new()
        .name("playpen-broker-tunnel".into())
        .spawn(move || {
            let mut from = client;
            let mut to = upstream;
            let _ = std::io::copy(&mut from, &mut to);
            // Half-close, so the far end learns the near end is done rather than waiting on a
            // stream that will never speak again.
            let _ = to.shutdown(std::net::Shutdown::Write);
        });
    let mut from = upstream_back;
    let mut to = client_back;
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(std::net::Shutdown::Write);
    if let Ok(outbound) = outbound {
        let _ = outbound.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A broker with `routes`, its own session CA and its own phantom, against the host's roots as
    /// a launch has them.
    fn brokering(routes: Vec<Route>) -> Arc<Broker> {
        let ca = ca().expect("a session CA");
        let phantom = Phantom::random().expect("a phantom");
        let roots = Roots::host().expect("the host's roots");
        Arc::new(Broker::new(ca, phantom, routes, &roots).expect("a broker"))
    }

    /// A broker with no route at all: every host gets an opaque tunnel.
    fn tunnelling() -> Arc<Broker> {
        brokering(Vec::new())
    }

    /// A route on `localhost` under `prefix` carrying `secret`, with no endpoint rule set, which
    /// is what unrestricted is.
    fn unrestricted(prefix: &str, secret: &str) -> Route {
        Route {
            host: "localhost".into(),
            path_prefix: prefix.into(),
            secret: Secret::new(secret.into()),
            allowed: Allowed::Everything,
        }
    }

    /// One allow-only rule.
    fn rule(method: &str, path: &str) -> Rule {
        Rule {
            method: method.into(),
            path: crate::endpoint::Glob::parse(path).expect("a path glob"),
        }
    }

    /// The head `head` as the broker would send it upstream, or a panic naming what it did
    /// instead: these tests are about what is forwarded, so a denial here is a failure.
    fn forwarded(head: &str, host: &str, broker: &Broker) -> String {
        match decide(head.as_bytes(), host, broker) {
            Some(Decision::Forward(rewritten)) => String::from_utf8(rewritten.head).expect("utf-8"),
            Some(Decision::Denied) => panic!("denied rather than forwarded: {head}"),
            None => panic!("not a request: {head}"),
        }
    }

    /// A TLS destination on loopback with a certificate for `localhost`, which records the first
    /// request head it is sent. Returns its address, its own root, and where the head will land.
    ///
    /// `localhost` rather than a made-up name, because the proxy connects to the authority the
    /// `CONNECT` named and nothing here can make a name resolve.
    fn destination() -> (SocketAddr, CertificateDer<'static>, Arc<Mutex<Vec<u8>>>) {
        let root_key = rcgen::KeyPair::generate().expect("a root key");
        let mut root_params = rcgen::CertificateParams::new(Vec::new()).expect("root params");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let root = root_params.self_signed(&root_key).expect("a root");
        let leaf_key = rcgen::KeyPair::generate().expect("a leaf key");
        let leaf_params =
            rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf params");
        let leaf = leaf_params
            .signed_by(
                &leaf_key,
                &rcgen::Issuer::from_params(&root_params, &root_key),
            )
            .expect("a leaf");
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone(), root.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
            )
            .expect("a destination certificate");
        config.alpn_protocols = vec![ALPN.to_vec()];
        let listener = TcpListener::bind((INTERFACE, 0)).expect("a destination");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recording = Arc::clone(&seen);
        std::thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accepted");
            let session = rustls::ServerConnection::new(Arc::new(config)).expect("a session");
            let mut tls = rustls::StreamOwned::new(session, socket);
            if let Some(head) = read_head(&mut tls) {
                *recording.lock().expect("the recording") = head;
            }
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            let _ = tls.flush();
        });
        (addr, root.der().clone(), seen)
    }

    /// A self-signed root and the leaf for one host it issued: what a root a client has to trust
    /// looks like, and what the destination behind it serves.
    struct Issued {
        root: CertificateDer<'static>,
        chain: Vec<CertificateDer<'static>>,
        key: Vec<u8>,
    }

    /// A root of its own, and the leaf for `host` it issues.
    fn issued(host: &str) -> Issued {
        let root_key = rcgen::KeyPair::generate().expect("a root key");
        let mut root_params = rcgen::CertificateParams::new(Vec::new()).expect("root params");
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let root = root_params.self_signed(&root_key).expect("a root");
        let leaf_key = rcgen::KeyPair::generate().expect("a leaf key");
        let leaf = rcgen::CertificateParams::new(vec![host.to_owned()])
            .expect("leaf params")
            .signed_by(
                &leaf_key,
                &rcgen::Issuer::from_params(&root_params, &root_key),
            )
            .expect("a leaf");
        Issued {
            root: root.der().clone(),
            chain: vec![leaf.der().clone(), root.der().clone()],
            key: leaf_key.serialize_der(),
        }
    }

    /// A TLS listener on loopback serving `chain` proved by `key`, which answers one request and
    /// closes. Returns where it is listening.
    fn serving_tls(chain: Vec<CertificateDer<'static>>, key: Vec<u8>) -> SocketAddr {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(chain, PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
            .expect("a server certificate");
        config.alpn_protocols = vec![ALPN.to_vec()];
        let listener = TcpListener::bind((INTERFACE, 0)).expect("a listener");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let Ok((socket, _)) = listener.accept() else {
                return;
            };
            let session = rustls::ServerConnection::new(Arc::new(config)).expect("a session");
            let mut tls = rustls::StreamOwned::new(session, socket);
            let _ = read_head(&mut tls);
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            let _ = tls.flush();
        });
        addr
    }

    /// Whether a client trusting **only** what the PEM `bundle` holds can verify `addr` as
    /// `localhost`: one client config, built the way a tool that reads `SSL_CERT_FILE` as a
    /// replacement builds it.
    fn verified_by(bundle: &str, addr: SocketAddr) -> Result<(), String> {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in pem::parse_many(bundle).expect("the bundle is PEM") {
            assert_eq!(certificate.tag(), "CERTIFICATE", "the bundle holds a key");
            roots
                .add(CertificateDer::from(certificate.contents().to_vec()))
                .expect("a root the store takes");
        }
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN.to_vec()];
        let socket = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
        let session = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from("localhost").expect("a name"),
        )
        .map_err(|e| format!("a session: {e}"))?;
        let mut tls = rustls::StreamOwned::new(session, socket);
        tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .map_err(|e| format!("the handshake: {e}"))?;
        tls.flush().map_err(|e| format!("flush: {e}"))?;
        let mut answer = Vec::new();
        let _ = tls.read_to_end(&mut answer);
        match String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200 OK") {
            true => Ok(()),
            false => Err(format!("answered {:?}", String::from_utf8_lossy(&answer))),
        }
    }

    /// `SSL_CERT_FILE` means the same thing inside the boundary as outside — **the roots this
    /// process trusts** — so it names a bundle of the host's own roots *and* the session CA. A
    /// client that reads the variable as a replacement, which `rustls-native-certs` does, can then
    /// verify a routed host against the session CA and a non-routed one against a host root
    /// ([#140]).
    ///
    /// [#140]: https://github.com/firefly-engineering/playpen/issues/140
    #[test]
    fn the_bundle_verifies_both_a_session_leaf_and_a_host_root() {
        let dir = tempfile::TempDir::new().expect("dir");
        // A host root, standing for the platform store's, with a destination it signed: the
        // non-routed host an opaque tunnel reaches.
        let host = issued("localhost");
        let roots = Roots::of(vec![host.root.clone()]);
        let session = ca().expect("a session CA");
        let at = dir.path().join(BUNDLE_FILE);
        roots.bundle(&session, &at).expect("the bundle");
        let bundle = std::fs::read_to_string(&at).expect("the bundle");

        // Every certificate and no key, the host's roots first and the session CA last.
        let held = pem::parse_many(&bundle).expect("PEM");
        assert_eq!(held.len(), 2, "the host's root and the session CA");
        assert_eq!(held[0].contents(), host.root.as_ref());
        assert_eq!(held[1].contents(), session.certificate.as_ref());
        assert!(!bundle.contains("PRIVATE KEY"), "a key is in the bundle");

        // A routed host, as the proxy serves it: a leaf the session CA issued.
        let leaf = session.leaf("localhost").expect("a leaf");
        let routed = serving_tls(leaf.chain.clone(), leaf.key.clone());
        assert_eq!(verified_by(&bundle, routed), Ok(()));
        // A non-routed host, as the opaque tunnel reaches it: its own certificate, chaining to a
        // host root. This is what the bare session CA lost.
        let direct = serving_tls(host.chain, host.key);
        assert_eq!(verified_by(&bundle, direct), Ok(()));
    }

    /// The two variables name two different files, because only one of them is additive: pointed at
    /// the bundle, `NODE_EXTRA_CA_CERTS` would have Node re-add every root it already has.
    #[test]
    fn the_additive_variable_names_the_bare_ca_and_the_replacing_one_the_bundle() {
        let set = Set {
            addr: SocketAddr::from((INTERFACE, 1)),
            ca: PathBuf::from("/scratch").join(CA_FILE),
            bundle: PathBuf::from("/scratch").join(BUNDLE_FILE),
            phantom: Phantom::random().expect("a phantom"),
            deliveries: vec!["CLAUDE_CODE_OAUTH_TOKEN".to_owned()],
        };
        let entries: HashMap<String, String> = set.entries().into_iter().collect();
        assert_eq!(entries["SSL_CERT_FILE"], "/scratch/broker-roots.pem");
        assert_eq!(entries["NODE_EXTRA_CA_CERTS"], "/scratch/broker-ca.pem");
        assert_ne!(entries["SSL_CERT_FILE"], entries["NODE_EXTRA_CA_CERTS"]);
    }

    /// `P-endpoint` without rule sets ([spec §17.2]): a request through the proxy reaches upstream
    /// with the phantom stripped and the secret injected **in the same header**.
    ///
    /// [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
    #[test]
    fn a_routed_request_reaches_upstream_with_the_secret_in_place_of_the_phantom() {
        let (destination, destination_root, seen) = destination();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(destination_root).expect("the destination's root");
        let session = ca().expect("a session CA");
        let ca_certificate = session.certificate.clone();
        let phantom = Phantom::random().expect("a phantom");
        let broker = Arc::new(
            Broker::trusting(
                session,
                phantom.clone(),
                vec![unrestricted("/v1/", "the-real-secret")],
                roots,
            )
            .expect("a broker"),
        );
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let mut serving = bound.serve(broker, 0);

        // The agent's own client: trusts the session CA, as `SSL_CERT_FILE` tells it to.
        let mut trusted = rustls::RootCertStore::empty();
        trusted.add(ca_certificate).expect("the session CA");
        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(trusted)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN.to_vec()];
        let mut socket = TcpStream::connect(addr).expect("the proxy");
        socket
            .write_all(
                format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", destination.port()).as_bytes(),
            )
            .expect("the CONNECT");
        let mut established = [0u8; 39];
        socket.read_exact(&mut established).expect("established");
        let session = rustls::ClientConnection::new(
            Arc::new(client_config),
            rustls::pki_types::ServerName::try_from("localhost").expect("a name"),
        )
        .expect("a client session");
        let mut tls = rustls::StreamOwned::new(session, socket);
        // The phantom, in the header this harness happens to use.
        tls.write_all(
            format!(
                "GET /v1/messages HTTP/1.1\r\nHost: localhost\r\n\
                 x-api-key: {}\r\nAccept: application/json\r\n\r\n",
                phantom.as_str()
            )
            .as_bytes(),
        )
        .expect("the request");
        tls.flush().expect("flushed");
        let mut answer = Vec::new();
        let _ = tls.read_to_end(&mut answer);
        assert!(
            String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200 OK"),
            "{}",
            String::from_utf8_lossy(&answer)
        );

        let head = String::from_utf8(seen.lock().expect("the recording").clone()).expect("utf-8");
        // The secret arrived, in the header the phantom came in, and the phantom did not.
        assert!(
            head.contains("x-api-key: the-real-secret"),
            "the secret was not injected in place: {head}"
        );
        assert!(
            !head.contains(phantom.as_str()),
            "the phantom reached upstream: {head}"
        );
        // Everything else the harness sent is still the harness's own.
        assert!(head.contains("Accept: application/json"), "{head}");
        assert!(head.starts_with("GET /v1/messages HTTP/1.1\r\n"), "{head}");
        serving.stop();
    }

    /// `N-endpoint` and `N-endpoint-no-leg` ([spec §17.2]): a request the route's rule set does
    /// not allow comes back `403` with `X-Playpen-Denied` and `broker.endpoint.denied`, and the
    /// **instrumented upstream sees no request at all** — so the secret is never sent to a
    /// destination a rule refused.
    ///
    /// [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
    #[test]
    fn a_denied_request_is_answered_and_no_upstream_leg_occurs() {
        let (destination, destination_root, seen) = destination();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(destination_root).expect("the destination's root");
        let session = ca().expect("a session CA");
        let ca_certificate = session.certificate.clone();
        let phantom = Phantom::random().expect("a phantom");
        let broker = Arc::new(
            Broker::trusting(
                session,
                phantom.clone(),
                vec![Route {
                    host: "localhost".into(),
                    path_prefix: "/".into(),
                    secret: Secret::new("the-real-secret".into()),
                    allowed: Allowed::Only(vec![rule("POST", "/v1/messages")]),
                }],
                roots,
            )
            .expect("a broker"),
        );
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let mut serving = bound.serve(broker, 0);

        let mut trusted = rustls::RootCertStore::empty();
        trusted.add(ca_certificate).expect("the session CA");
        let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_root_certificates(trusted)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ALPN.to_vec()];
        let mut socket = TcpStream::connect(addr).expect("the proxy");
        socket
            .write_all(
                format!("CONNECT localhost:{} HTTP/1.1\r\n\r\n", destination.port()).as_bytes(),
            )
            .expect("the CONNECT");
        let mut established = [0u8; 39];
        socket.read_exact(&mut established).expect("established");
        let client = rustls::ClientConnection::new(
            Arc::new(client_config),
            rustls::pki_types::ServerName::try_from("localhost").expect("a name"),
        )
        .expect("a client session");
        let mut tls = rustls::StreamOwned::new(client, socket);
        // A `GET` where the one rule allows a `POST`.
        tls.write_all(
            format!(
                "GET /v1/messages HTTP/1.1\r\nHost: localhost\r\nx-api-key: {}\r\n\r\n",
                phantom.as_str()
            )
            .as_bytes(),
        )
        .expect("the request");
        tls.flush().expect("flushed");
        let mut answer = Vec::new();
        let _ = tls.read_to_end(&mut answer);
        let answer = String::from_utf8_lossy(&answer).into_owned();
        assert!(answer.starts_with("HTTP/1.1 403 "), "{answer}");
        assert!(answer.contains("X-Playpen-Denied: localhost"), "{answer}");
        assert!(answer.contains("broker.endpoint.denied"), "{answer}");
        serving.stop();
        // No upstream leg: the destination was never spoken to, so it recorded no head.
        assert!(
            seen.lock().expect("the recording").is_empty(),
            "a request reached upstream: {:?}",
            String::from_utf8_lossy(&seen.lock().expect("the recording").clone())
        );
    }

    /// A routed host whose path matches no prefix goes out **unauthenticated** — and with the
    /// phantom stripped even so: a destination playpen did not mean to authenticate should not
    /// learn the run's phantom either.
    #[test]
    fn a_path_that_matches_no_prefix_is_neither_authenticated_nor_given_the_phantom() {
        let broker = brokering(vec![unrestricted("/v1/", "the-real-secret")]);
        let phantom = broker.phantom.as_str().to_owned();
        let head = format!(
            "GET /other HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {phantom}\r\n\r\n"
        );
        let rewritten = forwarded(&head, "localhost", &broker);
        assert!(!rewritten.contains(&phantom), "{rewritten}");
        assert!(!rewritten.contains("the-real-secret"), "{rewritten}");
        assert!(
            rewritten.contains("Authorization: Bearer \r\n"),
            "{rewritten}"
        );
    }

    /// A request is authenticated with the route whose prefix matches it, and where two prefixes on
    /// one host both match, with the longer. The coherence tier has refused every pair that is not
    /// ordered by strict extension, so "the longer" is never a tie.
    #[test]
    fn the_route_whose_prefix_matches_is_the_one_that_authenticates() {
        let broker = brokering(vec![
            unrestricted("/", "the-coarse-secret"),
            unrestricted("/repos/op/", "the-workspace-secret"),
        ]);
        let phantom = broker.phantom.as_str().to_owned();
        let authenticated = |path: &str| {
            let head = format!(
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {phantom}\r\n\r\n"
            );
            forwarded(&head, "localhost", &broker)
        };
        // Only the coarse prefix matches.
        let coarse = authenticated("/user");
        assert!(
            coarse.contains("Authorization: Bearer the-coarse-secret"),
            "{coarse}"
        );
        // Both match, and the longer is the one that minimizes to a workspace.
        let narrow = authenticated("/repos/op/notes/commits");
        assert!(
            narrow.contains("Authorization: Bearer the-workspace-secret"),
            "{narrow}"
        );
        assert!(!narrow.contains("the-coarse-secret"), "{narrow}");
        // Route order is not what decided it.
        let reversed = brokering(vec![
            unrestricted("/repos/op/", "the-workspace-secret"),
            unrestricted("/", "the-coarse-secret"),
        ]);
        let head = format!(
            "GET /repos/op/notes HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            reversed.phantom.as_str()
        );
        let rewritten = forwarded(&head, "localhost", &reversed);
        assert!(
            rewritten.contains("Authorization: Bearer the-workspace-secret"),
            "{rewritten}"
        );
    }

    /// The phantom is replaced in whichever header carried it, and nowhere else: a path or a
    /// header that merely looks like one is left alone.
    #[test]
    fn the_phantom_is_replaced_only_where_a_credential_is_presented() {
        let broker = brokering(vec![unrestricted("/", "the-real-secret")]);
        let phantom = broker.phantom.as_str().to_owned();
        for header in ["Authorization: Bearer", "x-api-key:", "X-Custom-Token:"] {
            let head = format!(
                "POST /v1/messages HTTP/1.1\r\nHost: localhost\r\n{header} {phantom}\r\n\r\n"
            );
            let rewritten = forwarded(&head, "localhost", &broker);
            assert!(
                rewritten.contains(&format!("{header} the-real-secret")),
                "{header}: {rewritten}"
            );
            assert!(!rewritten.contains(&phantom), "{rewritten}");
        }
        // A path that happens to hold the phantom is not a place a credential is presented.
        let head = format!("GET /{phantom} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let rewritten = forwarded(&head, "localhost", &broker);
        assert!(
            rewritten.contains(&format!("GET /{phantom} ")),
            "{rewritten}"
        );
        assert!(!rewritten.contains("the-real-secret"), "{rewritten}");
    }

    /// `N-endpoint` ([spec §17.2]): a request a route's rule sets do not allow is **denied**, and
    /// one they do is forwarded. The query string is never matched, and the method is matched
    /// exactly.
    ///
    /// [spec §17.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#172-rows
    #[test]
    fn a_request_a_rule_set_does_not_allow_is_denied() {
        let broker = brokering(vec![Route {
            host: "localhost".into(),
            path_prefix: "/".into(),
            secret: Secret::new("the-real-secret".into()),
            // A `GET`-only set cannot `clone`: a git fetch is `GET …/info/refs` then
            // `POST …/git-upload-pack` ([spec §7.6]).
            allowed: Allowed::Only(vec![
                rule("GET", "/*/*/info/refs"),
                rule("GET", "/repos/*/*/**"),
            ]),
        }]);
        let phantom = broker.phantom.as_str().to_owned();
        let head = |method: &str, path: &str| {
            format!(
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: Bearer {phantom}\r\n\r\n"
            )
        };
        let denied = |method: &str, path: &str| {
            matches!(
                decide(head(method, path).as_bytes(), "localhost", &broker),
                Some(Decision::Denied)
            )
        };
        // Allowed, and the secret goes out in place of the phantom as it would unrestricted.
        let allowed = forwarded(
            &head("GET", "/repos/firefly/playpen/pulls"),
            "localhost",
            &broker,
        );
        assert!(
            allowed.contains("Authorization: Bearer the-real-secret"),
            "{allowed}"
        );
        // The query string is never matched, so it cannot make a request allowed or deny one.
        let queried = forwarded(
            &head("GET", "/repos/firefly/playpen/pulls?state=open"),
            "localhost",
            &broker,
        );
        assert!(
            queried.starts_with("GET /repos/firefly/playpen/pulls?state=open HTTP/1.1\r\n"),
            "the path reached upstream rewritten: {queried}"
        );
        assert!(denied("GET", "/user"), "a path no rule allows");
        assert!(
            denied("POST", "/firefly/playpen/git-upload-pack"),
            "a GET-only set allowed a POST"
        );
        assert!(
            denied("get", "/repos/firefly/playpen/pulls"),
            "the method was matched loosely"
        );
        // A query string holding an allowed path does not make a denied request allowed.
        assert!(
            denied("GET", "/user?next=/repos/firefly/playpen/pulls"),
            "a query string decided the match"
        );
    }

    /// A route with no rule set is unrestricted, and a route whose rule sets resolved to nothing
    /// denies everything: the two readings an empty list would share are opposites, so the type
    /// names which it holds.
    #[test]
    fn an_absent_rule_set_is_unrestricted_and_an_empty_one_allows_nothing() {
        let request = |broker: &Broker| {
            let head = format!(
                "GET /v1/messages HTTP/1.1\r\nHost: localhost\r\n\
                 Authorization: Bearer {}\r\n\r\n",
                broker.phantom.as_str()
            );
            matches!(
                decide(head.as_bytes(), "localhost", broker),
                Some(Decision::Denied)
            )
        };
        assert!(!request(&brokering(vec![unrestricted("/", "s")])));
        assert!(request(&brokering(vec![Route {
            host: "localhost".into(),
            path_prefix: "/".into(),
            secret: Secret::new("s".into()),
            allowed: Allowed::Only(Vec::new()),
        }])));
    }

    /// A rule set exists only on a credential route, so a routed host whose path matches no
    /// prefix is restricted by nothing: it goes out unauthenticated, which the provider's own
    /// `401` answers, and never as a `broker.*` denial ([spec §6.4]).
    ///
    /// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
    #[test]
    fn a_request_no_route_selects_is_never_a_broker_denial() {
        let broker = brokering(vec![Route {
            host: "localhost".into(),
            path_prefix: "/v1/".into(),
            secret: Secret::new("the-real-secret".into()),
            allowed: Allowed::Only(vec![rule("POST", "/v1/messages")]),
        }]);
        // `DELETE /other` matches neither the prefix nor the rule, so no route selects it.
        let head = format!(
            "DELETE /other HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n",
            broker.phantom.as_str()
        );
        let rewritten = forwarded(&head, "localhost", &broker);
        assert!(!rewritten.contains("the-real-secret"), "{rewritten}");
        assert!(!rewritten.contains(broker.phantom.as_str()), "{rewritten}");
    }

    /// The denial names playpen, the code and the destination, and carries the header the
    /// manifest states ([spec §6.4]). It is an *answer*, because Bun's `fetch` hands a proxy
    /// refusal to the application as an ordinary `Response`, and the body is the only thing that
    /// tells it apart from the origin's own `403`.
    ///
    /// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
    #[test]
    fn the_denial_is_self_describing_and_names_no_rule_set() {
        let answer = denial("api.github.com");
        assert!(answer.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{answer}");
        assert!(
            answer.contains("X-Playpen-Denied: api.github.com\r\n"),
            "{answer}"
        );
        let (head, body) = answer.split_once("\r\n\r\n").expect("a head and a body");
        assert!(
            head.contains(&format!("Content-Length: {}", body.len())),
            "{answer}"
        );
        assert!(body.contains("playpen"), "{body}");
        assert!(body.contains("broker.endpoint.denied"), "{body}");
        assert!(body.contains("api.github.com"), "{body}");
        // It names no rule set: the manifest already states them.
        assert!(!body.contains("rule set `"), "{body}");
        // A destination that could end a header line is never echoed into one.
        let injected = denial("evil\r\nX-Smuggled: 1");
        assert_eq!(injected.matches("\r\n\r\n").count(), 1, "{injected}");
        assert!(!injected.contains("X-Smuggled"), "{injected}");
    }

    /// The body that follows a head is read to the length that head declared. A request with no
    /// framing header has no body — which is every `GET` — and reading until the client closed
    /// instead would stall each of them until the idle timeout.
    #[test]
    fn the_body_is_framed_by_the_head_and_never_by_the_client_closing() {
        let broker = tunnelling();
        let framed = |head: &str| match decide(head.as_bytes(), "localhost", &broker) {
            Some(Decision::Forward(rewritten)) => rewritten.body,
            _ => panic!("not forwarded: {head}"),
        };
        assert_eq!(framed("GET /x HTTP/1.1\r\nHost: h\r\n\r\n"), Body::None);
        assert_eq!(
            framed("POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 12\r\n\r\n"),
            Body::Length(12)
        );
        assert_eq!(
            framed("POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"),
            Body::Chunked
        );
        // Chunked wins over a length, as the standard has it.
        assert_eq!(
            framed(
                "POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\
                 Content-Length: 12\r\n\r\n"
            ),
            Body::Chunked
        );
    }

    /// A body is forwarded byte for byte, and the forwarding stops where the framing says: nothing
    /// after the body is read, so what follows on the stream is still there.
    #[test]
    fn a_framed_body_is_forwarded_and_nothing_past_it() {
        let mut from = std::io::Cursor::new(b"twelve bytesTRAILING".to_vec());
        let mut to = Vec::new();
        forward_body(&mut from, &mut to, Body::Length(12)).expect("forwarded");
        assert_eq!(to, b"twelve bytes");
        let mut rest = Vec::new();
        from.read_to_end(&mut rest).expect("the rest");
        assert_eq!(rest, b"TRAILING");

        let mut nothing = std::io::Cursor::new(b"NOT A BODY".to_vec());
        let mut to = Vec::new();
        forward_body(&mut nothing, &mut to, Body::None).expect("forwarded");
        assert!(to.is_empty(), "{to:?}");
    }

    /// A chunked body ends at its own zero chunk, read from the body rather than from the client
    /// closing, and every byte of it is passed on as it came.
    #[test]
    fn a_chunked_body_ends_at_its_zero_chunk() {
        let chunked = "4\r\nWiki\r\n7\r\npedia i\r\n0\r\n\r\nAFTER";
        let mut from = std::io::Cursor::new(chunked.as_bytes().to_vec());
        let mut to = Vec::new();
        forward_body(&mut from, &mut to, Body::Chunked).expect("forwarded");
        assert_eq!(
            String::from_utf8(to).expect("utf-8"),
            "4\r\nWiki\r\n7\r\npedia i\r\n0\r\n\r\n"
        );
        let mut rest = Vec::new();
        from.read_to_end(&mut rest).expect("the rest");
        assert_eq!(rest, b"AFTER");
        // A chunk size that is not one is an error, never a guess.
        let mut broken = std::io::Cursor::new(b"not-a-size\r\n".to_vec());
        assert!(forward_body(&mut broken, &mut Vec::new(), Body::Chunked).is_err());
    }

    /// TLS is terminated only for a routed host; every other host is a tunnel.
    #[test]
    fn only_a_routed_host_is_intercepted() {
        let broker = brokering(vec![Route {
            host: "api.anthropic.com".into(),
            path_prefix: "/".into(),
            secret: Secret::new("s".into()),
            allowed: Allowed::Everything,
        }]);
        assert!(broker.routed("api.anthropic.com"));
        assert!(!broker.routed("example.com"));
        assert!(!broker.routed("evil.api.anthropic.com"));
        assert_eq!(authority_host("api.anthropic.com:443"), "api.anthropic.com");
        assert_eq!(authority_host("api.anthropic.com"), "api.anthropic.com");
    }

    /// The CA is ephemeral and per-session: two runs share nothing, and only the certificate is
    /// ever written.
    #[test]
    fn the_ca_is_per_session_and_only_its_certificate_is_written() {
        let dir = tempfile::TempDir::new().expect("dir");
        let first = ca().expect("a CA");
        let second = ca().expect("another CA");
        assert_ne!(first.pem, second.pem, "two sessions shared a CA");
        let at = dir.path().join(CA_FILE);
        first.write(&at).expect("written");
        let written = std::fs::read_to_string(&at).expect("the certificate");
        assert_eq!(written, first.pem);
        assert!(written.contains("BEGIN CERTIFICATE"), "{written}");
        assert!(
            !written.contains("PRIVATE KEY"),
            "the CA's key was written: {written}"
        );
        // The leaf for a host is minted once and kept.
        let leaf = first.leaf("api.github.com").expect("a leaf");
        let again = first.leaf("api.github.com").expect("the same leaf");
        assert!(Arc::ptr_eq(&leaf, &again));
        assert_eq!(leaf.chain.len(), 2, "the leaf is served with its CA");
    }

    /// A phantom is this run's own, and never shown.
    #[test]
    fn a_phantom_is_random_and_never_shown() {
        let first = Phantom::random().expect("a phantom");
        let second = Phantom::random().expect("another");
        assert_ne!(first.as_str(), second.as_str());
        assert_eq!(first.as_str().len(), PHANTOM_BYTES * 2);
        assert!(first.as_str().bytes().all(|b| b.is_ascii_hexdigit()));
        let shown = format!("{first:?}");
        assert!(!shown.contains(first.as_str()), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }

    #[test]
    fn it_binds_loopback_at_a_port_the_kernel_picks() {
        let bound = bind().expect("bound");
        assert_eq!(bound.addr().ip(), INTERFACE);
        assert_ne!(bound.addr().port(), 0, "the kernel picked no port");
        // Two proxies never collide: each gets its own.
        let other = bind().expect("bound");
        assert_ne!(bound.addr(), other.addr());
    }

    /// A `CONNECT` names its authority, and nothing else here is one.
    #[test]
    fn a_connect_names_its_authority() {
        assert_eq!(
            connect_target(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n"),
            Some("api.github.com:443".to_owned())
        );
        for other in [
            &b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"[..],
            // No port: not a tunnel target.
            &b"CONNECT api.github.com HTTP/1.1\r\n\r\n"[..],
            &b"not a request at all\r\n\r\n"[..],
            &b"\r\n\r\n"[..],
        ] {
            assert_eq!(
                connect_target(other),
                None,
                "{:?}",
                String::from_utf8_lossy(other)
            );
        }
    }

    /// A head ends at the blank line, and a peer that never sends one gets nowhere.
    #[test]
    fn a_head_ends_at_the_blank_line() {
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let serving = std::thread::spawn(move || {
            let (mut client, _) = bound.listener.accept().expect("accepted");
            read_head(&mut client)
        });
        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(b"CONNECT h:1 HTTP/1.1\r\nHost: h\r\n\r\nand the body")
            .expect("wrote");
        let head = serving.join().expect("served").expect("a head");
        assert_eq!(head, b"CONNECT h:1 HTTP/1.1\r\nHost: h\r\n\r\n");
    }

    /// Every host gets an opaque tunnel, and nothing of it is read: what goes in one end comes out
    /// the other, byte for byte.
    #[test]
    fn a_tunnel_is_opaque_in_both_directions() {
        // An upstream that echoes what it is sent, with a greeting first.
        let upstream = TcpListener::bind((INTERFACE, 0)).expect("upstream");
        let upstream_addr = upstream.local_addr().expect("addr");
        std::thread::spawn(move || {
            let (mut peer, _) = upstream.accept().expect("accepted");
            peer.write_all(b"hello from upstream\n").expect("greeted");
            let mut echoed = Vec::new();
            let _ = peer.read_to_end(&mut echoed);
            let _ = peer.write_all(&echoed);
            let _ = peer.shutdown(std::net::Shutdown::Write);
        });
        let bound = bind().expect("bound");
        let addr = bound.addr();
        // Served with no child to kill: the pid 0 group is never signalled here, because the
        // tunnel closes in good order.
        let mut serving = bound.serve(tunnelling(), 0);

        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(format!("CONNECT {upstream_addr} HTTP/1.1\r\n\r\n").as_bytes())
            .expect("wrote the CONNECT");
        // The tunnel is established, then the bytes are the peers' own.
        let mut answer = [0u8; 39];
        client.read_exact(&mut answer).expect("read the answer");
        assert_eq!(&answer[..], b"HTTP/1.1 200 Connection Established\r\n\r\n");
        client.write_all(b"opaque bytes").expect("wrote");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("half-closed");
        let mut seen = Vec::new();
        client.read_to_end(&mut seen).expect("read");
        assert_eq!(seen, b"hello from upstream\nopaque bytes");
        serving.stop();
    }

    /// Only `HTTPS_PROXY` points at the broker, so anything that is not a `CONNECT` is answered
    /// rather than dropped — and never with a `broker.*` code, which is the endpoint rule's alone.
    #[test]
    fn a_request_that_is_not_a_connect_is_answered() {
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let mut serving = bound.serve(tunnelling(), 0);
        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")
            .expect("wrote");
        let mut answer = String::new();
        client.read_to_string(&mut answer).expect("read");
        assert!(answer.starts_with("HTTP/1.1 501 "), "{answer}");
        assert!(!answer.contains("broker."), "{answer}");
        serving.stop();
    }

    /// A destination the proxy cannot reach is an upstream failure: `502`, and no code
    /// ([spec §6.4]).
    ///
    /// [spec §6.4]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#64-broker-denial
    #[test]
    fn an_unreachable_destination_is_a_bare_502() {
        // A port nothing listens on: bound and dropped, so the kernel has not reassigned it yet.
        let closed = TcpListener::bind((INTERFACE, 0)).expect("a port");
        let closed_addr = closed.local_addr().expect("addr");
        drop(closed);
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let mut serving = bound.serve(tunnelling(), 0);
        let mut client = TcpStream::connect(addr).expect("connected");
        client
            .write_all(format!("CONNECT {closed_addr} HTTP/1.1\r\n\r\n").as_bytes())
            .expect("wrote");
        let mut answer = String::new();
        client.read_to_string(&mut answer).expect("read");
        assert!(answer.starts_with("HTTP/1.1 502 "), "{answer}");
        assert!(!answer.contains("broker."), "{answer}");
        serving.stop();
    }

    /// A sleeping child of this process, to be torn down.
    fn sleeper() -> std::process::Child {
        let sleep = crate::floor::binary("sleep").unwrap_or_else(|searched| {
            panic!("the floor holds no `sleep`; looked at {searched:?}")
        });
        std::process::Command::new(sleep)
            .arg("30")
            .spawn()
            .expect("a child to tear down")
    }

    /// A dead proxy tears the run down: every client points at it, and a loud end beats
    /// credentials lapsing silently ([spec §6.2]).
    ///
    /// [spec §6.2]: https://github.com/firefly-engineering/playpen/blob/main/docs/spec.md#62-the-broker
    #[test]
    fn a_proxy_that_stops_serving_tears_the_run_down() {
        let mut child = sleeper();
        let pid = child.id() as libc::pid_t;
        // A listener whose `accept` fails, with nobody having asked it to stop: exactly what "the
        // proxy stopped serving" looks like from inside the loop. Non-blocking with nothing
        // pending fails with `WouldBlock` on every OS, where `shutdown` only breaks `accept` on
        // Linux.
        let listener = TcpListener::bind((INTERFACE, 0)).expect("bound");
        listener.set_nonblocking(true).expect("non-blocking");
        accept_loop(listener, &tunnelling(), &AtomicBool::new(false), pid);
        let status = child.wait().expect("reaped");
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGTERM),
            "the run was not torn down: {status:?}"
        );
    }

    /// Teardown stopping the proxy is not the proxy dying, so it kills nothing.
    #[test]
    fn stopping_at_teardown_tears_nothing_down() {
        let mut child = sleeper();
        let pid = child.id() as libc::pid_t;
        let bound = bind().expect("bound");
        let mut serving = bound.serve(tunnelling(), pid);
        serving.stop();
        // Still running: it was teardown that stopped the proxy, not the proxy that stopped.
        assert_eq!(
            child.try_wait().expect("try_wait").map(|s| s.success()),
            None,
            "stopping the proxy killed the child"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    /// Stopping is what teardown does, and it is idempotent: the accept loop is woken out of
    /// `accept`, sees the flag, and ends.
    #[test]
    fn stopping_ends_the_accept_loop() {
        let bound = bind().expect("bound");
        let addr = bound.addr();
        let mut serving = bound.serve(tunnelling(), 0);
        serving.stop();
        serving.stop();
        drop(serving);
        // Nothing is served once it has stopped.
        if let Ok(mut client) = TcpStream::connect(addr) {
            let mut answer = String::new();
            let _ = client.write_all(b"CONNECT h:1 HTTP/1.1\r\n\r\n");
            let _ = client.read_to_string(&mut answer);
            assert!(answer.is_empty(), "{answer}");
        }
    }
}
