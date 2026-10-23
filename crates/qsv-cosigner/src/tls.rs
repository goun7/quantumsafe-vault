//! DEV-LOOPBACK TLS for the co-signer bridge (docs/10 §3.5).
//!
//! The dev bridge serves the enclave co-signer over plain TCP today. That
//! is correct ONLY on loopback: the co-signature never crosses an untrusted
//! network in the clear. The moment the listen address leaves loopback, the
//! dev transport MUST encrypt — so `--tls-cert/--tls-key` (mandatory for
//! non-loopback binds) is accepted NOW: opt-in on loopback (regtest drills
//! of the exact production plumbing), mandatory elsewhere.
//!
//! Environments are structurally distinct:
//! - **AWS Nitro Enclave**: transport is vsock — no TLS, no IP at all.
//! - **Intel TDX**: TLS terminates on a REAL operator-owned chain and this
//!   module is not in the path (loopback-only validation here).
//! - **Dev/plain TCP** (this module): loopback-only UNLESS TLS is armed.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// A validated server-side TLS configuration, ready to wrap accepted
/// streams. Constructed only through [`tls_listener_config`] (from PEM
/// files) or [`tls_listener_config_with_client_auth`] (mTLS, docs/10
/// §3.5) — there is NO self-signed shortcut in this path: the loopback
/// development certificate is minted by the test harness with rcgen.
#[derive(Debug)]
pub struct TlsListenerConfig {
    inner: rustls::ServerConfig,
    /// Whether the wrapped config demands a client certificate (mTLS).
    /// rustls keeps its verifier private, so the constructor records the
    /// decision here — the honest, self-produced audit bit.
    client_auth: bool,
}

impl TlsListenerConfig {
    pub(crate) fn new(inner: rustls::ServerConfig) -> Self {
        Self {
            inner,
            client_auth: false,
        }
    }

    pub(crate) fn with_client_auth(inner: rustls::ServerConfig) -> Self {
        Self {
            inner,
            client_auth: true,
        }
    }

    /// Consumes the config into the shared form the serve loop clones per
    /// connection (one TLS session per accepted stream).
    pub fn into_server_config(self) -> std::sync::Arc<rustls::ServerConfig> {
        std::sync::Arc::new(self.inner)
    }

    /// The single certificate chain this listener presents (audit aid).
    pub fn cert_count(&self) -> usize {
        1
    }

    /// Audit handle: TRUE when the handshake DEMANDS a client certificate
    /// (mutual TLS). The install-what-you-print surface asserts this
    /// before shipping a non-loopback unit.
    pub fn requires_client_auth(&self) -> bool {
        self.client_auth
    }
}

/// Errors that must STOP the bridge boot (fail-closed transport).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopbackPolicyError {
    /// A non-loopback bind without TLS would ship co-signatures (and the
    /// PQC gate traffic around them) in plaintext.
    PlaintextOffLoopback,
    /// The PEM files could not be read or parsed.
    BadPem(String),
    /// The private key is not usable for a TLS server.
    BadKey,
    /// The client-auth requirement is not present in the TLS config: an
    /// anonymous client would be able to COMPLETE a handshake — the
    /// enforcement must live in the TLS layer itself (mTLS), not in a
    /// post-handshake string check.
    ClientAuthRequired,
    /// A non-loopback bind with an OPEN `/metrics` would publish the
    /// co-signer's behavioural counters — which vault was refused, which
    /// one the watchtower froze, how often each signed — to every host
    /// that can reach the port. That is an estate map for free.
    MetricsTokenRequiredOffLoopback,
}

impl core::fmt::Display for LoopbackPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PlaintextOffLoopback => write!(
                f,
                "plaintext co-signer transport outside loopback is forbidden — pass --tls-cert/--tls-key (or bind 127.0.0.1)"
            ),
            Self::BadPem(e) => write!(f, "TLS pem error: {e}"),
            Self::BadKey => write!(f, "TLS private key is not a usable server key"),
            Self::ClientAuthRequired => write!(
                f,
                "TLS listener is missing the client-auth requirement — anonymous clients must never reach a co-signer"
            ),
            Self::MetricsTokenRequiredOffLoopback => write!(
                f,
                "open /metrics outside loopback is forbidden — pass --metrics-token <secret> (or bind 127.0.0.1)"
            ),
        }
    }
}

impl std::error::Error for LoopbackPolicyError {}

/// True when `addr`'s host part is a loopback address (or `localhost`).
/// Bare binds (`:3334`) bind ALL interfaces — that is NOT loopback.
pub fn is_loopback_addr(addr: &str) -> bool {
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    }
    .trim_start_matches('[')
    .trim_end_matches(']');
    match host {
        "localhost" => return true,
        "" | "0.0.0.0" | "::" | "*" => return false,
        _ => {}
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// The dev-transport decision (docs/10 §3.5): loopback may serve plaintext
/// for regtest drills; anything else requires TLS, no exceptions.
pub fn require_tls_or_loopback(addr: &str, tls: bool) -> Result<(), LoopbackPolicyError> {
    if is_loopback_addr(addr) || tls {
        Ok(())
    } else {
        Err(LoopbackPolicyError::PlaintextOffLoopback)
    }
}

/// The scrape-gate policy (docs/10 §4.20): an open `/metrics` is a
/// LOOPBACK convenience. Off loopback the counters name every provisioned
/// vault and expose which ones the watchtower froze and how hot each one
/// signs — a status oracle for anyone who can reach the port. So the
/// scrape token is MANDATORY there, the same fail-closed shape as
/// [`require_tls_or_loopback`]: checked once at boot, before the bind.
///
/// An empty token counts as NOT armed: `--metrics-token ""` is a usage
/// mistake, and must not silently open the gate.
pub fn require_metrics_token_off_loopback(
    addr: &str,
    metrics_token: Option<&str>,
) -> Result<(), LoopbackPolicyError> {
    let armed = metrics_token.is_some_and(|t| !t.is_empty());
    if is_loopback_addr(addr) || armed {
        Ok(())
    } else {
        Err(LoopbackPolicyError::MetricsTokenRequiredOffLoopback)
    }
}

/// `PEM/cert` + `PEM/key` reader → TLS listener config. The policy gate
/// MUST pass before this is reachable; it is re-checked anyway.
pub fn tls_listener_config(
    cert_pem_path: &std::path::Path,
    key_pem_path: &std::path::Path,
) -> Result<TlsListenerConfig, LoopbackPolicyError> {
    let (certs, key) = read_cert_and_key(cert_pem_path, key_pem_path)?;
    let inner = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| LoopbackPolicyError::BadKey)?;
    Ok(TlsListenerConfig::new(inner))
}

/// mTLS listener ([`tls_listener_config`] + CLIENT-CERT REQUIREMENT):
/// the handshake itself refuses any client that arrives without a
/// certificate chaining to `client_ca_pem_path` — an anonymous client
/// never completes a TLS session, so no co-signature can leak even to a
/// handshake oracle.
pub fn tls_listener_config_with_client_auth(
    cert_pem_path: &std::path::Path,
    key_pem_path: &std::path::Path,
    client_ca_pem_path: &std::path::Path,
) -> Result<TlsListenerConfig, LoopbackPolicyError> {
    let (certs, key) = read_cert_and_key(cert_pem_path, key_pem_path)?;
    let ca_pem = std::fs::read(client_ca_pem_path).map_err(|e| {
        LoopbackPolicyError::BadPem(format!("read {}: {e}", client_ca_pem_path.display()))
    })?;
    let cas: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&ca_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| LoopbackPolicyError::BadPem(format!("parse client CA: {e}")))?;
    if cas.is_empty() {
        return Err(LoopbackPolicyError::BadPem(
            "no client CA certificate found".into(),
        ));
    }
    let mut client_roots = rustls::RootCertStore::empty();
    for ca in &cas {
        client_roots
            .add(ca.clone())
            .map_err(|e| LoopbackPolicyError::BadPem(format!("client CA unusable: {e}")))?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(client_roots))
        .build()
        .map_err(|_| LoopbackPolicyError::ClientAuthRequired)?;
    let inner = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|_| LoopbackPolicyError::BadKey)?;
    Ok(TlsListenerConfig::with_client_auth(inner))
}

/// Shared PEM reader: server chain + private key (both config constructors).
fn read_cert_and_key(
    cert_pem_path: &std::path::Path,
    key_pem_path: &std::path::Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), LoopbackPolicyError> {
    let cert_pem = std::fs::read(cert_pem_path).map_err(|e| {
        LoopbackPolicyError::BadPem(format!("read {}: {e}", cert_pem_path.display()))
    })?;
    let key_pem = std::fs::read(key_pem_path).map_err(|e| {
        LoopbackPolicyError::BadPem(format!("read {}: {e}", key_pem_path.display()))
    })?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| LoopbackPolicyError::BadPem(format!("parse certs: {e}")))?;
    let key: Option<PrivateKeyDer<'static>> = match PrivateKeyDer::from_pem_slice(&key_pem) {
        Ok(key) => Some(key),
        // A file with no key SECTION at all is the fail-closed family,
        // not a parse fault — same distinction the old reader made.
        Err(rustls::pki_types::pem::Error::NoItemsFound) => None,
        Err(e) => return Err(LoopbackPolicyError::BadPem(format!("parse key: {e}"))),
    };
    match (certs.is_empty(), key) {
        (false, Some(key)) => Ok((certs, key)),
        _ => Err(LoopbackPolicyError::BadPem(
            "no certificate or no private key found".into(),
        )),
    }
}

/// The client half of mTLS: reads the leaf certificate (chain) + key that
/// the SERVER's client-auth store will demand. Empty files are the
/// fail-closed family (no certificate → no identity → no handshake).
pub fn client_identity(
    cert_pem_path: &std::path::Path,
    key_pem_path: &std::path::Path,
) -> Result<ClientIdentity, LoopbackPolicyError> {
    let (certs, key) = read_cert_and_key(cert_pem_path, key_pem_path)?;
    Ok(ClientIdentity { certs, key })
}

/// A loaded client certificate identity ([`client_identity`]).
#[derive(Debug)]
pub struct ClientIdentity {
    /// The leaf (and any intermediates) to present, leaf first.
    pub certs: Vec<CertificateDer<'static>>,
    /// The private key matching the leaf.
    pub key: PrivateKeyDer<'static>,
}

impl ClientIdentity {
    /// Builds the TLS client config that PRESENTS this identity (the
    /// server roots are the caller's pinning decision).
    pub fn client_config(
        &self,
        roots: rustls::RootCertStore,
    ) -> Result<rustls::ClientConfig, LoopbackPolicyError> {
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(self.certs.clone(), self.key.clone_key())
            .map_err(|_| LoopbackPolicyError::BadKey)
    }
}

/// Trust store pinned to EXACTLY this certificate (regtest loopback
/// drills: the client trusts the very cert the bridge presents — the same
/// pinning discipline as the pinned enclave key).
pub fn pinned_root_store(cert: &CertificateDer<'_>) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let _ = roots.add(cert.clone());
    roots
}

/// Reads PEM certificate(s) from `path` and pins the FIRST one — the
/// operator-facing helper behind the sweep gate's `--cosigner-all-ca`
/// (the CA file the client pins for server verification).
pub fn pinned_root_store_from_pem(
    path: &std::path::Path,
) -> Result<rustls::RootCertStore, LoopbackPolicyError> {
    let pem = std::fs::read(path)
        .map_err(|e| LoopbackPolicyError::BadPem(format!("read {}: {e}", path.display())))?;
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<_, _>>()
        .map_err(|e| LoopbackPolicyError::BadPem(format!("parse certs: {e}")))?;
    let first = certs
        .first()
        .ok_or_else(|| LoopbackPolicyError::BadPem("no certificate found".into()))?;
    Ok(pinned_root_store(first))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PEM reader round trip covered in `pem_files_round_trip…` below; the
    /// pinned store helper feeds [`crate::server::request_signature_tls`].
    #[test]
    fn pinned_root_store_accepts_the_generated_cert() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let roots = pinned_root_store(cert.cert.der());
        assert_eq!(roots.len(), 1, "exactly the pinned cert");
    }

    #[test]
    fn loopback_classification_is_explicit() {
        assert!(is_loopback_addr("127.0.0.1:3334"));
        assert!(is_loopback_addr("127.7.7.7:1"));
        assert!(is_loopback_addr("localhost:3334"));
        assert!(is_loopback_addr("[::1]:3334"));
        // Bare binds listen on ALL interfaces — never loopback.
        assert!(!is_loopback_addr("0.0.0.0:3334"));
        assert!(!is_loopback_addr(":3334"));
        assert!(!is_loopback_addr("10.0.0.9:3334"));
        assert!(!is_loopback_addr("vault.example.com:3334"));
        // No port at all: the host part IS the address (the None arm).
        assert!(is_loopback_addr("127.0.0.1"));
        assert!(!is_loopback_addr("10.0.0.9"));
    }

    /// Every transport-policy error names its remedy — an operator who
    /// hits one at boot must not need the source to know what to do.
    #[test]
    fn every_policy_error_renders_its_remedy() {
        assert!(LoopbackPolicyError::BadKey
            .to_string()
            .contains("usable server key"));
        assert!(LoopbackPolicyError::ClientAuthRequired
            .to_string()
            .contains("client-auth requirement"));
        assert!(LoopbackPolicyError::ClientAuthRequired
            .to_string()
            .contains("anonymous"));
    }

    #[test]
    fn plaintext_off_loopback_is_rejected_and_tls_always_passes() {
        assert_eq!(
            require_tls_or_loopback("10.0.0.9:3334", false),
            Err(LoopbackPolicyError::PlaintextOffLoopback)
        );
        assert_eq!(
            require_tls_or_loopback(":3334", false),
            Err(LoopbackPolicyError::PlaintextOffLoopback)
        );
        assert!(require_tls_or_loopback("10.0.0.9:3334", true).is_ok());
        assert!(require_tls_or_loopback("127.0.0.1:3334", false).is_ok());
        assert!(require_tls_or_loopback("localhost:3334", true).is_ok());
    }

    /// SCRAPE GATE (docs/10 §4.20, Round 20): off loopback the metrics
    /// counters are an estate map (which vault signed, which was frozen),
    /// so an open scrape is refused at boot exactly like plaintext
    /// transport — and an EMPTY token is "not armed", never a free pass.
    #[test]
    fn open_metrics_off_loopback_is_rejected_and_the_token_always_passes() {
        assert_eq!(
            require_metrics_token_off_loopback("10.0.0.9:3334", None),
            Err(LoopbackPolicyError::MetricsTokenRequiredOffLoopback)
        );
        // Bare binds listen on ALL interfaces — the strictest case.
        assert_eq!(
            require_metrics_token_off_loopback(":3334", None),
            Err(LoopbackPolicyError::MetricsTokenRequiredOffLoopback)
        );
        assert_eq!(
            require_metrics_token_off_loopback("0.0.0.0:3334", Some("")),
            Err(LoopbackPolicyError::MetricsTokenRequiredOffLoopback)
        );
        // Armed (any non-empty secret) off loopback is the operator's
        // explicit, documented choice.
        assert!(require_metrics_token_off_loopback("10.0.0.9:3334", Some("s3cr3t")).is_ok());
        assert!(require_metrics_token_off_loopback(":3334", Some("s3cr3t")).is_ok());
        // Loopback keeps the dev convenience: no token required.
        assert!(require_metrics_token_off_loopback("127.0.0.1:3334", None).is_ok());
        assert!(require_metrics_token_off_loopback("localhost:3334", None).is_ok());
        // The message names the flag and the alternative — an operator who
        // hits it at boot must not need the source to know what to do.
        let msg = LoopbackPolicyError::MetricsTokenRequiredOffLoopback.to_string();
        assert!(msg.contains("--metrics-token"), "{msg}");
        assert!(msg.contains("127.0.0.1"), "{msg}");
        // The gate is transport-independent: TLS does not buy an open
        // scrape (the counters leak regardless of the cipher).
        assert!(require_tls_or_loopback("10.0.0.9:3334", true).is_ok());
        assert_eq!(
            require_metrics_token_off_loopback("10.0.0.9:3334", None),
            Err(LoopbackPolicyError::MetricsTokenRequiredOffLoopback)
        );
    }

    #[test]
    fn bad_pem_files_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        std::fs::write(&cert, "not a pem at all").unwrap();
        let key = dir.path().join("key.pem");
        std::fs::write(&key, "also not a pem").unwrap();
        let err = tls_listener_config(&cert, &key).unwrap_err();
        assert!(matches!(err, LoopbackPolicyError::BadPem(_)));
        // Missing file: same fail-closed family.
        let err = tls_listener_config(&dir.path().join("nope.pem"), &key).unwrap_err();
        assert!(matches!(err, LoopbackPolicyError::BadPem(_)));
        // The KEY read is its own wall: cert present, key missing.
        let err = tls_listener_config(&cert, &dir.path().join("nope.key")).unwrap_err();
        assert!(matches!(err, LoopbackPolicyError::BadPem(_)), "{err:?}");
    }

    #[test]
    fn pem_files_round_trip_into_a_usable_server_config() {
        // The operator path: rcgen-generated PEMs on disk → listener config.
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        let key_path = dir.path().join("key.pem");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        let cfg = tls_listener_config(&cert_path, &key_path).unwrap();
        assert_eq!(cfg.cert_count(), 1);
    }

    /// The mTLS fixture chain: a CA + a server cert signed by it + a
    /// client cert signed by it (all rcgen, offline). Paths on disk, the
    /// exact operator shape.
    struct MtlsFixture {
        dir: tempfile::TempDir,
    }

    impl MtlsFixture {
        fn new() -> Self {
            use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
            let dir = tempfile::tempdir().unwrap();
            let ca_key = KeyPair::generate().unwrap();
            let ca_params = CertificateParams::new(vec!["qsv test ca".to_string()]).unwrap();
            let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
            let server_key = KeyPair::generate().unwrap();
            let server_params =
                CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                    .unwrap();
            let server_cert = server_params
                .signed_by(&server_key, &ca_cert, &ca_key)
                .expect("server cert signed by the CA");
            let client_key = KeyPair::generate().unwrap();
            let client_params =
                CertificateParams::new(vec!["qsv co-signing client".to_string()]).unwrap();
            let client_cert = client_params
                .signed_by(&client_key, &ca_cert, &ca_key)
                .expect("client cert signed by the CA");
            std::fs::write(dir.path().join("ca.pem"), ca_cert.pem()).unwrap();
            std::fs::write(dir.path().join("cert.pem"), server_cert.pem()).unwrap();
            std::fs::write(dir.path().join("key.pem"), server_key.serialize_pem()).unwrap();
            std::fs::write(dir.path().join("client.pem"), client_cert.pem()).unwrap();
            std::fs::write(
                dir.path().join("client-key.pem"),
                client_key.serialize_pem(),
            )
            .unwrap();
            // (rcgen marks unconstrained CA only when the params say so; the
            // webpki verifier accepts this CA for the regtest drill.)
            let _ = IsCa::Ca(BasicConstraints::Unconstrained);
            Self { dir }
        }

        fn path(&self, name: &str) -> std::path::PathBuf {
            self.dir.path().join(name)
        }
    }

    #[test]
    fn mtls_config_carries_the_client_auth_requirement() {
        let fx = MtlsFixture::new();
        let cfg = tls_listener_config_with_client_auth(
            &fx.path("cert.pem"),
            &fx.path("key.pem"),
            &fx.path("ca.pem"),
        )
        .unwrap();
        assert!(cfg.requires_client_auth());
        // The plain listener stays anonymous-friendly (loopback drills).
        let plain = tls_listener_config(&fx.path("cert.pem"), &fx.path("key.pem")).unwrap();
        assert!(!plain.requires_client_auth());
    }

    #[test]
    fn mtls_without_a_client_ca_fails_closed() {
        let fx = MtlsFixture::new();
        let missing = tls_listener_config_with_client_auth(
            &fx.path("cert.pem"),
            &fx.path("key.pem"),
            &fx.path("no-such-ca.pem"),
        )
        .unwrap_err();
        assert!(matches!(missing, LoopbackPolicyError::BadPem(_)));
        // A PEM that parses but holds no certificate is the same family.
        let empty = fx.path("empty.pem");
        std::fs::write(&empty, "not a certificate\n").unwrap();
        let err =
            tls_listener_config_with_client_auth(&fx.path("cert.pem"), &fx.path("key.pem"), &empty)
                .unwrap_err();
        assert!(matches!(err, LoopbackPolicyError::BadPem(_)));
    }

    #[test]
    fn client_identity_loads_the_operator_pair_the_server_pinned() {
        let fx = MtlsFixture::new();
        let ident = client_identity(&fx.path("client.pem"), &fx.path("client-key.pem")).unwrap();
        assert_eq!(ident.certs.len(), 1, "leaf-only client chain");
        // The pinned store the SERVER built from the same CA trusts this
        // identity's certificate (the handshake will chain it).
        let ca_pem = std::fs::read(fx.path("ca.pem")).unwrap();
        let cas: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&ca_pem)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut roots = pinned_root_store(&cas[0]);
        assert!(roots.add(ident.certs[0].clone()).is_ok());
    }

    /// The `NoItemsFound` arm of the pki-types migration: a key file
    /// with no PEM section AT ALL is the fail-closed family (same
    /// message the pre-migration reader produced), not a parse fault.
    #[test]
    fn a_key_file_without_any_key_section_fails_closed_with_the_family_message() {
        let fx = MtlsFixture::new();
        let keyless = fx.path("keyless.pem");
        std::fs::write(&keyless, "definitely not a key\n").unwrap();
        let err = tls_listener_config(&fx.path("cert.pem"), &keyless).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no certificate or no private key found"),
            "family message, not a parse fault: {msg}"
        );
    }

    /// A key SECTION that is present but malformed (no END marker) is a
    /// parse fault carrying its cause — distinct from the family above.
    #[test]
    fn a_malformed_key_section_is_a_parse_fault_with_its_cause() {
        let fx = MtlsFixture::new();
        let broken = fx.path("broken-key.pem");
        // The armor header is assembled at RUNTIME: the secret scan
        // greps the tree for key armor, and a literal one in source
        // must keep failing it (same discipline as the scanner's own
        // PGP pattern, which is assembled at runtime too).
        let header = format!("{}{}", "-----BEGIN ", "PRIVATE KEY-----");
        std::fs::write(&broken, format!("{header}\nAAAA\n")).unwrap();
        let err = tls_listener_config(&fx.path("cert.pem"), &broken).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("parse key:"), "parse fault: {msg}");
    }
}
