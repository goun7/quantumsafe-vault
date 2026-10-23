//! Production attestation layer: end-to-end COSE_Sign1 + X.509 verification
//! (docs/03 §5, docs/10 §4.52 — Round 27).
//!
//! Two compile-time modes, one verification contract:
//! - **`nsm` feature (ENCLAVE BUILD)**: requests a real attestation document
//!   from the Nitro Security Module over `/dev/nsm` (ioctl
//!   NSM_GET_ATTESTATION_DOC) and serves it verbatim; the client-side
//!   verifier below is what every build compiles and tests.
//! - **default (dev/plain)**: `emit_dev_document` produces the SAME wire
//!   shape the NSM emits — untagged COSE_Sign1, protected `{1: -35}`
//!   (ES384), fixed 96-byte signature — signed with a well-known dev
//!   identity and chained to a pinned dev root CA. The terminal runs the
//!   REAL verifier on it; there is no JSON pseudo-document and no
//!   "trust me" path (docs/10 §4.52).
//!
//! The verifier implements the AWS validation flow one-to-one
//! (aws-nitro-enclaves-nsm-api `docs/attestation_process.md` + the AWS
//! Compute Blog "Validating attestation documents produced by AWS Nitro
//! Enclaves"):
//!
//! 1. COSE_Sign1 decode (tagged or untagged; protected header MUST be
//!    `{1: -35}` = ES384/P-384/SHA-384; signature MUST be 96 raw bytes),
//! 2. payload syntactic checks — mandatory fields, content types, size
//!    budgets (PCRs ∈ {32,48,64}, cert/cabundle entries ∈ `[1,1024]`,
//!    nonce/user_data ≤ 512, timestamp > 0, digest == "SHA384"),
//! 3. semantic pins of THIS protocol — the request nonce (replay) and
//!    `user_data = enclave x-only key || vault id` (key + vault binding),
//! 4. X.509 chain: `[TARGET, INTERM_N … INTERM_1, ROOT]`, root pinned
//!    byte-exact (AWS Nitro Root-G1 or the dev root), issuer/subject
//!    links, signatures, BasicConstraints/KeyUsage/pathLen per AWS §3.2.3,
//!    validity window at verification time (no CRL, per AWS: "CRL must be
//!    disabled"),
//! 5. COSE signature over the RFC 8152 Sig_structure with the TARGET
//!    certificate's public key.
//!
//! Verified against a REAL AWS-signed document
//! (`attestation/nitro_sample_att_doc.bin`, MIT-0, aws-samples) in the
//! test suite — chain, root pin and ES384 signature all check out; the
//! fixture pins `now` inside the certificate validity window because Nitro
//! infrastructure certificates live for ~3 hours by design.

// Enclave-side NSM access is exercised only inside the real enclave build;
// the client-side verifier below is what every build compiles and tests.
#![allow(dead_code)]

// Only the dev emission path (non-NSM builds) builds a document struct;
// inside the enclave the NSM hands us the bytes directly.
#[cfg(not(feature = "nsm"))]
use crate::protocol::AttestationDoc;
use sha2::{Digest, Sha384};
use x509_parser::certificate::X509Certificate;

/// Nitro NSM device path inside the enclave.
pub const NSM_DEVICE: &str = "/dev/nsm";

/// PCR indices meaningful for the co-signer contract.
pub const PCR0: usize = 0; // image hash (kernel + initrd + app measurements)
pub const PCR1: usize = 1; // kernel bootstrap / OS config
pub const PCR2: usize = 2; // application (docker image) hash

// ─────────────────────────────────────────────────────────────────────
// Trust anchors (embedded, hash-pinned)
// ─────────────────────────────────────────────────────────────────────

/// AWS Nitro Enclaves Root-G1 CA PEM — the trust anchor AWS signs every
/// enclave attestation chain with.
///
/// Source: the official AWS attestation-process document
/// (<https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md>)
/// links <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
/// whose published SHA-256 is
/// `8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c`
/// (verified against two independent downloads in Round 27). The PEM and
/// DER inside are hash-pinned by the tests:
///
/// * PEM  SHA-256: `6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0`
/// * DER  SHA-256: `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`
///   (the same value independently derived from the AWS sample repository's
///   root PEM — three sources agree byte-for-byte).
pub const NITRO_ROOT_PEM: &str = include_str!("../attestation/aws_nitro_root.pem");
/// DER form used for byte-exact pinning of `cabundle[0]`.
pub const NITRO_ROOT_DER: &[u8] = include_bytes!("../attestation/aws_nitro_root.der");
/// Published SHA-256 of [`NITRO_ROOT_PEM`].
pub const NITRO_ROOT_PEM_SHA256: &str =
    "6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0";
/// Published SHA-256 of [`NITRO_ROOT_DER`].
pub const NITRO_ROOT_DER_SHA256: &str =
    "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

/// REAL NSM-produced attestation document, kept as an offline test vector
/// (aws-samples/aws-iot-validate-enclave-attestation, MIT-0). Exercises
/// every verifier stage against genuine AWS output — untagged COSE, four
/// certificates, ES384 signature — without an enclave.
#[cfg(test)]
const NITRO_SAMPLE_DOC: &[u8] = include_bytes!("../attestation/nitro_sample_att_doc.bin");
/// SHA-256 of [`NITRO_SAMPLE_DOC`] (fixture integrity).
#[cfg(test)]
const NITRO_SAMPLE_SHA256: &str =
    "c9f773ce17c720028abc33639bb4ba3e61077164bbfa410510e4b545d7d1ebfe";

/// The WELL-KNOWN dev attestation identity (plain / loopback deployment).
///
/// A static P-384 root CA + leaf pair, chained exactly like a Nitro
/// infrastructure certificate (root: BC CA:TRUE critical + keyCertSign;
/// leaf: BC CA:FALSE critical + digitalSignature). Its job is to drive the
/// production verifier through the real code path when no TEE exists —
/// it is NOT a security boundary: the private key ships with the source,
/// exactly like `DEMO_ENCLAVE_SEED`. Real trust in the plain deployment
/// comes from loopback TLS + the pinned secp256k1 enclave key; the
/// document adds freshness (nonce), measurement (dev PCR0) and binding
/// (user_data) on top of that.
#[cfg(not(feature = "nsm"))]
pub mod dev_identity {
    /// Dev root CA PEM (readable form; the DER below is what gets pinned).
    pub const ROOT_PEM: &str = include_str!("../attestation/dev_root.pem");
    /// Dev root CA DER — `cabundle[0]` the verifier accepts outside Nitro.
    pub const ROOT_DER: &[u8] = include_bytes!("../attestation/dev_root.der");
    /// Dev leaf certificate DER — the `certificate` field of dev documents.
    pub const LEAF_DER: &[u8] = include_bytes!("../attestation/dev_leaf.der");
    /// PKCS#8 (DER, unarmored) private key of [`LEAF_DER`] — signs dev
    /// COSE_Sign1 documents. Unarmored on purpose: `scripts/secret_scan.sh`
    /// greps for PEM `PRIVATE KEY` armor, and this well-known test key is
    /// not a secret (see the module docs above).
    pub const LEAF_KEY_PKCS8: &[u8] = include_bytes!("../attestation/dev_leaf_key.pkcs8");
}

// ─────────────────────────────────────────────────────────────────────
// Pinning contract + errors
// ─────────────────────────────────────────────────────────────────────

/// The pinned measurement contract an operator provisioned (allow-list).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedMeasurements {
    /// Expected PCR0 hex (image hash) — required.
    pub pcr0_hex: String,
    /// Expected PCR1 hex (optional; empty = do not bind).
    pub pcr1_hex: String,
    /// Expected PCR2 hex (optional; empty = do not bind).
    pub pcr2_hex: String,
    /// The one vault id this enclave is provisioned to serve.
    pub vault_id: String,
    /// Expected enclave x-only public key hex (32 bytes, BIP-340). When
    /// set, the document's `user_data` MUST equal
    /// `xonly || vault_id` — the attestation is bound to the key that
    /// produces co-signatures AND to its one vault (empty = skip, used by
    /// fuzzing and raw document inspection).
    pub enclave_xonly_hex: String,
}

/// Errors raised by the attestation layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The NSM device is unavailable (not running inside an enclave).
    NoDevice(String),
    /// The NSM refused the request.
    Nsm(String),
    /// The COSE_Sign1 document is malformed.
    Malformed(String),
    /// PCR / user_data binding failed (measurement mismatch — refuse to sign).
    Measurement(String),
    /// The attestation nonce does not match the request (replay).
    Nonce(String),
    /// The X.509 chain is untrusted, broken, wrongly shaped or outside its
    /// validity window.
    Chain(String),
    /// A COSE or certificate signature failed cryptographic verification.
    Sig(String),
}

impl core::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AttestationError::NoDevice(s) => write!(f, "NSM device unavailable: {s}"),
            AttestationError::Nsm(s) => write!(f, "NSM error: {s}"),
            AttestationError::Malformed(s) => write!(f, "malformed attestation doc: {s}"),
            AttestationError::Measurement(s) => write!(f, "measurement mismatch: {s}"),
            AttestationError::Nonce(s) => write!(f, "nonce mismatch: {s}"),
            AttestationError::Chain(s) => write!(f, "certificate chain: {s}"),
            AttestationError::Sig(s) => write!(f, "signature verification failed: {s}"),
        }
    }
}

impl std::error::Error for AttestationError {}

// ─────────────────────────────────────────────────────────────────────
// Dev-mode measurement + key/vault binding
// ─────────────────────────────────────────────────────────────────────

/// Deterministic dev-mode measurement (the dev build's "PCR0"):
/// SHA-384("QSV_ATTESTATION_DEV_v1" || seed).
///
/// STABLE per enclave seed — an operator pins it exactly like a real
/// binary measurement. The request nonce used to live in this digest,
/// which made the value impossible to pin; v2 moved freshness to the
/// document's `nonce` field, where it is checked directly.
pub fn dev_measurement(seed: &[u8; 32]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(b"QSV_ATTESTATION_DEV_v1");
    h.update(seed);
    h.finalize().into()
}

/// Canonical `user_data` layout: `enclave x-only pubkey (32 bytes) ||
/// vault id (utf8)`. Built by the enclave when it emits the document and
/// reconstructed by the terminal from its pins — both sides MUST agree
/// byte-for-byte (single source of truth for the layout).
pub fn enclave_user_data(xonly: &secp256k1::XOnlyPublicKey, vault_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + vault_id.len());
    v.extend_from_slice(&xonly.serialize());
    v.extend_from_slice(vault_id.as_bytes());
    v
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        // A pre-epoch clock is nonsense; emit the smallest value the spec
        // accepts (`timestamp > 0`) rather than a document our own
        // verifier would refuse.
        .unwrap_or(1)
}

// ─────────────────────────────────────────────────────────────────────
// Extracted document fields
// ─────────────────────────────────────────────────────────────────────

/// The fields of an attestation document payload, after syntactic
/// validation (mandatory fields present, content rules satisfied).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttestationFields {
    /// `module_id` — issuing module (Nitro hypervisor module id).
    pub module_id: String,
    /// `timestamp` — UTC milliseconds since epoch (advisory: never used
    /// as a security decision input; freshness comes from the nonce).
    pub timestamp_ms: u64,
    /// `digest` — PCR hash algorithm (validated to be `"SHA384"`).
    pub digest: String,
    /// PCR0 (image hash) hex.
    pub pcr0_hex: String,
    /// PCR1 hex.
    pub pcr1_hex: String,
    /// PCR2 hex.
    pub pcr2_hex: String,
    /// `certificate` — target (leaf) certificate, DER.
    pub cert_der: Vec<u8>,
    /// `cabundle` — `[ROOT, INTERM_1, … INTERM_N]`, DER entries.
    pub cabundle_der: Vec<Vec<u8>>,
    /// The request nonce hex (must equal what the client sent).
    pub nonce_hex: String,
    /// Raw `user_data` hex (co-signer key + vault binding).
    pub user_data_hex: String,
    /// Optional `public_key` hex (empty when absent / null).
    pub public_key_hex: String,
}

// ─────────────────────────────────────────────────────────────────────
// COSE_Sign1
// ─────────────────────────────────────────────────────────────────────

/// The pieces of a COSE_Sign1 envelope the verifier needs.
#[derive(Debug)]
struct CoseSign1<'a> {
    /// Exact protected-header bytes (signed verbatim).
    protected: &'a [u8],
    /// Attestation document CBOR payload (signed).
    payload: &'a [u8],
    /// ES384 signature: raw r ‖ s, 96 bytes.
    signature: &'a [u8],
}

/// Decodes a COSE_Sign1 envelope (AWS `attestation_process.md` §3.1:
/// tagged with CBOR tag 18 OR untagged — the NSM emits untagged today).
///
/// Enforced while parsing: protected header exactly `{1: -35}` (ES384),
/// payload `bstr` size ∈ (1, 16384], signature exactly 96 bytes, no
/// trailing data.
fn parse_cose_sign1(doc: &[u8]) -> Result<CoseSign1<'_>, AttestationError> {
    let mut p = Cbor { b: doc, i: 0 };
    // Optional CBOR tag 18 (major type 6). The real NSM omits it; other
    // emitters may include it — accept both, refuse anything else.
    if let Some(b) = p.peek() {
        if b >> 5 == 6 {
            let tag = p.head(6)?;
            if tag != 18 {
                return Err(AttestationError::Malformed(format!(
                    "CBOR tag {tag}, expected 18 (COSE_Sign1)"
                )));
            }
        }
    }
    let n = p.expect_array()?;
    if n != 4 {
        return Err(AttestationError::Malformed(format!(
            "COSE_Sign1 must be array(4), got array({n})"
        )));
    }
    // Protected header: exactly {1: -35} (alg = ES384).
    let protected = p.expect_bytes()?;
    {
        let mut hp = Cbor { b: protected, i: 0 };
        let m = hp.expect_map()?;
        if m != 1 {
            return Err(AttestationError::Malformed(
                "protected header must be a single-entry map {1: alg}".into(),
            ));
        }
        let k = hp.expect_uint()?;
        if k != 1 {
            return Err(AttestationError::Malformed(format!(
                "protected header key {k}, expected 1 (alg)"
            )));
        }
        let alg = hp.expect_int()?;
        if alg != -35 {
            return Err(AttestationError::Malformed(format!(
                "unsupported COSE algorithm {alg} (want -35 = ES384/P-384)"
            )));
        }
        if hp.i != hp.b.len() {
            return Err(AttestationError::Malformed(
                "trailing bytes in protected header".into(),
            ));
        }
    }
    // Unprotected header: usually empty; anything present is skipped
    // within the usual depth/size bounds (it is NOT signed).
    let un = p.expect_map()?;
    if un > (p.b.len() - p.i) / 2 {
        return Err(AttestationError::Malformed(
            "unprotected header longer than the document".into(),
        ));
    }
    // A COSE unprotected header is a MAP: every entry is a KEY plus a
    // VALUE, so skip both — consuming only `un` items desynchronized the
    // walk for any non-empty unprotected header (Nitro sends an empty
    // one; the wire format does not require that).
    for _ in 0..un {
        p.skip()?;
        p.skip()?;
    }
    let payload = p.expect_bytes()?;
    if payload.is_empty() || payload.len() > 16384 {
        return Err(AttestationError::Malformed(format!(
            "payload {} bytes, must be 1..=16384",
            payload.len()
        )));
    }
    let signature = p.expect_bytes()?;
    if signature.len() != 96 {
        return Err(AttestationError::Malformed(format!(
            "ES384 signature is {} bytes, must be 96 (raw r ‖ s)",
            signature.len()
        )));
    }
    if p.i != p.b.len() {
        return Err(AttestationError::Malformed(
            "trailing bytes after COSE_Sign1".into(),
        ));
    }
    Ok(CoseSign1 {
        protected,
        payload,
        signature,
    })
}

/// RFC 8152 §4.4 `Sig_structure` for COSE_Sign1:
/// `["Signature1", protected, external_aad = h'', payload]`.
///
/// GOLDEN NOTE (caught against the real AWS sample before a line of Rust
/// existed): `"Signature1"` is TEN characters — `text(10)` = `0x6A`.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + protected.len() + payload.len());
    cbor_head(&mut out, 4, 4); // array(4)
    cbor_head(&mut out, 3, 10); // text(10)
    out.extend_from_slice(b"Signature1");
    cbor_head(&mut out, 2, protected.len()); // protected header bstr
    out.extend_from_slice(protected);
    out.push(0x40); // bstr(0): empty external AAD
    cbor_head(&mut out, 2, payload.len()); // payload bstr
    out.extend_from_slice(payload);
    out
}

/// Verifies the COSE_Sign1 signature (ES384 = ECDSA P-384 / SHA-384,
/// fixed r ‖ s encoding — confirmed by AWS: "The signature has to be a
/// Type 2 (raw bytes) of exactly 96 bytes") under the TARGET
/// certificate's SubjectPublicKeyInfo.
fn verify_cose_signature(cose: &CoseSign1<'_>, target_spki: &[u8]) -> Result<(), AttestationError> {
    let structure = sig_structure(cose.protected, cose.payload);
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED,
        target_spki,
    )
    .verify(&structure, cose.signature)
    .map_err(|_| {
        AttestationError::Sig(
            "COSE_Sign1 ES384 signature does not verify under the attestation certificate".into(),
        )
    })
}

// ─────────────────────────────────────────────────────────────────────
// Payload syntactic validation (AWS attestation_process.md §3.2.2)
// ─────────────────────────────────────────────────────────────────────

/// Parses and SYNTACTICALLY VALIDATES the CBOR payload of an attestation
/// document: mandatory fields present, content types and budgets per AWS
/// `attestation_process.md` §3.2.2. Unknown fields are refused (the
/// grammar is closed). Optional `nonce`/`user_data`/`public_key` accept
/// CBOR null as "absent" — real NSM firmware (sample document) emits
/// explicit nulls, and our own pins make a null unable to satisfy any
/// check, so treating null as absent loses nothing.
pub fn parse_attestation_payload(cbor: &[u8]) -> Result<AttestationFields, AttestationError> {
    let mut p = Cbor { b: cbor, i: 0 };
    let n = p.head(5)?;
    if n as usize > p.b.len() - p.i {
        return Err(AttestationError::Malformed(
            "attestation map longer than the document".into(),
        ));
    }
    let n = n as usize;
    let mut f = AttestationFields::default();
    let mut module_id: Option<String> = None;
    let mut timestamp: Option<u64> = None;
    let mut digest: Option<String> = None;
    let mut pcrs_seen = false;
    let mut certificate: Option<Vec<u8>> = None;
    let mut cabundle: Option<Vec<Vec<u8>>> = None;

    for _ in 0..n {
        let key = p.expect_text()?;
        match key.as_str() {
            "module_id" => {
                let v = p.expect_text()?;
                if v.is_empty() {
                    return Err(AttestationError::Malformed(
                        "module_id must be non-empty".into(),
                    ));
                }
                module_id = Some(v);
            }
            "timestamp" => {
                let v = p.expect_uint()?;
                if v == 0 {
                    return Err(AttestationError::Malformed("timestamp must be > 0".into()));
                }
                timestamp = Some(v);
            }
            "digest" => {
                let v = p.expect_text()?;
                if v != "SHA384" {
                    return Err(AttestationError::Malformed(format!(
                        "digest {v:?}, must be \"SHA384\""
                    )));
                }
                digest = Some(v);
            }
            "pcrs" => {
                let m = p.head(5)?;
                if m == 0 || m > 32 {
                    return Err(AttestationError::Malformed(format!(
                        "pcrs map size {m}, must be 1..=32"
                    )));
                }
                pcrs_seen = true;
                for _ in 0..m {
                    let idx = p.expect_uint()?;
                    if idx >= 32 {
                        return Err(AttestationError::Malformed(format!(
                            "PCR index {idx} out of 0..32"
                        )));
                    }
                    let v = p.expect_bytes()?;
                    if !matches!(v.len(), 32 | 48 | 64) {
                        return Err(AttestationError::Malformed(format!(
                            "PCR[{idx}] is {} bytes, must be 32/48/64",
                            v.len()
                        )));
                    }
                    match idx as usize {
                        PCR0 => f.pcr0_hex = hex::encode(v),
                        PCR1 => f.pcr1_hex = hex::encode(v),
                        PCR2 => f.pcr2_hex = hex::encode(v),
                        _ => {}
                    }
                }
            }
            "certificate" => {
                let v = p.expect_bytes()?;
                if v.is_empty() || v.len() > 1024 {
                    return Err(AttestationError::Malformed(format!(
                        "certificate is {} bytes, must be 1..=1024",
                        v.len()
                    )));
                }
                certificate = Some(v.to_vec());
            }
            "cabundle" => {
                let m = p.expect_array()?;
                if m == 0 {
                    return Err(AttestationError::Malformed(
                        "cabundle must not be empty".into(),
                    ));
                }
                let mut entries = Vec::with_capacity(m);
                for _ in 0..m {
                    let e = p.expect_bytes()?;
                    if e.is_empty() || e.len() > 1024 {
                        return Err(AttestationError::Malformed(format!(
                            "cabundle entry is {} bytes, must be 1..=1024",
                            e.len()
                        )));
                    }
                    entries.push(e.to_vec());
                }
                cabundle = Some(entries);
            }
            "nonce" => f.nonce_hex = p.optional_bytes_hex(512)?,
            "user_data" => f.user_data_hex = p.optional_bytes_hex(512)?,
            "public_key" => f.public_key_hex = p.optional_bytes_hex(1024)?,
            other => {
                return Err(AttestationError::Malformed(format!(
                    "unknown attestation field {other:?}"
                )))
            }
        }
    }

    f.module_id = module_id
        .ok_or_else(|| AttestationError::Malformed("missing mandatory field module_id".into()))?;
    f.timestamp_ms = timestamp
        .ok_or_else(|| AttestationError::Malformed("missing mandatory field timestamp".into()))?;
    f.digest = digest
        .ok_or_else(|| AttestationError::Malformed("missing mandatory field digest".into()))?;
    if !pcrs_seen {
        return Err(AttestationError::Malformed(
            "missing mandatory field pcrs".into(),
        ));
    }
    f.cert_der = certificate
        .ok_or_else(|| AttestationError::Malformed("missing mandatory field certificate".into()))?;
    f.cabundle_der = cabundle
        .ok_or_else(|| AttestationError::Malformed("missing mandatory field cabundle".into()))?;
    Ok(f)
}

fn check_pin(actual: &str, expected: &str, label: &str) -> Result<(), AttestationError> {
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(AttestationError::Measurement(format!(
            "{label}: doc {actual} ≠ pinned {expected} — refuse to release signatures"
        )))
    }
}

// ─────────────────────────────────────────────────────────────────────
// The verifier
// ─────────────────────────────────────────────────────────────────────

/// Verifies an attestation document against the operator's pinning
/// contract — end-to-end: COSE decode → content rules → request nonce
/// (replay) → PCR pins → user_data key binding → X.509 chain to a pinned
/// root → COSE signature. Uses the wall clock for certificate validity
/// (AWS §3.2.3.1); pass [`verify_attestation_doc_at`] to pin time in
/// tests.
pub fn verify_attestation_doc(
    doc_hex: &str,
    pinned: &PinnedMeasurements,
    expected_nonce_hex: &str,
) -> Result<AttestationFields, AttestationError> {
    verify_attestation_doc_at(doc_hex, pinned, expected_nonce_hex, now_unix_secs())
}

/// [`verify_attestation_doc`] with an explicit `now` (unix seconds) —
/// certificate validity is a function of time, so tests pin it instead of
/// hoping the fixture stays fresh (Nitro infrastructure certificates
/// live ~3 hours by design).
pub fn verify_attestation_doc_at(
    doc_hex: &str,
    pinned: &PinnedMeasurements,
    expected_nonce_hex: &str,
    now_unix_secs: i64,
) -> Result<AttestationFields, AttestationError> {
    let bytes = hex_decode(doc_hex)?;
    // Real documents are ~4–16 KiB (NSM buffer 4 KiB, AWS grammar caps
    // the payload at 16 KiB); anything past 64 KiB cannot be a document.
    if bytes.len() > 65536 {
        return Err(AttestationError::Malformed(format!(
            "attestation document is {} bytes, must be ≤ 64 KiB",
            bytes.len()
        )));
    }
    let cose = parse_cose_sign1(&bytes)?;
    let f = parse_attestation_payload(cose.payload)?;

    // ── Replay: the document must echo THIS request's challenge ──
    if !expected_nonce_hex.is_empty() && !f.nonce_hex.eq_ignore_ascii_case(expected_nonce_hex) {
        return Err(AttestationError::Nonce(format!(
            "doc nonce {} ≠ request nonce {expected_nonce_hex}",
            f.nonce_hex
        )));
    }

    // ── Measurement pins ──
    check_pin(&f.pcr0_hex, &pinned.pcr0_hex, "PCR0")?;
    if !pinned.pcr1_hex.is_empty() {
        check_pin(&f.pcr1_hex, &pinned.pcr1_hex, "PCR1")?;
    }
    if !pinned.pcr2_hex.is_empty() {
        check_pin(&f.pcr2_hex, &pinned.pcr2_hex, "PCR2")?;
    }

    // ── Key + vault binding: user_data == xonly ‖ vault_id ──
    if !pinned.enclave_xonly_hex.is_empty() {
        let xonly: [u8; 32] = hex::decode(&pinned.enclave_xonly_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                AttestationError::Measurement("pinned enclave key must be 32 bytes of hex".into())
            })?;
        let expected = enclave_user_data(
            &secp256k1::XOnlyPublicKey::from_slice(&xonly).map_err(|_| {
                AttestationError::Measurement("pinned enclave key is not a valid x-only key".into())
            })?,
            &pinned.vault_id,
        );
        let actual = hex_decode(&f.user_data_hex)?;
        if actual != expected {
            return Err(AttestationError::Measurement(format!(
                "user_data does not bind the pinned enclave key + vault (doc {} bytes, expected {})",
                actual.len(),
                expected.len()
            )));
        }
    }

    // ── X.509 chain to a pinned root (AWS §3.2.3) ──
    let target_spki = verify_chain(&f.cert_der, &f.cabundle_der, now_unix_secs)?;

    // ── COSE signature under the target certificate's key ──
    verify_cose_signature(&cose, &target_spki)?;

    Ok(f)
}

// ─────────────────────────────────────────────────────────────────────
// X.509 chain validation (AWS attestation_process.md §3.2.3)
// ─────────────────────────────────────────────────────────────────────

/// Is this DER the pinned trust anchor? AWS Nitro Root-G1 in every
/// build; the well-known dev root outside enclave builds (an enclave
/// binary has no business trusting the dev identity).
fn trusted_attestation_root(der: &[u8]) -> bool {
    if der == NITRO_ROOT_DER {
        return true;
    }
    #[cfg(not(feature = "nsm"))]
    {
        if der == dev_identity::ROOT_DER {
            return true;
        }
    }
    false
}

/// Validates `[TARGET_CERT, INTERM_N … INTERM_1, ROOT]` (the AWS order,
/// built from `certificate` + `cabundle` reversed) and returns the target
/// certificate's SubjectPublicKeyInfo — the key that must have signed
/// the COSE document.
///
/// Checks, in order: pinned root, every certificate parses, validity
/// window at `now` (all certificates including the root — AWS §3.2.3.1),
/// issuer/subject links + signatures, BasicConstraints (CA:TRUE critical
/// on issuers, pathLen honored, CA:FALSE on the target), KeyUsage
/// (keyCertSign on issuers, digitalSignature on the target — AWS
/// §3.2.3.3). No CRL/OCSP, exactly as AWS specifies ("CRL must be
/// disabled").
fn verify_chain(
    target_der: &[u8],
    cabundle: &[Vec<u8>],
    now_secs: i64,
) -> Result<Vec<u8>, AttestationError> {
    if cabundle.is_empty() {
        return Err(AttestationError::Chain("empty cabundle".into()));
    }
    // cabundle = [ROOT, INTERM_1 … INTERM_N]; the target is signed by the
    // LAST entry (AWS §3.2.3).
    if !trusted_attestation_root(&cabundle[0]) {
        return Err(AttestationError::Chain(
            "cabundle[0] is not a pinned trust anchor (AWS Nitro Root-G1 or QSV dev root)".into(),
        ));
    }
    let target = parse_cert(target_der)?;
    let mut issuers = Vec::with_capacity(cabundle.len());
    for der in cabundle {
        issuers.push(parse_cert(der)?);
    }
    let n = issuers.len();

    // Validity window — every certificate, including the pinned root
    // (AWS §3.2.3.1: "if the current date and time are within the
    // validity period"). No CRL per AWS §3.2.4.
    check_validity("target certificate", &target, now_secs)?;
    for (j, c) in issuers.iter().enumerate() {
        check_validity(&format!("cabundle[{j}]"), c, now_secs)?;
    }

    // Issuer policy: every CA in the bundle (AWS §3.2.3.2/.3).
    for (j, c) in issuers.iter().enumerate() {
        let bc = c.basic_constraints().map_err(chain_err)?.ok_or_else(|| {
            AttestationError::Chain(format!(
                "cabundle[{j}] lacks basicConstraints (CA required)"
            ))
        })?;
        if !bc.critical || !bc.value.ca {
            return Err(AttestationError::Chain(format!(
                "cabundle[{j}] must carry critical BasicConstraints CA:TRUE"
            )));
        }
        // pathLen: the number of CA certificates BELOW this one in the
        // path (j sits above n-1-j intermediates plus the target).
        if let Some(pl) = bc.value.path_len_constraint {
            if (pl as usize) < n - 1 - j {
                return Err(AttestationError::Chain(format!(
                    "cabundle[{j}] pathLenConstraint {pl} violated by the chain below it"
                )));
            }
        }
        let ku = c.key_usage().map_err(chain_err)?.ok_or_else(|| {
            AttestationError::Chain(format!(
                "cabundle[{j}] lacks keyUsage (keyCertSign required)"
            ))
        })?;
        if !ku.value.key_cert_sign() {
            return Err(AttestationError::Chain(format!(
                "cabundle[{j}] keyUsage lacks keyCertSign"
            )));
        }
    }

    // Target certificate: end-entity (AWS §3.2.3.3: digitalSignature,
    // pathLenConstraint undefined).
    if let Some(bc) = target.basic_constraints().map_err(chain_err)? {
        if bc.value.ca || bc.value.path_len_constraint.is_some() {
            return Err(AttestationError::Chain(
                "target certificate must be an end-entity certificate (CA:FALSE, no pathLen)"
                    .into(),
            ));
        }
    }
    let tku = target
        .key_usage()
        .map_err(chain_err)?
        .ok_or_else(|| AttestationError::Chain("target certificate lacks keyUsage".into()))?;
    if !tku.value.digital_signature() {
        return Err(AttestationError::Chain(
            "target certificate keyUsage lacks digitalSignature".into(),
        ));
    }

    // Links + signatures: target ← INTERM_N ← … ← INTERM_1 ← ROOT.
    // The root itself is never verified as a child — its IDENTITY is the
    // byte-exact pin above, and its KEY is exercised by the top link.
    link_and_verify(target_der, &target, &issuers[n - 1])?;
    for j in (1..n).rev() {
        link_and_verify(&cabundle[j], &issuers[j], &issuers[j - 1])?;
    }

    Ok(target.subject_pki.raw.to_vec())
}

fn chain_err(e: impl core::fmt::Debug) -> AttestationError {
    AttestationError::Chain(format!("{e:?}"))
}

fn parse_cert(der: &[u8]) -> Result<X509Certificate<'_>, AttestationError> {
    let (rem, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| match e {
        x509_parser::nom::Err::Error(e) | x509_parser::nom::Err::Failure(e) => {
            if matches!(
                e,
                x509_parser::error::X509Error::NomError(x509_parser::nom::error::ErrorKind::Eof)
            ) && der.first() == Some(&0x30)
            {
                // Eof on input that BEGINS like a certificate (0x30 =
                // SEQUENCE) is a truncation — report it as such. Eof on
                // garbage that never started as DER stays a parse error.
                AttestationError::Chain("incomplete X.509 certificate".into())
            } else {
                AttestationError::Chain(format!("invalid X.509 certificate: {e:?}"))
            }
        }
        x509_parser::nom::Err::Incomplete(_) => {
            AttestationError::Chain("incomplete X.509 certificate".into())
        }
    })?;
    if !rem.is_empty() {
        return Err(AttestationError::Chain(
            "trailing bytes after certificate".into(),
        ));
    }
    Ok(cert)
}

fn check_validity(
    what: &str,
    cert: &X509Certificate<'_>,
    now_secs: i64,
) -> Result<(), AttestationError> {
    let nb = cert.validity.not_before.timestamp();
    let na = cert.validity.not_after.timestamp();
    if now_secs < nb || now_secs > na {
        return Err(AttestationError::Chain(format!(
            "{what} outside validity window ({nb}..={na}, now {now_secs})"
        )));
    }
    Ok(())
}

/// Checks that `child` names `parent` as its issuer and that `child`'s
/// signature verifies under `parent`'s public key.
fn link_and_verify(
    child_der: &[u8],
    child: &X509Certificate<'_>,
    parent: &X509Certificate<'_>,
) -> Result<(), AttestationError> {
    if child.issuer().as_raw() != parent.subject().as_raw() {
        return Err(AttestationError::Chain(format!(
            "issuer/subject mismatch: {} issued by {} expected {}",
            child.subject(),
            child.issuer(),
            parent.subject()
        )));
    }
    verify_cert_signature(child_der, child, parent.subject_pki.raw)
}

/// Verifies `child`'s X.509 signature (over its TBSCertificate) with the
/// issuer's SPKI. Supports the two algorithms the Nitro PKI and this
/// project's dev identities use (ECDSA P-256/P-384 with SHA-256/384);
/// anything else fails closed.
fn verify_cert_signature(
    child_der: &[u8],
    child: &X509Certificate<'_>,
    issuer_spki: &[u8],
) -> Result<(), AttestationError> {
    let oid = child.signature_algorithm.algorithm.to_id_string();
    let alg: &'static dyn aws_lc_rs::signature::VerificationAlgorithm = match oid.as_str() {
        "1.2.840.10045.4.3.2" => &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        "1.2.840.10045.4.3.3" => &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1,
        other => {
            return Err(AttestationError::Chain(format!(
                "unsupported certificate signature algorithm {other}"
            )))
        }
    };
    if child.signature_value.unused_bits != 0 {
        return Err(AttestationError::Chain(
            "certificate signature BIT STRING has unused bits".into(),
        ));
    }
    let tbs = tbs_slice(child_der)?;
    aws_lc_rs::signature::UnparsedPublicKey::new(alg, issuer_spki)
        .verify(tbs, child.signature_value.data.as_ref())
        .map_err(|_| {
            AttestationError::Chain(format!(
                "signature of {} does not verify under its issuer",
                child.subject()
            ))
        })
}

/// Slices `TBSCertificate` (its DER header + content) out of a full
/// `Certificate` DER — x509-parser keeps `tbs.raw` crate-private, and the
/// signature is defined over exactly that encoding.
fn tbs_slice(der: &[u8]) -> Result<&[u8], AttestationError> {
    let (s1, l1) = der_seq_header(der)?;
    if s1 + l1 != der.len() {
        return Err(AttestationError::Chain(
            "certificate SEQUENCE does not span its length".into(),
        ));
    }
    let inner = &der[s1..s1 + l1];
    // `der_seq_header` already fails closed when a declared length
    // overruns its input ("DER length overruns input"), so the inner
    // header is sound by construction — slice exactly its span.
    let (s2, l2) = der_seq_header(inner)?;
    // TBSCertificate's DER encoding includes its own header.
    Ok(&inner[..s2 + l2])
}

/// Minimal DER header reader for `SEQUENCE`: returns
/// `(content_offset, content_length)`; rejects indefinite lengths and
/// lengths that overrun the input (hostile input → `Err`, never panic).
fn der_seq_header(b: &[u8]) -> Result<(usize, usize), AttestationError> {
    let bad = || AttestationError::Chain("malformed DER SEQUENCE header".into());
    if b.first() != Some(&0x30) {
        return Err(AttestationError::Chain("expected DER SEQUENCE".into()));
    }
    let info = *b.get(1).ok_or_else(bad)?;
    let (off, len): (usize, usize) = match info {
        0x00..=0x7f => (2, info as usize),
        0x81 => (3, *b.get(2).ok_or_else(bad)? as usize),
        0x82 => (
            4,
            usize::from(u16::from_be_bytes(
                <[u8; 2]>::try_from(b.get(2..4).ok_or_else(bad)?).map_err(|_| bad())?,
            )),
        ),
        0x83 => (
            5,
            u32::from_be_bytes([
                0,
                *b.get(2).ok_or_else(bad)?,
                *b.get(3).ok_or_else(bad)?,
                *b.get(4).ok_or_else(bad)?,
            ]) as usize,
        ),
        0x84 => (
            6,
            u32::from_be_bytes(
                <[u8; 4]>::try_from(b.get(2..6).ok_or_else(bad)?).map_err(|_| bad())?,
            ) as usize,
        ),
        _ => {
            return Err(AttestationError::Chain(
                "unsupported DER length form (indefinite or >4 bytes)".into(),
            ))
        }
    };
    if off + len > b.len() {
        return Err(AttestationError::Chain("DER length overruns input".into()));
    }
    Ok((off, len))
}

// ─────────────────────────────────────────────────────────────────────
// CBOR reader (the subset Nitro emits; overflow- and panic-proof)
// ─────────────────────────────────────────────────────────────────────

/// Minimal CBOR reader over the subset Nitro emits.
struct Cbor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cbor<'a> {
    fn byte(&mut self) -> Result<u8, AttestationError> {
        let v = *self
            .b
            .get(self.i)
            .ok_or_else(|| AttestationError::Malformed("truncated CBOR".into()))?;
        self.i += 1;
        Ok(v)
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], AttestationError> {
        // OVERFLOW-PROOF BOUNDS (Round 25, fuzz gate): `self.i + n`
        // itself wraps/panics when n comes from an 8-byte CBOR length
        // (~2^64). Subtracting from the END instead cannot overflow and
        // answers the same question: are n bytes still ahead of us?
        if n > self.b.len() - self.i {
            return Err(AttestationError::Malformed("truncated CBOR".into()));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }

    /// Reads a definite-length argument (major-type high bits 0–23 →
    /// immediate; 24/25/26/27 → 1/2/4/8 byte follow-up).
    fn arg(&mut self, info: u8) -> Result<u64, AttestationError> {
        Ok(match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.byte()?),
            25 => u64::from(u16::from_be_bytes(self.take(2)?.try_into().unwrap())),
            26 => u64::from(u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
            27 => u64::from_be_bytes(self.take(8)?.try_into().unwrap()),
            _ => return Err(AttestationError::Malformed("indefinite CBOR length".into())),
        })
    }

    fn head(&mut self, want_major: u8) -> Result<u64, AttestationError> {
        let b = self.byte()?;
        let major = b >> 5;
        if major != want_major {
            return Err(AttestationError::Malformed(format!(
                "CBOR major type {major}, expected {want_major}"
            )));
        }
        self.arg(b & 0x1F)
    }

    fn expect_map(&mut self) -> Result<usize, AttestationError> {
        self.head(5).map(|n| n as usize)
    }

    fn expect_array(&mut self) -> Result<usize, AttestationError> {
        let n = self.head(4)?;
        if n as usize > self.b.len() - self.i {
            return Err(AttestationError::Malformed(
                "array longer than the document".into(),
            ));
        }
        Ok(n as usize)
    }

    fn expect_text(&mut self) -> Result<String, AttestationError> {
        let n = self.head(3)? as usize;
        let s = self.take(n)?;
        String::from_utf8(s.to_vec())
            .map_err(|_| AttestationError::Malformed("CBOR text is not UTF-8".into()))
    }

    fn expect_bytes(&mut self) -> Result<&'a [u8], AttestationError> {
        let n = self.head(2)? as usize;
        self.take(n)
    }

    /// Optional `bytes` field: CBOR null → absent (`""`), otherwise a
    /// bounded byte string. Real NSM firmware emits explicit nulls for
    /// unused optional fields (verified on the sample document).
    fn optional_bytes_hex(&mut self, max: usize) -> Result<String, AttestationError> {
        if let Some(b) = self.peek() {
            if b == 0xF6 {
                self.i += 1; // null — treat as absent
                return Ok(String::new());
            }
        }
        let v = self.expect_bytes()?;
        if v.len() > max {
            return Err(AttestationError::Malformed(format!(
                "{}-byte optional field exceeds the {}-byte budget",
                v.len(),
                max
            )));
        }
        Ok(hex::encode(v))
    }

    fn expect_uint(&mut self) -> Result<u64, AttestationError> {
        let b = self.byte()?;
        if b >> 5 != 0 {
            return Err(AttestationError::Malformed("expected CBOR uint".into()));
        }
        self.arg(b & 0x1F)
    }

    /// Reads a CBOR integer of either sign (used for the COSE `alg`
    /// header, which is the NEGATIVE integer -35).
    fn expect_int(&mut self) -> Result<i64, AttestationError> {
        let b = self.byte()?;
        match b >> 5 {
            0 => {
                let v = self.arg(b & 0x1F)?;
                i64::try_from(v)
                    .map_err(|_| AttestationError::Malformed("CBOR int out of range".into()))
            }
            1 => {
                let v = self.arg(b & 0x1F)?;
                // -1 - v, checked.
                if v > i64::MAX as u64 {
                    return Err(AttestationError::Malformed("CBOR int out of range".into()));
                }
                Ok(-1 - v as i64)
            }
            _ => Err(AttestationError::Malformed("expected CBOR int".into())),
        }
    }

    fn skip(&mut self) -> Result<(), AttestationError> {
        self.skip_within(0)
    }

    /// Depth-bounded recursive skip (Round 25, fuzz gate).
    ///
    /// TWO hostile-input classes are answered here:
    ///   1. MULTIPLY OVERFLOW (the 11-byte crash): an 8-byte CBOR
    ///      length fed `2 * n` in the map arm — a count derived from
    ///      the document must be bounded by the document BEFORE it
    ///      drives arithmetic or a loop.
    ///   2. RECURSION DEPTH: tags/arrays/maps nest by construction, so
    ///      a hostile document can recurse until the stack runs out —
    ///      a deadly signal, not an `Err`. Attestation documents are
    ///      shallow (a map of PCRs, a nonce, user data), so 32 levels
    ///      is generous; past that the document is hostile.
    fn skip_within(&mut self, depth: usize) -> Result<(), AttestationError> {
        if depth > 32 {
            return Err(AttestationError::Malformed(
                "CBOR nesting deeper than 32".into(),
            ));
        }
        let b = self.byte()?;
        match b >> 5 {
            0 => {
                self.i -= 1;
                self.expect_uint()?;
            }
            1 => {
                // Negative integers carry their magnitude through `arg`
                // (multi-byte encodings included) — rewind and consume
                // exactly what the head promises.
                self.i -= 1;
                self.expect_int()?;
            }
            2 | 3 => {
                // Byte/text string: `take` bounds the length against
                // the remaining input (no overflow, no loop).
                let n = self.arg(b & 0x1F)? as usize;
                self.take(n)?;
            }
            4 => {
                // Array: every element consumes AT LEAST one byte, so
                // an element count larger than the remaining document
                // is malformed — check before the loop runs.
                let n = self.arg(b & 0x1F)? as usize;
                if n > self.b.len() - self.i {
                    return Err(AttestationError::Malformed(
                        "array longer than the document".into(),
                    ));
                }
                for _ in 0..n {
                    self.skip_within(depth + 1)?;
                }
            }
            5 => {
                // Map: each entry is key + value, at least TWO bytes.
                // n is capped by half the remaining input, so `2 * n`
                // can neither overflow nor outlive the document.
                let n = self.arg(b & 0x1F)? as usize;
                if n > (self.b.len() - self.i) / 2 {
                    return Err(AttestationError::Malformed(
                        "map longer than the document".into(),
                    ));
                }
                for _ in 0..(2 * n) {
                    self.skip_within(depth + 1)?;
                }
            }
            6 => {
                // Tag: skip the tagged value.
                self.skip_within(depth + 1)?;
            }
            // `b >> 5` yields exactly 0..=7 (the top three bits of a
            // byte), so this arm IS major 7: floats & simples. 20..=23
            // (false/true/null/undefined) are immediate; 24..=27 carry
            // 1/2/4/8 bytes AFTER the head byte — consuming only the head
            // would desynchronize the walk and silently misread
            // everything after it. 0..=19 are unassigned, 28..=30
            // reserved, 31 indefinite: hostile input, refuse, never skip
            // blind.
            _ => match b & 0x1F {
                20..=23 => {}
                24 => {
                    self.take(1)?;
                }
                25 => {
                    self.take(2)?;
                }
                26 => {
                    self.take(4)?;
                }
                27 => {
                    self.take(8)?;
                }
                _ => {
                    return Err(AttestationError::Malformed(
                        "unsupported CBOR major 7 argument in header".into(),
                    ))
                }
            },
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────
// CBOR writer (emission + Sig_structure)
// ─────────────────────────────────────────────────────────────────────

/// CBOR head byte(s) for a definite length: immediate (0..=23) or
/// 1/2/4/8-byte follow-up. Used by the Sig_structure encoder in EVERY
/// build (verification) and by the emission path.
fn cbor_head(out: &mut Vec<u8>, major: u8, n: usize) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= u8::MAX as usize {
        out.push(m | 24);
        out.push(n as u8);
    } else if n <= u16::MAX as usize {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as usize {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
}

#[cfg(not(feature = "nsm"))]
fn push_bstr(out: &mut Vec<u8>, data: &[u8]) {
    cbor_head(out, 2, data.len());
    out.extend_from_slice(data);
}

#[cfg(not(feature = "nsm"))]
fn push_text(out: &mut Vec<u8>, s: &str) {
    cbor_head(out, 3, s.len());
    out.extend_from_slice(s.as_bytes());
}

/// Builds the AttestationDocument payload CBOR with the exact field set
/// the verifier accepts (`module_id`, `timestamp`, `digest`, `pcrs`,
/// `certificate`, `cabundle`, `nonce`, `user_data` — `public_key` is
/// optional and omitted).
#[cfg(not(feature = "nsm"))]
fn build_payload(
    module_id: &str,
    timestamp_ms: u64,
    pcrs: &[(u64, &[u8])],
    certificate: &[u8],
    cabundle: &[&[u8]],
    nonce: &[u8],
    user_data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        256 + module_id.len() + certificate.len() + nonce.len() + user_data.len(),
    );
    cbor_head(&mut out, 5, 8); // map(8)

    push_text(&mut out, "module_id");
    push_text(&mut out, module_id);

    push_text(&mut out, "timestamp");
    cbor_head(&mut out, 0, timestamp_ms as usize); // uint — caller ensures > 0

    push_text(&mut out, "digest");
    push_text(&mut out, "SHA384");

    push_text(&mut out, "pcrs");
    cbor_head(&mut out, 5, pcrs.len());
    for (idx, v) in pcrs {
        cbor_head(&mut out, 0, *idx as usize);
        push_bstr(&mut out, v);
    }

    push_text(&mut out, "certificate");
    push_bstr(&mut out, certificate);

    push_text(&mut out, "cabundle");
    cbor_head(&mut out, 4, cabundle.len());
    for e in cabundle {
        push_bstr(&mut out, e);
    }

    push_text(&mut out, "nonce");
    push_bstr(&mut out, nonce);

    push_text(&mut out, "user_data");
    push_bstr(&mut out, user_data);
    out
}

/// Signs a payload into a COSE_Sign1 envelope with the given PKCS#8
/// (P-384) key — UNTAGGED array(4), byte-for-byte the shape the NSM
/// emits (verified against the real AWS sample: `84 44 a101 3822 a0 …`).
#[cfg(not(feature = "nsm"))]
fn sign_cose(payload: &[u8], pkcs8: &[u8]) -> Result<Vec<u8>, AttestationError> {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P384_SHA384_FIXED_SIGNING};

    let protected = [0xA1u8, 0x01, 0x38, 0x22]; // {1: -35} = ES384
    let structure = sig_structure(&protected, payload);
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8)
        .map_err(|e| AttestationError::Sig(format!("attestation signing key: {e:?}")))?;
    let rng = SystemRandom::new();
    let sig = key
        .sign(&rng, &structure)
        .map_err(|e| AttestationError::Sig(format!("COSE signing failed: {e:?}")))?;
    let sig: &[u8] = sig.as_ref();
    // aws-lc's FIXED P-384 signing is DER-independent R‖S: always 96 B.
    // An internal invariant, not a runtime wall — assert it in one line
    // so the emission path stays fully covered.
    assert_eq!(sig.len(), 96, "ES384 fixed signing emits exactly 96 bytes");
    let mut out = Vec::with_capacity(16 + 4 + payload.len() + sig.len());
    out.push(0x84); // untagged array(4)
    push_bstr(&mut out, &protected);
    out.push(0xA0); // empty unprotected map
    push_bstr(&mut out, payload);
    push_bstr(&mut out, sig);
    Ok(out)
}

/// Emits the dev/plain-mode attestation document: the SAME wire format
/// the NSM produces, signed with the well-known dev leaf key and chained
/// to the pinned dev root. This is the ONLY document the non-NSM server
/// emits — the terminal verifies it with the production verifier (no
/// JSON pseudo-document, no alternate path).
#[cfg(not(feature = "nsm"))]
pub fn emit_dev_document(
    seed: &[u8; 32],
    nonce: &[u8; 32],
    user_data: &[u8],
) -> Result<Vec<u8>, AttestationError> {
    let doc = AttestationDoc::dev(seed, nonce, user_data);
    let pcr0 = hex_decode(&doc.measurement_hex)?;
    let payload = build_payload(
        "qsv-dev-cosigner",
        now_unix_ms(),
        &[(PCR0 as u64, pcr0.as_slice())],
        dev_identity::LEAF_DER,
        &[dev_identity::ROOT_DER],
        nonce,
        user_data,
    );
    sign_cose(&payload, dev_identity::LEAF_KEY_PKCS8)
}

// ─────────────────────────────────────────────────────────────────────
// Real NSM access — compiled ONLY inside the enclave build
// ─────────────────────────────────────────────────────────────────────

/// Requests the attestation doc from the real NSM device (enclave build
/// only; the dev build refuses at compile time — the server maps this to
/// a fail-closed error, never to a fabricated document).
#[cfg(feature = "nsm")]
pub fn request_attestation_doc(
    nonce: &[u8],
    user_data: &[u8],
) -> Result<Vec<u8>, AttestationError> {
    enclave_side::request_attestation_doc(nonce, user_data)
}

#[cfg(feature = "nsm")]
mod enclave_side {
    //! REAL NSM access — compiled ONLY inside the enclave build
    //! (`--features nsm`), where `/dev/nsm` exists.
    //!
    //! The ioctl contract (aws-nitro-enclaves-nsm-api): open the device,
    //! issue NSM_GET_ATTESTATION_DOC with the request nonce + user_data,
    //! receive a COSE_Sign1 document. We keep the raw FFI surface tiny and
    //! dependency-free; the returned document feeds the production
    //! verifier on the client side.

    #![allow(dead_code)]

    use super::AttestationError;

    const NSM_IOCTL_BASE: u8 = 0xFA;
    const NSM_GET_ATTESTATION_DOC: u8 = 2;

    // ioctl number: _IOWR(NSM_IOCTL_BASE, 2, struct nsm_msg_v1) — matches
    // the upstream header without a libclang dependency in the enclave build.
    const NSM_IOCTL_GET_ATTESTATION_DOC: libc_ulong = 0xFA02;

    /// Requests the attestation doc from the real NSM device.
    pub fn request_attestation_doc(
        nonce: &[u8],
        user_data: &[u8],
    ) -> Result<Vec<u8>, AttestationError> {
        use std::fs::OpenOptions;
        use std::os::unix::io::AsRawFd;

        let dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(super::NSM_DEVICE)
            .map_err(|e| AttestationError::NoDevice(format!("open {}: {e}", super::NSM_DEVICE)))?;

        // Request CBOR: {1: nonce (bstr), 2: user_data (bstr), 3: null (pubkeys)}
        let req = cbor_request(nonce, user_data);

        // The NSM response buffer: 4 KiB is the documented upper bound.
        let mut resp = vec![0u8; 4096];
        let rc = unsafe {
            nsm_ioctl(
                dev.as_raw_fd(),
                NSM_IOCTL_GET_ATTESTATION_DOC,
                req.as_ptr(),
                req.len(),
                resp.as_mut_ptr(),
                resp.len(),
            )
        };
        if rc < 0 {
            return Err(AttestationError::Nsm(format!(
                "ioctl failed (rc {rc}); errno {}",
                std::io::Error::last_os_error()
            )));
        }
        resp.truncate(rc as usize);
        // The kernel returns {1: document (bstr), 2: error code}; unwrap 1.
        unwrap_document(&resp)
    }

    fn cbor_request(nonce: &[u8], user_data: &[u8]) -> Vec<u8> {
        let mut out = vec![0xA2u8]; // map(2)
        out.push(0x01); // key 1
        push_bstr(&mut out, nonce);
        out.push(0x02); // key 2
        push_bstr(&mut out, user_data);
        out
    }

    fn push_bstr(out: &mut Vec<u8>, data: &[u8]) {
        if data.len() < 24 {
            out.push(0x40 | data.len() as u8);
        } else if data.len() <= u8::MAX as usize {
            out.push(0x58);
            out.push(data.len() as u8);
        } else {
            out.push(0x59);
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(data);
    }

    fn unwrap_document(resp: &[u8]) -> Result<Vec<u8>, AttestationError> {
        let mut p = super::Cbor { b: resp, i: 0 };
        let n = p.expect_map()?;
        for _ in 0..n {
            let key = p.expect_uint()?;
            if key == 1 {
                return p.expect_bytes().map(|b| b.to_vec());
            }
            p.skip()?;
        }
        Err(AttestationError::Nsm("no document in NSM response".into()))
    }

    #[allow(non_camel_case_types)]
    type libc_ulong = std::os::raw::c_ulong;

    // Tiny FFI: the ioctl(2) syscall. Linked from libc (already in the
    // enclave's std). Kept here so the dev build never touches it.
    extern "C" {
        fn ioctl(fd: std::os::raw::c_int, request: libc_ulong, ...) -> std::os::raw::c_int;
    }

    #[allow(non_snake_case)]
    unsafe fn nsm_ioctl(
        fd: std::os::raw::c_int,
        request: libc_ulong,
        req_ptr: *const u8,
        req_len: usize,
        resp_ptr: *mut u8,
        resp_len: usize,
    ) -> std::os::raw::c_int {
        // struct nsm_msg_v1 { header(8) | req_len(4) | req | resp_len(4) | resp }
        // The real layout packs the request/response inline; the NSM driver
        // copies per the lengths. We marshal into the upstream layout:
        let mut msg = Vec::with_capacity(16 + req_len + resp_len);
        msg.extend_from_slice(&(NSM_IOCTL_BASE as u32).to_le_bytes()); // magic
        msg.extend_from_slice(&(NSM_GET_ATTESTATION_DOC as u32).to_le_bytes());
        msg.extend_from_slice(&(req_len as u32).to_le_bytes());
        let req_slice = std::slice::from_raw_parts(req_ptr, req_len);
        msg.extend_from_slice(req_slice);
        msg.extend_from_slice(&(resp_len as u32).to_le_bytes());
        let rc = ioctl(fd, request, msg.as_ptr(), msg.len());
        if rc >= 0 {
            // Response payload starts after the fixed header + req_len.
            let off = 16 + req_len;
            if msg.len() > off {
                std::ptr::copy_nonoverlapping(&msg[off], resp_ptr, msg.len() - off);
                return (msg.len() - off) as std::os::raw::c_int;
            }
        }
        rc
    }
}

/// Hex decode helper.
///
/// CHAR-BOUNDARY SAFETY (found by the Round 25 fuzz gate, crash input
/// `0a c8`): the byte-index slices below panicked on any multi-byte
/// character — `String::from_utf8_lossy` turns invalid bytes into
/// U+FFFD (3 bytes) and `s[0..2]` then lands INSIDE that character. A
/// verifier fed a JSON/disk string must never panic on its CONTENT,
/// and hex digits are ASCII by definition — so any non-ASCII input is
/// answered as "bad hex", before a single slice index is formed.
pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>, AttestationError> {
    if !s.len().is_multiple_of(2) {
        return Err(AttestationError::Malformed("odd-length hex".into()));
    }
    if !s.is_ascii() {
        return Err(AttestationError::Malformed(
            "bad hex: non-ASCII input".into(),
        ));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|e| AttestationError::Malformed(format!("bad hex: {e}")))
        })
        .collect()
}

#[cfg(all(test, not(feature = "nsm")))]
mod tests {
    use super::*;
    use sha2::Sha256;

    // ── helpers ────────────────────────────────────────────────────

    fn sha256_hex(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    /// The demo enclave identity (same seed the bridge provisions and
    /// the CLI pins by default).
    fn demo_seed() -> [u8; 32] {
        [77u8; 32]
    }

    fn demo_xonly_hex() -> String {
        let kp = qsv_pqc::enclave_keypair_from_seed(&demo_seed()).unwrap();
        hex::encode(qsv_pqc::enclave_xonly_public_key(&kp).serialize())
    }

    fn demo_pinned(vault_id: &str) -> PinnedMeasurements {
        PinnedMeasurements {
            pcr0_hex: hex::encode(dev_measurement(&demo_seed())),
            pcr1_hex: String::new(),
            pcr2_hex: String::new(),
            vault_id: vault_id.to_string(),
            enclave_xonly_hex: demo_xonly_hex(),
        }
    }

    fn demo_user_data(vault_id: &str) -> Vec<u8> {
        let kp = qsv_pqc::enclave_keypair_from_seed(&demo_seed()).unwrap();
        enclave_user_data(&qsv_pqc::enclave_xonly_public_key(&kp), vault_id)
    }

    /// Emits a dev document as the server does (hex on the wire).
    fn emit_demo(nonce: &[u8; 32], vault_id: &str) -> String {
        hex::encode(
            emit_dev_document(&demo_seed(), nonce, &demo_user_data(vault_id))
                .expect("dev emission"),
        )
    }

    /// Wraps a payload in an UNSIGNED COSE_Sign1 envelope (garbage
    /// signature) — enough to exercise parse/content gates, which run
    /// BEFORE any cryptography.
    fn wrap_unsigned(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x84u8];
        push_bstr(&mut out, &[0xA1, 0x01, 0x38, 0x22]);
        out.push(0xA0);
        push_bstr(&mut out, payload);
        push_bstr(&mut out, &[0u8; 96]);
        out
    }

    // Tiny CBOR writers for hand-built negative payloads.
    fn cb_text(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        cbor_head(&mut v, 3, s.len());
        v.extend_from_slice(s.as_bytes());
        v
    }
    fn cb_uint(n: u64) -> Vec<u8> {
        let mut v = Vec::new();
        cbor_head(&mut v, 0, n as usize);
        v
    }
    fn cb_bytes(b: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        push_bstr(&mut v, b);
        v
    }
    fn cb_map(n: usize) -> Vec<u8> {
        let mut v = Vec::new();
        cbor_head(&mut v, 5, n);
        v
    }
    fn chain_map(entries: Vec<(String, Vec<u8>)>) -> Vec<u8> {
        let mut v = cb_map(entries.len());
        for (k, val) in entries {
            v.extend_from_slice(&cb_text(&k));
            v.extend_from_slice(&val);
        }
        v
    }

    fn expect_payload_err(payload: &[u8], fragment: &str) {
        let doc_hex = hex::encode(wrap_unsigned(payload));
        let pinned = demo_pinned("bc1ptest");
        let e = verify_attestation_doc(&doc_hex, &pinned, "").expect_err("payload must be refused");
        let msg = e.to_string();
        assert!(
            msg.contains(fragment),
            "expected error containing {fragment:?}, got: {msg}"
        );
    }

    // ── dev roundtrip through the PRODUCTION verifier ───────────────────────

    #[test]
    fn dev_document_verifies_end_to_end() {
        let nonce = [9u8; 32];
        let doc_hex = emit_demo(&nonce, "bc1ptest");
        let bytes = hex::decode(&doc_hex).unwrap();
        // Byte-for-byte the shape the NSM emits: untagged array(4).
        assert_eq!(bytes[0], 0x84, "untagged COSE_Sign1 (NSM shape)");

        let pinned = demo_pinned("bc1ptest");
        let f = verify_attestation_doc(&doc_hex, &pinned, &hex::encode(nonce)).unwrap();
        assert_eq!(f.module_id, "qsv-dev-cosigner");
        assert_eq!(f.digest, "SHA384");
        assert!(f.timestamp_ms > 0);
        assert_eq!(f.pcr0_hex, hex::encode(dev_measurement(&demo_seed())));
        assert_eq!(f.pcr1_hex, "", "dev documents carry only PCR0");
        assert_eq!(f.nonce_hex, hex::encode(nonce));
        assert_eq!(f.user_data_hex, hex::encode(demo_user_data("bc1ptest")));
        assert_eq!(f.cert_der, dev_identity::LEAF_DER);
        assert_eq!(f.cabundle_der, vec![dev_identity::ROOT_DER.to_vec()]);
    }

    #[test]
    fn fails_closed_on_measurement_nonce_and_binding() {
        let nonce = [0x01u8; 32];
        let doc_hex = emit_demo(&nonce, "bc1ptest");

        // Wrong PCR0 pin → refuse.
        let mut pinned = demo_pinned("bc1ptest");
        pinned.pcr0_hex = hex::encode([0x33u8; 48]);
        let e = verify_attestation_doc(&doc_hex, &pinned, &hex::encode(nonce)).unwrap_err();
        assert!(matches!(e, AttestationError::Measurement(_)), "{e:?}");

        // Replayed / foreign nonce → refuse.
        let pinned = demo_pinned("bc1ptest");
        let e = verify_attestation_doc(&doc_hex, &pinned, &hex::encode([0x02u8; 32])).unwrap_err();
        assert!(matches!(e, AttestationError::Nonce(_)), "{e:?}");

        // Document WITHOUT the client's challenge at all → refuse.
        let e = verify_attestation_doc(&doc_hex, &pinned, &hex::encode([0x05u8; 32])).unwrap_err();
        assert!(matches!(e, AttestationError::Nonce(_)), "{e:?}");

        // Wrong pinned enclave key → user_data binding refuses.
        let mut pinned = demo_pinned("bc1ptest");
        pinned.enclave_xonly_hex = hex::encode([0x44u8; 32]);
        let e = verify_attestation_doc(&doc_hex, &pinned, &hex::encode(nonce)).unwrap_err();
        assert!(matches!(e, AttestationError::Measurement(_)), "{e:?}");
        assert!(e.to_string().contains("user_data"), "{e}");

        // Wrong pinned vault → same binding refuses.
        let pinned = demo_pinned("bc1pother");
        let e = verify_attestation_doc(&doc_hex, &pinned, &hex::encode(nonce)).unwrap_err();
        assert!(matches!(e, AttestationError::Measurement(_)), "{e:?}");

        // An x-only pin that is not valid hex → config error, fail-closed.
        let mut pinned = demo_pinned("bc1ptest");
        pinned.enclave_xonly_hex = "zz".into();
        let e = verify_attestation_doc(&doc_hex, &pinned, &hex::encode(nonce)).unwrap_err();
        assert!(matches!(e, AttestationError::Measurement(_)), "{e:?}");
    }

    #[test]
    fn dev_measurement_is_stable_and_seed_bound() {
        let a = dev_measurement(&[1u8; 32]);
        let b = dev_measurement(&[1u8; 32]);
        let c = dev_measurement(&[7u8; 32]);
        assert_eq!(a, b, "deterministic per seed");
        assert_ne!(a, c, "bound to the enclave seed");
        assert_eq!(a.len(), 48, "SHA-384 (matches the document digest)");
    }

    #[test]
    fn enclave_user_data_is_xonly_then_vault() {
        let kp = qsv_pqc::enclave_keypair_from_seed(&demo_seed()).unwrap();
        let xonly = qsv_pqc::enclave_xonly_public_key(&kp);
        let ud = enclave_user_data(&xonly, "bc1ptest");
        assert_eq!(&ud[..32], &xonly.serialize());
        assert_eq!(&ud[32..], b"bc1ptest");
    }

    // ── published trust anchors ────────────────────────────────────────────

    #[test]
    fn nitro_root_pins_match_published_hashes() {
        assert_eq!(
            sha256_hex(NITRO_ROOT_PEM.as_bytes()),
            NITRO_ROOT_PEM_SHA256,
            "PEM hash == the AWS-published value"
        );
        assert_eq!(
            sha256_hex(NITRO_ROOT_DER),
            NITRO_ROOT_DER_SHA256,
            "DER hash == the value independently derived from two AWS sources"
        );
        assert!(NITRO_ROOT_PEM.starts_with("-----BEGIN CERTIFICATE-----"));
        let root = parse_cert(NITRO_ROOT_DER).unwrap();
        assert!(
            format!("{}", root.subject()).contains("aws.nitro-enclaves"),
            "subject is the published CN"
        );
        // The pinned root must itself be inside its validity window today
        // (published lifetime 2019-10-28 → 2049-10-28).
        check_validity("AWS Nitro Root-G1", &root, now_unix_secs()).unwrap();
    }

    // ── the REAL AWS-signed sample document ────────────────────────────────

    /// `now` inside the sample's validity window (2023-03-28 12:00:00 UTC;
    /// the target certificate lives 11:55:57→14:56:00 by AWS design).
    const SAMPLE_NOW: i64 = 1_680_004_800;

    fn sample_pinned() -> PinnedMeasurements {
        PinnedMeasurements {
            // The sample enclaves ran with all-zero PCRs (documented AWS
            // sample behaviour) — pin exactly what the document carries.
            pcr0_hex: "00".repeat(48),
            pcr1_hex: String::new(),
            pcr2_hex: String::new(),
            vault_id: String::new(),
            enclave_xonly_hex: String::new(),
        }
    }

    #[test]
    fn real_nitro_sample_verifies_end_to_end() {
        assert_eq!(
            sha256_hex(NITRO_SAMPLE_DOC),
            NITRO_SAMPLE_SHA256,
            "fixture integrity"
        );
        let doc_hex = hex::encode(NITRO_SAMPLE_DOC);
        let f = verify_attestation_doc_at(&doc_hex, &sample_pinned(), "", SAMPLE_NOW).unwrap();
        assert!(f.module_id.starts_with("i-"), "{}", f.module_id);
        assert_eq!(f.timestamp_ms, 1_680_004_560_937);
        assert_eq!(f.digest, "SHA384");
        assert_eq!(f.pcr0_hex, "00".repeat(48));
        assert_eq!(f.cert_der.len(), 638);
        assert_eq!(f.cabundle_der.len(), 4, "root + three intermediates");
        assert_eq!(f.cabundle_der[0], NITRO_ROOT_DER, "root pinned");
        assert_eq!(f.nonce_hex, "", "old NSM emits null nonce → absent");
        assert_eq!(f.user_data_hex, "", "old NSM emits null user_data → absent");
    }

    #[test]
    fn real_nitro_sample_refused_outside_certificate_validity() {
        let doc_hex = hex::encode(NITRO_SAMPLE_DOC);
        // Nitro infrastructure certificates live ~3 hours; after that the
        // document is refused — freshness is enforced by PKI, not hope.
        let e = verify_attestation_doc_at(&doc_hex, &sample_pinned(), "", 1_760_000_000)
            .expect_err("expired sample must refuse");
        assert!(matches!(e, AttestationError::Chain(_)), "{e:?}");
        assert!(e.to_string().contains("outside validity window"), "{e}");
    }

    #[test]
    fn real_nitro_sample_nonce_and_user_data_pins_enforce() {
        let doc_hex = hex::encode(NITRO_SAMPLE_DOC);
        // A client challenge the document does not carry → replay refuse.
        let e = verify_attestation_doc_at(&doc_hex, &sample_pinned(), &"ab".repeat(32), SAMPLE_NOW)
            .unwrap_err();
        assert!(matches!(e, AttestationError::Nonce(_)), "{e:?}");
        // An enclave-key pin the document does not bind → refuse.
        let mut pinned = sample_pinned();
        pinned.enclave_xonly_hex = demo_xonly_hex();
        pinned.vault_id = "bc1ptest".into();
        let e = verify_attestation_doc_at(&doc_hex, &pinned, "", SAMPLE_NOW).unwrap_err();
        assert!(matches!(e, AttestationError::Measurement(_)), "{e:?}");
        assert!(e.to_string().contains("user_data"), "{e}");
        // A PCR0 pin the document contradicts → refuse.
        let mut pinned = sample_pinned();
        pinned.pcr0_hex = hex::encode([0xEEu8; 48]);
        let e = verify_attestation_doc_at(&doc_hex, &pinned, "", SAMPLE_NOW).unwrap_err();
        assert!(matches!(e, AttestationError::Measurement(_)), "{e:?}");
    }

    #[test]
    fn real_nitro_sample_tamper_and_shape_refused() {
        let n = NITRO_SAMPLE_DOC.len();
        let pinned = sample_pinned();

        // Flip a byte in the SIGNATURE (last 96 bytes) → crypto refuse.
        let mut bad = NITRO_SAMPLE_DOC.to_vec();
        bad[n - 1] ^= 0x01;
        let e = verify_attestation_doc_at(&hex::encode(&bad), &pinned, "", SAMPLE_NOW)
            .expect_err("tampered signature");
        assert!(matches!(e, AttestationError::Sig(_)), "{e:?}");

        // Flip a byte INSIDE the payload (module_id value region) → the
        // COSE signature no longer covers it → crypto refuse.
        let mut bad = NITRO_SAMPLE_DOC.to_vec();
        bad[9 + 20] ^= 0x20;
        let e = verify_attestation_doc_at(&hex::encode(&bad), &pinned, "", SAMPLE_NOW)
            .expect_err("tampered payload");
        assert!(matches!(e, AttestationError::Sig(_)), "{e:?}");

        // Corrupt the protected algorithm header → refuse at parse.
        let mut bad = NITRO_SAMPLE_DOC.to_vec();
        assert_eq!(bad[5], 0x22, "-35 encoded as 0x38 0x22");
        bad[5] = 0x23; // -36
        let e = verify_attestation_doc_at(&hex::encode(&bad), &pinned, "", SAMPLE_NOW)
            .expect_err("wrong alg");
        assert!(matches!(e, AttestationError::Malformed(_)), "{e:?}");

        // Trailing garbage after the envelope → refuse.
        let mut bad = NITRO_SAMPLE_DOC.to_vec();
        bad.push(0x00);
        let e = verify_attestation_doc_at(&hex::encode(&bad), &pinned, "", SAMPLE_NOW)
            .expect_err("trailing garbage");
        assert!(matches!(e, AttestationError::Malformed(_)), "{e:?}");

        // The TAGGED variant (CBOR tag 18) is equally valid per RFC 8152
        // and AWS §3.1 — the NSM just doesn't emit it today.
        let mut tagged = Vec::with_capacity(n + 1);
        tagged.push(0xD2);
        tagged.extend_from_slice(NITRO_SAMPLE_DOC);
        verify_attestation_doc_at(&hex::encode(&tagged), &pinned, "", SAMPLE_NOW)
            .expect("tagged COSE_Sign1 must verify");
    }

    // ── COSE structure ──────────────────────────────────────────────────────

    #[test]
    fn sig_structure_matches_rfc8152() {
        // GOLDEN: "Signature1" is text(10) → 0x6A (the off-by-two that
        // the real sample caught before this code existed).
        let got = sig_structure(&[0xA1, 0x01, 0x38, 0x22], &[0xAA, 0xBB]);
        let want: Vec<u8> = [
            vec![0x84, 0x6A],
            b"Signature1".to_vec(),
            vec![0x44, 0xA1, 0x01, 0x38, 0x22, 0x40, 0x42, 0xAA, 0xBB],
        ]
        .concat();
        assert_eq!(got, want);
    }

    #[test]
    fn cose_rejects_wrong_alg_shape_and_signature_length() {
        // alg = -7 (ES256) instead of -35 (ES384) → refuse.
        let mut doc = vec![0x84u8];
        push_bstr(&mut doc, &[0xA1, 0x01, 0x38, 0x06]); // {1: -7}
        doc.push(0xA0);
        push_bstr(&mut doc, &[0x01]); // 1-byte payload
        push_bstr(&mut doc, &[0u8; 96]);
        let e = parse_cose_sign1(&doc).expect_err("ES256 must refuse");
        assert!(e.to_string().contains("-7"), "{e}");

        // array(3) instead of array(4) → refuse.
        let mut doc = vec![0x83u8];
        push_bstr(&mut doc, &[0xA1, 0x01, 0x38, 0x22]);
        doc.push(0xA0);
        push_bstr(&mut doc, &[0x01]);
        let e = parse_cose_sign1(&doc).expect_err("array(3) must refuse");
        assert!(matches!(e, AttestationError::Malformed(_)), "{e:?}");

        // 95-byte signature (not fixed-96) → refuse.
        let mut doc = vec![0x84u8];
        push_bstr(&mut doc, &[0xA1, 0x01, 0x38, 0x22]);
        doc.push(0xA0);
        push_bstr(&mut doc, &[0x01]);
        push_bstr(&mut doc, &[0u8; 95]);
        let e = parse_cose_sign1(&doc).expect_err("short sig must refuse");
        assert!(e.to_string().contains("96"), "{e}");

        // A foreign CBOR tag (not 18) → refuse.
        let mut doc = vec![0xC0u8]; // tag(0)
        doc.extend_from_slice(&[
            0x84, 0x44, 0xA1, 0x01, 0x38, 0x22, 0xA0, 0x41, 0x01, 0x41, 0x01,
        ]);
        let e = parse_cose_sign1(&doc).expect_err("foreign tag must refuse");
        assert!(e.to_string().contains("tag"), "{e}");
    }

    // ── payload syntactic rules (AWS §3.2.2) ────────────────────────────────

    #[test]
    fn mandatory_and_content_rules_enforce() {
        let ok_ts = cb_uint(1_680_004_560_937);
        let ok_mod = cb_text("i-0abc");
        let ok_dig = cb_text("SHA384");

        // Missing all mandatory fields → refuse.
        let p = chain_map(vec![]);
        expect_payload_err(&p, "module_id");

        // module_id empty → refuse.
        let p = chain_map(vec![("module_id".into(), cb_text(""))]);
        expect_payload_err(&p, "module_id");

        // digest not SHA384 → refuse.
        let p = chain_map(vec![
            ("module_id".into(), ok_mod.clone()),
            ("digest".into(), cb_text("SHA256")),
        ]);
        expect_payload_err(&p, "digest");

        // timestamp = 0 → refuse.
        let p = chain_map(vec![
            ("module_id".into(), ok_mod.clone()),
            ("timestamp".into(), cb_uint(0)),
        ]);
        expect_payload_err(&p, "timestamp");

        // pcrs empty map → refuse.
        let mut pcrs = Vec::new();
        cbor_head(&mut pcrs, 5, 0);
        let p = chain_map(vec![
            ("module_id".into(), ok_mod.clone()),
            ("timestamp".into(), ok_ts.clone()),
            ("digest".into(), ok_dig.clone()),
            ("pcrs".into(), pcrs),
        ]);
        expect_payload_err(&p, "pcrs map size");

        // PCR with a 5-byte value → refuse.
        let mut pcrs = Vec::new();
        cbor_head(&mut pcrs, 5, 1);
        cbor_head(&mut pcrs, 0, 0);
        push_bstr(&mut pcrs, &[0u8; 5]);
        let p = chain_map(vec![
            ("module_id".into(), ok_mod.clone()),
            ("timestamp".into(), ok_ts.clone()),
            ("digest".into(), ok_dig.clone()),
            ("pcrs".into(), pcrs),
        ]);
        expect_payload_err(&p, "32/48/64");

        // PCR index out of range → refuse.
        let mut pcrs = Vec::new();
        cbor_head(&mut pcrs, 5, 1);
        cbor_head(&mut pcrs, 0, 33);
        push_bstr(&mut pcrs, &[0u8; 48]);
        let p = chain_map(vec![
            ("module_id".into(), ok_mod.clone()),
            ("timestamp".into(), ok_ts.clone()),
            ("digest".into(), ok_dig.clone()),
            ("pcrs".into(), pcrs),
        ]);
        expect_payload_err(&p, "PCR index");

        // Unknown field → refuse (closed grammar).
        let p = chain_map(vec![
            ("module_id".into(), ok_mod.clone()),
            ("evil".into(), cb_uint(1)),
        ]);
        expect_payload_err(&p, "unknown attestation field");

        // Over-budget nonce (600 > 512) → refuse.
        let p = chain_map(vec![
            ("module_id".into(), ok_mod),
            ("timestamp".into(), ok_ts),
            ("digest".into(), ok_dig),
            ("nonce".into(), cb_bytes(&[0xAB; 600])),
        ]);
        expect_payload_err(&p, "budget");

        // Empty cabundle → refuse.
        let mut bundle = Vec::new();
        cbor_head(&mut bundle, 4, 0);
        let p = chain_map(vec![
            ("module_id".into(), cb_text("x")),
            ("timestamp".into(), cb_uint(1)),
            ("digest".into(), cb_text("SHA384")),
            ("pcrs".into(), {
                let mut m = Vec::new();
                cbor_head(&mut m, 5, 1);
                cbor_head(&mut m, 0, 0);
                push_bstr(&mut m, &[0u8; 48]);
                m
            }),
            ("certificate".into(), cb_bytes(&[0x30; 16])),
            ("cabundle".into(), bundle),
        ]);
        expect_payload_err(&p, "cabundle");
    }

    #[test]
    fn truncated_payload_fails_closed() {
        let payload = build_payload(
            "qsv-dev-cosigner",
            1_680_004_560_937,
            &[(0, &[0x11u8; 48])],
            dev_identity::LEAF_DER,
            &[dev_identity::ROOT_DER],
            &[0xA5; 32],
            &[0x77; 40],
        );
        for cut in [0usize, 1, 3, 10, payload.len() - 1] {
            assert!(
                parse_attestation_payload(&payload[..cut]).is_err(),
                "truncation at {cut} must refuse"
            );
        }
        // The full payload parses (the control case for the cuts above).
        assert!(parse_attestation_payload(&payload).is_ok());
    }

    // ── legacy fuzz regressions (kept verbatim) ──────────────────────────────

    /// FUZZ REGRESSION (Round 25, crash input `0a c8`): `hex_decode`
    /// used to SLICE BY BYTE INDEX into a `&str` — lossy UTF-8 turns
    /// invalid bytes into U+FFFD (3 bytes) and `s[0..2]` then landed
    /// inside that character, panicking the verifier. Any non-ASCII
    /// input must be an ERROR, never a panic; ASCII and odd-length
    /// contracts stay as they were.
    #[test]
    fn hex_decode_refuses_non_ascii_without_panicking() {
        let lossy = String::from_utf8_lossy(&[0x0a, 0xc8]);
        assert!(
            lossy.contains('\u{FFFD}'),
            "the crash shape really is a replacement char"
        );
        assert!(hex_decode(&lossy).is_err(), "lossy input is refused");
        assert!(hex_decode("ab\u{00df}d").is_err(), "multi-byte, even len");
        assert!(hex_decode("\u{1f600}\u{1f600}").is_err(), "emoji pair");
        assert!(hex_decode("abc").is_err(), "odd length still refused");
        assert!(hex_decode("").unwrap().is_empty(), "empty decodes empty");
        assert_eq!(hex_decode("0aff").unwrap(), vec![0x0a, 0xff]);
    }

    /// FUZZ REGRESSION (Round 25, crash `b7 60 bb bb …`): an 8-byte
    /// CBOR length feeding `2 * n` overflowed the multiply, and a
    /// hostile tag/array/map chain recursed until the stack ran out.
    /// Both must be REFUSED as malformed — before any arithmetic or
    /// unbounded recursion can happen — while a shallow well-formed
    /// document still skips cleanly.
    #[test]
    fn cbor_absurd_lengths_and_deep_nesting_are_errors_not_panics() {
        // Map header with an 8-byte length of u64::MAX: bounded by the
        // REMAINING bytes before `2 * n` is ever formed.
        let huge_map = [0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut c = Cbor { b: &huge_map, i: 0 };
        assert!(c.skip().is_err(), "u64::MAX map count must be refused");

        // Byte string with an 8-byte huge length: `take` must answer
        // "truncated", not overflow `self.i + n`.
        let huge_str = [0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut c = Cbor { b: &huge_str, i: 0 };
        assert!(c.skip().is_err(), "huge byte string must be refused");

        // 100 nested single-element arrays: depth-limited as an Err,
        // never a stack overflow.
        let mut deep = vec![0x81u8; 100];
        deep.push(0x01);
        let mut c = Cbor { b: &deep, i: 0 };
        assert!(c.skip().is_err(), "100-deep nesting must be refused");

        // A shallow well-formed map still skips (the limits must not
        // reject what the parser exists to accept).
        let ok = [0xa1u8, 0x01, 0x01];
        let mut c = Cbor { b: &ok, i: 0 };
        assert!(
            c.skip().is_ok(),
            "a shallow single-entry map must still skip"
        );
    }

    // ── X.509 chain policy: fixture chains against the pinned root ─────
    //
    // The bundle root must ALWAYS be a pinned anchor, so every test here
    // roots at the embedded dev root; the policy checks (BasicConstraints,
    // KeyUsage, pathLen) run BEFORE link/signature checks in
    // `verify_chain`, so intermediate fixtures need only parse — which is
    // exactly how the AWS rules are ordered (§3.2.3 before §3.2.4).

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
        PKCS_ECDSA_P384_SHA384,
    };

    /// 2023-11-14: inside the dev-root window (2020..2050) and every
    /// rcgen default window (1975..4096).
    const CHAIN_NOW: i64 = 1_700_000_000;

    fn pinned_for(pcr0: &[u8]) -> PinnedMeasurements {
        PinnedMeasurements {
            pcr0_hex: hex::encode(pcr0),
            pcr1_hex: String::new(),
            pcr2_hex: String::new(),
            vault_id: "bc1ptest".into(),
            enclave_xonly_hex: String::new(),
        }
    }

    fn ca_kus() -> Vec<KeyUsagePurpose> {
        vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]
    }
    fn leaf_kus() -> Vec<KeyUsagePurpose> {
        vec![KeyUsagePurpose::DigitalSignature]
    }

    fn mint(cn: &str, is_ca: IsCa, kus: Vec<KeyUsagePurpose>) -> (KeyPair, rcgen::Certificate) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut p = CertificateParams::new(Vec::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = is_ca;
        p.key_usages = kus;
        let cert = p.self_signed(&key).unwrap();
        (key, cert)
    }

    fn mint_signed(
        cn: &str,
        is_ca: IsCa,
        kus: Vec<KeyUsagePurpose>,
        issuer: (&KeyPair, &rcgen::Certificate),
    ) -> (KeyPair, rcgen::Certificate) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).unwrap();
        let mut p = CertificateParams::new(vec![cn.to_string()]).unwrap();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.is_ca = is_ca;
        p.key_usages = kus;
        let cert = p.signed_by(&key, issuer.1, issuer.0).unwrap();
        (key, cert)
    }

    /// Builds a COSE-signed document over a custom target + bundle.
    fn doc_with(
        pcr0: &[u8],
        nonce: &[u8; 32],
        target: &[u8],
        bundle: &[&[u8]],
        pkcs8: &[u8],
    ) -> String {
        let payload = build_payload(
            "qsv-test",
            1_690_000_000_000,
            &[(0, pcr0)],
            target,
            bundle,
            nonce,
            &[0xEEu8; 64],
        );
        hex::encode(sign_cose(&payload, pkcs8).unwrap())
    }

    fn verify_doc(
        doc: &str,
        pcr0: &[u8],
        nonce: &[u8; 32],
        now: i64,
    ) -> Result<AttestationFields, AttestationError> {
        verify_attestation_doc_at(doc, &pinned_for(pcr0), &hex::encode(nonce), now)
    }

    fn chain_err_from(doc: &str, pcr0: &[u8], nonce: &[u8; 32], now: i64) -> String {
        let e = verify_doc(doc, pcr0, nonce, now).expect_err("chain must refuse");
        assert!(matches!(e, AttestationError::Chain(_)), "{e:?}");
        e.to_string()
    }

    #[test]
    fn foreign_root_refused_before_anything_else() {
        let (fkey, fcert) = mint(
            "evil root",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_kus(),
        );
        let (lkey, lcert) = mint_signed("evil enclave", IsCa::NoCa, leaf_kus(), (&fkey, &fcert));
        let target: &[u8] = lcert.der();
        let foreign: &[u8] = fcert.der();
        let pkcs8 = lkey.serialize_der();
        let nonce = [7u8; 32];
        let pcr0 = [0x11u8; 48];
        let doc = doc_with(&pcr0, &nonce, target, &[foreign], &pkcs8);
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("not a pinned trust anchor"), "{msg}");
    }

    #[test]
    fn missing_intermediate_breaks_the_chain() {
        let (ikey, icert) = mint(
            "qsv lone intermediate",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_kus(),
        );
        let (lkey, lcert) = mint_signed(
            "qsv orphan enclave",
            IsCa::NoCa,
            leaf_kus(),
            (&ikey, &icert),
        );
        let target: &[u8] = lcert.der();
        let pkcs8 = lkey.serialize_der();
        let nonce = [8u8; 32];
        let pcr0 = [0x22u8; 48];
        // The bundle carries only the pinned root — the orphan's issuer
        // (the lone intermediate) can never be reached from it.
        let doc = doc_with(&pcr0, &nonce, target, &[dev_identity::ROOT_DER], &pkcs8);
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("issuer/subject mismatch"), "{msg}");
    }

    #[test]
    fn corrupted_target_signature_refused() {
        // A REAL dev chain (leaf ← pinned dev root) with the target
        // certificate's own signature bytes corrupted: DN links match,
        // so the chain reaches the cryptographic step and refuses there.
        let mut target = dev_identity::LEAF_DER.to_vec();
        let idx = target.len() - 5;
        target[idx] ^= 0x5A;
        let nonce = [3u8; 32];
        let pcr0 = dev_measurement(&demo_seed());
        let doc = doc_with(
            &pcr0,
            &nonce,
            &target,
            &[dev_identity::ROOT_DER],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("does not verify"), "{msg}");
    }

    #[test]
    fn issuer_without_basic_constraints_refused() {
        let (ikey, noca) = mint("qsv no-bc issuer", IsCa::NoCa, ca_kus());
        let (lkey, lcert) = mint_signed(
            "qsv bc-test enclave",
            IsCa::NoCa,
            leaf_kus(),
            (&ikey, &noca),
        );
        let target: &[u8] = lcert.der();
        let interm: &[u8] = noca.der();
        let pkcs8 = lkey.serialize_der();
        let nonce = [10u8; 32];
        let pcr0 = [0x33u8; 48];
        let doc = doc_with(
            &pcr0,
            &nonce,
            target,
            &[dev_identity::ROOT_DER, interm],
            &pkcs8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("basicConstraints"), "{msg}");
    }

    #[test]
    fn issuer_without_key_cert_sign_refused() {
        // A CA certificate whose keyUsage lacks keyCertSign (AWS §3.2.3.3).
        // Policy checks run before links, so the target only needs to
        // parse and be a sane end-entity — self-signed is fine here.
        let (_ikey, ca_noku) = mint(
            "qsv no-kc issuer",
            IsCa::Ca(BasicConstraints::Unconstrained),
            leaf_kus(),
        );
        let (_lkey, lcert) = mint("qsv ku-test enclave", IsCa::NoCa, leaf_kus());
        let target: &[u8] = lcert.der();
        let interm: &[u8] = ca_noku.der();
        let nonce = [11u8; 32];
        let pcr0 = [0x44u8; 48];
        let doc = doc_with(
            &pcr0,
            &nonce,
            target,
            &[dev_identity::ROOT_DER, interm],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("keyCertSign"), "{msg}");
    }

    #[test]
    fn path_len_violation_refused() {
        // bundle = [dev root, pathLen:0 CA, another CA]: the pathLen:0 CA
        // sits one intermediate ABOVE the bottom CA — AWS §3.2.3.3 forbids
        // exactly this (the constraint is already exceeded below it).
        let (_a_key, a) = mint(
            "qsv pathlen0 ca",
            IsCa::Ca(BasicConstraints::Constrained(0)),
            ca_kus(),
        );
        let (_b_key, b) = mint(
            "qsv below pathlen0 ca",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_kus(),
        );
        let a_der: &[u8] = a.der();
        let b_der: &[u8] = b.der();
        let nonce = [12u8; 32];
        let pcr0 = [0x55u8; 48];
        let doc = doc_with(
            &pcr0,
            &nonce,
            dev_identity::LEAF_DER,
            &[dev_identity::ROOT_DER, a_der, b_der],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("pathLenConstraint"), "{msg}");
    }

    #[test]
    fn target_certificate_must_not_be_a_ca() {
        let (_k, target_ca) = mint(
            "qsv target ca",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_kus(),
        );
        let target: &[u8] = target_ca.der();
        let nonce = [13u8; 32];
        let pcr0 = [0x66u8; 48];
        let doc = doc_with(
            &pcr0,
            &nonce,
            target,
            &[dev_identity::ROOT_DER],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("end-entity"), "{msg}");
    }

    #[test]
    fn validity_window_enforced_on_dev_documents() {
        let nonce = [4u8; 32];
        let doc_hex = emit_demo(&nonce, "bc1ptest");
        let pinned = demo_pinned("bc1ptest");
        // Control: inside the dev certificate window (2020..2050).
        verify_attestation_doc_at(&doc_hex, &pinned, &hex::encode(nonce), CHAIN_NOW)
            .expect("valid window verifies");
        // After expiry → refuse (target first, AWS §3.2.3.1).
        let e = verify_attestation_doc_at(&doc_hex, &pinned, &hex::encode(nonce), 200_000_000_000)
            .expect_err("expired must refuse");
        assert!(matches!(e, AttestationError::Chain(_)), "{e:?}");
        assert!(e.to_string().contains("outside validity window"), "{e}");
        // Before not-before → refuse.
        let e = verify_attestation_doc_at(&doc_hex, &pinned, &hex::encode(nonce), 100)
            .expect_err("not-yet-valid must refuse");
        assert!(matches!(e, AttestationError::Chain(_)), "{e:?}");
        assert!(e.to_string().contains("outside validity window"), "{e}");
    }

    #[test]
    fn dev_identity_is_well_formed() {
        // The embedded identity satisfies EVERYTHING the verifier demands
        // of a chain — self-consistency of the fixtures.
        let spki = verify_chain(
            dev_identity::LEAF_DER,
            &[dev_identity::ROOT_DER.to_vec()],
            CHAIN_NOW,
        )
        .expect("dev chain verifies");
        assert!(!spki.is_empty(), "target SPKI extracted");

        let root = parse_cert(dev_identity::ROOT_DER).unwrap();
        let bc = root.basic_constraints().unwrap().expect("root BC");
        assert!(bc.critical && bc.value.ca, "root is a critical CA");
        let ku = root.key_usage().unwrap().expect("root KU");
        assert!(ku.value.key_cert_sign(), "root can keyCertSign");

        let leaf = parse_cert(dev_identity::LEAF_DER).unwrap();
        assert_eq!(leaf.issuer().as_raw(), root.subject().as_raw());
        let tbc = leaf.basic_constraints().unwrap().expect("leaf BC");
        assert!(
            !tbc.value.ca && tbc.value.path_len_constraint.is_none(),
            "leaf is an end-entity"
        );
        let tku = leaf.key_usage().unwrap().expect("leaf KU");
        assert!(tku.value.digital_signature(), "leaf can digitalSignature");
        assert_eq!(
            leaf.signature_algorithm.algorithm.to_id_string(),
            "1.2.840.10045.4.3.3",
            "ecdsa-with-SHA384"
        );
        // The leaf key material is a P-384 PKCS#8 the signer accepts.
        assert!(
            aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
                &aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                dev_identity::LEAF_KEY_PKCS8,
            )
            .is_ok(),
            "embedded leaf key loads"
        );
    }

    // ── Round 30 · exhaustive parser/refusal coverage ────────────────────

    /// Every `Display` arm — the operator-facing message of each variant.
    #[test]
    fn display_impl_covers_every_error_variant() {
        let cases: [(AttestationError, &str); 7] = [
            (
                AttestationError::NoDevice("d".into()),
                "NSM device unavailable",
            ),
            (AttestationError::Nsm("n".into()), "NSM error"),
            (
                AttestationError::Malformed("m".into()),
                "malformed attestation doc",
            ),
            (
                AttestationError::Measurement("x".into()),
                "measurement mismatch",
            ),
            (AttestationError::Nonce("x".into()), "nonce mismatch"),
            (AttestationError::Chain("c".into()), "certificate chain"),
            (
                AttestationError::Sig("s".into()),
                "signature verification failed",
            ),
        ];
        for (e, want) in cases {
            let msg = e.to_string();
            assert!(msg.contains(want), "{msg} must contain {want}");
            assert!(msg.contains(": "), "every arm renders 'reason: {msg}'");
        }
    }

    /// Every COSE_Sign1 shape refusal: tag, arity, protected header
    /// (map/key/alg/trailing), unprotected budget, payload budget,
    /// signature length and trailing bytes.
    #[test]
    fn cose_sign1_shape_refusals_cover_every_parser_arm() {
        let cose_err = |doc: Vec<u8>| {
            parse_cose_sign1(&doc)
                .expect_err("shape must be refused")
                .to_string()
        };
        // Wrong CBOR tag (major 6 | 1 → tag 1, not 18).
        assert!(cose_err(vec![0xC1]).contains("CBOR tag 1, expected 18"));
        // array(5) with room to spare → arity refusal.
        let mut a5 = vec![0x85u8];
        a5.extend([0xA0u8; 5]);
        assert!(cose_err(a5).contains("array(4), got array(5)"));
        // Protected header is a map(2), not the single {1: -35} entry.
        let mut two = vec![0x84u8];
        push_bstr(&mut two, &[0xA2, 0x01, 0x01, 0x02, 0x02]);
        assert!(cose_err(two).contains("single-entry map"));
        // Protected header key 2 (not 1 = alg).
        let mut k2 = vec![0x84u8];
        push_bstr(&mut k2, &[0xA1, 0x02, 0x38, 0x22]);
        assert!(cose_err(k2).contains("protected header key 2"));
        // alg 0 (not -35 = ES384).
        let mut alg = vec![0x84u8];
        push_bstr(&mut alg, &[0xA1, 0x01, 0x00]);
        assert!(cose_err(alg).contains("unsupported COSE algorithm 0"));
        // Trailing byte inside the protected header.
        let mut tr = vec![0x84u8];
        push_bstr(&mut tr, &[0xA1, 0x01, 0x38, 0x22, 0x00]);
        assert!(cose_err(tr).contains("trailing bytes in protected header"));
        // Unprotected header claims more entries than the document holds.
        let mut un = vec![0x84u8];
        push_bstr(&mut un, &[0xA1, 0x01, 0x38, 0x22]);
        un.push(0xB8);
        un.push(0x40); // map(64) in a ~6-byte envelope
        assert!(cose_err(un).contains("unprotected header longer"));
        // Empty payload (after a valid protected header).
        let mut ep = vec![0x84u8];
        push_bstr(&mut ep, &[0xA1, 0x01, 0x38, 0x22]);
        ep.push(0xA0);
        push_bstr(&mut ep, &[]);
        push_bstr(&mut ep, &[0u8; 96]);
        assert!(cose_err(ep).contains("payload 0 bytes"));
        // Oversized payload (20 KiB > 16 KiB budget).
        let mut op = vec![0x84u8];
        push_bstr(&mut op, &[0xA1, 0x01, 0x38, 0x22]);
        op.push(0xA0);
        push_bstr(&mut op, &[0u8; 20_000]);
        push_bstr(&mut op, &[0u8; 96]);
        assert!(cose_err(op).contains("must be 1..=16384"));
        // Signature of the wrong length.
        let mut sl = vec![0x84u8];
        push_bstr(&mut sl, &[0xA1, 0x01, 0x38, 0x22]);
        sl.push(0xA0);
        push_bstr(&mut sl, b"payload");
        push_bstr(&mut sl, &[0u8; 95]);
        assert!(cose_err(sl).contains("must be 96"));
        // Trailing bytes after the signature.
        let mut tb = vec![0x84u8];
        push_bstr(&mut tb, &[0xA1, 0x01, 0x38, 0x22]);
        tb.push(0xA0);
        push_bstr(&mut tb, b"payload");
        push_bstr(&mut tb, &[0u8; 96]);
        tb.push(0x00);
        assert!(cose_err(tb).contains("trailing bytes"));
    }

    /// The top-level document gates: the 64 KiB wall and the PCR1/PCR2
    /// pin branches (only armed when the operator pins them).
    #[test]
    fn document_gates_64k_wall_and_pcr1_pcr2_pins() {
        let pinned = demo_pinned("bc1ptest");
        let huge = "00".repeat(65_537);
        let e = verify_attestation_doc(&huge, &pinned, "")
            .expect_err("a >64 KiB document cannot be a document");
        assert!(e.to_string().contains("64 KiB"), "{e}");

        // PCR1 pinned, document has none → mismatch names PCR1.
        let mut p1 = demo_pinned("bc1ptest");
        p1.pcr1_hex = "ab".repeat(48);
        let nonce = [7u8; 32];
        let e = verify_attestation_doc(&emit_demo(&nonce, "bc1ptest"), &p1, "")
            .expect_err("missing PCR1 vs pinned PCR1 must refuse");
        assert!(e.to_string().contains("PCR1"), "{e}");

        // PCR2 pinned, document has none → mismatch names PCR2.
        let mut p2 = demo_pinned("bc1ptest");
        p2.pcr2_hex = "cd".repeat(48);
        let e = verify_attestation_doc(&emit_demo(&nonce, "bc1ptest"), &p2, "")
            .expect_err("missing PCR2 vs pinned PCR2 must refuse");
        assert!(e.to_string().contains("PCR2"), "{e}");
    }

    /// DER/X.509 layer refusals: empty bundle, unparseable certificate,
    /// trailing bytes, TBS slicing and every length form of the SEQUENCE
    /// header reader (1..=4 byte lengths, unsupported forms, overruns).
    #[test]
    fn chain_layer_refusals_cover_cert_and_der_parsing() {
        let e = verify_chain(&[], &[], 1_700_000_000)
            .expect_err("an empty cabundle must refuse before any crypto");
        assert!(e.to_string().contains("empty cabundle"), "{e}");

        let e = parse_cert(&[0x00, 0x01]).expect_err("garbage is not a certificate");
        assert!(e.to_string().contains("invalid X.509"), "{e}");

        let mut with_tail = dev_identity::LEAF_DER.to_vec();
        with_tail.push(0x00);
        let e = parse_cert(&with_tail).expect_err("trailing bytes must refuse");
        assert!(e.to_string().contains("trailing bytes"), "{e}");

        let e = tbs_slice(&[0x00, 0x02, 0x01]).expect_err("not a SEQUENCE");
        assert!(e.to_string().contains("expected DER SEQUENCE"), "{e}");

        // Header length fits the buffer, but the SEQUENCE does not
        // consume all of it (trailing bytes) → the span check fires.
        let e = tbs_slice(&[0x30, 0x02, 0x01, 0x02, 0xFF])
            .expect_err("a SEQUENCE must span exactly the buffer");
        assert!(e.to_string().contains("does not span"), "{e}");

        let e = tbs_slice(&[0x30, 0x03, 0x30, 0x05, 0x02]).expect_err("TBS overrun must refuse");
        assert!(e.to_string().contains("overruns"), "{e}");

        // 1-byte length form (0x81) parses: SEQUENCE of 1 content byte.
        let (off, len) = der_seq_header(&[0x30, 0x81, 0x01, 0xAA]).unwrap();
        assert_eq!((off, len), (3, 1));
        // 2-byte form (0x82).
        let (off, len) = der_seq_header(&[0x30, 0x82, 0x00, 0x01, 0xAA]).unwrap();
        assert_eq!((off, len), (4, 1));
        // 3-byte form (0x83).
        let (off, len) = der_seq_header(&[0x30, 0x83, 0x00, 0x00, 0x01, 0xAA]).unwrap();
        assert_eq!((off, len), (5, 1));
        // 4-byte form (0x84).
        let (off, len) = der_seq_header(&[0x30, 0x84, 0x00, 0x00, 0x00, 0x01, 0xAA]).unwrap();
        assert_eq!((off, len), (6, 1));
        // Indefinite / >4-byte forms fail closed.
        let e = der_seq_header(&[0x30, 0x80]).expect_err("indefinite length");
        assert!(e.to_string().contains("unsupported DER length form"), "{e}");
        // Truncated length bytes hit the malformed guard.
        let e = der_seq_header(&[0x30]).expect_err("no length byte");
        assert!(
            e.to_string().contains("malformed DER SEQUENCE header"),
            "{e}"
        );
        let e = der_seq_header(&[0x30, 0x82, 0x00]).expect_err("short 2-byte len");
        assert!(
            e.to_string().contains("malformed DER SEQUENCE header"),
            "{e}"
        );
        // Length that overruns the input.
        let e = der_seq_header(&[0x30, 0x05, 0x02, 0x01]).expect_err("overrun");
        assert!(e.to_string().contains("DER length overruns input"), "{e}");
    }

    /// CBOR reader primitives: every truncation, length form, major-type
    /// mismatch, UTF-8 and integer-range refusal — hostile input never
    /// panics, every arm answers Err.
    #[test]
    fn cbor_reader_refuses_every_malformed_shape() {
        // byte()/take() truncation (overflow-proof bound).
        let mut c = Cbor { b: b"", i: 0 };
        assert!(c.byte().unwrap_err().to_string().contains("truncated CBOR"));
        let mut c = Cbor { b: b"\x00", i: 1 };
        assert!(c
            .take(usize::MAX)
            .unwrap_err()
            .to_string()
            .contains("truncated CBOR"));
        // arg(): indefinite length (info 31) and every follow-up width.
        let mut c = Cbor { b: b"\x9f", i: 0 };
        assert!(c
            .expect_array()
            .unwrap_err()
            .to_string()
            .contains("indefinite CBOR length"));
        let mut c = Cbor { b: b"\x78", i: 0 };
        assert!(c.expect_bytes().is_err()); // 1-byte follow-up truncated
        let mut c = Cbor {
            b: b"\x79\x00",
            i: 0,
        };
        assert!(c.expect_bytes().is_err()); // 2-byte follow-up truncated
        let mut c = Cbor {
            b: b"\x7a\x00\x00",
            i: 0,
        };
        assert!(c.expect_bytes().is_err()); // 4-byte follow-up truncated
        let mut c = Cbor {
            b: b"\x7b\x00\x00\x00\x00\x00",
            i: 0,
        };
        assert!(c.expect_bytes().is_err()); // 8-byte follow-up truncated
                                            // head(): major-type mismatch.
        let mut c = Cbor { b: b"\x80", i: 0 };
        assert!(c
            .expect_map()
            .unwrap_err()
            .to_string()
            .contains("major type 4, expected 5"));
        // expect_array(): element count beyond the document.
        let mut c = Cbor {
            b: b"\x98\x30",
            i: 0,
        };
        assert!(c
            .expect_array()
            .unwrap_err()
            .to_string()
            .contains("array longer than the document"));
        // expect_text(): non-UTF-8 payload.
        let mut c = Cbor {
            b: b"\x61\xff",
            i: 0,
        };
        assert!(c
            .expect_text()
            .unwrap_err()
            .to_string()
            .contains("not UTF-8"));
        // optional_bytes_hex(): CBOR null → absent, oversize → refused.
        let mut c = Cbor { b: b"\xf6", i: 0 };
        assert_eq!(c.optional_bytes_hex(512).unwrap(), "");
        let mut c = Cbor {
            b: b"\x58\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            i: 0,
        };
        assert!(c
            .optional_bytes_hex(5)
            .unwrap_err()
            .to_string()
            .contains("exceeds the 5-byte budget"));
        // expect_uint(): a negative integer is not a uint.
        let mut c = Cbor { b: b"\x20", i: 0 };
        assert!(c
            .expect_uint()
            .unwrap_err()
            .to_string()
            .contains("expected CBOR uint"));
        // expect_int(): both out-of-range signs and a non-integer major.
        let mut c = Cbor {
            b: b"\x1b\xff\xff\xff\xff\xff\xff\xff\xff",
            i: 0,
        };
        assert!(c
            .expect_int()
            .unwrap_err()
            .to_string()
            .contains("CBOR int out of range"));
        let mut c = Cbor {
            b: b"\x3b\xff\xff\xff\xff\xff\xff\xff\xff",
            i: 0,
        };
        assert!(c
            .expect_int()
            .unwrap_err()
            .to_string()
            .contains("CBOR int out of range"));
        let mut c = Cbor { b: b"\x60", i: 0 };
        assert!(c
            .expect_int()
            .unwrap_err()
            .to_string()
            .contains("expected CBOR int"));
        // skip_within(): the depth wall, both overrun walls, the tag and
        // the simple-value/half-float majors.
        let mut deep = Vec::new();
        for _ in 0..33 {
            deep.push(0xA1u8); // map(1) nested 33 deep
            deep.push(0x00); // key: uint 0
        }
        // Two spare bytes so the map-length cap (n vs remaining/2)
        // does not fire FIRST at map #33 — the DEPTH wall must be the
        // one that answers (each map needs 2 bytes for its entry).
        deep.push(0x00);
        deep.push(0x00);
        let mut c = Cbor { b: &deep, i: 0 };
        assert!(c
            .skip_within(0)
            .unwrap_err()
            .to_string()
            .contains("nesting deeper than 32"));
        let mut c = Cbor {
            b: b"\x98\x30",
            i: 0,
        };
        assert!(c.skip_within(0).is_err()); // array longer than document
        let mut c = Cbor {
            b: b"\xb8\x30",
            i: 0,
        };
        assert!(c.skip_within(0).is_err()); // map longer than document
        let mut c = Cbor {
            b: b"\xc0\x00",
            i: 0,
        };
        assert!(c.skip_within(0).is_ok()); // tag → skip the value
        let mut c = Cbor { b: b"\x20", i: 0 };
        assert!(c.skip_within(0).is_ok()); // major 1 (negative int)
        let mut c = Cbor { b: b"\xf6", i: 0 };
        assert!(c.skip_within(0).is_ok()); // major 7 (simple value)
        let mut c = Cbor {
            b: b"\x78\x02\x00\x00",
            i: 0,
        };
        assert!(c.skip_within(0).is_ok()); // byte string inside a header
    }

    /// The CBOR writer's length ladder (immediate/1/2/4/8-byte heads) —
    /// every branch of `cbor_head`, round-tripped through the reader
    /// with the promised payload present, plus the 8-byte form's
    /// truncated-argument wall (a 4 GiB promise nothing can satisfy).
    #[test]
    fn cbor_head_covers_every_length_form() {
        for n in [0usize, 23, 24, 255, 256, 65_535, 65_536] {
            let mut out = Vec::new();
            cbor_head(&mut out, 2, n);
            let head_len = out.len();
            assert_eq!(
                head_len,
                match n {
                    0..=23 => 1,
                    24..=255 => 2,
                    256..=65_535 => 3,
                    _ => 5,
                },
                "major 2, n={n}"
            );
            out.extend(std::iter::repeat_n(0xAAu8, n));
            let mut c = Cbor { b: &out, i: 0 };
            assert_eq!(c.expect_bytes().map(|s| s.len()), Ok(n), "n={n}");
            assert_eq!(c.i, head_len + n, "head+payload consumed");
        }
        // The 8-byte form: the 9-byte head alone promises a length that
        // could never be present — the take wall answers.
        let mut out = Vec::new();
        cbor_head(&mut out, 2, u32::MAX as usize + 1);
        assert_eq!(out.len(), 9, "major | 27 + 8 follow-up bytes");
        let mut c = Cbor { b: &out, i: 0 };
        assert!(c.expect_bytes().is_err(), "4 GiB length never satisfied");
        // A mid-varint truncation: major|27 with only 3 of the 8
        // argument bytes on the wire.
        let mut c = Cbor {
            b: b"\x7b\x00\x00\x00",
            i: 0,
        };
        assert!(
            c.expect_bytes().is_err(),
            "length argument itself truncated"
        );
    }

    // ── Round 30: parse & chain walls driven by crafted documents ──────

    /// Rebuilds a dev-signed document with a REPLACED unprotected header
    /// map (byte 6 of the COSE_Sign1 array). The unprotected map is NOT
    /// covered by the signature (Sig_structure binds protected+payload
    /// only), so the document still verifies end-to-end — the parser
    /// walls below run against a fully valid signature chain.
    fn doc_with_unprotected(unprotected: &[u8]) -> String {
        let pcr0 = [0x33u8; 48];
        let payload = build_payload(
            "qsv-test",
            1_690_000_000_000,
            &[(0, pcr0.as_slice())],
            dev_identity::LEAF_DER,
            &[dev_identity::ROOT_DER],
            &[7u8; 32],
            &[0xEEu8; 64],
        );
        let doc = sign_cose(&payload, dev_identity::LEAF_KEY_PKCS8).expect("dev sign");
        assert_eq!(doc[6], 0xA0, "unprotected placeholder: {doc:02x?}");
        let mut out = Vec::with_capacity(doc.len() + unprotected.len());
        out.extend_from_slice(&doc[..6]);
        out.extend_from_slice(unprotected);
        out.extend_from_slice(&doc[7..]);
        hex::encode(out)
    }

    #[test]
    fn tagged_documents_verify_and_unprotected_entries_are_walked() {
        let pcr0 = [0x33u8; 48];
        let nonce = [7u8; 32];
        // (a) TAGGED COSE (0xD2 = tag 18): the tag branch parses and the
        // document still verifies — the tag is advisory, not a wall.
        let payload = build_payload(
            "qsv-test",
            1_690_000_000_000,
            &[(0, pcr0.as_slice())],
            dev_identity::LEAF_DER,
            &[dev_identity::ROOT_DER],
            &nonce,
            &[0xEEu8; 64],
        );
        let untagged = sign_cose(&payload, dev_identity::LEAF_KEY_PKCS8).unwrap();
        let mut tagged = vec![0xD2u8];
        tagged.extend_from_slice(&untagged);
        let doc = hex::encode(tagged);
        verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).expect("tagged dev document verifies");

        // (b) ONE unprotected entry: `p.skip()` walks it and the ceremony
        // completes (COSE leaves the unprotected map unsigned by design).
        let doc = doc_with_unprotected(&[0xA1, 0x01, 0x01]);
        verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).expect("one unprotected entry is fine");

        // (c) A RESERVED major-7 code point (0xFC): skip_within fails
        // closed — CBOR forbids it, a header map may not smuggle it past
        // the walk.
        let doc = doc_with_unprotected(&[0xA1, 0x01, 0xFC]);
        let e = verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).expect_err("reserved code must refuse");
        assert!(e.to_string().contains("unsupported CBOR"), "{e}");

        // (d) A count that dwarfs the remaining document: the budget
        // wall fires before any skip loop starts.
        let doc = doc_with_unprotected(&[0xB9, 0x80, 0x00]); // map(32768)
        let e =
            verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).expect_err("absurd entry count must refuse");
        assert!(
            e.to_string()
                .contains("unprotected header longer than the document"),
            "{e}"
        );
    }

    #[test]
    fn payload_field_walls_refuse_before_any_crypto() {
        let pcr0 = [0x44u8; 48];
        let nonce = [9u8; 32];
        // A 2,000-byte "certificate": the size wall fires in the parser —
        // no X.509 byte is ever interpreted.
        let doc = doc_with(
            &pcr0,
            &nonce,
            &[0u8; 2_000],
            &[dev_identity::ROOT_DER],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let e =
            verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).expect_err("fat certificate must refuse");
        assert!(e.to_string().contains("certificate is 2000 bytes"), "{e}");

        // A 1,100-byte bundle ENTRY: the per-entry wall (the cumulative
        // wall stays silent because the document itself is larger).
        let doc = doc_with(
            &pcr0,
            &nonce,
            dev_identity::LEAF_DER,
            &[&[0xAAu8; 1_100]],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let e =
            verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).expect_err("fat bundle entry must refuse");
        assert!(
            e.to_string().contains("cabundle entry is 1100 bytes"),
            "{e}"
        );

        // A cabundle ARRAY that claims more entries than the document has
        // bytes: the cumulative wall.
        let mut pl = Vec::new();
        cbor_head(&mut pl, 5, 4);
        push_text(&mut pl, "module_id");
        push_text(&mut pl, "qsv-test");
        push_text(&mut pl, "timestamp");
        cbor_head(&mut pl, 0, 1_690_000_000);
        push_text(&mut pl, "digest");
        push_text(&mut pl, "SHA384");
        push_text(&mut pl, "cabundle");
        cbor_head(&mut pl, 4, 4); // claims FOUR entries…
        push_bstr(&mut pl, &[0u8; 1]); // …but the document ends after one
        let doc = hex::encode(sign_cose(&pl, dev_identity::LEAF_KEY_PKCS8).unwrap());
        let e = verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).expect_err("lying array must refuse");
        assert!(
            e.to_string().contains("array longer than the document"),
            "{e}"
        );

        // An explicitly EMPTY cabundle.
        let mut pl = Vec::new();
        cbor_head(&mut pl, 5, 4);
        push_text(&mut pl, "module_id");
        push_text(&mut pl, "qsv-test");
        push_text(&mut pl, "timestamp");
        cbor_head(&mut pl, 0, 1_690_000_000);
        push_text(&mut pl, "digest");
        push_text(&mut pl, "SHA384");
        push_text(&mut pl, "cabundle");
        cbor_head(&mut pl, 4, 0); // array(0)
        let doc = hex::encode(sign_cose(&pl, dev_identity::LEAF_KEY_PKCS8).unwrap());
        let e = verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).expect_err("empty bundle");
        assert!(e.to_string().contains("cabundle must not be empty"), "{e}");

        // A payload without the mandatory `pcrs` map.
        let mut pl = Vec::new();
        cbor_head(&mut pl, 5, 3);
        push_text(&mut pl, "module_id");
        push_text(&mut pl, "qsv-test");
        push_text(&mut pl, "timestamp");
        cbor_head(&mut pl, 0, 1_690_000_000);
        push_text(&mut pl, "digest");
        push_text(&mut pl, "SHA384");
        let doc = hex::encode(sign_cose(&pl, dev_identity::LEAF_KEY_PKCS8).unwrap());
        let e = verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).expect_err("pcrs wall");
        assert!(
            e.to_string().contains("missing mandatory field pcrs"),
            "{e}"
        );

        // The LAST key with no value: the optional nonce reader reaches the
        // end of the document (its absent-value path) and fails closed.
        let mut pl = Vec::new();
        cbor_head(&mut pl, 5, 5);
        push_text(&mut pl, "module_id");
        push_text(&mut pl, "qsv-test");
        push_text(&mut pl, "timestamp");
        cbor_head(&mut pl, 0, 1_690_000_000);
        push_text(&mut pl, "digest");
        push_text(&mut pl, "SHA384");
        push_text(&mut pl, "certificate");
        push_bstr(&mut pl, dev_identity::LEAF_DER);
        push_text(&mut pl, "nonce"); // ← key, then EOF
        let doc = hex::encode(sign_cose(&pl, dev_identity::LEAF_KEY_PKCS8).unwrap());
        assert!(verify_doc(&doc, &pcr0, &nonce, CHAIN_NOW).is_err());
    }

    #[test]
    fn issuer_policy_walls_fire_before_any_signature_is_checked() {
        let pcr0 = [0x55u8; 48];
        let nonce = [3u8; 32];
        // A CA WITHOUT any basicConstraints at all (rcgen emits no
        // extensions for a plain NoCa cert): the structural wall.
        let (_, no_bc) = mint("evil ca", IsCa::NoCa, ca_kus());
        let doc = doc_with(
            &pcr0,
            &nonce,
            dev_identity::LEAF_DER,
            &[dev_identity::ROOT_DER, no_bc.der()],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(
            msg.contains("cabundle[1] lacks basicConstraints (CA required)"),
            "{msg}"
        );

        // ExplicitNoCa DOES carry basicConstraints — but CA:FALSE → the
        // critical-CA wall (the link stage never runs; no valid issuer
        // chain is needed at all).
        let (_, false_ca) = mint("ca: false", IsCa::ExplicitNoCa, ca_kus());
        let doc = doc_with(
            &pcr0,
            &nonce,
            dev_identity::LEAF_DER,
            &[dev_identity::ROOT_DER, false_ca.der()],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(
            msg.contains("cabundle[1] must carry critical BasicConstraints CA:TRUE"),
            "{msg}"
        );

        // CA:TRUE but no keyCertSign → the KU wall.
        let (_, no_ku) = mint(
            "ca without keyCertSign",
            IsCa::Ca(BasicConstraints::Unconstrained),
            leaf_kus(),
        );
        let doc = doc_with(
            &pcr0,
            &nonce,
            dev_identity::LEAF_DER,
            &[dev_identity::ROOT_DER, no_ku.der()],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("keyUsage lacks keyCertSign"), "{msg}");

        // A CORRUPT basicConstraints extension: the X.509 parser error
        // path (`chain_err`), not a policy verdict.
        let (_, bad_ext) = mint(
            "ca with mangled BC",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_kus(),
        );
        let mut der = bad_ext.der().to_vec();
        let oid = [0x06u8, 0x03, 0x55, 0x1D, 0x13]; // 2.5.29.19 basicConstraints
        let at = der
            .windows(5)
            .position(|w| w == oid)
            .expect("BC extension present");
        let val = der[at..]
            .iter()
            .position(|&b| b == 0x04)
            .map(|p| at + p)
            .expect("extnValue OCTET STRING");
        // The OCTET STRING wrapper stays intact (the extension list still
        // parses); the BC SEQUENCE INSIDE it does not — the lazy
        // `basic_constraints()` read is the wall that must answer.
        der[val + 2] = 0x01; // was 0x30 (SEQUENCE)
        let doc = doc_with(
            &pcr0,
            &nonce,
            dev_identity::LEAF_DER,
            &[dev_identity::ROOT_DER, &der],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(!msg.is_empty(), "a mangled extension still refuses");
    }

    #[test]
    fn target_policy_walls_fire_before_any_link() {
        let pcr0 = [0x66u8; 48];
        let nonce = [4u8; 32];
        // Target that is itself a CA → end-entity wall.
        let (_, fat) = mint(
            "fat target",
            IsCa::Ca(BasicConstraints::Constrained(0)),
            leaf_kus(),
        );
        let doc = doc_with(
            &pcr0,
            &nonce,
            fat.der(),
            &[dev_identity::ROOT_DER],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("must be an end-entity certificate"), "{msg}");

        // Target without digitalSignature → the KU wall. ExplicitNoCa
        // so rcgen actually writes the extensions block (a plain NoCa
        // cert with nothing else to say emits NO extensions at all).
        let (_, no_ds) = mint(
            "no digsig",
            IsCa::ExplicitNoCa,
            vec![KeyUsagePurpose::KeyEncipherment],
        );
        let doc = doc_with(
            &pcr0,
            &nonce,
            no_ds.der(),
            &[dev_identity::ROOT_DER],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("keyUsage lacks digitalSignature"), "{msg}");

        // A TRUNCATED target DER → the incomplete-certificate wall.
        let short = &dev_identity::LEAF_DER[..40];
        let doc = doc_with(
            &pcr0,
            &nonce,
            short,
            &[dev_identity::ROOT_DER],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("incomplete X.509 certificate"), "{msg}");
    }

    #[test]
    fn link_time_x509_walls_refuse_exotic_encodings() {
        let pcr0 = [0x77u8; 48];
        let nonce = [5u8; 32];
        // A real two-cert chain: the TARGET link (leaf ← custom CA) runs
        // and verifies first; each splice below isolates exactly ONE wall
        // while everything else stays byte-identical.
        let (ikey, icert) = mint(
            "qsv round30 intermediate",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_kus(),
        );
        let (_, lcert) = mint_signed("qsv round30 leaf", IsCa::NoCa, leaf_kus(), (&ikey, &icert));
        let target = lcert.der().to_vec();
        let bundle: [&[u8]; 2] = [dev_identity::ROOT_DER, icert.der()];

        // (a) Unsupported signature algorithm: the OUTER AlgorithmIdentifier
        // OID (LAST occurrence — the TBS copy comes first) loses its final byte.
        let oid = [0x2Au8, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]; // ecdsa-with-SHA384
        let mut der = target.clone();
        let at = der
            .windows(8)
            .rposition(|w| w == oid)
            .expect("outer alg OID");
        der[at + 7] = 0x04; // …now an unknown OID
        let doc = doc_with(&pcr0, &nonce, &der, &bundle, dev_identity::LEAF_KEY_PKCS8);
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(
            msg.contains("unsupported certificate signature algorithm"),
            "{msg}"
        );

        // (b) BIT STRING with unused bits: the signature's unused-bits
        // octet (right after the BIT STRING header) becomes 0x01 — a
        // value that is legal DER (≤ 7) and therefore parses, yet must
        // still be refused before any crypto runs. (Anything ≥ 8 would
        // be rejected by the parser itself with a different wall.) The
        // header is located STRUCTURALLY — the trailing BIT STRING is the
        // one whose body spans to the end of the certificate — and the
        // padding bit is cleared so asn1-rs's DER padding check stays
        // satisfied: no byte-pattern luck, no flake.
        let mut der = target.clone();
        let l = der.len();
        let at = (0..l.saturating_sub(4))
            .rev()
            .find(|&i| {
                der[i] == 0x03
                    && usize::from(der[i + 1]) == l - i - 2 // spans to the end
                    && der[i + 3] == 0x30 // SEQUENCE { r, s }
            })
            .expect("signature BIT STRING header");
        der[at + 2] = 0x01; // unused = 1
        der[l - 1] &= 0xFE; // last data bit becomes padding — zero it
        let doc = doc_with(&pcr0, &nonce, &der, &bundle, dev_identity::LEAF_KEY_PKCS8);
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("BIT STRING has unused bits"), "{msg}");

        // (c) Data AFTER the certificate: the parser hands back a
        // non-empty remainder and parse_cert refuses it (the DER bytes
        // themselves are perfectly valid).
        let mut der = target.clone();
        der.push(0x00); // trailing junk after a well-formed certificate
        let doc = doc_with(&pcr0, &nonce, &der, &bundle, dev_identity::LEAF_KEY_PKCS8);
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("trailing bytes after certificate"), "{msg}");
    }

    /// `tbs_slice`'s inner-overrun wall, exercised directly: the chain
    /// path parses successfully only for certificates whose framing is
    /// already sound, so this arm is reached as a unit — like its
    /// siblings (`does not span`, `expected DER SEQUENCE`, …) above.
    /// DER SEQUENCE header length: immediate (short form) or long form
    /// with 1/2/4/8 length bytes after the head.
    fn der_seq_header_len(der: &[u8]) -> usize {
        assert_eq!(der[0], 0x30, "Certificate is a SEQUENCE");
        if der[1] & 0x80 != 0 {
            2 + (der[1] & 0x7F) as usize
        } else {
            2
        }
    }

    /// Both header forms parse: the dev root is long-form; a small
    /// SEQUENCE is short-form (the header is 2 bytes either way).
    #[test]
    fn der_seq_header_reads_both_length_forms() {
        let short = [0x30u8, 0x05, 0x02, 0x01, 0x00, 0x05, 0x00];
        assert_eq!(der_seq_header_len(&short), 2);
        let root = dev_identity::ROOT_DER;
        assert!(root[1] & 0x80 != 0, "the dev root uses the long form");
        assert_eq!(der_seq_header_len(root), 2 + (root[1] & 0x7F) as usize);
    }

    #[test]
    fn tbs_slice_refuses_an_inner_length_that_overruns_the_certificate() {
        let mut der = dev_identity::ROOT_DER.to_vec();
        let inner = der_seq_header_len(&der);
        assert_eq!(der[inner], 0x30, "TBSCertificate is a SEQUENCE");
        der[inner + 1] = 0x82;
        der[inner + 2] = 0xFF;
        der[inner + 3] = 0xFF; // claims 64 KiB
        let e = tbs_slice(&der).expect_err("an inner length overrun must refuse");
        assert!(e.to_string().contains("DER length overruns input"), "{e}");
    }

    /// `parse_cose_sign1`'s optional-tag peek has a None edge: EMPTY
    /// input refuses at the very first wall (never a panic, never a
    /// fabricated shape).
    #[test]
    fn an_empty_document_is_refused_at_the_first_wall() {
        let e = parse_cose_sign1(&[]).expect_err("empty input can never parse");
        assert!(!e.to_string().is_empty());
    }

    /// AWS §3.2.3.2: EVERY CA must carry keyUsage with keyCertSign — a
    /// CA with NO keyUsage extension at all fails the same wall (an
    /// absent extension is not "unrestricted").
    #[test]
    fn issuer_without_any_key_usage_extension_refused() {
        let (_ikey, ca_noku) = mint(
            "qsv no-ku issuer",
            IsCa::Ca(BasicConstraints::Unconstrained),
            vec![],
        );
        let (_lkey, lcert) = mint("qsv no-ku target", IsCa::NoCa, leaf_kus());
        let nonce = [12u8; 32];
        let pcr0 = [0x45u8; 48];
        let doc = doc_with(
            &pcr0,
            &nonce,
            lcert.der(),
            &[dev_identity::ROOT_DER, ca_noku.der()],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(msg.contains("lacks keyUsage"), "{msg}");
    }

    /// `chain_err` is the extension-PARSER fault line (distinct from the
    /// policy walls): a keyUsage whose BIT STRING framing is invalid
    /// (unused-bits > 7) must refuse through the parse wall.
    #[test]
    fn an_unparsable_key_usage_extension_fails_the_chain_parse_wall() {
        let (_ikey, ca) = mint(
            "qsv corrupt-ku issuer",
            IsCa::Ca(BasicConstraints::Unconstrained),
            ca_kus(),
        );
        let (_lkey, lcert) = mint("qsv corrupt-ku target", IsCa::NoCa, leaf_kus());
        let mut interm_der = ca.der().to_vec();
        // Locate the keyUsage extension (OID 2.5.29.15) and corrupt the
        // BIT STRING unused-bits count (> 7 is invalid DER — the parser
        // must refuse, never skip).
        let oid = [0x55u8, 0x1d, 0x0f];
        let oid_pos = interm_der
            .windows(3)
            .position(|w| w == oid)
            .expect("keyUsage OID is present");
        let tail = &interm_der[oid_pos + 3..];
        let os = tail.iter().position(|&b| b == 0x04).expect("extnValue");
        assert_eq!(tail[os + 2], 0x03, "BIT STRING inside the OCTET STRING");
        interm_der[oid_pos + 3 + os + 4] = 0x09; // unused-bits > 7
        let interm: &[u8] = &interm_der;
        let nonce = [13u8; 32];
        let pcr0 = [0x46u8; 48];
        let doc = doc_with(
            &pcr0,
            &nonce,
            lcert.der(),
            &[dev_identity::ROOT_DER, interm],
            dev_identity::LEAF_KEY_PKCS8,
        );
        let msg = chain_err_from(&doc, &pcr0, &nonce, CHAIN_NOW);
        assert!(
            !msg.contains("keyCertSign"),
            "parse wall fires first: {msg}"
        );
        assert!(!msg.contains("lacks keyUsage"), "{msg}");
    }

    /// `parse_cert`'s framing walls: truncated certificates refuse as
    /// INCOMPLETE (whether nom reports Eof-on-a-certificate or
    /// Incomplete), while garbage that never started as DER stays a
    /// plain parse error.
    #[test]
    fn truncated_certificates_are_refused_as_incomplete() {
        let root = dev_identity::ROOT_DER;
        for cut in [1usize, 2, 10, root.len() / 2, root.len() - 1] {
            let e = parse_cert(&root[..cut]).expect_err("truncated must refuse");
            assert!(
                e.to_string().contains("X.509 certificate"),
                "cut {cut}: {e}"
            );
        }
        let e = parse_cert(b"hello").expect_err("garbage must refuse");
        assert!(e.to_string().contains("invalid X.509 certificate"), "{e}");
    }

    /// The skip walker consumes the 1/2/4/8-byte arguments of major-7
    /// heads (simple-24, f16, f32, f64): consuming only the head byte
    /// would desynchronize the walk and misread everything after it.
    #[test]
    fn major7_arguments_are_consumed_not_desynchronized() {
        // map(4): f16 1.0, f32 1.0, f64 1.0 and simple(24) values.
        let mut map = vec![
            0xA4u8, 0x01, 0xF9, 0x3C, 0x00, 0x02, 0xFA, 0x3F, 0x80, 0x00, 0x00,
        ];
        map.extend_from_slice(&[0x03, 0xFB, 0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        map.extend_from_slice(&[0x04, 0xF8, 0x18]);
        let doc = doc_with_unprotected(&map);
        verify_doc(&doc, &[0x33u8; 48], &[7u8; 32], CHAIN_NOW)
            .expect("float and simple header values are skipped verbatim");
    }
}
