//! Wire protocol between the air-gapped client terminal and the co-signer
//! enclave service.
//!
//! Security model (docs/03 §5):
//! 1. The client proves the PQC identity (ML-DSA-65 signature over the sighash).
//! 2. The enclave proves its software identity (COSE_Sign1 attestation doc:
//!    X.509 chain to a pinned root CA + PCR measurement + the client's
//!    challenge nonce + the co-signing key binding, docs/10 §4.52).
//! 3. Only then is the second Schnorr signature released — deterministically,
//!    with zero human interaction (zero-HITL).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current protocol version (bumped on incompatible changes).
///
/// * v1 — the enclave derived the attestation nonce itself and dev mode
///   shipped a JSON pseudo-document the terminal never parsed.
/// * v2 (Round 27) — the client CHALLENGES the enclave with its own nonce
///   (`SignRequest::nonce_hex`), every accepted response carries a real
///   COSE_Sign1 attestation document, and the terminal verifies the whole
///   chain end-to-end (X.509 chain → COSE signature → PCR pin → nonce →
///   `user_data` key binding) before it trusts the co-signature.
pub const PROTOCOL_VERSION: u32 = 2;

/// Client -> enclave: request a co-signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignRequest {
    /// Protocol version.
    pub version: u32,
    /// Vault id (bech32m address string the vault pays from).
    pub vault_id: String,
    /// The 32-byte BIP-341 sighash to sign.
    pub sighash_hex: String,
    /// The client's ML-DSA-65 verifying key (1,952 bytes, hex).
    pub pqc_vk_hex: String,
    /// The client's ML-DSA-65 signature over `sighash` (3,309 bytes, hex).
    pub pqc_sig_hex: String,
    /// CLIENT-GENERATED attestation challenge (32 bytes, hex).
    ///
    /// The enclave validates the shape and echoes this value verbatim
    /// inside its COSE_Sign1 attestation document — it never re-derives
    /// it. The terminal refuses any document whose nonce differs from
    /// the one it sent, so a document replayed from any other signing
    /// event can never satisfy the check (docs/10 §4.52).
    pub nonce_hex: String,
}

impl SignRequest {
    pub fn new(vault_id: &str, sighash: &[u8; 32], pqc_vk: &[u8], pqc_sig: &[u8]) -> Self {
        // The nonce is generated CLIENT-SIDE, inside the constructor every
        // caller already uses: derived from the full request material, so
        // it is unique per signing event — two requests that differ in
        // vault, sighash, identity or proof can never share a nonce, and
        // an identical request replays an identical (harmless, Theorem 1)
        // response. No RNG needed on the air-gapped terminal.
        let mut n = Sha256::new();
        n.update(b"QSV_REQ_NONCE_v1");
        n.update(vault_id.as_bytes());
        n.update(sighash);
        n.update(pqc_vk);
        n.update(pqc_sig);
        Self {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_string(),
            sighash_hex: hex::encode(sighash),
            pqc_vk_hex: hex::encode(pqc_vk),
            pqc_sig_hex: hex::encode(pqc_sig),
            nonce_hex: hex::encode(n.finalize()),
        }
    }
}

/// Enclave -> client: attestation document + (conditionally) the co-signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignResponse {
    /// Protocol version.
    pub version: u32,
    /// Whether the co-signature was released.
    pub accepted: bool,
    /// Machine-readable refusal reason (docs/03 §5 ADIM 1 fail-closed).
    pub reason: Option<String>,
    /// The released BIP-340 signature (64 bytes, hex) — present iff accepted.
    pub schnorr_sig_hex: Option<String>,
    /// COSE_Sign1 attestation document (Nitro PCR-bound / TDX quote;
    /// opaque hex to the transport, verified end-to-end by the terminal
    /// against the operator's pinned root CA + PCR values + its own
    /// challenge nonce). Present on EVERY accepted response in v2; `None`
    /// on refusals (fail-closed transport answers stay doc-free).
    pub attestation_doc_hex: Option<String>,
}

/// The attestation payload an enclave binds into its COSE_Sign1 document.
///
/// Field shapes mirror the AWS Nitro AttestationDocument (`module_id`,
/// `timestamp`, `digest`, `pcrs`, `certificate`, `cabundle`, optional
/// `nonce`/`user_data`/`public_key`) so ONE verifier —
/// `nsm::verify_attestation_doc` — checks the real NSM document and the
/// dev-mode document through the identical code path (docs/10 §4.52).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationDoc {
    /// Platform identifier ("nitro", "tdx", "dev") — owned `String` so the
    /// document round-trips through serde like real attestation payloads.
    pub platform: String,
    /// Measurement binding (PCR0 equivalent or dev binary digest,
    /// SHA-384 → 48 bytes — stable per enclave build, pinnable).
    pub measurement_hex: String,
    /// The client's challenge nonce, echoed verbatim.
    pub nonce_hex: String,
    /// `enclave x-only pubkey (32 bytes) || vault id (utf8)` — binds the
    /// document to the key that produced the co-signature AND the one
    /// vault it is provisioned to serve.
    pub user_data_hex: String,
}

impl AttestationDoc {
    /// Dev/plain-deployment attestation payload: a STABLE per-seed
    /// measurement (the "PCR0" of the dev build — constant across
    /// requests, like a real binary measurement) plus the client's
    /// challenge nonce for replay binding.
    ///
    /// The nonce no longer leaks into the measurement (it has its own
    /// field and its own check): pinning a measurement that changed on
    /// every request would be impossible for an operator.
    pub fn dev(seed: &[u8; 32], nonce: &[u8; 32], user_data: &[u8]) -> Self {
        Self {
            platform: "dev".to_string(),
            measurement_hex: hex::encode(crate::nsm::dev_measurement(seed)),
            nonce_hex: hex::encode(nonce),
            user_data_hex: hex::encode(user_data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_response_roundtrip_json() {
        let req = SignRequest::new("bc1ptest", &[1u8; 32], &vec![2u8; 1952], &vec![3u8; 3309]);
        let json = serde_json::to_string(&req).unwrap();
        let back: SignRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
        assert_eq!(req.version, PROTOCOL_VERSION);
        // v2: the client's challenge rides in every request.
        assert_eq!(req.nonce_hex.len(), 64, "32-byte nonce, hex-encoded");
        assert_eq!(hex::decode(&req.nonce_hex).unwrap().len(), 32);
    }

    #[test]
    fn nonce_changes_when_any_request_material_changes() {
        let base = SignRequest::new("bc1ptest", &[1u8; 32], &[2u8; 4], &[3u8; 4]);
        let same = SignRequest::new("bc1ptest", &[1u8; 32], &[2u8; 4], &[3u8; 4]);
        assert_eq!(base.nonce_hex, same.nonce_hex, "deterministic per request");
        assert_ne!(
            base.nonce_hex,
            SignRequest::new("bc1pother", &[1u8; 32], &[2u8; 4], &[3u8; 4]).nonce_hex
        );
        assert_ne!(
            base.nonce_hex,
            SignRequest::new("bc1ptest", &[9u8; 32], &[2u8; 4], &[3u8; 4]).nonce_hex
        );
        assert_ne!(
            base.nonce_hex,
            SignRequest::new("bc1ptest", &[1u8; 32], &[2u8; 4], &[4u8; 4]).nonce_hex
        );
    }

    #[test]
    fn dev_attestation_measurement_is_stable_and_nonce_binds() {
        let a = AttestationDoc::dev(&[1u8; 32], &[2u8; 32], &[9u8; 40]);
        let b = AttestationDoc::dev(&[1u8; 32], &[2u8; 32], &[9u8; 40]);
        let c = AttestationDoc::dev(&[1u8; 32], &[3u8; 32], &[9u8; 40]);
        assert_eq!(a, b);
        assert_ne!(a, c, "the challenge nonce differs per request");
        // PCR0 equivalent: STABLE per seed (an operator can pin it) —
        // SHA-384 digest, so it matches the document's `digest` field.
        let d = AttestationDoc::dev(&[1u8; 32], &[4u8; 32], &[]);
        assert_eq!(a.measurement_hex, d.measurement_hex, "stable across nonces");
        assert_eq!(a.measurement_hex.len(), 96, "48 bytes (SHA-384)");
        assert_eq!(a.user_data_hex, hex::encode([9u8; 40]));
        assert_eq!(a.platform, "dev");
        assert_ne!(
            a.measurement_hex,
            AttestationDoc::dev(&[7u8; 32], &[2u8; 32], &[9u8; 40]).measurement_hex
        );
    }
}
