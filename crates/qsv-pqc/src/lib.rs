//! NIST FIPS 204 (ML-DSA-65) post-quantum engine and the hybrid co-signer gate.
//!
//! Theorem 1 (docs/04): the enclave releases its BIP-340 Schnorr signature if
//! and only if a valid ML-DSA-65 signature is presented. This module implements
//! that contract on top of the RustCrypto `ml-dsa` crate (FIPS 204 final) and
//! the audited `secp256k1` bindings — there is no placeholder cryptography.

use ml_dsa::{Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier, VerifyingKey};
use secp256k1::{Keypair as SchnorrKeypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

/// Byte lengths mandated by FIPS 204 for ML-DSA-65.
pub const ML_DSA_65_VK_LEN: usize = 1_952;
pub const ML_DSA_65_SIG_LEN: usize = 3_309;

/// A post-quantum identity: ML-DSA-65 seed + derived keys.
pub struct PqcIdentity {
    signing_key: SigningKey<MlDsa65>,
    verifying_key_bytes: [u8; ML_DSA_65_VK_LEN],
}

impl PqcIdentity {
    /// Deterministically derives an identity from a 32-byte seed
    /// (FIPS 204 Appendix D preferred key serialization).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let seed_arr: ml_dsa::Seed = (*seed).into();
        let sk = SigningKey::<MlDsa65>::from_seed(&seed_arr);
        let vk_bytes: [u8; ML_DSA_65_VK_LEN] = sk.verifying_key().encode().into();
        Self {
            signing_key: sk,
            verifying_key_bytes: vk_bytes,
        }
    }

    /// The encoded verifying key (1,952 bytes for ML-DSA-65).
    pub fn verifying_key_bytes(&self) -> &[u8; ML_DSA_65_VK_LEN] {
        &self.verifying_key_bytes
    }

    /// Signs `msg`, returning the 3,309-byte encoded signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; ML_DSA_65_SIG_LEN] {
        let sig: Signature<MlDsa65> = self.signing_key.sign(msg);
        sig.encode().into()
    }
}

/// Fail-closed verification: returns `true` only for a valid signature over
/// `msg` under the encoded verifying key. Any decode/validation failure is
/// `false` — never an exception path that could be bypassed.
pub fn pqc_verify(vk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    let Ok(vk_arr) = <[u8; ML_DSA_65_VK_LEN]>::try_from(vk_bytes) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa65>::decode((&vk_arr).into());
    let Ok(sig) = Signature::<MlDsa65>::try_from(sig_bytes) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

/// Errors raised by the co-signer gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateError {
    /// The submitted PQC signature failed verification — no Schnorr signature
    /// is produced (fail-closed, docs/03 §5 ADIM 1).
    PqcVerificationFailed,
    /// The enclave key material was invalid.
    EnclaveKey,
    /// The released Schnorr signature failed self-verification (defence in
    /// depth: the gate never emits a signature it cannot verify itself).
    SelfVerificationFailed,
}

impl core::fmt::Display for GateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GateError::PqcVerificationFailed => {
                write!(
                    f,
                    "ML-DSA-65 verification failed; co-signer refuses to sign (fail-closed)"
                )
            }
            GateError::EnclaveKey => write!(f, "invalid enclave key material"),
            GateError::SelfVerificationFailed => {
                write!(f, "released Schnorr signature failed self-verification")
            }
        }
    }
}

impl std::error::Error for GateError {}

/// Deterministic BIP-340 keypair expansion for the enclave co-signer.
///
/// Production note: inside a TEE/HSM this keypair is generated from the
/// hardware entropy source and sealed to the enclave image (AWS KMS /
/// Nitro Secure PRF); the *deterministic-from-seed* form here is the air-gap
/// reproducible equivalent used by cold deployments and tests.
pub fn enclave_keypair_from_seed(seed: &[u8; 32]) -> Result<SchnorrKeypair, GateError> {
    keypair_from_derivation(|counter| {
        // Domain-separated, rejection-sampled scalar derivation.
        let mut h = Sha256::new();
        h.update(b"QSV_ENCLAVE_KEY_v1");
        h.update(seed);
        h.update(counter.to_be_bytes());
        let d: [u8; 32] = h.finalize().into();
        SecretKey::from_slice(&d).ok()
    })
}

/// Counter-scan seam (coverage + clarity): the first scalar that decodes
/// wins; a full 1000-miss scan is the exhaustion wall. The production
/// sampler cannot exhaust it (~2^-128 per counter), so the wall itself is
/// driven by the unit test that feeds `None` every time.
fn keypair_from_derivation(
    mut next: impl FnMut(u32) -> Option<SecretKey>,
) -> Result<SchnorrKeypair, GateError> {
    let secp = Secp256k1::signing_only();
    for counter in 0u32..1_000 {
        if let Some(sk) = next(counter) {
            return Ok(SchnorrKeypair::from_secret_key(&secp, &sk));
        }
    }
    Err(GateError::EnclaveKey)
}

/// The x-only public half of an enclave co-signer keypair (goes into the vault
/// policy as `key_enclave` at setup time).
pub fn enclave_xonly_public_key(kp: &SchnorrKeypair) -> XOnlyPublicKey {
    kp.x_only_public_key().0
}

/// The deterministic enclave co-signer gate (Theorem 1 / docs/03 §5).
///
/// Releases a REAL BIP-340 Schnorr signature over `msg` ONLY when the
/// ML-DSA-65 signature over `msg` verifies under `pqc_vk_bytes`. The released
/// signature is self-verified before it leaves the gate. Deterministic: no
/// clocks, no network, no human approval (zero-HITL principle).
pub fn enclave_sign_if_pqc_valid(
    pqc_vk_bytes: &[u8],
    pqc_sig: &[u8],
    msg: &[u8],
    enclave_seed: &[u8; 32],
) -> Result<[u8; 64], GateError> {
    if !pqc_verify(pqc_vk_bytes, msg, pqc_sig) {
        return Err(GateError::PqcVerificationFailed);
    }
    let kp = enclave_keypair_from_seed(enclave_seed)?;
    let secp = Secp256k1::signing_only();
    // BIP-340 RFC-6979 nonce with a FIXED aux_rand: byte-deterministic output.
    // (Zero aux is explicitly allowed by BIP-340; the nonce remains bound to
    // the key and message, and the TEE binds the seed to its sealed image.)
    let sig =
        secp.sign_schnorr_with_aux_rand(&Message::from_digest(*msg_as_array(msg)), &kp, &[0u8; 32]);
    let sig_bytes: [u8; 64] = *sig.as_ref();

    // Defence in depth: never release a signature the gate cannot verify.
    let vk = enclave_xonly_public_key(&kp);
    self_verify(&vk, msg, &sig_bytes)?;
    Ok(sig_bytes)
}

/// The defence-in-depth self-check, split out so BOTH failure walls are
/// testable: the gate only ever produces parseable, verifiable bytes, so
/// the unparseable-bytes arm and the wrong-signature arm are reachable
/// exclusively by injection — the unit tests drive them with crafted
/// 64-byte strings.
fn self_verify(vk: &secp256k1::XOnlyPublicKey, msg: &[u8], sig: &[u8]) -> Result<(), GateError> {
    let verify = Secp256k1::verification_only();
    let sig = secp256k1::schnorr::Signature::from_slice(sig)
        .map_err(|_| GateError::SelfVerificationFailed)?;
    if verify
        .verify_schnorr(&sig, &Message::from_digest(*msg_as_array(msg)), vk)
        .is_err()
    {
        return Err(GateError::SelfVerificationFailed);
    }
    Ok(())
}

fn msg_as_array(msg: &[u8]) -> &[u8; 32] {
    <&[u8; 32]>::try_from(msg).expect("sighash messages are 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_sizes_match_fips_204() {
        let id = PqcIdentity::from_seed(&[9u8; 32]);
        assert_eq!(id.verifying_key_bytes().len(), 1_952);
        let sig = id.sign(b"payload");
        assert_eq!(sig.len(), 3_309);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = PqcIdentity::from_seed(&[1u8; 32]);
        let msg = b"vault heartbeat 2026-09-27";
        let sig = id.sign(msg);
        assert!(pqc_verify(id.verifying_key_bytes(), msg, &sig));
    }

    #[test]
    fn forge_is_rejected() {
        let id = PqcIdentity::from_seed(&[2u8; 32]);
        let msg = b"tx1";
        let sig = id.sign(msg);
        // Tampered message
        assert!(!pqc_verify(id.verifying_key_bytes(), b"tx2", &sig));
        // Tampered signature
        let mut bad = sig;
        bad[0] ^= 0xFF;
        assert!(!pqc_verify(id.verifying_key_bytes(), msg, &bad));
        // Wrong verifying key
        let other = PqcIdentity::from_seed(&[3u8; 32]);
        assert!(!pqc_verify(other.verifying_key_bytes(), msg, &sig));
        // Truncated signature
        assert!(!pqc_verify(id.verifying_key_bytes(), msg, &sig[..100]));
    }

    #[test]
    fn gate_is_fail_closed() {
        let id = PqcIdentity::from_seed(&[4u8; 32]);
        let msg = [7u8; 32]; // 32-byte "sighash"
        let good_sig = id.sign(&msg);
        let enclave_seed = [7u8; 32];

        // Valid PQC signature -> gate opens and releases a REAL BIP-340 sig.
        let released =
            enclave_sign_if_pqc_valid(id.verifying_key_bytes(), &good_sig, &msg, &enclave_seed)
                .expect("gate must open");
        // The released signature verifies under the enclave public key.
        let kp = enclave_keypair_from_seed(&enclave_seed).unwrap();
        let vk = enclave_xonly_public_key(&kp);
        let verify = Secp256k1::verification_only();
        let s = secp256k1::schnorr::Signature::from_slice(&released).unwrap();
        assert!(verify
            .verify_schnorr(&s, &Message::from_digest(msg), &vk)
            .is_ok());

        // Invalid PQC signature -> NO Schnorr signature (fail-closed).
        let mut bad_sig = good_sig;
        bad_sig[100] ^= 0x01;
        assert_eq!(
            enclave_sign_if_pqc_valid(id.verifying_key_bytes(), &bad_sig, &msg, &enclave_seed),
            Err(GateError::PqcVerificationFailed)
        );
    }

    #[test]
    fn gate_is_deterministic() {
        let id = PqcIdentity::from_seed(&[5u8; 32]);
        let msg = [8u8; 32];
        let sig = id.sign(&msg);
        let seed = [8u8; 32];
        let a = enclave_sign_if_pqc_valid(id.verifying_key_bytes(), &sig, &msg, &seed).unwrap();
        let b = enclave_sign_if_pqc_valid(id.verifying_key_bytes(), &sig, &msg, &seed).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn enclave_keypair_is_deterministic_and_distinct() {
        let a = enclave_keypair_from_seed(&[1u8; 32]).unwrap();
        let b = enclave_keypair_from_seed(&[1u8; 32]).unwrap();
        let c = enclave_keypair_from_seed(&[2u8; 32]).unwrap();
        assert_eq!(enclave_xonly_public_key(&a), enclave_xonly_public_key(&b));
        assert_ne!(enclave_xonly_public_key(&a), enclave_xonly_public_key(&c));
    }

    #[test]
    fn key_derivation_exhaustion_fails_closed_with_the_display_walls() {
        // 1000 consecutive misses → the Err arm (production cannot reach
        // it; the seam can, which is exactly why the seam exists).
        assert_eq!(
            keypair_from_derivation(|_| None).err(),
            Some(GateError::EnclaveKey)
        );
        // Every Display arm renders its own message.
        assert!(GateError::EnclaveKey.to_string().contains("enclave key"));
        assert!(GateError::SelfVerificationFailed
            .to_string()
            .contains("self-verification"));
        assert!(GateError::PqcVerificationFailed
            .to_string()
            .contains("fail-closed"));
    }

    #[test]
    fn self_verify_walls_reject_unparseable_and_wrong_bytes() {
        let kp = enclave_keypair_from_seed(&[9u8; 32]).unwrap();
        let vk = enclave_xonly_public_key(&kp);
        let msg = [1u8; 32];
        // r ≥ p (all-FF) → the signature does not even PARSE.
        assert_eq!(
            self_verify(&vk, &msg, &[0xFFu8; 64]),
            Err(GateError::SelfVerificationFailed)
        );
        // Parses (r=0 < p, s=0 < n) but does not verify → the second wall.
        assert_eq!(
            self_verify(&vk, &msg, &[0u8; 64]),
            Err(GateError::SelfVerificationFailed)
        );
        // Wrong length → parse wall as well.
        assert_eq!(
            self_verify(&vk, &msg, &[0u8; 32]),
            Err(GateError::SelfVerificationFailed)
        );
        // The REAL released signature passes the same check.
        let id = PqcIdentity::from_seed(&[9u8; 32]);
        let sig = id.sign(&msg);
        let released =
            enclave_sign_if_pqc_valid(id.verifying_key_bytes(), &sig, &msg, &[9u8; 32]).unwrap();
        assert!(self_verify(&vk, &msg, &released).is_ok());
    }

    #[test]
    fn pqc_verify_refuses_wrong_lengths_before_looking_at_any_crypto() {
        let id = PqcIdentity::from_seed(&[6u8; 32]);
        let msg = b"walls";
        let sig = id.sign(msg);
        // Verifying key of the wrong size never reaches decode.
        assert!(!pqc_verify(&[0u8; 100], msg, &sig));
        // Correct-size key, signature of the wrong size.
        assert!(!pqc_verify(id.verifying_key_bytes(), msg, &sig[..3_308]));
        assert!(!pqc_verify(&[0u8; 1_951], msg, &sig));
    }
}
