//! Watchtower↔co-signer INTEGRATION (docs/10 §3.2): the alarm mirror.
//!
//! The daemon's read-only pass decides DUE/undue per vault; the co-signer
//! is the enforcement point. These tests pin the wiring contract:
//!   1. CLEAR → a valid PQC-proofed request releases the co-signature
//!      (Theorem 1 path unchanged).
//!   2. ALARM DOMINATES CRYPTO: with the alarm mirrored, the SAME valid
//!      request is refused — even a perfectly proven ML-DSA-65 identity
//!      cannot shortcut a frozen vault (fail-closed).
//!   3. FREEZE IS PER-VAULT: a sibling vault keeps signing.
//!   4. OPERATOR CLEAR after a verified refresh restores the exact
//!      deterministic release (same request → same signature).
//!   5. REBOOT HYGIENE: a reloaded provisioning descriptor starts with no
//!      alarms mirrored (the daemon re-raises them on its first pass).

use qsv_cosigner::{AlarmState, Cosigner, SignRequest};
use qsv_pqc::PqcIdentity;
use secp256k1::Secp256k1;

const VAULT_A: &str = "bc1ptestvault-a";
const VAULT_B: &str = "bc1ptestvault-b";

fn cosigner() -> Cosigner {
    Cosigner::provision([42u8; 32], vec![VAULT_A.into(), VAULT_B.into()])
}

fn valid_request(vault_id: &str) -> SignRequest {
    let pqc = PqcIdentity::from_seed(&[11u8; 32]);
    let sighash = [0xABu8; 32];
    SignRequest::new(
        vault_id,
        &sighash,
        pqc.verifying_key_bytes(),
        &pqc.sign(&sighash),
    )
}

#[test]
fn clear_vault_releases_signature_through_the_normal_gate() {
    let c = cosigner();
    assert_eq!(c.alarm_state(VAULT_A), AlarmState::Clear);

    let resp = c.handle_request(&valid_request(VAULT_A)).unwrap();
    assert!(resp.accepted, "clear vault must sign: {resp:?}");
    let sig_hex = resp.schnorr_sig_hex.clone().unwrap();
    let sig_bytes: [u8; 64] = hex::decode(&sig_hex).unwrap().try_into().unwrap();

    // The released signature verifies under the co-signer's public key —
    // the freeze must never alter WHAT is signed, only WHETHER.
    let vk = c.public_key().unwrap();
    let verify = Secp256k1::verification_only();
    assert!(verify
        .verify_schnorr(
            &secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap(),
            &secp256k1::Message::from_digest([0xABu8; 32]),
            &vk,
        )
        .is_ok());
}

#[test]
fn mirrored_alarm_freezes_the_vault_even_against_valid_crypto() {
    let mut c = cosigner();
    let req = valid_request(VAULT_A);

    c.set_alarm(VAULT_A);
    assert_eq!(c.alarm_state(VAULT_A), AlarmState::Alarm);
    assert_eq!(c.alarmed_vaults(), vec![VAULT_A.to_string()]);

    let resp = c.handle_request(&req).unwrap();
    assert!(!resp.accepted, "an alarmed vault must NOT sign");
    assert!(resp
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("watchtower alarm active"));
    assert!(resp.schnorr_sig_hex.is_none());
    assert!(resp.attestation_doc_hex.is_none());
}

#[test]
fn freeze_is_per_vault_and_clear_restores_determinism() {
    let mut c = cosigner();

    // Sibling vault keeps signing while A is frozen.
    c.set_alarm(VAULT_A);
    let resp_b = c.handle_request(&valid_request(VAULT_B)).unwrap();
    assert!(resp_b.accepted, "the freeze must not leak across vaults");

    // Operator clear after the verified refresh: the exact same request
    // releases the exact same signature as a never-alarmed cosigner.
    c.clear_alarm(VAULT_A);
    let resp_a = c.handle_request(&valid_request(VAULT_A)).unwrap();
    assert!(resp_a.accepted);
    let pristine = cosigner().handle_request(&valid_request(VAULT_A)).unwrap();
    assert_eq!(
        resp_a.schnorr_sig_hex, pristine.schnorr_sig_hex,
        "alarm round trip must not perturb the deterministic release"
    );
}

#[test]
fn provisioning_reload_starts_with_no_alarms() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("provisioning.json");

    let mut c = cosigner();
    c.set_alarm(VAULT_A);
    c.save_provisioning(&path).unwrap();

    let loaded = Cosigner::load_provisioning(&path).unwrap();
    assert_eq!(loaded.alarm_state(VAULT_A), AlarmState::Clear);
    assert!(loaded.alarmed_vaults().is_empty());
    // And the freshly booted enclave signs again (the daemon re-raises
    // alarms from the persisted watchtower state on its next pass).
    assert!(
        loaded
            .handle_request(&valid_request(VAULT_A))
            .unwrap()
            .accepted
    );
}
