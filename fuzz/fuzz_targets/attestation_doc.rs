//! Fuzz target: the NSM attestation document parser (docs/09 §nsm).
//!
//! `verify_attestation_doc` is the gate that decides whether a
//! co-signature may be released: it hex-decodes then CBOR-parses a
//! document that, in production, arrives over vsock from the enclave
//! boundary. Any panic here is a remote crash of the co-signer; any
//! hang is a stalled bridge. The harness exercises BOTH entry shapes —
//! raw bytes hex-encoded (valid hex, adversarial CBOR) and the lossy
//! UTF-8 string as-is (adversarial hex).
#![no_main]
use libfuzzer_sys::fuzz_target;
use qsv_cosigner::nsm::{verify_attestation_doc, PinnedMeasurements};

fuzz_target!(|data: &[u8]| {
    let pinned = PinnedMeasurements {
        pcr0_hex: String::new(),
        pcr1_hex: String::new(),
        pcr2_hex: String::new(),
        vault_id: "bc1pfuzz".into(),
        // Empty pin skips the user_data key-binding check (it needs a
        // document that actually binds a key); the shape of that check
        // is exercised by the unit tests in nsm.rs.
        enclave_xonly_hex: String::new(),
    };
    let nonce = hex::encode(&data[..data.len().min(32)]);
    // Shape 1: well-formed hex wrapping adversarial CBOR bytes.
    let _ = verify_attestation_doc(&hex::encode(data), &pinned, &nonce);
    // Shape 2: adversarial text hitting the hex decoder directly.
    let _ = verify_attestation_doc(&String::from_utf8_lossy(data), &pinned, &nonce);
});
