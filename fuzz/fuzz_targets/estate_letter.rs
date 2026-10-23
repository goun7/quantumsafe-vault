//! Fuzz target: the estate-letter parser and verifier (docs/07).
//!
//! The letter is the ONE artifact a family receives after the owner is
//! gone — its text arrives from paper, OCR, a USB stick, a translator.
//! `parse_letter` (section walker) and `verify_letter` (base58/bech32
//! decodes + digest/threshold recomputation against the real vault) must
//! answer with data — never a panic — for ANY string on ANY network.
#![no_main]
use libfuzzer_sys::fuzz_target;
use qsv_core::demo_keys;
use qsv_core::estate;
use qsv_core::taproot::VaultTaproot;
use std::sync::OnceLock;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    // The section parser is the cheap front door: any string → ParsedLetter.
    let _parsed = estate::parse_letter(&text);

    // The verifier additionally recomputes against a REAL vault. The tap
    // tree is deterministic demo material — derive it ONCE so the fuzz
    // budget goes to the parser, not to MAST rebuilding per input.
    static VAULT: OnceLock<VaultTaproot> = OnceLock::new();
    let vault = VAULT.get_or_init(|| {
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[demo_keys::heir_one(), demo_keys::heir_two()],
            2,
        )
        .expect("demo vault must derive")
    });

    // Every network: address encodings differ, so the decode paths differ.
    for network in [
        bitcoin::Network::Bitcoin,
        bitcoin::Network::Testnet,
        bitcoin::Network::Signet,
        bitcoin::Network::Regtest,
    ] {
        let checks = estate::verify_letter(&text, vault, network);
        // The verifier's own contract: 4 identity fields + 4 leaf scripts —
        // a fixed-width report, never partial.
        assert_eq!(checks.len(), 8, "verify_letter must report every check");
    }
});
