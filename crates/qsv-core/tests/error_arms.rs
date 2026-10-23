//! Round 30 coverage walls: every fail-closed arm and Display message of
//! qsv-core's PUBLIC surface, asserted behaviorally (the refusal text is
//! the contract — a test that only checks `is_err()` would not notice a
//! wall that stops refusing).

use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{
    absolute, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
};
use qsv_core::consensus::VerifyError;
use qsv_core::psbt::{self, PsbtError};
use qsv_core::taproot::{inheritance_script, TaprootError};
use qsv_core::unvault::{build_settlement_tx, build_unvault_tx, UnvaultError};
use qsv_core::wots::{self, WotsError};
use std::str::FromStr;

fn gen_xonly() -> XOnlyPublicKey {
    // secp256k1 generator point x-coordinate (always on the curve).
    XOnlyPublicKey::from_str("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
        .expect("generator x is a valid x-only key")
}

#[test]
fn budget_error_display_renders_both_walls() {
    use qsv_core::budget::BudgetError;
    assert_eq!(
        BudgetError::MissingControl("emergency leaf").to_string(),
        "control block missing for leaf emergency leaf"
    );
    assert_eq!(
        BudgetError::Tx("dust".into()).to_string(),
        "tx assembly error: dust"
    );
    let _: &dyn std::error::Error = &BudgetError::Tx("x".into());
}

#[test]
fn psbt_refusal_walls_and_the_sighash_display() {
    // Display: the sighash arm has no other way to run.
    assert_eq!(
        PsbtError::Sighash("bad tap leaf".into()).to_string(),
        "sighash error: bad tap leaf"
    );

    // empty_tap_scripts is the BIP-371 "no tap context" default.
    let empty = psbt::empty_tap_scripts();
    assert!(empty.is_empty());

    // A PSBT whose unsigned tx has ZERO inputs trips the wall first.
    let bare = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let mut psbt0 =
        bitcoin::Psbt::from_unsigned_tx(bare).expect("empty-input tx is a legal psbt shell");
    assert!(matches!(
        psbt::finalize_and_extract(&mut psbt0, Default::default()),
        Err(PsbtError::Malformed(m)) if m.contains("expected exactly one input")
    ));

    // Two-input shape: witness/input count mismatch refuses before extract.
    let tx2 = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            };
            2
        ],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let mut psbt2 = bitcoin::Psbt::from_unsigned_tx(tx2).expect("two-input tx shells fine");
    assert!(matches!(
        psbt::finalize_multi_input_and_extract(&mut psbt2, vec![Default::default()]),
        Err(PsbtError::Malformed(m)) if m.contains("witness count must equal")
    ));

    // One-input shape: out-of-range input index refuses before any sighash.
    let tx1 = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![],
    };
    let psbt1 = bitcoin::Psbt::from_unsigned_tx(tx1).expect("shell");
    assert!(matches!(
        psbt::sighash_multi_input(&psbt1, 7, &ScriptBuf::new()),
        Err(PsbtError::Malformed(m)) if m.contains("no such input")
    ));
}

#[test]
fn build_multi_input_psbt_refuses_an_empty_set() {
    assert!(matches!(
        psbt::build_multi_input_psbt(&[], vec![], gen_xonly()),
        Err(PsbtError::Malformed(m)) if m.contains("no inputs supplied")
    ));
}

#[test]
fn unvault_walls_and_displays() {
    assert_eq!(
        UnvaultError::InsufficientFunds.to_string(),
        "insufficient funds after fee deduction"
    );
    assert_eq!(
        UnvaultError::OutpointMismatch.to_string(),
        "vault outpoint metadata mismatch"
    );
    assert_eq!(
        UnvaultError::Encode("x".into()).to_string(),
        "encode error: x"
    );

    let op = OutPoint::null();
    let spk = ScriptBuf::new();
    // Fee above the input value → checked_sub wall.
    assert_eq!(
        build_unvault_tx(op, Amount::from_sat(100), &spk, Amount::from_sat(200)),
        Err(UnvaultError::InsufficientFunds)
    );
    // Leftover below the 546-sat dust floor → the second wall.
    assert_eq!(
        build_unvault_tx(op, Amount::from_sat(1_000), &spk, Amount::from_sat(600)),
        Err(UnvaultError::InsufficientFunds)
    );
    // Settlement keeps the same two walls (330-sat floor).
    assert_eq!(
        build_settlement_tx(op, Amount::from_sat(100), &spk, Amount::from_sat(200), 144),
        Err(UnvaultError::InsufficientFunds)
    );
    assert_eq!(
        build_settlement_tx(op, Amount::from_sat(500), &spk, Amount::from_sat(300), 144),
        Err(UnvaultError::InsufficientFunds)
    );
}

#[test]
fn taproot_walls_and_displays() {
    assert_eq!(
        TaprootError::Builder("x".into()).to_string(),
        "taproot builder error: x"
    );
    assert_eq!(
        TaprootError::Script("x".into()).to_string(),
        "script error: x"
    );
    // Threshold out of range: fewer than two keys, and k beyond the set.
    let pk = gen_xonly();
    assert!(matches!(
        inheritance_script(&[pk], 1),
        Err(TaprootError::Script(s)) if s.contains("threshold out of range")
    ));
    assert!(inheritance_script(&[pk, pk], 0).is_err());
    assert!(inheritance_script(&[pk, pk], 3).is_err());
}

#[test]
fn wots_refusal_walls_render_their_own_messages() {
    let (pk, sk) = wots::keypair_from_seed(&[7u8; wots::N]);
    let msg = [9u8; wots::N];
    let sig = wots::sign(&sk, &msg).expect("signs");
    // Truncated signature → size wall with both numbers in the message.
    let err = wots::verify(&pk, &msg, &sig[..100]).unwrap_err();
    assert!(matches!(err, WotsError::BadSize { .. }));
    assert!(
        err.to_string()
            .contains("bad WOTS+ buffer size (expected 2144, got 100)"),
        "{err}"
    );
    // Right size, tampered content → verification wall.
    let mut bad = sig;
    bad[0] ^= 0xFF;
    let err = wots::verify(&pk, &msg, &bad).unwrap_err();
    assert_eq!(err, WotsError::VerificationFailed);
    assert_eq!(err.to_string(), "WOTS+ verification failed");
    let _: &dyn std::error::Error = &err;
}

#[test]
fn consensus_display_and_the_engine_error_arm() {
    assert_eq!(
        VerifyError::Encode("x".into()).to_string(),
        "encode error: x"
    );
    // A well-formed tx with an OUT-OF-RANGE input index maps the engine's
    // ERR_TX_INDEX through the non-ERR_SCRIPT arm of `verify_input`.
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![],
    };
    let spk = ScriptBuf::new();
    #[cfg(feature = "consensus")]
    {
        let err = qsv_core::consensus::verify_input(&tx, 5, &spk, Amount::from_sat(1_000))
            .expect_err("index 5 does not exist");
        assert!(matches!(err, VerifyError::ScriptFailed(code) if code != 0));
    }
    #[cfg(not(feature = "consensus"))]
    {
        let _ = (tx, spk);
    }
}
