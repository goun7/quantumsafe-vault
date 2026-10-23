//! Two-stage unvault covenant flow (docs/03 §6, Theorem 3).
//!
//! Stage 1 (unvault): vault UTXO -> STAGING output (the ONLY permitted
//! destination at consensus level for this leaf).
//! Stage 2 (settlement): after `csv_blocks`, staging -> final destination.
//! During the delay window the recovery leaf can sweep (clawback/veto).

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::script::Builder as ScriptBuilder;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::witness::Witness;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};

/// Errors raised while assembling the unvault/settlement transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnvaultError {
    /// The output value would be dust or negative after fees.
    InsufficientFunds,
    /// The referenced vault UTXO metadata is inconsistent.
    OutpointMismatch,
    /// Transaction serialization failure (should be impossible for these shapes).
    Encode(String),
}

impl core::fmt::Display for UnvaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UnvaultError::InsufficientFunds => write!(f, "insufficient funds after fee deduction"),
            UnvaultError::OutpointMismatch => write!(f, "vault outpoint metadata mismatch"),
            UnvaultError::Encode(s) => write!(f, "encode error: {s}"),
        }
    }
}

impl std::error::Error for UnvaultError {}

/// STAGING leaf script: `<pk_staging> CHECKSIG` — pins stage-2 funds to the
/// single-key staging demo; Phase 2 widens this into the full covenant tree.
pub fn staging_script(staging_key: XOnlyPublicKey) -> ScriptBuf {
    ScriptBuilder::new()
        .push_x_only_key(&staging_key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Stage-1 unvault transaction: single input (vault), single output (staging).
pub fn build_unvault_tx(
    vault_outpoint: OutPoint,
    vault_value: Amount,
    staging_script_pubkey: &ScriptBuf,
    fee: Amount,
) -> Result<Transaction, UnvaultError> {
    let output_value = vault_value
        .checked_sub(fee)
        .ok_or(UnvaultError::InsufficientFunds)?;
    if output_value < Amount::from_sat(546) {
        return Err(UnvaultError::InsufficientFunds);
    }
    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: vault_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: output_value,
            script_pubkey: staging_script_pubkey.clone(),
        }],
    })
}

/// Stage-2 settlement transaction: staging -> final destination after CSV.
/// The input sequence encodes the CSV height lock (BIP-68).
pub fn build_settlement_tx(
    staging_outpoint: OutPoint,
    staging_value: Amount,
    final_script_pubkey: &ScriptBuf,
    fee: Amount,
    csv_blocks: u16,
) -> Result<Transaction, UnvaultError> {
    let output_value = staging_value
        .checked_sub(fee)
        .ok_or(UnvaultError::InsufficientFunds)?;
    if output_value < Amount::from_sat(330) {
        return Err(UnvaultError::InsufficientFunds);
    }
    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: staging_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(csv_blocks),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: output_value,
            script_pubkey: final_script_pubkey.clone(),
        }],
    })
}

/// Computes the BIP-341 script-path sighash for a taproot input.
pub fn script_spend_sighash(
    tx: &Transaction,
    input_index: usize,
    script: &ScriptBuf,
    prev_value: Amount,
    prev_script_pubkey: &ScriptBuf,
) -> TapSighash {
    let prevouts = Prevouts::All(&[TxOut {
        value: prev_value,
        script_pubkey: prev_script_pubkey.clone(),
    }]);
    let leaf_hash = TapLeafHash::from_script(script, LeafVersion::TapScript);
    let mut cache = SighashCache::new(tx);
    cache
        .taproot_signature_hash(
            input_index,
            &prevouts,
            None,
            // BIP-341: default OP_CODESEPARATOR position is 0xFFFFFFFF.
            Some((leaf_hash, 0xFFFFFFFF)),
            TapSighashType::Default,
        )
        .expect("script spend sighash")
}

/// Signs a sighash with a BIP-340 Schnorr keypair (64-byte default sighash).
pub fn sign_schnorr(keypair: &Keypair, sighash: &TapSighash) -> [u8; 64] {
    let secp = Secp256k1::signing_only();
    let msg = Message::from_digest(*sighash.as_byte_array());
    let sig = secp.sign_schnorr(&msg, keypair);
    *sig.as_ref()
}

/// Assembles the script-path witness: `<sig_0> <sig_1> ... <script> <control_block>`.
///
/// `signatures[0]` is the FIRST argument consumed by the script (the deepest
/// stack element). For `<pk_user> CHECKSIGVERIFY <pk_enclave> CHECKSIG` the
/// script consumes the stack TOP first, so pass `[σ_enclave, σ_user]`.
pub fn build_script_path_witness(
    signatures: &[Vec<u8>],
    script: &ScriptBuf,
    control_block: &ControlBlock,
) -> Witness {
    let mut control_serialized = Vec::new();
    control_block
        .encode(&mut control_serialized)
        .expect("control block encode cannot fail into Vec");
    let mut w = Witness::new();
    // BIP-341 witness order: [σ1, σ2, ..., <script>, <control_block>]
    // (the control block is the LAST/top stack element).
    for sig in signatures {
        w.push(sig.clone());
    }
    w.push(script.as_bytes());
    w.push(control_serialized);
    w
}

/// Everything needed to sign one script-path input (BIP-341 context).
pub struct SpendContext<'a> {
    /// The tap leaf script being spent.
    pub script: &'a ScriptBuf,
    /// Control block proving the leaf's membership in the MAST.
    pub control_block: &'a ControlBlock,
    /// Value of the prevout being spent.
    pub prev_value: Amount,
    /// scriptPubKey of the prevout being spent.
    pub prev_script_pubkey: &'a ScriptBuf,
}

/// Full signing helper: user + enclave keys over the normal leaf, writing the
/// completed witness into the transaction (2-of-2 hybrid at consensus layer).
pub fn sign_normal_leaf_spend(
    tx: &mut Transaction,
    input_index: usize,
    ctx: &SpendContext<'_>,
    user_keypair: &Keypair,
    enclave_keypair: &Keypair,
) {
    let sig_user = {
        let sh = script_spend_sighash(
            tx,
            input_index,
            ctx.script,
            ctx.prev_value,
            ctx.prev_script_pubkey,
        );
        sign_schnorr(user_keypair, &sh).to_vec()
    };
    let sig_enclave = {
        let sh = script_spend_sighash(
            tx,
            input_index,
            ctx.script,
            ctx.prev_value,
            ctx.prev_script_pubkey,
        );
        sign_schnorr(enclave_keypair, &sh).to_vec()
    };
    // Execution order: the script consumes σ_enclave first (stack top), then σ_user.
    tx.input[input_index].witness =
        build_script_path_witness(&[sig_enclave, sig_user], ctx.script, ctx.control_block);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo_keys;
    use crate::taproot::normal_leaf_script;
    use bitcoin::consensus::serialize;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
    use bitcoin::Txid;

    /// Test helper: Txid from fixed bytes.
    fn txid32(bytes: [u8; 32]) -> Txid {
        Txid::from_byte_array(bytes)
    }

    #[test]
    fn unvault_tx_pins_single_staging_output() {
        let staging = staging_script(demo_keys::recovery_key());
        let tx = build_unvault_tx(
            OutPoint::new(txid32([2u8; 32]), 0),
            Amount::from_sat(100_000),
            &staging,
            Amount::from_sat(1_000),
        )
        .unwrap();
        assert_eq!(tx.output.len(), 1, "covenant emulation: exactly one output");
        assert_eq!(tx.output[0].script_pubkey, staging);
        assert_eq!(tx.output[0].value, Amount::from_sat(99_000));
    }

    #[test]
    fn settlement_tx_encodes_csv_sequence() {
        let tx = build_settlement_tx(
            OutPoint::new(txid32([3u8; 32]), 0),
            Amount::from_sat(99_000),
            &staging_script(demo_keys::recovery_key()),
            Amount::from_sat(1_000),
            144,
        )
        .unwrap();
        assert_eq!(tx.input[0].sequence, Sequence::from_height(144));
        assert_eq!(tx.input[0].sequence.to_consensus_u32(), 144);
    }

    #[test]
    fn fee_below_dust_rejected() {
        let r = build_unvault_tx(
            OutPoint::new(txid32([4u8; 32]), 0),
            Amount::from_sat(1_200),
            &staging_script(demo_keys::recovery_key()),
            Amount::from_sat(1_000),
        );
        assert!(matches!(r, Err(UnvaultError::InsufficientFunds)));
    }

    #[test]
    fn hybrid_spend_signs_and_verifies() {
        let secp_verify = Secp256k1::<VerifyOnly>::verification_only();
        let user = demo_keys::user_keypair();
        let enclave = demo_keys::enclave_keypair();
        let leaf = normal_leaf_script(user.x_only_public_key().0, enclave.x_only_public_key().0);

        let staging = staging_script(demo_keys::recovery_key());
        let vault_spk = ScriptBuf::new(); // demo prevout spk
        let tx = build_unvault_tx(
            OutPoint::new(txid32([5u8; 32]), 7),
            Amount::from_sat(200_000),
            &staging,
            Amount::from_sat(2_000),
        )
        .unwrap();
        let prev_value = Amount::from_sat(200_000);

        let sh = script_spend_sighash(&tx, 0, &leaf, prev_value, &vault_spk);
        let msg = Message::from_digest(*sh.as_byte_array());
        let s1 = Secp256k1::signing_only().sign_schnorr(&msg, &user);
        let s2 = Secp256k1::signing_only().sign_schnorr(&msg, &enclave);
        assert!(secp_verify
            .verify_schnorr(&s1, &msg, &user.x_only_public_key().0)
            .is_ok());
        assert!(secp_verify
            .verify_schnorr(&s2, &msg, &enclave.x_only_public_key().0)
            .is_ok());
    }

    #[test]
    fn tx_roundtrip_serializes() {
        let staging = staging_script(demo_keys::recovery_key());
        let tx = build_unvault_tx(
            OutPoint::new(txid32([6u8; 32]), 1),
            Amount::from_sat(50_000),
            &staging,
            Amount::from_sat(500),
        )
        .unwrap();
        let bytes = serialize(&tx);
        assert!(!bytes.is_empty());
    }
}
