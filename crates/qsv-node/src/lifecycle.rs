//! Vault lifecycle transaction builders driven by real chain state.
//!
//! The caller supplies confirmed UTXOs; this module produces fully signed,
//! broadcast-ready transactions and verifies them through
//! `qsv_core::consensus` before returning them.

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};
use bitcoin::transaction::Version;
use bitcoin::witness::Witness;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use qsv_core::taproot::VaultTaproot;
use qsv_core::unvault;

/// A confirmed UTXO of the vault (or staging) as reported by chain state.
#[derive(Debug, Clone)]
pub struct LiveUtxo {
    pub outpoint: OutPoint,
    pub value: Amount,
    pub script_pubkey: ScriptBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    InsufficientFunds,
    Consensus(qsv_core::consensus::VerifyError),
}

impl core::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LifecycleError::InsufficientFunds => write!(f, "insufficient funds"),
            LifecycleError::Consensus(e) => write!(f, "consensus rejected: {e}"),
        }
    }
}

impl std::error::Error for LifecycleError {}

fn p2tr_spk(out_key: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(out_key.serialize())
        .into_script()
}

/// Derives the BIP-341 tweaked output key for a key-path-only output whose
/// internal key is `staging_key` (empty merkle root).
fn out_key_tweaked(staging_key: XOnlyPublicKey) -> XOnlyPublicKey {
    key_path_output_key(staging_key)
}

fn key_path_output_key(staging_key: XOnlyPublicKey) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let tweak = bitcoin::taproot::TapTweakHash::from_key_and_tweak(staging_key, None).to_scalar();
    staging_key
        .add_tweak(&secp, &tweak)
        .expect("tweak within curve order (BIP-341)")
        .0
}

/// Key-path sighash (BIP-341): leaf-hash field is absent, codeseparator n/a.
fn key_path_sighash(
    tx: &Transaction,
    input_index: usize,
    prev_value: Amount,
    prev_script_pubkey: &ScriptBuf,
) -> [u8; 32] {
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    let prevouts = Prevouts::All(&[TxOut {
        value: prev_value,
        script_pubkey: prev_script_pubkey.clone(),
    }]);
    let mut cache = SighashCache::new(tx);
    let sh = cache
        .taproot_signature_hash(input_index, &prevouts, None, None, TapSighashType::Default)
        .expect("key path sighash");
    use bitcoin::hashes::Hash as _;
    sh.to_byte_array()
}

/// The unvault request handed to the PQC gate: sighash + user signature.
pub struct UnvaultIntent {
    /// The unsigned stage-1 transaction (single staging output).
    pub tx: Transaction,
    /// The 32-byte BIP-341 script-path sighash of input 0.
    pub sighash: [u8; 32],
    /// Control block of the normal leaf.
    pub control: bitcoin::taproot::ControlBlock,
    /// The user's BIP-340 signature over `sighash` (64 bytes).
    pub sig_user: Vec<u8>,
}

/// Builds the unsigned stage-1 unvault transaction (vault → staging P2TR)
/// and returns everything the caller needs to run the PQC gate exchange:
/// the exact sighash the enclave will co-sign and the user's signature.
pub fn prepare_unvault(
    vault: &VaultTaproot,
    utxo: &LiveUtxo,
    staging_destination_key: XOnlyPublicKey,
    fee: Amount,
    user_keypair: &Keypair,
) -> Result<UnvaultIntent, LifecycleError> {
    let out_value = utxo
        .value
        .checked_sub(fee)
        .ok_or(LifecycleError::InsufficientFunds)?;
    let staging_output_key = key_path_output_key(staging_destination_key);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: out_value,
            script_pubkey: p2tr_spk(staging_output_key),
        }],
    };

    let control = vault
        .spend_info
        .control_block(&(
            vault.leaves.normal.clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .expect("control block for normal leaf");
    let sighash = unvault::script_spend_sighash(
        &tx,
        0,
        &vault.leaves.normal,
        utxo.value,
        &utxo.script_pubkey,
    );
    let sig_user = unvault::sign_schnorr(user_keypair, &sighash).to_vec();
    Ok(UnvaultIntent {
        tx,
        sighash: sighash.to_byte_array(),
        control,
        sig_user,
    })
}

/// Binds the PQC-gated enclave co-signature (released over `intent.sighash`)
/// into the witness and self-verifies with libbitcoinconsensus.
pub fn finalize_unvault(
    vault: &VaultTaproot,
    utxo: &LiveUtxo,
    intent: UnvaultIntent,
    enclave_sig: [u8; 64],
) -> Result<Transaction, LifecycleError> {
    let mut tx = intent.tx;
    // Execution order: script consumes σ_enclave (stack top) then σ_user.
    tx.input[0].witness = unvault::build_script_path_witness(
        &[enclave_sig.to_vec(), intent.sig_user],
        &vault.leaves.normal,
        &intent.control,
    );
    qsv_core::consensus::verify_input(&tx, 0, &utxo.script_pubkey, utxo.value)
        .map_err(LifecycleError::Consensus)?;
    Ok(tx)
}

/// Builds + signs the stage-1 unvault transaction (vault → staging P2TR)
/// through the hybrid leaf and self-verifies it with libbitcoinconsensus.
///
/// `enclave_sig` is the PQC-gated co-signature released by the enclave gate
/// over the SAME sighash — use `prepare_unvault` to obtain that sighash.
pub fn build_unvault(
    vault: &VaultTaproot,
    utxo: &LiveUtxo,
    staging_destination_key: XOnlyPublicKey,
    fee: Amount,
    user_keypair: &Keypair,
    enclave_sig: [u8; 64],
) -> Result<Transaction, LifecycleError> {
    let out_value = utxo
        .value
        .checked_sub(fee)
        .ok_or(LifecycleError::InsufficientFunds)?;
    // Staging output: P2TR key-path-only output locked to the tweaked
    // staging key (a standard, consensus-clean scriptPubKey type).
    let staging_output_key = key_path_output_key(staging_destination_key);
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: out_value,
            script_pubkey: p2tr_spk(staging_output_key),
        }],
    };

    let control = vault
        .spend_info
        .control_block(&(
            vault.leaves.normal.clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .expect("control block for normal leaf");
    let ctx = unvault::SpendContext {
        script: &vault.leaves.normal,
        control_block: &control,
        prev_value: utxo.value,
        prev_script_pubkey: &utxo.script_pubkey,
    };

    // σ_user locally; σ_enclave comes pre-released from the PQC gate. The
    // script consumes the stack top first: execution order [σ_enclave, σ_user].
    let sig_user = {
        let sh = unvault::script_spend_sighash(
            &tx,
            0,
            ctx.script,
            ctx.prev_value,
            ctx.prev_script_pubkey,
        );
        unvault::sign_schnorr(user_keypair, &sh).to_vec()
    };
    tx.input[0].witness = unvault::build_script_path_witness(
        &[enclave_sig.to_vec(), sig_user],
        ctx.script,
        ctx.control_block,
    );

    // Consensus-level self-check before the caller ever broadcasts.
    qsv_core::consensus::verify_input(&tx, 0, &utxo.script_pubkey, utxo.value)
        .map_err(LifecycleError::Consensus)?;
    Ok(tx)
}

/// Builds + signs the stage-2 settlement (staging → final destination) after
/// CSV maturity. The staging output is a P2TR key-path-only output: the
/// signature must be produced with the TWEAKED secret key
/// `sk' = sk + H_taptweak(P)` (BIP-341 §3). The input sequence encodes
/// `csv_blocks` (BIP-68).
pub fn build_settlement(
    staging_utxo: &LiveUtxo,
    staging_keypair: &Keypair,
    final_destination: XOnlyPublicKey,
    fee: Amount,
    csv_blocks: u16,
) -> Result<Transaction, LifecycleError> {
    let out_value = staging_utxo
        .value
        .checked_sub(fee)
        .ok_or(LifecycleError::InsufficientFunds)?;
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: staging_utxo.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(csv_blocks),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: out_value,
            // Demo destination is a plain P2TR key-path spend.
            script_pubkey: p2tr_spk(final_destination),
        }],
    };

    // KEY-PATH spend of the staging P2TR output: the witness is exactly one
    // 64-byte BIP-340 signature under the TWEAKED keypair
    // (sk' = sk + H_taptweak(P); BIP-341 §3).
    let (staging_key, parity) = staging_keypair.x_only_public_key();
    let tweak = bitcoin::taproot::TapTweakHash::from_key_and_tweak(staging_key, None).to_scalar();
    // BIP-341: if the keypair's pubkey has ODD parity, the x-only key's
    // discrete log is n - sk, so the tweaked scalar is (n - sk) + t.
    let base_sk = if parity == secp256k1::Parity::Odd {
        staging_keypair.secret_key().negate()
    } else {
        staging_keypair.secret_key()
    };
    let tweaked_sk = base_sk
        .add_tweak(&tweak)
        .expect("tweaked scalar valid (BIP-341)");
    let tweaked_kp =
        secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::signing_only(), &tweaked_sk);
    let sh = key_path_sighash(&tx, 0, staging_utxo.value, &staging_utxo.script_pubkey);
    let msg = secp256k1::Message::from_digest(sh);
    let secp_sign = secp256k1::Secp256k1::signing_only();
    let sig = secp_sign.sign_schnorr_with_aux_rand(&msg, &tweaked_kp, &[0u8; 32]);
    // Self-check: released signature must verify under the tweaked pubkey.
    let secp_verify = secp256k1::Secp256k1::verification_only();
    secp_verify
        .verify_schnorr(&sig, &msg, &out_key_tweaked(staging_key))
        .expect("key-path signature must self-verify");
    let mut w = Witness::new();
    w.push(*sig.as_ref());
    tx.input[0].witness = w;

    qsv_core::consensus::verify_input(&tx, 0, &staging_utxo.script_pubkey, staging_utxo.value)
        .map_err(LifecycleError::Consensus)?;
    Ok(tx)
}

/// The full chain-state summary the e2e test prints for the runbook.
pub fn lifecycle_report(
    vault: &VaultTaproot,
    unvault_tx: &Transaction,
    settle_tx: &Transaction,
) -> String {
    format!(
        "vault={} unvault_witness={} settle_witness={}",
        vault.address(bitcoin::Network::Regtest),
        unvault_tx.input[0].witness.len(),
        settle_tx.input[0].witness.len(),
    )
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use qsv_core::demo_keys;
    use qsv_core::taproot::VaultTaproot;

    #[test]
    fn tweak_derivation_paths_agree() {
        use bitcoin::taproot::{TapTweakHash, TaprootBuilder};
        let staging_kp = demo_keys::recovery_keypair();
        let k: XOnlyPublicKey = staging_kp.x_only_public_key().0;
        let secp = Secp256k1::verification_only();
        // Path A: manual TapTweakHash + add_tweak
        let a = TapTweakHash::from_key_and_tweak(k, None).to_scalar();
        let manual = k.add_tweak(&secp, &a).unwrap().0;
        // Path B: TaprootSpendInfo (canonical)
        let info = TaprootBuilder::new()
            .finalize(&secp, k)
            .expect("empty tree finalizes");
        let canonical = info.output_key();
        assert_eq!(manual, canonical.into(), "tweak paths must agree");
    }

    #[test]
    fn key_path_settlement_verifies_under_consensus() {
        let staging_kp = demo_keys::recovery_keypair();
        let staging_key = staging_kp.x_only_public_key().0;
        let out_key = key_path_output_key(staging_key);
        let spk = p2tr_spk(out_key);
        let dest = demo_keys::heir_one();

        let staging_utxo = LiveUtxo {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([9u8; 32]), 0),
            value: Amount::from_sat(100_000),
            script_pubkey: spk,
        };
        let tx = build_settlement(
            &staging_utxo,
            &staging_kp,
            dest,
            Amount::from_sat(1_000),
            144,
        )
        .expect("key-path settlement must be consensus-valid");
        assert_eq!(tx.input[0].witness.len(), 1);
    }

    /// BIP-341 parity: an EVEN x-only staging key needs NO negation of
    /// the discrete log — the tweak math must self-verify and pass
    /// consensus either way (the demo keys happen to be Odd).
    #[test]
    fn settlement_signs_under_an_even_parity_staging_key() {
        let secp = secp256k1::Secp256k1::signing_only();
        let staging_kp = (1u32..)
            .find_map(|i| {
                let mut sk = [0u8; 32];
                sk[28..].copy_from_slice(&i.to_be_bytes());
                let sk = secp256k1::SecretKey::from_slice(&sk).ok()?;
                let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
                (kp.x_only_public_key().1 == secp256k1::Parity::Even).then_some(kp)
            })
            .expect("half the keys are Even");
        assert_eq!(staging_kp.x_only_public_key().1, secp256k1::Parity::Even);
        let staging_key = staging_kp.x_only_public_key().0;
        let spk = p2tr_spk(key_path_output_key(staging_key));
        let staging_utxo = LiveUtxo {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([6u8; 32]), 0),
            value: Amount::from_sat(100_000),
            script_pubkey: spk,
        };
        let tx = build_settlement(
            &staging_utxo,
            &staging_kp,
            demo_keys::heir_one(),
            Amount::from_sat(1_000),
            144,
        )
        .expect("the Even branch must produce a consensus-valid settlement");
        assert_eq!(tx.input[0].witness.len(), 1);
    }

    #[test]
    fn unvault_flow_verifies_under_consensus() {
        let secp = Secp256k1::verification_only();
        let enclave_seed = [42u8; 32];
        let enclave_kp = qsv_pqc::enclave_keypair_from_seed(&enclave_seed).unwrap();
        let enclave_pk = qsv_pqc::enclave_xonly_public_key(&enclave_kp);
        let vault = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            enclave_pk,
            demo_keys::recovery_key(),
            &[demo_keys::heir_one(), demo_keys::heir_two()],
            2,
        )
        .unwrap();
        let out_key: XOnlyPublicKey = vault.output_key();
        let spk = p2tr_spk(out_key);
        let utxo = LiveUtxo {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([8u8; 32]), 0),
            value: Amount::from_sat(200_000),
            script_pubkey: spk,
        };
        let staging_kp = demo_keys::recovery_keypair();
        let intent = prepare_unvault(
            &vault,
            &utxo,
            staging_kp.x_only_public_key().0,
            Amount::from_sat(2_000),
            &demo_keys::user_keypair(),
        )
        .unwrap();
        let pqc = qsv_pqc::PqcIdentity::from_seed(&[77u8; 32]);
        let pqc_sig = pqc.sign(&intent.sighash);
        let enclave_sig = qsv_pqc::enclave_sign_if_pqc_valid(
            pqc.verifying_key_bytes(),
            &pqc_sig,
            &intent.sighash,
            &enclave_seed,
        )
        .unwrap();
        let tx = finalize_unvault(&vault, &utxo, intent, enclave_sig).unwrap();
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    #[test]
    fn build_unvault_direct_report_and_fail_closed_paths() {
        let secp = Secp256k1::verification_only();
        let enclave_seed = [43u8; 32];
        let enclave_kp = qsv_pqc::enclave_keypair_from_seed(&enclave_seed).unwrap();
        let enclave_pk = qsv_pqc::enclave_xonly_public_key(&enclave_kp);
        let vault = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            enclave_pk,
            demo_keys::recovery_key(),
            &[demo_keys::heir_one(), demo_keys::heir_two()],
            2,
        )
        .unwrap();
        let utxo = LiveUtxo {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([7u8; 32]), 0),
            value: Amount::from_sat(300_000),
            script_pubkey: p2tr_spk(vault.output_key()),
        };
        let staging_kp = demo_keys::recovery_keypair();
        let staging_xonly = staging_kp.x_only_public_key().0;

        // The one-shot builder runs the SAME gate flow: fetch the sighash
        // (prepare), get the PQC-gated co-signature, then build_unvault.
        let first = prepare_unvault(
            &vault,
            &utxo,
            staging_xonly,
            Amount::from_sat(2_000),
            &demo_keys::user_keypair(),
        )
        .unwrap();
        let pqc = qsv_pqc::PqcIdentity::from_seed(&[78u8; 32]);
        let enclave_sig = qsv_pqc::enclave_sign_if_pqc_valid(
            pqc.verifying_key_bytes(),
            &pqc.sign(&first.sighash),
            &first.sighash,
            &enclave_seed,
        )
        .unwrap();
        drop(first);
        let tx = build_unvault(
            &vault,
            &utxo,
            staging_xonly,
            Amount::from_sat(2_000),
            &demo_keys::user_keypair(),
            enclave_sig,
        )
        .expect("one-shot unvault must be consensus-valid");
        assert_eq!(tx.input[0].witness.len(), 4);

        // Stage-2 settlement for the runbook report.
        let staging_utxo = LiveUtxo {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([6u8; 32]), 1),
            value: Amount::from_sat(100_000),
            script_pubkey: p2tr_spk(key_path_output_key(staging_xonly)),
        };
        let settle = build_settlement(
            &staging_utxo,
            &staging_kp,
            demo_keys::heir_one(),
            Amount::from_sat(1_000),
            144,
        )
        .unwrap();
        let rep = lifecycle_report(&vault, &tx, &settle);
        assert!(rep.contains("unvault_witness=4"), "{rep}");
        assert!(rep.contains("settle_witness=1"), "{rep}");

        // Fail-closed value checks + the operator-facing error strings.
        assert_eq!(
            LifecycleError::InsufficientFunds.to_string(),
            "insufficient funds"
        );
        let ce = LifecycleError::Consensus(qsv_core::consensus::VerifyError::EngineUnavailable);
        assert_eq!(
            ce.to_string(),
            "consensus rejected: consensus engine unavailable"
        );
        let poor_staging = LiveUtxo {
            value: Amount::from_sat(500),
            ..staging_utxo.clone()
        };
        assert!(matches!(
            build_settlement(
                &poor_staging,
                &staging_kp,
                demo_keys::heir_one(),
                Amount::from_sat(1_000),
                144
            ),
            Err(LifecycleError::InsufficientFunds)
        ));
        let poor_vault = LiveUtxo {
            value: Amount::from_sat(500),
            ..utxo.clone()
        };
        assert!(matches!(
            prepare_unvault(
                &vault,
                &poor_vault,
                staging_xonly,
                Amount::from_sat(1_000),
                &demo_keys::user_keypair(),
            ),
            Err(LifecycleError::InsufficientFunds)
        ));
    }
}
