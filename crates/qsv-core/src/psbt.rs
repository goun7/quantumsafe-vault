//! PSBT (BIP-174/BIP-371) round-trip for hardware wallets (Coldcard, Ledger).
//!
//! Flow: the coordinator builds an unsigned taproot PSBT with the full
//! script-path context (leaf script, control block, prevout info), the device
//! verifies the policy on its screen and returns taproot key signatures, and
//! the coordinator assembles the final witness. No trust in the coordinator:
//! the device signs only what its user inspected.

use bitcoin::hashes::Hash;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, Verification, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use std::collections::BTreeMap;

/// Errors raised during the PSBT lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsbtError {
    /// PSBT structure rejected (missing fields or wrong input count).
    Malformed(String),
    /// The device signature failed verification against the leaf script keys.
    SignatureVerification,
    /// Sighash computation failed.
    Sighash(String),
}

impl core::fmt::Display for PsbtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PsbtError::Malformed(s) => write!(f, "malformed PSBT: {s}"),
            PsbtError::SignatureVerification => {
                write!(
                    f,
                    "hardware signature failed verification (refusing to assemble)"
                )
            }
            PsbtError::Sighash(s) => write!(f, "sighash error: {s}"),
        }
    }
}

impl std::error::Error for PsbtError {}

/// Everything a signing device needs to inspect one vault input.
pub struct VaultPsbtInput {
    /// UTXO being spent.
    pub outpoint: OutPoint,
    /// Prevout value.
    pub prev_value: Amount,
    /// P2TR scriptPubKey of the prevout.
    pub prev_script_pubkey: ScriptBuf,
    /// The tap leaf script selected for the spend.
    pub leaf_script: ScriptBuf,
    /// Control block proving leaf membership.
    pub control_block: ControlBlock,
    /// CSV sequence for the input (0 for no height lock).
    pub sequence: Sequence,
    /// The vault's MAST merkle root (BIP-371 `PSBT_IN_TAP_MERKLE_ROOT`):
    /// Coldcard/Ledger recompute Q = P + H(P‖root) and REFUSE a script-path
    /// input whose root is missing while tap_scripts are present.
    pub merkle_root: Option<bitcoin::taproot::TapNodeHash>,
}

/// Builds an unsigned PSBT for one vault input with full taproot context.
///
/// The BIP-371 tap fields (`PSBT_IN_TAP_LEAF_SCRIPT`, `PSBT_IN_TAP_BIP32_DERIVATION`,
/// `PSBT_IN_TAP_INTERNAL_KEY`) are populated so Coldcard/Ledger can reconstruct
/// and display the exact spending policy.
pub fn build_unsigned_psbt(
    input: &VaultPsbtInput,
    outputs: Vec<TxOut>,
    internal_key: XOnlyPublicKey,
) -> Result<Psbt, PsbtError> {
    let unsigned = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: input.outpoint,
            script_sig: ScriptBuf::new(),
            sequence: input.sequence,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    let mut psbt =
        Psbt::from_unsigned_tx(unsigned).map_err(|e| PsbtError::Malformed(e.to_string()))?;
    let _ = &mut psbt.unsigned_tx;

    let inp = &mut psbt.inputs[0];
    inp.witness_utxo = Some(TxOut {
        value: input.prev_value,
        script_pubkey: input.prev_script_pubkey.clone(),
    });
    inp.sighash_type = Some(PsbtSighashType::from(TapSighashType::Default));

    // BIP-371: tap leaf script keyed by control block (leaf version encoded
    // in the control block's final byte).
    let mut leaf_map: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)> = BTreeMap::new();
    leaf_map.insert(
        input.control_block.clone(),
        (input.leaf_script.clone(), LeafVersion::TapScript),
    );
    inp.tap_scripts = leaf_map;

    // BIP-371: internal key (NUMS) + merkle root so the device can verify
    // key-path absence and recompute the output key. Coldcard/Ledger REJECT
    // a Taproot input whose merkle root is absent when tap_scripts are
    // present (they cannot recompute Q without it).
    inp.tap_internal_key = Some(internal_key);
    inp.tap_merkle_root = input.merkle_root;

    Ok(psbt)
}

/// The message a signing device signs for script-path input `index`
/// (BIP-341 sighash, default type). This is what Coldcard/Ledger compute
/// internally; exposed here for verification of returned signatures.
pub fn sighash_for_psbt_input(
    psbt: &Psbt,
    index: usize,
    ctx_leaf_script: &ScriptBuf,
) -> Result<[u8; 32], PsbtError> {
    let tx = &psbt.unsigned_tx;
    let inp = psbt
        .inputs
        .get(index)
        .ok_or_else(|| PsbtError::Malformed("no such input".into()))?;
    let utxo = inp
        .witness_utxo
        .clone()
        .ok_or_else(|| PsbtError::Malformed("missing witness_utxo".into()))?;
    let prevouts = Prevouts::All(&[utxo]);
    let leaf_hash = TapLeafHash::from_script(ctx_leaf_script, LeafVersion::TapScript);
    let mut cache = SighashCache::new(tx);
    let sh = cache
        .taproot_signature_hash(
            index,
            &prevouts,
            None,
            // BIP-341: default OP_CODESEPARATOR position is 0xFFFFFFFF.
            Some((leaf_hash, 0xFFFFFFFF)),
            TapSighashType::Default,
        )
        .map_err(|e| PsbtError::Sighash(e.to_string()))?;
    Ok(sh.to_byte_array())
}

/// Verifies a signature returned by a signing device against the expected
/// x-only key. `dev_key` is the leaf-script key the device controls.
pub fn verify_device_signature<C: Verification>(
    secp: &Secp256k1<C>,
    dev_key: XOnlyPublicKey,
    sighash: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), PsbtError> {
    let sig = secp256k1::schnorr::Signature::from_slice(signature)
        .map_err(|_| PsbtError::SignatureVerification)?;
    secp.verify_schnorr(&sig, &Message::from_digest(*sighash), &dev_key)
        .map_err(|_| PsbtError::SignatureVerification)
}

/// Assembles the final script-path witness from collected signatures
/// (order matters: [first leaf CHECKSIG(VERIFY) key, then subsequent keys]).
pub fn assemble_witness(
    signatures_in_script_order: &[Vec<u8>],
    leaf_script: &ScriptBuf,
    control_block: &ControlBlock,
) -> Witness {
    let mut control_bytes = Vec::new();
    control_block
        .encode(&mut control_bytes)
        .expect("control block encode cannot fail into Vec");
    let mut w = Witness::new();
    for sig in signatures_in_script_order {
        w.push(sig.clone());
    }
    w.push(leaf_script.as_bytes());
    w.push(control_bytes);
    w
}

/// `Psbt::extract_tx` with the rust-bitcoin 0.32 `fee()`-error trap
/// closed: the dependency maps any `fee()` error OUTSIDE its three
/// listed variants (e.g. `PsbtUtxoOutOfbounds` — a hostile
/// `non_witness_utxo` whose vout cannot resolve) to `unreachable!()` —
/// a PANIC, not an `Err` (found by the `psbt_parse` fuzz gate:
/// crash-8523a028). Judging `fee()` first turns every one of them
/// into our `Err`; on a fee() that succeeds, the internal
/// recomputation over the same clone is deterministic and reaches the
/// same `Ok`.
fn extract_tx_checked(cloned: Psbt) -> Result<Transaction, PsbtError> {
    cloned
        .fee()
        .map_err(|e| PsbtError::Malformed(format!("fee: {e}")))?;
    cloned
        .extract_tx()
        .map_err(|e| PsbtError::Malformed(e.to_string()))
}

/// Convenience: finalize the PSBT's input from a completed witness and return
/// the extracted transaction (BIP-174 finalize + extract).
pub fn finalize_and_extract(psbt: &mut Psbt, witness: Witness) -> Result<Transaction, PsbtError> {
    if psbt.inputs.len() != 1 {
        return Err(PsbtError::Malformed("expected exactly one input".into()));
    }
    psbt.inputs[0].final_script_witness = Some(witness);
    let cloned = psbt.clone();
    extract_tx_checked(cloned)
}

/// Signs an input with a demo/local keypair (test path only; hardware returns
/// signatures over the same sighash). Ensures the ordering contract is
/// exercised end-to-end.
pub fn sign_with_local_keypair(
    psbt: &Psbt,
    index: usize,
    leaf_script: &ScriptBuf,
    keypair: &Keypair,
) -> Result<Vec<u8>, PsbtError> {
    let sh = sighash_for_psbt_input(psbt, index, leaf_script)?;
    let secp = Secp256k1::signing_only();
    let sig = secp.sign_schnorr(&Message::from_digest(sh), keypair);
    Ok(sig.as_ref().to_vec())
}

/// Signs an input as a signing device would: the coordinator hands over the
/// PSBT, the device recomputes the exact BIP-341 sighash LOCALLY (it never
/// trusts a server-provided digest), signs it deterministically and returns
/// the 64-byte BIP-340 signature. This is the qsv-cosigner/Coldcard/Ledger
/// contract: key material never crosses the device boundary, only PSBT in /
/// signature out.
pub fn device_sign_input(
    psbt: &Psbt,
    index: usize,
    leaf_script: &ScriptBuf,
    keypair: &Keypair,
) -> Result<Vec<u8>, PsbtError> {
    let sighash = sighash_for_psbt_input(psbt, index, leaf_script)?;
    let secp = Secp256k1::signing_only();
    // BIP-340 nonce with aux bound to the sighash: deterministic per (key,
    // message) pair, yet distinct across inputs of the same session.
    let sig = secp.sign_schnorr_with_aux_rand(&Message::from_digest(sighash), keypair, &sighash);
    Ok(sig.as_ref().to_vec())
}

/// Allocating helper for `Input` consumers that need a mutable map view.
pub fn empty_tap_scripts() -> BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)> {
    BTreeMap::new()
}

// ─── Multi-input vault PSBT (Part 3): coin-selection aggregation ───

/// One vault input for the multi-input builder (same fields as
/// [`VaultPsbtInput`], grouped so the builder can iterate).
pub struct MultiInput {
    /// Per-input vault context (leaf, control block, prevout info).
    pub vault: VaultPsbtInput,
}

/// Builds an unsigned multi-input vault PSBT: every input carries its own
/// full BIP-371 tap context (leaf script + control block + witness utxo +
/// merkle root), so each signing device inspects exactly what its key
/// commits to.
pub fn build_multi_input_psbt(
    inputs: &[VaultPsbtInput],
    outputs: Vec<TxOut>,
    internal_key: XOnlyPublicKey,
) -> Result<Psbt, PsbtError> {
    if inputs.is_empty() {
        return Err(PsbtError::Malformed("no inputs supplied".into()));
    }
    let unsigned = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|i| TxIn {
                previous_output: i.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: i.sequence,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs,
    };
    let mut psbt =
        Psbt::from_unsigned_tx(unsigned).map_err(|e| PsbtError::Malformed(e.to_string()))?;
    for (inp, i) in psbt.inputs.iter_mut().zip(inputs) {
        inp.witness_utxo = Some(TxOut {
            value: i.prev_value,
            script_pubkey: i.prev_script_pubkey.clone(),
        });
        inp.sighash_type = Some(PsbtSighashType::from(TapSighashType::Default));
        let mut leaf_map: BTreeMap<ControlBlock, (ScriptBuf, LeafVersion)> = BTreeMap::new();
        leaf_map.insert(
            i.control_block.clone(),
            (i.leaf_script.clone(), LeafVersion::TapScript),
        );
        inp.tap_scripts = leaf_map;
        inp.tap_internal_key = Some(internal_key);
        inp.tap_merkle_root = i.merkle_root;
    }
    Ok(psbt)
}

/// Signs ONE input of a multi-input PSBT as the device would (the device
/// recomputes the BIP-341 sighash for its input from the PSBT itself).
pub fn device_sign_input_multi(
    psbt: &Psbt,
    index: usize,
    leaf_script: &ScriptBuf,
    keypair: &Keypair,
) -> Result<Vec<u8>, PsbtError> {
    let sighash = sighash_multi_input(psbt, index, leaf_script)?;
    let secp = Secp256k1::signing_only();
    let sig = secp.sign_schnorr_with_aux_rand(&Message::from_digest(sighash), keypair, &sighash);
    Ok(sig.as_ref().to_vec())
}

/// The BIP-341 sighash for one input of a MULTI-input PSBT: builds the full
/// prevout list from every witness_utxo (sighash commits to ALL of them).
pub fn sighash_multi_input(
    psbt: &Psbt,
    index: usize,
    ctx_leaf_script: &ScriptBuf,
) -> Result<[u8; 32], PsbtError> {
    let tx = &psbt.unsigned_tx;
    if index >= psbt.inputs.len() {
        return Err(PsbtError::Malformed("no such input".into()));
    }
    let utxos: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| {
            i.witness_utxo
                .clone()
                .ok_or_else(|| PsbtError::Malformed("missing witness_utxo".into()))
        })
        .collect::<Result<_, _>>()?;
    let prevouts = Prevouts::All(&utxos);
    let leaf_hash = TapLeafHash::from_script(ctx_leaf_script, LeafVersion::TapScript);
    let mut cache = SighashCache::new(tx);
    let sh = cache
        .taproot_signature_hash(
            index,
            &prevouts,
            None,
            Some((leaf_hash, 0xFFFFFFFF)),
            TapSighashType::Default,
        )
        .map_err(|e| PsbtError::Sighash(e.to_string()))?;
    Ok(sh.to_byte_array())
}

/// Coordinator-side verification for one input of a multi-input PSBT.
pub fn verify_device_signature_multi<C: Verification>(
    secp: &Secp256k1<C>,
    dev_key: XOnlyPublicKey,
    psbt: &Psbt,
    index: usize,
    leaf_script: &ScriptBuf,
    signature: &[u8; 64],
) -> Result<(), PsbtError> {
    let sighash = sighash_multi_input(psbt, index, leaf_script)?;
    verify_device_signature(secp, dev_key, &sighash, signature)
}

/// Stores one device signature into the PSBT's tap script sig map.
pub fn store_tap_script_sig(
    psbt: &mut Psbt,
    index: usize,
    dev_key: XOnlyPublicKey,
    leaf_script: &ScriptBuf,
    sig64: &[u8; 64],
) -> Result<(), PsbtError> {
    let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(sig64)
        .map_err(|_| PsbtError::SignatureVerification)?;
    psbt.inputs[index].tap_script_sigs.insert(
        (dev_key, leaf_hash),
        bitcoin::taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        },
    );
    Ok(())
}

/// Assembles the multi-input script-path witness for input `index` from the
/// stored tap script sigs.
///
/// `execution_order` is the order the SCRIPT consumes the signatures: the
/// first entry is the FIRST signature checked by the script and therefore
/// the LAST one pushed (stack discipline) — identical to
/// `unvault::build_script_path_witness(&[σ_exec0, σ_exec1, …], …)`. For the
/// normal hybrid leaf `<pk_user> CHECKSIGVERIFY <pk_enclave> CHECKSIG` that
/// order is [σ_enclave, σ_user] (the enclave's signature sits on the stack
/// top). Missing signatures fail closed.
pub fn assemble_witness_for_input(
    psbt: &Psbt,
    index: usize,
    leaf_script: &ScriptBuf,
    control_block: &ControlBlock,
    execution_order: &[XOnlyPublicKey],
) -> Result<Witness, PsbtError> {
    let leaf_hash = TapLeafHash::from_script(leaf_script, LeafVersion::TapScript);
    let sigs = &psbt.inputs[index].tap_script_sigs;
    let mut w = Witness::new();
    for k in execution_order {
        let s = sigs
            .get(&(*k, leaf_hash))
            .ok_or(PsbtError::SignatureVerification)?;
        w.push(s.signature.serialize());
    }
    let mut control_bytes = Vec::new();
    control_block
        .encode(&mut control_bytes)
        .expect("control block encode cannot fail into Vec");
    w.push(leaf_script.as_bytes());
    w.push(control_bytes);
    Ok(w)
}

/// Extracts the transaction from a fully signed multi-input PSBT after
/// attaching the assembled witnesses (one call per input before extract).
pub fn finalize_multi_input_and_extract(
    psbt: &mut Psbt,
    witnesses: Vec<Witness>,
) -> Result<Transaction, PsbtError> {
    if psbt.inputs.len() != witnesses.len() {
        return Err(PsbtError::Malformed(
            "witness count must equal the input count".into(),
        ));
    }
    for (inp, w) in psbt.inputs.iter_mut().zip(witnesses) {
        inp.final_script_witness = Some(w);
    }
    let cloned = psbt.clone();
    extract_tx_checked(cloned)
}

/// Greedy largest-first coin selection over live UTXOs: returns the inputs
/// that reach `target`, or None when the coins cannot cover it (fee-aware:
/// the caller passes `target = spend + fee`).
pub fn select_coins_largest_first(
    mut coins: Vec<(OutPoint, Amount)>,
    target: Amount,
) -> Option<Vec<(OutPoint, Amount)>> {
    coins.sort_by_key(|(_, a)| std::cmp::Reverse(*a));
    let mut acc = Amount::ZERO;
    let mut chosen = Vec::new();
    for c in coins {
        if acc >= target {
            break;
        }
        acc = acc.checked_add(c.1)?;
        chosen.push(c);
    }
    if acc >= target {
        Some(chosen)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo_keys;
    use crate::taproot::VaultTaproot;

    #[test]
    fn psbt_roundtrip_with_real_signatures() {
        let secp_v = Secp256k1::verification_only();
        let vault = VaultTaproot::derive(
            &secp_v,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();

        let internal_key = vault.internal_key;
        let out_key = vault.output_key();
        let prev_spk = builder_p2tr(out_key);
        let staging = crate::unvault::staging_script(demo_keys::recovery_key());

        let input = VaultPsbtInput {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([0x11u8; 32]), 0),
            prev_value: Amount::from_sat(120_000),
            prev_script_pubkey: prev_spk,
            leaf_script: vault.leaves.normal.clone(),
            control_block: vault
                .spend_info
                .control_block(&(vault.leaves.normal.clone(), LeafVersion::TapScript))
                .unwrap(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            merkle_root: vault.merkle_root(),
        };
        let outputs = vec![TxOut {
            value: Amount::from_sat(118_500),
            script_pubkey: staging.clone(),
        }];

        let mut psbt = build_unsigned_psbt(&input, outputs, internal_key).unwrap();
        // BIP-371 fields populated?
        assert!(psbt.inputs[0].tap_internal_key.is_some());
        assert_eq!(psbt.inputs[0].tap_scripts.len(), 1);
        assert!(psbt.inputs[0].witness_utxo.is_some());
        // Tapscript merkle root lets Coldcard/Ledger re-derive Q (BIP-341).
        assert_eq!(psbt.inputs[0].tap_merkle_root, vault.merkle_root());

        // "Hardware" (local demo keypairs) signs the exact BIP-341 sighash.
        let sig_user =
            sign_with_local_keypair(&psbt, 0, &vault.leaves.normal, &demo_keys::user_keypair())
                .unwrap();
        let sig_enclave = sign_with_local_keypair(
            &psbt,
            0,
            &vault.leaves.normal,
            &demo_keys::enclave_keypair(),
        )
        .unwrap();

        // Coordinator verifies device signatures before assembling.
        let sh = sighash_for_psbt_input(&psbt, 0, &vault.leaves.normal).unwrap();
        verify_device_signature(
            &Secp256k1::verification_only(),
            demo_keys::user_key(),
            &sh,
            &sig_user[..64].try_into().unwrap(),
        )
        .unwrap();
        verify_device_signature(
            &Secp256k1::verification_only(),
            demo_keys::enclave_key(),
            &sh,
            &sig_enclave[..64].try_into().unwrap(),
        )
        .unwrap();

        // Cross-device signature MUST fail verification (fail-closed).
        assert!(verify_device_signature(
            &Secp256k1::verification_only(),
            demo_keys::user_key(),
            &sh,
            &sig_enclave[..64].try_into().unwrap(),
        )
        .is_err());

        let witness = assemble_witness(
            &[sig_user, sig_enclave],
            &vault.leaves.normal,
            &input.control_block,
        );
        let tx = finalize_and_extract(&mut psbt, witness).unwrap();
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    #[test]
    fn device_signing_path_is_deterministic_and_fail_closed() {
        let secp_v = Secp256k1::verification_only();
        let vault = VaultTaproot::derive(
            &secp_v,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();

        let input = VaultPsbtInput {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([0x22u8; 32]), 0),
            prev_value: Amount::from_sat(90_000),
            prev_script_pubkey: builder_p2tr(vault.output_key()),
            leaf_script: vault.leaves.normal.clone(),
            control_block: vault
                .spend_info
                .control_block(&(vault.leaves.normal.clone(), LeafVersion::TapScript))
                .unwrap(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            merkle_root: vault.merkle_root(),
        };
        let outputs = vec![TxOut {
            value: Amount::from_sat(88_500),
            script_pubkey: crate::unvault::staging_script(demo_keys::recovery_key()),
        }];
        let psbt = build_unsigned_psbt(&input, outputs, vault.internal_key).unwrap();

        // Device-side signing: both devices sign the sighash they compute
        // themselves from the PSBT.
        let sig_user =
            device_sign_input(&psbt, 0, &vault.leaves.normal, &demo_keys::user_keypair()).unwrap();
        let sig_enclave = device_sign_input(
            &psbt,
            0,
            &vault.leaves.normal,
            &demo_keys::enclave_keypair(),
        )
        .unwrap();
        assert_eq!(sig_user.len(), 64);

        // Determinism: the same device + same PSBT → the same signature.
        let again =
            device_sign_input(&psbt, 0, &vault.leaves.normal, &demo_keys::user_keypair()).unwrap();
        assert_eq!(sig_user, again);

        // Coordinator verification: correct keys pass, cross-device fails.
        let sh = sighash_for_psbt_input(&psbt, 0, &vault.leaves.normal).unwrap();
        verify_device_signature(
            &secp_v,
            demo_keys::user_key(),
            &sh,
            &sig_user[..64].try_into().unwrap(),
        )
        .unwrap();
        verify_device_signature(
            &secp_v,
            demo_keys::enclave_key(),
            &sh,
            &sig_enclave[..64].try_into().unwrap(),
        )
        .unwrap();
        assert!(verify_device_signature(
            &secp_v,
            demo_keys::user_key(),
            &sh,
            &sig_enclave[..64].try_into().unwrap(),
        )
        .is_err());

        // Witness order: script consumes σ_enclave (top) then σ_user.
        let witness = assemble_witness(
            &[sig_enclave.clone(), sig_user.clone()],
            &vault.leaves.normal,
            &input.control_block,
        );
        let mut finalized = psbt;
        let tx = finalize_and_extract(&mut finalized, witness).unwrap();
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    fn builder_p2tr(out_key: XOnlyPublicKey) -> ScriptBuf {
        use bitcoin::opcodes::all::OP_PUSHNUM_1;
        bitcoin::script::Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(out_key.serialize())
            .into_script()
    }

    /// Multi-input PSBT: TWO live vault coins, one 2-input spend, both
    /// devices sign every input, witnesses assemble per-input and the whole
    /// transaction passes the consensus engine (multi-input verify path).
    /// The consensus assertions require the `consensus` feature; without it
    /// the engine is unavailable by design (fail-closed VerifyError).
    #[test]
    #[cfg(feature = "consensus")]
    fn multi_input_psbt_consensus_verifies_and_fail_closed() {
        use crate::consensus;

        let secp_v = Secp256k1::verification_only();
        let vault = VaultTaproot::derive(
            &secp_v,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();
        let leaf = vault.leaves.normal.clone();
        let control = vault
            .spend_info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap();
        let prev_spk = builder_p2tr(vault.output_key());

        // Two fake-but-consistent live coins; outpoints differ.
        let mk = |b: u8, sat: u64| VaultPsbtInput {
            outpoint: OutPoint::new(bitcoin::Txid::from_byte_array([b; 32]), 0),
            prev_value: Amount::from_sat(sat),
            prev_script_pubkey: prev_spk.clone(),
            leaf_script: leaf.clone(),
            control_block: control.clone(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            merkle_root: vault.merkle_root(),
        };
        let inputs = vec![mk(0x01, 120_000), mk(0x02, 80_000)];
        let total = 200_000;
        let outputs = vec![TxOut {
            value: Amount::from_sat(total - 2_000),
            script_pubkey: crate::unvault::staging_script(demo_keys::recovery_key()),
        }];

        let mut psbt = build_multi_input_psbt(&inputs, outputs, vault.internal_key).unwrap();
        assert_eq!(psbt.inputs.len(), 2);
        assert_eq!(psbt.inputs[0].tap_merkle_root, vault.merkle_root());
        assert_eq!(psbt.inputs[1].tap_merkle_root, vault.merkle_root());

        // Both devices sign BOTH inputs (4 signatures total).
        let devices = [
            (demo_keys::user_key(), demo_keys::user_keypair()),
            (demo_keys::enclave_key(), demo_keys::enclave_keypair()),
        ];
        for (idx, _) in inputs.iter().enumerate() {
            for (pk, kp) in &devices {
                let sig = device_sign_input_multi(&psbt, idx, &leaf, kp).unwrap();
                let s64: [u8; 64] = sig[..64].try_into().unwrap();
                verify_device_signature_multi(&secp_v, *pk, &psbt, idx, &leaf, &s64).unwrap();
                store_tap_script_sig(&mut psbt, idx, *pk, &leaf, &s64).unwrap();
            }
        }

        // Cross-device signature must fail (per-input, fail-closed).
        let forged = device_sign_input_multi(&psbt, 0, &leaf, &devices[1].1).unwrap();
        let f64: [u8; 64] = forged[..64].try_into().unwrap();
        assert!(
            verify_device_signature_multi(&secp_v, devices[0].0, &psbt, 0, &leaf, &f64).is_err()
        );

        // Witness assembly: the script checks <pk_user> first, so the
        // execution order is [σ_enclave, σ_user] (enclave sig on stack top).
        let witnesses = (0..inputs.len())
            .map(|i| {
                assemble_witness_for_input(
                    &psbt,
                    i,
                    &leaf,
                    &inputs[i].control_block,
                    &[demo_keys::enclave_key(), demo_keys::user_key()],
                )
                .unwrap()
            })
            .collect();
        let tx = finalize_multi_input_and_extract(&mut psbt, witnesses).unwrap();
        assert_eq!(tx.input.len(), 2);
        assert_eq!(tx.input[0].witness.len(), 4);
        assert_eq!(tx.input[1].witness.len(), 4);

        // FULL multi-input consensus verification (both inputs).
        let prevouts: Vec<(ScriptBuf, Amount)> = inputs
            .iter()
            .map(|i| (i.prev_script_pubkey.clone(), i.prev_value))
            .collect();
        consensus::verify_transaction(&tx, &prevouts).unwrap();

        // Tamper with an output amount → consensus must reject.
        let mut bad = tx.clone();
        bad.output[0].value = Amount::from_sat(total); // over-spend
        let prevouts2 = prevouts.clone();
        assert!(consensus::verify_transaction(&bad, &prevouts2).is_err());

        // Greedy selection: largest-first reaches the target exactly.
        let coins = vec![
            (
                OutPoint::new(bitcoin::Txid::from_byte_array([9; 32]), 0),
                Amount::from_sat(50_000),
            ),
            (
                OutPoint::new(bitcoin::Txid::from_byte_array([8; 32]), 0),
                Amount::from_sat(120_000),
            ),
            (
                OutPoint::new(bitcoin::Txid::from_byte_array([7; 32]), 0),
                Amount::from_sat(70_000),
            ),
        ];
        let pick = select_coins_largest_first(coins.clone(), Amount::from_sat(190_000)).unwrap();
        assert_eq!(pick.len(), 2);
        assert_eq!(pick[0].1, Amount::from_sat(120_000));
        assert_eq!(pick[1].1, Amount::from_sat(70_000));
        // Unreachable target → None.
        assert!(select_coins_largest_first(coins, Amount::from_sat(500_000)).is_none());
    }

    /// rust-bitcoin 0.32's `extract_tx` maps any `fee()` error outside
    /// its three listed variants to `unreachable!()` — a hostile
    /// `non_witness_utxo` whose vout cannot resolve
    /// (`PsbtUtxoOutOfbounds`) used to PANIC deep in the dependency
    /// (found by the `psbt_parse` fuzz gate, crash-8523a028). Extract
    /// must answer `Err`.
    #[test]
    fn extract_refuses_a_hostile_non_witness_utxo_instead_of_panicking() {
        let unsigned = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(unsigned).unwrap();
        // No witness_utxo; the non_witness_utxo carries ZERO outputs,
        // so the input's vout can never resolve inside it.
        let hostile = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        psbt.inputs[0].non_witness_utxo = Some(hostile);
        let err = finalize_and_extract(&mut psbt, Witness::new()).unwrap_err();
        assert!(
            err.to_string().contains("fee:"),
            "the fee judgment must carry the cause, not panic: {err}"
        );
    }
}
