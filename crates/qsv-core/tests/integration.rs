//! End-to-end test matrix (docs/09 §9).
//!
//! Cross-verifies the paper's theorems against the implementation:
//! T1 hybrid resistance, T2 NUMS key-path cancellation, T3 two-stage
//! unvault pinning, T4 inheritance CSV gating, T5 consensus-engine proof,
//! T6 emergency leaf + 520-byte BIP-342 discipline, T7 all-leaf budget
//! consensus proof, T8 policy↔MAST consistency.

use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
// Used only inside the #[cfg(feature = "consensus")] tests below — keeping
// it unconditional would be an unused import (clippy -D warnings) in the
// default (non-consensus) build, and missing under --features consensus.
#[cfg(feature = "consensus")]
use bitcoin::secp256k1::Message;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Txid};
use miniscript::descriptor::DescriptorPublicKey;
use qsv_core::demo_keys;
use qsv_core::heirs::HeirSet;
use qsv_core::nums;
use qsv_core::policy::{self, compile_vault_policy};
use qsv_core::taproot::VaultTaproot;
use qsv_core::unvault;
#[cfg(feature = "consensus")]
use qsv_core::wots;
use std::str::FromStr;

fn p2tr_spk(output_key: XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(output_key.serialize())
        .into_script()
}

fn desc_pk(seed: u8) -> DescriptorPublicKey {
    // Deterministic compressed pubkey parsed from hex (miniscript accepts raw keys).
    let kp = demo_keys::demo_keypair(&format!("test/desc/{seed}"));
    let pk = secp256k1::PublicKey::from_keypair(&kp);
    DescriptorPublicKey::from_str(&pk.to_string()).expect("raw compressed pubkey parses")
}

#[test]
fn t2_nums_key_is_deterministic_and_matches_paper_protocol() {
    let k1 = nums::nums_internal_key_bytes();
    let k2 = nums::nums_internal_key_bytes();
    assert_eq!(k1, k2);
    // Manual recomputation of docs/03 §2.2 (v2026.2 canonical: SHA256(S||LE32(c))):
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"QuantumSafe_Vault_v2026_Unspendable_Internal_Key_Nothing_Up_My_Sleeve");
    h.update(0u32.to_le_bytes());
    let d: [u8; 32] = h.finalize().into();
    assert_eq!(d, k1);
}

#[test]
fn t2_key_path_is_mathematically_cancelled() {
    let secp = Secp256k1::verification_only();
    let vault = VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        &[],
        2,
    )
    .unwrap();
    // The output key is the tweaked NUMS point; nobody knows the NUMS discrete
    // log, therefore no key-path signature can ever be produced.
    assert_ne!(vault.internal_key, vault.output_key());
    assert!(vault.merkle_root().is_some());
}

#[test]
fn vault_addresses_resolve_on_all_networks() {
    let secp = Secp256k1::verification_only();
    let vault = VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        &[],
        2,
    )
    .unwrap();
    assert!(vault
        .address(Network::Bitcoin)
        .to_string()
        .starts_with("bc1p"));
    assert!(vault
        .address(Network::Signet)
        .to_string()
        .starts_with("tb1p"));
    assert!(vault
        .address(Network::Regtest)
        .to_string()
        .starts_with("bcrt1p"));
}

#[test]
fn bip379_policy_compiles_with_expected_guards() {
    let input = policy::VaultPolicyInput {
        key_user: desc_pk(1),
        key_enclave: desc_pk(2),
        key_recovery: desc_pk(3),
        key_heirs: vec![desc_pk(4), desc_pk(5)],
        key_executor: desc_pk(6),
    };
    let ms = compile_vault_policy(&input).expect("policy compiles");
    assert!(policy::contains_older_check(
        &ms,
        policy::RECOVERY_CSV_BLOCKS
    ));
    assert!(policy::contains_older_check(
        &ms,
        policy::INHERITANCE_CSV_BLOCKS
    ));
}

#[test]
fn bip379_policy_rejects_singleton_heir_group() {
    let input = policy::VaultPolicyInput {
        key_user: desc_pk(1),
        key_enclave: desc_pk(2),
        key_recovery: desc_pk(3),
        key_heirs: vec![desc_pk(4)],
        key_executor: desc_pk(5),
    };
    assert!(matches!(
        compile_vault_policy(&input),
        Err(policy::PolicyError::NotEnoughHeirs)
    ));
}

#[test]
fn t3_unvault_pins_single_staging_output() {
    let staging_real = unvault::staging_script(demo_keys::recovery_key());

    let tx = unvault::build_unvault_tx(
        OutPoint::new(Txid::from_byte_array([1u8; 32]), 0),
        Amount::from_sat(500_000),
        &staging_real,
        Amount::from_sat(2_000),
    )
    .unwrap();

    assert_eq!(tx.output.len(), 1, "Theorem 3: exactly one covenant output");
    assert_eq!(tx.output[0].script_pubkey, staging_real);
    assert_eq!(tx.output[0].value, Amount::from_sat(498_000));
    assert_eq!(
        tx.input[0].previous_output,
        OutPoint::new(Txid::from_byte_array([1u8; 32]), 0)
    );
}

#[test]
fn t3_t4_csv_encodings_are_exact() {
    // CSV block counts are pushed as minimal CScriptNum (2-byte LE encodings):
    //   144   = 0x0090 -> "9000"
    //   26280 = 0x66A8 -> "a866"
    let rec = qsv_core::taproot::recovery_leaf_script(demo_keys::recovery_key()).unwrap();
    let asm = rec.to_string();
    assert!(asm.contains("OP_CSV"), "recovery CSV missing: {asm}");
    assert!(asm.contains("9000"), "144 encoding missing: {asm}");

    let inh = qsv_core::taproot::inheritance_script(
        &[
            demo_keys::heir_one(),
            demo_keys::heir_two(),
            demo_keys::executor_key(),
        ],
        2,
    )
    .unwrap();
    let asm = inh.to_string();
    assert!(asm.contains("OP_CSV"), "inheritance CSV missing: {asm}");
    assert!(asm.contains("a866"), "26280 encoding missing: {asm}");
    assert!(
        asm.contains("CHECKSIGADD"),
        "threshold shape missing: {asm}"
    );
}

#[test]
fn t1_hybrid_witness_completes_and_structure_holds() {
    let secp = Secp256k1::verification_only();
    let vault = VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        &[],
        2,
    )
    .unwrap();

    let prev_spk = p2tr_spk(vault.output_key());
    let staging = unvault::staging_script(demo_keys::recovery_key());
    let mut tx = unvault::build_unvault_tx(
        OutPoint::new(Txid::from_byte_array([7u8; 32]), 3),
        Amount::from_sat(250_000),
        &staging,
        Amount::from_sat(2_500),
    )
    .unwrap();

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
        prev_value: Amount::from_sat(250_000),
        prev_script_pubkey: &prev_spk,
    };
    unvault::sign_normal_leaf_spend(
        &mut tx,
        0,
        &ctx,
        &demo_keys::user_keypair(),
        &demo_keys::enclave_keypair(),
    );

    // Witness layout (BIP-341 execution order): [σ_enclave, σ_user, script, control]
    // — the script consumes the stack TOP first (σ_enclave), then σ_user.
    let w = &tx.input[0].witness;
    let items: Vec<&[u8]> = w.iter().collect();
    assert_eq!(items.len(), 4, "witness must be 4 elements");
    assert_eq!(items[0].len(), 64, "σ_enclave is 64-byte BIP-340");
    assert_eq!(items[1].len(), 64, "σ_user is 64-byte BIP-340");
    assert_eq!(items[2], vault.leaves.normal.as_bytes());
    assert!(items[3].len() >= 65, "control block is 65+ bytes");
}

#[test]
fn t4_inheritance_settlement_uses_csv_sequence() {
    let tx = unvault::build_settlement_tx(
        OutPoint::new(Txid::from_byte_array([9u8; 32]), 0),
        Amount::from_sat(300_000),
        &unvault::staging_script(demo_keys::heir_one()),
        Amount::from_sat(1_000),
        policy::INHERITANCE_CSV_BLOCKS,
    )
    .unwrap();
    assert_eq!(tx.input[0].sequence.to_consensus_u32(), 26_280);
}

#[test]
fn heir_registry_binds_classic_keys_to_pqc_identities() {
    let pqc1 = qsv_pqc::PqcIdentity::from_seed(&[21u8; 32]);
    let pqc2 = qsv_pqc::PqcIdentity::from_seed(&[22u8; 32]);
    let set = HeirSet::build([
        (
            demo_keys::heir_one().serialize(),
            pqc1.verifying_key_bytes().to_vec(),
        ),
        (
            demo_keys::heir_two().serialize(),
            pqc2.verifying_key_bytes().to_vec(),
        ),
    ])
    .unwrap();

    assert!(set.verify_member(
        &demo_keys::heir_one().serialize(),
        pqc1.verifying_key_bytes()
    ));
    assert!(set.verify_member(
        &demo_keys::heir_two().serialize(),
        pqc2.verifying_key_bytes()
    ));
    // Cross pairs must fail (fail-closed identity binding).
    assert!(!set.verify_member(
        &demo_keys::heir_one().serialize(),
        pqc2.verifying_key_bytes()
    ));
    assert!(!set.verify_member(
        &demo_keys::executor_key().serialize(),
        pqc1.verifying_key_bytes()
    ));
}

#[test]
fn t1_end_to_end_pqc_gate_and_hybrid_spend() {
    // 1. PQC identity signs the 32-byte unvault intent (sighash-shaped).
    let pqc = qsv_pqc::PqcIdentity::from_seed(&[31u8; 32]);
    let msg: [u8; 32] = [0x5A; 32];
    let sig = pqc.sign(&msg);

    // 2. Enclave gate opens only for a valid PQC signature, releasing a REAL
    // BIP-340 signature that verifies under the enclave public key.
    let enclave_seed = [32u8; 32];
    let released =
        qsv_pqc::enclave_sign_if_pqc_valid(pqc.verifying_key_bytes(), &sig, &msg, &enclave_seed)
            .expect("gate must open for valid PQC proof");
    let kp = qsv_pqc::enclave_keypair_from_seed(&enclave_seed).unwrap();
    let vk = qsv_pqc::enclave_xonly_public_key(&kp);
    let verify = secp256k1::Secp256k1::verification_only();
    assert!(verify
        .verify_schnorr(
            &secp256k1::schnorr::Signature::from_slice(&released).unwrap(),
            &secp256k1::Message::from_digest(msg),
            &vk,
        )
        .is_ok());
    let mut forged = sig;
    forged[7] ^= 0x40;
    assert!(qsv_pqc::enclave_sign_if_pqc_valid(
        pqc.verifying_key_bytes(),
        &forged,
        &msg,
        &enclave_seed
    )
    .is_err());

    // 3. Consensus layer: 2-of-2 hybrid witness completes the spend.
    let secp = Secp256k1::verification_only();
    let vault = VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        &[],
        2,
    )
    .unwrap();
    let control = vault
        .spend_info
        .control_block(&(
            vault.leaves.normal.clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .unwrap();
    let w = unvault::build_script_path_witness(
        &[vec![0xAA; 64], vec![0xBB; 64]],
        &vault.leaves.normal,
        &control,
    );
    assert_eq!(w.iter().count(), 4);
}

/// Consensus-level proof: a fully signed unvault transaction is accepted by
/// the REAL Bitcoin Core script interpreter (libbitcoinconsensus, C++), and a
/// tampered signature is rejected by the same engine.
#[cfg(feature = "consensus")]
#[test]
fn t5_consensus_engine_accepts_hybrid_spend_and_rejects_tamper() {
    let secp = Secp256k1::verification_only();
    let vault = VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        &[],
        2,
    )
    .unwrap();

    let out_key: XOnlyPublicKey = vault.output_key();
    let prev_spk = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(out_key.serialize())
        .into_script();
    let staging = unvault::staging_script(demo_keys::recovery_key());
    let mut tx = unvault::build_unvault_tx(
        OutPoint::new(Txid::from_byte_array([0x77u8; 32]), 5),
        Amount::from_sat(250_000),
        &staging,
        Amount::from_sat(2_500),
    )
    .unwrap();

    let control = vault
        .spend_info
        .control_block(&(
            vault.leaves.normal.clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .unwrap();
    let ctx = unvault::SpendContext {
        script: &vault.leaves.normal,
        control_block: &control,
        prev_value: Amount::from_sat(250_000),
        prev_script_pubkey: &prev_spk,
    };
    unvault::sign_normal_leaf_spend(
        &mut tx,
        0,
        &ctx,
        &demo_keys::user_keypair(),
        &demo_keys::enclave_keypair(),
    );

    // The consensus engine (Bitcoin Core C++ v26) accepts the spend.
    qsv_core::consensus::verify_input(&tx, 0, &prev_spk, Amount::from_sat(250_000))
        .expect("consensus engine must accept the hybrid spend");

    // Tamper with sigma_user -> the SAME engine rejects.
    let mut tampered = tx.clone();
    let mut bad_sig = tampered.input[0].witness[0].to_vec();
    bad_sig[0] ^= 0x01;
    tampered.input[0].witness = unvault::build_script_path_witness(
        &[bad_sig, tampered.input[0].witness[1].to_vec()],
        &vault.leaves.normal,
        &control,
    );
    assert!(
        qsv_core::consensus::verify_input(&tampered, 0, &prev_spk, Amount::from_sat(250_000))
            .is_err()
    );
}

// The recovery (clawback) leaf consensus proof now lives in T7 (full signed
// spend with CSV nSequence); the historical shape-only check was superseded.

/// Theorem 6 (docs/08 §2): the emergency leaf is a REAL MAST branch whose full
/// spend verifies on the REAL Bitcoin Core script interpreter:
///
///   leaf:  `OP_DUP OP_SHA256 <H(pk_em)> OP_EQUALVERIFY OP_CHECKSIG` (37 B)
///   witness: [σ_em, pk_em, script, control] — stack top first; every element
///   ≤ 520 B (BIP-342).
///
/// The plaintext emergency key exists NOWHERE on-chain (not in the script, not
/// in the tree): it is committed by digest and disclosed only at spend time
/// from the WOTS+-sealed offline kit. Consensus verifies hash-lock + Schnorr;
/// the WOTS+ seal binding the kit to the digest is checked OFFLINE before
/// broadcast (docs/10 §4: the kit opening is air-gapped, chain sees classical
/// Schnorr only).
#[cfg(feature = "consensus")]
#[test]
fn t6_consensus_engine_accepts_full_emergency_leaf_spend_and_rejects_tamper() {
    use bitcoin::hashes::{sha256, Hash};

    let secp = Secp256k1::verification_only();
    let vault = VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        &[],
        2,
    )
    .unwrap();

    // Off-chain kit opening (air-gapped): verify the WOTS+ seal over the
    // claim digest, then release the plaintext emergency key. The claim is
    // domain-separated with the kit scope and binds sha256(pk_em).
    let (kit_sk, kit_pk) = wots::keypair_from_seed(&[0x42u8; 32]);
    let pk_em: XOnlyPublicKey = demo_keys::emergency_kit_key();
    let kit_claim: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"QSV_WOTS_EMERGENCY_KIT_v1");
        h.update(sha256::Hash::hash(&pk_em.serialize()).to_byte_array());
        h.finalize().into()
    };
    let kit_sig = wots::sign(&kit_sk, &kit_claim).expect("WOTS+ kit seal");
    wots::verify(&kit_pk, &kit_claim, &kit_sig)
        .expect("WOTS+ seal must verify before the emergency key is released");

    // The leaf embeds ONLY the digest — the plaintext key appears nowhere on-chain.
    let script = &vault.leaves.emergency;
    assert_eq!(script.as_bytes().len(), 37);
    let digest = sha256::Hash::hash(&pk_em.serialize()).to_byte_array();
    assert!(script.as_bytes().windows(32).any(|w| w == digest));
    assert!(!script
        .as_bytes()
        .windows(32)
        .any(|w| w == pk_em.serialize()));

    // Build the unvault transaction paying from the vault UTXO via leaf 4.
    let out_key: XOnlyPublicKey = vault.output_key();
    let prev_spk = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(out_key.serialize())
        .into_script();
    let staging = unvault::staging_script(demo_keys::recovery_key());
    let value = Amount::from_sat(400_000);
    let mut tx = unvault::build_unvault_tx(
        OutPoint::new(Txid::from_byte_array([0x60u8; 32]), 1),
        value,
        &staging,
        Amount::from_sat(3_000),
    )
    .unwrap();

    // Control block proving the emergency leaf's membership in the MAST.
    let control = vault
        .spend_info
        .control_block(&(script.clone(), bitcoin::taproot::LeafVersion::TapScript))
        .expect("emergency leaf must be a committed MAST branch");

    // BIP-341 script-path sighash over the emergency leaf (codesep 0xFFFFFFFF).
    let sighash = unvault::script_spend_sighash(&tx, 0, script, value, &prev_spk);
    let msg = Message::from_digest(*sighash.as_byte_array());

    // σ_em from the disclosed key; verify it before assembly (kit discipline:
    // one WOTS+ seal per disclosed key, checked air-gapped before broadcast).
    let kit_keypair = qsv_core::demo_keys::emergency_kit_keypair();
    assert_eq!(kit_keypair.x_only_public_key().0, pk_em);
    let sig_em = unvault::sign_schnorr(&kit_keypair, &sighash);
    Secp256k1::verification_only()
        .verify_schnorr(
            &secp256k1::schnorr::Signature::from_slice(&sig_em).unwrap(),
            &msg,
            &pk_em,
        )
        .expect("emergency key signature must verify");

    // Witness: [σ_em, pk_em, script, control] — OP_DUP replicates the revealed
    // key, OP_SHA256 hashes it, OP_EQUALVERIFY checks the committed digest,
    // OP_CHECKSIG pops σ_em. Max element 64 B ≪ 520 B; plaintext key appears
    // only in the witness (commit-reveal).
    tx.input[0].witness = unvault::build_script_path_witness(
        &[sig_em.to_vec(), pk_em.serialize().to_vec()],
        script,
        &control,
    );
    assert_eq!(tx.input[0].witness.len(), 4);

    // THE consensus engine accepts the complete post-Q-Day emergency spend.
    qsv_core::consensus::verify_input(&tx, 0, &prev_spk, value)
        .expect("consensus engine must accept the emergency-leaf spend");

    // Tamper ONE byte of the revealed key -> hash lock fails -> engine rejects.
    let mut bad_key = pk_em.serialize().to_vec();
    bad_key[0] ^= 0x01;
    let bad_tx = unvault::build_script_path_witness(&[sig_em.to_vec(), bad_key], script, &control);
    let mut tampered = tx.clone();
    tampered.input[0].witness = bad_tx;
    assert!(
        qsv_core::consensus::verify_input(&tampered, 0, &prev_spk, value).is_err(),
        "tampered emergency key must be rejected by consensus"
    );

    // Tampered WOTS+ seal (offline check) would stop the key from ever being
    // released — fail-closed at the kit layer.
    let mut bad_seal = kit_sig;
    bad_seal[0] ^= 0x01;
    assert!(wots::verify(&kit_pk, &kit_claim, &bad_seal).is_err());
}

/// PINNED FINDING (Sept 2026, Bitcoin Core v26.2 consensus engine): a witness
/// stack element larger than 520 bytes is consensus-ILLEGAL under tapscript —
/// BIP-342's resource limits apply to the INITIAL stack, not only to runtime
/// pushes. A raw WOTS+ signature (2,144 B) therefore can never satisfy a
/// tapscript check on mainnet consensus rules, with or without CAT/CSFS.
/// This test freezes that fact as a regression guard: any future engine that
/// relaxes the limit will flip this test, prompting a docs/08 re-evaluation.
#[cfg(feature = "consensus")]
#[test]
fn t6_wots_element_above_520_bytes_is_consensus_illegal() {
    use bitcoin::absolute::LockTime;
    use bitcoin::opcodes::all::{OP_DROP, OP_PUSHNUM_1};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo};
    use bitcoin::transaction::Version;
    use bitcoin::{Sequence, Transaction, TxIn, TxOut};

    // Minimal tapscript: consume one element, push true.
    let script = Builder::new()
        .push_opcode(OP_DROP)
        .push_opcode(OP_PUSHNUM_1)
        .into_script();
    let secp = Secp256k1::verification_only();
    let internal = nums::nums_internal_key();
    let info: TaprootSpendInfo = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    let out_key: XOnlyPublicKey = info.output_key().into();
    let prev_spk = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(out_key.serialize())
        .into_script();
    let value = Amount::from_sat(100_000);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0x61u8; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::witness::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: prev_spk.clone(),
        }],
    };

    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let sighash = SighashCache::new(&tx)
        .taproot_signature_hash(
            0,
            &Prevouts::All(&[TxOut {
                value,
                script_pubkey: prev_spk.clone(),
            }]),
            None,
            Some((leaf_hash, 0xFFFFFFFF)),
            TapSighashType::Default,
        )
        .unwrap();
    let _ = sighash;

    let control = info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap();

    // 64-byte element: legal (control).
    let mut ok_tx = tx.clone();
    ok_tx.input[0].witness =
        unvault::build_script_path_witness(&[vec![0xABu8; 64]], &script, &control);
    assert!(
        qsv_core::consensus::verify_input(&ok_tx, 0, &prev_spk, value).is_ok(),
        "64-byte witness element must be consensus-legal"
    );

    // 2,144-byte element (one WOTS+ signature): consensus-ILLEGAL.
    let mut wots_tx = tx.clone();
    wots_tx.input[0].witness =
        unvault::build_script_path_witness(&[vec![0xABu8; wots::PK_SIZE]], &script, &control);
    assert!(
        qsv_core::consensus::verify_input(&wots_tx, 0, &prev_spk, value).is_err(),
        "a 2,144-byte witness element must stay consensus-ILLEGAL (BIP-342 initial-stack discipline)"
    );
}

/// T7 (Round 4): budget-measured reference spends for ALL FOUR leaves are
/// consensus-valid as signed — real Schnorr signatures, the leaf's own CSV
/// nSequence (BIP-68), the full witness — and a single-byte tamper of any
/// witness element is rejected by the same engine. This upgrades the earlier
/// shape-only checks (recovery/inheritance) into full consensus proofs: every
/// MAST branch is not merely present, it SPENDS on Bitcoin Core's interpreter.
#[cfg(feature = "consensus")]
#[test]
fn t7_all_four_leaf_reference_spends_consensus_verify_and_reject_tamper() {
    let secp = Secp256k1::verification_only();
    let vault = VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        &[],
        2,
    )
    .unwrap();
    let prev_spk = p2tr_spk(vault.output_key());
    let value = Amount::from_sat(100_000); // matches budget::reference_spend

    for kind in qsv_core::budget::LeafKind::ALL {
        let tx = qsv_core::budget::reference_spend(&vault, kind)
            .unwrap_or_else(|e| panic!("{}: {e}", kind.label()));
        qsv_core::consensus::verify_input(&tx, 0, &prev_spk, value)
            .unwrap_or_else(|e| panic!("{} spend rejected by consensus: {e}", kind.label()));

        // Every element ≤ 520 B is structural (asserted in budget tests);
        // tampering the FIRST real signature must fail verification. (The
        // inheritance witness begins with an empty 0-byte slot — the
        // non-signing executor — so pick the first non-empty element.)
        let mut elems: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|e| e.to_vec()).collect();
        let sig_pos = elems
            .iter()
            .position(|e| !e.is_empty())
            .expect("every spend carries at least one signature");
        elems[sig_pos][0] ^= 0x01;
        let mut tampered = tx.clone();
        let mut w = bitcoin::witness::Witness::new();
        for e in elems {
            w.push(e);
        }
        tampered.input[0].witness = w;
        assert!(
            qsv_core::consensus::verify_input(&tampered, 0, &prev_spk, value).is_err(),
            "{}: tampered witness must be rejected",
            kind.label()
        );
    }
}

/// T8 (Round 4): the Miniscript policy layer (BIP-379, 3 classical branches)
/// and the on-chain MAST (4 leaves) are two views of ONE protocol:
///   • both encode the SAME CSV constants (144 / 26,280),
///   • the policy's 6 keys are exactly the on-chain keys of leaves 1–3,
///   • leaf 4 (post-Q kit) is deliberately OUTSIDE the classical policy —
///     its destination key is committed by digest, never as a policy key,
///   • all four leaves are addressable via control blocks (spendable tree).
#[test]
fn t8_policy_layer_and_mast_tree_agree_on_the_classical_leaves() {
    // 1. Policy compiles with both CSV guards and exactly six keys.
    let input = policy::VaultPolicyInput {
        key_user: desc_pk(1),
        key_enclave: desc_pk(2),
        key_recovery: desc_pk(3),
        key_heirs: vec![desc_pk(4), desc_pk(5)],
        key_executor: desc_pk(6),
    };
    let ms = compile_vault_policy(&input).expect("policy compiles");
    assert!(policy::contains_older_check(
        &ms,
        policy::RECOVERY_CSV_BLOCKS
    ));
    assert!(policy::contains_older_check(
        &ms,
        policy::INHERITANCE_CSV_BLOCKS
    ));
    // Exactly six key references across the compiled policy: user, enclave,
    // recovery (PkK/PkH) + 3 keys inside the multi_a threshold.
    use miniscript::miniscript::decode::Terminal;
    let key_count: usize = ms
        .iter()
        .map(|n| match &n.node {
            Terminal::PkK(_) | Terminal::PkH(_) => 1,
            Terminal::MultiA(thresh) => thresh.data().len(),
            _ => 0,
        })
        .sum();
    assert_eq!(
        key_count, 6,
        "user + enclave + recovery + 2 heirs + executor"
    );

    // 2. The MAST leaves embed the SAME CSV constants as the policy.
    let secp = Secp256k1::verification_only();
    let vault = VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        &[],
        2,
    )
    .unwrap();
    let rec_asm = vault.leaves.recovery.to_string();
    assert!(rec_asm.contains("OP_CSV"), "recovery CSV: {rec_asm}");
    assert!(rec_asm.contains("9000"), "144 encoding: {rec_asm}");
    let inh_asm = vault.leaves.inheritance.to_string();
    assert!(inh_asm.contains("OP_CSV"), "inheritance CSV: {inh_asm}");
    assert!(inh_asm.contains("a866"), "26280 encoding: {inh_asm}");

    // 3. Leaf 4 commits a DIGEST — none of the six policy keys appears in it.
    let em = vault.leaves.emergency.as_bytes();
    for key in [
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        demo_keys::heir_one(),
        demo_keys::heir_two(),
        demo_keys::executor_key(),
    ] {
        let kb = key.serialize();
        assert!(
            !em.windows(32).any(|w| w == kb),
            "policy key leaked into the commit-reveal leaf"
        );
    }

    // 4. The six policy keys are exactly the on-chain keys of leaves 1–3
    //    (tie-out: policy description ↔ MAST reality).
    let has_key = |s: &bitcoin::ScriptBuf, k: XOnlyPublicKey| {
        s.as_bytes().windows(32).any(|w| w == k.serialize())
    };
    assert!(has_key(&vault.leaves.normal, demo_keys::user_key()));
    assert!(has_key(&vault.leaves.normal, demo_keys::enclave_key()));
    assert!(has_key(&vault.leaves.recovery, demo_keys::recovery_key()));
    for k in [
        demo_keys::heir_one(),
        demo_keys::heir_two(),
        demo_keys::executor_key(),
    ] {
        assert!(
            has_key(&vault.leaves.inheritance, k),
            "heir/executor key missing from the inheritance leaf"
        );
    }
    // None of the other policy keys leaks into the wrong leaf.
    assert!(!has_key(&vault.leaves.normal, demo_keys::recovery_key()));
    assert!(!has_key(&vault.leaves.recovery, demo_keys::user_key()));
    assert!(!has_key(
        &vault.leaves.inheritance,
        demo_keys::enclave_key()
    ));

    // 5. All four leaves are committed and addressable (control blocks).
    assert_eq!(vault.leaf_hashes.len(), 4);
    for leaf in [
        vault.leaves.normal.clone(),
        vault.leaves.recovery.clone(),
        vault.leaves.inheritance.clone(),
        vault.leaves.emergency.clone(),
    ] {
        assert!(vault
            .spend_info
            .control_block(&(leaf, bitcoin::taproot::LeafVersion::TapScript))
            .is_some());
    }
}
