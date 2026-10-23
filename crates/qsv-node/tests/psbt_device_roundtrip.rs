//! End-to-end PSBT device-signing round trip against a REAL bitcoind
//! (downloaded by the `bitcoind` dev-dependency, v28.2).
//!
//! This is the hardware-wallet rehearsal (Coldcard/Ledger contract): the
//! coordinator builds an unsigned BIP-174/371 PSBT, two independent "devices"
//! recompute the BIP-341 sighash locally and sign, the coordinator verifies
//! the returned signatures, assembles the witness and extracts the
//! transaction — which the real node then accepts into its mempool.
//!
//! Soft-skips when the bitcoind binary is unavailable for the platform.

use bitcoin::amount::Amount;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::OutPoint;
use bitcoind::{serde_json, BitcoinD};
use qsv_core::demo_keys;
use qsv_core::psbt::{
    assemble_witness, build_unsigned_psbt, device_sign_input, finalize_and_extract,
    sighash_for_psbt_input, verify_device_signature, VaultPsbtInput,
};
use qsv_core::taproot::VaultTaproot;
use qsv_pqc::PqcIdentity;

/// Mines `n` blocks to a fresh miner address via generatetoaddress.
macro_rules! mine {
    ($rpc:expr, $n:expr) => {{
        let addr: String = $rpc
            .call("getnewaddress", &[serde_json::json!("")])
            .unwrap();
        let _: serde_json::Value = $rpc
            .call(
                "generatetoaddress",
                &[serde_json::json!($n), serde_json::json!(addr)],
            )
            .unwrap();
    }};
}

fn p2tr_spk(out_key: bitcoin::XOnlyPublicKey) -> bitcoin::ScriptBuf {
    Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(out_key.serialize())
        .into_script()
}

fn node_available() -> Option<BitcoinD> {
    let exe = match bitcoind::downloaded_exe_path() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("SKIP: bitcoind binary unavailable for this platform");
            return None;
        }
    };
    let conf = bitcoind::Conf::default();
    match BitcoinD::with_conf(&exe, &conf) {
        Ok(d) => Some(d),
        Err(e) => {
            eprintln!("SKIP: could not start bitcoind: {e}");
            None
        }
    }
}

#[test]
fn psbt_device_roundtrip_is_accepted_by_real_node() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let secp_v = Secp256k1::verification_only();

    // 1. Vault: enclave key from the gate seed goes into the policy (same
    //    binding as the lifecycle e2e).
    let enclave_seed = [43u8; 32];
    let enclave_kp = qsv_pqc::enclave_keypair_from_seed(&enclave_seed).unwrap();
    let enclave_pk = qsv_pqc::enclave_xonly_public_key(&enclave_kp);
    let vault = VaultTaproot::derive(
        &secp_v,
        demo_keys::user_key(),
        enclave_pk,
        demo_keys::recovery_key(),
        &[demo_keys::heir_one(), demo_keys::heir_two()],
        2,
    )
    .unwrap();
    let vault_addr = vault.address(bitcoin::Network::Regtest);
    let vault_spk = p2tr_spk(vault.output_key());

    // 2. Fund the vault on-chain.
    mine!(rpc, 101);
    let funded: bitcoin::Txid = rpc
        .call(
            "sendtoaddress",
            &[
                serde_json::json!(vault_addr.to_string()),
                serde_json::json!(3.0f64),
            ],
        )
        .unwrap();
    mine!(rpc, 1);

    // 3. Locate the confirmed vault UTXO (wallet RPC, no -txindex needed).
    let details: serde_json::Value = rpc
        .call("gettransaction", &[serde_json::json!(funded.to_string())])
        .unwrap();
    let mut utxo: Option<(OutPoint, Amount)> = None;
    if let Some(vouts) = details["details"].as_array() {
        for d in vouts {
            if d["category"].as_str() == Some("send") && d["vout"].is_u64() {
                let vout = d["vout"].as_u64().expect("vout index");
                let amt_btc = d["amount"].as_f64().map(|a| a.abs()).expect("amount");
                utxo = Some((
                    OutPoint::new(funded, vout as u32),
                    Amount::from_sat((amt_btc * 100_000_000.0).round() as u64),
                ));
                break;
            }
        }
    }
    let (outpoint, prev_value) = utxo.expect("vault output not found in wallet details");

    // 4. COORDINATOR: build the unsigned BIP-174/371 PSBT with full taproot
    //    context (witness_utxo, tap_scripts, tap_internal_key, sighash type).
    let input = VaultPsbtInput {
        outpoint,
        prev_value,
        prev_script_pubkey: vault_spk.clone(),
        leaf_script: vault.leaves.normal.clone(),
        control_block: vault
            .spend_info
            .control_block(&(
                vault.leaves.normal.clone(),
                bitcoin::taproot::LeafVersion::TapScript,
            ))
            .unwrap(),
        merkle_root: vault.merkle_root(),
        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
    };
    let staging_key = demo_keys::recovery_keypair();
    let staging_output_key = {
        let (k, _parity) = staging_key.x_only_public_key();
        let tweak = bitcoin::taproot::TapTweakHash::from_key_and_tweak(k, None).to_scalar();
        k.add_tweak(&secp_v, &tweak).unwrap().0
    };
    let outputs = vec![bitcoin::TxOut {
        value: prev_value - Amount::from_sat(2_000),
        script_pubkey: p2tr_spk(staging_output_key),
    }];
    let psbt =
        build_unsigned_psbt(&input, outputs, vault.internal_key).expect("unsigned PSBT must build");

    // 5. DEVICE 1 (user hardware wallet): recomputes the sighash locally from
    //    the PSBT and signs. Key material never leaves the "device".
    let sig_user = device_sign_input(&psbt, 0, &vault.leaves.normal, &demo_keys::user_keypair())
        .expect("device 1 must sign");

    // 6. DEVICE 2 (PQC-gated enclave co-signer): the gate releases its
    //    BIP-340 co-signature only for a valid ML-DSA-65 proof over the EXACT
    //    sighash, then signs through the same PSBT contract.
    let sighash = sighash_for_psbt_input(&psbt, 0, &vault.leaves.normal).unwrap();
    let pqc = PqcIdentity::from_seed(&[78u8; 32]);
    let pqc_sig = pqc.sign(&sighash);
    let gate_sig = qsv_pqc::enclave_sign_if_pqc_valid(
        pqc.verifying_key_bytes(),
        &pqc_sig,
        &sighash,
        &enclave_seed,
    )
    .expect("gate must release co-signature for valid PQC proof");
    // The gate's release verifies under the enclave policy key, and the
    // enclave device signs through the same PSBT contract. Nonce policies
    // differ (gate: fixed-aux RFC-6979; device: sighash-bound aux), so the
    // signatures are distinct but BOTH must verify under the same key.
    let sig_enclave =
        device_sign_input(&psbt, 0, &vault.leaves.normal, &enclave_kp).expect("device 2 must sign");
    verify_device_signature(&secp_v, enclave_pk, &sighash, &gate_sig)
        .expect("gate-released signature must verify under the policy key");

    // 7. COORDINATOR: verify both returned signatures (fail-closed on any
    //    mismatch) before assembling.
    let sig_user_arr: [u8; 64] = sig_user.clone().try_into().unwrap();
    verify_device_signature(&secp_v, demo_keys::user_key(), &sighash, &sig_user_arr)
        .expect("user device signature must verify");
    let sig_enclave_arr: [u8; 64] = sig_enclave.clone().try_into().unwrap();
    verify_device_signature(&secp_v, enclave_pk, &sighash, &sig_enclave_arr)
        .expect("enclave device signature must verify");

    // 8. Assemble + finalize + extract (BIP-174 finalize/extract).
    //    Execution order: script consumes σ_enclave (top) then σ_user.
    let witness = assemble_witness(
        &[sig_enclave, sig_user],
        &vault.leaves.normal,
        &input.control_block,
    );
    let mut finalized = psbt;
    let spend_tx = finalize_and_extract(&mut finalized, witness)
        .expect("finalized PSBT must extract to a transaction");

    // 9. The REAL node accepts the assembled transaction into its mempool.
    let hex = bitcoin::consensus::encode::serialize_hex(&spend_tx);
    let txid: bitcoin::Txid = rpc
        .call("sendrawtransaction", &[serde_json::json!(hex)])
        .expect("real node must accept the PSBT-assembled transaction");
    mine!(rpc, 1);

    // 10. The staging output exists and is unspent on-chain.
    let staging_txid = spend_tx.compute_txid();
    assert_eq!(staging_txid, txid, "node txid must match our computation");
    let staging_out = rpc.get_tx_out(staging_txid, 0).expect("staging UTXO live");
    assert!(staging_out.confirmations >= 1);
    assert_eq!(
        Amount::from_btc(staging_out.value).unwrap(),
        prev_value - Amount::from_sat(2_000)
    );
}
