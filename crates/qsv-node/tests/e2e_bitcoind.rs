//! End-to-end vault lifecycle against a REAL bitcoind (v26+).
//!
//! The `bitcoind` dev-dependency (with the `download` + `28_2` features)
//! fetches a bitcoind v28.2 binary at build time. If the platform/arch is
//! unsupported, the test soft-skips instead of failing CI on irrelevant
//! platforms.
//!
//! Flow (regtest):
//!   mine 101 blocks → fund vault (sendtoaddress) → confirm
//!   → unvault (hybrid 2-of-2, PQC-gated enclave sig) → sendrawtransaction
//!   → mine → CSV maturity (144 blocks mined) → settlement
//!   → sendrawtransaction → mine → confirmations asserted.
//!
//! Consensus: the node itself is the final judge; additionally every tx is
//! self-verified through libbitcoinconsensus inside the lifecycle builders.

use bitcoin::amount::Amount;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::OutPoint;
use bitcoind::{serde_json, BitcoinD};
use qsv_core::demo_keys;
use qsv_core::taproot::VaultTaproot;
use qsv_node::lifecycle::{build_settlement, finalize_unvault, prepare_unvault, LiveUtxo};
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

fn p2tr_spk(out_key: XOnlyPublicKey) -> bitcoin::ScriptBuf {
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
fn e2e_full_vault_lifecycle_on_real_bitcoind() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let secp_v = Secp256k1::verification_only();

    // 1. Vault derivation. The enclave co-signer keypair is derived from the
    // gate seed FIRST and its x-only key goes into the vault policy, so the
    // gate-released signature verifies under the policy's key_enclave.
    let enclave_seed = [42u8; 32];
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

    // 2. Mine mature funds to the miner wallet.
    mine!(rpc, 101);

    // 3. Fund the vault with a confirmed UTXO.
    let funded: bitcoin::Txid = rpc
        .call(
            "sendtoaddress",
            &[
                serde_json::json!(vault_addr.to_string()),
                serde_json::json!(5.0f64),
            ],
        )
        .unwrap();
    mine!(rpc, 1);

    // Read the confirmed vault UTXO via the wallet RPC (no -txindex needed):
    // the vault output is the one whose address == our vault address.
    let details: serde_json::Value = rpc
        .call("gettransaction", &[serde_json::json!(funded.to_string())])
        .unwrap();
    let mut utxo: Option<LiveUtxo> = None;
    if let Some(vouts) = details["details"].as_array() {
        for d in vouts {
            if d["category"].as_str() == Some("send") && d["vout"].is_u64() {
                let vout = d["vout"].as_u64().expect("vout index");
                let amt_btc = d["amount"].as_f64().map(|a| a.abs()).expect("amount");
                utxo = Some(LiveUtxo {
                    outpoint: OutPoint::new(funded, vout as u32),
                    value: bitcoin::Amount::from_sat((amt_btc * 100_000_000.0).round() as u64),
                    script_pubkey: vault_spk.clone(),
                });
                break;
            }
        }
    }
    let utxo = utxo.unwrap_or_else(|| {
        panic!(
            "vault output not found; details={details}",
            details = serde_json::to_string_pretty(&details).unwrap_or_default()
        )
    });
    assert!(utxo.value > Amount::from_sat(100_000));

    // 4. Prepare the unvault intent: exact sighash + user signature.
    let staging_key = demo_keys::recovery_keypair();
    let intent = prepare_unvault(
        &vault,
        &utxo,
        staging_key.x_only_public_key().0,
        Amount::from_sat(2_000),
        &demo_keys::user_keypair(),
    )
    .expect("intent must build");

    // 5. PQC gate exchange over the EXACT final sighash: the enclave releases
    //    its BIP-340 co-signature only for a valid ML-DSA-65 proof.
    let pqc = PqcIdentity::from_seed(&[77u8; 32]);
    let pqc_sig = pqc.sign(&intent.sighash);
    let enclave_sig = qsv_pqc::enclave_sign_if_pqc_valid(
        pqc.verifying_key_bytes(),
        &pqc_sig,
        &intent.sighash,
        &enclave_seed,
    )
    .expect("gate must release co-signature for valid PQC proof");

    // 6. Bind the co-signature and self-verify with libbitcoinconsensus.
    let unvault_tx = finalize_unvault(&vault, &utxo, intent, enclave_sig)
        .expect("unvault must be consensus-valid");

    // 6. The node accepts it into the mempool (consensus + policy pass).
    let hex = bitcoin::consensus::encode::serialize_hex(&unvault_tx);
    let _txid: bitcoin::Txid = rpc
        .call("sendrawtransaction", &[serde_json::json!(hex)])
        .unwrap();
    mine!(rpc, 1);

    // 7. CSV maturity: the staging script requires 144 blocks of relative lock,
    //    counted from the staging output's confirmation block.
    mine!(rpc, 144);

    // 8. Read the staging UTXO (single output of the unvault tx).
    let staging_txid = unvault_tx.compute_txid();
    let staging_out = rpc.get_tx_out(staging_txid, 0).unwrap();
    let staging_utxo = LiveUtxo {
        outpoint: OutPoint::new(staging_txid, 0),
        value: Amount::from_btc(staging_out.value).unwrap(),
        script_pubkey: unvault_tx.output[0].script_pubkey.clone(),
    };

    // 9. Settlement to the heir destination, consensus-verified.
    let heir_dest = demo_keys::heir_one();
    let settle_tx = build_settlement(
        &staging_utxo,
        &staging_key,
        heir_dest,
        Amount::from_sat(1_000),
        144,
    )
    .expect("settlement must be consensus-valid");
    let hex2 = bitcoin::consensus::encode::serialize_hex(&settle_tx);
    let settle_txid: bitcoin::Txid = rpc
        .call("sendrawtransaction", &[serde_json::json!(hex2)])
        .unwrap();
    mine!(rpc, 1);

    // 10. The settlement is confirmed: its output is now an unspent UTXO
    // locked to the heir destination (gettxout needs no -txindex).
    let settled_out = rpc
        .get_tx_out(settle_txid, 0)
        .expect("gettxout after confirmation");
    assert!(
        settled_out.confirmations >= 1,
        "settlement must be confirmed"
    );
}
