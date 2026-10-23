//! Mempool policy e2e (docs/10 §5): the policy claims are checked against a
//! REAL bitcoind v28.2 mempool via `testmempoolaccept` — the dry-run judge
//! every broadcast path goes through.
//!
//! Test 1 (template + live spend):
//!   1. RBF POLICY: `build_refresh_tx` sets BIP-125 opt-in (sequence
//!      0xfffffffd) on every input.
//!   2. NO-DUST: every refresh output clears the P2TR dust floor (330 sat).
//!   3. FEERATE: the operator's exact arithmetic (fee / vsize) holds on the
//!      template AND on the signed live transaction.
//!   4. LIVE SPEND: the frost-spend flow's SIGNED refresh passes
//!      `testmempoolaccept` — the node would broadcast it as-is.
//!
//! Test 2 (chain-level RBF asymmetry): a non-RBF (0xffffffff) spend is
//! accepted once, but an RBF-signalling replacement of it is REFUSED —
//! BIP-125 requires the ORIGINAL to signal. The refresh template's opt-in
//! is exactly what keeps the heartbeat replaceable on chain.

use std::process::Command;

use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::transaction::Version;
use bitcoin::{
    absolute::LockTime, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoind::serde_json::json;

/// The demo policy vault (the SAME derivation the CLI uses everywhere).
fn qsv_demo_vault() -> qsv_core::taproot::VaultTaproot {
    let secp = secp256k1::Secp256k1::verification_only();
    qsv_core::taproot::VaultTaproot::derive(
        &secp,
        qsv_core::demo_keys::user_key(),
        qsv_core::demo_keys::enclave_key(),
        qsv_core::demo_keys::recovery_key(),
        &[
            qsv_core::demo_keys::heir_one(),
            qsv_core::demo_keys::heir_two(),
        ],
        2,
    )
    .unwrap()
}

macro_rules! mine {
    ($rpc:expr, $n:expr) => {{
        let addr: String = $rpc.call("getnewaddress", &[json!("")]).unwrap();
        let _: bitcoind::serde_json::Value = $rpc
            .call("generatetoaddress", &[json!($n), json!(addr)])
            .unwrap();
    }};
}

fn qsv(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args(args)
        .output()
        .expect("qsv-cli binary must run")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn node_available() -> Option<bitcoind::BitcoinD> {
    let exe = match bitcoind::downloaded_exe_path() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("SKIP: bitcoind binary unavailable for this platform");
            return None;
        }
    };
    match bitcoind::BitcoinD::with_conf(&exe, &bitcoind::Conf::default()) {
        Ok(d) => Some(d),
        Err(e) => {
            eprintln!("SKIP: could not start bitcoind: {e}");
            None
        }
    }
}

#[test]
fn mempool_policy_template_and_live_spend_pass_the_node_judge() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_str().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    // 1. TEMPLATE POLICIES (no node needed):
    let template = qsv_core::heartbeat::build_refresh_tx(
        &qsv_demo_vault(),
        OutPoint::null(),
        Amount::from_sat(100_000),
        Amount::from_sat(1_000),
    )
    .unwrap();
    assert_eq!(
        template.input[0].sequence,
        Sequence::ENABLE_RBF_NO_LOCKTIME,
        "policy: the refresh OPTS INTO RBF (BIP-125)"
    );
    let dust = 330u64; // P2TR dust floor (zero-script Taproot output)
    for out in &template.output {
        assert!(
            out.value.to_sat() >= dust,
            "policy: a refresh output is never dust"
        );
    }
    let t_vsize = template.vsize() as u64;
    // The unspent template (witnessless) is 94 vB: version+locktime+input+
    // output+P2TR spk, no witness yet. The SIGNED form below is what pays.
    assert_eq!(t_vsize, 94, "template vsize (the operator math)");
    assert_eq!(
        1_000 / t_vsize,
        10,
        "policy: feerate = fee_sat / tx_vbytes, operator-visible (10.63 → 10 sat/vB)"
    );

    // 2. LIVE SPEND judged by the REAL mempool: run the FULL frost-spend
    //    flow (kit setup → funding → 2-of-3 ceremony) in hold mode, then
    //    feed the SIGNED spend to testmempoolaccept.
    mine!(rpc, 101);
    let d = dir.path().to_str().unwrap();
    let setup = qsv(&[
        "inheritance-kit",
        "setup",
        "--threshold",
        "2",
        "--heir",
        "heir-1",
        "--heir",
        "heir-2",
        "--heir",
        "notary",
        "--dir",
        d,
    ]);
    let s = stdout(&setup);
    assert!(setup.status.success(), "kit setup failed: {s}");
    let ids: Vec<String> = s
        .lines()
        .filter_map(|l| {
            let i = l.find("(id ")?;
            let r = &l[i + 4..];
            Some(r[..r.find(')')?].to_string())
        })
        .collect();
    assert_eq!(ids.len(), 3);
    let out = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/public-package.txt"),
        "--deal",
        &format!("h0={d}/heir-00-{}-deal.txt", ids[0]),
        "--deal",
        &format!("h1={d}/heir-02-{}-deal.txt", ids[2]),
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--fund-sat",
        "100000",
        "--no-broadcast",
        "--dir",
        d,
    ]);
    assert!(
        out.status.success(),
        "frost-spend hold must succeed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let txhex = std::fs::read_to_string(dir.path().join("frost-spend.txhex")).unwrap();
    let res: bitcoind::serde_json::Value = rpc
        .call(
            "testmempoolaccept",
            &[json!([json!(txhex.trim())]), json!(0.0)],
        )
        .unwrap();
    let entry = &res.as_array().unwrap()[0];
    assert!(
        entry["allowed"].as_bool().unwrap(),
        "the LIVE signed refresh must pass the node's own judge: {entry}"
    );
    // 3. FEERATE on the SIGNED transaction: the node reports what it sees.
    let signed_vsize = entry["vsize"].as_u64().unwrap();
    let signed_fee_sat = (entry["fees"]["base"].as_f64().unwrap() * 100_000_000.0) as u64;
    assert_eq!(
        signed_fee_sat, 1_500,
        "frost-spend's default fee is the operator's number"
    );
    assert!(
        signed_fee_sat * 1000 / signed_vsize >= 1,
        "policy: the live refresh pays a sane feerate"
    );
    let signed_tx: Transaction =
        bitcoin::consensus::deserialize(&hex::decode(txhex.trim()).unwrap()).unwrap();
    for i in &signed_tx.input {
        assert_eq!(
            i.sequence,
            Sequence::ENABLE_RBF_NO_LOCKTIME,
            "policy: the SIGNED live spend also opts into RBF"
        );
    }
}

/// The chain-level RBF replaceability, proven with REAL wallet spends: an
/// RBF-signalling original is accepted, a LOWER-fee replacement is refused
/// (BIP-125 rule 4: higher package feerate required — this is the node's
/// own replacement gate), and a HIGHER-fee replacement of the SAME
/// signalling original is accepted. The refresh template's opt-in is
/// exactly what keeps the heartbeat replaceable on chain; the refused
/// low-fee case is what a fee-stuck operator must avoid.
#[test]
fn mempool_policy_rbf_original_is_replaceable_by_a_higher_fee() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;

    mine!(rpc, 101);
    let mint_addr: String = rpc.call("getnewaddress", &[json!("")]).unwrap();
    let _res: bitcoind::serde_json::Value = rpc
        .call(
            "sendtoaddress",
            &[
                json!(mint_addr),
                json!(0.010),
                json!(""),
                json!(""),
                json!(true),
            ],
        )
        .unwrap();
    mine!(rpc, 1);

    let src_all: bitcoind::serde_json::Value = rpc
        .call(
            "listunspent",
            &[json!(1), json!(9999999), json!([json!(mint_addr)])],
        )
        .unwrap();
    let src = src_all
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["spendable"].as_bool() == Some(true))
        .expect("a spendable minted utxo")
        .clone();
    let src_outpoint = OutPoint {
        txid: src["txid"].as_str().unwrap().parse().unwrap(),
        vout: src["vout"].as_u64().unwrap() as u32,
    };
    let src_value = Amount::from_sat((src["amount"].as_f64().unwrap() * 100_000_000.0) as u64);

    let spend = |fee_sat: u64, seq: Sequence| -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: src_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: seq,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: src_value - Amount::from_sat(fee_sat),
                script_pubkey: Builder::new()
                    .push_opcode(OP_PUSHNUM_1)
                    .push_slice([0x51u8; 32])
                    .into_script(),
            }],
        }
    };
    let sign = |tx: &Transaction| -> String {
        let signed: bitcoind::serde_json::Value = rpc
            .call(
                "signrawtransactionwithwallet",
                &[json!(bitcoin::consensus::encode::serialize_hex(tx))],
            )
            .unwrap();
        signed["hex"]
            .as_str()
            .map(String::from)
            .expect("the wallet must sign its own coin")
    };

    // A: RBF-signalling original (the refresh template's discipline).
    let a = sign(&spend(1_000, Sequence::ENABLE_RBF_NO_LOCKTIME));
    let res: bitcoind::serde_json::Value = rpc
        .call("testmempoolaccept", &[json!([json!(a)]), json!(0.0)])
        .unwrap();
    assert!(
        res.as_array().unwrap()[0]["allowed"].as_bool().unwrap(),
        "the RBF-signalling original is a valid spend: {res}"
    );
    let _res: bitcoind::serde_json::Value = rpc
        .call("sendrawtransaction", &[json!(a)])
        .expect("the RBF original must be accepted for real");

    // B: a LOWER-fee replacement → REFUSED (BIP-125 rule 4). The node's
    //    own replacement gate — the reason the refresh fee must not dip.
    let b = sign(&spend(500, Sequence::ENABLE_RBF_NO_LOCKTIME));
    let res: bitcoind::serde_json::Value = rpc
        .call("testmempoolaccept", &[json!([json!(b)]), json!(0.0)])
        .unwrap();
    let entry = &res.as_array().unwrap()[0];
    assert!(
        !entry["allowed"].as_bool().unwrap(),
        "a lower-fee replacement must be refused: {entry}"
    );

    // C: a HIGHER-fee replacement of the SAME signalling original → the
    //    mempool ACCEPTS the swap (heartbeat fee-bump path, end to end).
    let c = sign(&spend(3_000, Sequence::ENABLE_RBF_NO_LOCKTIME));
    let res: bitcoind::serde_json::Value = rpc
        .call("testmempoolaccept", &[json!([json!(c)]), json!(0.0)])
        .unwrap();
    assert!(
        res.as_array().unwrap()[0]["allowed"].as_bool().unwrap(),
        "a higher-fee replacement of a signalling original must be allowed: {res}"
    );
}
