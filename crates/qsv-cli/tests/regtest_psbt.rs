//! Live PSBT end-to-end (Phase 2): the Phase-1 file flow wired to a REAL
//! confirmed UTXO on a REAL bitcoind (regtest).
//!
//! Flow:
//!   start bitcoind v28.2 → mine 101 blocks → fund the demo vault address
//!   (sendtoaddress, 1 conf) → `psbt-live` reads the live outpoint from the
//!   node's UTXO set, builds the unsigned BIP-174/371 PSBT, both devices sign
//!   (each recomputing the BIP-341 sighash itself), the coordinator finalizes
//!   and the extracted transaction is broadcast — the REAL mempool accepts it
//!   (consensus + policy). A second full run proves the coordinator follows
//!   the LARGEST live coin and fails closed when nothing funds the vault.
//!
//! The stopping points (`--build-only` / `--sign-only`) are verified by
//! re-running the next stage from the live coin; split runs that would
//! double-spend the same coin are intentionally NOT broadcast (they stop
//! before the broadcast step). Tampered PSBT envelopes must exit 1.
//!
//! If no bitcoind binary is available for this platform the test soft-skips,
//! exactly like the qsv-node lifecycle test.

use std::process::Command;

use bitcoind::serde_json;

/// Runs the real `qsv-cli` binary and returns its output.
fn qsv(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args(args)
        .output()
        .expect("qsv-cli binary must run")
}

/// Same, for owned argument vectors built at runtime.
fn qsv_owned(args: &[String]) -> std::process::Output {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    qsv(&refs)
}

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

fn node_available() -> Option<bitcoind::BitcoinD> {
    let exe = match bitcoind::downloaded_exe_path() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("SKIP: bitcoind binary unavailable for this platform");
            return None;
        }
    };
    // The coordinator reads the live coin via the CHAIN namespace
    // (scantxoutset): no wallet needed on the node at all.
    let conf = bitcoind::Conf::default();
    match bitcoind::BitcoinD::with_conf(&exe, &conf) {
        Ok(d) => Some(d),
        Err(e) => {
            eprintln!("SKIP: could not start bitcoind: {e}");
            None
        }
    }
}

/// The demo vault address as printed by `vault-setup --network regtest`.
fn demo_vault_address() -> String {
    let setup = qsv(&["vault-setup", "--network", "regtest"]);
    let out = String::from_utf8_lossy(&setup.stdout);
    let line = out
        .lines()
        .find(|l| l.starts_with("Address (regtest): "))
        .unwrap_or_else(|| panic!("vault-setup must print the regtest address: {out}"));
    line.trim_start_matches("Address (regtest): ")
        .trim()
        .to_string()
}

#[test]
fn live_psbt_from_real_utxo_to_real_mempool() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().expect("temp dir");
    let dir_s = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();

    // 1. Mature funds + the one demo vault address.
    mine!(rpc, 101);
    let address = demo_vault_address();

    // 2. No live coin yet → the command must fail closed (exit 1), not fabricate.
    let empty = qsv_owned(&psbt_live_args(cookie_dir, rpc_port_of(&btc), dir_s, &[]));
    assert_eq!(
        empty.status.code(),
        Some(1),
        "unfunded vault must exit 1: {}",
        String::from_utf8_lossy(&empty.stdout)
    );
    assert!(
        String::from_utf8_lossy(&empty.stderr).contains("no live UTXO"),
        "the refusal must name the missing coin"
    );

    // 3. Fund the vault with TWO coins; the coordinator must pick the largest.
    //    The payment vout is located via gettransaction details (the wallet
    //    may place change before the payment).
    let tx_big: bitcoin::Txid = rpc
        .call(
            "sendtoaddress",
            &[
                serde_json::json!(address.clone()),
                serde_json::json!(2.0f64),
            ],
        )
        .unwrap();
    let _tx_small: bitcoin::Txid = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(address), serde_json::json!(1.0f64)],
        )
        .unwrap();
    mine!(rpc, 1);

    let (big_vout, expected_sats) =
        payment_vout(rpc, &tx_big.to_string(), &address).expect("funding UTXO confirmed");
    let big = rpc
        .get_tx_out(tx_big, big_vout)
        .expect("funding UTXO readable");
    assert!(big.confirmations >= 1);

    // 4. FULL RUN: build → sign → finish → broadcast, on the live coin.
    let run = qsv_owned(&psbt_live_args(
        cookie_dir,
        rpc_port_of(&btc),
        dir_s,
        &["--fee-sat", "1500"],
    ));
    let run_out = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "psbt-live failed: {run_out}{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        run_out.contains(&format!("{expected_sats} sats")),
        "the coordinator must spend the LARGEST live coin: {run_out}"
    );
    assert!(
        run_out.contains("mempool ACCEPTED"),
        "the REAL mempool must accept the finalized transaction: {run_out}"
    );
    let txid_line = run_out
        .lines()
        .find(|l| l.contains("txid "))
        .expect("broadcast prints the txid");
    let spent_txid = txid_line.split("txid ").nth(1).unwrap().trim().to_string();

    // 5. The node confirms the broadcast spend (its inputs were consumed).
    mine!(rpc, 1);
    let spent: bitcoin::Txid = spent_txid.parse().expect("txid hex");
    let out0 = rpc.get_tx_out(spent, 0).expect("staging output is live");
    assert!(out0.confirmations >= 1, "spend must confirm on-chain");
    // Staged value = live coin − fee (1500 sat).
    assert_eq!(
        (out0.value * 100_000_000.0).round() as u64,
        expected_sats - 1_500,
        "staged value = live coin − fee"
    );
    // The staging output is a live P2TR output locked to the demo covenant.
    let setup_spk = out0.script_pubkey.hex;
    assert!(setup_spk.starts_with("5120"), "staging output is P2TR");
}

#[test]
fn live_psbt_split_run_and_tamper_detection() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().expect("temp dir");
    let dir_s = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();

    mine!(rpc, 101);
    let address = demo_vault_address();
    let funded: bitcoin::Txid = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(address), serde_json::json!(1.5f64)],
        )
        .unwrap();
    mine!(rpc, 1);
    let (_, expected_sats) =
        payment_vout(rpc, &funded.to_string(), &address).expect("funding confirmed");

    // 1. BUILD ONLY stops after the unsigned PSBT.
    let build = qsv_owned(&psbt_live_args(
        cookie_dir,
        rpc_port_of(&btc),
        dir_s,
        &["--build-only"],
    ));
    let build_out = String::from_utf8_lossy(&build.stdout);
    assert!(
        build.status.success() && build_out.contains("BUILD ONLY"),
        "build-only must stop early: {build_out} | stderr: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let unsigned = std::fs::read_to_string(dir.path().join("vault.psbt")).unwrap();
    assert!(!unsigned.is_empty());
    assert!(
        build_out.contains(&format!("{expected_sats} sats")),
        "build-only also reports the largest live coin: {build_out}"
    );

    // 2. SIGN ONLY: resumes from the live coin (deterministic rerun).
    let sign = qsv_owned(&psbt_live_args(
        cookie_dir,
        rpc_port_of(&btc),
        dir_s,
        &["--sign-only"],
    ));
    let sign_out = String::from_utf8_lossy(&sign.stdout);
    assert!(
        sign.status.success() && sign_out.contains("SIGN ONLY"),
        "sign-only must stop after signing: {sign_out} | stderr: {}",
        String::from_utf8_lossy(&sign.stderr)
    );
    let signed = std::fs::read_to_string(dir.path().join("vault-signed.psbt")).unwrap();
    assert!(!signed.is_empty());

    // 3. FINISH: the full flow again — the live coin is spent exactly once.
    let finish = qsv_owned(&psbt_live_args(
        cookie_dir,
        rpc_port_of(&btc),
        dir_s,
        &["--fee-sat", "1500"],
    ));
    let finish_out = String::from_utf8_lossy(&finish.stdout);
    assert!(
        finish.status.success() && finish_out.contains("mempool ACCEPTED"),
        "the single live coin is spent exactly once: {finish_out} | stderr: {}",
        String::from_utf8_lossy(&finish.stderr)
    );

    // 4. Tampered envelopes fail closed, never sign garbage:
    //    (a) non-base64 garbage → decode error, (b) valid base64 with a
    //    wrong magic → PSBT deserialization error. Both must exit 1.
    let bad1 = dir.path().join("vault-garbage.psbt");
    std::fs::write(&bad1, "not base64 at all!!").unwrap();
    let reject1 = qsv(&[
        "psbt",
        "sign",
        "--in",
        bad1.to_str().unwrap(),
        "--out",
        "/dev/null",
    ]);
    assert_eq!(
        reject1.status.code(),
        Some(1),
        "non-base64 PSBT must exit 1"
    );
    let bad2 = dir.path().join("vault-wrongmagic.psbt");
    std::fs::write(&bad2, "QUJDRA==").unwrap(); // valid base64, wrong magic
    let reject2 = qsv(&[
        "psbt",
        "sign",
        "--in",
        bad2.to_str().unwrap(),
        "--out",
        "/dev/null",
    ]);
    assert_eq!(
        reject2.status.code(),
        Some(1),
        "wrong-magic PSBT must exit 1"
    );
}

/// MULTI-INPUT coin selection (Part 2): fund the vault with THREE coins,
/// aggregate them into ONE multi-input PSBT, both devices sign every input,
/// the multi-input consensus self-check passes and the mempool accepts the
/// consolidation spend. An unreachable coin count fails closed.
#[test]
fn live_psbt_multi_input_consolidation() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().expect("temp dir");
    let dir_s = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();

    mine!(rpc, 101);
    let address = demo_vault_address();
    // THREE distinct coins to the vault address (confirmed)."
    for amount in [0.6f64, 0.7, 0.8] {
        let _: bitcoin::Txid = rpc
            .call(
                "sendtoaddress",
                &[serde_json::json!(address), serde_json::json!(amount)],
            )
            .unwrap();
    }
    mine!(rpc, 1);

    // More coins requested than exist ⇒ exit 1 (fail-closed selection).
    let short = qsv_owned(&psbt_live_args(
        cookie_dir,
        rpc_port_of(&btc),
        dir_s,
        &["--min-inputs", "5"],
    ));
    assert_eq!(
        short.status.code(),
        Some(1),
        "5-coin selection must fail with 3 coins: {}",
        String::from_utf8_lossy(&short.stderr)
    );

    // The consolidation run: 3 inputs × 2 devices = 6 signatures.
    let run = qsv_owned(&psbt_live_args(
        cookie_dir,
        rpc_port_of(&btc),
        dir_s,
        &["--min-inputs", "3", "--fee-sat", "1500"],
    ));
    let out = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "multi-input run failed: {out} | stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        out.contains("multi-input sweep") && out.contains("3 coins"),
        "selection banner: {out}"
    );
    assert!(
        out.contains("3 inputs × 2 devices"),
        "signing banner: {out}"
    );
    assert!(
        out.contains("mempool ACCEPTED"),
        "the consolidation spend must be accepted: {out}"
    );
    let broadcast = out
        .lines()
        .find(|l| l.contains("broadcast:") && l.contains("txid "))
        .expect("broadcast line");
    let spent_txid = broadcast.split("txid ").nth(1).unwrap().trim();

    // The 3 coins are consumed: the aggregate output confirms on-chain.
    mine!(rpc, 1);
    let txid: bitcoin::Txid = spent_txid.parse().expect("txid hex");
    let out0 = rpc.get_tx_out(txid, 0).expect("consolidation output live");
    assert!(out0.confirmations >= 1);
    // 0.6 + 0.7 + 0.8 BTC − 1500 sat fee (BTC amounts via f64 rounding).
    let expected = 210_000_000 - 1_500;
    assert_eq!(
        (out0.value * 100_000_000.0).round() as u64,
        expected,
        "aggregate = 3 coins − fee"
    );
}

/// Helper: the node's randomly chosen RPC port (test harness assigns one).
fn rpc_port_of(btc: &bitcoind::BitcoinD) -> u16 {
    btc.params.rpc_socket.port()
}

/// Locates the payment vout of a wallet transaction by address and returns
/// (vout, satoshis). The wallet may put change before the payment.
fn payment_vout(rpc: &bitcoind::Client, txid: &str, address: &str) -> Option<(u64, u64)> {
    let details: serde_json::Value = rpc
        .call("gettransaction", &[serde_json::json!(txid)])
        .ok()?;
    for d in details["details"].as_array()? {
        if d["category"].as_str() == Some("send")
            && d["address"].as_str() == Some(address)
            && d["vout"].is_u64()
        {
            let vout = d["vout"].as_u64()?;
            // gettransaction reports "send" amounts as negative.
            let sats = (d["amount"].as_f64()?.abs() * 100_000_000.0).round() as u64;
            return Some((vout, sats));
        }
    }
    None
}

/// Builds the `psbt-live` invocation with extra flags.
fn psbt_live_args(
    cookie_dir: &std::path::Path,
    rpc_port: u16,
    dir_s: &str,
    extra: &[&str],
) -> Vec<String> {
    let mut args = vec![
        "psbt-live".to_string(),
        "--datadir".to_string(),
        cookie_dir.to_str().unwrap().to_string(),
        "--rpc-port".to_string(),
        rpc_port.to_string(),
        "--dir".to_string(),
        dir_s.to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    args
}
