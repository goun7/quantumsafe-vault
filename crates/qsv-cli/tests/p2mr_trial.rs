//! EXPERIMENTAL BIP-360 (P2MR) source-branch trial e2e (docs/11 Phase 4b,
//! K1-gated): a REAL regtest coin is funded at the vault's experimental P2MR
//! address (witness v2 program = merkle root) and pushed through the
//! full psbt-live machinery — build → sign → verify → finalize → consensus.
//!
//!   1. MAINNET REFUSAL: --p2mr on any network other than regtest exits 1.
//!   2. ADDRESS MATH LIVE: the trial's own fail-closed path prints the
//!      experimental address (bcrt1z…); bitcoind accepts it and a
//!      wallet-funded coin to it is discovered by the same read-only scan.
//!   3. FULL TRIAL: the spend through the SAME hybrid leaf verifies under
//!      libbitcoinconsensus and lands in p2mr-source-trial.txhex —
//!      broadcast is structurally impossible (K1 outstanding: no live
//!      consensus rules for witness v2; the mempool stays empty).

use std::process::Command;

use bitcoind::serde_json;

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

/// The demo vault's experimental P2MR address, taken from the trial's own
/// fail-closed error line ("no live UTXO pays bcrt1z… — fund it first").
/// This exercises the REAL address derivation end to end: the CLI derives
/// the witness-v2 program from the vault's merkle root, bech32m-encodes it
/// under the regtest HRP and scans for it via scantxoutset.
fn demo_p2mr_address(cookie_dir: &str, port: &str) -> String {
    let out = qsv(&[
        "psbt-live",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        port,
        "--p2mr",
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unfunded P2MR vault must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = stderr(&out);
    let start = text
        .find("no live UTXO pays ")
        .expect("fail-closed line present");
    let rest = &text[start + "no live UTXO pays ".len()..];
    let end = rest
        .find(" —")
        .expect("error line ends with an em-dash clause");
    rest[..end].trim().to_string()
}

#[test]
fn p2mr_source_trial_refuses_mainnet_and_completes_on_regtest() {
    // 1. MAINNET REFUSAL: the trial is regtest-only, fail-closed.
    let out = qsv(&[
        "psbt-live",
        "--datadir",
        "/nonexistent-node",
        "--p2mr",
        "--network",
        "bitcoin",
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "mainnet P2MR trial must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stderr(&out).contains("REGTEST-ONLY"));

    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_str().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 101);
    let p2mr_addr = demo_p2mr_address(cookie_dir, &port);
    assert!(p2mr_addr.starts_with("bcrt1z"), "got {p2mr_addr}");

    // 2. ADDRESS MATH LIVE: bitcoind accepts the experimental P2MR address
    //    and the funded coin is visible to the trial's read-only scan.
    let _: serde_json::Value = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(p2mr_addr), serde_json::json!(0.001)],
        )
        .expect("bitcoind must accept the experimental P2MR address");
    mine!(rpc, 1);

    // 3. FULL TRIAL: build, sign, verify, finalize — then HOLD.
    let out_weight1;
    let out = {
        let o = qsv(&[
            "psbt-live",
            "--datadir",
            cookie_dir,
            "--rpc-port",
            &port,
            "--p2mr",
            "--dir",
            d,
        ]);
        out_weight1 = o;
        &out_weight1
    };
    assert!(
        out.status.success(),
        "P2MR source trial must complete: {}{}",
        stdout(out),
        stderr(out)
    );
    assert!(stdout(out).contains("P2MR source trial: COMPLETE"));
    let hold = dir.path().join("p2mr-source-trial.txhex");
    assert!(hold.exists(), "the hold artifact must exist");
    let hex_tx = std::fs::read_to_string(&hold).unwrap();
    assert!(!hex_tx.trim().is_empty());

    // K1: nothing was ever broadcast — the mempool is empty and the coin
    // is still locked at the P2MR address.
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert!(
        mempool.as_array().unwrap().is_empty(),
        "the K1 gate must keep the trial off the network: {mempool}"
    );
    let coins: serde_json::Value = rpc
        .call(
            "scantxoutset",
            &[
                serde_json::json!("start"),
                serde_json::json!([{ "desc": format!("addr({p2mr_addr})") }]),
            ],
        )
        .unwrap();
    assert_eq!(
        coins["unspents"].as_array().map(Vec::len),
        Some(1),
        "the P2MR coin must remain untouched: {coins}"
    );

    // 4. MULTI-INPUT TRIAL: fund a SECOND P2MR coin, then consolidate BOTH
    //    live P2MR coins into ONE trial transaction (--min-inputs 2). The
    //    PSBT engine runs with full multi-input context; the hold artifact
    //    overwrites and the mempool stays empty (K1).
    let _: serde_json::Value = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(p2mr_addr), serde_json::json!(0.002)],
        )
        .unwrap();
    mine!(rpc, 1);
    let out_multi = qsv(&[
        "psbt-live",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--p2mr",
        "--min-inputs",
        "2",
        "--dir",
        d,
    ]);
    assert!(
        out_multi.status.success(),
        "multi-input P2MR trial must complete: {}{}",
        stdout(&out_multi),
        stderr(&out_multi)
    );
    assert!(
        stdout(&out_multi).contains("2 coins"),
        "aggregation line: {}",
        stdout(&out_multi)
    );
    // MEASURED DELTA (docs/11 §7.5): both runs print the real weight of the
    // assembled trial tx beside a P2TR twin (+32 B control block per input);
    // witness bytes are 1 WU each, so the saving is 32 WU = 8 vB per input.
    let w1 = stdout(out)
        .lines()
        .find(|l| l.contains("p2mr weight"))
        .unwrap_or_else(|| panic!("weight line must print: {}", stdout(out)))
        .to_string();
    let w2 = stdout(&out_multi)
        .lines()
        .find(|l| l.contains("p2mr weight"))
        .unwrap_or_else(|| panic!("weight line must print: {}", stdout(&out_multi)))
        .to_string();
    for (line, inputs) in [(&w1, 1u64), (&w2, 2u64)] {
        let saved: u64 = line
            .split("saved ")
            .nth(1)
            .and_then(|r| r.split(" WU").next())
            .and_then(|n| n.trim().parse().ok())
            .unwrap_or(0);
        assert_eq!(saved, 32 * inputs, "saving must be 32 WU per input: {line}");
    }
    let hex_multi = std::fs::read_to_string(dir.path().join("p2mr-source-trial.txhex")).unwrap();
    assert_ne!(
        hex_tx.trim(),
        hex_multi.trim(),
        "the multi-input trial must be a DIFFERENT transaction"
    );
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert!(mempool.as_array().unwrap().is_empty(), "{mempool}");
}
