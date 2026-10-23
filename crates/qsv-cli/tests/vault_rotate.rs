//! Vault rotation e2e (docs/10 §4): the owner's heartbeat drill against a
//! REAL regtest node — live UTXO discovery, self-churn refresh, heir PQC
//! re-attestation, consensus self-check, broadcast.
//!
//!   1. PARTIAL REGISTRY FAIL-CLOSED: fewer --heir specs than registered
//!      heirs → exit 1, nothing scanned, nothing signed.
//!   2. NO UTXO FAIL-CLOSED: an unfunded vault → exit 1 ("no confirmed
//!      UTXO"), the coin never moves.
//!   3. HAPPY PATH: funded vault + both heir re-attestations → exit 0, the
//!      signed refresh lands in the mempool (self-churn: one output back
//!      to the SAME address).
//!   4. HOLD MODE (--no-broadcast): the signed refresh goes to
//!      vault-rotate.txhex and the mempool stays EMPTY.

use std::process::Command;

use bitcoind::serde_json;

/// Round 19: the parallel workspace matrix can starve a bitcoind past the
/// RPC transport's hard 15s timeout — a transient that failed a sweep test
/// while the very same tests passed in the next run. Mining is safe to
/// repeat, so a stalled call is retried instead of sinking the test.
fn retry<T, E: std::fmt::Debug>(what: &str, mut call: impl FnMut() -> Result<T, E>) -> T {
    let mut last = String::new();
    for attempt in 1..=5 {
        match call() {
            Ok(v) => return v,
            Err(e) => {
                last = format!("{e:?}");
                eprintln!("retry {what}: attempt {attempt}/5 failed: {last}");
                if attempt < 5 {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }
    }
    panic!("{what} still failing after 5 attempts: {last}");
}

macro_rules! mine {
    ($rpc:expr, $n:expr) => {{
        // Split large requests into ≤250-block chunks: one huge
        // generatetoaddress call can exceed the RPC client timeout.
        let mut remaining: u64 = $n;
        while remaining > 0 {
            let chunk = remaining.min(250);
            let addr: String = retry("getnewaddress", || {
                $rpc.call("getnewaddress", &[serde_json::json!("")])
            });
            let _: serde_json::Value = retry("generatetoaddress", || {
                $rpc.call(
                    "generatetoaddress",
                    &[serde_json::json!(chunk), serde_json::json!(addr)],
                )
            });
            remaining -= chunk;
        }
    }};
}

fn qsv(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args(args)
        .output()
        .expect("qsv-cli binary must run")
}

fn run(args: &[String]) -> std::process::Output {
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

/// The demo policy vault address on regtest (from `vault-setup`).
fn demo_vault_address() -> String {
    let out = qsv(&["vault-setup", "--network", "regtest"]);
    assert!(out.status.success(), "vault-setup failed: {}", stdout(&out));
    stdout(&out)
        .lines()
        .find_map(|l| l.strip_prefix("Address (regtest): "))
        .map(str::trim)
        .map(str::to_string)
        .expect("vault-setup must print the regtest address")
}

fn rotate_args(cookie_dir: &str, port: &str, dir: &str, extra: &[&str]) -> Vec<String> {
    let mut v = vec![
        "vault-rotate".into(),
        "--datadir".into(),
        cookie_dir.into(),
        "--rpc-port".into(),
        port.into(),
        "--dir".into(),
        dir.into(),
    ];
    v.extend(extra.iter().map(|s| s.to_string()));
    v
}

#[test]
fn vault_rotate_refreshes_on_real_chain_with_heir_attestation() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_str().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 101);
    // The DUE gate needs tip − baseline ≥ 12,960; the macro above mines in
    // ≤250-block chunks (one huge generatetoaddress call would hit the RPC
    // client timeout). Baseline 400 then yields idle ≥ 12,960.
    mine!(rpc, 13_400);
    let addr = demo_vault_address();

    // 32-byte hex seeds, built to be exactly 64 chars. The rotation state
    // lives in the TEST dir (never ./ — a leftover rotation-state.json from
    // another run would poison the baseline resolution).
    let state_dir = dir.path().join("rot-state");
    let state_flag = ["--state-dir", state_dir.to_str().unwrap()];
    let spec_a = format!("heir-a={}", "a1".repeat(32));
    let spec_b = format!("heir-b={}", "b2".repeat(32));
    let both = [spec_a.as_str(), spec_b.as_str()];
    let partial = [spec_a.as_str()];

    // 1. PARTIAL REGISTRY FAIL-CLOSED (no funding needed — the identity
    //    check precedes the chain-state heartbeat gate).
    let out = run(&rotate_args(
        cookie_dir,
        &port,
        d,
        &[
            "--heir",
            partial[0],
            "--last-refresh-block",
            "400",
            "--state-dir",
            state_flag[1],
        ],
    ));
    assert_eq!(
        out.status.code(),
        Some(1),
        "partial heir re-attestation must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("must cover all 2 registered heirs"),
        "unexpected failure: {}{}",
        stdout(&out),
        stderr(&out)
    );

    // 2. NO UTXO FAIL-CLOSED: both heirs attest, the heartbeat is due, but
    //    the vault holds no confirmed coin yet.
    let out = run(&rotate_args(
        cookie_dir,
        &port,
        d,
        &[
            "--heir",
            both[0],
            "--heir",
            both[1],
            "--last-refresh-block",
            "400",
            "--state-dir",
            state_flag[1],
        ],
    ));
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unfunded vault must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("no confirmed UTXO pays"),
        "unexpected failure: {}{}",
        stdout(&out),
        stderr(&out)
    );

    // 3. HAPPY PATH: fund the vault, rotate with BOTH heirs re-attested.
    let _: serde_json::Value = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(addr), serde_json::json!(0.001)],
        )
        .unwrap();
    mine!(rpc, 1);

    let out = run(&rotate_args(
        cookie_dir,
        &port,
        d,
        &[
            "--heir",
            both[0],
            "--heir",
            both[1],
            "--last-refresh-block",
            "400",
            "--state-dir",
            state_flag[1],
        ],
    ));
    assert!(
        out.status.success(),
        "rotation must succeed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains("identity verified"));
    assert!(stdout(&out).contains("Vault rotate: COMPLETE"));
    // The refresh transaction is really in the mempool (self-churn spend
    // of the confirmed vault coin back to the same address).
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert_eq!(
        mempool.as_array().map(Vec::len),
        Some(1),
        "exactly the refresh tx must be in flight: {mempool}"
    );
    mine!(rpc, 1);
    // Self-churn: the coin lands back on the SAME address (confirmed).
    let coins: serde_json::Value = rpc
        .call(
            "scantxoutset",
            &[
                serde_json::json!("start"),
                serde_json::json!([{ "desc": format!("addr({addr})") }]),
            ],
        )
        .unwrap();
    assert_eq!(
        coins["unspents"].as_array().map(Vec::len),
        Some(1),
        "the refreshed coin must sit at the same vault address: {coins}"
    );

    // 4. HOLD MODE: the refreshed coin rotates again (explicit baseline —
    //    the persisted rotation state would refuse the early re-run) — but
    //    the signed refresh goes to the hold file and the mempool stays
    //    EMPTY.
    let out = run(&rotate_args(
        cookie_dir,
        &port,
        d,
        &[
            "--no-broadcast",
            "--last-refresh-block",
            "400",
            "--state-dir",
            state_flag[1],
        ],
    ));
    assert!(
        out.status.success(),
        "hold rotation must succeed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains("Vault rotate: HOLD COMPLETE"));
    let hold = dir.path().join("vault-rotate.txhex");
    assert!(hold.exists(), "the hold artifact must exist");
    let hex_tx = std::fs::read_to_string(&hold).unwrap();
    assert!(!hex_tx.trim().is_empty());
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert!(
        mempool.as_array().unwrap().is_empty(),
        "--no-broadcast must NEVER broadcast: {mempool}"
    );
}
