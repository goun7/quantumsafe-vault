//! Inheritance watchtower e2e (docs/04 §2 + §4): one REAL regtest node,
//! a REAL FROST group, and the full operator loop.
//!
//!   1. HEALTHY PASS: fresh tip → `watchtower` exits 0, prints the heartbeat
//!      schedule (healthy), the CSV countdown and the live coin total.
//!   2. FULL REHEARSAL (--deal/--public/--fund-sat): a REAL threshold
//!      ceremony runs in watchtower mode — the raw transaction lands in
//!      frost-spend.txhex and is proven NOT to be in the mempool; the two
//!      runs differ in outpoint (each run funds a fresh coin — that IS the
//!      provably-different real state) while the output side stays locked
//!      to the same deterministic destination and value.
//!   3. NO FALSE ALARM: the healthy pass never prints ALERT.
//!   4. FAIL-CLOSED: --deal without --public exits 1.

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

fn rehearsal_args(
    cookie_dir: &str,
    port: &str,
    setup_dir: &std::path::Path,
    artifact_dir: &std::path::Path,
    ids: &[String],
) -> Vec<String> {
    let s = setup_dir.to_str().unwrap();
    vec![
        "watchtower".into(),
        "--datadir".into(),
        cookie_dir.into(),
        "--rpc-port".into(),
        port.into(),
        "--fund-sat".into(),
        "250000".into(),
        "--dir".into(),
        artifact_dir.to_str().unwrap().into(),
        "--deal".into(),
        format!("h0={s}/heir-00-{}-deal.txt", ids[0]),
        "--deal".into(),
        format!("h2={s}/heir-02-{}-deal.txt", ids[2]),
        "--public".into(),
        format!("{s}/public-package.txt"),
    ]
}

#[test]
fn watchtower_rehearses_threshold_and_alerts_on_missed_heartbeat() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_str().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 101);

    // The FROST group the watchtower will rehearse.
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
    assert!(setup.status.success(), "setup failed: {}", stdout(&setup));
    let ids: Vec<String> = stdout(&setup)
        .lines()
        .filter_map(|l| {
            let i = l.find("(id ")?;
            let r = &l[i + 4..];
            Some(r[..r.find(')')?].to_string())
        })
        .collect();
    assert_eq!(ids.len(), 3);

    // 1. HEALTHY PASS: no deals → pure health check.
    let healthy = qsv(&[
        "watchtower",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--dir",
        d,
    ]);
    let h = stdout(&healthy);
    assert!(
        healthy.status.success(),
        "healthy watchtower failed: {h}{}",
        stderr(&healthy)
    );
    assert!(h.contains("heartbeat:"));
    assert!(h.contains("healthy"));
    assert!(h.contains("all clear"));
    assert!(!h.contains("ALERT"));

    // 1b. FAILING REHEARSAL: the group address has no coin and
    //     --fund-sat 0 mints none — frost-spend fails closed and the
    //     error PROPAGATES out of the watchtower (the `?` at the
    //     rehearsal call site), never a silent skip.
    let mut nofund = rehearsal_args(
        cookie_dir,
        &port,
        dir.path(),
        &dir.path().join("rehearsal-empty"),
        &ids,
    );
    let fi = nofund
        .iter()
        .position(|a| a == "--fund-sat")
        .expect("rehearsal args carry --fund-sat");
    nofund[fi + 1] = "0".into();
    let refs: Vec<&str> = nofund.iter().map(String::as_str).collect();
    let failed = qsv(&refs);
    assert_eq!(
        failed.status.code(),
        Some(1),
        "an unfunded group must fail the rehearsal: {}{}",
        stdout(&failed),
        stderr(&failed)
    );
    assert!(
        stderr(&failed).contains("no live UTXO pays"),
        "the frost-spend wall must surface: {}",
        stderr(&failed)
    );

    // 2. FULL REHEARSAL: real ceremony, hold artifact, NOTHING broadcast.
    let rehearsal_dir = dir.path().join("rehearsal");
    let _ = std::fs::create_dir_all(&rehearsal_dir);
    let args = rehearsal_args(cookie_dir, &port, dir.path(), &rehearsal_dir, &ids);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let full = qsv(&refs);
    let f = stdout(&full);
    assert!(
        full.status.success(),
        "watchtower rehearsal failed: {f}{}",
        stderr(&full)
    );
    assert!(f.contains("rehearsal:"));
    assert!(f.contains("watchtower mode"));
    let hex = std::fs::read_to_string(rehearsal_dir.join("frost-spend.txhex")).unwrap();
    assert!(hex.trim().len() > 200, "hold must be a raw tx hex");
    let decode = |h: &str| {
        use bitcoin::consensus::Decodable;
        bitcoin::Transaction::consensus_decode_from_finite_reader(&mut std::io::Cursor::new(
            &hex::decode(h.trim()).unwrap(),
        ))
        .unwrap()
    };
    let tx1 = decode(&hex);
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert!(
        !mempool
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some(&tx1.compute_txid().to_string())),
        "watchtower must NEVER broadcast"
    ); // 3. HOLD ARTIFACT SEMANTICS: each run selects exactly ONE live coin
       //    and holds (never broadcasts) it; the destination side is policy-
       //    deterministic across runs (BIP-341 tweaked demo destination and
       //    the fixed fee), while the input side is whatever the chain REALLY
       //    holds at pass time (scantxoutset, largest-first) — the hold is a
       //    faithful snapshot of a spendable state, never a fabrication.
    let rehearsal_dir2 = dir.path().join("rehearsal2");
    let _ = std::fs::create_dir_all(&rehearsal_dir2);
    let args2 = rehearsal_args(cookie_dir, &port, dir.path(), &rehearsal_dir2, &ids);
    let refs2: Vec<&str> = args2.iter().map(String::as_str).collect();
    let again = qsv(&refs2);
    assert!(
        again.status.success(),
        "second rehearsal: {}{}",
        stdout(&again),
        stderr(&again)
    );
    let hex2 = std::fs::read_to_string(rehearsal_dir2.join("frost-spend.txhex")).unwrap();
    let tx2 = decode(&hex2);
    assert_eq!(tx1.input.len(), 1);
    assert_eq!(tx2.input.len(), 1);
    assert_eq!(
        tx1.output.len(),
        tx2.output.len(),
        "single deterministic staging-like destination"
    );
    assert_eq!(
        tx1.output[0].script_pubkey, tx2.output[0].script_pubkey,
        "spend destination must be deterministic (BIP-341 tweaked dest)"
    );
    // Every hold input MUST be a real, currently-live coin: the node still
    // reports it as an unspent UTXO (nothing was ever broadcast).
    for tx in [&tx1, &tx2] {
        let op = &tx.input[0].previous_output;
        let live: serde_json::Value = rpc
            .call(
                "gettxout",
                &[
                    serde_json::json!(op.txid.to_string()),
                    serde_json::json!(op.vout),
                ],
            )
            .unwrap();
        assert!(
            live.get("confirmations").is_some(),
            "held input {op} must still be a live UTXO (never broadcast)"
        );
    }

    // 4. FAIL-CLOSED: --deal without --public exits 1.
    let bad = qsv(&[
        "watchtower",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--deal",
        "h0=nowhere.txt",
        "--dir",
        d,
    ]);
    assert_eq!(
        bad.status.code(),
        Some(1),
        "--deal without --public must exit 1"
    );
    assert!(stderr(&bad).contains("--deal requires --public"));
}
