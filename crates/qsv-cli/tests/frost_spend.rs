//! Part 1: the FROST group key spends on a REAL chain.
//!
//! `inheritance-kit setup` derives the group key; the test funds the GROUP
//! address on regtest and `frost-spend` runs the RFC 9591 ceremony with a
//! BIP-341-tweaked public package and broadcasts the k-of-n threshold spend
//! — ONE plain BIP-340 signature the REAL mempool accepts and the chain
//! confirms. Also proves the fail-closed edge: no live coin ⇒ exit 1.

use std::process::Command;

use bitcoind::serde_json;

/// SIGTERM + wait — the bridge's graceful stop, and the only child exit
/// that FLUSHES the llvm-cov profile (Round 30, P5): a SIGKILLed child
/// scores zero coverage for every line it actually ran.
fn stop_gracefully(bridge: &mut std::process::Child) {
    let pid = bridge.id() as libc::pid_t;
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match bridge.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(_) => return,
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bridge child must exit after SIGTERM"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
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

fn qsv(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args(args)
        .output()
        .expect("qsv-cli binary must run")
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
fn frost_group_key_spend_confirms_on_real_bitcoind() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 101);

    // 1. Wizard setup: 2-of-3 group, printed SLIP-0039 backups.
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
    let s = String::from_utf8_lossy(&setup.stdout);
    assert!(setup.status.success(), "setup failed: {s}");
    let ids: Vec<String> = s
        .lines()
        .filter_map(|l| {
            let i = l.find("(id ")?;
            let r = &l[i + 4..];
            Some(r[..r.find(')')?].to_string())
        })
        .collect();
    assert_eq!(ids.len(), 3);

    // 2. No live coin yet → frost-spend must fail closed.
    let empty = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/public-package.txt"),
        "--deal",
        &format!("h0={d}/heir-00-{}-deal.txt", ids[0]),
        "--deal",
        &format!("h1={d}/heir-02-{}-deal.txt", ids[2]),
        "--datadir",
        cookie_dir.to_str().unwrap(),
        "--rpc-port",
        &port,
        "--dir",
        d,
    ]);
    assert_eq!(
        empty.status.code(),
        Some(1),
        "unfunded group address must exit 1: {}{}",
        String::from_utf8_lossy(&empty.stdout),
        String::from_utf8_lossy(&empty.stderr)
    );

    // 3. FUND + SPEND in one command (--fund-sat): 2 heirs sign.
    let spend = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/public-package.txt"),
        "--deal",
        &format!("h0={d}/heir-00-{}-deal.txt", ids[0]),
        "--deal",
        &format!("h1={d}/heir-02-{}-deal.txt", ids[2]),
        "--datadir",
        cookie_dir.to_str().unwrap(),
        "--rpc-port",
        &port,
        "--fund-sat",
        "250000",
        "--fee-sat",
        "1500",
        "--dir",
        d,
    ]);
    let sp = String::from_utf8_lossy(&spend.stdout);
    assert!(
        spend.status.success(),
        "frost-spend failed: {sp}{}",
        String::from_utf8_lossy(&spend.stderr)
    );
    assert!(sp.contains("mempool ACCEPTED"), "mempool must accept: {sp}");
    assert!(
        sp.contains("verified under the tweaked group key"),
        "aggregate must verify: {sp}"
    );
    // The BROADCAST line (not the funded line) carries the spend txid.
    let broadcast_line = sp
        .lines()
        .find(|l| l.contains("broadcast:") && l.contains("txid "))
        .expect("broadcast line printed");
    let spent_txid = broadcast_line.split("txid ").nth(1).unwrap().trim();

    // 4. The threshold spend CONFIRMS on-chain (its output is now a UTXO).
    mine!(rpc, 1);
    let txid: bitcoin::Txid = spent_txid.parse().expect("txid hex");
    let out0 = rpc.get_tx_out(txid, 0).expect("spend output is live");
    assert!(out0.confirmations >= 1, "FROST spend must confirm");
    assert_eq!(
        (out0.value * 100_000_000.0).round() as u64,
        250_000 - 1_500,
        "staged value = funded − fee"
    );
}

// ─── frost-spend --cosigner: the enclave gate in front of the ceremony ───

const VAULT_ID: &str = "frost-cosigner-vault";

fn cosigner_state_body(verdict: &str) -> String {
    format!(
        r#"{{ "tip": 900000, "vaults": {{ "{VAULT_ID}": {{ "last_tip": 900000, "last_verdict": "{verdict}", "idle_blocks": 13000 }} }} }}"#
    )
}

/// Spawns a co-signer bridge child on a free loopback port serving exactly
/// VAULT_ID with the watchtower state dir given; returns (child, addr).
fn spawn_cosigner_bridge(state_dir: &std::path::Path) -> (std::process::Child, String) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    std::thread::sleep(std::time::Duration::from_millis(200));
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT_ID,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("bridge child must spawn");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::net::TcpStream::connect(&addr).is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bridge never came up at {addr}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    (child, addr)
}

/// The `--destination` arm of the key-path spend (docs/10 §4): every
/// malformed shape fails closed BEFORE the ceremony (bad hex, wrong
/// length, off-curve x), and a valid 64-hex x-only key redirects the
/// sweep to a REAL output on the live chain.
#[test]
fn frost_spend_destination_walls_and_the_valid_key_path() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 101);

    // 1. Wizard setup: 2-of-3 group (same shape as the happy-path test).
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
    let s = String::from_utf8_lossy(&setup.stdout);
    assert!(setup.status.success(), "setup failed: {s}");
    let ids: Vec<String> = s
        .lines()
        .filter_map(|l| {
            let i = l.find("(id ")?;
            let r = &l[i + 4..];
            Some(r[..r.find(')')?].to_string())
        })
        .collect();
    assert_eq!(ids.len(), 3);

    let base = || {
        vec![
            "frost-spend".to_string(),
            "--public".into(),
            format!("{d}/public-package.txt"),
            "--deal".into(),
            format!("h0={d}/heir-00-{}-deal.txt", ids[0]),
            "--deal".into(),
            format!("h1={d}/heir-02-{}-deal.txt", ids[2]),
            "--datadir".into(),
            cookie_dir.to_str().unwrap().into(),
            "--rpc-port".into(),
            port.clone(),
            "--dir".into(),
            d.into(),
        ]
    };
    let dest_run = |dest: &str, extra: &[&str]| {
        let mut args = base();
        args.push("--destination".into());
        args.push(dest.into());
        for a in extra {
            args.push((*a).into());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        qsv(&refs)
    };

    // 2. NOT HEX → refused. The fund step precedes the destination wall,
    //    so this run also seeds the group address (1 conf) for the runs.
    let out = dest_run("zz", &["--fund-sat", "250000"]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "non-hex --destination must exit 1: {err}"
    );
    assert!(err.contains("must be 64 hex chars"), "{err}");

    // 3. HEX, WRONG LENGTH → the same wall (the [u8; 32] conversion).
    let out = dest_run("abcd", &[]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "short --destination must exit 1: {err}"
    );
    assert!(err.contains("must be 64 hex chars"), "{err}");

    // 4. 32 BYTES, OFF-CURVE (≥ the field modulus) → not an x-only key.
    let out = dest_run(&"ff".repeat(32), &[]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "off-curve --destination must exit 1: {err}"
    );
    assert!(err.contains("not a valid x-only pubkey"), "{err}");

    // 5. VALID destination: secp256k1's generator x-coordinate — the
    //    threshold spend to its key-path output reaches the REAL mempool.
    let gx = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    let out = dest_run(gx, &["--fee-sat", "1500"]);
    let out_text = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "a valid --destination must spend: {out_text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out_text.contains("mempool ACCEPTED"),
        "the redirected spend must reach the mempool: {out_text}"
    );
}

/// The co-signer gate is a REAL fail-closed enforcement point:
///   1. watchtower ALERT ⇒ the bridge refuses the sighash proof ⇒ exit 1,
///      nothing broadcast, no ceremony output;
///   2. state cleared (same bridge process, per-request mirror) ⇒ the gate
///      releases a signature verified under the PINNED enclave key and the
///      SAME spend reaches the REAL mempool.
#[test]
fn frost_spend_cosigner_gate_blocks_alarm_then_allows_cleared_vault() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 101);

    // Group key setup (2-of-3, same drill as the plain spend test).
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
    assert!(setup.status.success(), "setup failed");
    let s = String::from_utf8_lossy(&setup.stdout);
    let ids: Vec<String> = s
        .lines()
        .filter_map(|l| {
            let i = l.find("(id ")?;
            let r = &l[i + 4..];
            Some(r[..r.find(')')?].to_string())
        })
        .collect();
    assert_eq!(ids.len(), 3);
    let deals = [
        format!("h0={d}/heir-00-{}-deal.txt", ids[0]),
        format!("h1={d}/heir-02-{}-deal.txt", ids[2]),
    ];

    // Fund the GROUP address WITHOUT broadcasting a spend (--no-broadcast
    // stops after the consensus self-check) and capture the address the
    // tool derived, so the gated runs find a live confirmed UTXO.
    let fund_run = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/public-package.txt"),
        "--deal",
        &deals[0],
        "--deal",
        &deals[1],
        "--datadir",
        cookie_dir.to_str().unwrap(),
        "--rpc-port",
        &port,
        "--fund-sat",
        "250000",
        "--no-broadcast",
        "--dir",
        d,
    ]);
    let fr = String::from_utf8_lossy(&fund_run.stdout);
    assert!(
        fund_run.status.success(),
        "fund/hold run failed: {fr}{}",
        String::from_utf8_lossy(&fund_run.stderr)
    );
    let group_addr = fr
        .lines()
        .find(|l| l.contains("address:"))
        .and_then(|l| l.split_whitespace().last())
        .expect("group address printed")
        .to_string();
    assert!(
        group_addr.starts_with("bcrt1p"),
        "regtest P2TR address: {group_addr}"
    );

    // 1. BRIDGE IN ALARM → the gate refuses BEFORE any heir round: exit 1,
    //    no mempool line, nothing broadcast. The witness never materializes.
    let wt_dir = dir.path().join("wt");
    std::fs::create_dir_all(&wt_dir).unwrap();
    std::fs::write(
        wt_dir.join("watchtower-state.json"),
        cosigner_state_body("ALERT"),
    )
    .unwrap();
    let (mut bridge, bridge_addr) = spawn_cosigner_bridge(&wt_dir);

    let refused = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/public-package.txt"),
        "--deal",
        &deals[0],
        "--deal",
        &deals[1],
        "--datadir",
        cookie_dir.to_str().unwrap(),
        "--rpc-port",
        &port,
        "--cosigner",
        &bridge_addr,
        "--vault-id",
        VAULT_ID,
        "--dir",
        d,
    ]);
    let ro = String::from_utf8_lossy(&refused.stdout);
    assert_eq!(
        refused.status.code(),
        Some(1),
        "ALARM-frozen vault must exit 1: {ro}{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("watchtower alarm active"),
        "refusal must carry the watchtower-freeze reason"
    );
    assert!(
        !ro.contains("mempool ACCEPTED"),
        "nothing may broadcast: {ro}"
    );
    assert!(
        !ro.contains("aggregate:"),
        "no heir aggregation may run: {ro}"
    );

    // 2. WATCHTOWER CLEARS (same bridge process — the per-request mirror
    //    re-reads the state file) → the gate releases, the co-signature is
    //    verified under the pinned enclave key, and the spend broadcasts.
    std::fs::write(
        wt_dir.join("watchtower-state.json"),
        cosigner_state_body("clear"),
    )
    .unwrap();
    let spend = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/public-package.txt"),
        "--deal",
        &deals[0],
        "--deal",
        &deals[1],
        "--datadir",
        cookie_dir.to_str().unwrap(),
        "--rpc-port",
        &port,
        "--cosigner",
        &bridge_addr,
        "--vault-id",
        VAULT_ID,
        "--dir",
        d,
    ]);
    let sp = String::from_utf8_lossy(&spend.stdout);
    assert!(
        spend.status.success(),
        "gated spend failed after recovery: {sp}{}",
        String::from_utf8_lossy(&spend.stderr)
    );
    assert!(
        sp.contains("signature verified under the pinned enclave key"),
        "gate proof must verify: {sp}"
    );
    assert!(
        sp.contains("mempool ACCEPTED"),
        "spend must broadcast: {sp}"
    );

    stop_gracefully(&mut bridge);
    let _ = bridge.wait();
}

/// MULTI-UTXO CONSOLIDATION (--min-inputs N): two live group-address coins
/// merge into ONE key-path spend (the aggregated FROST sig is valid on every
/// input of the group output); the mempool accepts and the chain confirms a
/// SINGLE output worth sum(inputs) − fee. The floor is fail-closed: --min-
/// inputs 3 with only two live coins exits 1 BEFORE any ceremony runs.
#[test]
fn frost_spend_consolidates_multiple_coins_and_fails_closed_below_floor() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 101);

    // Group setup (2-of-3) — same drill as the other tests.
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
    assert!(setup.status.success(), "setup failed");
    let s = String::from_utf8_lossy(&setup.stdout);
    let ids: Vec<String> = s
        .lines()
        .filter_map(|l| {
            let i = l.find("(id ")?;
            let r = &l[i + 4..];
            Some(r[..r.find(')')?].to_string())
        })
        .collect();
    assert_eq!(ids.len(), 3);
    let deals = [
        format!("h0={d}/heir-00-{}-deal.txt", ids[0]),
        format!("h1={d}/heir-02-{}-deal.txt", ids[2]),
    ];

    // Discover the group address via the fail-closed error line.
    let probe = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/public-package.txt"),
        "--deal",
        &deals[0],
        "--deal",
        &deals[1],
        "--datadir",
        cookie_dir.to_str().unwrap(),
        "--rpc-port",
        &port,
        "--dir",
        d,
    ]);
    let perr = String::from_utf8_lossy(&probe.stderr);
    let line_start = perr.find("no live UTXO pays ").expect("fail-closed line");
    let rest = &perr[line_start + "no live UTXO pays ".len()..];
    let group_addr = rest.split_whitespace().next().unwrap().to_string();

    // Fund TWO separate coins at the group address (2 distinct txids → 2
    // UTXOs), confirm both.
    for amount in ["0.111", "0.222"] {
        let _: serde_json::Value = rpc
            .call(
                "sendtoaddress",
                &[serde_json::json!(group_addr), serde_json::json!(amount)],
            )
            .unwrap();
    }
    mine!(rpc, 1);

    // FAIL-CLOSED FLOOR: --min-inputs 3 with only 2 live coins → exit 1,
    // nothing broadcast, NO ceremony output anywhere in stdout.
    let below = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/public-package.txt"),
        "--deal",
        &deals[0],
        "--deal",
        &deals[1],
        "--datadir",
        cookie_dir.to_str().unwrap(),
        "--rpc-port",
        &port,
        "--min-inputs",
        "3",
        "--dir",
        d,
    ]);
    let bo = String::from_utf8_lossy(&below.stdout);
    assert_eq!(
        below.status.code(),
        Some(1),
        "floor below the live-coin count must exit 1: {bo}{}",
        String::from_utf8_lossy(&below.stderr)
    );
    assert!(
        String::from_utf8_lossy(&below.stderr).contains("--min-inputs 3 unreachable"),
        "fail-closed reason must name the floor"
    );
    assert!(!bo.contains("sighash:"), "no ceremony may run: {bo}");

    // CONSOLIDATION: --min-inputs 2 merges BOTH coins into ONE broadcast.
    let spend = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/public-package.txt"),
        "--deal",
        &deals[0],
        "--deal",
        &deals[1],
        "--datadir",
        cookie_dir.to_str().unwrap(),
        "--rpc-port",
        &port,
        "--min-inputs",
        "2",
        "--fee-sat",
        "1500",
        "--dir",
        d,
    ]);
    let sp = String::from_utf8_lossy(&spend.stdout);
    assert!(
        spend.status.success(),
        "consolidating spend failed: {sp}{}",
        String::from_utf8_lossy(&spend.stderr)
    );
    assert!(
        sp.contains("2 coin(s)"),
        "two live coins must be listed: {sp}"
    );
    assert!(
        sp.contains("ACCEPT ×2"),
        "both inputs must pass consensus: {sp}"
    );
    assert!(
        sp.contains("mempool ACCEPTED"),
        "spend must broadcast: {sp}"
    );
    let broadcast_line = sp
        .lines()
        .find(|l| l.contains("broadcast:") && l.contains("txid "))
        .expect("broadcast line printed");
    let spent_txid: bitcoin::Txid = broadcast_line
        .split("txid ")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .expect("txid hex");

    // ONE output worth 33,300,000 − 1,500 sats (0.111 + 0.222 BTC) confirms.
    mine!(rpc, 1);
    let out0 = rpc
        .get_tx_out(spent_txid, 0)
        .expect("consolidated spend output is live");
    assert!(out0.confirmations >= 1, "consolidated spend must confirm");
    assert_eq!(
        (out0.value * 100_000_000.0).round() as u64,
        33_300_000 - 1_500,
        "single output = sum(inputs) − fee"
    );
}

/// The gate is opt-in but WHOLE: --cosigner without --vault-id (or the
/// reverse) is a usage error (exit 1) fired BEFORE any file read or node
/// contact — the pair check is the first statement of frost_spend.
#[test]
fn frost_spend_rejects_half_configured_cosigner_gate() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();

    let out = qsv(&[
        "frost-spend",
        "--public",
        &format!("{d}/nonexistent-public.txt"),
        "--deal",
        &format!("h0={d}/nonexistent-deal.txt"),
        "--cosigner",
        "127.0.0.1:1",
        "--dir",
        d,
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "half-configured gate must exit 1: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--cosigner and --vault-id"),
        "usage error must name the pair"
    );
}

/// ATTESTATION PINS fail closed at PARSE/STARTUP time (docs/10 §4.52):
/// a key without its measurement is refused by clap's `requires`, pins
/// without a bridge endpoint and malformed pin hex are refused by the
/// dispatch resolver — all exit 2 BEFORE any file read or node contact,
/// never mid-ceremony.
#[test]
fn frost_spend_attestation_pins_fail_closed_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let xonly = "ab".repeat(32);
    let pcr0 = "cd".repeat(48);
    let base_public = format!("{d}/nonexistent-public.txt");
    let base_deal = format!("h0={d}/nonexistent-deal.txt");
    let base: [&str; 6] = [
        "--public",
        base_public.as_str(),
        "--deal",
        base_deal.as_str(),
        "--dir",
        d,
    ];

    // 1. --cosigner-key without --cosigner-pcr0: clap `requires` → exit 2.
    let mut args: Vec<&str> = vec!["frost-spend"];
    args.extend(base.iter().copied());
    args.extend(["--cosigner-key", xonly.as_str()]);
    let out = qsv(&args);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "key without pcr0 must exit 2: {err}"
    );
    assert!(
        err.contains("--cosigner-pcr0"),
        "clap must name the missing requirement: {err}"
    );

    // 2. Pins WITHOUT a --cosigner endpoint: dispatch resolver → exit 2.
    let mut args: Vec<&str> = vec!["frost-spend"];
    args.extend(base.iter().copied());
    args.extend(["--cosigner-pcr0", pcr0.as_str()]);
    let out = qsv(&args);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "pins without endpoint must exit 2: {err}"
    );
    assert!(
        err.contains("require a co-signer endpoint"),
        "resolver must name the missing endpoint: {err}"
    );

    // 3. Malformed pin hex WITH an endpoint: refused at startup (exit 2),
    //    before the pair even reaches the bridge.
    let mut args: Vec<&str> = vec!["frost-spend"];
    args.extend(base.iter().copied());
    args.extend([
        "--cosigner",
        "127.0.0.1:1",
        "--vault-id",
        "bc1ptest",
        "--cosigner-pcr0",
        "zz",
    ]);
    let out = qsv(&args);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "malformed pin must exit 2: {err}"
    );
    assert!(
        err.contains("--cosigner-pcr0 must be hex"),
        "resolver must name the bad pin: {err}"
    );

    // 4. vault-rotate carries the SAME pins and the same clap contract.
    let mut args: Vec<&str> = vec!["vault-rotate", "--dir", d];
    args.extend(["--cosigner-key", xonly.as_str()]);
    let out = qsv(&args);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "vault-rotate key without pcr0 must exit 2: {err}"
    );
    assert!(
        err.contains("--cosigner-pcr0"),
        "clap must name the missing requirement: {err}"
    );
}
