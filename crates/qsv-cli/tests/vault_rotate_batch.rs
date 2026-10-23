//! Multi-vault DUE sweep e2e (docs/10 §4.1): `vault-rotate --inventory
//! <file> --all` against a REAL regtest node.
//!
//!   1. USAGE: --all is a sweep flag — the single-vault options
//!      (--vault-id/--last-refresh-block/--heir/--no-broadcast) are refused
//!      with exit 2, and --all without --inventory never parses (clap exit 2).
//!   2. ALL ATTEMPTED, FAIL-CLOSED: two DUE rows and an unfunded vault →
//!      BOTH are attempted in inventory order and the sweep exits 1.
//!   3. ONE COIN, ONE REFRESH: once the (single demo) vault address is
//!      funded, BOTH due ids refresh in one sweep — the first performs the
//!      broadcast, the second is recorded under the SAME tip/txid WITHOUT
//!      re-broadcasting the byte-identical refresh (all rows resolve to
//!      the same estate address).
//!   4. IDEMPOTENT RE-RUN: the immediate re-sweep finds every row healthy
//!      at its state-recorded baseline — nothing is attempted, nothing
//!      double-spends.
//!   5. STALE ROW: a row older than its rotation-state record is classified
//!      through the record ("stale row: fix the inventory") and skipped as
//!      healthy — the sweep never silently rewrites the operator's file.
//!   6. HEARTBEAT REPORT: a fresh state dir classifies every row DUE
//!      without consulting any state file (state-less mode preserved);
//!      the funded estate legally renews again.
//!   7. DRY RUN: --dry-run classifies and names the actions (broadcast /
//!      shared record) but writes NOTHING — no rotation state, no mempool
//!      entry — and the real sweep still succeeds right after.

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

fn qsv(args: &[String]) -> std::process::Output {
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

fn sweep_args(cookie_dir: &str, port: &str, inv: &str, state_dir: &str) -> Vec<String> {
    vec![
        "vault-rotate".into(),
        "--datadir".into(),
        cookie_dir.into(),
        "--rpc-port".into(),
        port.into(),
        "--inventory".into(),
        inv.into(),
        "--all".into(),
        "--state-dir".into(),
        state_dir.into(),
    ]
}

#[test]
fn vault_rotate_batch_sweeps_due_vaults_and_fails_closed_without_a_coin() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_str().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 101);
    // The DUE gate needs tip − baseline ≥ 12,960; the macro above mines in
    // ≤250-block chunks (one huge generatetoaddress call would hit the RPC
    // client timeout). Baseline 400 then yields idle ≥ 12,960.
    mine!(rpc, 13_400);
    let vault_addr = {
        let out = Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
            .args(["vault-setup", "--network", "regtest"])
            .output()
            .unwrap();
        assert!(out.status.success(), "vault-setup failed");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.strip_prefix("Address (regtest): "))
            .map(str::trim)
            .map(str::to_string)
            .expect("vault-setup must print the regtest address")
    };

    let state_dir = dir.path().join("rot-state");
    let state = state_dir.to_str().unwrap();
    // TWO due rows: the ONE demo vault address (fundable) + an id that can
    // NEVER hold a coin (inventory order = sweep order). A far-past
    // last_refresh_block keeps both rows DUE.
    let inv = dir.path().join("env.json");
    std::fs::write(
        &inv,
        r#"{ "vaults": [
            { "id": "vault-due", "last_refresh_block": 400 },
            { "id": "vault-empty", "last_refresh_block": 400 }
        ] }"#,
    )
    .unwrap();

    // 1. USAGE: single-vault options are meaningless in a sweep (exit 2),
    //    and --all without --inventory never parses.
    let bad = qsv(&[
        "vault-rotate".into(),
        "--inventory".into(),
        inv.to_str().unwrap().into(),
        "--all".into(),
        "--vault-id".into(),
        "vault-due".into(),
        "--state-dir".into(),
        state.into(),
    ]);
    assert_eq!(
        bad.status.code(),
        Some(2),
        "sweep + --vault-id must be a usage error: {}{}",
        stdout(&bad),
        stderr(&bad)
    );
    let bad = qsv(&["vault-rotate".to_string(), "--all".to_string()]);
    assert_eq!(
        bad.status.code(),
        Some(2),
        "--all without --inventory must not parse: {}{}",
        stdout(&bad),
        stderr(&bad)
    );

    // 2. ALL ATTEMPTED, FAIL-CLOSED: the sweep exits 1 with BOTH rows
    //    attempted in inventory order. The first (vault-due) has no coin
    //    yet either — but the point is the ORDER and the CONTINUATION:
    //    both failures appear, and NEITHER stops the other from being
    //    tried. (Funding happens after this pass.)
    let out = qsv(&sweep_args(cookie_dir, &port, inv.to_str().unwrap(), state));
    assert_eq!(
        out.status.code(),
        Some(1),
        "a sweep with an unfunded vault must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("sweep 1/2: vault [vault-due]"), "{text}");
    assert!(text.contains("sweep 2/2: vault [vault-empty]"), "{text}");
    assert!(text.contains("VAULT ROTATE SWEEP: 0 refreshed"), "{text}");
    assert!(
        stderr(&out).contains("sweep failed on: vault 'vault-due'"),
        "the FIRST failure drives the exit (all were attempted): {}",
        stderr(&out)
    );

    // 3. ONE COIN, ONE REFRESH: fund the (single demo) address and re-run
    //    — the first DUE id performs the broadcast; the second is recorded
    //    under the SAME tip/txid without re-broadcasting. The sweep exits 0
    //    with BOTH ids recorded in the v2 state.
    let _: serde_json::Value = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(vault_addr), serde_json::json!(0.001)],
        )
        .unwrap();
    mine!(rpc, 1);
    let out = qsv(&sweep_args(cookie_dir, &port, inv.to_str().unwrap(), state));
    assert!(
        out.status.success(),
        "a funded sweep must refresh every due id: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("VAULT ROTATE SWEEP: 2 refreshed"), "{text}");
    assert!(
        text.contains("shared coin, no re-broadcast"),
        "the second id must reuse the first refresh: {text}"
    );
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert_eq!(
        mempool.as_array().map(Vec::len),
        Some(1),
        "exactly ONE refresh transaction for the shared coin: {mempool}"
    );
    let rot_state = std::fs::read_to_string(state_dir.join("rotation-state.json")).unwrap();
    let recorded: serde_json::Value = serde_json::from_str(&rot_state).unwrap();
    assert_eq!(recorded["version"].as_u64(), Some(2), "{rot_state}");
    let due_tip = recorded["vaults"]["vault-due"]["last_refresh_block"]
        .as_u64()
        .expect("vault-due must be recorded in the v2 state");
    let empty_tip = recorded["vaults"]["vault-empty"]["last_refresh_block"]
        .as_u64()
        .expect("vault-empty must share the refresh");
    assert_eq!(
        due_tip, empty_tip,
        "both ids record the SAME renewal tip: {rot_state}"
    );
    assert_eq!(
        recorded["vaults"]["vault-due"]["refresh_txid"],
        recorded["vaults"]["vault-empty"]["refresh_txid"],
        "both ids record the SAME refresh txid: {rot_state}"
    );
    mine!(rpc, 1);

    // 4. IDEMPOTENT RE-RUN: the immediate re-sweep finds both rows healthy
    //    at their state-recorded baselines — nothing attempted, nothing
    //    broadcast twice.
    let out = qsv(&sweep_args(cookie_dir, &port, inv.to_str().unwrap(), state));
    assert!(
        out.status.success(),
        "a fresh sweep over a fresh estate must be green: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("stale row: fix the inventory"),
        "the state record must outrank the stale inventory row: {text}"
    );
    assert!(text.contains("nothing due — 2 vault(s) healthy"), "{text}");
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert!(
        mempool.as_array().unwrap().is_empty(),
        "a healthy vault must not be rotated twice: {mempool}"
    );

    // 5. STALE ROW: write a row that claims a refresh OLDER than the state
    //    record — the sweep classifies through the record ("stale row: fix
    //    the inventory") and skips it as healthy; nothing is due, nothing
    //    is attempted, the sweep exits 0 WITHOUT rewriting the file.
    let stale_inv = dir.path().join("stale-env.json");
    std::fs::write(
        &stale_inv,
        r#"{ "vaults": [ { "id": "vault-due", "last_refresh_block": 400 } ] }"#,
    )
    .unwrap();
    let out = qsv(&sweep_args(
        cookie_dir,
        &port,
        stale_inv.to_str().unwrap(),
        state,
    ));
    assert!(
        out.status.success(),
        "nothing is due here — the stale row is skipped: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("stale row: fix the inventory"), "{text}");
    assert!(text.contains("nothing due — 1 vault(s) healthy"), "{text}");
    let stale_now = std::fs::read_to_string(&stale_inv).unwrap();
    assert_eq!(
        stale_now, r#"{ "vaults": [ { "id": "vault-due", "last_refresh_block": 400 } ] }"#,
        "the sweep must NEVER rewrite the operator's inventory"
    );

    // 6. HEARTBEAT REPORT: on a FRESH state dir both rows are classified
    //    DUE (far-past rows) and the sweep legally renews the funded
    //    heartbeat again — what matters here is that the classification
    //    ran WITHOUT consulting any state file (state-less mode preserved:
    //    no `consulted (id-based v2)` line).
    let fresh_state = dir.path().join("fresh-state");
    let dry_state = dir.path().join("dry-state");
    let out = qsv(&sweep_args(
        cookie_dir,
        &port,
        inv.to_str().unwrap(),
        fresh_state.to_str().unwrap(),
    ));
    assert!(
        out.status.success(),
        "a funded sweep renews the heartbeat: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.matches("DUE — queued for refresh").count() >= 2,
        "both rows must be classified DUE on a fresh state dir: {text}"
    );
    assert!(
        !text.contains("consulted (id-based v2)"),
        "a missing state file must leave the inventory alone: {text}"
    );

    // 7. DRY RUN (Round 16): a sweep with --dry-run classifies BOTH rows
    //    DUE (this inventory has no fresh state), names what it WOULD do
    //    (first broadcast + shared-coin records), and touches NOTHING: no
    //    rotation state is created, the mempool stays empty.
    let mempool_before: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    let out = qsv(&[vec![
        "vault-rotate".into(),
        "--datadir".into(),
        cookie_dir.into(),
        "--rpc-port".into(),
        port.clone(),
        "--inventory".into(),
        inv.to_str().unwrap().into(),
        "--all".into(),
        "--state-dir".into(),
        dry_state.to_str().unwrap().into(),
        "--dry-run".into(),
    ]]
    .concat());
    assert!(
        out.status.success(),
        "a dry run must exit 0 (it is a preview): {}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.matches("DUE — queued for refresh").count() >= 2,
        "the dry run must classify the due rows: {text}"
    );
    assert!(
        text.contains("would rotate (broadcast refresh)"),
        "the first due vault must be named as the broadcast: {text}"
    );
    assert!(
        text.contains("would record (shared coin, no re-broadcast)"),
        "the second due vault must be named as a shared record: {text}"
    );
    assert!(
        text.contains("VAULT ROTATE SWEEP (DRY RUN): 2 would refresh"),
        "{text}"
    );
    assert!(text.contains("DRY RUN COMPLETE"), "{text}");
    assert!(
        !dry_state.join("rotation-state.json").exists(),
        "a dry run must NEVER write rotation state"
    );
    let mempool_after: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert_eq!(
        mempool_before, mempool_after,
        "a dry run must NEVER broadcast (mempool unchanged)"
    );
    // And the REAL sweep still works right after the preview.
    let out = qsv(&sweep_args(
        cookie_dir,
        &port,
        inv.to_str().unwrap(),
        dry_state.to_str().unwrap(),
    ));
    assert!(
        out.status.success(),
        "the real sweep must still succeed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains("2 refreshed"), "{}", stdout(&out));
}
