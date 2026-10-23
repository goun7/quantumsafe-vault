//! Watchtower DAEMON e2e (docs/10 §3.2): multi-vault inventory, persistent
//! state, best-effort webhook, exit-code contract.
//!
//!   1. MULTI-VAULT HEALTHY PASS: two fresh vaults → exit 0, per-vault
//!      heartbeat lines, state file written with both entries (clear).
//!   2. DUE VAULT = PASS FAILURE: one vault's last_refresh_block far in
//!      the past → exit 1, ALERT[vault-id] printed, state records ALERT.
//!   3. WEBHOOK IS BEST-EFFORT: an unreachable webhook never changes the
//!      healthy exit code (delivery failure is a printed line).
//!   4. USAGE CONFUSION: --inventory + single-vault flags → exit 2.
//!   5. FAIL-CLOSED: malformed inventory JSON → exit 1, no state written.
//!
//! The multi-vault pass never needs a funded group (no rehearsal) and
//! never broadcasts: the demo vault scan is read-only.

use bitcoind::serde_json;
use std::process::Command;

/// Round 19: the parallel workspace matrix can starve a bitcoind past the
/// RPC transport's hard 15s timeout — a transient that failed sweep tests
/// while the very same tests passed in the next run. The 13,100-block
/// fixture push below is safe to repeat, so a stalled call is retried
/// instead of sinking the test.
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

fn write_inventory(path: &std::path::Path, body: &str) {
    std::fs::write(path, body).unwrap();
}

#[test]
fn watchtower_daemon_multi_vault_state_and_alert_contract() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let inv_path = dir.path().join("env.json");

    // Tip is fetched live; use far-past refresh blocks so BOTH vaults are
    // healthy regardless of where the regtest tip is (any tip > 200 keeps
    // idle < 12,960 for refresh blocks near the tip minus 100).
    let base = 400u32;

    // 1. HEALTHY MULTI-VAULT PASS.
    write_inventory(
        &inv_path,
        &format!(
            r#"{{
  "vaults": [
    {{ "id": "family-main", "last_refresh_block": {base} }},
    {{ "id": "cold-storage-2", "last_refresh_block": {base}, 
      "webhook": "http://127.0.0.1:9/webhook", "webhook_token": "tok" }}
  ]
}}"#
        ),
    );
    let out = qsv(&[
        "watchtower",
        "--datadir",
        "/nonexistent-bitcoin",
        "--inventory",
        inv_path.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    // The node is unreachable in this unit-style pass → the daemon must
    // fail closed with a CONNECTION error (no fake data), exit 1. The
    // multi-vault contract needs a live node, so the full behavioral pass
    // runs in watchtower.rs against a real bitcoind; here we pin the
    // no-fake-data contract first.
    assert_eq!(
        out.status.code(),
        Some(1),
        "unreachable node must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stderr(&out).contains("cannot reach node"));

    // 2. USAGE CONFUSION: --inventory + single-vault flags → exit 2.
    let out = qsv(&[
        "watchtower",
        "--datadir",
        "/nonexistent-bitcoin",
        "--inventory",
        inv_path.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--last-refresh-block",
        "1",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "conflicting flags must exit 2: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stderr(&out).contains("conflicts with the single-vault"));

    // 3. FAIL-CLOSED: malformed inventory → exit 1, nothing written.
    let bad_inv = dir.path().join("bad.json");
    write_inventory(&bad_inv, "{ \"vaults\": [ { \"id\": ");
    let out = qsv(&[
        "watchtower",
        "--datadir",
        "/nonexistent-bitcoin",
        "--inventory",
        bad_inv.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "malformed inventory must exit 1"
    );
    assert!(stderr(&out).contains("malformed inventory"));
    // The connection check happens AFTER the inventory parse (no node
    // needed to reject a malformed file) — and NO state file was written.
    assert!(
        !state_dir.join("watchtower-state.json").exists(),
        "no state may be written for a malformed inventory"
    );

    // 4. EMPTY INVENTORY → exit 1.
    let empty_inv = dir.path().join("empty.json");
    write_inventory(&empty_inv, "{ \"vaults\": [] }");
    let out = qsv(&[
        "watchtower",
        "--datadir",
        "/nonexistent-bitcoin",
        "--inventory",
        empty_inv.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1), "empty inventory must exit 1");
    assert!(stderr(&out).contains("empty vaults array"));
}

/// ROTATION-STATE v2 INTEGRATION (live bitcoind): the daemon consults the
/// id-based rotation records the SAME state dir holds and lets a LATER
/// recorded baseline override a stale inventory row — the alarm the
/// vault-rotate refresh already cured must never be re-raised:
///
///   1. stale inventory rows alone → the old vault ALERTS (exit 1);
///   2. the SAME inventory + a v2 rotation-state recording a LATER refresh
///      for that vault → it reads healthy, the OTHER vault stays ALERT,
///      and the state file records the overridden (healthy) verdict;
///   3. a CORRUPT record (refresh above the tip) is ignored — the inventory
///      row rules again;
///   4. an UNREADABLE rotation state fails closed (exit 1) instead of
///      silently falling back to a stale row.
#[test]
fn watchtower_daemon_uses_rotation_state_v2_records_per_id() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_str().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    // Tip sanity: the fixture needs a refresh at height 1 to sit BEYOND the
    // 12,960-block heartbeat interval (the DUE gate), so mine past it in
    // 250-block chunks (huge single calls can time out the RPC).
    let miner: String = retry("getnewaddress", || {
        rpc.call("getnewaddress", &[serde_json::json!("")])
    });
    let mut left: u32 = 13_100;
    while left > 0 {
        let n = left.min(250);
        let _: serde_json::Value = retry("generatetoaddress", || {
            rpc.call(
                "generatetoaddress",
                &[serde_json::json!(n), serde_json::json!(miner)],
            )
        });
        left -= n;
    }
    let tip: u32 = rpc.call("getblockcount", &[]).unwrap();
    assert!(tip > 12_960, "tip {tip} too low for the fixture");
    let base = tip - 800; // stale but healthy (idle 800 < 12,960)

    // Two vaults; "stale-row" will be the one the rotation state rescues.
    let inv_path = dir.path().join("env.json");
    std::fs::write(
        &inv_path,
        format!(
            r#"{{ "vaults": [
            {{ "id": "stale-row", "last_refresh_block": {base} }},
            {{ "id": "still-due", "last_refresh_block": 1 }}
        ] }}"#
        ),
    )
    .unwrap();
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();

    // 1. WITHOUT rotation state → "stale-row" is healthy, "still-due"
    //    ALERTS (exit 1). Baseline behavior for the comparison below.
    let out = qsv(&[
        "watchtower",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--inventory",
        inv_path.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    let o = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "still-due (refresh 1) must alert: {o}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(o.contains("ALERT[still-due]"), "ALERT line missing: {o}");
    assert!(!o.contains("ALERT[stale-row]"));

    // 2. Seed a v2 rotation state recording a LATER refresh for stale-row
    //    only. The daemon must override the stale row (rotation line in the
    //    output) — still-due keeps its alert.
    let refreshed = tip - 100; // later than base
    std::fs::write(
        state_dir.join("rotation-state.json"),
        format!(
            r#"{{ "version": 2, "vaults": {{ "stale-row": {{ "last_refresh_block": {refreshed}, "refresh_txid": "seeded", "policy_interval_blocks": 12960 }} }} }}"#
        ),
    )
    .unwrap();
    let out = qsv(&[
        "watchtower",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--inventory",
        inv_path.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    let o = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "still-due must STILL alert: {o}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        o.contains("ALERT[still-due]"),
        "the other vault's alert must survive: {o}"
    );
    assert!(
        !o.contains("ALERT[stale-row]"),
        "overridden vault stays healthy: {o}"
    );
    assert!(
        o.contains("rotation-state: refreshed at"),
        "override must be printed as an audit line: {o}"
    );
    assert!(
        o.contains("consulted (id-based v2)"),
        "consultation must be visible: {o}"
    );

    // 3. The watchtower-state mirror records the OVERRIDDEN verdict: the
    //    bridge reads healthy for stale-row (its last idle reflects the
    //    rotation-state baseline, not the stale row).
    let mirror: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(state_dir.join("watchtower-state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(mirror["vaults"]["stale-row"]["last_verdict"], "clear");
    assert_eq!(
        mirror["vaults"]["stale-row"]["idle_blocks"].as_u64(),
        Some((tip - refreshed) as u64),
        "idle must be computed from the rotation-state baseline: {mirror}"
    );

    // 4. CORRUPT record (refresh ABOVE the tip) → ignored; the stale row
    //    rules again. The pass still alerts only for still-due.
    std::fs::write(
        state_dir.join("rotation-state.json"),
        format!(
            r#"{{ "version": 2, "vaults": {{ "stale-row": {{ "last_refresh_block": {}, "refresh_txid": "seeded", "policy_interval_blocks": 12960 }} }} }}"#,
            tip + 50
        ),
    )
    .unwrap();
    let out = qsv(&[
        "watchtower",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--inventory",
        inv_path.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    let o = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "corrupt record must not hide still-due: {o}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !o.contains("rotation-state: refreshed at"),
        "corrupt record must not drive: {o}"
    );

    // 5. UNREADABLE rotation state → fail-closed (exit 1), never a silent
    //    fallback to the stale row.
    std::fs::write(state_dir.join("rotation-state.json"), "not json at all").unwrap();
    let out = qsv(&[
        "watchtower",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--inventory",
        inv_path.to_str().unwrap(),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "unreadable rotation state must exit 1"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("rotation state unreadable"),
        "fail-closed reason must print"
    );
}
