//! Vault-rotate × co-signer bridge + rotation inventory e2e (docs/10 §3.3):
//! a REAL bitcoind, a REAL bridge child process serving the enclave over
//! TCP, and the persistent rotation state that keeps the heartbeat gate
//! consistent with the watchtower.
//!
//!   1. DUE GATE: a rotation whose baseline is NOT due exits 1 ("rotation
//!      not due"); the same vault with a far-past baseline proceeds to the
//!      next check (no UTXO yet).
//!   2. LIVE CO-SIGNER: with the bridge up and the watchtower state CLEAR,
//!      the rotation's second signature comes over the PQC gate, verifies
//!      under the pinned enclave key, and the refresh lands in the mempool;
//!      rotation-state.json records the tip as the new baseline.
//!   3. EARLY RE-ROTATION GUARD: a second run WITHOUT an explicit baseline
//!      reads the persisted state and refuses ("rotation not due").
//!   4. WATCHTOWER FROZEN: the state file flips to ALERT (the bridge re-reads
//!      it per request) → the co-signer REFUSES; the rotation exits 1 and
//!      the mempool stays empty — alarm enforcement, end to end.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

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

/// Round 19: the parallel workspace matrix can starve a bitcoind past the
/// RPC transport's hard 15s timeout — a transient that failed THIS test
/// (`mine!` at the 54×250 push past the heartbeat window) while the very
/// same tests passed in the next run. Mining is safe to repeat, so a
/// stalled call is retried instead of sinking the test.
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
        let addr: String = retry("getnewaddress", || {
            $rpc.call("getnewaddress", &[serde_json::json!("")])
        });
        let _: serde_json::Value = retry("generatetoaddress", || {
            $rpc.call(
                "generatetoaddress",
                &[serde_json::json!($n), serde_json::json!(addr)],
            )
        });
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

/// The demo vault's regtest address (from `vault-setup`).
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

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    std::thread::sleep(Duration::from_millis(200));
    port
}

fn wait_ready(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if std::net::TcpStream::connect(addr).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "bridge never came up at {addr}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn spawn_bridge(state_dir: &std::path::Path, vault_addr: &str) -> (Child, String) {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            vault_addr,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);
    (child, addr)
}

#[test]
fn vault_rotate_uses_live_cosigner_and_respects_due_gate_and_watchtower_freeze() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_str().unwrap();
    let port = btc.params.rpc_socket.port().to_string();
    let state_dir = dir.path().join("wt");

    mine!(rpc, 101);
    // The DUE gate needs tip − baseline ≥ 12,960; push the chain past the
    // heartbeat window in ≤250-block chunks (bigger calls hit the RPC
    // client timeout).
    for _ in 0..54 {
        mine!(rpc, 250);
    }
    let vault_addr = demo_vault_address();

    // Watchtower state: CLEAR for the vault (the bridge boots only with a
    // readable state file — fail-closed).
    std::fs::create_dir_all(&state_dir).unwrap();
    let state_path = state_dir.join("watchtower-state.json");
    let state_body = |verdict: &str| {
        format!(
            r#"{{ "tip": 900000, "vaults": {{ "{vault_addr}": {{ "last_verdict": "{verdict}" }} }} }}"#
        )
    };
    std::fs::write(&state_path, state_body("clear")).unwrap();
    let (mut bridge, bridge_addr) = spawn_bridge(&state_dir, &vault_addr);

    // Inventory shared by the multi-vault paths.
    let inv = dir.path().join("env.json");
    std::fs::write(
        &inv,
        r#"{ "vaults": [ { "id": "family-main", "last_refresh_block": 4000000 } ] }"#,
    )
    .unwrap();

    // 1. DUE GATE: baseline near tip (4,000,000 saturates to 0 idle) → exit 1.
    //    --state-dir points at the TEST dir (no rotation-state.json exists
    //    there yet), so the inventory row alone drives the baseline.
    let out = qsv(&[
        "vault-rotate",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--inventory",
        inv.to_str().unwrap(),
        "--vault-id",
        "family-main",
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--dir",
        d,
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "an early rotation must be refused: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("rotation not due"),
        "unexpected failure: {}{}",
        stdout(&out),
        stderr(&out)
    );

    // 1b. Far-past explicit baseline → the gate passes; the run proceeds to
    //     UTXO discovery and fails closed on the empty vault.
    let out = qsv(&[
        "vault-rotate",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--last-refresh-block",
        "400",
        "--dir",
        d,
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "unfunded vault must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("no confirmed UTXO pays"),
        "unexpected failure: {}{}",
        stdout(&out),
        stderr(&out)
    );

    // Fund the vault.
    let _: serde_json::Value = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(vault_addr), serde_json::json!(0.001)],
        )
        .unwrap();
    mine!(rpc, 1);

    // 2. LIVE CO-SIGNER: the second signature comes from the bridge over the
    //    PQC gate; the refresh broadcasts and the rotation state is written.
    let out = qsv(&[
        "vault-rotate",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--last-refresh-block",
        "400",
        "--cosigner",
        &bridge_addr,
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--dir",
        d,
    ]);
    assert!(
        out.status.success(),
        "live co-signer rotation must succeed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stdout(&out).contains("requesting signature from"));
    assert!(stdout(&out).contains("signature verified under the pinned enclave key"));
    assert!(stdout(&out).contains("Vault rotate: COMPLETE"));
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert_eq!(mempool.as_array().map(Vec::len), Some(1), "{mempool}");
    let tip_before_conf: serde_json::Value = rpc.call("getblockcount", &[]).unwrap();
    mine!(rpc, 1);
    let rot_state = std::fs::read_to_string(state_dir.join("rotation-state.json")).unwrap();
    assert!(rot_state.contains("last_refresh_block"));
    let recorded: serde_json::Value = serde_json::from_str(&rot_state).unwrap();
    assert_eq!(
        recorded["version"].as_u64(),
        Some(2),
        "v2 id-based state schema"
    );
    assert_eq!(
        recorded["vaults"]["single-vault"]["last_refresh_block"].as_u64(),
        Some(tip_before_conf.as_u64().unwrap()),
        "the rotation must persist ITS OWN tip as the new baseline"
    );

    // 3. EARLY RE-ROTATION: no explicit baseline → the persisted state says
    //    "just refreshed" → refused. (Single-vault rotations now record under
    //    the id "default" in the v2 state; re-running without --last-refresh-
    //    block and without an inventory reads that record.)
    let out = qsv(&[
        "vault-rotate",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--dir",
        d,
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "an early re-rotation must be refused: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("rotation not due"),
        "unexpected failure: {}{}",
        stdout(&out),
        stderr(&out)
    );

    // 3b. INVENTORY/STATE CONSISTENCY: the run above recorded a FRESH
    //     baseline; an inventory row claiming an OLDER refresh must now be
    //     refused (the rotation state reflects the chain — the watchtower
    //     would fire a false ALARM on the fresh vault).
    let stale_inv = dir.path().join("stale-env.json");
    std::fs::write(
        &stale_inv,
        r#"{ "vaults": [ { "id": "single-vault", "last_refresh_block": 400 } ] }"#,
    )
    .unwrap();
    let out = qsv(&[
        "vault-rotate",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--inventory",
        stale_inv.to_str().unwrap(),
        "--vault-id",
        "single-vault",
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--dir",
        d,
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "stale inventory vs fresh rotation state must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("MISMATCH"),
        "unexpected failure: {}{}",
        stdout(&out),
        stderr(&out)
    );

    // 4. WATCHTOWER FROZEN: the daemon flips the state file to ALERT; the
    //    bridge re-reads it PER REQUEST. An inventory-driven due rotation
    //    still passes the heartbeat gate — but the co-signer refuses, the
    //    run exits 1 and the mempool stays empty. (The inventory row's
    //    baseline is refreshed to below the tip so ONLY the co-signer gate
    //    can block this run.)
    let tip_now: serde_json::Value = rpc.call("getblockcount", &[]).unwrap();
    let old = tip_now.as_u64().unwrap().saturating_sub(20_000);
    std::fs::write(
        &inv,
        format!(r#"{{ "vaults": [ {{ "id": "family-main", "last_refresh_block": {old} }} ] }}"#),
    )
    .unwrap();
    std::fs::write(&state_path, state_body("ALERT")).unwrap();
    let out = qsv(&[
        "vault-rotate",
        "--datadir",
        cookie_dir,
        "--rpc-port",
        &port,
        "--inventory",
        inv.to_str().unwrap(),
        "--vault-id",
        "family-main",
        "--cosigner",
        &bridge_addr,
        "--dir",
        d,
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a frozen vault must not rotate: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let combined = format!("{}{}", stdout(&out), stderr(&out));
    assert!(combined.contains("REFUSED"));
    assert!(combined.contains("watchtower alarm active"));
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert!(
        mempool.as_array().unwrap().is_empty(),
        "a frozen vault must NEVER broadcast: {mempool}"
    );

    stop_gracefully(&mut bridge);
    let _ = bridge.wait();
}
