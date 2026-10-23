//! `vault-rotate --all --cosigner-all` e2e (docs/10 §4.2): the multi-vault
//! sweep behind a LIVE co-signer gate — a frozen vault is skipped with an
//! explicit report line, the rest of the fleet refreshes, and an
//! unanswerable gate fails the sweep CLOSED.
//!
//!   1. USAGE: --cosigner-all without --all never parses (exit 2) and the
//!      plain --cosigner conflicts with it (exit 2).
//!   2. FAIL-CLOSED: with the gate endpoint DOWN, the sweep refuses to run
//!      any ceremony at all (exit 1 BEFORE any rotation — the gate exists
//!      to catch frozen vaults, an unanswerable gate is not a green light).
//!   3. FROZEN SKIP: the bridge serves a watchtower state that freezes one
//!      due vault; the sweep skips it with an explicit FROZEN line, the
//!      OTHER due vault refreshes through the very same live gate (its
//!      second signature verified under the pinned enclave key), and the
//!      sweep exits 0 — a dead beacon must not kill the fleet.
//!   4. THE GATE SEES NOTHING FOR THE FROZEN VAULT: the skip happened
//!      BEFORE any ceremony — the frozen vault's per-vault artifact dir is
//!      never created and the frozen id is NEVER recorded in the rotation
//!      state (its alarm must survive until the operator clears it).

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

const VAULT: &str = "vault-gate-frozen";

macro_rules! mine {
    ($rpc:expr, $n:expr) => {{
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

/// Round 19: the workspace matrix runs several bitcoinds side by side and
/// memory pressure can stall ONE of them past the RPC transport's hard 15s
/// timeout — a transient that failed the suite at `mine!` while the very same
/// tests passed in the next run. Both calls below are safe to repeat (a fresh
/// address, more blocks), so a stalled call is retried instead of sinking the
/// whole sweep test.
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

fn sweep_args(cookie_dir: &str, port: &str, inv: &str, state_dir: &str, gate: &str) -> Vec<String> {
    vec![
        "vault-rotate".into(),
        "--datadir".into(),
        cookie_dir.into(),
        "--rpc-port".into(),
        port.into(),
        "--inventory".into(),
        inv.into(),
        "--all".into(),
        "--cosigner-all".into(),
        gate.into(),
        "--state-dir".into(),
        state_dir.into(),
    ]
}

#[test]
fn batch_sweep_gate_skips_frozen_vaults_and_fails_closed_when_the_gate_is_down() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_str().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 13_500);
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
    let _: serde_json::Value = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(vault_addr), serde_json::json!(0.001)],
        )
        .unwrap();
    mine!(rpc, 1);

    // Two DUE rows; VAULT will be FROZEN at the gate, "vault-gate-healthy"
    // must clear it and refresh through the live bridge.
    let inv = dir.path().join("env.json");
    std::fs::write(
        &inv,
        format!(
            r#"{{ "vaults": [
            {{ "id": "{VAULT}", "last_refresh_block": 400 }},
            {{ "id": "vault-gate-healthy", "last_refresh_block": 400 }}
        ] }}"#
        ),
    )
    .unwrap();
    let state_dir = dir.path().join("rot-state");
    let state = state_dir.to_str().unwrap();

    // 1. USAGE: --cosigner-all is a sweep-only flag.
    let bad = qsv(&[
        "vault-rotate".into(),
        "--cosigner-all".into(),
        "127.0.0.1:9".into(),
    ]);
    assert_eq!(
        bad.status.code(),
        Some(2),
        "--cosigner-all without --all must not parse: {}{}",
        stdout(&bad),
        stderr(&bad)
    );
    let bad = qsv(&[
        "vault-rotate".into(),
        "--inventory".into(),
        inv.to_str().unwrap().into(),
        "--all".into(),
        "--cosigner-all".into(),
        "127.0.0.1:9".into(),
        "--cosigner".into(),
        "127.0.0.1:9".into(),
        "--state-dir".into(),
        state.into(),
    ]);
    assert_eq!(
        bad.status.code(),
        Some(2),
        "--cosigner-all conflicts with --cosigner: {}{}",
        stdout(&bad),
        stderr(&bad)
    );

    // 1b. DRY-RUN WITH NO GATE: the sweep states that FROZEN status is
    //     not evaluated (no co-signer configured) and completes dry.
    let out = qsv(&[
        "vault-rotate".into(),
        "--datadir".into(),
        cookie_dir.into(),
        "--rpc-port".into(),
        port.clone(),
        "--inventory".into(),
        inv.to_str().unwrap().into(),
        "--all".into(),
        "--dry-run".into(),
        "--state-dir".into(),
        state.into(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a gateless dry-run sweep must complete: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("no co-signer gate configured"),
        "the gateless dry-run arm must say so: {}{}",
        stdout(&out),
        stderr(&out)
    );

    // 1c. HALF-GIVEN mTLS MATERIAL: --cosigner-all-cert without the key
    //     and CA is a usage error (exit 2) — before any gate query.
    let out = qsv(&[
        "vault-rotate".into(),
        "--datadir".into(),
        cookie_dir.into(),
        "--rpc-port".into(),
        port.clone(),
        "--inventory".into(),
        inv.to_str().unwrap().into(),
        "--all".into(),
        "--cosigner-all".into(),
        "127.0.0.1:9".into(),
        "--cosigner-all-cert".into(),
        inv.to_str().unwrap().into(),
        "--state-dir".into(),
        state.into(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "partial sweep-gate material must exit 2: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("mTLS material is incomplete"),
        "the wall must name the incomplete material: {}",
        stderr(&out)
    );

    // 1d. UNPARSEABLE mTLS MATERIAL: a complete-looking set of non-PEM
    //     files fails the gate client construction closed (exit 1, the
    //     error propagates out of the sweep before any ceremony).
    let garbage = dir.path().join("garbage.pem");
    std::fs::write(&garbage, "not a pem at all").unwrap();
    let out = qsv(&[
        "vault-rotate".into(),
        "--datadir".into(),
        cookie_dir.into(),
        "--rpc-port".into(),
        port.clone(),
        "--inventory".into(),
        inv.to_str().unwrap().into(),
        "--all".into(),
        "--cosigner-all".into(),
        "127.0.0.1:9".into(),
        "--cosigner-all-cert".into(),
        garbage.to_str().unwrap().into(),
        "--cosigner-all-key".into(),
        garbage.to_str().unwrap().into(),
        "--cosigner-all-ca".into(),
        garbage.to_str().unwrap().into(),
        "--state-dir".into(),
        state.into(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "unparseable sweep-gate material must fail the sweep closed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("sweep-gate client identity"),
        "the identity wall must be named: {}",
        stderr(&out)
    );

    // 2. FAIL-CLOSED: the gate endpoint is a dead port → the sweep refuses
    //    to rotate ANYTHING (exit 1, no ceremony started).
    let out = qsv(&sweep_args(
        cookie_dir,
        &port,
        inv.to_str().unwrap(),
        state,
        "127.0.0.1:9",
    ));
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unanswerable gate must fail the sweep closed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(
        err.contains("sweep co-signer gate"),
        "the fail-closed reason must name the gate: {err}"
    );
    assert!(
        !stdout(&out).contains("sweep 1/"),
        "NO ceremony may start behind a dead gate: {}",
        stdout(&out)
    );
    assert!(
        !state_dir.join("rotation-state.json").exists(),
        "a dead gate must not mint rotation records"
    );

    // 3. THE LIVE GATE: a real bridge whose watchtower state freezes VAULT.
    let bridge_state = dir.path().join("wt-state");
    std::fs::create_dir_all(&bridge_state).unwrap();
    std::fs::write(
        bridge_state.join("watchtower-state.json"),
        format!(
            r#"{{ "tip": 900000, "vaults": {{ "{VAULT}": {{ "last_tip": 900000, "last_verdict": "ALERT", "idle_blocks": 13000 }} }} }}"#
        ),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = listener.local_addr().unwrap().port();
    drop(listener);
    std::thread::sleep(std::time::Duration::from_millis(200));
    let bridge_addr = format!("127.0.0.1:{bridge_port}");
    let mut bridge = Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args([
            "cosigner-bridge",
            "--listen",
            &bridge_addr,
            "--state-dir",
            bridge_state.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--vault-id",
            "vault-gate-healthy",
            // The ROTATION signature request identifies the vault by its
            // ADDRESS (the single-vault contract, Round 11); the pre-flight
            // GATE asks by INVENTORY id (the watchtower alarm space). One
            // bridge serves both namespaces.
            "--vault-id",
            vault_addr.as_str(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::net::TcpStream::connect(&bridge_addr).is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bridge never came up at {bridge_addr}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // 3a. THE PREVIEW: the same frozen fleet under --dry-run classifies
    //     every row (DUE / healthy / FROZEN) without running a ceremony.
    let mut dry_args = sweep_args(
        cookie_dir,
        &port,
        inv.to_str().unwrap(),
        state,
        &bridge_addr,
    );
    dry_args.push("--dry-run".into());
    let dry = qsv(&dry_args);
    let dry_text = stdout(&dry);
    assert!(
        dry.status.success(),
        "the preview must complete: {dry_text}{}",
        stderr(&dry)
    );
    assert!(dry_text.contains("DRY RUN COMPLETE"), "{dry_text}");
    assert!(
        dry_text.contains("FROZEN["),
        "the preview names the frozen vault: {dry_text}"
    );

    let out = qsv(&sweep_args(
        cookie_dir,
        &port,
        inv.to_str().unwrap(),
        state,
        &bridge_addr,
    ));
    assert!(
        out.status.success(),
        "the healthy fleet must refresh behind the live gate: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("FROZEN (watchtower alarm) — skipping"),
        "the frozen vault must be skipped with an explicit line: {text}"
    );
    assert!(
        text.contains("sweep: vault [vault-gate-healthy] refreshed"),
        "the healthy vault must refresh THROUGH the live gate: {text}"
    );
    assert!(
        text.contains("1 skipped (frozen)"),
        "the summary must report the frozen skip: {text}"
    );
    assert!(text.contains("FROZEN["), "{text}");

    // 4. THE FROZEN VAULT WAS NEVER TOUCHED: no rotation record, no
    //    artifact dir — its alarm survives until the operator clears it.
    let rot_state = std::fs::read_to_string(state_dir.join("rotation-state.json")).unwrap();
    let recorded: serde_json::Value = serde_json::from_str(&rot_state).unwrap();
    assert!(
        recorded["vaults"].get(VAULT).is_none(),
        "the frozen vault must NEVER be recorded as refreshed: {rot_state}"
    );
    assert!(
        recorded["vaults"].get("vault-gate-healthy").is_some(),
        "the healthy vault IS recorded: {rot_state}"
    );
    assert!(
        !dir.path().join(format!("vault-rotate-{}", VAULT)).exists(),
        "no ceremony may have run for the frozen vault"
    );

    // 4b. ALL-CLEAR GATE: a second live bridge whose watchtower rows are
    //     healthy — the gate answers NOT-frozen for every due row, so the
    //     sweep must NOT print a frozen summary (there is nothing to
    //     summarize). This is the other side of the frozen arm: gate
    //     configured, zero freezes.
    let healthy_state = dir.path().join("wt-state-healthy");
    std::fs::create_dir_all(&healthy_state).unwrap();
    std::fs::write(
        healthy_state.join("watchtower-state.json"),
        r#"{ "tip": 900000, "vaults": {
            "vault-gate-healthy": { "last_tip": 900000, "last_verdict": "OK", "idle_blocks": 0 }
        } }"#,
    )
    .unwrap();
    let listener2 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let healthy_port = listener2.local_addr().unwrap().port();
    drop(listener2);
    std::thread::sleep(std::time::Duration::from_millis(200));
    let healthy_addr = format!("127.0.0.1:{healthy_port}");
    let mut bridge2 = Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args([
            "cosigner-bridge",
            "--listen",
            &healthy_addr,
            "--state-dir",
            healthy_state.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--vault-id",
            "vault-gate-healthy",
            "--vault-id",
            vault_addr.as_str(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("healthy bridge must spawn");
    let deadline2 = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::net::TcpStream::connect(&healthy_addr).is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline2,
            "healthy bridge never came up at {healthy_addr}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut healthy_args = sweep_args(
        cookie_dir,
        &port,
        inv.to_str().unwrap(),
        state,
        &healthy_addr,
    );
    healthy_args.push("--dry-run".into());
    let healthy = qsv(&healthy_args);
    let healthy_text = stdout(&healthy);
    assert!(
        healthy.status.success(),
        "the all-clear dry sweep must complete: {healthy_text}{}",
        stderr(&healthy)
    );
    assert!(healthy_text.contains("DRY RUN COMPLETE"), "{healthy_text}");
    assert!(
        !healthy_text.contains("of due vault(s) frozen"),
        "an all-clear gate must not print a frozen summary: {healthy_text}"
    );
    assert!(
        !healthy_text.contains("FROZEN["),
        "nothing is frozen behind an all-clear gate: {healthy_text}"
    );
    stop_gracefully(&mut bridge2);
    let _ = bridge2.wait();

    stop_gracefully(&mut bridge);
    let _ = bridge.wait();
}

/// mTLS SWEEP GATE (Round 16): the sweep talks MUTUAL TLS end to end — the
/// bridge serves `--tls-cert/--tls-key --tls-client-ca ca.pem`, the sweep
/// presents `--cosigner-all-cert/--cosigner-all-key` and pins the bridge
/// via `--cosigner-all-ca`. A wrong-client-CA sweep fails closed BEFORE
/// any ceremony; the correctly pinned sweep refreshes the healthy fleet
/// and skips the frozen one through the encrypted gate.
#[test]
fn batch_sweep_gate_runs_over_mutual_tls() {
    use rcgen::{CertificateParams, KeyPair};

    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().unwrap();
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_str().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    mine!(rpc, 13_500);
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
    let _: serde_json::Value = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(vault_addr), serde_json::json!(0.001)],
        )
        .unwrap();
    mine!(rpc, 1);

    let inv = dir.path().join("env.json");
    std::fs::write(
        &inv,
        format!(
            r#"{{ "vaults": [
            {{ "id": "{VAULT}", "last_refresh_block": 400 }},
            {{ "id": "vault-gate-healthy", "last_refresh_block": 400 }}
        ] }}"#
        ),
    )
    .unwrap();
    let state_dir = dir.path().join("rot-state");
    let state = state_dir.to_str().unwrap();

    // PKI: CA + server (bridge) + TWO client identities (the operator's
    // and a FOREIGN-CA one for the fail-closed check).
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = CertificateParams::new(vec!["qsv sweep ca".into()])
        .unwrap()
        .self_signed(&ca_key)
        .unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
        .unwrap()
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_cert = CertificateParams::new(vec!["qsv sweep client".into()])
        .unwrap()
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();
    let foreign_key = KeyPair::generate().unwrap();
    let foreign_ca_cert = CertificateParams::new(vec!["qsv foreign ca".into()])
        .unwrap()
        .self_signed(&foreign_key)
        .unwrap();
    let foreign_client_key = KeyPair::generate().unwrap();
    let foreign_client_cert = CertificateParams::new(vec!["qsv foreign client".into()])
        .unwrap()
        .signed_by(&foreign_client_key, &foreign_ca_cert, &foreign_key)
        .unwrap();
    let pki = dir.path().join("pki");
    std::fs::create_dir_all(&pki).unwrap();
    let ca_pem = pki.join("ca.pem");
    std::fs::write(&ca_pem, ca_cert.pem()).unwrap();
    let server_cert_pem = pki.join("server-cert.pem");
    std::fs::write(&server_cert_pem, server_cert.pem()).unwrap();
    let server_key_pem = pki.join("server-key.pem");
    std::fs::write(&server_key_pem, server_key.serialize_pem()).unwrap();
    let client_cert_pem = pki.join("client-cert.pem");
    std::fs::write(&client_cert_pem, client_cert.pem()).unwrap();
    let client_key_pem = pki.join("client-key.pem");
    std::fs::write(&client_key_pem, client_key.serialize_pem()).unwrap();
    let foreign_cert_pem = pki.join("foreign-cert.pem");
    std::fs::write(&foreign_cert_pem, foreign_client_cert.pem()).unwrap();
    let foreign_key_pem = pki.join("foreign-key.pem");
    std::fs::write(&foreign_key_pem, foreign_client_key.serialize_pem()).unwrap();

    // The mTLS bridge: watchtower state freezes VAULT.
    let bridge_state = dir.path().join("wt-state");
    std::fs::create_dir_all(&bridge_state).unwrap();
    std::fs::write(
        bridge_state.join("watchtower-state.json"),
        format!(
            r#"{{ "tip": 900000, "vaults": {{ "{VAULT}": {{ "last_tip": 900000, "last_verdict": "ALERT", "idle_blocks": 13000 }} }} }}"#
        ),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = listener.local_addr().unwrap().port();
    drop(listener);
    std::thread::sleep(std::time::Duration::from_millis(200));
    let bridge_addr = format!("127.0.0.1:{bridge_port}");
    let mut bridge = Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args([
            "cosigner-bridge",
            "--listen",
            &bridge_addr,
            "--state-dir",
            bridge_state.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--vault-id",
            "vault-gate-healthy",
            "--vault-id",
            vault_addr.as_str(),
            "--tls-cert",
            server_cert_pem.to_str().unwrap(),
            "--tls-key",
            server_key_pem.to_str().unwrap(),
            "--tls-client-ca",
            ca_pem.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("mTLS bridge child must spawn");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if std::net::TcpStream::connect(&bridge_addr).is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bridge never came up at {bridge_addr}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // 1. FAIL-CLOSED PKI: the sweep presents a FOREIGN-CA client cert —
    //    the handshake refuses it, the gate cannot answer, the sweep dies
    //    BEFORE any ceremony (no rotation state, no mempool entry).
    let out = Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args([
            "vault-rotate",
            "--datadir",
            cookie_dir,
            "--rpc-port",
            &port,
            "--inventory",
            inv.to_str().unwrap(),
            "--all",
            "--cosigner-all",
            &bridge_addr,
            "--cosigner-all-cert",
            foreign_cert_pem.to_str().unwrap(),
            "--cosigner-all-key",
            foreign_key_pem.to_str().unwrap(),
            "--cosigner-all-ca",
            ca_pem.to_str().unwrap(),
            "--state-dir",
            state,
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "a foreign client identity must fail the gate closed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!state_dir.join("rotation-state.json").exists());
    let mempool: serde_json::Value = rpc.call("getrawmempool", &[]).unwrap();
    assert!(mempool.as_array().unwrap().is_empty());

    // 2. THE PINNED SWEEP: correct client identity + server CA pin → the
    //    gate answers over mTLS, the frozen vault is skipped, the healthy
    //    vault refreshes THROUGH the same encrypted gate.
    let out = Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args([
            "vault-rotate",
            "--datadir",
            cookie_dir,
            "--rpc-port",
            &port,
            "--inventory",
            inv.to_str().unwrap(),
            "--all",
            "--cosigner-all",
            &bridge_addr,
            "--cosigner-all-cert",
            client_cert_pem.to_str().unwrap(),
            "--cosigner-all-key",
            client_key_pem.to_str().unwrap(),
            "--cosigner-all-ca",
            ca_pem.to_str().unwrap(),
            "--state-dir",
            state,
        ])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "the pinned sweep must refresh through mTLS: {text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("(mTLS)"),
        "the gate transport must be named: {text}"
    );
    assert!(
        text.contains("FROZEN (watchtower alarm) — skipping"),
        "{text}"
    );
    assert!(
        text.contains("sweep: vault [vault-gate-healthy] refreshed"),
        "{text}"
    );
    let rot_state = std::fs::read_to_string(state_dir.join("rotation-state.json")).unwrap();
    let recorded: serde_json::Value = serde_json::from_str(&rot_state).unwrap();
    assert!(recorded["vaults"].get("vault-gate-healthy").is_some());
    assert!(recorded["vaults"].get(VAULT).is_none());

    stop_gracefully(&mut bridge);
    let _ = bridge.wait();
}
