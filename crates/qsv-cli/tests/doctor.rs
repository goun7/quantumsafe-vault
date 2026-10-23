//! OPERATOR DOCTOR e2e (docs/10 §4.24, Round 20): `qsv-cli doctor` asks
//! every liveness layer the same question in one command and answers with
//! an honest table — node cookie RPC, the watchtower state file, the
//! mirror lag, the bridge health record (pid + policy) and a live
//! `/metrics` scrape. Only a FAIL turns into exit 1, so the command works
//! as a scripted health gate.
//!
//! The layers are broken ONE AT A TIME, against a REAL bitcoind:
//!   1. All green → exit 0, zero warnings.
//!   2. Bridge stopped cleanly → WARN (absent record is not a failure),
//!      still exit 0.
//!   3. Bridge killed uncleanly → the record survives with a DEAD pid →
//!      FAIL. A stale claim must never read as "co-signer up".
//!   4. Scrape token missing → the alert rules would be BLIND → FAIL;
//!      with the token the same bridge is green again.
//!   5. Malformed watchtower state → FAIL (the bridge would refuse to
//!      boot on it too — the operator sees the same failure up front).
//!   6. Verdict tip far behind the node → WARN: the mirror is protecting
//!      against a stale view of the chain.

use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Round 19: the parallel workspace matrix can starve a bitcoind past the
/// RPC transport's hard 15s timeout — a transient that failed sweep tests
/// while the very same tests passed in the next run. Mining here is safe
/// to repeat, so a stalled call is retried instead of sinking the test.
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

/// Mines `n` blocks in ≤250-block chunks (one huge generatetoaddress call
/// can exceed the RPC client timeout).
fn mine(rpc: &bitcoind::Client, n: u64) {
    let mut remaining = n;
    while remaining > 0 {
        let chunk = remaining.min(250);
        let addr: String = retry("getnewaddress", || {
            rpc.call("getnewaddress", &[serde_json::json!("")])
        });
        let _: serde_json::Value = retry("generatetoaddress", || {
            rpc.call(
                "generatetoaddress",
                &[serde_json::json!(chunk), serde_json::json!(addr)],
            )
        });
        remaining -= chunk;
    }
}

fn qsv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_qsv-cli")
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

fn spawn_bridge(state_dir: &std::path::Path, port: u16, extra: &[&str]) -> Child {
    let addr = format!("127.0.0.1:{port}");
    let mut args = vec![
        "cosigner-bridge".to_string(),
        "--listen".to_string(),
        addr.clone(),
        "--state-dir".to_string(),
        state_dir.to_string_lossy().to_string(),
        "--vault-id".to_string(),
        "test-vault-1".to_string(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    Command::new(qsv_bin())
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn")
}

fn state_body_at(tip: u32) -> String {
    format!(
        r#"{{ "tip": {tip}, "vaults": {{ "test-vault-1": {{ "last_tip": {tip}, "last_verdict": "clear", "idle_blocks": 13000 }} }} }}"#
    )
}

struct Doctor {
    out: std::process::Output,
    text: String,
}

impl Doctor {
    fn new(args: &[&str]) -> Self {
        let out = Command::new(qsv_bin())
            .args(args)
            .output()
            .expect("qsv-cli doctor must run");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Self { out, text }
    }

    fn rc(&self) -> Option<i32> {
        self.out.status.code()
    }

    fn summary(&self) -> &str {
        self.text
            .lines()
            .find(|l| l.starts_with("DOCTOR:"))
            .unwrap_or("<no summary>")
    }
}

#[test]
fn doctor_answers_each_layer_honestly_and_fails_only_on_required_checks() {
    let Some(btc) = node_available() else { return };
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let cookie_dir = cookie_dir.to_string_lossy().to_string();
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    let tip: u32 = retry("getblockcount", || btc.client.get_block_count()).0 as u32;
    std::fs::write(state_dir.join("watchtower-state.json"), state_body_at(tip)).unwrap();
    let state = state_dir.to_string_lossy().to_string();
    let rpc_port = btc.params.rpc_socket.port().to_string();
    // The cookie carries credentials, never the port: the harness node
    // listens on a random port, so the doctor needs --rpc-port (same
    // contract as psbt/watchtower).
    let node_args = [
        "--datadir",
        &cookie_dir,
        "--network",
        "regtest",
        "--rpc-port",
        &rpc_port,
    ];

    // 1. ALL GREEN: node, state, live bridge record and scrape.
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = spawn_bridge(&state_dir, port, &[]);
    wait_ready(&addr);
    let d = Doctor::new(&[
        "doctor",
        node_args[0],
        node_args[1],
        node_args[2],
        node_args[3],
        node_args[4],
        node_args[5],
        "--state-dir",
        &state,
    ]);
    assert_eq!(d.rc(), Some(0), "healthy estate must exit 0:\n{}", d.text);
    assert!(d.text.contains("node rpc"), "{}", d.text);
    assert!(d.text.contains(&format!("tip {tip}")), "{}", d.text);
    assert!(d.text.contains("watchtower state"), "{}", d.text);
    assert!(
        d.text.contains(&format!("pid {} alive", child.id())),
        "the live pid must be named:\n{}",
        d.text
    );
    assert!(d.text.contains(&addr), "the bound address:\n{}", d.text);
    assert!(d.text.contains("metrics scrape"), "{}", d.text);
    assert!(d.text.contains("request(s)"), "{}", d.text);
    // Round 23 (docs/10 §4.37): the record also names the RELOAD source —
    // an unarmed loopback bridge has nothing to rotate and the doctor says
    // so, instead of leaving a silent gap in front of the operator.
    assert!(d.text.contains("scrape rotation"), "{}", d.text);
    assert_eq!(d.summary(), "DOCTOR: 6 check(s) — 0 FAIL, 0 WARN");
    // MACHINE-READABLE (Round 22, docs/10 §4.32): the SAME verdict as
    // ONE JSON document on stdout — no banner, no table — so a
    // deployment gate parses the details and trusts the exit code.
    let out = Command::new(qsv_bin())
        .args([
            "doctor",
            node_args[0],
            node_args[1],
            node_args[2],
            node_args[3],
            node_args[4],
            node_args[5],
            "--state-dir",
            &state,
            "--json",
        ])
        .output()
        .expect("qsv-cli doctor --json must run");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a healthy JSON run exits 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let raw = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value = serde_json::from_str(raw.trim())
        .unwrap_or_else(|e| panic!("stdout must be ONE JSON document: {e}\n{raw}"));
    assert_eq!(doc["schema"], "qsv-doctor/v1");
    // Round 23 added the reload-readiness check: six layers now, each with
    // a JSON twin.
    assert_eq!(doc["total"], 6);
    assert_eq!(doc["fail"], 0);
    assert_eq!(doc["warn"], 0);
    assert_eq!(doc["exit_code"], 0);
    assert!(
        !raw.contains("DOCTOR:") && !raw.contains("QUANTUMSAFE-VAULT"),
        "no prose may share stdout with the document: {raw}"
    );
    let checks = doc["checks"].as_array().expect("checks array");
    assert_eq!(checks.len(), 6, "every human row has a JSON twin");
    assert!(
        checks.iter().any(|c| c["name"] == "scrape rotation"),
        "the reload-readiness layer travels in machine form too: {doc}"
    );
    for c in checks {
        let status = c["status"].as_str().expect("status word");
        assert!(
            matches!(status, "ok" | "warn" | "fail"),
            "unknown status: {status}"
        );
        assert!(c["name"].as_str().is_some() && c["detail"].as_str().is_some());
    }
    // The doctor only READS: it must not disturb the co-signer or the
    // record it just inspected.
    assert_eq!(
        qsv_cosigner::health::read(&state_dir).map(|h| h.pid),
        Some(child.id()),
        "the health record survives the doctor"
    );

    // 2. GRACEFUL STOP: the record is gone → WARN, NOT a failure. An
    //    intentionally stopped bridge is a normal operator action.
    let ret = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(ret, 0, "SIGTERM must reach the bridge child");
    assert_eq!(child.wait().unwrap().code(), Some(0), "graceful exit 0");
    let d = Doctor::new(&[
        "doctor",
        node_args[0],
        node_args[1],
        node_args[2],
        node_args[3],
        node_args[4],
        node_args[5],
        "--state-dir",
        &state,
    ]);
    assert_eq!(
        d.rc(),
        Some(0),
        "a stopped bridge is not a broken estate:\n{}",
        d.text
    );
    assert!(d.text.contains("WARN"), "{}", d.text);
    assert!(d.text.contains("stopped cleanly"), "{}", d.text);
    assert_eq!(d.summary(), "DOCTOR: 5 check(s) — 0 FAIL, 2 WARN");

    // 3. UNCLEAN DEATH: a record whose pid is gone is a FAIL. Write one
    //    naming a reaped pid (exactly what SIGKILL leaves behind).
    let dead = {
        let mut dead_child = Command::new("true").spawn().unwrap();
        let pid = dead_child.id();
        dead_child.wait().unwrap();
        pid
    };
    let stale = qsv_cosigner::health::current(
        &addr,
        "plain",
        vec!["test-vault-1".to_string()],
        tip,
        qsv_cosigner::health::ServePolicyRecord {
            metrics_token_armed: false,
            metrics_token_file: None,
            max_inflight: 64,
            frame_timeout_ms: Some(10_000),
        },
    );
    let mut stale = stale;
    stale.pid = dead;
    qsv_cosigner::health::write(&state_dir, &stale).unwrap();
    let d = Doctor::new(&[
        "doctor",
        node_args[0],
        node_args[1],
        node_args[2],
        node_args[3],
        node_args[4],
        node_args[5],
        "--state-dir",
        &state,
    ]);
    assert_eq!(
        d.rc(),
        Some(1),
        "a stale record is a hard failure:\n{}",
        d.text
    );
    assert!(
        d.text.contains(&format!("DEAD pid {dead}")),
        "the dead pid must be named:\n{}",
        d.text
    );
    // The dead record also fails the live scrape probe (its recorded listen
    // address refuses the connection) — two genuinely broken layers, both
    // named. Nothing is downgraded to a warning to make the table prettier.
    assert_eq!(d.summary(), "DOCTOR: 6 check(s) — 2 FAIL, 0 WARN");
    // The SAME failure in machine form: still ONE document on stdout
    // (the reason goes to stderr), exit code 1, fail count spelled out —
    // a gate reads `exit_code` instead of matching prose.
    let out = Command::new(qsv_bin())
        .args([
            "doctor",
            node_args[0],
            node_args[1],
            node_args[2],
            node_args[3],
            node_args[4],
            node_args[5],
            "--state-dir",
            &state,
            "--json",
        ])
        .output()
        .expect("qsv-cli doctor --json must run");
    assert_eq!(
        out.status.code(),
        Some(1),
        "FAIL still exits 1 in json mode"
    );
    let raw = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value = serde_json::from_str(raw.trim())
        .unwrap_or_else(|e| panic!("stdout must stay ONE JSON document: {e}\n{raw}"));
    assert_eq!(doc["schema"], "qsv-doctor/v1");
    assert_eq!(doc["fail"], 2, "the two broken layers are counted");
    assert_eq!(doc["exit_code"], 1);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("required check(s) failed"),
        "the reason stays on stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    qsv_cosigner::health::remove(&state_dir);

    // 4. SCRAPE TOKEN: an armed gate the operator cannot open leaves the
    //    alert rules blind → FAIL. With the token the SAME bridge is OK.
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = spawn_bridge(&state_dir, port, &["--metrics-token", "s3cr3t"]);
    wait_ready(&addr);
    let base = [
        "doctor",
        node_args[0],
        node_args[1],
        node_args[2],
        node_args[3],
        node_args[4],
        node_args[5],
        "--state-dir",
        &state,
    ];
    let mut blind = base.to_vec();
    blind.push("--bridge");
    blind.push(&addr);
    let d = Doctor::new(&blind);
    assert_eq!(
        d.rc(),
        Some(1),
        "a refused scrape means monitoring is blind:\n{}",
        d.text
    );
    assert!(d.text.contains("401"), "{}", d.text);
    assert!(
        d.text.contains("--metrics-token"),
        "the message names the fix:\n{}",
        d.text
    );
    // With the token the very same estate is green (and the record's own
    // listen address is used, no --bridge needed).
    let mut with_token = base.to_vec();
    with_token.push("--metrics-token");
    with_token.push("s3cr3t");
    let d = Doctor::new(&with_token);
    assert_eq!(d.rc(), Some(0), "armed + token = healthy:\n{}", d.text);
    // Round 23: THIS bridge was armed from argv, so `systemctl reload`
    // has no file to re-read — named as a WARN, never a silent no-op.
    assert!(d.text.contains("cannot rotate it"), "{}", d.text);
    assert_eq!(d.summary(), "DOCTOR: 6 check(s) — 0 FAIL, 1 WARN");
    // Round 21 (docs/10 §4.27): the SAME token via a chmod-600 FILE — the
    // doctor's own argv stays secret-free (only the PATH lands there)
    // while the probe still opens the very same gate.
    let token_file = state_dir.join("doctor-token.txt");
    std::fs::write(&token_file, "s3cr3t\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut from_file = base.to_vec();
    from_file.push("--metrics-token-file");
    from_file.push(token_file.to_str().unwrap());
    let d = Doctor::new(&from_file);
    assert_eq!(d.rc(), Some(0), "armed + token FILE = healthy:\n{}", d.text);
    // The doctor's own token file is a PROBE source; the record still
    // reports the bridge's reload source (argv → not rotatable), and the
    // warning stays exactly that honest.
    assert_eq!(d.summary(), "DOCTOR: 6 check(s) — 0 FAIL, 1 WARN");
    // SIGKILL is the UNCLEAN path: it leaves the record behind. Clear it here
    // so the next step starts from an honest "no bridge" state (the stale-
    // record detection is asserted in step 3, not smuggled in here).
    let _ = child.kill();
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        qsv_cosigner::health::liveness(&state_dir).0,
        qsv_cosigner::Liveness::Stale,
        "an unclean death leaves a stale record"
    );
    qsv_cosigner::health::remove(&state_dir);

    // 5. MALFORMED WATCHTOWER STATE: the bridge refuses to boot on this,
    //    so the doctor must refuse to call it healthy (exit 1).
    std::fs::write(state_dir.join("watchtower-state.json"), "{ not json").unwrap();
    let d = Doctor::new(&base);
    assert_eq!(
        d.rc(),
        Some(1),
        "unreadable state is a failure:\n{}",
        d.text
    );
    assert!(d.text.contains("FAIL"), "{}", d.text);
    assert!(
        d.text.contains("watchtower state"),
        "the failing layer is named:\n{}",
        d.text
    );
    std::fs::write(state_dir.join("watchtower-state.json"), state_body_at(tip)).unwrap();

    // 6. MIRROR LAG: verdicts 20+ blocks behind the node are a WARN — the
    //    estate is protected against a stale view of the chain.
    mine(&btc.client, 20);
    std::fs::write(state_dir.join("watchtower-state.json"), state_body_at(tip)).unwrap();
    let d = Doctor::new(&base);
    assert_eq!(
        d.rc(),
        Some(0),
        "lag is a warning, not a failure:\n{}",
        d.text
    );
    assert!(d.text.contains("behind the node"), "{}", d.text);
    assert!(d.text.contains("WARN"), "{}", d.text);
    assert_eq!(d.summary(), "DOCTOR: 5 check(s) — 0 FAIL, 3 WARN");
}

#[test]
fn doctor_fails_closed_when_the_node_is_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(
        state_dir.join("watchtower-state.json"),
        state_body_at(820_000),
    )
    .unwrap();
    let d = Doctor::new(&[
        "doctor",
        "--datadir",
        "/nonexistent-bitcoin",
        "--network",
        "regtest",
        "--state-dir",
        &state_dir.to_string_lossy(),
    ]);
    assert_eq!(d.rc(), Some(1), "no node = not healthy:\n{}", d.text);
    assert!(d.text.contains("FAIL"), "{}", d.text);
    assert!(d.text.contains("node rpc"), "{}", d.text);
    // The other layers are still reported — a partial answer beats silence.
    assert!(d.text.contains("watchtower state"), "{}", d.text);
    assert!(d.text.contains("stopped cleanly"), "{}", d.text);
}

/// RELOAD READINESS (docs/10 §4.37, Round 23): `systemctl reload` swaps
/// the scrape token in place (Round 22) — but a reload that CANNOT
/// rotate leaves the old secret live while the operator believes it
/// moved, and the only other witness is
/// `QsvCosignerTokenRotationStalled`, AFTER the fact. The doctor says it
/// BEFORE the reload: it reads the `--metrics-token-file` path out of the
/// bridge's own health record and applies the very contract the bridge
/// enforces (mode 600, one line, no whitespace) — no guessing, no
/// discovery at 3 a.m.
///
/// Needs no node: the record on disk is the input, and every verdict is
/// read out of the SAME `doctor --json` document a deployment gate uses.
#[test]
fn doctor_proves_whether_a_reload_could_rotate_the_scrape_token() {
    fn rotation_check(state: &str) -> serde_json::Value {
        let out = Command::new(qsv_bin())
            .args(["doctor", "--state-dir", state, "--json"])
            .output()
            .expect("qsv-cli doctor must run");
        let raw = String::from_utf8_lossy(&out.stdout);
        let doc: serde_json::Value = serde_json::from_str(raw.trim())
            .unwrap_or_else(|e| panic!("doctor --json must stay ONE document: {e}\n{raw}"));
        doc["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .find(|c| c["name"] == "scrape rotation")
            .cloned()
            .unwrap_or_else(|| panic!("the reload-readiness check must be present:\n{doc}"))
    }

    fn publish(state_dir: &std::path::Path, armed: bool, file: Option<&str>) {
        let record = qsv_cosigner::health::current(
            "127.0.0.1:3334",
            "plain",
            vec!["test-vault-1".to_string()],
            820_000,
            qsv_cosigner::health::ServePolicyRecord {
                metrics_token_armed: armed,
                metrics_token_file: file.map(str::to_string),
                max_inflight: 64,
                frame_timeout_ms: Some(10_000),
            },
        );
        qsv_cosigner::health::write(state_dir, &record).unwrap();
    }

    fn detail(check: &serde_json::Value) -> &str {
        check["detail"].as_str().unwrap_or_default()
    }

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    let token = dir.path().join("scrape.token");
    std::fs::write(&token, "sekrit-v1\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let state = state_dir.to_string_lossy().to_string();

    // 1. Armed from a file that satisfies the contract: a reload rotates.
    publish(&state_dir, true, Some(token.to_str().unwrap()));
    let check = rotation_check(&state);
    assert_eq!(check["status"], "ok", "{check}");
    assert!(detail(&check).contains("rotates in place"), "{check}");

    // 2. The file loosened to 0644 (the shape the Round 21 reader
    //    refuses): the reload would be REFUSED — a FAIL, because the
    //    operator cannot rotate a leaked token.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let check = rotation_check(&state);
    assert_eq!(check["status"], "fail", "{check}");
    assert!(detail(&check).contains("would be REFUSED"), "{check}");

    // 3. Armed from argv: nothing to re-read → every reload is a no-op.
    //    A WARN (the estate still signs), but named.
    publish(&state_dir, true, None);
    let check = rotation_check(&state);
    assert_eq!(check["status"], "warn", "{check}");
    assert!(detail(&check).contains("cannot rotate it"), "{check}");

    // 4. Never armed (loopback dev default): nothing to keep ready.
    publish(&state_dir, false, None);
    let check = rotation_check(&state);
    assert_eq!(check["status"], "ok", "{check}");
    assert!(
        detail(&check).contains("no rotation to keep ready"),
        "{check}"
    );
}
