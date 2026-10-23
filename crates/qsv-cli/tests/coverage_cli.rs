//! Round 30 · 100% coverage round: the operator-flow arms that only a REAL
//! node, a REAL port or a real invocation shape can reach — the dashboard's
//! live frame and graceful watch stop, the watchtower's DUE/OPEN verdicts,
//! the rotation baseline walls and dust floor, the batch inventory walls,
//! `psbt-live`'s funding path and destination walls, and the doctor's
//! probe edges. Every assertion is the operator-visible contract.

use std::process::{Child, Command, Output};

fn qsv(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args(args)
        .output()
        .expect("qsv-cli binary must run")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// Round 19 discipline (same helper as doctor.rs / vault_rotate.rs): the
/// parallel workspace matrix can starve a bitcoind past the RPC transport's
/// hard 15s timeout — a transient that sank this suite at `mine` while the
/// very same test passed in the next run. Read-only calls and mining are
/// safe to repeat, so a stalled call is retried instead of the test.
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

/// SIGTERM + wait — the graceful stop path (and the child exit that
/// flushes the llvm-cov profile).
fn sigterm_and_wait(child: &mut Child) -> std::process::ExitStatus {
    let pid = child.id() as libc::pid_t;
    let _ = unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "child must exit after SIGTERM"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
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

/// The LIVE dashboard frame (no --tip override) plus the graceful watch
/// stop: SIGTERM ends the loop with exit 0 instead of killing the process.
#[test]
fn dashboard_live_node_and_graceful_watch_stop() {
    let Some(btc) = node_available() else { return };
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();
    let datadir = cookie_dir.to_str().unwrap();

    // One live frame from the REAL tip.
    let out = qsv(&[
        "vault-dashboard",
        "--datadir",
        datadir,
        "--network",
        "regtest",
        "--rpc-port",
        &port,
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("live node · best"), "{text}");

    // --watch: a live loop that STOPS CLEANLY on SIGTERM (exit 0).
    let mut child = Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args([
            "vault-dashboard",
            "--datadir",
            datadir,
            "--network",
            "regtest",
            "--rpc-port",
            &port,
            "--watch",
            "1",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("watch child must spawn");
    std::thread::sleep(std::time::Duration::from_millis(2500));
    let status = sigterm_and_wait(&mut child);
    assert!(
        status.success(),
        "a watched dashboard must stop CLEANLY on SIGTERM, got {status:?}"
    );
}

/// The watchtower's verdicts at BOTH clocks: DUE ⇒ ALERT + exit 1 (the
/// owner missed the refresh) and, once the CSV window has elapsed, the
/// OPEN line — in ONE pass over a chain aged past both thresholds.
#[test]
fn watchtower_alerts_on_a_due_heartbeat_and_reports_an_open_window() {
    let Some(btc) = node_available() else { return };
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();
    let datadir = cookie_dir.to_str().unwrap();

    // Age the chain past BOTH clocks: the heartbeat interval (12,960) and
    // the inheritance CSV (26,280) — mined in ≤250-block chunks, each
    // wrapped in retry, so a starved RPC transport never times out (same
    // discipline as vault_rotate/doctor).
    let tip: u64 = retry("getblockcount", || btc.client.call("getblockcount", &[]));
    let miner: String = retry("getnewaddress", || {
        btc.client.call("getnewaddress", &[serde_json::json!("")])
    });
    let mut left = 27_000u64.saturating_sub(tip);
    while left > 0 {
        let n = left.min(250);
        let _: serde_json::Value = retry("generatetoaddress", || {
            btc.client.call(
                "generatetoaddress",
                &[serde_json::json!(n), serde_json::json!(&miner)],
            )
        });
        left -= n;
    }

    // ONE pass (the harness node is on a RANDOM port, so the pass needs
    // --rpc-port; the plain-cookie arm is unit-covered in main.rs): due
    // AND open, alert on both counts.
    let out = qsv(&[
        "watchtower",
        "--datadir",
        datadir,
        "--network",
        "regtest",
        "--rpc-port",
        &port,
        "--last-refresh-block",
        "100",
        "--state-dir",
        datadir, // any writable dir; the pass overwrites the state file
    ]);
    assert_eq!(out.status.code(), Some(1), "DUE exits 1: {}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("DUE — OWNER REFRESH MISSED"), "{text}");
    assert!(
        text.contains("OPEN — heirs may settle"),
        "an elapsed CSV window is named: {text}"
    );
    assert!(text.contains("WATCHTOWER: ALERT"), "{text}");
}

/// Rotation baseline walls: every refusal names its remedy, and the dust
/// floor protects a coin too small to pay its own refresh fee.
#[test]
fn vault_rotate_baseline_walls_and_the_dust_floor() {
    let Some(btc) = node_available() else { return };
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();

    // A REAL chain: mature coinbase in the node's OWN wallet (the dust
    // step's sendtoaddress needs spendable funds) and 13,500 blocks so the
    // heartbeat interval (12,960 idle) is reachable — mined in ≤250-block
    // chunks behind retry so a starved RPC transport never times out.
    let miner: String = retry("getnewaddress", || {
        btc.client.call("getnewaddress", &[serde_json::json!("")])
    });
    let mut left = 13_500u64;
    while left > 0 {
        let n = left.min(250);
        let _: serde_json::Value = retry("generatetoaddress", || {
            btc.client.call(
                "generatetoaddress",
                &[serde_json::json!(n), serde_json::json!(&miner)],
            )
        });
        left -= n;
    }
    let datadir = cookie_dir.to_str().unwrap();
    let fx = tempfile::tempdir().unwrap();

    let rotate = |extra: &[&str]| -> Output {
        let mut args = vec![
            "vault-rotate",
            "--datadir",
            datadir,
            "--network",
            "regtest",
            "--rpc-port",
            &port,
            "--dir",
            fx.path().to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        qsv(&args)
    };

    // 1. No baseline anywhere → the refusal names every alternative.
    let out = rotate(&["--state-dir", fx.path().to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no heartbeat baseline"),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );

    // 2. A v2 state with only id-based records: the single-vault path
    //    refuses to guess.
    std::fs::write(
        fx.path().join("rotation-state.json"),
        r#"{"version":2,"vaults":{"some-vault":{"last_refresh_block":10,"txid":"aa","rotated_at_tip":10}}}"#,
    )
    .unwrap();
    let out = rotate(&["--state-dir", fx.path().to_str().unwrap()]);
    assert!(
        stderr(&out).contains("id-based records"),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );

    // 3. A v1 document ABOVE the tip is refused; one below the tip drives
    //    the baseline (and the run proceeds to the coin scan).
    std::fs::write(
        fx.path().join("rotation-state.json"),
        r#"{"version":1,"last_refresh_block":999999}"#,
    )
    .unwrap();
    let out = rotate(&["--state-dir", fx.path().to_str().unwrap()]);
    assert!(
        stderr(&out).contains("no heartbeat baseline"),
        "an impossible v1 baseline must be refused: {}{}",
        stdout(&out),
        stderr(&out)
    );
    std::fs::write(
        fx.path().join("rotation-state.json"),
        r#"{"version":1,"last_refresh_block":10}"#,
    )
    .unwrap();
    let out = rotate(&["--state-dir", fx.path().to_str().unwrap()]);
    assert!(
        !stderr(&out).contains("no heartbeat baseline"),
        "a sane v1 baseline must be accepted: {}",
        stderr(&out)
    );

    // 4. An UNREADABLE state file in the inventory path is fail-closed.
    std::fs::write(fx.path().join("rotation-state.json"), "{ not json").unwrap();
    let inv = fx.path().join("inv.json");
    std::fs::write(&inv, r#"{"vaults":[{"id":"v1","last_refresh_block":10}]}"#).unwrap();
    let out = rotate(&[
        "--inventory",
        inv.to_str().unwrap(),
        "--vault-id",
        "v1",
        "--state-dir",
        fx.path().to_str().unwrap(),
    ]);
    assert!(
        stderr(&out).contains("rotation state unreadable (fail-closed)")
            || stderr(&out).contains("No such file")
            || !out.status.success(),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );

    // 4b. A CORRUPT state in the SINGLE-VAULT fallback (no overrides at
    //     all) surfaces the raw parse error — not the "no heartbeat
    //     baseline" wall (that arm is the file-MISSING case, above).
    std::fs::write(fx.path().join("rotation-state.json"), "{ not json").unwrap();
    let out = rotate(&["--state-dir", fx.path().to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "a corrupt single-vault rotation state must fail closed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("no heartbeat baseline"),
        "the parse error must surface raw: {}",
        stderr(&out)
    );

    // 5. Inventory AHEAD of the recorded rotation: the verified record
    //    wins the max (no mismatch, the run proceeds).
    std::fs::write(
        fx.path().join("rotation-state.json"),
        r#"{"version":2,"vaults":{"v1":{"last_refresh_block":10,"txid":"aa","rotated_at_tip":10}}}"#,
    )
    .unwrap();
    let out = rotate(&[
        "--inventory",
        inv.to_str().unwrap(),
        "--vault-id",
        "v1",
        "--state-dir",
        fx.path().to_str().unwrap(),
    ]);
    assert!(
        !stderr(&out).contains("MISMATCH"),
        "a newer inventory row must merge, not clash: {}",
        stderr(&out)
    );

    // 6. DUST FLOOR: a coin too small for its own refresh fee is refused
    //    before anything is signed or broadcast.
    let addr = demo_vault_address();
    let _: serde_json::Value = btc
        .client
        .call(
            "sendtoaddress",
            &[serde_json::json!(addr), serde_json::json!("0.00000600")],
        )
        .expect("fund the dust coin");
    let miner: String = retry("getnewaddress", || {
        btc.client.call("getnewaddress", &[serde_json::json!("")])
    });
    let _: serde_json::Value = retry("generatetoaddress", || {
        btc.client.call(
            "generatetoaddress",
            &[serde_json::json!(1), serde_json::json!(&miner)],
        )
    });
    let out = rotate(&["--last-refresh-block", "400", "--fee-sat", "1500"]);
    assert!(
        stderr(&out).contains("too small for a 1500-sat refresh fee"),
        "the dust floor must name the fee: {}{}",
        stdout(&out),
        stderr(&out)
    );
}

/// Batch sweep inventory walls: an empty fleet, an unreadable state file
/// and a HEALTHY (non-stale) row are each reported precisely.
#[test]
fn vault_rotate_batch_inventory_walls_and_healthy_skips() {
    let Some(btc) = node_available() else { return };
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();
    let datadir = cookie_dir.to_str().unwrap();
    let fx = tempfile::tempdir().unwrap();

    // 1. An empty fleet is refused (cookie fallback arm).
    let empty = fx.path().join("empty.json");
    std::fs::write(&empty, r#"{"vaults":[]}"#).unwrap();
    let out = qsv(&[
        "vault-rotate",
        "--all",
        "--inventory",
        empty.to_str().unwrap(),
        "--datadir",
        datadir,
        "--network",
        "regtest",
        "--dir",
        fx.path().to_str().unwrap(),
        "--state-dir",
        fx.path().to_str().unwrap(),
    ]);
    assert!(
        stderr(&out).contains("empty vaults array"),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );

    // 2. An unreadable rotation state is fail-closed, loudly.
    let fresh = fx.path().join("fresh.json");
    std::fs::write(
        &fresh,
        format!(
            r#"{{"vaults":[{{"id":"v1","last_refresh_block":{}}}]}}"#,
            1_000_000
        ),
    )
    .unwrap();
    std::fs::write(fx.path().join("rotation-state.json"), "{ not json").unwrap();
    let out = qsv(&[
        "vault-rotate",
        "--all",
        "--inventory",
        fresh.to_str().unwrap(),
        "--datadir",
        datadir,
        "--network",
        "regtest",
        "--rpc-port",
        &port,
        "--dir",
        fx.path().to_str().unwrap(),
        "--state-dir",
        fx.path().to_str().unwrap(),
    ]);
    assert!(
        stderr(&out).contains("rotation state unreadable (fail-closed)"),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );

    // 3. A HEALTHY row (refreshed at the live tip) is skipped with the
    //    non-stale wording, and the dry run completes.
    std::fs::remove_file(fx.path().join("rotation-state.json")).ok();
    let out = qsv(&[
        "vault-rotate",
        "--all",
        "--dry-run",
        "--inventory",
        fresh.to_str().unwrap(),
        "--datadir",
        datadir,
        "--network",
        "regtest",
        "--rpc-port",
        &port,
        "--dir",
        fx.path().to_str().unwrap(),
        "--state-dir",
        fx.path().to_str().unwrap(),
    ]);
    let text = stdout(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        text.contains("healthy — skipping"),
        "a fresh row is a healthy skip: {text}"
    );
    assert!(
        !text.contains("stale row"),
        "a tip-current row is NOT stale: {text}"
    );
    // Nothing was due, so the sweep states the fleet verdict and returns
    // before the per-rotation dry-run footer.
    assert!(text.contains("nothing due — 1 vault(s) healthy"), "{text}");
}

/// `psbt-live`: the regtest funding convenience (sendtoaddress + mine)
/// and every `--destination` wall, in order.
#[test]
fn psbt_live_funds_the_vault_and_refuses_bad_destinations() {
    let Some(btc) = node_available() else { return };
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();
    let datadir = cookie_dir.to_str().unwrap();
    let fx = tempfile::tempdir().unwrap();

    // Mature coinbase in the node's OWN wallet: `--fund-sat` spends via
    // sendtoaddress, which fails closed on an empty wallet (node error -6).
    let miner: String = retry("getnewaddress", || {
        btc.client.call("getnewaddress", &[serde_json::json!("")])
    });
    let _: serde_json::Value = retry("generatetoaddress", || {
        btc.client.call(
            "generatetoaddress",
            &[serde_json::json!(110), serde_json::json!(&miner)],
        )
    });

    let live = |extra: &[&str]| -> Output {
        let mut args = vec![
            "psbt-live",
            "--datadir",
            datadir,
            "--network",
            "regtest",
            "--rpc-port",
            &port,
            "--dir",
            fx.path().to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        qsv(&args)
    };

    // 1. Funding + a NON-HEX destination: the fund path runs first, then
    //    the wall fires.
    let out = live(&["--fund-sat", "100000", "--destination", "zz"]);
    assert!(
        stderr(&out).contains("--destination must be 64 hex chars"),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );

    // 2. The funded coin is now live: a SHORT hex key hits the length wall.
    let out = live(&["--destination", &"ab".repeat(31)]);
    assert!(
        stderr(&out).contains("--destination must be 64 hex chars"),
        "{}",
        stderr(&out)
    );

    // 3. A full-length x that is NOT a field element (2^256-1 ≥ the
    //    secp256k1 modulus) hits the key wall — x-only keys need a valid
    //    curve x-coordinate, and ~50% of x-values are on the curve, so the
    //    test pins the GUARANTEED-invalid side.
    let out = live(&["--destination", &"ff".repeat(32)]);
    assert!(
        stderr(&out).contains("--destination is not a valid x-only pubkey"),
        "{}",
        stderr(&out)
    );
}

/// The doctor's probe edges: mutually exclusive token flags are exit 2,
/// and a TCP endpoint that answers WITHOUT a 200 is a FAIL — "not a
/// co-signer?" — never a silent pass.
#[test]
fn doctor_exclusive_token_flags_exit_2_and_a_non_bridge_scrape_fails() {
    let fx = tempfile::tempdir().unwrap();
    let token_file = fx.path().join("tok");
    std::fs::write(&token_file, "sekrit\n").unwrap();

    // 1. Both token sources at once = usage error, exit 2.
    let out = qsv(&[
        "doctor",
        "--datadir",
        fx.path().to_str().unwrap(),
        "--network",
        "regtest",
        "--state-dir",
        fx.path().to_str().unwrap(),
        "--metrics-token",
        "sekrit",
        "--metrics-token-file",
        token_file.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("mutually exclusive"),
        "{}",
        stderr(&out)
    );

    // 2. A plain TCP server that answers WITHOUT an HTTP 200: the scrape
    //    check must FAIL, naming the endpoint.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for mut s in listener.incoming().take(2).flatten() {
            // Drain the request BEFORE answering: closing with the
            // client's bytes unread resets the connection (RST) and the
            // client would report "connection reset" instead of the
            // non-HTTP greeting.
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"hello, i am not a co-signer\n");
            let _ = s.flush();
            let _ = s.shutdown(std::net::Shutdown::Write);
            // Hold the socket open briefly so the client reads the
            // greeting before the read half closes.
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    });
    let out = qsv(&[
        "doctor",
        "--datadir",
        fx.path().to_str().unwrap(),
        "--network",
        "regtest",
        "--state-dir",
        fx.path().to_str().unwrap(),
        "--bridge",
        &addr,
    ]);
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("answered without a 200"),
        "a non-200 endpoint is a FAIL: {text}"
    );
}

/// The doctor's mirror-lag check with the verdicts AHEAD of the live node
/// (a bridge mirroring a longer chain than the node has — a warning the
/// operator must see, not a silent Ok).
#[test]
fn doctor_warns_when_the_mirror_is_ahead_of_the_node() {
    let Some(btc) = node_available() else { return };
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();
    let datadir = cookie_dir.to_str().unwrap();
    let fx = tempfile::tempdir().unwrap();
    std::fs::write(
        fx.path().join("watchtower-state.json"),
        r#"{"tip":820000,"vaults":{"qa-mirror":{"last_tip":820000,"last_verdict":"clear","idle_blocks":10}}}"#,
    )
    .unwrap();

    let out = qsv(&[
        "doctor",
        "--datadir",
        datadir,
        "--network",
        "regtest",
        "--rpc-port",
        &port,
        "--state-dir",
        fx.path().to_str().unwrap(),
        "--json",
    ]);
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.contains("AHEAD of node tip"),
        "an ahead-of-node mirror is a WARN: {text}"
    );
}

/// The pin set is resolved AT DISPATCH (before any node connection):
/// attestation pins without a co-signer endpoint are a usage error the
/// operator sees as exit 2 with the reason, never a half-started run.
#[test]
fn vault_rotate_pin_wall_is_a_dispatch_usage_error() {
    let out = qsv(&[
        "vault-rotate",
        "--cosigner-pcr0",
        "00",
        "--cosigner-key",
        "020000000000000000000000000000000000000000000000000000000000000001",
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "pins without an endpoint must exit 2: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let err = stderr(&out);
    assert!(err.contains("usage error"), "{err}");
    assert!(err.contains("attestation pins"), "{err}");
    assert!(err.contains("require a co-signer endpoint"), "{err}");
}

/// The multi-vault webhook verdicts: a DEAD endpoint is reported FAILED
/// (exit code unaffected) and an all-clear fleet prints its own line.
#[test]
fn watchtower_multi_webhook_failures_are_reported_and_all_clear_passes() {
    let Some(btc) = node_available() else { return };
    let cookie_dir = btc.params.cookie_file.parent().unwrap().parent().unwrap();
    let port = btc.params.rpc_socket.port().to_string();
    let datadir = cookie_dir.to_str().unwrap();
    let fx = tempfile::tempdir().unwrap();

    // A webhook pointing at a CLOSED port: the delivery must be reported
    // as FAILED without softening the pass.
    let inv = fx.path().join("inv.json");
    std::fs::write(
        &inv,
        r#"{"vaults":[{"id":"v1","last_refresh_block":1000000,"webhook":"http://127.0.0.1:9/webhook"}]}"#,
    )
    .unwrap();
    let out = qsv(&[
        "watchtower",
        "--inventory",
        inv.to_str().unwrap(),
        "--datadir",
        datadir,
        "--network",
        "regtest",
        "--rpc-port",
        &port,
        "--state-dir",
        fx.path().to_str().unwrap(),
    ]);
    let text = stdout(&out);
    assert!(
        text.contains("webhook: FAILED"),
        "a dead webhook is reported: {text}{}",
        stderr(&out)
    );

    // A LIVE loopback endpoint: the delivery succeeds on the first
    // attempt and the SUCCESS arm of the secondary channel prints.
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let alive_port = listener.local_addr().unwrap().port();
    let relay = std::thread::spawn(move || {
        // Accept ONCE: a working relay answers the first attempt, and a
        // broken one must surface as a FAILED assertion (the client's
        // retry would be refused) — never as a hang on join.
        let Ok((mut s, _)) = listener.accept() else {
            return;
        };
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(2)));
        let mut buf = [0u8; 65_536];
        let mut seen = 0usize;
        loop {
            match s.read(&mut buf[seen..]) {
                Ok(0) => break,
                Ok(n) => {
                    seen += n;
                    if seen >= buf.len() {
                        break;
                    }
                }
                Err(_) => break, // timeout: request fully drained on loopback
            }
            if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
        let _ = s.flush();
    });
    std::fs::write(
        &inv,
        format!(
            r#"{{"vaults":[{{"id":"v1","last_refresh_block":1000000,"webhook":"http://127.0.0.1:{alive_port}/watchtower"}}]}}"#
        ),
    )
    .unwrap();
    let out = qsv(&[
        "watchtower",
        "--inventory",
        inv.to_str().unwrap(),
        "--datadir",
        datadir,
        "--network",
        "regtest",
        "--rpc-port",
        &port,
        "--state-dir",
        fx.path().to_str().unwrap(),
    ]);
    let text = stdout(&out);
    assert!(
        text.contains("webhook: delivered after 1 attempt"),
        "a live webhook is delivered: {text}{}",
        stderr(&out)
    );
    relay.join().unwrap();

    // All-clear fleet: every row refreshed at the live tip.
    let tip: u64 = retry("getblockcount", || btc.client.call("getblockcount", &[]));
    std::fs::write(
        &inv,
        format!(r#"{{"vaults":[{{"id":"v1","last_refresh_block":{tip}}}]}}"#),
    )
    .unwrap();
    let out = qsv(&[
        "watchtower",
        "--inventory",
        inv.to_str().unwrap(),
        "--datadir",
        datadir,
        "--network",
        "regtest",
        "--rpc-port",
        &port,
        "--state-dir",
        fx.path().to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("all clear across 1 vaults"),
        "the fleet verdict is stated: {text}"
    );
}

/// `bench` WITHOUT --json prints the human table (the release report the
/// capacity gate's baseline is built from).
#[test]
fn bench_prints_the_human_table_without_json() {
    let out = qsv(&["bench", "--iterations", "2"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("ops/s"), "{text}");
    assert!(text.contains("µs/op"), "{text}");
}
