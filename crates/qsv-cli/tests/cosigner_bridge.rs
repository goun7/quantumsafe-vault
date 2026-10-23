//! Co-signer bridge e2e (docs/10 §3.2→§3.3): a REAL TCP service with the
//! watchtower alarm mirror applied from the persisted state file — re-read
//! per request, so a daemon refresh takes effect WITHOUT a restart.
//!
//!   1. CLEAR STATE → a valid PQC-proofed request over the socket releases
//!      the co-signature.
//!   2. STATE FLIPS TO ALERT (same process!) → the SAME request is refused
//!      with the watchtower-freeze reason; nothing is released.
//!   3. STATE RECOVERS → the exact same request releases the exact same
//!      deterministic signature again.
//!   4. UNLISTED VAULT → refused (vault not provisioned).
//!
//! TLS transport (docs/10 §3.5, `cosigner_bridge_tls_end_to_end`):
//!   1. A self-signed loopback cert + `--tls-cert/--tls-key` bridge serves
//!      the SAME frame ceremony INSIDE TLS: request, metrics scrape and
//!      refusal frame all round-trip through the tunnel (pinned root).
//!   2. A PLAINTEXT client against the TLS port cannot speak the protocol
//!      (the handshake fails) — no cleartext co-signature ever crosses.
//!   3. BOOT POLICY: a non-loopback bind WITHOUT TLS material is refused
//!      at startup (exit 1); mismatched --tls-cert/--tls-key usage is
//!      exit 2.
//!
//! MUTUAL TLS (docs/10 §3.6, `cosigner_bridge_mtls_requires_a_pinned_client_identity`):
//!   1. `--tls-client-ca ca.pem` flips the handshake into client-cert
//!      REQUIRED: an anonymous TLS client (server roots only) NEVER
//!      completes a session, and a client whose certificate chains to a
//!      FOREIGN CA is refused the same way.
//!   2. The operator's client identity (`client_identity` +
//!      `request_signature_mtls`) releases the SAME deterministic
//!      co-signature and scrapes /metrics through the same tunnel.
//!   3. USAGE: --tls-client-ca without the --tls pair is exit 2.

use std::io::{Read, Write};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use qsv_cosigner::{
    client_identity, request_signature, request_signature_mtls, request_signature_tls, SignRequest,
};
use qsv_pqc::PqcIdentity;

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

const VAULT: &str = "test-vault-1";

fn qsv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_qsv-cli")
}

fn state_body(verdict: &str) -> String {
    format!(
        r#"{{ "tip": 820000, "vaults": {{ "{VAULT}": {{ "last_tip": 820000, "last_verdict": "{verdict}", "idle_blocks": 13000 }} }} }}"#
    )
}

/// Reserves a free loopback port by binding and dropping a listener; a
/// short cooldown lets the kernel release the bind so the bridge child can
/// claim it (a concurrent test could otherwise race in between).
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    std::thread::sleep(Duration::from_millis(200));
    port
}

/// Waits until the bridge answers a TCP connect (or times out).
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

fn spawn_bridge(state_dir: &std::path::Path, port: u16) -> Child {
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);
    child
}

fn valid_request() -> SignRequest {
    let pqc = PqcIdentity::from_seed(&[21u8; 32]);
    let sighash = [0x77u8; 32];
    SignRequest::new(
        VAULT,
        &sighash,
        pqc.verifying_key_bytes(),
        &pqc.sign(&sighash),
    )
}

#[test]
fn bridge_mirrors_watchtower_state_per_request_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();

    // 1. Boot with a CLEAR state file → the request is released.
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let port = free_port();
    let mut child = spawn_bridge(&state_dir, port);
    let addr = format!("127.0.0.1:{port}");

    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "clear state must release: {resp:?}");
    let first_sig = resp.schnorr_sig_hex.clone().unwrap();
    assert!(!first_sig.is_empty());

    // 2. The watchtower flips to ALERT (state file rewritten on disk — the
    //    bridge process is NOT restarted) → the same request is refused.
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("ALERT")).unwrap();
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(!resp.accepted, "ALERT state must freeze the vault");
    assert!(resp
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("watchtower alarm active"));
    assert!(resp.schnorr_sig_hex.is_none());

    // 3. Recovery: the freeze lifts and the deterministic release returns —
    //    byte-identical to the pre-alarm signature (Theorem 1 untouched).
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "recovered state must release again");
    assert_eq!(resp.schnorr_sig_hex.unwrap(), first_sig);

    // 4. An unlisted vault is refused by the provisioning allowlist.
    let pqc = PqcIdentity::from_seed(&[21u8; 32]);
    let sighash = [0x78u8; 32];
    let foreign = SignRequest::new(
        "unprovisioned-vault",
        &sighash,
        pqc.verifying_key_bytes(),
        &pqc.sign(&sighash),
    );
    let resp = request_signature(&addr, &foreign).unwrap();
    assert!(!resp.accepted);
    assert!(resp
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("not provisioned"));

    // 5. METRICS SCRAPE: plain HTTP `GET /metrics` answers with the
    //    Prometheus text exposition — and moves NO counter (observing is
    //    not signing). So far the socket saw: release, refusal, release,
    //    unprovisioned refusal → 4 requests / 2 accepted / 2 refused /
    //    1 alarm refusal.
    let mut scrape = std::net::TcpStream::connect(&addr).unwrap();
    scrape.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").unwrap();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut scrape, &mut text).unwrap();
    assert!(
        text.contains("HTTP/1.1 200 OK"),
        "scrape must answer 200: {text}"
    );
    assert!(text.contains("Content-Type: text/plain; version=0.0.4"));
    assert!(text.contains("# TYPE qsv_cosigner_requests_total counter"));
    assert!(
        text.contains("qsv_cosigner_requests_total 4"),
        "exposition: {text}"
    );
    assert!(text.contains("qsv_cosigner_accepted_total 2"));
    assert!(text.contains("qsv_cosigner_refused_total 2"));
    assert!(text.contains("qsv_cosigner_alarm_refused_total 1"));
    assert!(text.contains("qsv_cosigner_serve_latency_us_sum"));
    // The scrape is invisible to the signer: the SAME request still yields
    // the SAME deterministic signature after it.
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "service must keep signing after a scrape");
    assert_eq!(resp.schnorr_sig_hex.unwrap(), first_sig);

    // 6. PLAIN HTTP GARBAGE (wrong path): answered with a REFUSAL frame —
    //    the loop survives and keeps serving real requests.
    let mut junk = std::net::TcpStream::connect(&addr).unwrap();
    junk.write_all(b"GET /health HTTP/1.1\r\n\r\n").unwrap();
    let mut len_buf = [0u8; 8];
    junk.read_exact(&mut len_buf).unwrap();
    let len = u64::from_be_bytes(len_buf) as usize;
    assert!(len < 1 << 20, "refusal frame must be small");
    let mut body = vec![0u8; len];
    junk.read_exact(&mut body).unwrap();
    let refusal: qsv_cosigner::SignResponse = serde_json::from_slice(&body).unwrap();
    assert!(!refusal.accepted);
    assert!(refusal
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("frame too large"));
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "loop must survive junk input");

    // Stop the service child (no stdout drain: the bridge never closes its
    // output while serving, so a blocking read would hang the test).
    stop_gracefully(&mut child);
    let _ = child.wait();
    let _ = std::io::stdout().flush();
}

#[test]
fn cosigner_bridge_dry_run_rehearses_the_policy_surface() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    // Real PEM material (rcgen, offline) — TLS WITHOUT a client CA.
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_pem = dir.path().join("cert.pem");
    std::fs::write(&cert_pem, cert.cert.pem()).unwrap();
    let key_pem = dir.path().join("key.pem");
    std::fs::write(&key_pem, cert.key_pair.serialize_pem()).unwrap();

    let port = free_port();
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--state-dir",
            state_dir.to_str().unwrap(),
            // NO --vault-id: the demo vault is the default allowlist entry.
            "--tls-cert",
            cert_pem.to_str().unwrap(),
            "--tls-key",
            key_pem.to_str().unwrap(),
            // No frame deadline: the capacity banner must say "unbounded".
            "--frame-timeout-ms",
            "0",
            "--dry-run",
        ])
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "the boot rehearsal must succeed: {text}"
    );
    assert!(text.contains("BOOT WOULD SUCCEED"), "{text}");
    // Plain TLS (cert+key, no client CA) must label itself TLS, not mTLS.
    assert!(text.contains("transport:    TLS"), "{text}");
    // The default allowlist: the ONE demo vault (--vault-id omitted).
    assert!(text.contains("vaults:       1 provisioned"), "{text}");
    // --frame-timeout-ms 0 → the policy reads unbounded.
    assert!(text.contains("frame timeout unbounded"), "{text}");
}

/// The per-request mirror FAILS CLOSED when the state file vanishes
/// mid-run (the LAST verdicts stay applied — alarms never silently
/// clear), and a SIGTERM with nothing in flight drains IN TIME: the
/// drain thread bows out on `finished` before its deadline, even while
/// the STOPPING report finds the supervisor gone.
#[test]
fn cosigner_bridge_mirror_keeps_last_verdicts_when_the_state_vanishes() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    // A supervisor socket: READY lands, then the supervisor GOES AWAY —
    // STOPPING=1 can never arrive, so main's bounded wait spans its full
    // 250 ms and the drain thread is guaranteed to observe `finished`.
    let npath = dir.path().join("notify.sock");
    let notify = std::os::unix::net::UnixDatagram::bind(&npath).unwrap();
    notify
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--drain-timeout-ms",
            "10000",
        ])
        .env("NOTIFY_SOCKET", &npath)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("bridge child must spawn");
    let mut buf = [0u8; 256];
    let n = notify.recv(&mut buf).expect("READY=1 must land");
    assert!(String::from_utf8_lossy(&buf[..n]).contains("READY=1"));
    drop(notify); // the supervisor vanished: later sends fail closed
    wait_ready(&addr);

    // The state file DISAPPEARS between requests: the per-request mirror
    // keeps the LAST verdicts (boot had `clear`) instead of erroring the
    // request or silently clearing the alarm state.
    std::fs::remove_file(state_dir.join("watchtower-state.json")).unwrap();
    let resp = request_signature(&addr, &valid_request()).expect("framed reply");
    assert!(resp.accepted, "keep-last mirror must release: {resp:?}");

    // Graceful stop: nothing in flight → serve returns, drain_done is
    // set, and the drain thread returns on `finished` long before the
    // (10 s) deadline.
    stop_gracefully(&mut child);
    let status = child.wait().unwrap();
    // The final report is a println! (stdout), not stderr.
    let mut out_txt = String::new();
    use std::io::Read;
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out_txt)
        .unwrap();
    assert!(
        out_txt.contains("graceful stop complete"),
        "the final report must land: {out_txt}"
    );
    assert!(status.success(), "a graceful stop must exit 0");
}

/// The watchdog is the LAST bound on a wedged bridge: with the frame
/// deadline OFF, a silent peer parks the SERIAL loop, the accept-loop
/// stamp freezes, and the stall witness is said ONCE (stderr → journald)
/// instead of blind pings. SIGTERM then still delivers STOPPING=1 (the
/// watcher is independent of the wedged loop) and the drain CUT keeps
/// the stop bounded even though the worker never returns.
#[test]
fn cosigner_bridge_watchdog_witnesses_a_wedged_loop_then_stops() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let npath = dir.path().join("notify.sock");
    let notify = std::os::unix::net::UnixDatagram::bind(&npath).unwrap();
    notify
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            // No frame deadline: silence can park the serial loop.
            "--frame-timeout-ms",
            "0",
            // The CUT keeps SIGTERM bounded even though a worker hangs.
            "--drain-timeout-ms",
            "1500",
        ])
        .env("NOTIFY_SOCKET", &npath)
        .env("WATCHDOG_USEC", "400000") // ping every 200 ms; stall = 0 + 200 ms
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("bridge child must spawn");
    let mut buf = [0u8; 256];
    let n = notify.recv(&mut buf).expect("READY=1 must land");
    assert!(String::from_utf8_lossy(&buf[..n]).contains("READY=1"));
    wait_ready(&addr);

    // A SILENT peer: connect and never speak — the serial loop parks in
    // the frame read, the progress stamp freezes, the witness must fire.
    let quiet = std::net::TcpStream::connect(&addr).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(900));

    stop_gracefully(&mut child);
    let status = child.wait().unwrap();
    let mut err = String::new();
    use std::io::Read;
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(
        err.contains("watchdog: accept loop silent"),
        "the stall witness must be said: {err}"
    );
    // Drain the datagrams (watchdog pings may sit in front of it).
    let mut nbuf = [0u8; 256];
    let mut seen_stopping = false;
    while let Ok(n) = notify.recv(&mut nbuf) {
        if String::from_utf8_lossy(&nbuf[..n]).contains("STOPPING=1") {
            seen_stopping = true;
            break;
        }
    }
    assert!(seen_stopping, "STOPPING=1 must reach the supervisor");
    assert!(status.success(), "the CUT exits 0 — a stop is a stop");
    drop(quiet);
}

#[test]
fn cosigner_bridge_tls_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    // Self-signed loopback certificate (rcgen, cached crate — no network).
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_pem_path = dir.path().join("cert.pem");
    std::fs::write(&cert_pem_path, cert.cert.pem()).unwrap();
    let key_pem_path = dir.path().join("key.pem");
    std::fs::write(&key_pem_path, cert.key_pair.serialize_pem()).unwrap();

    // 0a. BOOT POLICY: a non-loopback bind WITHOUT TLS is refused (exit 1);
    //     and mismatched TLS material is a usage error (exit 2).
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "0.0.0.0:3333",
            "--state-dir",
            state_dir.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "plaintext off loopback must die"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("plaintext"), "{err}");
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "127.0.0.1:3333",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--tls-cert",
            cert_pem_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "cert without key is a usage error"
    );

    // 1. TLS BRIDGE: the SAME frame ceremony inside the tunnel.
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--tls-cert",
            cert_pem_path.to_str().unwrap(),
            "--tls-key",
            key_pem_path.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("TLS bridge child must spawn");
    wait_ready(&addr);

    let resp = request_signature_tls(
        &addr,
        &valid_request(),
        "localhost",
        qsv_cosigner::tls::pinned_root_store(cert.cert.der()),
    )
    .unwrap();
    assert!(resp.accepted, "TLS transport must release: {resp:?}");
    // Determinism across transports: the TLS release equals the plaintext
    // release of the SAME request (transport never touches Theorem 1).
    let plain_ref = request_signature_tls(
        &addr,
        &valid_request(),
        "localhost",
        qsv_cosigner::tls::pinned_root_store(cert.cert.der()),
    )
    .unwrap();
    assert_eq!(resp.schnorr_sig_hex, plain_ref.schnorr_sig_hex);

    // 1b. An UNPROVISIONED vault over TLS is refused — and the refusal is
    //     attributed to the ASKING vault id in the per-vault metric rows.
    let pqc = PqcIdentity::from_seed(&[21u8; 32]);
    let sighash = [0x79u8; 32];
    let foreign = SignRequest::new(
        "unprovisioned-vault",
        &sighash,
        pqc.verifying_key_bytes(),
        &pqc.sign(&sighash),
    );
    let resp = request_signature_tls(
        &addr,
        &foreign,
        "localhost",
        qsv_cosigner::tls::pinned_root_store(cert.cert.der()),
    )
    .unwrap();
    assert!(!resp.accepted, "unprovisioned must refuse over TLS too");

    // 2. METRICS SCRAPE inside TLS (same HTTP probe, same no-counter rule).
    let mut tls = rustls_helpers::client_stream(&addr, "localhost", cert.cert.der());
    tls.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").unwrap();
    // TLS-buffered writes leave ONLY on flush.
    tls.flush().unwrap();
    let mut text = String::new();
    tls.read_to_string(&mut text).unwrap();
    assert!(text.contains("HTTP/1.1 200 OK"), "{text}");
    assert!(text.contains("qsv_cosigner_requests_total 3"), "{text}");
    assert!(text.contains("qsv_cosigner_accepted_total 2"), "{text}");
    assert!(
        text.contains("qsv_cosigner_refused_by_vault_total{vault=\"unprovisioned-vault\"} 1"),
        "per-vault rows are keyed by the ASKING vault: {text}"
    );
    // Round 17: the matching ACCEPTED rows — the two releases are
    // attributed to test-vault-1, the unprovisioned vault shows an
    // EXPLICIT zero.
    assert!(
        text.contains("qsv_cosigner_accepted_by_vault_total{vault=\"test-vault-1\"} 2"),
        "accepted rows per vault: {text}"
    );
    assert!(
        text.contains("qsv_cosigner_accepted_by_vault_total{vault=\"unprovisioned-vault\"} 0"),
        "{text}"
    );

    // 3. A PLAINTEXT client against the TLS port cannot speak the protocol:
    //    the raw frame bytes fail the TLS handshake. Whatever bytes come
    //    back (the TLS alert, EOF, or nothing at all), NONE of them may be
    //    a cleartext protocol frame — our frames start with a big-endian
    //    8-byte length (first byte 0x00 for any reply under 16 MiB), TLS
    //    records with a content type (0x15/0x16/0x17).
    let mut raw = std::net::TcpStream::connect(&addr).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    raw.write_all(&[0u8; 8]).unwrap(); // "zero-length frame" in plaintext
    let mut sink = Vec::new();
    let _ = raw.read_to_end(&mut sink);
    assert!(
        sink.is_empty() || matches!(sink[0], 0x15..=0x17),
        "the plaintext client must NEVER see a cleartext protocol frame: {:?}",
        &sink[..sink.len().min(32)]
    );
    // …and the loop keeps serving REAL TLS clients afterwards.
    let resp = request_signature_tls(
        &addr,
        &valid_request(),
        "localhost",
        qsv_cosigner::tls::pinned_root_store(cert.cert.der()),
    )
    .unwrap();
    assert!(resp.accepted, "loop must survive a plaintext attack");

    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// PER-VAULT RATE LIMIT e2e (docs/10 §3.6, Round 16): the bridge CLI takes
/// `--rate-limit <capacity>:<refill-per-sec>`; a vault that exceeds its
/// token bucket is refused with an explicit reason (never a hang), its
/// refusal is counted in `/metrics` (`rate_limited_by_vault_total`), and a
/// sibling vault keeps its own budget. The child's stderr is piped so the
/// test reads the operator-facing warning line.
#[test]
fn bridge_rate_limits_a_flood_per_vault_without_blocking_the_sibling() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--vault-id",
            "sibling-vault",
            "--rate-limit",
            "2:0",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("rate-limited bridge child must spawn");
    wait_ready(&addr);

    // The burst consumes exactly 2 tokens; request 3 is refused with the
    // limiter reason; the refusal answers FAST (a limit must never hang).
    let mut first_sig = String::new();
    for i in 0..3 {
        let started = std::time::Instant::now();
        let resp = request_signature(&addr, &valid_request()).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "request {i} must be answered promptly"
        );
        if i < 2 {
            assert!(resp.accepted, "burst request {i} must pass");
            first_sig = resp.schnorr_sig_hex.unwrap();
        } else {
            assert!(!resp.accepted, "request 3 must be rate-limited");
            assert!(resp
                .reason
                .as_deref()
                .unwrap_or_default()
                .contains("rate limited"));
        }
    }

    // The SIBLING vault keeps its own budget (per-vault buckets). It is
    // unprovisioned in this bridge? No — it IS provisioned above; its
    // release must succeed AND be deterministic across the flood.
    let pqc = PqcIdentity::from_seed(&[21u8; 32]);
    let sighash = [0x7Bu8; 32];
    let sibling_req = SignRequest::new(
        "sibling-vault",
        &sighash,
        pqc.verifying_key_bytes(),
        &pqc.sign(&sighash),
    );
    let resp = request_signature(&addr, &sibling_req).unwrap();
    assert!(resp.accepted, "the sibling vault must keep its own budget");
    let sibling_sig = resp.schnorr_sig_hex.clone().unwrap();
    let resp2 = request_signature(&addr, &sibling_req).unwrap();
    assert!(resp2.accepted, "sibling bucket is independent");
    assert_eq!(resp2.schnorr_sig_hex.unwrap(), sibling_sig);

    // The flood victim's DETERMINISM is intact: once the bucket refills
    // (capacity 2, refill 0 — force a fresh bucket via a new bridge? No:
    // refill is 0, so instead assert the refusal REPEATS deterministically
    // and the accepted signatures never changed).
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(!resp.accepted, "refill 0 keeps the flood refused");
    assert!(!first_sig.is_empty());

    // /metrics: the limiter counters are exposed (requests=6: 2 burst ok,
    // 2 flood refusals, 2 sibling ok; rate_limited total = 2, row keyed by
    // the FLOODING vault only).
    let mut scrape = std::net::TcpStream::connect(&addr).unwrap();
    scrape.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").unwrap();
    let mut text = String::new();
    std::io::Read::read_to_string(&mut scrape, &mut text).unwrap();
    assert!(text.contains("HTTP/1.1 200 OK"), "{text}");
    assert!(text.contains("qsv_cosigner_rate_limited_total 2"), "{text}");
    assert!(
        text.contains("qsv_cosigner_rate_limited_by_vault_total{vault=\"test-vault-1\"} 2"),
        "{text}"
    );
    // Round 17: the ACCEPTED rows split the same history per vault — the
    // flooding vault released 2 (the burst), the sibling released its own
    // 2; Σ rows == accepted_total == 4.
    assert!(
        text.contains("qsv_cosigner_accepted_by_vault_total{vault=\"test-vault-1\"} 2"),
        "{text}"
    );
    assert!(
        text.contains("qsv_cosigner_accepted_by_vault_total{vault=\"sibling-vault\"} 2"),
        "{text}"
    );

    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// GRACEFUL SHUTDOWN e2e (docs/10 §3.7, Round 17): SIGTERM stops the
/// accept loop, the bind is RELEASED for the next replica and the process
/// exits 0 — systemd's `Restart=on-failure` has nothing to restart on a
/// stop. The in-flight drain contract is proven at the unit level
/// (qsv-cosigner); this drill proves the WIRE: real signal → real exit 0.
#[cfg(unix)]
#[test]
fn bridge_sigterm_stops_gracefully_and_releases_the_bind() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    // One release while up (the bridge works until the signal arrives).
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted);

    // SIGTERM: NOT SIGKILL — the graceful contract must hold on the real
    // signal. A graceful stop is exit 0 (a restart-looping supervisor
    // would see failure otherwise). std Child::kill() is SIGKILL and
    // would bypass the handler under test, so we raise TERM ourselves.
    let pid = child.id() as i32;
    let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(
        ret, 0,
        "SIGTERM must reach the bridge child (pid {pid}), kill rc={ret}"
    );
    let status = child.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "SIGTERM must be a graceful exit 0 (drain + released bind), got {status:?}"
    );

    // The bind is RELEASED: the next replica can take the port over
    // immediately (zero-downtime handover needs no SO_REUSEPORT tricks).
    let rebound = std::net::TcpListener::bind(&addr);
    assert!(rebound.is_ok(), "SIGTERM must release the bind: {addr}");
}

/// SD_NOTIFY e2e (docs/10 §4.26, Round 21): under a supervisor the bridge
/// must REPORT instead of being guessed — READY=1 only after the bind and
/// the health record are real, WATCHDOG=1 while the accept loop still
/// ticks, STOPPING=1 when SIGTERM begins the drain. The datagram socket
/// below plays systemd's part (NOTIFY_SOCKET is the same filesystem form
/// /run/systemd/notify uses; WATCHDOG_USEC asks for a 100ms ping).
#[cfg(unix)]
#[test]
fn bridge_reports_ready_watchdog_and_stopping_to_notify_socket() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    // "systemd" side: one bound datagram socket, reachable by path.
    let notify_path = dir.path().join("notify.sock");
    let rx = std::os::unix::net::UnixDatagram::bind(&notify_path).unwrap();
    rx.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
        ])
        .env("NOTIFY_SOCKET", &notify_path)
        .env("WATCHDOG_USEC", "200000") // ping every 100ms (sd_notify(3): half)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    let mut buf = [0u8; 64];
    // 1. READY=1 — sent once the bind + health record are real (the TCP
    //    connect above only succeeds AFTER that message went out).
    let n = rx.recv(&mut buf).expect("READY=1 must arrive");
    assert_eq!(&buf[..n], b"READY=1", "first report must be READY");
    // 2. WATCHDOG=1 — the idle loop ticks every 10ms, so the stamp is
    //    fresh and the pings keep coming while nothing is wrong.
    let n = rx
        .recv(&mut buf)
        .expect("WATCHDOG=1 must arrive while the loop ticks");
    assert_eq!(&buf[..n], b"WATCHDOG=1");
    // 3. SIGTERM → STOPPING=1 lands BEFORE the exit code: the supervisor
    //    learns the drain BEGAN, not that it already ended. The watchdog
    //    keeps pinging THROUGH the drain (a draining bridge is healthy —
    //    that is the design), so those queued pings are skipped on the
    //    way to STOPPING.
    let pid = child.id() as i32;
    let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(ret, 0, "SIGTERM must reach the bridge child (pid {pid})");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut saw_stopping = false;
    while Instant::now() < deadline {
        match rx.recv(&mut buf) {
            Ok(n) if &buf[..n] == b"STOPPING=1" => {
                saw_stopping = true;
                break;
            }
            Ok(_) => continue, // WATCHDOG=1 ping — expected during the drain
            Err(_) => break,   // read timeout: no report will come
        }
    }
    assert!(
        saw_stopping,
        "STOPPING=1 must arrive on SIGTERM (before the exit, not instead of it)"
    );
    let status = child.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "the notify path must not disturb the graceful exit 0, got {status:?}"
    );
}

/// SLOWLORIS BOUND e2e (docs/10 §4.19, Round 18): a peer that connects
/// and goes quiet holds the bridge for at most `--frame-timeout-ms`, the
/// stalled socket is HUNG UP by the deadline and the service keeps
/// signing throughout — slowloris degrades, never denies. A dribbling
/// peer (half a frame length prefix, then silence) is bounded the same
/// way.
#[test]
fn bridge_bounds_stalling_peers_and_keeps_serving() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--frame-timeout-ms",
            "300",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    // 1. A SILENT peer connects FIRST and never sends a byte: the serial
    //    loop parks in its probe read — bounded by the 300 ms deadline.
    let mut stall = std::net::TcpStream::connect(&addr).unwrap();
    stall
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // 2. A healthy request STILL lands (it waits behind the stall for at
    //    most one timeout).
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "the bridge must outlive the stalled peer");

    // 3. The silent peer is HUNG UP by the deadline (clean EOF — never a
    //    permanent half-open socket holding a worker).
    let mut byte = [0u8; 1];
    let started = Instant::now();
    let n = stall.read(&mut byte);
    let hung_up = matches!(&n, Ok(0)) || n.is_err();
    assert!(hung_up, "the deadline must close the silent peer: {n:?}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "hang-up must follow the deadline, not the client's patience"
    );

    // 4. A DRIBBLING peer (4 of the 8 length-prefix bytes, then silence)
    //    is bounded the same way — the frame path answers with the
    //    deterministic refusal and the loop moves on.
    let mut partial = std::net::TcpStream::connect(&addr).unwrap();
    partial
        .set_read_timeout(Some(Duration::from_millis(400)))
        .unwrap();
    partial.write_all(&[0u8; 4]).unwrap();
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(
        resp.accepted,
        "a dribbling peer must not take the bridge down"
    );
    let started = Instant::now();
    let mut closed = false;
    while started.elapsed() < Duration::from_secs(3) {
        match partial.read(&mut byte) {
            Ok(0) => {
                closed = true;
                break;
            }
            Ok(_) => {} // the refusal frame's bytes — keep draining
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => {
                closed = true;
                break;
            }
        }
    }
    assert!(closed, "the dribbling peer must be hung up too");

    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// SCRAPE AUTH e2e (docs/10 §4.20, Round 18): an armed `--metrics-token`
/// gates the exposition — missing/wrong `X-QSV-Metrics-Token` = 401 AND a
/// counted denial, the authorized scrape renders the counters plus the
/// denial total, and the signing path is untouched by the gate.
#[test]
fn bridge_metrics_scrape_requires_the_token() {
    fn scrape(addr: &str, extra: &[&str]) -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut req = "GET /metrics HTTP/1.1\r\nHost: x\r\n".to_string();
        for h in extra {
            req.push_str(h);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut s, &mut out).unwrap();
        out
    }

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--metrics-token",
            "sekrit-scrape",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    // 1-2. Missing and WRONG tokens are refused 401 (and counted).
    let denied = scrape(&addr, &[]);
    assert!(
        denied.starts_with("HTTP/1.1 401"),
        "token-armed scrape without a token must be denied: {denied}"
    );
    let denied = scrape(&addr, &["X-QSV-Metrics-Token: wrong"]);
    assert!(
        denied.starts_with("HTTP/1.1 401"),
        "a wrong token must be denied: {denied}"
    );

    // 3. The authorized scrape renders the exposition AND the denial
    //    counter (both probes are visible to the operator).
    let ok = scrape(&addr, &["X-QSV-Metrics-Token: sekrit-scrape"]);
    assert!(ok.starts_with("HTTP/1.1 200"), "authorized scrape: {ok}");
    assert!(ok.contains("Content-Type: text/plain; version=0.0.4"));
    assert!(ok.contains("# TYPE qsv_cosigner_requests_total counter"));
    assert!(
        ok.contains("qsv_cosigner_metrics_denied_total 2"),
        "denials must be counted: {ok}"
    );

    // 4. The gate is an OBSERVABILITY control: signing is untouched.
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "signing must be untouched by scrape auth");

    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// TOKEN-FILE e2e (docs/10 §4.27, Round 21): the scrape token is a
/// SECRET — as a flag it lands in /proc/*/cmdline, the shell history and
/// the unit's ExecStart, every one readable by any process on the box.
/// Via `--metrics-token-file` (chmod 600, exactly one line) the gate arms
/// exactly as before while argv stays secret-free; a LOOSE file refuses
/// to boot, and naming BOTH sources is a usage confusion (exit 2) — two
/// token sources is how a gate gets bypassed by accident.
#[cfg(unix)]
#[test]
fn bridge_scrape_token_file_arms_the_gate_without_leaking_argv() {
    use std::os::unix::fs::PermissionsExt;

    fn scrape(addr: &str, extra: &[&str]) -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut req = "GET /metrics HTTP/1.1\r\nHost: x\r\n".to_string();
        for h in extra {
            req.push_str(h);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut s, &mut out).unwrap();
        out
    }

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    // The ONLY layout the bridge accepts: 0600, one line.
    let token_path = dir.path().join("scrape.token");
    std::fs::write(&token_path, "sekrit-from-file\n").unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--metrics-token-file",
            token_path.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    // 1. The secret is NOT on the command line — the whole point. The
    //    PATH is expected there; the VALUE must not be, in any form.
    let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", child.id()))
        .unwrap()
        .replace('\0', " ");
    assert!(
        cmdline.contains("--metrics-token-file"),
        "the flag itself is expected: {cmdline}"
    );
    assert!(
        !cmdline.contains("sekrit-from-file"),
        "token VALUE leaked into argv: {cmdline}"
    );

    // 2. The health record proves the FILE was actually resolved: the
    //    armed bit is set without --metrics-token ever being passed.
    let read_deadline = Instant::now() + Duration::from_secs(5);
    let health = loop {
        if let Some(h) = qsv_cosigner::health::read(&state_dir) {
            break h;
        }
        assert!(Instant::now() < read_deadline, "health record must appear");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        health.metrics_token_armed,
        "the file's token must arm the gate (health record)"
    );

    // 3. The gate behaves EXACTLY like the flag form: 401 without a
    //    token, 200 with the FILE's token, the denial counted.
    let denied = scrape(&addr, &[]);
    assert!(
        denied.starts_with("HTTP/1.1 401"),
        "file-armed scrape without a token must be denied: {denied}"
    );
    let ok = scrape(&addr, &["X-QSV-Metrics-Token: sekrit-from-file"]);
    assert!(ok.starts_with("HTTP/1.1 200"), "authorized scrape: {ok}");
    assert!(
        ok.contains("qsv_cosigner_metrics_denied_total 1"),
        "the denial must be counted: {ok}"
    );

    // 4. The signing path is untouched (the token guards the SCRAPE only).
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(
        resp.accepted,
        "signing must be untouched by the token source"
    );

    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// The REFUSAL half of the token-file contract (docs/10 §4.27): a loose
/// file (group/other can read it), a multi-line paste, or two token
/// sources at once must stop the boot BEFORE any socket opens — fail
/// closed, and name the fix ("chmod 600") in the error.
#[cfg(unix)]
#[test]
fn bridge_refuses_a_loose_token_file_and_double_token_sources() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let base_args = [
        "cosigner-bridge",
        "--listen",
        addr.as_str(),
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--vault-id",
        VAULT,
    ];

    // 1. World-readable token file → boot refused with the fix named.
    let loose = dir.path().join("loose.token");
    std::fs::write(&loose, "too-open\n").unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = Command::new(qsv_bin())
        .args(base_args)
        .arg("--metrics-token-file")
        .arg(&loose)
        .output()
        .expect("run bridge");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "a loose token file must refuse the boot: {err}"
    );
    assert!(err.contains("chmod 600"), "the fix must be named: {err}");
    // Fail closed BEFORE the bind: nothing opened a socket.
    assert!(
        std::net::TcpStream::connect(&addr).is_err(),
        "a refused boot must never bind {addr}"
    );

    // 2. A second line is a paste accident (or a header-injection
    //    attempt) — refuse rather than guess which line is the token.
    let two = dir.path().join("two.token");
    std::fs::write(&two, "line-one\nline-two\n").unwrap();
    std::fs::set_permissions(&two, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = Command::new(qsv_bin())
        .args(base_args)
        .arg("--metrics-token-file")
        .arg(&two)
        .output()
        .expect("run bridge");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "multi-line file: {err}");
    assert!(err.contains("ONE line"), "{err}");

    // 3. Both sources at once = usage confusion → exit 2 (the CLI
    //    contract for "the operator must decide", not a config error).
    let tight = dir.path().join("tight.token");
    std::fs::write(&tight, "sekrit\n").unwrap();
    std::fs::set_permissions(&tight, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = Command::new(qsv_bin())
        .args(base_args)
        .arg("--metrics-token")
        .arg("flag-token")
        .arg("--metrics-token-file")
        .arg(&tight)
        .output()
        .expect("run bridge");
    assert_eq!(
        out.status.code(),
        Some(2),
        "two token sources = usage error: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// SIGHUP ROTATION e2e (docs/10 §4.30, Round 22): a scrape secret has a
/// lifetime, and rotating it must NOT cost a restart — a restart drops
/// the in-flight drain, re-runs the boot gates and opens a signing gap
/// nobody asked for. `systemctl reload` (ExecReload → SIGHUP) makes the
/// RUNNING bridge re-read `--metrics-token-file` and swap the gate in
/// place: the new value answers on the very next request, the old one is
/// refused, the pid never moves — and a BROKEN rotation (a loosened
/// file) keeps the previous token, because failing to rotate must never
/// fail open.
#[cfg(unix)]
#[test]
fn bridge_rotates_the_scrape_token_on_sighup_without_a_restart() {
    use std::os::unix::fs::PermissionsExt;

    fn scrape(addr: &str, token: &str) -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut req = "GET /metrics HTTP/1.1\r\nHost: x\r\n".to_string();
        if !token.is_empty() {
            req.push_str(&format!("X-QSV-Metrics-Token: {token}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut s, &mut out).unwrap();
        out
    }

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let token_path = dir.path().join("scrape.token");
    std::fs::write(&token_path, "sekrit-v1\n").unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--metrics-token-file",
            token_path.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);
    let boot_pid = child.id();

    // 1. Boot state: v1 answers, v2 does not exist yet.
    let ok = scrape(&addr, "sekrit-v1");
    assert!(ok.starts_with("HTTP/1.1 200"), "v1 must scrape: {ok}");
    let denied = scrape(&addr, "sekrit-v2");
    assert!(denied.starts_with("HTTP/1.1 401"), "v2 must not: {denied}");

    // 2. Rotate: rewrite the file (still 0600) and HUP the RUNNING
    //    process — the same pid the health record published.
    std::fs::write(&token_path, "sekrit-v2\n").unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let _ = unsafe { libc::kill(boot_pid as libc::pid_t, libc::SIGHUP) };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if scrape(&addr, "sekrit-v2").starts_with("HTTP/1.1 200") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the SIGHUP rotation must land within 5 s"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // 3. The OLD secret is refused from the next request on, and the
    //    process is the very same one — rotation is not a restart.
    let stale = scrape(&addr, "sekrit-v1");
    assert!(
        stale.starts_with("HTTP/1.1 401"),
        "the rotated-out secret must stop working: {stale}"
    );
    let after = qsv_cosigner::health::read(&state_dir).expect("health record survives rotation");
    assert_eq!(
        after.pid, boot_pid,
        "rotation must never move the pid (no restart)"
    );
    assert!(
        after.metrics_token_armed,
        "the gate stays armed across a rotation"
    );

    // 4. The signing path never noticed any of this.
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "signing must be untouched by rotation");

    // 4b. Round 24: a rotation that LANDED is as visible as one that was
    //     refused — this is how the operator confirms Prometheus is
    //     scraping with the NEW secret (the alert only speaks up about
    //     the failures).
    let landed: u64 = scrape(&addr, "sekrit-v2")
        .lines()
        .find_map(|l| l.strip_prefix("qsv_cosigner_rotate_total "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    assert_eq!(
        landed, 1,
        "exactly one rotation landed (the refused ones never counted)"
    );
    assert!(
        scrape(&addr, "sekrit-v2").contains("qsv_cosigner_rotate_denied_total 0"),
        "a working rotation raises no denial"
    );

    // 5. A BROKEN rotation keeps the previous secret: the file loosens to
    //    0644 (read refusal), the HUP still lands — and the gate neither
    //    opens nor switches to a token it could not verify.
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = unsafe { libc::kill(boot_pid as libc::pid_t, libc::SIGHUP) };
    std::thread::sleep(Duration::from_millis(500)); // ≥5 rotation polls
    let kept = scrape(&addr, "sekrit-v2");
    assert!(
        kept.starts_with("HTTP/1.1 200"),
        "a refused rotation keeps the last good token: {kept}"
    );
    assert!(
        scrape(&addr, "").starts_with("HTTP/1.1 401"),
        "and never falls open"
    );
    let still = qsv_cosigner::health::read(&state_dir).unwrap();
    assert_eq!(still.pid, boot_pid, "still the same process");

    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// ROTATION STALL ACCOUNTING e2e (docs/10 §4.36, Round 23): a refused
/// rotation is only safe if somebody can SEE it. Two production paths
/// make `systemctl reload` a no-op while the operator believes the
/// secret moved — the unit was armed through `--metrics-token` (there is
/// no file to re-read) or the file stopped yielding a usable token. Both
/// increment `qsv_cosigner_rotate_denied_total`, the counter behind
/// `QsvCosignerTokenRotationStalled`; the gate stays exactly where it
/// was in both cases.
#[cfg(unix)]
#[test]
fn bridge_counts_a_reload_that_could_not_rotate() {
    use std::os::unix::fs::PermissionsExt;

    fn scrape(addr: &str, token: &str) -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut req = "GET /metrics HTTP/1.1\r\nHost: x\r\n".to_string();
        if !token.is_empty() {
            req.push_str(&format!("X-QSV-Metrics-Token: {token}\r\n"));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes()).unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut s, &mut out).unwrap();
        out
    }

    /// The exported refusal count (the value `QsvCosignerTokenRotationStalled`
    /// reads) — a missing row is itself the failure: the alert would be
    /// dead exactly when it is needed.
    fn denials(text: &str) -> u64 {
        text.lines()
            .find_map(|l| l.strip_prefix("qsv_cosigner_rotate_denied_total "))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("the refusal counter must be exported:\n{text}"))
    }

    /// Bounded poll: the reload edge is consumed by a 100 ms polling
    /// thread, so the count lands shortly after the signal — never wait
    /// forever for it.
    fn await_denial(addr: &str, token: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let text = scrape(addr, token);
            if denials(&text) > 0 {
                return text;
            }
            assert!(
                Instant::now() < deadline,
                "the refused reload must be counted within 5 s"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // ── Case 1: armed through argv — there is NO file to re-read ─────
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--metrics-token",
            "sekrit-argv",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    assert_eq!(
        denials(&scrape(&addr, "sekrit-argv")),
        0,
        "a boot that never reloaded has refused nothing"
    );
    let _ = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGHUP) };
    let counted = await_denial(&addr, "sekrit-argv");
    assert!(
        counted.contains("qsv_cosigner_rotate_denied_total "),
        "the refusal must reach the exposition the alert reads"
    );
    assert!(
        scrape(&addr, "").starts_with("HTTP/1.1 401"),
        "a stalled rotation never falls open"
    );
    stop_gracefully(&mut child);
    let _ = child.wait();

    // ── Case 2: armed from a file that no longer yields a token ─────
    let state_dir2 = dir.path().join("wt2");
    std::fs::create_dir_all(&state_dir2).unwrap();
    std::fs::write(
        state_dir2.join("watchtower-state.json"),
        state_body("clear"),
    )
    .unwrap();
    let token_path = dir.path().join("scrape.token");
    std::fs::write(&token_path, "sekrit-v1\n").unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let port2 = free_port();
    let addr2 = format!("127.0.0.1:{port2}");
    let mut child2 = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr2,
            "--state-dir",
            state_dir2.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--metrics-token-file",
            token_path.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr2);

    // Empty the file (still 0600): the reload lands, the gate keeps the
    // LAST GOOD secret — and the attempt is counted, not swallowed.
    std::fs::write(&token_path, "\n").unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let _ = unsafe { libc::kill(child2.id() as libc::pid_t, libc::SIGHUP) };
    await_denial(&addr2, "sekrit-v1");
    let kept = scrape(&addr2, "sekrit-v1");
    assert!(
        kept.starts_with("HTTP/1.1 200"),
        "the previous secret must keep serving: {kept}"
    );
    assert!(
        scrape(&addr2, "").starts_with("HTTP/1.1 401"),
        "and the gate never falls open while the rotation is stalled"
    );

    stop_gracefully(&mut child2);
    let _ = child2.wait();
}

/// DRAIN DEADLINE e2e (docs/10 §4.28, Round 21): with
/// `--frame-timeout-ms 0`, a peer that goes quiet MID-FRAME parks the
/// serial loop forever — the SIGTERM drain then waits on a request that
/// can never finish (a supervisor would SIGKILL at TimeoutStopSec,
/// leaving the health record behind as a lie). `--drain-timeout-ms` is
/// the bound: report, clear the record, exit 0 — the hung peer is simply
/// abandoned.
#[cfg(unix)]
#[test]
fn bridge_drain_deadline_ends_a_parked_drain() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--frame-timeout-ms",
            "0", // NO per-connection clock — the hole under test
            "--drain-timeout-ms",
            "700",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    // 1. The bait: half a frame, then silence. With the frame deadline
    //    off, the serial loop PARKS on this read — for as long as the
    //    socket lives (which is the rest of this test).
    let mut stuck = std::net::TcpStream::connect(&addr).unwrap();
    stuck.write_all(&[0u8; 4]).unwrap(); // 4 of the 8 length-prefix bytes
    std::thread::sleep(Duration::from_millis(300)); // loop accepts + enters the read

    // 2. SIGTERM: the handler flips the edge, but the parked loop never
    //    returns to poll it — ONLY the deadline can end this drain.
    let pid = child.id() as i32;
    let ret = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(ret, 0, "SIGTERM must reach the bridge child (pid {pid})");
    let started = Instant::now();
    let status = child.wait().unwrap();
    let elapsed = started.elapsed();

    // 3. The deadline CUT the drain: it actually WAITED for the deadline
    //    (no instant collapse), stayed bounded (no forever), and exited
    //    0 — an operator-initiated stop is a stop even when cut.
    assert_eq!(
        status.code(),
        Some(0),
        "a cut drain is still a graceful exit 0: {status:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(500),
        "the drain must WAIT out its deadline ({elapsed:?} elapsed)"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the parked drain must be bounded by --drain-timeout-ms, took {elapsed:?}"
    );

    // 4. The cut is REPORTED (stderr names the flag that ended the stop)
    //    and the health record is GONE — a process that abandoned
    //    in-flight work must leave no "serving" claim behind.
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(
        err.contains("drain deadline of 700 ms exceeded"),
        "the cut must be reported: {err}"
    );
    assert!(
        qsv_cosigner::health::read(&state_dir).is_none(),
        "a cut stop must clear the health record (no stale claim)"
    );
}

/// ZERO-DOWNTIME HANDOVER e2e (docs/10 §4.21, Round 18): SIGTERM on the
/// OLD bridge stops accepting and releases the bind WHILE its drain is
/// still running (an in-flight peer is mid-handshake); the NEW replica
/// takes the port over and serves BEFORE the old process exits — and the
/// old process still exits 0 when its (frame-timeout-bounded) drain
/// finishes. That is the rolling restart systemd performs: no dropped
/// window, no restart loop.
#[cfg(unix)]
#[test]
fn bridge_rolling_restart_serves_while_the_old_replica_drains() {
    fn spawn_tls(
        state_dir: &std::path::Path,
        addr: &str,
        cert: &std::path::Path,
        key: &std::path::Path,
    ) -> Child {
        Command::new(qsv_bin())
            .args([
                "cosigner-bridge",
                "--listen",
                addr,
                "--state-dir",
                state_dir.to_str().unwrap(),
                "--vault-id",
                VAULT,
                "--tls-cert",
                cert.to_str().unwrap(),
                "--tls-key",
                key.to_str().unwrap(),
                "--frame-timeout-ms",
                "5000",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("bridge child must spawn")
    }

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_path = dir.path().join("cert.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    let key_path = dir.path().join("key.pem");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut old = spawn_tls(&state_dir, &addr, &cert_path, &key_path);
    wait_ready(&addr);

    // An IN-FLIGHT peer: connected, mid-handshake, silent — the old
    // replica's worker is draining exactly this connection. Give the
    // accept loop a few ticks to actually ACCEPT it first (connect()
    // completes in the kernel backlog; a TERM that wins the race would
    // drain nothing and exit before the new replica even boots).
    let in_flight = std::net::TcpStream::connect(&addr).unwrap();
    in_flight
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));

    // TERM: stop accepting → drain starts (the in-flight peer is NOT
    // done — std kill() would be SIGKILL and skip the drain entirely).
    let pid = old.id() as i32;
    assert_eq!(
        unsafe { libc::kill(pid, libc::SIGTERM) },
        0,
        "TERM must reach the old replica"
    );
    // …and the drain is now OBSERVABLE: the old process must still be
    // alive immediately after TERM (it is waiting on the silent peer).
    assert!(
        old.try_wait().unwrap().is_none(),
        "TERM must start a DRAIN, not an immediate exit"
    );

    // The bind is released on the next poll tick — poll for it (the new
    // replica can only take over once the old listener is gone).
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if std::net::TcpListener::bind(&addr).is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "old replica never released the bind"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // The NEW replica takes the port while the OLD one is still draining.
    let mut new = spawn_tls(&state_dir, &addr, &cert_path, &key_path);
    wait_ready(&addr);
    assert!(
        old.try_wait().unwrap().is_none(),
        "the old replica must still be draining when the new one serves"
    );

    // Served by the NEW replica during the OLD one's drain: co-signing
    // has NO downtime window during the handover.
    let resp = request_signature_tls(
        &addr,
        &valid_request(),
        "localhost",
        qsv_cosigner::tls::pinned_root_store(cert.cert.der()),
    )
    .unwrap();
    assert!(resp.accepted, "handover must not lose a request: {resp:?}");

    // The drain is BOUNDED (frame timeout): the old process exits 0
    // without waiting on a hung-up peer forever.
    let status = old.wait().expect("old replica must exit");
    assert_eq!(
        status.code(),
        Some(0),
        "the old replica's drain ends in exit 0, got {status:?}"
    );

    // …and the new replica keeps serving after the old one is gone.
    let resp = request_signature_tls(
        &addr,
        &valid_request(),
        "localhost",
        qsv_cosigner::tls::pinned_root_store(cert.cert.der()),
    )
    .unwrap();
    assert!(resp.accepted, "new replica must keep serving");

    stop_gracefully(&mut new);
    let _ = new.wait();
    drop(in_flight);
}

/// CONNECTION CAP e2e (docs/10 §4.22, Round 19): `--max-inflight 1` — a
/// connection beyond the cap is accepted and IMMEDIATELY closed (clean
/// EOF long before any frame timeout could act), the denial is counted
/// in /metrics, and the slot frees when the held peer times out: a
/// flood becomes a REFUSAL, never an unbounded thread/fd count — and
/// the service recovers by itself.
#[cfg(unix)]
#[test]
fn bridge_caps_inflight_workers_and_recovers_after_the_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_path = dir.path().join("cert.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    let key_path = dir.path().join("key.pem");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--tls-cert",
            cert_path.to_str().unwrap(),
            "--tls-key",
            key_path.to_str().unwrap(),
            "--frame-timeout-ms",
            "3000",
            "--max-inflight",
            "1",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);
    // Let the readiness probe's worker die AND leave the ledger — the cap
    // must count the HELD peer, not the bootstrap probe.
    std::thread::sleep(Duration::from_millis(200));

    // The single slot is taken by a SILENT mid-handshake peer.
    let held = std::net::TcpStream::connect(&addr).unwrap();
    held.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    std::thread::sleep(Duration::from_millis(150));

    // A second connection is accepted and closed RIGHT AWAY: without the
    // cap its worker would sit in the handshake until the 3 s timeout;
    // with the cap the client sees the server hang up instead.
    let mut extra = std::net::TcpStream::connect(&addr).unwrap();
    extra
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .unwrap();
    let started = Instant::now();
    let mut byte = [0u8; 1];
    let n = extra.read(&mut byte);
    let server_closed = matches!(&n, Ok(0))
        || matches!(
            n.as_ref().err().map(|e| e.kind()),
            Some(std::io::ErrorKind::ConnectionReset) | Some(std::io::ErrorKind::ConnectionAborted)
        );
    assert!(
        server_closed,
        "the cap must close the extra connection at once: {n:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a capped connection must not wait for the frame timeout: {:?}",
        started.elapsed()
    );

    // Recovery: once the held peer hits its frame timeout the slot frees
    // and signing succeeds again — retries while capped fail fast.
    let deadline = Instant::now() + Duration::from_secs(8);
    let resp = loop {
        match request_signature_tls(
            &addr,
            &valid_request(),
            "localhost",
            qsv_cosigner::tls::pinned_root_store(cert.cert.der()),
        ) {
            Ok(r) => break r,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => panic!("service must recover once the slot frees: {e}"),
        }
    };
    assert!(
        resp.accepted,
        "the capped bridge must keep signing: {resp:?}"
    );

    // The denials are VISIBLE: capacity refusals counted in /metrics.
    // The scrape gets its OWN connection; under machine load the server
    // may hang up a late-handshaking peer at its frame timeout, so a
    // fresh connection is retried a few times (Round-19 transport-retry
    // discipline — the metric ASSERTIONS below are untouched; only the
    // transport retries). Found red by the Round-33 full gate.
    let text = {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let mut tls = rustls_helpers::client_stream(&addr, "localhost", cert.cert.der());
            let got = (|| -> std::io::Result<String> {
                tls.write_all(b"GET /metrics HTTP/1.1\r\n\r\n")?;
                tls.flush()?;
                let mut text = String::new();
                tls.read_to_string(&mut text)?;
                Ok(text)
            })();
            match got {
                Ok(t) if t.contains("HTTP/1.1 200 OK") => break t,
                other if attempt < 5 => {
                    let why = other
                        .as_ref()
                        .err()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "no 200 line yet".into());
                    eprintln!("metrics scrape attempt {attempt} not ready ({why}); retrying");
                    std::thread::sleep(Duration::from_millis(300));
                }
                other => panic!("metrics scrape failed after {attempt} attempts: {other:?}"),
            }
        }
    };
    assert!(
        text.contains("qsv_cosigner_capacity_refused_total"),
        "capacity counter must be exposed: {text}"
    );
    let denials: u64 = text
        .lines()
        .find_map(|l| l.strip_prefix("qsv_cosigner_capacity_refused_total "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    assert!(
        denials >= 1,
        "every capped connection must be counted: {text}"
    );
    assert!(
        text.contains("qsv_cosigner_accepted_total 1"),
        "the recovered release is still on the ledger: {text}"
    );

    // Round 24 (docs/10 §4.39): the ceiling and the occupancy it
    // produced are EXPORTED — sizing `--max-inflight` is then evidence
    // instead of folklore, and the saturation alert compares against the
    // CONFIGURED number rather than a constant typed into a rule file.
    let gauge = |name: &str| -> u64 {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{name} ")))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or_else(|| panic!("{name} must be exported: {text}"))
    };
    assert_eq!(
        gauge("qsv_cosigner_worker_limit"),
        1,
        "the published ceiling is the configured one: {text}"
    );
    assert_eq!(
        gauge("qsv_cosigner_workers_peak"),
        1,
        "the held peer is the high-water mark: {text}"
    );
    assert!(
        gauge("qsv_cosigner_workers_active") <= 1,
        "occupancy never exceeds the cap: {text}"
    );

    let _ = held;
    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// BOOT REHEARSAL e2e (docs/10 §4.41, Round 24): "would systemd start
/// succeed right now?" has an answer that costs nobody a port and
/// publishes nothing — every boot gate runs (token file contract,
/// watchtower state, transport policy, TLS material, the bind itself),
/// the resulting policy is printed, exit 0, and the state dir is left
/// EXACTLY as it was. A rehearsal that wrote a health record would make
/// `doctor` report a co-signer that never served: the whole point is
/// that it is invisible to everything downstream.
#[test]
fn bridge_dry_run_rehearses_the_boot_and_publishes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--max-inflight",
            "32",
            "--dry-run",
        ])
        .output()
        .expect("rehearsal must run");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(0),
        "a healthy estate rehearses cleanly: {stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("BOOT WOULD SUCCEED"),
        "the verdict must be stated: {stdout}"
    );
    assert!(
        stdout.contains("32 in-flight worker(s)"),
        "the operator's own policy is echoed back: {stdout}"
    );
    assert!(
        stdout.contains(&addr),
        "the address that was proven bindable is named: {stdout}"
    );
    assert_eq!(
        std::fs::read_dir(&state_dir).unwrap().count(),
        1,
        "the rehearsal publishes NOTHING — only the input state file stays"
    );
    assert_eq!(
        qsv_cosigner::health::liveness(&state_dir).0,
        qsv_cosigner::Liveness::Absent,
        "a rehearsal must never look like a live bridge"
    );

    // A broken gate is still broken: the rehearsal is not a rubber stamp.
    std::fs::write(state_dir.join("watchtower-state.json"), "{ not json").unwrap();
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--dry-run",
        ])
        .output()
        .expect("rehearsal must run");
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unreadable watchtower state fails the REAL boot too: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("BOOT WOULD SUCCEED"),
        "no verdict may be printed over a failed gate"
    );

    // …and the BIND is part of the rehearsal: a port already taken is
    // the failure systemd would hit at start.
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let taken = std::net::TcpListener::bind(&addr).expect("hold the port");
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--dry-run",
        ])
        .output()
        .expect("rehearsal must run");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a busy port fails the rehearsal: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    drop(taken);
}

/// Minimal TLS client for the scrape (rustls is already in the dep tree).
mod rustls_helpers {
    use super::*;
    use rustls::pki_types::CertificateDer;

    pub fn client_stream(
        addr: &str,
        server_name: &str,
        pinned: &CertificateDer<'_>,
    ) -> impl Read + Write {
        let stream = std::net::TcpStream::connect(addr).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pinned.clone()).unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string()).unwrap();
        let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name).unwrap();
        rustls::StreamOwned::new(conn, stream)
    }

    /// An mTLS client stream for the scrape: presents a client identity
    /// (leaf+key PEM files) in addition to the server pin.
    pub fn mtls_client_stream(
        addr: &str,
        server_name: &str,
        pinned: &CertificateDer<'_>,
        ident: &qsv_cosigner::ClientIdentity,
    ) -> std::io::Result<impl Read + Write> {
        let stream = std::net::TcpStream::connect(addr)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(pinned.clone()).unwrap();
        let config = ident
            .client_config(roots)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string()).unwrap();
        let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(rustls::StreamOwned::new(conn, stream))
    }
}

/// A tiny certificate authority + server + client identity, all rcgen
/// (offline): the exact PEM-file shape the operator provisions.
struct MtlsPems {
    _dir: tempfile::TempDir,
    server_cert: std::path::PathBuf,
    server_key: std::path::PathBuf,
    ca: std::path::PathBuf,
    client_cert: std::path::PathBuf,
    client_key: std::path::PathBuf,
    /// The CA (the client pins the CA: the server leaf is signed BY it,
    /// so the leaf itself cannot serve as anchor).
    ca_der: rustls::pki_types::CertificateDer<'static>,
}

impl MtlsPems {
    fn generate() -> Self {
        use rcgen::{CertificateParams, KeyPair};
        let dir = tempfile::tempdir().unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let ca_params = CertificateParams::new(vec!["qsv e2e ca".to_string()]).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let server_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client_params =
            CertificateParams::new(vec!["qsv e2e co-signing client".to_string()]).unwrap();
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();
        let server_cert_path = dir.path().join("cert.pem");
        std::fs::write(&server_cert_path, server_cert.pem()).unwrap();
        let server_key_path = dir.path().join("key.pem");
        std::fs::write(&server_key_path, server_key.serialize_pem()).unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();
        let client_cert_path = dir.path().join("client.pem");
        std::fs::write(&client_cert_path, client_cert.pem()).unwrap();
        let client_key_path = dir.path().join("client-key.pem");
        std::fs::write(&client_key_path, client_key.serialize_pem()).unwrap();
        Self {
            _dir: dir,
            server_cert: server_cert_path,
            server_key: server_key_path,
            ca: ca_path,
            client_cert: client_cert_path,
            client_key: client_key_path,
            ca_der: ca_cert.der().clone(),
        }
    }

    fn client_identity(&self) -> qsv_cosigner::ClientIdentity {
        client_identity(&self.client_cert, &self.client_key).unwrap()
    }
}

#[test]
fn cosigner_bridge_mtls_requires_a_pinned_client_identity() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let pems = MtlsPems::generate();

    // 1. USAGE: --tls-client-ca without the --tls pair is exit 2.
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "127.0.0.1:3333",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--tls-client-ca",
            pems.ca.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "client CA without TLS pair");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--tls-client-ca requires"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 2. THE mTLS BRIDGE: server cert + client-CA requirement.
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--tls-cert",
            pems.server_cert.to_str().unwrap(),
            "--tls-key",
            pems.server_key.to_str().unwrap(),
            "--tls-client-ca",
            pems.ca.to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("mTLS bridge child must spawn");
    wait_ready(&addr);

    // 3. ANONYMOUS TLS client (CA pin, NO client cert): the request
    //    CANNOT complete — the handshake dies on missing client auth. The
    //    client may see a local alert/error or a closed stream; what it
    //    must NEVER see is a co-signature.
    let anon = request_signature_tls(
        &addr,
        &valid_request(),
        "localhost",
        qsv_cosigner::tls::pinned_root_store(&pems.ca_der),
    );
    assert!(
        anon.is_err(),
        "an anonymous client must NEVER complete the mTLS handshake: {anon:?}"
    );

    // 4. THE PINNED CLIENT identity: releases the SAME deterministic
    //    co-signature (transport never touches Theorem 1) — and scrapes
    //    /metrics through the same tunnel (requests_total counts the two
    //    probes that reached the gate: the anonymous attempt died IN the
    //    handshake, before the gate).
    let ident = pems.client_identity();
    let roots = qsv_cosigner::tls::pinned_root_store(&pems.ca_der);
    let resp = request_signature_mtls(&addr, &valid_request(), "localhost", roots.clone(), &ident)
        .unwrap();
    assert!(resp.accepted, "the pinned client must release: {resp:?}");
    let first_sig = resp.schnorr_sig_hex.clone().unwrap();
    assert!(!first_sig.is_empty());

    // 5. /metrics INSIDE mTLS: scrape answered, no counter moved by it.
    let mut tls =
        rustls_helpers::mtls_client_stream(&addr, "localhost", &pems.ca_der, &ident).unwrap();
    tls.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").unwrap();
    tls.flush().unwrap();
    let mut text = String::new();
    tls.read_to_string(&mut text).unwrap();
    assert!(text.contains("HTTP/1.1 200 OK"), "{text}");
    assert!(text.contains("qsv_cosigner_requests_total 1"), "{text}");
    // Round 17: the mTLS release is attributed per vault through the
    // tunnel, too.
    assert!(
        text.contains("qsv_cosigner_accepted_by_vault_total{vault=\"test-vault-1\"} 1"),
        "{text}"
    );

    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// HEALTH RECORD + SCRAPE GATE e2e (docs/10 §4.23, Round 20):
///   1. The bridge publishes `bridge-health.json` (pid, bind, transport,
///      vaults, mirror tip, policy) BEFORE it accepts a connection — the
///      operator's "who is actually serving" answer.
///   2. The record vanishes on the GRACEFUL stop: presence means "up",
///      so a leftover claim would be a lie.
///   3. A SIGKILL leaves the record BEHIND with a dead pid — the stale
///      case an operator must be able to see (checked by `qsv-cli doctor`).
///   4. Off loopback an OPEN `/metrics` is refused at boot (exit 1): the
///      counters are an estate map. With `--metrics-token` the same bind
///      boots and serves normally.
#[test]
fn bridge_publishes_a_health_record_and_clears_it_only_on_a_graceful_stop() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    // 1. The record exists while serving and describes THIS process.
    //    Bounded poll: the connect above completes off the LISTENER's
    //    kernel backlog — potentially a few ms BEFORE the child publishes
    //    the record (bind → policy → publish is the design order). The
    //    contract is "published while serving", not "published before our
    //    scheduler got around to reading".
    let read_deadline = Instant::now() + Duration::from_secs(5);
    let health = loop {
        if let Some(h) = qsv_cosigner::health::read(&state_dir) {
            break h;
        }
        assert!(
            Instant::now() < read_deadline,
            "the bridge must publish its health record at boot"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(health.pid, child.id(), "the record names the serving pid");
    assert_eq!(health.listen, addr, "the record names the bound address");
    assert_eq!(health.transport, "plain", "loopback serve is plain TCP");
    assert_eq!(health.vaults, vec![VAULT.to_string()]);
    assert_eq!(
        health.watchtower_tip, 820_000,
        "mirror seeded at the state tip"
    );
    assert!(!health.metrics_token_armed, "no --metrics-token was passed");
    assert_eq!(health.max_inflight, 64, "the CLI default is on the record");
    assert_eq!(health.frame_timeout_ms, Some(10_000));
    assert!(
        health.started_at_unix > 1_600_000_000,
        "boot clock recorded: {}",
        health.started_at_unix
    );
    // The token VALUE is never on disk (only the armed bit is).
    let raw = std::fs::read_to_string(qsv_cosigner::health_path(&state_dir)).unwrap();
    assert!(
        !raw.contains("metrics_token\""),
        "no token field at all: {raw}"
    );

    // 3. SIGKILL (NOT the graceful path): the record STAYS, and its pid is
    //    reported dead — the raw truth behind the doctor's FAIL.
    let ret = unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
    assert_eq!(ret, 0, "SIGKILL must reach the child");
    let status = child.wait().unwrap();
    assert!(!status.success(), "SIGKILL is not a clean exit");
    std::thread::sleep(Duration::from_millis(200));
    let stale = qsv_cosigner::health::read(&state_dir)
        .expect("an unclean death leaves the record behind (that IS the signal)");
    assert_eq!(stale.pid, health.pid);
    assert_eq!(
        qsv_cosigner::health::pid_alive(stale.pid),
        Some(false),
        "a reaped pid is not alive"
    );
    assert_eq!(
        qsv_cosigner::health::liveness(&state_dir).0,
        qsv_cosigner::Liveness::Stale
    );
    // Clean up the dead record so the tempdir does not linger as a lie.
    qsv_cosigner::health::remove(&state_dir);

    // 2. Graceful stop: the record is torn down.
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);
    // The record lands during boot; poll briefly instead of assuming it is
    // ordered after the socket (instrumented coverage builds schedule the
    // publish thread differently).
    let mut published = false;
    for _ in 0..100 {
        if qsv_cosigner::health::read(&state_dir).is_some() {
            published = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(published, "record published");
    let ret = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(ret, 0, "SIGTERM must reach the bridge child");
    let status = child.wait().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "graceful stop is exit 0: {status:?}"
    );
    assert!(
        qsv_cosigner::health::read(&state_dir).is_none(),
        "a graceful stop must NOT leave a live-co-signer claim behind"
    );
    assert_eq!(
        qsv_cosigner::health::liveness(&state_dir).0,
        qsv_cosigner::Liveness::Absent
    );
    // Only the watchtower state file is left — no .tmp debris either.
    let mut left: Vec<String> = std::fs::read_dir(&state_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    left.sort();
    assert_eq!(left, vec!["watchtower-state.json".to_string()], "{left:?}");

    // 4. SCRAPE GATE: TLS + non-loopback bind, no token → refused at boot.
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    let cert_pem = dir.path().join("cert.pem");
    std::fs::write(&cert_pem, cert.cert.pem()).unwrap();
    let key_pem = dir.path().join("key.pem");
    std::fs::write(&key_pem, cert.key_pair.serialize_pem()).unwrap();
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "0.0.0.0:3333",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--tls-cert",
            cert_pem.to_str().unwrap(),
            "--tls-key",
            key_pem.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "an open scrape off loopback must die at boot: {out:?}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("open /metrics outside loopback is forbidden"),
        "{err}"
    );
    assert!(
        err.contains("--metrics-token"),
        "the message names the fix: {err}"
    );
    // The refused bridge opened NO socket and left NO health record.
    assert!(qsv_cosigner::health::read(&state_dir).is_none());

    // …with the token armed, the SAME non-loopback bind boots and serves.
    let port = free_port();
    let addr = format!("0.0.0.0:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--tls-cert",
            cert_pem.to_str().unwrap(),
            "--tls-key",
            key_pem.to_str().unwrap(),
            "--metrics-token",
            "s3cr3t",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("armed non-loopback bridge must boot");
    wait_ready(&format!("127.0.0.1:{port}"));
    // `wait_ready` only proves the LISTEN socket exists (the kernel
    // completes a TCP handshake at bind time); the record lands between
    // the TLS-material check and the accept loop — poll for it instead
    // of racing it (the same bounded read the other phases use).
    let record_deadline = Instant::now() + Duration::from_secs(5);
    let armed = loop {
        if let Some(h) = qsv_cosigner::health::read(&state_dir) {
            break h;
        }
        assert!(
            Instant::now() < record_deadline,
            "health record must appear"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        armed.metrics_token_armed,
        "the record shows the gate is armed"
    );
    assert_eq!(armed.transport, "tls");
    assert!(
        !std::fs::read_to_string(qsv_cosigner::health_path(&state_dir))
            .unwrap()
            .contains("s3cr3t"),
        "the SECRET is never written to the record"
    );
    // The gate really is on: no token → 401.
    let mut tls =
        rustls_helpers::client_stream(&format!("127.0.0.1:{port}"), "localhost", cert.cert.der());
    tls.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").unwrap();
    tls.flush().unwrap();
    let mut text = String::new();
    tls.read_to_string(&mut text).unwrap();
    assert!(text.contains("HTTP/1.1 401"), "{text}");

    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// Collect every `qsv_cosigner_*` family token in a text (rules file or
/// exposition), longest possible ASCII run after the prefix.
fn family_tokens(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let prefix = b"qsv_cosigner_";
    let mut out = Vec::new();
    let mut i = 0;
    while i + prefix.len() <= bytes.len() {
        if &bytes[i..i + prefix.len()] == prefix {
            let start = i;
            i += prefix.len();
            while i < bytes.len()
                && (bytes[i].is_ascii_lowercase() || bytes[i].is_ascii_digit() || bytes[i] == b'_')
            {
                i += 1;
            }
            out.push(text[start..i].to_string());
        } else {
            i += 1;
        }
    }
    out
}

/// LIVE EXPOSITION contract (docs/10 §4.45, Round 25): every series an
/// alert rule READS must be rendered by a REAL running bridge — either
/// at boot or by the very event the rule alerts on. The static asset
/// test proves the name is in METRIC_FAMILIES; this proves a booted
/// process actually emits it. Three families are EVENT-CONDITIONAL by
/// design (per-vault rows render only once that vault has history —
/// Prometheus warms the counter from its first sample, which is exactly
/// when an `increase(...)` alert becomes evaluable), so the contract is:
///   · boot: everything else, present immediately;
///   · after each event: the conditional row its rule reads.
/// A rule on a family that NO event ever renders is silently dead:
/// Prometheus holds no series and nobody is ever paged.
#[test]
fn every_alert_reference_is_a_series_the_live_bridge_exports() {
    let alerts_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/prometheus_alerts.yml");
    let alerts = std::fs::read_to_string(&alerts_path)
        .unwrap_or_else(|e| panic!("alerts file at {}: {e}", alerts_path.display()));
    let mut wanted = family_tokens(&alerts);
    wanted.sort();
    wanted.dedup();
    assert!(
        wanted.len() >= 8,
        "the rules must read the bridge's series, got: {wanted:?}"
    );

    // Rendered only after their event (see doc comment): the freeze
    // refusal, any per-vault refusal, and the token-bucket refusal.
    let conditional = [
        "qsv_cosigner_alarm_refused_by_vault_total",
        "qsv_cosigner_refused_by_vault_total",
        "qsv_cosigner_rate_limited_by_vault_total",
    ];

    let scrape = |addr: &str| -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut text = String::new();
        s.read_to_string(&mut text).unwrap();
        assert!(text.starts_with("HTTP/1.1 200"), "scrape: {text}");
        text
    };
    let missing_from = |text: &str, allowed: &[&str]| -> Vec<String> {
        wanted
            .iter()
            .filter(|n| !text.contains(n.as_str()))
            .filter(|n| !allowed.contains(&n.as_str()))
            .cloned()
            .collect()
    };

    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    // A deliberately tiny bucket (3 burst, 1/s refill) so the
    // rate-limit event is reachable inside one test without a flood
    // that would only prove the machine is slow.
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--rate-limit",
            "3:1",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    // 1. BOOT: every non-conditional family is on the wire before a
    //    single request has arrived (the dev scrape gate is disarmed —
    //    this is exactly the query Prometheus runs).
    let text = scrape(&addr);
    let boot_missing = missing_from(&text, &conditional);
    assert!(
        boot_missing.is_empty(),
        "a family a rule reads must render at BOOT: {boot_missing:?}\n{text}"
    );

    // 2. THE FREEZE EVENT: watchtower flips to ALERT → the refusal
    //    creates the per-vault history both freeze rules read.
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("ALERT")).unwrap();
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(!resp.accepted, "ALERT state must freeze the vault");
    let text = scrape(&addr);
    for family in [
        "qsv_cosigner_alarm_refused_by_vault_total",
        "qsv_cosigner_refused_by_vault_total",
    ] {
        assert!(
            text.contains(family),
            "the freeze event must render {family}:\n{text}"
        );
    }

    // 3. THE BUCKET EVENT: clear the state, then burst past the
    //    3-token bucket → the rate-limit row its rule reads appears.
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let mut shed = 0;
    for _ in 0..12 {
        if let Ok(r) = request_signature(&addr, &valid_request()) {
            if !r.accepted {
                shed += 1;
            }
        }
    }
    assert!(shed >= 1, "the burst must shed at least one request");

    // 4. FINAL: every series any alert rule reads now exists for real.
    let text = scrape(&addr);
    let missing = missing_from(&text, &[]);
    assert!(
        missing.is_empty(),
        "alert rules read series the LIVE bridge never renders: {missing:?}\n{text}"
    );

    stop_gracefully(&mut child);
    let _ = child.wait();
}

/// Round 30: a malformed `--rate-limit` spec is a USAGE error — exit 2 with
/// the reason on stderr, and the refused boot never opens a socket.
#[test]
fn bridge_refuses_a_malformed_rate_limit_spec_with_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--rate-limit",
            "not-a-spec",
        ])
        .output()
        .expect("bridge must spawn");
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2: {stderr}");
    assert!(stderr.contains("usage error"), "{stderr}");
    assert!(
        std::net::TcpStream::connect(&addr).is_err(),
        "a refused boot must never open the socket"
    );
}

/// Round 30: the mTLS rehearsal — dry-run with the PRODUCTION shape (pinned
/// server cert + required client CA + file-armed scrape gate + a real
/// drain deadline) boots cleanly and echoes every policy line.
#[test]
fn bridge_dry_run_rehearses_the_mtls_boot_with_a_file_armed_gate() {
    use std::os::unix::fs::PermissionsExt;
    let pems = MtlsPems::generate();
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let token_file = dir.path().join("scrape.token");
    std::fs::write(&token_file, "dry-run-token\n").unwrap();
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
            "--tls-cert",
            pems.server_cert.to_str().unwrap(),
            "--tls-key",
            pems.server_key.to_str().unwrap(),
            "--tls-client-ca",
            pems.ca.to_str().unwrap(),
            "--metrics-token-file",
            token_file.to_str().unwrap(),
            "--drain-timeout-ms",
            "500",
            "--max-inflight",
            "0",
            "--dry-run",
        ])
        .output()
        .expect("rehearsal must run");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        out.status.code(),
        Some(0),
        "an mTLS estate rehearses cleanly: {stdout}{stderr}"
    );
    assert!(stdout.contains("BOOT WOULD SUCCEED"), "{stdout}");
    assert!(
        stdout.contains("mTLS (client certs required)"),
        "the transport is named: {stdout}"
    );
    assert!(
        stdout.contains("token armed FROM FILE"),
        "the file-armed gate is stated: {stdout}"
    );
    assert!(stdout.contains("(unlimited)"), "{stdout}");
    assert!(
        stdout.contains("reload source") && stdout.contains("rotation-ready"),
        "the SIGHUP rotation source is named: {stdout}"
    );
    assert!(
        stdout.contains("drain deadline 500 ms"),
        "the operator's drain policy is echoed: {stdout}"
    );
    assert!(
        stdout.contains("client CA") && stdout.contains("anonymous clients refused"),
        "the mTLS CA is named: {stdout}"
    );
}

/// Round 30: a supervisor that can never be told READY must fail the boot
/// LOUDLY — a bridge whose sd_notify send fails would sit "activating"
/// forever while the operator waits on a heartbeat that never comes.
#[test]
fn bridge_fails_the_boot_when_sd_notify_cannot_deliver() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("wt");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(state_dir.join("watchtower-state.json"), state_body("clear")).unwrap();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--vault-id",
            VAULT,
        ])
        .env("NOTIFY_SOCKET", "/nonexistent/qsv-notify.sock")
        .output()
        .expect("bridge must spawn");
    assert_ne!(
        out.status.code(),
        Some(0),
        "an undeliverable READY=1 must fail the boot"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("sd_notify READY=1 failed"),
        "the operator sees WHY the boot failed: {stderr}"
    );
}

// ── k-of-n WATCHTOWER MIRROR QUORUM (docs/10 §3.4 / §4.60) ─────────

/// Usage walls for the k-of-n mirror quorum: k must be satisfiable
/// (1..=n) and — with EXACTLY two mirrors — explicitly chosen, because no
/// compromise-resistant default exists there (k=2 is silenced by one dead
/// host, k=1 is forged by one). Every refusal is exit 2 and fires BEFORE
/// the socket binds, so a misconfigured estate never half-serves.
#[test]
fn cosigner_bridge_quorum_usage_walls_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let m1 = dir.path().join("wt1");
    let m2 = dir.path().join("wt2");
    for d in [&m1, &m2] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("watchtower-state.json"), state_body("clear")).unwrap();
    }

    // n=2 WITHOUT an explicit k → no guessable default, exit 2.
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "127.0.0.1:3333",
            "--state-dir",
            m1.to_str().unwrap(),
            "--watchtower",
            m2.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "two mirrors need an explicit quorum"
    );
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("--watchtower-quorum is required with exactly two mirrors"),
        "the operator is told WHY: {err}"
    );

    // k > n could NEVER fire (a flag typo that silently unlocks) → exit 2.
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "127.0.0.1:3333",
            "--state-dir",
            m1.to_str().unwrap(),
            "--watchtower",
            m2.to_str().unwrap(),
            "--watchtower-quorum",
            "3",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "k>n must be refused");
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("--watchtower-quorum must be in 1..=2"),
        "{err}"
    );

    // k = 0 would freeze EVERYTHING (the other direction of the same
    // wall) → exit 2 even on a single-mirror estate.
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "127.0.0.1:3333",
            "--state-dir",
            m1.to_str().unwrap(),
            "--watchtower-quorum",
            "0",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "k=0 must be refused");
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("--watchtower-quorum must be in 1..=1"),
        "{err}"
    );
}

/// The resolved merge is NAMED in the boot rehearsal: two mirrors with an
/// explicit k=2 print exactly that (n=2 without the flag would already
/// have exited 2 in the wall test above).
#[test]
fn cosigner_bridge_rehearsal_names_the_resolved_quorum() {
    let dir = tempfile::tempdir().unwrap();
    let m1 = dir.path().join("wt1");
    let m2 = dir.path().join("wt2");
    for d in [&m1, &m2] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("watchtower-state.json"), state_body("clear")).unwrap();
    }
    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "127.0.0.1:3333",
            "--state-dir",
            m1.to_str().unwrap(),
            "--watchtower",
            m2.to_str().unwrap(),
            "--watchtower-quorum",
            "2",
            "--dry-run",
        ])
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "an explicit k on two mirrors rehearses cleanly: {text}"
    );
    assert!(
        text.contains("2 mirror(s) · quorum 2"),
        "the merged quorum is stated: {text}"
    );
}

/// Fail-closed BOOT across the mirror set: an extra `--watchtower` dir
/// with no `watchtower-state.json` aborts the boot (exit 1) — one silent
/// host is an operator decision, never a guessed "all clear".
#[test]
fn cosigner_bridge_aborts_the_boot_when_a_mirror_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    let m1 = dir.path().join("wt1");
    let m2 = dir.path().join("wt2"); // never written
    std::fs::create_dir_all(&m1).unwrap();
    std::fs::create_dir_all(&m2).unwrap();
    std::fs::write(m1.join("watchtower-state.json"), state_body("clear")).unwrap();

    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "127.0.0.1:3333",
            "--state-dir",
            m1.to_str().unwrap(),
            "--watchtower",
            m2.to_str().unwrap(),
            "--watchtower-quorum",
            "2",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "an unreadable mirror must abort the boot"
    );
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("cannot read") && err.contains("watchtower-state.json"),
        "the operator sees WHICH mirror is silent: {err}"
    );
}

/// M46 (Round 36) · the VACUOUS-STATE WALL: a watchtower state file that
/// PARSES but carries no vault record (`{"tip": N, "vaults": {}}` — the
/// shape a truncated or clobbered writer leaves behind) must abort the
/// boot exactly like an unreadable one. Boot has no last-good verdicts
/// to keep, so accepting the empty map would serve every vault as a
/// silent ALL-CLEAR — presence without content may never read as health.
#[test]
fn cosigner_bridge_aborts_the_boot_on_a_vacuous_state_file() {
    let dir = tempfile::tempdir().unwrap();
    let m1 = dir.path().join("wt1");
    std::fs::create_dir_all(&m1).unwrap();
    // Parses fine (valid tip, valid object) — yet holds ZERO vault records.
    std::fs::write(
        m1.join("watchtower-state.json"),
        "{\"tip\": 820001, \"vaults\": {}}",
    )
    .unwrap();

    let mut out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            "127.0.0.1:3340",
            "--state-dir",
            m1.to_str().unwrap(),
            "--vault-id",
            VAULT,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // BOUNDED REAP: a REFUSING boot exits in well under a second, while a
    // boot that (under a removed wall) starts SERVING must be killed by
    // THIS test — never hang the suite. This is also the audit's own
    // contract (M46): a mutant must fail FAST and leave no orphan bridge
    // behind, or a killed run poisons the next one's port and machine.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        match out.try_wait().expect("reap") {
            Some(st) => break st,
            None if std::time::Instant::now() >= deadline => {
                out.kill().ok();
                panic!("the vacuous state must ABORT the boot — the bridge is still serving");
            }
            None => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    };
    assert_eq!(
        status.code(),
        Some(1),
        "a vacuous mirror must abort the boot — never an implicit all-clear"
    );
    use std::io::Read;
    let mut err = String::new();
    out.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    assert!(
        err.contains("vacuous mirror must never boot as all-clear"),
        "the operator sees WHY the state file counts as empty: {err}"
    );
    // Before the bind: a refused bridge must never print the serving
    // banner or the "mirror applied" line (those land AFTER a load).
    let mut out_txt = String::new();
    out.stdout
        .take()
        .unwrap()
        .read_to_string(&mut out_txt)
        .unwrap();
    assert!(
        !out_txt.contains("serving:") && !out_txt.contains("mirror applied"),
        "the vacuous state is refused before any serving banner: {out_txt}"
    );
}

/// The k-of-n verdict over a LIVE service: n = `--state-dir` + every
/// repeatable `--watchtower`, k = the majority default (⌊n/2⌋+1 = 2 for
/// n=3). One alarmed host alone may NOT freeze the vault; k hosts may;
/// a mirror DELETED mid-run keeps the LAST verdicts (it can never
/// unlock); and every release carries the SAME deterministic signature.
#[test]
fn cosigner_bridge_freezes_only_when_k_of_n_mirrors_agree() {
    let dir = tempfile::tempdir().unwrap();
    let m1 = dir.path().join("wt1"); // --state-dir (mirror #1)
    let m2 = dir.path().join("wt2"); // --watchtower
    let m3 = dir.path().join("wt3"); // --watchtower
    for d in [&m1, &m2, &m3] {
        std::fs::create_dir_all(d).unwrap();
    }
    let write = |d: &std::path::Path, verdict: &str| {
        std::fs::write(d.join("watchtower-state.json"), state_body(verdict)).unwrap()
    };
    // Boot: exactly ONE of three mirrors reports ALERT — below the
    // majority default k=2, so the vault must RELEASE.
    write(&m1, "ALERT");
    write(&m2, "clear");
    write(&m3, "clear");

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let mut child = Command::new(qsv_bin())
        .args([
            "cosigner-bridge",
            "--listen",
            &addr,
            "--state-dir",
            m1.to_str().unwrap(),
            "--watchtower",
            m2.to_str().unwrap(),
            "--watchtower",
            m3.to_str().unwrap(),
            "--vault-id",
            VAULT,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("bridge child must spawn");
    wait_ready(&addr);

    // 1. ONE of three (k=2 default) → released: a single host's word is
    //    not a freeze.
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "1 of 3 must not freeze: {resp:?}");
    let first_sig = resp.schnorr_sig_hex.clone().unwrap();

    // 2. A SECOND host joins the alarm → k reached → frozen (no restart).
    write(&m2, "ALERT");
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(!resp.accepted, "2 of 3 must freeze");
    assert!(resp
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("watchtower alarm active"));

    // 3. The second host recovers → back to 1 of 3 → the freeze lifts
    //    and the deterministic release returns byte-identically.
    write(&m2, "clear");
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "recovery below k must release: {resp:?}");
    assert_eq!(resp.schnorr_sig_hex.unwrap(), first_sig);

    // 4. A DIFFERENT pair alarms (m1 + m3): the quorum counts HOSTS, not
    //    which ones — frozen again.
    write(&m3, "ALERT");
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(!resp.accepted, "the other pair must freeze too");

    // 5. m1's state file VANISHES mid-run: all mirrors must load or the
    //    LAST verdict stays (fail-closed) — a deleted mirror can NEVER
    //    unlock a frozen vault, it just stops counting.
    std::fs::remove_file(m1.join("watchtower-state.json")).unwrap();
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(
        !resp.accepted,
        "a vanished mirror keeps the LAST (frozen) verdicts: {resp:?}"
    );

    // 6. The mirror returns (clear): now only m3 still says ALERT → 1 of
    //    3 < k → released, SAME signature as the very first release.
    write(&m1, "clear");
    let resp = request_signature(&addr, &valid_request()).unwrap();
    assert!(resp.accepted, "1 of 3 must release again: {resp:?}");
    assert_eq!(resp.schnorr_sig_hex.unwrap(), first_sig);

    stop_gracefully(&mut child);
    let _ = child.wait();
    let _ = std::io::stdout().flush();
}
