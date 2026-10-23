//! Live-wire e2e for the Nitro ceremony (docs/10 §4.53): the SAME two
//! binaries `scripts/nitro_e2e.sh` runs, driven here over loopback so
//! PHASE 1 is proven on every `cargo test`. Real processes, real sockets,
//! real attestation documents — no stubs, no in-process shortcuts.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// A free-ish port: nanos-based so parallel test binaries rarely collide.
fn fresh_port() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .subsec_nanos();
    40_000 + (nanos % 20_000) as u16
}

/// Kills the server when the test ends (panic or not).
struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawns `enclave_server` and reads its startup contract:
/// `DEV_PCR0=…`, `DEV_XONLY=…`, `E2E_READY mode=… port=…`.
fn spawn_server(args: &[&str], env: Option<(&str, &str)>) -> (ServerGuard, String, String, u16) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_enclave_server"));
    cmd.args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("QSV_VAULT");
    if let Some((k, v)) = env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn enclave_server");
    let stdout = child.stdout.take().expect("stdout piped");
    let mut pcr0 = String::new();
    let mut xonly = String::new();
    let mut port = 0u16;
    let mut mode = String::new();
    for line in BufReader::new(stdout).lines() {
        let line = line.expect("server stdout line");
        if let Some(v) = line.strip_prefix("DEV_PCR0=") {
            pcr0 = v.to_string();
        } else if let Some(v) = line.strip_prefix("DEV_XONLY=") {
            xonly = v.to_string();
        } else if let Some(v) = line.strip_prefix("E2E_READY ") {
            assert!(!xonly.is_empty(), "E2E_READY before DEV_XONLY: {line}");
            for kv in v.split_whitespace() {
                if let Some(p) = kv.strip_prefix("port=") {
                    port = p.parse().expect("port parse");
                }
                if let Some(m) = kv.strip_prefix("mode=") {
                    mode = m.to_string();
                }
            }
            assert_ne!(port, 0, "E2E_READY without port: {line}");
            assert_eq!(mode, "tcp", "dev build must serve over tcp");
            assert!(!pcr0.is_empty(), "dev build must print DEV_PCR0");
            return (ServerGuard(child), pcr0, xonly, port);
        }
    }
    // EOF before E2E_READY: reap the child, then fail loudly.
    let _ = child.kill();
    let _ = child.wait();
    panic!("server exited before E2E_READY");
}

/// Runs the probe; returns (exit_ok, combined output).
fn probe(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cosign_probe"))
        .args(args)
        .output()
        .expect("spawn cosign_probe");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn wire_e2e_passes_and_refusals_fail_closed() {
    let port = fresh_port();
    let (server, pcr0, xonly, bport) =
        spawn_server(&["--port", &port.to_string(), "--vault", "e2e-vault"], None);
    let p = bport.to_string();

    // 1. The full ceremony passes: gate + attestation chain + signature.
    let (ok, out) = probe(&[
        "--tcp",
        "--port",
        &p,
        "--vault",
        "e2e-vault",
        "--pcr0",
        &pcr0,
        "--xonly",
        &xonly,
    ]);
    assert!(ok, "probe must PASS the real wire: {out}");
    assert!(out.contains("PROBE PASS"), "missing PASS line: {out}");

    // 2. A WRONG PCR0 pin must be refused (measurement is load-bearing).
    let zero_pcr0 = "00".repeat(48);
    let (ok, out) = probe(&[
        "--tcp",
        "--port",
        &p,
        "--vault",
        "e2e-vault",
        "--pcr0",
        &zero_pcr0,
        "--xonly",
        &xonly,
    ]);
    assert!(!ok, "wrong PCR0 must be refused: {out}");
    assert!(out.contains("REFUSED"), "expected REFUSED: {out}");

    // 3. An UNALLOWED vault must be refused by the gate.
    let (ok, out) = probe(&[
        "--tcp",
        "--port",
        &p,
        "--vault",
        "other-vault",
        "--pcr0",
        &pcr0,
        "--xonly",
        &xonly,
    ]);
    assert!(!ok, "unallowed vault must be refused: {out}");

    // 4. A WRONG pinned key must break the user_data binding.
    let wrong_xonly = hex::encode([0x11u8; 32]);
    let (ok, out) = probe(&[
        "--tcp",
        "--port",
        &p,
        "--vault",
        "e2e-vault",
        "--pcr0",
        &pcr0,
        "--xonly",
        &wrong_xonly,
    ]);
    assert!(!ok, "wrong xonly pin must be refused: {out}");

    drop(server);
}

#[test]
fn server_env_vault_fallback_and_usage_errors() {
    // Usage errors exit 2 (fail closed before serving anything).
    let out = Command::new(env!("CARGO_BIN_EXE_enclave_server"))
        .output()
        .expect("spawn enclave_server");
    assert_eq!(out.status.code(), Some(2), "--port is required");

    let out = Command::new(env!("CARGO_BIN_EXE_enclave_server"))
        .args(["--port", "70000"])
        .output()
        .expect("spawn enclave_server");
    assert_eq!(out.status.code(), Some(2), "bad --port must be usage error");

    // An EMPTY --vault id is a usage error (an empty allowlist entry
    // would silently allow nothing). The port must be VALID here — a bad
    // --port would exit via the port wall before the vault wall runs.
    let out = Command::new(env!("CARGO_BIN_EXE_enclave_server"))
        .args(["--port", "17000", "--vault", ""])
        .output()
        .expect("spawn enclave_server");
    assert_eq!(out.status.code(), Some(2), "--vault needs a non-empty id");

    // --max-requests must be an integer >= 1 (the graceful-exit path).
    let out = Command::new(env!("CARGO_BIN_EXE_enclave_server"))
        .args(["--port", "70000", "--max-requests", "0"])
        .output()
        .expect("spawn enclave_server");
    assert_eq!(out.status.code(), Some(2), "--max-requests must be >= 1");
    let out = Command::new(env!("CARGO_BIN_EXE_enclave_server"))
        .args(["--port", "70000", "--max-requests", "nan"])
        .output()
        .expect("spawn enclave_server");
    assert_eq!(
        out.status.code(),
        Some(2),
        "--max-requests must be an integer"
    );

    let (ok, _) = probe(&["--tcp", "--vault", "x"]);
    assert!(!ok, "probe without --port/--pcr0 must exit non-zero");

    // The enclave image carries the allowlist as ENV, not run-time args:
    // QSV_VAULT must be honored when no --vault flag is given.
    let port = fresh_port();
    let (server, pcr0, xonly, bport) = spawn_server(
        &["--port", &port.to_string()],
        Some(("QSV_VAULT", "env-vault,second-vault")),
    );
    let p = bport.to_string();
    let (ok, out) = probe(&[
        "--tcp",
        "--port",
        &p,
        "--vault",
        "env-vault",
        "--pcr0",
        &pcr0,
        "--xonly",
        &xonly,
    ]);
    assert!(ok, "QSV_VAULT allowlist must be honored: {out}");
    let (ok, _) = probe(&[
        "--tcp",
        "--port",
        &p,
        "--vault",
        "not-listed",
        "--pcr0",
        &pcr0,
        "--xonly",
        &xonly,
    ]);
    assert!(!ok, "vault outside QSV_VAULT must be refused");
    drop(server);
}

/// Round 29 coverage pin — the STARTUP paths (flag parsing, the env
/// allowlist fallback, the empty-allowlist warning, the occupied-port
/// refusal) are only RECORDED when the child exits NORMALLY: a SIGKILL'd
/// server never flushes its profile data. So the probe here is a second
/// server that hits the bind error and exits 1 on its own, carrying every
/// startup branch with it.
#[test]
fn startup_paths_are_carried_by_a_normally_exiting_child() {
    use std::net::TcpStream;

    let port = fresh_port();
    let p = port.to_string();
    let (first, _, _, _) = spawn_server(&["--port", &p, "--vault", "e2e-vault"], None);
    // E2E_READY prints BEFORE the bind — poll until the port is really held.
    let mut bound = false;
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            bound = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(bound, "the first server must hold the port");

    // B1: --vault AND a valid --seed are parsed, then the double-bind
    // refuses to serve → exit 1 with the cause on stderr.
    let out = Command::new(env!("CARGO_BIN_EXE_enclave_server"))
        .args([
            "--port",
            &p,
            "--vault",
            "e2e-vault",
            "--seed",
            &"ab".repeat(32),
        ])
        .output()
        .expect("spawn enclave_server");
    assert_eq!(out.status.code(), Some(1), "occupied port must exit 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("tcp serve failed"), "{err}");

    // B2: no --vault, no QSV_VAULT → the fail-closed WARNING (an empty
    // allowlist refuses every request), then the same bind refusal.
    let out = Command::new(env!("CARGO_BIN_EXE_enclave_server"))
        .args(["--port", &p])
        .env_remove("QSV_VAULT")
        .output()
        .expect("spawn enclave_server");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("WARNING no vault allowlist"),
        "empty allowlist warning missing: {err}"
    );

    // B3: no flag, QSV_VAULT in the environment (the enclave-image form)
    // → parsed WITHOUT the warning, then the bind refusal.
    let out = Command::new(env!("CARGO_BIN_EXE_enclave_server"))
        .args(["--port", &p, "--seed", &"cd".repeat(32)])
        .env("QSV_VAULT", "env-vault, second-vault")
        .output()
        .expect("spawn enclave_server");
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("WARNING no vault allowlist"),
        "the env allowlist must be seen: {err}"
    );
    assert!(err.contains("tcp serve failed"), "{err}");

    drop(first);
}

/// Round 29 P5: `--max-requests 1` serves ONE connection and exits 0 —
/// the NORMAL exit that flushes this process's own profile data, and the
/// graceful contract the enclave runner relies on.
#[test]
fn bounded_server_exits_normally_after_its_last_request() {
    let port = fresh_port();
    let (mut server, pcr0, xonly, bport) = spawn_server(
        &[
            "--port",
            &port.to_string(),
            "--vault",
            "e2e-vault",
            "--max-requests",
            "1",
        ],
        None,
    );
    let p = bport.to_string();
    let (ok, out) = probe(&[
        "--tcp",
        "--port",
        &p,
        "--vault",
        "e2e-vault",
        "--pcr0",
        &pcr0,
        "--xonly",
        &xonly,
    ]);
    assert!(ok, "the bounded server must still serve the request: {out}");
    // The server exits ON ITS OWN with code 0 (not SIGKILL'd).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match server.0.try_wait().expect("try_wait") {
            Some(status) => {
                assert!(status.success(), "a bounded server exits 0: {status}");
                break;
            }
            None => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the bounded server must exit on its own"
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

/// Dev-build only: section 2 emits a canned document through
/// `nsm::emit_dev_document`, which the real (`--features nsm`) build
/// intentionally does not compile — the NSM path has no dev emitter.
#[cfg(not(feature = "nsm"))]
#[test]
fn probe_deep_walls_refuse_missing_documents_and_bad_signatures() {
    use qsv_cosigner::protocol::{SignRequest, SignResponse, PROTOCOL_VERSION};
    use std::io::{Read, Write};

    /// ONE canned answer, built FROM the incoming request (the nonce is
    /// request-bound — the doc must carry it or verification refuses).
    fn canned_server<F>(reply: F) -> u16
    where
        F: Fn(&SignRequest) -> SignResponse + Send + 'static,
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                // REAL framing: 8-byte BE length + payload, both ways.
                let mut len_buf = [0u8; 8];
                if s.read_exact(&mut len_buf).is_ok() {
                    let len = u64::from_be_bytes(len_buf) as usize;
                    let mut buf = vec![0u8; len];
                    if s.read_exact(&mut buf).is_ok() {
                        let req: SignRequest = serde_json::from_slice(&buf).expect("request json");
                        let resp = reply(&req);
                        let body = serde_json::to_vec(&resp).expect("response json");
                        let _ = s.write_all(&(body.len() as u64).to_be_bytes());
                        let _ = s.write_all(&body);
                    }
                }
            }
        });
        port
    }

    let vault = "probe-vault";
    let seed = [42u8; 32];
    let pcr0 = hex::encode(qsv_cosigner::nsm::dev_measurement(&seed));
    let xonly = hex::encode(
        qsv_pqc::enclave_xonly_public_key(&qsv_pqc::enclave_keypair_from_seed(&seed).unwrap())
            .serialize(),
    );
    // 1. accepted WITHOUT an attestation document → the v2 wall fires
    //    before any crypto (exit 1, exact contract on the output).
    let port = canned_server(|_req| SignResponse {
        version: PROTOCOL_VERSION,
        accepted: true,
        reason: None,
        schnorr_sig_hex: Some("aa".repeat(64)),
        attestation_doc_hex: None,
    });
    let (ok, out) = probe(&[
        "--tcp",
        "--port",
        &port.to_string(),
        "--vault",
        vault,
        "--pcr0",
        &pcr0,
        "--xonly",
        &xonly,
    ]);
    assert!(!ok, "a missing attestation document must be refused: {out}");
    assert!(
        out.contains("WITHOUT an attestation document"),
        "expected the v2 wall: {out}"
    );

    // 2. accepted WITH a VALID dev document but a GARBAGE signature →
    //    the doc verifies (pins + nonce bind) and the co-signature
    //    verification fails closed.
    let port = canned_server(move |req| {
        let nonce: [u8; 32] = hex::decode(&req.nonce_hex)
            .expect("nonce is hex")
            .try_into()
            .expect("nonce is 32 bytes");
        let xonly_pk =
            qsv_pqc::enclave_xonly_public_key(&qsv_pqc::enclave_keypair_from_seed(&seed).unwrap());
        let user_data = qsv_cosigner::nsm::enclave_user_data(&xonly_pk, vault);
        let doc = qsv_cosigner::nsm::emit_dev_document(&seed, &nonce, &user_data)
            .expect("dev document builds");
        SignResponse {
            version: PROTOCOL_VERSION,
            accepted: true,
            reason: None,
            schnorr_sig_hex: Some("bb".repeat(64)),
            attestation_doc_hex: Some(hex::encode(doc)),
        }
    });
    let (ok, out) = probe(&[
        "--tcp",
        "--port",
        &port.to_string(),
        "--vault",
        vault,
        "--pcr0",
        &pcr0,
        "--xonly",
        &xonly,
    ]);
    assert!(!ok, "a bad co-signature must be refused: {out}");
    assert!(
        out.contains("does not verify under the pinned key"),
        "expected the signature wall: {out}"
    );
}

/// The probe's whole argument surface fails CLOSED: every usage mistake is
/// exit 2 with the exact contract on stderr, the dev build's `--cid`
/// (AF_VSOCK) path is a transport refusal, and `--pcr1/--pcr2` are parsed
/// (a wrong pin refuses only at verification, never at parse time).
#[test]
fn probe_argument_surface_fails_closed() {
    let zero_pcr = "00".repeat(48);
    let key = "11".repeat(32);

    // Dev build: AF_VSOCK has no stack → transport refusal (exit 1).
    let (ok, out) = probe(&[
        "--cid", "16", "--port", "5005", "--vault", "v", "--pcr0", &zero_pcr, "--xonly", &key,
    ]);
    assert!(!ok, "vsock must never silently succeed in dev: {out}");
    assert!(out.contains("transport"), "transport refusal: {out}");

    // Both transports at once → usage error.
    let (ok, out) = probe(&[
        "--tcp", "--cid", "16", "--port", "9", "--vault", "v", "--pcr0", &zero_pcr, "--xonly", &key,
    ]);
    assert!(!ok, "two transports must be refused: {out}");
    assert!(out.contains("need exactly one of"), "{out}");

    // Missing --xonly → usage error.
    let (ok, out) = probe(&["--tcp", "--port", "9", "--vault", "v", "--pcr0", &zero_pcr]);
    assert!(!ok, "missing --xonly must be refused: {out}");
    assert!(out.contains("--xonly is required"), "{out}");

    // Unknown flag → usage error.
    let (ok, out) = probe(&["--bogus"]);
    assert!(!ok, "unknown flag must be refused: {out}");
    assert!(out.contains("unknown argument"), "{out}");

    // --pcr1/--pcr2 are PARSED; nothing listens on the port, so the
    // transport refuses — the pin comparison never gets to run.
    let (ok, out) = probe(&[
        "--tcp", "--port", "9", "--vault", "v", "--pcr0", &zero_pcr, "--pcr1", &zero_pcr, "--pcr2",
        &zero_pcr, "--xonly", &key,
    ]);
    assert!(!ok, "an empty port must refuse: {out}");
    assert!(out.contains("transport"), "{out}");
}

/// Round 29 P5 completion: `--max-requests N` turns the serve loop into a
/// NORMALLY-EXITING child — N connections are served, the loop returns
/// `Ok`, the process exits 0 on its own. Unlike SIGKILL (whose `.profraw`
/// is never flushed), this child carries its own startup coverage out
/// with it, which is exactly what `cargo llvm-cov` needs to score
/// `enclave_server.rs` honestly.
#[test]
fn bounded_server_serves_n_then_exits_zero() {
    use std::net::TcpStream;

    let (mut server, _, _, bport) = spawn_server(
        &[
            "--port",
            &fresh_port().to_string(),
            "--vault",
            "e2e-vault",
            "--max-requests",
            "1",
        ],
        None,
    );

    // E2E_READY prints BEFORE the bind — poll until the listener is up.
    // This connect is also the ONE request: an empty probe is answered
    // with a refusal (never a crash) and counts toward the bound.
    let mut connected = false;
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", bport)) {
            drop(s);
            connected = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(connected, "bounded server must bind and accept");

    // The child now returns Ok from the serve loop → exit 0 by itself.
    let status = server.0.wait().expect("wait for the bounded child");
    assert!(
        status.success(),
        "expected a NORMAL exit 0 (profraw flush), got {status:?}"
    );

    // Usage wall: the bound must be an integer >= 1.
    let out = Command::new(env!("CARGO_BIN_EXE_enclave_server"))
        .args(["--port", &fresh_port().to_string(), "--max-requests", "0"])
        .output()
        .expect("spawn enclave_server");
    assert_eq!(
        out.status.code(),
        Some(2),
        "--max-requests 0 must be a usage error"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--max-requests needs an integer >= 1"),
        "{err}"
    );
}
