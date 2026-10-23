//! Live end-to-end proof of the estate-letter workflow (docs/10 §4.5).
//!
//! The printable letter — including its `QSV1|…` QR payload — is issued by
//! the real CLI binary, verified independently, then the address it commits
//! to is funded on a REAL bitcoind (regtest) and read back through the node.
//! Finally a single flipped character must make `verify-estate` exit 1.
//!
//! If no bitcoind binary is available for this platform the test soft-skips,
//! exactly like the qsv-node lifecycle test.

use std::process::Command;

use bitcoind::serde_json;

/// Runs the real `qsv-cli` binary and returns its output.
fn qsv(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args(args)
        .output()
        .expect("qsv-cli binary must run")
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

/// Index of the first 64-hex-char run (an identity field) in the letter.
fn first_hex64(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut run = 0usize;
    let mut start = 0usize;
    for (i, b) in bytes.iter().enumerate() {
        if b.is_ascii_hexdigit() {
            if run == 0 {
                start = i;
            }
            run += 1;
            if run == 64 {
                return Some(start);
            }
        } else {
            run = 0;
        }
    }
    None
}

#[test]
fn estate_letter_qr_verify_and_live_funding() {
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;
    let dir = tempfile::tempdir().expect("temp dir");
    let letter = dir.path().join("letter.txt");

    // 1. Issue the letter with a QR block for regtest.
    let out = qsv(&[
        "estate-letter",
        "--network",
        "regtest",
        "--qr",
        "--label",
        "E2E family vault",
        "--date",
        "2026-09-28",
    ]);
    assert!(
        out.status.success(),
        "estate-letter failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("utf8");
    std::fs::write(&letter, &text).expect("save letter");

    // 2. The QR payload is the five-field §1 identity and carries the same
    //    address the letter prints in prose.
    let payload_line = text
        .lines()
        .find(|l| l.starts_with("payload: "))
        .expect("QR payload line present when --qr is passed");
    let payload = payload_line.trim_start_matches("payload: ");
    let fields: Vec<&str> = payload.split('|').collect();
    assert_eq!(fields.len(), 5, "QSV1 payload has five fields");
    assert_eq!(fields[0], "QSV1");
    assert_eq!(fields[1], "regtest");
    let address = fields[2];
    assert!(address.starts_with("bcrt1p"), "regtest P2TR address");
    assert_eq!(fields[3].len(), 64, "merkle root hex");
    assert_eq!(fields[4].len(), 64, "output key hex");
    assert!(text.contains(&format!("Vault address (regtest): {address}")));

    // 3. Independent verification of the saved copy: 8/8 checks.
    let verify = qsv(&[
        "verify-estate",
        "--file",
        letter.to_str().unwrap(),
        "--network",
        "regtest",
    ]);
    let verify_out = String::from_utf8_lossy(&verify.stdout);
    assert!(
        verify.status.success(),
        "verify-estate failed: {verify_out}{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(
        verify_out.contains("PASS (8/8)"),
        "expected 8/8, got: {verify_out}"
    );

    // 4. `vault-setup` reports the SAME address — one provisioning identity.
    let setup = qsv(&["vault-setup", "--network", "regtest"]);
    let setup_out = String::from_utf8_lossy(&setup.stdout);
    assert!(
        setup_out.contains(address),
        "vault-setup must report the letter's address: {setup_out}"
    );

    // 5. Fund the letter's address on the live chain and read it back.
    mine!(rpc, 101);
    let funded: bitcoin::Txid = rpc
        .call(
            "sendtoaddress",
            &[serde_json::json!(address), serde_json::json!(5.0f64)],
        )
        .unwrap();
    mine!(rpc, 1);

    let details: serde_json::Value = rpc
        .call("gettransaction", &[serde_json::json!(funded.to_string())])
        .unwrap();
    let mut vout: Option<u64> = None;
    if let Some(rows) = details["details"].as_array() {
        for d in rows {
            if d["category"].as_str() == Some("send") && d["vout"].is_u64() {
                vout = Some(d["vout"].as_u64().unwrap());
                break;
            }
        }
    }
    let vout = vout.expect("vault output index in the funding tx");
    let utxo = rpc
        .get_tx_out(funded, vout)
        .expect("the letter's address is a live, funded UTXO on regtest");
    assert!(utxo.confirmations >= 1);
    assert!(bitcoin::Amount::from_btc(utxo.value).unwrap() > bitcoin::Amount::from_sat(100_000));

    // 6. A single flipped character in an identity field ⇒ exit code 1.
    let s = first_hex64(&text).expect("letter carries a 64-hex identity field");
    let mut tampered = text.as_bytes().to_vec();
    let replacement = if tampered[s] == b'0' { b'1' } else { b'0' };
    tampered[s] = replacement;
    let tampered = String::from_utf8(tampered).expect("ascii letter");
    assert_ne!(tampered, text);
    let bad = dir.path().join("tampered.txt");
    std::fs::write(&bad, &tampered).expect("write tampered letter");
    let reject = qsv(&[
        "verify-estate",
        "--file",
        bad.to_str().unwrap(),
        "--network",
        "regtest",
    ]);
    assert_eq!(
        reject.status.code(),
        Some(1),
        "tampered letter must exit 1: {}",
        String::from_utf8_lossy(&reject.stdout)
    );
    assert!(
        String::from_utf8_lossy(&reject.stdout).contains("RESULT: FAIL"),
        "the failure must be reported to the operator"
    );
}
