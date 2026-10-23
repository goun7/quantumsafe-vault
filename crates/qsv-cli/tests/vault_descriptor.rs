//! Watch-only descriptor export (docs/10 §4.59).
//!
//! Three layers of proof, in increasing strength:
//!
//! 1. The exported `addr()` / `rawtr()` descriptors describe the SAME demo
//!    vault every other command reports (address, output key, merkle root
//!    cross-checked against `vault-setup` and the estate letter's QR
//!    payload) and carry a well-formed 8-character BIP-380 checksum.
//! 2. The human output hands over exactly those two strings and points at
//!    §4.59 for why there is no `tr(...)`.
//! 3. A REAL Bitcoin Core (regtest, v28.2) parses both, recomputes the SAME
//!    checksum as ground truth, imports them, and — after the vault address
//!    is funded on the live chain — reports that UTXO through the imported
//!    watch-only descriptor. That is the feature's actual purpose.
//!
//! If no bitcoind binary is available for this platform the test soft-skips,
//! exactly like the other regtest tests.

use std::process::Command;

use bitcoind::serde_json;

/// Runs the real `qsv-cli` binary and returns its output.
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

/// `desc#checksum` → the 8-character checksum half, or a clear panic.
fn checksum_of(desc: &str) -> &str {
    let (_, ck) = desc.rsplit_once('#').unwrap_or_else(|| {
        panic!("descriptor must carry a BIP-380 checksum: {desc}");
    });
    assert_eq!(ck.len(), 8, "checksum is 8 chars: {desc}");
    assert!(
        ck.chars()
            .all(|c| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".chars().any(|d| d == c)),
        "checksum uses the bech32 charset: {desc}"
    );
    ck
}

#[test]
fn watch_only_descriptors_are_the_demo_vault_and_real_bitcoin_core_uses_them() {
    // ── 1. JSON export: self-consistent, checksummed, one identity ──
    let out = qsv(&["vault-descriptor", "--network", "regtest", "--json"]);
    assert!(
        out.status.success(),
        "vault-descriptor failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // stdout must be exactly ONE JSON document (the --json contract).
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON document");
    let addr = doc["address"].as_str().expect("address").to_string();
    assert!(addr.starts_with("bcrt1p"), "regtest P2TR address: {addr}");

    let addr_desc = doc["descriptors"]["addr"]
        .as_str()
        .expect("addr desc")
        .to_string();
    let rawtr_desc = doc["descriptors"]["rawtr"]
        .as_str()
        .expect("rawtr desc")
        .to_string();
    assert!(
        addr_desc.starts_with(&format!("addr({addr})#")),
        "{addr_desc}"
    );
    let output_key = doc["output_key"].as_str().expect("output key").to_string();
    assert!(
        rawtr_desc.starts_with(&format!("rawtr({output_key})#")),
        "{rawtr_desc}"
    );
    checksum_of(&addr_desc);
    checksum_of(&rawtr_desc);

    // The scriptPubKey is `OP_1 <output key>` — both descriptors expand to it.
    assert_eq!(
        doc["script_pubkey"].as_str().unwrap(),
        format!("5120{output_key}")
    );
    // The tree commitment is exported too, and no tr() is claimed.
    assert_eq!(doc["merkle_root"].as_str().unwrap().len(), 64);
    assert_eq!(doc["leaf_hashes"].as_array().unwrap().len(), 4);
    assert_eq!(doc["tr_exportable"], serde_json::json!(false));

    // ── 2. The SAME vault as every other command (one provisioning identity) ──
    let setup = qsv(&["vault-setup", "--network", "regtest"]);
    let setup_out = String::from_utf8_lossy(&setup.stdout);
    assert!(
        setup_out.contains(&addr),
        "vault-setup must report the descriptor's address: {setup_out}"
    );

    let letter = qsv(&["estate-letter", "--network", "regtest", "--qr"]);
    let letter_out = String::from_utf8_lossy(&letter.stdout);
    let payload = letter_out
        .lines()
        .find(|l| l.starts_with("payload: "))
        .expect("QR payload line")
        .trim_start_matches("payload: ")
        .to_string();
    let fields: Vec<&str> = payload.split('|').collect();
    assert_eq!(fields.len(), 5, "QSV1 payload: {payload}");
    assert_eq!(fields[0], "QSV1");
    assert_eq!(fields[2], addr, "letter and descriptor name one address");
    assert_eq!(fields[3], doc["merkle_root"].as_str().unwrap());
    assert_eq!(fields[4], output_key);

    // ── 3. The human output hands over exactly those two strings ──
    let human = qsv(&["vault-descriptor", "--network", "regtest"]);
    assert!(human.status.success());
    let human_out = String::from_utf8_lossy(&human.stdout);
    assert!(human_out.contains(&addr_desc), "human: {human_out}");
    assert!(human_out.contains(&rawtr_desc), "human: {human_out}");
    assert!(
        human_out.contains("§4.59"),
        "the operator must be told where the honest limitation is written"
    );
    // ...and it must not claim a tr() descriptor.
    assert!(
        !human_out.lines().any(|l| l.trim_start().starts_with("tr(")),
        "no tr(...) descriptor may be offered: {human_out}"
    );

    // ── 4. REAL reader: Bitcoin Core parses, checksums, expands, imports ──
    let Some(btc) = node_available() else { return };
    let rpc = &btc.client;

    // (a) Parse + BIP-380 checksum ground truth: Core recomputes the SAME
    //     checksum for both forms.
    for desc in [&addr_desc, &rawtr_desc] {
        let info: serde_json::Value = rpc
            .call("getdescriptorinfo", &[serde_json::json!(desc)])
            .unwrap_or_else(|e| panic!("Core rejected {desc}: {e}"));
        assert_eq!(
            info["checksum"].as_str(),
            Some(checksum_of(desc)),
            "Core's checksum differs for {desc}: {info}"
        );
    }

    // (b) Core EXPANDS both descriptors to the very same address — addr()
    //     by the bech32m program, rawtr() by the tweaked output key.
    for desc in [&addr_desc, &rawtr_desc] {
        let derived: Vec<String> = rpc
            .call("deriveaddresses", &[serde_json::json!(desc)])
            .unwrap_or_else(|e| panic!("Core could not derive {desc}: {e}"));
        assert_eq!(derived, vec![addr.clone()], "Core's expansion of {desc}");
    }

    // (c) Import BOTH into a BLANK wallet without private keys — the only
    //     wallet class Core accepts watch-only descriptors in (a
    //     private-key wallet refuses them with -4, observed while writing
    //     this test). The call goes to `/wallet/qsvwatch`: the root endpoint
    //     pins wallet methods to the harness's startup `default` wallet.
    let _: serde_json::Value = rpc
        .call(
            "createwallet",
            &[
                serde_json::json!("qsvwatch"),
                serde_json::json!(true),
                serde_json::json!(true),
            ],
        )
        .expect("create the blank watch-only wallet");
    // Wallet-scoped endpoint: the root endpoint only answers wallet methods
    // when a single wallet is loaded, and pins to the startup one otherwise.
    let watch = qsv_node::rpc::BitcoinRpc::from_cookie_with_port(
        std::path::Path::new(&btc.workdir()),
        qsv_node::rpc::Network::Regtest,
        btc.params.rpc_socket.port(),
    )
    .expect("wallet-capable RPC client over the node cookie");
    let imported: serde_json::Value = watch
        .call_wallet(
            "qsvwatch",
            "importdescriptors",
            &[serde_json::json!([
                { "desc": addr_desc, "timestamp": "now" },
                { "desc": rawtr_desc, "timestamp": "now" },
            ])],
        )
        .expect("importdescriptors RPC");
    for row in imported.as_array().expect("one row per descriptor") {
        assert_eq!(
            row["success"],
            serde_json::json!(true),
            "import failed: {row}"
        );
    }

    // (d) Fund the vault address on the live chain (mined straight to it,
    //     so no private key is involved anywhere in the loop) …
    let _: serde_json::Value = rpc
        .call(
            "generatetoaddress",
            &[serde_json::json!(101), serde_json::json!(addr)],
        )
        .expect("mine to the vault address");

    // … and the IMPORTED descriptors now report those UTXOs: the
    // independent balance verification this feature exists for.
    let unspent: serde_json::Value = watch
        .call_wallet(
            "qsvwatch",
            "listunspent",
            &[
                serde_json::json!(1),
                serde_json::json!(999_999),
                serde_json::json!([addr]),
                serde_json::json!(true),
            ],
        )
        .expect("listunspent on the watch-only wallet");
    let rows = unspent.as_array().expect("unspent array");
    assert!(
        !rows.is_empty(),
        "the imported watch-only descriptor must see the funded vault output: {unspent}"
    );
    assert_eq!(rows[0]["address"].as_str(), Some(addr.as_str()));
    assert!(
        rows[0]["amount"].as_f64().unwrap_or(0.0) > 4.9,
        "the watched value: {}",
        rows[0]
    );
}
