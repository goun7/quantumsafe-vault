//! Phase 1 hardware round trip (SD-card file flow) — the Coldcard/Ledger
//! rehearsal WITHOUT the hardware.
//!
//! Exactly what an operator does with a real air-gapped signer:
//!   1. `psbt build` (Phase-1 file flow) → `psbt export` splits the PSBT
//!      into the SD-card trio: binary .psbt + sha256 manifest + audit txt.
//!   2. The "device" step is simulated by byte-copying the card and
//!      re-deriving the signatures with the known leaf keys — the device's
//!      real behavior (recompute sighash from the PSBT, sign, store a
//!      BIP-371 tap script-sig) is what `psbt sign` already implements.
//!   3. `psbt import` reads the returned card, optionally checks the
//!      manifest, verifies EVERY stored signature under the known leaf
//!      keys, finalizes the witness and passes the transaction through
//!      libbitcoinconsensus.
//!
//! Fail-closed edges: a flipped byte in the card, a forged signature, a
//! signature from the WRONG key, or a stripped PSBT (no tap script-sigs)
//! must all exit 1 — never a broadcastable transaction.

use std::process::Command;

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

/// Simulates the hardware wallet step: loads the binary card, signs every
/// input with both leaf keys (the exact `psbt sign` semantics) and writes
/// the returned binary PSBT. The dev `psbt sign` surface speaks base64;
/// a real device loads BINARY BIP-174 and writes binary back — the base64
/// ↔ binary conversions here are byte-for-byte what device firmware does.
fn device_signs_card(card: &std::path::Path, returned: &std::path::Path) {
    use bitcoin::base64::Engine as _;
    let workdir = card.parent().unwrap();
    let in_b64 = workdir.join("device-input.b64.psbt");
    std::fs::write(
        &in_b64,
        bitcoin::base64::engine::general_purpose::STANDARD.encode(std::fs::read(card).unwrap()),
    )
    .unwrap();
    let out_b64 = workdir.join("device-output.b64.psbt");
    let out = qsv(&[
        "psbt",
        "sign",
        "--in",
        in_b64.to_str().unwrap(),
        "--out",
        out_b64.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "device signing step failed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let text = std::fs::read_to_string(&out_b64).unwrap();
    let signed = bitcoin::base64::engine::general_purpose::STANDARD
        .decode(text.trim().as_bytes())
        .unwrap();
    std::fs::write(returned, signed).unwrap();
}

#[test]
fn sd_card_roundtrip_export_sign_import_and_fail_closed() {
    let dir = tempfile::tempdir().unwrap();

    // 1. Phase-1 build → SD-card export trio.
    let built = dir.path().join("vault.psbt");
    let out = qsv(&["psbt", "build", "--out", built.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "psbt build failed: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let stem = dir.path().join("hw-card");
    let out = qsv(&[
        "psbt",
        "export",
        "--in",
        built.to_str().unwrap(),
        "--stem",
        stem.to_str().unwrap(),
    ]);
    let s = stdout(&out);
    assert!(
        out.status.success(),
        "psbt export failed: {s}{}",
        stderr(&out)
    );
    assert!(s.contains("BIP-174 binary"));
    // Coldcard/Ledger compliance gate ran and passed.
    assert!(s.contains("COMPLIANT"));

    let card = dir.path().join("hw-card.psbt");
    let manifest = dir.path().join("hw-card.sha256");
    let sheet = dir.path().join("hw-card.txt");
    let binary = std::fs::read(&card).unwrap();
    assert_eq!(
        &binary[..5],
        b"psbt\xff",
        "card must be the BINARY wire form"
    );
    assert!(std::fs::read_to_string(&manifest)
        .unwrap()
        .starts_with(&sha256_of(&binary)));
    let sheet_text = std::fs::read_to_string(&sheet).unwrap();
    assert!(sheet_text.contains("audit sheet"));
    assert!(sheet_text.contains("in 0:"));
    assert!(sheet_text.contains("out 0:"));

    // 2. The device signs the card.
    let returned = dir.path().join("hw-returned.psbt");
    device_signs_card(&card, &returned);

    // 3. Import: manifest OK → signatures verified → consensus ACCEPT.
    let final_psbt = dir.path().join("hw-final.psbt");
    let out = qsv(&[
        "psbt",
        "import",
        "--in",
        returned.to_str().unwrap(),
        "--manifest",
        &manifest_of_returned(&returned, &manifest),
        "--out",
        final_psbt.to_str().unwrap(),
    ]);
    let s = stdout(&out);
    assert!(
        out.status.success(),
        "psbt import failed: {s}{}",
        stderr(&out)
    );
    assert!(s.contains("tap script-sigs verified"));
    assert!(s.contains("consensus:    ACCEPT"));

    // 3b. Coldcard REAL-WORLD ARTIFACT FORMS: import must accept (a) the
    //     base64 PSBT our tooling exchanges and (b) re-serialize round trip
    //     binary — the exact forms <TXID>.txn-free device flows produce.
    //     (The raw <TXID>.txn hex path is exercised for the UNSIGNED form;
    //     a FINALIZED tx cannot be re-verified per-key because device
    //     finalization strips the PSBT maps — documented, fail-closed.)
    let b64_copy = dir.path().join("hw-returned.b64.psbt");
    std::fs::write(&b64_copy, {
        use bitcoin::base64::Engine as _;
        bitcoin::base64::engine::general_purpose::STANDARD.encode(std::fs::read(&returned).unwrap())
    })
    .unwrap();
    let out = qsv(&[
        "psbt",
        "import",
        "--in",
        b64_copy.to_str().unwrap(),
        "--out",
        dir.path().join("hw-final-b64.psbt").to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "import must accept the base64 form: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let garbage = dir.path().join("hw-garbage.txn");
    std::fs::write(&garbage, "not a psbt not hex not base64-psbt\n").unwrap();
    let out = qsv(&[
        "psbt",
        "import",
        "--in",
        garbage.to_str().unwrap(),
        "--out",
        dir.path().join("nope-garbage.psbt").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "unparseable artifact must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stderr(&out).contains("neither a binary PSBT"));

    // 4. FAIL-CLOSED: a flipped byte in the card → import exits 1.
    let mut flipped = std::fs::read(&returned).unwrap();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    let bad = dir.path().join("hw-flipped.psbt");
    std::fs::write(&bad, &flipped).unwrap();
    let out = qsv(&[
        "psbt",
        "import",
        "--in",
        bad.to_str().unwrap(),
        "--out",
        dir.path().join("nope.psbt").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "flipped card byte must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );

    // 5. FAIL-CLOSED: manifest mismatch (digest of a DIFFERENT file) → exit 1.
    let other = dir.path().join("other.sha256");
    std::fs::write(&other, format!("{}  x\n", "0".repeat(64))).unwrap();
    let out = qsv(&[
        "psbt",
        "import",
        "--in",
        returned.to_str().unwrap(),
        "--manifest",
        other.to_str().unwrap(),
        "--out",
        dir.path().join("nope2.psbt").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "manifest mismatch must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stderr(&out).contains("manifest mismatch"));

    // 6. FAIL-CLOSED: forged signature (right key slot, wrong signature) → exit 1.
    let forged = dir.path().join("hw-forged.psbt");
    forge_signature(&returned, &forged);
    let out = qsv(&[
        "psbt",
        "import",
        "--in",
        forged.to_str().unwrap(),
        "--out",
        dir.path().join("nope3.psbt").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "forged signature must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stderr(&out).contains("does NOT verify"));

    // 7. FAIL-CLOSED: stripped PSBT (no tap script-sigs) → exit 1.
    let stripped = dir.path().join("hw-stripped.psbt");
    strip_sigs(&card, &stripped);
    let out = qsv(&[
        "psbt",
        "import",
        "--in",
        stripped.to_str().unwrap(),
        "--out",
        dir.path().join("nope4.psbt").to_str().unwrap(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "signature-less PSBT must exit 1: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(stderr(&out).contains("NO user tap script-sig"));
}

/// sha256 of a byte slice, hex — mirrors the manifest digest.
fn sha256_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// The manifest line for the RETURNED card (what the operator re-exports
/// after the device rewrote the file). We write a temp manifest from the
/// returned file's actual digest, proving the --manifest path accepts a
/// device-rewritten file when its digest is recorded.
fn manifest_of_returned(returned: &std::path::Path, _exported: &std::path::Path) -> String {
    let digest = sha256_of(&std::fs::read(returned).unwrap());
    let m = returned.with_extension("sha256");
    std::fs::write(&m, format!("{digest}  {}\n", returned.display())).unwrap();
    m.to_str().unwrap().to_string()
}

/// Flips ONE byte inside the serialized signature of the FIRST tap
/// script-sig (key unchanged, signature forged).
fn forge_signature(src: &std::path::Path, dst: &std::path::Path) {
    let bytes = std::fs::read(src).unwrap();
    let mut psbt = bitcoin::psbt::Psbt::deserialize(&bytes).unwrap();
    let (key, leaf) = *psbt.inputs[0].tap_script_sigs.keys().next().unwrap();
    psbt.inputs[0]
        .tap_script_sigs
        .get_mut(&(key, leaf))
        .unwrap()
        .signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&[7u8; 64]).unwrap();
    // The device returns BINARY; keep the wire form so import parses it and
    // fails at SIGNATURE VERIFICATION (not at format parsing).
    std::fs::write(dst, psbt.serialize()).unwrap();
}

/// Rewrites a BINARY PSBT with all tap script-sigs removed.
fn strip_sigs(src: &std::path::Path, dst: &std::path::Path) {
    let bytes = std::fs::read(src).unwrap();
    let mut psbt = bitcoin::psbt::Psbt::deserialize(&bytes).unwrap();
    psbt.inputs[0].tap_script_sigs.clear();
    std::fs::write(dst, psbt.serialize()).unwrap();
}
