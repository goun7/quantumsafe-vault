//! Interface tests for `qsv-cli console` (roadmap slice 1).
//!
//! The REAL binary is the interface: one JSON document on stdout, a
//! self-contained HTML file on disk, and a fail-closed refusal for a
//! descriptor that is not this vault's.

use std::process::{Command, Output};

fn qsv(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args(args)
        .output()
        .expect("qsv-cli runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

#[test]
fn json_is_one_document_with_the_schema_and_live_clocks() {
    let out = qsv(&[
        "console",
        "--network",
        "signet",
        "--tip",
        "900100",
        "--last-refresh-block",
        "900000",
        "--label",
        "Test vault",
        "--json",
    ]);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let stdout = text(&out.stdout);
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON document");
    assert_eq!(doc["schema"], "qsv-console/v1");
    assert_eq!(doc["network"], "signet");
    assert!(doc["address"].as_str().unwrap().starts_with("tb1p"));
    assert_eq!(doc["descriptor_verified"], false);
    assert_eq!(doc["clocks"]["blocks_until_inheritance"], 26_180);
    assert_eq!(doc["clocks"]["blocks_until_clawback_close"], 44);
    assert_eq!(doc["clocks"]["blocks_until_refresh"], 12_860);
    let letter = doc["letter"].as_str().unwrap();
    assert!(letter.len() > 500, "the estate letter is embedded");
    assert_eq!(doc["letter_sha256"].as_str().unwrap().len(), 64);
    // Machine output: no banner before the document, no footer after it.
    assert!(stdout.trim_start().starts_with('{'));
    assert!(stdout.trim_end().ends_with('}'));
}

#[test]
fn a_foreign_descriptor_is_refused_with_empty_stdout() {
    let out = qsv(&[
        "console",
        "--network",
        "signet",
        "--descriptor",
        "rawtr(0000000000000000000000000000000000000000000000000000000000000000)",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(1), "refusal is a failure exit");
    assert!(
        out.stdout.is_empty(),
        "a refused run must not print a snapshot: {}",
        text(&out.stdout)
    );
    assert!(
        text(&out.stderr).contains("does not match this vault"),
        "stderr says why: {}",
        text(&out.stderr)
    );
}

#[test]
fn the_vaults_own_descriptor_is_verified() {
    let exported = qsv(&["vault-descriptor", "--network", "signet", "--json"]);
    assert!(exported.status.success());
    let doc: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    let rawtr = doc["descriptors"]["rawtr"].as_str().unwrap().to_string();

    let out = qsv(&[
        "console",
        "--network",
        "signet",
        "--tip",
        "900000",
        "--descriptor",
        &rawtr,
        "--json",
    ]);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let console: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(console["descriptor_verified"], true);
    assert_eq!(console["descriptors"]["rawtr"], rawtr);
    assert_eq!(console["address"], doc["address"]);
}

#[test]
fn the_html_page_is_written_and_needs_no_javascript() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("console.html");
    let out = qsv(&[
        "console",
        "--network",
        "signet",
        "--tip",
        "900000",
        "--out",
        path.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", text(&out.stderr));
    let html = std::fs::read_to_string(&path).expect("page written");
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("Vault Console"));
    assert!(html.contains("tb1p"), "the address is on the page");
    assert!(!html.contains("<script"), "zero JavaScript");
    assert!(!html.contains("http://") && !html.contains("https://"));
    assert!(html.contains("do not use with real funds"));
    assert!(
        text(&out.stdout).contains("Console written"),
        "the operator is told where the page went"
    );
}
