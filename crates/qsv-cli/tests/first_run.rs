//! FIRST RUN (roadmap slice D2): `qsv-cli demo` is the only command a new
//! user meets before reading anything. Two properties are load-bearing and
//! are pinned here, against the REAL binary:
//!
//!   1. It works offline, with no arguments, and writes a page it can prove
//!      it wrote (read-back, byte length, SHA-256) — never a claim without
//!      the artifact behind it.
//!   2. It is the SAME renderer as `console`: given the same inputs the two
//!      commands produce byte-identical pages, so the demo cannot silently
//!      drift from the operator surface it introduces.
//!
//! Both are offline: no node, no network, no key material.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

fn qsv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_qsv-cli")
}

fn run(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(qsv_bin())
        .args(args)
        .current_dir(dir)
        .output()
        .expect("spawn qsv-cli");
    (
        out.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn demo_writes_a_self_contained_page_offline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (code, out) = run(dir.path(), &["demo"]);
    assert_eq!(code, 0, "demo must exit 0: {out}");

    let page = dir.path().join("qsv-demo.html");
    let html = std::fs::read_to_string(&page).expect("default page qsv-demo.html must exist");

    // SELF-CONTAINED: the page must open on an air-gapped machine. A <script>
    // tag or a remote stylesheet/font would make that a false promise (and
    // the console's first rule is "zero JavaScript, zero network").
    for forbidden in ["<script", "http://", "https://", "srcset=", "@import"] {
        assert!(
            !html.contains(forbidden),
            "demo page must be self-contained, found {forbidden:?}"
        );
    }

    // The artifact says what it is: an offline rehearsal on demo keys.
    assert!(
        html.contains("Demo vault"),
        "demo label missing: {html:.400}"
    );
    assert!(
        html.contains("offline rehearsal"),
        "the page must announce that it is a rehearsal"
    );
    assert!(
        html.contains("<code>signet</code>"),
        "signet default missing"
    );
    // The three clocks and the letter are the actual content.
    assert!(html.contains("Heartbeat"));
    assert!(html.contains("Inheritance (CSV 26,280)"));
    assert!(html.contains("Estate letter"));

    // stdout must report the SAME artifact: path, size, letter hash.
    assert!(out.contains("Demo page written"), "{out}");
    assert!(out.contains(&format!("{} bytes", html.len())), "{out}");
    assert!(
        out.contains(&sha256_hex(html.as_bytes())[..8]),
        "stdout must carry the page hash: {out}"
    );
}

#[test]
fn demo_and_console_render_the_same_page_for_the_same_inputs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (code, out) = run(dir.path(), &["demo", "--out", "a.html"]);
    assert_eq!(code, 0, "{out}");
    let (code, out) = run(dir.path(), &["demo", "--out", "b.html"]);
    assert_eq!(code, 0, "{out}");
    let a = std::fs::read(dir.path().join("a.html")).expect("a.html");
    let b = std::fs::read(dir.path().join("b.html")).expect("b.html");
    assert_eq!(a, b, "demo must be deterministic for identical inputs");

    let (code, out) = run(
        dir.path(),
        &[
            "console",
            "--network",
            "signet",
            "--tip",
            "900000",
            "--label",
            "Demo vault — offline rehearsal (throwaway demo keys)",
            "--out",
            "c.html",
        ],
    );
    assert_eq!(code, 0, "{out}");
    let c = std::fs::read(dir.path().join("c.html")).expect("c.html");
    assert_eq!(
        a, c,
        "demo must be the console renderer, not a second one: same inputs, same bytes"
    );
}

#[test]
fn demo_json_is_one_bare_document_describing_the_real_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let out_file = Command::new(qsv_bin())
        .args(["demo", "--json", "--out", "page.html"])
        .current_dir(dir.path())
        .output()
        .expect("spawn qsv-cli");
    assert!(out_file.status.success());

    let stdout = String::from_utf8_lossy(&out_file.stdout);
    assert!(
        stdout.trim_start().starts_with('{'),
        "machine output must carry NO banner: {stdout}"
    );
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("one JSON document");
    assert_eq!(doc["schema"], "qsv-demo/v1");
    assert_eq!(doc["offline"], true);
    assert_eq!(doc["network"], "signet");

    let page = dir.path().join("page.html");
    let html = std::fs::read(&page).expect("page.html");
    assert_eq!(doc["bytes"].as_u64(), Some(html.len() as u64));
    assert_eq!(doc["html_sha256"], sha256_hex(&html));
    assert_eq!(
        doc["out"].as_str(),
        Some(page.display().to_string().as_str())
    );
    assert_eq!(doc["address"].as_str().map(str::len), Some(62)); // P2TR bech32m
}

#[test]
fn demo_refuses_to_announce_a_page_it_could_not_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("no-such-dir").join("page.html");
    let (code, out) = run(
        dir.path(),
        &["demo", "--out", missing.to_str().expect("utf8 path")],
    );
    assert_eq!(code, 1, "an unwritable page is a runtime failure: {out}");
    assert!(out.contains("cannot write"), "{out}");
}
