//! `qsv-cli docs-audit` — the documentation report (docs/10 §4.63, Round 40).
//!
//! The engine lives in `qsv_core::docs` and its walls are the same ones
//! `docs_sync` asserts. These tests exercise the INTERFACE an operator (or a
//! scripted audit) actually uses: the binary, its stdout discipline, its exit
//! codes — 0 in sync, 1 drift, 2 unreadable/empty tree — and the JSON
//! document that carries the same verdict without a banner in front of it.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_qsv-cli")
}

fn repo_docs() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs"))
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("qsv-cli runs");
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A throwaway docs tree. The gate's TMPDIR preflight already guarantees a
/// writable, home-free temp root.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(tag: &str, files: &[(&str, &str)]) -> Self {
        let dir = std::env::temp_dir().join(format!("qsv_cli_audit_{}_{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create docs dir");
        for (name, body) in files {
            std::fs::write(dir.join(name), body).expect("write fixture file");
        }
        Self { dir }
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const CLEAN: &str = "\
# Module 01 — Quantum Threat Model

## 1. Intro

- one
- two
";

#[test]
fn the_repository_report_is_in_sync_and_exits_zero() {
    let dir = repo_docs();
    let (code, stdout, stderr) = run(&["docs-audit", "--dir", dir.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("DOCS AUDIT: OK (11 modules, 0 structural drifts)"),
        "stdout tail: {}",
        &stdout[stdout.len().saturating_sub(300)..]
    );
    // Every module row is present, with its file named.
    for module in [
        "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11",
    ] {
        assert!(
            stdout.contains(&format!("  {module:>6}  ")),
            "module {module} missing from the report"
        );
    }
    assert!(stdout.contains("10_operations_guide.md"));
}

#[test]
fn an_in_sync_tree_reports_ok_and_exits_zero() {
    let f = Fixture::new("ok", &[("01_quantum_threat_model.md", CLEAN)]);
    let (code, stdout, stderr) = run(&["docs-audit", "--dir", f.path().to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("DOCS AUDIT: OK (1 module, 0 structural drifts)"),
        "{stdout}"
    );
    assert!(stdout.contains("01_quantum_threat_model.md"), "{stdout}");
}

#[test]
fn a_synthetic_drift_is_reported_and_exits_one() {
    // A dead link plus an unclosed fence: two kinds, two details.
    let doc = "\
# Module 01 — Broken

## 1. Intro

[gone](missing.md)

```bash
ls
";
    let f = Fixture::new("drift", &[("01_broken.md", doc)]);
    let (code, stdout, stderr) = run(&["docs-audit", "--dir", f.path().to_str().unwrap()]);
    assert_eq!(code, 1, "drift must exit 1 (stderr: {stderr})");
    assert!(stderr.contains("DOCS AUDIT: DRIFT"), "stderr: {stderr}");
    for kind in ["[link]", "[fence]"] {
        assert!(stdout.contains(kind), "missing {kind} in:\n{stdout}");
    }
    // The report names the target, not just the verdict.
    assert!(stdout.contains("missing.md"), "{stdout}");
}

#[test]
fn json_output_is_one_document_with_the_same_verdict() {
    let (code, stdout, stderr) = run(&["docs-audit", "--json"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.trim_start().starts_with('{'),
        "--json must not print a banner: {stdout}"
    );
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(doc["in_sync"], serde_json::json!(true));
    assert_eq!(doc["drift_count"], serde_json::json!(0));
    assert_eq!(doc["modules"].as_array().expect("modules array").len(), 11);
    assert_eq!(doc["modules"][9]["module"], serde_json::json!("10"));
    assert_eq!(
        doc["modules"][0]["file"],
        serde_json::json!("01_quantum_threat_model.md")
    );
    assert_eq!(doc["modules"][0]["drifts"], serde_json::json!([]));
    assert!(doc["modules"][0]["words"].as_u64().expect("words") > 500);
}

#[test]
fn an_unreadable_tree_is_a_usage_error_not_a_green() {
    let missing = std::env::temp_dir().join("qsv_cli_audit_does_not_exist");
    let _ = std::fs::remove_dir_all(&missing);
    let (code, stdout, stderr) = run(&["docs-audit", "--dir", missing.to_str().unwrap()]);
    assert_eq!(code, 2, "usage error must be exit 2");
    assert!(stdout.trim().is_empty(), "stdout must stay empty: {stdout}");
    assert!(stderr.contains("cannot list"), "stderr: {stderr}");
}

#[test]
fn an_empty_tree_is_refused_instead_of_reported_green() {
    let f = Fixture::new("empty", &[("README.md", "# Library\n")]);
    let (code, stdout, stderr) = run(&["docs-audit", "--dir", f.path().to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(stdout.trim().is_empty());
    assert!(stderr.contains("no numbered module documents"), "{stderr}");
}
