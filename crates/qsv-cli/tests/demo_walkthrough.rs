//! Offline demo & operator-surface smoke (Round 28): the DEFAULT invocation
//! runs all THREE demos in sequence, and the pure-offline subcommands run
//! on their own. Real binary, real stdout, real exit codes — nothing here
//! touches the network, so every machine runs it.
//!
//! Round 29 additions: the PSBT Phase-1 finish (consensus verdict), the
//! offline vault dashboard (render + both refusal paths) and the K1
//! tracker's offline audit — three operator flows that previously only
//! existed behind `cargo run` (an UNinstrumented child, hence invisible
//! to coverage).

use std::process::Command;

fn qsv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_qsv-cli")
}

/// Runs `qsv-cli` with `args`; returns (exit-ok, stdout+stderr).
fn run(args: &[&str]) -> (bool, String) {
    let out = Command::new(qsv_bin())
        .args(args)
        .output()
        .expect("spawn qsv-cli");
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
fn default_invocation_runs_the_three_demos() {
    let (ok, out) = run(&[]);
    assert!(ok, "demo walkthrough must exit 0: {out}");
    assert!(out.contains("[1] VAULT SETUP"), "demo 1 missing: {out}");
    assert!(out.contains("[2] HYBRID SPEND"), "demo 2 missing: {out}");
    assert!(out.contains("[3] INHERITANCE"), "demo 3 missing: {out}");
    assert!(
        out.contains("All operations completed successfully"),
        "footer missing: {out}"
    );
}

/// Each demo ALSO has a named subcommand dispatcher (the default
/// invocation reaches them through the no-command arm instead) — both
/// arms must run the same demo and exit 0.
#[test]
fn named_demo_dispatchers_run_each_demo_on_its_own() {
    let (ok, out) = run(&["hybrid-spend-demo"]);
    assert!(ok, "hybrid-spend-demo must exit 0: {out}");
    assert!(out.contains("[2] HYBRID SPEND"), "{out}");

    let (ok, out) = run(&["inheritance-demo"]);
    assert!(ok, "inheritance-demo must exit 0: {out}");
    assert!(out.contains("[3] INHERITANCE"), "{out}");
}

#[test]
fn offline_operator_subcommands_run_and_report() {
    let (ok, out) = run(&["constants"]);
    assert!(ok, "constants must exit 0: {out}");

    let (ok, out) = run(&["leaf-budget"]);
    assert!(ok, "leaf-budget must exit 0: {out}");
    let (ok, out2) = run(&["leaf-budget", "--p2mr-delta"]);
    assert!(ok, "leaf-budget --p2mr-delta must exit 0: {out2}");

    let (ok, out) = run(&["wots-params"]);
    assert!(ok, "wots-params must exit 0: {out}");
    assert!(
        out.contains("520"),
        "the 520-byte verdict must print: {out}"
    );

    // The estate letter's QR block: printed WITH --qr, skipped without
    // it — both edges of the flag, offline (the letter is pure math).
    let (ok, out) = run(&["estate-letter", "--network", "regtest", "--qr"]);
    assert!(ok, "estate-letter --qr must exit 0: {out}");
    assert!(
        out.contains("QR (§1 identity"),
        "QR block present with --qr: {out}"
    );
    let (ok, out) = run(&["estate-letter", "--network", "regtest"]);
    assert!(ok, "estate-letter must exit 0: {out}");
    assert!(
        !out.contains("QR (§1 identity"),
        "QR block skipped without --qr: {out}"
    );
    assert!(
        out.contains("Vault address (regtest):"),
        "the letter body still prints: {out}"
    );
}

#[test]
fn kit_seed_split_combine_roundtrip_both_formats() {
    // Native qsv shares: split → recombine → WOTS+ seal verified.
    let (ok, split) = run(&["kit-seed", "split", "--threshold", "2", "--shares", "3"]);
    assert!(ok, "native split must exit 0: {split}");
    let shares: Vec<String> = split
        .lines()
        .filter(|l| l.contains("qsvss1-"))
        .map(|l| l.trim().to_string())
        .collect();
    assert!(shares.len() >= 2, "shares must print: {split}");
    let (ok, out) = run(&[
        "kit-seed", "combine", "--share", &shares[0], "--share", &shares[1],
    ]);
    assert!(ok, "native combine must exit 0: {out}");
    assert!(out.contains("integrity tag: VERIFIED"), "{out}");
    assert!(out.contains("WOTS+ kit seal:   VERIFIED"), "{out}");

    // SLIP-0039 mnemonics with a passphrase (Feistel + PBKDF2 path).
    let (ok, split) = run(&[
        "kit-seed",
        "split",
        "--threshold",
        "2",
        "--shares",
        "3",
        "--format",
        "slip39",
        "--passphrase",
        "e2e passphrase",
    ]);
    assert!(ok, "slip39 split must exit 0: {split}");
    let mnemonics: Vec<String> = split
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| {
            let words: Vec<&str> = l.split_whitespace().collect();
            words.len() >= 20
                && words
                    .iter()
                    .all(|w| w.chars().all(|c| c.is_ascii_lowercase()))
        })
        .collect();
    assert!(mnemonics.len() >= 2, "mnemonics must print: {split}");

    let (ok, out) = run(&[
        "kit-seed",
        "combine",
        "--format",
        "slip39",
        "--passphrase",
        "e2e passphrase",
        "--share",
        &mnemonics[0],
        "--share",
        &mnemonics[1],
    ]);
    assert!(ok, "slip39 combine must exit 0: {out}");
    assert!(out.contains("WOTS+ kit seal:   VERIFIED"), "{out}");

    // WRONG passphrase does NOT error — it yields a different (deniable)
    // secret; the recovered-seed digest must differ from the true one.
    let (ok, out_wrong) = run(&[
        "kit-seed",
        "combine",
        "--format",
        "slip39",
        "--passphrase",
        "wrong passphrase",
        "--share",
        &mnemonics[0],
        "--share",
        &mnemonics[1],
    ]);
    assert!(
        ok,
        "wrong passphrase must not error (deniable secret): {out_wrong}"
    );
    let seed_line = |s: &str| {
        s.lines()
            .find(|l| l.contains("recovered seed sha256"))
            .unwrap_or_default()
            .to_string()
    };
    assert_ne!(
        seed_line(&out),
        seed_line(&out_wrong),
        "wrong passphrase must recover a DIFFERENT secret\nright: {out}\nwrong: {out_wrong}"
    );
}

/// Phase-1 PSBT, the HALF `hw_roundtrip` does not exercise: build → device
/// sign → FINISH (witness assembly + libbitcoinconsensus verdict). The
/// finish path is the one that turns two signatures into a consensus-
/// judged transaction — it must ACCEPT for the demo vault.
#[test]
fn psbt_phase1_finish_judges_the_demo_transaction_accept() {
    let dir = tempfile::tempdir().expect("tempdir");
    let built = dir.path().join("vault.psbt");
    let (ok, out) = run(&["psbt", "build", "--out", built.to_str().unwrap()]);
    assert!(ok, "psbt build must exit 0: {out}");

    let signed = dir.path().join("vault-signed.psbt");
    let (ok, out) = run(&[
        "psbt",
        "sign",
        "--in",
        built.to_str().unwrap(),
        "--out",
        signed.to_str().unwrap(),
    ]);
    assert!(ok, "psbt sign must exit 0: {out}");

    let finished = dir.path().join("vault-final.psbt");
    let (ok, out) = run(&[
        "psbt",
        "finish",
        "--in",
        signed.to_str().unwrap(),
        "--out",
        finished.to_str().unwrap(),
    ]);
    assert!(ok, "psbt finish must exit 0: {out}");
    assert!(
        out.contains("consensus engine:  ACCEPT"),
        "libbitcoinconsensus must accept: {out}"
    );
    assert!(finished.exists(), "finalized PSBT must be written");
}

/// The live dashboard, offline: `--tip` renders from real math (no node),
/// `--watch`+`--tip` is refused (a watch loop needs a live node), and a
/// datadir with no cookie must fail with the actionable node message —
/// never with fabricated data.
#[test]
fn vault_dashboard_renders_offline_and_refuses_fake_liveness() {
    let (ok, out) = run(&["vault-dashboard", "--tip", "900000"]);
    assert!(ok, "offline dashboard must exit 0: {out}");
    assert!(
        out.contains("VAULT DASHBOARD"),
        "dashboard banner missing: {out}"
    );
    assert!(
        out.contains("--tip override (offline)"),
        "the offline source must be labelled honestly: {out}"
    );

    let (ok, out) = run(&["vault-dashboard", "--tip", "900000", "--watch", "5"]);
    assert!(!ok, "--watch + --tip must be refused");
    assert!(
        out.contains("--watch requires a live node"),
        "refusal reason missing: {out}"
    );

    let (ok, out) = run(&["vault-dashboard", "--datadir", "/nonexistent-qsv-datadir"]);
    assert!(!ok, "a datadir without a cookie must fail closed");
    assert!(
        out.contains("cannot reach node"),
        "actionable node message missing: {out}"
    );
}

/// K1 tracker, the operator entrypoint: the OFFLINE audit of docs/11 must
/// pass on a clean tree, and a missing plan file must exit 1 with the
/// `--plan` hint — never a panic, never a silent pass.
#[test]
fn bip360_status_offline_audit_passes_and_missing_plan_fails_closed() {
    let (ok, out) = run(&["bip360-status"]);
    assert!(ok, "offline K1 audit must exit 0: {out}");
    assert!(
        out.contains("OFFLINE AUDIT: PASS"),
        "audit verdict missing: {out}"
    );

    let (ok, out) = run(&["bip360-status", "--plan", "/nonexistent-qsv/docs11.md"]);
    assert!(!ok, "a missing plan file must exit non-zero");
    assert!(
        out.contains("cannot read"),
        "read failure must be actionable: {out}"
    );
    assert!(out.contains("--plan"), "the hint must name the flag: {out}");
}
