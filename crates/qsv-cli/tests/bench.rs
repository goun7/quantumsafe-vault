//! CAPACITY BENCH e2e (docs/10 §4.29, Round 21): `qsv-cli bench` must
//! run to completion, print one honest row per operation (a parseable
//! ops/s AND µs/op pair), and every row must clear a MINIMUM throughput
//! floor. The floors sit an order of magnitude below the numbers a debug
//! build already prints — they catch a catastrophic regression (an
//! accidental `debug_assertions`-gated doubling, a wrong loop bound), not
//! a busy machine. The bench itself is a REPORT: exit 0 always.
//!
//! Scheduling noise is one-sided (a loaded box can only make a
//! measurement slower), so the floor test judges the BETTER of two runs —
//! the floors stay where they are; only the sample gets less fragile.

use std::process::Command;

fn qsv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_qsv-cli")
}

/// Every operation the two-key ceremony is built from — each must have a
/// row, and each row's throughput must parse and clear the floor.
const OPS: [&str; 7] = [
    "pqc keygen (ML-DSA-65)",
    "pqc sign (ML-DSA-65)",
    "pqc verify (ML-DSA-65)",
    "bip340 sign",
    "bip340 verify",
    "enclave gate (pqc→bip340)",
    "health write+read",
];

/// Extracts the ops/s figure from a bench row (`<label> <ops> ops/s <µs> µs/op`).
fn ops_per_s(stdout: &str, label: &str) -> f64 {
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with(label))
        .unwrap_or_else(|| panic!("missing bench row for `{label}`:\n{stdout}"));
    // Row tail: `<ops> ops/s <µs> µs/op` → ops = len-4, "ops/s" = len-3,
    // µs = len-2, "µs/op" = len-1 (the label itself may hold spaces).
    let toks: Vec<&str> = line.split_whitespace().collect();
    assert!(
        toks.len() >= 5 && toks[toks.len() - 3] == "ops/s" && toks[toks.len() - 1] == "µs/op",
        "row must carry the ops/s + µs/op pair: {line}"
    );
    let ops: f64 = toks[toks.len() - 4]
        .parse()
        .unwrap_or_else(|_| panic!("ops/s must parse as a number: {line}"));
    let us: f64 = toks[toks.len() - 2] // the µs/op value — right before "µs/op"
        .parse()
        .unwrap_or_else(|_| panic!("µs/op must parse as a number: {line}"));
    assert!(ops > 0.0 && us > 0.0, "throughput must be positive: {line}");
    ops
}

#[test]
fn bench_reports_every_operation_above_floor() {
    // One bench run, with the exit/banner contract checked on the way.
    fn run(iterations: &str) -> String {
        let out = Command::new(qsv_bin())
            .args(["bench", "--iterations", iterations])
            .output()
            .expect("run bench");
        assert_eq!(
            out.status.code(),
            Some(0),
            "the bench is a report — it always exits 0: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(
            stdout.contains("[17] CAPACITY BENCH"),
            "banner must name the bench: {stdout}"
        );
        stdout
    }

    // SCHEDULING NOISE IS ONE-SIDED: a busy machine can only make a
    // measurement SLOWER, never faster. So every operation is judged on
    // its BEST of N runs — a genuinely regressed operation misses every
    // run (an order-of-magnitude regression fails all N even on a loaded
    // box), while unlucky scheduling cannot sink a suite whose whole job
    // is catching catastrophic regressions.
    //
    // N=5 is measured, not guessed: during the Round-31 gate this box ran
    // at load 60+ (foreign CPU hogs) and a debug ML-DSA verify dipped to
    // 4.8 ops/s against a 5.0 floor — with best-of-2 the unlucky sample
    // survived the tiebreak; five samples give the scheduler room
    // without loosening a single floor.
    const SAMPLES: usize = 5;
    let runs: Vec<String> = (0..SAMPLES).map(|_| run("25")).collect();
    let best_of = |label: &str| -> f64 {
        runs.iter()
            .map(|r| ops_per_s(r, label))
            .fold(f64::NEG_INFINITY, f64::max)
    };

    // Conservative floors (a debug build measures 30–4500+ ops/s on the
    // reference machine): below these, something is CATASTROPHICALLY
    // wrong — an order-of-magnitude regression, not scheduling noise.
    let floors: [(&str, f64); 7] = [
        ("pqc keygen (ML-DSA-65)", 5.0),
        ("pqc sign (ML-DSA-65)", 10.0),
        ("pqc verify (ML-DSA-65)", 5.0),
        ("bip340 sign", 100.0),
        ("bip340 verify", 100.0),
        ("enclave gate (pqc→bip340)", 5.0),
        ("health write+read", 100.0),
    ];
    for (label, floor) in floors {
        let ops = best_of(label);
        assert!(
            ops >= floor,
            "`{label}` fell below its capacity floor in ALL {SAMPLES} runs: \
             best {ops:.1} ops/s < {floor} ops/s"
        );
    }
    // All 7 ops made it (no row silently dropped).
    assert_eq!(OPS.len(), floors.len());
}

/// MACHINE-READABLE form (Round 22, docs/10 §4.33): `--json` prints ONE
/// document with the SAME seven rows a capacity baseline is diffed
/// against — stdout carries no banner and no prose, so CI can parse it
/// without filtering.
#[test]
fn bench_json_report_carries_the_same_seven_operations() {
    let out = Command::new(qsv_bin())
        .args(["bench", "--iterations", "25", "--json"])
        .output()
        .expect("run bench");
    assert_eq!(
        out.status.code(),
        Some(0),
        "still a report — exit 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let raw = String::from_utf8_lossy(&out.stdout);
    let doc: serde_json::Value = serde_json::from_str(raw.trim())
        .unwrap_or_else(|e| panic!("stdout must be ONE JSON document: {e}\n{raw}"));
    assert_eq!(doc["schema"], "qsv-bench/v1");
    assert_eq!(doc["iterations"], 25);
    assert!(
        !raw.contains("QUANTUMSAFE-VAULT")
            && !raw.contains("CAPACITY BENCH")
            && !raw.contains("All operations completed"),
        "no prose may share stdout with the document: {raw}"
    );
    let rows = doc["rows"].as_array().expect("rows array");
    assert_eq!(rows.len(), OPS.len(), "every human row has a JSON twin");
    for (row, want) in rows.iter().zip(OPS) {
        assert_eq!(row["op"].as_str().unwrap(), want, "same order, same labels");
        let ops = row["ops_per_s"].as_f64().expect("ops/s as a number");
        let us = row["us_per_op"].as_f64().expect("µs/op as a number");
        assert!(ops > 0.0 && us > 0.0, "{want}: numbers must be positive");
        // The pair describes ONE measurement: ops/s × µs/op ≈ 1e6.
        let consistency = ops * us / 1e6;
        assert!(
            (consistency - 1.0).abs() < 0.02,
            "{want}: ops/s and µs/op disagree (×{consistency:.4})"
        );
    }
}

#[test]
fn bench_json_still_refuses_a_zero_iteration_run() {
    let out = Command::new(qsv_bin())
        .args(["bench", "--iterations", "0", "--json"])
        .output()
        .expect("run bench");
    assert_eq!(
        out.status.code(),
        Some(2),
        "the usage contract predates the output format: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--iterations"),
        "the message must still name the flag"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "a refused run prints no partial document"
    );
}

/// CAPACITY GATE (Round 23, docs/10 §4.38): a stored baseline turns the
/// bench into a regression gate — an operation far below its baseline
/// fails the run (exit 1) and names itself, a run comfortably ABOVE its
/// baseline passes, and a baseline that cannot support the comparison is
/// a usage error (exit 2): a gate that compares against nothing would
/// pass by accident.
#[test]
fn bench_baseline_gate_flags_regressions_and_refuses_bad_baselines() {
    let dir = tempfile::tempdir().unwrap();

    // A REAL report supplies the operation NAMES (the gate refuses a
    // baseline that misses one), then every rate is replaced by a fixed
    // floor no machine can reach — every row must read as a miss.
    //
    // Round 40: the floor used to be this run's own measurement × 100, which
    // made the wall depend on run A not being throttled — a shared CI runner
    // delivered one operation 75× faster on the gate run and the assertion
    // below counted 6 regressions instead of 7. The gate was right; the
    // test's premise ("100× faster than the machine can ever be") was not
    // deterministic. 1e12 ops/s is ~10,000× beyond the fastest row here.
    let out = Command::new(qsv_bin())
        .args(["bench", "--iterations", "25", "--json"])
        .output()
        .expect("run bench");
    assert_eq!(out.status.code(), Some(0));
    let mut doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("a real document");
    assert_eq!(
        doc["rows"].as_array().unwrap().len(),
        OPS.len(),
        "the report carries every operation"
    );
    for i in 0..OPS.len() {
        doc["rows"][i]["ops_per_s"] = serde_json::json!(1.0e12);
    }
    let too_fast = dir.path().join("too-fast.json");
    std::fs::write(&too_fast, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

    // 1. Far below baseline → exit 1, every operation named on stdout.
    let gate = Command::new(qsv_bin())
        .args([
            "bench",
            "--iterations",
            "10",
            "--baseline",
            too_fast.to_str().unwrap(),
        ])
        .output()
        .expect("run gated bench");
    assert_eq!(
        gate.status.code(),
        Some(1),
        "a capacity regression must fail the gate: {}",
        String::from_utf8_lossy(&gate.stderr)
    );
    let stdout = String::from_utf8_lossy(&gate.stdout);
    assert!(stdout.contains("REGRESSION:"), "named rows: {stdout}");
    assert!(stdout.contains("pqc keygen (ML-DSA-65)"), "{stdout}");
    assert!(
        String::from_utf8_lossy(&gate.stderr).contains("capacity regression"),
        "the verdict reaches stderr for the gate log: {}",
        String::from_utf8_lossy(&gate.stderr)
    );

    // 2. Same gate in JSON mode: one document, verdict inside it.
    let gate = Command::new(qsv_bin())
        .args([
            "bench",
            "--iterations",
            "10",
            "--json",
            "--baseline",
            too_fast.to_str().unwrap(),
        ])
        .output()
        .expect("run gated bench");
    assert_eq!(gate.status.code(), Some(1));
    let doc: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&gate.stdout).trim())
        .unwrap_or_else(|e| panic!("stdout must stay ONE document: {e}"));
    assert_eq!(doc["baseline"]["verdict"], "fail");
    assert_eq!(
        doc["baseline"]["regressions"].as_array().unwrap().len(),
        OPS.len()
    );
    assert_eq!(
        doc["baseline"]["tolerance_pct"].as_f64().unwrap(),
        25.0,
        "the default tolerance is reported"
    );

    // 3. A baseline 100× SLOWER than reality: nothing can miss it →
    //    exit 0 with the all-clear line (the gate is not a red herring).
    let mut slow = doc.clone();
    for i in 0..slow["rows"].as_array().unwrap().len() {
        let slower = slow["rows"][i]["ops_per_s"].as_f64().unwrap() / 10_000.0;
        slow["rows"][i]["ops_per_s"] = serde_json::json!(slower);
    }
    let too_slow = dir.path().join("too-slow.json");
    std::fs::write(&too_slow, serde_json::to_string_pretty(&slow).unwrap()).unwrap();
    let pass = Command::new(qsv_bin())
        .args([
            "bench",
            "--iterations",
            "10",
            "--baseline",
            too_slow.to_str().unwrap(),
        ])
        .output()
        .expect("run gated bench");
    assert_eq!(
        pass.status.code(),
        Some(0),
        "inside tolerance = pass: {}",
        String::from_utf8_lossy(&pass.stderr)
    );
    assert!(
        String::from_utf8_lossy(&pass.stdout).contains("within 25%"),
        "the all-clear line: {}",
        String::from_utf8_lossy(&pass.stdout)
    );
}

/// The gate must refuse to COMPARE when the comparison would be a guess:
/// missing file, garbage, a baseline that skips an operation, or a
/// tolerance outside [0, 100) — each exits 2, never a silent pass.
#[test]
fn bench_baseline_gate_refuses_anything_it_cannot_compare_against() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope.json");
    let garbage = dir.path().join("garbage.json");
    std::fs::write(&garbage, "{ not json").unwrap();
    let partial = dir.path().join("partial.json");
    std::fs::write(
        &partial,
        r#"{"schema":"qsv-bench/v1","rows":[{"op":"pqc keygen (ML-DSA-65)","ops_per_s":1.0,"us_per_op":1000000.0}]}"#,
    )
    .unwrap();

    for (label, file) in [
        ("missing", missing.to_str().unwrap().to_string()),
        ("garbage", garbage.to_str().unwrap().to_string()),
        ("not covering", partial.to_str().unwrap().to_string()),
    ] {
        let out = Command::new(qsv_bin())
            .args(["bench", "--iterations", "2", "--baseline", &file])
            .output()
            .expect("run gated bench");
        assert_eq!(
            out.status.code(),
            Some(2),
            "{label} baseline must be a usage error: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("--baseline"),
            "{label}: the flag must be named: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).is_empty(),
            "{label}: no partial report on stdout"
        );
    }

    // A tolerance that cannot exist (>100%) would make every row pass.
    let out = Command::new(qsv_bin())
        .args([
            "bench",
            "--iterations",
            "2",
            "--baseline",
            partial.to_str().unwrap(),
            "--baseline-tolerance-pct",
            "150",
        ])
        .output()
        .expect("run gated bench");
    assert_eq!(
        out.status.code(),
        Some(2),
        "an impossible tolerance is a usage error: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("[0, 100)"),
        "the range must be named: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn bench_refuses_a_zero_iteration_run_as_usage_error() {
    let out = Command::new(qsv_bin())
        .args(["bench", "--iterations", "0"])
        .output()
        .expect("run bench");
    assert_eq!(
        out.status.code(),
        Some(2),
        "--iterations 0 = usage error (division would be meaningless): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--iterations"),
        "the message must name the flag"
    );
}
