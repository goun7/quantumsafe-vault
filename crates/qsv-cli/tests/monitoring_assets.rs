//! MONITORING ASSETS vs THE EXPOSITION (docs/10 §4.25, Round 20).
//!
//! `scripts/prometheus_alerts.yml` and `scripts/grafana_dashboard.json`
//! are operator-facing files that can rot silently: Prometheus accepts a
//! rule that names a series the target never exports, and Grafana renders
//! an empty panel the same way. Both look fine in review and fire never.
//!
//! This test binds the two files to the bridge's ACTUAL exposition
//! (`qsv_cosigner::server::Metrics::METRIC_FAMILIES`, itself proven
//! against a live render by the unit test in server.rs):
//!
//!   1. Every `qsv_cosigner_*` token in either file is a declared family
//!      (or a derived `_bucket/_sum/_count` row of one).
//!   2. Every alert rule carries an expression, a severity and a summary.
//!   3. The rules + dashboard together COVER every safety-critical
//!      counter — an operator who installs them is never blind to a
//!      freeze, a flood or a scraping outage.

use std::collections::BTreeSet;

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// Every `qsv_cosigner_*` identifier in a file, with whitespace collapsed
/// so a YAML folded scalar (`>-`) or a wrapped JSON string cannot hide a
/// reference from the audit.
fn referenced_families(body: &str) -> BTreeSet<String> {
    let collapsed: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    let bytes = collapsed.as_bytes();
    let needle = b"qsv_cosigner_";
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(needle) {
            let end = (i..bytes.len())
                .find(|j| !(bytes[*j].is_ascii_alphanumeric() || bytes[*j] == b'_'))
                .unwrap_or(bytes.len());
            out.insert(collapsed.get(i..end).unwrap_or_default().to_string());
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

/// A referenced name is legitimate when it is a declared family, or a
/// Prometheus-derived row of the latency histogram (`_bucket`, `_sum`,
/// `_count`) — the one family whose rows are generated at scrape time.
fn is_declared(name: &str) -> bool {
    use qsv_cosigner::server::Metrics;
    if Metrics::METRIC_FAMILIES.contains(&name) {
        return true;
    }
    for suffix in ["_bucket", "_sum", "_count"] {
        if let Some(base) = name.strip_suffix(suffix) {
            return Metrics::METRIC_FAMILIES.contains(&base);
        }
    }
    false
}

#[test]
fn alert_rules_and_dashboard_only_name_families_the_bridge_exports() {
    let alerts_path = repo_root().join("scripts/prometheus_alerts.yml");
    let dash_path = repo_root().join("scripts/grafana_dashboard.json");
    let alerts = std::fs::read_to_string(&alerts_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", alerts_path.display()));
    let dash = std::fs::read_to_string(&dash_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dash_path.display()));

    let alert_families = referenced_families(&alerts);
    let dash_families = referenced_families(&dash);
    assert!(
        alert_families.len() >= 8,
        "the rules must reference the exposition, got {:?}",
        alert_families
    );
    assert!(
        dash_families.len() >= 8,
        "the dashboard must reference the exposition, got {:?}",
        dash_families
    );
    for name in alert_families.iter().chain(dash_families.iter()) {
        assert!(
            is_declared(name),
            "{name} is referenced by the monitoring assets but the bridge never exports it — \
             a rule on a series nobody produces is silently dead"
        );
    }

    // The dashboard must be importable JSON with real panels.
    let doc: serde_json::Value =
        serde_json::from_str(&dash).unwrap_or_else(|e| panic!("dashboard is not JSON: {e}"));
    assert_eq!(doc["uid"], "qsv-cosigner", "stable dashboard uid");
    assert!(
        doc["title"]
            .as_str()
            .unwrap_or_default()
            .contains("Co-signer"),
        "{:?}",
        doc["title"]
    );
    let panels = doc["panels"].as_array().expect("panels array");
    assert!(
        panels.len() >= 8,
        "expected a real dashboard, got {} panels",
        panels.len()
    );
    for p in panels {
        let title = p["title"].as_str().unwrap_or_default();
        assert!(!title.is_empty(), "every panel is titled: {p}");
        assert!(
            p["gridPos"]["w"].as_u64().unwrap_or(0) > 0,
            "{title} has a width"
        );
        assert!(
            p["gridPos"]["h"].as_u64().unwrap_or(0) > 0,
            "{title} has a height"
        );
        let empty = Vec::new();
        let targets = p["targets"].as_array().unwrap_or(&empty);
        assert!(!targets.is_empty(), "{title} has at least one query");
        for t in targets {
            let expr = t["expr"].as_str().unwrap_or_default();
            assert!(!expr.is_empty(), "{title} query has an expr: {t}");
        }
    }
}

#[test]
fn every_alert_rule_is_complete_and_actionable() {
    let path = repo_root().join("scripts/prometheus_alerts.yml");
    let body = std::fs::read_to_string(&path).unwrap();
    // Rule blocks start at `      - alert: <NAME>` and run until the next
    // one (or EOF). A hand-rolled scan keeps the project dependency-free.
    let mut rules: Vec<(String, String)> = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("- alert: ") {
            if let Some((name, block)) = current.take() {
                rules.push((name, block.join("\n")));
            }
            current = Some((rest.trim().to_string(), Vec::new()));
            continue;
        }
        if let Some((_, block)) = current.as_mut() {
            block.push(line.to_string());
        }
    }
    if let Some((name, block)) = current.take() {
        rules.push((name, block.join("\n")));
    }
    assert!(
        rules.len() >= 8,
        "expected a real rule set, got {}",
        rules.len()
    );
    let mut names = BTreeSet::new();
    for (name, block) in &rules {
        assert!(
            name.starts_with("QsvCosigner"),
            "alert names must be namespaced: {name}"
        );
        assert!(names.insert(name.clone()), "duplicate alert name {name}");
        assert!(
            block.contains("expr:"),
            "{name} has an expression:\n{block}"
        );
        assert!(block.contains("for:"), "{name} has a for: dwell:\n{block}");
        assert!(
            block.contains("severity:"),
            "{name} has a severity label:\n{block}"
        );
        assert!(
            block.contains("summary:") && block.contains("description:"),
            "{name} is annotated for an on-call human:\n{block}"
        );
        // The expression must actually read something — an `expr:` whose
        // value is empty (or only a comment) would parse as an empty
        // selector that matches nothing, silently.
        let lines: Vec<&str> = block.lines().collect();
        let idx = lines
            .iter()
            .position(|l| l.trim_start().starts_with("expr:"))
            .unwrap_or_else(|| panic!("{name} has no expr: line"));
        let expr: String = lines[idx + 1..]
            .iter()
            .take_while(|l| {
                let t = l.trim_start();
                !(t.starts_with("for:")
                    || t.starts_with("labels:")
                    || t.starts_with("annotations:"))
            })
            .cloned()
            .chain(std::iter::once(lines[idx].trim()))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            expr.contains("qsv_cosigner_") || expr.contains("up{"),
            "{name} must read the bridge's series, got: {expr:?}"
        );
    }
}

/// ROUND 25 — the saturation rule must EXEMPT the serial loop. The
/// serial accept loop honestly publishes `worker_limit 1` (it serves one
/// connection at a time) and its high-water mark hits 1 on the first
/// request; against a `> 0` guard that pages every idle serial
/// deployment 5 minutes after its first scrape. A ceiling of one cannot
/// be "80% saturated" — the guard must be `> 1` so the rule stays about
/// thread/FD headroom on the threaded loop where a cap actually exists.
#[test]
fn the_saturation_rule_exempts_the_serial_ceiling_of_one() {
    let root = repo_root();
    let alerts = std::fs::read_to_string(root.join("scripts/prometheus_alerts.yml")).unwrap();
    let block = alerts
        .split("- alert:")
        .find(|b| b.contains("QsvCosignerWorkerSaturation"))
        .expect("the saturation rule exists");
    assert!(
        block.contains("qsv_cosigner_worker_limit > 1"),
        "the saturation rule exempts the serial loop (limit <= 1):\n{block}"
    );
    assert!(
        block.contains("qsv_cosigner_workers_peak"),
        "the rule still reads the high-water mark (the sizing evidence):\n{block}"
    );
}

#[test]
fn the_assets_cover_every_safety_critical_counter() {
    let root = repo_root();
    let alerts = std::fs::read_to_string(root.join("scripts/prometheus_alerts.yml")).unwrap();
    let dash = std::fs::read_to_string(root.join("scripts/grafana_dashboard.json")).unwrap();
    let rules = referenced_families(&alerts);
    let panels = referenced_families(&dash);
    let covered = |name: &str| rules.contains(name) || panels.contains(name);
    for family in [
        // A freeze is the fail-closed path an operator MUST be told about.
        "qsv_cosigner_alarm_refused_total",
        "qsv_cosigner_alarm_refused_by_vault_total",
        // Refusal volume + attribution (which vault, how many).
        "qsv_cosigner_refused_total",
        "qsv_cosigner_refused_by_vault_total",
        // Releases (the only line that means "a key was produced").
        "qsv_cosigner_accepted_total",
        "qsv_cosigner_accepted_by_vault_total",
        // Traffic (the denominator every ratio needs).
        "qsv_cosigner_requests_total",
        // Load shedding + scraping health.
        "qsv_cosigner_capacity_refused_total",
        "qsv_cosigner_rate_limited_total",
        "qsv_cosigner_metrics_denied_total",
        // A reload that did not rotate the scrape token: the old secret
        // stays live and the operator never learns (Round 23).
        "qsv_cosigner_rotate_denied_total",
        // A rotation that LANDED (the operator must be able to confirm
        // the secret Prometheus holds is the live one) and the worker
        // occupancy gauges that size the box.
        "qsv_cosigner_rotate_total",
        "qsv_cosigner_workers_peak",
        "qsv_cosigner_worker_limit",
        // Latency (the p99 the frame timeout is sized against).
        "qsv_cosigner_serve_latency_us_bucket",
    ] {
        assert!(
            covered(family),
            "{family} is a safety-critical counter with NO alert rule and NO dashboard panel — \
             the operator would be blind to it"
        );
    }
}
