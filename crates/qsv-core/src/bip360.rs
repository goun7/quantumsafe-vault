//! BIP-360 (P2MR) decision-gate tracker — Phase 4a specification watching.
//!
//! docs/11 records a machine-readable snapshot of the live BIP header
//! (`status`, `version`, …) between `BIP360-SNAPSHOT:BEGIN/END` markers.
//! This module
//!
//! 1. parses that snapshot,
//! 2. parses the real `bip-0360.mediawiki` header (fetched by the CLI),
//! 3. diffs the two (any delta ⇒ exit 1 ⇒ K1 must be re-evaluated), and
//! 4. audits the plan document offline: snapshot present and self-consistent,
//!    gates K1–K3 declared, phases 4a–4e present, and the honesty clause that
//!    keeps consensus code out of the repository until activation.
//!
//! The whole point of gate K1: **no P2MR consensus code enters the
//! repository until the BIP reaches Status ≥ Proposed and two independent
//! implementations exist.** This module is the mechanical half of that rule.

/// Errors raised while reading a snapshot or a BIP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip360Error {
    /// The snapshot block is missing or a required field is absent.
    MissingField(String),
    /// A field is present but malformed.
    Malformed(String),
}

impl core::fmt::Display for Bip360Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Bip360Error::MissingField(s) => write!(f, "missing field: {s}"),
            Bip360Error::Malformed(s) => write!(f, "malformed field: {s}"),
        }
    }
}

impl std::error::Error for Bip360Error {}

/// Snapshot markers around the machine-readable block.
pub const SNAPSHOT_BEGIN: &str = "<!-- BIP360-SNAPSHOT:BEGIN";
pub const SNAPSHOT_END: &str = "<!-- BIP360-SNAPSHOT:END -->";

/// The machine-readable weight claim recorded in docs/11 (`weight-saving-wu:`
/// inside the snapshot block). The tracker verifies the plan's arithmetic
/// against the REAL measured saving every run — when K1 eventually opens,
/// the migration numbers are already proven to still match the BIP text.
pub const RECORDED_WEIGHT_SAVING_WU: u64 = 32;

/// Values an implementation row may carry in the snapshot (Round 30, P3):
/// a row that says anything else is not a tracked state and fails the
/// offline audit.
pub const IMPL_STATES: [&str; 3] = ["none", "partial", "supported"];

/// Fields both sides (plan snapshot and live BIP header) must agree on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bip360Header {
    /// BIP number (`360`).
    pub bip: String,
    /// Title (`Pay-to-Merkle-Root (P2MR)`).
    pub title: String,
    /// Status (`Draft` / `Proposed` / `Final` / …).
    pub status: String,
    /// Spec version (`0.12.1`).
    pub version: String,
    /// Assignment date (`2024-12-18`).
    pub assigned: String,
    /// Required BIPs (`340, 341, 342`).
    pub requires: String,
    /// Where the snapshot came from (snapshot side only).
    pub source: String,
    /// Retrieval date of the snapshot (snapshot side only).
    pub retrieved: String,
}

impl Bip360Header {
    /// Fields that constitute the K1 gate signal.
    pub fn gate_fields(&self) -> [(&'static str, &str); 5] {
        [
            ("status", &self.status),
            ("version", &self.version),
            ("title", &self.title),
            ("assigned", &self.assigned),
            ("requires", &self.requires),
        ]
    }
}

/// One audited property of the migration plan (offline check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Human label of the property.
    pub label: &'static str,
    /// Whether the document satisfies it.
    pub ok: bool,
    /// Actionable detail.
    pub detail: String,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim().strip_prefix(key)?;
    let rest = rest.strip_prefix(':')?;
    Some(rest.trim())
}

/// Parses the snapshot block embedded in the migration plan.
pub fn parse_snapshot(doc: &str) -> Result<Bip360Header, Bip360Error> {
    let begin = doc
        .find(SNAPSHOT_BEGIN)
        .ok_or_else(|| Bip360Error::MissingField("BIP360-SNAPSHOT:BEGIN marker".into()))?;
    let end = doc[begin..]
        .find(SNAPSHOT_END)
        .ok_or_else(|| Bip360Error::MissingField("BIP360-SNAPSHOT:END marker".into()))?;
    let block = &doc[begin..begin + end];

    let mut h = Bip360Header::default();
    let mut seen = 0usize;
    for line in block.lines() {
        for (key, slot) in [
            ("bip", 0usize),
            ("title", 1),
            ("status", 2),
            ("version", 3),
            ("assigned", 4),
            ("requires", 5),
            ("source", 6),
            ("retrieved", 7),
        ] {
            if let Some(v) = field(line, key) {
                if v.is_empty() {
                    return Err(Bip360Error::Malformed(format!("empty `{key}`")));
                }
                seen |= 1 << slot;
                let v = v.to_string();
                match slot {
                    0 => h.bip = v,
                    1 => h.title = v,
                    2 => h.status = v,
                    3 => h.version = v,
                    4 => h.assigned = v,
                    5 => h.requires = v,
                    6 => h.source = v,
                    _ => h.retrieved = v,
                }
            }
        }
    }
    if seen != 0b1111_1111 {
        let missing: Vec<&str> = [
            "bip",
            "title",
            "status",
            "version",
            "assigned",
            "requires",
            "source",
            "retrieved",
        ]
        .iter()
        .enumerate()
        .filter(|(i, _)| seen & (1 << i) == 0)
        .map(|(_, k)| *k)
        .collect();
        return Err(Bip360Error::MissingField(missing.join(", ")));
    }
    Ok(h)
}

/// Parses the `<pre>` header of a `bip-0360.mediawiki` document. Only the
/// first `<pre>…</pre>` block is considered, so later prose that happens to
/// contain the word "Status:" cannot poison the parse.
pub fn parse_bip_header(text: &str) -> Result<Bip360Header, Bip360Error> {
    let open = text.find("<pre>").unwrap_or(0) + 5;
    let close = text[open..]
        .find("</pre>")
        .map(|i| open + i)
        .unwrap_or(text.len());
    let header = &text[open..close];
    let mut h = Bip360Header::default();
    let mut found = 0u32;
    for line in header.lines() {
        for (key, bit) in [
            ("BIP", 0u32),
            ("Title", 1),
            ("Status", 2),
            ("Version", 3),
            ("Assigned", 4),
            ("Requires", 5),
        ] {
            if let Some(v) = field(line, key) {
                if v.is_empty() {
                    continue;
                }
                found |= 1 << bit;
                let v = v.to_string();
                match bit {
                    0 => h.bip = v,
                    1 => h.title = v,
                    2 => h.status = v,
                    3 => h.version = v,
                    4 => h.assigned = v,
                    _ => h.requires = v,
                }
            }
        }
    }
    if found != 0b111111 {
        return Err(Bip360Error::MissingField(
            "BIP header is incomplete (need BIP/Title/Status/Version/Assigned/Requires)".into(),
        ));
    }
    Ok(h)
}

/// Field-by-field comparison; every returned `(field, snapshot, live)` is a
/// delta that closes (or reopens) a decision gate.
pub fn diff(snapshot: &Bip360Header, live: &Bip360Header) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for (name, a) in snapshot.gate_fields() {
        if a != field_value(live, name) {
            out.push((
                name.to_string(),
                a.to_string(),
                field_value(live, name).to_string(),
            ));
        }
    }
    out
}

/// Reads one gate field out of a header by name.
fn field_value<'a>(h: &'a Bip360Header, field: &str) -> &'a str {
    match field {
        "status" => &h.status,
        "version" => &h.version,
        "title" => &h.title,
        "assigned" => &h.assigned,
        "requires" => &h.requires,
        _ => "",
    }
}

/// K1's SECOND mechanical half: two independent P2MR implementations.
/// The snapshot's `impl-independent-count` row is the tracked input;
/// two or more open this limb (the gate itself still needs the status
/// limb AND a human decision — this never auto-opens K1).
pub fn k1_impl_verdict(count: u8) -> (&'static str, bool) {
    if count >= 2 {
        ("impl limb of K1 MET (status limb still required)", true)
    } else {
        (
            "impl limb of K1 CLOSED — fewer than two independent implementations",
            false,
        )
    }
}

/// The tracked second-limb counter: how many independent P2MR
/// implementations the snapshot records (`impl-independent-count`).
pub fn impl_count(doc: &str) -> Option<u8> {
    doc.find(SNAPSHOT_BEGIN)
        .and_then(|s| doc.find(SNAPSHOT_END).map(|e| &doc[s..e]))
        .and_then(|block| {
            block
                .lines()
                .find_map(|l| field(l, "impl-independent-count"))
        })
        .and_then(|v| v.parse().ok())
}

/// K1's mechanical half: the status alone never opens the gate (two
/// independent implementations are also required), but a `Draft` status
/// certainly keeps it shut.
pub fn k1_status_verdict(status: &str) -> (&'static str, bool) {
    match status {
        "Draft" | "Call for Objections" | "Withdrawn" | "Rejected" | "Replaced" | "Obsolete" => {
            ("K1 CLOSED — BIP is not yet Proposed", false)
        }
        "Proposed" | "Final" => (
            "status limb of K1 MET (still needs two independent implementations)",
            true,
        ),
        _ => ("status limb of K1 INDETERMINATE — verify manually", false),
    }
}

/// Offline audit of the migration plan document.
pub fn audit_plan(doc: &str) -> Vec<Check> {
    let mut checks = Vec::new();

    let snapshot = parse_snapshot(doc);
    checks.push(Check {
        label: "machine-readable snapshot",
        ok: snapshot.is_ok(),
        detail: match &snapshot {
            Ok(h) => format!(
                "status {} · v{} · retrieved {}",
                h.status, h.version, h.retrieved
            ),
            Err(e) => e.to_string(),
        },
    });

    // Self-consistency: the prose in §1 must quote the same version the
    // snapshot claims (a stale snapshot is caught without network access).
    if let Ok(h) = &snapshot {
        let prose_version = doc
            .split("Draft")
            .nth(1)
            .and_then(|tail| tail.find('v').map(|i| &tail[i + 1..]))
            .and_then(|s| s.split(|c: char| !c.is_ascii_digit() && c != '.').next())
            .map(|s| s.trim_end_matches('.').to_string());
        let matches = prose_version.as_deref() == Some(h.version.as_str());
        checks.push(Check {
            label: "§1 prose ↔ snapshot version",
            ok: matches,
            detail: match &prose_version {
                Some(v) => format!("prose v{v} vs snapshot v{}", h.version),
                None => "could not locate `Draft vX.Y.Z` in the prose".into(),
            },
        });
        checks.push(Check {
            label: "snapshot retrieval date",
            ok: is_iso_date(&h.retrieved),
            detail: format!("retrieved: {}", h.retrieved),
        });
        checks.push(Check {
            label: "snapshot source allow-list",
            ok: allowed_source(&h.source),
            detail: format!("source: {}", h.source),
        });
    }

    // The §7.5 weight claim must survive a re-measurement: parse the
    // snapshot's `weight-saving-wu:` record and compare it with the REAL
    // measured per-input saving (witness bytes = 1 WU each, BIP-141).
    if snapshot.is_ok() {
        let block_start = doc.find(SNAPSHOT_BEGIN);
        let block_end = doc.find(SNAPSHOT_END);
        let claim = block_start
            .and_then(|s| block_end.map(|e| &doc[s..e]))
            .and_then(|block| block.lines().find_map(|l| field(l, "weight-saving-wu")))
            .and_then(|v| v.parse::<u64>().ok());
        let measured = crate::budget::measured_p2mr_weight_saving_wu();
        checks.push(Check {
            label: "§7.5 weight saving ↔ measurement",
            ok: claim == Some(measured) && measured == RECORDED_WEIGHT_SAVING_WU,
            detail: match claim {
                Some(c) if c == measured => {
                    format!("{c} WU/input matches the live measurement")
                }
                Some(c) => format!(
                    "plan claims {c} WU/input but the measured saving is {measured} — BIP text moved?",
                ),
                None => format!(
                    "snapshot has no `weight-saving-wu:` record (expected {RECORDED_WEIGHT_SAVING_WU})",
                ),
            },
        });
    }

    // Round 30 · P3 — Phase 4a implementation tracking: K1 has TWO limbs,
    // the BIP status (diffed online) and "two independent implementations"
    // (previously unauditable). The snapshot records the ecosystem rows
    // (rust-bitcoin / Bitcoin Core / hardware wallets) plus the honest
    // counter and the review date. A missing row, an unknown state word,
    // a non-numeric counter or a malformed review date all fail RED — the
    // implementation limb is now an offline-audited fact, not a hope.
    {
        let block = doc
            .find(SNAPSHOT_BEGIN)
            .and_then(|s| doc.find(SNAPSHOT_END).map(|e| &doc[s..e]));
        for (label, key) in [
            ("impl row: rust-bitcoin", "impl-rust-bitcoin"),
            ("impl row: bitcoin core", "impl-bitcoin-core"),
            ("impl row: hardware wallets", "impl-hardware"),
        ] {
            let value = block.and_then(|b| b.lines().find_map(|l| field(l, key)));
            checks.push(Check {
                label,
                ok: matches!(value, Some(v) if IMPL_STATES.contains(&v)),
                detail: match value {
                    Some(v) => format!("{key}: {v}"),
                    None => {
                        format!("`{key}:` row missing — the K1 implementation limb is unauditable")
                    }
                },
            });
        }
        let count = impl_count(doc);
        checks.push(Check {
            label: "impl count: K1 second limb",
            ok: count.is_some(),
            detail: match count {
                Some(c) => {
                    let (verdict, _met) = k1_impl_verdict(c);
                    format!("{c}/2 independent implementations — {verdict}")
                }
                None => "`impl-independent-count:` missing or not a number".into(),
            },
        });
        let reviewed = block.and_then(|b| b.lines().find_map(|l| field(l, "impl-reviewed")));
        checks.push(Check {
            label: "impl rows review date",
            ok: reviewed.is_some_and(is_iso_date),
            detail: format!(
                "impl-reviewed: {}",
                reviewed.unwrap_or("MISSING — the ecosystem rows can no longer go stale silently")
            ),
        });
    }

    for (label, needle) in [
        ("gate K1 declared", "GATE K1"),
        ("gate K2 declared", "GATE K2"),
        ("gate K3 declared", "GATE K3"),
        ("phase 4a", "Phase 4a"),
        ("phase 4b", "Phase 4b"),
        ("phase 4c", "Phase 4c"),
        ("phase 4d", "Phase 4d"),
        ("phase 4e", "Phase 4e"),
        (
            "honest no-consensus-code clause",
            "no consensus code is added to the repository before activation",
        ),
        ("activation test matrix", "end-to-end test vectors"),
    ] {
        checks.push(Check {
            label,
            ok: doc.contains(needle),
            detail: if doc.contains(needle) {
                format!("`{needle}` present")
            } else {
                format!("`{needle}` NOT found — the plan lost a required element")
            },
        });
    }

    checks
}

fn is_iso_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| c.is_ascii_digit() || (i == 4 || i == 7 && *c == b'-'))
        && s[..4].parse::<u16>().is_ok()
        && s[5..7].parse::<u8>().is_ok()
        && s[8..10].parse::<u8>().is_ok()
}

/// The CLI may only fetch origins recorded here — a snapshot must never turn
/// the tracker into an arbitrary-URL fetcher.
pub fn allowed_source(url: &str) -> bool {
    const ALLOWED: [&str; 2] = [
        "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0360.mediawiki",
        "https://en.bitcoin.it/wiki/BIP_0360",
    ];
    ALLOWED.contains(&url)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The normative migration plan, read straight from the repository.
    const PLAN: &str = include_str!("../../../docs/11_p2mr_migration_plan.md");

    /// Captured live header of `bip-0360.mediawiki` (28 Sep 2026).
    const LIVE_HEADER: &str = r#"<pre>
  BIP: 360
  Layer: Consensus (soft fork)
  Title: Pay-to-Merkle-Root (P2MR)
  Authors: Hunter Beast <hunter@surmount.systems>
  Status: Draft
  Type: Specification
  Assigned: 2024-12-18
  License: BSD-3-Clause
  Version: 0.12.1
  Requires: 340, 341, 342
</pre>"#;

    #[test]
    fn snapshot_parses_and_is_complete() {
        let h = parse_snapshot(PLAN).expect("docs/11 carries a valid snapshot");
        assert_eq!(h.bip, "360");
        assert_eq!(h.status, "Draft");
        assert_eq!(h.version, "0.12.1");
        assert_eq!(h.requires, "340, 341, 342");
        assert!(allowed_source(&h.source), "source must be allow-listed");
        assert!(is_iso_date(&h.retrieved));
    }

    #[test]
    fn live_header_parses_and_matches_snapshot() {
        let live = parse_bip_header(LIVE_HEADER).expect("header parses");
        assert_eq!(live.status, "Draft");
        assert_eq!(live.version, "0.12.1");
        let snap = parse_snapshot(PLAN).unwrap();
        let drift = diff(&snap, &live);
        assert!(
            drift.is_empty(),
            "recorded snapshot drifted from the BIP: {drift:?}"
        );
        let (verdict, open) = k1_status_verdict(&live.status);
        assert!(!open, "{verdict}");
    }

    #[test]
    fn a_status_change_is_reported_as_a_gate_delta() {
        let snap = parse_snapshot(PLAN).unwrap();
        let mut changed = parse_bip_header(LIVE_HEADER).unwrap();
        changed.status = "Proposed".into();
        let deltas = diff(&snap, &changed);
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].0, "status");
        assert_eq!(deltas[0].1, "Draft");
        assert_eq!(deltas[0].2, "Proposed");
        let (verdict, open) = k1_status_verdict("Proposed");
        assert!(open, "{verdict}");
    }

    #[test]
    fn the_real_plan_passes_every_offline_check() {
        let checks = audit_plan(PLAN);
        let failed: Vec<&Check> = checks.iter().filter(|c| !c.ok).collect();
        let details: Vec<_> = failed.iter().map(|c| (c.label, &c.detail)).collect();
        assert!(failed.is_empty(), "docs/11 failed audit: {details:?}");
        assert!(checks.len() >= 15, "the audit covers every gate element");
    }

    /// Round 30 · P3: the Phase 4a implementation rows are AUDITED, and the
    /// counter drives K1's second-limb verdict. A lost row, an unknown
    /// state word, a non-numeric counter or a malformed review date each
    /// fail RED; the real plan passes with 0/2 (honest: nothing upstream).
    #[test]
    fn implementation_rows_are_audited_and_drive_the_k1_impl_verdict() {
        let checks = audit_plan(PLAN);
        let labels: Vec<&str> = checks.iter().map(|c| c.label).collect();
        for want in [
            "impl row: rust-bitcoin",
            "impl row: bitcoin core",
            "impl row: hardware wallets",
            "impl count: K1 second limb",
            "impl rows review date",
        ] {
            assert!(labels.contains(&want), "the audit lost the `{want}` check");
        }
        let failed: Vec<&Check> = checks.iter().filter(|c| !c.ok).collect();
        assert!(failed.is_empty(), "docs/11 impl rows failed: {failed:?}");
        assert_eq!(
            impl_count(PLAN),
            Some(0),
            "honest counter: nothing upstream"
        );

        // A lost row must go red …
        let lost = PLAN.replace("impl-hardware: none\n", "");
        assert!(
            audit_plan(&lost)
                .iter()
                .any(|c| !c.ok && c.label == "impl row: hardware wallets"),
            "a missing impl row must fail the audit"
        );
        // …an unknown state word must go red …
        let bogus = PLAN.replace("impl-rust-bitcoin: none", "impl-rust-bitcoin: maybe");
        assert!(
            audit_plan(&bogus)
                .iter()
                .any(|c| !c.ok && c.label == "impl row: rust-bitcoin"),
            "an unknown impl state must fail the audit"
        );
        // …a non-numeric counter must go red …
        let bad_count = PLAN.replace("impl-independent-count: 0", "impl-independent-count: two");
        assert!(
            audit_plan(&bad_count)
                .iter()
                .any(|c| !c.ok && c.label == "impl count: K1 second limb"),
            "a non-numeric counter must fail the audit"
        );
        // …and a malformed review date must go red.
        let bad_date = PLAN.replace("impl-reviewed: 2026-10-11", "impl-reviewed: yesterday");
        assert!(
            audit_plan(&bad_date)
                .iter()
                .any(|c| !c.ok && c.label == "impl rows review date"),
            "a malformed review date must fail the audit"
        );

        // The verdict: shut below two, met at two — and even at two the
        // gate still requires the status limb plus a human decision.
        let (v, met) = k1_impl_verdict(0);
        assert!(!met && v.contains("CLOSED"), "{v}");
        let (v, met) = k1_impl_verdict(1);
        assert!(!met, "{v}");
        let (v, met) = k1_impl_verdict(2);
        assert!(met && v.contains("MET"), "{v}");
    }

    /// The audit's failure DETAIL paths are load-bearing (an operator
    /// reads them when a check flips), so both non-happy arms must be
    /// reachable: a document with NO snapshot at all, and a document
    /// whose prose lost the `Draft vX.Y.Z` marker the snapshot claims.
    #[test]
    fn audit_details_cover_the_missing_snapshot_and_missing_prose_markers() {
        let checks = audit_plan("# no snapshot marker anywhere in this document");
        assert!(
            !checks[0].ok,
            "a snapshotless plan must fail its first check"
        );
        // Hoisted so the capture runs on EVERY pass (a message-only
        // argument would only evaluate when the assert fails).
        let first_detail = checks[0].detail.clone();
        assert!(
            first_detail.contains("BIP360-SNAPSHOT:BEGIN"),
            "the operator must see WHICH marker is missing: {first_detail}"
        );

        let no_prose = audit_plan(&PLAN.replace("Draft", "X"));
        let prose_check = no_prose
            .iter()
            .find(|c| c.label == "§1 prose ↔ snapshot version")
            .expect("the prose check exists");
        assert!(!prose_check.ok);
        assert!(
            prose_check.detail.contains("could not locate"),
            "{}",
            prose_check.detail
        );
    }

    #[test]
    fn a_tampered_plan_fails_the_audit() {
        let broken = PLAN.replace("v0.12.1", "v0.9.0");
        let checks = audit_plan(&broken);
        assert!(checks.iter().any(|c| !c.ok));
        let no_gates = PLAN.replace("GATE K2", "GATE ?");
        assert!(audit_plan(&no_gates).iter().any(|c| !c.ok));

        assert!(parse_snapshot("no markers here").is_err());
        let partial = PLAN.replace("version: 0.12.1\n", "");
        assert!(matches!(
            parse_snapshot(&partial),
            Err(Bip360Error::MissingField(_))
        ));
        assert!(!allowed_source("https://evil.example/bip360.mediawiki"));
    }

    /// The §7.5 weight claim is AUDITED AGAINST REALITY: the recorded
    /// `weight-saving-wu` must equal the live re-measurement (witness bytes
    /// weigh 1 WU each under BIP-141 — the pre-Round-12 128 WU figure would
    /// fail this check), and a tampered plan record must fail the audit.
    #[test]
    fn weight_claim_matches_the_measured_saving_and_tampering_fails() {
        use crate::budget::measured_p2mr_weight_saving_wu;

        assert_eq!(
            measured_p2mr_weight_saving_wu(),
            RECORDED_WEIGHT_SAVING_WU,
            "docs/11's recorded claim drifted from the measured per-input saving"
        );
        let checks = audit_plan(PLAN);
        let weight = checks
            .iter()
            .find(|c| c.label == "§7.5 weight saving ↔ measurement")
            .expect("the weight audit check exists");
        assert!(weight.ok, "{}", weight.detail);

        // The pre-Round-12 arithmetic (32 B × 4 = 128 WU) must FAIL the audit:
        let stale = PLAN.replace("weight-saving-wu: 32", "weight-saving-wu: 128");
        let checks = audit_plan(&stale);
        let weight = checks
            .iter()
            .find(|c| c.label == "§7.5 weight saving ↔ measurement")
            .expect("weight check present");
        assert!(
            !weight.ok,
            "a stale 128 WU claim must be caught: {}",
            weight.detail
        );

        // A plan that LOSES the record must fail too (fail-closed, not skip).
        let missing = PLAN.replace("weight-saving-wu: 32\n", "");
        assert!(audit_plan(&missing).iter().any(|c| !c.ok));
    }

    /// The error type is the operator-facing contract: both variants must
    /// render their category (never a bare payload), and the `std::error`
    /// impl must keep them usable through `?` chains.
    #[test]
    fn error_display_names_the_category_for_both_variants() {
        let e: Box<dyn std::error::Error> = Box::new(Bip360Error::MissingField("status".into()));
        assert_eq!(e.to_string(), "missing field: status");
        let e = Bip360Error::Malformed("empty `status`".into());
        assert_eq!(e.to_string(), "malformed field: empty `status`");
    }

    /// A field that exists but carries no value must be MALFORMED, not
    /// silently kept as an empty string (an empty `status:` would compare
    /// equal to nothing and quietly open a diff row).
    #[test]
    fn snapshot_refuses_an_empty_field_value() {
        let doc = format!(
            "{SNAPSHOT_BEGIN}\nbip: 360\ntitle: T\nstatus:\nversion: 0.12.1\nassigned: 2024-12-18\nrequires: 340\nsource: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0360.mediawiki\nretrieved: 2026-09-28\n{SNAPSHOT_END}"
        );
        let err = parse_snapshot(&doc).expect_err("empty status must be refused");
        assert_eq!(err, Bip360Error::Malformed("empty `status`".into()));
    }

    /// The live-header parser is deliberately forgiving about the closing
    /// `</pre>` (a truncated fetch still parses field-by-field) but NEVER
    /// about an incomplete header, and an empty `Status:` is skipped rather
    /// than stored as "".
    #[test]
    fn live_header_tolerates_a_missing_close_tag_but_refuses_incomplete_headers() {
        let unclosed = "<pre>\nBIP: 360\nTitle: T\nStatus: Draft\nVersion: 0.12.1\nAssigned: 2024-12-18\nRequires: 340, 341, 342";
        let h = parse_bip_header(unclosed).expect("missing </pre> is tolerated");
        assert_eq!(h.status, "Draft");
        assert_eq!(h.bip, "360");

        let err = parse_bip_header("<pre>\nBIP: 360\nTitle: T\n</pre>").expect_err("incomplete");
        assert!(matches!(err, Bip360Error::MissingField(_)), "{err}");

        // Empty value → skipped by the parser, so the header stays incomplete.
        let err = parse_bip_header(
            "<pre>\nBIP: 360\nTitle: T\nStatus: \nVersion: 0.1\nAssigned: 2024-12-18\nRequires: 340</pre>",
        )
        .expect_err("empty Status must not count as found");
        assert!(matches!(err, Bip360Error::MissingField(_)), "{err}");
    }

    /// Every K1 status limb has a distinct verdict: the shut statuses, the
    /// met statuses (Proposed/Final) and the indeterminate fallback for a
    /// status the tracker has never seen.
    #[test]
    fn k1_status_verdict_covers_shut_met_and_unknown_statuses() {
        for shut in [
            "Draft",
            "Call for Objections",
            "Withdrawn",
            "Rejected",
            "Replaced",
            "Obsolete",
        ] {
            let (v, open) = k1_status_verdict(shut);
            assert!(!open, "{shut} must keep K1 shut: {v}");
        }
        let (v, open) = k1_status_verdict("Final");
        assert!(open, "Final must satisfy the status limb: {v}");
        let (v, open) = k1_status_verdict("Something New");
        assert!(!open, "an unknown status must fail closed: {v}");
        assert!(v.contains("INDETERMINATE"), "{v}");
    }

    /// `field_value` reads the five gate fields by name; an unknown name
    /// returns "" (the diff's default slot) instead of panicking.
    #[test]
    fn field_value_reads_gate_fields_and_defaults_unknown_names_to_empty() {
        let h = Bip360Header {
            status: "Draft".into(),
            version: "0.12.1".into(),
            ..Default::default()
        };
        assert_eq!(field_value(&h, "status"), "Draft");
        assert_eq!(field_value(&h, "version"), "0.12.1");
        assert_eq!(field_value(&h, "bogus"), "");
    }
}
