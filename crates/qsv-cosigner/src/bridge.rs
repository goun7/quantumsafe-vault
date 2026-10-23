//! Alarm bridge: feeds watchtower verdicts into a LIVE co-signer.
//!
//! The daemon's pass writes `<state-dir>/watchtower-state.json` with one
//! entry per vault (`last_verdict`: "ALERT" or "clear"). This module is the
//! enforcement half of that signal (docs/10 §3.2/§3.3): it parses the state
//! file, mirrors every ALERT into the co-signer with `set_alarm`, clears
//! every vault whose verdict recovered with `clear_alarm`, and reports the
//! deltas so an operator (or the `cosigner-bridge` command) can print an
//! audit line per action.
//!
//! Fail-closed bias: a vault present with verdict "ALERT" is frozen even if
//! other entries are unreadable; an absent state file returns an error and
//! the caller decides (the CLI exits 1 — it never silently unlocks).

use crate::server::Cosigner;
use std::collections::BTreeMap;

/// What the bridge did (or would do) for one vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlarmAction {
    /// Vault was ALERT in the watchtower state and is now frozen.
    Raised,
    /// Vault recovered in the watchtower state; freeze lifted.
    Cleared,
    /// Vault was already in the requested state; nothing changed.
    Unchanged,
}

/// One vault's outcome of a bridge pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeOutcome {
    pub vault_id: String,
    pub action: AlarmAction,
}

/// The watchtower state file (only the fields the bridge consumes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchtowerVerdicts {
    /// Chain tip the pass ran at (diagnostics only).
    pub tip: u32,
    /// Per-vault last verdict ("ALERT" or "clear").
    pub vaults: BTreeMap<String, String>,
}

/// Parses the persisted watchtower state (`watchtower-state.json`).
///
/// VACUOUS-STATE WALL (Round 36, M46): a file that PARSES but carries no
/// vault record — missing `vaults`, or an empty object — is refused like
/// an unreadable one. Presence without content must never read as "all
/// clear": boot has NO last-good verdicts to keep, so a truncated or
/// freshly-clobbered state file would silently serve every vault
/// unfrozen (the exact falsy all-clear the mirror exists to prevent).
/// The same refusal rides the per-request reload, where the keep-last
/// rule already turns it into a fail-closed keep (a mid-run clobber can
/// never lower an applied freeze).
pub fn parse_state(json: &str) -> Result<WatchtowerVerdicts, String> {
    let doc: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("malformed watchtower state: {e}"))?;
    let tip = doc["tip"].as_u64().ok_or("watchtower state: missing tip")? as u32;
    let entries = doc["vaults"].as_object().ok_or_else(|| {
        "watchtower state: vaults map missing (vacuous mirror refused)".to_string()
    })?;
    if entries.is_empty() {
        return Err(
            "watchtower state: written without any vault record (a vacuous mirror must never boot as all-clear)"
                .to_string(),
        );
    }
    let mut vaults = BTreeMap::new();
    for (id, v) in entries {
        let verdict = v["last_verdict"]
            .as_str()
            .ok_or_else(|| format!("watchtower state: {id} has no last_verdict"))?
            .to_string();
        vaults.insert(id.clone(), verdict);
    }
    Ok(WatchtowerVerdicts { tip, vaults })
}

/// Reads + parses `<state-dir>/watchtower-state.json`.
pub fn load_state(state_dir: &std::path::Path) -> Result<WatchtowerVerdicts, String> {
    let path = state_dir.join("watchtower-state.json");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    parse_state(&raw)
}

/// k-of-n MIRROR QUORUM (docs/10 §4.60): merges the verdicts of `n`
/// watchtower mirrors (one state file per watchtower HOST) into ONE pass.
/// A vault is "ALERT" iff at least `quorum` DISTINCT mirrors say so — the
/// approval step that makes a single compromised host harmless in BOTH
/// directions: forging a freeze costs `quorum` hosts, suppressing one
/// costs `n - quorum + 1`.
///
/// Every vault named by ANY mirror stays in the union of the merge; a
/// mirror that has never heard of a vault casts NO "ALERT" vote for it
/// (silence never freezes) but can never erase a sibling's observation.
/// The merged tip is the OLDEST mirror's tip — a mirror that has not
/// caught up may not claim a newer truth.
///
/// Fail-closed validation: no mirrors, `quorum == 0` or `quorum > n` is
/// an ERROR, never a silent clamp — a quorum that could never fire would
/// unlock every vault, so the caller aborts instead of running it.
pub fn quorum_verdicts(
    states: &[WatchtowerVerdicts],
    quorum: usize,
) -> Result<WatchtowerVerdicts, String> {
    let n = states.len();
    if n == 0 {
        return Err("watchtower quorum: no mirror states to merge".to_string());
    }
    if quorum == 0 || quorum > n {
        return Err(format!(
            "watchtower quorum: k={quorum} outside 1..={n} ({n} mirror(s))"
        ));
    }

    // NOTE (wording, not cosmetics): the panic message must NOT contain
    // a comparison operator — the sweep's first `>=` in this file would
    // otherwise land inside the STRING and mask the real merge
    // comparison (`votes >= quorum`) from the mechanical wall.
    let tip = states
        .iter()
        .map(|s| s.tip)
        .min()
        .expect("at least one mirror (n == 0 returned above)");
    let mut seen: BTreeMap<String, ()> = BTreeMap::new();
    let mut alert_votes: BTreeMap<String, usize> = BTreeMap::new();
    for s in states {
        for (id, verdict) in &s.vaults {
            seen.insert(id.clone(), ());
            if verdict == "ALERT" {
                *alert_votes.entry(id.clone()).or_insert(0) += 1;
            }
        }
    }
    let vaults = seen
        .into_keys()
        .map(|id| {
            let votes = alert_votes.get(&id).copied().unwrap_or(0);
            let verdict = if votes >= quorum { "ALERT" } else { "clear" };
            (id, verdict.to_string())
        })
        .collect();
    Ok(WatchtowerVerdicts { tip, vaults })
}

/// Mirrors the watchtower verdicts into the cosigner (in place):
/// ALERT → `set_alarm`, clear → `clear_alarm`, already-conforming vaults
/// are left untouched. Returns one outcome per vault for auditing.
pub fn apply_verdicts(
    cosigner: &mut Cosigner,
    verdicts: &WatchtowerVerdicts,
) -> Vec<BridgeOutcome> {
    let mut out = Vec::new();
    for (id, verdict) in &verdicts.vaults {
        let action = match verdict.as_str() {
            "ALERT" => {
                if cosigner.alarm_state(id) == crate::server::AlarmState::Alarm {
                    AlarmAction::Unchanged
                } else {
                    cosigner.set_alarm(id);
                    AlarmAction::Raised
                }
            }
            _ => {
                if cosigner.alarm_state(id) == crate::server::AlarmState::Alarm {
                    cosigner.clear_alarm(id);
                    AlarmAction::Cleared
                } else {
                    AlarmAction::Unchanged
                }
            }
        };
        out.push(BridgeOutcome {
            vault_id: id.clone(),
            action,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::AlarmState;

    fn cosigner() -> Cosigner {
        Cosigner::provision([42u8; 32], vec!["bc1pvault-a".into(), "bc1pvault-b".into()])
    }

    #[test]
    fn parses_persisted_state_and_raises_alerts() {
        let state = parse_state(
            r#"{"tip": 820001, "vaults": {
                "bc1pvault-a": {"last_tip": 820001, "last_verdict": "ALERT", "idle_blocks": 13000},
                "bc1pvault-b": {"last_tip": 820001, "last_verdict": "clear", "idle_blocks": 100}
            }}"#,
        )
        .unwrap();
        assert_eq!(state.tip, 820001);
        assert_eq!(state.vaults["bc1pvault-a"], "ALERT");

        let mut c = cosigner();
        let outcomes = apply_verdicts(&mut c, &state);
        assert_eq!(
            outcomes,
            vec![
                BridgeOutcome {
                    vault_id: "bc1pvault-a".into(),
                    action: AlarmAction::Raised
                },
                BridgeOutcome {
                    vault_id: "bc1pvault-b".into(),
                    action: AlarmAction::Unchanged
                },
            ]
        );
        assert_eq!(c.alarm_state("bc1pvault-a"), AlarmState::Alarm);
        assert_eq!(c.alarm_state("bc1pvault-b"), AlarmState::Clear);
    }

    #[test]
    fn recovery_clears_and_idempotence_reports_unchanged() {
        let alert =
            parse_state(r#"{"tip": 1, "vaults": {"bc1pvault-a": {"last_verdict": "ALERT"}}}"#)
                .unwrap();
        let mut c = cosigner();
        apply_verdicts(&mut c, &alert);
        assert_eq!(c.alarm_state("bc1pvault-a"), AlarmState::Alarm);

        // Re-applying the SAME alert changes nothing (idempotent mirror).
        let again = apply_verdicts(&mut c, &alert);
        assert_eq!(again[0].action, AlarmAction::Unchanged);

        // Recovery clears the freeze.
        let clear =
            parse_state(r#"{"tip": 2, "vaults": {"bc1pvault-a": {"last_verdict": "clear"}}}"#)
                .unwrap();
        let outcomes = apply_verdicts(&mut c, &clear);
        assert_eq!(outcomes[0].action, AlarmAction::Cleared);
        assert_eq!(c.alarm_state("bc1pvault-a"), AlarmState::Clear);
    }

    #[test]
    fn malformed_state_fails_closed() {
        assert!(parse_state("{ not json").is_err());
        assert!(parse_state(r#"{"vaults": {"a": {}}}"#).is_err()); // no tip
        let dir = tempfile::tempdir().unwrap();
        assert!(load_state(dir.path()).is_err()); // absent file
    }

    /// M46 (Round 36): PARSEABLE but VACUOUS states are refused like
    /// unreadable ones — at boot there is no last-good verdict to keep,
    /// so an empty `vaults` map would otherwise serve as a silent
    /// all-clear. Covers the clobber shapes: empty file, no `vaults`
    /// key, and an empty `vaults` object.
    #[test]
    fn vacuous_state_never_reads_as_all_clear() {
        let msg = |s: &str| parse_state(s).unwrap_err().to_string();
        // (a) an empty file: serde refuses before the map is even seen.
        assert!(parse_state("").is_err(), "empty file must be refused");
        // (b) a truncated document without the vaults map …
        let no_map = msg(r#"{"tip": 820001}"#);
        assert!(
            no_map.contains("vaults map missing"),
            "missing vaults map must say why: {no_map}"
        );
        // (c) … and one whose vaults map holds NO record at all.
        let no_records = msg(r#"{"tip": 820001, "vaults": {}}"#);
        assert!(
            no_records.contains("vacuous"),
            "an empty vaults map must never read as all-clear: {no_records}"
        );
        // Positive control: a populated state still parses (the wall
        // refuses emptiness, not the shape of a real pass record).
        assert!(
            parse_state(r#"{"tip": 1, "vaults": {"bc1pvault-a": {"last_verdict": "ALERT"}}}"#)
                .is_ok()
        );
    }

    /// One mirror's verdict at a tip, for a set of `(vault, verdict)` rows.
    fn mirror(tip: u32, rows: &[(&str, &str)]) -> WatchtowerVerdicts {
        WatchtowerVerdicts {
            tip,
            vaults: rows
                .iter()
                .map(|(id, v)| (id.to_string(), v.to_string()))
                .collect(),
        }
    }

    // ── k-of-n mirror quorum (docs/10 §4.60) ──

    #[test]
    fn quorum_needs_k_distinct_mirrors_to_freeze() {
        let a = mirror(900, &[("bc1pvault-a", "ALERT")]);
        let b = mirror(900, &[("bc1pvault-a", "ALERT")]);
        let c = mirror(900, &[("bc1pvault-a", "clear")]);

        // 2 of 3 affirmatives with k=2 → frozen …
        let merged = quorum_verdicts(&[a.clone(), b.clone(), c.clone()], 2).unwrap();
        assert_eq!(merged.vaults["bc1pvault-a"], "ALERT");
        // … ONE honest minority cannot: a single forged mirror (1 of 3)
        // with k=2 must NOT freeze the vault …
        let forged =
            quorum_verdicts(&[a, mirror(900, &[("bc1pvault-a", "clear")]), c.clone()], 2).unwrap();
        assert_eq!(forged.vaults["bc1pvault-a"], "clear");
        // … and 2 of 3 does not reach k=3 (an all-mirrors quorum).
        let strict = quorum_verdicts(&[b, c], 3);
        assert!(strict.is_err(), "k>n must fail closed: {strict:?}");

        // Recovery: votes drop below k → the freeze lifts again.
        let quiet = [
            mirror(901, &[("bc1pvault-a", "clear")]),
            mirror(901, &[("bc1pvault-a", "clear")]),
            mirror(901, &[("bc1pvault-a", "clear")]),
        ];
        let merged = quorum_verdicts(&quiet, 2).unwrap();
        assert_eq!(merged.vaults["bc1pvault-a"], "clear");
    }

    #[test]
    fn quorum_walls_fail_closed_never_silently_clamp() {
        let s = [mirror(10, &[("bc1pvault-a", "ALERT")])];
        // No mirrors → cannot merge.
        assert!(quorum_verdicts(&[], 1).is_err());
        // k=0 would freeze EVERYTHING, k>n would freeze NOTHING — both are
        // refusals, so neither can be reached by a flag typo.
        assert!(quorum_verdicts(&s, 0).is_err());
        assert!(quorum_verdicts(&s, 2).is_err());
        // The valid boundary still works: k=1 == today's single mirror.
        assert_eq!(
            quorum_verdicts(&s, 1).unwrap().vaults["bc1pvault-a"],
            "ALERT"
        );
    }

    #[test]
    fn quorum_unions_every_vault_and_keeps_the_oldest_tip() {
        // Mirror A knows vault-x (ALERT); mirror B never heard of it and
        // reports vault-y instead, at an OLDER tip.
        let a = mirror(100, &[("vault-x", "ALERT")]);
        let b = mirror(90, &[("vault-y", "clear")]);
        let merged = quorum_verdicts(&[a, b], 1).unwrap();

        // The tip is the OLDEST mirror's — a lagging host cannot claim a
        // newer truth than it observed.
        assert_eq!(merged.tip, 90);
        // The union keeps BOTH vaults: silence about x is not a veto …
        assert!(merged.vaults.contains_key("vault-x"));
        // … and with k=1 the single affirmative freezes x, while y (no
        // affirmative at all) stays clear.
        assert_eq!(merged.vaults["vault-x"], "ALERT");
        assert_eq!(merged.vaults["vault-y"], "clear");

        // Same shape with k=2: one vote for x is not enough to freeze it.
        let a2 = mirror(100, &[("vault-x", "ALERT")]);
        let b2 = mirror(90, &[("vault-y", "clear")]);
        let merged = quorum_verdicts(&[a2, b2], 2).unwrap();
        assert_eq!(merged.vaults["vault-x"], "clear");
    }
}
