//! Operator dashboard state: one pure computation from chain height to the
//! full vault timeline (heartbeat, unvault window, staging, inheritance).
//!
//! Both the CLI surface (`qsv-cli vault-dashboard`) and any future UI feed
//! from this struct — one source of truth, zero duplicated date math
//! (single source of truth, docs/10 §5-6).

use crate::heartbeat::{is_due, HeartbeatPolicy, INHERITANCE_CSV_BLOCKS};
use crate::policy::RECOVERY_CSV_BLOCKS;
use crate::taproot::VaultTaproot;

/// One vault UTXO as the dashboard sees it.
pub struct DashboardInput<'a> {
    pub vault: &'a VaultTaproot,
    /// Current chain height (tip).
    pub tip: u32,
    /// Last heartbeat refresh height.
    pub last_refresh_block: u32,
}

/// Complete, renderable vault state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStatus {
    /// Heartbeat refresh due at this height? (self-churn required now)
    pub heartbeat_due: bool,
    /// Blocks remaining until refresh becomes due (0 = due now).
    pub blocks_until_refresh: u32,
    /// Blocks remaining until the inheritance leaf activates (0 = open).
    pub blocks_until_inheritance: u32,
    /// Blocks remaining until the recovery clawback window closes (0 = open).
    pub blocks_until_clawback_close: u32,
    /// Calendar projections the operator can plan against.
    pub dates: TimelineDates,
}

/// Calendar projections of the vault's three clocks (approximation: 10
/// minutes per block, the difficulty-epoch average — adequate for operator
/// planning; consensus math uses heights, never these dates).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineDates {
    pub inheritance_activates: String,
    pub heartbeat_refresh_due: String,
}

/// Renderable row items for a plain-text dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusLines {
    pub tip: String,
    pub heartbeat: String,
    pub inheritance: String,
    pub clawback: String,
    pub policy: String,
}

/// Compute the full vault status from chain height.
pub fn vault_status(inp: &DashboardInput<'_>) -> VaultStatus {
    let policy = HeartbeatPolicy::default();
    let elapsed = inp.tip.saturating_sub(inp.last_refresh_block);
    let refresh_at = inp
        .last_refresh_block
        .saturating_add(policy.interval_blocks);
    let inheritance_remaining = INHERITANCE_CSV_BLOCKS.saturating_sub(elapsed);
    VaultStatus {
        heartbeat_due: is_due(&policy, inp.last_refresh_block, inp.tip),
        blocks_until_refresh: refresh_at.saturating_sub(inp.tip),
        blocks_until_inheritance: inheritance_remaining,
        blocks_until_clawback_close: (RECOVERY_CSV_BLOCKS as u32).saturating_sub(elapsed),
        dates: TimelineDates {
            inheritance_activates: epoch_date(inp.tip + inheritance_remaining),
            heartbeat_refresh_due: epoch_date(refresh_at),
        },
    }
}

/// Render status into human-facing lines.
pub fn render(s: &VaultStatus, tip: u32, vault_address: &str) -> StatusLines {
    let (hb_state, hb_detail) = if s.heartbeat_due {
        ("DUE", "self-churn refresh required NOW".to_string())
    } else {
        (
            "OK",
            format!(
                "refresh at block {} (≈ {}, ~{}d away)",
                tip + s.blocks_until_refresh,
                s.dates.heartbeat_refresh_due,
                s.blocks_until_refresh / 144
            ),
        )
    };
    let (inh_state, inh_detail) = if s.blocks_until_inheritance == 0 {
        ("OPEN", "2-of-3 heir settlement can execute".to_string())
    } else {
        (
            "LOCKED",
            format!(
                "opens in {} blk (≈ {}, ~{}d)",
                s.blocks_until_inheritance,
                s.dates.inheritance_activates,
                s.blocks_until_inheritance / 144
            ),
        )
    };
    StatusLines {
        tip: format!("Chain tip: {tip}"),
        heartbeat: format!("Heartbeat [{hb_state}]: {hb_detail}"),
        inheritance: format!("Inheritance [{inh_state}]: {inh_detail}"),
        clawback: format!(
            "Recovery clawback window: {} blk remaining",
            s.blocks_until_clawback_close
        ),
        policy: format!(
            "Vault: {vault_address} · 2-of-2 hybrid + CSV 144 recovery + CSV 26,280 inheritance"
        ),
    }
}

/// Approximate calendar date of `height` (10 min/block epoch average).
/// Anchor: mainnet block 900,000 ≈ 2025-05-14 (consensus math never depends
/// on this; operator planning only).
pub fn epoch_date(height: u32) -> String {
    const ANCHOR_HEIGHT: i64 = 900_000;
    const ANCHOR_UNIX: i64 = 1_747_190_400; // 2025-05-14T00:00:00Z
    let unix = ANCHOR_UNIX + ((height as i64) - ANCHOR_HEIGHT) * 600;
    let days = unix.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo_keys;
    use bitcoin::secp256k1::Secp256k1;

    fn demo_vault() -> VaultTaproot {
        let secp = Secp256k1::verification_only();
        VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[demo_keys::heir_one(), demo_keys::heir_two()],
            2,
        )
        .unwrap()
    }

    #[test]
    fn status_math_matches_heartbeat_policy() {
        let vault = demo_vault();
        let s = vault_status(&DashboardInput {
            vault: &vault,
            tip: 900_000,
            last_refresh_block: 900_000,
        });
        assert!(!s.heartbeat_due);
        assert_eq!(
            s.blocks_until_refresh,
            HeartbeatPolicy::default().interval_blocks
        );
        assert_eq!(s.blocks_until_inheritance, INHERITANCE_CSV_BLOCKS);
        assert_eq!(s.blocks_until_clawback_close, RECOVERY_CSV_BLOCKS as u32);
    }

    #[test]
    fn heartbeat_due_flips_at_interval() {
        let vault = demo_vault();
        let s = vault_status(&DashboardInput {
            vault: &vault,
            tip: 900_000 + HeartbeatPolicy::default().interval_blocks,
            last_refresh_block: 900_000,
        });
        assert!(s.heartbeat_due);
        assert_eq!(s.blocks_until_refresh, 0);
    }

    #[test]
    fn inheritance_opens_only_after_full_csv() {
        let vault = demo_vault();
        let mid = vault_status(&DashboardInput {
            vault: &vault,
            tip: 900_000 + 10_000,
            last_refresh_block: 900_000,
        });
        assert_eq!(
            mid.blocks_until_inheritance,
            INHERITANCE_CSV_BLOCKS - 10_000
        );
        let open = vault_status(&DashboardInput {
            vault: &vault,
            tip: 900_000 + INHERITANCE_CSV_BLOCKS,
            last_refresh_block: 900_000,
        });
        assert_eq!(open.blocks_until_inheritance, 0);
        let lines = render(&open, 900_000 + INHERITANCE_CSV_BLOCKS, "bc1ptest");
        assert!(lines.inheritance.contains("OPEN"));
    }

    #[test]
    fn render_lines_are_stable_and_informative() {
        let vault = demo_vault();
        let s = vault_status(&DashboardInput {
            vault: &vault,
            tip: 900_000,
            last_refresh_block: 900_000,
        });
        let lines = render(&s, 900_000, "bc1ptest");
        assert!(lines.heartbeat.contains("OK"));
        assert!(lines.heartbeat.contains("912960"));
        assert!(lines.inheritance.contains("LOCKED"));
        assert!(lines.policy.contains("bc1ptest"));
        assert!(lines.clawback.contains("144"));
    }

    #[test]
    fn epoch_date_matches_known_calendar_anchors() {
        assert_eq!(epoch_date(900_000), "2025-05-14");
        // 144 blocks ≈ 1 day.
        assert_eq!(epoch_date(900_144), "2025-05-15");
        assert_eq!(epoch_date(900_000 + 144 * 365), "2026-05-14");
    }

    #[test]
    fn epoch_date_rolls_the_year_for_january_and_february() {
        // The civil year roll (`if m <= 2 { y + 1 }`) must fire for BOTH
        // winter months — the Round-32 sweep's `<` flip kept January but
        // silently lost February (a February anchor pins the exact branch).
        assert_eq!(epoch_date(935_264), "2026-01-14");
        assert_eq!(epoch_date(939_728), "2026-02-14");
        assert_eq!(epoch_date(990_416), "2027-02-01");
    }
}
