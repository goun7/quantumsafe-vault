//! Estate debit/credit accounting — docs/05 §2.2 (Turkish Civil Code
//! m.599 estate inclusion, m.505–506 reserved/statutory shares) grounds
//! FAIL-CLOSED arithmetic.
//!
//! Model (E4c-b, the lending/receivables leg):
//! - **estate = assets + receivables (lending/receivables) − debts**,
//!   all `u64` sats, `checked_*` (overflow = Err, no silent wrapping);
//! - when debts exceed assets+receivables: **INSOLVENT**: NO distribution
//!   (`Insolvent`) — the creditor's rank never hands a heir a share; the
//!   boundary is **equality is NOT insolvency** (net = 0, everyone gets
//!   0 — the inclusive boundary test pins this reading);
//! - heir weights must be **exactly 10,000 basis points**, honouring
//!   docs/05 §2.2's intent of "split outputs by mathematical percentages
//!   of the statutory shares" (any other total = `InvalidWeights` — no
//!   normalization, no guessing, fail-closed);
//! - shares floor-round; the leftover (dust) is distributed by the
//!   **largest-remainder** method, ordered and deterministic:
//!   `Σ shares ≡ net` exact — the total can never exceed or fall short
//!   of the net;
//! - empty heir set / zero weight total = Err (fail-closed).
//!
//! Reconciliation inside the cryptographic contract is OUTSIDE this
//! layer: today's Leaf 3 is a single 2-of-3 `multi_a` (taproot.rs) —
//! `split outputs` is NOT yet an on-chain primitive. The outputs of
//! `split_estate(...)` are the AMOUNTS the per-heir transfer
//! transactions (or a future weighted-split leaf) must pay; binding
//! them on-chain belongs to an external verification layer in the
//! `qsv psbt-live`/inheritance flow and is not this module's
//! responsibility (pure air-gap, no network line).

/// Estate ledger inputs, in sats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstateLedger {
    /// Estate assets (vault, UTXO, movable/immovable property — TMK m.599).
    pub assets_sats: u64,
    /// Estate receivables (lending/receivables — collectible claims).
    pub receivables_sats: u64,
    /// Estate debts (inheritance debts, creditors' rights).
    pub debts_sats: u64,
}

/// Settlement errors (all fail-closed — NO share, NO partial share).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementError {
    /// Debts exceeded assets+receivables: no distribution happens.
    /// `short_by_sats`: the size of the shortfall (debts − assets+receivables).
    Insolvent { short_by_sats: u64 },
    /// Sum: `checked_*` overflow (u64 bounds exceeded).
    Overflow,
    /// Heir list empty — nobody to distribute to.
    NoHeirs,
    /// Weight total is not 10,000 bps (no agreement with the statutory shares).
    InvalidWeights { total_bps: u32 },
}

impl core::fmt::Display for SettlementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SettlementError::Insolvent { short_by_sats } => {
                write!(
                    f,
                    "estate is insolvent: {short_by_sats} sats short (no distribution)"
                )
            }
            SettlementError::Overflow => write!(f, "estate arithmetic u64 overflow (fail-closed)"),
            SettlementError::NoHeirs => write!(f, "heir list empty (fail-closed)"),
            SettlementError::InvalidWeights { total_bps } => {
                write!(f, "heir weights sum to {total_bps} bps != 10000 bps")
            }
        }
    }
}

impl std::error::Error for SettlementError {}

/// Full weight (not "bp" — `bps` means **basis points**: 10,000 = 100%).
pub const FULL_BPS: u32 = 10_000;

/// Net estate amount: `assets + receivables − debts` (sats).
/// Overflow → `Overflow`; debts exceed → `Insolvent` (net < 0, fail-closed).
pub fn net_estate_sats(ledger: &EstateLedger) -> Result<u64, SettlementError> {
    let gross = ledger
        .assets_sats
        .checked_add(ledger.receivables_sats)
        .ok_or(SettlementError::Overflow)?;
    if ledger.debts_sats > gross {
        return Err(SettlementError::Insolvent {
            short_by_sats: ledger.debts_sats - gross,
        });
    }
    Ok(gross - ledger.debts_sats)
}

/// Heir share: `weight_bps` statutory share (10,000 = 100%).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeirShare {
    /// Heir label (same spelling as in the docs/05 share table).
    pub label: String,
    /// Full-weight share — must total exactly 10,000 bps.
    pub weight_bps: u32,
    /// Distributed sats (deterministic, sum ≡ net).
    pub sats: u64,
}

/// Distributes the net estate among the heirs (§2.2 "split outputs by
/// mathematical percentages"): floor rounding + largest-remainder
/// distribution ⇒ `Σ sats ≡ net_sats` (zero margin of error).
///
/// Input rules (all fail-closed): empty list → `NoHeirs`; weight
/// total ≠ 10,000 → `InvalidWeights`; `net = 0` is valid (everyone gets
/// 0 — the equality boundary, NOT insolvency; `net_estate_sats` already
/// made the `None`/`0` distinction).
pub fn split_estate(net_sats: u64, heirs: &[HeirShare]) -> Result<Vec<HeirShare>, SettlementError> {
    if heirs.is_empty() {
        return Err(SettlementError::NoHeirs);
    }
    let total: u32 = heirs
        .iter()
        .try_fold(0u32, |acc, h| acc.checked_add(h.weight_bps))
        .ok_or(SettlementError::Overflow)?;
    if total != FULL_BPS {
        return Err(SettlementError::InvalidWeights { total_bps: total });
    }

    // 1) floor shares
    let mut out = Vec::with_capacity(heirs.len());
    let mut assigned: u64 = 0;
    let mut remainders = Vec::with_capacity(heirs.len());
    for h in heirs {
        let exact = net_sats
            .checked_mul(u64::from(h.weight_bps))
            .ok_or(SettlementError::Overflow)?;
        let floor = exact / u64::from(FULL_BPS);
        remainders.push(exact % u64::from(FULL_BPS));
        assigned = assigned
            .checked_add(floor)
            .ok_or(SettlementError::Overflow)?;
        out.push(HeirShare {
            label: h.label.clone(),
            weight_bps: h.weight_bps,
            sats: floor,
        });
    }

    // 2) leftover (dust) total: deterministic largest-remainder distribution.
    let mut leftover = net_sats - assigned; // Σfloor ≤ net, proven internally
    let mut order: Vec<usize> = (0..out.len()).collect();
    // Stable order: remainder descending, ties by index.
    order.sort_by(|&a, &b| remainders[b].cmp(&remainders[a]).then(a.cmp(&b)));
    for idx in order {
        if leftover == 0 {
            break;
        }
        out[idx].sats += 1;
        leftover -= 1;
    }
    debug_assert_eq!(leftover, 0, "remainder distribution must consume the net");
    Ok(out)
}

/// Shortcut: ledger + heirs → shares (net first, then split).
pub fn settle(
    ledger: &EstateLedger,
    heirs: &[HeirShare],
) -> Result<Vec<HeirShare>, SettlementError> {
    let net = net_estate_sats(ledger)?;
    split_estate(net, heirs)
}

/// Constructor: `label`, `weight_bps` → `sats = 0` (raw heir before the split).
pub fn heir(label: &str, weight_bps: u32) -> HeirShare {
    HeirShare {
        label: label.to_string(),
        weight_bps,
        sats: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(assets: u64, rec: u64, debts: u64) -> EstateLedger {
        EstateLedger {
            assets_sats: assets,
            receivables_sats: rec,
            debts_sats: debts,
        }
    }

    #[test]
    fn net_subtracts_debts_from_assets_plus_receivables() {
        // 1,000 BTC assets + 100 BTC receivables − 400 BTC debts = 700 BTC.
        assert_eq!(
            net_estate_sats(&ledger(100_000_000_000, 10_000_000_000, 40_000_000_000)),
            Ok(70_000_000_000)
        );
    }

    #[test]
    fn insolvency_is_fail_closed_with_exact_shortfall() {
        let e = net_estate_sats(&ledger(1_000, 100, 2_500));
        assert_eq!(
            e,
            Err(SettlementError::Insolvent {
                short_by_sats: 1_400
            })
        );
        assert_eq!(
            e.unwrap_err().to_string(),
            "estate is insolvent: 1400 sats short (no distribution)"
        );
    }

    #[test]
    fn exact_zero_net_is_not_insolvency_boundary() {
        // Debts exactly equal → net = 0 → NOT insolvency (boundary: inclusive).
        assert_eq!(net_estate_sats(&ledger(1_000, 500, 1_500)), Ok(0));
        // Shares are zero too: total ≡ net = 0.
        let shares = split_estate(0, &[heir("child A", 5_000), heir("child B", 5_000)]).unwrap();
        assert_eq!(shares.iter().map(|s| s.sats).sum::<u64>(), 0);
    }

    #[test]
    fn weights_must_be_exactly_ten_thousand_bps_or_fail_closed() {
        assert_eq!(
            split_estate(1_000, &[heir("A", 5_000), heir("B", 4_999)]),
            Err(SettlementError::InvalidWeights { total_bps: 9_999 })
        );
        assert_eq!(
            split_estate(1_000, &[heir("A", 12_000)]),
            Err(SettlementError::InvalidWeights { total_bps: 12_000 })
        );
        assert_eq!(split_estate(1_000, &[]), Err(SettlementError::NoHeirs));
    }

    #[test]
    fn remainder_goes_to_the_largest_remainder_deterministically() {
        // net = 100, 3333/3333/3334: floors 33/33/33 + leftover 1 → the 4th
        // unit goes to the largest remainder (3334×100 = 333400 → remainder 400).
        let shares =
            split_estate(100, &[heir("A", 3_333), heir("B", 3_333), heir("C", 3_334)]).unwrap();
        let sats: Vec<u64> = shares.iter().map(|s| s.sats).collect();
        assert_eq!(sats, vec![33, 33, 34]);
        assert_eq!(sats.iter().sum::<u64>(), 100);
    }

    #[test]
    fn sum_of_shares_equals_net_exactly_over_a_matrix_of_inputs() {
        let weight_sets: &[&[u32]] = &[
            &[10_000],
            &[5_000, 5_000],
            &[5_000, 3_000, 2_000],
            &[
                1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000,
            ],
            &[3_333, 3_333, 3_334],
            &[1, 9_999],
        ];
        let nets: &[u64] = &[0, 1, 7, 99, 100, 101, 543_210, 21_000_000_000_000];
        for ws in weight_sets {
            let heirs: Vec<HeirShare> = ws
                .iter()
                .enumerate()
                .map(|(i, w)| heir(&format!("m{i}"), *w))
                .collect();
            for &net in nets {
                let out = split_estate(net, &heirs).unwrap();
                let sum: u64 = out.iter().map(|s| s.sats).sum();
                assert_eq!(sum, net, "net={net} weights={ws:?}");
                // An individual share never exceeds the fair division + 1.
                for (h, s) in heirs.iter().zip(out.iter()) {
                    let fair = net * u64::from(h.weight_bps) / u64::from(FULL_BPS);
                    assert!(s.sats <= fair + 1, "net={net}: {} share too large", h.label);
                }
            }
        }
    }

    #[test]
    fn arithmetic_overflow_is_an_error_not_a_wrap() {
        // Assets + receivables overflow → Err (no silent wrapping).
        assert_eq!(
            net_estate_sats(&ledger(u64::MAX, 1, 0)),
            Err(SettlementError::Overflow)
        );
        // The weight sum's u32 overflow → Overflow (sum undefined).
        assert_eq!(
            split_estate(1, &[heir("A", u32::MAX), heir("B", 1)]),
            Err(SettlementError::Overflow)
        );
        // Non-overflowing but unequal-to-10,000 total → InvalidWeights.
        assert_eq!(
            split_estate(1, &[heir("A", u32::MAX), heir("B", 0)]),
            Err(SettlementError::InvalidWeights {
                total_bps: u32::MAX
            })
        );
        // Net × weight overflow is also Err: safe including floor rounding.
        assert_eq!(
            split_estate(u64::MAX, &[heir("A", 10_000)]),
            Err(SettlementError::Overflow)
        );
    }

    #[test]
    fn settle_is_ledger_to_shares_end_to_end() {
        // The docs/05 §2.2 story: a 7 BTC house inheritance, 2 children
        // 50/50 + a spouse in the literature… net 700M sats → 350M/350M.
        let l = ledger(700_000_000, 0, 0);
        let out = settle(&l, &[heir("child A", 5_000), heir("child B", 5_000)]).unwrap();
        assert_eq!(
            out.iter().map(|s| s.sats).collect::<Vec<_>>(),
            vec![350_000_000, 350_000_000]
        );
        // Same ledger, TMK m.505-style 1/4 + 3/4 shares: 175M / 525M.
        let out = settle(&l, &[heir("spouse", 2_500), heir("child", 7_500)]).unwrap();
        assert_eq!(
            out.iter().map(|s| s.sats).collect::<Vec<_>>(),
            vec![175_000_000, 525_000_000]
        );
    }
}
