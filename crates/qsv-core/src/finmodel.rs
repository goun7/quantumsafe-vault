//! docs/06 financial-model engine — prose-pinned, INTEGER arithmetic.
//!
//! docs/06 (normative) carries handwritten business figures: the
//! operator/plan classification (three tiers), AUM/SAAS revenue
//! arithmetic, LTV/CAC, break-even and the 36-month pro-forma. This
//! module pulls those figures INTO CODE and the gate tests pin that
//! document and code tell the SAME story (hand mutants M49–M50,
//! `scripts/mutation_audit.sh`).
//!
//! Rules:
//! - money is `u64` **cents** (1 USD = 100 cents) — NO floating point;
//! - AUM shares are **basis points** (10 bps = 0.10%, 15 bps = 0.15%);
//! - tier bounds are **low-INCLUSIVE / high-EXCLUSIVE**: docs/06 §2's
//!   "50–500 & 500–5,000 BTC" overlap (500 appears in both ranges) is
//!   resolved here into a single rule and noted in the document;
//! - **below 50 BTC there is no tier** (fail-closed: `None` — an
//!   unserved profile is not predicted);
//! - the `$100M+` third tier is pinned to the document's BTC scale
//!   (above 5,000 BTC) for one axis — the document's dual BTC/USD axes
//!   are resolved with a note;
//!
//! Economic constants are NOT SACRED: if a price/threshold changes,
//! docs/06 and this file are updated together; the gate tests both.

/// Setup license per tier, in cents (docs/06 §2): $4,900 / $9,900 / $24,900.
pub const SETUP_LICENSE_CENTS: [u64; 3] = [490_000, 990_000, 2_490_000];

/// Sovereign Whale's recurring revenue (docs/06 §2): $199/mo Heartbeat SaaS.
pub const SAAS_MONTHLY_CENTS: u64 = 19_900;

/// Annual AUM share per tier, in **basis points** (docs/06 §2):
/// Sovereign flat SaaS (no AUM share), Family 0.10% = 10 bps,
/// Custodian 0.15% = 15 bps.
pub const AUM_BPS: [u64; 3] = [0, 10, 15];

/// Tier lower bounds (in BTC, low-INCLUSIVE):
/// `[50, 500)` Sovereign · `[500, 5_000)` Family Office · `≥ 5_000`
/// Custodian/Fund (docs/06 §2 table's "$100M+ fund" row pinned to the
/// BTC axis — see the module note).
pub const TIER_MIN_BTC: [u64; 3] = [50, 500, 5_000];

/// docs/06 §5: fixed annual operational cost ($6,000).
pub const FIXED_ANNUAL_CENTS: u64 = 600_000;

/// docs/06 §3.2: blended customer acquisition cost ($850).
pub const CAC_CENTS: u64 = 85_000;

/// docs/06 §3.1: MoR commission, 5% of gross revenue (500 bps).
pub const MOR_BPS: u64 = 500;

/// docs/06 §3.1: monthly COGS per vault — enclave $1.20 + RPC $3.50.
pub const COGS_ENCLAVE_CENTS_PER_MONTH: u64 = 120;
/// docs/06 §3.1: monthly blockchain-indexer/watchtower RPC per vault.
pub const COGS_RPC_CENTS_PER_MONTH: u64 = 350;

/// docs/06 §3.2 LTV example: the number of years the AUM share is
/// collected for. Customer lifetime is 60 months; year one counts as
/// the setup year and the AUM share is not collected from there — the
/// $69,900 example is built on these 4 years (the document's number,
/// the single interpretation the module pins).
pub const LTV_AUM_YEARS: u64 = 4;

/// Tiers (docs/06 §2 target-customer profiles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorTier {
    /// 50–500 BTC individual whale: $4,900 setup + $238,800/yr SaaS.
    Sovereign,
    /// 500–5,000 BTC family office: $9,900 setup + 0.10% AUM/yr.
    FamilyOffice,
    /// ≥5,000 BTC ($100M+ scale) fund/institution: $24,900 setup + 0.15% AUM/yr.
    CustodianFund,
}

impl OperatorTier {
    /// Tier index (0..=2) — the arrays' index.
    pub fn index(self) -> usize {
        match self {
            OperatorTier::Sovereign => 0,
            OperatorTier::FamilyOffice => 1,
            OperatorTier::CustodianFund => 2,
        }
    }

    /// Setup license, cents.
    pub fn setup_license_cents(self) -> u64 {
        SETUP_LICENSE_CENTS[self.index()]
    }

    /// Annual recurring revenue (ARR), cents — on the AUM-share tiers
    /// it goes through `aum_usd_cents` × basis points (floor rounding:
    /// the document's examples stay whole numbers; a fraction is never
    /// rounded in the house's favour or to zero).
    pub fn annual_arr_cents(self, aum_usd_cents: u64) -> u64 {
        match self {
            // $199/mo × 12 = $2,388/yr (independent of AUM).
            OperatorTier::Sovereign => SAAS_MONTHLY_CENTS * 12,
            other => aum_usd_cents * AUM_BPS[other.index()] / 10_000,
        }
    }

    /// Lifetime value per customer (docs/06 §3.2):
    /// setup + AUM share × `LTV_AUM_YEARS`.
    pub fn ltv_cents(self, aum_usd_cents: u64) -> u64 {
        self.setup_license_cents() + self.annual_arr_cents(aum_usd_cents) * LTV_AUM_YEARS
    }
}

/// BTC-AUM → tier. **Below 50 BTC there is no tier** (`None`,
/// fail-closed); bounds are low-INCLUSIVE: 500 is exactly Family
/// Office, 5,000 exactly Custodian (the resolved form of docs/06 §2
/// table's overlapping ranges).
pub fn classify_operator(btc_aum: u64) -> Option<OperatorTier> {
    if btc_aum < TIER_MIN_BTC[0] {
        return None;
    }
    if btc_aum < TIER_MIN_BTC[1] {
        return Some(OperatorTier::Sovereign);
    }
    if btc_aum < TIER_MIN_BTC[2] {
        return Some(OperatorTier::FamilyOffice);
    }
    Some(OperatorTier::CustodianFund)
}

/// LTV / CAC ratio, tenth precision (822 = 82.2×).
/// Division-by-zero fail-closed: `cac == 0` → `None` (ratio undefined).
pub fn ltv_cac_ratio_x10(ltv_cents: u64, cac_cents: u64) -> Option<u64> {
    if cac_cents == 0 {
        return None;
    }
    Some(ltv_cents * 10 / cac_cents)
}

/// Minimum setup sales to break even — INTEGER (rounded up):
/// NOT docs/06 §5's "≈1.2 customers" fraction, but the count that must
/// actually be sold ($6,000 / $4,900 → 2).
pub fn break_even_customers(setup_license_cents: u64) -> Option<u64> {
    if setup_license_cents == 0 {
        return None;
    }
    Some(FIXED_ANNUAL_CENTS.div_ceil(setup_license_cents))
}

/// Fractional break-even threshold, tenth precision (docs/06 §5's "≈1.2").
pub fn break_even_exact_x10(setup_license_cents: u64) -> Option<u64> {
    if setup_license_cents == 0 {
        return None;
    }
    Some(FIXED_ANNUAL_CENTS * 10 / setup_license_cents)
}

/// MoR commission, cents (5% of gross revenue).
pub fn mor_cents(gross_cents: u64) -> u64 {
    gross_cents * MOR_BPS / 10_000
}

/// Total monthly COGS per vault, cents (enclave + RPC).
pub fn cogs_per_vault_month_cents() -> u64 {
    COGS_ENCLAVE_CENTS_PER_MONTH + COGS_RPC_CENTS_PER_MONTH
}

/// Gross margin, basis points — zero revenue → `None` (undefined).
pub fn gross_margin_bps(gross_cents: u64, cogs_cents: u64) -> Option<u64> {
    if gross_cents == 0 {
        return None;
    }
    Some((gross_cents - cogs_cents) * 10_000 / gross_cents)
}

/// Net operating profit, cents — profit/loss may be SIGNED (i64):
/// `gross − MoR − infra − CAC`. Never squeezes a loss to 0.
pub fn net_operating_profit_cents(
    gross_cents: u64,
    mor_cents: u64,
    infra_cents: u64,
    cac_cents: u64,
) -> i64 {
    gross_cents as i64 - mor_cents as i64 - infra_cents as i64 - cac_cents as i64
}

// ── docs/06 §4: 36-month pro-forma (document rows, verbatim) ─────────────

/// Active vault counts, by year and tier (S/F/C) — docs/06 §4.
pub const PROFORMA_VAULTS: [[u32; 3]; 3] = [[18, 5, 1], [50, 20, 5], [115, 52, 13]];

/// Setup license revenue (cents) — docs/06 §4.
/// ONLY YEAR 1 decomposes from the table's setup counts
/// (18×$4,900 + 5×$9,900 + 1×$24,900 = $162,600); YEARS 2–3 rows are
/// NOT decomposed in the document and the engine does not invent them —
/// the identity tests only exercise the totals (an honest gap, written
/// into docs/06 §4's model note).
pub const PROFORMA_LICENSE_REVENUE_CENTS: [u64; 3] = [16_260_000, 38_420_000, 82_150_000];

/// Annual AUM & SaaS revenue (cents) — docs/06 §4.
pub const PROFORMA_SAAS_REVENUE_CENTS: [u64; 3] = [8_790_000, 30_940_000, 89_420_000];

/// Cost lines (cents), in year order — docs/06 §4
/// (MoR 5% · infrastructure & servers · sales & marketing/CAC).
pub const PROFORMA_COSTS_CENTS: [[u64; 3]; 3] = [
    [1_252_500, 420_000, 2_040_000],
    [3_468_000, 1_260_000, 4_335_000],
    [8_578_500, 2_880_000, 8_925_000],
];

/// Total annual gross revenue (cents) — docs/06 §4.
pub const PROFORMA_GROSS_CENTS: [u64; 3] = [25_050_000, 69_360_000, 171_570_000];

#[cfg(test)]
mod tests {
    use super::*;

    // ── operator/plan classification (E4c, M49-pinned) ──

    #[test]
    fn classify_is_fail_closed_below_50_btc() {
        assert_eq!(classify_operator(0), None);
        assert_eq!(classify_operator(49), None);
        assert_eq!(classify_operator(50), Some(OperatorTier::Sovereign));
    }

    #[test]
    fn classify_boundaries_are_low_inclusive_high_exclusive() {
        // The resolved form of docs/06 §2's "50–500 & 500–5,000" overlap:
        assert_eq!(classify_operator(499), Some(OperatorTier::Sovereign));
        assert_eq!(classify_operator(500), Some(OperatorTier::FamilyOffice));
        assert_eq!(classify_operator(4_999), Some(OperatorTier::FamilyOffice));
        assert_eq!(classify_operator(5_000), Some(OperatorTier::CustodianFund));
        assert_eq!(
            classify_operator(u64::MAX),
            Some(OperatorTier::CustodianFund)
        );
    }

    // ── revenue arithmetic (M50-pinned) ──

    #[test]
    fn pricing_matches_the_docs_table() {
        assert_eq!(OperatorTier::Sovereign.setup_license_cents(), 490_000); // $4,900
        assert_eq!(OperatorTier::FamilyOffice.setup_license_cents(), 990_000); // $9,900
        assert_eq!(OperatorTier::CustodianFund.setup_license_cents(), 2_490_000); // $24,900
                                                                                  // $199/mo × 12 = $2,388/yr (independent of AUM).
        assert_eq!(OperatorTier::Sovereign.annual_arr_cents(0), 238_800);
    }

    #[test]
    fn aum_fees_are_basis_points_with_floor_semantics() {
        // docs/06 §2 example: $20M AUM × 0.10% = $20,000 exactly.
        let aum_20m = 2_000_000_000;
        assert_eq!(
            OperatorTier::FamilyOffice.annual_arr_cents(aum_20m),
            2_000_000
        );
        // $100M × 0.15% = $150,000 exactly (docs/06 §2 Custodian example).
        let aum_100m = 10_000_000_000;
        assert_eq!(
            OperatorTier::CustodianFund.annual_arr_cents(aum_100m),
            15_000_000
        );
        // A fraction is never rounded: 1 cent × 10 bps = 0 (floor).
        assert_eq!(OperatorTier::FamilyOffice.annual_arr_cents(1), 0);
    }

    #[test]
    fn ltv_matches_the_docs_example_and_ratio_is_82_2x() {
        // docs/06 §3.2: $9,900 + ($15,000/yr × 4 yr) = $69,900.
        let aum_15m = 1_500_000_000;
        assert_eq!(OperatorTier::FamilyOffice.ltv_cents(aum_15m), 6_990_000);
        // LTV/CAC = 69,900 / 850 ≈ 82.2× (tenth precision).
        assert_eq!(ltv_cac_ratio_x10(6_990_000, CAC_CENTS), Some(822));
        // Division by zero is undefined, never rounded to 0.
        assert_eq!(ltv_cac_ratio_x10(6_990_000, 0), None);
    }

    #[test]
    fn break_even_is_an_integer_count_not_a_fraction() {
        // docs/06 §5: $6,000 / $4,900 ≈ 1.2 fraction → but 2 setups are REALLY needed.
        assert_eq!(break_even_exact_x10(490_000), Some(12)); // "≈1.2 customers"
        assert_eq!(break_even_customers(490_000), Some(2));
        // Same cost on the pricier tier: 600,000/990,000 → 1 setup suffices.
        assert_eq!(break_even_customers(990_000), Some(1));
        // Zero license is undefined (division-by-zero fail-closed).
        assert_eq!(break_even_customers(0), None);
        assert_eq!(break_even_exact_x10(0), None);
    }

    #[test]
    fn costs_and_margin_follow_the_docs_units() {
        // $1.20 + $3.50 = $4.70 / vault / month.
        assert_eq!(cogs_per_vault_month_cents(), 470);
        // MoR: 5% of gross revenue.
        assert_eq!(mor_cents(25_050_000), 1_252_500); // docs/06 §4 Year 1
                                                      // Margin: zero revenue → undefined; example: 1000 revenue − 60 cost = 940 bps… no: 94%.
        assert_eq!(gross_margin_bps(1_000, 60), Some(9_400));
        assert_eq!(gross_margin_bps(0, 60), None);
    }

    #[test]
    fn net_profit_keeps_losses_signed() {
        // docs/06 §4 Year 1: 250,500 − 12,525 − 4,200 − 20,400 = 213,375 ✓
        assert_eq!(
            net_operating_profit_cents(25_050_000, 1_252_500, 420_000, 2_040_000),
            21_337_500
        );
        // A loss is NOT SQUEEZED to 0 (i64 signed): 100 − 300 = −200.
        assert_eq!(net_operating_profit_cents(100, 0, 300, 0), -200);
    }

    // ── pro-forma identities (docs/06 §4) ──

    #[test]
    fn proforma_vault_rows_sum_to_the_totals() {
        assert_eq!(
            PROFORMA_VAULTS
                .iter()
                .map(|r| r.iter().sum::<u32>())
                .collect::<Vec<_>>(),
            vec![24, 75, 180]
        );
    }

    #[test]
    fn proforma_identity_rows_hold_in_every_year() {
        for y in 0..3 {
            let gross = PROFORMA_GROSS_CENTS[y];
            let lic = PROFORMA_LICENSE_REVENUE_CENTS[y];
            let saas = PROFORMA_SAAS_REVENUE_CENTS[y];
            // TOTAL GROSS REVENUE = license + AUM&SaaS.
            assert_eq!(gross, lic + saas, "year {y}: gross identity");
            // NET = gross − (MoR + infra + CAC).
            let costs: u64 = PROFORMA_COSTS_CENTS[y].iter().sum();
            assert_eq!(
                net_operating_profit_cents(gross, 0, costs, 0),
                gross as i64 - costs as i64,
                "year {y}: net identity"
            );
        }
        // The NET OPERATING PROFIT row's document values (Years 1–3).
        assert_eq!(
            net_operating_profit_cents(
                PROFORMA_GROSS_CENTS[0],
                0,
                PROFORMA_COSTS_CENTS[0].iter().sum::<u64>(),
                0
            ),
            21_337_500
        );
        assert_eq!(
            net_operating_profit_cents(
                PROFORMA_GROSS_CENTS[1],
                0,
                PROFORMA_COSTS_CENTS[1].iter().sum::<u64>(),
                0
            ),
            60_297_000
        );
        assert_eq!(
            net_operating_profit_cents(
                PROFORMA_GROSS_CENTS[2],
                0,
                PROFORMA_COSTS_CENTS[2].iter().sum::<u64>(),
                0
            ),
            151_186_500
        );
    }

    #[test]
    fn year_one_license_revenue_decomposes_into_the_pricing_table() {
        // 18×$4,900 + 5×$9,900 + 1×$24,900 = $162,600 — the pricing model
        // and the pro-forma land on the SAME number (docs/06 §4 + §2 pinned
        // together).
        let derived: u64 = PROFORMA_VAULTS[0]
            .iter()
            .zip(SETUP_LICENSE_CENTS)
            .map(|(n, lic)| u64::from(*n) * lic)
            .sum();
        assert_eq!(derived, PROFORMA_LICENSE_REVENUE_CENTS[0]);
    }

    #[test]
    fn mor_matches_the_cost_row_in_every_year() {
        // §4's MoR row = 5% of gross revenue (the identity is not a separate account).
        assert_eq!(
            mor_cents(PROFORMA_GROSS_CENTS[0]),
            PROFORMA_COSTS_CENTS[0][0]
        );
        assert_eq!(
            mor_cents(PROFORMA_GROSS_CENTS[1]),
            PROFORMA_COSTS_CENTS[1][0]
        );
        assert_eq!(
            mor_cents(PROFORMA_GROSS_CENTS[2]),
            PROFORMA_COSTS_CENTS[2][0]
        );
    }
}
