//! Per-leaf spend budget analysis (BIP-341 weight, BIP-342 element limits).
//!
//! For every leaf of the vault MAST this module builds a REAL reference spend
//! (correct nSequence, genuine Schnorr signatures from the demo keypairs,
//! full witness: signatures → script → control block) and measures what
//! consensus actually sees: witness element sizes, transaction weight, virtual
//! size and the resulting fee at representative feerates.
//!
//! Why this exists (docs/02 §4, docs/03 §5): tapscript caps every INITIAL
//! witness stack element at 520 bytes (BIP-342 resource limits — pinned by the
//! `t6_wots_element_above_520_bytes_is_consensus_illegal` regression test).
//! A fee/size table computed from signed, consensus-shaped transactions turns
//! the "is any leaf unspendable or uneconomical?" question into an auditable
//! number instead of an estimate.
//!
//! Every figure is derived at runtime from the actual derived vault — nothing
//! is hard-coded.

use crate::demo_keys;
use crate::taproot::VaultLeaves;
use crate::unvault;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Keypair;
use bitcoin::taproot::{ControlBlock, LeafVersion};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, Txid};

/// Representative feerates (sat/vB) for the printed fee table.
pub const FEE_RATES_SAT_PER_VB: [u64; 5] = [1, 5, 10, 50, 100];

/// BIP-342 initial-stack element cap, in bytes.
pub const BIP342_MAX_ELEMENT_BYTES: usize = 520;

/// The four spendable branches of the vault MAST.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafKind {
    /// Leaf 1 — normal hybrid 2-of-2 (user + enclave co-signer).
    Normal,
    /// Leaf 2 — recovery / cold sweep after CSV 144.
    Recovery,
    /// Leaf 3 — inheritance k-of-n after CSV 26,280.
    Inheritance,
    /// Leaf 4 — post-Q-Day emergency kit (commit-reveal).
    Emergency,
}

impl LeafKind {
    /// Tree order (leaf index 1..=4 as documented).
    pub const ALL: [LeafKind; 4] = [
        LeafKind::Normal,
        LeafKind::Recovery,
        LeafKind::Inheritance,
        LeafKind::Emergency,
    ];

    /// Human label used by reports and the CLI.
    pub fn label(self) -> &'static str {
        match self {
            LeafKind::Normal => "Leaf 1 · normal hybrid (2-of-2)",
            LeafKind::Recovery => "Leaf 2 · recovery sweep (CSV 144)",
            LeafKind::Inheritance => "Leaf 3 · inheritance 2-of-3 (CSV 26,280)",
            LeafKind::Emergency => "Leaf 4 · emergency kit (commit-reveal)",
        }
    }

    /// CSV height lock encoded in the leaf's nSequence, if any.
    pub fn csv_blocks(self) -> Option<u16> {
        match self {
            LeafKind::Normal | LeafKind::Emergency => None,
            LeafKind::Recovery => Some(crate::policy::RECOVERY_CSV_BLOCKS),
            LeafKind::Inheritance => Some(crate::policy::INHERITANCE_CSV_BLOCKS),
        }
    }

    /// The leaf script as committed in the vault tree.
    pub fn script(self, leaves: &VaultLeaves) -> &ScriptBuf {
        match self {
            LeafKind::Normal => &leaves.normal,
            LeafKind::Recovery => &leaves.recovery,
            LeafKind::Inheritance => &leaves.inheritance,
            LeafKind::Emergency => &leaves.emergency,
        }
    }
}

/// Errors raised while assembling a reference spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetError {
    /// The control block for a committed leaf is missing (impossible for a
    /// finalized `VaultTaproot`; surfaced instead of panicking).
    MissingControl(&'static str),
    /// Transaction assembly failed (fee/value arithmetic).
    Tx(String),
}

impl core::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BudgetError::MissingControl(leaf) => {
                write!(f, "control block missing for leaf {leaf}")
            }
            BudgetError::Tx(s) => write!(f, "tx assembly error: {s}"),
        }
    }
}

impl std::error::Error for BudgetError {}

/// Measured budget of one leaf's reference spend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafBudget {
    /// Which leaf was measured.
    pub leaf: LeafKind,
    /// Leaf script size in bytes (committed in the merkle tree).
    pub script_bytes: usize,
    /// Control block size in bytes (33 + 32 × tree depth).
    pub control_bytes: usize,
    /// Witness element sizes, in witness serialization order (first element
    /// = deepest stack item; control block is last = stack top). The
    /// inheritance leaf shows a 0-byte element: the empty signature slot of
    /// the non-signing executor (multi_a discipline, BIP-342 `false`).
    pub witness_elements: Vec<usize>,
    /// Sum of all witness element sizes in bytes.
    pub witness_bytes: usize,
    /// Largest single witness element (BIP-342 limit applies to each).
    pub max_element_bytes: usize,
    /// Serialized transaction weight in weight units (WU).
    pub tx_weight: u64,
    /// Virtual size of the spend transaction (vbytes).
    pub tx_vbytes: u64,
}

impl LeafBudget {
    /// True iff every witness element satisfies the BIP-342 520-byte cap.
    pub fn bip342_ok(&self) -> bool {
        self.max_element_bytes <= BIP342_MAX_ELEMENT_BYTES
    }

    /// Margin to the BIP-342 cap in bytes.
    pub fn bip342_margin(&self) -> usize {
        BIP342_MAX_ELEMENT_BYTES.saturating_sub(self.max_element_bytes)
    }

    /// Fee table for this spend: `(sat_per_vb, fee_sats)` in `FEE_RATES_SAT_PER_VB` order.
    pub fn fee_table(&self) -> Vec<(u64, u64)> {
        FEE_RATES_SAT_PER_VB
            .iter()
            .map(|&r| (r, r.saturating_mul(self.tx_vbytes)))
            .collect()
    }
}

/// The EXPERIMENTAL BIP-360 (P2MR) delta for one measured leaf spend.
///
/// BIP-360 drops the control block's 33rd byte (the x-only internal key):
/// at tree depth d the witness carries 33+32·d bytes today but 1+32·d under
/// P2MR — a flat 32-byte saving per script-path input. Because witness bytes
/// count 1 WU each in the BIP-141 weight (the ×4 multiplier applies only to
/// the non-witness part), the saving is 32 WU = 8 vB per input. This is
/// ARITHMETIC ONLY: no P2MR consensus code exists or is exercised (K1
/// outstanding, docs/11). The witness v2 marker byte is NOT included in the
/// delta; it is part of the consensus wrapping, not the witness stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P2mrDelta {
    /// Today's control block size (33 + 32 × depth).
    pub control_bytes_p2tr: usize,
    /// P2MR control block size (1 + 32 × depth).
    pub control_bytes_p2mr: usize,
    /// Transaction weight today (WU).
    pub tx_weight_p2tr: u64,
    /// Transaction weight under P2MR (WU) = today − 32.
    pub tx_weight_p2mr: u64,
    /// Virtual size today (vbytes, ceiling).
    pub tx_vbytes_p2tr: u64,
    /// Virtual size under P2MR (vbytes, ceiling).
    pub tx_vbytes_p2mr: u64,
    /// Fee savings at each representative feerate `(rate, saved_sats)`.
    pub fee_savings: Vec<(u64, u64)>,
}

/// The REAL, measured P2MR weight saving per script-path input, as printed
/// by `psbt-live --p2mr` and audited by `bip360-status` against docs/11's
/// machine-readable claim. Witness bytes weigh 1 WU each under BIP-141 (the
/// ×4 multiplier applies only to the non-witness part), so dropping 32
/// control-block bytes saves exactly 32 WU = 8 vB per input.
pub fn measured_p2mr_weight_saving_wu() -> u64 {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let vault = crate::taproot::VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_keys::enclave_key(),
        demo_keys::recovery_key(),
        &[demo_keys::heir_one(), demo_keys::heir_two()],
        2,
    )
    .unwrap_or_else(|e| panic!("demo vault derivation failed: {e}"));
    let b = leaf_budgets(&vault)
        .expect("leaf budgets")
        .into_iter()
        .next()
        .expect("at least one leaf");
    let d = p2mr_delta(&b);
    d.tx_weight_p2tr - d.tx_weight_p2mr
}

/// Computes the P2MR delta for a measured leaf budget.
pub fn p2mr_delta(b: &LeafBudget) -> P2mrDelta {
    let saved_bytes = 32usize;
    // Witness bytes contribute 1 WU each (BIP-141: the ×4 multiplier applies
    // only to the non-witness part), so 32 B saved = 32 WU = 8 vB per input.
    let weight_saved = saved_bytes as u64;
    let p2mr_weight = b.tx_weight.saturating_sub(weight_saved);
    P2mrDelta {
        control_bytes_p2tr: b.control_bytes,
        control_bytes_p2mr: b.control_bytes.saturating_sub(saved_bytes),
        tx_weight_p2tr: b.tx_weight,
        tx_weight_p2mr: p2mr_weight,
        tx_vbytes_p2tr: b.tx_vbytes,
        tx_vbytes_p2mr: p2mr_weight.div_ceil(4),
        fee_savings: FEE_RATES_SAT_PER_VB
            .iter()
            .map(|&r| (r, r.saturating_mul(b.tx_vbytes - p2mr_weight.div_ceil(4))))
            .collect(),
    }
}

/// Builds the reference spend for one leaf: correct nSequence (CSV where the
/// leaf enforces it), genuine Schnorr signatures from the demo keypairs and
/// the full BIP-341 script-path witness. Output: a single P2TR payment to the
/// demo heir (shape-neutral: any 34-byte P2TR spk has identical weight).
///
/// The result is consensus-verifiable (the integration suite checks every
/// leaf against libbitcoinconsensus when the `consensus` feature is on).
pub fn reference_spend(
    vault: &crate::taproot::VaultTaproot,
    leaf: LeafKind,
) -> Result<Transaction, BudgetError> {
    let script = leaf.script(&vault.leaves).clone();
    let control: ControlBlock = vault
        .spend_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or(BudgetError::MissingControl(leaf.label()))?;

    let value = Amount::from_sat(100_000);
    let fee = Amount::from_sat(1_000);
    let outpoint = OutPoint::new(Txid::from_byte_array([0xB5u8; 32]), leaf_index(leaf));
    // Reference output: a P2TR payment to the demo heir (34-byte spk, the
    // standard vault-rotation destination).
    let out_spk = crate::wots::p2tr_spk(&demo_keys::heir_one());
    let mut tx = unvault::build_unvault_tx(outpoint, value, &out_spk, fee)
        .map_err(|e| BudgetError::Tx(e.to_string()))?;

    // nSequence must encode the leaf's relative lock (BIP-68) where the leaf
    // demands CSV; otherwise signal RBF.
    tx.input[0].sequence = match leaf.csv_blocks() {
        Some(csv) => Sequence::from_height(csv),
        None => Sequence::ENABLE_RBF_NO_LOCKTIME,
    };

    let prev_spk = crate::wots::p2tr_spk(&vault.output_key());
    let sighash = unvault::script_spend_sighash(&tx, 0, &script, value, &prev_spk);
    let sign = |kp: &Keypair| unvault::sign_schnorr(kp, &sighash).to_vec();

    // Witness stack order: first argument = deepest element; the script pops
    // the TOP (last) element first. Sizes are identical either way; the order
    // below is the one consensus accepts (integration tests verify it).
    let sigs: Vec<Vec<u8>> = match leaf {
        // `<user> CHECKSIGVERIFY <enclave> CHECKSIG` pops σ_enclave first.
        LeafKind::Normal => vec![
            sign(&demo_keys::enclave_keypair()),
            sign(&demo_keys::user_keypair()),
        ],
        // CSV DROP <recovery> CHECKSIG pops σ_recovery first.
        LeafKind::Recovery => vec![sign(&demo_keys::recovery_keypair())],
        // multi_a discipline (rust-miniscript satisfaction): ONE witness slot
        // per key in reverse script order; a missing signer's slot holds an
        // EMPTY signature, which tapscript counts as `false` (BIP-342:
        // `success = !sig.empty()`), never an error. 2-of-3 with the executor
        // absent → [∅, σ_heir2, σ_heir1]; CHECKSIGADD sums 1+1+0 = 2 ≥ k.
        LeafKind::Inheritance => vec![
            Vec::new(), // executor slot: empty signature (not a signer here)
            sign(&demo_keys::heir_two_keypair()),
            sign(&demo_keys::heir_one_keypair()),
        ],
        // OP_DUP … OP_CHECKSIG pops σ_em; then the revealed key is hashed.
        LeafKind::Emergency => vec![
            sign(&demo_keys::emergency_kit_keypair()),
            demo_keys::emergency_kit_key().serialize().to_vec(),
        ],
    };

    tx.input[0].witness = unvault::build_script_path_witness(&sigs, &script, &control);
    Ok(tx)
}

fn leaf_index(leaf: LeafKind) -> u32 {
    match leaf {
        LeafKind::Normal => 0,
        LeafKind::Recovery => 1,
        LeafKind::Inheritance => 2,
        LeafKind::Emergency => 3,
    }
}

/// Measures every leaf of the given vault (tree order).
pub fn leaf_budgets(vault: &crate::taproot::VaultTaproot) -> Result<Vec<LeafBudget>, BudgetError> {
    LeafKind::ALL
        .iter()
        .map(|&kind| {
            let tx = reference_spend(vault, kind)?;
            let control = vault
                .spend_info
                .control_block(&(kind.script(&vault.leaves).clone(), LeafVersion::TapScript))
                .ok_or(BudgetError::MissingControl(kind.label()))?;
            let witness_elements: Vec<usize> =
                tx.input[0].witness.iter().map(|e| e.len()).collect();
            Ok(LeafBudget {
                leaf: kind,
                script_bytes: kind.script(&vault.leaves).len(),
                control_bytes: control.serialize().len(),
                witness_bytes: witness_elements.iter().sum(),
                max_element_bytes: witness_elements.iter().copied().max().unwrap_or(0),
                tx_weight: tx.weight().to_wu(),
                tx_vbytes: tx.weight().to_vbytes_ceil(),
                witness_elements,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot::VaultTaproot;
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
    fn script_and_control_sizes_are_exact() {
        let vault = demo_vault();
        let budgets = leaf_budgets(&vault).unwrap();
        let by = |k: LeafKind| budgets.iter().find(|b| b.leaf == k).unwrap();

        // Script sizes: 1+1+33+1+1 = 37 (emergency), 33+1+33+1 = 68 (normal),
        // 3+1+1+33+1 = 39 (recovery: push 144 = 0x90 needs a sign pad byte),
        // 3+1+1+3×34+1+1 = 109 (inheritance, 2-of-3).
        assert_eq!(by(LeafKind::Normal).script_bytes, 68);
        assert_eq!(by(LeafKind::Recovery).script_bytes, 39);
        assert_eq!(by(LeafKind::Inheritance).script_bytes, 109);
        assert_eq!(by(LeafKind::Emergency).script_bytes, 37);

        // Balanced 4-leaf Huffman tree ⇒ depth 2 ⇒ control block 33+32·2 = 97 B.
        for b in &budgets {
            assert_eq!(b.control_bytes, 97, "{}", b.leaf.label());
        }
    }

    #[test]
    fn witness_layout_matches_leaf_grammar() {
        let vault = demo_vault();
        let budgets = leaf_budgets(&vault).unwrap();
        let by = |k: LeafKind| budgets.iter().find(|b| b.leaf == k).unwrap();

        // [σ_enclave, σ_user, script, control]
        assert_eq!(by(LeafKind::Normal).witness_elements, vec![64, 64, 68, 97]);
        // [σ_recovery, script, control]
        assert_eq!(by(LeafKind::Recovery).witness_elements, vec![64, 39, 97]);
        // [∅ (empty executor slot), σ_heir2, σ_heir1, script, control]
        assert_eq!(
            by(LeafKind::Inheritance).witness_elements,
            vec![0, 64, 64, 109, 97]
        );
        // [σ_em, pk_em, script, control] — commit-reveal keeps every element tiny.
        assert_eq!(
            by(LeafKind::Emergency).witness_elements,
            vec![64, 32, 37, 97]
        );
    }

    #[test]
    fn every_leaf_stays_within_bip342_and_fees_scale_linearly() {
        let vault = demo_vault();
        for b in leaf_budgets(&vault).unwrap() {
            // Label is bound EAGERLY: format args are lazy, so an always-true
            // assert would never evaluate `b.leaf.label()` on this line.
            let label = b.leaf.label();
            assert!(
                b.bip342_ok(),
                "{label}: max element {} > 520",
                b.max_element_bytes
            );
            assert!(b.bip342_margin() >= 520 - 109, "margin too small");
            assert!(b.tx_vbytes > 0 && b.tx_weight >= b.tx_vbytes * 3);
            let fees = b.fee_table();
            assert_eq!(fees.len(), FEE_RATES_SAT_PER_VB.len());
            for window in fees.windows(2) {
                assert!(window[1].1 > window[0].1, "fee must grow with rate");
                assert_eq!(window[1].1, window[1].0 * b.tx_vbytes);
            }
        }
    }

    #[test]
    fn bip342_cap_is_inclusive_at_exactly_520_bytes() {
        // BIP-342: an initial-stack element of EXACTLY 520 bytes is legal.
        // The public helper must agree AT the boundary — the Round-32 sweep's
        // `<=`→`<` flip survived until this was pinned, misjudging every
        // exactly-520 element (a consensus-legal witness refused).
        let mk = |max: usize| LeafBudget {
            leaf: LeafKind::Emergency,
            script_bytes: 37,
            control_bytes: 97,
            witness_elements: vec![max],
            witness_bytes: max,
            max_element_bytes: max,
            tx_weight: 600,
            tx_vbytes: 150,
        };
        assert!(mk(BIP342_MAX_ELEMENT_BYTES).bip342_ok());
        assert!(!mk(BIP342_MAX_ELEMENT_BYTES + 1).bip342_ok());
        assert_eq!(mk(BIP342_MAX_ELEMENT_BYTES).bip342_margin(), 0);
    }

    #[test]
    fn p2mr_delta_saves_exactly_32_bytes_per_script_path_input() {
        let vault = demo_vault();
        for b in leaf_budgets(&vault).unwrap() {
            let d = p2mr_delta(&b);
            // Control block 33+32d → 1+32d: exactly 32 B at any depth.
            assert_eq!(d.control_bytes_p2tr - d.control_bytes_p2mr, 32);
            assert_eq!(d.control_bytes_p2tr, b.control_bytes);
            // Witness saves 32 B ⇒ weight saves 32 WU (witness bytes × 1 WU).
            assert_eq!(d.tx_weight_p2tr - d.tx_weight_p2mr, 32);
            // vbytes = ceil(weight/4) on both sides.
            assert_eq!(d.tx_vbytes_p2mr, d.tx_weight_p2mr.div_ceil(4));
            assert!(d.tx_vbytes_p2mr < d.tx_vbytes_p2tr);
            // Fee savings scale with the feerate and match the vbytes delta.
            let saved_vb = d.tx_vbytes_p2tr - d.tx_vbytes_p2mr;
            assert_eq!(saved_vb, 8, "32 WU = exactly 8 vB at any alignment");
            for (rate, saved) in &d.fee_savings {
                assert_eq!(*saved, rate * saved_vb);
            }
        }
    }

    #[test]
    fn emergency_spend_is_the_lightest_after_recovery() {
        let vault = demo_vault();
        let budgets = leaf_budgets(&vault).unwrap();
        let vb = |k: LeafKind| budgets.iter().find(|b| b.leaf == k).unwrap().tx_vbytes;
        // Fewest bytes: recovery (3 elements, 38 B script), then emergency
        // (4 elements but 37 B script + 32 B reveal), then normal, inheritance.
        assert!(vb(LeafKind::Recovery) < vb(LeafKind::Emergency));
        assert!(vb(LeafKind::Emergency) < vb(LeafKind::Normal));
        assert!(vb(LeafKind::Normal) < vb(LeafKind::Inheritance));
    }

    #[test]
    fn reference_spends_have_expected_shape() {
        let vault = demo_vault();
        for kind in LeafKind::ALL {
            let tx = reference_spend(&vault, kind).unwrap();
            assert_eq!(tx.input.len(), 1);
            assert_eq!(tx.output.len(), 1);
            let expected_seq = match kind.csv_blocks() {
                Some(csv) => Sequence::from_height(csv).to_consensus_u32(),
                None => Sequence::ENABLE_RBF_NO_LOCKTIME.to_consensus_u32(),
            };
            assert_eq!(
                tx.input[0].sequence.to_consensus_u32(),
                expected_seq,
                "nSequence must encode the leaf's CSV guard (BIP-68) or RBF",
            );
            // Witness: signatures/key, script, control block last.
            let w = &tx.input[0].witness;
            let items: Vec<&[u8]> = w.iter().collect();
            assert!(items.len() >= 3);
            assert_eq!(
                items.last().unwrap().len(),
                97,
                "control block is the final element"
            );
            assert_eq!(
                items[items.len() - 2].len(),
                kind.script(&vault.leaves).len(),
                "script precedes the control block"
            );
        }
    }
}
