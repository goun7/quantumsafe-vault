//! Miniscript policy layer (BIP-379) for the QuantumSafe-Vault spending tree.
//!
//! Policy (docs/03 §4.1):
//!   or_d(
//!     and_v(v:pk(key_user), pk(key_enclave)),                 // normal hybrid spend
//!     or_c(
//!       and_v(v:older(144), pk(key_recovery)),                // 144-block emergency sweep
//!       and_v(v:older(26280),                                 // ~180d inheritance
//!         thresh(2, pk(key_heir_1), pk(key_heir_2), pk(key_executor)))
//!     )
//!   )
//!
//! Note (honest scoping, Module 02 §3): the enclave branch is 2-of-2 CLASSIC
//! Schnorr at the consensus layer; the quantum resistance of the second key
//! lives in the PQC-gated co-signer (qsv-pqc). On-chain covenant output pinning
//! is scoped to Phase 2 (see unvault.rs).
//!
//! Relationship to the on-chain MAST (pinned by integration test T8): this
//! policy describes the THREE classical branches — normal, recovery and
//! inheritance — whose six keys are exactly the keys committed in leaves 1–3,
//! with the SAME CSV constants (144 / 26,280). The fourth leaf (post-Q-Day
//! emergency kit, `taproot::emergency_leaf_script`) is deliberately OUTSIDE
//! the classical policy: its destination key is committed as a SHA-256 digest,
//! never as a policy key, because it must remain undisclosed until a Q-Day
//! spend. Two views, one protocol: policy = who may spend under normal rules;
//! MAST = every consensus-enforced spending path including the sealed kit.

use core::str::FromStr;
use miniscript::descriptor::DescriptorPublicKey;
use miniscript::miniscript::decode::Terminal;
use miniscript::miniscript::{Miniscript, Tap};
use miniscript::policy::concrete::Policy;
use miniscript::{MiniscriptKey, RelLockTime, Threshold};
use std::sync::Arc;

/// Public-key material accepted by the policy builder. Uses `DescriptorPublicKey`
/// so hardware-wallet xpubs drop in unchanged for production deployment.
pub type Pk = DescriptorPublicKey;

/// Errors raised while building or compiling the vault policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// The threshold needs at least 2 heirs to be meaningful for 2-of-n.
    NotEnoughHeirs,
    /// Miniscript compilation or type-check failure.
    Compile(String),
    /// Descriptor key parsing failure.
    Key(String),
    /// Threshold construction failure (k out of range).
    Threshold(String),
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PolicyError::NotEnoughHeirs => write!(f, "at least 2 heir keys are required"),
            PolicyError::Compile(s) => write!(f, "policy compile error: {s}"),
            PolicyError::Key(s) => write!(f, "descriptor key error: {s}"),
            PolicyError::Threshold(s) => write!(f, "threshold error: {s}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Parse a raw 33-byte compressed public key (hex) or xpub expression into a
/// descriptor public key.
pub fn parse_pk(key_expr: &str) -> Result<Pk, PolicyError> {
    Pk::from_str(key_expr).map_err(|e| PolicyError::Key(e.to_string()))
}

/// Builder inputs for the QuantumSafe vault policy.
pub struct VaultPolicyInput {
    /// Owner's classic (hardware wallet) key — normal branch, signature 1 of 2.
    pub key_user: Pk,
    /// Enclave co-signer key — normal branch, signature 2 of 2 (PQC-gated off-chain).
    pub key_enclave: Pk,
    /// Emergency cold-sweep key (clawback / veto path).
    pub key_recovery: Pk,
    /// Heir threshold group keys.
    pub key_heirs: Vec<Pk>,
    /// Estate executor / counsel key (completes the 2-of-n threshold).
    pub key_executor: Pk,
}

/// Blocks for the recovery path (docs/03: 144 blocks ≈ 24h).
pub const RECOVERY_CSV_BLOCKS: u16 = 144;
/// Blocks for the inheritance path (docs/04: 26,280 blocks ≈ 180 days).
pub const INHERITANCE_CSV_BLOCKS: u16 = 26_280;

fn arc<P: MiniscriptKey>(p: Policy<P>) -> Arc<Policy<P>> {
    Arc::new(p)
}

fn older(blocks: u16) -> Arc<Policy<Pk>> {
    arc(Policy::Older(RelLockTime::from_height(blocks)))
}

/// Compile the full QuantumSafe vault policy into a Taproot Miniscript (BIP-379).
pub fn compile_vault_policy(input: &VaultPolicyInput) -> Result<Miniscript<Pk, Tap>, PolicyError> {
    if input.key_heirs.len() < 2 {
        return Err(PolicyError::NotEnoughHeirs);
    }

    // Branch 1: normal hybrid spend (2-of-2 classic Schnorr at consensus layer).
    let normal = Policy::And(vec![
        arc(Policy::Key(input.key_user.clone())),
        arc(Policy::Key(input.key_enclave.clone())),
    ]);

    // Branch 2a: emergency recovery sweep after 144 blocks.
    let recovery = Policy::And(vec![
        older(RECOVERY_CSV_BLOCKS),
        arc(Policy::Key(input.key_recovery.clone())),
    ]);

    // Branch 2b: inheritance after 26,280 blocks with 2-of-n threshold.
    let mut heir_pks: Vec<Arc<Policy<Pk>>> = input
        .key_heirs
        .iter()
        .map(|k| arc(Policy::Key(k.clone())))
        .collect();
    heir_pks.push(arc(Policy::Key(input.key_executor.clone())));
    let threshold =
        Threshold::new(2, heir_pks).map_err(|e| PolicyError::Threshold(e.to_string()))?;
    let inheritance = Policy::And(vec![
        older(INHERITANCE_CSV_BLOCKS),
        arc(Policy::Thresh(threshold)),
    ]);

    let recovery_or_inheritance = Policy::Or(vec![(1, arc(recovery)), (1, arc(inheritance))]);
    let root = Policy::Or(vec![(1, arc(normal)), (1, arc(recovery_or_inheritance))]);

    root.compile()
        .map_err(|e| PolicyError::Compile(e.to_string()))
}

/// Compile ONLY the normal hybrid leaf (2-of-2: user + enclave co-signer).
pub fn compile_normal_leaf(
    key_user: &Pk,
    key_enclave: &Pk,
) -> Result<Miniscript<Pk, Tap>, PolicyError> {
    let leaf = Policy::And(vec![
        arc(Policy::Key(key_user.clone())),
        arc(Policy::Key(key_enclave.clone())),
    ]);
    leaf.compile()
        .map_err(|e| PolicyError::Compile(e.to_string()))
}

/// Compile ONLY the recovery leaf (CSV 144 + cold sweep key).
pub fn compile_recovery_leaf(key_recovery: &Pk) -> Result<Miniscript<Pk, Tap>, PolicyError> {
    let leaf = Policy::And(vec![
        older(RECOVERY_CSV_BLOCKS),
        arc(Policy::Key(key_recovery.clone())),
    ]);
    leaf.compile()
        .map_err(|e| PolicyError::Compile(e.to_string()))
}

/// Compile ONLY the inheritance leaf (k-of-n heir threshold after CSV 26,280).
pub fn compile_inheritance_leaf(
    key_heirs: &[Pk],
    key_executor: &Pk,
    threshold: usize,
) -> Result<Miniscript<Pk, Tap>, PolicyError> {
    if key_heirs.len() < 2 {
        return Err(PolicyError::NotEnoughHeirs);
    }
    let mut pks: Vec<Arc<Policy<Pk>>> = key_heirs
        .iter()
        .map(|k| arc(Policy::Key(k.clone())))
        .collect();
    pks.push(arc(Policy::Key(key_executor.clone())));
    let thresh =
        Threshold::new(threshold, pks).map_err(|e| PolicyError::Threshold(e.to_string()))?;
    let leaf = Policy::And(vec![
        older(INHERITANCE_CSV_BLOCKS),
        arc(Policy::Thresh(thresh)),
    ]);
    leaf.compile()
        .map_err(|e| PolicyError::Compile(e.to_string()))
}

/// Human-readable check: does this miniscript contain the expected CSV guard?
pub fn contains_older_check(ms: &Miniscript<Pk, Tap>, blocks: u16) -> bool {
    ms.iter()
        .any(|n| matches!(n.node, Terminal::Older(b) if b.to_consensus_u32() == u32::from(blocks)))
}

/// Count standalone `pk(K)` checks in the compiled miniscript (sanity for shape).
pub fn count_pk_checks(ms: &Miniscript<Pk, Tap>) -> usize {
    ms.iter()
        .filter(|n| matches!(n.node, Terminal::PkK(_)))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo_keys;

    fn desc_pk(seed: u8) -> Pk {
        let kp = demo_keys::demo_keypair(&format!("policy/{seed}"));
        let pk = secp256k1::PublicKey::from_keypair(&kp);
        Pk::from_str(&pk.to_string()).expect("raw compressed pubkey parses")
    }

    #[test]
    fn single_leaf_compilers_shape_and_csv_guards() {
        // Normal leaf: 2-of-2, NO timelock.
        let normal = compile_normal_leaf(&desc_pk(1), &desc_pk(2)).expect("normal leaf");
        assert!(!contains_older_check(&normal, RECOVERY_CSV_BLOCKS));
        assert!(!contains_older_check(&normal, INHERITANCE_CSV_BLOCKS));
        assert_eq!(count_pk_checks(&normal), 2);

        // Recovery leaf: CSV 144 + one sweep key.
        let rec = compile_recovery_leaf(&desc_pk(3)).expect("recovery leaf");
        assert!(contains_older_check(&rec, RECOVERY_CSV_BLOCKS));
        assert!(!contains_older_check(&rec, INHERITANCE_CSV_BLOCKS));
        assert_eq!(count_pk_checks(&rec), 1);

        // Inheritance leaf: CSV 26,280 + 2-of-3 threshold (2 heirs + executor).
        let inh = compile_inheritance_leaf(&[desc_pk(4), desc_pk(5)], &desc_pk(6), 2)
            .expect("inheritance leaf");
        assert!(contains_older_check(&inh, INHERITANCE_CSV_BLOCKS));
        assert!(!contains_older_check(&inh, RECOVERY_CSV_BLOCKS));
        // The compiler rewrites `thresh(m, pk…)` into `multi_a` on Tap
        // (CHECKMULTISIG is illegal in tapscript, so `Terminal::Multi` can
        // never appear here — counting multi_a is counting the whole
        // threshold).
        let threshold_keys: usize = inh
            .iter()
            .map(|n| match &n.node {
                Terminal::MultiA(k) => k.n(),
                _ => 0,
            })
            .sum();
        assert_eq!(count_pk_checks(&inh) + threshold_keys, 3);
    }

    #[test]
    fn leaf_compiler_error_paths_fail_closed() {
        // A 1-heir group is not a threshold (fail closed).
        assert!(matches!(
            compile_inheritance_leaf(&[desc_pk(4)], &desc_pk(6), 2),
            Err(PolicyError::NotEnoughHeirs)
        ));
        // k above the participant count is an invalid threshold.
        assert!(matches!(
            compile_inheritance_leaf(&[desc_pk(4), desc_pk(5)], &desc_pk(6), 5),
            Err(PolicyError::Threshold(_))
        ));
        // Key parse failure surfaces as PolicyError::Key, not a panic.
        assert!(matches!(parse_pk("not-a-key"), Err(PolicyError::Key(_))));
        // Valid raw compressed keys round-trip through parse_pk.
        let round = desc_pk(1).to_string();
        assert_eq!(
            parse_pk(&round).expect("valid key parses").to_string(),
            round
        );
    }

    #[test]
    fn policy_error_strings_are_stable() {
        assert_eq!(
            PolicyError::NotEnoughHeirs.to_string(),
            "at least 2 heir keys are required"
        );
        assert_eq!(
            PolicyError::Compile("x".into()).to_string(),
            "policy compile error: x"
        );
        assert_eq!(
            PolicyError::Key("y".into()).to_string(),
            "descriptor key error: y"
        );
        assert_eq!(
            PolicyError::Threshold("z".into()).to_string(),
            "threshold error: z"
        );
        let _: &dyn std::error::Error = &PolicyError::Compile(String::new());
    }
}
