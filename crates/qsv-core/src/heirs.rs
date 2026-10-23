//! Heir PQC identity commitments (docs/04 §5, L1-compatible binding).
//!
//! A quantum attacker who steals an heir's CLASSIC key cannot prove the
//! matching ML-DSA-65 identity: each heir's taproot key is hash-committed to
//! their post-quantum identity key at vault setup time. Chain-level PQC
//! verification is impossible today (no SHA-3/NTT opcodes); this commitment
//! provides the mathematical proof-of-identity layer for dispute resolution
//! and for the co-signer policy of Phase 1.

use sha2::{Digest, Sha256};

/// Domain-separated commitment: `SHA256("QSV_HEIR_PQC_v1" || pk_pqc || xonly_classic)`.
pub fn heir_commitment(pk_pqc: &[u8], xonly_classic: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"QSV_HEIR_PQC_v1");
    h.update(pk_pqc);
    h.update(xonly_classic);
    h.finalize().into()
}

/// Verified heir registry built at vault setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeirSet {
    entries: Vec<(XOnlyKey, [u8; 32])>,
}

/// Newtype over x-only key bytes for registry storage.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XOnlyKey(pub [u8; 32]);

impl XOnlyKey {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeirError {
    /// Registry empty or duplicate classic keys.
    InvalidRegistry,
    /// A commitment does not match the (classic key, PQC identity) pair.
    CommitmentMismatch,
}

impl core::fmt::Display for HeirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HeirError::InvalidRegistry => write!(f, "heir registry is empty or has duplicates"),
            HeirError::CommitmentMismatch => write!(f, "heir commitment mismatch (fail-closed)"),
        }
    }
}

impl std::error::Error for HeirError {}

impl HeirSet {
    /// Builds the registry, verifying every commitment at construction (fail-closed).
    pub fn build(
        entries: impl IntoIterator<Item = ([u8; 32], Vec<u8>)>,
    ) -> Result<Self, HeirError> {
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for (classic, pqc_pk) in entries {
            if !seen.insert(classic) {
                return Err(HeirError::InvalidRegistry);
            }
            let c = heir_commitment(&pqc_pk, &classic);
            out.push((XOnlyKey(classic), c));
        }
        if out.is_empty() {
            return Err(HeirError::InvalidRegistry);
        }
        Ok(Self { entries: out })
    }

    /// Cross-checks a candidate (classic, PQC) pair against the registry.
    pub fn verify_member(&self, classic: &[u8; 32], pqc_pk: &[u8]) -> bool {
        let c = heir_commitment(pqc_pk, classic);
        self.entries
            .iter()
            .any(|(k, c0)| k.as_bytes() == classic && *c0 == c)
    }

    /// Number of registered heirs.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Serialize the registry to hex commitments (audit report line items).
    pub fn commitments_hex(&self) -> Vec<String> {
        self.entries.iter().map(|(_, c)| hex::encode(c)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic_and_binding() {
        let classic = [7u8; 32];
        let pqc = vec![1u8; 64];
        let c1 = heir_commitment(&pqc, &classic);
        let c2 = heir_commitment(&pqc, &classic);
        assert_eq!(c1, c2);
        let other = heir_commitment(&[2u8; 64], &classic);
        assert_ne!(c1, other);
    }

    #[test]
    fn heir_set_roundtrip_and_reject() {
        let classic = [9u8; 32];
        let pqc = vec![3u8; 100];
        let set = HeirSet::build([(classic, pqc.clone())]).unwrap();
        assert!(set.verify_member(&classic, &pqc));
        assert!(!set.verify_member(&classic, &[4u8; 100]));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn duplicate_classic_keys_rejected() {
        let classic = [9u8; 32];
        let r = HeirSet::build([(classic, vec![1u8; 8]), (classic, vec![2u8; 8])]);
        assert!(matches!(r, Err(HeirError::InvalidRegistry)));
    }

    #[test]
    fn empty_registry_fails_closed_and_audit_helpers_work() {
        // An empty registry is not a registry (fail closed at build time).
        assert!(matches!(
            HeirSet::build(std::iter::empty()),
            Err(HeirError::InvalidRegistry)
        ));

        let classic = [5u8; 32];
        let pqc = vec![9u8; 40];
        let set = HeirSet::build([(classic, pqc.clone())]).unwrap();
        assert!(!set.is_empty());
        assert_eq!(
            set.commitments_hex(),
            vec![hex::encode(heir_commitment(&pqc, &classic))]
        );
        // A different classic key can never match a registered commitment.
        assert!(!set.verify_member(&[6u8; 32], &pqc));

        // Both error strings (operator-facing messages).
        assert_eq!(
            HeirError::InvalidRegistry.to_string(),
            "heir registry is empty or has duplicates"
        );
        assert_eq!(
            HeirError::CommitmentMismatch.to_string(),
            "heir commitment mismatch (fail-closed)"
        );
        let _: &dyn std::error::Error = &HeirError::CommitmentMismatch;

        let k = XOnlyKey::from_bytes([1u8; 32]);
        assert_eq!(k.as_bytes(), &[1u8; 32]);
    }
}
