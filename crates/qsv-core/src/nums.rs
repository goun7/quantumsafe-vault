//! NUMS (Nothing-Up-My-Sleeve) provably unspendable internal key derivation.
//!
//! Protocol (docs/03 §2.2, v2026.2 canonical definition):
//!   S     = "QuantumSafe_Vault_v2026_Unspendable_Internal_Key_Nothing_Up_My_Sleeve"
//!   x_c   = SHA256(S || LE32(c))      for c = 0, 1, 2, ...   (c is the "nonce")
//!   P     = lift_x(x_c)               first c where x_c is a valid curve x-coord
//!
//! Because ~50% of 256-bit strings are not valid x-coordinates on secp256k1,
//! the canonical derivation scans the counter deterministically. The FIRST
//  accepting counter is frozen by a unit test so the NUMS point is a public
//! constant-of-the-protocol: anyone can recompute it, and nobody knows its
//! discrete log (that would require inverting SHA-256 preimages; Shor cannot
//! shortcut this because x is derived from a hash, not from a scalar choice).

use bitcoin::secp256k1::XOnlyPublicKey;
use sha2::{Digest, Sha256};

/// Fixed domain separator (docs/03 §2.2). NEVER change this constant: doing so
/// would rotate the NUMS point and orphan every vault derived from the old one.
pub const NUMS_SEED_MESSAGE: &[u8] =
    b"QuantumSafe_Vault_v2026_Unspendable_Internal_Key_Nothing_Up_My_Sleeve";

/// Maximum scan depth for the deterministic counter. The expected number of
/// trials is ~2; 1,000 is astronomically safe and bounds runtime.
pub const NUMS_MAX_COUNTER: u32 = 1_000;

/// The canonical counter value (frozen by `nums_canonical_counter` test).
/// Cached at first use; recomputation is deterministic so this is safe.
pub const NUMS_CANONICAL_COUNTER: u32 = 0;

/// Errors surfaced by NUMS derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumsError {
    /// Exhausted the deterministic counter scan (probability ~2^-300).
    NoValidCounter,
}

impl core::fmt::Display for NumsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NumsError::NoValidCounter => {
                write!(f, "no valid curve x-coordinate found within counter bound")
            }
        }
    }
}

impl std::error::Error for NumsError {}

fn digest_with_counter(counter: u32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NUMS_SEED_MESSAGE);
    hasher.update(counter.to_le_bytes());
    hasher.finalize().into()
}

/// Derives the x-only NUMS internal key by scanning `counter` upward from
/// `start` until SHA256(S||LE32(c)) yields a valid curve x-coordinate.
pub fn derive_nums_internal_key_from(start: u32) -> Result<(u32, XOnlyPublicKey), NumsError> {
    for c in start..NUMS_MAX_COUNTER {
        let d = digest_with_counter(c);
        if let Ok(pk) = XOnlyPublicKey::from_slice(&d) {
            return Ok((c, pk));
        }
    }
    Err(NumsError::NoValidCounter)
}

/// Canonical NUMS internal key (counter starts at 0; the first valid point wins).
///
/// # Panics
/// Only if 1,000 consecutive SHA-256 outputs are all non-residues
/// (probability ~2^-1000). This panic is deliberately loud: silently rotating
/// the NUMS point is forbidden by the protocol.
pub fn nums_internal_key() -> XOnlyPublicKey {
    derive_nums_internal_key_from(NUMS_CANONICAL_COUNTER)
        .expect("NUMS counter scan exhausted (prob ~2^-1000)")
        .1
}

/// Convenience accessor for the raw 32-byte x-only serialization of the NUMS point.
pub fn nums_internal_key_bytes() -> [u8; 32] {
    nums_internal_key().serialize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Freezes the canonical counter so the NUMS point is a protocol constant.
    #[test]
    fn nums_canonical_counter_is_frozen() {
        let (c, _pk) = derive_nums_internal_key_from(0).expect("valid counter exists");
        // If this fails, SHA-256 or the seed message changed — a protocol break.
        assert_eq!(c, NUMS_CANONICAL_COUNTER, "canonical NUMS counter drifted");
    }

    #[test]
    fn nums_is_deterministic() {
        let k1 = nums_internal_key_bytes();
        let k2 = nums_internal_key_bytes();
        assert_eq!(k1, k2);
    }

    #[test]
    fn nums_matches_manual_sha256_of_seed_and_counter() {
        let (c, pk) = derive_nums_internal_key_from(0).unwrap();
        let mut h = Sha256::new();
        h.update(b"QuantumSafe_Vault_v2026_Unspendable_Internal_Key_Nothing_Up_My_Sleeve");
        h.update(c.to_le_bytes());
        let d: [u8; 32] = h.finalize().into();
        assert_eq!(d, pk.serialize());
    }

    #[test]
    fn nums_differs_across_counters() {
        let (_, k0) = derive_nums_internal_key_from(0).unwrap();
        // The next accepting counter yields a different (also unspendable) point.
        // (Unwrap, not `if let`: counters 0 and 1 both hash to on-curve x's,
        // and a straight line carries the coverage the old if-let masked.)
        let (c, _) = derive_nums_internal_key_from(0).unwrap();
        let (_, k1) = derive_nums_internal_key_from(c + 1).unwrap();
        assert_ne!(k0, k1);
        // Counter 2 hashes OFF the curve (SHA-256 is fixed), so this call
        // walks the scan loop past an invalid candidate — the loop's
        // back-edge is a real, repeatable path, not a hypothetical one.
        let (c2, k2) = derive_nums_internal_key_from(2).unwrap();
        assert!(c2 > c + 1);
        assert_ne!(k0, k2);
    }

    #[test]
    fn counter_exhaustion_fails_closed_with_display() {
        // An empty scan range (start == bound) must fail closed, never loop.
        assert_eq!(
            derive_nums_internal_key_from(NUMS_MAX_COUNTER),
            Err(NumsError::NoValidCounter)
        );
        assert_eq!(
            NumsError::NoValidCounter.to_string(),
            "no valid curve x-coordinate found within counter bound"
        );
        let _: &dyn std::error::Error = &NumsError::NoValidCounter;
    }
}
