//! Deterministic demo keys for tests and CLI demos.
//!
//! These are NOT production keys: they are derived from fixed seed strings via
//! SHA-256 so that every test run and demo output is reproducible and auditable.
//! Production deployments replace these with hardware wallet keys.

use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

fn seed_digest(seed: &str, counter: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"QSV_DEMO_KEY_v1");
    h.update(seed.as_bytes());
    h.update(counter.to_be_bytes());
    h.finalize().into()
}

/// Counter-scan seam: the first `next(counter)` result that decodes to a
/// scalar becomes the keypair; `None` after every counter means the scan
/// is exhausted (testable by feeding a sampler that always fails — the
/// production sampler cannot, by ~2^-128).
fn keypair_from_counters(mut next: impl FnMut(u32) -> Option<SecretKey>) -> Option<Keypair> {
    let secp = Secp256k1::signing_only();
    for counter in 0..1000u32 {
        // SecretKey::from_slice fails only if d == 0 or d >= n (prob ~2^-128).
        if let Some(sk) = next(counter) {
            return Some(Keypair::from_secret_key(&secp, &sk));
        }
    }
    None
}

/// Deterministic signing keypair from a seed string (tests & demos only).
pub fn demo_keypair(seed: &str) -> Keypair {
    keypair_from_counters(|counter| SecretKey::from_slice(&seed_digest(seed, counter)).ok())
        .expect("1000 consecutive invalid scalars is cryptographically impossible")
}

fn xonly_from_seed(seed: &str) -> XOnlyPublicKey {
    demo_keypair(seed).x_only_public_key().0
}

/// Owner's classic (hardware wallet) demo keypair.
pub fn user_keypair() -> Keypair {
    demo_keypair("owner/user")
}

/// Owner's classic (hardware wallet) demo key (x-only public half).
pub fn user_key() -> XOnlyPublicKey {
    user_keypair().x_only_public_key().0
}

/// Enclave co-signer demo keypair.
pub fn enclave_keypair() -> Keypair {
    demo_keypair("enclave/co-signer")
}

/// Enclave co-signer demo key (x-only public half).
pub fn enclave_key() -> XOnlyPublicKey {
    enclave_keypair().x_only_public_key().0
}

/// Emergency cold-sweep (recovery) demo keypair.
pub fn recovery_keypair() -> Keypair {
    demo_keypair("recovery/cold-sweep")
}

/// Emergency cold-sweep (recovery) demo key (x-only public half).
pub fn recovery_key() -> XOnlyPublicKey {
    recovery_keypair().x_only_public_key().0
}

/// Heir #1 demo keypair.
pub fn heir_one_keypair() -> Keypair {
    demo_keypair("heir/one")
}

/// Heir #1 demo key (x-only public half).
pub fn heir_one() -> XOnlyPublicKey {
    heir_one_keypair().x_only_public_key().0
}

/// Heir #2 demo keypair.
pub fn heir_two_keypair() -> Keypair {
    demo_keypair("heir/two")
}

/// Heir #2 demo key (x-only public half).
pub fn heir_two() -> XOnlyPublicKey {
    heir_two_keypair().x_only_public_key().0
}

/// Estate executor / counsel demo key.
pub fn executor_key() -> XOnlyPublicKey {
    xonly_from_seed("executor/counsel")
}

/// Emergency-leaf destination key (leaf 4). Hidden on-chain behind a SHA-256
/// hash lock; disclosed only inside the WOTS+-sealed offline kit (docs/08 §2).
pub fn emergency_kit_key() -> XOnlyPublicKey {
    xonly_from_seed("emergency/kit")
}

/// Emergency-leaf destination keypair (demo/tests; production: offline kit).
pub fn emergency_kit_keypair() -> Keypair {
    demo_keypair("emergency/kit")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_keys_are_deterministic_and_distinct() {
        assert_eq!(user_key(), user_key());
        let all = [
            user_key(),
            enclave_key(),
            recovery_key(),
            heir_one(),
            heir_two(),
            executor_key(),
            emergency_kit_key(),
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "demo keys must be distinct");
            }
        }
    }

    #[test]
    fn keypairs_match_public_halves() {
        assert_eq!(user_keypair().x_only_public_key().0, user_key());
        assert_eq!(heir_one_keypair().x_only_public_key().0, heir_one());
    }

    #[test]
    fn exhausted_counter_scan_fails_loudly_instead_of_returning_a_weak_key() {
        // A sampler that can never produce a valid scalar exercises the
        // full 1000-iteration exhaustion path (the production sampler
        // cannot reach it — that is the point of the invariant).
        assert!(keypair_from_counters(|_| None).is_none());
        // …while the real path still produces a stable keypair.
        assert_eq!(demo_keypair("probe"), demo_keypair("probe"));
    }
}
