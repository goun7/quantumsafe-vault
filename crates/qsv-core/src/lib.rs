//! QuantumSafe-Vault core library.
//!
//! Pure, deterministic, air-gap friendly building blocks:
//! - `nums`:      provably unspendable NUMS internal key (key-path cancelled)
//! - `policy`:    BIP-379 Miniscript policy compilation (Tap context)
//! - `taproot`:   BIP-341 vault output derivation (MAST leaves + address)
//! - `unvault`:   two-stage unvault covenant flow (staging + CSV delays)
//! - `psbt`:      BIP-174/371 hardware-wallet round-trip (Coldcard/Ledger)
//! - `heartbeat`: automated CSV refresh (HITL-minimum liveness)
//! - `consensus`: libbitcoinconsensus-backed script verification
//! - `heirs`:     heir PQC identity commitments (fail-closed registry)
//! - `wots`:      WOTS+ (RFC 8391) hash-based signatures — post-Q-Day
//!   emergency sweep layer resting only on SHA-256 (+ parameter study)
//! - `budget`:    per-leaf spend budget: witness sizes, weight, fee table
//! - `shamir`:    GF(256) secret sharing for the emergency kit seed
//! - `slip39`:    SLIP-0039 Shamir mnemonics (interoperable, spec vectors)
//! - `bip360`:    BIP-360 (P2MR) K1 decision-gate tracker (snapshot ↔ live)
//! - `frost`:    FROST threshold signatures (docs/04 §4.1 wizard core,
//!   BIP-340-compatible secp256k1-tr, SLIP-0039 share backup)
//! - `dashboard`: live vault state summary for operator surfaces
//! - `estate`: printable estate letters + independent verification
//! - `finmodel`: docs/06 financial model — operator tiers, AUM/SAAS,
//!   LTV/CAC, break-even, pro-forma (tested prose, integer cents)
//! - `settlement`: estate debit/credit → heir shares (fail-closed,
//!   TMK 599/505–506 arithmetic core for docs/05 §2.2)
//! - `console`:  one-screen watch-only vault console — clocks, address and
//!   estate letter as data plus a self-contained, script-free HTML page
//! - `docs`:     documentation audit for the single English edition — the
//!   `docs_sync` walls as data (what drifted, per module) for reviewers
//! - `demo_keys`: deterministic demo keypairs for tests and demos

pub mod bip360;
pub mod budget;
pub mod consensus;
pub mod console;
pub mod dashboard;
pub mod demo_keys;
pub mod docs;
pub mod estate;
pub mod finmodel;
pub mod frost;
pub mod heartbeat;
pub mod heirs;
pub mod nums;
pub mod policy;
pub mod psbt;
pub mod settlement;
pub mod shamir;
pub mod slip39;
pub mod taproot;
pub mod unvault;
pub mod wots;

/// Library version (matches the workspace package version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_constant_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
