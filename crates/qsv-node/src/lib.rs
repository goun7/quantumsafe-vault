//! QuantumSafe-Vault ↔ Bitcoin node integration.
//!
//! Library surface (`lifecycle`): builds and signs every transaction of the
//! full vault lifecycle against REAL chain state supplied by the caller
//! (bitcoincore-rpc in the e2e test; any provider in production):
//!
//!   1. fund        — mine to the vault address, confirm, read the UTXO
//!   2. unvault     — 2-of-2 hybrid spend vault → staging (single output)
//!   3. settle      — after CSV maturity, staging → heir destination
//!
//! The e2e test drives these against a real bitcoind (v26+) downloaded by the
//! `bitcoind` dev-dependency; consensus acceptance is enforced by the node
//! itself (testmempoolaccept / sendrawtransaction + mined block).

pub mod lifecycle;
pub mod rpc;

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
