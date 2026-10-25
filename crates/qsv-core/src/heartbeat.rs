//! Automated heartbeat (CSV refresh) — the HITL-minimum liveness engine.
//!
//! Docs/04 §2: every refresh re-deposits the vault into a fresh UTXO with the
//! identical policy and resets the 26,280-block inheritance timer. The owner's
//! only act is provisioning the scheduler; every renewal after that is a
//! deterministic, offline-computable transaction (zero-HITL principle, docs/03 §9).

use crate::taproot::VaultTaproot;
use crate::unvault::{self, SpendContext};
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::script::Builder;
use bitcoin::secp256k1::Keypair;
use bitcoin::transaction::Version;
use bitcoin::witness::Witness;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};

/// Errors raised by the heartbeat scheduler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeartbeatError {
    /// No refresh is due yet.
    NotDue,
    /// Policy would expire before the next check window (config error).
    ExpiryBeforeInterval,
    /// Insufficient value to pay the refresh fee and stay above dust.
    InsufficientFunds,
}

impl core::fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HeartbeatError::NotDue => write!(f, "heartbeat not due yet"),
            HeartbeatError::ExpiryBeforeInterval => {
                write!(
                    f,
                    "CSV expiry is before the scheduler interval; widen the margin"
                )
            }
            HeartbeatError::InsufficientFunds => write!(f, "value too low for refresh fee"),
        }
    }
}

/// Blocks for the inheritance path (docs/04: 26,280 ≈ 180 days).
pub const INHERITANCE_CSV_BLOCKS: u32 = 26_280;

/// Scheduler configuration. Defaults implement the docs/10 §6 recommendation:
/// refresh every ~90 days, six blocks before expiry would hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatPolicy {
    /// Refresh cadence in blocks (docs/10 §6: 90 days ≈ 12,960 blocks).
    pub interval_blocks: u32,
    /// Fire this many blocks BEFORE the CSV would expire (safety margin).
    pub expiry_margin_blocks: u32,
    /// Flat refresh fee in sats.
    pub refresh_fee_sats: u64,
}

impl Default for HeartbeatPolicy {
    fn default() -> Self {
        Self {
            interval_blocks: 12_960,
            expiry_margin_blocks: 1_008, // ~1 day before the 180-day wall
            refresh_fee_sats: 1_000,
        }
    }
}

impl HeartbeatPolicy {
    /// Sanity-checks the scheduling invariants.
    pub fn validate(&self) -> Result<(), HeartbeatError> {
        let expiry = self.expiry_block_offset();
        if self.interval_blocks + self.expiry_margin_blocks > expiry {
            return Err(HeartbeatError::ExpiryBeforeInterval);
        }
        Ok(())
    }

    /// Total dormancy budget in blocks (the CSV constant).
    pub fn expiry_block_offset(&self) -> u32 {
        INHERITANCE_CSV_BLOCKS
    }
}

/// Decides whether a refresh transaction must be produced now.
pub fn is_due(policy: &HeartbeatPolicy, last_refresh_block: u32, current_block: u32) -> bool {
    current_block.saturating_sub(last_refresh_block) >= policy.interval_blocks
}

/// Blocks remaining before the inheritance leaf becomes spendable (0 = open).
pub fn blocks_until_expiry(last_refresh_block: u32, current_block: u32) -> u32 {
    INHERITANCE_CSV_BLOCKS.saturating_sub(current_block.saturating_sub(last_refresh_block))
}

/// Builds the refresh transaction: vault UTXO -> identical vault policy
/// (self-churn). The output address equals the input address; only the CSV
/// clock resets. This transaction requires the normal hybrid leaf
/// (user + enclave co-signer), exactly like any live spend.
pub fn build_refresh_tx(
    vault: &VaultTaproot,
    vault_outpoint: OutPoint,
    vault_value: Amount,
    fee: Amount,
) -> Result<Transaction, HeartbeatError> {
    let out_value = vault_value
        .checked_sub(fee)
        .ok_or(HeartbeatError::InsufficientFunds)?;
    if out_value < Amount::from_sat(546) {
        return Err(HeartbeatError::InsufficientFunds);
    }
    // Self-churn: the output pays to the SAME taproot output key.
    let out_key = vault.output_key();
    let spk = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(out_key.serialize())
        .into_script();

    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: vault_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: out_value,
            script_pubkey: spk,
        }],
    })
}

/// Signs the refresh transaction through the normal hybrid leaf and returns
/// the finalized transaction (offline: no wallet daemon, no RPC).
pub fn sign_refresh_tx(
    vault: &VaultTaproot,
    mut refresh: Transaction,
    prev_value: Amount,
    user_keypair: &Keypair,
    enclave_sig: [u8; 64],
) -> Transaction {
    let control = vault
        .spend_info
        .control_block(&(
            vault.leaves.normal.clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .expect("control block for normal leaf");
    let out_key = vault.output_key();
    let prev_spk = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(out_key.serialize())
        .into_script();

    let ctx = SpendContext {
        script: &vault.leaves.normal,
        control_block: &control,
        prev_value,
        prev_script_pubkey: &prev_spk,
    };
    let sig_user = {
        let sh = unvault::script_spend_sighash(
            &refresh,
            0,
            ctx.script,
            ctx.prev_value,
            ctx.prev_script_pubkey,
        );
        unvault::sign_schnorr(user_keypair, &sh).to_vec()
    };
    // Witness order `[σ_enclave, σ_user]`: `<pk_user> CHECKSIGVERIFY
    // <pk_enclave> CHECKSIG` pops the stack TOP first, so σ_enclave is the
    // DEEPEST element. (Round 41: this arm had the two swapped, so every
    // transaction the documented cron entry point produced was rejected by
    // libbitcoinconsensus — see `tick_output_is_valid_under_consensus`.)
    refresh.input[0].witness = unvault::build_script_path_witness(
        &[enclave_sig.to_vec(), sig_user],
        ctx.script,
        ctx.control_block,
    );
    refresh
}

/// Full scheduler tick: given chain state and the vault, produce the refresh
/// transaction if due. This is the entry point a cron/systemd timer calls —
/// the only human act is provisioning the timer itself.
/// All live context needed to execute one heartbeat tick. The operator
/// supplies state; the function supplies the decision (HITL-minimum).
pub struct HeartbeatTick<'a> {
    pub policy: &'a HeartbeatPolicy,
    pub vault: &'a VaultTaproot,
    pub last_refresh_block: u32,
    pub current_block: u32,
    pub vault_outpoint: OutPoint,
    pub vault_value: Amount,
    pub user_keypair: &'a Keypair,
    pub enclave_sig: [u8; 64],
}

/// Runs one scheduler tick: returns the signed self-churn refresh transaction
/// when the policy is due, `Ok(None)` otherwise.
pub fn tick(ctx: HeartbeatTick<'_>) -> Result<Option<Transaction>, HeartbeatError> {
    ctx.policy.validate()?;
    if !is_due(ctx.policy, ctx.last_refresh_block, ctx.current_block) {
        return Ok(None);
    }
    let tx = build_refresh_tx(
        ctx.vault,
        ctx.vault_outpoint,
        ctx.vault_value,
        Amount::from_sat(ctx.policy.refresh_fee_sats),
    )?;
    let signed = sign_refresh_tx(
        ctx.vault,
        tx,
        ctx.vault_value,
        ctx.user_keypair,
        ctx.enclave_sig,
    );
    Ok(Some(signed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo_keys;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::Txid;

    fn vault() -> VaultTaproot {
        let secp = Secp256k1::verification_only();
        VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap()
    }

    #[test]
    fn scheduler_defaults_respect_expiry() {
        let p = HeartbeatPolicy::default();
        p.validate().unwrap();
        assert_eq!(p.expiry_block_offset(), 26_280);
    }

    #[test]
    fn scheduler_rejects_impossible_interval() {
        let p = HeartbeatPolicy {
            interval_blocks: 26_000,
            expiry_margin_blocks: 1_000,
            refresh_fee_sats: 1_000,
        };
        // 26,000 + 1,000 > 26,280 -> would fire after expiry.
        assert!(matches!(
            p.validate(),
            Err(HeartbeatError::ExpiryBeforeInterval)
        ));
    }

    #[test]
    fn due_logic_and_countdown() {
        let p = HeartbeatPolicy::default();
        assert!(!is_due(&p, 100_000, 100_000 + 12_959));
        assert!(is_due(&p, 100_000, 100_000 + 12_960));
        assert_eq!(blocks_until_expiry(100_000, 100_000), 26_280);
        assert_eq!(blocks_until_expiry(100_000, 100_000 + 26_280), 0);
    }

    #[test]
    fn tick_produces_refresh_transaction_when_due() {
        let p = HeartbeatPolicy::default();
        let v = vault();
        let outpoint = OutPoint::new(Txid::from_byte_array([0x33u8; 32]), 0);
        let value = Amount::from_sat(90_000);

        // Not due -> None.
        let idle = tick(HeartbeatTick {
            policy: &p,
            vault: &v,
            last_refresh_block: 500_000,
            current_block: 500_000,
            vault_outpoint: outpoint,
            vault_value: value,
            user_keypair: &demo_keys::user_keypair(),
            enclave_sig: [0u8; 64],
        })
        .unwrap();
        assert!(idle.is_none());

        // Due -> signed self-churn transaction.
        let tx = tick(HeartbeatTick {
            policy: &p,
            vault: &v,
            last_refresh_block: 500_000,
            current_block: 500_000 + 12_960,
            vault_outpoint: outpoint,
            vault_value: value,
            user_keypair: &demo_keys::user_keypair(),
            enclave_sig: [0u8; 64],
        })
        .unwrap()
        .expect("refresh must be produced");

        // Self-churn: single output paying to the SAME vault output key.
        assert_eq!(tx.output.len(), 1);
        let out_key = v.output_key();
        let expected_spk = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(out_key.serialize())
            .into_script();
        assert_eq!(tx.output[0].script_pubkey, expected_spk);
        assert_eq!(tx.output[0].value, Amount::from_sat(89_000));
        // Witness completed through the hybrid leaf.
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    #[test]
    fn refresh_tx_fails_closed_on_fee_and_dust() {
        let v = vault();
        let outpoint = OutPoint::new(Txid::from_byte_array([0x44u8; 32]), 0);
        // Fee above the input value: checked_sub must fail closed.
        assert_eq!(
            build_refresh_tx(&v, outpoint, Amount::from_sat(500), Amount::from_sat(600)),
            Err(HeartbeatError::InsufficientFunds)
        );
        // Leftover below the 546-sat dust floor: refused.
        assert_eq!(
            build_refresh_tx(&v, outpoint, Amount::from_sat(600), Amount::from_sat(100)),
            Err(HeartbeatError::InsufficientFunds)
        );
    }

    #[test]
    fn tick_surfaces_the_build_wall_and_every_display_renders() {
        let p = HeartbeatPolicy::default();
        let v = vault();
        let outpoint = OutPoint::new(Txid::from_byte_array([0x44u8; 32]), 0);
        // DUE, but the refresh cannot even be built (1-sat input vs. the
        // policy fee) — the `?` inside `tick` must propagate the wall.
        let err = tick(HeartbeatTick {
            policy: &p,
            vault: &v,
            last_refresh_block: 500_000,
            current_block: 500_000 + 12_960,
            vault_outpoint: outpoint,
            vault_value: Amount::from_sat(1),
            user_keypair: &demo_keys::user_keypair(),
            enclave_sig: [0u8; 64],
        })
        .unwrap_err();
        assert_eq!(err, HeartbeatError::InsufficientFunds);

        // Display arms render their own messages (operator-facing text).
        assert_eq!(HeartbeatError::NotDue.to_string(), "heartbeat not due yet");
        assert!(HeartbeatError::ExpiryBeforeInterval
            .to_string()
            .contains("CSV expiry is before the scheduler interval"));
        assert_eq!(
            HeartbeatError::InsufficientFunds.to_string(),
            "value too low for refresh fee"
        );
    }

    /// Round 41 (audit): the scheduler entry point a cron timer calls must
    /// produce what the NETWORK accepts, not just a four-element witness.
    /// The witness is `[σ_enclave, σ_user]`; with the two swapped the real
    /// interpreter rejects the spend (`ScriptFailed(0)`), which no unit test
    /// noticed because none ran the reference engine over this path.
    #[cfg(feature = "consensus")]
    #[test]
    fn tick_output_is_valid_under_consensus() {
        let p = HeartbeatPolicy::default();
        let v = vault();
        let spk = v.script_pubkey();
        let outpoint = OutPoint::new(Txid::from_byte_array([0x55u8; 32]), 0);
        let value = Amount::from_sat(90_000);

        // The sighash is witness-independent: sign it, then let `tick` build.
        let unsigned = build_refresh_tx(&v, outpoint, value, Amount::from_sat(1_000)).unwrap();
        let sighash =
            crate::unvault::script_spend_sighash(&unsigned, 0, &v.leaves.normal, value, &spk);
        let enclave_sig = crate::unvault::sign_schnorr(&demo_keys::enclave_keypair(), &sighash);

        let tx = tick(HeartbeatTick {
            policy: &p,
            vault: &v,
            last_refresh_block: 500_000,
            current_block: 500_000 + 12_960,
            vault_outpoint: outpoint,
            vault_value: value,
            user_keypair: &demo_keys::user_keypair(),
            enclave_sig,
        })
        .unwrap()
        .expect("refresh must be produced");

        crate::consensus::verify_input(&tx, 0, &spk, value)
            .expect("the reference interpreter must accept the scheduler's refresh");
    }
}
