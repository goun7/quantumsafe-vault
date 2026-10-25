//! Consensus-level script verification backed by `libbitcoinconsensus`
//! (the exact C++ validation code shipped in Bitcoin Core).
//!
//! Claim in docs/09 §9 ("the spend tx hex is real") is upgraded from structural
//! checks to FULL script validation: every test that asserts a spend is valid
//! now proves it against the reference consensus engine.

use bitcoin::consensus::Encodable;
use bitcoin::Amount;

/// Verification outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Script failed consensus validation (error code from libbitcoinconsensus).
    ScriptFailed(i32),
    /// Serialization failed (should be impossible for built transactions).
    Encode(String),
    /// libbitcoinconsensus is unavailable in this build (feature off).
    EngineUnavailable,
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::ScriptFailed(code) => {
                write!(f, "consensus: script rejected (code {code})")
            }
            VerifyError::Encode(s) => write!(f, "encode error: {s}"),
            VerifyError::EngineUnavailable => write!(f, "consensus engine unavailable"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Serializes a tx to raw consensus bytes.
fn tx_to_bytes_inner(tx: &bitcoin::Transaction) -> Result<Vec<u8>, VerifyError> {
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf)
        .map_err(|e| VerifyError::Encode(e.to_string()))?;
    Ok(buf)
}

/// Serializes a tx to raw consensus bytes.
pub fn tx_to_bytes(tx: &bitcoin::Transaction) -> Result<Vec<u8>, VerifyError> {
    tx_to_bytes_inner(tx)
}

/// Verifies ALL inputs of a multi-input transaction against the consensus
/// engine (the multi-input coin-selection spend path). `inputs` must carry
/// every prevout (scriptPubKey + amount) in tx input order.
pub fn verify_transaction(
    tx: &bitcoin::Transaction,
    inputs: &[(bitcoin::ScriptBuf, Amount)],
) -> Result<(), VerifyError> {
    if inputs.len() != tx.input.len() {
        return Err(VerifyError::Encode(format!(
            "{} prevouts supplied for {} inputs",
            inputs.len(),
            tx.input.len()
        )));
    }
    let tx_bytes = tx_to_bytes_inner(tx)?;

    #[cfg(feature = "consensus")]
    {
        let utxos: Vec<bitcoinconsensus::Utxo> = inputs
            .iter()
            .map(|(spk, amount)| bitcoinconsensus::Utxo {
                script_pubkey: spk.as_bytes().as_ptr(),
                script_pubkey_len: spk.as_bytes().len() as u32,
                value: amount.to_sat() as i64,
            })
            .collect();
        for (i, (spk, amount)) in inputs.iter().enumerate() {
            bitcoinconsensus::verify_with_flags(
                spk.as_bytes(),
                amount.to_sat(),
                &tx_bytes,
                Some(&utxos),
                i,
                bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT | bitcoinconsensus::VERIFY_TAPROOT,
            )
            // ERR_SCRIPT is code 0 (the C library's "no code set"), so the
            // numeric value IS the enum discriminant for every variant.
            // (Round 41: a second `map_err` re-labelled every rejection as an
            // Encode error, so a caller matching on ScriptFailed — the only
            // variant that means "the network would refuse this" — could never
            // see it.)
            .map_err(|e| VerifyError::ScriptFailed(e as i32))?;
        }
        Ok(())
    }

    #[cfg(not(feature = "consensus"))]
    {
        let _ = (tx_bytes, inputs);
        Err(VerifyError::EngineUnavailable)
    }
}

/// Verifies a single input against the consensus engine.
///
/// With the `consensus` feature enabled this calls libbitcoinconsensus
/// (Bitcoin Core v26 script interpreter) over the serialized transaction and
/// the serialized prevout scriptPubKey. Amount is passed for sighash
/// commitment (BIP-341).
pub fn verify_input(
    tx: &bitcoin::Transaction,
    input_index: usize,
    script_pubkey: &bitcoin::ScriptBuf,
    amount: Amount,
) -> Result<(), VerifyError> {
    let tx_bytes = tx_to_bytes(tx)?;
    let spk_bytes = script_pubkey.as_bytes();

    #[cfg(feature = "consensus")]
    {
        // BIP-341 requires the prevout amount and script for sighash commitment:
        // pass the spent output via the Utxo struct (taproot-aware verify path).
        let utxo = bitcoinconsensus::Utxo {
            script_pubkey: spk_bytes.as_ptr(),
            script_pubkey_len: spk_bytes.len() as u32,
            value: amount.to_sat() as i64,
        };
        match bitcoinconsensus::verify_with_flags(
            spk_bytes,
            amount.to_sat(),
            &tx_bytes,
            Some(&[utxo]),
            input_index,
            bitcoinconsensus::VERIFY_ALL_PRE_TAPROOT | bitcoinconsensus::VERIFY_TAPROOT,
        ) {
            Ok(()) => Ok(()),
            Err(bitcoinconsensus::Error::ERR_SCRIPT) => Err(VerifyError::ScriptFailed(0)),
            Err(e) => Err(VerifyError::ScriptFailed(e as i32)),
        }
    }

    #[cfg(not(feature = "consensus"))]
    {
        let _ = (tx_bytes, input_index, spk_bytes, amount);
        Err(VerifyError::EngineUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, TxIn, TxOut};

    #[test]
    fn verify_transaction_requires_one_prevout_per_input() {
        let tx = bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        // The count guard runs BEFORE the engine, in every feature set.
        let err = verify_transaction(&tx, &[]).expect_err("0 prevouts for 1 input must fail");
        assert!(
            matches!(err, VerifyError::Encode(_)),
            "count mismatch must fail as an Encode error, got {err:?}"
        );
    }

    /// Round 41 (audit): a REJECTED script must surface as the consensus
    /// verdict, never as an encode error — the multi-input path used to
    /// re-label every refusal, hiding "the network would refuse this" behind
    /// "serialization broke".
    #[cfg(feature = "consensus")]
    #[test]
    fn verify_transaction_reports_the_script_verdict_not_an_encode_error() {
        let tx = bitcoin::Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: bitcoin::OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bitcoin::Witness::new(),
                },
                TxIn {
                    previous_output: bitcoin::OutPoint::null(),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        // OP_RETURN as a prevout script: unspendable under any witness.
        let unspendable = ScriptBuf::from_bytes(vec![0x6a]);
        let prevouts = vec![
            (unspendable.clone(), Amount::from_sat(10_000)),
            (unspendable, Amount::from_sat(10_000)),
        ];
        let err = verify_transaction(&tx, &prevouts).expect_err("OP_RETURN cannot be spent");
        assert!(
            matches!(err, VerifyError::ScriptFailed(_)),
            "a script rejection must stay a ScriptFailed verdict, got {err:?}"
        );
    }
}
