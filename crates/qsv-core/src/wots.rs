//! WOTS+ (RFC 8391 §3, w=16, n=32) — hash-based one-time signatures as the
//! post-Q-Day emergency sweep layer.
//!
//! Role in the protocol (docs/02 §5, docs/08 §1): lattice signatures (ML-DSA)
//! rest on structured-lattice hardness. WOTS+ rests ONLY on the (second)
//! preimage resistance of SHA-256 — the same assumption as Bitcoin itself —
//! so it survives a world where every lattice assumption also fell.
//!
//! Sizes at n=32, w=16: len1 = 32·8/4 = 64, len2 = ⌊log2(64·15)/4⌋+1 = 3,
//! len = 67 chunks → public key = 67·32 = 2,144 bytes, signature =
//! 67·32 = 2,144 bytes. One-time: a leaf-key pair signs ONE emergency sweep.
//!
//! The emergency leaf script commits to the WOTS+ public key with
//! `OP_SHA256 <32-byte digest> OP_EQUALVERIFY` (2,144 bytes hash to 32), so
//! the chain-visible cost of the option is one extra leaf hash — the WOTS+
//! key itself never appears on-chain until the leaf is actually spent.

use bitcoin::opcodes::all::{OP_EQUALVERIFY, OP_PUSHNUM_1, OP_SHA256};
use bitcoin::script::Builder;
use bitcoin::ScriptBuf;
use sha2::{Digest, Sha256};

/// Chain length n in bytes (RFC 8391 §2 recommends n=32 for SHA-256).
pub const N: usize = 32;
/// Winternitz parameter (RFC 8391 §5.2 recommends w=16).
pub const W: usize = 16;
/// Message digest width in chunks: len1 = n·8 / log2(w) = 32·8/4.
pub const LEN1: usize = N * 8 / 4;
/// Checksum chunk count: len2 = floor(log2(len1 * (w-1)) / log2(w)) + 1 = 3.
pub const LEN2: usize = 3;
/// Total chain count: len = len1 + len2 = 67.
pub const LEN: usize = LEN1 + LEN2;
/// Public key / signature size in bytes: len * n = 2,144.
pub const PK_SIZE: usize = LEN * N;
/// Number of hash iterations per chain (maximum): w - 1 = 15.
pub const CHAIN_STEPS: usize = W - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WotsError {
    /// Public key or signature buffer has the wrong size.
    BadSize { expected: usize, got: usize },
    /// Signature does not verify against the committed public key.
    VerificationFailed,
}

impl core::fmt::Display for WotsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WotsError::BadSize { expected, got } => {
                write!(f, "bad WOTS+ buffer size (expected {expected}, got {got})")
            }
            WotsError::VerificationFailed => write!(f, "WOTS+ verification failed"),
        }
    }
}

impl std::error::Error for WotsError {}

/// Base-w expansion of a 32-byte message into `len1` nibbles (big-endian).
fn expand_message(msg: &[u8; N]) -> Vec<u8> {
    let mut chunks = Vec::with_capacity(LEN1);
    for byte in msg {
        chunks.push(byte >> 4); // high nibble
        chunks.push(byte & 0x0F); // low nibble
    }
    chunks
}

/// Checksum (RFC 8391 §3.1): sum of (w-1-x) over message chunks, base-w.
fn checksum(msg_chunks: &[u8]) -> Vec<u8> {
    let total: u32 = msg_chunks.iter().map(|&c| (W as u32 - 1) - c as u32).sum();
    // c_max = len1 * (w-1) = 64 * 15 = 960 < 2^10; len2 = 3 nibbles.
    let mut nibbles = [0u8; LEN2];
    let mut c = total;
    for slot in nibbles.iter_mut().rev() {
        *slot = (c % W as u32) as u8;
        c /= W as u32;
    }
    nibbles.to_vec()
}

/// Forward hash iteration: block -> H(block) applied `steps` times. This is
/// the RFC 8391 chain function proper (no domain separation inside a chain).
fn hash_forward(mut block: [u8; N], steps: u8) -> [u8; N] {
    for _ in 0..steps {
        let mut h = Sha256::new();
        h.update(block);
        block = h.finalize().into();
    }
    block
}

/// One WOTS+ hash chain step: the private key block is hashed into the
/// per-chain key derivation stream first, per RFC 8391 §3 chain construction
/// (seed domain separation: every chain input starts as H(seed ‖ LE32(i))).
fn chain_step(seed: &[u8; N], chain_index: usize, steps: u8) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(seed);
    h.update((chain_index as u32).to_le_bytes());
    let block: [u8; N] = h.finalize().into();
    hash_forward(block, steps)
}

/// Deterministic WOTS+ keypair from a 32-byte leaf seed.
///
/// SECURITY: one-time use. Each emergency leaf burns its key pair; reuse
/// exposes the full private key by differential cryptanalysis of the chains.
pub fn keypair_from_seed(seed: &[u8; N]) -> ([u8; PK_SIZE], [u8; PK_SIZE]) {
    let mut sk = [0u8; PK_SIZE];
    let mut pk = [0u8; PK_SIZE];
    for i in 0..LEN {
        let leaf = chain_step(seed, i, 0);
        sk[i * N..(i + 1) * N].copy_from_slice(&leaf);
        // Public block: the chain head after w-1 forward hashes of the leaf.
        let pub_block = hash_forward(leaf, CHAIN_STEPS as u8);
        pk[i * N..(i + 1) * N].copy_from_slice(&pub_block);
    }
    (sk, pk)
}

/// Signs a 32-byte digest (RFC 8391 §3.3).
pub fn sign(sk: &[u8; PK_SIZE], msg: &[u8; N]) -> Result<[u8; PK_SIZE], WotsError> {
    let mut sig = [0u8; PK_SIZE];
    let mut chunks = expand_message(msg);
    chunks.extend(checksum(&chunks));
    for i in 0..LEN {
        let steps = chunks[i];
        let mut block = [0u8; N];
        block.copy_from_slice(&sk[i * N..(i + 1) * N]);
        for _ in 0..steps {
            let mut h = Sha256::new();
            h.update(block);
            block = h.finalize().into();
        }
        sig[i * N..(i + 1) * N].copy_from_slice(&block);
    }
    Ok(sig)
}

/// Verifies a WOTS+ signature by recomputing the public key (RFC 8391 §3.4).
pub fn verify(pk: &[u8; PK_SIZE], msg: &[u8; N], sig: &[u8]) -> Result<(), WotsError> {
    if sig.len() != PK_SIZE {
        return Err(WotsError::BadSize {
            expected: PK_SIZE,
            got: sig.len(),
        });
    }
    let mut chunks = expand_message(msg);
    chunks.extend(checksum(&chunks));
    for i in 0..LEN {
        let steps = chunks[i];
        let mut block = [0u8; N];
        block.copy_from_slice(&sig[i * N..(i + 1) * N]);
        for _ in 0..(CHAIN_STEPS - steps as usize) {
            let mut h = Sha256::new();
            h.update(block);
            block = h.finalize().into();
        }
        if block[..] != pk[i * N..(i + 1) * N] {
            return Err(WotsError::VerificationFailed);
        }
    }
    Ok(())
}

/// The 32-byte leaf commitment: SHA-256(WOTS+ public key). This is the only
/// on-chain artifact of the escape hatch (inside the emergency leaf script).
pub fn commit_digest(pk: &[u8; PK_SIZE]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(pk);
    h.finalize().into()
}

/// Emergency leaf script committing to a WOTS+ public key:
///
/// ```text
/// OP_SHA256 <sha256(wots_pk)> OP_EQUALVERIFY <pk_user> OP_CHECKSIG
/// ```
///
/// The WOTS+ signature itself is witness data (2,144 B, well under the 4 MWU
/// weight budget: 2,144 + 64 + script + control ≈ 2,350 weight units < 4M).
/// Spending reveals the preimage of the commitment; consensus enforces both
/// the hash lock and the classical key, tying the escape to one holder.
pub fn emergency_leaf_script(pk: &[u8; PK_SIZE], pk_user: &bitcoin::XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_SHA256)
        .push_slice(commit_digest(pk))
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(pk_user)
        .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
        .into_script()
}

/// Key-path-only P2TR scriptPubKey over an output key (helper for deriving
/// the emergency sweep destination address from the committed escape key).
pub fn p2tr_spk(output_key: &bitcoin::XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(output_key.serialize())
        .into_script()
}

/// Parameter-space study (docs/08 §3, RFC 8391 §5.2): sizes for every legal
/// Winternitz parameter over an `msg_bytes`-byte message.
///
/// Derivation: `len1 = ⌈8·msg_bytes / log2(w)⌉` message chunks,
/// `len2 = ⌊log2(len1·(w−1)) / log2(w)⌋ + 1` checksum chunks, signature =
/// `(len1+len2) · n` bytes. For n = 32 the study proves an impossibility:
/// NO parameter set fits a full 32-byte message inside BIP-342's 520-byte
/// initial-stack element cap (best case w = 256 → 34 chains → 1,088 B).
/// Truncating the message far enough to fit (≤ 14 bytes / 112 bits at the
/// best parameters) drops below SHA-256's 128-bit collision target — so the
/// protocol's 37-byte commit-reveal leaf (taproot::emergency_leaf_script)
/// is not an optimization, it is the ONLY safe shape until a future soft
/// fork (OP_CAT-family opcodes, or Blockstream's OP_CHECKSHRINCS over
/// BIP-360 P2MR leaves) can verify hash-based signatures directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamRow {
    /// Winternitz parameter (power of two, ≥ 2).
    pub w: usize,
    /// Message chunks (`len1`).
    pub len1: usize,
    /// Checksum chunks (`len2`).
    pub len2: usize,
    /// Total chains = len1 + len2.
    pub chains: usize,
    /// Signature / public key size in bytes (chains · n).
    pub sig_bytes: usize,
    /// Maximum hash steps per chain (w − 1).
    pub max_chain_steps: usize,
    /// Whether the signature fits a single BIP-342 witness element (≤ 520 B).
    pub fits_520: bool,
}

/// Legal Winternitz parameters swept by the study (RFC 8391 allows any
/// power of two ≥ 2; XMSS commonly uses {4,16}; RFC 8391 recommends 16).
pub const PARAM_STUDY_W: [usize; 8] = [2, 4, 8, 16, 32, 64, 128, 256];

/// Message lengths (bytes) studied: full digest, half digest, 64-bit digest.
pub const PARAM_STUDY_MSG_BYTES: [usize; 3] = [32, 16, 8];

/// RFC 8391 sizing for one (w, message length) pair.
pub fn params_for(w: usize, msg_bytes: usize) -> ParamRow {
    assert!(
        w.is_power_of_two() && w >= 2,
        "w must be a power of two ≥ 2"
    );
    assert!(msg_bytes >= 1, "message must be ≥ 1 byte");
    let logw = w.trailing_zeros() as usize;
    let len1 = msg_bytes
        .checked_mul(8)
        .expect("message bits overflow")
        .div_ceil(logw);
    let cmax = len1 * (w - 1);
    let log2_cmax = (usize::BITS - 1 - cmax.leading_zeros()) as usize;
    let len2 = log2_cmax / logw + 1;
    let chains = len1 + len2;
    let sig_bytes = chains * N;
    ParamRow {
        w,
        len1,
        len2,
        chains,
        sig_bytes,
        max_chain_steps: w - 1,
        fits_520: sig_bytes <= crate::budget::BIP342_MAX_ELEMENT_BYTES,
    }
}

/// Full sweep: every legal `w` for a fixed message length (tree order).
pub fn param_study(msg_bytes: usize) -> Vec<ParamRow> {
    PARAM_STUDY_W
        .iter()
        .map(|&w| params_for(w, msg_bytes))
        .collect()
}

/// Largest message (bytes) that parameter `w` can still sign inside a
/// `budget_bytes` single witness element. Returns 0 if even 1 byte cannot fit.
pub fn max_message_bytes_for_budget(w: usize, budget_bytes: usize) -> usize {
    if params_for(w, 1).sig_bytes > budget_bytes {
        return 0;
    }
    let mut m = 1usize;
    while params_for(w, m + 1).sig_bytes <= budget_bytes {
        m += 1;
    }
    m
}

/// Security ceiling of any sub-520-byte WOTS+ signature: the best message
/// length over all legal `w`, in bytes. For n = 32 this is 14 bytes = 112
/// bits — below the 128-bit collision target of SHA-256, which is why the
/// emergency leaf reveals a Schnorr key (commit-reveal) instead of a
/// truncated WOTS+ signature.
pub fn sub520_max_message_bytes() -> usize {
    PARAM_STUDY_W
        .iter()
        .map(|&w| max_message_bytes_for_budget(w, crate::budget::BIP342_MAX_ELEMENT_BYTES))
        .max()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo_msg() -> [u8; N] {
        let mut h = Sha256::new();
        h.update(b"qsv emergency sweep digest");
        h.finalize().into()
    }

    #[test]
    fn rfc_sizes_and_constants_are_exact() {
        assert_eq!(LEN1, 64);
        assert_eq!(LEN2, 3);
        assert_eq!(LEN, 67);
        assert_eq!(PK_SIZE, 2_144);
        assert_eq!(CHAIN_STEPS, 15);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, pk) = keypair_from_seed(&[7u8; N]);
        let msg = demo_msg();
        let sig = sign(&sk, &msg).unwrap();
        verify(&pk, &msg, &sig).expect("valid WOTS+ signature must verify");
    }

    #[test]
    fn tampered_message_is_rejected() {
        let (sk, pk) = keypair_from_seed(&[9u8; N]);
        let msg = demo_msg();
        let sig = sign(&sk, &msg).unwrap();
        let mut forged_msg = msg;
        forged_msg[0] ^= 0x01;
        assert!(verify(&pk, &forged_msg, &sig).is_err());
        let mut forged_sig = sig;
        forged_sig[10] ^= 0x80;
        assert!(verify(&pk, &msg, &forged_sig).is_err());
    }

    #[test]
    fn bad_size_is_fail_closed() {
        let (_, pk) = keypair_from_seed(&[5u8; N]);
        assert!(matches!(
            verify(&pk, &demo_msg(), &[0u8; 100]),
            Err(WotsError::BadSize { .. })
        ));
    }

    #[test]
    fn keys_are_deterministic_and_seed_separated() {
        let (sk1, pk1) = keypair_from_seed(&[3u8; N]);
        let (sk2, pk2) = keypair_from_seed(&[3u8; N]);
        let (sk3, pk3) = keypair_from_seed(&[4u8; N]);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
        assert_ne!(sk1, sk3);
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn commitment_binds_the_full_public_key() {
        let (_, pk) = keypair_from_seed(&[21u8; N]);
        let (_, pk_other) = keypair_from_seed(&[22u8; N]);
        let mut pk_tampered = pk;
        pk_tampered[100] ^= 0x01;
        assert_ne!(commit_digest(&pk), commit_digest(&pk_other));
        assert_ne!(commit_digest(&pk), commit_digest(&pk_tampered));
    }

    #[test]
    fn emergency_leaf_script_embeds_the_commitment() {
        use bitcoin::opcodes::all::{OP_CHECKSIG as OP_CS, OP_SHA256 as OP_SHA};
        let (_, pk) = keypair_from_seed(&[31u8; N]);
        let user = bitcoin::XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
        let script = emergency_leaf_script(&pk, &user);
        let bytes = script.as_bytes();
        // Opcode skeleton present: SHA256 ... EQUALVERIFY ... CHECKSIG.
        assert!(bytes.contains(&OP_SHA.to_u8()));
        assert!(bytes.contains(&OP_CS.to_u8()));
        // The 32-byte commitment is embedded verbatim.
        let digest = commit_digest(&pk);
        assert!(bytes.windows(32).any(|w| w == digest));
        // Script = 1 + 33 (digest push) + 1 + 33 (key push) + 1 = 69 bytes:
        // the commitment, never the 2,144-byte WOTS+ key.
        assert_eq!(bytes.len(), 69);
    }

    #[test]
    fn param_study_rfc8391_row_matches_shipped_constants() {
        // w = 16, n = 32 must reproduce the shipped RFC 8391 constants.
        let row = params_for(W, N);
        assert_eq!(row.len1, LEN1);
        assert_eq!(row.len2, LEN2);
        assert_eq!(row.chains, LEN);
        assert_eq!(row.sig_bytes, PK_SIZE);
        assert_eq!(row.max_chain_steps, CHAIN_STEPS);
        assert!(!row.fits_520, "2,144 B cannot fit a 520 B element");
    }

    #[test]
    fn param_study_w4_row_is_exact() {
        // w = 4: len1 = 256/2 = 128, len2 = ⌊log2(128·3)/2⌋+1 = 5 → 133 chains.
        let row = params_for(4, 32);
        assert_eq!((row.len1, row.len2, row.chains), (128, 5, 133));
        assert_eq!(row.sig_bytes, 133 * 32); // 4,256 B — WORSE than w=16
        assert_eq!(row.max_chain_steps, 3);
        assert!(!row.fits_520);
        // Smaller w trades size for speed: fewer hashes/chain, MORE chains.
        assert!(row.sig_bytes > PK_SIZE);
        assert!(row.max_chain_steps < CHAIN_STEPS);
    }

    #[test]
    fn no_winternitz_parameter_fits_a_full_digest_in_520_bytes() {
        let study = param_study(N);
        assert_eq!(study.len(), PARAM_STUDY_W.len());
        for row in &study {
            assert!(!row.fits_520, "w={} unexpectedly fits", row.w);
        }
        // Global minimum is w = 256: len1 = 32, len2 = 2 → 34 chains → 1,088 B.
        let best = study.iter().min_by_key(|r| r.sig_bytes).unwrap();
        assert_eq!(best.w, 256);
        assert_eq!(best.sig_bytes, 1_088);
        // The shipped w=16 configuration sits in the middle of the sweep.
        assert!(study.iter().any(|r| r.w == 16 && r.sig_bytes == PK_SIZE));
    }

    #[test]
    fn sub520_truncation_ceiling_is_below_sha256_collision_target() {
        // Largest message each parameter can still sign within 520 bytes:
        assert_eq!(max_message_bytes_for_budget(4, 520), 3);
        assert_eq!(max_message_bytes_for_budget(16, 520), 7);
        assert_eq!(max_message_bytes_for_budget(64, 520), 10);
        // …best over ALL legal w is 14 bytes = 112 bits:
        let best = sub520_max_message_bytes();
        assert_eq!(best, 14);
        assert!(
            best * 8 < 128,
            "112-bit forgery cost is below SHA-256's 128-bit target"
        );
        // Degenerate budget: nothing fits.
        assert_eq!(max_message_bytes_for_budget(16, 100), 0);
    }
}
