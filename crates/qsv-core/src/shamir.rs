//! Shamir's Secret Sharing (SSS) over GF(256) for the 32-byte emergency-kit
//! seed (docs/08 §2, docs/10 §4).
//!
//! The WOTS+-sealed offline kit is the post-Q-Day escape hatch. Whoever
//! reconstructs the kit seed can derive the WOTS+ keypair, unseal the kit and
//! move the emergency funds — so the seed must not live in one place for
//! decades. SSS splits it into `n` shares where any `k` reconstruct it and
//! fewer than `k` reveal NOTHING (each share is one evaluation of a random
//! polynomial per seed byte).
//!
//! Construction (classic Shamir 1979, field GF(2^8) with the AES reduction
//! polynomial 0x11B):
//!
//! * For each of the 32 seed bytes independently: `f_p(x) = c₀ + c₁x + … +
//!   c_{k−1}x^{k−1}` with `c₀ = seed[p]` and `c₁..c_{k−1}` drawn from OS
//!   randomness.
//! * Share `i` is `(i, f₁(i), …, f₃₂(i))` — 32 y-bytes.
//! * Reconstruction evaluates the Lagrange basis at `x = 0`.
//!
//! Fail-closed integrity: every share carries `tag = SHA256("QSV-SSS-TAG-v1"
//! ‖ seed)[0..4]`. Fewer-than-k shares, shares from a different split, or
//! corrupted bytes all fail the tag check — the combiner NEVER returns
//! silently-wrong key material. The tag defends against corruption and typos;
//! as in every unauthenticated SSS scheme it cannot defend against an
//! adversary who controls ALL share copies (store shares separately).
//!
//! Seed requirement: the shared secret must be ≥ 128-bit uniformly random
//! (the emergency kit seed is 256-bit). Low-entropy secrets would make the
//! tag a verification oracle for dictionary attacks — split those only with
//! a KDF-hardened scheme (SLIP-0039, planned for Phase 1 provisioning).
//!
//! Encoding: `qsvss1-<index>-<72 hex chars>` (versioned, checksum-free — the
//! 4-byte tag is the integrity check).

use bitcoin::secp256k1::rand::RngCore;
use sha2::{Digest, Sha256};

/// Seed length (bytes) shared by this module — the emergency kit seed.
pub const SECRET_LEN: usize = 32;
/// Integrity tag length (bytes) appended to every share.
pub const TAG_LEN: usize = 4;
/// Share payload length: y-bytes + tag.
pub const SHARE_LEN: usize = SECRET_LEN + TAG_LEN;
/// Wire-format version prefix of an encoded share.
pub const SHARE_VERSION: &str = "qsvss1";
/// Domain separator for the integrity tag.
pub const TAG_DOMAIN: &[u8] = b"QSV-SSS-TAG-v1";

/// Errors raised while splitting or recombining shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShamirError {
    /// Threshold below 2 (a 1-of-n "split" is just duplication).
    InvalidThreshold,
    /// Share count below the threshold or above the 255 index space.
    InvalidShareCount,
    /// Fewer than 2 shares supplied to the combiner.
    NotEnoughShares,
    /// Two shares carry the same x-index.
    DuplicateIndex(u8),
    /// Shares come from different splits (tags disagree).
    MixedShareSets,
    /// Recombination produced a secret whose tag does not match: insufficient
    /// shares, corrupted data, or foreign shares. Never returns wrong key.
    TagMismatch,
    /// Encoded share string is malformed.
    BadEncoding,
}

impl core::fmt::Display for ShamirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ShamirError::InvalidThreshold => write!(f, "threshold must be >= 2"),
            ShamirError::InvalidShareCount => {
                write!(f, "share count must satisfy threshold <= n <= 255")
            }
            ShamirError::NotEnoughShares => write!(f, "at least 2 shares are required"),
            ShamirError::DuplicateIndex(i) => write!(f, "duplicate share index {i}"),
            ShamirError::MixedShareSets => write!(f, "shares come from different splits"),
            ShamirError::TagMismatch => {
                write!(
                    f,
                    "integrity tag mismatch: insufficient or corrupted shares"
                )
            }
            ShamirError::BadEncoding => write!(f, "malformed share string"),
        }
    }
}

impl std::error::Error for ShamirError {}

/// One reconstructed-able share: x-index + y-bytes + integrity tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Evaluation point (1..=255), unique within a split.
    pub index: u8,
    /// `f(index)` per seed byte, followed by the 4-byte tag.
    pub data: [u8; SHARE_LEN],
}

impl Share {
    /// The 32 secret-sharing y-bytes (no tag).
    pub fn y_bytes(&self) -> [u8; SECRET_LEN] {
        let mut out = [0u8; SECRET_LEN];
        out.copy_from_slice(&self.data[..SECRET_LEN]);
        out
    }

    /// The embedded integrity tag.
    pub fn tag(&self) -> [u8; TAG_LEN] {
        let mut out = [0u8; TAG_LEN];
        out.copy_from_slice(&self.data[SECRET_LEN..]);
        out
    }

    /// Canonical wire form: `qsvss1-<index>-<hex>`.
    pub fn encode(&self) -> String {
        format!(
            "{}-{}-{}",
            SHARE_VERSION,
            self.index,
            hex::encode(self.data)
        )
    }

    /// Parses the canonical wire form (fail-closed on any malformation).
    pub fn decode(s: &str) -> Result<Share, ShamirError> {
        let mut parts = s.trim().splitn(3, '-');
        let ver = parts.next().ok_or(ShamirError::BadEncoding)?;
        let idx = parts.next().ok_or(ShamirError::BadEncoding)?;
        let data = parts.next().ok_or(ShamirError::BadEncoding)?;
        if ver != SHARE_VERSION {
            return Err(ShamirError::BadEncoding);
        }
        let index: u8 = idx.parse().map_err(|_| ShamirError::BadEncoding)?;
        if index == 0 {
            return Err(ShamirError::BadEncoding);
        }
        let bytes = hex::decode(data).map_err(|_| ShamirError::BadEncoding)?;
        if bytes.len() != SHARE_LEN {
            return Err(ShamirError::BadEncoding);
        }
        let mut fixed = [0u8; SHARE_LEN];
        fixed.copy_from_slice(&bytes);
        Ok(Share { index, data: fixed })
    }
}

/// Integrity tag of a secret (binds every share to the exact seed).
pub fn secret_tag(secret: &[u8; SECRET_LEN]) -> [u8; TAG_LEN] {
    let mut h = Sha256::new();
    h.update(TAG_DOMAIN);
    h.update(secret);
    let d: [u8; 32] = h.finalize().into();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&d[..TAG_LEN]);
    tag
}

// ── GF(2^8), AES reduction polynomial x⁸+x⁴+x³+x+1 (0x11B) ────────────────

/// GF(256) multiplication (Russian peasant, reduced by 0x11B).
fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a as u16;
    let mut b = b as u16;
    let mut p = 0u16;
    while b > 0 {
        if b & 1 == 1 {
            p ^= a;
        }
        a <<= 1;
        if a & 0x100 != 0 {
            a ^= 0x11B;
        }
        b >>= 1;
    }
    p as u8
}

/// GF(256) inverse via a²⁵⁴ (None for 0 — callers guard).
fn gf_inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    // a^254 = a^(11111110₂): square-and-multiply over exponent 254.
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u8;
    while exp > 0 {
        if exp & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    Some(result)
}

/// f(x) for one byte-position polynomial: coefficients `[c₀..c_{k−1}]`.
fn poly_eval(coefficients: &[u8], x: u8) -> u8 {
    // Horner: c₀ + x·(c₁ + x·(c₂ + …))
    coefficients
        .iter()
        .rev()
        .fold(0u8, |acc, &c| gf_mul(acc, x) ^ c)
}

/// Splits a 32-byte secret into `share_count` shares; any `threshold` of them
/// recombine. Shares are randomized (OS entropy); the pair is inherently
/// non-deterministic, which is the correct property for secret sharing.
pub fn split(
    secret: &[u8; SECRET_LEN],
    threshold: usize,
    share_count: usize,
) -> Result<Vec<Share>, ShamirError> {
    if threshold < 2 {
        return Err(ShamirError::InvalidThreshold);
    }
    if share_count < threshold || share_count > 255 {
        return Err(ShamirError::InvalidShareCount);
    }

    let tag = secret_tag(secret);

    // Random coefficients c₁..c_{k−1} for each of the 32 byte positions.
    let rand_len = SECRET_LEN * (threshold - 1); // threshold ≥ 2 ⇒ ≥ 32 bytes
    let mut random = vec![0u8; rand_len];
    let mut rng = bitcoin::secp256k1::rand::thread_rng();
    rng.fill_bytes(&mut random);

    let mut shares = Vec::with_capacity(share_count);
    for idx in 1..=share_count as u8 {
        let x = idx;
        let mut data = [0u8; SHARE_LEN];
        for (p, &secret_byte) in secret.iter().enumerate() {
            let mut coefficients = vec![0u8; threshold];
            coefficients[0] = secret_byte;
            for j in 1..threshold {
                coefficients[j] = random[p * (threshold - 1) + (j - 1)];
            }
            data[p] = poly_eval(&coefficients, x);
        }
        data[SECRET_LEN..].copy_from_slice(&tag);
        shares.push(Share { index: idx, data });
    }
    Ok(shares)
}

/// Recombines shares into the secret. Uses EVERY supplied share (≥ k consistent
/// points interpolate the same polynomial; < k or foreign/corrupted shares
/// fail the integrity tag — wrong key material is never returned).
pub fn combine(shares: &[Share]) -> Result<[u8; SECRET_LEN], ShamirError> {
    if shares.len() < 2 {
        return Err(ShamirError::NotEnoughShares);
    }
    // All shares must belong to the same split.
    let first_tag = shares[0].tag();
    for s in shares {
        if s.tag() != first_tag {
            return Err(ShamirError::MixedShareSets);
        }
    }
    // Unique indices (Lagrange denominator would otherwise be 0).
    for (i, a) in shares.iter().enumerate() {
        for b in &shares[i + 1..] {
            if a.index == b.index {
                return Err(ShamirError::DuplicateIndex(a.index));
            }
        }
    }

    // Lagrange interpolation at x = 0, per byte position.
    let mut secret = [0u8; SECRET_LEN];
    for (p, out) in secret.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (i, si) in shares.iter().enumerate() {
            // basis_i = Π_{j≠i} x_j / (x_j − x_i)   (evaluated at 0)
            let mut basis = 1u8;
            for (j, sj) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let num = sj.index;
                let den = sj.index ^ si.index; // subtraction = XOR in GF(2^m)
                let inv = gf_inv(den).ok_or(ShamirError::DuplicateIndex(si.index))?;
                basis = gf_mul(basis, gf_mul(num, inv));
            }
            acc ^= gf_mul(si.y_bytes()[p], basis);
        }
        *out = acc;
    }

    // Fail-closed integrity: never hand back wrong key material.
    if secret_tag(&secret) != first_tag {
        return Err(ShamirError::TagMismatch);
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret_from(n: u8) -> [u8; SECRET_LEN] {
        let mut s = [0u8; SECRET_LEN];
        for (i, b) in s.iter_mut().enumerate() {
            *b = n.wrapping_add(i as u8);
        }
        s
    }

    #[test]
    fn any_threshold_shares_reconstruct_the_secret() {
        let secret = secret_from(7);
        let shares = split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        // Every 3-subset of the 5 shares (C(5,3) = 10 combinations).
        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let got = combine(&[shares[a].clone(), shares[b].clone(), shares[c].clone()])
                        .expect("any 3 of 5 must recombine");
                    assert_eq!(got, secret);
                }
            }
        }
        // All 5 together also work (consistent points of the same polynomial).
        assert_eq!(combine(&shares).unwrap(), secret);
    }

    #[test]
    fn fewer_than_threshold_shares_never_leak_the_secret() {
        let secret = secret_from(9);
        let shares = split(&secret, 3, 5).unwrap();
        // 2 shares: underdetermined → wrong polynomial → tag rejects.
        for a in 0..5 {
            for b in (a + 1)..5 {
                assert_eq!(
                    combine(&[shares[a].clone(), shares[b].clone()]),
                    Err(ShamirError::TagMismatch)
                );
            }
        }
        // A single share carries no recognizable secret material.
        assert_ne!(shares[0].y_bytes(), secret);
        assert_eq!(
            combine(&[shares[0].clone()]),
            Err(ShamirError::NotEnoughShares)
        );
    }

    #[test]
    fn tampered_share_is_rejected_fail_closed() {
        let secret = secret_from(3);
        let mut shares = split(&secret, 3, 5).unwrap();
        // Corrupt a y-byte (tag intact → only Lagrange+tag catches it).
        shares[2].data[10] ^= 0x01;
        assert_eq!(
            combine(&[shares[0].clone(), shares[1].clone(), shares[2].clone()]),
            Err(ShamirError::TagMismatch)
        );
        // Corrupt the tag itself → caught immediately as a mixed/foreign set
        // once compared against a pristine share, or TagMismatch alone.
        let mut shares2 = split(&secret, 3, 5).unwrap();
        shares2[0].data[SHARE_LEN - 1] ^= 0xFF;
        let r = combine(&[shares2[0].clone(), shares2[1].clone(), shares2[2].clone()]);
        assert!(r.is_err());
        assert_ne!(r, Ok(secret));
    }

    #[test]
    fn mixed_splits_are_rejected() {
        let a = split(&secret_from(1), 2, 3).unwrap();
        let b = split(&secret_from(2), 2, 3).unwrap();
        assert_eq!(
            combine(&[a[0].clone(), b[1].clone()]),
            Err(ShamirError::MixedShareSets)
        );
    }

    #[test]
    fn duplicate_index_is_rejected() {
        let shares = split(&secret_from(5), 2, 3).unwrap();
        let mut dup = shares[1].clone();
        dup.index = shares[0].index;
        // Index drives interpolation; identical x breaks the denominator.
        assert_eq!(
            combine(&[shares[0].clone(), dup]),
            Err(ShamirError::DuplicateIndex(1))
        );
    }

    #[test]
    fn invalid_parameters_fail_at_split_time() {
        let s = secret_from(1);
        assert_eq!(split(&s, 1, 3), Err(ShamirError::InvalidThreshold));
        assert_eq!(split(&s, 4, 3), Err(ShamirError::InvalidShareCount));
        assert_eq!(split(&s, 3, 256), Err(ShamirError::InvalidShareCount));
    }

    #[test]
    fn share_wire_format_roundtrips_and_rejects_malformed() {
        let shares = split(&secret_from(11), 2, 3).unwrap();
        for s in &shares {
            let enc = s.encode();
            assert!(enc.starts_with("qsvss1-"));
            assert_eq!(&Share::decode(&enc).unwrap(), s);
        }
        assert_eq!(Share::decode("nope"), Err(ShamirError::BadEncoding));
        assert_eq!(
            Share::decode("qsvss2-1-deadbeef"),
            Err(ShamirError::BadEncoding)
        );
        assert_eq!(
            Share::decode("qsvss1-0-aabb"),
            Err(ShamirError::BadEncoding)
        );
        assert_eq!(Share::decode("qsvss1-1-zz"), Err(ShamirError::BadEncoding));
        // Whitespace-tolerant (copy/paste friendly).
        assert_eq!(
            Share::decode(&format!("  {}\n", shares[0].encode())).unwrap(),
            shares[0]
        );
    }

    #[test]
    fn tags_are_domain_separated_and_secret_bound() {
        let t1 = secret_tag(&secret_from(1));
        let t2 = secret_tag(&secret_from(2));
        assert_ne!(t1, t2);
        // Tag is not the bare SHA-256 prefix (domain separation).
        let mut h = Sha256::new();
        h.update(secret_from(1));
        let d: [u8; 32] = h.finalize().into();
        assert_ne!(&t1[..], &d[..TAG_LEN]);
    }

    #[test]
    fn wire_decode_refuses_every_malformed_shape() {
        // Wrong payload length (the wall the round-trip vectors never hit).
        assert_eq!(Share::decode("qsvss1-1-00"), Err(ShamirError::BadEncoding));
        // Missing fields, foreign version, zero index, non-hex, short data.
        for bad in [
            "bogus",
            "qsvss1",
            "qsvss9-1-00",
            "qsvss1-0-00",
            "qsvss1-x-00",
            "qsvss1-1-zzz",
            &format!("qsvss1-1-{}", "00".repeat(SHARE_LEN - 1)),
        ] {
            assert_eq!(Share::decode(bad), Err(ShamirError::BadEncoding), "{bad}");
        }
        // Every Display arm renders its own message.
        let cases = [
            (ShamirError::InvalidThreshold, "threshold must be >= 2"),
            (
                ShamirError::InvalidShareCount,
                "share count must satisfy threshold <= n <= 255",
            ),
            (
                ShamirError::NotEnoughShares,
                "at least 2 shares are required",
            ),
            (ShamirError::DuplicateIndex(9), "duplicate share index 9"),
            (
                ShamirError::MixedShareSets,
                "shares come from different splits",
            ),
            (ShamirError::BadEncoding, "malformed share string"),
        ];
        for (e, want) in cases {
            assert_eq!(e.to_string(), want);
        }
        assert!(ShamirError::TagMismatch
            .to_string()
            .contains("integrity tag mismatch"));
    }

    #[test]
    fn gf_inverse_of_zero_is_none_and_inverts_every_element() {
        // The guarded wall: GF(2^8) has no inverse for 0.
        assert_eq!(gf_inv(0), None);
        for a in 1..=u8::MAX {
            assert_eq!(gf_mul(a, gf_inv(a).expect("nonzero inverts")), 1, "a={a}");
        }
    }
}
