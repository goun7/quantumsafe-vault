//! SLIP-0039 — Shamir's Secret-Sharing for Mnemonic Codes (Final, 2017-12-18).
//!
//! Interoperable backup format for the emergency-kit master secret: the seed
//! is split into human-readable 20/33-word mnemonics, any threshold subset
//! reconstitutes it, fewer shares reveal nothing. Two levels (groups →
//! members) let the operator separate "money folder" trust from "friends"
//! trust, and the encrypted master secret is protected by a 4-round
//! Feistel/PBKDF2 permutation so a leaked share never exposes plaintext.
//!
//! Faithful implementation of the specification:
//!   * GF(256) with the Rijndael polynomial `x^8+x^4+x^3+x+1`
//!   * `SplitSecret` stores the secret at index 255 and its HMAC digest at
//!     index 254 (never at index 0 — the index-0 substitution attack)
//!   * RS1024 checksum, customization string `shamir` / `shamir_extendable`
//!   * Feistel encryption: `F(i,R) = PBKDF2-HMAC-SHA256(i‖passphrase,
//!     salt_prefix‖R, 2500<<e, n/2)`
//!   * the 1024-word list mandated by the SLIP
//!
//! Validated against all 45 official test vectors
//! (trezor/python-shamir-mnemonic `vectors.json`), including every negative
//! vector: bad checksum, bad padding, mixed identifiers / iteration
//! exponents / thresholds, duplicate indices, invalid digest and
//! insufficient-share sets.

use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::RngCore;
use sha2::{Digest, Sha256};

/// The mandated 1024-word list (alphabetically sorted, unique 4-letter
/// prefixes), embedded verbatim from the SLIP repository.
const WORDLIST: &str = include_str!("slip39_wordlist.txt");

/// Customization strings for the RS1024 checksum.
const CS_PLAIN: &str = "shamir";
const CS_EXTENDABLE: &str = "shamir_extendable";

/// Header size of a share in bits: id(15) + ext(1) + e(4) + GI(4) + Gt(4)
/// + g(4) + I(4) + t(4).
const HEADER_BITS: usize = 40;

/// Errors raised by the SLIP-0039 codec. Every failure path is fail-closed:
/// the caller receives an error, never partial or wrong key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slip39Error {
    /// A mnemonic word is unknown, the count is wrong, or the RS1024
    /// checksum does not verify.
    ChecksumOrFormat(String),
    /// The share set violates the combining preconditions (mixed metadata,
    /// duplicate indices, too few shares, …).
    Mismatch(String),
    /// The recovered digest at index 254 does not match the secret.
    Digest,
    /// Split parameters out of range (threshold, share count, secret size).
    Parameters(String),
}

impl core::fmt::Display for Slip39Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Slip39Error::ChecksumOrFormat(s) => write!(f, "mnemonic format/checksum: {s}"),
            Slip39Error::Mismatch(s) => write!(f, "share set mismatch: {s}"),
            Slip39Error::Digest => write!(
                f,
                "share digest mismatch (wrong or fabricated share set — fail-closed)"
            ),
            Slip39Error::Parameters(s) => write!(f, "invalid parameters: {s}"),
        }
    }
}

impl std::error::Error for Slip39Error {}

/// One group of the two-level scheme: `threshold`-of-`members`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupSpec {
    /// Member threshold T (1 ≤ T ≤ N).
    pub threshold: u8,
    /// Member count N (1 ≤ N ≤ 16).
    pub members: u8,
}

impl GroupSpec {
    /// Convenience constructor.
    pub fn new(threshold: u8, members: u8) -> Self {
        Self { threshold, members }
    }
}

/// A decoded share mnemonic (all fields are the *actual* values, not the
/// 4-bit encoded ones).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Random 15-bit identifier binding shares that belong together.
    pub id: u16,
    /// Extendable backup flag (id excluded from the encryption salt).
    pub ext: bool,
    /// Iteration exponent (PBKDF2 iterations = `2500 << e` per Feistel round).
    pub e: u8,
    /// Group index (x value of the group share), 0-based.
    pub group_index: u8,
    /// Group threshold Gt (actual value, 1-based).
    pub group_threshold: u8,
    /// Group count G (actual value, 1-based).
    pub group_count: u8,
    /// Member index I (x value of the member share), 0-based.
    pub member_index: u8,
    /// Member threshold T of the share's group (actual value).
    pub member_threshold: u8,
    /// Raw share value (`n` bytes, one GF(256) byte per secret byte).
    pub value: Vec<u8>,
}

// ───────────────────────────── GF(256) ─────────────────────────────

/// GF(256) multiplication modulo `x^8+x^4+x^3+x+1` (Rijndael/AES field).
fn gf_mul(a: u8, b: u8) -> u8 {
    let (mut a, mut b, mut p) = (a, b, 0u8);
    for _ in 0..8 {
        if b & 1 == 1 {
            p ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse in GF(256) (`a^254`); `None` for 0.
fn gf_inv(a: u8) -> Option<u8> {
    if a == 0 {
        return None;
    }
    let (mut result, mut base, mut exp) = (1u8, a, 254u16);
    while exp > 0 {
        if exp & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    Some(result)
}

/// Lagrange interpolation of a byte-vector polynomial at `x`.
/// Subtraction in GF(2^m) is XOR; all `x_i` must be distinct.
fn interpolate(x: u8, points: &[(u8, Vec<u8>)]) -> Vec<u8> {
    debug_assert!(!points.is_empty());
    let mut out = vec![0u8; points[0].1.len()];
    for (i, (xi, yi)) in points.iter().enumerate() {
        let (mut num, mut den) = (1u8, 1u8);
        for (j, (xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            num = gf_mul(num, x ^ xj);
            den = gf_mul(den, xi ^ xj);
        }
        let coeff = gf_mul(num, gf_inv(den).expect("distinct interpolation points"));
        for (o, y) in out.iter_mut().zip(yi.iter()) {
            *o ^= gf_mul(coeff, *y);
        }
    }
    out
}

// ─────────────────── HMAC-SHA256 / PBKDF2 (FIPS 210) ───────────────────

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5Cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dk_len + 32);
    let mut block: u32 = 1;
    while out.len() < dk_len {
        let mut salted = salt.to_vec();
        salted.extend_from_slice(&block.to_be_bytes());
        let mut u = hmac_sha256(password, &salted);
        let mut acc = u;
        for _ in 1..iterations {
            u = hmac_sha256(password, &u);
            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        out.extend_from_slice(&acc);
        block += 1;
    }
    out.truncate(dk_len);
    out
}

// ───────────────────────────── RS1024 ─────────────────────────────

fn rs1024_polymod(values: &[u16]) -> u32 {
    const GEN: [u32; 10] = [
        0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009, 0x1c0c2412, 0x38086c24, 0x3090fc48,
        0x21b1f890, 0x3f3f120,
    ];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 20;
        chk = ((chk & 0xFFFFF) << 10) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn rs1024_verify(cs: &str, data: &[u16]) -> bool {
    let mut values: Vec<u16> = cs.bytes().map(u16::from).collect();
    values.extend_from_slice(data);
    rs1024_polymod(&values) == 1
}

fn rs1024_create(cs: &str, data: &[u16]) -> [u16; 3] {
    let mut values: Vec<u16> = cs.bytes().map(u16::from).collect();
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0]);
    let polymod = rs1024_polymod(&values) ^ 1;
    let mut out = [0u16; 3];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = ((polymod >> (10 * (2 - i))) & 1023) as u16;
    }
    out
}

// ───────────────────────── bit-level codec ─────────────────────────

fn push_bits(out: &mut Vec<bool>, value: u32, count: usize) {
    for i in (0..count).rev() {
        out.push((value >> i) & 1 == 1);
    }
}

fn words_to_bits(words: &[u16]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(words.len() * 10);
    for w in words {
        push_bits(&mut bits, u32::from(*w), 10);
    }
    bits
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    debug_assert_eq!(bits.len() % 8, 0);
    let mut out = Vec::with_capacity(bits.len() / 8);
    for chunk in bits.chunks(8) {
        let mut b = 0u8;
        for bit in chunk {
            b = (b << 1) | u8::from(*bit);
        }
        out.push(b);
    }
    out
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for b in bytes {
        push_bits(&mut bits, u32::from(*b), 8);
    }
    bits
}

/// Nearest multiple of 10 that is ≥ `bit_len` (the padded-share-value rule).
fn padded_len(bit_len: usize) -> usize {
    bit_len.div_ceil(10) * 10
}

// ───────────────────────── share encode/decode ─────────────────────────

fn wordlist() -> impl Iterator<Item = &'static str> {
    WORDLIST.lines().filter(|l| !l.is_empty())
}

/// Encodes a share into its mnemonic word sequence.
fn encode_share(share: &Share) -> Result<Vec<String>, Slip39Error> {
    let mut bits: Vec<bool> = Vec::new();
    push_bits(&mut bits, u32::from(share.id), 15);
    push_bits(&mut bits, u32::from(share.ext), 1);
    push_bits(&mut bits, u32::from(share.e), 4);
    push_bits(&mut bits, u32::from(share.group_index), 4);
    push_bits(&mut bits, share.group_threshold as u32 - 1, 4);
    push_bits(&mut bits, share.group_count as u32 - 1, 4);
    push_bits(&mut bits, u32::from(share.member_index), 4);
    push_bits(&mut bits, share.member_threshold as u32 - 1, 4);
    debug_assert_eq!(bits.len(), HEADER_BITS);

    let raw_bits = share.value.len() * 8;
    let pad = padded_len(raw_bits) - raw_bits;
    push_bits(&mut bits, 0, pad); // left padding is all zeros
    bits.extend_from_slice(&bytes_to_bits(&share.value));

    // data part → 10-bit words. Provably unreachable: padded_len()
    // rounds the value up to a multiple of 10, so header(40) + pad +
    // 8v = 40 + 10k is always a multiple of 10.
    debug_assert!(
        bits.len().is_multiple_of(10),
        "padded share value is not a multiple of 10 bits"
    );
    let data_words: Vec<u16> = bits
        .chunks(10)
        .map(|c| c.iter().fold(0u16, |acc, b| (acc << 1) | u16::from(*b)))
        .collect();
    let cs = if share.ext { CS_EXTENDABLE } else { CS_PLAIN };
    let checksum = rs1024_create(cs, &data_words);

    let all: Vec<u16> = data_words
        .iter()
        .copied()
        .chain(checksum)
        .collect::<Vec<u16>>();
    let words = wordlist().collect::<Vec<_>>();
    // Provably total: data words are 10-bit chunks and rs1024_create
    // masks every checksum word with & 1023, while the list holds
    // exactly 1024 entries — the index is in range by construction.
    debug_assert!(all.iter().all(|&w| (w as usize) < words.len()));
    Ok(all.iter().map(|&w| words[w as usize].to_string()).collect())
}

/// Decodes one mnemonic (space-separated words) into a [`Share`], verifying
/// the RS1024 checksum and all padding rules.
pub fn decode_share(mnemonic: &str) -> Result<Share, Slip39Error> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    // The shortest legal share is 20 words (128-bit secret).
    if words.len() < 20 {
        return Err(Slip39Error::ChecksumOrFormat(format!(
            "mnemonic too short: {} words (minimum 20)",
            words.len()
        )));
    }
    let table = wordlist().collect::<Vec<_>>();
    let indices: Vec<u16> = words
        .iter()
        .map(|w| {
            table
                .iter()
                .position(|t| t == w)
                .map(|i| i as u16)
                .ok_or_else(|| Slip39Error::ChecksumOrFormat(format!("unknown word: {w}")))
        })
        .collect::<Result<_, _>>()?;

    // Header layout: id(15) ‖ ext(1) ‖ e(4) … → word0 holds id[14:5], word1
    // holds id[4:0] ‖ ext ‖ e, so ext is bit 4 of the second word.
    let ext = (indices[1] >> 4) & 1 == 1;
    if !rs1024_verify(if ext { CS_EXTENDABLE } else { CS_PLAIN }, &indices) {
        return Err(Slip39Error::ChecksumOrFormat(
            "RS1024 checksum failed".into(),
        ));
    }

    let data_words = &indices[..indices.len() - 3];
    let bits = words_to_bits(data_words);
    // Provably unreachable (the ≥20-word gate above forces data_words ≥
    // 17 → bits ≥ 170 > HEADER_BITS = 40): asserted in dev/test builds
    // instead of an Err arm that can never fire.
    debug_assert!(bits.len() >= HEADER_BITS, "data part too short");

    let mut pos = 0usize;
    let mut field = |n: usize| -> u32 {
        let mut v = 0u32;
        for _ in 0..n {
            v = (v << 1) | u32::from(bits[pos]);
            pos += 1;
        }
        v
    };
    let id = field(15) as u16;
    let ext = field(1) == 1;
    let e = field(4) as u8;
    let group_index = field(4) as u8;
    let group_threshold = field(4) as u8 + 1;
    let group_count = field(4) as u8 + 1;
    let member_index = field(4) as u8;
    let member_threshold = field(4) as u8 + 1;
    debug_assert_eq!(pos, HEADER_BITS);
    let rest = &bits[HEADER_BITS..];
    if group_threshold > group_count {
        return Err(Slip39Error::ChecksumOrFormat(format!(
            "group threshold {group_threshold} exceeds group count {group_count}"
        )));
    }

    // Provably unreachable: rest = bits[40..] and bits = 10·n (10-bit
    // words), so rest.len() = 10n − 40 is always a multiple of 10.
    debug_assert!(
        rest.len().is_multiple_of(10),
        "padded share value is not a multiple of 10 bits"
    );
    // padding length = padded length mod 16 (8·n is a multiple of 16)
    let padding_len = rest.len() % 16;
    if padding_len > 8 {
        return Err(Slip39Error::ChecksumOrFormat(format!(
            "invalid padding: {padding_len} bits (max 8)"
        )));
    }
    // Provably unreachable: with data_words ≥ 17 the minimum of
    // (10n − 40) − (10n − 40) mod 16 is 128 (attained at n = 17, 18),
    // so a decoded share value always spans ≥ 128 bits.
    debug_assert!(
        rest.len() - padding_len >= 128,
        "share value shorter than 128 bits"
    );
    if rest[..padding_len].iter().any(|b| *b) {
        return Err(Slip39Error::ChecksumOrFormat(
            "padding bits are not zero".into(),
        ));
    }
    let value = bits_to_bytes(&rest[padding_len..]);

    Ok(Share {
        id,
        ext,
        e,
        group_index,
        group_threshold,
        group_count,
        member_index,
        member_threshold,
        value,
    })
}

/// Encodes a share back to its mnemonic string (round-trip helper).
pub fn encode_share_mnemonic(share: &Share) -> Result<String, Slip39Error> {
    Ok(encode_share(share)?.join(" "))
}

// ─────────────────── SplitSecret / RecoverSecret ───────────────────

/// Splits `secret` into `n` shares with threshold `t`.
/// Share `i` (1-based) is the polynomial evaluated at `x = i-1`; the secret
/// itself lives at index 255 and its digest at index 254.
fn split_secret(t: u8, n: u8, secret: &[u8]) -> Result<Vec<Vec<u8>>, Slip39Error> {
    let (t, n) = (usize::from(t), usize::from(n));
    if t == 0 || t > n || n > 16 {
        return Err(Slip39Error::Parameters(format!(
            "threshold/members out of range: {t}-of-{n}"
        )));
    }
    if secret.len() < 16 || !secret.len().is_multiple_of(2) {
        return Err(Slip39Error::Parameters(format!(
            "secret must be ≥16 bytes and an even number of bytes (got {})",
            secret.len()
        )));
    }
    if t == 1 {
        return Ok(vec![secret.to_vec(); n]);
    }

    let mut rng = OsRng;
    // Random R + 4-byte HMAC digest → the index-254 point.
    let mut r = vec![0u8; secret.len() - 4];
    rng.fill_bytes(&mut r);
    let tag = &hmac_sha256(&r, secret)[..4];
    let mut digest_point = tag.to_vec();
    digest_point.extend_from_slice(&r);

    // The first T-2 shares are random; the rest are interpolated.
    let mut points: Vec<(u8, Vec<u8>)> = Vec::with_capacity(t);
    let mut shares: Vec<Vec<u8>> = Vec::with_capacity(n);
    for i in 0..(t - 2) {
        let mut y = vec![0u8; secret.len()];
        rng.fill_bytes(&mut y);
        points.push((i as u8, y.clone()));
        shares.push(y);
    }
    points.push((254, digest_point));
    points.push((255, secret.to_vec()));
    for i in (t - 1)..=n {
        shares.push(interpolate((i - 1) as u8, &points));
    }
    Ok(shares)
}

/// Recovers the secret from `t` (index, value) pairs and verifies the
/// index-254 digest. Wrong or fabricated share sets abort here.
fn recover_secret(t: u8, points: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, Slip39Error> {
    if usize::from(t) != points.len() {
        return Err(Slip39Error::Mismatch(format!(
            "need exactly {} shares, got {}",
            t,
            points.len()
        )));
    }
    if t == 1 {
        return Ok(points[0].1.clone());
    }
    let secret = interpolate(255, points);
    let digest_point = interpolate(254, points);
    let (tag, r) = digest_point.split_at(4);
    if hmac_sha256(r, &secret)[..4] != *tag {
        return Err(Slip39Error::Digest);
    }
    Ok(secret)
}

// ─────────────── Feistel encryption of the master secret ───────────────

fn round_function(i: u8, r: &[u8], passphrase: &str, e: u8, id: u16, ext: bool) -> Vec<u8> {
    let mut password = vec![i];
    password.extend_from_slice(passphrase.as_bytes());
    let mut salt = Vec::new();
    if !ext {
        salt.extend_from_slice(b"shamir");
        salt.extend_from_slice(&id.to_be_bytes());
    }
    salt.extend_from_slice(r);
    let iterations = 2500u32 << e;
    pbkdf2_hmac_sha256(&password, &salt, iterations, r.len())
}

/// Encrypts the master secret into the EMS (4-round Feistel, Luby-Rackoff).
fn encrypt_master_secret(ms: &[u8], passphrase: &str, e: u8, id: u16, ext: bool) -> Vec<u8> {
    let half = ms.len() / 2;
    let (mut l, mut r) = (ms[..half].to_vec(), ms[half..].to_vec());
    for i in 0..4u8 {
        let f = round_function(i, &r, passphrase, e, id, ext);
        let new_l = std::mem::take(&mut r);
        let new_r: Vec<u8> = l.iter().zip(f.iter()).map(|(a, b)| a ^ b).collect();
        l = new_l;
        r = new_r;
    }
    let mut out = r;
    out.extend_from_slice(&l);
    out
}

/// Decrypts the EMS back to the master secret (reverse Feistel order).
fn decrypt_master_secret(ems: &[u8], passphrase: &str, e: u8, id: u16, ext: bool) -> Vec<u8> {
    let half = ems.len() / 2;
    let (mut l, mut r) = (ems[..half].to_vec(), ems[half..].to_vec());
    for i in (0..4u8).rev() {
        let f = round_function(i, &r, passphrase, e, id, ext);
        let new_l = std::mem::take(&mut r);
        let new_r: Vec<u8> = l.iter().zip(f.iter()).map(|(a, b)| a ^ b).collect();
        l = new_l;
        r = new_r;
    }
    let mut out = r;
    out.extend_from_slice(&l);
    out
}

// ────────────────────────── public API ──────────────────────────

/// Splits `master_secret` into a two-level SLIP-0039 share set.
///
/// * `group_threshold` — how many *groups* are needed (1 … `groups.len()`)
/// * `groups` — per-group member threshold/count; for a plain k-of-n backup
///   pass a single `GroupSpec::new(k, n)` group
/// * `passphrase` — printable ASCII, encrypts the master secret (empty = "")
/// * `iteration_exponent` — 0 is the interoperable default (10,000 total
///   PBKDF2 iterations per Feistel round pair)
///
/// Returns one `Vec<String>` of mnemonics per group, in group order.
pub fn split(
    master_secret: &[u8],
    group_threshold: u8,
    groups: &[GroupSpec],
    passphrase: &str,
    iteration_exponent: u8,
) -> Result<Vec<Vec<String>>, Slip39Error> {
    let g = groups.len();
    if g == 0 || g > 16 {
        return Err(Slip39Error::Parameters(format!(
            "group count out of range: {g}"
        )));
    }
    if group_threshold == 0 || usize::from(group_threshold) > g {
        return Err(Slip39Error::Parameters(format!(
            "group threshold {group_threshold} invalid for {g} groups"
        )));
    }
    if iteration_exponent > 15 {
        return Err(Slip39Error::Parameters(format!(
            "iteration exponent {iteration_exponent} > 15"
        )));
    }
    for (i, grp) in groups.iter().enumerate() {
        if grp.threshold == 1 && grp.members > 1 {
            return Err(Slip39Error::Parameters(format!(
                "group {i}: threshold 1 requires exactly 1 member"
            )));
        }
        if grp.threshold == 0 || grp.threshold > grp.members || grp.members > 16 {
            return Err(Slip39Error::Parameters(format!(
                "group {i}: invalid {}-of-{}",
                grp.threshold, grp.members
            )));
        }
    }
    if master_secret.len() < 16 || !master_secret.len().is_multiple_of(2) {
        return Err(Slip39Error::Parameters(format!(
            "master secret must be ≥16 bytes and even (got {})",
            master_secret.len()
        )));
    }

    let mut rng = OsRng;
    let id = rng.next_u32() & 0x7FFF;
    let ext = true; // current spec: new shares are extendable
    let e = iteration_exponent;

    let ems = encrypt_master_secret(master_secret, passphrase, e, id as u16, ext);
    let group_shares = split_secret(group_threshold, g as u8, &ems)?;

    let mut out: Vec<Vec<String>> = Vec::with_capacity(g);
    for (gi, grp) in groups.iter().enumerate() {
        let member_shares = split_secret(grp.threshold, grp.members, &group_shares[gi])?;
        let mut mnemonics = Vec::with_capacity(grp.members as usize);
        for (mi, value) in member_shares.iter().enumerate() {
            let share = Share {
                id: id as u16,
                ext,
                e,
                group_index: gi as u8,
                group_threshold,
                group_count: g as u8,
                member_index: mi as u8,
                member_threshold: grp.threshold,
                value: value.clone(),
            };
            mnemonics.push(encode_share(&share)?.join(" "));
        }
        out.push(mnemonics);
    }
    Ok(out)
}

/// Combines a set of mnemonics back into the master secret.
///
/// Validates the RS1024 checksum of every share, cross-share metadata
/// (id/ext/e/Gt/g), per-group thresholds and distinct indices, then runs the
/// two-level recovery and the Feistel decryption. Any failure is an error —
/// never a wrong secret.
pub fn combine(mnemonics: &[&str], passphrase: &str) -> Result<Vec<u8>, Slip39Error> {
    if mnemonics.is_empty() {
        return Err(Slip39Error::Mismatch("no mnemonics supplied".into()));
    }
    let shares: Vec<Share> = mnemonics
        .iter()
        .map(|m| decode_share(m))
        .collect::<Result<_, _>>()?;

    let first = &shares[0];
    for s in &shares[1..] {
        if s.id != first.id {
            return Err(Slip39Error::Mismatch(
                "shares carry different identifiers".into(),
            ));
        }
        if s.ext != first.ext {
            return Err(Slip39Error::Mismatch(
                "shares carry different extendable flags".into(),
            ));
        }
        if s.e != first.e {
            return Err(Slip39Error::Mismatch(
                "shares carry different iteration exponents".into(),
            ));
        }
        if s.group_threshold != first.group_threshold {
            return Err(Slip39Error::Mismatch(
                "shares carry different group thresholds".into(),
            ));
        }
        if s.group_count != first.group_count {
            return Err(Slip39Error::Mismatch(
                "shares carry different group counts".into(),
            ));
        }
        if s.value.len() != first.value.len() {
            return Err(Slip39Error::Mismatch(
                "shares carry different value lengths".into(),
            ));
        }
    }
    // Provably unreachable: every share arrived via decode_share,
    // which refuses group_threshold > group_count per share — so
    // first.group_count ≥ first.group_threshold always holds.
    debug_assert!(
        first.group_count >= first.group_threshold,
        "group count {} < group threshold {}",
        first.group_count,
        first.group_threshold
    );

    // Group shares by index; every supplied group must be complete.
    let mut groups: Vec<(u8, Vec<&Share>)> = Vec::new();
    for s in &shares {
        match groups.iter_mut().find(|(gi, _)| *gi == s.group_index) {
            Some((_, list)) => list.push(s),
            None => groups.push((s.group_index, vec![s])),
        }
    }
    if groups.len() != usize::from(first.group_threshold) {
        return Err(Slip39Error::Mismatch(format!(
            "need {} distinct groups, got {}",
            first.group_threshold,
            groups.len()
        )));
    }

    let mut group_points: Vec<(u8, Vec<u8>)> = Vec::with_capacity(groups.len());
    for (_, list) in &groups {
        let t = list[0].member_threshold;
        if list.iter().any(|s| s.member_threshold != t) {
            return Err(Slip39Error::Mismatch(
                "mismatching member thresholds inside one group".into(),
            ));
        }
        if list.len() != usize::from(t) {
            return Err(Slip39Error::Mismatch(format!(
                "group {} has {} shares, threshold is {t}",
                list[0].group_index,
                list.len()
            )));
        }
        let mut seen: Vec<u8> = Vec::new();
        for s in list {
            if seen.contains(&s.member_index) {
                return Err(Slip39Error::Mismatch(format!(
                    "duplicate member index {}",
                    s.member_index
                )));
            }
            seen.push(s.member_index);
        }
        let points: Vec<(u8, Vec<u8>)> = list
            .iter()
            .map(|s| (s.member_index, s.value.clone()))
            .collect();
        let group_share = recover_secret(t, &points)?;
        group_points.push((list[0].group_index, group_share));
    }
    group_points.sort_by_key(|(gi, _)| *gi);

    let ems = recover_secret(first.group_threshold, &group_points)?;
    // Provably unreachable: interpolation (and the t == 1 shortcut)
    // preserve the value length, every share value was already checked
    // equal to first.value.len() above, so the recovered EMS matches.
    debug_assert!(
        ems.len() == first.value.len(),
        "recovered EMS length differs from share length"
    );
    let ms = decrypt_master_secret(&ems, passphrase, first.e, first.id, first.ext);
    // Provably unreachable: Feistel decryption preserves the EMS
    // length, which equals first.value.len() — a decoded value spans
    // ≥ 128 bits and a whole number of 16-bit units (proof above).
    debug_assert!(
        ms.len() >= 16 && ms.len().is_multiple_of(2),
        "decrypted master secret has an illegal length"
    );
    Ok(ms)
}

/// Number of words a share mnemonic carries for a given master-secret size.
pub fn mnemonic_word_count(master_secret_len: usize) -> usize {
    (HEADER_BITS + padded_len(master_secret_len * 8) + 30) / 10
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The official test vector set (quadruple: description, mnemonics, MS,
    /// xprv). Loaded at compile time; `ms == ""` means "must fail".
    const VECTORS: &str = include_str!("../tests/slip39_vectors.json");

    /// Minimal JSON reader for the vector file (avoids a runtime dep in
    /// shipping code): each entry is `[string, [strings], string, string]`.
    fn vectors() -> Vec<(String, Vec<String>, String)> {
        let raw: Vec<serde_json::Value> = serde_json::from_str(VECTORS).expect("valid JSON");
        raw.into_iter()
            .map(|v| {
                let arr = v.as_array().expect("vector is an array");
                let desc = arr[0].as_str().unwrap_or_default().to_string();
                let mnem = arr[1]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|m| m.as_str().unwrap().to_string())
                    .collect();
                let ms = arr[2].as_str().unwrap_or_default().to_string();
                (desc, mnem, ms)
            })
            .collect()
    }

    #[test]
    fn all_official_vectors_pass() {
        let mut ok = 0;
        let mut rejected = 0;
        for (desc, mnem, ms) in vectors() {
            let refs: Vec<&str> = mnem.iter().map(|s| s.as_str()).collect();
            let got = combine(&refs, "TREZOR");
            if ms.is_empty() {
                // Hoisted out of the assert so the formatting value is
                // computed on EVERY vector (assert! args are lazy).
                let shown = format!("{:?}", got.as_ref().map(hex::encode));
                assert!(
                    got.is_err(),
                    "vector `{desc}` must fail but succeeded: {shown}"
                );
                rejected += 1;
            } else {
                let got = got.unwrap_or_else(|e| panic!("vector `{desc}` failed: {e}"));
                assert_eq!(
                    hex::encode(&got),
                    ms,
                    "vector `{desc}` produced the wrong master secret"
                );
                ok += 1;
            }
        }
        assert_eq!(ok + rejected, 45, "all official vectors are exercised");
        assert!(ok > 10 && rejected > 20, "both classes are covered");
    }

    #[test]
    fn roundtrip_single_group_2_of_3() {
        let ms: Vec<u8> = (0u8..32).collect();
        let groups = [GroupSpec::new(2, 3)];
        let out = split(&ms, 1, &groups, "", 0).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].len(), 3);
        assert_eq!(out[0][0].split_whitespace().count(), 33);

        // Any 2 of 3 recover the secret.
        for drop in 0..3 {
            let picked: Vec<&str> = out[0]
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != drop)
                .map(|(_, m)| m.as_str())
                .collect();
            assert_eq!(combine(&picked, "").unwrap(), ms, "drop {drop}");
        }
        // A single share never does.
        assert!(combine(&[out[0][0].as_str()], "").is_err());
        // The wrong passphrase yields *something* only by design — but a
        // tampered mnemonic must fail the checksum.
        let mut words: Vec<String> = out[0][1]
            .split_whitespace()
            .map(|w| w.to_string())
            .collect();
        let table: Vec<&str> = WORDLIST.lines().collect();
        // Both replacement arms must run deterministically: the original
        // single if depended on the random share id (flaky coverage).
        let orig10 = words[10].clone();
        // BOTH branches of BOTH replacement expressions must run — each
        // textual `if` sits on its own lines, so each is evaluated twice:
        // condition TRUE (word == table[0]) and FALSE (word == table[1]).
        // The old single-shot version flipped only one arm per expression.
        // Each guard is evaluated with BOTH truth values: the tampered
        // text (body runs) and the ORIGINAL text (body skipped) — a guard
        // whose false path never executes is a coverage hole that hides a
        // silently-skipped assertion.
        for seed in [table[0].to_string(), table[1].to_string()] {
            words[10] = seed;
            words[10] = if table[0] == words[10] {
                table[1].to_string() // arm taken when the tamper hit table[1]
            } else {
                table[0].to_string() // arm taken when the tamper hit table[0]
            };
            let tampered = words[10].clone();
            for candidate in [tampered, orig10.clone()] {
                words[10] = candidate;
                if words[10] != orig10 {
                    assert!(combine(&[out[0][0].as_str(), &words.join(" ")], "").is_err());
                }
            }
        }
        for seed in [table[0].to_string(), table[1].to_string()] {
            words[10] = seed;
            words[10] = if table[0] == words[10] {
                table[1].to_string()
            } else {
                table[0].to_string()
            };
            let tampered = words[10].clone();
            for candidate in [tampered, orig10.clone()] {
                words[10] = candidate;
                if words[10] != orig10 {
                    assert!(combine(&[out[0][0].as_str(), &words.join(" ")], "").is_err());
                }
            }
        }
    }

    /// Every Display arm renders its own prefix; Error::source is always
    /// None (the enum chains no causes).
    #[test]
    fn display_covers_every_error_variant() {
        let cases = [
            (
                Slip39Error::ChecksumOrFormat("fmt".into()),
                "mnemonic format/checksum: fmt",
            ),
            (
                Slip39Error::Mismatch("mix".into()),
                "share set mismatch: mix",
            ),
            (
                Slip39Error::Digest,
                "share digest mismatch (wrong or fabricated share set — fail-closed)",
            ),
            (
                Slip39Error::Parameters("par".into()),
                "invalid parameters: par",
            ),
        ];
        for (e, want) in cases {
            assert_eq!(e.to_string(), want);
            assert!(std::error::Error::source(&e).is_none());
        }
    }

    /// Private primitive branches: gf_inv(0) is the only None (and
    /// every nonzero element inverts), and an HMAC key longer than the
    /// 64-byte block is hashed down first (RFC 2104 — identical to
    /// pre-hashing the key).
    #[test]
    fn gf_inv_zero_and_long_hmac_key() {
        assert_eq!(gf_inv(0), None);
        for a in 1..=255u8 {
            let inv = gf_inv(a).expect("every nonzero element inverts");
            assert_eq!(gf_mul(a, inv), 1, "a · a⁻¹ == 1 for {a}");
        }
        let long = [0xABu8; 65];
        let prehashed = Sha256::digest(long);
        assert_eq!(
            hmac_sha256(&long, b"payload"),
            hmac_sha256(&prehashed, b"payload"),
            "|k| > 64 must equal hashing k down first"
        );
    }

    /// split_secret's parameter walls and the 1-of-n shortcut, driven
    /// directly (split() pre-validates, so only unit tests reach them).
    #[test]
    fn split_secret_guards_and_single_threshold() {
        let s = [7u8; 16];
        assert!(matches!(
            split_secret(0, 3, &s),
            Err(Slip39Error::Parameters(_))
        ));
        assert!(matches!(
            split_secret(4, 3, &s),
            Err(Slip39Error::Parameters(_))
        ));
        assert!(matches!(
            split_secret(2, 17, &s),
            Err(Slip39Error::Parameters(_))
        ));
        assert!(matches!(
            split_secret(2, 3, &[0u8; 15]),
            Err(Slip39Error::Parameters(_))
        ));
        assert!(matches!(
            split_secret(2, 3, &[0u8; 17]),
            Err(Slip39Error::Parameters(_))
        ));
        // t == 1: every share IS the secret — no randomness involved.
        let ones = split_secret(1, 3, &s).unwrap();
        assert_eq!(ones, vec![s.to_vec(); 3]);
    }

    /// recover_secret's count wall, the t == 1 shortcut and the
    /// index-254 digest gate (fabricated shares fail closed).
    #[test]
    fn recover_secret_count_t1_and_digest_gates() {
        let pts = vec![(1u8, vec![9u8; 16]), (2, vec![8u8; 16])];
        let e = recover_secret(3, &pts).unwrap_err();
        assert!(
            e.to_string().contains("need exactly 3 shares, got 2"),
            "{e}"
        );
        let one = recover_secret(1, &[(42u8, vec![5u8; 16])]).unwrap();
        assert_eq!(one, vec![5u8; 16]);
        // Consistent-looking zeros interpolate to *a* secret and *a*
        // digest point — yet the HMAC tag disagrees → Digest error.
        let bad = recover_secret(2, &[(1u8, vec![0u8; 16]), (2, vec![0u8; 16])]);
        assert!(matches!(bad, Err(Slip39Error::Digest)), "{bad:?}");
    }

    /// split()'s group-count wall (driven directly with an empty or
    /// oversized group list) and the iteration-exponent wall.
    #[test]
    fn split_group_walls() {
        let ms = [1u8; 32];
        let e = split(&ms, 1, &[], "", 0).unwrap_err();
        assert!(e.to_string().contains("group count out of range: 0"), "{e}");
        let many = vec![GroupSpec::new(2, 3); 17];
        let e = split(&ms, 1, &many, "", 0).unwrap_err();
        assert!(
            e.to_string().contains("group count out of range: 17"),
            "{e}"
        );
        let e = split(&ms, 1, &[GroupSpec::new(2, 3)], "", 16).unwrap_err();
        assert!(e.to_string().contains("iteration exponent 16"), "{e}");
    }

    /// combine()'s input walls: empty set, extendable-flag mismatch and
    /// value-length mismatch — crafted through encode_share so the
    /// RS1024 checksums stay valid while the metadata differs.
    #[test]
    fn combine_input_walls() {
        let e = combine(&[], "").unwrap_err();
        assert!(e.to_string().contains("no mnemonics supplied"), "{e}");

        let ms = [4u8; 32];
        let out = split(&ms, 1, &[GroupSpec::new(2, 3)], "", 0).unwrap();
        let a = decode_share(&out[0][0]).unwrap();
        let b = decode_share(&out[0][1]).unwrap();
        let enc = |s: &Share| encode_share(s).unwrap().join(" ");

        // Extendable-flag mismatch (checked right after the id row).
        let mut b_ext = b.clone();
        b_ext.ext = !b_ext.ext;
        let (m0, m1) = (enc(&a), enc(&b_ext));
        let e = combine(&[m0.as_str(), m1.as_str()], "").unwrap_err();
        assert!(e.to_string().contains("different extendable flags"), "{e}");

        // Value-length mismatch: truncate b's value (encode recomputes
        // the checksum, so decode_accepts the share itself).
        let mut b_val = b.clone();
        b_val.value.truncate(16);
        let (m0, m1) = (enc(&a), enc(&b_val));
        let e = combine(&[m0.as_str(), m1.as_str()], "").unwrap_err();
        assert!(e.to_string().contains("different value lengths"), "{e}");
    }

    /// decode_share refuses a ≥20-word mnemonic carrying a word that is
    /// not on the list — before any checksum arithmetic runs.
    #[test]
    fn decode_unknown_word_refused() {
        let ms = [1u8; 16];
        let out = split(&ms, 1, &[GroupSpec::new(2, 3)], "", 0).unwrap();
        let mut words: Vec<String> = out[0][0].split_whitespace().map(String::from).collect();
        words[15] = "zzzz-not-a-slip39-word-zzzz".to_string();
        let e = decode_share(&words.join(" ")).unwrap_err();
        assert!(
            e.to_string()
                .contains("unknown word: zzzz-not-a-slip39-word-zzzz"),
            "{e}"
        );
    }

    #[test]
    fn two_level_group_threshold() {
        let ms = [7u8; 16];
        // GT=2 of G=3 groups: A(1-of-1), B(2-of-3), C(2-of-2)
        let groups = [
            GroupSpec::new(1, 1),
            GroupSpec::new(2, 3),
            GroupSpec::new(2, 2),
        ];
        let out = split(&ms, 2, &groups, "", 0).unwrap();
        assert_eq!(out.len(), 3);

        // group0 alone is not enough (GT=2), but group0 + group1 is.
        let set_a = [out[0][0].as_str(), out[1][0].as_str(), out[1][1].as_str()];
        assert_eq!(combine(&set_a, "").unwrap(), ms.to_vec());
        // groups 1 + 2 (any complete pair)
        let set_b = [
            out[1][1].as_str(),
            out[1][2].as_str(),
            out[2][0].as_str(),
            out[2][1].as_str(),
        ];
        assert_eq!(combine(&set_b, "").unwrap(), ms.to_vec());
        // incomplete group → fail-closed
        assert!(combine(&[out[1][0].as_str(), out[2][0].as_str()], "").is_err());
    }

    #[test]
    fn passphrase_binds_the_secret() {
        let ms = [9u8; 32];
        let out = split(&ms, 1, &[GroupSpec::new(2, 3)], "correct horse", 0).unwrap();
        assert_eq!(
            combine(&[out[0][0].as_str(), out[0][1].as_str()], "correct horse").unwrap(),
            ms
        );
        // A wrong passphrase produces a different (garbage) secret — there is
        // no way to verify it by design (plausible deniability), so this
        // asserts the *decryption actually differs*, not that it errors.
        let wrong = combine(&[out[0][0].as_str(), out[0][1].as_str()], "wrong").unwrap();
        assert_ne!(wrong, ms);
    }

    #[test]
    fn invalid_parameters_fail_closed() {
        let ms = [1u8; 32];
        assert!(split(&ms, 1, &[GroupSpec::new(3, 2)], "", 0).is_err());
        assert!(split(&ms, 1, &[GroupSpec::new(1, 5)], "", 0).is_err());
        assert!(split(&ms, 2, &[GroupSpec::new(2, 3)], "", 0).is_err());
        assert!(split(&[1u8; 15], 1, &[GroupSpec::new(2, 3)], "", 0).is_err());
        assert!(split(&[1u8; 17], 1, &[GroupSpec::new(2, 3)], "", 0).is_err());
    }

    #[test]
    fn share_encode_decode_roundtrip() {
        let ms = [0xA5u8; 32];
        let out = split(&ms, 1, &[GroupSpec::new(2, 3)], "", 0).unwrap();
        for m in &out[0] {
            let s = decode_share(m).unwrap();
            assert_eq!(encode_share_mnemonic(&s).unwrap(), *m);
            assert_eq!(s.value.len(), 32);
            assert_eq!(s.group_count, 1);
            assert_eq!(s.member_threshold, 2);
        }
        // 20 words for a 16-byte secret.
        let out16 = split(&[3u8; 16], 1, &[GroupSpec::new(2, 3)], "", 0).unwrap();
        assert_eq!(out16[0][0].split_whitespace().count(), 20);
        assert_eq!(mnemonic_word_count(16), 20);
        assert_eq!(mnemonic_word_count(32), 33);
    }
}
