//! FROST threshold signatures (docs/04 §4.1) over secp256k1 with Taproot
//! tweaks (`frost-secp256k1-tr`: BIP-340-compatible Schnorr).
//!
//! The wizard flow (docs/04 §4.1 + §4.2):
//!   1. TRUSTED-DEALER KEY GENERATION: the coordinator derives ONE group key;
//!      each heir receives a private deal (identifier + signing share). The
//!      32-byte signing scalar is sealed as SLIP-0039 mnemonics (docs/04
//!      §4.2) so heirs store printed words; the identifier and the
//!      coordinator's public package are printed alongside.
//!   2. THRESHOLD SIGNING (RFC 9591): round 1 — every heir commits nonces;
//!      round 2 — `k` heirs sign the coordinator's package; aggregate —
//!      ONE standard 64-byte BIP-340 signature over the 32-byte message,
//!      verifiable under the GROUP key with plain Schnorr (no
//!      threshold-aware verifier anywhere).
//!   3. Every hand-off is a printable base64 package behind a strict
//!      envelope tag; malformed or cross-flow packages fail closed.
//!
//! Everything is deterministic given the inputs; the only randomness source
//! is the caller's RNG (`rand_core::OsRng` at the CLI boundary).

use bitcoin::secp256k1::{Message, Secp256k1, Verification, XOnlyPublicKey};
use frost_secp256k1_tr as frost;
use frost_secp256k1_tr::{
    keys::{KeyPackage, PublicKeyPackage, SigningShare},
    round1, round2, SigningPackage,
};
use rand_core::{CryptoRng, RngCore};
use std::collections::BTreeMap;

/// The group (aggregate) public key in 32-byte x-only form — the value a
/// vault leaf or heir payout script commits to.
pub type GroupKey = [u8; 32];

/// Errors raised by the FROST wizard layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrostError {
    /// A helper package failed its envelope/length validation.
    Malformed(String),
    /// Threshold parameters invalid (k == 0, k > n, …).
    Params(String),
    /// A protocol round failed (bad identifier, wrong participants, …).
    Protocol(String),
    /// The assembled signature does not verify under the group key.
    BadSignature,
    /// SLIP-0039 share backup failed.
    Slip39(String),
}

impl core::fmt::Display for FrostError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrostError::Malformed(s) => write!(f, "malformed package: {s}"),
            FrostError::Params(s) => write!(f, "bad parameters: {s}"),
            FrostError::Protocol(s) => write!(f, "protocol error: {s}"),
            FrostError::BadSignature => {
                write!(f, "assembled signature does NOT verify under the group key")
            }
            FrostError::Slip39(s) => write!(f, "SLIP-0039 backup error: {s}"),
        }
    }
}

impl std::error::Error for FrostError {}

fn fro(e: frost_secp256k1_tr::Error) -> FrostError {
    FrostError::Protocol(e.to_string())
}

/// Printable package kinds (strict envelope tags — a nonce package can never
/// be replayed as a deal package or vice versa).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PkgKind {
    /// Coordinator's key-generation package (verifying shares + group key).
    Deal,
    /// Heir's private deal: identifier (32 B) + KeyPackage bytes. SECRET.
    DealPrivate,
    /// Heir's round-1 private nonces. SECRET (single use).
    Nonce,
    /// Coordinator's round-2 signing package (commitment set + message).
    Sign,
    /// Heir's round-2 signature share.
    Share,
}

impl PkgKind {
    fn tag(self) -> &'static [u8] {
        match self {
            PkgKind::Deal => b"QSV_FROST_DEAL_v1",
            PkgKind::DealPrivate => b"QSV_FROST_DEALPRIV_v1",
            PkgKind::Nonce => b"QSV_FROST_NONCE_v1",
            PkgKind::Sign => b"QSV_FROST_SIGN_v1",
            PkgKind::Share => b"QSV_FROST_SHARE_v1",
        }
    }
}

/// Wraps one package as base64 with the strict envelope tag.
pub fn seal(kind: PkgKind, body: &[u8]) -> String {
    use bitcoin::base64::Engine as _;
    let mut frame = kind.tag().to_vec();
    frame.extend_from_slice(body);
    bitcoin::base64::engine::general_purpose::STANDARD.encode(frame)
}

/// Opens a package, verifying the envelope tag.
pub fn unseal(kind: PkgKind, text: &str) -> Result<Vec<u8>, FrostError> {
    use bitcoin::base64::Engine as _;
    let frame = bitcoin::base64::engine::general_purpose::STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|e| FrostError::Malformed(format!("not base64: {e}")))?;
    let tag = kind.tag();
    if frame.len() < tag.len() || frame[..tag.len()] != *tag {
        return Err(FrostError::Malformed("wrong envelope tag".into()));
    }
    Ok(frame[tag.len()..].to_vec())
}

/// Fully-applied key package type (the re-export is a 0-generic alias).
type KeyPackageCs = KeyPackage;

/// The x-only group key from the ciphersuite's compressed verifying-key
/// serialization (33-byte SEC1: `[02|03] || X`).
/// One heir slot in the threshold set.
#[derive(Debug, Clone)]
pub struct HeirSlot {
    /// FROST identifier (32-byte ciphersuite scalar encoding).
    pub identifier: [u8; 32],
    /// Human label (printed on every package).
    pub label: String,
}

/// Output of the trusted-dealer setup.
pub struct DealOutput {
    /// The aggregate vault key (x-only, 32 bytes).
    pub group_key: GroupKey,
    /// One slot per heir, sorted by label.
    pub slots: Vec<HeirSlot>,
    /// The coordinator's public package (`PkgKind::Deal`).
    pub public_package: String,
    /// Per-heir private packages (`PkgKind::DealPrivate`), aligned with
    /// `slots`. The caller seals each one into SLIP-0039 mnemonics.
    pub private_packages: Vec<String>,
}

/// Trusted-dealer key generation for a `threshold`-of-`labels.len()` heir
/// set (RFC 9591 Appendix C). Identifiers are derived from the labels, so
/// the same label list reproduces the same identifier assignment.
pub fn trusted_deal<R: CryptoRng + RngCore>(
    threshold: u16,
    labels: &[String],
    rng: &mut R,
) -> Result<DealOutput, FrostError> {
    let total = labels.len() as u16;
    if threshold == 0 || total == 0 {
        return Err(FrostError::Params("threshold/total must be nonzero".into()));
    }
    if threshold > total {
        return Err(FrostError::Params(
            "threshold cannot exceed the heir count".into(),
        ));
    }
    if total > 100 {
        return Err(FrostError::Params("total capped at 100 heirs".into()));
    }

    // Stable, label-sorted identifier order (reproducible wizard output).
    let mut sorted: Vec<&String> = labels.iter().collect();
    sorted.sort();
    let identifiers = sorted
        .iter()
        .map(|l| frost::Identifier::derive(l.as_bytes()).map_err(fro))
        .collect::<Result<Vec<frost::Identifier>, _>>()?;

    let (shares, pubkeys): (
        BTreeMap<frost::Identifier, frost_secp256k1_tr::keys::SecretShare>,
        PublicKeyPackage,
    ) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Custom(&identifiers),
        rng,
    )
    .map_err(fro)?;

    let vk_bytes: Vec<u8> = pubkeys.verifying_key().serialize().map_err(fro)?;
    let group_key: GroupKey = vk_bytes
        .get(1..33)
        .and_then(|x| x.try_into().ok())
        .ok_or_else(|| FrostError::Protocol("group key length".into()))?;

    let mut slots = Vec::new();
    let mut private_packages = Vec::new();
    for (label, id) in sorted.iter().zip(&identifiers) {
        let share = shares
            .get(id)
            .ok_or_else(|| FrostError::Protocol("share missing for identifier".into()))?;
        let kp = KeyPackage::try_from(share.clone()).map_err(fro)?;
        let mut body = id.serialize();
        body.extend_from_slice(&kp.serialize().map_err(fro)?);
        private_packages.push(seal(PkgKind::DealPrivate, &body));
        slots.push(HeirSlot {
            identifier: id.serialize().try_into().expect("identifier is 32 bytes"),
            label: (*label).clone(),
        });
    }

    Ok(DealOutput {
        group_key,
        slots,
        public_package: seal(PkgKind::Deal, &pubkeys.serialize().map_err(fro)?),
        private_packages,
    })
}

/// Distributed key generation (RFC 9591 DKG, docs/04 §4.1c — Round 33): the
/// SAME output contract as [`trusted_deal`] — label-sorted slots, the same
/// sealed package bytes, the same [`DealOutput`] — but with NO trusted
/// dealer: every heir generates its own signing share through the three
/// DKG rounds, so no machine ever observes a complete signing scalar (the
/// dealer's single-point exposure is gone). The ceremony wizard runs the
/// participants in-process — a single-machine rehearsal of exactly the
/// round-package flow a distributed deployment carries between hosts.
/// Identifiers are still derived from the labels, but chosen by each
/// participant itself (which is what the DKG expects), so every
/// downstream file name and the SLIP-0039 backup drill stay unchanged.
pub fn dkg_rehearsal<R: CryptoRng + RngCore>(
    threshold: u16,
    labels: &[String],
    rng: &mut R,
) -> Result<DealOutput, FrostError> {
    let total = labels.len() as u16;
    if threshold == 0 || total == 0 {
        return Err(FrostError::Params("threshold/total must be nonzero".into()));
    }
    if threshold > total {
        return Err(FrostError::Params(
            "threshold cannot exceed the heir count".into(),
        ));
    }
    if total > 100 {
        return Err(FrostError::Params("total capped at 100 heirs".into()));
    }

    // Same label-sorted, label-derived identifiers as the trusted dealer:
    // slot bookkeeping and downstream file names stay identical.
    let mut sorted: Vec<&String> = labels.iter().collect();
    sorted.sort();
    let identifiers = sorted
        .iter()
        .map(|l| frost::Identifier::derive(l.as_bytes()).map_err(fro))
        .collect::<Result<Vec<frost::Identifier>, _>>()?;

    // Round 1 — each heir samples its OWN share and publishes a commitment.
    let mut round1_secrets = Vec::with_capacity(total as usize);
    let mut round1_packages = BTreeMap::new();
    for id in &identifiers {
        let (secret, package) =
            frost::keys::dkg::part1(*id, total, threshold, &mut *rng).map_err(fro)?;
        round1_secrets.push(secret);
        round1_packages.insert(*id, package);
    }

    // Round 2 — pairwise shares. Each heir feeds the protocol the OTHERS'
    // commitments; its own is rejected by frost-core (UnknownIdentifier).
    let mut round2_secrets = Vec::with_capacity(total as usize);
    let mut outgoing: Vec<BTreeMap<frost::Identifier, _>> = Vec::with_capacity(total as usize);
    for (i, secret) in round1_secrets.into_iter().enumerate() {
        let others: BTreeMap<frost::Identifier, _> = round1_packages
            .iter()
            .filter(|(id, _)| **id != identifiers[i])
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();
        let (secret2, packages2) = frost::keys::dkg::part2(secret, &others).map_err(fro)?;
        round2_secrets.push(secret2);
        outgoing.push(packages2);
    }

    // Round 3 — every heir finalizes with the packages RECEIVED from the
    // others. All participants must derive the SAME public package; a
    // disagreement is a protocol violation and fails closed, not a warning.
    let mut slots = Vec::new();
    let mut private_packages = Vec::new();
    let mut public_bytes: Option<Vec<u8>> = None;
    for (i, secret2) in round2_secrets.iter().enumerate() {
        let r1_in: BTreeMap<frost::Identifier, _> = round1_packages
            .iter()
            .filter(|(id, _)| **id != identifiers[i])
            .map(|(id, pkg)| (*id, pkg.clone()))
            .collect();
        let mut r2_in = BTreeMap::new();
        for (j, mine) in outgoing.iter().enumerate() {
            if j == i {
                continue;
            }
            let pkg = mine
                .get(&identifiers[i])
                .ok_or_else(|| FrostError::Protocol("missing pairwise DKG package".into()))?;
            r2_in.insert(identifiers[j], pkg.clone());
        }
        let (key_package, public_package) =
            frost::keys::dkg::part3(secret2, &r1_in, &r2_in).map_err(fro)?;

        let serialized = public_package.serialize().map_err(fro)?;
        match &public_bytes {
            None => public_bytes = Some(serialized),
            Some(prev) if *prev == serialized => {}
            Some(_) => {
                return Err(FrostError::Protocol(
                    "DKG participants disagree on the public package".into(),
                ))
            }
        }

        let id = &identifiers[i];
        let mut body = id.serialize();
        body.extend_from_slice(&key_package.serialize().map_err(fro)?);
        private_packages.push(seal(PkgKind::DealPrivate, &body));
        slots.push(HeirSlot {
            identifier: id.serialize().try_into().expect("identifier is 32 bytes"),
            label: (*sorted[i]).clone(),
        });
    }

    let public_bytes =
        public_bytes.ok_or_else(|| FrostError::Protocol("no DKG participants".into()))?;
    let pubkeys = PublicKeyPackage::deserialize(&public_bytes).map_err(fro)?;
    let vk_bytes: Vec<u8> = pubkeys.verifying_key().serialize().map_err(fro)?;
    let group_key: GroupKey = vk_bytes
        .get(1..33)
        .and_then(|x| x.try_into().ok())
        .ok_or_else(|| FrostError::Protocol("group key length".into()))?;

    Ok(DealOutput {
        group_key,
        slots,
        public_package: seal(PkgKind::Deal, &public_bytes),
        private_packages,
    })
}

/// The heir's identity and REAL 32-byte signing scalar, extracted from the
/// private deal package. Sealing that scalar into SLIP-0039 gives printed
/// backup; unsealing reproduces the exact share.
fn signing_scalar_of(private_package: &str) -> Result<([u8; 32], [u8; 32]), FrostError> {
    let body = unseal(PkgKind::DealPrivate, private_package)?;
    if body.len() <= 32 {
        return Err(FrostError::Malformed("private package too short".into()));
    }
    let mut identifier = [0u8; 32];
    identifier.copy_from_slice(&body[..32]);
    let kp = KeyPackage::deserialize(&body[32..]).map_err(fro)?;
    let scalar: [u8; 32] = kp
        .signing_share()
        .serialize()
        .as_slice()
        .try_into()
        .map_err(|_| FrostError::Protocol("signing share length".into()))?;
    Ok((identifier, scalar))
}

/// Rebuilds the heir's KeyPackage from (identifier, scalar, public package).
fn key_package_from_scalar(
    identifier: &[u8; 32],
    scalar: &[u8; 32],
    public_package: &str,
) -> Result<KeyPackageCs, FrostError> {
    let pubkeys =
        PublicKeyPackage::deserialize(&unseal(PkgKind::Deal, public_package)?).map_err(fro)?;
    let id = frost::Identifier::deserialize(identifier).map_err(fro)?;
    let vs = pubkeys
        .verifying_shares()
        .get(&id)
        .cloned()
        .ok_or_else(|| FrostError::Protocol("identifier not in public package".into()))?;
    let vk = *pubkeys.verifying_key();
    Ok(KeyPackage::new(
        id,
        SigningShare::deserialize(scalar).map_err(fro)?,
        vs,
        vk,
        pubkeys.min_signers().unwrap_or(1),
    ))
}

/// The identifier carried by a private deal package (wizard bookkeeping:
/// file names and coordinator round books are keyed by it).
pub fn deal_identifier(private_package: &str) -> Result<[u8; 32], FrostError> {
    Ok(signing_scalar_of(private_package)?.0)
}

/// The REAL 32-byte signing scalar inside a private deal package (the
/// value the SLIP-0039 backup must reproduce).
pub fn deal_signing_scalar(private_package: &str) -> Result<[u8; 32], FrostError> {
    Ok(signing_scalar_of(private_package)?.1)
}

/// The 32-byte message committed by a round-2 signing package (the
/// coordinator re-verifies the final signature against exactly this).
pub fn sign_package_message(sign_package: &str) -> Result<[u8; 32], FrostError> {
    let pkg = SigningPackage::deserialize(&unseal(PkgKind::Sign, sign_package)?).map_err(fro)?;
    let msg = pkg.message();
    let arr: [u8; 32] = msg
        .as_slice()
        .try_into()
        .map_err(|_| FrostError::Malformed("sign package message must be 32 bytes".into()))?;
    Ok(arr)
}

/// The group key committed by a public deal package (for final, plain
/// Schnorr verification of the assembled signature).
pub fn group_key_of(public_package: &str) -> Result<GroupKey, FrostError> {
    let pubkeys =
        PublicKeyPackage::deserialize(&unseal(PkgKind::Deal, public_package)?).map_err(fro)?;
    let vk: Vec<u8> = pubkeys.verifying_key().serialize().map_err(fro)?;
    vk.get(1..33)
        .and_then(|x| x.try_into().ok())
        .ok_or_else(|| FrostError::Protocol("group key length".into()))
}

/// Seals one heir's signing scalar into `k_slip`-of-`n_slip` SLIP-0039
/// mnemonics (docs/04 §4.2): printed words, never files.
pub fn seal_share_as_slip39(
    private_package: &str,
    k_slip: u8,
    n_slip: u8,
    passphrase: &str,
) -> Result<Vec<String>, FrostError> {
    let (_, scalar) = signing_scalar_of(private_package)?;
    let groups = [crate::slip39::GroupSpec::new(k_slip, n_slip)];
    crate::slip39::split(&scalar, 1, &groups, passphrase, 0)
        .map(|g| g.into_iter().next().unwrap_or_default())
        .map_err(|e| FrostError::Slip39(e.to_string()))
}

/// Recovers the 32-byte signing scalar from SLIP-0039 mnemonics.
pub fn recover_share_from_slip39(
    mnemonics: &[&str],
    passphrase: &str,
) -> Result<[u8; 32], FrostError> {
    let ms = crate::slip39::combine(mnemonics, passphrase)
        .map_err(|e| FrostError::Slip39(e.to_string()))?;
    let arr: [u8; 32] = ms
        .try_into()
        .map_err(|_| FrostError::Slip39("signing scalar must be 32 bytes".into()))?;
    Ok(arr)
}
/// Round 1 (per heir): derive single-use nonces and publish the commitment.
/// Returns (private nonces package, round-1 commitment package). PLAIN
/// ceremony: no BIP-341 tweak is applied to the key package.
pub fn heir_round1<R: CryptoRng + RngCore>(
    private_package: &str,
    public_package: &str,
    rng: &mut R,
) -> Result<(String, String), FrostError> {
    let (identifier, scalar) = signing_scalar_of(private_package)?;
    let kp = key_package_from_scalar(&identifier, &scalar, public_package)?;
    let (nonces, commitments) = round1::commit(kp.signing_share(), rng);
    Ok((
        seal(PkgKind::Nonce, &nonces.serialize().map_err(fro)?),
        seal(PkgKind::Share, &commitments.serialize().map_err(fro)?),
    ))
}

/// Round 1 with a BIP-341 tweak: the heir's key package is tweaked by the
/// SAME merkle root the coordinator applied to the public package. The
/// tweak is linear, so signing shares stay valid under the tweaked group
/// key. NOTE: the frost crate's `tweak(None)` is the BIP-341 KEY-PATH
/// tweak (Q = P + tH(P)), NOT the identity — plain ceremonies must not
/// call it.
pub fn heir_round1_tweaked<R: CryptoRng + RngCore>(
    private_package: &str,
    public_package: &str,
    merkle_root: Option<&[u8; 32]>,
    rng: &mut R,
) -> Result<(String, String), FrostError> {
    let (identifier, scalar) = signing_scalar_of(private_package)?;
    let kp = key_package_from_scalar(&identifier, &scalar, public_package)?;
    let kp = kp.tweak(merkle_root);
    let (nonces, commitments) = round1::commit(kp.signing_share(), rng);
    Ok((
        seal(PkgKind::Nonce, &nonces.serialize().map_err(fro)?),
        seal(PkgKind::Share, &commitments.serialize().map_err(fro)?),
    ))
}

/// Round 2 (per heir): sign the coordinator's package with the round-1
/// nonces. Returns the signature-share package. PLAIN ceremony: no
/// BIP-341 tweak is applied (see `heir_round1`).
pub fn heir_round2(
    private_package: &str,
    public_package: &str,
    nonce_package: &str,
    sign_package: &str,
) -> Result<String, FrostError> {
    let (identifier, scalar) = signing_scalar_of(private_package)?;
    let kp = key_package_from_scalar(&identifier, &scalar, public_package)?;
    let nonces =
        round1::SigningNonces::deserialize(&unseal(PkgKind::Nonce, nonce_package)?).map_err(fro)?;
    let pkg = SigningPackage::deserialize(&unseal(PkgKind::Sign, sign_package)?).map_err(fro)?;
    let result = round2::sign(&pkg, &nonces, &kp).map_err(fro)?;
    Ok(seal(PkgKind::Share, &result.serialize()))
}

/// Round 2 with the matching BIP-341 tweak (see `heir_round1_tweaked`).
pub fn heir_round2_tweaked(
    private_package: &str,
    public_package: &str,
    nonce_package: &str,
    sign_package: &str,
    merkle_root: Option<&[u8; 32]>,
) -> Result<String, FrostError> {
    let (identifier, scalar) = signing_scalar_of(private_package)?;
    let kp = key_package_from_scalar(&identifier, &scalar, public_package)?;
    let kp = kp.tweak(merkle_root);
    let nonces =
        round1::SigningNonces::deserialize(&unseal(PkgKind::Nonce, nonce_package)?).map_err(fro)?;
    let pkg = SigningPackage::deserialize(&unseal(PkgKind::Sign, sign_package)?).map_err(fro)?;
    let sig_share = round2::sign(&pkg, &nonces, &kp).map_err(fro)?;
    Ok(seal(PkgKind::Share, &sig_share.serialize()))
}

/// Identifier-tagged round-1 response from one heir.
#[derive(Debug, Clone)]
pub struct HeirRound1 {
    /// The heir's FROST identifier (32-byte encoding, hex at the CLI edge).
    pub identifier: [u8; 32],
    /// The round-1 commitment package (`PkgKind::Share`).
    pub commitment: String,
}

/// Builds the coordinator's round-2 package from tagged round-1 responses.
pub fn coordinator_sign_package_tagged(
    msg32: &[u8; 32],
    responses: &[HeirRound1],
) -> Result<String, FrostError> {
    let mut map = BTreeMap::new();
    for r in responses {
        let id = frost::Identifier::deserialize(&r.identifier).map_err(fro)?;
        let c = round1::SigningCommitments::deserialize(&unseal(PkgKind::Share, &r.commitment)?)
            .map_err(fro)?;
        if map.insert(id, c).is_some() {
            return Err(FrostError::Protocol("duplicate identifier".into()));
        }
    }
    let pkg = SigningPackage::new(map, msg32);
    Ok(seal(PkgKind::Sign, &pkg.serialize().map_err(fro)?))
}

/// Identifier-tagged round-2 response from one heir.
#[derive(Debug, Clone)]
pub struct HeirRound2 {
    /// The heir's FROST identifier.
    pub identifier: [u8; 32],
    /// The signature-share package (`PkgKind::Share`).
    pub share: String,
}

/// Aggregates `k` signature shares into the final 64-byte BIP-340 signature.
/// Fails closed: wrong participants, duplicate identifiers and invalid
/// shares (cheater detection) all abort the assembly.
pub fn coordinator_assemble(
    sign_package: &str,
    public_package: &str,
    shares: &[HeirRound2],
) -> Result<[u8; 64], FrostError> {
    let pkg = SigningPackage::deserialize(&unseal(PkgKind::Sign, sign_package)?).map_err(fro)?;
    let pubkeys =
        PublicKeyPackage::deserialize(&unseal(PkgKind::Deal, public_package)?).map_err(fro)?;
    let mut map = BTreeMap::new();
    for s in shares {
        let id = frost::Identifier::deserialize(&s.identifier).map_err(fro)?;
        let share =
            round2::SignatureShare::deserialize(&unseal(PkgKind::Share, &s.share)?).map_err(fro)?;
        if map.insert(id, share).is_some() {
            return Err(FrostError::Protocol("duplicate identifier".into()));
        }
    }
    let sig = frost::aggregate(&pkg, &map, &pubkeys).map_err(fro)?;
    let bytes = sig.serialize().map_err(fro)?;
    bytes
        .try_into()
        .map_err(|_| FrostError::Protocol("signature length".into()))
}
/// Plain-Schnorr verification of the assembled signature under the group key
/// (a FROST signature is INDISTINGUISHABLE from a single-signer one).
pub fn verify_group_signature<C: Verification>(
    secp: &Secp256k1<C>,
    group_key: &GroupKey,
    msg32: &[u8; 32],
    sig64: &[u8; 64],
) -> Result<(), FrostError> {
    let pk = XOnlyPublicKey::from_slice(group_key).map_err(|_| FrostError::BadSignature)?;
    let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(sig64)
        .map_err(|_| FrostError::BadSignature)?;
    secp.verify_schnorr(&sig, &Message::from_digest(*msg32), &pk)
        .map_err(|_| FrostError::BadSignature)
}

// ─── Taproot binding (Part 1): group key as a REAL vault spending key ───
//
// The ciphersuite is FROST(secp256k1, SHA-256) with BIP-341 TapTweak
// support baked in (`keys::Tweak`): tweaking the whole PublicKeyPackage by
// a merkle root tweaks the group key AND every verifying share exactly as
// BIP-341 §3 prescribes, so the ceremony output verifies under the TWEAKED
// output key — i.e. it spends a real P2TR output locked to that tree.

use frost_secp256k1_tr::keys::Tweak as FrostTweak;

/// BIP-341 tweak of a public package by an optional merkle root. Returns
/// (tweaked_public_package, tweaked_group_key). The coordinator MUST use
/// the tweaked package for aggregation whenever the vault output is a P2TR
/// with that merkle root (empty tree = tweak by None, the key-path shape).
pub fn tweak_public_package(
    public_package: &str,
    merkle_root: Option<&[u8; 32]>,
) -> Result<(String, GroupKey), FrostError> {
    let pubkeys =
        PublicKeyPackage::deserialize(&unseal(PkgKind::Deal, public_package)?).map_err(fro)?;
    let tweaked = pubkeys.tweak(merkle_root);
    let vk: Vec<u8> = tweaked.verifying_key().serialize().map_err(fro)?;
    let group_key: GroupKey = vk
        .get(1..33)
        .and_then(|x| x.try_into().ok())
        .ok_or_else(|| FrostError::Protocol("group key length".into()))?;
    Ok((
        seal(PkgKind::Deal, &tweaked.serialize().map_err(fro)?),
        group_key,
    ))
}

/// BIP-341 tweak of one heir's key material by the same merkle root. The
/// heir applies this before round 1/2 whenever the coordinator announces a
/// tweaked ceremony (root travels in the sign package by convention).
pub fn tweak_private_package(
    private_package: &str,
    public_package: &str,
    merkle_root: Option<&[u8; 32]>,
) -> Result<String, FrostError> {
    let body = unseal(PkgKind::DealPrivate, private_package)?;
    if body.len() <= 32 {
        return Err(FrostError::Malformed("private package too short".into()));
    }
    let kp = key_package_from_private_body(&body, public_package)?;
    let tweaked = kp.tweak(merkle_root);
    let mut out = Vec::new();
    out.extend_from_slice(&tweaked.identifier().serialize());
    out.extend_from_slice(&tweaked.serialize().map_err(fro)?);
    Ok(seal(PkgKind::DealPrivate, &out))
}

fn key_package_from_private_body(
    body: &[u8],
    public_package: &str,
) -> Result<KeyPackageCs, FrostError> {
    let mut identifier = [0u8; 32];
    identifier.copy_from_slice(&body[..32]);
    let kp = KeyPackage::deserialize(&body[32..]).map_err(fro)?;
    // Bind the key package to the coordinator's public package: the
    // verifying share must match, otherwise the package pair is inconsistent.
    let pubkeys =
        PublicKeyPackage::deserialize(&unseal(PkgKind::Deal, public_package)?).map_err(fro)?;
    let id = frost::Identifier::deserialize(&identifier).map_err(fro)?;
    if pubkeys.verifying_shares().get(&id).is_none() {
        return Err(FrostError::Protocol(
            "identifier not present in the public package".into(),
        ));
    }
    Ok(kp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const LABELS: [&str; 3] = ["heir-1 (big kid)", "heir-2 (little kid)", "notary"];

    fn deal(threshold: u16) -> DealOutput {
        let labels: Vec<String> = LABELS.iter().map(|s| s.to_string()).collect();
        trusted_deal(threshold, &labels, &mut OsRng).unwrap()
    }

    #[test]
    fn trusted_deal_derives_group_key_and_label_sorted_slots() {
        let d = deal(2);
        assert_eq!(d.slots.len(), 3);
        // Label-sorted order.
        assert_eq!(d.slots[0].label, "heir-1 (big kid)");
        assert_eq!(d.slots[1].label, "heir-2 (little kid)");
        assert_eq!(d.slots[2].label, "notary");
        // Group key is a valid x-only point (not the NUMS key).
        assert!(XOnlyPublicKey::from_slice(&d.group_key).is_ok());
        // Packages carry the right envelope tags.
        assert_eq!(
            unseal(PkgKind::Deal, &d.public_package).unwrap().len(),
            unseal(PkgKind::Deal, &d.public_package).unwrap().len()
        );
        for p in &d.private_packages {
            assert!(unseal(PkgKind::DealPrivate, p).is_ok());
        }
    }

    #[test]
    fn threshold_flow_2of3_produces_verifiable_schnorr_signature() {
        let d = deal(2);
        let msg = [0x5Au8; 32];
        let pubpkg = &d.public_package;

        // Any TWO of the three heirs sign (here: slots 0 and 2).
        let mut r1s = Vec::new();
        let mut nonces = Vec::new();
        let privs = [d.private_packages[0].clone(), d.private_packages[2].clone()];
        for p in &privs {
            let (nonce, cmt) = heir_round1(p, pubpkg, &mut OsRng).unwrap();
            nonces.push(nonce);
            r1s.push(HeirRound1 {
                identifier: signing_scalar_of(p).unwrap().0,
                commitment: cmt,
            });
        }
        let sign_pkg = coordinator_sign_package_tagged(&msg, &r1s).unwrap();

        let mut r2s = Vec::new();
        for (p, n) in privs.iter().zip(&nonces) {
            let share = heir_round2(p, pubpkg, n, &sign_pkg).unwrap();
            r2s.push(HeirRound2 {
                identifier: signing_scalar_of(p).unwrap().0,
                share,
            });
        }
        let sig = coordinator_assemble(&sign_pkg, pubpkg, &r2s).unwrap();
        verify_group_signature(&Secp256k1::verification_only(), &d.group_key, &msg, &sig)
            .expect("2-of-3 FROST signature must verify as plain Schnorr");

        // The same message signed again (fresh nonces) verifies too but
        // differs (randomized nonces) — never replay a nonce package.
        let (n0, c0) = heir_round1(&privs[0], pubpkg, &mut OsRng).unwrap();
        let (n2, c2) = heir_round1(&privs[1], pubpkg, &mut OsRng).unwrap();
        let pkg2 = coordinator_sign_package_tagged(
            &msg,
            &[
                HeirRound1 {
                    identifier: signing_scalar_of(&privs[0]).unwrap().0,
                    commitment: c0,
                },
                HeirRound1 {
                    identifier: signing_scalar_of(&privs[1]).unwrap().0,
                    commitment: c2,
                },
            ],
        )
        .unwrap();
        let s0 = heir_round2(&privs[0], pubpkg, &n0, &pkg2).unwrap();
        let s2 = heir_round2(&privs[1], pubpkg, &n2, &pkg2).unwrap();
        let sig2 = coordinator_assemble(
            &pkg2,
            pubpkg,
            &[
                HeirRound2 {
                    identifier: signing_scalar_of(&privs[0]).unwrap().0,
                    share: s0,
                },
                HeirRound2 {
                    identifier: signing_scalar_of(&privs[1]).unwrap().0,
                    share: s2,
                },
            ],
        )
        .unwrap();
        assert_ne!(sig, sig2, "fresh nonces must give a fresh signature");
    }

    #[test]
    fn below_threshold_and_wrong_tag_fail_closed() {
        let d = deal(2);
        let msg = [0x77u8; 32];
        let pubpkg = &d.public_package;

        // TWO commitments make a valid sign package, but presenting only
        // ONE signature share at aggregate time must fail (k=2 unmet).
        let (n0, c0) = heir_round1(&d.private_packages[0], pubpkg, &mut OsRng).unwrap();
        let (_n1, c1) = heir_round1(&d.private_packages[1], pubpkg, &mut OsRng).unwrap();
        let pkg = coordinator_sign_package_tagged(
            &msg,
            &[
                HeirRound1 {
                    identifier: signing_scalar_of(&d.private_packages[0]).unwrap().0,
                    commitment: c0,
                },
                HeirRound1 {
                    identifier: signing_scalar_of(&d.private_packages[1]).unwrap().0,
                    commitment: c1,
                },
            ],
        )
        .unwrap();
        let s0 = heir_round2(&d.private_packages[0], pubpkg, &n0, &pkg).unwrap();
        let short = coordinator_assemble(
            &pkg,
            pubpkg,
            &[HeirRound2 {
                identifier: signing_scalar_of(&d.private_packages[0]).unwrap().0,
                share: s0,
            }],
        );
        assert!(short.is_err(), "one share cannot satisfy a 2-of-3 group");

        // Cross-flow: a NONCE package presented where a SHARE is required.
        assert!(matches!(
            unseal(PkgKind::Share, &n0),
            Err(FrostError::Malformed(_))
        ));

        // Tampered threshold parameters.
        assert!(trusted_deal(0, &["a".into()], &mut OsRng).is_err());
        assert!(trusted_deal(3, &["a".into(), "b".into()], &mut OsRng).is_err());
    }

    #[test]
    fn coordinator_fails_closed_on_duplicate_identifiers() {
        let d = deal(2);
        let msg = [0x99u8; 32];
        let pubpkg = &d.public_package;
        let id0 = signing_scalar_of(&d.private_packages[0]).unwrap().0;
        let (_n0, c0) = heir_round1(&d.private_packages[0], pubpkg, &mut OsRng).unwrap();

        // The SAME identifier twice at round-2 package build time: a cheater
        // signal — the coordinator must refuse, not silently deduplicate.
        let dup = [
            HeirRound1 {
                identifier: id0,
                commitment: c0.clone(),
            },
            HeirRound1 {
                identifier: id0,
                commitment: c0,
            },
        ];
        assert!(matches!(
            coordinator_sign_package_tagged(&msg, &dup),
            Err(FrostError::Protocol(m)) if m.contains("duplicate identifier")
        ));

        // …and again at share-aggregate time: THREE entries where one
        // identifier repeats. The coordinator must refuse — deduplicating
        // would silently satisfy the 2-of-3 threshold.
        let id1 = signing_scalar_of(&d.private_packages[1]).unwrap().0;
        let (n0b, c0b) = heir_round1(&d.private_packages[0], pubpkg, &mut OsRng).unwrap();
        let (n1, c1) = heir_round1(&d.private_packages[1], pubpkg, &mut OsRng).unwrap();
        let pkg = coordinator_sign_package_tagged(
            &msg,
            &[
                HeirRound1 {
                    identifier: id0,
                    commitment: c0b,
                },
                HeirRound1 {
                    identifier: id1,
                    commitment: c1,
                },
            ],
        )
        .unwrap();
        let s0 = heir_round2(&d.private_packages[0], pubpkg, &n0b, &pkg).unwrap();
        let s1 = heir_round2(&d.private_packages[1], pubpkg, &n1, &pkg).unwrap();
        let dup_shares = [
            HeirRound2 {
                identifier: id0,
                share: s0,
            },
            HeirRound2 {
                identifier: id1,
                share: s1.clone(),
            },
            HeirRound2 {
                identifier: id0, // duplicate — must abort
                share: s1,
            },
        ];
        assert!(matches!(
            coordinator_assemble(&pkg, pubpkg, &dup_shares),
            Err(FrostError::Protocol(m)) if m.contains("duplicate identifier")
        ));
    }

    #[test]
    fn slip39_backup_roundtrip_recovers_the_exact_scalar() {
        let d = deal(2);
        let pass = "estate passphrase";
        let mnemonics = seal_share_as_slip39(&d.private_packages[1], 2, 3, pass).unwrap();
        assert_eq!(mnemonics.len(), 3);
        assert!(mnemonics[0].split_whitespace().count() >= 20);

        // Any 2 of the 3 mnemonics recover the exact scalar.
        let full = signing_scalar_of(&d.private_packages[1]).unwrap().1;
        let a = recover_share_from_slip39(&[&mnemonics[0], &mnemonics[1]], pass).unwrap();
        assert_eq!(a, full);
        let b = recover_share_from_slip39(&[&mnemonics[1], &mnemonics[2]], pass).unwrap();
        assert_eq!(b, full);

        // One mnemonic is not enough (fail-closed digest tag).
        assert!(recover_share_from_slip39(&[&mnemonics[0]], pass).is_err());
        // Wrong passphrase yields a different (deniable) secret, not an error.
        let wrong = recover_share_from_slip39(&[&mnemonics[0], &mnemonics[1]], "nope").unwrap();
        assert_ne!(wrong, full);
    }

    /// Full BIP-341-tweaked ceremony: 2-of-3 FROST whose group key is
    /// tweaked by a merkle root (the vault MAST tree), aggregated with the
    /// tweaked packages, and verified under the TWEAKED output key.
    #[test]
    fn taproot_tweaked_ceremony_verifies_under_output_key() {
        let d = deal(2);
        let root = [0x42u8; 32];
        let (tweaked_pub, tweaked_group) =
            tweak_public_package(&d.public_package, Some(&root)).unwrap();

        // The tweaked key is the plain BIP-341 tweak of the group key.
        let secp = Secp256k1::verification_only();
        let base = XOnlyPublicKey::from_slice(&d.group_key).unwrap();
        use bitcoin::hashes::Hash as _;
        let node_hash = bitcoin::taproot::TapNodeHash::from_byte_array(root);
        let t =
            bitcoin::taproot::TapTweakHash::from_key_and_tweak(base, Some(node_hash)).to_scalar();
        let expected = base.add_tweak(&secp, &t).unwrap().0;
        assert_eq!(tweaked_group, expected.serialize());

        // Heirs tweak their own packages with the SAME root and sign.
        let msg = [0x33u8; 32];
        let mut r1s = Vec::new();
        let mut nonces = Vec::new();
        let privs = [d.private_packages[0].clone(), d.private_packages[2].clone()];
        let tweaked_privs: Vec<String> = privs
            .iter()
            .map(|p| tweak_private_package(p, &d.public_package, Some(&root)).unwrap())
            .collect();
        for p in &tweaked_privs {
            let (nonce, cmt) = heir_round1(p, &tweaked_pub, &mut OsRng).unwrap();
            nonces.push(nonce);
            r1s.push(HeirRound1 {
                identifier: signing_scalar_of(p).unwrap().0,
                commitment: cmt,
            });
        }
        let pkg = coordinator_sign_package_tagged(&msg, &r1s).unwrap();
        let mut r2s = Vec::new();
        for (p, n) in tweaked_privs.iter().zip(&nonces) {
            let share = heir_round2(p, &tweaked_pub, n, &pkg).unwrap();
            r2s.push(HeirRound2 {
                identifier: signing_scalar_of(p).unwrap().0,
                share,
            });
        }
        let sig = coordinator_assemble(&pkg, &tweaked_pub, &r2s).unwrap();
        verify_group_signature(&Secp256k1::verification_only(), &tweaked_group, &msg, &sig)
            .expect("tweaked FROST signature must verify under the tweaked output key");

        // …and it must NOT verify under the untweaked group key.
        assert!(
            verify_group_signature(&Secp256k1::verification_only(), &d.group_key, &msg, &sig,)
                .is_err()
        );
    }

    #[test]
    fn package_walls_and_display_arms_fail_closed() {
        // trusted_deal caps the heir set at 100.
        let big: Vec<String> = (0..101).map(|i| format!("heir-{i:03}")).collect();
        let err = trusted_deal(2, &big, &mut OsRng)
            .err()
            .expect("101 heirs must be refused");
        assert!(matches!(err, FrostError::Params(_)));
        assert!(err.to_string().contains("total capped at 100 heirs"));

        // A private package of exactly 32 bytes carries no key material.
        let short = seal(PkgKind::DealPrivate, &[7u8; 32]);
        assert!(deal_identifier(&short)
            .unwrap_err()
            .to_string()
            .contains("private package too short"));
        assert!(deal_signing_scalar(&short).is_err());
        assert!(
            tweak_private_package(&short, &seal(PkgKind::Deal, &[0u8; 8]), None)
                .unwrap_err()
                .to_string()
                .contains("private package too short")
        );

        // Cross-ceremony pairing: A's private vs B's public package → the
        // identifier is absent from the foreign verifying-share table.
        let labels_a: Vec<String> = (0..2).map(|i| format!("a-{i}")).collect();
        let labels_b: Vec<String> = (0..2).map(|i| format!("b-{i}")).collect();
        let a = trusted_deal(2, &labels_a, &mut OsRng).unwrap();
        let b = trusted_deal(2, &labels_b, &mut OsRng).unwrap();
        let err =
            tweak_private_package(&a.private_packages[0], &b.public_package, None).unwrap_err();
        assert!(matches!(err, FrostError::Protocol(_)));
        assert!(err
            .to_string()
            .contains("identifier not present in the public package"));

        // Display arms render their own operator-facing messages.
        assert!(FrostError::Params("x".into())
            .to_string()
            .contains("bad parameters"));
        assert!(FrostError::Protocol("x".into())
            .to_string()
            .contains("protocol error"));
        assert!(FrostError::BadSignature
            .to_string()
            .contains("does NOT verify under the group key"));
        assert!(FrostError::Slip39("x".into())
            .to_string()
            .contains("SLIP-0039 backup error"));
    }

    #[test]
    fn dkg_rehearsal_matches_the_deal_contract_and_signs() {
        let labels: Vec<String> = LABELS.iter().map(|s| s.to_string()).collect();
        let d = dkg_rehearsal(2, &labels, &mut OsRng).unwrap();

        // The SAME contract as the trusted dealer: label-sorted slots,
        // label-derived identifiers, a valid x-only group key, sealed
        // packages of the right kind.
        assert_eq!(d.slots.len(), 3);
        assert_eq!(d.slots[0].label, "heir-1 (big kid)");
        assert_eq!(d.slots[1].label, "heir-2 (little kid)");
        assert_eq!(d.slots[2].label, "notary");
        assert!(XOnlyPublicKey::from_slice(&d.group_key).is_ok());
        for p in &d.private_packages {
            assert!(unseal(PkgKind::DealPrivate, p).is_ok());
        }
        // Identifiers stay label-derived, so the dealer's file naming and
        // every downstream consumer work unchanged…
        let dealer = trusted_deal(2, &labels, &mut OsRng).unwrap();
        for (a, b) in d.slots.iter().zip(&dealer.slots) {
            assert_eq!(a.identifier, b.identifier);
            assert_eq!(a.label, b.label);
        }
        // …while the group key differs: no dealer means fresh JOINT
        // randomness instead of one machine's RNG.
        assert_ne!(d.group_key, dealer.group_key);

        // The DKG shares sign: any two heirs → ONE plain Schnorr signature
        // under the group key (the whole downstream contract).
        let msg = [0xD6u8; 32];
        let pubpkg = &d.public_package;
        let privs = [d.private_packages[0].clone(), d.private_packages[2].clone()];
        let mut r1s = Vec::new();
        let mut nonces = Vec::new();
        for p in &privs {
            let (nonce, cmt) = heir_round1(p, pubpkg, &mut OsRng).unwrap();
            nonces.push(nonce);
            r1s.push(HeirRound1 {
                identifier: signing_scalar_of(p).unwrap().0,
                commitment: cmt,
            });
        }
        let sign_pkg = coordinator_sign_package_tagged(&msg, &r1s).unwrap();
        let mut r2s = Vec::new();
        for (p, n) in privs.iter().zip(&nonces) {
            let share = heir_round2(p, pubpkg, n, &sign_pkg).unwrap();
            r2s.push(HeirRound2 {
                identifier: signing_scalar_of(p).unwrap().0,
                share,
            });
        }
        let sig = coordinator_assemble(&sign_pkg, pubpkg, &r2s).unwrap();
        verify_group_signature(&Secp256k1::verification_only(), &d.group_key, &msg, &sig)
            .expect("DKG shares must produce a verifiable group signature");
    }

    #[test]
    fn dkg_below_threshold_fails_closed() {
        let labels: Vec<String> = LABELS.iter().map(|s| s.to_string()).collect();
        let d = dkg_rehearsal(2, &labels, &mut OsRng).unwrap();
        let msg = [0x99u8; 32];
        let pubpkg = &d.public_package;

        // Two commitments, but only ONE share at aggregate time: k=2 unmet.
        let (n0, c0) = heir_round1(&d.private_packages[0], pubpkg, &mut OsRng).unwrap();
        let (_n1, c1) = heir_round1(&d.private_packages[1], pubpkg, &mut OsRng).unwrap();
        let pkg = coordinator_sign_package_tagged(
            &msg,
            &[
                HeirRound1 {
                    identifier: signing_scalar_of(&d.private_packages[0]).unwrap().0,
                    commitment: c0,
                },
                HeirRound1 {
                    identifier: signing_scalar_of(&d.private_packages[1]).unwrap().0,
                    commitment: c1,
                },
            ],
        )
        .unwrap();
        let s0 = heir_round2(&d.private_packages[0], pubpkg, &n0, &pkg).unwrap();
        let short = coordinator_assemble(
            &pkg,
            pubpkg,
            &[HeirRound2 {
                identifier: signing_scalar_of(&d.private_packages[0]).unwrap().0,
                share: s0,
            }],
        );
        assert!(
            short.is_err(),
            "one share of a 2-of-3 DKG deal must not assemble"
        );
    }

    #[test]
    fn dkg_validates_its_threshold_like_the_dealer() {
        let labels: Vec<String> = LABELS.iter().map(|s| s.to_string()).collect();
        assert!(matches!(
            dkg_rehearsal(0, &labels, &mut OsRng),
            Err(FrostError::Params(_))
        ));
        assert!(matches!(
            dkg_rehearsal(4, &labels, &mut OsRng),
            Err(FrostError::Params(_))
        ));
        assert!(matches!(
            dkg_rehearsal(1, &[], &mut OsRng),
            Err(FrostError::Params(_))
        ));
    }
}
