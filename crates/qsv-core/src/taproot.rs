//! Taproot output derivation for QuantumSafe-Vault (BIP-341).
//!
//! The key-path is mathematically cancelled: the internal key is the NUMS
//! point (see `nums`), whose discrete log is unknown by construction. Every
//! spend therefore goes through the script path (MAST).

use crate::nums::nums_internal_key;
use bitcoin::address::{Address, KnownHrp};
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGADD, OP_CHECKSIGVERIFY, OP_CSV, OP_DROP, OP_GREATERTHANOREQUAL,
};
use bitcoin::script::Builder as ScriptBuilder;
use bitcoin::secp256k1::{Secp256k1, Verification, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TapNodeHash, TaprootBuilder, TaprootSpendInfo};
use bitcoin::Network;

/// Errors raised while building the vault taproot output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaprootError {
    /// Taproot builder rejected a leaf or the tree is incomplete.
    Builder(String),
    /// Script construction failure.
    Script(String),
}

impl core::fmt::Display for TaprootError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TaprootError::Builder(s) => write!(f, "taproot builder error: {s}"),
            TaprootError::Script(s) => write!(f, "script error: {s}"),
        }
    }
}

impl std::error::Error for TaprootError {}

/// Leaf scripts of the vault MAST (docs/03 §3, docs/02 §5).
pub struct VaultLeaves {
    /// Leaf 1 — normal hybrid spend: `<pk_user> CHECKSIGVERIFY <pk_enclave> CHECKSIG`.
    pub normal: bitcoin::ScriptBuf,
    /// Leaf 2 — emergency cold sweep: `<144> CSV DROP <pk_recovery> CHECKSIG`.
    pub recovery: bitcoin::ScriptBuf,
    /// Leaf 3 — inheritance: `<26280> CSV DROP` + k-of-n heir threshold.
    pub inheritance: bitcoin::ScriptBuf,
    /// Leaf 4 — post-Q-Day emergency kit (docs/08 §2), commit-reveal form:
    /// `OP_DUP OP_SHA256 <H(pk_em)> OP_EQUALVERIFY OP_CHECKSIG` (38 B). The
    /// plaintext emergency destination key appears ONLY in the witness; the
    /// script (and therefore the tree) commits to its 32-byte digest. The key
    /// is disclosed exclusively inside the WOTS+-sealed offline kit; consensus
    /// verifies hash-lock + Schnorr. Every witness element stays ≤ 520 B
    /// (BIP-342 discipline — a 2,144-byte WOTS+ element is consensus-ILLEGAL,
    /// pinned by the t6 regression test).
    pub emergency: bitcoin::ScriptBuf,
}

/// The canonical emergency leaf script (37 bytes, commit-reveal):
///
/// ```text
/// OP_DUP OP_SHA256 <sha256(pk_em)> OP_EQUALVERIFY OP_CHECKSIG
/// ```
///
/// Witness layout: `[σ_em (64 B), pk_em (32 B), script (37 B), control]` —
/// stack top first; every element within the 520-byte BIP-342 limit. The
/// plaintext key never appears in the script or the tree: it is disclosed
/// ONLY at spend time, from the WOTS+-sealed offline kit, and the on-chain
/// digest binds that key cryptographically. HONEST LIMIT (Round 41 audit):
/// the Schnorr check is CLASSICAL — leaf 4 is a hiding mechanism plus a
/// SHA-256 hash lock, not a post-quantum signature path. On Q-Day the
/// revealed key can be forged against, so the WOTS+-sealed offline kit
/// protects the SECRET until use, not the spend itself.
pub fn emergency_leaf_script(pk_em: XOnlyPublicKey) -> bitcoin::ScriptBuf {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_SHA256};
    let digest = sha256::Hash::hash(&pk_em.serialize());
    ScriptBuilder::new()
        .push_opcode(OP_DUP)
        .push_opcode(OP_SHA256)
        .push_slice(digest.to_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Builds the k-of-n threshold inheritance script:
/// `<26280> CSV DROP <pk1> CHECKSIG <pk2> CHECKSIGADD ... <k> GREATERTHANOREQUAL`.
pub fn inheritance_script(
    pks: &[XOnlyPublicKey],
    k: usize,
) -> Result<bitcoin::ScriptBuf, TaprootError> {
    if pks.len() < 2 || k < 1 || k > pks.len() {
        return Err(TaprootError::Script("threshold out of range".into()));
    }
    let mut b = ScriptBuilder::new()
        .push_int(i64::from(crate::policy::INHERITANCE_CSV_BLOCKS))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP);
    for (i, pk) in pks.iter().enumerate() {
        b = b.push_x_only_key(pk);
        b = if i == 0 {
            b.push_opcode(OP_CHECKSIG)
        } else {
            b.push_opcode(OP_CHECKSIGADD)
        };
    }
    Ok(b.push_int(k as i64)
        .push_opcode(OP_GREATERTHANOREQUAL)
        .into_script())
}

/// Builds the normal hybrid leaf script (2-of-2 classic Schnorr at consensus):
/// `<pk_user> CHECKSIGVERIFY <pk_enclave> CHECKSIG`.
///
/// Exactly two signatures are required: the first must be valid for
/// `pk_user` (CHECKSIGVERIFY pops and requires success), the second for
/// `pk_enclave`. No other combination satisfies this leaf.
pub fn normal_leaf_script(user: XOnlyPublicKey, enclave: XOnlyPublicKey) -> bitcoin::ScriptBuf {
    ScriptBuilder::new()
        .push_x_only_key(&user)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_x_only_key(&enclave)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Builds the recovery (clawback) leaf script: `<144> CSV DROP <pk> CHECKSIG`.
pub fn recovery_leaf_script(recovery: XOnlyPublicKey) -> Result<bitcoin::ScriptBuf, TaprootError> {
    Ok(ScriptBuilder::new()
        .push_int(i64::from(crate::policy::RECOVERY_CSV_BLOCKS))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&recovery)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

/// Watch-only export of ONE exact vault output (docs/10 §4.59): the two
/// descriptor forms that expand to this output's scriptPubKey and that
/// Bitcoin Core imports, each carrying a BIP-380 checksum.
///
/// Deliberately NOT a `tr(...)`: a `tr()` descriptor must restate the whole
/// script tree, three of this vault's four leaves are not miniscript, and
/// raw hex tapscript leaves are non-standard (BIP-386 — a tree leaf is a
/// script *expression*; Core documents `raw(HEX)` as top-level only).
/// Shipping a `tr()` with a DIFFERENT tree would derive a DIFFERENT address
/// and a watcher would silently watch nothing — so the export refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchOnly {
    /// Bech32m address of the output (the same one every command reports).
    pub address: Address,
    /// `OP_1 <output key>` — what both descriptors must expand to.
    pub script_pubkey: bitcoin::ScriptBuf,
    /// `addr(bc1p…)#checksum` — BIP-385, exact output for the network.
    pub addr_descriptor: String,
    /// `rawtr(<output key>)#checksum` — Core's output-key form of the same
    /// scriptPubKey (no claim about the tree).
    pub rawtr_descriptor: String,
}

/// The complete vault taproot structure: NUMS internal key + MAST leaves.
pub struct VaultTaproot {
    /// The provably unspendable internal key.
    pub internal_key: XOnlyPublicKey,
    /// Spend info (output key, merkle root, per-script control blocks).
    pub spend_info: TaprootSpendInfo,
    /// The four leaf scripts.
    pub leaves: VaultLeaves,
    /// Tap leaf hashes for addressing and witness construction.
    pub leaf_hashes: Vec<TapLeafHash>,
}

impl VaultTaproot {
    /// Derives the vault taproot structure.
    ///
    /// `heir_keys` + `threshold` define the inheritance leaf (docs default:
    /// 2 heirs + executor key == 3 keys, 2-of-3).
    pub fn derive(
        secp: &Secp256k1<impl Verification>,
        user: XOnlyPublicKey,
        enclave: XOnlyPublicKey,
        recovery: XOnlyPublicKey,
        heir_keys: &[XOnlyPublicKey],
        threshold: usize,
    ) -> Result<Self, TaprootError> {
        let internal_key = nums_internal_key();

        let normal = normal_leaf_script(user, enclave);
        let recovery = recovery_leaf_script(recovery)?;
        let mut heirs = heir_keys.to_vec();
        if heirs.len() < 2 {
            heirs.push(crate::demo_keys::heir_one());
            heirs.push(crate::demo_keys::heir_two());
        }
        heirs.push(crate::demo_keys::executor_key());
        let inheritance = inheritance_script(&heirs, threshold)?;

        // Leaf 4 (docs/08 §2): the post-Q-Day emergency kit leaf. The
        // destination key is hidden behind a 32-byte hash lock and disclosed
        // only inside the WOTS+-sealed kit; consensus verifies hash + Schnorr
        // with every witness element ≤ 520 B.
        let emergency = emergency_leaf_script(crate::demo_keys::emergency_kit_key());

        // Equal-weight Huffman tree: the four leaves form a balanced MAST.
        // (Manual add_leaf requires strict DFS ordering; Huffman handles it.)
        let builder = TaprootBuilder::with_huffman_tree(vec![
            (1u32, normal.clone()),
            (1u32, recovery.clone()),
            (1u32, inheritance.clone()),
            (1u32, emergency.clone()),
        ])
        .map_err(|e| TaprootError::Builder(e.to_string()))?;

        let spend_info = builder
            .clone()
            .finalize(secp, internal_key)
            .map_err(|_builder| TaprootError::Builder("tree incomplete at finalize".into()))?;

        let leaf_hashes = vec![
            TapLeafHash::from_script(&normal, LeafVersion::TapScript),
            TapLeafHash::from_script(&recovery, LeafVersion::TapScript),
            TapLeafHash::from_script(&inheritance, LeafVersion::TapScript),
            TapLeafHash::from_script(&emergency, LeafVersion::TapScript),
        ];

        Ok(Self {
            internal_key,
            spend_info,
            leaves: VaultLeaves {
                normal,
                recovery,
                inheritance,
                emergency,
            },
            leaf_hashes,
        })
    }

    /// The tweaked output key (x-only) — what appears in the scriptPubKey.
    pub fn output_key(&self) -> XOnlyPublicKey {
        self.spend_info.output_key().into()
    }

    /// Merkle root of the script tree.
    pub fn merkle_root(&self) -> Option<TapNodeHash> {
        self.spend_info.merkle_root()
    }

    /// Bech32m P2TR address for the given network.
    pub fn address(&self, network: Network) -> Address {
        let secp = Secp256k1::verification_only();
        let hrp = match network {
            Network::Bitcoin => KnownHrp::Mainnet,
            Network::Regtest => KnownHrp::Regtest,
            // Testnet, Testnet4 and Signet share the testnets hrp.
            _ => KnownHrp::Testnets,
        };
        Address::p2tr(&secp, self.internal_key, self.merkle_root(), hrp)
    }

    /// The output's scriptPubKey built from the tweaked output key ALONE
    /// (BIP-341: `OP_1 <32-byte output key>`) — an independent path from the
    /// address encoding, so the two can be cross-checked.
    pub fn script_pubkey(&self) -> bitcoin::ScriptBuf {
        ScriptBuilder::new()
            .push_opcode(bitcoin::opcodes::all::OP_PUSHNUM_1)
            .push_slice(self.output_key().serialize())
            .into_script()
    }

    /// Watch-only descriptor export (docs/10 §4.59).
    ///
    /// Returns the two descriptors that describe THIS output exactly and are
    /// accepted by Bitcoin Core, each with a BIP-380 checksum:
    ///
    /// * `addr(bc1p…)#checksum` (BIP-385) — the exact network-tagged output;
    /// * `rawtr(<output key>)#checksum` — the same scriptPubKey addressed by
    ///   its output key (no claim about the tree).
    ///
    /// # Why there is no `tr(...)` (fail-closed, not an oversight)
    ///
    /// A `tr()` descriptor has to restate the ENTIRE script tree, because the
    /// address commits to the merkle root of every leaf. Three of this
    /// vault's four leaves are not expressible as miniscript:
    ///
    /// * leaf 2/3 open with `<n> CSV DROP` — miniscript only compiles the
    ///   `older(n)` check as `<n> CSV VERIFY` (different byte ⇒ different
    ///   leaf hash ⇒ different address);
    /// * leaf 4 is a SHA-256 commit-reveal lock on the key — no miniscript
    ///   fragment hashes a pubkey with SHA-256.
    ///
    /// Raw hex tapscript leaves would be the escape hatch, but they are
    /// non-standard: BIP-386 defines a tree leaf as a script *expression*,
    /// Core documents `raw(HEX)` as top level only (its `rawleaf()` PR
    /// bitcoin/bitcoin#30243 was closed), and rust-miniscript parses every
    /// leaf as miniscript. A `tr()` built from a *different* tree would
    /// derive a *different* address — a watcher would watch nothing — so
    /// this export refuses to invent one and hands over what is true.
    pub fn watch_descriptors(&self, network: Network) -> Result<WatchOnly, TaprootError> {
        use miniscript::descriptor::checksum::{verify_checksum, Engine};

        let checksummed = |desc: String| -> Result<String, TaprootError> {
            let mut eng = Engine::new();
            eng.input(&desc)
                .map_err(|e| TaprootError::Script(format!("descriptor checksum input: {e}")))?;
            let full = format!("{desc}#{}", eng.checksum());
            // Round-trip our own computation before printing it: a descriptor
            // with a bad checksum would be REJECTED by every importer.
            verify_checksum(&full)
                .map_err(|e| TaprootError::Script(format!("descriptor checksum verify: {e}")))?;
            Ok(full)
        };

        let address = self.address(network);
        let script_pubkey = self.script_pubkey();

        // Fail-closed, both directions: the address must encode exactly this
        // output key's scriptPubKey, otherwise the emitted descriptors would
        // watch a different output than the vault pays to.
        if address.script_pubkey() != script_pubkey {
            return Err(TaprootError::Script(format!(
                "address/scriptPubKey mismatch: {address} does not encode the output key"
            )));
        }
        let back = Address::from_script(&script_pubkey, network)
            .map_err(|e| TaprootError::Script(format!("address round-trip: {e}")))?;
        if back != address {
            return Err(TaprootError::Script(format!(
                "address round-trip mismatch: {address} != {back}"
            )));
        }

        let addr_descriptor = checksummed(format!("addr({address})"))?;
        let rawtr_descriptor = checksummed(format!("rawtr({})", self.output_key()))?;

        Ok(WatchOnly {
            address,
            script_pubkey,
            addr_descriptor,
            rawtr_descriptor,
        })
    }

    /// EXPERIMENTAL — BIP-360 Pay-to-Merkle-Root (P2MR), Draft v0.12.1,
    /// **not activated** (docs/11, Phase 4 migration plan).
    ///
    /// P2MR commits to the script-tree merkle root with NO internal key and
    /// NO tap tweak: SegWit **version 2** program = the 32-byte merkle root
    /// (mainnet prefix `bc1z`). This vault's tree needs no key-path removal —
    /// the NUMS point already cancels it — so the migration is a pure output
    /// re-wrapping: leaf scripts, CSV constants and every witness rule
    /// (including the 520 B element cap) are unchanged. Control blocks shed
    /// the 32-byte internal key (1+32·m instead of 33+32·m: 97 B → 65 B at
    /// depth 2), making every script-path spend 32 WU cheaper.
    ///
    /// Spending such an output requires BIP-360 consensus rules; this helper
    /// derives the address TODAY so the migration plan is executable and
    /// testable (address math, size arithmetic, estate-letter wording) while
    /// only the soft fork itself remains outstanding.
    pub fn p2mr_address_experimental(&self, network: Network) -> Result<Address, TaprootError> {
        let root = self
            .merkle_root()
            .ok_or_else(|| TaprootError::Builder("tree has no merkle root".into()))?;
        let program =
            bitcoin::WitnessProgram::new(bitcoin::WitnessVersion::V2, root.as_byte_array())
                .map_err(|e| TaprootError::Builder(e.to_string()))?;
        let hrp = match network {
            Network::Bitcoin => KnownHrp::Mainnet,
            Network::Regtest => KnownHrp::Regtest,
            _ => KnownHrp::Testnets,
        };
        Ok(Address::from_witness_program(program, hrp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo_keys;

    #[test]
    fn vault_derives_valid_output_key() {
        let secp = Secp256k1::verification_only();
        let v = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();
        // Output key must differ from the NUMS internal key (tweak applied).
        assert_ne!(v.internal_key, v.output_key());
        assert!(v.merkle_root().is_some());
    }

    #[test]
    fn vault_address_is_bech32m() {
        let secp = Secp256k1::verification_only();
        let v = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();
        let s = v.address(Network::Signet).to_string();
        // P2TR addresses use bech32m with the `p` witness-version separator.
        assert!(s.starts_with("tb1p"), "unexpected address prefix: {s}");
        let m = v.address(Network::Bitcoin).to_string();
        assert!(m.starts_with("bc1p"), "unexpected mainnet prefix: {m}");
    }

    #[test]
    fn inheritance_script_shape() {
        let s = inheritance_script(
            &[
                demo_keys::heir_one(),
                demo_keys::heir_two(),
                demo_keys::executor_key(),
            ],
            2,
        )
        .unwrap();
        let asm = s.to_string();
        assert!(asm.contains("CHECKSIGADD"), "asm: {asm}");
        assert!(asm.contains("GREATERTHANOREQUAL"), "asm: {asm}");
        assert!(asm.contains("DROP"), "asm: {asm}");
    }

    #[test]
    fn recovery_script_shape() {
        let s = recovery_leaf_script(demo_keys::recovery_key()).unwrap();
        let asm = s.to_string();
        assert!(
            asm.contains("CHECKSEQUENCEVERIFY") || asm.contains("CSV"),
            "asm: {asm}"
        );
    }

    #[test]
    fn emergency_leaf_is_fourth_mast_branch_with_embedded_commitment() {
        let secp = Secp256k1::verification_only();
        let v = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();
        // The emergency key is hidden behind its SHA-256 commitment...
        let em = demo_keys::emergency_kit_key();
        let bytes = v.leaves.emergency.as_bytes();
        assert_eq!(bytes.len(), 37);
        assert!(!bytes.windows(32).any(|w| w == em.serialize()));
        use bitcoin::hashes::{sha256, Hash};
        let digest = sha256::Hash::hash(&em.serialize()).to_byte_array();
        assert!(bytes.windows(32).any(|w| w == digest));
        // ...the leaf is a real MAST branch: hash present and control block derivable.
        let leaf_hash = TapLeafHash::from_script(&v.leaves.emergency, LeafVersion::TapScript);
        assert!(v.leaf_hashes.contains(&leaf_hash));
        assert!(v
            .spend_info
            .control_block(&(v.leaves.emergency.clone(), LeafVersion::TapScript))
            .is_some());
        // Derivation is deterministic (protocol constant, like the NUMS point).
        let v2 = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();
        assert_eq!(v.leaves.emergency, v2.leaves.emergency);
        assert_eq!(v.merkle_root(), v2.merkle_root());
    }

    #[test]
    fn emergency_leaf_script_shape_is_within_bip342_element_limits() {
        let s = emergency_leaf_script(demo_keys::emergency_kit_key());
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 37);
        // Push opcodes are ≤ 33-byte pushes (0x20 = 32-byte push): no push in
        // the script can ever create a >520-byte stack element.
        assert!(bytes.windows(32).any(|w| w == {
            use bitcoin::hashes::{sha256, Hash};
            sha256::Hash::hash(&demo_keys::emergency_kit_key().serialize()).to_byte_array()
        }));
    }

    /// BIP-360 (docs/11): the experimental P2MR address commits to the SAME
    /// merkle root with witness version 2 — no internal key, no tweak.
    #[test]
    fn p2mr_experimental_address_is_witness_v2_over_the_merkle_root() {
        use bitcoin::hashes::Hash;
        let secp = Secp256k1::verification_only();
        let v = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();

        let addr = v.p2mr_address_experimental(Network::Bitcoin).unwrap();
        let encoded = addr.to_string();
        // BIP-360: SegWit v2 ⇒ bech32m prefix `z` (bc1z…), never bc1p/bc1q.
        assert!(encoded.starts_with("bc1z"), "addr: {encoded}");

        // The witness program IS the merkle root (32 bytes), version 2.
        let program = addr.witness_program().expect("witness program present");
        assert_eq!(program.version(), bitcoin::WitnessVersion::V2);
        assert_eq!(
            program.program().as_bytes(),
            v.merkle_root().unwrap().to_byte_array().as_slice(),
            "P2MR program = script-tree merkle root (no tap tweak)"
        );

        // The catch-all HRP arm: every other network wraps the SAME program
        // with the testnets prefix (signet → tb1z…), one call, no re-derive.
        let snet = v.p2mr_address_experimental(Network::Signet).unwrap();
        assert!(snet.to_string().starts_with("tb1z"), "signet: {snet}");
        assert_eq!(
            snet.witness_program().unwrap().program().as_bytes(),
            program.program().as_bytes()
        );

        // Same tree ⇒ P2TR and P2MR share the merkle root; only the wrapping
        // differs. Control block shrinks by the omitted internal key: at the
        // demo tree's depth 2, 33+32·2 = 97 B (P2TR) → 1+32·2 = 65 B (P2MR).
        let p2tr_control = v
            .spend_info
            .control_block(&(v.leaves.normal.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize()
            .len();
        assert_eq!(p2tr_control, 97);
        assert_eq!(p2tr_control - 32, 65, "P2MR control block at depth 2");

        // Deterministic and distinct from the P2TR address of the same tree.
        assert_eq!(
            v.p2mr_address_experimental(Network::Bitcoin)
                .unwrap()
                .to_string(),
            encoded
        );
        assert_ne!(v.address(Network::Bitcoin).to_string(), encoded);
        // Regtest HRP works too.
        assert!(v
            .p2mr_address_experimental(Network::Regtest)
            .unwrap()
            .to_string()
            .starts_with("bcrt1z"));
    }

    /// docs/10 §4.59 — the watch-only export must describe THIS output:
    /// both descriptors checksummed, both expanding to the vault's own
    /// scriptPubKey, on every network.
    #[test]
    fn watch_descriptors_pin_the_exact_output() {
        use miniscript::descriptor::checksum::verify_checksum;

        let secp = Secp256k1::verification_only();
        let v = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();

        for net in [
            Network::Regtest,
            Network::Bitcoin,
            Network::Signet,
            Network::Testnet,
        ] {
            let w = v.watch_descriptors(net).expect("watch-only export");
            let addr_s = v.address(net).to_string();

            // addr(): the same address every other command reports, checksummed.
            assert!(
                w.addr_descriptor.starts_with(&format!("addr({addr_s})#")),
                "{}",
                w.addr_descriptor
            );
            let bare = verify_checksum(&w.addr_descriptor).expect("addr checksum verifies");
            assert_eq!(bare, format!("addr({addr_s})"));

            // rawtr(): the TWEAKED output key (not the NUMS internal key).
            assert!(
                w.rawtr_descriptor
                    .starts_with(&format!("rawtr({})#", v.output_key())),
                "{}",
                w.rawtr_descriptor
            );
            let bare = verify_checksum(&w.rawtr_descriptor).expect("rawtr checksum verifies");
            assert_eq!(bare, format!("rawtr({})", v.output_key()));

            // ...and both name the output the vault actually pays to.
            assert_eq!(w.address.to_string(), addr_s);
            assert_eq!(w.address.script_pubkey(), w.script_pubkey);
            assert_eq!(
                Address::from_script(&w.script_pubkey, net).unwrap(),
                w.address
            );
            assert!(!w.addr_descriptor.starts_with("tr("));
            assert!(!w.rawtr_descriptor.starts_with("tr("));
        }
    }

    /// The REASON §4.59 exports `addr()`/`rawtr()` instead of `tr()`: three
    /// of the four leaves are not miniscript. Leaf 1 IS (positive control),
    /// so if miniscript ever grows the missing expressiveness this test goes
    /// red and says so — the export should then become a real `tr()`.
    #[test]
    fn three_of_four_leaves_are_not_miniscript_so_no_tr_descriptor() {
        use miniscript::{Miniscript, Tap};

        let compile = |s: &str| -> Option<bitcoin::ScriptBuf> {
            s.parse::<Miniscript<XOnlyPublicKey, Tap>>()
                .ok()
                .map(|m| m.encode())
        };

        let secp = Secp256k1::verification_only();
        let v = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[demo_keys::heir_one(), demo_keys::heir_two()],
            2,
        )
        .unwrap();

        // Positive control: leaf 1 is byte-for-byte miniscript.
        let normal = compile(&format!(
            "and_v(v:pk({}),pk({}))",
            demo_keys::user_key(),
            demo_keys::enclave_key()
        ));
        assert_eq!(
            normal.as_ref(),
            Some(&v.leaves.normal),
            "leaf 1 must remain miniscript-expressible (control)"
        );

        // Leaf 2: `<144> CSV DROP <pk> CHECKSIG` — miniscript can only emit
        // `<n> CSV VERIFY` for the closest fragment (different bytes ⇒ a
        // different leaf hash ⇒ a DIFFERENT address).
        let recovery = compile(&format!(
            "and_v(v:older({}),pk({}))",
            crate::policy::RECOVERY_CSV_BLOCKS,
            demo_keys::recovery_key()
        ));
        assert_ne!(
            recovery.as_ref(),
            Some(&v.leaves.recovery),
            "recovery leaf became miniscript-expressible — upgrade the export to tr() (docs/10 §4.59)"
        );

        // Leaf 3: same `<n> CSV DROP` prefix over the multi_a body.
        let inheritance = compile(&format!(
            "and_v(v:older({}),multi_a(2,{},{},{}))",
            crate::policy::INHERITANCE_CSV_BLOCKS,
            demo_keys::heir_one(),
            demo_keys::heir_two(),
            demo_keys::executor_key()
        ));
        assert_ne!(
            inheritance.as_ref(),
            Some(&v.leaves.inheritance),
            "inheritance leaf became miniscript-expressible — upgrade the export to tr() (docs/10 §4.59)"
        );

        // Leaf 4: SHA-256 commit-reveal. The closest fragment, pk_h, hashes
        // with HASH160 and is refused outright in tapscript context.
        let emergency = compile(&format!("pk_h({})", demo_keys::emergency_kit_key()));
        assert_ne!(
            emergency.as_ref(),
            Some(&v.leaves.emergency),
            "emergency leaf became miniscript-expressible — upgrade the export to tr() (docs/10 §4.59)"
        );
    }
}
