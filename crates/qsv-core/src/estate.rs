//! Estate letter generation (docs/10 §7): a printable, self-contained
//! emergency & inheritance document produced deterministically from the vault
//! structure. No secrets are ever included — only public keys, commitments and
//! protocol constants — so the letter can be stored with any notary, bank box
//! or family member without creating a theft target.
//!
//! The letter is the bridge between the on-chain state and the humans who will
//! one day need it: it documents WHERE the money is (vault address), WHAT the
//! spending rules are (the four MAST leaves), WHO can act (heirs, executor,
//! emergency kit) and HOW to prove the letter matches the chain (merkle root,
//! output key, heir PQC commitments — all independently recomputable).
//!
//! Determinism: the same inputs always produce the same letter, so a printed
//! copy from 2026 can be diffed against a regenerated copy in 2046 to detect
//! tampering (any difference = re-derive the vault and compare the root).

use crate::heirs::HeirSet;
use crate::policy::{INHERITANCE_CSV_BLOCKS, RECOVERY_CSV_BLOCKS};
use crate::taproot::VaultTaproot;
use bitcoin::Network;

/// Inputs for [`estate_letter`]. Everything here is PUBLIC by design.
pub struct EstateLetterInput<'a> {
    /// Deriving vault (supplies the MAST leaves and merkle root).
    pub vault: &'a VaultTaproot,
    /// Bitcoin network for the rendered address.
    pub network: Network,
    /// Vault label (e.g. "Family main vault"); printed verbatim.
    pub label: &'a str,
    /// Verification date (ISO-8601, e.g. "2026-09-27"); printed verbatim.
    pub verification_date: &'a str,
    /// Verified heir registry (classic key ↔ PQC identity commitments).
    pub heirs: &'a HeirSet,
}

/// 26280 -> "26,280" (printable thousand separators for time constants).
fn with_commas(n: u32) -> String {
    let digits = n.to_string();
    let bytes = digits.as_bytes();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
}

/// Formats a hex column block for the heirs section (one row per heir).
fn heir_rows(heirs: &HeirSet) -> String {
    heirs
        .commitments_hex()
        .iter()
        .enumerate()
        .map(|(i, c)| format!("  heir #{}: sha256 commitment {}\n", i + 1, c))
        .collect()
}

/// Renders the full estate letter as plain text (printable, diff-stable).
///
/// Sections: header, vault identification, spending tree (all four leaves),
/// calendar constants, heir registry, emergency kit procedure, verification
/// instructions. Zero secrets by construction — the function has no access to
/// private key material at all.
pub fn estate_letter(inp: &EstateLetterInput<'_>) -> String {
    let address = inp.vault.address(inp.network).to_string();
    let merkle = inp
        .vault
        .merkle_root()
        .map(|h| h.to_string())
        .unwrap_or_else(|| "none".into());
    let output_key = hex::encode(inp.vault.output_key().serialize());
    let internal_key = hex::encode(inp.vault.internal_key.serialize());
    let heirs_block = heir_rows(inp.heirs);
    let normal_hex = hex::encode(inp.vault.leaves.normal.as_bytes());
    let recovery_hex = hex::encode(inp.vault.leaves.recovery.as_bytes());
    let inheritance_hex = hex::encode(inp.vault.leaves.inheritance.as_bytes());
    let emergency_hex = hex::encode(inp.vault.leaves.emergency.as_bytes());

    format!(
        "══════════════════════════════════════════════════════════════════\n\
         QUANTUMSAFE-VAULT · ESTATE LETTER\n\
         protocol v{version} · label: {label}\n\
         verification date: {date}\n\
         ══════════════════════════════════════════════════════════════════\n\
         \n\
         1. WHERE THE MONEY IS\n\
         Vault address ({network}): {address}\n\
         Output key (x-only):  {output_key}\n\
         Internal key (NUMS):  {internal_key}\n\
         Merkle root:          {merkle}\n\
         The NUMS internal key has no known discrete log (nothing-up-my-sleeve;\n\
         a SHA-256 preimage assumption, not a proof);\n\
         every spend is a script-path spend inside the tree committed by the\n\
         merkle root above.\n\
         \n\
         2. SPENDING RULES (MAST leaves, all consensus-enforced)\n\
         Leaf 1 · normal hybrid spend (2-of-2 classical):\n               {normal_hex}\n\
         Leaf 2 · recovery / cold sweep (ONE key), usable {recovery_commas} blocks (≈24 h) after each refresh:\n               {recovery_hex}\n\
         Leaf 3 · inheritance, CSV {inheritance_commas} blocks (≈180 d) + heir threshold:\n               {inheritance_hex}\n\
         Leaf 4 · emergency kit (SHA-256 key commitment + classical Schnorr):\n               {emergency_hex}\n\
         Leaf 4 reveals its destination key only from the offline kit; the\n\
         on-chain digest binds that key. The signature it requires is still\n\
         classical BIP-340: leaf 4 is a HIDING mechanism, not a post-quantum\n\
         signature path. Witness elements stay ≤ 520 B (BIP-342).\n\
         \n\
         3. TIME CONSTANTS\n\
         Heartbeat refresh cadence: every 12,960 blocks (≈90 d) — resets the\n\
         inheritance clock; ran by scheduler, zero human action.\n\
         Inheritance lock: {inheritance_commas} blocks after last refresh.\n\
         Recovery key: usable once the vault output is {recovery_commas} blocks old,\n\
         then permanently. It cannot cancel or redirect a staged spend, and it\n\
         is a single key — there is no veto window in flight (docs/03 §6.1).\n\
         \n\
         4. WHO CAN ACT (heir registry, fail-closed PQC commitments)\n\
         {heirs_block}\
         Each heir's taproot key is hash-committed to an ML-DSA-65 (FIPS 204)\n\
         identity key at setup. A stolen classical key without the matching\n\
         PQC identity fails dispute resolution.\n\
         \n\
         5. EMERGENCY PROCEDURE (Q-Day or owner incapacitation)\n\
         a. Open the sealed WOTS+ kit (air-gapped machine only).\n\
         b. Verify the kit's WOTS+ seal against the digest inside leaf 4.\n\
         c. Follow the printed witness recipe; the chain sees only classical\n\
            Schnorr (64-byte signature, 32-byte key — both hash-survivable).\n\
         d. For the inheritance path, gather any {inheritance_threshold} of the registered\n\
            heirs' signatures after the CSV lock, or the executor's.\n\
         \n\
         6. VERIFYING THIS LETTER (independent recomputation)\n\
         Machine check: qsv-cli verify-estate --file <this letter> --network <network>\n\
         re-derives the vault from the protocol constants (docs/03) and compares\n\
         all §1 identity fields and the four §2 leaf scripts byte-for-byte\n\
         (8 checks; exit code 0 = authentic, 1 = tampered or rotated). With\n\
         --qr the generator appends a scannable block encoding §1 for a phone\n\
         camera cross-check. Any mismatch: re-run qsv-cli estate-letter from\n\
         the provisioning machine and investigate before relying on this copy.\n\
         ══════════════════════════════════════════════════════════════════\n",
        version = crate::VERSION,
        label = inp.label,
        date = inp.verification_date,
        network = match inp.network {
            Network::Bitcoin => "mainnet",
            Network::Regtest => "regtest",
            Network::Signet => "signet",
            _ => "testnet",
        },
        address = address,
        output_key = output_key,
        internal_key = internal_key,
        merkle = merkle,
        normal_hex = normal_hex,
        recovery_hex = recovery_hex,
        inheritance_hex = inheritance_hex,
        emergency_hex = emergency_hex,
        recovery_commas = with_commas(u32::from(RECOVERY_CSV_BLOCKS)),
        inheritance_commas = with_commas(u32::from(INHERITANCE_CSV_BLOCKS)),
        heirs_block = heirs_block,
        inheritance_threshold = 2,
    )
}

/// Short lowercase network name used in letters and verification output.
fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "mainnet",
        Network::Regtest => "regtest",
        Network::Signet => "signet",
        _ => "testnet",
    }
}

/// Identity fields parsed back out of a printed letter (`None` = missing).
/// Used by `qsv-cli verify-estate` to close the loop: print → store → later
/// independently re-derive and compare against the live vault structure.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedLetter {
    /// §1 vault address for the letter's network.
    pub address: Option<String>,
    /// §1 tweaked output key (x-only, hex).
    pub output_key: Option<String>,
    /// §1 NUMS internal key (hex).
    pub internal_key: Option<String>,
    /// §1 merkle root (hex).
    pub merkle_root: Option<String>,
    /// §2 leaf scripts 1..=4 (hex).
    pub leaves: [Option<String>; 4],
}

/// A non-empty token composed only of hex digits.
fn is_hex_token(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Value after the first `:` of a line, trimmed; empty → `None`.
fn value_after_colon(line: &str) -> Option<String> {
    line.split_once(':')
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Extracts the identity block (§1) and the four leaf hexes (§2) from letter
/// text. Line-based and dependency-free: only the documented section headers
/// are trusted as anchors; anything malformed stays `None` (never guessed).
pub fn parse_letter(text: &str) -> ParsedLetter {
    let mut out = ParsedLetter::default();
    let lines: Vec<&str> = text.lines().collect();
    for line in &lines {
        let t = line.trim_start();
        if t.starts_with("Vault address (") {
            out.address = value_after_colon(line);
        } else if t.starts_with("Output key (x-only)") {
            out.output_key = value_after_colon(line);
        } else if t.starts_with("Internal key (NUMS)") {
            out.internal_key = value_after_colon(line);
        } else if t.starts_with("Merkle root") {
            out.merkle_root = value_after_colon(line);
        }
    }
    // Leaf N · … header, then the next non-empty line must be the leaf hex.
    for (i, slot) in out.leaves.iter_mut().enumerate() {
        let marker = format!("Leaf {} ·", i + 1);
        if let Some(pos) = lines
            .iter()
            .position(|l| l.trim_start().starts_with(marker.as_str()))
        {
            for l in &lines[pos + 1..] {
                let v = l.trim();
                if v.is_empty() {
                    continue;
                }
                if is_hex_token(v) {
                    *slot = Some(v.to_ascii_lowercase());
                }
                break;
            }
        }
    }
    out
}

/// One verification outcome of a printed letter against the re-derived vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationCheck {
    /// Field being checked ("vault address", "leaf 3 script", …).
    pub label: &'static str,
    /// True iff the printed value equals the freshly derived value.
    pub ok: bool,
    /// Human-readable outcome; on mismatch both values are shown.
    pub detail: String,
}

fn field_check(label: &'static str, printed: &Option<String>, expected: &str) -> VerificationCheck {
    match printed {
        None => VerificationCheck {
            label,
            ok: false,
            detail: "field missing from letter".into(),
        },
        Some(p) if p.eq_ignore_ascii_case(expected) => {
            // Long hex (leaf scripts) is abbreviated for terminal readability;
            // the FULL value was still compared byte-for-byte.
            let shown = if expected.len() > 48 {
                format!("{}…", &expected[..40])
            } else {
                expected.to_string()
            };
            VerificationCheck {
                label,
                ok: true,
                detail: format!("{shown} ✓ matches re-derived vault"),
            }
        }
        Some(p) => VerificationCheck {
            label,
            ok: false,
            detail: format!("letter: {p} · derived: {expected}"),
        },
    }
}

/// Address check with a network hint: if the printed address does not match
/// the requested network but matches another one, the detail says which
/// network the letter was actually issued for (the #1 user mistake).
fn address_check(
    printed: &Option<String>,
    vault: &VaultTaproot,
    network: Network,
) -> VerificationCheck {
    let expected = vault.address(network).to_string();
    let base = field_check("vault address", printed, &expected);
    if base.ok {
        return base;
    }
    if let Some(p) = printed {
        for candidate in [
            Network::Bitcoin,
            Network::Signet,
            Network::Testnet,
            Network::Regtest,
        ] {
            if vault.address(candidate).to_string().eq_ignore_ascii_case(p) {
                return VerificationCheck {
                    label: "vault address",
                    ok: false,
                    detail: format!(
                        "issued for {} — re-run with --network {} (expected {expected})",
                        network_name(candidate),
                        network_name(candidate),
                    ),
                };
            }
        }
    }
    base
}

/// Verifies a printed letter against a freshly derived vault: every §1 field
/// and all four §2 leaf scripts are re-derived from the protocol constants
/// and compared byte-for-byte. Returns one check per field; an all-`ok` vec
/// means the letter is authentic and matches the live vault structure.
pub fn verify_letter(text: &str, vault: &VaultTaproot, network: Network) -> Vec<VerificationCheck> {
    let parsed = parse_letter(text);
    let mut checks = vec![
        address_check(&parsed.address, vault, network),
        field_check(
            "output key",
            &parsed.output_key,
            &hex::encode(vault.output_key().serialize()),
        ),
        field_check(
            "internal key (NUMS)",
            &parsed.internal_key,
            &hex::encode(vault.internal_key.serialize()),
        ),
        field_check(
            "merkle root",
            &parsed.merkle_root,
            &vault
                .merkle_root()
                .map(|h| h.to_string())
                .unwrap_or_else(|| "none".into()),
        ),
    ];
    let leaf_specs: [(&'static str, &bitcoin::ScriptBuf); 4] = [
        ("leaf 1 script", &vault.leaves.normal),
        ("leaf 2 script", &vault.leaves.recovery),
        ("leaf 3 script", &vault.leaves.inheritance),
        ("leaf 4 script", &vault.leaves.emergency),
    ];
    for (i, (label, script)) in leaf_specs.into_iter().enumerate() {
        checks.push(field_check(
            label,
            &parsed.leaves[i],
            &hex::encode(script.as_bytes()),
        ));
    }
    checks
}

/// Machine-readable identity record for the letter's QR block:
/// `QSV1|<network>|<address>|<merkle-root>|<output-key>` — 5 pipe-separated
/// fields a phone camera can capture from the printed page and compare
/// against a freshly derived vault (full verification = `verify-estate`).
pub fn qr_payload(vault: &VaultTaproot, network: Network) -> String {
    format!(
        "QSV1|{}|{}|{}|{}",
        network_name(network),
        vault.address(network),
        vault
            .merkle_root()
            .map(|h| h.to_string())
            .unwrap_or_else(|| "none".into()),
        hex::encode(vault.output_key().serialize()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo_keys;
    use bitcoin::secp256k1::Secp256k1;
    use qsv_pqc::PqcIdentity;
    fn demo_input<'a>(
        vault: &'a VaultTaproot,
        heirs: &'a HeirSet,
        label: &'a str,
        date: &'a str,
    ) -> EstateLetterInput<'a> {
        EstateLetterInput {
            vault,
            network: Network::Signet,
            label,
            verification_date: date,
            heirs,
        }
    }

    #[test]
    fn letter_contains_all_sections_and_is_secret_free() {
        let secp = Secp256k1::verification_only();
        let vault = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[demo_keys::heir_one(), demo_keys::heir_two()],
            2,
        )
        .unwrap();
        let pqc1 = PqcIdentity::from_seed(&[11u8; 32]);
        let pqc2 = PqcIdentity::from_seed(&[12u8; 32]);
        let heirs = HeirSet::build([
            (
                demo_keys::heir_one().serialize(),
                pqc1.verifying_key_bytes().to_vec(),
            ),
            (
                demo_keys::heir_two().serialize(),
                pqc2.verifying_key_bytes().to_vec(),
            ),
        ])
        .unwrap();

        let letter = estate_letter(&demo_input(
            &vault,
            &heirs,
            "Family main vault",
            "2026-09-27",
        ));

        // All six sections present.
        for section in [
            "1. WHERE THE MONEY IS",
            "2. SPENDING RULES",
            "3. TIME CONSTANTS",
            "4. WHO CAN ACT",
            "5. EMERGENCY PROCEDURE",
            "6. VERIFYING THIS LETTER",
        ] {
            assert!(letter.contains(section), "missing section: {section}");
        }
        // Vault identification binds the actual derived values.
        assert!(letter.contains(&vault.address(Network::Signet).to_string()));
        assert!(letter.contains(&hex::encode(vault.output_key().serialize())));
        assert!(letter.contains(&vault.merkle_root().unwrap().to_string()));
        // Protocol constants and heir commitments appear.
        assert!(letter.contains("26,280"));
        assert!(letter.contains("144"));
        assert!(letter.contains(&heirs.commitments_hex()[0]));
        // WOTS+ kit discipline documented.
        assert!(letter.contains("WOTS+"));
        // No secret-shaped material: the letter must not embed any 64-byte
        // hex secret-looking blob beyond public keys (spot check: no 'sk').
        assert!(!letter.to_lowercase().contains("secret key"));
    }

    #[test]
    fn letter_is_deterministic_and_label_sensitive() {
        let secp = Secp256k1::verification_only();
        let vault = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[], // default demo heirs + executor
            2,
        )
        .unwrap();
        let pqc1 = PqcIdentity::from_seed(&[21u8; 32]);
        let pqc2 = PqcIdentity::from_seed(&[22u8; 32]);
        let heirs = HeirSet::build([
            (
                demo_keys::heir_one().serialize(),
                pqc1.verifying_key_bytes().to_vec(),
            ),
            (
                demo_keys::heir_two().serialize(),
                pqc2.verifying_key_bytes().to_vec(),
            ),
        ])
        .unwrap();

        let a = estate_letter(&demo_input(&vault, &heirs, "Alpha", "2026-09-27"));
        let b = estate_letter(&demo_input(&vault, &heirs, "Alpha", "2026-09-27"));
        let c = estate_letter(&demo_input(&vault, &heirs, "Beta", "2026-09-27"));
        let d = estate_letter(&demo_input(&vault, &heirs, "Alpha", "2026-10-01"));

        assert_eq!(a, b, "same inputs must produce byte-identical letters");
        assert_ne!(a, c, "label must be bound into the letter");
        assert_ne!(a, d, "verification date must be bound into the letter");
    }

    /// Builds a demo vault + heir set + letter for the verification tests.
    fn demo_letter(network: Network) -> (VaultTaproot, String) {
        let secp = Secp256k1::verification_only();
        let vault = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();
        let pqc1 = PqcIdentity::from_seed(&[31u8; 32]);
        let pqc2 = PqcIdentity::from_seed(&[32u8; 32]);
        let heirs = HeirSet::build([
            (
                demo_keys::heir_one().serialize(),
                pqc1.verifying_key_bytes().to_vec(),
            ),
            (
                demo_keys::heir_two().serialize(),
                pqc2.verifying_key_bytes().to_vec(),
            ),
        ])
        .unwrap();
        let letter = estate_letter(&demo_input(&vault, &heirs, "Verify vault", "2026-09-28"));
        // demo_input fixes Signet; re-render for the requested network.
        let letter = if network == Network::Signet {
            letter
        } else {
            estate_letter(&EstateLetterInput {
                vault: &vault,
                network,
                label: "Verify vault",
                verification_date: "2026-09-28",
                heirs: &heirs,
            })
        };
        (vault, letter)
    }

    #[test]
    fn verify_letter_passes_for_an_authentic_letter_on_every_network() {
        for network in [
            Network::Bitcoin,
            Network::Signet,
            Network::Testnet,
            Network::Regtest,
        ] {
            let (vault, letter) = demo_letter(network);
            let checks = verify_letter(&letter, &vault, network);
            assert_eq!(checks.len(), 8, "4 identity fields + 4 leaf scripts");
            for c in &checks {
                assert!(c.ok, "{}: {}", c.label, c.detail);
            }
        }
    }

    #[test]
    fn tampered_or_truncated_letters_fail_closed_with_precise_labels() {
        let (vault, letter) = demo_letter(Network::Bitcoin);

        // Flip one character of the address → exactly that check fails.
        let mut tampered = letter.clone();
        let addr = vault.address(Network::Bitcoin).to_string();
        let pos = tampered.find(&addr).expect("address printed in letter");
        let replacement = if addr.ends_with('q') { "p" } else { "q" };
        tampered.replace_range(pos + addr.len() - 1..pos + addr.len(), replacement);
        let checks = verify_letter(&tampered, &vault, Network::Bitcoin);
        let failed: Vec<&VerificationCheck> = checks.iter().filter(|c| !c.ok).collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].label, "vault address");

        // Remove the merkle line → missing-field check fails, no panic.
        let truncated: String = letter
            .lines()
            .filter(|l| !l.trim_start().starts_with("Merkle root"))
            .collect::<Vec<_>>()
            .join("\n");
        let checks = verify_letter(&truncated, &vault, Network::Bitcoin);
        let failed: Vec<&VerificationCheck> = checks.iter().filter(|c| !c.ok).collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].label, "merkle root");
        assert!(failed[0].detail.contains("missing"));

        // A mangled leaf-4 hex → only leaf 4 fails.
        let mut mangled = letter.clone();
        let leaf4 = hex::encode(vault.leaves.emergency.as_bytes());
        let pos = mangled.find(&leaf4).expect("leaf 4 hex printed");
        mangled.replace_range(pos..pos + 2, "ff");
        let checks = verify_letter(&mangled, &vault, Network::Bitcoin);
        let failed: Vec<&VerificationCheck> = checks.iter().filter(|c| !c.ok).collect();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].label, "leaf 4 script");
    }

    #[test]
    fn wrong_network_verification_reports_the_correct_network() {
        let (vault, letter) = demo_letter(Network::Signet);
        // Verifier mistakenly assumes mainnet → address check must explain.
        let checks = verify_letter(&letter, &vault, Network::Bitcoin);
        let addr_check = checks.iter().find(|c| c.label == "vault address").unwrap();
        assert!(!addr_check.ok);
        assert!(
            addr_check.detail.contains("signet"),
            "hint must name the issuing network: {}",
            addr_check.detail
        );
        // The other seven fields still verify (they are network-independent).
        assert_eq!(checks.iter().filter(|c| !c.ok).count(), 1);
    }

    #[test]
    fn qr_payload_is_a_five_field_identity_record() {
        let secp = Secp256k1::verification_only();
        let vault = VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[],
            2,
        )
        .unwrap();
        let payload = qr_payload(&vault, Network::Bitcoin);
        let parts: Vec<&str> = payload.split('|').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "QSV1");
        assert_eq!(parts[1], "mainnet");
        assert_eq!(parts[2], vault.address(Network::Bitcoin).to_string());
        assert_eq!(parts[3], vault.merkle_root().unwrap().to_string());
        assert_eq!(parts[4], hex::encode(vault.output_key().serialize()));
        // Compact enough for a phone-scannable QR (≈200 bytes).
        assert!(payload.len() < 240, "payload {} bytes", payload.len());
    }

    #[test]
    fn letter_parsing_skips_blanks_and_testnets_render_as_testnet() {
        // `network_name` wildcard: Testnet4 (and Testnet) print as "testnet".
        let (vault, _) = demo_letter(Network::Bitcoin);
        let payload = qr_payload(&vault, Network::Testnet4);
        assert!(payload.contains("testnet"), "{payload}");
        let checks = verify_letter(&demo_letter(Network::Bitcoin).1, &vault, Network::Bitcoin);
        assert!(checks.iter().all(|c| c.ok), "{checks:?}");

        // A BLANK line between a leaf header and its hex must be skipped
        // (the parse loop's `continue` + back-edge), and the scan still
        // stops at the first non-hex line afterwards.
        let (_, letter) = demo_letter(Network::Bitcoin);
        let marker = "Leaf 1 ·";
        let pos = letter.find(marker).expect("leaf marker printed");
        let cut = pos + marker.len();
        let patched = format!("{}\n\n{}", &letter[..cut], &letter[cut..]);
        let patched_parsed = parse_letter(&patched);
        let plain_parsed = parse_letter(&letter);
        assert_eq!(patched_parsed.address, plain_parsed.address);
        assert!(
            plain_parsed.leaves[0].is_some(),
            "plain letter parses leaf 1"
        );
        assert!(
            patched_parsed.leaves[0].is_none(),
            "blank line skipped, header tail is not hex → scan stops"
        );

        // No leaf markers at all: the whole marker lookup misses (the
        // if-let's false path) and every leaf slot stays empty.
        let bare = parse_letter("no leaf markers at all\nVault address (mainnet): x");
        assert!(bare.leaves.iter().all(Option::is_none));
        assert_eq!(bare.address.as_deref(), Some("x"));

        // A letter WITHOUT an address line drives the address check down
        // its missing-field path (printed = None), not the candidate scan.
        let headless: String = letter
            .lines()
            .filter(|l| !l.trim_start().starts_with("Vault address"))
            .collect::<Vec<_>>()
            .join("\n");
        let checks = verify_letter(&headless, &vault, Network::Bitcoin);
        let addr = checks.iter().find(|c| c.label == "vault address").unwrap();
        assert!(!addr.ok);
        assert!(addr.detail.contains("missing"), "{}", addr.detail);
    }

    #[test]
    fn field_check_renders_short_matches_verbatim_and_long_ones_abbreviated() {
        // expected ≤ 48 chars → verbatim (the else arm).
        let chk = field_check("policy", &Some("2-of-3".into()), "2-of-3");
        assert!(chk.ok);
        assert!(chk.detail.contains("2-of-3 ✓ matches"), "{}", chk.detail);
        // expected > 48 chars → abbreviated with the ellipsis.
        let long = "f".repeat(64);
        let chk = field_check("leaf", &Some(long.clone()), &long);
        assert!(chk.ok);
        assert!(chk.detail.contains('…'));
        // Missing and mismatched fields carry their own details.
        assert_eq!(
            field_check("x", &None, "y").detail,
            "field missing from letter"
        );
        assert!(field_check("x", &Some("a".into()), "b")
            .detail
            .contains("letter: a · derived: b"));
    }
}
