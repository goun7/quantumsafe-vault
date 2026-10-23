//! ROUND 27 — property-based tests (proptest) for the three surfaces whose
//! correctness must hold for EVERY input, not just the hand-picked vectors:
//!
//!   1. the two-stage unvault covenant (value conservation + dust refusal),
//!   2. the Miniscript vault policy (branch guards for arbitrary key sets),
//!   3. the SLIP-0039 codec (roundtrip for any valid parameter set, and
//!      fail-closed behaviour for every invalid one).
//!
//! Each property encodes the invariant the example tests assert for a few
//! fixed inputs; proptest searches the input space and shrinks any
//! counterexample to a minimal one.

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, ScriptBuf, Txid};
use miniscript::descriptor::DescriptorPublicKey;
use miniscript::miniscript::decode::Terminal;
use miniscript::miniscript::{Miniscript, Tap};
use proptest::prelude::*;
use qsv_core::demo_keys;
use qsv_core::policy::{self, Pk};
use qsv_core::slip39::{self, GroupSpec, Slip39Error};
use qsv_core::unvault;
use std::str::FromStr;

/// 21M BTC in sats — the consensus ceiling; no transaction may exceed it.
const MAX_MONEY_SATS: u64 = 21_000_000 * 100_000_000;
/// Dust threshold for a Taproot P2TR output (the staging/final scripts).
const P2TR_DUST_SATS: u64 = 546;
/// Dust threshold used by the settlement builder (Phase-1 single-key output).
const SETTLE_DUST_SATS: u64 = 330;

fn desc_pk(seed: &str) -> Pk {
    let kp = demo_keys::demo_keypair(seed);
    let pk = secp256k1::PublicKey::from_keypair(&kp);
    DescriptorPublicKey::from_str(&pk.to_string()).expect("raw compressed pubkey parses")
}

fn staging_spk() -> ScriptBuf {
    unvault::staging_script(demo_keys::recovery_key())
}

/// Counts EVERY key the compiler may emit — `pk` (PkK), `pkh` (PkH) and
/// the `multi_a` threshold (MultiA/Multi). `policy::count_pk_checks`
/// only counts `PkK`, but the miniscript compiler freely rewrites
/// `thresh(m, pk…)` into `multi_a(m, …)` and `pk` into `pkh`; a property
/// that wants to prove "no key was dropped" (a dropped key = a stuck
/// vault) must count all three shapes.
fn count_all_keys(ms: &Miniscript<Pk, Tap>) -> usize {
    ms.iter()
        .map(|n| match &n.node {
            Terminal::PkK(_) | Terminal::PkH(_) => 1,
            Terminal::Multi(keys) => keys.n(),
            Terminal::MultiA(keys) => keys.n(),
            _ => 0,
        })
        .sum()
}

// ─────────────────────────────────────────────────────────────────────
// 1. Unvault covenant — value conservation, dust refusal, CSV encoding
// ─────────────────────────────────────────────────────────────────────

proptest! {
    /// Stage-1 unvault: exactly one input, one output, the output is
    /// `value - fee` whenever the tx exists, and it exists exactly when
    /// that amount clears dust. No input value may ever be created.
    #[test]
    fn unvault_tx_conserves_value_and_refuses_dust(
        value in 0u64..=MAX_MONEY_SATS,
        fee in 0u64..=MAX_MONEY_SATS,
        vout in 0u32..16,
        txid in any::<[u8; 32]>(),
    ) {
        let outpoint = OutPoint::new(Txid::from_byte_array(txid), vout);
        let result = unvault::build_unvault_tx(
            outpoint,
            Amount::from_sat(value),
            &staging_spk(),
            Amount::from_sat(fee),
        );

        let affordable = fee <= value && value - fee >= P2TR_DUST_SATS;
        prop_assert_eq!(
            result.is_ok(),
            affordable,
            "fee={} value={}",
            fee,
            value
        );

        if let Ok(tx) = result {
            prop_assert_eq!(tx.input.len(), 1);
            prop_assert_eq!(tx.output.len(), 1);
            prop_assert_eq!(tx.input[0].previous_output, outpoint);
            prop_assert_eq!(tx.output[0].value.to_sat(), value - fee);
            // Input sats = output sats + fee: value is never created.
            prop_assert_eq!(
                tx.output[0].value.to_sat() + fee,
                value,
                "conservation of value"
            );
            prop_assert_eq!(&tx.output[0].script_pubkey, &staging_spk());
        }
    }

    /// Stage-2 settlement: same conservation, plus the input sequence
    /// MUST be the BIP-68 height lock the caller asked for (the CSV is
    /// the covenant — an encoding slip would make the spend immediate).
    #[test]
    fn settlement_tx_encodes_csv_and_conserves_value(
        value in 0u64..=MAX_MONEY_SATS,
        fee in 0u64..=MAX_MONEY_SATS,
        csv_blocks in 0u16..=u16::MAX,
        txid in any::<[u8; 32]>(),
    ) {
        let outpoint = OutPoint::new(Txid::from_byte_array(txid), 7);
        let result = unvault::build_settlement_tx(
            outpoint,
            Amount::from_sat(value),
            &staging_spk(),
            Amount::from_sat(fee),
            csv_blocks,
        );

        let affordable = fee <= value && value - fee >= SETTLE_DUST_SATS;
        prop_assert_eq!(
            result.is_ok(),
            affordable,
            "fee={} value={}",
            fee,
            value
        );

        if let Ok(tx) = result {
            prop_assert_eq!(tx.output[0].value.to_sat(), value - fee);
            let seq = tx.input[0].sequence;
            // The CSV value survives the roundtrip bit-for-bit …
            prop_assert_eq!(seq.to_consensus_u32(), u32::from(csv_blocks));
            // … and it is a LIVE relative height lock (BIP-68 disable bit
            // clear), never an accidentally-disabled sequence.
            prop_assert!(seq.is_relative_lock_time(), "CSV must be enabled");
            prop_assert!(seq.is_height_locked(), "CSV must be block-based");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// 2. Vault policy — guards hold for any key set
// ─────────────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// The full policy compiles for any 2+ heir set and ALWAYS carries
    /// both timelocks (144 recovery / 26,280 inheritance) plus every key:
    /// `count_pk_checks == user + enclave + recovery + heirs + executor`.
    #[test]
    fn vault_policy_keeps_both_timelocks_and_every_key(
        n_heirs in 2usize..=10,
        seed_salt in any::<u64>(),
    ) {
        let s = seed_salt.to_string();
        let input = policy::VaultPolicyInput {
            key_user: desc_pk(&format!("proptest/user/{s}")),
            key_enclave: desc_pk(&format!("proptest/enclave/{s}")),
            key_recovery: desc_pk(&format!("proptest/recovery/{s}")),
            key_heirs: (0..n_heirs)
                .map(|i| desc_pk(&format!("proptest/heir/{s}/{i}")))
                .collect(),
            key_executor: desc_pk(&format!("proptest/executor/{s}")),
        };
        let ms = policy::compile_vault_policy(&input)
            .expect("any 2+ heir key set must compile");
        prop_assert!(
            policy::contains_older_check(&ms, policy::RECOVERY_CSV_BLOCKS),
            "144-block recovery timelock missing"
        );
        prop_assert!(
            policy::contains_older_check(&ms, policy::INHERITANCE_CSV_BLOCKS),
            "26280-block inheritance timelock missing"
        );
        prop_assert_eq!(
            count_all_keys(&ms),
            n_heirs + 4,
            "user+enclave+recovery+heirs+executor — a dropped key is a stuck vault"
        );
    }

    /// Fewer than 2 heirs can never compile — the 2-of-n threshold is
    /// structurally impossible, and the error must be fail-closed.
    #[test]
    fn vault_policy_refuses_singleton_heirs(n_heirs in 0usize..=1, seed_salt in any::<u64>()) {
        let s = seed_salt.to_string();
        let input = policy::VaultPolicyInput {
            key_user: desc_pk(&format!("proptest/u2/{s}")),
            key_enclave: desc_pk(&format!("proptest/e2/{s}")),
            key_recovery: desc_pk(&format!("proptest/r2/{s}")),
            key_heirs: (0..n_heirs)
                .map(|i| desc_pk(&format!("proptest/h2/{s}/{i}")))
                .collect(),
            key_executor: desc_pk(&format!("proptest/x2/{s}")),
        };
        prop_assert_eq!(
            policy::compile_vault_policy(&input).map(|_| ()),
            Err(policy::PolicyError::NotEnoughHeirs)
        );
    }

    /// The normal hybrid leaf: two keys, zero timelocks (it is the
    /// immediate-spend branch), for arbitrary distinct keys.
    #[test]
    fn normal_leaf_is_two_keys_without_timelocks(seed_salt in any::<u64>()) {
        let s = seed_salt.to_string();
        let ms = policy::compile_normal_leaf(
            &desc_pk(&format!("proptest/nu/{s}")),
            &desc_pk(&format!("proptest/ne/{s}")),
        )
        .expect("any two keys compile");
        prop_assert_eq!(count_all_keys(&ms), 2);
        prop_assert!(!policy::contains_older_check(&ms, policy::RECOVERY_CSV_BLOCKS));
        prop_assert!(!policy::contains_older_check(&ms, policy::INHERITANCE_CSV_BLOCKS));
    }

    /// The inheritance leaf: the 26,280-block CSV is unconditional and
    /// every key of the k-of-n threshold appears exactly once.
    #[test]
    fn inheritance_leaf_threshold_behaviour(
        n_heirs in 2usize..=8,
        k in 0usize..=12,
        seed_salt in any::<u64>(),
    ) {
        let s = seed_salt.to_string();
        let heirs: Vec<Pk> = (0..n_heirs)
            .map(|i| desc_pk(&format!("proptest/ih/{s}/{i}")))
            .collect();
        let executor = desc_pk(&format!("proptest/ix/{s}"));
        let n_keys = n_heirs + 1; // heirs + executor
        let result = policy::compile_inheritance_leaf(&heirs, &executor, k);

        if k == 0 || k > n_keys {
            prop_assert!(
                result.is_err(),
                "k={} of {} must be rejected (got Ok)",
                k,
                n_keys
            );
        } else {
            let ms = result.expect("in-range k compiles");
            prop_assert!(
                policy::contains_older_check(&ms, policy::INHERITANCE_CSV_BLOCKS),
                "inheritance CSV missing"
            );
            prop_assert_eq!(count_all_keys(&ms), n_keys);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// 3. SLIP-0039 — roundtrip for any valid parameter set, fail-closed
//    otherwise
// ─────────────────────────────────────────────────────────────────────

/// Normalises arbitrary (threshold, members) draws into the valid
/// combinations the codec accepts: `1 ≤ threshold ≤ members ≤ 3`, with
/// threshold 1 requiring exactly one member.
fn arb_group_params(params: &[(u8, u8)], g: usize) -> Vec<GroupSpec> {
    params[..g]
        .iter()
        .map(|&(t, m)| {
            if t == 1 {
                GroupSpec::new(1, 1)
            } else {
                GroupSpec::new(t, m.max(t))
            }
        })
        .collect()
}

/// The official wordlist, used to build a single-word corruption that
/// still IS a word (checksum must catch it, not the dictionary).
const WORDLIST: &str = include_str!("../src/slip39_wordlist.txt");

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// split → (decode each share, re-encode it, combine the threshold
    /// subset) must reproduce the master secret for ANY valid parameter
    /// set, and every share mnemonic must be canonical: decode∘encode is
    /// the identity on the wire format.
    #[test]
    fn slip39_roundtrips_any_valid_parameters(
        secret in prop::collection::vec(any::<u8>(), 16..=32).prop_map(|mut v| {
            if v.len() % 2 != 0 { v.pop(); }
            v
        }),
        g in 1usize..=3,
        gt in 1usize..=3,
        params in prop::collection::vec((1u8..=3, 1u8..=3), 3),
        passphrase in "[a-zA-Z0-9 _-]{0,12}",
    ) {
        let gt = gt.min(g);
        let groups = arb_group_params(&params, g);
        let share_set = slip39::split(&secret, gt as u8, &groups, &passphrase, 0)
            .expect("normalised parameters are valid");

        // Pick gt groups × their threshold members — the minimal legal set.
        let picked: Vec<String> = share_set
            .iter()
            .zip(&groups)
            .take(gt)
            .flat_map(|(mnemonics, grp)| {
                mnemonics.iter().take(usize::from(grp.threshold)).cloned()
            })
            .collect();
        prop_assert!(!picked.is_empty());

        // Canonical wire format: decode∘encode is the identity.
        for m in &picked {
            let share = slip39::decode_share(m).expect("share decodes");
            let re = slip39::encode_share_mnemonic(&share).expect("share re-encodes");
            prop_assert_eq!(&re, m, "mnemonic must be canonical");
            prop_assert_eq!(share.group_threshold as usize, gt);
            prop_assert_eq!(share.group_count as usize, g);
        }

        // Roundtrip: the threshold subset recovers the exact secret.
        let refs: Vec<&str> = picked.iter().map(String::as_str).collect();
        let recovered = slip39::combine(&refs, &passphrase)
            .expect("threshold subset combines");
        prop_assert_eq!(recovered, secret, "split∘combine must be the identity");
    }

    /// A single-word corruption (to ANOTHER valid word) must be caught:
    /// RS1024 detects every one-word error, so combine fails CLOSED —
    /// never a wrong secret, never a panic.
    #[test]
    fn slip39_single_word_corruption_fails_closed(
        secret in prop::collection::vec(any::<u8>(), 16..=32),
        word_i in 0usize..20,
        passphrase in "[a-z]{0,8}",
    ) {
        let mut secret = secret;
        if secret.len() % 2 != 0 { secret.pop(); }
        prop_assume!(secret.len() >= 16);

        let group = [GroupSpec::new(2, 3)];
        let share_set = slip39::split(&secret, 1, &group, &passphrase, 0)
            .expect("2-of-3 split");
        let mut words: Vec<String> = share_set[0][0].split_whitespace()
            .map(str::to_owned)
            .collect();
        prop_assume!(words.len() >= 20);

        let list: Vec<&str> = WORDLIST.split_whitespace().collect();
        let at = word_i % words.len();
        let cur = list.iter().position(|w| *w == words[at])
            .expect("emitted word comes from the wordlist");
        // Substitute a DIFFERENT real word — only the checksum can catch it.
        let substitute = list[(cur + 1) % list.len()];
        words[at] = substitute.to_owned();

        let corrupted: Vec<String> = share_set[0]
            .iter()
            .enumerate()
            .map(|(i, m)| {
                if i == 0 { words.join(" ") } else { m.clone() }
            })
            .collect();
        let refs: Vec<&str> = corrupted.iter().map(String::as_str).collect();

        let result = slip39::combine(&refs, &passphrase);
        prop_assert!(
            result.is_err(),
            "a corrupted share must never combine (got {:?})",
            result.map(|v| v.len())
        );
    }

    /// Wrong passphrase → either an error or a DIFFERENT secret; the
    /// recovery must never silently hand back the original secret.
    #[test]
    fn slip39_wrong_passphrase_never_leaks_the_secret(
        secret in prop::collection::vec(any::<u8>(), 16..=32),
        passphrase in "[a-z]{0,10}",
        salt in "[a-z]{1,4}",
    ) {
        let mut secret = secret;
        if secret.len() % 2 != 0 { secret.pop(); }
        prop_assume!(secret.len() >= 16);

        let group = [GroupSpec::new(2, 3)];
        let share_set = slip39::split(&secret, 1, &group, &passphrase, 0)
            .expect("2-of-3 split");
        let refs: Vec<&str> = share_set[0].iter().map(String::as_str).collect();

        let wrong = format!("{passphrase}{salt}");
        prop_assume!(wrong != passphrase);
        match slip39::combine(&refs, &wrong) {
            Err(_) => { /* fail-closed: fine */ }
            Ok(recovered) => prop_assert_ne!(
                recovered,
                secret,
                "wrong passphrase must not yield the original secret"
            ),
        }
    }

    /// Secret-length preconditions are enforced, not guessed: Ok exactly
    /// when the secret is ≥16 bytes and even.
    #[test]
    fn slip39_rejects_bad_secret_lengths(
        len in 0usize..=24,
        byte in any::<u8>(),
    ) {
        let secret = vec![byte; len];
        let result = slip39::split(&secret, 1, &[GroupSpec::new(1, 1)], "", 0);
        let valid = len >= 16 && len % 2 == 0;
        prop_assert_eq!(result.is_ok(), valid, "len={}", len);
        if let Err(e) = result {
            prop_assert!(
                matches!(e, Slip39Error::Parameters(_)),
                "length violations are parameter errors, got {:?}",
                e
            );
        }
    }

    /// Iteration exponent > 15 is out of range — refuse before any
    /// PBKDF2 work (a hostile exponent would be a DoS, not a slow KDF).
    #[test]
    fn slip39_rejects_absurd_iteration_exponents(
        secret in prop::collection::vec(any::<u8>(), 16..=24),
        e in 16u8..=u8::MAX,
    ) {
        let mut secret = secret;
        if secret.len() % 2 != 0 { secret.pop(); }
        prop_assume!(secret.len() >= 16);
        let result = slip39::split(&secret, 1, &[GroupSpec::new(1, 1)], "", e);
        prop_assert!(
            matches!(result, Err(Slip39Error::Parameters(_))),
            "e={e} must be refused"
        );
    }
}
