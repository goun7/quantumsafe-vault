# Module 03 — Bitcoin Taproot, Miniscript & the Two-Layer Hybrid Vault

> Specification module 03 of QuantumSafe-Vault — v2026.3.

## 1. Introduction and architectural vision

Off-the-shelf vault designs either lean on consensus proposals that are still unactivated (`OP_VAULT` BIP-345, `OP_CHECKTEMPLATEVERIFY` BIP-119) or leave elliptic-curve keys exposed behind a plain multisig. QuantumSafe-Vault combines **BIP-341 Taproot** merkle trees with the **BIP-379 Miniscript** discipline on today's mainnet: one indistinguishable output, four auditable spending policies, and a key path that is *provably* unspendable. The result is a vault that needs no soft fork now, and maps one-to-one onto BIP-360 (P2MR) when activation arrives.

## 2. BIP-341 Taproot mathematics and NUMS isolation

A P2TR output commits to `Q = P + t·G` where `P` is the internal key and `t` the taproot tweak. If `P` were a key we controlled, the key path would bypass every script rule. Instead `P` is a **NUMS (nothing-up-my-sleeve) point**: `SHA-256(seed-text || LE32(c))` for the smallest canonical counter `c`, with the exact counter frozen by test. No discrete log for that point is known to anyone — including us — so the key path is *mathematically* dead rather than merely unused (Theorem 2), and every spend must reveal which leaf was used. The derivation, the canonical counter and the address encoding live in `nums.rs` / `taproot.rs`.

## 3. Taproot MAST leaf tree topology

```
P2TR(NUMS_internal_key) — merkle root m, balanced Huffman tree (depth 2)
 ├─ Leaf 1 (normal):      2-of-2 hybrid   <user> CHECKSIGVERIFY <enclave> CHECKSIG
 ├─ Leaf 2 (recovery):    CSV 144 blocks (~24 h)  <cold-sweep>
 ├─ Leaf 3 (inheritance): CSV 26,280 blocks (~180 d) + 2-of-3 heirs (multi_a)
 └─ Leaf 4 (emergency):   WOTS+-sealed kit, 37 B commit-reveal (SHA-256 only)
```

Four equally weighted leaves ⇒ depth 2 ⇒ control block `33 + 32·2 = 97 B` per input. Each leaf is consensus-verified through libbitcoinconsensus (T7), the policy keys and CSV constants are checked against the compiled tree (T8), and witness elements stay ≤ 520 B (BIP-342). Address derivation yields mainnet/signet/testnet/regtest addresses from one policy; the experimental P2MR (`bc1z`) form is derived from the same root (Module 11).

## 4. BIP-379 Miniscript policy and compiled byte code

Miniscript models spending conditions formally so that composition, resource bounds and sighash scope are *compiler-verified* instead of eyeballed. The vault policy compiles under the Tap context into the leaf scripts of §3; `policy.rs` holds the canonical template, and the compiled byte code is what the estate letter prints and `verify-estate` re-derives byte-for-byte. Property that matters here: a Miniscript analysis can prove a leaf is satisfiable only with the intended key sets — which is exactly what T8 asserts for all four leaves (6 keys, 2 CSV locks, 4 control blocks).

## 5. Hardware TEE and PQC enclave co-signer architecture

The service that validates the user's local ML-DSA-65 signature and returns the second Bitcoin Schnorr signature is isolated in a **trusted execution environment** (AWS Nitro Enclave / Intel TDX): no interactive shell, no persistent storage, measured boot, attestation-bound policy. The enclave holds only the gate seed; it releases its BIP-340 co-signature **solely** over the exact sighash it was shown, and only after a fail-closed ML-DSA-65 verification (`enclave_sign_if_pqc_valid`). A tampered proof, a wrong message or a malformed key all end in denial. Design rule: *no code path may ever give the service unilateral spend capability* — the enclave cannot choose destinations (covenant-pinned) and cannot spend without the user's key.

## 6. Two-stage covenant cancelling mempool sniffing

**Status of this section: the mechanism is a convention, not a covenant — see §6.1.**
Taproot scripts cannot constrain a transaction's outputs. What this repository
actually provides is a BUILDER that pays the single staging output, plus four
independent spending paths; a stolen key can broadcast a transaction that pays
anyone. The paragraph below is the INTENDED Phase-2 design (CTV/APO-class
covenants), not the behaviour of this tree.

1. **Stage 1 (unvault, builder-enforced):** `unvault::build_unvault_tx`
   constructs exactly one output, the staging script. Consensus does not
   enforce this: leaf 1 is `<pk_user> CHECKSIGVERIFY <pk_enclave> CHECKSIG`
   with no output constraint, so a hostile builder can pay any address.
2. **Stage 2 (CSV 144, mislabelled as a window):** the recovery leaf is
   `<144> CSV DROP <pk_recovery> CHECKSIG` on the VAULT output. It becomes
   available 144 blocks after each refresh and then stays available forever;
   it cannot reach the staging output at all, which is a plain single-key
   script. There is no veto window in flight.

### 6.1. Correction (Round 41 audit): what the scripts do and do not enforce

Measured, not argued:

- **No output pinning.** A transaction spending leaf 1 with a valid
  user+enclave witness and paying an arbitrary attacker address is ACCEPTED by
  `libbitcoinconsensus` (`VERIFY_ALL_PRE_TAPROOT | VERIFY_TAPROOT`). Probe:
  build the dishonest unvault, sign it with the two demo keys, call
  `consensus::verify_input` → `Ok(())`.
- **No clawback.** The recovery key can spend the vault output (after 144
  blocks of output age, i.e. almost always); it has no path to the staging
  output and no way to cancel a settlement.
- **No single-veto window.** `dashboard::vault_status` counts
  `144 - age` and the console prints it as "the sweep path stays open this
  long"; the script's semantics are the opposite — the path OPENS at 144 and
  never closes. The estate letter's "Clawback veto window: first 144 blocks
  after unvault" describes a mechanism that does not exist.

Consequence for the threat model: with a stolen user key and quantum-forged
enclave co-signature, the attacker pays themselves directly. The
mempool-sniffing/RBF argument above therefore does not hold for this tree.
A real covenant needs `OP_CTV` (BIP-119) or an equivalent consensus rule; the
Phase-2 plan in [`docs/11`](11_p2mr_migration_plan.md) has to carry it.

## 7. BIP-360 (P2MR) and roadmap alignment (February 2026)

**BIP-360 "Pay-to-Merkle-Root (P2MR)"** (H. Beast, E. Heilman, I. Foxen Duke) merged into the BIP repository in **February 2026**: it keeps P2TR functionality while removing the key-path spend at consensus level (SegWit v2, `bc1z`, program = merkle root, control block `1 + 32·m`). QuantumSafe-Vault's architecture is already the protocol-level mirror of that rule — NUMS cancels the key path mathematically — so migration is an output-wrapper change: leaves, CSV constants and the 520 B rule are untouched, control block shrinks 97 → 65 B. The migration plan, phases 4a–4e and gates K1–K3 live in Module 11, with `qsv-cli bip360-status` tracking the BIP header against the recorded snapshot.

## 8. Core reference implementation (`qsv-core`)

This specification is synchronized with the Rust workspace in the repository root:

| Paper concept | Module |
|---|---|
| NUMS derivation & canonical counter | `nums.rs` |
| Policy → Miniscript compilation | `policy.rs` |
| MAST leaves, addresses, P2MR experiment | `taproot.rs` |
| Two-stage covenant, Schnorr signing | `unvault.rs` |
| BIP-174/371 hardware round-trip | `psbt.rs` |
| Heartbeat / dead-man's switch | `heartbeat.rs` |
| Heir commitments, PQC identities | `heirs.rs`, `qsv-pqc` |
| WOTS+ emergency layer & parameter study | `wots.rs` |
| Per-leaf budget (weight, fees, 520 B) | `budget.rs` |
| Share formats (native + SLIP-0039) | `shamir.rs`, `slip39.rs` |
| Estate letter + independent verification | `estate.rs` |
| Consensus-level verification | `consensus.rs` (feature `consensus`) |
| BIP-360 K1 tracker | `bip360.rs` |

## 9. Zero-HITL automation and minimum human control points

> This section is the normative counterpart of the "zero-HITL principle, Document 03 §9" references in `heartbeat.rs`, `qsv-pqc` and Document 10 (consistent with Project Sheet §9).

**§9.1 — inside zero-HITL (deterministic code):** heartbeat refresh scheduling (every 12,960 blocks ≈ 90 d), unvault co-signing behind the ML-DSA gate, CSV/veto clock evaluation, dashboard status derivation and every verification step (`verify-estate`, consensus checks, PSBT sighash recomputation). None of these require a human, and none of them may silently degrade — each failure path exits non-zero.

**§9.2 — the four irreducible human touchpoints:** (1) signing the unvault transaction (owner intent), (2) exercising the veto/clawback inside 144 blocks, (3) opening the sealed emergency kit, (4) the yearly `verify-estate` audit of the printed letter. Everything else is automation; these four are deliberately human because they are the intent decisions the protocol exists to protect.
