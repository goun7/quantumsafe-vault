# MODULE 11: BIP-360 (P2MR) Migration Plan — Phase 4 Vault Conversion

> **Document Code:** `QSV-MIG-11`
> **Version:** v2026.3 · **Date:** 28 September 2026
> **Source:** BIP-360 *Pay-to-Merkle-Root (P2MR)*, **Draft v0.12.1** (bitcoin/bips, `bip-0360.mediawiki`; authors: Hunter Beast, Ethan Heilman, Isabel Foxen Duke; assigned 2024-12-18; requires BIP-340/341/342)
> **Scope:** Moving QuantumSafe-Vault's current P2TR (bc1p) structure to the P2MR (bc1z) output type upon BIP-360 activation: impact analysis, phased plan, test matrix, risks and decision gates.

<!-- BIP360-SNAPSHOT:BEGIN (machine-readable; audited by `qsv-cli bip360-status`) -->
```yaml
bip: 360
title: Pay-to-Merkle-Root (P2MR)
status: Draft
version: 0.12.1
assigned: 2024-12-18
requires: 340, 341, 342
weight-saving-wu: 32
impl-rust-bitcoin: none
impl-bitcoin-core: none
impl-hardware: none
impl-independent-count: 0
impl-reviewed: 2026-10-11
source: https://raw.githubusercontent.com/bitcoin/bips/master/bip-0360.mediawiki
retrieved: 2026-09-28
```
<!-- BIP360-SNAPSHOT:END -->

> **Tracker (K1):** The block above is machine-readable and audited by `qsv-cli bip360-status`: offline mode checks this document's own consistency (version, K1–K3, phases 4a–4e, honest status) AND compares the `weight-saving-wu` record against the REAL measurement (`budget::measured_p2mr_weight_saving_wu` — freshly measured from a reference spend), while `--online` compares the live BIP header at `source` field by field. **Any delta = exit code 1 = K1 is re-evaluated** (if the BIP text moves, the §7.5 arithmetic is questioned automatically). **Latest online re-check: 18 October 2026 — PASS** (`bip360-status --online` exit 0 · the live BIP is still v0.12.1 Draft · the snapshot has not moved since 2026-09-28).

---

## 1. BIP-360 (P2MR) — Status as of September 2026

**What it proposes.** P2MR is a new output type with "nearly the same functionality as P2TR"; the only difference is that the **key-path spend is removed at the consensus layer**. A P2MR output:

- carries **no internal key** and performs **no tap tweak**;
- witness program = **the script tree's merkle root itself** (32 bytes, "TapBranch"-tagged);
- uses **SegWit version 2** ⇒ mainnet prefix **`bc1z`** (bech32m; P2TR is `bc1p`);
- scriptPubKey: `OP_2 <32-byte merkle root>`;
- control block: **`[1 control byte + 32·m-byte merkle path]`** — unlike P2TR there is **no 32-byte internal key**; the control byte's parity bit is always **1**;
- initial-stack rules, tapscript, the OP_SUCCESSx upgrade path and annex support are **identical to P2TR**;
- **depth-0 (single-leaf) trees are anyone-can-spend** ⇒ at least two leaves are required/encouraged (our four-leaf tree already qualifies).

**Protection boundary (honest scope).** P2MR only mitigates **long-exposure** attacks — quantum key recovery against keys exposed on-chain for extended periods. Protection against **short-exposure** attacks (keys leaked from the mempool while a transaction awaits confirmation) is, per the BIP's own text, deferred to **future post-quantum signature proposals**. P2MR is not "quantum protection"; it is the **first step**.

**Ecosystem status (September 2026):**

| Event | Date | Note |
|---|---|---|
| BIP-360 (formerly P2QRH) merged into bitcoin/bips | Feb 2026 | Forbes: "Bitcoin's first step against quantum computers" |
| BTQ "Bitcoin Quantum" testnet v0.3.0 — first working BIP-360 implementation | Mar 2026 | P2MR outputs live on test network |
| Blockstream SHRINCS — first PQ-signed production transactions on Liquid (Simplicity) | Mar 2026 | Hash-based, WOTS+-cored; opcode proposal (OP_CHECKSHRINCS) presented Apr 2026 at OP_NEXT |
| Fidelity Digital Assets 2026 trends report cites BIP-360 + OP_CHECKSHRINCS momentum | May 2026 | Institutional attention |
| US federal phase-out of ECDSA | by 2035 (NIST IR 8547) | hybrid exemption |
| CNSA 2.0: software/networking equipment to PQ | 2030; browsers/OS 2033 | mandatory timeline |

The BIP is still **Draft**: activation version flags, end-to-end test vectors and final field names may change. This document is a migration plan **waiting on activation**; no consensus code is added to the repository before activation (no mocks, no speculation).

---

## 2. Why Migration Is Low-Risk for Our Vault

QuantumSafe-Vault already enforces P2MR's discipline by other means: the NUMS internal key **mathematically cancels** the key path (Theorem 2). P2MR moves that cancellation into consensus. Result: **the spending model does not change — only the output wrapper does.**

| Dimension | Today's P2TR (bc1p) | Target P2MR (bc1z) | Change |
|---|---|---|---|
| Key-path | cancelled by NUMS (mathematical) | cancelled by consensus (structural) | same outcome, stronger guarantee |
| Witness program | tweaked output key | the merkle root itself | address changes |
| NUMS internal key | required (for cancellation) | **retired** (structurally unnecessary) | simplification |
| Leaf scripts (1–4) | tapscript | **identical** (tapscript-native) | **ZERO change** |
| CSV constants (144 / 26,280) | in script | **identical** | ZERO change |
| Witness ≤520 B (BIP-342) | enforced | **same** initial-stack rules | ZERO change |
| Control block (depth 2) | 33+32·2 = **97 B** | 1+32·2 = **65 B** | **−32 B/input** |
| Normal-spend weight (measured) | 169 vB | ~161 vB (−32 WU) | cheaper fees |
| MAST structure (4 leaves, Huffman) | same | same (depth 2 ⇒ no depth-0 caveat) | ZERO change |
| PSBT / hardware wallets | BIP-371 fields | v2 program fields | upstream update required |
| Estate letter §1 | output key + NUMS line | merkle root = program; NUMS line retired | letter format revision |

**Key point:** the experimental `p2mr_address_experimental()` already lives in the repo (`qsv-core::taproot`) and is tested: it derives a `bc1z…` address from the same merkle root, SegWit version 2, program = root — a literal match to the BIP text. The migration plan is therefore **executable today** (address math, size arithmetic, letter wording); only the consensus rules await the soft fork.

---

## 3. Phase Plan (4a–4e)

```
[Phase 4a · SPEC TRACKING]                  ← WE ARE HERE (Draft v0.12.1)
├── track bip-0360.mediawiki diffs (version ≥ 0.13 or Status: Proposed/Final)
├── rust-bitcoin / miniscript upstream P2MR support (tr() descriptors, …)
├── Bitcoin Core: P2MR scriptPubKey + witness validation paths
├── hardware wallet roadmaps (Ledger/Trezor/Coldcard v2 PSBT fields)
└── GATE K1: BIP Status ≥ Proposed + two independent implementations
        │
[Phase 4b · QSV CODE SUPPORT]
├── taproot.rs: P2MR output derivation (experimental fn promoted to prod)
├── address() / psbt / dashboard: v2 program fields
├── control block 65 B; P2MR column in budget.rs
├── estate letter §1 revision (merkle-root-as-program; NUMS line archived)
├── estate verify_letter: P2MR field checks (verify-estate --format p2mr)
└── test vectors: official scriptPubKey/address pairs from the BIP
        │
[Phase 4c · SIGNET REHEARSAL]
├── Core ≥ (activation release) on signet/regtest e2e
├── lifecycle e2e: prepare → unvault → CSV → settlement on P2MR outputs
├── PSBT round-trip: v2 program encoding + device signature
├── GATE K2: e2e green + T1–T8 matrix green on P2MR
        │
[Phase 4d · MAINNET ROTATION]
├── new deposits go straight to the bc1z address
├── existing P2TR balances: one-time loop through the unvault flow
│     (tx 1: P2TR → staging (existing covenant), tx 2: staging → P2MR)
│     cost: measured P2TR spend vbytes + normal fee (one-off)
├── veto/heartbeat windows: clawback protection preserved during rotation
└── GATE K3: 90-day monitoring (uninterrupted heartbeat, dashboard green)
        │
[Phase 4e · FAREWELL TO P2TR]
├── docs/README address examples updated to P2MR
├── no NEW money into old P2TR addresses (address freeze)
└── old addresses are archival-only
```

**Gates are explicit; not a single line of consensus code lands before K1 opens.**

---

## 4. Component Impact Matrix

| Component | Impact | Action |
|---|---|---|
| `taproot.rs` | `p2mr_*` beside `address()`; internal key retired | 4b |
| `budget.rs` | control 97→65 B; P2MR fee column | 4b |
| `estate.rs` | §1 lines: program line instead of output key/NUMS; verify extension | 4b |
| `unvault.rs` | none (same tapleaf sighash family) | — |
| `policy.rs` / miniscript | descriptor shape depends on upstream (K1) | 4a tracking |
| `psbt.rs` | v2 program fields, BIP-371 extension | 4b–4c |
| `dashboard.rs` | address renders bc1z on the right network | 4b |
| `wots.rs` / leaf 4 | **untouched** (commit-reveal stays tapscript) | — |
| `qsv-node` e2e | new e2e scenario on an activated Core | 4c |
| `qsv-cosigner` | none (off-chain) | — |

---

## 5. Test Matrix (mandatory after activation)

1. **BIP vectors:** official `bc1z` address ↔ scriptPubKey pairs from the spec (added at K1).
2. **T1–T8 invariance:** the full matrix re-runs on P2MR outputs (NUMS already cancelled; same CSVs; same 520 B).
3. **Control block 65 B:** `1+32·depth` — 65 at depth 2 (pinned by the experimental test `p2mr_experimental_address_is_witness_v2_over_the_merkle_root`).
4. **Depth-0 guard:** rejection/warning for single-leaf trees (ours is four-leaf — regression pin).
5. **e2e:** fund → unvault → settlement on regtest with P2MR destination outputs; node mempool acceptance.
6. **PSBT round-trip** with a v2-program signer (hardware or software).

---

## 6. Risk Table

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Final BIP drifts from Draft (fields/addresses change) | Medium | K1 gate holds; no code landed | no speculation, tracking only |
| rust-bitcoin P2MR support lags | Medium | address validation hand-rolled | `WitnessProgram::V2` already exists; minimal surface |
| Hardware wallet v2 support lags | High | PSBT slips to 4c | rehearsal with software signer |
| Veto window open during rotation | Low | clawback protection preserved (good) | order: wait for CSV close |
| Short-exposure (mempool) threat | Medium | P2MR alone does not cover it | RBF/aggressive confirmation + future PQ sigs (§7) |
| Accidental new deposit to an old address | Medium | funds at reduced-protection type | address freeze + estate letter warning |

---

## 7. Connection: OP_CHECKSHRINCS and the Future of Leaf 4

Blockstream's May 2026 OP_CHECKSHRINCS design (SHRINCS, first signature 324 B, ~580 B deployed, SHA-256 throughout) proposes verifying hash-based signatures **inside tapscript**, explicitly transportable "via BIP-360's P2MR leaves". Consequences for this repo:

- **Today:** the WOTS+ seal lives off-chain (air-gapped); the chain sees only the 37 B commit-reveal + classical Schnorr (consensus-proven by T6/T7).
- **Phase 4f (if activated):** a new emergency leaf verifying WOTS+/SHRINCS directly can be added; commit-reveal retires. The w-parameter study (`qsv-cli wots-params`) is the numerical basis for that decision: no `w` fits a full 32-byte message into 520 B (minimum 1,088 B) — an impossibility proof without opcodes.

---

## 7.5. Source-Branch Spend Rehearsal (Phase 4b rehearsal — K1-gated, REGTEST-ONLY)

Even with K1 still open, proof that the migration path **works today** is worth
having. An experimental source-branch trial is now wired in (`qsv-cli psbt-live
--p2mr`):

1. **The address is live:** the demo vault's experimental P2MR address
   (`bcrt1z…`, witness v2 program = merkle root) is accepted by a real bitcoind
   and a coin there is visible to the same read-only `scantxoutset` discovery.
2. **The SAME spending machinery:** the coin is signed through the SAME hybrid
   leaf (user + enclave co-sign), the SAME BIP-341 sighash machinery and the
   SAME PSBT engine; the assembled witness passes the libbitcoinconsensus
   self-check.
3. **Broadcast is structurally impossible:** the trial transaction lands in
   `p2mr-source-trial.txhex` — BIP-360 consensus rules exist on NO live
   network, so a witness-v2 spend cannot be relayed (K1: evidence pending).
4. **Gates:** `--p2mr` exits 1 on mainnet/testnet/signet (fail-closed);
   anything beyond regtest is out of design scope.

The point is NOT to skip K1 but to be ready to skip it: on activation day the
only missing piece will be the consensus code that understands witness
version 2 — address math, PSBT, sighash and witness layout are tested today.

**Multi-input and budget proof (continuing 7.5):** the trial now also covers
MULTIPLE coins — `psbt-live --p2mr --min-inputs 2` consolidates two live P2MR
coins into ONE hold transaction (the multi-input PSBT engine, e2e-verified).
On the size side, `leaf-budget --p2mr-delta` prints the experimental saving
per leaf: control block 33+32d → 1+32d (exactly 32 B per input at depth 2).
Under the BIP-141 weighting rule witness bytes count 1 WU each (the ×4
multiplier applies only to the non-witness part), so the saving is exactly
32 WU = 8 vB per script-path input — `psbt-live --p2mr` prints the REAL
weight of the assembled transaction beside a P2TR twin on every run and
asserts the delta (measured, never estimated); with vbytes/fee deltas at
every representative feerate — pure arithmetic, K1 outstanding, and tested.

---

## 8. Honest Status Summary

- **In the repo:** P2MR address derivation (experimental, tested), size/fee arithmetic (tested), this plan, the **K1 tracker** (`qsv-cli bip360-status`: recorded snapshot ↔ live BIP header diff) and the **source-branch spend rehearsal** (`psbt-live --p2mr`, below).
- **NOT in the repo (deliberately):** P2MR spending/consensus code — the BIP is Draft and unactivated; adding it would be a mock.
- **Critical path:** K1 (BIP Proposed + two implementations) → 4b → K2 (e2e) → 4d (rotation).
- For QuantumSafe-Vault's threat model P2MR is an **optional hardening**: NUMS already cancels the key path; P2MR moves that into consensus and shaves 32 B off every control block.

---

## 9. Plan B: if BIP-360 is rejected / partially activated

*Evaluation finding #3 said the fallback was "a draft, not a documented Plan B". This section closes that gap — the SPENDING PATH under BIP Reject/Withdrawn or a partial activation is written out here.*

### 9.1. Scenario matrix

| BIP-360 outcome | K1 decision | Spending path (READY TODAY) |
|---|---|---|
| **Reject / Withdrawn / Obsolete** | K1 permanently closed — `bip360-status` says so in the offline audit | **Script-path-only spending:** all four leaves are already tapscript; NUMS already cancels the key path — P2TR + MAST is PROD with zero code change. The loss: 32 WU/input + the 33 B control block. |
| **Proposed but fewer than two implementations** | K1 implementation limb closed (`impl-independent-count < 2`) | Same: the existing P2TR MAST. Migration is HELD (4b/4c never start) — no speculation. |
| **Proposed + two independent implementations** | K1 opens | 4b → 4c → K2 → 4d (the plan's main path). |
| **Partial activation** (some nodes only) | K1 "INDETERMINATE" — manual review | The only transaction type carrying chain-compatibility risk is a P2MR output spend; rotation is DEFERRED and the permanent P2TR vault continues (see §8: P2MR is optional hardening). |

### 9.2. Plan B's code proof (today, without K1)

- The `psbt-live --p2mr` source-branch rehearsal (§7.5) is REGTEST-ONLY and K1-gated; the main spending path (`psbt-live`) is green TODAY without touching any P2MR code — the live regtest e2e suites prove it every round (docs/09 §9, T7).
- `verify-estate` re-derives all four leaves from the P2TR MAST; if the BIP dies, the letter/verify/PSBT/heartbeat chain does not change.
- The `budget.rs` P2MR column is an ARITHMETIC ESTIMATE (§7.5: 32 WU/input, a verified measurement), not a consensus claim — if the BIP dies the column is archived and prod code is unaffected.

### 9.3. Decision protocol

1. When `bip360-status --online` sees Reject/Withdrawn, K1's permanently-closed label is recorded in docs/11 (human decision; the tracker never auto-writes).
2. Phase 4b/4c items are CANCELLED (not parked — carrying no speculation debt).
3. The vault stays on P2TR+MAST; the only loss is 32 WU/input (measured).

---

*This document rests on the BIP-360 Draft v0.12.1 text and September 2026 ecosystem data; if the BIP is revised, gate K1 is re-evaluated.*
