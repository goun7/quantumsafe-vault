# 🛡️ QuantumSafe-Vault — Post-Quantum Hybrid Bitcoin Vault & Sovereign Inheritance Protocol

> **v2026.3 — Enterprise-Sovereign** · Quantum-shielded assets, Miniscript Taproot shield, trustless digital inheritance.
> Specification: 11 modules in [`docs/`](docs/) · paper: [`PAPER_EN.md`](PAPER_EN.md) · release notes: [`CHANGELOG.md`](CHANGELOG.md)

> ## ⚠️ Status: testnet/signet reference implementation — do not use with real funds
>
> - **No independent audit.** The cryptographic paths are hand-written and have never been reviewed by a third party.
> - **No production TEE provisioning.** Attestation is simulated in development mode (`--features nsm` contains the real NSM ioctl path but has not run on hardware).
> - **Mainnet is not supported.** Lost funds are permanent; this repository is an evidence-bearing core, not a product.
> - What is proven and what is not: [`STATUS.md`](STATUS.md) · [`SECURITY.md`](SECURITY.md) §2 · roadmap: [`ROADMAP.md`](ROADMAP.md).
>
> *Status: reference implementation for testnet/signet. **Not audited, not production-ready — do not use with real funds.***

[![version](https://img.shields.io/badge/v2026.3.1-blue)](CHANGELOG.md) [![tests](https://img.shields.io/badge/tests-507-green)]() [![clippy](https://img.shields.io/badge/clippy--clean-green)]() [![mutation](https://img.shields.io/badge/mutation--audit-54%2F54%20killed-green)]() [![coverage](https://img.shields.io/badge/coverage-97.57%25%20lines%20%2F%2083.25%25%20funcs-green)]() [![FIPS 204](https://img.shields.io/badge/PQC-ML--DSA--65-blue)]() [![BIP-341/342/379](https://img.shields.io/badge/Bitcoin-Taproot%20%2B%20Miniscript-orange)]() [![e2e](https://img.shields.io/badge/e2e-bitcoind%20v28.2-green)]()

---

## What it does

| Threat | Shield | Implementation |
|---|---|---|
| **Shor's algorithm** breaks classical keys | NUMS (Nothing-Up-My-Sleeve) internal key: key-path spending is **mathematically impossible** | `qsv-core::nums` |
| **Single-key vaults on Q-Day** | 2-of-2 hybrid: classical Schnorr + a **PQC-gated enclave co-signer** (NIST FIPS 204 ML-DSA-65, real BIP-340) | `qsv-pqc`, `qsv-core::taproot` |
| **Mempool sniffing / RBF theft** | Two-stage unvault covenant: funds can only move to the Staging UTXO, then a 144-block CSV + clawback | `qsv-core::unvault` |
| **Dead keys / inheritance crisis** | Dead Man's Switch: heartbeat self-churn + 26,280-block CSV + 2-of-3 heir threshold | `qsv-core::heartbeat`, `policy`, `heirs` |
| **Heir identity forgery** | Every heir's classical key is sealed to an ML-DSA-65 identity commitment (fail-closed) | `qsv-core::heirs` |

**Core principle:** spending flows **only through the MAST script path**. Even if a quantum computer breaks the classical keys: (i) it cannot forge the second signature without the enclave's PQC proof (Theorem 1), (ii) it cannot open the key path because the NUMS discrete log is unknown (Theorem 2), (iii) it cannot redirect the covenant outputs (Theorem 3).

---

## Quick start

```bash
# Requirement: Rust 1.85+
cargo build --release
cargo test --workspace        # full matrix, incl. live bitcoind v28.2 e2e
cargo test --workspace --features qsv-core/consensus   # + libbitcoinconsensus
cargo run -p qsv-cli -- vault-setup        # no network access, fully local demo
```

CLI (`clap`):

```text
qsv-cli vault-setup         --network {bitcoin|signet|testnet|regtest}
qsv-cli vault-descriptor    --network regtest [--json]
                            # watch-only descriptor export (docs/10 §4.59):
                            # addr(bc1p…)#checksum (BIP-385) + rawtr(<output key>)#
                            # proven against REAL bitcoind (getdescriptorinfo /
                            # deriveaddresses / importdescriptors); tr() is
                            # deliberately absent — 3 of 4 leaves are not
                            # miniscript, so a different tree = a different address
qsv-cli hybrid-spend-demo                              # consensus verify_input
qsv-cli inheritance-demo                               # dead man's switch flow
qsv-cli vault-dashboard     --datadir ~/.bitcoin --network signet [--watch 30]
                            # live chain tip (read-only RPC) or --tip N (offline)
qsv-cli console [--network signet] [--tip N] [--last-refresh-block N] \
                [--descriptor 'addr(…)#…'] [--out page.html] [--json]
                            # ONE-SCREEN VAULT CONSOLE (roadmap slice 1): the three
                            # clocks, address and estate letter in one script-free
                            # HTML file (no JS, no network, no keys); a descriptor
                            # that is not this vault's is REFUSED
qsv-cli estate-letter       --network bitcoin --label "Family vault" --date 2026-09-28 [--qr]
                            # printable estate & emergency document (no secrets);
                            # --qr adds a scannable QR block for §1 identity
qsv-cli verify-estate       --file letter.txt --network bitcoin
                            # re-derives the letter independently, compares 8 fields
                            # (exit 1 = forged)
qsv-cli leaf-budget [--p2mr-delta]                    # per-leaf witness/vbytes/fee table
                            # --p2mr-delta: EXPERIMENTAL BIP-360 saving (control 97→65 B,
                            # 32 B = 128 WU per input; K1 gated, arithmetic only)
qsv-cli wots-params                              # WOTS+ w parameter study + the 520 B verdict
qsv-cli kit-seed split   --threshold 3 --shares 5
                            # split the emergency kit seed with Shamir (fail-closed tag)
qsv-cli kit-seed split --format slip39 --threshold 2 --shares 3
                            # SLIP-0039 mnemonics (20/33 words, RS1024)
qsv-cli kit-seed combine --share qsvss1-1=… --share qsvss1-2=… --share qsvss1-3=…
                            # recombine + WOTS+ kit seal round-trip verification
qsv-cli psbt build --out vault.psbt                      # BIP-174/371 unsigned PSBT
qsv-cli psbt sign  --in vault.psbt --out signed.psbt     # two device slots sign + verify
qsv-cli psbt finish --in signed.psbt --out final.psbt     # witness assembly + consensus verify
qsv-cli psbt export --in vault.psbt --stem hw-card        # SD-CARD export (Coldcard/Ledger):
                            # <stem>.psbt (BINARY BIP-174) + <stem>.sha256 manifest
                            # + <stem>.txt (human-auditable spend summary)
qsv-cli psbt import --in hw-returned.psbt [--manifest x.sha256] --out final.psbt
                            # SD-CARD return: manifest check → EVERY tap script-sig is
                            # checked against the known leaf keys → witness assembly
                            # → libbitcoinconsensus verdict (one tampered byte = exit 1)
qsv-cli psbt-live --datadir ~/.bitcoin --rpc-port 8332    # PHASE 2: REAL UTXO → real mempool
                            # finds the live vault coin via scantxoutset, builds the PSBT,
                            # signs on two devices, finalizes and BROADCASTS
                            # [--build-only | --sign-only] checkpoints; [--destination <x-only>]
qsv-cli psbt-live --datadir ~/.bitcoin --rpc-port 8332 --min-inputs 3
                            # MULTI-INPUT consolidation: largest-first, spent in ONE
                            # transaction (vault script-path on every input; fail-closed)
qsv-cli frost-spend --public public-package.txt --deal h0=… --deal h2=… \
                    --datadir ~/.bitcoin --rpc-port 8332 --fund-sat 250000 \
                    --fee-sat 1500 --dir ceremony/
                            # FROST k-of-n GROUP key spent on the REAL chain: BIP-341
                            # key-path tweak + RFC 9591 ceremony → consensus self-check
                            # → broadcast; [--no-broadcast] is the WATCHTOWER dry run
qsv-cli watchtower --datadir ~/.bitcoin --rpc-port 8332 [--deal … --public …]
                            # INHERITANCE WATCHTOWER: one read-only pass — ALERT on a
                            # missed heartbeat (exit 1), CSV countdown, live coin total;
                            # a real FROST rehearsal with --deal (never broadcasts);
                            # an ALARM mirror makes the cosigner refuse every request
qsv-cli vault-rotate --datadir ~/.bitcoin --rpc-port 8332 [--heir …] [--no-broadcast] \
                     [--cosigner 127.0.0.1:3334] [--state-dir /var/lib/qsv] …
                            # OWNERSHIP HEARTBEAT: self-churn refresh (same address,
                            # CSV clock reset); --heir re-seals each heir slot with a
                            # FRESH ML-DSA-65 identity (missing/forged = exit 1);
                            # --cosigner fetches the live PQC-gated co-signature
qsv-cli cosigner-bridge --listen 127.0.0.1:3334 --state-dir /var/lib/qsv \
                        [--vault-id …] [--metrics-token-file …] [--watchtower …] [--dry-run]
                            # CO-SIGNER BRIDGE: enclave TCP service + watchtower ALARM
                            # mirror re-read per request; k-of-n quorum freeze; SIGHUP
                            # reloads the metrics token without a restart (docs/10 §4.30)
qsv-cli doctor [--datadir …] [--network …] [--state-dir …] [--json]
                            # OPERATOR DIAGNOSIS in one command: node RPC tip,
                            # watchtower + mirror lag, bridge-health pid liveness,
                            # live /metrics scrape + reload readiness
qsv-cli bench [--iterations N] [--json] [--baseline <report>] [--baseline-tolerance-pct N]
                            # CAPACITY MEASURER: ML-DSA-65 keygen/sign/verify, BIP-340
                            # sign/verify, enclave gate, health record write+read;
                            # --baseline turns it into a gate (exit 1 / exit 2)
qsv-cli psbt-live … --p2mr                    # EXPERIMENTAL BIP-360 source-tree trial
qsv-cli inheritance-kit setup|recover-check|heir-round1|build-sign-pkg|heir-round2|finish
                            # FROST inheritance wizard: threshold key + SLIP-0039 backups
qsv-cli bip360-status [--online]                         # K1 decision-gate tracker (docs/11)
qsv-cli docs-audit [--json] [--dir docs]                # documentation structure report
qsv-cli constants                                      # FIPS 204 + CSV + NUMS + WOTS+
```

Example output (truncated):

```text
NUMS internal key (x-only): 4ca0f3767f47e87ffabe08c40a9321cf657c2528bd70535f96c4cadcd55a95a6
  └─ discrete log unknown by construction (SHA-256 preimage resistance)
Leaf 1 (normal):      2-of-2 hybrid  <user> <enclave>
Leaf 2 (recovery):    CSV 144 blk    <cold-sweep>
Leaf 3 (inheritance): CSV 26,280 blk + 2-of-3 heirs
Leaf 4 (emergency):   WOTS+-sealed kit (commit-reveal, SHA-256 only)
Address (bitcoin):    bc1p0x8hu958cvstlfvqrt96v6lwtkm8ruaq3tj4ph85v2z0xydy03dscqh0qr
ML-DSA-65 signature:  3309 bytes (FIPS 204 final)
Enclave gate:         OPEN (PQC valid) → co-sign released
Forge attempt:        REJECTED (fail-closed) ✅
```

---

## Architecture

```
quantumsafe-vault/
├── crates/
│   ├── qsv-core/        # Pure deterministic core (no I/O — air-gap friendly)
│   │   ├── nums.rs      #   NUMS internal key (provably unspendable key path)
│   │   ├── policy.rs    #   BIP-379 Miniscript policy compiler
│   │   ├── taproot.rs   #   BIP-341 MAST leaves + address derivation
│   │   ├── unvault.rs   #   Two-stage covenant flow + Schnorr signing
│   │   ├── psbt.rs      #   BIP-174/371 signer & co-signer + device_sign_input
│   │   ├── heartbeat.rs #   Dead Man's Switch: self-churn refresh tx + tick
│   │   ├── consensus.rs #   libbitcoinconsensus (feature "consensus") verification
│   │   ├── wots.rs      #   WOTS+ (RFC 8391): post-Q-Day emergency layer
│   │   ├── budget.rs    #   Per-leaf spend budget (witness/vbytes/fee, real spends)
│   │   ├── shamir.rs    #   GF(256) Shamir k-of-n kit-seed splitting
│   │   ├── slip39.rs    #   SLIP-0039 mnemonics (45/45 official test vectors)
│   │   ├── frost.rs     #   FROST threshold signatures (RFC 9591, BIP-340-compatible)
│   │   ├── bip360.rs    #   BIP-360 (P2MR) K1 decision-gate tracker
│   │   ├── dashboard.rs #   Operator dashboard: heartbeat / inheritance / clawback clocks
│   │   ├── console.rs   #   One-screen watch-only console: snapshot + script-free HTML
│   │   ├── estate.rs    #   Estate letter + independent verification + QR payload
│   │   ├── finmodel.rs  #   docs/06 financial model engine (tested, integer cents)
│   │   ├── settlement.rs#   Estate debits/credits → heir shares (fail-closed on bankruptcy)
│   │   ├── heirs.rs     #   Heir PQC identity commitments
│   │   └── demo_keys.rs #   Deterministic demo keys (tests/demos only)
│   ├── qsv-pqc/         # NIST FIPS 204 ML-DSA-65 engine + fail-closed enclave gate
│   ├── qsv-cosigner/    # Co-signer service: TCP protocol v1, allowlist, provisioning
│   │                    #   record; PRODUCTION (--features nsm): real NSM ioctl +
│   │                    #   COSE_Sign1 attestation + PCR pinning + AF_VSOCK
│   ├── qsv-node/        # Vault lifecycle: prepare/finalize unvault, key-path
│   │                    #   settlement, read-only RPC client + REAL bitcoind e2e
│   └── qsv-cli/         # clap-driven operator surface
└── crates/qsv-core/tests/integration.rs   # Theorem ↔ test cross matrix (T1–T8)
```

Auditable dependencies: `bitcoin` 0.32, `miniscript` 13.1, `secp256k1` 0.29, `ml-dsa` 0.1, `bitcoinconsensus` 26.0, `clap` 4 (RustCrypto + rust-bitcoin ecosystem). No hand-rolled cryptographic primitive.

### Vault policy (BIP-379 Miniscript)

```miniscript
or_d(
    and_v(v:pk(key_user), pk(key_enclave)),                    /* normal hybrid */
    or_c(
        and_v(v:older(144), pk(key_recovery)),                 /* 144-block clawback */
        and_v(v:older(26280),                                  /* ~180-day inheritance */
            thresh(2, pk(key_heir_1), pk(key_heir_2), pk(key_executor)))
    )
)
```

---

## Test matrix (theorem ↔ test)

| Theorem | Claim | Test |
|---|---|---|
| **T1** | No co-sign without a valid PQC signature; forged PQC rejected | `gate_is_fail_closed`, `forge_is_rejected`, `t1_end_to_end_pqc_gate_and_hybrid_spend` |
| **T2** | NUMS key path mathematically cancelled; the point is deterministic | `t2_key_path_is_mathematically_cancelled`, `nums_canonical_counter_is_frozen` |
| **T3** | Unvault is pinned to the staging output; CSV 144 encoding exact | `t3_unvault_pins_single_staging_output`, `t3_t4_csv_encodings_are_exact` |
| **T4** | Inheritance locked by a 26,280-block CSV at consensus level | `t4_inheritance_settlement_uses_csv_sequence` |
| **T5** | Hybrid spend accepted by **libbitcoinconsensus**; tampered signature rejected | `t5_consensus_engine_accepts_hybrid_spend_and_rejects_tamper` |
| **T6** | Emergency leaf (4) full spend accepted; tampered key rejected; >520 B witness item is consensus-illegal | `t6_consensus_engine_accepts_full_emergency_leaf_spend_and_rejects_tamper` |
| **T7** | **All four leaves** verify as reference spends (CSV nSequence included); any tamper = reject | `t7_all_four_leaf_reference_spends_consensus_verify_and_reject_tamper` |
| **T8** | Miniscript policy ↔ MAST consistency: same CSVs, 6 policy keys, 4 control blocks | `t8_policy_layer_and_mast_tree_agree_on_the_classical_leaves` |
| **E2E** | Real bitcoind v28.2: mine → unvault → CSV → settlement | `e2e_full_vault_lifecycle_on_real_bitcoind` |
| **E2E-PSBT** | The real node accepts the built transaction in its mempool | `psbt_device_roundtrip_is_accepted_by_real_node` |
| **E2E-ESTATE** | Letter → `verify-estate` 8/8 → live funding → forged byte = **exit 1** | `estate_letter_qr_verify_and_live_funding` |
| **E2E-PSBT-LIVE** | Real UTXO via scantxoutset → PSBT → 2 device signatures → **mempool ACCEPT** | `live_psbt_from_real_utxo_to_real_mempool` |
| **HW-ROUNDTRIP** | SD-card export → sign → import: manifest + every signature checked against leaf keys | `sd_card_roundtrip_export_sign_import_and_fail_closed` |
| **WATCHTOWER** | Healthy run exits 0 and never fakes an alarm; `--deal` rehearses a real FROST ceremony | `watchtower_rehearses_threshold_and_alerts_on_missed_heartbeat` |
| **MUTATION** | `scripts/mutation_audit.sh`: **54 deliberate crypto/logic mutations, 54/54 KILLED** (NUMS counter, Shamir tag, FROST envelope + group signature + duplicate identities, heir binding, device-verification gate, multi-input amounts, heartbeat due/expiry/self-churn, attestation chain, rate-limit bucket, HMAC envelope, BIP-371 root, SLIP-39 tag, source allowlist, metric scrape gate, estate-letter comparators, WOTS+ chain step, `pid_alive(0)`, loopback policy, P2MR witness version, CBOR depth, ASCII hex, scan-budget guard, DKG threshold, watch-only output key, vacuous-mirror wall, k-of-n merge, clamp wall, finmodel tiers, estate bankruptcy walls, documentation item wall, console descriptor wall) — plus the automatic file wall of `scripts/mutation_sweep.sh` (every product file carries a hand mutant, a mechanical mutant, or a written allowlist reason) | `scripts/mutation_audit.sh` + `mutation_sweep.sh` (CI job) |
| **FROST** | 2-of-3 FROST verifies as plain BIP-340 Schnorr under the GROUP key; sub-threshold aggregation fails closed; SLIP-0039 backup round-trips | `frost::tests::*` + `frost_wizard_full_ceremony_and_backup_drill` |
| **SLIP-39** | All **45/45 official test vectors** (accepted and rejected) | `all_official_vectors_pass`, `two_level_group_threshold` |
| **K1** | docs/11 snapshot ↔ live `bip-0360.mediawiki`, field by field | `bip360::tests::*` + `qsv-cli bip360-status --online` |
| **DOCS** | Document structure: module set, English titles, monotonic sections, subsections that belong to a section, balanced fences, resolvable links, the BIP-360 snapshot, and an English-only public tree | `docs_sync` (8 tests) + `qsv-cli docs-audit` |

Also: FIPS 204 key/signature sizes (1,952/3,309 bytes), heir commitment binding, BIP-174 PSBT flow (device-sign determinism + fail-closed), heartbeat policy, **WOTS+ parameter study** (no `w` fits a 32-byte message under 520 B — 1,088 B minimum), **commit-reveal emergency leaf + the 520 B consensus pin**, **per-leaf budget measurements**, **Shamir/SLIP-39 round-trips**, **estate-letter determinism + forgery tests**, dashboard clock math, co-signer protocol/TCP e2e, taproot address derivation, **PSBT Phase 1 file flow**, **BIP-360 K1 tracker**, and the **documentation structure walls**.

---

## Security notes

- This repository is a **Phase 0 reference implementation**: an evidence-bearing core before testnet. Mainnet use requires production TEE provisioning (the Nitro Enclave attestation document is simulated in dev mode) and hardware-wallet integration.
- `demo_keys` is **never** for production; real deployments replace it with hardware-wallet keys.
- `qsv-cosigner` runs in dev mode: attestation is simulated, while the protocol contract (fail-closed, deterministic, allowlisted) is preserved verbatim for the production TEE. The production path (`--features nsm`) contains the real NSM ioctl + COSE_Sign1 parsing + PCR0/1/2 pinning + AF_VSOCK transport; the client-side verifier compiles and is tested in both modes.
- **The K1 tracker runs in CI**: `.github/workflows/k1-tracker.yml` runs an offline audit on every push/PR and a live BIP-360 heading diff at 06:37 UTC on Mondays and Thursdays; any delta = red job. The tracker never edits docs/11 itself — the protocol decision stays with a human.
- **Local full gate**: `scripts/round_gate.sh` — the single-command local mirror of every CI job; each leg is **evidence-patterned** (a leg that exits 0 without printing the output of its real work is rejected as `EMPTY-GREEN`). `GATE_SKIP="fuzz mutation-audit coverage"` for a quick run, `GATE_ONLY=fmt` for one leg, `GATE_CONTINUE=1` to keep going after a failure.
- **Main CI pipeline**: `.github/workflows/ci.yml` runs the same mirror on every push/PR — fmt, clippy in three configurations, `cargo test --workspace` in two configurations (including the real bitcoind e2e flows), the **mutation audit**, the **relay drill** (HMAC+replay refusal map), the **monitoring drill** (`promtool check rules --lint all`, real PromQL parser), the **capacity gate** (`bench --baseline` three verdicts on a real binary), the **security audit** (RustSec + `cargo deny` + `scripts/secret_scan.sh` over the tree and the full git history) and the **fuzz gate** (attestation CBOR/COSE, frame/health/watchtower JSON, SLIP-0039, PSBT raw/base64, estate letter, WOTS+/kit seal).
- **Funded signet lap**: the funded loop closed 7/7 with honest exit codes — funding (0) · funded rotate (0, block 326866, CSV reset) · psbt-live honest fee refusal (1) · **funded psbt-live spend (0**, mempool `02703d3f…`, confirmed in block 326869) · dashboard (0) · watchtower (0) · early-rotate refusal (1) — docs/10 §4.62.
- The NUMS seed text and canonical counter are frozen by tests; changing them breaks the protocol and CI catches it.

## Documentation

| Module | Content |
|---|---|
| `docs/01` | Quantum threat model: Shor/Grover, 2025–2026 source estimates, mempool sniffing |
| `docs/02` | FIPS 204 (ML-DSA), Winternitz WOTS+, hybrid aggregators, CNSA 2.0, side-channel/rollback position (§6) |
| `docs/03` | Taproot/Miniscript architecture, NUMS protocol, BIP-360 compatibility, `qsv-core` mapping |
| `docs/04` | Dead Man's Switch, CSV timelocks, FROST/SLIP-0039, PQC identity sealing |
| `docs/05` | Legal armor: RUFADAA, Turkish Civil Code Art. 599, non-custodial exemption, ITL 89/13 |
| `docs/06` | Financial model, unit economics, TAM/SAM/SOM, break-even |
| `docs/07` | Competitive teardown: Casa, Unchained, BitGo, Fireblocks |
| `docs/08` | Academic bibliography + 2026 empirical UTXO fragility report |
| `docs/09` | Implementation architecture and coding plan (this repository's spec) |
| `docs/10` | Operations and user guide (`qsv-cli`, estate letter) |
| `docs/11` | BIP-360 (P2MR) migration plan — Phase 4 |

Status and limits: [`STATUS.md`](STATUS.md) · roadmap: [`ROADMAP.md`](ROADMAP.md) · security policy: [`SECURITY.md`](SECURITY.md) · release notes: [`RELEASE_NOTES.md`](RELEASE_NOTES.md).

## License

MIT
