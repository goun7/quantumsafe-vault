# Module 09 — Implementation Architecture & Coding Plan

> Specification module 09 of QuantumSafe-Vault — v2026.3.

## 1. Workspace topology

```
quantumsafe-vault/
├── Cargo.toml                     # workspace definition (5 crates)
├── crates/
│   ├── qsv-core/                  # pure logic, no I/O, deterministic
│   │   └── src/
│   │       ├── nums.rs            # NUMS internal key derivation (§2)
│   │       ├── policy.rs          # Miniscript policy templates (§3)
│   │       ├── taproot.rs         # spend info + address derivation (§4)
│   │       ├── unvault.rs         # two-stage unvault covenant (§5)
│   │       ├── heirs.rs           # inheritance commitment (§6)
│   │       ├── wots.rs            # WOTS+ (RFC 8391) emergency layer
│   │       ├── budget.rs          # per-leaf spend budget (measured)
│   │       ├── shamir.rs          # native GF(256) k-of-n kit seed shares
│   │       ├── slip39.rs          # SLIP-0039 mnemonics (spec vectors)
│   │       ├── bip360.rs          # BIP-360 K1 decision-gate tracker
│   │       ├── estate.rs          # estate letter + verify-estate
│   │       ├── psbt.rs / dashboard.rs / heartbeat.rs / consensus.rs
│   ├── qsv-pqc/                   # NIST FIPS 204 ML-DSA-65 engine (§7)
│   ├── qsv-cli/                   # operator commands and demos (§8)
│   ├── qsv-cosigner/              # enclave co-signer daemon
│   └── qsv-node/                  # bitcoind integration + live e2e
└── crates/qsv-core/tests/
    └── integration.rs             # T1–T8 theorem↔test matrix (§9)
```

**Design principles:** (1) `qsv-core` has no network, filesystem or clock access — everything is pure and air-gap friendly; (2) cryptographic dependencies come only from auditable crates (`secp256k1` C bindings, Blockstream's `miniscript`, RustCrypto's `ml-dsa`) — no hand-rolled primitives; (3) verification is fail-closed — an invalid PQC proof never yields a co-signer signature.

## 2. NUMS internal key module (`nums.rs`)

A literal implementation of Document 03 §2.2: the seed text `QuantumSafe_Vault_v2026_Unspendable_Internal_Key_Nothing_Up_My_Sleeve` is hashed with SHA-256 under a counter loop until the output lifts to a valid x-only secp256k1 point; the smallest canonical counter that succeeds is frozen by test. The resulting point has no known discrete log, which is what makes the taproot key path provably unspendable.

## 3. Miniscript policy layer (`policy.rs`)

The compilable form of the policy in Document 03 §4.1: four branches (hybrid 2-of-2, recovery with CSV 144, inheritance with CSV 26,280 + threshold heirs, emergency commit-reveal) expressed as a Tap-context Miniscript policy and compiled with `miniscript`'s compiler. The compiled descriptor is the single source of truth for the leaf scripts the estate letter prints and `verify-estate` re-derives.

## 4. Taproot output derivation (`taproot.rs`)

1. **Four-leaf MAST:** `TaprootBuilder::with_huffman_tree` builds an equally weighted four-leaf tree (normal, recovery, inheritance, emergency) — balanced ⇒ depth 2 ⇒ control block 97 B for every spend.
2. `SpendInfo` is finalized; the four `TapLeafHash` values are stored, and `control_block(&leaf)` serves each spend path.
3. Address derivation runs for mainnet/signet/testnet/regtest from one policy; `p2mr_address_experimental()` additionally renders the BIP-360 `bc1z` form (witness v2 over the merkle root, control block 65 B) pinned by test.

## 5. Two-stage unvault covenant (`unvault.rs`)

The end-to-end emulation of the covenant in Document 03 §6: build the unvault transaction whose outputs can only be the pinned staging address, compute the BIP-341 script-path sighash with leaf hash and `0xFFFFFFFF` codeseparator position, sign with both keys, assemble the witness in script order and run the result through libbitcoinconsensus before anything is considered valid. The staging output then carries `nSequence` for the CSV lock so settlement can only happen after 144 blocks.

## 6. Inheritance participation commitment (`heirs.rs`)

The L1-compatible implementation of the PQC identity sealing in Document 04 §5: `heir_commitment_i = SHA256(pk_pqc_heir_i ‖ xonly(key_heir_i))`, registered in a fail-closed heir set (2-of-3: two heirs or the executor). A stolen classical heir key without the matching ML-DSA identity fails dispute resolution, and the commitment is what the estate letter prints so heirs can check their own entry without any secret being revealed.

## 7. PQC engine (`qsv-pqc`)

A thin, auditable wrapper over the RustCrypto `ml-dsa` crate (FIPS 204 final): `PqcIdentity { sk: SigningKey<MlDsa65> }` (1,952 B verifying key, 3,309 B signature), key generation from a seed, sign/verify, and the enclave gate `enclave_sign_if_pqc_valid` which re-verifies the proof over the *exact* message before releasing a BIP-340 signature — any malformed input returns a `GateError` instead of a signature.

## 8. CLI demos (`qsv-cli`)

Network-free, in-memory end-to-end scenarios plus live surfaces: `vault-setup` (NUMS + policy + address audit), `hybrid-spend-demo` (ML-DSA proof → gate → 2-of-2 witness → consensus), `inheritance-demo` (CSV 26,280 + 2-of-3 + veto), `vault-dashboard` (real bitcoind tip or `--tip`), `estate-letter [--qr]` / `verify-estate`, `leaf-budget`, `wots-params`, `kit-seed split|combine` (native and `--format slip39`), `psbt build|sign|finish` (BIP-174 file round trip), `psbt export|import` (Phase-1 SD-card round trip: BINARY card + sha256 manifest + audit sheet; import re-verifies EVERY signature against the leaf keys and judges with libbitcoinconsensus), `psbt-live` (live discovery → real mempool; `--min-inputs N ≥ 2` = multi-input consolidation, largest-first, fail-closed when unreachable), `frost-spend` (spends the FROST k-of-n GROUP key on the real chain: BIP-341 key-path-tweaked RFC 9591 ceremony, consensus self-check, broadcast; `--no-broadcast` = watchtower hold), `watchtower` (one read-only pass: heartbeat DUE ⇒ ALERT exit 1, CSV countdown, live coins, optional REAL FROST dry run) and `bip360-status [--online]` (K1 tracker). Exit codes are scripting-friendly: 0 ok, 1 failure, 2 usage.

## 9. Test matrix (acceptance criteria)

| # | Test | Pins |
|---|---|---|
| 1 | NUMS determinism (fixed seed ⇒ fixed point) | Doc 03 §2.2 |
| 2 | NUMS point is a valid secp256k1 element | BIP-340 lift_x |
| 3 | Address derivation (mainnet/testnet/regtest) | BIP-341 |
| 4 | Policy compiles + Tap descriptor encoding | BIP-379 |
| 5 | 2-of-2 hybrid witness satisfies | Theorem 1 |
| 6 | PQC round trip / forge rejection / fail-closed | FIPS 204 |
| 7 | Enclave gate refuses an invalid PQC proof | Theorem 1 |
| 8 | Unvault output is forced to staging | Theorem 3 |
| 9 | CSV 144 / 26,280 encoding correctness | BIP-68/112 |
| 10 | 2-of-3 heir threshold + PQC commitment parity | Doc 04 §5–6 |
| 11 | WOTS+ size constants (67×32) + round trip + tamper | Doc 02 §4 |
| 12 | PSBT device round trip accepted by a real node's mempool | BIP-174/371 + e2e |
| 13 | Emergency leaf full spend accepted by consensus, tamper rejected | Theorem 6 |
| 14 | Witness element > 520 B is consensus-illegal | BIP-342 |
| 15 | Estate letter determinism + secret-free + section integrity | Doc 10 §7 |
| 16 | **All four leaves** accepted by consensus from real signed reference spends (CSV nSequence included); first-signature tamper rejected | T7 · Theorems 3+4+6 |
| 17 | Policy ↔ MAST parity: same CSVs, 6 policy keys in leaves 1–3, leaf 4 policy-free (digest commitment), 4 control blocks | T8 · BIP-379 ↔ BIP-341 |
| 18 | Per-leaf budget measurements (script/control/witness/vbytes/fees); every element ≤ 520 B | BIP-341/342 · `budget.rs` |
| 19 | WOTS+ parameter space: no `w` fits a 32 B message in 520 B (min 1,088 B); truncation ceiling 112 bits | RFC 8391 · `wots-params` |
| 20 | Native Shamir k-of-n round trip + fail-closed tag (2-of-5 never yields a wrong key; mixed sets rejected) | `shamir.rs` |
| 21 | verify-estate: authentic letter 8/8 PASS, one flipped byte = FAIL + exit 1, wrong-network hint | Doc 10 §7 |
| 22 | Experimental P2MR address: `bc1z…`, witness v2, program = merkle root, control block 65 B | BIP-360 Draft v0.12.1 (Doc 11) |

| 28 | Multi-input PSBT: 3 live coins merge into one consolidation spend (PSBT fields + per-input device signatures + witness assembly + consensus ACCEPT, over-spend REJECT); the CLI `--min-inputs` path is rehearsed against a live node; the builder writes `tap_merkle_root` on every input (Coldcard/Ledger BIP-341 Q derivation) | T7 · BIP-174/371 · `qsv-core/src/psbt.rs` · `qsv-cli/tests/regtest_psbt.rs` |
| 29 | SD-card hardware round trip: export trio (BINARY BIP-174 + sha256 manifest + audit sheet) → device signing → import: manifest + EVERY tap script-sig verified under the leaf keys + consensus ACCEPT; flipped byte / manifest mismatch / forged signature / stripped PSBT = exit 1 | Doc 10 §3.1 · `qsv-cli/tests/hw_roundtrip.rs` |
| 30 | Inheritance watchtower: healthy pass exits 0 and NEVER false-alarms; with --deal a REAL FROST dry run (hold absent from the mempool, second run yields the SAME txid — RFC 9591 nonces fresh, spend deterministic) | Doc 04 §2+§4 · `qsv-cli/tests/watchtower.rs` |
| 31 | Mutation audit: 30 deliberate crypto/logic mutations (NUMS counter, Shamir tag, FROST envelope + group signature + duplicate identifiers ×2, heir binding, device-verification gate, multi-input amounts + prevout-count guard, heartbeat due + expiry invariant + self-churn + dust, unvault dust, attestation: root pin + PCR0 + nonce + user_data binding + validity window + COSE signature + Signature1 label; **Round 30:** rate-limit bucket, drain-deadline health clear, webhook HMAC outer pad, rotation-state v2 gate, BIP-371 merkle root, SLIP-39 digest tag, source allow-list, metrics scrape gate; **Round 31:** estate-letter comparators ×2 (incl. the wrong-network hint), WOTS+ verification-chain step, the `pid_alive(0)` bogus-record wall, `classify(None) ≠ Live`, the plaintext-off-loopback refusal, bare/wildcard bind ≠ loopback, the webhook `"<ts>.<body>"` replay binding, the P2MR witness version (bc1z), the CBOR depth wall (32), the non-ASCII hex wall; **the live-scan fix (Round 31, §4.56):** the scan read-budget guard (M42), the `-8 Scan already in progress` recovery guard (M43); **Rounds 33–36:** the DKG threshold binding (M44), the watch-only output-key binding (M45), the vacuous-mirror wall + k-of-n merge + k=0/k>n clamp (M46–M48); **Round 37:** the finmodel tiers/gross-MoR identity (M49–M50) and the estate insolvency/priority/overflow walls (M51–M52); **Round 38:** the documentation fence wall (M53 — `qsv-core::docs`); **Round 39:** the console descriptor wall (M54) — 43 → **54 mutants**, every file restored from a byte snapshot) — all KILLED = the test matrix is behavioral | `scripts/mutation_audit.sh` (CI job) |
| 32 | **Panic audit + fuzz gate (Round 25):** 42 production panic sites classified (server request path = 0); 3 parsers run under libFuzzer in a bounded window (attestation CBOR, frame/health/watchtower JSON, SLIP-0039) — the fuzz found TWO real panic classes (byte-index slicing on multi-byte text, a multiply overflowing on a document length plus unbounded recursion) and both are fixed; crash inputs are locked into the corpus as regression seeds | `scripts/fuzz_gate.sh` · `nsm.rs` regression tests |

**Panic classification (Round 25 — 43 candidates, 42 production; test modules excluded):**

| Group | Sites | Verdict |
|---|---|---|
| Server request path (`server.rs` + `serve_http_head` + frame) | **0** | every external input is answered with `Result`; no panic on the request path |
| `nsm.rs` take-unwraps ×3 (210–212) | 3 | `take(n)` returns `Err` on truncation → the `try_into().unwrap()` can never fire; `take` itself was hardened against overflow in Round 25 |
| `nsm.rs` `hex_decode` + `skip` (invisible to the token grep) | 0→2 | **found by fuzz:** byte-index slicing (char boundary) and a `2*n` multiply overflow plus unbounded recursion → is_ascii guard / end-bounds arithmetic / depth-32 limit, with regression tests |
| `slip39.rs` gf_inv expectation (162) | 1 | `combine` checks duplicate indices and thresholds BEFORE interpolating — guarded |
| `main.rs` internal-consistency expectations | 19 | the application's own construction (merkle root, tweak, control block) — each `expect` says why; 2117 sits behind `if let Some(url)`; 2521 is the infallible `to_value(String)` |
| Deterministic internal data (qsv-core ×13, qsv-node ×6, qsv-pqc ×1) | 20 | tweak/sighash/control-block encodes — input is derived, never external |

**Plus the live/structural suites:** the SLIP-0039 implementation passes all 45 official vectors (`slip39.rs`), the K1 tracker audits the migration plan and diffs the live BIP header (`bip360.rs`), the CLI's estate-letter flow is proven against a real bitcoind (fund → verify → tamper ⇒ exit 1), the FROST group key spends on the real chain (`frost-spend`: tweaked ceremony → mempool acceptance → confirmation; unfunded address fails closed), the multi-input PSBT consolidation merges 3 live coins into one consensus-verified spend with `tap_merkle_root` on every input (`regtest_psbt.rs`, `psbt.rs`), and the docs-sync walls keep every module structurally sound.

**Acceptance threshold:** `cargo test --workspace` 100% green (**512 tests in both the plain and the consensus configuration — the two runs execute the identical test set, because `qsv-cli` and `qsv-node` enable the consensus feature unconditionally so the reference engine links in either build; `qsv-core`'s own suite is 191 of the 512** — including the 45 SLIP-0039 vectors, 5 K1-tracker checks, 9 docs-sync walls, 5 FROST core tests, 35 live CLI/node e2e flows [estate + live PSBT ×3 + FROST spend (+ co-signer gate + multi-UTXO consolidation) + watchtower + watchtower-daemon (+ rotation-state v2) + inheritance-kit + SD-card hardware-round-trip + vault-rotate (+ bridge) + vault-rotate multi-vault sweep (+ dry-run) + vault-rotate sweep co-signer gate (+ mTLS) + P2MR source trial + bridge unit generator (+ TLS bake) + bridge TLS + bridge mTLS + bridge rate limit + bridge SIGTERM drain + bridge slowloris bound + bridge scrape token + bridge rolling handover + bridge in-flight cap + bridge health record (SIGTERM cleanup) + bridge notify/watchdog + bridge scrape-token-file ×2 + bridge drain deadline + bridge SIGHUP token rotation + bridge live exposition contract + operator doctor ×2 + mempool policy ×2] — on top of the live and document suites); `cargo clippy -D warnings` clean in both configurations plus the cosigner `nsm` feature as a third; the mutation audit kills all 54 injected mutants plus the automated sweep wall (`scripts/mutation_sweep.sh`, Round 32: every product file is either hand-mutant-covered, mechanically mutant-covered, or on an allowlist with a written reason; a surviving applicable test = KILLED, a non-compiling mutant = UNVIABLE and never counted, a survivor with no documented equivalence = RED); `cargo llvm-cov` coverage gate is DOUBLE-THRESHOLDED (Round 31: lines ≥ 97.5% AND functions ≥ 82.0% — both floors live as single numbers in `scripts/coverage_gate.sh`; measured in the Round-31 full gate run: lines 97.78%, functions 82.58% — `tests/` targets are not in the llvm-cov data); `scripts/nitro_e2e.sh` phase-1 live-wire rehearsal (PASS + 3 refusals); every theorem cross-linked to at least one test.

## 10. Phase map and next milestones

* **Phase 0 (DONE):** this repository — evidence-driven core + PQC engine + test matrix + operation guide.
* **Phase 1:** real signet transaction loop (Bitcoin Core signet node), Nitro Enclave co-signer daemon (vsock + PCR attestation), Coldcard/Ledger PSBT integration, SLIP-0039 provisioning wizard.
* **Phase 2:** inheritance watchtower service + corporate panel. *(The SLIP-0039/FROST threshold wizard was pulled into Phase 0 in the September 2026 round: `qsv-core::frost` core + the RFC 9591 ceremony CLI `inheritance-kit` + SLIP-0039 share backup; the live PSBT Phase-2 beginning also landed as `psbt-live`; the read-only `watchtower` alert pass with a REAL FROST dry run and the `frost-spend --no-broadcast` hold mode joined Phase 0 in the Round 8 round.)*
* **Phases 3–4:** BitVM2 verification-line research and the BIP-360 (P2MR) migration — **defined in Document 11 with decision gates K1–K3** (consensus code only after K1; `qsv-cli bip360-status` tracks the gate).
