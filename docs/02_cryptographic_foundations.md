# Module 02 — Cryptographic Foundations: NIST FIPS 204 (ML-DSA), Lattices, WOTS+

> Specification module 02 of QuantumSafe-Vault — v2026.3.

## 1. Scope: post-quantum cryptography and the 2024 NIST standards

Post-quantum cryptography (PQC) is asymmetric encryption and digital signatures built on problems that defeat **both** classical and quantum computers. In August 2024, after an eight-year global competition, NIST published the first official PQC standards: **FIPS 203 (ML-KEM)** for key establishment, **FIPS 204 (ML-DSA)** for signatures and **FIPS 205 (SLH-DSA)** as the hash-based signature standard, with FN-DSA (Falcon) to follow. This module covers the two families this protocol actually uses — lattice-based ML-DSA for the co-signer gate, hash-based WOTS+ for the post-Q-Day emergency layer — plus the hybrid-combiner rule that says never to trust either alone.

## 2. Lattice cryptography and NIST FIPS 204 (ML-DSA)

ML-DSA is derived from CRYSTALS-Dilithium and rests on Module-LWE/Module-SWR over cyclotomic polynomial rings — no number-theoretic structure a quantum algorithm exploits, and no subexponential or quantum advantage known against M(LWE/LWR). This project standardizes on **ML-DSA-65** (Category 3):

| Parameter | Value |
|---|---|
| Public key | 1,952 bytes |
| Signature | 3,309 bytes |
| Security level | NIST Category 3 (~AES-192 equivalent) |

FIPS 204 was chosen as the best size/speed/maturity trade-off for a gate verifier inside a TEE: verification is fast, purely algebraic, and side-channel friendly. Implementation hygiene: no hand-rolled primitives (`ml-dsa` 0.1 RustCrypto for FIPS 204, `secp256k1` libsecp256k1 bindings for BIP-340), deterministic signing wherever reproducible test vectors are required, and **fail-closed** handling — a malformed key, a bad encoding or a wrong size always results in denial, never a fallback approval (`qsv-pqc::GateError`).

## 3. Bitcoin script limits and cryptographic reality

Many superficial analyses claim *"we added Dilithium to Taproot."* That claim is a **hallucination**, for two hard reasons:

1. **The 520-byte stack element limit** (`MAX_SCRIPT_ELEMENT_SIZE`): BIP-342 tapscript keeps it, and a 3,309-byte ML-DSA signature (or any 2-of-2 combination of them) cannot be pushed onto the stack at all. Opcode-level PQ verification would need a consensus change plus a verification routine far too large for script.
2. **Bytecode and witness-size economics**: even where a scheme would fit, the script budget (fee per byte, standardness, and the ≤520 B per witness element rule enforced by BIP-342) makes multi-kilobyte signatures a fee and relay liability.

Hence the honest architecture: keep consensus cryptography classical and short (Schnorr, 64 bytes), move the post-quantum assertion **off-chain** into a gate that releases a classical signature, and keep any on-chain PQ verification hash-based (Module 02 §4, Module 11 §7). The only PQ material that ever touches the chain today is a 32-byte digest (leaf 4's commit), which is why it is a commit-reveal.

## 4. On-chain post-quantum: Winternitz one-time signatures (WOTS+)

Hash functions (SHA-256) keep their security against quantum computers, so **hash-based signatures are the only PQ signature family verifiable inside Bitcoin Script without a soft fork**. WOTS+ (RFC 8391) signs with chained hash invocations: for a 32-byte message at `w=16`, chains are 64 steps long and the signature is `(len1+len2)·32` bytes — one-time, large, but built only on SHA-256. Delivered result (**Sept 2026, `qsv-cli wots-params`**): *no* Winternitz parameter fits a full 32-byte digest into a single 520-byte tapscript element — the global minimum is 1,088 B at w=256 (34 chains), and truncating to fit bottoms out at **14 bytes = 112 bits**, below SHA-256's 128-bit collision target, which is forgery-prone. Therefore leaf 4 ships as a **37-byte commit-reveal**: the chain stores a digest, the WOTS+ seal itself stays air-gapped inside the emergency kit, and the parameter table above is the numeric proof that this is not a stylistic choice but an impossibility result.

## 5. Hybrid cryptographic combiners and CNSA 2.0 compliance

NIST SP 800-227 and BSI guidance are explicit: *PQC algorithms are young; never trust PQC alone — always hybridize it with a classical algorithm.* The vault therefore uses a **strong combiner**: the composite claim is *"theft requires breaking Schnorr **and** ML-DSA **and** the TEE"*, i.e. the spend condition is `Schnorr(user) ∧ Schnorr(enclave)` with the enclave's release gated by `ML-DSA-65(gate)`. The components rest on disjoint hardness assumptions (ECDLP vs. Module-LWR) and the TEE adds an independent hardware boundary, so no known classical or quantum attack breaks the combination without breaking all three. The same combiner logic extends to the future migration slots (BIP-361 PQ signatures; hybrid ECDSA+PQ remains the NIST IR 8547 default through 2035). Compliance posture: **CNSA 2.0** (NSA) requires national-security systems on PQC by 2030 and browsers/OS by 2033 — this design is ahead of that curve rather than behind it.

---

## 6. Defense position against side channels and rollback (Round 31)

> This section is a **defense POSITION paper**: what we defend, with which mechanism, which literature it contends with, and — explicitly — **what we deliberately do NOT defend**. Trigger: the Round-29 finding #4 ("are the Nitro critiques — side channel, replay/rollback — present in the docs, or do they retreat?"). The evidence level is code + tests; it **claims no measurement or laboratory result.**

### 6.1. Threat inventory → the countermeasure in place

| # | Attack (literature) | Countermeasure (code) | Evidence |
|---|---|---|---|
| 1 | **Attestation replay** — re-presenting an old COSE_Sign1 document | v2 **client-side challenge nonce** (generated inside `SignRequest::nonce_hex`); a mismatching nonce is refused. On top: PCR0/1/2 pins, X.509 root pin, `user_data` = xonly‖vault binding; `timestamp` is advisory only — **freshness comes from the nonce** | docs/10 §4.52 · `cosign_probe` · `nsm.rs` |
| 2 | **A forged "all-clear"** dropping the alarm freeze | the alarm state can only **STOP the protocol, never shortcut it**; the bridge mirrors every ALERT into `set_alarm` and every recovery into `clear_alarm`; the health file records which `watchtower_tip` the mirror was seeded from | `server.rs` (AlarmState) · `bridge.rs` · `health.rs` |
| 3 | **Terminal-state rollback** (`watchtower-state.json` / `rotation-state.json`) | unreadable state = **fail-closed, never a silent reset**; stale-row detection (`rotation_baseline_for` + `row_is_stale`); a stale file preserves the OLD view, and the old view is treated as the threat; atomic writes (temp+rename), a dead pid = hard failure; "absence never means healthy" | `main.rs` (watchtower/rotation) · `health.rs` |
| 4 | **PSBT/ceremony signature replay** | envelope tags force the `NONCE_v1` vs `SHARE_v1` split; FROST nonces are single-use per ceremony and post-aggregation BIP-340 verification is mandatory; the webhook `"<ts>.<body>"` binding makes a captured POST forever invalid | module 04 §7 · mutation M38 |
| 5 | **Timing / shared-cache** (Trail of Bits, 2024-09-24: the parent can measure application timing to near clock precision; Rammouz & Le, SysTEX@EuroSys 2026: Prime+Probe secret-bit extraction through the LLC) | **no hand-rolled primitives at the signing boundary**: BIP-340 → libsecp256k1, ML-DSA-65 → RustCrypto `ml-dsa` (FIPS 204); gate verification is pure algebra; the network layer is TLS + loopback walls (M36/M37) | `tls.rs` · `nsm.rs` · M36/M37 |
| 6 | **Enclave time control / rolled-back clocks** (ToB: untrusted time → replaying time-sensitive documents) | freshness **never comes from the enclave clock** — the client nonce carries it; `timestamp_ms` is explicitly **not a security-decision input** (advisory) | `nsm.rs` (the timestamp comment) |

### 6.2. What we deliberately do NOT defend (the honest list)

- **No measurement:** no power/EM/acoustic lab; no Prime+Probe mitigation (Intel CAT / NUMA pinning) is **configured**. Rammouz & Le's production result means an operator running inside an enclave must ASSUME the LLC side channel is available. The ToB advice "attest the mitigation" was not implemented because there is no mitigation to report — written down as: **absent = absent.**
- **No constant-time audit:** our own Shamir GF(256) arithmetic (Russian-peasant bit loop) is **not constant-time**. The scoping rationale: an air-gapped offline emergency kit that never runs on the signing path and sits outside the attacker's channel; RustCrypto `ml-dsa`'s "never independently audited" warning is upstream and carried verbatim.
- **No persistent sealing:** Nitro offers no persistent storage or sealing, and we do NOT trust sealed-rollback-prone state — the alarm and its mirror live on the terminal side with fail-closed reads. Consequence: a fully compromised terminal can SUPPRESS alerts; the remaining depth is an independent watchtower host (docs/10 §5).
- **Blast radius (a description, not a claim):** the co-signer key alone is never sufficient — the spend is `Schnorr(user) ∧ Schnorr(enclave)` gated by ML-DSA-65, and an alarm freeze stops co-signing entirely. That is a *depth* argument, NOT a measured side-channel resistance.

### 6.3. What would upgrade this section (the watch list)

1. A cache/LOG mitigation inside the enclave plus the measurement info in the attestation (the ToB advice).
2. An independent constant-time / side-channel **measurement** audit (alongside the audit item).
3. An alarm-mirror **rollback drill** on an independent watchtower host.

*Sources: blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface · doi.org/10.1145/3805690.3805729 (Rammouz & Le, "Breaking Isolation: Last-level Cache Side-Channel Attacks on AWS Nitro Enclaves", SysTEX@EuroSys 2026).*
