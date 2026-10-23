# Module 01 — Quantum Threat Model: Shor/Grover, Mempool Sniffing

> Specification module 01 of QuantumSafe-Vault — v2026.3.

## 1. Scope and introduction

Bitcoin's theft resistance rests on the presumed hardness of the elliptic-curve discrete logarithm problem on **secp256k1**: ECDSA since 2009 and BIP-340 Schnorr since the 2021 Taproot upgrade. Both are broken by Shor's algorithm on a large fault-tolerant quantum computer — a public key (fully exposed by any *spent* P2PK or reused address) yields the private key directly. Classically, the best generic attack is Pollard's rho at ≈ 2^128 operations, i.e. thermodynamically infeasible; quantumly, that margin disappears. This module defines the threat model every later design decision is measured against.

## 2. The quantum algorithms: secp256k1, ECDLP and the 2025–2026 resource estimates

secp256k1 is the curve `y² = x³ + 7` over the prime field `p = 2^256 − 2^32 − 977`. Solving ECDLP is what a CRQC (cryptographically relevant quantum computer) must do to forge a signature from a known public key. What changed in 2025–2026:

| Datum | Value | Source |
|---|---|---|
| RSA-2048 factoring cost | < 1M noisy qubits, < 1 week | Gidney 2025, arXiv:2505.15917 (~100× better than 2019) |
| 256-bit ECDLP | ~1.2–1.45K logical qubits (< 500K physical) | Babbush et al. 2026, arXiv:2603.28846 |
| Logical-qubit leader | 96 (QuEra); Microsoft+Quantinuum 12 @ 2·10⁻³ error | 2026 hardware surveys |
| Break-even QEC at scale | dozens of protected logical qubits, trapped ion, March 2026 | Quantinuum |
| Roadmap milestone | IBM Starling ~200 logical qubits, 2029 | IBM Quantum roadmap |
| IonQ break-time estimate (8 Sep 2026) | 20,000 physical qubits ⇒ secp256k1 in **< 26 days** | IonQ paper, Sept 2026 |
| Logical-qubit record (Aug 2026) | Google Willow **105 logical qubits**, next milestone 1,000+ | Google / Circle, Aug 2026 |
| ECC-breaking hardware / migration advice | hardware ≈ **end of decade**; transition advised **by 2029** | Google research, March 2026 |
| Exposed BTC | ~6.9M in P2PK / reused outputs (4.5–7M, Nervos July 2026) | Project Eleven, May 2026 |
| Planning Q-Day window | 2030–2042 (base 2033); BIP-360 retitled **P2MR** | Composite; bip360.org |

**Design consequence:** "no big machine yet" is not a defense. Harvest-now-decrypt-later attackers already collect exposed keys; a vault designed today must assume Q-Day inside its *owner's* holding horizon.

## 3. Grover's algorithm and cryptographic hash functions (SHA-256)

Bitcoin's other foundation is SHA-256 (block headers, merkle trees, address hashing). Grover search speeds up preimage attacks quadratically: a 256-bit preimage becomes ~2^128 work, and collision resistance degrades far more gracefully (BHT-style ≈ 2^85, and only with substantial quantum memory). **SHA-256 therefore survives the quantum era at a still-comfortable margin; secp256k1 does not.** This asymmetry is the design lever of the whole protocol: security must be moved *from public keys to hashes* — which is exactly what a NUMS internal key (a hash output with no known discrete log) and a hash-based (WOTS+) emergency layer do.

## 4. Empirical distribution of vulnerable assets on the Bitcoin chain

Not every BTC is equally exposed; exposure depends on whether the *public key* sits unhashed on-chain:

| Asset class | Exposure | Why |
|---|---|---|
| P2PK (Satoshi-era coinbase) | immediate | pubkey in the output script |
| Address-reuse outputs | immediate | pubkey revealed at first spend |
| Any single-use address at spend time | 10-minute window | pubkey enters the mempool with the spending tx |
| Fresh, never-spent P2WPKH/P2TR | long-exposure only | pubkey hidden behind a hash / NUMS point |

Roughly 6.9M BTC sits in the first two classes. The vault's rule follows directly: never reuse an address, and make the *only* spend path a script-path spend under a NUMS key so no usable public key is ever exposed.

## 5. Mempool sniffing and the zero-day race condition

A classically-motivated attacker (no quantum computer needed, active **today**) watches the mempool for unvault transactions and RBF-outbids the victim to redirect coins to an address of their own. The attack window is the ~10-minute block interval during which the spender's public key is public. Without a covenant the attacker simply double-spends the input; with the two-stage covenant, *every* spend of the unvaulted input — theirs included — must land in the pinned staging address, so the sniffer can only follow the money into the same cage. The 144-block window (~24 h) gives the owner time to claw back through the recovery leaf. Adversary classes carried into the design: **A** quantum key attacker (defeated by NUMS + PQC gate + no reuse), **B** mempool sniffer (defeated by path pinning), **C** key loss / inheritance failure (defeated by the heartbeat dead man's switch and 2-of-3 heir settlement).

## 6. Harvest Now, Decrypt Later (HNDL) and the BIP-360 merger

HNDL is far more destructive on a blockchain than in ordinary communications: ciphertext captured today can be stored indefinitely and decrypted the moment keys become breakable, and the chain *is* the ciphertext — public keys of spent outputs are already readable. The protocol-side first answer arrived in **February 2026**, when **BIP-360 "Pay-to-Merkle-Root (P2MR)"** was merged: it preserves P2TR functionality while removing the key-path spend **at consensus level** (`bc1z`, SegWit v2, program = merkle root). QuantumSafe-Vault's architecture is already the protocol-level mirror of that rule (NUMS cancels the key path mathematically), so the migration is an output-wrapper change, tracked in Module 11 with decision gates K1–K3. P2MR alone covers *long exposure* only; short exposure (mempool) stays the domain of the covenant and future PQ signatures.

## 7. Scope of the QuantumSafe-Vault countermeasure

1. **NUMS internal key ⇒ key-path cancellation:** the internal key is a SHA-256 output, not a curve point with a known discrete log; Shor has nothing to solve (Theorem 2).
2. **PQC-gated second signature:** the enclave releases its Schnorr key only behind a fail-closed ML-DSA-65 verification (Theorem 1).
3. **Path-pinned funds:** unvault outputs are consensus-pinned to a single staging address (Theorem 3).
4. **Chain-observable inheritance:** heartbeat dead man's switch + 2-of-3 heirs (Theorem 4).
5. **Consensus-level proof:** every construction is verified by libbitcoinconsensus, not by our own code alone (Theorem 5).

Every invariant above is pinned by tests (Module 09 §9) and verified live on bitcoind (qsv-node e2e).
