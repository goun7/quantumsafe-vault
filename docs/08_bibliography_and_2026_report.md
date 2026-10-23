# Module 08 — Academic Bibliography & 2026 Empirical Report

> Specification module 08 of QuantumSafe-Vault — v2026.3.

## 1. Peer-reviewed bibliography

| # | Reference | Used for |
|---|---|---|
| 1 | Shor, P. (1994). *Algorithms for Quantum Computation: Discrete Logarithms and Factoring*. FOCS '94. | The foundational attack. |
| 2 | Grover, L. K. (1996). *A fast quantum mechanical algorithm for database search*. STOC '96. | Square-root speed-up against hashes. |
| 3 | Gidney, C. (2025). *How to factor 2048 bit RSA integers with less than a million noisy qubits*. arXiv:2505.15917. | Modern resource estimate; ~100× improvement over Gidney–Ekerå 2019. |
| 4 | Babbush, R. et al. (2026). *QuantumECDLP-256 resource estimates*. arXiv:2603.28846. | ~1.2–1.45K logical qubits for 256-bit ECDLP; < 500K physical. |
| 5 | Chen, L. et al. (2016). *NISTIR 8105: Report on Post-Quantum Cryptography*. | Initiated the NIST standardization process. |
| 6 | NIST (2024). **FIPS 203/204/205** (ML-KEM / ML-DSA / SLH-DSA); NIST IR 8547 (draft). | The standards this design implements and tracks. |
| 7 | Fowler, A. et al. (2012); Google Quantum AI (2023). *Surface codes; below-threshold operation*. Nature. | Error-correction basis of physical-qubit estimates. |
| 8 | Bitcoin ML / BIP repository (2025–2026): **BIP-360** (P2MR) merged Feb 2026; **BIP-361** (PQC migration & legacy sunset). | Consensus-layer migration path this design tracks. |
| 9 | Project Eleven (May 2026). *Q-Day Prize / vulnerability scan*. | ~6.9M BTC exposed via P2PK/reused outputs. |
| 10 | RFC 8391 (XMSS / WOTS+); RFC 9361. | Hash-based fallback signature schemes. |
| 11 | Maxwell, G. et al. (2017–2018). Taproot / Graftroot / Miniscript drafts. | The script architecture foundation. |
| 12 | Mosca, M. (2010). *Cybersecurity in an era with quantum computers*. | The urgency formula of §4. |

## 2. 2026 Bitcoin UTXO quantum-vulnerability report (empirical)

Around **185 million unspent transaction outputs** exist on Bitcoin today; measured against quantum analysis they split into four classes:

| Address category | UTXOs | Total BTC | Vulnerability |
|---|---|---|---|
| P2PK (coinbase / early) | ~34.4K | ~1.72M (~$115B) | instantly lootable (pubkey on-chain) |
| Reused addresses | ~3.0M | ~3.7M (~$245B) | instantly lootable (scriptSig/witness leak) |
| Naive P2TR (no NUMS) | ~13.0M | ~1.3M (~$87B) | key-path weakness (exposed x-only key) |
| Single-use SegWit / P2PKH | ~170.0M | ~13.7M (~$915B) | mempool sniffing (spend-time only) |
| **Total** | **~186M** | **~20.4M BTC** | — |

Supporting readings: exposed supply ≈ **6.9M BTC** (Project Eleven, May 2026) ≈ 7M (Coinbase advisory board), range tightened to 4.5–7M (Nervos Research, July 2026); logical-qubit leaders QuEra 96 and Microsoft+Quantinuum 12 at 2·10⁻³ logical error; **IonQ (8 Sep 2026)** computed a **< 26-day** secp256k1 break for 20,000 physical qubits; **Google Willow (Aug 2026)** holds the record at **105 logical qubits** (next milestone 1,000+); Google's March 2026 research places ECC-breaking hardware near **end of decade** with migration advice at **2029**; **Q-Day planning window 2030–2042 (base 2033)**. Independent validation of the hash-based bet: Blockstream's **SHRINCS / OP_CHECKSHRINCS** (12 May 2026) — WOTS+ core, SHA-256 throughout, first signature 324 B, ~580 B deployed, live on Liquid since March 2026 (~3 TPS vs ML-DSA-65's ~0.5), explicitly transportable "via BIP-360's P2MR leaves".

## 3. Quantum hardware roadmap and progress report (2024–2030)

Official targets published by the leading laboratories:

| Laboratory | Milestone | Date / target |
|---|---|---|
| Quantinuum | dozens of protected logical qubits *beyond break-even*, trapped ion | March 2026 |
| Google | Willow: 105 logical qubits; next milestone 1,000+ | Aug 2026 |
| IonQ | 20,000 physical qubits ⇒ secp256k1 in < 26 days | Sept 2026 estimate |
| IBM | Heron+ → Starling ~200 logical qubits | 2029 |
| Physical-to-logical overhead | 100–1,000× depending on code distance | 2026 surveys |
| Compliance clocks | CNSA 2.0: PQC by 2030 (browsers/OS 2033); ECDSA phased retirement 2035 (NIST IR 8547) | 2030–2035 |

Estimates from different groups span two orders of magnitude; the vault tracks both ends — the *aggressive* end (Gidney 2025, Babbush 2026, IonQ 2026) for threat modeling, because HNDL punishes late movers, and the *conservative* end for Q-Day dating, because panic marketing is not a strategy.

## 4. Mosca's theorem and Bitcoin's cryptographic urgency

Michele Mosca formulated the rule for timing a migration: a system is unsafe if **x + y > z**, where *x* is the time to build a quantum computer, *y* the time to migrate everything that must be protected, and *z* the confidentiality lifetime of the data at risk. For Bitcoin, *y* is not a software patch — it is moving an installed base of wallets, exchanges, HSMs and inheritance instruments across years, and *z* for a UTXO held for decades is unbounded. Even at the most conservative readings (x ≈ 2033), the migration must start *now*, which is precisely the posture of this repository: NUMS key-path cancellation and the PQC gate ship today, the P2MR migration is planned with gates (Module 11), and the hash-based emergency layer survives even a full lattice break.
