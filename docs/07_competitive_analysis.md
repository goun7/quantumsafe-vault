# Module 07 — Realistic Competitive Analysis: Casa, Unchained, BitGo, Fireblocks Teardown & Moats

> Specification module 07 of QuantumSafe-Vault — v2026.3.

## 1. Landscape (verified 2026 posture)

| Competitor | Model | Quantum posture | Inheritance | Covenant |
|---|---|---|---|---|
| **Casa** | 2-of-3 / 3-of-5 collaborative multisig (ECDSA) | None — ECDSA-only key sets | Heir service (human process) | No |
| **Unchained** | 2-of-3 multisig + IRA products | None | Documentation + cosign process | No |
| **BitGo** | Institutional custodial + MPC | MPC ≠ PQC; threshold ECDSA | Contractual | No |
| **Fireblocks** | MPC custody/ops | Same — MPC reshuffles shares, still classical | Contractual | Policy-engine, not consensus covenant |
| **Project Eleven / BTQ** | Research testnet | PQC *experiments* | — | — |

**Reading:** every production custody product remains classical-ECDSA-based; PQC exists only in research testnets. The intersection *PQC gate × covenant × inheritance* is unoccupied.

**Verified 2026 pricing & features (September 2026):**

| Provider | Plan & annual price | Key model | Inheritance mechanism | Insurance | Quantum protection |
|---|---|---|---|---|---|
| **Casa** | Standard **$250/yr** (2-of-3); Premium **$2,100/yr** (3-of-5); Private Client | Client holds 2 keys + Casa 1 recovery key (Casa cannot spend unilaterally) | Inactivity detection + **6-month wait** (Private Client: identity verification + death certificate, no wait) | **None** on client balances | **None** — classical ECDSA |
| **Unchained** | Vault **$250/yr** | 2-of-3 (client 2 + Unchained 1) | Documentation + cosign process; heir must recover keys | Product-specific | **None** |
| **Onramp** | Tiered Core/Private; brokerage **0.65%** | **Multi-institution 2-of-3** (Onramp + BitGo + CoinCover) | Death certificate + guided institutional transfer (heir never manages keys) | Lloyd's of London (operational, not client assets) | **None** |
| **BitGo** | Institutional custody; public company + federal bank charter (2026) | Qualified custodian + TSS/MPC | Contractual (months-long process) | Institutional | **None** — threshold ECDSA |
| **Fireblocks** | **Six-figure** annual entry (2026) | MPC-CMP (SGX) | Contractual; B2B-only rail | Policy engine | **None** |
| **QuantumSafe-Vault** | MIT-licensed protocol (Phase 0) | Hybrid 2-of-2: Schnorr + **FIPS 204 PQC gate** | **L1 consensus:** CSV 26,280 + 2-of-3 + 30-day veto (code, not contract) | Not needed (non-custodial) | **Yes** — NUMS + PQC gate + WOTS+ kit |

**Reading:** (1) incumbents' inheritance is either a *human process* (Casa's 6-month wait) or *institutional guidance* (Onramp) — both depend on a counterparty's goodwill; ours is enforced by Bitcoin L1 alone. (2) Insurance is a **financial compensator**, not cryptographic protection: against Shor it pays out after the loss. (3) The market floor ($250–2,100/vault/yr, or 0.05–0.50% of AUC) shows a mature market where the only open lane is post-quantum verifiability.

**Threat clock (September 2026 deltas):**

- **IonQ (8 Sep 2026):** a 20,000-physical-qubit machine could break secp256k1 in **under 26 days**.
- **Google Willow:** 105 logical qubits achieved; next milestone 1,000+. Google's March 2026 research puts 256-bit-ECC-breaking hardware at **end of decade**; its own migration advice says **by 2029**.
- **~7M BTC** sit in quantum-exposed addresses (Project Eleven ~6.9M).
- **US federal ECDSA phase-out by 2035** (NIST IR 8547, hybrid exemption); CNSA 2.0 software/networking by 2030 (browsers/OS 2033).
- **SHRINCS / OP_CHECKSHRINCS (Blockstream, 12 May 2026):** a Bitcoin-specific compact PQC candidate with a **WOTS+ core**, SHA-256 throughout (324 B first signature, ~580 B deployed, live on Liquid since March 2026; ~3 TPS vs ML-DSA-65's ~0.5). It is explicitly transportable "via BIP-360's P2MR leaves" — independent validation of this project's hash-based emergency bet, quantified by `qsv-cli wots-params`.

## 2. Their real moats — and our counters

- **Brand & insurance**: incumbents carry SOC 2 / insurance. Counter: non-custody by construction shrinks insurable surface to code liability; open-source auditability is the counter-brand.
- **Keyceremony operations**: they run polished multisig ceremonies. Counter: PSBT (BIP-174/371) flow with hardware wallets is the same UX without their servers.
- **Regulatory licenses**: they *need* them; we are architected to not need them (Module 05) — a cost structure advantage, not a gap.
- **Distribution**: Casa's consumer brand, BitGo's institutional rails. Counter: the protocol is MIT-licensed — exchanges/wallet vendors can embed it; distribution-by-compatibility beats distribution-by-salesforce for protocol adoption.

## 3. Honest gaps (what incumbents have that we do not)

1. Insurance policies and compliance paperwork enterprises demand.
2. 24/7 human recovery desks.
3. Multi-asset support (we are deliberately Bitcoin-only — taproot, covenants, and Miniscript depth beat breadth).

## 4. Strategy

Do not fight the incumbents' game (custody operations). Make their key architecture *the* liability: every Q-Day news cycle converts anxiety into demand, and the protocol is positioned exactly where that demand lands — "your multisig provider cannot fix Shor; your *keys* are the problem." The 2026 competitive window is real: BIP-360/361 activity makes PQC treasury migration a board-level topic, while no incumbent has shipped anything — as of September 2026, not one Casa/Unchained/BitGo/Fireblocks roadmap contains quantum-resistant spending, and research testnets (BTQ, Project Eleven) are not production custody.
