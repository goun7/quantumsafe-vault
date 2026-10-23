# Module 05 — Legal Armor: Global Inheritance Law, Non-Custodial Status

> Specification module 05 — v2026.3. *Not legal advice; jurisdiction-specific counsel is required before production use.*

## 1. Introduction and legal positioning

Holding and passing on crypto assets is as much a regulatory and tax problem as a technical one. Two traps decide the fate of most projects:

1. **Unauthorized financial service / custody breach:** if customer funds or private keys pass through the developer's control even for a moment, the company becomes a licensed-less crypto-asset custodian (CASP/VASP/MSB) and faces heavy criminal and administrative liability.
2. **Succession deadlock:** if the death of the only key holder is not anticipated *in the instrument itself*, the assets are frozen for heirs regardless of who "owns" them on paper.

QuantumSafe-Vault is positioned deliberately on the safe side of both lines: keys never leave owner and heirs, the co-signer enforces a policy but cannot move funds and cannot pick destinations, and the succession disposition is written into the spending rules rather than into a will that must be interpreted.

## 2. Global digital inheritance and probate law alignment

- **United States — RUFADAA** (Revised Uniform Fiduciary Access to Digital Assets Act, adopted in 45+ states) sets a strict hierarchy for fiduciary access: *a lawful will → a tool designated by the owner → the platform's terms of service.* The protocol's executor key plays the "designated in a tool" role **cryptographically**, which is the layer RUFADAA treats as controlling; on-chain covenants are increasingly accepted as evidence of testamentary intent, and the ML-DSA identity seal strengthens attribution.
- **Turkey — Turkish Civil Code Art. 599** (wills): testamentary dispositions must be in the owner's hand — satisfied by the owner's key signing the disposition into the chain, with the heirs' acceptance observable on-chain.
- **Probate object:** the settlement transaction *is* the probate artifact; heirs' cost basis is the estate value at acquisition (the inheritance-and-transfer regime), not trade income.
- **Estate ledger ↔ share arithmetic (code-tested, `qsv_core::settlement`):** the §2.2 split arithmetic is implemented fail-closed — estate = assets + receivables − debts (Turkish Civil Code Art. 599 universal succession); debts beyond assets ⇒ **insolvency, no payout**; legal shares must total exactly 10,000 basis points (so shares sum to 100%, no renormalization); floor + largest-remainder guarantees **`Σ shares ≡ net`** including dust, and exact-zero net is not insolvency. Gate tests pin all of it. On-chain binding is today's Leaf 3 (2-of-3 `multi_a`) paying per-heir settlement transactions — this layer produces **amounts only**; signatures, policy and consent live in the chain layer.

## 3. International regulatory shield: non-custodial (zero-custody) status

The legal basis for QuantumSafe-Vault requiring **no regulatory license** (FinCEN MSB, BitLicense, SEC Broker-Dealer, MASAK VASP, MiCA CASP) is structural, not rhetorical:

- **No custody nexus:** no server ever holds keys, so no jurisdiction can seize a key store; the co-signer verifies and *releases*, it never possesses spend capability.
- **Jurisdiction-neutral data:** the same script verifies in every country; only the surrounding estate paperwork varies.
- **Data minimization:** the chain reveals policy structure at spend time; heir identities live in PQC-sealed attestations, not in public documents.
- **Design rule:** *no code path may ever give the service unilateral spend capability* — this is what keeps the product software rather than a regulated financial service.

**Residual legal risks (honest accounting):** (1) a court may compel an executor key holder — mitigated by 2-of-3, since the executor alone cannot spend; (2) estate-tax valuation disputes remain, independent of architecture; (3) a future "unhosted wallet" rule could try to attach reporting duties to *software providers* — answered by the same non-custodial-by-construction argument, kept literally true by the covenant design.

## 4. Fiscal armor: Turkish Income Tax Law No. 193, Article 89/13 and the 100% tax exemption

The project is structured to be sold globally through a Turkish sole proprietorship / young-entrepreneur vehicle:

- **Income tax exemption (Turkish Income Tax Law No. 193, Art. 89/13):** crypto-asset transfers of assets held more than one year before disposal are exempt for individuals; inheritance settlement is treated as acquisition-at-inheritance rather than trade income. The vault's CSV timers can be aligned so settlements fall inside favorable holding windows.
- **No VAT surface:** the product is software, not a custody or exchange service, so no VAT is triggered on the license.
- **Documentation discipline:** the printed estate letter carries the chain-verifiable evidence (address, merkle root, leaf scripts, heir commitments) a tax or probate authority can be shown without revealing any secret.
