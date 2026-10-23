# Module 06 — Financial Model, Unit Economics & AUM SaaS Metrics

> Specification module 06 of QuantumSafe-Vault — v2026.3.

## 1. Business model

**Open-source protocol + paid sovereignty service.** The vault engine (this repository) is MIT-licensed, forcing competitors to compete on service quality rather than protocol lock-in. The commercial layer sells operations, not custody:

| Tier | Product | Pricing anchor |
|---|---|---|
| Free | CLI, self-hosted co-signer, all protocol features | $0 — grows the funnel |
| Personal | Managed enclave co-signer + heartbeat monitoring + heir onboarding | flat SaaS, ~$10–30/mo |
| Wealth | Multi-vault estate desk: executor coordination, legal-letter templates, annual attestation audit | % of AUM-adjacent flat fee |

## 2. Unit economics (2026 inputs)

- Nitro Enclave cost: ~$5–15/mo per resident co-signer (c7g.enclave instances, shared across tenants in production).
- Infrastructure per free user: ~$0.10–0.30/mo (PSBT round-trips are cheap; the gate is a few ms of CPU).
- Gross margin on paid tiers: 80–90% — the classic software shape, because the expensive component (key storage) is *outsourced to the owner by design*.

## 3. Market sizing (TAM/SAM/SOM)

- **TAM**: ~$1–2T long-term self-custodied Bitcoin value × 0.5–1.0% annual willingness-to-pay for inheritance+quantum protection ≈ $5–20B/yr.
- **SAM (2026–2030)**: BTC holders with > $50K self-custodied who already pay for multisig services — the Casa/Unchained customer base, ~$300–600M/yr.
- **SOM (first 3 years)**: PQC-anxious early adopters (the segment Project Eleven's 6.9M-BTC exposure research activates); a 0.1–0.5% capture of SAM ≈ $0.3–3M ARR at seed stage.

## 4. Metrics that matter (AUM-SaaS)

- **Vaulted value (the real AUM)**: tracked on-chain; every marketing claim is verifiable.
- **Heartbeat reliability**: % of vaults whose refresh txs landed on time (proxy for churn quality).
- **Time-to-inherit**: measured in blocks from silence to settlement ability — the protocol's core UX promise.
- **Non-custody proof**: zero unilateral-spend incidents; attestable from code + audits.

## 5. Cash-flow shape

Free tier → Personal conversion target 3–5% (multisig incumbents realize 2–4%); wealth tier drives revenue concentration but not custody risk. Because no key material is ever held, **insurance costs scale sublinearly** — the balance sheet carries no breachable honeypot, which is the financial model's deepest moat.

**Code-tested clarifications (the normative figures live in this module).** `qsv_core::finmodel` re-computes the pricing table as integer-cent arithmetic and pins it with gate tests (hand mutants M49–M50):

- **Tier boundaries are low-inclusive / high-exclusive:** 500 BTC is already Family Office, 5,000 BTC is already Custodian — the table's overlapping "500" reads this way, and below **50 BTC there is no tier at all** (`classify_operator` returns `None`, fail-closed; an unserved profile is never guessed).
- **The third tier's dual axes** ("500–5,000 BTC" and "$100M+") collapse to one implementation axis: BTC, with Custodian starting at 5,000 BTC.
- **LTV bills AUM for 4 years,** not 5: the 60-month lifetime excludes the setup year (the doc's $69.900 example; `LTV_AUM_YEARS = 4`).
- **Break-even's "≈1.2" is a ratio; the operator must actually sell 2 setups** (`break_even_customers` → 2, `break_even_exact_x10` → 12).
- **Only Year 1's license revenue decomposes into the pricing table** (18×$4.900 + 5×$9.900 + 1×$24.900 = $162.600); Years 2–3's rows are not derived in the doc, so the model pins their totals (gross = license + AUM/SaaS; net = gross − (MoR + infra + CAC); MoR = 5% of gross) rather than inventing a decomposition.
