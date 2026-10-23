# QuantumSafe-Vault — Specification Library

The 11 specification modules of the project, in English. Version v2026.3.

| # | Module | File |
|---|---|---|
| 01 | Quantum Threat Model: Shor/Grover, mempool sniffing | [`01_quantum_threat_model.md`](01_quantum_threat_model.md) |
| 02 | Cryptographic Foundations: FIPS 204 (ML-DSA), WOTS+, side-channel/rollback position | [`02_cryptographic_foundations.md`](02_cryptographic_foundations.md) |
| 03 | Taproot, Miniscript & Two-Layer Hybrid Vault Architecture | [`03_taproot_miniscript_vault_architecture.md`](03_taproot_miniscript_vault_architecture.md) |
| 04 | Legacy: Dead Man's Switch & Digital Inheritance Protocol | [`04_legacy_dead_mans_switch.md`](04_legacy_dead_mans_switch.md) |
| 05 | Legal Armor: Inheritance Law & Non-Custodial Status | [`05_legal_armor.md`](05_legal_armor.md) |
| 06 | Financial Model & Unit Economics (AUM / SaaS metrics) | [`06_financial_model.md`](06_financial_model.md) |
| 07 | Realistic Competitive Analysis (Casa, Unchained, BitGo, Fireblocks) | [`07_competitive_analysis.md`](07_competitive_analysis.md) |
| 08 | Academic Bibliography & 2026 Empirical Report | [`08_bibliography_and_2026_report.md`](08_bibliography_and_2026_report.md) |
| 09 | Implementation Architecture & Coding Plan | [`09_implementation_architecture.md`](09_implementation_architecture.md) |
| 10 | Operations & User Guide (`qsv-cli`) | [`10_operations_guide.md`](10_operations_guide.md) |
| 11 | BIP-360 (P2MR) Migration Plan — Phase 4 | [`11_p2mr_migration_plan.md`](11_p2mr_migration_plan.md) |

Top-level paper: [`PAPER_EN.md`](../PAPER_EN.md) · status and limits:
[`STATUS.md`](../STATUS.md) · roadmap: [`ROADMAP.md`](../ROADMAP.md).

## Consistency walls

`docs_sync` (integration test) and `qsv-cli docs-audit` (report) keep this
library structurally sound: every module present, English titles, monotonic
section numbering, subsections that belong to an existing section, balanced
code fences, resolvable links, the BIP-360 snapshot markers, and — because the
public tree is English-only — **no Turkish text anywhere in the published
docs**. A drift fails the build instead of silently shipping.
