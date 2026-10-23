# Module 04 — QuantumSafe Legacy: Dead Man's Switch & Digital Inheritance Protocol

> Specification module 04 of QuantumSafe-Vault — v2026.3.

## 1. The inheritance problem is a liveness problem

Every custody product solves "who can spend?" — almost none solves "what happens when the owner *cannot*?" Court-supervised probate for Bitcoin is slow, public, and jurisdiction-dependent; the statistically dominant loss mode for self-custody is not theft but **silent key loss**.

## 2. The Dead Man's Switch, on-chain

`qsv-core::heartbeat` defines the policy:

- **Period** 12,960 blocks (~90 days), **margin** 1,008 blocks (~7 days), configurable.
- A healthy owner periodically builds a **self-churn refresh transaction**: the vault spends to *itself* (same policy, new keys derived deterministically), resetting the timer. This is the only recurring on-chain act — one signature per period, minimal HITL.
- `is_due()` / `blocks_until_expiry()` are pure functions of chain height, so any observer — heir, executor, service — computes the same state without trusting anyone.

## 3. Inheritance leaf

After 26,280 blocks (~180 days) of silence, leaf 3 activates: a **2-of-3 threshold** among user/heir/executor keys pays out. No company, server, or signature service participates; the chain itself is the notary. The 180-day delay is the trade: long enough to survive owner travel, device loss, and hospital stays; short enough that heirs are not economically punished.

## 4. Heir identity sealing

Impersonation of heirs is the classic inheritance attack. Each heir's classical key is **hash-bound to an ML-DSA-65 identity attestation** (`qsv-core::heirs`); verification is fail-closed — a mismatched commitment rejects the spend rather than falling back. Breaking inheritance requires breaking FIPS 204 *in addition to* acquiring threshold keys.

## 5. Succession mechanics & privacy

- Executor key exists to *help* the 2-of-3, never to spend alone.
- Veto window (30 days) lets a returning owner recover from a false trigger by churning the vault once more.
- Heirs learn of their role out-of-band; the blockchain reveals only an ordinary-looking taproot output until settlement, when the revealed leaf is the inheritance script — nothing else about the vault's other policies leaks.

## 6. Property alignment

The scheme mirrors **TMK m. 599** (Turkish Civil Code on wills): the owner's hand (their key) writes the disposition, heirs accept it on-chain, and the state's role is reduced to recognizing an already-executed transfer — the subject of Module 05's legal analysis.

## 7. FROST adaptive-security & nonce-lifetime security statement

*This section is a BOUNDARY statement, not marketing: what we claim, what we do not, and why — aligned with the 2025–2026 literature (ePrint 2025/1061 · 2025/1001 · RFC 9591).*

### 7.1. Where the standards stand — what we do NOT claim

- **RFC 9591 (Jun 2024) is *Informational*** and defines **no BIP-340 ciphersuite** for Bitcoin. This repo uses FROST on its own terms: the threshold signature verifies as ONE standard 64-byte BIP-340 signature under the group key; the chain layer is independent of the protocol.
- **The adaptive-security debate (CRYPTO 2025) is unresolved:** both adaptive-security results (ePrint 2025/1061) and the counter-paper claiming full adaptive security cannot be proven without modifying the protocol (ePrint 2025/1001) appeared. **This project does NOT claim to produce an adaptive-security proof.** Our attack model is static corruption plus a live threshold scene; that boundary is written here.
- The FROST core is an **audited crate** (`frost-secp256k1-tr` 3.0, the secp256k1/Taproot derivative of the Zcash FROST reference); the hand-written layer in this repo is not the protocol but the **envelope distribution, package tags and ceremony wizard**. Even so, no hand-written layer — this one included — has passed an independent cryptographic audit (STATUS.md §2); this statement does not substitute for one.

### 7.2. Nonce-lifetime rules (each maps to code)

1. **Single-use nonces minted at ceremony start.** `round1::commit` derives fresh nonces every ceremony (`OsRng` at the CLI boundary); the nonce package is sealed under the `QSV_FROST_NONCE_v1` envelope tag and carried separately from share packages (`…_SHARE_v1`) — a nonce package can never be replayed as a share package (only a tag match is accepted).
2. **Nonce reuse is locked by a test.** Re-signing the same message with *fresh* nonces must produce a DIFFERENT signature (`frost.rs`: "fresh nonces must give a fresh signature"). Reusing a deterministic nonce across two messages leaks the private key; nonce packages are therefore NOT persisted after a ceremony — the next ceremony mints new ones.
3. **Mandatory post-aggregation verification.** Aggregation enforces BIP-340 verification under the group key; a failure is `BadSignature` and fails closed — a wrong nonce/key combination can never be reported as a "successful ceremony".
4. **Tweak linearity kept separate.** The BIP-341 key-path tweak is linear; a tweaked ceremony runs only with tweaked packages and a plain ceremony only with plain ones — the envelope tags enforce the split.

### 7.3. Out of scope (what this statement does not rely on)

- An adaptive/UCO security proof — the literature is open, no claim is made.
- Independent audit — none performed; 97.85% line coverage and 30/30 mutations are *behavioral* evidence, not an audit.
- Hardware-secure nonce storage: the ceremony coordinator is a trusted-but-compromisable party; share holders never write nonce packages to disk, and the printed SLIP-0039 words are the share's backup.
- Coordinator-less ceremonies: the current flow is trusted-dealer plus a two-round coordinator ceremony — it models the OWNER arranging their own family distribution, not a third-party coordinator.
