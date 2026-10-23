# Security Policy

*QuantumSafe-Vault · `github.com/goun7/quantumsafe-vault` · ROADMAP.md D8*

> This file is the normative reporting channel for vulnerabilities in this
> repository.

## 1. Reporting a vulnerability — Raporda bulunma

Report privately through **GitHub Security Advisories (private vulnerability
reporting)**:

    https://github.com/goun7/quantumsafe-vault/security/advisories/new

- **Never open a public issue** for anything that is in scope below.
- Include: affected commit / crate / file, reproduction steps (on
  regtest/signet/testnet — never mainnet), the impact you believe it has, and
  whether you are aware of active exploitation.
- **First response: within 72 hours** (human acknowledgement with a triage
  estimate). Status updates at least weekly while a report is open.
- We request **coordinated disclosure**: please give us up to 90 days before
  publishing, shorter by mutual agreement (a fix that ships sooner ends the
  embargo sooner).
- Channel availability note for the maintainer: this flow requires
  *Private vulnerability reporting* to be enabled in the repository's
  Settings → Security (account owner, ROADMAP.md D8).

## 2. In scope

A report qualifies if it affects a **released artifact of this repository**
and can be reproduced against the code as committed:

| Surface | What it covers |
|---|---|
| `qsv-core` crypto/consensus paths | `frost.rs` (RFC 9591-style ceremony, envelope tags), `wots.rs`, `shamir.rs`/`slip39.rs`, `psbt.rs` (device-verification gate), `bip360.rs`/`taproot.rs` (NUMS + P2MR), `heartbeat.rs`/`estate.rs` (dead-man's switch), `policy.rs`/`heirs.rs`/`unvault.rs`/`nums.rs`/`consensus.rs` |
| `qsv-cosigner` protocol & validation | attestation-document verification (`nsm.rs`), gate/allowlist/watchtower/alarm decisions (`server.rs`, `notify.rs`, `health.rs`), TLS + loopback policy (`tls.rs`), bridge framing (`client.rs`, `vsock.rs`) |
| `qsv-pqc` | ML-DSA-65 wrapper boundaries: anything that verifies a signature or decides a gate outcome |
| `qsv-node` / `qsv-cli` signing paths | RPC hardening (`rpc.rs`), PSBT assembly, witness construction, estate/verification commands |
| Supply chain of released artifacts | dependency policy (`deny.toml`, `cargo audit`), CI/gate logic that a bypass would silently weaken |

## 3. Out of scope

- **Upstream dependencies** (`bitcoin`, `miniscript`, `rustls`, RustCrypto
  `ml-dsa`, `libsecp256k1`, LLVM/clang toolchain): report upstream. Tell us
  only if there is a practical exploitation path *through this project*.
- **Nitro enclave image / hardware findings**: the enclave build has not been
  exercised on real hardware yet (ROADMAP.md D8) — honestly out of scope
  until then.
- Hardening gaps **already documented** in `docs/02` §6.2 and `docs/08`
  (no constant-time audit for our own Shamir GF(256) code, no measured
  side-channel resistance, no persistent sealing, blast radius is a design
  argument, not a measurement). Duplicating them as reports is welcome
  commentary but does not qualify for recognition.
- **Development attestation fixtures:** `crates/qsv-cosigner/attestation/dev_*`
  (root CA, leaf cert, and the throwaway `dev_leaf_key.pkcs8`) are
  deliberately-published development keys that simulate the enclave's
  attestation signer in dev mode only (`#[cfg(not(feature = "nsm"))]`,
  documented in-code as “NOT a security boundary”). They protect nothing
  and are never used by the NSM/production path; reports presenting them
  as leaked secrets are closed as not-a-vulnerability, with thanks.
- Social engineering, physical/laboratory attacks (power/EM/acoustic),
  anything that already requires full control of the operator's machine,
  pure local DoS of loopback-only services, and typographic/doc issues.
- Test-only code (`#[cfg(test)]`), fuzz harnesses, and benchmark floors:
  improvements welcome, not qualifying findings.

## 4. Testing rules and safe harbor

- Test **only** on regtest/signet/testnet. Never touch mainnet funds, other
  users' data, or third-party systems.
- Stay within minimal proof-of-concept intensity: no data destruction, no
  mass scanning, no privacy violations, no sustained denial of service.
- **Safe harbor:** good-faith research following these rules will not face
  legal action from us, and your report will be credited as long as you
  follow coordinated disclosure. We consider this policy a binding
  commitment of the project.

## 5. Rewards and recognition

- Every confirmed report gets: credit in the fix commit, the GitHub advisory
  *Credit* field (unless you decline), and an entry in the findings-closure
  table — after P2 that table lives in the independent-audit deliverable
  (ROADMAP.md D8).
- **Monetary bounty: not funded yet — stated honestly.** This repository has
  no funded vault; a paid private program (Immunefi / HackerOne class) is a
  post-P2 step in `ROADMAP.md` D8. Severity is assessed with CVSS v3.1
  by the maintainer; triage and credit are identical regardless of reward.
- Valid reports that improve the tests/gates (a killed mutant, a new pinned
  regression) receive the same credit as code findings.

## 6. Disclosure policy

Coordinated by default. We publish a GitHub Security Advisory when the fix
ships (or a partial mitigation + timeline if the fix takes longer), request a
CVE when the report merits one, and mark anything we could not reproduce as
*not reproduced* in writing rather than silently closing it.

---
