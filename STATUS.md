# STATUS — what is proven, what is not

*Last updated: 21 October 2026 · version v2026.3.1 · updated with every release.*

QuantumSafe-Vault is a **reference implementation**, not a product. This page
is the honest answer for anyone who finds the repository and asks "is this
usable?".

> **Do not use with real funds.** Mainnet is not supported; lost funds are
> permanent. Rehearse on signet or regtest.

---

## 1. What is proven today

Every row is reproducible with one command or one real-network lap.

| Claim | How to verify |
|---|---|
| The NUMS internal key makes key-path spending mathematically impossible | `cargo test -p qsv-core --lib nums::` |
| All four MAST leaves verify as reference spends under **libbitcoinconsensus**; a single tampered byte is rejected | `cargo test --workspace --features qsv-core/consensus` |
| The full lifecycle runs on a REAL `bitcoind` v28.2 (mine → unvault → CSV → settlement) | `cargo test -p qsv-node --test e2e_bitcoind` |
| PSBT → SD card → device signing → import verifies the manifest and every leaf key (fail-closed) | `cargo test -p qsv-cli --test hw_roundtrip` |
| The estate letter is independently re-derived; a forged byte = exit 1 | `qsv-cli verify-estate --file letter.txt --network signet` |
| A funded signet lap: funding → rotate → confirmed spend (7/7 honest exit codes) | CHANGELOG v2026.3.1 |
| 512 tests, 54 mutations (54/54 killed), every product file inside the mutation wall | `bash scripts/round_gate.sh` |
| One-screen console: three clocks + address + estate letter in a single script-free HTML file; a foreign descriptor is refused | `qsv-cli console --tip 900000 --json` |
| First run needs no Rust and no node: one command writes the console page, re-reads it from disk and prints its SHA-256 — measured 6–8 ms, 9,272-byte page (release build, warm cache) | `qsv-cli demo` · `cargo test -p qsv-cli --test first_run` |
| Release archives are attributable: five targets built `--locked`, one `SHA256SUMS`, `--version` must equal the tag, GitHub build provenance per archive | release workflow dry run · `bash scripts/verify_release.sh <archive> --repo <owner>/<repo>` |

The gate (14 legs) runs both locally and on GitHub Actions. A green run means
**only this list was measured** — never "everything is fine".

## 2. What is not proven

| Gap | Consequence |
|---|---|
| **No independent audit.** The cryptographic paths are hand-written and have never been reviewed by a third party | Unacceptable for real funds |
| **No production TEE provisioning.** Attestation is simulated in development mode (`--features nsm` carries the real NSM ioctl path but has not run on hardware) | The enclave security boundary is unproven |
| **No measured side-channel resistance** | No claim against timing/cache attacks |
| **No second "proof-of-life" channel.** If the heartbeat is missed, heirs can spend after 26,280 blocks | Premature-inheritance risk by design |
| **No insurance and no legal opinion.** The letter is not a will | Local succession law still applies |
| **Single maintainer** | No continuity guarantee |

## 3. How the quantum claim should be read

Both on-chain signatures are classical Schnorr (secp256k1). The ML-DSA-65
gate lives **off-chain**: it stops a classical attacker, not one who can forge
both signatures on Q-Day. The Q-Day escape route is **leaf 4** (WOTS+,
SHA-256 only, commit-reveal). The honest sentence is therefore *"Q-Day
preparedness plus a hash-based single-use escape path"*, not "quantum-proof
vault" — see [`docs/02`](docs/02_cryptographic_foundations.md).

## 4. What to do instead

1. Rehearse end to end on signet: `vault-setup` → `estate-letter` → backup
   drill (`kit-seed split` / `combine`).
2. `qsv-cli console --tip <N> --out page.html` puts the three clocks on one page.
3. Before any real key material: hardware wallets and the two-device flow
   (`psbt export` / `import`) rehearsed on signet.
4. If you are considering production: read the open items in
   [`ROADMAP.md`](ROADMAP.md) first — audit, real enclave, second maintainer.

## 5. Reporting a vulnerability

[`SECURITY.md`](SECURITY.md) §1 — private reports through GitHub Security
Advisories. Out of scope: tests run with real funds on mainnet.
