# ROADMAP — from vault to policy layer

*19 October 2026 · v2026.3.1 · updated with every release.*

## 0. Principles

This project will **not become a spending wallet.** Wallets answer "how do I
spend?"; this project answers "how is spending possible **only under the
conditions I chose**?". The evolution direction:

> Sparrow tells you what you own. QSV tells you what happens when you stop
> signing.

Three rules hold for every slice:

1. **No key custody.** No layer of the product stores private keys; everything
   works from public data (descriptor, PSBT, clocks).
2. **No unmeasured claims.** Every slice proves its acceptance criteria with a
   command anyone can run.
3. **No mainnet before an audit.** Until that changes, no slice counts as
   "ready".

---

## 1. Status table

| # | Slice | Status | Acceptance criteria |
|---|---|---|---|
| **D0** | Publish the repo + CI | ✅ done | 14/14 legs green on GitHub Actions; free runners on a public repo |
| **D1** | **Vault console (one screen)** | ✅ this release | `qsv-cli console` renders the three clocks, address and estate letter in a script-free HTML file; a foreign descriptor exits 1 with empty stdout |
| **D2** | Setup: signed binaries + one-command demo | next | On a fresh machine, no Rust required: download → `qsv-cli demo` → signet page in 60 seconds |
| **D3** | Premature-inheritance protection | design | Second proof-of-life channel + heir objection window; false-alarm drill under test |
| **D4** | Read-only monitoring service | external | Descriptor in, monthly alert out; no signature, no key; two independent users to pilot |
| **D5** | Estate rehearsal kit | external | Lawyer/advisor package: a 90-minute rehearsal script + output checklist |
| **D6** | `qsv-estate` specification | design | A descriptor profile + letter format other wallets can embed; public draft on Delving |
| **D7** | Q-Day readiness scanner | idea | Watch-only scan: exposed UTXOs, key-path usage, migration cost; no signing |
| **D8** | Audit + real enclave + second maintainer | external blocker | Independent report + `NITRO_E2E=FULL` + a 14/14 gate run on someone else's machine |

D0 and D1 are done in this repository. No slice opens mainnet except D8.

---

## 2. Next slice: D2 — setup

Today's largest usability obstacle is not cryptography, it is **setup**:

```
Rust 1.85+ → cargo build --release → bitcoind + RPC credentials → two hardware devices
```

Target:

- One **signed, single-file** `qsv-cli` build for Linux/macOS/Windows
  (GitHub Releases, SHA-256 manifest, signed tag).
- `qsv-cli demo` — no network, no node: a console page in 60 seconds.
- `qsv-cli console --descriptor …` already refuses a descriptor that is not
  this vault's (done in D1).

Acceptance: on a clean machine, without installing Rust, one download opens
the page; the measured time is recorded in [`STATUS.md`](STATUS.md).

## 3. D3 — premature-inheritance protection (the real product risk)

If the heartbeat lapses, heirs can spend after 26,280 blocks. That is by
design — but if it fires while the owner is alive, it is a disaster. Required:

- A second, independent proof-of-life channel (phone/email/second address).
- An **objection window** before an heir can spend (e.g. 1,008 blocks) and a
  way for the owner to cancel with one signature.
- A false-alarm drill: a test stops the heartbeat, the alarm fires, the owner
  cancels, and no coin moves.

Acceptance: a scenario test plus a "premature-inheritance risk" indicator in
the console.

## 4. D6 — becoming a standard (the cheapest distribution)

Code can be copied; **formats cannot**. Two documents are enough:

1. The `qsv-estate` descriptor profile: which leaves, which CSVs, which tags —
   enough for another wallet to watch the same vault.
2. The estate letter format: machine-readable fields that `verify-estate`
   re-derives independently.

Acceptance: a public draft on Delving Bitcoin / bitcoin-dev; at least one
foreign wallet imports the descriptor.

## 5. D7 — Q-Day readiness scanner (option value)

When BIP-360 (P2MR) activates, everyone asks "am I exposed?". The repository
already carries `bip360-status`, the migration plan and the P2MR trial code. A
free watch-only scanner leads into a paid migration service. A bet on timing:
cheap today, valuable if it lands.

## 6. D4 / D5 — the first revenue

- **D4 monitoring**: descriptor in, monthly alert out. No keys, no signatures,
  no custody — the cleanest product legally.
- **D5 rehearsal**: a 90-minute setup and backup drill for a family, sold
  through lawyers and advisors. What you sell is responsibility, not code.

## 7. Non-goals

- A spending wallet (an UX race against Sparrow/Nunchuk).
- Custody — holding someone else's key puts you in the licensing regime.
- Mainnet without an audit.
- AUM-based pricing (needs audit + insurance + years).

## 8. Contributing

- The most valuable feedback: run a signet rehearsal and write where you got
  stuck (issue label `drill-report`).
- For the audit scope and threat model: [`SECURITY.md`](SECURITY.md).
- Current limits: [`STATUS.md`](STATUS.md).
