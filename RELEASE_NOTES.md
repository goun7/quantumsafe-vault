# Release v2026.3.1 — Rounds 29–38

_GitHub Release body (draft). Tag: `v2026.3.1` · 2026-10-19. Previous
release: `v2026.3.0` (Rounds 7–28). Full entries: `CHANGELOG.md`._

## Highlights

**The one-command local gate (Round 31).** CI being one billing outage away
from blind no longer matters: `bash scripts/round_gate.sh` is a
byte-for-byte mirror of the eleven CI jobs plus the Round-32 sweep leg —
14 legs, every one evidence-patterned (a leg that exits 0 without doing
its real work prints `EMPTY-GREEN` and fails the gate; the Round-29 fake
that "passed" in 0.00s is now structurally impossible). Latest full run:
14/14 green in ≈88 minutes on this tag's tree (19 Oct 2026, every leg
re-verified immediately before the tag).

**A funded live signet lap, end to end (Round 37).** Real coins from the
one CAPTCHA-free faucet rail (`scripts/signet_faucet.sh`), then the full
lifecycle on the real network with honest exit codes at every stop:
funding (block 326865) → FUNDED heartbeat rotation with the CSV clock
reset and heir registry re-sealed (block 326866) → an honest
insufficient-fee refusal → FUNDED PSBT spend, two device signatures,
libbitcoinconsensus ACCEPT, confirmed on-chain (block 326869) →
dashboard/watchtower green → early-rotation refusal. Two real script
bugs were found and fixed by doing it (a hidden 20 sat/vB fallback fee
and a datadir/amount argument collision).

**Dealer-less threshold keys (Round 33).** `inheritance-kit setup --dkg`
runs the three RFC 9591 DKG rounds — no machine ever sees a complete
signing share by itself; the output contract, frost-spend flow and
watchtower integration are unchanged.

**Watch-only descriptors a real node accepts (Round 34).**
`vault-descriptor` emits BIP-380-checksummed `addr()` and `rawtr()`
forms, fail-closed round-tripped, and the e2e proves them against
Bitcoin Core itself (`getdescriptorinfo` → `deriveaddresses` →
`importdescriptors` → `listunspent` sees the vault's UTXO). The absence
of `tr(...)` is documented as a true statement about the tree, not an
omission.

**k-of-n watchtower mirror approval (Round 35) + the vacuous-state wall
(Round 36).** A vault freezes only when k DISTINCT mirror hosts say ALERT;
k=0/k>n never clamp silently (exit 2 before bind); a state file that
parses but carries no vault record counts as unreadable — boot aborts
instead of serving a silent all-clear from an empty map.

**Financial-model and estate-settlement engines (Round 37).**
`qsv-core::finmodel` mirrors the docs/06 pricing table, integer
break-even and the MoR identity verbatim; `qsv-core::settlement`
distributes the estate fail-closed on TMK m.599/505–506 — insolvency
blocks distribution, Σ shares ≡ net base (largest-remainder, dust
included), every operation checked (overflow = `Err`, never wrap).

**Assurance that behaves like the product.** The hand-mutant corpus grew
to **54/54 KILLED** (M44–M54 added since v2026.3.0's wall), the
automated sweep holds every product file to a written wall (37 files —
hand-covered, mechanically mutated, or an allowlist with a reason), the
coverage floor holds at **97.75% lines / 83.30% functions** (≥97.5/82.0),
507 tests ×2 configurations with the live-bitcoind e2e in both, six
fuzzers at CI's 120-second window, and a single English documentation
edition held to eight walls: the module set, English titles, monotonic
sections, subsections that belong to a section, balanced fences (it already
caught an unclosed block that rendered half of docs/10 as code), resolvable
links, the BIP-360 snapshot in module 11 only, and no Turkish text anywhere
in the published tree.

**Two tools that answer the questions the gates raise.** `qsv-cli
docs-audit` turns those walls into a per-module report — what drifted, in
which module. And `scripts/round_gate.sh` now picks its own `TMPDIR` and refuses to start on
an unusable one: a full `/tmp`, a `TMPDIR` inside `$HOME` (the `ProtectHome`
red) or a slow disk-backed fallback used to produce three different REDS on
the same tree. A host problem now exits 3 with the diagnosis and no verdict.

**Supply chain, honestly documented.** rustls 0.23.46, bitcoind test
harness 0.42.0, and four RustSec advisory IDs carried as
byte-identical, reasoned, re-evaluated ignores in three homes (ci.yml +
round_gate.sh + deny.toml) — with the yanked-crate rule enforced
(`yanked = "deny"`).

## Upgrade notes

Drop-in: no wire, storage or key-format changes. Operator-visible
changes: `signet_setup.sh vault-fund` now takes its amount as `$2`
without poisoning the datadir and sends an explicit `fee_rate`
(`FEE_RATE` to override); `lifecycle` passes `FEE_SAT` to both
psbt-live legs. Known external blockers unchanged: CI billing (P1,
account owner) and the independent audit (P2, budget).

_Generated with Codebuff · verified by `scripts/round_gate.sh` 14/14 on
this tree._
