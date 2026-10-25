# Changelog

All notable changes to QuantumSafe-Vault are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
version line is calendar-based (`vYYYY.M.P`), matching the workspace
`Cargo.toml` version and the docs banner (`v2026.3`).

## [v2026.3.1] — 2026-10-18/25 (Rounds 29–41)

### Added — first run without Rust (Round 41 · roadmap D2)

- **`qsv-cli demo`**: one command, no arguments, no node, no network, no keys.
  It renders the console page through the SAME builder as `console` (a test
  pins byte equality, so the demo cannot drift from the surface it
  introduces), writes it, READS IT BACK, and only then reports size + SHA-256;
  an unwritable path is exit 1 `cannot write …`. `--json` emits one bare
  `qsv-demo/v1` document (absolute `out`, `bytes`, `html_sha256`, address,
  letter hash, `elapsed_ms`). Measured: 6–8 ms, 9,272-byte page (release).
- **Release pipeline** (`.github/workflows/release.yml`, tag `v*` or manual
  dry run): four targets — x86_64/aarch64 Linux, x86_64/aarch64 macOS — each
  built `--locked`; the binary's `--version` must equal
  the tag; every target that can run on its own runner executes the offline
  first run before packaging; one `SHA256SUMS` over all archives, recomputed
  from disk, plus GitHub build provenance (Sigstore keyless) for the archives
  and the manifest. No maintainer key on a runner; the release body says
  whether the git tag itself is signed instead of implying it.
- **`scripts/verify_release.sh`**: checksum + `gh attestation verify`; exit 0
  verified · 1 refused · 2 incomplete (a check that cannot run is never a
  pass).
- **English-only repair:** the console page still carried three Turkish UI
  labels (an address row label, a heartbeat status word, a letter-hash
  caption) that the docs wall never looked at — the wall scans `docs/`, not
  renderer strings. The page is now fully English, and the wall sweeps
  `crates/`, `scripts/` and `.github/` too, so the next leak is caught by a
  test instead of by a reader. The widened sweep immediately found two more:
  the faucet script logged its claim lines in Turkish (an address label and a
  missing-value message).
- Test count 507 → **512** (4 first-run + 1 source-level wall).
- **Windows is not a target** — the first release dry run proved it: the
  co-signer's vsock/signal code is `std::os::unix`, so a Windows build dies at
  `qsv-cosigner`. Removed from the matrix and stated in docs/10 §4.65 instead
  of shipping a red platform.
- **Audit repairs (same round):** `heartbeat::tick` — the scheduler entry
  point the docs present as a cron target — signed the refresh witness as
  `[σ_user, σ_enclave]`, which libbitcoinconsensus rejects
  (`ScriptFailed(0)`); no test had ever run the reference engine over that
  path. Fixed, with `tick_output_is_valid_under_consensus` as the wall.
  `consensus::verify_transaction` also re-labelled every script rejection as
  an `Encode` error, hiding the only verdict that means "the network would
  refuse this"; the multi-input path now keeps `ScriptFailed`.

### Added — `docs-audit`, the single English edition (Round 40)

- **One published edition.** `docs/en/NN_*.md` became `docs/NN_*.md`; the
  Turkish originals are archived OUTSIDE the public repository, and the
  published prose (help text, README, STATUS/ROADMAP, scripts, workflows)
  describes the English tree only — no bilingual instruction survives.
- **`docs-parity` → `docs-audit` (`qsv_core::docs` rewrite):** the eight walls
  as DATA — module set (contiguous from 01, no duplicates, `docs/README.md`
  indexes every file), English `# Module NN` titles, strictly increasing
  section numbers, subsections that belong to an existing section, balanced
  code fences, resolvable links (file targets on disk, pure `#anchor` targets
  against the document's own headings), the BIP-360 snapshot in module 11
  only and parseable, and **no Turkish text in the published tree** (the
  twelve Turkish letters plus unambiguous vocabulary — the cutoff is written
  down in the module, so the wall cannot be gamed by one spelling). Exit
  contract unchanged: 0 in sync · 1 drift · 2 unreadable/empty tree with
  EMPTY stdout. Tests: 16 engine-level (`qsv-core`) + 8 `docs_sync` walls +
  6 interface-level (`qsv-cli`).
- **M53 (`docs_fence_wall`)** inverts the fence-parity check: every healthy
  module then reports an unclosed block and the repository-is-in-sync test
  must die. Audit **54/54 KILLED**; the sweep keeps `docs.rs` on the
  hand-covered wall.
- **`scripts/round_gate.sh` TMPDIR preflight:** the live e2e legs mine into
  `std::env::temp_dir()`, so the gate now chooses that host itself — a tmpfs
  with room, outside `$HOME` — and exports it. An explicit `TMPDIR` is
  honoured only if it passes the same checks; otherwise the gate refuses to
  start (exit 3, no leg runs, no verdict) because a full `/tmp`, a
  `$HOME`-rooted temp dir (the `ProtectHome` red) and a disk-backed fallback
  each used to look like a CODE failure on a healthy tree.
- Test count 475 → **507** (both deterministic proxies agree), and the
  changelog/README counts move with it.

### Fixed — the capacity wall no longer depends on run-A timing (Round 40)

- `bench_baseline_gate_flags_regressions_and_refuses_bad_baselines` built its
  "baseline no machine can meet" by multiplying that run's own measurement by
  100, so a throttled first run made the floor REACHABLE: CI counted 6 of 7
  regressions and the wall went red on a healthy tree. The floor is now a
  fixed `1e12` ops/s while the real report still supplies the seven operation
  names; the gate's comparison is unchanged — the wall was right, the test's
  premise was not deterministic.

### Changed — `docs_sync` is the wall, `docs-audit` is the explanation (Round 40)

- **`docs_sync` rewritten as 8 walls over the single edition:** the module
  set, English titles, monotonic section numbers, subsections that belong to
  a section, balanced fences, resolvable links (modules and the index), the
  BIP-360 snapshot, and the English-only sweep. The fence wall stays because
  it earned its place: its first run caught an unclosed block that rendered
  everything after §4.20 of the operations guide as code. The item-count
  parity wall retired together with the second language.
- **Module 10 depth preserved:** the dashboard's real sample output, the
  no-fake-data rule and the output-key audit point (recomputable by hand from
  the NUMS seed + Merkle root) stay in the English edition — they were the
  reason the old parity walls existed.
- **`SECURITY.md` no longer points at an unpublished working paper;** the
  audit-rewards table now names the deliverable, not an internal filename.

### Added — funded live signet lap (closing-plan P5 closed), finmodel/settlement engines (Round 37)

- **The FUNDED live signet lap — CLOSING-PLAN P5 CLOSED (docs/10 §4.62
  Round-31 §3.2):** programmatic funding became possible through the
  ONE CAPTCHA-free exception (arkfaucet.com `POST /api/request`,
  429 = 60 s, ~4,965 sat/day rail) wired into `scripts/signet_faucet.sh`
  (halts on 429 instead of hammering the IP), plus two real script fixes:
  `vault-fund` now sends an explicit `fee_rate` (the conf's
  `fallback_fee=0.0002` = **20 sat/vB** would have burned the faucet
  budget) and the `$2` datadir-vs-amount collision that made
  `vault-fund 2100` poison its own datadir. Result — **7/7 honest exit
  codes on the live network** (bitcoind v28.2, `~/.signet-qsv`, blocks
  326865–326868): funding 0 (`7a44d704…`) · **FUNDED heartbeat rotate 0**
  (`e7d6c8ef…`, block 326866, CSV clock reset, heir registry re-sealed) ·
  `psbt-live --build-only` honest fee rejection 1 (`fee exceeds the
  aggregate input value` — the post-rotation 1,300-sat coin under the
  default 1,500 fee; the coin was never touched) · **FUNDED spend 0**
  (two device signatures → libbitcoinconsensus ACCEPT → mempool
  accepted, tx `02703d3f…`, later CONFIRMED in block 326869 — the
  chain reads 326865 funding → 326866 rotation → 326869 spend) ·
  dashboard 0 · watchtower all-clear 0 ·
  early-rotate refusal 1 (`rotation not due: 3/12960`). The acceptance
  criterion "4/4 → 5/5 (funded rotate included)" was EXCEEDED. Also
  documented: the measurement trap that non-wallet txs are invisible to
  wallet polls (`gettransaction` → `-5`, a silent `conf=0` illusion) —
  confirmations must be read by block walk / `gettxout`, and
  `lifecycle()` now passes `FEE_SAT` to both psbt-live legs.
- **Financial-model engine (`qsv-core::finmodel`, E4c-a, docs/06 §2–§5
 ):** operator/plan tier classification with fail-closed
  layer-less input, license/SaaS/AUM-bps pricing that mirrors the docs/06
  §2 table verbatim, 4-year LTV, integer break-even, and a pro-forma that
  keeps the identity "gross = license + AUM/SaaS; net = gross − expenses;
  MoR-margin = 5%" (hand mutants **M49–M50**). The hand-mutant corpus
  rises **48 → 52**, and the sweep's file wall already reports both new
  files HAND-COVERED (37 files wall-checked).
- **Estate settlement engine (`qsv-core::settlement`, E4c-b, docs/05
  §2.2):** TMK m.599/505–506 grounded FAIL-CLOSED arithmetic —
  insolvency blocks distribution entirely, debts == assets is NOT
  insolvency (net 0), reserved portions at exactly 10,000 bps, Σ shares
  ≡ net base with largest-remainder rounding (dust included), checked
  ops all the way (overflow = `Err`, never wrap) (hand mutants
  **M51–M52**).
- **Babysitter-candidate onboarding pack — the babysitter-candidate pack:** six
  first tasks (G1–G6) each with its own gate commands and the
  two-machines acceptance rule, linked from the handover pack §1.
- **K1 online re-check (2026-10-18):** `bip360-status --online` PASS —
  the docs/11 snapshot still matches the live BIP-0360 (Draft v0.12.1),
  so K1 stays CLOSED; both docs/11 files record the re-run.

### Fixed — signet script bugs found by the live lap (Round 37)

- `scripts/signet_setup.sh`: the global `$2` (datadir) collided with
  `vault-fund [sats]` — every `vault-fund <amount>` run poisoned its own
  datadir and died on RPC (argument parsing is now per-subcommand), and
  `fallback_fee` silently priced sends at 20 sat/vB (explicit
  `fee_rate=${FEE_RATE:-1}`); `signet-artifacts/` (live PSBT/hex/state
  material) is now git-ignored.

### Added — vacuous-state wall, docs language scale, floor scenarios (Round 36)

- **M46 · the VACUOUS-STATE wall (`qsv-cosigner::bridge`, docs/10 §4.60
 ):** a watchtower state file that PARSES but carries no vault
  record (`{"tip": N, "vaults": {}}` — the shape a truncated or
  clobbered writer leaves behind) now counts as UNREADABLE: at boot it
  aborts with exit 1 BEFORE the bind, mid-run it rides the keep-last
  rule, and the installer refuses to bake it (it validates the same
  loader the bridge boots with). The hole was real: boot has NO
  last-good verdicts to keep, so accepting the empty map served every
  vault as a silent ALL-CLEAR from the first request — file existence
  is not health, the CONTENT is what reads (docs/02's "absence never
  means healthy", now enforced at the parse layer). Evidence: unit
  `vacuous_state_never_reads_as_all_clear` (empty file · missing map ·
  empty map · populated positive control) + boot e2e
  `cosigner_bridge_aborts_the_boot_on_a_vacuous_state_file` written with
  a BOUNDED REAP (30 s try_wait + child kill) so even the MUTANT fails
  fast instead of hanging the suite or orphaning a serving bridge +
  hand mutant **M46**. Sibling fix: four fixtures that leaned on
  vacuous-parse (three installer mirrors + the doctor mirror-lag state)
  now write a real vault record — each test's own assertions are
  untouched.
- **Mutation audit 45 → 48/48 KILLED:** **M46** the wall above, **M47**
  `votes >= quorum` (the merge comparison Round 35 root-fixed in text —
  hand-pinned here because M46 moves bridge.rs into the sweep's
  hand-covered set, retiring its mechanical `ge` site), **M48** the
  k=0/k>n clamp wall (takes over the retired mechanical `==` site, the
  k-wall's own mutant). All three were first proven KILLED individually
  (filter mode) before the round gate re-ran the full matrix.
- **The audit's `<name>` filter now actually filters:** the header
  always promised "run one: e.g. M01" but the guard was never
  implemented — a filtered call silently ran the WHOLE matrix (observed
  for real: a timed-out mid-run this round, caught by the trap). Now a
  prefix match on the mutant name; empty argument = full matrix; result
  lines, verdict and exit semantics unchanged.
- **The docs language scale (E4d — `docs_sync` grows 4 → 7 tests,
 ):** (1) module 10's numbered `### ` subheadings must mirror the
  reference edition EXACTLY (its header promises “Section numbers
  mirror”) — the first run caught THREE dropped EN headings (§2.1 live
  dashboard, §3.4 co-signer bridge & live co-signing, §4.6 measurement
  tools), all restored with condensed translations of the original
  content; (2) no EN edition may INVENT or REORDER a subsection number —
  caught module 07's fabricated `1.1/1.2` (the original has no such
  anchors), now bold lead-ins per the condensed-edition convention; (3)
  titles must declare the language they are written in (an English
  `# Module NN` heading). Negative probe: deleting an EN heading flips the new
  test RED — proven before the round went green.
- **Audit-scope file refreshed (P2 preparation, internal record):**
  `frost.rs` 890 → **1128** lines / 7 → **10** tests (the Round-33 DKG
  grew it), `bridge.rs` added to secondary scope (k-of-n merge + the new
  wall, M46–M48), budget/dashboard/test counts spelled out, and §6 gains
  the DETERMINISTIC count commands (`wc -l`, `grep -c '#[test]'`,
  `cargo test -- --list | grep -c ': test'`) dated to the refresh — the
  auditor reproduces the exact numbers instead of trusting prose.
- **Floor scenarios (E5SED, docs/10 §4.61):**
  `scripts/floor_scenario.sh` — a measurement, never a gate; it moves NO
  threshold (floors live only in `coverage_gate.sh`). It reuses the SAME
  llvm-cov JSON the gate consumes and prints: **S0** the gate's own
  number cross-checked against llvm-cov totals (the committed floor
  applies HERE and only here), **S1** per-crate sub-floors, **S2** the
  audit-scope §2 critical surface (parsed FROM the scope record, never copied),
  **S3** a degrade curve — the floor when the least-covered 1/5/10% of
  files leave the suite — and **S4** the product floor without the
  K1-gated experimental layer (`bip360.rs`). The function floor is
  reported at S0 only: per-scenario function subsets are not derivable
  from the JSON and are deliberately not fabricated (absent = absent).
  Measured record: S0 = **97.72% lines / 82.51% functions PASS** (file
  sum 17,291/17,695 matches llvm-cov totals to 0.01); S1 per-crate:
  qsv-core 98.82 · qsv-cosigner 98.88 · qsv-node 98.06 · qsv-pqc 99.45 ·
  qsv-cli 95.25; S2 audit-scope §2 surface **98.80%** (4,186/4,237, the 9
  critical files); S3 degrade — dropping the least-covered 1/5/10% of
  files moves the floor UP (97.75 → 98.86 → 99.04%), i.e. the committed
  floor is held DOWN by the lowest-covered files (main.rs, rpc.rs, …)
  and the remaining surface only looks better — the honest shape of
  "the zemin will ditch"; S4 without `bip360.rs` = 97.66% (the
  experimental layer itself measures 99.60%). Machine lines:
  `SCN0_LINES=97.72 SCN0_FUNC=82.51 SCN_VERDICT=PASS`.
- **Gate (Round 36, single local mirror of the 11 CI jobs):** 14/14
  legs green on the SECOND full run — fmt + clippy ×3, test-default
  (998 s) and test-consensus (1,156 s) both with the live-bitcoind e2e
  evidence under the bumped bitcoind 0.42.0 harness, the three drills,
  security-audit (4 s — the tracked zip ignores, deny, secret scan),
  fuzz 6×120 s (871 s), mutation-audit **48/48 KILLED** (316 s),
  mutation-sweep GREEN (34 s: 11 automatic mutants — 10 killed + the
  documented `vsock_lt` equivalent — 21 hand-covered, 7 allowlisted, 35
  files wall-checked) and coverage **97.72% lines / 82.51% functions**
  (floors 97.5 / 82.0; 838 s). The FIRST full run stopped honestly
  RED at security-audit (the zip advisories above) — one root-cause
  fix, then a start-to-finish rerun; never a threshold change. Test
  matrix: **453** (`#[test]` attribute sum == `-- --list` count).

### Changed — Round 36 supply chain: bitcoind 0.42.0, the zip advisories

- **The gate's FIRST full run went honestly RED at `security-audit`:**
  RustSec had published THREE `zip` advisories two days earlier
  (2026-10-09/10: RUSTSEC-2026-0367, 7.3 high — SUID/SGID preservation
  during extract(); RUSTSEC-2026-0368 — symlink escape;
  RUSTSEC-2026-0369, 9.1 critical — permissions through symlinks; the
  fixed line for all three is zip >= 9.0.0). Round-34's yanked-ignore
  could not cover VULNERABILITIES (yank ≠ CVE), so the path was the
  documented one, re-evaluation included: **the harness was bumped
  (bitcoind 0.41 → 0.42.0, the newest release — pulling bitreq 0.4,
  corepc-regtest-client 0.17, jsonrpc 0.21)** and it did NOT clear the
  line: 0.42.0 still requires `zip ^0.6.6`, and 9.x is semver-
  incompatible with that requirement from this side. The three
  advisory IDs therefore became TRACKED, REASONED ignores at all three
  homes — identical `cargo audit --ignore` flags in ci.yml and
  `scripts/round_gate.sh` (gate equality), and the same IDs in
  `deny.toml`'s [advisories] list (deny scans the same RustSec DB) —
  with the full reasoning + the re-evaluate-at-every-harness-bump rule
  written in `deny.toml`: zip enters ONLY as an optional BUILD-dep of
  the bitcoind TEST harness (dev-dependency — `cargo build --release`
  never compiles it; no shipped binary contains it), and any extraction
  runs on archives fetched over HTTPS from bitcoincore.org inside test
  runs, never on adversarial input.
- **The same re-evaluation removed Round 34's yanked-ignore:** zip
  0.6.6 is no longer yanked upstream — cargo-deny FAILS on a
  yanked-ignore that matches no yanked crate ("yanked crate not
  detected"), so the exact-version entry came out and
  `yanked = "deny"` stays armed for everything else. Security leg
  standalone green after the fix (deny: advisories/bans/licenses/
  sources ok · secret scan ok · audit: 0 vulnerabilities over 208
  packages), then the ENTIRE gate rerun start-to-finish (the Round-33
  discipline: one honest red → root-cause fix → full rerun, never a
  threshold drop).

### Added — multi-watchtower k-of-n mirror quorum (Round 35)

- **`cosigner-bridge --watchtower <dir> [--watchtower <dir>…]
  [--watchtower-quorum k]` (docs/10 §4.60):** `--state-dir` is
  mirror #1 and every repeatable `--watchtower` adds one watchtower
  HOST's own `watchtower-state.json` (n = 1 + repeats). A vault freezes
  only when k DISTINCT mirrors report `ALERT`; the new core merger
  `qsv_cosigner::quorum_verdicts` merges the set fail-closed: the union
  of every mirror's vaults (a vault a mirror never heard of casts NO
  "ALERT" vote — silence never freezes, and a sibling's observation can
  never be erased), the merged tip is the OLDEST mirror's, and one
  unreadable mirror aborts the BOOT (exit 1) instead of guessing "all
  clear". Mid-run the LAST verdicts stay across the WHOLE set (the
  Round-23 keep-last rule extended) — a deleted mirror can never unlock.
- **Quorum walls, exit 2 BEFORE the bind:** k must be in `1..=n` (k=0
  would freeze everything, k>n nothing — never silently clamped) and with
  EXACTLY two mirrors an explicit k is REQUIRED (no compromise-resistant
  default: k=2 is silenced by one dead host, k=1 forged by one); the
  default elsewhere is the majority ⌊n/2⌋+1 (n=1 → 1 — today's
  single-mirror behaviour byte-identical). Forging a freeze costs `k`
  hosts, silencing one costs `n−k+1`.
- **`cosigner-bridge-install` bakes the same set:** each mirror dir is
  canonicalized, its state must parse (a unit that would die at boot is
  refused BEFORE any file is written), and ExecStart carries
  `--watchtower <abs>…` plus `--watchtower-quorum <operative k>` —
  verified verbatim on read-back like every other baked flag.
- **Evidence:** 3 core unit tests (`quorum_verdicts`: k distinct hosts,
  the k=0/k>n walls, union + oldest tip), 4 bridge e2e tests (the three
  exit-2 walls, the `2 mirror(s) · quorum 2` dry-run banner, the
  unreadable-mirror boot abort, and the LIVE 3-mirror drill: 1/3
  releases → 2/3 freezes → recovery → a different host pair → a deleted
  mirror keeps the freeze → return, every release byte-identical) and 1
  installer e2e (absolute mirror paths + quorum in ExecStart, both walls
  write nothing). expansion-plan item P1-3 closed.
- **Gate (Round 35, single local mirror of the 11 CI jobs):** 14/14 legs
  green — fmt + clippy ×3, test-default/test-consensus (real-bitcoind
  e2e in both configurations), the three drills, security-audit, fuzz
  6×120 s, mutation-audit 45/45 KILLED, mutation-sweep GREEN (13
  automatic mutants, 35 files wall-checked) and coverage **97.71%
  lines / 82.47% functions** (floors 97.5 / 82.0). One honest find on
  the way: the sweep's mechanical `>=` mutant landed inside the string
  of an `expect("n >= 1")` message and masked the real
  `votes >= quorum` merge comparison — fixed at the ROOT (the message no
  longer contains a comparison operator, so the wall now sweeps the
  actual merge), not by an equivalence record.

### Added — watch-only descriptor export (Round 34)

- **`qsv-cli vault-descriptor [--network …] [--json]` (docs/10 §4.59):**
  the two descriptor forms that describe this vault's output EXACTLY,
  each with a BIP-380 checksum: `addr(bc1p…)#checksum` (BIP-385, the
  network-tagged full scriptPubKey) and Core's
  `rawtr(<output key>)#checksum` (the same scriptPubKey by its tweaked
  output key). Built fail-closed in `VaultTaproot::watch_descriptors`:
  nothing is printed until the scriptPubKey ↔ address round-trip matches
  in both directions and the checksum re-verifies. `--json` writes one
  document (address, output key, merkle root, four leaf hashes, both
  descriptors) under the §4.32 single-document contract.
- **There is deliberately NO `tr(...)`:** three of the four MAST leaves
  are not miniscript (leaves 2/3 open with `<n> CSV DROP` where miniscript
  can only emit `<n> CSV VERIFY` — different bytes, different leaf hash,
  DIFFERENT address; leaf 4 is the SHA-256 commit-reveal lock), and raw
  hex tapscript leaves are non-standard (BIP-386 defines a leaf as a
  script expression; Core documents `raw(HEX)` top level only;
  rust-miniscript parses every leaf as miniscript; the `rawleaf()` PR
  bitcoin/bitcoin#30243 was closed). A `tr()` over a different tree would
  derive a different address and the watcher would watch nothing — the
  export refuses and says why, in the output and in §4.59.
- **Evidence:** 2 core tests — `watch_descriptors_pin_the_exact_output`
  (checksum round-trip + two-way scriptPubKey equality on four networks)
  and `three_of_four_leaves_are_not_miniscript_so_no_tr_descriptor` (leaf
  1 positive control: miniscript's bytes ARE the real leaf; leaves 2/3/4
  are not — the test goes RED if miniscript ever gains the expressiveness
  and orders the export upgraded) — plus a REAL-bitcoind drill in four
  steps: `getdescriptorinfo` (Core recomputes the SAME checksum) →
  `deriveaddresses` (Core's own expansion of BOTH descriptors is the
  vault's address) → `importdescriptors` into a blank keyless wallet
  (both rows success; a private-key wallet refuses with -4) → mine to the
  vault → `listunspent` reports the watched UTXO: independent balance
  verification against the live chain. `qsv-node`'s RPC client gained
  `call_wallet` (`/wallet/<name>` — root-endpoint wallet methods pin to
  the node's startup wallet).
- **Hand mutant M45** (`rawtr()` must bind the TWEAKED output key, not
  the NUMS internal key — an internal-key swap exports a descriptor that
  watches a different script) KILLED by both descriptor tests; the audit
  grew 44 → **45/45 KILLED**. Test matrix 437 → **440**.
- **Supply chain (upstream event, not a code change):** `zip 0.6.6` — a
  build-time-only dependency of the `bitcoind` TEST harness — was yanked
  with no non-yanked resolution for `^0.6.6` and no newer harness
  release, turning `cargo deny`'s `yanked = "deny"` red on an otherwise
  unchanged tree. Fixed with ONE exact-version `ignore` entry carrying
  the full reasoning in `deny.toml` (build-only, locked, re-evaluate on
  the next bitcoind bump); the policy stays armed for everything else.
  Full gate re-verified after the fix: 14/14 legs — audit **45/45**,
  sweep GREEN (35 files), fuzz 6×120 s, coverage **97.73% lines /
  82.46% functions**, secret scan clean.

### Added — the closure-plan's repo-side half (Round 33)

- **`SECURITY.md` (P3.1):** the normative reporting channel — GitHub
  Security Advisories (private), first human response within 72 hours,
  in-scope surface table (`qsv-core` crypto paths, `qsv-cosigner`
  attestation-validation/gate, `qsv-pqc` boundary, signing paths, supply
  chain), reasoned out-of-scope list (upstream deps, Nitro hardware,
  the already-declared limits of `docs/02 §6.2`/`docs/08`), safe-harbor
  terms, and an honest reward status (credit + advisory now; monetary
  bounty is a post-P2 step, because no vault is funded yet).
- **(P4.2):** the second-maintainer handover pack —
  first-60-minutes checklist, the 14-leg `round_gate.sh` with its
  evidence discipline and honest durations, the `vYYYY.M.P` release
  procedure, CI-billing ownership, the doc/quality rules that turn red
  when broken (sweep wall for new `.rs` files, single-home coverage
  floors, docs-sync walls, fuzz-window equality), security-incident contacts,
  and the last known good commit.
- **Audit-scope record (P2.1):** the scope file for the
  independent review — the qsv-core critical surface with line/test
  counts per file, the hardware-independent cosigner validation path as
  secondary scope, a reasoned out-of-scope list, the pre-declared known
  limits (docs/02 §6.2), the auditor's exact reproduce commands, and the
  finding-closure discipline (every fixed finding pins a test/mutant).
- **closure-plan status annotations:** the three repo-doable steps
  are marked done; everything left (billing, audit firm, second
  maintainer, signet funding, Nitro hardware, advisory-channel toggle)
  is external and named as such.
- **FROST DKG (`inheritance-kit setup --dkg`, Round 33):** dealer-less
  RFC 9591 three-round key generation — no machine ever sees a complete
  signing share, closing the trusted-dealer's single-point exposure.
  Same output contract as the dealer flow (public package + sealed
  per-heir deals + printed SLIP-0039), so frost-spend, the backup drill
  and the watchtower are unchanged; identifiers stay label-derived.
  Evidence: three core tests (contract parity + a group-key BIP-340
  signature, below-threshold fail-closed, parameter walls) plus an
  end-to-end CLI drill on the REAL binary (setup → r1 ×2 → package →
  r2 ×2 → finish). Hand mutant **M44** (part1 `(max, min)` threshold
  binding) pins the argument-order contract; the mutation audit grew
  43 → **44/44 KILLED**.
- **Pre-launch deep audit (Round 33):** repository + full git history
  scanned for identity/credential leaks (username, home paths, emails,
  key material, wallet/xpub patterns): two findings fixed — a real
  `/home/<user>` path in the docs/10 systemd example ( genericized)
  and an inaccurate .gitignore comment about the dev attestation
  fixtures (now states that `dev_leaf_key.pkcs8` IS a deliberately
  published throwaway key; SECURITY.md §3 discloses it to reporters).
  The commit-author email itself is flagged as an explicit pre-launch
  decision for the account owner (keep as-is vs. noreply rewrite of
  history); it is NOT present anywhere in the tree or this file.
- **Two gate lessons made structural (Round 33):** (1) the metrics
  scrape in `bridge_caps_inflight_workers_and_recovers_after_the_timeout`
  raced the server's frame timeout under machine load (ConnectionReset =
  honest red at 43 s into `test-default`; 3/3 green standalone) — it now
  retries the TRANSPORT (fresh connection, up to 5 attempts) while every
  metric assertion is untouched, the Round-19 retry discipline; (2)
  `mutation_audit.sh` gains `trap emergency_restore EXIT INT TERM` — an
  interrupted run can no longer leave an applied mutant behind to poison
  the next run's byte snapshot (this happened for real: a timeout-killed
  run left M41 applied; the follow-up honestly reported
  PRECONDITION-FAILED). Honest boundary: the trap covers graceful
  signals (INT/TERM/EXIT) — a SIGKILL (tool timeout, `kill -9`) cannot
  be trapped, so the audit must run un-killed (background), and a
  precondition failure is the standing detector for leftovers (a second
  incident left M26 applied in main.rs the same way).

### Changed — Round 33 supply chain: rustls 0.23.46

- **rustls 0.23.45 → 0.23.46 (one-package lock bump).** The first full
  14-leg local gate run of this round went honestly RED on exactly one
  leg: `security-audit`, because RustSec published FOUR rustls advisories
  on 2026-10-14 (RUSTSEC-2026-0346/0347/0348/0349 — session-Debug secret
  exposure, ECH-reject buffering, Brotli pre-auth allocation, ServerHello
  downgrade — all fixed in 0.23.46; our lock pinned 0.23.45).
  `cargo update -p rustls --precise 0.23.46` moved nothing else; the
  security leg then passed standalone (audit clean under the standing
  ignore, cargo-deny ok, secret scan ok) and the ENTIRE gate was rerun
  start-to-finish: **14/14 ALL GREEN, GATE_EXIT=0**
  (`/tmp/qsv_round33b.log`, 2026-10-15: coverage 97.79% lines / 82.64%
  functions, 43/43 mutants killed, sweep GREEN, 6×120s fuzz clean, live
  bitcoind e2e evidence both configurations). CI being billing-blocked
  made the local mirror the ONLY thing that caught this — the Round-31
  gate paying off in its first full round.

### Added — the round gate, 43 mutants, the FROST statement (Rounds 29–31)

- **Automated mutation sweep + file wall (Round 32,
  `scripts/mutation_sweep.sh`):** the Round-31 review's "the mutation set
  is hand-picked" gap now has a MECHANICAL backstop — every product
  `.rs` file must carry a hand mutant (parsed from the audit script), a
  sweep mutant (≤2 boundary flips per file outside `#[cfg(test)]`,
  deterministic, snapshot-restored), or an allowlist entry with a
  WRITTEN reason; survivors are classified KILLED / UNVIABLE (never
  counted as kills) / SURVIVED, and a survivor only passes with a
  documented equivalence in `scripts/sweep_equivalence.txt`. First run
  found two REAL test gaps (the exact-520 BIP-342 boundary and the
  February calendar roll) — both pinned with tests — plus the vsock EOF
  edge (reviewed equivalent: hardware-gated path).
- **Fuzz equality + depth (Round 32):** the local gate's fuzz leg now
  runs CI's SAME 120 s window (the 45 s default was the one-sided gate
  equality dimension E flagged); `FUZZ_DEEP=1` opens the 300 s/target
  release pass.
- **The external closure plan:** every remaining
  score item that no code change can close (CI billing, independent
  audit, bug bounty, second maintainer, signet funding, Nitro hardware)
  broken into owner / steps / acceptance / estimate, ordered by what is
  doable today.

- **`scripts/round_gate.sh` — the 11-job CI pipeline as ONE local
  command** (docs/10 §4.55). Every leg is EVIDENCE-PATTERNED: a leg that
  exits 0 without printing its real-work proof (the live-bitcoind suite
  name, `ALL MUTATIONS KILLED`, `FUZZ GATE OK`, `COV_GATE=PASS`, …) is
  reported `EMPTY-GREEN` and fails — the Round-29 `BITCOIND_SKIP_DOWNLOAD`
  mousetrap is now embedded IN the gate. `GATE_SKIP`/`GATE_ONLY`/
  `GATE_CONTINUE` select legs.
- **Mutation audit 30 → 43 mutants, all KILLED** (M31–M43): the estate-
  letter comparators (incl. the wrong-network hint), the WOTS+ verifi-
  cation-chain step count, the `pid_alive(0)` bogus-record wall,
  `classify(None) ≠ Live`, the plaintext-off-loopback refusal, bare/
  wildcard binds never counting as loopback, the webhook `"<ts>.<body>"`
  replay binding, the P2MR witness version (bc1z), and the two parser
  walls the fuzz gate FOUND (CBOR depth 32, non-ASCII hex). Two more
  from the live-scan fix (M42/M43): the scan read-budget guard
  (shrinking 600 s → 5 s must kill the slow-scan test) and the `-8 Scan
  already in progress` recovery guard. The audit no longer touches git
  at all: every mutated file restores from a BYTE-FOR-BYTE SNAPSHOT, so
  a dirty worktree (this round's uncommitted fix) can never be wiped —
  the old "commit first" refusal is gone.
- **Gate-equipment hardening from an honest red run (loaded box):**
  `bench_reports_every_operation_above_floor` measured 4.8 ops/s against
  its 5.0 floor under load — it now samples best-of-5 (a 10× regression
  still dies in every sample; one unlucky timer does not sink the gate),
  and `tests/coverage_cli.rs` gains the Round-19 `retry` discipline its
  siblings already had: the 27,000/13,500-block watchtower/rotation
  fixtures mine in ≤250-block chunks behind a 5-attempt retry, so a
  starved RPC transport no longer fails the suite at `mine`.
- **The coverage gate is now DOUBLE-THRESHOLDED** (lines ≥ 97.5% AND
  functions ≥ 82.0%, both as single numbers in
  `scripts/coverage_gate.sh`); measured 97.85% lines / 82.47% functions,
  and `tests/` targets are NOT in the llvm-cov data — the number was
  product-code-only all along. P5's child-profraw gap is CLOSED:
  `enclave_server --max-requests N` exits normally so its `.profraw`
  flushes — `enclave_server.rs` went 52% → 98.63% lines.
- **The FROST adaptive-security / nonce-lifetime security STATEMENT**
  (docs/04 §7,): RFC 9591 is *Informational* and defines no
  Bitcoin ciphersuite; the CRYPTO 2025 debate (ePrint 2025/1061 vs
  2025/1001) is UNRESOLVED and this project claims NO adaptive-security
  proof; the four nonce-lifetime rules map to code; the out-of-scope
  list is explicit.
- **BIP-360 Plan B** (docs/11 §9,): a four-scenario matrix plus a
  decision protocol — if the BIP is rejected/withdrawn, K1 closes
  permanently and the spending path is script-path-only, READY TODAY
  (NUMS already cancels the key path; the only loss is the measured
  32 WU/input). No more "draft of a fallback".
- **Signet rehearsal (P6, partial):** `scripts/signet_setup.sh bootstrap`
  verified against the LIVE signet network (bitcoind v28.2, IBD 90%+,
  10 peers). Programmatic funding is impossible as of 2026: every known
  faucet sits behind Cloudflare Turnstile (the APIs closed 2025-08) —
  the funded `vault-fund`/`lifecycle` step waits on an operator
  transfer. docs/10 §4.54.
- **Round 29 close-out** (committed as `c5f4fef`): coverage floor 91→97.5,
  both empty-green traps caught and documented, 5 clippy violations
  fixed while CI was dead, the harsh 71/100 evaluation
  — the Round-31 follow-up scored 78/100.

### Fixed — the live UTXO scan could never finish outside regtest (Round 31)

- **`qsv-node` RPC read budget:** every request used a hard 10-second
  read timeout, but `scantxoutset start` blocks the calling connection
  until the ENTIRE UTXO set is walked — invisible on regtest, fatal on
  signet where every live scan died with `Resource temporarily
  unavailable (os error 11)`. A live UTXO scan could never have
  succeeded outside regtest. Now `post_with_timeout`: the default stays
  10 s (a dead node still fails fast), the scan gets 600 s, and
  `-8 Scan already in progress` polls `scantxoutset status` and retries
  once — blowing the budget fails closed. Three new tests: an 11-second
  slow-scan response (past the old budget), the -8 → status → retry
  recovery, and a wire-shape pin that `scanobjects` travels as an ARRAY
  (a canned response never validates the request; bitcoind rejects an
  object with -3). docs/10 §4.56.
- **Live signet fail-closed lap** (bitcoind v28.2, block 326202, IBD
  complete, 10 peers): `psbt-live` unfunded rejection (exit 1),
  `vault-dashboard` live + heartbeat OK (exit 0), `watchtower`
  read-only all-clear (exit 0), `vault-rotate` early-rotation AND
  past-due unfunded refusals (exit 1) — the whole read-only surface is
  honest on the real network; only the operator's 1 tBTC funding step
  remains (faucet CAPTCHA wall). docs/10 §4.56.

---

## [v2026.3.0] — 2026-09-29/30+ (Rounds 7–28)

### Added — the live Nitro e2e round + the coverage floor (Round 28)

- **The live Nitro Enclaves e2e round now exists (two binaries, two
  phases).** `serve_vsock` had NO caller — no enclave image could be
  built or launched. `enclave_server` serves the ceremony over AF_VSOCK
  (`--features nsm`) or loopback TCP (dev), reading its allowlist from
  `--vault` or the `QSV_VAULT` ENV baked into the image (an enclave
  gets no run-time arguments); `cosign_probe` is the client half
  running the SAME verification chain as the production terminal
  (gate → document mandatory → chain/root/PCR/nonce/user_data →
  BIP-340 under the pinned key), exit 0 only on a full PASS.
  `scripts/nitro_build_enclave.sh` packages the EIF through docker +
  nitro-cli; `scripts/nitro_e2e.sh` phase 1 (EVERY machine, also
  `cargo test` via `tests/nitro_e2e.rs`) drives both binaries over
  real sockets — PASS plus three refusals; phase 2 boots the EIF and
  repeats over vsock against the hardware measurement, skipping with a
  clear reason where nitro-cli is absent (`--require-enclave` makes
  the prereq mandatory). docs/10 §4.53.
- **The DEFAULT `qsv` invocation was broken and is now proven green.**
  Nothing executed the demo path: demo 2 passed a 44-byte intent
  where the gate contract is a 32-byte sighash (panic), and its
  witness bound a co-signature over the intent instead of the
  transaction sighash (consensus reject). The demo now hashes the
  intent and runs the gate over the exact sighash (Theorem 1: proof
  and co-signature over the SAME message); `tests/demo_walkthrough.rs`
  runs the default invocation plus the offline operator subcommands
  (constants, leaf-budget ±p2mr, wots-params, kit-seed split/combine
  in both formats including the deniable wrong-passphrase secret) as
  real processes.
- **Mutation audit M16–M22 (22 total)**: heartbeat expiry invariant,
  self-churn output key and dust floor; the prevout-count guard; the
  FROST group-signature check and both duplicate-identifier guards —
  each killed by a test that pins the branch.
- **Coverage floor**: `cargo llvm-cov` line coverage is a GATE now
  (≥ 90%): 87.19% → **90.38%** via targeted tests for the policy leaf
  compilers/error strings, heir registry helpers, NUMS counter
  exhaustion, the lifecycle one-shot unvault + runbook report, the
  RPC cookie/JSON-RPC error surfaces (real local sockets), and the
  demo walkthrough.
- **Hardening**: the bridge health-record test polls instead of
  assuming publish order relative to the socket (instrumented builds
  schedule differently). **292 tests green** (was 274; `qsv-core`
  118), mutation audit 22/22 KILLED.

### Added — end-to-end attestation verification (Round 27)
- **The co-signer now PROVES which enclave answered.** `SignRequest`
  carries a client-generated challenge (protocol v2, deterministic —
  SHA-256 over vault+sighash+identity, no RNG on the air-gapped
  terminal); the enclave's COSE_Sign1 document must echo it back
  (replay refuse) and bind `user_data = enclave_xonly ‖ vault_id` to the
  pinned key and vault.
- **The production verifier (`nsm.rs`) implements AWS
  `attestation_process.md` §3.2.2/§3.2.3**: COSE_Sign1 decode (tag 18
  optional, protected `{1:-35}`=ES384, fixed 96-byte signature, no
  trailing bytes) → mandatory/content rules (PCRs ∈ {32,48,64},
  cabundle 1..1024, nonce/user_data ≤ 512, unknown field = refuse) →
  request-nonce check → PCR pins → user_data binding → X.509 chain to a
  PINNED root → COSE signature under the target certificate's key. The
  chain checks validity at `now` for EVERY certificate (Nitro
  infrastructure certs live ~3 hours), issuer/subject links, Basic
  Constraints + pathLen, KeyUsage — no CRL, exactly as AWS specifies.
- **Trust anchors are byte-pinned**: the AWS Nitro Root-G1 PEM+DER are
  embedded with SHA-256 pins verified against three independent sources;
  outside enclave builds the QSV dev root is the second anchor. Proven
  against the REAL AWS sample document (aws-samples, MIT-0) — all four
  chain links, root self-signature, root pin and COSE ES384 verify.
- **Emission path**: the dev server mints REAL COSE_Sign1 documents
  (`emit_dev_document`) through the same verifier the production path
  uses — no JSON pseudo-document, no alternate code path. Enclave builds
  request the document from the actual NSM device (ioctl, compile-time
  gated by `--features nsm`).
- **CLI choke point (fail-closed)**: `--cosigner-pcr0/1/2` +
  `--cosigner-key` pins on `frost-spend` / `vault-rotate` (+batch);
  without an attestation document the live co-signature is REFUSED; a
  pin without an endpoint or bad hex = exit 2 at startup, before the
  first request.
- **12 new property tests (proptest)**: covenant value conservation +
  dust refusal + CSV BIP-68 encoding, vault-policy shape for arbitrary
  heir key sets (every key present, both timelocks), SLIP-0039
  roundtrip/corruption/wrong-passphrase, and `token_eq` byte-equality
  (no padding forgery).
- **New quality gates**: `RUSTDOCFLAGS=-D warnings cargo doc --workspace
  --no-deps` (dead links and stray HTML in docs now fail) and the
  `cargo llvm-cov` coverage run (87.19% line coverage baseline).

### Added — threshold spending on a real chain
- **`frost-spend`**: the FROST k-of-n GROUP key SPENDS on a real bitcoind —
  RFC 9591 ceremony under the BIP-341 key-path tweak (the coordinator and
  ALL heir packages are tweaked by the SAME root; the frost crate's
  `tweak(None)` is the key-path tweak, not the identity), consensus
  self-check, broadcast; the regtest e2e proves mempool acceptance and
  on-chain confirmation. `--no-broadcast` = watchtower hold mode.
- `psbt-live --min-inputs N`: multi-input consolidation (largest-first,
  fail-closed) — N live vault coins merge into ONE mempool-accepted spend.
- qsv-core multi-input engine: `build_multi_input_psbt`,
  `device_sign_input_multi`, `verify_device_signature_multi`,
  `store_tap_script_sig`, `assemble_witness_for_input`,
  `finalize_multi_input_and_extract`, `verify_transaction`,
  `select_coins_largest_first`.

### Added — hardware-ready PSBT layer
- **`tap_merkle_root` on every PSBT input** (`VaultPsbtInput.merkle_root`):
  Coldcard/Ledger re-derive Q per BIP-341 — the missing field for real
  device script-path signing.
- **`psbt export|import`** (SD-card round trip): BINARY BIP-174 card +
  sha256 manifest + human audit sheet; import accepts binary, base64 and
  Coldcard-style artifact forms, re-verifies EVERY tap script-sig under
  the leaf keys and judges with libbitcoinconsensus.
- **Coldcard compliance gate**: export refuses PSBTs missing
  witness_utxo / tap_internal_key / tap_scripts / tap_merkle_root or with
  an implicit sighash type — the exact fields air-gapped signers require.

### Added — inheritance watchtower
- **`watchtower`**: one read-only pass — heartbeat DUE is the only alert
  (exit 1), 26,280-block CSV countdown, live coins via scantxoutset;
  optional REAL FROST dry run (`--deal`/`--public`/`--fund-sat`). A
  healthy pass never exits 1: false alarms are structurally impossible.
- **Daemon mode** (`--inventory env.json --state-dir <dir>`): multi-vault
  inventory, per-vault heartbeat, persistent `watchtower-state.json`
  (fail-closed on unreadable state), best-effort webhook alarms (never
  affects the exit code), single-vault flag conflicts exit 2.

### Added — assurance & operations
- **Mutation audit** (`scripts/mutation_audit.sh`, a CI job): 8 injected
  crypto/logic mutants (NUMS anchor, Shamir tag, FROST envelope, heir
  binding, device gate, multi-input amounts, heartbeat due, dust guard) —
  ALL KILLED by the test matrix (behavioral proof, 8/8).
- **Signet bootstrap** (`scripts/signet_setup.sh`): node + wallet +
  faucet flow + vault funding + the first real-network `psbt-live` round
  trip, signet-pinned end to end.
- **Full CI** (`.github/workflows/ci.yml`): fmt, clippy in 3
  configurations, the test matrix in 2 configurations, the qsv-node
  lifecycle e2e, and the mutation audit — beside the K1 watchdog.

### Fixed
- Plain FROST ceremonies no longer apply a spurious key-path tweak
  (Round-7 regression caught by the inheritance-kit e2e).
- clippy -D warnings clean in all three configurations; two latent
  initializers now carry `merkle_root` (qsv-node round trip, psbt-build).

### Added — Round 10: rotation, alarm enforcement, P2MR source trial
- **`vault-rotate`**: the owner's heartbeat drill on a REAL node — live
  scantxoutset discovery, self-churn refresh (same address in/out, CSV
  clock reset), consensus self-check, broadcast; `--no-broadcast` hold
  mode. With `--heir label=<pqc-seed>` every registered heir slot must
  re-attest a fresh ML-DSA-65 identity (partial registries fail closed —
  the registry is re-sealed in the refresh, docs/04 §5).
- **Watchtower→co-signer alarm mirror** (`qsv-cosigner`):
  `Cosigner::set_alarm/clear_alarm/alarm_state/alarmed_vaults` — while a
  vault is ALARMED the enclave refuses ALL signing requests for it, even
  with a perfectly valid ML-DSA-65 proof (fail-closed, per-vault,
  Theorem 1 degrades safely; reload starts clear, the daemon re-raises).
- **EXPERIMENTAL BIP-360 (P2MR) source trial** (`psbt-live --p2mr`,
  REGTEST-ONLY, K1-gated): funds/reads a coin at the vault's experimental
  P2MR address (witness v2 program = merkle root, `bc1z`), walks it
  through the identical hybrid-leaf/BIP-341 signing machinery with the
  same PSBT engine and consensus self-check, then HOLDS the transaction
  in `p2mr-source-trial.txhex` — broadcast is structurally impossible
  until BIP-360 consensus rules exist (docs/11 Phase 4b rehearsal).

### Added — Round 11: alarm enforcement service, live co-signing, P2MR arithmetic
- **`cosigner-bridge`** (qsv-cli + qsv-cosigner): the enclave co-signer as
  a REAL TCP service with the watchtower alarm mirror applied PER REQUEST
  (the state file is re-read before every request — a daemon refresh takes
  effect without a restart; read/parse failure keeps the last mirror so
  alarms never silently clear). Core additions: `serve_shared`/
  `serve_listener`/`serve_with_mirror` (Arc<Mutex<Cosigner>>), bad-client
  resilience (probes/short frames never kill the loop), and the
  `bridge` module: `parse_state`/`load_state`/`apply_verdicts` with
  idempotent Raised/Cleared/Unchanged outcomes. Socket e2e: CLEAR→release,
  state flip→refuse, recovery→identical deterministic release, unlisted
  vault→refused — all over a real socket WITHOUT restarting the service.
- **`vault-rotate --cosigner host:port`**: the second signature is
  requested over the PQC gate from the LIVE bridge and verified under the
  pinned enclave key before use (demo-path fallback unchanged).
- **`vault-rotate --inventory/--vault-id/--state-dir`**: the SAME inventory
  schema the watchtower daemon uses; the rotation proceeds ONLY when the
  heartbeat is DUE (early re-rotation refused); a successful rotation
  persists `rotation-state.json` (tip as the new baseline — the alarm↔
  rotation story stays consistent). Live e2e: due gate, live co-signer
  broadcast, persisted-baseline guard, and a frozen vault refusing to
  rotate with an empty mempool.
- **`leaf-budget --p2mr-delta`** + `qsv_core::budget::p2mr_delta`: the
  EXPERIMENTAL BIP-360 saving per leaf — control block 33+32d → 1+32d
  (exactly 32 B = 128 WU per script-path input), vbytes/fee deltas at all
  representative feerates; pure arithmetic, K1 outstanding (tested for
  every leaf).
- **`psbt-live --p2mr --min-inputs 2`**: the P2MR source trial now
  consolidates MULTIPLE live P2MR coins into ONE hold transaction through
  the multi-input PSBT engine (e2e-verified: a different tx than the
  single-input trial, mempool still empty).

### Fixed
- vault-rotate baseline resolution order: the pure-crypto heir identity
  check now precedes the chain-state heartbeat gate (an identity failure
  is reported as such, not masked by a not-due error); the rotation state
  file is read from `--state-dir` only (never the ambient cwd).

### Test matrix
**159 tests green in both configurations** (was 155 at Round 12),
including 14 live e2e flows (12 bitcoind-backed + the co-signer bridge
socket suite + the systemd generator suite: estate, live PSBT ×3, FROST
spend (+ co-signer gate, + multi-UTXO consolidation), watchtower,
watchtower-daemon (+ rotation-state v2), inheritance-kit, SD-card
hardware-round-trip, vault-rotate (+ bridge), P2MR source trial,
cosigner-bridge-install), 5 FROST core tests, and the 45-official-vector
SLIP-0039 suite.

### Added — Round 12: deployment tooling, gated threshold spend, measured P2MR weight
- **`cosigner-bridge-install`**: generates the hardened systemd unit +
  timer pair for the bridge (ProtectSystem=strict, ReadWritePaths pinned
  to the state dir, PrivateTmp/NoNewPrivileges/ProtectHome,
  Restart=on-failure, OnCalendar timer with Persistent=yes), writes them
  with `--unit-dir` and RE-READS what landed on disk, exiting 1 when any
  required directive is missing (install-what-you-print); stdout preview
  mode writes nothing. Bakes the real `cosigner-bridge --listen/--state-dir/
  --vault-id` invocation into ExecStart.
- **`frost-spend --cosigner host:port --vault-id ID`**: the enclave gate in
  front of the threshold ceremony — the ML-DSA-65-proofed sighash request
  goes to the bridge BEFORE any heir round runs; a watchtower-frozen vault
  is refused (exit 1, nothing broadcast, no aggregation), a clear vault
  releases a co-signature that the client verifies under the pinned
  enclave key before the ceremony proceeds. `--cosigner`/`--vault-id` are
  pair-checked before any file or node contact (usage error exit 1).
- **`rotation-state.json` v2 (id-based)**: per-vault records under the
  SAME id space as the watchtower inventory (`version: 2` + `vaults` map);
  single-vault rotations record under the stable id `single-vault` (the
  same id the no-baseline read path uses). An inventory row claiming an
  EARLIER baseline than a recorded rotation fails closed ("inventory/
  rotation-state MISMATCH"); a missing state file is tolerated (the
  inventory alone drives the baseline); v1 top-level `last_refresh_block`
  still loads as a fallback; a v2 file with only inventory-id records
  refuses the single-vault no-baseline path instead of guessing.
- **`psbt-live --p2mr` measured weight**: every trial run prints the REAL
  weight of the assembled transaction beside a P2TR twin (same inputs +
  32 B control block each) and asserts the delta — the BIP-141 correction:
  witness bytes weigh 1 WU each (the ×4 multiplier applies only to the
  non-witness part), so the P2MR control-block saving is exactly
  32 WU = 8 vB per script-path input (not 128 WU). `budget::p2mr_delta`
  fixed accordingly with a regression test; the e2e parses both runs'
  weight lines and validates saved == 32 WU × inputs.

### Fixed
- `qsv_core::budget::p2mr_delta`: witness bytes count 1 WU each under
  BIP-141, so the control-block saving per script-path input is 32 WU
  (8 vB), not 32 B × 4 = 128 WU; docs/11 §7.5 numbers now match the
  measured CLI output.

### Added — Round 13: watchtower↔rotation consistency, observability, consolidation
- **Watchtower daemon reads rotation-state v2**: the multi-vault pass
  consults the id-based rotation records in the SAME state dir and lets a
  LATER recorded baseline override a stale inventory row (audit line
  printed, mirror records the overridden verdict) — a vault whose refresh
  already cured the alarm is never re-alerted. Missing file = state-less
  behavior; UNREADABLE file = fail-closed exit 1; a record claiming a
  refresh above the tip is ignored as corrupt.
- **Co-signer metrics (`qsv-cosigner::Metrics`)**: per-request atomic
  counters — requests/accepted/refused/alarm-refused totals plus cumulative
  serve latency — with a Prometheus text-exposition `render()`. The TCP
  loop answers a plain HTTP `GET /metrics` (200, text/plain version=0.0.4)
  WITHOUT moving any counter (observing is not signing) and keeps serving
  deterministic signatures byte-identically afterwards; other HTTP paths
  are answered as normal refusal frames (loop survives junk). Every close
  drains the receive queue so scrapers see a clean FIN, never RST.
- **`frost-spend --min-inputs N` (multi-UTXO consolidation)**: the group
  key sweeps its LARGEST N live coins into ONE key-path spend — one FROST
  ceremony round PER input (each sighash is a distinct message), the
  aggregated per-input signatures verified under the tweaked group key and
  against libbitcoinconsensus, then broadcast once. Fail-closed floor:
  fewer live coins than N exits 1 before any ceremony. E2E: two coins
  (0.111 + 0.222 BTC) → ONE mempool-accepted, chain-confirmed output worth
  sum(inputs) − fee.
- **`bip360-status` weight-claim audit**: docs/11's snapshot carries a
  machine-readable `weight-saving-wu: 32` record; the offline audit now
  re-measures the REAL per-input saving from a freshly built reference
  spend (`budget::measured_p2mr_weight_saving_wu`) and fails when the plan
  claims a different number (the pre-Round-12 128 WU arithmetic is caught by
  a regression test) — when K1 opens, the migration arithmetic is already
  proven to still match the BIP text.

### Added — Round 14: fleet rotation sweep, per-vault metrics, bridge TLS, mempool policy
- **`vault-rotate --all --inventory`**: the owner sweeps EVERY due vault in
  the inventory in one invocation — per-vault rotation-state v2 records are
  classified first (a record beats a stale inventory row with an audit
  line; an unreadable record fails closed), the DUE vaults rotate
  sequentially, and the first failure is reported after ALL due vaults
  were attempted. `--all` conflicts with single-vault selectors
  (`--vault-id/--last-refresh-block/--heir/--no-broadcast`) — usage error,
  exit 2. ONE COIN, ONE REFRESH: every inventory id resolves to the same
  demo address, so after the first successful rotation the remaining ids
  record the SAME tip/txid instead of re-broadcasting a byte-identical
  transaction (a live-tested real bug: the duplicate broadcast was a
  mempool no-op that still minted a phantom record).
- **Per-vault Prometheus counters** (`qsv-cosigner::Metrics`):
  `qsv_cosigner_refused_by_vault_total{vault="id"}` and
  `qsv_cosigner_alarm_refused_by_vault_total{vault="id"}` attribute every
  verdict to the requesting vault (deterministic BTreeMap order; the
  unlabelled totals are unchanged) — the /metrics scrape now answers
  WHICH vault was frozen, not merely how many refusals happened.
- **Bridge TLS**: `cosigner-bridge --tls-cert/--tls-key` serves the
  exact mirror+frame ceremony INSIDE rustls TLS 1.3; a plaintext client
  on a TLS port can never observe a clean frame (it sees only TLS
  records/alerts). Boot policy: plaintext on a non-loopback address is
  refused (PlaintextOffLoopback), `--tls-cert` without `--tls-key` (or
  vice versa) is a usage error (exit 2); clients verify under a PINNED
  root store. Accept loop fix: the TLS path accepts one THREAD PER
  CONNECTION (a serial loop stalled the whole service while a silent
  client held the first handshake read — root-caused live with a Python
  probe), so scrapes, slow clients and poison payloads never block
  deterministic signing.
- **Mempool policy e2e**: the frost-spend flow now proves BIP-125
  RBF signalling (`Sequence::ENABLE_RBF_NO_LOCKTIME`), no-dust, exact
  vsize and feerate via `testmempoolaccept` on a LIVE node, and a full
  replace-by-fee cycle: the RBF-signalled original is accepted, a
  LOWER-fee replacement is refused (BIP-125 rule 4), a higher-fee
  replacement is accepted.

### Fixed
- cosigner-bridge TLS accept loop: a silent (non-handshaking) TCP client
  stalled the single-threaded TLS serve loop indefinitely; connections
  are now served concurrently and a poisoned client costs 0.05 s.

### Added — Round 15: sweep co-signer gate, bridge mTLS, latency histogram, at-least-once webhooks
- **`vault-rotate --all --cosigner-all host:port`**: the fleet sweep runs
  behind the LIVE bridge — the gate asks about EVERY due vault BEFORE any
  ceremony; a FROZEN vault (watchtower alarm) is skipped with an explicit
  report line (`FROZEN[vault-id]`), never recorded in the rotation state
  (its alarm survives until the operator clears it), and the REST of the
  fleet refreshes through the very same bridge (exit 0). An unanswerable
  gate fails the sweep CLOSED (exit 1, no ceremony started). `--cosigner-all`
  requires `--all` and conflicts with the plain `--cosigner` (exit 2);
  single-vault `--cosigner` behavior unchanged. Live e2e
  (`tests/vault_rotate_batch_gate.rs`): dead-gate fail-closed before ANY
  rotation, frozen skip + healthy refresh through the same bridge, no
  artifact dir and no state record for the frozen id.
- **Bridge mTLS (`--tls-client-ca ca.pem`)**: the TLS handshake itself
  demands a client certificate chaining to the operator's CA
  (WebPkiClientVerifier) — an anonymous client NEVER completes a session,
  hence reaches neither the gate, the alarm mirror nor `/metrics`. The
  pinned client identity (`client_identity` + `request_signature_mtls`)
  releases the SAME deterministic co-signature and scrapes metrics through
  the same tunnel; `--tls-client-ca` without the `--tls` pair is exit 2.
  e2e: anonymous TLS client refused IN the handshake, foreign-CA cert
  refused identically, pinned client signs + scrapes.
- **Prometheus serve-latency histogram**: `qsv_cosigner_serve_latency_us`
  as a real `histogram` — fixed cumulative buckets (1 ms · 10 ms · 100 ms ·
  500 ms · 1 s · 2 s + `+Inf`), `_bucket{le=…}` rows + `_sum` + `_count`;
  the legacy `serve_latency_us_sum` counter row is KEPT (dashboards do not
  break). Buckets are a crate-level contract (never reordered at runtime);
  a scrape moves NO bucket.
- **Watchtower webhooks at-least-once**: a failed alarm POST is retried
  within the SAME pass (3 attempts, fixed 0.5 s + 1.0 s backoff) and the
  LAST outcome persists per vault in the state file
  (`webhook_delivery: delivered|failed|not_configured`) — the operator
  sees what the secondary channel actually did while the exit code stays
  the PRIMARY alarm channel (a dead relay never softens a real ALERT).
  The alert body is byte-identical across attempts (relay-side dedupe
  sees one alert). Delivery moved to `qsv-cli::webhook` with a
  request-capturing loopback relay unit suite (wire shape, retry ladder,
  mid-ladder recovery, URL policy).

### Added — Round 16: mTLS sweep gate, dry-run preview, per-vault rate limit, HMAC-signed webhooks
- **`vault-rotate --cosigner-all --cosigner-all-cert/--cosigner-all-key/--cosigner-all-ca`**:
  the fleet sweep talks MUTUAL TLS to the gate bridge — a wrong-CA client
  identity fails the gate CLOSED before any ceremony (exit 1, no rotation
  state, empty mempool), while the correctly pinned identity carries BOTH
  the gate probes AND the rotation signature requests through one
  encrypted channel (the production dev-bridge path closes end to end).
  The unified `qsv_cosigner::BridgeClient` (plain | mTLS transports, the
  three-verdict `ask()` → Release/Frozen/Refused) now backs the gate, the
  per-rotation signature and the frost-spend co-signature; a partial PEM
  material set is exit 2. Live e2e: foreign-CA sweep dies closed, pinned
  sweep refreshes through mTLS with the frozen skip intact.
- **`vault-rotate --all --dry-run`**: the sweep PREVIEW — every row is
  classified DUE/healthy/stale (FROZEN too when a gate is attached) and
  the actions are NAMED (`would rotate (broadcast refresh)` for the first
  due id, `would record (shared coin, no re-broadcast)` for the rest),
  with a hard side-effect contract: exit 0, NO rotation state written,
  NOTHING broadcast (e2e proves the mempool snapshot is unchanged and the
  real sweep succeeds right after). Requires `--all`.
- **Bridge per-vault rate limit (`--rate-limit <capacity>:<refill>`)**:
  a token bucket PER REQUESTING vault id (lazy instant-based refill,
  capacity-capped) — a flood from ONE vault is refused IMMEDIATELY with
  the explicit `rate limited` reason (never stalled) while a provisioned
  sibling keeps its own budget. Refusals count in the exposition
  (`qsv_cosigner_rate_limited_total` + per-vault
  `qsv_cosigner_rate_limited_by_vault_total{vault=…}`). The default policy
  is armed but practically unlimited (60 burst / 30 per min);
  `RateLimitPolicy::validate` refuses a zero/negative capacity (the
  previous policy stays in place) and a malformed spec is exit 2. e2e:
  burst passes, 3rd request refused promptly, sibling deterministic,
  metrics rows exact.
- **HMAC-signed webhooks (`webhook_secret`)**: an inventory row carrying a
  secret adds `X-QSV-Signature: sha256=<hex>` — the byte-exact HMAC-SHA256
  of the POST body, hand-rolled over the workspace sha2 (no new
  dependency) and verified against the OFFICIAL RFC 4231 test vectors.
  The relay authenticates the SENDER through the CONTENT: one flipped
  body byte fails the tag. Unsigned rows are unchanged (no header).

### Added — Round 17: installer bake, per-vault accepted rows, graceful shutdown, relay verifier
- **Transport/budget BAKE into the unit (`cosigner-bridge-install`)**:
  `--tls-cert/--tls-key/--tls-client-ca` (canonicalized to absolute paths)
  and `--rate-limit` land VERBATIM in `ExecStart`; after writing, each unit
  is re-read from disk — the body must match AND every baked flag must
  appear in the `ExecStart=` line (exit 1 otherwise, no `N baked flag(s)`
  confirmation). A malformed `--rate-limit` spec exits 1 BEFORE any file
  is written (no policy, no bridge — fail-closed).
- **Per-vault ACCEPTED rows** (`qsv_cosigner_accepted_by_vault_total{
  vault=…}`): `/metrics` now shows which vault CONSUMED the co-signer, not
  only which was denied — every seen vault gets a row (explicit zero
  included), BTreeMap order, and the Σ per-vault rows equals the
  unlabeled total on ONE scrape (scraping never moves a counter).
- **Graceful SIGTERM shutdown**: an async-signal-safe `signal(2)` handler
  (one atomic store + re-arm) flips a process-global flag; BOTH accept
  loops poll it over a NONBLOCKING listener every 10 ms (a blocking
  `accept()` would swallow the signal until the next connection), stop
  accepting, DROP the listener (bind releases immediately for the next
  replica), drain in-flight workers (the TLS loop joins them — no torn
  frame) and return `Ok(())` → exit 0. e2e drill: a real SIGTERM exits 0
  and the port is immediately re-bindable (std `Child::kill()` is
  SIGKILL and would skip the drain — the drill raises TERM itself).
- **Reference HMAC relay** (`scripts/webhook_relay.py`, std-only
  Python): content-based webhook authentication end to end — 400 for a
  missing signature, 401 for a bad tag (neither forwarded upstream),
  optional Bearer check, optional upstream forward and 204 to the
  daemon; fail-closed boot without `WEBHOOK_SECRET`, `--print-curl`
  signed drill, clean SIGTERM. Drill: good→204, tampered→401,
  unsigned→400.

### Added — Round 18: frame timeout, scrape token, rolling handover, replay-bound webhooks
- **Frame timeout (`--frame-timeout-ms`, default 10000)**: a read+write
  deadline on EVERY accepted socket — probe, HTTP head, frame ceremony
  and (through the inner TcpStream) the TLS handshake share one clock. A
  silent peer holds the serial loop for at most ONE timeout, a dribbling
  peer gets its deterministic refusal; the graceful-shutdown worker join
  runs on the SAME clock, so a half-handshaken client can never pin the
  SIGTERM drain — and a never-established handshake skips the
  close_notify flush (drain is exactly 1×, not 2×).
- **Metrics scrape token (`--metrics-token`)**: `/metrics` requires
  `X-QSV-Metrics-Token` when armed — missing/wrong = 401, counted in the
  new `qsv_cosigner_metrics_denied_total` counter (constant-time token
  compare; the signing path is untouched). The installer bakes the flag
  into ExecStart and verifies it on read-back; a whitespace token exits 1
  BEFORE any file is written.
- **Rolling restart proof**: SIGTERM releases the bind on the 10 ms tick
  while workers drain in parallel — the NEW replica takes the port and
  signs BEFORE the old process exits 0 (zero-downtime handover, no
  SO_REUSEPORT tricks). e2e drives the full stop→takeover→exit-0 cycle
  with a mid-handshake in-flight peer holding the drain open.
- **Replay-bound webhooks**: the daemon signs `"<unix-seconds>.<body>"`
  with `X-QSV-Timestamp` beside the tag — each attempt stamps a fresh
  second (at-least-once redelivery stays legitimate); the reference
  relay enforces ±300 s freshness, dedupes delivered tags under a lock
  and refuses replay/stale/bad-tag/bad-bearer BEFORE any forward.
- **Relay drill + CI job** (`scripts/webhook_relay_drill.sh` →
  `relay-drill`): the full refusal map on loopback — 204 / 401-replay /
  401-tamper / 400 unsigned / 400 no-stamp / 401 stale / 401 bearer /
  SIGTERM→0 — standard tools only, runs on every push.

### Added — Round 19: connection cap, systemd sandboxing, upstream 502
- **Connection cap (`--max-inflight`, default 64, 0 = unlimited)**: the
  TLS loop reaps finished workers on every accept and, when the cap is
  reached, accepts-and-closes immediately (clean EOF to the peer) — a
  connection flood becomes `qsv_cosigner_capacity_refused_total` instead
  of a thread/fd explosion; the slot holder runs on the frame timeout,
  so refusals are never permanent. e2e proves cap=1 (fast EOF, NOT the
  frame timeout), self-recovery and the counter.
- **systemd sandboxing**: the unit generator now ships
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  `RestrictNamespaces/Realtime/SUIDSGID=yes`, `LockPersonality=yes`,
  `ProtectKernel{Tunables,Modules,ControlGroups}=yes`,
  `SystemCallArchitectures=native` (SystemCallFilter and
  MemoryDenyWriteExecute deliberately absent: aws-lc's assembly maps
  executable pages) — asserted verbatim by the install e2e.
- **Upstream 502 (true at-least-once)**: when `--upstream` is set and
  curl fails, the relay answers 502 instead of a hollow 204 — the daemon
  retries with a fresh stamp and the alarm chain reaches the PAGER, not
  merely the relay. The drill + CI cover the dead-upstream case.

### Added — Round 20: scrape gate off loopback, health record, doctor, alerting
- **Open `/metrics` is now refused off loopback**
  (`require_metrics_token_off_loopback`): the counters name every
  provisioned vault and expose which one the watchtower froze — an
  open scrape maps the estate for free. Binding `0.0.0.0`, `:port` or
  any external address without `--metrics-token` exits 1 BEFORE the
  bind; an empty token counts as not armed. Loopback keeps the dev
  convenience, and TLS buys no exemption (the leak is the data, not the
  wire). `cosigner-bridge-install` re-runs BOTH gates before writing, so
  it can never generate a systemd unit that restart-fails forever.
- **`bridge-health.json`**: the bridge publishes pid, bind address,
  transport, vaults, mirror tip and its serve policy atomically (temp +
  rename) after the bind and the TLS material are verified, and
  REMOVES the record on every exit path from the accept loop onward. An
  unclean death (SIGKILL/OOM) therefore leaves a record whose pid is
  dead — the one state a supervisor must not mistake for "serving". The
  scrape token value never reaches disk, only the armed bit.
- **`qsv-cli doctor`**: one command, five layers — node cookie RPC tip,
  watchtower state readability + frozen count, MIRROR LAG against the
  node (a stale mirror protects against a stale view of the chain),
  the health record's pid liveness, and a live `/metrics` scrape. Only
  a FAIL exits 1 (WARN is advisory), so it works as a scripted health
  gate; a 401 scrape is a FAIL because the alert rules would be blind.
  Read-only: it never touches the record it inspects.
- **Prometheus + Grafana assets** (`scripts/prometheus_alerts.yml`,
  `scripts/grafana_dashboard.json`): 9 alerts and 9 panels bound to a
  `Metrics::METRIC_FAMILIES` contract that is itself proven against a
  live render. Prometheus happily accepts a rule on a series nobody
  exports — so every metric name is cross-checked in both directions
  (no phantom metric, no uncovered safety-critical counter), every rule
  must carry alert/expr/for/severity/summary/description, and
  `scripts/monitoring_drill.sh` (new CI job `monitoring-drill`) loads
  the YAML/JSON with python3 and re-checks coverage.

### Added — supervisor-grade service lifecycle (Round 21)
- **`Type=notify` + watchdog for the bridge**: the generated unit is
  `Type=notify` · `NotifyAccess=main` · `WatchdogSec=30`, and the verify
  gate REJECTS a unit without a real period (`Type=notify without a
  watchdog is theater`). `READY=1` fires only after the bind, the TLS
  material and the health record are real; `WATCHDOG=1` pings at half of
  `WATCHDOG_USEC` but ONLY while the accept loop's progress stamp still
  ticks — a wedged loop goes silent on purpose (silence is the restart
  signal, liveness-blind pings would be theater); `STOPPING=1` fires on
  the drain edge. No `NOTIFY_SOCKET` = byte-for-byte old behavior.
- **`--metrics-token-file`**: the scrape secret lives in one `chmod 600`,
  single-line file and NEVER enters argv/`/proc/*/cmdline`; group/other
  bits or a second line exit 1 before the bind, both token sources at
  once exit 2. `cosigner-bridge-install` bakes the PATH (never the value)
  into ExecStart and re-reads the file to verify with the real token;
  `doctor --metrics-token-file` exercises the same gate.
- **`--drain-timeout-ms`**: `--frame-timeout-ms 0` disables the only
  per-connection clock, so a peer that goes quiet mid-frame parks the
  loop and the SIGTERM drain never returns (TimeoutStopSec would SIGKILL
  with a stale `bridge-health.json`). The deadline starts at the stop
  edge; on expiry the bridge reports the cut, clears the record and
  exits 0. Default 0 = the unbounded classic drain.
- **`qsv-cli bench`**: an honest per-operation capacity report —
  ML-DSA-65 keygen/sign/verify, BIP-340 sign/verify, the enclave gate
  (the bridge's exact per-request path) and the health write+read loop,
  each as `ops/s` + `µs/op` under `black_box`. A REPORT: exit 0 always,
  `--iterations 0` is a usage error, and the floors live in the test
  suite (`tests/bench.rs`).

### Added — operability: rotate, declare, read (Round 22)
- **Live scrape-token rotation** (`systemctl reload`): the bridge
  re-reads `--metrics-token-file` on SIGHUP and swaps the gate IN
  PLACE — no restart, no signing gap, pid unchanged; an invalid
  rotation keeps the previous token (failing to rotate must not fail
  open). The handler is installed on every boot (the default
  disposition KILLS the process), the read runs on a polling thread,
  and the unit carries `ExecReload=/bin/kill -HUP $MAINPID` (verified).
- **The unit declares its clocks**: `cosigner-bridge-install` always
  bakes `--frame-timeout-ms` and `--drain-timeout-ms` into ExecStart —
  production runs the operator's timing, not the binary's defaults,
  and `systemctl show` states it verbatim.
- **Machine-readable operator output**: `doctor --json` (one
  `qsv-doctor/v1` document: per-check status/detail, fail/warn counts,
  `exit_code` — same exit contract, reason on stderr) and
  `bench --json` (one `qsv-bench/v1` document with the SAME rows as
  the table, for capacity baselines; still exit 0, `--iterations 0`
  prints no partial document). No banner, no prose on stdout.
- **The watchdog says why it went silent**: the moment pings stop
  (progress stamp past the stall limit) the thread writes ONE line per
  episode — freeze age and limit — before going silent; a restart in
  journald now has a witness, and a recovered loop closes the episode.

### Added — Round 23: capacity gate, rotation accounting, reload readiness
- **The capacity GATE** (`qsv-cli bench --baseline <report>` plus
  `--baseline-tolerance-pct N`, default 25): the report became an exit
  code. An operation landing below its baseline minus the tolerance
  prints `REGRESSION: <op>` with the delta and exits 1; nothing
  regressed → the `within N%` line and exit 0; `--json` carries the
  verdict inside the document. A baseline that cannot be COMPARED
  against (missing, unreadable, malformed, not covering all seven
  operations, or a tolerance outside `[0,100)`) is a usage error with
  COMPLETELY EMPTY stdout and exit 2 — a gate that compares against
  nothing must never pass by accident, and a measurement followed by
  "I can't use the baseline" would ship a wrong baseline.
- **A refused rotation is counted, not swallowed**:
  `qsv_cosigner_rotate_denied_total` lives INSIDE the scrape gate and
  the exposition renders the very same counter (one `Arc`, two readers,
  zero drift). Every refused rotation and every reload that could not
  even reach one increments it; new alert `QsvCosignerTokenRotationStalled`
  (warning) plus a Grafana panel. A rotation that WORKED is never
  counted, and a stray SIGHUP on a disarmed dev bridge never pages
  anyone.
- **`doctor` proves a reload would rotate BEFORE one runs**: the bridge
  health record now carries `metrics_token_file` — the PATH only, never
  the value — and the doctor audits that file with the bridge's OWN
  contract (mode 600, exactly one line, no whitespace): OK · FAIL ("a
  reload would be REFUSED") · WARN ("armed via `--metrics-token`: no
  file to re-read, so `systemctl reload` cannot rotate it").
- **The unit declares its capacity too**: `cosigner-bridge-install`
  always bakes `--max-inflight` (defaults included) and verifies the
  exact syntax in the ExecStart it wrote — 8 baked flags now.
- **Health record constructor takes a policy record**
  (`health::ServePolicyRecord`) instead of a four-knob positional tail.
  The on-disk shape is unchanged and a record written by an older build
  still parses (`#[serde(default)]`), so a missing field never
  manufactures a false "stale" verdict.

### Added — Round 24: capacity evidence, sandbox reachability, boot rehearsal
- **WORKER OCCUPANCY GAUGES**: `qsv_cosigner_workers_active` (right
  now), `qsv_cosigner_workers_peak` (high-water mark since boot) and
  `qsv_cosigner_worker_limit` (the CONFIGURED `--max-inflight`) — the
  first gauges in the exposition. Sizing the worker ceiling is evidence,
  not folklore, and the new `QsvCosignerWorkerSaturation` rule reads the
  operator's own ceiling instead of a constant typed into a rule file.
- **LANDED ROTATIONS COUNTED TOO**: `qsv_cosigner_rotate_total` rides
  the same pair of shared `Arc`s as the refusal counter, so "did my
  reload actually land?" is answerable from a scrape — the failures were
  loud while the successes were silent.
- **INSTALL AUDITS SANDBOX REACHABILITY**: the generated unit runs with
  `ProtectHome=yes`, so a token file under `/home`, `/root` or
  `/run/user` is unreadable BY THE SERVICE. Install now refuses such a
  file (exit 1, nothing written) instead of baking a unit that can never
  boot; the file itself is never the objection — only its location.
- **`cosigner-bridge --dry-run`**: the boot rehearsal. Every boot gate
  runs — token file contract, watchtower state, transport policy, TLS
  material and the BIND ITSELF — then the resulting policy is printed
  and exit 0. No health record (it would lie), no sd_notify, no accept
  loop, no SIGHUP handler.

### Added — Round 25: honest ceiling, live alert contract, continuous audit
- **HONEST SERIAL CEILING**: the plain accept loop now publishes what
  it IS — `qsv_cosigner_worker_limit 1` (a fresh `Metrics` used to render
  0, which reads "unlimited" for a loop that serves one connection at a
  time) plus the `active`/`peak` occupancy of the connection it serves.
  `QsvCosignerWorkerSaturation` guards on `worker_limit > 1`: a ceiling
  of one cannot be "80% saturated", so an idle serial deployment no
  longer pages 5 minutes after its first request.
- **CONSTANT-TIME SCRAPE COMPARISON**: `token_eq` no longer returns
  early on a length mismatch (the old check answered a wrong length
  faster than a wrong last byte) — the fold now runs over the longer
  input with zero padding, so runtime depends only on the presented
  length. Paired with a **panic audit** (43 candidates, 42 of them
  production code, test modules excluded): ZERO on the server request
  path; the CBOR `take(n)` exact-length contract, SLIP-39's
  duplicate-index guard and every `main.rs` expectation classified as
  proven-safe (docs/09 §9). The fuzz gate then PROVED why a grep is
  not enough: it found two real panic classes a token scan cannot see
  — byte-index slicing on multi-byte text in `hex_decode`, and a
  `2 * n` multiply overflow with unbounded recursion in the CBOR
  `skip` — both fixed with regression tests.
- **SECURITY AUDIT IN CI**: the `security-audit` job runs `cargo audit`
  (RustSec, 197 dependencies, any vulnerability fails) plus
  `scripts/secret_scan.sh` — 11 credential-material patterns over the
  tracked tree AND the full git history (owning commit reported),
  offline and byte-identical between CI and a laptop.
- **LIVE ALERT EXPOSITION CONTRACT**: `every_alert_reference_is_a_series_the_live_bridge_exports`
  boots a REAL bridge and scrapes every series a rule reads, producing
  the three event-conditional `*_by_vault` families by actually causing
  their events (watchtower ALERT, then a `--rate-limit 3:1` overflow) —
  a family no event can render would be a silently dead alert. The
  monitoring drill now demands `promtool check rules --lint all` (real
  PromQL parser) under `PROMTOOL_REQUIRED=1`, via the pinned official
  `prom/prometheus` image through docker — no root, read-only mount.
- **BOUNDED FUZZ GATE** (`scripts/fuzz_gate.sh`): three untrusted-input
  parsers under libFuzzer — the NSM attestation document (valid and
  invalid hex layers, adversarial CBOR), the frame/health/watchtower
  JSON surfaces, and SLIP-39 shares (`decode_share` round-trip +
  `combine` fed duplicate shares) — 45–60s per target with a 10s
  per-input timeout, real seeds committed under `fuzz/corpus`. The
  first runs found and locked in TWO crashes — the `hex_decode`
  char-boundary panic (input `0a c8`) and the `skip` map-multiply
  overflow (8-byte CBOR length) — with the skipper's recursion depth
  bounded preemptively as a third class; all covered by `nsm.rs`
  regression tests plus the committed corpus seeds.
- **CAPACITY GATE DRILLED IN CI** (`scripts/capacity_gate.sh`): the
  `bench --baseline` machinery is exercised end to end on the real
  binary every push — round-trip baseline passes, a 100x-inflated
  baseline refuses with exit 1 + `REGRESSION:` on stdout, a malformed
  baseline refuses with exit 2 and an EMPTY stdout.

### Added — Round 26 (supply-chain policy, parser completion)
- **RUSTSEC "UNMAINTAINED" ROOT-CLOSED**: the TLS PEM reader migrated
  off `rustls-pemfile` (RUSTSEC-2025-0134, a DIRECT dependency) onto
  `rustls::pki_types::pem::PemObject` — already shipped by rustls, so
  no new crate entered the graph and rustls-pemfile left Cargo.lock
  entirely; the fail-closed contracts are pinned by 2 new tests (no
  key SECTION → the family message, a malformed section →
  `parse key: <cause>`). The one remaining notice,
  `atomic-polyfill` (RUSTSEC-2023-0089), is DOCUMENTED where it
  applies instead of waved through: target-gated to MCUs without
  native atomics, never compiled on x86_64/aarch64 (`cargo tree -i`
  prints nothing), the postcard→heapless chain already at the latest
  versions — `cargo audit --ignore` carries that justification in
  ci.yml, and `deny.toml` locks the graph to the two targets that
  ship.
- **DEPENDENCY POLICY** (`deny.toml` + `cargo deny check` in the
  security-audit job, every push): a 9-SPDX license whitelist (NOT on
  the list = error, including `hex_lit`'s MITNFA variant, allowed
  deliberately), wildcard and duplicate bans kept visible as
  warnings, and registry-only sources — a git dependency or an
  unknown registry fails the job.
- **PSBT FUZZ TARGET** (`psbt_parse`, the fourth parser): the CLI's
  raw-wire and base64 file read paths, parse→serialize→parse
  stability, the vault BIP-341 sighash helper over EVERY input and
  `finalize_and_extract` — all answering hostile maps with `Err`.
  Seeded from a REAL `psbt build` artifact (532 B base64 + the same
  data's 397 B raw form); COSE_Sign1 remains inside
  `attestation_doc`. CI caches the evolved corpus between runs
  (actions/cache on `fuzz/corpus`) and the window grows to
  120s/target (local long pass: `FUZZ_SECONDS=300`). The first
  300s pass paid for itself immediately: it caught a REAL crash —
  rust-bitcoin 0.32's `extract_tx` maps any `fee()` error outside
  three listed variants to `unreachable!()`, so a hostile
  `non_witness_utxo` (vout that cannot resolve, `PsbtUtxoOutOfbounds`)
  PANICKED inside the dependency (crash-8523a028).
  `finalize_and_extract` / `finalize_multi_input_and_extract` now
  judge `fee()` FIRST through one shared helper — every such error
  becomes our `Err` — with a regression test and the crash input
  committed as a corpus seed.
- **NATIVE PROMTOOL**: the monitoring drill resolves a system
  `promtool` first and now REPORTS which source it used
  (native path / pinned docker image); `PROMTOOL_REQUIRED=1` still
  fails when neither exists.

### Test matrix
**274 tests green in both the plain and the consensus configuration**
(identical test sets — `qsv-cli`/`qsv-node` enable `qsv-core/consensus`
unconditionally, so the reference engine links in either build; the
`qsv-core` crate's own suite is 110 of the 274) (was 242/98 at Round 26;
239/98 at Round 25;
233/98 at Round 24;
231/98 at Round 23),
including **35 live e2e flows**
(12 bitcoind-backed + the co-signer bridge socket/TLS/mTLS/rate-limit/
SIGTERM/slowloris/scrape-token/rolling/in-flight-cap/health-record/notify-watchdog/scrape-token-file/drain-deadline/sighup-rotation/rotation-stall/live-exposition-contract suite + the systemd generator suite: estate, live PSBT ×3, FROST spend
(+ co-signer gate, + multi-UTXO consolidation), watchtower,
watchtower-daemon (+ rotation-state v2), inheritance-kit, SD-card
hardware-round-trip, vault-rotate (+ bridge), vault-rotate batch sweep
(+ dry-run), vault-rotate sweep gate (+ mTLS), P2MR source trial,
cosigner-bridge-install (+ TLS bake + scrape token), operator doctor ×3, mempool policy ×2), 5 FROST core tests, and the
45-official-vector SLIP-0039 suite. The batch-gate mining loop now
retries a stalled RPC (the transport's hard 15s cap under the parallel
matrix) instead of failing the suite.

## [v2026.2.0] — 2026-09-27 (Round 6)

### Added
- Live-PSBT Phase 2 (`psbt-live`): scantxoutset discovery → real mempool
  acceptance, no wallet ownership.
- FROST + SLIP-0039 inheritance wizard (`inheritance-kit`): trusted-deal,
  recover-check, RFC 9591 ceremony, printed-word backups.
- BIP-360 K1 watchdog CI (`.github/workflows/k1-tracker.yml`).
- Nitro Enclave production attestation (`qsv-cosigner --features nsm`).
- Bilingual docs sync suite; live dashboard `--watch` proof.

## [v2026.1.0] — earlier rounds

- qsv-core protocol engine (NUMS, policy, MAST, unvault covenant),
  qsv-pqc ML-DSA-65 gate, PSBT Phase-1 file flow, estate letter +
  `verify-estate`, WOTS+ emergency leaf (T6 consensus-proven), leaf
  budgets, Shamir/SLIP-0039 kit shares, BIP-360 migration plan (docs/11).
