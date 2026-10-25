# Module 10 — Operations & User Guide (qsv-cli)

> Specification module 10 of QuantumSafe-Vault — v2026.3.

## 1. Build and first run

No Rust toolchain is needed to TRY it: prebuilt archives land on Releases
(D2, §4.65) — download → `bash scripts/verify_release.sh …` → `qsv-cli demo`
→ `qsv-demo.html`. From source:

```bash
cargo build --release
cargo test --workspace                       # full matrix; current count: STATUS.md §1
cargo run -p qsv-cli -- demo                 # offline first run: one page, no keys
cargo run -p qsv-cli -- constants            # CSV timings, FIPS 204 sizes, NUMS seed text
```

The CLI is built with clap 4 derive: `--help`, `-V`, per-subcommand help and typed `--network {bitcoin|signet|testnet|regtest}` validation. Exit codes are scripting-friendly — `0` success, `1` any failure with a one-line diagnostic, `2` usage errors — and output is deterministic for fixed seeds (same command, same bytes, every run). All demos are fully local; only the commands that explicitly talk to a node do.

**No-fake-data rule:** `vault-dashboard` reads the tip from a REAL node (read-only cookie-auth JSON-RPC, no wallet access). Without a node it refuses to fabricate numbers and fails with an actionable message; pass `--tip N` for offline planning and `--watch S` for a live frame every S seconds.

## 2. Vault setup (vault setup & live dashboard)

```bash
cargo run -p qsv-cli -- vault-setup --network signet
```

1. Derive user/enclave/recovery/heir keys (production: hardware wallets + enclave provisioning), build the policy, record the address, merkle root and NUMS seed text for the estate letter.

### 2.1. Live vault dashboard (vault-dashboard)

Reads the timelock clocks from the REAL chain tip (RPC cookie auth, read-only):

```bash
cargo run -p qsv-cli -- vault-dashboard --datadir ~/.bitcoin --network bitcoin
cargo run -p qsv-cli -- vault-dashboard --network signet --watch 30
cargo run -p qsv-cli -- vault-dashboard --tip 900000    # offline planning mode
```

Sample output:

```text
Chain tip: 900000  (live node · best 000000000000…abc123)
Heartbeat [OK]: refresh at block 912960 (≈ 2025-08-12, ~90d away)
Inheritance [LOCKED]: opens in 26280 blk (≈ 2025-11-12, ~182d)
Recovery clawback window: 144 blk remaining
Vault: bc1p… · 2-of-2 hybrid + CSV 144 recovery + CSV 26,280 inheritance
```

No-fake-data rule: when the node is unreachable the command produces NO invented
number; it returns an actionable error ("start bitcoind or pass --tip N"). Dates
are projections at the 10 min/block epoch average; the reconciliation math never
uses dates.

Sample output (values belong to the demo keys):

```text
╔══════════════════════════════════════════════════════════════════╗
║           QUANTUMSAFE-VAULT SETUP REPORT (v2026.3)               ║
╠══════════════════════════════════════════════════════════════════╣
║ [1] NUMS Internal Key (x-only): 8a92f1...  (PROVABLY             ║
║     UNSPENDABLE — the d scalar rests on SHA-256 preimage          ║
║     resistance)                                                   ║
║ [2] Hybrid Policy: 2-of-2 (user ⊕ enclave-PQC)                   ║
║     + 144-block recovery + 26,280-block inheritance (2-of-3)      ║
║ [3] Vault Address (signet): tb1q...                               ║
║ [4] Estate Commitments: sealed to 3 heir PQC identities ✅        ║
╚══════════════════════════════════════════════════════════════════╝
```

**Audit point:** the output key can be recomputed by hand from the NUMS seed +
the Merkle root (`qsv-core::taproot`); on a mismatch the installation is
 cancelled.

## 3. Hybrid spend (enclave co-sign flow)

```bash
cargo run -p qsv-cli -- hybrid-spend-demo
```

The flow mirrors Document 03 §5 exactly: client-side ML-DSA-65 proof over the intent → enclave gate re-verifies it over the *exact* message → a real BIP-340 co-signature is released → the 2-of-2 witness is assembled in script order → **libbitcoinconsensus** judges the transaction. A tampered proof is refused (fail-closed), and the demo asserts that refusal before spending. Operationally: `prepare_unvault` → sign the user side (hardware PSBT flow via `qsv-core::psbt`, or `qsv-cli psbt build|sign|finish` for the file-based Phase-1 round trip) → co-signer release → `finalize_unvault` → broadcast. During the 144-block CSV window the recovery clawback stays armed.

## 4. Inheritance (dead man's switch)

```bash
cargo run -p qsv-cli -- inheritance-demo
```

1. The vault UTXO stays idle for 26,280 blocks (~180 days) → the CSV lock opens.
2. Any 2 of the 3 registered parties settle: heir₁, heir₂ or the executor (2-of-3, `multi_a` with the empty-slot discipline required by BIP-342).
3. Until settlement the owner's veto window (4,320 blocks ≈ 30 days after an unvault) allows clawback.
4. The heartbeat refresh resets the dormancy clock; missing it is the *trigger*, not a failure mode — that is the dead man's switch.

**PSBT Phase 2 (live chain):**

```bash
# The REAL live vault coin → the real mempool (scantxoutset discovery, no wallet ownership needed):
cargo run -p qsv-cli -- psbt-live --datadir ~/.bitcoin --rpc-port 8332
# MULTI-INPUT consolidation: ≥N live coins spent in ONE transaction, largest first;
# full vault script-path context + tap_merkle_root on every input (hardware-wallet Q derivation):
cargo run -p qsv-cli -- psbt-live --datadir ~/.bitcoin --rpc-port 8332 --min-inputs 3

# Spend the FROST k-of-n GROUP key on the real chain (threshold inheritance spend):
cargo run -p qsv-cli -- frost-spend --public public-package.txt \
    --deal h0=heir-00-…-deal.txt --deal h2=heir-02-…-deal.txt \
    --datadir ~/.bitcoin --rpc-port 8332 --fund-sat 250000 --fee-sat 1500 --dir ceremony/
```

`psbt-live` writes the complete BIP-371 taproot context on every input (`tap_internal_key`, `tap_scripts`, `tap_merkle_root`, `witness_utxo`); `--min-inputs N ≥ 2` fails closed when the target is unreachable. `frost-spend` runs the RFC 9591 ceremony under the BIP-341 key-path tweak — the coordinator and ALL heir packages are tweaked by the SAME root (and by none in the untweaked ceremony); the aggregated 64 B signature verifies under the tweaked output key, passes the consensus self-check and is broadcast. `--no-broadcast` (watchtower dry run) stops BEFORE broadcasting and writes the deterministic transaction hex to `frost-spend.txhex`.

**Co-signer gate (`--cosigner ADDR --vault-id ID`):** The threshold spend can also pass
through the bridge: the ML-DSA-65 proof over the given sighash goes to the bridge and NO
heir round runs until the enclave releases THAT sighash — a watchtower-frozen vault is
REFUSED (exit 1, nothing changes on chain, heir aggregation never starts); when the state
is clear the signature is VERIFIED under the pinned enclave key and the ceremony proceeds
to broadcast. `--cosigner`/`--vault-id` must be given TOGETHER (a half-pair is a usage
error).

**Signet environment (Phase 1, real-network rehearsal — valueless coins):**

```bash
scripts/signet_setup.sh bootstrap          # signet bitcoind + qsv wallet + faucet address
scripts/signet_faucet.sh                   # ArkFaucet CAPTCHA-free claim loop (halts on 429, reports the rail budget)
scripts/signet_setup.sh status             # chain tip + wallet + demo vault address
scripts/signet_setup.sh vault-fund 20000   # send 20,000 sats to the demo vault (1 conf)
scripts/signet_setup.sh lifecycle          # psbt-live end-to-end: the REAL signet mempool
```

The script pins `-signet` on every call (it never touches mainnet), starts the node
with cookie auth in daemon mode, runs `psbt-live` with `--build-only` first
(coordinator/device split discipline) and then the full pass: scantxoutset discovery →
BIP-174/371 PSBT → both device signatures → consensus self-check → **signet mempool
ACCEPT**. Signet blocks take ~10 minutes; wait for 1 confirmation after `vault-fund`.
The same node can be watched with `watchtower --network signet` for the alert line.

**SD-card hardware round trip (Coldcard/Ledger, Phase 1 rehearsal):**

```bash
cargo run -p qsv-cli -- psbt export --in vault.psbt --stem hw-card
#   → hw-card.psbt (BINARY BIP-174; the real device format) + hw-card.sha256
#     (integrity manifest) + hw-card.txt (human-readable spend audit sheet)
# … the device loads the card, computes the sighashes ITSELF, writes back …
cargo run -p qsv-cli -- psbt import --in hw-returned.psbt --manifest hw-returned.sha256 --out final.psbt
#   manifest verification → EVERY tap script-sig verified under the known
#   leaf keys → witness assembly → libbitcoinconsensus verdict.
#   One flipped byte / manifest mismatch / forged signature / stripped PSBT = exit 1.
```

### 3.1. Inheritance watchtower

```bash
cargo run -p qsv-cli -- watchtower --datadir ~/.bitcoin --rpc-port 8332
cargo run -p qsv-cli -- watchtower --datadir ~/.bitcoin --rpc-port 8332 \
    --deal h0=heir-00-…-deal.txt --deal h2=heir-02-…-deal.txt \
    --public public-package.txt --fund-sat 250000 --dir rehearsal/
```

One read-only pass (a cron/systemd timer owns the cadence; alert latency = one pass):

1. **Heartbeat**: if the policy is DUE → `ALERT` + **exit 1** (the dead man's switch fired — that is what the tower is for); when healthy, the next window is printed.
2. **Inheritance CSV**: the 26,280-block countdown; when open, "heirs may settle".
3. **Live coins**: the vault address's UTXOs via scantxoutset (read-only — nothing is spent).
4. **Threshold rehearsal** (with `--deal`): a REAL RFC 9591 ceremony in `frost-spend --no-broadcast` mode — real sighash, real threshold aggregation, real consensus self-check; the artifact is `frost-spend.txhex` (deterministic: a second run yields the SAME txid). False alarms are structurally impossible: a healthy pass NEVER exits 1.

### 3.2. Watchtower daemon (multi-vault, persistent state, webhook)

For institutional deployment the single-pass command extends into a daemon discipline. The one unchanged principle: **no broadcasting** — the daemon only reads, decides and raises ALARM; the spending decision always stays human (Doc 03 §9).

**Inventory file (`--inventory env.json`)** — multiple vaults in one pass, per-vault heartbeat + optional webhook:

```json
{
  "vaults": [
    { "id": "family-main", "last_refresh_block": 812345,
      "webhook": "https://ops.example.com/hooks/qsv", "webhook_token": "whsec_…" },
    { "id": "cold-storage-2", "last_refresh_block": 810000 }
  ]
}
```

**Persistent state (`<state-dir>/watchtower-state.json`)** — every pass writes per-vault `last_tip` / `last_verdict` / `idle_blocks`; the next pass reads it as the baseline. An unreadable state file exits **fail-closed** (no silent resets). A webhook call NEVER changes the exit code: a network error is a `webhook: FAILED (<reason>)` line; the primary channel is the process exit (ALARM = exit 1). In multi-vault mode ONE due vault makes the whole pass exit 1 (`ALERT[vault-id]`).

**Webhook delivery (Round 15) is at-least-once:** a failed POST is retried within the SAME pass with fixed backoff (3 attempts; 0.5 s + 1.0 s) and the LAST outcome persists per vault in the state file (`webhook_delivery`: `delivered` / `failed` / `not_configured`) — the operator sees what the secondary channel actually did. A persistently failing webhook NEVER softens the exit code (the primary channel stays exit 1); the alert body is byte-identical across attempts (a relay that dedupes by body sees one alert).

**HMAC signature (Round 16):** when the inventory row carries `webhook_secret`, the POST adds an `X-QSV-Signature: sha256=<hex>` header — the byte-exact HMAC-SHA256 of the body (RFC 2104; verified against the official RFC 4231 test vectors; from Round 18 on the tag covers the `"<ts>.<body>"` unit — see the replay binding below). The relay authenticates the SENDER through the CONTENT, not just the channel: a forged alert with one flipped body byte fails the tag.

**Relay verifier (Round 17):** `scripts/webhook_relay.py` is the working reference implementation of the HMAC contract — it authenticates from the CONTENT of the message, not the channel (`X-QSV-Signature: sha256=<hex>` over `"<X-QSV-Timestamp>.<body>"`, constant-time compare via `hmac.compare_digest`). A missing/unsigned request is 400, a bad signature is 401 — neither is EVER forwarded upstream; a valid signature passes the optional Bearer check, is logged and (when `--upstream` is given) forwarded, and the daemon gets 204. Without `WEBHOOK_SECRET` the relay fails closed at boot (no secret, no channel); `--print-curl` emits a signed drill request for the daemon, and SIGTERM stops it cleanly (exit 0).

```bash
WEBHOOK_SECRET=whsec_… python3 scripts/webhook_relay.py \
    --port 8099 --upstream http://127.0.0.1:9090/oncall
python3 scripts/webhook_relay.py --print-curl   # signed drill request
```

**Replay binding (Round 18):** the signature covers NOT the body alone
but the unit `"<X-QSV-Timestamp>." + body` — bytes and freshness stamp are
ONE signed payload. The relay refuses a stamp outside the ±300 s window
(`WEBHOOK_TOLERANCE`), and inside the window it refuses the SAME signed
payload a second time (delivered tags are kept under lock). Each daemon
attempt stamps a fresh second, so at-least-once redelivery is never
mistaken for a replay. The full refusal map is drilled by
`scripts/webhook_relay_drill.sh` (204 / 401-replay / 401-tamper / 400 /
400-no-stamp / 401-stale / 401-bearer / 502-upstream / SIGTERM→0) and CI's
`relay-drill` job runs it on every push. **Upstream hop (Round 19):** when
`--upstream` is set and curl FAILS, the relay answers **502** (authenticated
but NOT delivered) — the daemon retries with a fresh stamp, so
at-least-once aims at the PAGER, not merely at this relay.

```bash
cargo run -p qsv-cli -- watchtower --datadir ~/.bitcoin \
    --inventory env.json --state-dir /var/lib/qsv
```

**systemd deployment:** a `Type=oneshot` unit + a 30-minute `OnCalendar=*-*-* *:15/30` timer, `Persistent=true` (missed passes are compensated at boot), `ProtectSystem=strict` + `ReadWritePaths=/var/lib/qsv` (the daemon is read-only, with no spending authority). Alert latency = timer interval + one pass. With `--inventory` the single-vault `--last-refresh-block`/`--deal` paths are unavailable (confusion error, exit 2); the FROST dry run is supported in single-vault mode only (a threshold ceremony requires a per-vault package set).

**From alarm to enforcement (co-signer alarm mirror):** the daemon's exit code is the alert; the co-signer is the lock. The operator's relay mirrors each `ALERT[vault-id]` into the enclave with `Cosigner::set_alarm(vault_id)`: from that moment EVERY signing request for that vault is refused — even with a perfectly valid ML-DSA-65 proof (fail-closed; Theorem 1 can only ever STOP the two-key protocol, never shortcut it). The freeze is per-vault, survives nothing across reboots (a fresh enclave starts clear and the daemon re-raises from persisted watchtower state), and only the explicit `clear_alarm` path after a VERIFIED heartbeat refresh unfreezes the vault:

```text
watchtower pass (exit 1, ALERT[vault-id])
      └─ operator relay ──▶ Cosigner::set_alarm(vault_id)     # signing FROZEN
refresh verified (vault-rotate, new coin confirmed)
      └─ operator relay ──▶ Cosigner::clear_alarm(vault_id)   # determinism restored
```

### 3.3. Ownership heartbeat: vault-rotate (refresh + heir recommitment)

The owner's single action is keeping the timer honest (ZERO HITL): cron/systemd runs
`vault-rotate`; if a refresh is missed the watchtower ALARMS, the co-signer lock drops
and the vault stays silent until the mirror clears — three components closed in ONE
loop: **heartbeat (liveness) → watchtower (threat) → co-signer (enforcement)**.

```bash
cargo run -p qsv-cli -- vault-rotate --datadir ~/.bitcoin --rpc-port 8332
# live scantxoutset discovery → self-churn refresh (SAME address in and out, CSV
# clock reset, estate letter stays valid) → hybrid leaf signing → consensus
# self-check → broadcast. [--no-broadcast] holds the signed tx instead.
cargo run -p qsv-cli -- vault-rotate --datadir ~/.bitcoin --rpc-port 8332 \
    --heir "kiz=pqc-seed-hex-64" --heir "ogul=pqc-seed-hex-64"
# HEIR RECOMMITMENT: before the coin moves, every registered heir slot must
# present a FRESH ML-DSA-65 identity; partial/stale = exit 1, chain untouched.
```

### 3.4. The lock as a service (cosigner-bridge) and live co-signing

The lock is now a SERVICE: `cosigner-bridge` runs the enclave co-signer on TCP and
applies the alarm mirror PER REQUEST — the watchtower state file is re-read before
every request, so a daemon refresh takes effect WITHOUT a restart (a read/parse
failure keeps the LAST mirror: alarms never silently clear). Bad clients are
survivable: an empty probe, a truncated frame or malformed JSON answers a refusal
or is dropped — the loop lives on.

```bash
cargo run -p qsv-cli -- cosigner-bridge --listen 127.0.0.1:3334 \
    --state-dir /var/lib/qsv --vault-id bcrt1q…
```

`vault-rotate --cosigner 127.0.0.1:3334` requests the SECOND signature from this
service: the client proves the ML-DSA-65 identity over the sighash, the enclave
releases the co-signature behind the Theorem-1 gate, and the client VERIFIES it
under the pinned enclave key before placing it in the witness. A refusal
(`watchtower alarm active`) stops the rotation with exit 1 — nothing changes on
chain.

**Inventory and persistent state:** `vault-rotate --inventory env.json --vault-id
family` reuses the SAME inventory schema as the watchtower daemon; the rotation
runs ONLY when the heartbeat is DUE (an early re-rotation is refused) and a
successful run writes `<state-dir>/rotation-state.json` (the tip becomes the new
baseline). The alarm↔rotation story stays consistent: a watchtower ALERT and the
rotation state can never contradict each other.

**Rotation state v2 (id-based):** `rotation-state.json` now keeps a PER-VAULT record
under the `version: 2` schema (a `vaults` map in the SAME id space as the watchtower
inventory); single-vault rotations record under the stable id `single-vault` (the
no-baseline read path looks up the same id). The consistency layer: an inventory row
claiming an EARLIER baseline than a recorded rotation fails closed ("inventory/
rotation-state MISMATCH" — the rotation state reflects the chain, so fix the inventory
row); a missing state file is NOT an error (the inventory alone drives the baseline); v1
top-level `last_refresh_block` files still load for transition; a v2 file holding only
inventory-id records REFUSES the single-vault no-baseline path instead of guessing.
The DAEMON reads the same source: a `watchtower --inventory` pass consults the id-based
rotation records in the SAME state dir and, when a record is LATER than the inventory
row, overrides it (a `rotation-state: refreshed at N — inventory row is stale` audit
line; the mirror records the overridden verdict) — an alarm already cured by a rotation
is never re-raised by the daemon. A record above the tip counts as corrupt (ignored);
a missing rotation-state file keeps the daemon state-less; an UNREADABLE file fails
closed with exit 1 — never a silent fallback.

**systemd install generator:** For a persistent deployment, don't hand-write the
unit pair — `cosigner-bridge-install` GENERATES the service + timer, writes them,
and VERIFIES what landed on disk (any missing required directive exits 1 —
install-what-you-print):

```bash
cargo run -p qsv-cli -- cosigner-bridge-install \
    --listen 127.0.0.1:3334 \
    --state-dir /var/lib/qsv \
    --vault-id bcrt1q… \
    --unit-dir /etc/systemd/system
sudo systemctl daemon-reload && sudo systemctl enable --now qsv-cosigner-bridge.timer
```

Unit hardening: `ProtectSystem=strict` (the only writable path is
`ReadWritePaths=<state-dir>`), `PrivateTmp`, `NoNewPrivileges`, `ProtectHome` and
`Restart=on-failure` (Round 19 adds `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictNamespaces/Realtime/
SUIDSGID=yes`, `LockPersonality=yes`, `ProtectKernel{Tunables,Modules,ControlGroups}=
yes` and `SystemCallArchitectures=native` — `SystemCallFilter`/
`MemoryDenyWriteExecute` are deliberately ABSENT: aws-lc's hand-written assembly
maps executable pages); `ExecStart` carries the real
`cosigner-bridge --listen/--state-dir/--vault-id` invocation. Without `--unit-dir`
the generator prints a stdout PREVIEW and writes nothing; `--timer-calendar`
(default: every 5 minutes) sets the watchtower pass cadence, and `Persistent=yes`
catches passes missed while the host was down.

**Bridge metrics (Prometheus):** the `cosigner-bridge` listening socket answers a plain
HTTP `GET /metrics` with the Prometheus text exposition (200,
`text/plain; version=0.0.4`): `qsv_cosigner_requests_total`, `accepted_total`,
`refused_total`, `alarm_refused_total` (refusals caused by a watchtower freeze) and
`serve_latency_us_sum` (cumulative serve latency). A scrape moves NO counter —
observing is not signing: the same request yields the same deterministic signature
after a scrape. Other HTTP paths answer a normal refusal frame (the loop survives
junk); every close drains the receive queue so scrapers see a clean FIN, never RST.

**Scrape token (Round 18):** with `--metrics-token <tok>`, `/metrics` now
REQUIRES the `X-QSV-Metrics-Token` header — a missing or wrong token is
refused 401 and counted in `qsv_cosigner_metrics_denied_total`; only the
authorized scrape renders the exposition (constant-time token compare).
The token never touches the signing path (it closes the observability
endpoint, not the gate). `cosigner-bridge-install --metrics-token` bakes
the same flag into ExecStart and reads it back from disk.

```bash
curl -s --raw http://127.0.0.1:3334/metrics
```

**Multi-UTXO threshold spend:** `frost-spend --min-inputs N` sweeps the LARGEST N live
coins at the group address into ONE key-path spend — one FROST ceremony round PER input
each sighash is a distinct message), the aggregated per-input signatures verified under
the tweaked group key and against libbitcoinconsensus, ONE broadcast. Fewer live coins
than N exits 1 BEFORE any ceremony runs (fail-closed floor).

## 4.5. Estate letter (inheritance & emergency document)

```bash
cargo run -p qsv-cli -- estate-letter --network bitcoin --label "Family vault" --date 2026-09-28 --qr > letter.txt
cargo run -p qsv-cli -- verify-estate --file letter.txt --network bitcoin   # exit 0 = authentic
cargo run -p qsv-cli -- verify-estate --file letter.txt --network regtest   # wrong network ⇒ hinted refusal
```

Produces the printable, self-contained document — **secret-free**: only address, merkle root, output key, leaf hex, heir commitments and procedure text. Sections: (1) where the money is, (2) spending rules (all four MAST leaves), (3) time constants, (4) who can act, (5) the emergency procedure (WOTS+ kit opening), (6) independent verification instructions.

**Determinism contract:** identical inputs produce a byte-identical document, so diffing an old print against a new output detects tampering; `--label` and `--date` are bound into the document.

**QR block (`--qr`):** §1 identity (address | merkle root | output key) encoded as one pipe-separated `QSV1|…` line plus terminal QR art, so a phone camera can cross-check the printed page.

**Independent verification:** `verify-estate` re-derives the vault from protocol constants and byte-compares the four §1 identity fields plus all four leaf scripts (**8 checks**). Authentic → `PASS (8/8)`, exit 0; one flipped byte → `FAIL`, exit 1 (script-friendly); wrong network → an "issued for signet" hint instead of a blind failure. Long hex is abbreviated on success and printed in full on mismatch. The same workflow is proven against a live bitcoind in the CLI's regtest test: issue → verify → fund the letter's address → tamper ⇒ exit 1.

### 4.6. Measurement tools (budget · parameters · kit shares)

```bash
# Per-leaf spend budget, measured from REAL signed reference spends:
cargo run -p qsv-cli -- leaf-budget
#   script/control/witness sizes, witness item list, tx vB/WU,
#   BIP-342 ≤520 B compatibility + headroom, 1–100 sat/vB fee table.
#   (Normal 169 vB · recovery 146 · heir 180 · emergency 154.)

# WOTS+ parameter space (RFC 8391) + the 520-byte ruling:
cargo run -p qsv-cli -- wots-params
#   VERDICT: no w ever fits a full 32-byte message (min 1,088 B @ w=256);
#   truncation cap is 14 bytes = 112 bits < 128 ⇒ leaf 4 MUST be
#   commit-reveal (a structural-impossibility proof, not a preference).

# Split/combine the emergency kit seed with Shamir (GF(256)), 3-of-5:
cargo run -p qsv-cli -- kit-seed split --threshold 3 --shares 5
cargo run -p qsv-cli -- kit-seed combine --share qsvss1-1-… --share qsvss1-2-… --share qsvss1-3-…
#   any 3 shares restore; 2 shares = integrity-tag REFUSAL (never a wrong
#   key). Combine round-trips the WOTS+ kit seal: "WOTS+ kit seal: VERIFIED".
```

**Live verification record (27 September 2026):** `vault-dashboard --watch` was
verified against a real regtest bitcoind v28.2 — the tip advanced 120→121 under
mining and the best hash refreshed live (`59f04969…`→`4773c0a9…`): the empirical
documentation of the no-fake-data rule.

### 4.7. Multi-vault sweep (Round 14): `vault-rotate --inventory <env.json> --all`

Refresh EVERY due vault in one operator action:

```bash
cargo run -p qsv-cli -- vault-rotate --inventory env.json --all --state-dir .
```

Behavior rules (pinned by a live e2e):

- **Classification first:** when a rotation-state v2 record is NEWER than the inventory row, the RECORD wins (`stale row: fix the inventory` warning) — the sweep never silently rewrites the operator's file.
- **ONE coin, ONE refresh per sweep:** every row resolves to the same demo vault address; the first successful rotation renews the coin's heartbeat and every remaining DUE id is recorded under the SAME tip/txid (the byte-identical refresh is never re-broadcast — a duplicate ceremony would fabricate a record from a mempool no-op).
- **Idempotent re-run:** re-running the sweep immediately is safe — refreshed rows classify as healthy at their state-recorded baseline; nothing double-spends.
- **Single-vault options (`--vault-id/--last-refresh-block/--heir/--no-broadcast`) with `--all` exit 2** — a sweep must not silently apply a single-vault option to one row.

### 4.8. Per-vault metrics (Round 14): Prometheus label rows

The `GET /metrics` scrape now also breaks every gate outcome down PER REQUESTING vault (rows in BTreeMap order — deterministic for a given history): `qsv_cosigner_refused_by_vault_total{vault="<id>"} <n>` (which vault consumed which refusal) and `qsv_cosigner_alarm_refused_by_vault_total{vault="<id>"} <n>` (which vault's freeze produced how many refusals). The UNLABELED totals are unchanged: `accepted + refused = requests_total` still closes exactly in every scrape.

### 4.9. Bridge TLS (Round 14): `--tls-cert/--tls-key`

```bash
# Dev loop: TLS is optional on loopback but available — a regtest drill
# runs the exact production plumbing:
cargo run -p qsv-cli -- cosigner-bridge --listen 127.0.0.1:3334 \
  --tls-cert cert.pem --tls-key key.pem
# Any non-loopback bind REQUIRES TLS: booting without it exits 1 with
# "plaintext co-signer transport outside loopback is forbidden".
```

Tunnel scope: the frame ceremony (sign request/response), the `GET /metrics` scrape AND refusal frames all live INSIDE the TLS record. A plaintext client against a TLS port cannot pass the handshake (it never sees a cleartext protocol frame); the accept loop is thread-per-connection (a silent or hostile client cannot stall the whole service). Production transports are unchanged: Nitro = vsock, TDX = operator-owned chain.

### 4.10. Mempool policy constants (Round 14): live `testmempoolaccept` e2e

The code-level claims are now cross-checked by the node's own dry-run judge (`tests/mempool_policy.rs`, real bitcoind v28.2):

- **RBF opt-in:** the refresh template carries `Sequence::ENABLE_RBF_NO_LOCKTIME` on every input — the heartbeat stays REPLACEABLE on chain.
- **BIP-125 asymmetry (chain proof):** a higher-fee replacement of a NON-signalling original is REFUSED; a signalling original is replaceable by a higher fee and protected against a lower-fee swap (rule 4) — the chain-level reason the sweep must never lower the fee.
- **No-dust:** every refresh output clears the 330-sat P2TR dust floor.
- **Operator feerate arithmetic:** `fee_sat / tx_vbytes` is verified on the template AND on the node-reported signed transaction.

### 4.11. Sweep co-signer gate (Round 15): `--cosigner-all`

Put the multi-vault sweep behind the LIVE bridge — a frozen vault must not take the fleet down:

```bash
# The gate asks about EVERY due vault FIRST: a frozen vault (watchtower
# alarm) is skipped with an explicit report line, the REST of the fleet
# refreshes (exit 0). An UNANSWERABLE gate fails the sweep closed (exit 1,
# no ceremony started) — a silent gate is never a green light.
cargo run -p qsv-cli -- vault-rotate --inventory env.json --all \
  --cosigner-all 127.0.0.1:3334 --state-dir .
```

- **Frozen-skip report:** a `FROZEN (watchtower alarm) — skipping` line, a `N skipped (frozen)` summary and `FROZEN[vault-id]: clear the watchtower alarm, then re-run the sweep`. The frozen id is NEVER written into the rotation state — its alarm survives until the operator clears it.
- **Healthy vaults sign through the SAME gate:** the refresh's second signature is requested from the same live bridge and verified under the pinned enclave key (e2e proof: the frozen vault's ceremony artifact dir is never CREATED).
- **Usage:** `--cosigner-all` requires `--all`; it conflicts with the plain `--cosigner` (exit 2). The single-vault `--cosigner` behavior is unchanged.
- **mTLS gate (Round 16):** the sweep can talk MUTUAL TLS to the bridge — `--cosigner-all-cert/--cosigner-all-key` (client identity) + `--cosigner-all-ca` (the CA pinning the bridge server). A wrong-CA client identity fails the gate closed (exit 1, no ceremony started); the pinned identity carries BOTH the gate probes and the rotation signature requests through the same encrypted channel (the production transport path closes end to end). A partial material set is exit 2.

### 4.12. Bridge mTLS (Round 15): `--tls-client-ca`

```bash
# Server certificate + CLIENT-certificate requirement: the handshake
# itself refuses any client that does not chain to the CA — an anonymous
# client can NEVER complete a session (no gate, no mirror, no /metrics).
cargo run -p qsv-cli -- cosigner-bridge --listen 127.0.0.1:3334 \
  --tls-cert cert.pem --tls-key key.pem --tls-client-ca client-ca.pem
```

- **Enforced at the transport layer:** the check lives INSIDE the handshake (WebPkiClientVerifier) — not a post-handshake string test. The audit surface reports the flag via `requires_client_auth()`.
- **Client half:** `client_identity(cert.pem, key.pem)` + `request_signature_mtls` — the pinned operator identity releases the SAME deterministic signature and scrapes `/metrics` through the same tunnel.
- **Usage:** `--tls-client-ca` without the `--tls-cert/--tls-key` pair is exit 2.

### 4.13. Serve-latency histogram (Round 15): Prometheus `histogram`

The `GET /metrics` scrape now exposes a REAL histogram under `qsv_cosigner_serve_latency_us`: fixed upper bounds `1ms · 10ms · 100ms · 500ms · 1s · 2s` + `+Inf`, CUMULATIVE bucket counts, `_bucket{le="…"}` rows + `_sum` + `_count`. The legacy `qsv_cosigner_serve_latency_us_sum` counter row is KEPT (existing dashboards keep working; the mean is still `sum/count`). The buckets are a crate-level contract: never reordered at runtime — scrape diffs stay comparable across restarts. A scrape (`GET /metrics`) touches NO bucket: observing is not signing.

### 4.14. Sweep dry-run (Round 16): `--dry-run`

```bash
# Classify + preview WITHOUT running any ceremony:
cargo run -p qsv-cli -- vault-rotate --inventory env.json --all --state-dir . --dry-run
```

- **Report:** every row is classified DUE/healthy/stale (rotation-state v2 = chain truth, same as the live sweep); with a `--cosigner-all` gate attached, frozen vaults are marked FROZEN too. The first due vault is named `would rotate (broadcast refresh)`, the rest `would record (shared coin, no re-broadcast)`.
- **Side-effect contract:** a dry run exits 0, writes NO rotation state and broadcasts NOTHING (e2e: the mempool snapshot is unchanged) — the real sweep succeeds right after over the same inventory.
- **Usage:** `--dry-run` requires `--all` (exit 2 otherwise).

### 4.15. Bridge rate limit (Round 16): `--rate-limit <capacity>:<refill>`

```bash
# Per-vault token bucket: 2-request burst, zero refill (drill value).
# A flood from ONE vault cannot consume ANOTHER vault's budget.
cargo run -p qsv-cli -- cosigner-bridge --listen 127.0.0.1:3334 \
  --state-dir . --rate-limit 2:0
```

- **Deterministic refusal:** an exhausted vault is refused IMMEDIATELY with `rate limited: too many requests for this vault (token bucket)` (never stalled); a provisioned sibling keeps signing from its own bucket.
- **/metrics visibility:** `qsv_cosigner_rate_limited_total` plus per-vault `qsv_cosigner_rate_limited_by_vault_total{vault="<id>"}` rows (BTreeMap order).
- **Default:** the limiter is ARMED but effectively unlimited (60 burst, 30/min refill); `RateLimitPolicy::validate` refuses a zero/negative capacity (fail-closed — the previous policy stays in place).
- **Usage error:** a malformed spec (no `:`) or a non-numeric field is exit 2.

### 4.16. Installer bake (Round 17): TLS + rate-limit flags go into ExecStart

```bash
# The generated unit now bakes the transport + budget policy too:
cargo run -p qsv-cli -- cosigner-bridge-install \
    --listen 0.0.0.0:3334 --state-dir /var/lib/qsv --unit-dir /etc/systemd/system \
    --tls-cert /etc/qsv/bridge.pem --tls-key /etc/qsv/bridge.key \
    --tls-client-ca /etc/qsv/clients-ca.pem --rate-limit 2:0
```

- **Single source (install-what-you-print):** `ExecStart` carries EVERY previewed flag byte-for-byte — TLS paths are `canonicalize`d to ABSOLUTE paths, `--rate-limit` is included. The unit boots with the SAME transport/budget policy the operator previewed.
- **Read-back verification:** after the units are written to disk they are re-read: the body must be byte-identical AND every baked flag must appear verbatim in the on-disk `ExecStart=` line — otherwise exit 1 (no `· N baked flag(s)` confirmation, unit never goes live).
- **Fail-closed budget:** a malformed `--rate-limit` spec (a `2` without `:`) exits 1 BEFORE writing any file (no policy, no bridge; the error carries the `rate-limit` word).
- **Round 20 — never generate a unit that cannot boot:** the generator runs the SAME gates the bridge boot runs (transport + scrape policy) BEFORE writing anything: an off-loopback bind without TLS material or without `--metrics-token` is refused (`transport policy` / `scrape policy` error) and no file is written — a unit that could never start is worse than no unit (systemd would restart-fail forever).

### 4.17. Per-vault accepted rows (Round 17): `qsv_cosigner_accepted_by_vault_total`

- **What:** `/metrics` now counts per-vault ACCEPTS, not only refusals: `qsv_cosigner_accepted_by_vault_total{vault="<id>"} <n>` (one HELP/TYPE block, BTreeMap order — the exposition is deterministic).
- **Visibility:** every seen vault gets a row (explicit zero included); Σ the per-vault accepted rows equals `qsv_cosigner_accepted_total` on one scrape (the same count, two cuts — scraping never moves a counter).
- **Disambiguation:** which vault CONSUMED the co-signer is now readable from metrics (accepted + refused = that vault's requests that reached the gate); alarm-freeze refusals stay on separate `qsv_cosigner_alarm_refused_by_vault_total` rows.

### 4.18. Graceful shutdown (Round 17): SIGTERM → drain → exit 0

```bash
systemctl stop qsv-cosigner-bridge   # SIGTERM → stop accepting, drain, exit 0
```

- **Contract:** SIGTERM/SIGINT flips a process-global flag through an async-signal-safe `signal(2)` handler (one atomic store + re-arm); the accept loops poll the flag every 10 ms — because the listener is NONBLOCKING, the signal is observed without waiting for the NEXT connection (a blocking `accept()` would swallow it).
- **Order:** accepting STOPS first (the listener is dropped — the bind releases immediately and the next replica can take it), then accepted connections are DRAINED (the TLS loop joins its workers: every request accepted before the signal is served to completion, no torn frame). The return path is `Ok(())` → exit 0: systemd's `Restart=on-failure` has nothing to restart.
- **Drill (e2e):** a bridge that receives a real SIGTERM exits 0 and the port is immediately re-bindable. Rust std `Child::kill()` is SIGKILL and skips the drain — the drill raises TERM itself.

### 4.19. Frame timeout (Round 18): slowloris, bounded by `--frame-timeout-ms`

```bash
# A silent peer may hold the bridge for at most 300 ms (drill value; default 10000):
cargo run -p qsv-cli -- cosigner-bridge --listen 127.0.0.1:3334 \
  --state-dir . --frame-timeout-ms 300
```

- **Where it lands:** a read+write deadline on EVERY accepted socket — the 16-byte HTTP probe, the head read, the frame ceremony and (through the inner TcpStream) the TLS HANDSHAKE all run on the same clock. A silent peer delays the serial loop for at most ONE timeout; a DRIBBLING peer (half a length prefix) gets its deterministic refusal and is closed on the same schedule.
- **The drain clock:** the graceful shutdown's worker join runs on the same deadline — a half-handshaken client can NEVER extend the SIGTERM drain indefinitely (the Round 17 contract is now structurally built). A connection that never finished the handshake gets NO close_notify flush (it would drive a second bounded read and make the drain 2×).
- **0 = off:** `--frame-timeout-ms 0` removes the deadline; the library default is 10 s (`ServePolicy::default`).
- **Drill (e2e):** `bridge_bounds_stalling_peers_and_keeps_serving` — with a silent AND a dribbling peer the service keeps releasing signatures and both peers are hung up by the deadline.

### 4.20. Metrics scrape token (Round 18): `--metrics-token`

```bash
cargo run -p qsv-cli -- cosigner-bridge --listen 127.0.0.1:3334 \
  --state-dir . --metrics-token s3cr3t-scrape
```

- **Contract:** when armed, `/metrics` requires the `X-QSV-Metrics-Token: <tok>` header; missing/wrong token = **401**, every denial counted in `qsv_cosigner_metrics_denied_total` (the operator sees scrape attempts). Constant-time compare; without a token the scrape stays open (loopback dev default).
- **The signing path is untouched:** the token closes only the observability endpoint — the frame ceremony (signature/refusal) is token-independent.
- **Baked into units:** `cosigner-bridge-install --metrics-token` writes the flag VERBATIM into ExecStart and verifies it by reading the unit back; a token with whitespace exits 1 BEFORE any file is written (it would break the ExecStart word split).
- **Drill (e2e):** `bridge_metrics_scrape_requires_the_token` — 401/401/200 with denial counter 2, and signing still releases after.
- **Round 20 — the token is MANDATORY off loopback:** the counters name every vault and expose which one the watchtower froze, so an open scrape is a status oracle that maps the estate for free. Binding `0.0.0.0`, `:port` or any external address therefore REQUIRES `--metrics-token` at boot: without it the bridge exits 1 before the bind is even opened (`qsv_cosigner::tls::require_metrics_token_off_loopback`). An empty token (`--metrics-token ""`) counts as NOT armed and never opens the gate. The loopback dev convenience is unchanged.

### 4.21. Rolling restart (Round 18): handover while the old replica drains (e2e)

```bash
systemctl stop qsv-cosigner-bridge   # old: stop accepting, release the bind, drain
systemctl start qsv-cosigner-bridge  # new: takes the port over immediately
```

- **Order (proven):** SIGTERM → the accept loop drops the listener on its 10 ms tick (THE BIND RELEASES AT ONCE) → workers keep draining on the frame-timeout clock → **the NEW replica takes the port and starts signing IN BETWEEN** — the old process is still alive (draining) and exits 0 when the drain finishes.
- **No downtime window:** zero-downtime handover needs no SO_REUSEPORT tricks — the new replica binds as soon as the old listener is gone, and the drain runs PARALLEL to serving.
- **Drill (e2e):** `bridge_rolling_restart_serves_while_the_old_replica_drains` — the new replica releases a signature mid-drain, the old process exits 0 after 1× frame timeout, the new service is unaffected.

### 4.22. Connection cap (Round 19): `--max-inflight <n>`

```bash
cargo run -p qsv-cli -- cosigner-bridge --listen 127.0.0.1:3334 \
  --state-dir . --tls-cert cert.pem --tls-key key.pem --max-inflight 64
```

- **The problem:** TLS mode spawns one thread per connection — unbounded accepts mean a thread/fd explosion under a flood.
- **Contract:** when the cap is REACHED a connection is accepted and immediately CLOSED (the peer sees a clean EOF); every denial counts in `qsv_cosigner_capacity_refused_total`. Finished workers leave the ledger on each accept (the slot frees by itself) and the peer holding a slot runs on `--frame-timeout-ms` — capacity refusals are never permanent.
- **Default:** 64 concurrent workers; `0` = unlimited. The serial (plain) loop is one-connection-at-a-time by construction — the cap bounds the TLS mode where threads multiply.
- **Drill (e2e):** `bridge_caps_inflight_workers_and_recovers_after_the_timeout` — with cap 1 a silent peer holds the slot, the second connection gets EOF within 2 s (NOT the 3 s frame timeout), and once the peer times out the service resumes signing on its own with the denials visible in /metrics.

### 4.23. Bridge health record (Round 20): `bridge-health.json`

```bash
cargo run -p qsv-cli -- cosigner-bridge --listen 127.0.0.1:3334 --state-dir /var/lib/qsv
cat /var/lib/qsv/bridge-health.json   # who, where, under which policy
```

- **The problem:** `systemctl is-active` knows only the unit, `ss -ltnp` only the socket. When a signing queue backs up the question is different: **which process** owns the port, from **which bind**, serving **which vaults**, with the mirror at **which tip**?
- **Contract:** the record is written AFTER the bind succeeds and the TLS material is verified, BEFORE the accept loop starts — temp file + rename (atomic), so a half-written record is never visible. On a graceful stop (SIGTERM/SIGINT → drain) the file is **removed**: presence means "up", and a leftover claim would be a lie.
- **The one thing that is not cleaned up:** an unclean death (SIGKILL/OOM) leaves the record behind with a dead pid — `qsv-cli doctor` reports that as a **FAIL** (a stale record must never read as "serving"). No `.tmp` debris is ever left.
- **What is never stored:** the token **value** never touches disk; only the `metrics_token_armed` bit is recorded. Fields: `pid`, `listen`, `transport` (plain/tls/mtls), `vaults[]`, `started_at_unix`, `watchtower_tip`, `metrics_token_armed`, `max_inflight`, `frame_timeout_ms`.
- **Drill (e2e + unit):** `bridge_publishes_a_health_record_and_clears_it_only_on_a_graceful_stop` — publication and fields verified, SIGKILL leaves the record (pid dead), SIGTERM removes it, and the state dir is left holding only `watchtower-state.json`.

### 4.24. Operator doctor (Round 20): `qsv-cli doctor`

```bash
qsv-cli doctor --datadir ~/.bitcoin --network regtest \
  --state-dir /var/lib/qsv --rpc-port 18443 --metrics-token s3cr3t-scrape
```

- **One command, five layers:** (1) node cookie RPC + tip, (2) `watchtower-state.json` readability + frozen-vault count, (3) **mirror lag** — a tip delta above `--max-mirror-lag` (default 6) warns, (4) the health record + pid liveness, (5) a live `/metrics` scrape.
- **The rule:** only a **FAIL** exits 1, so the command works as a scripted health gate; a **WARN** is advisory (the estate still signs). A red table that cries wolf is a table operators learn to ignore.
- **The mirrors are the point:** a tip delta is a security gap (the bridge freezes on the verdicts IN THE FILE, so it protects against a stale view of the chain), and a 401 is a **FAIL** — the alert rules would be blind.
- **Read-only:** the doctor never signs, deletes or edits the record it inspects. Diagnosis, not intervention.
- **Drill (e2e):** `doctor_answers_each_layer_honestly_and_fails_only_on_required_checks` — with a live bitcoind and a live bridge: green (0 FAIL/0 WARN) → clean stop (2 WARN, exit 0) → DEAD pid (FAIL) → scrape without the token (401 → FAIL, green again with it) → malformed state (FAIL) → 20-block mirror lag (WARN).

### 4.25. Alert rules and dashboard (Round 20): Prometheus + Grafana

```bash
install -m644 scripts/prometheus_alerts.yml /etc/prometheus/rules/qsv-cosigner.rules.yml
# Grafana → Dashboards → Import → scripts/grafana_dashboard.json
bash scripts/monitoring_drill.sh   # also runs in CI (ci.yml → monitoring-drill)
```

- **The rule file** carries 9 alerts: bridge unreachable, blind scrape, alarm freeze, per-vault freeze, refusal dominance, capacity saturation, rate-limit storm, p99 latency, idle bridge — each bound to a counter family that really exists.
- **The silent-death trap is closed:** Prometheus happily accepts a rule on a series the target never exports. So (a) every metric name is cross-checked against the `Metrics::METRIC_FAMILIES` contract (chained to a live render by a unit test in `server.rs`), (b) `scripts/monitoring_drill.sh` loads the YAML/JSON and re-checks coverage with python3, and (c) every rule must carry `alert/expr/for/severity/summary/description`.
- **The Grafana dashboard** is 9 panels on the same contract: lifetime totals, released vs refused, freezes (total + per vault), per-vault refusals/releases, latency percentiles, load shedding (capacity/rate/scrape), target health.
- **Coverage is a contract:** the rules + panels together MUST cover every safety-critical counter — a freeze nobody can see is a fail-closed path gone silent.

### 4.26. systemd Type=notify and watchdog (Round 21): a proven boot

```bash
qsv-cli cosigner-bridge-install --state-dir /var/lib/qsv --metrics-token-file /etc/qsv/scrape.token
# generated unit: Type=notify · NotifyAccess=main · WatchdogSec=30
```

- **The problem:** `Type=process`/`simple` scores the boot at fork time — systemd declares "active" while the bind, the TLS material and the health record may still be missing; a broken boot hides until `TimeoutStartSec`, and a wedged process reads as "running" forever. The gate becomes theater.
- **Contract — three messages, only when `NOTIFY_SOCKET` exists:** without the variable the bridge behaves exactly as before (byte-for-byte identical in dev, tests and bare metal):
  - **READY=1** — sent ONLY after the bind, the TLS material and the health record are real: the supervisor's start clock runs on PROOF, not on fork.
  - **WATCHDOG=1** — pinged at half of `WATCHDOG_USEC` (the sd_notify rule), but the ping goes out only while the accept loop's progress stamp still TICKS. If the loop wedges the pings deliberately go silent — silence is the restart signal; liveness-blind pings would call a wedged bridge healthy. The stall limit is `--frame-timeout-ms` plus one ping period.
  - **STOPPING=1** — sent on the drain edge, as soon as the drain BEGINS; the rest of the stop belongs to `TimeoutStopSec`.
- **The unit:** `cosigner-bridge-install` writes `Type=notify` + `NotifyAccess=main` + `WatchdogSec=30` and verifies the unit by reading it back; a missing `WatchdogSec` or one below 1 s is an ERROR (`Type=notify without a watchdog is theater`) — the verify gate parses the period and makes it mandatory, and the verified line reports it.
- **Drill:** `bridge_reports_ready_watchdog_and_stopping_to_notify_socket` (path socket: READY → WATCHDOG → SIGTERM → STOPPING → exit 0) plus the 6 unit tests in `notify.rs` (path/abstract socket parsing, the half-period rule, deliberate silence when the loop stops ticking).

### 4.27. Scrape token from a file (Round 21): `--metrics-token-file`

```bash
umask 077 && printf '%s\n' "s3cr3t-scrape" > /etc/qsv/scrape.token   # one line, 600
qsv-cli cosigner-bridge --listen 127.0.0.1:3334 --state-dir . \
  --metrics-token-file /etc/qsv/scrape.token
```

- **The problem:** a `--metrics-token` value lives in argv — `/proc/<pid>/cmdline` is world-readable, and `systemctl show` prints the unit's command line too. A secret on the command line is not a secret.
- **Contract:** the token is read from a file, and only a tight file opens the gate: any group/other bit = **exit 1** (`group/other can read it (mode 0644) — chmod 600 it`, before the bind); a second line = **exit 1** (`exactly ONE line expected` — a paste accident); `--metrics-token` together with `--metrics-token-file` = **exit 2** (the operator must decide — the two-sources contract).
- **The value never enters argv:** the bridge and the unit carry only the file PATH (no `ps`/cmdline leak); the gate keeps its constant-time compare — 401/200, the denial counter and the signing path are byte-for-byte unchanged.
- **Baked into units:** the install flag writes the PATH verbatim into ExecStart and reads the file back to verify with the REAL token at boot; if the VALUE leaks into the unit (e.g. `--metrics-token-file s3cr3t`) nothing is written and it fails.
- **Doctor:** `doctor --metrics-token-file` exercises the scrape layer from the file as well.
- **Drill:** `bridge_scrape_token_file_arms_the_gate_without_leaking_argv` (no value in cmdline, gate armed, 401/200, signing untouched), `bridge_refuses_a_loose_token_file_and_double_token_sources`, `cosigner_bridge_install_bakes_the_token_file_path_never_the_value`.

### 4.28. Drain deadline (Round 21): `--drain-timeout-ms`

```bash
qsv-cli cosigner-bridge --listen 127.0.0.1:3334 --state-dir . \
  --frame-timeout-ms 0 --drain-timeout-ms 5000
```

- **The problem:** `--frame-timeout-ms 0` disables the only clock — a peer that goes quiet mid-frame parks the connection forever, so the SIGTERM drain never returns, systemd SIGKILLs at `TimeoutStopSec`, and `bridge-health.json` is left claiming "serving" (the §4.23 trap, now on the drain path).
- **Contract:** `--drain-timeout-ms N` (default **0** = unbounded, the classic behavior) starts counting ONLY at the stop edge — the bound belongs to the drain, not to the service lifetime. When the deadline passes with the drain unfinished: (1) stderr gets `drain deadline of N ms exceeded — abandoning in-flight work, clearing the health record, exit 0`, (2) the health record is removed, (3) **exit 0** — an operator-initiated stop stays a stop, so `Restart=on-failure` has nothing to restart.
- **The normal path always wins the race:** if the drain finishes in time the FIRST thing after serve returns is the `drain_done` set, and the counter bows out on its 10 ms tick.
- **Drill:** `bridge_drain_deadline_ends_a_parked_drain` — `--frame-timeout-ms 0 --drain-timeout-ms 700`, a peer that writes half a frame then goes quiet → SIGTERM → exit 0 within 500 ms–5 s, message on stderr, record cleared, process exits clean.

### 4.29. Capacity bench (Round 21): `qsv-cli bench`

```bash
qsv-cli bench                    # 100 iterations per operation
qsv-cli bench --iterations 500   # more rounds amortize the clock
```

- **What it measures:** every component the two-key ceremony is built from, one honest `ops/s` + `µs/op` row each: ML-DSA-65 keygen/sign/verify, BIP-340 sign/verify, the enclave gate (PQC verify → enclave keypair → BIP-340 sign → self-verify — the bridge's EXACT per-request path) and the health-record write+read loop (atomic temp+rename).
- **A report, never a gate:** always exit 0 — a busy box must not fail a capacity measurement; the floors live in the test suite (`tests/bench.rs` pulls all 7 rows down to a catastrophic-regression floor an order of magnitude below the measured numbers), and `--iterations 0` is a meaningless division → exit 2.
- **Honesty:** the work is wrapped in `std::hint::black_box` (so the optimizer cannot delete what is being measured) and the setup (seed, signature, keypair) is built OUTSIDE the timed loops — the bench measures the op, never its surroundings. The slowest row rules the estate: that is the non-scaling link.
- **Drill:** `bench_reports_every_operation_above_floor` (7/7 rows, parseable pair) + `bench_refuses_a_zero_iteration_run_as_usage_error`.

### 4.30. Live token rotation (Round 22): `systemctl reload`

```bash
umask 077 && printf '%s\n' "new-token" > /etc/qsv/scrape.token   # still one line, 600
systemctl reload qsv-cosigner-bridge                                # SIGHUP → re-read the file
curl -s -H 'X-QSV-Metrics-Token: new-token' localhost:3334/metrics   # valid at once
```

- **The problem:** scrape secrets expire and should — but rotating one meant a restart: drain + boot, for a ceremony where no request may be left unanswered, an unnecessary risk and a SIGNING GAP. If rotation is "something we do next maintenance window", it does not get done, and a stale secret is worse than none.
- **Contract:** a bridge armed via `--metrics-token-file` re-reads the file the moment it sees **SIGHUP** (the same chmod-600 + one-line gates apply): if valid, the `ScrapeToken` swaps IN PLACE — the gate never opens, the signing path never observes the swap, the pid does not move (this is NOT a restart). If invalid (loosened mode, second line, empty file) the PREVIOUS token stays and stderr names why — failing to rotate must never fail open.
- **Signal hygiene:** the handler is installed on every boot (the default SIGHUP disposition KILLS the process — a stray HUP must never take the bridge down); the file read + swap run on a polling thread (I/O inside a signal handler is a deadlock). Armed via `--metrics-token` (no file) the HUP is absorbed and reported as "nothing to re-read".
- **Unit side:** `cosigner-bridge-install` writes AND verifies `ExecReload=/bin/kill -HUP $MAINPID` — `systemctl reload` is therefore never a silent no-op, and the verify gate looks for that exact line.
- **Drill:** `bridge_rotates_the_scrape_token_on_sighup_without_a_restart` — v1 works → rewrite to v2 + HUP → within 5 s v2 answers 200 / v1 gets 401, pid and `metrics_token_armed` unchanged, signing untouched; then the file loosens to 644 and another HUP keeps the PREVIOUS token and never opens the gate. Plus the `ScrapeToken` unit test (empty rotation refused, a disarmed gate cannot be armed at runtime) and the install test's `ExecReload` line.

### 4.31. The clocks baked into the unit (Round 22): `--frame-timeout-ms` / `--drain-timeout-ms`

```bash
qsv-cli cosigner-bridge-install --state-dir /var/lib/qsv \
  --frame-timeout-ms 15000 --drain-timeout-ms 5000 --metrics-token-file /etc/qsv/scrape.token
grep ExecStart /etc/systemd/system/qsv-cosigner-bridge.service   # the clocks are written verbatim
```

- **The problem:** Round 19's slowloris bound (`--frame-timeout-ms`) and Round 21's drain deadline (`--drain-timeout-ms`) were NOT baked into the generated unit — production ran whatever the binary's defaults happened to be. `systemctl show` must state what the service ACTUALLY does, not what the code defaults to.
- **Contract:** the installer now ALWAYS writes both clocks into ExecStart (defaults included — the unit declares its own timing), and verification re-reads the unit demanding `--frame-timeout-ms N` / `--drain-timeout-ms N` word for word. The flags share the bridge's vocabulary: 0 = unbounded.
- **Watchdog harmony:** `WatchdogSec=30` stays safe with any frame timeout: the bridge keeps pinging through `frame_timeout + ping period` of a legitimately quiet accept loop (a slow stream is healthy), and only after it deliberately goes silent does systemd's `WatchdogSec` run out — no early restarts, no late ones either.
- **Drill:** `cosigner_bridge_install_bakes_tls_and_rate_limit_flags_into_execstart` now also runs with `--frame-timeout-ms 2500` and `--drain-timeout-ms 4000` and demands both in ExecStart (the banner's "baked flag(s)" count rose to 7).

### 4.32. Machine-readable diagnosis (Round 22): `qsv-cli doctor --json`

```bash
qsv-cli doctor --datadir ~/.bitcoin --network regtest --state-dir /var/lib/qsv --json | jq '.fail, .exit_code'
# 0
# 0   → the gate passed; .checks[] carries each layer's name/status/detail
```

- **Contract:** the same five layers, the same exit contract (only FAIL exits 1) — but stdout is now **ONE JSON document**: `schema: qsv-doctor/v1`, `total/fail/warn`, `exit_code` and `checks[]` (`name`, `status: ok|warn|fail`, `detail`). No banner, no table, no "All operations completed": `| jq` works unfiltered.
- **Why:** a script gating on the doctor must not match human lines — when the wording changes, the gate either passes something it should not (security) or cries red until alarms are learned to be ignored. Document + exit code = two independent proofs, and they cannot disagree.
- **Failure shape is unchanged:** on FAIL the document is STILL printed to stdout, the reason goes to stderr (`error: N required check(s) failed`), exit 1 — a broken estate still answers in machine form.
- **Drill:** two new steps in `doctor_answers_each_layer_honestly_and_fails_only_on_required_checks`: the green state runs `--json` (parses, `fail=0`, `exit_code=0`, 5 checks, status vocabulary) and the dead-pid state runs `--json` (rc 1, `fail=2`, `exit_code=1`, reason on stderr).

### 4.33. Machine-readable capacity report (Round 22): `qsv-cli bench --json`

```bash
qsv-cli bench --iterations 500 --json > capacity-$(date +%F).json
jq '.rows[] | select(.op == "enclave gate (pqc→bip340)")' capacity-*.json
```

- **Contract:** `schema: qsv-bench/v1`, `iterations` and `rows[]` (`op`, `ops_per_s`, `us_per_op`) — the SAME numbers as the human table (one `BenchRow` measurement, two presentations). It stores as a capacity baseline: last release vs this one is one `jq` diff away.
- **Still a report:** always exit 0; `--iterations 0` remains exit 2 and prints NO document (a partial document is a wrong baseline). Stdout carries the document alone — banner and footer are suppressed in `--json` mode.
- **Self-consistency is tested too:** per row `ops_per_s × us_per_op ≈ 1e6` (±2%) — if the two numbers stop being two faces of one measurement, the document is lying.
- **Drill:** `bench_json_report_carries_the_same_seven_operations` (7/7 rows, same order and labels, consistency, no prose) + `bench_json_still_refuses_a_zero_iteration_run`.

### 4.34. Watchdog silence report (Round 22): say WHY you went quiet

```text
# journalctl -u qsv-cosigner-bridge
watchdog: accept loop silent for 75012 ms (stall limit 75000 ms) — yielding pings to systemd; a restart is the recovery if it does not resume
```

- **The gap:** Round 21's watchdog deliberately goes SILENT (silence is the restart signal) — correct behavior, but all journald then shows is a process death: "why was I restarted?" has no answer. Silence is evidence, but it is not a witness.
- **Contract:** at the exact moment the pings STOP (the progress stamp passes `stall_limit`), the watchdog thread writes the reason ONCE per episode: the freeze's age and the limit. If the loop recovers on its own (a slow stream finishes) the pings resume and the episode closes; if the same bridge freezes again, a second report follows.
- **What it is NOT:** a witness, not a metric — it touches no counter, no health record and no exit code; the only behavioral change is one stderr line BEFORE the silence.
- **Drill:** the two `notify.rs` tests — a ticking loop produces NO report (`watchdog_pings_only_while_the_loop_still_ticks`), a stale stamp produces exactly ONE report containing "accept loop silent" (`watchdog_goes_silent_when_the_progress_stamp_is_stale`).

### 4.35. The capacity cap baked into the unit (Round 23): `--max-inflight`

```bash
qsv-cli cosigner-bridge-install --state-dir /var/lib/qsv --max-inflight 128
grep ExecStart /etc/systemd/system/qsv-cosigner-bridge.service   # --max-inflight 128 is in there
```

- **The gap:** the concurrent worker cap lived in a code default (64); how many refreshes the operator actually sized for was never written into the generated unit. `systemctl show` must report the setting that actually runs, not the binary's default.
- **Contract:** install always writes the flag — defaults included (the unit states its own cap) — and verification looks for the exact `--max-inflight N` syntax in the ExecStart it reads back (missing = error). `0` means unlimited, the same vocabulary the bridge uses.
- **Why it sits with the clocks:** the same reason as `--frame-timeout-ms` / `--drain-timeout-ms` — the only path to production must make the operator's decision visible in production; otherwise "64" is an accident and "128" an assumption.
- **Drill:** the install test now runs `--frame-timeout-ms 2500 --drain-timeout-ms 4000 --max-inflight 32`, looks for all three in ExecStart and demands the verification banner's **"8 baked flag(s)"** count (4/4 green).

### 4.36. The missed-rotation counter (Round 23): `qsv_cosigner_rotate_denied_total` + `QsvCosignerTokenRotationStalled`

```text
# curl -H "X-QSV-Metrics-Token: $TOK" http://127.0.0.1:3334/metrics | grep rotate_denied
qsv_cosigner_rotate_denied_total 3
```

- **The gap:** Round 22 made rotation live, but "the RELOAD DID NOTHING" state lived only on stderr. An operator runs `systemctl reload`, hands Prometheus the new token, and scraping silently continues with the OLD one — nothing breaks and nothing alerts. Exactly during an incident, the one move you need cannot be made.
- **Contract:** every refused rotation (Round 22's two refusals: a gate that never booted armed, an empty secret) AND every reload that could not even reach a rotation (gate armed but no file · file yields no usable token) increments the counter. A rotation that WORKED is never counted, and neither is a stray HUP on a disarmed dev bridge — there is no rotation to miss.
- **One source of truth:** the counter lives INSIDE `ScrapeToken`, and `main.rs` adopts that same `Arc` into the metrics field at boot. The number the alert reads and the number the gate counts cannot drift — two sources, two truths is not a thing.
- **Alert:** `QsvCosignerTokenRotationStalled` = `increase(qsv_cosigner_rotate_denied_total[15m]) > 0`, `for: 1m`, severity warning. Its story: "the previous token is still live while you believe a new one is in force", plus the fix (one line, 0600, reload again). A Grafana panel landed with it (increase over 15m).
- **Drill:** `rotation_refusals_are_counted_into_the_exposition` (counting + the shared `Arc` + a working rotation NOT counted + a stray HUP not counted) and the e2e `bridge_counts_a_reload_that_could_not_rotate`: SIGHUP on an argv-armed bridge and SIGHUP on an emptied file — both counted, and the gate never falls open.

### 4.37. Pre-reload readiness audit (Round 23): `doctor` → "scrape rotation"

```text
[ OK  ] scrape rotation   /etc/qsv/scrape.token is a valid token source — `systemctl reload` rotates in place
[ FAIL] scrape rotation   a reload would be REFUSED (…group/other can read it (mode 0644) — chmod 600 it) — the previous token stays live
[ WARN] scrape rotation   gate armed via --metrics-token: no file to re-read, so `systemctl reload` cannot rotate it …
```

- **The gap:** §4.36's alert says rotation STOPPED — afterwards. The question can be asked BEFORE the reload: is the file you are holding actually rotatable? The answer already existed in the bridge's own record; it just was not published.
- **Contract:** the bridge now writes the `--metrics-token-file` PATH into `metrics_token_file` on its health record (never the value — the record only ever carried "is it armed"). The doctor audits that path with the bridge's OWN `read_metrics_token_file` rules (0600, exactly one line, no whitespace): valid → OK · would be refused → FAIL ("a reload would be REFUSED") · no file on record while the gate is armed → WARN ("armed via argv — reload cannot rotate it") · gate never armed → OK ("no rotation to keep ready").
- **Readability:** the field is `#[serde(default)]` — a record written by an older build parses instead of reading as "stale". A missing field never manufactures a fake failure (here the fail-closed bias runs the other way: unknown is not red).
- **Drill:** `doctor_proves_whether_a_reload_could_rotate_the_scrape_token` reads all four states out of the `--json` document (OK · FAIL(0644) · WARN(argv) · OK(never armed)); no node needed — the record on disk is the only input.

### 4.38. The capacity GATE (Round 23): `qsv-cli bench --baseline`

```bash
qsv-cli bench --iterations 500 --json > capacity-base.json        # once, on a clean machine
qsv-cli bench --iterations 500 --baseline capacity-base.json       # every release: the CI gate
# exit 0 → "… within 25%" · exit 1 → "REGRESSION: enclave gate …" · exit 2 → the baseline is unusable
```

- **The gap:** `bench` was a REPORT — a dropping ops/s is visible only by eye, and "does this box have the capacity?" had no gate form; the floors lived in the test suite, not on the operator's hardware.
- **Contract:** `--baseline <a --json report>` plus `--baseline-tolerance-pct N` (default 25). If an operation lands below its baseline minus the tolerance, the table gets a `REGRESSION: <op>` line (baseline → measured, percent), stderr carries a `capacity regression` summary and the run **exits 1**; when nothing regresses, the `within 25%` line prints and the run exits 0. In `--json` mode the verdict travels inside the document (`baseline: {file, tolerance_pct, verdict, regressions[]}`).
- **A gate that cannot compare goes SILENT:** a missing file · unreadable or malformed JSON · a report that does not cover all seven operations · a tolerance outside `[0,100)` → **stdout stays COMPLETELY empty**, stderr names the `--baseline` flag as a usage error, **exit 2**. Printing a measurement and then saying "I can't use the baseline" would ship a wrong baseline.
- **Coverage rule:** a baseline must cover every operation in `BENCH_OPS` — a partial report is a partial gate that silently protects the operations it forgot.
- **Clean stdout:** a gate run prints no banner and no footer either; with `--baseline` the output is the measurement plus the verdict alone (a banner would itself suggest "the gate ran").
- **Drill:** `bench_baseline_gate_flags_regressions_and_refuses_bad_baselines` (100× too fast baseline → exit 1 with named rows, the JSON verdict, a 10,000× slower baseline → exit 0 and "within 25%") and `bench_baseline_gate_refuses_anything_it_cannot_compare_against` (four refusal shapes × empty stdout).
- **Scheduling noise does not break the gate:** the floor test (§4.29) judges the BETTER of two runs. The reasoning is one-sided — a loaded box can only make a measurement slower, never faster. The floors stay exactly where they are (a catastrophic regression, say a loop bound that grew by ten, misses both runs); only the sampling gets less fragile, so a suite that mines regtest blocks next door can no longer sink the gate.

### 4.39. Capacity evidence (Round 24): `qsv_cosigner_workers_active` / `_peak` / `_limit` + `qsv_cosigner_rotate_total`

```text
# curl -H "X-QSV-Metrics-Token: $TOK" http://127.0.0.1:3334/metrics | grep -E "workers|rotate"
qsv_cosigner_rotate_total 4
qsv_cosigner_workers_active 2
qsv_cosigner_workers_peak 11
qsv_cosigner_worker_limit 16
```

- **The gap:** `--max-inflight` was a number that lived ONLY in ExecStart. The one thing you could observe was `capacity_refused_total` once the cap was ALREADY being hit — there was no data to size a ceiling with, only data you could buy afterwards by refusing clients.
- **Contract:** three GAUGES (the first non-counter shapes in this exposition): `active` = TLS workers open right now, `peak` = high-water mark since boot (never falls), `limit` = the configured ceiling. The loop publishes its ledger every tick (a finished worker frees its own slot) and the peak uses `fetch_max`, so the "who was higher" race is irrelevant. The plain (serial) dev loop serves one connection at a time by construction: the cap is structurally unreachable there.
- **Alert:** `QsvCosignerWorkerSaturation` = `worker_limit > 0 and workers_peak > 0.8 × worker_limit` (`for: 5m`). The rule hardcodes no number — it READS the ceiling the operator actually configured. Nothing is being shed yet (the refusal counter is flat), but the next burst will be.
- **The positive side of rotation:** §4.36 counted refusals; "did my reload land?" had no answer. `qsv_cosigner_rotate_total` rides the same pair of `Arc`s — one landed swap, one increment. It is how the operator confirms Prometheus is scraping with the NEW secret.
- **Drill:** `rotation_refusals_are_counted_into_the_exposition` now also proves the success counter and all three gauges; the e2e `bridge_caps_inflight_workers_and_recovers_after_the_timeout` proves the published ceiling equals the configured `--max-inflight 1` and the peak marker is 1; `bridge_rotates_the_scrape_token_on_sighup_without_a_restart` states that a landed rotation leaves `rotate_total 1` and `rotate_denied_total 0`.

### 4.40. Sandbox reachability (Round 24): install audits the token file

```bash
qsv-cli cosigner-bridge-install --state-dir /var/lib/qsv --metrics-token-file ~/.secrets/scrape.token
# error: --metrics-token-file /home/<user>/.secrets/scrape.token: the unit runs with ProtectHome=yes,
#        so the SERVICE cannot read it (/home is made inaccessible) — move the file outside the
#        home trees (e.g. /etc/qsv/scrape.token, mode 600) and re-run
```

- **The problem:** the generated unit runs with `ProtectHome=yes` — `/home`, `/root` and `/run/user` are invisible to the service. Install read the file ITSELF (in the operator's context, outside the sandbox) and, finding it 0600 and single-line, wrote the unit anyway: a file the operator reads daily and the service can NEVER read. The bridge then learns it at 3 a.m. (boot failure) or, worse, looks healthy while rotating nothing.
- **Contract:** install checks that the canonicalized path does not sit under a `ProtectHome` tree (component-exact — `/rooted` is not `/root`). If it does: exit 1 before a single unit byte is written, with the reason and the fix. The file itself is never the objection — only its LOCATION.
- **Why at install time:** "install what you print, print what can run" would otherwise be a lie — a unit we believe boots, when we know it does not, must not be written.
- **Drill:** `install_refuses_a_token_file_the_unit_sandbox_cannot_read` stages a file under the REAL home tree (skipping on any other machine shape), proves the refusal, and then proves the SAME file outside the home tree installs cleanly (5/5 green).

### 4.41. Boot rehearsal (Round 24): `cosigner-bridge --dry-run`

```text
qsv-cli cosigner-bridge --listen 127.0.0.1:3334 --state-dir /var/lib/qsv \
  --vault-id bc1… --metrics-token-file /etc/qsv/scrape.token --max-inflight 32 --dry-run
#   verdict:      BOOT WOULD SUCCEED — nothing served, nothing published
#   scrape gate:  armed · reload source /etc/qsv/scrape.token (rotation-ready)
#   capacity:     32 in-flight worker(s) · frame timeout 10000 ms · drain deadline classic
```

- **The problem:** the answer to "would systemd start this right now?" used to be learned by starting it — a bind conflict, a broken PEM, an unreadable token file, all surfacing at the first REAL start, which is the most expensive moment to learn them.
- **Contract:** `--dry-run` runs every boot gate (token file contract, watchtower state, transport policy, TLS material, and the BIND ITSELF), prints the resulting policy and exits 0. Nothing below that line has a side effect worth rehearsing: no health record is written (it would lie — "up" with nothing serving), no `sd_notify`, no accept loop, no SIGHUP handler. Rehearsing the bind is deliberate: a busy port fails the rehearsal too.
- **Not a rubber stamp:** a broken gate stays broken — an unreadable watchtower state exits 1, a taken port exits 1, and `BOOT WOULD SUCCEED` is never printed over a failed gate.
- **Drill:** `bridge_dry_run_rehearses_the_boot_and_publishes_nothing` proves all three steps: the healthy path (exit 0, policy echoed, state dir left UNCHANGED, `liveness` Absent), the broken state (exit 1, no verdict), and the taken port (exit 1).

### 4.42. Honest serial ceiling (Round 25): the plain loop publishes `worker_limit 1` + the saturation guard

```text
# a single scrape from the plain (non-TLS) bridge:
qsv_cosigner_worker_limit 1
qsv_cosigner_workers_active 1      # this very scrape — the loop is serving it
qsv_cosigner_workers_peak 1
```

- **The problem:** the serial accept loop published no occupancy at all — a fresh `Metrics` renders `worker_limit 0`, which reads "unlimited", a lie for a loop that serves one connection at a time. The saturation rule guarded on `worker_limit > 0`, so had the ceiling been published honestly (1), an IDLE serial bridge would have paged five minutes after its first request.
- **Contract:** the serial loop publishes its ceiling as **1** at boot (only the TRUTH) and books every connection into the `active` ledger — its own scrape included, exactly as the TLS loop counts its scrape worker. The peak can never exceed 1.
- **Rule guard:** `QsvCosignerWorkerSaturation` now starts with `worker_limit > 1`. A ceiling of one cannot be "80% saturated" — that loop's overload signal is work (the latency histogram's tail), not thread count. The TLS rule is unchanged: peak past 80% of the configured cap, sustained 5 minutes.
- **Drill:** `serial_loop_publishes_a_ceiling_of_one_and_counts_itself` proves boot → sign → scrape end to end (`limit 1`, `active 1`, `peak 1`); `the_saturation_rule_exempts_the_serial_ceiling_of_one` locks the guard into the rules file as a contract.

### 4.43. Constant-time token comparison and the panic audit (Round 25)

- **The `token_eq` shortcut is gone:** the old implementation compared lengths and RETURNED EARLY — a length mismatch answered faster than a mismatch in the last byte (a timing leak). The new fold runs over the LONGER input (the shorter side padded with zeros, length folded in separately); runtime depends only on the presented length — a value the attacker chose and can already see on the wire.
- **Panic audit (43 candidates, 42 of them production code, test modules excluded): ZERO on the server request path (`server.rs`).** Classification: `nsm::Cbor::take(n)` returns `Err` with an exact-`n` contract (the unwrap can never fire), `slip39::combine` checks duplicate indices and thresholds before interpolation (the `gf_inv` expectation is guarded), the `main.rs` sites are internal-consistency expectations on data the application constructed itself (each `expect` says why), and 2117 sits behind `if let Some(url)`. **And the fuzz gate PROVED it:** a token grep (unwrap/expect/panic) found 42 hand-auditable sites but could NOT see two REAL panic classes — byte-index slicing on multi-byte text (`hex_decode`) and a multiply overflowing on a length from the document (`skip`). Both were fixed this round and locked in by fuzz + regression tests (§4.46); the full classification is docs/09 §9.
- **Why both together:** closing a leak while leaving its neighbour open is not an audit — comparison and panics are two separate channels an attacker walks on the same line.

### 4.44. Continuous security audit (Round 25): RustSec + secret scan in CI

```bash
cargo audit --ignore RUSTSEC-2023-0089 --ignore RUSTSEC-2026-0367 --ignore RUSTSEC-2026-0368 --ignore RUSTSEC-2026-0369   # 208 dependencies → 0 VULNERABILITIES (cargo metadata, x86_64-linux) (4 DOCUMENTED ignores: 1 atomic-polyfill + 3 zip; justifications live in ci.yml + deny.toml)
bash scripts/secret_scan.sh   # 11 patterns · tracked files + FULL git history → 0
cargo deny check              # Round 26: advisories ok, bans ok, licenses ok, sources ok
```

- **The problem:** these audits had never run in this repository — `cargo audit` was installed but unwired; the secret scan was manual and one-shot. A leaked credential or a vulnerable dependency could ride a green pipeline.
- **Contract:** the `security-audit` CI job runs `cargo audit` (any RustSec VULNERABILITY fails the job; the documented ignores — `RUSTSEC-2023-0089` (atomic-polyfill, §4.48) and, since Round 36, `RUSTSEC-2026-0367/0368/0369` (zip: an OPTIONAL BUILD-dependency of the bitcoind TEST harness only — `cargo build --release` never compiles it, no shipped binary contains it; the fixed line zip ≥9.0.0 is unreachable while even the newest harness release 0.42.0 requires ^0.6.6. The reasoning + the re-evaluate-at-every-harness-bump rule live in `deny.toml`  (the Round 36 bump shipped and re-checked — the exception stood); the same three IDs also sit in `deny.toml`'s [advisories] list (deny scans the same RustSec database); the flags are byte-identical in ci.yml and the local gate. No ignore gets added without a written why), `cargo deny check` (license whitelist/bans/sources — §4.49) and `scripts/secret_scan.sh` on every push. The scan is offline grep — CI and a laptop see byte-identical results — and its patterns fire only on credential MATERIAL (private-key armor, AKIA/ASIA, ghp_/gho_/github_pat_, glpat-, xox*, sk-32+); generic words like "password" are deliberately absent because they only train people to ignore the scanner.
- **Why history:** deleting a file does not delete `.git` history — a redacted file still leaks through `git log -p` to anyone who clones. The scan walks every added line of every reachable commit and reports the OWNING commit for each hit.
- **Drill:** both commands ran this round: audit rc=0, scan `SECRET SCAN OK (11 patterns, tree + full history)`.

### 4.45. Live exposition contract (Round 25): alert expressions against a REAL bridge

```text
# monitoring drill with PROMTOOL_REQUIRED=1 (official prom/prometheus image):
Checking /w/prometheus_alerts.yml
  SUCCESS: 11 rules found          # the real PromQL parser, --lint all
```

- **The problem:** the asset checks validated expressions only BY NAME — nothing proved the series a rule reads is actually rendered by a running process, and nothing proved the expressions were valid PromQL at all (a syntax error in a folded expr could ship silently).
- **Contract, two halves:** (1) `monitoring_drill.sh` now runs `promtool check rules --lint all` under `PROMTOOL_REQUIRED=1`, via the pinned official `prom/prometheus:v3.15.0` image through docker (no root, read-only mount, version-pinned); with neither promtool nor docker the drill FAILS instead of falling back to "structural checks only". (2) `every_alert_reference_is_a_series_the_live_bridge_exports` boots a REAL bridge and scrapes every family a rule reads, producing the three event-driven ones: `alarm_refused_by_vault` (watchtower ALERT), `refused_by_vault` (the same refusal) and `rate_limited_by_vault` (overflowing `--rate-limit 3:1`).
- **The conditional-render contract:** those three `*_by_vault` families are absent BEFORE their event (per-vault rows appear once the vault has history) — Prometheus warms the counter from its first sample, which is exactly when `increase(...)` becomes evaluable. The contract: every OTHER family exists at boot; the three exist after their event. A family no event can render = a silently dead rule.
- **Drill:** the test drives all three stages (at boot only the three are allowed missing → ALERT → overflow) and demands `missing` be EMPTY on the final scrape.

### 4.46. Bounded fuzz gate (Round 25): `scripts/fuzz_gate.sh`

```bash
FUZZ_SECONDS=45 bash scripts/fuzz_gate.sh   # 6 targets × 45s (CI: 120s), per-input timeout 10s
# FUZZ GATE OK (6 targets × 45s, no panic/hang/crash)
```

- **The problem:** three untrusted-input parsers (the NSM attestation CBOR, the frame/health/watchtower JSON, human-typed SLIP-39 mnemonics) were protected only by error-path unit tests — the "never panics" claim stopped at the examples someone thought of.
- **Targets:** `attestation_doc` (hex layer exercised both valid and invalid, CBOR bytes adversarial — the COSE_Sign1 container is inside this target too), `frame_json` (`SignRequest` + `BridgeHealth` + `parse_state` — the three JSON surfaces from the wire and the disk), `slip39_share` (`decode_share` + round-trip + `combine` fed two copies of the SAME share to force the duplicate-index path); **Round 26:** fourth target `psbt_parse` (§4.50); **Round 30:** fifth target `estate_letter` (the letter the family receives — it arrives via OCR/translation/USB; `parse_letter` plus full `verify_letter` on every network, all 8 checks fixed-width) and sixth target `wots_kit_seal` (the post-Q-Day emergency path: any (pk, msg, sig) triple answers without panic, a FRESH keypair signature from ANY 32-byte seed must verify, and all five kit-seal envelope kinds cleanly refuse any text). Seeds come from real artifacts: `kit-seed split --format slip39` output and a full-size signature frame (fuzz/corpus is committed; crash artifacts are gitignored).
- **Toolchain note:** cargo-fuzz drives `-Zsanitizer=address`, which stable rustc REJECTS. On this machine `~/.local/bin/{cargo,rustc}` are plain symlinks into stable, not rustup proxies, so even `rustup run nightly` is not enough — the gate prepends the nightly toolchain's own `bin` directory to PATH (for every child process, no proxy, no default-toolchain fallback).
- **Scope bound:** this is a REGRESSION gate (parsers must stay panic-free), not a research campaign — the window is bounded and the durable evidence lives in `fuzz/corpus`.

### 4.47. Capacity gate drilled in CI (Round 25): `scripts/capacity_gate.sh`

```text
  [1/3] a fresh report round-trips as its own baseline
  [2/3] a 100x-inflated baseline must FAIL the gate
  [3/3] a malformed baseline is refused with an EMPTY stdout
CAPACITY GATE OK (round-trip passes, 100x regression refused exit 1, malformed refused exit 2)
```

- **The problem:** `bench --baseline` was written as release machinery but never executed — the gate itself could rot (wrong loading, a silent exit 0, a flooded stdout) and nobody would notice.
- **Contract:** the `capacity-gate` CI job puts the REAL binary through three verdicts on every push: (1) a fresh `bench --json` report round-trips as its own baseline (exit 0 — nothing changed, the gate PASSES); (2) a 100x-inflated baseline exits 1 with `REGRESSION:` on stdout and `capacity regression` on stderr; (3) a malformed baseline exits 2 with stdout completely EMPTY (a measurement report never precedes a usage error). The pass leg is deliberately tolerant (consecutive measurements drift on loaded runners); the refusal leg is noise-immune — 100x sits orders of magnitude past any timing wobble.
- **Real usage:** before a release the operator runs the same command against THEIR baseline at the default 25% tolerance — CI proves the mechanism, the operator holds the threshold.

### 4.48. Root-closing the RustSec "unmaintained" warning (Round 26): `rustls-pemfile` → `rustls-pki-types`

```text
cargo audit --ignore RUSTSEC-2023-0089
  Scanning Cargo.lock for vulnerabilities (197 crate dependencies)
  0 vulnerabilities · 0 warnings (1 documented ignore)
```

- **The problem:** `cargo audit` reported two "unmaintained" warnings: `rustls-pemfile` (RUSTSEC-2025-0134 — a DIRECT dependency of our TLS PEM reader) and `atomic-polyfill` (RUSTSEC-2023-0089, transitive). To every gate a warning is green: neither dependency rotting would ever turn a job red.
- **The migration:** the TLS PEM paths (mTLS CA chain, the shared `read_cert_and_key`, the pinned store, the test) moved to `rustls::pki_types::pem::PemObject` — rustls already ships those types, so NO new dependency entered the graph and `rustls-pemfile` left Cargo.lock entirely. The behavioral contract is pinned by tests: a file with no key SECTION gets the family message (`no certificate or no private key found`), a malformed key section gets `parse key: <cause>` (+2 tests; tls suite 12/12).
- **The remaining warning is DOCUMENTED, not silenced:** `atomic-polyfill` is only ever called under MCUs-without-native-atomics targets (`cfg(target_arch = "avr" | "riscv32i" …)`) — `cargo tree -i atomic-polyfill` prints nothing for x86_64/aarch64. The chain is `postcard 1.1.3 → heapless 0.7.17`, both the LATEST versions; no upstream fix exists (it would mean replacing FROST's codec). `cargo audit --ignore RUSTSEC-2023-0089` sits in ci.yml WITH its justification; `deny.toml` enforces the same reality by locking the graph to x86_64+aarch64 — neither audit excuses anything without writing down why.

### 4.49. Dependency policy: `deny.toml` + `cargo deny check` (Round 26)

```text
cargo deny check
advisories ok, bans ok, licenses ok, sources ok
```

- **The problem:** no license/ban/source policy existed at all — a dependency arriving under a license outside any whitelist would have entered the root silently.
- **The policy:** a 9-SPDX license whitelist (MIT, Apache-2.0, BSD-2/3, ISC, Zlib, CC0-1.0, Unicode-3.0 plus `hex_lit`'s MIT variant MITNFA); NOT on the list = an error, so a new dependency demands a conscious decision. Bans: wildcards = warning (only the workspace's own path crates resolve as `*` — a literal version beside each path would drift on every release bump), duplicates = warning, EXTERNAL default features are upstream's design → allowed. Sources: crates.io ONLY; a git dependency or unknown registry = error.
- **Gate:** `cargo deny check` was added to the `security-audit` CI job — byte-identical to the local gate.

### 4.50. Fuzz coverage completed (Round 26): `psbt_parse` + corpus durability

```bash
FUZZ_SECONDS=45 bash scripts/fuzz_gate.sh   # 6 targets × 45s — the 4th is psbt_parse, 5th/6th are Round 30
# FUZZ GATE OK (4 targets × 45s, no panic/hang/crash)
```

- **The problem:** the last unfuzzed parser path was PSBT: the coordinator reads operator files/SD-card input in TWO shapes (raw wire bytes and the base64 export — the CLI's own file paths) and libFuzzer never saw either. (COSE_Sign1/CBOR is not uncovered: the NSM verifier path lives inside the `attestation_doc` target.)
- **The target:** `psbt_parse` — raw deserialize + base64→deserialize (exact copies of the CLI's read paths), parse→serialize→parse stability, OUR BIP-341 sighash helper over EVERY input and `finalize_and_extract` — all must answer hostile maps with `Err`, never a panic. The seed is REAL: `qsv-cli psbt build` output (532 B base64 plus the same data's 397 B raw form).
- **The first long pass found a REAL crash:** rust-bitcoin 0.32's `extract_tx` maps any `fee()` error outside three listed variants to `unreachable!()` — a hostile `non_witness_utxo` with an unresolvable vout (`PsbtUtxoOutOfbounds`) meant a PANIC inside the dependency (crash-8523a028). `finalize_and_extract` and `finalize_multi_input_and_extract` now judge `fee()` FIRST through one shared helper — every such error becomes our `Err` — with a regression test and the crash input committed as a corpus seed.
- **Durability:** curated seeds are committed; the EVOLVED corpus (64-hex names) stays local under `.gitignore`; CI carries `fuzz/corpus` BETWEEN runs via `actions/cache` — every push resumes where the previous one stopped, and a crash artifact is never committed.
- **Scope bound:** the window is bounded per run (local long pass: `FUZZ_SECONDS=300`); this is a REGRESSION gate.

### 4.51. Native promtool: the monitoring drill without docker (Round 26)

```text
  promtool: rules + lints OK [/usr/bin/promtool]   # native — the docker step was skipped
```

- **The problem:** the drill's real PromQL parser could only run through docker locally; the system `promtool` (installed by the operator) is now the first resolution.
- **Resolution order (unchanged, now also REPORTED):** (a) native `promtool` on PATH → (b) the official `prom/prometheus:v3.15.0` image → (c) neither with `PROMTOOL_REQUIRED=1` = failure. The drill states which source it used; CI keeps docker (the runner has no package) — shared code, one gate.

### 4.52. The attestation chain, end to end (Round 27): COSE_Sign1 + X.509 + root pin + CLI choke point

```text
  real AWS sample (aws-samples, MIT-0): ALL CHECKS PASSED
  Chain [TARGET, INTERM_3..INTERM_1, ROOT] → root pin → COSE ES384 ✓
  dev document → production verifier → 24/24 nsm tests, 75/75 cosigner lib
```

- **The problem:** the enclave that releases co-signatures carried ONLY its own signature. "Which measurement produced this?" had no answer. A stale, malformed or forged document could pass unnoticed — there was attestation TRANSPORT but no attestation VERIFICATION.
- **The envelope (protocol v2):** the CLIENT generates `SignRequest.nonce_hex` (SHA256("QSV_REQ_NONCE_v1"‖vault‖sighash‖pqc_vk‖pqc_sig) — no RNG, deterministic); the server validates only the SHAPE and echoes it verbatim; `user_data = xonly(32)‖vault_id` — the document is bound to the REQUESTED enclave key + vault. An identical request replays an identical (harmless, Theorem 1) response.
- **The verifier (`nsm.rs`) follows AWS §3.2.2/§3.2.3 step for step:** COSE_Sign1 (tag 18 optional, protected `{1:-35}`=ES384, signature EXACTLY 96 bytes) → content rules (mandatory fields, PCRs ∈ {32,48,64}, cabundle 1..1024, nonce/user_data ≤512, digest=SHA384, unknown field = ERROR) → the request nonce (replay) → PCR pins → user_data binding → the X.509 chain → the COSE signature. The "Signature1" text(10)=0x6A golden test — an off-by-two caught by the REAL AWS sample document (8 was written first, yielding InvalidSignature).
- **Root pin:** the AWS Nitro Root-G1 PEM+DER is embedded (its hashes match across 3 independent sources); outside enclave builds the QSV dev root is a second anchor. Chain order `[ROOT, INTERM_1..N]` (AWS §3.2.3), validity at `now` enforced on EVERY certificate (Nitro infrastructure certificates live ~3 hours — freshness comes from the PKI, not hope), BC/KU/pathLen, NO CRL (exactly as AWS specifies); a key/algorithm mismatch fails closed.
- **Proven against the real world:** AWS's own sample document (4396 B, MIT-0) and the old NSM firmware's habit of emitting `null` for optional fields are in the test suite — the verifier treats null as "absent". `emit_dev_document` produces REAL COSE_Sign1 (no JSON pseudo-document); the production and dev documents pass through the SAME verifier.
- **The CLI choke point (fail-closed):** `--cosigner-pcr0/1/2` + `--cosigner-key` pins (`CosignerPin`) sit at the SINGLE passage every frost-spend / vault-rotate batch / watchtower rehearsal path crosses; a live request WITHOUT an attestation document is refused ("refusing"); a pin without an endpoint = exit 2, hex that is not 32/48/64 bytes = exit 2 (at startup, BEFORE the first request).
- **New gates (Round 27):** proptest — covenant value conservation + dust refusal + CSV BIP-68 encoding, policy shape (every key in a branch), SLIP-0039 roundtrip / single-word corruption / wrong passphrase (11 properties); `token_eq` as a byte-equality property (no padding forgery); the `cargo llvm-cov` coverage run; `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps` (an HTML tag or dead link now fails the gate).

### 4.53. The live Nitro Enclaves e2e round (Round 28): two binaries, two phases

```text
PHASE 1 (every machine):
  PROBE PASS: gate + attestation + signature all verified
  wrong PCR0 / unallowed vault / wrong xonly → REFUSED (3/3)
PHASE 2 (nitro-cli + docker + Nitro hardware): EIF → run-enclave → vsock
  NITRO_E2E=FULL   (PASS under the hardware measurement, REFUSED under dev)
```

- **The problem:** the attestation verifier was proven against AWS's sample document, but (a) it had never run against a REAL enclave, and (b) `serve_vsock` existed with **no caller** — no entrypoint meant no enclave image could be built or launched. The "live round" simply did not exist in the box.
- **The enclave entrypoint (`enclave_server` bin):** `--port` + `--vault` (or `QSV_VAULT` baked into the image as ENV — an enclave receives NO run-time arguments); `--features nsm` serves real AF_VSOCK via `serve_vsock`, the plain build serves loopback TCP via `serve` — the SAME ceremony, two transports. On startup it prints `DEV_PCR0=` / `DEV_XONLY=` / `E2E_READY` lines (those are the runner's pin values).
- **The client (`cosign_probe` bin):** the SAME verification chain as the production terminal — gate accepted → document mandatory (missing = refuse) → `verify_attestation_doc` (chain / root pin / PCR / nonce / user_data) → the BIP-340 signature under the pinned key. Exit codes: 0 = PASS, 1 = any refusal (fail closed), 2 = usage error. Transport: `--tcp` (dev) or `--cid` (real vsock, the `nsm` build).
- **Phase 1 (every machine, `scripts/nitro_e2e.sh`):** runs the two binaries as REAL processes over loopback — the PASS scenario plus three refusals (wrong PCR0, unallowed vault, wrong xonly pin). This phase ALSO runs inside `cargo test` via `tests/nitro_e2e.rs` (2 tests: real processes, real sockets, real documents — no stubs).
- **Phase 2 (the real enclave):** `scripts/nitro_build_enclave.sh` packages the Dockerfile (rust build → debian slim, `QSV_VAULT` as ENV) into an EIF via `nitro-cli build-enclave-image`; `nitro-cli run-enclave` → `describe-enclaves` yields PCR0/CID → the `nsm` build dials vsock: `cosign_probe --cid $CID --port 5005 --pcr0 <hardware measurement>` must PASS; the same request under the **dev** measurement must be REFUSED (measurement pins are real). The enclave is always closed with `terminate-enclave`.
- **Phase 2 installation (nitro-cli, the official path — docs.aws.amazon.com/enclaves):** AL2023: `sudo dnf install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel -y`; AL2: `sudo amazon-linux-extras install aws-nitro-enclaves-cli -y` + `sudo yum install aws-nitro-enclaves-cli-devel -y` (other distros: build from `github.com/aws/aws-nitro-enclaves-cli`); `sudo usermod -aG ne $USER` and `sudo usermod -aG docker $USER` (log back in after the group changes), `sudo systemctl enable --now nitro-enclaves-allocator.service` (the default preallocation is 512 MiB / 2 vCPU — exactly what the script's `--memory-mib 512 --cpu-count 2` requests), `sudo systemctl enable --now docker`, then verify with `nitro-cli --version` and `nitro-cli describe-enclaves`. The runner matches the FRESH enclave by the `EnclaveID` printed in the `run-enclave` output against the `describe-enclaves` list; the old `d[0]` habit (first listed enclave) could silently probe a stranger on a shared parent instance — with no match the run stops fail-closed.
- **Honest boundary:** without nitro-cli/docker/Nitro hardware, phase 2 skips with `SKIP PHASE 2: ...` (`NITRO_E2E=PHASE1_ONLY`); for CI/release runs `--require-enclave` turns a missing prereq into exit 4. Phase 1 never skips — the ceremony itself still crosses the real wire.

### 4.54. Round 31: coverage depth, 43 mutants, the FROST security statement

- **The P5 child-profraw gap is closed:** `enclave_server --max-requests N` exits NORMALLY after N connections (`serve_limited` / `serve_vsock_limited`) — a normal exit flushes the process's `.profraw`, which SIGKILL can never do. Test guards now use that path; `nitro_e2e.rs` pins the flag validation (`--max-requests 0`/`nan` = exit 2).
- **Mutation set 30 → 43** (`scripts/mutation_audit.sh`, M31–M43): the estate-letter field comparators (including the wrong-network hint), the WOTS+ verification chain step count, the `pid_alive(0)` bogus-record wall, `classify(None) ≠ Live` (an undecidable liveness probe is never "alive"), the plaintext-off-loopback refusal, bare/wildcard binds never counting as loopback, the webhook `"<ts>.<body>"` replay binding, the P2MR witness version (bc1z), the two parser walls the fuzz gate found (CBOR depth 32, non-ASCII hex), and the two guards of the live-scan fix: M42 the scan read-budget (600 s → 5 s must kill the slow-scan test) and M43 the `-8 Scan already in progress` recovery guard. **The audit no longer touches git at all:** every file is snapshotted byte-for-byte before the mutation and restored from that copy — a dirty worktree (this round's uncommitted fix) can never lose a byte, and the old "commit first" refusal is gone.
- **The FROST adaptive-security / nonce-lifetime security statement** lives in module 04 §7 (both languages): RFC 9591 is *Informational*, defines no Bitcoin ciphersuite; the CRYPTO 2025 debate (ePrint 2025/1061 vs 2025/1001) is UNRESOLVED and this project does NOT claim an adaptive-security proof; nonces are single-use, envelope tags enforce the split, post-aggregation BIP-340 verification is mandatory, and the out-of-scope list is explicit.
- **Equivalent-mutant review:** all 48 mutants (incl. M45, Round 34; M46–M48, Round 36) are behaviorally distinguishable — under each mutant either a positive path or its negative twin still runs, so none can stay green without editing the tests (each KILLED line is the evidence). M42/M43 included: with the budget shrunk the FAST scan still passes, and with the recovery guard broken only the -8 path dies — both two-sided. The set is a hand-picked behavioral proof corpus, NOT a general quality score.
- **Signet (P6, partial):** `scripts/signet_setup.sh bootstrap` verified against the LIVE signet network (bitcoind v28.2, IBD). Faucet wall: every known faucet as of 2026 sits behind Cloudflare Turnstile (the APIs were closed in 2025-08), so programmatic funding is impossible; the `vault-fund` + `lifecycle` step waits on an operator-supplied tBTC transfer (state: synced, unfunded). **→ Round 37 (2026-10-18): CLOSED** —
  arkfaucet.com's CAPTCHA-free rail made funding possible; the live loop
  closed funded at 7/7 honest exits (§4.62).

### 4.55. The one-command local gate (`scripts/round_gate.sh`, Round 31)

- **The problem:** CI defines 11 jobs but has been red for months on billing — the gates existed, their RUNNER did not; every door hung on a single dead channel.
- **The fix:** a byte-for-byte local mirror of `.github/workflows/ci.yml`: fmt → clippy ×3 → test ×2 → relay/monitoring/capacity drills → security (audit + deny + secret scan) → fuzz → mutation → coverage. Same order, same thresholds, same underlying scripts.
- **The empty-green wall (the Round-29 lesson, embedded in the gate):** every leg has a minimum plausible wall-clock; if `test-default` finishes in under 90s (the Round-29 fake returned in 0.00s) the gate refuses to call it green — it reports `EMPTY-GREEN` and fails. Duration is evidence.
- **Usage:** `bash scripts/round_gate.sh` (~25–40 min) · `GATE_SKIP="fuzz mutation-audit coverage"` for a fast lap · `GATE_ONLY=fmt` for one leg · `GATE_CONTINUE=1` to run everything and summarize at the end.
- **Honest boundary:** the local gate does NOT turn GitHub green (P1 billing, account owner); the equivalence is one-sided — once CI is revived both doors run the same sequence.

### 4.56. The live-network fail-closed lap (Round 31): the scan-timeout fix + unfunded signet rejections

- **The find (P6's hidden real blocker):** the `qsv-node` RPC client used a 10-second read budget on EVERY request, while `scantxoutset start` blocks the calling connection until the ENTIRE UTXO set has been walked. Invisible on regtest (the scan finishes in seconds), on signet it killed every live scan with `Resource temporarily unavailable (os error 11)` — without the fix a live UTXO scan could NEVER work outside regtest.
- **The fix (`crates/qsv-node/src/rpc.rs`):** `post_with_timeout` — the default stays 10 s (a dead node still fails fast), the scan gets 600 s. On `node error -8 (Scan already in progress)` the client polls `scantxoutset status` until the foreign scanner drains and retries start once; blowing the budget fails closed. Three new tests: (1) a response delayed 11 s — past the old budget — still parses, (2) the -8 → status → retry recovery path, (3) a **wire-shape** test — a canned response never validates the request, so the test pins `scanobjects` as an ARRAY (bitcoind rejects an object with -3).
- **Live signet evidence** (bitcoind v28.2 · `~/.signet-qsv` · block 326202 · IBD complete · 10 peers):
  - `psbt-live`: live scan succeeds → `no live UTXO pays tb1p0x8h… fund it first` · **exit 1** (unfunded rejection).
  - `vault-dashboard`: live endpoint · heartbeat OK · inheritance LOCKED · exit 0.
  - `watchtower --last-refresh-block 326200`: read-only pass · 0 live coins · `all clear` · exit 0.
  - `vault-rotate`: the early-rotation refusal (`rotation not due … refusing an early re-rotation` · exit 1) AND the past-due unfunded rejection (`no confirmed UTXO pays tb1p0x8h… fund the vault first` · exit 1).
- **Boundary (honest) — CLOSED in Round 37 (§4.62, 2026-10-18):** the only missing step was operator funding — 1 tBTC past the faucet CAPTCHA wall (§4.54) → `scripts/signet_setup.sh lifecycle` closes the full live loop. Every read-only/surface command was green on the real network; the spendable proof waited on funding. **Status: funded (arkfaucet.com, CAPTCHA-free §4.62) — 7/7 honest exits including a real mempool spend.**

### 4.57. The automated mutation sweep + file wall (Round 32): `scripts/mutation_sweep.sh`

- **The problem (Round-31 dimension A):** §4.54's 43 mutants are a hand-picked behavioral corpus; nothing guaranteed a NEW file could not ship with zero mutants (the 2024 cost warning against AST-driven generation still applied).
- **The fix — three layers:**
  1. **File wall:** EVERY `.rs` file in the `qsv-core`/`qsv-cosigner`/`qsv-cli`/`qsv-node` `src/` tree is either hand-mutant-covered (the §4.54 set is PARSED out of the audit script), or gets a sweep mutant, or sits on an explicit allowlist with a written reason (the lib.rs files = module declarations only; `demo_keys.rs` = non-production test fixtures). An uncovered file turns the sweep RED.
  2. **Mechanical mutants:** up to 2 boundary flips per file OUTSIDE `#[cfg(test)]` blocks (`>=`→`>`, `<=`→`<`, `==`→`!=`, `&&`→`||`) — deterministic (same tree ⇒ same mutants), each restored from a byte snapshot (dirty-worktree safe).
  3. **Honest classification:** KILLED (the module's test subset fails — escalated to the whole crate on a survive) · UNVIABLE (does not compile — never counted as a kill, reported apart) · SURVIVED = a test gap: either a test is added, or the mutant is recorded in `scripts/sweep_equivalence.txt` WITH its written reason. No silent escapes.
- **Wired into the gate:** `round_gate.sh` leg 9b (`mutation-sweep`), and the CI mutation job now runs both: the 45 hand mutants (§4.54) plus the automated sweep. Fuzz equality fix on the same round: the local gate's fuzz leg now runs CI's SAME 120-second window (the old 45 s default was the one-sided equality the Round-31 review flagged); `FUZZ_DEEP=1` opens the 300 s/target release pass.
- **Drill:** `bash scripts/mutation_sweep.sh` → `SWEEP VERDICT: GREEN — … files wall-checked`; single file: `bash scripts/mutation_sweep.sh bridge`.

### 4.58. FROST DKG — dealer-less key generation (Round 33): `setup --dkg`

- **The problem:** `inheritance-kit setup`'s trusted-dealer flow produces
  ALL signing shares on ONE machine; compromise of that machine (or of
  the coordinator moment) leaks the entire group key from a single point.
  SLIP-0039 backups PROTECT each share afterwards, but they do not change
  that generation-time exposure.
- **The fix:** `qsv-cli inheritance-kit setup --dkg` runs the three RFC
  9591 DKG rounds (commitment → pairwise shares → finalization) — **no
  machine ever sees a complete signing share by itself.** Same frost-core
  `keys::dkg` (part1/2/3), SAME output contract as the dealer:
  `public-package.txt` + `heir-XX-<id>-deal.txt` + printed SLIP-0039;
  frost-spend, the backup drill and the watchtower flow are unchanged.
- **Identifiers:** still label-derived (identical file names), but each
  participant CHOOSES its own — exactly what the DKG expects.
- **Evidence:** `dkg_rehearsal_matches_the_deal_contract_and_signs`
  (contract parity + a BIP-340 signature under the group key),
  `dkg_below_threshold_fails_closed`,
  `dkg_validates_its_threshold_like_the_dealer`, and the CLI drill
  `frost_dkg_setup_runs_the_same_ceremony_without_a_dealer` (the REAL
  binary: setup → r1 ×2 → package → r2 ×2 → finish). Hand mutant
  **M44** (part1 `(max, min)` threshold binding) KILLED; the audit grew
  43 → **44/44**.
- **Honest limit:** this run is a single-process REHEARSAL (the wizard
  is one machine); a distributed deployment carries the same round
  packages between hosts — same API, same message types, different
  transport.

### 4.59. Watch-only descriptor export (Round 34): `vault-descriptor`

- **The problem:** an external watcher (a second pair of eyes, an
  independent balance check) expects the standard tool — an *output
  descriptor*. QSV emitted none, so reading this vault's UTXOs with an
  external wallet or node meant depending on QSV's own dashboard.
- **The fix:** `qsv-cli vault-descriptor [--network …] [--json]` emits the
  two descriptor forms that describe this output EXACTLY, each with a
  BIP-380 checksum:
  - `addr(bc1p…)#checksum` — BIP-385, the network-tagged full scriptPubKey;
  - `rawtr(<output key>)#checksum` — the same scriptPubKey addressed by
    its TWEAKED output key (it makes no claim about the tree).
  Both are built fail-closed in `VaultTaproot::watch_descriptors`: nothing
  is printed until the scriptPubKey ↔ address round-trip matches in both
  directions and the checksum re-verifies through `verify_checksum`.
- **Why there is NO `tr(...)` (the honest reason, written down on
  purpose):** a `tr()` must restate the WHOLE tree, because the address
  commits to every leaf's hash. In this vault **3 of the 4 leaves are not
  miniscript**: leaves 2 and 3 open with `<n> CSV DROP` — miniscript can
  only compile the `older(n)` check as `<n> CSV VERIFY` (different bytes ⇒
  different leaf hash ⇒ **a different address**); leaf 4 is a SHA-256
  commit-reveal lock on the key, with no miniscript fragment at all. Raw
  hex leaves are not standard either: BIP-386 defines a tree leaf as a
  script *expression*, Core accepts `raw(HEX)` top level only (its
  `rawleaf()` PR bitcoin/bitcoin#30243 was closed), and rust-miniscript
  parses every leaf as miniscript. **A `tr()` built from a different tree
  derives a DIFFERENT address — the watcher would watch nothing**, so the
  export refuses to invent one and hands over what is true.
- **Evidence:** the core tests `watch_descriptors_pin_the_exact_output`
  (checksum round-trip plus two-way scriptPubKey equality on four
  networks) and
  `three_of_four_leaves_are_not_miniscript_so_no_tr_descriptor` (leaf 1 is
  the positive control — miniscript's output IS the real leaf; leaves
  2/3/4 are not — if miniscript ever compiles them the test goes RED and
  says "upgrade the export to tr()"), and the CLI drill
  `watch_only_descriptors_are_the_demo_vault_and_real_bitcoin_core_uses_them`
  on a REAL bitcoind v28.2 in four steps: `getdescriptorinfo` (Core
  recomputes the SAME checksum) → `deriveaddresses` (Core's expansion IS
  the vault's address, for BOTH descriptors) → `importdescriptors` into a
  blank keyless wallet (both rows success; a private-key wallet refuses
  with -4) → mine 101 blocks to the vault → `listunspent` reports that
  UTXO: the independent balance verification the feature exists for.
- **Honest limit:** Sparrow does not support single-address wallets and
  no Sparrow release documents `addr()` import; rust-miniscript-based
  libraries do not parse `addr()`/`rawtr()` either. The proven-compatible
  reader is **Bitcoin Core**; watchers that accept address lists also
  work. `--json` writes exactly ONE document to stdout (no banner/footer —
  the §4.32 contract). The spending policy stays in QSV: this descriptor
  only watches.

### 4.60. Multi-watchtower k-of-n mirror approval (Round 35): `--watchtower` / `--watchtower-quorum`

- **The problem:** one watchtower host is a single point of failure: a
  compromised host buys BOTH directions for one price — it can stamp a
  false `ALERT` and freeze the vault permanently (the idempotent alarm of
  §3.2), or silence a real one and leave the heartbeat window spending.
- **The solution:** `cosigner-bridge` (and `cosigner-bridge-install`,
  which bakes the mirror flags into ExecStart as ABSOLUTE paths plus the
  OPERATIVE quorum) runs k-of-n mirror approval: `--state-dir` is mirror
  #1, `--watchtower <dir>` is repeatable, n = 1 + repeats. A vault
  freezes only when k DISTINCT mirrors report `ALERT`:
  - `--watchtower-quorum k` — the explicit quorum, `1..=n`. k=0 (freeze
    everything) or k>n (freeze nothing) is NEVER silently clamped:
    usage error, **exit 2**, BEFORE the socket binds — a misconfigured
    estate never half-serves.
  - default: majority ⌊n/2⌋+1 (n=1 → 1, today's single-mirror behaviour
    unchanged; n=3 → 2; n=4 → 3).
  - with EXACTLY TWO mirrors there is no compromise-resistant default
    (k=2 is silenced by one dead host, k=1 is forged by one), so the
    explicit value is REQUIRED — otherwise exit 2.
  - the price is symmetric: forging a freeze costs `k` hosts, silencing
    one costs `n−k+1` — at n=3, k=2 no single host buys either direction.
- **The merge (`qsv_cosigner::quorum_verdicts`):** the union of every
  mirror's vaults — a vault a mirror never heard of casts NO "ALERT"
  vote (silence never freezes) and a sibling's observation can never be
  erased; the merged tip is the OLDEST mirror's (a lagging host cannot
  claim a newer truth); a vault is ALERT iff ≥ k DISTINCT mirrors say so.
- **Fail-closed towers:** one unreadable mirror aborts the BOOT (exit 1 —
  a silent host is an operator decision, never a guessed "all clear").
  **The VACUOUS-STATE wall — Round 36, M46:** a file that PARSES but
  carries NO vault record (`{"tip": N, "vaults": {}}` — the shape a
  truncated/clobbered writer leaves behind) counts as UNREADABLE and
  takes the same abort: at boot there are no last-good verdicts to keep,
  and accepting the empty map would have served every vault as a silent
  ALL-CLEAR from the very first request (existence of a file is not
  health — the CONTENT is what reads). The same refusal rides the
  per-request reload: a state file that goes vacuous mid-run keeps the
  LAST verdicts. If a mirror file is deleted mid-run or the set cannot
  be re-read, the LAST verdicts stay applied across the WHOLE set (the
  Round-23 keep-last rule extended) — a deleted mirror can never
  unlock, a cleared alarm can never silently vanish. The rules re-apply
  per request: no restart.
- **Evidence:** three core unit tests for `quorum_verdicts`, four CLI e2e
  tests — the three exit-2 walls
  (`cosigner_bridge_quorum_usage_walls_exit_2`), the dry-run banner
  (`cosigner_bridge_rehearsal_names_the_resolved_quorum`), the
  unreadable-mirror boot abort, and the LIVE three-mirror drill
  (`cosigner_bridge_freezes_only_when_k_of_n_mirrors_agree`: 1/3
  releases → 2/3 freezes → recovery → a DIFFERENT host pair → a deleted
  mirror keeps the freeze → return; every release is byte-identical) —
  plus the installer e2e
  `install_bakes_the_k_of_n_mirrors_and_walls_bad_quorums` (absolute
  paths + quorum verbatim in ExecStart, both walls write NOTHING).
  Round 36:
  `cosigner_bridge_aborts_the_boot_on_a_vacuous_state_file` (a vacuous
  state file aborts the boot with exit 1 — a bounded reap keeps even the
  MUTANT from hanging), unit test
  `vacuous_state_never_reads_as_all_clear` — pinning M46 (the wall),
  M47 (the merge comparison `votes >= quorum`) and M48 (the k=0/k>n
  clamp wall — the hand mutant that keeps that site watched now that
  M46 put bridge.rs under the sweep's hand-covered set); the audit grew
  45 → **48/48 KILLED**.
- **Honest limit:** the quorum COUNTS, it does not authenticate the
  transport — how a mirror's file reaches the bridge (file sync,
  enterprise distribution) is the operator's transport trust; mirror dirs
  are only READ under `ProtectSystem=strict` (never in ReadWritePaths),
  which is why the installer canonicalizes each one and verifies its
  state parses before any unit file is written.

### 4.61. Floor-scenario measurement (Round 36): `scripts/floor_scenario.sh`

- **The problem:** the gate defends the floor as ONE number pair (lines
  ≥ 97.5% · functions ≥ 82.0% — §4.54, `coverage_gate.sh`, the single
  home). The auditor asks something else: "what does the floor BECOME
  when a layer drops, or when the least-covered files leave the suite?"
  A threshold-compliant single number cannot answer that, and making
  one up is not a measurement.
- **The solution:** `bash scripts/floor_scenario.sh` — reads the SAME
  llvm-cov JSON the gate consumes (`COV_OUT=target/coverage.json`; runs
  the ~25-minute coverage pass itself if absent) and prints a scenario
  table while moving NO threshold (a measurement, not a gate):
  - **S0 · workspace** — the number the gate sees, cross-checked against
    llvm-cov's own totals; the floor applies HERE and only here;
  - **S1 · per crate** — the five crates' sub-floors;
  - **S2 · audit scope** — the file list of the internal audit-scope record §2 (the
    surface actually delivered to the auditor — the script PARSES the
    document instead of copying it);
  - **S3 · degrade curve** — the floor when the least-covered %1/%5/%10
    files are REMOVED (`SCN_DROP="5 20"` customizes the curve);
  - **S4 · without the experimental layer** — the remaining product
    floor when the K1-gated BIP-360/P2MR rule engine (`bip360.rs`) is
    excluded.
- **Output:** `SCN_*=…` one-line summary + `SCENARIO=REPORTED`; exit 2
  when there is no data. The FUNCTION floor exists in the llvm-cov JSON
  only at the workspace total — it is deliberately NOT fabricated per
  scenario (absent = absent).
- **Evidence:** the measured record lives in `CHANGELOG.md`'s Round-36
  entry; this is NOT a gate leg — thresholds change only in
  `coverage_gate.sh` (the single-home rule, BAKICI §5).

### 4.62. The funded live lap (Round 37 · closing-plan P5): ArkFaucet → vault-fund → rotate → psbt-live

- **The faucet wall, re-checked (18 October 2026):** §4.54's ruling that
  "every known faucet sits behind CAPTCHA" now has ONE exception:
  **arkfaucet.com** publishes a plain `POST /api/request` interface
  (`openapi.json` + a site Skill `SKILL.md`) that needs **no account, key,
  cookie or CAPTCHA** (Round 31's hint still holds — bitcoin-faucet-shell's
  "No more API, really" notice: the APIs closed in 2025-08 are still
  closed). Operating limits: `429` + `Retry-After: 60s` (the script stops
  instead of looping against the IP: `scripts/signet_faucet.sh` halts on
  429 and refuses to retry the same address), an approved-rail budget of
  ~4,965 sats/day, allowed amounts 500/1,000/1,500. No second verifiable
  Turnstile-free source was found. Verdict: programmatic funding is
  POSSIBLE through that one exception — 3,000 sats collected (2 × 1,500,
  78 conf; remaining rail budget 1,965).
- **The budget-killing fee discovery (script fix):** `fallback_fee=0.0002`
  in `bitcoin.conf` is **20 sat/vB** — one `sendtoaddress` could eat the
  whole faucet budget; `vault-fund` now passes an explicit `fee_rate=`
  (tunable via `FEE_RATE`; real run: `FEE_RATE=2` → 464 sats for the
  2-in-2-out tx, change 436). Second script bug: `$2` was BOTH the datadir
  and `vault-fund [sats]` — `vault-fund 2100` poisoned the datadir with
  "2100" and killed every RPC; argument parsing is now per-subcommand.
- **The seven-step honest lap (live · bitcoind v28.2 · `~/.signet-qsv` ·
  blocks 326865–326868 · 18 October 2026):**

| # | Step | Exit | Evidence |
|---|---|---|---|
| 1 | `vault-fund 2100` (`FEE_RATE=2`) | exit 0 | tx `7a44d704…` · block 326865 · fee 464 sat |
| 2 | `vault-rotate --fee-sat 800 --last-refresh-block tip−30000` | **exit 0 (FUNDED)** | tx `e7d6c8ef…` · block 326866 · 2,100 → 1,300 self-churn · CSV clock reset · both heir attestations re-sealed · rotation-state v2 written |
| 3 | `psbt-live --build-only` (default 1,500 fee) | **exit 1** | honest rejection: `fee exceeds the aggregate input value` — post-rotation 1,300-coin is under the default fee; the coin was never touched |
| 4 | `psbt-live --fee-sat 800 --dir signet-artifacts` | **exit 0** | build (BIP-371 ✓) → two device signatures ✓ → libbitcoinconsensus ACCEPT → **mempool accepted**: tx `02703d3f…` |
| 5 | `vault-dashboard --network signet` | exit 0 | live endpoint · heartbeat OK · inheritance LOCKED |
| 6 | `watchtower --network signet --last-refresh-block tip−2` | exit 0 | read-only · 1 live coin (1,300 sat) · `all clear` recorded |
| 7 | `vault-rotate --state-dir signet-artifacts` | **exit 1** | `rotation not due: 3/12960 idle — refusing an early re-rotation` |

- **The measurement trap (for the operator following us):** non-wallet txs
  cannot be watched through the wallet — `gettransaction` answers `-5` and
  a polling loop silently reads `confirmations=0`; BOTH confirmations were
  read only from a block walk / `gettxout <txid> 0` (the rotation landed in
  block 326866). Never build a wait loop on a wallet poll.
- **The `lifecycle` flow:** the `--build-only` leg was pinned to the
  default 1,500 fee (an honest rejection once the rotation leaves a small
  coin); `FEE_SAT=800 bash scripts/signet_setup.sh lifecycle` now passes
  `--fee-sat` to BOTH legs.
- **Acceptance criterion (ROADMAP.md D8):** "the live loop 4/4 → **5/5**
  (funded rotate included)" → met: seven steps (funding · funded rotate ·
  honest fee rejection · funded spend · dashboard · watchtower ·
  early-rotate refusal), every one its real exit code. **P6's funding
  dependency is GONE**, and the spend tx confirmed too: **`02703d3f…`
  confirmed in block 326869** — a three-link chain: 326865 funding →
  326866 rotation → 326869 spend (a real on-chain spend, not an
  anecdote).

### 4.63. Documentation audit (Round 40): `docs-audit`

`docs_sync` fails the build when the published tree drifts; a failed assert
does not answer "what drifted, in which module?". `docs-audit` prints the same
walls as DATA — an operator sees a module number, a reviewer diffs two runs.

```bash
cargo run -p qsv-cli -- docs-audit                 # human table
cargo run -p qsv-cli -- docs-audit --json          # ONE JSON document (no banner)
cargo run -p qsv-cli -- docs-audit --dir docs      # another tree
```

The library is a single English edition (`docs/NN_*.md`, indexed by
`docs/README.md`). Walls (red = exit 1): a gap or duplicate in the module set,
a title that does not open `# Module NN`, section numbers that do not strictly
increase, a `###` subsection without its `##` section, an odd code-fence count
(an unclosed block), a relative link that resolves to nothing (file targets on
disk, pure `#anchor` targets against the document's own headings), the BIP-360
snapshot missing from module 11 or present anywhere else, and any Turkish text
in the published tree — the corpus is archived outside the public repository.

Exit contract: 0 in sync · 1 drift · 2 unreadable/empty tree (stdout EMPTY —
an unreadable tree must never look like a green report).

## 5. Emergency procedures

```bash
cargo run -p qsv-cli -- leaf-budget            # measured per-leaf witness/vB/fee tables
cargo run -p qsv-cli -- wots-params            # the 520-byte impossibility result
cargo run -p qsv-cli -- kit-seed split --threshold 3 --shares 5
cargo run -p qsv-cli -- kit-seed split --format slip39 --threshold 2 --shares 3
cargo run -p qsv-cli -- kit-seed combine --format slip39 --share "word1 …" --share "…"
```

- **WOTS+ escape layer (post-Q-Day):** `qsv-core::wots` implements RFC 8391 over SHA-256 only (n=32, w=16 → 67 chains, 2,144-byte keys/signatures, one-time per seal). It is wired into the MAST as **leaf 4**, a 37-byte commit-reveal: `OP_DUP OP_SHA256 <H(pk_em)> OP_EQUALVERIFY OP_CHECKSIG`. The plaintext destination key exists only inside the sealed offline kit; the on-chain digest binds the kit contents.
- **BIP-342 discipline (empirical):** witness elements above 520 bytes are consensus-ILLEGAL (pinned on the Bitcoin Core engine: 64 B accepted, 521 B rejected), so the 2,144-byte seal never touches the chain — it is verified air-gapped before broadcast and consensus sees hash-lock + classical Schnorr only (T6/T7 consensus-proven).
- **Parameter-space verdict:** `wots-params` proves no Winternitz parameter fits a 32-byte digest inside the 520 B cap (global minimum 1,088 B at w=256) and truncation bottoms out at 14 bytes = 112 bits — the structural reason leaf 4 is commit-reveal.
- **Measured budgets:** `leaf-budget` builds a real signed reference spend per leaf and prints script/control/witness sizes, vbytes/weight, the BIP-342 margin and a fee table — measurements, never estimates.
- **Kit-seed sharing:** `kit-seed split/combine` implements GF(256) Shamir k-of-n with a 4-byte fail-closed integrity tag, and `--format slip39` emits interoperable **SLIP-0039** mnemonics (20/33 words, RS1024 checksum, Feistel+PBKDF2 passphrase) that any SLIP-0039 wallet can recombine. Either way, `combine` proves the recovered seed reproduces the WOTS+ kit seal; fewer than the threshold fails the tag — never a wrong key.
- **K1 tracker:** `bip360-status [--online]` audits the migration plan offline and, with `--online`, diffs the recorded snapshot against the live `bip-0360.mediawiki` header; any delta exits 1 (Module 11).

## 6. Security contract (operator)

- [ ] Replace `demo_keys` with hardware-derived keys; the enclave key lives only in the TEE.
- [ ] Provision the real co-signer (`qsv-cosigner` provisioning file, allowlist, persistent keys) — dev-mode attestation is for tests only.
- [ ] Run the signet round-trip; rehearse the inheritance settlement with test coins.
- [ ] Verify the NUMS seed text matches the frozen test value; document it in the estate letter.
- [ ] Back up: seed material per heir, PQC identity attestations, the policy descriptor, and the SLIP-0039/native shares in **separate** locations.
- [ ] Never generate the `qsv-pqc` signing key on a networked machine; keep the heartbeat period below 180 days (90 recommended).
- [ ] Re-run `verify-estate` yearly, and `bip360-status --online` whenever the BIP moves.

**Diagnostics:** exit code and stderr carry the failure stage (gate, covenant, consensus, RPC); consensus errors surface verbatim from `libbitcoinconsensus`. The e2e tests (`qsv-node/tests/e2e_bitcoind.rs`, `psbt_device_roundtrip.rs`, `qsv-cli/tests/regtest_estate.rs`) double as reference integration scripts on a fresh regtest node: mining, funding, unvaulting, CSV waiting, settling, the PSBT device round trip and the estate-letter audit.

### 4.64. One-screen console (Round 39): `console`

`vault-dashboard` prints the three clocks as TEXT; what a family inherits is a
PAGE. `console` composes the same engines (`dashboard`, `estate`,
`taproot::watch_descriptors`) into one script-free HTML file — no network, no
keys, no external assets.

```bash
qsv-cli console --network signet --tip 900000 --last-refresh-block 899000 \
                --out vault.html                 # clocks + address + estate letter
qsv-cli console --tip 900000 --json              # ONE JSON document (no banner)
qsv-cli console --descriptor 'rawtr(…)#…'        # VERIFIES; mismatch = exit 1
```

1. **Inputs:** `--tip` (chain tip) and `--last-refresh-block` (last heartbeat);
   live RPC arrives in slice 2. Without `--date` the date is derived from the
   tip's approximate calendar day, so the same inputs yield the same bytes.
2. **Descriptor gate:** if the supplied `addr()/rawtr()` line (or the bare
   address) does not match this vault, the command exits **1** with EMPTY
   stdout; a valid-looking page for the wrong address is worse than none.
3. **Output:** one printable HTML file with the letter embedded and its
   SHA-256 on the page; `--json` gives the same snapshot under the
   `qsv-console/v1` schema.
4. **Limit:** demo keys are used (reference implementation); real vaults need
   production key provisioning and an independent audit — `STATUS.md` §2.

### 4.65. First run and prebuilt releases (Round 41 · D2): `demo`

Everything up to here assumed a Rust toolchain. D2 removes that assumption:
one download, one command, one page.

```bash
bash scripts/verify_release.sh qsv-cli-v2026.3.1-x86_64-unknown-linux-gnu.tar.gz \
     --repo <owner>/<repo>          # exit 0 verified · 1 refused · 2 incomplete
tar -xzf qsv-cli-v2026.3.1-x86_64-unknown-linux-gnu.tar.gz
./qsv-cli demo                      # → ./qsv-demo.html
./qsv-cli demo --out page.html --network regtest --tip 1000
./qsv-cli demo --json               # ONE bare document, schema qsv-demo/v1
```

1. **Offline by construction:** `demo` contacts nothing and signs nothing. The
   page is the SAME renderer as `console` (§4.64) — one builder, so the demo
   cannot drift from the surface it introduces; the test
   `demo_and_console_render_the_same_page_for_the_same_inputs` pins that as
   byte equality. Heights are illustrative, and the demo label says so on the
   page itself.
2. **Artifact before claim:** the command writes the page, READS IT BACK, and
   only then reports size and SHA-256; an unwritable path exits **1** with
   `cannot write …` — never a success line without the file.
3. **Machine output:** `--json` prints exactly one document (no banner):
   `schema`, `network`, `tip`, `offline`, absolute `out`, `bytes`,
   `html_sha256`, `address`, `letter_sha256`, `elapsed_ms`.
4. **Release pipeline** (`.github/workflows/release.yml`): five targets
   (x86_64/aarch64 Linux, x86_64/aarch64 macOS, x86_64 Windows), each built
   `--locked`; the binary's `--version` must equal the tag or the release
   fails; every target that can run on its own runner executes the offline
   first run before packaging; one `SHA256SUMS` covers every archive and is
   itself attested. **Provenance, not a maintainer key:** GitHub build
   provenance (Sigstore keyless) lets anyone run
   `gh attestation verify <archive> --repo <owner>/<repo>` and learn which
   workflow, commit and tag produced the file. A GPG signature over the
   binaries is deliberately absent — the key does not belong on a runner —
   and the release body states whether the git tag itself is signed instead
   of implying more.
5. **Limit:** the archives are unsigned by GPG and the demo keys are public
   fixtures. Neither is a security boundary; `STATUS.md` §1–2 draws the line.
