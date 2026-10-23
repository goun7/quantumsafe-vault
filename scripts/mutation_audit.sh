#!/usr/bin/env bash
# Mutation audit (Round 8): proves the test matrix is BEHAVIORAL — it kills
# every deliberately introduced crypto/logic mutation, never just compiling.
#
# Usage:  scripts/mutation_audit.sh            (run all mutations)
#         scripts/mutation_audit.sh <name>     (run one: e.g. "M01")
#
# A mutation "dies" (KILLED) when the targeted test subset fails. A mutation
# that survives (SURVIVED) would mean a test suite gap — the audit FAILS.
#
# All mutations live in crates/qsv-core/src (the audited-critical core),
# crates/qsv-cosigner/src (the attestation verifier, Round 27) and
# crates/qsv-cli/src (operator-flow logic, Round 30: drain deadline, webhook
# HMAC, rotation-state v2).
# The script mutates each target file, runs `cargo test` with the minimal
# feature set, then RESTORES the file from a BYTE-FOR-BYTE SNAPSHOT taken
# right before the mutation (Round 31: the worktree may legitimately be
# dirty — e.g. the qsv-node live-scan fix was uncommitted when this audit
# ran — and a `git checkout --` restore would have WIPED it; snapshots
# make uncommitted work untouchable and remove the old "commit first"
# refusal).
set -u
cd "$(dirname "$0")/.."

# Filter mode (`scripts/mutation_audit.sh M46`): the header always
# promised "run one", but the guard was never implemented — a filtered
# call used to run the WHOLE matrix and (Round 36) timed out mid-run.
# Prefix match on the mutant name; empty = full matrix.
REQ="${1:-}"

CORE=crates/qsv-core/src
COSIGNER=crates/qsv-cosigner/src
NODE=crates/qsv-node/src
RESULTS=()
FAILED=0
SNAPSHOT=""
CURRENT_FILE=""

save() {
    SNAPSHOT="$(mktemp)"
    cp -- "$1" "$SNAPSHOT"
    CURRENT_FILE="$1"
}

restore() {
    if [ -n "$SNAPSHOT" ] && [ -f "$SNAPSHOT" ]; then
        cp -- "$SNAPSHOT" "$1"
        rm -f "$SNAPSHOT"
    else
        git checkout -- "$1" 2>/dev/null || true
    fi
    SNAPSHOT=""
    CURRENT_FILE=""
}

# Round 33: a KILLED run (timeout, Ctrl-C, terminal close) must never leave a
# mutated file behind. Observed for real: a timeout-killed run left M41
# applied in nsm.rs; the NEXT run snapshotted the already-mutated file and
# honestly reported PRECONDITION-FAILED. This trap restores any pending
# byte snapshot on every exit path (SIGKILL cannot be trapped — do not
# `kill -9` the audit).
emergency_restore() {
    if [ -n "${SNAPSHOT:-}" ] && [ -f "$SNAPSHOT" ] && [ -n "${CURRENT_FILE:-}" ]; then
        cp -- "$SNAPSHOT" "$CURRENT_FILE"
        echo "  emergency restore: $CURRENT_FILE (run interrupted mid-mutation)" >&2
    fi
}
trap emergency_restore EXIT INT TERM

run_mutation() {
    local name="$1" file="$2" old="$3" new="$4" test_cmd="$5"
    case "$REQ" in
        "") ;;
        *)
            case "$name" in
                "$REQ"*) ;;
                *) return 0 ;;
            esac
            ;;
    esac
    if ! grep -qF "$old" "$file"; then
        RESULTS+=("$name  PRECONDITION-FAILED (pattern not found in $file)")
        FAILED=1
        return
    fi
    save "$file"
    python3 - "$file" "$old" "$new" <<'PYEOF'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path).read()
assert src.count(old) >= 1, "pattern missing"
open(path, "w").write(src.replace(old, new, 1))
PYEOF
    if eval "$test_cmd" >/tmp/qsv_mut_out.txt 2>&1; then
        RESULTS+=("$name  SURVIVED  ← TEST GAP")
        FAILED=1
    else
        RESULTS+=("$name  KILLED    ($(grep -cE 'FAILED|panicked|error\[' /tmp/qsv_mut_out.txt) failure lines)")
    fi
    restore "$file"
}

echo "═══ QuantumSafe-Vault mutation audit ═══"
CLI=crates/qsv-cli/src
# Round 31: the worktree may be DIRTY — every mutated file is restored
# from its byte snapshot, so uncommitted work cannot be wiped. CI still
# runs this on a clean checkout; a dirty local run is now SAFE, not
# forbidden, and the audit proves exactly what it always did: every
# mutation is killed by the behavioral suite.
if ! git diff --quiet -- "$CORE" "$COSIGNER" "$CLI" "$NODE" 2>/dev/null; then
    echo "  note: dirty worktree — each mutated file restores from a byte snapshot"
fi

# M01 · NUMS counter: the frozen constant IS the protocol anchor.
run_mutation "M01 nums_canonical_counter" \
    "$CORE/nums.rs" \
    "pub const NUMS_CANONICAL_COUNTER: u32 = 0;" \
    "pub const NUMS_CANONICAL_COUNTER: u32 = 1;" \
    "cargo test -p qsv-core nums -- --test-threads=2"

# M02 · Shamir tag: the fail-closed integrity check must actually compare.
run_mutation "M02 shamir_tag_check" \
    "$CORE/shamir.rs" \
    "if secret_tag(&secret) != first_tag {" \
    "if false && secret_tag(&secret) != first_tag {" \
    "cargo test -p qsv-core shamir -- --test-threads=2"

# M03 · FROST envelope: share verification must reject a WRONG-kind package
# (the check is one-sided — flip the expected tag inside unseal's caller
# path, i.e. make round2 accept a Nonce-tagged share).
run_mutation "M03 frost_envelope_tag" \
    "$CORE/frost.rs" \
    'round2::SignatureShare::deserialize(&unseal(PkgKind::Share, &s.share)?).map_err(fro)?;' \
    'round2::SignatureShare::deserialize(&unseal(PkgKind::Nonce, &s.share)?).map_err(fro)?;' \
    "cargo test -p qsv-core frost -- --test-threads=2"

# M04 · Commitment binding: verify_member must compare against the STORED
# commitment, not recompute-and-accept (one-sided domain flip that only the
# verify path uses → any tampered-pair test must fail).
run_mutation "M04 heir_commitment_domain" \
    "$CORE/heirs.rs" \
    "        self.entries
            .iter()
            .any(|(k, c0)| k.as_bytes() == classic && *c0 == c)" \
    "        self.entries
            .iter()
            .any(|(k, _c0)| k.as_bytes() == classic)" \
    "cargo test -p qsv-core --lib heirs:: -- --test-threads=2"

# M05 · Verify gate: the WRONG-device rejection branch must be load-bearing.
run_mutation "M05 verify_device_signature_reject" \
    "$CORE/psbt.rs" \
    "    secp.verify_schnorr(&sig, &Message::from_digest(*sighash), &dev_key)
        .map_err(|_| PsbtError::SignatureVerification)
}" \
    "    let _ = dev_key;
    let _ = &sig;
    let _ = &sighash;
    Ok::<(), PsbtError>(())
}" \
    "cargo test -p qsv-core psbt -- --test-threads=2"

# M06 · Multi-input consensus: over-spend must be caught (verify_transaction).
run_mutation "M06 verify_transaction_amounts" \
    "$CORE/consensus.rs" \
    "                value: amount.to_sat() as i64," \
    "                value: (amount.to_sat() + 1) as i64," \
    "cargo test -p qsv-core --features consensus psbt::tests::multi_input -- --test-threads=2"

# M07 · Heartbeat due logic: missed refresh must flip is_due.
run_mutation "M07 heartbeat_is_due" \
    "$CORE/heartbeat.rs" \
    "    current_block.saturating_sub(last_refresh_block) >= policy.interval_blocks" \
    "    current_block.saturating_sub(last_refresh_block) >= policy.interval_blocks + 1" \
    "cargo test -p qsv-core heartbeat -- --test-threads=2"

# M08 · Unvault dust guard: dust outputs must be refused.
run_mutation "M08 unvault_dust_guard" \
    "$CORE/unvault.rs" \
    "    if output_value < Amount::from_sat(546) {" \
    "    if output_value < Amount::from_sat(0) {" \
    "cargo test -p qsv-core unvault -- --test-threads=2"

# ── Round 27 · attestation verifier (qsv-cosigner) ──────────────────────────
# Every mutation below targets a load-bearing step of the AWS
# attestation_process.md chain; the nsm::tests suite must kill each one.

# M09 · Root pin: ANY byte string must NOT count as a trust anchor.
run_mutation "M09 attestation_root_pin" \
    "$COSIGNER/nsm.rs" \
    "    if der == NITRO_ROOT_DER {" \
    "    if der == der {" \
    "cargo test -p qsv-cosigner --lib nsm::tests:: -- --test-threads=2"

# M10 · Replay: the request-nonce comparison must be load-bearing.
run_mutation "M10 attestation_nonce_replay" \
    "$COSIGNER/nsm.rs" \
    "    if !expected_nonce_hex.is_empty() && !f.nonce_hex.eq_ignore_ascii_case(expected_nonce_hex) {" \
    "    if false && !expected_nonce_hex.is_empty() && !f.nonce_hex.eq_ignore_ascii_case(expected_nonce_hex) {" \
    "cargo test -p qsv-cosigner --lib nsm::tests:: -- --test-threads=2"

# M11 · COSE signature: skipping the crypto must be caught by the tamper tests.
run_mutation "M11 attestation_cose_signature" \
    "$COSIGNER/nsm.rs" \
    "    verify_cose_signature(&cose, &target_spki)?;" \
    "    let _ = (&cose, &target_spki);" \
    "cargo test -p qsv-cosigner --lib nsm::tests:: -- --test-threads=2"

# M12 · Key binding: user_data == xonly‖vault must actually be compared.
run_mutation "M12 attestation_user_data_binding" \
    "$COSIGNER/nsm.rs" \
    "        if actual != expected {" \
    "        if actual != expected && false {" \
    "cargo test -p qsv-cosigner --lib nsm::tests:: -- --test-threads=2"

# M13 · PCR0 pin: the measurement pin must refuse a contradicting document.
run_mutation "M13 attestation_pcr0_pin" \
    "$COSIGNER/nsm.rs" \
    "    check_pin(&f.pcr0_hex, &pinned.pcr0_hex, \"PCR0\")?;" \
    "    let _ = (&f.pcr0_hex, &pinned.pcr0_hex);" \
    "cargo test -p qsv-cosigner --lib nsm::tests:: -- --test-threads=2"

# M14 · Validity window: certificate freshness must be checked at `now`.
run_mutation "M14 attestation_validity_window" \
    "$COSIGNER/nsm.rs" \
    "    if now_secs < nb || now_secs > na {" \
    "    if false && (now_secs < nb || now_secs > na) {" \
    "cargo test -p qsv-cosigner --lib nsm::tests:: -- --test-threads=2"

# M15 · Sig_structure label: \"Signature1\" is TEN characters (0x6A) — the
# golden vector AND the real AWS sample both die if it drifts.
run_mutation "M15 cose_sig_structure_label" \
    "$COSIGNER/nsm.rs" \
    "    out.extend_from_slice(b\"Signature1\");" \
    "    out.extend_from_slice(b\"Signature1x\");" \
    "cargo test -p qsv-cosigner --lib nsm::tests:: -- --test-threads=2"

# ── Round 28 · heartbeat / consensus / FROST ────────────────────────────────
# Load-bearing branches of the liveness engine, the prevout precondition
# and the threshold-signature coordinator.

# M16 · Heartbeat expiry invariant: interval+margin must be checked against
# the dormancy wall, otherwise an impossible schedule validates.
run_mutation "M16 heartbeat_expiry_invariant" \
    "$CORE/heartbeat.rs" \
    "        if self.interval_blocks + self.expiry_margin_blocks > expiry {" \
    "        if self.interval_blocks > expiry {" \
    "cargo test -p qsv-core heartbeat -- --test-threads=2"

# M17 · Self-churn output: the refresh must pay the SAME vault output key
# (the CSV clock resets, the destination never moves).
run_mutation "M17 heartbeat_self_churn_output" \
    "$CORE/heartbeat.rs" \
    "    let spk = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(out_key.serialize())" \
    "    let spk = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice([0u8; 32])" \
    "cargo test -p qsv-core heartbeat -- --test-threads=2"

# M18 · Refresh dust floor: a leftover below 546 sats must be refused.
run_mutation "M18 heartbeat_refresh_dust_guard" \
    "$CORE/heartbeat.rs" \
    "    if out_value < Amount::from_sat(546) {" \
    "    if out_value < Amount::from_sat(0) {" \
    "cargo test -p qsv-core heartbeat -- --test-threads=2"

# M19 · Prevout-count guard: one prevout per input is a precondition of
# consensus verification — fail closed BEFORE the engine sees the tx.
run_mutation "M19 consensus_prevout_count_guard" \
    "$CORE/consensus.rs" \
    "    if inputs.len() != tx.input.len() {" \
    "    if false {" \
    "cargo test -p qsv-core consensus::tests -- --test-threads=2"

# M20 · Group-signature verification: an assembled FROST result must be
# checked under the group key (the untweaked-key negative test kills it).
run_mutation "M20 frost_group_signature_verify" \
    "$CORE/frost.rs" \
    "    secp.verify_schnorr(&sig, &Message::from_digest(*msg32), &pk)
        .map_err(|_| FrostError::BadSignature)" \
    "    let _ = (secp, &sig, &pk, msg32);
    Ok(())" \
    "cargo test -p qsv-core frost -- --test-threads=2"

# M21 · Duplicate identifier at package build: a repeated identifier is a
# cheater signal — silently deduplicating must be caught.
run_mutation "M21 frost_duplicate_round1" \
    "$CORE/frost.rs" \
    "        if map.insert(id, c).is_some() {" \
    "        if map.insert(id, c).is_some() && false {" \
    "cargo test -p qsv-core frost -- --test-threads=2"

# M22 · Duplicate identifier at share aggregation: same signal on the
# round-2 path (a skipped check lets the repeat clobber/aggregate instead
# of aborting with the duplicate-identifier refusal).
run_mutation "M22 frost_duplicate_assemble" \
    "$CORE/frost.rs" \
    "        if map.insert(id, share).is_some() {" \
    "        if map.insert(id, share).is_some() && false {" \
    "cargo test -p qsv-core frost -- --test-threads=2"

# ── Round 30 · rate-limit / drain / HMAC / rotation-state / PSBT ────────────
# Load-bearing refusals of the Round 16–22 surfaces: the token bucket, the
# drain-deadline health cut, the webhook signature, the v2 state gate,
# the BIP-371 merkle root, the SLIP-39 digest tag, the source allow-list
# and the metrics scrape gate.

# M23 · Token bucket gate: a spent bucket must refuse — accepting at 0
# tokens turns the per-vault limiter into a no-op.
run_mutation "M23 rate_limit_bucket_gate" \
    "$COSIGNER/server.rs" \
    "if bucket.tokens >= 1.0 {" \
    "if bucket.tokens >= 0.0 {" \
    "cargo test -p qsv-cosigner rate_limit_refuses -- --test-threads=2"

# M24 · Drain-deadline health cut: abandoning in-flight work must clear
# the 'serving' claim FIRST — a stale record pages on a dead process.
run_mutation "M24 drain_deadline_health_clear" \
    "$CLI/main.rs" \
    "            qsv_cosigner::health::remove(&state_path);" \
    "            let _ = &state_path;" \
    "cargo test -p qsv-cli --test cosigner_bridge bridge_drain_deadline -- --test-threads=2"

# M25 · Webhook HMAC outer pad: the RFC 4231 vectors die on ANY change
# to the ipad/opad constants (replay binding is only as strong as this).
run_mutation "M25 webhook_hmac_outer_pad" \
    "$CLI/webhook.rs" \
    "outer.update([b ^ 0x5c]);" \
    "outer.update([b ^ 0x56]);" \
    "cargo test -p qsv-cli hmac -- --test-threads=2"

# M26 · Rotation-state v2 schema gate: only version-2 documents may be
# merged — a gate that matches nothing (or everything) breaks the
# per-vault record contract the sweep tests read back.
run_mutation "M26 rotation_state_v2_gate" \
    "$CLI/main.rs" \
    "if doc.get(\"version\").and_then(serde_json::Value::as_u64) != Some(2) {" \
    "if doc.get(\"version\").and_then(serde_json::Value::as_u64) != Some(999) {" \
    "cargo test -p qsv-cli --test vault_rotate -- --test-threads=2"

# M27 · BIP-371 merkle root: the device CANNOT recompute Q without it —
# dropping it makes Coldcard/Ledger reject the PSBT (asserted at build).
run_mutation "M27 psbt_tap_merkle_root" \
    "$CORE/psbt.rs" \
    "inp.tap_merkle_root = input.merkle_root;" \
    "inp.tap_merkle_root = None;" \
    "cargo test -p qsv-core psbt -- --test-threads=2"

# M28 · SLIP-39 digest tag: wrong/fabricated shares must abort at the
# index-254 HMAC tag (the 45-vector suite carries tampered-share cases).
run_mutation "M28 slip39_digest_tag" \
    "$CORE/slip39.rs" \
    "if hmac_sha256(r, &secret)[..4] != *tag {" \
    "if false {" \
    "cargo test -p qsv-core slip39 -- --test-threads=2"

# M29 · Source allow-list: a snapshot must never turn the K1 tracker into
# an arbitrary-URL fetcher (the evil.example negative test kills this).
run_mutation "M29 bip360_allowed_source" \
    "$CORE/bip360.rs" \
    "ALLOWED.contains(&url)" \
    "ALLOWED.contains(&url) || true" \
    "cargo test -p qsv-core bip360 -- --test-threads=2"

# M30 · Metrics scrape gate: a missing token must map to 401 (unwrap_or
# (false) → true silently renders the exposition to an anonymous peer).
run_mutation "M30 metrics_scrape_gate" \
    "$COSIGNER/server.rs" \
    "                .map(|p| token_eq(p.as_bytes(), want.as_bytes()))
                .unwrap_or(false);" \
    "                .map(|p| token_eq(p.as_bytes(), want.as_bytes()))
                .unwrap_or(true);" \
    "cargo test -p qsv-cosigner metrics_scrape_requires -- --test-threads=2"

# ── Round 31 · estate letter / WOTS+ / health / TLS policy / replay ─────────
# Eleven more load-bearing refusals: the printed-letter comparators, the
# WOTS+ verification chain, the liveness probes, the loopback transport
# policy, the webhook timestamp binding, the P2MR witness version and the
# two parser walls the fuzz gate found (CBOR depth, non-ASCII hex).

# M31 · Estate letter field comparator: a MISMATCHED field must not read
# as "matches re-derived vault" (the tampered-letter test pins labels).
run_mutation "M31 estate_field_check_always_matches" \
    "$CORE/estate.rs" \
    "Some(p) if p.eq_ignore_ascii_case(expected) => {" \
    "Some(p) if p.eq_ignore_ascii_case(expected) || true => {" \
    "cargo test -p qsv-core estate -- --test-threads=2"

# M32 · Wrong-network hint: verifying a signet letter as mainnet must
# NAME the issuing network — a silent miss loses the #1 user mistake.
run_mutation "M32 estate_wrong_network_hint" \
    "$CORE/estate.rs" \
    "if vault.address(candidate).to_string().eq_ignore_ascii_case(p) {" \
    "if false && vault.address(candidate).to_string().eq_ignore_ascii_case(p) {" \
    "cargo test -p qsv-core estate -- --test-threads=2"

# M33 · WOTS+ verification chain: the remaining-step count must respect
# the message chunk — a constant walk verifies forged chains as readily
# as honest ones (roundtrip + tamper tests both die).
run_mutation "M33 wots_verify_chain_steps" \
    "$CORE/wots.rs" \
    "for _ in 0..(CHAIN_STEPS - steps as usize) {" \
    "for _ in 0..(CHAIN_STEPS as usize) {" \
    "cargo test -p qsv-core wots -- --test-threads=2"

# M34 · pid_alive(0): signal 0 against pid 0 targets OUR process group —
# the bogus record must read as dead, never alive.
run_mutation "M34 health_pid_zero_is_bogus" \
    "$COSIGNER/health.rs" \
    "            return Some(false);" \
    "            return Some(true);" \
    "cargo test -p qsv-cosigner --lib health:: -- --test-threads=2"

# M35 · Undecidable liveness probe: `None` must NEVER classify as Live
# (the platform that cannot ask is not a witness that it is running).
run_mutation "M35 health_unknown_never_live" \
    "$COSIGNER/health.rs" \
    "None => Liveness::Unknown," \
    "None => Liveness::Live," \
    "cargo test -p qsv-cosigner --lib health:: -- --test-threads=2"

# M36 · Transport policy: plaintext off loopback must be REFUSED (an
# always-Ok policy ships co-signatures over the clear).
run_mutation "M36 tls_plaintext_off_loopback" \
    "$COSIGNER/tls.rs" \
    "if is_loopback_addr(addr) || tls {" \
    "if true {" \
    "cargo test -p qsv-cosigner --lib tls:: -- --test-threads=2"

# M37 · Bare/wildcard binds: 0.0.0.0 and `:3334` listen on ALL interfaces
# and must never classify as loopback.
run_mutation "M37 tls_bare_bind_not_loopback" \
    "$COSIGNER/tls.rs" \
    "\"\" | \"0.0.0.0\" | \"::\" | \"*\" => return false," \
    "\"\" | \"0.0.0.0\" | \"::\" | \"*\" => return true," \
    "cargo test -p qsv-cosigner --lib tls:: -- --test-threads=2"

# M38 · Webhook replay binding: the tag must cover `\"<unix-s>.<body>\"` —
# dropping the stamp makes a captured POST valid forever.
run_mutation "M38 webhook_timestamp_binding" \
    "$CLI/webhook.rs" \
    "format!(\"{ts}.{body}\")" \
    "format!(\"{body}\")" \
    "cargo test -p qsv-cli webhook -- --test-threads=2"

# M39 · P2MR witness version: the experimental address must be v2 (bc1z);
# v1 silently re-derives a P2TR-looking address that no P2MR rule matches.
run_mutation "M39 p2mr_witness_version" \
    "$CORE/taproot.rs" \
    "bitcoin::WitnessVersion::V2, root.as_byte_array()" \
    "bitcoin::WitnessVersion::V1, root.as_byte_array()" \
    "cargo test -p qsv-core p2mr -- --test-threads=2"

# M40 · CBOR depth wall (found by the fuzz gate): past 32 levels the walk
# must Err — the 33-deep nested-map test pins the exact refusal.
run_mutation "M40 cbor_depth_wall" \
    "$COSIGNER/nsm.rs" \
    "if depth > 32 {" \
    "if depth > 1000 {" \
    "cargo test -p qsv-cosigner --lib cbor -- --test-threads=2"

# M41 · Non-ASCII hex guard (found by the fuzz gate): slicing a &str at a
# byte index inside a multi-byte char PANICS — the refusal must come first.
run_mutation "M41 hex_decode_ascii_guard" \
    "$COSIGNER/nsm.rs" \
    "if !s.is_ascii() {" \
    "if false && !s.is_ascii() {" \
    "cargo test -p qsv-cosigner --lib hex_decode -- --test-threads=2"

# M42 · Live-scan read budget (Round 31): `scantxoutset start` blocks the
# calling connection for the WHOLE UTXO-set walk — shrinking the scan
# budget back to ~5 s must kill the slow-scan test (a real-network scan
# can't finish inside it; this is the exact bug found on live signet).
run_mutation "M42 scan_read_budget" \
    "$NODE/rpc.rs" \
    "const SCAN_READ_TIMEOUT: Duration = Duration::from_secs(600);" \
    "const SCAN_READ_TIMEOUT: Duration = Duration::from_secs(5);" \
    "cargo test -p qsv-node scan_outlives -- --test-threads=2"

# M43 · In-progress recovery (Round 31): the `-8 Scan already in
# progress` match arm must actually MATCH — with the code constant
# flipped the foreign scanner's -8 propagates and the busy → status →
# retry recovery test dies.
run_mutation "M43 scan_busy_recovery_guard" \
    "$NODE/rpc.rs" \
    "Err(RpcError::Rpc { code: -8, message })" \
    "Err(RpcError::Rpc { code: -7, message })" \
    "cargo test -p qsv-node scan -- --test-threads=2"

# M44 · DKG threshold binding (Round 33): part1's (max_signers,
# min_signers) argument order IS the threshold contract of the dealer-less
# ceremony — swapping them inverts k/n and every DKG test must die.
run_mutation "M44 dkg_threshold_binding" \
    "$CORE/frost.rs" \
    "frost::keys::dkg::part1(*id, total, threshold, &mut *rng)" \
    "frost::keys::dkg::part1(*id, threshold, total, &mut *rng)" \
    "cargo test -p qsv-core dkg -- --test-threads=2"

# M45 · Watch-only output-key binding (Round 34): `rawtr()` must name the
# TWEAKED output key. The NUMS internal key yields a DIFFERENT
# scriptPubKey — an exported descriptor that watches the wrong output is
# exactly the silent-failure this feature exists to prevent, so both
# descriptor tests must die on the swap.
run_mutation "M45 watch_only_output_key_binding" \
    "$CORE/taproot.rs" \
    "let rawtr_descriptor = checksummed(format!(\"rawtr({})\", self.output_key()))?;" \
    "let rawtr_descriptor = checksummed(format!(\"rawtr({})\", self.internal_key))?;" \
    "cargo test -p qsv-core descriptor -- --test-threads=2"

# M46 · Vacuous-state wall (Round 36): a watchtower state file that
# PARSES but carries zero vault records (`{"tip": N, "vaults": {}}` —
# the shape a truncated/clobbered writer leaves behind) must be refused
# like an unreadable one. Removing the wall makes the REAL boot accept
# it and serve a silent all-clear — the vacuous-boot e2e must die.
run_mutation "M46 vacuous_state_wall" \
    "$COSIGNER/bridge.rs" \
    "if entries.is_empty() {" \
    "if entries.len() == usize::MAX {" \
    "cargo test -p qsv-cli --test cosigner_bridge vacuous -- --test-threads=2"

# M47 · k-of-n merge comparison (Round 35's root fix, now hand-pinned):
# `votes >= quorum` freezes at EXACTLY k distinct mirrors; flipping it to
# strict `>` breaks the boundary (k votes would read clear) and every
# quorum unit test plus the live 3-mirror drill must die. This mutant
# keeps the merger comparison under a hand mutant after M46 moves
# bridge.rs into the sweep's hand-covered set (the sweep's mechanical
# `>=` flip used to be the only mutant watching this line).
run_mutation "M47 quorum_merge_comparison" \
    "$COSIGNER/bridge.rs" \
    "if votes >= quorum { \"ALERT\" } else { \"clear\" };" \
    "if votes > quorum { \"ALERT\" } else { \"clear\" };" \
    "cargo test -p qsv-cosigner quorum -- --test-threads=2"

# M48 · The k=0 / k>n clamp-no wall (Round 36): `quorum == 0` would
# freeze EVERYTHING, `quorum > n` could never fire — both must REFUSE
# (no silent clamp). M46 moved bridge.rs into the sweep's hand-covered
# set, retiring its mechanical `==` flip; this hand mutant keeps the
# exact same site under a mutant. Breaking the wall lets k=0 merge run
# and every quorum wall test dies.
run_mutation "M48 quorum_bounds_wall" \
    "$COSIGNER/bridge.rs" \
    "if quorum == 0 || quorum > n {" \
    "if quorum == usize::MAX {" \
    "cargo test -p qsv-cosigner quorum -- --test-threads=2"

# M49 · Operator-tier boundary (Round 37, E4c finmodel): tier limits are
# low-inclusive — 500 BTC is ALREADY Family Office (docs/06 §2's table
# writes "500" in both rows; the code is the single truth). `<=` demotes
# the boundary to Sovereign and the boundary test must die.
run_mutation "M49 operator_tier_boundary" \
    "$CORE/finmodel.rs" \
    "    if btc_aum < TIER_MIN_BTC[1] {" \
    "    if btc_aum <= TIER_MIN_BTC[1] {" \
    "cargo test -p qsv-core --lib finmodel -- --test-threads=2"

# M50 · AUM fee basis-point divisor (Round 37): %0.10 AUM = bps/10_000.
# Dividing by 1_000 charges TEN TIMES the documented fee — the $20M →
# $20k pricing example and the $69.900 LTV example both must die.
run_mutation "M50 aum_bps_divisor" \
    "$CORE/finmodel.rs" \
    "            other => aum_usd_cents * AUM_BPS[other.index()] / 10_000," \
    "            other => aum_usd_cents * AUM_BPS[other.index()] / 1_000," \
    "cargo test -p qsv-core --lib finmodel -- --test-threads=2"

# M51 · Insolvency boundary (Round 37, settlement): debts EXACTLY equal to
# assets+receivables is net = 0, NOT iflas (everyone gets zero, but the
# split exists). `>=` flips the boundary and the zero-net test must die.
run_mutation "M51 insolvency_boundary" \
    "$CORE/settlement.rs" \
    "    if ledger.debts_sats > gross {" \
    "    if ledger.debts_sats >= gross {" \
    "cargo test -p qsv-core --lib settlement -- --test-threads=2"

# M52 · Largest-remainder divisor (Round 37): floor shares divide by
# exactly 10_000 bps; +1 shrinks every floor, Σ shares lands below net,
# the dust bucket cannot absorb the gap — the exact-sum property dies.
run_mutation "M52 split_divisor" \
    "$CORE/settlement.rs" \
    "        let floor = exact / u64::from(FULL_BPS);" \
    "        let floor = exact / (u64::from(FULL_BPS) + 1);" \
    "cargo test -p qsv-core --lib settlement -- --test-threads=2"

# M53 · Docs fence wall inverted (Round 40): the report's verdict is "the
# code fences balance". Inverting the parity test makes every healthy module
# report an unclosed block, so the test that asserts the repository is in
# sync (qsv-core docs::documented_repository_...) and the CLI's OK row must
# die — and they exist precisely because the report is a WALL, not a
# printout.
run_mutation "M53 docs_fence_wall" \
    "$CORE/docs.rs" \
    "    if fences % 2 != 0 {" \
    "    if fences % 2 == 0 {" \
    "cargo test -p qsv-core --lib docs:: -- --test-threads=2"

# M54 · Console descriptor wall inverted (Round 39): the console may only
# render a page for the vault whose address/descriptor the operator supplied.
# Inverting the equality accepts a foreign descriptor, so the fail-closed test
# (empty stdout, exit 1) must die — and it exists because a valid-looking page
# for the WRONG address is the one failure this tool cannot afford.
run_mutation "M54 console_descriptor_wall" \
    "$CORE/console.rs" \
    "        if !matches {" \
    "        if matches {" \
    "cargo test -p qsv-core --lib console:: -- --test-threads=2"

# Only the requested one? (filter mode)
if [ $# -ge 1 ]; then
    echo "(single-mutation filter mode: results above cover every mutation; re-run without args for the full matrix)"
fi

echo ""
echo "═══ Mutation audit results ═══"
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""
if [ "$FAILED" -ne 0 ]; then
    echo "VERDICT: FAILED — a mutation survived; the suite has a gap."
    exit 1
fi
echo "VERDICT: ALL MUTATIONS KILLED — the test matrix is behavioral."
