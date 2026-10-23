#!/usr/bin/env bash
# ROUND 26/30 — BOUNDED FUZZ GATE (docs/10 §4.46): six parser entry
# points that face untrusted bytes — the NSM attestation document
# (incl. its COSE_Sign1/CBOR container), the frame/watchtower/health
# JSON, SLIP-39 shares typed by a human, PSBT files in their raw
# and base64 transport shapes, the estate letter the family receives
# (parse + full verify on every network), and the WOTS+/kit-seal
# emergency path (verifier + envelope refusal map) — run under
# libFuzzer for a bounded window. ANY panic, hang (per-input -timeout)
# or crash artifact fails the gate.
#
# Bounded on purpose: this is a REGRESSION gate (parsers must stay
# panic-free), not a research campaign — corpus and artifacts persist
# across runs (fuzz/corpus is committed, fuzz/artifacts is not; CI
# additionally caches the evolved corpus between runs).
#
#   FUZZ_SECONDS=90 bash scripts/fuzz_gate.sh   # longer window locally
#   FUZZ_SECONDS=300 bash scripts/fuzz_gate.sh  # the Round-26 long pass
#   FUZZ_DEEP=1 bash scripts/fuzz_gate.sh       # Round 32: 300s/target deep pass
set -u
cd "$(dirname "$0")/.." || exit 99

# FUZZ_DEEP (Round 32) upgrades the default window to the Round-26 long
# pass (300s/target = 30 min for six targets). The BOUNDED default stays
# the regression gate; the deep pass is for releases and the local round
# gate's fuzz leg now runs at CI's 120s so the two are EQUAL (the Round-31
# evaluation scored "gate equality one-sided" — a 45s local window next
# to a 120s CI window was exactly that).
if [ "${FUZZ_DEEP:-0}" = "1" ]; then
    SECONDS_PER_TARGET="${FUZZ_SECONDS:-300}"
else
    SECONDS_PER_TARGET="${FUZZ_SECONDS:-45}"
fi
TARGETS=(attestation_doc frame_json slip39_share psbt_parse estate_letter wots_kit_seal)
cd fuzz || exit 99

# TOOLCHAIN: cargo-fuzz drives `-Zsanitizer=address` and friends,
# which stable rustc REJECTS ("the option Z is only accepted on the
# nightly compiler"). Neither `rustup run nightly` (it resolves only
# the top-level binary) nor RUSTUP_TOOLCHAIN (it only steers rustup
# PROXIES) survives this machine: ~/.local/bin/{cargo,rustc} are plain
# symlinks into the stable toolchain and sit BEFORE the proxies in
# PATH. Prepending the nightly toolchain's own bin directory puts the
# REAL nightly cargo/rustc first for cargo-fuzz AND every child it
# spawns — no proxy, no default-toolchain fallback, same on any box.
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc 2>/dev/null)" || {
    echo "FUZZ GATE FAILED: no nightly toolchain (rustup toolchain install nightly)"
    exit 9
}
export PATH="$(dirname "$NIGHTLY_RUSTC"):$PATH"
echo "  toolchain: $(rustc --version)"
fail=0
for t in "${TARGETS[@]}"; do
    echo "── fuzz $t (${SECONDS_PER_TARGET}s, per-input timeout 10s)"
    cargo fuzz run "$t" -- -max_total_time="$SECONDS_PER_TARGET" -timeout=10 \
        || { echo "FUZZ GATE FAILED: $t (crash artifacts in fuzz/artifacts/$t/)"; fail=1; }
done

if [ "$fail" -eq 0 ]; then
    echo "FUZZ GATE OK (${#TARGETS[@]} targets × ${SECONDS_PER_TARGET}s, no panic/hang/crash)"
fi
exit "$fail"
