#!/usr/bin/env bash
# LOCAL ROUND GATE (Round 31): the EXACT mirror of .github/workflows/ci.yml's
# eleven jobs, runnable on any machine — the answer to "CI is one billing
# outage away from blind" (docs/10 §4.55). Every leg is TIMED, and a leg
# that finishes in 0 seconds where it must do real work (the empty-green
# trap of Round 29: BITCOIND_SKIP_DOWNLOAD made every live e2e "pass" in
# 0.00s) is a FAILURE, not a pass.
#
#   bash scripts/round_gate.sh              # everything (~25-40 min)
#   GATE_SKIP=slow bash scripts/round_gate.sh   # skip fuzz+mutation+coverage
#   GATE_ONLY=relay-drill bash scripts/round_gate.sh
#
# Exit 0 = every gate green. Any failure prints the failing leg and stops
# (fail-fast by default; GATE_CONTINUE=1 runs every leg and summarizes).
# Exit 3 = the ENVIRONMENT cannot host the gate (no usable TMPDIR) — see the
# preflight below; that is not a code verdict and is never reported as one.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 99

CONTINUE="${GATE_CONTINUE:-0}"
SKIP="${GATE_SKIP:-}"
ONLY="${GATE_ONLY:-}"
NIGHTLY_NEEDED=0
declare -a NAMES=() STATES=() SECONDS_=()

# ── TMPDIR PREFLIGHT (Round 38) ──────────────────
# The live e2e legs create regtest datadirs under std::env::temp_dir(), so
# the gate inherits whatever TMPDIR the shell has. Three inherited values
# produced three DIFFERENT reds on the SAME tree (Round 38): a full /tmp made
# bitcoind die with "Disk space is too low"; TMPDIR=$HOME tripped the
# doctor's ProtectHome=yes validator (it was RIGHT — a systemd unit may not
# read home); a disk-backed /var/tmp made coverage_cli mine for 40+ minutes
# without finishing. None of those is a statement about the code, so the
# gate now picks a host it can trust and REFUSES to start otherwise.
tmp_free_mb() { df -Pm "$1" 2>/dev/null | awk 'NR==2 {print $4}'; }
tmp_fs() { stat -f -c %T "$1" 2>/dev/null || echo unknown; }
tmp_under_home() {
    local p h
    p=$(cd "$1" 2>/dev/null && pwd -P) || return 0
    h=$(cd "$HOME" 2>/dev/null && pwd -P) || return 0
    case "$p" in "$h"|"$h"/*) return 0;; esac
    return 1
}
tmp_refuse() {
    echo "!! GATE ENVIRONMENT: $1" >&2
    shift
    printf '!!   %s\n' "$@" >&2
    echo "!! Not a code verdict — no leg ran. Fix the host (or export a TMPDIR" >&2
    echo "!! that passes these checks); never lower a test threshold for this." >&2
    exit 3
}
pick_tmpdir() {
    local min_mb="${GATE_MIN_TMP_MB:-4096}" cand free fs
    local -a checked=()
    if [ -n "${TMPDIR:-}" ]; then
        cand="$TMPDIR"
        { [ -d "$cand" ] && [ -w "$cand" ]; } || tmp_refuse \
            "TMPDIR=$cand is not a writable directory." \
            "The live e2e legs create a regtest datadir there and would fail" \
            "with an error that looks like a test failure."
        tmp_under_home "$cand" && tmp_refuse "TMPDIR=$cand is inside \$HOME." \
            "The doctor leg's systemd validator enforces ProtectHome=yes and is" \
            "RIGHT to reject it: a unit may not read home. That red is about the" \
            "host. Unset TMPDIR to let the gate choose, or use /dev/shm."
        free=$(tmp_free_mb "$cand")
        [ "${free:-0}" -ge "$min_mb" ] || tmp_refuse \
            "TMPDIR=$cand has ${free:-?} MB free (< ${min_mb} MB)." \
            "bitcoind aborts with \"Disk space is too low\" when it fills mid-run."
        echo "$cand"
        return 0
    fi
    for cand in /dev/shm /tmp /var/tmp; do
        { [ -d "$cand" ] && [ -w "$cand" ]; } || {
            checked+=("$cand: not a writable directory"); continue; }
        tmp_under_home "$cand" && { checked+=("$cand: inside HOME"); continue; }
        free=$(tmp_free_mb "$cand"); fs=$(tmp_fs "$cand")
        if [ "${free:-0}" -lt "$min_mb" ]; then
            checked+=("$cand: $fs, ${free:-?} MB free (< ${min_mb} MB)")
            continue
        fi
        echo "$cand"
        return 0
    done
    if [ "${#checked[@]}" -eq 0 ]; then checked=("(no candidate directory exists)"); fi
    tmp_refuse "no usable temp directory (need >= ${min_mb} MB outside \$HOME)." \
        "${checked[@]}" \
        "GATE_MIN_TMP_MB lowers the floor — only for a run you know is small," \
        "never as a way to turn a disk problem into a green."
}

# Leg runner: NAME, evidence-regex-| -separated (a leg that does its REAL
# work always prints all of these — the Round-29 lesson, enforced here: a
# 0.00s "pass" had no bitcoind lines because an env var skipped the work).
# Empty evidence = "exit code only" (fmt/clippy: cargo's fingerprint
# analysis is itself the proof — a cache hit is a real check).
leg() {
    local name="$1" evidence="$2"; shift 2
    if [ -n "$ONLY" ] && [ "$ONLY" != "$name" ]; then return 0; fi
    case " $SKIP " in *" $name "*) echo "── SKIP  $name"; return 0;; esac
    echo ""
    echo "══════ $name ══════"
    local t0=$SECONDS out rc
    out=$("$@" 2>&1); rc=$?
    local dt=$((SECONDS - t0))
    printf '%s\n' "$out" | tail -15
    local state="PASS" missing=""
    if [ "$rc" -ne 0 ]; then state="FAIL"
    elif [ -n "$evidence" ]; then
        local pat
        IFS='|' read -ra pats <<< "$evidence"
        for pat in "${pats[@]}"; do
            printf '%s' "$out" | grep -qE "$pat" || missing="$pat"
        done
        if [ -n "$missing" ]; then
            state="EMPTY-GREEN"
            echo "!! $name exited 0 but printed no evidence of its real work"
            echo "!! (missing /$missing/). Refusing to call this green (Round 29 lesson)."
            rc=1
        fi
    fi
    NAMES+=("$name"); STATES+=("$state"); SECONDS_+=("${dt}s")
    echo "── $name: $state in ${dt}s"
    if [ "$state" != "PASS" ] && [ "$CONTINUE" != "1" ]; then summary; exit 1; fi
}

summary() {
    echo ""
    echo "══════════════ ROUND GATE SUMMARY ══════════════"
    local i fail=0
    for i in "${!NAMES[@]}"; do
        printf '  %-24s %-12s %s\n' "${NAMES[$i]}" "${STATES[$i]}" "${SECONDS_[$i]}"
        [ "${STATES[$i]}" = "PASS" ] || fail=1
    done
    if [ "$fail" -eq 0 ]; then
        echo "ROUND GATE: ALL GREEN — every CI job's local mirror passed."
    else
        echo "ROUND GATE: RED — see the failing legs above."
    fi
    return "$fail"
}

echo "═══ QuantumSafe-Vault local round gate (mirror of the 11 CI jobs) ═══"
echo "    $(date -u +%FT%TZ) · $(rustc --version 2>/dev/null || echo 'no rustc')"

# The host the live e2e legs will mine into (preflight above). A refusal here
# exits 3 from the subshell AND stops the gate: no leg runs, no verdict is
# printed, so a disk problem can never masquerade as a code failure.
GATE_TMP_HOST=$(pick_tmpdir) || exit 3
GATE_TMP="$GATE_TMP_HOST/qsv-gate-tmp"
mkdir -p "$GATE_TMP" || tmp_refuse "cannot create $GATE_TMP."
export TMPDIR="$GATE_TMP"
TMP_FS=$(tmp_fs "$GATE_TMP_HOST")
echo "    TMPDIR=$GATE_TMP ($TMP_FS, $(tmp_free_mb "$GATE_TMP_HOST") MB free)"
if [ "$TMP_FS" != "tmpfs" ]; then
    echo "    !! $TMP_FS is disk-backed: the live e2e legs mine thousands of blocks"
    echo "    !! at fsync cost (Round 38: coverage_cli did not finish in 40 min on XFS)."
    echo "    !! /dev/shm with room is the fast host; this run will be slow."
fi

# 1-2. fmt + clippy ×3 (the three CI configurations). Evidence: fmt prints
# nothing on success; clippy's proof is cargo's fingerprint analysis —
# a cache hit means "checked, unchanged, clean" which IS the verdict.
leg fmt '' cargo fmt --all -- --check
leg "clippy-workspace" '' cargo clippy --workspace --all-targets -- -D warnings
leg "clippy-consensus" '' cargo clippy --workspace --all-targets --features qsv-core/consensus -- -D warnings
leg "clippy-nsm" '' cargo clippy -p qsv-cosigner --all-targets --features nsm -- -D warnings

# 3. the workspace test matrix ×2. Evidence: the live e2e legs print
# "test result: ok" for every target AND the real-bitcoind suite's name —
# the Round-29 fake skipped bitcoind via BITCOIND_SKIP_DOWNLOAD and never
# printed the lifecycle line. Tests RE-RUN on every invocation (cache only
# covers compilation), so this is a real proof, not a duration guess.
leg "test-default" 'e2e_full_vault_lifecycle_on_real_bitcoind.*ok' cargo test --workspace
leg "test-consensus" 'e2e_full_vault_lifecycle_on_real_bitcoind.*ok' cargo test --workspace --features qsv-core/consensus

# 4-6. the three drills (relay: python3+curl; monitoring: promtool or
# structural; capacity: the real bench binary) — each prints its own
# completion contract.
leg relay-drill 'RELAY DRILL OK' bash scripts/webhook_relay_drill.sh
leg monitoring-drill 'MONITORING DRILL OK|rules loadable' env PROMTOOL_REQUIRED="${PROMTOOL_REQUIRED:-0}" bash scripts/monitoring_drill.sh
leg capacity-gate 'CAPACITY GATE OK' bash scripts/capacity_gate.sh

# 7. security: RustSec + cargo-deny + secret scan (history included).
# The audit ignores are the DOCUMENTED set, identical to ci.yml (gate
# equality): RUSTSEC-2023-0089 (atomic-polyfill, target-gated to MCUs)
# + RUSTSEC-2026-0367/0368/0369 (zip — build-only dep of the bitcoind
# TEST harness; fixed line >=9.0.0 is unreachable while the newest
# harness release requires ^0.6.6 — reasoning + re-evaluation rule in
# deny.toml; Round 36 bumped the harness to 0.42.0 and re-checked)
# + RUSTSEC-2026-0387 (crypto-bigint 0.5.5, timing variability; FROST-only:
# frost-secp256k1-tr 3.0.0 pins k256 0.13, the sold fix needs k256 0.14 —
# same ignore, same reason, at all three homes).
leg security-audit 'advisories ok|SECRET SCAN OK' bash -c \
    'cargo audit --ignore RUSTSEC-2023-0089 --ignore RUSTSEC-2026-0367 --ignore RUSTSEC-2026-0368 --ignore RUSTSEC-2026-0369 --ignore RUSTSEC-2026-0387 && cargo deny check && bash scripts/secret_scan.sh'

# 8. fuzz: six parsers (needs nightly — fuzz_gate.sh resolves it
# itself; skipped explicitly via GATE_SKIP=fuzz). The window is CI's
# 120s, NOT the script's 45s default: the local gate and the CI job run
# the SAME window (Round-32 equality fix). FUZZ_DEEP=1 upgrades to 300s.
leg fuzz-gate 'FUZZ GATE OK' env FUZZ_SECONDS="${FUZZ_SECONDS:-120}" bash scripts/fuzz_gate.sh

# 9. mutation: 54 injected mutants (M49–M54 — finmodel/settlement in
# Round 37, the docs fence wall in Round 40, the console descriptor wall in
# Round 39), every one must die
# (Round 31: each file restores from a byte snapshot, so a dirty
# worktree is safe).
leg mutation-audit 'ALL MUTATIONS KILLED' bash scripts/mutation_audit.sh

# 9b. mutation SWEEP (Round 32): the automated wall over EVERY product
# file — mechanical boundary mutants plus the hand-covered and
# allowlisted sets; a file with no mutant and no written reason fails.
leg mutation-sweep 'SWEEP VERDICT: GREEN' bash scripts/mutation_sweep.sh

# 10. coverage: llvm-cov, DOUBLE floor (lines + functions) from the one
# file that owns both numbers.
leg coverage 'COV_GATE=PASS' bash scripts/coverage_gate.sh

summary
