#!/usr/bin/env bash
# Line-coverage gate (docs/10, Round 28+): `cargo llvm-cov` line coverage
# must meet the committed floor. This script IS the floor's home — the
# CI job and the local round gate both call it, so there is exactly one
# number to raise.
#
# Usage:
#   bash scripts/coverage_gate.sh               # gate at the committed floor
#   COV_FLOOR=92 bash scripts/coverage_gate.sh  # experiment with a higher bar
#   COV_OUT=/tmp/cov.json bash scripts/coverage_gate.sh
#
# Needs: cargo-llvm-cov + llvm-tools-preview.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

# Round 29: floor moved 91.0 -> 97.5 (measured 97.85% at the round-29
# audit; the residual ~2% is the documented irreducible set — poisoned-
# lock skips, unreachable-by-design defensive arms, and the llvm-cov
# macro-region artifact — see docs/10 coverage notes).
FLOOR="${COV_FLOOR:-97.5}"
# Round 31: a SECOND single number — FUNCTION coverage (main.rs-style CLI
# dispatch has hundreds of thin handlers; the floor guards against the
# function ratio silently rotting while lines stay pinned). Measured
# 82.47% at the round-31 audit.
FUNC_FLOOR="${COV_FUNC_FLOOR:-82.0}"
OUT="${COV_OUT:-target/coverage.json}"
mkdir -p "$(dirname "$OUT")"

cargo llvm-cov --workspace --json --output-path "$OUT" \
    > /tmp/qsv_coverage_gate_build.log 2>&1 || {
    echo "COV_GATE=ERROR (llvm-cov run failed — see /tmp/qsv_coverage_gate_build.log)" >&2
    tail -20 /tmp/qsv_coverage_gate_build.log >&2
    exit 2
}

# llvm-cov export JSON: data[0].totals.lines.percent is the workspace
# TOTAL (key is `percent`, not `pct` — verified against a real export).
# The same run yields totals.functions.percent (the second floor).
read -r PCT FPCT < <(python3 - "$OUT" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
t = d['data'][0]['totals']
print(f"{t['lines']['percent']:.2f} {t['functions']['percent']:.2f}")
PYEOF
)

VERDICT=$(python3 - "$PCT" "$FLOOR" "$FPCT" "$FUNC_FLOOR" <<'PYEOF'
import sys
pct, floor, fpct, ffloor = (float(x) for x in sys.argv[1:5])
print("PASS" if pct >= floor and fpct >= ffloor else "FAIL")
PYEOF
)

echo "COV_PCT=$PCT (floor $FLOOR) · COV_FUNC_PCT=$FPCT (floor $FUNC_FLOOR)"
if [ "$VERDICT" = "PASS" ]; then
    echo "COV_GATE=PASS"
    exit 0
fi
echo "COV_GATE=FAIL: line $PCT < $FLOOR or function $FPCT < $FUNC_FLOOR" >&2
exit 1
