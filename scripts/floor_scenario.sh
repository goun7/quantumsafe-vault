#!/usr/bin/env bash
# FLOOR SCENARIOS (docs/10 §4.61, Round 36 / E5SED): the coverage gate
# defends ONE number pair (lines ≥ FLOOR, functions ≥ FUNC_FLOOR — both
# living in scripts/coverage_gate.sh, the single home of every threshold).
# This script answers the auditor's NEXT question without touching those
# thresholds: what does the floor become per crate, for the audit scope
# alone, when the least-covered files leave the suite (a real degrade),
# and without the experimental layer? It is a REPORT, not a gate: exit 0
# on a report, exit 2 when there is no data to report on.
#
#   bash scripts/floor_scenario.sh              # reuse target/coverage.json
#   SCN_DROP="5 20" bash scripts/floor_scenario.sh   # degrade curve %
#   COV_OUT=other.json bash scripts/floor_scenario.sh
#
# Shares COV_OUT with coverage_gate.sh (same JSON, one truth). If the
# file is absent it runs `cargo llvm-cov` itself (~25 min) — after a gate
# run the file already exists and this reports in seconds.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

OUT="${COV_OUT:-target/coverage.json}"
SCN_DROP="${SCN_DROP:-1 5 10}"

if [ ! -f "$OUT" ]; then
    echo "(no $OUT — running cargo llvm-cov once; ~25 min, see /tmp/qsv_scenario_cov.log)"
    cargo llvm-cov --workspace --json --output-path "$OUT" \
        > /tmp/qsv_scenario_cov.log 2>&1 || {
        echo "SCENARIO=ERROR (llvm-cov failed — see /tmp/qsv_scenario_cov.log)" >&2
        exit 2
    }
fi

python3 - "$OUT" "$SCN_DROP" <<'PYEOF'
import json, os, re, sys

path, drops = sys.argv[1], [int(x) for x in sys.argv[2].split()]
doc = json.load(open(path))
data = doc["data"][0]

# The committed floors come from their single home — never copied here.
gate = open("scripts/coverage_gate.sh").read()
floor = float(re.search(r'FLOOR="\$\{COV_FLOOR:-([0-9.]+)\}"', gate).group(1))
ffloor = float(re.search(r'FUNC_FLOOR="\$\{COV_FUNC_FLOOR:-([0-9.]+)\}"', gate).group(1))

# Workspace-relative paths of every instrumented file.
recs = []  # (path, covered_lines, total_lines)
for f in data.get("files", []):
    name = f.get("filename", "")
    s = f.get("summary", {}).get("lines", {})
    n, c = s.get("count", 0), s.get("covered", 0)
    if os.path.isabs(name):
        name = os.path.relpath(name, os.getcwd())
    if "crates/" not in name or not n:
        continue  # dependencies are uninstrumented anyway; belt and braces
    recs.append((name, c, n))

if not recs:
    print("SCENARIO=ERROR (no workspace files in %s)" % path, file=sys.stderr)
    sys.exit(2)

def pct(rows):
    c = sum(r[1] for r in rows); n = sum(r[2] for r in rows)
    return (100.0 * c / n) if n else 0.0

def line(tag, rows, note=""):
    c = sum(r[1] for r in rows); n = sum(r[2] for r in rows)
    print(f"  {tag:32s} lines {pct(rows):6.2f}%  ({c}/{n}, {len(rows)} files){note}")

total = pct(recs)
canonical = data["totals"]["lines"]["percent"]
func = data["totals"]["functions"]["percent"]

print("═══ Coverage floor scenarios (measurement only — NO threshold moves) ═══")
print(f"  data: {path} · floors from coverage_gate.sh: lines ≥ {floor}, functions ≥ {ffloor}")
print()

# S0 — what the gate itself sees (sum must agree with llvm-cov's totals).
line("S0 workspace (gate regions)", recs)
print(f"  {'  ↳ llvm-cov totals (proof)':32s} lines {canonical:6.2f}% · function "
      f"{func:6.2f}%  (the gate threshold applies to THIS line only: "
      f"{'PASS' if canonical >= floor and func >= ffloor else 'FAIL'})")
if abs(total - canonical) > 0.01:
    print(f"  !! file-sum {total:.2f}% != totals {canonical:.2f}% — investigate the data")

# S1 — per crate.
print()
crates = {}
for r in recs:
    m = re.search(r"crates/([a-z0-9-]+)/", r[0])
    crates.setdefault(m.group(1) if m else "?", []).append(r)
for name in sorted(crates):
    line(f"S1 {name}", crates[name])

# S3 — degrade curve: deleting the LEAST-COVERED files, by file count.
print()
ranked = sorted(recs, key=lambda r: (r[1] / r[2], -r[2]))
worst = ", ".join(os.path.basename(r[0]) for r in ranked[:5])
print(f"  least-covered 5 files: {worst}")
for pct_drop in drops:
    k = max(1, round(len(recs) * pct_drop / 100))
    line(f"S3 degrade: worst %{pct_drop:>2} of files removed", ranked[k:],
         f" ({k} removed)")

# S4 — without the EXPERIMENTAL layer (K1-open BIP-360/P2MR rule engine).
print()
exp = [r for r in recs if r[0].endswith("bip360.rs")]
rest = [r for r in recs if not r[0].endswith("bip360.rs")]
if exp:
    line("S4 without bip360.rs (experimental P2MR engine)", rest)
    line("   |- included experimental layer", exp)

# Functions: llvm-cov aggregates per-function regions at TOP LEVEL only —
# per-file function subsets are not derivable from this JSON. Reported at
# S0 (workspace) and deliberately NOT fabricated below it.
print()
print(f"  function floor (workspace only): {func:.2f}% ≥ {ffloor} → "
      f"{'PASS' if func >= ffloor else 'FAIL'} · per-scenario function "
      "counts cannot be derived from this JSON (not fabricating them is the honest thing).")
print(f"SCN0_LINES={canonical:.2f} SCN0_FUNC={func:.2f} SCN_VERDICT="
      f"{'PASS' if canonical >= floor and func >= ffloor else 'FAIL'}")
print("SCENARIO=REPORTED (measurement only; thresholds live ONLY in coverage_gate.sh)")
PYEOF