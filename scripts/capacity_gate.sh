#!/usr/bin/env bash
# ROUND 25 — THE CAPACITY GATE, EXERCISED ON EVERY PUSH (docs/10 §4.38).
# `bench --baseline` is release machinery: if the gate itself silently
# rotted, a release could ship a throughput regression through a green
# pipeline. This drill proves the whole path on the REAL binary:
#
#   1. a fresh `bench --json` report round-trips as its own baseline
#      (exit 0 — the gate PASSES when nothing changed);
#   2. a baseline inflated 100x must FAIL (exit 1, `REGRESSION:` on
#      stdout, `capacity regression` on stderr);
#   3. a malformed baseline must be REFUSED (exit 2) with an EMPTY
#      stdout — never a measurement report followed by a usage error.
#
# The pass leg runs with a deliberately generous tolerance: the drill
# runs on loaded CI boxes and two consecutive debug measurements can
# drift tens of percent. The FAIL leg is immune to noise — 100x sits
# orders of magnitude past any timing wobble.
set -u
cd "$(dirname "$0")/.." || exit 99

BENCH=(cargo run -q -p qsv-cli --)
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "  [1/3] a fresh report round-trips as its own baseline"
"${BENCH[@]}" bench --json > "$TMP/baseline.json" || {
  echo "CAPACITY GATE FAILED: bench report exited $?"
  exit 1
}
grep -q '"schema": *"qsv-bench/v1"' "$TMP/baseline.json" || {
  echo "CAPACITY GATE FAILED: report is not a qsv-bench/v1 document"
  exit 1
}
"${BENCH[@]}" bench \
  --baseline "$TMP/baseline.json" --baseline-tolerance-pct 90 \
  > "$TMP/pass.txt" 2>&1 || {
  echo "CAPACITY GATE FAILED: identical baseline must PASS, got $?:"
  cat "$TMP/pass.txt"
  exit 1
}

echo "  [2/3] a 100x-inflated baseline must FAIL the gate"
python3 - "$TMP/baseline.json" "$TMP/inflated.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
for row in doc["rows"]:
    row["ops_per_s"] *= 100.0
json.dump(doc, open(sys.argv[2], "w"))
PY
if [ $? -ne 0 ]; then
  echo "CAPACITY GATE FAILED: cannot inflate the baseline"
  exit 1
fi
"${BENCH[@]}" bench \
  --baseline "$TMP/inflated.json" --baseline-tolerance-pct 90 \
  > "$TMP/stdout.txt" 2> "$TMP/stderr.txt"
rc=$?
if [ "$rc" -ne 1 ]; then
  echo "CAPACITY GATE FAILED: inflated baseline must exit 1, got $rc"
  echo "--- stdout:"; cat "$TMP/stdout.txt"
  echo "--- stderr:"; cat "$TMP/stderr.txt"
  exit 1
fi
grep -q "REGRESSION:" "$TMP/stdout.txt" || {
  echo "CAPACITY GATE FAILED: the FAIL leg must print REGRESSION: rows"
  cat "$TMP/stdout.txt"
  exit 1
}
grep -q "capacity regression" "$TMP/stderr.txt" || {
  echo "CAPACITY GATE FAILED: the FAIL leg must say why on stderr"
  cat "$TMP/stderr.txt"
  exit 1
}

echo "  [3/3] a malformed baseline is refused with an EMPTY stdout"
printf '{"schema":"qsv-bench/v1","rows":[]}' > "$TMP/broken.json"
"${BENCH[@]}" bench \
  --baseline "$TMP/broken.json" \
  > "$TMP/o2.txt" 2> "$TMP/e2.txt"
rc=$?
if [ "$rc" -ne 2 ]; then
  echo "CAPACITY GATE FAILED: malformed baseline must exit 2, got $rc"
  exit 1
fi
if [ -s "$TMP/o2.txt" ]; then
  echo "CAPACITY GATE FAILED: stdout must be EMPTY when the gate refuses:"
  cat "$TMP/o2.txt"
  exit 1
fi
grep -q -- "--baseline" "$TMP/e2.txt" || {
  echo "CAPACITY GATE FAILED: stderr must name --baseline:"
  cat "$TMP/e2.txt"
  exit 1
}

echo "CAPACITY GATE OK (round-trip passes, 100x regression refused exit 1, malformed refused exit 2)"
