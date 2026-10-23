#!/usr/bin/env bash
# Monitoring-asset drill (docs/10 §4.25, Round 20): proves the shipped
# Prometheus rule file and Grafana dashboard are LOADABLE and that every
# metric they name is one the co-signer bridge actually exports.
#
#   1. promtool check rules --lint all (REQUIRED in CI: native binary or
#                                 the official pinned docker image — the
#                                 real Prometheus PromQL parser, so a
#                                 syntax error in a folded expr cannot
#                                 ship, lints fail too)
#   2. python3 yaml.safe_load    (every rule has alert/expr/for/labels/
#                                 annotations and the expr is non-empty)
#   3. python3 json.load         (the dashboard is importable JSON with
#                                 titled panels and non-empty queries)
#   4. metric cross-check        (every qsv_cosigner_* token in either
#                                 file is a family in the exposition, and
#                                 every safety-critical family is covered)
#
# CI runs this job (ci.yml → monitoring-drill); no cargo build, no
# network. The Rust test crates/qsv-cli/tests/monitoring_assets.rs makes
# the same cross-check against the LIVE exposition — this drill is the
# toolchain-free half (a YAML/JSON error caught without building Rust).
set -euo pipefail
cd "$(dirname "$0")/.."

ALERTS="scripts/prometheus_alerts.yml"
DASH="scripts/grafana_dashboard.json"

for f in "$ALERTS" "$DASH"; do
    [[ -f "$f" ]] || { echo "DRILL FAIL: missing $f"; exit 1; }
done

# 1. The real Prometheus parser — REQUIRED in CI (PROMTOOL_REQUIRED=1)
#    and everywhere a promtool binary or docker exists. Resolution order:
#      a) a native promtool on PATH (fastest);
#      b) the OFFICIAL prom/prometheus image via docker — version-pinned,
#         mounted read-only, no root, byte-identical rules file;
#      c) neither → structural checks only, unless PROMTOOL_REQUIRED=1
#         demands the real parser and fails loudly instead of pretending.
#    --lint all promotes PromQL lints (duplicate rules, agnostic
#    naming, unoptimizable expressions) to failures too: a folded expr
#    with a syntax or lint error must never ship silently.
PROMTOOL_IMAGE="${PROMTOOL_IMAGE:-prom/prometheus:v3.15.0}"
PROMTOOL_SRC=""
promtool_check() {
    if command -v promtool >/dev/null 2>&1; then
        PROMTOOL_SRC="native ($(command -v promtool))"
        promtool check rules --lint all "$1"
    else
        PROMTOOL_SRC="docker ($PROMTOOL_IMAGE)"
        docker run --rm --user "$(id -u):$(id -g)" \
            -v "$PWD/scripts:/w:ro" --entrypoint promtool \
            "$PROMTOOL_IMAGE" check rules --lint all "/w/${1##*/}"
    fi
}
if command -v promtool >/dev/null 2>&1 || command -v docker >/dev/null 2>&1; then
    promtool_check "$ALERTS"
    echo "  promtool: rules + lints OK [$PROMTOOL_SRC]"
elif [[ "${PROMTOOL_REQUIRED:-0}" == "1" ]]; then
    echo "DRILL FAIL: PROMTOOL_REQUIRED=1 but neither promtool nor docker is available"
    exit 1
else
    echo "  promtool: not available (structural checks only)"
fi

# 2/3/4. Everything else is one python3 pass — the same parser the relay
#        drill already depends on, so CI gains no new tool requirement.
python3 - "$ALERTS" "$DASH" crates/qsv-cosigner/src/server.rs <<'PY'
import json, re, sys

alerts_path, dash_path, server_path = sys.argv[1:4]
import yaml

alerts_text = open(alerts_path, encoding="utf-8").read()
dash_text = open(dash_path, encoding="utf-8").read()
server_src = open(server_path, encoding="utf-8").read()

failures = []

# The declared family list is read straight out of the source that renders
# the exposition, so the drill cannot drift from the binary.
m = re.search(r"METRIC_FAMILIES: &'static \[&'static str\] = &\[(.*?)\];", server_src, re.S)
if not m:
    print("DRILL FAIL: could not find Metrics::METRIC_FAMILIES in", server_path)
    sys.exit(1)
declared = set(re.findall(r'"([^"]+)"', m.group(1)))
print(f"  declared families: {len(declared)}")

# 2. The rule file must LOAD and every rule must be complete.
doc = yaml.safe_load(alerts_text)
rules = [r for g in doc.get("groups", []) for r in g.get("rules", [])]
if len(rules) < 8:
    failures.append(f"only {len(rules)} alert rules (expected >= 8)")
seen = set()
for r in rules:
    name = r.get("alert")
    if not name:
        failures.append("a rule has no alert name")
        continue
    if name in seen:
        failures.append(f"duplicate alert {name}")
    seen.add(name)
    expr = (r.get("expr") or "").strip()
    if not expr:
        failures.append(f"{name}: empty expr")
    if "for" not in r:
        failures.append(f"{name}: no for: dwell")
    if not (r.get("labels") or {}).get("severity"):
        failures.append(f"{name}: no severity label")
    ann = r.get("annotations") or {}
    for key in ("summary", "description"):
        if not ann.get(key):
            failures.append(f"{name}: no {key} annotation")
print(f"  alert rules: {len(rules)}")

# 3. The dashboard must LOAD and every panel must carry a real query.
dash = json.loads(dash_text)
panels = dash.get("panels") or []
if len(panels) < 8:
    failures.append(f"dashboard has {len(panels)} panels (expected >= 8)")
for p in panels:
    title = p.get("title") or "<untitled>"
    grid = p.get("gridPos") or {}
    if not grid.get("w") or not grid.get("h"):
        failures.append(f"panel {title!r} has no gridPos")
    targets = p.get("targets") or []
    if not targets:
        failures.append(f"panel {title!r} has no target")
    for t in targets:
        if not (t.get("expr") or "").strip():
            failures.append(f"panel {title!r} has an empty expr")
print(f"  dashboard panels: {len(panels)}")

# 4. Every metric reference must exist, and the critical set must be covered.
def families(text):
    flat = " ".join(text.split())
    return set(re.findall(r"qsv_cosigner_[A-Za-z0-9_]+", flat))

rules_families = families(alerts_text) | families(json.dumps(dash))
for name in sorted(rules_families):
    if name in declared:
        continue
    # Prometheus-derived rows of the latency histogram are generated at
    # scrape time, so only the family itself is declared.
    base = name
    for suffix in ("_bucket", "_sum", "_count"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    if base not in declared:
        failures.append(f"{name} is referenced but never exported")

covered = families(alerts_text) | families(json.dumps(dash))
critical = [
    "qsv_cosigner_alarm_refused_total",
    "qsv_cosigner_alarm_refused_by_vault_total",
    "qsv_cosigner_refused_total",
    "qsv_cosigner_refused_by_vault_total",
    "qsv_cosigner_accepted_total",
    "qsv_cosigner_accepted_by_vault_total",
    "qsv_cosigner_requests_total",
    "qsv_cosigner_capacity_refused_total",
    "qsv_cosigner_rate_limited_total",
    "qsv_cosigner_metrics_denied_total",
    "qsv_cosigner_serve_latency_us_bucket",
    # Round 23/24: rotation accounting and worker occupancy — the gauges
    # the rotation-stall and saturation rules read (kept in sync with
    # the Rust coverage contract in monitoring_assets.rs).
    "qsv_cosigner_rotate_denied_total",
    "qsv_cosigner_rotate_total",
    "qsv_cosigner_workers_peak",
    "qsv_cosigner_worker_limit",
]
for name in critical:
    if name not in covered:
        failures.append(f"{name} has no alert rule and no dashboard panel")

if failures:
    print("\nDRILL FAIL:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print("MONITORING DRILL OK (rules loadable, dashboard importable, metrics real)")
PY