#!/usr/bin/env bash
# Round 32 — AUTOMATED MUTATION SWEEP (docs/10 §4.57).
#
# scripts/mutation_audit.sh is the HAND-CURATED behavioral corpus (43
# mutants, each with a bespoke test filter). Its documented weakness
# (Round-31 score, dimension A): the set is hand-picked — a new module
# could ship with zero mutants. This sweep closes that gap MECHANICALLY:
#
#   1. FILE WALL: every product .rs file must be covered by a hand
#      mutant, an auto mutant, or an explicit allowlist entry that
#      names its reason. A new uncovered file FAILS the audit.
#   2. AUTO MUTANTS: for each uncovered file, up to 2 boundary flips
#      (>=, <=, ==, &&) OUTSIDE #[cfg(test)] blocks, applied one at a
#      time, each run against the module's own test subset — escalated
#      to the whole crate on a survive.
#   3. HONEST CLASSIFICATION: KILLED (some applicable suite fails),
#      UNVIABLE (does not compile — reported, never counted as a kill),
#      SURVIVED (every applicable suite passes) = a test gap that FAILS
#      the audit unless the mutant is listed in
#      scripts/sweep_equivalence.txt WITH A WRITTEN REASON.
#
# Deterministic: same tree -> same mutants -> same filters. Every
# mutated file restores from a byte snapshot (dirty-worktree safe, same
# discipline as mutation_audit.sh).
#
#   bash scripts/mutation_sweep.sh              # the full sweep
#   bash scripts/mutation_sweep.sh bridge       # one file's mutants only
set -u
cd "$(dirname "$0")/.." || exit 99

ONLY_FILE="${1:-}"

python3 - "$ONLY_FILE" <<'PYEOF'
import os, re, shutil, subprocess, sys, tempfile, time

ONLY_FILE = sys.argv[1] if len(sys.argv) > 1 else ""

CORE = "crates/qsv-core/src"
COSIGNER = "crates/qsv-cosigner/src"
CLI = "crates/qsv-cli/src"
NODE = "crates/qsv-node/src"
VARMAP = {"CORE": CORE, "COSIGNER": COSIGNER, "CLI": CLI, "NODE": NODE}
AUDIT = "scripts/mutation_audit.sh"
EQUIV_FILE = "scripts/sweep_equivalence.txt"
MAX_PER_FILE = 2
# Order matters: the four classic flips first (stable mutant names for
# files that already have sites), then the SPACE-DELIMITED strict
# comparisons ` > ` / ` < ` (excludes `->`, `Foo<Bar>` generics and
# `=>` arms — only real Rust comparisons match).
PATTERNS = [("ge", ">=", ">"), ("le", "<=", "<"), ("eq", "==", "!="),
            ("andor", "&&", "||"), ("gt", " > ", " >= "), ("lt", " < ", " <= ")]

# Files exempt from the wall, each with the REASON the sweep prints.
ALLOW = {
    f"{CORE}/lib.rs":
        "module declarations only — no logic to mutate",
    f"{COSIGNER}/lib.rs":
        "module declarations only — no logic to mutate",
    f"{NODE}/lib.rs":
        "module declarations only — no logic to mutate",
    f"{CORE}/demo_keys.rs":
        "deterministic TEST/demo fixture generator (header: NOT production "
        "keys) — mutating it changes fixtures, not a security decision",
    f"{COSIGNER}/protocol.rs":
        "wire data structures + one constructor — no comparison operators; "
        "shape changes die in the serde/wire tests (server.rs, vsock.rs, "
        "client.rs socket tests)",
    f"{COSIGNER}/client.rs":
        "pure enum dispatch + string classification — no comparison "
        "operators; all three gate verdicts pinned by the in-file REAL-"
        "socket tests (ask_distinguishes_release_frozen_and_refused)",
    f"{COSIGNER}/bin/cosign_probe.rs":
        "argument parsing for the DEV probe binary — the refusal map is "
        "exercised by nitro_e2e.rs; no comparison operators in the parse "
        "path",
}

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)

# ── 1. hand-covered files (parsed from the curated audit) ──────────────────
audit_src = open(AUDIT).read()
hand = {
    os.path.join(VARMAP[v], f)
    for v, f in re.findall(r"\$(CORE|COSIGNER|CLI|NODE)/([a-z_0-9]+\.rs)", audit_src)
}

# ── 2. every product source file ───────────────────────────────────────────
files = []
for root in (CORE, COSIGNER, CLI, NODE):
    for dirpath, _, names in os.walk(root):
        for n in sorted(names):
            if n.endswith(".rs"):
                files.append(os.path.join(dirpath, n))
files.sort()

# ── 3. equivalence list (mutant name → written reason) ─────────────────────
equiv = {}
if os.path.exists(EQUIV_FILE):
    for line in open(EQUIV_FILE):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, why = line.partition("::")
        equiv[name.strip()] = why.strip()

def cfg_test_cut(lines):
    """Index of the first #[cfg(...test...)] line, else len(lines)."""
    for i, l in enumerate(lines):
        if re.search(r"#\[cfg\([^)]*\btest\b", l):
            return i
    return len(lines)

def candidates(path):
    """Up to MAX_PER_FILE (name, line_no, old, new) mechanical mutants."""
    lines = open(path).read().splitlines()
    cut = cfg_test_cut(lines)
    out, used = [], set()
    for pname, old, new in PATTERNS:
        if len(out) >= MAX_PER_FILE:
            break
        for i, l in enumerate(lines[:cut]):
            stripped = l.split("//", 1)[0]          # strip line comments
            if l.lstrip().startswith(("*", "/*", "//")):
                continue
            if old in stripped:
                key = (i, stripped.index(old))
                if key in used:
                    break
                used.add(key)
                out.append((f"{os.path.basename(path)[:-3]}_{pname}", i, old, new))
                break
    return out

def suite_for(path):
    """(primary, escalate) cargo test invocations for a mutated file."""
    if path.startswith(CORE):
        stem = os.path.basename(path)[:-3]
        return (f"cargo test -p qsv-core {stem} -- --test-threads=2",
                "cargo test -p qsv-core -- --test-threads=2")
    if path.startswith(NODE):
        stem = os.path.basename(path)[:-3]
        return (f"cargo test -p qsv-node {stem} -- --test-threads=2",
                "cargo test -p qsv-node -- --test-threads=2")
    if path.startswith(COSIGNER):
        stem = os.path.basename(path)[:-3]
        if "/bin/" in path:
            # The two bins are only exercised by the live-wire e2e file.
            return ("cargo test -p qsv-cosigner --test nitro_e2e -- --test-threads=2",
                    "cargo test -p qsv-cosigner --test nitro_e2e -- --test-threads=2")
        return (f"cargo test -p qsv-cosigner --lib {stem}:: -- --test-threads=2",
                "cargo test -p qsv-cosigner --lib -- --test-threads=2")
    # qsv-cli operator logic: the kill vector is the live binary suites.
    return ("cargo test -p qsv-cli --test demo_walkthrough -- --test-threads=2",
            "cargo test -p qsv-cli --test demo_walkthrough -- --test-threads=2")

results, wall_gaps, n_killed, n_unviable, n_equiv, n_swept = [], [], 0, 0, 0, 0

print("═══ QuantumSafe-Vault automated mutation sweep ═══")

target = [f for f in files if not ONLY_FILE or ONLY_FILE in os.path.basename(f)]
for path in target:
    if path in hand:
        results.append(f"  {path:48s} HAND-COVERED (mutation_audit.sh)")
        continue
    reason = ALLOW.get(path)
    if reason:
        results.append(f"  {path:48s} ALLOWLISTED — {reason}")
        continue
    cands = candidates(path)
    if not cands:
        wall_gaps.append(f"{path} — no mechanical mutation site found; "
                         "inspect it and add a hand mutant or an allowlist reason")
        continue
    primary, escalate = suite_for(path)
    for mname, lineno, old, new in cands:
        n_swept += 1
        full = f"S-{mname}"
        src = open(path).read().splitlines(keepends=True)
        assert old in src[lineno], f"{full}: site vanished"
        snap = tempfile.mktemp(prefix="qsv_sweep_")
        shutil.copyfile(path, snap)
        src[lineno] = src[lineno].replace(old, new, 1)
        open(path, "w").writelines(src)
        t0 = time.time()
        proc = sh(primary)
        out = proc.stdout + proc.stderr
        verdict = None
        if proc.returncode != 0 and re.search(r"error(\[E\d+\]|: could not compile)", out):
            verdict = "UNVIABLE"
        elif proc.returncode != 0:
            verdict = "KILLED"
        else:
            if escalate != primary:
                proc2 = sh(escalate)
                out += proc2.stdout + proc2.stderr
                if proc2.returncode != 0:
                    verdict = "KILLED"
        shutil.copyfile(snap, path)
        os.unlink(snap)
        dt = time.time() - t0
        if verdict == "KILLED":
            n_killed += 1
            results.append(f"  {path:48s} {full:24s} KILLED    ({dt:.0f}s)")
        elif verdict == "UNVIABLE":
            n_unviable += 1
            results.append(f"  {path:48s} {full:24s} UNVIABLE  ({dt:.0f}s, compile error — not a kill)")
        elif mname in equiv or full in equiv:
            n_equiv += 1
            why = equiv.get(mname, equiv.get(full, ""))
            results.append(f"  {path:48s} {full:24s} EQUIV     ({dt:.0f}s) — {why}")
        else:
            results.append(f"  {path:48s} {full:24s} SURVIVED  ({dt:.0f}s) ← TEST GAP")
            wall_gaps.append(f"{full} in {path}:{lineno + 1} survived every applicable "
                             f"suite — add a test, or add \"{full} :: <why equivalent>\" "
                             f"to {EQUIV_FILE}")

for line in results:
    print(line)
print()

if wall_gaps:
    print("WALL GAPS:")
    for g in wall_gaps:
        print(f"  ✗ {g}")
    print()
    print("SWEEP VERDICT: RED — the automated wall found a gap.")
    sys.exit(1)

print(f"SWEEP VERDICT: GREEN — {n_swept} auto mutants ({n_killed} killed, "
      f"{n_equiv} reviewed-equivalent, {n_unviable} unviable), "
      f"{len(hand)} files hand-covered, {len(ALLOW)} allowlisted, "
      f"{len(files)} files wall-checked.")
PYEOF
