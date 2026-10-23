#!/usr/bin/env bash
# ROUND 25 — SECRET SCAN (docs/10 §4.44): no credential material in the
# working tree, and none anywhere in the HISTORY a clone would receive.
# Offline grep only — CI and a laptop see byte-identical results, no
# service, no upload, no third-party binary.
#
# Patterns are true positives for credential MATERIAL (private-key
# armor, cloud access key IDs, provider tokens). Generic words like
# "password" or "secret" are deliberately absent: they fire on docs and
# train people to ignore the scanner.
set -u
cd "$(dirname "$0")/.." || exit 99

# The PGP armor pattern is assembled at RUNTIME so this scanner does
# not flag its own source (the literal text below must never contain
# a full match of any pattern above — self-match is the classic way a
# secret scanner goes red on a clean tree).
PGP_ARMOR='BEGIN PGP PRIVATE KEY'
PATTERNS=(
  'BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY'
  "${PGP_ARMOR} BLOCK"
  'AKIA[0-9A-Z]{16}'
  'ASIA[0-9A-Z]{16}'
  'ghp_[A-Za-z0-9]{36}'
  'gho_[A-Za-z0-9]{36}'
  'ghu_[A-Za-z0-9]{36}'
  'github_pat_[A-Za-z0-9_]{22,}'
  'glpat-[A-Za-z0-9_-]{20,}'
  'xox[baprs]-[A-Za-z0-9-]{10,}'
  'sk-[A-Za-z0-9]{32,}'
)

JOIN="$(printf '%s|' "${PATTERNS[@]}")"
JOIN="${JOIN%|}"

fail=0

# 1. THE TREE — tracked files only (no build output, no local notes).
#    -I skips binaries; -n keeps the location; -E is the dialect.
while IFS= read -r hit; do
  echo "TREE: $hit"
  fail=1
done < <(git ls-files -z | xargs -0 grep -InE "$JOIN" 2>/dev/null)

# 2. THE HISTORY — every added line of every reachable commit, with the
#    owning commit reported for each hit. This is the scan that matters:
#    a redacted file still leaks through `git log -p` for anyone who
#    clones, and a secret deleted in a later commit still lives here.
if git log -p --all --format='commit %H' 2>/dev/null \
  | awk -v pat="$JOIN" '
      /^commit [0-9a-f]+/ { c = $2 }
      $0 ~ pat { print c ": " substr($0, 1, 160); hits++ }
      END { exit (hits > 0 ? 1 : 0) }'; then
  :
else
  echo "HISTORY: credential material found in commits above"
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "SECRET SCAN FAILED — credential material found (tree or history)."
  echo "Purge with git-filter-repo / BFG, then ROTATE the credential."
  exit 1
fi
echo "SECRET SCAN OK (${#PATTERNS[@]} patterns, tree + full history)"
