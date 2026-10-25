#!/usr/bin/env bash
# D2 (docs/10 §4.64): verify a downloaded release BEFORE running it.
#
#   bash scripts/verify_release.sh qsv-cli-v2026.3.1-x86_64-unknown-linux-gnu.tar.gz
#   bash scripts/verify_release.sh <archive> --repo owner/name
#
# Two INDEPENDENT checks, both required for a pass:
#
#   1. CHECKSUM — the archive's SHA-256 must equal the entry the manifest
#      names. Answers "is this the file the project published?".
#   2. PROVENANCE — `gh attestation verify` checks the Sigstore bundle GitHub
#      generated while building it. Answers "which workflow, commit and tag
#      built it?" without trusting the download host.
#
# A check that CANNOT run is reported as SKIP and the script exits 2 — an
# unverifiable download is not a verified one. Exit codes: 0 verified,
# 1 mismatch/refusal, 2 incomplete verification.
set -uo pipefail

ARCHIVE="${1:-}"
shift || true
REPO="${QSV_REPO:-}"
while [ $# -gt 0 ]; do
    case "$1" in
        --repo) REPO="${2:-}"; shift 2 ;;
        *) echo "verify_release: unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [ -z "$ARCHIVE" ]; then
    echo "usage: bash scripts/verify_release.sh <archive> [--repo owner/name]" >&2
    exit 1
fi
if [ ! -f "$ARCHIVE" ]; then
    echo "verify_release: no such file: $ARCHIVE" >&2
    exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="${QSV_SHA256SUMS:-$(dirname "$ARCHIVE")/SHA256SUMS}"
if [ ! -f "$MANIFEST" ] && [ -f "$HERE/../SHA256SUMS" ]; then
    MANIFEST="$HERE/../SHA256SUMS"
fi

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

BASE="$(basename "$ARCHIVE")"
FAILED=0
SKIPPED=0

# ── 1. CHECKSUM ────────────────────────────────────────────────────────────
if [ ! -f "$MANIFEST" ]; then
    echo "SKIP  checksum: no SHA256SUMS beside the archive (pass QSV_SHA256SUMS=<path>)"
    SKIPPED=1
else
    EXPECTED="$(awk -v f="$BASE" '{ n=$2; sub(/^\*/, "", n); if (n == f) print $1 }' "$MANIFEST" | head -n1)"
    if [ -z "$EXPECTED" ]; then
        echo "FAIL  checksum: $BASE is NOT listed in $MANIFEST"
        FAILED=1
    else
        ACTUAL="$(sha256_of "$ARCHIVE")"
        if [ "$EXPECTED" = "$ACTUAL" ]; then
            echo "OK    checksum: $ACTUAL"
        else
            echo "FAIL  checksum: expected $EXPECTED, got $ACTUAL"
            FAILED=1
        fi
    fi
fi

# ── 2. PROVENANCE ──────────────────────────────────────────────────────────
if ! command -v gh >/dev/null 2>&1; then
    echo "SKIP  provenance: gh CLI not installed (https://cli.github.com) — install it and rerun"
    SKIPPED=1
else
    if [ -z "$REPO" ]; then
        REPO="$(git -C "$(dirname "$ARCHIVE")" remote get-url origin 2>/dev/null \
            | sed -e 's#^git@github.com:##' -e 's#^https://github.com/##' -e 's#\.git$##')"
    fi
    if [ -z "$REPO" ]; then
        echo "SKIP  provenance: no repository known (pass --repo owner/name or set QSV_REPO)"
        SKIPPED=1
    elif gh attestation verify "$ARCHIVE" --repo "$REPO" >/dev/null 2>&1; then
        echo "OK    provenance: attested by $REPO"
    else
        echo "FAIL  provenance: no valid attestation from $REPO"
        FAILED=1
    fi
fi

if [ "$FAILED" -ne 0 ]; then
    echo "verdict: REFUSED — do not run this archive"
    exit 1
fi
if [ "$SKIPPED" -ne 0 ]; then
    echo "verdict: INCOMPLETE — a check could not run; not verified"
    exit 2
fi
echo "verdict: VERIFIED (checksum + provenance)"
