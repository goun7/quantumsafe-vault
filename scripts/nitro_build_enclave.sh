#!/usr/bin/env bash
# Builds the co-signer enclave image (EIF) for the live Nitro e2e
# (docs/10 §4.53). Drives `nitro-cli build-enclave-image` against the
# committed Dockerfile template, baking the requested vault allowlist.
#
# Usage: scripts/nitro_build_enclave.sh [vault-id]     (default: e2e-vault)
# Needs: nitro-cli (aws-nitro-enclaves-cli) + docker.
# Output: target/eif/qsv-cosigner.eif  (+ EIF_READY=... line).
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
VAULT="${1:-e2e-vault}"
TEMPLATE="crates/qsv-cosigner/enclave/Dockerfile"
GENERATED="crates/qsv-cosigner/enclave/Dockerfile.gen"
OUT_DIR="target/eif"
OUT_EIF="$OUT_DIR/qsv-cosigner.eif"

command -v nitro-cli >/dev/null 2>&1 || {
    echo "FATAL: nitro-cli not found (install aws-nitro-enclaves-cli)" >&2
    exit 4
}
command -v docker >/dev/null 2>&1 || {
    echo "FATAL: docker not found (nitro-cli builds through docker)" >&2
    exit 4
}
[ -f "$TEMPLATE" ] || {
    echo "FATAL: $TEMPLATE missing" >&2
    exit 4
}

# Bake the allowlist: the enclave receives no run-time args, so the vault
# travels as ENV in the image. Generate (never mutate the committed file).
sed "s|^ENV QSV_VAULT=.*|ENV QSV_VAULT=${VAULT}|" "$TEMPLATE" > "$GENERATED"
trap 'rm -f "$GENERATED"' EXIT

mkdir -p "$OUT_DIR"
rm -f "$OUT_EIF"
nitro-cli build-enclave-image \
    --docker-dir "$ROOT" \
    --dockerfile "$ROOT/$GENERATED" \
    --enclave-cwd / \
    --output "$ROOT/$OUT_EIF"

[ -f "$OUT_EIF" ] || {
    echo "FATAL: nitro-cli reported success but $OUT_EIF is missing" >&2
    exit 1
}
echo "EIF_READY path=$OUT_EIF vault=$VAULT"
