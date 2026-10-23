#!/usr/bin/env bash
# Live Nitro Enclaves e2e (docs/10 §4.53).
#
#   PHASE 1 — dev loopback ceremony: ALWAYS runs. Builds and drives the
#             SAME two binaries the enclave image contains
#             (enclave_server + cosign_probe) over loopback TCP: full
#             gate → attestation chain → PCR pin → nonce → key binding →
#             signature verification, plus the refusal paths.
#
#   PHASE 2 — REAL enclave: builds the EIF, boots it with nitro-cli and
#             repeats the ceremony over AF_VSOCK against the hardware
#             measurement. Requires nitro-cli + docker + a Nitro-capable
#             host (EC2 .metal). Skips with a clear reason unless
#             --require-enclave is given.
#
# PHASE 2 prerequisites (official install:
# docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html):
#   AL2023: sudo dnf install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel -y
#   AL2:    sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
#           sudo yum install aws-nitro-enclaves-cli-devel -y
#   other distros: build from github.com/aws/aws-nitro-enclaves-cli
#   sudo usermod -aG ne $USER     (nitro-cli runs as the ne group)
#   sudo usermod -aG docker $USER (EIF build goes through docker)
#           — log out and back in after both group changes.
#   sudo systemctl enable --now nitro-enclaves-allocator.service
#           (default preallocation: 512 MiB / 2 vCPU — exactly what
#            `run-enclave --cpu-count 2 --memory-mib 512` requests below)
#   sudo systemctl enable --now docker
#   nitro-cli --version            (sanity check)
#   nitro-cli describe-enclaves    (must succeed with zero enclaves)
#
# Usage: scripts/nitro_e2e.sh [--require-enclave]
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
REQUIRE=0
[ "${1:-}" = "--require-enclave" ] && REQUIRE=1

skip_or_fail() { # $1 = reason
    if [ "$REQUIRE" = 1 ]; then
        echo "FATAL: $1 (--require-enclave)" >&2
        exit 4
    fi
    echo "SKIP PHASE 2: $1"
    echo "NITRO_E2E=PHASE1_ONLY"
    exit 0
}

# ── PHASE 1 · dev loopback ceremony ─────────────────────────────────────
echo "=== PHASE 1: dev loopback ceremony ==="
cargo build -q -p qsv-cosigner --bins
BIN="$ROOT/target/debug"
PORT=$((41000 + $$ % 900))
LOG=$(mktemp /tmp/qsv_nitro_e2e.XXXXXX.log)

"$BIN/enclave_server" --port "$PORT" --vault e2e-vault >"$LOG" 2>&1 &
SRV=$!
cleanup() {
    kill "$SRV" 2>/dev/null || true
    wait "$SRV" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 150); do
    grep -q E2E_READY "$LOG" && break
    sleep 0.2
done
if ! grep -q E2E_READY "$LOG"; then
    cat "$LOG"
    echo "FATAL: enclave_server never became ready" >&2
    exit 1
fi
PCR0=$(sed -n 's/^DEV_PCR0=//p' "$LOG")
XONLY=$(sed -n 's/^DEV_XONLY=//p' "$LOG")
if [ -z "$PCR0" ] || [ -z "$XONLY" ]; then
    cat "$LOG"
    echo "FATAL: missing DEV_PCR0 / DEV_XONLY pin lines" >&2
    exit 1
fi

probe() { "$BIN/cosign_probe" --tcp --port "$PORT" "$@"; }

echo "--- PASS case (full ceremony)"
probe --vault e2e-vault --pcr0 "$PCR0" --xonly "$XONLY"

echo "--- wrong PCR0 pin must be refused"
if probe --vault e2e-vault --pcr0 "$(printf '00%.0s' $(seq 48))" --xonly "$XONLY" 2>/dev/null; then
    echo "FATAL: wrong PCR0 was accepted" >&2
    exit 1
fi

echo "--- unallowed vault must be refused"
if probe --vault evil-vault --pcr0 "$PCR0" --xonly "$XONLY" 2>/dev/null; then
    echo "FATAL: unallowed vault was accepted" >&2
    exit 1
fi

echo "--- wrong pinned key must be refused"
if probe --vault e2e-vault --pcr0 "$PCR0" --xonly "$(printf '11%.0s' $(seq 32))" 2>/dev/null; then
    echo "FATAL: wrong xonly pin was accepted" >&2
    exit 1
fi

echo "PHASE 1 OK (gate + attestation chain + refusals over the real wire)"
cleanup
trap - EXIT

# ── PHASE 2 · real Nitro enclave ────────────────────────────────────────
echo "=== PHASE 2: real Nitro enclave ==="
command -v nitro-cli >/dev/null 2>&1 || skip_or_fail "nitro-cli not installed (aws-nitro-enclaves-cli)"
command -v docker >/dev/null 2>&1 || skip_or_fail "docker not available"
if ! lspci 2>/dev/null | grep -qi nitro; then
    echo "WARN: no Nitro PCI device visible — run-enclave needs a Nitro-capable host (EC2 .metal)"
fi

bash scripts/nitro_build_enclave.sh e2e-vault

run_out=$(nitro-cli run-enclave \
    --cpu-count 2 \
    --memory-mib 512 \
    --eif-path target/eif/qsv-cosigner.eif)
echo "$run_out"

# Pin the EXACT enclave this run just created: on a shared parent
# instance `describe-enclaves` may list other enclaves, and probing
# `d[0]` would silently test a stranger (wrong PCR0, bogus verdicts).
EID_WANT=$(printf '%s\n' "$run_out" | sed -n 's/^EnclaveID:[[:space:]]*//p' | head -n1 | tr -d '[:space:]')
desc=$(nitro-cli describe-enclaves)
read -r EID PCR0E CID < <(python3 - "$desc" "${EID_WANT:-}" <<'PYEOF'
import json, sys
d = json.loads(sys.argv[1])
want = sys.argv[2] if len(sys.argv) > 2 else ""
if want:
    hits = [e for e in d if e.get("EnclaveId") == want]
elif len(d) == 1:
    hits = d
else:
    sys.exit(
        "cannot identify the fresh enclave "
        f"(no EnclaveID in run output, {len(d)} candidates)"
    )
if not hits:
    sys.exit(f"fresh enclave {want} not found in describe-enclaves")
e = hits[0]
print(e["EnclaveId"], e["Measurements"]["PCR0"], e["EnclaveConfig"]["EnclaveCID"])
PYEOF
)
echo "enclave=$EID cid=$CID pcr0=$PCR0E"
terminate() { nitro-cli terminate-enclave --enclave-id "$EID" >/dev/null 2>&1 || true; }
trap terminate EXIT

# Probe over AF_VSOCK: needs the nsm-feature build (real vsock).
cargo build -q -p qsv-cosigner --features nsm --bin cosign_probe

echo "--- PASS case (hardware measurement)"
ok=0
for _ in $(seq 1 30); do
    if target/debug/cosign_probe --cid "$CID" --port 5005 \
        --vault e2e-vault --pcr0 "$PCR0E" --xonly "$XONLY"; then
        ok=1
        break
    fi
    sleep 1
done
if [ "$ok" != 1 ]; then
    echo "FATAL: enclave probe never passed" >&2
    exit 1
fi

echo "--- dev measurement must NOT satisfy the hardware pin"
if target/debug/cosign_probe --cid "$CID" --port 5005 \
    --vault e2e-vault --pcr0 "$PCR0" --xonly "$XONLY" 2>/dev/null; then
    echo "FATAL: dev PCR0 accepted for a real enclave" >&2
    exit 1
fi

terminate
trap - EXIT
echo "PHASE 2 OK (real enclave, hardware attestation, vsock wire)"
echo "NITRO_E2E=FULL"
