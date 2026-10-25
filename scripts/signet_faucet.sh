#!/usr/bin/env bash
# scripts/signet_faucet.sh — ArkFaucet CAPTCHA-free signet funding loop (Round 37, P5).
#
# Official source (agent-friendly, verified): https://arkfaucet.com/skills/ark-faucet/SKILL.md
#   + https://arkfaucet.com/openapi.json  →  NO account/key/cookie/CAPTCHA.
# Rails: ark (tark1) · lightning (lntbs) · onchain (tb1) — this script uses
# ONCHAIN only (to fund the qsv wallet). Flow: POST /api/request →
# HTTP 202 + claim_status_url → GET /api/claim/{token} → only "sent" is OK.
#
# Usage:
#   scripts/signet_faucet.sh [amount_sats] [max_claim]    # defaults: 1500 3
# Output file: /tmp/qsv_faucet_body (last body) · exit: 0 = ≥1 payment "sent".
#
# Honesty rules (SKILL.md): stop when the rail budget is exhausted
# (rail_cap_reached); obey Retry-After on 429; "unknown" is NEVER retried;
# not a single request to mainnet (the script only produces addresses for
# the -signet wallet).
set -euo pipefail

BASE="${QSV_FAUCET_URL:-https://arkfaucet.com}"
AMOUNT="${1:-1500}"
MAX="${2:-3}"
DATADIR="${QSV_SIGNET_DATADIR:-$HOME/.signet-qsv}"
CLI=(bitcoin-cli "-datadir=$DATADIR" -signet -rpcwallet=qsv)
BODY=/tmp/qsv_faucet_body

log() { echo "[faucet] $*"; }

wallet_addr() { "${CLI[@]}" getnewaddress "" bech32; }

py() { python3 -c "$1" "${@:2}"; }

onchain_budget() {
    curl -sS -m 20 "$BASE/api/status" |
        py 'import json,sys;d=json.load(sys.stdin);print(d["rail_budgets"]["onchain"]["remaining_sats"])' 2>/dev/null || echo -1
}

# Resolve the claim URL from the 202 response (absolute or path-relative).
claim_url() {
    py 'import json,sys
u=json.load(open(sys.argv[1])).get("claim_status_url","")
print(u if u.startswith("http") else sys.argv[2]+u)' "$BODY" "$BASE"
}

poll() { # $1 = claim url
    local i s body
    for i in $(seq 1 60); do          # ≤10 min: a signet block lands ~every 10 min
        body=$(curl -sS -m 20 "$1" || true)
        s=$(printf '%s' "$body" | py 'import json,sys;print(json.load(sys.stdin).get("status","?"))' 2>/dev/null || echo "?")
        case "$s" in
            sent)                log "  ✓ SENT: $body"; return 0 ;;
            failed)               log "  ✗ failed: $body"; return 1 ;;
            unknown|payout_unknown) log "  ✗ UNKNOWN — never retried: $body"; return 2 ;;
            pending|processing)   sleep 10 ;;
            *)                    log "  ? status=$s body=$body"; sleep 10 ;;
        esac
    done
    log "  ⏱ timeout (10 min) — claim $1 unresolved"
    return 1
}

log "target=$BASE amount=${AMOUNT}S max=$MAX datadir=$DATADIR"
budget=$(onchain_budget)
log "onchain rail remaining budget: ${budget}S"
if [ "$budget" -lt "$AMOUNT" ]; then
    log "rail budget insufficient — no request sent (fail-closed, SKILL.md rail rule)"
    exit 3
fi

got=0
for i in $(seq 1 "$MAX"); do
    addr=$(wallet_addr)
    code=$(curl -sS -m 25 -o "$BODY" -w '%{http_code}' \
        -X POST "$BASE/api/request" -H 'Content-Type: application/json' \
        -d "{\"rail\":\"onchain\",\"destination\":\"$addr\",\"amount_sats\":$AMOUNT}" || echo 000)
    log "claim $i/$MAX → HTTP $code addr=$addr"
    case "$code" in
        202|200)
            if url=$(claim_url); then
                if poll "$url"; then got=$((got + 1)); else log "poll failed — loop stopped"; break; fi
            else
                log "no claim_status_url in the response: $(cat "$BODY")"; break
            fi
            ;;
        429)
            ra=$(cat "$BODY" | py 'import json,sys;d=json.load(sys.stdin);print(d.get("retry_after_seconds",60))' 2>/dev/null || echo 60)
            log "429 — Retry-After=${ra}s (SKILL.md: no IP retry, loop stops)"; break
            ;;
        000) log "network error"; break ;;
        *)   log "HTTP $code: $(cat "$BODY")"; break ;;
    esac
    budget=$(onchain_budget)
    if [ "$budget" -lt "$AMOUNT" ]; then
        log "onchain rail budget exhausted ($budget < $AMOUNT) — rail_cap_reached, stopping"
        break
    fi
    sleep 3
done

log "completed payments: $got/$MAX · wallet balance: $(${CLI[@]} getbalance 2>/dev/null || echo '?')"
[ "$got" -gt 0 ]
