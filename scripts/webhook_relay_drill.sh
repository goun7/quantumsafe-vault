#!/usr/bin/env bash
# Webhook relay drill (docs/10 §3.2, Rounds 18–19): proves the FULL HMAC +
# replay + upstream contract end to end on loopback, standard tools only —
#
#   good + fresh      -> 204
#   REPLAYED          -> 401 (tag already delivered — never forwarded twice)
#   tampered body     -> 401 (tag no longer covers the bytes)
#   unsigned          -> 400
#   no timestamp      -> 400 (freshness is part of the contract)
#   stale (>±tol)     -> 401 (a captured POST expires)
#   wrong bearer      -> 401 (defense in depth after the tag verifies)
#   upstream dead     -> 502 (daemon retries with a fresh stamp — the
#                        at-least-once chain reaches the PAGER)
#   SIGTERM           -> exit 0  (graceful like the Rust bridge)
#
# CI runs this job (ci.yml → relay-drill); no network, no cargo.
set -euo pipefail
cd "$(dirname "$0")/.."

free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

PORT="$(free_port)"
export WEBHOOK_SECRET="whsec_drill_$(date +%s)"
export WEBHOOK_TOKEN="drill-bearer"
LOG="$(mktemp /tmp/qsv_relay_drill.XXXXXX.log)"

cleanup() {
    [[ -n "${RELAY_PID:-}" ]] && kill "$RELAY_PID" 2>/dev/null || true
    [[ -n "${RELAY2_PID:-}" ]] && kill "$RELAY2_PID" 2>/dev/null || true
    rm -f "$LOG" "$LOG2" 2>/dev/null || true
}
trap cleanup EXIT

python3 scripts/webhook_relay.py --port "$PORT" >"$LOG" 2>&1 &
RELAY_PID=$!

wait_ready() { # wait_ready <port> <pid> <log>
    for _ in $(seq 1 50); do
        if curl -s -o /dev/null "http://127.0.0.1:$1/" 2>/dev/null; then return 0; fi
        kill -0 "$2" 2>/dev/null || { echo "DRILL FAIL: relay died at boot ($3)"; cat "$3"; exit 1; }
        sleep 0.1
    done
    echo "DRILL FAIL: relay never came up on $1"; cat "$3"; exit 1
}
wait_ready "$PORT" "$RELAY_PID" "$LOG"

sig() { # sig <ts> <body> — the daemon's byte-exact tag over "<ts>.<body>"
    python3 -c 'import hashlib,hmac,os,sys; print(hmac.new(os.environ["WEBHOOK_SECRET"].encode(), sys.argv[1].encode()+b"."+sys.argv[2].encode(), hashlib.sha256).hexdigest())' "$1" "$2"
}

post() { # post <port> <expected-code> <curl args...>
    local port="$1" want="$2"; shift 2
    local got
    got="$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$port/watchtower" "$@")"
    if [[ "$got" != "$want" ]]; then
        echo "DRILL FAIL: expected $want, got $got — args: $*"
        echo "--- relay log ---"; cat "$LOG"
        exit 1
    fi
}

BODY='{"type":"qsv_watchtower_alert","vault":"drill-vault","tip":900,"idle_blocks":12960}'
NOW="$(date +%s)"
TAG="$(sig "$NOW" "$BODY")"

# 1. A fresh, correctly signed alert is ACCEPTED (204).
post "$PORT" 204 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer drill-bearer" \
    -H "X-QSV-Timestamp: $NOW" \
    -H "X-QSV-Signature: sha256=$TAG" \
    --data-binary "$BODY"

# 2. The EXACT same signed payload again is a REPLAY (401, not 204).
post "$PORT" 401 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer drill-bearer" \
    -H "X-QSV-Timestamp: $NOW" \
    -H "X-QSV-Signature: sha256=$TAG" \
    --data-binary "$BODY"

# 3. A byte-flipped body no longer matches the tag (401).
post "$PORT" 401 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer drill-bearer" \
    -H "X-QSV-Timestamp: $NOW" \
    -H "X-QSV-Signature: sha256=$TAG" \
    --data-binary "${BODY/tip\":900/tip\":901}"

# 4. An unsigned POST never reaches the upstream (400).
post "$PORT" 400 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer drill-bearer" \
    --data-binary "$BODY"

# 5. A signature WITHOUT the freshness stamp is a contract violation (400).
post "$PORT" 400 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer drill-bearer" \
    -H "X-QSV-Signature: sha256=$TAG" \
    --data-binary "$BODY"

# 6. A captured POST that went stale is refused (401) — even signed.
STALE_TS=$((NOW - 4000))
post "$PORT" 401 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer drill-bearer" \
    -H "X-QSV-Timestamp: $STALE_TS" \
    -H "X-QSV-Signature: sha256=$(sig "$STALE_TS" "$BODY")" \
    --data-binary "$BODY"

# 7. Defense in depth: a FRESH valid tag but wrong bearer (401) — a new
#    body so this is not the replay path.
BODY7='{"type":"qsv_watchtower_alert","vault":"drill-bearer","tip":902,"idle_blocks":12960}'
post "$PORT" 401 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer not-the-token" \
    -H "X-QSV-Timestamp: $NOW" \
    -H "X-QSV-Signature: sha256=$(sig "$NOW" "$BODY7")" \
    --data-binary "$BODY7"

# 8. UPSTREAM HOP (Round 19): a relay whose --upstream is DEAD answers 502
#    (authenticated but NOT delivered) — the daemon retries with a fresh
#    stamp, so at-least-once reaches the pager, not just this relay.
PORT2="$(free_port)"
DEAD="$(free_port)"   # bound then dropped: nothing listens there
LOG2="$(mktemp /tmp/qsv_relay_drill2.XXXXXX.log)"
python3 scripts/webhook_relay.py --port "$PORT2" \
    --upstream "http://127.0.0.1:$DEAD/oncall" >"$LOG2" 2>&1 &
RELAY2_PID=$!
wait_ready "$PORT2" "$RELAY2_PID" "$LOG2"
NOW2="$(date +%s)"
BODY8='{"type":"qsv_watchtower_alert","vault":"drill-upstream","tip":903,"idle_blocks":12960}'
post "$PORT2" 502 \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer drill-bearer" \
    -H "X-QSV-Timestamp: $NOW2" \
    -H "X-QSV-Signature: sha256=$(sig "$NOW2" "$BODY8")" \
    --data-binary "$BODY8"
kill -TERM "$RELAY2_PID"
rc2=0; wait "$RELAY2_PID" || rc2=$?
[[ "$rc2" -eq 0 ]] || { echo "DRILL FAIL: relay2 SIGTERM must exit 0, got $rc2"; exit 1; }
RELAY2_PID=""

# 9. Graceful stop: SIGTERM exits 0 (like the Rust bridge).
kill -TERM "$RELAY_PID"
rc=0; wait "$RELAY_PID" || rc=$?
if [[ "$rc" -ne 0 ]]; then
    echo "DRILL FAIL: SIGTERM must exit 0, got $rc"
    exit 1
fi
RELAY_PID=""

echo "RELAY DRILL OK (204/401-replay/401-tamper/400/400/401-stale/401-bearer/502-upstream/exit0)"
