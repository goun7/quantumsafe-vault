#!/usr/bin/env python3
"""QSV watchtower webhook relay — HMAC validator + replay guard (docs/10 §3.2).

The qsv watchtower daemon is std-only: no TLS stack in the daemon itself
(https:// webhooks are delegated to "the operator's local relay"). This
script IS that relay: a STANDARD-LIBRARY-ONLY HTTP receiver that
authenticates every alarm POST before acting on it.

Wire contract (the daemon side lives in `crates/qsv-cli/src/webhook.rs`):

    POST /watchtower HTTP/1.1
    Content-Type: application/json
    Authorization: Bearer whsec_…              (optional WEBHOOK_TOKEN check)
    X-QSV-Timestamp: <unix-seconds>            (freshness stamp)
    X-QSV-Signature: sha256=<hex>              HMAC-SHA256 over "<ts>.<body>"
    …
    {"type":"qsv_watchtower_alert","vault":"…","tip":900,"idle_blocks":12960,…}

REPLAY BINDING (Round 18): the timestamp and the body are ONE signed unit.
A captured POST is refused outside the ±WEBHOOK_TOLERANCE window (default
300 s) and refused AGAIN inside it — the relay dedupes delivered tags, so
an exact duplicate never gets a second 204. Each daemon retry stamps a
fresh second, so at-least-once redelivery is never mistaken for a replay.

Refusal map (nothing is forwarded before authentication):
    400  missing/malformed timestamp or signature header, bad JSON shape
    401  bad tag, stale timestamp, replayed tag, wrong bearer token
    500  server has no WEBHOOK_SECRET (fail-closed boot refuses to start)
    502  authenticated, but the --upstream forward FAILED (Round 19: the
         daemon retries with a fresh stamp — at-least-once runs all the
         way to the pager, not just to this relay)
    204  authenticated (and forwarded upstream when --upstream is set)

Usage:
    WEBHOOK_SECRET=whsec_… python3 scripts/webhook_relay.py \
        [--port 8099] [--bind 127.0.0.1] [--upstream https://ops.example.com/hooks/qsv]

    python3 scripts/webhook_relay.py --print-curl   # signed drill curl

Exit codes: 0 on SIGTERM/SIGINT (graceful stop, like the Rust bridge).
Drill: scripts/webhook_relay_drill.sh (the full refusal map, CI-run).
"""

import argparse
import hashlib
import hmac
import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = os.environ.get("WEBHOOK_SECRET", "")
TOKEN = os.environ.get("WEBHOOK_TOKEN", "")
TOLERANCE = int(os.environ.get("WEBHOOK_TOLERANCE", "300"))
UPSTREAM = None  # set from --upstream

# Delivered tags inside the replay window: tag -> stamped second. Exact
# duplicates are refused ONCE inside the window, pruned after it. The
# check-and-mark is ONE critical section (ThreadingHTTPServer = races).
SEEN = {}
SEEN_LOCK = threading.Lock()


def compute_signature(secret: str, ts: str, body: bytes) -> str:
    """HMAC-SHA256 over `"<ts>.<body>"` — the freshness stamp and the body
    are one signed unit; must match the daemon byte for byte (the relay
    recomputes, never trusts a client-supplied tag)."""
    return hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()


def _prune(now: int) -> None:
    stale = [k for k, t in SEEN.items() if abs(now - t) > TOLERANCE]
    for k in stale:
        del SEEN[k]


class RelayHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802  (http.server API name)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""

        # 1. The freshness stamp must exist and be numeric (Round 18).
        ts = (self.headers.get("X-QSV-Timestamp") or "").strip()
        if not ts.isdigit():
            self._answer(400, {"error": "missing X-QSV-Timestamp: <unix-seconds> header"})
            return

        # 2. The signature header must be present and well-formed.
        header = self.headers.get("X-QSV-Signature", "")
        if not header.startswith("sha256="):
            self._answer(400, {"error": "missing X-QSV-Signature: sha256=<hex> header"})
            return
        got = header[len("sha256="):].strip().lower()

        # 3. Recompute over "<ts>.<body>" and compare CONSTANT-TIME
        #    (hmac.compare_digest — never `==`, which leaks timing).
        if not SECRET:
            self._answer(500, {"error": "server has no WEBHOOK_SECRET configured"})
            return
        want = compute_signature(SECRET, ts, body)
        if not hmac.compare_digest(got, want):
            self._answer(401, {"error": "HMAC verification failed"})
            return

        # 4. Freshness: a captured POST goes stale (Round 18 replay guard).
        now = int(time.time())
        age = abs(now - int(ts))
        if age > TOLERANCE:
            self._answer(401, {"error": f"stale timestamp ({age}s outside ±{TOLERANCE}s)"})
            return

        # 5. Exact-duplicate refusal inside the window: the SAME signed
        #    payload is delivered ONCE (network duplicate == replay).
        with SEEN_LOCK:
            _prune(now)
            if got in SEEN:
                self._answer(401, {"error": "replay detected (tag already delivered)"})
                return
            SEEN[got] = int(ts)

        # 6. Optional bearer-token check (defense in depth, not the auth).
        if TOKEN:
            auth = self.headers.get("Authorization", "")
            if auth != f"Bearer {TOKEN}":
                self._answer(401, {"error": "bad bearer token"})
                return

        # 7. Authenticated: parse, log, forward (if upstream configured).
        try:
            alert = json.loads(body)
        except ValueError:
            self._answer(400, {"error": "body is not JSON"})
            return
        print(
            f"ALARM vault={alert.get('vault')} tip={alert.get('tip')} "
            f"idle={alert.get('idle_blocks')} (signature OK, ts={ts})",
            flush=True,
        )
        if UPSTREAM:
            proc = subprocess.run(
                [
                    "curl",
                    "-fsS",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "-H",
                    f"X-QSV-Signature: sha256={want}",
                    "-H",
                    f"X-QSV-Timestamp: {ts}",
                    "-H",
                    f"X-Forwarded-Signature: sha256={want}",
                    "--data-binary",
                    "@-",
                    UPSTREAM,
                ],
                input=body,
                check=False,
            )
            if proc.returncode != 0:
                # UPSTREAM HOP (Round 19): a failed forward is a FAILED
                # delivery — 502 tells the daemon to retry (with a fresh
                # stamp, so the replay guard lets it through), making
                # at-least-once run all the way to the pager, not just
                # to this relay.
                self._answer(
                    502,
                    {"error": f"upstream forward failed (curl rc={proc.returncode})"},
                )
                return
        self._answer(204, None)

    def _answer(self, code, payload):
        data = b"" if payload is None else (json.dumps(payload) + "\n").encode()
        self.send_response(code)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def log_message(self, fmt, *args):  # quiet default access log
        pass


def print_curl(port):
    """Drill recipe: the exact loopback POST the daemon sends (HMAC computed
    with hashlib, byte-identical to the Rust implementation)."""
    body = json.dumps(
        {
            "type": "qsv_watchtower_alert",
            "vault": "bcrt1qdrill",
            "tip": 900,
            "idle_blocks": 12960,
            "message": "heartbeat due: inheritance countdown is running",
        },
        separators=(",", ":"),
    ).encode()
    ts = str(int(time.time()))
    tag = compute_signature(os.environ.get("WEBHOOK_SECRET", "whsec_test"), ts, body)
    print(
        f'curl -s -X POST http://127.0.0.1:{port}/watchtower \\\n'
        f'  -H "Content-Type: application/json" \\\n'
        f'  -H "X-QSV-Timestamp: {ts}" \\\n'
        f'  -H "X-QSV-Signature: sha256={tag}" \\\n'
        f"  --data-binary '{body.decode()}'"
    )


def main():
    global UPSTREAM
    ap = argparse.ArgumentParser(description="QSV watchtower webhook HMAC relay")
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--upstream", default=None, help="forward authenticated POSTs here (curl)")
    ap.add_argument("--print-curl", action="store_true", help="print a signed drill curl")
    args = ap.parse_args()
    UPSTREAM = args.upstream
    if args.print_curl:
        print_curl(args.port)
        return 0
    if not SECRET:
        sys.exit("WEBHOOK_SECRET env var is required (fail-closed: no secret, no relay)")
    httpd = ThreadingHTTPServer((args.bind, args.port), RelayHandler)
    print(
        f"qsv webhook relay on http://{args.bind}:{args.port}/watchtower "
        f"(HMAC+timestamp required, ±{TOLERANCE}s; upstream={UPSTREAM or 'none'})",
        flush=True,
    )
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))  # graceful like the bridge
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
