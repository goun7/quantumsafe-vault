//! Best-effort ALARM webhooks (docs/10 §3.2): the daemon's secondary alarm
//! channel. Every delivery is AT LEAST ONCE — a failed POST is retried with
//! fixed backoff within the same pass, and the LAST delivery attempt per
//! vault persists in the watchtower state file (`webhook_delivery`) so an
//! operator can see what actually happened. A webhook that keeps failing
//! NEVER changes the process exit code: the primary alarm channel is the
//! exit code itself (the watchtower must not soften a real ALERT because a
//! pager relay was down).

use serde::Serialize;

/// How a vault's webhook delivery ended in the last pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookDelivery {
    /// POST answered 2xx (the relay owns the alert now).
    Delivered,
    /// Every attempt failed; the exit code carried the alarm instead.
    Failed,
    /// This vault configured no webhook (nothing was attempted).
    NotConfigured,
}

/// The observable outcome of one [`post_webhook`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookOutcome {
    /// The delivery verdict (what goes into the state file).
    pub delivery: WebhookDelivery,
    /// How many POST attempts were made (1..=3). 0 when nothing was sent.
    pub attempts: u32,
    /// The last error, when delivery is `Failed` (reporting only).
    pub last_error: Option<String>,
}

/// Best-effort ALARM webhook with FIXED-BACKOFF RETRY (docs/10 §3.2): the
/// POST is attempted up to three times (0.5 s, 1.0 s between attempts —
/// a dead relay costs one pass ~1.5 s, never the daemon). ANY persistent
/// failure is REPORTED (the state file's `webhook_delivery` row), never
/// propagated to the exit code — the alarm contract stays: exit code first.
///
/// HTTPS URLs are honored through the operator's local relay convention
/// (the daemon is std-only: no TLS stack; docs/10 §3.2). Loopback HTTP is
/// the regtest drill path (this module's own unit tests drive it).
pub fn post_webhook(
    url: &str,
    token: Option<&str>,
    secret: Option<&str>,
    vault_id: String,
    tip: u32,
    idle: u32,
) -> WebhookOutcome {
    const RETRIES: u32 = 3;
    let mut last_error: Option<String> = None;
    for attempt in 1..=RETRIES {
        match post_webhook_once(url, token, secret, &vault_id, tip, idle) {
            Ok(()) => {
                return WebhookOutcome {
                    delivery: WebhookDelivery::Delivered,
                    attempts: attempt,
                    last_error: None,
                }
            }
            Err(e) => {
                last_error = Some(e);
                if attempt < RETRIES {
                    // Fixed backoff: 500 ms, then 1 s. Deterministic and
                    // cheap — the pass is already an operator-visible event.
                    std::thread::sleep(std::time::Duration::from_millis(500 * (attempt as u64)));
                }
            }
        }
    }
    WebhookOutcome {
        delivery: WebhookDelivery::Failed,
        attempts: RETRIES,
        last_error,
    }
}

/// The alarm JSON body (identical across attempts — a relay that dedupes
/// by body sees exactly one alert).
fn alarm_body(vault_id: &str, tip: u32, idle: u32) -> String {
    serde_json::json!({
        "type": "qsv_watchtower_alert",
        "vault": vault_id,
        "tip": tip,
        "idle_blocks": idle,
        "message": "heartbeat due: inheritance countdown is running"
    })
    .to_string()
}

/// HMAC-SHA256 over the raw request body (RFC 2104, hand-rolled over the
/// workspace sha2 — no new dependency): the key is zero-padded (or hashed)
/// to the 64-byte block size, then the inner(0x36)/outer(0x5c) passes.
/// The relay re-computes the digest over the EXACT body bytes and compares
/// before trusting the alert.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for b in k.iter() {
        inner.update([b ^ 0x36]);
    }
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    for b in k.iter() {
        outer.update([b ^ 0x5c]);
    }
    outer.update(inner_digest);
    outer.finalize().into()
}

/// ONE webhook POST attempt: std-only HTTP/1.1 over TCP (https:// delegates
/// to the operator's local relay — the daemon has no TLS stack, docs/10
/// §3.2); loopback http:// is the regtest drill path. A 2xx answer means
/// delivered; anything else (status, connect, write, read) is an error.
/// When `secret` is set, the request carries `X-QSV-Timestamp: <unix-s>`
/// and `X-QSV-Signature: sha256=<hex>` — an HMAC-SHA256 over
/// `"<unix-s>.<body>"`, so the freshness stamp and the EXACT body are one
/// signed unit (docs/10 §3.2 replay binding: the relay refuses stale or
/// duplicated deliveries, while each retry stamps a fresh second).
fn post_webhook_once(
    url: &str,
    token: Option<&str>,
    secret: Option<&str>,
    vault_id: &str,
    tip: u32,
    idle: u32,
) -> Result<(), String> {
    // Only https (and http for regtest drills against loopback) is allowed.
    if !(url.starts_with("https://")
        || url.starts_with("http://127.0.0.1")
        || url.starts_with("http://localhost"))
    {
        return Err("webhook url must be https (or http on loopback)".to_string());
    }
    if url.starts_with("https://") {
        // No TLS stack in the daemon's std-only posture: TLS webhooks are
        // delegated to a local relay (curl/systemd) — fail honestly here.
        return Err(
            "tls webhooks require the operator's local relay; see docs/10 §3.2".to_string(),
        );
    }
    let body = alarm_body(vault_id, tip, idle);
    use std::io::{Read, Write};
    let host_port = url
        .strip_prefix("http://")
        .ok_or("bad url")?
        .split('/')
        .next()
        .ok_or("bad url")?
        .to_string();
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>().unwrap_or(80)),
        None => (host_port.clone(), 80),
    };
    let addr = format!("{host}:{port}");
    let mut stream =
        std::net::TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    // REPLAY BINDING (Round 18, docs/10 §3.2): with a secret armed, the
    // tag covers `"<unix-seconds>.<body>"` and `X-QSV-Timestamp` rides
    // alongside — a captured POST is only good inside the relay's
    // freshness window, and never twice (the relay dedupes tags). Each
    // RETRY stamps a fresh second, so at-least-once redelivery is never
    // mistaken for a replay.
    let signed_headers = match secret.filter(|s| !s.is_empty()) {
        Some(s) => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let tag = hex::encode(hmac_sha256(s.as_bytes(), format!("{ts}.{body}").as_bytes()));
            format!("X-QSV-Timestamp: {ts}\r\nX-QSV-Signature: sha256={tag}\r\n")
        }
        None => String::new(),
    };
    let req = format!(
        "POST /watchtower HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}{signed_headers}Connection: close\r\n\r\n{body}",
        body.len(),
        token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default(),
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| format!("read: {e}"))?;
    let ok = resp.starts_with("HTTP/1.1 2") || resp.starts_with("HTTP/1.0 2");
    if ok {
        Ok(())
    } else {
        Err(format!(
            "http status: {}",
            resp.lines().next().unwrap_or("?")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    /// A loopback HTTP relay fixture: accepts up to `hits` connections,
    /// answering the FIRST `fail_first` POSTs with `fail_status` and every
    /// later one with 204. Captures the raw requests so tests can assert
    /// the exact wire shape (path, token header, JSON body). The serve
    /// thread ends by itself after `hits` accepts — tests never manage
    /// the relay's lifetime.
    struct Relay {
        addr: std::net::SocketAddr,
        observed: Arc<Mutex<Vec<String>>>,
    }

    impl Relay {
        fn spawn(hits: u32, fail_first: u32, fail_status: u16) -> Self {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let observed = Arc::new(Mutex::new(Vec::new()));
            let observed_in = Arc::clone(&observed);
            std::thread::spawn(move || {
                for i in 0..hits {
                    let (mut stream, _) = match listener.accept() {
                        Ok(s) => s,
                        Err(_) => break,
                    };
                    let mut buf = vec![0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    observed_in.lock().unwrap().push(req.clone());
                    let status = if i < fail_first { fail_status } else { 204 };
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                }
            });
            Self { addr, observed }
        }

        fn url(&self) -> String {
            format!("http://{}/watchtower", self.addr)
        }

        fn requests(&self) -> Vec<String> {
            self.observed.lock().unwrap().clone()
        }
    }

    #[test]
    fn delivers_on_the_first_attempt_with_the_exact_wire_shape() {
        let relay = Relay::spawn(2, 0, 500);
        let out = post_webhook(&relay.url(), Some("tok"), None, "v".into(), 900, 12_960);
        assert_eq!(out.delivery, WebhookDelivery::Delivered);
        assert_eq!(out.attempts, 1, "a healthy relay answers on attempt 1");
        assert!(out.last_error.is_none());
        let reqs = relay.requests();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].starts_with("POST /watchtower HTTP/1.1\r\n"));
        assert!(reqs[0].contains("Authorization: Bearer tok\r\n"));
        assert!(!reqs[0].contains("X-QSV-Signature"), "no secret, no header");
        assert!(
            !reqs[0].contains("X-QSV-Timestamp"),
            "no secret, no signature pair"
        );
        assert!(reqs[0].contains("\"type\":\"qsv_watchtower_alert\""));
        assert!(reqs[0].contains("\"vault\":\"v\""));
        assert!(reqs[0].contains("\"tip\":900"));
        assert!(reqs[0].contains("\"idle_blocks\":12960"));
    }

    #[test]
    fn retries_a_failing_relay_and_reports_failure_without_magic() {
        let relay = Relay::spawn(3, 3, 500);
        let started = std::time::Instant::now();
        let out = post_webhook(&relay.url(), None, None, "dead".into(), 900, 12_960);
        assert_eq!(out.delivery, WebhookDelivery::Failed);
        assert_eq!(out.attempts, 3, "the ladder must exhaust all three tries");
        let err = out.last_error.unwrap_or_default();
        assert!(err.contains("http status: HTTP/1.1 500"), "{err}");
        // Fixed backoff: 0.5 s + 1.0 s between the three attempts.
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(1_500),
            "backoff must actually back off"
        );
        // Every attempt carried the SAME alert body (relay-side dedupe by
        // body sees one alert, not three variants). The signed pair may
        // differ per attempt — each RETRY stamps a fresh second so the
        // relay never mistakes at-least-once redelivery for a replay.
        let reqs = relay.requests();
        assert_eq!(reqs.len(), 3);
        let bodies: Vec<&str> = reqs
            .iter()
            .map(|r| &r[r.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0)..])
            .collect();
        assert!(
            bodies.windows(2).all(|w| w[0] == w[1]),
            "the alert body must be byte-identical across attempts"
        );
    }

    #[test]
    fn recovers_on_a_later_attempt_of_the_same_pass() {
        // The first two POSTs hit a 5xx, the third is answered 204 —
        // the ladder DELIVERS on attempt 3 without caller intervention.
        let relay = Relay::spawn(3, 2, 500);
        let out = post_webhook(&relay.url(), None, None, "flap".into(), 900, 12_960);
        assert_eq!(out.delivery, WebhookDelivery::Delivered);
        assert_eq!(out.attempts, 3);
        assert!(out.last_error.is_none(), "success clears the error");
        assert_eq!(relay.requests().len(), 3, "all three attempts were sent");
    }

    #[test]
    fn bad_urls_fail_fast_without_connecting_anywhere() {
        let out = post_webhook("ftp://example.invalid", None, None, "v".into(), 1, 1);
        assert_eq!(out.delivery, WebhookDelivery::Failed);
        assert!(out
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("https (or http on loopback)"));
        let out = post_webhook("https://example.invalid/x", None, None, "v".into(), 1, 1);
        assert_eq!(out.delivery, WebhookDelivery::Failed);
        assert!(out
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("local relay"));
        // A loopback url with NO port: the host part is used verbatim and
        // the default port 80 is assumed (the None arm) — the connect
        // then fails loudly, never silently.
        let out = post_webhook("http://localhost", None, None, "v".into(), 1, 1);
        assert_eq!(out.delivery, WebhookDelivery::Failed);
        // Hoisted so the defaulting runs on EVERY pass (a message-only
        // argument would only evaluate when the assert fails).
        let last_error = out.last_error.unwrap_or_default();
        assert!(last_error.contains("connect localhost:80"), "{last_error}");
    }

    #[test]
    fn hmac_sha256_matches_the_rfc_4231_test_vector() {
        // RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There".
        let key = [0x0bu8; 20];
        let tag = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        // Test case 2: key = "Jefe", data = "what do ya want for nothing?".
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // A key LONGER than the 64-byte block is hashed to K0 first
        // (RFC 2104 §4.2): hmac(K, m) == hmac(sha256(K), m) for |K| > 64.
        use sha2::{Digest as _, Sha256};
        let long_key = [0x5Au8; 100];
        let msg = b"over-length key binding";
        assert_eq!(
            hmac_sha256(&long_key, msg),
            hmac_sha256(&Sha256::digest(long_key), msg),
            "an over-block key must be hashed, not truncated"
        );
    }

    #[test]
    fn secret_signs_the_exact_body_and_the_relay_can_authenticate_it() {
        let relay = Relay::spawn(2, 0, 500);
        let out = post_webhook(
            &relay.url(),
            None,
            Some("whsec_test"),
            "v".into(),
            900,
            12_960,
        );
        assert_eq!(out.delivery, WebhookDelivery::Delivered);
        let reqs = relay.requests();
        assert_eq!(reqs.len(), 1);
        // The header is present; re-compute the tag over the captured body
        // EXACTLY as a relay would — `"<captured-ts>.<body>"`, one signed
        // unit. A byte-flipped body OR a shifted timestamp fails the check.
        let ts_line = reqs[0]
            .lines()
            .find(|l| l.starts_with("X-QSV-Timestamp: "))
            .expect("signed request must carry the timestamp");
        let ts = ts_line.trim_start_matches("X-QSV-Timestamp: ");
        let line = reqs[0]
            .lines()
            .find(|l| l.starts_with("X-QSV-Signature: sha256="))
            .expect("signed request must carry the HMAC header");
        let got = line.trim_start_matches("X-QSV-Signature: sha256=");
        let body_start = reqs[0].find("\r\n\r\n").unwrap() + 4;
        let body = &reqs[0][body_start..];
        let want = hex::encode(hmac_sha256(
            b"whsec_test",
            format!("{ts}.{body}").as_bytes(),
        ));
        let raw = &reqs[0];
        assert_eq!(got, want, "relay-side recomputation must match: {raw}");
        // A DIFFERENT key produces a different tag (the relay would refuse).
        let other = hex::encode(hmac_sha256(
            b"whsec_wrong",
            format!("{ts}.{body}").as_bytes(),
        ));
        assert_ne!(got, other);
        // A DIFFERENT second produces a different tag (replay refused).
        let shifted = hex::encode(hmac_sha256(
            b"whsec_test",
            format!("{}.{}", ts.parse::<u64>().unwrap() + 1, body).as_bytes(),
        ));
        assert_ne!(got, shifted, "the tag must be bound to the stamped second");
    }

    #[test]
    fn signature_binds_a_fresh_timestamp_so_a_captured_post_expires() {
        let relay = Relay::spawn(2, 0, 500);
        let out = post_webhook(
            &relay.url(),
            None,
            Some("whsec_test"),
            "v".into(),
            900,
            12_960,
        );
        assert_eq!(out.delivery, WebhookDelivery::Delivered);
        let reqs = relay.requests();
        assert_eq!(reqs.len(), 1);
        // The stamped second sits NEXT to the tag and is fresh (the relay
        // enforces a ±window on it — a captured POST goes stale).
        let ts_line = reqs[0]
            .lines()
            .find(|l| l.starts_with("X-QSV-Timestamp: "))
            .expect("signed request must carry the timestamp");
        let ts: u64 = ts_line
            .trim_start_matches("X-QSV-Timestamp: ")
            .trim()
            .parse()
            .expect("timestamp must be unix seconds");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(
            ts <= now && now - ts <= 5,
            "the stamped second must be fresh: ts={ts} now={now}"
        );
    }

    #[test]
    fn delivery_states_serialize_into_the_state_file_vocabulary() {
        assert_eq!(
            serde_json::to_string(&WebhookDelivery::Delivered).unwrap(),
            "\"delivered\""
        );
        assert_eq!(
            serde_json::to_string(&WebhookDelivery::Failed).unwrap(),
            "\"failed\""
        );
        assert_eq!(
            serde_json::to_string(&WebhookDelivery::NotConfigured).unwrap(),
            "\"not_configured\""
        );
    }
}
