//! Co-signer service core: the deterministic signing state machine plus an
//! optional TCP front-end (`serve` / `request_signature`).
//!
//! Deployment modes:
//! - **AWS Nitro Enclave** (Phase 1 prod): the same `Cosigner::handle_request`
//!   runs inside the enclave; transport is vsock; attestation comes from NSM.
//! - **Intel TDX**: same handler, TD quote attestation.
//! - **Dev/plain TCP** (this module): loopback-only, attestation via
//!   `nsm::emit_dev_document` — a REAL COSE_Sign1 document verified by the
//!   terminal through the same production verifier (docs/10 §4.52).

use crate::protocol::{SignRequest, SignResponse, PROTOCOL_VERSION};
use qsv_pqc::{enclave_keypair_from_seed, enclave_xonly_public_key, GateError};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The per-vault counter set (label extension): every gate outcome is
/// recorded under the REQUESTING vault's id.
#[derive(Debug, Default)]
pub struct VaultCounters {
    /// Co-signatures RELEASED for this vault.
    pub accepted_total: AtomicU64,
    /// Refusals for this vault (any gate branch).
    pub refused_total: AtomicU64,
}

/// Per-request service counters (the Prometheus exposition source). The
/// handler increments BEFORE the gate runs, so the accepted + refused split
/// always equals the total: a request that is missing, counted, is a request
/// that crashed the loop — structurally impossible in this design.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Every request that reached the gate (released or refused).
    pub requests_total: AtomicU64,
    /// Requests that RELEASED a co-signature (Theorem 1 passed).
    pub accepted_total: AtomicU64,
    /// Requests refused by ANY gate branch (unprovisioned vault, alarm
    /// freeze, bad PQC proof, bad version, bad hex) plus transport errors.
    pub refused_total: AtomicU64,
    /// Refusals whose reason named the watchtower alarm freeze.
    pub alarm_refused_total: AtomicU64,
    /// Sum of serve latencies in microseconds (the histogram `_sum`).
    pub serve_latency_us_total: AtomicU64,
    /// Number of latency samples recorded (the histogram `_count`) —
    /// protocol requests only (an HTTP scrape is never a serve).
    pub serve_latency_count: AtomicU64,
    /// PER-VAULT attribution (label extension): every gate outcome is
    /// recorded under the REQUESTING vault's id, so the operator sees
    /// WHICH vault consumed (or was denied) the co-signer.
    pub per_vault: Mutex<BTreeMap<String, VaultCounters>>,
    /// Per-vault alarm refusals (count per vault id; a vault appears here
    /// the first time its freeze refuses a request).
    pub alarm_rows: Mutex<BTreeMap<String, AtomicU64>>,
    /// Per-vault RATE-LIMIT refusals (same shape as the alarm rows).
    pub rate_limited_rows: Mutex<BTreeMap<String, AtomicU64>>,
    /// Total requests refused by the per-vault rate limiter.
    pub rate_limited_total: AtomicU64,
    /// LATENCY HISTOGRAM (Prometheus `histogram`): cumulative per-bucket
    /// counts for the SAME serve latencies the `_sum/_count` pair tracks.
    /// CUMULATIVE buckets (Prometheus convention): bucket b counts every
    /// serve ≤ its upper bound; the last `+Inf` row equals the count.
    pub serve_latency_buckets: Mutex<BTreeMap<u64, u64>>,
    /// METRICS SCRAPE DENIALS (Round 18): `GET /metrics` requests refused
    /// for a missing or wrong `X-QSV-Metrics-Token` — a probe counter, the
    /// operator sees who is knocking at the exposition.
    pub metrics_denied_total: AtomicU64,
    /// CAPACITY REFUSALS (Round 19): connections accepted and immediately
    /// closed because every in-flight worker slot was taken — a flood
    /// shows up here instead of an unbounded thread/FD count.
    pub capacity_refused_total: AtomicU64,
    /// SCRAPE-TOKEN ROTATION REFUSALS (Round 23): reload attempts that did
    /// NOT move the gate — `rotate()` refused (armedness is a boot decision;
    /// an empty secret would open the scrape) or the reload could not even
    /// reach a rotation (no token file to re-read while the gate is armed).
    /// The old token stays active in every one of those cases, so the alert
    /// (`QsvCosignerTokenRotationStalled`) fires exactly when the operator
    /// believes a rotation happened and it did not.
    ///
    /// It is an `Arc` because the GATE does the counting: `main.rs` adopts
    /// [`ScrapeToken::denial_counter`] into this field at boot, so a
    /// refusal increments precisely the counter the exposition renders.
    pub rotate_denied_total: Arc<AtomicU64>,
    /// SCRAPE-TOKEN ROTATIONS THAT LANDED (Round 24): the POSITIVE side of
    /// the same contract — a rotation that worked is otherwise invisible,
    /// so the operator can never confirm that the secret Prometheus holds
    /// is the one the bridge now expects. Shared with the gate for the
    /// same reason as the refusal counter: one `Arc`, two readers.
    pub rotate_total: Arc<AtomicU64>,
    /// CONCURRENT WORKERS RIGHT NOW (Round 24, a GAUGE): how much of the
    /// `--max-inflight` budget the bridge is spending at this instant.
    pub workers_active: AtomicU64,
    /// High-water mark of `workers_active` since boot (a gauge, not a
    /// counter): the number that actually sizes a box. With `worker_limit`
    /// below it is the whole capacity story of the deployment.
    pub workers_peak: AtomicU64,
    /// The CONFIGURED `--max-inflight` ceiling (`0` = unlimited), exported
    /// so a saturation rule can compare against it instead of hardcoding
    /// a number the operator never wrote down.
    pub worker_limit: AtomicU64,
}

/// The per-vault token-bucket policy: `capacity` burst tokens, refilled at
/// `refill_per_sec` tokens/second (floor 0 → tokens never exceed capacity).
/// A live bridge with the DEFAULT policy is effectively unthrottled for a
/// single operator (60 burst, 30/min sustained); drills narrow it to prove
/// the limiter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RateLimitPolicy {
    pub capacity: f64,
    pub refill_per_sec: f64,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            capacity: 60.0,
            refill_per_sec: 0.5,
        }
    }
}

impl RateLimitPolicy {
    /// Validates the operator-supplied policy (fail-closed: a zero/negative
    /// capacity would refuse EVERYTHING forever).
    pub fn validate(&self) -> Result<(), String> {
        if !self.capacity.is_finite() || self.capacity < 1.0 {
            return Err(format!(
                "rate-limit capacity must be ≥ 1, got {}",
                self.capacity
            ));
        }
        if !self.refill_per_sec.is_finite() || self.refill_per_sec < 0.0 {
            return Err(format!(
                "rate-limit refill must be ≥ 0 tokens/s, got {}",
                self.refill_per_sec
            ));
        }
        Ok(())
    }
}

/// One vault's token bucket (instant-based refill, evaluated lazily).
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last: std::time::Instant,
}

impl Metrics {
    /// EVERY family name the exposition can ever emit, in a stable order.
    ///
    /// This is the binding contract with the operator tooling:
    /// `scripts/prometheus_alerts.yml` and `scripts/grafana_dashboard.json`
    /// reference these names, and `crates/qsv-cli/tests/monitoring_assets.rs`
    /// asserts the two match. A renamed counter that misses this list would
    /// leave every alert rule silently dead (Prometheus accepts a rule that
    /// references a series nobody exports) — the test turns that into a
    /// build failure instead of a 3 a.m. page that never fires.
    ///
    /// The `_bucket/_sum/_count` rows of the latency histogram are DERIVED
    /// from the `qsv_cosigner_serve_latency_us` family, so only the family
    /// itself is listed.
    pub const METRIC_FAMILIES: &'static [&'static str] = &[
        "qsv_cosigner_requests_total",
        "qsv_cosigner_accepted_total",
        "qsv_cosigner_refused_total",
        "qsv_cosigner_alarm_refused_total",
        "qsv_cosigner_rate_limited_total",
        "qsv_cosigner_metrics_denied_total",
        "qsv_cosigner_capacity_refused_total",
        "qsv_cosigner_rotate_denied_total",
        "qsv_cosigner_rotate_total",
        "qsv_cosigner_workers_active",
        "qsv_cosigner_workers_peak",
        "qsv_cosigner_worker_limit",
        "qsv_cosigner_serve_latency_us",
        "qsv_cosigner_serve_latency_us_sum",
        "qsv_cosigner_refused_by_vault_total",
        "qsv_cosigner_accepted_by_vault_total",
        "qsv_cosigner_alarm_refused_by_vault_total",
        "qsv_cosigner_rate_limited_by_vault_total",
    ];

    /// Fixed latency bucket upper bounds in MICROSECONDS. A single write
    /// lands in the 100 µs bucket; the 2 s bucket is the "something is
    /// wrong" wall. Buckets are the CRATE-LEVEL contract — never reordered
    /// at runtime (scrape diffs must stay comparable across restarts).
    pub const SERVE_LATENCY_BUCKETS_US: &'static [u64] =
        &[1_000, 10_000, 100_000, 500_000, 1_000_000, 2_000_000];

    /// ADOPT THE GATE'S OWN COUNTERS (Round 24): points the exposition at
    /// the [`ScrapeToken`] handle that actually counts rotations, so
    /// `qsv_cosigner_rotate_total` and `qsv_cosigner_rotate_denied_total`
    /// cannot drift away from the gate that produced them. One call, both
    /// counters — the point of sharing the `Arc`s is that they were never
    /// a second source of truth to begin with.
    pub fn adopt_rotation_counters(&mut self, gate: &ScrapeToken) {
        self.rotate_denied_total = gate.denial_counter();
        self.rotate_total = gate.rotation_counter();
    }

    /// Declares the worker ceiling the exposition publishes (Round 24): a
    /// saturation rule needs the CONFIGURED number, and the only place
    /// that number exists is the policy the process was booted with.
    pub fn set_worker_limit(&self, limit: usize) {
        self.worker_limit.store(limit as u64, Ordering::Relaxed);
    }

    /// Publishes how much of the worker budget is in use (Round 24).
    /// `active` follows the live ledger (it can only fall when a worker
    /// is reaped); `peak` is a high-water mark — `fetch_max` makes the
    /// racy "who was higher" answer irrelevant: the maximum wins.
    pub fn observe_workers(&self, active: usize) {
        self.workers_active.store(active as u64, Ordering::Relaxed);
        self.workers_peak
            .fetch_max(active as u64, Ordering::Relaxed);
    }

    /// Records one latency sample: adds to the `_sum/_count` pair AND to
    /// the cumulative histogram buckets. Under the map lock (a serve is
    /// already done by the time its latency lands; contention is nil) —
    /// a poisoned mutex skips the histogram, never the signing path.
    pub fn observe_latency(&self, micros: u64) {
        self.serve_latency_us_total
            .fetch_add(micros, Ordering::Relaxed);
        self.serve_latency_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut buckets) = self.serve_latency_buckets.lock() {
            for &upper in Self::SERVE_LATENCY_BUCKETS_US {
                if micros <= upper {
                    *buckets.entry(upper).or_default() += 1;
                }
            }
            // The +Inf bucket mirrors the total count (cumulative form).
            *buckets.entry(u64::MAX).or_default() += 1;
        }
    }

    /// Renders the histogram rows for `qsv_cosigner_serve_latency_us`:
    /// `# TYPE histogram` + `_bucket{le=".."}` (cumulative, BTreeMap order,
    /// u64::MAX renders as the required `+Inf`) + `_sum` + `_count`. The
    /// old `serve_latency_us_total` counter rows are KEPT unchanged so
    /// existing dashboards never break.
    fn render_latency_histogram(&self, out: &mut String) {
        let sum = self.serve_latency_us_total.load(Ordering::Relaxed);
        let count = self.serve_latency_count.load(Ordering::Relaxed);
        out.push_str(
            "# HELP qsv_cosigner_serve_latency_us Co-signer request serve latency (microseconds)\n# TYPE qsv_cosigner_serve_latency_us histogram\n",
        );
        let buckets = match self.serve_latency_buckets.lock() {
            Ok(g) => g,
            Err(_) => return, // poisoned: skip the rows, keep the scrape
        };
        for &upper in Self::SERVE_LATENCY_BUCKETS_US {
            // The loop iterates only SERVE_LATENCY_BUCKETS_US (no
            // u64::MAX member — the +Inf row is emitted below from the
            // map's dedicated u64::MAX entry), so `le` is plain digits.
            let le = upper.to_string();
            let n = buckets.get(&upper).copied().unwrap_or(0);
            out.push_str(&format!(
                "qsv_cosigner_serve_latency_us_bucket{{le=\"{le}\"}} {n}\n"
            ));
        }
        let inf = buckets.get(&u64::MAX).copied().unwrap_or(0);
        out.push_str(&format!(
            "qsv_cosigner_serve_latency_us_bucket{{le=\"+Inf\"}} {inf}\n"
        ));
        out.push_str(&format!("qsv_cosigner_serve_latency_us_sum {sum}\n"));
        out.push_str(&format!("qsv_cosigner_serve_latency_us_count {count}\n"));
    }
}

impl Metrics {
    /// The Prometheus text exposition (`text/plain; version=0.0.4`).
    /// Counters are read with one relaxed load each — no locks held.
    pub fn render(&self) -> String {
        let t = self.requests_total.load(Ordering::Relaxed);
        let a = self.accepted_total.load(Ordering::Relaxed);
        let r = self.refused_total.load(Ordering::Relaxed);
        let al = self.alarm_refused_total.load(Ordering::Relaxed);
        let rl = self.rate_limited_total.load(Ordering::Relaxed);
        let md = self.metrics_denied_total.load(Ordering::Relaxed);
        let cr = self.capacity_refused_total.load(Ordering::Relaxed);
        let rd = self.rotate_denied_total.load(Ordering::Relaxed);
        let rt = self.rotate_total.load(Ordering::Relaxed);
        let wa = self.workers_active.load(Ordering::Relaxed);
        let wp = self.workers_peak.load(Ordering::Relaxed);
        let wl = self.worker_limit.load(Ordering::Relaxed);
        let l = self.serve_latency_us_total.load(Ordering::Relaxed);
        let mut out = String::with_capacity(1024);
        for (name, help, mtype, value) in [
            (
                "qsv_cosigner_requests_total",
                "Sign requests that reached the enclave gate",
                "counter",
                t,
            ),
            (
                "qsv_cosigner_accepted_total",
                "Co-signatures released (Theorem 1 passed)",
                "counter",
                a,
            ),
            (
                "qsv_cosigner_refused_total",
                "Requests refused by any gate branch",
                "counter",
                r,
            ),
            (
                "qsv_cosigner_alarm_refused_total",
                "Refusals caused by a watchtower alarm freeze",
                "counter",
                al,
            ),
            (
                "qsv_cosigner_rate_limited_total",
                "Requests refused by the per-vault token-bucket limiter",
                "counter",
                rl,
            ),
            (
                "qsv_cosigner_metrics_denied_total",
                "Metric scrapes refused for a missing or wrong scrape token",
                "counter",
                md,
            ),
            (
                "qsv_cosigner_capacity_refused_total",
                "Connections closed because every in-flight worker slot was taken",
                "counter",
                cr,
            ),
            (
                "qsv_cosigner_rotate_denied_total",
                "Scrape-token rotations refused (the previous token stayed active)",
                "counter",
                rd,
            ),
            (
                "qsv_cosigner_rotate_total",
                "Scrape-token rotations that swapped in a new secret",
                "counter",
                rt,
            ),
            (
                "qsv_cosigner_workers_active",
                "Concurrent TLS workers serving right now",
                "gauge",
                wa,
            ),
            (
                "qsv_cosigner_workers_peak",
                "Highest concurrent worker count since boot",
                "gauge",
                wp,
            ),
            (
                "qsv_cosigner_worker_limit",
                "Configured --max-inflight ceiling (0 = unlimited)",
                "gauge",
                wl,
            ),
            (
                "qsv_cosigner_serve_latency_us_sum",
                "Cumulative serve latency in microseconds",
                "counter",
                l,
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} {mtype}\n{name} {value}\n"
            ));
        }
        self.render_latency_histogram(&mut out);
        self.render_per_vault(&mut out);
        out
    }

    /// The per-vault label rows: `qsv_cosigner_refused_by_vault_total
    /// {vault="<id>"} <n>` per seen vault, the matching ACCEPTED rows
    /// `qsv_cosigner_accepted_by_vault_total{vault="<id>"} <n>` (Round 17:
    /// which vault CONSUMED the co-signer, not only which was denied), plus
    /// the alarm-freeze rows
    /// `qsv_cosigner_alarm_refused_by_vault_total{vault="<id>"} <n>`. Rows
    /// are emitted in BTreeMap order — the exposition is DETERMINISTIC for
    /// a given history (scrape diffs are trustworthy).
    fn render_per_vault(&self, out: &mut String) {
        // Rendered UNDER the locks (the exposition is a rare, slow path);
        // a poisoned mutex means the process already panicked — a metrics
        // scrape must not fabricate zeroes on top of that.
        let per_vault = match self.per_vault.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if per_vault.is_empty() {
            return;
        }
        out.push_str(
            "# HELP qsv_cosigner_refused_by_vault_total Requests refused by any gate branch, per vault\n# TYPE qsv_cosigner_refused_by_vault_total counter\n",
        );
        for (id, c) in per_vault.iter() {
            out.push_str(&format!(
                "qsv_cosigner_refused_by_vault_total{{vault=\"{id}\"}} {}\n",
                c.refused_total.load(Ordering::Relaxed)
            ));
        }
        // Round 17: the matching ACCEPTED rows — accepted + refused per
        // vault sums to that vault's requests that reached the gate.
        out.push_str(
            "# HELP qsv_cosigner_accepted_by_vault_total Co-signatures released, per vault\n# TYPE qsv_cosigner_accepted_by_vault_total counter\n",
        );
        for (id, c) in per_vault.iter() {
            out.push_str(&format!(
                "qsv_cosigner_accepted_by_vault_total{{vault=\"{id}\"}} {}\n",
                c.accepted_total.load(Ordering::Relaxed)
            ));
        }
        let alarm_rows = match self.alarm_rows.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if !alarm_rows.is_empty() {
            out.push_str(
                "# HELP qsv_cosigner_alarm_refused_by_vault_total Watchtower-freeze refusals, per vault\n# TYPE qsv_cosigner_alarm_refused_by_vault_total counter\n",
            );
            for (id, n) in alarm_rows.iter() {
                out.push_str(&format!(
                    "qsv_cosigner_alarm_refused_by_vault_total{{vault=\"{id}\"}} {}\n",
                    n.load(Ordering::Relaxed)
                ));
            }
        }
        let rate_rows = match self.rate_limited_rows.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if !rate_rows.is_empty() {
            out.push_str(
                "# HELP qsv_cosigner_rate_limited_by_vault_total Token-bucket refusals, per vault\n# TYPE qsv_cosigner_rate_limited_by_vault_total counter\n",
            );
            for (id, n) in rate_rows.iter() {
                out.push_str(&format!(
                    "qsv_cosigner_rate_limited_by_vault_total{{vault=\"{id}\"}} {}\n",
                    n.load(Ordering::Relaxed)
                ));
            }
        }
    }
}

/// Watchtower alarm status for a single vault, mirrored from the read-only
/// monitoring pass (docs/10 §2). While a vault is in `Alarm`, the co-signer
/// freezes ALL signing for it — fail-closed, Theorem 1 degrades safely:
/// an alarm can only STOP the two-key protocol, never shortcut it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlarmState {
    /// Watchtower reports the heartbeat policy as satisfied.
    Clear,
    /// Watchtower reported the policy overdue; signing is frozen.
    Alarm,
}

/// The enclave co-signer: holds the sealed key material and answers requests
/// strictly according to Theorem 1.
pub struct Cosigner {
    enclave_seed: [u8; 32],
    /// Vault ids this instance is provisioned to serve (allowlist).
    allowed_vaults: Vec<String>,
    /// Watchtower alarm mirror per vault (docs/10 §3.2). Absent == Clear.
    alarms: BTreeMap<String, AlarmState>,
    /// PER-VAULT rate limiter (token buckets; None disables limiting —
    /// the determinism drills may want an unthrottled signer).
    rate_limit: Option<(RateLimitPolicy, Mutex<BTreeMap<String, TokenBucket>>)>,
    /// Per-request counters (exposed via the metrics endpoint).
    pub metrics: Metrics,
}

/// Errors surfaced by the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError {
    /// Request failed the gate (PQC invalid, unknown vault, version mismatch).
    Rejected(String),
    /// Transport-level failure.
    Io(String),
    /// Key material invalid.
    Key(GateError),
}

impl core::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ServiceError::Rejected(s) => write!(f, "request rejected: {s}"),
            ServiceError::Io(s) => write!(f, "transport error: {s}"),
            ServiceError::Key(e) => write!(f, "key error: {e}"),
        }
    }
}

impl std::error::Error for ServiceError {}

/// Gate-result mapping (Round 30): the PQC failure is a REFUSAL (the
/// ceremony answered, nothing signed); every other gate fault is a KEY
/// error that fails the connection. Split from the handler so the KEY
/// arm — unreachable through the enclave key, which cannot fail to derive
/// from any 32-byte seed — is exercised by a direct unit call instead of
/// sitting in the report as an untestable (and therefore untrustworthy)
/// defensive branch.
fn map_gate_outcome(
    res: Result<[u8; 64], GateError>,
    attested: impl FnOnce([u8; 64]) -> Result<SignResponse, ServiceError>,
) -> Result<SignResponse, ServiceError> {
    match res {
        Ok(sig) => attested(sig),
        Err(GateError::PqcVerificationFailed) => {
            Ok(refused("ML-DSA-65 verification failed".into()))
        }
        Err(e) => Err(ServiceError::Key(e)),
    }
}

impl Cosigner {
    /// Provisions a co-signer for an allowlist of vault ids.
    pub fn provision(enclave_seed: [u8; 32], allowed_vaults: Vec<String>) -> Self {
        Self {
            enclave_seed,
            allowed_vaults,
            alarms: BTreeMap::new(),
            rate_limit: Some((RateLimitPolicy::default(), Mutex::new(BTreeMap::new()))),
            metrics: Metrics::default(),
        }
    }

    /// Replaces the per-vault rate-limit policy (None disables limiting).
    /// Fails closed on an invalid policy: the PREVIOUS policy stays armed.
    pub fn set_rate_limit(&mut self, policy: Option<RateLimitPolicy>) -> Result<(), String> {
        match policy {
            Some(p) => {
                p.validate()?;
                self.rate_limit = Some((p, Mutex::new(BTreeMap::new())));
                Ok(())
            }
            None => {
                self.rate_limit = None;
                Ok(())
            }
        }
    }

    /// The token-bucket check: takes ONE token for `vault_id` or reports
    /// the refusal. Refill = `tokens + elapsed × rate`, capped at capacity.
    /// A poisoned bucket map keeps serving (never a self-DoS) — the limiter
    /// is protection, not the gate itself.
    fn take_rate_limit_token(&self, vault_id: &str) -> bool {
        let Some((policy, buckets)) = &self.rate_limit else {
            return true;
        };
        let Ok(mut buckets) = buckets.lock() else {
            return true;
        };
        let now = std::time::Instant::now();
        let bucket = buckets.entry(vault_id.to_string()).or_insert(TokenBucket {
            tokens: policy.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * policy.refill_per_sec).min(policy.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Mirrors a watchtower alarm into the enclave (docs/10 §3.2 integration).
    /// Monotonic by design: an operator can only RAISE alarms here; lowering
    /// requires the explicit `clear_alarm` path after a verified refresh.
    pub fn set_alarm(&mut self, vault_id: &str) {
        self.alarms.insert(vault_id.to_string(), AlarmState::Alarm);
    }

    /// Operator path after a verified heartbeat refresh: clears the frozen
    /// state so the vault can sign again.
    pub fn clear_alarm(&mut self, vault_id: &str) {
        self.alarms.remove(vault_id);
    }

    /// Current alarm status for `vault_id` (absent == Clear).
    pub fn alarm_state(&self, vault_id: &str) -> AlarmState {
        self.alarms
            .get(vault_id)
            .copied()
            .unwrap_or(AlarmState::Clear)
    }

    /// Vault ids currently frozen by a watchtower alarm.
    pub fn alarmed_vaults(&self) -> Vec<String> {
        self.alarms
            .iter()
            .filter(|(_, s)| **s == AlarmState::Alarm)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The x-only public key of this instance's co-signer key. This is the
    /// value that goes into the vault policy as `key_enclave` at setup time.
    pub fn public_key(&self) -> Result<secp256k1::XOnlyPublicKey, ServiceError> {
        let kp = enclave_keypair_from_seed(&self.enclave_seed).map_err(ServiceError::Key)?;
        Ok(enclave_xonly_public_key(&kp))
    }

    /// The deterministic request handler (Theorem 1). The SIGNING decision
    /// is pure: no clocks, no RNG, no human input — same request → same
    /// co-signature, always. Two deliberate exceptions live ONLY in the
    /// attestation envelope produced after the gate opens (Round 27): its
    /// ECDSA signature is randomized (freshness by construction) and its
    /// `timestamp` reads the wall clock (AWS mandates `timestamp > 0`).
    /// The METRICS counters remain the one other observable side effect:
    /// totals split into accepted/refused, alarm branch separated.
    pub fn handle_request(&self, req: &SignRequest) -> Result<SignResponse, ServiceError> {
        self.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
        let outcome = self.handle_request_inner(req);
        let accepted = matches!(&outcome, Ok(resp) if resp.accepted);
        if accepted {
            self.metrics.accepted_total.fetch_add(1, Ordering::Relaxed);
        } else {
            // A refusal answer OR a transport/key error both count as
            // refused — the serve loop renders errors as refusals.
            self.metrics.refused_total.fetch_add(1, Ordering::Relaxed);
        }
        self.record_per_vault(&req.vault_id, accepted);
        outcome
    }

    /// Per-vault attribution: one accepted/refused pair per REQUESTING
    /// vault id (allocated on first sight). Alarm-freeze refusals also
    /// mark the vault's alarm row. Lock-held counters only — no atomics
    /// per vault, no races between the two maps.
    fn record_per_vault(&self, vault_id: &str, accepted: bool) {
        let mut per_vault = match self.metrics.per_vault.lock() {
            Ok(g) => g,
            Err(_) => return, // poisoned: keep serving, skip attribution
        };
        let entry = per_vault.entry(vault_id.to_string()).or_default();
        if accepted {
            entry.accepted_total.fetch_add(1, Ordering::Relaxed);
        } else {
            entry.refused_total.fetch_add(1, Ordering::Relaxed);
            drop(per_vault);
            if self.alarm_state(vault_id) == AlarmState::Alarm {
                if let Ok(mut rows) = self.metrics.alarm_rows.lock() {
                    rows.entry(vault_id.to_string())
                        .or_default()
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    fn handle_request_inner(&self, req: &SignRequest) -> Result<SignResponse, ServiceError> {
        if req.version != PROTOCOL_VERSION {
            return Ok(refused(format!(
                "unsupported protocol version {}",
                req.version
            )));
        }
        // CLIENT CHALLENGE (Round 27, docs/10 §4.52): v2 clients generate
        // the attestation nonce. The enclave validates the SHAPE and
        // echoes the client's value verbatim inside its document — it
        // never re-derives (a server-derived nonce proves nothing about
        // the client's own freshness challenge). A malformed nonce is a
        // protocol-shape violation: fail closed with the reason.
        let nonce: [u8; 32] = match hex::decode(&req.nonce_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
        {
            Some(n) => n,
            None => {
                return Ok(refused(
                    "nonce must be 32 bytes of hex (protocol v2 challenge)".into(),
                ));
            }
        };
        if !self.allowed_vaults.contains(&req.vault_id) {
            return Ok(refused("vault not provisioned on this enclave".into()));
        }
        if !self.take_rate_limit_token(&req.vault_id) {
            // PER-VAULT rate limit: a flood from ONE vault may not consume
            // another vault's budget (provisioned sibling stays served).
            self.metrics
                .rate_limited_total
                .fetch_add(1, Ordering::Relaxed);
            if let Ok(mut rows) = self.metrics.rate_limited_rows.lock() {
                rows.entry(req.vault_id.clone())
                    .or_default()
                    .fetch_add(1, Ordering::Relaxed);
            }
            return Ok(refused(
                "rate limited: too many requests for this vault (token bucket)".into(),
            ));
        }
        if self.alarm_state(&req.vault_id) == AlarmState::Alarm {
            // Watchtower freeze: the heartbeat policy is overdue, so the
            // two-key protocol must stay silent until the vault is refreshed
            // and the operator clears the alarm (docs/10 §3.2).
            self.metrics
                .alarm_refused_total
                .fetch_add(1, Ordering::Relaxed);
            return Ok(refused(
                "watchtower alarm active for vault: signing frozen".into(),
            ));
        }
        let sighash: [u8; 32] = hex::decode(&req.sighash_hex)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| ServiceError::Rejected("sighash must be 32 bytes".into()))?;

        // KEY + VAULT BINDING (Round 27, docs/10 §4.52): the document's
        // `user_data` carries `enclave x-only pubkey ‖ vault_id`, so the
        // terminal binds the attestation to the exact key that produced
        // THIS signature and to the one vault it serves.
        let user_data = crate::nsm::enclave_user_data(&self.public_key()?, &req.vault_id);

        map_gate_outcome(
            qsv_pqc::enclave_sign_if_pqc_valid(
                &req.pqc_vk_hex_bytes()?,
                &req.pqc_sig_hex_bytes()?,
                &sighash,
                &self.enclave_seed,
            ),
            |sig| {
                // Attestation AFTER the gate: no document is ever emitted
                // for a request the gate refused — and if attestation
                // itself fails, the signature is dropped (fail-closed: no
                // unattested co-signature leaves this handler).
                let doc = self.attestation_document(&nonce, &user_data)?;
                Ok(SignResponse {
                    version: PROTOCOL_VERSION,
                    accepted: true,
                    reason: None,
                    schnorr_sig_hex: Some(hex::encode(sig)),
                    attestation_doc_hex: Some(hex::encode(doc)),
                })
            },
        )
    }

    /// Produces the attestation document for an ACCEPTED request.
    ///
    /// * enclave build (`--features nsm`): the REAL NSM document — the
    ///   same COSE_Sign1 the terminal's production verifier checks.
    /// * plain/dev build: `nsm::emit_dev_document` — the same wire shape
    ///   (untagged COSE_Sign1, ES384 fixed-96), signed with the well-known
    ///   dev identity and chained to the pinned dev root.
    ///
    /// Both paths emit a real COSE_Sign1 document; a failure maps to a
    /// refusal, so a co-signature is never released unattested.
    fn attestation_document(
        &self,
        nonce: &[u8; 32],
        user_data: &[u8],
    ) -> Result<Vec<u8>, ServiceError> {
        #[cfg(feature = "nsm")]
        {
            crate::nsm::request_attestation_doc(nonce, user_data)
                .map_err(|e| ServiceError::Rejected(format!("attestation failed: {e}")))
        }
        #[cfg(not(feature = "nsm"))]
        {
            crate::nsm::emit_dev_document(&self.enclave_seed, nonce, user_data)
                .map_err(|e| ServiceError::Rejected(format!("attestation failed: {e}")))
        }
    }

    /// Persisted provisioning descriptor (air-gap install step).
    pub fn save_provisioning(&self, path: &PathBuf) -> Result<(), ServiceError> {
        let doc = serde_json::json!({
            "version": PROTOCOL_VERSION,
            "seed_hex": hex::encode(self.enclave_seed),
            "allowed_vaults": self.allowed_vaults,
        });
        // The json! object is infallible to serialize; only the write
        // can fail (bad path, permissions) and it stays mapped below.
        let bytes = serde_json::to_vec_pretty(&doc)
            .expect("JSON provisioning object serializes infallibly");
        std::fs::write(path, bytes).map_err(|e| ServiceError::Io(e.to_string()))
    }

    /// Loads a provisioning descriptor written by `save_provisioning`.
    pub fn load_provisioning(path: &PathBuf) -> Result<Self, ServiceError> {
        let raw = std::fs::read(path).map_err(|e| ServiceError::Io(e.to_string()))?;
        let doc: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| ServiceError::Io(e.to_string()))?;
        let seed_hex = doc["seed_hex"]
            .as_str()
            .ok_or_else(|| ServiceError::Rejected("missing seed".into()))?;
        let seed: [u8; 32] = hex::decode(seed_hex)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .ok_or_else(|| ServiceError::Rejected("seed must be 32 bytes".into()))?;
        let vaults = doc["allowed_vaults"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        // A fresh enclave boot starts with no alarms mirrored; the daemon
        // re-raises them from persisted watchtower state on its first pass.
        Ok(Self {
            enclave_seed: seed,
            allowed_vaults: vaults,
            alarms: BTreeMap::new(),
            rate_limit: Some((RateLimitPolicy::default(), Mutex::new(BTreeMap::new()))),
            metrics: Metrics::default(),
        })
    }
}

fn refused(reason: String) -> SignResponse {
    SignResponse {
        version: PROTOCOL_VERSION,
        accepted: false,
        reason: Some(reason),
        schnorr_sig_hex: None,
        attestation_doc_hex: None,
    }
}

impl SignRequest {
    fn pqc_vk_hex_bytes(&self) -> Result<Vec<u8>, ServiceError> {
        hex::decode(&self.pqc_vk_hex).map_err(|_| ServiceError::Rejected("bad pqc vk hex".into()))
    }
    fn pqc_sig_hex_bytes(&self) -> Result<Vec<u8>, ServiceError> {
        hex::decode(&self.pqc_sig_hex).map_err(|_| ServiceError::Rejected("bad pqc sig hex".into()))
    }
}

/// One-framed transport: 8-byte big-endian length prefix + JSON. Works over
/// ANY stream (plain TCP today, TLS-wrapped TCP on the dev bridge).
pub(crate) fn read_frame<S: Read>(stream: &mut S) -> Result<Vec<u8>, ServiceError> {
    let mut len_buf = [0u8; 8];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    let len = u64::from_be_bytes(len_buf) as usize;
    if len > 1 << 20 {
        return Err(ServiceError::Rejected("frame too large".into()));
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    Ok(buf)
}

pub(crate) fn write_frame<S: Write>(stream: &mut S, bytes: &[u8]) -> Result<(), ServiceError> {
    let len = (bytes.len() as u64).to_be_bytes();
    stream
        .write_all(&len)
        .and_then(|_| stream.write_all(bytes))
        // Flush so a buffered sink hands the frame onward — a flush
        // failure must surface as an error, never become a silent drop.
        .and_then(|_| stream.flush())
        .map_err(|e| ServiceError::Io(e.to_string()))
}

/// Per-serve policy (Round 18): how an accepted stream is bounded and who
/// may scrape `/metrics`.
///
/// * `frame_timeout` — read/write deadline on EVERY accepted socket: the
///   16-byte probe, the frame ceremony, the HTTP head and (through the
///   inner TcpStream) the TLS handshake share it. A peer that connects and
///   goes quiet can delay the serial loop for at most ONE timeout and can
///   never pin a TLS worker forever — which also BOUNDS the graceful
///   shutdown drain (SIGTERM joins in-flight workers, and in-flight is now
///   finite by construction). `None` = unbounded (library callers that
///   manage their own liveness).
/// * `metrics_token` — the ROTATABLE scrape gate: when armed, `GET
///   /metrics` must present the exact `X-QSV-Metrics-Token` value; every
///   denial counts in `qsv_cosigner_metrics_denied_total`. Disarmed =
///   open scrape (loopback dev default). The value lives behind
///   [`ScrapeToken`] so a running bridge can adopt a new secret on
///   SIGHUP without a restart (docs/10 §4.30).
/// * `max_inflight` — cap on concurrent worker threads (TLS loop): a
///   connection beyond the cap is accepted and immediately CLOSED (the
///   peer sees a clean refusal), counted in
///   `qsv_cosigner_capacity_refused_total`. `0` = unlimited.
#[derive(Clone, Debug)]
pub struct ServePolicy {
    /// Per-stream read/write deadline (`None` = unbounded).
    pub frame_timeout: Option<std::time::Duration>,
    /// Required scrape token for `GET /metrics` (disarmed = open scrape).
    pub metrics_token: ScrapeToken,
    /// Concurrent worker cap (`0` = unlimited).
    pub max_inflight: usize,
}

impl Default for ServePolicy {
    fn default() -> Self {
        Self {
            // 10 s default: generous for any honest client (handshake +
            // frame), short enough that a stalled peer can never pin a
            // worker or the SIGTERM drain.
            frame_timeout: Some(std::time::Duration::from_secs(10)),
            metrics_token: ScrapeToken::disarmed(),
            // 64 concurrent workers: a flood becomes a REFUSAL long
            // before threads/fds run out (0 = unlimited).
            max_inflight: 64,
        }
    }
}

/// ROTATABLE SCRAPE GATE (docs/10 §4.30, Round 22): the secret behind
/// `/metrics` lives in a shared handle so a RUNNING bridge can adopt a
/// new one without a restart — `systemctl reload` (SIGHUP) re-reads
/// `--metrics-token-file` and swaps the value in place. The gate closes
/// for zero milliseconds, the signing path never observes the swap, and
/// the handle cannot go back to "open" once armed: rotation REPLACES the
/// secret and an empty rotation is refused (the old value stays).
#[derive(Clone, Debug, Default)]
pub struct ScrapeToken {
    /// The shared secret (`None` = the scrape is open).
    gate: std::sync::Arc<std::sync::RwLock<Option<String>>>,
    /// ROTATION-REFUSAL COUNTER (Round 23): every rotation the gate turns
    /// away (plus every reload that could not even reach a rotation) adds
    /// one here. `main.rs` adopts this exact `Arc` into
    /// [`Metrics::rotate_denied_total`] at boot, so the count the alert
    /// rule reads IS the count the gate recorded — no second source of
    /// truth, no wire-up to forget at the call site.
    denials: Arc<AtomicU64>,
    /// The mirror image: rotations that actually SWAPPED a secret (Round
    /// 24). Same sharing discipline as `denials` — one `Arc`, rendered by
    /// the exposition, so "did my reload land?" is answerable from a
    /// scrape instead of from a journald line nobody is watching.
    rotations: Arc<AtomicU64>,
}

impl ScrapeToken {
    /// No token — the scrape stays open (loopback dev default).
    pub fn disarmed() -> Self {
        Self::default()
    }

    /// Gate armed with `secret` (compared constant-time at scrape time).
    pub fn armed(secret: impl Into<String>) -> Self {
        Self {
            gate: std::sync::Arc::new(std::sync::RwLock::new(Some(secret.into()))),
            denials: Arc::new(AtomicU64::new(0)),
            rotations: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Boot form: `Some` arms the gate, `None` leaves the scrape open.
    pub fn from_option(secret: Option<String>) -> Self {
        secret.map(Self::armed).unwrap_or_else(Self::disarmed)
    }

    /// Is the gate closed (a token is required to scrape)?
    pub fn is_armed(&self) -> bool {
        self.gate.read().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Snapshot of the current secret (`None` = open scrape).
    pub fn current(&self) -> Option<String> {
        self.gate.read().ok().and_then(|g| g.clone())
    }

    /// Rotations this gate has REFUSED so far.
    pub fn denials(&self) -> u64 {
        self.denials.load(Ordering::Relaxed)
    }

    /// The shared refusal counter — `main.rs` adopts it into
    /// [`Metrics::rotate_denied_total`] so the exposition renders the
    /// gate's own count (Round 23).
    pub fn denial_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.denials)
    }

    /// The shared SUCCESS counter (Round 24) — the pair of
    /// `denial_counter()`, so "rotations landed" is as answerable as
    /// "rotations were refused".
    pub fn rotation_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.rotations)
    }

    /// Rotations this gate has performed so far.
    pub fn rotations(&self) -> u64 {
        self.rotations.load(Ordering::Relaxed)
    }

    /// Record a reload that never became a rotation (Round 23): the
    /// operator sent SIGHUP, the gate is armed, but there is no token
    /// file to re-read — `systemctl reload` did NOTHING and the unit
    /// keeps scraping with the old secret. Counted for the alert; the
    /// caller still logs the human-readable reason.
    ///
    /// Only an ARMED gate counts: a disarmed bridge has nothing to
    /// rotate, so a stray HUP there is not a failed rotation (and must
    /// not page anyone).
    pub fn record_denial(&self) {
        if self.is_armed() {
            self.denials.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Swap in a new secret, returning the previous one (the operator
    /// log proves the swap without ever printing the new value).
    /// CONTRACT: armedness is a BOOT decision — rotation only changes
    /// the secret, it can neither arm a disarmed gate (a runtime policy
    /// change) nor empty it (that would open the scrape); both are
    /// refused with the old value intact. A refusal is COUNTED
    /// (`qsv_cosigner_rotate_denied_total`) — a `systemctl reload` that
    /// did nothing must be visible to the alerting, not only to stderr.
    pub fn rotate(&self, secret: String) -> Result<Option<String>, String> {
        let mut gate = match self.gate.write() {
            Ok(g) => g,
            Err(e) => {
                self.denials.fetch_add(1, Ordering::Relaxed);
                return Err(format!("scrape gate unreadable: {e}"));
            }
        };
        if gate.is_none() {
            self.denials.fetch_add(1, Ordering::Relaxed);
            return Err(
                "the scrape gate was never armed; armedness is decided at boot, not on rotation"
                    .to_string(),
            );
        }
        if secret.is_empty() {
            self.denials.fetch_add(1, Ordering::Relaxed);
            return Err("refusing to rotate the scrape gate to an empty token".to_string());
        }
        // The swap HAPPENED: count it before releasing the lock (the
        // counter is independent of the gate, so this is also the exact
        // moment the exposition will see).
        let previous = gate.replace(secret);
        drop(gate);
        self.rotations.fetch_add(1, Ordering::Relaxed);
        Ok(previous)
    }
}

/// Applies the policy's deadlines to an accepted socket (best effort: a
/// platform that refuses the call still serves, just unbounded).
fn apply_frame_timeout(stream: &TcpStream, timeout: Option<std::time::Duration>) {
    if let Some(t) = timeout {
        let _ = stream.set_read_timeout(Some(t));
        let _ = stream.set_write_timeout(Some(t));
    }
}

/// Constant-time byte comparison for scrape tokens: no early exit, a
/// scrape oracle must not leak the token prefix through timing.
fn token_eq(a: &[u8], b: &[u8]) -> bool {
    // CONSTANT-TIME (Round 25): no early return — the old length check
    // exited before the fold, so a mismatch LENGTH answered faster than
    // a mismatch in the last byte. The fold now always runs over the
    // LONGER input (the shorter padded with zeros, which cannot forge a
    // match because the length is folded in separately at the end).
    // Runtime depends only on the presented length — which the attacker
    // chose and can already see on the wire — never on WHERE the first
    // differing byte sits.
    let max = a.len().max(b.len());
    let mut diff = 0u8;
    for i in 0..max {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0 && a.len() == b.len()
}

/// Case-insensitive header lookup in a raw HTTP head (first match wins).
fn header_value(head: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Feeds the bytes read during the HTTP probe back into the ordinary frame
/// reader: the probe consumes, NOTHING is lost, nothing is read twice.
struct Prefixed<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S: Read> Read for Prefixed<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // The prefix is an in-memory Cursor — its read cannot fail, so
        // the `?` error region on this line is an invariant, not a path.
        let from_prefix = self.prefix.read(buf).expect("Cursor::read is infallible");
        if from_prefix > 0 {
            return Ok(from_prefix);
        }
        self.inner.read(buf)
    }
}

impl<S: Write> Write for Prefixed<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Reads the request head (until a blank line) and answers ONE of two ways:
/// `GET /metrics` → the Prometheus exposition (no counters moved —
/// observing is not signing); ANY other HTTP path → a REFUSAL frame (the
/// junk is treated as the frame-length attack it is). The loop always
/// survives. Returns false when the peer vanished mid-head (just close).
fn serve_http_head<S: Read + Write>(
    stream: &mut S,
    head0: &[u8],
    shared: &Arc<Mutex<Cosigner>>,
    gate: &ScrapeToken,
) -> bool {
    let mut head = head0.to_vec();
    let header_done =
        |h: &[u8]| h.windows(4).any(|w| w == b"\r\n\r\n") || h.windows(2).any(|w| w == b"\n\n");
    while !header_done(&head) {
        if head.len() > 8192 {
            return false;
        }
        let mut b = [0u8; 64];
        match stream.read(&mut b) {
            Ok(0) => return false,
            Ok(m) => head.extend_from_slice(&b[..m]),
            Err(_) => return false,
        }
    }
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .or_else(|| head.windows(1).position(|w| w == b"\n"))
        .unwrap_or(head.len());
    let line = String::from_utf8_lossy(&head[..line_end]);
    if line.starts_with("GET ") && line.contains(" /metrics ") {
        // SCRAPE AUTH (Round 18, ROTATABLE since Round 22): an armed
        // gate snapshots its CURRENT secret per scrape — a SIGHUP swap
        // is visible on the very next request. A scrape without (or
        // with a wrong) `X-QSV-Metrics-Token` is refused 401 AND
        // counted; only the authorized scrape renders.
        if let Some(want) = gate.current() {
            let presented = header_value(&head, "X-QSV-Metrics-Token");
            let ok = presented
                .as_deref()
                .map(|p| token_eq(p.as_bytes(), want.as_bytes()))
                .unwrap_or(false);
            if !ok {
                if let Ok(c) = shared.lock() {
                    c.metrics
                        .metrics_denied_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                let body = "{\"error\":\"metrics scrape denied\"}";
                let http = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(http.as_bytes());
                let _ = stream.flush();
                return true;
            }
        }
        let body = match shared.lock() {
            Ok(c) => c.metrics.render().into_bytes(),
            Err(_) => return false,
        };
        let http = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(http.as_bytes());
        let _ = stream.write_all(&body);
        let _ = stream.flush();
        return true;
    }
    // Other HTTP junk: the 8-byte length reader would see a monstrous
    // length — answer exactly that refusal, deterministically.
    // SignResponse is a flat struct of numbers/strings — serialization
    // is infallible, so this asserts an invariant rather than a path.
    let body = serde_json::to_vec(&refused("frame too large".into()))
        .expect("refused(SignResponse) serializes infallibly");
    let _ = write_frame(stream, &body);
    let _ = stream.flush();
    true
}

/// ONE connection, ANY stream (plain TCP or TLS-wrapped): the HTTP probe,
/// the metrics scrape, the frame ceremony and the best-effort reply. A bad
/// client is answered or dropped — it can never take the service down.
fn serve_one_stream<S: Read + Write>(
    stream: &mut S,
    shared: &Arc<Mutex<Cosigner>>,
    mirror: &dyn Fn(),
    policy: &ServePolicy,
) {
    let started = std::time::Instant::now();
    // HTTP probe: a scraper's first bytes are ASCII "GET "; a protocol
    // client's are a binary length prefix. The probe bytes are FED BACK
    // through [`Prefixed`], so no byte is lost and nothing is read twice.
    let mut probe = [0u8; 16];
    let n = match stream.read(&mut probe) {
        Ok(0) | Err(_) => return,
        Ok(n) => n,
    };
    if probe[..n].starts_with(b"GET ") {
        // An HTTP client never reaches the gate: no mirror, no latency,
        // no counters (an observability probe must not touch signing).
        let _ = serve_http_head(stream, &probe[..n], shared, &policy.metrics_token);
        return;
    }
    mirror();
    let mut prefixed = Prefixed {
        prefix: std::io::Cursor::new(probe[..n].to_vec()),
        inner: stream,
    };
    let resp = (|| -> Result<SignResponse, ServiceError> {
        let frame = read_frame(&mut prefixed)?;
        let req: SignRequest = serde_json::from_slice(&frame)
            .map_err(|e| ServiceError::Rejected(format!("bad request json: {e}")))?;
        shared
            .lock()
            .map_err(|_| ServiceError::Io("cosigner lock poisoned".into()))?
            .handle_request(&req)
    })();
    let resp = match resp {
        Ok(r) => r,
        Err(e) => refused(e.to_string()),
    };
    if let Ok(c) = shared.lock() {
        // ONE sample feeds the _sum/_count pair AND the histogram buckets
        // (the mean stays derivable from the unchanged counter rows).
        c.metrics
            .observe_latency(started.elapsed().as_micros() as u64);
    }
    // Best-effort reply: a client that vanished mid-request must not kill
    // the service loop. The request head/frame was fully consumed by the
    // readers, so the close is a clean FIN (never a reset).
    if let Ok(body) = serde_json::to_vec(&resp) {
        let _ = write_frame(&mut prefixed, &body);
        // TLS-buffered writes leave ONLY on flush (plain TCP sends
        // immediately; rustls waits for the explicit flush).
        let _ = prefixed.flush();
    }
}

/// Serves co-signature requests on `addr` (loopback in dev mode; vsock in the
/// enclave build). One request per connection; deterministic responses.
pub fn serve(cosigner: Cosigner, addr: &str) -> Result<(), ServiceError> {
    let listener = TcpListener::bind(addr).map_err(|e| ServiceError::Io(e.to_string()))?;
    serve_listener(listener, Arc::new(Mutex::new(cosigner)))
}

/// NORMAL-EXITING serve (Round 29 P5): identical semantics to [`serve`] for
/// the first `max_requests` connections, then the loop returns the ordinary
/// `Ok(())` and the process exits 0. This exists because a child killed with
/// SIGKILL never flushes its `.profraw` — its own startup lines score ZERO
/// line coverage no matter what it did. A bounded child carries its
/// coverage out with it, so `enclave_server --max-requests N` under
/// `cargo llvm-cov` is honest instead of silently blind.
pub fn serve_limited(
    cosigner: Cosigner,
    addr: &str,
    max_requests: u64,
) -> Result<(), ServiceError> {
    let listener = TcpListener::bind(addr).map_err(|e| ServiceError::Io(e.to_string()))?;
    let shared = Arc::new(Mutex::new(cosigner));
    let policy = ServePolicy::default();
    // A RANGE loop, not `loop`+return: the back-edge executes after every
    // served connection (including the last), so the bounded child's own
    // profile data covers this function completely before it exits 0.
    for _ in 0..max_requests {
        let (mut stream, _) = listener
            .accept()
            .map_err(|e| ServiceError::Io(e.to_string()))?;
        apply_frame_timeout(&stream, policy.frame_timeout);
        serve_one_stream(&mut stream, &shared, &|| {}, &policy);
    }
    // The listener drops here (bind releases) and the exit is the
    // ordinary Ok — never an error, never a kill.
    Ok(())
}

/// Serves on `addr` with a SHARED cosigner: the alarm mirror (and any other
/// operator control path) can raise/clear freezes while the service runs.
pub fn serve_shared(addr: &str, shared: Arc<Mutex<Cosigner>>) -> Result<(), ServiceError> {
    let listener = TcpListener::bind(addr).map_err(|e| ServiceError::Io(e.to_string()))?;
    serve_listener(listener, shared)
}

/// The accept loop on an already-bound listener (testable: bind 127.0.0.1:0
/// yourself and pass the listener). One request per connection; the cosigner
/// is locked per request so alarms can move between requests. A BAD client
/// (empty probe, truncated frame, malformed JSON) is answered with a refusal
/// or dropped — it must never take the whole service down; only a listener
/// failure is fatal.
pub fn serve_listener(
    listener: TcpListener,
    shared: Arc<Mutex<Cosigner>>,
) -> Result<(), ServiceError> {
    serve_with_mirror(listener, shared, || {})
}

/// Like [`serve_listener`], but `mirror` runs BEFORE every request: this is
/// where the alarm bridge re-reads the watchtower state file, so a daemon
/// refresh takes effect without restarting the service. The mirror must be
/// fast and must never panic the loop; on its internal errors it should keep
/// the last known mirror (conservative: alarms never silently clear).
pub fn serve_with_mirror(
    listener: TcpListener,
    shared: Arc<Mutex<Cosigner>>,
    mirror: impl Fn(),
) -> Result<(), ServiceError> {
    serve_with_mirror_and_shutdown(
        listener,
        shared,
        mirror,
        Shutdown::disabled(),
        ServePolicy::default(),
    )
}

/// Cooperative wait granularity (Round 17): the accept loops set the
/// listener NONBLOCKING and re-poll the shutdown edge every tick. A
/// blocking `accept()` would PARK the loop with the flag already flipped
/// (SIGTERM noticed only at the NEXT connection — possibly never); the
/// tick makes the edge observable within 10ms even when nobody connects.
/// Frame I/O is untouched: only the ACCEPT is nonblocking, an accepted
/// stream is restored to blocking so a request is always served whole.
const SHUTDOWN_POLL_TICK: std::time::Duration = std::time::Duration::from_millis(10);

/// The SERIAL accept loop with a cooperative shutdown edge (Round 17):
/// `should_shutdown` is polled between iterations. SIGTERM flips the flag
/// (the bridge installs the signal hook via `install_signal_shutdown`) → the
/// loop falls out, the listener is DROPPED here (bind releases) and the
/// return path is the ordinary `Ok(())` — the process exits 0, systemd's
/// `Restart=on-failure` has nothing to restart. In-flight frames are never
/// aborted mid-parse (serial loop: a request is finished before the next
/// accept), so no client sees a torn frame.
pub fn serve_with_mirror_and_shutdown(
    listener: TcpListener,
    shared: Arc<Mutex<Cosigner>>,
    mirror: impl Fn(),
    shutdown: Shutdown,
    policy: ServePolicy,
) -> Result<(), ServiceError> {
    // NONBLOCKING accept + tick (see SHUTDOWN_POLL_TICK): otherwise the
    // loop parks inside a blocking accept() and never observes the edge.
    listener
        .set_nonblocking(true)
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    // HONEST SERIAL CEILING (Round 25): this loop serves exactly ONE
    // connection at a time. A fresh Metrics renders `worker_limit 0`,
    // which reads "unlimited" — a lie; the TLS loop's --max-inflight is
    // a cap this loop never enforces either. The saturation rule reads
    // this gauge, so it publishes the truth: 1. (The rule exempts
    // limit <= 1: a serial loop that is BUSY is not saturated — busy IS
    // its normal state, and its overload signal is latency, not threads.)
    if let Ok(c) = shared.lock() {
        c.metrics.set_worker_limit(1);
    }
    loop {
        // Cooperative poll BEFORE the accept: when the flag flips we drop
        // the listener ON PURPOSE (releases the bind immediately) and
        // return the ordinary Ok — a graceful stop, not an error.
        if shutdown.should_shutdown() {
            drop(listener);
            return Ok(());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // Only the ACCEPT is nonblocking: frame reads/writes stay
                // blocking, so the request completes before the next
                // shutdown check (no torn frame on TERM).
                let _ = stream.set_nonblocking(false);
                // Round 18: the policy's deadline bounds this connection —
                // a silent peer holds the SERIAL loop for at most one
                // timeout, then the loop moves on (never poisoned).
                apply_frame_timeout(&stream, policy.frame_timeout);
                // OCCUPANCY (Round 25): the serial ledger counts the ONE
                // connection in service — the scrape that renders this
                // gauge included, exactly like the TLS loop counts its
                // own scrape worker. Peaked at 1, never more.
                if let Ok(c) = shared.lock() {
                    c.metrics.observe_workers(1);
                }
                serve_one_stream(&mut stream, &shared, &mirror, &policy);
                if let Ok(c) = shared.lock() {
                    c.metrics.observe_workers(0);
                }
            }
            // Idle: wait a tick, then re-poll the edge.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(SHUTDOWN_POLL_TICK)
            }
            Err(e) => return Err(ServiceError::Io(e.to_string())),
        }
    }
}

/// TLS variant of [`serve_with_mirror`]: every accepted connection is
/// wrapped in a fresh rustls server session (clone of the SAME config), so
/// the metrics scrape and the frame ceremony both run INSIDE the tunnel.
/// A plaintext client against this port fails the handshake and is closed —
/// it never sees (or sends) a single cleartext co-signature.
/// The per-connection mirror as a trait object (the TLS loop hands every
/// worker thread its own clone; the shared `Arc` keeps it cheap).
type Mirror = Arc<dyn Fn() + Send + Sync>;

pub fn serve_with_tls_mirror(
    listener: TcpListener,
    shared: Arc<Mutex<Cosigner>>,
    mirror: impl Fn() + Send + Sync + 'static,
    tls: std::sync::Arc<rustls::ServerConfig>,
) -> Result<(), ServiceError> {
    serve_with_tls_mirror_and_shutdown(
        listener,
        shared,
        mirror,
        tls,
        Shutdown::disabled(),
        ServePolicy::default(),
    )
}

/// TLS accept loop with a cooperative shutdown edge (Round 17): SIGTERM
/// closes the listener AND drains the in-flight workers — every connection
/// accepted BEFORE the signal is served to completion (the TLS frame
/// ceremony is one request per connection, so the drain is bounded by the
/// request timeout, not by a hostile client's imagination). Connections
/// accepted AFTER the signal: refused (connection reset — the bridge is
/// going away; the client retries against the next replica). The workers
/// are JOINED: when this function returns, every in-flight co-signature is
/// already on its way back to its client.
pub fn serve_with_tls_mirror_and_shutdown(
    listener: TcpListener,
    shared: Arc<Mutex<Cosigner>>,
    mirror: impl Fn() + Send + Sync + 'static,
    tls: std::sync::Arc<rustls::ServerConfig>,
    shutdown: Shutdown,
    policy: ServePolicy,
) -> Result<(), ServiceError> {
    // THREAD PER CONNECTION. The TLS handshake consumes a full ClientHello
    // inside the FIRST stream read — a serial accept loop would stall the
    // whole service behind any client that connects and goes quiet (even
    // without TLS this is why the loop must never wait on one peer's
    // bytes). All state is shared behind the cosigner mutex; the loop
    // itself only accepts.
    let mirror: Mirror = Arc::new(mirror);
    // NONBLOCKING accept + tick (see SHUTDOWN_POLL_TICK): a blocking
    // accept() would swallow SIGTERM until the next client connects.
    listener
        .set_nonblocking(true)
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    let mut in_flight: Vec<std::thread::JoinHandle<()>> = Vec::new();
    // WORKER OCCUPANCY (Round 24): the configured ceiling is published
    // ONCE, from the policy this loop actually runs, so a saturation
    // rule compares against the operator's number and not a constant
    // someone typed into a rule file.
    if let Ok(c) = shared.lock() {
        c.metrics.set_worker_limit(policy.max_inflight);
    }
    loop {
        // Cooperative poll BEFORE the accept: SIGTERM stops accepting
        // FIRST (the bind releases for the next replica), then drains.
        if shutdown.should_shutdown() {
            drop(listener);
            break;
        }
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            // Idle: wait a tick, then re-poll the edge.
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(SHUTDOWN_POLL_TICK);
                continue;
            }
            Err(e) => return Err(ServiceError::Io(e.to_string())),
        };
        // The handshake worker does blocking reads — restore blocking mode
        // (only the ACCEPT is nonblocking).
        let _ = stream.set_nonblocking(false);
        // Round 18: the deadline lands on the INNER TcpStream, so it
        // bounds the TLS handshake AND the frame ceremony — a silent
        // peer's worker (and the SIGTERM drain waiting on it) is finite.
        apply_frame_timeout(&stream, policy.frame_timeout);
        // Round 19: REAP + CAP. Finished workers leave the ledger (their
        // slot frees up), and the cap turns a connection flood into a
        // REFUSAL (immediate clean close) instead of an unbounded
        // thread/FD explosion. 0 = unlimited.
        in_flight.retain(|h| !h.is_finished());
        let live = in_flight.len();
        if policy.max_inflight > 0 && live >= policy.max_inflight {
            if let Ok(c) = shared.lock() {
                c.metrics
                    .capacity_refused_total
                    .fetch_add(1, Ordering::Relaxed);
                c.metrics.observe_workers(live);
            }
            drop(stream);
            continue;
        }
        let shared = Arc::clone(&shared);
        // A SECOND handle for the occupancy publish below: the first
        // binding is moved into the worker, the gauge still needs the
        // cosigner after the push.
        let gauge_view = Arc::clone(&shared);
        let mirror = Arc::clone(&mirror);
        let tls = Arc::clone(&tls);
        let policy = policy.clone();
        in_flight.push(std::thread::spawn(move || {
            let conn = match rustls::ServerConnection::new(tls) {
                Ok(c) => c,
                Err(_) => return,
            };
            let mut tls_stream = rustls::StreamOwned::new(conn, stream);
            serve_one_stream(&mut tls_stream, &shared, &*mirror, &policy);
            // Best-effort TLS shutdown: queue close_notify ONLY when a
            // session actually exists — a peer that never finished the
            // handshake has no session to close, and flushing a
            // handshaking conn would drive a SECOND bounded read (making
            // the graceful drain 2× the frame timeout for a silent peer).
            // A hostile half-open peer may keep this socket's FIN from
            // arriving — harmless: the loop has moved on, the fd dies
            // with the thread, no protocol state depends on it.
            if !tls_stream.conn.is_handshaking() {
                tls_stream.conn.send_close_notify();
                let _ = tls_stream.flush();
            }
        }));
        // WORKER OCCUPANCY: the ledger IS the truth, published on every
        // tick (and right here) — a finished worker's slot frees itself
        // and the gauge follows instead of drifting.
        if let Ok(c) = gauge_view.lock() {
            c.metrics.observe_workers(in_flight.len());
        };
    }
    // DRAIN: serve everything accepted before the signal, then return.
    // SIGTERM stays graceful even in TLS mode — never a torn handshake,
    // never a client left holding a half-closed tunnel.
    for handle in in_flight {
        let _ = handle.join();
    }
    Ok(())
}

/// Cooperative shutdown edge (Round 17): the server loops poll this
/// between accepts — std-only by design (no signal crate in the workspace:
/// an FFI `signal(2)` handler flips a process-global atomic, the loops do
/// the rest). `disabled()` never fires on its own (unit tests, library
/// users) but still responds to the process-global signal edge and to a
/// manual `trigger()`. A signal is REQUESTED, not forced: the exact
/// graceful contract a systemd `Restart=on-failure` unit needs (SIGTERM →
/// drain → exit 0).
/// A cloned edge SHARES the manual flag (`Arc` semantics): flipping one
/// clone signals every loop holding a clone — how a test triggers a server
/// thread without a real signal.
#[derive(Clone)]
pub struct Shutdown {
    /// Manual/tests edge (shared via `Arc` when a test must flip it while
    /// a server thread holds the borrow-free copy).
    flag: Arc<AtomicBool>,
    /// ROUND 21 (docs/10 §4.26): unix-ms stamp of the last accept-loop
    /// poll — the ONLY honest liveness source a systemd watchdog can read.
    /// Every `should_shutdown()` call advances it; the sd_notify watchdog
    /// thread pings only while it moves. A loop wedged on the cosigner
    /// mutex stops the stamp, the pings go silent, systemd restarts us.
    /// Shared with clones (Arc), exactly like the flag.
    progress_ms: Arc<AtomicU64>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::disabled()
    }
}

impl Shutdown {
    /// An edge that never fires by itself (it still honors a real signal
    /// and an explicit [`Shutdown::trigger`]).
    pub fn disabled() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            progress_ms: Arc::new(AtomicU64::new(crate::notify::now_ms())),
        }
    }

    /// Installs the SIGTERM (+ SIGINT) handlers behind the PROCESS-GLOBAL
    /// signal flag (the very edge every serve loop polls). Handlers re-arm
    /// themselves (BSD `signal` semantics on Linux), stay async-signal-safe
    /// (one atomic store, no allocation, no locks, no libc calls beyond the
    /// re-arm) and `signal(2)`'s default Linux behavior keeps interrupted
    /// syscalls restarting instead of spewing EINTR through the loops.
    /// Returns the SAME edge back (fluent boot path); a failure is an `Io`
    /// error surfaced at bridge boot.
    pub fn install_signal_handlers(self) -> Result<Self, ServiceError> {
        #[cfg(unix)]
        {
            install_signal_shutdown().map_err(ServiceError::Io)?;
        }
        Ok(self)
    }

    /// Manual trigger (tests, supervisor tooling): flips THIS edge the
    /// same way a signal would flip the global one.
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    fn should_shutdown(&self) -> bool {
        // Round 21: EVERY accept-loop poll is a liveness heartbeat — stamp
        // it BEFORE the flag check so even the final (shutdown) iteration
        // counts as progress. The watchdog reads this stamp, never the
        // flag: a requested-but-draining loop is healthy and must keep
        // pinging (systemd's TimeoutStopSec, not the watchdog, owns the
        // drain bound).
        self.progress_ms
            .store(crate::notify::now_ms(), Ordering::Relaxed);
        if self.flag.load(Ordering::SeqCst) {
            return true;
        }
        #[cfg(unix)]
        if signal_shutdown_requested() {
            return true;
        }
        false
    }

    /// Has a stop edge fired (manual trigger or process signal)? A PUBLIC
    /// READ that does NOT advance the progress stamp — the watchdog's
    /// drain rule (`requested() → keep pinging`) must never be able to
    /// fake loop liveness by calling it.
    pub fn requested(&self) -> bool {
        if self.flag.load(Ordering::SeqCst) {
            return true;
        }
        #[cfg(unix)]
        if signal_shutdown_requested() {
            return true;
        }
        false
    }

    /// The shared progress stamp (unix-ms) the accept loops advance — the
    /// watchdog thread's liveness source ([`crate::notify::spawn_watchdog`]).
    pub fn progress_stamp(&self) -> crate::notify::ArcProgress {
        Arc::clone(&self.progress_ms)
    }
}

#[cfg(unix)]
static SIGNAL_SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
fn signal_shutdown_requested() -> bool {
    SIGNAL_SHUTDOWN.load(Ordering::SeqCst)
}

#[cfg(unix)]
fn install_signal_shutdown() -> Result<(), String> {
    use std::os::raw::c_int;
    // The handler: async-signal-safe ONLY (store + re-arm). No allocation,
    // no locks, no I/O — a signal handler that allocates is a deadlock.
    unsafe extern "C" fn on_term(sig: c_int) {
        SIGNAL_SHUTDOWN.store(true, Ordering::SeqCst);
        // Re-arm (BSD semantics are the Linux default, but re-arm anyway:
        // a `signal(2)` on SysV semantics would reset to SIG_DFL).
        unsafe {
            libc::signal(sig, on_term as *const () as usize);
        }
    }
    let ret = unsafe { libc::signal(libc::SIGTERM, on_term as *const () as usize) };
    // signal(2) answers SIG_ERR only for an invalid signum/handler —
    // both are compile-time constants here, so this is an invariant.
    assert_ne!(ret, libc::SIG_ERR, "cannot install SIGTERM handler");
    let ret = unsafe { libc::signal(libc::SIGINT, on_term as *const () as usize) };
    assert_ne!(ret, libc::SIG_ERR, "cannot install SIGINT handler");
    Ok(())
}

#[cfg(unix)]
static SIGNAL_RELOAD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// SIGHUP (docs/10 §4.30, Round 22): `systemctl reload` (ExecReload →
/// SIGHUP) asks the RUNNING bridge to re-read its scrape secret — the
/// rotation source is `--metrics-token-file`, and the swap happens on a
/// polling thread, never in the handler. The handler itself is the same
/// async-signal-safe story as shutdown: one atomic store + re-arm, no
/// allocation, no locks, no I/O (reading a file inside a signal handler
/// is a deadlock waiting to happen). Installing it also makes a stray
/// HUP harmless instead of the default disposition — which KILLS the
/// process.
#[cfg(unix)]
pub fn install_reload_handler() -> Result<(), String> {
    use std::os::raw::c_int;
    unsafe extern "C" fn on_hup(sig: c_int) {
        SIGNAL_RELOAD.store(true, Ordering::SeqCst);
        unsafe {
            libc::signal(sig, on_hup as *const () as usize);
        }
    }
    let ret = unsafe { libc::signal(libc::SIGHUP, on_hup as *const () as usize) };
    // Same invariant as the shutdown installers: constants can't fail.
    assert_ne!(ret, libc::SIG_ERR, "cannot install SIGHUP handler");
    Ok(())
}

/// True exactly once per SIGHUP: the polling thread consumes the edge
/// with a swap, so one signal = one rotation attempt (no burst, no
/// double read).
#[cfg(unix)]
pub fn reload_requested() -> bool {
    SIGNAL_RELOAD.swap(false, Ordering::SeqCst)
}

/// Client half: sends one request and returns the response.
pub fn request_signature(addr: &str, req: &SignRequest) -> Result<SignResponse, ServiceError> {
    let mut stream = TcpStream::connect(addr).map_err(|e| ServiceError::Io(e.to_string()))?;
    // SignRequest is a flat struct — serialization is infallible.
    let body = serde_json::to_vec(req).expect("SignRequest serializes infallibly");
    write_frame(&mut stream, &body)?;
    let frame = read_frame(&mut stream)?;
    serde_json::from_slice(&frame).map_err(|e| ServiceError::Io(e.to_string()))
}

/// TLS accept loop with MUTUAL auth: the worker wraps the stream in the
/// SAME rustls server session — but the config was built by
/// [`crate::tls::tls_listener_config_with_client_auth`], so the HANDSHAKE
/// itself demands a client certificate chaining to the operator's CA. An
/// anonymous client never completes a session, hence never reaches the
/// gate, the mirror or the metrics (fail-closed at the transport layer).
pub fn serve_with_mtls_mirror(
    listener: TcpListener,
    shared: Arc<Mutex<Cosigner>>,
    mirror: impl Fn() + Send + Sync + 'static,
    tls: std::sync::Arc<rustls::ServerConfig>,
) -> Result<(), ServiceError> {
    serve_with_tls_mirror(listener, shared, mirror, tls)
}

/// Client half over MUTUAL TLS: presents `identity` (client-cert auth) in
/// addition to verifying the server under `roots`. Every TLS write MUST
/// flush (a buffered ClientHello/request is the classic both-sides-deadlock).
pub fn request_signature_mtls(
    addr: &str,
    req: &SignRequest,
    server_name: &str,
    roots: rustls::RootCertStore,
    identity: &crate::tls::ClientIdentity,
) -> Result<SignResponse, ServiceError> {
    let stream = TcpStream::connect(addr).map_err(|e| ServiceError::Io(e.to_string()))?;
    let config = identity
        .client_config(roots)
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| ServiceError::Rejected("bad TLS server name".into()))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    let mut tls_stream = rustls::StreamOwned::new(conn, stream);
    // SignRequest is a flat struct — serialization is infallible.
    let body = serde_json::to_vec(req).expect("SignRequest serializes infallibly");
    write_frame(&mut tls_stream, &body)?;
    // TLS-buffered writes leave ONLY on flush (see request_signature_tls).
    tls_stream
        .flush()
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    let frame = read_frame(&mut tls_stream)?;
    serde_json::from_slice(&frame).map_err(|e| ServiceError::Io(e.to_string()))
}

/// Client half over TLS: the server certificate must chain to `roots`
/// (regtest drills: the self-signed cert itself) and MUST match
/// `server_name` ("localhost" on loopback). A plaintext server on the
/// other end simply fails the handshake — the client never leaks a PQC
/// proof into a cleartext socket.
pub fn request_signature_tls(
    addr: &str,
    req: &SignRequest,
    server_name: &str,
    roots: rustls::RootCertStore,
) -> Result<SignResponse, ServiceError> {
    let stream = TcpStream::connect(addr).map_err(|e| ServiceError::Io(e.to_string()))?;
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| ServiceError::Rejected("bad TLS server name".into()))?;
    let conn = rustls::ClientConnection::new(std::sync::Arc::new(config), name)
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    let mut tls_stream = rustls::StreamOwned::new(conn, stream);
    // SignRequest is a flat struct — serialization is infallible.
    let body = serde_json::to_vec(req).expect("SignRequest serializes infallibly");
    write_frame(&mut tls_stream, &body)?;
    // TLS-buffered writes leave ONLY on flush — without it the server
    // never sees the request and BOTH sides deadlock.
    tls_stream
        .flush()
        .map_err(|e| ServiceError::Io(e.to_string()))?;
    let frame = read_frame(&mut tls_stream)?;
    serde_json::from_slice(&frame).map_err(|e| ServiceError::Io(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qsv_pqc::PqcIdentity;
    use secp256k1::Secp256k1;

    fn cosigner() -> Cosigner {
        Cosigner::provision([42u8; 32], vec!["bc1ptestvault".into()])
    }

    /// The attestation closure for the outcome-mapper tests, as a
    /// FUNCTION ITEM: an Err gate never attests, so a closure literal in
    /// the Err arms would carry a body that can never run. Passing the
    /// same function on every arm keeps the contract (the attestation
    /// only happens on Ok) while the body still scores exactly once.
    fn attest_ok(sig: [u8; 64]) -> Result<SignResponse, ServiceError> {
        Ok(SignResponse {
            version: PROTOCOL_VERSION,
            accepted: true,
            reason: None,
            schnorr_sig_hex: Some(hex::encode(sig)),
            attestation_doc_hex: None,
        })
    }

    /// A mirror hook as a FUNCTION ITEM (rationale as [`attest_ok`]): a
    /// scenario where the hook legitimately never fires — a TLS config
    /// that cannot make a session — then carries no dead closure body,
    /// while every completed ceremony still invokes the real function.
    static MIRROR_CALLS: AtomicU64 = AtomicU64::new(0);
    fn counting_mirror() {
        MIRROR_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    /// The two convenience wrappers must SURFACE a bind failure as an
    /// `ServiceError::Io` — a busy or unbindable address is an error the
    /// operator sees, never a panic that takes the supervisor down.
    #[test]
    fn serve_wrappers_surface_bind_failures_as_io_errors() {
        let e = serve(cosigner(), "999.999.999.999:0").expect_err("invalid bind must fail");
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");

        let shared = Arc::new(Mutex::new(cosigner()));
        let e = serve_shared("999.999.999.999:0", shared).expect_err("invalid bind must fail");
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
    }

    /// The `serve_listener` wrapper (the simplest entrypoint: no shutdown,
    /// no mirror) carries a REAL request end to end, and the client half's
    /// refused connect is an `Io` error — the service never answers, and
    /// the caller learns why.
    #[test]
    fn serve_listener_carries_a_request_and_a_refused_connect_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let shared = Arc::new(Mutex::new(cosigner()));
        let s = Arc::clone(&shared);
        // The wrapper has no shutdown edge; the thread outlives this test
        // and is reaped with the process (documented: one request/connection).
        std::thread::spawn(move || {
            let _ = serve_listener(listener, s);
        });

        let pqc = PqcIdentity::from_seed(&[12u8; 32]);
        let sighash = [0xC5u8; 32];
        let sig = pqc.sign(&sighash);
        let req = SignRequest::new("bc1ptestvault", &sighash, pqc.verifying_key_bytes(), &sig);
        let resp = request_signature(&format!("127.0.0.1:{port}"), &req)
            .expect("the listener must answer");
        assert!(resp.accepted, "gate must open for a valid PQC proof");
        assert!(resp.schnorr_sig_hex.is_some());

        // Port 1 has no listener → refused connect, surfaced (not hung).
        let e = request_signature("127.0.0.1:1", &req).expect_err("refused");
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
    }

    #[test]
    fn handler_releases_real_signature_for_valid_pqc() {
        let c = cosigner();
        let pqc = PqcIdentity::from_seed(&[11u8; 32]);
        let sighash = [0xABu8; 32];
        let sig = pqc.sign(&sighash);
        let req = SignRequest::new("bc1ptestvault", &sighash, pqc.verifying_key_bytes(), &sig);

        let resp = c.handle_request(&req).unwrap();
        assert!(resp.accepted);
        let sig_hex = resp.schnorr_sig_hex.clone().unwrap();
        let sig_bytes: [u8; 64] = hex::decode(&sig_hex).unwrap().try_into().unwrap();

        // Released signature verifies under the co-signer's public key.
        let vk = c.public_key().unwrap();
        let verify = Secp256k1::verification_only();
        assert!(verify
            .verify_schnorr(
                &secp256k1::schnorr::Signature::from_slice(&sig_bytes).unwrap(),
                &secp256k1::Message::from_digest(sighash),
                &vk,
            )
            .is_ok());
    }

    #[test]
    fn handler_refuses_invalid_pqc_and_unknown_vault() {
        let c = cosigner();
        let pqc = PqcIdentity::from_seed(&[11u8; 32]);
        let sighash = [0xABu8; 32];
        let mut bad_sig = pqc.sign(&sighash);
        bad_sig[5] ^= 0x20;
        let req = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &bad_sig,
        );
        let resp = c.handle_request(&req).unwrap();
        assert!(!resp.accepted);
        assert!(resp.reason.unwrap().contains("ML-DSA-65"));

        let foreign = SignRequest::new(
            "bc1punknown",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let resp = c.handle_request(&foreign).unwrap();
        assert!(!resp.accepted);
    }

    #[test]
    fn handler_is_deterministic() {
        let c = cosigner();
        let pqc = PqcIdentity::from_seed(&[12u8; 32]);
        let sighash = [0xCDu8; 32];
        let req = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let a = c.handle_request(&req).unwrap();
        let b = c.handle_request(&req).unwrap();
        assert_eq!(a.schnorr_sig_hex, b.schnorr_sig_hex);
    }

    #[test]
    fn metrics_split_totals_exactly_and_separate_alarms() {
        let mut c = cosigner();
        let pqc = PqcIdentity::from_seed(&[13u8; 32]);
        let sighash = [0xEEu8; 32];
        let ok = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        // 2 accepted.
        c.handle_request(&ok).unwrap();
        c.handle_request(&ok).unwrap();
        // 1 unprovisioned refusal.
        let foreign = SignRequest::new(
            "bc1punknown",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        c.handle_request(&foreign).unwrap();
        // 1 alarm refusal.
        c.set_alarm("bc1ptestvault");
        c.handle_request(&ok).unwrap();
        // 1 bad-proof refusal (post-alarm-clear so the branch differs).
        c.clear_alarm("bc1ptestvault");
        let mut bad_sig = pqc.sign(&sighash);
        bad_sig[0] ^= 0x01;
        let bad = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &bad_sig,
        );
        c.handle_request(&bad).unwrap();

        assert_eq!(
            c.metrics.requests_total.load(Ordering::Relaxed),
            5,
            "total counts every gate visit"
        );
        assert_eq!(c.metrics.accepted_total.load(Ordering::Relaxed), 2);
        assert_eq!(c.metrics.refused_total.load(Ordering::Relaxed), 3);
        assert_eq!(c.metrics.alarm_refused_total.load(Ordering::Relaxed), 1);
        let text = c.metrics.render();
        assert!(text.contains("# TYPE qsv_cosigner_requests_total counter"));
        assert!(text.contains("qsv_cosigner_requests_total 5"));
        assert!(text.contains("qsv_cosigner_accepted_total 2"));
        assert!(text.contains("qsv_cosigner_refused_total 3"));
        assert!(text.contains("qsv_cosigner_alarm_refused_total 1"));
    }

    #[test]
    fn metrics_attribute_outcomes_to_the_requesting_vault() {
        let mut c = cosigner();
        let pqc = PqcIdentity::from_seed(&[23u8; 32]);
        let sighash = [0x77u8; 32];
        let ok = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let foreign = SignRequest::new(
            "bc1pstranger",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        c.handle_request(&ok).unwrap();
        c.handle_request(&ok).unwrap();
        // Unprovisioned refusal — attributed to the ASKING vault.
        c.handle_request(&foreign).unwrap();
        // Alarm freeze — attributed to the frozen vault.
        c.set_alarm("bc1ptestvault");
        c.handle_request(&ok).unwrap();
        c.clear_alarm("bc1ptestvault");

        let text = c.metrics.render();
        assert!(
            text.contains("qsv_cosigner_refused_by_vault_total{vault=\"bc1pstranger\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("qsv_cosigner_refused_by_vault_total{vault=\"bc1ptestvault\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("qsv_cosigner_alarm_refused_by_vault_total{vault=\"bc1ptestvault\"} 1"),
            "{text}"
        );
        // The unlabeled totals are UNCHANGED by the label rows: the scrape
        // sums must keep matching accepted + refused == requests_total.
        assert!(text.contains("qsv_cosigner_requests_total 4"), "{text}");
        assert!(text.contains("qsv_cosigner_accepted_total 2"), "{text}");
        assert!(text.contains("qsv_cosigner_refused_total 2"), "{text}");
        assert!(
            text.contains("qsv_cosigner_alarm_refused_total 1"),
            "{text}"
        );
    }

    #[test]
    fn latency_histogram_buckets_are_cumulative_and_inf_matches_count() {
        let c = cosigner();
        // Three simulated serves of 500 µs (the SERVE path feeds
        // observe_latency — the bare handler does not, an HTTP scrape is
        // never a serve).
        c.metrics.observe_latency(500);
        c.metrics.observe_latency(500);
        c.metrics.observe_latency(500);

        // The histogram rows land in the SAME exposition with cumulative
        // bucket counts.
        let text = c.metrics.render();
        assert!(
            text.contains("# TYPE qsv_cosigner_serve_latency_us histogram"),
            "{text}"
        );
        // Every sample ≤ 2 s → EVERY bucket from 1 ms up must hold all
        // three counts (cumulative form), +Inf == 3 == count.
        for le in ["1000", "10000", "100000", "500000", "1000000", "2000000"] {
            assert!(
                text.contains(&format!(
                    "qsv_cosigner_serve_latency_us_bucket{{le=\"{le}\"}} 3"
                )),
                "bucket {le} must be cumulative (3): {text}"
            );
        }
        assert!(
            text.contains("qsv_cosigner_serve_latency_us_bucket{le=\"+Inf\"} 3"),
            "{text}"
        );
        assert!(
            text.contains("qsv_cosigner_serve_latency_us_count 3"),
            "{text}"
        );
        // The SAME total appears as a VALUE row exactly TWICE — the legacy
        // counter and the histogram's own _sum (backwards compatibility +
        // histogram form, identical numbers by construction).
        assert_eq!(
            text.matches("qsv_cosigner_serve_latency_us_sum 1500\n")
                .count(),
            2,
            "{text}"
        );

        // observe_latency routes a sample into exactly the right buckets:
        // 1_500 µs lands in ≤2 ms .. ≤2 s (NOT in ≤1 ms), +Inf counts it.
        let m = &c.metrics;
        m.observe_latency(1_500);
        let buckets = m.serve_latency_buckets.lock().unwrap();
        assert_eq!(
            buckets.get(&1_000),
            Some(&3),
            "1.5 ms misses the 1 ms bucket"
        );
        assert_eq!(buckets.get(&10_000), Some(&4));
        assert_eq!(buckets.get(&100_000), Some(&4));
        assert_eq!(buckets.get(&2_000_000), Some(&4));
        assert_eq!(buckets.get(&u64::MAX), Some(&4));
    }

    #[test]
    fn rate_limit_refuses_the_flood_and_serves_the_sibling_vault() {
        let mut c = cosigner();
        // A tiny burst proves the limiter: 3 tokens, no refill within the
        // test window (refill checked lazily per request; the elapsed time
        // between in-process calls adds < 1 token at 0.5/s only after 2 s,
        // and the whole test runs in milliseconds).
        c.set_rate_limit(Some(RateLimitPolicy {
            capacity: 3.0,
            refill_per_sec: 0.0,
        }))
        .unwrap();
        let pqc = PqcIdentity::from_seed(&[41u8; 32]);
        let sighash = [0x33u8; 32];
        let flood = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let sibling = SignRequest::new(
            "bc1psibling",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );

        // The burst consumes exactly the 3 tokens.
        for i in 0..3 {
            let resp = c.handle_request(&flood).unwrap();
            assert!(resp.accepted, "request {i} must pass inside the burst");
        }
        // The 4th is rate-limited with the EXPLICIT reason.
        let resp = c.handle_request(&flood).unwrap();
        assert!(!resp.accepted);
        assert!(resp
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("rate limited"));
        // The PROVISIONED sibling keeps its own budget (per-vault buckets).
        c2_allow(&mut c, "bc1psibling");
        let resp = c.handle_request(&sibling).unwrap();
        assert!(resp.accepted, "a sibling vault must keep its own budget");

        // Metrics: the total AND the per-vault row.
        assert_eq!(c.metrics.rate_limited_total.load(Ordering::Relaxed), 1);
        let text = c.metrics.render();
        assert!(text.contains("qsv_cosigner_rate_limited_total 1"), "{text}");
        assert!(
            text.contains("qsv_cosigner_rate_limited_by_vault_total{vault=\"bc1ptestvault\"} 1"),
            "{text}"
        );

        // An invalid policy is REFUSED (fail-closed: the previous policy
        // stays armed) and disabling the limiter restores unlimited flow.
        assert!(c
            .set_rate_limit(Some(RateLimitPolicy {
                capacity: 0.0,
                refill_per_sec: 1.0
            }))
            .is_err());
        assert_eq!(
            c.metrics.rate_limited_total.load(Ordering::Relaxed),
            1,
            "the failed swap must not have re-armed a new limiter"
        );
        c.set_rate_limit(None).unwrap();
        let resp = c.handle_request(&flood).unwrap();
        assert!(resp.accepted, "no limiter → unlimited flow");
    }

    /// The cosigner fixture allows only "bc1ptestvault"; add a sibling to
    /// the allowlist for the per-vault budget proof.
    fn c2_allow(c: &mut Cosigner, id: &str) {
        c.allowed_vaults.push(id.to_string());
    }

    #[test]
    fn watchtower_alarm_freezes_signing_until_cleared() {
        let pqc = PqcIdentity::from_seed(&[13u8; 32]);
        let sighash = [0x5Eu8; 32];
        let req = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );

        let mut c = cosigner();
        assert_eq!(c.alarm_state("bc1ptestvault"), AlarmState::Clear);
        assert!(c.alarmed_vaults().is_empty());

        // Watchtower raises the alarm: even a perfectly valid PQC proof is
        // refused. Fail-closed — the freeze dominates the crypto gate.
        c.set_alarm("bc1ptestvault");
        assert_eq!(c.alarm_state("bc1ptestvault"), AlarmState::Alarm);
        assert_eq!(c.alarmed_vaults(), vec!["bc1ptestvault".to_string()]);
        let resp = c.handle_request(&req).unwrap();
        assert!(!resp.accepted);
        assert!(resp.reason.unwrap().contains("watchtower alarm active"));
        assert!(resp.schnorr_sig_hex.is_none());

        // The freeze is per-vault: an unalarmed sibling vault keeps signing.
        let mut c2 = cosigner();
        c2.set_alarm("bc1pother");
        let resp = c2.handle_request(&req).unwrap();
        assert!(resp.accepted);

        // Operator clears after a verified refresh: determinism preserved,
        // the exact same request releases the exact same signature again.
        c.clear_alarm("bc1ptestvault");
        assert_eq!(c.alarm_state("bc1ptestvault"), AlarmState::Clear);
        let resp = c.handle_request(&req).unwrap();
        assert!(resp.accepted);
        let deterministic = cosigner().handle_request(&req).unwrap();
        assert_eq!(resp.schnorr_sig_hex, deterministic.schnorr_sig_hex);
    }

    #[test]
    fn provisioning_roundtrip_and_tcp_e2e() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provisioning.json");
        let c = cosigner();
        c.save_provisioning(&path).unwrap();
        let loaded = Cosigner::load_provisioning(&path).unwrap();
        assert_eq!(loaded.public_key().unwrap(), c.public_key().unwrap());

        // Real TCP round trip on loopback.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let frame = read_frame(&mut stream).unwrap();
            let req: SignRequest = serde_json::from_slice(&frame).unwrap();
            let resp = loaded.handle_request(&req).unwrap();
            write_frame(&mut stream, &serde_json::to_vec(&resp).unwrap()).unwrap();
        });
        let pqc = PqcIdentity::from_seed(&[11u8; 32]);
        let sighash = [0xA9u8; 32];
        let req = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let resp = request_signature(&addr, &req).unwrap();
        assert!(resp.accepted);
        assert!(resp.schnorr_sig_hex.is_some());
        assert!(resp.attestation_doc_hex.is_some());
        server.join().unwrap();
    }

    #[test]
    fn accepted_outcomes_are_rendered_per_vault_round17() {
        let mut c = cosigner();
        let pqc = PqcIdentity::from_seed(&[17u8; 32]);
        let sighash = [0x61u8; 32];
        let ok = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let foreign = SignRequest::new(
            "bc1pstranger",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        c.handle_request(&ok).unwrap();
        c.handle_request(&ok).unwrap();
        // A refusal for the SAME vault must NOT move its accepted row.
        c.set_alarm("bc1ptestvault");
        c.handle_request(&ok).unwrap();
        c.clear_alarm("bc1ptestvault");
        // The unprovisioned vault appears with an EXPLICIT ZERO accepted
        // row (one HELP/TYPE block, one row per seen vault).
        c.handle_request(&foreign).unwrap();

        let text = c.metrics.render();
        assert!(
            text.contains(
                "# HELP qsv_cosigner_accepted_by_vault_total Co-signatures released, per vault",
            ),
            "{text}"
        );
        assert!(
            text.contains("# TYPE qsv_cosigner_accepted_by_vault_total counter"),
            "{text}"
        );
        assert!(
            text.contains("qsv_cosigner_accepted_by_vault_total{vault=\"bc1ptestvault\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("qsv_cosigner_accepted_by_vault_total{vault=\"bc1pstranger\"} 0"),
            "every seen vault gets a row (explicit zero): {text}"
        );
        // Sum invariant stays visible on one scrape: Σ per-vault accepted
        // rows == the unlabeled total (2).
        assert!(text.contains("qsv_cosigner_accepted_total 2"), "{text}");
    }

    #[test]
    fn serial_serve_loop_stops_cooperatively_on_shutdown() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let shared = Arc::new(Mutex::new(cosigner()));
        let shutdown = Shutdown::disabled();
        let server = std::thread::spawn({
            let shared = Arc::clone(&shared);
            let listener = listener;
            let shutdown = shutdown.clone();
            move || {
                serve_with_mirror_and_shutdown(
                    listener,
                    shared,
                    || {},
                    shutdown,
                    ServePolicy::default(),
                )
            }
        });
        // The loop serves while up…
        let resp = request_signature(&addr, &valid_sign_request()).unwrap();
        assert!(resp.accepted);
        // …and SIGTERM-equivalent stops it CLEANLY: Ok(()) (exit 0 — a
        // graceful stop, NOT an error the service would report).
        shutdown.trigger();
        let outcome = server.join().unwrap();
        assert!(outcome.is_ok(), "graceful stop is the Ok path");
        // The listener is GONE: the port is released for the next replica.
        assert!(std::net::TcpListener::bind(addr).is_ok(), "bind rebindable");
    }

    /// ROUND 25 — HONEST SERIAL CEILING: the one-thread loop publishes
    /// a ceiling of 1 (not the 0 that reads "unlimited", not the TLS
    /// loop's --max-inflight it never enforces), counts the connection
    /// it is serving (its own scrape included, exactly like the TLS
    /// loop counts its scrape worker) and the high-water mark follows.
    #[test]
    fn serial_loop_publishes_a_ceiling_of_one_and_counts_itself() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let shared = Arc::new(Mutex::new(cosigner()));
        let shutdown = Shutdown::disabled();
        let server = std::thread::spawn({
            let shared = Arc::clone(&shared);
            let listener = listener;
            let shutdown = shutdown.clone();
            move || {
                serve_with_mirror_and_shutdown(
                    listener,
                    shared,
                    || {},
                    shutdown,
                    ServePolicy::default(),
                )
            }
        });
        // One real request gives the peak a history…
        let resp = request_signature(&addr, &valid_sign_request()).unwrap();
        assert!(resp.accepted);
        // …then a scrape reads the loop's self-assessment.
        let mut s = std::net::TcpStream::connect(&addr).unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        s.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut s, &mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 200"), "open dev scrape: {out}");
        assert!(
            out.contains("qsv_cosigner_worker_limit 1\n"),
            "the serial loop's ceiling is ONE — truth, not the configured TLS cap:\n{out}"
        );
        assert!(
            out.contains("qsv_cosigner_workers_active 1\n"),
            "the connection being served (this very scrape) is the active worker:\n{out}"
        );
        assert!(
            out.contains("qsv_cosigner_workers_peak 1\n"),
            "peak cannot exceed the ceiling in a serial loop:\n{out}"
        );
        shutdown.trigger();
        let outcome = server.join().unwrap();
        assert!(outcome.is_ok(), "graceful stop is the Ok path");
    }

    /// ROUND 25 — the scrape comparison resolves by VALUE only: a
    /// last-byte miss, a first-byte miss and a length mismatch must all
    /// take the same fold (no early return), and no length combination
    /// may panic or misfire.
    #[test]
    fn token_eq_folds_every_length_and_only_the_value_decides() {
        let want = b"0123456789abcdef";
        assert!(token_eq(want, want), "exact match");
        assert!(token_eq(b"", b""), "empty equals empty");
        assert!(!token_eq(b"0123456789abcdeX", want), "last byte differs");
        assert!(!token_eq(b"X123456789abcdef", want), "first byte differs");
        assert!(!token_eq(b"X", want), "first byte differs, short input");
        assert!(!token_eq(b"", want), "empty against armed");
        assert!(
            !token_eq(b"0123456789abcdef0", want),
            "one byte longer must not match"
        );
        assert!(
            !token_eq(b"0123456789abcde", want),
            "one byte shorter must not match"
        );
        // Padding must never forge a match: every zero-pad byte of the
        // shorter side against a NON-zero expected byte keeps the fold
        // non-zero (this is the padding-forgery edge of the CT fold).
        assert!(!token_eq(b"0123456789abcd\0\0", want));
    }

    /// ROUND 27 — the constant-time fold is EXACTLY byte equality for
    /// every pair of inputs: no input may forge a match through zero
    /// padding, and no input may break one (the fold's correctness half,
    /// complementing the timing half the round-25 test documents).
    #[test]
    fn token_eq_equals_byte_equality_for_every_pair() {
        proptest::proptest! {
            |(a in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
              b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64))| {
                proptest::prop_assert_eq!(token_eq(&a, &b), a == b);
            }
        }
    }

    #[test]
    fn tls_serve_loop_stops_accepting_and_drains_in_flight_workers() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        let key_path = dir.path().join("key.pem");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        let config = crate::tls::tls_listener_config(&cert_path, &key_path)
            .unwrap()
            .into_server_config();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let shared = Arc::new(Mutex::new(cosigner()));
        let shutdown = Shutdown::disabled();
        let server = std::thread::spawn({
            let shared = Arc::clone(&shared);
            let listener = listener;
            let shutdown = shutdown.clone();
            move || {
                serve_with_tls_mirror_and_shutdown(
                    listener,
                    shared,
                    counting_mirror,
                    config,
                    shutdown,
                    ServePolicy::default(),
                )
            }
        });

        // In-flight BEFORE the signal: this request must still be SERVED to
        // completion (drain, never torn).
        let roots = crate::tls::pinned_root_store(cert.cert.der());
        let resp = request_signature_tls(&addr, &valid_sign_request(), "localhost", roots.clone())
            .unwrap();
        assert!(resp.accepted, "pre-shutdown request must be served");
        assert!(
            MIRROR_CALLS.load(Ordering::Relaxed) >= 1,
            "a completed TLS ceremony runs the mirror hook before the gate"
        );

        // Signal → stop accepting → drain → Ok(()). The already-accepted
        // worker above finishes first (this join IS the drain).
        shutdown.trigger();
        let outcome = server.join().unwrap();
        assert!(outcome.is_ok(), "graceful TLS stop is the Ok path");
        assert!(std::net::TcpListener::bind(addr).is_ok(), "bind rebindable");
    }

    /// ROUND 18 — SLOWLORIS BOUND: a peer that connects and never sends a
    /// byte holds the SERIAL loop for at most ONE frame timeout; the loop
    /// then moves on, serves the healthy client and keeps its graceful
    /// edge (Ok on TERM). The stalled socket is hung up by the deadline.
    #[test]
    fn frame_timeout_bounds_a_stalling_peer_and_the_loop_survives() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let shared = Arc::new(Mutex::new(cosigner()));
        let shutdown = Shutdown::disabled();
        let policy = ServePolicy {
            frame_timeout: Some(std::time::Duration::from_millis(250)),
            metrics_token: ScrapeToken::disarmed(),
            max_inflight: 64,
        };
        let server = std::thread::spawn({
            let shared = Arc::clone(&shared);
            let shutdown = shutdown.clone();
            move || serve_with_mirror_and_shutdown(listener, shared, || {}, shutdown, policy)
        });

        // 1. A SILENT peer: connect, send nothing — the loop parks in its
        //    probe read, bounded by the 250 ms deadline.
        let mut stall = std::net::TcpStream::connect(&addr).unwrap();
        // The client's own read timeout (15 s) is deliberately LONGER than
        // the promptness bound asserted in 3, so a server that never hung
        // up would surface as elapsed≈15 s — not as a client-side
        // timeout that would silently satisfy the "hung up" check.
        stall
            .set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .unwrap();

        // 2. A healthy request STILL lands (it waits behind the stall for
        //    at most one timeout — slowloris degrades, never denies).
        //
        //    The harness budget below is 15 s, NOT the product bound: the
        //    contract under test is "the healthy request eventually lands
        //    and the stalled peer is hung up" (asserted in 3), while the
        //    250 ms frame deadline is what the SERVER owes. A 4 s wall
        //    clock measured a loaded machine (the parallel workspace
        //    matrix), not the service — this test failed at 3.9 s of
        //    scheduling noise and passed 3×3.3 s in isolation. 15 s still
        //    catches an unbounded hang (which would block forever) while
        //    surviving the load the CI matrix actually runs under.
        let (tx, rx) = std::sync::mpsc::channel();
        let addr_h = addr.clone();
        let healthy = std::thread::spawn(move || {
            let r = request_signature(&addr_h, &valid_sign_request());
            let _ = tx.send(r);
        });
        let resp = rx
            .recv_timeout(std::time::Duration::from_secs(15))
            .expect("healthy request must land within the frame-timeout bound")
            .expect("healthy request must not error");
        healthy.join().unwrap();
        assert!(resp.accepted, "the service must outlive the stalled peer");

        // 3. The stalled socket is CLOSED by the deadline (the client sees
        //    a hang-up, not a permanent half-open peer).
        let mut byte = [0u8; 1];
        let started = std::time::Instant::now();
        let n = stall.read(&mut byte);
        let hung_up = matches!(&n, Ok(0)) || n.is_err();
        assert!(hung_up, "server must hang up on the stalled peer: {n:?}");
        assert!(
            // 8 s is still 32× the 250 ms frame deadline — the bound the
            // server owes — while tolerating the scheduler noise a
            // loaded CI matrix produces (see the note in 2).
            started.elapsed() < std::time::Duration::from_secs(8),
            "the deadline must close the silent peer promptly"
        );

        // 4. The loop is unpoisoned: another request releases, and TERM
        //    still takes the graceful Ok path.
        let resp = request_signature(&addr, &valid_sign_request()).unwrap();
        assert!(resp.accepted, "loop must survive a timed-out peer");
        shutdown.trigger();
        let outcome = server.join().unwrap();
        assert!(
            outcome.is_ok(),
            "graceful stop after a stall is the Ok path"
        );
    }

    /// ROUND 18 — SCRAPE AUTH: an armed token gates `/metrics` — missing
    /// or wrong `X-QSV-Metrics-Token` = 401 AND a counted denial; the
    /// authorized scrape renders the exposition plus the denial counter.
    #[test]
    fn metrics_scrape_requires_the_token_and_counts_denials() {
        fn scrape(addr: &str, extra: &[&str]) -> String {
            let mut s = std::net::TcpStream::connect(addr).unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut req = "GET /metrics HTTP/1.1\r\nHost: x\r\n".to_string();
            for h in extra {
                req.push_str(h);
                req.push_str("\r\n");
            }
            req.push_str("\r\n");
            s.write_all(req.as_bytes()).unwrap();
            let mut out = String::new();
            std::io::Read::read_to_string(&mut s, &mut out).unwrap();
            out
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let shared = Arc::new(Mutex::new(cosigner()));
        let shutdown = Shutdown::disabled();
        let policy = ServePolicy {
            frame_timeout: Some(std::time::Duration::from_secs(5)),
            metrics_token: ScrapeToken::armed("s3cr3t-scrape"),
            max_inflight: 64,
        };
        let server = std::thread::spawn({
            let shared = Arc::clone(&shared);
            let shutdown = shutdown.clone();
            move || serve_with_mirror_and_shutdown(listener, shared, || {}, shutdown, policy)
        });

        let denied = scrape(&addr, &[]);
        assert!(
            denied.starts_with("HTTP/1.1 401"),
            "missing token must be denied: {denied}"
        );
        let denied = scrape(&addr, &["X-QSV-Metrics-Token: wrong"]);
        assert!(
            denied.starts_with("HTTP/1.1 401"),
            "wrong token must be denied: {denied}"
        );
        let ok = scrape(&addr, &["X-QSV-Metrics-Token: s3cr3t-scrape"]);
        assert!(ok.starts_with("HTTP/1.1 200"), "authorized scrape: {ok}");
        assert!(ok.contains("# TYPE qsv_cosigner_requests_total counter"));
        assert!(
            ok.contains("qsv_cosigner_metrics_denied_total 2"),
            "denials are counted: {ok}"
        );

        // The gate is an OBSERVABILITY control: it never gates the gate —
        // a frame request still releases with the token armed.
        let resp = request_signature(&addr, &valid_sign_request()).unwrap();
        assert!(resp.accepted, "signing must be untouched by scrape auth");

        shutdown.trigger();
        let outcome = server.join().unwrap();
        assert!(outcome.is_ok(), "graceful stop is the Ok path");
    }

    /// ROTATABLE GATE unit contract (docs/10 §4.30, Round 22): rotation
    /// swaps the SECRET in place (the clone main.rs holds shares the
    /// same state), refuses an empty one (that would open the scrape),
    /// refuses to arm a gate that booted disarmed (armedness is a boot
    /// decision), and a disarmed gate stays the loopback dev default.
    #[test]
    fn scrape_token_rotation_swaps_in_place_and_never_reopens() {
        let open = ScrapeToken::disarmed();
        assert!(!open.is_armed());
        assert!(open.current().is_none());
        assert!(
            open.rotate("forced".into()).is_err(),
            "rotation must never arm a gate that booted open"
        );
        assert!(!open.is_armed(), "the disarmed gate stays disarmed");

        let gate = ScrapeToken::armed("v1");
        let worker = gate.clone(); // the SIGHUP thread's handle
        let previous = worker.rotate("v2".into()).unwrap();
        assert_eq!(
            previous.as_deref(),
            Some("v1"),
            "the swap reports the old secret"
        );
        assert_eq!(gate.current().as_deref(), Some("v2"), "the swap is shared");
        assert!(gate.is_armed(), "rotation replaces, it never reopens");
        assert!(
            gate.rotate(String::new()).is_err(),
            "an empty rotation would open the scrape"
        );
        assert_eq!(
            gate.current().as_deref(),
            Some("v2"),
            "a refused rotation leaves the previous secret intact"
        );
    }

    /// REFUSAL ACCOUNTING (Round 23, docs/10 §4.36): every rotation the
    /// gate turns away is counted, the count is SHARED with the metrics
    /// exposition (the wiring `main.rs` performs at boot), and a
    /// SUCCESSFUL rotation never moves it — `QsvCosignerTokenRotationStalled`
    /// therefore fires on reloads that did nothing, never on reloads that
    /// worked.
    #[test]
    fn rotation_refusals_are_counted_into_the_exposition() {
        let gate = ScrapeToken::armed("v1");
        let mut m = Metrics::default();
        // THE BOOT WIRING: the gate's counters ARE the exported ones.
        m.adopt_rotation_counters(&gate);

        assert!(
            gate.rotate(String::new()).is_err(),
            "an empty rotation would open the scrape"
        );
        assert_eq!(gate.denials(), 1, "the refused empty rotation is counted");

        let open = ScrapeToken::disarmed();
        assert!(open.rotate("forced".into()).is_err());
        assert_eq!(
            open.denials(),
            1,
            "arming a gate that booted open is a refusal too"
        );
        assert_eq!(
            gate.denials(),
            1,
            "each gate counts its own refusals — no cross-talk"
        );

        assert_eq!(
            gate.rotate("v2".into()).unwrap().as_deref(),
            Some("v1"),
            "the swap reports the old secret"
        );
        assert_eq!(gate.denials(), 1, "a rotation that WORKED is not a denial");
        assert_eq!(gate.rotations(), 1, "but it IS a rotation");

        let text = m.render();
        assert!(
            text.contains("# TYPE qsv_cosigner_rotate_denied_total counter"),
            "the refusal counter is a declared family:\n{text}"
        );
        assert!(
            text.contains("qsv_cosigner_rotate_denied_total 1\n"),
            "the gate's refusals reach the exposition:\n{text}"
        );

        // A reload that could not even ROTATE (armed gate, no file to
        // re-read) counts through the same shared handle.
        gate.record_denial();
        assert_eq!(
            m.rotate_denied_total.load(Ordering::Relaxed),
            2,
            "a no-op reload lands in the very counter the alert reads"
        ); // …while a disarmed gate shrugs off a stray HUP: nothing to
           // rotate, nobody to page.
        open.record_denial();
        assert_eq!(
            open.denials(),
            1,
            "a disarmed gate has no rotation to stall"
        );

        // The POSITIVE side travels through the same pair of counters:
        // "did my reload land?" must be answerable from a scrape.
        let text = m.render();
        assert!(
            text.contains("# TYPE qsv_cosigner_rotate_total counter"),
            "landed rotations are a declared family:\n{text}"
        );
        assert!(
            text.contains("qsv_cosigner_rotate_total 1\n"),
            "the landed rotation reaches the exposition:\n{text}"
        );

        // WORKER OCCUPANCY (Round 24): active follows the ledger, peak
        // never falls back, and the ceiling is the configured one.
        m.set_worker_limit(64);
        m.observe_workers(3);
        m.observe_workers(9); // the flood
        m.observe_workers(1); // …then the estate goes quiet again
        let text = m.render();
        assert!(
            text.contains("qsv_cosigner_workers_active 1\n"),
            "active follows the live ledger:\n{text}"
        );
        assert!(
            text.contains("qsv_cosigner_workers_peak 9\n"),
            "peak is a high-water mark:\n{text}"
        );
        assert!(
            text.contains("qsv_cosigner_worker_limit 64\n"),
            "the exported ceiling is the CONFIGURED one:\n{text}"
        );
        for family in [
            "qsv_cosigner_workers_active",
            "qsv_cosigner_workers_peak",
            "qsv_cosigner_worker_limit",
        ] {
            assert!(
                text.contains(&format!("# TYPE {family} gauge\n")),
                "{family} is a gauge in the exposition:\n{text}"
            );
        }
    }

    fn valid_sign_request() -> SignRequest {
        let pqc = PqcIdentity::from_seed(&[19u8; 32]);
        let sighash = [0x5Au8; 32];
        SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        )
    }

    /// METRIC FAMILY CONTRACT (Round 20): a Metrics that has actually seen
    /// EVERY kind of traffic must export a `# TYPE` line for each family in
    /// [`Metrics::METRIC_FAMILIES`]. The list is what the Prometheus alert
    /// rules and the Grafana dashboard are validated against — a family
    /// added here without a render path (or renamed without the list) is
    /// exactly the silent-monitoring-failure this test exists to prevent.
    #[test]
    fn every_declared_metric_family_is_actually_exported() {
        use std::sync::atomic::AtomicU64;
        let m = Metrics::default();
        m.requests_total.fetch_add(4, Ordering::Relaxed);
        m.accepted_total.fetch_add(2, Ordering::Relaxed);
        m.refused_total.fetch_add(2, Ordering::Relaxed);
        m.alarm_refused_total.fetch_add(1, Ordering::Relaxed);
        m.rate_limited_total.fetch_add(1, Ordering::Relaxed);
        m.metrics_denied_total.fetch_add(1, Ordering::Relaxed);
        m.capacity_refused_total.fetch_add(1, Ordering::Relaxed);
        m.rotate_denied_total.fetch_add(1, Ordering::Relaxed);
        m.observe_latency(1_500);
        let mut per_vault = m.per_vault.lock().unwrap();
        let vc = VaultCounters::default();
        vc.accepted_total.fetch_add(2, Ordering::Relaxed);
        vc.refused_total.fetch_add(2, Ordering::Relaxed);
        per_vault.insert("bc1ptestvault".to_string(), vc);
        drop(per_vault);
        m.alarm_rows
            .lock()
            .unwrap()
            .insert("bc1ptestvault".to_string(), AtomicU64::new(1));
        m.rate_limited_rows
            .lock()
            .unwrap()
            .insert("bc1ptestvault".to_string(), AtomicU64::new(1));

        let text = m.render();
        for family in Metrics::METRIC_FAMILIES {
            assert!(
                text.contains(&format!("# TYPE {family} ")),
                "declared family {family} is not exported:\n{text}"
            );
        }
        // The histogram rows are DERIVED from the latency family — they
        // are not separate families, and the alert rules must use them
        // with the `_bucket` suffix Prometheus requires.
        assert!(text.contains("qsv_cosigner_serve_latency_us_bucket{le=\"+Inf\"} 1"));
        assert!(text.contains("qsv_cosigner_serve_latency_us_count 1"));
        // …and nothing extra slipped into the exposition undeclared.
        for line in text.lines().filter(|l| l.starts_with("# TYPE ")) {
            let name = line
                .trim_start_matches("# TYPE ")
                .split(' ')
                .next()
                .unwrap();
            assert!(
                Metrics::METRIC_FAMILIES.contains(&name),
                "undeclared family {name} in the exposition:\n{text}"
            );
        }
    }

    // ── Round 30: paths reachable only through direct unit calls ──────

    /// Poisons a mutex by panicking in a thread while it holds the lock —
    /// every render/attribution path must then skip, never fabricate.
    fn poison_mutex<T: Send>(m: &Mutex<T>) {
        std::thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let _guard = m.lock().unwrap();
                    panic!("poison on purpose");
                })
                .join();
        });
    }

    /// A controllable in-memory stream: scripted bytes in, captured bytes
    /// out, with optional injected read/write failures.
    struct MockStream {
        pending: Vec<u8>,
        fail_reads: bool,
        fail_write: bool,
        fail_flush: bool,
        written: Vec<u8>,
    }

    impl MockStream {
        fn new(pending: Vec<u8>) -> Self {
            Self {
                pending,
                fail_reads: false,
                fail_write: false,
                fail_flush: false,
                written: Vec::new(),
            }
        }

        fn failing_reads(pending: Vec<u8>) -> Self {
            Self {
                fail_reads: true,
                ..Self::new(pending)
            }
        }

        fn parse_response(&self) -> SignResponse {
            assert!(self.written.len() >= 8, "a framed reply was written");
            let len = u64::from_be_bytes(self.written[..8].try_into().unwrap()) as usize;
            serde_json::from_slice(&self.written[8..8 + len]).expect("reply is a SignResponse")
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pending.is_empty() {
                return if self.fail_reads {
                    Err(std::io::Error::other("mock read failure"))
                } else {
                    Ok(0) // EOF
                };
            }
            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Ok(n)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.fail_write {
                return Err(std::io::Error::other("mock write failure"));
            }
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                return Err(std::io::Error::other("mock flush failure"));
            }
            Ok(())
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u64).to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    fn wait_for(mut cond: impl FnMut() -> bool, ms: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(ms);
        while std::time::Instant::now() < deadline {
            if cond() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(cond(), "condition not met within {ms} ms");
    }

    #[test]
    fn rate_limit_refill_wall_and_disabled_short_circuit() {
        // Negative refill would never refill → refused at validation.
        let bad = RateLimitPolicy {
            capacity: 5.0,
            refill_per_sec: -1.0,
        };
        let e = bad.validate().unwrap_err();
        assert!(e.contains("refill must be ≥ 0"), "{e}");
        // A failed set_rate_limit leaves the PREVIOUS policy armed.
        let mut c = cosigner();
        assert!(c.set_rate_limit(Some(bad)).is_err());
        assert!(c.rate_limit.is_some(), "the old policy must stay armed");
        // Disabling takes the `rate_limit == None` fast path per call.
        c.set_rate_limit(None).unwrap();
        assert!(c.take_rate_limit_token("bc1ptestvault"));
    }

    #[test]
    fn service_error_display_rows() {
        let r = ServiceError::Rejected("bad shape".into());
        assert_eq!(r.to_string(), "request rejected: bad shape");
        assert!(std::error::Error::source(&r).is_none());
        let k = ServiceError::Key(GateError::PqcVerificationFailed);
        assert!(k.to_string().starts_with("key error: "), "{k}");
    }

    #[test]
    fn metrics_render_survives_every_poisoned_lock() {
        // Histogram lock poisoned → rows skipped, exposition continues.
        let m = Metrics::default();
        m.observe_latency(500);
        poison_mutex(&m.serve_latency_buckets);
        let text = m.render();
        assert!(text.contains("qsv_cosigner_requests_total"), "{text}");
        assert!(
            !text.contains("qsv_cosigner_serve_latency_us_bucket"),
            "a poisoned histogram must not fabricate rows"
        );

        // The healthy histogram still renders the +Inf bucket + sum/count.
        let m = Metrics::default();
        m.observe_latency(42);
        let text = m.render();
        assert!(text.contains("le=\"+Inf\""), "{text}");
        assert!(text.contains("qsv_cosigner_serve_latency_us_count 1"));

        // Each per-vault map poisoned in turn → early return, no panic.
        for which in 0..3 {
            let m = Metrics::default();
            {
                let mut pv = m.per_vault.lock().unwrap();
                pv.entry("bc1ptestvault".into()).or_default();
            }
            match which {
                0 => poison_mutex(&m.per_vault),
                1 => poison_mutex(&m.alarm_rows),
                _ => poison_mutex(&m.rate_limited_rows),
            }
            let text = m.render();
            assert!(text.contains("qsv_cosigner_requests_total"), "{text}");
        }
    }

    #[test]
    fn attribution_survives_a_poisoned_per_vault_map() {
        let c = cosigner();
        poison_mutex(&c.metrics.per_vault);
        let pqc = PqcIdentity::from_seed(&[31u8; 32]);
        let sighash = [0x33u8; 32];
        let req = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        // The request still succeeds — attribution is best-effort.
        let resp = c
            .handle_request(&req)
            .expect("poison must not kill serving");
        assert!(resp.accepted);
    }

    #[test]
    fn handler_shape_walls_fail_closed_with_reasons() {
        let c = cosigner();
        let pqc = PqcIdentity::from_seed(&[32u8; 32]);
        let sighash = [0x44u8; 32];
        let sig = pqc.sign(&sighash);
        let vk = pqc.verifying_key_bytes();

        // Wrong protocol version → refusal (never an error).
        let mut req = SignRequest::new("bc1ptestvault", &sighash, vk, &sig);
        req.version = 99;
        let resp = c.handle_request(&req).unwrap();
        assert!(!resp.accepted);
        assert!(resp
            .reason
            .unwrap()
            .contains("unsupported protocol version 99"));

        // Malformed challenge nonce → refusal naming the v2 challenge.
        let mut req = SignRequest::new("bc1ptestvault", &sighash, vk, &sig);
        req.nonce_hex = "beef".into();
        let resp = c.handle_request(&req).unwrap();
        assert!(!resp.accepted);
        assert!(resp.reason.unwrap().contains("nonce must be 32 bytes"));

        // Sighash that is not 32 hex bytes → ServiceError::Rejected.
        let mut req = SignRequest::new("bc1ptestvault", &sighash, vk, &sig);
        req.sighash_hex = "ab".into();
        let e = c.handle_request(&req).unwrap_err();
        assert!(matches!(e, ServiceError::Rejected(_)), "{e:?}");
        assert!(e.to_string().contains("sighash must be 32 bytes"), "{e}");

        // Direct hex walls on the PQC envelope.
        let mut req = SignRequest::new("bc1ptestvault", &sighash, vk, &sig);
        req.pqc_vk_hex = "zz".into();
        let e = req.pqc_vk_hex_bytes().unwrap_err();
        assert!(e.to_string().contains("bad pqc vk hex"), "{e}");
        let mut req = SignRequest::new("bc1ptestvault", &sighash, vk, &sig);
        req.pqc_sig_hex = "no".into();
        let e = req.pqc_sig_hex_bytes().unwrap_err();
        assert!(e.to_string().contains("bad pqc sig hex"), "{e}");
    }

    #[test]
    fn provisioning_roundtrip_and_every_wall() {
        let fx = tempfile::tempdir().unwrap();
        let path = fx.path().join("prov.json");
        let c = cosigner();
        c.save_provisioning(&path).expect("roundtrip save");
        let loaded = Cosigner::load_provisioning(&path).expect("roundtrip load");
        assert_eq!(loaded.enclave_seed, [42u8; 32]);
        assert_eq!(loaded.allowed_vaults, vec!["bc1ptestvault".to_string()]);

        // Missing file → transport error before any parsing.
        let e = Cosigner::load_provisioning(&fx.path().join("nope.json"))
            .err()
            .expect("must fail");
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
        // Unparseable JSON → transport error, never a panic.
        let broken = fx.path().join("broken.json");
        std::fs::write(&broken, b"{not json").unwrap();
        let e = Cosigner::load_provisioning(&broken)
            .err()
            .expect("must fail");
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
        // Parseable but seedless → refusal.
        let seedless = fx.path().join("seedless.json");
        std::fs::write(&seedless, br#"{"version":2}"#).unwrap();
        let e = Cosigner::load_provisioning(&seedless)
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("missing seed"), "{e}");
        // Seed that isn't 32 bytes of hex → refusal.
        let short = fx.path().join("short.json");
        std::fs::write(&short, br#"{"seed_hex":"abcd"}"#).unwrap();
        let e = Cosigner::load_provisioning(&short)
            .err()
            .expect("must fail");
        assert!(e.to_string().contains("seed must be 32 bytes"), "{e}");
        // Writing the descriptor to a directory → mapped IO failure.
        let e = c.save_provisioning(&fx.path().to_path_buf()).unwrap_err();
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
    }

    #[test]
    fn rotate_counts_a_denial_on_an_unreadable_gate() {
        let tok = ScrapeToken::armed("sekrit");
        // Poison the gate lock: rotation must refuse AND count the denial.
        std::thread::scope(|s| {
            let _ = s
                .spawn(|| {
                    let _guard = tok.gate.write().unwrap();
                    panic!("poison on purpose");
                })
                .join();
        });
        let e = tok.rotate("next".into()).unwrap_err();
        assert!(e.contains("scrape gate unreadable"), "{e}");
        assert_eq!(tok.denials.load(Ordering::Relaxed), 1);
        assert_eq!(tok.rotations.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn frame_reader_walls_are_io_not_panics() {
        // Length beyond the 1 MiB wall → refusal.
        let len = ((1u64 << 20) + 1).to_be_bytes().to_vec();
        let mut s = MockStream::new(len);
        let e = read_frame(&mut s).unwrap_err();
        assert!(matches!(e, ServiceError::Rejected(_)), "{e:?}");
        assert!(e.to_string().contains("frame too large"), "{e}");
        // Length prefix promising 8 bytes that never arrive → IO error.
        let mut s = MockStream::new(8u64.to_be_bytes().to_vec());
        let e = read_frame(&mut s).unwrap_err();
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
        // Body shorter than the declared length → IO error (line 843).
        let mut s = MockStream::new(frame(b"abc"));
        s.pending.truncate(8 + 2);
        let e = read_frame(&mut s).unwrap_err();
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
        // A write failure surfaces as a transport error, never a panic.
        let mut boom = MockStream::new(Vec::new());
        boom.fail_write = true;
        let e = write_frame(&mut boom, b"payload").unwrap_err();
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
    }

    #[test]
    fn http_head_probe_units_cover_eof_errors_and_junk() {
        let shared = Arc::new(Mutex::new(cosigner()));
        let open = ScrapeToken::disarmed();

        // EOF mid-head → false (peer vanished, just close).
        let mut s = MockStream::new(Vec::new());
        assert!(!serve_http_head(
            &mut s,
            b"GET /metrics HTT",
            &shared,
            &open
        ));
        // Read error mid-head → false as well.
        let mut s = MockStream::failing_reads(Vec::new());
        assert!(!serve_http_head(
            &mut s,
            b"GET /metrics HTT",
            &shared,
            &open
        ));
        // An endless head beyond the 8 KiB wall → false.
        let mut s = MockStream::new(Vec::new());
        assert!(!serve_http_head(&mut s, &vec![b'A'; 8200], &shared, &open));

        // Non-metrics HTTP junk → deterministic frame refusal.
        let mut s = MockStream::new(Vec::new());
        assert!(serve_http_head(
            &mut s,
            b"POST /evil HTTP/1.1\r\nContent-Length: 4\r\n\r\n",
            &shared,
            &open
        ));
        let resp = s.parse_response();
        assert!(!resp.accepted);
        assert!(resp.reason.unwrap().contains("frame too large"));

        // Authorized scrape renders the exposition.
        let armed = ScrapeToken::armed("sekrit");
        let mut s = MockStream::new(Vec::new());
        assert!(serve_http_head(
            &mut s,
            b"GET /metrics HTTP/1.1\r\nX-QSV-Metrics-Token: sekrit\r\n\r\n",
            &shared,
            &armed
        ));
        let out = String::from_utf8_lossy(&s.written);
        assert!(out.contains("HTTP/1.1 200 OK"), "{out}");
        assert!(out.contains("# TYPE qsv_cosigner_requests_total counter"));

        // Wrong token → 401 AND the denial counter moves.
        let mut s = MockStream::new(Vec::new());
        assert!(serve_http_head(
            &mut s,
            b"GET /metrics HTTP/1.1\r\nX-QSV-Metrics-Token: wrong\r\n\r\n",
            &shared,
            &armed
        ));
        let out = String::from_utf8_lossy(&s.written);
        assert!(out.contains("HTTP/1.1 401 Unauthorized"), "{out}");
        assert_eq!(
            shared
                .lock()
                .unwrap()
                .metrics
                .metrics_denied_total
                .load(Ordering::Relaxed),
            1
        );

        // Poisoned cosigner lock during the authorized render → false.
        let poisoned = Arc::new(Mutex::new(cosigner()));
        poison_mutex(&poisoned);
        let mut s = MockStream::new(Vec::new());
        assert!(!serve_http_head(
            &mut s,
            b"GET /metrics HTTP/1.1\r\nX-QSV-Metrics-Token: sekrit\r\n\r\n",
            &poisoned,
            &armed
        ));
    }

    #[test]
    fn one_stream_units_cover_empty_bad_and_poisoned_inputs() {
        let shared = Arc::new(Mutex::new(cosigner()));
        let policy = ServePolicy::default();

        // Empty connection: probe EOF → return without touching the gate.
        let mut s = MockStream::new(Vec::new());
        serve_one_stream(&mut s, &shared, &|| {}, &policy);
        assert!(s.written.is_empty(), "an empty peer gets no reply");

        // Garbage frame body → bad-request-json refusal (line 1217).
        let mut s = MockStream::new(frame(b"not json at all"));
        serve_one_stream(&mut s, &shared, &|| {}, &policy);
        let resp = s.parse_response();
        assert!(!resp.accepted);
        assert!(resp.reason.unwrap().contains("bad request json"));

        // Handler-level ServiceError → rendered as a refusal (line 1225).
        let pqc = PqcIdentity::from_seed(&[34u8; 32]);
        let sighash = [0x55u8; 32];
        let mut bad = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        bad.sighash_hex = "ab".into();
        let body = serde_json::to_vec(&bad).unwrap();
        let mut s = MockStream::new(frame(&body));
        serve_one_stream(&mut s, &shared, &|| {}, &policy);
        let resp = s.parse_response();
        assert!(!resp.accepted);
        assert!(resp.reason.unwrap().contains("sighash must be 32 bytes"));

        // Poisoned cosigner lock: the frame parses, the lock maps to IO,
        // the refusal is written — serving continues.
        let poisoned = Arc::new(Mutex::new(cosigner()));
        poison_mutex(&poisoned);
        let valid = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let body = serde_json::to_vec(&valid).unwrap();
        let mut s = MockStream::new(frame(&body));
        serve_one_stream(&mut s, &poisoned, &|| {}, &policy);
        let resp = s.parse_response();
        assert!(!resp.accepted);
        assert!(resp.reason.unwrap().contains("lock poisoned"));
    }

    #[test]
    fn serve_wrappers_bind_and_enter_the_accept_loop() {
        // Both convenience wrappers must BIND successfully and park in
        // their accept loop — the thread outlives the test (documented
        // one-request-per-connection convention) and is reaped at exit.
        let h1 = std::thread::spawn(|| serve(cosigner(), "127.0.0.1:0"));
        let shared = Arc::new(Mutex::new(cosigner()));
        let h2 = std::thread::spawn(move || serve_shared("127.0.0.1:0", shared));
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!h1.is_finished(), "serve() must be alive in its loop");
        assert!(
            !h2.is_finished(),
            "serve_shared() must be alive in its loop"
        );
        // Intentionally leaked: no shutdown edge on these entrypoints.
        std::mem::forget(h1);
        std::mem::forget(h2);
    }

    #[test]
    fn shutdown_default_trigger_and_signal_installers() {
        let s = Shutdown::default();
        assert!(!s.should_shutdown(), "default must not fire by itself");
        assert!(!s.requested());
        s.trigger();
        assert!(s.should_shutdown());
        assert!(s.requested(), "a manual trigger is a stop edge");
        let progressed = s.progress_stamp().load(Ordering::Relaxed);
        assert!(progressed > 0, "the liveness stamp must be readable");

        // Installing handlers is infallible for valid signums; the global
        // edge stays CLEAR (no signal is raised here).
        Shutdown::disabled()
            .install_signal_handlers()
            .expect("signal installers install");
    }

    #[cfg(unix)]
    #[test]
    fn sighup_reload_edge_fires_exactly_once() {
        install_reload_handler().expect("SIGHUP installer installs");
        unsafe { libc::raise(libc::SIGHUP) };
        assert!(reload_requested(), "the handler must flip the edge");
        assert!(!reload_requested(), "one signal = one consumed edge");
    }

    #[test]
    fn request_signature_surfaces_a_malformed_response_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut probe = [0u8; 512];
            let _ = s.read(&mut probe);
            // A framed but non-JSON payload → parse failure, mapped.
            let _ = s.write_all(&frame(b"jnk"));
        });
        let pqc = PqcIdentity::from_seed(&[35u8; 32]);
        let sighash = [0x66u8; 32];
        let req = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let e = request_signature(&format!("127.0.0.1:{port}"), &req)
            .expect_err("junk response must surface as an error");
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
    }

    #[test]
    fn tls_client_walls_refuse_connect_and_bad_names() {
        let pqc = PqcIdentity::from_seed(&[36u8; 32]);
        let sighash = [0x77u8; 32];
        let req = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let fx = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = fx.path().join("cert.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        let roots = crate::tls::pinned_root_store_from_pem(&cert_path).unwrap();
        // Refused connect → IO, surfaced before any handshake.
        let e = request_signature_tls("127.0.0.1:1", &req, "localhost", roots.clone())
            .expect_err("nothing listens on port 1");
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
        // A syntactically invalid DNS name → refusal, not a panic.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::mem::forget(std::thread::spawn(move || {
            let _ = listener;
        }));
        let e = request_signature_tls(&format!("127.0.0.1:{port}"), &req, "bad name!", roots)
            .expect_err("invalid DNS name must refuse");
        assert!(matches!(e, ServiceError::Rejected(_)), "{e:?}");
    }

    /// rcgen CA + server + client PEMs — the operator's mTLS shape.
    fn mtls_fixture(dir: &std::path::Path) {
        use rcgen::{CertificateParams, KeyPair};
        let ca_key = KeyPair::generate().unwrap();
        let ca_params = CertificateParams::new(vec!["qsv test ca".to_string()]).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
        let server_key = KeyPair::generate().unwrap();
        let server_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        let server_cert = server_params
            .signed_by(&server_key, &ca_cert, &ca_key)
            .expect("server cert signed by the CA");
        let client_key = KeyPair::generate().unwrap();
        let client_params =
            CertificateParams::new(vec!["qsv co-signing client".to_string()]).unwrap();
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .expect("client cert signed by the CA");
        std::fs::write(dir.join("ca.pem"), ca_cert.pem()).unwrap();
        std::fs::write(dir.join("cert.pem"), server_cert.pem()).unwrap();
        std::fs::write(dir.join("key.pem"), server_key.serialize_pem()).unwrap();
        std::fs::write(dir.join("client.pem"), client_cert.pem()).unwrap();
        std::fs::write(dir.join("client-key.pem"), client_key.serialize_pem()).unwrap();
    }

    #[test]
    fn mtls_wrapper_serves_a_client_cert_request_end_to_end() {
        let fx = tempfile::tempdir().unwrap();
        mtls_fixture(fx.path());
        let p = |n: &str| fx.path().join(n);
        let cfg = crate::tls::tls_listener_config_with_client_auth(
            &p("cert.pem"),
            &p("key.pem"),
            &p("ca.pem"),
        )
        .unwrap()
        .into_server_config();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = Arc::new(Mutex::new(cosigner()));
        let s = Arc::clone(&shared);
        // Chain: mtls wrapper → tls wrapper → _and_shutdown(disabled):
        // the thread outlives this test and is reaped at process exit.
        std::thread::spawn(move || {
            let _ = serve_with_mtls_mirror(listener, s, || {}, cfg);
        });
        // The server's leaf is CA-signed: the client pins the CA (the
        // issuer) so the chain validates — same discipline as the bridge.
        let roots = crate::tls::pinned_root_store_from_pem(&p("ca.pem")).unwrap();
        let ident = crate::tls::client_identity(&p("client.pem"), &p("client-key.pem")).unwrap();
        let pqc = PqcIdentity::from_seed(&[37u8; 32]);
        let sighash = [0x88u8; 32];
        let req = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let addr = format!("127.0.0.1:{port}");
        let resp = request_signature_mtls(&addr, &req, "localhost", roots, &ident)
            .expect("the mTLS tunnel must answer");
        assert!(resp.accepted, "valid client cert + valid proof opens");
    }

    #[test]
    fn tls_loop_caps_inflight_workers_and_drains_on_shutdown() {
        let fx = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        let cert_path = fx.path().join("cert.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        let key_path = fx.path().join("key.pem");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        let cfg = crate::tls::tls_listener_config(&cert_path, &key_path)
            .unwrap()
            .into_server_config();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let shared = Arc::new(Mutex::new(cosigner()));
        let s = Arc::clone(&shared);
        let shutdown = Shutdown::disabled();
        let edge = shutdown.clone();
        let policy = ServePolicy {
            frame_timeout: Some(std::time::Duration::from_secs(3)),
            metrics_token: ScrapeToken::disarmed(),
            max_inflight: 1,
        };
        let server = std::thread::spawn(move || {
            serve_with_tls_mirror_and_shutdown(listener, s, || {}, cfg, edge, policy)
        });
        let roots = crate::tls::pinned_root_store_from_pem(&cert_path).unwrap();
        let pqc = PqcIdentity::from_seed(&[38u8; 32]);
        let sighash = [0x99u8; 32];
        let req = SignRequest::new(
            "bc1ptestvault",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let addr = format!("127.0.0.1:{port}");

        // Holder: a bare TCP connect sends nothing, so the worker parks
        // in its (frame-timeout-bounded) handshake read — in_flight = 1.
        let _holder = TcpStream::connect(&addr).expect("the loop must accept the holder");
        wait_for(
            || {
                shared
                    .lock()
                    .map(|c| c.metrics.workers_active.load(Ordering::Relaxed) >= 1)
                    .unwrap_or(false)
            },
            3_000,
        );

        // Second connection under cap=1 → refused at the transport, and
        // the refusal counter records it.
        let e = request_signature_tls(&addr, &req, "localhost", roots.clone())
            .expect_err("the cap must refuse the second worker");
        assert!(matches!(e, ServiceError::Io(_)), "{e:?}");
        wait_for(
            || {
                shared
                    .lock()
                    .map(|c| c.metrics.capacity_refused_total.load(Ordering::Relaxed) >= 1)
                    .unwrap_or(false)
            },
            3_000,
        );

        // Graceful edge: the loop stops accepting, drains the holder's
        // worker (bounded by frame_timeout) and returns the ordinary Ok.
        shutdown.trigger();
        let out = server.join().expect("the accept loop must not panic");
        assert!(out.is_ok(), "an operator stop is an Ok: {out:?}");
    }

    // ── Round 30 (b): arms only a direct call can reach ─────────────────

    #[test]
    fn latency_histogram_survives_a_poisoned_bucket_map() {
        let m = Metrics::default();
        poison_mutex(&m.serve_latency_buckets);
        // The sum/count pair still advances; only the histogram is skipped.
        m.observe_latency(42);
        assert_eq!(m.serve_latency_count.load(Ordering::Relaxed), 1);
        assert!(m.serve_latency_buckets.lock().is_err());
    }

    #[test]
    fn rate_limiter_never_self_dos_on_a_poisoned_bucket_map() {
        let c = cosigner();
        let (_, buckets) = c.rate_limit.as_ref().expect("provision arms the limiter");
        poison_mutex(buckets);
        // Poisoned map → allow: the limiter is protection, not the gate.
        assert!(c.take_rate_limit_token("bc1ptestvault"));
    }

    #[test]
    fn gate_outcome_maps_every_arm() {
        // PQC failure → refusal carrying the operator-facing reason.
        let resp = map_gate_outcome(Err(GateError::PqcVerificationFailed), attest_ok)
            .expect("a refusal is a response");
        assert!(!resp.accepted);
        assert!(resp
            .reason
            .unwrap()
            .contains("ML-DSA-65 verification failed"));
        // Success → the attestation closure decides the response.
        let resp = map_gate_outcome(Ok([7u8; 64]), attest_ok).expect("attested ok");
        assert!(resp.accepted);
        assert_eq!(resp.schnorr_sig_hex.unwrap(), hex::encode([7u8; 64]));
        // Any OTHER gate fault is a connection-level KEY error.
        let e = map_gate_outcome(Err(GateError::EnclaveKey), attest_ok).unwrap_err();
        assert!(
            matches!(e, ServiceError::Key(GateError::EnclaveKey)),
            "{e:?}"
        );
    }

    #[test]
    fn wait_for_fails_loudly_when_the_condition_never_holds() {
        let hit = AtomicBool::new(false);
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            wait_for(|| hit.load(Ordering::Relaxed), 30);
        }))
        .is_err();
        assert!(
            panicked,
            "a wait that never resolves must panic with its deadline"
        );
    }

    #[test]
    fn frame_flush_failure_is_an_error_not_a_silent_drop() {
        let mut s = MockStream::new(vec![]);
        s.fail_flush = true;
        let e = write_frame(&mut s, b"body").expect_err("flush failure must surface");
        assert!(e.to_string().contains("mock flush failure"), "{e}");
    }

    #[test]
    fn tls_worker_drops_connections_whose_config_cannot_make_a_session() {
        use std::io::Read as _;
        // A config with an INVALID fragment size: `ServerConnection::new`
        // refuses per connection (rustls validates the buffer bound), so
        // the worker exits BEFORE any handshake byte — the client sees an
        // immediate close, never a half-negotiated session.
        let key = rcgen::KeyPair::generate().expect("key");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .self_signed(&key)
            .expect("self-signed");
        let certs = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
        let key_der: rustls::pki_types::PrivateKeyDer<'static> =
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into();
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key_der)
            .expect("server cert");
        cfg.max_fragment_size = Some(1); // too small → connection refused
        assert!(
            rustls::ServerConnection::new(std::sync::Arc::new(cfg.clone())).is_err(),
            "the broken config must refuse a session up front"
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let shared = Arc::new(Mutex::new(cosigner()));
        let shutdown = Shutdown::disabled();
        let stop = shutdown.clone();
        let server = std::thread::spawn(move || {
            serve_with_tls_mirror_and_shutdown(
                listener,
                shared,
                counting_mirror,
                std::sync::Arc::new(cfg),
                shutdown,
                ServePolicy::default(),
            )
        });

        // The worker for THIS connection dies at session construction →
        // EOF without a ServerHello.
        let mut client = std::net::TcpStream::connect(addr).expect("connect");
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .expect("timeout");
        let mut buf = [0u8; 8];
        let n = client.read(&mut buf).expect("EOF, not a hang");
        assert_eq!(n, 0, "a refused session closes without handshake bytes");

        stop.trigger();
        let out = server.join().expect("the accept loop must not panic");
        assert!(out.is_ok(), "an operator stop is an Ok: {out:?}");
    }
}
