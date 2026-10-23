//! BRIDGE HEALTH FILE (docs/10 §4.23) — the operator's one-glance
//! "is the co-signer actually up, and with which policy?" answer, on disk.
//!
//! `systemctl is-active` only knows the unit; `ss -ltnp` only knows the
//! socket. Neither answers the question that matters when a signing queue
//! backs up: *which* process owns the port, from *which* bind address,
//! serving *which* vaults, with the alarm mirror at *what* tip. This file
//! is that record, and it is written **fail-closed on the read side**:
//!
//! - Written atomically at boot (temp file + rename) so a scraper or
//!   `qsv-cli doctor` can never observe a half-written record.
//! - Removed on the graceful path (SIGTERM/SIGINT drain, serve returned).
//!   Its presence with a live pid means "up"; its absence means "not
//!   serving" — an honest default, the same fail-closed bias as the alarm
//!   mirror (absence never means "healthy".
//! - Presence with a DEAD pid is a stale record: the bridge died without
//!   its cleanup (SIGKILL, OOM, `kill -9`). A supervisor wants that as a
//!   hard failure, not silence.

use serde::{Deserialize, Serialize};

/// The file name inside the state dir (the operator-facing, greppable one).
pub const HEALTH_FILE: &str = "bridge-health.json";

/// The boot record: WHO is serving, from WHERE, with WHICH policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeHealth {
    /// Serving process id (`getpid`).
    pub pid: u32,
    /// The `--listen` address the process actually bound.
    pub listen: String,
    /// `plain` (loopback), `tls` or `mtls` — never "unknown".
    pub transport: String,
    /// The vaults provisioned into this co-signer.
    pub vaults: Vec<String>,
    /// UNIX seconds at boot (diagnostics: how long has it been up).
    pub started_at_unix: u64,
    /// Watchtower tip whose verdicts the alarm mirror was seeded from.
    pub watchtower_tip: u32,
    /// Whether the `/metrics` scrape gate is armed (never the token).
    pub metrics_token_armed: bool,
    /// The `--metrics-token-file` PATH a SIGHUP reload would re-read —
    /// the PATH only, never the value (Round 23). `None` means the gate
    /// was armed from argv (or is open), so `systemctl reload` has
    /// nothing to re-read: `qsv-cli doctor` says that out loud instead of
    /// letting the next rotation fail silently
    /// (`QsvCosignerTokenRotationStalled`).
    ///
    /// `#[serde(default)]` keeps a record written by an older build
    /// READABLE — a missing field must never turn a live bridge into a
    /// false "stale record".
    #[serde(default)]
    pub metrics_token_file: Option<String>,
    /// In-flight worker cap (`0` = unlimited).
    pub max_inflight: usize,
    /// Per-stream deadline in ms (`null` = unbounded).
    pub frame_timeout_ms: Option<u64>,
}

/// `<state_dir>/bridge-health.json`.
pub fn health_path(state_dir: &std::path::Path) -> std::path::PathBuf {
    state_dir.join(HEALTH_FILE)
}

/// The POLICY half of the boot record, bundled (Round 23): the four
/// operator-facing knobs the process actually runs with. One parameter
/// instead of four keeps the constructor honest — a new knob is a new
/// field everyone is forced to fill, not a positional tail someone
/// silently forgets. The on-disk shape is unchanged (the record stays
/// flat, field for field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServePolicyRecord {
    /// Whether the `/metrics` scrape gate is armed (never the token).
    pub metrics_token_armed: bool,
    /// The `--metrics-token-file` PATH a reload re-reads (`None` = the
    /// gate was armed from argv, so a reload cannot rotate it).
    pub metrics_token_file: Option<String>,
    /// In-flight worker cap (`0` = unlimited).
    pub max_inflight: usize,
    /// Per-stream deadline in ms (`None` = unbounded).
    pub frame_timeout_ms: Option<u64>,
}

/// Builds the record for the CURRENT process (id + boot clock).
pub fn current(
    listen: &str,
    transport: &str,
    vaults: Vec<String>,
    watchtower_tip: u32,
    policy: ServePolicyRecord,
) -> BridgeHealth {
    BridgeHealth {
        pid: std::process::id(),
        listen: listen.to_string(),
        transport: transport.to_string(),
        vaults,
        started_at_unix: now_unix(),
        watchtower_tip,
        metrics_token_armed: policy.metrics_token_armed,
        metrics_token_file: policy.metrics_token_file,
        max_inflight: policy.max_inflight,
        frame_timeout_ms: policy.frame_timeout_ms,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Publishes the record atomically. A half-written file is worse than
/// none (a reader would parse a truncated object and call it stale), so
/// the temp-file + rename is not decoration.
///
/// The token VALUE never reaches this file — only whether the gate is
/// armed. The health file is readable by anyone who can read the state
/// dir, which is exactly the audience the token protects from.
pub fn write(state_dir: &std::path::Path, health: &BridgeHealth) -> Result<(), String> {
    let path = health_path(state_dir);
    let tmp = state_dir.join(format!("{HEALTH_FILE}.tmp"));
    let body = serde_json::to_string_pretty(health)
        .map_err(|e| format!("cannot serialize bridge health: {e}"))?;
    std::fs::write(&tmp, body.as_bytes())
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        // Clean the temp so a failed boot leaves no debris behind.
        let _ = std::fs::remove_file(&tmp);
        format!("cannot publish {}: {e}", path.display())
    })
}

/// Reads the record (`None` = never served / already stopped cleanly).
pub fn read(state_dir: &std::path::Path) -> Option<BridgeHealth> {
    let body = std::fs::read_to_string(health_path(state_dir)).ok()?;
    serde_json::from_str(&body).ok()
}

/// Removes the record on the graceful path. Idempotent, and a missing file
/// is success (a stop is a stop).
pub fn remove(state_dir: &std::path::Path) {
    let _ = std::fs::remove_file(health_path(state_dir));
    let _ = std::fs::remove_file(state_dir.join(format!("{HEALTH_FILE}.tmp")));
}

/// Liveness of a recorded pid: `Some(true/false)` on POSIX, `None` where
/// this crate cannot ask (no `kill(2)`). `None` must NEVER be read as
/// "alive" — an unknown is unknown, and the caller says so.
pub fn pid_alive(pid: u32) -> Option<bool> {
    #[cfg(unix)]
    {
        if pid == 0 {
            // Signal 0 against pid 0 means "my process group" — not the
            // answer the operator asked for. Treat the record as bogus.
            return Some(false);
        }
        // signal 0 performs the permission + existence checks without
        // delivering anything. EPERM = the process EXISTS but is not ours
        // (e.g. root-owned bridge, non-root operator) — that is alive.
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if ret == 0 {
            Some(true)
        } else {
            Some(std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        None
    }
}

/// The three states a record can be in, as an operator sees them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    /// No record at all: the bridge never booted here, or stopped cleanly.
    Absent,
    /// A record whose pid still answers `kill(pid, 0)`.
    Live,
    /// A record whose pid is gone: an unclean death (SIGKILL/OOM) left
    /// the file behind — the supervisor's restart has not happened yet.
    Stale,
    /// A record exists but liveness cannot be decided on this platform.
    Unknown,
}

/// Classifies the record in `state_dir` in ONE pass.
pub fn liveness(state_dir: &std::path::Path) -> (Liveness, Option<BridgeHealth>) {
    match read(state_dir) {
        None => (Liveness::Absent, None),
        Some(h) => (classify(pid_alive(h.pid)), Some(h)),
    }
}

/// One record's liveness from a probe result. `None` (the platform
/// cannot ask) is NEVER read as "alive": the caller reports Unknown.
fn classify(probe: Option<bool>) -> Liveness {
    match probe {
        Some(true) => Liveness::Live,
        Some(false) => Liveness::Stale,
        None => Liveness::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(pid: u32) -> BridgeHealth {
        current(
            "127.0.0.1:3334",
            "plain",
            vec!["test-vault-1".to_string()],
            820_000,
            ServePolicyRecord {
                metrics_token_armed: false,
                metrics_token_file: None,
                max_inflight: 64,
                frame_timeout_ms: Some(10_000),
            },
        )
        .tap_pid(pid)
    }

    impl BridgeHealth {
        fn tap_pid(mut self, pid: u32) -> Self {
            self.pid = pid;
            self
        }
    }

    #[test]
    fn record_round_trips_and_never_carries_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let h = sample(std::process::id());
        write(dir.path(), &h).unwrap();
        let back = read(dir.path()).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.listen, "127.0.0.1:3334");
        assert_eq!(back.transport, "plain");
        assert_eq!(back.vaults, vec!["test-vault-1".to_string()]);
        assert_eq!(back.watchtower_tip, 820_000);
        assert_eq!(back.max_inflight, 64);
        assert_eq!(back.frame_timeout_ms, Some(10_000));
        assert_eq!(
            back.metrics_token_file, None,
            "a gate armed from argv records no reload source"
        );
        assert!(back.started_at_unix > 1_600_000_000, "boot clock");
        // The ARMED bit is diagnostic; the secret is not on disk.
        let raw = std::fs::read_to_string(health_path(dir.path())).unwrap();
        assert!(!raw.contains("s3cr3t"));
        assert!(raw.contains("\"metrics_token_armed\": false"));
    }

    #[test]
    fn no_temp_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &sample(std::process::id())).unwrap();
        assert!(!dir.path().join(format!("{HEALTH_FILE}.tmp")).exists());
        assert!(health_path(dir.path()).exists());
        // The rename is atomic: readers only ever see a complete object.
        remove(dir.path());
        assert!(!health_path(dir.path()).exists());
        // Idempotent: stopping twice is still a stop.
        remove(dir.path());
        assert!(read(dir.path()).is_none());
        assert_eq!(liveness(dir.path()).0, Liveness::Absent);
    }

    #[test]
    fn a_dead_pid_is_reported_stale_not_healthy() {
        let dir = tempfile::tempdir().unwrap();
        // Fork a child, reap it: the pid is definitively gone.
        let dead = {
            let mut child = std::process::Command::new("true").spawn().unwrap();
            let pid = child.id();
            child.wait().unwrap();
            pid
        };
        write(dir.path(), &sample(dead)).unwrap();
        let (state, h) = liveness(dir.path());
        assert_eq!(state, Liveness::Stale, "a dead pid is never 'live'");
        assert_eq!(h.unwrap().pid, dead);
        // This very process IS live.
        write(dir.path(), &sample(std::process::id())).unwrap();
        assert_eq!(liveness(dir.path()).0, Liveness::Live);
        // A zero pid is bogus (signal 0 would target our process group).
        assert_eq!(pid_alive(0), Some(false));
    }

    #[test]
    fn a_malformed_record_reads_as_absent_never_as_healthy() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(health_path(dir.path()), "{ \"pid\": ").unwrap();
        assert!(read(dir.path()).is_none());
        assert_eq!(
            liveness(dir.path()).0,
            Liveness::Absent,
            "unparseable is unknown, and unknown is not 'up'"
        );
    }

    /// The classification table itself: an undecidable probe (a platform
    /// without `kill(2)`) must surface as Unknown, never as Live.
    #[test]
    fn an_undecidable_probe_is_unknown_never_healthy() {
        assert_eq!(classify(None), Liveness::Unknown);
        assert_eq!(classify(Some(true)), Liveness::Live);
        assert_eq!(classify(Some(false)), Liveness::Stale);
    }

    /// A failed publish (rename(2) refusing) cleans its temp file: a
    /// half-published health record is worse than none.
    #[test]
    fn a_failed_publish_leaves_no_temp_debris() {
        let dir = tempfile::tempdir().unwrap();
        // A DIRECTORY at the publish path makes the rename fail (EISDIR).
        std::fs::create_dir(health_path(dir.path())).unwrap();
        let err = write(dir.path(), &sample(std::process::id()))
            .expect_err("a rename onto a directory must fail");
        assert!(err.contains("cannot publish"), "{err}");
        assert!(
            !dir.path().join(format!("{HEALTH_FILE}.tmp")).exists(),
            "the temp must be cleaned so a failed boot leaves no debris"
        );
        std::fs::remove_dir(health_path(dir.path())).unwrap();
    }
}
