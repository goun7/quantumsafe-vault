//! SD_NOTIFY (docs/10 §4.26, Round 21) — the systemd `Type=notify` client.
//!
//! `systemctl is-active` only knows the unit file; a co-signer that bound
//! its socket, wrote its health record and then **deadlocked** looks exactly
//! as "active" as a healthy one — until a signature request times out. The
//! notify protocol closes that gap in BOTH directions:
//!
//! - `READY=1` — sent only after the bind AND the health record are real
//!   (systemd starts the service clock from this message, not from `fork`);
//! - `WATCHDOG=1` — sent periodically, but ONLY while the accept loop can
//!   prove it is still ticking (see [`spawn_watchdog`]): pings that ignore
//!   liveness are theater, and a theater watchdog never restarts a wedged
//!   bridge;
//! - `STOPPING=1` — the graceful path is beginning its drain.
//!
//! Everything is std-only (one datagram per message): `NOTIFY_SOCKET` is a
//! filesystem path or an abstract (`@name`, Linux) socket, `WATCHDOG_USEC`
//! is systemd's watchdog period in microseconds (sd_notify(3): ping at
//! HALF of it). Outside systemd — dev runs, tests, bare metal — neither
//! variable exists and every call is a no-op, never an error.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Where systemd is listening: a filesystem path, or an abstract socket
/// (`NOTIFY_SOCKET=@…`, the Linux short form sd_notify(3) documents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotifySocket {
    /// A filesystem socket path (`/run/systemd/notify`).
    Path(std::path::PathBuf),
    /// An abstract socket name — WITHOUT the leading `@` (Linux only).
    Abstract(Vec<u8>),
}

impl NotifySocket {
    /// Parses a `NOTIFY_SOCKET` spec: a leading `@` selects the abstract
    /// namespace, anything else is a filesystem path.
    pub fn parse(spec: &str) -> Self {
        match spec.strip_prefix('@') {
            Some(name) => Self::Abstract(name.as_bytes().to_vec()),
            None => Self::Path(spec.to_string().into()),
        }
    }

    /// Sends one `KEY=value` state message. Callers decide what a failure
    /// MEANS: for `READY` it is fatal (systemd would never see the service
    /// start), for watchdog pings it is best-effort silence.
    pub fn send(&self, state: &str) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::net::UnixDatagram;
            let sock = UnixDatagram::unbound()?;
            match self {
                Self::Path(path) => {
                    sock.send_to(state.as_bytes(), path)?;
                }
                Self::Abstract(name) => {
                    #[cfg(target_os = "linux")]
                    {
                        use std::os::linux::net::SocketAddrExt;
                        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
                        sock.send_to_addr(state.as_bytes(), &addr)?;
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = name;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "abstract NOTIFY_SOCKET is Linux-only",
                        ));
                    }
                }
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let _ = state;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "sd_notify requires unix sockets",
            ))
        }
    }
}

/// The supervisor's socket, or `None` when no supervisor listens (dev,
/// tests, bare metal) — the caller then skips every notify call.
pub fn from_env() -> Option<NotifySocket> {
    std::env::var_os("NOTIFY_SOCKET").map(|spec| NotifySocket::parse(&spec.to_string_lossy()))
}

/// The watchdog ping interval derived from systemd's `WATCHDOG_USEC`
/// (sd_notify(3): ping at half the period). `None` when the variable is
/// absent/invalid/zero — no watchdog was requested.
pub fn watchdog_interval() -> Option<Duration> {
    let spec = std::env::var("WATCHDOG_USEC").ok()?;
    interval_from_usecs(spec.trim())
}

/// Pure core of [`watchdog_interval`] (unit-testable without env).
pub fn interval_from_usecs(spec: &str) -> Option<Duration> {
    let usecs = spec.parse::<u64>().ok()?;
    if usecs == 0 {
        return None;
    }
    // Halve, and keep the result non-degenerate even for a 1µs watchdog.
    Some(Duration::from_micros((usecs / 2).max(1)))
}

/// Current wall clock in unix milliseconds (progress stamps).
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// THE WATCHDOG THREAD (docs/10 §4.26): pings every `interval` — but only
/// while `progress_ms` has moved within `stall_limit`. The accept loops
/// stamp that counter on every poll tick, so:
///
/// - a loop serving a slow stream is LEGITIMATELY quiet for at most one
///   frame timeout — `stall_limit = frame_timeout + interval` never calls
///   that a stall;
/// - a loop that stopped ticking (deadlock, livelock, a worker that
///   poisoned the cosigner mutex) goes silent, systemd sees no ping within
///   `WatchdogSec` and restarts us — the fail-closed supervisor action a
///   `bridge-health.json` with a live pid can never provide on its own.
///
/// After `done` flips the thread exits on its next tick (never joined: the
/// process is leaving anyway, and a watchdog thread must not delay exit).
///
/// The moment the pings STOP, `on_stall` is called ONCE per episode (and
/// again if the loop unwedges and freezes a second time): silence stays
/// the restart signal, but silence with no reason leaves the operator
/// reading a restart in journald with no witness to WHY (docs/10 §4.34).
/// The stall predicate, boundary INCLUDED: an episode age exactly AT the
/// limit IS a stall (the limit is a floor, never a target). Extracted as a
/// pure function so the boundary is unit-pinned — the Round-32 sweep's
/// `>=` → `>` flip must die here instead of hiding behind wall-clock
/// jitter in the loop.
fn stalled_at(age_ms: u64, stall_limit_ms: u64) -> bool {
    age_ms >= stall_limit_ms
}

pub fn spawn_watchdog<R>(
    socket: NotifySocket,
    interval: Duration,
    progress_ms: ArcProgress,
    stall_limit: Duration,
    done: std::sync::Arc<AtomicBool>,
    on_stall: R,
) -> std::thread::JoinHandle<()>
where
    R: Fn(&str) + Send + 'static,
{
    std::thread::spawn(move || {
        let stall_ms = stall_limit.as_millis() as u64;
        let mut reported = false;
        loop {
            std::thread::sleep(interval);
            if done.load(Ordering::Relaxed) {
                return;
            }
            let age = now_ms().saturating_sub(progress_ms.load(Ordering::Relaxed));
            if stalled_at(age, stall_ms) {
                // WHY we are going silent — reported BEFORE the silence,
                // once per episode: claiming health we cannot prove is
                // the lie this record refuses, but leaving no witness is
                // a post-mortem nobody can write.
                if !reported {
                    reported = true;
                    on_stall(&format!(
                        "watchdog: accept loop silent for {age} ms (stall limit {stall_ms} ms) — yielding pings to systemd; a restart is the recovery if it does not resume"
                    ));
                }
            } else {
                // Best-effort: a vanished supervisor is not OUR error —
                // the missing pings are what makes systemd act.
                let _ = socket.send("WATCHDOG=1");
                if reported {
                    // The loop ticked again: close the episode so the
                    // NEXT freeze reports like the first one.
                    reported = false;
                }
            }
            // Stalled: SILENCE on purpose from here on.
        }
    })
}

/// Shared handle on the accept-loop progress stamp (an `Arc<AtomicU64>` of
/// unix-ms; type alias so the public watchdog API does not spell the Arc).
pub type ArcProgress = std::sync::Arc<AtomicU64>;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn bound_pair(name: &str) -> (std::os::unix::net::UnixDatagram, NotifySocket) {
        let dir = std::env::temp_dir().join(format!("qsv-notify-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify.sock");
        let _ = std::fs::remove_file(&path);
        let rx = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        (rx, NotifySocket::Path(path))
    }

    #[cfg(unix)]
    fn recv(rx: &std::os::unix::net::UnixDatagram) -> String {
        let mut buf = [0u8; 64];
        let n = rx.recv(&mut buf).expect("a datagram must arrive");
        String::from_utf8_lossy(&buf[..n]).to_string()
    }

    #[test]
    fn parse_splits_path_and_abstract_specs() {
        assert_eq!(
            NotifySocket::parse("/run/systemd/notify"),
            NotifySocket::Path("/run/systemd/notify".into())
        );
        assert_eq!(
            NotifySocket::parse("@qsv/notify"),
            NotifySocket::Abstract(b"qsv/notify".to_vec())
        );
        // The abstract form must NOT keep the '@' — the kernel namespace
        // name is the bytes after it.
        assert!(!matches!(
            NotifySocket::parse("@qsv"),
            NotifySocket::Abstract(n) if n.first() == Some(&b'@')
        ));
    }

    #[test]
    fn watchdog_interval_is_half_the_period_and_gives_up_on_nonsense() {
        assert_eq!(
            interval_from_usecs("400000"),
            Some(Duration::from_millis(200))
        );
        assert_eq!(interval_from_usecs("1"), Some(Duration::from_micros(1)));
        assert_eq!(interval_from_usecs("0"), None, "0 = no watchdog asked");
        assert_eq!(interval_from_usecs("-5"), None, "not a number");
        assert_eq!(interval_from_usecs("later"), None);
        assert_eq!(interval_from_usecs(""), None);
    }

    #[cfg(unix)]
    #[test]
    fn ready_stopping_and_watchdog_cross_a_filesystem_socket() {
        let (rx, socket) = bound_pair("states");
        socket.send("READY=1").unwrap();
        assert_eq!(recv(&rx), "READY=1");
        socket.send("WATCHDOG=1").unwrap();
        assert_eq!(recv(&rx), "WATCHDOG=1");
        socket.send("STOPPING=1").unwrap();
        assert_eq!(recv(&rx), "STOPPING=1");
        let dir = rx
            .local_addr()
            .unwrap()
            .as_pathname()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn abstract_sockets_round_trip_too() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        // Unique per pid — abstract names are machine-global.
        let name = format!("qsv-notify-abs-{}", std::process::id());
        let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let rx = UnixDatagram::bind_addr(&addr).unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        NotifySocket::Abstract(name.into_bytes())
            .send("READY=1")
            .unwrap();
        let mut buf = [0u8; 32];
        let n = rx.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1");
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_reports_each_freeze_episode_and_pings_only_while_ticking() {
        use std::sync::Arc;
        let (rx, socket) = bound_pair("watch");
        // START STALLED: the counter is far older than the 2 s stall
        // limit, so the first tick reports episode #1 before any ping.
        let progress = Arc::new(AtomicU64::new(now_ms() - 1_000_000));
        let done = Arc::new(AtomicBool::new(false));
        let reports = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let handle = spawn_watchdog(
            socket,
            Duration::from_millis(10),
            Arc::clone(&progress),
            Duration::from_secs(2),
            Arc::clone(&done),
            {
                let reports = Arc::clone(&reports);
                move |m| reports.lock().unwrap().push(m.to_string())
            },
        );
        // Episode 1: silence is reported ONCE (the witness for the
        // restart an operator will see in journald).
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while reports.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            reports.lock().unwrap().len(),
            1,
            "one stall episode reports exactly once"
        );

        // A FOREIGN datagram on the socket: a recv that is not a ping
        // must simply not count (the loop keeps ticking).
        let sender = std::os::unix::net::UnixDatagram::unbound().unwrap();
        let path = rx
            .local_addr()
            .unwrap()
            .as_pathname()
            .unwrap()
            .to_path_buf();
        sender.send_to(b"JUNK", &path).unwrap();

        // The loop unwedges → the resumed ticks PING and close the
        // episode (the NEXT freeze reports like the first one).
        progress.store(now_ms(), Ordering::Relaxed);
        let mut got = 0;
        for _ in 0..25 {
            if recv(&rx) == "WATCHDOG=1" {
                got += 1;
            }
        }
        assert!(got >= 2, "a ticking loop must be pinged, got {got}");

        // Episode 2: stalling again MUST report again — it only does if
        // the resumed tick reset the episode flag.
        progress.store(now_ms() - 1_000_000, Ordering::Relaxed);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while reports.lock().unwrap().len() < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        done.store(true, Ordering::Relaxed);
        handle.join().unwrap();
        let seen = reports.lock().unwrap().clone();
        assert_eq!(seen.len(), 2, "each episode reports once: {seen:?}");
        assert!(
            seen.iter().all(|m| m.contains("silent")),
            "each report names the silence: {seen:?}"
        );
        let dir = rx
            .local_addr()
            .unwrap()
            .as_pathname()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn stall_boundary_is_inclusive_at_exactly_the_limit() {
        // The limit is a floor: age exactly AT the limit IS a stall (a
        // stale-but-equal episode must not keep pinging health to systemd).
        // Unit-pinned so the Round-32 sweep's `>=` flip dies here.
        assert!(!stalled_at(99, 100), "below the limit is healthy");
        assert!(stalled_at(100, 100), "exactly at the limit is a stall");
        assert!(stalled_at(101, 100), "past the limit is a stall");
        assert!(!stalled_at(0, 1), "zero age under a 1 ms limit is healthy");
    }

    #[cfg(unix)]
    #[test]
    fn watchdog_goes_silent_when_the_progress_stamp_is_stale() {
        use std::sync::Arc;
        let (rx, socket) = bound_pair("stale");
        // Stamp from a minute ago: the accept loop has NOT ticked.
        let progress = Arc::new(AtomicU64::new(now_ms().saturating_sub(60_000)));
        let done = Arc::new(AtomicBool::new(false));
        let reports = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let handle = spawn_watchdog(
            socket,
            Duration::from_millis(15),
            Arc::clone(&progress),
            Duration::from_millis(100),
            Arc::clone(&done),
            {
                let reports = Arc::clone(&reports);
                move |m| reports.lock().unwrap().push(m.to_string())
            },
        );
        // Several ping periods pass in silence — that IS the signal.
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            rx.recv(&mut [0u8; 32]).is_err(),
            "a stalled loop must NOT receive watchdog pings"
        );
        done.store(true, Ordering::Relaxed);
        handle.join().unwrap();
        // …but the silence carries a WITNESS: one report per episode, on
        // the operator's log, naming the freeze (docs/10 §4.34).
        {
            let seen = reports.lock().unwrap();
            assert_eq!(
                seen.len(),
                1,
                "exactly one stall report per episode: {seen:?}"
            );
            assert!(
                seen[0].contains("accept loop silent"),
                "the report must name the freeze: {seen:?}"
            );
        }
        let dir = rx
            .local_addr()
            .unwrap()
            .as_pathname()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();
        let _ = std::fs::remove_dir_all(dir);
    }
}
