//! Co-signer bridge systemd unit + timer generator e2e (docs/10 §3.4):
//! `qsv-cli cosigner-bridge-install` must produce a hardened unit pair that
//! matches the documented install recipe:
//!
//!   1. WRITE + VERIFY: passing --unit-dir writes both files and the
//!      command self-verifies (exit 0), with every required hardening
//!      directive present on disk.
//!   2. Unit content: ExecStart carries the real bridge invocation
//!      (--listen/--state-dir/--vault-id), ProtectSystem=strict, and
//!      ReadWritePaths is pinned to exactly the state dir.
//!   3. Timer content: the requested OnCalendar lands verbatim.
//!   4. STDOUT PREVIEW: without --unit-dir nothing is written; the full
//!      unit text goes to stdout so an operator can pipe it to systemctl.

use std::process::Command;

fn qsv_bin() -> &'static str {
    env!("CARGO_BIN_EXE_qsv-cli")
}

#[test]
fn cosigner_bridge_install_writes_and_verifies_hardened_units() {
    let base = std::env::temp_dir().join(format!("qsv-bridge-install-{}", std::process::id()));
    let state_dir = base.join("wt-state");
    let unit_dir = base.join("units");
    std::fs::create_dir_all(&state_dir).unwrap();
    // Seed a watchtower state file so the dir is a REAL state dir.
    std::fs::write(
        state_dir.join("watchtower-state.json"),
        r#"{ "tip": 820000, "vaults": { "qa-mirror": { "last_tip": 820000, "last_verdict": "clear", "idle_blocks": 10 } } }"#,
    )
    .unwrap();
    let state_abs = std::fs::canonicalize(&state_dir).unwrap();

    let out = Command::new(qsv_bin())
        .args([
            "cosigner-bridge-install",
            "--listen",
            "127.0.0.1:3334",
            "--state-dir",
        ])
        .arg(&state_dir)
        .args(["--vault-id", "test-vault-1", "--vault-id", "test-vault-2"])
        .args(["--unit-dir"])
        .arg(&unit_dir)
        .args([
            "--timer-calendar",
            "*-*-* *:00/5:00",
            "--unit-name",
            "qsv-cosigner-bridge",
        ])
        .output()
        .expect("run cosigner-bridge-install");
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 1. Both files exist and the command verified them.
    let svc_path = unit_dir.join("qsv-cosigner-bridge.service");
    let timer_path = unit_dir.join("qsv-cosigner-bridge.timer");
    let svc = std::fs::read_to_string(&svc_path).expect("service unit written");
    let timer = std::fs::read_to_string(&timer_path).expect("timer unit written");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("verified"),
        "self-verification banner missing: {stdout}"
    );
    assert!(
        stdout.contains(state_abs.to_str().unwrap()),
        "resolved state dir not echoed"
    );

    // 2. Service unit: real ExecStart + hardening directives.
    let exec_line = svc
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .expect("ExecStart present");
    assert!(exec_line.contains("qsv-cli cosigner-bridge"));
    assert!(exec_line.contains("--listen 127.0.0.1:3334"));
    assert!(exec_line.contains(&format!("--state-dir {}", state_abs.display())));
    assert!(exec_line.contains("--vault-id test-vault-1"));
    assert!(exec_line.contains("--vault-id test-vault-2"));
    assert!(svc.lines().any(|l| l == "ProtectSystem=strict"));
    assert!(svc.lines().any(|l| l == "NoNewPrivileges=yes"));
    assert!(svc.lines().any(|l| l == "PrivateTmp=yes"));
    assert!(svc.lines().any(|l| l == "ProtectHome=yes"));
    // Round 21: the notify trio — Type=simple would let systemd call a
    // deadlocked bridge "active" until the first client times out.
    assert!(
        svc.lines().any(|l| l == "Type=notify"),
        "unit must be Type=notify: {svc}"
    );
    assert!(
        svc.lines().any(|l| l == "NotifyAccess=main"),
        "unit must allow the main process to notify: {svc}"
    );
    assert!(
        svc.lines().any(|l| {
            l.strip_prefix("WatchdogSec=")
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|secs| secs >= 1)
        }),
        "unit must ask for a real WatchdogSec: {svc}"
    );
    assert!(
        !svc.lines().any(|l| l == "Type=simple"),
        "Type=simple defeats the whole notify round: {svc}"
    );
    // Round 22: reload reaches the RUNNING process — without ExecReload
    // `systemctl reload` is a silent no-op and a rotated secret never
    // moves (docs/10 §4.30).
    assert!(
        svc.lines()
            .any(|l| l == "ExecReload=/bin/kill -HUP $MAINPID"),
        "unit must route reload to SIGHUP: {svc}"
    );
    // Round 19 sandboxing: capability bounding, address families and the
    // kernel/personality/namespace surfaces are pinned — the unit carries
    // them VERBATIM (install-what-you-print covers the sandbox too).
    for directive in [
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
        "RestrictNamespaces=yes",
        "RestrictRealtime=yes",
        "RestrictSUIDSGID=yes",
        "LockPersonality=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
        "SystemCallArchitectures=native",
    ] {
        assert!(
            svc.lines().any(|l| l == directive),
            "hardened unit must carry {directive}: {svc}"
        );
    }
    assert!(
        svc.lines()
            .any(|l| l == format!("ReadWritePaths={}", state_abs.display())),
        "ReadWritePaths pinned to the state dir: {svc}"
    );
    assert!(svc.contains("WantedBy=multi-user.target"));

    // 3. Timer unit: OnCalendar verbatim + Persistent.
    assert!(timer.contains("OnCalendar=*-*-* *:00/5:00"));
    assert!(timer.contains("Persistent=yes"));
    assert!(timer.contains("WantedBy=timers.target"));

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn cosigner_bridge_install_stdout_preview_writes_nothing() {
    let base = std::env::temp_dir().join(format!("qsv-bridge-preview-{}", std::process::id()));
    let state_dir = base.join("wt-state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let sentinel = base.join("sentinel-check");
    std::fs::create_dir_all(&sentinel).unwrap();

    // Run with cwd = the sentinel dir: preview mode must write NOTHING into
    // it (the demo_vault() default path is pure — no disk writes). No
    // --unit-dir passed at all here.
    let out = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--state-dir"])
        .arg(&state_dir)
        // No --vault-id: ExecStart bakes the demo vault address default.
        .current_dir(&sentinel)
        .output()
        .expect("run preview");

    // Preview mode never writes: --unit-dir pointing at an empty dir stays
    // empty (the banner says so).
    assert!(
        out.status.success(),
        "preview failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[Unit]"));
    assert!(stdout.contains("ExecStart="));
    assert!(stdout.contains("ProtectSystem=strict"));
    assert!(stdout.contains("Type=notify"));
    assert!(stdout.contains("WatchdogSec="));
    assert!(stdout.contains("ExecReload=/bin/kill -HUP $MAINPID"));
    assert!(stdout.contains("cosigner-bridge"));
    assert!(
        stdout.contains("stdout preview"),
        "preview banner missing: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "--state-dir {}",
            std::fs::canonicalize(&state_dir).unwrap().display()
        )),
        "ExecStart preview must carry the resolved state dir: {stdout}"
    );
    assert!(
        std::fs::read_dir(&sentinel).unwrap().next().is_none(),
        "preview mode must not write any files"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// Round 17–18: the Round 14–18 surface (TLS pair, client CA, per-vault
/// rate limit, metrics scrape token) bakes into ExecStart VERBATIM
/// (absolute TLS paths) and is re-verified on disk — install-what-you-
/// print covers the WHOLE bridge invocation, so the unit boots the exact
/// transport and scrape gate the operator previewed. A rate-limit spec
/// the bridge itself would exit 2 on — and a token that would break the
/// ExecStart word split — are refused fail-closed (exit 1, no unit
/// written).
#[test]
fn cosigner_bridge_install_bakes_tls_and_rate_limit_flags_into_execstart() {
    let base = std::env::temp_dir().join(format!("qsv-bridge-install-tls-{}", std::process::id()));
    let state_dir = base.join("wt-state");
    let unit_dir = base.join("units");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(
        state_dir.join("watchtower-state.json"),
        r#"{ "tip": 820000, "vaults": { "qa-mirror": { "last_tip": 820000, "last_verdict": "clear", "idle_blocks": 10 } } }"#,
    )
    .unwrap();

    // Real PEM material (rcgen, offline): the installer bakes ABSOLUTE
    // paths — systemd needs them anyway.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = base.join("cert.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    let key_path = base.join("key.pem");
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
    let ca_path = base.join("client-ca.pem");
    std::fs::write(&ca_path, cert.cert.pem()).unwrap();

    let out = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--listen", "127.0.0.1:3334"])
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--vault-id", "test-vault-1"])
        .args(["--tls-cert"])
        .arg(&cert_path)
        .args(["--tls-key"])
        .arg(&key_path)
        .args(["--tls-client-ca"])
        .arg(&ca_path)
        .args(["--rate-limit", "60:0.5"])
        .args(["--metrics-token", "b4ked-scrape"])
        .args(["--frame-timeout-ms", "2500"])
        .args(["--drain-timeout-ms", "4000"])
        .args(["--max-inflight", "32"])
        .args(["--unit-dir"])
        .arg(&unit_dir)
        .output()
        .expect("run tls install");
    assert!(
        out.status.success(),
        "tls install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let svc = std::fs::read_to_string(unit_dir.join("qsv-cosigner-bridge.service"))
        .expect("service unit written");
    let exec_line = svc
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .expect("ExecStart present");
    let cert_abs = std::fs::canonicalize(&cert_path).unwrap();
    let key_abs = std::fs::canonicalize(&key_path).unwrap();
    let ca_abs = std::fs::canonicalize(&ca_path).unwrap();
    assert!(
        exec_line.contains(&format!("--tls-cert {}", cert_abs.display())),
        "baked --tls-cert must be the ABSOLUTE path: {exec_line}"
    );
    assert!(exec_line.contains(&format!("--tls-key {}", key_abs.display())));
    assert!(exec_line.contains(&format!("--tls-client-ca {}", ca_abs.display())));
    assert!(
        exec_line.contains("--rate-limit 60:0.5"),
        "rate limit baked verbatim: {exec_line}"
    );
    assert!(
        exec_line.contains("--metrics-token b4ked-scrape"),
        "scrape token baked verbatim: {exec_line}"
    );
    // Round 22: the serve clocks the OPERATOR chose travel with the unit
    // (not whatever the binary's defaults happen to be at deploy time).
    assert!(
        exec_line.contains("--frame-timeout-ms 2500"),
        "frame timeout baked: {exec_line}"
    );
    assert!(
        exec_line.contains("--drain-timeout-ms 4000"),
        "drain deadline baked: {exec_line}"
    );
    // Round 23: the worker cap is a clock too — the unit must STATE it
    // (docs/10 §4.22/§4.35) instead of inheriting the binary default.
    assert!(
        exec_line.contains("--max-inflight 32"),
        "worker cap baked: {exec_line}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("8 baked flag(s)"),
        "verification banner counts the baked flags: {stdout}"
    );

    // FAIL-CLOSED: a spec the bridge would exit 2 on must never reach the
    // unit file — the installer refuses it (exit 1) and writes NOTHING.
    let guard_dir = base.join("guard-units");
    std::fs::create_dir_all(&guard_dir).unwrap();
    let bad = Command::new(qsv_bin())
        .args(["cosigner-bridge-install"])
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--rate-limit", "not-a-spec"])
        .args(["--unit-dir"])
        .arg(&guard_dir)
        .output()
        .expect("run bad-spec install");
    assert_eq!(
        bad.status.code(),
        Some(1),
        "malformed rate-limit spec must fail the install"
    );
    assert!(
        String::from_utf8_lossy(&bad.stderr).contains("rate-limit"),
        "{}",
        String::from_utf8_lossy(&bad.stderr)
    );
    assert!(
        std::fs::read_dir(&guard_dir).unwrap().next().is_none(),
        "a failed install must not leave units behind"
    );

    // ROUND 18: a token with WHITESPACE would break the ExecStart word
    // split — refused before anything is written (fail-closed, exit 1).
    let guard2 = base.join("guard2-units");
    std::fs::create_dir_all(&guard2).unwrap();
    let bad_tok = Command::new(qsv_bin())
        .args(["cosigner-bridge-install"])
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--metrics-token", "has space"])
        .args(["--unit-dir"])
        .arg(&guard2)
        .output()
        .expect("run bad-token install");
    assert_eq!(
        bad_tok.status.code(),
        Some(1),
        "a whitespace scrape token must fail the install"
    );
    assert!(
        String::from_utf8_lossy(&bad_tok.stderr).contains("metrics-token"),
        "{}",
        String::from_utf8_lossy(&bad_tok.stderr)
    );
    assert!(
        std::fs::read_dir(&guard2).unwrap().next().is_none(),
        "a failed install must not leave units behind"
    );

    // Round 20: a unit that CANNOT boot is worse than no unit. The
    // installer re-runs the SAME transport + scrape gates the bridge
    // boot performs, BEFORE writing anything — so an off-loopback bind
    // without TLS material or without a scrape token never reaches disk.
    let guard3 = base.join("guard3");
    std::fs::create_dir_all(&guard3).unwrap();
    let no_tls = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--listen", "0.0.0.0:3334"])
        .arg("--state-dir")
        .arg(&state_dir)
        .args(["--unit-dir"])
        .arg(&guard3)
        .output()
        .expect("run off-loopback install");
    assert_eq!(
        no_tls.status.code(),
        Some(1),
        "an off-loopback unit without TLS must not be generated"
    );
    assert!(
        String::from_utf8_lossy(&no_tls.stderr).contains("transport policy"),
        "{}",
        String::from_utf8_lossy(&no_tls.stderr)
    );
    assert!(
        std::fs::read_dir(&guard3).unwrap().next().is_none(),
        "a refused install must not leave units behind"
    );

    // TLS material present, but the scrape gate unarmed off loopback.
    let cert_pem = base.join("cert.pem");
    let key_pem = base.join("key.pem");
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .unwrap();
    std::fs::write(&cert_pem, cert.cert.pem()).unwrap();
    std::fs::write(&key_pem, cert.key_pair.serialize_pem()).unwrap();
    let guard4 = base.join("guard4");
    std::fs::create_dir_all(&guard4).unwrap();
    let no_token = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--listen", "0.0.0.0:3334"])
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("--tls-cert")
        .arg(&cert_pem)
        .arg("--tls-key")
        .arg(&key_pem)
        .args(["--unit-dir"])
        .arg(&guard4)
        .output()
        .expect("run off-loopback install without a token");
    assert_eq!(
        no_token.status.code(),
        Some(1),
        "an off-loopback unit with an open /metrics must not be generated"
    );
    let err = String::from_utf8_lossy(&no_token.stderr);
    assert!(err.contains("scrape policy"), "{err}");
    assert!(
        err.contains("--metrics-token"),
        "the message names the fix: {err}"
    );
    assert!(
        std::fs::read_dir(&guard4).unwrap().next().is_none(),
        "a refused install must not leave units behind"
    );

    // …with the token armed, the SAME off-loopback bind generates fine and
    // the unit carries both the TLS pair and the scrape token.
    let guard5 = base.join("guard5");
    std::fs::create_dir_all(&guard5).unwrap();
    let armed = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--listen", "0.0.0.0:3334"])
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("--tls-cert")
        .arg(&cert_pem)
        .arg("--tls-key")
        .arg(&key_pem)
        .args(["--metrics-token", "s3cr3t"])
        .args(["--unit-dir"])
        .arg(&guard5)
        .output()
        .expect("run armed off-loopback install");
    assert!(
        armed.status.success(),
        "an armed off-loopback unit must generate: {}",
        String::from_utf8_lossy(&armed.stderr)
    );
    let unit = std::fs::read_to_string(guard5.join("qsv-cosigner-bridge.service"))
        .expect("armed service unit written");
    assert!(unit.contains("--listen 0.0.0.0:3334"), "{unit}");
    assert!(unit.contains("--metrics-token s3cr3t"), "{unit}");
    assert!(unit.contains("--tls-cert"), "{unit}");

    let _ = std::fs::remove_dir_all(&base);
}

/// TOKEN-FILE install (docs/10 §4.27, Round 21): the unit must carry the
/// PATH of the scrape token — never the VALUE (an ExecStart secret is a
/// `systemctl cat` secret, a /etc/systemd secret, a git secret). Same
/// preview → read-back rule as everything else, plus the negative half:
/// a loose token file stops the install before a single byte is written,
/// and naming BOTH token sources is exit 2.
#[cfg(unix)]
#[test]
fn cosigner_bridge_install_bakes_the_token_file_path_never_the_value() {
    use std::os::unix::fs::PermissionsExt;

    let base = std::env::temp_dir().join(format!("qsv-install-tokenfile-{}", std::process::id()));
    let state_dir = base.join("wt-state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let token_path = base.join("scrape.token");
    std::fs::write(&token_path, "sekrit-file-token\n").unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let token_abs = std::fs::canonicalize(&token_path).unwrap();

    let run = |extra: &[&std::ffi::OsStr]| {
        Command::new(qsv_bin())
            .args(["cosigner-bridge-install"])
            .arg("--state-dir")
            .arg(&state_dir)
            .args(["--vault-id", "test-vault-1"])
            .arg("--metrics-token-file")
            .arg(&token_path)
            .args(extra)
            .output()
            .expect("run token-file install")
    };

    // 1. Preview: the CANONICALIZED path bakes into ExecStart, the VALUE
    //    appears nowhere in the printed unit.
    let out = run(&[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "token-file install must preview: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(&format!("--metrics-token-file {}", token_abs.display())),
        "the canonicalized path must bake: {stdout}"
    );
    assert!(
        !stdout.contains("sekrit-file-token"),
        "the token VALUE must never reach the unit: {stdout}"
    );

    // 2. A group/other-readable file stops the install (fail closed, the
    //    fix named) — a token file the whole box can open is not storage.
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = run(&[]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "loose file must refuse: {err}");
    assert!(err.contains("chmod 600"), "the fix must be named: {err}");

    // 3. Both token sources at once = usage confusion → exit 2.
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = run(&[
        std::ffi::OsStr::new("--metrics-token"),
        std::ffi::OsStr::new("flag-token"),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "two token sources = usage error: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// SANDBOX REACHABILITY (docs/10 §4.40, Round 24): the generated unit
/// runs with `ProtectHome=yes`, so a token file under a home tree is
/// UNREADABLE by the service even though the operator reads it every day.
/// Install must refuse before writing a unit whose bridge can never
/// boot — install-what-you-print has to mean print-what-can-run.
#[test]
fn install_refuses_a_token_file_the_unit_sandbox_cannot_read() {
    use std::os::unix::fs::PermissionsExt;

    // Stage the file under the REAL home tree (the same tree the unit
    // makes inaccessible). Any other machine shape skips, like the
    // node-gated suites do.
    let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) else {
        eprintln!("SKIP: no HOME to stage a protected-path token file under");
        return;
    };
    let canonical_home = std::fs::canonicalize(&home).unwrap_or_else(|_| home.clone());
    let text = canonical_home.to_string_lossy().to_string();
    let protected = ["/home", "/root", "/run/user"]
        .iter()
        .any(|root| text == *root || text.strip_prefix(root).is_some_and(|r| r.starts_with('/')));
    if !protected {
        eprintln!("SKIP: HOME ({text}) is not a ProtectHome tree on this machine");
        return;
    }

    let base = canonical_home.join(format!("qsv-install-sandbox-{}", std::process::id()));
    let state_dir =
        std::env::temp_dir().join(format!("qsv-install-sandbox-wt-{}", std::process::id()));
    let token_path = base.join("scrape.token");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(&token_path, "sekrit-sandbox\n").unwrap();
    std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let out = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--state-dir"])
        .arg(&state_dir)
        .args(["--vault-id", "test-vault-1", "--metrics-token-file"])
        .arg(&token_path)
        .output()
        .expect("run install");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        out.status.code(),
        Some(1),
        "a unit that can never boot must be refused: {stdout}{stderr}"
    );
    assert!(
        stderr.contains("ProtectHome=yes"),
        "the reason must name the sandbox that blocks it: {stderr}"
    );
    assert!(
        stderr.contains("--metrics-token-file"),
        "the flag must be named: {stderr}"
    );
    assert!(
        !stdout.contains("ExecStart=") && !stdout.contains("[Service]"),
        "no unit body may be previewed as workable: {stdout}"
    );

    // The same file OUTSIDE the home tree installs fine — the check
    // refuses a location, never the secret.
    let outside = state_dir.join("scrape.token");
    std::fs::write(&outside, "sekrit-sandbox\n").unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ok = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--state-dir"])
        .arg(&state_dir)
        .args(["--vault-id", "test-vault-1", "--metrics-token-file"])
        .arg(&outside)
        .output()
        .expect("run install");
    assert!(
        ok.status.success(),
        "a reachable token file installs: {}",
        String::from_utf8_lossy(&ok.stderr)
    );

    let _ = std::fs::remove_dir_all(&base);
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// k-of-n MIRROR SET (docs/10 §4.60): every `--watchtower` dir lands in
/// ExecStart as an ABSOLUTE path together with the OPERATIVE quorum, and
/// the SAME walls the bridge boot enforces refuse a bad configuration
/// BEFORE any file is written — while a mirror whose state can't parse
/// would fail the generated unit at boot, so the installer refuses it
/// too (install-what-you-print starts with print-what-can-run).
#[test]
fn install_bakes_the_k_of_n_mirrors_and_walls_bad_quorums() {
    let base = std::env::temp_dir().join(format!("qsv-bridge-install-kofn-{}", std::process::id()));
    let state_dir = base.join("wt-state");
    let m2 = base.join("wt-2");
    for d in [&state_dir, &m2] {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(
            d.join("watchtower-state.json"),
            r#"{ "tip": 820000, "vaults": { "qa-mirror": { "last_tip": 820000, "last_verdict": "clear", "idle_blocks": 10 } } }"#,
        )
        .unwrap();
    }

    // 1. n=2 without an explicit k → the SAME exit-2 wall as the bridge
    //    boot, and NOTHING is written.
    let guard = base.join("guard-units");
    std::fs::create_dir_all(&guard).unwrap();
    let bad = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--state-dir"])
        .arg(&state_dir)
        .args(["--watchtower"])
        .arg(&m2)
        .args(["--unit-dir"])
        .arg(&guard)
        .output()
        .expect("run install");
    let err = String::from_utf8_lossy(&bad.stderr).to_string();
    assert_eq!(
        bad.status.code(),
        Some(2),
        "two mirrors need an explicit quorum: {err}"
    );
    assert!(
        err.contains("--watchtower-quorum is required with exactly two mirrors"),
        "{err}"
    );
    assert!(
        std::fs::read_dir(&guard).unwrap().next().is_none(),
        "a refused install writes nothing"
    );

    // 2. A mirror with NO state file would die at the unit's first boot →
    //    refused (exit 1) before anything is written.
    let m_missing = base.join("wt-missing");
    std::fs::create_dir_all(&m_missing).unwrap();
    let guard2 = base.join("guard2-units");
    std::fs::create_dir_all(&guard2).unwrap();
    let unreadable = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--state-dir"])
        .arg(&state_dir)
        .args(["--watchtower"])
        .arg(&m_missing)
        .args(["--watchtower-quorum", "2"])
        .args(["--unit-dir"])
        .arg(&guard2)
        .output()
        .expect("run install");
    let err = String::from_utf8_lossy(&unreadable.stderr).to_string();
    assert_eq!(
        unreadable.status.code(),
        Some(1),
        "an unreadable mirror must refuse the install: {err}"
    );
    assert!(
        err.contains("watchtower-state.json"),
        "the mirror is named: {err}"
    );
    assert!(
        std::fs::read_dir(&guard2).unwrap().next().is_none(),
        "a refused install writes nothing"
    );

    // 3. A valid pair bakes BOTH the absolute mirror path and the quorum
    //    verbatim, and the preview names the resolved merge.
    let unit_dir = base.join("units");
    let ok = Command::new(qsv_bin())
        .args(["cosigner-bridge-install", "--state-dir"])
        .arg(&state_dir)
        .args(["--watchtower"])
        .arg(&m2)
        .args(["--watchtower-quorum", "2"])
        .args(["--unit-dir"])
        .arg(&unit_dir)
        .output()
        .expect("run install");
    assert!(
        ok.status.success(),
        "two mirrors with explicit k install: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let svc = std::fs::read_to_string(unit_dir.join("qsv-cosigner-bridge.service"))
        .expect("service unit written");
    let exec_line = svc
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .expect("ExecStart present");
    let m2_abs = std::fs::canonicalize(&m2).unwrap();
    assert!(
        exec_line.contains(&format!("--watchtower {}", m2_abs.display())),
        "baked mirror path is ABSOLUTE: {exec_line}"
    );
    assert!(
        exec_line.contains("--watchtower-quorum 2"),
        "the operative quorum travels verbatim: {exec_line}"
    );
    let stdout = String::from_utf8_lossy(&ok.stdout).to_string();
    assert!(
        stdout.contains("2 mirror(s) · quorum 2"),
        "the resolved merge is previewed: {stdout}"
    );

    let _ = std::fs::remove_dir_all(&base);
}
