//! End-to-end proof of the FROST + SLIP-0039 inheritance wizard (docs/04 §4):
//!
//!   setup (2-of-3, printed SLIP-0039 shares) → recover-check (backup drill)
//!   → heir-round-1 ×2 → build-sign-pkg (coordinator) → heir-round-2 ×2
//!   → finish (aggregate + plain-Schnorr verification under the GROUP key).
//!
//! Also proves the fail-closed edges: below-threshold aggregation, a tampered
//! commitment package and a wrong passphrase drill all exit 1. The wizard
//! runs the REAL binary; only the cryptographic core is qsv-core.

use std::process::Command;

fn qsv(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_qsv-cli"))
        .args(args)
        .output()
        .expect("qsv-cli binary must run")
}

fn stdout(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).to_string()
}

/// Extracts a hex identifier from the setup output ("id <64 hex>").`
fn ids_from_setup(setup_out: &str) -> Vec<String> {
    setup_out
        .lines()
        .filter_map(|l| {
            let idx = l.find("(id ")?;
            let rest = &l[idx + 4..];
            let end = rest.find(')')?;
            Some(rest[..end].to_string())
        })
        .collect()
}

#[test]
fn frost_wizard_full_ceremony_and_backup_drill() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();

    // 1. SETUP: 2-of-3 heirs, 2-of-3 SLIP-0039 shares per heir.
    let setup = qsv(&[
        "inheritance-kit",
        "setup",
        "--threshold",
        "2",
        "--heir",
        "heir-1 (big kid)",
        "--heir",
        "heir-2 (little kid)",
        "--heir",
        "notary",
        "--slip-threshold",
        "2",
        "--slip-shares",
        "3",
        "--passphrase",
        "estate drill",
        "--dir",
        d,
    ]);
    let s = stdout(&setup);
    assert!(
        setup.status.success(),
        "setup failed: {s}{}",
        stderr(&setup)
    );
    assert!(s.contains("2-of-3"), "threshold banner missing: {s}");
    assert!(s.contains("group key:"), "group key missing: {s}");
    let ids = ids_from_setup(&s);
    assert_eq!(ids.len(), 3, "three heir ids expected: {s}");
    assert!(
        s.contains("SLIP-0039 1/3"),
        "printed mnemonics missing: {s}"
    );

    // Artifacts on disk: public package + 3 private deals.
    let public = dir.path().join("public-package.txt");
    assert!(public.is_file());
    let mut deals = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let p = dir.path().join(format!("heir-{i:02}-{id}-deal.txt"));
        assert!(p.is_file(), "deal file missing: {}", p.display());
        deals.push(p);
    }

    // 2. BACKUP DRILL: 2 of the printed mnemonics restore heir 0's deal.
    //    Mnemonics are re-typed from the letter — parse them from stdout.
    let mut mnemonics = Vec::new();
    let mut grab = false;
    for line in s.lines() {
        if line.contains(&format!("heir-{:02}", 0)) {
            grab = true;
        } else if line.trim_start().starts_with("heir ") {
            grab = false;
        }
        if grab {
            if let Some(idx) = line.find("SLIP-0039 ") {
                let m = line[idx + "SLIP-0039 X/3: ".len().saturating_sub(4)..]
                    .split_once(": ")
                    .map(|(_, w)| w.trim().to_string());
                if let Some(m) = m {
                    if m.split_whitespace().count() >= 20 {
                        mnemonics.push(m);
                    }
                }
            }
        }
    }
    assert!(mnemonics.len() >= 2, "two printed mnemonics expected");
    let drill = qsv(&[
        "inheritance-kit",
        "recover-check",
        "--deal",
        deals[0].to_str().unwrap(),
        "--share",
        &mnemonics[0],
        "--share",
        &mnemonics[1],
        "--passphrase",
        "estate drill",
    ]);
    assert!(
        drill.status.success(),
        "backup drill must pass: {}{}",
        stdout(&drill),
        stderr(&drill)
    );
    // Wrong passphrase must fail closed.
    let bad = qsv(&[
        "inheritance-kit",
        "recover-check",
        "--deal",
        deals[0].to_str().unwrap(),
        "--share",
        &mnemonics[0],
        "--share",
        &mnemonics[1],
        "--passphrase",
        "wrong",
    ]);
    assert_eq!(bad.status.code(), Some(1), "wrong passphrase must exit 1");

    // 3. ROUND 1: heirs 0 and 2 commit nonces (any 2 of 3).
    let r1dir = dir.path().join("r1");
    let _ = std::fs::create_dir_all(&r1dir);
    let mut r1_files = Vec::new();
    for &i in &[0usize, 2usize] {
        let out = qsv(&[
            "inheritance-kit",
            "heir-round1",
            "--deal",
            deals[i].to_str().unwrap(),
            "--public",
            public.to_str().unwrap(),
            "--dir",
            r1dir.to_str().unwrap(),
        ]);
        let o = stdout(&out);
        assert!(
            out.status.success(),
            "heir round 1 failed: {o}{}",
            stderr(&out)
        );
        let id = &ids[i];
        r1_files.push((id.clone(), r1dir.join(format!("heir-{id}-r1.txt"))));
        assert!(r1_files.last().unwrap().1.is_file());
    }

    // 4. COORDINATOR builds the sign package over a fixed message.
    let msg = "1111111111111111111111111111111111111111111111111111111111111111";
    let pkg_path = dir.path().join("sign-package.txt");
    let mut args: Vec<String> = vec![
        "inheritance-kit".into(),
        "build-sign-pkg".into(),
        "--message".into(),
        msg.into(),
        "--out".into(),
        pkg_path.to_string_lossy().to_string(),
    ];
    for (id, f) in &r1_files {
        args.push("--commitment".into());
        args.push(format!("{id}:{}", f.display()));
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let build = qsv(&arg_refs);
    assert!(
        build.status.success(),
        "build-sign-pkg failed: {}{}",
        stdout(&build),
        stderr(&build)
    );
    assert!(pkg_path.is_file());

    // 4b. The WRITE wall: an --out whose parent directory does not exist
    //     fails closed with the kit_write error — the package is never
    //     half-written somewhere the operator did not ask for.
    let mut bad_args = args.clone();
    let oi = bad_args.iter().position(|a| a == "--out").unwrap();
    bad_args[oi + 1] = dir
        .path()
        .join("no-such-subdir")
        .join("pkg.txt")
        .to_string_lossy()
        .to_string();
    let bad_refs: Vec<&str> = bad_args.iter().map(String::as_str).collect();
    let bad = qsv(&bad_refs);
    assert!(
        !bad.status.success(),
        "an unwritable --out must fail closed: {}{}",
        stdout(&bad),
        stderr(&bad)
    );
    assert!(
        stderr(&bad).contains("cannot write"),
        "the write wall must name the path: {}",
        stderr(&bad)
    );

    // 5. ROUND 2: the same two heirs sign.
    let r2dir = dir.path().join("r2");
    let _ = std::fs::create_dir_all(&r2dir);
    let mut r2_files = Vec::new();
    for &i in &[0usize, 2usize] {
        let heir_id = &ids[i];
        let out = qsv(&[
            "inheritance-kit",
            "heir-round2",
            "--deal",
            deals[i].to_str().unwrap(),
            "--public",
            public.to_str().unwrap(),
            "--nonce",
            r1dir
                .join(format!("heir-{heir_id}-nonce.txt"))
                .to_str()
                .unwrap(),
            "--pkg",
            pkg_path.to_str().unwrap(),
            "--dir",
            r2dir.to_str().unwrap(),
        ]);
        let o = stdout(&out);
        assert!(
            out.status.success(),
            "heir round 2 failed: {o}{}",
            stderr(&out)
        );
        r2_files.push((
            heir_id.clone(),
            r2dir.join(format!("heir-{heir_id}-r2.txt")),
        ));
    }

    // 6. FINISH: aggregate → plain-Schnorr verify under the GROUP key.
    let mut args: Vec<String> = vec![
        "inheritance-kit".into(),
        "finish".into(),
        "--pkg".into(),
        pkg_path.to_string_lossy().to_string(),
        "--public".into(),
        public.to_string_lossy().to_string(),
    ];
    for (id, f) in &r2_files {
        args.push("--share".into());
        args.push(format!("{id}:{}", f.display()));
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let finish = qsv(&arg_refs);
    let f = stdout(&finish);
    assert!(
        finish.status.success(),
        "finish failed: {f}{}",
        stderr(&finish)
    );
    assert!(f.contains("verifies as PLAIN Schnorr"), "final banner: {f}");
    assert!(f.lines().any(|l| l.starts_with("  BIP-340 sig:  ")));

    // 7. FAIL-CLOSED: below-threshold aggregation (1 share) exits 1.
    let args: Vec<String> = vec![
        "inheritance-kit".into(),
        "finish".into(),
        "--pkg".into(),
        pkg_path.to_string_lossy().to_string(),
        "--public".into(),
        public.to_string_lossy().to_string(),
        "--share".into(),
        format!("{}:{}", r2_files[0].0, r2_files[0].1.display()),
    ];
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let short = qsv(&arg_refs);
    assert_eq!(short.status.code(), Some(1), "one share must not aggregate");

    // 8. FAIL-CLOSED: a tampered commitment poisons the sign package.
    let tampered = dir.path().join("tampered-r1.txt");
    std::fs::write(&tampered, "QSV_FROST_SHARE_v1QUJDRA==").unwrap();
    let poison_out = dir.path().join("poison.txt");
    let args = [
        "inheritance-kit",
        "build-sign-pkg",
        "--message",
        msg,
        "--out",
        poison_out.to_str().unwrap(),
        "--commitment",
        &format!("{}:{}", ids[0], tampered.to_str().unwrap()),
        "--commitment",
        &format!("{}:{}", ids[1], r1_files[1].1.to_str().unwrap()),
    ];
    let poison = qsv(&args);
    assert_eq!(
        poison.status.code(),
        Some(1),
        "tampered commitment must exit 1"
    );
}

/// Round 33 — DKG mode: the SAME ceremony contract (files, rounds, final
/// plain-Schnorr banner) driven end-to-end from a dealer-less setup.
#[test]
fn frost_dkg_setup_runs_the_same_ceremony_without_a_dealer() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path().to_str().unwrap();

    // 1. SETUP --dkg: 2-of-3 heirs, joint three-round key generation.
    let setup = qsv(&[
        "inheritance-kit",
        "setup",
        "--threshold",
        "2",
        "--heir",
        "heir-1 (big kid)",
        "--heir",
        "heir-2 (little kid)",
        "--heir",
        "notary",
        "--dkg",
        "--dir",
        d,
    ]);
    let s = stdout(&setup);
    assert!(
        setup.status.success(),
        "dkg setup failed: {s}{}",
        stderr(&setup)
    );
    assert!(s.contains("DKG"), "DKG banner missing: {s}");
    assert!(s.contains("2-of-3"), "threshold banner missing: {s}");
    let ids = ids_from_setup(&s);
    assert_eq!(ids.len(), 3, "three heir ids expected: {s}");

    // Identical artifact contract: public package + 3 private deals.
    let public = dir.path().join("public-package.txt");
    assert!(public.is_file());
    let mut deals = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let p = dir.path().join(format!("heir-{i:02}-{id}-deal.txt"));
        assert!(p.is_file(), "deal file missing: {}", p.display());
        deals.push(p);
    }

    // 2..4. The REAL signing flow on DKG shares: r1 ×2 → package → r2 ×2.
    let r1dir = dir.path().join("r1");
    let _ = std::fs::create_dir_all(&r1dir);
    let mut r1_files = Vec::new();
    for &i in &[0usize, 2usize] {
        let out = qsv(&[
            "inheritance-kit",
            "heir-round1",
            "--deal",
            deals[i].to_str().unwrap(),
            "--public",
            public.to_str().unwrap(),
            "--dir",
            r1dir.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "heir round 1 failed: {}{}",
            stdout(&out),
            stderr(&out)
        );
        r1_files.push((
            ids[i].clone(),
            r1dir.join(format!("heir-{}-r1.txt", ids[i])),
        ));
    }

    let msg = "2222222222222222222222222222222222222222222222222222222222222222";
    let pkg_path = dir.path().join("sign-package.txt");
    let mut args: Vec<String> = vec![
        "inheritance-kit".into(),
        "build-sign-pkg".into(),
        "--message".into(),
        msg.into(),
        "--out".into(),
        pkg_path.to_string_lossy().to_string(),
    ];
    for (id, f) in &r1_files {
        args.push("--commitment".into());
        args.push(format!("{id}:{}", f.display()));
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let build = qsv(&arg_refs);
    assert!(
        build.status.success(),
        "build-sign-pkg failed: {}{}",
        stdout(&build),
        stderr(&build)
    );

    let r2dir = dir.path().join("r2");
    let _ = std::fs::create_dir_all(&r2dir);
    let mut r2_files = Vec::new();
    for &i in &[0usize, 2usize] {
        let heir_id = &ids[i];
        let out = qsv(&[
            "inheritance-kit",
            "heir-round2",
            "--deal",
            deals[i].to_str().unwrap(),
            "--public",
            public.to_str().unwrap(),
            "--nonce",
            r1dir
                .join(format!("heir-{heir_id}-nonce.txt"))
                .to_str()
                .unwrap(),
            "--pkg",
            pkg_path.to_str().unwrap(),
            "--dir",
            r2dir.to_str().unwrap(),
        ]);
        assert!(
            out.status.success(),
            "heir round 2 failed: {}{}",
            stdout(&out),
            stderr(&out)
        );
        r2_files.push((
            heir_id.clone(),
            r2dir.join(format!("heir-{heir_id}-r2.txt")),
        ));
    }

    // 5. FINISH: aggregate → plain-Schnorr verify under the GROUP key.
    let mut args: Vec<String> = vec![
        "inheritance-kit".into(),
        "finish".into(),
        "--pkg".into(),
        pkg_path.to_string_lossy().to_string(),
        "--public".into(),
        public.to_string_lossy().to_string(),
    ];
    for (id, f) in &r2_files {
        args.push("--share".into());
        args.push(format!("{id}:{}", f.display()));
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let finish = qsv(&arg_refs);
    let f = stdout(&finish);
    assert!(
        finish.status.success(),
        "finish failed: {f}{}",
        stderr(&finish)
    );
    assert!(f.contains("verifies as PLAIN Schnorr"), "final banner: {f}");
}
