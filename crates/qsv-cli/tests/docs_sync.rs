//! Documentation walls for the single English edition (Round 40).
//!
//! The published tree is English-only: `docs/NN_*.md` are the 11
//! specification modules and `docs/README.md` indexes them. Any drift fails
//! the build — the same discipline the protocol code has.
//!
//! `qsv-cli docs-audit` (`qsv_core::docs`) is the REPORT form of these same
//! walls: the test is the wall, the command is the explanation.

use std::path::{Path, PathBuf};

use qsv_core::bip360::{parse_snapshot, SNAPSHOT_BEGIN, SNAPSHOT_END};
use qsv_core::docs::turkish_markers;

fn docs_dir() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs"))
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

/// The 11 module numbers the library must cover, once each.
const MODULES: [&str; 11] = [
    "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11",
];

/// The one `NN_*.md` file for a module number.
fn module_path(docs: &Path, module: &str) -> PathBuf {
    let prefix = format!("{module}_");
    let mut hits: Vec<PathBuf> = std::fs::read_dir(docs)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", docs.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with(&prefix) && n.ends_with(".md"))
                .unwrap_or(false)
        })
        .collect();
    hits.sort();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one module {module} in {}",
        docs.display()
    );
    hits.remove(0)
}

/// Leading section numbers of every `## ` heading, in order.
fn section_numbers(doc: &str) -> Vec<String> {
    doc.lines()
        .filter_map(|l| l.strip_prefix("## "))
        .filter_map(|rest| {
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if num.is_empty() {
                None
            } else {
                Some(num.trim_end_matches('.').to_string())
            }
        })
        .collect()
}

/// Leading section numbers of every `### ` subheading (`### 4.6.` → "4.6").
fn subsection_numbers(doc: &str) -> Vec<String> {
    doc.lines()
        .filter_map(|l| l.strip_prefix("### "))
        .filter_map(|rest| {
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if num.is_empty() {
                None
            } else {
                Some(num.trim_end_matches('.').to_string())
            }
        })
        .collect()
}

/// `"4.63"` → `[4, 63]`, for ordered comparison.
fn num_key(number: &str) -> Vec<u32> {
    number
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

/// Every relative FILE link in a document: fence-aware, external URLs and
/// pure `#anchor` targets skipped (the report audits anchors).
fn relative_links(doc: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut in_fence = false;
    for line in doc.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let mut rest = line;
        while let Some(pos) = rest.find("](") {
            let after = &rest[pos + 2..];
            let Some(end) = after.find(')') else { break };
            let target = after[..end].trim();
            rest = &after[end + 1..];
            if target.is_empty()
                || target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
                || target.starts_with("//")
                || target.starts_with('#')
            {
                continue;
            }
            targets.push(target.split('#').next().unwrap_or(target).to_string());
        }
    }
    targets
}

/// `docs/` holds exactly the 11 numbered modules, once each — no gaps, no
/// duplicates, no orphans.
#[test]
fn every_module_01_through_11_is_present_exactly_once() {
    let docs = docs_dir();
    let mut numbers: Vec<String> = std::fs::read_dir(&docs)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", docs.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(str::to_string))
        .filter(|n| n.ends_with(".md"))
        .filter_map(|n| {
            let digits: String = n.chars().take_while(|c| c.is_ascii_digit()).collect();
            (digits.len() == 2 && n[2..].starts_with('_')).then_some(digits)
        })
        .collect();
    numbers.sort();
    assert_eq!(
        numbers,
        MODULES.map(str::to_string).to_vec(),
        "the docs directory must hold modules 01..11 exactly once (gaps, duplicates and \
         non-module files all show up here)"
    );
}

/// Titles declare the language they are actually written in, and the module
/// they belong to (module 11 shouts `# MODULE 11` — case-insensitive).
#[test]
fn every_module_title_is_english_and_numbered() {
    let docs = docs_dir();
    for m in MODULES {
        let path = module_path(&docs, m);
        let doc = read(&path);
        let first = doc
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("");
        assert!(
            first.to_lowercase().starts_with(&format!("# module {m}")),
            "{} does not open with `# Module {m}`: {first}",
            path.display()
        );
    }
}

/// Section numbers strictly increase down every module — the guide is read
/// top to bottom, and a §4.9 after §4.10 is a reordering bug, not a style.
#[test]
fn section_numbers_strictly_increase() {
    let docs = docs_dir();
    for m in MODULES {
        let path = module_path(&docs, m);
        let numbers = section_numbers(&read(&path));
        for pair in numbers.windows(2) {
            assert!(
                num_key(&pair[1]) > num_key(&pair[0]),
                "{}: §{} is followed by §{} — section numbers must strictly increase",
                path.display(),
                pair[0],
                pair[1]
            );
        }
        assert!(
            !numbers.is_empty(),
            "{} has no numbered sections",
            path.display()
        );
    }
}

/// A `### N.M` heading belongs to a `## N` section that exists — a subsection
/// under a section that was renamed away is unreachable in the table of
/// contents and in the reader's head.
#[test]
fn every_subsection_belongs_to_an_existing_section() {
    let docs = docs_dir();
    for m in MODULES {
        let path = module_path(&docs, m);
        let doc = read(&path);
        let sections = section_numbers(&doc);
        for sub in subsection_numbers(&doc) {
            let parent = sub.split('.').next().unwrap_or("").to_string();
            assert!(
                sections.iter().any(|s| s == &parent),
                "{}: §{sub} has no `## {parent}` section to belong to",
                path.display()
            );
        }
    }
}

/// An ODD fence count anywhere = an unclosed block somewhere: everything
/// after it renders as code, and every fence-blind counter after it lies.
#[test]
fn code_fences_are_balanced_in_every_module() {
    let docs = docs_dir();
    let mut paths: Vec<PathBuf> = MODULES.iter().map(|m| module_path(&docs, m)).collect();
    paths.push(docs.join("README.md"));
    for path in paths {
        let fences = read(&path).lines().filter(|l| l.starts_with("```")).count();
        assert_eq!(
            fences % 2,
            0,
            "{} has {fences} code-fence lines (odd = an unclosed block)",
            path.display()
        );
    }
}

/// Every relative link resolves to a real file, relative to the document that
/// carries it. A dead link in the module index is the first thing a reader
/// hits and the last thing anyone notices.
#[test]
fn every_relative_link_resolves() {
    let docs = docs_dir();
    let mut paths: Vec<PathBuf> = MODULES.iter().map(|m| module_path(&docs, m)).collect();
    paths.push(docs.join("README.md"));
    let mut checked = 0usize;
    for path in paths {
        let doc = read(&path);
        let base = path.parent().expect("a document has a parent");
        for target in relative_links(&doc) {
            let resolved = base.join(&target);
            assert!(
                resolved.exists(),
                "{} links to a missing file: {target} (resolved to {})",
                path.display(),
                resolved.display()
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 12,
        "expected the module links to be exercised, saw only {checked}"
    );
}

/// The machine-readable BIP-360 snapshot lives in module 11 — once, parseable
/// — and nowhere else: two snapshots would let the K1 tracker audit a stale
/// one.
#[test]
fn the_bip360_snapshot_lives_in_module_eleven_and_parses() {
    let docs = docs_dir();
    let plan_path = module_path(&docs, "11");
    let plan = read(&plan_path);
    assert!(
        plan.contains(SNAPSHOT_BEGIN) && plan.contains(SNAPSHOT_END),
        "{} lost the BIP-360 snapshot markers",
        plan_path.display()
    );
    parse_snapshot(&plan).unwrap_or_else(|e| {
        panic!(
            "{} carries a snapshot that does not parse: {e}",
            plan_path.display()
        )
    });
    for m in MODULES.iter().filter(|m| **m != "11") {
        let path = module_path(&docs, m);
        let doc = read(&path);
        assert!(
            !doc.contains(SNAPSHOT_BEGIN) && !doc.contains(SNAPSHOT_END),
            "{} carries BIP-360 snapshot markers — they belong to module 11 only",
            path.display()
        );
    }
}

/// THE ENGLISH-ONLY WALL (Round 40): the published tree carries no Turkish
/// text — not a letter, not a word. The corpus is archived outside the public
/// repository; a regression here means translated material leaked back in.
#[test]
fn the_published_tree_contains_no_turkish_text() {
    let docs = docs_dir();
    let root = docs.parent().expect("docs/ has a parent");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&docs)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", docs.display()))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("md"))
        .collect();
    for name in [
        "README.md",
        "PAPER_EN.md",
        "STATUS.md",
        "ROADMAP.md",
        "SECURITY.md",
        "RELEASE_NOTES.md",
        "CHANGELOG.md",
    ] {
        let path = root.join(name);
        if path.exists() {
            files.push(path);
        }
    }
    assert!(
        files.len() >= 12,
        "expected at least the 11 modules and the index, saw {}",
        files.len()
    );
    for path in files {
        let hits = turkish_markers(&read(&path));
        assert!(
            hits.is_empty(),
            "{} carries Turkish text (the published tree is English-only): {}",
            path.display(),
            hits.join("; ")
        );
    }
}

/// Walk a directory for files a human could read as text; `target/` and
/// fuzzing build output are not published and are skipped.
fn collect_text_files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == "node_modules" {
            continue;
        }
        if path.is_dir() {
            collect_text_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// The English-only wall covers the CODE, not just `docs/` (Round 41). The
/// console page shipped three Turkish labels — an address row, a heartbeat
/// status word, a letter-hash caption — for a whole release because this file
/// only swept the numbered modules: renderer strings, CLI help, scripts and
/// workflow comments are published artifacts too. Binary fixtures
/// (attestation DER/COSE, keys) are skipped by the UTF-8 read; the one file
/// allowed to hold Turkish is the detector itself, which ships the marker
/// table (and this comment names the leak without reproducing it).
#[test]
fn product_sources_carry_no_turkish_text() {
    let docs = docs_dir();
    let root = docs.parent().expect("docs/ has a parent").to_path_buf();
    let mut files = Vec::new();
    for dir in ["crates", "scripts", ".github"] {
        collect_text_files(&root.join(dir), &mut files);
    }
    assert!(
        files.len() > 50,
        "expected the product tree, saw {} files",
        files.len()
    );
    let mut checked = 0;
    for path in files {
        if path.ends_with("qsv-core/src/docs.rs") {
            continue; // the detector's own marker table and fixtures
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // binary fixture
        };
        let hits = turkish_markers(&text);
        assert!(
            hits.is_empty(),
            "{} carries Turkish text (the published tree is English-only): {}",
            path.display(),
            hits.join("; ")
        );
        checked += 1;
    }
    assert!(checked > 40, "only {checked} text files were audited");
}
