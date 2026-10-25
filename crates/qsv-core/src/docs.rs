//! Documentation consistency audit for the single English edition (Round 40).
//!
//! The repository publishes ONE edition of every specification module: the
//! English `docs/NN_*.md` files. `docs_sync` (the qsv-cli integration test)
//! FAILS the build when a wall fires; this module turns the same walls into
//! DATA, so an operator sees WHAT drifted and where instead of a panic, and
//! two runs can be diffed.
//!
//! Walls (one report row per module; every one is also a `docs_sync` test):
//!
//! * `module-set` — numbered `NN_*.md` files are contiguous from 01, no
//!   number appears twice, and `docs/README.md` (when present) indexes every
//!   one (tree-level findings land on the first row);
//! * `title-english` — a module opens with `# Module NN …` (case-insensitive:
//!   module 11 shouts `# MODULE 11`);
//! * `section-order` — numbered `## ` sections strictly increase;
//! * `subsection-parent` — every numbered `### N.M` has an existing `## N`;
//! * `fence` — code fences balance (an odd count = an unclosed block);
//! * `link` — every relative link resolves: a file target must exist, a
//!   pure `#anchor` must match one of the document's own headings; external
//!   URLs are free, and nothing inside a code fence is a link;
//! * `snapshot` — module 11 carries the machine-readable BIP-360 snapshot,
//!   it parses, and no other module carries the markers;
//! * `turkish-text` — the published tree is English-only: no Turkish
//!   letters and no Turkish vocabulary (the corpus is archived OUTSIDE the
//!   public repository).
//!
//! The report covers numbered modules; [`turkish_markers`] is public so
//! `docs_sync` can sweep every file in the tree — including `README.md`,
//! which is not a numbered module.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::bip360::{self, SNAPSHOT_BEGIN, SNAPSHOT_END};

/// One structural finding. `kind` is stable for the JSON report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drift {
    pub kind: &'static str,
    pub detail: String,
}

impl Drift {
    fn new(kind: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// One module's verdict: identity, size and every drift found.
#[derive(Debug, Clone)]
pub struct ModuleReport {
    /// Two-digit module number (`"01"` … `"11"`).
    pub module: String,
    /// File name inside the docs directory.
    pub file: String,
    pub bytes: usize,
    pub words: usize,
    pub drifts: Vec<Drift>,
}

impl ModuleReport {
    pub fn in_sync(&self) -> bool {
        self.drifts.is_empty()
    }
}

/// Audit every numbered module in `dir`.
///
/// An unreadable or empty directory is an ERROR (not a green report): a tree
/// that cannot be read must never look like a tree that passed.
pub fn report(dir: &Path) -> Result<Vec<ModuleReport>, String> {
    let files = module_files(dir)?;
    if files.is_empty() {
        return Err(format!(
            "no numbered module documents (NN_*.md) in {}",
            dir.display()
        ));
    }
    let readme = std::fs::read_to_string(dir.join("README.md")).ok();
    let mut tree = tree_drifts(&files);
    let mut out = Vec::with_capacity(files.len());
    for (module, path) in files {
        let text = read(&path)?;
        let mut drifts = if out.is_empty() {
            std::mem::take(&mut tree)
        } else {
            Vec::new()
        };
        let module_no: u32 = module
            .parse()
            .map_err(|_| format!("{}: module number is not numeric", path.display()))?;
        if let Some(readme) = &readme {
            let name = name(&path);
            if !readme.contains(&name) {
                drifts.push(Drift::new(
                    "module-set",
                    format!("docs/README.md does not index {name}"),
                ));
            }
        }
        if let Some(d) = title_drift(&text, module_no) {
            drifts.push(d);
        }
        drifts.extend(section_order_drifts(&text));
        drifts.extend(subsection_parent_drifts(&text));
        if let Some(d) = fence_drift(&text) {
            drifts.push(d);
        }
        drifts.extend(link_drifts(&text, &path));
        drifts.extend(snapshot_drifts(module_no, &text));
        if let Some(d) = turkish_drift(&text) {
            drifts.push(d);
        }
        out.push(ModuleReport {
            module,
            file: name(&path),
            bytes: text.len(),
            words: words(&text),
            drifts,
        });
    }
    Ok(out)
}

/// True when EVERY module passed every wall.
pub fn in_sync(reports: &[ModuleReport]) -> bool {
    reports.iter().all(ModuleReport::in_sync)
}

/// Total number of structural findings.
pub fn drift_count(reports: &[ModuleReport]) -> usize {
    reports.iter().map(|r| r.drifts.len()).sum()
}

/// The one-line verdict (`DOCS AUDIT: OK (11 modules, 0 structural drifts)`).
pub fn summary_line(reports: &[ModuleReport]) -> String {
    let modules = reports.len();
    let noun = if modules == 1 { "module" } else { "modules" };
    let total = drift_count(reports);
    if total == 0 {
        format!("DOCS AUDIT: OK ({modules} {noun}, 0 structural drifts)")
    } else {
        let dirty = reports.iter().filter(|r| !r.in_sync()).count();
        format!("DOCS AUDIT: DRIFT ({total} drifts in {dirty} of {modules} {noun})")
    }
}

/// Human report: one row per module, drift lines indented under it.
pub fn render(reports: &[ModuleReport]) -> String {
    let mut out = String::new();
    out.push_str("───── DOCUMENTATION AUDIT (single English edition) ─────────────\n");
    out.push_str("  module   words  status\n");
    for r in reports {
        let status = if r.in_sync() { "ok" } else { "DRIFT" };
        out.push_str(&format!("  {:>6}  {:>6}  {status}\n", r.module, r.words));
        out.push_str(&format!("          {} ({} bytes)\n", r.file, r.bytes));
        for d in &r.drifts {
            out.push_str(&format!("          ✗ [{}] {}\n", d.kind, d.detail));
        }
    }
    out.push('\n');
    out.push_str(&summary_line(reports));
    out.push('\n');
    out
}

// ────────────────────────────── tree level ──────────────────────────────

/// The numbered module files (`NN_*.md`), sorted by name.
fn module_files(dir: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !fname.ends_with(".md") {
            continue;
        }
        let digits: String = fname.chars().take_while(|c| c.is_ascii_digit()).collect();
        // Exactly two digits and an underscore: `NN_*.md` and nothing else.
        if digits.len() != 2 || !fname[digits.len()..].starts_with('_') {
            continue;
        }
        files.push((digits, path));
    }
    files.sort();
    Ok(files)
}

/// Tree-level findings: the module set must be contiguous from 01, once each.
fn tree_drifts(files: &[(String, PathBuf)]) -> Vec<Drift> {
    let mut drifts = Vec::new();
    let mut numbers: Vec<u32> = files
        .iter()
        .map(|(digits, _)| digits.parse::<u32>().unwrap_or(0))
        .collect();
    let mut seen = BTreeSet::new();
    for (digits, _) in files {
        let n = digits.parse::<u32>().unwrap_or(0);
        if !seen.insert(n) {
            drifts.push(Drift::new(
                "module-set",
                format!("module {digits} appears more than once — one file per number"),
            ));
        }
        if n == 0 {
            drifts.push(Drift::new(
                "module-set",
                format!("module {digits} is not a module number — numbering starts at 01"),
            ));
        }
    }
    numbers.sort_unstable();
    if let Some(&max) = numbers.last() {
        for n in 1..=max {
            if !numbers.contains(&n) {
                drifts.push(Drift::new(
                    "module-set",
                    format!("module {n:02} is missing — numbering must be contiguous from 01"),
                ));
            }
        }
    }
    drifts
}

// ──────────────────────────── module level ────────────────────────────

/// The title wall: the first non-empty line must be `# Module NN …`.
fn title_drift(text: &str, module_no: u32) -> Option<Drift> {
    let first = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let Some(rest) = first.strip_prefix("# ") else {
        return Some(Drift::new(
            "title-english",
            format!("the first line is not a `# Module {module_no:02} …` title: `{first}`"),
        ));
    };
    let lower = rest.to_lowercase();
    let Some(after) = lower.strip_prefix("module ") else {
        return Some(Drift::new(
            "title-english",
            format!("the title must open with `# Module {module_no:02} …`, found `{first}`"),
        ));
    };
    let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Some(Drift::new(
            "title-english",
            format!("the title does not number the module: `{first}`"),
        ));
    }
    if digits.parse::<u32>().ok() != Some(module_no) {
        return Some(Drift::new(
            "title-english",
            format!("the title declares module {digits} but the file is {module_no:02}"),
        ));
    }
    None
}

/// `## N` numbers must strictly increase down the document.
fn section_order_drifts(text: &str) -> Vec<Drift> {
    let mut drifts = Vec::new();
    let numbers = heading_numbers(text, "## ");
    for pair in numbers.windows(2) {
        if num_key(&pair[1]) <= num_key(&pair[0]) {
            drifts.push(Drift::new(
                "section-order",
                format!(
                    "§{} is followed by §{} — section numbers must strictly increase",
                    pair[0], pair[1]
                ),
            ));
        }
    }
    drifts
}

/// Every `### N.M` needs a `## N` section to belong to.
fn subsection_parent_drifts(text: &str) -> Vec<Drift> {
    let sections = heading_numbers(text, "## ");
    let mut drifts = Vec::new();
    for sub in heading_numbers(text, "### ") {
        let parent = sub.split('.').next().unwrap_or("").to_string();
        if !sections.iter().any(|s| s == &parent) {
            drifts.push(Drift::new(
                "subsection-parent",
                format!("§{sub} has no `## {parent}` section to belong to"),
            ));
        }
    }
    drifts
}

/// An odd number of fence lines means one block was never closed.
fn fence_drift(text: &str) -> Option<Drift> {
    let fences = text.lines().filter(|l| l.starts_with("```")).count();
    if fences % 2 != 0 {
        Some(Drift::new(
            "fence",
            format!("{fences} code-fence lines (odd = an unclosed block)"),
        ))
    } else {
        None
    }
}

/// Every relative link resolves — files on disk, anchors against headings.
fn link_drifts(text: &str, path: &Path) -> Vec<Drift> {
    let mut drifts = Vec::new();
    let slugs = heading_slugs(text);
    let mut in_fence = false;
    for (i, line) in text.lines().enumerate() {
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
            {
                continue;
            }
            let (file_part, anchor) = match target.split_once('#') {
                Some((p, a)) => (p, Some(a)),
                None => (target, None),
            };
            if file_part.is_empty() {
                if let Some(anchor) = anchor {
                    if !anchor.is_empty() && !slugs.contains(anchor) {
                        drifts.push(Drift::new(
                            "link",
                            format!("line {}: `#{anchor}` matches no heading here", i + 1),
                        ));
                    }
                }
                continue;
            }
            let file_part = file_part.split('?').next().unwrap_or(file_part);
            let resolved = path.parent().unwrap_or(Path::new(".")).join(file_part);
            if !resolved.exists() {
                drifts.push(Drift::new(
                    "link",
                    format!(
                        "line {}: `{file_part}` does not exist (resolved to {})",
                        i + 1,
                        resolved.display()
                    ),
                ));
            }
        }
    }
    drifts
}

/// Module 11 must carry a parseable BIP-360 snapshot; no other module may.
fn snapshot_drifts(module_no: u32, text: &str) -> Vec<Drift> {
    let has_begin = text.contains(SNAPSHOT_BEGIN);
    let has_end = text.contains(SNAPSHOT_END);
    if module_no == 11 {
        let mut drifts = Vec::new();
        if !has_begin || !has_end {
            drifts.push(Drift::new(
                "snapshot",
                "module 11 must carry the machine-readable BIP-360 snapshot block (BEGIN/END markers)",
            ));
        } else if let Err(e) = bip360::parse_snapshot(text) {
            drifts.push(Drift::new(
                "snapshot",
                format!("the BIP-360 snapshot block does not parse: {e}"),
            ));
        }
        drifts
    } else if has_begin || has_end {
        vec![Drift::new(
            "snapshot",
            format!("{module_no:02} carries BIP-360 snapshot markers — they belong to module 11"),
        )]
    } else {
        Vec::new()
    }
}

/// One `turkish-text` drift when the document carries Turkish markers.
fn turkish_drift(text: &str) -> Option<Drift> {
    let hits = turkish_markers(text);
    if hits.is_empty() {
        return None;
    }
    let shown: Vec<&str> = hits.iter().take(3).map(String::as_str).collect();
    let extra = hits.len().saturating_sub(3);
    let more = if extra > 0 {
        format!(" (+{extra} more lines)")
    } else {
        String::new()
    };
    Some(Drift::new(
        "turkish-text",
        format!(
            "the published tree is English-only: {}{more}",
            shown.join("; ")
        ),
    ))
}

// ─────────────────────────────── helpers ───────────────────────────────

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string()
}

/// Leading numbers of every heading using `marker` (`## 4. X` → "4"),
/// skipping headings without a number (titles, prose headings).
fn heading_numbers(text: &str, marker: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.strip_prefix(marker))
        .filter_map(|rest| {
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let num = num.trim_end_matches('.');
            if num.is_empty() {
                None
            } else {
                Some(num.to_string())
            }
        })
        .collect()
}

/// `"4.63"` → `[4, 63]`, for ordered comparison of section numbers.
fn num_key(number: &str) -> Vec<u32> {
    number
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

/// GitHub-style slugs of every heading, for pure `#anchor` targets.
fn heading_slugs(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter(|l| l.starts_with('#'))
        .map(|l| l.trim_start_matches('#').trim())
        .map(|heading| {
            let mut slug = String::with_capacity(heading.len());
            for c in heading.to_lowercase().chars() {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    slug.push(c);
                } else if c == ' ' {
                    slug.push('-');
                }
            }
            slug
        })
        .collect()
}

fn words(text: &str) -> usize {
    text.split_whitespace().count()
}

// ───────────────────────── English-only detection ─────────────────────────

/// The twelve letters Turkish has and English does not (both cases).
const TURKISH_LETTERS: [char; 12] = ['ç', 'Ç', 'ğ', 'Ğ', 'ı', 'İ', 'ö', 'Ö', 'ş', 'Ş', 'ü', 'Ü'];

/// Unambiguous Turkish vocabulary: every entry is ≥ 4 ASCII letters and is
/// not an English word, so a hit is a translation leak, not a coincidence.
/// (Short, ambiguous words — `ve`, `bir`, `son`, `sure`, `bin` — are
/// deliberately absent: the letter wall catches the accented text and a
/// false positive here would teach operators to ignore the wall.)
const TURKISH_WORDS: &[&str] = &[
    "acik",
    "aday",
    "adres",
    "anahtar",
    "arac",
    "asama",
    "baslangic",
    "belge",
    "bilgi",
    "bolum",
    "calisma",
    "cevap",
    "degil",
    "denetim",
    "destek",
    "devir",
    "dogru",
    "duzen",
    "eksik",
    "fayda",
    "gelir",
    "gerekli",
    "gizli",
    "guvenli",
    "hakkinda",
    "harita",
    "hesap",
    "ifade",
    "icin",
    "ihrac",
    "kapsam",
    "karsilik",
    "kaynak",
    "kilit",
    "kontrol",
    "kural",
    "mektup",
    "merkez",
    "metin",
    "miktar",
    "nedeni",
    "olcum",
    "olarak",
    "onemli",
    "ortam",
    "saglam",
    "sebep",
    "sinir",
    "sonuc",
    "surec",
    "surekli",
    "taban",
    "takim",
    "tamam",
    "tanim",
    "tarih",
    "taslak",
    "tehlike",
    "teslim",
    "toplam",
    "tutar",
    "uygun",
    "uzun",
    "veri",
    "yontem",
    "zaman",
    "zorunlu",
];

/// Every line that carries a Turkish marker, as `line N: …` (empty = clean).
///
/// Public so `docs_sync` can sweep files that are not numbered modules
/// (`docs/README.md`) with the same detector the report uses.
pub fn turkish_markers(text: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let lower = line.to_lowercase();
        let mut markers: Vec<String> = Vec::new();
        if let Some(c) = line.chars().find(|c| TURKISH_LETTERS.contains(c)) {
            markers.push(format!("Turkish letter '{c}'"));
        }
        for w in TURKISH_WORDS {
            if contains_word(&lower, w) {
                markers.push(format!("Turkish word `{w}`"));
            }
        }
        if !markers.is_empty() {
            hits.push(format!("line {}: {}", i + 1, markers.join(", ")));
        }
    }
    hits
}

/// Whole-word (ASCII-boundary) match of `word` in `hay`.
fn contains_word(hay: &str, word: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = hay[from..].find(word) {
        let start = from + pos;
        let end = start + word.len();
        let before = hay[..start].chars().next_back();
        let after = hay[end..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric());
        if boundary(before) && boundary(after) {
            return true;
        }
        from = end;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway docs directory. The gate's TMPDIR preflight guarantees a
    /// writable, home-free temp root.
    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str, files: &[(&str, &str)]) -> Self {
            let dir =
                std::env::temp_dir().join(format!("qsv_core_audit_{}_{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create docs dir");
            for (name, body) in files {
                std::fs::write(dir.join(name), body).expect("write fixture file");
            }
            Self { dir }
        }

        fn path(&self) -> &Path {
            &self.dir
        }

        fn report(&self) -> Vec<ModuleReport> {
            report(self.path()).expect("audit report")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const CLEAN: &str = "\
# Module 01 — Quantum Threat Model

## 1. Intro

### 1.1. List

- one
- two

```bash
qsv-cli constants
```

## 2. End

See [the next module](02_next.md) and [the site](https://example.org).
";

    const NEXT: &str = "\
# Module 02 — Next

## 1. One

Plain text.
";

    fn kinds(reports: &[ModuleReport]) -> Vec<&'static str> {
        reports
            .iter()
            .flat_map(|r| r.drifts.iter().map(|d| d.kind))
            .collect()
    }

    #[test]
    fn module_files_reads_two_digit_prefixes_in_order() {
        let f = Fixture::new(
            "order",
            &[
                ("02_b.md", NEXT),
                ("10_c.md", "# Module 10 — C\n"),
                ("01_a.md", CLEAN),
                ("README.md", "# Library\n"),
                ("2026_report.md", "not a module\n"),
            ],
        );
        let files = module_files(f.path()).expect("list");
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["01", "02", "10"]);
    }

    #[test]
    fn a_clean_tree_reports_no_drift() {
        let f = Fixture::new("clean", &[("01_a.md", CLEAN), ("02_next.md", NEXT)]);
        let reports = f.report();
        assert_eq!(reports.len(), 2);
        assert!(in_sync(&reports), "drifts: {:?}", kinds(&reports));
        assert_eq!(drift_count(&reports), 0);
        assert_eq!(
            summary_line(&reports),
            "DOCS AUDIT: OK (2 modules, 0 structural drifts)"
        );
        let rendered = render(&reports);
        assert!(rendered.contains("01_a.md"), "{rendered}");
        assert!(rendered.contains("ok"));
    }

    #[test]
    fn an_empty_tree_is_an_error_not_a_green_report() {
        let f = Fixture::new("empty", &[]);
        let err = report(f.path()).expect_err("an empty tree must be refused");
        assert!(err.contains("no numbered module documents"), "{err}");
    }

    #[test]
    fn a_missing_module_number_is_a_drift() {
        let f = Fixture::new(
            "gap",
            &[
                ("01_a.md", CLEAN),
                ("03_c.md", "# Module 03 — C\n\n## 1. One\n"),
            ],
        );
        let reports = f.report();
        let details: Vec<&str> = reports
            .iter()
            .flat_map(|r| r.drifts.iter().map(|d| d.detail.as_str()))
            .collect();
        assert!(
            details.iter().any(|d| d.contains("module 02 is missing")),
            "{details:?}"
        );
        assert!(!in_sync(&reports));
    }

    #[test]
    fn a_duplicate_module_number_is_a_drift() {
        let f = Fixture::new(
            "dupe",
            &[
                ("01_a.md", CLEAN),
                ("01_b.md", "# Module 01 — B\n\n## 1. One\n"),
            ],
        );
        let reports = f.report();
        assert!(
            reports
                .iter()
                .flat_map(|r| &r.drifts)
                .any(|d| d.detail.contains("appears more than once")),
            "{:?}",
            kinds(&reports)
        );
    }

    #[test]
    fn a_title_must_declare_its_module_in_english() {
        // The Turkish word for `module`, spelled with an escape so the source
        // itself carries no Turkish literal.
        let turkish_title = "# MOD\u{00dc}L 01 — Wrong title\n\n## 1. One\n";
        let f = Fixture::new("title", &[("01_a.md", turkish_title)]);
        let reports = f.report();
        assert!(
            reports[0].drifts.iter().any(|d| d.kind == "title-english"),
            "{:?}",
            reports[0].drifts
        );
        // The English title of a different number is just as wrong.
        let f = Fixture::new(
            "title-number",
            &[("01_a.md", "# Module 02 — Wrong number\n\n## 1. One\n")],
        );
        let reports = f.report();
        assert!(
            reports[0]
                .drifts
                .iter()
                .any(|d| d.kind == "title-english" && d.detail.contains("declares module 02")),
            "{:?}",
            reports[0].drifts
        );
    }

    #[test]
    fn section_numbers_must_strictly_increase() {
        let f = Fixture::new(
            "sections",
            &[(
                "01_a.md",
                "# Module 01 — A\n\n## 2. Later\n\n## 1. Earlier\n",
            )],
        );
        let reports = f.report();
        assert!(
            reports[0]
                .drifts
                .iter()
                .any(|d| d.kind == "section-order" && d.detail.contains("§2 is followed by §1")),
            "{:?}",
            reports[0].drifts
        );
    }

    #[test]
    fn a_subsection_must_belong_to_a_listed_section() {
        let f = Fixture::new(
            "subsections",
            &[(
                "01_a.md",
                "# Module 01 — A\n\n## 1. One\n\n### 2.1. Orphan\n",
            )],
        );
        let reports = f.report();
        assert!(
            reports[0].drifts.iter().any(|d| {
                d.kind == "subsection-parent" && d.detail.contains("§2.1 has no `## 2`")
            }),
            "{:?}",
            reports[0].drifts
        );
    }

    #[test]
    fn an_odd_fence_count_is_a_drift() {
        let f = Fixture::new(
            "fence",
            &[(
                "01_a.md",
                "# Module 01 — A\n\n## 1. One\n\n```bash\nls\n\n## 2. Two\n",
            )],
        );
        let reports = f.report();
        assert!(
            reports[0]
                .drifts
                .iter()
                .any(|d| d.kind == "fence" && d.detail.contains("odd")),
            "{:?}",
            reports[0].drifts
        );
    }

    #[test]
    fn a_dead_relative_link_is_a_drift() {
        let dead = format!("{CLEAN}\n[gone](missing.md)\n");
        let f = Fixture::new("dead-link", &[("01_a.md", &dead)]);
        let reports = f.report();
        assert!(
            reports[0]
                .drifts
                .iter()
                .any(|d| d.kind == "link" && d.detail.contains("missing.md")),
            "{:?}",
            reports[0].drifts
        );
        // A link to a file that resolves is fine (CLEAN links 02_next.md).
        let f = Fixture::new("live-link", &[("01_a.md", CLEAN), ("02_next.md", NEXT)]);
        assert!(in_sync(&f.report()), "{:?}", kinds(&f.report()));
    }

    #[test]
    fn links_inside_code_fences_are_not_links() {
        let doc = "\
# Module 01 — A

## 1. One

```markdown
[not a link](nope.md)
```
";
        let f = Fixture::new("fenced-link", &[("01_a.md", doc)]);
        assert!(in_sync(&f.report()), "{:?}", kinds(&f.report()));
    }

    #[test]
    fn a_pure_anchor_must_match_a_heading() {
        let doc = format!("{CLEAN}\n[jump](#2-end)\n");
        let f = Fixture::new("anchor-ok", &[("01_a.md", &doc), ("02_next.md", NEXT)]);
        assert!(in_sync(&f.report()), "{:?}", kinds(&f.report()));
        let doc = format!("{CLEAN}\n[jump](#no-such-heading)\n");
        let f = Fixture::new("anchor-bad", &[("01_a.md", &doc), ("02_next.md", NEXT)]);
        let reports = f.report();
        assert!(
            reports[0]
                .drifts
                .iter()
                .any(|d| d.kind == "link" && d.detail.contains("no-such-heading")),
            "{:?}",
            reports[0].drifts
        );
    }

    #[test]
    fn the_snapshot_wall_binds_module_eleven_only() {
        let missing = Fixture::new(
            "snap-missing",
            &[("11_p2mr.md", "# MODULE 11: BIP-360\n\n## 1. One\n")],
        );
        assert!(
            missing.report()[0]
                .drifts
                .iter()
                .any(|d| d.kind == "snapshot"),
            "{:?}",
            missing.report()[0].drifts
        );
        let stray = Fixture::new(
            "snap-stray",
            &[(
                "05_legal.md",
                &format!("# Module 05 — Legal\n\n## 1. One\n\n{SNAPSHOT_BEGIN}\n{SNAPSHOT_END}\n"),
            )],
        );
        assert!(
            stray.report()[0]
                .drifts
                .iter()
                .any(|d| d.kind == "snapshot" && d.detail.contains("belong to module 11")),
            "{:?}",
            stray.report()[0].drifts
        );
        // Markers present in module 11 but nothing parseable between them.
        let unparsable = Fixture::new(
            "snap-unparsable",
            &[(
                "11_p2mr.md",
                &format!("# MODULE 11: BIP-360\n\n## 1. One\n\n{SNAPSHOT_BEGIN}\n{SNAPSHOT_END}\n"),
            )],
        );
        assert!(
            unparsable.report()[0]
                .drifts
                .iter()
                .any(|d| d.kind == "snapshot" && d.detail.contains("does not parse")),
            "{:?}",
            unparsable.report()[0].drifts
        );
    }

    #[test]
    fn turkish_text_is_flagged_but_english_is_not() {
        assert!(turkish_markers("Public information about the vault, in English.").is_empty());
        // The letter wall: letters English does not have (escaped literals).
        assert!(!turkish_markers("a\u{011f}a\u{00e7}").is_empty());
        // The vocabulary wall, and the word boundary around it.
        let hits = turkish_markers("the metin value");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].contains("line 1"), "{hits:?}");
        assert!(turkish_markers("the meting of the group").is_empty());
    }

    #[test]
    fn the_readme_must_index_every_module() {
        let partial = Fixture::new(
            "readme-partial",
            &[
                ("01_a.md", CLEAN),
                ("02_next.md", NEXT),
                ("README.md", "# Library\n\n[01](01_a.md)\n"),
            ],
        );
        assert!(
            partial.report().iter().flat_map(|r| &r.drifts).any(|d| {
                d.kind == "module-set" && d.detail.contains("does not index 02_next.md")
            }),
            "{:?}",
            kinds(&partial.report())
        );
        // No README at all is not a drift: the wall binds only when present.
        let none = Fixture::new("readme-none", &[("01_a.md", CLEAN), ("02_next.md", NEXT)]);
        assert!(in_sync(&none.report()));
    }

    #[test]
    fn documented_repository_is_structurally_in_sync() {
        let docs = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs"));
        let reports = report(&docs).expect("audit the repository docs");
        assert_eq!(reports.len(), 11, "the library is 11 modules");
        assert!(
            in_sync(&reports),
            "the repository drifted: {:#?}",
            reports
                .iter()
                .filter(|r| !r.in_sync())
                .map(|r| (&r.module, &r.drifts))
                .collect::<Vec<_>>()
        );
        assert!(summary_line(&reports).starts_with("DOCS AUDIT: OK (11 modules"));
        assert_eq!(reports[9].module, "10");
    }
}
