//! One-screen vault console: a PURE snapshot (JSON-able) plus a
//! self-contained HTML page — no keys, no network, no JavaScript.
//!
//! This is the first slice of the "Vault Console" roadmap item: an operator
//! pastes the watch-only descriptor they already exported, and sees the
//! three clocks, the address and the printable estate letter on one page.
//! Everything here is derived from public data; the module has no access to
//! private key material and the renderer emits zero `<script>` tags, so the
//! page can be opened offline, printed, and archived.
//!
//! FAIL-CLOSED: a descriptor that is not THIS vault's is refused, never
//! silently ignored — a console showing a valid-looking page for the wrong
//! address is worse than no console at all.

use crate::dashboard::{vault_status, DashboardInput};
use crate::estate::{estate_letter, EstateLetterInput};
use crate::heirs::HeirSet;
use crate::taproot::VaultTaproot;
use bitcoin::Network;
use sha2::{Digest, Sha256};

/// Schema tag of the machine-readable snapshot (`qsv-cli console --json`).
pub const CONSOLE_SCHEMA: &str = "qsv-console/v1";

/// Inputs for [`snapshot`]. All public: watch-only by construction.
pub struct ConsoleInput<'a> {
    pub vault: &'a VaultTaproot,
    pub network: Network,
    /// Current chain height (live RPC or an explicit `--tip`).
    pub tip: u32,
    /// Height of the last heartbeat refresh.
    pub last_refresh_block: u32,
    /// Vault label, printed verbatim on the letter.
    pub label: &'a str,
    /// Verification date for the letter (ISO-8601, printed verbatim).
    pub date: &'a str,
    /// Verified heir registry (classic key ↔ PQC identity commitments).
    pub heirs: &'a HeirSet,
    /// Optional watch-only descriptor (`addr(...)#…`, `rawtr(...)#…`) or the
    /// bare address. When present it MUST match this vault.
    pub descriptor: Option<&'a str>,
}

/// Everything the console shows, as data (the HTML is a pure function of it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleSnapshot {
    pub schema: &'static str,
    pub network: String,
    pub address: String,
    pub output_key: String,
    pub merkle_root: String,
    pub addr_descriptor: String,
    pub rawtr_descriptor: String,
    /// True only when a descriptor was supplied AND matched this vault.
    pub descriptor_verified: bool,
    pub tip: u32,
    pub last_refresh_block: u32,
    pub heartbeat_due: bool,
    pub blocks_until_refresh: u32,
    pub heartbeat_refresh_due: String,
    pub blocks_until_clawback_close: u32,
    pub blocks_until_inheritance: u32,
    pub inheritance_activates: String,
    /// SHA-256 of `letter` — the page prints it so a printed copy can be
    /// compared with `sha256sum` of the text a `verify-estate` run consumes.
    pub letter_sha256: String,
    pub letter: String,
}

/// Build the snapshot. The only failure is a descriptor that does not match
/// this vault: that is a refusal, not a warning.
pub fn snapshot(inp: &ConsoleInput<'_>) -> Result<ConsoleSnapshot, String> {
    let w = inp
        .vault
        .watch_descriptors(inp.network)
        .map_err(|e| e.to_string())?;
    let address = w.address.to_string();

    let mut descriptor_verified = false;
    if let Some(candidate) = inp.descriptor {
        let candidate = candidate.trim();
        if candidate.is_empty() {
            return Err(
                "empty --descriptor: pass the addr()/rawtr() line from `qsv-cli vault-descriptor`"
                    .into(),
            );
        }
        let matches = [
            address.as_str(),
            w.addr_descriptor.as_str(),
            w.rawtr_descriptor.as_str(),
        ]
        .contains(&candidate);
        if !matches {
            return Err(format!(
                "descriptor does not match this vault (fail-closed): expected the address {address} or one of its addr()/rawtr() descriptors from `qsv-cli vault-descriptor`"
            ));
        }
        descriptor_verified = true;
    }

    let status = vault_status(&DashboardInput {
        vault: inp.vault,
        tip: inp.tip,
        last_refresh_block: inp.last_refresh_block,
    });
    let letter = estate_letter(&EstateLetterInput {
        vault: inp.vault,
        network: inp.network,
        label: inp.label,
        verification_date: inp.date,
        heirs: inp.heirs,
    });
    let letter_sha256 = hex::encode(Sha256::digest(letter.as_bytes()));

    Ok(ConsoleSnapshot {
        schema: CONSOLE_SCHEMA,
        network: format!("{:?}", inp.network).to_lowercase(),
        address,
        output_key: hex::encode(inp.vault.output_key().serialize()),
        merkle_root: inp
            .vault
            .merkle_root()
            .map(|h| h.to_string())
            .unwrap_or_else(|| "none".into()),
        addr_descriptor: w.addr_descriptor,
        rawtr_descriptor: w.rawtr_descriptor,
        descriptor_verified,
        tip: inp.tip,
        last_refresh_block: inp.last_refresh_block,
        heartbeat_due: status.heartbeat_due,
        blocks_until_refresh: status.blocks_until_refresh,
        heartbeat_refresh_due: status.dates.heartbeat_refresh_due,
        blocks_until_clawback_close: status.blocks_until_clawback_close,
        blocks_until_inheritance: status.blocks_until_inheritance,
        inheritance_activates: status.dates.inheritance_activates,
        letter_sha256,
        letter,
    })
}

/// Escape the five HTML-significant characters. The letter is plain text by
/// construction, but the renderer never trusts that.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render the one-page console. Deterministic: same snapshot → same bytes.
///
/// Zero JavaScript, zero external assets — the file opens from disk, prints
/// on one sheet, and can be archived next to the estate letter.
pub fn render_html(s: &ConsoleSnapshot) -> String {
    let (hb_state, hb_class) = if s.heartbeat_due {
        ("REFRESH NOW", "warn")
    } else {
        ("OK", "ok")
    };
    let (inh_state, inh_class) = if s.blocks_until_inheritance == 0 {
        ("OPEN", "warn")
    } else {
        ("LOCKED", "ok")
    };
    let descriptor_row = match s.descriptor_verified {
        true => "<span class=\"badge ok\">VERIFIED</span>".to_string(),
        false => "<span class=\"badge\">NOT VERIFIED — no descriptor supplied</span>".to_string(),
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QuantumSafe-Vault — {address}</title>
<style>
:root {{ --ink:#14161a; --muted:#5b6470; --line:#d8dde3; --ok:#1c7a4a; --warn:#a33b12; --bg:#fbfaf7; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
main {{ max-width:920px; margin:0 auto; padding:32px 24px 48px; }}
h1 {{ font-size:22px; margin:0 0 4px; letter-spacing:-.01em; }}
h2 {{ font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin:28px 0 10px; }}
.banner {{ border:1px solid var(--warn); background:#fff4ee; color:var(--warn); padding:10px 12px; border-radius:6px; font-size:13px; margin:16px 0 20px; }}
.sub {{ color:var(--muted); font-size:13px; }}
.grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }}
@media (max-width:720px) {{ .grid {{ grid-template-columns:1fr; }} }}
.card {{ border:1px solid var(--line); background:#fff; border-radius:8px; padding:14px 16px; }}
.card .k {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }}
.card .v {{ font-size:20px; font-weight:600; margin:4px 0 2px; }}
.card .d {{ font-size:12px; color:var(--muted); }}
.ok {{ color:var(--ok); }}
.warn {{ color:var(--warn); }}
.badge {{ display:inline-block; border:1px solid var(--line); border-radius:999px; padding:2px 10px; font-size:12px; color:var(--muted); }}
.badge.ok {{ border-color:var(--ok); color:var(--ok); }}
code, pre {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
pre {{ white-space:pre-wrap; word-break:break-word; background:#fff; border:1px solid var(--line); border-radius:8px; padding:14px; font-size:12.5px; }}
code {{ font-size:12.5px; background:#f2f4f7; padding:2px 6px; border-radius:4px; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
td {{ border-top:1px solid var(--line); padding:8px 6px; vertical-align:top; }}
td:first-child {{ color:var(--muted); width:180px; }}
ul {{ margin:8px 0 0 18px; padding:0; font-size:13px; }}
li {{ margin:4px 0; }}
footer {{ margin-top:28px; color:var(--muted); font-size:11.5px; border-top:1px solid var(--line); padding-top:12px; }}
@media print {{ body {{ background:#fff; }} .banner {{ border-width:1px; }} main {{ max-width:none; padding:0; }} }}
</style>
</head>
<body>
<main>
<h1>QuantumSafe-Vault · Vault Console</h1>
<div class="sub">Schema <code>{schema}</code> · network <code>{network}</code> · chain tip <code>{tip}</code> · last refresh <code>{last_refresh}</code></div>
<div class="banner"><strong>Reference implementation — do not use with real funds.</strong> No independent audit, no production TEE provisioning, mainnet is not supported. This page is built from public (watch-only) data only and contains no keys.</div>

<h2>Identity</h2>
<table>
<tr><td>Address</td><td><code>{address}</code></td></tr>
<tr><td>Output key</td><td><code>{output_key}</code></td></tr>
<tr><td>Merkle root</td><td><code>{merkle}</code></td></tr>
<tr><td>addr() descriptor</td><td><code>{addr_desc}</code></td></tr>
<tr><td>rawtr() descriptor</td><td><code>{rawtr_desc}</code></td></tr>
<tr><td>Descriptor check</td><td>{descriptor_row}</td></tr>
</table>

<h2>The three clocks</h2>
<div class="grid">
<div class="card"><div class="k">Heartbeat (self-churn)</div><div class="v {hb_class}">{hb_state}</div><div class="d">{hb_blocks} blocks left · refresh ≈ {hb_date}</div></div>
<div class="card"><div class="k">Recovery window (CSV 144)</div><div class="v">{clawback_blocks}</div><div class="d">blocks left · the sweep path stays open this long</div></div>
<div class="card"><div class="k">Inheritance (CSV 26,280)</div><div class="v {inh_class}">{inh_state}</div><div class="d">{inh_blocks} blocks left · opens ≈ {inh_date}</div></div>
</div>

<h2>Estate letter</h2>
<pre>{letter}</pre>
<div class="sub">Letter SHA-256: <code>{letter_sha}</code></div>

<h2>What this page does NOT protect</h2>
<ul>
<li>Both on-chain signatures are classical Schnorr (secp256k1): leaf 1 does not protect against an adversary who can forge both signatures on Q-Day. The Q-Day escape route is leaf 4 (WOTS+, SHA-256 only).</li>
<li>If the heartbeat is missed, heirs can spend after 26,280 blocks — that is by design, not a bug. There is no second "proof-of-life" channel yet.</li>
<li>No independent audit, no real enclave attestation run and no insurance: losses are permanent.</li>
<li>This page is not a legal will; local succession law still applies.</li>
</ul>

<footer>Built by: <code>qsv-cli console</code> · machine-readable form: <code>qsv-cli console --json</code> · independent letter verification: <code>qsv-cli verify-estate --file letter.txt --network {network}</code></footer>
</main>
</body>
</html>
"#,
        schema = s.schema,
        network = esc(&s.network),
        tip = s.tip,
        last_refresh = s.last_refresh_block,
        address = esc(&s.address),
        output_key = esc(&s.output_key),
        merkle = esc(&s.merkle_root),
        addr_desc = esc(&s.addr_descriptor),
        rawtr_desc = esc(&s.rawtr_descriptor),
        descriptor_row = descriptor_row,
        hb_state = hb_state,
        hb_class = hb_class,
        hb_blocks = s.blocks_until_refresh,
        hb_date = esc(&s.heartbeat_refresh_due),
        clawback_blocks = s.blocks_until_clawback_close,
        inh_state = inh_state,
        inh_class = inh_class,
        inh_blocks = s.blocks_until_inheritance,
        inh_date = esc(&s.inheritance_activates),
        letter = esc(&s.letter),
        letter_sha = esc(&s.letter_sha256),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo_keys;
    use bitcoin::secp256k1::Secp256k1;

    fn vault() -> VaultTaproot {
        let secp = Secp256k1::verification_only();
        VaultTaproot::derive(
            &secp,
            demo_keys::user_key(),
            demo_keys::enclave_key(),
            demo_keys::recovery_key(),
            &[demo_keys::heir_one(), demo_keys::heir_two()],
            2,
        )
        .unwrap()
    }

    fn heirs() -> HeirSet {
        // The console takes the registry as DATA (it never verifies PQC
        // keys itself), so fixed 32-byte commitments are enough here — the
        // real CLI builds them from ML-DSA-65 verifying keys.
        HeirSet::build([
            (demo_keys::heir_one().serialize(), vec![7u8; 32]),
            (demo_keys::heir_two().serialize(), vec![8u8; 32]),
        ])
        .unwrap()
    }

    fn snapshot_for(tip: u32, last: u32, descriptor: Option<&str>) -> ConsoleSnapshot {
        let v = vault();
        let h = heirs();
        snapshot(&ConsoleInput {
            vault: &v,
            network: Network::Signet,
            tip,
            last_refresh_block: last,
            label: "Family vault",
            date: "2026-10-19",
            heirs: &h,
            descriptor,
        })
        .unwrap()
    }

    #[test]
    fn clocks_are_the_dashboard_engines_own_numbers() {
        let v = vault();
        let expected = vault_status(&DashboardInput {
            vault: &v,
            tip: 900_000,
            last_refresh_block: 899_000,
        });
        let s = snapshot_for(900_000, 899_000, None);
        assert_eq!(
            s.blocks_until_inheritance,
            expected.blocks_until_inheritance
        );
        assert_eq!(s.blocks_until_refresh, expected.blocks_until_refresh);
        assert_eq!(
            s.blocks_until_clawback_close,
            expected.blocks_until_clawback_close
        );
        assert_eq!(
            s.inheritance_activates,
            expected.dates.inheritance_activates
        );
        assert_eq!(s.heartbeat_due, expected.heartbeat_due);
    }

    #[test]
    fn full_dormancy_flips_both_cheap_paths_to_open() {
        let s = snapshot_for(900_000 + 26_280, 900_000, None);
        assert_eq!(s.blocks_until_inheritance, 0);
        assert_eq!(s.blocks_until_clawback_close, 0);
        assert!(s.heartbeat_due);
        let html = render_html(&s);
        assert!(html.contains("OPEN"));
        assert!(html.contains("REFRESH NOW"));
    }

    #[test]
    fn own_descriptors_and_address_are_accepted() {
        let base = snapshot_for(900_000, 900_000, None);
        for candidate in [
            base.address.clone(),
            base.addr_descriptor.clone(),
            base.rawtr_descriptor.clone(),
            format!("  {}  ", base.rawtr_descriptor),
        ] {
            let s = snapshot_for(900_000, 900_000, Some(&candidate));
            assert!(s.descriptor_verified, "candidate {candidate}");
        }
    }

    #[test]
    fn foreign_descriptor_is_refused_not_ignored() {
        let v = vault();
        let h = heirs();
        let err = snapshot(&ConsoleInput {
            vault: &v,
            network: Network::Signet,
            tip: 900_000,
            last_refresh_block: 900_000,
            label: "x",
            date: "2026-10-19",
            heirs: &h,
            descriptor: Some(
                "rawtr(0000000000000000000000000000000000000000000000000000000000000000)",
            ),
        })
        .unwrap_err();
        assert!(err.contains("does not match this vault"), "{err}");
        // Empty is its own refusal: "no descriptor" is `None`, not `""`.
        let err = snapshot(&ConsoleInput {
            vault: &v,
            network: Network::Signet,
            tip: 900_000,
            last_refresh_block: 900_000,
            label: "x",
            date: "2026-10-19",
            heirs: &h,
            descriptor: Some("   "),
        })
        .unwrap_err();
        assert!(err.contains("empty --descriptor"), "{err}");
    }

    #[test]
    fn html_is_self_contained_and_script_free() {
        let s = snapshot_for(900_000, 900_000, None);
        let html = render_html(&s);
        assert!(html.starts_with("<!doctype html>"));
        assert!(!html.contains("<script"), "a console page must need no JS");
        assert!(!html.contains("http://") && !html.contains("https://"));
        assert!(html.contains(&s.address));
        assert!(html.contains(&s.letter_sha256));
        // The letter is embedded HTML-escaped (so it can never inject markup).
        assert!(html.contains(&esc(&s.letter)));
        assert!(html.contains("do not use with real funds"));
    }

    #[test]
    fn html_escapes_hostile_label_and_letter() {
        let v = vault();
        let h = heirs();
        let s = snapshot(&ConsoleInput {
            vault: &v,
            network: Network::Signet,
            tip: 900_000,
            last_refresh_block: 900_000,
            label: "<img src=x onerror=alert(1)>",
            date: "\"><script>",
            heirs: &h,
            descriptor: None,
        })
        .unwrap();
        let html = render_html(&s);
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;img src=x"));
    }

    #[test]
    fn snapshot_bytes_are_deterministic() {
        let a = snapshot_for(900_000, 899_500, None);
        let b = snapshot_for(900_000, 899_500, None);
        assert_eq!(a, b);
        assert_eq!(render_html(&a), render_html(&b));
    }
}
