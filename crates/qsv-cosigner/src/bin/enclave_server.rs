//! Enclave-side entrypoint for the live Nitro e2e (docs/10 §4.53).
//!
//! * default build — serves the SAME ceremony over loopback TCP (the dev
//!   drill: `scripts/nitro_e2e.sh` phase 1 and `tests/nitro_e2e.rs` run
//!   this binary for real, no stubs).
//! * `--features nsm` — serves over real AF_VSOCK inside the enclave
//!   (`scripts/nitro_e2e.sh` phase 2, after `nitro-cli run-enclave`).
//!
//! Startup writes machine-readable lines the e2e runner parses:
//!
//! ```text
//! DEV_PCR0=<96 hex>   dev builds only: the measurement pin of THIS seed
//! DEV_XONLY=<64 hex>  the co-signer x-only key (= vault policy key_enclave)
//! E2E_READY mode=<tcp|vsock> port=<port>
//! ```
//!
//! Vault allowlist: repeatable `--vault <id>`, or the `QSV_VAULT`
//! environment variable (comma-separated — the form baked into the enclave
//! image, which cannot receive run-time arguments). No vaults → the
//! allowlist is empty and every request is refused (fail closed).

use qsv_cosigner::server::Cosigner;
#[cfg(not(feature = "nsm"))]
use qsv_cosigner::server::{serve, serve_limited};
use std::process::exit;

fn usage(msg: &str) -> ! {
    eprintln!("enclave_server: {msg}");
    eprintln!(
        "usage: enclave_server --port <u16> [--vault <id>]... [--seed <64-hex>]\
         [--max-requests <n>]\n\
         env:   QSV_VAULT=<id,id,...>  comma-separated allowlist fallback"
    );
    exit(2);
}

fn main() {
    let mut port: Option<u16> = None;
    let mut vaults: Vec<String> = Vec::new();
    let mut seed = [0u8; 32];
    // Round 29 P5: serve N connections then exit 0 (a NORMAL exit flushes
    // this process's .profraw; SIGKILL never does — without this flag the
    // child's own startup lines score zero coverage under llvm-cov).
    let mut max_requests: Option<u64> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--port" => {
                let v = args.next().unwrap_or_default();
                port = Some(v.parse().unwrap_or_else(|_| usage("--port needs a u16")));
            }
            "--vault" => {
                let v = args.next().unwrap_or_default();
                if v.is_empty() {
                    usage("--vault needs a non-empty id");
                }
                vaults.push(v);
            }
            "--seed" => {
                let v = args.next().unwrap_or_default();
                seed = hex::decode(&v)
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .unwrap_or_else(|| usage("--seed needs 64 hex chars (32 bytes)"));
            }
            "--max-requests" => {
                let v = args.next().unwrap_or_default();
                max_requests = Some(
                    v.parse()
                        .ok()
                        .filter(|n: &u64| *n >= 1)
                        .unwrap_or_else(|| usage("--max-requests needs an integer >= 1")),
                );
            }
            other => usage(&format!("unknown argument {other:?}")),
        }
    }
    let port = port.unwrap_or_else(|| usage("--port is required"));

    // Env fallback (enclave images carry ENV, not run-time args).
    if vaults.is_empty() {
        if let Ok(list) = std::env::var("QSV_VAULT") {
            vaults.extend(
                list.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
    }
    if vaults.is_empty() {
        eprintln!("enclave_server: WARNING no vault allowlist (--vault / QSV_VAULT) — every request will be refused");
    }

    let cosigner = Cosigner::provision(seed, vaults);

    // The pins the e2e runner needs, printed BEFORE serving.
    match cosigner.public_key() {
        Ok(x) => println!("DEV_XONLY={}", hex::encode(x.serialize())),
        Err(e) => {
            eprintln!("enclave_server: enclave key unavailable: {e}");
            exit(1);
        }
    }
    #[cfg(not(feature = "nsm"))]
    {
        let m: [u8; 48] = qsv_cosigner::nsm::dev_measurement(&seed);
        println!("DEV_PCR0={}", hex::encode(m));
    }

    #[cfg(feature = "nsm")]
    {
        println!("E2E_READY mode=vsock port={port}");
        let result = match max_requests {
            Some(n) => qsv_cosigner::vsock::serve_vsock_limited(cosigner, u32::from(port), n),
            None => qsv_cosigner::vsock::serve_vsock(cosigner, u32::from(port)),
        };
        if let Err(e) = result {
            eprintln!("enclave_server: vsock serve failed: {e}");
            exit(1);
        }
    }
    #[cfg(not(feature = "nsm"))]
    {
        println!("E2E_READY mode=tcp port={port}");
        let result = match max_requests {
            Some(n) => serve_limited(cosigner, &format!("127.0.0.1:{port}"), n),
            None => serve(cosigner, &format!("127.0.0.1:{port}")),
        };
        if let Err(e) = result {
            eprintln!("enclave_server: tcp serve failed: {e}");
            exit(1);
        }
    }
}
