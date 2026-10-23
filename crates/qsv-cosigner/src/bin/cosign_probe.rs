//! Live e2e probe (docs/10 §4.53): the CLIENT half of the Nitro ceremony.
//!
//! Sends ONE `SignRequest` to a running co-signer and verifies the v2
//! answer end-to-end, exactly like the production terminal does
//! (`qsv-cli`'s `live_enclave_signature`):
//!
//! 1. the response is `accepted` (the gate opened — PQC proof + allowlist),
//! 2. an attestation document is present (protocol v2, fail closed),
//! 3. the document verifies: COSE_Sign1 → X.509 chain → pinned root,
//!    PCR0 pin, request-nonce echo (replay), `user_data == xonly‖vault`,
//! 4. the returned BIP-340 signature verifies under the PINNED enclave key
//!    over this request's digest.
//!
//! Exit codes: 0 = PROBE PASS, 1 = any refusal/mismatch (fail closed),
//! 2 = usage error.
//!
//! Transports: `--tcp --port <p>` (dev loopback) or `--cid <c> --port <p>`
//! (AF_VSOCK to a real enclave — requires the `nsm` feature build).

use qsv_cosigner::nsm::{verify_attestation_doc, PinnedMeasurements};
use qsv_cosigner::protocol::SignRequest;
use qsv_cosigner::vsock::{request_signature, Endpoint};
use std::process::exit;

fn usage(msg: &str) -> ! {
    eprintln!("cosign_probe: {msg}");
    eprintln!(
        "usage: cosign_probe (--tcp | --cid <u32>) --port <u16> --vault <id>\n\
         \x20      --pcr0 <96-hex> --xonly <64-hex> [--pcr1 <hex>] [--pcr2 <hex>]"
    );
    exit(2);
}

fn fail(msg: impl core::fmt::Display) -> ! {
    eprintln!("cosign_probe: REFUSED: {msg}");
    exit(1);
}

fn main() {
    let mut tcp = false;
    let mut cid: Option<u32> = None;
    let mut port: Option<u16> = None;
    let mut vault: Option<String> = None;
    let mut pcr0: Option<String> = None;
    let mut pcr1 = String::new();
    let mut pcr2 = String::new();
    let mut xonly: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--tcp" => tcp = true,
            "--cid" => {
                cid = Some(
                    args.next()
                        .unwrap_or_default()
                        .parse()
                        .unwrap_or_else(|_| usage("--cid needs a u32")),
                )
            }
            "--port" => {
                port = Some(
                    args.next()
                        .unwrap_or_default()
                        .parse()
                        .unwrap_or_else(|_| usage("--port needs a u16")),
                )
            }
            "--vault" => vault = args.next(),
            "--pcr0" => pcr0 = args.next(),
            "--pcr1" => pcr1 = args.next().unwrap_or_default(),
            "--pcr2" => pcr2 = args.next().unwrap_or_default(),
            "--xonly" => xonly = args.next(),
            other => usage(&format!("unknown argument {other:?}")),
        }
    }

    let ep = match (tcp, cid, port) {
        (true, None, Some(port)) => Endpoint::Tcp { port },
        (false, Some(cid), Some(port)) => Endpoint::Vsock {
            cid,
            port: u32::from(port),
        },
        _ => usage("need exactly one of --tcp / --cid, plus --port"),
    };
    let vault = vault
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| usage("--vault is required"));
    let pcr0 = pcr0
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| usage("--pcr0 is required"));
    let xonly = xonly
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| usage("--xonly is required"));

    // One request: deterministic client nonce, demo PQC identity (the
    // production terminal uses its hardware-sealed key — same contract).
    let digest = [7u8; 32];
    let pqc = qsv_pqc::PqcIdentity::from_seed(&[21u8; 32]);
    let req = SignRequest::new(
        &vault,
        &digest,
        pqc.verifying_key_bytes(),
        &pqc.sign(&digest),
    );

    let resp = request_signature(&ep, &req).unwrap_or_else(|e| fail(format!("transport: {e}")));
    if !resp.accepted {
        fail(format!(
            "gate refused: {}",
            resp.reason.as_deref().unwrap_or("no reason given")
        ));
    }
    let doc_hex = resp.attestation_doc_hex.as_deref().unwrap_or_else(|| {
        fail("accepted WITHOUT an attestation document (protocol v2 requires one)")
    });

    let pinned = PinnedMeasurements {
        pcr0_hex: pcr0,
        pcr1_hex: pcr1,
        pcr2_hex: pcr2,
        vault_id: vault,
        enclave_xonly_hex: xonly,
    };
    let doc = verify_attestation_doc(doc_hex, &pinned, &req.nonce_hex)
        .unwrap_or_else(|e| fail(format!("attestation: {e}")));
    println!(
        "attestation verified ({} · {} certs to pinned root · PCR0 + nonce + key bound)",
        doc.module_id,
        doc.cabundle_der.len() + 1
    );

    // The co-signature itself, under the PINNED enclave key.
    let sig_hex = resp
        .schnorr_sig_hex
        .as_deref()
        .unwrap_or_else(|| fail("accepted but returned no signature"));
    let sig: [u8; 64] = hex::decode(sig_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| fail("malformed signature (want 64 bytes)"));
    let xonly_pk = secp256k1::XOnlyPublicKey::from_slice(
        &hex::decode(&pinned.enclave_xonly_hex).unwrap_or_else(|_| fail("xonly pin is not hex")),
    )
    .unwrap_or_else(|_| fail("xonly pin is not a valid BIP-340 key"));
    let secp = secp256k1::Secp256k1::verification_only();
    secp.verify_schnorr(
        &secp256k1::schnorr::Signature::from_slice(&sig)
            .unwrap_or_else(|_| fail("signature is not valid BIP-340")),
        &secp256k1::Message::from_digest(digest),
        &xonly_pk,
    )
    .unwrap_or_else(|e| {
        fail(format!(
            "co-signature does not verify under the pinned key: {e}"
        ))
    });

    println!("PROBE PASS: gate + attestation + signature all verified");
}
