//! Fuzz target: the JSON surfaces that face the network and the disk
//! (docs/10 §4.19 frame protocol).
//!
//! Three parsers, all fed arbitrary bytes:
//!   · `SignRequest` — the frame that walks the wire on every
//!     co-signature request (the bridge deserializes it with
//!     `serde_json::from_slice` before ANY validation);
//!   · `BridgeHealth` — the health record `doctor` reads from disk
//!     (a tampered file must not crash the reader);
//!   · `parse_state` — the watchtower verdict file the alarm mirror
//!     re-reads on every request.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<qsv_cosigner::protocol::SignRequest>(data);
    let _ = serde_json::from_slice::<qsv_cosigner::BridgeHealth>(data);
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = qsv_cosigner::parse_state(s);
    }
});
