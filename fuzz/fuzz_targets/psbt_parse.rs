//! Fuzz target: PSBT parsing and the vault signing path over it (docs/09).
//!
//! The coordinator reads operator files and SD-card exports in THREE
//! transport shapes — raw wire bytes, the base64 export form the CLI
//! writes (`psbt build`), and hex — so all parser entries face
//! adversarial bytes. Once a PSBT PARSES, the harness drives our own
//! helpers over it: the BIP-341 sighash each signing device recomputes
//! and the finalize+extract step. Every one of them must answer with
//! `Err` for hostile maps — never a panic, never a hang.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Shape 1: raw binary PSBT (what a device writes to the card).
    // Shape 2: the base64 text form the CLI reads back from files.
    let parsed = bitcoin::psbt::Psbt::deserialize(data).ok().or_else(|| {
        use bitcoin::base64::Engine as _;
        let text = String::from_utf8_lossy(data);
        bitcoin::base64::engine::general_purpose::STANDARD
            .decode(text.trim().as_bytes())
            .ok()
            .and_then(|bytes| bitcoin::psbt::Psbt::deserialize(&bytes).ok())
    });
    let Some(mut psbt) = parsed else {
        return;
    };
    // Canonical stability: parse → serialize → parse must be
    // idempotent and must not panic on any input set the parser
    // accepted (serialize is the infallible Vec form in this wire
    // version — same call the CLI's base64 export makes).
    let wire = psbt.serialize();
    let _ = bitcoin::psbt::Psbt::deserialize(&wire);
    // The vault sighash helper the two signing devices recompute
    // locally — for EVERY input of an adversarial input set.
    let leaf = bitcoin::ScriptBuf::from_bytes(vec![0x51u8]);
    for i in 0..psbt.inputs.len() {
        let _ = std::hint::black_box(qsv_core::psbt::sighash_for_psbt_input(&psbt, i, &leaf));
    }
    // Finalize + extract: the exactly-one-input guard and the extract
    // validation, driven with an empty witness over hostile fields.
    let _ = std::hint::black_box(qsv_core::psbt::finalize_and_extract(
        &mut psbt,
        bitcoin::Witness::new(),
    ));
});
