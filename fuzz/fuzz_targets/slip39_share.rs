//! Fuzz target: SLIP-39 share decoding and combination (docs/04).
//!
//! Mnemonics arrive from a human (typing, OCR, a recovery sheet), so
//! the parser must answer with `Err` — never a panic — for ANY string.
//! `combine` additionally exercises the duplicate-index and threshold
//! guards: two copies of the SAME share are the cheapest way to hit
//! the interpolation-denominator path that must be refused.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Ok(share) = qsv_core::slip39::decode_share(&text) {
        // A decoded share must round-trip through the encoder without
        // panicking either — the pairs are what recovery combines.
        if let Ok(mnemonic) = qsv_core::slip39::encode_share_mnemonic(&share) {
            let _ = qsv_core::slip39::decode_share(&mnemonic);
        }
    }
    let owned = text.into_owned();
    let refs: [&str; 2] = [owned.as_str(), owned.as_str()];
    let _ = qsv_core::slip39::combine(&refs, "fuzz-passphrase");
});
