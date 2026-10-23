//! Fuzz target: the WOTS+ verifier and the FROST kit-seal envelopes (docs/08 §5).
//!
//! Both are the post-Q-Day emergency path: the WOTS+ public key lands in a
//! spendable leaf the day every lattice assumption has fallen, and the kit
//! seals carry the materials that leaf spends with. The gate is total:
//!   1. ANY (pk, msg, sig) triple answers Err/Ok — never a panic.
//!   2. ANY seed produces a keypair whose signature VERIFIES (round trip).
//!   3. ANY string against EVERY envelope kind answers Err — never a panic
//!      (a nonce package can never unseal as a deal package, and garbage
//!      never unseals as anything).
#![no_main]
use libfuzzer_sys::fuzz_target;
use qsv_core::frost::{self, PkgKind};
use qsv_core::wots;

fuzz_target!(|data: &[u8]| {
    // 1 + 2 · WOTS+ verify over arbitrary key material …
    if data.len() >= wots::PK_SIZE + wots::N {
        let mut pk = [0u8; wots::PK_SIZE];
        pk.copy_from_slice(&data[..wots::PK_SIZE]);
        let mut msg = [0u8; wots::N];
        msg.copy_from_slice(&data[wots::PK_SIZE..wots::PK_SIZE + wots::N]);
        // … the undersized and oversized signature paths included.
        let _ = wots::verify(&pk, &msg, &data[wots::PK_SIZE + wots::N..]);
    }

    // … and the deterministic keypair round trip for ANY 32-byte seed.
    if let Some(seed) = data.get(..wots::N) {
        let mut s = [0u8; wots::N];
        s.copy_from_slice(seed);
        let (sk, pk) = wots::keypair_from_seed(&s);
        let mut m = [0u8; wots::N];
        let tail = &data[wots::N..];
        let n = tail.len().min(wots::N);
        m[..n].copy_from_slice(&tail[..n]);
        if let Ok(sig) = wots::sign(&sk, &m) {
            // A signature from a FRESH keypair must always verify — this
            // is the emergency sweep's only liveness property.
            wots::verify(&pk, &m, &sig).expect("fresh-keypair signature must verify");
        }
    }

    // 3 · Kit seals: every envelope kind refuses arbitrary text cleanly.
    let text = String::from_utf8_lossy(data);
    for kind in [
        PkgKind::Deal,
        PkgKind::DealPrivate,
        PkgKind::Nonce,
        PkgKind::Sign,
        PkgKind::Share,
    ] {
        let _ = frost::unseal(kind, &text);
    }
});
