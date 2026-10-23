//! Unified bridge CLIENT (Round 16): one endpoint, one helper — the caller
//! picks the transport, the crate picks the plumbing.
//!
//! - [`BridgeClient::plain`] — loopback dev/drill transport (`request_
//!   signature` under the hood).
//! - [`BridgeClient::mtls`] — the PRODUCTION dev-bridge shape: pinned
//!   server root + REQUIRED client identity (docs/10 §3.6).
//!
//! `ask()` answers ONE question the operator surface asks BEFORE spending
//! time on a ceremony: may vault X sign right now? The three verdicts are
//! explicit — [`GateVerdict::Release`], [`GateVerdict::Frozen`] (the
//! watchtower alarm freeze) and [`GateVerdict::Refused`] (everything else:
//! unprovisioned vault, rate limit, bad proof, transport trouble) — so a
//! caller can never confuse "the gate is down" with "the gate said no".

use crate::protocol::{SignRequest, SignResponse};
use crate::server::{request_signature, request_signature_mtls, ServiceError};
use crate::tls::ClientIdentity;
use qsv_pqc::PqcIdentity;

/// How the client reaches the bridge.
pub enum BridgeTransport {
    /// Plain TCP (loopback drills).
    Plain,
    /// Mutual TLS: pinned server root + client certificate identity.
    Mtls {
        /// The pinned SERVER root (the bridge's CA/leaf, per the drill).
        roots: rustls::RootCertStore,
        /// The operator client identity the bridge's CA must trust.
        identity: ClientIdentity,
        /// The TLS SNI (e.g. "localhost").
        server_name: String,
    },
}

/// A reusable bridge client bound to ONE endpoint + transport.
pub struct BridgeClient {
    pub(crate) addr: String,
    pub(crate) transport: BridgeTransport,
}

impl BridgeClient {
    /// The endpoint this client talks to (operator reporting only).
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// A plain-TCP client (loopback drills).
    pub fn plain(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            transport: BridgeTransport::Plain,
        }
    }

    /// An mTLS client (pinned server root + client identity).
    pub fn mtls(
        addr: &str,
        roots: rustls::RootCertStore,
        identity: ClientIdentity,
        server_name: &str,
    ) -> Self {
        Self {
            addr: addr.to_string(),
            transport: BridgeTransport::Mtls {
                roots,
                identity,
                server_name: server_name.to_string(),
            },
        }
    }

    /// Sends ONE sign request and returns the raw response.
    pub fn send(&self, req: &SignRequest) -> Result<SignResponse, ServiceError> {
        match &self.transport {
            BridgeTransport::Plain => request_signature(&self.addr, req),
            BridgeTransport::Mtls {
                roots,
                identity,
                server_name,
            } => request_signature_mtls(&self.addr, req, server_name, roots.clone(), identity),
        }
    }

    /// The gate question: may `vault_id` sign RIGHT NOW? The probe digest
    /// is the zero hash ON PURPOSE — the gate decides BEFORE any sighash
    /// exists (the watchtower freeze and the allowlist do not depend on
    /// the request payload).
    pub fn ask(&self, vault_id: &str) -> Result<GateVerdict, ServiceError> {
        let digest = [0u8; 32];
        let pqc = PqcIdentity::from_seed(&[21u8; 32]);
        let req = SignRequest::new(
            vault_id,
            &digest,
            pqc.verifying_key_bytes(),
            &pqc.sign(&digest),
        );
        let resp = self.send(&req)?;
        if resp.accepted {
            return Ok(GateVerdict::Release);
        }
        let reason = resp
            .reason
            .as_deref()
            .unwrap_or("no reason given")
            .to_string();
        if reason.contains("watchtower alarm active") {
            Ok(GateVerdict::Frozen)
        } else {
            Ok(GateVerdict::Refused(reason))
        }
    }
}

/// The gate's answer to "may this vault sign right now?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateVerdict {
    /// The gate releases (proceed with the ceremony).
    Release,
    /// The watchtower freeze holds (skip this vault, report it).
    Frozen,
    /// Any OTHER refusal (unprovisioned, rate limit, bad proof…).
    Refused(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PROTOCOL_VERSION;

    /// ONE canned gate answer on a real socket: the REAL client dials,
    /// reads the REAL frame and parses the REAL JSON — only the server
    /// side is canned, the wire never is.
    fn canned(resp: SignResponse) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let _ = crate::vsock::read_frame(&mut s); // drain the request
                let body = serde_json::to_vec(&resp).expect("response serializes");
                let _ = crate::vsock::write_frame(&mut s, &body);
            }
        });
        addr
    }

    fn resp(accepted: bool, reason: Option<&str>) -> SignResponse {
        SignResponse {
            version: PROTOCOL_VERSION,
            accepted,
            reason: reason.map(str::to_string),
            schnorr_sig_hex: None,
            attestation_doc_hex: None,
        }
    }

    /// The three verdicts are EXPLICIT: a caller can never confuse "the
    /// gate is down" with "the gate said no".
    #[test]
    fn ask_distinguishes_release_frozen_and_refused() {
        let addr = canned(resp(true, None));
        assert_eq!(
            BridgeClient::plain(&addr).ask("v").unwrap(),
            GateVerdict::Release
        );

        let addr = canned(resp(false, Some("watchtower alarm active for vault v")));
        assert_eq!(
            BridgeClient::plain(&addr).ask("v").unwrap(),
            GateVerdict::Frozen
        );

        let addr = canned(resp(false, Some("vault not provisioned")));
        match BridgeClient::plain(&addr).ask("v").unwrap() {
            GateVerdict::Refused(reason) => {
                assert!(reason.contains("not provisioned"), "{reason}")
            }
            other => panic!("a plain refusal is Refused, got {other:?}"),
        }

        // A refusal WITHOUT a reason still yields a verdict (the default
        // text, never a panic).
        let addr = canned(resp(false, None));
        match BridgeClient::plain(&addr).ask("v").unwrap() {
            GateVerdict::Refused(reason) => assert_eq!(reason, "no reason given"),
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn addr_is_reported_verbatim_for_the_operator() {
        let c = BridgeClient::plain("127.0.0.1:3999");
        assert_eq!(c.addr(), "127.0.0.1:3999");
    }
}
