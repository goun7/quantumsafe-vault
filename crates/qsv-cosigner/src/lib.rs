//! QuantumSafe-Vault enclave co-signer service.
//!
//! Theorem 1 as a service: the co-signer releases its BIP-340 Schnorr
//! signature over a sighash if and only if a valid ML-DSA-65 signature over
//! the same sighash is presented by the client. Deterministic, fail-closed,
//! zero human interaction.

pub mod bridge;
pub mod client;
pub mod health;
pub mod notify;
pub mod nsm;
pub mod protocol;
pub mod server;
pub mod tls;
pub mod vsock;

pub use bridge::{
    apply_verdicts, load_state, parse_state, quorum_verdicts, AlarmAction, BridgeOutcome,
    WatchtowerVerdicts,
};
pub use client::{BridgeClient, BridgeTransport, GateVerdict};
pub use health::{health_path, BridgeHealth, Liveness};
pub use notify::{from_env as notify_from_env, spawn_watchdog, watchdog_interval, NotifySocket};
pub use protocol::{AttestationDoc, SignRequest, SignResponse, PROTOCOL_VERSION};
#[cfg(unix)]
pub use server::{install_reload_handler, reload_requested};
pub use server::{
    request_signature, request_signature_mtls, request_signature_tls, serve, serve_listener,
    serve_shared, serve_with_mirror, serve_with_mirror_and_shutdown, serve_with_mtls_mirror,
    serve_with_tls_mirror, serve_with_tls_mirror_and_shutdown, AlarmState, Cosigner, Metrics,
    RateLimitPolicy, ScrapeToken, ServePolicy, ServiceError, Shutdown, VaultCounters,
};
pub use tls::{
    client_identity, require_metrics_token_off_loopback, require_tls_or_loopback,
    tls_listener_config, tls_listener_config_with_client_auth, ClientIdentity, LoopbackPolicyError,
    TlsListenerConfig,
};
pub use vsock::{Endpoint, VsockError};

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }
}
