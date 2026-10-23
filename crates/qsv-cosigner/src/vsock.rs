//! Production transport for AWS Nitro Enclaves (Phase 1 prod): the same
//! length-prefixed JSON framing as the dev TCP server, carried over the
//! **vsock** AF_VSOCK address family instead of TCP.
//!
//! Addressing:
//! - **client side (parent/terminal)**: connects to the enclave's CID
//!   (context identifier — the value reported by
//!   `nitro-cli describe-enclaves`) on the co-signer's port.
//! - **enclave side (server)**: listens on ANY local CID, the same port.
//!
//! Inside the enclave build (`--features nsm`) this module uses real
//! AF_VSOCK sockets; in the dev build the same functions are provided over
//! loopback TCP so the whole ceremony (framing, handler, attestation
//! verification) is testable without a hypervisor. The one contract that
//! matters is unchanged: SignRequest in → attested SignResponse out.

use crate::protocol::{SignRequest, SignResponse};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};

/// Errors surfaced by the vsock layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VsockError {
    /// Socket creation/connect/bind failed.
    Io(String),
    /// The platform has no AF_VSOCK (dev build without the feature).
    Unsupported(String),
    /// Framing violated (oversized frame, truncated read, bad UTF-8).
    Malformed(String),
}

impl core::fmt::Display for VsockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VsockError::Io(s) => write!(f, "vsock I/O error: {s}"),
            VsockError::Unsupported(s) => write!(f, "vsock unsupported: {s}"),
            VsockError::Malformed(s) => write!(f, "malformed frame: {s}"),
        }
    }
}

impl std::error::Error for VsockError {}

/// Maximum accepted frame (the request carries a 3,309-byte ML-DSA sig;
/// 4 MiB is generous headroom and rejects garbage early).
pub const MAX_FRAME: u64 = 4 << 20;

/// One frame write: 8-byte big-endian length + payload.
pub fn write_frame(w: &mut impl Write, bytes: &[u8]) -> Result<(), VsockError> {
    let len = (bytes.len() as u64).to_be_bytes();
    w.write_all(&len)
        .and_then(|_| w.write_all(bytes))
        .map_err(|e| VsockError::Io(e.to_string()))
}

/// One frame read with the size cap.
pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, VsockError> {
    let mut len_buf = [0u8; 8];
    r.read_exact(&mut len_buf)
        .map_err(|e| VsockError::Io(e.to_string()))?;
    let len = u64::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(VsockError::Malformed(format!(
            "frame of {len} bytes exceeds the {MAX_FRAME} cap"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)
        .map_err(|e| VsockError::Io(e.to_string()))?;
    Ok(buf)
}

/// A connection endpoint: real vsock (enclave build) or loopback TCP (dev).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// AF_VSOCK: (cid, port).
    Vsock { cid: u32, port: u32 },
    /// Dev fallback: `127.0.0.1:<port>`.
    Tcp { port: u16 },
}

/// Special CIDs (linux/vm_sockets.h).
pub const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
pub const VMADDR_CID_HOST: u32 = 2;

#[cfg(feature = "nsm")]
mod real_vsock {
    //! AF_VSOCK via libc socket calls (enclave build only).
    use super::{VsockError, VMADDR_CID_ANY};
    use std::io::{Read, Write};
    use std::os::unix::io::RawFd;

    pub const AF_VSOCK: c_int = 40;
    pub const SOCK_STREAM: c_int = 1;

    #[repr(C)]
    struct SockaddrVsock {
        family: std::os::raw::c_ushort,
        reserved1: std::os::raw::c_ushort,
        port: std::os::raw::c_uint,
        cid: std::os::raw::c_uint,
    }

    #[allow(non_camel_case_types)]
    type c_int = std::os::raw::c_int;
    #[allow(non_camel_case_types)]
    type socklen_t = std::os::raw::c_uint;

    extern "C" {
        #[link_name = "socket"]
        fn sys_socket(domain: c_int, ty: c_int, protocol: c_int) -> RawFd;
        #[link_name = "connect"]
        fn sys_connect(fd: RawFd, addr: *const SockaddrVsock, len: socklen_t) -> c_int;
        #[link_name = "bind"]
        fn sys_bind(fd: RawFd, addr: *const SockaddrVsock, len: socklen_t) -> c_int;
        #[link_name = "listen"]
        fn sys_listen(fd: RawFd, backlog: c_int) -> c_int;
        #[link_name = "accept"]
        fn sys_accept(fd: RawFd, addr: *mut SockaddrVsock, len: *mut socklen_t) -> RawFd;
        #[link_name = "close"]
        fn sys_close(fd: RawFd) -> c_int;
        #[link_name = "read"]
        fn sys_read(fd: RawFd, buf: *mut core::ffi::c_void, count: usize) -> isize;
        #[link_name = "write"]
        fn sys_write(fd: RawFd, buf: *const core::ffi::c_void, count: usize) -> isize;
    }

    pub struct VsockStream(RawFd);

    impl Drop for VsockStream {
        fn drop(&mut self) {
            unsafe { sys_close(self.0) };
        }
    }

    impl Read for VsockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = unsafe { sys_read(self.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    impl Write for VsockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = unsafe { sys_write(self.0, buf.as_ptr().cast(), buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn addr(cid: u32, port: u32) -> SockaddrVsock {
        SockaddrVsock {
            family: AF_VSOCK as std::os::raw::c_ushort,
            reserved1: 0,
            port,
            cid,
        }
    }

    pub fn connect(cid: u32, port: u32) -> Result<VsockStream, VsockError> {
        let fd = unsafe { sys_socket(AF_VSOCK, SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(VsockError::Io(std::io::Error::last_os_error().to_string()));
        }
        let a = addr(cid, port);
        let rc = unsafe { sys_connect(fd, &a, std::mem::size_of::<SockaddrVsock>() as socklen_t) };
        if rc < 0 {
            unsafe { sys_close(fd) };
            return Err(VsockError::Io(std::io::Error::last_os_error().to_string()));
        }
        Ok(VsockStream(fd))
    }

    pub struct VsockListener(RawFd);

    impl Drop for VsockListener {
        fn drop(&mut self) {
            unsafe { sys_close(self.0) };
        }
    }

    pub fn bind_any(port: u32) -> Result<VsockListener, VsockError> {
        let fd = unsafe { sys_socket(AF_VSOCK, SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(VsockError::Io(std::io::Error::last_os_error().to_string()));
        }
        let a = addr(VMADDR_CID_ANY, port);
        let rc = unsafe { sys_bind(fd, &a, std::mem::size_of::<SockaddrVsock>() as socklen_t) };
        if rc < 0 {
            unsafe { sys_close(fd) };
            return Err(VsockError::Io(std::io::Error::last_os_error().to_string()));
        }
        if unsafe { sys_listen(fd, 8) } < 0 {
            unsafe { sys_close(fd) };
            return Err(VsockError::Io(std::io::Error::last_os_error().to_string()));
        }
        Ok(VsockListener(fd))
    }

    impl VsockListener {
        /// Accepts one connection (blocking).
        pub fn accept_one(&self) -> Result<VsockStream, VsockError> {
            let mut a: SockaddrVsock = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<SockaddrVsock>() as socklen_t;
            let fd = unsafe { sys_accept(self.0, &mut a, &mut len) };
            if fd < 0 {
                return Err(VsockError::Io(std::io::Error::last_os_error().to_string()));
            }
            Ok(VsockStream(fd))
        }
    }
}

/// Client half: one request → one response over the endpoint.
pub fn request_signature(ep: &Endpoint, req: &SignRequest) -> Result<SignResponse, VsockError> {
    let body = serde_json::to_vec(req).map_err(|e| VsockError::Malformed(e.to_string()))?;
    match ep {
        #[cfg(feature = "nsm")]
        Endpoint::Vsock { cid, port } => {
            let mut s = real_vsock::connect(*cid, *port)?;
            super::vsock::write_frame(&mut s, &body)?;
            let resp = super::vsock::read_frame(&mut s)?;
            serde_json::from_slice(&resp).map_err(|e| VsockError::Malformed(e.to_string()))
        }
        #[cfg(not(feature = "nsm"))]
        Endpoint::Vsock { .. } => Err(VsockError::Unsupported(
            "built without --features nsm; use Endpoint::Tcp or rebuild the enclave image".into(),
        )),
        Endpoint::Tcp { port } => {
            let mut s = std::net::TcpStream::connect(("127.0.0.1", *port))
                .map_err(|e| VsockError::Io(format!("127.0.0.1:{port}: {e}")))?;
            write_frame(&mut s, &body)?;
            let resp = read_frame(&mut s)?;
            serde_json::from_slice(&resp).map_err(|e| VsockError::Malformed(e.to_string()))
        }
    }
}

/// Server half: serve one connection with the cosigner handler. Returns the
/// serialized response (the caller writes it — keeps the loop testable).
pub fn handle_connection(
    stream: &mut impl Read,
    handler: impl FnOnce(&SignRequest) -> Result<SignResponse, crate::server::ServiceError>,
) -> Result<Vec<u8>, VsockError> {
    let frame = read_frame(stream)?;
    let req: SignRequest = serde_json::from_slice(&frame)
        .map_err(|e| VsockError::Malformed(format!("bad request json: {e}")))?;
    let resp = handler(&req).unwrap_or_else(|e| {
        // Fail-closed refusal with the reason surfaced (never a signature).
        SignResponse {
            version: crate::protocol::PROTOCOL_VERSION,
            accepted: false,
            reason: Some(e.to_string()),
            schnorr_sig_hex: None,
            attestation_doc_hex: None,
        }
    });
    serde_json::to_vec(&resp).map_err(|e| VsockError::Malformed(e.to_string()))
}

/// The enclave-side accept loop (REAL vsock, enclave build only).
#[cfg(feature = "nsm")]
pub fn serve_vsock(cosigner: crate::server::Cosigner, port: u32) -> Result<(), VsockError> {
    serve_vsock_limited(cosigner, port, u64::MAX)
}

/// NORMAL-EXITING vsock loop (Round 29 P5): serves `max_requests`
/// connections, then returns `Ok(())` so the enclave process exits 0 and
/// flushes its `.profraw` — a SIGKILL'd child never does, which is why
/// bounded children exist under `cargo llvm-cov`. `u64::MAX` keeps the
/// forever-server semantics of [`serve_vsock`].
#[cfg(feature = "nsm")]
pub fn serve_vsock_limited(
    cosigner: crate::server::Cosigner,
    port: u32,
    max_requests: u64,
) -> Result<(), VsockError> {
    let listener = real_vsock::bind_any(port)?;
    // RANGE loop (mirrors the dev TCP `serve_limited`): the back-edge runs
    // after every served connection — including the last — so the bounded
    // child's own profile data covers the loop before it exits 0.
    for _ in 0..max_requests {
        let mut s = listener.accept_one()?;
        let _ = handle_connection(&mut s, |req| cosigner.handle_request(req));
        // One request per connection (mirrors the dev TCP server).
        drop(s);
    }
    Ok(())
}

/// Accessor kept for tests/tools that need the raw fd contract.
pub fn raw_fd_of(stream: &mut impl AsRawFd) -> RawFd {
    stream.as_raw_fd()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PROTOCOL_VERSION;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    /// A handler as a FUNCTION ITEM that counts its calls: the malformed
    /// request test proves the parse wall skipped it (counter unchanged),
    /// and the well-formed half proves the counter moves when a request
    /// DOES reach it — the invariant is comparative, not aspirational.
    static HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
    fn counted_handler(_req: &SignRequest) -> Result<SignResponse, crate::server::ServiceError> {
        HANDLER_CALLS.fetch_add(1, AtomicOrdering::SeqCst);
        Ok(SignResponse {
            version: PROTOCOL_VERSION,
            accepted: false,
            reason: Some("counted".into()),
            schnorr_sig_hex: None,
            attestation_doc_hex: None,
        })
    }

    #[test]
    fn framing_roundtrips_and_caps_oversize() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello vsock").unwrap();
        let mut rd = buf.as_slice();
        assert_eq!(read_frame(&mut rd).unwrap(), b"hello vsock");

        // Oversize frame rejected before allocation.
        let mut big = Vec::new();
        write_frame(&mut big, &[0u8; 8]).unwrap();
        big[..8].copy_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        let mut rd = big.as_slice();
        assert!(matches!(read_frame(&mut rd), Err(VsockError::Malformed(_))));

        // Exactly AT the cap is LEGAL (the cap is exclusive) — a full
        // MAX_FRAME-byte payload must round-trip. The Round-32 sweep's
        // `>`→`>=` flip refused exactly-cap frames until this was pinned.
        let exact = vec![0u8; MAX_FRAME as usize];
        let mut buf = Vec::new();
        write_frame(&mut buf, &exact).unwrap();
        let mut rd = buf.as_slice();
        assert_eq!(read_frame(&mut rd).unwrap().len(), MAX_FRAME as usize);
    }

    #[test]
    fn connection_handler_fails_closed_without_a_signature() {
        let req = SignRequest {
            version: PROTOCOL_VERSION,
            vault_id: "bc1punknown".into(),
            sighash_hex: hex::encode([0u8; 32]),
            pqc_vk_hex: hex::encode(vec![0u8; 1952]),
            pqc_sig_hex: hex::encode(vec![0u8; 3309]),
            nonce_hex: hex::encode([0u8; 32]),
        };
        let json = serde_json::to_vec(&req).unwrap();
        let mut framed = Vec::new();
        write_frame(&mut framed, &json).unwrap();
        let mut stream = std::io::Cursor::new(framed);
        let resp = handle_connection(&mut stream, |r| {
            crate::server::Cosigner::provision([0u8; 32], vec!["bc1pok".into()]).handle_request(r)
        })
        .unwrap();
        let r: SignResponse = serde_json::from_slice(&resp).unwrap();
        assert!(!r.accepted);
        assert!(r.schnorr_sig_hex.is_none());
        assert!(r.attestation_doc_hex.is_none());
    }

    #[test]
    fn dev_tcp_endpoint_end_to_end() {
        // Dev build: Endpoint::Tcp drives the SAME framing over loopback.
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let body = handle_connection(&mut s, |r| {
                crate::server::Cosigner::provision([42u8; 32], vec!["bc1pok".into()])
                    .handle_request(r)
            })
            .unwrap();
            write_frame(&mut s, &body).unwrap();
        });
        let pqc = qsv_pqc::PqcIdentity::from_seed(&[11u8; 32]);
        let sighash = [0xA9u8; 32];
        let req = SignRequest::new(
            "bc1pok",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let resp = request_signature(&Endpoint::Tcp { port }, &req).unwrap();
        assert!(resp.accepted);
        assert!(resp.schnorr_sig_hex.is_some());
        server.join().unwrap();
    }

    #[test]
    fn vsock_endpoint_is_refused_without_the_feature() {
        // Dev build: a Vsock endpoint must be refused loudly, not silently
        // downgraded to TCP. Enclave build (nsm): the real AF_VSOCK connect
        // against the host CID fails with an I/O error (no vsock stack in
        // CI) — either way the request NEVER silently succeeds.
        let pqc = qsv_pqc::PqcIdentity::from_seed(&[11u8; 32]);
        let sighash = [0xA8u8; 32];
        let req = SignRequest::new(
            "bc1pok",
            &sighash,
            pqc.verifying_key_bytes(),
            &pqc.sign(&sighash),
        );
        let e = request_signature(
            &Endpoint::Vsock {
                cid: VMADDR_CID_HOST,
                port: 5000,
            },
            &req,
        )
        .unwrap_err();
        #[cfg(feature = "nsm")]
        assert!(matches!(e, VsockError::Io(_)));
        #[cfg(not(feature = "nsm"))]
        assert!(matches!(e, VsockError::Unsupported(_)));
    }

    /// Every variant renders its category — an operator grepping a log for
    /// "malformed frame" must never see a bare payload.
    #[test]
    fn every_vsock_error_formats_with_its_category() {
        assert_eq!(
            VsockError::Io("boom".into()).to_string(),
            "vsock I/O error: boom"
        );
        assert_eq!(
            VsockError::Unsupported("no AF_VSOCK".into()).to_string(),
            "vsock unsupported: no AF_VSOCK"
        );
        assert_eq!(
            VsockError::Malformed("truncated".into()).to_string(),
            "malformed frame: truncated"
        );
    }

    /// A well-framed but NON-JSON request must be refused as malformed
    /// BEFORE the handler ever runs (fail-closed at the parse boundary),
    /// and the raw-fd accessor hands back a live descriptor.
    #[test]
    fn malformed_request_json_never_reaches_the_handler() {
        let mut framed = Vec::new();
        write_frame(&mut framed, b"not json at all").unwrap();
        let mut stream = std::io::Cursor::new(framed);
        let before = HANDLER_CALLS.load(AtomicOrdering::SeqCst);
        let e = handle_connection(&mut stream, counted_handler).unwrap_err();
        assert!(matches!(e, VsockError::Malformed(_)), "{e:?}");
        assert_eq!(
            HANDLER_CALLS.load(AtomicOrdering::SeqCst),
            before,
            "handler must not run for a non-JSON request"
        );

        // The SAME handler on a WELL-formed request runs exactly once —
        // proving the counter COULD have moved (the skip above is the
        // parse wall, not an unreachable handler).
        let req = {
            let pqc = qsv_pqc::PqcIdentity::from_seed(&[11u8; 32]);
            let sighash = [0xA8u8; 32];
            SignRequest::new(
                "bc1pok",
                &sighash,
                pqc.verifying_key_bytes(),
                &pqc.sign(&sighash),
            )
        };
        let mut framed = Vec::new();
        write_frame(&mut framed, &serde_json::to_vec(&req).unwrap()).unwrap();
        let mut stream = std::io::Cursor::new(framed);
        let out = handle_connection(&mut stream, counted_handler).unwrap();
        assert!(!out.is_empty(), "a well-formed request gets a response");
        assert_eq!(
            HANDLER_CALLS.load(AtomicOrdering::SeqCst),
            before + 1,
            "a well-formed request must reach the handler"
        );

        use std::net::TcpListener;
        let mut listener = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(raw_fd_of(&mut listener) >= 0, "live fd expected");
    }

    /// A handler FAULT becomes a refusal carrying the reason — never a
    /// signature, never a connection dropped without an answer.
    #[test]
    fn a_handler_fault_becomes_a_refusal_never_a_signature() {
        let req = {
            let pqc = qsv_pqc::PqcIdentity::from_seed(&[12u8; 32]);
            let sighash = [0x5Cu8; 32];
            SignRequest::new(
                "bc1pok",
                &sighash,
                pqc.verifying_key_bytes(),
                &pqc.sign(&sighash),
            )
        };
        let mut framed = Vec::new();
        write_frame(&mut framed, &serde_json::to_vec(&req).unwrap()).unwrap();
        let mut stream = std::io::Cursor::new(framed);
        let out = handle_connection(&mut stream, |_r| {
            Err(crate::server::ServiceError::Rejected(
                "policy said no".into(),
            ))
        })
        .unwrap();
        let resp: SignResponse = serde_json::from_slice(&out).unwrap();
        assert!(!resp.accepted, "a fault is never a signature");
        assert!(
            resp.reason.unwrap().contains("policy said no"),
            "the operator sees WHY"
        );
        assert!(resp.schnorr_sig_hex.is_none());
        assert_eq!(resp.version, PROTOCOL_VERSION);
    }
}
