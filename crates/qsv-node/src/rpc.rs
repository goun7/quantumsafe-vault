//! Minimal JSON-RPC 1.0 client for a local bitcoind — real chain reads only.
//!
//! Scope: the read-only methods the operator surfaces need
//! (`getblockcount`, `getbestblockhash`, `gettxout`, `getrawtransaction`).
//! No wallet access, no signing, no state change: the client is
//! deliberately incapable of moving funds.
//!
//! No fake data: connection or RPC errors are surfaced verbatim so the
//! operator sees "no node" instead of a fabricated number.

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// Cookie file missing/unreadable — usually "node not running".
    Auth(String),
    /// TCP connect/write/read failure.
    Io(String),
    /// Node returned a JSON-RPC error object.
    Rpc { code: i64, message: String },
    /// Response was not valid JSON-RPC.
    Malformed(String),
}

impl core::fmt::Display for RpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RpcError::Auth(s) => write!(f, "RPC auth unavailable: {s}"),
            RpcError::Io(s) => write!(f, "RPC connection failed: {s}"),
            RpcError::Rpc { code, message } => write!(f, "node error {code}: {message}"),
            RpcError::Malformed(s) => write!(f, "malformed RPC response: {s}"),
        }
    }
}

impl std::error::Error for RpcError {}

/// Read budget for ordinary calls (status, tips, balances): these answer
/// in milliseconds, so a short budget surfaces a dead node fast.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Read budget for `scantxoutset start`: bitcoind blocks THAT connection
/// until the entire UTXO set has been walked. On regtest that is instant;
/// on signet/mainnet it takes minutes — a 10 s budget used to kill every
/// live scan on a real network with `Resource temporarily unavailable`.
const SCAN_READ_TIMEOUT: Duration = Duration::from_secs(600);

/// A read-only connection to one bitcoind's JSON-RPC over TCP with cookie
/// authentication.
pub struct BitcoinRpc {
    host: String,
    port: u16,
    auth_header: String,
}

/// Where to find the node: explicit params or a datadir cookie file.
pub enum NodeEndpoint {
    /// host, port, username, password (explicit credentials).
    Explicit(String, u16, String, String),
    /// Read `<datadir>/regtest/.cookie` (or `<datadir>/.cookie`) and the
    /// port embedded in that file's `user:pass` is derived from the standard
    /// per-network defaults plus the cookie credentials.
    Cookie { datadir: PathBuf, network: Network },
}

/// Networks with standard RPC ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    /// Standard RPC port per network (regtest/signet share testnet defaults
    /// only when the cookie supplies no port; the cookie normally encodes it).
    pub fn default_rpc_port(self) -> u16 {
        match self {
            Network::Bitcoin => 8332,
            Network::Testnet => 18332,
            Network::Signet => 38332,
            Network::Regtest => 18443,
        }
    }
}

impl BitcoinRpc {
    /// Connect to an explicit host/port with user/password credentials.
    pub fn connect(host: &str, port: u16, user: &str, password: &str) -> Result<Self, RpcError> {
        Ok(Self {
            host: host.to_string(),
            port,
            auth_header: format!("Basic {}", base64_basic(&format!("{user}:{password}"))),
        })
    }

    /// Reads the cookie credentials under `datadir` (network subdir first).
    fn read_cookie_creds(
        datadir: &std::path::Path,
        network: Network,
    ) -> Result<(String, String), RpcError> {
        let candidates = [
            datadir.join(network_debug_name(network)).join(".cookie"),
            datadir.join(".cookie"),
        ];
        let cookie = candidates.iter().find(|p| p.is_file()).ok_or_else(|| {
            RpcError::Auth(format!(
                "no .cookie file under {} (is the node running?)",
                datadir.display()
            ))
        })?;
        let raw = std::fs::read_to_string(cookie)
            .map_err(|e| RpcError::Auth(format!("cannot read {}: {e}", cookie.display())))?;
        raw.trim_end()
            .split_once(':')
            .map(|(u, p)| (u.to_string(), p.to_string()))
            .ok_or_else(|| RpcError::Auth("malformed cookie file".into()))
    }

    /// Resolve a [`NodeEndpoint`] into a connection (reads the cookie file).
    pub fn from_endpoint(ep: &NodeEndpoint) -> Result<Self, RpcError> {
        match ep {
            NodeEndpoint::Explicit(host, port, user, pass) => {
                Self::connect(host, *port, user, pass)
            }
            NodeEndpoint::Cookie { datadir, network } => {
                let (user, pass) = Self::read_cookie_creds(datadir, *network)?;
                Self::connect("127.0.0.1", network.default_rpc_port(), &user, &pass)
            }
        }
    }

    /// Cookie credentials + an EXPLICIT port. Needed when the node was
    /// started on a non-default RPC port (the `bitcoind` test harness picks
    /// a random free port per instance).
    pub fn from_cookie_with_port(
        datadir: &std::path::Path,
        network: Network,
        port: u16,
    ) -> Result<Self, RpcError> {
        let (user, pass) = Self::read_cookie_creds(datadir, network)?;
        Self::connect("127.0.0.1", port, &user, &pass)
    }

    /// Issue one JSON-RPC 1.0 request on `path` with the default read budget.
    fn post(&self, path: &str, method: &str, params: &[Value]) -> Result<Value, RpcError> {
        self.post_with_timeout(path, method, params, DEFAULT_READ_TIMEOUT)
    }

    /// Issue one JSON-RPC 1.0 request on `path` with an explicit read
    /// budget and extract the `result` field.
    fn post_with_timeout(
        &self,
        path: &str,
        method: &str,
        params: &[Value],
        read_timeout: Duration,
    ) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "qsv",
            "method": method,
            "params": params,
        })
        .to_string();

        let mut stream = TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|e| RpcError::Io(format!("{}:{}: {e}", self.host, self.port)))?;
        stream
            .set_read_timeout(Some(read_timeout))
            .map_err(|e| RpcError::Io(e.to_string()))?;
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.host,
            self.auth_header,
            body.len(),
            body
        );
        stream
            .write_all(req.as_bytes())
            .map_err(|e| RpcError::Io(e.to_string()))?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| RpcError::Io(e.to_string()))?;
        let text = String::from_utf8_lossy(&response);

        // Split headers from the JSON body (HTTP/1.1 from bitcoind always
        // carries a JSON object after the blank line).
        let json_part = text
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or(&text);
        let v: Value = serde_json::from_str(json_part.trim())
            .map_err(|e| RpcError::Malformed(e.to_string()))?;
        if let Some(err) = v.get("error") {
            if !err.is_null() {
                return Err(RpcError::Rpc {
                    code: err["code"].as_i64().unwrap_or(-1),
                    message: err["message"].as_str().unwrap_or("unknown").to_string(),
                });
            }
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Issue one JSON-RPC 1.0 request on the root path (chain namespace).
    pub fn call(&self, method: &str, params: &[Value]) -> Result<Value, RpcError> {
        self.post("/", method, params)
    }

    /// Issue one JSON-RPC 1.0 request on a WALLET endpoint
    /// (`/wallet/<name>`). Bitcoin Core routes wallet methods —
    /// `importdescriptors`, `listunspent`, … — through that path: the root
    /// endpoint answers wallet methods only when exactly one wallet is
    /// loaded, and otherwise pins to the node's startup `-wallet=`. The
    /// name is placed in the URL path verbatim, so callers pass a plain
    /// ASCII wallet name (the harness and QSV both use simple identifiers).
    pub fn call_wallet(
        &self,
        wallet: &str,
        method: &str,
        params: &[Value],
    ) -> Result<Value, RpcError> {
        self.post(&format!("/wallet/{wallet}"), method, params)
    }

    /// One chain-namespace request with a custom read budget (long-running
    /// calls such as `scantxoutset start`).
    fn call_with_timeout(
        &self,
        method: &str,
        params: &[Value],
        read_timeout: Duration,
    ) -> Result<Value, RpcError> {
        self.post_with_timeout("/", method, params, read_timeout)
    }

    /// Current chain tip height (`getblockcount`).
    pub fn getblockcount(&self) -> Result<u32, RpcError> {
        self.call("getblockcount", &[]).and_then(|v| {
            v.as_u64()
                .map(|n| n as u32)
                .ok_or_else(|| RpcError::Malformed("getblockcount: not a number".into()))
        })
    }

    /// Best block hash (`getbestblockhash`).
    pub fn getbestblockhash(&self) -> Result<String, RpcError> {
        self.call("getbestblockhash", &[]).and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or_else(|| RpcError::Malformed("getbestblockhash: not a string".into()))
        })
    }

    /// Finds confirmed UTXOs paying `address` via the CHAIN-namespace
    /// `scantxoutset` (descriptor `addr(…)`): no wallet ownership required —
    /// the vault address deliberately lives OUTSIDE any wallet. Returns up
    /// to `limit` (outpoint, value) pairs, largest value first. Only
    /// confirmed coins are ever returned (the UTXO set has no mempool).
    pub fn scan_utxos_for_address(
        &self,
        address: &str,
        limit: usize,
    ) -> Result<Vec<(bitcoin::OutPoint, bitcoin::Amount)>, RpcError> {
        let scan = json!([{ "desc": format!("addr({address})") }]);
        let start = || [json!("start"), scan.clone()];
        let result = match self.call_with_timeout("scantxoutset", &start(), SCAN_READ_TIMEOUT) {
            Ok(r) => r,
            // Another scan owns the scanner (possibly one whose client
            // vanished mid-scan): wait for it to finish, then start ours.
            // The wait is bounded — a wedged scanner fails closed.
            Err(RpcError::Rpc { code: -8, message })
                if message.contains("Scan already in progress") =>
            {
                self.wait_for_idle_scanner(SCAN_READ_TIMEOUT)?;
                self.call_with_timeout("scantxoutset", &start(), SCAN_READ_TIMEOUT)?
            }
            Err(e) => return Err(e),
        };
        if !result
            .get("success")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(RpcError::Malformed(
                "scantxoutset: scan failed (another scan may be running)".into(),
            ));
        }
        let empty = Vec::new();
        let unspents = result
            .get("unspents")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let mut out = Vec::new();
        for u in unspents {
            let (Some(txid), Some(vout), Some(amount)) = (
                u.get("txid").and_then(Value::as_str),
                u.get("vout").and_then(Value::as_u64),
                u.get("amount").and_then(Value::as_f64),
            ) else {
                continue;
            };
            let txid: bitcoin::Txid = txid
                .parse()
                .map_err(|_| RpcError::Malformed("scantxoutset: bad txid".into()))?;
            let sats = (amount * 100_000_000.0).round() as u64;
            out.push((
                bitcoin::OutPoint::new(txid, vout as u32),
                bitcoin::Amount::from_sat(sats),
            ));
            if out.len() >= limit {
                break;
            }
        }
        out.sort_by_key(|(_, a)| std::cmp::Reverse(*a));
        Ok(out)
    }

    /// Poll `scantxoutset status` until the node reports no scan running
    /// (`false`) or the budget runs out. An object `{"progress": …}` means
    /// a scan is still in flight.
    fn wait_for_idle_scanner(&self, budget: Duration) -> Result<(), RpcError> {
        let deadline = std::time::Instant::now() + budget;
        loop {
            let status = self.call("scantxoutset", &[json!("status")])?;
            if status.is_boolean() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(RpcError::Rpc {
                    code: -8,
                    message: format!(
                        "scantxoutset: another scan still running after {}s (fail-closed)",
                        budget.as_secs()
                    ),
                });
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }
}

fn network_debug_name(n: Network) -> &'static str {
    match n {
        Network::Bitcoin => "",
        Network::Testnet => "testnet3",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

/// Minimal base64 (RFC 4648) for the Basic auth header — no extra dependency.
fn base64_basic(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64_basic("user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64_basic("a"), "YQ==");
        assert_eq!(base64_basic("ab"), "YWI=");
        assert_eq!(base64_basic("abc"), "YWJj");
        assert_eq!(base64_basic("__cookie__:"), "X19jb29raWVfXzo=");
    }

    #[test]
    fn rpc_error_display_is_actionable() {
        let e = RpcError::Auth("no .cookie under /tmp/x".into());
        assert!(e.to_string().contains("no .cookie"));
        let e = RpcError::Rpc {
            code: -18,
            message: "Requested wallet does not exist".into(),
        };
        assert!(e.to_string().contains("-18"));
    }

    use std::io::{Read, Write};

    /// ONE canned HTTP/JSON-RPC response on a real local socket — the REAL
    /// client parses it (headers, body split, JSON); only the server side
    /// is canned, the transport never is.
    fn one_shot(body: &str) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 16_384];
                let _ = s.read(&mut buf);
                let _ = s.write_all(resp.as_bytes());
            }
        });
        port
    }

    fn rpc_at(port: u16) -> BitcoinRpc {
        BitcoinRpc::connect("127.0.0.1", port, "user", "pass").unwrap()
    }

    /// Like [`one_shot`], but also records the raw REQUEST — canned
    /// responses never validate what was sent, and bitcoind does.
    fn one_shot_captured(body: &str) -> (u16, std::sync::Arc<std::sync::Mutex<String>>) {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let slot = captured.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 16_384];
                let n = s.read(&mut buf).unwrap_or(0);
                *slot.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).into_owned();
                let _ = s.write_all(resp.as_bytes());
            }
        });
        (port, captured)
    }

    /// A server that answers EACH connection with the next canned response,
    /// optionally sleeping before writing (to model a slow, blocking call
    /// such as a minutes-long `scantxoutset start` on a real network).
    fn scripted(responses: Vec<(Duration, String)>) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for (delay, body) in responses {
                if let Ok((mut s, _)) = listener.accept() {
                    let mut buf = [0u8; 16_384];
                    let _ = s.read(&mut buf);
                    if !delay.is_zero() {
                        std::thread::sleep(delay);
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = s.write_all(resp.as_bytes());
                }
            }
        });
        port
    }

    #[test]
    fn scan_outlives_the_default_budget_and_recovers_from_a_foreign_scan() {
        let ok = format!(
            r#"{{"result":{{"success":true,"unspents":[
                {{"txid":"{}","vout":0,"amount":0.25}}
            ]}},"error":null,"id":"qsv"}}"#,
            "44".repeat(32)
        );

        // 1) A scan that takes LONGER than the ordinary 10 s read budget
        //    still succeeds — a real-network scantxoutset blocks the
        //    calling connection for minutes (regtest never showed this).
        let port = scripted(vec![(Duration::from_secs(11), ok.clone())]);
        let out = rpc_at(port)
            .scan_utxos_for_address("tb1pexample", 5)
            .unwrap();
        assert_eq!(out.len(), 1, "the slow scan's result must parse");

        // 2) A foreign scan owns the scanner (-8): poll status (idle),
        //    then start OUR scan — never a fabricated result in between.
        let busy = r#"{"result":null,"error":{"code":-8,"message":"Scan already in progress, use action \"abort\" or \"status\""},"id":"qsv"}"#;
        let idle = r#"{"result":false,"error":null,"id":"qsv"}"#;
        let port = scripted(vec![
            (Duration::ZERO, busy.to_string()),
            (Duration::ZERO, idle.to_string()),
            (Duration::ZERO, ok),
        ]);
        let out = rpc_at(port)
            .scan_utxos_for_address("tb1pexample", 5)
            .unwrap();
        assert_eq!(out.len(), 1, "retry after the foreign scan starts clean");
    }

    #[test]
    fn scan_wire_shape_carries_an_array_scanobjects() {
        // bitcoind REJECTS an object where it expects an array of
        // scanobjects (-3); a canned response would have hidden that.
        let ok = r#"{"result":{"success":true,"unspents":[]},"error":null,"id":"qsv"}"#;
        let (port, captured) = one_shot_captured(ok);
        rpc_at(port).scan_utxos_for_address("tb1pwire", 5).unwrap();
        let req = captured.lock().unwrap().clone();
        let body = req
            .split_once("\r\n\r\n")
            .map(|(_, b)| b)
            .unwrap_or(&req)
            .trim();
        let v: Value = serde_json::from_str(body).expect("request must be JSON");
        let params = v.get("params").expect("params present");
        assert_eq!(params[0], "start");
        assert!(
            params[1].is_array(),
            "scanobjects must be an ARRAY on the wire, got {}",
            params[1]
        );
        assert_eq!(params[1][0]["desc"], "addr(tb1pwire)");
    }

    #[test]
    fn post_surfaces_node_errors_malformed_and_io_failures() {
        // JSON-RPC error object → Rpc { code, message }, verbatim.
        let port = one_shot(
            r#"{"result":null,"error":{"code":-18,"message":"Requested wallet does not exist"},"id":"qsv"}"#,
        );
        let err = rpc_at(port).call("listwallets", &[]).unwrap_err();
        assert_eq!(
            err,
            RpcError::Rpc {
                code: -18,
                message: "Requested wallet does not exist".into()
            }
        );
        assert_eq!(
            err.to_string(),
            "node error -18: Requested wallet does not exist"
        );

        // Garbage body → Malformed (fail closed, never a fabricated number).
        let port = one_shot("<html>not json</html>");
        let err = rpc_at(port).call("getblockcount", &[]).unwrap_err();
        assert!(matches!(err, RpcError::Malformed(_)));
        assert!(err.to_string().contains("malformed RPC response"));

        // Connection refused → Io ("no node", not a fake value).
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        let err = rpc_at(dead_port).getblockcount().unwrap_err();
        assert!(matches!(err, RpcError::Io(_)));
        assert!(err.to_string().contains("RPC connection failed"));
    }

    #[test]
    fn typed_getters_refuse_wrong_shapes() {
        // An EXPLICIT endpoint needs no cookie file (the connection is
        // lazy — credentials are formatted, nothing dials yet).
        let rpc = BitcoinRpc::from_endpoint(&NodeEndpoint::Explicit(
            "127.0.0.1".into(),
            18444,
            "user".into(),
            "pass".into(),
        ))
        .unwrap();
        assert_eq!(rpc.port, 18444, "the explicit port must be honored");

        // A response with NO "error" member at all (a stripping proxy):
        // still a success, never a fabricated error.
        let port = one_shot(r#"{"result":7,"id":"qsv"}"#);
        assert_eq!(rpc_at(port).getblockcount().unwrap(), 7);

        let port = one_shot(r#"{"result":"not-a-number","error":null,"id":"qsv"}"#);
        assert!(matches!(
            rpc_at(port).getblockcount(),
            Err(RpcError::Malformed(_))
        ));
        let port = one_shot(r#"{"result":42,"error":null,"id":"qsv"}"#);
        assert!(matches!(
            rpc_at(port).getbestblockhash(),
            Err(RpcError::Malformed(_))
        ));
        // Happy shapes parse verbatim.
        let port = one_shot(r#"{"result":123,"error":null,"id":"qsv"}"#);
        assert_eq!(rpc_at(port).getblockcount().unwrap(), 123);
        let port = one_shot(r#"{"result":"00ff","error":null,"id":"qsv"}"#);
        assert_eq!(rpc_at(port).getbestblockhash().unwrap(), "00ff");
    }

    #[test]
    fn scantxoutset_parses_sorts_limits_and_fails_closed() {
        let body = format!(
            r#"{{"result":{{"success":true,"unspents":[
                {{"txid":"{}","vout":0,"amount":0.5}},
                {{"txid":"{}","vout":1,"amount":1.25}},
                {{"txid":"{}","vout":2,"amount":0.01}},
                {{"vout":3,"amount":9.99}}
            ]}},"error":null,"id":"qsv"}}"#,
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32)
        );

        let port = one_shot(&body);
        let out = rpc_at(port)
            .scan_utxos_for_address("bcrt1qexample", 10)
            .unwrap();
        assert_eq!(out.len(), 3, "field-less entry is skipped, not invented");
        assert!(
            out[0].1 >= out[1].1 && out[1].1 >= out[2].1,
            "largest first"
        );
        assert_eq!(out[0].1, bitcoin::Amount::from_sat(125_000_000));

        let port = one_shot(&body);
        let out = rpc_at(port)
            .scan_utxos_for_address("bcrt1qexample", 2)
            .unwrap();
        assert_eq!(out.len(), 2, "limit is honored");

        // success:false → fail closed (another scan / refused).
        let port = one_shot(r#"{"result":{"success":false},"error":null,"id":"qsv"}"#);
        assert!(matches!(
            rpc_at(port).scan_utxos_for_address("x", 5),
            Err(RpcError::Malformed(_))
        ));

        // Unparseable txid → fail closed, never a wrong outpoint.
        let port = one_shot(
            r#"{"result":{"success":true,"unspents":[{"txid":"zz","vout":0,"amount":1.0}]},"error":null,"id":"qsv"}"#,
        );
        assert!(matches!(
            rpc_at(port).scan_utxos_for_address("x", 5),
            Err(RpcError::Malformed(_))
        ));

        // The RPC CALL itself failing (no node) surfaces as Io — the
        // `?` on the call is its own error path, not a fabricated scan.
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_port = dead.local_addr().unwrap().port();
        drop(dead);
        assert!(matches!(
            rpc_at(dead_port).scan_utxos_for_address("x", 5),
            Err(RpcError::Io(_))
        ));
    }

    #[test]
    fn cookie_endpoint_resolution_and_default_ports() {
        // Every network maps to its standard RPC port.
        assert_eq!(Network::Bitcoin.default_rpc_port(), 8332);
        assert_eq!(Network::Testnet.default_rpc_port(), 18332);
        assert_eq!(Network::Signet.default_rpc_port(), 38332);
        assert_eq!(Network::Regtest.default_rpc_port(), 18443);

        let dir = tempfile::tempdir().unwrap();
        // Missing cookie → Auth ("is the node running?"), never a guess.
        let err = BitcoinRpc::from_endpoint(&NodeEndpoint::Cookie {
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
        })
        .err()
        .expect("missing cookie must fail closed");
        assert!(matches!(err, RpcError::Auth(_)));
        assert!(err.to_string().contains("is the node running?"));

        // Network subdir cookie resolves (regtest).
        std::fs::create_dir_all(dir.path().join("regtest")).unwrap();
        std::fs::write(dir.path().join("regtest/.cookie"), "user:pass\n").unwrap();
        BitcoinRpc::from_endpoint(&NodeEndpoint::Cookie {
            datadir: dir.path().to_path_buf(),
            network: Network::Regtest,
        })
        .unwrap();

        // Top-level cookie resolves (bitcoin: empty network dir name).
        std::fs::write(dir.path().join(".cookie"), "u2:p2").unwrap();
        BitcoinRpc::from_endpoint(&NodeEndpoint::Cookie {
            datadir: dir.path().to_path_buf(),
            network: Network::Bitcoin,
        })
        .unwrap();

        // Malformed cookie (no colon) → Auth, not a bogus credential pair.
        let dir2 = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir2.path().join("signet")).unwrap();
        std::fs::write(dir2.path().join("signet/.cookie"), "nocolon").unwrap();
        let err = BitcoinRpc::from_endpoint(&NodeEndpoint::Cookie {
            datadir: dir2.path().to_path_buf(),
            network: Network::Signet,
        })
        .err()
        .expect("malformed cookie must fail closed");
        assert!(matches!(err, RpcError::Auth(_)));
        assert!(err.to_string().contains("malformed cookie file"));

        // testnet3 subdir + explicit-port variant.
        let dir3 = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir3.path().join("testnet3")).unwrap();
        std::fs::write(dir3.path().join("testnet3/.cookie"), "u:p").unwrap();
        BitcoinRpc::from_cookie_with_port(dir3.path(), Network::Testnet, 18_332).unwrap();

        // Explicit endpoint arm.
        BitcoinRpc::connect("127.0.0.1", 1, "user", "pass").unwrap();
    }
}
