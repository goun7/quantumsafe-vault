//! QuantumSafe-Vault operator CLI.
//!
//! Professional operator surface: clap-driven subcommands, actionable errors,
//! `--version`, `--help` and exit codes suitable for scripting (0 ok / 1 demo
//! failure / 2 usage error). All demos run fully local (no network).

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::Amount;
use clap::{Parser, Subcommand};
use qsv_core::demo_keys;
use qsv_core::heirs::HeirSet;
use qsv_core::nums;
use qsv_core::taproot::VaultTaproot;
use qsv_core::unvault;

mod webhook;

use webhook::WebhookDelivery;

#[derive(Parser)]
#[command(
    name = "qsv-cli",
    version = qsv_core::VERSION,
    about = "QuantumSafe-Vault: post-quantum Bitcoin vault & sovereign inheritance protocol",
    long_about = "Operator CLI for QuantumSafe-Vault.\n\nKey-path spending is MATHEMATICALLY CANCELLED via the NUMS internal key; all\nspends flow through the MAST script tree. The second signature of the hybrid\n2-of-2 leaf is released only behind a NIST FIPS 204 (ML-DSA-65) gate with\nfail-closed self-verification."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Derive the NUMS internal key, the MAST leaves and the vault addresses.
    VaultSetup {
        /// Networks to render addresses for.
        #[arg(long, value_enum, default_value_t = NetworkArg::Bitcoin)]
        network: NetworkArg,
    },
    /// Watch-only descriptor export for INDEPENDENT balance verification
    /// (docs/10 §4.59): the `addr()` (BIP-385) and `rawtr()` forms Bitcoin
    /// Core imports, each with a BIP-380 checksum, both proven to expand to
    /// THIS vault output. No `tr(...)` is emitted — three of the four MAST
    /// leaves are not miniscript and a tr() over a different tree would
    /// watch a different address (fail-closed, §4.59).
    VaultDescriptor {
        /// Network to render the descriptors for.
        #[arg(long, value_enum, default_value_t = NetworkArg::Bitcoin)]
        network: NetworkArg,
        /// Write exactly ONE JSON document to stdout (no banner/footer).
        #[arg(long)]
        json: bool,
    },
    /// End-to-end PQC-gated hybrid spend: ML-DSA-65 proof → enclave co-sign →
    /// 2-of-2 witness, verified by libbitcoinconsensus.
    HybridSpendDemo,
    /// Dead Man's Switch flow: CSV 26,280 + 2-of-3 heirs + veto window.
    InheritanceDemo,
    /// Live vault status: heartbeat, inheritance and clawback clocks read
    /// from a REAL bitcoind (no fake data; explicit --tip for offline runs).
    VaultDashboard {
        /// bitcoind datadir holding the network's .cookie file.
        #[arg(long, default_value = ".bitcoin")]
        datadir: std::path::PathBuf,
        /// Network (selects the cookie subdir and default RPC port).
        #[arg(long, value_enum, default_value_t = NetworkArg::Bitcoin)]
        network: NetworkArg,
        /// Explicit RPC port override (cookie supplies the credentials) —
        /// same contract as psbt-live/watchtower.
        #[arg(long)]
        rpc_port: Option<u16>,
        /// Offline mode: use this height instead of a live node.
        #[arg(long)]
        tip: Option<u32>,
        /// Height of the last heartbeat refresh (default: tip = fresh vault).
        #[arg(long, default_value = "900000")]
        last_refresh_block: u32,
        /// Poll interval in seconds for live mode (requires a running node;
        /// not combinable with --tip).
        #[arg(long, default_value_t = 0)]
        watch: u64,
    },
    /// One-screen watch-only console (roadmap slice 1): the three clocks,
    /// the address and the printable estate letter as a SELF-CONTAINED HTML
    /// page — zero JavaScript, zero network, zero keys. Pass the descriptor
    /// you already exported (`vault-descriptor`) and it is either verified
    /// or refused; a page for the wrong address is worse than no page.
    Console {
        /// Network to render the vault address for.
        #[arg(long, value_enum, default_value_t = NetworkArg::Bitcoin)]
        network: NetworkArg,
        /// Current chain height (live RPC is out of scope for slice 1).
        #[arg(long, default_value = "900000")]
        tip: u32,
        /// Height of the last heartbeat refresh.
        #[arg(long, default_value = "900000")]
        last_refresh_block: u32,
        /// Vault label, printed verbatim on the letter.
        #[arg(long, default_value = "Family vault")]
        label: String,
        /// Verification date (ISO-8601). Default: the tip's approximate date.
        #[arg(long)]
        date: Option<String>,
        /// Watch-only descriptor (`addr(...)#…` / `rawtr(...)#…`) or the bare
        /// address. When given it MUST match this vault (fail-closed).
        #[arg(long)]
        descriptor: Option<String>,
        /// Write the HTML page here (default: ./qsv-console.html).
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Print exactly ONE JSON snapshot to stdout (no banner, no footer).
        #[arg(long)]
        json: bool,
    },
    /// FIRST RUN (roadmap slice D2): one command, no arguments, no node, no
    /// network — writes the watch-only console page and prints what to do
    /// next. Rust is only needed to BUILD the binary; the release archives
    /// ship it prebuilt (release workflow, SHA-256 manifest, build
    /// provenance). Heights are illustrative because nothing is contacted:
    /// the page is a rehearsal, clearly labelled as one.
    Demo {
        /// Network to render the demo page for.
        #[arg(long, value_enum, default_value_t = NetworkArg::Signet)]
        network: NetworkArg,
        /// Illustrative chain height (offline: no node is contacted).
        #[arg(long, default_value = "900000")]
        tip: u32,
        /// Write the HTML page here (default: ./qsv-demo.html).
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Print exactly ONE JSON document to stdout (no banner, no footer).
        #[arg(long)]
        json: bool,
    },
    /// Generate the printable estate letter (inheritance & emergency
    /// document): vault identification, spending rules, heir registry,
    /// emergency-kit procedure and verification instructions. Zero secrets.
    EstateLetter {
        /// Networks to render the vault address for.
        #[arg(long, value_enum, default_value_t = NetworkArg::Bitcoin)]
        network: NetworkArg,
        /// Human label of the vault (printed verbatim; binds the letter).
        #[arg(long, default_value = "Family vault")]
        label: String,
        /// Verification date (ISO-8601, printed verbatim; binds the letter).
        #[arg(long)]
        date: Option<String>,
        /// Append a scannable QR block encoding §1 (address | merkle root |
        /// output key) so a phone camera can cross-check the printed page.
        #[arg(long)]
        qr: bool,
    },
    /// Per-leaf spend budget measured from real signed reference spends:
    /// script/control/witness sizes, BIP-342 ≤520 B compliance, tx weight
    /// and the fee table at representative feerates. With --p2mr-delta the
    /// EXPERIMENTAL BIP-360 saving (control block 97 B → 65 B at depth 2)
    /// is printed beside every leaf — math only, K1 outstanding.
    LeafBudget {
        /// Print the experimental P2MR size/fee delta per leaf.
        #[arg(long)]
        p2mr_delta: bool,
    },
    /// WOTS+ parameter-space study (RFC 8391): signature sizes for every
    /// legal w, the 520-byte impossibility result, and the security ceiling
    /// of truncated messages — why leaf 4 must be commit-reveal.
    WotsParams,
    /// Split / recombine the emergency-kit seed with Shamir secret sharing —
    /// either the native GF(256) wire format or interoperable SLIP-0039
    /// mnemonics (Trezor/Electrum-compatible, 20/33 words per share).
    KitSeed {
        #[command(subcommand)]
        action: KitSeedAction,
    },
    /// PSBT Phase 1: file-based BIP-174/BIP-371 round trip — build an
    /// unsigned vault PSBT, sign it as the two devices would, then finalize
    /// and let libbitcoinconsensus judge the extracted transaction.
    Psbt {
        #[command(subcommand)]
        action: PsbtAction,
    },
    /// Live PSBT (Phase 2): wire the Phase-1 flow to a REAL, confirmed
    /// regtest UTXO — the coordinator reads the live outpoint and amount
    /// from the node (read-only RPC), builds the unsigned PSBT, the two
    /// devices sign and the finalized transaction is broadcast to the
    /// node's mempool. No fake outpoints anywhere in the loop.
    PsbtLive {
        /// bitcoind datadir holding the network's .cookie file.
        #[arg(long, default_value = ".bitcoin")]
        datadir: std::path::PathBuf,
        /// Explicit RPC port override (needed when the node runs on a
        /// non-default port; the cookie still supplies the credentials).
        #[arg(long)]
        rpc_port: Option<u16>,
        /// Network (selects the cookie subdir and default RPC port).
        #[arg(long, value_enum, default_value_t = NetworkArg::Regtest)]
        network: NetworkArg,
        /// Destination for the staging output (P2TR x-only key; demo
        /// provisioning key when omitted).
        #[arg(long)]
        destination: Option<String>,
        /// Miner fee in satoshis.
        #[arg(long, default_value_t = 1_500)]
        fee_sat: u64,
        /// Stop after writing the unsigned PSBT (coordinator/device split).
        #[arg(long)]
        build_only: bool,
        /// Stop after writing the signed PSBT (finish happens separately).
        #[arg(long)]
        sign_only: bool,
        /// Working directory for the vault.psbt / vault-signed.psbt /
        /// vault-final.psbt artifacts (default: current directory).
        #[arg(long, default_value = ".")]
        dir: std::path::PathBuf,
        /// MULTI-INPUT coin selection: aggregate at least this many live
        /// vault coins into ONE PSBT (greedy largest-first; the fee is paid
        /// from the aggregate). 1 = the original single-coin flow.
        #[arg(long, default_value_t = 1)]
        min_inputs: usize,
        /// EXPERIMENTAL BIP-360 (P2MR) source trial, REGTEST-ONLY: spend a
        /// live coin paying the vault's experimental P2MR address (witness
        /// v2 program = merkle root, no tweak, no internal key) through the
        /// SAME hybrid leaf and BIP-341 sighash machinery. K1-gated (docs/11
        /// Phase 4b): this exercises the address math and the signing
        /// plumbing — no P2MR consensus code exists in this repository.
        #[arg(long)]
        p2mr: bool,
        /// Fund the destination (or experimental P2MR) address with this
        /// many sats first (regtest convenience; 0 = spend an existing
        /// confirmed coin).
        #[arg(long, default_value_t = 0)]
        fund_sat: u64,
    },
    /// FROST + SLIP-0039 inheritance wizard (docs/04 §4): threshold group
    /// key generation, printed-word share backup and the RFC 9591 signing
    /// ceremony. Every hand-off is a printable file; the final signature is
    /// a plain BIP-340 Schnorr under the GROUP key.
    InheritanceKit {
        #[command(subcommand)]
        action: KitAction,
    },
    /// FROST group-key SPEND on a live chain (docs/04 §4, Part 1): funds
    /// (or finds) a confirmed UTXO paying the GROUP key's P2TR address,
    /// runs the RFC 9591 ceremony with a TWEAKED public package and
    /// broadcasts the threshold spend — the mempool accepts.
    FrostSpend {
        /// The coordinator's public package file (from inheritance-kit setup).
        #[arg(long = "public")]
        public: std::path::PathBuf,
        /// Heir deal files (k of them) as `label=file` pairs.
        #[arg(long = "deal", required = true)]
        deals: Vec<String>,
        /// bitcoind datadir holding the network's .cookie file.
        #[arg(long, default_value = ".bitcoin")]
        datadir: std::path::PathBuf,
        /// Explicit RPC port override (cookie supplies the credentials).
        #[arg(long)]
        rpc_port: Option<u16>,
        /// Network (selects the cookie subdir and default RPC port).
        #[arg(long, value_enum, default_value_t = NetworkArg::Regtest)]
        network: NetworkArg,
        /// Miner fee in satoshis.
        #[arg(long, default_value_t = 1_500)]
        fee_sat: u64,
        /// Fund the group address with this amount (sats) before spending —
        /// 0 = spend an existing confirmed UTXO (must be pre-funded).
        #[arg(long, default_value_t = 0)]
        fund_sat: u64,
        /// Destination for the spend (x-only key; demo key when omitted).
        #[arg(long)]
        destination: Option<String>,
        /// Working directory for ceremony artifacts.
        #[arg(long, default_value = ".")]
        dir: std::path::PathBuf,
        /// WATCHTOWER MODE: stop after the consensus self-check and write
        /// the signed transaction hex to `<dir>/frost-spend.txhex` (nothing
        /// is broadcast; the hold text is deterministic and false alarms
        /// are structurally impossible).
        #[arg(long)]
        no_broadcast: bool,
        /// CO-SIGNER GATE: the co-signer bridge TCP address. When given
        /// (with --vault-id), the enclave must release a co-signature over
        /// THIS sighash BEFORE the heirs may aggregate — a watchtower-frozen
        /// vault refuses and the spend aborts with nothing broadcast.
        #[arg(long)]
        cosigner: Option<String>,
        /// Vault id the co-signer knows this spend under (required with
        /// --cosigner).
        #[arg(long)]
        vault_id: Option<String>,
        /// ATTESTATION PIN: expected enclave PCR0 (hex; 32, 48 or 64
        /// bytes) — the COSE_Sign1 document must match exactly or the
        /// co-signature is refused. Defaults to the demo enclave
        /// measurement when omitted (docs/10 §4.52).
        #[arg(long)]
        cosigner_pcr0: Option<String>,
        /// ATTESTATION PIN: expected PCR1 (hex) — bound when given.
        #[arg(long)]
        cosigner_pcr1: Option<String>,
        /// ATTESTATION PIN: expected PCR2 (hex) — bound when given.
        #[arg(long)]
        cosigner_pcr2: Option<String>,
        /// ATTESTATION PIN: the enclave's BIP-340 x-only public key (hex,
        /// 32 bytes) the document's user_data must bind. Defaults to the
        /// demo enclave key. Requires --cosigner-pcr0 (clap-enforced: a
        /// real key needs its real measurement).
        #[arg(long, requires = "cosigner_pcr0")]
        cosigner_key: Option<String>,
        /// CONSOLIDATION FLOOR: require at least N live coins paying the
        /// group address (largest-first selection, `psbt-live --min-inputs`
        /// discipline) and merge ALL of them into ONE key-path spend.
        /// Fail-closed when fewer live coins exist.
        #[arg(long)]
        min_inputs: Option<usize>,
    },
    /// Inheritance WATCHTOWER (docs/04 §2 + §4): one read-only pass over a
    /// REAL bitcoind. Checks the heartbeat schedule (missed refresh = the
    /// dead man's switch trigger), the inheritance CSV countdown and the
    /// live vault coins, then rehearse a full FROST threshold ceremony in
    /// watchtower mode (--no-broadcast). Nothing is ever broadcast; exit 1
    /// only when the HEARTBEAT IS DUE — the alert a watchtower exists for.
    Watchtower {
        /// bitcoind datadir holding the network's .cookie file.
        #[arg(long, default_value = ".bitcoin")]
        datadir: std::path::PathBuf,
        /// Explicit RPC port override (cookie supplies the credentials).
        #[arg(long)]
        rpc_port: Option<u16>,
        /// Network (selects the cookie subdir and default RPC port).
        #[arg(long, value_enum, default_value_t = NetworkArg::Regtest)]
        network: NetworkArg,
        /// Blocks since the last owner refresh (0 = the vault was just
        /// refreshed). A real deployment persists this per vault.
        #[arg(long, default_value_t = 0)]
        last_refresh_block: u32,
        /// Heir deal files (at least k of them) as `label=file` pairs for
        /// the dry-run threshold ceremony. Omit to skip the rehearsal.
        #[arg(long = "deal")]
        deals: Vec<String>,
        /// The coordinator's public package file (from inheritance-kit
        /// setup). Required when --deal is given.
        #[arg(long = "public")]
        public: Option<std::path::PathBuf>,
        /// Working directory for the rehearsal artifact (frost-spend.txhex).
        #[arg(long, default_value = ".")]
        dir: std::path::PathBuf,
        /// Rehearsal convenience: fund the group address with this many
        /// sats first (regtest drill; 0 = spend an existing coin).
        #[arg(long, default_value_t = 0)]
        fund_sat: u64,
        /// MULTI-VAULT INVENTORY (daemon mode): a JSON file with a
        /// `vaults` array — per-vault `id`, `last_refresh_block` and
        /// optional `webhook`/`webhook_token`. Conflicts with the
        /// single-vault --last-refresh-block/--deal paths (exit 2).
        #[arg(long)]
        inventory: Option<std::path::PathBuf>,
        /// Directory for the persistent state file
        /// (watchtower-state.json; written every pass, read as the next
        /// pass's baseline). Unreadable state = fail-closed, never a
        /// silent reset.
        #[arg(long, default_value = ".")]
        state_dir: std::path::PathBuf,
    },
    /// VAULT ROTATION (docs/10 §4): the owner's heartbeat drill against a
    /// REAL bitcoind. Scans the vault address for its confirmed UTXO,
    /// builds the self-churn refresh transaction (identical policy, CSV
    /// clock reset), signs it through the normal hybrid leaf and broadcasts
    /// it. The coin lands back on the SAME address — the estate letter
    /// stays valid. When --heir is given, every heir is REQUIRED to present
    /// a fresh PQC identity whose commitment matches the one sealed in the
    /// vault at setup time (fail-closed: a stale, rotated or forged heir
    /// identity aborts the rotation — the registry is re-sealed in the
    /// refresh, docs/04 §5).
    VaultRotate {
        /// bitcoind datadir holding the network's .cookie file.
        #[arg(long, default_value = ".bitcoin")]
        datadir: std::path::PathBuf,
        /// Explicit RPC port override (cookie supplies the credentials).
        #[arg(long)]
        rpc_port: Option<u16>,
        /// Network (selects the cookie subdir and default RPC port).
        #[arg(long, value_enum, default_value_t = NetworkArg::Regtest)]
        network: NetworkArg,
        /// Miner fee in satoshis for the refresh transaction.
        #[arg(long, default_value_t = 1_000)]
        fee_sat: u64,
        /// Heir re-attestation as `label=pqc-seed-hex` pairs. When present,
        /// EVERY vault heir slot must be covered; each seed's ML-DSA-65
        /// verifying key must reproduce the commitment stored in the vault
        /// registry (demo registry seeds when omitted).
        #[arg(long = "heir")]
        heirs: Vec<String>,
        /// DRY RUN: build and consensus-verify the refresh transaction but
        /// write it to `<dir>/vault-rotate.txhex` instead of broadcasting.
        #[arg(long)]
        no_broadcast: bool,
        /// Working directory for the hold artifact (--no-broadcast).
        #[arg(long, default_value = ".")]
        dir: std::path::PathBuf,
        /// LIVE CO-SIGNER endpoint (host:port, e.g. 127.0.0.1:3334). When
        /// given, the SECOND signature is requested over the PQC gate from
        /// the running enclave service (cosigner-bridge) and verified under
        /// the pinned enclave key before use; the deterministic demo enclave
        /// key is used when omitted.
        #[arg(long)]
        cosigner: Option<String>,
        /// ATTESTATION PIN: expected enclave PCR0 (hex; 32, 48 or 64
        /// bytes) — the COSE_Sign1 document must match exactly or the
        /// co-signature is refused. Defaults to the demo enclave
        /// measurement when omitted (docs/10 §4.52).
        #[arg(long)]
        cosigner_pcr0: Option<String>,
        /// ATTESTATION PIN: expected PCR1 (hex) — bound when given.
        #[arg(long)]
        cosigner_pcr1: Option<String>,
        /// ATTESTATION PIN: expected PCR2 (hex) — bound when given.
        #[arg(long)]
        cosigner_pcr2: Option<String>,
        /// ATTESTATION PIN: the enclave's BIP-340 x-only public key (hex,
        /// 32 bytes) the document's user_data must bind. Defaults to the
        /// demo enclave key. Requires --cosigner-pcr0 (clap-enforced: a
        /// real key needs its real measurement).
        #[arg(long, requires = "cosigner_pcr0")]
        cosigner_key: Option<String>,
        /// MULTI-VAULT inventory (SAME schema the watchtower daemon uses):
        /// per-vault `id` + `last_refresh_block`. The rotation proceeds
        /// ONLY when the heartbeat is DUE for the selected vault.
        #[arg(long)]
        inventory: Option<std::path::PathBuf>,
        /// Which inventory row to rotate (matches the row's `id`).
        #[arg(long)]
        vault_id: Option<String>,
        /// Explicit heartbeat baseline for single-vault mode (blocks since
        /// the last refresh). Overrides rotation-state.json when given.
        #[arg(long)]
        last_refresh_block: Option<u32>,
        /// Rotation state dir: `<state-dir>/rotation-state.json` records the
        /// successful rotation's tip as the new last_refresh_block (the
        /// next run reads it as its baseline — an early re-rotation is
        /// refused, keeping the alarm↔rotation story consistent).
        #[arg(long, default_value = ".")]
        state_dir: std::path::PathBuf,
        /// MULTI-VAULT SWEEP: rotate EVERY DUE vault in the --inventory, in
        /// inventory order, writing an id-based rotation-state v2 record per
        /// success. Requires --inventory; excludes the single-vault options
        /// --vault-id/--last-refresh-block/--heir/--no-broadcast (exit 2).
        #[arg(long, requires = "inventory")]
        all: bool,
        /// LIVE CO-SIGNER GATE FOR THE SWEEP (host:port): every DUE vault's
        /// refresh requests its SECOND signature from the bridge BEFORE the
        /// ceremony, and a FROZEN vault (watchtower alarm) is SKIPPED with an
        /// explicit report line (exit stays 0 when the rest refreshes) — the
        /// fleet sweep must not die on the one vault the watchtower already
        /// stopped. Requires --all; conflicts with the plain --cosigner (exit 2).
        #[arg(long, requires = "all", conflicts_with = "cosigner")]
        cosigner_all: Option<String>,
        /// MUTUAL TLS FOR THE SWEEP GATE: the PEM client certificate chain
        /// (leaf first) presented to the --cosigner-all bridge. Requires
        /// --cosigner-all and its key half.
        #[arg(long, requires = "cosigner_all")]
        cosigner_all_cert: Option<std::path::PathBuf>,
        /// PEM private key matching --cosigner-all-cert.
        #[arg(long, requires = "cosigner_all", requires = "cosigner_all_cert")]
        cosigner_all_key: Option<std::path::PathBuf>,
        /// PEM CA(s) pinning the GATE BRIDGE's server certificate (mutual
        /// TLS server verification). Requires --cosigner-all.
        #[arg(long, requires = "cosigner_all")]
        cosigner_all_ca: Option<std::path::PathBuf>,
        /// SWEEP PREVIEW: classify every inventory row (DUE/healthy/stale,
        /// plus FROZEN when a --cosigner-all gate is configured) and print
        /// what a real sweep WOULD do — no ceremony runs, no state is
        /// written, nothing is broadcast. Requires --all.
        #[arg(long, requires = "all")]
        dry_run: bool,
    },
    /// CO-SIGNER BRIDGE (docs/10 §3.2→§3.3): serve the enclave co-signer on
    /// TCP and MIRROR the watchtower verdicts into it. Every vault whose
    /// persisted verdict is ALERT is frozen (ALL signing refused, even with
    /// a valid ML-DSA-65 proof); recovered vaults are cleared. The mirror
    /// is re-applied per request from the same state file, so a daemon
    /// refresh takes effect WITHOUT restarting the bridge.
    CosignerBridge {
        /// TCP listen address (loopback in dev mode).
        #[arg(long, default_value = "127.0.0.1:3334")]
        listen: String,
        /// Watchtower state dir holding watchtower-state.json (mirror #1 —
        /// also the bridge's health home).
        #[arg(long, default_value = ".")]
        state_dir: std::path::PathBuf,
        /// EXTRA watchtower mirror dir (docs/10 §4.60) — repeatable: each
        /// holds ITS OWN watchtower-state.json (one dir per watchtower
        /// HOST, published however the operator syncs it). The bridge
        /// freezes a vault only when the k-of-n quorum below agrees, so a
        /// single compromised host can neither forge a freeze (costs k
        /// hosts) nor silence one (costs n-k+1 hosts).
        #[arg(long = "watchtower")]
        watchtower: Vec<std::path::PathBuf>,
        /// Mirror quorum k (docs/10 §4.60): 1..=n, default majority
        /// ⌊n/2⌋+1 (n=1 → 1, today's single-mirror behaviour unchanged;
        /// n=3 → 2). With exactly TWO mirrors there is no
        /// compromise-resistant default (k=2 is silenced by one dead host,
        /// k=1 is forged by one), so the explicit value becomes REQUIRED
        /// there — usage error, exit 2. 0 or k>n is exit 2 as well.
        #[arg(long = "watchtower-quorum")]
        watchtower_quorum: Option<usize>,
        /// Vault ids this bridge serves (the demo vault address when
        /// omitted). Requests for unlisted vaults are refused.
        #[arg(long = "vault-id")]
        vault_ids: Vec<String>,
        /// DEV TLS (docs/10 §3.5): PEM certificate chain to present.
        /// Mandatory for any non-loopback bind (plaintext co-signatures
        /// off loopback are refused at boot), opt-in on loopback.
        #[arg(long)]
        tls_cert: Option<std::path::PathBuf>,
        /// PEM private key matching --tls-cert.
        #[arg(long)]
        tls_key: Option<std::path::PathBuf>,
        /// MUTUAL TLS: PEM certificate(s) of the CA that must sign EVERY
        /// client certificate (the co-signing client presents one). When
        /// given, the TLS handshake REFUSES anonymous clients — only pinned
        /// identities reach the gate. Requires the --tls pair.
        #[arg(long)]
        tls_client_ca: Option<std::path::PathBuf>,
        /// PER-VAULT RATE LIMIT as `<capacity>:<refill-per-sec>` (token
        /// bucket per requesting vault id; e.g. `2:0` = 2-request burst,
        /// no refill). A flood from ONE vault may not consume another
        /// vault's budget; refusals are counted in /metrics.
        #[arg(long)]
        rate_limit: Option<String>,
        /// FRAME TIMEOUT in milliseconds (docs/10 §4.19): every accepted
        /// socket gets this read/write deadline — a peer that connects and
        /// goes quiet can stall a worker for at most this long (slowloris
        /// bound; it also BOUNDS the SIGTERM drain waiting on that
        /// worker). 0 disables the deadline (default: 10000).
        #[arg(long, default_value = "10000")]
        frame_timeout_ms: u64,
        /// DRAIN DEADLINE in milliseconds (docs/10 §4.28): after
        /// SIGTERM the graceful drain waits at most this long, then
        /// reports, clears the health record and stops (exit 0 — a stop
        /// is a stop). This is the bound `--frame-timeout-ms 0` leaves
        /// open: a peer that goes quiet mid-frame would otherwise park
        /// the drain forever. 0 = unbounded (default: classic drain).
        #[arg(long, default_value = "0")]
        drain_timeout_ms: u64,
        /// METRICS SCRAPE TOKEN (docs/10 §4.20): when set, `GET /metrics`
        /// must present `X-QSV-Metrics-Token: <token>` — 401 otherwise,
        /// counted in qsv_cosigner_metrics_denied_total. Unset = open
        /// scrape (loopback dev default).
        #[arg(long)]
        metrics_token: Option<String>,
        /// METRICS SCRAPE TOKEN read from a FILE (docs/10 §4.27): the same
        /// gate as --metrics-token, but the secret never touches a command
        /// line (/proc/*/cmdline, shell history, a unit's ExecStart). The
        /// file must be chmod 600, hold exactly one line, no whitespace.
        /// Mutually exclusive with --metrics-token (usage error, exit 2).
        #[arg(long)]
        metrics_token_file: Option<std::path::PathBuf>,
        /// MAX CONCURRENT in-flight workers (docs/10 §4.22): a connection
        /// beyond the cap is accepted and immediately closed (counted in
        /// qsv_cosigner_capacity_refused_total) — a flood becomes a
        /// refusal instead of an unbounded thread/fd count. 0 = unlimited.
        #[arg(long, default_value = "64")]
        max_inflight: usize,
        /// BOOT REHEARSAL (docs/10 §4.41, Round 24): run every gate the
        /// real boot runs — token file contract, watchtower state, TLS
        /// material, transport policy, the bind itself — then print the
        /// resulting policy and EXIT 0 without publishing a health
        /// record, notifying systemd or serving a single request. It is
        /// the answer to "would systemd start succeed right now?", asked
        /// without taking the port hostage.
        #[arg(long)]
        dry_run: bool,
    },
    /// Generate a hardened systemd unit + timer pair for the co-signer
    /// bridge (docs/10 §3.4): ProtectSystem=strict sandbox, ReadWritePaths
    /// pinned to the state dir, OnCalendar timer for the watchtower pass
    /// that keeps the alarm mirror fresh. Files are WRITTEN (into --unit-dir
    /// when given, stdout otherwise) and re-parsed for verification — exit 1
    /// if anything required is missing (install-what-you-print).
    CosignerBridgeInstall {
        /// TCP listen address baked into ExecStart.
        #[arg(long, default_value = "127.0.0.1:3334")]
        listen: String,
        /// Watchtower state dir — becomes ReadWritePaths and --state-dir.
        #[arg(long, default_value = ".")]
        state_dir: std::path::PathBuf,
        /// EXTRA watchtower mirror dir baked into ExecStart as
        /// --watchtower (repeatable) — the same k-of-n mirror set and
        /// walls the bridge boot enforces (docs/10 §4.60). The service
        /// only READS these (ProtectSystem=strict allows that), so they
        /// stay outside ReadWritePaths.
        #[arg(long = "watchtower")]
        watchtower: Vec<std::path::PathBuf>,
        /// Mirror quorum k baked into ExecStart as --watchtower-quorum
        /// (docs/10 §4.60): 1..=n; required with exactly two mirrors.
        #[arg(long = "watchtower-quorum")]
        watchtower_quorum: Option<usize>,
        /// Vault ids for --vault-id (repeatable, baked into ExecStart).
        #[arg(long = "vault-id")]
        vault_ids: Vec<String>,
        /// Output dir for `<name>.service`/`<name>.timer` (stdout when omitted).
        #[arg(long)]
        unit_dir: Option<std::path::PathBuf>,
        /// systemd OnCalendar expression for the timer.
        #[arg(long, default_value = "*-*-* *:00/5:00")]
        timer_calendar: String,
        /// PEM certificate chain baked into ExecStart as --tls-cert.
        #[arg(long)]
        tls_cert: Option<std::path::PathBuf>,
        /// PEM private key baked into ExecStart as --tls-key.
        #[arg(long)]
        tls_key: Option<std::path::PathBuf>,
        /// PEM client CA baked into ExecStart as --tls-client-ca (mTLS).
        #[arg(long)]
        tls_client_ca: Option<std::path::PathBuf>,
        /// PER-VAULT RATE LIMIT baked into ExecStart as
        /// --rate-limit `<capacity>:<refill-per-sec>`.
        #[arg(long)]
        rate_limit: Option<String>,
        /// FRAME TIMEOUT baked into ExecStart as --frame-timeout-ms
        /// (docs/10 §4.19): the unit STATES the per-stream deadline it
        /// actually runs with instead of inheriting a code default —
        /// 0 disables the deadline (default 10000).
        #[arg(long, default_value = "10000")]
        frame_timeout_ms: u64,
        /// DRAIN DEADLINE baked into ExecStart as --drain-timeout-ms
        /// (docs/10 §4.28): the stop bound travels with the unit — 0 =
        /// unbounded classic drain (default), N = report + clear health
        /// + exit 0 after N ms of drain.
        #[arg(long, default_value = "0")]
        drain_timeout_ms: u64,
        /// MAX IN-FLIGHT WORKERS baked into ExecStart as --max-inflight
        /// (docs/10 §4.22/§4.35): the unit states the worker cap it
        /// actually runs with — 64 by default, 0 = unlimited. Always
        /// written, defaults included: `systemctl show` must report the
        /// capacity the bridge runs, not the binary's default.
        #[arg(long, default_value = "64")]
        max_inflight: usize,
        /// METRICS SCRAPE TOKEN baked into ExecStart as --metrics-token
        /// (the bridge boots with the SAME scrape gate the operator
        /// previewed; no whitespace — it splits ExecStart words).
        #[arg(long)]
        metrics_token: Option<String>,
        /// METRICS SCRAPE TOKEN baked as --metrics-token-file `<path>`
        /// (docs/10 §4.27): the unit carries the PATH, never the VALUE —
        /// the secret stays in one chmod-600 file the bridge reads at
        /// boot. Mutually exclusive with --metrics-token (exit 2).
        #[arg(long)]
        metrics_token_file: Option<std::path::PathBuf>,
        /// Unit basename (qsv-cosigner-bridge.service/.timer).
        #[arg(long, default_value = "qsv-cosigner-bridge")]
        unit_name: String,
    },
    /// OPERATOR DOCTOR (docs/10 §4.24): ONE command that answers "is this
    /// co-signing estate healthy right now?" — node cookie RPC, the
    /// watchtower state file, the mirror lag, the bridge health record
    /// (pid + policy) and a live `/metrics` scrape. Prints a verdict
    /// table; exit 1 when a REQUIRED check fails (scriptable health gate).
    Doctor {
        /// bitcoind datadir holding the network's .cookie file.
        #[arg(long, default_value = ".bitcoin")]
        datadir: std::path::PathBuf,
        /// Network (selects the cookie subdir and default RPC port).
        #[arg(long, value_enum, default_value_t = NetworkArg::Bitcoin)]
        network: NetworkArg,
        /// State dir shared with the bridge and the watchtower pass.
        #[arg(long, default_value = ".")]
        state_dir: std::path::PathBuf,
        /// Bridge address to probe (defaults to the health record's own).
        #[arg(long)]
        bridge: Option<String>,
        /// Scrape token for the /metrics probe (mandatory off loopback —
        /// the bridge refuses an open scrape there).
        #[arg(long)]
        metrics_token: Option<String>,
        /// Scrape token read from a chmod-600 FILE instead of argv
        /// (docs/10 §4.27) — the doctor's own command line stays secret-
        /// free too. Mutually exclusive with --metrics-token (exit 2).
        #[arg(long)]
        metrics_token_file: Option<std::path::PathBuf>,
        /// Blocks the watchtower mirror may lag behind the node before the
        /// doctor warns (a stale mirror freezes on stale verdicts).
        #[arg(long, default_value = "6")]
        max_mirror_lag: u64,
        /// Explicit RPC port for nodes started off the network default
        /// (the cookie carries credentials, never the port).
        #[arg(long)]
        rpc_port: Option<u16>,
        /// MACHINE-READABLE verdict (docs/10 §4.32): print ONE JSON
        /// document on stdout instead of the human table — the same
        /// checks, the same exit contract (FAIL still exits 1, with the
        /// error on stderr), so a script can gate on it without
        /// scraping ANSI-ish columns.
        #[arg(long)]
        json: bool,
    },
    /// BIP-360 (P2MR) decision-gate tracker: audits the migration plan
    /// (docs/11) against the live BIP status. Exit 1 when the recorded
    /// snapshot no longer matches reality — K1 has moved.
    Bip360Status {
        /// Compare against the live BIP-360 wiki page (needs `curl`).
        #[arg(long)]
        online: bool,
        /// Path to the migration plan (defaults to the repo copy).
        #[arg(long)]
        plan: Option<std::path::PathBuf>,
    },
    /// Verify a saved estate letter against a freshly derived vault: every
    /// §1 field and all four leaf scripts are re-derived and compared
    /// (exit code 1 on any mismatch — suitable for scripted audits).
    VerifyEstate {
        /// Path to the saved letter text (estate-letter > letter.txt).
        #[arg(long)]
        file: std::path::PathBuf,
        /// Network the letter was issued for.
        #[arg(long, value_enum, default_value_t = NetworkArg::Bitcoin)]
        network: NetworkArg,
    },
    /// CAPACITY BENCH (docs/10 §4.29): what ONE operation costs —
    /// ML-DSA-65 keygen/sign/verify, BIP-340 sign/verify, the enclave
    /// gate (PQC verify → co-sign → self-verify) and the health-record
    /// write+read loop — reported as ops/s + µs/op. A REPORT, never a
    /// gate: exit 0 (a busy box must not fail a capacity measurement);
    /// the threshold floors live in the test suite.
    Bench {
        /// Iterations per operation (each row is measured over the
        /// whole run — more iterations amortize the clock).
        #[arg(long, default_value_t = 100)]
        iterations: usize,
        /// MACHINE-READABLE report (docs/10 §4.33): print ONE JSON
        /// document (schema + the same per-op rows) instead of the human
        /// table — CI stores it as a capacity baseline. Still a report:
        /// exit 0, `--iterations 0` stays a usage error.
        #[arg(long)]
        json: bool,
        /// CAPACITY BASELINE (docs/10 §4.38): compare the fresh
        /// measurement against a stored `bench --json` report — an
        /// operation more than `--baseline-tolerance-pct` below its
        /// baseline makes the run FAIL (exit 1). A missing, unreadable or
        /// non-covering baseline is a usage error (exit 2): a gate that
        /// compares against nothing would pass by accident.
        #[arg(long)]
        baseline: Option<std::path::PathBuf>,
        /// Allowed regression per operation, in percent (default 25).
        #[arg(long, default_value_t = 25.0)]
        baseline_tolerance_pct: f64,
    },
    /// DOCUMENTATION AUDIT (docs/10 §4.63): the `docs_sync` walls as data —
    /// per module a missing or duplicated module number, a non-English title,
    /// non-increasing section numbers, an orphan `###` subsection, an
    /// unbalanced code fence, a dead relative link, a misplaced BIP-360
    /// snapshot and any Turkish text in the published tree. The findings are
    /// the same walls the build fails on, so the report can never disagree
    /// with `docs_sync`. Exit 0 in sync · 1 drift · 2 usage error.
    DocsAudit {
        /// Docs directory (defaults to the repo copy next to this crate).
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
        /// MACHINE-READABLE report: ONE JSON document on stdout — no banner,
        /// no footer (same discipline as `doctor --json`).
        #[arg(long)]
        json: bool,
    },
    /// Show library/protocol constants (FIPS 204 sizes, CSV constants, NUMS,
    /// WOTS+ emergency layer).
    Constants,
}

#[derive(Subcommand)]
enum KitSeedAction {
    /// Split the demo kit seed into `--shares` shares (`--threshold` of them
    /// recombine; fewer fail the integrity tag — never wrong key material).
    Split {
        /// Threshold k (2 ≤ k ≤ n): shares needed to recombine.
        #[arg(long, default_value_t = 3)]
        threshold: usize,
        /// Total number of shares n (k ≤ n ≤ 255).
        #[arg(long, default_value_t = 5)]
        shares: usize,
        /// Share wire format: native `qsv` tags or interoperable `slip39`
        /// mnemonics.
        #[arg(long, value_enum, default_value_t = KitFormat::Qsv)]
        format: KitFormat,
        /// SLIP-0039 passphrase (printable ASCII 32–126; empty = none).
        #[arg(long, default_value = "")]
        passphrase: String,
    },
    /// Recombine shares and prove the recovered seed reproduces the WOTS+
    /// kit seal (fail-closed: tag mismatch returns an error, not a wrong seed).
    Combine {
        /// Share strings: `qsvss1-<index>-<hex>` tags, or full SLIP-0039
        /// mnemonics when `--format slip39` (quote each share).
        #[arg(long = "share", required = true)]
        shares: Vec<String>,
        /// Share wire format.
        #[arg(long, value_enum, default_value_t = KitFormat::Qsv)]
        format: KitFormat,
        /// SLIP-0039 passphrase used at split time.
        #[arg(long, default_value = "")]
        passphrase: String,
    },
}

/// Wire format of the emergency-kit shares.
#[derive(clap::ValueEnum, Clone, Copy)]
enum KitFormat {
    /// Native `qsvss1-<index>-<hex>` tags with a 4-byte fail-closed digest.
    Qsv,
    /// SLIP-0039 mnemonics (RS1024 checksum, 20/33 words, interoperable).
    Slip39,
}

#[derive(Subcommand)]
enum PsbtAction {
    /// Build an unsigned vault PSBT (BIP-174 + BIP-371 tap fields) and write
    /// it as base64. Uses the ONE demo vault; demo outpoint for Phase 1.
    Build {
        /// Output path for the base64 PSBT.
        #[arg(long, default_value = "vault.psbt")]
        out: std::path::PathBuf,
    },
    /// Sign every input as the two devices would: each device recomputes the
    /// BIP-341 sighash from the PSBT itself and returns a Schnorr signature,
    /// which the coordinator verifies against the leaf keys before storing.
    Sign {
        /// Base64 PSBT produced by `psbt build`.
        #[arg(long = "in")]
        input: std::path::PathBuf,
        /// Output path for the signed PSBT.
        #[arg(long, default_value = "vault-signed.psbt")]
        out: std::path::PathBuf,
    },
    /// Assemble the script-path witness, extract the transaction and verify
    /// it with libbitcoinconsensus (Bitcoin Core script interpreter).
    Finish {
        /// Base64 PSBT produced by `psbt sign`.
        #[arg(long = "in")]
        input: std::path::PathBuf,
        /// Output path for the finalized PSBT (contains the witness).
        #[arg(long, default_value = "vault-final.psbt")]
        out: std::path::PathBuf,
    },
    /// SD-CARD EXPORT (Phase 1 hardware round trip): split a PSBT into the
    /// Coldcard/Ledger air-gapped file format — `<stem>.psbt` (binary,
    /// BIP-174) + `<stem>.sha256` (integrity manifest) + `<stem>.txt`
    /// (human-readable sighash audit sheet). The device signs the .psbt
    /// file, recomputing every sighash itself.
    Export {
        /// Base64 PSBT to export (from `psbt build` or `psbt-live
        /// --build-only`).
        #[arg(long = "in")]
        input: std::path::PathBuf,
        /// Output stem: writes `<stem>.psbt`, `<stem>.sha256`, `<stem>.txt`.
        #[arg(long, default_value = "hw-card")]
        stem: std::path::PathBuf,
    },
    /// SD-CARD IMPORT (Phase 1 hardware round trip): read back a device-
    /// returned BINARY PSBT, verify the manifest, prove every tap
    /// script-sig under the known leaf keys, finalize the witness and
    /// judge the transaction with libbitcoinconsensus. Any flipped byte,
    /// forged signature or structural damage exits 1.
    Import {
        /// The binary .psbt file returned by the hardware wallet.
        #[arg(long = "in")]
        input: std::path::PathBuf,
        /// Optional SHA-256 manifest from export — verified byte-exact
        /// when present (a device may rewrite the file).
        #[arg(long)]
        manifest: Option<std::path::PathBuf>,
        /// Output path for the finalized PSBT.
        #[arg(long, default_value = "hw-final.psbt")]
        out: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum KitAction {
    /// Trusted-dealer setup: derive the GROUP key, write the coordinator's
    /// public package and each heir's private deal, and print every heir's
    /// share as SLIP-0039 mnemonics (k_slip-of-n_slip printed words).
    Setup {
        /// Threshold k of heirs required to spend (k-of-n).
        #[arg(long, default_value_t = 2)]
        threshold: u16,
        /// Heir labels (one per heir; identifiers derive from them).
        #[arg(long = "heir", required = true)]
        heirs: Vec<String>,
        /// DKG mode (Round 33): RFC 9591 three-round joint key generation —
        /// NO trusted dealer; output files are byte-contract-compatible
        /// with the dealer flow (frost-spend, backups unchanged).
        #[arg(long)]
        dkg: bool,
        /// SLIP-0039 shares needed to recover ONE heir's deal.
        #[arg(long, default_value_t = 2)]
        slip_threshold: u8,
        /// SLIP-0039 total shares per heir.
        #[arg(long, default_value_t = 3)]
        slip_shares: u8,
        /// SLIP-0039 passphrase (never printed).
        #[arg(long, default_value = "")]
        passphrase: String,
        /// Output directory for the wizard artifacts.
        #[arg(long, default_value = ".")]
        dir: std::path::PathBuf,
    },
    /// Prove a printed SLIP-0039 backup round-trips: k recovered mnemonics
    /// must reproduce the heir's signing share (exit 1 on any mismatch).
    RecoverCheck {
        /// This heir's private deal file (from `setup`).
        #[arg(long = "deal")]
        deal: std::path::PathBuf,
        /// The SLIP-0039 mnemonics (repeatable, k of them).
        #[arg(long = "share", required = true)]
        shares: Vec<String>,
        /// SLIP-0039 passphrase used at setup time.
        #[arg(long, default_value = "")]
        passphrase: String,
    },
    /// Heir round 1: derive single-use nonces; write the nonce package and
    /// the round-1 commitment package.
    HeirRound1 {
        /// This heir's private deal file (from `setup`).
        #[arg(long = "deal")]
        deal: std::path::PathBuf,
        /// The coordinator's public package file.
        #[arg(long = "public")]
        public: std::path::PathBuf,
        /// Output directory.
        #[arg(long, default_value = ".")]
        dir: std::path::PathBuf,
    },
    /// Coordinator: build the round-2 signing package from the heirs'
    /// round-1 commitments (at least k of them).
    BuildSignPkg {
        /// The 32-byte message to sign (64 hex chars, e.g. a sighash).
        #[arg(long)]
        message: String,
        /// Round-1 commitment files as `<id-hex>:<file>` (repeatable).
        #[arg(long = "commitment", required = true)]
        commitments: Vec<String>,
        /// Output path for the signing package.
        #[arg(long, default_value = "sign-package.txt")]
        out: std::path::PathBuf,
    },
    /// Heir round 2: sign the coordinator's package with the round-1
    /// nonces; write the signature-share package.
    HeirRound2 {
        /// This heir's private deal file.
        #[arg(long = "deal")]
        deal: std::path::PathBuf,
        /// The coordinator's public package file.
        #[arg(long = "public")]
        public: std::path::PathBuf,
        /// This heir's round-1 nonce file.
        #[arg(long = "nonce")]
        nonce: std::path::PathBuf,
        /// The coordinator's signing package file.
        #[arg(long = "pkg")]
        pkg: std::path::PathBuf,
        /// Output directory.
        #[arg(long, default_value = ".")]
        dir: std::path::PathBuf,
    },
    /// Coordinator: aggregate the k signature shares into the final 64-byte
    /// BIP-340 signature and verify it under the GROUP key (fail-closed).
    Finish {
        /// The signing package file (from `build-sign-pkg`).
        #[arg(long = "pkg")]
        pkg: std::path::PathBuf,
        /// The coordinator's public package file.
        #[arg(long = "public")]
        public: std::path::PathBuf,
        /// Signature-share files as `<id-hex>:<file>` (repeatable, k of them).
        #[arg(long = "share", required = true)]
        shares: Vec<String>,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum NetworkArg {
    Bitcoin,
    Signet,
    Regtest,
    Testnet,
}

impl From<NetworkArg> for bitcoin::Network {
    fn from(n: NetworkArg) -> Self {
        match n {
            NetworkArg::Bitcoin => bitcoin::Network::Bitcoin,
            NetworkArg::Signet => bitcoin::Network::Signet,
            NetworkArg::Regtest => bitcoin::Network::Regtest,
            NetworkArg::Testnet => bitcoin::Network::Testnet,
        }
    }
}

fn banner() {
    // Fixed 68-column frame: the inner line is padded/truncated to 66 display
    // columns so the box stays aligned for any version string.
    fn frame(inner: &str) {
        let mut s: String = inner.chars().take(66).collect();
        while s.chars().count() < 66 {
            s.push(' ');
        }
        println!("║{s}║");
    }
    println!("╔══════════════════════════════════════════════════════════════════╗");
    frame(&format!(
        "       QUANTUMSAFE-VAULT  v{}  (P2TR NUMS + ML-DSA-65)",
        qsv_core::VERSION
    ));
    frame("  Key-path: MATHEMATICALLY CANCELLED (NUMS) · Spend: MAST-only");
    println!("╚══════════════════════════════════════════════════════════════════╝");
}

/// The demo enclave co-signer seed — the SAME derivation the production
/// co-signer uses (`qsv_pqc::enclave_keypair_from_seed`), so vault-setup,
/// estate letters, the dashboard, the hybrid-spend demo and the e2e tests
/// all describe ONE identical vault (single provisioning identity).
pub const DEMO_ENCLAVE_SEED: [u8; 32] = [77u8; 32];

/// The demo emergency-kit seed — the value the WOTS+ kit seal commits to and
/// the one both share formats (native tags and SLIP-0039) must reproduce.
pub const DEMO_KIT_SEED: [u8; 32] = [0x42u8; 32];

/// The enclave co-signer key of the demo vault (gate-seed derived).
fn demo_enclave_key() -> Result<XOnlyPublicKey, String> {
    let kp = qsv_pqc::enclave_keypair_from_seed(&DEMO_ENCLAVE_SEED).map_err(|e| e.to_string())?;
    Ok(qsv_pqc::enclave_xonly_public_key(&kp))
}

/// Derives the ONE demo vault (user + gate-seed enclave + recovery + heirs)
/// that every command reports on.
fn demo_vault() -> Result<VaultTaproot, String> {
    let secp = Secp256k1::verification_only();
    VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        demo_enclave_key()?,
        demo_keys::recovery_key(),
        &[demo_keys::heir_one(), demo_keys::heir_two()],
        2,
    )
    .map_err(|e| e.to_string())
}

/// P2TR scriptPubKey: `OP_1 <32-byte output key>` (BIP-341).
fn p2tr_spk(output_key: XOnlyPublicKey) -> bitcoin::ScriptBuf {
    use bitcoin::opcodes::all::OP_PUSHNUM_1;
    bitcoin::script::Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(output_key.serialize())
        .into_script()
}

/// EXPERIMENTAL BIP-360 (P2MR) scriptPubKey: `OP_2 <32-byte merkle root>`
/// (witness version 2, program = the script-tree merkle root; no tweak, no
/// internal key — BIP-360 also drops the control block's 33rd byte). K1-gated:
/// nothing on any live network understands this output yet (docs/11).
fn p2mr_witness_v2_spk(program: &[u8]) -> bitcoin::ScriptBuf {
    use bitcoin::opcodes::all::OP_PUSHNUM_2;
    let root: [u8; 32] = program.try_into().expect("32-byte merkle root program");
    bitcoin::script::Builder::new()
        .push_opcode(OP_PUSHNUM_2)
        .push_slice(root)
        .into_script()
}

/// Demo 1: vault setup report.
fn vault_setup(network: bitcoin::Network) -> Result<(), String> {
    println!("\n───── [1] VAULT SETUP ────────────────────────────────────────────");
    let internal = nums::nums_internal_key_bytes();
    println!("NUMS internal key (x-only): {}", hex::encode(internal));
    println!("  └─ discrete log unknown by construction (SHA-256 preimage resistance)");

    let vault = demo_vault()?;

    println!("Leaf 1 (normal):      2-of-2 hybrid  <user> <enclave>");
    println!("Leaf 2 (recovery):    CSV 144 blk    <cold-sweep>");
    println!("Leaf 3 (inheritance): CSV 26,280 blk + 2-of-3 heirs");
    println!("Leaf 4 (emergency):   WOTS+-sealed kit (commit-reveal, SHA-256 only)");
    println!(
        "Merkle root:          {}",
        vault
            .merkle_root()
            .map(|h| h.to_string())
            .unwrap_or_else(|| "none".into())
    );
    println!(
        "Output key:           {}",
        hex::encode(vault.output_key().serialize())
    );
    println!(
        "Address ({}): {}",
        format!("{network:?}").to_lowercase(),
        vault.address(network)
    );

    // Heir PQC commitments (fail-closed registry, docs/04 §5).
    let heir1 = qsv_pqc::PqcIdentity::from_seed(&[11u8; 32]);
    let heir2 = qsv_pqc::PqcIdentity::from_seed(&[12u8; 32]);
    let heir3 = qsv_pqc::PqcIdentity::from_seed(&[13u8; 32]);
    let set = HeirSet::build([
        (
            demo_keys::heir_one().serialize(),
            heir1.verifying_key_bytes().to_vec(),
        ),
        (
            demo_keys::heir_two().serialize(),
            heir2.verifying_key_bytes().to_vec(),
        ),
        (
            demo_keys::executor_key().serialize(),
            heir3.verifying_key_bytes().to_vec(),
        ),
    ])
    .map_err(|e| e.to_string())?;
    println!("Heir PQC commitments: {} registered ✅", set.len());
    Ok(())
}

/// Watch-only export (docs/10 §4.59): the exact descriptors an EXTERNAL
/// watcher imports to verify this vault's balance without QSV — plus the
/// honest reason the export is not a `tr(...)` (the tree is not miniscript).
fn vault_descriptor(network: bitcoin::Network, json: bool) -> Result<(), String> {
    let vault = demo_vault()?;
    let w = vault
        .watch_descriptors(network)
        .map_err(|e| e.to_string())?;
    let net = format!("{network:?}").to_lowercase();

    if json {
        let doc = serde_json::json!({
            "network": net,
            "address": w.address.to_string(),
            "script_pubkey": hex::encode(w.script_pubkey.as_bytes()),
            "output_key": hex::encode(vault.output_key().serialize()),
            "merkle_root": vault.merkle_root().map(|h| h.to_string()).unwrap_or_default(),
            "internal_key": hex::encode(vault.internal_key.serialize()),
            "leaf_hashes": vault.leaf_hashes.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            "descriptors": {
                "addr": w.addr_descriptor,
                "rawtr": w.rawtr_descriptor,
            },
            "tr_exportable": false,
            "doc": "docs/10 §4.59",
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    println!("\n───── [18] WATCH-ONLY DESCRIPTOR EXPORT (docs/10 §4.59) ────");
    let row = |label: String, value: String| println!("{label:<18}{value}");
    row(format!("Address ({net}):"), w.address.to_string());
    row(
        "Output key:".into(),
        hex::encode(vault.output_key().serialize()),
    );
    row(
        "Merkle root:".into(),
        vault
            .merkle_root()
            .map(|h| h.to_string())
            .unwrap_or_else(|| "none".into()),
    );
    row(
        "scriptPubKey:".into(),
        hex::encode(w.script_pubkey.as_bytes()),
    );
    println!("\n  Bitcoin Core — import as-is (independent balance watch):");
    println!("    {}", w.addr_descriptor);
    println!("\n  Bitcoin Core — the same output addressed by its key:");
    println!("    {}", w.rawtr_descriptor);
    println!("\n  Why no tr(...): 3 of the 4 MAST leaves are not miniscript");
    println!("  (`<n> CSV DROP`, SHA-256 commit-reveal) and raw tapscript leaves");
    println!("  are non-standard (BIP-386; Core's raw() is top-level only) —");
    println!("  a tr() over a different tree would watch a DIFFERENT address.");
    Ok(())
}

/// Demo 2: PQC-gated hybrid spend (Theorem 1 end-to-end, consensus-verified).
/// The fail-closed wall around the enclave gate. The DEMO always opens
/// (fixed seeds), so the mapping lives here: an operator sees the
/// refusal's cause, and a test can inject the fault the demo cannot.
fn enclave_gate_wall(res: Result<[u8; 64], String>) -> Result<(), String> {
    match res {
        Ok(_) => {
            println!("Enclave gate:         OPEN (PQC valid) → BIP-340 co-sign released");
            Ok(())
        }
        Err(e) => Err(format!("FAIL-CLOSED: {e}")),
    }
}

fn hybrid_spend_demo() -> Result<(), String> {
    println!("\n───── [2] HYBRID SPEND (PQC-GATED CO-SIGNER) ─────────────────────");

    // Client-side post-quantum identity.
    let pqc = qsv_pqc::PqcIdentity::from_seed(&[42u8; 32]);
    // The enclave gate signs 32-byte SIGHASHES only (qsv-pqc contract): the
    // human-readable intent crosses it as its SHA-256 digest.
    let msg_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(b"QSV unvault intent: stage 1 to staging contract").into()
    };
    let msg: &[u8] = &msg_hash;
    let pqc_sig = pqc.sign(msg);
    println!(
        "ML-DSA-65 signature:  {} bytes (FIPS 204 final)",
        pqc_sig.len()
    );

    // Enclave co-signer keypair: the demo provisioning seed (gate-derived).
    let enclave_seed = DEMO_ENCLAVE_SEED;
    let enclave_kp =
        qsv_pqc::enclave_keypair_from_seed(&enclave_seed).map_err(|e| e.to_string())?;
    let enclave_pk = qsv_pqc::enclave_xonly_public_key(&enclave_kp);

    // Enclave gate: deterministic, fail-closed, releases a REAL BIP-340 sig
    // over THE SAME message the PQC proof covers (Theorem 1). The witness
    // below re-runs the gate over the tx sighash itself.
    enclave_gate_wall(
        qsv_pqc::enclave_sign_if_pqc_valid(pqc.verifying_key_bytes(), &pqc_sig, msg, &enclave_seed)
            .map_err(|e| e.to_string()),
    )?;

    // Forge attempt: tampered PQC signature must be refused.
    let mut forged = pqc_sig;
    forged[0] ^= 0x01;
    assert!(qsv_pqc::enclave_sign_if_pqc_valid(
        pqc.verifying_key_bytes(),
        &forged,
        msg,
        &enclave_seed
    )
    .is_err());
    println!("Forge attempt:        REJECTED (fail-closed) ✅");

    // Build the unvault transaction and complete the 2-of-2 witness.
    let secp = Secp256k1::verification_only();
    let vault = VaultTaproot::derive(
        &secp,
        demo_keys::user_key(),
        enclave_pk,
        demo_keys::recovery_key(),
        &[demo_keys::heir_one(), demo_keys::heir_two()],
        2,
    )
    .map_err(|e| e.to_string())?;

    let out_xonly: XOnlyPublicKey = vault.output_key();
    let prev_spk = p2tr_spk(out_xonly);
    let staging = unvault::staging_script(demo_keys::recovery_key());
    let vault_value = Amount::from_sat(150_000);
    let fee = Amount::from_sat(1_500);

    let outpoint = bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([0xABu8; 32]), 0);
    let mut tx = unvault::build_unvault_tx(outpoint, vault_value, &staging, fee)
        .map_err(|e| e.to_string())?;
    println!(
        "Unvault tx:           {} sats → staging (single output, covenant-pinned)",
        (vault_value - fee).to_sat()
    );

    // Consensus-layer signatures over the normal leaf.
    let control = vault
        .spend_info
        .control_block(&(
            vault.leaves.normal.clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .ok_or("control block missing for normal leaf")?;

    // σ_user + the EXACT sighash the consensus engine will hash.
    let (sig_user, sighash_bytes) = {
        let sh =
            unvault::script_spend_sighash(&tx, 0, &vault.leaves.normal, vault_value, &prev_spk);
        let bytes = sh.to_byte_array();
        (
            unvault::sign_schnorr(&demo_keys::user_keypair(), &sh).to_vec(),
            bytes,
        )
    };
    // σ_enclave: the gate co-signs THE TX SIGHASH — the ML-DSA proof must
    // cover exactly the bytes the consensus engine hashes (Theorem 1: proof
    // and co-signature over the SAME message), and the witness pins the
    // result to this transaction.
    let pqc_over_sighash = pqc.sign(&sighash_bytes);
    let sig_enclave = qsv_pqc::enclave_sign_if_pqc_valid(
        pqc.verifying_key_bytes(),
        &pqc_over_sighash,
        &sighash_bytes,
        &enclave_seed,
    )
    .map_err(|e| format!("FAIL-CLOSED gate on the tx sighash: {e}"))?;
    // Execution order: script consumes σ_enclave first (stack top), then σ_user.
    let w = unvault::build_script_path_witness(
        &[sig_enclave.to_vec(), sig_user],
        &vault.leaves.normal,
        &control,
    );
    tx.input[0].witness = w;

    // Full consensus verification (Bitcoin Core script interpreter).
    qsv_core::consensus::verify_input(&tx, 0, &prev_spk, vault_value)
        .map_err(|e| format!("consensus rejected hybrid spend: {e}"))?;
    println!("Consensus engine:     ACCEPT (libbitcoinconsensus, Bitcoin Core v26) ✅");
    println!(
        "Hybrid 2-of-2 spend:  COMPLETE (enclave sig cryptographically bound to PQC proof) ✅"
    );
    Ok(())
}

/// Demo 3: inheritance (Dead Man's Switch) flow.
fn inheritance_demo() -> Result<(), String> {
    println!("\n───── [3] INHERITANCE (CSV 26,280 + 2-of-3 HEIRS) ────────────────");
    let _vault = demo_vault()?;

    println!("Dormancy lock:        26,280 blocks (~180 days) via OP_CSV");
    let final_out = unvault::staging_script(demo_keys::heir_one());
    let tx = unvault::build_settlement_tx(
        bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([0xCDu8; 32]), 0),
        Amount::from_sat(148_500),
        &final_out,
        Amount::from_sat(1_200),
        qsv_core::policy::INHERITANCE_CSV_BLOCKS,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "Settlement tx:        nSequence={} (BIP-68 height lock)",
        tx.input[0].sequence.to_consensus_u32()
    );
    println!("Heir threshold:       2-of-3 (heir₁ + heir₂ + executor)");
    println!("Veto window:          30 days (4,320 blocks) for owner clawback");
    println!("Inheritance leaf:     READY ✅");
    Ok(())
}

/// Estate letter: printable, deterministic, secret-free inheritance document
/// (docs/10 §7). Uses the demo provisioning keys, like every other demo.
/// Roadmap slice 1 — the watch-only console. Composes the EXISTING engines
/// (`dashboard`, `estate`, `taproot::watch_descriptors`) instead of
/// duplicating any date/clocks math, then renders one self-contained page.
struct ConsoleArgs<'a> {
    network: bitcoin::Network,
    tip: u32,
    last_refresh_block: u32,
    label: &'a str,
    date: Option<&'a str>,
    descriptor: Option<&'a str>,
    out: Option<&'a std::path::Path>,
    json: bool,
}

/// One builder for both `console` and `demo`: the demo page must never be a
/// second renderer that could drift from the console it introduces.
fn console_snapshot(
    network: bitcoin::Network,
    tip: u32,
    last_refresh_block: u32,
    label: &str,
    date: Option<&str>,
    descriptor: Option<&str>,
) -> Result<qsv_core::console::ConsoleSnapshot, String> {
    let vault = demo_vault()?;

    let heir1 = qsv_pqc::PqcIdentity::from_seed(&[11u8; 32]);
    let heir2 = qsv_pqc::PqcIdentity::from_seed(&[12u8; 32]);
    let heirs = HeirSet::build([
        (
            demo_keys::heir_one().serialize(),
            heir1.verifying_key_bytes().to_vec(),
        ),
        (
            demo_keys::heir_two().serialize(),
            heir2.verifying_key_bytes().to_vec(),
        ),
    ])
    .map_err(|e| e.to_string())?;

    // Undated runs use the tip's approximate calendar date: deterministic for
    // a given height (a wall-clock default would make reruns diff).
    let date = date
        .map(str::to_string)
        .unwrap_or_else(|| qsv_core::dashboard::epoch_date(tip));

    qsv_core::console::snapshot(&qsv_core::console::ConsoleInput {
        vault: &vault,
        network,
        tip,
        last_refresh_block,
        label,
        date: &date,
        heirs: &heirs,
        descriptor,
    })
}

/// The demo label is part of the artifact: a page printed by `demo` must not
/// be mistakable for the console of a real vault (throwaway demo keys).
const DEMO_LABEL: &str = "Demo vault — offline rehearsal (throwaway demo keys)";

/// FIRST RUN (roadmap slice D2): no arguments, no node, no network. The page
/// is written, READ BACK (a demo that announces a page it cannot re-read is
/// a lie) and followed by the next three offline commands.
fn demo_cmd(
    network: bitcoin::Network,
    tip: u32,
    out: Option<&std::path::Path>,
    json: bool,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    let snap = console_snapshot(network, tip, tip, DEMO_LABEL, None, None)?;
    let path = out
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("qsv-demo.html"));
    let html = qsv_core::console::render_html(&snap);
    std::fs::write(&path, &html).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    let stored =
        std::fs::read(&path).map_err(|e| format!("cannot re-read {}: {e}", path.display()))?;
    if stored != html.as_bytes() {
        return Err(format!(
            "{} did not round-trip on disk ({} bytes written, {} read)",
            path.display(),
            html.len(),
            stored.len()
        ));
    }
    let html_sha = file_sha256_hex(html.as_bytes());
    // Machine consumers get the SAME absolute path the human line prints:
    // a relative path in the JSON changes meaning with the caller's cwd.
    let abs_path = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    let elapsed_ms = started.elapsed().as_millis() as u64;

    if json {
        let doc = serde_json::json!({
            "schema": "qsv-demo/v1",
            "network": network_name(network),
            "tip": tip,
            "offline": true,
            "out": abs_path.display().to_string(),
            "bytes": html.len(),
            "html_sha256": html_sha,
            "address": snap.address,
            "letter_sha256": snap.letter_sha256,
            "elapsed_ms": elapsed_ms,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    let abs = abs_path;
    println!("\n───── [0] FIRST RUN (offline demo) ──────────────────────────────");
    println!(
        "Demo page written: {} ({} bytes, script-free HTML)",
        path.display(),
        html.len()
    );
    println!(
        "  network:   {} — no node contacted, heights are illustrative",
        network_name(network)
    );
    println!("  vault:     {}", snap.address);
    println!("  page:      sha256 {html_sha}");
    println!("  letter:    sha256 {}", snap.letter_sha256);
    println!("  elapsed:   {elapsed_ms} ms (render + write + read-back)");
    println!("  open:      file://{}", abs.display());
    println!("\nNext (offline; nothing is signed and nothing is broadcast):");
    println!("  1. open the page: three clocks, address, estate letter");
    println!(
        "  2. qsv-cli estate-letter --network {}  > letter.txt",
        network_name(network)
    );
    println!(
        "  3. qsv-cli verify-estate --file letter.txt --network {}",
        network_name(network)
    );
    println!(
        "  4. qsv-cli console --descriptor '<paste the addr() line from the page>' — refused unless it IS this vault"
    );
    Ok(())
}

fn console_cmd(args: ConsoleArgs<'_>) -> Result<(), String> {
    let ConsoleArgs {
        network,
        tip,
        last_refresh_block,
        label,
        date,
        descriptor,
        out,
        json,
    } = args;
    let snap = console_snapshot(network, tip, last_refresh_block, label, date, descriptor)?;

    if json {
        let doc = serde_json::json!({
            "schema": snap.schema,
            "network": snap.network,
            "address": snap.address,
            "output_key": snap.output_key,
            "merkle_root": snap.merkle_root,
            "descriptors": {
                "addr": snap.addr_descriptor,
                "rawtr": snap.rawtr_descriptor,
            },
            "descriptor_verified": snap.descriptor_verified,
            "tip": snap.tip,
            "last_refresh_block": snap.last_refresh_block,
            "clocks": {
                "heartbeat_due": snap.heartbeat_due,
                "blocks_until_refresh": snap.blocks_until_refresh,
                "heartbeat_refresh_due": snap.heartbeat_refresh_due,
                "blocks_until_clawback_close": snap.blocks_until_clawback_close,
                "blocks_until_inheritance": snap.blocks_until_inheritance,
                "inheritance_activates": snap.inheritance_activates,
            },
            "letter": snap.letter,
            "letter_sha256": snap.letter_sha256,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
    }

    if out.is_some() || !json {
        let path = out
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from("qsv-console.html"));
        let html = qsv_core::console::render_html(&snap);
        std::fs::write(&path, &html)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        if !json {
            println!(
                "Console written: {} ({} bytes, script-free) · letter sha256 {}",
                path.display(),
                html.len(),
                snap.letter_sha256
            );
        }
    }
    Ok(())
}

fn estate_letter_cmd(
    network: bitcoin::Network,
    label: &str,
    date: Option<&str>,
    qr: bool,
) -> Result<(), String> {
    println!("\n───── [5] ESTATE LETTER ──────────────────────────────────────────");
    let vault = demo_vault()?;

    let heir1 = qsv_pqc::PqcIdentity::from_seed(&[11u8; 32]);
    let heir2 = qsv_pqc::PqcIdentity::from_seed(&[12u8; 32]);
    let heirs = HeirSet::build([
        (
            demo_keys::heir_one().serialize(),
            heir1.verifying_key_bytes().to_vec(),
        ),
        (
            demo_keys::heir_two().serialize(),
            heir2.verifying_key_bytes().to_vec(),
        ),
    ])
    .map_err(|e| e.to_string())?;

    let letter = qsv_core::estate::estate_letter(&qsv_core::estate::EstateLetterInput {
        vault: &vault,
        network,
        label,
        verification_date: date.unwrap_or("(undated — set at print time)"),
        heirs: &heirs,
    });
    print!("{letter}");
    println!(
        "Letter determinism: same inputs → byte-identical output (diff old vs new copies to detect tampering)."
    );
    if qr {
        let payload = qsv_core::estate::qr_payload(&vault, network);
        let code = qrcode::QrCode::new(payload.as_bytes()).map_err(|e| e.to_string())?;
        let art = code
            .render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .build();
        println!("\nQR (§1 identity — scan to cross-check the printed page):");
        println!("{art}");
        println!("\npayload: {payload}\nVerify: qsv-cli verify-estate --file <saved-letter> --network {net}", net = network_name(network));
    }
    Ok(())
}

/// The bridge-record half of the doctor, extracted (Round 30) so EVERY
/// classification is unit-testable — including the platform-cannot-ask
/// `Unknown`, which POSIX can never produce and therefore never exercised.
fn health_diagnoses(
    state: qsv_cosigner::Liveness,
    record: Option<&qsv_cosigner::health::BridgeHealth>,
    state_dir: &std::path::Path,
) -> Vec<(&'static str, Diagnosis, String)> {
    let mut results = Vec::new();
    match state {
        qsv_cosigner::Liveness::Live => {
            let h = record.expect("Live implies a record");
            results.push((
                "bridge health",
                Diagnosis::Ok,
                format!(
                    "pid {} alive · {} · {} · {} vault(s) · mirror tip {}",
                    h.pid,
                    h.listen,
                    h.transport,
                    h.vaults.len(),
                    h.watchtower_tip
                ),
            ));
        }
        qsv_cosigner::Liveness::Stale => {
            let h = record.expect("Stale implies a record");
            results.push((
                "bridge health",
                Diagnosis::Fail,
                format!(
                    "record from DEAD pid {} (unclean exit — SIGKILL/OOM?); the supervisor has not restarted it",
                    h.pid
                ),
            ));
        }
        // On POSIX `pid_alive` is total, so `Unknown` cannot occur here;
        // the real arm exists for platforms without `kill(2)`.
        #[cfg(not(unix))]
        qsv_cosigner::Liveness::Unknown => {
            let h = record.expect("Unknown implies a record");
            results.push((
                "bridge health",
                Diagnosis::Warn,
                format!("pid {} recorded; liveness not decidable here", h.pid),
            ));
        }
        #[cfg(unix)]
        qsv_cosigner::Liveness::Unknown => {}
        qsv_cosigner::Liveness::Absent => results.push((
            "bridge health",
            Diagnosis::Warn,
            format!(
                "no {} (never booted here, or stopped cleanly)",
                qsv_cosigner::health_path(state_dir).display()
            ),
        )),
    }
    results
}

/// Per-leaf spend budget: sizes measured from real signed reference spends.
fn leaf_budget_cmd(p2mr_delta: bool) -> Result<(), String> {
    println!("\n───── [6] LEAF BUDGET (BIP-341 WEIGHT · BIP-342 ≤520 B · FEES) ───");
    let vault = demo_vault()?;
    let budgets = qsv_core::budget::leaf_budgets(&vault).map_err(|e| e.to_string())?;
    println!("  All figures measured from REAL signed reference spends (no estimates).\n");
    for b in &budgets {
        let elements = b
            .witness_elements
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {}", b.leaf.label());
        println!(
            "    script {:>4} B · control {:>3} B · witness {:>4} B in {} elements [{}]",
            b.script_bytes,
            b.control_bytes,
            b.witness_bytes,
            b.witness_elements.len(),
            elements
        );
        println!(
            "    spend tx {:>4} vB ({:>5} WU) · max element {:>3} B ≤ 520 B {} · BIP-342 margin {} B",
            b.tx_vbytes,
            b.tx_weight,
            b.max_element_bytes,
            if b.bip342_ok() { "OK ✅" } else { "VIOLATED ❌" },
            b.bip342_margin()
        );
        let fees = b
            .fee_table()
            .iter()
            .map(|(r, f)| format!("{r}→{f}"))
            .collect::<Vec<_>>()
            .join("  ");
        println!("    fees (sat/vB→sats): {fees}");
        if p2mr_delta {
            // EXPERIMENTAL BIP-360 arithmetic (K1 outstanding): the control
            // block drops its 33rd byte, so every script-path input saves
            // exactly 32 witness bytes (= 128 WU = 32 vB at depth 2).
            let d = qsv_core::budget::p2mr_delta(b);
            println!(
                "    p2mr delta    : control {}→{} B · tx {}→{} WU ({}→{} vB) · fees saved {}",
                d.control_bytes_p2tr,
                d.control_bytes_p2mr,
                d.tx_weight_p2tr,
                d.tx_weight_p2mr,
                d.tx_vbytes_p2tr,
                d.tx_vbytes_p2mr,
                d.fee_savings
                    .iter()
                    .map(|(r, s)| format!("{r}→{s}"))
                    .collect::<Vec<_>>()
                    .join("  ")
            );
        }
    }
    println!(
        "\n  MAST overhead: balanced 4-leaf tree ⇒ depth 2 ⇒ control block 97 B (+64 B/input)"
    );
    if p2mr_delta {
        println!(
            "  p2mr note: EXPERIMENTAL BIP-360 arithmetic only (K1 outstanding) — witness v2\n             saves 32 B/input of control block; spend requires BIP-360 consensus rules."
        );
    }
    Ok(())
}

/// WOTS+ parameter-space study: sizes per legal w and the 520-byte verdict.
fn wots_params_cmd() -> Result<(), String> {
    println!("\n───── [7] WOTS+ PARAMETER STUDY (RFC 8391 · n=32) ───────────────");
    println!("  Signature size = (len1+len2)·32 bytes; len1 = ⌈8m/log₂w⌉, len2 = checksum.\n");
    println!(
        "  {:>4} {:>7} {:>7} {:>7} {:>9} {:>7} {:>8}",
        "w", "len1", "len2", "chains", "sig bytes", "steps", "≤520 B?"
    );
    for row in qsv_core::wots::param_study(32) {
        println!(
            "  {:>4} {:>7} {:>7} {:>7} {:>9} {:>7} {:>8}",
            row.w,
            row.len1,
            row.len2,
            row.chains,
            row.sig_bytes,
            row.max_chain_steps,
            if row.fits_520 { "yes" } else { "NO" }
        );
    }
    let best = qsv_core::wots::sub520_max_message_bytes();
    println!("\n  VERDICT 1: no w fits a full 32-byte digest in one witness element;");
    println!("             global minimum is w=256 → 34 chains → 1,088 B (2.1× the 520 B cap).");
    println!(
        "  VERDICT 2: truncating to fit caps the message at {best} bytes = {} bits",
        best * 8
    );
    println!("             — below SHA-256's 128-bit collision target ⇒ forgery-prone.");
    println!("  DESIGN: leaf 4 is therefore a 37 B commit-reveal (Schnorr key disclosed");
    println!("          in the witness, ≤ 97 B elements). Future soft fork (OP_CHECKSHRINCS");
    println!("          over BIP-360 P2MR leaves, Blockstream May 2026) could verify the");
    println!("          2,144 B seal directly — tracked in docs/11 (Phase 4).");
    Ok(())
}

/// Kit seed sharing: Shamir split / combine with fail-closed integrity.
fn kit_seed_split(
    threshold: usize,
    shares: usize,
    format: KitFormat,
    passphrase: &str,
) -> Result<(), String> {
    // Demo kit seed — same constant the WOTS+ kit seal uses (t6 test).
    let seed = DEMO_KIT_SEED;
    match format {
        KitFormat::Qsv => {
            println!("\n───── [8] KIT SEED · SHAMIR SPLIT (GF(256), k-of-n) ─────────────");
            let split =
                qsv_core::shamir::split(&seed, threshold, shares).map_err(|e| e.to_string())?;
            println!("  secret: 32-byte emergency-kit seed (Phase 0 DEMO value — production seed");
            println!("          is generated once inside the sealed kit and never printed).\n");
            for s in &split {
                println!("  share[{:>2}]:", s.index);
                println!("         {}", s.encode());
            }
            println!(
                "\n  threshold {threshold}-of-{shares}: ANY {threshold} shares recombine; fewer"
            );
            println!("  fail the integrity tag (fail-closed — never wrong key material).");
            println!("  Store shares in SEPARATE locations; tag ≠ authentication vs. an adversary");
            println!("  who controls every copy. Recombine: qsv-cli kit-seed combine --share …");
        }
        KitFormat::Slip39 => {
            println!("\n───── [8] KIT SEED · SLIP-0039 SPLIT (20/33-word mnemonics) ─────");
            println!("  spec: SLIP-0039 Final · GF(256) · RS1024 checksum · Feistel+PBKDF2");
            println!(
                "  passphrase: {pw}",
                pw = if passphrase.is_empty() {
                    "(none)"
                } else {
                    "set"
                }
            );
            println!("  secret: 32-byte emergency-kit seed (Phase 0 DEMO value).\n");
            let groups = [qsv_core::slip39::GroupSpec::new(
                threshold as u8,
                shares as u8,
            )];
            let out = qsv_core::slip39::split(&seed, 1, &groups, passphrase, 0)
                .map_err(|e| format!("SLIP-0039 split failed: {e}"))?;
            for (gi, group) in out.iter().enumerate() {
                for (mi, mnemonic) in group.iter().enumerate() {
                    println!(
                        "  G{} M{} ({} words):",
                        gi + 1,
                        mi + 1,
                        mnemonic.split_whitespace().count()
                    );
                    println!("    {mnemonic}");
                }
            }
            println!("\n  threshold {threshold}-of-{shares}: ANY {threshold} mnemonics recombine");
            println!("  (same first two words = same share set; third word = group data).");
            println!("  Wrong passphrase does NOT error — it yields a different (deniable)");
            println!("  secret; keep it in a password manager, never on the printed page.");
            println!("  Recombine: qsv-cli kit-seed combine --format slip39 \\");
            println!("             --share \"word1 word2 …\" --share \"…\"");
        }
    }
    Ok(())
}

/// Proves a recovered kit seed IS the protocol kit seed: it must reproduce
/// the WOTS+ seal checked before any emergency spend.
fn verify_kit_seed(seed: &[u8; 32]) -> Result<(), String> {
    let (kit_sk, kit_pk) = qsv_core::wots::keypair_from_seed(seed);
    let claim: [u8; 32] = {
        use bitcoin::hashes::Hash as _;
        use sha2::{Digest, Sha256};
        let pk_em = demo_keys::emergency_kit_key();
        let mut h = Sha256::new();
        h.update(b"QSV_WOTS_EMERGENCY_KIT_v1");
        h.update(bitcoin::hashes::sha256::Hash::hash(&pk_em.serialize()).to_byte_array());
        h.finalize().into()
    };
    let seal = qsv_core::wots::sign(&kit_sk, &claim).map_err(|e| e.to_string())?;
    qsv_core::wots::verify(&kit_pk, &claim, &seal).map_err(|e| e.to_string())?;
    let fingerprint = qsv_core::wots::commit_digest(&kit_pk);
    println!("  WOTS+ kit seal:   VERIFIED (keypair derived, seal round-trip ok)");
    println!("  seal fingerprint: {}", hex::encode(fingerprint));
    println!(
        "  recovered seed sha256: {}",
        hex::encode({
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(seed);
            let d: [u8; 32] = h.finalize().into();
            d
        })
    );
    Ok(())
}

fn kit_seed_combine(raw: &[String], format: KitFormat, passphrase: &str) -> Result<(), String> {
    let slip39 = matches!(format, KitFormat::Slip39);
    println!(
        "\n───── [8] KIT SEED · {} ─────",
        if slip39 {
            "SLIP-0039 COMBINE"
        } else {
            "SHAMIR COMBINE"
        }
    );
    let seed: [u8; 32] = match format {
        KitFormat::Qsv => {
            let mut shares = Vec::with_capacity(raw.len());
            for s in raw {
                shares.push(qsv_core::shamir::Share::decode(s).map_err(|e| e.to_string())?);
            }
            let seed = qsv_core::shamir::combine(&shares).map_err(|e| {
                format!("fail-closed: {e} — supply at least the threshold count of shares from ONE split")
            })?;
            println!("  integrity tag: VERIFIED over {} shares", shares.len());
            seed
        }
        KitFormat::Slip39 => {
            let refs: Vec<&str> = raw.iter().map(|s| s.as_str()).collect();
            let ms = qsv_core::slip39::combine(&refs, passphrase).map_err(|e| {
                format!("fail-closed: {e} — check the mnemonic set, thresholds and passphrase")
            })?;
            println!(
                "  RS1024 checksums + share metadata: VERIFIED over {} mnemonics",
                refs.len()
            );
            if ms.len() != 32 {
                return Err(format!(
                    "recovered secret is {} bytes; the kit seed is 32",
                    ms.len()
                ));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&ms);
            out
        }
    };
    verify_kit_seed(&seed)
}

/// Independent letter verification: parse the saved text, re-derive the
/// vault from protocol constants, compare every field. Exit 1 on mismatch.
fn verify_estate_cmd(file: &std::path::Path, network: bitcoin::Network) -> Result<(), String> {
    println!("\n───── [9] VERIFY ESTATE LETTER ───────────────────────────────────");
    let text = std::fs::read_to_string(file)
        .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
    let vault = demo_vault()?;
    let checks = qsv_core::estate::verify_letter(&text, &vault, network);
    for c in &checks {
        let mark = if c.ok { "✓" } else { "✗" };
        println!("  {mark} {:22} {}", format!("{}:", c.label), c.detail);
    }
    let passed = checks.iter().filter(|c| c.ok).count();
    let total = checks.len();
    if passed == total {
        println!("\nRESULT: PASS ({passed}/{total}) — letter matches the re-derived vault. ✅");
        Ok(())
    } else {
        println!("\nRESULT: FAIL ({passed}/{total}) — do NOT trust this letter. ❌");
        Err(format!(
            "{} of {total} checks failed: treat the letter as tampered or rotated",
            total - passed
        ))
    }
}

/// Protocol constants reference.
fn constants() {
    println!(
        "NUMS seed message:     {}",
        core::str::from_utf8(nums::NUMS_SEED_MESSAGE).unwrap_or("?")
    );
    println!(
        "Recovery CSV:          {} blocks (~24h)",
        qsv_core::policy::RECOVERY_CSV_BLOCKS
    );
    println!(
        "Inheritance CSV:       {} blocks (~180d)",
        qsv_core::policy::INHERITANCE_CSV_BLOCKS
    );
    println!("Veto window:           4,320 blocks (~30d)");
    println!(
        "ML-DSA-65 verifying key: {} bytes",
        qsv_pqc::ML_DSA_65_VK_LEN
    );
    println!(
        "ML-DSA-65 signature:     {} bytes",
        qsv_pqc::ML_DSA_65_SIG_LEN
    );
    println!("Schnorr signature:       64 bytes (BIP-340)");
    println!(
        "WOTS+ (n=32, w=16):      pk/sig {} bytes each — post-Q-Day kit seal (SHA-256 only)",
        qsv_core::wots::PK_SIZE
    );
    println!(
        "Emergency leaf 4:        37 B commit-reveal (OP_DUP OP_SHA256 …); witness elements ≤ 520 B (BIP-342)"
    );
    println!(
        "WOTS+ sub-520 ceiling:   {} B message max ({} bits) — full digest never fits; commit-reveal mandated",
        qsv_core::wots::sub520_max_message_bytes(),
        qsv_core::wots::sub520_max_message_bytes() * 8
    );
    println!(
        "Inheritance witness:     multi_a empty-slot discipline (0-byte sig = false, BIP-342)"
    );
    println!("Kit seed sharing:        GF(256) Shamir k-of-n · 4-byte fail-closed tag");
    println!("qsv-core version:        {}", qsv_core::VERSION);
}

/// Live vault dashboard: real chain tip via read-only RPC (or --tip offline),
/// then the pure dashboard math. No fabricated data: without a node and
/// without --tip this fails with an actionable message.
fn vault_dashboard(
    datadir: std::path::PathBuf,
    network: bitcoin::Network,
    rpc_port: Option<u16>,
    tip_override: Option<u32>,
    last_refresh_block: u32,
    watch_secs: u64,
) -> Result<(), String> {
    if watch_secs > 0 && tip_override.is_some() {
        return Err("--watch requires a live node; remove --tip".into());
    }
    let vault = demo_vault()?;
    let address = vault.address(network).to_string();

    let connect = || {
        let rpc_net = match network {
            bitcoin::Network::Bitcoin => qsv_node::rpc::Network::Bitcoin,
            bitcoin::Network::Testnet | bitcoin::Network::Testnet4 => {
                qsv_node::rpc::Network::Testnet
            }
            bitcoin::Network::Signet => qsv_node::rpc::Network::Signet,
            bitcoin::Network::Regtest => qsv_node::rpc::Network::Regtest,
        };
        match rpc_port {
            Some(port) => qsv_node::rpc::BitcoinRpc::from_cookie_with_port(&datadir, rpc_net, port),
            None => {
                qsv_node::rpc::BitcoinRpc::from_endpoint(&qsv_node::rpc::NodeEndpoint::Cookie {
                    datadir: datadir.clone(),
                    network: rpc_net,
                })
            }
        }
        .map_err(|e| format!("cannot reach node (start bitcoind or pass --tip N): {e}"))
    };

    let render_once = |tip: u32, source: &str| {
        let status = qsv_core::dashboard::vault_status(&qsv_core::dashboard::DashboardInput {
            vault: &vault,
            tip,
            last_refresh_block,
        });
        let lines = qsv_core::dashboard::render(&status, tip, &address);
        println!("\n───── [4] VAULT DASHBOARD ────────────────────────────────────");
        println!("{}  ({source})", lines.tip);
        println!("{}", lines.heartbeat);
        println!("{}", lines.inheritance);
        println!("{}", lines.clawback);
        println!("{}", lines.policy);
        println!(
            "Dates (≈10 min/block): refresh {}, inheritance {}",
            status.dates.heartbeat_refresh_due, status.dates.inheritance_activates
        );
    };

    match tip_override {
        Some(t) => {
            render_once(t, "--tip override (offline)");
            Ok(())
        }
        None => {
            let rpc = connect()?;
            // GRACEFUL WATCH (Round 30): SIGTERM/SIGINT ends the watch loop
            // CLEANLY (exit 0) instead of killing the process — an
            // operator's Ctrl-C and a supervisor's stop both leave an
            // honest exit status (and, under coverage, the child's profile)
            // behind.
            let stop = qsv_cosigner::Shutdown::disabled()
                .install_signal_handlers()
                .map_err(|e| format!("signal handler: {e}"))?;
            loop {
                if stop.requested() {
                    println!("\nDashboard: watch stopped (signal). 🛑");
                    return Ok(());
                }
                let t = rpc
                    .getblockcount()
                    .map_err(|e| format!("getblockcount failed: {e}"))?;
                let best = rpc
                    .getbestblockhash()
                    .map_err(|e| format!("getbestblockhash failed: {e}"))?;
                let source = format!(
                    "live node · best {}…{}",
                    &best[..12],
                    &best[best.len() - 6..]
                );
                if watch_secs > 0 {
                    print!("\x1b[2J\x1b[1;1H"); // clear screen for the next frame
                }
                render_once(t, &source);
                if watch_secs == 0 {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_secs(watch_secs));
            }
        }
    }
}

// ───────────────────────── PSBT Phase 1 (BIP-174/371) ─────────────────────────

/// Demo outpoint the Phase-1 PSBT spends. The flow — not the coin — is what
/// Phase 1 pins down; a live outpoint is wired in Phase 2 (wallet RPC).
const PSBT_DEMO_TXID: [u8; 32] = [0xABu8; 32];

/// Maps a CLI network onto the qsv-node RPC network tag.
fn rpc_network(network: bitcoin::Network) -> qsv_node::rpc::Network {
    match network {
        bitcoin::Network::Bitcoin => qsv_node::rpc::Network::Bitcoin,
        bitcoin::Network::Testnet | bitcoin::Network::Testnet4 => qsv_node::rpc::Network::Testnet,
        bitcoin::Network::Signet => qsv_node::rpc::Network::Signet,
        bitcoin::Network::Regtest => qsv_node::rpc::Network::Regtest,
    }
}

/// Maps a network onto its lowercase CLI spelling.
fn network_name(network: bitcoin::Network) -> &'static str {
    match network {
        bitcoin::Network::Bitcoin => "mainnet",
        bitcoin::Network::Regtest => "regtest",
        bitcoin::Network::Signet => "signet",
        _ => "testnet",
    }
}

/// Live PSBT (Phase 2): coordinator reads a REAL confirmed UTXO paying the
/// demo vault address from the node, builds the unsigned BIP-174/371 PSBT,
/// the two devices sign (each recomputing the BIP-341 sighash itself), the
/// coordinator verifies and finalizes, and the extracted transaction is
/// broadcast to the node — the mempool IS the judge.
fn psbt_live(
    datadir: &std::path::Path,
    rpc_port: Option<u16>,
    network: bitcoin::Network,
    destination: Option<&str>,
    fee_sat: u64,
    build_only: bool,
    sign_only: bool,
    dir: &std::path::Path,
    min_inputs: usize,
    p2mr: bool,
    fund_sat: u64,
) -> Result<(), String> {
    #![allow(clippy::too_many_arguments)]
    if build_only && sign_only {
        return Err("--build-only and --sign-only are mutually exclusive".into());
    }
    if p2mr {
        // BIP-360 (P2MR) has no consensus rules on ANY live network today;
        // the source-branch prototype may only ever execute on regtest
        // (docs/11 Phase 4b, K1-gated).
        if network != bitcoin::Network::Regtest {
            return Err("--p2mr is a REGTEST-ONLY experimental source-branch trial (BIP-360 is not active on any live network)".into());
        }
        println!("  MODE:         EXPERIMENTAL BIP-360 (P2MR) SOURCE TRIAL — regtest only, K1-gated (docs/11)");
    }
    println!("\n───── [10] PSBT · LIVE (Phase 2: real UTXO → real mempool) ─────");

    // 1. Read-only node connection via the datadir cookie (optionally on an
    //    explicit RPC port for nodes started off the default port).
    let rpc = match rpc_port {
        Some(port) => {
            qsv_node::rpc::BitcoinRpc::from_cookie_with_port(datadir, rpc_network(network), port)
        }
        None => qsv_node::rpc::BitcoinRpc::from_endpoint(&qsv_node::rpc::NodeEndpoint::Cookie {
            datadir: datadir.to_path_buf(),
            network: rpc_network(network),
        }),
    }
    .map_err(|e| format!("cannot reach node (is bitcoind running?): {e}"))?;
    let tip = rpc
        .getblockcount()
        .map_err(|e| format!("getblockcount failed: {e}"))?;
    let best = rpc
        .getbestblockhash()
        .map_err(|e| format!("getbestblockhash failed: {e}"))?;
    println!(
        "  node:         tip {tip} · best {}…{}",
        &best[..12],
        &best[best.len() - 6..]
    );

    // 2. The one demo vault and its live address.
    let vault = demo_vault()?;
    // P2MR source trial: the INPUT coin pays the vault's experimental P2MR
    // address (witness v2 over the merkle root). The spending machinery —
    // leaf script, BIP-341 sighash, witness layout — is IDENTICAL; only the
    // output commitment differs (no internal key, no tweak).
    let (address, prev_spk) = if p2mr {
        let p2mr_addr = vault
            .p2mr_address_experimental(network)
            .map_err(|e| e.to_string())?;
        let program = p2mr_addr
            .witness_program()
            .expect("v2 witness program present");
        (
            p2mr_addr.to_string(),
            p2mr_witness_v2_spk(program.program().as_bytes()),
        )
    } else {
        (
            vault.address(network).to_string(),
            p2tr_spk(vault.output_key()),
        )
    };
    let enclave_kp =
        qsv_pqc::enclave_keypair_from_seed(&DEMO_ENCLAVE_SEED).map_err(|e| e.to_string())?;

    // 3. Scan the live UTXO set (gettxoutsetinfo) for the vault coin.
    if fund_sat > 0 {
        // Regtest convenience (same drill frost-spend uses): fund the
        // scanned address, then mine one block so the coin confirms.
        let amount = format!("{:.8}", fund_sat as f64 / 100_000_000.0);
        rpc.call(
            "sendtoaddress",
            &[serde_json::json!(address), serde_json::json!(amount)],
        )
        .map_err(|e| format!("fund sendtoaddress failed: {e}"))?;
        let miner = rpc
            .call("getnewaddress", &[serde_json::json!("")])
            .map_err(|e| e.to_string())?;
        let _: serde_json::Value = rpc
            .call(
                "generatetoaddress",
                &[serde_json::json!(1), serde_json::json!(miner)],
            )
            .map_err(|e| e.to_string())?;
        println!("  funded:       {fund_sat} sats → {address} (1 conf)");
    }
    println!("  scanning:     UTXO set for {address}");
    let utxo_info = rpc
        .scan_utxos_for_address(&address, 10_000)
        .map_err(|e| format!("UTXO scan failed: {e}"))?;
    if utxo_info.len() < min_inputs {
        return Err(if utxo_info.is_empty() {
            format!("no live UTXO pays {address} — fund it first (sendtoaddress + 1 conf)")
        } else {
            format!(
                "no live UTXO set large enough: need {min_inputs} coins paying {address}, found {}",
                utxo_info.len()
            )
        });
    }
    // MULTI-INPUT coin selection: greedy largest-first over the live coins.
    let total: Amount = utxo_info.iter().map(|(_, a)| *a).sum();
    let fee = Amount::from_sat(fee_sat);
    let selection = if min_inputs == 1 {
        utxo_info[..1].to_vec()
    } else {
        // Sum ALL scanned coins first; the selection covers the whole sweep
        // (simplest sound policy for a vault consolidation: sweep everything).
        utxo_info.clone()
    };
    let inputs_total: Amount = selection.iter().map(|(_, a)| *a).sum();
    for (o, a) in &selection {
        println!("  live UTXO:    {o} · {} sats (confirmed)", a.to_sat());
    }
    if min_inputs > 1 {
        println!(
            "  selection:    {} coins · {} sats aggregate (multi-input sweep)",
            selection.len(),
            inputs_total.to_sat()
        );
    } else {
        println!("  selection:    {} coin", selection.len());
    }
    let _ = total;
    if p2mr {
        println!("  staging:      EXPERIMENTAL P2MR SOURCE TRIAL (K1 outstanding: spend requires BIP-360 consensus rules — this tx will NOT be broadcast)");
    } else {
        println!("  staging:      key-path P2TR (tweaked, stage-2 CSV via nSequence)");
    }

    // 4. Output: the stage-1 STAGING policy — a key-path-only P2TR locked to
    //    the tweaked staging key (the REAL unvault output shape; the Phase-1
    //    demo's tapscript output was a documentational fixture that a real
    //    node rightly rejects as non-standard). The operator-supplied
    //    destination key (or the demo provisioning key) is tweaked per
    //    BIP-341 §3 exactly like qsv-node's lifecycle builder.
    let staging_key: XOnlyPublicKey = match destination {
        Some(hex_key) => {
            let bytes = hex::decode(hex_key)
                .map_err(|_| "--destination must be 64 hex chars (x-only pubkey)".to_string())?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "--destination must be 64 hex chars (x-only pubkey)".to_string())?;
            XOnlyPublicKey::from_slice(&arr)
                .map_err(|_| "--destination is not a valid x-only pubkey".to_string())?
        }
        None => demo_keys::recovery_key(),
    };
    let staging_output_key = {
        let secp = Secp256k1::verification_only();
        let tweak =
            bitcoin::taproot::TapTweakHash::from_key_and_tweak(staging_key, None).to_scalar();
        staging_key
            .add_tweak(&secp, &tweak)
            .expect("tweak within curve order (BIP-341)")
            .0
    };
    let staging_spk = p2tr_spk(staging_output_key);
    let out_value = inputs_total
        .checked_sub(fee)
        .ok_or("fee exceeds the aggregate input value")?;
    let outputs = vec![bitcoin::TxOut {
        value: out_value,
        script_pubkey: staging_spk.clone(),
    }];

    // 5. Build the unsigned PSBT from the LIVE outpoint(s).
    let control = vault
        .spend_info
        .control_block(&(
            vault.leaves.normal.clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .ok_or("control block missing for the normal leaf")?;
    let vault_inputs: Vec<qsv_core::psbt::VaultPsbtInput> = selection
        .iter()
        .map(|(outpoint, prev_value)| qsv_core::psbt::VaultPsbtInput {
            outpoint: *outpoint,
            prev_value: *prev_value,
            prev_script_pubkey: prev_spk.clone(),
            leaf_script: vault.leaves.normal.clone(),
            control_block: control.clone(),
            merkle_root: vault.merkle_root(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
        })
        .collect();
    let unsigned = if vault_inputs.len() == 1 {
        qsv_core::psbt::build_unsigned_psbt(&vault_inputs[0], outputs, vault.internal_key)
            .map_err(|e| e.to_string())?
    } else {
        qsv_core::psbt::build_multi_input_psbt(&vault_inputs, outputs, vault.internal_key)
            .map_err(|e| e.to_string())?
    };
    let build_path = dir.join("vault.psbt");
    psbt_write(&build_path, &unsigned)?;
    println!(
        "  build:        wrote {} (BIP-371 fields ✓)",
        build_path.display()
    );
    if build_only {
        println!("\nLive PSBT: BUILD ONLY (stop requested). 🛡️");
        return Ok(());
    }

    // 6. Device signing: each device recomputes the BIP-341 sighash for
    //    EVERY input from the PSBT itself; the coordinator refuses anything
    //    that does not verify under the leaf key.
    let mut signed = unsigned;
    let leaf = vault.leaves.normal.clone();
    let secp = Secp256k1::verification_only();
    let devices: Vec<(&str, bitcoin::secp256k1::Keypair, XOnlyPublicKey)> = vec![
        (
            "slot 1 · user hardware wallet",
            demo_keys::user_keypair(),
            demo_keys::user_key(),
        ),
        (
            "slot 2 · enclave co-signer",
            enclave_kp,
            qsv_pqc::enclave_xonly_public_key(&enclave_kp),
        ),
    ];
    for idx in 0..vault_inputs.len() {
        for (name, kp, pk) in &devices {
            let sig = qsv_core::psbt::device_sign_input_multi(&signed, idx, &leaf, kp)
                .map_err(|e| e.to_string())?;
            let s64: [u8; 64] = sig[..64].try_into().map_err(|_| "short signature")?;
            qsv_core::psbt::verify_device_signature_multi(&secp, *pk, &signed, idx, &leaf, &s64)
                .map_err(|e| e.to_string())?;
            qsv_core::psbt::store_tap_script_sig(&mut signed, idx, *pk, &leaf, &s64)
                .map_err(|e| e.to_string())?;
            if idx == 0 {
                println!("  sign:         {name} ✓ input {idx} (verified under leaf key)");
            }
        }
    }
    println!(
        "  sign:         {} inputs × 2 devices ✓ (all verified)",
        vault_inputs.len()
    );
    let sign_path = dir.join("vault-signed.psbt");
    psbt_write(&sign_path, &signed)?;
    println!("  sign:         wrote {}", sign_path.display());
    if sign_only {
        println!("\nLive PSBT: SIGN ONLY (stop requested). 🛡️");
        return Ok(());
    }

    // 7. Finalize: per-input witness (script execution order: the script
    //    checks <pk_user> first, so [σ_enclave, σ_user]), extract, and the
    //    multi-input consensus self-check.
    let user_x = demo_keys::user_key();
    let enclave_x = qsv_pqc::enclave_xonly_public_key(&enclave_kp);
    let exec_order = [enclave_x, user_x];
    let witnesses: Vec<bitcoin::Witness> = (0..vault_inputs.len())
        .map(|i| {
            qsv_core::psbt::assemble_witness_for_input(
                &signed,
                i,
                &leaf,
                &vault_inputs[i].control_block,
                &exec_order,
            )
        })
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let prevouts: Vec<(bitcoin::ScriptBuf, Amount)> = vault_inputs
        .iter()
        .map(|i| (i.prev_script_pubkey.clone(), i.prev_value))
        .collect();
    let mut final_psbt = signed;
    let tx = qsv_core::psbt::finalize_multi_input_and_extract(&mut final_psbt, witnesses)
        .map_err(|e| e.to_string())?;
    if vault_inputs.len() == 1 {
        let utxo = &vault_inputs[0];
        qsv_core::consensus::verify_input(&tx, 0, &utxo.prev_script_pubkey, utxo.prev_value)
            .map_err(|e| format!("consensus REJECTED the extracted transaction: {e}"))?;
    } else {
        qsv_core::consensus::verify_transaction(&tx, &prevouts)
            .map_err(|e| format!("consensus REJECTED the multi-input spend: {e}"))?;
    }
    let final_path = dir.join("vault-final.psbt");
    psbt_write(&final_path, &final_psbt)?;
    println!("  finish:       consensus engine ACCEPT (libbitcoinconsensus) ✅");
    println!("  finish:       wrote {}", final_path.display());

    // 8. Broadcast: the node's mempool is the final judge.
    if p2mr {
        // K1 gate (docs/11): BIP-360 has no consensus rules on any live
        // network. The trial transaction goes to the hold file; broadcasting
        // a spend of a witness-v2 P2MR output is IMPOSSIBLE today — bitcoind
        // would reject the unknown witness version.
        let hold = dir.join("p2mr-source-trial.txhex");
        std::fs::write(&hold, bitcoin::consensus::encode::serialize_hex(&tx))
            .map_err(|e| format!("cannot write {}: {e}", hold.display()))?;
        println!(
            "  hold:         {} (NOT broadcast — K1 outstanding)",
            hold.display()
        );
        // MEASURED P2MR delta (docs/11 §7.5): the P2TR reference control
        // block carries the 33rd (internal-key) byte, so a P2TR twin of this
        // exact spend weighs 32 WU (= 8 vB) more per input — witness bytes
        // count 1 WU each under BIP-141. Rebuild the SAME spend with a
        // +32-byte control block and compare the REAL weights.
        let weight_actual = tx.weight().to_wu();
        let n_inputs = tx.input.len();
        let mut tx_p2tr = tx.clone();
        for vin in tx_p2tr.input.iter_mut() {
            let mut w_p2tr = bitcoin::Witness::new();
            let last = vin.witness.last().expect("control block present").to_vec();
            let cb_twin = {
                let mut b = vec![0u8; last.len() + 32];
                b[..last.len()].copy_from_slice(&last);
                b
            };
            for (i, e) in vin.witness.iter().enumerate() {
                let is_last = i == vin.witness.len() - 1;
                w_p2tr.push(if is_last { cb_twin.clone() } else { e.to_vec() });
            }
            vin.witness = w_p2tr;
        }
        let weight_p2tr = tx_p2tr.weight().to_wu();
        println!(
            "  p2mr weight:  {} WU ({} vB) vs P2TR twin {} WU ({} vB) · saved {} WU = {} vB × {} input(s)",
            weight_actual,
            weight_actual.div_ceil(4),
            weight_p2tr,
            weight_p2tr.div_ceil(4),
            weight_p2tr - weight_actual,
            (weight_p2tr - weight_actual) / 4 / n_inputs as u64,
            n_inputs
        );
        assert_eq!(
            weight_p2tr - weight_actual,
            32 * n_inputs as u64,
            "the measured saving must equal 32 WU = 8 vB per input (32 witness B × 1 WU)"
        );
        println!("\nP2MR source trial: COMPLETE (address → PSBT → sighash → witness). 🛡️");
        return Ok(());
    }
    let hex = bitcoin::consensus::encode::serialize_hex(&tx);
    let txid: bitcoin::Txid = rpc
        .call("sendrawtransaction", &[serde_json::json!(hex)])
        .map_err(|e| format!("mempool REJECTED the transaction: {e}"))?
        .as_str()
        .ok_or("node returned no txid")?
        .parse()
        .map_err(|e| format!("node returned a bad txid: {e}"))?;
    println!("  broadcast:    mempool ACCEPTED · txid {txid}");
    println!("  next:         mine 1 block and gettxout {txid} 0 confirms the spend on-chain");
    println!("\nLive PSBT: COMPLETE (real UTXO → real mempool). 🛡️");
    Ok(())
}

// ─── Inheritance watchtower DAEMON (multi-vault inventory, docs/10 §3.2) ───

/// One vault row of the inventory file (`--inventory env.json`).
#[derive(serde::Deserialize)]
struct WatchtowerVaultSpec {
    id: String,
    last_refresh_block: u32,
    #[serde(default)]
    webhook: Option<String>,
    #[serde(default)]
    webhook_token: Option<String>,
    #[serde(default)]
    webhook_secret: Option<String>,
}

#[derive(serde::Deserialize)]
struct WatchtowerInventory {
    vaults: Vec<WatchtowerVaultSpec>,
}

/// Persistent per-pass observation (state file schema, docs/10 §3.2).
/// `webhook_delivery` records the LAST delivery outcome of the secondary
/// alarm channel per vault (`delivered`/`failed`/`not_configured`) so the
/// operator can see what the relay actually received — the exit code stays
/// the PRIMARY channel (a failed webhook never softens a real ALERT).
#[derive(serde::Serialize)]
struct WatchtowerStateEntry {
    last_tip: u32,
    last_verdict: &'static str,
    idle_blocks: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    webhook_delivery: Option<WebhookDelivery>,
}

#[derive(serde::Serialize)]
struct WatchtowerStateFile {
    tip: u32,
    generated_at: String,
    vaults: std::collections::BTreeMap<String, WatchtowerStateEntry>,
}

/// Multi-vault watchtower pass (docs/10 §3.2): every vault in the
/// inventory is heartbeat-audited in ONE read-only pass; per-vault
/// observations persist to `<state-dir>/watchtower-state.json` and any
/// configured webhook receives an ALARM POST (the exit code NEVER depends
/// on the webhook — the primary alarm channel is the process exit).
/// ONE due vault fails the whole pass (ALERT[vault-id]). No broadcasting,
/// no spending authority, ever.
fn watchtower_multi(
    datadir: &std::path::Path,
    rpc_port: Option<u16>,
    network: bitcoin::Network,
    inventory: &std::path::Path,
    state_dir: &std::path::Path,
    single_vault_flags_present: bool,
) -> Result<(), String> {
    println!("\n───── [14] WATCHTOWER · MULTI-VAULT DAEMON PASS ────────────────");
    if single_vault_flags_present {
        // Usage confusion is exit 2 per the CLI contract (docs/10 §1).
        eprintln!(
            "usage error: --inventory conflicts with the single-vault --last-refresh-block/--deal/--public paths"
        );
        std::process::exit(2);
    }
    let inv_text = std::fs::read_to_string(inventory)
        .map_err(|e| format!("cannot read inventory {}: {e}", inventory.display()))?;
    let inv: WatchtowerInventory =
        serde_json::from_str(&inv_text).map_err(|e| format!("malformed inventory: {e}"))?;
    if inv.vaults.is_empty() {
        return Err("inventory has an empty vaults array".to_string());
    }

    let rpc = match rpc_port {
        Some(port) => {
            qsv_node::rpc::BitcoinRpc::from_cookie_with_port(datadir, rpc_network(network), port)
        }
        None => qsv_node::rpc::BitcoinRpc::from_endpoint(&qsv_node::rpc::NodeEndpoint::Cookie {
            datadir: datadir.to_path_buf(),
            network: rpc_network(network),
        }),
    }
    .map_err(|e| format!("cannot reach node (is bitcoind running?): {e}"))?;
    let tip = rpc.getblockcount().map_err(|e| e.to_string())?;
    println!("  node:         tip {tip} (read-only pass — nothing is broadcast)");
    println!(
        "  inventory:    {} vaults from {}",
        inv.vaults.len(),
        inventory.display()
    );

    let policy = qsv_core::heartbeat::HeartbeatPolicy::default();
    policy
        .validate()
        .map_err(|e| format!("heartbeat policy: {e}"))?;

    // ROTATION-STATE v2: the id-based rotation records (written by
    // vault-rotate) are the CHAIN TRUTH — a stale inventory row must not
    // fabricate an alert for a vault that DID refresh. The recorded baseline
    // wins when it is LATER than the inventory row (a warning line tells the
    // operator to fix the inventory); a missing rotation-state file leaves
    // the inventory alone (the daemon still works state-less); an unreadable
    // one fails closed; a record claiming a refresh ABOVE the tip is corrupt
    // and ignored (rotation_baseline_for filters it).
    let rotation_state = match load_rotation_state(state_dir) {
        Ok(s) => {
            println!(
                "  rotation:     {} consulted (id-based v2)",
                state_dir.join("rotation-state.json").display()
            );
            Some(s)
        }
        Err(e) if e.contains("No such file") => None,
        Err(e) => return Err(format!("rotation state unreadable (fail-closed): {e}")),
    };

    let mut alerts = Vec::new();
    let mut entries = std::collections::BTreeMap::new();
    for v in &inv.vaults {
        let lrb = match rotation_state
            .as_ref()
            .and_then(|s| rotation_baseline_for(s, &v.id, tip))
        {
            Some(recorded) if recorded > v.last_refresh_block => {
                println!(
                    "  [{:>16}] rotation-state: refreshed at {recorded} — inventory row ({}) is stale, using {recorded}",
                    v.id, v.last_refresh_block
                );
                recorded
            }
            _ => v.last_refresh_block,
        };
        let idle = tip.saturating_sub(lrb);
        let due = qsv_core::heartbeat::is_due(&policy, lrb, tip);
        let verdict = if due { "ALERT" } else { "clear" };
        println!(
            "  [{:>16}] idle {:>6} / {} blocks · {}",
            v.id,
            idle,
            policy.interval_blocks,
            if due {
                "DUE — OWNER REFRESH MISSED"
            } else {
                "healthy"
            }
        );
        if due {
            alerts.push(v.id.clone());
        }
        // AT-LEAST-ONCE delivery: the POST is retried with fixed backoff
        // inside `post_webhook`; the verdict persists in the state file so
        // the operator sees what the secondary channel actually did. A
        // failing webhook NEVER softens the pass — the ALERT above and the
        // exit code remain the primary alarm channel (docs/10 §3.2).
        let delivery =
            if let Some(url) = &v.webhook {
                let out = webhook::post_webhook(
                    url,
                    v.webhook_token.as_deref(),
                    v.webhook_secret.as_deref(),
                    v.id.clone(),
                    tip,
                    idle,
                ); // Anything that is not a delivery is reported as FAILED —
                   // `post_webhook` with a URL never answers NotConfigured, and a
                   // verdict this pass cannot classify must never read green.
                match out.delivery {
                    WebhookDelivery::Delivered => println!(
                        "  [{:>16}] webhook: delivered after {} attempt(s) ✓",
                        v.id, out.attempts
                    ),
                    _ => println!(
                    "  [{:>16}] webhook: FAILED after {} attempt(s) ({} — exit code unaffected)",
                    v.id, out.attempts, out.last_error.as_deref().unwrap_or("unknown")
                ),
                }
                Some(out.delivery)
            } else {
                Some(WebhookDelivery::NotConfigured)
            };
        entries.insert(
            v.id.clone(),
            WatchtowerStateEntry {
                last_tip: tip,
                last_verdict: verdict,
                idle_blocks: idle,
                webhook_delivery: delivery,
            },
        );
    }

    // Persist the pass (fail-closed: an unreadable state dir must not be
    // silently ignored — the next pass's baseline would be fabricated).
    std::fs::create_dir_all(state_dir)
        .map_err(|e| format!("cannot create state dir {}: {e}", state_dir.display()))?;
    let state = WatchtowerStateFile {
        tip,
        generated_at: "".to_string(),
        vaults: entries,
    };
    let state_path = state_dir.join("watchtower-state.json");
    let body =
        serde_json::to_string_pretty(&state).map_err(|e| format!("cannot serialize state: {e}"))?;
    std::fs::write(&state_path, body)
        .map_err(|e| format!("cannot write {}: {e}", state_path.display()))?;
    println!("  state:        {} updated", state_path.display());

    if !alerts.is_empty() {
        for id in &alerts {
            println!("  ALERT[{id}]: heartbeat due, owner refresh MISSED");
        }
        println!(
            "\nWATCHTOWER: ALERT — {} vault(s) missed the heartbeat. 🚨",
            alerts.len()
        );
        return Err(format!("heartbeat due for vault(s): {}", alerts.join(", ")));
    }
    println!(
        "\nWATCHTOWER: all clear across {} vaults. 🛡️",
        inv.vaults.len()
    );
    Ok(())
}

// ─── Vault rotation: the owner's heartbeat drill (docs/10 §4) ───

/// Parses `label=pqc-seed-hex` heir re-attestation specs.
fn parse_heir_specs(specs: &[String]) -> Result<Vec<(String, [u8; 32])>, String> {
    specs
        .iter()
        .map(|s| {
            let (label, seed_hex) = s
                .split_once('=')
                .ok_or_else(|| format!("--heir must be <label>=<pqc-seed-hex>, got '{s}'"))?;
            let seed = hex::decode(seed_hex.trim())
                .ok()
                .and_then(|v| <[u8; 32]>::try_from(v).ok())
                .ok_or_else(|| format!("heir '{label}': seed must be 32 bytes of hex"))?;
            Ok((label.trim().to_string(), seed))
        })
        .collect()
}

/// The chain outcome of a broadcast rotation: the tip (recorded as the new
/// heartbeat baseline) and the refresh transaction id.
#[derive(Debug, Clone, Copy)]
struct RefreshedRotation {
    tip: u32,
    txid: bitcoin::Txid,
}

/// Vault rotation: heartbeat refresh + heir registry re-attestation
/// (docs/10 §4). The vault pays ITSELF: one confirmed UTXO in, one output
/// back to the same address, CSV clock reset. The spend goes through the
/// normal hybrid leaf, so the user key signs and the enclave co-signs —
/// the vault never relies on the inheritance path while the owner is
/// alive. Fail-closed everywhere: no UTXO, no match, a stale heir
/// identity or a consensus reject aborts with exit 1 and nothing changes
/// on chain. Broadcast success returns `Some(RefreshedRotation { tip,
/// txid })` (hold mode returns `None`) so the multi-vault sweep can share
/// ONE refresh across all ids that resolve to the SAME demo vault address.
#[allow(clippy::too_many_arguments)]
fn vault_rotate(
    datadir: &std::path::Path,
    rpc_port: Option<u16>,
    network: bitcoin::Network,
    fee_sat: u64,
    heirs: &[String],
    no_broadcast: bool,
    dir: &std::path::Path,
    cosigner_client: Option<&qsv_cosigner::BridgeClient>,
    cosigner_pin: &CosignerPin,
    inventory: Option<&std::path::Path>,
    vault_id: Option<&str>,
    last_refresh_override: Option<u32>,
    state_dir: &std::path::Path,
) -> Result<Option<RefreshedRotation>, String> {
    use bitcoin::consensus::Encodable;
    use bitcoin::opcodes::all::OP_PUSHNUM_1;
    use bitcoin::script::Builder;
    use qsv_core::heartbeat;
    use qsv_core::unvault::{self, SpendContext};

    println!("\n───── [15] VAULT ROTATE · HEARTBEAT REFRESH + HEIR ATTESTATION ──");
    if inventory.is_some() != vault_id.is_some() {
        return Err(
            "--inventory and --vault-id must be given together (single-vault mode uses --last-refresh-block)"
                .into(),
        );
    }
    let rpc = match rpc_port {
        Some(port) => {
            qsv_node::rpc::BitcoinRpc::from_cookie_with_port(datadir, rpc_network(network), port)
        }
        None => qsv_node::rpc::BitcoinRpc::from_endpoint(&qsv_node::rpc::NodeEndpoint::Cookie {
            datadir: datadir.to_path_buf(),
            network: rpc_network(network),
        }),
    }
    .map_err(|e| format!("cannot reach node (is bitcoind running?): {e}"))?;
    let tip = rpc.getblockcount().map_err(|e| e.to_string())?;

    // The same demo policy the rest of the operator surface uses.
    let vault = demo_vault()?;
    let address = vault.address(network);
    let address_str = address.to_string();
    println!("  vault:        {address_str}");

    // HEIR RE-ATTESTATION (docs/04 §5): every registered heir must prove
    // the PQC identity behind its commitment BEFORE the coin moves.
    let heir_pairs: Vec<([u8; 32], Vec<u8>)> = if heirs.is_empty() {
        println!("  heirs:        demo registry (2 heirs, no re-attestation)");
        vec![
            (
                qsv_core::demo_keys::heir_one().serialize(),
                qsv_pqc::PqcIdentity::from_seed(&[11u8; 32])
                    .verifying_key_bytes()
                    .to_vec(),
            ),
            (
                qsv_core::demo_keys::heir_two().serialize(),
                qsv_pqc::PqcIdentity::from_seed(&[12u8; 32])
                    .verifying_key_bytes()
                    .to_vec(),
            ),
        ]
    } else {
        let specs = parse_heir_specs(heirs)?;
        println!(
            "  heirs:        re-attesting {} PQC identit(y/ies)",
            specs.len()
        );
        // The demo vault registers two heir slots; a rotation that
        // re-attests must cover ALL of them (partial registries would
        // silently change the inheritance policy).
        let expected = 2usize;
        if specs.len() != expected {
            return Err(format!(
                "heir re-attestation must cover all {expected} registered heirs, got {}",
                specs.len()
            ));
        }
        // Demo slot binding is positional: re-attestation #1 renews the
        // identity committed under heir slot one, #2 under slot two.
        let slot_keys = [
            qsv_core::demo_keys::heir_one().serialize(),
            qsv_core::demo_keys::heir_two().serialize(),
        ];
        specs
            .iter()
            .enumerate()
            .map(|(i, (label, seed))| {
                let pqc = qsv_pqc::PqcIdentity::from_seed(seed);
                println!("    [{label:>16}] ML-DSA-65 identity verified ✓");
                (slot_keys[i], pqc.verifying_key_bytes().to_vec())
            })
            .collect()
    };
    let registry =
        qsv_core::heirs::HeirSet::build(heir_pairs).map_err(|e| format!("heir registry: {e}"))?;
    println!(
        "  registry:     {} commitment(s) re-sealed into the refreshed vault",
        registry.len()
    );

    // HEARTBEAT BASELINE (after the pure-crypto heir check: identity is
    // chain-independent): inventory row / persisted rotation state / explicit
    // --last-refresh-block — in that order of precedence. A rotation may run
    // ONLY when the heartbeat is DUE; the successful run persists the tip as
    // the new baseline (an early re-rotation is refused, so the alarm↔
    // rotation story stays consistent: the watchtower can never observe an
    // "ALERT" that rotation state contradicts).
    let policy = heartbeat::HeartbeatPolicy::default();
    policy
        .validate()
        .map_err(|e| format!("heartbeat policy: {e}"))?;
    let (id_label, baseline): (String, u32) = match (inventory, vault_id) {
        (Some(inv), Some(vid)) => {
            let text = std::fs::read_to_string(inv)
                .map_err(|e| format!("cannot read inventory {}: {e}", inv.display()))?;
            let inv_json: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("malformed inventory: {e}"))?;
            let rows = inv_json["vaults"]
                .as_array()
                .ok_or("malformed inventory: missing vaults array")?;
            let row = rows
                .iter()
                .find(|r| r["id"].as_str() == Some(vid))
                .ok_or_else(|| format!("vault '{vid}' not found in the inventory"))?;
            let inv_lrb = row["last_refresh_block"]
                .as_u64()
                .ok_or_else(|| format!("inventory row '{vid}' has no last_refresh_block"))?
                as u32;
            // CROSS-SOURCE CONSISTENCY: the persisted rotation state (if any)
            // must agree with the inventory row. The rotation state records
            // what ACTUALLY happened on chain; a row older than the recorded
            // refresh means the watchtower would fire a false ALARM on a
            // fresh vault — refuse and let the operator fix the inventory.
            // A MISSING state file is not an error: nothing was ever
            // recorded, so the inventory alone drives the baseline.
            let state = match load_rotation_state(state_dir) {
                Ok(s) => s,
                Err(e) if e.contains("No such file") => {
                    serde_json::json!({"version": 2, "vaults": {}})
                }
                Err(e) => return Err(e),
            };
            match rotation_baseline_for(&state, vid, tip) {
                Some(recorded) if inv_lrb < recorded => {
                    return Err(format!(
                        "inventory/rotation-state MISMATCH for '{vid}': inventory claims last_refresh_block {inv_lrb} but a verified rotation recorded {recorded} — fix the inventory row (rotation state wins: it reflects the chain)"
                    ));
                }
                Some(recorded) => (vid.to_string(), recorded.max(inv_lrb)),
                None => (vid.to_string(), inv_lrb),
            }
        }
        _ => match last_refresh_override {
            Some(lrb) => ("single-vault".to_string(), lrb),
            None => {
                let state = match load_rotation_state(state_dir) {
                    Ok(s) => s,
                    Err(e) if e.contains("No such file") => {
                        return Err(
                            "no heartbeat baseline: pass --inventory+--vault-id, --last-refresh-block, or seed <state-dir>/rotation-state.json"
                                .into(),
                        )
                    }
                    Err(e) => return Err(e),
                };
                match rotation_baseline_for(&state, "single-vault", tip) {
                    Some(lrb) => ("single-vault".to_string(), lrb),
                    None if state["version"].as_u64() == Some(2) => {
                        // v2 state without a "single-vault" record: a v2 file
                        // with only inventory-id records means the operator
                        // manages those vaults via inventory; refusing beats
                        // guessing.
                        return Err(
                            "no heartbeat baseline for the single-vault path: the state file uses id-based records — pass --inventory+--vault-id or --last-refresh-block"
                                .into(),
                        );
                    }
                    None => {
                        // v1 fallback: single-vault documents store the
                        // baseline at top level (kept for transition).
                        let v1 = state.as_object().and_then(|m| m.get("last_refresh_block"));
                        match v1.and_then(serde_json::Value::as_u64) {
                            Some(v) if (v as u32) <= tip => {
                                ("single-vault".to_string(), v as u32)
                            }
                            _ => return Err(
                                "no heartbeat baseline: pass --inventory+--vault-id, --last-refresh-block, or seed <state-dir>/rotation-state.json"
                                    .into(),
                            ),
                        }
                    }
                }
            }
        },
    };
    if !heartbeat::is_due(&policy, baseline, tip) {
        let idle = tip.saturating_sub(baseline);
        return Err(format!(
            "rotation not due: {idle}/{} idle blocks since the last refresh — refusing an early re-rotation",
            policy.interval_blocks
        ));
    }
    println!("  heartbeat:    DUE at tip {tip} · vault [{id_label}] · baseline {baseline}");

    // 1. LIVE UTXO DISCOVERY — read-only scantxoutset, wallet-free.
    let coins = rpc
        .scan_utxos_for_address(&address_str, 25)
        .map_err(|e| format!("cannot scan the vault address: {e}"))?;
    if coins.is_empty() {
        return Err(format!(
            "no confirmed UTXO pays {address_str} — fund the vault first (or point --datadir at the right node)"
        ));
    }
    let (outpoint, value) = coins
        .iter()
        .filter(|(_, v)| v.to_sat() > fee_sat + 546)
        .copied()
        .next()
        .ok_or_else(|| {
            format!("vault UTXO(s) too small for a {fee_sat}-sat refresh fee — nothing was changed")
        })?;
    println!("  coin:         {outpoint} · {} sats", value.to_sat());

    // 2. SELF-CHURN REFRESH: same address in, same address out.
    let refresh =
        heartbeat::build_refresh_tx(&vault, outpoint, value, bitcoin::Amount::from_sat(fee_sat))
            .map_err(|e| e.to_string())?;
    let out_value = refresh.output[0].value;
    println!(
        "  refresh:      {} sats → same address · CSV clock resets",
        out_value.to_sat()
    );

    // 3. HYBRID-LEAF SIGNATURES: user key signs, the enclave co-signs
    //    (deterministic demo enclave signature — the live path requests it
    //    from the co-signer service over the PQC gate).
    let control = vault
        .spend_info
        .control_block(&(
            vault.leaves.normal.clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .expect("control block for normal leaf");
    let out_key = vault.output_key();
    let prev_spk = Builder::new()
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(out_key.serialize())
        .into_script();
    let ctx = SpendContext {
        script: &vault.leaves.normal,
        control_block: &control,
        prev_value: value,
        prev_script_pubkey: &prev_spk,
    };
    // Sighash + user signature over the unsigned refresh.
    let sighash = unvault::script_spend_sighash(
        &refresh,
        0,
        ctx.script,
        ctx.prev_value,
        ctx.prev_script_pubkey,
    );
    let user_sig = unvault::sign_schnorr(&qsv_core::demo_keys::user_keypair(), &sighash);
    // The enclave co-signature: over a LIVE bridge (cosigner-bridge) it is
    // requested through the PQC gate and verified under the pinned enclave
    // key; otherwise the deterministic demo enclave key signs (tests/demos).
    let enclave_sig: [u8; 64] = match cosigner_client {
        Some(client) => {
            println!(
                "  co-signer:    requesting signature from {} (PQC gate)",
                client.addr()
            );
            live_enclave_signature(client, &address_str, &sighash, cosigner_pin)?
        }
        None => unvault::sign_schnorr(
            &qsv_pqc::enclave_keypair_from_seed(&DEMO_ENCLAVE_SEED).map_err(|e| e.to_string())?,
            &sighash,
        ),
    };
    // Witness order `[σ_enclave, σ_user]`: the script pops the stack TOP
    // first (σ_user CHECKSIGVERIFY), so σ_enclave is the deepest element.
    let mut signed = refresh;
    signed.input[0].witness = unvault::build_script_path_witness(
        &[enclave_sig.to_vec(), user_sig.to_vec()],
        ctx.script,
        ctx.control_block,
    );

    // 4. CONSENSUS SELF-CHECK before anything leaves the machine.
    let serialized = {
        let mut buf = Vec::new();
        signed
            .consensus_encode(&mut buf)
            .map_err(|e| format!("encode: {e}"))?;
        buf
    };
    qsv_core::consensus::verify_transaction(&signed, &[(prev_spk.clone(), value)])
        .map_err(|e| format!("consensus REJECTED the refresh transaction: {e}"))?;
    println!("  consensus:    libbitcoinconsensus ACCEPTED the refresh ✓");

    let txid = signed.compute_txid();
    if no_broadcast {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let path = dir.join("vault-rotate.txhex");
        std::fs::write(&path, hex::encode(&serialized))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        println!("  hold:         {} (NOT broadcast)", path.display());
        println!("\nVault rotate: HOLD COMPLETE (signed refresh, nothing broadcast). 🛡️");
        return Ok(None);
    }

    // 5. BROADCAST the refresh — the heartbeat is maintained.
    let raw = serde_json::to_value(hex::encode(&serialized)).unwrap();
    rpc.call("sendrawtransaction", &[raw])
        .map_err(|e| format!("mempool REJECTED the refresh transaction: {e}"))?;
    println!("  broadcast:    mempool ACCEPTED · refresh txid {txid}");
    // 6. PERSIST the new heartbeat baseline (the next run's early-rotation
    //    guard reads this — keeping rotation state and watchtower alarms
    //    consistent).
    // Single-vault rotations record under the stable id "single-vault" (the
    // same id the no-baseline guard reads back); inventory-driven rotations
    // record under the row's id.
    let state_id = vault_id
        .map(str::to_string)
        .unwrap_or_else(|| "single-vault".to_string());
    save_rotation_state(state_dir, tip, &state_id, txid)?;
    println!(
        "  state:        {} updated (baseline {tip})",
        state_dir.join("rotation-state.json").display()
    );
    println!("\nVault rotate: COMPLETE (heartbeat renewed, heirs re-attested). 🛡️");
    Ok(Some(RefreshedRotation { tip, txid }))
}

/// MULTI-VAULT SWEEP (`vault-rotate --inventory <file> --all`): classify
/// every inventory row against the CURRENT tip (with the rotation-state v2
/// id records as chain truth, exactly like the watchtower daemon), then
/// rotate each DUE vault in inventory order. A healthy vault is skipped
/// with a report line; when a rotation-state record is LATER than the row
/// (the row is stale), the record WINS and the report says so — the
/// operator fixes the inventory, the sweep never silently rewrites it.
/// Every SUCCESSFUL rotation
/// persists an id-based rotation-state v2 record (the watchtower daemon's
/// next pass then computes its baseline from that record — the loop
/// closes). A DUE vault that fails (no coin, co-signer refusal, mempool
/// rejection) fails the whole sweep AFTER the remaining vaults were
/// attempted — every vault gets its chance in one operator action.
#[allow(clippy::too_many_arguments)]
fn vault_rotate_batch(
    datadir: &std::path::Path,
    rpc_port: Option<u16>,
    network: bitcoin::Network,
    fee_sat: u64,
    dir: &std::path::Path,
    cosigner_addr: Option<&str>,
    cosigner_all_addr: Option<&str>,
    cosigner_all_cert: Option<&std::path::Path>,
    cosigner_all_key: Option<&std::path::Path>,
    cosigner_all_ca: Option<&std::path::Path>,
    dry_run: bool,
    inventory: &std::path::Path,
    state_dir: &std::path::Path,
    cosigner_pin: &CosignerPin,
) -> Result<(), String> {
    use qsv_core::heartbeat;

    println!("\n───── [15b] VAULT ROTATE · MULTI-VAULT DUE SWEEP ──────────────");
    // Inventory FIRST (fail-fast, no node needed for the walls): a missing,
    // malformed or empty fleet is an operator error and must be reported as
    // such BEFORE any RPC connection is attempted — same shape as the
    // watchtower daemon pass.
    let inv_text = std::fs::read_to_string(inventory)
        .map_err(|e| format!("cannot read inventory {}: {e}", inventory.display()))?;
    let inv: WatchtowerInventory =
        serde_json::from_str(&inv_text).map_err(|e| format!("malformed inventory: {e}"))?;
    if inv.vaults.is_empty() {
        return Err("inventory has an empty vaults array".to_string());
    }
    println!(
        "  inventory:    {} vault(s) from {}",
        inv.vaults.len(),
        inventory.display()
    );

    let rpc = match rpc_port {
        Some(port) => {
            qsv_node::rpc::BitcoinRpc::from_cookie_with_port(datadir, rpc_network(network), port)
        }
        None => qsv_node::rpc::BitcoinRpc::from_endpoint(&qsv_node::rpc::NodeEndpoint::Cookie {
            datadir: datadir.to_path_buf(),
            network: rpc_network(network),
        }),
    }
    .map_err(|e| format!("cannot reach node (is bitcoind running?): {e}"))?;
    let tip = rpc.getblockcount().map_err(|e| e.to_string())?;
    println!("  node:         tip {tip}");

    // The rotation-state v2 records (chain truth) participate in the
    // classification exactly like in the watchtower daemon: a record
    // LATER than the inventory row overrides it (with a warning); an
    // unreadable state file fails closed (never a silent baseline reset).
    let rotation_state = match load_rotation_state(state_dir) {
        Ok(s) => {
            println!(
                "  rotation:     {} consulted (id-based v2)",
                state_dir.join("rotation-state.json").display()
            );
            Some(s)
        }
        Err(e) if e.contains("No such file") => None,
        Err(e) => return Err(format!("rotation state unreadable (fail-closed): {e}")),
    };

    let policy = heartbeat::HeartbeatPolicy::default();
    policy
        .validate()
        .map_err(|e| format!("heartbeat policy: {e}"))?;

    let mut due: Vec<&WatchtowerVaultSpec> = Vec::new();
    let mut refreshed = 0usize;
    let mut skipped_healthy = 0usize;
    for v in &inv.vaults {
        let (baseline, row_is_stale) = match rotation_state
            .as_ref()
            .and_then(|s| rotation_baseline_for(s, &v.id, tip))
        {
            Some(recorded) if recorded > v.last_refresh_block => {
                println!(
                    "  [{:>16}] rotation-state: refreshed at {recorded} — inventory row ({}) is stale, using {recorded}",
                    v.id, v.last_refresh_block
                );
                (recorded, true)
            }
            _ => (v.last_refresh_block, false),
        };
        if heartbeat::is_due(&policy, baseline, tip) {
            println!(
                "  [{:>16}] DUE — queued for refresh (idle {} ≥ {})",
                v.id,
                tip.saturating_sub(baseline),
                policy.interval_blocks
            );
            due.push(v);
        } else {
            skipped_healthy += 1;
            println!(
                "  [{:>16}] healthy — skipping (idle {} < {}){}",
                v.id,
                tip.saturating_sub(baseline),
                policy.interval_blocks,
                if row_is_stale {
                    " · stale row: fix the inventory"
                } else {
                    ""
                }
            );
        }
    }
    if due.is_empty() {
        println!(
            "\nVAULT ROTATE SWEEP: nothing due — {} vault(s) healthy. 🛡️",
            inv.vaults.len()
        );
        return Ok(());
    }
    println!(
        "  sweep:        {} vault(s) due → rotating in order\n",
        due.len()
    );

    // LIVE CO-SIGNER GATE (--cosigner-all): before ANY ceremony, ask the
    // bridge about EVERY due vault — a FROZEN vault (watchtower alarm) is
    // skipped with an explicit line, never attempted, and never fails the
    // sweep (the watchtower already stopped it; the sweep's job is the
    // REST of the fleet). Unprovisioned/transport failures FAIL CLOSED:
    // the gate exists to catch frozen vaults, and an unanswerable gate is
    // not a green light.
    // The gate AND the per-rotation co-signer are the SAME live bridge:
    // --cosigner-all is the explicit sweep form; a plain --cosigner under
    // --all keeps its historical meaning (sign every rotation) AND gains
    // the pre-flight gate (both halves need the bridge up anyway). With
    // mTLS material the sweep talks MUTUAL TLS end to end (the production
    // dev-bridge shape: pinned server root + client identity).
    let gate_addr = cosigner_all_addr.or(cosigner_addr);
    let gate_client = build_gate_client(
        gate_addr,
        cosigner_all_addr.map(|_| (cosigner_all_cert, cosigner_all_key, cosigner_all_ca)),
    )?;
    let mut frozen: Vec<String> = Vec::new();
    if let Some(client) = &gate_client {
        println!(
            "  co-signer:    sweep gate {} ({}) — asking before any ceremony",
            gate_addr.unwrap_or("?"),
            if cosigner_all_addr.is_some() && cosigner_all_cert.is_some() {
                "mTLS"
            } else {
                "plain"
            }
        );
        for v in &due {
            match sweep_vault_gate(client, &v.id) {
                Ok(false) => {}
                Ok(true) => {
                    println!(
                        "  [{:>16}] co-signer: FROZEN (watchtower alarm) — skipping, exit code unaffected",
                        v.id
                    );
                    frozen.push(v.id.clone());
                }
                Err(e) => {
                    return Err(format!(
                        "sweep co-signer gate {} FAILED for vault '{}': {e} (fail-closed: the fleet sweep never proceeds on an unanswerable gate)",
                        gate_addr.unwrap_or("?"),
                        v.id
                    ));
                }
            }
        }
        if !frozen.is_empty() {
            println!(
                "  co-signer:    {} of {} due vault(s) frozen — the sweep refreshes the rest",
                frozen.len(),
                due.len()
            );
        }
    } else if dry_run {
        println!("  dry-run:      no co-signer gate configured — FROZEN status not evaluated");
    }
    let mut failure: Option<String> = None;
    let mut renewed: Option<(u32, bitcoin::Txid)> = None;
    let mut would_renew = false;
    for (i, v) in due.iter().enumerate() {
        if frozen.contains(&v.id) {
            println!(
                "\n  ▶ sweep {}/{}: vault [{}] — FROZEN, skipped",
                i + 1,
                due.len(),
                v.id
            );
            continue;
        }
        if dry_run {
            // PREVIEW ONLY: name the action a real sweep would take — the
            // first DUE vault would broadcast the refresh (the rest share
            // the same coin), and NOTHING is written anywhere.
            if would_renew || renewed.is_some() {
                println!(
                    "\n  ▶ dry-run {}/{}: vault [{}] — would record (shared coin, no re-broadcast)",
                    i + 1,
                    due.len(),
                    v.id
                );
            } else {
                println!(
                    "\n  ▶ dry-run {}/{}: vault [{}] — would rotate (broadcast refresh)",
                    i + 1,
                    due.len(),
                    v.id
                );
                would_renew = true;
            }
            continue;
        }
        println!("\n  ▶ sweep {}/{}: vault [{}]", i + 1, due.len(), v.id);
        if let Some((tip, txid)) = renewed {
            // The estate coin was already refreshed this sweep (ONE demo
            // address backs every row): record this id under the SAME
            // tip/txid — never re-broadcast the byte-identical refresh.
            save_rotation_state(state_dir, tip, &v.id, txid)?;
            refreshed += 1;
            println!(
                "  ▶ sweep: vault [{}] recorded (heartbeat renewed at {tip} · shared coin, no re-broadcast) ✓",
                v.id
            );
            continue;
        }
        let per_vault = dir.join(format!("vault-rotate-{}", sanitize_id(&v.id)));
        let res = vault_rotate(
            datadir,
            rpc_port,
            network,
            fee_sat,
            &[],
            false,
            &per_vault,
            gate_client.as_ref(),
            cosigner_pin,
            Some(inventory),
            Some(&v.id),
            None,
            state_dir,
        );
        match res {
            Ok(outcome) => {
                refreshed += 1;
                renewed = outcome.map(|o| (o.tip, o.txid));
                println!("  ▶ sweep: vault [{}] refreshed ✓", v.id);
            }
            Err(e) => {
                println!("  ▶ sweep: vault [{}] FAILED: {e}", v.id);
                if failure.is_none() {
                    failure = Some(format!("vault '{}': {e}", v.id));
                }
            }
        }
    }
    if dry_run {
        println!(
            "\nVAULT ROTATE SWEEP (DRY RUN): {} would refresh · {} skipped (healthy) · {} skipped (frozen)",
            due.len() - frozen.len(),
            skipped_healthy,
            frozen.len()
        );
        for id in &frozen {
            println!("  FROZEN[{id}]: co-signer refused — clear the watchtower alarm, then re-run the sweep");
        }
        println!("DRY RUN COMPLETE — no ceremony ran, no state was written. 🛡️");
        return Ok(());
    }
    println!(
        "\nVAULT ROTATE SWEEP: {} refreshed · {} skipped (healthy) · {} skipped (frozen)",
        refreshed,
        skipped_healthy,
        frozen.len()
    );
    for id in &frozen {
        println!(
            "  FROZEN[{id}]: co-signer refused — clear the watchtower alarm, then re-run the sweep"
        );
    }
    match failure {
        Some(e) => Err(format!(
            "sweep failed on: {e} (all due vaults were attempted)"
        )),
        None => {
            println!("VAULT ROTATE SWEEP: COMPLETE — every due vault refreshed. 🛡️");
            Ok(())
        }
    }
}

/// Builds the sweep gate client: PLAIN for a plain `--cosigner`/`--cosigner-all`
/// endpoint, MUTUAL TLS when the sweep gate carries its PEM material (pinned
/// server root + client identity — the production dev-bridge shape).
/// Fail-closed: a half-given mTLS material set is a usage error (exit 2).
type GateMtlsMaterial<'a> = (
    Option<&'a std::path::Path>,
    Option<&'a std::path::Path>,
    Option<&'a std::path::Path>,
);

fn build_gate_client(
    addr: Option<&str>,
    mtls: Option<GateMtlsMaterial<'_>>,
) -> Result<Option<qsv_cosigner::BridgeClient>, String> {
    let Some(addr) = addr else { return Ok(None) };
    let Some((cert, key, ca)) = mtls else {
        return Ok(Some(qsv_cosigner::BridgeClient::plain(addr)));
    };
    // NO material at all → the plain loopback transport (the --cosigner-all
    // drill shape); a PARTIAL set is the operator error.
    if cert.is_none() && key.is_none() && ca.is_none() {
        return Ok(Some(qsv_cosigner::BridgeClient::plain(addr)));
    }
    if cosigner_all_material_is_partial(cert, key, ca) {
        eprintln!(
            "usage error: the sweep-gate mTLS material is incomplete — --cosigner-all-cert, --cosigner-all-key and --cosigner-all-ca must be given together"
        );
        std::process::exit(2);
    }
    let ident = qsv_cosigner::client_identity(
        cert.expect("checked complete above"),
        key.expect("checked complete above"),
    )
    .map_err(|e| format!("sweep-gate client identity: {e}"))?;
    let roots = qsv_cosigner::tls::pinned_root_store_from_pem(ca.expect("checked complete above"))
        .map_err(|e| format!("--cosigner-all-ca: {e}"))?;
    Ok(Some(qsv_cosigner::BridgeClient::mtls(
        addr,
        roots,
        ident,
        "localhost",
    )))
}

fn cosigner_all_material_is_partial(
    cert: Option<&std::path::Path>,
    key: Option<&std::path::Path>,
    ca: Option<&std::path::Path>,
) -> bool {
    cert.is_some() != key.is_some() || cert.is_some() != ca.is_some()
}

/// Parses the `--rate-limit <capacity>:<refill-per-sec>` spec.
fn parse_rate_limit(spec: &str) -> Result<qsv_cosigner::RateLimitPolicy, String> {
    let (cap_s, refill_s) = spec.split_once(':').ok_or_else(|| {
        format!(
            "--rate-limit must be <capacity>:<refill-per-sec> (e.g. 2:0 or 60:0.5), got '{spec}'"
        )
    })?;
    let capacity: f64 = cap_s
        .trim()
        .parse()
        .map_err(|_| format!("--rate-limit capacity must be a number, got '{cap_s}'"))?;
    let refill_per_sec: f64 = refill_s
        .trim()
        .parse()
        .map_err(|_| format!("--rate-limit refill must be a number, got '{refill_s}'"))?;
    let policy = qsv_cosigner::RateLimitPolicy {
        capacity,
        refill_per_sec,
    };
    policy
        .validate()
        .map_err(|e| format!("--rate-limit: {e}"))?;
    Ok(policy)
}

/// ONE pre-ceremony gate probe for the sweep (`--cosigner-all`): asks the
/// bridge whether `vault_id` may sign RIGHT NOW. Returns Ok(true) ONLY for
/// the watchtower FROZEN verdict (skip this vault); Ok(false) = the gate
/// releases (proceed); Err = the gate could not answer (unprovisioned
/// allowlist, transport trouble, malformed frame) — the caller fails the
/// sweep closed.
fn sweep_vault_gate(client: &qsv_cosigner::BridgeClient, vault_id: &str) -> Result<bool, String> {
    match client
        .ask(vault_id)
        .map_err(|e| format!("gate probe failed: {e}"))?
    {
        qsv_cosigner::GateVerdict::Release => Ok(false),
        qsv_cosigner::GateVerdict::Frozen => Ok(true),
        qsv_cosigner::GateVerdict::Refused(reason) => Err(format!("gate refused: {reason}")),
    }
}

/// Filesystem-safe short form of a vault id for per-vault artifact dirs
/// (`vault-rotate-<sanitized>`): hex-encode any byte that is not a plainly
/// safe ASCII character, so ids stay recognizable but cannot traverse
/// paths or collide through `..`/separators.
fn sanitize_id(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for b in id.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The persisted rotation state (`<state-dir>/rotation-state.json`), v2:
/// id-based per-vault records (the SAME id space as the watchtower
/// inventory). v1 single-vault documents (`last_refresh_block` at top level)
/// still load, but a mixed/v1 record used in multi-vault mode fails closed.
fn load_rotation_state(state_dir: &std::path::Path) -> Result<serde_json::Value, String> {
    let path = state_dir.join("rotation-state.json");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("malformed rotation state: {e}"))
}

/// Resolves the persisted baseline for ONE vault id out of the v2 state
/// document. A record claiming a refresh ABOVE the current tip is corrupt
/// (the future cannot be the past) — fail-closed.
fn rotation_baseline_for(state: &serde_json::Value, vault_id: &str, tip: u32) -> Option<u32> {
    state
        .as_object()?
        .get("vaults")?
        .get(vault_id)?
        .get("last_refresh_block")?
        .as_u64()
        .map(|v| v as u32)
        .filter(|&lrb| lrb <= tip)
}

fn save_rotation_state(
    state_dir: &std::path::Path,
    tip: u32,
    vault_id: &str,
    txid: bitcoin::Txid,
) -> Result<(), String> {
    std::fs::create_dir_all(state_dir)
        .map_err(|e| format!("cannot create {}: {e}", state_dir.display()))?;
    let path = state_dir.join("rotation-state.json");
    // v2 schema: per-vault records under "vaults" keyed by id (merge into
    // an existing document so multi-vault state is preserved).
    let mut doc: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({"version": 2, "vaults": {}}));
    if doc.get("version").and_then(serde_json::Value::as_u64) != Some(2) {
        // v1 state cannot be merged safely (no id on the old record).
        return Err(format!(
            "{} is v1 (single-vault) rotation state — it has no vault id; delete it or migrate manually before multi-vault use",
            path.display()
        ));
    }
    doc["vaults"][vault_id] = serde_json::json!({
        "last_refresh_block": tip,
        "refresh_txid": txid.to_string(),
        "policy_interval_blocks": qsv_core::heartbeat::HeartbeatPolicy::default().interval_blocks,
    });
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&doc).map_err(|e| format!("serialize: {e}"))?,
    )
    .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

/// The operator's attestation pin set for the live co-signer gate.
///
/// Defaults reproduce the DEMO enclave identity (the bridge provisions
/// `DEMO_ENCLAVE_SEED`), so existing deployments keep working — and the
/// default is still a REAL pin: the document's PCR0, nonce and
/// user_data are all verified against it. Every component is
/// overridable per deployment: `--cosigner-pcr0/1/2` pin measurements,
/// `--cosigner-key` pins the x-only key (clap requires PCR0 with it).
struct CosignerPin {
    pcr0_hex: String,
    pcr1_hex: String,
    pcr2_hex: String,
    xonly: secp256k1::XOnlyPublicKey,
    xonly_hex: String,
}

impl CosignerPin {
    /// Resolves flags into a validated pin set (fail-closed at STARTUP:
    /// a malformed pin aborts before any ceremony, never mid-spend).
    fn resolve(
        endpoint_configured: bool,
        pcr0: Option<&str>,
        pcr1: Option<&str>,
        pcr2: Option<&str>,
        key: Option<&str>,
    ) -> Result<Self, String> {
        let pins_given = pcr0.is_some() || pcr1.is_some() || pcr2.is_some() || key.is_some();
        if pins_given && !endpoint_configured {
            return Err(
                "attestation pins (--cosigner-pcr0/1/2, --cosigner-key) require a co-signer endpoint (--cosigner / --cosigner-all)"
                    .into(),
            );
        }
        let pcr = |label: &str, v: Option<&str>, default: &str| -> Result<String, String> {
            match v {
                None => Ok(default.to_string()),
                Some(h) => {
                    let b =
                        hex::decode(h).map_err(|_| format!("--cosigner-{label} must be hex"))?;
                    if !matches!(b.len(), 32 | 48 | 64) {
                        return Err(format!(
                            "--cosigner-{label} must be 32, 48 or 64 bytes (got {})",
                            b.len()
                        ));
                    }
                    Ok(hex::encode(b))
                }
            }
        };
        let demo_pcr0 = hex::encode(qsv_cosigner::nsm::dev_measurement(&DEMO_ENCLAVE_SEED));
        let pcr0_hex = pcr("pcr0", pcr0, &demo_pcr0)?;
        let pcr1_hex = pcr("pcr1", pcr1, "")?;
        let pcr2_hex = pcr("pcr2", pcr2, "")?;
        let (xonly, xonly_hex) = match key {
            None => {
                let kp = qsv_pqc::enclave_keypair_from_seed(&DEMO_ENCLAVE_SEED)
                    .map_err(|e| e.to_string())?;
                let x = qsv_pqc::enclave_xonly_public_key(&kp);
                (x, hex::encode(x.serialize()))
            }
            Some(h) => {
                let b = hex::decode(h).map_err(|_| "--cosigner-key must be hex".to_string())?;
                let arr: [u8; 32] = b
                    .as_slice()
                    .try_into()
                    .map_err(|_| format!("--cosigner-key must be 32 bytes, got {}", b.len()))?;
                let x = secp256k1::XOnlyPublicKey::from_slice(&arr)
                    .map_err(|_| "--cosigner-key is not a valid x-only public key".to_string())?;
                (x, hex::encode(arr))
            }
        };
        Ok(Self {
            pcr0_hex,
            pcr1_hex,
            pcr2_hex,
            xonly,
            xonly_hex,
        })
    }
}

/// Requests the SECOND signature from a LIVE co-signer over the PQC gate,
/// verifies the v2 COSE_Sign1 ATTESTATION DOCUMENT end-to-end (chain →
/// PCR pin → nonce → user_data key binding, docs/10 §4.52) and verifies
/// the signature under the pinned enclave key before returning it.
fn live_enclave_signature(
    client: &qsv_cosigner::BridgeClient,
    vault_id: &str,
    sighash: &bitcoin::sighash::TapSighash,
    pin: &CosignerPin,
) -> Result<[u8; 64], String> {
    use qsv_cosigner::SignRequest;

    let digest: [u8; 32] = *sighash.as_byte_array();
    // The client-side ML-DSA-65 proof over THIS sighash (demo identity —
    // the production client signs with its hardware-sealed PQC key).
    // `SignRequest::new` also generates the v2 attestation challenge.
    let pqc = qsv_pqc::PqcIdentity::from_seed(&[21u8; 32]);
    let req = SignRequest::new(
        vault_id,
        &digest,
        pqc.verifying_key_bytes(),
        &pqc.sign(&digest),
    );
    let resp = client
        .send(&req)
        .map_err(|e| format!("co-signer {}: {e}", client.addr()))?;
    if !resp.accepted {
        return Err(format!(
            "co-signer {} REFUSED: {} (is the vault watchtower-frozen?)",
            client.addr(),
            resp.reason.as_deref().unwrap_or("no reason given")
        ));
    }
    // ATTESTATION IS MANDATORY (Round 27): an accepted response without a
    // document is a v1/broken bridge — an unattested signature is never
    // trusted, fail closed.
    let doc_hex = resp.attestation_doc_hex.as_deref().ok_or_else(|| {
        format!(
            "co-signer {} accepted WITHOUT an attestation document (protocol v2 requires one) — refusing the unattested signature",
            client.addr()
        )
    })?;
    let pinned = qsv_cosigner::nsm::PinnedMeasurements {
        pcr0_hex: pin.pcr0_hex.clone(),
        pcr1_hex: pin.pcr1_hex.clone(),
        pcr2_hex: pin.pcr2_hex.clone(),
        vault_id: vault_id.to_string(),
        enclave_xonly_hex: pin.xonly_hex.clone(),
    };
    let doc = qsv_cosigner::nsm::verify_attestation_doc(doc_hex, &pinned, &req.nonce_hex)
        .map_err(|e| format!("co-signer {} ATTESTATION REFUSED: {e}", client.addr()))?;
    println!(
        "  co-signer:    attestation verified ({} · {} certs to pinned root · PCR0 + nonce + key bound) ✓",
        doc.module_id,
        doc.cabundle_der.len() + 1
    );
    let sig_hex = resp
        .schnorr_sig_hex
        .ok_or("co-signer accepted but returned no signature")?;
    let sig: [u8; 64] = hex::decode(&sig_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("co-signer returned a malformed signature")?;
    // Verify under the PINNED enclave key (demo identity by default; the
    // operator's --cosigner-key pin for real deployments).
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(
        &secp256k1::schnorr::Signature::from_slice(&sig)
            .map_err(|_| "co-signer signature is not valid BIP-340".to_string())?,
        &secp256k1::Message::from_digest(digest),
        &pin.xonly,
    )
    .map_err(|_| {
        "co-signer signature FAILED verification under the pinned enclave key".to_string()
    })?;
    println!("  co-signer:    signature verified under the pinned enclave key ✓");
    Ok(sig)
}

/// Loads EVERY watchtower mirror's state file (`<dir>/watchtower-state.json`).
/// Fail-closed, same rule the single mirror always had: one unreadable or
/// unparseable mirror aborts — an operator must decide what a silent host
/// means, the bridge never guesses (docs/10 §4.60).
fn load_watchtower_mirrors(
    dirs: &[std::path::PathBuf],
) -> Result<Vec<qsv_cosigner::WatchtowerVerdicts>, String> {
    dirs.iter().map(|d| qsv_cosigner::load_state(d)).collect()
}

/// The cosigner-bridge command: serve the enclave on TCP with the watchtower
/// alarm mirror applied from the persisted state file (re-read per request,
/// so daemon refreshes take effect without a restart).
#[allow(clippy::too_many_arguments)] // Round 18: frame-timeout + scrape-token args (project convention)
fn cosigner_bridge(
    listen: &str,
    state_dir: &std::path::Path,
    watchtower: &[std::path::PathBuf],
    watchtower_quorum: Option<usize>,
    vault_ids: &[String],
    tls_cert: Option<&std::path::Path>,
    tls_key: Option<&std::path::Path>,
    tls_client_ca: Option<&std::path::Path>,
    rate_limit: Option<&str>,
    frame_timeout_ms: u64,
    drain_timeout_ms: u64,
    metrics_token: Option<String>,
    metrics_token_file: Option<&std::path::Path>,
    max_inflight: usize,
    dry_run: bool,
) -> Result<(), String> {
    use std::sync::{Arc, Mutex};

    // KOF-N MIRROR QUORUM (docs/10 §3.3/§4.60): n = the default mirror
    // (state_dir) + every repeatable `--watchtower` mirror; k =
    // `--watchtower-quorum` or the majority default ⌊n/2⌋+1. A quorum that
    // could NEVER fire (k=0, k>n) would unlock every vault and one a
    // single host alone controls defeats the whole point — both refused
    // as USAGE errors BEFORE the socket binds (fail fast beats a bridge
    // that accepts frames and then rejects every one of them).
    let mirrors: Vec<std::path::PathBuf> = std::iter::once(state_dir.to_path_buf())
        .chain(watchtower.iter().cloned())
        .collect();
    let n_mirrors = mirrors.len();
    let quorum = match watchtower_quorum {
        Some(k) if k >= 1 && k <= n_mirrors => k,
        Some(k) => {
            eprintln!("usage error: --watchtower-quorum must be in 1..={n_mirrors} (got {k})");
            std::process::exit(2);
        }
        // Majority default (n=1 → 1: today's single-mirror behaviour is
        // byte-identical; n=3 → 2; n=4 → 3).
        None if n_mirrors != 2 => n_mirrors / 2 + 1,
        // Exactly TWO mirrors have no compromise-resistant default: k=2
        // is silenced by ONE dead host, k=1 is forged by ONE — so the
        // explicit value becomes REQUIRED rather than guessed.
        None => {
            eprintln!(
                "usage error: --watchtower-quorum is required with exactly two mirrors (no compromise-resistant default; give 1 or 2)"
            );
            std::process::exit(2);
        }
    };

    // TOKEN SOURCE (docs/10 §4.27, Round 21): resolve the file form
    // FIRST so every gate below (scrape policy, health record,
    // ServePolicy) sees the real token. Both sources at once = usage
    // confusion (exit 2): which one the operator believes would be a
    // guess, and a guess about a gate is how gates get bypassed.
    if metrics_token.is_some() && metrics_token_file.is_some() {
        eprintln!("usage error: --metrics-token and --metrics-token-file are mutually exclusive");
        std::process::exit(2);
    }
    let metrics_token = match metrics_token_file {
        Some(path) => Some(read_metrics_token_file(path)?),
        None => metrics_token,
    };
    // TRANSPORT POLICY (docs/10 §3.5): loopback may serve plaintext; any
    // other bind MUST arrive with TLS material — fail closed at boot.
    let tls_enabled = tls_cert.is_some();
    qsv_cosigner::tls::require_tls_or_loopback(listen, tls_enabled).map_err(|e| e.to_string())?;
    // SCRAPE POLICY (docs/10 §4.20): an open `/metrics` is a loopback
    // convenience only. Off loopback the counters name every vault and
    // expose which one the watchtower froze — an estate map for free — so
    // the scrape token becomes MANDATORY, same fail-closed shape. Checked
    // here, BEFORE the bind: a refused bridge must never open a socket.
    qsv_cosigner::tls::require_metrics_token_off_loopback(listen, metrics_token.as_deref())
        .map_err(|e| e.to_string())?;

    println!("\n───── [16] CO-SIGNER BRIDGE · TCP SERVE + WATCHTOWER ALARM MIRROR ──");
    let mut allowed = vault_ids.to_vec();
    if allowed.is_empty() {
        // Default: the ONE demo vault address the whole operator surface uses.
        allowed.push(demo_vault()?.address(bitcoin::Network::Regtest).to_string());
    }
    let seed_hex = hex::encode(DEMO_ENCLAVE_SEED);
    let mut cosigner = qsv_cosigner::Cosigner::provision(DEMO_ENCLAVE_SEED, allowed.clone());
    // ROTATION COUNTERS (Round 23/24, docs/10 §4.36): the scrape gate
    // counts the reloads it refuses AND the ones that landed; adopt its
    // Arcs into the metrics exposition BEFORE the cosigner moves behind
    // `shared`, so `qsv_cosigner_rotate_denied_total` /
    // `qsv_cosigner_rotate_total` render exactly what the gate recorded —
    // one number, one source of truth, the alert and the scrape can
    // never disagree.
    let scrape_gate = qsv_cosigner::ScrapeToken::from_option(metrics_token.clone());
    cosigner.metrics.adopt_rotation_counters(&scrape_gate);
    // PER-VAULT RATE LIMIT (`<capacity>:<refill-per-sec>`): a flood from
    // one vault may not consume another vault's budget. Parse errors are
    // usage errors (exit 2); the limiter's own validation re-checks the
    // policy inside the cosigner (fail-closed, the default stays armed).
    if let Some(spec) = rate_limit {
        let policy = parse_rate_limit(spec).map_err(|e| {
            eprintln!("usage error: {e}");
            std::process::exit(2);
            #[allow(unreachable_code)]
            String::new()
        })?;
        cosigner
            .set_rate_limit(Some(policy))
            .map_err(|e| format!("rate limit: {e}"))?;
        println!("  rate limit:   {spec} (per-vault token bucket; refusals counted in /metrics)");
    }
    // Initial mirror from EVERY persisted watchtower state (fail-closed:
    // an unreadable mirror aborts the boot — the operator must decide).
    let states = load_watchtower_mirrors(&mirrors)?;
    let verdicts = qsv_cosigner::quorum_verdicts(&states, quorum)?;
    let outcomes = qsv_cosigner::apply_verdicts(&mut cosigner, &verdicts);
    println!(
        "  watchtower:   {n_mirrors} mirror(s) · quorum {quorum} · state at tip {} · mirror applied",
        verdicts.tip
    );
    for o in &outcomes {
        println!("    [{:>16}] {:?}", o.vault_id, o.action);
    }
    println!(
        "  serving:      {listen} · {} vault(s) · transport {}",
        allowed.len(),
        match (tls_enabled, tls_client_ca.is_some()) {
            (true, true) => "mTLS (client certs required)",
            (true, false) => "TLS",
            _ => "plain (loopback)",
        }
    );
    println!(
        "  enclave:      demo seed {}… (prod: NSM-sealed key)",
        &seed_hex[..8]
    );
    let shared = Arc::new(Mutex::new(cosigner));
    // PER-REQUEST mirror: the state file is re-read before every request so
    // a watchtower daemon refresh takes effect WITHOUT a restart. Read or
    // parse failure keeps the LAST mirror (fail-closed: alarms never
    // silently clear because a state file went missing mid-run).
    let mirror_dirs = mirrors.clone();
    let shared_for_mirror = Arc::clone(&shared);
    let mirror = move || {
        // ALL mirrors must load and merge, or the LAST applied verdict
        // stays (fail-closed: alarms never silently clear because a state
        // file went missing mid-run — the Round-23 rule, now all-or-nothing
        // across the mirror set, so a deleted mirror cannot unlock).
        if let Ok(states) = load_watchtower_mirrors(&mirror_dirs) {
            if let Ok(v) = qsv_cosigner::quorum_verdicts(&states, quorum) {
                if let Ok(mut c) = shared_for_mirror.lock() {
                    let _ = qsv_cosigner::apply_verdicts(&mut c, &v);
                }
            }
        }
    };
    let listener =
        std::net::TcpListener::bind(listen).map_err(|e| format!("cannot bind {listen}: {e}"))?;
    // GRACEFUL SHUTDOWN (docs/10 §3.7): SIGTERM/SIGINT flip a std-only
    // async-signal-safe flag; the accept loops stop, TLS workers drain,
    // the bind releases and the process exits 0 — systemd's
    // `Restart=on-failure` has nothing to restart on a stop.
    let shutdown = qsv_cosigner::Shutdown::disabled()
        .install_signal_handlers()
        .map_err(|e| format!("signal handler: {e}"))?;
    println!("  shutdown:     SIGTERM/SIGINT → stop accepting, drain, exit 0");
    // SERVE POLICY (docs/10 §4.19→§4.20): bounded streams + optional
    // scrape gate — a silent peer can pin a worker for at most ONE
    // timeout, and the graceful drain waiting on that worker runs on the
    // same clock (finite by construction).
    let policy = qsv_cosigner::ServePolicy {
        frame_timeout: match frame_timeout_ms {
            0 => None,
            ms => Some(std::time::Duration::from_millis(ms)),
        },
        metrics_token: scrape_gate,
        max_inflight,
    };
    println!(
        "  frame-timeout:{}",
        match policy.frame_timeout {
            Some(t) => format!(" {} ms (read/write deadline, every socket)", t.as_millis()),
            None => " disabled".to_string(),
        }
    );
    println!(
        "  metrics:      {}",
        match (&metrics_token, metrics_token_file) {
            (Some(_), Some(_)) => {
                "token armed FROM FILE (X-QSV-Metrics-Token required; the VALUE never touched argv)"
            }
            (Some(_), None) => "token armed (X-QSV-Metrics-Token required; denials counted)",
            (None, _) => "open scrape (loopback dev default)",
        }
    );
    println!(
        "  capacity:     {} in-flight worker(s){}",
        policy.max_inflight,
        if policy.max_inflight == 0 {
            " (unlimited)"
        } else {
            ""
        }
    );
    // LIVE TOKEN ROTATION (docs/10 §4.30, Round 22): SIGHUP re-reads
    // `--metrics-token-file` and swaps the gate IN PLACE — no restart,
    // no signing gap, no millisecond where the scrape is open. The
    // handler is installed on EVERY boot (the default SIGHUP disposition
    // KILLS the process; a stray HUP must never be able to do that), but
    // the file read + swap run on this polling thread: one atomic edge
    // per signal, never I/O inside the handler. A refused rotation keeps
    // the previous token — failing to rotate must not fail OPEN.
    #[cfg(unix)]
    if !dry_run {
        qsv_cosigner::install_reload_handler().map_err(|e| format!("signal handler: {e}"))?;
        let gate = policy.metrics_token.clone();
        let path = metrics_token_file.map(std::path::Path::to_path_buf);
        match &path {
            Some(p) => println!(
                "  token:        SIGHUP → re-read {} (systemctl reload); the value never re-enters argv",
                p.display()
            ),
            None if metrics_token.is_some() => {
                println!("  token:        SIGHUP idle (armed via --metrics-token; no file to re-read)")
            }
            None => {}
        }
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
            if !qsv_cosigner::reload_requested() {
                continue;
            }
            let Some(path) = &path else {
                eprintln!("token rotation ignored: armed via --metrics-token, no file to re-read");
                // The operator's `systemctl reload` did NOTHING (the
                // gate is armed but has no file to re-read) — counted so
                // `QsvCosignerTokenRotationStalled` says it out loud;
                // a disarmed dev bridge ignores the count by design.
                gate.record_denial();
                continue;
            };
            match read_metrics_token_file(path).and_then(|next| gate.rotate(next)) {
                Ok(_) => println!(
                    "  token:        rotated from {} (SIGHUP) — gate never opened, signing untouched",
                    path.display()
                ),
                // Read failure OR gate refusal: the old token stays
                // active and the reload is COUNTED — failing to rotate
                // must never fail open. (`rotate` counts its own
                // refusals too; a double count only ever happens on a
                // path the boot gates make unreachable.)
                Err(e) => {
                    // The file exists but cannot supply a token (unreadable
                    // or empty): the reload failed, the OLD token stays
                    // active — the alert's exact scenario.
                    gate.record_denial();
                    eprintln!("token rotation failed, previous token still active: {e}");
                }
            }
        });
    }
    // TLS MATERIAL IS LOADED BEFORE the health record is published: a bad
    // PEM must fail the boot without ever having claimed "co-signer up"
    // on disk. Same for the bind itself, which already happened above.
    let tls_config = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            let config = match tls_client_ca {
                Some(ca) => {
                    // MUTUAL TLS: the handshake itself demands a client
                    // certificate chaining to the operator's CA — an
                    // anonymous client never completes a session.
                    let cfg =
                        qsv_cosigner::tls::tls_listener_config_with_client_auth(cert, key, ca)
                            .map_err(|e| format!("TLS material: {e}"))?;
                    println!("  mtls:         client CA {ca:?} (anonymous clients refused)");
                    cfg
                }
                None => qsv_cosigner::tls::tls_listener_config(cert, key)
                    .map_err(|e| format!("TLS material: {e}"))?,
            };
            println!("  tls:          cert {cert:?} · key {key:?}");
            Some(config.into_server_config())
        }
        _ => None,
    };
    // BOOT REHEARSAL (docs/10 §4.41, Round 24): every gate ABOVE has passed
    // — token file contract, watchtower state, transport policy, TLS
    // material, and the bind itself (a port already in use is exactly
    // what an operator needs to learn BEFORE systemd tries). Nothing
    // below this line has a side effect worth rehearsing: a health
    // record would LIE ("up" with nothing serving), sd_notify would
    // announce a readiness that does not exist, and the accept loop
    // would answer requests nobody asked for.
    if dry_run {
        println!("\n───── [16b] CO-SIGNER BRIDGE · BOOT REHEARSAL ─────────────────");
        println!("  verdict:      BOOT WOULD SUCCEED — nothing served, nothing published");
        println!("  listen:       {listen} (bound for the rehearsal, then released)");
        println!(
            "  transport:    {}",
            match &tls_config {
                Some(_) => match tls_client_ca.is_some() {
                    true => "mTLS (client certs required)",
                    false => "TLS",
                },
                None => "plain (loopback)",
            }
        );
        println!("  vaults:       {} provisioned", allowed.len());
        println!(
            "  scrape gate:  {}{}",
            if policy.metrics_token.is_armed() {
                "armed"
            } else {
                "open (loopback dev default)"
            },
            match metrics_token_file {
                Some(p) => format!(" · reload source {} (rotation-ready)", p.display()),
                None => String::new(),
            }
        );
        println!(
            "  capacity:     {} in-flight worker(s) · frame timeout {} · drain deadline {}",
            policy.max_inflight,
            match policy.frame_timeout {
                Some(t) => format!("{} ms", t.as_millis()),
                None => "unbounded".to_string(),
            },
            if drain_timeout_ms == 0 {
                "classic".to_string()
            } else {
                format!("{drain_timeout_ms} ms")
            },
        );
        println!("  watchtower:   state at tip {}", verdicts.tip);
        return Ok(());
    }

    // HEALTH RECORD (docs/10 §4.23): publish WHO/WHERE/WHICH-POLICY before
    // the accept loop starts, atomically, so `qsv-cli doctor` and any
    // supervisor scraping the state dir never read a half-written file.
    // The token VALUE is never written — only the armed bit.
    let health = qsv_cosigner::health::current(
        listen,
        match &tls_config {
            Some(_) => match tls_client_ca.is_some() {
                true => "mtls",
                false => "tls",
            },
            None => "plain",
        },
        allowed.clone(),
        verdicts.tip,
        qsv_cosigner::health::ServePolicyRecord {
            metrics_token_armed: policy.metrics_token.is_armed(),
            // The reload SOURCE (the PATH only — the secret never leaves
            // its 0600 file), so `doctor` can prove a `systemctl reload`
            // would rotate before anyone runs it.
            metrics_token_file: metrics_token_file.map(|p| p.display().to_string()),
            max_inflight: policy.max_inflight,
            frame_timeout_ms: policy.frame_timeout.map(|t| t.as_millis() as u64),
        },
    );
    qsv_cosigner::health::write(state_dir, &health)
        .map_err(|e| format!("cannot publish bridge health: {e}"))?;
    println!(
        "  health:       {} (pid {}; removed on graceful stop)",
        qsv_cosigner::health_path(state_dir).display(),
        health.pid
    );
    // SYSTEMD TYPE=NOTIFY (docs/10 §4.26, Round 21): every sd_notify call
    // below is a SILENT NO-OP unless systemd handed us NOTIFY_SOCKET (dev
    // runs, tests and bare metal never see the variable — same behavior
    // as before, byte for byte).
    //
    // READY=1    — sent ONLY now: the bind succeeded, the TLS material is
    //              loaded and the health record is real on disk. The
    //              supervisor's start clock runs on PROOF, not on fork.
    // WATCHDOG=1 — pinged at half of systemd's own WATCHDOG_USEC, and only
    //              while the accept loop's progress stamp still moves
    //              (spawn_watchdog): a wedged loop goes SILENT on purpose
    //              — silence is the restart signal, liveness-blind pings
    //              would be theater that hides the wedge.
    // STOPPING=1 — the drain edge fired; from that message on, systemd's
    //              TimeoutStopSec owns the stop bound.
    let notify = qsv_cosigner::notify_from_env();
    if let Some(sock) = &notify {
        sock.send("READY=1").map_err(|e| {
            format!("sd_notify READY=1 failed (the supervisor would never see this boot): {e}")
        })?;
        println!("  notify:       READY=1 sent (bind + TLS material + health record are real)");
    } else {
        println!("  notify:       inactive (no NOTIFY_SOCKET — dev/bare-metal run)");
    }
    // WATCHDOG THREAD: the ping cadence comes from WATCHDOG_USEC, so the
    // bridge can never ping on a rhythm the unit did not ask for. The
    // stall limit is ONE legitimate quiet window (a slow stream inside
    // the serial loop) plus one ping period; past it the pings stop —
    // with --frame-timeout-ms 0 a hung peer then makes the watchdog the
    // ONLY bound on a wedged bridge (fail closed, by restart).
    let watchdog_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let (Some(sock), Some(interval)) = (notify.clone(), qsv_cosigner::watchdog_interval()) {
        let stall = std::time::Duration::from_millis(
            frame_timeout_ms.saturating_add(interval.as_millis() as u64),
        );
        qsv_cosigner::spawn_watchdog(
            sock,
            interval,
            shutdown.progress_stamp(),
            stall,
            std::sync::Arc::clone(&watchdog_done),
            // Round 22 (docs/10 §4.34): the reason we go silent is said
            // ONCE per episode, on stderr → journald: a watchdog restart
            // with no witness is a post-mortem nobody can write.
            |m| eprintln!("{m}"),
        );
        println!(
            "  watchdog:     ping every {interval:?} · silent once the accept loop stops ticking for {stall:?}"
        );
    }
    // STOPPING=1 belongs to the DRAIN EDGE, not to the print after serve:
    // the drain may take seconds and the supervisor must learn that the
    // stop BEGAN. The watcher polls `requested()` — a read that never
    // advances the progress stamp, so it cannot fake loop liveness.
    let stopping_sent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Some(sock) = notify.clone() {
        let edge = shutdown.clone();
        let sent = std::sync::Arc::clone(&stopping_sent);
        std::thread::spawn(move || loop {
            if edge.requested() {
                // Best-effort: a vanished supervisor is not OUR error —
                // the missing state is what makes systemd act.
                if sock.send("STOPPING=1").is_ok() {
                    sent.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        });
    }
    // A second edge handle for the post-serve report: did a stop edge
    // actually fire? (The watcher alone cannot answer — it is gone once
    // it has sent, and its `sent` bit says "delivered", not "owed".)
    let shutdown_probe = shutdown.clone();
    // DRAIN DEADLINE (docs/10 §4.28, Round 21): `--frame-timeout-ms 0`
    // disables the ONLY per-connection clock — a peer that goes quiet
    // mid-frame parks the serial loop (or a TLS worker) FOREVER, and the
    // graceful drain waiting on it would never come back. This thread is
    // the bound: it starts counting at the stop edge, and if the drain
    // has not finished by the deadline it reports, clears the health
    // record (a cut stop must not leave a stale "serving" claim) and
    // exits 0 — an operator-initiated stop stays a stop, so systemd's
    // Restart=on-failure still has nothing to restart on. 0 = the
    // unbounded drain (classic behavior, frame-timeout bounds it).
    let drain_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    if drain_timeout_ms > 0 {
        let edge = shutdown.clone();
        let finished = std::sync::Arc::clone(&drain_done);
        let state_path = state_dir.to_path_buf();
        let drain = std::time::Duration::from_millis(drain_timeout_ms);
        std::thread::spawn(move || {
            // 1. No countdown before the stop edge — the deadline is the
            //    DRAIN's bound, not the service lifetime's.
            while !edge.requested() {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            // 2. Count down, letting the normal graceful path win every
            //    race (it sets `finished` the moment serve returns).
            let deadline = std::time::Instant::now() + drain;
            while std::time::Instant::now() < deadline {
                if finished.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if finished.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            // 3. CUT: report FIRST (the operator must see WHY this stop
            //    was not the usual graceful one), clear the record, go.
            eprintln!(
                "drain deadline of {drain_timeout_ms} ms exceeded — abandoning in-flight work, clearing the health record, exit 0"
            );
            qsv_cosigner::health::remove(&state_path);
            std::process::exit(0);
        });
        println!(
            "  drain:        {drain_timeout_ms} ms after SIGTERM → report + clear health + exit 0 (0 = unbounded)"
        );
    }
    let serve_result = match tls_config {
        Some(config) => qsv_cosigner::serve_with_tls_mirror_and_shutdown(
            listener, shared, mirror, config, shutdown, policy,
        )
        .map_err(|e| e.to_string()),
        None => {
            qsv_cosigner::serve_with_mirror_and_shutdown(listener, shared, mirror, shutdown, policy)
                .map_err(|e| e.to_string())
        }
    };
    // The health record is torn down on EVERY exit path from here on —
    // graceful stop, serve error, or the `?` below. Its presence is the
    // operator's "this process is serving" proof; leaving it behind would
    // claim a live co-signer that is gone (the stale-record trap).
    let outcome = serve_result;
    // The drain finished IN TIME — the deadline thread (if armed) bows
    // out on its next tick. Set FIRST: everything below (STOPPING wait,
    // health removal, prints) is post-drain and must not be cut.
    drain_done.store(true, std::sync::atomic::Ordering::Relaxed);
    // Watchdog pings stop with the loop that justified them (the thread
    // exits on its next tick — never joined: a watchdog must not delay exit).
    watchdog_done.store(true, std::sync::atomic::Ordering::Relaxed);
    // The STOPPING report RACES process exit: the watcher polls the edge
    // every 10ms, so give it a bounded window to land before this process
    // disappears (250ms ceiling; in practice one 5ms nap — the watcher
    // sees the edge on the same tick the serve loop did). Omitted when no
    // stop edge fired (serve error path): nothing is owed, nothing is
    // invented.
    if notify.is_some() && shutdown_probe.requested() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(250);
        while !stopping_sent.load(std::sync::atomic::Ordering::Relaxed)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    qsv_cosigner::health::remove(state_dir);
    // Claim STOPPING=1 only if it was really delivered — the same
    // never-invent-a-healthy-answer rule the health record follows.
    if stopping_sent.load(std::sync::atomic::Ordering::Relaxed) {
        println!("  notify:       STOPPING=1 delivered (drain reported to the supervisor)");
    }
    outcome?;
    println!("  bridge:       graceful stop complete (all in-flight requests served)");
    println!("  health:       record removed (no stale co-signer claim)");
    Ok(())
}

/// The cosigner-bridge-install command: generate a hardened systemd unit +
/// timer pair for the bridge (docs/10 §3.4). The unit bakes ExecStart to the
/// real `cosigner-bridge` invocation, sandboxes it (ProtectSystem=strict,
/// ReadWritePaths=state-dir only, PrivateTmp, no new privileges), and the
/// timer drives the cadence the daemon needs to keep the alarm mirror
/// fresh. Files are written AND re-read for verification: every required
/// directive is asserted present — install-what-you-print, exit 1 on any
/// gap.
#[allow(clippy::too_many_arguments)] // Round 17: TLS bake + rate-limit args (project convention)
fn cosigner_bridge_install(
    listen: &str,
    state_dir: &std::path::Path,
    watchtower: &[std::path::PathBuf],
    watchtower_quorum: Option<usize>,
    vault_ids: &[String],
    unit_dir: Option<&std::path::Path>,
    timer_calendar: &str,
    unit_name: &str,
    tls_cert: Option<&std::path::Path>,
    tls_key: Option<&std::path::Path>,
    tls_client_ca: Option<&std::path::Path>,
    rate_limit: Option<&str>,
    metrics_token: Option<&str>,
    metrics_token_file: Option<&std::path::Path>,
    frame_timeout_ms: u64,
    drain_timeout_ms: u64,
    max_inflight: usize,
) -> Result<(), String> {
    println!("\n───── [16b] CO-SIGNER BRIDGE · SYSTEMD UNIT + TIMER GENERATOR ──");
    // TOKEN SOURCE (docs/10 §4.27, Round 21): both flags at once = exit 2
    // (same contract the bridge boot enforces — install-what-you-print
    // starts with one-unambiguous-source). The FILE is read HERE to run
    // the boot gates against the REAL token — but only its PATH travels
    // into ExecStart (the VALUE never touches the unit file).
    if metrics_token.is_some() && metrics_token_file.is_some() {
        eprintln!("usage error: --metrics-token and --metrics-token-file are mutually exclusive");
        std::process::exit(2);
    }
    let file_token = match metrics_token_file {
        Some(path) => Some(read_metrics_token_file(path)?),
        None => None,
    };
    let resolved_token: Option<String> = match metrics_token {
        Some(t) => Some(t.to_string()),
        None => file_token.clone(),
    };
    let state_abs = std::fs::canonicalize(state_dir)
        .map_err(|e| format!("cannot resolve --state-dir {}: {e}", state_dir.display()))?;
    println!("  state-dir:    {}", state_abs.display());
    // KOF-N MIRROR QUORUM (docs/10 §4.60): the SAME walls the bridge boot
    // enforces run BEFORE any file is written (install-what-you-print) —
    // a unit whose bridge would exit 2 at boot is a unit systemd restart-
    // fails forever with a config the operator never sees.
    let n_mirrors = 1 + watchtower.len();
    let quorum = match watchtower_quorum {
        Some(k) if k >= 1 && k <= n_mirrors => k,
        Some(k) => {
            eprintln!("usage error: --watchtower-quorum must be in 1..={n_mirrors} (got {k})");
            std::process::exit(2);
        }
        None if n_mirrors != 2 => n_mirrors / 2 + 1,
        None => {
            eprintln!(
                "usage error: --watchtower-quorum is required with exactly two mirrors (no compromise-resistant default; give 1 or 2)"
            );
            std::process::exit(2);
        }
    };
    if !watchtower.is_empty() {
        println!("  watchtower:   {n_mirrors} mirror(s) · quorum {quorum} (k-of-n, docs/10 §4.60)");
    }
    // Round 20: a unit that CANNOT boot is worse than no unit — systemd
    // would restart-fail forever with a config the operator never sees.
    // The SAME gates the bridge boot performs run here, BEFORE any file
    // is written: an off-loopback bind needs TLS material AND a scrape
    // token (install-what-you-print starts with print-what-can-run).
    qsv_cosigner::tls::require_tls_or_loopback(listen, tls_cert.is_some())
        .map_err(|e| format!("transport policy: {e}"))?;
    qsv_cosigner::tls::require_metrics_token_off_loopback(listen, resolved_token.as_deref())
        .map_err(|e| format!("scrape policy: {e}"))?;
    // ExecStart mirrors the dev-mode default: no --vault-id means the demo
    // vault address (cosigner_bridge derives it the same way).
    let mut vault_args = Vec::new();
    if vault_ids.is_empty() {
        vault_args.push(demo_vault()?.address(bitcoin::Network::Regtest).to_string());
    } else {
        vault_args.extend(vault_ids.iter().cloned());
    }
    let vault_flags = vault_args
        .iter()
        .map(|v| format!("--vault-id {v}"))
        .collect::<Vec<_>>()
        .join(" ");
    // Round 17: the Round 14–16 surface bakes into ExecStart TOO — the unit
    // must boot the SAME transport/rate-limit policy the operator previewed
    // (install-what-you-print covers the WHOLE invocation, not just the
    // listen/state/vault triple). TLS material is baked by ABSOLUTE path.
    let mut tls_flags: Vec<String> = Vec::new();
    // KOF-N MIRROR SET (docs/10 §4.60): each mirror dir is canonicalized
    // like the TLS material (the service re-reads it per request — READS
    // are exactly what ProtectSystem=strict still allows, so mirrors stay
    // outside ReadWritePaths) and its state must PARSE HERE: a mirror the
    // bridge would fail on at boot must never be baked into a unit that
    // then restart-fails forever.
    let mirror_abs: Vec<String> = watchtower
        .iter()
        .map(|d| {
            std::fs::canonicalize(d)
                .map_err(|e| format!("cannot resolve --watchtower {}: {e}", d.display()))?
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| format!("--watchtower {} is not valid UTF-8", d.display()))
        })
        .collect::<Result<_, String>>()?;
    for m in &mirror_abs {
        qsv_cosigner::load_state(std::path::Path::new(m)).map_err(|e| {
            format!("--watchtower {m}: {e} — the generated unit would fail at boot")
        })?;
        tls_flags.push(format!("--watchtower {m}"));
    }
    // The OPERATIVE quorum travels verbatim whenever mirrors are baked
    // (§4.31 rule: state the value you run with, never the code default).
    if !mirror_abs.is_empty() {
        tls_flags.push(format!("--watchtower-quorum {quorum}"));
    }
    if let Some(cert) = tls_cert {
        let cert_abs = std::fs::canonicalize(cert)
            .map_err(|e| format!("cannot resolve --tls-cert {}: {e}", cert.display()))?;
        tls_flags.push(format!("--tls-cert {}", cert_abs.display()));
    }
    if let Some(key) = tls_key {
        let key_abs = std::fs::canonicalize(key)
            .map_err(|e| format!("cannot resolve --tls-key {}: {e}", key.display()))?;
        tls_flags.push(format!("--tls-key {}", key_abs.display()));
    }
    if let Some(ca) = tls_client_ca {
        let ca_abs = std::fs::canonicalize(ca)
            .map_err(|e| format!("cannot resolve --tls-client-ca {}: {e}", ca.display()))?;
        tls_flags.push(format!("--tls-client-ca {}", ca_abs.display()));
    }
    if let Some(spec) = rate_limit {
        // Fail-closed: a spec the bridge itself would exit 2 on must never
        // reach the unit file (parse_rate_limit is the SAME validation the
        // bridge boot performs).
        parse_rate_limit(spec)?;
        tls_flags.push(format!("--rate-limit {spec}"));
    }
    if let Some(tok) = metrics_token {
        // Round 18: the scrape gate travels INSIDE the unit (same
        // preview → disk → read-back rule as the TLS material). Whitespace
        // would break the ExecStart word split — refuse before writing.
        if tok.is_empty() || tok.chars().any(char::is_whitespace) {
            return Err("--metrics-token must be a non-empty token without whitespace".to_string());
        }
        tls_flags.push(format!("--metrics-token {tok}"));
    }
    if let Some(tf) = metrics_token_file {
        // Round 21: the FILE form bakes the PATH (canonicalized, like the
        // TLS material) — ExecStart stays free of the secret itself. The
        // unit sandbox must be able to READ the file at boot: keep it
        // outside ProtectHome paths and readable under ProtectSystem=strict.
        let tf_abs = std::fs::canonicalize(tf)
            .map_err(|e| format!("cannot resolve --metrics-token-file {}: {e}", tf.display()))?;
        println!(
            "  token-file:   {} (VALUE stays on disk — only this path lands in ExecStart)",
            tf_abs.display()
        );
        // SANDBOX REACHABILITY (Round 24): the generated unit runs with
        // `ProtectHome=yes`, so a token file under a home tree is
        // UNREADABLE by the service — install-what-you-print would bake a
        // unit whose bridge can never boot (or, worse, one that keeps
        // rotating nothing). Refuse here, where the operator is watching.
        if let Some(blocked) = protected_home_prefix(&tf_abs) {
            return Err(format!(
                "--metrics-token-file {}: the unit runs with ProtectHome=yes, so the SERVICE \
                 cannot read it ({blocked} is made inaccessible) — move the file outside the \
                 home trees (e.g. /etc/qsv/scrape.token, mode 600) and re-run",
                tf.display()
            ));
        }
        tls_flags.push(format!("--metrics-token-file {}", tf_abs.display()));
    }
    // Round 22 (docs/10 §4.31): the two clocks operators actually tune
    // travel WITH the unit — always baked (even at their defaults), so
    // `systemctl show` states the operative frame timeout and drain
    // deadline verbatim instead of whatever the binary's defaults are.
    tls_flags.push(format!("--frame-timeout-ms {frame_timeout_ms}"));
    tls_flags.push(format!("--drain-timeout-ms {drain_timeout_ms}"));
    tls_flags.push(format!("--max-inflight {max_inflight}"));
    let tls_flag_str = tls_flags.join(" ");
    let exec = format!(
        "{qsv} cosigner-bridge --listen {listen} --state-dir {state} {vault_flags} {tls_flag_str}",
        qsv = "qsv-cli",
        state = state_abs.display(),
    );
    // Round 21: the watchdog period this unit ASKS for (the bridge pings
    // at half of it, sd_notify(3)). 30s > default frame timeout (10s) +
    // ping period (15s): a legitimately slow stream never reads as a
    // wedge, while a loop that truly stopped ticking is silent past 25s
    // and systemd restarts the bridge within the 30s window.
    let watchdog_sec: u64 = 30;
    let unit = format!(
        "[Unit]\n\
         Description=QuantumSafe-Vault co-signer bridge (PQC-gated signing)\n\
         After=network.target\n\n\
         [Service]\n\
         # Round 21 (docs/10 §4.26): the bridge REPORTS instead of being
         # guessed — READY=1 only after the bind + health record are real,
         # WATCHDOG=1 only while the accept loop still ticks (silence =
         # restart), STOPPING=1 when the drain begins. NotifyAccess=main
         # matches the sender's ucred (worker threads share the main pid).\n\
         Type=notify\n\
         NotifyAccess=main\n\
         WatchdogSec={watchdog_sec}\n\
         ExecStart={exec}\n\
         # Round 22 (docs/10 §4.30): `systemctl reload` asks the RUNNING\n\
         # bridge to re-read --metrics-token-file and swap the scrape\n\
         # gate in place — no restart, no signing gap. The handler is\n\
         # installed on every boot, so a stray HUP can never kill it.\n\
         ExecReload=/bin/kill -HUP $MAINPID\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         # Hardening: read-only filesystem except the watchtower state dir.\n\
         ProtectSystem=strict\n\
         ReadWritePaths={state}\n\
         PrivateTmp=yes\n\
         NoNewPrivileges=yes\n\
         ProtectHome=yes\n\
         # Round 19 sandboxing: only the bind capability survives, no\n\
         # address families beyond the socket, no namespace/realtime/\n\
         # personality/SUID games, kernel surfaces untouched (no\n\
         # SystemCallFilter/MemoryDenyWriteExecute on purpose: aws-lc's\n\
         # hand-written assembly maps executable pages).\n\
         CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n\
         RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\
         RestrictNamespaces=yes\n\
         RestrictRealtime=yes\n\
         RestrictSUIDSGID=yes\n\
         LockPersonality=yes\n\
         ProtectKernelTunables=yes\n\
         ProtectKernelModules=yes\n\
         ProtectControlGroups=yes\n\
         SystemCallArchitectures=native\n\
\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        state = state_abs.display()
    );
    let timer = format!(
        "[Unit]\n\
         Description=Periodic watchtower pass for the QuantumSafe-Vault bridge\n\n\
         [Timer]\n\
         OnCalendar={cal}\n\
         Persistent=yes\n\n\
         [Install]\n\
         WantedBy=timers.target\n",
        cal = timer_calendar
    );

    // Write (or print) — then VERIFY by re-reading what landed on disk.
    let mut written: Vec<(String, String)> = Vec::new();
    match unit_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            for (suffix, body) in [(".service", &unit), (".timer", &timer)] {
                let path = dir.join(format!("{unit_name}{suffix}"));
                std::fs::write(&path, body)
                    .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                println!("  unit:         {} written", path.display());
                written.push((path.display().to_string(), body.clone()));
            }
        }
        None => {
            println!("\n# {unit_name}.service\n{unit}");
            println!("# {unit_name}.timer\n{timer}");
        }
    }

    if !written.is_empty() {
        verify_bridge_units(
            &written,
            &state_abs,
            &tls_flags,
            metrics_token_file.is_some(),
            resolved_token.as_deref(),
            timer_calendar,
            watchdog_sec,
        )?;
    }
    println!(
        "\nCo-signer bridge units: GENERATED{} 🛡️",
        if written.is_empty() {
            " (stdout preview — pass --unit-dir to write)"
        } else {
            " and verified"
        }
    );
    Ok(())
}

/// Read-back verifier for the generated systemd pair: every load-bearing
/// directive is re-checked against the ON-DISK text. Extracted (Round 30)
/// so each wall is unit-testable — the generator can never produce a bad
/// body, but a partial write or an on-disk edit could, and a wall nobody
/// can exercise is a wall nobody trusts.
fn verify_bridge_units(
    written: &[(String, String)],
    state_abs: &std::path::Path,
    tls_flags: &[String],
    token_file_flag_present: bool,
    resolved_token: Option<&str>,
    timer_calendar: &str,
    watchdog_sec: u64,
) -> Result<(), String> {
    println!("  verify:       re-reading written units for required directives");
    for (path, body) in written {
        let on_disk = std::fs::read_to_string(path)
            .map_err(|e| format!("written unit vanished ({path}): {e}"))?;
        if on_disk != *body {
            return Err(format!(
                "unit on disk differs from generated content: {path}"
            ));
        }
    }
    let service_body = &written[0].1;
    let exec_line = service_body
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .ok_or_else(|| "generated unit has no ExecStart".to_string())?;
    if !exec_line.contains("cosigner-bridge")
        || !exec_line.contains(&format!("--state-dir {}", state_abs.display()))
    {
        return Err(format!(
            "ExecStart must invoke cosigner-bridge with --state-dir {state} — got: {exec_line}",
            state = state_abs.display()
        ));
    }
    // Round 17: the baked transport/rate-limit flags must land VERBATIM
    // in the on-disk ExecStart — install-what-you-print covers the
    // WHOLE invocation, not just the listen/state/vault triple.
    for flag in tls_flags {
        if !exec_line.contains(flag.as_str()) {
            return Err(format!(
                "ExecStart must carry the baked flag `{flag}` — got: {exec_line}"
            ));
        }
    }
    // Round 21: the FILE form must travel as a PATH — the token VALUE
    // has no business anywhere in a unit file (world-readable under
    // /etc/systemd, printed by `systemctl cat`, kept forever in git).
    if token_file_flag_present {
        if let Some(value) = resolved_token {
            if service_body.contains(value) {
                return Err(
                    "the metrics token VALUE must never reach the unit file — bake --metrics-token-file <path> instead"
                        .to_string(),
                );
            }
        }
    }
    for required in [
        "ProtectSystem=strict",
        "NoNewPrivileges=yes",
        "Restart=on-failure",
        // Round 21: a Type=simple unit would let systemd "start" a
        // bridge that deadlocked before its first request — the
        // notify trio is the whole point of the round.
        "Type=notify",
        "NotifyAccess=main",
    ] {
        if !service_body.lines().any(|l| l == required) {
            return Err(format!(
                "generated unit is missing required directive: {required}"
            ));
        }
    }
    // WatchdogSec must be a REAL period: Type=notify without a watchdog
    // is the same theater as liveness-blind pings.
    let watchdog_ok = service_body.lines().any(|l| {
        l.strip_prefix("WatchdogSec=")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .is_some_and(|secs| secs >= 1)
    });
    if !watchdog_ok {
        return Err(
            "generated unit is missing a sane WatchdogSec= (Type=notify without a watchdog is theater)"
                .to_string(),
        );
    }
    let rw_ok = service_body
        .lines()
        .any(|l| l == format!("ReadWritePaths={}", state_abs.display()));
    if !rw_ok {
        return Err(format!(
            "generated unit is missing ReadWritePaths={}",
            state_abs.display()
        ));
    }
    // The reload half of the rotation contract: without ExecReload,
    // `systemctl reload` is a silent no-op and the operator believes
    // they rotated a secret that never moved (docs/10 §4.30).
    if !service_body
        .lines()
        .any(|l| l == "ExecReload=/bin/kill -HUP $MAINPID")
    {
        return Err(
            "generated unit is missing ExecReload=/bin/kill -HUP $MAINPID (reload must reach the token rotation)"
                .to_string(),
        );
    }
    let timer_body = &written[1].1;
    if !timer_body.contains(&format!("OnCalendar={timer_calendar}")) {
        return Err(format!(
            "generated timer is missing OnCalendar={timer_calendar}"
        ));
    }
    println!(
        "  verified:     ProtectSystem=strict · ReadWritePaths(state-dir) · ExecStart · ExecReload(SIGHUP rotation) · Type=notify+WatchdogSec={watchdog_sec} · OnCalendar{}",
        if tls_flags.is_empty() {
            String::new()
        } else {
            format!(" · {} baked flag(s)", tls_flags.len())
        }
    );
    Ok(())
}

// ─── Capacity bench: what one operation actually costs ───

/// Times ONE operation `iterations` times and prints the honest pair:
/// throughput (ops/s) and cost (µs/op). `black_box` keeps the optimizer
/// from deleting the very work being measured.
/// ONE measured operation — the unit BOTH outputs are built from (the
/// human table and `bench --json` report the identical numbers).
struct BenchRow {
    label: &'static str,
    ops_per_s: f64,
    us_per_op: f64,
}

/// The rows every report and every BASELINE share (docs/10 §4.29/§4.38):
/// a baseline missing one of these refuses to gate. The literals at the
/// `bench_row` call sites must match — the bench tests compare them, so a
/// rename in one place without the other fails the SUITE, not the
/// operator's gate.
const BENCH_OPS: [&str; 7] = [
    "pqc keygen (ML-DSA-65)",
    "pqc sign (ML-DSA-65)",
    "pqc verify (ML-DSA-65)",
    "bip340 sign",
    "bip340 verify",
    "enclave gate (pqc→bip340)",
    "health write+read",
];

fn bench_row(label: &'static str, iterations: usize, mut op: impl FnMut()) -> BenchRow {
    let started = std::time::Instant::now();
    for _ in 0..iterations {
        op();
    }
    let elapsed = started.elapsed();
    let secs = elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    BenchRow {
        label,
        ops_per_s: iterations as f64 / secs,
        us_per_op: elapsed.as_micros() as f64 / iterations as f64,
    }
}

/// CAPACITY BASELINE (docs/10 §4.38): one operation that fell below its
/// stored report by more than the tolerance — the gate half of the bench.
struct CapacityRegression {
    op: &'static str,
    baseline_ops_per_s: f64,
    ops_per_s: f64,
    delta_pct: f64,
}

/// Loads a stored `bench --json` report BEFORE anything is printed.
/// Everything that would turn the comparison into a GUESS is an error —
/// unreadable file, no document, a row without numbers, a coverage gap,
/// or a tolerance outside [0, 100): the gate must refuse to compare
/// rather than pass by accident, and it must do so before stdout carries
/// a single measurement (a half report followed by a usage error is how
/// a log reader mistakes noise for a verdict).
fn load_baseline(
    path: &std::path::Path,
    tolerance_pct: f64,
) -> Result<std::collections::HashMap<String, f64>, String> {
    if !(0.0..100.0).contains(&tolerance_pct) {
        return Err("--baseline-tolerance-pct must be in [0, 100)".to_string());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read: {e}"))?;
    let doc: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("not a JSON document: {e}"))?;
    let stored = doc
        .get("rows")
        .and_then(|r| r.as_array())
        .ok_or_else(|| "no rows[] — is this a `bench --json` report?".to_string())?;
    let mut baseline = std::collections::HashMap::new();
    for row in stored {
        let op = row
            .get("op")
            .and_then(|o| o.as_str())
            .ok_or_else(|| "a baseline row has no op name".to_string())?;
        let ops = row
            .get("ops_per_s")
            .and_then(|o| o.as_f64())
            .ok_or_else(|| format!("`{op}` has no numeric ops_per_s"))?;
        if ops <= 0.0 {
            return Err(format!("`{op}` baseline must be positive, got {ops}"));
        }
        baseline.insert(op.to_string(), ops);
    }
    for op in BENCH_OPS {
        if !baseline.contains_key(op) {
            return Err(format!("baseline does not cover `{op}`"));
        }
    }
    Ok(baseline)
}

/// Match-up after the measurement — infallible: coverage was proven at
/// load, so every row finds its baseline.
fn compare_rows(
    baseline: &std::collections::HashMap<String, f64>,
    rows: &[BenchRow],
    tolerance_pct: f64,
) -> Vec<CapacityRegression> {
    let mut regressions = Vec::new();
    for row in rows {
        let base = *baseline
            .get(row.label)
            .expect("coverage was validated when the baseline loaded");
        if row.ops_per_s < base * (1.0 - tolerance_pct / 100.0) {
            regressions.push(CapacityRegression {
                op: row.label,
                baseline_ops_per_s: base,
                ops_per_s: row.ops_per_s,
                delta_pct: (row.ops_per_s - base) / base * 100.0,
            });
        }
    }
    regressions
}

/// CAPACITY BENCH (docs/10 §4.29, Round 21): an estate's throughput is
/// the SLOWEST op below — so measure every op the two-key ceremony is
/// built from: ML-DSA-65 keygen/sign/verify, BIP-340 sign/verify, the
/// enclave gate (PQC verify + co-sign + self-verify, the exact path
/// `cosigner-bridge` runs per request) and the health-record write+read
/// loop. A REPORT (exit 0) by default — unless `--baseline` turns it
/// into the capacity GATE of docs/10 §4.38 (exit 1 beyond tolerance);
/// floors belong in the test suite either way.
fn bench(
    iterations: usize,
    json: bool,
    baseline: Option<&std::path::Path>,
    tolerance_pct: f64,
) -> Result<(), String> {
    if iterations == 0 {
        eprintln!("usage error: --iterations must be at least 1");
        std::process::exit(2);
    }
    // BASELINE FIRST (docs/10 §4.38): a gate that cannot compare must
    // say so BEFORE the first byte of stdout — exit 2 with an empty
    // output, never a measurement report followed by a usage error.
    let baseline_map = match baseline {
        Some(path) => match load_baseline(path, tolerance_pct) {
            Ok(map) => Some(map),
            Err(why) => {
                eprintln!("usage error: --baseline {}: {why}", path.display());
                std::process::exit(2);
            }
        },
        None => None,
    };
    if !json {
        println!("\n───── [17] CAPACITY BENCH · PER-OP COST OF THE ESTATE ───────");
        println!("  iterations:     {iterations} per operation (wall clock, single thread)");
    }
    let mut rows: Vec<BenchRow> = Vec::new();

    // MATERIAL: built OUTSIDE the timed loops — the bench measures the
    // op under test, never the setup around it.
    let pqc_seed = [21u8; 32];
    let msg = [0x5au8; 32]; // sighash-sized — the gate's real input shape
    let pqc = qsv_pqc::PqcIdentity::from_seed(&pqc_seed);
    let pqc_sig = pqc.sign(&msg);
    rows.push(bench_row("pqc keygen (ML-DSA-65)", iterations, || {
        std::hint::black_box(qsv_pqc::PqcIdentity::from_seed(&pqc_seed));
    }));
    rows.push(bench_row("pqc sign (ML-DSA-65)", iterations, || {
        std::hint::black_box(pqc.sign(&msg));
    }));
    rows.push(bench_row("pqc verify (ML-DSA-65)", iterations, || {
        std::hint::black_box(qsv_pqc::pqc_verify(
            pqc.verifying_key_bytes(),
            &msg,
            &pqc_sig,
        ));
    }));

    // BIP-340: the co-signature half of the two-key ceremony.
    let secp_sign = bitcoin::secp256k1::Secp256k1::signing_only();
    let secp_verify = bitcoin::secp256k1::Secp256k1::verification_only();
    let keypair = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp_sign, &[0x11u8; 32])
        .map_err(|e| format!("bench keypair: {e}"))?;
    let (xonly, _) = keypair.x_only_public_key();
    let bip_msg = bitcoin::secp256k1::Message::from_digest(msg);
    let bip_sig = secp_sign.sign_schnorr_with_aux_rand(&bip_msg, &keypair, &[0u8; 32]);

    rows.push(bench_row("bip340 sign", iterations, || {
        std::hint::black_box(secp_sign.sign_schnorr_with_aux_rand(&bip_msg, &keypair, &[0u8; 32]));
    }));
    rows.push(bench_row("bip340 verify", iterations, || {
        std::hint::black_box(
            secp_verify
                .verify_schnorr(&bip_sig, &bip_msg, &xonly)
                .is_ok(),
        );
    }));

    // THE ENCLAVE GATE — the exact per-request path cosigner-bridge
    // runs: PQC verify, enclave keypair derivation, BIP-340 sign, then
    // self-verification before release (defense in depth, by design).
    rows.push(bench_row("enclave gate (pqc→bip340)", iterations, || {
        std::hint::black_box(
            qsv_pqc::enclave_sign_if_pqc_valid(
                pqc.verifying_key_bytes(),
                &pqc_sig,
                &msg,
                &DEMO_ENCLAVE_SEED,
            )
            .is_ok(),
        );
    }));

    // HEALTH RECORD — the operator-facing write+read loop (atomic temp+
    // rename per write, the doctor's read per probe).
    let state_dir = std::env::temp_dir().join(format!("qsv-bench-{}", std::process::id()));
    std::fs::create_dir_all(&state_dir).map_err(|e| format!("bench state dir: {e}"))?;
    let record = qsv_cosigner::health::current(
        "127.0.0.1:3334",
        "plain",
        vec!["bench-vault".to_string()],
        820_000,
        qsv_cosigner::health::ServePolicyRecord {
            metrics_token_armed: false,
            metrics_token_file: None,
            max_inflight: 64,
            frame_timeout_ms: Some(10_000),
        },
    );
    rows.push(bench_row("health write+read", iterations, || {
        qsv_cosigner::health::write(&state_dir, &record)
            .expect("health write during bench must succeed");
        std::hint::black_box(qsv_cosigner::health::read(&state_dir));
    }));
    let _ = std::fs::remove_dir_all(&state_dir);

    // CAPACITY BASELINE (docs/10 §4.38): the gate half — a stored report
    // turns "slower" from a comment into an exit code. An unusable
    // baseline is a usage error (exit 2), never a silent pass.
    let regressions = match (&baseline, &baseline_map) {
        (Some(_), Some(map)) => compare_rows(map, &rows, tolerance_pct),
        _ => Vec::new(),
    };

    if json {
        // MACHINE-READABLE (docs/10 §4.33): one document carrying the
        // SAME numbers as the table. With a baseline it also carries the
        // verdict — CI reads one parse and the exit code.
        let mut doc = serde_json::json!({
            "schema": "qsv-bench/v1",
            "iterations": iterations,
            "rows": rows
                .iter()
                .map(|r| serde_json::json!({
                    "op": r.label,
                    "ops_per_s": r.ops_per_s,
                    "us_per_op": r.us_per_op,
                }))
                .collect::<Vec<_>>(),
        });
        if let Some(path) = baseline {
            doc["baseline"] = serde_json::json!({
                "file": path.display().to_string(),
                "tolerance_pct": tolerance_pct,
                "verdict": if regressions.is_empty() { "pass" } else { "fail" },
                "regressions": regressions
                    .iter()
                    .map(|r| serde_json::json!({
                        "op": r.op,
                        "baseline_ops_per_s": r.baseline_ops_per_s,
                        "ops_per_s": r.ops_per_s,
                        "delta_pct": r.delta_pct,
                    }))
                    .collect::<Vec<_>>(),
            });
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
        if !regressions.is_empty() {
            return Err(format!(
                "{} capacity regression(s) beyond {tolerance_pct}% of the baseline",
                regressions.len()
            ));
        }
        // stdout must stay a SINGLE document — skip main()'s success line.
        std::process::exit(0);
    }
    if !json {
        // The human table — printed only now: every line on stdout is a
        // measurement the baseline gate already accepted.
        for r in &rows {
            println!(
                "  {:<26} {:>12.1} ops/s  {:>10.1} µs/op",
                r.label, r.ops_per_s, r.us_per_op
            );
        }
    }
    if let Some(baseline_path) = baseline {
        for r in &regressions {
            println!(
                "  REGRESSION:    {} {:.1} ops/s vs baseline {:.1} ({:+.1}% — beyond {tolerance_pct}%)",
                r.op, r.ops_per_s, r.baseline_ops_per_s, r.delta_pct
            );
        }
        if regressions.is_empty() {
            println!(
                "  baseline:      all {} operation(s) within {tolerance_pct}% of {}",
                rows.len(),
                baseline_path.display()
            );
        }
    }
    if !regressions.is_empty() {
        return Err(format!(
            "{} capacity regression(s) beyond {tolerance_pct}% of the baseline — re-measure on a quiet box, or accept the new floor explicitly",
            regressions.len()
        ));
    }
    println!("\n  the SLOWEST row rules the estate — re-measure with --iterations");
    Ok(())
}

// ─── Operator doctor: one command, every liveness signal ───

/// One doctor verdict. FAIL is the only state that turns into a non-zero
/// exit: a WARN is information (the estate still signs), and a red table
/// that cries wolf is a table operators learn to ignore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Diagnosis {
    Ok,
    Warn,
    Fail,
}

impl Diagnosis {
    fn mark(self) -> &'static str {
        match self {
            Self::Ok => "  OK  ",
            Self::Warn => " WARN ",
            Self::Fail => " FAIL ",
        }
    }
    /// Machine-readable status word (`doctor --json`).
    fn status(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// Reads one `qsv_cosigner_*` counter out of a scrape body.
fn metric_value(text: &str, name: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{name} ")))
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// METRICS TOKEN FROM A FILE (docs/10 §4.27, Round 21): a token passed
/// as a flag lands in `/proc/*/cmdline`, the shell history and the unit
/// file's ExecStart — every one of them readable by any process on the
/// box. The file form keeps the SECRET in one `chmod 600` file the
/// process reads once at boot.
///
/// Contract — each rule blocks a real attack or a real paste accident:
///   * permissions: NO group/other bits at all (`chmod 600`). A token
///     file the whole machine can open is not a secret store, and
///     failing closed here beats discovering the leak in a log scraper;
///   * exactly ONE line: a second line is a paste accident (or an
///     attempt to smuggle a second `Header: value` through the scrape);
///   * no whitespace inside: the value travels as an HTTP header —
///     CR/LF in it is header injection.
fn read_metrics_token_file(path: &std::path::Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| format!("--metrics-token-file {}: {e}", path.display()))?
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "--metrics-token-file {}: group/other can read it (mode {:04o}) — chmod 600 it",
                path.display(),
                mode & 0o7777
            ));
        }
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("--metrics-token-file {}: {e}", path.display()))?;
    let mut lines = raw.lines();
    let token = lines
        .next()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| format!("--metrics-token-file {}: the file is empty", path.display()))?;
    if lines.next().is_some() {
        return Err(format!(
            "--metrics-token-file {}: exactly ONE line expected (found more)",
            path.display()
        ));
    }
    if token.chars().any(char::is_whitespace) {
        return Err(format!(
            "--metrics-token-file {}: the token contains whitespace",
            path.display()
        ));
    }
    Ok(token.to_string())
}

/// The first tree `ProtectHome=yes` makes UNREADABLE for the service user
/// (docs/10 §4.40, Round 24). systemd mounts `/home`, `/root` and
/// `/run/user` inaccessible to the unit — a file the OPERATOR can read
/// right now may be invisible to the process the unit starts. `None`
/// when the path survives the sandbox.
///
/// Matching is component-exact (`/rooted` is not `/root`), because a
/// prefix match on a home tree is how an innocent path gets refused.
fn protected_home_prefix(path: &std::path::Path) -> Option<&'static str> {
    const PROTECTED: [&str; 3] = ["/home", "/root", "/run/user"];
    let text = path.to_string_lossy();
    PROTECTED.into_iter().find(|root| {
        text.as_ref() == *root
            || text
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Minimal `GET /metrics` probe over the bridge's plain listener — the
/// same wire form Prometheus uses (docs/10 §4.20). Read-only, no
/// dependencies: the doctor must run on a machine that has nothing but
/// this binary.
fn metrics_probe(addr: &str, token: Option<&str>) -> Result<String, String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .and_then(|_| s.set_write_timeout(Some(std::time::Duration::from_secs(5))))
        .map_err(|e| format!("deadline on {addr}: {e}"))?;
    let mut req = format!("GET /metrics HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(t) = token {
        req.push_str(&format!("X-QSV-Metrics-Token: {t}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())
        .map_err(|e| format!("write {addr}: {e}"))?;
    let mut buf = String::new();
    s.read_to_string(&mut buf)
        .map_err(|e| format!("read {addr}: {e}"))?;
    Ok(buf)
}

/// The operator doctor (docs/10 §4.24): the estate's liveness in ONE
/// command. Each layer is asked in dependency order — node, then the
/// watchtower verdicts derived from it, then the mirror lag between them,
/// then the bridge record, then the live scrape the alert rules consume.
/// A layer that cannot be reached is reported as such; nothing here
/// invents a healthy answer it could not verify.
#[allow(clippy::too_many_arguments)] // Round 21: --metrics-token-file (project convention)
fn doctor(
    datadir: &std::path::Path,
    network: bitcoin::Network,
    state_dir: &std::path::Path,
    bridge: Option<&str>,
    metrics_token: Option<&str>,
    metrics_token_file: Option<&std::path::Path>,
    max_mirror_lag: u64,
    rpc_port: Option<u16>,
    json: bool,
) -> Result<(), String> {
    if !json {
        println!("\n───── [16c] OPERATOR DOCTOR · ESTATE LIVENESS ──────────────────");
    }
    // TOKEN SOURCE (docs/10 §4.27, Round 21): the doctor is run by
    // operators and cron alike — its OWN argv must stay secret-free too.
    if metrics_token.is_some() && metrics_token_file.is_some() {
        eprintln!("usage error: --metrics-token and --metrics-token-file are mutually exclusive");
        std::process::exit(2);
    }
    let owned_token;
    let metrics_token = match metrics_token_file {
        Some(path) => {
            owned_token = read_metrics_token_file(path)?;
            Some(owned_token.as_str())
        }
        None => metrics_token,
    };
    let mut results: Vec<(&str, Diagnosis, String)> = Vec::new();

    // 1. NODE: the chain every other layer reads from. No node = no tip,
    //    and every downstream answer would be a guess.
    let rpc_network = rpc_network(network);
    // The cookie carries credentials, never the port — an off-default
    // node needs --rpc-port (same contract as psbt/watchtower).
    let rpc = match rpc_port {
        Some(port) => qsv_node::rpc::BitcoinRpc::from_cookie_with_port(datadir, rpc_network, port),
        None => qsv_node::rpc::BitcoinRpc::from_endpoint(&qsv_node::rpc::NodeEndpoint::Cookie {
            datadir: datadir.to_path_buf(),
            network: rpc_network,
        }),
    };
    let node_tip = match rpc.and_then(|rpc| rpc.getblockcount()) {
        Ok(h) => {
            results.push((
                "node rpc",
                Diagnosis::Ok,
                format!("tip {h} via cookie in {}", datadir.display()),
            ));
            Some(h)
        }
        Err(e) => {
            results.push((
                "node rpc",
                Diagnosis::Fail,
                format!("{} ({e})", datadir.display()),
            ));
            None
        }
    };

    // 2. WATCHTOWER STATE: the verdicts the bridge mirrors. The bridge
    //    refuses to boot on an unreadable state file (fail-closed), so an
    //    operator must see the SAME failure here, not discover it later
    //    as a co-signer that will not start.
    let verdicts = qsv_cosigner::load_state(state_dir);
    match &verdicts {
        Ok(v) => {
            let frozen = v
                .vaults
                .iter()
                .filter(|(_, verdict)| verdict.eq_ignore_ascii_case("alert"))
                .count();
            results.push((
                "watchtower state",
                Diagnosis::Ok,
                format!(
                    "tip {} · {} vault(s) tracked · {frozen} frozen",
                    v.tip,
                    v.vaults.len()
                ),
            ));
        }
        Err(e) => results.push(("watchtower state", Diagnosis::Fail, e.clone())),
    }

    // 3. MIRROR LAG: the bridge freezes on the verdicts IN THE FILE, so a
    //    stale file means the estate is protected against an old view of
    //    the chain while the node has moved on. That is a silent security
    //    gap — a warning, not a cosmetic note.
    if let (Some(node), Ok(v)) = (node_tip, &verdicts) {
        match node.checked_sub(v.tip) {
            Some(lag) if u64::from(lag) > max_mirror_lag => results.push((
                "mirror lag",
                Diagnosis::Warn,
                format!(
                    "verdicts {lag} block(s) behind the node (limit {max_mirror_lag}) — run the watchtower pass"
                ),
            )),
            Some(lag) => results.push((
                "mirror lag",
                Diagnosis::Ok,
                format!("{lag} block(s) behind the node (limit {max_mirror_lag})"),
            )),
            None => results.push((
                "mirror lag",
                Diagnosis::Warn,
                format!("verdicts at {} are AHEAD of node tip {node}", v.tip),
            )),
        }
    }

    // 4. BRIDGE RECORD: who is serving, from where, with which policy —
    //    plus the pid liveness that separates a clean stop from a corpse.
    let (state, record) = qsv_cosigner::health::liveness(state_dir);
    results.extend(health_diagnoses(state, record.as_ref(), state_dir));

    // 5. LIVE SCRAPE: the numbers the Prometheus alert rules read. If the
    //    gate rejects us, monitoring is BLIND — a FAIL, not a warning.
    let target = bridge.or_else(|| record.as_ref().map(|h| h.listen.as_str()));
    match target {
        None => results.push((
            "metrics scrape",
            Diagnosis::Warn,
            "no bridge address to probe (pass --bridge or start the bridge)".to_string(),
        )),
        Some(addr) => match metrics_probe(addr, metrics_token) {
            Err(e) => results.push(("metrics scrape", Diagnosis::Fail, e)),
            Ok(body) => {
                if body.contains("HTTP/1.1 401") {
                    results.push((
                        "metrics scrape",
                        Diagnosis::Fail,
                        format!("{addr} refused the scrape (401) — pass --metrics-token; the alert rules would be blind"),
                    ));
                } else if !body.contains("HTTP/1.1 200") {
                    results.push((
                        "metrics scrape",
                        Diagnosis::Fail,
                        format!("{addr} answered without a 200 (not a co-signer?)"),
                    ));
                } else {
                    let req = metric_value(&body, "qsv_cosigner_requests_total");
                    let acc = metric_value(&body, "qsv_cosigner_accepted_total");
                    let alarms =
                        metric_value(&body, "qsv_cosigner_alarm_refused_total").unwrap_or(0);
                    results.push((
                        "metrics scrape",
                        Diagnosis::Ok,
                        format!(
                            "{addr} · {req:?} request(s) · {acc:?} released · {alarms} alarm-refusal(s)"
                        ),
                    ));
                }
            }
        },
    }

    // 6. RELOAD READINESS (docs/10 §4.37): `systemctl reload` swaps the
    //    scrape secret in place (Round 22) — but a reload that CANNOT
    //    rotate leaves the OLD secret live while the operator believes it
    //    moved, and nothing breaks until the token is incident-response
    //    critical. The doctor proves the reload would work BEFORE it is
    //    run, with the very file contract the bridge enforces (mode 600,
    //    one line, no whitespace): no guessing, no 3 a.m. discovery
    //    through `qsv_cosigner_rotate_denied_total`.
    if let Some(h) = record.as_ref() {
        match h.metrics_token_file.as_deref() {
            Some(path) => match read_metrics_token_file(std::path::Path::new(path)) {
                Ok(_) => results.push((
                    "scrape rotation",
                    Diagnosis::Ok,
                    format!("{path} is a valid token source — `systemctl reload` rotates in place"),
                )),
                Err(e) => results.push((
                    "scrape rotation",
                    Diagnosis::Fail,
                    format!("a reload would be REFUSED ({e}) — the previous token stays live"),
                )),
            },
            // Armed from argv: the gate works, but there is NOTHING to
            // re-read, so every reload from here on is a silent no-op.
            None if h.metrics_token_armed => results.push((
                "scrape rotation",
                Diagnosis::Warn,
                "gate armed via --metrics-token: no file to re-read, so `systemctl reload` \
                 cannot rotate it — move the secret into a --metrics-token-file (chmod 600)"
                    .to_string(),
            )),
            None => results.push((
                "scrape rotation",
                Diagnosis::Ok,
                "scrape open (loopback dev default) — no rotation to keep ready".to_string(),
            )),
        }
    }

    let fails = results
        .iter()
        .filter(|(_, d, _)| *d == Diagnosis::Fail)
        .count();
    let warns = results
        .iter()
        .filter(|(_, d, _)| *d == Diagnosis::Warn)
        .count();
    if json {
        // MACHINE-READABLE (docs/10 §4.32): ONE document, one schema,
        // nothing else on stdout — a script parses it and reads the exit
        // code, which mirrors the human run exactly (FAIL → main() prints
        // the reason to STDERR and exits 1).
        let checks: Vec<serde_json::Value> = results
            .iter()
            .map(|(name, d, detail)| {
                serde_json::json!({
                    "name": name,
                    "status": d.status(),
                    "detail": detail,
                })
            })
            .collect();
        let doc = serde_json::json!({
            "schema": "qsv-doctor/v1",
            "total": results.len(),
            "fail": fails,
            "warn": warns,
            "exit_code": if fails > 0 { 1 } else { 0 },
            "checks": checks,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?
        );
        if fails > 0 {
            return Err(format!(
                "{fails} required check(s) failed — the estate is not fully healthy"
            ));
        }
        // stdout must stay a SINGLE document — skip main()'s success line.
        std::process::exit(0);
    }
    println!();
    for (name, d, detail) in &results {
        println!("[{}] {name:<17} {detail}", d.mark());
    }
    println!(
        "\nDOCTOR: {} check(s) — {fails} FAIL, {warns} WARN",
        results.len()
    );
    if fails > 0 {
        // main() prints the error and exits 1 — the scripted health gate.
        return Err(format!(
            "{fails} required check(s) failed — the estate is not fully healthy"
        ));
    }
    println!("All required checks passed 🛡️");
    Ok(())
}

// ─── Inheritance watchtower: one read-only alert pass ───

/// One watchtower pass over a REAL node (docs/04 §2 + §4):
///   1. tip + last-refresh delta vs the heartbeat policy (MISSED refresh =
///      the dead man's switch trigger — the only thing that exits 1);
///   2. the inheritance CSV countdown (OPEN = heirs may settle);
///   3. live vault coins (read-only scantxoutset — nothing is spent);
///   4. a full FROST threshold ceremony in --no-broadcast mode (proves the
///      heirs CAN spend TODAY: real sighash, real threshold aggregation,
///      real consensus self-check, deterministic hold artifact).
///
/// Alert latency: one pass, no state (a cron/systemd timer owns cadence).
/// Alert-only failure: the ONLY error this function returns is the due
/// heartbeat (plus transport failures). Healthy passes always exit 0.
#[allow(clippy::too_many_arguments)]
fn watchtower(
    datadir: &std::path::Path,
    rpc_port: Option<u16>,
    network: bitcoin::Network,
    last_refresh_block: u32,
    deals: &[String],
    public: Option<&std::path::Path>,
    dir: &std::path::Path,
    fund_sat: u64,
) -> Result<(), String> {
    println!("\n───── [14] WATCHTOWER · HEARTBEAT + THRESHOLD READINESS ────────");
    if !deals.is_empty() && public.is_none() {
        return Err("--deal requires --public (the coordinator package)".into());
    }

    let rpc = match rpc_port {
        Some(port) => {
            qsv_node::rpc::BitcoinRpc::from_cookie_with_port(datadir, rpc_network(network), port)
        }
        None => qsv_node::rpc::BitcoinRpc::from_endpoint(&qsv_node::rpc::NodeEndpoint::Cookie {
            datadir: datadir.to_path_buf(),
            network: rpc_network(network),
        }),
    }
    .map_err(|e| format!("cannot reach node (is bitcoind running?): {e}"))?;
    let tip = rpc.getblockcount().map_err(|e| e.to_string())?;
    println!("  node:         tip {tip} (read-only pass — nothing is broadcast)");

    // 1. HEARTBEAT: policy due? Missing it is the TRIGGER, not a failure.
    let policy = qsv_core::heartbeat::HeartbeatPolicy::default();
    policy
        .validate()
        .map_err(|e| format!("heartbeat policy: {e}"))?;
    let idle = tip.saturating_sub(last_refresh_block);
    let due = qsv_core::heartbeat::is_due(&policy, last_refresh_block, tip);
    let next = policy.interval_blocks.saturating_sub(idle).max(1);
    let open_in = qsv_core::heartbeat::blocks_until_expiry(last_refresh_block, tip);
    println!(
        "  heartbeat:    idle {idle} / {} blocks · {} (next window in ~{next} blocks)",
        policy.interval_blocks,
        if due {
            "DUE — OWNER REFRESH MISSED"
        } else {
            "healthy"
        }
    );
    println!(
        "  inheritance:  CSV 26,280 · {} ({open_in} blocks left)",
        if open_in == 0 {
            "OPEN — heirs may settle"
        } else {
            "locked"
        }
    );

    // 2. Live vault coins (demo provisioning vault; read-only).
    let vault = demo_vault()?;
    let address = vault.address(network).to_string();
    let utxo_info = rpc
        .scan_utxos_for_address(&address, 10_000)
        .map_err(|e| format!("UTXO scan failed: {e}"))?;
    let total: Amount = utxo_info.iter().map(|(_, a)| *a).sum();
    println!(
        "  vault coins:  {} live · {} sats at {address}",
        utxo_info.len(),
        total.to_sat()
    );

    // 3. FROST rehearsal (optional): heirs prove the threshold spend works
    //    TODAY, without broadcasting. Reuses frost-spend's verified path.
    if !deals.is_empty() {
        let public = public.expect("checked above");
        println!("  rehearsal:    FROST threshold ceremony (hold, no broadcast)");
        // No bridge in the rehearsal: the default demo pin set is inert
        // here (frost-spend only consults it behind --cosigner).
        let pin = CosignerPin::resolve(false, None, None, None, None)?;
        frost_spend(
            public, deals, datadir, rpc_port, network, 1_500, fund_sat, None, dir, true, None,
            None, None, &pin,
        )?;
    }

    // 4. Verdict: ONLY a missed heartbeat is an alert.
    if due {
        println!("\nWATCHTOWER: ALERT — heartbeat due, owner refresh MISSED. 🚨");
        return Err("heartbeat due: inheritance countdown is running".to_string());
    }
    println!("\nWATCHTOWER: all clear (heartbeat healthy, verdict recorded). 🛡️");
    Ok(())
}

// ─── FROST group-key spend on a live chain (Part 1) ───

/// Funds (or finds) a confirmed UTXO paying the FROST GROUP key's P2TR
/// address, runs the RFC 9591 ceremony with a BIP-341-TWEAKED public
/// package (key-path-only tweak, merkle root None) and broadcasts the
/// threshold spend. The mempool accepting is the whole point: a k-of-n
/// threshold signature is indistinguishable from a single-signer spend.
#[allow(clippy::too_many_arguments)]
fn frost_spend(
    public: &std::path::Path,
    deals: &[String],
    datadir: &std::path::Path,
    rpc_port: Option<u16>,
    network: bitcoin::Network,
    fee_sat: u64,
    fund_sat: u64,
    destination: Option<&str>,
    dir: &std::path::Path,
    no_broadcast: bool,
    cosigner: Option<&str>,
    vault_id: Option<&str>,
    min_inputs: Option<usize>,
    cosigner_pin: &CosignerPin,
) -> Result<(), String> {
    println!("\n───── [13] FROST · GROUP-KEY SPEND (live chain) ────────────────");
    if cosigner.is_some() != vault_id.is_some() {
        return Err("--cosigner and --vault-id must be given together".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    // 1. The group key and its P2TR address (key-path-only tweak: the
    //    spend will be a KEY-PATH spend under the tweaked group key).
    let public_text = kit_read(public)?;
    let group_key = qsv_core::frost::group_key_of(&public_text).map_err(|e| e.to_string())?;
    let (tweaked_pub, tweaked_group) =
        qsv_core::frost::tweak_public_package(&public_text, None).map_err(|e| e.to_string())?;
    let group_x = XOnlyPublicKey::from_slice(&tweaked_group)
        .map_err(|_| "tweaked group key is not a valid x-only key".to_string())?;
    use bitcoin::key::TapTweak;
    let group_addr = bitcoin::Address::p2tr_tweaked(group_x.dangerous_assume_tweaked(), network);
    println!("  group key:    {}", hex::encode(group_key));
    println!(
        "  output key:   {} (BIP-341 key-path tweak)",
        hex::encode(tweaked_group)
    );
    println!("  address:      {group_addr}");

    // 2. Node connection.
    let rpc = match rpc_port {
        Some(port) => {
            qsv_node::rpc::BitcoinRpc::from_cookie_with_port(datadir, rpc_network(network), port)
        }
        None => qsv_node::rpc::BitcoinRpc::from_endpoint(&qsv_node::rpc::NodeEndpoint::Cookie {
            datadir: datadir.to_path_buf(),
            network: rpc_network(network),
        }),
    }
    .map_err(|e| format!("cannot reach node (is bitcoind running?): {e}"))?;
    let tip = rpc.getblockcount().map_err(|e| e.to_string())?;
    println!("  node:         tip {tip}");

    // 3. Optionally fund the group address first (regtest convenience).
    if fund_sat > 0 {
        let amount = format!("{:.8}", fund_sat as f64 / 100_000_000.0);
        let txid: String = rpc
            .call(
                "sendtoaddress",
                &[
                    serde_json::json!(group_addr.to_string()),
                    serde_json::json!(amount),
                ],
            )
            .map_err(|e| format!("fund sendtoaddress failed: {e}"))?
            .as_str()
            .ok_or("no txid")?
            .to_string();
        let miner = rpc
            .call("getnewaddress", &[serde_json::json!("")])
            .map_err(|e| e.to_string())?;
        let _: serde_json::Value = rpc
            .call(
                "generatetoaddress",
                &[serde_json::json!(1), serde_json::json!(miner)],
            )
            .map_err(|e| e.to_string())?;
        println!("  funded:       {fund_sat} sats → {group_addr} (txid {txid}, 1 conf)");
    }

    // 4. Find the live coin(s) paying the group address. Multi-input
    //    consolidation (--min-inputs N) selects the LARGEST N live coins
    //    (psbt-live discipline) and fails closed when fewer exist; the
    //    default spends the single largest coin.
    let want = min_inputs.unwrap_or(1);
    let utxo_info = rpc
        .scan_utxos_for_address(&group_addr.to_string(), 10_000)
        .map_err(|e| format!("UTXO scan failed: {e}"))?;
    if utxo_info.is_empty() {
        return Err(format!(
            "no live UTXO pays {group_addr} — fund it first (--fund-sat or sendtoaddress + 1 conf)"
        ));
    }
    if utxo_info.len() < want {
        return Err(format!(
            "--min-inputs {want} unreachable: only {} live coin(s) pay {group_addr} — fund more first (fail-closed)",
            utxo_info.len()
        ));
    }
    let mut utxo_info = utxo_info;
    utxo_info.sort_by_key(|(_, a)| std::cmp::Reverse(*a));
    utxo_info.truncate(want);
    let total_in: Amount = utxo_info.iter().map(|(_, a)| *a).sum();
    let prevouts: Vec<bitcoin::TxOut> = utxo_info
        .iter()
        .map(|(_, a)| bitcoin::TxOut {
            value: *a,
            script_pubkey: p2tr_spk(group_x),
        })
        .collect();
    for (op, a) in &utxo_info {
        println!("  live UTXO:    {op} · {} sats", a.to_sat());
    }
    println!(
        "  inputs:       {} coin(s) · {} sats total (largest-first)",
        utxo_info.len(),
        total_in.to_sat()
    );

    // 5. Build the key-path spend (scriptSig empty, witness = 64-byte sig).
    let dest_key: XOnlyPublicKey = match destination {
        Some(hex_key) => {
            let bytes = hex::decode(hex_key)
                .map_err(|_| "--destination must be 64 hex chars".to_string())?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| "--destination must be 64 hex chars".to_string())?;
            XOnlyPublicKey::from_slice(&arr)
                .map_err(|_| "--destination is not a valid x-only pubkey".to_string())?
        }
        None => demo_keys::recovery_key(),
    };
    let dest_output_key = {
        let secp = Secp256k1::verification_only();
        let tweak = bitcoin::taproot::TapTweakHash::from_key_and_tweak(dest_key, None).to_scalar();
        dest_key
            .add_tweak(&secp, &tweak)
            .expect("tweak within curve order (BIP-341)")
            .0
    };
    let fee = Amount::from_sat(fee_sat);
    let out_value = total_in
        .checked_sub(fee)
        .ok_or("fee exceeds the live UTXO value")?;
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: utxo_info
            .iter()
            .map(|(outpoint, _)| bitcoin::TxIn {
                previous_output: *outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            })
            .collect(),
        output: vec![bitcoin::TxOut {
            value: out_value,
            script_pubkey: p2tr_spk(dest_output_key),
        }],
    };
    println!(
        "  spend:        {} sats → dest (key-path, fee {fee_sat})",
        out_value.to_sat()
    );

    // 6. The KEY-PATH sighash (BIP-341): the message every heir signs.
    //    In consolidation mode ALL inputs share the group-key spk, so every
    //    per-input sighash differs only by the input's outpoint/amount — the
    //    ceremony signs over input 0's sighash and the per-input witness
    //    below covers the rest.
    let msg32 = {
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        let prevouts = Prevouts::All(&prevouts);
        let mut cache = SighashCache::new(&tx);
        cache
            .taproot_signature_hash(0, &prevouts, None, None, TapSighashType::Default)
            .map_err(|e| format!("key-path sighash: {e}"))?
            .to_byte_array()
    };
    println!("  sighash:      {}", hex::encode(msg32));

    // 6.5. CO-SIGNER GATE (fail-closed): when a bridge is configured, the
    //    enclave must release a co-signature over THIS sighash before any
    //    heir round may run. The request carries the ML-DSA-65 proof, the
    //    returned signature is verified under the PINNED enclave key, and a
    //    watchtower-frozen vault is refused — the spend aborts here with
    //    NOTHING broadcast and no key material ever leaving the enclave.
    if let Some(bridge_addr) = cosigner {
        let vid = vault_id.expect("pair-checked above");
        println!("  co-signer:    gate {bridge_addr} (vault '{vid}')");
        let sighash = bitcoin::sighash::TapSighash::from_byte_array(msg32);
        let client = qsv_cosigner::BridgeClient::plain(bridge_addr);
        let cs_sig = live_enclave_signature(&client, vid, &sighash, cosigner_pin)?;
        let _ = cs_sig; // verified inside the gate; never placed in the witness
    }

    // 7. RFC 9591 ceremony: the TWEAKED public package pairs with heirs
    //    whose key packages are tweaked by the SAME root (None here). In
    //    consolidation mode the ceremony runs ONCE PER INPUT — each input's
    //    sighash is a distinct FROST message, so the group produces one
    //    aggregated signature per input (k-of-n over every coin, still ONE
    //    broadcast).
    let mut r1s = Vec::new();
    let mut nonces = Vec::new();
    let mut deal_texts = Vec::new();
    for spec in deals {
        let (label, file) = spec
            .split_once('=')
            .ok_or_else(|| format!("--deal must be label=file, got '{spec}'"))?;
        let text = kit_read(std::path::Path::new(file))?;
        let id = hex::encode(qsv_core::frost::deal_identifier(&text).map_err(|e| e.to_string())?);
        println!("  heir:         {label} (id {id}) → round 1");
        let (nonce, cmt) =
            qsv_core::frost::heir_round1_tweaked(&text, &public_text, None, &mut rand_core::OsRng)
                .map_err(|e| e.to_string())?;
        r1s.push(qsv_core::frost::HeirRound1 {
            identifier: qsv_core::frost::deal_identifier(&text).map_err(|e| e.to_string())?,
            commitment: cmt,
        });
        nonces.push(nonce);
        deal_texts.push((id, text));
    }
    let per_input_sighashes: Vec<[u8; 32]> = {
        use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
        (0..tx.input.len())
            .map(|i| {
                SighashCache::new(&tx)
                    .taproot_signature_hash(
                        i,
                        &Prevouts::All(&prevouts),
                        None,
                        None,
                        TapSighashType::Default,
                    )
                    .map_err(|e| format!("key-path sighash [{i}]: {e}"))
                    .map(|h| h.to_byte_array())
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let pkgs: Vec<String> = per_input_sighashes
        .iter()
        .map(|sh| qsv_core::frost::coordinator_sign_package_tagged(sh, &r1s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let mut r2_sets: Vec<Vec<qsv_core::frost::HeirRound2>> = Vec::new();
    for (input_idx, pkg) in pkgs.iter().enumerate() {
        let mut r2s = Vec::new();
        for ((id, text), nonce) in deal_texts.iter().zip(&nonces) {
            let share = qsv_core::frost::heir_round2_tweaked(text, &public_text, nonce, pkg, None)
                .map_err(|e| e.to_string())?;
            let mut idb = [0u8; 32];
            idb.copy_from_slice(&hex::decode(id).map_err(|e| e.to_string())?);
            r2s.push(qsv_core::frost::HeirRound2 {
                identifier: idb,
                share,
            });
        }
        if input_idx == 0 {
            for ((id, _), _) in deal_texts.iter().zip(&nonces) {
                println!("  heir:         id {id} → round 2 share ✓");
            }
        }
        r2_sets.push(r2s);
    }
    let sigs: Vec<[u8; 64]> = pkgs
        .iter()
        .zip(&r2_sets)
        .map(|(pkg, r2s)| qsv_core::frost::coordinator_assemble(pkg, &tweaked_pub, r2s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    for (i, sh) in per_input_sighashes.iter().enumerate() {
        qsv_core::frost::verify_group_signature(
            &Secp256k1::verification_only(),
            &tweaked_group,
            sh,
            &sigs[i],
        )
        .map_err(|e| format!("fail-closed on input {i}: {e}"))?;
    }
    println!(
        "  aggregate:    BIP-340 sig verified under the tweaked group key ✓ ({} input(s))",
        sigs.len()
    );

    // 8. Attach the per-input witnesses and self-verify against the
    //    consensus engine. Every input carries the group's aggregated
    //    signature over ITS sighash (key-path discipline: one 64-byte
    //    BIP-340 sig per input, one ceremony round per input).
    let mut tx = tx;
    for (i, sig) in sigs.iter().enumerate() {
        tx.input[i].witness = {
            let mut w = bitcoin::Witness::new();
            w.push(sig);
            w
        };
    }
    let prevout_list: Vec<(bitcoin::ScriptBuf, Amount)> = utxo_info
        .iter()
        .map(|(_, a)| (p2tr_spk(group_x), *a))
        .collect();
    qsv_core::consensus::verify_transaction(&tx, &prevout_list)
        .map_err(|e| format!("consensus REJECTED the FROST spend: {e}"))?;
    println!(
        "  consensus:    ACCEPT ×{} (libbitcoinconsensus) ✅",
        utxo_info.len()
    );

    // 9. Broadcast — or WATCHTOWER HOLD: serialize and park the transaction.
    //    The hex is deterministic (deterministic devices + fixed fee), so the
    //    coordinator can safely re-derive and broadcast it later; nothing is
    //    ever handed to the mempool in this mode.
    let hex = bitcoin::consensus::encode::serialize_hex(&tx);
    if no_broadcast {
        let hold = dir.join("frost-spend.txhex");
        std::fs::write(&hold, &hex).map_err(|e| format!("cannot write {}: {e}", hold.display()))?;
        println!(
            "  hold:         {} (NOT broadcast — watchtower dry run)",
            hold.display()
        );
        println!("\nFROST SPEND: ceremony verified, transaction HELD (watchtower mode). 🛡️");
        return Ok(());
    }
    let txid: bitcoin::Txid = rpc
        .call("sendrawtransaction", &[serde_json::json!(hex)])
        .map_err(|e| format!("mempool REJECTED the transaction: {e}"))?
        .as_str()
        .ok_or("node returned no txid")?
        .parse()
        .map_err(|e| format!("node returned a bad txid: {e}"))?;
    println!("  broadcast:    mempool ACCEPTED · txid {txid}");
    println!("\nFROST SPEND: k-of-n threshold → ONE plain BIP-340 spend. 🛡️");
    Ok(())
}

/// Base64 wire form of a PSBT (BIP-174 standard transport).
fn psbt_base64(psbt: &bitcoin::psbt::Psbt) -> String {
    use bitcoin::base64::Engine as _;
    bitcoin::base64::engine::general_purpose::STANDARD.encode(psbt.serialize())
}

fn psbt_read(path: &std::path::Path) -> Result<bitcoin::psbt::Psbt, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    use bitcoin::base64::Engine as _;
    let bytes = bitcoin::base64::engine::general_purpose::STANDARD
        .decode(text.trim().as_bytes())
        .map_err(|e| format!("{} is not valid base64: {e}", path.display()))?;
    bitcoin::psbt::Psbt::deserialize(&bytes).map_err(|e| format!("malformed PSBT: {e}"))
}

fn psbt_write(path: &std::path::Path, psbt: &bitcoin::psbt::Psbt) -> Result<(), String> {
    std::fs::write(path, psbt_base64(psbt))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

// ─── SD-card hardware round trip (Phase 1 Coldcard/Ledger rehearsal) ───

/// File hash for the SD-card manifest (hex).
fn file_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// BIP-174 compliance audit against what air-gapped signers REQUIRE
/// (Coldcard/Ledger class; coldcard.com/docs/psbt + multisig guidance):
///   1. every input carries a witness_utxo (devices refuse to sign when
///      absent — they cannot display amounts or compute BIP-341 sighashes);
///   2. every input carries the full taproot context (tap_internal_key,
///      tap_scripts, tap_merkle_root) so the device can re-derive Q and
///      show the script path being signed;
///   3. a non-empty tap leaf script exists (nothing to sign otherwise);
///   4. sighash type is explicit (devices dislike implicit Default).
fn coldcard_compliance_report(psbt: &bitcoin::psbt::Psbt) -> Result<(), String> {
    let mut problems = Vec::new();
    for (i, inp) in psbt.inputs.iter().enumerate() {
        if inp.witness_utxo.is_none() {
            problems.push(format!(
                "input {i}: witness_utxo missing (device cannot sign)"
            ));
        }
        if inp.tap_internal_key.is_none() {
            problems.push(format!("input {i}: tap_internal_key missing"));
        }
        if inp.tap_scripts.is_empty() {
            problems.push(format!("input {i}: tap_scripts missing (no leaf to sign)"));
        }
        if inp.tap_merkle_root.is_none() {
            problems.push(format!(
                "input {i}: tap_merkle_root missing (device cannot re-derive Q for a script path)"
            ));
        }
    }
    for inp in &psbt.inputs {
        if inp.sighash_type.is_none() {
            problems.push("sighash_type implicit (set SIGHASH_DEFAULT explicitly)".to_string());
            break;
        }
    }
    if problems.is_empty() {
        println!("  coldcard:     COMPLIANT (witness_utxo + tap context + explicit sighash) ✓");
        Ok(())
    } else {
        Err(format!(
            "fail-closed: PSBT is NOT air-gap-signer compliant: {}",
            problems.join("; ")
        ))
    }
}

/// SD-CARD EXPORT: one PSBT → the Coldcard/Ledger air-gapped trio
/// (`<stem>.psbt` binary, `<stem>.sha256` manifest, `<stem>.txt` audit sheet).
fn psbt_export(input: &std::path::Path, stem: &std::path::Path) -> Result<(), String> {
    println!("\n───── [10] PSBT · SD-CARD EXPORT (BIP-174 file trio) ──────────");
    let psbt = psbt_read(input)?;
    coldcard_compliance_report(&psbt)?;
    let binary = psbt.serialize();

    // 1. The binary PSBT the device consumes (BIP-174 wire bytes).
    let card = stem.with_extension("psbt");
    std::fs::write(&card, &binary).map_err(|e| format!("cannot write {}: {e}", card.display()))?;

    // 2. The integrity manifest the coordinator re-verifies on import.
    let manifest = stem.with_extension("sha256");
    let digest = file_sha256_hex(&binary);
    std::fs::write(&manifest, format!("{digest}  {}\n", card.display()))
        .map_err(|e| format!("cannot write {}: {e}", manifest.display()))?;

    // 3. The human-readable audit sheet: what the signer is about to
    //    approve (inputs, values, destinations, per-input sighashes).
    let mut sheet = String::new();
    sheet.push_str("QuantumSafe-Vault PSBT audit sheet\n");
    sheet.push_str("====================================\n");
    sheet.push_str(&format!("inputs:   {}\n", psbt.inputs.len()));
    sheet.push_str(&format!("outputs:  {}\n", psbt.outputs.len()));
    let tx = &psbt.unsigned_tx;
    for (i, txin) in tx.input.iter().enumerate() {
        let value = psbt.inputs[i]
            .witness_utxo
            .as_ref()
            .map(|o| o.value.to_sat())
            .unwrap_or(0);
        sheet.push_str(&format!(
            "  in {i}:  {} · {value} sats\n",
            txin.previous_output
        ));
    }
    for (i, txout) in tx.output.iter().enumerate() {
        sheet.push_str(&format!(
            "  out {}: {} sats · spk {}…\n",
            i,
            txout.value.to_sat(),
            hex::encode(&txout.script_pubkey.as_bytes()[..8.min(txout.script_pubkey.len())])
        ));
    }
    for i in 0..psbt.inputs.len() {
        sheet.push_str(&format!(
            "  sighash[{i}]: see device display (BIP-341 taproot)\n"
        ));
    }
    sheet.push_str(&format!("file sha256: {digest}\n"));
    let sheet_path = stem.with_extension("txt");
    std::fs::write(&sheet_path, &sheet)
        .map_err(|e| format!("cannot write {}: {e}", sheet_path.display()))?;

    println!(
        "  card:         {} ({} bytes, BIP-174 binary)",
        card.display(),
        binary.len()
    );
    println!("  manifest:     {} (sha256)", manifest.display());
    println!("  sheet:        {} (human audit)", sheet_path.display());
    println!("\nSD-CARD EXPORT: hand the card to the hardware wallet. 🛡️");
    Ok(())
}

/// SD-CARD IMPORT: device-returned binary PSBT → manifest check → per-input
/// signature verification under the KNOWN leaf keys → witness assembly →
/// libbitcoinconsensus verdict. Fail-closed at every step.
fn psbt_import(
    input: &std::path::Path,
    manifest: Option<&std::path::Path>,
    out: &std::path::Path,
) -> Result<(), String> {
    println!("\n───── [10] PSBT · SD-CARD IMPORT (verify + finalize) ──────────");
    let binary =
        std::fs::read(input).map_err(|e| format!("cannot read {}: {e}", input.display()))?;

    // 1. Optional manifest check (a device may rewrite the file; then the
    //    operator passes --manifest pointing at the new digest).
    if let Some(mpath) = manifest {
        let text = std::fs::read_to_string(mpath)
            .map_err(|e| format!("cannot read {}: {e}", mpath.display()))?;
        let expected = text
            .split_whitespace()
            .next()
            .ok_or_else(|| format!("{}: empty manifest", mpath.display()))?;
        let actual = file_sha256_hex(&binary);
        if expected != actual {
            return Err(format!(
                "fail-closed: manifest mismatch — expected {expected}, got {actual}"
            ));
        }
        println!("  manifest:     OK (sha256 {actual})");
    }

    // 2. Strict BIP-174 parse of the returned bytes — accepting BOTH the
    //    exported base64 form and the raw wire bytes a real device writes
    //    (and Coldcard's <TXID>.txn final form, which is raw tx hex).
    let psbt = if binary.starts_with(b"psbt\xff") {
        bitcoin::psbt::Psbt::deserialize(&binary)
            .map_err(|e| format!("fail-closed: malformed PSBT from device: {e}"))?
    } else {
        // Either base64 (our export form) or hex — try base64, then hex tx.
        let text = String::from_utf8_lossy(&binary);
        let trimmed = text.trim();
        use bitcoin::base64::Engine as _;
        let decoded = bitcoin::base64::engine::general_purpose::STANDARD
            .decode(trimmed.as_bytes())
            .ok()
            .filter(|b| b.starts_with(b"psbt\xff"))
            .or_else(|| {
                // Coldcard's finalized <TXID>.txn: hex raw transaction.
                use bitcoin::consensus::Decodable;
                hex::decode(trimmed).ok().and_then(|raw| {
                    bitcoin::Transaction::consensus_decode_from_finite_reader(
                        &mut std::io::Cursor::new(&raw),
                    )
                    .ok()
                    .and_then(|tx| bitcoin::psbt::Psbt::from_unsigned_tx(tx).ok())
                    .map(|p| p.serialize())
                })
            })
            .ok_or_else(|| {
                "fail-closed: file is neither a binary PSBT, base64 PSBT nor a hex transaction"
                    .to_string()
            })?;
        bitcoin::psbt::Psbt::deserialize(&decoded)
            .map_err(|e| format!("fail-closed: malformed PSBT from device: {e}"))?
    };
    println!(
        "  parse:        {} inputs · {} outputs (BIP-174 OK)",
        psbt.inputs.len(),
        psbt.outputs.len()
    );

    // 3. Verify EVERY stored tap script-sig under the KNOWN leaf keys.
    //    The vault identity is re-derived from protocol constants; a forged
    //    signature (or a PSBT from a different vault) cannot pass.
    let vault = demo_vault()?;
    let leaf = vault.leaves.normal.clone();
    let secp = Secp256k1::verification_only();
    let devices: Vec<(XOnlyPublicKey, &str)> = vec![
        (demo_keys::user_key(), "user"),
        (
            qsv_pqc::enclave_xonly_public_key(
                &qsv_pqc::enclave_keypair_from_seed(&DEMO_ENCLAVE_SEED)
                    .map_err(|e| e.to_string())?,
            ),
            "enclave",
        ),
    ];
    let mut verified = 0usize;
    for idx in 0..psbt.inputs.len() {
        for (pk, name) in &devices {
            let Some(sig) = psbt.inputs[idx]
                .tap_script_sigs
                .iter()
                .find(|((x, _), _)| x == pk)
                .map(|(_, s)| *s)
            else {
                return Err(format!(
                    "fail-closed: input {idx} has NO {name} tap script-sig (device returned an incomplete PSBT)"
                ));
            };
            let sig64: [u8; 64] = *sig.signature.as_ref();
            qsv_core::psbt::verify_device_signature_multi(&secp, *pk, &psbt, idx, &leaf, &sig64)
                .map_err(|e| {
                    format!("fail-closed: {name} signature on input {idx} does NOT verify: {e}")
                })?;
            verified += 1;
        }
    }
    println!("  signatures:   {verified} tap script-sigs verified under leaf keys ✓");

    // 4. Witness assembly (script checks <pk_user> first → [σ_enclave, σ_user])
    //    and the consensus verdict.
    let control = vault
        .spend_info
        .control_block(&(leaf.clone(), bitcoin::taproot::LeafVersion::TapScript))
        .ok_or("control block missing for the normal leaf")?;
    let user_x = demo_keys::user_key();
    let enclave_x = qsv_pqc::enclave_xonly_public_key(
        &qsv_pqc::enclave_keypair_from_seed(&DEMO_ENCLAVE_SEED).map_err(|e| e.to_string())?,
    );
    let exec_order = [enclave_x, user_x];
    let witnesses: Vec<bitcoin::Witness> = (0..psbt.inputs.len())
        .map(|i| qsv_core::psbt::assemble_witness_for_input(&psbt, i, &leaf, &control, &exec_order))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let prevouts: Vec<(bitcoin::ScriptBuf, Amount)> = psbt
        .inputs
        .iter()
        .zip(&psbt.unsigned_tx.input)
        .map(|(i, txin)| {
            let utxo = i
                .witness_utxo
                .as_ref()
                .ok_or_else(|| format!("input {} has no witness_utxo", txin.previous_output))?;
            Ok((utxo.script_pubkey.clone(), utxo.value))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut final_psbt = psbt;
    let tx = qsv_core::psbt::finalize_multi_input_and_extract(&mut final_psbt, witnesses)
        .map_err(|e| format!("fail-closed: cannot finalize: {e}"))?;
    qsv_core::consensus::verify_transaction(&tx, &prevouts)
        .map_err(|e| format!("fail-closed: consensus REJECTED the device transaction: {e}"))?;
    psbt_write(out, &final_psbt)?;
    println!("  consensus:    ACCEPT (libbitcoinconsensus) ✅");
    println!("  final:        wrote {}", out.display());
    println!("\nSD-CARD IMPORT: device transaction verified end-to-end. 🛡️");
    Ok(())
}

/// PSBT build: unsigned vault PSBT with full script-path context.
fn psbt_build(out: &std::path::Path) -> Result<(), String> {
    println!("\n───── [10] PSBT · BUILD (BIP-174 + BIP-371 unsigned) ────────────");
    let vault = demo_vault()?;
    let control = vault
        .spend_info
        .control_block(&(
            vault.leaves.normal.clone(),
            bitcoin::taproot::LeafVersion::TapScript,
        ))
        .ok_or("control block missing for the normal leaf")?;
    let input = qsv_core::psbt::VaultPsbtInput {
        outpoint: bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array(PSBT_DEMO_TXID), 0),
        prev_value: Amount::from_sat(150_000),
        prev_script_pubkey: p2tr_spk(vault.output_key()),
        leaf_script: vault.leaves.normal.clone(),
        control_block: control.clone(),
        merkle_root: vault.merkle_root(),
        sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
    };
    let outputs = vec![bitcoin::TxOut {
        value: Amount::from_sat(148_500),
        script_pubkey: unvault::staging_script(demo_keys::recovery_key()),
    }];
    let psbt = qsv_core::psbt::build_unsigned_psbt(&input, outputs, vault.internal_key)
        .map_err(|e| e.to_string())?;
    psbt_write(out, &psbt)?;

    println!(
        "  vault address ({}): {}",
        "regtest".to_uppercase(),
        vault.address(bitcoin::Network::Regtest)
    );
    println!("  input: demo outpoint · 150,000 sats → staging (148,500 sats + fee)");
    println!(
        "  leaf 1 (hybrid 2-of-2): script {} B · control {} B",
        vault.leaves.normal.len(),
        control.size()
    );
    println!("  BIP-371 fields: witness_utxo ✓ · tap_internal_key ✓ · tap_scripts ✓");
    println!("  wrote {}", out.display());
    println!(
        "  next: qsv-cli psbt sign --in {} --out vault-signed.psbt",
        out.display()
    );
    Ok(())
}

/// PSBT sign: both devices sign the sighash THEY compute from the PSBT.
fn psbt_sign(input: &std::path::Path, out: &std::path::Path) -> Result<(), String> {
    println!("\n───── [10] PSBT · DEVICE SIGN (2 hardware slots) ────────────────");
    let mut psbt = psbt_read(input)?;
    let vault = demo_vault()?;
    let leaf = vault.leaves.normal.clone();
    let leaf_hash =
        bitcoin::taproot::TapLeafHash::from_script(&leaf, bitcoin::taproot::LeafVersion::TapScript);
    let secp = Secp256k1::verification_only();

    let enclave_kp =
        qsv_pqc::enclave_keypair_from_seed(&DEMO_ENCLAVE_SEED).map_err(|e| e.to_string())?;
    let enclave_x = qsv_pqc::enclave_xonly_public_key(&enclave_kp);
    let devices: Vec<(&str, bitcoin::secp256k1::Keypair, XOnlyPublicKey)> = vec![
        (
            "slot 1 · user hardware wallet",
            demo_keys::user_keypair(),
            demo_keys::user_key(),
        ),
        ("slot 2 · enclave co-signer", enclave_kp, enclave_x),
    ];

    for (name, kp, pk) in devices {
        let sig =
            qsv_core::psbt::device_sign_input(&psbt, 0, &leaf, &kp).map_err(|e| e.to_string())?;
        let sighash =
            qsv_core::psbt::sighash_for_psbt_input(&psbt, 0, &leaf).map_err(|e| e.to_string())?;
        let s64: [u8; 64] = sig[..64].try_into().map_err(|_| "short signature")?;
        // Coordinator refuses anything that does not verify under the leaf key.
        qsv_core::psbt::verify_device_signature(&secp, pk, &sighash, &s64)
            .map_err(|e| e.to_string())?;
        let signature =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&s64).map_err(|e| e.to_string())?;
        psbt.inputs[0].tap_script_sigs.insert(
            (pk, leaf_hash),
            bitcoin::taproot::Signature {
                signature,
                sighash_type: bitcoin::sighash::TapSighashType::Default,
            },
        );
        println!("  {name}: BIP-341 sighash signed & verified ✓");
    }
    psbt_write(out, &psbt)?;
    println!("  wrote {}", out.display());
    println!(
        "  next: qsv-cli psbt finish --in {} --out vault-final.psbt",
        out.display()
    );
    Ok(())
}

/// PSBT finish: assemble the witness in script order, extract the tx and let
/// libbitcoinconsensus judge it.
/// Witness order from the leaf's key positions: the key the script
/// checks FIRST ends on TOP of the stack (pushed last). Pure so both
/// orders are testable — the demo leaf fixes one of them.
fn witness_order<'a, T>(
    pos_user: usize,
    pos_enclave: usize,
    user: &'a T,
    enclave: &'a T,
) -> (&'a T, &'a T) {
    if pos_user < pos_enclave {
        (enclave, user)
    } else {
        (user, enclave)
    }
}

fn psbt_finish(input: &std::path::Path, out: &std::path::Path) -> Result<(), String> {
    println!("\n───── [10] PSBT · FINALIZE + CONSENSUS VERIFY ──────────────────");
    let mut psbt = psbt_read(input)?;
    let vault = demo_vault()?;
    let leaf = vault.leaves.normal.clone();
    let leaf_hash =
        bitcoin::taproot::TapLeafHash::from_script(&leaf, bitcoin::taproot::LeafVersion::TapScript);
    let control = vault
        .spend_info
        .control_block(&(leaf.clone(), bitcoin::taproot::LeafVersion::TapScript))
        .ok_or("control block missing for the normal leaf")?;
    let enclave_kp =
        qsv_pqc::enclave_keypair_from_seed(&DEMO_ENCLAVE_SEED).map_err(|e| e.to_string())?;
    let user_x = demo_keys::user_key();
    let enclave_x = qsv_pqc::enclave_xonly_public_key(&enclave_kp);

    let sigs = psbt.inputs[0].tap_script_sigs.clone();
    let user_sig = sigs
        .get(&(user_x, leaf_hash))
        .ok_or("missing slot-1 (user) signature — run `psbt sign` first")?;
    let enclave_sig = sigs
        .get(&(enclave_x, leaf_hash))
        .ok_or("missing slot-2 (enclave) signature — run `psbt sign` first")?;

    // The key checked FIRST by the script needs its signature on TOP of the
    // stack, i.e. pushed LAST in the witness element order.
    let script_bytes = leaf.as_bytes();
    let pos = |k: XOnlyPublicKey| {
        script_bytes
            .windows(32)
            .position(|w| w == k.serialize())
            .unwrap_or(usize::MAX)
    };
    let (bottom, top) = witness_order(pos(user_x), pos(enclave_x), user_sig, enclave_sig);
    println!("  witness order: script-key order derived from the leaf bytes ✓");

    let witness = qsv_core::psbt::assemble_witness(
        &[
            bottom.signature.serialize().to_vec(),
            top.signature.serialize().to_vec(),
        ],
        &leaf,
        &control,
    );
    let utxo = psbt.inputs[0]
        .witness_utxo
        .clone()
        .ok_or("PSBT carries no witness_utxo")?;
    let tx = qsv_core::psbt::finalize_and_extract(&mut psbt, witness).map_err(|e| e.to_string())?;
    qsv_core::consensus::verify_input(&tx, 0, &utxo.script_pubkey, utxo.value)
        .map_err(|e| format!("consensus REJECTED the extracted transaction: {e}"))?;
    psbt_write(out, &psbt)?;

    println!("  consensus engine:  ACCEPT (libbitcoinconsensus) ✅");
    println!("  txid:              {}", tx.compute_txid());
    println!("  witness elements:  {}", tx.input[0].witness.len());
    println!(
        "  signed tx hex:     {}",
        bitcoin::consensus::encode::serialize_hex(&tx)
    );
    println!("  wrote {}", out.display());
    Ok(())
}

// ───────────────── Inheritance kit: FROST + SLIP-0039 wizard ─────────────────

fn kit_write(dir: &std::path::Path, name: &str, text: &str) -> Result<std::path::PathBuf, String> {
    let path = dir.join(name);
    std::fs::write(&path, text.trim_end())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}

fn kit_read(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn kit_parse_tagged(spec: &str, what: &str) -> Result<(String, std::path::PathBuf), String> {
    let (id, file) = spec
        .split_once(':')
        .ok_or_else(|| format!("--{what} must be <id-hex>:<file>, got '{spec}'"))?;
    let id = id.trim().to_lowercase();
    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "--{what} identifier must be 64 hex chars, got '{id}'"
        ));
    }
    Ok((id, std::path::PathBuf::from(file.trim())))
}

/// Wizard step 1 (docs/04 §4.1 + §4.2): key setup — trusted-dealer by
/// default, or `--dkg` for RFC 9591 joint generation with NO dealer. Both
/// modes derive the GROUP key, write the coordinator's public package and
/// each heir's private deal, and print every heir's signing share as
/// SLIP-0039 mnemonics (printed words, never files). The passphrase is
/// never echoed.
fn kit_setup(
    threshold: u16,
    heirs: &[String],
    slip_threshold: u8,
    slip_shares: u8,
    passphrase: &str,
    dir: &std::path::Path,
    dkg: bool,
) -> Result<(), String> {
    println!("\n───── [12] INHERITANCE KIT · FROST SETUP (k-of-n) ───────────────");
    if heirs.is_empty() {
        return Err("at least one --heir label is required".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    let out = if dkg {
        println!("  keygen:       DKG — RFC 9591 three rounds, NO TRUSTED DEALER;");
        println!("                no machine ever sees a full signature share alone");
        qsv_core::frost::dkg_rehearsal(threshold, heirs, &mut rand_core::OsRng)
    } else {
        qsv_core::frost::trusted_deal(threshold, heirs, &mut rand_core::OsRng)
    }
    .map_err(|e| e.to_string())?;
    let group = hex::encode(out.group_key);
    println!("  threshold:    {threshold}-of-{}", out.slots.len());
    println!("  group key:    {group}");
    println!("  (x-only BIP-340 aggregate key — the vault leaf commits to it)\n");

    let public = kit_write(dir, "public-package.txt", &out.public_package)?;
    println!("  coordinator:  {} (public)", public.display());

    for (i, (slot, deal)) in out.slots.iter().zip(&out.private_packages).enumerate() {
        let id = hex::encode(slot.identifier);
        let deal_path = kit_write(dir, format!("heir-{i:02}-{id}-deal.txt").as_str(), deal)?;
        let mnemonics =
            qsv_core::frost::seal_share_as_slip39(deal, slip_threshold, slip_shares, passphrase)
                .map_err(|e| e.to_string())?;
        println!("  heir {i:02} · {} (id {id}):", slot.label);
        println!(
            "    deal file:  {}  ← keep OFFLINE, it is the signing share",
            deal_path.display()
        );
        for (mi, m) in mnemonics.iter().enumerate() {
            println!("    SLIP-0039 {}/{}: {m}", mi + 1, mnemonics.len());
        }
    }
    println!(
        "\n  {slip_threshold}-of-{slip_shares} mnemonics reconstitute ONE heir's deal (qsv-cli"
    );
    println!("  inheritance-kit recover-check round-trips them before you rely on them).");
    println!("  Spend ceremony: heir-round-1 → build-sign-pkg → heir-round-2 → finish.");
    println!("\nInheritance kit: SETUP COMPLETE. 🛡️");
    Ok(())
}

/// Backup drill: k printed mnemonics must reproduce the heir's exact
/// signing share (fail-closed; exit 1 otherwise).
fn kit_recover_check(
    deal: &std::path::Path,
    shares: &[String],
    passphrase: &str,
) -> Result<(), String> {
    println!("\n───── [12] INHERITANCE KIT · SLIP-0039 RECOVER CHECK ───────────");
    let deal_text = kit_read(deal)?;
    let expected = qsv_core::frost::deal_signing_scalar(&deal_text).map_err(|e| e.to_string())?;
    let refs: Vec<&str> = shares.iter().map(String::as_str).collect();
    let recovered =
        qsv_core::frost::recover_share_from_slip39(&refs, passphrase).map_err(|e| e.to_string())?;
    if recovered != expected {
        return Err(
            "recovered share does NOT match the deal — wrong mnemonics, wrong passphrase, or wrong deal file".into(),
        );
    }
    println!("  mnemonics:    {} → signing share RECOVERED ✓", refs.len());
    println!("\nBackup drill: PASS — these printed words restore this heir's deal. 🛡️");
    Ok(())
}

/// Wizard step 2 (heir, offline): single-use nonces → commitment package.
fn kit_heir_round1(
    deal: &std::path::Path,
    public: &std::path::Path,
    dir: &std::path::Path,
) -> Result<(), String> {
    println!("\n───── [12] INHERITANCE KIT · HEIR ROUND 1 (nonces) ─────────────");
    let deal_text = kit_read(deal)?;
    let public_text = kit_read(public)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let id = hex::encode(qsv_core::frost::deal_identifier(&deal_text).map_err(|e| e.to_string())?);
    let (nonce, commitment) =
        qsv_core::frost::heir_round1(&deal_text, &public_text, &mut rand_core::OsRng)
            .map_err(|e| e.to_string())?;
    let nonce_path = kit_write(dir, format!("heir-{id}-nonce.txt").as_str(), &nonce)?;
    let cmt_path = kit_write(dir, format!("heir-{id}-r1.txt").as_str(), &commitment)?;
    println!("  heir id:      {id}");
    println!(
        "  nonce file:   {}  ← SECRET, single use",
        nonce_path.display()
    );
    println!(
        "  commitment:   {}  → hand to the coordinator",
        cmt_path.display()
    );
    println!("\nHeir round 1: COMPLETE. 🛡️");
    Ok(())
}

/// Wizard step 3 (coordinator): round-2 signing package from ≥ k round-1
/// commitments over one 32-byte message (e.g. a BIP-341 sighash).
fn kit_build_sign_pkg(
    message: &str,
    commitments: &[String],
    out: &std::path::Path,
) -> Result<(), String> {
    println!("\n───── [12] INHERITANCE KIT · BUILD SIGN PACKAGE ────────────────");
    let msg_bytes = hex::decode(message)
        .map_err(|_| "--message must be 64 hex chars (32 bytes)".to_string())?;
    let msg32: [u8; 32] = msg_bytes
        .try_into()
        .map_err(|_| "--message must be 64 hex chars (32 bytes)".to_string())?;
    let mut responses = Vec::new();
    for spec in commitments {
        let (id_hex, file) = kit_parse_tagged(spec, "commitment")?;
        let text = kit_read(&file)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&hex::decode(&id_hex).map_err(|e| e.to_string())?);
        responses.push(qsv_core::frost::HeirRound1 {
            identifier: id,
            commitment: text,
        });
    }
    if responses.len() < 2 {
        println!(
            "  note:         {} commitment(s) supplied — must reach the group threshold",
            responses.len()
        );
    }
    let pkg = qsv_core::frost::coordinator_sign_package_tagged(&msg32, &responses)
        .map_err(|e| e.to_string())?;
    kit_write(
        out.parent().unwrap_or(std::path::Path::new(".")),
        out.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("sign-package.txt"),
        &pkg,
    )?;
    println!("  message:      {message}");
    println!("  commitments:  {}", responses.len());
    println!("  wrote         {}", out.display());
    println!("\nSign package: READY — distribute to the signing heirs. 🛡️");
    Ok(())
}

/// Wizard step 4 (heir, offline): sign the coordinator's package.
fn kit_heir_round2(
    deal: &std::path::Path,
    public: &std::path::Path,
    nonce: &std::path::Path,
    pkg: &std::path::Path,
    dir: &std::path::Path,
) -> Result<(), String> {
    println!("\n───── [12] INHERITANCE KIT · HEIR ROUND 2 (share) ─────────────");
    let deal_text = kit_read(deal)?;
    let public_text = kit_read(public)?;
    let nonce_text = kit_read(nonce)?;
    let pkg_text = kit_read(pkg)?;
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let id = hex::encode(qsv_core::frost::deal_identifier(&deal_text).map_err(|e| e.to_string())?);
    let share = qsv_core::frost::heir_round2(&deal_text, &public_text, &nonce_text, &pkg_text)
        .map_err(|e| e.to_string())?;
    let share_path = kit_write(dir, format!("heir-{id}-r2.txt").as_str(), &share)?;
    println!("  heir id:      {id}");
    println!(
        "  share file:   {}  → hand to the coordinator",
        share_path.display()
    );
    println!("\nHeir round 2: COMPLETE (the nonce file is now burnt — never reuse). 🛡️");
    Ok(())
}

/// Wizard step 5 (coordinator): aggregate k shares into the final 64-byte
/// BIP-340 signature and verify it under the GROUP key (fail-closed).
fn kit_finish(
    pkg: &std::path::Path,
    public: &std::path::Path,
    shares: &[String],
) -> Result<(), String> {
    println!("\n───── [12] INHERITANCE KIT · FINISH (aggregate + verify) ───────");
    let pkg_text = kit_read(pkg)?;
    let public_text = kit_read(public)?;
    let group = qsv_core::frost::group_key_of(&public_text).map_err(|e| e.to_string())?;
    let mut r2s = Vec::new();
    for spec in shares {
        let (id_hex, file) = kit_parse_tagged(spec, "share")?;
        let text = kit_read(&file)?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&hex::decode(&id_hex).map_err(|e| e.to_string())?);
        r2s.push(qsv_core::frost::HeirRound2 {
            identifier: id,
            share: text,
        });
    }
    let sig = qsv_core::frost::coordinator_assemble(&pkg_text, &public_text, &r2s)
        .map_err(|e| e.to_string())?;
    let msg32 = qsv_core::frost::sign_package_message(&pkg_text).map_err(|e| e.to_string())?;
    qsv_core::frost::verify_group_signature(&Secp256k1::verification_only(), &group, &msg32, &sig)
        .map_err(|e| format!("fail-closed: {e}"))?;
    println!("  shares:       {}", r2s.len());
    println!("  group key:    {}", hex::encode(group));
    println!("  message:      {}", hex::encode(msg32));
    println!("  BIP-340 sig:  {}", hex::encode(sig));
    println!("\n  The threshold signature verifies as PLAIN Schnorr under the group key");
    println!("  — indistinguishable from a single-signer spend. 🛡️");
    Ok(())
}

/// Documentation audit (docs/10 §4.63, Round 40). The engine lives in
/// `qsv_core::docs` so the walls have ONE home: `docs_sync` asserts them,
/// this command explains them. Drift is a REPORT with an exit code, not a
/// panic: the operator sees which module broke which wall, and a scripted
/// audit can gate on the same verdict.
fn docs_audit_cmd(dir: Option<std::path::PathBuf>, json: bool) -> Result<(), String> {
    let dir = dir.unwrap_or_else(|| {
        std::path::PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs"))
    });
    // A directory we cannot read is a USAGE error (exit 2, empty stdout), not
    // drift: an unreadable tree must never look like a passing report.
    let reports = match qsv_core::docs::report(&dir) {
        Ok(reports) => reports,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    };
    let in_sync = qsv_core::docs::in_sync(&reports);
    let summary = qsv_core::docs::summary_line(&reports);
    if json {
        let modules: Vec<serde_json::Value> = reports
            .iter()
            .map(|r| {
                serde_json::json!({
                    "module": r.module,
                    "file": r.file,
                    "bytes": r.bytes,
                    "words": r.words,
                    "in_sync": r.in_sync(),
                    "drifts": r
                        .drifts
                        .iter()
                        .map(|d| serde_json::json!({"kind": d.kind, "detail": d.detail}))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "dir": dir.display().to_string(),
            "in_sync": in_sync,
            "drift_count": qsv_core::docs::drift_count(&reports),
            "summary": summary,
            "modules": modules,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&doc)
                .map_err(|e| format!("cannot render the audit report as JSON: {e}"))?
        );
    } else {
        print!("{}", qsv_core::docs::render(&reports));
    }
    if in_sync {
        Ok(())
    } else {
        Err(summary)
    }
}

fn bip360_status(online: bool, plan: Option<std::path::PathBuf>) -> Result<(), String> {
    println!("\n───── [11] BIP-360 (P2MR) · K1 DECISION-GATE TRACKER ───────────");
    let plan_path = plan.unwrap_or_else(|| {
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/11_p2mr_migration_plan.md"
        ))
    });
    let doc = std::fs::read_to_string(&plan_path).map_err(|e| {
        format!(
            "cannot read {}: {e} (pass --plan <path>)",
            plan_path.display()
        )
    })?;

    let checks = qsv_core::bip360::audit_plan(&doc);
    for c in &checks {
        println!(
            "  {} {:30} {}",
            if c.ok { "✓" } else { "✗" },
            format!("{}:", c.label),
            c.detail
        );
    }
    let failed = checks.iter().filter(|c| !c.ok).count();
    let snapshot = qsv_core::bip360::parse_snapshot(&doc).map_err(|e| e.to_string())?;

    if !online {
        if failed > 0 {
            return Err(format!(
                "offline audit FAILED ({failed}/{} checks) — docs/11 lost a required element",
                checks.len()
            ));
        }
        println!(
            "\nOFFLINE AUDIT: PASS ({}/{}) · snapshot v{} ({})",
            checks.len(),
            checks.len(),
            snapshot.version,
            snapshot.retrieved
        );
        println!("Re-run with --online to diff the live BIP header.");
        return Ok(());
    }

    if failed > 0 {
        return Err(format!(
            "plan audit FAILED ({failed}/{} checks) — fix docs/11 before trusting the online diff",
            checks.len()
        ));
    }
    // NOTE: there is no second `allowed_source` gate here — the offline
    // audit above already refuses a snapshot whose `source:` is not on the
    // allow-list (pinned by `snapshot_source_allow_list_is_the_only_gate`
    // in the bip360 unit tests); one gate, one truth.
    // The fetch binary is injectable for tests (QSV_CURL); operators never
    // set it — plain `curl` is the default.
    let curl = std::env::var("QSV_CURL").unwrap_or_else(|_| "curl".to_string());
    let out = std::process::Command::new(&curl)
        .args(["-fsSL", "--max-time", "30", &snapshot.source])
        .output()
        .map_err(|e| {
            format!("cannot run curl ({e}); fetch the BIP manually and compare with the snapshot")
        })?;
    if !out.status.success() {
        return Err(format!(
            "fetch failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let text =
        String::from_utf8(out.stdout).map_err(|_| "BIP response is not UTF-8".to_string())?;
    let live =
        qsv_core::bip360::parse_bip_header(&text).map_err(|e| format!("live header: {e}"))?;
    let deltas = qsv_core::bip360::diff(&snapshot, &live);

    println!(
        "\n  {:10} {:22} {:22}",
        "field", "snapshot (docs/11)", "live (bip-0360)"
    );
    let rows: [(&str, &str, &str); 5] = [
        ("status", &snapshot.status, &live.status),
        ("version", &snapshot.version, &live.version),
        ("title", &snapshot.title, &live.title),
        ("assigned", &snapshot.assigned, &live.assigned),
        ("requires", &snapshot.requires, &live.requires),
    ];
    for (name, snap, live_v) in rows {
        let changed = deltas.iter().any(|(f, _, _)| f.as_str() == name);
        println!(
            "  {:10} {:22} {:22} {}",
            name,
            snap,
            live_v,
            if changed { "Δ CHANGED" } else { "match ✓" }
        );
    }
    let (verdict, _open) = qsv_core::bip360::k1_status_verdict(&live.status);
    println!("\n  K1: {verdict}");
    // Round 30 · P3: the second limb is no longer "manual" — the snapshot's
    // audited counter feeds it straight into this report.
    if let Some(n) = qsv_core::bip360::impl_count(&doc) {
        let (impl_verdict, _met) = qsv_core::bip360::k1_impl_verdict(n);
        println!("  K1 impl limb: {impl_verdict} ({n}/2, docs/11 snapshot — offline-audited)");
    }

    if deltas.is_empty() {
        println!(
            "\nONLINE DIFF: PASS — docs/11 matches the live BIP ({}). ✅",
            snapshot.retrieved
        );
        Ok(())
    } else {
        let list = deltas
            .iter()
            .map(|(f, a, b)| format!("{f}: {a} → {b}"))
            .collect::<Vec<_>>()
            .join("; ");
        Err(format!(
            "K1 DELTA: {list} — update the snapshot in docs/11 and re-evaluate the gate"
        ))
    }
}

fn main() {
    let cli = Cli::parse();
    // MACHINE-READABLE OUTPUT (`--json`): stdout must carry exactly ONE
    // JSON document — no banner here, no success footer at the tail —
    // so `qsv-cli doctor --json | jq` works without filtering prose.
    let machine_output = matches!(
        &cli.command,
        Some(Command::Bench { json: true, .. })
            | Some(Command::Doctor { json: true, .. })
            | Some(Command::VaultDescriptor { json: true, .. })
            | Some(Command::Console { json: true, .. })
            | Some(Command::Demo { json: true, .. })
            | Some(Command::DocsAudit { json: true, .. })
    );
    // CAPACITY GATE (docs/10 §4.38): `bench --baseline` validates the
    // baseline BEFORE the first byte of stdout — a refused comparison
    // exits 2 with EMPTY stdout, so the banner may not precede it either.
    // A gate run therefore prints only its verdict report: no frame, no
    // success footer (same discipline as `--json`).
    let gate_output = matches!(
        &cli.command,
        Some(Command::Bench {
            baseline: Some(_),
            ..
        })
    );
    // DOCUMENTATION AUDIT (docs/10 §4.63): the report IS the output — no
    // banner in front of it and no success footer behind it. That is not
    // cosmetic: a refused tree must exit 2 with EMPTY stdout (the bench
    // baseline discipline), and a redirected report must be clean enough to
    // diff between two runs.
    let report_output = matches!(&cli.command, Some(Command::DocsAudit { .. }));
    if !machine_output && !gate_output && !report_output {
        banner();
    }

    let result = match cli.command {
        Some(Command::VaultSetup { network }) => vault_setup(network.into()),
        Some(Command::VaultDescriptor { network, json }) => vault_descriptor(network.into(), json),
        Some(Command::HybridSpendDemo) => hybrid_spend_demo(),
        Some(Command::InheritanceDemo) => inheritance_demo(),
        Some(Command::VaultDashboard {
            datadir,
            network,
            rpc_port,
            tip,
            last_refresh_block,
            watch,
        }) => vault_dashboard(
            datadir,
            network.into(),
            rpc_port,
            tip,
            last_refresh_block,
            watch,
        ),
        Some(Command::Console {
            network,
            tip,
            last_refresh_block,
            label,
            date,
            descriptor,
            out,
            json,
        }) => console_cmd(ConsoleArgs {
            network: network.into(),
            tip,
            last_refresh_block,
            label: &label,
            date: date.as_deref(),
            descriptor: descriptor.as_deref(),
            out: out.as_deref(),
            json,
        }),
        Some(Command::Demo {
            network,
            tip,
            out,
            json,
        }) => demo_cmd(network.into(), tip, out.as_deref(), json),
        Some(Command::EstateLetter {
            network,
            label,
            date,
            qr,
        }) => estate_letter_cmd(network.into(), &label, date.as_deref(), qr),
        Some(Command::LeafBudget { p2mr_delta }) => leaf_budget_cmd(p2mr_delta),
        Some(Command::WotsParams) => wots_params_cmd(),
        Some(Command::KitSeed { action }) => match action {
            KitSeedAction::Split {
                threshold,
                shares,
                format,
                passphrase,
            } => kit_seed_split(threshold, shares, format, &passphrase),
            KitSeedAction::Combine {
                shares,
                format,
                passphrase,
            } => kit_seed_combine(&shares, format, &passphrase),
        },
        Some(Command::Psbt { action }) => match action {
            PsbtAction::Build { out } => psbt_build(&out),
            PsbtAction::Sign { input, out } => psbt_sign(&input, &out),
            PsbtAction::Finish { input, out } => psbt_finish(&input, &out),
            PsbtAction::Export { input, stem } => psbt_export(&input, &stem),
            PsbtAction::Import {
                input,
                manifest,
                out,
            } => psbt_import(&input, manifest.as_deref(), &out),
        },
        Some(Command::PsbtLive {
            datadir,
            rpc_port,
            network,
            destination,
            fee_sat,
            build_only,
            sign_only,
            dir,
            min_inputs,
            p2mr,
            fund_sat,
        }) => psbt_live(
            &datadir,
            rpc_port,
            network.into(),
            destination.as_deref(),
            fee_sat,
            build_only,
            sign_only,
            &dir,
            min_inputs,
            p2mr,
            fund_sat,
        ),
        Some(Command::InheritanceKit { action }) => match action {
            KitAction::Setup {
                threshold,
                heirs,
                dkg,
                slip_threshold,
                slip_shares,
                passphrase,
                dir,
            } => kit_setup(
                threshold,
                &heirs,
                slip_threshold,
                slip_shares,
                &passphrase,
                &dir,
                dkg,
            ),
            KitAction::RecoverCheck {
                deal,
                shares,
                passphrase,
            } => kit_recover_check(&deal, &shares, &passphrase),
            KitAction::HeirRound1 { deal, public, dir } => kit_heir_round1(&deal, &public, &dir),
            KitAction::BuildSignPkg {
                message,
                commitments,
                out,
            } => kit_build_sign_pkg(&message, &commitments, &out),
            KitAction::HeirRound2 {
                deal,
                public,
                nonce,
                pkg,
                dir,
            } => kit_heir_round2(&deal, &public, &nonce, &pkg, &dir),
            KitAction::Finish {
                pkg,
                public,
                shares,
            } => kit_finish(&pkg, &public, &shares),
        },
        Some(Command::FrostSpend {
            public,
            deals,
            datadir,
            rpc_port,
            network,
            fee_sat,
            fund_sat,
            destination,
            dir,
            no_broadcast,
            cosigner,
            vault_id,
            min_inputs,
            cosigner_pcr0,
            cosigner_pcr1,
            cosigner_pcr2,
            cosigner_key,
        }) => {
            let cosigner_pin = match CosignerPin::resolve(
                cosigner.is_some(),
                cosigner_pcr0.as_deref(),
                cosigner_pcr1.as_deref(),
                cosigner_pcr2.as_deref(),
                cosigner_key.as_deref(),
            ) {
                Ok(pin) => pin,
                Err(e) => {
                    eprintln!("usage error: {e}");
                    std::process::exit(2);
                }
            };
            frost_spend(
                &public,
                &deals,
                &datadir,
                rpc_port,
                network.into(),
                fee_sat,
                fund_sat,
                destination.as_deref(),
                &dir,
                no_broadcast,
                cosigner.as_deref(),
                vault_id.as_deref(),
                min_inputs,
                &cosigner_pin,
            )
        }
        Some(Command::Watchtower {
            datadir,
            rpc_port,
            network,
            last_refresh_block,
            deals,
            public,
            dir,
            fund_sat,
            inventory,
            state_dir,
        }) => match inventory {
            Some(inv) => watchtower_multi(
                &datadir,
                rpc_port,
                network.into(),
                &inv,
                &state_dir,
                last_refresh_block != 0 || !deals.is_empty() || public.is_some(),
            ),
            None => watchtower(
                &datadir,
                rpc_port,
                network.into(),
                last_refresh_block,
                &deals,
                public.as_deref(),
                &dir,
                fund_sat,
            ),
        },
        Some(Command::Bip360Status { online, plan }) => bip360_status(online, plan),
        Some(Command::VaultRotate {
            datadir,
            rpc_port,
            network,
            fee_sat,
            heirs,
            no_broadcast,
            dir,
            cosigner,
            cosigner_pcr0,
            cosigner_pcr1,
            cosigner_pcr2,
            cosigner_key,
            inventory,
            vault_id,
            last_refresh_block,
            state_dir,
            all,
            cosigner_all,
            cosigner_all_cert,
            cosigner_all_key,
            cosigner_all_ca,
            dry_run,
        }) => {
            let cosigner_pin = match CosignerPin::resolve(
                cosigner.is_some() || cosigner_all.is_some(),
                cosigner_pcr0.as_deref(),
                cosigner_pcr1.as_deref(),
                cosigner_pcr2.as_deref(),
                cosigner_key.as_deref(),
            ) {
                Ok(pin) => pin,
                Err(e) => {
                    eprintln!("usage error: {e}");
                    std::process::exit(2);
                }
            };
            if all {
                // Usage confusion is exit 2 per the CLI contract (docs/10 §1):
                // the sweep drives the whole inventory; single-vault options
                // would silently apply to only ONE of the swept vaults.
                if vault_id.is_some()
                    || last_refresh_block.is_some()
                    || !heirs.is_empty()
                    || no_broadcast
                {
                    eprintln!(
                        "usage error: --all sweeps the whole inventory — the single-vault options --vault-id/--last-refresh-block/--heir/--no-broadcast do not apply"
                    );
                    std::process::exit(2);
                }
                let inv = inventory
                    .as_deref()
                    .expect("clap requires --inventory with --all");
                vault_rotate_batch(
                    &datadir,
                    rpc_port,
                    network.into(),
                    fee_sat,
                    &dir,
                    cosigner.as_deref(),
                    cosigner_all.as_deref(),
                    cosigner_all_cert.as_deref(),
                    cosigner_all_key.as_deref(),
                    cosigner_all_ca.as_deref(),
                    dry_run,
                    inv,
                    &state_dir,
                    &cosigner_pin,
                )
            } else {
                // The CLI contract is exit-code based: the sweep-internal
                // (tip, txid) outcome is flattened to () here. The single-
                // vault --cosigner endpoint speaks plain TCP (loopback).
                let cosigner_client = cosigner.as_deref().map(qsv_cosigner::BridgeClient::plain);
                vault_rotate(
                    &datadir,
                    rpc_port,
                    network.into(),
                    fee_sat,
                    &heirs,
                    no_broadcast,
                    &dir,
                    cosigner_client.as_ref(),
                    &cosigner_pin,
                    inventory.as_deref(),
                    vault_id.as_deref(),
                    last_refresh_block,
                    &state_dir,
                )
                .map(|_| ())
            }
        }
        Some(Command::CosignerBridge {
            listen,
            state_dir,
            watchtower,
            watchtower_quorum,
            vault_ids,
            tls_cert,
            tls_key,
            tls_client_ca,
            rate_limit,
            frame_timeout_ms,
            drain_timeout_ms,
            metrics_token,
            metrics_token_file,
            max_inflight,
            dry_run,
        }) => {
            if tls_cert.is_some() != tls_key.is_some() {
                eprintln!("usage error: --tls-cert and --tls-key must be given together");
                std::process::exit(2);
            }
            if tls_client_ca.is_some() && tls_cert.is_none() {
                eprintln!("usage error: --tls-client-ca requires the --tls-cert/--tls-key pair");
                std::process::exit(2);
            }
            cosigner_bridge(
                &listen,
                &state_dir,
                &watchtower,
                watchtower_quorum,
                &vault_ids,
                tls_cert.as_deref(),
                tls_key.as_deref(),
                tls_client_ca.as_deref(),
                rate_limit.as_deref(),
                frame_timeout_ms,
                drain_timeout_ms,
                metrics_token,
                metrics_token_file.as_deref(),
                max_inflight,
                dry_run,
            )
        }
        Some(Command::CosignerBridgeInstall {
            listen,
            state_dir,
            watchtower,
            watchtower_quorum,
            vault_ids,
            unit_dir,
            timer_calendar,
            unit_name,
            tls_cert,
            tls_key,
            tls_client_ca,
            rate_limit,
            metrics_token,
            metrics_token_file,
            frame_timeout_ms,
            drain_timeout_ms,
            max_inflight,
        }) => cosigner_bridge_install(
            &listen,
            &state_dir,
            &watchtower,
            watchtower_quorum,
            &vault_ids,
            unit_dir.as_deref(),
            &timer_calendar,
            &unit_name,
            tls_cert.as_deref(),
            tls_key.as_deref(),
            tls_client_ca.as_deref(),
            rate_limit.as_deref(),
            metrics_token.as_deref(),
            metrics_token_file.as_deref(),
            frame_timeout_ms,
            drain_timeout_ms,
            max_inflight,
        ),
        Some(Command::Doctor {
            datadir,
            network,
            state_dir,
            bridge,
            metrics_token,
            metrics_token_file,
            max_mirror_lag,
            rpc_port,
            json,
        }) => doctor(
            &datadir,
            network.into(),
            &state_dir,
            bridge.as_deref(),
            metrics_token.as_deref(),
            metrics_token_file.as_deref(),
            max_mirror_lag,
            rpc_port,
            json,
        ),
        Some(Command::VerifyEstate { file, network }) => verify_estate_cmd(&file, network.into()),
        Some(Command::Bench {
            iterations,
            json,
            baseline,
            baseline_tolerance_pct,
        }) => bench(
            iterations,
            json,
            baseline.as_deref(),
            baseline_tolerance_pct,
        ),
        Some(Command::DocsAudit { dir, json }) => docs_audit_cmd(dir, json),
        Some(Command::Constants) => {
            constants();
            Ok(())
        }
        None => {
            // Default: run all demos in sequence.
            vault_setup(bitcoin::Network::Bitcoin)
                .and_then(|_| hybrid_spend_demo())
                .and_then(|_| inheritance_demo())
        }
    };

    match result {
        Ok(()) if machine_output || gate_output || report_output => {
            // The JSON document already ended stdout (and the `--json`
            // paths exit(0) themselves; this arm is the backstop). A
            // baseline gate run ends on its own verdict line instead of
            // the demo footer.
        }
        Ok(()) => println!("\nAll operations completed successfully. 🛡️"),
        Err(e) => {
            eprintln!("\nerror: {e}");
            std::process::exit(1);
        }
    }
}

// ────────────────────── Round 30: direct unit walls ──────────────────────
//
// The binary crate gets an in-process test module so private subcommand
// helpers are exercised WITHOUT spawning: flag walls, format walls and
// every fail-closed arm that needs crafted input instead of a live node.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_arg_conversions_map_every_variant() {
        assert_eq!(
            bitcoin::Network::from(NetworkArg::Bitcoin),
            bitcoin::Network::Bitcoin
        );
        assert_eq!(
            bitcoin::Network::from(NetworkArg::Signet),
            bitcoin::Network::Signet
        );
        assert_eq!(
            bitcoin::Network::from(NetworkArg::Regtest),
            bitcoin::Network::Regtest
        );
        assert_eq!(
            bitcoin::Network::from(NetworkArg::Testnet),
            bitcoin::Network::Testnet
        );
    }

    #[test]
    fn rpc_network_and_name_cover_every_spelling() {
        use bitcoin::Network as N;
        assert!(matches!(
            rpc_network(N::Testnet4),
            qsv_node::rpc::Network::Testnet
        ));
        assert!(matches!(
            rpc_network(N::Signet),
            qsv_node::rpc::Network::Signet
        ));
        assert_eq!(network_name(N::Bitcoin), "mainnet");
        assert_eq!(network_name(N::Regtest), "regtest");
        assert_eq!(network_name(N::Signet), "signet");
        assert_eq!(network_name(N::Testnet4), "testnet"); // wildcard arm
        assert_eq!(network_name(N::Testnet), "testnet");
    }

    #[test]
    fn dashboard_refuses_watch_plus_tip_and_fails_closed_without_a_node() {
        let fx = tempfile::tempdir().unwrap();
        // --watch with --tip is a usage error before any work.
        let e = vault_dashboard(
            fx.path().to_path_buf(),
            bitcoin::Network::Regtest,
            None,
            Some(100),
            0,
            5,
        )
        .unwrap_err();
        assert!(e.contains("--watch requires a live node"), "{e}");
        // No tip override and no bitcoind: the cookie connect fails
        // closed — once per network tag, so EVERY arm of the network
        // match inside the connect closure executes.
        for net in [
            bitcoin::Network::Bitcoin,
            bitcoin::Network::Testnet4,
            bitcoin::Network::Signet,
            bitcoin::Network::Regtest,
        ] {
            let e = vault_dashboard(fx.path().to_path_buf(), net, None, None, 0, 0).unwrap_err();
            assert!(e.contains("cannot reach node"), "{net:?}: {e}");
        }
    }

    /// Every live flow fails CLOSED on the cookie-fallback arm
    /// (rpc_port=None): no reachable node ⇒ an actionable error, never a
    /// panic and never a half-run ceremony. Each flow also exercises its
    /// startup wall (pairing, fleet inventory, deals/public) so the
    /// fail-fast ordering is pinned together with the connect.
    #[test]
    fn live_flows_fail_closed_on_the_cookie_fallback() {
        let fx = tempfile::tempdir().unwrap();
        let pin = CosignerPin::resolve(false, None, None, None, None).expect("no pins given");
        let net = bitcoin::Network::Regtest;

        // psbt-live.
        let e = psbt_live(
            fx.path(),
            None,
            net,
            None,
            1_000,
            false,
            false,
            fx.path(),
            1,
            false,
            0,
        )
        .unwrap_err();
        assert!(e.contains("cannot reach node"), "psbt-live: {e}");

        // vault-rotate: --inventory without --vault-id is a usage wall
        // BEFORE any node connection is attempted.
        let inv = fx.path().join("inv.json");
        std::fs::write(&inv, r#"{"vaults":[{"id":"v1","last_refresh_block":1}]}"#).unwrap();
        let e = vault_rotate(
            fx.path(),
            None,
            net,
            1_000,
            &[],
            false,
            fx.path(),
            None,
            &pin,
            Some(&inv),
            None,
            None,
            fx.path(),
        )
        .unwrap_err();
        assert!(
            e.contains("--inventory and --vault-id must be given together"),
            "{e}"
        );

        // vault-rotate: cookie-fallback arm.
        let e = vault_rotate(
            fx.path(),
            None,
            net,
            1_000,
            &[],
            false,
            fx.path(),
            None,
            &pin,
            None,
            None,
            None,
            fx.path(),
        )
        .unwrap_err();
        assert!(e.contains("cannot reach node"), "rotate: {e}");

        // vault-rotate-batch: a VALID fleet validates first (fail-fast),
        // then the cookie fallback — never a node connection earlier.
        let e = vault_rotate_batch(
            fx.path(),
            None,
            net,
            1_000,
            fx.path(),
            None,
            None,
            None,
            None,
            None,
            true,
            &inv,
            fx.path(),
            &pin,
        )
        .unwrap_err();
        assert!(e.contains("cannot reach node"), "batch: {e}");

        // watchtower (single-vault pass).
        let e = watchtower(fx.path(), None, net, 100, &[], None, fx.path(), 0).unwrap_err();
        assert!(e.contains("cannot reach node"), "watchtower: {e}");

        // watchtower-multi (fleet pass).
        let e = watchtower_multi(fx.path(), None, net, &inv, fx.path(), false).unwrap_err();
        assert!(e.contains("cannot reach node"), "multi: {e}");

        // frost-spend: the kit reads and the group key tweaks fine, then
        // the connect fails closed.
        kit_setup(
            2,
            &["alice".into(), "bob".into()],
            2,
            3,
            "",
            fx.path(),
            false,
        )
        .expect("setup runs");
        let public = fx.path().join("public-package.txt");
        let e = frost_spend(
            &public,
            &[],
            fx.path(),
            None,
            net,
            1_500,
            0,
            None,
            fx.path(),
            true,
            None,
            None,
            None,
            &pin,
        )
        .unwrap_err();
        assert!(e.contains("cannot reach node"), "frost-spend: {e}");
    }

    #[test]
    fn kit_seed_split_prints_both_passphrase_arms() {
        // "(none)" and "set" — the SLIP-0039 display arms.
        kit_seed_split(2, 3, KitFormat::Slip39, "").expect("empty passphrase");
        kit_seed_split(2, 3, KitFormat::Slip39, "pw").expect("set passphrase");
    }

    #[test]
    fn kit_combine_fails_closed_on_every_format_wall() {
        // SHAMIR: valid tags but only one share (threshold 2) → the
        // fail-closed combine arm fires with the operator hint.
        let shares = qsv_core::shamir::split(&DEMO_KIT_SEED, 2, 3).expect("split works");
        let raw = vec![shares[0].encode()];
        let e = kit_seed_combine(&raw, KitFormat::Qsv, "").unwrap_err();
        assert!(e.contains("fail-closed:"), "{e}");

        // SLIP-0039: a lone share cannot recover → same wall.
        let groups = [qsv_core::slip39::GroupSpec::new(2, 3)];
        let out = qsv_core::slip39::split(&DEMO_KIT_SEED, 1, &groups, "", 0).expect("split");
        let one = vec![out[0][0].clone()];
        let e = kit_seed_combine(&one, KitFormat::Slip39, "").unwrap_err();
        assert!(e.contains("fail-closed:"), "{e}");

        // SLIP-0039: a complete set recovering a 16-byte secret trips
        // the "kit seed is 32" length wall.
        let sixteen = [7u8; 16];
        let out = qsv_core::slip39::split(&sixteen, 1, &groups, "", 0).expect("split");
        let pair = vec![out[0][0].clone(), out[0][1].clone()];
        let e = kit_seed_combine(&pair, KitFormat::Slip39, "").unwrap_err();
        assert!(e.contains("recovered secret is 16 bytes"), "{e}");
    }

    #[test]
    fn sanitize_id_escapes_everything_that_is_not_path_safe() {
        assert_eq!(sanitize_id("ok_id-1"), "ok_id-1");
        assert_eq!(sanitize_id("a/b"), "a%2Fb");
        assert_eq!(sanitize_id(".."), "%2E%2E");
        assert_eq!(sanitize_id("sp ace"), "sp%20ace");
    }

    #[test]
    fn rotation_state_refuses_v1_and_writes_v2() {
        let txid_hex = "ab".repeat(32);
        let txid: bitcoin::Txid = txid_hex.parse().expect("32 bytes of hex is a txid");
        // v1 single-vault documents cannot carry ids → fail closed.
        let fx = tempfile::tempdir().unwrap();
        std::fs::write(
            fx.path().join("rotation-state.json"),
            r#"{"version":1,"last_refresh_block":100}"#,
        )
        .unwrap();
        let e = save_rotation_state(fx.path(), 100, "bc1ptestvault", txid).unwrap_err();
        assert!(e.contains("is v1 (single-vault) rotation state"), "{e}");
        // The healthy v2 path writes (and would merge) normally.
        let fx2 = tempfile::tempdir().unwrap();
        save_rotation_state(fx2.path(), 100, "vault-a", txid).expect("v2 save");
    }

    /// `unwrap_err` needs `T: Debug`; the pin struct deliberately isn't,
    /// so every wall assertion funnels through this helper instead.
    fn pin_wall(r: Result<CosignerPin, String>) -> String {
        r.err().expect("a fail-closed wall must refuse")
    }

    #[test]
    fn cosigner_pins_resolve_or_fail_at_startup() {
        let good32 = "00".repeat(32);
        let good48 = "11".repeat(48);
        let good64 = "22".repeat(64);
        // Pins without an endpoint → refused before any parsing.
        let e = pin_wall(CosignerPin::resolve(false, Some(&good32), None, None, None));
        assert!(e.contains("require a co-signer endpoint"), "{e}");
        // PCR walls: bad hex, wrong length, valid at every legal size.
        let e = pin_wall(CosignerPin::resolve(true, Some("zz"), None, None, None));
        assert!(e.contains("--cosigner-pcr0 must be hex"), "{e}");
        let short = "00".repeat(31);
        let e = pin_wall(CosignerPin::resolve(true, Some(&short), None, None, None));
        assert!(
            e.contains("--cosigner-pcr0 must be 32, 48 or 64 bytes (got 31)"),
            "{e}"
        );
        let pins = CosignerPin::resolve(true, Some(&good32), Some(&good48), Some(&good64), None)
            .expect("every legal PCR size resolves");
        assert_eq!(pins.xonly_hex.len(), 64, "demo key fills the default");
        // Absent PCRs take the documented empty default.
        CosignerPin::resolve(true, None, None, None, None).expect("defaults resolve");
        // Key walls: bad hex, wrong length, off-curve, valid.
        let e = pin_wall(CosignerPin::resolve(true, None, None, None, Some("zz")));
        assert!(e.contains("--cosigner-key must be hex"), "{e}");
        let e = pin_wall(CosignerPin::resolve(true, None, None, None, Some(&short)));
        assert!(e.contains("--cosigner-key must be 32 bytes"), "{e}");
        let e = pin_wall(CosignerPin::resolve(true, None, None, None, Some(&good32)));
        assert!(e.contains("not a valid x-only public key"), "{e}");
        // secp256k1 generator point x-coordinate — on the curve.
        let gen_x = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        let pins = CosignerPin::resolve(true, None, None, None, Some(gen_x)).expect("valid key");
        // The stored pin is the canonical lowercase hex of the key.
        assert_eq!(pins.xonly_hex, gen_x.to_ascii_lowercase());
    }

    #[test]
    fn gate_client_is_plain_for_none_and_full_material_sets() {
        assert!(build_gate_client(None, None).expect("no addr").is_none());
        let plain = build_gate_client(Some("127.0.0.1:9"), None)
            .expect("plain builds")
            .expect("an addr yields a client");
        drop(plain);
        // ALL-None material is the documented plain fallback too.
        let plain = build_gate_client(Some("127.0.0.1:9"), Some((None, None, None)))
            .expect("all-none is plain")
            .expect("an addr yields a client");
        drop(plain);
    }

    #[test]
    fn psbt_live_refuses_build_only_with_sign_only() {
        let fx = tempfile::tempdir().unwrap();
        let e = psbt_live(
            fx.path(),
            None,
            bitcoin::Network::Regtest,
            None,
            1_000,
            true,
            true,
            fx.path(),
            1,
            false,
            0,
        )
        .unwrap_err();
        assert!(
            e.contains("--build-only and --sign-only are mutually exclusive"),
            "{e}"
        );
        // P2MR is regtest-only, enforced before any node contact.
        let e = psbt_live(
            fx.path(),
            None,
            bitcoin::Network::Signet,
            None,
            1_000,
            true,
            false,
            fx.path(),
            1,
            true,
            0,
        )
        .unwrap_err();
        assert!(e.contains("REGTEST-ONLY"), "{e}");
    }

    // ── Round 30 · 100% coverage sweep: main.rs's untested branches ──

    /// The fail-closed gate wall's Err arm is injectable by design; the
    /// Ok arm (and its `?` at the call site) rides the real deterministic
    /// demo, which also proves the PQC→BIP-340 release path end to end.
    #[test]
    fn gate_wall_injects_a_failure_and_the_demo_runs_green() {
        let e = enclave_gate_wall(Err("injected PQC failure".into())).unwrap_err();
        assert!(e.contains("FAIL-CLOSED: injected PQC failure"), "{e}");
        hybrid_spend_demo().expect("the deterministic demo must pass");
    }

    /// The QR branch of the estate letter (§1 identity block rendered as
    /// a terminal QR) is only reached with `--qr`.
    #[test]
    fn estate_letter_qr_branch_renders() {
        estate_letter_cmd(bitcoin::Network::Regtest, "coverage", None, true)
            .expect("the QR branch must render");
    }

    /// A metrics token file is operator-editable under systemd; a VALUE
    /// with whitespace would break the HTTP header and must be refused.
    #[test]
    fn metrics_token_file_refuses_whitespace() {
        use std::os::unix::fs::PermissionsExt;
        let fx = tempfile::tempdir().unwrap();
        let p = fx.path().join("token");
        std::fs::write(&p, "two words\n").unwrap();
        // The permission wall runs FIRST — chmod 600 so the whitespace
        // wall is the one being asserted.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        let e = read_metrics_token_file(&p).unwrap_err();
        assert!(e.contains("the token contains whitespace"), "{e}");
    }

    /// Kit tagging walls: no `<id>:<file>` separator, a non-hex id, and
    /// an empty heir set are each refused before any ceremony runs.
    #[test]
    fn kit_parsing_walls_and_an_empty_heir_set_refuse() {
        let e = kit_parse_tagged("no-colon", "heir").unwrap_err();
        assert!(e.contains("must be <id-hex>:<file>"), "{e}");
        let e = kit_parse_tagged("zz:/tmp/x", "commitment").unwrap_err();
        assert!(e.contains("identifier must be 64 hex chars"), "{e}");
        let fx = tempfile::tempdir().unwrap();
        let e = kit_setup(2, &[], 1, 2, "", fx.path(), false).unwrap_err();
        assert!(e.contains("at least one --heir"), "{e}");
    }

    /// A capacity baseline is a release gate input: a zero/negative row
    /// would divide by it later — refused at load.
    #[test]
    fn bench_baseline_refuses_a_non_positive_row() {
        let fx = tempfile::tempdir().unwrap();
        let p = fx.path().join("base.json");
        std::fs::write(&p, r#"{"rows":[{"op":"x","ops_per_s":0.0}]}"#).unwrap();
        let e = load_baseline(&p, 25.0).unwrap_err();
        assert!(e.contains("baseline must be positive"), "{e}");
    }

    /// The witness-ordering contract: the enclave key always signs at the
    /// slot the leaf expects — BOTH orderings must be representable.
    #[test]
    fn witness_order_returns_both_orderings() {
        let (first, second) = witness_order(0, 1, &"user", &"enclave");
        assert_eq!((*first, *second), ("enclave", "user"));
        let (first, second) = witness_order(1, 1, &"user", &"enclave");
        assert_eq!((*first, *second), ("user", "enclave"));
    }

    /// An unsigned PSBT is exactly what a device must never be asked to
    /// sign: every missing field must appear in the refusal, by name.
    #[test]
    fn coldcard_compliance_report_lists_every_missing_field() {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };
        let psbt = bitcoin::psbt::Psbt::from_unsigned_tx(tx).expect("an empty psbt builds");
        let e = coldcard_compliance_report(&psbt).unwrap_err();
        for needle in [
            "witness_utxo missing",
            "tap_internal_key missing",
            "tap_scripts missing",
            "tap_merkle_root missing",
            "sighash_type implicit",
        ] {
            assert!(e.contains(needle), "`{needle}` missing from: {e}");
        }
    }

    /// Coldcard's finalized `<TXID>.txn` shape: a HEX raw transaction
    /// (not a PSBT) must still parse — the fallback decode arm.
    #[test]
    fn psbt_import_accepts_a_hex_raw_transaction_shape() {
        use bitcoin::consensus::Encodable;
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let mut raw = Vec::new();
        tx.consensus_encode(&mut raw).expect("encodes");
        let fx = tempfile::tempdir().unwrap();
        let input = fx.path().join("card.txn");
        std::fs::write(&input, hex::encode(&raw)).unwrap();
        let out = fx.path().join("imported.psbt");
        let r = psbt_import(&input, None, &out);
        // The hex shape PARSED (a parse refusal would name the three
        // shapes); later verification may still fail-closed on content.
        let msg = match r {
            Ok(_) => String::new(),
            Err(e) => e,
        };
        assert!(
            !msg.contains("neither a binary PSBT, base64 PSBT nor a hex transaction"),
            "the hex raw-tx fallback must parse: {msg}"
        );
    }

    /// The SUCCESS arm of the import verdict: a device PSBT carrying both
    /// tap script-sigs verifies, finalizes and imports cleanly. The hex
    /// shape test above legitimately fails-closed on content (its match
    /// takes the Err arm only) — this one proves the Ok arm end to end.
    #[test]
    fn psbt_import_accepts_the_fully_signed_demo_psbt() {
        let fx = tempfile::tempdir().unwrap();
        let built = fx.path().join("built.psbt");
        let signed = fx.path().join("signed.psbt");
        let out = fx.path().join("imported.psbt");
        psbt_build(&built).expect("the demo PSBT must build");
        psbt_sign(&built, &signed).expect("the demo PSBT must sign");
        psbt_import(&signed, None, &out).expect("a fully signed device PSBT must import");
        assert!(out.exists(), "the import must write the finalized PSBT");
    }

    /// The full FROST kit ceremony IN-PROCESS: one commitment prints the
    /// sub-threshold NOTE (and the coordinator then refuses), two
    /// commitments build and write the sign package.
    #[test]
    fn kit_build_sign_pkg_notes_a_lone_committee_and_writes_a_full_one() {
        use rand_core::OsRng;
        let fx = tempfile::tempdir().unwrap();
        // DKG mode here on purpose: the coordinator's build-sign-pkg must
        // treat dealer-less deals IDENTICALLY (same file contract).
        kit_setup(
            2,
            &["alice".to_string(), "bob".to_string()],
            2,
            3,
            "",
            fx.path(),
            true,
        )
        .expect("setup runs");
        let public = std::fs::read_to_string(fx.path().join("public-package.txt"))
            .expect("public package written");
        let mut deals: Vec<String> = std::fs::read_dir(fx.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("heir-") && n.ends_with("-deal.txt"))
            .collect();
        deals.sort();
        assert_eq!(deals.len(), 2, "two heir deals");

        let mut specs = Vec::new();
        for (i, name) in deals.iter().enumerate() {
            let deal = std::fs::read_to_string(fx.path().join(name)).unwrap();
            let id = qsv_core::frost::deal_identifier(&deal).expect("identifier");
            let (_nonce, commitment) =
                qsv_core::frost::heir_round1(&deal, &public, &mut OsRng).expect("round 1");
            let cpath = fx.path().join(format!("commit-{i}.txt"));
            std::fs::write(&cpath, commitment).unwrap();
            specs.push(format!("{}:{}", hex::encode(id), cpath.display()));
        }

        let msg = "ab".repeat(32);
        // ONE commitment: the sub-threshold NOTE fires (the threshold is
        // enforced when signature SHARES arrive, not at package build).
        kit_build_sign_pkg(&msg, &[specs[0].clone()], &fx.path().join("pkg1.txt"))
            .expect("a lone commitment still builds the package");
        assert!(fx.path().join("pkg1.txt").exists(), "note-path package");
        // BOTH: the full-committee path writes its own package.
        kit_build_sign_pkg(&msg, &specs, &fx.path().join("pkg2.txt"))
            .expect("two commitments meet the threshold");
        assert!(fx.path().join("pkg2.txt").exists(), "package written");
    }

    /// docs/11 losing a required element must fail the CLI's own audit
    /// gate in BOTH modes before any network contact happens.
    #[test]
    fn bip360_offline_audit_failure_paths_are_operator_visible() {
        let fx = tempfile::tempdir().unwrap();
        let plan = fx.path().join("plan.md");
        let real = include_str!("../../../docs/11_p2mr_migration_plan.md");
        std::fs::write(&plan, real.replace("Phase 4a", "Phase ?")).unwrap();
        let e = bip360_status(false, Some(plan.clone())).unwrap_err();
        assert!(e.contains("offline audit FAILED"), "{e}");
        let e = bip360_status(true, Some(plan)).unwrap_err();
        assert!(e.contains("plan audit FAILED"), "{e}");
    }

    /// The ONLINE tracker path end to end with the fetch INJECTED
    /// (QSV_CURL — no network in tests): every fetch wall fails closed
    /// (curl error, non-UTF-8, headerless body), a STALE live header
    /// produces the K1 DELTA, and the CURRENT one passes with the impl
    /// limb printed. One test fn on purpose: QSV_CURL is process-wide.
    #[test]
    fn bip360_online_diff_covers_pass_delta_and_every_fetch_wall() {
        use std::os::unix::fs::PermissionsExt;
        let fx = tempfile::tempdir().unwrap();
        // Pre-set a nonexistent fetch binary so `saved` is Some(...) — the
        // restore closure takes its RE-SET arm (the remove arm needs an
        // unset variable, which is the other side of the same test).
        // The nonexistent path also doubles as the SPAWN-failure wall:
        // Command::new errors before any child exists.
        std::env::set_var("QSV_CURL", "/nonexistent-qsv-curl-for-tests");
        let curl = fx.path().join("fake-curl");
        let saved: Option<std::ffi::OsString> = std::env::var_os("QSV_CURL");
        let run = |script: &str| {
            std::fs::write(&curl, format!("#!/bin/sh\n{script}\n")).unwrap();
            std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::env::set_var("QSV_CURL", &curl);
        };
        let restore = |saved: &Option<std::ffi::OsString>| match saved {
            Some(v) => std::env::set_var("QSV_CURL", v),
            None => std::env::remove_var("QSV_CURL"),
        };
        let header = |status: &str, version: &str| {
            format!(
                "<pre>\n  BIP: 360\n  Title: Pay-to-Merkle-Root (P2MR)\n  Status: {status}\n  Type: Specification\n  Assigned: 2024-12-18\n  Version: {version}\n  Requires: 340, 341, 342\n</pre>"
            )
        };

        // 0. the fetch binary cannot be SPAWNED at all → the spawn wall
        //    (still pointing at the nonexistent path set above).
        let e = bip360_status(true, None).unwrap_err();
        assert!(e.contains("cannot run curl"), "{e}");
        // 1. curl exits non-zero → the fetch wall.
        run("echo '404 not found' >&2; exit 22");
        let e = bip360_status(true, None).unwrap_err();
        assert!(e.contains("fetch failed"), "{e}");
        // 2. non-UTF-8 output → refused.
        run("printf '\\377\\376'");
        let e = bip360_status(true, None).unwrap_err();
        assert!(e.contains("not UTF-8"), "{e}");
        // 3. valid UTF-8 WITHOUT a BIP header → live-header wall.
        run("echo 'no header here'");
        let e = bip360_status(true, None).unwrap_err();
        assert!(e.contains("live header"), "{e}");
        // 4. a STALE live header (status Draft→Proposed, version bump) →
        //    the K1 delta report, field by field.
        run(&format!(
            "cat <<'EOF'\n{}\nEOF",
            header("Proposed", "0.13.0")
        ));
        let e = bip360_status(true, None).unwrap_err();
        assert!(e.contains("K1 DELTA"), "{e}");
        assert!(e.contains("status: Draft → Proposed"), "{e}");
        assert!(e.contains("version: 0.12.1 → 0.13.0"), "{e}");
        // 5. the live header matches the snapshot → PASS + impl limb line.
        run(&format!("cat <<'EOF'\n{}\nEOF", header("Draft", "0.12.1")));
        bip360_status(true, None).expect("a matching live header passes");
        restore(&saved);
        // And the OTHER arm of the restore contract: unset → remove, so
        // the ambient environment is exactly what the test found.
        restore(&None);
    }

    /// The systemd read-back verifier, wall by wall: the generator can
    /// never emit a broken unit — but a partial write or an on-disk edit
    /// could, and every refusal must fire on a crafted body.
    #[test]
    fn unit_verifier_walls_refuse_every_broken_directive() {
        use std::os::unix::fs::PermissionsExt;
        let fx = tempfile::tempdir().unwrap();
        let state = fx.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let token_file = fx.path().join("scrape.token");
        std::fs::write(&token_file, "tok123\n").unwrap();
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let unit_dir = fx.path().join("units");
        cosigner_bridge_install(
            "127.0.0.1:19999",
            &state,
            &[],
            None,
            &[],
            Some(&unit_dir),
            "*-*-* *:0/5",
            "qsv-cosigner-bridge",
            None,
            None,
            None,
            Some("2:1"),
            None,
            Some(&token_file),
            0,
            0,
            0,
        )
        .expect("the generator's own output must verify");
        let service_path = unit_dir.join("qsv-cosigner-bridge.service");
        let timer_path = unit_dir.join("qsv-cosigner-bridge.timer");
        let good_service = std::fs::read_to_string(&service_path).unwrap();
        let good_timer = std::fs::read_to_string(&timer_path).unwrap();
        let state_abs = std::fs::canonicalize(&state).unwrap();
        let rate_flag = "--rate-limit 2:1".to_string();
        let flags = vec![rate_flag.clone()];

        // `check` writes the mutated bodies to disk (so the read-back
        // comparison passes) and runs the verifier against them.
        let check = |service: &str, timer: &str, token_flag: bool, token: Option<&str>| {
            std::fs::write(&service_path, service).unwrap();
            std::fs::write(&timer_path, timer).unwrap();
            verify_bridge_units(
                &[
                    (service_path.display().to_string(), service.to_string()),
                    (timer_path.display().to_string(), timer.to_string()),
                ],
                &state_abs,
                &flags,
                token_flag,
                token,
                "*-*-* *:0/5",
                30,
            )
        };

        // Happy path first: the untouched bodies verify.
        check(&good_service, &good_timer, true, Some("tok123")).expect("golden bodies verify");
        // 1. on-disk drift: the file on disk no longer matches the body
        //    the installer believes it wrote (mutate the DISK only, and
        //    call the verifier directly — `check` rewrites both files).
        std::fs::write(&service_path, "Type=simple\n").unwrap();
        let e = verify_bridge_units(
            &[
                (service_path.display().to_string(), good_service.clone()),
                (timer_path.display().to_string(), good_timer.clone()),
            ],
            &state_abs,
            &flags,
            true,
            Some("tok123"),
            "*-*-* *:0/5",
            30,
        )
        .unwrap_err();
        assert!(e.contains("differs"), "{e}");
        // 2. ExecStart loses the state dir.
        let e = check(
            &good_service.replace(
                &format!("--state-dir {}", state_abs.display()),
                "--state-dir /tmp/x",
            ),
            &good_timer,
            true,
            Some("tok123"),
        )
        .unwrap_err();
        assert!(e.contains("ExecStart must invoke cosigner-bridge"), "{e}");
        // 3. a baked flag vanishes from ExecStart.
        let e = check(
            &good_service.replace(&format!(" {rate_flag}"), ""),
            &good_timer,
            true,
            Some("tok123"),
        )
        .unwrap_err();
        assert!(e.contains("must carry the baked flag"), "{e}");
        // 4. the token VALUE leaks into the unit.
        let e = check(
            &format!("{good_service}\n# tok123 leaked\n"),
            &good_timer,
            true,
            Some("tok123"),
        )
        .unwrap_err();
        assert!(e.contains("must never reach the unit file"), "{e}");
        // 5. a required directive disappears.
        let e = check(
            &good_service.replace("Type=notify\n", ""),
            &good_timer,
            true,
            Some("tok123"),
        )
        .unwrap_err();
        assert!(e.contains("missing required directive"), "{e}");
        // 6. an insane watchdog period.
        let e = check(
            &good_service.replace("WatchdogSec=30", "WatchdogSec=0"),
            &good_timer,
            true,
            Some("tok123"),
        )
        .unwrap_err();
        assert!(e.contains("sane WatchdogSec"), "{e}");
        // 7. the state dir leaves ReadWritePaths.
        let e = check(
            &good_service.replace(&format!("ReadWritePaths={}\n", state_abs.display()), ""),
            &good_timer,
            true,
            Some("tok123"),
        )
        .unwrap_err();
        assert!(e.contains("missing ReadWritePaths"), "{e}");
        // 8. the reload half vanishes.
        let e = check(
            &good_service.replace("ExecReload=/bin/kill -HUP $MAINPID\n", ""),
            &good_timer,
            true,
            Some("tok123"),
        )
        .unwrap_err();
        assert!(e.contains("missing ExecReload"), "{e}");
        // 9. the timer loses its calendar.
        let e = check(
            &good_service,
            &good_timer.replace("OnCalendar=*-*-* *:0/5\n", ""),
            true,
            Some("tok123"),
        )
        .unwrap_err();
        assert!(e.contains("missing OnCalendar"), "{e}");
        // 10. no ExecStart at all.
        let e = check(
            &good_service.replace("ExecStart=", "ExecRun="),
            &good_timer,
            true,
            Some("tok123"),
        )
        .unwrap_err();
        assert!(e.contains("no ExecStart"), "{e}");
    }

    /// The doctor's bridge-record diagnosis covers EVERY liveness state —
    /// including the platform-cannot-ask `Unknown` POSIX can never emit.
    #[test]
    fn health_diagnoses_classify_every_liveness_state() {
        let fx = tempfile::tempdir().unwrap();
        let record = qsv_cosigner::health::current(
            "127.0.0.1:1",
            "plain",
            vec!["v".to_string()],
            0,
            qsv_cosigner::health::ServePolicyRecord {
                metrics_token_armed: false,
                metrics_token_file: None,
                max_inflight: 0,
                frame_timeout_ms: None,
            },
        );
        let d = health_diagnoses(qsv_cosigner::Liveness::Live, Some(&record), fx.path());
        assert_eq!(d.len(), 1);
        assert!(d[0].2.contains("alive"), "{}", d[0].2);
        let d = health_diagnoses(qsv_cosigner::Liveness::Stale, Some(&record), fx.path());
        assert!(d[0].2.contains("DEAD pid"), "{}", d[0].2);
        // `Unknown` on POSIX is silent by design (never read as alive).
        let d = health_diagnoses(qsv_cosigner::Liveness::Unknown, Some(&record), fx.path());
        assert!(d.is_empty(), "{d:?}");
        let d = health_diagnoses(qsv_cosigner::Liveness::Absent, None, fx.path());
        assert!(d[0].2.contains("never booted here"), "{}", d[0].2);
    }

    /// The sweep gate's THREE verdicts come off a REAL in-process bridge:
    /// Release for the allow-listed vault, Refused (never Frozen) for
    /// anything else — a gate that cannot say "no" would sweep anyway.
    #[test]
    fn sweep_gate_answers_release_and_refused_from_a_live_bridge() {
        use std::sync::{Arc, Mutex};
        let cosigner = qsv_cosigner::Cosigner::provision([7u8; 32], vec!["allowed-vault".into()]);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let _ = qsv_cosigner::server::serve_listener(listener, Arc::new(Mutex::new(cosigner)));
        });
        let client = build_gate_client(Some(&addr), None)
            .expect("plain gate client")
            .expect("an addr yields a client");
        assert!(
            !sweep_vault_gate(&client, "allowed-vault").expect("release"),
            "Release = not frozen"
        );
        let e = sweep_vault_gate(&client, "unknown-vault").unwrap_err();
        assert!(e.contains("gate refused:"), "{e}");
    }

    /// The co-signer signature is trusted ONLY after the attestation
    /// document AND the BIP-340 signature both verify under the pins: a
    /// real document with a tampered signature, and an accepted answer
    /// with NO document, must each fail closed.
    #[test]
    fn live_enclave_signature_refuses_an_unattested_or_tampered_answer() {
        use std::sync::{Arc, Mutex};
        let seed = [7u8; 32];
        let cosigner = qsv_cosigner::Cosigner::provision(seed, vec!["allowed-vault".into()]);
        let xonly = cosigner.public_key().expect("demo key");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let _ = qsv_cosigner::server::serve_listener(listener, Arc::new(Mutex::new(cosigner)));
        });
        let pin = CosignerPin::resolve(
            true,
            Some(&hex::encode(qsv_cosigner::nsm::dev_measurement(&seed))),
            None,
            None,
            Some(&hex::encode(xonly.serialize())),
        )
        .expect("pins resolve");
        let sighash = bitcoin::sighash::TapSighash::from_byte_array([0x77u8; 32]);
        let client = qsv_cosigner::BridgeClient::plain(&addr);

        // 1. The REAL bridge: document verifies, signature verifies.
        live_enclave_signature(&client, "allowed-vault", &sighash, &pin)
            .expect("the real co-signer answer verifies end to end");

        // A genuine accepted response to tamper with (the nonce is
        // request-derived, so live_enclave_signature rebuilds the VERY
        // request this response was minted for).
        let pqc = qsv_pqc::PqcIdentity::from_seed(&[21u8; 32]);
        let digest = [0x77u8; 32];
        let req = qsv_cosigner::SignRequest::new(
            "allowed-vault",
            &digest,
            pqc.verifying_key_bytes(),
            &pqc.sign(&digest),
        );
        let genuine = client.send(&req).expect("accepted");
        assert!(genuine.accepted);

        // Fake-bridge helper: one framed JSON reply per connection.
        let fake = |resp: qsv_cosigner::SignResponse| -> String {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                if let Ok((mut s, _)) = listener.accept() {
                    let mut len_buf = [0u8; 8];
                    let _ = s.read_exact(&mut len_buf);
                    let len = u64::from_be_bytes(len_buf) as usize;
                    let mut body = vec![0u8; len];
                    let _ = s.read_exact(&mut body);
                    let out = serde_json::to_vec(&resp).expect("serializes");
                    let _ = s.write_all(&(out.len() as u64).to_be_bytes());
                    let _ = s.write_all(&out);
                    let _ = s.flush();
                }
            });
            addr
        };

        // 2. ACCEPTED without a document = protocol v1 / broken bridge →
        //    the unattested signature is refused.
        let addr = fake(qsv_cosigner::SignResponse {
            version: 2,
            accepted: true,
            reason: None,
            schnorr_sig_hex: genuine.schnorr_sig_hex.clone(),
            attestation_doc_hex: None,
        });
        let e = live_enclave_signature(
            &qsv_cosigner::BridgeClient::plain(&addr),
            "allowed-vault",
            &sighash,
            &pin,
        )
        .unwrap_err();
        assert!(e.contains("WITHOUT an attestation document"), "{e}");

        // 3. A GENUINE document carrying a TAMPERED signature: the
        //    attestation chain passes, the BIP-340 check must not.
        let mut bad_sig = [0u8; 64];
        bad_sig.copy_from_slice(&hex::decode(genuine.schnorr_sig_hex.as_deref().unwrap()).unwrap());
        bad_sig[0] ^= 0x01;
        let addr = fake(qsv_cosigner::SignResponse {
            version: 2,
            accepted: true,
            reason: None,
            schnorr_sig_hex: Some(hex::encode(bad_sig)),
            attestation_doc_hex: genuine.attestation_doc_hex.clone(),
        });
        let e = live_enclave_signature(
            &qsv_cosigner::BridgeClient::plain(&addr),
            "allowed-vault",
            &sighash,
            &pin,
        )
        .unwrap_err();
        assert!(e.contains("FAILED verification"), "{e}");
    }
}
