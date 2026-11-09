//! # OpenAudit Server
//!
//! Control plane binary for OpenAudit, providing the authoritative enrollment
//! and outbox retrieval verification engines, TPM-backed monotonic counter
//! synchronization, and catalog promotion services for Dimension 4.

#![allow(
    clippy::missing_errors_doc,
    clippy::significant_drop_tightening,
    clippy::too_many_lines,
    clippy::struct_excessive_bools,
    clippy::result_large_err,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::too_many_arguments
)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use openaudit_core::protocol::catalog::{
    AssessmentCatalog, CatalogManager, MonotonicCounter, RecoveryOutcome,
};
use openaudit_core::protocol::error::ProtocolError;
use openaudit_core::protocol::tpm::{
    resolve_tpm_device_path, DeviceTransport, TpmClient, TpmCounterConfig, TpmMonotonicCounter,
    UnixSocketTransport,
};
use openaudit_core::protocol::trust::UnverifiedRetrievalRequest;
use openaudit_core::protocol::types::{
    ChallengeNonce, EnrollmentGeneration, EnrollmentTranscript, MachineId, SharedSecret,
    TimestampNs,
};
use openaudit_core::protocol::{AuthorityService, SqliteAuthorityStore, SqliteReplayStore};

/// Multi-transport adapter satisfying [`MonotonicCounter`] for server catalog updates.
enum ServerMonotonicCounter {
    Socket(TpmMonotonicCounter<UnixSocketTransport>),
    Device(TpmMonotonicCounter<DeviceTransport>),
}

impl MonotonicCounter for ServerMonotonicCounter {
    fn read_counter(&self) -> Result<u64, ProtocolError> {
        match self {
            Self::Socket(c) => c.read_counter(),
            Self::Device(c) => c.read_counter(),
        }
    }

    fn increment_counter(&mut self) -> Result<u64, ProtocolError> {
        match self {
            Self::Socket(c) => c.increment_counter(),
            Self::Device(c) => c.increment_counter(),
        }
    }
}

fn is_socket_path(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if let Ok(meta) = fs::metadata(path) {
            return meta.file_type().is_socket();
        }
    }
    let p_str = path.to_string_lossy();
    p_str.ends_with(".sock") || p_str.contains("/sock")
}

/// Opens a hardware character device or software socket as a [`ServerMonotonicCounter`].
fn open_monotonic_counter(tpm_path: &Path) -> ServerMonotonicCounter {
    if !is_socket_path(tpm_path) {
        let client = TpmClient::new(DeviceTransport::new(tpm_path));
        return ServerMonotonicCounter::Device(TpmMonotonicCounter::new(
            client,
            TpmCounterConfig::default(),
        ));
    }

    let client = TpmClient::new(UnixSocketTransport::new(tpm_path));
    ServerMonotonicCounter::Socket(TpmMonotonicCounter::new(
        client,
        TpmCounterConfig::default(),
    ))
}

/// Reads a 32-byte shared secret from `path`, strictly enforcing regular file type and mode `0600`.
///
/// # Security Invariant
/// Error messages report metadata validation failures without echoing the secret content.
fn read_strict_secret_file(path: &Path) -> Result<[u8; 32], String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to stat secret file at '{}': {err}", path.display()))?;

    if !meta.file_type().is_file() {
        return Err(format!(
            "secret path '{}' is not a regular file (symlinks, directories, and special devices rejected)",
            path.display()
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "insecure permissions on secret file '{}': mode 0{:o} detected; strictly mode 0600 required",
                path.display(),
                mode
            ));
        }
    }

    if meta.len() != 32 {
        return Err(format!(
            "invalid secret file size for '{}': expected exactly 32 bytes, found {}",
            path.display(),
            meta.len()
        ));
    }

    let bytes = fs::read(path)
        .map_err(|err| format!("failed to read secret file at '{}': {err}", path.display()))?;

    if bytes.len() != 32 {
        return Err(format!(
            "unexpected byte length read from '{}': expected 32, read {}",
            path.display(),
            bytes.len()
        ));
    }

    let mut secret = [0u8; 32];
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

/// Generates 32 cryptographically secure random bytes for challenge nonce issuance.
fn generate_nonce_32() -> [u8; 32] {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut file) = fs::File::open("/dev/urandom") {
            let mut buf = [0u8; 32];
            if file.read_exact(&mut buf).is_ok() {
                return buf;
            }
        }
    }

    // High-entropy UUID-based fallback
    let m1 = MachineId::new();
    let m2 = MachineId::new();
    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(m1.as_bytes());
    buf[16..].copy_from_slice(m2.as_bytes());
    buf
}

/// Decodes an even-length hex string into raw bytes.
fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let clean = s.trim();
    if clean.len() % 2 != 0 {
        return Err(format!(
            "hex string has odd length {} (must be even)",
            clean.len()
        ));
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&clean[i..i + 2], 16)
                .map_err(|err| format!("invalid hex sequence '{}': {err}", &clean[i..i + 2]))
        })
        .collect()
}

/// Decodes exactly 32 bytes from a 64-character hex string.
fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(s)?;
    bytes.try_into().map_err(|vec: Vec<u8>| {
        format!(
            "expected 32 bytes (64 hex characters), received {}",
            vec.len()
        )
    })
}

/// Encodes raw bytes into lowercase hexadecimal representation.
fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Returns the current system clock time in Unix nanoseconds.
fn current_time_ns() -> Result<TimestampNs, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock precedes UNIX epoch: {err}"))?;
    let nanos_u128 = duration.as_nanos();
    let nanos_i64 = i64::try_from(nanos_u128)
        .map_err(|_| "timestamp overflowed signed 64-bit nanoseconds".to_string())?;
    Ok(TimestampNs::from_nanos(nanos_i64))
}

/// Opens the authority persistence stores and catalog manager rooted under `data_dir`.
fn open_authority_service(data_dir: &Path) -> Result<AuthorityService, ProtocolError> {
    fs::create_dir_all(data_dir).map_err(|err| {
        ProtocolError::StorageUnavailable(format!(
            "failed to create authority data directory '{}': {err}",
            data_dir.display()
        ))
    })?;

    let authority_store = Arc::new(SqliteAuthorityStore::open(data_dir.join("authority.db"))?);
    let replay_store = Arc::new(SqliteReplayStore::open(data_dir.join("replay.db"))?);
    let catalog_manager = Arc::new(CatalogManager::open(data_dir.join("catalog"))?);

    Ok(AuthorityService::new(
        authority_store,
        replay_store,
        catalog_manager,
    ))
}

fn print_help() {
    println!(
        "OpenAudit Server v{}\n\n\
        Usage: openaudit-server <COMMAND> [OPTIONS]\n\n\
        Commands:\n  \
          serve                            Run the OpenAudit control plane HTTP server (Milestone 5)\n  \
          authority status                 Inspect authority persistence databases and catalog health\n  \
          authority token-issue            Issue and persist a single-use enrollment token\n  \
          authority process-enrollment     Validate enrollment transcript and HMAC proof\n  \
          authority process-retrieval      Verify retrieval request and enforce replay cache\n  \
          authority catalog-init           Initialize a baseline catalog repository\n  \
          authority catalog-update         Execute 6-stage catalog promotion synchronized with TPM counter\n  \
          authority recover-catalog        Reconcile catalog consistency against TPM counter (CB-01..13)\n  \
          authority serve-tls              Run an authoritative TLS 1.3 service endpoint\n  \
          version                          Print version information\n  \
          help                             Print this help message\n\n\
        Global Options:\n  \
          --data-dir <DIR>                 Storage root directory (default: ./data)\n  \
          --bind <IP:PORT>                 Network address to bind HTTP server (default: 127.0.0.1:8080)\n  \
          --port <PORT>                    Override port number for HTTP server\n",
        openaudit_core::version()
    );
}

fn print_version() {
    println!("OpenAudit Server v{}", openaudit_core::version());
}

fn get_data_dir(args: &[String]) -> PathBuf {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--data-dir" {
            if let Some(val) = iter.next() {
                return PathBuf::from(val);
            }
        }
    }
    PathBuf::from("./data")
}

fn run_authority_status(args: &[String]) -> Result<(), String> {
    let data_dir = get_data_dir(args);
    let service = open_authority_service(&data_dir)
        .map_err(|err| format!("failed to initialize authority service: {err}"))?;

    println!("OpenAudit Authority Service: ONLINE");
    println!("DATA_DIR: {}", data_dir.display());
    println!(
        "AUTHORITY_STORE: {}",
        data_dir.join("authority.db").display()
    );
    println!("REPLAY_STORE: {}", data_dir.join("replay.db").display());
    println!("CATALOG_DIR: {}", data_dir.join("catalog").display());

    match service.load_active_catalog() {
        Ok(active) => {
            println!("ACTIVE_CATALOG_VERSION: {}", active.version);
            println!("ACTIVE_CATALOG_COUNTER: {}", active.counter);
            println!("ACTIVE_CATALOG_PAYLOAD_HASH: {}", active.payload_hash);
        }
        Err(ProtocolError::StorageUnavailable(_) | ProtocolError::CatalogCorrupted(_)) => {
            println!("ACTIVE_CATALOG: NOT_INITIALIZED");
        }
        Err(err) => {
            println!("ACTIVE_CATALOG_ERROR: {err}");
        }
    }

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_authority_token_issue(args: &[String]) -> Result<(), String> {
    let data_dir = get_data_dir(args);
    let mut machine_id_str: Option<String> = None;
    let mut nonce_hex: Option<String> = None;
    let mut generate_nonce = false;
    let mut generation_u32: Option<u32> = None;
    let mut ttl_secs: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--machine-id" | "--machine" => {
                i += 1;
                if i < args.len() {
                    machine_id_str = Some(args[i].clone());
                }
            }
            "--nonce" => {
                i += 1;
                if i < args.len() {
                    nonce_hex = Some(args[i].clone());
                }
            }
            "--generate-nonce" => {
                generate_nonce = true;
            }
            "--generation" => {
                i += 1;
                if i < args.len() {
                    generation_u32 = args[i].parse::<u32>().ok();
                }
            }
            "--ttl-secs" => {
                i += 1;
                if i < args.len() {
                    ttl_secs = args[i].parse::<u64>().ok();
                }
            }
            _ => {}
        }
        i += 1;
    }

    let machine_id_raw = machine_id_str
        .ok_or_else(|| "missing mandatory argument: --machine-id <UUID>".to_string())?;
    let machine_id =
        MachineId::parse(&machine_id_raw).map_err(|err| format!("invalid --machine-id: {err}"))?;

    let nonce_bytes = if let Some(hex_str) = nonce_hex {
        decode_hex_32(&hex_str)?
    } else if generate_nonce {
        generate_nonce_32()
    } else {
        return Err(
            "missing challenge nonce: specify either --nonce <HEX> or --generate-nonce".to_string(),
        );
    };

    let gen_val = generation_u32
        .ok_or_else(|| "missing mandatory argument: --generation <U32>".to_string())?;
    let generation = EnrollmentGeneration(gen_val);

    let ttl_val =
        ttl_secs.ok_or_else(|| "missing mandatory argument: --ttl-secs <U64>".to_string())?;
    let ttl_nanos = ttl_val
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "ttl-secs overflowed nanoseconds calculation".to_string())?;

    let now = current_time_ns()?;

    let service = open_authority_service(&data_dir)
        .map_err(|err| format!("failed to initialize authority service: {err}"))?;

    let issued = service
        .issue_enrollment_token(
            machine_id,
            ChallengeNonce(nonce_bytes),
            generation,
            ttl_nanos,
            now,
        )
        .map_err(|err| format!("token issuance rejected: {err}"))?;

    println!("TOKEN_ISSUE: SUCCESS");
    println!("TOKEN_ID: {}", encode_hex(issued.token_id.as_bytes()));
    println!("MACHINE_ID: {}", issued.machine_id);
    println!("NONCE: {}", encode_hex(issued.expected_nonce.as_bytes()));
    println!("GENERATION: {}", issued.expected_generation.0);
    println!("EXPIRES_AT_NS: {}", issued.expires_at.as_nanos());

    Ok(())
}

fn run_authority_process_enrollment(args: &[String]) -> Result<(), String> {
    let data_dir = get_data_dir(args);
    let mut transcript_hex: Option<String> = None;
    let mut proof_hex: Option<String> = None;
    let mut secret_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--transcript" => {
                i += 1;
                if i < args.len() {
                    transcript_hex = Some(args[i].clone());
                }
            }
            "--proof" => {
                i += 1;
                if i < args.len() {
                    proof_hex = Some(args[i].clone());
                }
            }
            "--secret-file" => {
                i += 1;
                if i < args.len() {
                    secret_path = Some(PathBuf::from(&args[i]));
                }
            }
            _ => {}
        }
        i += 1;
    }

    let t_hex = transcript_hex
        .ok_or_else(|| "missing mandatory argument: --transcript <HEX>".to_string())?;
    let p_hex = proof_hex.ok_or_else(|| "missing mandatory argument: --proof <HEX>".to_string())?;
    let s_path = secret_path
        .ok_or_else(|| "missing mandatory argument: --secret-file <PATH>".to_string())?;

    let raw_transcript = decode_hex(&t_hex)?;
    let transcript = EnrollmentTranscript::parse_canonical(&raw_transcript)
        .map_err(|err| format!("malformed enrollment transcript: {err}"))?;

    let proof = decode_hex_32(&p_hex)?;
    let secret = read_strict_secret_file(&s_path)?;

    let now = current_time_ns()?;

    let service = open_authority_service(&data_dir)
        .map_err(|err| format!("failed to initialize authority service: {err}"))?;

    let verified = service
        .process_enrollment(&transcript, &proof, &SharedSecret(secret), now)
        .map_err(|err| format!("enrollment validation failed: {err}"))?;

    println!("ENROLLMENT_VERIFIED: SUCCESS");
    println!("MACHINE_ID: {}", verified.machine_id);
    println!("TRANSACTION_ID: {}", verified.tx_id);
    println!("GENERATION: {}", verified.generation.0);
    println!("COUNTER_BASE: {}", verified.counter_base.as_u64());
    println!("CATALOG_BASE: {}", verified.catalog_base.as_u64());

    Ok(())
}

fn run_authority_process_retrieval(args: &[String]) -> Result<(), String> {
    let data_dir = get_data_dir(args);
    let mut request_hex: Option<String> = None;
    let mut proof_hex: Option<String> = None;
    let mut secret_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--request" => {
                i += 1;
                if i < args.len() {
                    request_hex = Some(args[i].clone());
                }
            }
            "--proof" => {
                i += 1;
                if i < args.len() {
                    proof_hex = Some(args[i].clone());
                }
            }
            "--secret-file" => {
                i += 1;
                if i < args.len() {
                    secret_path = Some(PathBuf::from(&args[i]));
                }
            }
            _ => {}
        }
        i += 1;
    }

    let req_hex =
        request_hex.ok_or_else(|| "missing mandatory argument: --request <HEX>".to_string())?;
    let s_path = secret_path
        .ok_or_else(|| "missing mandatory argument: --secret-file <PATH>".to_string())?;

    let raw_bytes = decode_hex(&req_hex)?;
    let (payload, proof) = if let Some(p_hex) = proof_hex {
        let p_bytes = decode_hex_32(&p_hex)?;
        (raw_bytes, p_bytes)
    } else if raw_bytes.len() == 121 {
        let p_slice: [u8; 32] = raw_bytes[89..121].try_into().map_err(|_| "slice error")?;
        (raw_bytes[..89].to_vec(), p_slice)
    } else {
        return Err(format!(
            "invalid request payload length: {} bytes (specify separate --proof <HEX> or composite 121-byte hex)",
            raw_bytes.len()
        ));
    };

    let secret = read_strict_secret_file(&s_path)?;
    let unverified = UnverifiedRetrievalRequest::new(payload, proof);
    let now = current_time_ns()?;

    let service = open_authority_service(&data_dir)
        .map_err(|err| format!("failed to initialize authority service: {err}"))?;

    let verified = service
        .process_retrieval(&unverified, &SharedSecret(secret), now)
        .map_err(|err| format!("retrieval validation failed: {err}"))?;

    println!("RETRIEVAL_VERIFIED: SUCCESS");
    println!("MACHINE_ID: {}", verified.message.machine_id);
    println!("TX_ID: {}", verified.message.tx_id);
    println!("REQ_ID: {}", verified.message.req_id);
    println!("T_REQ: {}", verified.message.t_req.as_nanos());
    println!("EXPIRES_AT_NS: {}", verified.expires_at.as_nanos());

    Ok(())
}

fn run_authority_catalog_update(args: &[String]) -> Result<(), String> {
    let data_dir = get_data_dir(args);
    let mut candidate_path: Option<PathBuf> = None;
    let mut tpm_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--candidate" | "--candidate-file" => {
                i += 1;
                if i < args.len() {
                    candidate_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--tpm" => {
                i += 1;
                if i < args.len() {
                    tpm_path = Some(PathBuf::from(&args[i]));
                }
            }
            _ => {}
        }
        i += 1;
    }

    let c_path = candidate_path
        .ok_or_else(|| "missing mandatory argument: --candidate <PATH>".to_string())?;
    let t_path = resolve_tpm_device_path(tpm_path.as_deref());

    let candidate_bytes = fs::read(&c_path).map_err(|err| {
        format!(
            "failed to read candidate catalog at '{}': {err}",
            c_path.display()
        )
    })?;

    let candidate: AssessmentCatalog = serde_json::from_slice(&candidate_bytes)
        .map_err(|err| format!("invalid candidate catalog JSON: {err}"))?;
    candidate
        .validate_integrity()
        .map_err(|err| format!("candidate catalog failed integrity check: {err}"))?;

    let mut counter = open_monotonic_counter(&t_path);

    let service = open_authority_service(&data_dir)
        .map_err(|err| format!("failed to initialize authority service: {err}"))?;

    service
        .execute_catalog_update(&candidate, &mut counter)
        .map_err(|err| format!("catalog update transaction failed: {err}"))?;

    println!("CATALOG_UPDATE: SUCCESS");
    println!("VERSION: {}", candidate.version);
    println!("COUNTER: {}", candidate.counter);
    println!("PAYLOAD_HASH: {}", candidate.payload_hash);

    Ok(())
}

fn run_authority_recover_catalog(args: &[String]) -> Result<(), String> {
    let data_dir = get_data_dir(args);
    let mut tpm_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        if args[i] == "--tpm" {
            i += 1;
            if i < args.len() {
                tpm_path = Some(PathBuf::from(&args[i]));
            }
        }
        i += 1;
    }

    let t_path = resolve_tpm_device_path(tpm_path.as_deref());

    let counter = open_monotonic_counter(&t_path);

    let service = open_authority_service(&data_dir)
        .map_err(|err| format!("failed to initialize authority service: {err}"))?;

    let outcome = service
        .recover_catalog(&counter)
        .map_err(|err| format!("catalog recovery failed: {err}"))?;

    let outcome_str = match outcome {
        RecoveryOutcome::CleanCurrent => "CleanCurrent",
        RecoveryOutcome::RolledBackUnincremented => "RolledBackUnincremented",
        RecoveryOutcome::RolledBackPreIncrement => "RolledBackPreIncrement",
        RecoveryOutcome::RecoveredPromotedNew => "RecoveredPromotedNew",
        RecoveryOutcome::RecoveredCompletedExisting => "RecoveredCompletedExisting",
        RecoveryOutcome::RecoveredViaStagedPromotion => "RecoveredViaStagedPromotion",
    };

    println!("CATALOG_RECOVERY: SUCCESS");
    println!("OUTCOME: {outcome_str}");

    if let Ok(active) = service.load_active_catalog() {
        println!("ACTIVE_VERSION: {}", active.version);
        println!("ACTIVE_COUNTER: {}", active.counter);
    }

    Ok(())
}

fn run_authority_catalog_init(args: &[String]) -> Result<(), String> {
    let data_dir = get_data_dir(args);
    let mut version: u64 = 1;
    let mut counter: u64 = 1;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--version" => {
                i += 1;
                if i < args.len() {
                    if let Ok(v) = args[i].parse::<u64>() {
                        version = v;
                    }
                }
            }
            "--counter" => {
                i += 1;
                if i < args.len() {
                    if let Ok(c) = args[i].parse::<u64>() {
                        counter = c;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    let catalog_mgr = CatalogManager::open(data_dir.join("catalog"))
        .map_err(|err| format!("failed to open catalog manager: {err}"))?;

    let base_catalog = AssessmentCatalog::new(
        version,
        counter,
        serde_json::json!({"baseline": "initial_m3_d4", "version": version}),
    )
    .map_err(|err| format!("failed to construct baseline catalog: {err}"))?;

    catalog_mgr
        .initialize_new(&base_catalog)
        .map_err(|err| format!("failed to initialize catalog: {err}"))?;

    println!("CATALOG_INIT: SUCCESS");
    println!("VERSION: {version}");
    println!("COUNTER: {counter}");
    println!("PAYLOAD_HASH: {}", base_catalog.payload_hash);

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_authority_serve_tls(args: &[String]) -> Result<(), String> {
    let data_dir = get_data_dir(args);
    let mut bind_addr = "127.0.0.1:8443".to_string();
    let mut cert_path: Option<PathBuf> = None;
    let mut key_path: Option<PathBuf> = None;
    let mut secret_path: Option<PathBuf> = None;
    let mut once = false;
    let mut max_requests: Option<usize> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                if i < args.len() {
                    bind_addr.clone_from(&args[i]);
                }
            }
            "--cert" => {
                i += 1;
                if i < args.len() {
                    cert_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--key" => {
                i += 1;
                if i < args.len() {
                    key_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--secret-file" => {
                i += 1;
                if i < args.len() {
                    secret_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--once" => {
                once = true;
            }
            "--max-requests" => {
                i += 1;
                if i < args.len() {
                    max_requests = args[i].parse::<usize>().ok();
                }
            }
            _ => {}
        }
        i += 1;
    }

    let c_path =
        cert_path.ok_or_else(|| "missing mandatory argument: --cert <PATH>".to_string())?;
    let k_path = key_path.ok_or_else(|| "missing mandatory argument: --key <PATH>".to_string())?;
    let s_path = secret_path
        .ok_or_else(|| "missing mandatory argument: --secret-file <PATH>".to_string())?;

    let certs = openaudit_core::protocol::load_certificates_from_file(&c_path)
        .map_err(|err| format!("failed to load server certificate: {err}"))?;
    let key = openaudit_core::protocol::load_private_key_from_file(&k_path)
        .map_err(|err| format!("failed to load server private key: {err}"))?;

    let server_config = openaudit_core::protocol::build_tls13_server_config(certs, key)
        .map_err(|err| format!("failed to build TLS 1.3 server config: {err}"))?;
    let server_config = Arc::new(server_config);

    let secret_bytes = read_strict_secret_file(&s_path)?;
    let secret = SharedSecret(secret_bytes);

    let listener = std::net::TcpListener::bind(&bind_addr)
        .map_err(|err| format!("failed to bind TLS server to '{bind_addr}': {err}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|err| format!("failed to get local address: {err}"))?;

    println!("TLS_SERVER_LISTENING: {local_addr}");
    println!("TLS_VERSION: TLSv1.3");

    let limit = if once { Some(1) } else { max_requests };
    let mut handled = 0;

    let service = open_authority_service(&data_dir)
        .map_err(|err| format!("failed to initialize authority service: {err}"))?;

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(err) => {
                eprintln!("failed to accept connection: {err}");
                continue;
            }
        };

        let conn = match rustls::ServerConnection::new(server_config.clone()) {
            Ok(c) => c,
            Err(err) => {
                eprintln!("failed to create TLS connection: {err}");
                continue;
            }
        };

        let mut tls_stream = rustls::StreamOwned::new(conn, stream);

        match openaudit_core::protocol::read_framed(
            &mut tls_stream,
            openaudit_core::protocol::MAX_FRAMED_MESSAGE_BYTES,
        ) {
            Ok(req_bytes) => {
                let now = current_time_ns().unwrap_or_else(|_| TimestampNs::from_nanos(0));
                let resp = openaudit_core::protocol::dispatch_authority_request(
                    &req_bytes, &service, &secret, now,
                )
                .unwrap_or_else(|err| {
                    openaudit_core::protocol::TlsProtocolResponse::Error {
                        code: "MALFORMED_REQUEST".to_string(),
                        message: err.to_string(),
                    }
                });

                let resp_bytes = serde_json::to_vec(&resp).unwrap_or_default();
                let _ = openaudit_core::protocol::write_framed(&mut tls_stream, &resp_bytes);
            }
            Err(err) => {
                eprintln!("TLS framing/handshake error: {err}");
            }
        }

        handled += 1;
        if let Some(max) = limit {
            if handled >= max {
                break;
            }
        }
    }

    Ok(())
}

fn run_serve(args: &[String]) -> Result<(), String> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    let mut config = openaudit_server::config::ServerConfig::from_env()?;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                i += 1;
                if i < args.len() {
                    config.bind_addr = args[i]
                        .parse()
                        .map_err(|e| format!("Invalid --bind address: {e}"))?;
                }
            }
            "--port" => {
                i += 1;
                if i < args.len() {
                    let p: u16 = args[i]
                        .parse()
                        .map_err(|e| format!("Invalid --port: {e}"))?;
                    config.bind_addr.set_port(p);
                }
            }
            "--data-dir" => {
                i += 1;
                if i < args.len() {
                    config.data_dir = PathBuf::from(&args[i]);
                }
            }
            _ => {}
        }
        i += 1;
    }

    config.validate()?;

    fs::create_dir_all(&config.data_dir)
        .map_err(|e| format!("Failed to create data directory: {e}"))?;

    let store_path = config.data_dir.join("control_plane.db");
    let store = Arc::new(
        openaudit_server::store::sqlite::SqliteControlPlaneStore::open(&store_path)
            .map_err(|e| format!("Failed to open control plane store: {e}"))?,
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to start tokio runtime: {e}"))?;

    rt.block_on(async {
        openaudit_server::run_server(config, store)
            .await
            .map_err(|e| e.to_string())
    })
}

/// Dispatches command line arguments to subcommands.
///
/// # Errors
/// Returns an error string if mandatory options are missing or subcommands fail.
pub fn run(args: &[String]) -> Result<(), String> {
    if args.len() < 2 {
        print_help();
        return Ok(());
    }

    match args[1].as_str() {
        "serve" | "start" => run_serve(&args[2..]),
        "version" | "--version" | "-V" => {
            print_version();
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "authority" => {
            if args.len() < 3 {
                return Err("missing authority subcommand: status, token-issue, process-enrollment, process-retrieval, catalog-init, catalog-update, recover-catalog".to_string());
            }
            match args[2].as_str() {
                "status" => run_authority_status(&args[3..]),
                "token-issue" => run_authority_token_issue(&args[3..]),
                "process-enrollment" => run_authority_process_enrollment(&args[3..]),
                "process-retrieval" => run_authority_process_retrieval(&args[3..]),
                "catalog-init" => run_authority_catalog_init(&args[3..]),
                "catalog-update" => run_authority_catalog_update(&args[3..]),
                "recover-catalog" => run_authority_recover_catalog(&args[3..]),
                "serve-tls" => run_authority_serve_tls(&args[3..]),
                other => Err(format!("unknown authority subcommand: '{other}'")),
            }
        }
        other => Err(format!("unknown command: '{other}'")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openaudit_core::protocol::crypto::compute_hmac_sha256;
    use openaudit_core::protocol::types::{
        CatalogVersion, CounterValue, LifecycleId, RequestId, RetrievalMessage, SrkName,
        TransactionId,
    };

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let dir = env::temp_dir().join(format!("openaudit_server_test_{}", MachineId::new()));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_server_entry_point() {
        assert_ne!(openaudit_core::version(), "");
    }

    #[test]
    fn test_secret_file_validation_strict_mode() {
        let temp = TestDir::new();
        let secret_path = temp.path().join("test.secret");
        let secret_bytes = [42u8; 32];

        // 1. Create file with valid 0600 permissions
        fs::write(&secret_path, secret_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let loaded = read_strict_secret_file(&secret_path).expect("mode 0600 must pass");
        assert_eq!(loaded, secret_bytes);

        // 2. Reject insecure permissions (e.g. 0644) on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644)).unwrap();
            let err = read_strict_secret_file(&secret_path).unwrap_err();
            assert!(
                err.contains("insecure permissions"),
                "expected permission error: {err}"
            );
            // Reset to 0600
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        // 3. Reject invalid size (not 32 bytes)
        let bad_size_path = temp.path().join("bad_size.secret");
        fs::write(&bad_size_path, [1u8; 16]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bad_size_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let err = read_strict_secret_file(&bad_size_path).unwrap_err();
        assert!(
            err.contains("expected exactly 32 bytes"),
            "expected size error: {err}"
        );

        // 4. Reject symlink
        #[cfg(unix)]
        {
            let symlink_path = temp.path().join("symlink.secret");
            std::os::unix::fs::symlink(&secret_path, &symlink_path).unwrap();
            let err = read_strict_secret_file(&symlink_path).unwrap_err();
            assert!(
                err.contains("not a regular file"),
                "expected symlink rejection: {err}"
            );
        }
    }

    #[test]
    fn test_hex_encode_decode_roundtrip() {
        let original = vec![0x00, 0x01, 0x0F, 0x10, 0xFF, 0xAA, 0x55];
        let hex = encode_hex(&original);
        assert_eq!(hex, "00010f10ffaa55");
        let decoded = decode_hex(&hex).unwrap();
        assert_eq!(decoded, original);

        assert!(decode_hex("abc").is_err(), "odd length must fail");
        assert!(decode_hex("zz").is_err(), "invalid hex chars must fail");
    }

    #[test]
    fn test_server_authority_status_cli() {
        let temp = TestDir::new();
        let data_dir = temp.path().join("authority_data");

        let args = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "status".to_string(),
            "--data-dir".to_string(),
            data_dir.to_str().unwrap().to_string(),
        ];

        let result = run(&args);
        assert!(result.is_ok(), "status run must succeed: {result:?}");
        assert!(data_dir.join("authority.db").is_file());
        assert!(data_dir.join("replay.db").is_file());
        assert!(data_dir.join("catalog").is_dir());
    }

    #[test]
    fn test_server_token_issue_cli_full_contract() {
        let temp = TestDir::new();
        let data_dir = temp.path().join("authority_data");
        let mach_id = MachineId::new();
        let nonce = [7u8; 32];
        let nonce_hex = encode_hex(&nonce);

        let args = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "token-issue".to_string(),
            "--machine-id".to_string(),
            mach_id.to_string(),
            "--nonce".to_string(),
            nonce_hex,
            "--generation".to_string(),
            "1".to_string(),
            "--ttl-secs".to_string(),
            "300".to_string(),
            "--data-dir".to_string(),
            data_dir.to_str().unwrap().to_string(),
        ];

        let res = run(&args);
        assert!(res.is_ok(), "token-issue command must succeed: {res:?}");
    }

    #[test]
    fn test_server_process_enrollment_and_retrieval_cli() {
        let temp = TestDir::new();
        let data_dir = temp.path().join("authority_data");
        let secret_path = temp.path().join("shared.secret");
        let secret_bytes = [0x5A; 32];

        fs::write(&secret_path, secret_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        // Initialize active catalog so baseline matches
        let cat_mgr = CatalogManager::open(data_dir.join("catalog")).unwrap();
        let base_catalog =
            AssessmentCatalog::new(1, 1, serde_json::json!({"baseline": "v1.0"})).unwrap();
        cat_mgr.initialize_new(&base_catalog).unwrap();

        let mach_id = MachineId::new();
        let nonce = [0x11; 32];
        let tx_id = TransactionId::new();
        let now = current_time_ns().unwrap();

        // Issue token using service
        let service = open_authority_service(&data_dir).unwrap();
        let issued = service
            .issue_enrollment_token(
                mach_id,
                ChallengeNonce(nonce),
                EnrollmentGeneration(1),
                300_000_000_000,
                now,
            )
            .unwrap();

        // Valid NIST P-256 SPKI DER
        let spki_der = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x6b,
            0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
            0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8,
            0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
            0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb,
            0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];

        let transcript = EnrollmentTranscript {
            nonce_auth: ChallengeNonce(nonce),
            token_id: issued.token_id,
            tx_id,
            machine_id: mach_id,
            ek_pub: spki_der,
            name_srk: SrkName([0xAA; 34]),
            lifecycle_id: LifecycleId([0xBB; 32]),
            generation_mach: EnrollmentGeneration(1),
            counter_base: CounterValue(1),
            catalog_base: CatalogVersion(1),
            timestamp_issued: TimestampNs::from_nanos(now.as_nanos() - 1_000_000_000),
            timestamp_expires: TimestampNs::from_nanos(now.as_nanos() + 300_000_000_000),
        };

        let raw_transcript = transcript.serialize_canonical().unwrap();
        let proof = compute_hmac_sha256(&SharedSecret(secret_bytes), &raw_transcript);

        // Run process-enrollment CLI
        let enroll_args = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "process-enrollment".to_string(),
            "--transcript".to_string(),
            encode_hex(&raw_transcript),
            "--proof".to_string(),
            encode_hex(&proof),
            "--secret-file".to_string(),
            secret_path.to_str().unwrap().to_string(),
            "--data-dir".to_string(),
            data_dir.to_str().unwrap().to_string(),
        ];

        let enroll_res = run(&enroll_args);
        assert!(
            enroll_res.is_ok(),
            "process-enrollment must succeed: {enroll_res:?}"
        );

        // Now run process-retrieval CLI
        let msg = RetrievalMessage {
            machine_id: mach_id,
            tx_id,
            req_id: RequestId::new(),
            t_req: current_time_ns().unwrap(),
        };
        let raw_req = msg.serialize_canonical();
        let req_proof = compute_hmac_sha256(&SharedSecret(secret_bytes), &raw_req);

        let retrieve_args = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "process-retrieval".to_string(),
            "--request".to_string(),
            encode_hex(&raw_req),
            "--proof".to_string(),
            encode_hex(&req_proof),
            "--secret-file".to_string(),
            secret_path.to_str().unwrap().to_string(),
            "--data-dir".to_string(),
            data_dir.to_str().unwrap().to_string(),
        ];

        let retrieve_res = run(&retrieve_args);
        assert!(
            retrieve_res.is_ok(),
            "process-retrieval must succeed: {retrieve_res:?}"
        );
    }

    #[test]
    fn test_server_retrieval_replay_rejection_fail_closed() {
        let temp = TestDir::new();
        let data_dir = temp.path().join("authority_data");
        let secret_path = temp.path().join("shared.secret");
        let secret_bytes = [0x5A; 32];

        fs::write(&secret_path, secret_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let mach_id = MachineId::new();
        let tx_id = TransactionId::new();
        let msg = RetrievalMessage {
            machine_id: mach_id,
            tx_id,
            req_id: RequestId::new(),
            t_req: current_time_ns().unwrap(),
        };
        let raw_req = msg.serialize_canonical();
        let req_proof = compute_hmac_sha256(&SharedSecret(secret_bytes), &raw_req);

        let retrieve_args = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "process-retrieval".to_string(),
            "--request".to_string(),
            encode_hex(&raw_req),
            "--proof".to_string(),
            encode_hex(&req_proof),
            "--secret-file".to_string(),
            secret_path.to_str().unwrap().to_string(),
            "--data-dir".to_string(),
            data_dir.to_str().unwrap().to_string(),
        ];

        // First attempt succeeds
        let res1 = run(&retrieve_args);
        assert!(res1.is_ok(), "first retrieval attempt must succeed");

        // Duplicate replay must fail closed
        let res2 = run(&retrieve_args);
        assert!(res2.is_err(), "replayed retrieval must fail closed");
        let err_msg = res2.unwrap_err();
        assert!(
            err_msg.contains("retrieval validation failed"),
            "expected replay failure: {err_msg}"
        );
    }

    #[test]
    fn test_server_missing_arguments_error_handling() {
        let bad_token = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "token-issue".to_string(),
        ];
        assert!(run(&bad_token).is_err());

        let bad_enroll = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "process-enrollment".to_string(),
        ];
        assert!(run(&bad_enroll).is_err());

        let bad_retrieve = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "process-retrieval".to_string(),
        ];
        assert!(run(&bad_retrieve).is_err());
    }

    #[test]
    fn test_server_catalog_init_cli() {
        let temp = TestDir::new();
        let data_dir = temp.path().join("authority_data");

        let init_args = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "catalog-init".to_string(),
            "--version".to_string(),
            "1".to_string(),
            "--counter".to_string(),
            "1".to_string(),
            "--data-dir".to_string(),
            data_dir.to_str().unwrap().to_string(),
        ];

        let res = run(&init_args);
        assert!(res.is_ok(), "catalog-init must succeed: {res:?}");
        assert!(data_dir.join("catalog").join("catalog.json").is_file());

        // Second init must fail because active catalog already exists
        let res2 = run(&init_args);
        assert!(res2.is_err(), "second catalog-init must fail: {res2:?}");
    }

    #[test]
    fn test_server_default_tpmrm_resolution_diagnostic() {
        let temp = TestDir::new();
        let data_dir = temp.path().join("authority_data");

        // Initialize base catalog first
        let init_args = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "catalog-init".to_string(),
            "--data-dir".to_string(),
            data_dir.to_str().unwrap().to_string(),
        ];
        run(&init_args).expect("base catalog init must succeed");

        // Create a dummy candidate catalog
        let candidate_path = temp.path().join("candidate.json");
        let candidate = AssessmentCatalog::new(2, 2, serde_json::json!({"v": 2})).unwrap();
        fs::write(
            &candidate_path,
            serde_json::to_vec_pretty(&candidate).unwrap(),
        )
        .unwrap();

        // Catalog update without --tpm defaults to /dev/tpmrm0 (or /dev/tpm0)
        let update_args = vec![
            "openaudit-server".to_string(),
            "authority".to_string(),
            "catalog-update".to_string(),
            "--candidate".to_string(),
            candidate_path.to_str().unwrap().to_string(),
            "--data-dir".to_string(),
            data_dir.to_str().unwrap().to_string(),
        ];

        let res = run(&update_args);
        if !Path::new("/dev/tpmrm0").exists() && !Path::new("/dev/tpm0").exists() {
            assert!(res.is_err(), "must fail when hardware TPM device is absent");
            let err = res.err().unwrap();
            assert!(
                err.contains("TPM 2.0 device node not found")
                    || err.contains("failed to open TPM device node")
                    || err.contains("TPM socket connect failed"),
                "error must provide diagnostic context: {err}"
            );
        }
    }
}
