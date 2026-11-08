//! # OpenAudit Agent
//!
//! Node attestation and outbox retrieval client binary for OpenAudit M3 D4.
//!
//! Provides the host-level command-line interface for:
//! 1. Executing the 4-state TPM 2.0 provisioning lifecycle (§7.1).
//! 2. Constructing canonical 14-element enrollment transcripts with HMAC-SHA256 proofs (§7.2).
//! 3. Constructing 5-element canonical outbox retrieval requests with single-use nonces (§7.3).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use openaudit_core::protocol::agent::{AgentAttestationClient, AgentCredentials};
use openaudit_core::protocol::catalog::MonotonicCounter;
use openaudit_core::protocol::crypto::compute_hmac_sha256;
use openaudit_core::protocol::error::ProtocolError;
use openaudit_core::protocol::tpm::{
    resolve_tpm_device_path, DeviceTransport, ProvisioningState, TpmClient, TpmCounterConfig,
    TpmMonotonicCounter, TpmProvisioningManager, UnixSocketTransport,
};
use openaudit_core::protocol::types::{
    CatalogVersion, ChallengeNonce, EnrollmentGeneration, EnrollmentTokenId, LifecycleId,
    MachineId, RequestId, RetrievalMessage, SharedSecret, SrkName, TimestampNs, TransactionId,
};

/// Default standard NIST P-256 SPKI DER public key structure (91 bytes).
const DEFAULT_EK_SPKI: [u8; 91] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1,
    0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d,
    0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe,
    0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b,
    0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

/// Multi-transport adapter satisfying [`MonotonicCounter`] for agent operations.
enum AgentMonotonicCounter {
    Socket(TpmMonotonicCounter<UnixSocketTransport>),
    Device(TpmMonotonicCounter<DeviceTransport>),
}

impl MonotonicCounter for AgentMonotonicCounter {
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

/// Opens a hardware character device or software socket as an [`AgentMonotonicCounter`].
fn open_monotonic_counter(tpm_path: &Path) -> AgentMonotonicCounter {
    if !is_socket_path(tpm_path) {
        let client = TpmClient::new(DeviceTransport::new(tpm_path));
        return AgentMonotonicCounter::Device(TpmMonotonicCounter::new(
            client,
            TpmCounterConfig::default(),
        ));
    }

    let client = TpmClient::new(UnixSocketTransport::new(tpm_path));
    AgentMonotonicCounter::Socket(TpmMonotonicCounter::new(
        client,
        TpmCounterConfig::default(),
    ))
}

/// Executes TPM provisioning lifecycle using either character device or Unix socket.
fn execute_provisioning(
    tpm_path: &Path,
    state_dir: &Path,
    rotate: bool,
    override_quarantine: bool,
) -> Result<(ProvisioningState, u64), ProtocolError> {
    if !is_socket_path(tpm_path) {
        let client = TpmClient::new(DeviceTransport::new(tpm_path));
        let mut mgr = TpmProvisioningManager::new(client, state_dir);
        let state = mgr.determine_state(rotate)?;
        let counter = mgr.execute(rotate, override_quarantine, None)?;
        return Ok((state, counter));
    }

    let client = TpmClient::new(UnixSocketTransport::new(tpm_path));
    let mut mgr = TpmProvisioningManager::new(client, state_dir);
    let state = mgr.determine_state(rotate)?;
    let counter = mgr.execute(rotate, override_quarantine, None)?;
    Ok((state, counter))
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

/// Decodes exactly 16 bytes from a 32-character hex string.
fn decode_hex_16(s: &str) -> Result<[u8; 16], String> {
    let bytes = decode_hex(s)?;
    bytes.try_into().map_err(|vec: Vec<u8>| {
        format!(
            "expected 16 bytes (32 hex characters), received {}",
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

/// Writes `data` to `path` with restrictive mode `0600` permissions.
fn write_strict_file(path: &Path, data: &[u8]) -> Result<(), String> {
    fs::write(path, data)
        .map_err(|err| format!("failed to write file '{}': {err}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

fn print_help() {
    println!(
        "OpenAudit Agent v{}\n\n\
        Usage: openaudit-agent <COMMAND> [OPTIONS]\n\n\
        Commands:\n  \
          provision            Execute four-state TPM provisioning lifecycle\n  \
          enroll               Assemble 14-element enrollment transcript and sign HMAC proof\n  \
          retrieve             Assemble 5-element retrieval request (89 bytes) and sign HMAC proof\n  \
          version              Print version information\n  \
          help                 Print this help message\n\n\
        Options:\n  \
          --tpm <PATH>         Path to TPM character device or Unix socket [default: /dev/tpmrm0]\n  \
          --state-dir <DIR>    Node credentials directory\n  \
          --secret-file <PATH> Path to 32-byte secret file (mode 0600)\n",
        openaudit_core::version()
    );
}

fn print_version() {
    println!("OpenAudit Agent v{}", openaudit_core::version());
}

#[allow(clippy::too_many_lines)]
fn run_provision(args: &[String]) -> Result<(), String> {
    let mut tpm_path: Option<PathBuf> = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut rotate = false;
    let mut override_quarantine = false;
    let mut machine_id_arg: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tpm" => {
                i += 1;
                if i < args.len() {
                    tpm_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--state-dir" => {
                i += 1;
                if i < args.len() {
                    state_dir = Some(PathBuf::from(&args[i]));
                }
            }
            "--rotate" => {
                rotate = true;
            }
            "--override-quarantine" => {
                override_quarantine = true;
            }
            "--machine-id" | "--machine" => {
                i += 1;
                if i < args.len() {
                    machine_id_arg = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    let t_path = resolve_tpm_device_path(tpm_path.as_deref());
    let s_dir =
        state_dir.ok_or_else(|| "missing mandatory argument: --state-dir <DIR>".to_string())?;

    fs::create_dir_all(&s_dir).map_err(|err| {
        format!(
            "failed to create state directory '{}': {err}",
            s_dir.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&s_dir, fs::Permissions::from_mode(0o700));
    }

    let (state, baseline_counter) =
        execute_provisioning(&t_path, &s_dir, rotate, override_quarantine)
            .map_err(|err| format!("provisioning execution failed: {err}"))?;

    // Manage machine_id persistence
    let machine_id_path = s_dir.join("machine_id.txt");
    let machine_id = if let Some(m_str) = machine_id_arg {
        let m = MachineId::parse(&m_str).map_err(|err| format!("invalid --machine-id: {err}"))?;
        write_strict_file(&machine_id_path, m.to_string().as_bytes())?;
        m
    } else if machine_id_path.is_file() {
        let content = fs::read_to_string(&machine_id_path)
            .map_err(|err| format!("failed to read machine_id.txt: {err}"))?;
        MachineId::parse(content.trim()).map_err(|err| format!("corrupt machine_id.txt: {err}"))?
    } else {
        let fresh = MachineId::new();
        write_strict_file(&machine_id_path, fresh.to_string().as_bytes())?;
        fresh
    };

    // Manage generation persistence
    let gen_path = s_dir.join("generation.txt");
    let generation = match state {
        ProvisioningState::FreshProvisioning => {
            write_strict_file(&gen_path, b"1")?;
            1u32
        }
        ProvisioningState::ExplicitCredentialRotation => {
            let current = if gen_path.is_file() {
                fs::read_to_string(&gen_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(1)
            } else {
                1
            };
            let next = current + 1;
            write_strict_file(&gen_path, next.to_string().as_bytes())?;
            next
        }
        ProvisioningState::ExistingValidationAndRecovery
        | ProvisioningState::TpmClearOrLifecycleMismatchQuarantine => {
            if gen_path.is_file() {
                fs::read_to_string(&gen_path)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(1)
            } else {
                write_strict_file(&gen_path, b"1")?;
                1
            }
        }
    };

    // Persist default template credentials if not present
    let ek_path = s_dir.join("ek_pub.der");
    if !ek_path.is_file() {
        let _ = write_strict_file(&ek_path, &DEFAULT_EK_SPKI);
    }

    let srk_path = s_dir.join("name_srk.bin");
    if !srk_path.is_file() {
        let mut srk = [0xAAu8; 34];
        srk[0..2].copy_from_slice(&0x000Bu16.to_be_bytes());
        let _ = write_strict_file(&srk_path, &srk);
    }

    let state_str = match state {
        ProvisioningState::FreshProvisioning => "FreshProvisioning",
        ProvisioningState::ExistingValidationAndRecovery => "ExistingValidationAndRecovery",
        ProvisioningState::ExplicitCredentialRotation => "ExplicitCredentialRotation",
        ProvisioningState::TpmClearOrLifecycleMismatchQuarantine => {
            "TpmClearOrLifecycleMismatchQuarantine"
        }
    };

    println!("PROVISIONING_STATE: {state_str}");
    println!("BASELINE_COUNTER: {baseline_counter}");
    println!("MACHINE_ID: {machine_id}");
    println!("GENERATION: {generation}");
    println!("STATE_DIR: {}", s_dir.display());

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn run_enroll(args: &[String]) -> Result<(), String> {
    let mut token_id_hex: Option<String> = None;
    let mut nonce_hex: Option<String> = None;
    let mut tpm_path: Option<PathBuf> = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut secret_path: Option<PathBuf> = None;
    let mut tx_id_arg: Option<String> = None;
    let mut catalog_base_arg: u64 = 1;
    let mut expires_at_arg: Option<i64> = None;
    let mut ttl_secs_arg: u64 = 60;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--token-id" => {
                i += 1;
                if i < args.len() {
                    token_id_hex = Some(args[i].clone());
                }
            }
            "--nonce" => {
                i += 1;
                if i < args.len() {
                    nonce_hex = Some(args[i].clone());
                }
            }
            "--tpm" => {
                i += 1;
                if i < args.len() {
                    tpm_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--state-dir" => {
                i += 1;
                if i < args.len() {
                    state_dir = Some(PathBuf::from(&args[i]));
                }
            }
            "--secret-file" => {
                i += 1;
                if i < args.len() {
                    secret_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--tx-id" => {
                i += 1;
                if i < args.len() {
                    tx_id_arg = Some(args[i].clone());
                }
            }
            "--catalog-base" => {
                i += 1;
                if i < args.len() {
                    if let Ok(v) = args[i].parse::<u64>() {
                        catalog_base_arg = v;
                    }
                }
            }
            "--expires-at-ns" => {
                i += 1;
                if i < args.len() {
                    expires_at_arg = args[i].parse::<i64>().ok();
                }
            }
            "--ttl-secs" => {
                i += 1;
                if i < args.len() {
                    if let Ok(v) = args[i].parse::<u64>() {
                        ttl_secs_arg = v;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    let tok_hex =
        token_id_hex.ok_or_else(|| "missing mandatory argument: --token-id <HEX>".to_string())?;
    let non_hex =
        nonce_hex.ok_or_else(|| "missing mandatory argument: --nonce <HEX>".to_string())?;
    let t_path = resolve_tpm_device_path(tpm_path.as_deref());
    let s_dir =
        state_dir.ok_or_else(|| "missing mandatory argument: --state-dir <DIR>".to_string())?;

    let token_bytes = decode_hex_16(&tok_hex)?;
    let token_id = EnrollmentTokenId::from_bytes(token_bytes);

    let nonce_bytes = decode_hex_32(&non_hex)?;
    let nonce = ChallengeNonce::from_bytes(nonce_bytes);

    // Load secret file
    let s_path = secret_path.unwrap_or_else(|| s_dir.join("tpm-auth.secret"));
    let secret_bytes = read_strict_secret_file(&s_path)?;

    // Load machine ID
    let machine_id_path = s_dir.join("machine_id.txt");
    let machine_id = if machine_id_path.is_file() {
        let content = fs::read_to_string(&machine_id_path)
            .map_err(|err| format!("failed to read machine_id.txt: {err}"))?;
        MachineId::parse(content.trim()).map_err(|err| format!("corrupt machine_id.txt: {err}"))?
    } else {
        return Err(format!(
            "machine_id.txt not found in '{}'; run 'provision' first",
            s_dir.display()
        ));
    };

    // Load lifecycle ID
    let lifecycle_path = s_dir.join("lifecycle_id.bin");
    let lc_bytes = fs::read(&lifecycle_path).map_err(|err| {
        format!(
            "failed to read lifecycle_id.bin at '{}': {err}",
            lifecycle_path.display()
        )
    })?;
    if lc_bytes.len() != 32 {
        return Err(format!(
            "invalid lifecycle_id.bin size: expected 32, read {}",
            lc_bytes.len()
        ));
    }
    let mut lc_arr = [0u8; 32];
    lc_arr.copy_from_slice(&lc_bytes);
    let lifecycle_id = LifecycleId::from_bytes(lc_arr);

    // Load generation
    let gen_path = s_dir.join("generation.txt");
    let generation_val = if gen_path.is_file() {
        fs::read_to_string(&gen_path)
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(1)
    } else {
        1
    };
    let generation = EnrollmentGeneration::from_u32(generation_val);

    // Load EK public key
    let ek_path = s_dir.join("ek_pub.der");
    let ek_pub = if ek_path.is_file() {
        fs::read(&ek_path).unwrap_or_else(|_| DEFAULT_EK_SPKI.to_vec())
    } else {
        DEFAULT_EK_SPKI.to_vec()
    };

    // Load SRK name
    let srk_path = s_dir.join("name_srk.bin");
    let name_srk = if srk_path.is_file() {
        let bytes = fs::read(&srk_path).unwrap_or_default();
        if bytes.len() == 34 {
            let mut arr = [0u8; 34];
            arr.copy_from_slice(&bytes);
            SrkName::from_bytes(arr)
        } else {
            let mut arr = [0xAAu8; 34];
            arr[0..2].copy_from_slice(&0x000Bu16.to_be_bytes());
            SrkName::from_bytes(arr)
        }
    } else {
        let mut arr = [0xAAu8; 34];
        arr[0..2].copy_from_slice(&0x000Bu16.to_be_bytes());
        SrkName::from_bytes(arr)
    };

    let tx_id = if let Some(t_str) = tx_id_arg {
        TransactionId::parse(&t_str).map_err(|err| format!("invalid --tx-id: {err}"))?
    } else {
        TransactionId::new()
    };

    let counter = Arc::new(Mutex::new(open_monotonic_counter(&t_path)));
    let creds = AgentCredentials {
        machine_id,
        shared_secret: SharedSecret::from_bytes(secret_bytes),
        ek_pub,
        name_srk,
        lifecycle_id,
        generation,
    };

    let client = AgentAttestationClient::new(creds, counter);

    let now = current_time_ns()?;
    let t_issued = now;
    let t_expires = expires_at_arg.map_or_else(
        || {
            let ttl_nanos = ttl_secs_arg
                .checked_mul(1_000_000_000)
                .unwrap_or(60_000_000_000);
            TimestampNs::from_nanos(
                now.as_nanos() + i64::try_from(ttl_nanos).unwrap_or(60_000_000_000),
            )
        },
        TimestampNs::from_nanos,
    );

    let (transcript, proof) = client
        .construct_enrollment_transcript(
            nonce,
            token_id,
            tx_id,
            CatalogVersion::from_u64(catalog_base_arg),
            t_issued,
            t_expires,
        )
        .map_err(|err| format!("enrollment transcript construction failed: {err}"))?;

    let canonical_bytes = transcript
        .serialize_canonical()
        .map_err(|err| format!("failed to serialize transcript: {err}"))?;

    println!("ENROLLMENT_TRANSCRIPT: {}", encode_hex(&canonical_bytes));
    println!("HMAC_PROOF: {}", encode_hex(&proof));
    println!("MACHINE_ID: {}", transcript.machine_id);
    println!("TOKEN_ID: {}", encode_hex(transcript.token_id.as_bytes()));
    println!("COUNTER_BASE: {}", transcript.counter_base.as_u64());

    Ok(())
}

fn run_retrieve(args: &[String]) -> Result<(), String> {
    let mut machine_id_arg: Option<String> = None;
    let mut tx_id_arg: Option<String> = None;
    let mut secret_path: Option<PathBuf> = None;
    let mut state_dir: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--machine-id" | "--machine" => {
                i += 1;
                if i < args.len() {
                    machine_id_arg = Some(args[i].clone());
                }
            }
            "--tx-id" => {
                i += 1;
                if i < args.len() {
                    tx_id_arg = Some(args[i].clone());
                }
            }
            "--secret-file" => {
                i += 1;
                if i < args.len() {
                    secret_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--state-dir" => {
                i += 1;
                if i < args.len() {
                    state_dir = Some(PathBuf::from(&args[i]));
                }
            }
            _ => {}
        }
        i += 1;
    }

    let tx_str =
        tx_id_arg.ok_or_else(|| "missing mandatory argument: --tx-id <UUID>".to_string())?;
    let tx_id = TransactionId::parse(&tx_str).map_err(|err| format!("invalid --tx-id: {err}"))?;

    // Determine secret file
    let s_path = if let Some(p) = secret_path {
        p
    } else if let Some(ref d) = state_dir {
        d.join("tpm-auth.secret")
    } else {
        return Err(
            "missing secret file: specify either --secret-file <PATH> or --state-dir <DIR>"
                .to_string(),
        );
    };
    let secret = read_strict_secret_file(&s_path)?;

    // Determine machine ID
    let machine_id = if let Some(m_str) = machine_id_arg {
        MachineId::parse(&m_str).map_err(|err| format!("invalid --machine-id: {err}"))?
    } else if let Some(ref d) = state_dir {
        let m_path = d.join("machine_id.txt");
        let content = fs::read_to_string(&m_path)
            .map_err(|err| format!("failed to read machine_id.txt: {err}"))?;
        MachineId::parse(content.trim()).map_err(|err| format!("corrupt machine_id.txt: {err}"))?
    } else {
        return Err(
            "missing machine ID: specify either --machine-id <UUID> or --state-dir <DIR>"
                .to_string(),
        );
    };

    let t_req = current_time_ns()?;
    let req_id = RequestId::new();

    let msg = RetrievalMessage {
        machine_id,
        tx_id,
        req_id,
        t_req,
    };

    let raw_payload = msg.serialize_canonical();
    let proof = compute_hmac_sha256(&SharedSecret::from_bytes(secret), &raw_payload);

    println!("RETRIEVAL_REQUEST: {}", encode_hex(&raw_payload));
    println!("HMAC_PROOF: {}", encode_hex(&proof));
    println!("MACHINE_ID: {machine_id}");
    println!("TX_ID: {tx_id}");
    println!("REQ_ID: {req_id}");
    println!("T_REQ: {}", t_req.as_nanos());

    Ok(())
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
        "version" | "--version" | "-V" => {
            print_version();
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "provision" => run_provision(&args[2..]),
        "enroll" => run_enroll(&args[2..]),
        "retrieve" => run_retrieve(&args[2..]),
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
    use std::process::{Child, Command};
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;

    static AGENT_TEST_MUTEX: Mutex<()> = Mutex::new(());

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let dir = env::temp_dir().join(format!("openaudit_agent_test_{}", MachineId::new()));
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

    struct LiveSwtpm {
        temp_dir: PathBuf,
        sock_path: PathBuf,
        child: Option<Child>,
    }

    impl LiveSwtpm {
        fn new() -> Option<Self> {
            let swtpm_bin = if Path::new("/opt/homebrew/bin/swtpm").is_file() {
                "/opt/homebrew/bin/swtpm".to_string()
            } else if let Ok(out) = Command::new("which").arg("swtpm").output() {
                if out.status.success() {
                    String::from_utf8_lossy(&out.stdout).trim().to_string()
                } else {
                    return None;
                }
            } else {
                return None;
            };

            let rand_suffix = (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                % 1_000_000_000) as u32;
            let temp_dir =
                PathBuf::from(format!("/tmp/oa_sw_{}_{rand_suffix}", std::process::id()));
            fs::create_dir_all(&temp_dir).ok()?;
            let ctrl_path = temp_dir.join("c.sock");
            let sock_path = temp_dir.join("t.sock");

            let child = Command::new(&swtpm_bin)
                .args([
                    "socket",
                    "--tpm2",
                    "--tpmstate",
                    &format!("dir={}", temp_dir.display()),
                    "--ctrl",
                    &format!("type=unixio,path={}", ctrl_path.display()),
                    "--server",
                    &format!("type=unixio,path={}", sock_path.display()),
                    "--flags",
                    "not-need-init,startup-clear",
                ])
                .spawn()
                .ok()?;

            let mut ready = false;
            for _ in 0..50 {
                thread::sleep(Duration::from_millis(50));
                if sock_path.exists() {
                    thread::sleep(Duration::from_millis(50));
                    ready = true;
                    break;
                }
            }

            if !ready {
                return None;
            }

            Some(Self {
                temp_dir,
                sock_path,
                child: Some(child),
            })
        }
    }

    impl Drop for LiveSwtpm {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }

    #[test]
    fn test_agent_entry_point() {
        assert_ne!(openaudit_core::version(), "");
    }

    #[test]
    fn test_strict_secret_file_validation() {
        let temp = TestDir::new();
        let secret_path = temp.path().join("agent.secret");
        let secret_bytes = [0x33u8; 32];

        fs::write(&secret_path, secret_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let loaded = read_strict_secret_file(&secret_path).expect("mode 0600 must pass");
        assert_eq!(loaded, secret_bytes);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o644)).unwrap();
            let err = read_strict_secret_file(&secret_path).unwrap_err();
            assert!(
                err.contains("insecure permissions"),
                "expected permission error: {err}"
            );
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let bad_size = temp.path().join("bad.secret");
        fs::write(&bad_size, [1u8; 16]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bad_size, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(read_strict_secret_file(&bad_size).is_err());

        #[cfg(unix)]
        {
            let symlink = temp.path().join("sym.secret");
            std::os::unix::fs::symlink(&secret_path, &symlink).unwrap();
            assert!(read_strict_secret_file(&symlink).is_err());
        }
    }

    #[test]
    fn test_agent_retrieve_pure_crypto_offline() {
        let temp = TestDir::new();
        let secret_path = temp.path().join("test.secret");
        let secret_bytes = [0x77u8; 32];

        fs::write(&secret_path, secret_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let mach_id = MachineId::new();
        let tx_id = TransactionId::new();

        let args = vec![
            "openaudit-agent".to_string(),
            "retrieve".to_string(),
            "--machine-id".to_string(),
            mach_id.to_string(),
            "--tx-id".to_string(),
            tx_id.to_string(),
            "--secret-file".to_string(),
            secret_path.to_str().unwrap().to_string(),
        ];

        let res = run(&args);
        assert!(
            res.is_ok(),
            "offline retrieve command must succeed: {res:?}"
        );
    }

    #[test]
    fn test_agent_missing_arguments_error_handling() {
        let bad_provision = vec!["openaudit-agent".to_string(), "provision".to_string()];
        assert!(run(&bad_provision).is_err());

        let bad_enroll = vec!["openaudit-agent".to_string(), "enroll".to_string()];
        assert!(run(&bad_enroll).is_err());

        let bad_retrieve = vec!["openaudit-agent".to_string(), "retrieve".to_string()];
        assert!(run(&bad_retrieve).is_err());
    }

    #[test]
    fn test_agent_default_tpmrm_resolution_diagnostic() {
        let temp = TestDir::new();
        let state_dir = temp.path().join("agent_state");

        // Omit --tpm: defaults to /dev/tpmrm0 (or /dev/tpm0)
        let prov_args = vec![
            "openaudit-agent".to_string(),
            "provision".to_string(),
            "--state-dir".to_string(),
            state_dir.to_str().unwrap().to_string(),
        ];

        let res = run(&prov_args);
        // On macOS / environments without /dev/tpmrm0, must fail with diagnostic
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

    #[test]
    fn test_agent_swtpm_fresh_and_existing_provisioning() {
        let _lock = AGENT_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(swtpm) = LiveSwtpm::new() else {
            eprintln!("swtpm not available; skipping swtpm execution test");
            return;
        };

        let temp = TestDir::new();
        let state_dir = temp.path().join("agent_state");

        // 1. Fresh provisioning
        let prov_args = vec![
            "openaudit-agent".to_string(),
            "provision".to_string(),
            "--tpm".to_string(),
            swtpm.sock_path.to_str().unwrap().to_string(),
            "--state-dir".to_string(),
            state_dir.to_str().unwrap().to_string(),
        ];

        let res1 = run(&prov_args);
        assert!(res1.is_ok(), "fresh provisioning must succeed: {res1:?}");
        assert!(state_dir.join("tpm-auth.secret").is_file());
        assert!(state_dir.join("lifecycle_id.bin").is_file());
        assert!(state_dir.join("machine_id.txt").is_file());
        assert!(state_dir.join("generation.txt").is_file());

        // 2. Existing provisioning (idempotent validation)
        let res2 = run(&prov_args);
        assert!(res2.is_ok(), "existing validation must succeed: {res2:?}");
    }

    #[test]
    fn test_agent_swtpm_rotation_provisioning() {
        let _lock = AGENT_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(swtpm) = LiveSwtpm::new() else {
            eprintln!("swtpm not available; skipping swtpm rotation test");
            return;
        };

        let temp = TestDir::new();
        let state_dir = temp.path().join("agent_state");

        // Fresh
        let prov_args = vec![
            "openaudit-agent".to_string(),
            "provision".to_string(),
            "--tpm".to_string(),
            swtpm.sock_path.to_str().unwrap().to_string(),
            "--state-dir".to_string(),
            state_dir.to_str().unwrap().to_string(),
        ];
        run(&prov_args).unwrap();

        let gen_str = fs::read_to_string(state_dir.join("generation.txt")).unwrap();
        assert_eq!(gen_str.trim(), "1");

        // Rotate
        let rotate_args = vec![
            "openaudit-agent".to_string(),
            "provision".to_string(),
            "--tpm".to_string(),
            swtpm.sock_path.to_str().unwrap().to_string(),
            "--state-dir".to_string(),
            state_dir.to_str().unwrap().to_string(),
            "--rotate".to_string(),
        ];
        let res_rot = run(&rotate_args);
        assert!(res_rot.is_ok(), "rotation must succeed: {res_rot:?}");

        let gen_str_after = fs::read_to_string(state_dir.join("generation.txt")).unwrap();
        assert_eq!(gen_str_after.trim(), "2");
    }

    #[test]
    fn test_agent_swtpm_quarantine_enforcement() {
        let _lock = AGENT_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(swtpm) = LiveSwtpm::new() else {
            eprintln!("swtpm not available; skipping swtpm quarantine test");
            return;
        };

        let temp = TestDir::new();
        let state_dir = temp.path().join("agent_state");

        // Fresh provision
        let prov_args = vec![
            "openaudit-agent".to_string(),
            "provision".to_string(),
            "--tpm".to_string(),
            swtpm.sock_path.to_str().unwrap().to_string(),
            "--state-dir".to_string(),
            state_dir.to_str().unwrap().to_string(),
        ];
        run(&prov_args).unwrap();

        // Tamper with local files to trigger partial state / quarantine
        fs::remove_file(state_dir.join("lifecycle_id.bin")).unwrap();

        // Attempting normal provision must fail closed under quarantine
        let res_quar = run(&prov_args);
        assert!(
            res_quar.is_err(),
            "quarantine must fail closed without override"
        );
        let err_str = res_quar.unwrap_err();
        assert!(
            err_str.contains("quarantine enforced"),
            "expected quarantine error: {err_str}"
        );

        // Recovery with --override-quarantine
        let recover_args = vec![
            "openaudit-agent".to_string(),
            "provision".to_string(),
            "--tpm".to_string(),
            swtpm.sock_path.to_str().unwrap().to_string(),
            "--state-dir".to_string(),
            state_dir.to_str().unwrap().to_string(),
            "--override-quarantine".to_string(),
        ];
        let res_rec = run(&recover_args);
        assert!(
            res_rec.is_ok(),
            "override quarantine must succeed: {res_rec:?}"
        );
        assert!(state_dir.join("lifecycle_id.bin").is_file());
    }

    #[test]
    fn test_agent_swtpm_enroll_command() {
        let _lock = AGENT_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(swtpm) = LiveSwtpm::new() else {
            eprintln!("swtpm not available; skipping swtpm enroll test");
            return;
        };

        let temp = TestDir::new();
        let state_dir = temp.path().join("agent_state");

        // 1. Provision
        let prov_args = vec![
            "openaudit-agent".to_string(),
            "provision".to_string(),
            "--tpm".to_string(),
            swtpm.sock_path.to_str().unwrap().to_string(),
            "--state-dir".to_string(),
            state_dir.to_str().unwrap().to_string(),
        ];
        run(&prov_args).unwrap();

        // 2. Enroll
        let token_id = [0x55u8; 16];
        let nonce = [0x88u8; 32];
        let tx_id = TransactionId::new();

        let enroll_args = vec![
            "openaudit-agent".to_string(),
            "enroll".to_string(),
            "--token-id".to_string(),
            encode_hex(&token_id),
            "--nonce".to_string(),
            encode_hex(&nonce),
            "--tpm".to_string(),
            swtpm.sock_path.to_str().unwrap().to_string(),
            "--state-dir".to_string(),
            state_dir.to_str().unwrap().to_string(),
            "--tx-id".to_string(),
            tx_id.to_string(),
        ];

        let enroll_res = run(&enroll_args);
        assert!(
            enroll_res.is_ok(),
            "enroll command must succeed: {enroll_res:?}"
        );
    }
}
