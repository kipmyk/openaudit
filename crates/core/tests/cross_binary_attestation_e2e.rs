//! Cross-binary end-to-end attestation and outbox retrieval integration suite for OpenAudit M3 D4.
//!
//! Executes compiled `openaudit-server` and `openaudit-agent` binaries as separate OS processes,
//! validating the complete protocol exchange against real `SQLite` storage, the filesystem, and live `swtpm`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tempfile::TempDir;

static CROSS_BINARY_MUTEX: Mutex<()> = Mutex::new(());

/// Helper managing a live local `swtpm` daemon for cross-binary testing.
struct LiveSwtpm {
    temp_dir: PathBuf,
    sock_path: PathBuf,
    child: Option<Child>,
}

impl LiveSwtpm {
    fn new() -> Self {
        let swtpm_bin = if Path::new("/opt/homebrew/bin/swtpm").is_file() {
            "/opt/homebrew/bin/swtpm".to_string()
        } else if let Ok(out) = Command::new("which").arg("swtpm").output() {
            if out.status.success() {
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            } else {
                panic!("swtpm binary not found in PATH; swtpm is a mandatory prerequisite for cross-binary attestation tests");
            }
        } else {
            panic!("swtpm binary not found; swtpm is a mandatory prerequisite for cross-binary attestation tests");
        };

        let rand_suffix = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            % 1_000_000_000) as u32;
        let temp_dir = PathBuf::from(format!(
            "/tmp/oa_cb_tpm_{}_{rand_suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&temp_dir).expect("failed to create swtpm state dir");
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
            .expect("failed to spawn swtpm daemon process");

        let mut ready = false;
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(50));
            if sock_path.exists() {
                thread::sleep(Duration::from_millis(50));
                ready = true;
                break;
            }
        }

        assert!(
            ready,
            "swtpm failed to create socket at '{}'",
            sock_path.display()
        );

        Self {
            temp_dir,
            sock_path,
            child: Some(child),
        }
    }

    fn restart(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        let ctrl_path = self.temp_dir.join("c.sock");
        let sock_path = self.temp_dir.join("t.sock");
        let _ = fs::remove_file(&ctrl_path);
        let _ = fs::remove_file(&sock_path);

        let swtpm_bin = if Path::new("/opt/homebrew/bin/swtpm").is_file() {
            "/opt/homebrew/bin/swtpm".to_string()
        } else {
            "swtpm".to_string()
        };

        let child = Command::new(&swtpm_bin)
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", self.temp_dir.display()),
                "--ctrl",
                &format!("type=unixio,path={}", ctrl_path.display()),
                "--server",
                &format!("type=unixio,path={}", sock_path.display()),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .spawn()
            .expect("failed to respawn swtpm daemon process");

        let mut ready = false;
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(50));
            if sock_path.exists() {
                thread::sleep(Duration::from_millis(50));
                ready = true;
                break;
            }
        }

        assert!(ready, "respawned swtpm failed to become ready");
        self.child = Some(child);
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

/// Resolves the absolute path to a compiled cargo binary in `target/debug`.
fn get_binary_path(bin_name: &str) -> PathBuf {
    // Navigate from CARGO_MANIFEST_DIR (crates/core) up to workspace root
    let target_debug = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .join("target")
        .join("debug")
        .join(bin_name);

    if target_debug.is_file() {
        return target_debug;
    }

    // Attempt on-demand compilation if not present
    let _ = Command::new("cargo")
        .args(["build", "--bin", bin_name])
        .output();

    if target_debug.is_file() {
        return target_debug;
    }

    panic!(
        "compiled binary '{}' not found at '{}'; ensure cargo build --bins was executed",
        bin_name,
        target_debug.display()
    );
}

/// Extracts a key-value token from binary stdout stream: `KEY: VALUE`.
fn extract_field(output: &str, prefix: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(stripped) = trimmed.strip_prefix(prefix) {
            return Some(stripped.trim().to_string());
        }
    }
    None
}

#[test]
#[allow(clippy::too_many_lines)]
fn test_cross_binary_full_attestation_and_retrieval_workflow() {
    let _lock = CROSS_BINARY_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let swtpm = LiveSwtpm::new();
    let server_bin = get_binary_path("openaudit-server");
    let agent_bin = get_binary_path("openaudit-agent");

    let server_data_dir = TempDir::new().expect("server temp dir");
    let agent_state_dir = TempDir::new().expect("agent temp dir");

    // -------------------------------------------------------------------------
    // STEP 1: Server initializes persistence storage
    // -------------------------------------------------------------------------
    let status_res = Command::new(&server_bin)
        .args([
            "authority",
            "status",
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute openaudit-server status");

    assert!(
        status_res.status.success(),
        "server status failed: {status_res:?}"
    );
    let status_stdout = String::from_utf8_lossy(&status_res.stdout);
    assert!(status_stdout.contains("OpenAudit Authority Service: ONLINE"));
    assert!(server_data_dir.path().join("authority.db").is_file());
    assert!(server_data_dir.path().join("replay.db").is_file());

    // -------------------------------------------------------------------------
    // STEP 2: Server initializes baseline catalog (version 1, counter 1)
    // -------------------------------------------------------------------------
    let cat_init_res = Command::new(&server_bin)
        .args([
            "authority",
            "catalog-init",
            "--version",
            "1",
            "--counter",
            "1",
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute catalog-init");

    assert!(
        cat_init_res.status.success(),
        "catalog-init failed: {cat_init_res:?}"
    );
    let cat_stdout = String::from_utf8_lossy(&cat_init_res.stdout);
    assert!(cat_stdout.contains("CATALOG_INIT: SUCCESS"));
    assert!(server_data_dir
        .path()
        .join("catalog")
        .join("catalog.json")
        .is_file());

    // -------------------------------------------------------------------------
    // STEP 3: Agent executes four-state provisioning against live swtpm
    // -------------------------------------------------------------------------
    let prov_res = Command::new(&agent_bin)
        .args([
            "provision",
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute openaudit-agent provision");

    assert!(
        prov_res.status.success(),
        "agent provision failed: {prov_res:?}"
    );
    let prov_stdout = String::from_utf8_lossy(&prov_res.stdout);
    assert!(prov_stdout.contains("PROVISIONING_STATE: FreshProvisioning"));
    assert!(prov_stdout.contains("BASELINE_COUNTER: 1"));

    let machine_id = extract_field(&prov_stdout, "MACHINE_ID:").expect("must output MACHINE_ID");
    assert_ne!(machine_id, "");

    let secret_file_path = agent_state_dir.path().join("tpm-auth.secret");
    assert!(secret_file_path.is_file(), "tpm-auth.secret must exist");
    assert!(agent_state_dir.path().join("lifecycle_id.bin").is_file());

    // Verify secret file permissions strictly mode 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&secret_file_path).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "secret file must have strict 0600 permissions"
        );
    }

    // -------------------------------------------------------------------------
    // STEP 4: Server issues single-use enrollment token bound to machine_id
    // -------------------------------------------------------------------------
    let token_res = Command::new(&server_bin)
        .args([
            "authority",
            "token-issue",
            "--machine-id",
            &machine_id,
            "--generate-nonce",
            "--generation",
            "1",
            "--ttl-secs",
            "300",
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute token-issue");

    assert!(
        token_res.status.success(),
        "server token-issue failed: {token_res:?}"
    );
    let token_stdout = String::from_utf8_lossy(&token_res.stdout);
    assert!(token_stdout.contains("TOKEN_ISSUE: SUCCESS"));

    let token_id = extract_field(&token_stdout, "TOKEN_ID:").expect("must output TOKEN_ID");
    let challenge_nonce = extract_field(&token_stdout, "NONCE:").expect("must output NONCE");
    let expires_at_ns =
        extract_field(&token_stdout, "EXPIRES_AT_NS:").expect("must output EXPIRES_AT_NS");
    assert_eq!(
        token_id.len(),
        32,
        "token ID must be 16 bytes (32 hex chars)"
    );
    assert_eq!(
        challenge_nonce.len(),
        64,
        "nonce must be 32 bytes (64 hex chars)"
    );

    // -------------------------------------------------------------------------
    // STEP 5: Agent constructs 14-element enrollment transcript and HMAC proof
    // -------------------------------------------------------------------------
    let enroll_res = Command::new(&agent_bin)
        .args([
            "enroll",
            "--token-id",
            &token_id,
            "--nonce",
            &challenge_nonce,
            "--expires-at-ns",
            &expires_at_ns,
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute openaudit-agent enroll");

    assert!(
        enroll_res.status.success(),
        "agent enroll failed: {enroll_res:?}"
    );
    let enroll_stdout = String::from_utf8_lossy(&enroll_res.stdout);

    let transcript_hex = extract_field(&enroll_stdout, "ENROLLMENT_TRANSCRIPT:")
        .expect("must output ENROLLMENT_TRANSCRIPT");
    let proof_hex = extract_field(&enroll_stdout, "HMAC_PROOF:").expect("must output HMAC_PROOF");

    // Fixed overhead is 204 bytes (408 hex chars); total must be >= 204 + 91 bytes = 295 bytes (590 hex chars)
    assert!(
        transcript_hex.len() >= 590,
        "transcript hex must be >= 590 characters, found {}",
        transcript_hex.len()
    );
    assert_eq!(
        proof_hex.len(),
        64,
        "HMAC proof must be 32 bytes (64 hex chars)"
    );

    // -------------------------------------------------------------------------
    // STEP 6: Server verifies enrollment transcript, checks HMAC proof, registers node
    // -------------------------------------------------------------------------
    let process_enroll_res = Command::new(&server_bin)
        .args([
            "authority",
            "process-enrollment",
            "--transcript",
            &transcript_hex,
            "--proof",
            &proof_hex,
            "--secret-file",
            secret_file_path.to_str().unwrap(),
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute process-enrollment");

    assert!(
        process_enroll_res.status.success(),
        "server process-enrollment failed: {process_enroll_res:?}"
    );
    let process_enroll_stdout = String::from_utf8_lossy(&process_enroll_res.stdout);
    assert!(process_enroll_stdout.contains("ENROLLMENT_VERIFIED: SUCCESS"));

    let tx_id = extract_field(&process_enroll_stdout, "TRANSACTION_ID:")
        .expect("must output TRANSACTION_ID");
    assert_ne!(tx_id, "");

    // -------------------------------------------------------------------------
    // STEP 7: Replay enrollment: Duplicate consumption of same token fails closed
    // -------------------------------------------------------------------------
    let dup_enroll_res = Command::new(&server_bin)
        .args([
            "authority",
            "process-enrollment",
            "--transcript",
            &transcript_hex,
            "--proof",
            &proof_hex,
            "--secret-file",
            secret_file_path.to_str().unwrap(),
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute duplicate process-enrollment");

    assert!(
        !dup_enroll_res.status.success(),
        "duplicate enrollment must fail closed (non-zero exit code)"
    );
    let dup_err = String::from_utf8_lossy(&dup_enroll_res.stderr);
    assert!(
        dup_err.contains("enrollment validation failed") || dup_err.contains("already consumed"),
        "expected single-use token consumption rejection: {dup_err}"
    );

    // -------------------------------------------------------------------------
    // STEP 8: Agent constructs 5-element canonical outbox retrieval request (89 bytes)
    // -------------------------------------------------------------------------
    let retrieve_res = Command::new(&agent_bin)
        .args([
            "retrieve",
            "--tx-id",
            &tx_id,
            "--state-dir",
            agent_state_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute openaudit-agent retrieve");

    assert!(
        retrieve_res.status.success(),
        "agent retrieve failed: {retrieve_res:?}"
    );
    let retrieve_stdout = String::from_utf8_lossy(&retrieve_res.stdout);

    let request_hex = extract_field(&retrieve_stdout, "RETRIEVAL_REQUEST:")
        .expect("must output RETRIEVAL_REQUEST");
    let req_proof_hex =
        extract_field(&retrieve_stdout, "HMAC_PROOF:").expect("must output HMAC_PROOF");

    // Canonical retrieval message is strictly 89 octets (178 hex chars)
    assert_eq!(
        request_hex.len(),
        178,
        "canonical retrieval request must be exactly 89 bytes (178 hex characters)"
    );
    assert_eq!(
        req_proof_hex.len(),
        64,
        "retrieval proof must be 32 bytes (64 hex characters)"
    );

    // -------------------------------------------------------------------------
    // STEP 9: Server processes retrieval request, enforces replay gate in SQLite WAL
    // -------------------------------------------------------------------------
    let process_retrieve_res = Command::new(&server_bin)
        .args([
            "authority",
            "process-retrieval",
            "--request",
            &request_hex,
            "--proof",
            &req_proof_hex,
            "--secret-file",
            secret_file_path.to_str().unwrap(),
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute process-retrieval");

    assert!(
        process_retrieve_res.status.success(),
        "server process-retrieval failed: {process_retrieve_res:?}"
    );
    let process_retrieve_stdout = String::from_utf8_lossy(&process_retrieve_res.stdout);
    assert!(process_retrieve_stdout.contains("RETRIEVAL_VERIFIED: SUCCESS"));

    // -------------------------------------------------------------------------
    // STEP 10: Replay gate enforcement: Reusing exact same request fails closed
    // -------------------------------------------------------------------------
    let replayed_res = Command::new(&server_bin)
        .args([
            "authority",
            "process-retrieval",
            "--request",
            &request_hex,
            "--proof",
            &req_proof_hex,
            "--secret-file",
            secret_file_path.to_str().unwrap(),
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("failed to execute replayed process-retrieval");

    assert!(
        !replayed_res.status.success(),
        "replayed retrieval request must fail closed (non-zero exit code)"
    );
    let replay_err = String::from_utf8_lossy(&replayed_res.stderr);
    assert!(
        replay_err.contains("retrieval validation failed"),
        "expected replay rejection in error output: {replay_err}"
    );
}

#[test]
fn test_cross_binary_restart_and_durability() {
    let _lock = CROSS_BINARY_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut swtpm = LiveSwtpm::new();
    let server_bin = get_binary_path("openaudit-server");
    let agent_bin = get_binary_path("openaudit-agent");

    let server_data_dir = TempDir::new().expect("server temp dir");
    let agent_state_dir = TempDir::new().expect("agent temp dir");

    // Initialize server and agent
    let _ = Command::new(&server_bin)
        .args([
            "authority",
            "catalog-init",
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("init catalog");

    let prov1 = Command::new(&agent_bin)
        .args([
            "provision",
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("agent provision");
    assert!(prov1.status.success());

    // Restart swtpm emulator (simulates power loss or host reboot)
    swtpm.restart();

    // Agent executes existing validation against restarted TPM
    let prov2 = Command::new(&agent_bin)
        .args([
            "provision",
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("agent re-provision");
    assert!(
        prov2.status.success(),
        "existing validation failed after restart: {prov2:?}"
    );
    let prov2_stdout = String::from_utf8_lossy(&prov2.stdout);
    assert!(prov2_stdout.contains("PROVISIONING_STATE: ExistingValidationAndRecovery"));
    assert!(prov2_stdout.contains("BASELINE_COUNTER: 1"));

    // Server process re-opens database and verifies active catalog survives
    let status_res = Command::new(&server_bin)
        .args([
            "authority",
            "status",
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("server status check");
    assert!(status_res.status.success());
    let status_stdout = String::from_utf8_lossy(&status_res.stdout);
    assert!(status_stdout.contains("ACTIVE_CATALOG_VERSION: 1"));
}

#[test]
fn test_cross_binary_fail_closed_error_handling() {
    let _lock = CROSS_BINARY_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let swtpm = LiveSwtpm::new();
    let server_bin = get_binary_path("openaudit-server");
    let agent_bin = get_binary_path("openaudit-agent");

    let server_data_dir = TempDir::new().expect("server temp dir");
    let agent_state_dir = TempDir::new().expect("agent temp dir");

    // Init catalog & provision
    let _ = Command::new(&server_bin)
        .args([
            "authority",
            "catalog-init",
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("init catalog");

    let _ = Command::new(&agent_bin)
        .args([
            "provision",
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("agent provision");

    let secret_file_path = agent_state_dir.path().join("tpm-auth.secret");

    // 1. Insecure secret file permissions fail closed
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secret_file_path, fs::Permissions::from_mode(0o644)).unwrap();

        let insecure_res = Command::new(&server_bin)
            .args([
                "authority",
                "process-retrieval",
                "--request",
                &"aa".repeat(89),
                "--proof",
                &"bb".repeat(32),
                "--secret-file",
                secret_file_path.to_str().unwrap(),
                "--data-dir",
                server_data_dir.path().to_str().unwrap(),
            ])
            .output()
            .expect("insecure permissions test");

        assert!(
            !insecure_res.status.success(),
            "mode 0644 secret file must fail closed"
        );
        let stderr = String::from_utf8_lossy(&insecure_res.stderr);
        assert!(
            stderr.contains("insecure permissions"),
            "expected permission error: {stderr}"
        );

        // Restore mode 0600
        fs::set_permissions(&secret_file_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    // 2. Corrupt HMAC proof on retrieval fails closed
    let corrupt_proof_res = Command::new(&server_bin)
        .args([
            "authority",
            "process-retrieval",
            "--request",
            &"aa".repeat(89),
            "--proof",
            &"00".repeat(32),
            "--secret-file",
            secret_file_path.to_str().unwrap(),
            "--data-dir",
            server_data_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("corrupt proof test");

    assert!(
        !corrupt_proof_res.status.success(),
        "corrupted HMAC proof must fail closed"
    );

    // 3. Agent with unconnectable TPM socket fails closed
    let bad_tpm_res = Command::new(&agent_bin)
        .args([
            "provision",
            "--tpm",
            "/tmp/non_existent_tpm_socket.sock",
            "--state-dir",
            agent_state_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("bad tpm test");

    assert!(
        !bad_tpm_res.status.success(),
        "missing TPM socket must fail closed"
    );
}
