//! Comprehensive End-to-End Attestation & Outbox Retrieval Integration Test Suite (Dimension 4).
//!
//! Validates the normative Phase F.1 orchestration workflows connecting verified Phase A-E components:
//! - Machine Enrollment: Challenge nonce validation, token issuance, single-use atomic consumption,
//!   SPKI DER parameter validation, and canonical 14-element HMAC-SHA256 transcript verification.
//! - Outbox Retrieval: Timestamp boundary skew checking (+/-60s), HMAC proof verification, and atomic
//!   `SQLite` WAL replay protection (WAL mode, FULL synchronous durability).
//! - Catalog Durability: 6-stage crash-safe update transactions synchronized with live TPM monotonic counters.
//! - TPM Hardware/Emulator Integration: Live execution against `swtpm 0.10.2_1` over Unix domain sockets,
//!   verifying restart persistence, quarantine safety, and fail-closed desync recovery.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use openaudit_core::protocol::{
    AgentAttestationClient, AgentCredentials, AssessmentCatalog, AuthorityService, CatalogManager,
    CatalogVersion, ChallengeNonce, EnrollmentGeneration, LifecycleId, MachineId,
    MockMonotonicCounter, MonotonicCounter, ProtocolError, RecoveryOutcome, SharedSecret,
    SqliteReplayStore, SrkName, TimestampNs, TpmClient, TpmCounterConfig, TpmMonotonicCounter,
    TpmProvisioningManager, TransactionId, UnixSocketTransport,
};

static E2E_TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Valid RSA-2048 SPKI DER fixture (294 octets) from normative D4 Vector 1.
const VALID_RSA_SPKI: [u8; 294] = [
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
    0x00, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5e, 0xd4, 0xb8, 0xa2, 0xe1, 0xf4, 0x09, 0x4a, 0x97, 0xb2, 0x1a, 0x3e, 0x6c, 0x8d, 0x7f, 0x0b,
    0x5f, 0x02, 0x03, 0x01, 0x00, 0x01,
];

/// Helper harness managing a live local `swtpm` instance.
struct LiveSwtpm {
    _temp_dir: TempDir,
    state_dir: PathBuf,
    ctrl_path: PathBuf,
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
                panic!("swtpm binary not found in PATH; swtpm is a mandatory prerequisite for d4_attestation_e2e tests");
            }
        } else {
            panic!("swtpm command check failed; swtpm is a mandatory prerequisite for d4_attestation_e2e tests");
        };

        let temp_dir = tempfile::tempdir().expect("temp dir creation must succeed");
        let state_dir = temp_dir.path().join("tpmstate");
        std::fs::create_dir_all(&state_dir).expect("state dir creation must succeed");
        let ctrl_path = state_dir.join("ctrl.sock");
        let sock_path = state_dir.join("tpm.sock");

        let child = Command::new(&swtpm_bin)
            .args([
                "socket",
                "--tpm2",
                "--tpmstate",
                &format!("dir={}", state_dir.display()),
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
            "spawned swtpm process failed to create socket at '{}'",
            sock_path.display()
        );

        Self {
            _temp_dir: temp_dir,
            state_dir,
            ctrl_path,
            sock_path,
            child: Some(child),
        }
    }

    fn connect_client(&self) -> TpmClient<UnixSocketTransport> {
        let transport = UnixSocketTransport::new(&self.sock_path);
        TpmClient::new(transport)
    }

    fn restart(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        let _ = std::fs::remove_file(&self.sock_path);
        let _ = std::fs::remove_file(&self.ctrl_path);

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
                &format!("dir={}", self.state_dir.display()),
                "--ctrl",
                &format!("type=unixio,path={}", self.ctrl_path.display()),
                "--server",
                &format!("type=unixio,path={}", self.sock_path.display()),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .spawn()
            .expect("failed to respawn swtpm daemon process");

        let mut ready = false;
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(50));
            if self.sock_path.exists() {
                thread::sleep(Duration::from_millis(50));
                ready = true;
                break;
            }
        }

        assert!(ready, "respawned swtpm process failed to become ready");

        self.child = Some(child);
    }
}

impl Drop for LiveSwtpm {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn setup_authority_and_storage() -> (AuthorityService, TempDir, TempDir) {
    let replay_dir = tempfile::tempdir().expect("replay dir creation");
    let replay_db_path = replay_dir.path().join("replay.db");
    let replay_store = Arc::new(
        SqliteReplayStore::open(&replay_db_path).expect("sqlite replay store initialization"),
    );

    let catalog_dir = tempfile::tempdir().expect("catalog dir creation");
    let catalog_mgr =
        Arc::new(CatalogManager::open(catalog_dir.path()).expect("catalog manager open"));

    // Initialize baseline catalog version 1, counter 1
    let base_catalog = AssessmentCatalog::new(1, 1, serde_json::json!({"baseline": "v1.0"}))
        .expect("baseline catalog creation");
    catalog_mgr
        .initialize_new(&base_catalog)
        .expect("baseline catalog initialization");

    let authority = AuthorityService::new(replay_store, catalog_mgr);
    (authority, replay_dir, catalog_dir)
}

#[test]
fn test_e2e_valid_enrollment_workflow_succeeds() {
    let _lock = E2E_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let swtpm = LiveSwtpm::new();
    let prov_dir = tempfile::tempdir().unwrap();

    // 1. Provision client TPM state
    let baseline_counter = {
        let mut prov = TpmProvisioningManager::new(swtpm.connect_client(), prov_dir.path());
        prov.execute(false, false, None)
            .expect("fresh provisioning")
    };
    assert_eq!(baseline_counter, 1);

    let tpm_client = swtpm.connect_client();
    let tpm_counter = Arc::new(Mutex::new(TpmMonotonicCounter::new(
        tpm_client,
        TpmCounterConfig::default(),
    )));

    // 2. Setup Agent credentials
    let machine_id = MachineId::new();
    let secret = SharedSecret::from_bytes([0x42u8; 32]);
    let lifecycle_id = LifecycleId::from_bytes([0xAAu8; 32]);
    let mut srk_name_bytes = [0u8; 34];
    srk_name_bytes[0..2].copy_from_slice(&0x000Bu16.to_be_bytes());
    let name_srk = SrkName::from_bytes(srk_name_bytes);

    let creds = AgentCredentials {
        machine_id,
        shared_secret: secret,
        ek_pub: VALID_RSA_SPKI.to_vec(),
        name_srk,
        lifecycle_id,
        generation: EnrollmentGeneration::from_u32(1),
    };
    let agent = AgentAttestationClient::new(creds, tpm_counter);

    // 3. Setup Authority
    let (authority, _replay_dir, _cat_dir) = setup_authority_and_storage();

    // 4. Authority issues enrollment token
    let nonce = ChallengeNonce::from_bytes([0x77u8; 32]);
    let now = TimestampNs::from_nanos(1_700_000_000_000_000_000);
    let token = authority
        .issue_enrollment_token(
            agent.machine_id(),
            nonce,
            agent.generation(),
            300_000_000_000, // 300s TTL
            now,
        )
        .expect("token issuance");

    // 5. Agent constructs canonical enrollment transcript
    let tx_id = TransactionId::new();
    let (transcript, proof) = agent
        .construct_enrollment_transcript(
            nonce,
            token.token_id,
            tx_id,
            CatalogVersion::from_u64(1),
            now,
            TimestampNs::from_nanos(now.as_nanos() + 300_000_000_000),
        )
        .expect("transcript construction");

    // 6. Authority processes and verifies enrollment
    let verified = authority
        .process_enrollment(&transcript, &proof, agent.shared_secret(), now)
        .expect("enrollment verification must succeed");

    assert_eq!(verified.machine_id, agent.machine_id());
    assert_eq!(verified.token_id, token.token_id);
    assert_eq!(verified.tx_id, tx_id);
    assert_eq!(verified.counter_base.as_u64(), 1);

    // Verify machine is registered
    let reg = authority
        .get_registered_machine(&agent.machine_id())
        .unwrap();
    assert!(reg.is_some());
}

#[test]
fn test_e2e_enrollment_negative_security_scenarios() {
    let _lock = E2E_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (authority, _replay_dir, _cat_dir) = setup_authority_and_storage();

    let machine_id = MachineId::new();
    let secret = SharedSecret::from_bytes([0x55u8; 32]);
    let nonce = ChallengeNonce::from_bytes([0x12u8; 32]);
    let now = TimestampNs::from_nanos(1_700_000_000_000_000_000);

    let token = authority
        .issue_enrollment_token(
            machine_id,
            nonce,
            EnrollmentGeneration::from_u32(1),
            300_000_000_000,
            now,
        )
        .unwrap();

    let mock_counter = Arc::new(Mutex::new(MockMonotonicCounter::new(1)));
    let creds = AgentCredentials {
        machine_id,
        shared_secret: secret,
        ek_pub: VALID_RSA_SPKI.to_vec(),
        name_srk: SrkName::from_bytes([0u8; 34]),
        lifecycle_id: LifecycleId::from_bytes([0u8; 32]),
        generation: EnrollmentGeneration::from_u32(1),
    };
    let agent = AgentAttestationClient::new(creds, mock_counter);

    let (transcript, valid_proof) = agent
        .construct_enrollment_transcript(
            nonce,
            token.token_id,
            TransactionId::new(),
            CatalogVersion::from_u64(1),
            now,
            TimestampNs::from_nanos(now.as_nanos() + 300_000_000_000),
        )
        .unwrap();

    // 1. Invalid HMAC proof is rejected; token is NOT consumed
    let bad_proof = [0xFFu8; 32];
    let err_hmac =
        authority.process_enrollment(&transcript, &bad_proof, agent.shared_secret(), now);
    assert!(matches!(err_hmac, Err(ProtocolError::InvalidHmacProof)));

    // 2. Malformed SPKI is rejected; token is NOT consumed
    let mut malformed_transcript = transcript.clone();
    malformed_transcript.ek_pub = vec![0x30, 0x05, 0x01, 0x02, 0x03]; // malformed ASN.1
    let raw_malformed = malformed_transcript.serialize_canonical().unwrap();
    let proof_malformed =
        openaudit_core::protocol::compute_hmac_sha256(agent.shared_secret(), &raw_malformed);
    let err_spki = authority.process_enrollment(
        &malformed_transcript,
        &proof_malformed,
        agent.shared_secret(),
        now,
    );
    assert!(matches!(err_spki, Err(ProtocolError::MalformedDerKey(_))));

    // 3. Invalid challenge nonce is rejected
    let mut wrong_nonce_transcript = transcript.clone();
    wrong_nonce_transcript.nonce_auth = ChallengeNonce::from_bytes([0x99u8; 32]);
    let raw_wn = wrong_nonce_transcript.serialize_canonical().unwrap();
    let proof_wn = openaudit_core::protocol::compute_hmac_sha256(agent.shared_secret(), &raw_wn);
    let err_nonce = authority.process_enrollment(
        &wrong_nonce_transcript,
        &proof_wn,
        agent.shared_secret(),
        now,
    );
    assert!(err_nonce.is_err());

    // 4. Expired enrollment is rejected
    let future_now = TimestampNs::from_nanos(now.as_nanos() + 400_000_000_000); // 400s later (past 300s TTL)
    let err_exp =
        authority.process_enrollment(&transcript, &valid_proof, agent.shared_secret(), future_now);
    assert!(err_exp.is_err());

    // 5. Valid enrollment now succeeds with original valid token
    let ok = authority.process_enrollment(&transcript, &valid_proof, agent.shared_secret(), now);
    assert!(ok.is_ok());

    // 6. Token reuse is REJECTED (single-use constraint)
    let err_reuse =
        authority.process_enrollment(&transcript, &valid_proof, agent.shared_secret(), now);
    assert!(matches!(err_reuse, Err(ProtocolError::CryptoError(_))));
}

#[test]
fn test_e2e_concurrent_duplicate_enrollment_race_fails_closed() {
    let _lock = E2E_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (authority, _replay_dir, _cat_dir) = setup_authority_and_storage();
    let auth = Arc::new(authority);

    let machine_id = MachineId::new();
    let secret = SharedSecret::from_bytes([0x88u8; 32]);
    let nonce = ChallengeNonce::from_bytes([0x33u8; 32]);
    let now = TimestampNs::from_nanos(1_700_000_000_000_000_000);

    let token = auth
        .issue_enrollment_token(
            machine_id,
            nonce,
            EnrollmentGeneration::from_u32(1),
            300_000_000_000,
            now,
        )
        .unwrap();

    let mock_counter = Arc::new(Mutex::new(MockMonotonicCounter::new(1)));
    let creds = AgentCredentials {
        machine_id,
        shared_secret: secret,
        ek_pub: VALID_RSA_SPKI.to_vec(),
        name_srk: SrkName::from_bytes([0u8; 34]),
        lifecycle_id: LifecycleId::from_bytes([0u8; 32]),
        generation: EnrollmentGeneration::from_u32(1),
    };
    let agent = AgentAttestationClient::new(creds, mock_counter);

    let (transcript, proof) = agent
        .construct_enrollment_transcript(
            nonce,
            token.token_id,
            TransactionId::new(),
            CatalogVersion::from_u64(1),
            now,
            TimestampNs::from_nanos(now.as_nanos() + 300_000_000_000),
        )
        .unwrap();

    // Spawn 8 concurrent threads attempting to enroll with the identical valid token
    let mut handles = Vec::new();
    for _ in 0..8 {
        let auth_clone = Arc::clone(&auth);
        let trans_clone = transcript.clone();
        let sec_bytes = *agent.shared_secret().as_bytes();

        handles.push(thread::spawn(move || {
            let s = SharedSecret::from_bytes(sec_bytes);
            auth_clone.process_enrollment(&trans_clone, &proof, &s, now)
        }));
    }

    let mut successes = 0;
    let mut failures = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(_) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    // Exactly ONE thread must succeed; all others MUST fail with already consumed
    assert_eq!(
        successes, 1,
        "exactly one concurrent enrollment must succeed"
    );
    assert_eq!(failures, 7, "all concurrent duplicates must be rejected");
}

#[test]
fn test_e2e_outbox_retrieval_and_replay_protection() {
    let _lock = E2E_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (authority, _replay_dir, _cat_dir) = setup_authority_and_storage();

    let machine_id = MachineId::new();
    let secret = SharedSecret::from_bytes([0x77u8; 32]);
    let mock_counter = Arc::new(Mutex::new(MockMonotonicCounter::new(1)));
    let creds = AgentCredentials {
        machine_id,
        shared_secret: secret,
        ek_pub: VALID_RSA_SPKI.to_vec(),
        name_srk: SrkName::from_bytes([0u8; 34]),
        lifecycle_id: LifecycleId::from_bytes([0u8; 32]),
        generation: EnrollmentGeneration::from_u32(1),
    };
    let agent = AgentAttestationClient::new(creds, mock_counter);

    let tx_id = TransactionId::new();
    let now = TimestampNs::from_nanos(1_700_000_000_000_000_000);

    // 1. Valid retrieval request succeeds
    let req = agent.construct_retrieval_request(tx_id, now);
    let verified = authority.process_retrieval(&req, agent.shared_secret(), now);
    assert!(
        verified.is_ok(),
        "valid retrieval must succeed: {verified:?}"
    );

    // 2. Immediate duplicate retrieval request is REJECTED with ReplayDetected
    let replay_err = authority.process_retrieval(&req, agent.shared_secret(), now);
    assert!(matches!(
        replay_err,
        Err(ProtocolError::ReplayDetected { .. })
    ));

    // 3. Timestamp out of bounds (> 60s skew) is rejected BEFORE touching storage
    let skewed_time = TimestampNs::from_nanos(now.as_nanos() + 61_000_000_000); // 61s skew
    let skewed_req = agent.construct_retrieval_request(tx_id, skewed_time);
    let err_skew = authority.process_retrieval(&skewed_req, agent.shared_secret(), now);
    assert!(matches!(
        err_skew,
        Err(ProtocolError::TimestampOutOfBounds { .. })
    ));

    // 4. Invalid HMAC proof is rejected BEFORE touching storage
    let mut bad_proof_req = agent.construct_retrieval_request(tx_id, now);
    bad_proof_req.proof = [0xEEu8; 32];
    let err_hmac = authority.process_retrieval(&bad_proof_req, agent.shared_secret(), now);
    assert!(matches!(err_hmac, Err(ProtocolError::InvalidHmacProof)));
}

#[test]
fn test_e2e_concurrent_duplicate_retrieval_race() {
    let _lock = E2E_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (authority, _replay_dir, _cat_dir) = setup_authority_and_storage();
    let auth = Arc::new(authority);

    let machine_id = MachineId::new();
    let secret = SharedSecret::from_bytes([0x99u8; 32]);
    let mock_counter = Arc::new(Mutex::new(MockMonotonicCounter::new(1)));
    let creds = AgentCredentials {
        machine_id,
        shared_secret: secret,
        ek_pub: VALID_RSA_SPKI.to_vec(),
        name_srk: SrkName::from_bytes([0u8; 34]),
        lifecycle_id: LifecycleId::from_bytes([0u8; 32]),
        generation: EnrollmentGeneration::from_u32(1),
    };
    let agent = AgentAttestationClient::new(creds, mock_counter);

    let tx_id = TransactionId::new();
    let now = TimestampNs::from_nanos(1_700_000_000_000_000_000);

    // Single request payload and proof
    let req = agent.construct_retrieval_request(tx_id, now);

    // 8 concurrent threads race to consume this identical request
    let mut handles = Vec::new();
    for _ in 0..8 {
        let auth_clone = Arc::clone(&auth);
        let req_clone = req.clone();
        let sec_bytes = *agent.shared_secret().as_bytes();

        handles.push(thread::spawn(move || {
            let s = SharedSecret::from_bytes(sec_bytes);
            auth_clone.process_retrieval(&req_clone, &s, now)
        }));
    }

    let mut successes = 0;
    let mut replays = 0;
    for h in handles {
        match h.join().unwrap() {
            Ok(_) => successes += 1,
            Err(ProtocolError::ReplayDetected { .. }) => replays += 1,
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    // Exactly ONE succeeds; 7 detect replay
    assert_eq!(
        successes, 1,
        "exactly one concurrent retrieval must succeed"
    );
    assert_eq!(
        replays, 7,
        "remaining concurrent attempts must report ReplayDetected"
    );
}

#[test]
fn test_e2e_catalog_durability_and_tpm_synchronization() {
    let _lock = E2E_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let swtpm = LiveSwtpm::new();
    let prov_dir = tempfile::tempdir().unwrap();

    // 1. Provision client TPM state
    let baseline = {
        let mut prov = TpmProvisioningManager::new(swtpm.connect_client(), prov_dir.path());
        prov.execute(false, false, None)
            .expect("fresh provisioning")
    };
    assert_eq!(baseline, 1);

    let tpm_client = swtpm.connect_client();
    let mut tpm_counter = TpmMonotonicCounter::new(tpm_client, TpmCounterConfig::default());

    // 2. Setup Authority
    let (authority, _replay_dir, _cat_dir) = setup_authority_and_storage();

    // 3. Update catalog to version 2 (counter target = 2)
    let v2_catalog = AssessmentCatalog::new(2, 2, serde_json::json!({"release": "catalog_v2"}))
        .expect("catalog v2 creation");
    authority
        .execute_catalog_update(&v2_catalog, &mut tpm_counter)
        .expect("catalog update must succeed");

    // 4. Verify catalog on disk and TPM counter are synchronized
    let active = authority.load_active_catalog().unwrap();
    assert_eq!(active.version, 2);
    assert_eq!(active.counter, 2);

    let tpm_val = tpm_counter.read_counter().unwrap();
    assert_eq!(tpm_val, 2);

    // 5. Recovery on synchronized state reports CleanCurrent
    let outcome = authority.recover_catalog(&tpm_counter).unwrap();
    assert_eq!(outcome, RecoveryOutcome::CleanCurrent);
}

#[test]
fn test_e2e_catalog_tpm_desynchronization_fails_closed() {
    let _lock = E2E_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let swtpm = LiveSwtpm::new();
    let prov_dir = tempfile::tempdir().unwrap();

    let baseline = {
        let mut prov = TpmProvisioningManager::new(swtpm.connect_client(), prov_dir.path());
        prov.execute(false, false, None).unwrap()
    };
    assert_eq!(baseline, 1);

    let tpm_client = swtpm.connect_client();
    let tpm_counter = TpmMonotonicCounter::new(tpm_client, TpmCounterConfig::default());

    let replay_dir = tempfile::tempdir().expect("replay dir creation");
    let replay_db_path = replay_dir.path().join("replay.db");
    let replay_store = Arc::new(
        SqliteReplayStore::open(&replay_db_path).expect("sqlite replay store initialization"),
    );

    let catalog_dir = tempfile::tempdir().expect("catalog dir creation");
    let catalog_mgr =
        Arc::new(CatalogManager::open(catalog_dir.path()).expect("catalog manager open"));

    // Fabricate desynchronization: catalog on disk claims counter 9999 while TPM is at 1
    let desync_catalog =
        AssessmentCatalog::new(2, 9999, serde_json::json!({"desync": true})).unwrap();
    catalog_mgr.initialize_new(&desync_catalog).unwrap();

    let authority = AuthorityService::new(replay_store, catalog_mgr);

    // Recovery must detect desync and fail closed!
    let res = authority.recover_catalog(&tpm_counter);
    assert!(matches!(res, Err(ProtocolError::CatalogDesync(_))));
}

#[test]
fn test_e2e_tpm_restart_persistence_and_unavailability() {
    let _lock = E2E_TEST_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut swtpm = LiveSwtpm::new();
    let prov_dir = tempfile::tempdir().unwrap();

    let baseline = {
        let mut prov = TpmProvisioningManager::new(swtpm.connect_client(), prov_dir.path());
        prov.execute(false, false, None).unwrap()
    };
    assert_eq!(baseline, 1);

    {
        let mut counter =
            TpmMonotonicCounter::new(swtpm.connect_client(), TpmCounterConfig::default());
        let val2 = counter.increment_counter().unwrap();
        assert_eq!(val2, 2);
    }

    // Restart swtpm (kill process and respawn with same state dir)
    swtpm.restart();

    // Reconnected client reads persisted counter = 2
    {
        let mut reconnected_counter =
            TpmMonotonicCounter::new(swtpm.connect_client(), TpmCounterConfig::default());
        let val_persisted = reconnected_counter.read_counter().unwrap();
        assert_eq!(
            val_persisted, 2,
            "counter value must persist across swtpm restart"
        );

        let val3 = reconnected_counter.increment_counter().unwrap();
        assert_eq!(val3, 3);
    }

    // Point transport to invalid non-existent socket -> must fail closed
    let dead_transport = UnixSocketTransport::new("/tmp/dead_non_existent_openaudit_socket.sock");
    let dead_client = TpmClient::new(dead_transport);
    let mut dead_counter = TpmMonotonicCounter::new(dead_client, TpmCounterConfig::default());

    let res_read = dead_counter.read_counter();
    assert!(res_read.is_err(), "reading dead socket must fail closed");
    let res_inc = dead_counter.increment_counter();
    assert!(
        res_inc.is_err(),
        "incrementing dead socket must fail closed"
    );
}
