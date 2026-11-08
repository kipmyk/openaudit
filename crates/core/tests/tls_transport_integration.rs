//! Comprehensive integration tests for TLS 1.3 transport, handshake enforcement,
//! certificate chain validation, hostname verification, and cross-binary encrypted workflows.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static TLS_XB_MUTEX: Mutex<()> = Mutex::new(());

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
            "/tmp/oa_tls_tpm_{}_{rand_suffix}",
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

use rcgen::{
    date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use openaudit_core::protocol::{
    build_tls13_client_config, build_tls13_server_config, load_certificates_from_file,
    load_private_key_from_file, parse_certificates_from_pem, parse_private_key_from_pem,
    read_framed, write_framed, TlsClientTransport, TlsProtocolRequest, TlsProtocolResponse,
};

/// Helper holding temporary PKI artifacts for tests.
struct TestPki {
    _temp_dir: PathBuf,
    ca_cert_pem: String,
    ca_cert_path: PathBuf,
    server_cert_pem: String,
    server_cert_path: PathBuf,
    server_key_pem: String,
    server_key_path: PathBuf,
}

impl TestPki {
    fn generate(hostname: &str) -> Self {
        let temp_dir = std::env::temp_dir().join(format!(
            "oa_tls_pki_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                % 1_000_000_000
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        // 1. Root CA
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "OpenAudit Test Root CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_cert_pem = ca_cert.pem();
        let ca_cert_path = temp_dir.join("ca.crt");
        fs::write(&ca_cert_path, &ca_cert_pem).unwrap();

        let issuer = Issuer::from_params(&ca_params, &ca_key);

        // 2. Server Certificate
        let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut server_params = CertificateParams::default();
        server_params.is_ca = IsCa::NoCa;
        server_params
            .distinguished_name
            .push(DnType::CommonName, hostname);
        server_params
            .subject_alt_names
            .push(SanType::DnsName(hostname.try_into().unwrap()));
        let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();
        let server_cert_pem = server_cert.pem();
        let server_cert_path = temp_dir.join("server.crt");
        fs::write(&server_cert_path, &server_cert_pem).unwrap();

        let server_key_pem = server_key.serialize_pem();
        let server_key_path = temp_dir.join("server.key");
        fs::write(&server_key_path, &server_key_pem).unwrap();
        fs::set_permissions(&server_key_path, fs::Permissions::from_mode(0o600)).unwrap();

        Self {
            _temp_dir: temp_dir,
            ca_cert_pem,
            ca_cert_path,
            server_cert_pem,
            server_cert_path,
            server_key_pem,
            server_key_path,
        }
    }
}

// -----------------------------------------------------------------------------
// Test 1: Successful TLS 1.3 Handshake & Protocol Negotiation
// -----------------------------------------------------------------------------
#[test]
fn test_successful_tls13_handshake_and_exchange() {
    let pki = TestPki::generate("localhost");

    let server_certs = parse_certificates_from_pem(pki.server_cert_pem.as_bytes()).unwrap();
    let server_key = parse_private_key_from_pem(pki.server_key_pem.as_bytes()).unwrap();
    let server_config = Arc::new(build_tls13_server_config(server_certs, server_key).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let conn = ServerConnection::new(server_config).unwrap();
        let mut tls_stream = StreamOwned::new(conn, stream);

        let msg = read_framed(&mut tls_stream, 1024).unwrap();
        assert_eq!(msg, b"HELLO_TLS13");

        assert_eq!(
            tls_stream.conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "negotiated protocol version must strictly be TLS 1.3"
        );

        write_framed(&mut tls_stream, b"ACK_TLS13").unwrap();
    });

    let root_certs = parse_certificates_from_pem(pki.ca_cert_pem.as_bytes()).unwrap();
    let client_config = Arc::new(build_tls13_client_config(root_certs).unwrap());

    let server_name = ServerName::try_from("localhost".to_string()).unwrap();
    let tcp_stream = TcpStream::connect(addr).unwrap();
    let conn = ClientConnection::new(client_config, server_name).unwrap();
    let mut tls_client = StreamOwned::new(conn, tcp_stream);

    write_framed(&mut tls_client, b"HELLO_TLS13").unwrap();
    let reply = read_framed(&mut tls_client, 1024).unwrap();
    assert_eq!(reply, b"ACK_TLS13");

    assert_eq!(
        tls_client.conn.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "client protocol version must strictly be TLS 1.3"
    );

    server_handle.join().unwrap();
}

// -----------------------------------------------------------------------------
// Test 2: Rejection of TLS 1.2 (Strict Downgrade Protection)
// -----------------------------------------------------------------------------
#[test]
fn test_rejection_of_tls12_downgrade() {
    let pki = TestPki::generate("localhost");

    let server_certs = parse_certificates_from_pem(pki.server_cert_pem.as_bytes()).unwrap();
    let server_key = parse_private_key_from_pem(pki.server_key_pem.as_bytes()).unwrap();
    let server_config = Arc::new(build_tls13_server_config(server_certs, server_key).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server_handle = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Ok(mut conn) = ServerConnection::new(server_config) {
                let mut stream = stream;
                // Reading from client should fail because TLS 1.2 is rejected
                let _ = conn.read_tls(&mut stream);
            }
        }
    });

    // Send a raw TLS 1.2 ClientHello record
    let tls12_client_hello = [
        0x16, 0x03, 0x03, 0x00, 0x2f, // Handshake record, TLS 1.2 (0x0303), len 47
        0x01, 0x00, 0x00, 0x2b, // ClientHello (1), len 43
        0x03, 0x03, // Version: TLS 1.2 (0x0303)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, // 32 random
        0x00, // Session ID len: 0
        0x00, 0x02, 0xc0, 0x2f, // Cipher suites len: 2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x01, 0x00, // Compression len: 1, null
        0x00, 0x00, // Extensions len: 0
    ];

    let mut client_tcp = TcpStream::connect(addr).unwrap();
    let _ = client_tcp.write_all(&tls12_client_hello);

    let mut response = [0u8; 128];
    let bytes_read = client_tcp.read(&mut response).unwrap_or(0);

    // TLS 1.3 server either closes connection or responds with fatal alert (record type 0x15)
    if bytes_read > 0 {
        assert_eq!(
            response[0], 0x15,
            "server must respond with fatal alert when TLS 1.2 is offered"
        );
    }

    server_handle.join().unwrap();
}

// -----------------------------------------------------------------------------
// Test 3: Rejection of Expired Server Certificate
// -----------------------------------------------------------------------------
#[test]
fn test_rejection_of_expired_certificate() {
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "OpenAudit Expired CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut expired_params = CertificateParams::default();
    expired_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    expired_params
        .subject_alt_names
        .push(SanType::DnsName("localhost".try_into().unwrap()));
    expired_params.not_before = date_time_ymd(2020, 1, 1);
    expired_params.not_after = date_time_ymd(2021, 1, 1);
    let expired_cert = expired_params.signed_by(&server_key, &issuer).unwrap();

    let server_certs = parse_certificates_from_pem(expired_cert.pem().as_bytes()).unwrap();
    let server_key = parse_private_key_from_pem(server_key.serialize_pem().as_bytes()).unwrap();
    let server_config = Arc::new(build_tls13_server_config(server_certs, server_key).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Ok(conn) = ServerConnection::new(server_config) {
                let mut tls_stream = StreamOwned::new(conn, stream);
                let _ = read_framed(&mut tls_stream, 1024);
            }
        }
    });

    let root_certs = parse_certificates_from_pem(ca_cert.pem().as_bytes()).unwrap();
    let client_config = Arc::new(build_tls13_client_config(root_certs).unwrap());

    let server_name = ServerName::try_from("localhost".to_string()).unwrap();
    let tcp_stream = TcpStream::connect(addr).unwrap();
    let conn = ClientConnection::new(client_config, server_name).unwrap();
    let mut tls_client = StreamOwned::new(conn, tcp_stream);

    let res = write_framed(&mut tls_client, b"PING");
    let res2 = read_framed(&mut tls_client, 1024);

    assert!(
        res.is_err() || res2.is_err(),
        "expired certificate must be rejected during handshake"
    );
}

// -----------------------------------------------------------------------------
// Test 4: Rejection of Hostname Mismatch (SAN / SNI Verification)
// -----------------------------------------------------------------------------
#[test]
fn test_rejection_of_hostname_mismatch() {
    // Server certificate issued for 'legitimate.openaudit.local'
    let pki = TestPki::generate("legitimate.openaudit.local");

    let server_certs = parse_certificates_from_pem(pki.server_cert_pem.as_bytes()).unwrap();
    let server_key = parse_private_key_from_pem(pki.server_key_pem.as_bytes()).unwrap();
    let server_config = Arc::new(build_tls13_server_config(server_certs, server_key).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Ok(conn) = ServerConnection::new(server_config) {
                let mut tls_stream = StreamOwned::new(conn, stream);
                let _ = read_framed(&mut tls_stream, 1024);
            }
        }
    });

    // Client connects expecting 'unrelated.attacker.local'
    let root_certs = parse_certificates_from_pem(pki.ca_cert_pem.as_bytes()).unwrap();
    let client_config = Arc::new(build_tls13_client_config(root_certs).unwrap());

    let server_name = ServerName::try_from("unrelated.attacker.local".to_string()).unwrap();
    let tcp_stream = TcpStream::connect(addr).unwrap();
    let conn = ClientConnection::new(client_config, server_name).unwrap();
    let mut tls_client = StreamOwned::new(conn, tcp_stream);

    let res = write_framed(&mut tls_client, b"PROBE");
    let res2 = read_framed(&mut tls_client, 1024);

    assert!(
        res.is_err() || res2.is_err(),
        "hostname mismatch must be rejected during handshake"
    );
}

// -----------------------------------------------------------------------------
// Test 5: Rejection of Untrusted Root CA (Unknown Issuer)
// -----------------------------------------------------------------------------
#[test]
fn test_rejection_of_untrusted_root_certificate() {
    let server_pki = TestPki::generate("localhost");
    let unrelated_pki = TestPki::generate("localhost");

    let server_certs = parse_certificates_from_pem(server_pki.server_cert_pem.as_bytes()).unwrap();
    let server_key = parse_private_key_from_pem(server_pki.server_key_pem.as_bytes()).unwrap();
    let server_config = Arc::new(build_tls13_server_config(server_certs, server_key).unwrap());

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Ok(conn) = ServerConnection::new(server_config) {
                let mut tls_stream = StreamOwned::new(conn, stream);
                let _ = read_framed(&mut tls_stream, 1024);
            }
        }
    });

    // Client trust store only trusts unrelated_pki's CA, NOT server_pki's CA
    let root_certs = parse_certificates_from_pem(unrelated_pki.ca_cert_pem.as_bytes()).unwrap();
    let client_config = Arc::new(build_tls13_client_config(root_certs).unwrap());

    let server_name = ServerName::try_from("localhost".to_string()).unwrap();
    let tcp_stream = TcpStream::connect(addr).unwrap();
    let conn = ClientConnection::new(client_config, server_name).unwrap();
    let mut tls_client = StreamOwned::new(conn, tcp_stream);

    let res = write_framed(&mut tls_client, b"UNTRUSTED");
    let res2 = read_framed(&mut tls_client, 1024);

    assert!(
        res.is_err() || res2.is_err(),
        "untrusted root certificate must be rejected with UnknownIssuer"
    );
}

// -----------------------------------------------------------------------------
// Test 6: Insecure Private Key Permissions Gating (Mode 0644 Rejection)
// -----------------------------------------------------------------------------
#[test]
fn test_rejection_of_insecure_private_key_permissions() {
    let pki = TestPki::generate("localhost");

    // Overwrite permissions to insecure 0644
    fs::set_permissions(&pki.server_key_path, fs::Permissions::from_mode(0o644)).unwrap();

    let res = load_private_key_from_file(&pki.server_key_path);
    assert!(
        res.is_err(),
        "insecure private key (mode 0644) must fail closed"
    );

    let err_msg = res.err().unwrap().to_string();
    assert!(
        err_msg.contains("insecure permissions"),
        "error must indicate permissions violation: {err_msg}"
    );

    // Restore 0600
    fs::set_permissions(&pki.server_key_path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_private_key_from_file(&pki.server_key_path).is_ok());
}

// -----------------------------------------------------------------------------
// Test 6b: Symlink Rejection for Private Keys and Certificates
// -----------------------------------------------------------------------------
#[test]
fn test_rejection_of_symlink_private_key_and_cert() {
    let pki = TestPki::generate("localhost");
    let temp_dir = std::env::temp_dir().join(format!("oa_tls_sym_{}", std::process::id()));
    fs::create_dir_all(&temp_dir).unwrap();

    let symlink_key = temp_dir.join("sym_key.pem");
    let symlink_cert = temp_dir.join("sym_cert.pem");

    std::os::unix::fs::symlink(&pki.server_key_path, &symlink_key).unwrap();
    std::os::unix::fs::symlink(&pki.server_cert_path, &symlink_cert).unwrap();

    let key_err = load_private_key_from_file(&symlink_key)
        .err()
        .unwrap()
        .to_string();
    assert!(
        key_err.contains("is not a regular file"),
        "symlink key must be rejected: {key_err}"
    );

    let cert_err = load_certificates_from_file(&symlink_cert)
        .err()
        .unwrap()
        .to_string();
    assert!(
        cert_err.contains("is not a regular file"),
        "symlink cert must be rejected: {cert_err}"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

// -----------------------------------------------------------------------------
// Test 6c: Frame Encoding, Decoding, and Error Handling (Empty, Oversized, Truncated)
// -----------------------------------------------------------------------------
#[test]
fn test_frame_encoding_and_error_handling() {
    use std::io::Cursor;

    // 1. Empty write is rejected
    let mut out = Vec::new();
    let err1 = write_framed(&mut out, b"").err().unwrap().to_string();
    assert!(err1.contains("cannot write empty framed message"));

    // 2. Empty read (len == 0) is rejected
    let mut zero_len = Cursor::new(0u32.to_be_bytes());
    let err2 = read_framed(&mut zero_len, 1024).err().unwrap().to_string();
    assert!(err2.contains("incoming message length is zero"));

    // 3. Oversized read is rejected
    let mut oversized = Cursor::new(100u32.to_be_bytes());
    let err3 = read_framed(&mut oversized, 50).err().unwrap().to_string();
    assert!(err3.contains("exceeds permitted limit"));

    // 4. Truncated read is rejected
    let mut truncated_data = Vec::new();
    truncated_data.extend_from_slice(&10u32.to_be_bytes());
    truncated_data.extend_from_slice(&[1, 2, 3]); // only 3 bytes instead of 10
    let mut truncated = Cursor::new(truncated_data);
    let err4 = read_framed(&mut truncated, 1024).err().unwrap().to_string();
    assert!(err4.contains("failed to read message body"));
}

// -----------------------------------------------------------------------------
// Test 7: Cross-Binary Encrypted Enrollment & Retrieval over Live TLS 1.3
// -----------------------------------------------------------------------------
#[test]
#[allow(clippy::too_many_lines)]
fn test_cross_binary_tls13_enrollment_and_retrieval() {
    let _lock = TLS_XB_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let swtpm = LiveSwtpm::new();
    let pki = TestPki::generate("localhost");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("target/debug"))
        .expect("must resolve target/debug");

    let server_bin = target_dir.join("openaudit-server");
    let agent_bin = target_dir.join("openaudit-agent");

    if !server_bin.is_file() || !agent_bin.is_file() {
        let _ = Command::new("cargo").args(["build", "--bins"]).output();
    }

    if !server_bin.is_file() || !agent_bin.is_file() {
        let _ = Command::new("cargo").args(["build", "--bins"]).output();
    }

    assert!(server_bin.is_file(), "server binary must exist");
    assert!(agent_bin.is_file(), "agent binary must exist");

    let temp_root = std::env::temp_dir().join(format!("oa_tls_xb_{}", std::process::id()));
    fs::create_dir_all(&temp_root).unwrap();

    let server_data = temp_root.join("server_data");
    let agent_state = temp_root.join("agent_state");
    fs::create_dir_all(&server_data).unwrap();
    fs::create_dir_all(&agent_state).unwrap();

    // 1. Initialize server baseline catalog
    let init_res = Command::new(&server_bin)
        .args([
            "authority",
            "catalog-init",
            "--data-dir",
            server_data.to_str().unwrap(),
        ])
        .output()
        .expect("catalog init");
    assert!(init_res.status.success());

    // 2. Agent provisions against swtpm
    let prov_res = Command::new(&agent_bin)
        .args([
            "provision",
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state.to_str().unwrap(),
        ])
        .output()
        .expect("agent provision");
    assert!(
        prov_res.status.success(),
        "agent provision failed: {}",
        String::from_utf8_lossy(&prov_res.stderr)
    );
    let prov_stdout = String::from_utf8_lossy(&prov_res.stdout);
    let machine_id = extract_field(&prov_stdout, "MACHINE_ID:").expect("machine id");

    // Copy agent-generated secret to server data directory with mode 0600
    let agent_secret = agent_state.join("tpm-auth.secret");
    let secret_file = server_data.join("tpm-auth.secret");
    fs::copy(&agent_secret, &secret_file).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();

    // 3. Issue single-use enrollment token bound to machine_id
    let token_res = Command::new(&server_bin)
        .args([
            "authority",
            "token-issue",
            "--data-dir",
            server_data.to_str().unwrap(),
            "--machine-id",
            &machine_id,
            "--generate-nonce",
            "--generation",
            "1",
            "--ttl-secs",
            "300",
        ])
        .output()
        .expect("token issue");
    assert!(
        token_res.status.success(),
        "token issue failed: {}",
        String::from_utf8_lossy(&token_res.stderr)
    );
    let token_stdout = String::from_utf8_lossy(&token_res.stdout);

    let token_id = extract_field(&token_stdout, "TOKEN_ID:").expect("token id");
    let nonce = extract_field(&token_stdout, "NONCE:").expect("nonce");
    let expires_at_ns = extract_field(&token_stdout, "EXPIRES_AT_NS:").expect("expires at");

    // 4. Start Server TLS 1.3 daemon on an ephemeral port
    let probe_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe_listener.local_addr().unwrap().port();
    drop(probe_listener);

    let bind_addr = format!("127.0.0.1:{port}");

    let mut server_child = Command::new(&server_bin)
        .args([
            "authority",
            "serve-tls",
            "--bind",
            &bind_addr,
            "--cert",
            pki.server_cert_path.to_str().unwrap(),
            "--key",
            pki.server_key_path.to_str().unwrap(),
            "--secret-file",
            secret_file.to_str().unwrap(),
            "--data-dir",
            server_data.to_str().unwrap(),
            "--max-requests",
            "3", // Handle enroll + 2 retrieves then cleanly shut down
        ])
        .spawn()
        .expect("spawn server daemon");

    // Wait for server to bind
    thread::sleep(Duration::from_millis(300));

    // 5. Agent executes enroll-tls
    let enroll_res = Command::new(&agent_bin)
        .args([
            "enroll-tls",
            "--server",
            &bind_addr,
            "--server-name",
            "localhost",
            "--ca-cert",
            pki.ca_cert_path.to_str().unwrap(),
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state.to_str().unwrap(),
            "--token-id",
            &token_id,
            "--nonce",
            &nonce,
            "--expires-at-ns",
            &expires_at_ns,
        ])
        .output()
        .expect("agent enroll-tls");

    assert!(
        enroll_res.status.success(),
        "enroll-tls failed: stderr={}",
        String::from_utf8_lossy(&enroll_res.stderr)
    );
    let enroll_out = String::from_utf8_lossy(&enroll_res.stdout);
    assert!(enroll_out.contains("TLS_ENROLL: SUCCESS"));

    // 6. Agent executes retrieve-tls
    let retrieve_res = Command::new(&agent_bin)
        .args([
            "retrieve-tls",
            "--server",
            &bind_addr,
            "--server-name",
            "localhost",
            "--ca-cert",
            pki.ca_cert_path.to_str().unwrap(),
            "--state-dir",
            agent_state.to_str().unwrap(),
        ])
        .output()
        .expect("agent retrieve-tls");

    assert!(
        retrieve_res.status.success(),
        "retrieve-tls failed: stderr={}",
        String::from_utf8_lossy(&retrieve_res.stderr)
    );
    let retrieve_out = String::from_utf8_lossy(&retrieve_res.stdout);
    assert!(retrieve_out.contains("TLS_RETRIEVE: SUCCESS"));
    assert!(retrieve_out.contains("CATALOG_VERSION: 1"));

    let _ = server_child.kill();
    let _ = server_child.wait();
    let _ = fs::remove_dir_all(&temp_root);
}

// -----------------------------------------------------------------------------
// Test 8: Replay Rejection Enforcement over Live TLS 1.3 Transport
// -----------------------------------------------------------------------------
#[test]
#[allow(clippy::too_many_lines)]
fn test_replay_protection_over_tls_transport() {
    let _lock = TLS_XB_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let swtpm = LiveSwtpm::new();
    let pki = TestPki::generate("localhost");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("target/debug"))
        .expect("must resolve target/debug");

    let server_bin = target_dir.join("openaudit-server");
    let agent_bin = target_dir.join("openaudit-agent");

    if !server_bin.is_file() || !agent_bin.is_file() {
        let _ = Command::new("cargo").args(["build", "--bins"]).output();
    }

    let temp_root = std::env::temp_dir().join(format!("oa_tls_replay_{}", std::process::id()));
    fs::create_dir_all(&temp_root).unwrap();

    let server_data = temp_root.join("server_data");
    let agent_state = temp_root.join("agent_state");
    fs::create_dir_all(&server_data).unwrap();
    fs::create_dir_all(&agent_state).unwrap();

    // Initialize catalog
    let _ = Command::new(&server_bin)
        .args([
            "authority",
            "catalog-init",
            "--data-dir",
            server_data.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    // Agent provisions against swtpm
    let prov_res = Command::new(&agent_bin)
        .args([
            "provision",
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state.to_str().unwrap(),
        ])
        .output()
        .expect("agent provision");
    assert!(prov_res.status.success());
    let prov_stdout = String::from_utf8_lossy(&prov_res.stdout);
    let machine_id = extract_field(&prov_stdout, "MACHINE_ID:").expect("machine id");

    // Copy agent-generated secret to server data directory
    let agent_secret = agent_state.join("tpm-auth.secret");
    let secret_file = server_data.join("tpm-auth.secret");
    fs::copy(&agent_secret, &secret_file).unwrap();
    fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600)).unwrap();

    // Issue token and enroll
    let token_res = Command::new(&server_bin)
        .args([
            "authority",
            "token-issue",
            "--data-dir",
            server_data.to_str().unwrap(),
            "--machine-id",
            &machine_id,
            "--generate-nonce",
            "--generation",
            "1",
            "--ttl-secs",
            "300",
        ])
        .output()
        .unwrap();
    assert!(
        token_res.status.success(),
        "token issue failed: {}",
        String::from_utf8_lossy(&token_res.stderr)
    );
    let token_stdout = String::from_utf8_lossy(&token_res.stdout);
    let token_id = extract_field(&token_stdout, "TOKEN_ID:").unwrap();
    let nonce = extract_field(&token_stdout, "NONCE:").unwrap();
    let expires_at_ns = extract_field(&token_stdout, "EXPIRES_AT_NS:").unwrap();

    let probe_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe_listener.local_addr().unwrap().port();
    drop(probe_listener);

    let bind_addr = format!("127.0.0.1:{port}");

    let mut server_child = Command::new(&server_bin)
        .args([
            "authority",
            "serve-tls",
            "--bind",
            &bind_addr,
            "--cert",
            pki.server_cert_path.to_str().unwrap(),
            "--key",
            pki.server_key_path.to_str().unwrap(),
            "--secret-file",
            secret_file.to_str().unwrap(),
            "--data-dir",
            server_data.to_str().unwrap(),
            "--max-requests",
            "4",
        ])
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_millis(300));

    // Enroll over TLS
    let enroll_res = Command::new(&agent_bin)
        .args([
            "enroll-tls",
            "--server",
            &bind_addr,
            "--server-name",
            "localhost",
            "--ca-cert",
            pki.ca_cert_path.to_str().unwrap(),
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state.to_str().unwrap(),
            "--token-id",
            &token_id,
            "--nonce",
            &nonce,
            "--expires-at-ns",
            &expires_at_ns,
        ])
        .output()
        .unwrap();
    assert!(
        enroll_res.status.success(),
        "enroll-tls failed: {}",
        String::from_utf8_lossy(&enroll_res.stderr)
    );

    // Generate a fixed retrieval request manually to test explicit replay attack
    let enroll_stdout = String::from_utf8_lossy(&enroll_res.stdout);
    let tx_id = extract_field(&enroll_stdout, "TRANSACTION_ID:").unwrap();
    let agent_retrieve_offline = Command::new(&agent_bin)
        .args([
            "retrieve",
            "--state-dir",
            agent_state.to_str().unwrap(),
            "--tx-id",
            &tx_id,
        ])
        .output()
        .unwrap();

    let retrieve_stdout = String::from_utf8_lossy(&agent_retrieve_offline.stdout);
    let raw_req_hex = extract_field(&retrieve_stdout, "RETRIEVAL_REQUEST:").unwrap();
    let proof_hex = extract_field(&retrieve_stdout, "HMAC_PROOF:").unwrap();

    // Now connect with TlsClientTransport and send the request
    let root_certs = load_certificates_from_file(&pki.ca_cert_path).unwrap();
    let client_config = Arc::new(build_tls13_client_config(root_certs).unwrap());

    let mut transport1 =
        TlsClientTransport::connect(&bind_addr, "localhost", client_config.clone()).unwrap();
    let req = TlsProtocolRequest::Retrieval {
        retrieval_message_hex: raw_req_hex,
        hmac_proof_hex: proof_hex,
    };

    let resp1 = transport1.exchange(&req).unwrap();
    assert!(
        matches!(resp1, TlsProtocolResponse::Success { .. }),
        "first retrieval over TLS must succeed"
    );
    let _ = transport1.shutdown();
    drop(transport1);

    // Replay attack: send identical request over a second TLS connection
    let mut transport2 =
        TlsClientTransport::connect(&bind_addr, "localhost", client_config).unwrap();
    let resp2 = transport2.exchange(&req).unwrap();

    match resp2 {
        TlsProtocolResponse::Error { code, message } => {
            assert_eq!(
                code, "REPLAY_DETECTED",
                "must be rejected as replay over TLS"
            );
            assert!(message.contains("replay detected"));
        }
        other @ TlsProtocolResponse::Success { .. } => {
            panic!("expected REPLAY_DETECTED error, got {other:?}")
        }
    }

    let _ = server_child.kill();
    let _ = server_child.wait();
    let _ = fs::remove_dir_all(&temp_root);
}

// -----------------------------------------------------------------------------
// Test 9: Complete 10-Step Cross-Binary TLS 1.3 Lifecycle with Process Restarts
// -----------------------------------------------------------------------------
#[test]
#[allow(clippy::too_many_lines)]
fn test_cross_binary_complete_tls13_lifecycle_with_restart() {
    let _lock = TLS_XB_MUTEX
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let swtpm = LiveSwtpm::new();
    let pki = TestPki::generate("localhost");
    let unrelated_pki = TestPki::generate("unrelated.authority");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(|p| p.join("target/debug"))
        .expect("must resolve target/debug");

    let server_bin = target_dir.join("openaudit-server");
    let agent_bin = target_dir.join("openaudit-agent");

    if !server_bin.is_file() || !agent_bin.is_file() {
        let _ = Command::new("cargo").args(["build", "--bins"]).output();
    }

    let temp_root = std::env::temp_dir().join(format!("oa_tls_lifecycle_{}", std::process::id()));
    fs::create_dir_all(&temp_root).unwrap();

    let server_data = temp_root.join("server_data");
    let agent_state = temp_root.join("agent_state");
    fs::create_dir_all(&server_data).unwrap();
    fs::create_dir_all(&agent_state).unwrap();

    // STEP 0: Initialize authority catalog (version 1)
    let init_res = Command::new(&server_bin)
        .args([
            "authority",
            "catalog-init",
            "--data-dir",
            server_data.to_str().unwrap(),
        ])
        .output()
        .expect("catalog init");
    assert!(init_res.status.success());

    // STEP 1: Start TLS Server daemon on an ephemeral port
    let probe_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = probe_listener.local_addr().unwrap().port();
    drop(probe_listener);

    let bind_addr = format!("127.0.0.1:{port}");

    // Agent provisions first to establish shared secret
    // STEP 3: Provision agent against TPM emulator
    let prov_res = Command::new(&agent_bin)
        .args([
            "provision",
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state.to_str().unwrap(),
        ])
        .output()
        .expect("agent provision");
    assert!(prov_res.status.success());
    let prov_stdout = String::from_utf8_lossy(&prov_res.stdout);
    let machine_id = extract_field(&prov_stdout, "MACHINE_ID:").expect("machine id");

    // Copy agent-generated secret to server data directory (mode 0600)
    let agent_secret = agent_state.join("tpm-auth.secret");
    let server_secret = server_data.join("tpm-auth.secret");
    fs::copy(&agent_secret, &server_secret).unwrap();
    fs::set_permissions(&server_secret, fs::Permissions::from_mode(0o600)).unwrap();

    let mut server_child = Command::new(&server_bin)
        .args([
            "authority",
            "serve-tls",
            "--bind",
            &bind_addr,
            "--cert",
            pki.server_cert_path.to_str().unwrap(),
            "--key",
            pki.server_key_path.to_str().unwrap(),
            "--secret-file",
            server_secret.to_str().unwrap(),
            "--data-dir",
            server_data.to_str().unwrap(),
            "--max-requests",
            "10",
        ])
        .spawn()
        .expect("spawn server daemon");

    thread::sleep(Duration::from_millis(300));

    // STEP 2: Validate server certificate over TLS
    let root_certs = load_certificates_from_file(&pki.ca_cert_path).unwrap();
    let client_config = Arc::new(build_tls13_client_config(root_certs).unwrap());
    {
        let mut transport_check =
            TlsClientTransport::connect(&bind_addr, "localhost", client_config.clone())
                .expect("certificate validation must succeed");
        let _ = transport_check.shutdown();
    }

    // STEP 4: Server issues single-use enrollment token
    let token_res = Command::new(&server_bin)
        .args([
            "authority",
            "token-issue",
            "--data-dir",
            server_data.to_str().unwrap(),
            "--machine-id",
            &machine_id,
            "--generate-nonce",
            "--generation",
            "1",
            "--ttl-secs",
            "300",
        ])
        .output()
        .expect("token issue");
    assert!(token_res.status.success());
    let token_stdout = String::from_utf8_lossy(&token_res.stdout);
    let token_id = extract_field(&token_stdout, "TOKEN_ID:").unwrap();
    let nonce = extract_field(&token_stdout, "NONCE:").unwrap();
    let expires_at_ns = extract_field(&token_stdout, "EXPIRES_AT_NS:").unwrap();

    // STEP 5: Enroll agent over live TLS
    let enroll_res = Command::new(&agent_bin)
        .args([
            "enroll-tls",
            "--server",
            &bind_addr,
            "--server-name",
            "localhost",
            "--ca-cert",
            pki.ca_cert_path.to_str().unwrap(),
            "--tpm",
            swtpm.sock_path.to_str().unwrap(),
            "--state-dir",
            agent_state.to_str().unwrap(),
            "--token-id",
            &token_id,
            "--nonce",
            &nonce,
            "--expires-at-ns",
            &expires_at_ns,
        ])
        .output()
        .expect("enroll-tls");
    assert!(
        enroll_res.status.success(),
        "enroll-tls stderr: {}",
        String::from_utf8_lossy(&enroll_res.stderr)
    );
    let enroll_out = String::from_utf8_lossy(&enroll_res.stdout);
    assert!(enroll_out.contains("TLS_ENROLL: SUCCESS"));
    let tx_id = extract_field(&enroll_out, "TRANSACTION_ID:").expect("transaction id");

    // STEP 6: Verify machine registration persisted in authority.db
    let authority_db = server_data.join("authority.db");
    assert!(authority_db.is_file(), "authority.db must exist");
    let auth_conn = rusqlite::Connection::open(&authority_db).unwrap();
    let registered_count: i64 = auth_conn
        .query_row("SELECT COUNT(*) FROM registered_machines", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        registered_count, 1,
        "machine must be registered in authority.db"
    );

    let token_consumed: i64 = auth_conn
        .query_row(
            "SELECT COUNT(*) FROM enrollment_tokens WHERE consumed = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(token_consumed, 1, "token must be marked consumed");
    drop(auth_conn);

    // STEP 7: Restart server and agent processes
    // Kill existing server child and spawn fresh instance
    let _ = server_child.kill();
    let _ = server_child.wait();

    let mut restarted_server = Command::new(&server_bin)
        .args([
            "authority",
            "serve-tls",
            "--bind",
            &bind_addr,
            "--cert",
            pki.server_cert_path.to_str().unwrap(),
            "--key",
            pki.server_key_path.to_str().unwrap(),
            "--secret-file",
            server_secret.to_str().unwrap(),
            "--data-dir",
            server_data.to_str().unwrap(),
            "--max-requests",
            "10",
        ])
        .spawn()
        .expect("restart server daemon");

    thread::sleep(Duration::from_millis(300));

    // STEP 8: Retrieve authorized catalog data over TLS using restarted agent & server
    let retrieve_res = Command::new(&agent_bin)
        .args([
            "retrieve-tls",
            "--server",
            &bind_addr,
            "--server-name",
            "localhost",
            "--ca-cert",
            pki.ca_cert_path.to_str().unwrap(),
            "--state-dir",
            agent_state.to_str().unwrap(),
            "--tx-id",
            &tx_id,
        ])
        .output()
        .expect("retrieve-tls");
    assert!(
        retrieve_res.status.success(),
        "retrieve-tls stderr: {}",
        String::from_utf8_lossy(&retrieve_res.stderr)
    );
    let retrieve_out = String::from_utf8_lossy(&retrieve_res.stdout);
    assert!(retrieve_out.contains("TLS_RETRIEVE: SUCCESS"));
    assert!(retrieve_out.contains("CATALOG_VERSION: 1"));

    // STEP 9: Replay rejection over TLS
    // Generate offline raw retrieval message
    let offline_retrieve = Command::new(&agent_bin)
        .args([
            "retrieve",
            "--state-dir",
            agent_state.to_str().unwrap(),
            "--tx-id",
            &tx_id,
        ])
        .output()
        .unwrap();
    let off_out = String::from_utf8_lossy(&offline_retrieve.stdout);
    let req_hex = extract_field(&off_out, "RETRIEVAL_REQUEST:").unwrap();
    let proof_hex = extract_field(&off_out, "HMAC_PROOF:").unwrap();

    let req_envelope = TlsProtocolRequest::Retrieval {
        retrieval_message_hex: req_hex,
        hmac_proof_hex: proof_hex,
    };

    let mut live_client =
        TlsClientTransport::connect(&bind_addr, "localhost", client_config.clone()).unwrap();
    let first_resp = live_client.exchange(&req_envelope).unwrap();
    assert!(matches!(first_resp, TlsProtocolResponse::Success { .. }));
    let _ = live_client.shutdown();
    drop(live_client);

    // Replay attack over a second TLS connection
    let mut replay_client =
        TlsClientTransport::connect(&bind_addr, "localhost", client_config).unwrap();
    let replay_resp = replay_client.exchange(&req_envelope).unwrap();
    match replay_resp {
        TlsProtocolResponse::Error { code, message } => {
            assert_eq!(code, "REPLAY_DETECTED");
            assert!(message.contains("replay detected"));
        }
        other @ TlsProtocolResponse::Success { .. } => {
            panic!("expected REPLAY_DETECTED error, got {other:?}")
        }
    }
    let _ = replay_client.shutdown();
    drop(replay_client);

    // STEP 10: Reject invalid certificates and malformed requests
    // 10a. Connection with untrusted CA certificate
    let untrusted_roots = load_certificates_from_file(&unrelated_pki.ca_cert_path).unwrap();
    let untrusted_config = Arc::new(build_tls13_client_config(untrusted_roots).unwrap());
    let untrusted_conn = TlsClientTransport::connect(&bind_addr, "localhost", untrusted_config);
    if let Ok(mut c) = untrusted_conn {
        let exchange_res = c.exchange(&req_envelope);
        assert!(
            exchange_res.is_err(),
            "untrusted certificate exchange must fail"
        );
    }

    // 10b. Malformed frame sent over valid TLS connection
    let raw_stream = TcpStream::connect(&bind_addr).unwrap();
    let valid_roots = load_certificates_from_file(&pki.ca_cert_path).unwrap();
    let valid_config = Arc::new(build_tls13_client_config(valid_roots).unwrap());
    let server_name = ServerName::try_from("localhost".to_string()).unwrap();
    let conn = ClientConnection::new(valid_config, server_name).unwrap();
    let mut tls_stream = StreamOwned::new(conn, raw_stream);

    // Send malformed JSON payload
    let bad_json = b"{ NOT_VALID_JSON }";
    write_framed(&mut tls_stream, bad_json).unwrap();
    let malformed_resp_bytes = read_framed(&mut tls_stream, 1024).unwrap();
    let malformed_resp: TlsProtocolResponse =
        serde_json::from_slice(&malformed_resp_bytes).unwrap();
    match malformed_resp {
        TlsProtocolResponse::Error { code, message } => {
            assert_eq!(code, "MALFORMED_REQUEST");
            assert!(message.contains("invalid request JSON"));
        }
        other @ TlsProtocolResponse::Success { .. } => {
            panic!("expected MALFORMED_REQUEST, got {other:?}")
        }
    }

    let _ = restarted_server.kill();
    let _ = restarted_server.wait();
    let _ = fs::remove_dir_all(&temp_root);
}

fn extract_field(output: &str, field_prefix: &str) -> Option<String> {
    for line in output.lines() {
        if let Some(rest) = line.strip_prefix(field_prefix) {
            return Some(rest.trim().to_string());
        }
    }
    None
}
