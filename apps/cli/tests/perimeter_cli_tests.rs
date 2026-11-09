//! # CLI Perimeter Assessment Integration Tests (M4 Increment 7)
//!
//! Validates the CLI interface for agentless network perimeter assessment:
//! - Mandatory authorization gate (--authorized / --certified)
//! - Scope validation and SSRF defenses (private CIDRs, loopback, metadata endpoints)
//! - Multi-subcommand routing (`network scan`, `perimeter scan`, `scan remote`)
//! - Output formats (Human, JSON, Markdown)
//! - File output handling (--output)
//! - Policy threshold enforcement (--fail-on)
//! - Preservation of local host scan backward compatibility

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn cli_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_openaudit-cli"))
}

/// Helper to run a local mock HTTP server on an ephemeral port.
fn run_mock_http_server(running: Arc<AtomicBool>) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    listener
        .set_nonblocking(true)
        .expect("Must set nonblocking");

    let handle = thread::spawn(move || {
        while running.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 1024];
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                    let _ = stream.read(&mut buf);

                    let response = "HTTP/1.1 200 OK\r\n\
                        Content-Length: 13\r\n\
                        Content-Type: text/plain\r\n\
                        Server: OpenAuditTest/1.0\r\n\
                        \r\n\
                        Hello, world!";
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    (port, handle)
}

#[test]
fn test_cli_network_scan_missing_authorized_fails_closed() {
    let output = Command::new(cli_binary_path())
        .args([
            "network",
            "scan",
            "127.0.0.1",
            "--allow-loopback",
            "--ports",
            "80",
        ])
        .output()
        .expect("CLI execution must succeed");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Must fail closed with exit code 1 when --authorized is omitted"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires explicit authorization"),
        "Must explain missing authorization: {stderr}"
    );
    assert!(
        stderr.contains("--authorized"),
        "Must advise passing --authorized: {stderr}"
    );
}

#[test]
fn test_cli_network_scan_unauthorized_private_cidr_fails_closed() {
    let output = Command::new(cli_binary_path())
        .args([
            "network",
            "scan",
            "10.250.1.1",
            "--authorized",
            "--ports",
            "80",
        ])
        .output()
        .expect("CLI execution must succeed");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Must fail closed when private network is not authorized via --allow-cidr"
    );

    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        stderr.contains("prohibited")
            || stderr.contains("ssrf violation")
            || stderr.contains("authorized cidr"),
        "Must explain scope violation: {stderr}"
    );
}

#[test]
fn test_cli_network_scan_cloud_metadata_unconditionally_prohibited() {
    let output = Command::new(cli_binary_path())
        .args([
            "network",
            "scan",
            "169.254.169.254",
            "--authorized",
            "--allow-cidr",
            "169.254.0.0/16",
            "--ports",
            "80",
        ])
        .output()
        .expect("CLI execution must succeed");

    assert_eq!(
        output.status.code(),
        Some(1),
        "Must unconditionally prohibit cloud metadata endpoints"
    );

    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        stderr.contains("metadata") || stderr.contains("prohibited"),
        "Must explicitly explain metadata prohibition: {stderr}"
    );
}

#[test]
fn test_cli_network_scan_local_server_with_authorization_json() {
    let running = Arc::new(AtomicBool::new(true));
    let (port, server_handle) = run_mock_http_server(running.clone());

    let port_str = port.to_string();
    let output = Command::new(cli_binary_path())
        .args([
            "network",
            "scan",
            "127.0.0.1",
            "--authorized",
            "--allow-loopback",
            "--ports",
            &port_str,
            "--format",
            "json",
        ])
        .output()
        .expect("CLI execution must succeed");

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    assert_eq!(
        output.status.code(),
        Some(0),
        "Authorized scan against local server must succeed with exit code 0"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Stdout must be valid JSON report");

    assert_eq!(parsed["canonical_host"], "127.0.0.1");
    assert_eq!(parsed["pinned_ip"], "127.0.0.1");
    assert_eq!(parsed["open_ports_count"], 1);

    let disclaimer = parsed["architecture_disclaimer"].as_str().unwrap();
    assert!(
        disclaimer.contains("Architectural Distinction")
            || disclaimer.contains("agentless assessment"),
        "Disclaimer must be preserved in JSON report"
    );
}

#[test]
fn test_cli_subcommand_aliases_route_identically() {
    let running = Arc::new(AtomicBool::new(true));
    let (port, server_handle) = run_mock_http_server(running.clone());

    let port_str = port.to_string();

    // 1. `scan remote <TARGET>`
    let out1 = Command::new(cli_binary_path())
        .args([
            "scan",
            "remote",
            "127.0.0.1",
            "--authorized",
            "--allow-loopback",
            "--ports",
            &port_str,
            "--format",
            "json",
        ])
        .output()
        .expect("scan remote must execute");

    // 2. `perimeter scan <TARGET>`
    let out2 = Command::new(cli_binary_path())
        .args([
            "perimeter",
            "scan",
            "127.0.0.1",
            "--certified",
            "--allow-loopback",
            "--ports",
            &port_str,
            "--format",
            "json",
        ])
        .output()
        .expect("perimeter scan must execute");

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    assert_eq!(out1.status.code(), Some(0));
    assert_eq!(out2.status.code(), Some(0));

    let j1: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out1.stdout)).unwrap();
    let j2: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out2.stdout)).unwrap();

    assert_eq!(j1["canonical_host"], j2["canonical_host"]);
    assert_eq!(j1["pinned_ip"], j2["pinned_ip"]);
}

#[test]
fn test_cli_network_scan_markdown_format() {
    let running = Arc::new(AtomicBool::new(true));
    let (port, server_handle) = run_mock_http_server(running.clone());

    let port_str = port.to_string();
    let output = Command::new(cli_binary_path())
        .args([
            "network",
            "scan",
            "127.0.0.1",
            "--authorized",
            "--allow-loopback",
            "--ports",
            &port_str,
            "--format",
            "markdown",
        ])
        .output()
        .expect("CLI execution must succeed");

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(stdout.contains("# OpenAudit Network Perimeter Assessment Report"));
    assert!(stdout.contains("## Discovered Endpoints"));
    assert!(stdout.contains("| Port | Status | Protocol | Service |"));
    assert!(stdout.contains("## Architectural Boundary Notice"));
}

#[test]
fn test_cli_network_scan_output_to_file() {
    let running = Arc::new(AtomicBool::new(true));
    let (port, server_handle) = run_mock_http_server(running.clone());

    let temp_dir = std::env::temp_dir();
    let out_file = temp_dir.join(format!("openaudit_test_report_{port}.md"));

    let port_str = port.to_string();
    let output = Command::new(cli_binary_path())
        .args([
            "network",
            "scan",
            "127.0.0.1",
            "--authorized",
            "--allow-loopback",
            "--ports",
            &port_str,
            "--format",
            "markdown",
            "--output",
            out_file.to_str().unwrap(),
        ])
        .output()
        .expect("CLI execution must succeed");

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    assert_eq!(output.status.code(), Some(0));
    assert!(out_file.exists(), "Report file must be created");

    let file_content = fs::read_to_string(&out_file).expect("File must be readable");
    assert!(file_content.contains("# OpenAudit Network Perimeter Assessment Report"));
    let _ = fs::remove_file(out_file);
}

#[test]
fn test_cli_network_scan_fail_on_policy_threshold() {
    let running = Arc::new(AtomicBool::new(true));
    let (port, server_handle) = run_mock_http_server(running.clone());

    let port_str = port.to_string();

    // 1. --fail-on info: Should trigger exit code 2 because the mock server lacks security headers (CSP, HSTS)
    let out_fail = Command::new(cli_binary_path())
        .args([
            "network",
            "scan",
            "127.0.0.1",
            "--authorized",
            "--allow-loopback",
            "--ports",
            &port_str,
            "--fail-on",
            "info",
        ])
        .output()
        .expect("CLI execution must succeed");

    // 2. --fail-on critical: Should succeed with exit code 0 because missing headers are Low/Medium/Info
    let out_pass = Command::new(cli_binary_path())
        .args([
            "network",
            "scan",
            "127.0.0.1",
            "--authorized",
            "--allow-loopback",
            "--ports",
            &port_str,
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("CLI execution must succeed");

    running.store(false, Ordering::Relaxed);
    let _ = server_handle.join();

    assert_eq!(
        out_fail.status.code(),
        Some(2),
        "Must exit with code 2 when findings meet or exceed --fail-on threshold"
    );
    assert_eq!(
        out_pass.status.code(),
        Some(0),
        "Must exit with code 0 when no findings meet or exceed --fail-on critical"
    );
}

#[test]
fn test_cli_local_host_scan_backward_compatibility() {
    // Verifies that `openaudit-cli scan` remains completely functional for local host auditing
    let output = Command::new(cli_binary_path())
        .args(["scan", "--format", "json"])
        .output()
        .expect("CLI local scan must execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Stdout must be valid host audit report JSON");

    assert!(parsed.get("asset").is_some());
    assert!(parsed.get("findings").is_some());
    assert!(parsed.get("summary").is_some());
}
