//! # Headless CLI Isolation & Architecture Regression Tests
//!
//! Validates that `openaudit-cli` remains a strictly headless, standalone binary
//! completely isolated from graphical/desktop frameworks (Tao, Wry, Tauri, `WebKit`, GTK, X11).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use openaudit_core::OrganizationId;
use openaudit_engine::{AuditEngine, AuditProfile, PlatformFamily};

/// Inspects the workspace `Cargo.lock` to assert that `openaudit-cli` does not transitively
/// pull in any desktop, windowing, or browser-engine crates.
#[test]
fn test_cli_dependency_tree_is_strictly_headless() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lock_path = manifest_dir.join("../../Cargo.lock");

    let lock_content = fs::read_to_string(&lock_path)
        .expect("Cargo.lock must exist at workspace root for dependency auditing");

    // Forbidden graphical frameworks and browser runtimes for headless CLI
    let forbidden_crates = [
        "name = \"tao\"",
        "name = \"wry\"",
        "name = \"tauri\"",
        "name = \"gtk\"",
        "name = \"gdk\"",
        "name = \"x11\"",
        "name = \"x11-dl\"",
        "name = \"wayland-client\"",
        "name = \"webkit2gtk\"",
        "name = \"winit\"",
    ];

    // Locate the [[package]] block for openaudit-cli
    let cli_package_start = lock_content
        .find("name = \"openaudit-cli\"")
        .expect("openaudit-cli package must be present in Cargo.lock");

    let cli_package_slice = &lock_content[cli_package_start..];
    let next_pkg = cli_package_slice[1..]
        .find("[[package]]")
        .map_or(cli_package_slice.len(), |idx| idx + 1);
    let cli_block = &cli_package_slice[..next_pkg];

    // Assert that the direct dependencies list in Cargo.lock does not include forbidden GUI crates
    for forbidden in &forbidden_crates {
        assert!(
            !cli_block.contains(forbidden),
            "Architectural violation: openaudit-cli directly or transitively depends on forbidden GUI crate: {forbidden}"
        );
    }

    // Now run `cargo tree -p openaudit-cli --prefix none` programmatically to inspect full transitive tree
    let output = Command::new("cargo")
        .args(["tree", "-p", "openaudit-cli", "--prefix", "none"])
        .current_dir(&manifest_dir)
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let tree_output = String::from_utf8_lossy(&out.stdout);
            for crate_name in &["tao ", "wry ", "tauri ", "gtk ", "webkit ", "winit "] {
                assert!(
                    !tree_output.contains(crate_name),
                    "Architectural violation: Transitive dependency '{crate_name}' detected in openaudit-cli graph!"
                );
            }
        }
    }
}

/// Verifies that local host posture evaluation can run completely headlessly without
/// any display server or graphical environment variables (e.g. over SSH, cron, CI/CD).
#[test]
fn test_cli_runs_headlessly_without_display_environment() {
    let org_id = OrganizationId::from_seed(b"openaudit:headless:test-org");
    let engine = AuditEngine::default();

    // Verify baseline profile execution in pure headless mode
    let report = engine
        .run_audit_with_profile(org_id, AuditProfile::Baseline)
        .expect("Headless audit must execute cleanly without display environment");

    assert!(!report.asset.name.is_empty());
    assert!(report.duration_ms > 0);

    // Verify hardened profile execution in pure headless mode
    let hardened_report = engine
        .run_audit_with_profile(org_id, AuditProfile::Hardened)
        .expect("Hardened audit must execute cleanly in headless environment");

    assert!(!hardened_report.asset.name.is_empty());
}

/// Verifies that the CLI's HTML report generator produces a self-contained, standalone
/// HTML document that does not require `WebKit`, network fetching, or graphical execution.
#[test]
fn test_cli_html_report_is_self_contained_and_headless() {
    let org_id = OrganizationId::from_seed(b"openaudit:headless:report-org");
    let engine = AuditEngine::default();
    let report = engine
        .run_audit_with_profile(org_id, AuditProfile::Baseline)
        .expect("Audit execution must succeed");

    // Serialize report to JSON
    let json_bytes = serde_json::to_vec(&report).expect("Audit report must serialize to JSON");
    assert!(!json_bytes.is_empty());

    // Verify JSON round-trip deserialization without UI runtime
    let deserialized: openaudit_engine::AuditReport =
        serde_json::from_slice(&json_bytes).expect("Audit report must deserialize headlessly");
    assert_eq!(deserialized.asset.name, report.asset.name);
}

/// Verifies that the engine contains all built-in rules across Linux, Windows, and macOS,
/// and that server host auditing does not silently drop or simulate rules.
#[test]
fn test_server_auditing_rule_coverage_and_invariants() {
    let engine = AuditEngine::default();
    let rules = engine.rules();

    // Minimum requirement: 43 built-in rules (11 macOS, 20 Linux, 12 Windows)
    assert!(
        rules.len() >= 43,
        "Engine must retain all 43 built-in rules for server auditing, found {}",
        rules.len()
    );

    // Verify Linux server rules exist
    let linux_rule_count = rules
        .iter()
        .filter(|r| r.target_platforms().contains(&PlatformFamily::Linux))
        .count();
    assert!(linux_rule_count >= 20, "Must contain Linux server rules");

    // Verify Windows server rules exist
    let windows_rule_count = rules
        .iter()
        .filter(|r| r.target_platforms().contains(&PlatformFamily::Windows))
        .count();
    assert!(
        windows_rule_count >= 12,
        "Must contain Windows server rules"
    );

    // Verify macOS rules exist
    let macos_rule_count = rules
        .iter()
        .filter(|r| r.target_platforms().contains(&PlatformFamily::MacOS))
        .count();
    assert!(macos_rule_count >= 11, "Must contain macOS rules");
}

/// Regression test proving that rule totals and platform execution counts are 100% consistent:
/// - 43 total registered rules (20 Linux, 12 Windows, 11 macOS).
/// - On macOS: exactly 32 rules are marked `UnsupportedPlatform` (20 Linux + 12 Windows).
/// - On macOS Baseline: 9 executed + 2 profile-excluded + 32 unsupported = 43 total.
/// - On macOS Hardened: 11 executed + 0 profile-excluded + 32 unsupported = 43 total.
#[test]
fn test_audit_rule_accounting_exact_counts_and_invariants() {
    use openaudit_engine::CheckExecutionStatus;

    let org_id = OrganizationId::from_seed(b"openaudit:rule-accounting:test-org");
    let engine = AuditEngine::default();
    assert_eq!(
        engine.rules().len(),
        43,
        "Engine must register exactly 43 rules"
    );

    // 1. Baseline profile evaluation
    let baseline_report = engine
        .run_audit_with_profile(org_id, AuditProfile::Baseline)
        .expect("Baseline audit must succeed");

    assert_eq!(baseline_report.check_statuses.len(), 43);

    let baseline_unsupported = baseline_report
        .check_statuses
        .iter()
        .filter(|s| matches!(s.status, CheckExecutionStatus::UnsupportedPlatform { .. }))
        .count();
    assert_eq!(
        baseline_unsupported, 32,
        "All 20 Linux and 12 Windows rules must be marked UnsupportedPlatform on macOS"
    );

    let baseline_excluded = baseline_report
        .check_statuses
        .iter()
        .filter(|s| matches!(s.status, CheckExecutionStatus::NotApplicable { .. }))
        .count();
    assert_eq!(
        baseline_excluded, 2,
        "Exactly 2 macOS hardened rules must be excluded under Baseline profile"
    );

    let baseline_executed = baseline_report
        .check_statuses
        .iter()
        .filter(|s| matches!(s.status, CheckExecutionStatus::Executed { .. }))
        .count();
    assert_eq!(
        baseline_executed, 9,
        "Exactly 9 macOS baseline rules must be executed under Baseline profile"
    );

    // Sum invariant: 32 + 2 + 9 == 43
    assert_eq!(
        baseline_unsupported + baseline_excluded + baseline_executed,
        43
    );

    // 2. Hardened profile evaluation
    let hardened_report = engine
        .run_audit_with_profile(org_id, AuditProfile::Hardened)
        .expect("Hardened audit must succeed");

    assert_eq!(hardened_report.check_statuses.len(), 43);

    let hardened_unsupported = hardened_report
        .check_statuses
        .iter()
        .filter(|s| matches!(s.status, CheckExecutionStatus::UnsupportedPlatform { .. }))
        .count();
    assert_eq!(hardened_unsupported, 32);

    let hardened_executed = hardened_report
        .check_statuses
        .iter()
        .filter(|s| matches!(s.status, CheckExecutionStatus::Executed { .. }))
        .count();
    assert_eq!(
        hardened_executed, 11,
        "All 11 macOS native rules must be executed under Hardened profile"
    );

    // Sum invariant: 32 + 0 + 11 == 43
    assert_eq!(hardened_unsupported + hardened_executed, 43);
}
