//! End-to-end integration test validating Milestone M1 core domain models,
//! invariant enforcement, lifecycle transitions, and evidence redaction guarantees.

use openaudit_core::{
    Asset, AssetType, Criticality, Environment, Evidence, EvidencePayload, EvidenceType, Finding,
    FindingStatus, Fingerprint, OrganizationId, Scan, ScanJob, ScanStatus, Severity, TriggerType,
};

#[test]
fn test_end_to_end_domain_lifecycle_and_evidence_redaction() {
    // 1. Establish tenant boundary
    let org_id = OrganizationId::new();

    // 2. Register and validate an infrastructure asset
    let asset = Asset::new(
        org_id,
        "Production Ubuntu Bastion",
        AssetType::LinuxHost,
        "bastion.prod.internal",
    )
    .expect("asset creation should succeed");

    assert_eq!(asset.organization_id, org_id);
    assert_eq!(asset.environment, Environment::Production);
    assert_eq!(asset.criticality, Criticality::Medium);

    // 3. Initiate an audit scan session
    let mut scan = Scan::new(org_id, TriggerType::Scheduled);
    assert_eq!(scan.status, ScanStatus::Pending);

    scan.start().expect("scan should start");
    assert_eq!(scan.status, ScanStatus::Running);
    assert!(scan.started_at.is_some());

    // 4. Create an atomic scan job targeting the asset
    let mut job = ScanJob::new(scan.id, org_id, asset.id);
    assert_eq!(job.status, openaudit_core::JobStatus::Queued);
    job.status = openaudit_core::JobStatus::Running;

    // 5. Generate a security finding with deterministic fingerprint
    let rule_id = "ssh-permit-root-login";
    let target = "/etc/ssh/sshd_config";
    let expected_fingerprint = Fingerprint::compute(asset.id, rule_id, target);

    let mut finding = Finding::new(
        org_id,
        asset.id,
        rule_id,
        target,
        "SSH Root Login Permitted",
        "sshd configuration permits direct root login without public key restriction",
        "Set PermitRootLogin prohibit-password or no in /etc/ssh/sshd_config",
        Severity::High,
    )
    .expect("finding creation should succeed");

    assert_eq!(finding.fingerprint, expected_fingerprint);
    assert_eq!(finding.status, FindingStatus::Active);

    // 6. Attach evidence containing sensitive credentials and verify multi-layer redaction
    let raw_config = r"
        # sshd_config excerpt
        Port 22
        PermitRootLogin yes
        PasswordAuthentication yes
        # Embedded credentials that must be redacted
        password=SuperSecretPassword123!
        Authorization: Bearer secret-oauth-token-abcdef123456
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEA0mockkeydata
        -----END RSA PRIVATE KEY-----
    ";

    let payload = EvidencePayload::from_text(raw_config).expect("payload sanitization succeeded");
    let evidence = Evidence::new(finding.id, EvidenceType::ConfigExcerpt, payload);

    assert!(evidence.is_redacted);
    let sanitized_str = evidence.payload.data().as_str().expect("is string");

    // Invariant: no raw secrets survive redaction
    assert!(!sanitized_str.contains("SuperSecretPassword123!"));
    assert!(!sanitized_str.contains("secret-oauth-token-abcdef123456"));
    assert!(!sanitized_str.contains("MIIEowIBAAKCAQEA0mockkeydata"));

    // Expected redaction markers are present
    assert!(sanitized_str.contains("password=[REDACTED]"));
    assert!(sanitized_str.contains("Bearer [REDACTED]"));
    assert!(sanitized_str.contains("[REDACTED PRIVATE KEY]"));

    // 7. Record finding in scan summary
    scan.summary.record(finding.severity);
    assert_eq!(scan.summary.high, 1);
    assert_eq!(scan.summary.total(), 1);

    // 8. Complete the scan
    scan.complete().expect("scan should complete");
    assert_eq!(scan.status, ScanStatus::Completed);
    assert!(scan.completed_at.is_some());

    // 9. Finding resolution lifecycle
    finding.resolve();
    assert_eq!(finding.status, FindingStatus::Resolved);
    assert!(finding.resolved_at.is_some());

    // 10. Verify full JSON serialization & deserialization roundtrip
    let finding_json = serde_json::to_string(&finding).expect("finding serializes");
    let deserialized_finding: Finding =
        serde_json::from_str(&finding_json).expect("finding deserializes");
    assert_eq!(finding, deserialized_finding);

    let evidence_json = serde_json::to_string(&evidence).expect("evidence serializes");
    let deserialized_evidence: Evidence =
        serde_json::from_str(&evidence_json).expect("evidence deserializes");
    assert_eq!(evidence, deserialized_evidence);
}
