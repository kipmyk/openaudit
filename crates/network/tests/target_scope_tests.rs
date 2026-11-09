//! Comprehensive test suite for OpenAudit M4:
//! - Canonical target parsing, hardening, and normalization
//! - Explicit CIDR private authorization and multi-range validation
//! - SSRF defense and unconditional cloud metadata immunity
//! - Multi-address DNS resolution and dual-homed fail-closed defense
//! - DNS rebinding prevention via destination pinning
//! - Out-of-scope HTTP redirection prevention
//! - Real socket-level TCP connection discovery tests

use openaudit_network::error::NetworkError;
use openaudit_network::redirect::RedirectValidator;
use openaudit_network::resolver::{resolve_and_pin, MockDnsResolver};
use openaudit_network::scanner::{PortStatus, TcpScanConfig, TcpScanner};
use openaudit_network::scope::{IpCidr, IpClassification, ScopeDecision, TargetScope};
use openaudit_network::target::CanonicalTarget;
use std::net::{IpAddr, TcpListener};

#[test]
fn test_cidr_parsing_and_normalization() {
    let c1 = IpCidr::parse("10.20.0.0/16").expect("Valid IPv4 CIDR");
    assert_eq!(c1.to_string(), "10.20.0.0/16");
    assert!(c1.contains("10.20.1.1".parse().unwrap()));
    assert!(c1.contains("10.20.255.254".parse().unwrap()));
    assert!(!c1.contains("10.21.0.1".parse().unwrap()));

    // Host bits outside prefix length must be normalized out
    let c2 = IpCidr::parse("192.168.1.155/24").expect("Un-normalized host bits");
    assert_eq!(c2.to_string(), "192.168.1.0/24");
    assert!(c2.contains("192.168.1.1".parse().unwrap()));
    assert!(!c2.contains("192.168.2.1".parse().unwrap()));

    // IPv6 CIDR
    let c3 = IpCidr::parse("fd12:3456:789a::/48").expect("Valid IPv6 CIDR");
    assert!(c3.contains("fd12:3456:789a:1::1".parse().unwrap()));
    assert!(!c3.contains("fd12:3456:789b::1".parse().unwrap()));

    // Malformed CIDRs
    assert!(IpCidr::parse("10.20.0.0").is_err(), "Missing prefix slash");
    assert!(
        IpCidr::parse("10.20.0.0/33").is_err(),
        "Prefix exceeds 32 for IPv4"
    );
    assert!(
        IpCidr::parse("fd00::/129").is_err(),
        "Prefix exceeds 128 for IPv6"
    );
    assert!(IpCidr::parse("invalid/24").is_err(), "Invalid IP in CIDR");
}

#[test]
fn test_explicit_cidr_private_authorization() {
    let mut scope = TargetScope::default();
    let cidr1 = IpCidr::parse("10.20.0.0/16").unwrap();
    let cidr2 = IpCidr::parse("192.168.10.0/24").unwrap();
    scope.add_authorized_cidr(cidr1);
    scope.add_authorized_cidr(cidr2);

    // Targets inside authorized CIDR 1: allowed
    let allowed_ip1: IpAddr = "10.20.5.25".parse().unwrap();
    assert_eq!(
        scope.evaluate(allowed_ip1),
        ScopeDecision::Allowed(IpClassification::PrivateRfc1918)
    );

    // Targets inside authorized CIDR 2: allowed
    let allowed_ip2: IpAddr = "192.168.10.42".parse().unwrap();
    assert_eq!(
        scope.evaluate(allowed_ip2),
        ScopeDecision::Allowed(IpClassification::PrivateRfc1918)
    );

    // Targets in private range outside authorized CIDRs: strictly blocked!
    let unauthorized_private_ips: Vec<IpAddr> = vec![
        "10.21.0.1".parse().unwrap(),   // Different /16 in 10.0.0.0/8
        "192.168.1.1".parse().unwrap(), // Different /24 in 192.168.0.0/16
        "172.16.5.1".parse().unwrap(),  // Completely unlisted RFC 1918
        "fd00:1::1".parse().unwrap(),   // Unlisted IPv6 ULA
    ];

    for ip in unauthorized_private_ips {
        assert!(
            matches!(
                scope.evaluate(ip),
                ScopeDecision::Prohibited {
                    classification: IpClassification::PrivateRfc1918,
                    ..
                }
            ),
            "Private IP {ip} outside authorized CIDRs must be blocked"
        );
    }
}

#[test]
fn test_cloud_metadata_unconditionally_blocked_even_with_overlapping_cidr() {
    let mut scope = TargetScope::default();
    // Deliberately try to authorize an overlapping broad subnet
    let broad_v4 = IpCidr::parse("0.0.0.0/0").unwrap();
    let link_local_cidr = IpCidr::parse("169.254.0.0/16").unwrap();
    let broad_v6 = IpCidr::parse("fd00::/8").unwrap();

    scope.add_authorized_cidr(broad_v4);
    scope.add_authorized_cidr(link_local_cidr);
    scope.add_authorized_cidr(broad_v6);

    // AWS IPv4 metadata: 169.254.169.254 must still be unconditionally blocked!
    let aws_meta: IpAddr = "169.254.169.254".parse().unwrap();
    assert_eq!(
        scope.evaluate(aws_meta),
        ScopeDecision::Prohibited {
            classification: IpClassification::CloudMetadata,
            reason: "Destination is a Cloud Metadata Service (SSRF prohibited)"
        }
    );

    // AWS IPv6 metadata: [fd00:ec2::254] must still be unconditionally blocked!
    let aws_v6_meta: IpAddr = "fd00:ec2::254".parse().unwrap();
    assert_eq!(
        scope.evaluate(aws_v6_meta),
        ScopeDecision::Prohibited {
            classification: IpClassification::CloudMetadata,
            reason: "Destination is a Cloud Metadata Service (SSRF prohibited)"
        }
    );
}

#[test]
fn test_hardened_target_parsing_rejects_ambiguity() {
    // 1. Prohibit URL userinfo
    assert!(
        CanonicalTarget::parse("admin@example.com").is_err(),
        "Must reject userinfo"
    );
    assert!(
        CanonicalTarget::parse("user:pass@192.0.2.1").is_err(),
        "Must reject user:pass"
    );

    // 2. Prohibit unsupported schemes
    assert!(
        CanonicalTarget::parse("ssh://example.com").is_err(),
        "Must reject ssh://"
    );
    assert!(
        CanonicalTarget::parse("ftp://192.0.2.1").is_err(),
        "Must reject ftp://"
    );
    assert!(
        CanonicalTarget::parse("file:///etc/passwd").is_err(),
        "Must reject file://"
    );

    // 3. Allowed web schemes are stripped cleanly
    let http_target = CanonicalTarget::parse("http://example.com:8080/path?q=1#frag").unwrap();
    assert_eq!(http_target.normalized_host, "example.com");
    assert_eq!(http_target.port, Some(8080));

    // 4. Reject invalid and reserved port 0
    assert!(
        CanonicalTarget::parse("example.com:0").is_err(),
        "Must reject port 0"
    );
    assert!(
        CanonicalTarget::parse("example.com:70000").is_err(),
        "Must reject port > 65535"
    );
    assert!(
        CanonicalTarget::parse("example.com:abc").is_err(),
        "Must reject non-numeric port"
    );

    // 5. Reject malformed brackets in IPv6
    assert!(CanonicalTarget::parse("[::1").is_err(), "Unclosed bracket");
    assert!(
        CanonicalTarget::parse("::1]").is_err(),
        "Unmatched closing bracket"
    );
    assert!(CanonicalTarget::parse("[]").is_err(), "Empty brackets");
}

#[test]
fn test_loopback_and_link_local_require_separate_controls() {
    let mut scope = TargetScope::default();
    scope.add_authorized_cidr(IpCidr::parse("127.0.0.0/8").unwrap());

    // Even if 127.0.0.0/8 was added to CIDRs, loopback requires allow_loopback = true!
    let loopback_ip: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(matches!(
        scope.evaluate(loopback_ip),
        ScopeDecision::Prohibited {
            classification: IpClassification::Loopback,
            ..
        }
    ));

    scope.allow_loopback = true;
    assert_eq!(
        scope.evaluate(loopback_ip),
        ScopeDecision::Allowed(IpClassification::Loopback)
    );
}

#[test]
fn test_ipv4_mapped_ipv6_scope_evaluation() {
    let mut scope = TargetScope::default();
    scope.add_authorized_cidr(IpCidr::parse("10.50.0.0/16").unwrap());

    // Mapped IPv4 address matching authorized CIDR
    let mapped_authorized = CanonicalTarget::parse("::ffff:10.50.1.1").unwrap();
    let ip_auth = mapped_authorized.as_ip().unwrap();
    assert_eq!(
        scope.evaluate(ip_auth),
        ScopeDecision::Allowed(IpClassification::PrivateRfc1918)
    );

    // Mapped IPv4 address outside authorized CIDR
    let mapped_unauthorized = CanonicalTarget::parse("::ffff:192.168.1.1").unwrap();
    let ip_unauth = mapped_unauthorized.as_ip().unwrap();
    assert!(matches!(
        scope.evaluate(ip_unauth),
        ScopeDecision::Prohibited {
            classification: IpClassification::PrivateRfc1918,
            ..
        }
    ));
}

#[test]
fn test_dns_dual_homed_mixed_answers_fail_closed() {
    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert(
        "dual-homed.corp",
        vec![
            "93.184.216.34".parse().unwrap(), // Public
            "10.99.1.1".parse().unwrap(),     // Private (outside authorized CIDR)
        ],
    );

    let target = CanonicalTarget::parse("dual-homed.corp").unwrap();
    let scope = TargetScope::default(); // No private CIDRs authorized

    let err = resolve_and_pin(&target, &scope, &mock_dns, 80).expect_err("Must fail closed!");
    assert!(
        matches!(err, NetworkError::SsrfViolation(ref s) if s.contains("Private RFC 1918")),
        "Dual-homed DNS response containing unauthorized IP must fail closed: {err:?}"
    );
}

#[test]
fn test_redirect_to_unauthorized_private_cidr_blocked() {
    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert("public.example.com", vec!["93.184.216.34".parse().unwrap()]);
    mock_dns.insert("unauthorized.corp", vec!["10.88.1.1".parse().unwrap()]);

    let mut scope = TargetScope::default();
    scope.add_authorized_cidr(IpCidr::parse("10.20.0.0/16").unwrap()); // Only 10.20 is authorized!

    let origin_target = CanonicalTarget::parse("public.example.com").unwrap();
    let origin_pinned = resolve_and_pin(&origin_target, &scope, &mock_dns, 80).unwrap();

    let validator = RedirectValidator::default();
    let err = validator
        .validate_redirect(
            0,
            "http://unauthorized.corp/internal",
            &origin_pinned,
            &scope,
            &mock_dns,
        )
        .expect_err("Redirect into unauthorized private CIDR must be blocked");

    assert!(
        matches!(err, NetworkError::RedirectViolation(ref s) if s.contains("Private RFC 1918")),
        "Must abort redirect: {err:?}"
    );
}

/// Real socket-level TCP connection discovery tests using local loopback listeners.
#[test]
fn test_real_socket_tcp_connection_discovery() {
    // 1. Bind a real TCP listener on an ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind test listener");
    let open_port = listener.local_addr().unwrap().port();

    // 2. Choose an adjacent closed port (bind and drop to ensure it is closed)
    let closed_port = {
        let temp_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        temp_listener.local_addr().unwrap().port()
    };

    // 3. Create target and scope permitting loopback
    let target = CanonicalTarget::parse("127.0.0.1").unwrap();
    let scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let mock_dns = MockDnsResolver::new();
    let pinned = resolve_and_pin(&target, &scope, &mock_dns, open_port).unwrap();

    // 4. Configure real TCP scanner
    let config = TcpScanConfig::new(vec![open_port, closed_port], 1000, 2).unwrap();

    // 5. Execute actual socket-level discovery
    let results = TcpScanner::scan(&pinned, &config, None).expect("Scan executes");

    assert_eq!(results.len(), 2);

    let open_res = results.iter().find(|r| r.port == open_port).unwrap();
    assert_eq!(
        open_res.status,
        PortStatus::Open,
        "Port with active listener must be Open"
    );

    let closed_res = results.iter().find(|r| r.port == closed_port).unwrap();
    assert_eq!(
        closed_res.status,
        PortStatus::Closed,
        "Port without listener must be Closed"
    );
}

#[test]
fn test_ipv4_parsing_and_normalization() {
    let t1 = CanonicalTarget::parse("192.0.2.1").expect("Valid IPv4");
    assert_eq!(t1.normalized_host, "192.0.2.1");
    assert_eq!(t1.port, None);

    let t2 = CanonicalTarget::parse("  198.51.100.25:8080  ").expect("IPv4 with port");
    assert_eq!(t2.normalized_host, "198.51.100.25");
    assert_eq!(t2.port, Some(8080));

    let t3 = CanonicalTarget::parse("https://203.0.113.10:443/api/v1?test=1")
        .expect("IPv4 with URL scheme and path");
    assert_eq!(t3.normalized_host, "203.0.113.10");
    assert_eq!(t3.port, Some(443));
}

#[test]
fn test_ipv6_parsing_and_bracket_normalization() {
    let t1 = CanonicalTarget::parse("2001:db8::1").expect("Bare IPv6");
    assert_eq!(t1.normalized_host, "2001:db8::1");

    let t2 = CanonicalTarget::parse("[2001:db8::2]:8443").expect("Bracketed IPv6 with port");
    assert_eq!(t2.normalized_host, "2001:db8::2");
    assert_eq!(t2.port, Some(8443));

    let t3 = CanonicalTarget::parse("[::1]").expect("Bracketed loopback IPv6");
    assert_eq!(t3.normalized_host, "::1");
}

#[test]
fn test_hostname_rfc1123_validation() {
    let t1 = CanonicalTarget::parse("api.internal.corp").expect("Valid hostname");
    assert_eq!(t1.normalized_host, "api.internal.corp");

    let t2 = CanonicalTarget::parse("http://Web-01.Prod.Example.Com:8080/metrics")
        .expect("Hostname with scheme");
    assert_eq!(t2.normalized_host, "web-01.prod.example.com");
    assert_eq!(t2.port, Some(8080));
}

#[test]
fn test_dns_rebinding_prevention_via_pinned_socket_addr() {
    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert("rebind.example.com", vec!["93.184.216.34".parse().unwrap()]);

    let scope = TargetScope::default();
    let target = CanonicalTarget::parse("rebind.example.com").unwrap();
    let pinned = resolve_and_pin(&target, &scope, &mock_dns, 443).unwrap();

    assert_eq!(
        pinned.socket_addr().ip(),
        "93.184.216.34".parse::<std::net::IpAddr>().unwrap(),
        "Pinned target remains bound to initially resolved IP"
    );

    // Attacker modifies DNS record to point to cloud metadata
    mock_dns.insert(
        "rebind.example.com",
        vec!["169.254.169.254".parse().unwrap()],
    );

    // Subsequent operations using pinned target NEVER re-query DNS and remain pinned
    assert_eq!(
        pinned.socket_addr().ip(),
        "93.184.216.34".parse::<std::net::IpAddr>().unwrap(),
        "Pinned target is immune to DNS rebinding"
    );
}
