//! Comprehensive test suite for OpenAudit M4 Increment 1:
//! - Canonical target parsing and normalization
//! - Scope authorization policy evaluation
//! - SSRF and cloud metadata defense
//! - Multi-address DNS resolution and fail-closed validation
//! - DNS rebinding prevention via destination pinning
//! - Out-of-scope HTTP redirection prevention

use openaudit_network::error::NetworkError;
use openaudit_network::redirect::RedirectValidator;
use openaudit_network::resolver::{resolve_and_pin, MockDnsResolver};
use openaudit_network::scope::{IpClassification, ScopeDecision, TargetScope};
use openaudit_network::target::{CanonicalTarget, TargetType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[test]
fn test_ipv4_parsing_and_normalization() {
    let t1 = CanonicalTarget::parse("192.0.2.1").expect("Valid IPv4");
    assert_eq!(t1.normalized_host, "192.0.2.1");
    assert_eq!(
        t1.target_type,
        TargetType::Ipv4(Ipv4Addr::new(192, 0, 2, 1))
    );
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
    assert_eq!(
        t1.target_type,
        TargetType::Ipv6("2001:db8::1".parse().unwrap())
    );

    let t2 = CanonicalTarget::parse("[2001:db8::2]:8443").expect("Bracketed IPv6 with port");
    assert_eq!(t2.normalized_host, "2001:db8::2");
    assert_eq!(t2.port, Some(8443));

    let t3 = CanonicalTarget::parse("[::1]").expect("Bracketed loopback IPv6");
    assert_eq!(t3.normalized_host, "::1");
    assert_eq!(t3.target_type, TargetType::Ipv6(Ipv6Addr::LOCALHOST));
}

#[test]
fn test_ipv4_mapped_ipv6_canonicalization() {
    // ::ffff:192.0.2.1 must canonicalize to IPv4 192.0.2.1
    let t1 = CanonicalTarget::parse("::ffff:192.0.2.1").expect("IPv4-mapped IPv6");
    assert_eq!(t1.normalized_host, "192.0.2.1");
    assert_eq!(
        t1.target_type,
        TargetType::Ipv4(Ipv4Addr::new(192, 0, 2, 1))
    );

    let t2 =
        CanonicalTarget::parse("[::ffff:198.51.100.5]:80").expect("Bracketed IPv4-mapped IPv6");
    assert_eq!(t2.normalized_host, "198.51.100.5");
    assert_eq!(
        t2.target_type,
        TargetType::Ipv4(Ipv4Addr::new(198, 51, 100, 5))
    );
    assert_eq!(t2.port, Some(80));
}

#[test]
fn test_hostname_validation_and_normalization() {
    let t1 = CanonicalTarget::parse("Example.COM.").expect("FQDN with trailing dot");
    assert_eq!(t1.normalized_host, "example.com");
    assert_eq!(t1.target_type, TargetType::Hostname("example.com".into()));

    let t2 = CanonicalTarget::parse("https://Api-Prod.Server.Co.Ke:8443/v1/health#frag")
        .expect("URL with scheme and port");
    assert_eq!(t2.normalized_host, "api-prod.server.co.ke");
    assert_eq!(t2.port, Some(8443));

    // Invalid hostnames
    assert!(
        CanonicalTarget::parse("-invalid.com").is_err(),
        "Label cannot start with hyphen"
    );
    assert!(
        CanonicalTarget::parse("invalid-.com").is_err(),
        "Label cannot end with hyphen"
    );
    assert!(
        CanonicalTarget::parse("invalid..com").is_err(),
        "Empty consecutive label"
    );
    assert!(CanonicalTarget::parse("").is_err(), "Empty target");
}

#[test]
fn test_cloud_metadata_unconditionally_blocked() {
    let scope_open = TargetScope {
        allow_public: true,
        allow_private: true,
        allow_loopback: true,
        allow_link_local: true,
        allow_testnets: true,
        explicit_allowed_ips: std::collections::HashSet::new(),
    };

    // AWS IPv4 metadata: 169.254.169.254
    let aws_meta: IpAddr = "169.254.169.254".parse().unwrap();
    assert_eq!(
        scope_open.evaluate(aws_meta),
        ScopeDecision::Prohibited {
            classification: IpClassification::CloudMetadata,
            reason: "Destination is a Cloud Metadata Service (SSRF prohibited)"
        }
    );

    // AWS IPv6 metadata: [fd00:ec2::254]
    let aws_v6_meta: IpAddr = "fd00:ec2::254".parse().unwrap();
    assert_eq!(
        scope_open.evaluate(aws_v6_meta),
        ScopeDecision::Prohibited {
            classification: IpClassification::CloudMetadata,
            reason: "Destination is a Cloud Metadata Service (SSRF prohibited)"
        }
    );

    // Google Cloud Metadata hostname
    assert!(
        CanonicalTarget::parse("metadata.google.internal").is_err(),
        "Cloud metadata pseudo-hostname must be rejected at parse time"
    );
}

#[test]
fn test_authorized_and_unauthorized_private_networks() {
    let default_scope = TargetScope::default(); // allow_private = false
    let private_scope = TargetScope {
        allow_private: true,
        ..Default::default()
    };

    let rfc1918_ips: Vec<IpAddr> = vec![
        "10.0.1.50".parse().unwrap(),
        "172.20.10.1".parse().unwrap(),
        "192.168.1.254".parse().unwrap(),
        "fd12:3456:789a::1".parse().unwrap(), // IPv6 ULA
    ];

    for ip in rfc1918_ips {
        // Default scope: must be prohibited
        assert!(
            matches!(
                default_scope.evaluate(ip),
                ScopeDecision::Prohibited {
                    classification: IpClassification::PrivateRfc1918,
                    ..
                }
            ),
            "Private IP {ip} must be blocked under default scope"
        );

        // Authorized private scope: must be allowed
        assert_eq!(
            private_scope.evaluate(ip),
            ScopeDecision::Allowed(IpClassification::PrivateRfc1918),
            "Private IP {ip} must be permitted under authorized scope"
        );
    }
}

#[test]
fn test_loopback_and_link_local_restrictions() {
    let default_scope = TargetScope::default();
    let loopback_scope = TargetScope {
        allow_loopback: true,
        ..Default::default()
    };
    let link_local_scope = TargetScope {
        allow_link_local: true,
        ..Default::default()
    };

    let loopback_ips: Vec<IpAddr> = vec![
        "127.0.0.1".parse().unwrap(),
        "127.0.1.1".parse().unwrap(),
        "::1".parse().unwrap(),
    ];

    for ip in loopback_ips {
        assert!(matches!(
            default_scope.evaluate(ip),
            ScopeDecision::Prohibited {
                classification: IpClassification::Loopback,
                ..
            }
        ));
        assert_eq!(
            loopback_scope.evaluate(ip),
            ScopeDecision::Allowed(IpClassification::Loopback)
        );
    }

    let link_local: IpAddr = "169.254.10.20".parse().unwrap();
    assert!(matches!(
        default_scope.evaluate(link_local),
        ScopeDecision::Prohibited {
            classification: IpClassification::LinkLocal,
            ..
        }
    ));
    assert_eq!(
        link_local_scope.evaluate(link_local),
        ScopeDecision::Allowed(IpClassification::LinkLocal)
    );
}

#[test]
fn test_dns_resolution_and_address_pinning() {
    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert("api.example.com", vec!["93.184.216.34".parse().unwrap()]);

    let target = CanonicalTarget::parse("api.example.com:443").unwrap();
    let scope = TargetScope::default();

    let pinned = resolve_and_pin(&target, &scope, &mock_dns, 443).expect("Resolution succeeds");
    assert_eq!(
        pinned.pinned_addr,
        SocketAddr::new("93.184.216.34".parse().unwrap(), 443)
    );
    assert_eq!(pinned.sni_hostname, "api.example.com");
    assert_eq!(pinned.classification, IpClassification::Public);
    assert_eq!(pinned.http_host_header(), "api.example.com");
}

#[test]
fn test_dns_mixed_answers_fail_closed_ssrf_defense() {
    // An attacker configures a domain returning both a public IP and an internal metadata or private IP
    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert(
        "attacker-dual-homed.net",
        vec![
            "93.184.216.34".parse().unwrap(),   // Public IP
            "169.254.169.254".parse().unwrap(), // Prohibited Cloud Metadata!
        ],
    );

    let target = CanonicalTarget::parse("attacker-dual-homed.net").unwrap();
    let scope = TargetScope::default();

    let err = resolve_and_pin(&target, &scope, &mock_dns, 80).expect_err("Must fail closed!");
    assert!(
        matches!(err, NetworkError::SsrfViolation(ref s) if s.contains("Cloud Metadata")),
        "Dual-homed DNS response containing prohibited metadata must abort scan: {err:?}"
    );
}

#[test]
fn test_dns_rebinding_prevention_via_pinned_socket_addr() {
    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert("rebind-target.corp", vec!["93.184.216.34".parse().unwrap()]);

    let target = CanonicalTarget::parse("rebind-target.corp").unwrap();
    let scope = TargetScope::default();

    // 1. Initial resolution pins to 93.184.216.34
    let pinned = resolve_and_pin(&target, &scope, &mock_dns, 80).unwrap();
    assert_eq!(
        pinned.pinned_addr.ip(),
        "93.184.216.34".parse::<IpAddr>().unwrap()
    );

    // 2. Attacker modifies DNS to point to internal 127.0.0.1
    mock_dns.insert("rebind-target.corp", vec!["127.0.0.1".parse().unwrap()]);

    // 3. Socket connections strictly use pinned.socket_addr(), NOT re-resolving the hostname!
    assert_eq!(
        pinned.socket_addr().ip(),
        "93.184.216.34".parse::<IpAddr>().unwrap(),
        "Pinned target remains immune to subsequent DNS rebinding changes"
    );
}

#[test]
fn test_redirect_validation_blocks_ssrf_destination() {
    let mut mock_dns = MockDnsResolver::new();
    mock_dns.insert("legit-public.com", vec!["93.184.216.34".parse().unwrap()]);
    mock_dns.insert("evil-redirect.internal", vec!["10.0.0.5".parse().unwrap()]);

    let scope = TargetScope::default(); // private IP not authorized
    let origin_target = CanonicalTarget::parse("legit-public.com").unwrap();
    let origin_pinned = resolve_and_pin(&origin_target, &scope, &mock_dns, 80).unwrap();

    let validator = RedirectValidator::default();

    // 1. Relative redirect to same host: allowed
    let rel_redirect = validator
        .validate_redirect(0, "/dashboard", &origin_pinned, &scope, &mock_dns)
        .expect("Relative redirect to same host allowed");
    assert_eq!(rel_redirect.sni_hostname, "legit-public.com");

    // 2. Redirect to prohibited private IP: blocked!
    let err_private = validator
        .validate_redirect(
            0,
            "http://evil-redirect.internal/admin",
            &origin_pinned,
            &scope,
            &mock_dns,
        )
        .expect_err("Redirect to unauthorized internal IP must be blocked");
    assert!(
        matches!(err_private, NetworkError::RedirectViolation(ref s) if s.contains("Private internal RFC 1918")),
        "Redirect to unauthorized private address must abort: {err_private:?}"
    );

    // 3. Redirect to cloud metadata: blocked!
    let err_meta = validator
        .validate_redirect(
            0,
            "http://169.254.169.254/latest/meta-data/",
            &origin_pinned,
            &scope,
            &mock_dns,
        )
        .expect_err("Redirect to cloud metadata must be blocked");
    assert!(
        matches!(err_meta, NetworkError::RedirectViolation(ref s) if s.contains("Cloud Metadata")),
        "Redirect to cloud metadata must abort: {err_meta:?}"
    );

    // 4. Redirect hop limit exceeded
    let err_hops = validator
        .validate_redirect(5, "/next", &origin_pinned, &scope, &mock_dns)
        .expect_err("Hop limit exceeded must abort");
    assert!(
        matches!(err_hops, NetworkError::RedirectViolation(ref s) if s.contains("hop limit exceeded"))
    );
}
