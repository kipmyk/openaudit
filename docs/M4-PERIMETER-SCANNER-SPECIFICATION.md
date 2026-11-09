# OpenAudit Milestone 4: Agentless Network Perimeter Scanner Specification

**Author:** OpenAudit Engineering & Security Architecture Team  
**Milestone:** M4 &mdash; Agentless Network Perimeter Auditing  
**Document Version:** 1.0.0  
**Status:** Approved Architectural Specification (Pre-Implementation Gate)  
**Contract Invariants:** Re-uses `AssessmentType::RemoteNetworkAssessment` and shared `Finding`/`Evidence` models in `openaudit-core`.

---

## 1. Executive Summary & Architectural Scope

Milestone 4 extends OpenAudit from local host security auditing into non-destructive, agentless perimeter security assessment. It enables security operators and system administrators to inspect the external or perimeter posture of an infrastructure endpoint using only an IPv4 address, IPv6 address, or fully qualified domain name (FQDN).

### The Inviolable Core Distinction: Network Assessment vs OS Audit

```
+-----------------------------------------------------------------------------------+
|                        M4 ASSESSMENT SCOPE & BOUNDARIES                           |
+-----------------------------------------------------------------------------------+
| WHAT M4 OBSERVES OVER THE NETWORK:                                                |
|  - Observable TCP/UDP open ports and responsive network services                  |
|  - Service protocol banners (e.g. SSH Identification, HTTP Server header)         |
|  - TLS certificate chains, SAN coverage, expiry, cipher suites, protocol versions |
|  - HTTP security response headers (HSTS, CSP, X-Frame-Options, Permissions-Policy) |
|  - DNS configuration, PTR consistency, and transport latency                     |
+-----------------------------------------------------------------------------------+
| WHAT M4 CAN NEVER INFER OR DETERMINE (BLOCKED BOUNDARY):                          |
|  - Local OS user accounts, UID 0 duplicates, or password hashes (/etc/shadow)     |
|  - Filesystem permissions, sensitive file modes (0600 vs 0777), SUID/SGID binaries |
|  - Kernel sysctl parameters (ASLR, dmesg restriction, IP forwarding)              |
|  - Internal package inventories (dpkg, rpm) and unexposed package CVEs           |
|  - Operating system firewall socket state (e.g. pf, iptables, socketfilterfw)     |
+-----------------------------------------------------------------------------------+
```

Every finding produced by M4 is strongly typed as `AssessmentType::RemoteNetworkAssessment`. It is an architectural defect to claim or present network-observable evidence as a full host configuration audit.

---

## 2. Target Ingestion, Normalization & Validation

### 2.1 Supported Target Formats
The M4 scanner accepts four canonical target formats:
1. **IPv4 Addresses:** Strict RFC 791 notation (e.g. `192.0.2.10`). Octal (`0300.0.2.10`), hex (`0xc0.0x00.0x02.0x0a`), or integer representations are rejected during parsing.
2. **IPv6 Addresses:** Strict RFC 4291 notation (e.g. `2001:db8::1`), enclosed in brackets when paired with ports (`[2001:db8::1]:443`). IPv4-mapped IPv6 addresses (`::ffff:192.0.2.1`) are canonicalized to standard IPv4.
3. **Fully Qualified Domain Names (FQDN):** RFC 1123 compliant hostnames (e.g. `api.example.com`). Maximum length 253 characters; labels between 1 and 63 characters consisting of `[a-zA-Z0-9-]`. Trailing dots (`example.com.`) are normalized.
4. **Target Address with Explicit Port:** Optional port override syntax (`target.example.com:8443`).

### 2.2 Rejection of Ambiguous or Malformed Inputs
The parser fails closed on:
- URI schemes (`http://`, `https://`, `ssh://`) passed as host targets.
- Embedded credentials (`user:pass@host`).
- URL path components, queries, or fragments (`host.com/admin?debug=1#frag`).
- Trailing whitespace, control characters, or non-printable ASCII.

---

## 3. Threat Model & Security Guardrails

### 3.1 Server-Side Request Forgery (SSRF) Prevention
To prevent OpenAudit from being coerced into scanning unauthorized internal endpoints, cloud metadata services, or private loopback addresses, the target evaluator enforces **Strict Scope Authorization**:

```
+-------------------------------------------------------------------------+
| Target String -> Strict Parser -> DNS Resolution -> IP Filter -> Scope |
+-------------------------------------------------------------------------+
                                          |
                         +----------------+----------------+
                         |                                 |
                  [Public Scope]                   [Private Scope]
             Routable Internet IP             RFC 1918 (10.0/8, 172.16/12, 192.168/16)
             Allowed by default               RFC 6598 CGNAT (100.64/10)
                                              Loopback (127.0.0.0/8, ::1)
                                              Link-Local (169.254.0.0/16, fe80::/10)
                                              Cloud Metadata (169.254.169.254)
                                              Multicast / Reserved / Broadcast
                                              REQUIRES --allow-private-targets FLAG
```

**Scope Invariant:** By default, scans against loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), cloud metadata (`169.254.169.254`, `[fd00:ec2::254]`), and private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) fail closed unless the operator explicitly passes `--allow-private-targets` alongside cryptographic or CLI authorization.

### 3.2 DNS Rebinding Defense (Two-Stage Verification)
Malicious targets may configure short TTLs (0s) where an initial lookup resolves to a benign public IP, and subsequent connections resolve to `127.0.0.1` or `169.254.169.254`.
- **Mitigation:**
  1. The target resolver resolves the FQDN to a concrete IP address before scan initiation.
  2. The resolved IP is validated against the scope filter.
  3. **Pinned Socket Connection:** All subsequent TCP/TLS probes connect directly to the resolved IP address via `SocketAddr`.
  4. The FQDN is retained solely as the HTTP `Host` header and TLS `ServerName` (SNI), never re-queried across individual port probes.

### 3.3 Explicit Authorization & Audit Logging
1. **Interactive / UI Confirmation:** Desktop GUI requires an explicit checkbox certification:  
   `"I certify that I am authorized to conduct perimeter assessments against this target."`
2. **CLI Requirement:** Unattended scans require `--confirm-authorized` or exit with code `2`.
3. **Audit Log Trail:** All scans record target, resolved IP, timestamp, user ID, scan profile, and probe counts.

---

## 4. Scan Profiles & Port Discovery Engine

### 4.1 Scan Profiles

| Profile Name | Default Port Set | Probe Depth | Operational Intent | Target Time |
| :--- | :--- | :--- | :--- | :--- |
| **Network (Conservative)** | Top 20 Common Ports (`21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443, 9000, 9090, 9443`) | TCP Connect + Service Banner + TLS / HTTP Headers | Fast, zero-disruption perimeter audit | $< 3\,\text{s}$ |
| **Standard** | Top 100 Well-Known Services (`1..1024` selected subsets + common web/db ports) | Conservative + Protocol Identification + TLS Cipher Suite Matrix | Comprehensive infrastructure audit | $5\,\text{s} - 15\,\text{s}$ |
| **Deep** | Custom port ranges (e.g. `1-1024` or explicit `1-65535` if requested) | Standard + Full Certificate Chain Hierarchy + HTTP Redirect Trace | Exhaustive perimeter verification | Bounded by rate limits |

### 4.2 Conservative TCP Connect Scanning (Unprivileged)
OpenAudit strictly rejects raw socket manipulation (`libpcap` / `AF_PACKET`), which requires root/admin capabilities and risks network driver instability.
- **Implementation:** Standard OS `std::net::TcpStream::connect_timeout`.
- **Port States:**
  - `Open`: TCP three-way handshake completed successfully (`SYN-ACK` received, connection established, immediately closed with `TCP FIN/RST`).
  - `Closed`: Immediate `TCP RST` received from target OS stack.
  - `Filtered / Timeout`: Connection timeout exceeded ($T_{\text{timeout}} = 1500\,\text{ms}$) or ICMP unreachable returned.
- **Concurrency & Rate Limiting:**
  - Max concurrent sockets: 32 (Conservative), 64 (Standard), 128 (Deep).
  - Rate limiting via token bucket algorithm to avoid triggering intrusion detection thresholds or firewall rate-blocks.

---

## 5. Service & Protocol Identification

When an open port is identified, the service probe engine inspects observable protocol responses:

```
+-----------+------------------------------------+-------------------------------------+
| Port      | Probe Sent                         | Expected Deterministic Parsing      |
+-----------+------------------------------------+-------------------------------------+
| 22 (SSH)  | Read initial server banner         | Extract SSH-2.0-OpenSSH_9.6p1, OS   |
| 80 (HTTP) | HEAD / HTTP/1.1\r\nHost: ...\r\n\r\n | Extract Server, Date, Headers     |
| 443 (TLS) | ClientHello (TLS 1.3 / 1.2)        | Extract ServerHello, Cert, Cipher   |
| 25 (SMTP) | Read initial greeting              | Extract 220 banner, ESMTP host      |
| 3306      | Read initial handshake packet      | Extract MySQL protocol version      |
| 5432      | SSLRequest probe                   | Detect PostgreSQL SSL capability    |
+-----------+------------------------------------+-------------------------------------+
```

**Confidence Scoring:** Every service identification is accompanied by an empirical confidence score:
- `High (0.9 - 1.0)`: Verbatim RFC protocol banner with unambiguous signature.
- `Medium (0.6 - 0.8)`: Port default matches response heuristic, but banner string is generic.
- `Low (0.3 - 0.5)`: Port open, but no recognizable application payload returned before timeout.

---

## 6. TLS Security & Certificate Evaluation

For every open TLS endpoint (`443`, `8443`, `9443`, or TLS-enabled service):

1. **Certificate Validity & Temporal Bounds:**
   - Evaluates `notBefore` and `notAfter`.
   - Generates finding if expired, not yet valid, or expiring within $\le 30$ days.
2. **Subject Alternative Names (SAN) Validation:**
   - Verifies target FQDN or IP matches SAN DNS names or IP addresses.
   - Detects wildcard certificate misuse.
3. **Certificate Chain & Trust Hierarchy:**
   - Validates against webpki standard root trust store.
   - Flags self-signed certificates, missing intermediate certificates, or untrusted CAs.
4. **Protocol Version Assessment:**
   - `TLS 1.3`: Compliant / Best Practice.
   - `TLS 1.2`: Acceptable Baseline (flags weak ciphers).
   - `TLS 1.0 / 1.1`: Deprecated & Insecure (Generates High Severity finding).
   - `SSLv3 / SSLv2`: Critical Severity finding.

---

## 7. HTTP Security Header Inspection

For web endpoints, OpenAudit evaluates defensive HTTP headers:

| Header | Evaluated Policy | Severity if Missing / Insecure |
| :--- | :--- | :--- |
| `Strict-Transport-Security` | Must include `max-age` $\ge 31536000$; recommend `includeSubDomains` | Medium |
| `Content-Security-Policy` | Detects absence or dangerous directives (`unsafe-inline`, `unsafe-eval`) | Medium |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` (Clickjacking defense) | Low |
| `X-Content-Type-Options` | Must be `nosniff` (MIME sniffing defense) | Low |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | Low |
| `Server` / `X-Powered-By` | Verifies whether excessive version information is leaked | Info |

---

## 8. Data Contracts & Architecture Integration

### 8.1 Engine Integration
M4 will be implemented as a dedicated crate: `crates/network`.
- Implements `NetworkScanner` trait.
- Produces standard `openaudit_core::Finding` and `openaudit_core::Evidence` objects.
- Does NOT touch or modify `crates/engine` platform collectors (`macos.rs`, `linux.rs`, `windows.rs`).

### 8.2 Strongly Typed Findings
Example M4 Finding:
```json
{
  "rule_id": "network.tls.cert-expiring-soon",
  "target": "api.example.com:443",
  "title": "TLS Certificate Expiring in 14 Days",
  "severity": "medium",
  "assessment_type": "remote_network_assessment",
  "evidence": {
    "type": "text",
    "payload": "Subject: CN=api.example.com\nIssuer: Let's Encrypt\nExpires: 2026-11-23T00:00:00Z\nDays Remaining: 14"
  },
  "remediation": "Renew TLS certificate before expiration to prevent service disruption."
}
```

---

## 9. M4 Acceptance Gates & Test Matrix

Prior to declaring M4 complete, the implementation must pass:
1. **SSRF Unit & Integration Tests:** 100% rejection of cloud metadata (`169.254.169.254`), loopback, and unauthorized private subnets.
2. **DNS Rebinding Tests:** Proof that IP address is pinned to initial connection and cannot be redirected mid-scan.
3. **Controlled Local Lab Probes:** Verification against local mock TCP/TLS servers with predictable open, closed, and timeout states.
4. **CLI Headless Verification:** `openaudit-cli scan remote <target>` executes without desktop or browser dependencies.
5. **Desktop UI Verification:** Target selection, profile picking, authorization confirmation, live progress, and report export working end to end.

