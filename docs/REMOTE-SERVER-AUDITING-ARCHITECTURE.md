# OpenAudit: Remote Server Auditing & Interface Separation Architecture

**Document Status:** NORMATIVE ARCHITECTURE SPECIFICATION  
**Milestone Alignment:** Milestone 3 (Host Auditing Foundation) & Milestone 4–6 Roadmap  
**Target Platforms:** Linux Servers (Ubuntu 24.04, Debian 12 & 13), Windows Server (2022, 2025), macOS Host (Sonoma, Sequoia)  
**Security Invariant:** Strict Deliverable Isolation; Zero Shared State; Single Canonical Rust Engine  

---

## 1. Executive Architectural Principles

OpenAudit is designed for rigorous security posture auditing across **enterprise servers**, infrastructure nodes, and developer workstations. To prevent the degradation of security guarantees, architectural bloat, and false compliance claims, the platform strictly enforces three foundational principles:

1. **An IP address alone is never a substitute for an Operating System audit.**  
   Network-observable services (ports, TLS certificates, banners) indicate perimeter exposure, but cannot verify file permissions, local user accounts, sysctl hardening, daemon containment, or kernel security flags.
2. **The CLI is a permanently headless, standalone deliverable.**  
   `openaudit-cli` must never depend on desktop frameworks (Tauri, Wry, Tao), browser runtimes (WebKit, Chromium), or graphical environments (X11, Wayland, Cocoa). It must execute cleanly over SSH, in continuous integration, and inside minimal container environments.
3. **Single Canonical Engine; Zero Duplicated Logic.**  
   All interfaces—CLI, native Desktop, Server control plane, and background Agent—consume the identical typed domain contracts (`crates/core`) and evaluation engine (`crates/engine`). Security rules are implemented once in Rust and executed deterministically across all environments.

---

## 2. The Three Server Auditing Modes

```
+---------------------------------------------------------------------------------------------------+
|                                      OPENAUDIT SERVER MODES                                       |
+------------------------------------+----------------------------------+---------------------------+
| 1. Remote IP Scan (Agentless)      | 2. Authenticated Remote Scan     | 3. Agent-Based Auditing   |
| Roadmap: Milestone 4               | Roadmap: Future Remote Tooling   | Roadmap: Milestone 5 & 6  |
+------------------------------------+----------------------------------+---------------------------+
| Target: IPv4 / IPv6 / Hostname     | Target: IP + SSH / WinRM creds   | Target: Enrolled Agent    |
| Privilege: Zero host credentials   | Privilege: Operator SSH key/pass | Privilege: Local Token    |
| Scope: Network perimeter only      | Scope: Ad-hoc OS inspection      | Scope: Continuous Full OS |
| Transport: Raw TCP / TLS probes    | Transport: Ephemeral SSH tunnel  | Transport: mTLS / HTTPS   |
| Engine: Remote network probes      | Engine: Remote shell commands    | Engine: Native In-Process |
+------------------------------------+----------------------------------+---------------------------+
```

### Mode 1: Remote IP Scan (Agentless Perimeter Assessment) — Milestone 4
- **Operational Model:** The operator provides an external IPv4, IPv6, or FQDN (e.g. `192.0.2.10` or `api.corp.internal`).
- **Inspection Boundaries:**
  - Active TCP/UDP port enumeration across standardized service boundaries.
  - TLS/SSL handshake analysis (cipher suites, certificate expiration, SAN validation, protocol versions).
  - HTTP/HTTPS security header auditing (`HSTS`, `CSP`, `X-Content-Type-Options`, cookie security flags).
  - DNS hygiene (zone transfers, CAA records, DNSSEC validation).
  - Service banner capture and unauthenticated exposure detection (e.g. exposed databases, Redis, Elasticsearch).
- **Mandatory Safeguards:**
  - **Explicit Authorization:** Operators must explicitly confirm target ownership before initiating active port scanning.
  - **Anti-SSRF Protection:** Agentless scanning strictly forbids scanning link-local addresses (`169.254.0.0/16`, `fe80::/10`), loopback (`127.0.0.0/8`, `::1`), and cloud metadata endpoints (`169.254.169.254`) unless explicitly initiated in internal network mode with verified permissions.
  - **Strict Negative Scope:** *Never claim an agentless IP scan constitutes an OS compliance audit.* Reports must prominently state: *"Perimeter scan observable only from external network vantage point; internal OS posture unverified."*

### Mode 2: Authenticated Remote Scan (Ephemeral SSH / WinRM) — Future Remote Capability
- **Operational Model:** The operator provides an IP/hostname along with remote credentials (SSH private key or WinRM credentials) to perform an ad-hoc deep audit without pre-installing a persistent daemon.
- **Evaluation & Trade-offs:**
  - *Advantages:* Useful for legacy systems, air-gapped hosts, or one-off third-party audits where installing persistent agents is restricted by change-control policy.
  - *Critical Risks:* Requires handling high-privilege credentials in flight; vulnerable to network interruptions during multi-stage command execution; presents substantial SSH credential leakage risks if stored improperly; slow execution due to network round-trips for each telemetry check.
- **Architectural Decision:** Authenticated remote execution serves strictly as an ad-hoc, secondary utility. OpenAudit's primary architecture for enterprise server fleets is **Agent-Based Auditing (Mode 3)**.

### Mode 3: Agent-Based Server Auditing (Recommended Architecture) — Milestones 5 & 6
- **Operational Model:** A lightweight, headless daemon (`openaudit-agent`) is installed on the target Linux, Windows, or macOS server. It establishes cryptographic identity via TPM 2.0 / hardware keys or securely enrolled machine certificates with the OpenAudit Server (`openaudit-server`).
- **Workflow:**
  1. **Enrollment:** Agent generates machine identity and exchanges public keys during cryptographic enrollment (Dimension 4 protocols).
  2. **Local Evaluation:** Agent executes local posture checks in-process via `crates/engine` at sub-millisecond latencies with zero network latency.
  3. **Attested Transmission:** Audit results are canonically serialized (RFC 8785), cryptographically signed, and transmitted over mutual TLS to the control plane.
  4. **Fleet Visibility:** Central control plane aggregates findings, tracks configuration drift, alerts on regressions, and feeds the enterprise web dashboard (M7–M8).
- **Security Advantages:**
  - Zero distribution of operator SSH credentials across servers.
  - Audits run reliably on schedule regardless of network availability.
  - Size-bounded telemetry and strict cryptographic verification eliminate arbitrary remote shell injection vulnerabilities.

---

## 3. Strict Deliverable Isolation Matrix

To maintain the architectural integrity of OpenAudit, deliverables are partitioned into five strictly isolated targets:

| Deliverable Target | Workspace Path | Binary Name | Target Environment | Graphical / Desktop Dependencies |
| :--- | :--- | :--- | :--- | :--- |
| **Operator CLI** | `apps/cli` | `openaudit-cli` | Linux, macOS, Windows (Terminal, CI/CD, SSH) | **STRICTLY ZERO** (No Tao, Wry, Tauri, WebKit, X11, GTK) |
| **Desktop GUI** | `apps/desktop` | `openaudit-desktop` | macOS Workstation (Native Cocoa WebKit via Tao/Wry) | **ISOLATED** (Restricted to `apps/desktop` build target) |
| **Server Service** | `apps/server` | `openaudit-server` | Linux / Cloud Server (Headless Control Plane & API) | **STRICTLY ZERO** (Headless service daemon) |
| **Fleet Agent** | `apps/agent` | `openaudit-agent` | Linux Server, Windows Server, macOS (Headless) | **STRICTLY ZERO** (Headless audit daemon) |
| **Web Console** | `apps/web` | Browser Client | Web Browsers (M7–M8 Cloud Dashboard) | Pure frontend bundle; connects via authenticated API |

### Enforcement Mechanisms:
- **Cargo Dependency Fencing:** Graphical dependencies (`tao`, `wry`) are placed exclusively in `apps/desktop/Cargo.toml` under `[target.'cfg(target_os = "macos")'.dependencies]`. They do not exist in the root `Cargo.toml` workspace dependencies.
- **Automated Regression Auditing:** `apps/cli/tests/headless_isolation_regression.rs` parses `Cargo.lock` and executes programmatic `cargo tree` validation during CI to assert that no GUI crate ever enters the CLI or server dependency trees.

---

## 4. Security Rule Catalog Scoping by OS Platform

Security rules in `crates/engine` are explicitly classified and isolated by OS family to prevent misleading metrics:

```
+---------------------------------------------------------------------------------------------------+
|                            43 CANONICAL BUILT-IN SECURITY RULES                                   |
+------------------------------------+----------------------------------+---------------------------+
| macOS Native Controls (11 Rules)   | Linux Server Rules (20 Rules)    | Windows Server (12 Rules) |
+------------------------------------+----------------------------------+---------------------------+
| Host Target: macOS Sonoma/Sequoia  | Target: Ubuntu 24.04, Debian 12+ | Target: Server 2022/2025  |
| System Integrity Protection (SIP)  | SSH PermitRootLogin / Passwords  | Windows Defender Status   |
| FileVault Disk Encryption          | Interactive Service Shells       | Advanced Firewall Profiles|
| Gatekeeper Assessment Policy       | Sudoers NOPASSWD & Privileges    | LSA Protection & Registry |
| Application Firewall Socket Filter | Sysctl TCP/IP & Memory Hardening | Insecure Sharing Ports    |
| Guest Account & Remote Login State | Sensitive World-Writable Paths   | PowerShell Execution Policy|
| LaunchDaemon File Permissions      | Exposed Database Ports           | Unquoted Service Paths    |
+------------------------------------+----------------------------------+---------------------------+
```

### Presentation Standard:
- Interfaces must never label Linux or Windows server rules as "Cross-Platform" when auditing a macOS host.
- The UI and CLI must explicitly group rules by their native operating system:
  - **Active Host Controls:** Displayed with high signal priority for the currently running operating system.
  - **Server / Remote Catalog:** Scoped cleanly as reference rules executed via `openaudit-cli` on server baselines or via remote agent attestation.

---

## 5. Implementation Roadmap & Milestones

```
+---------------------------------------------------------------------------------------------------+
| M3: Host Posture Engine & Multi-Platform Packaging (CURRENT)                                      |
| [X] Linux Server baseline validation (Ubuntu 24.04, Debian 12, Debian 13)                        |
| [X] Windows Server rule implementations (Server 2022, Server 2025)                                |
| [X] macOS native host collectors and desktop GUI foundation                                       |
| [X] Headless CLI packaging and dependency isolation tests                                         |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| M4: Perimeter & Network Auditing (NEXT)                                                           |
| [ ] Agentless IPv4/IPv6 port enumeration and service fingerprinting                               |
| [ ] TLS 1.3/1.2 cipher suite, certificate validity, and HTTPS security header verification        |
| [ ] DNS hygiene and unauthenticated service exposure detection                                    |
| [ ] Anti-SSRF boundary enforcement and explicit target authorization workflows                    |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| M5: Control Plane & Fleet Registry                                                                |
| [ ] Centralized server inventory, organization hierarchies, and role-based access control         |
| [ ] Durable findings store with historical drift tracking and compliance scoring                  |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| M6: Agent Communication & Cryptographic Enrollment                                                |
| [ ] Secure agent identity enrollment using Dimension 4 protocols and hardware TPM/key stores      |
| [ ] Signed telemetry transmission over mutual TLS                                                 |
| [ ] Autonomous local scan scheduling and policy updates                                           |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| M7–M8: Multi-Server Web Console & Enterprise Reporting                                            |
| [ ] Multi-tenant fleet dashboard, compliance reports (SOC2, CIS, ISO 27001), and remediation sync |
+---------------------------------------------------------------------------------------------------+
```
