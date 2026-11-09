# OpenAudit: Competitor Benchmark & Technical Capability Research

**Author:** OpenAudit Architecture Team  
**Scope:** Technical evaluation of established host auditing, network scanning, and server management platforms  
**Status:** Normative Engineering Decision Record  
**Target Roadmap:** M3 (Local Host & GUI) • M4 (Agentless Perimeter) • M5 (Control Plane) • M6 (Attested Agents) • M7 (Reporting)

---

## Executive Summary

To evolve OpenAudit into a differentiated, high-assurance security auditing platform across local workstations, remote network endpoints, and enrolled server fleets, this research benchmark analyzes seven industry-standard tools:

1. **Lynis** (Local host security auditing & hardening)
2. **Wazuh** (Agent-based server fleet management & SIEM/XDR)
3. **Greenbone Community Edition / OpenVAS** (Vulnerability management & network scanning)
4. **Nmap** (Network discovery & service/version detection)
5. **Tenable Nessus** (Commercial enterprise credentialed & uncredentialed auditing)
6. **OpenSCAP** (Standardized compliance policy & OVAL evaluation)
7. **Chef InSpec** (Human-readable infrastructure compliance-as-code)

### Core Architectural Principle
A central finding across all evaluated tools is the **impermeable boundary between network perimeter observation and internal host configuration**. An IP address alone can never replace an operating system audit. OpenAudit maintains this boundary strictly across typed contracts, execution collectors, CLI subcommands, and desktop UI views.

---

## 1. Capability Comparison Matrix

| Dimension | Lynis | Wazuh | Greenbone (OpenVAS) | Nmap | Tenable Nessus | OpenSCAP | Chef InSpec | OpenAudit Target Architecture |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Focus** | Local host hardening | Centralized fleet XDR | Network vulnerability | Network discovery | Enterprise vulnerability | Regulatory compliance | Infrastructure testing | **Unified Local + Perimeter + Fleet** |
| **Execution Language** | POSIX Shell | C (Agent), Go/Python (Mgr) | C, Python, NASL | C/C++, Lua (NSE) | C++, Proprietary plugins | C, C++ | Ruby | **Rust (Zero Runtime Overhead)** |
| **Agentless IP Scan** | No | No | Yes (Deep vulnerability) | Yes (Discovery/Fingerprint) | Yes (Network checks) | No | No | **M4 (Fast, Safe Perimeter Engine)** |
| **Local Host Audit** | Yes (Excellent) | Yes (SCA/FIM) | No (Requires LSC) | No | No (Requires agent) | Yes (XCCDF/OVAL) | Yes (Local runner) | **M3 (Native Shared Engine)** |
| **Authenticated Remote** | Experimental SSH | No (Agent-first) | Yes (SSH, WMI/SMB) | Limited (NSE SSH) | Yes (SSH, WinRM, WMI) | Yes (Workbench over SSH) | Yes (Train SSH/WinRM) | **Evaluated Ad-hoc Tooling** |
| **Agent-Based Fleet** | No | Yes (Scalable) | No | No | Yes (Tenable Agent) | No | No | **M5/M6 (D4 Attested Agents)** |
| **OS Support** | Linux, macOS, BSD | Linux, Windows, macOS | Target OS independent | Target OS independent | Linux, Windows, macOS | Linux (RHEL first) | Linux, Windows, macOS | **Linux, Windows, macOS** |
| **Rule/Check Format** | Modular Shell scripts | XML/YAML rules | NASL scripts | Lua scripts | Proprietary NASL | XML (XCCDF, OVAL) | Ruby DSL | **Rust Trait-based Built-ins** |
| **Execution Duration** | 30s – 120s | Continuous background | Minutes to hours | 2s – 60s | 5 – 45 mins | 30s – 5 mins | 10s – 60s | **< 300ms Local, Predictable Net** |
| **Evidence Quality** | High (Text snippets) | Medium (Alert JSON) | High (Raw requests/responses) | High (Raw banners) | High (Detailed diffs) | Formal (OVAL XML) | High (Expected vs Actual) | **Cryptographic Tamper-Evident** |
| **Licensing** | GPLv3 | GPLv2 / Apache 2.0 | GPLv2+ | GPLv2 (Custom terms) | Commercial Proprietary | LGPL 2.1 | Commercial EULA | **Clean Apache 2.0 / MIT** |

---

## 2. Technical Profile & Deep-Dive by Benchmark Tool

### 2.1 Lynis (CISOfy)
- **Architecture:** Monolithic POSIX shell script engine with dynamic plugin loading (`include/tests_*`, `include/consts`). Zero compilation required.
- **Strengths to Adopt:**
  - **Hardening Index:** Synthesizes an overall system security score based on weighted controls.
  - **Categorized Output:** Clean separation of warnings (urgent vulnerabilities) and suggestions (hardening best practices).
  - **Practical Remediation:** Links findings directly to documentation and precise configuration directives.
- **Limitations & Antipatterns to Avoid:**
  - Shell-based execution is fundamentally fragile, slow, and prone to command substitution race conditions.
  - Spawns thousands of subshells per audit run, resulting in significant process overhead.
  - Parsing free-form text output from system utilities breaks across differing distro versions.
  - No remote network discovery; no central agent management.

### 2.2 Wazuh
- **Architecture:** Multi-tier distributed system comprising lightweight C endpoint agents (`wazuh-agent`), clustered Go/Python control managers (`wazuh-manager`), and an OpenSearch indexing/storage cluster.
- **Strengths to Adopt:**
  - **Secure Machine Enrollment:** Structured enrollment workflow with mutual TLS and cryptographic agent keys.
  - **Security Configuration Assessment (SCA):** YAML-based policy checks evaluating local registry keys, files, and running services.
  - **System Inventory (syscollector):** Asynchronous telemetry gathering for OS packages, open ports, network interfaces, and hardware specs.
- **Limitations & Antipatterns to Avoid:**
  - **Massive Infrastructure Footprint:** Deploying a minimal Wazuh cluster requires 8–16 GB of RAM and complex microservice orchestration.
  - **Legacy C Codebase:** Agent components have historically faced memory safety vulnerabilities in string parsing and network decoders.
  - **Asynchronous Alert Flooding:** Lacks localized, synchronous CLI report generation; everything flows to a remote database.

### 2.3 Greenbone Community Edition (OpenVAS)
- **Architecture:** Microservice architecture consisting of `openvas-scanner`, `gvmd` (Greenbone Vulnerability Management Daemon), PostgreSQL, Redis cache, and Greenbone Web Interface (GSA).
- **Strengths to Adopt:**
  - **NASL Plugin Logic:** Scripted checks that probe network ports and evaluate response banners against vulnerability databases.
  - **Authenticated LSC (Local Security Checks):** Connects over SSH or SMB to query RPM/DEB package databases directly from an external scanner.
  - **CVSS v3.1 Scoring & Evidence:** Pairs every vulnerability with CVE references, CVSS vectors, and verbatim service responses.
- **Limitations & Antipatterns to Avoid:**
  - Extremely heavy resource footprint (GBs of feeds, persistent Redis and PostgreSQL daemons).
  - High risk of intrusive scans: misconfigured vulnerability feeds can trigger denial-of-service on sensitive network devices.
  - Fragile SSH key handling requiring external credential stores.

### 2.4 Nmap (Network Mapper)
- **Architecture:** High-performance C/C++ engine utilizing raw socket crafting (`libpcap`, `libnetutil`), customized thread/connection pools, and the Lua-based Nmap Scripting Engine (NSE).
- **Strengths to Adopt:**
  - **Port Discovery Heuristics:** Adaptive round-trip time (RTT) calculation, congestion control, and timing templates (`-T1` to `-T4`).
  - **Service & Version Probes (`nmap-service-probes`):** Standardized, deterministic regex database for identifying protocols and server software from initial handshake bytes.
  - **Confidence Ratings:** Clear communication of detection certainty (e.g., Service Fingerprint confidence: 9/10).
- **Limitations & Antipatterns to Avoid:**
  - Requires elevated permissions (`root` or `CAP_NET_RAW`) for SYN stealth scans (`-sS`); unprivileged scanning requires fallbacks to TCP `connect()`.
  - Lua scripts vary drastically in code quality and error resilience.
  - Strictly limited to network-observable state; provides zero visibility into filesystem permissions or OS-internal configurations.

### 2.5 Tenable Nessus
- **Architecture:** Client-server scanning engine with proprietary compiled plugins, web administration console, and optional lightweight Tenable Agents.
- **Strengths to Adopt:**
  - **Executive & Forensic Reporting:** Industry-standard report templates providing executive summaries, technical forensics, and exportable compliance matrices.
  - **Vulnerability Prioritization Rating (VPR):** Combines CVSS severity with real-world exploit availability and threat intelligence.
  - **Audit File Compliance Policies:** Formal .audit files testing system benchmarks (CIS, DISA STIG).
- **Limitations & Antipatterns to Avoid:**
  - Proprietary, closed-source black box with restrictive licensing.
  - Enormous feed download bundles requiring multi-gigabyte storage updates before execution.

### 2.6 OpenSCAP
- **Architecture:** C/C++ library (`libopenscap`) implementing NIST's Security Content Automation Protocol (SCAP), supporting XCCDF benchmarks, OVAL checks, and CPE dictionaries.
- **Strengths to Adopt:**
  - **Rigorous Standard Mappings:** Direct traceability of every rule check to NIST SP 800-53, PCI-DSS, or CIS controls.
  - **State Machine Rule Statuses:** Formal distinction between `Pass`, `Fail`, `NotApplicable`, `Skipped`, and `Error`.
- **Limitations & Antipatterns to Avoid:**
  - Overwhelming XML schema complexity (XCCDF/OVAL files are tens of megabytes of nested XML).
  - Negligible Windows and macOS native coverage; heavily biased toward Red Hat Enterprise Linux.
  - Heavy build and runtime dependencies (`libxml2`, `libxslt`, `libgcrypt`).

### 2.7 Chef InSpec
- **Architecture:** Ruby DSL on top of the Chef runtime, utilizing `Train` (transport library) to connect locally or remotely over SSH, WinRM, or container APIs.
- **Strengths to Adopt:**
  - **Human-Readable Policy Code:** Expressive testing syntax that non-specialists can audit and understand.
  - **Unified Remote Transport Abstraction:** Same test runs locally or over SSH/WinRM without modifying check logic.
- **Limitations & Antipatterns to Avoid:**
  - Requires a full Ruby interpreter, making headless zero-dependency distribution impractical.
  - Relicensed from Apache 2.0 to commercial restrictive terms.
  - Slower execution speed due to interpreted Ruby VM startup times.

---

## 3. Crucial Technical Distinctions

```
+-----------------------------------------------------------------------------------+
|                           THE THREE ASSESSMENT BOUNDARIES                         |
+-----------------------------------------------------------------------------------+
| 1. AGENTLESS REMOTE NETWORK ASSESSMENT (IP / Hostname)                            |
|    Available: Open ports, TLS certs, HTTP headers, banner strings, DNS records     |
|    BLOCKED: Local users, /etc/shadow, package CVEs, sysctl kernel, SIP/Firewall   |
+-----------------------------------------------------------------------------------+
| 2. AUTHENTICATED REMOTE HOST ASSESSMENT (SSH / WinRM)                             |
|    Available: Full OS configuration, installed packages, user privileges          |
|    RISKS: Root credential storage, SSH key management, SSRF to internal jumphosts|
+-----------------------------------------------------------------------------------+
| 3. ENROLLED AGENT HOST ASSESSMENT (Lightweight Rust Agent)                        |
|    Available: Full OS configuration, continuous telemetry, offline evaluation     |
|    ASSURANCE: Hardware TPM / D4 attestation, mutual TLS, zero credentials stored  |
+-----------------------------------------------------------------------------------+
```

---

## 4. Architectural Lessons for OpenAudit

### What OpenAudit Adopts:
1. **Lynis-Style Local Audit Efficiency:** Zero-dependency, immediate terminal feedback, high-density actionable findings with explicit remediation commands.
2. **Nmap-Style Safe Network Probing:** Non-destructive TCP connect discovery, TLS handshake evaluation, and safe HTTP security header checks (M4).
3. **OpenSCAP-Style Rigorous Status States:** Explicit typing for `Pass`, `Fail`, `NotApplicable`, `Skipped`, and `Error`.
4. **Wazuh-Style Secure Agent Architecture:** Decoupled agent-server relationship with hardware-attested machine identity (D4) and mutual TLS (M5/M6).
5. **Nessus-Style High-Density Reporting:** Enterprise SaaS aesthetics (Linear/Stripe standard), crisp tabular forensics, and verifiable evidence payloads.

### What OpenAudit Deliberately Rejects:
1. **Heavy Microservice Footprints:** No mandatory multi-container Elasticsearch/Redis/PostgreSQL stacks for basic auditing.
2. **Interpreted Runtimes:** No Python, Ruby, or Node.js runtime prerequisites on audited hosts. The CLI and Agent remain 100% standalone, statically compiled Rust binaries.
3. **Destructive Network Probes:** No denial-of-service triggers, buffer overflow tests, or exploit payloads.
4. **Credential Sprawl:** No storage of plaintext root passwords or unprotected SSH keys for fleet management.
5. **Simulated Findings:** Zero synthetic metrics, mock data, or vibecoded progress bars. Every visual element reflects verified Rust telemetry.

---

## 5. Implementation Roadmap Alignment

| Roadmap Phase | Focus Area | Benchmarked Reference | OpenAudit Deliverable |
| :--- | :--- | :--- | :--- |
| **Milestone 3 (Current)** | Cross-Platform Local Host & Desktop GUI | Lynis, OpenSCAP | Native in-process engine, 43 platform-isolated rules, enterprise desktop GUI |
| **Milestone 4** | Agentless Network Perimeter Auditing | Nmap, Greenbone | Safe TCP discovery, TLS verification, HTTP security headers, anti-SSRF protections |
| **Milestone 5** | Centralized Control Plane & Storage | Wazuh Manager, Nessus | Multi-tenant REST/gRPC API, audit persistence, SQLite/PostgreSQL storage |
| **Milestone 6** | Secure Agent Communication & Attestation | Wazuh Agent, D4 TPM | Enrolled headless `openaudit-agent`, mutual TLS, hardware attestation, scheduled runs |
| **Milestone 7** | Enterprise Reporting & Governance | Nessus Reports, OpenSCAP | Automated compliance mapping (CIS/NIST), HTML/JSON/PDF exports, lifecycle management |
| **Milestone 8** | Public Alpha Release | Enterprise standards | Production-ready packaging, distribution, and community governance |

---

## 6. Exact Next Implementation Task

**Task:** Finalize and verify Milestone 3 local cross-platform packaging and git governance:
1. Perform local Git commit of verified M3 deliverables (`feat(desktop)`, `feat(cli)`, `docs(architecture)`).
2. Ensure working tree is clean and ready for Milestone 4 perimeter scanner design.

