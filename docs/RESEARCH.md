# Landscape Research & Standards Alignment

This document analyzes existing open-source security tools, examines relevant security frameworks, differentiates verified facts from technical assumptions, and identifies OpenAudit's practical niche for small organizations, nonprofits, and independent operators.

---

## 1. Tool Analysis

### 1. Wazuh
- **Problem Solved:** Full-scale Security Information and Event Management (SIEM), Extended Detection and Response (XDR), and host-based intrusion detection (HIDS).
- **Architecture:** Distributed multi-component architecture comprising Wazuh Agents (C daemons), Wazuh Manager (central analysis server), and Wazuh Indexer/Dashboard (fork of OpenSearch / Elasticsearch).
- **Deployment Model:** Self-hosted cluster or multi-container Docker deployment; requires dedicated management infrastructure.
- **Strengths:** Comprehensive log correlation, real-time file integrity monitoring (FIM), regulatory compliance mapping (PCI-DSS, HIPAA), rich active response ecosystem.
- **Limitations:** Extreme operational complexity and heavy resource consumption. Running the complete stack (OpenSearch + Manager) typically requires substantial memory allocations that quickly overwhelm modest single-node VPS environments. Complex alert tuning is required to prevent debilitating alert fatigue.
- **Licensing:** GPLv2 (Wazuh core), Apache 2.0 (Indexer/Dashboard).
- **Complementary Positioning:** OpenAudit does not attempt to be a real-time event log correlation engine or SIEM. OpenAudit focuses on scheduled posture auditing and state drift, avoiding heavy indexer dependencies.
- **Interoperability:** OpenAudit finding exports (JSON) can be forwarded to Wazuh log collectors if an organization outgrows standalone auditing.

### 2. Lynis
- **Problem Solved:** Automated security auditing, compliance testing, and system hardening inspection for Unix-like systems.
- **Architecture:** Monolithic shell script (`bash`/`sh`) executing sequential local tests against operating system configuration, files, and binaries.
- **Deployment Model:** Single-host CLI execution; runs directly on the target machine without background daemons.
- **Strengths:** Virtually zero installation overhead, minimal resource usage, deep inspection of CIS-style hardening checks, highly readable modular shell scripts.
- **Limitations:** Inherently single-host and CLI-driven. Lacks a native open-source centralized multi-host control plane, historical drift database, automated fleet scheduling, or agentless external perimeter inspection (enterprise centralized features require a commercial SaaS subscription).
- **Licensing:** GPLv3.
- **Complementary Positioning:** Lynis excels at standalone host inspection. OpenAudit brings a modern, type-safe Rust auditing engine with native multi-asset management, centralized history, and integrated external perimeter checks.
- **Interoperability:** OpenAudit's rule design draws inspiration from Lynis's check categories while implementing them in memory-safe Rust with structured JSON/typed outputs.

### 3. OpenVAS / Greenbone Community Edition (GVM)
- **Problem Solved:** Full-featured network vulnerability scanning, CVE discovery, and vulnerability management.
- **Architecture:** Complex multi-daemon architecture: Greenbone Vulnerability Manager (`gvmd`), OpenVAS Scanner daemon (`openvas`), PostgreSQL database, Redis (for feed/target caching), and Greenbone Security Assistant web interface (`gsa`).
- **Deployment Model:** Heavy self-hosted multi-service deployment; relies on daily feed synchronization (Greenbone Community Feed).
- **Strengths:** Vast database of tens of thousands of Network Vulnerability Tests (NVTs), extensive CVE detection, detailed CVSS vulnerability scoring.
- **Limitations:** High operational and resource overhead. Feed synchronization and multi-process scanning require significant CPU and memory, often failing or slowing down on small VPS instances. Can be aggressive on networks, with a high incidence of non-actionable vulnerability noise.
- **Licensing:** GPLv2 / GPLv3.
- **Complementary Positioning:** OpenAudit deliberately avoids running large, opaque NVT script feeds. Instead, OpenAudit focuses on explainable posture hygiene (TLS configurations, HTTP headers, SSH hardening, open ports, service exposures) where every finding has transparent remediation steps.

### 4. Trivy (Aqua Security)
- **Problem Solved:** Fast security scanner for container images, file systems, Git repositories, virtual machine images, and Kubernetes configurations.
- **Architecture:** Single binary written in Go utilizing embedded vulnerability databases (BoltDB/oras) and metadata parsers.
- **Deployment Model:** Primarily CLI and CI/CD pipeline integration; also supports client/server mode and Kubernetes operators.
- **Strengths:** Extremely fast, developer-friendly, outstanding container and package SBOM vulnerability detection, widespread ecosystem adoption.
- **Limitations:** Primarily targeted at static artifacts (containers, lockfiles, repositories) and point-in-time CI/CD scans. Not designed as an ongoing host infrastructure posture monitor that inspects live kernel parameters, active systemd services, listening socket state, or external DNS/TLS drift over time.
- **Licensing:** Apache 2.0.
- **Complementary Positioning:** OpenAudit audits live running operating systems and live network perimeters over time, tracking state drift across recurring schedules.

### 5. Nuclei (ProjectDiscovery)
- **Problem Solved:** Fast, template-driven external vulnerability and security posture scanning across web protocols.
- **Architecture:** Highly concurrent Go CLI driven by declarative YAML templates defining protocol requests and matchers.
- **Deployment Model:** Stateless CLI tool; community-maintained template repository.
- **Strengths:** Tremendous community rule ecosystem, highly expressive YAML syntax, exceptionally fast external network scanning.
- **Limitations:** Purely an active external scanner. Has no concept of host-level configuration auditing, operating system internal state, persistent multi-tenant asset management, or long-term drift tracking.
- **Licensing:** MIT.
- **Complementary Positioning:** OpenAudit incorporates declarative YAML check definitions for perimeter inspection, but integrates them into a persistent management platform with historical findings and host auditing.

### 6. OSV-Scanner (Google)
- **Problem Solved:** Vulnerability scanning using the Open Source Vulnerabilities (OSV) distributed database.
- **Architecture:** Lightweight Go CLI that parses dependency manifests and lockfiles, querying the OSV API or local database.
- **Deployment Model:** CLI tool for developer workstations and CI/CD pipelines.
- **Strengths:** High-accuracy package vulnerability matching with precise commit-level and semver range data; zero false-positive design philosophy.
- **Limitations:** Strictly limited to software dependency lockfiles and package manifests. Does not inspect operating system hardening, network listeners, TLS configurations, or live server posture.
- **Licensing:** Apache 2.0.
- **Complementary Positioning:** OpenAudit can leverage the open OSV schema and data feeds for operating system package inventory auditing while evaluating full system security posture.

---

## 2. Standards Alignment

OpenAudit's rule engine and finding categories are explicitly mapped to recognized security frameworks:

### A. CIS Benchmarks (Center for Internet Security)
- **Relevance:** The gold standard for operating system hardening (e.g., CIS Ubuntu Linux Benchmark, CIS Debian Linux Benchmark).
- **OpenAudit Mapping:**
  - *Section 1: Initial Setup* (Filesystem permissions, core dumps, package manager updates).
  - *Section 3: Network Configuration* (Firewall active, packet forwarding, ICMP settings).
  - *Section 5: Access, Authentication and Authorization* (SSH daemon configuration: disabling root login, enforcing key-based auth, idle timeouts).
  - *Section 6: System Maintenance* (Unowned files, permissions on `/etc/passwd`, `/etc/shadow`).

### B. OWASP Top 10 & ASVS (Application Security Verification Standard)
- **Relevance:** External perimeter checks for web-facing infrastructure.
- **OpenAudit Mapping:**
  - *A05:2021 Security Misconfiguration:* Auditing missing HTTP security headers (HSTS, Content-Security-Policy, X-Frame-Options), exposed administrative panels, debug endpoints, and default web server pages.
  - *A07:2021 Identification and Authentication Failures:* Auditing exposed authentication endpoints lacking TLS, weak TLS versions (TLS 1.0/1.1), expired certificates, and unencrypted HTTP access.
  - *ASVS V9: Communications Verification:* Validating certificate chains, strong cipher suites, and modern TLS configurations.

### C. NIST Cybersecurity Framework (CSF 2.0)
- **Relevance:** High-level organizational security posture management.
- **OpenAudit Mapping:**
  - **Identify (ID):** Asset discovery, hardware/software inventory, service mapping.
  - **Protect (PR):** Baseline configuration management, posture hardening verification.
  - **Detect (DE):** Identifying configuration drift, newly opened ports, expired certificates, and missing patches over time.

---

## 3. Verified Facts vs. Technical Assumptions

To maintain intellectual and engineering integrity, we explicitly distinguish between what is verified and what remains an assumption pending benchmark validation:

| Statement | Category | Status / Evidence |
|---|---|---|
| Wazuh requires multiple heavy background services (OpenSearch, Manager). | **Verified Fact** | Documented in official Wazuh system requirements (recommends 4–8+ GB RAM for small single-node clusters). |
| Lynis lacks centralized open-source multi-node drift reporting. | **Verified Fact** | Lynis Community is strictly a local CLI tool; centralized management is a commercial proprietary offering (Lynis Enterprise). |
| PostgreSQL `FOR UPDATE SKIP LOCKED` can serve as an ACID job queue. | **Verified Fact** | Extensively documented pattern in production database engineering; supported natively in PostgreSQL 9.5+. |
| Rust binaries have zero runtime GC pauses and predictable memory layout. | **Verified Fact** | Core architectural property of the Rust language and LLVM compilation. |
| OpenAudit server will use < 100 MB RAM under load. | **Engineering Objective (Unverified Assumption)** | Must be verified via load testing and memory profiling under realistic asset loads before being claimed publicly. |
| OpenAudit agent will use < 20 MB RAM during scans. | **Engineering Objective (Unverified Assumption)** | Must be verified on Ubuntu/Debian test VMs with full `/proc` parsing and package inventory sweeps. |
| Small organizations prefer self-hosted posture auditing over SaaS tools. | **Hypothesis (Pending User Feedback)** | Core market hypothesis to be validated during Milestone M2 (CLI engine) and Milestone M7 (Public Alpha). |
