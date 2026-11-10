# OpenAudit

> Accessible, transparent, and self-hosted infrastructure security auditing and monitoring.

[![CI](https://github.com/kipmyk/openaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/kipmyk/openaudit/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status: Public Alpha](https://img.shields.io/badge/Status-Public_Alpha_(v0.1.0--alpha.0)-blue.svg)](#current-status)

---

## 1. Problem Statement

Small organizations, nonprofits, independent digital publishers, and small tech teams operate critical infrastructure (cloud VPS instances, web applications, and internal services), but frequently lack the resources, budget, and operational bandwidth to deploy complex enterprise security platforms.

Enterprise solutions (such as heavyweight SIEMs and vulnerability management suites) introduce steep operational friction:
- **Excessive Resource Overhead:** Requiring gigabytes of RAM and multiple background services that overwhelm modest cloud VPS instances.
- **Alert Fatigue & Opaque Findings:** Outputting thousands of uncontextualized CVE records without clear, actionable explanations of why a setting matters or how to verify it.
- **Operational Complexity:** Requiring dedicated security operations personnel simply to configure, tune, and maintain the scanning infrastructure.
- **Data Sovereignty Concerns:** Requiring operators to send sensitive infrastructure metadata, network maps, and configuration details to third-party proprietary SaaS providers.

Conversely, running ad-hoc, disconnected CLI scripts (like standalone Lynis or custom bash scripts) leaves teams without centralized visibility, audit history, drift tracking, or automated cross-infrastructure reporting.

## 2. Project Vision

**OpenAudit** is an open-source security auditing and monitoring platform engineered to make infrastructure posture visibility accessible, transparent, affordable, and fully controlled by the infrastructure owner.

OpenAudit gives organizations complete ownership of their security data and the infrastructure used to inspect their systems. Rather than attempting to serve as an opaque vulnerability scanner or real-time intrusion prevention engine, OpenAudit focuses on **transparent, explainable posture hygiene, configuration auditing, and attack surface monitoring**.

---

## 3. Current Status

> **Current Status: Public Alpha (`v0.1.0-alpha.0`)**<br>
> **Milestone Baseline:** [`v0.2.0-m2`](https://github.com/kipmyk/openaudit/releases/tag/v0.2.0-m2) (Milestone M2: Linux Auditing Engine).<br>
> **Active Target Release:** `v0.1.0-alpha.0` (Milestone M8: Public Alpha Prerelease).

| Milestone | Scope | Status | Evidence / Baseline |
|---|---|---|---|
| **M0: Foundation** | Project architecture, threat modeling, workspace foundation, CI | **Completed** | Clean workspace, pinned toolchain |
| **M1: Core Domain** | Domain models (Asset, Scan, Finding, Severity, Evidence), error types | **Completed** | Full typed domain invariants |
| **M2: Linux Auditing Engine** | Local host audit (Ubuntu/Debian) via standalone CLI (`v0.2.0-m2`) | **Completed** | 55 Lab Scenarios, 100% Precision/Recall |
| **M3: Cross-Platform & Desktop GUI** | Platform abstraction (Linux, macOS, Windows), GUI application (`OpenAudit.app`), packaging scripts | **Completed with Qualifications** | Commit `f9a8bd5`, 43 rules, packaging verified |
| **M4: Agentless Perimeter Auditing** | DNS, TLS certificate inspection, and HTTP posture checks with SSRF defenses | **Completed** | 57 network integration tests |
| **M5: Control Plane & Persistence** | Axum HTTP API, SQLite & PostgreSQL persistence, RBAC, scheduler | **Completed** | Full CRUD, tenant isolation, live Postgres |
| **M6: Agent Communication** | Outbound agent polling, secure enrollment, job claiming, rotation fallback | **Completed** | Shared-secret proof-of-possession, 15m grace |
| **M7: Finding Lifecycle & Posture** | Finding state machine, occurrence counter, diff comparison engine, posture metrics | **Completed** | Verified remediations vs unverified omissions |
| **M8: Public Alpha Acceptance** | Self-hosted operator E2E workflow, restart persistence, Docker compose, web UI | **Completed** | Commit `9b09d2e`, 382 passing workspace tests |

### Documented Environmental Qualifications & Release Boundaries

OpenAudit maintains an honest, verifiable engineering standard. The following boundary conditions apply to the `v0.1.0-alpha.0` Public Alpha:

1. **Linux Architecture Qualification:** Standalone packages (`.deb`, `.tar.gz`) are verified in clean containers on **ARM64 / aarch64** against `glibc >= 2.34` (Ubuntu 24.04 LTS, Debian 12 Bookworm, Debian 13 Trixie). Linux `x86_64` / `amd64` packages require verification on native x86_64 runners.
2. **macOS Code Signing & Notarization:** Native desktop GUI (`OpenAudit.app`) is ad-hoc signed and verified running on Apple Silicon (macOS Sonoma 14 / Sequoia 15). External distribution without Gatekeeper quarantine requires Developer ID signing and Apple notarization. Intel x86_64 macOS is unverified.
3. **Windows Native CI Status:** Native Windows 11 and Windows Server 2022/2025 collectors, registry rules, and PowerShell service installers are implemented and mock-tested; native hardware CI execution is configured in GitHub Actions and runs upon branch push.
4. **Agent Trust Model:** Fleet agents authenticate via shared-secret proof-of-possession over server-authenticated HTTPS / TLS 1.3 with a bounded 15-minute credential rotation grace period (not mutual TLS or asymmetric hardware identity).
5. **Distributed Coordination:** Rate limiting and recurring job scheduling are qualified for single-instance control planes. Distributed multi-instance clustering requires shared PostgreSQL/Redis state locking.
6. **Hardware Attestation (D4 Foundation):** Software TPM 2.0 (`swtpm`) emulation and software crash-recovery matrices (CB-01..13) are verified in CI. Physical discrete TPM 2.0 (`scripts/qualify_physical_tpm.sh`), relay power-loss bench testing (`scripts/qualify_power_loss.sh`), and external security audits remain pending external hardware qualification.

---

## 4. Core Principles

OpenAudit is designed around fifteen foundational engineering principles:

1. **Security by Design:** Security considerations dictate architectural choices; security is not an afterthought or bolted-on wrapper.
2. **Least Privilege:** All components operate with the minimum filesystem, kernel, and network permissions necessary.
3. **Read-Only Auditing by Default:** The inspection engine strictly queries configuration and state; it never mutates host configurations, modifies firewalls, or alters services.
4. **Self-Hosted Deployment & Data Ownership:** Organizations retain exclusive physical and cryptographic control over their security data and inspection logs.
5. **Cross-Platform Architecture:** The core domain and rule engine are platform-agnostic, with modular host inspection targets (starting with Ubuntu and Debian, expanding to Rocky Linux).
6. **Low Resource Footprint (Engineering Objective):** Built in Rust to minimize memory consumption and CPU cycles, aiming to run comfortably on modest single-node Linux VPS hosts (resource claims remain explicit engineering targets until verified by rigorous benchmarks).
7. **Modular Monolith Architecture:** Clear separation of responsibilities across workspace crates without premature distributed microservices.
8. **Secure Communication:** Encrypted transport across all network boundaries with outbound-only communication for internal agents.
9. **Transparent, Explainable Findings:** Every reported finding must explain *what* was detected, *why* it matters, and *how* an operator can verify it independently.
10. **Reproducible & Testable Checks:** Audits must produce deterministic results accompanied by reproducible automated tests.
11. **No Unnecessary Dependencies:** Strict evaluation of all external dependencies for security, maintenance, and transitive baggage.
12. **No Unnecessary Microservices:** A single server binary with PostgreSQL-backed job orchestration, avoiding message broker complexity (e.g., no Redis or Kafka in initial milestones).
13. **No Vendor Lock-In:** Standard formats (JSON, Markdown, YAML) and open protocols throughout.
14. **No Automatic Remediation in Initial Releases:** Avoid risky automated mutations that could disrupt running production services; prioritize human operator awareness.
15. **No Collection of Unnecessary Sensitive Data:** Audit checks actively redact secrets, authentication tokens, and private keys from captured evidence.

---

## 5. Architecture Overview

OpenAudit follows a modular workspace architecture implemented in Rust:

```text
openaudit/
├── apps/
│   ├── openaudit-server/   # Control plane: Axum API, SQLite & Postgres storage, scheduler, web UI
│   ├── openaudit-cli/      # Operator CLI: local host audits & network perimeter scanner
│   ├── openaudit-agent/    # Minimal outbound-only inspection daemon
│   └── openaudit-desktop/  # Native macOS desktop GUI application
│
├── crates/
│   ├── openaudit-core/     # Domain models: Asset, Scan, Finding, Severity, Evidence
│   ├── openaudit-engine/   # Rule engine and collectors (Linux, macOS, Windows)
│   └── openaudit-network/  # Network perimeter engine: DNS, TLS, HTTP, SSRF defense
│
├── docs/                   # Architecture, Threat Model, Packaging, and Roadmap
├── .github/workflows/      # Automated CI pipelines
├── Cargo.toml              # Cargo workspace manifest
├── rust-toolchain.toml     # Pinned stable toolchain
├── LICENSE                 # Apache License 2.0
└── README.md
```

### Auditing Capabilities

OpenAudit supports three complementary inspection approaches:

#### A. Local Host Posture Inspection
In-process evaluation of local operating system controls, users, services, and kernel configuration:
- **Operating System Targets:** Linux (Ubuntu 24.04, Debian 12/13), macOS (Sonoma, Sequoia), and Windows (11, Server 2022/2025).
- **Inspection Targets:** Kernel sysctls, SSH hardening, firewall state (UFW/nftables/iptables/Windows Defender), sensitive file permissions, SUID/SGID binaries, service accounts, and open listening ports.

#### B. Agentless Perimeter Inspection
Non-destructive evaluation of observable services, open ports, TLS posture, and HTTP headers without software installation:
- **Inspection Targets:** DNS record hygiene, port & service identification, TLS certificate validation (expiration, self-signed, hostname mismatch), and HTTP security headers (HSTS, CSP, X-Frame-Options, cookie security attributes).
- **SSRF Defenses:** Unconditional blocking of cloud metadata (169.254.169.254), strict CIDR parsing, post-resolution pinned IP binding against DNS rebinding, and re-validation on all redirects.

#### C. Centralized Self-Hosted Fleet & Finding Management
Self-hosted server with embedded operator web interface, outbound agent polling, stable finding fingerprinting, triage tracking, verified remediation diffing, and export formats (HTML, CSV, JSON).

---

## 6. Standalone Production Packages & Distribution

OpenAudit is distributed as **self-contained production packages** that require **no Rust, Cargo, Node.js, npm, or development toolchains** on target systems.

### Installation Options

#### Linux (Debian / Ubuntu Native Package — ARM64 Qualified)
Download the `.deb` package and install via `dpkg` (ARM64 verified on Ubuntu 24.04 / Debian 12 / Debian 13 with `glibc >= 2.34`; `amd64` builds require x86_64 CI runner):
```bash
sudo dpkg -i openaudit_0.1.0-alpha.0_arm64.deb
openaudit version
openaudit scan --profile baseline
```

#### Linux / macOS (Portable Archive — ARM64 Qualified)
Extract the `.tar.gz` archive to any directory or `/usr/local`:
```bash
tar -xzf openaudit-0.1.0-alpha.0-linux-aarch64.tar.gz   # or -darwin-aarch64.tar.gz
./openaudit scan --format human
./openaudit report --format html --output report.html
```

#### Windows (Portable Distribution — Pending Native CI Runner)
Once generated by the GitHub Actions Windows runner, extract `openaudit-0.1.0-alpha.0-windows-x86_64.zip` in PowerShell:
```powershell
Expand-Archive openaudit-0.1.0-alpha.0-windows-x86_64.zip -DestinationPath "C:\OpenAudit"
cd C:\OpenAudit\bin
.\openaudit.exe scan --format human
```

For complete packaging architecture, runtime dependency analysis, and clean-environment test evidence, see:
- [Packaging, Distribution, and Runtime Independence Specification](docs/PACKAGING-AND-DISTRIBUTION.md)

---

## 7. Development & Verification

### Prerequisites
- Rust stable (matching `rust-toolchain.toml`)
- Cargo components: `rustfmt`, `clippy`

### Quality Checks
```bash
# Verify formatting
cargo fmt --check

# Run linter
cargo clippy --all-targets -- -D warnings

# Execute test suite
cargo test
```

---

## 8. Documentation Index

### Core Architecture & Foundations
- [Architecture Design & Technical Decisions](docs/ARCHITECTURE.md)
- [Packaging, Distribution, and Runtime Independence Specification](docs/PACKAGING-AND-DISTRIBUTION.md)
- [Threat Model & Security Boundaries](docs/THREAT-MODEL.md)
- [PostgreSQL Multi-Tenant Data Model](docs/DATA-MODEL.md)
- [CLI Contracts & Command Reference](docs/CLI-CONTRACTS.md)
- [Public Milestone Development Roadmap](docs/ROADMAP.md)

### Milestone M2 Reports & Evidence
- [M2 Detection Lab Baseline Report](docs/M2-BASELINE-REPORT.md)
- [M2.1 Reliability & Defect Remediation Report](docs/M2.1-COMPARISON-REPORT.md)
- [M2.2 55-Scenario Lab Evaluation Report](docs/M2.2-LAB-RESULTS.md)
- [M2.3 Independent Validation Report](docs/M2.3-INDEPENDENT-VALIDATION-REPORT.md)

### Contributing & Security
- [Security Policy & Vulnerability Reporting](SECURITY.md)
- [Developer Contribution Guidelines](CONTRIBUTING.md)

---

## 9. License

OpenAudit is licensed under the [Apache License, Version 2.0](LICENSE).
