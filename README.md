# OpenAudit

> Accessible, transparent, and self-hosted infrastructure security auditing and monitoring.

[![CI](https://github.com/kipmyk/openaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/kipmyk/openaudit/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status: Pre-Alpha](https://img.shields.io/badge/Status-Pre--Alpha_(M0)-orange.svg)](#current-status)

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

> **Important:** OpenAudit is currently in active early foundation (**Milestone M0**). 
> All planned features described below represent architectural design objectives and are under incremental development. There are currently no compiled production releases.

| Milestone | Scope | Status |
|---|---|---|
| **M0: Foundation** | Project architecture, threat modeling, workspace foundation, CI | **Completed** |
| **M1: Core Domain** | Domain models (Asset, Scan, Finding, Severity, Evidence), error types | **Completed (Verified Locally)** |
| **M2: Linux Auditing Engine** | Local host audit (Ubuntu/Debian) via standalone CLI | Planned |
| **M3: Agentless Perimeter Auditing** | DNS, TLS, and HTTP security posture checks with SSRF defenses | Planned |
| **M4: Control Plane & Persistence** | Axum HTTP API, PostgreSQL persistence, transactional scheduling | Planned |
| **M5: Agent Communication** | Outbound agent polling, identity management, secure enrollment | Planned |
| **M6: Reporting & Lifecycle** | Finding lifecycle, diff tracking, evidence export (JSON/HTML) | Planned |
| **M7: Public Alpha** | End-to-end verified release and documented deployment | Planned |

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
│   ├── openaudit-server/   # Control plane: Axum API, Postgres storage & task scheduling
│   ├── openaudit-cli/      # Operator CLI: local host audits & control plane client
│   └── openaudit-agent/    # Minimal outbound-only inspection daemon
│
├── crates/
│   ├── openaudit-core/     # Domain models: Asset, Scan, Finding, Severity, Evidence
│   └── openaudit-engine/   # Rule engine and check runners (Linux host, DNS/TLS checks)
│
├── docs/                   # Architecture, Threat Model, Research, and Roadmap
├── .github/workflows/      # Automated CI pipelines
├── Cargo.toml              # Cargo workspace manifest
├── rust-toolchain.toml     # Pinned stable toolchain
├── LICENSE                 # Apache License 2.0
└── README.md
```

### Planned Auditing Capabilities

OpenAudit is designed to support two complementary inspection approaches:

#### A. Agent-Based Host Inspection (Planned)
An optional, minimal Rust daemon installed on authorized servers:
- **Operating System Targets:** Ubuntu, Debian, Rocky Linux.
- **Inspection Targets:** Kernel version, installed packages, security updates, active systemd services, open listening ports, SSH daemon configuration, firewall state (UFW/iptables/nftables), file permissions on sensitive paths, and container daemon configurations.
- **Security Boundaries:** Outbound-only HTTPS polling (zero listening ports on the agent), read-only inspection, no remote shell execution capability, and cryptographically revocable credentials.

#### B. Agentless Perimeter Inspection (Planned)
Inspection of authorized external infrastructure without software installation:
- **Inspection Targets:** DNS record hygiene (SPF, DKIM, DMARC, DNSSEC), HTTP/HTTPS availability, TLS configuration and certificate validity, HTTP security headers (HSTS, CSP, X-Frame-Options), and exposed administrative interfaces.
- **SSRF Defenses:** Blocklist for private, loopback, link-local, and cloud metadata IP ranges by default; administrator-controlled allowlists for authorized internal networks; post-resolution socket-level IP binding to prevent DNS rebinding; and re-validation on all HTTP redirects.

---

## 6. Development & Verification

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

## 7. Documentation Index

- [Architecture Design & Technical Decisions](docs/ARCHITECTURE.md)
- [Threat Model & Security Boundaries](docs/THREAT-MODEL.md)
- [PostgreSQL Multi-Tenant Data Model](docs/DATA-MODEL.md)
- [Landscape Research & Project Positioning](docs/RESEARCH.md)
- [Milestone Development Roadmap](docs/ROADMAP.md)
- [Security Policy & Vulnerability Reporting](SECURITY.md)
- [Developer Contribution Guidelines](CONTRIBUTING.md)

---

## 8. License

OpenAudit is licensed under the [Apache License, Version 2.0](LICENSE).
