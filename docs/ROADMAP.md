# OpenAudit Public Roadmap

This document outlines the public milestones and development status for OpenAudit.

OpenAudit is an open-source, local-first security posture assessment and infrastructure auditing platform built with memory-safe Rust.

---

## Development Milestones

```text
[M0: Foundation] ➔ [M1: Core Domain] ➔ [M2: Linux Posture Engine] ➔ [M3: Cross-Platform Auditing]
                                                                             │
[M7: Public Alpha] ⬅ [M6: Agent Communication] ⬅ [M5: Control Plane] ⬅ [M4: Perimeter Auditing]
```

---

## Milestone Status

### Milestone M0: Project Foundation (Completed)
- **Status:** Complete & Released
- **Summary:** Repository governance, Apache 2.0 licensing, pinned Rust workspace toolchain, automated CI, and architectural blueprints.

### Milestone M1: Core Domain Models (Completed)
- **Status:** Complete & Released
- **Summary:** Foundational domain entities (`Asset`, `Finding`, `Evidence`, `ScanSummary`), typed identifiers, severity ordering, and robust serialization invariants.

### Milestone M2: Linux Host Auditing Engine (Completed — `v0.2.0-m2`)
- **Status:** Complete & Released (`v0.2.0-m2`)
- **Summary:** 20+ deterministic Linux security rules evaluated against live operating system state (SSH daemon hardening, open database ports, firewall posture, file permissions, SUID/SGID binaries, service accounts, and kernel sysctls) with 100% precision and recall on Ubuntu 24.04 LTS.

### Milestone M3: Cross-Platform Auditing, CLI & Desktop GUI (In Progress)
- **Status:** In Active Development
- **Scope:**
  - Standardized platform abstraction supporting Linux (Ubuntu 24.04, Debian 12, Debian 13), Microsoft Windows, and Apple macOS.
  - Full-featured standalone CLI interface (`openaudit-cli`) for headless servers, automation, and CI/CD pipelines.
  - Optional cross-platform desktop application for visual posture management and evidence inspection.
  - Deterministic exit codes and machine-readable output formats (JSON, HTML).

### Milestone M4: Agentless Perimeter Auditing (Planned)
- **Status:** Scheduled
- **Scope:** Read-only inspection of internet-facing endpoints, DNS security records (SPF, DMARC, MX), TLS certificate validation, and HTTP security headers with strict SSRF defense.

### Milestone M5: Control Plane & Persistence (Planned)
- **Status:** Scheduled
- **Scope:** Multi-tenant PostgreSQL control plane, tenant data isolation, scheduled scanning, and job queuing.

### Milestone M6: Agent Communication & Fleets (Planned)
- **Status:** Scheduled
- **Scope:** Fleet agent communication, hardware-rooted device identity, and centralized fleet posture aggregation.

### Milestone M7: Public Alpha (Planned)
- **Status:** Scheduled
- **Scope:** Public release, comprehensive documentation, packaging, and community distribution.

---

## Community & Contributions

OpenAudit welcomes community feedback, bug reports, and contributions. Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for details on code standards and testing guidelines.
