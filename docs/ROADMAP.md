# OpenAudit Public Roadmap

This document outlines the public milestones and development status for OpenAudit.

OpenAudit is an open-source, local-first security posture assessment and infrastructure auditing platform built with memory-safe Rust.

---

## Development Milestones

```text
[M0: Foundation] ➔ [M1: Core Domain] ➔ [M2: Linux Posture Engine] ➔ [M3: Cross-Platform Auditing]
                                                                             │
[M8: Public Alpha] ⬅ [M7: Lifecycle & Posture] ⬅ [M6: Agent Plane] ⬅ [M5: Control Plane] ⬅ [M4: Perimeter]
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
- **Summary:** 20+ deterministic Linux security rules evaluated against live operating system state with 100% precision and recall on Ubuntu 24.04 LTS.

### Milestone M3: Cross-Platform Auditing, CLI & Desktop GUI (Completed with Qualifications)
- **Status:** Complete with Documented Qualifications (commit `f9a8bd5`)
- **Summary:** Platform abstraction across Linux (Ubuntu 24.04, Debian 12, Debian 13 with `glibc >= 2.34`), macOS (Sonoma 14, Sequoia 15), and Windows (11, Server 2022/2025). 43 platform rules, standalone CLI with headless isolation, native desktop GUI (`OpenAudit.app`) verified on macOS Apple Silicon, and packaging scripts.

### Milestone M4: Agentless Perimeter Auditing (Completed)
- **Status:** Complete
- **Summary:** Bounded DNS record hygiene, port scanning, service identification, TLS certificate inspection, and HTTP posture assessment with multi-layer SSRF defenses (cloud metadata prohibition, strict CIDRs, post-resolution pinned IP binding).

### Milestone M5: Control Plane & Persistence (Completed)
- **Status:** Complete
- **Summary:** Axum HTTP API with versioned endpoints, dual SQLite & PostgreSQL persistence, Argon2id hashing, HMAC-SHA256 session tokens, RBAC (Admin, Auditor, Viewer), tenant isolation, and task scheduling.

### Milestone M6: Agent Communication & Secure Enrollment (Completed)
- **Status:** Complete
- **Summary:** Outbound-only agent polling, token-based enrollment, distributed job leasing, result provenance, and 15-minute credential rotation fallback grace period.

### Milestone M7: Finding Lifecycle, Diff Tracking & Posture Reporting (Completed)
- **Status:** Complete
- **Summary:** Central finding state machine (`new`, `in_progress`, `verified_remediated`, `closed`), stable fingerprinting, occurrence counting, coverage comparison engine distinguishing verified remediations from unverified omissions, and multi-format exports (HTML, CSV, JSON).

### Milestone M8: Public Alpha Self-Hosted Acceptance (Completed — `v0.1.0-alpha.0`)
- **Status:** Complete & Accepted (commit `9b09d2e`)
- **Summary:** End-to-end self-hosted operator acceptance suite, zero-state-loss restart persistence against SQLite, live PostgreSQL rotation verification, Docker Compose deployment, embedded operator web UI, and 382 passing workspace tests.

---

## Community & Contributions

OpenAudit welcomes community feedback, bug reports, and contributions. Please see [CONTRIBUTING.md](../CONTRIBUTING.md) for details on code standards and testing guidelines.
