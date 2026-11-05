# OpenAudit Development Roadmap

This document outlines the phased development roadmap for OpenAudit. Milestones are organized incrementally: proving local auditing value first, establishing perimeter inspection, and then building the centralized control plane and fleet agent communication.

---

## Milestone Overview

```text
[M0: Foundation] ➔ [M1: Core Domain] ➔ [M2: Linux Host Engine (CLI)] ➔ [M3: Agentless Scanning]
                                                                                │
[M7: Public Alpha] ⬅ [M6: Reporting & Diffing] ⬅ [M5: Agent Polling] ⬅ [M4: Control Plane (DB)]
```

---

## Milestone Specifications

### Milestone M0: Project Foundation (Completed)
- **Objective:** Establish architectural clarity, formal threat model, landscape research, repository governance, Rust workspace, and automated CI.
- **Scope:**
  - Complete architectural definitions (`ARCHITECTURE.md`).
  - Comprehensive threat model and abuse cases (`THREAT-MODEL.md`).
  - PostgreSQL multi-tenant schema and data model architecture (`DATA-MODEL.md`).
  - Tool landscape research and standards alignment (`RESEARCH.md`).
  - Contribution guidelines, security disclosure policy, and Apache 2.0 licensing.
  - Rust workspace layout with pinned toolchain (`rust-toolchain.toml`).
  - GitHub Actions CI workflow (formatting, Clippy, tests, doc generation, cargo-audit).
- **Acceptance Criteria:** A clean, documented repository that any Rust engineer can clone, understand, and build with `cargo check` and `cargo test`. Zero compiler or linter warnings.
- **Dependencies:** None.

---

### Milestone M1: Core Domain Models (Completed - Verified Locally)
- **Objective:** Build the platform's core domain types and invariants in `crates/openaudit-core`.
- **Scope:**
  - `Asset` entity and typed identifiers (`AssetId`, `OrganizationId`).
  - `Finding` model with remediation notes, CWE mappings, and references.
  - `Severity` enum (`Info`, `Low`, `Medium`, `High`, `Critical`) with sorting and serialization.
  - `Evidence` model with payload redaction helpers.
  - `Scan` and `ScanJob` state models.
  - Domain error types using `thiserror`.
- **Acceptance Criteria:**
  - 100% unit test coverage of domain model serialization, deserialization, and validation invariants.
  - Pure domain models with zero dependencies on database drivers or transport protocols.
- **Dependencies:** M0.

---

### Milestone M2: Linux Host Auditing Engine (Local CLI Proof-of-Value)
- **Objective:** Enable operators to run a standalone local audit on Ubuntu/Debian systems without requiring a server or database.
- **Scope:**
  - Build `openaudit-engine` check execution runner.
  - Operating system identification (distribution name, release, kernel version).
  - System package inspection (Debian/Ubuntu `dpkg` query for pending security updates).
  - Running services inspection (active systemd services).
  - Listening port inventory (parsing `/proc/net/tcp` and `/proc/net/tcp6`).
  - SSH daemon hardening checks (parsing `/etc/ssh/sshd_config` for root login, password auth, protocol).
  - Basic firewall status inspection (UFW / iptables / nftables state).
  - `openaudit-cli audit local` command producing structured JSON and formatted terminal Markdown.
- **Acceptance Criteria:**
  - Operator can run `cargo run -p openaudit-cli -- audit local` on Ubuntu/Debian and receive explainable, structured findings.
  - All checks run strictly read-only with bounded execution times.
  - No database or daemon required to run local audits.
- **Dependencies:** M1.

---

### Milestone M3: Agentless Perimeter Auditing & SSRF Defense
- **Objective:** Inspect external authorized network endpoints with strict SSRF defenses.
- **Scope:**
  - DNS record validation (A, AAAA, MX, TXT/SPF, DMARC).
  - TLS certificate inspection (validity, expiration date, issuer, protocol version).
  - HTTP security header auditing (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
  - SSRF protection module:
    - Default denylist: blocking RFC 1918, loopback, link-local, cloud metadata, and CGNAT IP ranges.
    - Explicit administrator allowlist for authorized internal subnets.
    - Post-DNS socket-level IP binding to prevent DNS rebinding TOCTOU.
    - Per-redirect IP re-validation (capped at 3 hops).
    - Response body stream cap (512 KB) and strict 10s connection timeouts.
  - `openaudit-cli audit remote <target>` command.
- **Acceptance Criteria:**
  - Successful audit of public domain endpoints.
  - Complete, tested rejection of SSRF attempts against `127.0.0.1`, `169.254.169.254`, and private subnets without explicit allowlist configuration.
- **Dependencies:** M1, M2.

---

### Milestone M4: Control Plane & PostgreSQL Persistence
- **Objective:** Implement the central multi-tenant management server and persistent task scheduler.
- **Scope:**
  - `openaudit-server` built with Axum.
  - PostgreSQL schema and migrations (Assets, Scans, Jobs, Findings, Organizations).
  - Tenant data isolation enforced via organization scoping.
  - Transactional job scheduling using `SELECT ... FOR UPDATE SKIP LOCKED` (no Redis).
  - REST/JSON API endpoints for asset registration, scan triggering, and finding queries.
- **Acceptance Criteria:**
  - REST API passes end-to-end integration tests.
  - Concurrent workers reliably consume jobs from PostgreSQL without duplicate execution or deadlocks.
  - Database migrations are fully testable and reversible.
- **Dependencies:** M1, M2, M3.

---

### Milestone M5: Agent Communication & Secure Enrollment
- **Objective:** Implement the lightweight background agent for continuous fleet monitoring.
- **Scope:**
  - `openaudit-agent` daemon with periodic outbound HTTPS polling.
  - Time-limited enrollment token exchange mechanism.
  - Credential management: Agent secret tokens hashed with Argon2id in the control plane.
  - Heartbeat and job polling endpoint (`POST /api/v1/agent/heartbeat`).
  - Report submission endpoint (`POST /api/v1/agent/reports`).
  - Instant credential revocation workflow.
- **Acceptance Criteria:**
  - Agent successfully enrolls with a valid enrollment token.
  - Revoked agents are immediately denied access with 401 Unauthorized.
  - Agent daemon operates strictly outbound without opening any listening network socket.
- **Dependencies:** M4.

---

### Milestone M6: Reporting, Diffing & Finding Lifecycle
- **Objective:** Track security posture drift over time and provide actionable reports.
- **Scope:**
  - Finding state lifecycle (`New`, `Active`, `Resolved`, `Suppressed`).
  - Historical scan comparison (identifying newly opened ports, drifted configs, resolved issues).
  - Report generators: Machine-readable JSON and human-readable HTML/Markdown summaries.
  - Evidence export with automated sensitive credential redaction.
- **Acceptance Criteria:**
  - Scan comparison accurately highlights differences between successive scans of the same asset.
  - Sensitive credential strings in evidence payloads are sanitized prior to export.
- **Dependencies:** M4, M5.

---

### Milestone M7: Public Alpha Release
- **Objective:** Package OpenAudit for public evaluation by independent testers and operators.
- **Scope:**
  - Production Docker Compose deployment (Caddy + openaudit-server + PostgreSQL).
  - Single-command agent installation script for Ubuntu and Debian.
  - Complete administrator and operator documentation.
  - Automated smoke test suite across isolated virtual machines.
  - Public alpha release tagging on GitHub (`v0.1.0-alpha`).
- **Acceptance Criteria:**
  - Independent operators can deploy OpenAudit on a clean Linux VPS in under 15 minutes using provided documentation.
  - External feedback collected and triaged into post-alpha roadmap.
- **Dependencies:** M0 through M6.
