# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0-alpha.0] - 2026-11-10 (Public Alpha Prerelease)

First Public Alpha milestone combining cross-platform host auditing, agentless perimeter scanning, self-hosted control plane, outbound fleet management, and finding lifecycle reconciliation.

### Added

- **Cross-Platform Auditing & Desktop GUI (M3):**
  - Core platform abstraction layer across Linux (Ubuntu 24.04 LTS, Debian 12 Bookworm, Debian 13 Trixie), macOS (Sonoma 14, Sequoia 15), and Windows (11, Server 2022/2025).
  - 43 deterministic platform rules (20 Linux, 12 Windows, 11 macOS).
  - Standalone headless CLI (`openaudit-cli`) with strict dependency isolation.
  - Native macOS desktop GUI (`OpenAudit.app`) featuring local scanning, remote perimeter scanning, and rule catalog filtering.
  - Release packaging scripts (`.deb`, `.tar.gz`, systemd units, udev rules, launchd plists, PowerShell Windows service installers) and clean-install verification harness.
- **Agentless Perimeter Scanner (`openaudit-network`, M4):**
  - Bounded TCP port discovery, protocol-evidenced service identification, TLS certificate posture analysis, and HTTP security header evaluation (HSTS, CSP, cookies).
  - Strict SSRF protections: unconditional cloud metadata rejection (`169.254.169.254`), CIDR scope enforcement, pinned destination socket resolution against DNS rebinding, and redirect loop/scope validation.
- **Self-Hosted Control Plane (`openaudit-server`, M5):**
  - Axum REST API (`/api/v1`) with OpenAPI 3.1 contract endpoint and embedded operator web UI (`/`).
  - Dual persistence backends: embedded SQLite (`bundled` C amalgamation) and PostgreSQL (`deadpool-postgres`).
  - Argon2id password hashing, HMAC-SHA256 session tokens with key rotation fallback, RBAC (`admin`, `auditor`, `viewer`), and organization-scoped tenant isolation.
  - Bounded asynchronous job execution queue and recurring schedule execution engine.
- **Outbound Agent Plane (`openaudit-agent`, M6):**
  - Outbound-only HTTPS polling, one-time token agent enrollment, job lease claiming with reclaim authorization, and result submission.
  - Bounded 15-minute credential rotation fallback grace period across both SQLite and PostgreSQL backends.
- **Finding Lifecycle & Posture Engine (M7):**
  - Central managed findings state machine (`new`, `in_progress`, `verified_remediated`, `closed`), deterministic SHA-256 fingerprinting, occurrence tracking, triage owner assignment, and comparison engine separating verified remediations from unverified omissions.
  - Multi-format report exports (HTML, RFC 4180 CSV with formula injection defense, and JSON).
- **Self-Hosted Deployment & E2E Acceptance (M8):**
  - Multi-stage Dockerfiles (`docker/server.Dockerfile`, `docker/agent.Dockerfile`), `docker-compose.yml`, and deployment healthcheck.
  - Full E2E self-hosted operator workflow and process-restart persistence test suite verifying 382 workspace tests.

### Documented Qualifications

- **Linux Architecture:** Verified in clean containers on **ARM64 / aarch64** against `glibc >= 2.34`. Linux `x86_64` / `amd64` packages require verification on GitHub Actions x86_64 runners.
- **macOS Distribution:** Apple Silicon (`aarch64`) GUI and CLI verified locally with ad-hoc signing; external distribution without Gatekeeper quarantine requires Developer ID signing and Apple notarization. Intel `x86_64` macOS is unverified.
- **Windows Execution:** Collectors, registry rules, and service scripts are implemented and unit-tested; native Windows hardware CI execution is configured in GitHub Actions and executes upon remote push.
- **Agent Authentication:** Operates via shared-secret proof-of-possession tokens over server-authenticated HTTPS/TLS 1.3 (not mutual TLS or asymmetric hardware identity).
- **Distributed Coordination:** In-memory login rate limiting and scheduler coordination are single-instance qualified; multi-node clustering requires shared locking.

---

## [v0.2.0-m2] - Milestone M2 Release (Immutable Baseline)

- Completed Milestone M2: Linux Auditing Engine with 20 deterministic rules validated against 55 empirical lab scenarios on Ubuntu 24.04 LTS (100% precision and recall).

