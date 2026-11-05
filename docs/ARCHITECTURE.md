# OpenAudit System Architecture

This document defines the architectural boundaries, component responsibilities, data flows, communication patterns, and technical decisions governing the OpenAudit platform.

---

## 1. System Overview & Workspace Boundaries

OpenAudit is organized as a modular Rust workspace. To avoid premature distributed system complexity and excessive crate boundary churn, OpenAudit adopts a **modular monolith** foundation consisting of two core libraries and three application binaries:

```text
openaudit/
├── crates/
│   ├── openaudit-core/       # Domain primitives, common models, validation, and error types
│   └── openaudit-engine/     # Pluggable audit check execution engine and rule definitions
│
├── apps/
│   ├── openaudit-cli/        # Standalone operator CLI (local host audits & server client)
│   ├── openaudit-server/     # Control plane API, storage persistence, and task scheduler
│   └── openaudit-agent/      # Minimal, outbound-only host monitoring daemon
│
├── docs/                     # Architectural, threat model, research, and roadmap documentation
├── .github/workflows/        # Continuous integration workflows
├── Cargo.toml                # Workspace manifest
└── rust-toolchain.toml       # Pinned Rust compiler toolchain
```

### Component Responsibilities

| Component | Type | Responsibility | Key Dependencies (Planned) |
|---|---|---|---|
| `openaudit-core` | Library | Houses core domain entities (`Asset`, `Scan`, `Finding`, `Severity`, `Evidence`), identifier types (`AssetId`, `ScanId`), time utilities, and domain-wide error definitions. Completely decoupled from transport, databases, or OS-specific syscalls. | `serde`, `uuid`, `thiserror`, `chrono` |
| `openaudit-engine` | Library | Encapsulates the execution logic for audit rules. Houses both local Linux system checks (parsing `/proc`, `/sys`, config files, package lists) and external network checks (DNS, TLS, HTTP headers). | `openaudit-core`, `tracing` |
| `openaudit-cli` | Binary | The primary entry point for developers and operators. Can execute local host audits directly in a standalone, zero-daemon mode (`openaudit-cli audit local`), or query a remote OpenAudit server instance. | `openaudit-core`, `openaudit-engine`, `clap` |
| `openaudit-server` | Binary | The central control plane. Serves the authenticated REST/JSON API, enforces tenant isolation, persists scan records to PostgreSQL, and schedules asynchronous scan jobs via an embedded PostgreSQL task queue. | `openaudit-core`, `axum`, `tokio`, `sqlx`, `tower-http` |
| `openaudit-agent` | Binary | An optional, lightweight background service deployed on monitored Linux nodes. Periodically polls the control plane for assigned audit tasks, runs read-only host checks via `openaudit-engine`, and submits structured findings over outbound HTTPS. | `openaudit-core`, `openaudit-engine`, `tokio`, `reqwest` |

---

## 2. Auditing Paradigms & Data Flow

OpenAudit combines two distinct auditing paradigms to provide both internal system depth and external perimeter visibility.

### A. Local / Standalone CLI Auditing (Proof of Value)

The primary initial deliverable of OpenAudit is the ability for an operator to run an audit locally without needing to spin up a database or server daemon:

```mermaid
flowchart LR
    Operator((Operator)) -->|Runs| CLI[openaudit-cli]
    CLI -->|Executes Rules| Engine[openaudit-engine]
    Engine -->|Reads Config / State| OS[(Linux OS /proc, /etc, CLI)]
    Engine -->|Generates Findings| Core[openaudit-core Data Models]
    Core -->|Renders Structured Output| Output[JSON / Terminal Markdown Report]
```

1. The operator invokes `openaudit-cli audit local`.
2. `openaudit-engine` reads local operating system status (e.g., `/etc/ssh/sshd_config`, `/proc/net/tcp`, package manager queries).
3. Findings are evaluated against declarative rules and converted into typed `Finding` records.
4. Output is rendered directly to stdout in human-readable Markdown or machine-readable JSON.

### B. Centralized Agent-Based Host Auditing

For ongoing fleet monitoring, monitored servers run `openaudit-agent`:

```mermaid
sequenceDiagram
    participant Agent as openaudit-agent (Host)
    participant Server as openaudit-server (Control Plane)
    participant DB as PostgreSQL

    Agent->>Server: POST /api/v1/agent/heartbeat (Poll for tasks, Outbound TLS)
    Server->>DB: Query pending jobs for Agent ID
    DB-->>Server: Return assigned Scan Job
    Server-->>Agent: 200 OK (ScanJob instructions)
    Note over Agent: Executes read-only checks via openaudit-engine
    Agent->>Server: POST /api/v1/agent/reports (Submit findings + evidence)
    Server->>DB: Persist findings in transaction & update asset posture
    Server-->>Agent: 201 Created (Acknowledgment)
```

#### Key Agent Design Constraints
- **Zero Inbound Ports:** The agent never binds a listening network port. All communication is strictly outbound over TLS to the control plane.
- **Strictly Read-Only:** The agent only reads system configuration files, queries service states via systemd, and checks listening sockets. It never modifies firewall rules, service states, or files.
- **No Remote Shell Execution:** The agent protocol does not support arbitrary command execution or dynamic script evaluation. Only predefined, statically compiled check identifiers with bounded parameters can be requested by the control plane.

### C. Agentless External Perimeter Auditing

OpenAudit inspects public or authorized internal endpoints directly from `openaudit-server` or worker tasks:

```mermaid
flowchart TD
    Job[Scan Job Triggered] --> PreCheck{Pre-Flight Target Validation}
    PreCheck -->|Invalid / Unauthorized| Fail[Reject Job: Unauthorized Target]
    PreCheck -->|Allowed Target| DNS[Resolve DNS A / AAAA]
    DNS --> SSRFCheck{SSRF & IP Validation}
    SSRFCheck -->|Blocked IP Range| Drop[Abort: Blocked IP / SSRF Attempt]
    SSRFCheck -->|Permitted IP| Connect[Socket Connect to Validated IP]
    Connect --> TLS[TLS Handshake & Cert Inspection]
    TLS --> HTTP[HTTP GET with strict limits]
    HTTP --> Redirect{Redirect?}
    Redirect -->|Yes| SSRFCheck
    Redirect -->|No| Collect[Collect Headers & Findings]
    Collect --> Store[(Persist to PostgreSQL)]
```

---

## 3. Security Boundary & Target Validation Architecture

### SSRF & Network Validation Policy
Agentless scanning introduces severe Server-Side Request Forgery (SSRF) and target expansion risks if not tightly controlled. OpenAudit enforces a multi-layered defense:

1. **Default Denylist:** By default, all scan requests to the following IP ranges are strictly blocked:
   - Loopback addresses (`127.0.0.0/8`, `::1/128`)
   - RFC 1918 Private IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - RFC 3927 Link-Local (`169.254.0.0/16`, `fe80::/10`)
   - Cloud Metadata Service IP (`169.254.169.254`)
   - RFC 6598 Carrier-Grade NAT (`100.64.0.0/10`)
   - Multicast, broadcast, and reserved ranges (`224.0.0.0/4`, `240.0.0.0/4`, `0.0.0.0/8`)
   - IPv6 Unique Local Addresses (ULA `fc00::/7`)

2. **Explicit Administrator Allowlists:**
   - In environments where OpenAudit is legitimately tasked with auditing internal networks, an administrator must explicitly register approved CIDR blocks or domain patterns in the control plane database.
   - Any target resolving outside the explicitly approved scope is rejected immediately.

3. **DNS Rebinding & TOCTOU Defense:**
   - Standard HTTP clients resolve DNS and connect in separate operations, creating a Time-of-Check to Time-of-Use (TOCTOU) vulnerability where a malicious DNS server returns a public IP during validation but a private IP during socket connection.
   - **Mitigation:** OpenAudit performs custom DNS resolution, validates the resolved IP addresses against the allowlist/denylist, and establishes the TCP connection directly to the validated IP address, passing the target hostname explicitly via the HTTP `Host` header and TLS Server Name Indication (SNI).

4. **Redirect Revalidation:**
   - HTTP redirects are not followed automatically by default.
   - If redirects are enabled for a scan profile, the redirect destination URL is parsed, DNS-resolved, and subjected to the complete SSRF IP validation pipeline before any redirect socket is opened. Max redirect depth is strictly capped (default: 3 hops).

5. **Resource Bounding:**
   - Connection timeout: 10 seconds maximum.
   - Read timeout: 10 seconds maximum.
   - Response body streaming limit: 512 KB maximum (discarding trailing bytes to prevent memory exhaustion from response bombs).

---

## 4. Agent Authentication & Identity Management

Agent security is critical to prevent rogue nodes from impersonating legitimate infrastructure or submitting fabricated audit reports.

### Trade-Off Analysis: Ed25519 Asymmetric Keys vs. Hashed Bearer Tokens

| Attribute | Asymmetric Key Pairs (Ed25519) | Cryptographically Hashed Bearer Tokens |
|---|---|---|
| **Mechanism** | Agent generates an Ed25519 key pair locally. Public key is registered with control plane; agent signs requests or authenticates via mTLS/signed payloads. | Agent receives a high-entropy secret token (e.g., 256-bit random). The control plane stores an Argon2id or SHA-256 hash of the token. |
| **Credential Exposure at Server** | Zero. If the control plane database is compromised, the attacker only acquires public keys and cannot impersonate agents. | Secure against offline cracking if salted and hashed with Argon2id, but slightly higher exposure than asymmetric keys. |
| **Revocation** | Simple: Mark public key as revoked or deleted in the database. | Simple: Invalidate token record in database. |
| **Implementation Complexity** | Requires custom HTTP request signing header standard (e.g., RFC 9421 / HTTP Message Signatures) or mutual TLS (mTLS) with custom certificate management. | Standard HTTP `Authorization: Bearer <token>` over HTTPS. Standardized, well-vetted, supported by all HTTP libraries. |
| **Replay Attack Defense** | Requires timestamp / nonce validation in signature verification. | Relies on transport layer security (TLS) + token expiry/rotation. |
| **Operational Overhead** | Key generation, CSR/enrollment handshake, signature debugging. | Straightforward bootstrap token exchange. |

### Architectural Decision: Phased Identity Model
1. **Initial Implementation (M5): Hashed Bearer Tokens via Bootstrap Exchange**
   - The operator generates a one-time, time-limited **Enrollment Token** in the control plane.
   - The agent registers using this token over HTTPS.
   - The server issues a persistent, unique **Agent Secret Token**, storing only its Argon2id hash in the database.
   - The agent authenticates all subsequent requests using `Authorization: Bearer <token>` over HTTPS.
   - Any compromised token can be revoked instantly by the administrator in the database.
2. **Future Hardening:** Evaluate Ed25519 request signing or mTLS once the fleet orchestration primitives have stabilized, avoiding premature custom cryptographic protocols in early milestones.

---

## 5. Persistence & Task Queue Architecture

### PostgreSQL as the Single Source of Truth
To minimize operational overhead on modest VPS deployments, OpenAudit eliminates external message broker dependencies (such as Redis or RabbitMQ) by leveraging PostgreSQL for both persistent state and job orchestration.

#### Transactional Task Queue with `FOR UPDATE SKIP LOCKED`
Background scan execution uses PostgreSQL as an ACID-compliant, reliable queue:

```sql
-- Worker retrieves the next pending job atomically without blocking concurrent workers
WITH next_job AS (
    SELECT id
    FROM scan_jobs
    WHERE status = 'queued' 
      AND scheduled_at <= NOW()
    ORDER BY scheduled_at ASC, priority DESC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
UPDATE scan_jobs
SET status = 'running',
    started_at = NOW(),
    worker_id = $1
FROM next_job
WHERE scan_jobs.id = next_job.id
RETURNING scan_jobs.*;
```

**Benefits:**
- **Zero Extra Daemons:** No Redis or message broker to monitor, backup, or secure.
- **Strict Data Consistency:** Jobs and scan records live within the same transactional database. If a database transaction rolls back, job state consistency is preserved.
- **Low Memory Footprint:** PostgreSQL handles connections and indexing efficiently within standard memory constraints.

For the comprehensive relational entity design, Row-Level Security (RLS) policies, finding deduplication state machine, and evidence retention rules, see [DATA-MODEL.md](DATA-MODEL.md).

---

## 6. Observability & Structured Logging

OpenAudit standardizes on the `tracing` ecosystem across all crates and binaries:

- **Structured Key-Value Spans:** Every scan execution, API request, and agent polling cycle is bound to a structured trace span carrying `organization_id`, `asset_id`, and `scan_id`.
- **Environment Filter:** Configured via `RUST_LOG` with sensible defaults (e.g., `info,openaudit=debug`).
- **Log Formatting:** Standard human-readable formatting in development CLI contexts and machine-readable JSON in production server/container deployments.
- **No Logged Secrets:** Explicit filter sanitizers prevent logging bearer tokens, private keys, or raw unsanitized evidence payloads.

---

## 7. Deployment Architecture

For self-hosted production deployments, OpenAudit is packaged as a lightweight Docker Compose deployment:

```mermaid
flowchart TD
    Client[Operator Browser / CLI] -->|HTTPS :443| Caddy[Caddy Reverse Proxy]
    Agent[openaudit-agent Nodes] -->|HTTPS :443| Caddy
    Caddy -->|Internal Proxy| Server[openaudit-server :8080]
    Server -->|SQL Connection Pool| Postgres[(PostgreSQL 16+)]
```

- **Caddy:** Serves as the edge TLS terminator with automated Let's Encrypt certificate management and HTTP/2 support.
- **openaudit-server:** Stateless application binary handling API routes and embedded job processing.
- **PostgreSQL:** Stores asset metadata, scan schedules, findings, audit trails, and the job queue.
