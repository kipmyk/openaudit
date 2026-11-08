# OpenAudit M3 Dimension 4: Independent External Security Assessment Package

**Milestone:** Milestone 3 Dimension 4 (Subject-Bound Authority & Rollback Protection)  
**Target of Evaluation (ToE):** OpenAudit Core Protocol & Applications (`openaudit-core`, `openaudit-server`, `openaudit-agent`)  
**Assessment Status:** **`PENDING (Ready for External Third-Party Review)`**  
**Specification Invariant:** OpenAudit Architecture Specification v1.24 §4–14  

---

## 1. Executive Summary & Purpose

This package provides independent third-party security auditors with the architectural blueprints, threat model, cryptographic specifications, attack surface analysis, and reproducible verification procedures required to audit OpenAudit Milestone 3 Dimension 4.

The core objective of Dimension 4 is establishing **hardware-anchored subject-bound authority and rollback protection** across distributed audit agents and authority servers without trusting the host operating system's clock or mutable filesystem state.

---

## 2. Target of Evaluation (ToE) Components

The audit scope covers all cryptographic, persistence, protocol, and transport layers implemented in the repository:

| Module / Component | Source Location | Security Functionality |
| :--- | :--- | :--- |
| **Canonical JSON** | `crates/core/src/protocol/canonical.rs` | RFC 8785 canonical serialization, deterministic key sorting, safe integer range verification (`MIN_SAFE_INTEGER` to `MAX_SAFE_INTEGER`). |
| **Cryptographic Engine** | `crates/core/src/protocol/crypto.rs` | HMAC-SHA256 signature verification, constant-time comparisons, DER SPKI public key parser for RSA-2048 and NIST P-256 ECC. |
| **Time & Trust Validation** | `crates/core/src/protocol/trust.rs` | Bounded clock skew checking ($\pm 60\,\text{s}$), safe 128-bit timestamp arithmetic avoiding underflow/overflow. |
| **Durable Replay Prevention** | `crates/core/src/protocol/replay.rs` | SQLite WAL mode (`PRAGMA synchronous = FULL`), `BEGIN IMMEDIATE` check-and-consume write transactions, automatic pruning. |
| **Resilient Catalog Storage** | `crates/core/src/protocol/catalog.rs` | 6-stage crash-safe update transaction, parent dir `fsync` barriers, CB-01..13 recovery state machine, POSIX advisory file locking. |
| **TPM 2.0 Wire Client** | `crates/core/src/protocol/tpm.rs` | Part 3 wire protocol client, NV monotonic counter (`0x01800001`), policy session authorization, 4-state agent lifecycle. |
| **Authority Persistence** | `crates/core/src/protocol/authority_store.rs` | Dedicated `authority.db` enforcing atomic token consumption + machine registration in an ACID transaction with rollback protection. |
| **Authority Orchestration** | `crates/core/src/protocol/authority.rs` | Token validation, challenge generation, transcript verification, generation synchronization. |
| **TLS 1.3 Transport** | `crates/core/src/protocol/tls.rs` | Strict TLS 1.3 transport, rejection of TLS 1.2 downgrades, certificate chain validation, hostname authentication, mode 0600 private key enforcement. |
| **Server Application** | `apps/server/src/main.rs` | Authority daemon CLI, `serve-tls`, token issuance, catalog management, mode 0600 secret loading. |
| **Agent Application** | `apps/agent/src/main.rs` | Agent CLI, `provision`, `enroll-tls`, `retrieve-tls`, hardware TPM detection and diagnostic errors. |
| **Packaging & Udev** | `packaging/udev/99-openaudit-tpm.rules` | Linux least-privilege udev configuration restricting `/dev/tpmrm*` to `root:openaudit` (mode `0660`). |

---

## 3. Threat Model & Security Invariants

Auditors should evaluate the implementation against the following threat vectors:

1. **Replay Attacks:**
   - *Attack Vector:* Adversary captures a valid retrieval request or enrollment transcript and replays it over network transport.
   - *Defense:* Nonce uniqueness, timestamp freshness ($\pm 60\,\text{s}$), and atomic check-and-consume write locks in SQLite WAL replay storage (`REPLAY_DETECTED`).
2. **Rollback & Downgrade Attacks:**
   - *Attack Vector:* Adversary restores an older assessment catalog or rolls back filesystem state to bypass remediation rules.
   - *Defense:* Hardware NV monotonic counter in TPM 2.0 silicon. The catalog version $V$ is strictly synchronized with counter $C$. Any catalog with $V < C_{\text{TPM}}$ is immediately rejected (CB-08..10).
3. **Transport Eavesdropping & Tampering:**
   - *Attack Vector:* Adversary intercepts communication between agent and authority.
   - *Defense:* Strict TLS 1.3 encryption (`rustls` with ring crypto), authenticated hostname checking against root CA, and layered HMAC-SHA256 message authentication. TLS 1.2 negotiation is disabled and rejected with fatal alerts.
4. **Credential & Secret Exposure:**
   - *Attack Vector:* Unprivileged local processes read shared secrets from command-line arguments, environment variables, or world-readable files.
   - *Defense:* Secrets are never accepted via CLI flags. Protected secret files require strict POSIX mode `0600` on Unix and are validated before opening. Secrets implement redaction traits to prevent exposure in logs or backtraces.
5. **Race Conditions & Concurrency Contention:**
   - *Attack Vector:* Concurrent processes attempt duplicate token redemption simultaneously.
   - *Defense:* SQLite WAL transactions with `BEGIN IMMEDIATE` serialize write access across separate OS processes. Duplicate token consumption fails closed and rolls back.

---

## 4. Auditor Review Checklist

- [ ] **Cryptographic Primitives:**
  - [ ] Are constant-time equality checks employed for HMAC verification (`subtle::ConstantTimeEq`)?
  - [ ] Does canonical JSON serialization match RFC 8785 specifications across nested dictionaries and arrays?
  - [ ] Are integer values strictly validated within the IEEE 754 safe integer range?
- [ ] **State Machine & Concurrency:**
  - [ ] Does token consumption and node registration execute within a single atomic SQLite transaction?
  - [ ] Does a failed enrollment rollback token consumption cleanly?
  - [ ] Are file operations protected with atomic renames and parent directory `fsync` barriers?
- [ ] **Hardware TPM Integration:**
  - [ ] Does NV space definition enforce `TPMA_NV` attributes `0x02040018`?
  - [ ] Is policy session authorization verified using the correct target authorization digest?
  - [ ] Does agent provisioning handle TPM reset, NV space exhaustion, and lifecycle mismatch by entering quarantine?
- [ ] **Transport & Network Security:**
  - [ ] Is TLS 1.2 or earlier negotiation definitively rejected by the server?
  - [ ] Are expired, malformed, or hostname-mismatched certificates rejected fail-closed?
  - [ ] Are private keys validated for restrictive permissions (`0600`) before use?

---

## 5. Step-by-Step Reproduction Guide

Auditors can independently verify the entire suite using standard Rust tooling:

```bash
# 1. Clone repository
git clone git@github.com:kipmyk/openaudit.git
cd openaudit

# 2. Verify frozen remediation harness checksum
shasum -a 256 /tmp/d4_subject_bound_authority_remediation/src/lib.rs
# Expected: 69148e8cb50d7a9a10caadcd42286a112d086b426b03199ff718ccc1f6865ad9

# 3. Format & Lint Verification
cargo fmt -- --check
cargo clippy --workspace --all-targets -- -D warnings

# 4. Build Binaries
cargo build --bins --release

# 5. Execute Complete Workspace Test Suite (including live swtpm and TLS 1.3 tests)
cargo test --workspace

# 6. Execute TLS 1.3 Transport Integration Suite Individually
cargo test --test tls_transport_integration
```

---

## 6. Current Status: `PENDING`

This assessment package is complete and ready for submission to external security evaluation bodies. The status is formally designated as **`PENDING`** until third-party penetration testing and source code audit reports are returned and ratified.
