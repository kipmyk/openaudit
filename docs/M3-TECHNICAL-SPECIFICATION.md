# OpenAudit M3 Technical Specification: Two-Engine Architecture & Vulnerability Intelligence

**Document Version:** 1.0.0  
**Status:** Architecture & Engineering Specification  
**Preceding Milestone:** `v0.2.0-m2` (Frozen)  
**Author:** Lead Software Architect & Security Researcher  

---

## 1. Executive Summary & Core Design Principles

Milestone M2 established OpenAudit's **Engine 1: Security Posture**, providing deterministic, read-only configuration auditing across 20 security rules with 100% precision and recall on an empirical Ubuntu 24.04 testbed.

Milestone M3 introduces **Engine 2: Vulnerability Intelligence**, transforming OpenAudit into a unified Linux security assessment platform. Rather than attempting to serve as a generic, opaque CVE scanner, Engine 2 is built around rigorous distribution-specific advisory matching, explicit uncertainty modeling, and transparent evidentiary backing.

```mermaid
graph TD
    subgraph OpenAudit Unified Security Platform
        CLI["openaudit-cli audit local"]
        
        subgraph Engine 1: Security Posture (M2 - Frozen)
            Posture["Configuration & Exposure Auditing<br/>- SSH daemon policies<br/>- Firewall states & packet filters<br/>- Open database sockets<br/>- Permissions, SUID/SGID, PATH<br/>- Kernel sysctl hardening"]
        end

        subgraph Engine 2: Vulnerability Intelligence (M3 - Planned)
            Inventory["Package Inventory Collector<br/>(/var/lib/dpkg/status, rpmdb, apk)"]
            VersionNorm["Version Normalization Engine<br/>(Epochs, Debian Policy §5.6.12, RPM EVR)"]
            AdvisoryMatch["Distro Advisory Matcher<br/>(Ubuntu USN, Debian Tracker, OVAL)"]
            Uncertainty["Confidence & Uncertainty Assessor<br/>(Confirmed, Likely, Requires Verification)"]
            
            Inventory --> VersionNorm --> AdvisoryMatch --> Uncertainty
        end

        subgraph Shared Synthesis & Reporting
            Synthesis["Findings Aggregator & Provenance Sealer<br/>- Database timestamp & sync metadata<br/>- Universal secret redaction<br/>- Structured JSON / Human CLI output"]
        end

        CLI --> Posture & Inventory
        Posture --> Synthesis
        Uncertainty --> Synthesis
    end
```

### Core Design Principles

1. **Preserve M2 Immutability:** Engine 1 (Security Posture) remains completely frozen. Engine 2 is developed in clean, modular sub-crates without modifying M2 rules or test fixtures.
2. **Distribution-Aware Advisory Matching:** Upstream version numbers alone are fundamentally misleading on enterprise Linux distributions due to backported security patches. Engine 2 evaluates vendor security advisories (Ubuntu USN, Debian Security Tracker, RHEL OVAL) rather than naive upstream semver comparisons.
3. **Explicit Uncertainty & Confidence:** When vulnerability state cannot be mathematically proven (e.g. source-compiled binaries, missing advisory data, conditional compiler flags), OpenAudit assigns an explicit confidence rating (`Confirmed`, `LikelyVulnerable`, `RequiresVerification`, `Unknown`) rather than emitting false positives or silent false negatives.
4. **Offline & Air-Gapped Operation:** The engine supports fully offline local execution against a cached, timestamped vulnerability database, recording exact database provenance in every report.
5. **No False Promises:** Memory-safe Rust and low runtime overhead are architectural commitments; detection completeness and performance claims remain hypotheses to be proven through empirical benchmarking against tools like Trivy and OSV-Scanner.

---

## 2. Engine Boundaries & Workspace Architecture

OpenAudit enforces strict workspace crate separation:

```text
crates/
├── core/                   # Platform-agnostic domain models (Asset, Finding, Severity, Confidence)
├── engine/                 # Host inspection runtime
│   ├── collector/          # M2 posture telemetry collectors (frozen)
│   ├── rule/               # M2 posture rules (frozen)
│   ├── runner.rs           # M2 audit runner (frozen)
│   └── vulnerability/      # M3 Engine 2 implementation (NEW)
│       ├── inventory/      # Package managers: dpkg, rpm, apk
│       ├── version/        # Version comparison algorithms: debian.rs, rpm.rs
│       ├── database/       # Local advisory store & staleness validator
│       └── matcher/        # Advisory correlation & confidence evaluator
```

### Domain Model Extension: Confidence Rating

In `crates/core/src/finding.rs`, finding structures are extended with an explicit confidence classification:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Mathematically verified: exact package version matches vendor advisory fixed version.
    Confirmed,
    /// High probability: version appears vulnerable, but runtime configuration or patch backport cannot be 100% verified.
    LikelyVulnerable,
    /// Ambiguous: vulnerable package installed, but distribution patch status is unrecorded.
    RequiresVerification,
    /// Inconclusive: database staleness or partial metadata prevents definitive matching.
    Unknown,
}
```

---

## 3. Package Inventory Collection & Normalization

### 3.1 Direct Filesystem Inspection over Subprocess Execution

To preserve read-only auditing and minimize execution overhead (< 15 ms), the package inventory collector inspects native package status files directly rather than spawning external shell processes:

- **Debian / Ubuntu:** Directly parses `/var/lib/dpkg/status`.
  - Fallback: `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n'`.
- **RHEL / Rocky / CentOS:** Reads `/var/lib/rpm/rpmdb.sqlite` (modern) or Berkeley DB `/var/lib/rpm/Packages`.
- **Alpine Linux:** Directly parses `/lib/apk/db/installed`.

### 3.2 Inventory Schema

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageProvenance {
    /// Official Ubuntu archive distribution.
    OfficialUbuntu,
    /// Official Debian archive distribution.
    OfficialDebian,
    /// Ubuntu Personal Package Archive (PPA).
    UbuntuPpa,
    /// Third-party repository (e.g., Docker, PostgreSQL, Nodesource).
    ThirdPartyRepo,
    /// Manually installed package or unknown origin.
    ManualLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInventory {
    pub package_manager: PackageManagerType,
    pub total_packages: usize,
    pub packages: Vec<InstalledPackage>,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub binary_name: String,
    pub binary_version: String,
    pub source_name: String,
    pub source_version: String,
    pub architecture: String,
    pub status: String,
    pub provenance: PackageProvenance,
}
```

#### Parsing Contract for Source and Version:
In `/var/lib/dpkg/status`:
1. Parse `Package:` as `binary_name` and `Version:` as `binary_version`.
2. Inspect `Source:`:
   - If `Source:` has format `source_name (source_version)`, extract both.
   - If `Source:` has format `source_name` (no version), `source_version` defaults to `binary_version`.
   - If `Source:` is absent entirely, `source_name` defaults to `binary_name` and `source_version` defaults to `binary_version`.
3. Architecture identifiers are normalized: `x86_64` <-> `amd64`, `aarch64` <-> `arm64`.

### 3.3 Debian Version Parsing Algorithm (Policy Manual §5.6.12)

Debian versions follow the format `[epoch:]upstream_version[-debian_revision]`. Correct comparison requires implementing the full Debian specification:

```rust
pub struct DebianVersion<'a> {
    pub epoch: u32,
    pub upstream_version: &'a str,
    pub debian_revision: &'a str,
}

impl<'a> DebianVersion<'a> {
    pub fn parse(raw: &'a str) -> Result<Self, VersionError> {
        let (epoch, remainder) = if let Some((ep, rest)) = raw.split_once(':') {
            (ep.parse::<u32>().map_err(|_| VersionError::InvalidEpoch)?, rest)
        } else {
            (0, raw)
        };

        let (upstream, revision) = if let Some((up, rev)) = remainder.rsplit_once('-') {
            (up, rev)
        } else {
            (remainder, "0")
        };

        Ok(Self { epoch, upstream_version: upstream, debian_revision: revision })
    }

    /// Compares two version strings according to Debian Policy §5.6.12.
    /// Handles tilde `~` (sorts before empty string) and non-digit vs digit chunk ordering.
    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        if self.epoch != other.epoch {
            return self.epoch.cmp(&other.epoch);
        }
        match compare_deb_chunk(self.upstream_version, other.upstream_version) {
            std::cmp::Ordering::Equal => compare_deb_chunk(self.debian_revision, other.debian_revision),
            ord => ord,
        }
    }
}
```

---

## 4. Distro Advisory Ingestion & The Backport Dilemma

### 4.1 The Backport Problem

Enterprise distributions (Ubuntu LTS, Debian, RHEL) rarely update major upstream software versions in stable releases. Instead, security fixes are **backported** to the release version:

```text
Upstream Apache release:        2.4.62 (fixes CVE-2024-38473)
Ubuntu 24.04 LTS original:      2.4.58-1ubuntu8
Ubuntu 24.04 LTS security fix:  2.4.58-1ubuntu8.1 (fixes CVE-2024-38473)
```

A naive scanner comparing upstream versions checks `2.4.58 < 2.4.62` and generates a **false positive**, flagging a fully patched system as vulnerable.

### 4.2 Distro Advisory Feeds & Ingestion Formats

OpenAudit Engine 2 maps packages against distribution-specific feeds:

1. **Ubuntu Security Notices (USN) & Ubuntu OSV Feed:**
   - Authoritative source for Ubuntu releases (`noble`, `jammy`, `focal`).
   - Maps specific package releases (e.g. `2.4.58-1ubuntu8.1`) to fixed CVEs.
   - Leverages Canonical's standardized **Ubuntu OSV JSON feed** (`https://documentation.ubuntu.com/security/security-updates/osv/`) alongside OVAL and USN API.
2. **Debian Security Bug Tracker:**
   - JSON feed (`https://security-tracker.debian.org/tracker/data/json`) detailing DSA/DLA notices and package-specific fix versions.
3. **OSV.dev (Open Source Vulnerabilities):**
   - Supplementary feed for ecosystem dependencies (Python, Node.js, Rust) with strict ecosystem qualifiers (`Debian:12`, `Ubuntu:24.04`).

---

## 5. Version Range Semantics & Advisory Lifecycle

### 5.1 Strict Prohibition on Synthesizing Epochs

Debian version comparison defines an omitted epoch as `0`. **OpenAudit strictly prohibits inventing or inferring an epoch for an advisory based on the installed package.**

- Example: Installed is `1:1.9-1`. Advisory fixed version states bare `2.0`.
- The literal Debian comparison is evaluated: `1:1.9-1 > 2.0` (epoch `1` > epoch `0`).
- If advisory data appears inconsistent with distribution metadata, OpenAudit assigns `Confidence::RequiresVerification` or `Confidence::Unknown`. It **never** fabricates an epoch.

### 5.2 Structured Advisory Model

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityAdvisory {
    pub cve_id: String,
    pub source_package: String,
    pub release_codename: String,
    pub fixed_version: Option<String>,
    pub introduced_version: Option<String>,
    pub last_affected_version: Option<String>,
    pub status: AdvisoryStatus,
    pub urgency: AdvisoryUrgency,
    pub repositories: Vec<String>,
    pub published_at: DateTime<Utc>,
    pub last_modified_at: DateTime<Utc>,
}
```

### 5.3 Advisory Lifecycle & Canonical State Resolution

| State | Canonical / Debian Context | OpenAudit Engine Action |
|---|---|---|
| **`RESOLVED`** | Package fixed in `fixed_version`. | Compare `source_version < fixed_version`. If older, emit finding. |
| **`OPEN`** | Vulnerability active; no fix released. | Evaluate affected version range; report `unpatched_upstream` (no upgrade remediation). |
| **`NEEDED` / `PENDING`** | Fix acknowledged by vendor, build pending. | Emit finding flagging unpatched state; no false upgrade advice. |
| **`IGNORED`** | Vendor decided not to fix (won't fix / low risk). | Retain finding, disclose vendor decision explicitly. |
| **`DEFERRED`** | Fix postponed to future point release. | Retain finding with postponement notice. |
| **`UNDETERMINED`** | Security team assessment incomplete. | Return inconclusive finding (`Confidence::RequiresVerification`). |
| **`DISPUTED`** | CVE disputed by maintainers/community. | Retain finding with dispute caveat & reduced confidence. |
| **`REJECTED`** | CVE revoked by CNA / NVD. | Suppress active alert; preserve audit history. |
| **`NOT_AFFECTED`** | Explicitly non-vulnerable. | Do not alert for that release/architecture scope. |

### 5.4 Third-Party Packages & PPA Provenance Model

Packages installed from PPAs or third-party repositories may share a source name with Ubuntu packages but possess a different build history or patch set. OpenAudit enforces explicit provenance handling:

- **Official Ubuntu / Debian Archives:** Standard vendor advisory matching (`Confidence::Confirmed`).
- **Ubuntu PPA / Third-Party Repositories:** When installed version appears older than vendor fix, OpenAudit does **not** assert confirmed vulnerability. Instead, it emits:
  ```json
  {
    "confidence": "requires_verification",
    "reason": "external_package_provenance",
    "note": "Package sourced from third-party PPA; vendor USN patch status cannot be confirmed."
  }
  ```

---

## 6. Hybrid Local Database Architecture

To ensure fast local CLI execution (< 25 ms) with 100% offline air-gapped support:

```text
[Upstream Feeds: USN, Debian, OSV]
             │
             ▼ (Download & Snapshot)
[Immutable Source Snapshots] (*.json.gz / *.xml.gz with SHA-256)
             │
             ▼ (Normalize & Index)
[Operational SQLite Index] (openaudit-vuln.db)
             │
             ▼ (Read-Only Local Query)
[OpenAudit CLI Scanner] (Zero network calls during audit)
```

1. **Operational Database:** SQLite with indexed tables (`advisories`, `packages_cve_map`, `provenance_meta`).
2. **Immutable Snapshots:** Compressed raw JSON/OVAL files retained for cryptographic verification and auditability.
3. **Database Provenance:** Report records `feed_name`, `version`, `published_at`, `synced_at`, `is_stale`, and SHA-256 digest.

---

## 7. M3 Validation Standards & Fixture Suites

### 7.1 Dimension 1: Debian Version Conformance (32 Verified Cases)
Verified 1:1 against reference `dpkg 1.22.6` (Ubuntu 24.04 arm64):
- Epoch boundaries (`0..=2147483647`).
- Tilde sorting (`1.0~~ < 1.0~ < 1.0`).
- Upstream precedence over revision delimiter (`1.0a > 1.0-1`).
- Arbitrary length numeric runs without machine overflow (`1.000...02 == 1.2`).

### 7.2 Dimension 2: Advisory Matching & Provenance Fixtures (15 Cases)

| Test ID | Scenario | Expected Engine Behavior |
|---|---|---|
| **D2-01** | Ubuntu Noble advisory on Jammy host | Zero applicability; discard advisory. |
| **D2-02** | Matching source package generating multiple binaries | Correct binary attribution (`src:glibc` -> `libc6`). |
| **D2-03** | `Source:` field contains explicit `source_name (source_version)` | Evaluate `source_version`, not `binary_version`. |
| **D2-04** | Missing `Source:` field in `/var/lib/dpkg/status` | Fall back cleanly to `binary_name` and `binary_version`. |
| **D2-05** | Ubuntu `needed` vulnerability state | Vulnerable finding without false "upgrade" advice. |
| **D2-06** | Ubuntu `ignored` vulnerability state | Retain finding, disclose vendor decision explicitly. |
| **D2-07** | Debian `undetermined` status | Report inconclusive (`Confidence::RequiresVerification`). |
| **D2-08** | Debian `unimportant` urgency | Retain finding with low urgency; do NOT treat as immune. |
| **D2-09** | Third-party PPA package with older version | Flag with `Confidence::RequiresVerification` (provenance caveat). |
| **D2-10** | Advisory lacks epoch; installed package has epoch `1:` | Compare literally without synthesizing epoch. |
| **D2-11** | Architecture-specific advisory (`amd64` only on `arm64` host) | Architecture filter discards notice; zero false positives. |
| **D2-12** | Withdrawn / Rejected CVE advisory | Suppress active alert; preserve audit record. |
| **D2-13** | Superseding USN revision (`-2` over `-1`) | Resolve package-level advisory state to latest applicable. |
| **D2-14** | Missing or corrupted feed metadata | Report `Confidence::Unknown` with integrity error. |
| **D2-15** | Malformed advisory fixed version string | Reject malformed record; alert operator to feed corruption. |

---

## 8. M3 Implementation Phasing & Milestones

```text
M3.1: Platform Abstraction & Decoupling (Weeks 1–4)
      - Refactor HostInspectionContext into modular sub-contexts.
      - Verify zero regression on M2 55-scenario suite.

M3.2: Package Inventory & Version Normalization (Weeks 5–8)
      - Implement /var/lib/dpkg/status reader with Source version parsing.
      - Implement Debian Policy §5.6.12 version comparison engine.
      - Execute 32 Dimension 1 conformance test cases.

M3.3: Hybrid Vulnerability Database & USN/OSV Ingestion (Weeks 9–14)
      - Implement SQLite operational index and snapshot validator.
      - Build Ubuntu OSV and Debian Security Tracker parsers.
      - Implement backport-aware matching algorithm.

M3.4: Confidence Engine & Uncertainty Modeling (Weeks 15–18)
      - Implement 4-tier confidence classification and provenance guards.
      - Add DatabaseProvenance metadata to JSON report schema.

M3.5: Multi-Distro Lab Matrix & Benchmarks (Weeks 19–24)
      - Execute 15 Dimension 2 synthetic test fixtures.
      - Benchmark accuracy and memory footprint against Trivy and OSV-Scanner.
      - Publish M3 Lab Evaluation & Benchmark Report.
```
      - Refactor HostInspectionContext into modular sub-contexts.
      - Verify zero regression on M2 55-scenario suite.

M3.2: Package Inventory & Version Normalization (Weeks 5–8)
      - Implement /var/lib/dpkg/status reader.
      - Implement Debian Policy §5.6.12 version comparison engine.
      - Add 40 unit tests for complex epoch and tilde comparisons.

M3.3: Distribution Advisory Database & USN Matching (Weeks 9–14)
      - Implement local sqlite/compact-json advisory cache.
      - Build Ubuntu USN and Debian Security Tracker parser.
      - Implement backport-aware matching algorithm.

M3.4: Confidence Engine & Uncertainty Modeling (Weeks 15–18)
      - Implement 4-tier confidence classification.
      - Add DatabaseProvenance metadata to JSON report schema.

M3.5: Multi-Distro Lab Matrix & Benchmarks (Weeks 19–24)
      - Expand lab to evaluate 30 vulnerable/patched package fixtures.
      - Benchmark accuracy and memory footprint against Trivy and OSV-Scanner.
      - Publish M3 Lab Evaluation & Benchmark Report.
```

This specification establishes a disciplined, scientifically defensible roadmap for Milestone M3, maintaining OpenAudit's reputation for transparency, honesty about uncertainty, and verifiable systems engineering.

