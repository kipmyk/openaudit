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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInventory {
    pub package_manager: PackageManagerType,
    pub total_packages: usize,
    pub packages: Vec<InstalledPackage>,
    pub collected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub source_name: Option<String>,
    pub source_version: Option<String>,
    pub status: String,
}
```

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

## 4. The Backport Dilemma & Distro Advisory Matching

### 4.1 The Backport Problem

Enterprise distributions (Ubuntu LTS, Debian, RHEL) rarely update major upstream software versions in stable releases. Instead, security fixes are **backported** to the release version:

```text
Upstream Apache release:        2.4.62 (fixes CVE-2024-38473)
Ubuntu 24.04 LTS original:      2.4.58-1ubuntu8
Ubuntu 24.04 LTS security fix:  2.4.58-1ubuntu8.1 (fixes CVE-2024-38473)
```

A naive scanner comparing upstream versions checks `2.4.58 < 2.4.62` and generates a **false positive**, flagging a fully patched system as vulnerable.

### 4.2 Distro Advisory Feeds

OpenAudit Engine 2 maps packages against distribution-specific feeds:

1. **Ubuntu Security Notices (USN) / Ubuntu CVE Tracker:**
   - Authoritative source for Ubuntu releases (`noble`, `jammy`, `focal`).
   - Maps specific package releases (e.g. `2.4.58-1ubuntu8.1`) to fixed CVEs.
2. **Debian Security Bug Tracker:**
   - JSON feed detailing DSA (Debian Security Advisories) and package-specific fix versions.
3. **OSV.dev (Open Source Vulnerabilities):**
   - Utilized for language ecosystem packages (Python, Node.js, Rust) and supplementary matching, using ecosystem qualifiers (`Debian:12`, `Ubuntu:24.04`).

---

## 5. Vulnerability Database Provenance & Staleness

A vulnerability scanner with an outdated database creates a dangerous illusion of security. OpenAudit records and reports database provenance on every execution:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseProvenance {
    pub feed_name: String,
    pub feed_version: String,
    pub published_at: DateTime<Utc>,
    pub synchronized_at: DateTime<Utc>,
    pub total_advisories: usize,
    pub is_stale: bool,
    pub staleness_warning: Option<String>,
}
```

### Staleness Policy
- **Age < 7 days:** Green (`is_stale: false`).
- **Age 7–30 days:** Amber warning attached to report header; findings classified with caveat.
- **Age > 30 days:** Red alert flag; advisory matching marks unconfirmed CVEs with `Confidence::RequiresVerification` due to stale intelligence.

---

## 6. Rigorous M3 Validation Standards

Engine 2 will be subjected to the same rigorous ground-truth evaluation standards established in M2:

| Test Suite | Purpose | Target Metric |
|---|---|---|
| **Suite 1: Vulnerable Package Fixtures** | Synthetic `/var/lib/dpkg/status` containing known unpatched vulnerable versions (e.g. `openssh-server 1:8.9p1-3`). | 100% Recall on confirmed CVEs |
| **Suite 2: Backported Patch Fixtures (Controls)** | Packages containing security backports (e.g. `openssh-server 1:8.9p1-3ubuntu0.10`). | 0% False Positives (must NOT flag) |
| **Suite 3: Debian Version & Epoch Unit Tests** | Corner-case comparisons (`1:2.0 < 2:1.0`, `1.0~rc1 < 1.0`, `1.0+b1 > 1.0`). | 100% compliance with Debian Policy |
| **Suite 4: Missing & Stale Database Tests** | Execution when local database is missing, corrupted, or older than 30 days. | Honest error handling & degraded confidence |
| **Suite 5: Air-Gapped Offline Execution** | Running local audits with network interfaces disabled. | Zero network requests, 100% local operation |
| **Suite 6: Competitive Benchmarks** | Side-by-side run against **Trivy** and **OSV-Scanner** on identical systems. | Documented differential analysis |

---

## 7. M3 Implementation Phasing & Milestones

```text
M3.1: Platform Abstraction & Decoupling (Weeks 1–4)
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
