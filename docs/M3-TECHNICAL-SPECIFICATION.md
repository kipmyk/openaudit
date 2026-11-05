# OpenAudit M3 Technical Specification: Two-Engine Architecture & Vulnerability Intelligence

**Document Version:** 1.1.0  
**Status:** Architecture & Engineering Specification (Review in Progress)  
**Preceding Milestone:** `v0.2.0-m2` (Frozen)  
**Author:** Lead Software Architect & Security Researcher  

---

### Architecture Review Governance Status

| Dimension | Scope | Review Status |
| :--- | :--- | :--- |
| **Dimension 1** | Debian Version Comparison Correctness (Debian Policy §5.6.12) | **CLOSED** (32 Verified Cases) |
| **Dimension 2** | Ubuntu USN & Debian Advisory Matching Semantics | **CLOSED** (15 Conformance Cases) |
| **Dimension 3** | Source-to-Binary CVE-to-Package Mapping & Exposure | **CLOSED** (27 Conformance Cases) |
| **Dimension 4** | Confidence Classification Consistency & Trigger Matrix | **PENDING** |
| **Dimension 5** | Database Synchronization, Integrity & Provenance | **PENDING** |
| **Dimension 6** | Universal Secret Redaction Across Vulnerability Outputs | **PENDING** |

> **M3 Implementation Boundary:** M2 (`v0.2.0-m2`) is immutable and frozen. M3 implementation remains strictly on **HOLD** until all six architecture dimensions pass formal review approval.  

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

### 3.4 Five Independent Assessment Dimensions & Source-to-Binary Relationship Model

OpenAudit's vulnerability intelligence enforces a foundational governing principle:

> **Governing Principle:** *OpenAudit must distinguish what is installed, what the vendor states is affected, what evidence connects the two, and what is actually running.*

To prevent false confidence and semantic confusion, vulnerability findings are decomposed into five mutually independent dimensions:

```rust
/// 1. Vulnerability state according to vendor advisory criteria
/// Evaluated ONLY when an applicable installed package exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilityAssessment {
    Affected,
    NotAffected,
    Inconclusive,
}

/// 2. Evidence linking installed package artifacts to the advisory
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingEvidence {
    pub source_match: bool,
    pub binary_match: bool,
    pub binary_scope_completeness: BinaryScopeCompleteness,
    pub advisory_version_basis: AdvisoryVersionBasis,
    pub patch_lineage: PatchLineageEvidence,
    pub dependency_evidence: Vec<DependencyEvidence>,
    pub kernel_association: Option<KernelAssociationEvidence>,
    pub artifact_nature: ArtifactNature,
}

/// Explicit completeness guarantee of advisory binary package lists
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryScopeCompleteness {
    /// Vendor contract explicitly guarantees the list is complete and exhaustive.
    /// Only under this contract does omitting an installed binary support NotAffected.
    Exhaustive(Vec<String>),
    /// Vendor enumerates affected binaries descriptively, but does NOT guarantee completeness.
    /// Omission from a descriptive list CANNOT be used to infer NotAffected.
    Descriptive(Vec<String>),
    /// Derived from multi-criteria OVAL / OSV definitions
    Derived { exhaustive: bool, binaries: Vec<String> },
    /// Advisory specifies source package only; no binary list provided
    Unspecified,
    /// Feed format does not define binary relationships
    Unsupported,
}

/// Explicit basis for version comparison (resolves Dimension 2 contract)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryVersionBasis {
    SourcePackageVersion,  // Evaluated against installed_package.source_version
    BinaryPackageVersion,  // Evaluated against installed_package.binary_version
    VendorDefined(String), // Documented feed-specific evaluation contract
    Unsupported,           // Undefined version basis -> Inconclusive
}

/// Formal patch-lineage evidence for third-party and PPA builds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchLineageEvidence {
    VerifiedContainsVendorPatch, // Cryptographically or deterministically verified to contain vendor security fix
    VerifiedLacksVendorPatch,    // Verified build artifacts confirm vendor security fix is absent
    VerifiedBuildAndPatchSet,    // Source repo and build set verified, but specific patch state unconfirmed (Inconclusive)
    Unverified,                  // Lineage cannot be verified against vendor patch history
    Unknown,                     // Lineage inspection unsupported or unperformed
}

/// Static nature of the installed artifact (independent of runtime process scanning)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactNature {
    ExecutableOrLibrary,        // Standard binaries, daemons, shared objects
    NonExecutableDocumentation, // Manpages, HTML docs, examples (libc6-dev-doc)
    DevelopmentHeaders,         // C/C++ header files (linux-headers-*)
    DataOrAssets,               // Static dictionaries, fonts, themes
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyEvidence {
    DeclaredDependency { dependent_pkg: String, constraint: String },
    ResolvedDependency { dependent_pkg: String, resolved_version: String },
}

/// Manifest- and runtime-backed kernel association evidence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelAssociationEvidence {
    pub package_kernel_release: String,
    pub running_kernel_release: String,
    pub package_role: KernelPackageRole,
    pub ownership_evidence: KernelOwnershipEvidence,
    pub runtime_module_evidence: Option<RuntimeModuleEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelPackageRole {
    KernelImage,   // Executable kernel binary (/boot/vmlinuz-<release>)
    RuntimeModule, // Core loadable kernel module tree (/lib/modules/<release>/kernel/...)
    ExtraModule,   // Out-of-tree / DKMS module tree (/lib/modules/<release>/kernel/extra/...)
    Headers,       // Development C headers (/usr/src/linux-headers-<release>)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KernelOwnershipEvidence {
    VerifiedFileOwnership { path: String, package: String },
    ManifestAssociation { manifest_key: String, release: String },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeModuleEvidence {
    LoadedInKernel { module_name: String, source_file: String },
    NotObservedInKernel,
    InspectionUnavailable,
}

/// 5. Operational execution state on the host
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalExposure {
    Active,            // Direct runtime evidence (verified PID executable or loaded kernel/module)
    InstalledInactive, // Component verified installed but inactive within defined inspection scope
    Unknown,           // No direct runtime evidence available (baseline M3 state for packages/libraries)
}
```

#### Key Evidentiary Contracts & Qualifications:

1. **Kernel Image Association Qualification:**
   - Association between an installed package and the running kernel is established by verifying that the package manifest owns `/boot/vmlinuz-<release>` where `<release>` matches `uname -r`.
   - This represents **verified package-to-running-release association**. It does **not** claim cryptographic byte-level verification of the booted memory image against the on-disk file.
2. **Role-Specific Kernel Evidence:**
   - `runtime_module_evidence` is strictly required only for module package roles (`RuntimeModule`, `ExtraModule`). Kernel images and development headers do not require module-loading evidence.
3. **Loaded Kernel Module Attribution Qualification:**
   - `LoadedInKernel` constitutes runtime module identity evidence (via `/proc/modules` or `/sys/module`). Package-file ownership provides the corresponding package association. Byte-level or cryptographic attribution of the in-memory loaded module is not claimed.
4. **Kernel Operational Status Derivation:**
   - If `package_role == KernelImage` AND `package_kernel_release == running_kernel_release` with verified file ownership $\rightarrow$ eligible for `OperationalExposure::Active`.
   - If `package_kernel_release != running_kernel_release` $\rightarrow$ operational status is dormant $\rightarrow$ `OperationalExposure::InstalledInactive`.
   - If `runtime_module_evidence == NotObservedInKernel` $\rightarrow$ `OperationalExposure::Unknown` (absence from `/proc/modules` does not constitute conclusive proof of inactivity).
5. **Operational Exposure Rigor: "Package Type is Not Runtime Evidence":**
   - Active process association requires `/proc/<pid>/exe` to resolve to an executable file owned by the assessed package. Process name matching alone is strictly invalid.
   - For shared libraries and CLI packages without dynamic process/memory inspection, exposure defaults to `OperationalExposure::Unknown`.
   - Fixed packages (`VulnerabilityAssessment::NotAffected`) evaluate operational exposure independently (`OperationalExposure::Unknown` unless runtime inspection establishes another state). `N/A` is reserved strictly for inventory absence and provenance-only fixtures.
6. **Inventory Absence vs. Applicability:**
   - When an advisory targets a package that is not installed on the system (e.g. Apache missing, or meta-package only), OpenAudit produces **no finding** (Inventory Absence).
   - `VulnerabilityAssessment::NotAffected` is strictly reserved for applicable installed packages whose version or criteria verify they are safe.

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

### 7.3 Dimension 3: Source-to-Binary Mapping & Package Relationship Conformance (27 Cases)

| Test ID | Category | Scenario / Input | Vulnerability Assessment | Mapping Evidence & Scope | Confidence | Operational Exposure | Expected Evaluation Behavior |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **D3-01** | Direct Binary | Advisory lists binary `openssl 3.0.13-0ubuntu3.1`. Host has `openssl 3.0.13-0ubuntu3.0` | `Affected` | `binary_match: true`, `BinaryPackageVersion` | `Confirmed` | `Unknown` | Exact binary version match; exposure unknown without memory map |
| **D3-02** | Direct Binary Safe | Advisory fixed in `3.0.13-0ubuntu3.1`. Host has `openssl 3.0.13-0ubuntu3.2` | `NotAffected` | `binary_match: true`, `BinaryPackageVersion` | `Confirmed` | `Unknown` | Fixed binary installed; operational exposure evaluated independently as `Unknown` |
| **D3-03** | Multi-Binary Source Match | Source `src:curl` vulnerable. Host has `curl 7.88.1-10`. Advisory lists `curl` and `libcurl4` | `Affected` | `source_match: true`, `Exhaustive(["curl", "libcurl4"])`, `SourcePackageVersion` | `Confirmed` | `Unknown` | CLI package exposure is `Unknown` without active process inspection |
| **D3-04** | Multi-Binary Exhaustive Exclusion | Source `src:curl` vulnerable in `libcurl4` only. Advisory contract guarantees exhaustive binary list. Host has `curl 7.88.1-10` only | `NotAffected` | `source_match: true`, `binary_match: false`, `Exhaustive(["libcurl4"])` | `Confirmed` | `Unknown` | Exhaustive binary list excludes installed binary -> safe |
| **D3-05** | Daemon Process Association | Source `src:systemd` vulnerable. Vendor lists no binaries. Host has `udev 255.4-1ubuntu8`. `/proc/123/exe` points to package-owned `/usr/lib/systemd/systemd-udevd` | `Affected` | `source_match: true`, `Unspecified`, `SourcePackageVersion` | `LikelyVulnerable` | `Active` | Verified package-owned daemon executable via `/proc/<pid>/exe` |
| **D3-06** | Documentation Sub-package | Source `src:glibc` vulnerable. Host has `libc6-dev-doc` only. Advisory is `Exhaustive(["libc6"])` | `NotAffected` | `source_match: true`, `Exhaustive(["libc6"])`, `NonExecutableDocumentation` | `Confirmed` | `InstalledInactive` | Non-executable artifact excluded by exhaustive binary list |
| **D3-07** | Running Kernel Image | Advisory affects kernel `6.8.0-31.31`. Host runs `uname -r = 6.8.0-31-generic`. Package owns `/boot/vmlinuz-6.8.0-31-generic` | `Affected` | `binary_match: true`, `VerifiedFileOwnership`, `KernelImage`, `release == running` | `Confirmed` | `Active` | Verified package-to-running-release association |
| **D3-08** | Running Kernel Fixed | Advisory fixed in `6.8.0-35.35`. Host runs `6.8.0-35-generic`. Package owns `/boot/vmlinuz-6.8.0-35-generic` | `NotAffected` | `binary_match: true`, `VerifiedFileOwnership`, `KernelImage`, `release == running` | `Confirmed` | `Active` | Running kernel image verified and fixed |
| **D3-09** | Dormant Kernel Vulnerable | Host boots `6.8.0-35-generic`. Package `linux-image-6.8.0-31-generic` owns `/boot/vmlinuz-6.8.0-31-generic` | `Affected` | `binary_match: true`, `VerifiedFileOwnership`, `KernelImage`, `release != running` | `Confirmed` | `InstalledInactive` | Dormant kernel affected; inactive derived from release mismatch |
| **D3-10** | Dormant Kernel Multiple | Host boots `6.8.0-35-generic`. Two older dormant kernels with verified ownership: `6.8.0-28` and `6.8.0-31` | `Affected` (for each) | `binary_match: true`, `VerifiedFileOwnership`, `KernelImage`, `release != running` | `Confirmed` | `InstalledInactive` | Independent findings per dormant package; both confirmed inactive |
| **D3-11** | Kernel Meta-Package Only | Advisory affects `linux-image-6.8.0-31-generic`. Host has only meta-package `linux-generic` installed | **No Finding** (Inventory Absence) | `binary_match: false`, `ownership: none` | N/A | N/A | Meta-package contains no kernel files; implementation package absent |
| **D3-12** | Multi-Arch Disjoint | Advisory targets `amd64` binary only. Host has `libssl3:arm64` installed | `NotAffected` | `binary_match: true`, `architecture: mismatch` | `Confirmed` | `Unknown` | Architecture filter excludes installed package |
| **D3-13** | Arch: All Package | Advisory affects `python3-urllib3` (`Architecture: all`). Advisory architecture `Unrestricted` | `Affected` | `binary_match: true`, `Arch: all`, `Unrestricted` | `Confirmed` | `Unknown` | Architecture-independent package affected across architectures |
| **D3-14** | Multi-Arch Co-installation | Host has `libssl3:amd64` and `libssl3:i386`. Advisory affects both | `Affected` (for each) | `binary_match: true` | `Confirmed` | `Unknown` | Evaluated independently per `(binary_name, architecture)` |
| **D3-15** | Library Dependency Exposure | Nginx is running and depends on `libssl3`. Advisory affects `libssl3`. No `/proc/<pid>/maps` inspection | `Affected` (on `libssl3`) | `DeclaredDependency`, `ResolvedDependency` | `Confirmed` | `Unknown` | Finding stands at package level; library runtime loading unverified |
| **D3-16** | Uninstalled Advisory Match | Advisory affects `apache2`. Host has no `apache2` package installed | **No Finding** (Inventory Absence) | `binary_match: false`, `source_match: false` | N/A | N/A | Suppressed from host findings (no applicable artifact) |
| **D3-17** | Custom Local Build | Host has `openssl 3.0.13-custom`. Advisory for `3.0.13-0ubuntu3.1` | `Inconclusive` | `source_match: true`, `binary_match: true`, `patch_lineage: Unknown` | `RequiresVerification` | `Unknown` | Provenance unknown; version scheme non-standard |
| **D3-18** | Third-Party PPA Lineage Uncertainty | Host has `python3.11` from `ppa:deadsnakes`. Advisory from Ubuntu Security Archive. Upstream source matches, patch history unverified | `Inconclusive` | `source_match: true`, `patch_lineage: Unverified` | `RequiresVerification` | `Unknown` | Source identity matches but patch lineage unverified -> Inconclusive |
| **D3-19** | Version Basis Disparity | Binary version is `1.2-1`, Source version is `1.2-0ubuntu1`. Advisory basis is `SourcePackageVersion` fixed in `1.2-0ubuntu2` | `Affected` | `source_match: true`, `SourcePackageVersion` | `Confirmed` | `Unknown` | Explicitly evaluates `source_version` against advisory threshold |
| **D3-20** | Derived Binary Scope | OVAL criteria specify `obj_id` linking binary `git` to source `src:git` | `Affected` | `Derived { exhaustive: true, ... }` | `Confirmed` | `Unknown` | Multi-criteria OVAL successfully derived to binary package |
| **D3-21** | Single-Binary Source Match | Source `src:nano` produces single binary `nano`. Advisory lists `src:nano` with `Unspecified` binary scope | `Affected` | `source_match: true`, `Unspecified`, `SourcePackageVersion` | `LikelyVulnerable` | `Unknown` | Source-only advisory for single-binary package; vendor linkage strong |
| **D3-22** | Provenance Record Verification | Package record matches signed `Packages.xz` digest from authenticated `Release` file | N/A (Outside Scope) | `VerifiedRepositoryMatch` | N/A (Outside Scope) | N/A (Outside Scope) | Authenticated repo index match; does not prove file contents or CVE |
| **D3-23** | Kernel Module Loaded Match | Host runs `6.8.0-31-generic`. Package owns `/lib/modules/6.8.0-31-generic/kernel/net/wireguard.ko`. `/proc/modules` contains `wireguard` | `Affected` | `binary_match: true`, `VerifiedFileOwnership`, `LoadedInKernel` | `Confirmed` | `Active` | Active kernel module verified loaded via `/proc/modules` |
| **D3-24** | Kernel Headers Package | Host runs `6.8.0-31-generic`. Package `linux-headers-6.8.0-31-generic` owns `/usr/src/linux-headers-6.8.0-31-generic/` | `Affected` | `binary_match: true`, `VerifiedFileOwnership`, `Headers` | `Confirmed` | `InstalledInactive` | Headers are development artifacts; strictly `InstalledInactive` |
| **D3-25** | Provenance Without History | Package record verified against signed repository index, but `dpkg.log` historical installation source absent | N/A (Outside Scope) | `VerifiedRepositoryMatch` | N/A (Outside Scope) | N/A (Outside Scope) | Valid repo index match established without claiming historical origin |
| **D3-26** | Kernel Module Not Observed Loaded | Package `linux-modules-extra-6.8.0-31-generic` owns `/lib/modules/6.8.0-31-generic/kernel/extra/foo.ko`. Module `foo` absent from `/proc/modules` | `Affected` | `binary_match: true`, `VerifiedFileOwnership`, `NotObservedInKernel` | `Confirmed` | `Unknown` | Module not observed in inspected runtime interfaces; inactivity unproven |
| **D3-27** | Descriptive Non-Exhaustive Binary List | Advisory lists `libcurl4` descriptively (`Descriptive(["libcurl4"])`). Host has `curl` installed. Advisory feed does not guarantee exhaustiveness | `Inconclusive` | `source_match: true`, `Descriptive(["libcurl4"])` | `RequiresVerification` | `Unknown` | Omission from non-exhaustive list cannot yield `NotAffected` |

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
      - Execute 27 Dimension 3 package mapping and relationship test fixtures.
      - Benchmark accuracy and memory footprint against Trivy and OSV-Scanner.
      - Publish M3 Lab Evaluation & Benchmark Report.
```

This specification establishes a disciplined, scientifically defensible roadmap for Milestone M3, maintaining OpenAudit's reputation for transparency, honesty about uncertainty, and verifiable systems engineering.

