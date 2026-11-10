# OpenAudit Packaging, Distribution, and Runtime Independence Specification

**Document Version:** 1.1.0  
**Target Release:** OpenAudit v0.1.0-alpha.0  
**Specification Level:** Production Release Candidate Distribution  
**Minimum Supported Rust Version (MSRV):** 1.89.0  
**Embedded SQLite Engine:** SQLite 3.54.1 (`2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76`)  
**Operating Systems:** Linux (Ubuntu 22.04/24.04, Debian 12/13), macOS (Sonoma 14+, Sequoia 15+), Windows (11, Server 2022/2025)

---

## 1. Executive Summary: The Zero-Toolchain Guarantee

OpenAudit packages are engineered to be **completely self-contained production distributions**. End users, security auditors, compliance operators, and automated infrastructure agents can download, install, and execute OpenAudit without installing:
- **No Rust compiler (`rustc`) or Cargo**
- **No Node.js, npm, or JavaScript runtime**
- **No Python runtime or pip packages**
- **No C/C++ development headers or build tools (`gcc`, `clang`, `make`)**
- **No external DBMS services required for standalone or single-node operation (SQLite 3.54.1 is statically compiled and embedded; PostgreSQL 16+ is optionally supported for multi-tenant server deployments)**

### Core Acceptance Contract
> **Acceptance Criterion:** Take a pristine operating system installation with zero development toolchains present. Install OpenAudit via native package or unpack its portable archive, launch the CLI, execute a host security posture audit, and generate a self-contained HTML/JSON audit report. The workflow must execute completely and reliably with only documented OS prerequisites.

---

## 2. Platform Architecture & Binary Linking Matrix

OpenAudit achieves standalone runtime execution by minimizing dynamic dependencies to standard system libraries that are guaranteed to exist on clean OS installations.

| Platform | Distribution Format | Verified Target Architectures | Dynamic Linking Dependencies | Static Bundling Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Debian/Ubuntu)** | Native `.deb` Package (`arm64`, `amd64`) | `arm64` (Native Verified); `amd64` (Built & Container-Verified; Native CI on `ubuntu-24.04`) | `libc.so.6` (glibc $\ge 2.34$), `libm.so.6`, `libgcc_s.so.1` | SQLite 3.54.1 (bundled C amalgamation), Ring/Rustls (pure Rust crypto), all 43 rule definitions |
| **Linux (Universal)** | Portable `.tar.gz` (`aarch64`, `x86_64`) | `aarch64` (Native Verified); `x86_64` (Built & Container-Verified; Native CI on `ubuntu-24.04`) | `libc.so.6` (glibc $\ge 2.34$), `libm.so.6`, `libgcc_s.so.1` | Self-contained binaries (`openaudit`, `openaudit-cli`, `openaudit-agent`, `openaudit-server`), systemd units, udev rules |
| **macOS (Portable)** | Portable `.tar.gz` (`aarch64`, `x86_64`) | `aarch64` (Apple Silicon Native Verified); `x86_64` (Intel Mach-O Built & Verified via Rosetta 2) | `/usr/lib/libSystem.B.dylib`, `CoreFoundation.framework`, `Security.framework` | Mach-O 64-bit standalone binaries (`openaudit`, `openaudit-cli`, `openaudit-agent`, `openaudit-server`), embedded rules, launchd daemon plist |
| **macOS (Desktop GUI)** | Application Bundle `.zip` (`OpenAudit.app`) | `aarch64` (Apple Silicon Native Verified) | `AppKit.framework`, `WebKit.framework`, `CoreFoundation.framework`, `libSystem.B.dylib` | Native `WKWebView` desktop application (`openaudit-desktop`), embedded rules, local engine, `AppIcon.icns` |
| **Windows** | Portable `.zip` + Service Scripts (`x86_64`) | `x86_64` (PE32+ x86-64 Built & Verified; Native CI on `windows-latest`) | `KERNEL32.dll`, `ADVAPI32.dll`, `WS2_32.dll`, `NTDLL.dll`, `BCRYPT.dll` | Standalone `.exe` binaries (`openaudit.exe`, `openaudit-cli.exe`, `openaudit-agent.exe`, `openaudit-server.exe`), PowerShell service installer scripts |
| **Container Images** | Multi-stage Docker Images (`debian:12-slim`) | `linux/arm64`, `linux/amd64` | `libc.so.6` (Debian 12 glibc 2.36), `ca-certificates`, `curl` | `openaudit-server:0.1.0-alpha.0` (UID 10001) and `openaudit-agent:0.1.0-alpha.0` (UID 10002) |

---

## 3. Dependency Analysis: Honest Assessment (No False "Zero-Dependency" Claims)

We reject misleading claims of "zero dependencies." Running software on any operating system requires kernel interfaces, dynamic linkers, and system services. Below is the honest, exhaustive accounting of required operating-system components:

### A. Linux Unavoidable Prerequisites
1. **Kernel Version:** Linux kernel $\ge 5.15$ with `/proc` and `/sys` virtual filesystems mounted.
2. **C Runtime Library (glibc):**
   - **Empirical Symbol Inspection:** Inspection of both `aarch64` and `x86_64` release binaries built in `openaudit-ci:debian-12` using `objdump -T` / `readelf -V` confirms symbol references up to a maximum requirement of **`GLIBC_2.34`**.
   - **Supported Baseline:** Any Linux system providing `glibc >= 2.34` satisfies all dynamic symbol requirements. Distributions with older glibc ($< 2.34$, such as Debian 11 with glibc 2.31 or Ubuntu 20.04 with glibc 2.31) fail closed with dynamic linker symbol errors.
   - **Validated Distribution Matrix:**
     - **Ubuntu 24.04 LTS (Noble Numbat):** `glibc 2.39` (`arm64` & `amd64` verified)
     - **Ubuntu 22.04 LTS (Jammy Jellyfish):** `glibc 2.35` (`arm64` & `amd64` verified)
     - **Debian 12 (Bookworm):** `glibc 2.36` (`arm64` & `amd64` verified)
     - **Debian 13 (Trixie):** `glibc 2.41` (`arm64` & `amd64` verified)
3. **Execution Privileges:**
   - Standalone CLI unprivileged scan: Inspects user-accessible configurations, sysctl, environment, open sockets.
   - Privileged scan: Requires `root` or `sudo` to inspect `/etc/shadow`, `/etc/sudoers`, `/boot`, raw firewall rules (`iptables`/`nftables`), and privileged system accounts.
4. **Hardware Attestation (Agent / Server D4 Protocol):**
   - Physical TPM 2.0 device (`/dev/tpmrm0` or `/dev/tpm0`) or software TPM (`swtpm`) for monotonic counter synchronization and cryptographic transcript signing.

### B. macOS Unavoidable Prerequisites
1. **Operating System Version:** macOS 14.0 (Sonoma), macOS 15.0 (Sequoia), or newer. Legacy macOS ($< 14.0$) fails closed to prevent incorrect posture assumptions.
2. **System Libraries:** Standard macOS `libSystem.B.dylib`, `CoreFoundation.framework`, and `Security.framework` (pre-installed on all macOS systems). The CLI, agent, and server binaries remain strictly headless and never link `AppKit` or `WebKit`.
3. **Security Posture Independence (SIP):** System Integrity Protection (SIP) is an *audited posture check* (`macos.sip.disabled`), NOT a runtime prerequisite. OpenAudit executes cleanly whether SIP is enabled or disabled.
4. **Execution Privileges & Permissions:**
   - Terminal / binary Full Disk Access (FDA) in *System Settings $\rightarrow$ Privacy & Security* if auditing restricted user directories.
   - Root / Administrator (`sudo`) required for assessing FileVault status (`fdesetup`), directory services (`dscl`), and system launch daemons.

### C. Windows Unavoidable Prerequisites
1. **Operating System Version:** Windows 11 (build $\ge 22621$) or Windows Server 2022 / 2025. Legacy Windows ($< 10.0.22621$) fails closed.
2. **System Libraries:** Standard Win32 subsystems (`KERNEL32.dll`, `ADVAPI32.dll`, `WS2_32.dll`, `NTDLL.dll`, `BCRYPT.dll`).
3. **PowerShell:** PowerShell 5.1+ (included out-of-the-box in Windows 11 and Windows Server) for service management scripts (`install-service.ps1`, `uninstall-service.ps1`).
4. **Execution Privileges:** *Run as Administrator* (elevated UAC token) required for reading Windows Defender Firewall profiles, registry service configs under `HKLM`, and security event logs.

---

## 4. Native Installers & Portable Package Structure

### A. Debian / Ubuntu Native Packages (`openaudit_0.1.0-alpha.0_arm64.deb`, `openaudit_0.1.0-alpha.0_amd64.deb`)
The `.deb` packages install conformant filesystem hierarchies according to Debian Policy:
```text
/usr/bin/
├── openaudit             -> symlink to openaudit-cli
├── openaudit-cli         (standalone CLI binary)
├── openaudit-agent       (daemon binary)
└── openaudit-server      (control plane binary with embedded SQLite 3.54.1 + PostgreSQL support)

/lib/systemd/system/
├── openaudit-agent.service
└── openaudit-server.service

/lib/udev/rules.d/
└── 99-openaudit-tpm.rules

/usr/share/doc/openaudit/
├── copyright             (Apache-2.0 license)
└── README.md
```

### B. Linux Portable Archives (`openaudit-0.1.0-alpha.0-linux-aarch64.tar.gz`, `openaudit-0.1.0-alpha.0-linux-x86_64.tar.gz`)
Allows non-root or unprivileged installation anywhere on the system:
```text
stage-tar/
├── bin/
│   ├── openaudit         -> symlink to openaudit-cli
│   ├── openaudit-cli
│   ├── openaudit-agent
│   └── openaudit-server
├── lib/
│   ├── systemd/system/
│   └── udev/rules.d/
├── docs/
│   └── PACKAGING-AND-DISTRIBUTION.md
├── LICENSE
└── README.md
```

### C. macOS Portable Distributions (`openaudit-0.1.0-alpha.0-darwin-aarch64.tar.gz`, `openaudit-0.1.0-alpha.0-darwin-x86_64.tar.gz`)
Packaged with `COPYFILE_DISABLE=1` to guarantee zero AppleDouble (`._*`) metadata files:
```text
stage-tar/
├── bin/
│   ├── openaudit         -> symlink to openaudit-cli
│   ├── openaudit-cli
│   ├── openaudit-agent
│   └── openaudit-server
├── Library/LaunchDaemons/
│   └── com.openaudit.agent.plist
├── docs/
│   └── PACKAGING-AND-DISTRIBUTION.md
├── LICENSE
└── README.md
```

### D. Windows Portable Distribution (`openaudit-0.1.0-alpha.0-windows-x86_64.zip`)
```text
openaudit-0.1.0-alpha.0-windows-x86_64/
├── bin/
│   ├── openaudit.exe
│   ├── openaudit-cli.exe
│   ├── openaudit-agent.exe
│   └── openaudit-server.exe
├── scripts/
│   ├── install-service.ps1
│   └── uninstall-service.ps1
├── docs/
│   └── PACKAGING-AND-DISTRIBUTION.md
├── LICENSE
└── README.md
```

### E. macOS Desktop Application Bundle (`OpenAudit-0.1.0-alpha.0-macos-aarch64.zip`)
The native desktop GUI is packaged into a standard macOS application bundle (`OpenAudit.app`):
```text
OpenAudit.app/
└── Contents/
    ├── Info.plist              (Bundle ID: ke.co.mike.openaudit, LSMinimumSystemVersion: 14.0)
    ├── MacOS/
    │   └── openaudit-desktop   (Mach-O arm64 release binary, ad-hoc signed)
    └── Resources/
        └── AppIcon.icns        (Multi-resolution native icon)
```

---

## 5. Distribution Qualifications & Security Boundaries

We maintain an explicit, evidence-backed qualification record without overclaiming unperformed hardware or external validations:

1. **macOS Code Signing: Ad-Hoc vs. Developer ID & Apple Notarization:**
   - Current macOS builds (`OpenAudit.app` and CLI/server/agent binaries) are **ad-hoc signed** (`codesign --sign -`), which satisfies the Apple Silicon kernel requirement for local Mach-O execution.
   - Ad-hoc signatures **do NOT satisfy macOS Gatekeeper** for untrusted web downloads. External end-user distribution without quarantine prompts requires signing with an Apple `Developer ID Application` certificate (`--options runtime --timestamp`) and Apple Notary Service notarization (`xcrun notarytool submit` + `xcrun stapler staple`), which is wired in `scripts/package-macos-app.sh` via `MACOS_DEVELOPER_ID` and `MACOS_NOTARIZE=true` pending production certificate provisioning.

2. **Physical TPM 2.0 Hardware Qualification:**
   - The 4-state TPM 2.0 provisioning lifecycle, NV monotonic counter (`0x01500016`), and quarantine enforcement are verified against a live software TPM 2.0 emulator (`swtpm` over Unix domain socket) and unit-tested for character device transport (`/dev/tpmrm0`, `/dev/tpm0`).
   - Qualification against physical discrete or firmware TPM 2.0 hardware (`dTPM` / `fTPM`) on dedicated bare-metal Linux hosts remains an explicit hardware qualification item.

3. **Physical Power-Loss Qualification:**
   - Crash-consistency and fail-closed quarantine recovery for interrupted TPM/state provisioning are verified via deterministic fault injection and simulated mid-provisioning state corruption (`test_agent_swtpm_quarantine_enforcement`).
   - Physical power-cut testing across hardware NV writes and filesystem journaling on bare-metal appliances has not been performed and is not claimed.

4. **Independent External Security Assessment:**
   - OpenAudit has undergone internal security architecture hardening, frozen M2 subject-bound authority regression testing, SQLite `3.54.1` (`RUSTSEC-2026-0009`) remediation, and multi-tenant isolation verification.
   - An independent third-party cryptographic and penetration security audit has **not yet been conducted**.

5. **Single-Instance Control-Plane Scheduling Limitation:**
   - The `openaudit-server` background assessment and perimeter scheduler operates as an in-process loop designed for a **single active scheduler instance**.
   - While PostgreSQL storage supports concurrent multi-agent job claiming via `FOR UPDATE SKIP LOCKED`, deploying multiple active `openaudit-server` replicas with background scheduling enabled would require distributed leader election or database-backed schedule locking to prevent duplicate periodic job creation.

6. **Agent Authentication Model:**
   - OpenAudit currently includes two distinct agent communication paths:
     1. **M3 D4 Attestation & Outbox Protocol (`enroll-tls`, `retrieve-tls`):** Uses TPM-backed monotonic counters, 14-element canonical enrollment transcripts, 5-element 89-byte retrieval requests, and HMAC-SHA256 proofs over TLS 1.3.
     2. **M6 Outbound Polling Daemon (`daemon`, `poll-once`):** Uses one-time enrollment tokens (`token_id`, `token_secret`, `nonce`) exchanged over HTTPS to provision a persistent per-agent bearer credential (`auth_key` stored in `agent_credentials.json` with mode `0600`) and enforces tenant-scoped job claiming, revocation checks, and provenance recording.

---

## 6. Dependency Risk Review (`cargo audit`)

Running `cargo audit` against `Cargo.lock` reports **zero vulnerabilities** (`0 vulnerabilities found`), with 2 informational crate warnings in the lockfile:

| Advisory | Crate & Version | Warning Type | Dependency Path | Practical Runtime Exposure |
| :--- | :--- | :--- | :--- | :--- |
| `RUSTSEC-2024-0370` | `proc-macro-error 1.0.4` | `unmaintained` | `openaudit-desktop -> wry 0.57.1 -> gtk 0.18.2 -> glib 0.18.5 -> glib-macros 0.18.5 -> proc-macro-error 1.0.4` | **Zero.** `openaudit-desktop` only compiles `tao`/`wry` under `[target.'cfg(target_os = "macos")'.dependencies]`. On macOS, `wry` uses `objc2` / `WKWebView` and never compiles `gtk` or `glib-macros`. |
| `RUSTSEC-2024-0429` | `glib 0.18.5` | `unsound` (`VariantStrIter`) | `openaudit-desktop -> tao 0.37.2 / wry 0.57.1 -> gtk 0.18.2 -> glib 0.18.5` | **Zero.** Verified via `cargo tree --target aarch64-apple-darwin`, `x86_64-apple-darwin`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`, and `x86_64-pc-windows-msvc`: `glib` is not compiled or linked into any binary on any target platform. |

---

## 7. Measured Resource Benchmarks

Measurements were collected using the release binaries (`v0.1.0-alpha.0`) in a constrained Linux container environment (`--cpus="1.0" --memory="512m"`, Debian 12 Slim) and on the macOS Apple Silicon host (`./scripts/benchmark-cli.sh`):

| Metric | Environment | Configuration / Workload | Measured Value |
| :--- | :--- | :--- | :--- |
| **`openaudit-cli` Baseline Scan Latency** | Debian 12 (`1.0 vCPU`, `512 MB RAM`) | 5-run average (`20` active Linux rules evaluated) | **14.8 ms** (range: `10–27 ms`) |
| **`openaudit-cli` Hardened Scan Latency** | Debian 12 (`1.0 vCPU`, `512 MB RAM`) | 5-run average (`20` active Linux rules evaluated) | **12.4 ms** (range: `10–14 ms`) |
| **`openaudit-cli` Baseline Scan Latency** | macOS 27.2 (`Apple M1 Pro`) | 5-run average (`9` active macOS rules evaluated) | **453 ms** (range: `347–496 ms`) |
| **`openaudit-cli` Hardened Scan Latency** | macOS 27.2 (`Apple M1 Pro`) | 5-run average (`11` active macOS rules evaluated) | **350 ms** (range: `329–397 ms`) |
| **`openaudit-server` Idle Memory (`VmRSS`)** | Debian 12 (`1.0 vCPU`, `512 MB RAM`) | Control plane active with SQLite backend (2 threads) | **8,176 kB (~8.0 MB)** |
| **`openaudit-agent` Idle Memory (`VmRSS`)** | Debian 12 (`1.0 vCPU`, `512 MB RAM`) | Outbound polling daemon active (1 thread) | **4,124 kB (~4.0 MB)** |
| **SQLite Control-Plane Storage Footprint** | Debian 12 (`1.0 vCPU`, `512 MB RAM`) | Bootstrapped schema + migrations (`control_plane.db`) | **184 KB** (JSON scan payload: **15.0 KB** / scan) |

---

## 8. Clean-Environment Acceptance Testing Evidence

To guarantee true toolchain independence, tests were executed using pristine Docker containers with **zero developer toolchains** installed (`./scripts/test-clean-install.sh` and multi-arch verification):

| Target OS | Clean Base Image | GLIBC Version | Architecture | Package Installed | Audit & HTML Report | Clean Purge (`dpkg -P`) | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Ubuntu 24.04 LTS** | `ubuntu:24.04` | `2.39` | `arm64` & `amd64` | `openaudit_0.1.0-alpha.0_{arm64,amd64}.deb` | PASSED (5 findings, valid HTML) | Verified | **PASSED** |
| **Ubuntu 22.04 LTS** | `ubuntu:22.04` | `2.35` | `arm64` & `amd64` | `openaudit_0.1.0-alpha.0_{arm64,amd64}.deb` | PASSED (4 findings, valid HTML) | Verified | **PASSED** |
| **Debian 12 Slim** | `debian:12-slim` | `2.36` | `arm64` & `amd64` | `openaudit_0.1.0-alpha.0_{arm64,amd64}.deb` | PASSED (4 findings, valid HTML) | Verified | **PASSED** |
| **Debian 13 Slim** | `debian:trixie-slim` | `2.41` | `arm64` & `amd64` | `openaudit_0.1.0-alpha.0_{arm64,amd64}.deb` | PASSED (4 findings, valid HTML) | Verified | **PASSED** |
| **macOS (Apple Silicon)** | Host Darwin (`arm64`) | `libSystem.B` | `aarch64` & `x86_64` | `openaudit-0.1.0-alpha.0-darwin-{aarch64,x86_64}.tar.gz` | PASSED (valid HTML) | Verified | **PASSED** |

---

## 9. Automated Release Pipeline (GitHub Actions)

Reproducible releases are built via `.github/workflows/release.yml` (manual `workflow_dispatch` gate):
1. **Linux x86_64 Build (`package-linux`):** Runs on `ubuntu-24.04`, builds in `openaudit-ci:debian-12` (`glibc 2.36` baseline, max symbol `GLIBC_2.34`), and runs `./scripts/test-clean-install.sh`.
2. **Linux ARM64 Build (`package-linux-arm64`):** Runs natively on `ubuntu-24.04-arm`, builds in `openaudit-ci:debian-12`, and runs `./scripts/test-clean-install.sh`.
3. **macOS Build (`package-macos`):** Runs on `macos-latest`, builds standalone Mach-O binaries and `OpenAudit.app`, and verifies CLI execution and HTML report generation.
4. **Windows Build (`package-windows`):** Runs on `windows-latest`, compiles standalone PE64 executables, bundles PowerShell service scripts, tests Windows Service lifecycle, and compresses into `.zip` distribution.
