# OpenAudit Packaging, Distribution, and Runtime Independence Specification

**Document Version:** 1.0.0  
**Target Release:** OpenAudit v0.1.0-alpha.0  
**Specification Level:** Production Release Distribution  
**Operating Systems:** Linux (Ubuntu, Debian), macOS (Sonoma, Sequoia), Windows (11, Server 2022/2025)

---

## 1. Executive Summary: The Zero-Toolchain Guarantee

OpenAudit packages are engineered to be **completely self-contained production distributions**. End users, security auditors, compliance operators, and automated infrastructure agents can download, install, and execute OpenAudit without installing:
- **No Rust compiler (`rustc`) or Cargo**
- **No Node.js, npm, or JavaScript runtime**
- **No Python runtime or pip packages**
- **No C/C++ development headers or build tools (`gcc`, `clang`, `make`)**
- **No external DBMS services (SQLite is statically compiled and embedded)**

### Core Acceptance Contract
> **Acceptance Criterion:** Take a pristine operating system installation with zero development toolchains present. Install OpenAudit via native package or unpack its portable archive, launch the CLI, execute a host security posture audit, and generate a self-contained HTML/JSON audit report. The workflow must execute completely and reliably with only documented OS prerequisites.

---

## 2. Platform Architecture & Binary Linking Matrix

OpenAudit achieves standalone runtime execution by minimizing dynamic dependencies to standard system libraries that are guaranteed to exist on clean OS installations.

| Platform | Distribution Format | Primary Target Architecture | Dynamic Linking Dependencies | Static Bundling Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Linux (Debian/Ubuntu)** | Native `.deb` Package | `amd64`, `arm64` | `libc.so.6` (glibc $\ge 2.34$), `libm.so.6`, `libgcc_s.so.1` | SQLite (bundled C amalgamation), Ring/Rustls (pure Rust crypto), all rule definitions |
| **Linux (Universal)** | Portable `.tar.gz` | `x86_64`, `aarch64` | `libc.so.6` (glibc $\ge 2.34$), `libm.so.6`, `libgcc_s.so.1` | Self-contained binaries (`openaudit`, `openaudit-agent`, `openaudit-server`), systemd units, udev rules |
| **macOS** | Portable `.tar.gz` / Bundle | `aarch64` (Apple Silicon; Intel x86_64 unverified) | `/usr/lib/libSystem.B.dylib`, `CoreFoundation.framework`, `libiconv.2.dylib` | Mach-O standalone binary, embedded rules, launchd daemon plist |
| **Windows** | Portable `.zip` / Service Installer | `x86_64` (PE64) | `KERNEL32.dll`, `ADVAPI32.dll`, `WS2_32.dll`, `NTDLL.dll` | Standalone `.exe` binaries, embedded rules, PowerShell service installer scripts |

---

## 3. Dependency Analysis: Honest Assessment (No False "Zero-Dependency" Claims)

We reject misleading claims of "zero dependencies." Running software on any operating system requires kernel interfaces, dynamic linkers, and system services. Below is the honest, exhaustive accounting of required operating-system components:

### A. Linux Unavoidable Prerequisites
1. **Kernel Version:** Linux kernel $\ge 5.15$ with `/proc` and `/sys` virtual filesystems mounted.
2. **C Runtime Library:** `glibc` with symbols up to `GLIBC_2.34` (verified via `objdump -p` on Debian 12 release binaries).
   - *Validated Distribution Matrix:* Debian 12 (Bookworm, glibc 2.36), Debian 13 (Trixie, glibc 2.40+), and Ubuntu 24.04 (Noble, glibc 2.39).
   - *Compatibility Boundary:* Ubuntu 22.04 (Jammy, glibc 2.35) remains unvalidated and is not included in the supported distribution matrix until explicitly tested against clean environments.
3. **Execution Privileges:**
   - Standalone CLI unprivileged scan: Inspects user-accessible configurations, sysctl, environment, open sockets.
   - Privileged scan: Requires `root` or `sudo` to inspect `/etc/shadow`, `/etc/sudoers`, `/boot`, raw firewall rules (`iptables`/`nftables`), and privileged system accounts.
4. **Hardware Attestation (Agent / Server only):**
   - Physical TPM 2.0 device (`/dev/tpmrm0` or `/dev/tpm0`) or software TPM (`swtpm`) for monotonic counter synchronization and cryptographic transcript signing.

### B. macOS Unavoidable Prerequisites
1. **Operating System Version:** macOS 14.0 (Sonoma), macOS 15.0 (Sequoia), or newer. Legacy macOS ($< 14.0$) fails closed to prevent incorrect posture assumptions.
2. **System Libraries:** Standard macOS `libSystem.B.dylib` and `CoreFoundation.framework` (pre-installed on all macOS devices).
3. **Security Posture Independence (SIP):** System Integrity Protection (SIP) is an *audited posture check* (`macos.sip.disabled`), NOT a runtime prerequisite. OpenAudit executes cleanly whether SIP is enabled or disabled.
4. **Execution Privileges & Permissions:**
   - Terminal / binary Full Disk Access (FDA) in *System Settings $\rightarrow$ Privacy & Security* if auditing restricted user directories.
   - Root / Administrator (`sudo`) required for assessing FileVault status (`fdesetup`), directory services (`dscl`), and system launch daemons.

### C. Windows Unavoidable Prerequisites
1. **Operating System Version:** Windows 11 (build $\ge 22621$) or Windows Server 2022 / 2025. Legacy Windows ($< 10.0.22621$) fails closed.
2. **System Libraries:** Standard Win32 subsystems (`kernel32.dll`, `advapi32.dll`, `ws2_32.dll`).
3. **PowerShell:** PowerShell 5.1+ (included out-of-the-box in Windows 11 and Windows Server) for service management scripts.
4. **Execution Privileges:** *Run as Administrator* (elevated UAC token) required for reading Windows Defender Firewall profiles, registry service configs under `HKLM`, and security event logs.

---

## 4. Native Installers & Portable Package Structure

### A. Debian / Ubuntu Native Package (`openaudit_0.1.0-alpha.0_arm64.deb`)
The `.deb` package installs conformant filesystem hierarchies according to Debian Policy:
```text
/usr/bin/
├── openaudit             -> symlink to openaudit-cli
├── openaudit-cli         (3.6 MB standalone CLI binary)
├── openaudit-agent       (3.9 MB daemon binary)
└── openaudit-server      (4.1 MB control plane binary)

/lib/systemd/system/
├── openaudit-agent.service
└── openaudit-server.service

/lib/udev/rules.d/
└── 99-openaudit-tpm.rules

/usr/share/doc/openaudit/
├── copyright             (Apache-2.0 license)
└── README.md
```

### B. Portable Archive (`openaudit-0.1.0-alpha.0-linux-aarch64.tar.gz`)
Allows non-root or unprivileged installation anywhere on the system:
```text
openaudit-0.1.0-alpha.0-linux-aarch64/
├── bin/
│   ├── openaudit
│   ├── openaudit-cli
│   ├── openaudit-agent
│   └── openaudit-server
├── lib/
│   ├── systemd/system/
│   └── udev/rules.d/
├── docs/
├── LICENSE
└── README.md
```

### C. macOS Portable Distribution (`openaudit-0.1.0-alpha.0-darwin-aarch64.tar.gz`)
```text
openaudit-0.1.0-alpha.0-darwin-aarch64/
├── bin/
│   ├── openaudit
│   ├── openaudit-cli
│   └── openaudit-agent
├── Library/LaunchDaemons/
│   └── com.openaudit.agent.plist
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
├── LICENSE
└── README.md
```

### E. macOS Application Bundle (`OpenAudit.app`)
The native desktop GUI is packaged into a standard macOS application bundle:
```text
OpenAudit.app/
└── Contents/
    ├── Info.plist              (Bundle ID: ke.co.mike.openaudit, LSMinimumSystemVersion: 14.0)
    ├── MacOS/
    │   └── openaudit-desktop   (Mach-O arm64 release binary)
    └── Resources/
        └── AppIcon.icns        (Multi-resolution native icon)
```

---

## 5. macOS Code Signing, Gatekeeper & Notarization Realities

We maintain an honest, truthful engineering standard regarding macOS security boundaries:

1. **Locally Executable & Ad-Hoc Signed Development Builds:**
   - Apple Silicon kernels require Mach-O binaries to possess valid code directory hashes to launch (`codesign --sign -`). Without ad-hoc signatures, ARM64 kernels terminate the process immediately.
   - Ad-hoc signing enables **local developer execution** without requiring paid certificates or network access.
   - *Limitation:* Ad-hoc signatures **do NOT satisfy macOS Gatekeeper** for untrusted external distribution. Users downloading an ad-hoc signed app from the web will receive a quarantine block ("Apple could not verify this app").

2. **External Distribution Readiness (Developer ID + Notarization):**
   - Normal distribution to end-users without quarantine warnings requires:
     1. An active Apple Developer Program membership.
     2. Code signing using a valid `Developer ID Application` certificate with secure timestamping (`--options runtime --timestamp`).
     3. Submitting the package to Apple's Notary Service (`xcrun notarytool submit --wait`).
     4. Attaching the cryptographic ticket to the bundle (`xcrun stapler staple OpenAudit.app`).
   - *OpenAudit Status:* Current local builds are ad-hoc signed for developer execution on Apple Silicon. Developer ID signing and Apple notarization are supported in `scripts/package-macos-app.sh` (via `MACOS_DEVELOPER_ID` and `MACOS_NOTARIZE=true`), but are NOT claimed as completed until production release keys are provisioned.

---

## 5. Strict Independence of CLI Operation

The OpenAudit CLI (`openaudit-cli` / `openaudit`) is **strictly independent** of the OpenAudit web server, control plane, background daemon, and desktop GUI:
1. **Zero RPC / Zero Network Requirement:** The CLI directly embeds the `openaudit-engine` audit rules and platform collectors. It evaluates local host posture in-process.
2. **In-Memory Rule Engine:** All 43 platform rules (20 Linux, 12 Windows, 11 macOS) are compiled into the binary.
3. **Self-Contained Report Generation:**
   - **Human Console Output:** Colored, ANSI-formatted console summaries.
   - **JSON Output:** Structured machine-readable JSON matching the OpenAudit AuditReport data model.
   - **HTML Output:** Completely self-contained, inline CSS/HTML documents rendered with zero CDN dependencies, zero external fonts, and zero client-side scripts.

---

## 6. Clean-Environment Acceptance Testing Evidence

To guarantee true toolchain independence, tests were executed using pristine Docker containers with **zero developer toolchains** installed.

### Test Matrix & Verification Commands
```bash
./scripts/test-clean-install.sh
```

### Results Summary

| Target OS | Clean Base Image | Dev Toolchain Check (`rustc`, `node`, `gcc`) | Package Installed | Audit Execution | HTML Report Generated | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Ubuntu 24.04 LTS** | `ubuntu:24.04` (fe81560990fa) | Confirmed Absent (exit $\ne 0$) | `openaudit_0.1.0-alpha.0_arm64.deb` | PASSED (5 findings, 15ms) | Valid HTML, 1.2 KB | **PASSED** |
| **Debian 12 Slim** | `debian:12-slim` (734a72b3d614) | Confirmed Absent (exit $\ne 0$) | `openaudit_0.1.0-alpha.0_arm64.deb` | PASSED (4 findings, 12ms) | Valid HTML, 1.1 KB | **PASSED** |
| **Debian 13 Slim** | `debian:trixie-slim` (a72b4433de1c) | Confirmed Absent (exit $\ne 0$) | `openaudit_0.1.0-alpha.0_arm64.deb` | PASSED (4 findings, 11ms) | Valid HTML, 1.1 KB | **PASSED** |
| **macOS 27.2** | macOS Host (Darwin 27.2.0) | Clean sandbox execution | `openaudit-*-darwin-aarch64.tar.gz` | PASSED (0 findings, 256ms) | Valid HTML, 1.1 KB | **PASSED** |

### Verified Integrity Manifest (`SHA256SUMS`)
```text
2b9a3a76c612784caf18f64e02c2564c0778422c154cb411f2413f639df4ee78  openaudit_0.1.0-alpha.0_arm64.deb
10136311fbd9ac91e45a041bb2120e5541e0583c0278441acc074e41846e59d5  openaudit-0.1.0-alpha.0-darwin-aarch64.tar.gz
3bd29c84ea1f98a99b8a1fc7bb0b5ea4c4688efa216f043131d746b24d92a7d4  openaudit-0.1.0-alpha.0-linux-aarch64.tar.gz
```

---

## 7. Automated Release Pipeline (GitHub Actions)

Reproducible releases are built automatically via `.github/workflows/release.yml`:
1. **Linux Build (`package-linux`):** Uses the `openaudit-ci:debian-12` container to guarantee glibc 2.36 compatibility across all modern Linux distributions. Runs `./scripts/test-clean-install.sh` on pristine Ubuntu and Debian before artifact publication.
2. **macOS Build (`package-macos`):** Executes on `macos-14`, builds standalone Mach-O binaries, packages `.tar.gz`, and verifies execution and report generation.
3. **Windows Build (`package-windows`):** Executes on `windows-latest`, compiles standalone PE64 executables, bundles PowerShell service scripts, and compresses into `.zip` distribution.

