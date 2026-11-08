# OpenAudit CLI Contracts & Automation Specification

**Document Version:** 1.0.0  
**Milestone:** M3 - Cross-Platform Auditing & Validation  
**Phase:** M3.1 - First-Class Terminal Product Interface  
**Status:** Approved & Implemented

---

## 1. Overview

`openaudit-cli` is a permanent, first-class interface to the OpenAudit security platform. It is engineered for headless servers, automation scripts, continuous integration pipelines, and remote SSH administration without requiring any graphical display or background desktop daemon.

---

## 2. Command Synopsis & Usage

```bash
openaudit-cli <COMMAND> [OPTIONS]
```

### 2.1 Available Commands

| Command | Subcommand | Description |
| :--- | :--- | :--- |
| `scan` | `[local]` | Executes a read-only security audit of the local host. |
| `audit` | `local` | Backward-compatible alias for `scan` conforming to M2 contract. |
| `system` | `info` | Displays detected host platform metadata, kernel, architecture, and audit capabilities. |
| `rules` | `list` | Lists all available security rules with severity, privilege, and supported platforms. |
| `report` | — | Generates or renders host security posture reports in human, JSON, or HTML format. |
| `version` | — | Outputs the OpenAudit version string. |
| `help` | — | Displays usage information and flag reference. |

---

## 3. Options & Arguments

| Flag | Parameter | Default | Description |
| :--- | :--- | :--- | :--- |
| `--profile` | `baseline \| full \| hardened` | `baseline` | Selects the rule evaluation profile. |
| `--format` | `human \| json \| html` | `human` | Output rendering format. |
| `--min-severity` | `info \| low \| medium \| high \| critical` | `info` | Minimum severity threshold for displayed findings. |
| `--fail-on` | `info \| low \| medium \| high \| critical` | None | Terminates with exit code `2` if findings meeting or exceeding threshold exist. |
| `--strict` | — | False | Convenience alias for `--fail-on high`. |
| `--help`, `-h` | — | — | Displays command help. |
| `--version`, `-v`| — | — | Displays version. |

---

## 4. Exit Code Semantics

The CLI guarantees deterministic exit codes for automation and CI/CD pipelines:

| Exit Code | Identifier | Meaning |
| :---: | :--- | :--- |
| **`0`** | `SUCCESS` | Audit executed successfully and no findings exceed the `--fail-on` threshold. |
| **`1`** | `FAILURE` | Operational failure: invalid CLI arguments, platform error, or I/O failure. |
| **`2`** | `FINDINGS_DETECTED` | Policy failure: security violations detected at or above `--fail-on` / `--strict` threshold. |

---

## 5. Output Formats

### 5.1 Human-Readable Terminal Output (`--format human`)
Produces clean, monochromatic ANSI-compatible text with clear severity markers:

```text
OpenAudit Host Security Audit v0.1.0-alpha.0
Host: Ubuntu 24.04 LTS (6.8.0-45-generic x86_64)
Execution Privilege: Unprivileged

[!] 1 Security Findings Detected (0 Critical, 1 High, 0 Medium, 0 Low, 0 Info)

HIGH      linux.ssh.permit-root-login
  Target:      /etc/ssh/sshd_config:PermitRootLogin
  Title:       SSH Daemon Permits Root Login
  Description: Direct remote SSH access as the root superuser is permitted.
  Remediation: Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.
  Evidence:    PermitRootLogin yes

--------------------------------------------------------------------------------
Scan Summary: 0 Critical, 1 High, 0 Medium, 0 Low, 0 Info | Total: 1
Execution Time: 12ms | Status: Completed
```

### 5.2 Machine-Readable JSON Output (`--format json`)
Outputs a single, strictly valid JSON object matching `AuditReport` schema. Suitable for piping to `jq`, feeding into SIEM/SOAR platforms, or archiving.

### 5.3 Standalone HTML Report (`--format html`)
Generates an all-in-one HTML document with embedded styles, zero external network dependencies, high-contrast dark theme, and accessible typography.

---

## 6. Automation & CI/CD Examples

### GitHub Actions / GitLab CI Step:
```bash
# Fail pipeline if any HIGH or CRITICAL misconfigurations exist:
openaudit-cli scan --profile baseline --strict
```

### Headless Server Inspection over SSH:
```bash
ssh admin@vps.internal "openaudit-cli scan --format json" | jq '.findings[] | {rule: .finding.rule_id, severity: .finding.severity}'
```

### Diagnostics Collection:
```bash
openaudit-cli system info --format json > /var/log/openaudit-diagnostics.json
```

