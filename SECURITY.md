# Security Policy

OpenAudit is dedicated to building secure, transparent, and trustworthy infrastructure auditing software. We treat security reports with the highest priority.

## Supported Versions

OpenAudit is currently in active early development (**Milestone M0: Foundation**).

| Version | Status | Security Updates |
|---|---|---|
| `main` (pre-alpha) | Active development | Best-effort security fixes |
| < 0.1.0 | Unreleased | Not applicable |

Official security support policies and release version pinning will take effect upon the `v0.1.0-alpha` public release.

## Reporting a Security Vulnerability

If you discover a potential vulnerability or security issue within OpenAudit (including in the agent, control plane, rules engine, or distribution packages), please do **NOT** open a public issue, pull request, or discussion.

Instead, please report it via private disclosure:

1. **Email:** Send details to `security@openaudit.org` or contact the lead maintainer directly at `kipmyk@gmail.com`.
2. **Subject:** Use the subject prefix `[SECURITY VULNERABILITY] OpenAudit: <brief summary>`.
3. **Information to Include:**
   - Affected component(s) (`server`, `agent`, `cli`, `engine`, `core`).
   - Detailed description of the vulnerability and attack vector.
   - Proof of Concept (PoC) code, curl requests, or reproduction steps.
   - Potential impact (e.g., SSRF, privilege escalation, credential leakage, denial of service).
   - Any proposed remediations or patches if available.

## Response SLA and Coordination Timeline

When a report is received:

1. **Initial Acknowledgment:** Within **48 hours**, confirming receipt and an initial triage assessment.
2. **Status Updates:** Regular updates every **72 hours** while the issue is being investigated, validated, and patched.
3. **Fix and Disclosure:**
   - We aim to develop, test, and release a patched version within **14 days** of confirmation for critical issues.
   - We request a mutual **90-day coordinated disclosure embargo** (or until a release is published) before any public announcement.
   - Full credit will be attributed to the reporter in release notes and security advisories (unless requested to remain anonymous).

## Fundamental Security Guarantees & Non-Goals

### Guarantees
- **Read-Only Inspection:** OpenAudit's local and agent inspection engines operate strictly read-only. They never mutate host configuration, services, or firewalls.
- **No Arbitrary Remote Execution:** The agent never accepts or executes arbitrary remote shell commands.
- **SSRF Defense:** Agentless network inspections block private, loopback, and cloud metadata IP ranges by default, revalidating IP targets on every redirect.
- **Data Minimization:** Sensitive strings (passwords, private keys, authentication tokens) detected in audit evidence are redacted prior to persistence.

### Non-Goals
- OpenAudit is not a generic internet port scanner and should not be used as an open-ended reconnaissance tool against third-party networks.
- OpenAudit does not provide real-time kernel-level intrusion prevention (IPS) or automated exploit blocking; it is a posture auditing and drift monitoring platform.
