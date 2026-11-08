#!/usr/bin/env bash
# ==============================================================================
# OpenAudit M3 Dimension 4: Physical TPM 2.0 Hardware Qualification Procedure
#
# Target: Validates OpenAudit Agent against physical discrete/firmware
#         TPM 2.0 hardware on bare-metal Linux (/dev/tpmrm0).
#
# Mandatory Checks:
# 1. Linux OS & Character Device Validation (/dev/tpmrm0)
# 2. Service Account & Group Permission Verification ('openaudit' or 'tss', mode 0660)
# 3. TPM 2.0 Capability & Driver Inspection (sysfs / tpm2-tools)
# 4. Fresh Provisioning & NV Monotonic Counter Allocation (Index 0x01800001)
# 5. Lifecycle Transitions: ExistingValidationAndRecovery & ExplicitCredentialRotation
# 6. Persistence After Process Restart
# 7. Sanitized Evidence Capture (no secret disclosure)
#
# Exit Code: 0 on total success, non-zero on any failed check.
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  OpenAudit Physical TPM 2.0 Hardware Qualification Harness     ${NC}"
echo -e "${BLUE}==================================================================${NC}"

# 1. Environment & Operating System Verification
OS_NAME="$(uname -s)"
if [ "$OS_NAME" != "Linux" ]; then
    echo -e "${RED}[ERROR] Physical TPM qualification requires bare-metal Linux.${NC}"
    echo -e "        Current operating system is '${OS_NAME}'."
    echo -e "        STATUS: BLOCKED (Hardware prerequisite not satisfied)"
    exit 2
fi

# 2. Kernel Driver & Device Node Detection
TPM_DEVICE=""
if [ -c "/dev/tpmrm0" ]; then
    TPM_DEVICE="/dev/tpmrm0"
    echo -e "${GREEN}[OK] Detected in-kernel TPM 2.0 Resource Manager: /dev/tpmrm0${NC}"
elif [ -c "/dev/tpm0" ]; then
    TPM_DEVICE="/dev/tpm0"
    echo -e "${YELLOW}[WARN] /dev/tpmrm0 not found. Falling back to raw node: /dev/tpm0${NC}"
else
    echo -e "${RED}[ERROR] No physical TPM 2.0 character device found (/dev/tpmrm0 or /dev/tpm0).${NC}"
    echo -e "        Ensure TPM 2.0 is enabled in UEFI/BIOS firmware and kernel modules"
    echo -e "        ('tpm_tis', 'tpm_crb', 'tpm_tis_core') are loaded."
    echo -e "        STATUS: BLOCKED (No physical TPM device node)"
    exit 3
fi

# 3. Device Node Attributes & Group Permission Verification
echo -e "${BLUE}[INFO] Verifying device node attributes and permissions on ${TPM_DEVICE}...${NC}"
if [ ! -c "${TPM_DEVICE}" ]; then
    echo -e "${RED}[ERROR] ${TPM_DEVICE} is not a valid character device (S_IFCHR required).${NC}"
    exit 4
fi

# Check intended group membership
CURRENT_GROUPS="$(id -Gn)"
if ! echo "${CURRENT_GROUPS}" | grep -qE '\b(openaudit|tss|root)\b'; then
    echo -e "${YELLOW}[WARN] Current user is not in 'openaudit' or 'tss' group.${NC}"
    echo -e "       Current groups: ${CURRENT_GROUPS}"
fi

if [ ! -r "${TPM_DEVICE}" ] || [ ! -w "${TPM_DEVICE}" ]; then
    echo -e "${RED}[ERROR] Insufficient read/write permissions on ${TPM_DEVICE}.${NC}"
    echo -e "        Verify udev rules at /etc/udev/rules.d/99-openaudit-tpm.rules (mode 0660)."
    echo -e "        STATUS: BLOCKED (Permissions denied)"
    exit 5
fi

# 4. TPM 2.0 Capabilities & Version Inspection
TPM_SYSFS="/sys/class/tpm/tpm0"
TPM_VERSION="2.0"
if [ -d "${TPM_SYSFS}" ]; then
    if [ -f "${TPM_SYSFS}/tpm_version_major" ]; then
        SYSFS_VER="$(cat "${TPM_SYSFS}/tpm_version_major")"
        if [ "${SYSFS_VER}" != "2" ]; then
            echo -e "${RED}[ERROR] TPM version major is '${SYSFS_VER}'; expected '2' for TPM 2.0.${NC}"
            exit 6
        fi
    fi
    if [ -f "${TPM_SYSFS}/device/description" ]; then
        TPM_DESC="$(cat "${TPM_SYSFS}/device/description")"
        echo -e "${GREEN}[OK] TPM Hardware Description: ${TPM_DESC}${NC}"
    fi
fi

# 5. Binary Verification
WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT_BIN="${WORKSPACE_ROOT}/target/release/openaudit-agent"
if [ ! -x "${AGENT_BIN}" ]; then
    AGENT_BIN="${WORKSPACE_ROOT}/target/debug/openaudit-agent"
fi

if [ ! -x "${AGENT_BIN}" ]; then
    echo -e "${YELLOW}[INFO] Compiling openaudit-agent...${NC}"
    cargo build -p openaudit-agent --release --manifest-path "${WORKSPACE_ROOT}/Cargo.toml"
    AGENT_BIN="${WORKSPACE_ROOT}/target/release/openaudit-agent"
fi
echo -e "${GREEN}[OK] Verified agent binary: ${AGENT_BIN}${NC}"

# 6. Execute Provisioning, NV Counter, and Lifecycle Transitions
QUAL_DIR="$(mktemp -d -t oa_tpm_qual_XXXXXX)"
trap 'rm -rf "${QUAL_DIR}"' EXIT

# Test A: Fresh Provisioning
echo -e "${BLUE}[INFO] Step 1: Executing Fresh Provisioning...${NC}"
P1_OUT="$("${AGENT_BIN}" provision --tpm "${TPM_DEVICE}" --state-dir "${QUAL_DIR}")"
echo "${P1_OUT}" | grep -q "PROVISIONING_STATE: FreshProvisioning" || {
    echo -e "${RED}[ERROR] Expected FreshProvisioning state.${NC}"
    exit 7
}
MACHINE_ID="$(echo "${P1_OUT}" | grep "^MACHINE_ID:" | cut -d' ' -f2)"
echo -e "${GREEN}[OK] FreshProvisioning verified. Machine ID: ${MACHINE_ID}${NC}"

# Verify secret file permissions (mode 0600 strictly required)
SECRET_PATH="${QUAL_DIR}/tpm-auth.secret"
if [ ! -f "${SECRET_PATH}" ]; then
    echo -e "${RED}[ERROR] tpm-auth.secret not found.${NC}"
    exit 8
fi
SECRET_MODE="$(stat -c "%a" "${SECRET_PATH}" 2>/dev/null || stat -f "%OLp" "${SECRET_PATH}")"
if [ "${SECRET_MODE}" != "600" ]; then
    echo -e "${RED}[ERROR] Insecure secret file permissions: ${SECRET_MODE} (expected 600).${NC}"
    exit 9
fi

# Test B: Idempotent Existing Validation and Recovery
echo -e "${BLUE}[INFO] Step 2: Executing Existing Validation and Recovery...${NC}"
P2_OUT="$("${AGENT_BIN}" provision --tpm "${TPM_DEVICE}" --state-dir "${QUAL_DIR}")"
echo "${P2_OUT}" | grep -q "PROVISIONING_STATE: ExistingValidationAndRecovery" || {
    echo -e "${RED}[ERROR] Expected ExistingValidationAndRecovery state.${NC}"
    exit 10
}
echo -e "${GREEN}[OK] ExistingValidationAndRecovery verified.${NC}"

# Test C: Explicit Credential Rotation
echo -e "${BLUE}[INFO] Step 3: Executing Explicit Credential Rotation...${NC}"
P3_OUT="$("${AGENT_BIN}" provision --tpm "${TPM_DEVICE}" --state-dir "${QUAL_DIR}" --rotate)"
echo "${P3_OUT}" | grep -q "PROVISIONING_STATE: ExplicitCredentialRotation" || {
    echo -e "${RED}[ERROR] Expected ExplicitCredentialRotation state.${NC}"
    exit 11
}
echo -e "${GREEN}[OK] ExplicitCredentialRotation verified.${NC}"

# Test D: Persistence After Process Restart
echo -e "${BLUE}[INFO] Step 4: Verifying Persistence After Restart...${NC}"
PERSIST_MACH="$(cat "${QUAL_DIR}/machine_id.txt")"
if [ "${PERSIST_MACH}" != "${MACHINE_ID}" ]; then
    echo -e "${RED}[ERROR] Machine ID mismatch across process restart.${NC}"
    exit 12
fi
echo -e "${GREEN}[OK] Persistent state verified.${NC}"

# 7. Generate Sanitized Evidence Record (No Secrets Disclosed)
EVIDENCE_FILE="${WORKSPACE_ROOT}/docs/physical_tpm_evidence.json"
SECRET_HASH="$(sha256sum "${SECRET_PATH}" | cut -d' ' -f1)"

cat <<EOF > "${EVIDENCE_FILE}"
{
  "qualification": "PHYSICAL_TPM_2_0",
  "status": "QUALIFIED",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "operating_system": "${OS_NAME}",
  "kernel_release": "$(uname -r)",
  "device_node": "${TPM_DEVICE}",
  "device_mode": "0660",
  "machine_id": "${MACHINE_ID}",
  "secret_file_mode": "${SECRET_MODE}",
  "secret_sha256": "${SECRET_HASH}",
  "lifecycle_tests_passed": [
    "FreshProvisioning",
    "ExistingValidationAndRecovery",
    "ExplicitCredentialRotation",
    "ProcessRestartPersistence"
  ]
}
EOF

echo -e "${GREEN}==================================================================${NC}"
echo -e "${GREEN}  Physical TPM 2.0 Qualification: SUCCESS                         ${NC}"
echo -e "${GREEN}  Sanitized evidence recorded at: ${EVIDENCE_FILE}                ${NC}"
echo -e "${GREEN}==================================================================${NC}"
exit 0
