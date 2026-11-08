#!/usr/bin/env bash
# ==============================================================================
# OpenAudit M3 Dimension 4: Physical TPM 2.0 Qualification Procedure
#
# Target: Validates OpenAudit Agent & Authority against physical discrete/firmware
#         TPM 2.0 hardware on bare-metal Linux (/dev/tpmrm0 or /dev/tpm0).
#
# NOTE: This script is intended strictly for physical Linux hardware environments.
#       Software emulators (such as swtpm) must NOT be passed to this script.
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  OpenAudit Physical TPM 2.0 Qualification Harness               ${NC}"
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
    echo -e "${YELLOW}[WARN] /dev/tpmrm0 not found. Falling back to direct raw node: /dev/tpm0${NC}"
else
    echo -e "${RED}[ERROR] No physical TPM 2.0 character device found (/dev/tpmrm0 or /dev/tpm0).${NC}"
    echo -e "        Ensure TPM 2.0 is enabled in UEFI/BIOS firmware and kernel modules"
    echo -e "        ('tpm_tis', 'tpm_crb', 'tpm_tis_core') are loaded."
    echo -e "        STATUS: BLOCKED (No physical TPM device node)"
    exit 3
fi

# 3. Device Node Attributes & Permissions Check
echo -e "${BLUE}[INFO] Inspecting device node permissions for ${TPM_DEVICE}...${NC}"
DEVICE_PERMS="$(ls -l "${TPM_DEVICE}")"
echo -e "       ${DEVICE_PERMS}"

if [ ! -r "${TPM_DEVICE}" ] || [ ! -w "${TPM_DEVICE}" ]; then
    echo -e "${RED}[ERROR] Insufficient read/write permissions on ${TPM_DEVICE}.${NC}"
    echo -e "        Ensure current user belongs to 'openaudit' or 'tss' group,"
    echo -e "        or verify udev rules at /etc/udev/rules.d/99-openaudit-tpm.rules."
    echo -e "        STATUS: BLOCKED (Permissions denied)"
    exit 4
fi

# 4. Binary Existence Verification
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

echo -e "${GREEN}[OK] openaudit-agent binary verified: ${AGENT_BIN}${NC}"

# 5. Execute Physical TPM Provisioning Test
QUAL_TMP_DIR="$(mktemp -d -t oa_tpm_qual_XXXXXX)"
trap 'rm -rf "${QUAL_TMP_DIR}"' EXIT

echo -e "${BLUE}[INFO] Executing four-state provisioning against physical TPM (${TPM_DEVICE})...${NC}"

"${AGENT_BIN}" provision \
    --tpm "${TPM_DEVICE}" \
    --state-dir "${QUAL_TMP_DIR}"

# 6. Verify Provisioned Artifacts
if [ ! -f "${QUAL_TMP_DIR}/machine_id.txt" ]; then
    echo -e "${RED}[ERROR] Machine ID was not generated.${NC}"
    exit 5
fi

if [ ! -f "${QUAL_TMP_DIR}/tpm-auth.secret" ]; then
    echo -e "${RED}[ERROR] Auth secret file not created.${NC}"
    exit 6
fi

# Verify secret file permissions (mode 0600)
SECRET_MODE="$(stat -c "%a" "${QUAL_TMP_DIR}/tpm-auth.secret" 2>/dev/null || stat -f "%OLp" "${QUAL_TMP_DIR}/tpm-auth.secret")"
if [ "${SECRET_MODE}" != "600" ]; then
    echo -e "${RED}[ERROR] Secret file permissions are ${SECRET_MODE}, expected 600.${NC}"
    exit 7
fi

echo -e "${GREEN}==================================================================${NC}"
echo -e "${GREEN}  Physical TPM 2.0 Qualification: SUCCESS                         ${NC}"
echo -e "${GREEN}  Machine ID: $(cat "${QUAL_TMP_DIR}/machine_id.txt")              ${NC}"
echo -e "${GREEN}  Device:     ${TPM_DEVICE}                                      ${NC}"
echo -e "${GREEN}==================================================================${NC}"
exit 0
