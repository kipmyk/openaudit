#!/usr/bin/env bash
# ==============================================================================
# OpenAudit M3 Dimension 4: Physical Power-Loss Qualification Procedure
#
# Target: Validates OpenAudit Catalog Storage and SQLite WAL Replay Engine
#         under unbuffered raw storage controller power interruption.
#
# NOTE: Requires dedicated hardware testbench with relay-switched power delivery
#       to NVMe/SATA controller or bare-metal host.
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  OpenAudit Physical Power-Loss Qualification Harness            ${NC}"
echo -e "${BLUE}==================================================================${NC}"

# Check for dedicated bench environment variable
if [ -z "${OPENAUDIT_POWER_BENCH_READY:-}" ]; then
    echo -e "${YELLOW}[WARN] Hardware power-loss testbench environment not detected.${NC}"
    echo -e "       Physical power cut testing requires an external power interruption"
    echo -e "       controller (e.g. programmable relay/PDU) and a dedicated test disk."
    echo -e "       STATUS: BLOCKED (Awaiting laboratory power-cut hardware rig)"
    exit 2
fi

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${WORKSPACE_ROOT}/target/release/openaudit-server"
TEST_DATA_DIR="${OPENAUDIT_BENCH_DATA_DIR:-/mnt/test_power_disk/openaudit_data}"

echo -e "${BLUE}[INFO] Initializing power-loss qualification on ${TEST_DATA_DIR}...${NC}"

# 1. Initialize Baseline Catalog
"${SERVER_BIN}" authority catalog-init --data-dir "${TEST_DATA_DIR}" --version 1 --counter 1

# 2. Spawn concurrent catalog updates and replay transactions
echo -e "${BLUE}[INFO] Generating active SQLite WAL and multi-stage catalog writes...${NC}"
for i in $(seq 2 50); do
    "${SERVER_BIN}" authority catalog-update --data-dir "${TEST_DATA_DIR}" --version "$i" --counter "$i" &
done

# 3. Trigger abrupt power cut signal to external PDU / relay
echo -e "${RED}[ALERT] Triggering external hardware power cut...${NC}"
if [ -n "${OPENAUDIT_PDU_TRIGGER_CMD:-}" ]; then
    eval "${OPENAUDIT_PDU_TRIGGER_CMD}"
else
    echo -e "${RED}[ERROR] OPENAUDIT_PDU_TRIGGER_CMD not configured.${NC}"
    exit 3
fi

echo -e "${GREEN}[OK] Power cut cycle completed. Host reboot required.${NC}"
exit 0
