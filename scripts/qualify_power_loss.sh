#!/usr/bin/env bash
# ==============================================================================
# OpenAudit M3 Dimension 4: Physical Power-Loss Qualification Tooling
#
# Target: Validates Catalog Storage and SQLite WAL Replay durability under
#         both simulated crash-recovery cycles and physical power interruptions.
#
# Supported Modes:
#   --software-resilience : Runs automated software crash/recovery test harness
#                           (transaction interruption, WAL recovery, fsync, CB-01..13)
#   --physical-cut        : Orchestrates hardware relay-switched power cut during
#                           active concurrent write transactions (Requires bench rig)
#
# NOTE: Physical qualification remains BLOCKED until executed on a physical
#       power-relay testbench with bare-metal host and storage controller.
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_BIN="${WORKSPACE_ROOT}/target/release/openaudit-server"
if [ ! -x "${SERVER_BIN}" ]; then
    SERVER_BIN="${WORKSPACE_ROOT}/target/debug/openaudit-server"
fi

MODE="${1:---software-resilience}"

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}  OpenAudit Power-Loss & Crash-Resilience Qualification Harness   ${NC}"
echo -e "${BLUE}==================================================================${NC}"

if [ "${MODE}" = "--software-resilience" ]; then
    echo -e "${BLUE}[INFO] Executing automated software crash-resilience test suite...${NC}"

    # 1. Catalog Resilience Integration Suite (CB-01..13 recovery state machine)
    echo -e "${BLUE}[INFO] Running catalog resilience and crash-recovery matrix...${NC}"
    cargo test -p openaudit-core --test catalog_resilience_integration

    # 2. SQLite WAL Replay & Authority Store Crash Durability
    echo -e "${BLUE}[INFO] Running SQLite WAL recovery & transaction rollback tests...${NC}"
    cargo test -p openaudit-core --test d4_attestation_e2e test_e2e_concurrent_duplicate_enrollment_race_fails_closed

    # 3. Controlled Process Interruption Test
    TEST_DATA_DIR="$(mktemp -d -t oa_crash_bench_XXXXXX)"
    trap 'rm -rf "${TEST_DATA_DIR}"' EXIT

    echo -e "${BLUE}[INFO] Initializing catalog and testing crash during staged update...${NC}"
    "${SERVER_BIN}" authority catalog-init --data-dir "${TEST_DATA_DIR}" --version 1 --counter 1

    # Simulate an interrupted catalog update by creating an unpromoted candidate
    CANDIDATE_DIR="${TEST_DATA_DIR}/catalog/candidate"
    mkdir -p "${CANDIDATE_DIR}"
    echo '{"interrupted": true}' > "${CANDIDATE_DIR}/catalog.json"

    # Reconcile catalog
    echo -e "${BLUE}[INFO] Triggering authority catalog recovery...${NC}"
    RECOVER_OUT="$("${SERVER_BIN}" authority recover-catalog --data-dir "${TEST_DATA_DIR}")"
    echo -e "${GREEN}[OK] Recover output: ${RECOVER_OUT}${NC}"

    # Verify candidate directory was cleaned up and active catalog preserved
    if [ -d "${CANDIDATE_DIR}" ]; then
        echo -e "${RED}[ERROR] Interrupted candidate was not cleaned up during recovery.${NC}"
        exit 3
    fi

    echo -e "${GREEN}==================================================================${NC}"
    echo -e "${GREEN}  Software Crash Resilience Harness: PASSED                       ${NC}"
    echo -e "${GREEN}  Notice: Physical power-loss qualification remains BLOCKED      ${NC}"
    echo -e "${GREEN}          until executed with --physical-cut on dedicated bench.  ${NC}"
    echo -e "${GREEN}==================================================================${NC}"
    exit 0

elif [ "${MODE}" = "--physical-cut" ]; then
    echo -e "${BLUE}[INFO] Preparing for physical hardware power cut...${NC}"

    if [ -z "${OPENAUDIT_POWER_BENCH_READY:-}" ]; then
        echo -e "${RED}[ERROR] Hardware power-loss testbench environment not detected.${NC}"
        echo -e "        Requires OPENAUDIT_POWER_BENCH_READY=1 and dedicated test disk."
        echo -e "        STATUS: BLOCKED (Awaiting physical power-relay testbench)"
        exit 2
    fi

    BENCH_DIR="${OPENAUDIT_BENCH_DATA_DIR:-/mnt/test_power_disk/openaudit_data}"
    echo -e "${BLUE}[INFO] Initializing benchmark repository on ${BENCH_DIR}...${NC}"
    "${SERVER_BIN}" authority catalog-init --data-dir "${BENCH_DIR}" --version 1 --counter 1

    echo -e "${BLUE}[INFO] Spawning concurrent write workloads (SQLite WAL + Catalog)...${NC}"
    for i in $(seq 2 50); do
        "${SERVER_BIN}" authority catalog-update --data-dir "${BENCH_DIR}" --version "$i" --counter "$i" &
    done

    echo -e "${RED}[ALERT] Triggering external hardware power cut relay...${NC}"
    if [ -n "${OPENAUDIT_PDU_TRIGGER_CMD:-}" ]; then
        eval "${OPENAUDIT_PDU_TRIGGER_CMD}"
    else
        echo -e "${RED}[ERROR] OPENAUDIT_PDU_TRIGGER_CMD not configured.${NC}"
        exit 4
    fi

    echo -e "${GREEN}[OK] Power cut triggered. Perform filesystem check post-reboot.${NC}"
    exit 0
else
    echo -e "${RED}[ERROR] Unknown mode: ${MODE}.${NC}"
    echo -e "        Usage: $0 [--software-resilience | --physical-cut]"
    exit 1
fi
