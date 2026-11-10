#!/usr/bin/env bash
# ==============================================================================
# OpenAudit Reproducible CLI Performance Benchmark
# ==============================================================================
# Executes multi-run benchmark iterations of openaudit-cli, recording:
# - Operating system, architecture, kernel, and CPU hardware details
# - Audit profile (Baseline / Hardened)
# - Exact command line invocation
# - Individual run execution latencies in milliseconds
# - Statistical average and spread
# - Exact rule accounting (registered, applicable, executed, skipped)
# - Process exit codes and attestation
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CLI_BIN="${WORKSPACE_ROOT}/target/release/openaudit-cli"
OUTPUT_DIR="${WORKSPACE_ROOT}/artifacts/benchmarks"
mkdir -p "${OUTPUT_DIR}"

ITERATIONS=${ITERATIONS:-5}
PROFILE=${1:-baseline}

echo "================================================================================"
echo " OpenAudit CLI Reproducible Performance Benchmark"
echo "================================================================================"

# 1. Ensure binary is built in release mode
if [ ! -f "${CLI_BIN}" ]; then
    echo "[*] Building openaudit-cli in release mode..."
    cargo build --release -p openaudit-cli
fi

# 2. Gather environment hardware & OS telemetry
OS_NAME="$(uname -s)"
OS_ARCH="$(uname -m)"
KERNEL_VERSION="$(uname -r)"

if [ "${OS_NAME}" = "Darwin" ]; then
    OS_VERSION="$(sw_vers -productVersion)"
    OS_BUILD="$(sw_vers -buildVersion)"
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "Apple Silicon")"
    PLATFORM_STR="macOS ${OS_VERSION} (${OS_BUILD}) - ${OS_ARCH}"
elif [ "${OS_NAME}" = "Linux" ]; then
    OS_VERSION="$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Linux")"
    CPU_MODEL="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^[ \t]*//' || echo "Linux CPU")"
    PLATFORM_STR="${OS_VERSION} - ${OS_ARCH}"
else
    PLATFORM_STR="${OS_NAME} - ${OS_ARCH}"
    CPU_MODEL="Generic CPU"
fi

TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo " Timestamp:    ${TIMESTAMP}"
echo " Platform:     ${PLATFORM_STR}"
echo " Processor:    ${CPU_MODEL}"
echo " Profile:      ${PROFILE}"
echo " Iterations:   ${ITERATIONS}"
echo " Command:      ${CLI_BIN} scan --profile ${PROFILE} --format json"
echo "--------------------------------------------------------------------------------"

# 3. Execute benchmark iterations
DURATIONS=()
EXIT_CODES=()
TOTAL_MS=0
LAST_REGISTERED=0
LAST_EXECUTED=0
LAST_EXCLUDED=0
LAST_UNSUPPORTED=0

for i in $(seq 1 "${ITERATIONS}"); do
    OUT_FILE="/tmp/openaudit_bench_run_${i}.json"
    
    START_NS=$(python3 -c 'import time; print(int(time.time_ns()))')
    EXIT_CODE=0
    "${CLI_BIN}" scan --profile "${PROFILE}" --format json > "${OUT_FILE}" 2>/dev/null || EXIT_CODE=$?
    END_NS=$(python3 -c 'import time; print(int(time.time_ns()))')
    
    DIFF_MS=$(( (END_NS - START_NS) / 1000000 ))
    DURATIONS+=("${DIFF_MS}")
    EXIT_CODES+=("${EXIT_CODE}")
    TOTAL_MS=$(( TOTAL_MS + DIFF_MS ))
    
    # Extract rule metrics from JSON output if successful
    if [ "${EXIT_CODE}" -eq 0 ] && [ -f "${OUT_FILE}" ]; then
        LAST_REGISTERED=$(python3 -c "import json; data=json.load(open('${OUT_FILE}')); print(len(data.get('check_statuses', [])))" 2>/dev/null || echo 0)
        LAST_EXECUTED=$(python3 -c "import json; data=json.load(open('${OUT_FILE}')); print(sum(1 for s in data.get('check_statuses', []) if 'executed' in s.get('status', {}) or 'Executed' in s.get('status', {})))" 2>/dev/null || echo 0)
        LAST_EXCLUDED=$(python3 -c "import json; data=json.load(open('${OUT_FILE}')); print(sum(1 for s in data.get('check_statuses', []) if 'not_applicable' in s.get('status', {}) or 'NotApplicable' in s.get('status', {})))" 2>/dev/null || echo 0)
        LAST_UNSUPPORTED=$(python3 -c "import json; data=json.load(open('${OUT_FILE}')); print(sum(1 for s in data.get('check_statuses', []) if 'unsupported_platform' in s.get('status', {}) or 'UnsupportedPlatform' in s.get('status', {})))" 2>/dev/null || echo 0)
    fi
    
    printf "  Run #%d: %4d ms (exit code: %d)\n" "${i}" "${DIFF_MS}" "${EXIT_CODE}"
    rm -f "${OUT_FILE}"
done

AVG_MS=$(( TOTAL_MS / ITERATIONS ))
APPLICABLE_RULES=$(( LAST_EXECUTED + LAST_EXCLUDED ))

echo "--------------------------------------------------------------------------------"
echo " Benchmark Summary Statistics:"
echo "    Average Duration:    ${AVG_MS} ms"
echo "    Total Registered:    ${LAST_REGISTERED} rules"
echo "    Applicable to Host:  ${APPLICABLE_RULES} rules"
echo "    Executed on Host:    ${LAST_EXECUTED} rules"
echo "    Profile Excluded:    ${LAST_EXCLUDED} rules"
echo "    Platform Skipped:    ${LAST_UNSUPPORTED} rules"
echo "================================================================================"

# 4. Generate structured JSON output
JSON_OUT="${OUTPUT_DIR}/benchmark-${PROFILE}-${OS_ARCH}.json"
cat <<EOF > "${JSON_OUT}"
{
  "timestamp": "${TIMESTAMP}",
  "os": "${OS_NAME}",
  "platform": "${PLATFORM_STR}",
  "architecture": "${OS_ARCH}",
  "cpu": "${CPU_MODEL}",
  "profile": "${PROFILE}",
  "command": "${CLI_BIN} scan --profile ${PROFILE} --format json",
  "iterations": ${ITERATIONS},
  "durations_ms": [$(IFS=,; echo "${DURATIONS[*]}")],
  "exit_codes": [$(IFS=,; echo "${EXIT_CODES[*]}")],
  "average_duration_ms": ${AVG_MS},
  "rule_accounting": {
    "total_registered_rules": ${LAST_REGISTERED},
    "applicable_rules": ${APPLICABLE_RULES},
    "executed_rules": ${LAST_EXECUTED},
    "profile_excluded_rules": ${LAST_EXCLUDED},
    "platform_unsupported_rules": ${LAST_UNSUPPORTED}
  }
}
EOF

echo "[+] Structured benchmark evidence saved to:"
echo "    ${JSON_OUT}"
echo "================================================================================"
