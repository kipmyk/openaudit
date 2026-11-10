#!/usr/bin/env bash
# ==============================================================================
# OpenAudit M3.2 Multi-Distribution Linux Verification Runner
#
# Validates OpenAudit across target distributions:
#   1. Ubuntu 24.04 LTS (Noble Numbat)
#   2. Debian 12 (Bookworm)
#   3. Debian 13 (Trixie)
#
# Reuses preserved local Docker CI images:
#   - openaudit-ci:ubuntu-24.04
#   - openaudit-ci:debian-12
#   - openaudit-ci:debian-13
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================================"
echo " OpenAudit M3.2 Multi-Distribution Verification Suite"
echo "================================================================================"
echo ""

# 1. Ensure Docker CI images exist (reuse preserved local images if present)
if ! docker image inspect "openaudit-ci:ubuntu-24.04" >/dev/null 2>&1; then
    echo "[*] Building openaudit-ci:ubuntu-24.04..."
    docker build -f "${WORKSPACE_ROOT}/docker/ci.Dockerfile" -t "openaudit-ci:ubuntu-24.04" "${WORKSPACE_ROOT}"
fi
if ! docker image inspect "openaudit-ci:debian-12" >/dev/null 2>&1; then
    echo "[*] Building openaudit-ci:debian-12..."
    docker build -f "${WORKSPACE_ROOT}/docker/debian-12.Dockerfile" -t "openaudit-ci:debian-12" "${WORKSPACE_ROOT}"
fi
if ! docker image inspect "openaudit-ci:debian-13" >/dev/null 2>&1; then
    echo "[*] Building openaudit-ci:debian-13..."
    docker build -f "${WORKSPACE_ROOT}/docker/debian-13.Dockerfile" -t "openaudit-ci:debian-13" "${WORKSPACE_ROOT}"
fi

echo "[*] Checking preserved local Docker images..."
docker images "openaudit-ci*" --format "table {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}"

echo ""
echo "--------------------------------------------------------------------------------"
echo " [1/3] Validating Ubuntu 24.04 LTS (Noble Numbat)"
echo "--------------------------------------------------------------------------------"
docker run --rm \
    -v "${WORKSPACE_ROOT}:/workspace" \
    -v "openaudit-cargo-registry:/usr/local/cargo/registry" \
    -v "openaudit-cargo-git:/usr/local/cargo/git" \
    -v "openaudit-cargo-target:/target-linux" \
    -e CARGO_TARGET_DIR=/target-linux \
    -w /workspace \
    openaudit-ci:ubuntu-24.04 \
    bash -c "cargo test -p openaudit-engine --verbose"
echo "[+] Ubuntu 24.04 LTS verification successful."

echo ""
echo "--------------------------------------------------------------------------------"
echo " [2/3] Validating Debian 12 (Bookworm)"
echo "--------------------------------------------------------------------------------"
docker run --rm \
    -v "${WORKSPACE_ROOT}:/workspace" \
    -w /workspace \
    openaudit-ci:debian-12 \
    bash -c "cargo test -p openaudit-engine --test debian_compatibility_regression --verbose"
echo "[+] Debian 12 (Bookworm) verification successful."

echo ""
echo "--------------------------------------------------------------------------------"
echo " [3/3] Validating Debian 13 (Trixie)"
echo "--------------------------------------------------------------------------------"
docker run --rm \
    -v "${WORKSPACE_ROOT}:/workspace" \
    -w /workspace \
    openaudit-ci:debian-13 \
    bash -c "cargo test -p openaudit-engine --test debian_compatibility_regression --verbose"
echo "[+] Debian 13 (Trixie) verification successful."

echo ""
echo "================================================================================"
echo " [+] MULTI-DISTRIBUTION VERIFICATION SUCCEEDED: Ubuntu 24.04, Debian 12 & 13"
echo "================================================================================"

