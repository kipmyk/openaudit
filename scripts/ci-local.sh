#!/usr/bin/env bash
# ==============================================================================
# OpenAudit Reproducible Local CI Runner (Ubuntu 24.04 Docker Environment)
#
# Usage:
#   ./scripts/ci-local.sh            # Run complete CI verification suite
#   ./scripts/ci-local.sh fmt        # Check formatting only
#   ./scripts/ci-local.sh clippy     # Run Clippy linter
#   ./scripts/ci-local.sh build      # Build workspace binaries
#   ./scripts/ci-local.sh test       # Run all workspace tests (including swtpm)
#   ./scripts/ci-local.sh doc        # Build documentation
#   ./scripts/ci-local.sh audit      # Run cargo dependency security audit
#   ./scripts/ci-local.sh <command>  # Run custom command inside container
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE_NAME="openaudit-ci:ubuntu-24.04"
DOCKERFILE="${WORKSPACE_ROOT}/docker/ci.Dockerfile"
CONTAINER_NAME="openaudit-ci-runner-$$"

# Check Docker availability
if ! command -v docker >/dev/null 2>&1; then
    echo "[-] Error: docker is not installed or not in PATH." >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "[-] Error: docker daemon is not running or accessible." >&2
    exit 1
fi

# Build Docker CI image if not present
if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    echo "[*] Building OpenAudit Ubuntu 24.04 CI container image (${IMAGE_NAME})..."
    docker build -f "${DOCKERFILE}" -t "${IMAGE_NAME}" "${WORKSPACE_ROOT}"
fi

# Cleanup trap
cleanup() {
    local exit_code=$?
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    fi
    exit "${exit_code}"
}
trap cleanup EXIT INT TERM

# Run container with workspace mount and persistent Cargo caching
run_in_container() {
    local cmd="$1"
    docker run --rm \
        --name "${CONTAINER_NAME}" \
        -v "${WORKSPACE_ROOT}:/workspace" \
        -v "openaudit-cargo-registry:/usr/local/cargo/registry" \
        -v "openaudit-cargo-git:/usr/local/cargo/git" \
        -v "openaudit-cargo-target:/target-linux" \
        -e CARGO_TARGET_DIR=/target-linux \
        -e CARGO_TERM_COLOR=always \
        -w /workspace \
        "${IMAGE_NAME}" \
        bash -c "${cmd}"
}

SUITE="${1:-all}"

case "${SUITE}" in
    fmt)
        echo "[*] Running: cargo fmt --all --check"
        run_in_container "cargo fmt --all --check"
        ;;
    clippy)
        echo "[*] Running: cargo clippy --all-targets --workspace -- -D warnings"
        run_in_container "cargo clippy --all-targets --workspace -- -D warnings"
        ;;
    build)
        echo "[*] Running: cargo build --bins"
        run_in_container "cargo build --bins"
        ;;
    test)
        echo "[*] Running: cargo test --workspace --verbose"
        run_in_container "cargo test --workspace --verbose"
        ;;
    doc)
        echo "[*] Running: cargo doc --workspace --no-deps"
        run_in_container "cargo doc --workspace --no-deps"
        ;;
    audit)
        echo "[*] Running: cargo audit"
        run_in_container "cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0387 --ignore RUSTSEC-2025-0134"
        ;;
    all)
        echo "================================================================================"
        echo " OpenAudit Linux Verification Suite (Ubuntu 24.04 Container)"
        echo "================================================================================"

        echo ""
        echo "[1/5] Checking code formatting..."
        run_in_container "cargo fmt --all --check"
        echo "[+] Formatting verified."

        echo ""
        echo "[2/5] Running Clippy linter across all targets..."
        run_in_container "cargo clippy --all-targets --workspace -- -D warnings"
        echo "[+] Clippy checks passed with 0 warnings."

        echo ""
        echo "[3/5] Building workspace binaries..."
        run_in_container "cargo build --bins"
        echo "[+] Workspace binaries compiled successfully."

        echo ""
        echo "[4/5] Executing complete workspace test suite (including TPM emulation)..."
        run_in_container "cargo test --workspace --verbose"
        echo "[+] Complete workspace tests passed."

        echo ""
        echo "[5/5] Checking workspace documentation..."
        run_in_container "cargo doc --workspace --no-deps"
        echo "[+] Documentation generated without errors."

        echo ""
        echo "================================================================================"
        echo " [+] ALL CHECKS PASSED: OpenAudit Linux Verification Succeeded"
        echo "================================================================================"
        ;;
    *)
        # Execute arbitrary user-specified command
        run_in_container "$*"
        ;;
esac

