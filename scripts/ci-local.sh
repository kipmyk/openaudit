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
    local net_args=(--add-host=host.docker.internal:host-gateway)
    if [[ -n "${OPENAUDIT_DOCKER_NETWORK:-}" ]]; then
        net_args=(--network "${OPENAUDIT_DOCKER_NETWORK}")
    fi
    docker run --rm \
        --name "${CONTAINER_NAME}" \
        "${net_args[@]}" \
        -v "${WORKSPACE_ROOT}:/workspace" \
        -v "openaudit-cargo-registry:/usr/local/cargo/registry" \
        -v "openaudit-cargo-git:/usr/local/cargo/git" \
        -v "openaudit-cargo-target:/target-linux" \
        -e CARGO_TARGET_DIR=/target-linux \
        -e CARGO_TERM_COLOR=always \
        -e OPENAUDIT_TEST_POSTGRES_URL="${OPENAUDIT_TEST_POSTGRES_URL:-}" \
        -e TEST_DATABASE_URL="${TEST_DATABASE_URL:-}" \
        -e OPENAUDIT_REQUIRE_POSTGRES_TESTS="${OPENAUDIT_REQUIRE_POSTGRES_TESTS:-}" \
        -w /workspace \
        "${IMAGE_NAME}" \
        bash -c "${cmd}"
}

ensure_local_postgres() {
    if [[ -n "${OPENAUDIT_TEST_POSTGRES_URL:-}" || -n "${TEST_DATABASE_URL:-}" ]]; then
        export OPENAUDIT_REQUIRE_POSTGRES_TESTS="${OPENAUDIT_REQUIRE_POSTGRES_TESTS:-1}"
        return 0
    fi
    local pg_container="openaudit-postgres-test"
    if ! docker ps --format '{{.Names}}' | grep -q "^${pg_container}$"; then
        echo "[*] Starting local PostgreSQL 16 test container (${pg_container}) on 127.0.0.1:5433..."
        docker rm -f "${pg_container}" >/dev/null 2>&1 || true
        docker run -d \
            --name "${pg_container}" \
            -e POSTGRES_USER=postgres \
            -e POSTGRES_PASSWORD=postgres \
            -e POSTGRES_DB=openaudit_test \
            -p 127.0.0.1:5433:5432 \
            postgres:16-alpine >/dev/null
    fi
    for _ in $(seq 1 30); do
        if docker exec "${pg_container}" pg_isready -U postgres -d openaudit_test >/dev/null 2>&1; then
            export OPENAUDIT_TEST_POSTGRES_URL="postgres://postgres:postgres@host.docker.internal:5433/openaudit_test"
            export OPENAUDIT_REQUIRE_POSTGRES_TESTS="1"
            return 0
        fi
        sleep 1
    done
    echo "[-] Error: PostgreSQL test container (${pg_container}) failed readiness check." >&2
    exit 1
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
        ensure_local_postgres
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
        echo "[1/6] Checking code formatting..."
        run_in_container "cargo fmt --all --check"
        echo "[+] Formatting verified."

        echo ""
        echo "[2/6] Running Clippy linter across all targets..."
        run_in_container "cargo clippy --all-targets --workspace -- -D warnings"
        echo "[+] Clippy checks passed with 0 warnings."

        echo ""
        echo "[3/6] Building workspace binaries..."
        run_in_container "cargo build --bins"
        echo "[+] Workspace binaries compiled successfully."

        echo ""
        echo "[4/6] Executing complete workspace test suite (including TPM emulation & PostgreSQL)..."
        ensure_local_postgres
        run_in_container "cargo test --workspace --verbose"
        echo "[+] Complete workspace tests passed."

        echo ""
        echo "[5/6] Checking workspace documentation..."
        run_in_container "cargo doc --workspace --no-deps"
        echo "[+] Documentation generated without errors."

        echo ""
        echo "[6/6] Running dependency security audit..."
        run_in_container "cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0387 --ignore RUSTSEC-2025-0134"
        echo "[+] Dependency security audit clean."

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

