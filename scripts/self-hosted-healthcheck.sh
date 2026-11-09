#!/usr/bin/env bash
# OpenAudit Self-Hosted Deployment Healthcheck Script
# Validates liveness, readiness, version, and API capability endpoints.

set -euo pipefail

HOST="${1:-127.0.0.1}"
PORT="${2:-8080}"
BASE_URL="http://${HOST}:${PORT}"

echo "=== OpenAudit Self-Hosted Control Plane Diagnostic ==="
echo "Target Base URL: ${BASE_URL}"
echo ""

# 1. Liveness check
echo -n "Checking Liveness (/health/live)... "
if curl -s -f -m 5 "${BASE_URL}/health/live" > /dev/null; then
    echo "PASS (HTTP 200 OK)"
else
    echo "FAIL"
    echo "Error: Server process is not responsive."
    exit 1
fi

# 2. Readiness check
echo -n "Checking Readiness (/health/ready)... "
READY_RESP=$(curl -s -f -m 5 "${BASE_URL}/health/ready" || true)
if [ -n "${READY_RESP}" ]; then
    echo "PASS (${READY_RESP})"
else
    echo "FAIL"
    echo "Error: Server storage or database is not ready."
    exit 1
fi

# 3. Version endpoint
echo -n "Checking Engine Version (/version)... "
VERSION_RESP=$(curl -s -f -m 5 "${BASE_URL}/version" || true)
if [ -n "${VERSION_RESP}" ]; then
    echo "PASS (${VERSION_RESP})"
else
    echo "FAIL"
    exit 1
fi

# 4. Capabilities endpoint
echo -n "Checking API Capabilities (/api/v1/capabilities)... "
CAPS_RESP=$(curl -s -f -m 5 "${BASE_URL}/api/v1/capabilities" || true)
if [ -n "${CAPS_RESP}" ]; then
    echo "PASS (${CAPS_RESP})"
else
    echo "FAIL"
    exit 1
fi

# 5. Web UI check
echo -n "Checking Web UI Application Root (/)... "
ROOT_RESP=$(curl -s -f -m 5 "${BASE_URL}/" || true)
if echo "${ROOT_RESP}" | grep -q "OpenAudit Control Plane"; then
    echo "PASS (Web UI embedded bundle loaded)"
else
    echo "FAIL"
    echo "Error: Root path did not return the OpenAudit application."
    exit 1
fi

echo ""
echo "=== All Self-Hosted Diagnostics Passed Successfully ==="
exit 0
