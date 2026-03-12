#!/usr/bin/env bash
# End-to-end local enclave test runner.
#
# Starts mock AWS services, seeds parameters, optionally builds a test EIF
# from the skeleton app, boots it in QEMU, runs smoke tests, and cleans up.
#
# Usage:
#   ./run.sh              Build skeleton test app EIF, then run full test
#   ./run.sh <path-to-eif>  Use a pre-built EIF
#
# Prerequisites (pick one):
#   nix develop ./test   (provides QEMU, vhost-device-vsock, gvproxy, awscli)
#   docker compose --profile test run --build test-runner  (all-in-one Docker)
#
# Additional requirements:
#   docker compose       (for mock services, unless SKIP_MOCK_SERVICES=1)
#   enclave CLI          (for building EIF, only if no EIF path given)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

# Auto-enter Nix dev shell if required tools are missing.
if ! command -v vhost-device-vsock &>/dev/null || ! command -v qemu-system-x86_64 &>/dev/null; then
  echo "Required tools not found, entering nix develop ..."
  exec nix develop "${SCRIPT_DIR}" --command "$0" "$@"
fi

# Build enclave CLI from source (ensures latest code, no stale binaries).
ENCLAVE_CLI="/tmp/enclave-cli"
echo "Building enclave CLI..."
(cd "$REPO_ROOT" && go build -o "$ENCLAVE_CLI" ./cmd/enclave)
echo "  Built: $ENCLAVE_CLI"
echo ""

EIF_PATH="${1:-}"

cleanup() {
  echo ""
  echo "=== Tearing down ==="
  "$ENCLAVE_CLI" destroy --force 2>/dev/null || true
  [ -n "${BOOT_PID:-}" ] && kill "$BOOT_PID" 2>/dev/null && wait "$BOOT_PID" 2>/dev/null || true
  echo "Destroy Mock Services..."
  docker compose down -v 2>/dev/null || true
  echo "Done."
}
trap cleanup EXIT

echo "==============================="
echo " Enclave Local Test Runner"
echo "==============================="
echo ""

# Step 0 (optional): Build test EIF from skeleton app.
echo "=== [0/5] Building test EIF from skeleton app ==="
  echo "  Source: test/app/"
  (cd app && "$ENCLAVE_CLI" build --local)
  EIF_PATH="app/enclave/artifacts/image.eif"
  echo "  Built: $EIF_PATH"
echo ""

# Step 1: Start mock services (skipped when run inside Docker test-runner).
echo "=== [1/5] Starting mock services ==="
  docker compose down -v 2>/dev/null || true
  docker compose up -d --build --wait
echo ""

# Step 2: Deploy CDK stack to localstack.
echo "=== [2/5] Deploying local CDK stack to localstack ==="
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export LOCAL_DEPLOYMENT=true
export ENCLAVE_CONFIG="${SCRIPT_DIR}/app/enclave/enclave.yaml"

"$ENCLAVE_CLI" deploy
echo ""

# Step 3: Boot enclave in QEMU (runs in background).
echo "=== [3/5] Booting enclave in QEMU ==="
./boot-qemu.sh "$EIF_PATH" &
BOOT_PID=$!

# Wait for the enclave to boot and Init to complete.
# Phase 1: wait for any HTTP response (supervisor started).
# Phase 2: wait for HTTP 200 (Init complete). 503 means Init is still running.
BOOT_TIMEOUT="${BOOT_TIMEOUT:-90}"
INIT_TIMEOUT="${INIT_TIMEOUT:-120}"
echo "  Waiting for enclave boot (timeout: ${BOOT_TIMEOUT}s)..."
SECONDS=0
while [ $SECONDS -lt "$BOOT_TIMEOUT" ]; do
  if ! kill -0 "$BOOT_PID" 2>/dev/null; then
    echo "Error: boot-qemu.sh exited unexpectedly" >&2
    wait "$BOOT_PID" || true
    exit 1
  fi
  HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
    "https://localhost:${HOST_TLS_PORT:-8443}/health" 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "503" ]; then
    echo "  Enclave responding (${SECONDS}s) — HTTP $HTTP_CODE"
    break
  fi
  sleep 2
done

if [ $SECONDS -ge "$BOOT_TIMEOUT" ]; then
  echo "Error: enclave did not become ready within ${BOOT_TIMEOUT}s" >&2
  exit 1
fi

# Phase 2: wait for Init to complete (health returns 200).
echo "  Waiting for Init to complete (timeout: ${INIT_TIMEOUT}s)..."
SECONDS=0
while [ $SECONDS -lt "$INIT_TIMEOUT" ]; do
  if ! kill -0 "$BOOT_PID" 2>/dev/null; then
    echo "Error: boot-qemu.sh exited unexpectedly" >&2
    wait "$BOOT_PID" || true
    exit 1
  fi
  HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
    "https://localhost:${HOST_TLS_PORT:-8443}/health" 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "200" ]; then
    echo "  Init complete (${SECONDS}s)"
    break
  fi
  # Show progress with current init status.
  if [ "$HTTP_CODE" = "503" ]; then
    STATUS=$(curl -sk --max-time 5 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null \
      | jq -r '.error // "unknown"' 2>/dev/null || echo "unknown")
    echo "  Init in progress (${SECONDS}s): $STATUS"
  fi
  sleep 5
done

if [ $SECONDS -ge "$INIT_TIMEOUT" ]; then
  echo "Error: Init did not complete within ${INIT_TIMEOUT}s" >&2
  # Show final status for debugging.
  curl -sk --max-time 5 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || true
  exit 1
fi
echo ""

# Step 4: Run smoke tests.
echo "=== [4/5] Running smoke tests ==="
./smoke-test.sh
echo ""

# Step 5: Run migration via enclave deploy (upgrade detection).
# The enclave is running with secrets initialized, so a second deploy
# detects upgrade mode and exercises the full migration code path.
echo "=== [5/5] Running migration (enclave deploy upgrade) ==="
"$ENCLAVE_CLI" deploy

echo ""
echo "==============================="
echo " All tests passed!"
echo "==============================="
