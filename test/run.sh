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
cd "$SCRIPT_DIR"

# Auto-enter Nix dev shell if QEMU tools aren't available.
if ! command -v vhost-device-vsock >/dev/null 2>&1 || ! command -v gvproxy >/dev/null 2>&1 || ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
  if command -v nix >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/flake.nix" ]; then
    echo "Required tools not found. Entering nix develop ./test ..."
    exec nix develop "$SCRIPT_DIR" --command bash "$0" "$@"
  else
    echo "Error: Missing required tools (vhost-device-vsock, gvproxy, qemu-system-x86_64)." >&2
    echo "  Run: nix develop ./test" >&2
    exit 1
  fi
fi

EIF_PATH="${1:-}"

cleanup() {
  echo ""
  echo "=== Tearing down ==="
  [ -n "${BOOT_PID:-}" ] && kill "$BOOT_PID" 2>/dev/null && wait "$BOOT_PID" 2>/dev/null || true
  if [ "${SKIP_MOCK_SERVICES:-}" != "1" ]; then
    docker compose down -v 2>/dev/null || true
  fi
  echo "Done."
}
trap cleanup EXIT

echo "==============================="
echo " Enclave Local Test Runner"
echo "==============================="
echo ""

# Step 0 (optional): Build test EIF from skeleton app.
if [ -z "$EIF_PATH" ]; then
  echo "=== [0/4] Building test EIF from skeleton app ==="
  echo "  Source: test/app/"
  if ! command -v enclave >/dev/null 2>&1; then
    echo "Error: 'enclave' CLI not found. Either:" >&2
    echo "  - Install it: go install -o /tmp/enclave-test ./cmd/enclave" >&2
    echo "  - Or provide a pre-built EIF: ./run.sh <path-to-eif>" >&2
    exit 1
  fi
  (cd app && enclave build)
  EIF_PATH="app/enclave/artifacts/image.eif"
  if [ ! -f "$EIF_PATH" ]; then
    echo "Error: EIF build failed — $EIF_PATH not found" >&2
    exit 1
  fi
  echo "  Built: $EIF_PATH"
  echo ""
fi

# Step 1: Start mock services (skipped when run inside Docker test-runner).
if [ "${SKIP_MOCK_SERVICES:-}" != "1" ]; then
  echo "=== [1/4] Starting mock services ==="
  docker compose up -d --build --wait
  echo ""
else
  echo "=== [1/4] Mock services already running (Docker) ==="
  echo ""
fi

# Step 2: Deploy CDK stack to localstack.
echo "=== [2/4] Deploying local CDK stack to localstack ==="
./deploy-local.sh
echo ""

# Step 3: Boot enclave in QEMU (runs in background).
echo "=== [3/4] Booting enclave in QEMU ==="
./boot-qemu.sh "$EIF_PATH" &
BOOT_PID=$!

# Wait for the enclave to become ready (poll health endpoint).
BOOT_TIMEOUT="${BOOT_TIMEOUT:-90}"
echo "  Waiting for enclave health (timeout: ${BOOT_TIMEOUT}s)..."
SECONDS=0
while [ $SECONDS -lt "$BOOT_TIMEOUT" ]; do
  if ! kill -0 "$BOOT_PID" 2>/dev/null; then
    echo "Error: boot-qemu.sh exited unexpectedly" >&2
    wait "$BOOT_PID" || true
    exit 1
  fi
  # Accept any HTTP response (200 or 503) — supervisor is running.
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
echo ""

# Step 4: Run smoke tests.
echo "=== [4/4] Running smoke tests ==="
./smoke-test.sh

echo ""
echo "==============================="
echo " All tests passed!"
echo "==============================="
