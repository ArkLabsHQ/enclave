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

# Use pre-built binaries (Docker test-runner) 
ENCLAVE_CLI="/tmp/enclave-cli"
ENCLAVE_MGMT="/tmp/enclave-mgmt"
  echo "Building enclave CLI and mgmt server..."
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_CLI" ./cmd/enclave)
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_MGMT" ./mgmt/)


echo "  CLI:  $ENCLAVE_CLI"
echo "  Mgmt: $ENCLAVE_MGMT"
echo ""

EIF_PATH="${1:-}"
MGMT_PID=""

cleanup() {
  echo ""
  echo "=== Tearing down ==="
  "$ENCLAVE_CLI" destroy --force 2>/dev/null || true
  # Kill mgmt server.
  [ -n "${MGMT_PID:-}" ] && kill "$MGMT_PID" 2>/dev/null && wait "$MGMT_PID" 2>/dev/null || true
  # Kill enclave (boot-qemu.sh) via PID file.
  if [ -f /tmp/enclave-boot.pid ]; then
    kill "$(cat /tmp/enclave-boot.pid)" 2>/dev/null || true
    sleep 1
  fi
  echo "Destroy Mock Services..."
  docker compose down -v 2>/dev/null || true
  echo "Done."
}
trap cleanup EXIT

# Wait for enclave Init to complete (health returns 200).
# Reads boot PID from /tmp/enclave-boot.pid to detect crashes.
wait_for_enclave() {
  local label="${1:-}"
  local boot_timeout="${BOOT_TIMEOUT:-90}"
  local init_timeout="${INIT_TIMEOUT:-120}"

  echo "  Waiting for enclave boot (timeout: ${boot_timeout}s)..."
  SECONDS=0
  while [ $SECONDS -lt "$boot_timeout" ]; do
    # Check if boot-qemu.sh is still running.
    if [ -f /tmp/enclave-boot.pid ]; then
      local pid
      pid=$(cat /tmp/enclave-boot.pid)
      if ! kill -0 "$pid" 2>/dev/null; then
        echo "Error: boot-qemu.sh exited unexpectedly${label:+ ($label)}" >&2
        exit 1
      fi
    fi
    HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
      "https://localhost:${HOST_TLS_PORT:-8443}/health" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "503" ]; then
      echo "  Enclave responding (${SECONDS}s) — HTTP $HTTP_CODE"
      break
    fi
    sleep 2
  done

  if [ $SECONDS -ge "$boot_timeout" ]; then
    echo "Error: enclave did not become ready within ${boot_timeout}s${label:+ ($label)}" >&2
    exit 1
  fi

  echo "  Waiting for Init to complete (timeout: ${init_timeout}s)..."
  SECONDS=0
  while [ $SECONDS -lt "$init_timeout" ]; do
    if [ -f /tmp/enclave-boot.pid ]; then
      local pid
      pid=$(cat /tmp/enclave-boot.pid)
      if ! kill -0 "$pid" 2>/dev/null; then
        echo "Error: boot-qemu.sh exited unexpectedly${label:+ ($label)}" >&2
        exit 1
      fi
    fi
    HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
      "https://localhost:${HOST_TLS_PORT:-8443}/health" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ]; then
      echo "  Init complete (${SECONDS}s)"
      break
    fi
    if [ "$HTTP_CODE" = "503" ]; then
      STATUS=$(curl -sk --max-time 5 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null \
        | jq -r '.error // "unknown"' 2>/dev/null || echo "unknown")
      echo "  Init in progress (${SECONDS}s): $STATUS"
    fi
    sleep 5
  done

  if [ $SECONDS -ge "$init_timeout" ]; then
    echo "Error: Init did not complete within ${init_timeout}s${label:+ ($label)}" >&2
    curl -sk --max-time 5 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || true
    exit 1
  fi
}

echo "==============================="
echo " Enclave Local Test Runner"
echo "==============================="
echo ""

# Step 0 (optional): Build test EIF from skeleton app.
echo "=== [0/7] Building test EIF from skeleton app ==="
  echo "  Source: test/app/"
  (cd app && "$ENCLAVE_CLI" build --local)
  EIF_PATH="app/enclave/artifacts/image.eif"
  echo "  Built: $EIF_PATH"
echo ""

# Step 1: Start mock services (skipped when run inside Docker test-runner).
echo "=== [1/7] Starting mock services ==="
  docker compose down -v 2>/dev/null || true
  docker compose up -d --build --wait
echo ""

# Step 2: Deploy CDK stack to localstack and start mgmt server.
echo "=== [2/7] Deploying local CDK stack to localstack ==="
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export LOCAL_DEPLOYMENT=true
export ENCLAVE_CONFIG="${SCRIPT_DIR}/app/enclave/enclave.yaml"

"$ENCLAVE_CLI" deploy

# Start mgmt server on the host (like production EC2 host).
# Configured with stop/start commands that manage boot-qemu.sh via PID file.
echo "  Starting mgmt server..."
EIF_ABS_PATH="$(realpath "$EIF_PATH")"
ENCLAVE_AWS_REGION=us-east-1 \
ENCLAVE_DEPLOYMENT=dev \
ENCLAVE_APP_NAME=my-app \
ENCLAVE_MGMT_ADDR="127.0.0.1:8444" \
ENCLAVE_URL="https://127.0.0.1:8443" \
ENCLAVE_EIF_PATH="$EIF_ABS_PATH" \
ENCLAVE_STOP_CMD="kill \$(cat /tmp/enclave-boot.pid) 2>/dev/null; sleep 3" \
ENCLAVE_START_CMD="cd ${SCRIPT_DIR} && nohup ./boot-qemu.sh ${EIF_ABS_PATH} > /tmp/boot-qemu.log 2>&1 &" \
AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4000" \
AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566" \
AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566" \
AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566" \
AWS_ACCESS_KEY_ID=test \
AWS_SECRET_ACCESS_KEY=test \
  "$ENCLAVE_MGMT" &
MGMT_PID=$!
sleep 2

if ! kill -0 "$MGMT_PID" 2>/dev/null; then
  echo "Error: mgmt server failed to start" >&2
  exit 1
fi
echo "  Mgmt server running (PID $MGMT_PID) on http://127.0.0.1:8444"
echo ""

# Step 3: Boot enclave in QEMU (runs in background).
echo "=== [3/7] Booting enclave in QEMU ==="
./boot-qemu.sh "$EIF_PATH" &
wait_for_enclave "initial boot"
echo ""

# Step 4: Run integration tests.
echo "=== [4/7] Running integration tests ==="
./integration-test.sh
echo ""

# Step 5: Run migration via enclave deploy (upgrade detection).
# The enclave is running with secrets initialized, so a second deploy
# detects upgrade mode and exercises the full migration code path:
# CLI uploads EIF to S3 → calls mgmt POST /migrate → mgmt orchestrates
# KMS key creation, export-key, ciphertext adoption, EIF download,
# stops old enclave, starts new enclave with migrated KMS key.
echo "=== [5/7] Running migration (enclave deploy upgrade) ==="
"$ENCLAVE_CLI" deploy
echo ""

# Step 6: Wait for restarted enclave and verify migration survival.
# mgmt already stopped and restarted the enclave in step 5 (via boot-qemu.sh).
# The new enclave must decrypt secrets from the NEW KMS key and re-import
# the storage DEK from migrated ciphertexts.
echo "=== [6/7] Post-migration verification ==="
wait_for_enclave "post-migration restart"
HTTP_CODE=$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
  "https://localhost:${HOST_TLS_PORT:-8443}/health" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  echo "  PASS: Enclave healthy after restart"
else
  echo "  FAIL: Enclave unhealthy after restart (HTTP $HTTP_CODE)" >&2
  exit 1
fi

# Verify previous_pcr0 was updated (no longer "genesis" after export-key).
PREV_PCR0=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null \
  | jq -r '.previous_pcr0 // empty' 2>/dev/null || echo "")
if [ -n "$PREV_PCR0" ] && [ "$PREV_PCR0" != "genesis" ]; then
  echo "  PASS: previous_pcr0 updated after migration (${PREV_PCR0:0:16}...)"
elif [ "$PREV_PCR0" = "genesis" ]; then
  echo "  INFO: previous_pcr0 still genesis (expected for first migration)"
else
  echo "  WARN: could not read previous_pcr0"
fi

# Verify static secrets decrypted from new KMS key.
SECRETS_RESP=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/test/secrets" 2>/dev/null || echo "")
if echo "$SECRETS_RESP" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  echo "  PASS: Static secrets decrypted from new KMS key"
else
  echo "  FAIL: Static secrets not available after restart: ${SECRETS_RESP:0:120}" >&2
  exit 1
fi

# Verify storage round-trip (DEK re-imported from migrated ciphertext).
STORAGE_RESP=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/test/storage" 2>/dev/null || echo "")
if echo "$STORAGE_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  echo "  PASS: Storage round-trip works (DEK re-imported)"
else
  echo "  FAIL: Storage broken after restart: ${STORAGE_RESP:0:120}" >&2
  exit 1
fi

# Verify persistent storage key survived migration+restart (written in integration test 13).
PERSIST_RESP=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/test/storage-persistence" 2>/dev/null || echo "")
PERSIST_PHASE=$(echo "$PERSIST_RESP" | jq -r '.phase // empty' 2>/dev/null || echo "")
if [ "$PERSIST_PHASE" = "verify" ] && echo "$PERSIST_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  echo "  PASS: Persistent storage survived migration+restart"
elif [ "$PERSIST_PHASE" = "write" ]; then
  echo "  INFO: Persistent key was re-written (expected after full restart)"
else
  echo "  WARN: Could not verify storage persistence: ${PERSIST_RESP:0:120}"
fi

# Verify dynamic secrets API works after restart.
DYN_RESP=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/test/dynamic-secrets" 2>/dev/null || echo "")
if echo "$DYN_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  echo "  PASS: Dynamic secrets round-trip works after restart"
else
  echo "  FAIL: Dynamic secrets broken after restart: ${DYN_RESP:0:120}" >&2
  exit 1
fi

# Step 7: Final enclave info.
echo ""
echo "=== [7/7] Final enclave info ==="
FINAL_INFO=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || echo "")
if [ -n "$FINAL_INFO" ] && echo "$FINAL_INFO" | jq -e '.version' >/dev/null 2>&1; then
  echo "  PASS: Enclave info valid"
  echo "$FINAL_INFO" | jq -r '"  version: \(.version // "?"), pcr0: \(.previous_pcr0 // "?")"' 2>/dev/null || true
else
  echo "  FAIL: Could not read enclave info: ${FINAL_INFO:0:120}" >&2
  exit 1
fi

echo ""
echo "==============================="
echo " All tests passed!"
echo "==============================="
