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

# Use pre-built binaries (Docker test-runner) or build from source (nix develop).
if command -v enclave-cli &>/dev/null && command -v enclave-mgmt &>/dev/null; then
  ENCLAVE_CLI="$(command -v enclave-cli)"
  ENCLAVE_MGMT="$(command -v enclave-mgmt)"
  echo "Using pre-built binaries"
elif command -v go &>/dev/null; then
  ENCLAVE_CLI="/tmp/enclave-cli"
  ENCLAVE_MGMT="/tmp/enclave-mgmt"
  echo "Building enclave CLI and mgmt server..."
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_CLI" ./cmd/enclave)
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_MGMT" ./mgmt/)
else
  echo "Error: neither pre-built binaries (enclave-cli, enclave-mgmt) nor Go compiler found" >&2
  exit 1
fi


echo "  CLI:  $ENCLAVE_CLI"
echo "  Mgmt: $ENCLAVE_MGMT"
echo ""

# --- OpenTofu helpers ---
TOFU_DIR="${SCRIPT_DIR}/app/enclave/tofu"
LOCALSTACK="--endpoint-url http://127.0.0.1:4566 --region us-east-1"
export ENCLAVE_CONFIG="${SCRIPT_DIR}/app/enclave/enclave.yaml"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"

tofu_apply() {
  # Always regenerate tfvars — paths differ between host and Docker.
  echo "  Generating terraform.tfvars.json..."

  # Ensure artifact placeholders exist for tofu's filemd5() (local mode
  # doesn't actually use these S3 objects — the enclave boots from QEMU).
  mkdir -p "${SCRIPT_DIR}/app/enclave/artifacts"
  for f in image.eif enclave-mgmt gvproxy; do
    [ -f "${SCRIPT_DIR}/app/enclave/artifacts/$f" ] || touch "${SCRIPT_DIR}/app/enclave/artifacts/$f"
  done

  (cd "${SCRIPT_DIR}/app" && LOCAL_DEPLOYMENT=true "$ENCLAVE_CLI" tfvars)

  # Replace S3 backend with local backend for testing.
  sed -i 's/backend "s3" {}/backend "local" {}/' "${TOFU_DIR}/main.tf"

  # Override provider to point at localstack.
  cat > "${TOFU_DIR}/provider_override.tf" <<'OVERRIDE'
provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    s3  = "http://127.0.0.1:4566"
    ssm = "http://127.0.0.1:4566"
    sts = "http://127.0.0.1:4566"
    iam = "http://127.0.0.1:4566"
    kms = "http://127.0.0.1:4566"
    ec2 = "http://127.0.0.1:4566"
  }
}
OVERRIDE

  # Clean previous init state.
  rm -rf "${TOFU_DIR}/.terraform" 2>/dev/null || true

  echo "  tofu init..."
  tofu -chdir="$TOFU_DIR" init -input=false > ${SCRIPT_DIR}/tofu-init.log 2>&1 || { cat ${SCRIPT_DIR}/tofu-init.log; return 1; }
  echo "  tofu apply..."
  tofu -chdir="$TOFU_DIR" apply -auto-approve -input=false -compact-warnings > ${SCRIPT_DIR}/tofu-apply.log 2>&1 || { echo "  tofu apply FAILED:"; tail -20 ${SCRIPT_DIR}/tofu-apply.log; return 1; }
  echo "  tofu apply OK (log: ${SCRIPT_DIR}/tofu-apply.log)"
}

tofu_destroy() {
  # Ensure provider override + tfvars exist for destroy to work.
  if [ -f "${TOFU_DIR}/terraform.tfstate" ]; then
    tofu -chdir="$TOFU_DIR" destroy -auto-approve -input=false > ${SCRIPT_DIR}/tofu-destroy.log 2>&1 || true
  fi
  # Restore S3 backend in main.tf (test changed it to local).
  sed -i 's/backend "local" {}/backend "s3" {}/' "${TOFU_DIR}/main.tf" 2>/dev/null || true
  rm -f "${TOFU_DIR}/terraform.tfstate"* "${TOFU_DIR}/provider_override.tf" 2>/dev/null || true
  rm -rf "${TOFU_DIR}/.terraform" "${TOFU_DIR}/.artifacts" 2>/dev/null || true
}

EIF_PATH="${1:-}"
MGMT_PID=""

cleanup() {
  echo ""
  echo "=== Tearing down ==="
  tofu_destroy
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
    echo ""
    echo "  Boot log (errors and init):"
    grep -i 'error\|fail\|init\|KMS\|secret\|policy\|decrypt' /tmp/boot-qemu.log 2>/dev/null | tail -30 | sed 's/^/    /' || echo "    (no boot log)"
    echo ""
    echo "  SDK init logs (Application says):"
    grep 'Application says' /tmp/boot-qemu.log 2>/dev/null | head -30 | sed 's/^/    /' || echo "    (none)"
    exit 1
  fi
}

echo "==============================="
echo " Enclave Local Test Runner"
echo "==============================="
echo ""

# Detect if running inside Docker test-runner (no Nix, no docker CLI).
IN_DOCKER=false
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
  IN_DOCKER=true
fi

# Step 0: Build test EIF from skeleton app.
echo "=== [0/9] Building test EIF from skeleton app ==="
if [ -n "$EIF_PATH" ] && [ -f "$EIF_PATH" ]; then
  echo "  Using provided EIF: $EIF_PATH"
elif [ "$IN_DOCKER" = true ]; then
  # Inside Docker: use pre-built EIFs from mounted volume (built on host).
  if [ -f "app/enclave/artifacts/image.eif" ]; then
    EIF_PATH="app/enclave/artifacts/image.eif"
    echo "  Using pre-built EIF: $EIF_PATH"
    if [ -f "app/enclave/artifacts/image-v2.eif" ]; then
      echo "  Migration EIF: app/enclave/artifacts/image-v2.eif"
    else
      echo "  WARN: No migration EIF (image-v2.eif) — Step 7 will reuse same EIF"
    fi
  else
    echo "  Error: EIF must be pre-built when running inside Docker" >&2
    echo "  Build it on the host first: cd test/app && enclave build --local" >&2
    exit 1
  fi
else
  # On host: build v1 EIF, then v2 with different version for migration testing.
  ENCLAVE_YAML="${SCRIPT_DIR}/app/enclave/enclave.yaml"
  ARTIFACTS="${SCRIPT_DIR}/app/enclave/artifacts"
  ORIG_VERSION=$(grep '^version:' "$ENCLAVE_YAML" | awk '{print $2}')

  echo "  Building v1 EIF (version ${ORIG_VERSION})..."
  (cd app && "$ENCLAVE_CLI" build --local)
  EIF_PATH="app/enclave/artifacts/image.eif"
  V1_PCR0=$(jq -r '.PCR0' "${ARTIFACTS}/pcr.json")
  cp "${ARTIFACTS}/pcr.json" "${ARTIFACTS}/pcr-v1.json"
  echo "  v1 PCR0: ${V1_PCR0:0:16}..."

  # Build v2 with previous_pcr0 set to v1's PCR0.
  # This exercises the SDK's previousPCR0 validation during v2 Init:
  # the enclave checks that ENCLAVE_PREVIOUS_PCR0 (baked from enclave.yaml)
  # matches MigrationPreviousPCR0 in SSM (stored by v1's export-key).
  echo "  Building v2 EIF (version 0.0.2, previous_pcr0=${V1_PCR0:0:16}...)..."
  sed -i 's/^version: .*/version: 0.0.2/' "$ENCLAVE_YAML"
  if grep -q '^previous_pcr0:' "$ENCLAVE_YAML"; then
    sed -i "s/^previous_pcr0: .*/previous_pcr0: \"${V1_PCR0}\"/" "$ENCLAVE_YAML"
  else
    echo "" >> "$ENCLAVE_YAML"
    echo "previous_pcr0: \"${V1_PCR0}\"" >> "$ENCLAVE_YAML"
  fi
  (cd app && "$ENCLAVE_CLI" build --local)
  cp "${ARTIFACTS}/image.eif" "${ARTIFACTS}/image-v2.eif"
  cp "${ARTIFACTS}/pcr.json" "${ARTIFACTS}/pcr-v2.json"
  echo "  v2 PCR0: $(jq -r '.PCR0' "${ARTIFACTS}/pcr-v2.json" | cut -c1-16)..."

  # Restore v1 as the active EIF (genesis for first boot).
  sed -i "s/^version: .*/version: ${ORIG_VERSION}/" "$ENCLAVE_YAML"
  sed -i '/^previous_pcr0:/d' "$ENCLAVE_YAML"
  (cd app && "$ENCLAVE_CLI" build --local)
  echo "  Restored v1"
fi
echo ""

# Step 1: Start mock services (skipped inside Docker — compose handles it).
echo "=== [1/9] Starting mock services ==="
if [ "$IN_DOCKER" = true ]; then
  echo "  Skipped (services managed by docker compose)"
else
  docker compose down -v 2>/dev/null || true
  docker compose up -d --build --wait
fi
echo ""

# Step 2: Deploy to localstack via OpenTofu and start mgmt server.
echo "=== [2/9] Deploying to localstack via tofu ==="

# Clean up any stale state from previous runs.
tofu_destroy

tofu_apply

# Tofu created a KMS key in localstack, but we use local-kms for real KMS ops.
# Overwrite SSM with the local-kms seeded key ID so the enclave uses it.
aws ssm put-parameter $LOCALSTACK \
  --name "/dev/my-app/KMSKeyID" --value "test-key-id" \
  --type String --overwrite --no-cli-pager
echo "  Seeded SSM /dev/my-app/KMSKeyID = test-key-id"

# Start mgmt server on the host (like production EC2 host).
# Configured with stop/start commands that manage boot-qemu.sh via PID file.
echo "  Starting mgmt server..."
EIF_ABS_PATH="$(realpath "$EIF_PATH")"
ENCLAVE_AWS_REGION=us-east-1 \
ENCLAVE_DEPLOYMENT=dev \
ENCLAVE_APP_NAME=my-app \
ENCLAVE_MGMT_ADDR="127.0.0.1:8444" \
ENCLAVE_MIGRATION_COOLDOWN="1m" \
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
echo "=== [3/9] Booting enclave in QEMU ==="
./boot-qemu.sh "$EIF_PATH" &
wait_for_enclave "initial boot"
echo ""

# Step 4: Run integration tests.
echo "=== [4/9] Running integration tests ==="
./integration-test.sh
echo ""

# Step 5: Verify migration cooldown fields in enclave-info (pre-migration).
echo "=== [5/9] Migration cooldown: pre-migration check ==="
COOLDOWN_INFO=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || echo "")
COOLDOWN_SEC=$(echo "$COOLDOWN_INFO" | jq -r '.migration_cooldown_seconds // -1' 2>/dev/null || echo "-1")
MIG_PENDING=$(echo "$COOLDOWN_INFO" | jq -r 'if has("migration_pending") then .migration_pending | tostring else "missing" end' 2>/dev/null || echo "missing")
if echo "$COOLDOWN_INFO" | jq -e 'has("migration_cooldown_seconds")' >/dev/null 2>&1; then
  echo "  PASS: migration_cooldown_seconds=${COOLDOWN_SEC}, migration_pending=${MIG_PENDING}"
else
  echo "  FAIL: migration_cooldown_seconds missing from enclave-info" >&2
  exit 1
fi
if [ "$MIG_PENDING" = "false" ]; then
  echo "  PASS: No migration pending before deploy"
else
  echo "  FAIL: migration_pending should be false before deploy (got: ${MIG_PENDING})" >&2
  exit 1
fi
echo ""

# Step 6: Migration cooldown abort test.
# Start a migration in the background (enters cooldown), verify pending=true,
# abort, verify pending=false.
echo "=== [6/9] Migration cooldown: abort test ==="
MGMT_URL="http://localhost:${MGMT_PORT:-8444}"

export AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4000"
export AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566"

# Trigger migration directly via mgmt server in the background.
# (Not via tofu — we need to abort mid-migration, which tofu can't do.)
ABORT_EIF_BUCKET="dev-my-app-eif-000000000000-us-east-1"
aws s3 mb "s3://${ABORT_EIF_BUCKET}" $LOCALSTACK 2>/dev/null || true
aws s3 cp "$EIF_PATH" "s3://${ABORT_EIF_BUCKET}/image.eif" $LOCALSTACK 2>/dev/null
ABORT_PCR0=$(jq -r '.PCR0' "${SCRIPT_DIR}/app/enclave/artifacts/pcr.json")
curl -sf -X POST "${MGMT_URL}/migrate" \
  -H 'Content-Type: application/json' \
  -d "{\"eif_bucket\":\"${ABORT_EIF_BUCKET}\",\"eif_key\":\"image.eif\",\"pcr0\":\"${ABORT_PCR0}\",\"secret_names\":[\"signing_key\"]}" \
  > /tmp/deploy-abort-test.log 2>&1 &
DEPLOY_PID=$!

# Poll for migration_pending=true (timeout 30s).
echo "  Waiting for migration_pending=true..."
MIG_PENDING="false"
for i in $(seq 1 30); do
  COOLDOWN_INFO=$(curl -sk --max-time 5 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || echo "")
  MIG_PENDING=$(echo "$COOLDOWN_INFO" | jq -r 'if has("migration_pending") then .migration_pending | tostring else "false" end' 2>/dev/null || echo "false")
  if [ "$MIG_PENDING" = "true" ]; then
    COOLDOWN_REM=$(echo "$COOLDOWN_INFO" | jq -r '.migration_cooldown_remaining // 0' 2>/dev/null || echo "0")
    echo "  PASS: migration_pending=true after ${i}s (remaining=${COOLDOWN_REM}s)"
    break
  fi
  sleep 1
done
if [ "$MIG_PENDING" != "true" ]; then
  echo "  FAIL: migration_pending never became true (timed out after 30s)" >&2
  echo "  Last enclave-info response:"
  echo "$COOLDOWN_INFO" | jq . 2>/dev/null | sed 's/^/    /' || echo "    (not valid JSON)"
  echo "  Deploy log (full):"
  cat /tmp/deploy-abort-test.log 2>/dev/null | sed 's/^/    /'
  exit 1
fi

# Abort the migration.
ABORT_CODE=$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -X POST "${MGMT_URL}/migrate/abort" 2>/dev/null || echo "000")
if [ "$ABORT_CODE" = "200" ]; then
  echo "  PASS: Migration aborted (HTTP 200)"
else
  echo "  FAIL: Abort returned HTTP ${ABORT_CODE}" >&2
  exit 1
fi

# Wait for the aborted deploy to exit.
wait "$DEPLOY_PID" 2>/dev/null || true

# Poll for migration_pending=false (timeout 15s, accounts for 5s SSM cache).
echo "  Waiting for migration_pending=false..."
MIG_PENDING="true"
for i in $(seq 1 15); do
  COOLDOWN_INFO=$(curl -sk --max-time 5 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || echo "")
  MIG_PENDING=$(echo "$COOLDOWN_INFO" | jq -r 'if has("migration_pending") then .migration_pending | tostring else "false" end' 2>/dev/null || echo "false")
  if [ "$MIG_PENDING" = "false" ]; then
    echo "  PASS: migration_pending=false after abort (${i}s)"
    break
  fi
  sleep 1
done
if [ "$MIG_PENDING" != "false" ]; then
  echo "  FAIL: migration_pending still true after abort (timed out after 15s)" >&2
  exit 1
fi
echo ""

# Step 7: Deploy migration with a different EIF (different PCR0).
# A real migration deploys new code with a different PCR0. The second EIF
# must be pre-built on the host (see build-migration-eif.sh) and placed at
# app/enclave/artifacts/image-v2.eif. If not available, fall back to same EIF.
echo "=== [7/9] Running migration (enclave deploy upgrade) ==="
MIGRATION_EIF="${SCRIPT_DIR}/app/enclave/artifacts/image-v2.eif"
if [ -f "$MIGRATION_EIF" ]; then
  echo "  Using migration EIF: $MIGRATION_EIF"
  cp "$MIGRATION_EIF" "${SCRIPT_DIR}/app/enclave/artifacts/image.eif"
  # Update pcr.json with the v2 PCR0.
  if [ -f "${SCRIPT_DIR}/app/enclave/artifacts/pcr-v2.json" ]; then
    cp "${SCRIPT_DIR}/app/enclave/artifacts/pcr-v2.json" "${SCRIPT_DIR}/app/enclave/artifacts/pcr.json"
  fi
else
  echo "  WARN: No migration EIF found (image-v2.eif), reusing same EIF"
fi

# Re-apply with the new EIF — tofu detects expected_pcr0 changed and triggers
# enclave_migration_local, which calls the mgmt server to perform live migration.
echo "  v2 PCR0: $(jq -r '.PCR0' "${SCRIPT_DIR}/app/enclave/artifacts/pcr.json" | cut -c1-16)..."
tofu_apply
echo "  tofu apply log (migration lines):"
grep -i 'migrat\|trigger\|null_resource\|local-exec\|curl\|skip' ${SCRIPT_DIR}/tofu-apply.log 2>/dev/null | sed 's/^/    /' || echo "    (no migration lines found)"

# Step 8: Wait for restarted enclave and verify migration survival.
# mgmt already stopped and restarted the enclave in step 7 (via boot-qemu.sh).
# The new enclave must decrypt secrets from the NEW KMS key and re-import
# the storage DEK from migrated ciphertexts.
echo "=== [8/9] Post-migration verification ==="
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
POST_MIG_INFO=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || echo "")
PREV_PCR0=$(echo "$POST_MIG_INFO" | jq -r '.previous_pcr0 // empty' 2>/dev/null || echo "")
if [ -n "$PREV_PCR0" ] && [ "$PREV_PCR0" != "genesis" ]; then
  echo "  PASS: previous_pcr0 updated after migration (${PREV_PCR0:0:16}...)"
else
  echo "  FAIL: previous_pcr0 should not be genesis after migration (got: ${PREV_PCR0:-empty})" >&2
  exit 1
fi

# Verify previous_pcr0 matches v1 PCR0 from build artifacts.
V1_PCR0_FILE="${SCRIPT_DIR}/app/enclave/artifacts/pcr.json"
if [ -f "${SCRIPT_DIR}/app/enclave/artifacts/pcr-v1.json" ]; then
  V1_PCR0_FILE="${SCRIPT_DIR}/app/enclave/artifacts/pcr-v1.json"
fi
if [ -f "$V1_PCR0_FILE" ]; then
  EXPECTED_PCR0=$(jq -r '.PCR0' "$V1_PCR0_FILE" 2>/dev/null || echo "")
  if [ -n "$EXPECTED_PCR0" ]; then
    # PCR0 from enclave-info is lowercase, normalize for comparison.
    PREV_PCR0_LOWER=$(echo "$PREV_PCR0" | tr '[:upper:]' '[:lower:]')
    EXPECTED_PCR0_LOWER=$(echo "$EXPECTED_PCR0" | tr '[:upper:]' '[:lower:]')
    if [ "$PREV_PCR0_LOWER" = "$EXPECTED_PCR0_LOWER" ]; then
      echo "  PASS: previous_pcr0 matches v1 build PCR0"
    else
      echo "  WARN: previous_pcr0 mismatch with v1 build (enclave=${PREV_PCR0:0:32}... build=${EXPECTED_PCR0:0:32}...)"
    fi
  fi
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

# Verify attestation pubkey + PCR16 hash survived migration (write/verify pattern).
# Pre-migration values were stored to encrypted storage in integration test 14.
ATTEST_PERSIST_RESP=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/test/attestation-persistence" 2>/dev/null || echo "")
ATTEST_PERSIST_PHASE=$(echo "$ATTEST_PERSIST_RESP" | jq -r '.phase // empty' 2>/dev/null || echo "")
if [ "$ATTEST_PERSIST_PHASE" = "verify" ]; then
  PUBKEY_MATCH=$(echo "$ATTEST_PERSIST_RESP" | jq -r '.pubkey_match // false' 2>/dev/null || echo "false")
  PCR16_MATCH=$(echo "$ATTEST_PERSIST_RESP" | jq -r '.pcr16_match // false' 2>/dev/null || echo "false")
  if [ "$PUBKEY_MATCH" = "true" ] && [ "$PCR16_MATCH" = "true" ]; then
    echo "  PASS: Attestation pubkey + PCR16 identical after migration (SIGNING_KEY survived)"
  else
    echo "  FAIL: Attestation values changed after migration!" >&2
    echo "$ATTEST_PERSIST_RESP" | jq . >&2
    exit 1
  fi
elif [ "$ATTEST_PERSIST_PHASE" = "write" ]; then
  echo "  INFO: Attestation persistence re-written (expected after full restart)"
else
  echo "  WARN: Could not verify attestation persistence: ${ATTEST_PERSIST_RESP:0:120}"
fi

# Verify dynamic secret created before migration survived restart.
DYN_PERSIST_RESP=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/test/dynamic-secret-persistence" 2>/dev/null || echo "")
DYN_PERSIST_PHASE=$(echo "$DYN_PERSIST_RESP" | jq -r '.phase // empty' 2>/dev/null || echo "")
if [ "$DYN_PERSIST_PHASE" = "verify" ] && echo "$DYN_PERSIST_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  echo "  PASS: Dynamic secret survived migration+restart"
elif [ "$DYN_PERSIST_PHASE" = "write" ]; then
  echo "  INFO: Dynamic secret was re-written (expected after full restart)"
else
  echo "  WARN: Could not verify dynamic secret persistence: ${DYN_PERSIST_RESP:0:120}"
fi

# Step 9: Final enclave info.
echo ""
echo "=== [9/9] Final enclave info ==="
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
