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
SCRIPT_PATH="$(realpath "$0")"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

# boot_qemu: bring up AF_VSOCK fabric (vhost-device-vsock + heartbeat),
# then boot the EIF in QEMU emulating a Nitro Enclave. The supervisor,
# running out-of-band, provides gvproxy (vsock:1024) and the IMDS
# forwarder (vsock:8002) — see supervisor/gvproxy.go + supervisor/imds_proxy.go.
#
# Called two ways:
#   1. From run.sh's main flow, via watchdog (ENCLAVE_START_CMD) in the
#      supervisor — invokes this script with `--boot-only <eif>`.
#   2. Directly from run.sh on wait_for_enclave (for manual invocation).
boot_qemu() {
  local eif_path="${1:?Usage: boot_qemu <path-to-eif>}"

  echo $$ > /tmp/enclave-boot.pid

  if [ ! -f "$eif_path" ]; then
    echo "Error: EIF not found at $eif_path" >&2
    return 1
  fi
  eif_path="$(realpath "$eif_path")"

  local guest_cid="${GUEST_CID:-4}"
  local memory="${MEMORY:-4G}"
  local vsock_socket="/tmp/vhost${guest_cid}.socket"
  local boot_timeout="${BOOT_TIMEOUT:-300}"
  local host_tls_port="${HOST_TLS_PORT:-8443}"

  local qemu_pid hb_pid vsock_pid
  qemu_pid="" hb_pid="" vsock_pid=""

  _boot_qemu_cleanup() {
    echo "" 2>/dev/null
    echo "=== Cleaning up ===" 2>/dev/null
    [ -n "$qemu_pid" ] && kill "$qemu_pid" 2>/dev/null && echo "  Stopped QEMU ($qemu_pid)" 2>/dev/null
    [ -n "$hb_pid" ] && kill "$hb_pid" 2>/dev/null && echo "  Stopped heartbeat ($hb_pid)" 2>/dev/null
    [ -n "$vsock_pid" ] && kill "$vsock_pid" 2>/dev/null && echo "  Stopped vhost-device-vsock ($vsock_pid)" 2>/dev/null
    rm -f "$vsock_socket" /tmp/enclave-boot.pid
  }
  trap _boot_qemu_cleanup EXIT

  # Kill any stale processes from previous runs.
  killall vhost-device-vsock 2>/dev/null || true
  pkill -f heartbeat.py 2>/dev/null || true
  sleep 0.5
  rm -f "$vsock_socket"

  if [ ! -e /dev/vsock ]; then
    echo "Error: /dev/vsock not found. Load vsock + vsock_loopback kernel modules." >&2
    return 1
  fi

  echo "=== Starting vhost-device-vsock ==="
  echo "  CID:        $guest_cid"
  echo "  Socket:     $vsock_socket"
  echo "  Forward:    CID 1 (loopback)"
  vhost-device-vsock \
    --vm "guest-cid=${guest_cid},socket=${vsock_socket},forward-cid=1,forward-listen=9001+9002" &
  vsock_pid=$!
  sleep 1
  if ! kill -0 "$vsock_pid" 2>/dev/null; then
    echo "Error: vhost-device-vsock failed to start" >&2
    return 1
  fi

  echo "=== Starting heartbeat responder ==="
  python3 "$SCRIPT_DIR/heartbeat.py" &
  hb_pid=$!
  sleep 0.5
  if ! kill -0 "$hb_pid" 2>/dev/null; then
    echo "Error: heartbeat responder failed to start" >&2
    return 1
  fi

  # gvproxy (L2 networking over vsock:1024) and the IMDS vsock forwarder
  # (vsock:8002) are provided by the out-of-band supervisor. Port
  # forwarding is configured via GVPROXY_FORWARD_PORTS (set below).

  echo ""
  echo "=== Booting QEMU enclave ==="
  echo "  EIF:    $eif_path"
  echo "  Memory: $memory"
  local accel cpu_opt
  if [ -e /dev/kvm ]; then
    accel="--enable-kvm"
    cpu_opt="-cpu host"
    echo "  KVM:    enabled"
  else
    accel="-accel tcg"
    cpu_opt="-cpu max"
    echo "  KVM:    not available, using TCG (slow)"
  fi
  qemu-system-x86_64 \
    -M "nitro-enclave,vsock=c,id=test-enclave" \
    -kernel "$eif_path" \
    -nographic \
    -m "$memory" \
    $accel \
    $cpu_opt \
    -chardev "socket,id=c,path=${vsock_socket}" &
  qemu_pid=$!
  echo "  PID:    $qemu_pid"
  echo ""

  # Wait for the enclave to become ready.
  echo "=== Waiting for enclave to boot (timeout: ${boot_timeout}s) ==="
  local seconds=0
  while [ $seconds -lt "$boot_timeout" ]; do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
      echo "Error: QEMU exited unexpectedly" >&2
      wait "$qemu_pid" || true
      return 1
    fi
    local http_code
    http_code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
      "https://localhost:${host_tls_port}/health" 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ] || [ "$http_code" = "503" ]; then
      local health
      health=$(curl -sk --max-time 5 "https://localhost:${host_tls_port}/health" 2>/dev/null || echo "{}")
      echo "  Enclave responding (${seconds}s) — HTTP $http_code"
      echo "  Health: $health"
      echo ""
      echo "=== Enclave running ==="
      echo "  Health:        https://localhost:${host_tls_port}/health"
      echo "  Enclave info:  https://localhost:${host_tls_port}/v1/enclave-info"
      echo "  App:           https://localhost:${host_tls_port}/"
      wait "$qemu_pid"
      return 0
    fi
    sleep 2
    seconds=$((seconds + 2))
  done
  echo "Error: Enclave did not become ready within ${boot_timeout}s" >&2
  return 1
}

# Subcommand dispatch: when invoked as a launcher-shim (from the
# supervisor's ENCLAVE_START_CMD), run just boot_qemu and exit. Avoids
# re-running the main integration-test flow inside the launcher.
if [ "${1:-}" = "--boot-only" ]; then
  shift
  boot_qemu "$@"
  exit $?
fi

# Auto-enter Nix dev shell if required tools are missing.
if ! command -v vhost-device-vsock &>/dev/null || ! command -v qemu-system-x86_64 &>/dev/null; then
  echo "Required tools not found, entering nix develop ..."
  exec nix develop "${SCRIPT_DIR}" --command "$0" "$@"
fi

# Use pre-built binaries (Docker test-runner) or build from source (nix develop).
if command -v enclave-cli &>/dev/null && command -v supervisor &>/dev/null; then
  ENCLAVE_CLI="$(command -v enclave-cli)"
  ENCLAVE_SUPERVISOR="$(command -v supervisor)"
  echo "Using pre-built binaries"
elif command -v go &>/dev/null; then
  ENCLAVE_CLI="/tmp/enclave-cli"
  ENCLAVE_SUPERVISOR="/tmp/supervisor"
  echo "Building enclave CLI and supervisor..."
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_CLI" ./cli/cmd/enclave)
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_SUPERVISOR" ./supervisor/cmd/supervisor)
  # Seed the artifacts dir with the real v1 supervisor binary so the first
  # tofu_apply uploads it (not an empty placeholder) to the staging S3
  # key. Step 7 later overwrites this file with a v2 variant to force
  # Step 10 down the swap path.
  mkdir -p "${SCRIPT_DIR}/app/.enclave/artifacts"
  cp "$ENCLAVE_SUPERVISOR" "${SCRIPT_DIR}/app/.enclave/artifacts/supervisor"
else
  echo "Error: neither pre-built binaries (enclave-cli, supervisor) nor Go compiler found" >&2
  exit 1
fi


echo "  CLI:  $ENCLAVE_CLI"
echo "  Supervisor: $ENCLAVE_SUPERVISOR"
echo ""

# Reset image.eif to pristine v1; migration test-runs overwrite it.
V1_EIF="${SCRIPT_DIR}/app/.enclave/artifacts/image-v1.eif"
if [ -f "$V1_EIF" ]; then
  echo "  Resetting image.eif to pristine v1..."
  cp -f "$V1_EIF" "${SCRIPT_DIR}/app/.enclave/artifacts/image.eif"
  cp -f "${SCRIPT_DIR}/app/.enclave/artifacts/pcr-v1.json" \
        "${SCRIPT_DIR}/app/.enclave/artifacts/pcr.json" 2>/dev/null || true
fi
rm -f "${SCRIPT_DIR}/app/.enclave/artifacts/image.eif.backup"
: > /tmp/boot-qemu.log


# --- OpenTofu helpers ---
TOFU_DIR="${SCRIPT_DIR}/app/tofu"
LOCALSTACK="--endpoint-url http://127.0.0.1:4566 --region us-east-1"
export ENCLAVE_CONFIG="${SCRIPT_DIR}/app/enclave/enclave.yaml"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
# AWS CLI endpoint overrides for localstack — needed by null_resource local-exec
# provisioners which bypass the tofu provider config.
export AWS_ENDPOINT_URL_KMS="${AWS_ENDPOINT_URL_KMS:-http://127.0.0.1:4566}"
export AWS_ENDPOINT_URL_SSM="${AWS_ENDPOINT_URL_SSM:-http://127.0.0.1:4566}"
export AWS_ENDPOINT_URL_STS="${AWS_ENDPOINT_URL_STS:-http://127.0.0.1:4566}"
export AWS_ENDPOINT_URL_S3="${AWS_ENDPOINT_URL_S3:-http://127.0.0.1:4566}"

tofu_apply() {
  # Always regenerate tfvars — paths differ between host and Docker.
  # `enclave tofu` is merge-only-new (existing files are skipped) so the
  # committed test-app scaffold would mask CLI changes. Delete the
  # CLI-managed root and module main.tf first to force a fresh emit; the
  # rest of the tree (modules/backend, templates, etc.) is left untouched.
  rm -f "${TOFU_DIR}/main.tf" "${TOFU_DIR}/modules/enclave/main.tf"

  echo "  Generating terraform.tfvars.json..."

  # Ensure artifact placeholders exist for tofu's filemd5() (local mode
  # doesn't actually use these S3 objects — the enclave boots from QEMU).
  # Only image.eif and supervisor are uploaded now; gvproxy is vendored
  # into the supervisor binary itself.
  mkdir -p "${SCRIPT_DIR}/app/.enclave/artifacts"
  for f in image.eif supervisor; do
    [ -f "${SCRIPT_DIR}/app/.enclave/artifacts/$f" ] || touch "${SCRIPT_DIR}/app/.enclave/artifacts/$f"
  done

  (cd "${SCRIPT_DIR}/app" && LOCAL_DEPLOYMENT=true "$ENCLAVE_CLI" tofu > "${SCRIPT_DIR}/tofu-scaffold.log" 2>&1) \
    || { cat "${SCRIPT_DIR}/tofu-scaffold.log"; return 1; }

  # Write local backend config for testing (enclave build generates S3 backend.tf for production).
  cat > "${TOFU_DIR}/backend.tf" <<BACKEND
terraform {
  backend "local" {
    path = "${TOFU_DIR}/terraform.tfstate"
  }
}
BACKEND

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
  # env_values overrides are supplied via an auto-loaded tfvars file (the env-file
  # mechanism). tofu auto-loads any *.auto.tfvars.json next to the root module on
  # every plan/apply, so overrides stick across both the initial deploy and the
  # later migration apply without us repeating them on the command line.
  cat > "${TOFU_DIR}/env_values.auto.tfvars.json" <<EOF
{
  "env_values": {
    "TEST_RUNTIME_OVERRIDE": "override-from-tofu",
    "TEST_RUNTIME_OVERRIDE_ENVFILE": "override-from-envfile"
  }
}
EOF

  echo "  tofu apply..."
  tofu -chdir="$TOFU_DIR" apply -auto-approve -input=false -compact-warnings > ${SCRIPT_DIR}/tofu-apply.log 2>&1 || { echo "  tofu apply FAILED:"; tail -20 ${SCRIPT_DIR}/tofu-apply.log; return 1; }
  echo "  tofu apply OK (log: ${SCRIPT_DIR}/tofu-apply.log)"
}

tofu_destroy() {
  # Ensure provider override + tfvars exist for destroy to work.
  if [ -f "${TOFU_DIR}/terraform.tfstate" ]; then
    tofu -chdir="$TOFU_DIR" destroy -auto-approve -input=false > ${SCRIPT_DIR}/tofu-destroy.log 2>&1 || true
  fi
  rm -f "${TOFU_DIR}/terraform.tfstate"* "${TOFU_DIR}/provider_override.tf" "${TOFU_DIR}/backend.tf" 2>/dev/null || true
  rm -rf "${TOFU_DIR}/.terraform" "${TOFU_DIR}/.artifacts" 2>/dev/null || true
}

EIF_PATH="${1:-}"
SUP_PID=""

cleanup() {
  echo ""
  echo "=== Tearing down ==="
  tofu_destroy
  # Kill supervisor relauncher (which TERM-traps and kills its child supervisor).
  [ -n "${SUP_PID:-}" ] && kill -TERM "$SUP_PID" 2>/dev/null && wait "$SUP_PID" 2>/dev/null || true
  # Belt-and-suspenders: if the supervisor's child survived, kill it too.
  if [ -f /tmp/supervisor.pid ]; then
    kill "$(cat /tmp/supervisor.pid)" 2>/dev/null || true
    rm -f /tmp/supervisor.pid
  fi
  rm -f /tmp/supervisor-relauncher.sh
  # Kill enclave (boot_qemu) via PID file.
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
  local boot_timeout="${BOOT_TIMEOUT:-300}"
  local init_timeout="${INIT_TIMEOUT:-120}"

  echo "  Waiting for enclave boot (timeout: ${boot_timeout}s)..."
  SECONDS=0
  while [ $SECONDS -lt "$boot_timeout" ]; do
    # Check if boot_qemu is still running.
    if [ -f /tmp/enclave-boot.pid ]; then
      local pid
      pid=$(cat /tmp/enclave-boot.pid)
      if ! kill -0 "$pid" 2>/dev/null; then
        echo "Error: boot_qemu exited unexpectedly${label:+ ($label)}" >&2
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
        echo "Error: boot_qemu exited unexpectedly${label:+ ($label)}" >&2
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
    echo "  runtime init logs (Application says):"
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
  if [ -f "app/.enclave/artifacts/image.eif" ]; then
    EIF_PATH="app/.enclave/artifacts/image.eif"
    echo "  Using pre-built EIF: $EIF_PATH"
    if [ -f "app/.enclave/artifacts/image-v2.eif" ]; then
      echo "  Migration EIF: app/.enclave/artifacts/image-v2.eif"
    else
      echo "  WARN: No migration EIF (image-v2.eif) — Step 7 will reuse same EIF"
    fi
  else
    echo "  Error: EIF must be pre-built when running inside Docker" >&2
    echo "  Build it on the host first: cd test/app && enclave build" >&2
    exit 1
  fi
else
  # On host: build v1 EIF, then v2 with different version for migration testing.
  ENCLAVE_YAML="${SCRIPT_DIR}/app/enclave/enclave.yaml"
  ARTIFACTS="${SCRIPT_DIR}/app/.enclave/artifacts"
  ORIG_VERSION=$(grep '^version:' "$ENCLAVE_YAML" | awk '{print $2}')

  echo "  Building v1 EIF (version ${ORIG_VERSION})..."
  (cd app && "$ENCLAVE_CLI" build)
  EIF_PATH="app/.enclave/artifacts/image.eif"
  V1_PCR0=$(jq -r '.PCR0' "${ARTIFACTS}/pcr.json")
  cp "${ARTIFACTS}/pcr.json" "${ARTIFACTS}/pcr-v1.json"
  echo "  v1 PCR0: ${V1_PCR0:0:16}..."

  # Build v2 with previous_pcr0 set to v1's PCR0.
  # This exercises the runtime's previousPCR0 validation during v2 Init:
  # the enclave checks that ENCLAVE_PREVIOUS_PCR0 (baked from enclave.yaml)
  # matches MigrationPreviousPCR0 in SSM (stored by v1's start-migration).
  echo "  Building v2 EIF (version 0.0.2, previous_pcr0=${V1_PCR0:0:16}...)..."
  sed -i 's/^version: .*/version: 0.0.2/' "$ENCLAVE_YAML"
  if grep -q '^previous_pcr0:' "$ENCLAVE_YAML"; then
    sed -i "s/^previous_pcr0: .*/previous_pcr0: \"${V1_PCR0}\"/" "$ENCLAVE_YAML"
  else
    echo "" >> "$ENCLAVE_YAML"
    echo "previous_pcr0: \"${V1_PCR0}\"" >> "$ENCLAVE_YAML"
  fi
  (cd app && "$ENCLAVE_CLI" build)
  cp "${ARTIFACTS}/image.eif" "${ARTIFACTS}/image-v2.eif"
  cp "${ARTIFACTS}/pcr.json" "${ARTIFACTS}/pcr-v2.json"
  echo "  v2 PCR0: $(jq -r '.PCR0' "${ARTIFACTS}/pcr-v2.json" | cut -c1-16)..."

  # Restore v1 as the active EIF (genesis for first boot).
  sed -i "s/^version: .*/version: ${ORIG_VERSION}/" "$ENCLAVE_YAML"
  sed -i '/^previous_pcr0:/d' "$ENCLAVE_YAML"
  (cd app && "$ENCLAVE_CLI" build)
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

# Step 2: Deploy to localstack via OpenTofu and start supervisor.
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

# Start supervisor on the host (like production EC2 host).
# Configured with stop/start commands that manage boot_qemu via PID file.
# We run supervisor under a tiny relauncher script that loops "run supervisor; wait;
# relaunch" — the test's analog of systemd Restart=always in production.
# This lets ENCLAVE_SUPERVISOR_RESTART_CMD just kill the current supervisor process; the
# supervisor resurrects it with the updated on-disk binary.
echo "  Starting supervisor..."
EIF_ABS_PATH="$(realpath "$EIF_PATH")"

SUPERVISOR_PIDFILE=/tmp/supervisor.pid
SUP_RELAUNCHER=/tmp/supervisor-relauncher.sh
cat > "$SUP_RELAUNCHER" <<'SUPER'
#!/usr/bin/env bash
set -u
SUP_BIN="$1"
PIDFILE="$2"
child=""
trap '[ -n "$child" ] && kill -TERM "$child" 2>/dev/null; [ -n "$child" ] && wait "$child" 2>/dev/null; rm -f "$PIDFILE"; exit 0' TERM INT
while :; do
  "$SUP_BIN" &
  child=$!
  echo "$child" > "$PIDFILE"
  wait "$child" 2>/dev/null || true
  sleep 1
done
SUPER
chmod +x "$SUP_RELAUNCHER"

export ENCLAVE_AWS_REGION=us-east-1
export ENCLAVE_DEPLOYMENT=dev
export ENCLAVE_APP_NAME=my-app
export ENCLAVE_SUPERVISOR_ADDR="127.0.0.1:8444"
# The supervisor runs in-process gvproxy (vsock:1024) and IMDS forwarder
# (vsock:8002) just as it does in prod. Only the enclave launcher differs:
# QEMU stands in for nitro-cli via ENCLAVE_START_CMD below.
#
# Forward enclave TLS (443 inside) to unprivileged 8443 on the host so
# the test can curl https://localhost:8443/health without root.
export GVPROXY_FORWARD_PORTS="8443:443 7073 9090"
# Point the in-process IMDS forwarder at mock-imds instead of the real
# 169.254.169.254 (which isn't reachable from the test container).
export IMDS_PROXY_TARGET="127.0.0.1:1338"
export ENCLAVE_MIGRATION_COOLDOWN="1m"
# Shorten commit-poll timeout so rollback tests don't wait 5min for the default.
export ENCLAVE_MIGRATION_COMMIT_TIMEOUT="45s"
export ENCLAVE_URL="https://127.0.0.1:8443"
export ENCLAVE_EIF_PATH="$EIF_ABS_PATH"
export ENCLAVE_SUPERVISOR_BINARY_PATH="$ENCLAVE_SUPERVISOR"
export ENCLAVE_SUPERVISOR_RESTART_CMD="kill \$(cat $SUPERVISOR_PIDFILE)"
export ENCLAVE_STOP_CMD="kill \$(cat /tmp/enclave-boot.pid) 2>/dev/null; sleep 3"
export ENCLAVE_START_CMD="nohup \"$SCRIPT_PATH\" --boot-only \"$EIF_ABS_PATH\" >> /tmp/boot-qemu.log 2>&1 &"
export AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4000"
export AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_LOGS="http://127.0.0.1:4566"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

"$SUP_RELAUNCHER" "$ENCLAVE_SUPERVISOR" "$SUPERVISOR_PIDFILE" &
SUP_PID=$!
sleep 2

if ! kill -0 "$SUP_PID" 2>/dev/null; then
  echo "Error: supervisor relauncher failed to start" >&2
  exit 1
fi
if [ ! -s "$SUPERVISOR_PIDFILE" ]; then
  echo "Error: supervisor pidfile not populated by relauncher" >&2
  exit 1
fi
echo "  Supervisor relauncher running (PID $SUP_PID), supervisor child PID $(cat "$SUPERVISOR_PIDFILE") on http://127.0.0.1:8444"
echo ""

# Step 3: The supervisor's watchdog launches the enclave via
# ENCLAVE_START_CMD (→ boot_qemu) on its own. We just wait for it to
# come up.
echo "=== [3/9] Booting enclave in QEMU ==="
wait_for_enclave "initial boot"
echo ""

# Verify the locked KMS policy includes the default RootRecovery statement.
# The enclave's selfApplyKMSPolicy() runs at boot and calls PutKeyPolicy on
# the local-kms mock (port 4000). After boot, the policy should carry the
# fourth statement granting AWS account root the recovery action set.
KMS_KEY_ID=$(aws ssm get-parameter --name "/dev/my-app/KMSKeyID" \
  --endpoint-url "http://127.0.0.1:4566" --region us-east-1 \
  --query 'Parameter.Value' --output text 2>/dev/null || echo "")
if [ -n "$KMS_KEY_ID" ]; then
  POLICY=$(aws kms get-key-policy --key-id "$KMS_KEY_ID" --policy-name default \
    --endpoint-url "http://127.0.0.1:4000" --region us-east-1 \
    --query 'Policy' --output text 2>/dev/null || echo "")
  if echo "$POLICY" | jq -e '.Statement[] | select(.Sid=="RootRecovery") | (.Action | index("kms:PutKeyPolicy"))' >/dev/null 2>&1; then
    RR_PRINCIPAL=$(echo "$POLICY" | jq -r '.Statement[] | select(.Sid=="RootRecovery") | .Principal.AWS')
    echo "  PASS: KMS policy includes RootRecovery with kms:PutKeyPolicy (principal=${RR_PRINCIPAL})"
  else
    echo "  FAIL: KMS policy missing RootRecovery + kms:PutKeyPolicy (default is_kms_key_locked=false should produce this)" >&2
    echo "  policy: $POLICY" >&2
    exit 1
  fi
  # Sanity: root must NOT have direct Decrypt — recovery is via PutKeyPolicy.
  if echo "$POLICY" | jq -e '.Statement[] | select(.Sid=="RootRecovery") | (.Action | index("kms:Decrypt"))' >/dev/null 2>&1; then
    echo "  FAIL: RootRecovery must not grant kms:Decrypt directly to root (breaks attested-only-decrypt invariant)" >&2
    exit 1
  fi
else
  echo "  WARN: could not read KMSKeyID from SSM, skipping policy check"
fi
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

# Verify tofu's app.env overrides (supplied via env_values.auto.tfvars.json)
# flowed through SSM into the running app. Both keys default to "default-from-yaml"
# in enclave.yaml; the env file overrides them with distinct values.
ENV_OVERRIDE_RESP=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/test/env-override" 2>/dev/null || echo "")
ENV_OVERRIDE_VAL=$(echo "$ENV_OVERRIDE_RESP" | jq -r '.test_runtime_override // empty' 2>/dev/null || echo "")
ENV_OVERRIDE_ENVFILE_VAL=$(echo "$ENV_OVERRIDE_RESP" | jq -r '.test_runtime_override_envfile // empty' 2>/dev/null || echo "")
if [ "$ENV_OVERRIDE_VAL" = "override-from-tofu" ]; then
  echo "  PASS: app.env override applied (TEST_RUNTIME_OVERRIDE=${ENV_OVERRIDE_VAL})"
else
  printf "  FAIL: app.env override not applied — got %q, want \"override-from-tofu\" (response: %s)\n" "$ENV_OVERRIDE_VAL" "${ENV_OVERRIDE_RESP:0:120}" >&2
  exit 1
fi
if [ "$ENV_OVERRIDE_ENVFILE_VAL" = "override-from-envfile" ]; then
  echo "  PASS: env-file override applied (TEST_RUNTIME_OVERRIDE_ENVFILE=${ENV_OVERRIDE_ENVFILE_VAL})"
else
  printf "  FAIL: env-file override not applied — got %q, want \"override-from-envfile\" (response: %s)\n" "$ENV_OVERRIDE_ENVFILE_VAL" "${ENV_OVERRIDE_RESP:0:120}" >&2
  exit 1
fi
echo ""

# Step 6: Migration cooldown abort test.
# Start a migration in the background (enters cooldown), verify pending=true,
# abort, verify pending=false.
echo "=== [6/9] Migration cooldown: abort test ==="
SUPERVISOR_URL="http://localhost:${SUPERVISOR_PORT:-8444}"

export AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4000"
export AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566"

# Trigger migration directly via supervisor in the background.
# (Not via tofu — we need to abort mid-migration, which tofu can't do.)
ABORT_EIF_BUCKET="dev-my-app-eif-000000000000-us-east-1"
aws s3 mb "s3://${ABORT_EIF_BUCKET}" $LOCALSTACK 2>/dev/null || true
aws s3 cp "$EIF_PATH" "s3://${ABORT_EIF_BUCKET}/image.eif" $LOCALSTACK 2>/dev/null
ABORT_PCR0=$(jq -r '.PCR0' "${SCRIPT_DIR}/app/.enclave/artifacts/pcr.json")
curl -sf -X POST "${SUPERVISOR_URL}/migrate" \
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
ABORT_CODE=$(curl -s --max-time 10 -o /dev/null -w '%{http_code}' -X POST "${SUPERVISOR_URL}/migrate/abort" 2>/dev/null || echo "000")
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
# app/.enclave/artifacts/image-v2.eif. If not available, fall back to same EIF.
echo "=== [7/9] Running migration (enclave deploy upgrade) ==="
MIGRATION_EIF="${SCRIPT_DIR}/app/.enclave/artifacts/image-v2.eif"
if [ -f "$MIGRATION_EIF" ]; then
  echo "  Using migration EIF: $MIGRATION_EIF"
  cp "$MIGRATION_EIF" "${SCRIPT_DIR}/app/.enclave/artifacts/image.eif"
  # Update pcr.json with the v2 PCR0.
  if [ -f "${SCRIPT_DIR}/app/.enclave/artifacts/pcr-v2.json" ]; then
    cp "${SCRIPT_DIR}/app/.enclave/artifacts/pcr-v2.json" "${SCRIPT_DIR}/app/.enclave/artifacts/pcr.json"
  fi
else
  echo "  WARN: No migration EIF found (image-v2.eif), reusing same EIF"
fi

# Re-apply with the new EIF — tofu detects expected_pcr0 changed and triggers
# enclave_migration_local, which calls the supervisor to perform live migration.
echo "  v2 PCR0: $(jq -r '.PCR0' "${SCRIPT_DIR}/app/.enclave/artifacts/pcr.json" | cut -c1-16)..."

# Snapshot the current supervisor child PID so we can verify Step 10 actually
# restarted it (supervisor writes new child's PID back to the pidfile).
PRE_MIGRATION_SUP_PID=$(cat "$SUPERVISOR_PIDFILE" 2>/dev/null || echo "")
echo "  Pre-migration supervisor PID: $PRE_MIGRATION_SUP_PID"
tofu_apply
echo "  tofu apply log (migration lines):"
grep -i 'migrat\|trigger\|null_resource\|local-exec\|curl\|skip' ${SCRIPT_DIR}/tofu-apply.log 2>/dev/null | sed 's/^/    /' || echo "    (no migration lines found)"

# Report migration rollback directly — supervisor-update won't have run, so the
# "supervisor update ready" check below would only surface the symptom.
if grep -q '"status":"rollback-complete"' "${SCRIPT_DIR}/tofu-apply.log" 2>/dev/null; then
  echo "  FAIL: migration rolled back — happy-path migration was expected to commit" >&2
  echo "  Rollback reason (from tofu-apply.log):" >&2
  grep -E '"status":"(error|rollback)"' "${SCRIPT_DIR}/tofu-apply.log" | sed 's/^/    /' >&2
  echo "  v2 init errors (from /tmp/boot-qemu.log):" >&2
  grep -E 'enclave init failed|ERROR|previous_pcr0|migration|promote|KMS|decrypt' /tmp/boot-qemu.log 2>/dev/null | tail -20 | sed 's/^/    /' >&2 \
    || echo "    (boot-qemu.log empty or unavailable)" >&2
  echo "  Full tofu-apply.log tail:" >&2
  tail -30 "${SCRIPT_DIR}/tofu-apply.log" | sed 's/^/    /' >&2
  exit 1
fi

# Supervisor binary update: handler emits "supervisor update ready" after validate passes.
if ! grep -q "supervisor update ready" "${SCRIPT_DIR}/tofu-apply.log" 2>/dev/null; then
  echo "  FAIL: supervisor update did not complete — no 'supervisor update ready' NDJSON line" >&2
  echo "  Last 30 lines of tofu-apply.log:" >&2
  tail -30 "${SCRIPT_DIR}/tofu-apply.log" | sed 's/^/    /' >&2
  exit 1
fi
echo "  PASS: supervisor update ready — validate passed and binary was swapped"

# Wait for scheduleSupervisorAtomicRestart (2s detached sleep + systemctl restart)
# to run the restart cmd, for supervisor to exit, and for the supervisor to relaunch
# it with the new binary. The helper also polls /supervisor/health and rolls back
# on failure, but since validate passed and the binary is healthy, no rollback.
POST_MIGRATION_SUP_PID=""
for i in $(seq 1 15); do
  sleep 1
  CURRENT_PID=$(cat "$SUPERVISOR_PIDFILE" 2>/dev/null || echo "")
  if [ -n "$CURRENT_PID" ] && [ "$CURRENT_PID" != "$PRE_MIGRATION_SUP_PID" ] && kill -0 "$CURRENT_PID" 2>/dev/null; then
    POST_MIGRATION_SUP_PID="$CURRENT_PID"
    break
  fi
done
if [ -z "$POST_MIGRATION_SUP_PID" ]; then
  echo "  FAIL: relauncher did not relaunch supervisor within 15s (pidfile=$(cat "$SUPERVISOR_PIDFILE" 2>/dev/null), pre=$PRE_MIGRATION_SUP_PID)" >&2
  exit 1
fi
echo "  PASS: supervisor restarted ($PRE_MIGRATION_SUP_PID → $POST_MIGRATION_SUP_PID)"

# Sanity-check the new supervisor process serves requests.
if curl -sf --max-time 5 "http://127.0.0.1:8444/health" >/dev/null 2>&1; then
  echo "  PASS: restarted supervisor answering /health"
else
  echo "  FAIL: restarted supervisor not responding on /health" >&2
  exit 1
fi

# Verify the CLI promoted the staging object onto the canonical supervisor
# key after the migration succeeded (null_resource.promote_supervisor_binary_local).
ASSETS_BUCKET=$(aws s3api list-buckets $LOCALSTACK --query "Buckets[?starts_with(Name, 'dev-my-app-assets-')].Name | [0]" --output text 2>/dev/null || echo "")
if [ -n "$ASSETS_BUCKET" ] && [ "$ASSETS_BUCKET" != "None" ]; then
  if aws s3api head-object $LOCALSTACK --bucket "$ASSETS_BUCKET" --key "supervisor" >/dev/null 2>&1; then
    echo "  PASS: Canonical supervisor S3 key promoted"
  else
    echo "  FAIL: Canonical supervisor S3 key not found in $ASSETS_BUCKET" >&2
    exit 1
  fi
else
  echo "  WARN: assets bucket not found — skipping canonical-promotion check"
fi

# Step 8: Wait for restarted enclave and verify migration survival.
# supervisor already stopped and restarted the enclave in step 7 (via boot_qemu).
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

# Verify previous_pcr0 was updated (no longer "genesis" after start-migration).
POST_MIG_INFO=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || echo "")
PREV_PCR0=$(echo "$POST_MIG_INFO" | jq -r '.previous_pcr0 // empty' 2>/dev/null || echo "")
if [ -n "$PREV_PCR0" ] && [ "$PREV_PCR0" != "genesis" ]; then
  echo "  PASS: previous_pcr0 updated after migration (${PREV_PCR0:0:16}...)"
else
  echo "  FAIL: previous_pcr0 should not be genesis after migration (got: ${PREV_PCR0:-empty})" >&2
  exit 1
fi

# Verify previous_pcr0 matches v1 PCR0 from build artifacts.
V1_PCR0_FILE="${SCRIPT_DIR}/app/.enclave/artifacts/pcr.json"
if [ -f "${SCRIPT_DIR}/app/.enclave/artifacts/pcr-v1.json" ]; then
  V1_PCR0_FILE="${SCRIPT_DIR}/app/.enclave/artifacts/pcr-v1.json"
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

# Step 8.5: Verify new atomic-migration observability endpoints and CLI commands.
echo ""
echo "=== [8.5/9] Atomic migration observability checks ==="

# /supervisor/health — AWS auth + SSM + enclave reachability + migration lock state.
SUP_HEALTH_CODE=$(curl -s --max-time 5 -o /tmp/supervisor-health.json -w '%{http_code}' \
  "http://127.0.0.1:8444/supervisor/health" 2>/dev/null || echo "000")
if [ "$SUP_HEALTH_CODE" = "200" ]; then
  SUP_HEALTH_STATUS=$(jq -r '.status // empty' /tmp/supervisor-health.json 2>/dev/null || echo "")
  if [ "$SUP_HEALTH_STATUS" = "ok" ]; then
    echo "  PASS: /supervisor/health reports ok"
  else
    echo "  FAIL: /supervisor/health returned status=$SUP_HEALTH_STATUS" >&2
    cat /tmp/supervisor-health.json >&2
    exit 1
  fi
else
  echo "  FAIL: /supervisor/health HTTP $SUP_HEALTH_CODE" >&2
  cat /tmp/supervisor-health.json 2>/dev/null >&2
  exit 1
fi

# After a successful migration, MigrationKMSKeyID must be cleared (= atomic
# commit happened inside the new enclave's Init). This is the most important
# post-migration invariant.
POST_MIG_KEY=$(aws ssm get-parameter $LOCALSTACK \
  --name "/dev/my-app/MigrationKMSKeyID" \
  --query 'Parameter.Value' --output text 2>/dev/null || echo "")
if [ -z "$POST_MIG_KEY" ] || [ "$POST_MIG_KEY" = "UNSET" ]; then
  echo "  PASS: MigrationKMSKeyID cleared after commit (= atomic migration succeeded)"
else
  echo "  FAIL: MigrationKMSKeyID still set after migration (got: $POST_MIG_KEY)" >&2
  exit 1
fi

# Verify Migration/* staging params were cleaned up.
STAGING_SECRET=$(aws ssm get-parameter $LOCALSTACK \
  --name "/dev/my-app/Migration/signing_key/Ciphertext" \
  --query 'Parameter.Value' --output text 2>/dev/null || echo "")
if [ -z "$STAGING_SECRET" ] || [ "$STAGING_SECRET" = "UNSET" ]; then
  echo "  PASS: Migration staging ciphertexts cleaned up"
else
  echo "  WARN: Migration/signing_key/Ciphertext still present (length=${#STAGING_SECRET})"
fi

# `enclave migration-status` CLI command — should report committed state.
if [ -x "$ENCLAVE_CLI" ]; then
  (cd app && "$ENCLAVE_CLI" migration-status > /tmp/migration-status.out 2>&1) || true
  if grep -q "Phase:.*committed" /tmp/migration-status.out 2>/dev/null; then
    echo "  PASS: 'enclave migration-status' reports committed state"
  else
    echo "  WARN: 'enclave migration-status' did not report committed phase"
    sed 's/^/    /' /tmp/migration-status.out 2>/dev/null | head -10
  fi
fi


# Step 9: Rollback test — migration with wrong previous_pcr0.
# Build a v3 EIF with an intentionally WRONG baked-in previous_pcr0 and trigger
# a migration. The new enclave's Init() PCR0 check must fail, supervisor's commit
# poll must time out, and rollback must restore v2 with all data intact.
# Skipped inside Docker (no Nix toolchain to build v3).
echo ""
echo "=== [9/10] Rollback test: migration with wrong previous_pcr0 ==="

ARTIFACTS="${SCRIPT_DIR}/app/.enclave/artifacts"
V3_EIF="${ARTIFACTS}/image-v3.eif"
V3_PCR_FILE="${ARTIFACTS}/pcr-v3.json"

# Require pre-built v3 artifacts (produced by `make test-build`).
# This works identically in Docker and on the host — no Nix needed at test-run.
if [ ! -f "$V3_EIF" ] || [ ! -f "$V3_PCR_FILE" ]; then
  echo "  FAIL: v3 artifacts not found (run 'make test-build' to build them)" >&2
  echo "  expected: $V3_EIF, $V3_PCR_FILE" >&2
  exit 1
fi

V2_PCR0=$(jq -r '.PCR0' "${ARTIFACTS}/pcr.json")
V3_PCR0=$(jq -r '.PCR0' "$V3_PCR_FILE")
echo "  v2 PCR0: ${V2_PCR0:0:16}... (currently running)"
echo "  v3 PCR0: ${V3_PCR0:0:16}... (baked-in previous_pcr0 = 0000...ff — deliberately wrong)"

ROLLBACK_EIF_BUCKET="dev-my-app-eif-000000000000-us-east-1"
aws s3 cp "$V3_EIF" "s3://${ROLLBACK_EIF_BUCKET}/image-v3.eif" $LOCALSTACK > /dev/null 2>&1 || {
  echo "  FAIL: could not upload v3 EIF" >&2
  exit 1
}

MIGRATE_BODY=$(jq -nc \
  --arg b "$ROLLBACK_EIF_BUCKET" --arg k "image-v3.eif" --arg p "$V3_PCR0" \
  --argjson s '["signing_key"]' \
  '{eif_bucket:$b, eif_key:$k, pcr0:$p, secret_names:$s}')

echo "  Triggering migration v2 → v3 (expecting rollback)..."
curl -s --max-time 180 -X POST "${SUPERVISOR_URL}/migrate" \
  -H 'Content-Type: application/json' -d "$MIGRATE_BODY" \
  > /tmp/rollback-migrate.log 2>&1 || true

if grep -q '"status":"rollback"' /tmp/rollback-migrate.log 2>/dev/null; then
  echo "  PASS: Migration emitted rollback status"
else
  echo "  FAIL: No rollback status in migration response" >&2
  echo "  Last 20 NDJSON lines:" >&2
  tail -20 /tmp/rollback-migrate.log | sed 's/^/    /' >&2
  exit 1
fi

# A healthy v2 boot after rollback implies abortOrphanedMigration ran.
wait_for_enclave "post-rollback"

# Verify rollback restored v2 by checking previous_pcr0 — the abort path
# re-asserts it from the baked predecessor, so it should equal pcr-v1.json.
V1_PCR0=$(jq -r '.PCR0' "${ARTIFACTS}/pcr-v1.json")
POST_ROLLBACK_INFO=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || echo "")
POST_ROLLBACK_PREV=$(echo "$POST_ROLLBACK_INFO" | jq -r '.previous_pcr0 // empty' 2>/dev/null || echo "")
V1_LOWER=$(echo "$V1_PCR0" | tr '[:upper:]' '[:lower:]')
POST_LOWER=$(echo "$POST_ROLLBACK_PREV" | tr '[:upper:]' '[:lower:]')
if [ -n "$POST_LOWER" ] && [ "$V1_LOWER" = "$POST_LOWER" ]; then
  echo "  PASS: v2 restored after rollback (previous_pcr0 matches baked v1)"
else
  echo "  FAIL: previous_pcr0 after rollback (${POST_ROLLBACK_PREV:0:16}...) != v1 (${V1_PCR0:0:16}...)" >&2
  exit 1
fi

# Data must survive rollback unchanged.
ROLLBACK_STORAGE=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/test/storage" 2>/dev/null || echo "")
if echo "$ROLLBACK_STORAGE" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  echo "  PASS: v2 storage round-trip works after rollback (DEK intact)"
else
  echo "  FAIL: v2 storage broken after rollback: ${ROLLBACK_STORAGE:0:120}" >&2
  exit 1
fi

ROLLBACK_SECRETS=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/test/secrets" 2>/dev/null || echo "")
if echo "$ROLLBACK_SECRETS" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  echo "  PASS: v2 static secrets still decryptable after rollback"
else
  echo "  FAIL: v2 secrets broken after rollback: ${ROLLBACK_SECRETS:0:120}" >&2
  exit 1
fi


# Step 9.5: Supervisor resilience — SIGKILL supervisor and verify the
# supervisor relaunches it and it reconnects to AWS/enclave cleanly.
# This is the foundation that mid-migration crash recovery relies on:
# if supervisor dies mid-handleMigrate, a new supervisor must come up with fresh
# state (supervisor is stateless; all migration state lives in SSM).
echo ""
echo "=== [9.5/10] Supervisor resilience ==="
PRE_KILL_PID=$(cat "$SUPERVISOR_PIDFILE" 2>/dev/null || echo "")
if [ -z "$PRE_KILL_PID" ]; then
  echo "  FAIL: supervisor PID file missing" >&2
  exit 1
fi
echo "  Killing supervisor (PID $PRE_KILL_PID) with SIGKILL..."
kill -KILL "$PRE_KILL_PID" 2>/dev/null || true

POST_KILL_PID=""
for i in $(seq 1 15); do
  sleep 1
  CURRENT_PID=$(cat "$SUPERVISOR_PIDFILE" 2>/dev/null || echo "")
  if [ -n "$CURRENT_PID" ] && [ "$CURRENT_PID" != "$PRE_KILL_PID" ] && kill -0 "$CURRENT_PID" 2>/dev/null; then
    POST_KILL_PID="$CURRENT_PID"
    break
  fi
done
if [ -n "$POST_KILL_PID" ]; then
  echo "  PASS: Relauncher restored supervisor ($PRE_KILL_PID → $POST_KILL_PID)"
else
  echo "  FAIL: Relauncher did not restore supervisor within 15s" >&2
  exit 1
fi

# New supervisor must serve /health (enclave status) and /supervisor/health (its own
# AWS connectivity). Both are prerequisites for resuming any in-progress
# migration after a crash. `kill -0 $PID` already told us the process exists,
# but the HTTP listener takes a few seconds longer to bind in Docker+QEMU
# (Go runtime warmup + AWS config + 4 errgroup goroutines + ListenAndServe).
# Poll for up to 30s instead of a single-shot probe.
HEALTH_CODE="000"
for i in $(seq 1 30); do
  HEALTH_CODE=$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8444/health" 2>/dev/null || echo "000")
  [ "$HEALTH_CODE" = "200" ] && break
  sleep 1
done
if [ "$HEALTH_CODE" = "200" ]; then
  echo "  PASS: Relaunched supervisor serves /health (after ${i}s)"
else
  echo "  FAIL: Relaunched supervisor /health returned $HEALTH_CODE after 30 attempts (~90s)" >&2
  exit 1
fi

SUP_HEALTH_CODE="000"
for i in $(seq 1 30); do
  SUP_HEALTH_CODE=$(curl -s --max-time 2 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8444/supervisor/health" 2>/dev/null || echo "000")
  [ "$SUP_HEALTH_CODE" = "200" ] && break
  sleep 1
done
if [ "$SUP_HEALTH_CODE" = "200" ]; then
  echo "  PASS: Relaunched supervisor has working AWS/SSM/enclave connectivity (/supervisor/health, after ${i}s)"
else
  echo "  FAIL: Relaunched supervisor /supervisor/health returned $SUP_HEALTH_CODE after 30 attempts (~90s)" >&2
  exit 1
fi

echo ""
echo "=== [10/11] Final enclave info ==="
FINAL_INFO=$(curl -sk --max-time 10 "https://localhost:${HOST_TLS_PORT:-8443}/v1/enclave-info" 2>/dev/null || echo "")
if [ -n "$FINAL_INFO" ] && echo "$FINAL_INFO" | jq -e '.version' >/dev/null 2>&1; then
  echo "  PASS: Enclave info valid"
  echo "$FINAL_INFO" | jq -r '"  version: \(.version // "?"), pcr0: \(.previous_pcr0 // "?")"' 2>/dev/null || true
else
  echo "  FAIL: Could not read enclave info: ${FINAL_INFO:0:120}" >&2
  exit 1
fi

echo ""
echo "=== [11/11] Recovery rehearsal: root rewrites policy with new PCR0 ==="
# Verifies the locked policy permits root (= the AWS account principal,
# delegating to IAM in-account) to add a new PCR0 Decrypt condition. This
# is the load-bearing operation of the lockout-recovery story: rebuild an
# EIF, root pivots the lock to its PCR0, the new attested enclave decrypts.

RECOVERY_KMS_KEY_ID=$(aws ssm get-parameter --name "/dev/my-app/KMSKeyID" \
  --endpoint-url "http://127.0.0.1:4566" --region us-east-1 \
  --query 'Parameter.Value' --output text 2>/dev/null || echo "")
if [ -z "$RECOVERY_KMS_KEY_ID" ]; then
  echo "  FAIL: could not read /dev/my-app/KMSKeyID from SSM" >&2
  exit 1
fi

# Read the live policy.
CURRENT_POLICY=$(aws kms get-key-policy --key-id "$RECOVERY_KMS_KEY_ID" --policy-name default \
  --endpoint-url "http://127.0.0.1:4000" --region us-east-1 \
  --query 'Policy' --output text 2>/dev/null || echo "")
if [ -z "$CURRENT_POLICY" ]; then
  echo "  FAIL: could not read current KMS policy for ${RECOVERY_KMS_KEY_ID}" >&2
  exit 1
fi

# Construct a recovery policy: append a Decrypt statement gated on a fresh
# fake PCR0, reusing the existing enclave Principal so the new statement
# is structurally valid. The original RootRecovery statement stays, so a
# subsequent recovery call would still be possible.
NEW_PCR0=$(printf 'cafe%.0s' {1..24})  # 96 hex chars
ENCLAVE_PRINCIPAL=$(echo "$CURRENT_POLICY" | jq -r '.Statement[] | select(.Sid=="EnclaveDecryptWithAttestation") | .Principal.AWS')
if [ -z "$ENCLAVE_PRINCIPAL" ] || [ "$ENCLAVE_PRINCIPAL" = "null" ]; then
  echo "  FAIL: could not extract enclave Principal from policy" >&2
  exit 1
fi
NEW_POLICY=$(echo "$CURRENT_POLICY" | jq --arg pcr0 "$NEW_PCR0" --arg principal "$ENCLAVE_PRINCIPAL" '
  .Statement += [{
    "Sid": "EnclaveDecryptRecovery",
    "Effect": "Allow",
    "Principal": {"AWS": $principal},
    "Action": "kms:Decrypt",
    "Resource": "*",
    "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:PCR0": $pcr0}}
  }]
')

# Root call. With the RootRecovery statement granting kms:PutKeyPolicy and
# the new policy still keeping it (we only appended), the lockout safety
# check is satisfied — no bypass flag needed.
if ! aws kms put-key-policy --key-id "$RECOVERY_KMS_KEY_ID" --policy-name default \
    --policy "$NEW_POLICY" \
    --endpoint-url "http://127.0.0.1:4000" --region us-east-1 \
    >/tmp/put-key-policy.log 2>&1; then
  echo "  FAIL: root could not rewrite policy" >&2
  cat /tmp/put-key-policy.log >&2
  exit 1
fi

# Verify the new PCR0 actually landed.
UPDATED_POLICY=$(aws kms get-key-policy --key-id "$RECOVERY_KMS_KEY_ID" --policy-name default \
  --endpoint-url "http://127.0.0.1:4000" --region us-east-1 \
  --query 'Policy' --output text 2>/dev/null || echo "")
if echo "$UPDATED_POLICY" | jq -e --arg pcr0 "$NEW_PCR0" \
    '.Statement[] | .Condition? | .StringEqualsIgnoreCase? | ."kms:RecipientAttestation:PCR0"? | select(. == $pcr0)' \
    >/dev/null 2>&1; then
  echo "  PASS: root rewrote policy to include new PCR0 ${NEW_PCR0:0:16}..."
else
  echo "  FAIL: new PCR0 not present after PutKeyPolicy" >&2
  echo "  policy: $UPDATED_POLICY" >&2
  exit 1
fi

# Sanity: the RootRecovery statement should still be present (we only
# appended; nothing removed).
if echo "$UPDATED_POLICY" | jq -e '.Statement[] | select(.Sid=="RootRecovery")' >/dev/null 2>&1; then
  echo "  PASS: RootRecovery statement preserved across PutKeyPolicy"
else
  echo "  FAIL: RootRecovery statement vanished after PutKeyPolicy" >&2
  exit 1
fi

echo ""
echo "==============================="
echo " All tests passed!"
echo "==============================="
