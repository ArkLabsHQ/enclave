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
# Prerequisites:
#   docker compose --profile test run --build test-runner  (canonical invocation
#                                                           — image bakes in
#                                                           QEMU + vsock + supervisor)
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

  # ENCLAVE_START_CMD is intentionally async. After a supervisor restart, the
  # old QEMU wrapper may still be healthy while a new start command races in;
  # do not tear down vhost-device-vsock underneath it.
  if [ -s /tmp/enclave-boot.pid ]; then
    local existing_pid
    existing_pid=$(cat /tmp/enclave-boot.pid 2>/dev/null || true)
    if [ -n "$existing_pid" ] && [ "$existing_pid" != "$$" ] && kill -0 "$existing_pid" 2>/dev/null; then
      echo "Enclave boot already running (PID $existing_pid)"
      return 0
    fi
  fi

  echo $$ > /tmp/enclave-boot.pid

  if [ ! -f "$eif_path" ]; then
    echo "Error: EIF not found at $eif_path" >&2
    return 1
  fi
  eif_path="$(realpath "$eif_path")"

  local guest_cid="${GUEST_CID:-4}"
  local forward_cid="${VSOCK_FORWARD_CID:-1}"
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
  pkill -f enclave-test-heartbeat 2>/dev/null || true
  sleep 0.5
  rm -f "$vsock_socket"

  if [ ! -e /dev/vsock ]; then
    echo "Error: /dev/vsock not found. Load vsock + vsock_loopback kernel modules." >&2
    return 1
  fi

  echo "=== Starting vhost-device-vsock ==="
  echo "  CID:        $guest_cid"
  echo "  Socket:     $vsock_socket"
  echo "  Forward:    CID ${forward_cid} (loopback), host-to-guest port 8003"
  vhost-device-vsock \
    --vm "guest-cid=${guest_cid},socket=${vsock_socket},forward-cid=${forward_cid},forward-listen=8003+9001+9002" &
  vsock_pid=$!
  sleep 1
  if ! kill -0 "$vsock_pid" 2>/dev/null; then
    echo "Error: vhost-device-vsock failed to start" >&2
    return 1
  fi

  # Heartbeat responder. The EIF init binary connects to vsock CID 3 port
  # 9000, sends byte 0xB7, and expects 0xB7 back. With vhost-device-vsock's
  # forward-cid=1 mode the request hits the host's AF_VSOCK loopback, which
  # this inline Python listener echoes. Tagged "enclave-test-heartbeat" so
  # stale instances from prior runs can be pkill'd by name.
  echo "=== Starting heartbeat responder ==="
  python3 -c '
# enclave-test-heartbeat
import socket, sys
sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((0xFFFFFFFF, 9000))
sock.listen(1)
print("Heartbeat: listening on vsock port 9000", flush=True)
while True:
    try:
        conn, (cid, _) = sock.accept()
        data = conn.recv(1)
        if data: conn.send(data)
        conn.close()
        print(f"Heartbeat: OK (CID {cid}, sent {data.hex()})", flush=True)
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"Heartbeat: error: {e}", file=sys.stderr, flush=True)
' &
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

# run.sh runs inside the test-runner Docker image, which bakes in
# vhost-device-vsock + qemu-system-x86_64. If either is missing, the
# image was built wrong — fail fast rather than papering over it.
if ! command -v vhost-device-vsock &>/dev/null || ! command -v qemu-system-x86_64 &>/dev/null; then
  echo "Error: vhost-device-vsock and qemu-system-x86_64 must be on PATH (rebuild test/Dockerfile.runner)." >&2
  exit 1
fi

# Use pre-built binaries (Docker test-runner) or fall back to host-built.
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
else
  echo "Error: neither pre-built binaries (enclave-cli, supervisor) nor Go compiler found" >&2
  exit 1
fi

# Seed the artifacts dir with the binary under test so Tofu publishes the same
# supervisor for every candidate and self-update does not install a stale build.
mkdir -p "${SCRIPT_DIR}/app/.enclave/artifacts"
cp "$ENCLAVE_SUPERVISOR" "${SCRIPT_DIR}/app/.enclave/artifacts/supervisor"

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
  # `enclave tofu init` is merge-only-new (existing files are skipped) so the
  # committed test-app scaffold would mask CLI changes. Delete the
  # CLI-managed root and module main.tf first to force a fresh emit; the
  # rest of the tree (modules/backend, templates, etc.) is left untouched.
  rm -f "${TOFU_DIR}/main.tf" "${TOFU_DIR}/modules/enclave/main.tf"

  echo "  Generating terraform.tfvars.json..."

  # Ensure inputs exist for tofu's filemd5(). The enclave initially boots in
  # QEMU, while migrations download these generated candidate objects from S3.
  mkdir -p "${SCRIPT_DIR}/app/.enclave/artifacts"
  for f in image.eif supervisor; do
    [ -f "${SCRIPT_DIR}/app/.enclave/artifacts/$f" ] || touch "${SCRIPT_DIR}/app/.enclave/artifacts/$f"
  done

  (cd "${SCRIPT_DIR}/app" && LOCAL_DEPLOYMENT=true "$ENCLAVE_CLI" tofu init > "${SCRIPT_DIR}/tofu-scaffold.log" 2>&1) \
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
    s3       = "http://127.0.0.1:4566"
    ssm      = "http://127.0.0.1:4566"
    sts      = "http://127.0.0.1:4566"
    iam      = "http://127.0.0.1:4566"
    kms      = "http://127.0.0.1:4566"
    ec2      = "http://127.0.0.1:4566"
    dynamodb = "http://127.0.0.1:4566"
  }
}
OVERRIDE

  echo "  tofu init..."
  tofu -chdir="$TOFU_DIR" init -input=false > ${SCRIPT_DIR}/tofu-init.log 2>&1 || { cat ${SCRIPT_DIR}/tofu-init.log; return 1; }
  # env_values overrides are supplied via tofu/env_values.auto.tfvars.json,
  # which tofu auto-loads on every plan/apply. The 'enclave tofu env' CLI
  # populates that file — exercises the same UX an operator uses (rather
  # than the framework dropping its own hand-crafted JSON).
  (cd "${SCRIPT_DIR}/app" && LOCAL_DEPLOYMENT=true "$ENCLAVE_CLI" tofu env \
    --key TEST_RUNTIME_OVERRIDE         --value "override-from-tofu" \
    --key TEST_RUNTIME_OVERRIDE_ENVFILE --value "override-from-envfile" \
    > "${SCRIPT_DIR}/tofu-env.log" 2>&1) \
    || { cat "${SCRIPT_DIR}/tofu-env.log"; return 1; }

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
FIXTURE_YAML_BACKUP=""
ACTIVE_EIF_PATH="/tmp/enclave-active.eif"

cleanup() {
  echo ""
  echo "=== Tearing down ==="
  if [ -n "$FIXTURE_YAML_BACKUP" ] && [ -f "$FIXTURE_YAML_BACKUP" ]; then
    cp -f "$FIXTURE_YAML_BACKUP" "${SCRIPT_DIR}/app/enclave/enclave.yaml"
    rm -f "$FIXTURE_YAML_BACKUP"
  fi
  tofu_destroy
  # Kill supervisor relauncher (which TERM-traps and kills its child supervisor).
  [ -n "${SUP_PID:-}" ] && kill -TERM "$SUP_PID" 2>/dev/null && wait "$SUP_PID" 2>/dev/null || true
  # Belt-and-suspenders: if the supervisor's child survived, kill it too.
  if [ -f /tmp/supervisor.pid ]; then
    kill "$(cat /tmp/supervisor.pid)" 2>/dev/null || true
    rm -f /tmp/supervisor.pid
  fi
  rm -f /tmp/supervisor-relauncher.sh
  rm -f "$ACTIVE_EIF_PATH"
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
echo "=== [0/11] Building test EIF from skeleton app ==="
if [ -n "$EIF_PATH" ] && [ -f "$EIF_PATH" ]; then
  echo "  Using provided EIF: $EIF_PATH"
elif [ "$IN_DOCKER" = true ]; then
  # Inside Docker: use pre-built EIFs from mounted volume (built on host).
  if [ -f "app/.enclave/artifacts/image.eif" ]; then
    EIF_PATH="app/.enclave/artifacts/image.eif"
    echo "  Using pre-built EIF: $EIF_PATH"
    echo "  Migration EIFs: v2/v3 healthy, v4 wrong-app rollback fixture"
  else
    echo "  Error: EIF must be pre-built when running inside Docker" >&2
    echo "  Build it on the host first: cd test/app && enclave build" >&2
    exit 1
  fi
else
  # On host: build the same four fixtures as CI.
  ENCLAVE_YAML="${SCRIPT_DIR}/app/enclave/enclave.yaml"
  ARTIFACTS="${SCRIPT_DIR}/app/.enclave/artifacts"
  FIXTURE_YAML_BACKUP="$(mktemp /tmp/enclave-yaml.XXXXXX)"
  cp "$ENCLAVE_YAML" "$FIXTURE_YAML_BACKUP"

  echo "  Building v1 EIF with baked nonzero cooldown..."
  (cd app && "$ENCLAVE_CLI" build)
  cp "${ARTIFACTS}/image.eif" /tmp/image-v1.eif
  cp "${ARTIFACTS}/pcr.json" /tmp/pcr-v1.json
  V1_PCR0=$(jq -r '.PCR0' /tmp/pcr-v1.json)
  echo "  v1 PCR0: ${V1_PCR0:0:16}..."

  echo "  Building healthy v2 EIF with zero cooldown..."
  sed -i 's/^version: .*/version: 0.0.2/' "$ENCLAVE_YAML"
  sed -i 's/^migration_cooldown: .*/migration_cooldown: "0s"/' "$ENCLAVE_YAML"
  if grep -q '^previous_pcr0:' "$ENCLAVE_YAML"; then
    sed -i "s/^previous_pcr0: .*/previous_pcr0: \"${V1_PCR0}\"/" "$ENCLAVE_YAML"
  else
    echo "" >> "$ENCLAVE_YAML"
    echo "previous_pcr0: \"${V1_PCR0}\"" >> "$ENCLAVE_YAML"
  fi
  (cd app && "$ENCLAVE_CLI" build)
  cp "${ARTIFACTS}/image.eif" /tmp/image-v2.eif
  cp "${ARTIFACTS}/pcr.json" /tmp/pcr-v2.json
  V2_PCR0=$(jq -r '.PCR0' /tmp/pcr-v2.json)

  echo "  Building healthy v3 EIF with zero cooldown..."
  sed -i 's/^version: .*/version: 0.0.3/' "$ENCLAVE_YAML"
  sed -i "s|^previous_pcr0: .*|previous_pcr0: \"${V2_PCR0}\"|" "$ENCLAVE_YAML"
  (cd app && "$ENCLAVE_CLI" build)
  cp "${ARTIFACTS}/image.eif" /tmp/image-v3.eif
  cp "${ARTIFACTS}/pcr.json" /tmp/pcr-v3.json
  V3_PCR0=$(jq -r '.PCR0' /tmp/pcr-v3.json)

  echo "  Building wrong-app v4 EIF for readiness rollback..."
  sed -i 's/^version: .*/version: 0.0.4/' "$ENCLAVE_YAML"
  sed -i "s|^previous_pcr0: .*|previous_pcr0: \"${V3_PCR0}\"|" "$ENCLAVE_YAML"
  sed -i 's|^name: my-app\b|name: my-app-wrong|' "$ENCLAVE_YAML"
  (cd app && "$ENCLAVE_CLI" build)
  cp "${ARTIFACTS}/image.eif" /tmp/image-v4.eif
  cp "${ARTIFACTS}/pcr.json" /tmp/pcr-v4.json

  cp -f "$FIXTURE_YAML_BACKUP" "$ENCLAVE_YAML"
  rm -f "$FIXTURE_YAML_BACKUP"
  FIXTURE_YAML_BACKUP=""
  for version in 1 2 3 4; do
    cp "/tmp/image-v${version}.eif" "${ARTIFACTS}/image-v${version}.eif"
    cp "/tmp/pcr-v${version}.json" "${ARTIFACTS}/pcr-v${version}.json"
  done
  cp /tmp/image-v1.eif "${ARTIFACTS}/image.eif"
  cp /tmp/pcr-v1.json "${ARTIFACTS}/pcr.json"
  EIF_PATH="app/.enclave/artifacts/image.eif"
  echo "  Restored exact YAML and selected v1"
fi
for version in 1 2 3 4; do
  if [ ! -f "${SCRIPT_DIR}/app/.enclave/artifacts/image-v${version}.eif" ] || \
     [ ! -f "${SCRIPT_DIR}/app/.enclave/artifacts/pcr-v${version}.json" ]; then
    echo "  Error: missing v${version} migration fixture artifacts" >&2
    exit 1
  fi
done
echo ""

# Step 1: Start mock services (skipped inside Docker — compose handles it).
echo "=== [1/11] Starting mock services ==="
if [ "$IN_DOCKER" = true ]; then
  echo "  Skipped (services managed by docker compose)"
else
  docker compose down -v 2>/dev/null || true
  docker compose up -d --build --wait
fi
echo ""

# Step 2: Deploy to localstack via OpenTofu and start supervisor.
echo "=== [2/11] Deploying to localstack via tofu ==="

# Clean up any stale state from previous runs.
tofu_destroy

tofu_apply

# tofu leaves SSM /dev/my-app/unlocked/KMSKeyID = "UNSET"; the enclave's EnsureKeyID
# calls CreateKey on the first boot, registers the new ID, and locks the
# policy to its own PCR0 at creation time.

# Start supervisor on the host (like production EC2 host).
# Configured with stop/start commands that manage boot_qemu via PID file.
# We run supervisor under a tiny relauncher script that loops "run supervisor; wait;
# relaunch" — the test's analog of systemd Restart=always in production.
# This lets ENCLAVE_SUPERVISOR_RESTART_CMD just kill the current supervisor process; the
# supervisor resurrects it with the updated on-disk binary.
echo "  Starting supervisor..."
# Keep the running EIF separate from the mutable Tofu candidate input. Applying
# a candidate must never change what a watchdog restart boots.
cp -f "$EIF_PATH" "$ACTIVE_EIF_PATH"
EIF_ABS_PATH="$ACTIVE_EIF_PATH"

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
# vhost-device-vsock owns QEMU's actual guest CID and exposes selected guest
# ports on its host loopback forward CID. The supervisor must dial that bridge,
# not the unrelated production default CID or the unregistered QEMU guest CID.
export ENCLAVE_CID="${VSOCK_FORWARD_CID:-1}"
export ENCLAVE_SUPERVISOR_ADDR="127.0.0.1:8444"
# The supervisor runs in-process gvproxy (vsock:1024) and IMDS forwarder
# (vsock:8002) just as it does in prod. Only the enclave launcher differs:
# QEMU stands in for nitro-cli via ENCLAVE_START_CMD below.
#
# Forward enclave TLS (443 inside) to unprivileged 8443 on the host so
# the test can curl https://localhost:8443/health without root.
export GVPROXY_FORWARD_PORTS="8443:443"
# Point the in-process IMDS forwarder at mock-imds instead of the real
# 169.254.169.254 (which isn't reachable from the test container).
export IMDS_PROXY_TARGET="127.0.0.1:1338"
# Shorten commit-poll timeout so rollback tests don't wait 5min for the default.
export ENCLAVE_MIGRATION_COMMIT_TIMEOUT="45s"
export ENCLAVE_URL="https://127.0.0.1:8443"
export ENCLAVE_EIF_PATH="$EIF_ABS_PATH"
export ENCLAVE_SUPERVISOR_BINARY_PATH="$ENCLAVE_SUPERVISOR"
export ENCLAVE_SUPERVISOR_RESTART_CMD="kill \$(cat $SUPERVISOR_PIDFILE)"
export ENCLAVE_STOP_CMD="kill \$(cat /tmp/enclave-boot.pid) 2>/dev/null; sleep 3"
export ENCLAVE_START_CMD="nohup \"$SCRIPT_PATH\" --boot-only \"$EIF_ABS_PATH\" >> /tmp/boot-qemu.log 2>&1 &"
export AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_LOGS="http://127.0.0.1:4566"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

# Inline KMS endpoint for the supervisor only. The test env runs two
# independent KMS mocks: LocalStack at :4566 holds the pcr0_signing key
# that tofu created; kms-proxy → local-kms at :4000 holds the runtime's
# encryption key. Exporting AWS_ENDPOINT_URL_KMS=4000 globally would
# leak into later candidate applies, whose local-exec would
# then ask local-kms for a key UUID that only exists in LocalStack.
AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4000" \
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
echo "=== [3/11] Booting enclave in QEMU ==="
wait_for_enclave "initial boot"
echo ""

# Verify the locked KMS policy includes the default RootRecovery statement.
# The enclave's selfApplyKMSPolicy() runs at boot and calls PutKeyPolicy on
# the local-kms mock (port 4000). After boot, the policy should carry the
# fourth statement granting AWS account root the recovery action set.
KMS_KEY_ID=$(aws ssm get-parameter --name "/dev/my-app/unlocked/KMSKeyID" \
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
echo "=== [4/11] Running integration tests ==="
./integration-test.sh
echo ""

# Step 5: candidate publication and explicit migration control.
echo "=== [5/11] Explicit migration: v1 -> v2 ==="
SUPERVISOR_URL="http://127.0.0.1:${SUPERVISOR_PORT:-8444}"
ENCLAVE_LOCAL_URL="https://127.0.0.1:${HOST_TLS_PORT:-8443}"
ARTIFACTS="${SCRIPT_DIR}/app/.enclave/artifacts"
V1_PCR0=$(jq -r '.PCR0 | ascii_downcase' "${ARTIFACTS}/pcr-v1.json")
V2_PCR0=$(jq -r '.PCR0 | ascii_downcase' "${ARTIFACTS}/pcr-v2.json")
V3_PCR0=$(jq -r '.PCR0 | ascii_downcase' "${ARTIFACTS}/pcr-v3.json")
V4_PCR0=$(jq -r '.PCR0 | ascii_downcase' "${ARTIFACTS}/pcr-v4.json")

# KMS endpoint deliberately remains explicit on KMS calls. Exporting the local
# KMS proxy globally would divert Tofu's PCR0-signing calls away from LocalStack.
export AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566"

migration_status() {
  (cd "${SCRIPT_DIR}/app" && "$ENCLAVE_CLI" migration \
    --enclave-url "$ENCLAVE_LOCAL_URL" status)
}

migration_request() {
  (cd "${SCRIPT_DIR}/app" && "$ENCLAVE_CLI" migration \
    --supervisor-url "$SUPERVISOR_URL" "$@" request)
}

migration_abort() {
  (cd "${SCRIPT_DIR}/app" && "$ENCLAVE_CLI" migration \
    --supervisor-url "$SUPERVISOR_URL" abort)
}

migration_finalise() {
  (cd "${SCRIPT_DIR}/app" && "$ENCLAVE_CLI" migration \
    --supervisor-url "$SUPERVISOR_URL" "$@" finalise)
}

migration_json() {
  curl -skf --max-time 10 "${ENCLAVE_LOCAL_URL}/v1/enclave-info" | jq -c '.migration'
}

current_kms_key() {
  aws ssm get-parameter $LOCALSTACK \
    --name "/dev/my-app/unlocked/KMSKeyID" \
    --query 'Parameter.Value' --output text
}

restart_enclave() {
  curl -sf --max-time 10 -X POST "${SUPERVISOR_URL}/stop" >/dev/null
  curl -sf --max-time 10 -X POST "${SUPERVISOR_URL}/start" >/dev/null
}

publish_candidate() {
  local version="$1" expected_pcr0="$2"
  cp "${ARTIFACTS}/image-v${version}.eif" "${ARTIFACTS}/image.eif"
  cp "${ARTIFACTS}/pcr-v${version}.json" "${ARTIFACTS}/pcr.json"
  tofu_apply

  CANDIDATE_PCR0=$(tofu -chdir="$TOFU_DIR" output -raw candidate_pcr0)
  CANDIDATE_BUCKET=$(tofu -chdir="$TOFU_DIR" output -raw candidate_artifact_bucket)
  CANDIDATE_EIF_KEY=$(tofu -chdir="$TOFU_DIR" output -raw candidate_eif_key)
  CANDIDATE_SUPERVISOR_KEY=$(tofu -chdir="$TOFU_DIR" output -raw candidate_supervisor_key)
  if [ "$CANDIDATE_PCR0" != "$expected_pcr0" ] || \
     [ "$CANDIDATE_EIF_KEY" != "candidates/${expected_pcr0}/enclave.eif" ] || \
     [ "$CANDIDATE_SUPERVISOR_KEY" != "candidates/${expected_pcr0}/supervisor" ]; then
    echo "  FAIL: Tofu candidate outputs are not PCR0-addressed for v${version}" >&2
    exit 1
  fi
  aws s3api head-object $LOCALSTACK --bucket "$CANDIDATE_BUCKET" \
    --key "$CANDIDATE_EIF_KEY" >/dev/null
  aws s3api head-object $LOCALSTACK --bucket "$CANDIDATE_BUCKET" \
    --key "$CANDIDATE_SUPERVISOR_KEY" >/dev/null
  echo "  PASS: Tofu published v${version} at candidates/${expected_pcr0}/"
}

expect_finalise_http() {
  local expected="$1" log="$2" rc
  shift 2
  set +e
  migration_finalise "$@" >"$log" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ] || ! grep -q "HTTP ${expected}" "$log"; then
    echo "  FAIL: migration finalise did not fail with HTTP ${expected}" >&2
    cat "$log" >&2
    exit 1
  fi
  echo "  PASS: migration finalise rejected with HTTP ${expected}"
}

wait_for_supervisor_restart() {
  local old_pid="$1" current_pid=""
  for _ in $(seq 1 15); do
    sleep 1
    current_pid=$(cat "$SUPERVISOR_PIDFILE" 2>/dev/null || true)
    if [ -n "$current_pid" ] && [ "$current_pid" != "$old_pid" ] && kill -0 "$current_pid" 2>/dev/null; then
      echo "  PASS: supervisor restarted (${old_pid} -> ${current_pid})"
      curl -sf --max-time 5 "${SUPERVISOR_URL}/health" >/dev/null
      return
    fi
  done
  echo "  FAIL: supervisor did not restart within 15s (pre=${old_pid}, current=${current_pid})" >&2
  exit 1
}

verify_migrated_state() {
  local label="$1" expected_predecessor="$2" expected_current="$3"
  wait_for_enclave "$label"
  local info predecessor current secrets storage persistent attestation
  info=$(curl -skf --max-time 10 "${ENCLAVE_LOCAL_URL}/v1/enclave-info")
  predecessor=$(echo "$info" | jq -r '.previous_pcr0 | ascii_downcase')
  current=$(echo "$info" | jq -r '.migration.source_pcr0 | ascii_downcase')
  if [ "$predecessor" != "$expected_predecessor" ] || [ "$current" != "$expected_current" ]; then
    echo "  FAIL: ${label} PCR chain mismatch (predecessor=${predecessor}, current=${current})" >&2
    exit 1
  fi
  echo "  PASS: ${label} PCR chain ${expected_predecessor:0:16}... -> ${expected_current:0:16}..."

  secrets=$(curl -skf --max-time 10 "${ENCLAVE_LOCAL_URL}/test/secrets")
  storage=$(curl -skf --max-time 10 "${ENCLAVE_LOCAL_URL}/test/storage")
  persistent=$(curl -skf --max-time 10 "${ENCLAVE_LOCAL_URL}/test/storage-persistence")
  attestation=$(curl -skf --max-time 10 "${ENCLAVE_LOCAL_URL}/test/attestation-persistence")
  if ! echo "$secrets" | jq -e '.status == "ok"' >/dev/null || \
     ! echo "$storage" | jq -e '.roundtrip == true' >/dev/null || \
     ! echo "$persistent" | jq -e '.ok == true' >/dev/null || \
     ! echo "$attestation" | jq -e '.ok == true' >/dev/null; then
    echo "  FAIL: ${label} did not preserve secrets, storage, or attestation state" >&2
    exit 1
  fi
  echo "  PASS: ${label} preserved static secrets, DEK storage, persistent state, and signing identity"
}

SOURCE_INFO=$(curl -skf --max-time 10 "${ENCLAVE_LOCAL_URL}/v1/enclave-info")
SOURCE_COOLDOWN=$(echo "$SOURCE_INFO" | jq -r '.migration_cooldown_seconds')
SOURCE_STATE=$(echo "$SOURCE_INFO" | jq -r '.migration.state')
SOURCE_PCR0=$(echo "$SOURCE_INFO" | jq -r '.migration.source_pcr0 | ascii_downcase')
if [ "$SOURCE_COOLDOWN" -le 0 ] || [ "$SOURCE_STATE" != "none" ] || [ "$SOURCE_PCR0" != "$V1_PCR0" ]; then
  echo "  FAIL: v1 must start with a baked nonzero cooldown and migration state none" >&2
  exit 1
fi
echo "  PASS: v1 reports source PCR0 and baked ${SOURCE_COOLDOWN}s cooldown"

# Verify Tofu app.env overrides before migration while the source app is usable.
ENV_OVERRIDE_RESP=$(curl -skf --max-time 10 "${ENCLAVE_LOCAL_URL}/test/env-override")
if ! echo "$ENV_OVERRIDE_RESP" | jq -e \
    '.test_runtime_override == "override-from-tofu" and .test_runtime_override_envfile == "override-from-envfile"' \
    >/dev/null; then
  echo "  FAIL: Tofu app.env overrides are not visible in the source app" >&2
  exit 1
fi
echo "  PASS: Tofu app.env overrides are visible before migration"

SOURCE_KEY=$(current_kms_key)
publish_candidate 2 "$V2_PCR0"
POST_APPLY_STATUS=$(migration_json)
if [ "$(echo "$POST_APPLY_STATUS" | jq -r '.state')" != "none" ] || \
   [ "$(echo "$POST_APPLY_STATUS" | jq -r '.source_pcr0')" != "$V1_PCR0" ] || \
   [ "$(current_kms_key)" != "$SOURCE_KEY" ] || \
   ! cmp -s "$ACTIVE_EIF_PATH" "${ARTIFACTS}/image-v1.eif"; then
  echo "  FAIL: applying v2 activated or mutated the running v1 enclave" >&2
  exit 1
fi
echo "  PASS: v2 apply only published a candidate; v1 PCR, KMS key, and active EIF are unchanged"

# Request a different checked target first, then prove the public intent
# survives a source restart with identical timing metadata.
migration_request --target-pcr0 "$V3_PCR0" | tee /tmp/migration-request-v3.log
migration_status | tee /tmp/migration-status-v3.log
REQUEST_ONE=$(migration_json)
if ! echo "$REQUEST_ONE" | jq -e --arg source "$V1_PCR0" --arg target "$V3_PCR0" \
    '.state == "cooling_down" and .source_pcr0 == $source and .target_pcr0 == $target and .action == "requested" and .sequence == 1 and .remaining_seconds > 0' \
    >/dev/null; then
  echo "  FAIL: first request did not enter cooling_down for the alternate v3 target" >&2
  exit 1
fi
REQUEST_ONE_SEQUENCE=$(echo "$REQUEST_ONE" | jq -r '.sequence')
REQUEST_ONE_PUBLISHED=$(echo "$REQUEST_ONE" | jq -r '.published_at')
REQUEST_ONE_ELIGIBLE=$(echo "$REQUEST_ONE" | jq -r '.eligible_at')
if ! curl -skf --max-time 10 "${ENCLAVE_LOCAL_URL}/test/storage" | \
    jq -e '.roundtrip == true' >/dev/null; then
  echo "  FAIL: source application became unusable during cooldown" >&2
  exit 1
fi
echo "  PASS: source application remains usable during cooldown"
restart_enclave
wait_for_enclave "v1 restart during migration cooldown"
migration_status | tee /tmp/migration-status-restarted.log
REQUEST_RECOVERED=$(migration_json)
if ! echo "$REQUEST_RECOVERED" | jq -e \
    --argjson sequence "$REQUEST_ONE_SEQUENCE" \
    --arg published "$REQUEST_ONE_PUBLISHED" --arg eligible "$REQUEST_ONE_ELIGIBLE" \
    '(.state == "cooling_down" or .state == "eligible") and .sequence == $sequence and .published_at == $published and .eligible_at == $eligible' \
    >/dev/null; then
  echo "  FAIL: restarted v1 did not recover the same intent and eligibility deadline" >&2
  exit 1
fi
echo "  PASS: v1 restart recovered sequence, published_at, and eligible_at"

migration_abort | tee /tmp/migration-abort.log
migration_status | tee /tmp/migration-status-aborted.log
ABORTED_STATUS=$(migration_json)
ABORT_SEQUENCE=$(echo "$ABORTED_STATUS" | jq -r '.sequence')
if ! echo "$ABORTED_STATUS" | jq -e --arg target "$V3_PCR0" \
    '.state == "aborted" and .action == "aborted" and .target_pcr0 == $target and .sequence == 2' \
    >/dev/null; then
  echo "  FAIL: abort was not durably published" >&2
  exit 1
fi
expect_finalise_http 409 /tmp/finalise-aborted.log

PRE_EARLY_KEY=$(current_kms_key)
migration_request | tee /tmp/migration-request-v2.log
expect_finalise_http 425 /tmp/finalise-too-early.log \
  --target-pcr0 "$CANDIDATE_PCR0" \
  --artifact-bucket "$CANDIDATE_BUCKET" \
  --eif-key "$CANDIDATE_EIF_KEY" \
  --supervisor-key "$CANDIDATE_SUPERVISOR_KEY"
REQUEST_TWO=$(migration_json)
REQUEST_TWO_SEQUENCE=$(echo "$REQUEST_TWO" | jq -r '.sequence')
if ! echo "$REQUEST_TWO" | jq -e \
    --arg source "$V1_PCR0" --arg target "$V2_PCR0" --argjson previous "$ABORT_SEQUENCE" \
    '.state == "cooling_down" and .source_pcr0 == $source and .target_pcr0 == $target and .action == "requested" and .sequence == ($previous + 1)' \
    >/dev/null; then
  echo "  FAIL: replacement request did not advance the sequence to the v2 target" >&2
  exit 1
fi
echo "  PASS: replacement request advanced sequence ${ABORT_SEQUENCE} -> ${REQUEST_TWO_SEQUENCE} and selected v2"

if [ "$(current_kms_key)" != "$PRE_EARLY_KEY" ] || \
   ! cmp -s "$ACTIVE_EIF_PATH" "${ARTIFACTS}/image-v1.eif" || \
   [ "$(migration_json | jq -r '.source_pcr0')" != "$V1_PCR0" ]; then
  echo "  FAIL: too-early finalise changed KMS, EIF, or running source PCR0" >&2
  exit 1
fi
echo "  PASS: HTTP 425 finalise had no KMS or EIF activation side effects"

# Validate the generated public log anonymously, including the selected v2
# replacement request and the generated SSM bucket-name wiring.
INTENT_BUCKET=$(tofu -chdir="$TOFU_DIR" output -raw migration_intent_bucket)
SSM_INTENT_BUCKET=$(aws ssm get-parameter $LOCALSTACK \
  --name "/dev/my-app/MigrationIntentBucketName" \
  --query 'Parameter.Value' --output text)
if [ -z "$INTENT_BUCKET" ] || [ "$INTENT_BUCKET" != "$SSM_INTENT_BUCKET" ]; then
  echo "  FAIL: migration_intent_bucket output does not match generated MigrationIntentBucketName" >&2
  exit 1
fi
VERSIONING=$(aws s3api get-bucket-versioning $LOCALSTACK --bucket "$INTENT_BUCKET" --output json)
if [ "$(echo "$VERSIONING" | jq -r '.Status')" != "Enabled" ]; then
  echo "  FAIL: migration intent bucket versioning is not enabled" >&2
  exit 1
fi
PUBLIC_VERSIONS=$(aws s3api list-object-versions $LOCALSTACK --no-sign-request \
  --bucket "$INTENT_BUCKET" --prefix "migration-intent/${V1_PCR0}/" --output json)
if [ "$(echo "$PUBLIC_VERSIONS" | jq '[.Versions[]] | length')" -ne 3 ]; then
  echo "  FAIL: anonymous version listing did not expose exactly three v1 intent entries" >&2
  exit 1
fi
REQUEST_TWO_KEY=$(printf 'migration-intent/%s/%020d' "$V1_PCR0" "$REQUEST_TWO_SEQUENCE")
REQUEST_TWO_VERSION=$(echo "$PUBLIC_VERSIONS" | jq -r --arg key "$REQUEST_TWO_KEY" \
  '.Versions[] | select(.Key == $key) | .VersionId')
if [ -z "$REQUEST_TWO_VERSION" ] || [ "$REQUEST_TWO_VERSION" = "null" ]; then
  echo "  FAIL: selected replacement request version is not publicly listed" >&2
  exit 1
fi
aws s3api get-object $LOCALSTACK --no-sign-request --bucket "$INTENT_BUCKET" \
  --key "$REQUEST_TWO_KEY" --version-id "$REQUEST_TWO_VERSION" \
  /tmp/public-migration-intent.json >/dev/null
if ! jq -e --arg target "$V2_PCR0" --argjson sequence "$REQUEST_TWO_SEQUENCE" '
    (keys | sort) == ["action", "attestation", "schema", "sequence", "target_pcr0"] and
    .schema == "enclave.migration_intent.v1" and .action == "requested" and
    .target_pcr0 == $target and .sequence == $sequence and
    (.attestation | type == "string" and length > 0)
  ' /tmp/public-migration-intent.json >/dev/null; then
  echo "  FAIL: public migration intent JSON schema or selected values differ" >&2
  exit 1
fi
RETENTION=$(aws s3api get-object-retention $LOCALSTACK --bucket "$INTENT_BUCKET" \
  --key "$REQUEST_TWO_KEY" --version-id "$REQUEST_TWO_VERSION" --output json)
if [ "$(echo "$RETENTION" | jq -r '.Retention.Mode')" != "COMPLIANCE" ] || \
   [ -z "$(echo "$RETENTION" | jq -r '.Retention.RetainUntilDate // empty')" ]; then
  echo "  FAIL: selected migration intent lacks COMPLIANCE retention" >&2
  exit 1
fi
PUBLIC_POLICY=$(aws s3api get-bucket-policy $LOCALSTACK --bucket "$INTENT_BUCKET" \
  --query Policy --output text)
if ! echo "$PUBLIC_POLICY" | jq -e '
    [.Statement[] | select(.Effect == "Allow" and .Principal == "*") | .Action] |
    flatten | sort == ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucketVersions"]
  ' >/dev/null; then
  echo "  FAIL: public migration intent policy grants actions beyond list/read" >&2
  exit 1
fi
echo "  PASS: public log is anonymously listable/readable, versioned, COMPLIANCE-retained, exact-schema, and grants no public writes"

# The wait is bounded by the short cooldown baked into v1, plus a small margin.
WAIT_LIMIT=$(echo "$REQUEST_TWO" | jq -r '.remaining_seconds + 15')
if [ "$WAIT_LIMIT" -gt 90 ]; then
  echo "  FAIL: baked migration cooldown is too long for this integration path (${WAIT_LIMIT}s bound)" >&2
  exit 1
fi
ELIGIBLE=false
for _ in $(seq 1 "$WAIT_LIMIT"); do
  if [ "$(migration_json | jq -r '.state')" = "eligible" ]; then
    ELIGIBLE=true
    break
  fi
  sleep 1
done
if [ "$ELIGIBLE" != true ]; then
  echo "  FAIL: v2 request did not become eligible within ${WAIT_LIMIT}s" >&2
  exit 1
fi
migration_status | tee /tmp/migration-status-v2-eligible.log

PRE_MIGRATION_SUP_PID=$(cat "$SUPERVISOR_PIDFILE")
migration_finalise | tee /tmp/migration-finalise-v2.log
if ! grep -q "complete: Migration complete" /tmp/migration-finalise-v2.log || \
   ! grep -q "supervisor update ready" /tmp/migration-finalise-v2.log; then
  echo "  FAIL: v1 -> v2 finalise did not complete its supervisor update" >&2
  exit 1
fi
wait_for_supervisor_restart "$PRE_MIGRATION_SUP_PID"
V2_KEY=$(current_kms_key)
if [ "$V2_KEY" = "$SOURCE_KEY" ]; then
  echo "  FAIL: v1 -> v2 did not activate a new KMS key" >&2
  exit 1
fi
verify_migrated_state "v2 after successful migration" "$V1_PCR0" "$V2_PCR0"

# Step 6: v2 has zero cooldown baked in. Tofu still only publishes v3, and
# finalisation remains intent-gated even with no wait.
echo ""
echo "=== [6/11] Zero-cooldown migration: v2 -> v3 ==="
publish_candidate 3 "$V3_PCR0"
if [ "$(migration_json | jq -r '.source_pcr0')" != "$V2_PCR0" ] || \
   ! cmp -s "$ACTIVE_EIF_PATH" "${ARTIFACTS}/image-v2.eif"; then
  echo "  FAIL: v3 candidate apply automatically activated" >&2
  exit 1
fi
expect_finalise_http 409 /tmp/finalise-v3-no-intent.log
if [ "$(current_kms_key)" != "$V2_KEY" ]; then
  echo "  FAIL: no-intent finalise changed the v2 KMS key" >&2
  exit 1
fi
migration_request | tee /tmp/migration-request-v3-zero.log
migration_status | tee /tmp/migration-status-v3-zero.log
V3_REQUEST=$(migration_json)
if ! echo "$V3_REQUEST" | jq -e --arg source "$V2_PCR0" --arg target "$V3_PCR0" \
    '.state == "eligible" and .source_pcr0 == $source and .target_pcr0 == $target and .action == "requested" and .remaining_seconds == 0' \
    >/dev/null; then
  echo "  FAIL: v2 zero-cooldown request was not immediately eligible" >&2
  exit 1
fi
PRE_V3_SUP_PID=$(cat "$SUPERVISOR_PIDFILE")
migration_finalise | tee /tmp/migration-finalise-v3.log
wait_for_supervisor_restart "$PRE_V3_SUP_PID"
V3_KEY=$(current_kms_key)
if [ "$V3_KEY" = "$V2_KEY" ]; then
  echo "  FAIL: v2 -> v3 did not activate a new KMS key" >&2
  exit 1
fi
verify_migrated_state "v3 after zero-cooldown migration" "$V2_PCR0" "$V3_PCR0"

# Step 7: v4 is a Tofu-published candidate whose baked app name is wrong.
# The source v3 finalises, v4 fails readiness, and the supervisor restores v3.
echo ""
echo "=== [7/11] Wrong-app rollback: v3 -> v4 -> v3 ==="
publish_candidate 4 "$V4_PCR0"
if [ "$(migration_json | jq -r '.source_pcr0')" != "$V3_PCR0" ] || \
   ! cmp -s "$ACTIVE_EIF_PATH" "${ARTIFACTS}/image-v3.eif"; then
  echo "  FAIL: v4 candidate apply automatically activated" >&2
  exit 1
fi
migration_request | tee /tmp/migration-request-v4.log
if [ "$(migration_json | jq -r '.state')" != "eligible" ]; then
  echo "  FAIL: v3 zero-cooldown request for v4 was not immediately eligible" >&2
  exit 1
fi
set +e
migration_finalise >/tmp/migration-finalise-v4.log 2>&1
V4_FINALISE_RC=$?
set -e
if [ "$V4_FINALISE_RC" -eq 0 ] || \
   ! grep -q "rollback:" /tmp/migration-finalise-v4.log || \
   ! grep -q "rollback-complete:" /tmp/migration-finalise-v4.log; then
  echo "  FAIL: wrong-app v4 did not produce the expected readiness rollback" >&2
  cat /tmp/migration-finalise-v4.log >&2
  exit 1
fi
echo "  PASS: wrong-app v4 emitted rollback and rollback-complete"
verify_migrated_state "v3 restored and ready after v4 rollback" "$V3_PCR0" "$V3_PCR0"
if ! cmp -s "$ACTIVE_EIF_PATH" "${ARTIFACTS}/image-v3.eif"; then
  echo "  FAIL: rollback did not restore the v3 EIF" >&2
  exit 1
fi

# Step 8: Crash the app only after cooldown and migration coverage so the
# source application remains usable throughout operator decision windows.
echo ""
echo "=== [8/11] Runtime resilience: upstream app crash ==="
RESILIENCE_LOG="${SCRIPT_DIR}/crash-resilience.log"
: > "$RESILIENCE_LOG"
curl -sk -X POST --max-time 5 "${ENCLAVE_LOCAL_URL}/test/crash" \
  >>"$RESILIENCE_LOG" 2>&1 || true
sleep 3
HEALTH=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
  "${ENCLAVE_LOCAL_URL}/health" 2>>"$RESILIENCE_LOG" || echo "000")
RUNTIME_INFO=$(curl -sk --max-time 5 "${ENCLAVE_LOCAL_URL}/v1/enclave-info" \
  2>>"$RESILIENCE_LOG" || true)
APP_PROXY=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
  "${ENCLAVE_LOCAL_URL}/test/storage-persistence" 2>>"$RESILIENCE_LOG" || echo "000")
if [ "$HEALTH" != "200" ] || \
   [ "$(echo "$RUNTIME_INFO" | jq -r '.upstream_app.exited // false')" != "true" ] || \
   [ "$APP_PROXY" != "502" ]; then
  echo "  FAIL: runtime/app crash isolation assertions failed; see ${RESILIENCE_LOG}" >&2
  exit 1
fi
echo "  PASS: runtime stays healthy, reports app exit, and dead app routes return 502"

# Preserve the supervisor health and atomic key-scoped ciphertext assertions.
echo ""
echo "=== [8.5/11] Atomic migration observability checks ==="
SUP_HEALTH_CODE=$(curl -s --max-time 5 -o /tmp/supervisor-health.json -w '%{http_code}' \
  "${SUPERVISOR_URL}/supervisor/health" 2>/dev/null || echo "000")
if [ "$SUP_HEALTH_CODE" != "200" ] || \
   [ "$(jq -r '.status // empty' /tmp/supervisor-health.json 2>/dev/null || true)" != "ok" ]; then
  echo "  FAIL: /supervisor/health is not ok after migration" >&2
  exit 1
fi
NEW_KEY=$(current_kms_key)
NEW_CT=$(aws ssm get-parameter $LOCALSTACK \
  --name "/dev/my-app/unlocked/signing_key/Ciphertext/$NEW_KEY" \
  --query 'Parameter.Value' --output text 2>/dev/null || true)
if [ -z "$NEW_KEY" ] || [ "$NEW_KEY" = "UNSET" ] || \
   [ -z "$NEW_CT" ] || [ "$NEW_CT" = "UNSET" ]; then
  echo "  FAIL: key-scoped signing_key ciphertext is absent after migration" >&2
  exit 1
fi
echo "  PASS: supervisor health is ok and key-scoped migration ciphertext exists"

# Step 8.7: State-origin tamper (issue #131). The boot-time state root commits
# to every runtime ciphertext, so replacing one must make resume fail closed.
echo ""
echo "=== [8.7/11] State-origin: tampered ciphertext -> fail closed ==="
DEK_PARAM="/dev/my-app/unlocked/StorageDEK/Ciphertext/${NEW_KEY}"
ORIG_DEK=$(aws ssm get-parameter --name "$DEK_PARAM" $LOCALSTACK \
  --query 'Parameter.Value' --output text 2>/dev/null || true)
if [ -z "$ORIG_DEK" ]; then
  echo "  FAIL: could not read StorageDEK ciphertext from SSM" >&2
  exit 1
fi
aws ssm put-parameter --name "$DEK_PARAM" --value "dGFtcGVyZWQtY2lwaGVydGV4dA==" \
  --type String --overwrite $LOCALSTACK >/dev/null
restart_enclave
echo "  Asserting enclave stays unhealthy on tampered state (30s)..."
TAMPER_HEALTHY=false
for _ in $(seq 1 30); do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 \
    "${ENCLAVE_LOCAL_URL}/health" 2>/dev/null || echo "000")
  if [ "$CODE" = "200" ]; then TAMPER_HEALTHY=true; break; fi
  sleep 1
done
if [ "$TAMPER_HEALTHY" = true ]; then
  echo "  FAIL: enclave became healthy with a tampered ciphertext" >&2
  aws ssm put-parameter --name "$DEK_PARAM" --value "$ORIG_DEK" \
    --type String --overwrite $LOCALSTACK >/dev/null
  restart_enclave
  exit 1
fi
echo "  PASS: tampered StorageDEK ciphertext kept the enclave unhealthy for 30s"
aws ssm put-parameter --name "$DEK_PARAM" --value "$ORIG_DEK" \
  --type String --overwrite $LOCALSTACK >/dev/null
restart_enclave
wait_for_enclave "resume after state-origin restore"
echo "  PASS: restored ciphertext lets the enclave resume healthy"


# Step 9.5: Supervisor resilience — SIGKILL supervisor and verify the
# supervisor relaunches it and it reconnects to AWS/enclave cleanly.
# This is the foundation that mid-migration crash recovery relies on:
# if supervisor dies mid-handleMigrate, a new supervisor must come up with fresh
# state (supervisor is stateless; all migration state lives in SSM).
echo ""
echo "=== [9.5/11] Supervisor resilience ==="
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

wait_for_enclave "after supervisor relaunch"

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

RECOVERY_KMS_KEY_ID=$(aws ssm get-parameter --name "/dev/my-app/unlocked/KMSKeyID" \
  --endpoint-url "http://127.0.0.1:4566" --region us-east-1 \
  --query 'Parameter.Value' --output text 2>/dev/null || echo "")
if [ -z "$RECOVERY_KMS_KEY_ID" ]; then
  echo "  FAIL: could not read /dev/my-app/unlocked/KMSKeyID from SSM" >&2
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
ENCLAVE_PRINCIPAL=$(echo "$CURRENT_POLICY" | jq -r '.Statement[] | select(.Sid=="EnclaveAttestedOperations") | .Principal.AWS')
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
