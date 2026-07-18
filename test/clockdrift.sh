#!/usr/bin/env bash
# End-to-end clock-drift test: boots the test enclave with a synthetic clock skew injected
# via the kernel command line (enclavecfg.clock_test_step_ns), and verifies the PI servo
# detects and corrects it against the hypervisor PHC — hard-stepping CLOCK_REALTIME back onto
# the PHC and then holding a bounded offset.
#
# Requires /dev/ptp0 in the guest (ptp_kvm on a KVM runner); the enclave's clock sync is fatal
# at boot, so a missing PHC shows up as a boot timeout. The EIF must be a dev build
# (ENCLAVE_DEV=true baked) — enclavecfg.* overrides and the servo's dev cadence are gated on it.
#
# Runs inside the clockdrift-runner container (test/docker-compose.yml). `make test-clockdrift`
# is the entry point. The supervisor is run only for in-process gvproxy + the IMDS forwarder;
# this script boots QEMU directly (no watchdog restart loop).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

EIF_PATH="${1:?Usage: clockdrift.sh <path-to-eif>}"
EIF_ABS="$(realpath "$EIF_PATH")"

GUEST_CID="${GUEST_CID:-4}"
MEMORY="${MEMORY:-2G}"
HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"
TOFU_DIR="${SCRIPT_DIR}/app/tofu"
VSOCK_SOCKET="/tmp/vhost${GUEST_CID}.socket"
ENCLAVE_PIDS="/tmp/clockdrift-enclave-pids"
SUP_LOG="${SCRIPT_DIR}/clockdrift-supervisor.log"
BOOT_LOG="${SCRIPT_DIR}/clockdrift-boot.log"

# The synthetic skew (ns) + poll cadence injected via the dev cmdline channel (enclavecfg.*).
# 500ms > maxStepNs (100ms), so the servo must hard-step — not slew — to recover.
CLOCK_STEP_NS="${CLOCK_STEP_NS:-500000000}"
CLOCK_STEP_MS=$((CLOCK_STEP_NS / 1000000))
export QEMU_APPEND="enclavecfg.clock_poll_interval=2s enclavecfg.clock_test_step_ns=${CLOCK_STEP_NS}"

export ENCLAVE_CONFIG="${SCRIPT_DIR}/app/enclave/enclave.yaml"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566"
export AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4566"

if command -v enclave-cli &>/dev/null && command -v supervisor &>/dev/null; then
  ENCLAVE_CLI="$(command -v enclave-cli)"
  ENCLAVE_SUPERVISOR="$(command -v supervisor)"
else
  ENCLAVE_CLI="/tmp/enclave-cli"
  ENCLAVE_SUPERVISOR="/tmp/supervisor"
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_CLI" ./cli/cmd/enclave)
  (cd "$REPO_ROOT" && go build -o "$ENCLAVE_SUPERVISOR" ./supervisor/cmd/supervisor)
fi

PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1" >&2; FAIL=$((FAIL + 1)); }

tofu_destroy() {
  if [ -f "${TOFU_DIR}/terraform.tfstate" ]; then
    tofu -chdir="$TOFU_DIR" destroy -auto-approve -input=false >"${SCRIPT_DIR}/clockdrift-tofu-destroy.log" 2>&1 || true
  fi
  rm -f "${TOFU_DIR}/terraform.tfstate"* "${TOFU_DIR}/provider_override.tf" "${TOFU_DIR}/backend.tf" 2>/dev/null || true
  rm -rf "${TOFU_DIR}/.terraform" 2>/dev/null || true
}

# tofu_apply scaffolds the module and applies it against localstack, seeding the KMS key, the
# SSM parameters, and the S3 buckets the enclave reads at boot.
tofu_apply() {
  rm -f "${TOFU_DIR}/main.tf" "${TOFU_DIR}/modules/enclave/main.tf"
  mkdir -p "${SCRIPT_DIR}/app/.enclave/artifacts"
  for f in image.eif supervisor; do
    [ -f "${SCRIPT_DIR}/app/.enclave/artifacts/$f" ] || touch "${SCRIPT_DIR}/app/.enclave/artifacts/$f"
  done

  (cd "${SCRIPT_DIR}/app" && LOCAL_DEPLOYMENT=true "$ENCLAVE_CLI" tofu init >"${SCRIPT_DIR}/clockdrift-tofu-scaffold.log" 2>&1) \
    || { cat "${SCRIPT_DIR}/clockdrift-tofu-scaffold.log"; return 1; }

  cat >"${TOFU_DIR}/backend.tf" <<BACKEND
terraform {
  backend "local" {
    path = "${TOFU_DIR}/terraform.tfstate"
  }
}
BACKEND

  cat >"${TOFU_DIR}/provider_override.tf" <<'OVERRIDE'
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

  tofu -chdir="$TOFU_DIR" init -input=false >"${SCRIPT_DIR}/clockdrift-tofu-init.log" 2>&1 \
    || { cat "${SCRIPT_DIR}/clockdrift-tofu-init.log"; return 1; }
  tofu -chdir="$TOFU_DIR" apply -auto-approve -input=false -compact-warnings >"${SCRIPT_DIR}/clockdrift-tofu-apply.log" 2>&1 \
    || { echo "tofu apply FAILED:"; tail -25 "${SCRIPT_DIR}/clockdrift-tofu-apply.log"; return 1; }
}

# start_supervisor runs the supervisor purely for in-process gvproxy + the IMDS forwarder.
start_supervisor() {
  ENCLAVE_AWS_REGION=us-east-1 \
  ENCLAVE_DEPLOYMENT=dev \
  ENCLAVE_APP_NAME=my-app \
  ENCLAVE_SUPERVISOR_ADDR="127.0.0.1:8444" \
  ENCLAVE_URL="https://127.0.0.1:8443" \
  GVPROXY_FORWARD_PORTS="8443:443" \
  IMDS_PROXY_TARGET="127.0.0.1:1338" \
  AWS_ACCESS_KEY_ID=test \
  AWS_SECRET_ACCESS_KEY=test \
  AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566" \
  AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566" \
  AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566" \
  AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4000" \
    "$ENCLAVE_SUPERVISOR" >"$SUP_LOG" 2>&1 &
  local sup_pid=$!
  echo "$sup_pid" >/tmp/clockdrift-supervisor.pid
  sleep 3
  if ! kill -0 "$sup_pid" 2>/dev/null; then
    echo "Error: supervisor exited immediately — log:" >&2
    cat "$SUP_LOG" >&2 2>/dev/null || true
    return 1
  fi
  echo "  supervisor up (pid $sup_pid) — gvproxy + IMDS"
}

# boot_enclave brings up the AF_VSOCK fabric and launches the EIF in QEMU with the clock skew
# on the kernel cmdline, then returns; QEMU keeps running in the background.
boot_enclave() {
  stop_enclave
  rm -f "$VSOCK_SOCKET"
  if [ ! -e /dev/vsock ]; then
    echo "Error: /dev/vsock not found (load vsock + vsock_loopback)" >&2
    return 1
  fi
  vhost-device-vsock \
    --vm "guest-cid=${GUEST_CID},socket=${VSOCK_SOCKET},forward-cid=1,forward-listen=9001+9002" \
    >>"$BOOT_LOG" 2>&1 &
  local vsock_pid=$!
  sleep 1
  kill -0 "$vsock_pid" 2>/dev/null || { echo "Error: vhost-device-vsock failed to start" >&2; return 1; }

  # Host-side vsock heartbeat listener (port 9000): the enclave connects here to notify
  # readiness. Without it the runtime's readiness signal times out and init exits (panic).
  python3 -c '
# enclave-clockdrift-heartbeat
import socket, sys
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((0xFFFFFFFF, 9000))
s.listen(1)
while True:
    try:
        conn, _ = s.accept()
        d = conn.recv(1)
        if d: conn.send(d)
        conn.close()
    except KeyboardInterrupt:
        break
    except Exception as e:
        print(f"heartbeat: {e}", file=sys.stderr, flush=True)
' >>"$BOOT_LOG" 2>&1 &
  local hb_pid=$!
  sleep 0.5

  local accel cpu
  if [ -e /dev/kvm ]; then accel="--enable-kvm"; cpu="-cpu host"; else accel="-accel tcg"; cpu="-cpu max"; fi
  echo "  QEMU_APPEND: ${QEMU_APPEND}"
  qemu-system-x86_64 \
    -M "nitro-enclave,vsock=c,id=clockdrift-enclave" \
    -kernel "$EIF_ABS" \
    -nographic \
    -m "$MEMORY" \
    $accel \
    $cpu \
    -append "$QEMU_APPEND" \
    -chardev "socket,id=c,path=${VSOCK_SOCKET}" \
    >>"$BOOT_LOG" 2>&1 &
  local qemu_pid=$!
  echo "${vsock_pid} ${hb_pid} ${qemu_pid}" >"$ENCLAVE_PIDS"
  echo "  enclave launched (qemu pid ${qemu_pid})"
}

stop_enclave() {
  [ -f "$ENCLAVE_PIDS" ] || return 0
  local v h q
  read -r v h q <"$ENCLAVE_PIDS" || true
  kill "$q" "$h" "$v" 2>/dev/null || true
  pkill -f enclave-clockdrift-heartbeat 2>/dev/null || true
  rm -f "$ENCLAVE_PIDS" "$VSOCK_SOCKET"
  sleep 2
}

qemu_pid() {
  [ -f "$ENCLAVE_PIDS" ] || return 0
  local q
  read -r _ _ q <"$ENCLAVE_PIDS" 2>/dev/null || true
  printf '%s' "${q:-}"
}

# wait_health blocks until /health returns 200 (enclave Init complete), abandoning the wait
# immediately if QEMU exits (a missing /dev/ptp0 makes clock sync fatal → boot fails here).
wait_health() {
  local label="${1:-}" timeout="${2:-240}" seconds=0 code qpid rc
  qpid="$(qemu_pid)"
  while [ "$seconds" -lt "$timeout" ]; do
    if [ -n "$qpid" ] && ! kill -0 "$qpid" 2>/dev/null; then
      rc=0; wait "$qpid" 2>/dev/null || rc=$?
      echo "Error: QEMU (pid ${qpid}) exited during boot — status ${rc} ${label}" >&2
      echo "--- boot log (tail) ---" >&2; tail -40 "$BOOT_LOG" >&2 || true
      return 1
    fi
    code=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' \
      "https://localhost:${HOST_TLS_PORT}/health" 2>/dev/null || echo "000")
    if [ "$code" = "200" ] || [ "$code" = "503" ]; then
      echo "  enclave ready (${seconds}s, HTTP ${code}) ${label}"
      return 0
    fi
    [ $((seconds % 30)) -eq 0 ] && echo "  ...waiting (${seconds}s, HTTP ${code}) ${label}"
    sleep 5
    seconds=$((seconds + 5))
  done
  echo "Error: enclave not ready within ${timeout}s ${label}" >&2
  tail -40 "$BOOT_LOG" >&2 || true
  return 1
}

cleanup() {
  echo "=== Teardown ==="
  stop_enclave
  [ -f /tmp/clockdrift-supervisor.pid ] && kill "$(cat /tmp/clockdrift-supervisor.pid)" 2>/dev/null || true
  killall vhost-device-vsock 2>/dev/null || true
  rm -f /tmp/clockdrift-supervisor.pid
  tofu_destroy
}
trap cleanup EXIT

: >"$BOOT_LOG"

echo "=============================================="
echo " Enclave clock-drift (PTP servo) end-to-end test"
echo "=============================================="

echo "[1/3] tofu apply (localstack) — seeding KMS/SSM/S3..."
tofu_destroy
tofu_apply

echo "[2/3] Booting enclave (skew=${CLOCK_STEP_MS}ms, poll=2s via enclavecfg.*)..."
start_supervisor
boot_enclave
wait_health "(clock-drift boot)"

echo "[3/3] Verifying clock discipline + drift recovery from the boot log..."

# 1. The boot hard-step aligned CLOCK_REALTIME to the PHC — proves the device + PTP ioctls
#    + the dynamic clock-id all work against a real /dev/ptp0.
if grep -qiE "clock sync: initial hard-step to hypervisor PTP completed" "$BOOT_LOG"; then
  pass "clock sync hard-stepped CLOCK_REALTIME onto the PHC at boot"
else
  fail "no PHC hard-step in boot log — clock sync did not engage (is /dev/ptp0 present?)"
fi

# 2. The PI servo ran at least one poll cycle against the real PHC (2s cadence).
CLOCK_DISC=$(grep -c "clock sync: disciplined" "$BOOT_LOG" 2>/dev/null || true)
if [ "${CLOCK_DISC:-0}" -ge 1 ]; then
  pass "PI servo disciplined the clock ${CLOCK_DISC}x against the real PHC"
else
  fail "servo logged no 'disciplined' cycle (expected ~2s cadence)"
fi

# 3. The injected skew is a gross offset, so the servo must hard-step it back onto the PHC —
#    proving it CORRECTS a real error, not just holds an already-synced clock.
CLOCK_RECOV_MS=$(grep '"clock sync: hard-step"' "$BOOT_LOG" 2>/dev/null \
  | grep -oE '"offset_ms":-?[0-9.]+' | sed 's/.*://' \
  | awk 'function abs(x){return x<0?-x:x}{v=abs($1); if(v>m)m=v} END{printf "%.0f", m+0}' || true)
if [ "${CLOCK_RECOV_MS:-0}" -ge $((CLOCK_STEP_MS * 4 / 5)) ]; then
  pass "servo hard-stepped the injected ~${CLOCK_STEP_MS}ms skew back onto the PHC (|offset|=${CLOCK_RECOV_MS}ms)"
else
  fail "injected ${CLOCK_STEP_MS}ms skew not corrected (max hard-step |offset|=${CLOCK_RECOV_MS}ms)"
fi

# 4. After recovery, the residual offset stays sub-millisecond — the clock tracks the PHC.
CLOCK_MAX_OFF_US=$(grep "clock sync: disciplined" "$BOOT_LOG" 2>/dev/null \
  | grep -oE '"offset_us":-?[0-9.]+' | sed 's/.*://' \
  | awk 'function abs(x){return x<0?-x:x}{v=abs($1); if(v>m)m=v} END{printf "%.1f", m+0}' || true)
if awk "BEGIN{exit !(${CLOCK_MAX_OFF_US:-0} < 1000)}"; then
  pass "post-recovery offset stayed bounded to the PHC (max ${CLOCK_MAX_OFF_US} us < 1000)"
else
  fail "post-recovery offset exceeded 1ms (max ${CLOCK_MAX_OFF_US} us)"
fi

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[ "$FAIL" -eq 0 ]
