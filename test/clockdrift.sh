#!/usr/bin/env bash
# End-to-end clock-drift test: boots the test enclave, then injects a synthetic clock skew at
# runtime via the test app's POST /test/clock-skew endpoint, and verifies the PI servo detects
# and corrects it against the hypervisor PHC — hard-stepping a gross offset and
# frequency-disciplining a sub-threshold one.
#
# Requires /dev/ptp0 in the guest (ptp_kvm on a KVM runner); the enclave's clock sync is fatal
# at boot, so a missing PHC shows up as a boot timeout. The EIF must be a dev build
# (ENCLAVE_DEV=true baked) — the servo's dev poll cadence (5s) is gated on it.
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

# boot_enclave brings up the AF_VSOCK fabric and launches the EIF in QEMU, then returns;
# QEMU keeps running in the background.
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
  qemu-system-x86_64 \
    -M "nitro-enclave,vsock=c,id=clockdrift-enclave" \
    -kernel "$EIF_ABS" \
    -nographic \
    -m "$MEMORY" \
    $accel \
    $cpu \
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

echo "[2/3] Booting enclave (dev EIF, 5s servo cadence)..."
start_supervisor
boot_enclave
wait_health "(clock-drift boot)"

echo "[3/3] Injecting gross + sub-threshold clock skews; verifying both servo paths..."
BASE_URL="https://localhost:${HOST_TLS_PORT}"

# extract_ns pulls a "<field>":<int> value from a JSON blob on stdin.
extract_ns() { grep -oE "\"$1\":[0-9]+" | grep -oE '[0-9]+'; }

# skew_clock advances the guest CLOCK_REALTIME by $1 ms via the test app, failing the
# test if the endpoint did not apply it (no timestamp in the response).
skew_clock() {
  local resp
  resp=$(curl -sk --max-time 8 -X POST "${BASE_URL}/test/clock-skew?ms=${1}" || true)
  if printf '%s' "$resp" | grep -q '"guest_unix_ns"'; then
    return 0
  fi
  fail "POST /test/clock-skew?ms=${1} did not apply the skew (response: ${resp})"
  return 1
}

# hard_steps counts runtime recovery hard-steps logged so far.
hard_steps() { grep -c 'clock sync: hard-step' "$BOOT_LOG" 2>/dev/null || true; }

# 1. The boot hard-step aligned CLOCK_REALTIME to the PHC — proves the device + the
#    dynamic clock-id all work against a real /dev/ptp0.
if grep -qiE "clock sync: initial hard-step to hypervisor PTP completed" "$BOOT_LOG"; then
  pass "clock sync hard-stepped CLOCK_REALTIME onto the PHC at boot"
else
  fail "no PHC hard-step in boot log — clock sync did not engage (is /dev/ptp0 present?)"
fi

# 2. HARD-STEP path: a gross 500ms offset (> maxStepNs 100ms) must be hard-stepped back
#    onto the PHC. Confirm the guest reconverges to host and exactly one hard-step fires.
if skew_clock 500; then
  sleep 12
  HOST_AFTER=$(date +%s%N)
  GUEST_NOW=$(curl -sk --max-time 8 "${BASE_URL}/test/clock" | extract_ns guest_unix_ns || true)
  DRIFT_MS=$(( (${GUEST_NOW:-0} - HOST_AFTER) / 1000000 )); DRIFT_MS=${DRIFT_MS#-}
  if [ -n "${GUEST_NOW:-}" ] && [ "$DRIFT_MS" -le 250 ]; then
    pass "gross skew hard-stepped back: guest within ${DRIFT_MS}ms of host"
  else
    fail "gross skew not recovered (guest_ns=${GUEST_NOW:-none}, |drift|=${DRIFT_MS}ms)"
  fi
  if [ "$(hard_steps)" -eq 1 ]; then
    pass "gross offset triggered exactly one hard-step"
  else
    fail "expected 1 hard-step after the gross skew, saw $(hard_steps)"
  fi
fi

# 3. FREQUENCY path: a sub-threshold 50ms offset (< maxStepNs) must NOT hard-step; the PI loop frequency-disciplines it.
LINES_BEFORE=$(wc -l <"$BOOT_LOG")
if skew_clock 50; then
  sleep 12
  if [ "$(hard_steps)" -eq 1 ]; then
    pass "sub-threshold offset did not hard-step (handled by the frequency path)"
  else
    fail "sub-threshold skew must not hard-step; count is now $(hard_steps)"
  fi
  # Largest |offset_us| among disciplined ticks logged AFTER the skew (JSON or logfmt).
  MAX_US=$(tail -n +"$((LINES_BEFORE + 1))" "$BOOT_LOG" | grep 'clock sync: disciplined' \
    | grep -oE 'offset_us"?[:=]-?[0-9.]+' | sed 's/.*[:=]//' \
    | awk 'function abs(x){return x<0?-x:x}{v=abs($1); if(v>m)m=v} END{printf "%.0f", m+0}' || true)
  if [ "${MAX_US:-0}" -ge 30000 ]; then
    pass "servo frequency-disciplined the injected offset (|offset_us|=${MAX_US} in a disciplined tick)"
  else
    fail "no post-skew disciplined tick reflects the ~50ms offset (max |offset_us|=${MAX_US:-0})"
  fi
fi

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[ "$FAIL" -eq 0 ]
