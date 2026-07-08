#!/usr/bin/env bash
# End-to-end ACME test: boots the test enclave with ACME enabled against a
# local Pebble ACME server, and verifies the enclave obtains a Pebble-issued
# TLS cert via TLS-ALPN-01 and reuses it (from the encrypted S3 cert cache)
# across a reboot.
#
# Runs inside the acme-runner container (see test/docker-compose.yml); Pebble
# runs as a sibling compose service. `make test-acme` is the entry point — it
# also runs test/pebble/gen-certs.sh on the host first (Pebble needs its API
# certificate at startup).
#
# The supervisor is run purely for gvproxy + the IMDS forwarder (no
# ENCLAVE_START_CMD) — this script boots QEMU directly, so there is no
# watchdog restart loop. Networking: enclave -> Pebble via
# host.containers.internal:14000 (gvproxy NAT); Pebble -> enclave via
# enclave.test:8443 (host-gateway -> gvproxy's 8443:443 forward).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$SCRIPT_DIR"

EIF_PATH="${1:?Usage: acme-test.sh <path-to-eif>}"
EIF_ABS="$(realpath "$EIF_PATH")"

GUEST_CID="${GUEST_CID:-4}"
# 2G (run.sh uses 4G): the test app is tiny, and a smaller guest leaves
# headroom on memory-constrained CI runners so QEMU is not OOM-killed.
MEMORY="${MEMORY:-2G}"
HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"
FQDN="enclave.test"
PEBBLE_DIRECTORY="https://host.containers.internal:14000/dir"
TOFU_DIR="${SCRIPT_DIR}/app/tofu"
PEBBLE_DIR="${SCRIPT_DIR}/pebble"
VSOCK_SOCKET="/tmp/vhost${GUEST_CID}.socket"
ENCLAVE_PIDS="/tmp/acme-enclave-pids"
SUP_LOG="${SCRIPT_DIR}/acme-supervisor.log"
BOOT_LOG="${SCRIPT_DIR}/acme-boot.log"

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
    tofu -chdir="$TOFU_DIR" destroy -auto-approve -input=false >"${SCRIPT_DIR}/acme-tofu-destroy.log" 2>&1 || true
  fi
  rm -f "${TOFU_DIR}/terraform.tfstate"* "${TOFU_DIR}/provider_override.tf" "${TOFU_DIR}/backend.tf" 2>/dev/null || true
  rm -rf "${TOFU_DIR}/.terraform" "${TOFU_DIR}/.artifacts" 2>/dev/null || true
}

# tofu_apply scaffolds the module and applies it against localstack. The
# caller must write env_values.auto.tfvars.json first (write_env_values).
tofu_apply() {
  rm -f "${TOFU_DIR}/main.tf" "${TOFU_DIR}/modules/enclave/main.tf"
  mkdir -p "${SCRIPT_DIR}/app/.enclave/artifacts"
  for f in image.eif supervisor; do
    [ -f "${SCRIPT_DIR}/app/.enclave/artifacts/$f" ] || touch "${SCRIPT_DIR}/app/.enclave/artifacts/$f"
  done
  (cd "${SCRIPT_DIR}/app" && LOCAL_DEPLOYMENT=true "$ENCLAVE_CLI" tofu init >"${SCRIPT_DIR}/acme-tofu-scaffold.log" 2>&1) \
    || { cat "${SCRIPT_DIR}/acme-tofu-scaffold.log"; return 1; }

  # 'enclave tofu env' requires the scaffold to exist (above) — write env
  # vars now, before tofu init/apply runs.
  write_env_values

  cat > "${TOFU_DIR}/backend.tf" <<BACKEND
terraform {
  backend "local" {
    path = "${TOFU_DIR}/terraform.tfstate"
  }
}
BACKEND

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
    dynamodb = "http://127.0.0.1:4566"
  }
}
OVERRIDE

  tofu -chdir="$TOFU_DIR" init -input=false >"${SCRIPT_DIR}/acme-tofu-init.log" 2>&1 \
    || { cat "${SCRIPT_DIR}/acme-tofu-init.log"; return 1; }
  tofu -chdir="$TOFU_DIR" apply -auto-approve -input=false -compact-warnings >"${SCRIPT_DIR}/acme-tofu-apply.log" 2>&1 \
    || { echo "tofu apply FAILED:"; tail -25 "${SCRIPT_DIR}/acme-tofu-apply.log"; return 1; }
}

# write_env_values populates tofu/env_values.auto.tfvars.json via the
# `enclave tofu env` CLI — exercises the same UX an operator uses (rather
# than dumping framework-private JSON). tofu's aws_ssm_parameter.env_override
# turns each key into /dev/my-app/env/<key>, which the runtime reads at boot
# via loadDeployTLSConfig.
# Caller must have scaffolded the module first (enclave tofu init).
write_env_values() {
  (cd "${SCRIPT_DIR}/app" && LOCAL_DEPLOYMENT=true "$ENCLAVE_CLI" tofu env \
    --key ENCLAVE_NITRIDING_FQDN           --value "$FQDN" \
    --key ENCLAVE_NITRIDING_USE_ACME       --value "true" \
    --key ENCLAVE_NITRIDING_ACME_DIRECTORY --value "$PEBBLE_DIRECTORY" \
    --key ENCLAVE_NITRIDING_ACME_EMAIL     --value "acme-test@enclave.test" \
    --key ENCLAVE_NITRIDING_ACME_CA        --value "$(cat "${PEBBLE_DIR}/pebble-ca.crt")" \
    > "${SCRIPT_DIR}/acme-tofu-env.log" 2>&1) \
    || { cat "${SCRIPT_DIR}/acme-tofu-env.log"; return 1; }
}

# start_supervisor runs the supervisor purely for in-process gvproxy (the
# 8443->enclave:443 forward + host.containers.internal NAT) and the IMDS
# forwarder. No ENCLAVE_START_CMD — this script boots QEMU itself, so the
# supervisor's enclave watchdog stays out of the way.
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
  echo "$sup_pid" > /tmp/acme-supervisor.pid
  sleep 3
  if ! kill -0 "$sup_pid" 2>/dev/null; then
    echo "Error: supervisor exited immediately — log:" >&2
    cat "$SUP_LOG" >&2 2>/dev/null || true
    return 1
  fi
  echo "  supervisor up (pid $sup_pid) — gvproxy + IMDS"
}

# boot_enclave brings up the AF_VSOCK fabric and launches the EIF in QEMU,
# then returns — QEMU keeps running in the background. stop_enclave tears it
# down. No internal wait loop and no watchdog: wait_health does readiness.
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

  python3 -c '
# enclave-acme-heartbeat
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
    -M "nitro-enclave,vsock=c,id=acme-enclave" \
    -kernel "$EIF_ABS" \
    -nographic \
    -m "$MEMORY" \
    $accel \
    $cpu \
    -chardev "socket,id=c,path=${VSOCK_SOCKET}" \
    >>"$BOOT_LOG" 2>&1 &
  local qemu_pid=$!
  echo "${vsock_pid} ${hb_pid} ${qemu_pid}" > "$ENCLAVE_PIDS"
  echo "  enclave launched (qemu pid ${qemu_pid})"
}

stop_enclave() {
  [ -f "$ENCLAVE_PIDS" ] || return 0
  local v h q
  read -r v h q < "$ENCLAVE_PIDS" || true
  kill "$q" "$h" "$v" 2>/dev/null || true
  pkill -f enclave-acme-heartbeat 2>/dev/null || true
  rm -f "$ENCLAVE_PIDS" "$VSOCK_SOCKET"
  sleep 2
}

# qemu_pid prints the QEMU pid (3rd field) from the file boot_enclave wrote,
# or nothing if the enclave has not been launched.
qemu_pid() {
  [ -f "$ENCLAVE_PIDS" ] || return 0
  local q
  read -r _ _ q < "$ENCLAVE_PIDS" 2>/dev/null || true
  printf '%s' "${q:-}"
}

# dump_boot_diagnostics prints what a failed boot needs: whether QEMU is still
# alive (hung at init) or gone (crashed / OOM-killed), host memory, the dmesg
# tail (an OOM kill lands there), and the full supervisor + boot logs.
dump_boot_diagnostics() {
  local qpid lg
  qpid="$(qemu_pid)"
  if [ -n "$qpid" ]; then
    if kill -0 "$qpid" 2>/dev/null; then
      echo "  QEMU (pid ${qpid}): still running — hung at init" >&2
    else
      echo "  QEMU (pid ${qpid}): not running — exited or was killed" >&2
    fi
  fi
  echo "--- free -m ---" >&2
  free -m >&2 || true
  echo "--- dmesg (tail; an OOM kill of qemu lands here) ---" >&2
  dmesg 2>/dev/null | tail -30 >&2 || echo "(dmesg unavailable)" >&2
  for lg in "$SUP_LOG" "$BOOT_LOG"; do
    echo "--- ${lg} ---" >&2
    if [ -s "$lg" ]; then cat "$lg" >&2; else echo "(empty or missing)" >&2; fi
  done
}

# wait_health blocks until /health returns 200 (enclave Init complete). It
# also watches QEMU: if the process exits, the wait is abandoned immediately
# with its status, instead of curling a dead enclave until the timeout.
wait_health() {
  local label="${1:-}" timeout="${2:-420}" seconds=0 code qpid rc
  qpid="$(qemu_pid)"
  while [ "$seconds" -lt "$timeout" ]; do
    if [ -n "$qpid" ] && ! kill -0 "$qpid" 2>/dev/null; then
      rc=0; wait "$qpid" 2>/dev/null || rc=$?
      echo "Error: QEMU (pid ${qpid}) exited during boot — status ${rc} (137 = OOM/SIGKILL) ${label}" >&2
      dump_boot_diagnostics
      return 1
    fi
    # SNI must be FQDN — in ACME mode autocert rejects any other server name.
    code=$(curl -sk --max-time 8 -o /dev/null -w '%{http_code}' \
      --resolve "${FQDN}:${HOST_TLS_PORT}:127.0.0.1" \
      "https://${FQDN}:${HOST_TLS_PORT}/health" 2>/dev/null || echo "000")
    if [ "$code" = "200" ]; then
      echo "  enclave ready (${seconds}s) ${label}"
      return 0
    fi
    [ $((seconds % 30)) -eq 0 ] && echo "  ...waiting (${seconds}s, HTTP ${code}) ${label}"
    sleep 5
    seconds=$((seconds + 5))
  done
  echo "Error: enclave not ready within ${timeout}s ${label}" >&2
  dump_boot_diagnostics
  return 1
}

# served_cert prints `openssl x509` fields for the cert the enclave serves for
# FQDN. SNI must be FQDN — that is what autocert's HostWhitelist gates on.
served_cert() {
  echo | openssl s_client -connect "127.0.0.1:${HOST_TLS_PORT}" -servername "$FQDN" 2>/dev/null \
    | openssl x509 -noout "$@" 2>/dev/null
}

# trigger_issuance makes SNI=FQDN handshakes so autocert starts the ACME order.
# autocert issues lazily and the first handshakes race the order, so retry.
trigger_issuance() {
  local i
  for i in $(seq 1 40); do
    if served_cert -issuer | grep -qi 'Pebble'; then
      return 0
    fi
    curl -sk --max-time 20 --resolve "${FQDN}:${HOST_TLS_PORT}:127.0.0.1" \
      "https://${FQDN}:${HOST_TLS_PORT}/health" >/dev/null 2>&1 || true
    sleep 3
  done
  return 1
}

R53_FIXTURE_DIR="/tmp/acme-route53-smoke"
R53_ZONE_ID=""

# route53_smoke exercises the framework's aws_route53_record.enclave block
# against LocalStack's Route53 emulation. Extracts the resource verbatim from
# the scaffolded module so drift between the framework's emitted HCL and the
# test would surface here. Independent tofu state — does not touch the main
# acme tofu_apply state.
route53_smoke() {
  local fqdn="acme-r53.example.com" zone_ref ip_found
  local endpoint="http://127.0.0.1:4566"

  rm -rf "$R53_FIXTURE_DIR" && mkdir -p "$R53_FIXTURE_DIR"

  zone_ref=$(aws --endpoint-url "$endpoint" route53 create-hosted-zone \
    --name example.com --caller-reference "r53-$$" \
    --query 'HostedZone.Id' --output text 2>>"${SCRIPT_DIR}/acme-route53.log")
  R53_ZONE_ID="${zone_ref##*/}"
  [ -n "$R53_ZONE_ID" ] || { fail "could not create LocalStack hosted zone"; return 1; }

  cat > "$R53_FIXTURE_DIR/main.tf" <<HCL
terraform {
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
}
provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  endpoints {
    ec2     = "${endpoint}"
    route53 = "${endpoint}"
  }
}
variable "local" {
  type    = bool
  default = false
}
variable "tls" {
  type = object({
    fqdn            = string
    provider        = string
    email           = string
    route53_zone_id = string
  })
}
resource "aws_eip" "instance" {
  count  = var.local ? 0 : 1
  domain = "vpc"
}
HCL

  # Append the framework's actual route53 record block — drift detector.
  awk '/^resource "aws_route53_record" "enclave"/,/^}/' \
    "${TOFU_DIR}/modules/enclave/main.tf" >> "$R53_FIXTURE_DIR/main.tf"

  if ! grep -q 'aws_route53_record" "enclave"' "$R53_FIXTURE_DIR/main.tf"; then
    fail "framework's aws_route53_record block not found in scaffolded module"
    return 1
  fi

  # Auto-loaded tfvars — avoids HCL-vs-JSON escaping headaches on -var flags.
  jq -n \
    --arg fqdn "$fqdn" \
    --arg zone "$R53_ZONE_ID" \
    '{local: false, tls: {fqdn: $fqdn, provider: "letsencrypt", email: "", route53_zone_id: $zone}}' \
    > "$R53_FIXTURE_DIR/test.auto.tfvars.json"

  tofu -chdir="$R53_FIXTURE_DIR" init -input=false >"${SCRIPT_DIR}/acme-route53-init.log" 2>&1 \
    || { fail "route53 fixture tofu init"; cat "${SCRIPT_DIR}/acme-route53-init.log" >&2; return 1; }

  tofu -chdir="$R53_FIXTURE_DIR" apply -auto-approve -input=false \
    >"${SCRIPT_DIR}/acme-route53-apply.log" 2>&1 \
    || { fail "route53 fixture tofu apply"; tail -25 "${SCRIPT_DIR}/acme-route53-apply.log" >&2; return 1; }

  ip_found=$(aws --endpoint-url "$endpoint" route53 list-resource-record-sets \
    --hosted-zone-id "$R53_ZONE_ID" \
    --query "ResourceRecordSets[?Type=='A' && Name=='${fqdn}.'].ResourceRecords[].Value" \
    --output text 2>>"${SCRIPT_DIR}/acme-route53.log")

  if [ -n "$ip_found" ]; then
    pass "Route53 A record created for ${fqdn} → ${ip_found} (zone=${R53_ZONE_ID})"
  else
    fail "Route53 A record missing for ${fqdn} (zone=${R53_ZONE_ID})"
  fi

  tofu -chdir="$R53_FIXTURE_DIR" destroy -auto-approve -input=false \
    >>"${SCRIPT_DIR}/acme-route53-apply.log" 2>&1 || true
}

route53_cleanup() {
  [ -d "$R53_FIXTURE_DIR" ] || return 0
  if [ -n "$R53_ZONE_ID" ]; then
    aws --endpoint-url "http://127.0.0.1:4566" route53 delete-hosted-zone \
      --id "$R53_ZONE_ID" >/dev/null 2>&1 || true
  fi
  rm -rf "$R53_FIXTURE_DIR"
}

cleanup() {
  echo "=== Teardown ==="
  stop_enclave
  [ -f /tmp/acme-supervisor.pid ] && kill "$(cat /tmp/acme-supervisor.pid)" 2>/dev/null || true
  killall vhost-device-vsock 2>/dev/null || true
  rm -f /tmp/acme-supervisor.pid
  tofu_destroy
  route53_cleanup
}
trap cleanup EXIT

: > "$BOOT_LOG"

echo "=============================================="
echo " Enclave ACME (Pebble) end-to-end test"
echo "=============================================="

echo "[1/6] Checking Pebble fixtures..."
[ -f "${PEBBLE_DIR}/pebble-ca.crt" ] || { echo "Error: ${PEBBLE_DIR}/pebble-ca.crt missing — run test/pebble/gen-certs.sh" >&2; exit 1; }
echo "  Pebble directory: ${PEBBLE_DIRECTORY}"

echo "[2/6] tofu apply (localstack) — scaffolds module, writes env via 'enclave tofu env', applies..."
tofu_destroy
tofu_apply

echo "[3/6] Starting supervisor + booting enclave (ACME mode)..."
start_supervisor
boot_enclave
wait_health "(initial boot)"

echo "[4/6] Triggering ACME issuance via Pebble..."
if trigger_issuance; then
  pass "enclave obtained a cert via ACME"
else
  fail "ACME issuance did not complete"
fi

ISSUER="$(served_cert -issuer || true)"
SUBJECT_ALT="$(served_cert -ext subjectAltName || true)"
echo "  issuer: ${ISSUER}"
echo "  SAN:    ${SUBJECT_ALT}"
if echo "$ISSUER" | grep -qi 'Pebble'; then
  pass "served cert is Pebble-issued"
else
  fail "served cert issuer is not Pebble"
fi
if echo "$ISSUER" | grep -qi 'AWS Nitro enclave application'; then
  fail "enclave served the self-signed fallback cert (ACME did not take effect)"
else
  pass "served cert is not the self-signed fallback"
fi
if echo "$SUBJECT_ALT" | grep -qi "DNS:${FQDN}"; then
  pass "served cert SAN includes ${FQDN}"
else
  fail "served cert SAN missing ${FQDN}"
fi

echo "[5/6] Reboot — verifying the cert is reused from the S3 cache..."
SERIAL_BEFORE="$(served_cert -serial || true)"
echo "  serial before reboot: ${SERIAL_BEFORE}"
boot_enclave   # stop_enclave + relaunch; tofu state (S3 bucket) is untouched
wait_health "(after reboot)"
trigger_issuance || true
SERIAL_AFTER="$(served_cert -serial || true)"
echo "  serial after reboot:  ${SERIAL_AFTER}"
if [ -n "$SERIAL_BEFORE" ] && [ "$SERIAL_BEFORE" = "$SERIAL_AFTER" ]; then
  pass "cert serial unchanged across reboot — reused from acmeStorageCache"
else
  fail "cert serial changed across reboot — re-issued instead of reusing the S3 cache"
fi

echo "[6/6] Route53 record smoke against LocalStack..."
route53_smoke

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[ "$FAIL" -eq 0 ]
