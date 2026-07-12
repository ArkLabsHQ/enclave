#!/usr/bin/env bash
# Orchestrate a 1-leader + 2-follower threshold-scaling ceremony on ONE host.
#
# ============================================================================
# ⚠ SCAFFOLD — encodes the design; not yet validated end-to-end. Needs a KVM host
#   with QEMU 9.2.x + vhost-device-vsock (the test-runner container). Config-side
#   prerequisite: the EIF must declare a `kind: signing` secret (the dedicated
#   scaling_key in test/app/enclave/enclave.yaml). Its single env var holds this
#   node's share; the master lives only in the storage envelope.
# ============================================================================
#
# All three enclaves boot the SAME EIF (identical PCRs ⇒ admission's PCR check still
# passes) and get their own vsock ports / SSM namespace / scaling role from the
# kernel command line via the dev cmdline channel (runtime/devcmdline.go). They share
# one host (network_mode: host), so a follower reaches the leader over localhost:
#   follower enclave → gvproxy NAT (192.168.127.254 → 127.0.0.1) → leader's forwarded
#   :8443 (handshake) / :9000 (relay).
#
# Per-node boot is inlined below (--boot-node) rather than reusing run.sh's boot_qemu,
# which is single-node by construction (killall vhost-device-vsock, one heartbeat on
# host vsock:9000, one /tmp/enclave-boot.pid).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
SCRIPT_PATH="$(realpath "$0")"

# --------------------------------------------------------------------------
# --boot-node: multi-node-safe single-node boot (own CID/socket, no killall, no
# per-node heartbeat — it uses the orchestrator's one shared responder). A node's
# supervisor invokes this via ENCLAVE_START_CMD. Reads GUEST_CID/MEMORY/QEMU_APPEND.
# --------------------------------------------------------------------------
if [ "${1:-}" = "--boot-node" ]; then
  eif="${2:?--boot-node needs an EIF path}"
  cid="${GUEST_CID:?GUEST_CID required}"
  mem="${MEMORY:-2G}"
  sock="/tmp/vhost${cid}.socket"
  # Auto-restart re-runs START only (no Stop), so a stale vhost for this CID may still
  # hold guest-cid and a fresh one fails ("Failed to bind a vsock stream"). One pkill on
  # the socket path hits both vhost and qemu; clear the socket and pause before the new
  # bind. Keep on the START path — the supervisor never runs ENCLAVE_STOP_CMD on restart.
  pkill -f "/tmp/vhost${cid}.socket" 2>/dev/null || true
  rm -f "$sock"
  sleep 0.3
  # Per-node forward-listen ports so the three vhost instances don't collide on the
  # host. TODO(hw): confirm nothing in the guest depends on the exact 9001/9002.
  fl_base=$((9000 + cid * 10))

  vhost-device-vsock --vm \
    "guest-cid=${cid},socket=${sock},forward-cid=${FWD_CID:-1},forward-listen=$((fl_base + 1))+$((fl_base + 2))" &
  vpid=$!
  sleep 0.3

  accel="-accel tcg"; cpu="-cpu max"
  [ -e /dev/kvm ] && { accel="--enable-kvm"; cpu="-cpu host"; }
  qapp=()
  [ -n "${QEMU_APPEND:-}" ] && qapp=(-append "$QEMU_APPEND")

  qemu-system-x86_64 \
    -M "nitro-enclave,vsock=c,id=enc-${cid}" \
    -kernel "$eif" \
    -nographic \
    -m "$mem" \
    $accel \
    $cpu \
    ${qapp[@]+"${qapp[@]}"} \
    -chardev "socket,id=c,path=${sock}" &
  qpid=$!
  trap 'kill "$qpid" "$vpid" 2>/dev/null || true; rm -f "$sock"' EXIT INT TERM
  wait "$qpid"
  exit 0
fi

# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------
EIF_PATH="${1:-app/.enclave/artifacts/image.eif}"
[ -f "$EIF_PATH" ] || { echo "EIF not found: $EIF_PATH (run 'make test-build' first)" >&2; exit 1; }
EIF_ABS="$(realpath "$EIF_PATH")"
SUPERVISOR="${ENCLAVE_SUPERVISOR:-/tmp/supervisor}"
[ -x "$SUPERVISOR" ] || { echo "supervisor binary not found: $SUPERVISOR" >&2; exit 1; }
APP_NAME="${ENCLAVE_APP_NAME:-my-app}"
LEADER_ADDR="https://192.168.127.254:8443"
MEMORY="${MEMORY:-2G}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"

# Per-node config: name  cid  tlsport  support  gvproxy_port  imds_port  deployment  role
NODES=(
  "leader     4 8443 8444 1024 8002 dev-leader     leader"
  "follower-1 5 8543 8544 1124 8102 dev-follower-1 follower"
  "follower-2 6 8643 8644 1224 8202 dev-follower-2 follower"
)

PIDS=()
cleanup() {
  echo "=== teardown ==="
  killall qemu-system-x86_64 vhost-device-vsock supervisor 2>/dev/null || true
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -f /tmp/vhost*.socket /tmp/sup-*.pid
}
trap cleanup EXIT

wait_health() {  # wait_health <url> <name>
  local url="$1" name="$2" s=0
  while [ "$s" -lt "$BOOT_TIMEOUT" ]; do
    [ "$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "${url}/health" 2>/dev/null || echo 000)" = "200" ] \
      && { echo "  $name healthy (${s}s)"; return 0; }
    sleep 3; s=$((s + 3))
  done
  echo "Error: $name not healthy in ${BOOT_TIMEOUT}s (see /tmp/boot-${name}.log)" >&2; return 1
}
share_pubkey() { curl -sk --max-time 10 "${1}/test/scaling" 2>/dev/null | jq -r '.scaling_key.pubkey // ""' 2>/dev/null || echo ""; }

# One shared heartbeat responder (host vsock:9000) for all guests — its accept loop
# serves every node, so we start it once rather than per boot.
start_heartbeat() {
  python3 -c '
import socket
s=socket.socket(socket.AF_VSOCK,socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((0xFFFFFFFF,9000)); s.listen(8)
while True:
    try:
        c,_=s.accept(); d=c.recv(1)
        if d: c.send(d)
        c.close()
    except Exception: pass
' & PIDS+=("$!")
  sleep 0.3
}

# launch_node starts one node's supervisor; the supervisor boots the guest via
# ENCLAVE_START_CMD → this script's --boot-node.
launch_node() {
  local name="$1" cid="$2" tls="$3" sup="$4" gvport="$5" imds="$6" dep="$7" role="$8"
  local pidfile="/tmp/sup-${name}.pid"
  echo "=== launch $name (cid=$cid tls=$tls gvproxy=$gvport imds=$imds dep=$dep role=$role) ==="

  local append="enclavecfg.deployment=${dep} enclavecfg.role=${role} enclavecfg.gvproxy_port=${gvport} enclavecfg.imds_out=3:${imds}"
  [ "$role" = follower ] && append="${append} enclavecfg.leader_addr=${LEADER_ADDR}"

  local fwd="${tls}:443"
  [ "$role" = leader ] && fwd="${tls}:443 9000:9000"   # leader also forwards its relay

  ENCLAVE_AWS_REGION=us-east-1 \
  ENCLAVE_DEPLOYMENT="$dep" ENCLAVE_APP_NAME="$APP_NAME" \
  ENCLAVE_SUPERVISOR_ADDR="127.0.0.1:${sup}" \
  GVPROXY_LISTEN="vsock://:${gvport}" \
  GVPROXY_FORWARD_PORTS="$fwd" \
  IMDS_PROXY_VSOCK_PORT="$imds" \
  IMDS_PROXY_TARGET="127.0.0.1:1338" \
  ENCLAVE_URL="https://127.0.0.1:${tls}" \
  ENCLAVE_EIF_PATH="$EIF_ABS" \
  ENCLAVE_SUPERVISOR_BINARY_PATH="$SUPERVISOR" \
  ENCLAVE_SUPERVISOR_RESTART_CMD="kill \$(cat ${pidfile})" \
  ENCLAVE_STOP_CMD="true" \
  ENCLAVE_START_CMD="GUEST_CID=${cid} MEMORY=${MEMORY} QEMU_APPEND='${append}' nohup '${SCRIPT_PATH}' --boot-node '${EIF_ABS}' >> /tmp/boot-${name}.log 2>&1 &" \
  AWS_ENDPOINT_URL_SSM="http://127.0.0.1:4566" AWS_ENDPOINT_URL_STS="http://127.0.0.1:4566" \
  AWS_ENDPOINT_URL_S3="http://127.0.0.1:4566" AWS_ENDPOINT_URL_LOGS="http://127.0.0.1:4566" \
  AWS_ENDPOINT_URL_KMS="http://127.0.0.1:4000" \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
    bash -c '"$0" & echo $! > "$1"; wait' "$SUPERVISOR" "$pidfile" & PIDS+=("$!")
}

echo "=== [1/6] Mock services (expects docker compose up: localstack, aws-mocks) ==="
curl -sf http://127.0.0.1:4566/_localstack/health >/dev/null \
  || { echo "localstack not up — run 'docker compose up -d --wait' first" >&2; exit 1; }

echo "=== [2/6] Seed per-deployment KMS placeholders ==="
for n in "${NODES[@]}"; do set -- $n; ./seed-scaling.sh "$7"; done

echo "=== [3/6] Shared heartbeat ==="
start_heartbeat

echo "=== [4/6] Boot leader → follower-1 (snapshot) → follower-2 ==="
set -- ${NODES[0]}; launch_node "$@"; wait_health "https://localhost:8443" leader
set -- ${NODES[1]}; launch_node "$@"; wait_health "https://localhost:8543" follower-1
F1_V1=""; for _ in $(seq 1 60); do F1_V1="$(share_pubkey https://localhost:8543)"; [ -n "$F1_V1" ] && break; sleep 2; done
echo "  follower-1 share v1: ${F1_V1:0:16}..."
set -- ${NODES[2]}; launch_node "$@"; wait_health "https://localhost:8643" follower-2

echo "=== [5/6] Wait for reshare to re-randomize follower-1's share ==="
for _ in $(seq 1 60); do r="$(share_pubkey https://localhost:8543)"; [ -n "$r" ] && [ "$r" != "$F1_V1" ] && break; sleep 2; done

echo "=== [6/6] Assertions ==="
LEADER_URL="https://localhost:8443" FOLLOWER1_URL="https://localhost:8543" \
  FOLLOWER2_URL="https://localhost:8643" F1_SHARE_V1="$F1_V1" ./scaling-test.sh
