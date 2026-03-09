#!/usr/bin/env bash
# Boot an EIF in QEMU with nitro-enclave emulation.
#
# Prerequisites:
#   - QEMU 9.2+ with -M nitro-enclave support
#   - vhost-device-vsock (from rust-vmm)
#   - gvproxy (from gvisor-tap-vsock)
#   - KVM enabled (modprobe kvm-intel / kvm-amd)
#   - AF_VSOCK kernel support (vsock + vsock_loopback modules)
#   - python3 (for heartbeat responder)
#
# Use `nix develop ./test` to get all dependencies.
set -euo pipefail

EIF_PATH="${1:?Usage: $0 <path-to-eif>}"

if [ ! -f "$EIF_PATH" ]; then
  echo "Error: EIF not found at $EIF_PATH" >&2
  exit 1
fi

# Resolve to absolute path.
EIF_PATH="$(realpath "$EIF_PATH")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

GUEST_CID="${GUEST_CID:-4}"
MEMORY="${MEMORY:-4G}"
VSOCK_SOCKET="/tmp/vhost${GUEST_CID}.socket"
GVPROXY_SOCKET="/tmp/gvproxy-network.sock"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-60}"

# Host-side port for nitriding TLS (use unprivileged port to avoid needing root).
HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"

cleanup() {
  echo ""
  echo "=== Cleaning up ==="
  [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null && echo "  Stopped QEMU ($QEMU_PID)"
  [ -n "${GVPROXY_PID:-}" ] && kill "$GVPROXY_PID" 2>/dev/null && echo "  Stopped gvproxy ($GVPROXY_PID)"
  [ -n "${IMDS_PROXY_PID:-}" ] && kill "$IMDS_PROXY_PID" 2>/dev/null && echo "  Stopped IMDS proxy ($IMDS_PROXY_PID)"
  [ -n "${HB_PID:-}" ] && kill "$HB_PID" 2>/dev/null && echo "  Stopped heartbeat ($HB_PID)"
  [ -n "${VSOCK_PID:-}" ] && kill "$VSOCK_PID" 2>/dev/null && echo "  Stopped vhost-device-vsock ($VSOCK_PID)"
  rm -f "$VSOCK_SOCKET" "$GVPROXY_SOCKET"
}
trap cleanup EXIT

# Kill any stale processes from previous runs (use exact binary match, not -f).
killall vhost-device-vsock 2>/dev/null || true
killall gvproxy 2>/dev/null || true
sleep 0.5

# Clean up stale sockets.
rm -f "$VSOCK_SOCKET" "$GVPROXY_SOCKET"

# Verify AF_VSOCK kernel support.
if [ ! -e /dev/vsock ]; then
  echo "Error: /dev/vsock not found. Load vsock + vsock_loopback kernel modules." >&2
  exit 1
fi

echo "=== Starting vhost-device-vsock ==="
echo "  CID:        $GUEST_CID"
echo "  Socket:     $VSOCK_SOCKET"
echo "  Forward:    CID 1 (loopback)"

# Use forward-cid=1 mode: guest connections (to any CID) are forwarded to
# the host's AF_VSOCK loopback (CID 1). This correctly handles the Nitro
# init binary's connection to CID 3 (parent VM).
# forward-listen: ports for host-to-guest forwarding (per QEMU nitro-enclave docs).
vhost-device-vsock \
  --vm "guest-cid=${GUEST_CID},socket=${VSOCK_SOCKET},forward-cid=1,forward-listen=9001+9002" &
VSOCK_PID=$!
sleep 1

if ! kill -0 "$VSOCK_PID" 2>/dev/null; then
  echo "Error: vhost-device-vsock failed to start" >&2
  exit 1
fi

# Heartbeat responder: the EIF init sends byte 0xB7 to vsock CID 3 port 9000
# and expects 0xB7 back. vhost-device-vsock forwards this to AF_VSOCK CID 1:9000.
echo "=== Starting heartbeat responder ==="
python3 "$SCRIPT_DIR/heartbeat.py" &
HB_PID=$!
sleep 0.5

if ! kill -0 "$HB_PID" 2>/dev/null; then
  echo "Error: heartbeat responder failed to start" >&2
  exit 1
fi

# IMDS proxy: viproxy inside the enclave connects to vsock CID 3 port 8002 for IMDS.
# vhost-device-vsock forwards this to AF_VSOCK CID 1:8002. We proxy it to mock-imds.
# NOTE: Disabled by default — when IMDS is reachable, the supervisor's Init() blocks
# on KMS calls through gvproxy's TAP network. Without IMDS, Init() fails fast and the
# test app starts immediately. Enable with ENABLE_IMDS_PROXY=1 once gvproxy TAP
# forwarding to mock KMS/SSM is working.
if [ "${ENABLE_IMDS_PROXY:-0}" = "1" ]; then
  echo "=== Starting IMDS vsock proxy ==="
  MOCK_IMDS_PORT="${MOCK_IMDS_PORT:-1338}"
  python3 "$SCRIPT_DIR/vsock-proxy.py" 8002 127.0.0.1 "$MOCK_IMDS_PORT" &
  IMDS_PROXY_PID=$!
  sleep 0.5

  if ! kill -0 "$IMDS_PROXY_PID" 2>/dev/null; then
    echo "  Warning: IMDS vsock proxy failed to start (viproxy will not work)"
  else
    echo "  vsock:8002 -> 127.0.0.1:${MOCK_IMDS_PORT} (mock IMDS)"
  fi
fi

# gvproxy: the enclave's start.sh connects to vsock CID 3 port 1024 for networking.
# vhost-device-vsock forwards this to AF_VSOCK CID 1:1024 on the host.
# gvproxy listens on AF_VSOCK port 1024 + a Unix management socket.
echo "=== Starting gvproxy ==="
echo "  vsock:  AF_VSOCK port 1024"
echo "  mgmt:   $GVPROXY_SOCKET"

gvproxy \
  -listen "vsock://:1024" \
  -listen "unix://${GVPROXY_SOCKET}" \
  -ssh-port 2299 &
GVPROXY_PID=$!
sleep 2

if ! kill -0 "$GVPROXY_PID" 2>/dev/null; then
  echo "Error: gvproxy failed to start" >&2
  exit 1
fi

# Set up port forwarding through gvproxy for enclave services.
echo "=== Configuring gvproxy port forwarding ==="

# nitriding TLS (443 inside enclave -> HOST_TLS_PORT on host)
curl -sf --unix-socket "$GVPROXY_SOCKET" \
  "http:/unix/services/forwarder/expose" \
  -X POST \
  -d "{\"local\":\":${HOST_TLS_PORT}\",\"remote\":\"192.168.127.2:443\"}" \
  && echo "  :${HOST_TLS_PORT} -> 192.168.127.2:443 (nitriding TLS)" \
  || echo "  Warning: failed to forward TLS port"

# Additional service ports
for port in 7073 9090; do
  curl -sf --unix-socket "$GVPROXY_SOCKET" \
    "http:/unix/services/forwarder/expose" \
    -X POST \
    -d "{\"local\":\":${port}\",\"remote\":\"192.168.127.2:${port}\"}" \
    && echo "  :${port} -> 192.168.127.2:${port}" \
    || echo "  Warning: failed to forward port ${port}"
done

echo ""
echo "=== Booting QEMU enclave ==="
echo "  EIF:    $EIF_PATH"
echo "  Memory: $MEMORY"
echo "  KVM:    enabled"

qemu-system-x86_64 \
  -M "nitro-enclave,vsock=c,id=test-enclave" \
  -kernel "$EIF_PATH" \
  -nographic \
  -m "$MEMORY" \
  --enable-kvm \
  -cpu host \
  -chardev "socket,id=c,path=${VSOCK_SOCKET}" &
QEMU_PID=$!

echo "  PID:    $QEMU_PID"
echo ""

# Wait for the enclave to become ready.
echo "=== Waiting for enclave to boot (timeout: ${BOOT_TIMEOUT}s) ==="
SECONDS=0
while [ $SECONDS -lt "$BOOT_TIMEOUT" ]; do
  if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "Error: QEMU exited unexpectedly" >&2
    wait "$QEMU_PID" || true
    exit 1
  fi

  # nitriding serves HTTPS on enclave:443, forwarded to localhost:HOST_TLS_PORT.
  if curl -skf "https://localhost:${HOST_TLS_PORT}/enclave/health" -o /dev/null 2>/dev/null; then
    echo "  Enclave is ready! (${SECONDS}s)"
    echo ""
    echo "=== Enclave running ==="
    echo "  Health:        https://localhost:${HOST_TLS_PORT}/enclave/health"
    echo "  Enclave info:  https://localhost:${HOST_TLS_PORT}/v1/enclave-info"
    echo "  App:           https://localhost:${HOST_TLS_PORT}/"
    echo ""
    echo "Press Ctrl+C to stop."
    wait "$QEMU_PID"
    exit 0
  fi

  sleep 2
done

echo "Error: Enclave did not become ready within ${BOOT_TIMEOUT}s" >&2
echo "Check QEMU output above for errors." >&2
exit 1
