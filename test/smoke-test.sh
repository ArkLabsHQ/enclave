#!/usr/bin/env bash
# Smoke tests for a running QEMU enclave.
# Run after boot-qemu.sh reports the enclave is ready.
set -euo pipefail

HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"
BASE_URL="${ENCLAVE_URL:-https://localhost:${HOST_TLS_PORT}}"
CURL="curl -sf --max-time 10 -k"
PASSED=0
FAILED=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1 — $2"; FAILED=$((FAILED + 1)); }

echo "=== Smoke tests against $BASE_URL ==="
echo ""

# Test 1: Health endpoint
echo "[1/5] Health check"
if $CURL "${BASE_URL}/enclave/health" -o /dev/null; then
  pass "Health endpoint returns 200"
else
  fail "Health endpoint" "did not return 200"
fi

# Test 2: Enclave info returns JSON with attestation pubkey
echo "[2/5] Enclave info"
INFO=$($CURL "${BASE_URL}/v1/enclave-info" 2>/dev/null || echo "")
if [ -n "$INFO" ] && echo "$INFO" | jq -e '.attestation_pubkey' >/dev/null 2>&1; then
  PUBKEY=$(echo "$INFO" | jq -r '.attestation_pubkey')
  pass "Enclave info returns attestation_pubkey: ${PUBKEY:0:16}..."
else
  fail "Enclave info" "missing or invalid JSON (got: ${INFO:0:80})"
fi

# Test 3: Response signing headers present
echo "[3/5] Attestation signature headers"
HEADERS=$(curl -skI --max-time 10 "${BASE_URL}/v1/enclave-info" 2>/dev/null || echo "")
if echo "$HEADERS" | grep -qi "X-Attestation-Signature"; then
  pass "X-Attestation-Signature header present"
else
  fail "Attestation headers" "X-Attestation-Signature missing"
fi
if echo "$HEADERS" | grep -qi "X-Attestation-Pubkey"; then
  pass "X-Attestation-Pubkey header present"
else
  fail "Attestation headers" "X-Attestation-Pubkey missing"
fi

# Test 4: Init completed without error
echo "[4/5] Init status"
if [ -n "$INFO" ]; then
  INIT_ERR=$(echo "$INFO" | jq -r '.init_error // empty' 2>/dev/null || echo "")
  if [ -z "$INIT_ERR" ]; then
    pass "Init completed successfully (no init_error)"
  else
    fail "Init status" "init_error: $INIT_ERR"
  fi
else
  fail "Init status" "could not fetch enclave-info"
fi

# Test 5: SDK version present
echo "[5/5] SDK version"
if [ -n "$INFO" ]; then
  VERSION=$(echo "$INFO" | jq -r '.version // empty' 2>/dev/null || echo "")
  if [ -n "$VERSION" ]; then
    pass "SDK version: $VERSION"
  else
    fail "SDK version" "version field missing from enclave-info"
  fi
else
  fail "SDK version" "could not fetch enclave-info"
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
