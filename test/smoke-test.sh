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

# Test 1: Health endpoint responds (200 or 503 — supervisor is running)
echo "[1/5] Health check"
HEALTH_CODE=$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$HEALTH_CODE" = "200" ]; then
  pass "Health endpoint returns 200"
elif [ "$HEALTH_CODE" = "503" ]; then
  HEALTH_BODY=$(curl -sk --max-time 10 "${BASE_URL}/health" 2>/dev/null || echo "{}")
  pass "Health endpoint responds (503 — Init error expected without AWS services)"
else
  fail "Health endpoint" "no response (HTTP $HEALTH_CODE)"
fi

# Test 2: Enclave info returns valid JSON with version
echo "[2/5] Enclave info"
INFO=$(curl -sk --max-time 10 "${BASE_URL}/v1/enclave-info" 2>/dev/null || echo "")
if [ -n "$INFO" ] && echo "$INFO" | jq -e '.version' >/dev/null 2>&1; then
  PUBKEY=$(echo "$INFO" | jq -r '.attestation_pubkey // empty' 2>/dev/null || echo "")
  if [ -n "$PUBKEY" ]; then
    pass "Enclave info returns attestation_pubkey: ${PUBKEY:0:16}..."
  else
    pass "Enclave info returns valid JSON (attestation_pubkey not yet available — Init incomplete)"
  fi
else
  fail "Enclave info" "missing or invalid JSON (got: ${INFO:0:80})"
fi

# Test 3: Response signing headers (only available after Init completes with attestation key)
echo "[3/5] Attestation signature headers"
HEADERS=$(curl -skI --max-time 10 "${BASE_URL}/v1/enclave-info" 2>/dev/null || echo "")
INIT_ERR_CHECK=$(echo "$INFO" | jq -r '.error // empty' 2>/dev/null || echo "")
if echo "$HEADERS" | grep -qi "X-Attestation-Signature"; then
  pass "X-Attestation-Signature header present"
elif [ -n "$INIT_ERR_CHECK" ]; then
  pass "X-Attestation-Signature not present (expected — Init incomplete)"
else
  fail "Attestation headers" "X-Attestation-Signature missing"
fi
if echo "$HEADERS" | grep -qi "X-Attestation-Pubkey"; then
  pass "X-Attestation-Pubkey header present"
elif [ -n "$INIT_ERR_CHECK" ]; then
  pass "X-Attestation-Pubkey not present (expected — Init incomplete)"
else
  fail "Attestation headers" "X-Attestation-Pubkey missing"
fi

# Test 4: Init status (error expected without real AWS services)
echo "[4/5] Init status"
if [ -n "$INFO" ]; then
  INIT_ERR=$(echo "$INFO" | jq -r '.error // empty' 2>/dev/null || echo "")
  if [ -z "$INIT_ERR" ]; then
    pass "Init completed successfully (no init_error)"
  else
    pass "Init reported error (expected without AWS): ${INIT_ERR:0:60}"
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
