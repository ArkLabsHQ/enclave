#!/usr/bin/env bash
# Integration tests for a running QEMU enclave.
# Run after Init completes (health returns 200).
set -euo pipefail

HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"
BASE_URL="${ENCLAVE_URL:-https://localhost:${HOST_TLS_PORT}}"
CURL="curl -sk --max-time 10"
PASSED=0
FAILED=0
TOTAL=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); }
fail() { echo "  FAIL: $1 — $2"; FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); }

echo "=== Integration tests against $BASE_URL ==="
echo ""

# Test 1: Health endpoint returns 200 (Init must be complete).
echo "[1/10] Health check"
HEALTH_CODE=$($CURL -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$HEALTH_CODE" = "200" ]; then
  pass "Health endpoint returns 200"
else
  fail "Health endpoint" "expected 200, got HTTP $HEALTH_CODE"
fi

# Test 2: Enclave info returns valid JSON with required fields.
echo "[2/10] Enclave info"
INFO=$($CURL "${BASE_URL}/v1/enclave-info" 2>/dev/null || echo "")
if [ -n "$INFO" ] && echo "$INFO" | jq -e '.version' >/dev/null 2>&1; then
  pass "Enclave info returns valid JSON"
else
  fail "Enclave info" "missing or invalid JSON (got: ${INFO:0:80})"
fi

# Test 3: Init completed successfully (no error field).
echo "[3/10] Init status"
if [ -n "$INFO" ]; then
  INIT_ERR=$(echo "$INFO" | jq -r '.error // empty' 2>/dev/null || echo "")
  if [ -z "$INIT_ERR" ]; then
    pass "Init completed successfully"
  else
    fail "Init" "${INIT_ERR:0:80}"
  fi
else
  fail "Init status" "could not fetch enclave-info"
fi

# Test 4: Attestation pubkey is present and valid hex.
echo "[4/10] Attestation pubkey"
if [ -n "$INFO" ]; then
  PUBKEY=$(echo "$INFO" | jq -r '.attestation_pubkey // empty' 2>/dev/null || echo "")
  if [ -n "$PUBKEY" ] && echo "$PUBKEY" | grep -qE '^[0-9a-f]{66}$'; then
    pass "Attestation pubkey present (${PUBKEY:0:16}...)"
  elif [ -n "$PUBKEY" ]; then
    fail "Attestation pubkey" "present but unexpected format: ${PUBKEY:0:32}"
  else
    fail "Attestation pubkey" "missing from enclave-info"
  fi
else
  fail "Attestation pubkey" "could not fetch enclave-info"
fi

# Test 5: BIP-340 Schnorr signature verification (end-to-end inside enclave).
# The test app fetches /v1/enclave-info from the supervisor, parses the
# X-Attestation-Signature and X-Attestation-Pubkey headers, and verifies
# the Schnorr signature over sha256(response_body).
echo "[5/10] Attestation signature verification"
ATTEST_RESP=$($CURL "${BASE_URL}/test/attestation" 2>/dev/null || echo "")
if [ -n "$ATTEST_RESP" ] && echo "$ATTEST_RESP" | jq -e '.signature_valid == true' >/dev/null 2>&1; then
  ATTEST_PUBKEY=$(echo "$ATTEST_RESP" | jq -r '.pubkey // empty' 2>/dev/null || echo "")
  pass "Schnorr signature valid (pubkey: ${ATTEST_PUBKEY:0:16}...)"
else
  fail "Attestation signature" "${ATTEST_RESP:0:120}"
fi

# Test 6: SDK version present.
echo "[6/10] SDK version"
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

# Test 7: App endpoint responds through nitriding proxy.
echo "[7/10] App proxy"
APP_RESP=$($CURL "${BASE_URL}/" 2>/dev/null || echo "")
if [ -n "$APP_RESP" ] && echo "$APP_RESP" | jq -e '.app == "test-enclave-app"' >/dev/null 2>&1; then
  pass "App responds through proxy"
else
  fail "App proxy" "unexpected response: ${APP_RESP:0:80}"
fi

# Test 8: KMS secrets loaded (SIGNING_KEY env var set inside enclave).
echo "[8/10] KMS secrets"
SECRETS_RESP=$($CURL "${BASE_URL}/test/secrets" 2>/dev/null || echo "")
if [ -n "$SECRETS_RESP" ] && echo "$SECRETS_RESP" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  KEY_LEN=$(echo "$SECRETS_RESP" | jq -r '.signing_key.length // 0' 2>/dev/null || echo "0")
  pass "KMS secrets loaded (signing_key: ${KEY_LEN} bytes)"
else
  fail "KMS secrets" "secrets check failed: ${SECRETS_RESP:0:80}"
fi

# Test 9: Storage round-trip (put → get → verify → delete via S3+KMS).
echo "[9/10] Storage round-trip"
STORAGE_RESP=$($CURL "${BASE_URL}/test/storage" 2>/dev/null || echo "")
if [ -n "$STORAGE_RESP" ] && echo "$STORAGE_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  pass "Storage round-trip (put/get/delete)"
else
  fail "Storage round-trip" "${STORAGE_RESP:0:120}"
fi

# Test 10: previous_pcr0 is "genesis" on first boot (no prior enclave).
echo "[10/10] Previous PCR0"
if [ -n "$INFO" ]; then
  PREV_PCR0=$(echo "$INFO" | jq -r '.previous_pcr0 // empty' 2>/dev/null || echo "")
  if [ "$PREV_PCR0" = "genesis" ]; then
    pass "previous_pcr0 is genesis (first boot)"
  elif [ -n "$PREV_PCR0" ]; then
    pass "previous_pcr0 present: ${PREV_PCR0:0:16}..."
  else
    fail "Previous PCR0" "missing from enclave-info"
  fi
else
  fail "Previous PCR0" "could not fetch enclave-info"
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed (of $TOTAL) ==="

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
