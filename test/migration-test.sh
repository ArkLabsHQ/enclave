#!/usr/bin/env bash
# Migration test: exercises the enclave-side of the locked-key migration flow.
#
# Simulates what deploy.go:deployUpgrade() does on the CLI side:
#   1. Creates a new KMS key (migration target)
#   2. Stores migration params in SSM
#   3. Calls POST /v1/export-key on the running enclave
#   4. Verifies migration ciphertexts + PCR0 attestation in SSM
#
# Prerequisites: enclave must be booted and Init complete (secrets loaded).
set -euo pipefail

HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"
BASE_URL="${ENCLAVE_URL:-https://localhost:${HOST_TLS_PORT}}"
CURL="curl -sf --max-time 10 -k"

SSM_ENDPOINT="http://localhost:4566"
KMS_ENDPOINT="http://localhost:4000"

AWS_COMMON="--region us-east-1 --output text"
SSM="aws --endpoint-url=$SSM_ENDPOINT ssm $AWS_COMMON"
KMS="aws --endpoint-url=$KMS_ENDPOINT kms $AWS_COMMON"

DEPLOYMENT="dev"
APP_NAME="my-app"
PREFIX="/$DEPLOYMENT/$APP_NAME"

PASSED=0
FAILED=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "  FAIL: $1 — $2"; FAILED=$((FAILED + 1)); }

ssm_get() {
  $SSM get-parameter --name "$1" --query 'Parameter.Value' 2>/dev/null || echo ""
}

echo "=== Migration tests ==="
echo ""

# --- Pre-conditions ---
echo "[1/6] Verify secret was initialized by enclave Init"
SECRET_CT=$(ssm_get "$PREFIX/signing-key/Ciphertext")
if [ -n "$SECRET_CT" ] && [ "$SECRET_CT" != "UNSET" ]; then
  pass "signing-key ciphertext exists in SSM"
else
  fail "signing-key ciphertext" "not found in SSM (Init may not have completed)"
  echo ""
  echo "=== Results: $PASSED passed, $FAILED failed ==="
  exit 1
fi

OLD_KEY_ID=$(ssm_get "$PREFIX/KMSKeyID")
if [ -z "$OLD_KEY_ID" ] || [ "$OLD_KEY_ID" = "UNSET" ]; then
  # Fall back to the env-configured key ID
  OLD_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/test-key-id"
fi
echo "  Old KMS key: $OLD_KEY_ID"

# --- Step 1: Create migration KMS key ---
echo "[2/6] Create migration KMS key"
NEW_KEY_ARN=$($KMS create-key --description "migration test key" --query 'KeyMetadata.Arn')
if [ -n "$NEW_KEY_ARN" ]; then
  pass "Created migration KMS key: $NEW_KEY_ARN"
else
  fail "Create migration KMS key" "aws kms create-key failed"
  echo ""
  echo "=== Results: $PASSED passed, $FAILED failed ==="
  exit 1
fi

# --- Step 2: Store migration params in SSM ---
echo "[3/6] Store migration params in SSM"
$SSM put-parameter --name "$PREFIX/MigrationKMSKeyID" --value "$NEW_KEY_ARN" --type String --overwrite >/dev/null
$SSM put-parameter --name "$PREFIX/MigrationOldKMSKeyID" --value "$OLD_KEY_ID" --type String --overwrite >/dev/null
pass "Migration KMS key IDs stored in SSM"

# --- Step 3: Call export-key ---
echo "[4/6] Call POST /v1/export-key"
EXPORT_HTTP_CODE=$(curl -sk --max-time 30 -o /tmp/export-response.json -w '%{http_code}' \
  -X POST "${BASE_URL}/v1/export-key" 2>/dev/null || echo "000")

if [ "$EXPORT_HTTP_CODE" = "200" ]; then
  EXPORT_BODY=$(cat /tmp/export-response.json)
  EXPORTED=$(echo "$EXPORT_BODY" | jq -r '.exported[]' 2>/dev/null || echo "")
  PCR0=$(echo "$EXPORT_BODY" | jq -r '.pcr0' 2>/dev/null || echo "")

  if echo "$EXPORTED" | grep -q "signing-key"; then
    pass "export-key returned signing-key in exported list"
  else
    fail "export-key response" "signing-key not in exported list (got: $EXPORT_BODY)"
  fi

  if [ -n "$PCR0" ] && [ "$PCR0" != "null" ]; then
    pass "export-key returned PCR0: ${PCR0:0:32}..."
  else
    fail "export-key PCR0" "missing from response"
  fi
else
  EXPORT_ERR=$(cat /tmp/export-response.json 2>/dev/null || echo "no body")
  fail "export-key" "HTTP $EXPORT_HTTP_CODE (body: ${EXPORT_ERR:0:120})"
fi

# --- Step 4: Verify migration artifacts in SSM ---
echo "[5/6] Verify migration artifacts in SSM"

MIG_CT=$(ssm_get "$PREFIX/Migration/signing-key/Ciphertext")
if [ -n "$MIG_CT" ] && [ "$MIG_CT" != "UNSET" ]; then
  pass "Migration ciphertext for signing-key exists in SSM"
else
  fail "Migration ciphertext" "not found in SSM"
fi

MIG_DEK=$(ssm_get "$PREFIX/Migration/StorageDEK/Ciphertext")
if [ -n "$MIG_DEK" ] && [ "$MIG_DEK" != "UNSET" ]; then
  pass "Migration StorageDEK ciphertext exists in SSM (${#MIG_DEK} chars)"
else
  fail "Migration StorageDEK" "not found in SSM (storage DEK not exported)"
fi

MIG_PCR0=$(ssm_get "$PREFIX/MigrationPreviousPCR0")
if [ -n "$MIG_PCR0" ] && [ "$MIG_PCR0" != "UNSET" ]; then
  pass "MigrationPreviousPCR0 stored: ${MIG_PCR0:0:32}..."
else
  fail "MigrationPreviousPCR0" "not found in SSM"
fi

MIG_ATTEST=$(ssm_get "$PREFIX/MigrationPreviousPCR0Attestation")
if [ -n "$MIG_ATTEST" ] && [ "$MIG_ATTEST" != "UNSET" ]; then
  pass "MigrationPreviousPCR0Attestation stored (${#MIG_ATTEST} chars)"
else
  fail "MigrationPreviousPCR0Attestation" "not found in SSM"
fi

# --- Step 5: Verify storage still works after export ---
echo "[6/6] Storage round-trip after export"
STORAGE_RESP=$(curl -sk --max-time 10 "${BASE_URL}/test/storage" 2>/dev/null || echo "")
if echo "$STORAGE_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  pass "Storage round-trip works after DEK export"
else
  fail "Storage after export" "${STORAGE_RESP:0:120}"
fi

# --- Summary ---
echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
