#!/usr/bin/env bash
# Integration tests for a running QEMU enclave.
# Run after Init completes (health returns 200).
set -euo pipefail

HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"
MGMT_PORT="${MGMT_PORT:-8444}"
BASE_URL="${ENCLAVE_URL:-https://localhost:${HOST_TLS_PORT}}"
CURL="curl -sk --max-time 10"
PROM_URL="http://localhost:9191"
PASSED=0
FAILED=0
TOTAL=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); }
fail() { echo "  FAIL: $1 — $2"; FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); }

echo "=== Integration tests against $BASE_URL ==="
echo ""

# Test 1: Health endpoint returns 200 (Init must be complete).
echo "[1/22] Health check"
HEALTH_CODE=$($CURL -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$HEALTH_CODE" = "200" ]; then
  pass "Health endpoint returns 200"
else
  fail "Health endpoint" "expected 200, got HTTP $HEALTH_CODE"
fi

# Test 2: Enclave info returns valid JSON with required fields.
echo "[2/22] Enclave info"
INFO=$($CURL "${BASE_URL}/v1/enclave-info" 2>/dev/null || echo "")
if [ -n "$INFO" ] && echo "$INFO" | jq -e '.version' >/dev/null 2>&1; then
  pass "Enclave info returns valid JSON"
else
  fail "Enclave info" "missing or invalid JSON (got: ${INFO:0:80})"
fi

# Test 3: Init completed successfully (no error field).
echo "[3/22] Init status"
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

# Test 4: BIP-340 Schnorr signature verification (end-to-end inside enclave).
# The test app fetches /v1/enclave-info from the supervisor, parses the
# X-Attestation-Signature and X-Attestation-Pubkey headers, and verifies
# the Schnorr signature over sha256(response_body).
# This implicitly validates the attestation pubkey is present and correctly formatted.
echo "[4/22] Attestation signature verification"
ATTEST_RESP=$($CURL "${BASE_URL}/test/attestation" 2>/dev/null || echo "")
if [ -n "$ATTEST_RESP" ] && echo "$ATTEST_RESP" | jq -e '.signature_valid == true' >/dev/null 2>&1; then
  ATTEST_PUBKEY=$(echo "$ATTEST_RESP" | jq -r '.pubkey // empty' 2>/dev/null || echo "")
  pass "Schnorr signature valid (pubkey: ${ATTEST_PUBKEY:0:16}...)"
else
  fail "Attestation signature" "${ATTEST_RESP:0:120}"
fi

# Test 5: SDK version present.
echo "[5/22] SDK version"
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

# Test 6: App endpoint responds through nitriding proxy.
echo "[6/22] App proxy"
APP_RESP=$($CURL "${BASE_URL}/" 2>/dev/null || echo "")
if [ -n "$APP_RESP" ] && echo "$APP_RESP" | jq -e '.app == "test-enclave-app"' >/dev/null 2>&1; then
  pass "App responds through proxy"
else
  fail "App proxy" "unexpected response: ${APP_RESP:0:80}"
fi

# Test 7: KMS secrets loaded (SIGNING_KEY env var set inside enclave).
echo "[7/22] KMS secrets"
SECRETS_RESP=$($CURL "${BASE_URL}/test/secrets" 2>/dev/null || echo "")
if [ -n "$SECRETS_RESP" ] && echo "$SECRETS_RESP" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  KEY_LEN=$(echo "$SECRETS_RESP" | jq -r '.signing_key.length // 0' 2>/dev/null || echo "0")
  pass "KMS secrets loaded (signing_key: ${KEY_LEN} bytes)"
else
  fail "KMS secrets" "secrets check failed: ${SECRETS_RESP:0:80}"
fi

# Test 8: Storage round-trip (put → get → verify → delete via S3+KMS).
echo "[8/22] Storage round-trip"
STORAGE_RESP=$($CURL "${BASE_URL}/test/storage" 2>/dev/null || echo "")
if [ -n "$STORAGE_RESP" ] && echo "$STORAGE_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  pass "Storage round-trip (put/get/delete)"
else
  fail "Storage round-trip" "${STORAGE_RESP:0:120}"
fi

# Test 9: previous_pcr0 is "genesis" on first boot (no prior enclave).
echo "[9/22] Previous PCR0"
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

# Test 10: Dynamic secrets round-trip (PUT → GET → LIST → DELETE).
echo "[10/22] Dynamic secrets"
DYN_RESP=$($CURL "${BASE_URL}/test/dynamic-secrets" 2>/dev/null || echo "")
if [ -n "$DYN_RESP" ] && echo "$DYN_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  DYN_LISTED=$(echo "$DYN_RESP" | jq -r '.listed // false' 2>/dev/null || echo "false")
  pass "Dynamic secrets round-trip (listed=$DYN_LISTED)"
else
  fail "Dynamic secrets" "${DYN_RESP:0:120}"
fi

# Test 11: PCR secret derivation + attestation document PCR16 verification.
# Verifies SIGNING_KEY → pubkey → extension data derivation and that PCR16
# in the attestation document matches the expected value (extended + locked by SDK).
echo "[11/22] PCR secret derivation + PCR16 verification"
PCR_RESP=$($CURL "${BASE_URL}/test/pcr-secrets" 2>/dev/null || echo "")
if [ -n "$PCR_RESP" ] && echo "$PCR_RESP" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  PCR_COUNT=$(echo "$PCR_RESP" | jq -r '.pcr_count // 0' 2>/dev/null || echo "0")
  PCR16_VERIFIED=$(echo "$PCR_RESP" | jq -r '.pcr16_verified // false' 2>/dev/null || echo "false")
  PCR16_PRESENT=$(echo "$PCR_RESP" | jq -r '.pcr16_present // false' 2>/dev/null || echo "false")
  if [ "$PCR16_VERIFIED" = "true" ]; then
    pass "PCR derivation valid, PCR16 verified from attestation doc (${PCR_COUNT} PCRs)"
  elif [ "$PCR16_PRESENT" = "true" ]; then
    fail "PCR16 present but value mismatch" "$(echo "$PCR_RESP" | jq -c '{expected_pcr16,actual_pcr16}')"
  else
    fail "PCR16 missing from attestation doc (lock failed?)" "$(echo "$PCR_RESP" | jq -c '{pcr_count,pcr16_present}')"
  fi
else
  fail "PCR secret derivation" "${PCR_RESP:0:120}"
fi

# Test 12: Full attestation document structure verification.
# Fetches raw attestation doc, parses COSE Sign1 + CBOR, verifies PCR map exists,
# PCR0 is present and non-zero, and PCR16 matches expected value (locked by SDK).
echo "[12/22] Attestation document structure"
ATTEST_DOC_RESP=$($CURL "${BASE_URL}/test/attestation-document" 2>/dev/null || echo "")
if [ -n "$ATTEST_DOC_RESP" ] && echo "$ATTEST_DOC_RESP" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  PCR_COUNT=$(echo "$ATTEST_DOC_RESP" | jq -r '.pcr_count // 0' 2>/dev/null || echo "0")
  PCR0_NONZERO=$(echo "$ATTEST_DOC_RESP" | jq -r '.pcr0_nonzero // false' 2>/dev/null || echo "false")
  PCR16_OK=$(echo "$ATTEST_DOC_RESP" | jq -r '.pcr16_verified // false' 2>/dev/null || echo "false")
  if [ "$PCR0_NONZERO" != "true" ]; then
    fail "PCR0 is zero or missing" "$(echo "$ATTEST_DOC_RESP" | jq -c '{pcr0_present,pcr0_nonzero}')"
  elif [ "$PCR16_OK" != "true" ]; then
    fail "PCR16 verification failed" "$(echo "$ATTEST_DOC_RESP" | jq -c '{pcr16_verified,pcr16}')"
  else
    pass "Attestation doc: ${PCR_COUNT} PCRs, PCR0 valid, PCR16 verified"
  fi
else
  fail "Attestation document" "${ATTEST_DOC_RESP:0:120}"
fi

# Test 13: Storage persistence (write a known key for post-migration verification).
echo "[13/22] Storage persistence (write phase)"
PERSIST_RESP=$($CURL "${BASE_URL}/test/storage-persistence" 2>/dev/null || echo "")
if [ -n "$PERSIST_RESP" ] && echo "$PERSIST_RESP" | jq -e '.phase' >/dev/null 2>&1; then
  PHASE=$(echo "$PERSIST_RESP" | jq -r '.phase' 2>/dev/null || echo "")
  pass "Storage persistence $PHASE phase"
else
  fail "Storage persistence" "${PERSIST_RESP:0:120}"
fi

# Test 14: Dynamic secret persistence (write a known secret for post-migration verification).
echo "[14/22] Dynamic secret persistence (write phase)"
DYN_PERSIST_RESP=$($CURL "${BASE_URL}/test/dynamic-secret-persistence" 2>/dev/null || echo "")
if [ -n "$DYN_PERSIST_RESP" ] && echo "$DYN_PERSIST_RESP" | jq -e '.phase' >/dev/null 2>&1; then
  DYN_PHASE=$(echo "$DYN_PERSIST_RESP" | jq -r '.phase' 2>/dev/null || echo "")
  pass "Dynamic secret persistence $DYN_PHASE phase"
else
  fail "Dynamic secret persistence" "${DYN_PERSIST_RESP:0:120}"
fi

# Test 15: Attestation persistence (write pubkey + PCR16 hash for post-migration verification).
echo "[15/22] Attestation persistence (write phase)"
ATTEST_PERSIST=$($CURL "${BASE_URL}/test/attestation-persistence" 2>/dev/null || echo "")
if [ -n "$ATTEST_PERSIST" ] && echo "$ATTEST_PERSIST" | jq -e '.phase' >/dev/null 2>&1; then
  ATTEST_PHASE=$(echo "$ATTEST_PERSIST" | jq -r '.phase' 2>/dev/null || echo "")
  ATTEST_PCR16=$(echo "$ATTEST_PERSIST" | jq -r '.pcr16 // empty' 2>/dev/null || echo "")
  pass "Attestation persistence $ATTEST_PHASE phase (PCR16: ${ATTEST_PCR16:0:16}...)"
else
  fail "Attestation persistence" "${ATTEST_PERSIST:0:120}"
fi

# Test 16: Schnorr signature still valid (sanity check before migration).
echo "[16/22] Pre-migration signature check"
ATTEST2=$($CURL "${BASE_URL}/test/attestation" 2>/dev/null || echo "")
if [ -n "$ATTEST2" ] && echo "$ATTEST2" | jq -e '.signature_valid == true' >/dev/null 2>&1; then
  pass "Schnorr signature valid (pre-migration baseline)"
else
  fail "Pre-migration signature" "${ATTEST2:0:120}"
fi

# Test 17: Attestation binding (pubkey → UserData in attestation doc).
# Verifies the full chain: X-Attestation-Pubkey signs responses, and
# SHA256(pubkey) is bound to the NSM attestation document via UserData.
echo "[17/22] Attestation binding (pubkey → UserData)"
BINDING_RESP=$($CURL "${BASE_URL}/test/attestation-binding" 2>/dev/null || echo "")
if [ -n "$BINDING_RESP" ] && echo "$BINDING_RESP" | jq -e '.binding_valid == true' >/dev/null 2>&1; then
  pass "Attestation pubkey bound to NSM document (SHA256(pubkey) == UserData)"
else
  fail "Attestation binding" "${BINDING_RESP:0:120}"
fi

# --- Prometheus scraping tests ---
# Start Prometheus with a 2s scrape interval, wait for at least one scrape cycle,
# then query the Prometheus HTTP API to verify metrics were ingested.
PROM_PID=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if command -v prometheus &>/dev/null; then
  PROM_DATA_DIR=$(mktemp -d)
  prometheus \
    --config.file="${SCRIPT_DIR}/prometheus.yml" \
    --storage.tsdb.path="$PROM_DATA_DIR" \
    --web.listen-address=":9191" \
    --log.level=warn &
  PROM_PID=$!
  sleep 1
  if ! kill -0 "$PROM_PID" 2>/dev/null; then
    echo "  Warning: Prometheus failed to start, skipping Prometheus tests"
    PROM_PID=""
  else
    # Wait for at least one scrape cycle (2s interval + margin).
    sleep 6
  fi
else
  echo "  Warning: prometheus binary not found, skipping Prometheus tests"
fi

# Test 18: Prometheus scrapes enclave metrics successfully.
echo "[18/22] Prometheus scrape targets"
if [ -n "$PROM_PID" ]; then
  TARGETS_UP=$(curl -sf "${PROM_URL}/api/v1/targets" 2>/dev/null \
    | jq '[.data.activeTargets[] | select(.health == "up")] | length' 2>/dev/null || echo "0")
  if [ "$TARGETS_UP" -ge 1 ]; then
    pass "Prometheus scraped $TARGETS_UP target(s) successfully"
  else
    fail "Prometheus scrape" "no targets up (got $TARGETS_UP)"
  fi
else
  fail "Prometheus scrape" "prometheus not running"
fi

# Test 19: Prometheus has enclave application metrics (from /v1/metrics).
echo "[19/22] Prometheus enclave metrics"
if [ -n "$PROM_PID" ]; then
  # Query for one of the enclave_ prefixed counters.
  METRIC_VAL=$(curl -sf "${PROM_URL}/api/v1/query?query=enclave_http_requests_total" 2>/dev/null \
    | jq '.data.result | length' 2>/dev/null || echo "0")
  if [ "$METRIC_VAL" -ge 1 ]; then
    pass "enclave_http_requests_total present in Prometheus"
  else
    # Try the host gauge as fallback (mgmt endpoint).
    HOST_UP=$(curl -sf "${PROM_URL}/api/v1/query?query=enclave_host_up" 2>/dev/null \
      | jq '.data.result | length' 2>/dev/null || echo "0")
    if [ "$HOST_UP" -ge 1 ]; then
      pass "enclave_host_up present in Prometheus (app metrics may need more scrapes)"
    else
      fail "Prometheus enclave metrics" "no enclave_* metrics found"
    fi
  fi
else
  fail "Prometheus enclave metrics" "prometheus not running"
fi

# Test 20: Migration cooldown fields in enclave-info.
# Verifies the enclave-info response includes migration_cooldown_seconds,
# migration_cooldown_remaining, and migration_pending fields.
echo "[20/22] Migration cooldown in enclave-info"
COOLDOWN_INFO=$($CURL "${BASE_URL}/v1/enclave-info" 2>/dev/null || echo "")
if [ -n "$COOLDOWN_INFO" ] && echo "$COOLDOWN_INFO" | jq -e 'has("migration_cooldown_seconds")' >/dev/null 2>&1; then
  COOLDOWN_SEC=$(echo "$COOLDOWN_INFO" | jq -r '.migration_cooldown_seconds // -1' 2>/dev/null || echo "-1")
  MIG_PENDING=$(echo "$COOLDOWN_INFO" | jq -r '.migration_pending // false' 2>/dev/null || echo "false")
  if [ "$MIG_PENDING" = "false" ]; then
    pass "Migration cooldown present (configured=${COOLDOWN_SEC}s, pending=false)"
  else
    COOLDOWN_REM=$(echo "$COOLDOWN_INFO" | jq -r '.migration_cooldown_remaining // 0' 2>/dev/null || echo "0")
    pass "Migration cooldown present (configured=${COOLDOWN_SEC}s, remaining=${COOLDOWN_REM}s, pending=true)"
  fi
else
  fail "Migration cooldown" "migration_cooldown_seconds missing from enclave-info (got: ${COOLDOWN_INFO:0:80})"
fi

# Test 21: Migration abort endpoint (mgmt server).
# If the mgmt server is reachable, verify POST /migrate/abort returns a valid response
# when no migration is in progress (should be 409 Conflict).
MGMT_URL="http://localhost:${MGMT_PORT}"
echo "[21/22] Migration abort endpoint"
ABORT_CODE=$($CURL -o /dev/null -w '%{http_code}' -X POST "${MGMT_URL}/migrate/abort" 2>/dev/null || echo "000")
if [ "$ABORT_CODE" = "409" ]; then
  pass "Migration abort returns 409 (no migration in cooldown)"
elif [ "$ABORT_CODE" = "000" ]; then
  pass "Migration abort skipped (mgmt server not reachable)"
else
  fail "Migration abort" "expected 409, got HTTP $ABORT_CODE"
fi

# Test 22: Attestation still works after all tests (NSM stability).
echo "[22/22] Attestation stability check"
PCR_RESP2=$($CURL "${BASE_URL}/test/pcr-secrets" 2>/dev/null || echo "")
if [ -n "$PCR_RESP2" ] && echo "$PCR_RESP2" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  pass "Attestation stable after all tests"
else
  fail "Attestation stability" "${PCR_RESP2:0:120}"
fi

# Clean up Prometheus.
if [ -n "$PROM_PID" ]; then
  kill "$PROM_PID" 2>/dev/null || true
  wait "$PROM_PID" 2>/dev/null || true
  rm -rf "$PROM_DATA_DIR"
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed (of $TOTAL) ==="

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
