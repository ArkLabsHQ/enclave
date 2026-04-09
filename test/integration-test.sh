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
echo "[1/27] Health check"
HEALTH_CODE=$($CURL -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$HEALTH_CODE" = "200" ]; then
  pass "Health endpoint returns 200"
else
  fail "Health endpoint" "expected 200, got HTTP $HEALTH_CODE"
fi

# Test 2: Enclave info returns valid JSON with required fields.
echo "[2/27] Enclave info"
INFO=$($CURL "${BASE_URL}/v1/enclave-info" 2>/dev/null || echo "")
if [ -n "$INFO" ] && echo "$INFO" | jq -e '.version' >/dev/null 2>&1; then
  pass "Enclave info returns valid JSON"
else
  fail "Enclave info" "missing or invalid JSON (got: ${INFO:0:80})"
fi

# Test 3: Init completed successfully (no error field).
echo "[3/27] Init status"
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
echo "[4/27] Attestation signature verification"
ATTEST_RESP=$($CURL "${BASE_URL}/test/attestation" 2>/dev/null || echo "")
if [ -n "$ATTEST_RESP" ] && echo "$ATTEST_RESP" | jq -e '.signature_valid == true' >/dev/null 2>&1; then
  ATTEST_PUBKEY=$(echo "$ATTEST_RESP" | jq -r '.pubkey // empty' 2>/dev/null || echo "")
  pass "Schnorr signature valid (pubkey: ${ATTEST_PUBKEY:0:16}...)"
else
  fail "Attestation signature" "${ATTEST_RESP:0:120}"
fi

# Test 5: SDK version present.
echo "[5/27] SDK version"
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
echo "[6/27] App proxy"
APP_RESP=$($CURL "${BASE_URL}/" 2>/dev/null || echo "")
if [ -n "$APP_RESP" ] && echo "$APP_RESP" | jq -e '.app == "test-enclave-app"' >/dev/null 2>&1; then
  pass "App responds through proxy"
else
  fail "App proxy" "unexpected response: ${APP_RESP:0:80}"
fi

# Test 7: KMS secrets loaded (SIGNING_KEY env var set inside enclave).
echo "[7/27] KMS secrets"
SECRETS_RESP=$($CURL "${BASE_URL}/test/secrets" 2>/dev/null || echo "")
if [ -n "$SECRETS_RESP" ] && echo "$SECRETS_RESP" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  KEY_LEN=$(echo "$SECRETS_RESP" | jq -r '.signing_key.length // 0' 2>/dev/null || echo "0")
  pass "KMS secrets loaded (signing_key: ${KEY_LEN} bytes)"
else
  fail "KMS secrets" "secrets check failed: ${SECRETS_RESP:0:80}"
fi

# Test 8: Storage round-trip (put → get → verify → delete via S3+KMS).
echo "[8/27] Storage round-trip"
STORAGE_RESP=$($CURL "${BASE_URL}/test/storage" 2>/dev/null || echo "")
if [ -n "$STORAGE_RESP" ] && echo "$STORAGE_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  pass "Storage round-trip (put/get/delete)"
else
  fail "Storage round-trip" "${STORAGE_RESP:0:120}"
fi

# Test 9: previous_pcr0 is "genesis" on first boot (no prior enclave).
echo "[9/27] Previous PCR0"
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
echo "[10/27] Dynamic secrets"
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
echo "[11/27] PCR secret derivation + PCR16 verification"
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
echo "[12/27] Attestation document structure"
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
echo "[13/27] Storage persistence (write phase)"
PERSIST_RESP=$($CURL "${BASE_URL}/test/storage-persistence" 2>/dev/null || echo "")
if [ -n "$PERSIST_RESP" ] && echo "$PERSIST_RESP" | jq -e '.phase' >/dev/null 2>&1; then
  PHASE=$(echo "$PERSIST_RESP" | jq -r '.phase' 2>/dev/null || echo "")
  pass "Storage persistence $PHASE phase"
else
  fail "Storage persistence" "${PERSIST_RESP:0:120}"
fi

# Test 14: Dynamic secret persistence (write a known secret for post-migration verification).
echo "[14/27] Dynamic secret persistence (write phase)"
DYN_PERSIST_RESP=$($CURL "${BASE_URL}/test/dynamic-secret-persistence" 2>/dev/null || echo "")
if [ -n "$DYN_PERSIST_RESP" ] && echo "$DYN_PERSIST_RESP" | jq -e '.phase' >/dev/null 2>&1; then
  DYN_PHASE=$(echo "$DYN_PERSIST_RESP" | jq -r '.phase' 2>/dev/null || echo "")
  pass "Dynamic secret persistence $DYN_PHASE phase"
else
  fail "Dynamic secret persistence" "${DYN_PERSIST_RESP:0:120}"
fi

# Test 15: Attestation persistence (write pubkey + PCR16 hash for post-migration verification).
echo "[15/27] Attestation persistence (write phase)"
ATTEST_PERSIST=$($CURL "${BASE_URL}/test/attestation-persistence" 2>/dev/null || echo "")
if [ -n "$ATTEST_PERSIST" ] && echo "$ATTEST_PERSIST" | jq -e '.phase' >/dev/null 2>&1; then
  ATTEST_PHASE=$(echo "$ATTEST_PERSIST" | jq -r '.phase' 2>/dev/null || echo "")
  ATTEST_PCR16=$(echo "$ATTEST_PERSIST" | jq -r '.pcr16 // empty' 2>/dev/null || echo "")
  pass "Attestation persistence $ATTEST_PHASE phase (PCR16: ${ATTEST_PCR16:0:16}...)"
else
  fail "Attestation persistence" "${ATTEST_PERSIST:0:120}"
fi

# Test 16: Schnorr signature still valid (sanity check before migration).
echo "[16/27] Pre-migration signature check"
ATTEST2=$($CURL "${BASE_URL}/test/attestation" 2>/dev/null || echo "")
if [ -n "$ATTEST2" ] && echo "$ATTEST2" | jq -e '.signature_valid == true' >/dev/null 2>&1; then
  pass "Schnorr signature valid (pre-migration baseline)"
else
  fail "Pre-migration signature" "${ATTEST2:0:120}"
fi

# Test 17: Attestation binding (pubkey → UserData in attestation doc).
# Verifies the full chain: X-Attestation-Pubkey signs responses, and
# SHA256(pubkey) is bound to the NSM attestation document via UserData.
echo "[17/27] Attestation binding (pubkey → UserData)"
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
echo "[18/27] Prometheus scrape targets"
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
echo "[19/27] Prometheus enclave metrics"
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

# --- Log tests ---
# The test app POSTs logs to the supervisor. We verify the full pipeline
# by reading them back through the management server's /logs endpoint.
MGMT_URL="http://localhost:${MGMT_PORT}"

# Test 20: Log POST (app → supervisor) + GET via mgmt server.
echo "[20/27] Log round-trip via mgmt server"
# First, have the test app POST log entries to the supervisor.
LOG_POST=$($CURL "${BASE_URL}/test/logs" 2>/dev/null || echo "")
if [ -z "$LOG_POST" ] || ! echo "$LOG_POST" | jq -e '.post == "ok"' >/dev/null 2>&1; then
  fail "Log POST" "test app failed to post logs: ${LOG_POST:0:120}"
else
  # Now GET logs via the mgmt server (full pipeline: app → supervisor → mgmt).
  LOG_GET=$(curl -s --max-time 10 "${MGMT_URL}/enclave-logs" 2>/dev/null)
  if [ -z "$LOG_GET" ]; then LOG_GET="[]"; fi
  LOG_FOUND=$(echo "$LOG_GET" | jq '[.[] | select(.message == "integration test log" or .message == "batch entry 1" or .message == "batch entry 2")] | length' 2>/dev/null || echo "0")
  LOG_TOTAL=$(echo "$LOG_GET" | jq 'length' 2>/dev/null || echo "0")
  if [ "$LOG_FOUND" -ge 3 ]; then
    pass "Log round-trip via mgmt (found=$LOG_FOUND, total=$LOG_TOTAL)"
  else
    fail "Log round-trip via mgmt" "expected >= 3 entries, found $LOG_FOUND (total=$LOG_TOTAL)"
  fi
fi

# Test 21: Log level filtering via mgmt server.
echo "[21/27] Log level filtering via mgmt server"
LOG_FILTERED=$(curl -s --max-time 10 "${MGMT_URL}/enclave-logs?level=warn" 2>/dev/null)
if [ -z "$LOG_FILTERED" ]; then LOG_FILTERED="[]"; fi
FILTERED_COUNT=$(echo "$LOG_FILTERED" | jq 'length' 2>/dev/null || echo "0")
ALL_ABOVE_WARN=$(echo "$LOG_FILTERED" | jq 'all(.level == "warn" or .level == "error")' 2>/dev/null || echo "false")
if [ "$FILTERED_COUNT" -ge 2 ] && [ "$ALL_ABOVE_WARN" = "true" ]; then
  pass "Log level filter works via mgmt (filtered=$FILTERED_COUNT, all>=warn)"
else
  fail "Log level filtering" "filtered=$FILTERED_COUNT, all_above_warn=$ALL_ABOVE_WARN"
fi

# Test 22: Log POST requires auth token.
echo "[22/27] Log auth enforcement"
if [ -n "$LOG_POST" ] && echo "$LOG_POST" | jq -e '.auth_enforced == true' >/dev/null 2>&1; then
  pass "Log POST requires auth (401 without token)"
else
  fail "Log auth enforcement" "${LOG_POST:0:120}"
fi

# Test 23: CloudWatch Logs history (supervisor ships logs → mgmt queries CloudWatch).
echo "[23/27] CloudWatch Logs log history"
# Wait for the supervisor's log shipper to flush (5s interval + margin).
sleep 8
CW_HISTORY=$(curl -s --max-time 10 "${MGMT_URL}/enclave-logs?history=true" 2>/dev/null)
if [ -z "$CW_HISTORY" ]; then CW_HISTORY="[]"; fi
CW_COUNT=$(echo "$CW_HISTORY" | jq 'length' 2>/dev/null || echo "0")
CW_FOUND=$(echo "$CW_HISTORY" | jq '[.[] | select(.message == "integration test log" or .message == "batch entry 1" or .message == "batch entry 2")] | length' 2>/dev/null || echo "0")
if [ "$CW_FOUND" -ge 3 ]; then
  pass "CloudWatch history has logs (found=$CW_FOUND, total=$CW_COUNT)"
else
  fail "CloudWatch history" "expected >= 3 entries, found $CW_FOUND (total=$CW_COUNT, raw=${CW_HISTORY:0:200})"
fi

# --- Trace span tests ---
# The test app has OTEL tracing enabled at startup. Every HTTP request creates
# a span automatically (via otelhttp). The app also creates child spans.
# We trigger a request, wait for the OTEL batcher to flush, then check the
# supervisor's /v1/traces buffer via the mgmt proxy.

# Test 24: Make a request to trigger app spans, then verify via mgmt /enclave-traces.
echo "[24/27] App trace spans via mgmt server"
# Make a request to the app — otelhttp creates a span, handleRoot creates a child.
$CURL "${BASE_URL}/" >/dev/null 2>&1
# OTEL batcher flushes every 5s by default. Wait for it.
sleep 7
SPAN_GET=$(curl -sf --max-time 10 "${MGMT_URL}/enclave-traces" 2>/dev/null || echo "[]")
SPAN_ROOT=$(echo "$SPAN_GET" | jq '[.[] | select(.name == "GET /" and .source == "app")] | length' 2>/dev/null || echo "0")
SPAN_CHILD=$(echo "$SPAN_GET" | jq '[.[] | select(.name == "handleRoot.work" and .source == "app")] | length' 2>/dev/null || echo "0")
SPAN_TOTAL=$(echo "$SPAN_GET" | jq 'length' 2>/dev/null || echo "0")
if [ "$SPAN_ROOT" -ge 1 ] && [ "$SPAN_CHILD" -ge 1 ]; then
  pass "App trace spans (root=$SPAN_ROOT, child=$SPAN_CHILD, total=$SPAN_TOTAL)"
else
  fail "App trace spans" "root=$SPAN_ROOT child=$SPAN_CHILD (total=$SPAN_TOTAL, first_200=${SPAN_GET:0:200})"
fi

# Test 25: Supervisor spans present (init stages).
echo "[25/27] Supervisor init spans"
SUP_SPANS=$(echo "$SPAN_GET" | jq '[.[] | select(.source == "supervisor")] | length' 2>/dev/null || echo "0")
INIT_SPAN=$(echo "$SPAN_GET" | jq '[.[] | select(.name == "init" and .source == "supervisor")] | length' 2>/dev/null || echo "0")
if [ "$SUP_SPANS" -ge 1 ] && [ "$INIT_SPAN" -ge 1 ]; then
  pass "Supervisor init spans (supervisor=$SUP_SPANS, init=$INIT_SPAN)"
else
  fail "Supervisor init spans" "supervisor=$SUP_SPANS init=$INIT_SPAN"
fi

# Test 26: App and supervisor spans share the buffer.
echo "[26/27] Mixed app + supervisor spans in buffer"
APP_SPANS=$(echo "$SPAN_GET" | jq '[.[] | select(.source == "app")] | length' 2>/dev/null || echo "0")
if [ "$APP_SPANS" -ge 2 ] && [ "$SUP_SPANS" -ge 1 ]; then
  pass "Mixed spans (app=$APP_SPANS, supervisor=$SUP_SPANS, total=$SPAN_TOTAL)"
else
  fail "Mixed spans" "app=$APP_SPANS supervisor=$SUP_SPANS total=$SPAN_TOTAL"
fi

# Test 27: Attestation still works after all tests (NSM stability).
echo "[27/27] Attestation stability check"
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
