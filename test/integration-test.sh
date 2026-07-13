#!/usr/bin/env bash
# Integration tests for a running QEMU enclave.
# Run after Init completes (health returns 200).
set -euo pipefail

HOST_TLS_PORT="${HOST_TLS_PORT:-8443}"
SUPERVISOR_PORT="${SUPERVISOR_PORT:-8444}"
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
echo "[1/28] Health check"
HEALTH_CODE=$($CURL -o /dev/null -w '%{http_code}' "${BASE_URL}/health" 2>/dev/null || echo "000")
if [ "$HEALTH_CODE" = "200" ]; then
  pass "Health endpoint returns 200"
else
  fail "Health endpoint" "expected 200, got HTTP $HEALTH_CODE"
fi

# Test 2: Enclave info returns valid JSON with required fields.
echo "[2/28] Enclave info"
INFO=$($CURL "${BASE_URL}/v1/enclave-info" 2>/dev/null || echo "")
if [ -n "$INFO" ] && echo "$INFO" | jq -e '.version' >/dev/null 2>&1; then
  pass "Enclave info returns valid JSON"
else
  fail "Enclave info" "missing or invalid JSON (got: ${INFO:0:80})"
fi

# Test 3: Init completed successfully (no error field).
echo "[3/28] Init status"
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
echo "[4/28] Attestation signature verification"
ATTEST_RESP=$($CURL "${BASE_URL}/test/attestation" 2>/dev/null || echo "")
if [ -n "$ATTEST_RESP" ] && echo "$ATTEST_RESP" | jq -e '.signature_valid == true' >/dev/null 2>&1; then
  ATTEST_PUBKEY=$(echo "$ATTEST_RESP" | jq -r '.pubkey // empty' 2>/dev/null || echo "")
  pass "Schnorr signature valid (pubkey: ${ATTEST_PUBKEY:0:16}...)"
else
  fail "Attestation signature" "${ATTEST_RESP:0:120}"
fi

# Test 5: runtime version present.
echo "[5/28] runtime version"
if [ -n "$INFO" ]; then
  VERSION=$(echo "$INFO" | jq -r '.version // empty' 2>/dev/null || echo "")
  if [ -n "$VERSION" ]; then
    pass "runtime version: $VERSION"
  else
    fail "runtime version" "version field missing from enclave-info"
  fi
else
  fail "runtime version" "could not fetch enclave-info"
fi

# Test 6: App endpoint responds through nitriding proxy.
echo "[6/28] App proxy"
APP_RESP=$($CURL "${BASE_URL}/" 2>/dev/null || echo "")
if [ -n "$APP_RESP" ] && echo "$APP_RESP" | jq -e '.app == "test-enclave-app"' >/dev/null 2>&1; then
  pass "App responds through proxy"
else
  fail "App proxy" "unexpected response: ${APP_RESP:0:80}"
fi

# Test 7: KMS secrets loaded (SIGNING_KEY env var set inside enclave).
echo "[7/28] KMS secrets"
SECRETS_RESP=$($CURL "${BASE_URL}/test/secrets" 2>/dev/null || echo "")
if [ -n "$SECRETS_RESP" ] && echo "$SECRETS_RESP" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  KEY_LEN=$(echo "$SECRETS_RESP" | jq -r '.signing_key.length // 0' 2>/dev/null || echo "0")
  pass "KMS secrets loaded (signing_key: ${KEY_LEN} bytes)"
else
  fail "KMS secrets" "secrets check failed: ${SECRETS_RESP:0:80}"
fi

# Test 8: Storage round-trip (put → get → verify → delete via S3+KMS).
echo "[8/28] Storage round-trip"
STORAGE_RESP=$($CURL "${BASE_URL}/test/storage" 2>/dev/null || echo "")
if [ -n "$STORAGE_RESP" ] && echo "$STORAGE_RESP" | jq -e '.roundtrip == true' >/dev/null 2>&1; then
  pass "Storage round-trip (put/get/delete)"
else
  fail "Storage round-trip" "${STORAGE_RESP:0:120}"
fi

# Test 8b: Full Redis surface — hashes, lists, sets, sorted sets, streams,
# MULTI/EXEC, SCAN, pub/sub — exercised through the real go-redis client.
echo "[8b/28] Redis data types + transactions + pub/sub"
TYPES_RESP=$($CURL "${BASE_URL}/test/redis-types" 2>/dev/null || echo "")
if echo "$TYPES_RESP" | jq -e '.ok == true' >/dev/null 2>&1; then
  pass "Redis types/tx/pubsub (hash,list,set,zset,stream,transaction,scan,pubsub)"
else
  fail "Redis data types" "${TYPES_RESP:0:200}"
fi

# Test 9: previous_pcr0 is "genesis" on first boot (no prior enclave).
echo "[9/28] Previous PCR0"
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

# Test 9b: kms_key_locked exposed in enclave-info (issue #131 — clients inspect
# the KMS lock posture to trust the operator can't reach the secrets).
KMS_LOCKED=$(echo "$INFO" | jq -r 'if has("kms_key_locked") then .kms_key_locked | tostring else "missing" end' 2>/dev/null || echo "missing")
if [ "$KMS_LOCKED" = "true" ] || [ "$KMS_LOCKED" = "false" ]; then
  pass "kms_key_locked present in enclave-info (${KMS_LOCKED})"
else
  fail "kms_key_locked" "missing or non-boolean (got: ${KMS_LOCKED})"
fi

# Test 11: PCR secret derivation + attestation document PCR16 verification.
# Verifies SIGNING_KEY → pubkey → extension data derivation and that PCR16
# in the attestation document matches the expected value (extended + locked by runtime).
echo "[11/28] PCR secret derivation + PCR16 verification"
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
# PCR0 is present and non-zero, and PCR16 matches expected value (locked by runtime).
echo "[12/28] Attestation document structure"
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

# Test 13: Storage persistence — write a known key for post-migration verification.
# Uses POST to unconditionally write (deletes stale data first), so the
# post-migration GET verify always has a fresh baseline.
echo "[13/28] Storage persistence (write)"
PERSIST_RESP=$($CURL -X POST "${BASE_URL}/test/storage-persistence" 2>/dev/null || echo "")
if echo "$PERSIST_RESP" | jq -e '.ok == true' >/dev/null 2>&1; then
  pass "Storage persistence write"
else
  fail "Storage persistence write" "${PERSIST_RESP:0:120}"
fi

# Test 15: Attestation persistence — write pubkey + PCR16 hash for post-migration verification.
echo "[15/28] Attestation persistence (write)"
ATTEST_PERSIST=$($CURL -X POST "${BASE_URL}/test/attestation-persistence" 2>/dev/null || echo "")
if echo "$ATTEST_PERSIST" | jq -e '.ok == true' >/dev/null 2>&1; then
  ATTEST_PCR16=$(echo "$ATTEST_PERSIST" | jq -r '.pcr16 // empty' 2>/dev/null || echo "")
  pass "Attestation persistence write (PCR16: ${ATTEST_PCR16:0:16}...)"
else
  fail "Attestation persistence write" "${ATTEST_PERSIST:0:120}"
fi

# Test 16: Schnorr signature still valid (sanity check before migration).
echo "[16/28] Pre-migration signature check"
ATTEST2=$($CURL "${BASE_URL}/test/attestation" 2>/dev/null || echo "")
if [ -n "$ATTEST2" ] && echo "$ATTEST2" | jq -e '.signature_valid == true' >/dev/null 2>&1; then
  pass "Schnorr signature valid (pre-migration baseline)"
else
  fail "Pre-migration signature" "${ATTEST2:0:120}"
fi

# Test 17: Attestation binding (pubkey → UserData in attestation doc).
# Verifies the full chain: X-Attestation-Pubkey signs responses, and
# SHA256(pubkey) is bound to the NSM attestation document via UserData.
echo "[17/28] Attestation binding (pubkey → UserData)"
BINDING_RESP=$($CURL "${BASE_URL}/test/attestation-binding" 2>/dev/null || echo "")
if [ -n "$BINDING_RESP" ] && echo "$BINDING_RESP" | jq -e '.binding_valid == true' >/dev/null 2>&1; then
  pass "Attestation pubkey bound to NSM document (SHA256(pubkey) == UserData)"
else
  fail "Attestation binding" "${BINDING_RESP:0:120}"
fi

# --- Log tests ---
# The test app POSTs logs to the supervisor. We verify the full pipeline
# by reading them back through the management server's /logs endpoint.
SUPERVISOR_URL="http://localhost:${SUPERVISOR_PORT}"

# Test 20: Log POST (app → supervisor) + GET via supervisor.
echo "[18/28] Log round-trip via supervisor"
# First, have the test app POST log entries to the supervisor.
LOG_POST=$($CURL "${BASE_URL}/test/logs" 2>/dev/null || echo "")
if [ -z "$LOG_POST" ] || ! echo "$LOG_POST" | jq -e '.post == "ok"' >/dev/null 2>&1; then
  fail "Log POST" "test app failed to post logs: ${LOG_POST:0:120}"
else
  # Now GET logs via the supervisor (full pipeline: app → supervisor → supervisor).
  LOG_GET=$(curl -s --max-time 10 "${SUPERVISOR_URL}/enclave-logs" 2>/dev/null)
  if [ -z "$LOG_GET" ]; then LOG_GET="[]"; fi
  LOG_FOUND=$(echo "$LOG_GET" | jq '[.[] | select(.message == "integration test log" or .message == "batch entry 1" or .message == "batch entry 2")] | length' 2>/dev/null || echo "0")
  LOG_TOTAL=$(echo "$LOG_GET" | jq 'length' 2>/dev/null || echo "0")
  if [ "$LOG_FOUND" -ge 3 ]; then
    pass "Log round-trip via supervisor (found=$LOG_FOUND, total=$LOG_TOTAL)"
  else
    fail "Log round-trip via supervisor" "expected >= 3 entries, found $LOG_FOUND (total=$LOG_TOTAL)"
  fi
fi

# Test 21: Log level filtering via supervisor.
echo "[19/28] Log level filtering via supervisor"
LOG_FILTERED=$(curl -s --max-time 10 "${SUPERVISOR_URL}/enclave-logs?level=warn" 2>/dev/null)
if [ -z "$LOG_FILTERED" ]; then LOG_FILTERED="[]"; fi
FILTERED_COUNT=$(echo "$LOG_FILTERED" | jq 'length' 2>/dev/null || echo "0")
ALL_ABOVE_WARN=$(echo "$LOG_FILTERED" | jq 'all(.level == "warn" or .level == "error")' 2>/dev/null || echo "false")
if [ "$FILTERED_COUNT" -ge 2 ] && [ "$ALL_ABOVE_WARN" = "true" ]; then
  pass "Log level filter works via supervisor (filtered=$FILTERED_COUNT, all>=warn)"
else
  fail "Log level filtering" "filtered=$FILTERED_COUNT, all_above_warn=$ALL_ABOVE_WARN"
fi

# Test 22: Log POST requires auth token.
echo "[20/28] Log auth enforcement"
if [ -n "$LOG_POST" ] && echo "$LOG_POST" | jq -e '.auth_enforced == true' >/dev/null 2>&1; then
  pass "Log POST requires auth (401 without token)"
else
  fail "Log auth enforcement" "${LOG_POST:0:120}"
fi

# Test 23: CloudWatch Logs history (supervisor ships logs → supervisor queries CloudWatch).
echo "[21/28] CloudWatch Logs log history"
# Wait for the supervisor's log shipper to flush (5s interval + margin).
sleep 8
CW_HISTORY=$(curl -s --max-time 10 "${SUPERVISOR_URL}/enclave-logs?history=true" 2>/dev/null)
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
# supervisor's /v1/traces buffer via the supervisor proxy.

# Test 24: Make a request to trigger app spans, then verify via supervisor /enclave-traces.
echo "[22/28] App trace spans via supervisor"
# Make a request to the app — otelhttp creates a span, handleRoot creates a child.
$CURL "${BASE_URL}/" >/dev/null 2>&1
# OTEL batcher flushes every 5s by default. Wait for it.
sleep 7
SPAN_GET=$(curl -sf --max-time 10 "${SUPERVISOR_URL}/enclave-traces" 2>/dev/null || echo "[]")
SPAN_ROOT=$(echo "$SPAN_GET" | jq '[.[] | select(.name == "GET /" and .source == "app")] | length' 2>/dev/null || echo "0")
SPAN_CHILD=$(echo "$SPAN_GET" | jq '[.[] | select(.name == "handleRoot.work" and .source == "app")] | length' 2>/dev/null || echo "0")
SPAN_TOTAL=$(echo "$SPAN_GET" | jq 'length' 2>/dev/null || echo "0")
if [ "$SPAN_ROOT" -ge 1 ] && [ "$SPAN_CHILD" -ge 1 ]; then
  pass "App trace spans (root=$SPAN_ROOT, child=$SPAN_CHILD, total=$SPAN_TOTAL)"
else
  fail "App trace spans" "root=$SPAN_ROOT child=$SPAN_CHILD (total=$SPAN_TOTAL, first_200=${SPAN_GET:0:200})"
fi

# Test 25: Supervisor spans present (init stages).
echo "[23/28] Supervisor init spans"
SUP_SPANS=$(echo "$SPAN_GET" | jq '[.[] | select(.source == "supervisor")] | length' 2>/dev/null || echo "0")
INIT_SPAN=$(echo "$SPAN_GET" | jq '[.[] | select(.name == "init" and .source == "supervisor")] | length' 2>/dev/null || echo "0")
if [ "$SUP_SPANS" -ge 1 ] && [ "$INIT_SPAN" -ge 1 ]; then
  pass "Supervisor init spans (supervisor=$SUP_SPANS, init=$INIT_SPAN)"
else
  fail "Supervisor init spans" "supervisor=$SUP_SPANS init=$INIT_SPAN"
fi

# Test 26: App and supervisor spans share the buffer.
echo "[24/28] Mixed app + supervisor spans in buffer"
APP_SPANS=$(echo "$SPAN_GET" | jq '[.[] | select(.source == "app")] | length' 2>/dev/null || echo "0")
if [ "$APP_SPANS" -ge 2 ] && [ "$SUP_SPANS" -ge 1 ]; then
  pass "Mixed spans (app=$APP_SPANS, supervisor=$SUP_SPANS, total=$SPAN_TOTAL)"
else
  fail "Mixed spans" "app=$APP_SPANS supervisor=$SUP_SPANS total=$SPAN_TOTAL"
fi

# --- Metrics tests ---

# Test 27: Metric snapshot via supervisor.
echo "[25/28] Metric snapshot via supervisor"
# Wait for runtime collector + OTEL metric batcher to flush.
sleep 7
METRIC_GET=$(curl -s --max-time 10 "${SUPERVISOR_URL}/enclave-metrics" 2>/dev/null)
if [ -z "$METRIC_GET" ]; then METRIC_GET="{}"; fi
HAS_SUPERVISOR=$(echo "$METRIC_GET" | jq 'has("supervisor")' 2>/dev/null || echo "false")
HAS_RUNTIME=$(echo "$METRIC_GET" | jq 'has("runtime")' 2>/dev/null || echo "false")
if [ "$HAS_SUPERVISOR" = "true" ] && [ "$HAS_RUNTIME" = "true" ]; then
  pass "Metric snapshot has supervisor + runtime sections"
else
  fail "Metric snapshot" "supervisor=$HAS_SUPERVISOR runtime=$HAS_RUNTIME (body=${METRIC_GET:0:200})"
fi

# Test 28: Supervisor counters present in snapshot.
echo "[26/28] Supervisor metric counters"
HTTP_REQ=$(echo "$METRIC_GET" | jq '.supervisor.http_requests_total // 0' 2>/dev/null || echo "0")
if [ "$HTTP_REQ" -ge 1 ]; then
  pass "Supervisor http_requests_total=$HTTP_REQ"
else
  fail "Supervisor counters" "http_requests_total=$HTTP_REQ"
fi

# Test 29: Runtime metrics present (goroutines, heap).
echo "[27/28] Runtime metrics"
GOROUTINES=$(echo "$METRIC_GET" | jq '.runtime.goroutines // 0' 2>/dev/null || echo "0")
HEAP=$(echo "$METRIC_GET" | jq '.runtime.heap_alloc_bytes // 0' 2>/dev/null || echo "0")
if [ "$GOROUTINES" -ge 1 ] && [ "$HEAP" -ge 1 ]; then
  pass "Runtime metrics (goroutines=$GOROUTINES, heap=$HEAP)"
else
  fail "Runtime metrics" "goroutines=$GOROUTINES heap=$HEAP"
fi

# Test 30: Attestation still works after all tests (NSM stability).
echo "[28/33] Attestation stability check"
PCR_RESP2=$($CURL "${BASE_URL}/test/pcr-secrets" 2>/dev/null || echo "")
if [ -n "$PCR_RESP2" ] && echo "$PCR_RESP2" | jq -e '.status == "ok"' >/dev/null 2>&1; then
  pass "Attestation stable after all tests"
else
  fail "Attestation stability" "${PCR_RESP2:0:120}"
fi

# --- HTTP/2 + gRPC tests ---
#
# End-to-end HTTP/2 + gRPC through nitriding (TLS edge, h2 via ALPN) ->
# runtime proxy (h2c via http2.Transport{AllowHTTP:true}) -> test app (h2c
# unified handler routing gRPC vs REST).
# Issue: https://github.com/ArkLabsHQ/enclave/issues/85
GRPC_HOST="localhost:${HOST_TLS_PORT}"
GRPCURL="grpcurl -insecure -max-time 30 -authority test"

# Test 29: HTTP/2 negotiated end-to-end via ALPN.
echo "[29/33] HTTP/2 ALPN negotiation"
H2_OUT=$(curl -sk --http2 -o /dev/null -w '%{http_version}' --max-time 10 \
  "${BASE_URL}/health" 2>/dev/null || echo "")
if [ "$H2_OUT" = "2" ]; then
  pass "ALPN negotiated h2 (http_version=$H2_OUT)"
else
  fail "HTTP/2 negotiation" "expected http_version=2, got '$H2_OUT'"
fi

# Test 30: HTTP/1.1 still works (backward compatibility).
echo "[30/33] HTTP/1.1 backward compatibility"
H1_OUT=$(curl -sk --http1.1 -o /dev/null -w '%{http_version}' --max-time 10 \
  "${BASE_URL}/health" 2>/dev/null || echo "")
if [ "$H1_OUT" = "1.1" ]; then
  pass "HTTP/1.1 still serves /health (http_version=$H1_OUT)"
else
  fail "HTTP/1.1 compat" "expected http_version=1.1, got '$H1_OUT'"
fi

# Test 31: gRPC unary — grpc.health.v1.Health/Check returns SERVING.
echo "[31/33] gRPC unary (Health/Check)"
HEALTH_OUT=$($GRPCURL "$GRPC_HOST" grpc.health.v1.Health/Check 2>&1 || echo "")
if echo "$HEALTH_OUT" | grep -q '"status": "SERVING"'; then
  pass "gRPC unary returns SERVING"
else
  fail "gRPC unary" "${HEALTH_OUT:0:200}"
fi

# Test 32: gRPC server-streaming — grpc.health.v1.Health/Watch yields >=1
# message within 5s and the stream is not severed prematurely.
echo "[32/33] gRPC server-streaming (Health/Watch)"
WATCH_OUT=$(grpcurl -insecure -max-time 6 -authority test \
  "$GRPC_HOST" grpc.health.v1.Health/Watch 2>&1 || true)
WATCH_COUNT=$(echo "$WATCH_OUT" | grep -c '"status": "SERVING"' || true)
if [ "$WATCH_COUNT" -ge 1 ]; then
  pass "gRPC streaming delivered $WATCH_COUNT SERVING message(s)"
else
  fail "gRPC streaming" "no SERVING messages received: ${WATCH_OUT:0:200}"
fi

# Test 33: gRPC bypasses response-signing middleware. Native gRPC requests
# must NOT get X-Attestation-Signature — that would imply buffering, which
# breaks streaming. Use curl to shape an HTTP/2 request like gRPC and check
# response headers.
echo "[33/33] gRPC bypasses response-signing middleware"
GRPC_HDRS=$(curl -sk --http2 -D - -o /dev/null --max-time 10 \
  -H 'Content-Type: application/grpc' \
  -X POST "${BASE_URL}/grpc.health.v1.Health/Check" 2>/dev/null || echo "")
if echo "$GRPC_HDRS" | grep -qi '^x-attestation-signature:'; then
  fail "gRPC middleware bypass" "X-Attestation-Signature header present on gRPC response"
else
  pass "no X-Attestation-Signature on gRPC response (bypass active)"
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed (of $TOTAL) ==="

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
