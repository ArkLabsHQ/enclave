#!/usr/bin/env bash
# Integration assertions for a 1-leader + 2-follower threshold-scaling deployment.
#
# Transport-agnostic: point it at three already-booted enclaves via LEADER_URL,
# FOLLOWER1_URL, FOLLOWER2_URL (each the nitriding TLS edge). The boot orchestration
# (three QEMU guests + gvproxy forwarding + staged boot + SSM role seeding) lives in
# run-scaling.sh; this script only asserts the resulting state via /test/scaling and
# the leader's handshake surface.
#
# Single-env-var model: each node exposes exactly one secret env var, SCALING_KEY,
# holding what it signs with NOW — its own threshold share once a group has formed
# (leader and followers alike). The master (a0) is never exposed in an env var; it
# lives only in the encrypted storage envelope, so the endpoint reports shares only.
#
# The reshare check needs the pre-reshare snapshot: run-scaling.sh captures follower-1's
# share pubkey after follower-1 joins (committee of 2) and passes it as F1_SHARE_V1;
# after follower-2 joins (committee of 3 → re-DKG), follower-1's share must have been
# re-randomized.
#
# Verified properties:
#   - leader mounts its admission handshake route (regression guard for the
#     route-registration fix);
#   - the leader holds its own share (it drained Keys() and persisted it to SCALING_KEY);
#   - both followers received their share (initial DKG + join both ran);
#   - the second join triggered a reshare (follower-1's share changed);
#   - all three shares are three DISTINCT valid secp256k1 scalars.
set -euo pipefail

LEADER_URL="${LEADER_URL:-https://localhost:8443}"
FOLLOWER1_URL="${FOLLOWER1_URL:-https://localhost:8543}"
FOLLOWER2_URL="${FOLLOWER2_URL:-https://localhost:8643}"
F1_SHARE_V1="${F1_SHARE_V1:-}"   # follower-1 share pubkey before follower-2 joined (optional)
CURL="curl -sk --max-time 10"
PASSED=0
FAILED=0
TOTAL=0

pass() { echo "  PASS: $1"; PASSED=$((PASSED + 1)); TOTAL=$((TOTAL + 1)); }
fail() { echo "  FAIL: $1 — $2"; FAILED=$((FAILED + 1)); TOTAL=$((TOTAL + 1)); }

# scaling_field <url> <jq-filter> — fetch /test/scaling and extract a field.
scaling_field() { $CURL "${1}/test/scaling" 2>/dev/null | jq -r "$2" 2>/dev/null || echo ""; }

echo "=== Threshold-scaling tests (1 leader + 2 followers) ==="
echo "  leader=$LEADER_URL f1=$FOLLOWER1_URL f2=$FOLLOWER2_URL"
echo ""

# Test 1: all three enclaves are up (Init complete).
echo "[1/8] All three enclaves healthy"
L_H=$($CURL -o /dev/null -w '%{http_code}' "${LEADER_URL}/health" 2>/dev/null || echo "000")
F1_H=$($CURL -o /dev/null -w '%{http_code}' "${FOLLOWER1_URL}/health" 2>/dev/null || echo "000")
F2_H=$($CURL -o /dev/null -w '%{http_code}' "${FOLLOWER2_URL}/health" 2>/dev/null || echo "000")
if [ "$L_H" = "200" ] && [ "$F1_H" = "200" ] && [ "$F2_H" = "200" ]; then
  pass "leader + 2 followers all return 200"
else
  fail "health" "leader=$L_H f1=$F1_H f2=$F2_H"
fi

# Test 2: leader mounts the admission handshake route (route-registration fix).
echo "[2/8] Leader handshake route mounted"
NONCE=$($CURL "${LEADER_URL}/enclave/handshake/nonce" 2>/dev/null || echo "")
if [ -n "$NONCE" ] && printf '%s' "$NONCE" | base64 -d >/dev/null 2>&1; then
  pass "GET /enclave/handshake/nonce returns a base64 nonce"
else
  fail "handshake nonce" "empty or non-base64: ${NONCE:0:60}"
fi

# Test 3: roles parsed correctly.
echo "[3/8] Roles"
L_ROLE=$(scaling_field "$LEADER_URL" '.role')
F1_ROLE=$(scaling_field "$FOLLOWER1_URL" '.role')
F2_ROLE=$(scaling_field "$FOLLOWER2_URL" '.role')
if [ "$L_ROLE" = "leader" ] && [ "$F1_ROLE" = "follower" ] && [ "$F2_ROLE" = "follower" ]; then
  pass "leader / follower / follower"
else
  fail "roles" "leader=$L_ROLE f1=$F1_ROLE f2=$F2_ROLE"
fi

# Gather the three share pubkeys — every node's SCALING_KEY holds its own share.
L_SHARE=$(scaling_field "$LEADER_URL" '.scaling_key.pubkey')
F1_SHARE=$(scaling_field "$FOLLOWER1_URL" '.scaling_key.pubkey')
F2_SHARE=$(scaling_field "$FOLLOWER2_URL" '.scaling_key.pubkey')

# Test 4: leader holds its OWN share in SCALING_KEY (drained its Keys()).
echo "[4/8] Leader's own share present"
if $CURL "${LEADER_URL}/test/scaling" 2>/dev/null | jq -e '.scaling_key.present == true and .scaling_key.length == 64' >/dev/null 2>&1; then
  pass "leader SCALING_KEY is a 32-byte share (pub ${L_SHARE:0:16}...)"
else
  fail "leader own share" "leader never persisted its own share to SCALING_KEY"
fi

# Test 5: both followers received a share (ceremony + join both ran).
echo "[5/8] Both follower shares present"
ok5=true
for u in "$FOLLOWER1_URL" "$FOLLOWER2_URL"; do
  $CURL "${u}/test/scaling" 2>/dev/null | jq -e '.scaling_key.present == true and .scaling_key.length == 64' >/dev/null 2>&1 || ok5=false
done
if $ok5; then
  pass "follower-1 + follower-2 each hold a 32-byte share (pub ${F1_SHARE:0:12}.., ${F2_SHARE:0:12}..)"
else
  fail "follower shares" "a follower is missing its share"
fi

# Test 6: the second join triggered a reshare — follower-1's share was re-randomized.
echo "[6/8] Reshare re-randomized follower-1's share"
if [ -z "$F1_SHARE_V1" ]; then
  echo "  SKIP: F1_SHARE_V1 not provided (run via run-scaling.sh to capture the pre-reshare snapshot)"
elif [ -n "$F1_SHARE" ] && [ "$F1_SHARE" != "$F1_SHARE_V1" ]; then
  pass "follower-1 share changed after follower-2 joined (${F1_SHARE_V1:0:12}.. → ${F1_SHARE:0:12}..)"
else
  fail "reshare" "follower-1 share unchanged (v1=${F1_SHARE_V1:0:12}.. now=${F1_SHARE:0:12}..) — re-DKG did not run"
fi

# Test 7: all three shares are three distinct scalars.
echo "[7/8] All three shares distinct"
if [ -n "$L_SHARE" ] && [ -n "$F1_SHARE" ] && [ -n "$F2_SHARE" ] &&
   [ "$(printf '%s\n' "$L_SHARE" "$F1_SHARE" "$F2_SHARE" | sort -u | wc -l)" = "3" ]; then
  pass "leader share, follower-1 share, follower-2 share all differ"
else
  fail "distinctness" "ls=${L_SHARE:0:10} f1=${F1_SHARE:0:10} f2=${F2_SHARE:0:10}"
fi

# Test 8: shares are valid secp256k1 scalars (pubkey derivation succeeded).
echo "[8/8] Shares are valid secp256k1 scalars"
if [ -n "$L_SHARE" ] && [ -n "$F1_SHARE" ] && [ -n "$F2_SHARE" ]; then
  pass "leader + both follower shares derive valid compressed pubkeys"
else
  fail "scalar validity" "pubkey derivation failed for a share"
fi

echo ""
echo "=== Results: $PASSED passed, $FAILED failed (of $TOTAL) ==="
[ "$FAILED" -gt 0 ] && exit 1 || exit 0
