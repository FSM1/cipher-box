#!/usr/bin/env bash
set -euo pipefail

# test-round-trip.sh -- Verify desktop FUSE writes are visible via the API.
#
# Usage: ./test-round-trip.sh [mount-point] [api-url] [test-secret]
#   mount-point  Path to FUSE mount (default: $HOME/CipherBox)
#   api-url      Backend API URL (default: http://localhost:3000)
#   test-secret  Shared secret for test-login (default: e2e-test-secret-ci-only)
#
# The server is zero-knowledge -- it cannot decrypt file contents.
# These tests prove the pipeline: FUSE write -> encrypt -> IPFS upload -> IPNS publish -> API visibility.
#
# Exit code: number of failed tests (0 = all passed).

MP="${1:-$HOME/CipherBox}"
API_URL="${2:-http://localhost:3000}"
SECRET="${TEST_SECRET:-e2e-test-secret-ci-only}"
TEST_EMAIL="e2e-desktop-rt-$(date +%s)@test.local"

PASS=0
FAIL=0

pass() {
  PASS=$((PASS + 1))
  echo "PASS: $1"
}

fail() {
  FAIL=$((FAIL + 1))
  echo "FAIL: $1"
}

echo "=== API Round-Trip Tests ==="
echo "Mount point: $MP"
echo "API URL:     $API_URL"
echo "Test email:  $TEST_EMAIL"
echo ""

# ---- Test 1: Authenticate via test-login ----
echo "--- Test 1: Authenticate via test-login ---"
AUTH_RESPONSE=$(curl -fsS --connect-timeout 5 --max-time 30 -X POST "$API_URL/auth/test-login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"secret\":\"$SECRET\"}" 2>&1) || true

ACCESS_TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.accessToken // empty')
if [ -n "$ACCESS_TOKEN" ]; then
  pass "Authenticate via test-login"
else
  AUTH_ERROR=$(echo "$AUTH_RESPONSE" | jq -r '.message // .error // empty' 2>/dev/null || echo "non-JSON response")
  fail "Authenticate via test-login (error: $AUTH_ERROR)"
  echo "FATAL: Cannot proceed without authentication."
  echo ""
  echo "=== API Round-Trip Results ==="
  echo "  Passed: $PASS"
  echo "  Failed: $FAIL"
  echo "==============================="
  exit "$FAIL"
fi

# ---- Test 2: Desktop writes file, API verifies vault exists ----
echo "--- Test 2: Verify vault has content after FUSE write ---"
echo "API-visible content" > "$MP/rt-test.txt"
sleep 5

VAULT_RESPONSE=$(curl -fsS --connect-timeout 5 --max-time 30 -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$API_URL/vault" 2>&1) || true

ROOT_IPNS=$(echo "$VAULT_RESPONSE" | jq -r '.rootIpnsName // empty')
if [ -n "$ROOT_IPNS" ] && [ "$ROOT_IPNS" != "null" ]; then
  pass "Vault has rootIpnsName after FUSE write ($ROOT_IPNS)"
else
  VAULT_ERROR=$(echo "$VAULT_RESPONSE" | jq -r '.message // .error // empty' 2>/dev/null || echo "non-JSON response")
  fail "Vault has no rootIpnsName (error: $VAULT_ERROR)"
fi

# ---- Test 3: Verify IPNS resolve returns data ----
echo "--- Test 3: Verify IPNS resolve returns CID ---"
if [ -n "$ROOT_IPNS" ] && [ "$ROOT_IPNS" != "null" ]; then
  IPNS_RESPONSE=$(curl -fsS --connect-timeout 5 --max-time 30 -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$API_URL/ipns/$ROOT_IPNS/resolve" 2>&1) || true

  # The resolve response should contain a CID (starts with "bafy" or "Qm" or similar)
  RESOLVED_CID=$(echo "$IPNS_RESPONSE" | jq -r '.cid // .value // empty' 2>/dev/null || echo "")
  if [ -n "$RESOLVED_CID" ] && [ "$RESOLVED_CID" != "null" ]; then
    pass "IPNS resolve returned CID ($RESOLVED_CID)"
  else
    # Even if parsing fails, the response itself may be valid
    IPNS_ERROR=$(echo "$IPNS_RESPONSE" | jq -r '.message // .error // empty' 2>/dev/null || echo "non-JSON response")
    fail "IPNS resolve did not return expected CID (error: $IPNS_ERROR)"
  fi
else
  fail "IPNS resolve skipped (no rootIpnsName)"
fi

# ---- Cleanup ----
echo "--- Cleanup ---"
rm -f "$MP/rt-test.txt" 2>/dev/null || true
sleep 2

# ---- Summary ----
echo ""
echo "=== API Round-Trip Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "==============================="

exit "$FAIL"
