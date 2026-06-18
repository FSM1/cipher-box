#!/usr/bin/env bash
set -uo pipefail

# test-conflict-detection.sh -- Verify FUSE conflict detection and re-sync behavior.
#
# Usage: ./test-conflict-detection.sh [mount-point] [api-url]
#   mount-point  Path to FUSE mount (default: $HOME/CipherBox)
#   api-url      Backend API URL (default: http://localhost:3000)
#
# Environment:
#   TEST_SECRET  Shared secret for test-login (default: e2e-test-secret-ci-only)
#
# These tests verify that when the server-side IPNS sequence number is bumped
# (simulating another device publishing), the desktop detects the 409 conflict,
# re-syncs, and retries -- resulting in all files/directories being accessible.
#
# Exit code: number of failed tests (0 = all passed).

MP="${1:-$HOME/CipherBox}"
API_URL="${2:-http://localhost:3000}"
SECRET="${TEST_SECRET:-e2e-test-secret-ci-only}"
TEST_EMAIL="dev-key@cipherbox.local"

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

echo "=== Conflict Detection Tests ==="
echo "Mount point: $MP"
echo "API URL:     $API_URL"
echo "Test email:  $TEST_EMAIL"
echo ""

# ---- Setup: Authenticate via test-login ----
echo "--- Setup: Authenticate via test-login ---"
AUTH_RESPONSE=$(printf '{"email":"%s","secret":"%s"}' "$TEST_EMAIL" "$SECRET" | \
  curl -fsS --connect-timeout 5 --max-time 30 -X POST "$API_URL/auth/test-login" \
  -H "Content-Type: application/json" \
  --data-binary @- 2>&1) || true

ACCESS_TOKEN=$(echo "$AUTH_RESPONSE" | jq -r '.accessToken // empty')
if [ -z "$ACCESS_TOKEN" ]; then
  AUTH_ERROR=$(echo "$AUTH_RESPONSE" | jq -r '.message // .error // empty' 2>/dev/null || echo "non-JSON response")
  echo "FATAL: Authentication failed (error: $AUTH_ERROR)"
  echo ""
  echo "=== Conflict Detection Results ==="
  echo "  Passed: $PASS"
  echo "  Failed: $FAIL"
  echo "=================================="
  exit 1
fi
echo "  Authenticated successfully"

# ---- Setup: Get root IPNS name from vault ----
echo "--- Setup: Get root IPNS name from vault ---"
VAULT_RESPONSE=$(curl -fsS --connect-timeout 5 --max-time 30 \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$API_URL/vault" 2>&1) || true
ROOT_IPNS=$(echo "$VAULT_RESPONSE" | jq -r '.rootIpnsName // empty')

if [ -z "$ROOT_IPNS" ] || [ "$ROOT_IPNS" = "null" ]; then
  echo "FATAL: No rootIpnsName found in vault -- cannot test conflict detection without a published vault."
  echo "       Ensure the desktop app has made at least one FUSE write before running this test."
  echo ""
  echo "=== Conflict Detection Results ==="
  echo "  Passed: $PASS"
  echo "  Failed: $FAIL"
  echo "=================================="
  exit 1
fi
echo "  Root IPNS: $ROOT_IPNS"
echo ""

# ---- Helper: bump_server_sequence ----
# Advances the vault's root IPNS sequence with a REAL, validly-signed record.
# The server is signature-gated (it rejects records whose Ed25519 SignatureV2
# does not verify against the name's key), so a dummy unsigned record can no
# longer fake a bump. bump-ipns-sequence.mjs derives the deterministic vault IPNS
# keypair and republishes the current root metadata UNCHANGED at sequence+1 --
# exactly what a legitimate second device does -- making the desktop's cached
# sequence stale.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bump_server_sequence() {
  local ipns_name="$1"  # informational; the helper bumps the vault root via /vault

  if TEST_SECRET="$SECRET" node "$SCRIPT_DIR/bump-ipns-sequence.mjs" \
    --api-url "$API_URL" --email "$TEST_EMAIL"; then
    : # bump succeeded; sequence advanced for $ipns_name
  else
    echo "  WARNING: Failed to bump server sequence for $ipns_name"
  fi
}

# ---- Test 1: Write file via FUSE, bump server seq, write another file -> both readable ----
echo "--- Test 1: Write file, bump server sequence, write another file -> both readable ---"

# Step 1: Write first file and wait for FUSE debounce + publish
echo "file-before-bump" > "$MP/conflict-test-1.txt"
echo "  Wrote conflict-test-1.txt, waiting 8s for FUSE publish..."
sleep 8

# Step 2: Bump server sequence to make desktop's local sequence stale
echo "  Bumping server sequence..."
bump_server_sequence "$ROOT_IPNS"

# Step 3: Write second file -- the FUSE publish will get a 409, re-sync, and retry
echo "  Wrote conflict-test-2.txt, waiting 15s for conflict resolution + retry..."
echo "file-after-bump" > "$MP/conflict-test-2.txt"
sleep 15

# Step 4: Verify both files are readable
CONTENT1=$(cat "$MP/conflict-test-1.txt" 2>/dev/null || echo "")
CONTENT2=$(cat "$MP/conflict-test-2.txt" 2>/dev/null || echo "")

if [ "$CONTENT1" = "file-before-bump" ] && [ "$CONTENT2" = "file-after-bump" ]; then
  pass "Write file conflict: both files readable after re-sync and retry"
else
  if [ "$CONTENT1" != "file-before-bump" ]; then
    fail "Write file conflict: conflict-test-1.txt has unexpected content (got: '$CONTENT1')"
  else
    fail "Write file conflict: conflict-test-2.txt has unexpected content (got: '$CONTENT2')"
  fi
fi

# ---- Test 2: Create directory via FUSE, bump server seq, create file in dir -> both accessible ----
echo "--- Test 2: Create directory, bump server sequence, create file in dir -> both accessible ---"

# Step 1: Create directory and wait for FUSE publish
mkdir -p "$MP/conflict-dir"
echo "  Created conflict-dir, waiting 8s for FUSE publish..."
sleep 8

# Step 2: Bump server sequence
echo "  Bumping server sequence..."
bump_server_sequence "$ROOT_IPNS"

# Step 3: Write file in directory -- the mkdir publish will hit 409, re-sync, retry
echo "  Writing conflict-dir/nested.txt, waiting 15s for conflict resolution + retry..."
echo "nested-conflict-file" > "$MP/conflict-dir/nested.txt"
sleep 15

# Step 4: Verify directory exists and file is readable
DIR_EXISTS=false
[ -d "$MP/conflict-dir" ] && DIR_EXISTS=true

NESTED=$(cat "$MP/conflict-dir/nested.txt" 2>/dev/null || echo "")

if $DIR_EXISTS && [ "$NESTED" = "nested-conflict-file" ]; then
  pass "Directory conflict: dir exists and nested file readable after re-sync and retry"
else
  if ! $DIR_EXISTS; then
    fail "Directory conflict: conflict-dir does not exist after re-sync"
  else
    fail "Directory conflict: nested.txt has unexpected content (got: '$NESTED')"
  fi
fi

# ---- Cleanup ----
echo "--- Cleanup ---"
rm -f "$MP/conflict-test-1.txt" "$MP/conflict-test-2.txt" 2>/dev/null || true
rm -rf "$MP/conflict-dir" 2>/dev/null || true
sleep 3

# ---- Summary ----
echo ""
echo "=== Conflict Detection Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "=================================="

exit "$FAIL"
