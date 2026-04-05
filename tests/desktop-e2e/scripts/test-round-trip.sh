#!/usr/bin/env bash
set -euo pipefail

# test-round-trip.sh -- Verify desktop FUSE writes are visible via the API.
#
# Usage: ./test-round-trip.sh [mount-point] [api-url]
#   mount-point  Path to FUSE mount (default: $HOME/CipherBox)
#   api-url      Backend API URL (default: http://localhost:3000)
#
# Environment:
#   TEST_SECRET  Shared secret for test-login (default: e2e-test-secret-ci-only)
#
# The server is zero-knowledge -- it cannot decrypt file contents.
# These tests prove the pipeline: FUSE write -> encrypt -> IPFS upload -> IPNS publish -> API visibility.
#
# Exit code: number of failed tests (0 = all passed).

MP="${1:-$HOME/CipherBox}"
API_URL="${2:-http://localhost:3000}"
SECRET="${TEST_SECRET:-e2e-test-secret-ci-only}"
# Use the same email as the dev-key auth flow so we query the same user's vault
TEST_EMAIL="dev-key@cipherbox.local"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
TEST_FILE="rt-test-${RANDOM}.txt"
TEST_CONTENT="API-visible content"

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

ensure_verifier_runtime() {
  if [ -f "$REPO_ROOT/packages/sdk-core/dist/index.mjs" ] && [ -f "$REPO_ROOT/packages/api-client/dist/index.mjs" ]; then
    return
  fi

  pnpm --dir "$REPO_ROOT" --filter @cipherbox/crypto build
  pnpm --dir "$REPO_ROOT" --filter @cipherbox/core build
  pnpm --dir "$REPO_ROOT" --filter @cipherbox/api-client build
  pnpm --dir "$REPO_ROOT" --filter @cipherbox/sdk-core build
}

run_filepointer_verifier() {
  TEST_SECRET="$SECRET" node "$REPO_ROOT/packages/sdk-core/scripts/verify-filepointer.mjs" \
    --api-url "$API_URL" \
    --email "$TEST_EMAIL" \
    --file-name "$TEST_FILE" \
    --expected-content "$TEST_CONTENT"
}

echo "=== API Round-Trip Tests ==="
echo "Mount point: $MP"
echo "API URL:     $API_URL"
echo "Test email:  $TEST_EMAIL"
echo "Test file:   $TEST_FILE"
echo ""

ensure_verifier_runtime

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
printf '%s' "$TEST_CONTENT" > "$MP/$TEST_FILE"
# Force a FUSE readdir to drain upload completions — without this, the
# background upload finishes but the publish queue never flushes because
# no FUSE callbacks trigger drain_upload_completions() in CI.
sleep 2
ls "$MP" > /dev/null 2>&1 || true

ROOT_IPNS=""
for attempt in $(seq 1 24); do
  sleep 5
  VAULT_RESPONSE=$(curl -fsS --connect-timeout 5 --max-time 30 -H "Authorization: Bearer $ACCESS_TOKEN" \
    "$API_URL/vault" 2>&1) || true
  ROOT_IPNS=$(echo "$VAULT_RESPONSE" | jq -r '.rootIpnsName // empty' 2>/dev/null || echo "")
  if [ -n "$ROOT_IPNS" ] && [ "$ROOT_IPNS" != "null" ]; then
    break
  fi
  echo "  Vault poll attempt $attempt: no rootIpnsName yet"
  ROOT_IPNS=""
done

if [ -n "$ROOT_IPNS" ] && [ "$ROOT_IPNS" != "null" ]; then
  pass "Vault has rootIpnsName after FUSE write ($ROOT_IPNS)"
else
  VAULT_ERROR=$(echo "$VAULT_RESPONSE" | jq -r '.message // .error // empty' 2>/dev/null || echo "non-JSON response")
  fail "Vault has no rootIpnsName after 60s polling (error: $VAULT_ERROR)"
fi

# ---- Test 3: Verify FilePointer and per-file IPNS metadata resolve ----
echo "--- Test 3: Verify FilePointer and per-file IPNS metadata ---"
FILE_VERIFY_OUTPUT=""
FILE_VERIFY_OK=0
for attempt in $(seq 1 24); do
  sleep 5
  if FILE_VERIFY_OUTPUT=$(run_filepointer_verifier 2>&1); then
    FILE_VERIFY_OK=1
    break
  fi
  echo "  FilePointer verify attempt $attempt failed: $FILE_VERIFY_OUTPUT"
done

if [ "$FILE_VERIFY_OK" -eq 1 ]; then
  pass "FilePointer exists and per-file IPNS metadata resolves"
  echo "  $FILE_VERIFY_OUTPUT"
else
  fail "FilePointer/per-file IPNS verification failed after 120s"
fi

# ---- Test 4: Verify fresh client reload can still resolve file metadata ----
echo "--- Test 4: Verify fresh client reload resolves file metadata ---"
sleep 2
if RELOAD_OUTPUT=$(run_filepointer_verifier 2>&1); then
  pass "Fresh client reload resolves file metadata and content"
  echo "  $RELOAD_OUTPUT"
else
  fail "Fresh client reload failed to resolve file metadata ($RELOAD_OUTPUT)"
fi

# ---- Test 5: Verify IPNS resolve returns data ----
echo "--- Test 5: Verify IPNS resolve returns CID ---"
if [ -n "$ROOT_IPNS" ] && [ "$ROOT_IPNS" != "null" ]; then
  RESOLVED_CID=""
  for attempt in $(seq 1 24); do
    sleep 2
    IPNS_RESPONSE=$(curl -fsS --connect-timeout 5 --max-time 30 -H "Authorization: Bearer $ACCESS_TOKEN" \
      "$API_URL/ipns/resolve?ipnsName=$ROOT_IPNS" 2>&1) || true
    RESOLVED_CID=$(echo "$IPNS_RESPONSE" | jq -r '.cid // .value // empty' 2>/dev/null || echo "")
    if [ -n "$RESOLVED_CID" ] && [ "$RESOLVED_CID" != "null" ]; then
      break
    fi
    echo "  IPNS resolve attempt $attempt: no CID yet"
    RESOLVED_CID=""
  done

  if [ -n "$RESOLVED_CID" ] && [ "$RESOLVED_CID" != "null" ]; then
    pass "IPNS resolve returned CID ($RESOLVED_CID)"
  else
    IPNS_ERROR=$(echo "$IPNS_RESPONSE" | jq -r '.message // .error // empty' 2>/dev/null || echo "non-JSON response")
    fail "IPNS resolve did not return expected CID after 24s polling (error: $IPNS_ERROR)"
  fi
else
  fail "IPNS resolve skipped (no rootIpnsName)"
fi

# ---- Cleanup ----
echo "--- Cleanup ---"
rm -f "$MP/$TEST_FILE" 2>/dev/null || true
sleep 2

# ---- Summary ----
echo ""
echo "=== API Round-Trip Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "==============================="

exit "$FAIL"
