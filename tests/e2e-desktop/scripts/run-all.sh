#!/usr/bin/env bash
set -euo pipefail

# run-all.sh -- Orchestrate the full desktop E2E test suite.
#
# Runs wait-for-mount, FUSE file I/O tests, and API round-trip tests.
# Reports an aggregate pass/fail summary and exits with the total failure count.
#
# Environment:
#   MOUNT_POINT   Path to FUSE mount (default: $HOME/CipherBox)
#   API_URL       Backend API URL (default: http://localhost:3000)
#   TEST_SECRET   test-login shared secret (default: e2e-test-secret-ci-only)

MOUNT_POINT="${MOUNT_POINT:-$HOME/CipherBox}"
API_URL="${API_URL:-http://localhost:3000}"
TEST_SECRET="${TEST_SECRET:-e2e-test-secret-ci-only}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TOTAL_PASS=0
TOTAL_FAIL=0

echo "============================================"
echo "  CipherBox Desktop E2E Test Suite"
echo "============================================"
echo ""
echo "Mount point: $MOUNT_POINT"
echo "API URL:     $API_URL"
echo ""

# ---- Step 1: Wait for mount ----
echo "--- Step 1: Wait for mount ---"
if bash "$SCRIPT_DIR/wait-for-mount.sh" "$MOUNT_POINT"; then
  TOTAL_PASS=$((TOTAL_PASS + 1))
else
  echo "FATAL: Mount not available. Cannot continue."
  exit 1
fi
echo ""

# ---- Step 2: FUSE file operations ----
echo "--- Step 2: FUSE file operations ---"
set +e
bash "$SCRIPT_DIR/test-fuse-operations.sh" "$MOUNT_POINT"
FUSE_FAILURES=$?
set -e

if [ "$FUSE_FAILURES" -eq 0 ]; then
  echo "FUSE operations: ALL PASSED"
else
  echo "FUSE operations: $FUSE_FAILURES FAILURE(S)"
  TOTAL_FAIL=$((TOTAL_FAIL + FUSE_FAILURES))
fi
echo ""

# ---- Step 3: API round-trip ----
echo "--- Step 3: API round-trip ---"
set +e
TEST_SECRET="$TEST_SECRET" bash "$SCRIPT_DIR/test-round-trip.sh" "$MOUNT_POINT" "$API_URL"
RT_FAILURES=$?
set -e

if [ "$RT_FAILURES" -eq 0 ]; then
  echo "API round-trip: ALL PASSED"
else
  echo "API round-trip: $RT_FAILURES FAILURE(S)"
  TOTAL_FAIL=$((TOTAL_FAIL + RT_FAILURES))
fi
echo ""

# ---- Summary ----
echo "============================================"
echo "  Summary"
echo "============================================"
echo "  Total failures: $TOTAL_FAIL"
echo "============================================"

exit "$TOTAL_FAIL"
