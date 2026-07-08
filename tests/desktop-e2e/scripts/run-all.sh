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

# ---- Step 4: Conflict detection ----
echo "--- Step 4: Conflict detection ---"
set +e
TEST_SECRET="$TEST_SECRET" bash "$SCRIPT_DIR/test-conflict-detection.sh" "$MOUNT_POINT" "$API_URL"
CONFLICT_FAILURES=$?
set -e

if [ "$CONFLICT_FAILURES" -eq 0 ]; then
  echo "Conflict detection: ALL PASSED"
else
  echo "Conflict detection: $CONFLICT_FAILURES FAILURE(S)"
  TOTAL_FAIL=$((TOTAL_FAIL + CONFLICT_FAILURES))
fi
echo ""

# ---- Step 5: Recycle bin ----
echo "--- Step 5: Recycle bin ---"
set +e
TEST_SECRET="$TEST_SECRET" bash "$SCRIPT_DIR/test-recycle-bin.sh" "$MOUNT_POINT" "$API_URL"
BIN_FAILURES=$?
set -e

if [ "$BIN_FAILURES" -eq 0 ]; then
  echo "Recycle bin: ALL PASSED"
else
  echo "Recycle bin: $BIN_FAILURES FAILURE(S)"
  TOTAL_FAIL=$((TOTAL_FAIL + BIN_FAILURES))
fi
echo ""

# ---- Step 6: Cross-client sync ----
echo "--- Step 6: Cross-client sync ---"
set +e
TEST_SECRET="$TEST_SECRET" bash "$SCRIPT_DIR/test-cross-client-sync.sh" "$MOUNT_POINT" "$API_URL"
SYNC_FAILURES=$?
set -e

if [ "$SYNC_FAILURES" -eq 0 ]; then
  echo "Cross-client sync: ALL PASSED"
else
  echo "Cross-client sync: $SYNC_FAILURES FAILURE(S)"
  TOTAL_FAIL=$((TOTAL_FAIL + SYNC_FAILURES))
fi
echo ""

# ---- Step 7: Move content re-encryption (cross-platform) ----
# Shares one implementation with Windows (test-move-content.ts); runs after
# cross-client-sync so the SDK dist it shells out to is already built.
echo "--- Step 7: Move content re-encryption ---"
set +e
TEST_SECRET="$TEST_SECRET" pnpm exec tsx "$SCRIPT_DIR/test-move-content.ts" --mount "$MOUNT_POINT" --api-url "$API_URL"
MOVE_FAILURES=$?
set -e

if [ "$MOVE_FAILURES" -eq 0 ]; then
  echo "Move content: PASSED"
else
  echo "Move content: FAILED"
  TOTAL_FAIL=$((TOTAL_FAIL + MOVE_FAILURES))
fi
echo ""

# ---- Step 8: Shared scope-exit rotation acceptance (D-16) ----
# Real-mount smoke for the FUSE shared-scope-exit rotation live-wiring
# (2026-07-07-fuse-shared-scope-exit-rotation-live-wiring.md / Phase 70.1
# SC#8). Invoked via node + tsx's JS CLI entry (NOT the node_modules/.bin/tsx
# shell shim) per project convention for .mts helpers.
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
echo "--- Step 8: Shared scope-exit rotation acceptance (D-16) ---"
set +e
TEST_SECRET="$TEST_SECRET" node "$REPO_ROOT/node_modules/tsx/dist/cli.mjs" \
  "$SCRIPT_DIR/shared-scope-exit-rotation.mts" --mount "$MOUNT_POINT" --api-url "$API_URL"
ROTATION_FAILURES=$?
set -e

if [ "$ROTATION_FAILURES" -eq 0 ]; then
  echo "Shared scope-exit rotation: PASSED"
else
  echo "Shared scope-exit rotation: FAILED"
  TOTAL_FAIL=$((TOTAL_FAIL + ROTATION_FAILURES))
fi
echo ""

# ---- Summary ----
echo "============================================"
echo "  Summary"
echo "============================================"
echo "  Total failures: $TOTAL_FAIL"
echo "============================================"

exit "$TOTAL_FAIL"
