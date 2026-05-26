#!/usr/bin/env bash
set -uo pipefail

# test-fuse-operations.sh -- Exercise FUSE mount file I/O operations.
#
# Usage: ./test-fuse-operations.sh [mount-point]
#   mount-point  Path to FUSE mount (default: $HOME/CipherBox)
#
# Tests: create, read, overwrite, mkdir, nested write, binary round-trip,
#        rename file, rename directory, move file across directories,
#        delete file, delete directory.
#
# Exit code: number of failed tests (0 = all passed).

MP="${1:-$HOME/CipherBox}"
PASS=0
FAIL=0

# Detect SHA-256 command (macOS vs Linux)
if command -v shasum &>/dev/null; then
  SHA256_CMD="shasum -a 256"
elif command -v sha256sum &>/dev/null; then
  SHA256_CMD="sha256sum"
else
  echo "FAIL: No SHA-256 command found (shasum or sha256sum)"
  exit 1
fi

pass() {
  PASS=$((PASS + 1))
  echo "PASS: $1"
}

fail() {
  FAIL=$((FAIL + 1))
  echo "FAIL: $1"
}

echo "=== FUSE File I/O Tests ==="
echo "Mount point: $MP"
echo ""

# ---- Test 1: Create and read text file ----
echo "--- Test 1: Create and read text file ---"
echo "Hello from CI" > "$MP/e2e-test.txt"
sleep 3
CONTENT=$(cat "$MP/e2e-test.txt")
if [ "$CONTENT" = "Hello from CI" ]; then
  pass "Create and read text file"
else
  fail "Create and read text file (got: '$CONTENT')"
fi

# ---- Test 2: Create directory ----
echo "--- Test 2: Create directory ---"
mkdir -p "$MP/e2e-folder"
if [ -d "$MP/e2e-folder" ]; then
  pass "Create directory"
else
  fail "Create directory"
fi

# ---- Test 3: Write file in subdirectory ----
echo "--- Test 3: Write file in subdirectory ---"
echo "Nested content" > "$MP/e2e-folder/nested.txt"
sleep 3
NESTED=$(cat "$MP/e2e-folder/nested.txt")
if [ "$NESTED" = "Nested content" ]; then
  pass "Write file in subdirectory"
else
  fail "Write file in subdirectory (got: '$NESTED')"
fi

# ---- Test 4: Overwrite file (modify) ----
echo "--- Test 4: Overwrite file ---"
echo "Modified content" > "$MP/e2e-test.txt"
sleep 3
MODIFIED=$(cat "$MP/e2e-test.txt")
if [ "$MODIFIED" = "Modified content" ]; then
  pass "Overwrite file"
else
  fail "Overwrite file (got: '$MODIFIED')"
fi

# ---- Test 5: Binary file round-trip ----
echo "--- Test 5: Binary file round-trip ---"
dd if=/dev/urandom of=/tmp/e2e-binary.bin bs=1024 count=256 2>/dev/null
cp /tmp/e2e-binary.bin "$MP/e2e-binary.bin"
sleep 5
CHECKSUM_ORIG=$($SHA256_CMD /tmp/e2e-binary.bin | cut -d' ' -f1)
CHECKSUM_MOUNT=$($SHA256_CMD "$MP/e2e-binary.bin" | cut -d' ' -f1)
if [ "$CHECKSUM_ORIG" = "$CHECKSUM_MOUNT" ]; then
  pass "Binary file round-trip (256KB)"
else
  fail "Binary file round-trip (orig: $CHECKSUM_ORIG, mount: $CHECKSUM_MOUNT)"
fi

# ---- Test 6: Rename file ----
echo "--- Test 6: Rename file ---"
mv "$MP/e2e-test.txt" "$MP/e2e-renamed.txt"
sleep 2
if [ ! -f "$MP/e2e-test.txt" ] && [ -f "$MP/e2e-renamed.txt" ]; then
  RENAMED=$(cat "$MP/e2e-renamed.txt")
  if [ "$RENAMED" = "Modified content" ]; then
    pass "Rename file"
  else
    fail "Rename file (content changed: '$RENAMED')"
  fi
else
  fail "Rename file (old exists: $(test -f "$MP/e2e-test.txt" && echo yes || echo no), new exists: $(test -f "$MP/e2e-renamed.txt" && echo yes || echo no))"
fi

# ---- Test 6b: Rename directory ----
echo "--- Test 6b: Rename directory ---"
mv "$MP/e2e-folder" "$MP/e2e-folder-renamed"
sleep 2
if [ ! -d "$MP/e2e-folder" ] && [ -d "$MP/e2e-folder-renamed" ]; then
  # Verify nested content is still accessible
  NESTED_AFTER=$(cat "$MP/e2e-folder-renamed/nested.txt")
  if [ "$NESTED_AFTER" = "Nested content" ]; then
    pass "Rename directory (with nested content preserved)"
  else
    fail "Rename directory (nested content changed: '$NESTED_AFTER')"
  fi
else
  fail "Rename directory (old exists: $(test -d "$MP/e2e-folder" && echo yes || echo no), new exists: $(test -d "$MP/e2e-folder-renamed" && echo yes || echo no))"
fi

# ---- Test 6c: Move file across directories ----
echo "--- Test 6c: Move file across directories ---"
mkdir -p "$MP/e2e-dest-folder"
mv "$MP/e2e-folder-renamed/nested.txt" "$MP/e2e-dest-folder/nested.txt"
sleep 2
if [ ! -f "$MP/e2e-folder-renamed/nested.txt" ] && [ -f "$MP/e2e-dest-folder/nested.txt" ]; then
  MOVED=$(cat "$MP/e2e-dest-folder/nested.txt")
  if [ "$MOVED" = "Nested content" ]; then
    pass "Move file across directories"
  else
    fail "Move file across directories (content changed: '$MOVED')"
  fi
else
  fail "Move file across directories (source exists: $(test -f "$MP/e2e-folder-renamed/nested.txt" && echo yes || echo no), dest exists: $(test -f "$MP/e2e-dest-folder/nested.txt" && echo yes || echo no))"
fi

# ---- Test 7: Delete file ----
echo "--- Test 7: Delete file ---"
rm "$MP/e2e-renamed.txt"
sleep 2
if [ ! -f "$MP/e2e-renamed.txt" ]; then
  pass "Delete file"
else
  fail "Delete file (still exists)"
fi

# ---- Test 8: Delete directories ----
echo "--- Test 8: Delete directories ---"
rm -rf "$MP/e2e-dest-folder"
rm -rf "$MP/e2e-folder-renamed"
sleep 2
if [ ! -d "$MP/e2e-dest-folder" ] && [ ! -d "$MP/e2e-folder-renamed" ]; then
  pass "Delete directories"
else
  fail "Delete directories (e2e-dest-folder exists: $(test -d "$MP/e2e-dest-folder" && echo yes || echo no), e2e-folder-renamed exists: $(test -d "$MP/e2e-folder-renamed" && echo yes || echo no))"
fi

# ---- Test 9: Cleanup ----
echo "--- Test 9: Cleanup ---"
rm -f "$MP/e2e-binary.bin" 2>/dev/null || true
rm -f /tmp/e2e-binary.bin 2>/dev/null || true
# Filter .DS_Store from any remaining file checks
REMAINING=$(ls "$MP" 2>/dev/null | grep -v '\.DS_Store' | grep -v '^$' || true)
if [ -z "$REMAINING" ]; then
  pass "Cleanup (mount point clean)"
else
  # Not a hard failure -- other files may be present from the desktop app
  pass "Cleanup (remaining files: $REMAINING)"
fi

# ---- Summary ----
echo ""
echo "=== FUSE File I/O Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo "=============================="

exit "$FAIL"
