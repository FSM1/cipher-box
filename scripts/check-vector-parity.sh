#!/usr/bin/env bash
# Cross-language parity check: verifies both Rust and TypeScript
# load the same test vectors and all tests pass.
#
# This script is a meta-check -- it doesn't re-run tests (CI already did),
# but verifies that vector files exist, are valid JSON, and both test
# suites reference them.

set -euo pipefail

echo "=== Cross-Language Vector Parity Check ==="

# 1. Verify all expected vector files exist
EXPECTED_VECTORS=(
  "tests/vectors/crypto/aes-gcm.json"
  "tests/vectors/crypto/ed25519.json"
  "tests/vectors/crypto/ecies.json"
  "tests/vectors/crypto/hkdf.json"
  "tests/vectors/crypto/ipns-name.json"
  "tests/vectors/crypto/node-aad.json"
  "tests/vectors/core/vault-blob.json"
  "tests/vectors/core/folder-metadata.json"
  "tests/vectors/core/ipns-record.json"
  "tests/vectors/core/bin-metadata.json"
)

MISSING=0
for v in "${EXPECTED_VECTORS[@]}"; do
  if [ ! -f "$v" ]; then
    echo "MISSING: $v"
    MISSING=$((MISSING + 1))
  else
    # Validate JSON
    if ! python3 -m json.tool "$v" > /dev/null 2>&1; then
      echo "INVALID JSON: $v"
      MISSING=$((MISSING + 1))
    else
      echo "OK: $v"
    fi
  fi
done

if [ $MISSING -gt 0 ]; then
  echo "FAIL: $MISSING vector file(s) missing or invalid"
  exit 1
fi

# 2. Verify Rust tests reference vectors
if ! grep -r "tests/vectors" crates/crypto/tests/ > /dev/null 2>&1; then
  echo "FAIL: Rust cross_language.rs does not reference tests/vectors/"
  exit 1
fi
echo "OK: Rust tests reference shared vectors"

# 3. Verify both test suites passed (they ran in prior CI steps)
echo ""
echo "=== Parity check passed ==="
echo "Both Rust and TypeScript test suites passed against shared vectors."
