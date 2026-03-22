#!/usr/bin/env bash
set -euo pipefail

##############################################################################
# CipherBox Baseline Benchmark Script
#
# Purpose:
#   Exercises the CipherBox staging API to generate Prometheus histogram
#   observations for IPFS/IPNS operations. Captures client-side timings
#   and computes p50/p95/p99 percentiles for baseline comparison.
#
#   This script is designed to be run before and after architectural changes
#   (e.g., Phase 22) to measure performance impact.
#
# Usage:
#   ./scripts/baseline-benchmark.sh <api-url> <jwt-token>
#
#   Example:
#   ./scripts/baseline-benchmark.sh https://api-staging.cipherbox.cc "eyJhbGci..."
#
# Obtaining a JWT token:
#   1. Log in to the web app at https://app-staging.cipherbox.cc
#   2. Open browser DevTools > Application > Local Storage
#   3. Copy the value of the 'accessToken' key
#   OR use E2E test credentials (see tests/web-e2e/.env)
#
# Output:
#   Prints p50/p95/p99 timing results in a markdown table format suitable
#   for pasting into .planning/baselines/18-performance-baselines.md
#
##############################################################################

API_URL="${1:?Usage: $0 <api-url> <jwt-token>}"
JWT_TOKEN="${2:?Usage: $0 <api-url> <jwt-token>}"

ITERATIONS=20
WARMUP=3
# Remove trailing slash from API_URL
API_URL="${API_URL%/}"

# Temp directory for timing data
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "============================================================"
echo "CipherBox Baseline Benchmark"
echo "============================================================"
echo "API URL:    $API_URL"
echo "Iterations: $ITERATIONS (+ $WARMUP warmup)"
echo "Date:       $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "============================================================"
echo ""

# Helper: compute percentile from a sorted file of numbers
# Usage: percentile <file> <p> (where p is 50, 95, or 99)
percentile() {
  local file="$1"
  local p="$2"
  local count
  count=$(wc -l < "$file" | tr -d ' ')
  if [ "$count" -eq 0 ]; then
    echo "N/A"
    return
  fi
  # index = ceil(p/100 * count)
  local index
  index=$(awk "BEGIN { printf \"%d\", int(($p / 100.0) * $count + 0.999999) }")
  if [ "$index" -gt "$count" ]; then
    index=$count
  fi
  if [ "$index" -lt 1 ]; then
    index=1
  fi
  sed -n "${index}p" "$file"
}

# Helper: run a curl request and capture timing
# Usage: timed_curl <output_file> <curl_args...>
timed_curl() {
  local output_file="$1"
  shift
  local response
  response=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    "$@" 2>/dev/null) || true
  local http_code="${response%% *}"
  local time_total="${response##* }"
  if [[ ! "$http_code" =~ ^2[0-9][0-9]$ ]]; then
    >&2 echo "WARN: timed_curl got HTTP $http_code; sample skipped."
    return
  fi
  if [[ "$time_total" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "$time_total" >> "$output_file"
  else
    >&2 echo "WARN: timed_curl received non-numeric time_total='$time_total'; sample skipped."
  fi
}

##############################################################################
# 1. Discover IPNS name from vault
##############################################################################
echo ">> Discovering IPNS name from /vault..."
VAULT_RESPONSE=$(curl -s -H "Authorization: Bearer $JWT_TOKEN" "$API_URL/vault" 2>/dev/null) || true
IPNS_NAME=$(echo "$VAULT_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rootIpnsName',''))" 2>/dev/null) || true

if [ -z "$IPNS_NAME" ]; then
  echo "   WARNING: Could not discover IPNS name from /vault (HTTP request failed or ipnsName missing). Skipping IPNS resolve test."
  SKIP_RESOLVE=true
else
  echo "   IPNS Name: ${IPNS_NAME:0:20}..."
  SKIP_RESOLVE=false
fi
echo ""

##############################################################################
# 2. IPNS Resolve
##############################################################################
RESOLVE_FILE="$TMPDIR/resolve_times.txt"
touch "$RESOLVE_FILE"

if [ "$SKIP_RESOLVE" = false ]; then
  echo ">> IPNS Resolve (${WARMUP} warmup + ${ITERATIONS} measured)"

  # Warmup
  for i in $(seq 1 $WARMUP); do
    curl -s -o /dev/null -H "Authorization: Bearer $JWT_TOKEN" \
      "$API_URL/ipns/resolve?ipnsName=$IPNS_NAME" 2>/dev/null || true
    printf "  warmup %d/%d\r" "$i" "$WARMUP"
  done
  echo ""

  # Measured
  for i in $(seq 1 $ITERATIONS); do
    timed_curl "$RESOLVE_FILE" "$API_URL/ipns/resolve?ipnsName=$IPNS_NAME"
    printf "  iteration %d/%d\r" "$i" "$ITERATIONS"
  done
  echo ""

  sort -n "$RESOLVE_FILE" -o "$RESOLVE_FILE"
  echo "   p50: $(percentile "$RESOLVE_FILE" 50)s"
  echo "   p95: $(percentile "$RESOLVE_FILE" 95)s"
  echo "   p99: $(percentile "$RESOLVE_FILE" 99)s"
else
  echo ">> IPNS Resolve: SKIPPED (no IPNS name)"
fi
echo ""

##############################################################################
# 3. File Upload (IPFS Pin)
##############################################################################
UPLOAD_FILE="$TMPDIR/upload_times.txt"
touch "$UPLOAD_FILE"
UPLOAD_CIDS="$TMPDIR/upload_cids.txt"
touch "$UPLOAD_CIDS"

echo ">> File Upload / IPFS Pin (${WARMUP} warmup + ${ITERATIONS} measured)"
echo "   File size: 10KB random data"

# Generate test file
TEST_FILE="$TMPDIR/test_upload.bin"
dd if=/dev/urandom of="$TEST_FILE" bs=10240 count=1 2>/dev/null

# Warmup
for i in $(seq 1 $WARMUP); do
  curl -s -o /dev/null -H "Authorization: Bearer $JWT_TOKEN" \
    -F "file=@$TEST_FILE" "$API_URL/ipfs/upload" 2>/dev/null || true
  printf "  warmup %d/%d\r" "$i" "$WARMUP"
done
echo ""

# Measured
for i in $(seq 1 $ITERATIONS); do
  UPLOAD_RESPONSE=$(curl -s -w "\n%{http_code} %{time_total}" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    -F "file=@$TEST_FILE" "$API_URL/ipfs/upload" 2>/dev/null) || true

  # Extract HTTP status + timing (last line) and response body (everything else)
  STATUS_AND_TIME=$(echo "$UPLOAD_RESPONSE" | tail -1)
  BODY=$(echo "$UPLOAD_RESPONSE" | sed '$d')
  HTTP_CODE="${STATUS_AND_TIME%% *}"
  TIME_TOTAL="${STATUS_AND_TIME##* }"

  # Only record timings and CIDs for successful (2xx) responses
  if [[ "$HTTP_CODE" =~ ^2[0-9][0-9]$ && "$TIME_TOTAL" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo "$TIME_TOTAL" >> "$UPLOAD_FILE"

    # Try to extract CID from response
    CID=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cid',''))" 2>/dev/null) || true
    if [ -n "$CID" ]; then
      echo "$CID" >> "$UPLOAD_CIDS"
    fi
  else
    >&2 echo "WARN: upload got HTTP $HTTP_CODE; sample skipped."
  fi

  printf "  iteration %d/%d\r" "$i" "$ITERATIONS"
done
echo ""

sort -n "$UPLOAD_FILE" -o "$UPLOAD_FILE"
echo "   p50: $(percentile "$UPLOAD_FILE" 50)s"
echo "   p95: $(percentile "$UPLOAD_FILE" 95)s"
echo "   p99: $(percentile "$UPLOAD_FILE" 99)s"
echo "   CIDs captured: $(wc -l < "$UPLOAD_CIDS" | tr -d ' ')"
echo ""

##############################################################################
# 4. File Download (IPFS Cat)
##############################################################################
DOWNLOAD_FILE="$TMPDIR/download_times.txt"
touch "$DOWNLOAD_FILE"

# Pick a CID from uploads for download testing
DOWNLOAD_CID=$(head -1 "$UPLOAD_CIDS" 2>/dev/null) || true

if [ -z "$DOWNLOAD_CID" ]; then
  echo ">> File Download / IPFS Cat: SKIPPED (no CID from uploads)"
else
  echo ">> File Download / IPFS Cat (${WARMUP} warmup + ${ITERATIONS} measured)"
  echo "   CID: ${DOWNLOAD_CID:0:20}..."

  # Warmup
  for i in $(seq 1 $WARMUP); do
    curl -s -o /dev/null -H "Authorization: Bearer $JWT_TOKEN" \
      "$API_URL/ipfs/$DOWNLOAD_CID" 2>/dev/null || true
    printf "  warmup %d/%d\r" "$i" "$WARMUP"
  done
  echo ""

  # Measured
  for i in $(seq 1 $ITERATIONS); do
    timed_curl "$DOWNLOAD_FILE" "$API_URL/ipfs/$DOWNLOAD_CID"
    printf "  iteration %d/%d\r" "$i" "$ITERATIONS"
  done
  echo ""

  sort -n "$DOWNLOAD_FILE" -o "$DOWNLOAD_FILE"
  echo "   p50: $(percentile "$DOWNLOAD_FILE" 50)s"
  echo "   p95: $(percentile "$DOWNLOAD_FILE" 95)s"
  echo "   p99: $(percentile "$DOWNLOAD_FILE" 99)s"
fi
echo ""

##############################################################################
# 5. IPNS Publish (reduced iterations -- mutates state)
##############################################################################
echo ">> IPNS Publish: SKIPPED (requires signed IPNS record)"
echo "   Publish timing will be captured from organic staging usage via"
echo "   Prometheus histogram: cipherbox_ipfs_ipns_duration_seconds{operation=\"publish\"}"
echo ""

##############################################################################
# Summary
##############################################################################
echo "============================================================"
echo "RESULTS SUMMARY"
echo "============================================================"
echo ""
echo "| Operation      | p50       | p95       | p99       | Notes |"
echo "|----------------|-----------|-----------|-----------|-------|"

# IPNS Resolve
if [ "$SKIP_RESOLVE" = false ]; then
  printf "| IPNS Resolve   | %ss | %ss | %ss |       |\n" \
    "$(percentile "$RESOLVE_FILE" 50)" \
    "$(percentile "$RESOLVE_FILE" 95)" \
    "$(percentile "$RESOLVE_FILE" 99)"
else
  echo "| IPNS Resolve   | SKIPPED   | SKIPPED   | SKIPPED   | No IPNS name |"
fi

echo "| IPNS Publish   | --        | --        | --        | See Prometheus |"

printf "| IPFS Pin       | %ss | %ss | %ss | 10KB file |\n" \
  "$(percentile "$UPLOAD_FILE" 50)" \
  "$(percentile "$UPLOAD_FILE" 95)" \
  "$(percentile "$UPLOAD_FILE" 99)"

if [ -n "$DOWNLOAD_CID" ]; then
  printf "| IPFS Cat       | %ss | %ss | %ss | 10KB file |\n" \
    "$(percentile "$DOWNLOAD_FILE" 50)" \
    "$(percentile "$DOWNLOAD_FILE" 95)" \
    "$(percentile "$DOWNLOAD_FILE" 99)"
else
  echo "| IPFS Cat       | SKIPPED   | SKIPPED   | SKIPPED   | No CID |"
fi

echo ""
echo "Copy the table above into .planning/baselines/18-performance-baselines.md"
echo ""
echo "Done at $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
