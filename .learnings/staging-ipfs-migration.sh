#!/bin/bash
# IPFS Datastore Migration: flatfs -> pebbleds (parallel cutover)
# Run on staging VPS (76.13.151.200) as cicd user
#
# Prerequisites:
# - Current Docker stack running with flatfs Kubo
# - PostgreSQL accessible from the host
#
# This script:
# 1. Stops the API to prevent new writes
# 2. Queries DB for all valid CIDs
# 3. Lists all pinned CIDs on current Kubo
# 4. Diffs to find stale CIDs
# 5. Spins up a temporary pebbleds Kubo
# 6. Pins only valid CIDs to the new node
# 7. Cleans up (but does NOT delete old volume — that's manual)

set -euo pipefail

COMPOSE_FILE="/opt/cipherbox/docker/docker-compose.staging.yml"
COMPOSE="docker compose -f $COMPOSE_FILE"

echo "=== Step 1: Stop API to prevent new IPFS writes ==="
$COMPOSE stop api
echo "API stopped."

echo ""
echo "=== Step 2: Query DB for all valid CIDs ==="
VALID_CIDS=$(docker exec cipherbox-postgres psql -U cipherbox -d cipherbox -t -A -c "
  SELECT DISTINCT cid FROM (
    SELECT cid FROM pinned_cids
    UNION
    SELECT latest_cid FROM folder_ipns WHERE latest_cid IS NOT NULL
  ) AS all_valid_cids
  WHERE cid IS NOT NULL
  ORDER BY cid;
")
VALID_COUNT=$(echo "$VALID_CIDS" | grep -c '^' || echo 0)
echo "Found $VALID_COUNT valid CIDs in database."

echo ""
echo "=== Step 3: List all pinned CIDs on current Kubo ==="
PINNED_CIDS=$(docker exec cipherbox-ipfs ipfs pin ls --type=recursive -q 2>/dev/null || echo "")
PINNED_COUNT=$(echo "$PINNED_CIDS" | grep -c '^' || echo 0)
echo "Found $PINNED_COUNT pinned CIDs on Kubo."

echo ""
echo "=== Step 4: Diff — find stale CIDs ==="
VALID_FILE=$(mktemp)
PINNED_FILE=$(mktemp)
echo "$VALID_CIDS" | sort > "$VALID_FILE"
echo "$PINNED_CIDS" | sort > "$PINNED_FILE"

STALE_CIDS=$(comm -23 "$PINNED_FILE" "$VALID_FILE")
STALE_COUNT=$(echo "$STALE_CIDS" | grep -c '^' || echo 0)
MIGRATE_CIDS=$(comm -12 "$PINNED_FILE" "$VALID_FILE")
MIGRATE_COUNT=$(echo "$MIGRATE_CIDS" | grep -c '^' || echo 0)

echo "Stale CIDs (will NOT migrate): $STALE_COUNT"
echo "Valid CIDs (will migrate): $MIGRATE_COUNT"
echo "DB CIDs not pinned on Kubo: $(comm -23 "$VALID_FILE" "$PINNED_FILE" | grep -c '^' || echo 0)"

echo ""
echo "=== Step 5: Spin up temporary pebbleds Kubo ==="
# Create a temporary container with a new volume
docker volume create ipfs_staging_new
docker run -d \
  --name kubo-pebbleds-temp \
  --network docker_default \
  -e IPFS_PROFILE=server,pebbleds \
  -v ipfs_staging_new:/data/ipfs \
  ipfs/kubo:v0.40.0

echo "Waiting for pebbleds Kubo to initialize..."
sleep 15

# Verify pebbleds
DS_TYPE=$(docker exec kubo-pebbleds-temp ipfs config Datastore.Spec 2>/dev/null | grep -o '"type":"[^"]*"' | head -1 || echo "unknown")
echo "New Kubo datastore: $DS_TYPE"

echo ""
echo "=== Step 6: Pin valid CIDs to new node ==="
MIGRATED=0
FAILED=0
TOTAL=$MIGRATE_COUNT

echo "$MIGRATE_CIDS" | while IFS= read -r cid; do
  if [ -z "$cid" ]; then continue; fi
  MIGRATED=$((MIGRATED + 1))
  if docker exec kubo-pebbleds-temp ipfs pin add --progress=false "$cid" >/dev/null 2>&1; then
    echo "[$MIGRATED/$TOTAL] Pinned: $cid"
  else
    FAILED=$((FAILED + 1))
    echo "[$MIGRATED/$TOTAL] FAILED: $cid"
  fi
done

echo ""
echo "=== Step 7: Migration summary ==="
echo "Valid CIDs in DB: $VALID_COUNT"
echo "Pinned on old Kubo: $PINNED_COUNT"
echo "Stale (skipped): $STALE_COUNT"
echo "Migrated to pebbleds: $MIGRATE_COUNT"
echo ""
echo "=== Next steps (MANUAL) ==="
echo "1. Verify: docker exec kubo-pebbleds-temp ipfs pin ls --type=recursive -q | wc -l"
echo "2. Stop temp container: docker stop kubo-pebbleds-temp && docker rm kubo-pebbleds-temp"
echo "3. Stop old Kubo: $COMPOSE stop ipfs"
echo "4. Delete old volume: docker volume rm docker_ipfs_staging  (check exact name)"
echo "5. Approve/run staging deploy — creates blank ipfs_staging"
echo "6. Stop new Kubo: $COMPOSE stop ipfs"
echo "7. Copy data: docker run --rm -v ipfs_staging_new:/src -v docker_ipfs_staging:/dst alpine sh -c 'cp -a /src/. /dst/'"
echo "8. Remove temp volume: docker volume rm ipfs_staging_new"
echo "9. Restart everything: $COMPOSE up -d"
echo "10. Start API: $COMPOSE start api"
echo "11. Verify: curl -s http://localhost:3000/health"

# Cleanup temp files
rm -f "$VALID_FILE" "$PINNED_FILE"
