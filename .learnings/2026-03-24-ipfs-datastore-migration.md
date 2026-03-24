# IPFS Kubo Datastore Migration (flatfs → pebbleds)

**Date:** 2026-03-24

## Original Prompt

> Migrate staging IPFS Kubo from flatfs to pebbleds datastore as part of Phase 19.2 upload performance optimization. Preserve pinned CIDs by cross-referencing against the database.

## What I Learned

- **`ipfs-ds-convert` is archived and dead.** The tool (github.com/ipfs-inactive/ipfs-ds-convert) was designed for go-ipfs v0.8.0 / repo version 11. It is incompatible with modern Kubo (v0.40.0, repo version 18). Do not attempt to use it.
- **Kubo has NO built-in datastore conversion command.** `ipfs repo migrate` handles repo version upgrades, NOT datastore backend changes. `fs-repo-migrations` is similarly version-only.
- **Re-pinning via bitswap is impractically slow.** Even with two Kubo nodes on the same Docker network, sequential `ipfs pin add` for 31K CIDs was stuck after minutes — each pin does full block discovery and verification. The VPS became unresponsive.
- **Connecting peers manually helps but isn't enough.** `ipfs swarm connect /dns4/<container>/tcp/4001/p2p/<peerID>` establishes the connection, but bitswap block transfer is still slow for large repos.
- **`ipfs dag export/import` is the recommended migration path.** Export each root CID as a CAR file from the old node, import into the new pebbleds node. More efficient than pin-by-pin since it transfers raw blocks without bitswap overhead.
- **Parallel pinning (`xargs -P`) might work** as an alternative to sequential, but risks overwhelming the VPS — we saw SSH timeouts at high I/O load.
- **`IPFS_PROFILE=server,pebbleds` requires a fresh repo.** You cannot just change the environment variable on an existing flatfs volume — Kubo will fail to start. The profile is only applied during `ipfs init`.
- **Clean slate is often the pragmatic choice for staging.** With only 1 stale CID out of 31K, the data was 99.997% clean, but the migration tooling made preserving it impractical.

## Migration Strategies (ordered by complexity)

### 1. Clean Slate (simplest, staging-appropriate)

```bash
docker compose down
docker volume rm <ipfs_volume>
# Update IPFS_PROFILE=server,pebbleds in compose file
docker compose up -d
# Kubo initializes fresh with pebbleds
```

Loss: all pinned content. Users must re-upload.

### 2. DAG Export/Import (preserves data)

```bash
# Option A: stream directly old → new (no intermediate file)
docker exec old-kubo ipfs dag export <cid> \
  | docker exec -i new-kubo ipfs dag import
docker exec new-kubo ipfs pin add <cid>

# Option B: file-based transfer with docker cp
docker exec old-kubo ipfs dag export <cid> > /tmp/cid.car
docker cp /tmp/cid.car new-kubo:/tmp/cid.car
docker exec new-kubo ipfs dag import /tmp/cid.car
docker exec new-kubo ipfs pin add <cid>
```

For bulk migration, script with the CID list from the database. Option A avoids disk space issues; Option B is easier to debug but requires space for the CAR files (5.5GB repo in our case).

### 3. Parallel Cutover (production-grade)

1. Stop API to prevent writes
2. Query DB for valid CIDs (`pinned_cids` + `folder_ipns.latest_cid`)
3. Spin up new pebbleds Kubo on same Docker network
4. Connect peers: `ipfs swarm connect`
5. Export/import CIDs in batches (NOT pin-by-pin)
6. Verify pin counts match
7. Swap API config to new node
8. Delete old volume

### Database Query for Valid CIDs

```sql
SELECT DISTINCT cid FROM (
  SELECT cid FROM pinned_cids
  UNION
  SELECT latest_cid FROM folder_ipns WHERE latest_cid IS NOT NULL
) AS all_valid_cids
WHERE cid IS NOT NULL
ORDER BY cid;
```

Note: staging DB name is `cipherbox_staging`, not `cipherbox`.

## What Would Have Helped

- Knowing upfront that `ipfs-ds-convert` was archived — would have skipped the parallel cutover approach and gone straight to clean slate or dag export
- Understanding that bitswap pin-by-pin is O(blocks × discovery time), not O(CIDs) — a 31K CID repo with 372K blocks is impractical to migrate this way
- Having a pre-built migration script tested on a smaller dataset before attempting on staging

## Key Files

- `docker/docker-compose.staging.yml` — Kubo service config, IPFS_PROFILE setting
- `docker/docker-compose.yml` — local dev Kubo config
- `.github/workflows/deploy-staging.yml` — staging deployment workflow
- `apps/api/src/vault/entities/pinned-cid.entity.ts` — file content CID tracking
- `apps/api/src/ipns/entities/folder-ipns.entity.ts` — metadata CID tracking (latest_cid)
- `.learnings/staging-ipfs-migration.sh` — migration script (bitswap approach, too slow for large repos but useful as a reference for the DB query, CID diffing, and parallel cutover steps)
