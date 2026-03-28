---
status: passed
phase: 29
phase_name: Infrastructure Hardening
verified_at: 2026-03-28
---

# Phase 29: Infrastructure Hardening -- Verification

## Goal

Orphaned IPNS records are cleaned up on deletion, test login endpoint is hardened for staging, and IPFS node access is restricted.

## Success Criteria Results

### 1. IPNS unenrollment on file/folder deletion

**Status: PASS**

- `CipherBoxClient.fireAndForgetUnenroll()` calls `ipnsControllerUnenrollBatch` (generated API client)
- Wired into 4 deletion methods: `deleteItem`, `deleteToBin`, `permanentDelete`, `emptyBin`
- `POST /ipns/unenroll` endpoint accepts up to 200 IPNS names with validation
- `IpnsService.unenrollBatch` delegates to `RepublishService.unenrollIpns()` per name
- SDK builds successfully with full DTS output

### 2. Batch unenrollment for folder deletes with nested files

**Status: PASS**

- `collectSubtreeIpnsNames()` recursively walks in-memory FolderTree
- Collects folder IPNS name + all nested file `fileMetaIpnsName` values
- Used in both `deleteItem` and `deleteToBin` for folder-type removals
- Unloaded subtrees are gracefully skipped (returns folder name only)

### 3. Test login endpoint unreachable in production with monitoring alert

**Status: PASS**

- `test-auth.service.ts` line 44: `if (nodeEnv === 'production')` throws `ForbiddenException`
- `test-auth.service.ts` line 55: `timingSafeEqual` comparison for `TEST_LOGIN_SECRET`
- `test-auth.service.spec.ts` line 80: Unit test verifies `ForbiddenException` in production
- `docker/grafana/alerts/test-login-rate.json`: Alert fires when >100 calls/hour on staging

### 4. Kubo API port 5001 restricted in staging/production

**Status: PASS**

- `docker/docker-compose.staging.yml`: Kubo port bound to `127.0.0.1:5001:5001`
- Not accessible from external networks
- Dev compose uses `0.0.0.0:5001` (expected for local development)

## Automated Checks

| Check                                                                             | Result   |
| --------------------------------------------------------------------------------- | -------- |
| `grep "ArrayMaxSize(200)" apps/api/src/ipns/dto/unenroll.dto.ts`                  | PASS     |
| `grep "@Post('unenroll')" apps/api/src/ipns/ipns.controller.ts`                   | PASS     |
| `grep "async unenrollBatch" apps/api/src/ipns/ipns.service.ts`                    | PASS     |
| `grep "unenroll" packages/api-client/src/generated/ipns/ipns.ts`                  | PASS     |
| `grep -c "fireAndForgetUnenroll" packages/sdk/src/client.ts` >= 4                 | PASS (5) |
| `grep -c "collectSubtreeIpnsNames" packages/sdk/src/client.ts` >= 2               | PASS (4) |
| `! grep "TODO: Phase 14" apps/web/src/services/folder.service.ts`                 | PASS     |
| `! grep "TODO: Phase 14" apps/web/src/services/delete.service.ts`                 | PASS     |
| `! grep "orphaned after deletion" apps/web/src/services/folder.service.ts`        | PASS     |
| `grep "nodeEnv === 'production'" apps/api/src/auth/services/test-auth.service.ts` | PASS     |
| `grep "timingSafeEqual" apps/api/src/auth/services/test-auth.service.ts`          | PASS     |
| `grep "127.0.0.1:5001" docker/docker-compose.staging.yml`                         | PASS     |
| `pnpm --filter @cipherbox/sdk build`                                              | PASS     |
| `docker/grafana/alerts/test-login-rate.json` valid JSON                           | PASS     |

## Human Verification Items

None -- all criteria are verifiable through automated checks and code inspection.

## Summary

All 4 success criteria pass. Phase 29 execution is complete:

- **Plan 29-01**: IPNS batch unenroll API endpoint with validation and API client regeneration
- **Plan 29-02**: SDK delete-path unenrollment wiring with recursive folder subtree collection
- **Plan 29-03**: Grafana test-login alert + verification of existing production guards and Kubo binding
