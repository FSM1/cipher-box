# Phase 50: IPFS/IPNS Data-Integrity Fixes - Pattern Map

**Mapped:** 2026-06-19
**Files analyzed:** 7 modified source files + 3 test files (2 additive, 1 new)
**Analogs found:** 7 / 7

## File Classification

| Modified File | Role | Data Flow | Closest Analog | Match Quality |
| --- | --- | --- | --- | --- |
| `apps/api/src/vault/vault.service.ts` | service | CRUD / request-response | Self (existing `guardedUnpin` + test at spec:1003) | self |
| `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` | worker/processor | batch / event-driven | Self (existing drain loop at :53-65) | self |
| `apps/api/src/ipfs/ipfs.controller.ts` | controller | request-response | Self (upload compensation path at :119-132) | self |
| `apps/api/src/ipfs/dto/unpin.dto.ts` | DTO / validation | request-response | Self (existing `@IsString @IsNotEmpty` pattern) | self |
| `scripts/backfill-pinned-cids.ts` | script / utility | batch | Self (existing candidate query at :132-141) | self |
| `packages/sdk/src/client.ts` | SDK client | event-driven / transform | Self (`ensureFolderLoaded` DFS at :444-514) | self |
| `apps/api/src/vault/vault.service.spec.ts` | test | — | Self (existing `describe('guardedUnpin')` at :918-1033) | self |
| `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` | test | — | Self (existing drain describe at :86-100) | self |
| `packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts` | test (new file) | — | `packages/sdk/src/__tests__/ensure-folder-loaded.test.ts` | exact role-match |

## Pattern Assignments

### `apps/api/src/vault/vault.service.ts` — D-01 (WR-01): advisory lock hash fix

**Fix locus:** line 262

**Current code (lines 259-262):**
```typescript
// 1. Advisory xact lock — MUST be the first transactional statement (D-04)
// Compute the lock key inline so the lock is literally the first statement;
// abs() avoids bigint-out-of-range on negative hashtext values (Pitfall 2)
await manager.query(`SELECT pg_advisory_xact_lock(abs(hashtext($1))::bigint)`, [cid]);
```

**Fix:** Drop `abs()`. The comment is factually wrong — `abs(int4)` overflows for INT_MIN; `hashtext($1)::bigint` sign-extends safely to bigint which is what `pg_advisory_xact_lock` accepts.

```typescript
// abs() was incorrectly applied to int4 before bigint cast, overflowing for INT_MIN.
// pg_advisory_xact_lock accepts signed bigint; sign-extending hashtext int4→bigint is safe.
await manager.query(`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, [cid]);
```

**D-01 also flags IN-01 (line 310) and IN-06 (line 253/295):**

IN-01 fix locus — line 310:
```typescript
this.metricsService.fileUnpins.inc();
```
Must be guarded so it only fires when a row was actually deleted (track a `rowDeleted` flag analogous to the existing `outboxRowInserted` flag at line 253).

IN-06 fix locus — rename `outboxRowInserted` (line 253) → `shouldAttemptPhysicalUnpin` for clarity.

**D-04 WR-07 / IN-03 additional loci in this file:**
- `recordUnpin` at lines 317-322 — IN-03: delete this method (or `@deprecated` with pointer to `guardedUnpin`)
- refcount query at lines 279-284 — WR-07: if BYO is to block physical unpin, add inline comment documenting retention consequence; if filtering, add `AND NOT EXISTS (SELECT 1 FROM vaults WHERE owner_id = pc.user_id AND is_byo_user = true)`

---

### `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` — D-02 (WR-03): drain refcount guard

**Fix locus:** lines 53-65 (`drainPendingUnpins` loop)

**Current code (lines 53-65):**
```typescript
for (const row of rows) {
  try {
    // D-05: Call through provider so "not pinned" is treated as success
    await this.ipfsProvider.unpinFile(row.cid);
    await this.pendingUnpinRepository.delete({ cid: row.cid });
    this.logger.log(`Drained cid=${row.cid}`);
  } catch (err) {
    // Kubo failure: leave row for next run; do not abort the batch
    const message = err instanceof Error ? err.message : String(err);
    this.logger.error(`Failed to drain cid=${row.cid}: ${message}`);
  }
}
```

`this.pinnedCidRepository` is already injected (constructor line 26). Add `.count({ where: { cid } })` check before `unpinFile`.

**D-04 IN-05 fix locus — lines 84-91 (`runDriftReport`):**
```typescript
const dbCids = new Set<string>([
  ...pinnedCidRows.map((r) => r.cid),
  ...pendingUnpinRows.map((r) => r.cid),
]);
```
If WR-07 is resolved by filtering BYO from refcount, `pinnedCidRows` fetch must also exclude BYO-owned CIDs (or add a note explaining the asymmetry).

**D-04 WR-04 accept locus — line 97:**
```typescript
this.metricsService.driftOrphanedPinsTotal.inc();
```
Add comment: `// Counter (not Gauge) is intentional — each drift run appends orphan events to a cumulative total; a Gauge would require resetting on each run and tracking ephemeral state.`

---

### `apps/api/src/ipfs/ipfs.controller.ts` — D-04 WR-02: upload compensation no-row path

**Fix locus:** lines 119-132

**Current code (lines 119-132):**
```typescript
try {
  await this.vaultService.recordPin(req.user.id, result.cid, result.size);
} catch (err) {
  // ...
  await this.vaultService
    .guardedUnpin(req.user.id, result.cid, { suppressCrossUserAudit: true })
    .catch(() => undefined);
  throw err;
}
```

WR-02: when `recordPin` throws (no row written), `guardedUnpin` finds `pinnedCidRepo.findOne()` → null and returns early — it does NOT call Kubo. The pin leaks. Fix: for the compensation path where no row exists, call `this.ipfsProvider.unpinFile(result.cid)` directly (or add a `guardedUnpin` internal variant that handles the no-row case). `suppressCrossUserAudit` path already prevents the false cross-user signal; the gap is the missing physical unpin on no-row.

---

### `apps/api/src/ipfs/dto/unpin.dto.ts` — D-04 IN-02: CID format validation

**Current code (lines 1-12):**
```typescript
import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class UnpinDto {
  @ApiProperty({ ... })
  @IsString()
  @IsNotEmpty()
  cid!: string;
}
```

Fix: add `@Matches(/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/)` and `@MaxLength(255)` (import `Matches`, `MaxLength` from `class-validator`). This changes the OpenAPI spec — **must run `pnpm api:generate`** and commit the regenerated client alongside.

---

### `scripts/backfill-pinned-cids.ts` — D-04 WR-05 / WR-06: backfill TOCTOU and BYO fix

**Fix locus:** lines 132-141 (candidate query)

**Current code (lines 132-141):**
```typescript
const candidateRows = (await dataSource.query(`
  SELECT
    pc.id            AS "id",
    pc.user_id       AS "userId",
    pc.cid           AS "cid",
    false::boolean   AS "isByoUser"
  FROM pinned_cids pc
  JOIN vaults v ON v.owner_id = pc.user_id
  WHERE v.is_byo_user = false
`)) as BackfillRow[];
```

WR-05 fix: add `AND pc.pinned_at < NOW() - INTERVAL '1 hour'` to the WHERE clause (excludes in-flight uploads in the active-upload race window).

WR-06 fix: change `false::boolean AS "isByoUser"` → `v.is_byo_user AS "isByoUser"` (uses the actual vault value rather than hardcoding false, so the defensive re-assert in `selectRowsToDelete` is meaningful).

---

### `packages/sdk/src/client.ts` — D-03: on-demand subtree traversal

**Fix locus:** lines 230-243 (`collectSubtreeIpnsNames`)

**Current code (lines 230-243):**
```typescript
private collectSubtreeIpnsNames(folderIpnsName: string, acc: string[] = []): string[] {
  acc.push(folderIpnsName);
  const folder = this.folderTree.get(folderIpnsName);
  if (!folder) return acc;  // early return; skips unloaded subtree

  for (const child of folder.children) {
    if (child.type === 'file') {
      acc.push((child as FilePointer).fileMetaIpnsName);
    } else if (child.type === 'folder') {
      this.collectSubtreeIpnsNames((child as FolderEntry).ipnsName, acc);
    }
  }
  return acc;
}
```

**DFS template analog:** `ensureFolderLoaded` at lines 444-514. The key pattern to replicate (lines 478-503):

```typescript
// Unwrap subfolder keys with vault keypair (ECIES)
const folderKey = await unwrapKey(
  hexToBytes(child.folderKeyEncrypted),
  this.internalVaultKeypair.privateKey
);
const ipnsPrivateKey = await unwrapKey(
  hexToBytes(child.ipnsPrivateKeyEncrypted),
  this.internalVaultKeypair.privateKey
);
childState = await this.loadFolder(child.ipnsName, folderKey, { ... });
// ...
// A single corrupt/undecryptable sibling entry must not abort the whole bootstrap
// (Generic catch: unwrapKey/hexToBytes throw key-free errors.)
continue; // on catch
```

**Critical constraints for D-03:**
1. The new method must be `async` — signature changes to `private async collectSubtreeIpnsNamesAsync(folderIpnsName: string, folderKey: Uint8Array, acc: string[] = []): Promise<string[]>`
2. Do NOT write to `this.folderTree` — use a local map for any fetched metadata (avoids Zustand/SDK desync)
3. Try in-memory first (`this.folderTree.get()`); fall through to `sdkCore.loadFolderMetadata` only on miss
4. When `loadFolderMetadata` returns `null` (IPNS record not yet published), push the folder IPNS name (already done at top) and continue without recursing
5. Each child's failure must be caught independently — do not abort sibling iteration
6. The four callers (`collectRemovedItemIpnsNames`, `collectBinEntryIpnsNames` at deletion paths :856, :1866, :1880, :1927) need to become async or resolve the promise before passing to `fireAndForgetUnenroll`

**Initial `folderKey` for the top-level deleted folder:** When the item being deleted is a `FolderEntry` (came from its parent's decrypted metadata), its `folderKeyEncrypted` is available — unwrap it with `this.internalVaultKeypair.privateKey` using the same `unwrapKey(hexToBytes(...), ...)` call as `ensureFolderLoaded`.

---

## Shared Patterns

### TypeORM repository mock pattern (Jest — API tests)

**Source:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` lines 15-24
```typescript
const mockPendingUnpinRepository = {
  find: jest.fn(),
  delete: jest.fn(),
  count: jest.fn(),
};

const mockPinnedCidRepository = {
  find: jest.fn(),
  query: jest.fn(),
  // D-02: add count: jest.fn() here
};
```

The spec uses `getRepositoryToken(Entity)` as the provide token (line 52-59). All tests call `jest.clearAllMocks()` in `beforeEach`. Mock return values are set per-test with `.mockResolvedValue()`.

### NestJS test module compilation pattern (Jest)

**Source:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` lines 45-80
```typescript
const module: TestingModule = await Test.createTestingModule({
  providers: [
    PendingUnpinProcessor,
    { provide: getRepositoryToken(PendingUnpin), useValue: mockPendingUnpinRepository },
    { provide: getRepositoryToken(PinnedCid), useValue: mockPinnedCidRepository },
    { provide: IPFS_PROVIDER, useValue: mockIpfsProvider },
    { provide: MetricsService, useValue: mockMetricsService },
    { provide: ConfigService, useValue: mockConfigService },
  ],
}).compile();
processor = module.get<PendingUnpinProcessor>(PendingUnpinProcessor);
// Suppress logger noise
jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
```

### manager.query capture pattern (Jest — vault.service.spec.ts)

**Source:** `apps/api/src/vault/vault.service.spec.ts` lines 1003-1031 (advisory lock ordering test)
```typescript
const callOrder: string[] = [];
mockManager.query.mockImplementation((sql: string) => {
  if (sql.includes('pg_advisory_xact_lock')) {
    callOrder.push('advisory_lock');
    return Promise.resolve([]);
  }
  return Promise.resolve([]);
});
// Post-call assertions
expect(capturedSql).toMatch(/pg_advisory_xact_lock/);
expect(capturedSql).not.toMatch(/abs\(hashtext/);
```

The WR-01 regression test must assert `not.toMatch(/abs\(hashtext/)` against the captured SQL.

### SDK Vitest mock pattern (new collect-subtree test file)

**Source:** `packages/sdk/src/__tests__/ensure-folder-loaded.test.ts` lines 1-53
```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import type { FolderEntry, FolderMetadata } from '@cipherbox/core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return { ...actual, loadFolderMetadata: vi.fn() };
});

vi.mock('@cipherbox/crypto', () => ({
  unwrapKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(9)),
  hexToBytes: vi.fn().mockReturnValue(new Uint8Array(32)),
  clearBytes: vi.fn(),
}));

import * as sdkCore from '@cipherbox/sdk-core';

/** Drive loadFolderMetadata to return canned metadata keyed by IPNS name. */
function mockTree(tree: Record<string, FolderMetadata['children']>) {
  vi.mocked(sdkCore.loadFolderMetadata).mockImplementation(async ({ ipnsName }) => {
    const children = tree[ipnsName];
    if (!children) return null;
    return { metadata: { version: 'v2', children }, sequenceNumber: 1n, cid: `cid-${ipnsName}` };
  });
}
```

New file must be named `collect-subtree-ipns-names.test.ts` (`.test.ts` suffix — SDK vitest `include` glob only picks up `*.test.ts`, not `*.spec.ts`).

---

## No Analog Found

No files in this phase lack a codebase analog. All fixes are in existing well-tested files with existing specs, or (for the new SDK test) have a direct analog in `ensure-folder-loaded.test.ts`.

---

## Metadata

**Analog search scope:** `apps/api/src/vault/`, `apps/api/src/ipfs/`, `packages/sdk/src/`, `packages/sdk/src/__tests__/`, `scripts/`
**Files scanned:** 9 (7 source, 2 existing test)
**Pattern extraction date:** 2026-06-19

---

## PATTERN MAPPING COMPLETE

**Phase:** 50 - ipfs-ipns-data-integrity-fixes
**Files classified:** 9 (7 modified source + 2 additive test + 1 new test file)
**Analogs found:** 9 / 9

### Coverage

- Files with exact analog (self): 8
- Files with role-match analog: 1 (`collect-subtree-ipns-names.test.ts` → `ensure-folder-loaded.test.ts`)
- Files with no analog: 0

### Key Patterns Identified

- All API fixes are additive patches to existing methods; the surrounding transaction/error-handling structure is unchanged
- Jest spec pattern: `mockManager.query.mockImplementation((sql) => { capturedSql = sql; ... })` for SQL assertion (used for WR-01 regression test)
- SDK test pattern: `vi.mock('@cipherbox/sdk-core', async (importOriginal) => ({ ...actual, loadFolderMetadata: vi.fn() }))` + `mockTree()` helper drives per-IPNS metadata — copy exactly from `ensure-folder-loaded.test.ts`
- `collectSubtreeIpnsNamesAsync` must NOT write to `this.folderTree` (fire-and-forget timing + Zustand desync risk documented in project memory)
- IN-02 (`UnpinDto` validation) is the only change that requires `pnpm api:generate` and regenerated client commit

### File Created

`.planning/phases/50-ipfs-ipns-data-integrity-fixes/50-PATTERNS.md`

### Ready for Planning

Pattern mapping complete. Planner can reference analog patterns in PLAN.md files.
