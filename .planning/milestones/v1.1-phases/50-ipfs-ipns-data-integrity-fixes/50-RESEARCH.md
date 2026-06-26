# Phase 50: IPFS/IPNS Data-Integrity Fixes - Research

**Researched:** 2026-06-19
**Domain:** TypeScript — NestJS API (guarded-unpin / pending-unpin drain), TypeScript SDK (collectSubtreeIpnsNames on-demand traversal)
**Confidence:** HIGH

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01 (WR-01, HIGH):** Drop `abs()` from the advisory-lock hash in `vault.service.ts` (or cast first as `abs(hashtext($1)::bigint)`). Ship a regression test.
- **D-02 (WR-03, HIGH):** Add a refcount re-check in `drainPendingUnpins` before calling `unpinFile`. Ship a regression test.
- **D-03 (LOCKED — on-demand traversal):** Fix `collectSubtreeIpnsNames` to fetch + decrypt child folder metadata on demand from persisted IPNS records. Do NOT rely on in-memory `folderTree`. Do NOT implement a periodic reconciliation job.
- **D-04 (remaining WR/IN):** Every remaining finding (WR-02, WR-04, WR-05, WR-06, WR-07, IN-01..IN-06) must be either fixed per the `42-REVIEW.md` patch or explicitly accepted with an inline code comment and rationale. None may be silently skipped.

### Claude's Discretion

- Exact SQL form for D-01 (drop `abs()` vs. `abs(hashtext($1)::bigint)`)
- WR-02 no-row physical unpin mechanism (direct `unpinFile` vs. internal `guardedUnpin` variant)
- Whether to extract `IpfsProviderCoreModule` (IN-04) or comment-accept the triplicated factory
- Test framework placement and structure (follow existing spec conventions)
- On-demand traversal fetch/decrypt call path, batching, and error handling for undecryptable/missing child nodes

### Deferred Ideas (OUT OF SCOPE)

- Periodic unenroll-reconciliation background job (#14 alternative)
- HARD-02..06 hardening items (Phases 51–55)

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                                          | Research Support                                                                                                       |
| ------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| HARD-01 | IPFS/IPNS data-integrity: resolve Phase 42 unpin-integrity findings (no data loss / no permanently-undeletable CIDs) and unenroll nested IPNS records under unloaded subtrees | D-01 fix eliminates INT_MIN CID undeletability. D-02 fix prevents live-pin drain. D-03 on-demand traversal unenrolls full subtree. D-04 disposes all remaining WR/IN items. |

</phase_requirements>

## Summary

Phase 50 resolves two data-integrity defects against a well-understood codebase — both root causes are confirmed and the concrete patches are already written in `42-REVIEW.md` and the two todo files. This is a code-precision phase, not architecture exploration.

**#12 (API):** Seven warnings and six info findings from the Phase 42 review remain unresolved in the current code (re-verified 2026-06-18, confirmed again 2026-06-19 by reading live files). Two are correctness/data-loss risks: WR-01 (`abs(hashtext($1))::bigint` at `vault.service.ts:262` raises `integer out of range` for the CID whose hashtext is INT_MIN, making that file permanently undeletable) and WR-03 (`drainPendingUnpins` at `pending-unpin.processor.ts:53–58` unpins every outbox CID unconditionally, so a CID re-pinned while queued will have its live pin removed). The remaining WR/IN items require explicit fix-or-accept treatment.

**#14 (SDK):** `collectSubtreeIpnsNames` at `packages/sdk/src/client.ts:230–243` walks only the in-memory `folderTree`. The early-return on `folderTree.get()` returning undefined means deleting a folder whose subtree was never expanded in the current session leaves all descendant IPNS names un-unenrolled. The fix uses `sdkCore.loadFolderMetadata` — which already exists and is exercised by `ensureFolderLoaded` and `loadFolder` — to fetch-and-decrypt child folder metadata on demand, mirroring the DFS walk already implemented in `ensureFolderLoaded`.

**Primary recommendation:** Fix D-01 and D-03 first (highest severity, self-contained patches). Then D-02. Then D-03 (SDK on-demand traversal — largest scope). Dispose all WR/IN items in D-04 in a dedicated pass.

## Architectural Responsibility Map

| Capability                            | Primary Tier        | Secondary Tier   | Rationale                                                                  |
| ------------------------------------- | ------------------- | ---------------- | -------------------------------------------------------------------------- |
| Advisory-lock hash (D-01)             | API / Backend       | —                | PostgreSQL `pg_advisory_xact_lock` is a server-side serialization concern  |
| Pending-unpin drain refcount (D-02)   | API / Backend       | —                | `pinned_cids` refcount lives in the DB; only the API tier can read it      |
| Subtree IPNS collection (D-03)        | Browser / Client    | —                | SDK client owns `folderTree` and IPNS resolution; server is zero-knowledge |
| WR-02 upload compensation (D-04)      | API / Backend       | —                | `guardedUnpin` and `unpinFile` are API-tier constructs                     |
| Backfill TOCTOU (WR-05, WR-06, D-04) | API / Backend (script) | —             | `scripts/backfill-pinned-cids.ts` is an offline DB maintenance script      |
| Drift BYO dbCids set (IN-05, D-04)   | API / Backend       | —                | `PendingUnpinProcessor.runDriftReport` runs in the API process             |

## Standard Stack

No new packages are required for this phase. All fixes use libraries already in the codebase. [VERIFIED: live code grep]

### Core — already present

| Library/Module                                      | Purpose in this phase                                                                 |
| --------------------------------------------------- | ------------------------------------------------------------------------------------- |
| TypeORM `Repository` / `DataSource.transaction`     | DB access for D-01 refcount query, D-02 refcount re-check, D-04 IN-05 drift set      |
| `@cipherbox/sdk-core` `loadFolderMetadata`          | Fetch + decrypt child folder metadata for D-03 on-demand traversal                   |
| `@cipherbox/crypto` `unwrapKey`, `hexToBytes`       | Unwrap `folderKeyEncrypted` / `ipnsPrivateKeyEncrypted` for D-03                     |
| NestJS `@nestjs/bullmq` `PendingUnpinProcessor`     | Host for D-02 drain refcount guard and D-04 IN-05 drift fix                          |
| Jest (API)                                          | Test runner for D-01 and D-02 regression tests in `vault.service.spec.ts` / `pending-unpin.processor.spec.ts` |
| Vitest (SDK)                                        | Test runner for D-03 regression test in `packages/sdk/src/__tests__/`                |

### Installation

No new packages to install.

## Package Legitimacy Audit

No external packages are introduced. Section not applicable.

## Architecture Patterns

### WR-01 Fix (D-01) — Drop `abs()` from advisory-lock hash

**File:** `apps/api/src/vault/vault.service.ts:262`

**Current live code (verified 2026-06-19):**
```typescript
// vault.service.ts:262
await manager.query(`SELECT pg_advisory_xact_lock(abs(hashtext($1))::bigint)`, [cid]);
```
The comment on the preceding line reads: `abs() avoids bigint-out-of-range on negative hashtext values (Pitfall 2)` — this comment is factually wrong (`pg_advisory_xact_lock` accepts signed bigint; `abs(int4)` is the overflow, not the fix). [VERIFIED: live code]

**Fix (per D-01 / 42-REVIEW.md):**
```typescript
await manager.query(`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, [cid]);
```
Drop `abs()` — `hashtext()` returns `int4`; casting directly to `bigint` sign-extends safely and eliminates the `int4` overflow for `INT_MIN`. Update the comment accordingly.

Alternative (per D-01 discretion): `abs(hashtext($1)::bigint)` — cast first, then abs on `bigint` which cannot overflow.

**Key note:** The existing `vault.service.spec.ts` test at line 1003 mocks `manager.query` to look for `sql.includes('pg_advisory_xact_lock')`, so the regression test must verify the SQL text does NOT contain `abs(` before the `hashtext`.

### WR-03 Fix (D-02) — Refcount re-check in drain loop

**File:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts:53–64`

**Current live drain loop (verified 2026-06-19, lines 53–65):**
```typescript
for (const row of rows) {
  try {
    await this.ipfsProvider.unpinFile(row.cid);
    await this.pendingUnpinRepository.delete({ cid: row.cid });
    this.logger.log(`Drained cid=${row.cid}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    this.logger.error(`Failed to drain cid=${row.cid}: ${message}`);
  }
}
```
No refcount check before `unpinFile`. `this.pinnedCidRepository` is injected (constructor line 24, field name `pinnedCidRepository`). [VERIFIED: live code]

**Fix (per D-02 / 42-REVIEW.md):**
```typescript
for (const row of rows) {
  try {
    const refs = await this.pinnedCidRepository.count({ where: { cid: row.cid } });
    if (refs > 0) {
      await this.pendingUnpinRepository.delete({ cid: row.cid });
      this.logger.log(`Drain: CID re-pinned, discarding stale outbox row cid=${row.cid}`);
      continue;
    }
    await this.ipfsProvider.unpinFile(row.cid);
    await this.pendingUnpinRepository.delete({ cid: row.cid });
    this.logger.log(`Drained cid=${row.cid}`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    this.logger.error(`Failed to drain cid=${row.cid}: ${message}`);
  }
}
```
The mock in `pending-unpin.processor.spec.ts` already defines `mockPinnedCidRepository` with a `find` method (line 22). Adding `count` to that mock is required; existing tests continue to pass when `count` returns 0.

### D-03 Fix — On-demand traversal in `collectSubtreeIpnsNames`

**File:** `packages/sdk/src/client.ts:230–243`

**Current live code (verified 2026-06-19):**
```typescript
// client.ts:230–243
private collectSubtreeIpnsNames(folderIpnsName: string, acc: string[] = []): string[] {
  acc.push(folderIpnsName);
  const folder = this.folderTree.get(folderIpnsName);
  if (!folder) return acc;  // ← early return; skips unloaded subtree

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
[VERIFIED: live code]

**The four deletion paths that call this (via `collectRemovedItemIpnsNames` / `collectBinEntryIpnsNames`):**
1. `deleteItem` → `collectRemovedItemIpnsNames` → `collectSubtreeIpnsNames` (line 856)
2. `permanentDelete` → `collectBinEntryIpnsNames` → `collectSubtreeIpnsNames` (line 1866)
3. `emptyBin` → `collectBinEntryIpnsNames` → `collectSubtreeIpnsNames` (line 1880)
4. `purgeExpired` → `collectBinEntryIpnsNames` → `collectSubtreeIpnsNames` (line 1927)

**Fetch + decrypt call path (D-03 locked):**

The existing `ensureFolderLoaded` DFS (lines 444–514) already implements:
- `sdkCore.loadFolderMetadata({ ipnsName, folderKey, ctx })` — fetches from IPNS + decrypts with folderKey
- `unwrapKey(hexToBytes(child.folderKeyEncrypted), this.internalVaultKeypair.privateKey)` — unwraps subfolder's folderKey
- `unwrapKey(hexToBytes(child.ipnsPrivateKeyEncrypted), ...) ` — unwraps subfolder's IPNS private key

The on-demand traversal for `collectSubtreeIpnsNames` must replicate this pattern. However, it must NOT mutate `folderTree` (fire-and-forget unenrollment is a side effect; writing to folderTree during a delete could cause desync with Zustand, per the web/SDK folderTree desync known issue). The traversal should keep loaded metadata in a local map, not the shared `folderTree`.

**Critical constraint:** `collectSubtreeIpnsNames` is currently synchronous. Making it on-demand requires making it `async`. All four callers in `fireAndForgetUnenroll` via `collectRemovedItemIpnsNames` / `collectBinEntryIpnsNames` need to be made async. `fireAndForgetUnenroll` itself wraps in a fire-and-forget `.catch()` so the caller (deleteItem, permanentDelete, etc.) stays synchronous. The cleanest shape:

```typescript
private async collectSubtreeIpnsNamesAsync(
  folderIpnsName: string,
  folderKey: Uint8Array,
  acc: string[] = []
): Promise<string[]> {
  acc.push(folderIpnsName);
  // Try in-memory first
  let children = this.folderTree.get(folderIpnsName)?.children;
  if (!children) {
    // On-demand fetch from IPNS
    try {
      const result = await sdkCore.loadFolderMetadata({
        ipnsName: folderIpnsName,
        folderKey,
        ctx: this.ctx,
      });
      children = result?.metadata.children;
    } catch {
      // Fetch/decrypt failure: log and skip this node's children
      // (must not abort the whole collection)
    }
  }
  if (!children) return acc;
  for (const child of children) {
    if (child.type === 'file') {
      acc.push((child as FilePointer).fileMetaIpnsName);
    } else if (child.type === 'folder') {
      const entry = child as FolderEntry;
      try {
        const subfKey = await unwrapKey(
          hexToBytes(entry.folderKeyEncrypted),
          this.internalVaultKeypair.privateKey
        );
        await this.collectSubtreeIpnsNamesAsync(entry.ipnsName, subfKey, acc);
      } catch {
        // Unwrap or child fetch failure: skip subtree, add IPNS name at minimum
        acc.push(entry.ipnsName);
      }
    }
  }
  return acc;
}
```

**FolderEntry key fields (from `packages/core/src/folder/types.ts`, verified 2026-06-19):**
- `ipnsName: string` — IPNS name for the subfolder
- `ipnsPrivateKeyEncrypted: string` — hex-encoded ECIES-wrapped Ed25519 private key
- `folderKeyEncrypted: string` — hex-encoded ECIES-wrapped AES-256 folder key
- `FolderMetadata.children: FolderChild[]` — after decryption, contains the subfolder's own children

**Key insight for callers:** `collectRemovedItemIpnsNames(item)` currently receives a `FolderChild`. If the item is a `FolderEntry`, its `folderKeyEncrypted` field IS available (it came from the parent's decrypted metadata). So the initial `folderKey` for the top-level deleted folder can be obtained by unwrapping `item.folderKeyEncrypted`. The same pattern propagates down through children.

**Do NOT mutate `folderTree`:** Fire-and-forget unenrollment happens after the deletion has been committed and metadata published. Writing stale loaded state back to `folderTree` during a fire-and-forget async traversal would cause the Zustand/SDK folderTree desync described in project memory. Use a local `loadedMetadata` map or discard after traversal.

### D-04 — Remaining WR/IN Items

Fix-or-accept status per finding (each must be resolved):

| Finding | File:line (live, 2026-06-19)                              | Status Required  | Prescribed patch in 42-REVIEW.md                                                            |
| ------- | --------------------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------- |
| WR-02   | `ipfs.controller.ts:119–130`, `vault.service.ts:248–251` | Fix              | On upload compensation no-row path: call `unpinFile` directly (or skip cross-user telemetry) |
| WR-04   | `pending-unpin.processor.ts:97`                           | Accept w/comment | Reviewed by author as acceptable; add comment explaining counter vs gauge tradeoff          |
| WR-05   | `scripts/backfill-pinned-cids.ts:132–141`                 | Fix              | Add `AND pc.pinned_at < NOW() - INTERVAL '1 hour'` age cutoff to candidate query           |
| WR-06   | `scripts/backfill-pinned-cids.ts:137`                     | Fix              | Change `false::boolean AS "isByoUser"` → `v.is_byo_user AS "isByoUser"`                    |
| WR-07   | `vault.service.ts:279–284`                                | Fix or accept    | If D-07 stands, document retention consequence in `docs/CAPACITY.md`; or filter BYO rows from refcount |
| IN-01   | `vault.service.ts:310`                                    | Fix              | Track row-deleted flag; increment `fileUnpins` only on actual deletion                     |
| IN-02   | `apps/api/src/ipfs/dto/unpin.dto.ts:9–11`                 | Fix              | Add `@Matches(/^(Qm...|b...)$/)` and `@MaxLength(255)` decorators; run `pnpm api:generate` |
| IN-03   | `vault.service.ts:317–322`                                | Fix              | Delete `recordUnpin` and its tests (or `@deprecated` with pointer to `guardedUnpin`)       |
| IN-04   | Three module files                                        | Accept w/comment | Comment explaining the cycle reason; or extract `IpfsProviderCoreModule`                   |
| IN-05   | `pending-unpin.processor.ts:84–91`                        | Fix              | Build `dbCids` from non-BYO `pinned_cids` only (consistent with WR-07 resolution)         |
| IN-06   | `vault.service.ts:295`                                    | Fix              | Rename `outboxRowInserted` → `shouldAttemptPhysicalUnpin`                                  |

**`pnpm api:generate` requirement:** IN-02 adds validation decorators to `UnpinDto`. That DTO is in the OpenAPI spec. Any change to `unpin.dto.ts` is an API endpoint change and requires `pnpm api:generate` + committing the regenerated client alongside the change.

### Anti-Patterns to Avoid

- **Do not call `abs(int4)` before casting to bigint:** The overflow happens at the `int4` level. `abs(hashtext($1))::bigint` is wrong. `hashtext($1)::bigint` or `abs(hashtext($1)::bigint)` are both correct.
- **Do not mutate `folderTree` in the on-demand traversal:** The traversal happens fire-and-forget after deletion. Writing stale IPNS snapshots back to `folderTree` causes the desync described in project memory (Zustand store and SDK client holding different state → stale sequence 409 on next publish).
- **Do not abort the unenroll traversal on single-child failure:** A fetch/decrypt failure on one child folder must not prevent unenrolling the rest of the subtree. Each child's failure must be caught and logged independently.

## Don't Hand-Roll

| Problem                          | Don't Build                                      | Use Instead                                         | Why                                      |
| -------------------------------- | ------------------------------------------------ | --------------------------------------------------- | ---------------------------------------- |
| IPNS resolve + metadata decrypt  | Custom HTTP fetch to IPNS endpoint               | `sdkCore.loadFolderMetadata`                        | Already handles IPNS resolution, DB-first strategy, AES-256-GCM decrypt, timeout |
| Subfolder key unwrap             | Raw ECIES implementation                         | `unwrapKey` from `@cipherbox/crypto`                | Tested against cross-language vectors    |
| Advisory lock key                | Custom hash                                      | `hashtext($1)::bigint` (PostgreSQL built-in)        | Standard PostgreSQL; just remove `abs()` |
| Refcount check in drain          | Custom SQL query                                 | `this.pinnedCidRepository.count({ where: { cid } })`| TypeORM repository is already injected  |

## Common Pitfalls

### Pitfall 1: `abs(int4)` overflow for INT_MIN

**What goes wrong:** `abs(hashtext($1))::bigint` applies `abs` to the `int4` return value of `hashtext()`. PostgreSQL raises `ERROR: integer out of range` when hashtext returns `-2147483648` (INT_MIN). The cast to bigint happens AFTER abs, so the int4 overflow fires first.
**Why it happens:** The code comment says `abs()` avoids bigint-out-of-range, but `pg_advisory_xact_lock` accepts signed bigint — the comment is backwards.
**How to avoid:** `hashtext($1)::bigint` — cast int4 to bigint first (sign-extends safely). Or `abs(hashtext($1)::bigint)` if a non-negative key is desired.

### Pitfall 2: Drain window vs. inline Kubo window

**What goes wrong:** The D-13 comment in `ipfs.controller.ts:123` argues the re-pin race is negligible because it requires "identical ciphertext + sub-second window." That argument covers the **inline Kubo call** immediately after `recordPin`. It does not cover the **drain worker**: the drain window is ≥ 5 minutes (BullMQ retry interval) and unbounded while Kubo is down.
**How to avoid:** The refcount re-check (D-02) is specifically for the drain path; it does not need to be applied to the inline post-commit path in `guardedUnpin`.

### Pitfall 3: On-demand traversal must NOT treat `loadFolderMetadata` returning null as an error

**What goes wrong:** If an IPNS record has not been published yet (e.g. a folder was created but the IPNS publish failed), `loadFolderMetadata` returns `null`. Treating null as a hard failure would abort unenrollment of the siblings.
**How to avoid:** When `loadFolderMetadata` returns `null`, push the folder's own IPNS name to the acc (it was already pushed at the top), log a warning, and continue. Don't recurse into children.

### Pitfall 4: Making `collectSubtreeIpnsNames` async changes all four callers

**What goes wrong:** The sync signature `collectSubtreeIpnsNames(name, acc): string[]` is called from `collectRemovedItemIpnsNames` and `collectBinEntryIpnsNames`, which are called from `fireAndForgetUnenroll`-adjacent code in all four deletion paths. Making it async cascades to those helpers.
**How to avoid:** The safest approach is to add a new async method alongside the existing sync one (or replace it). `fireAndForgetUnenroll` currently takes `string[]` — it should be refactored to take a `Promise<string[]>` or the call sites should `Promise.resolve(asyncCollect).then(names => fireAndForgetUnenroll(names))` so the caller stays synchronous.

## Runtime State Inventory

Phase 50 is a code fix, not a rename/refactor/migration. No runtime state inventory is required. The DB schema is unchanged (no new tables/columns). The SDK fix is purely in-memory traversal logic.

## Code Examples

### Regression test structure for WR-01 (INT_MIN CID undeletability) — Jest

Follows `vault.service.spec.ts` pattern: `describe('guardedUnpin')`, mock `mockManager.query` to throw when SQL contains `abs(hashtext` and confirm the current code throws, OR verify the new code with the fix does NOT throw for any `int4` hashtext value:

```typescript
// vault.service.spec.ts — add to describe('guardedUnpin')
it('WR-01: advisory lock query must not use abs(int4) form', async () => {
  // Verify the SQL issued does not apply abs() to int4 hashtext
  // (would overflow for CID with hashtext == INT_MIN)
  mockManagerPinnedCidRepo.findOne.mockResolvedValue(mockPinnedRow);
  mockManagerQueryBuilder.getRawOne.mockResolvedValue({ count: '0' });
  mockIpfsProvider.unpinFile.mockResolvedValue(undefined);

  let capturedSql = '';
  mockManager.query.mockImplementation((sql: string) => {
    capturedSql = sql;
    return Promise.resolve([]);
  });

  await service.guardedUnpin(testUserId, testCid);

  // Must NOT apply abs() to int4 (safe form: hashtext($1)::bigint)
  expect(capturedSql).toMatch(/pg_advisory_xact_lock/);
  expect(capturedSql).not.toMatch(/abs\(hashtext/);
});
```

### Regression test structure for WR-03 (re-pin during drain) — Jest

Follows `pending-unpin.processor.spec.ts` pattern: mock `mockPinnedCidRepository.count` to return `> 0` for one CID and verify `unpinFile` is NOT called for it:

```typescript
// pending-unpin.processor.spec.ts — add new describe block
describe('drain: skips unpin when CID is re-pinned (WR-03)', () => {
  it('does NOT call unpinFile when pinnedCidRepository.count > 0', async () => {
    const row = { id: 'uuid-wr03', cid: 'cidRePinned', createdAt: new Date() } as PendingUnpin;
    mockPendingUnpinRepository.find.mockResolvedValue([row]);
    // CID is in pinned_cids again (re-uploaded while in outbox)
    mockPinnedCidRepository.count = jest.fn().mockResolvedValue(1);
    mockPendingUnpinRepository.delete.mockResolvedValue({ affected: 1 });
    mockPendingUnpinRepository.count.mockResolvedValue(0);

    await processor.process(makeJob('drain-pending-unpins'));

    // Must NOT unpin a live-pinned CID
    expect(mockIpfsProvider.unpinFile).not.toHaveBeenCalled();
    // Stale outbox row must still be cleaned up
    expect(mockPendingUnpinRepository.delete).toHaveBeenCalledWith({ cid: 'cidRePinned' });
  });
});
```

Note: `mockPinnedCidRepository` in the spec currently has `find` and `query` (lines 21–24). Add `count: jest.fn()` to the mock definition.

### D-03 on-demand traversal regression test — Vitest (SDK)

Follows `ensure-folder-loaded.test.ts` pattern: mock `sdkCore.loadFolderMetadata` per IPNS name, create a client with a root folder in folderTree containing a subfolder entry, but do NOT add the subfolder to folderTree:

```typescript
// new file: packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts
// (or add to client.test.ts)
// vi.mock('@cipherbox/sdk-core') + vi.mock('@cipherbox/crypto') as in ensure-folder-loaded.test.ts
it('collects IPNS names from unloaded subfolder by fetching on demand', async () => {
  // Setup: parent folder in folderTree, child subfolder NOT in folderTree
  // loadFolderMetadata returns child's metadata when called with child.ipnsName
  // Assert: returned acc contains both parent and child IPNS names + child file IPNS name
});
it('a fetch failure on one child does not abort collection of siblings', async () => {
  // loadFolderMetadata rejects for child B; assert child A's names still collected
});
```

### How to run a single spec

```bash
# API (Jest)
pnpm --filter @cipherbox/api test -- --testPathPattern="vault.service.spec"
pnpm --filter @cipherbox/api test -- --testPathPattern="pending-unpin.processor.spec"

# SDK (Vitest)
pnpm --filter @cipherbox/sdk test -- collect-subtree-ipns-names
```

## Validation Architecture

### Test Framework

| Property           | Value                                                                     |
| ------------------ | ------------------------------------------------------------------------- |
| API framework      | Jest (apps/api) — `pnpm --filter @cipherbox/api test`                    |
| SDK framework      | Vitest (packages/sdk) — `pnpm --filter @cipherbox/sdk test`              |
| Config file (API)  | `apps/api/jest.config.js`                                                 |
| Config file (SDK)  | `packages/sdk/vitest.config.ts`                                           |
| Quick run (API)    | `pnpm --filter @cipherbox/api test -- --testPathPattern="vault.service.spec"` |
| Quick run (SDK)    | `pnpm --filter @cipherbox/sdk test -- collect-subtree`                    |
| Full suite         | `pnpm test` (parallel workspace)                                          |

### Phase Requirements → Test Map

| Req ID  | Behavior                                                                                   | Test Type   | Automated Command                                                                           | File Exists?         |
| ------- | ------------------------------------------------------------------------------------------ | ----------- | ------------------------------------------------------------------------------------------- | -------------------- |
| HARD-01 | INT_MIN hashtext CID does not cause SQL overflow in advisory lock                          | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern="vault.service.spec"`              | Partial (add test)   |
| HARD-01 | Re-pinned CID is not physically unpinned during drain                                      | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern="pending-unpin.processor.spec"`    | Partial (add test)   |
| HARD-01 | Full-subtree IPNS names collected when subfolder is not in folderTree (on-demand traversal) | unit        | `pnpm --filter @cipherbox/sdk test -- collect-subtree`                                     | No — Wave 0 gap      |
| HARD-01 | Single child fetch failure does not abort sibling collection                               | unit        | `pnpm --filter @cipherbox/sdk test -- collect-subtree`                                     | No — Wave 0 gap      |

### Sampling Rate

- **Per task commit:** Run the single spec for that task's file
- **Per wave merge:** Full `pnpm test` (both Jest and Vitest suites)
- **Phase gate:** Full suite green before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts` — covers D-03 on-demand traversal (new file)
- [ ] `mockPinnedCidRepository.count` added to `pending-unpin.processor.spec.ts` mock definition — covers D-02 WR-03 test

_(API test file `vault.service.spec.ts` and `pending-unpin.processor.spec.ts` already exist; new `it()` blocks are additive, not new files)_

## Security Domain

### Applicable ASVS Categories

| ASVS Category       | Applies | Standard Control                                                                            |
| ------------------- | ------- | ------------------------------------------------------------------------------------------- |
| V2 Authentication   | no      | —                                                                                           |
| V3 Session Management | no    | —                                                                                           |
| V4 Access Control   | yes     | WR-07 — BYO advisory rows allowing non-owner to block physical unpin is an access-control gap |
| V5 Input Validation | yes     | IN-02 — `UnpinDto.cid` lacks CID format validation; add `@Matches` + `@MaxLength(255)`     |
| V6 Cryptography     | partial | D-03 traversal unwraps `folderKeyEncrypted` via ECIES — must use `unwrapKey`, never hand-roll |

### Known Threat Patterns for this stack

| Pattern                                   | STRIDE      | Standard Mitigation                                                       |
| ----------------------------------------- | ----------- | ------------------------------------------------------------------------- |
| BYO CID registration blocks hosted unpin  | Denial (WR-07) | Filter BYO rows from refcount or document the retention consequence in CAPACITY.md |
| Upload compensation fires cross-user alert | Spoofing (WR-02) | `suppressCrossUserAudit` flag (already wired); compensation path must use direct `unpinFile` for the no-row case |
| Oversized CID string in unpin request     | DoS (IN-02) | `@MaxLength(255)` + `@Matches` CID regex on `UnpinDto.cid`              |

## Assumptions Log

No `[ASSUMED]` claims in this research. All findings verified against live code at the cited line numbers on 2026-06-19.

| # | Claim | Section | Risk if Wrong |
| - | ----- | ------- | ------------- |

**This table is empty:** All claims in this research were verified against live files.

## Open Questions (RESOLVED)

1. **WR-07 (BYO blocks physical unpin) — fix or accept?**
   - What we know: the D-04 context says "fix unless there is a strong rationale to accept." Filtering BYO rows from the hosted refcount requires updating the `guardedUnpin` query AND the drift `dbCids` set (IN-05) consistently.
   - What's unclear: whether the product intends BYO advisory rows to block hosted-pin deletion (it currently does, by design per D-07).
   - Recommendation: At minimum document the retention consequence in `docs/CAPACITY.md` with an inline comment in `vault.service.ts:279-284`. The Claude's Discretion section does not lock this.
   - **RESOLVED:** in plan **50-04** (Task 2). Default disposition is ACCEPT-with-documentation rather than fix, because filtering BYO rows from the hosted refcount is a behavior change that ripples into IN-05 and contradicts the original D-07 design intent. 50-04 adds an inline accept-comment at `vault.service.ts:279-284` citing WR-07 (BYO advisory rows intentionally block physical unpin of hosted content per D-07) plus a "Retention consequence of BYO advisory rows" subsection in `docs/CAPACITY.md`, and keeps IN-05's `dbCids` drift set consistent (comment noting it intentionally includes BYO rows to mirror the refcount semantics). The plan leaves the FIX path (a refcount predicate excluding BYO rows + matching IN-05 filter) available if execution chooses it, but records ACCEPT as the recommended, lower-risk default; the chosen disposition is recorded in 50-04-SUMMARY.md.

2. **D-03 on-demand traversal — async signature impact**
   - What we know: `collectSubtreeIpnsNames` is currently synchronous; making it async changes the call chain through `collectRemovedItemIpnsNames`, `collectBinEntryIpnsNames`, and ultimately the fire-and-forget pattern at all four deletion paths.
   - What's unclear: Whether to add a parallel async method or rename-and-convert. The planner should decide based on the test conventions in `ensure-folder-loaded.test.ts`.
   - Recommendation: Add a new `async collectSubtreeIpnsNamesAsync(folderIpnsName, folderKey)` and convert the four call sites to `Promise<string[]>`, resolving before passing to `fireAndForgetUnenroll`.
   - **RESOLVED:** in plan **50-03** (Task 2). The decision is the new-method approach: add a new `private async collectSubtreeIpnsNamesAsync(folderIpnsName: string, folderKey: Uint8Array, acc?: string[]): Promise<string[]>` that fetches+decrypts persisted child metadata via `sdkCore.loadFolderMetadata` on a folderTree miss (and does NOT mutate `folderTree`). `collectRemovedItemIpnsNames` and `collectBinEntryIpnsNames` become async (`Promise<string[]>`), and all four deletion call sites — `deleteItem` (~:856), `permanentDelete` (~:1866), `emptyBin` (~:1880), `purgeExpired` (~:1927) — resolve the promise before calling `fireAndForgetUnenroll`, preserving the synchronous fire-and-forget contract. The obsolete synchronous `collectSubtreeIpnsNames` is removed in favor of the single async path.

## Environment Availability

Step 2.6: SKIPPED (no new external dependencies — all tools and services are already part of the running stack). PostgreSQL, Kubo, NestJS, and the SDK test runners are already present.

## Sources

### Primary (HIGH confidence — live code)

- `apps/api/src/vault/vault.service.ts:262` — advisory lock hash (WR-01, D-01)
- `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts:45–70` — drain loop (WR-03, D-02)
- `packages/sdk/src/client.ts:230–243` — `collectSubtreeIpnsNames` (D-03)
- `packages/sdk/src/client.ts:444–514` — `ensureFolderLoaded` DFS (traversal pattern for D-03)
- `packages/sdk/src/client.ts:370–420` — `loadFolder` (uses `sdkCore.loadFolderMetadata`)
- `packages/core/src/folder/types.ts:31–47` — `FolderEntry` type with `folderKeyEncrypted` / `ipnsPrivateKeyEncrypted`
- `packages/sdk-core/src/folder/index.ts:73–94` — `loadFolderMetadata` signature and return type
- `apps/api/src/vault/vault.service.spec.ts:918–1033` — existing `guardedUnpin` test patterns
- `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts:1–198` — existing processor test patterns
- `packages/sdk/src/__tests__/ensure-folder-loaded.test.ts` — vitest mock patterns for DFS tests
- `apps/api/src/ipfs/dto/unpin.dto.ts` — IN-02 missing validation (confirmed)
- `scripts/backfill-pinned-cids.ts:132–141` — WR-05/WR-06 confirmed present
- `apps/api/src/ipfs/ipfs.controller.ts:119–130` — WR-02 upload compensation confirmed
- `.planning/phases/42-api-unpin-integrity/42-REVIEW.md` — authoritative finding list + patches
- `.planning/todos/pending/2026-06-18-phase42-unpin-integrity-review-open-findings.md` — re-verification 2026-06-18
- `.planning/todos/pending/2026-06-18-unenroll-skips-unloaded-subtrees.md` — D-03 source todo

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — no new packages; all libraries verified in live files
- Architecture: HIGH — exact live line numbers cited; patch patterns are explicit in 42-REVIEW.md
- Pitfalls: HIGH — root causes confirmed by reading both the bug (current code) and the fix path (ensureFolderLoaded pattern)

**Research date:** 2026-06-19
**Valid until:** 2026-07-03 (30 days — stable codebase, no fast-moving upstream deps)

---

## RESEARCH COMPLETE

**Phase:** 50 - IPFS/IPNS Data-Integrity Fixes
**Confidence:** HIGH

### Key Findings

- WR-01 confirmed live at `vault.service.ts:262`: `abs(hashtext($1))::bigint` — the `abs()` is applied to `int4` before the bigint cast, producing INT_MIN overflow. Fix: remove `abs()` or cast first.
- WR-03 confirmed live at `pending-unpin.processor.ts:53–58`: `drainPendingUnpins` calls `unpinFile` unconditionally with no refcount check. `pinnedCidRepository` is already injected (field `pinnedCidRepository`); adding `count({ where: { cid } })` before unpin is the complete fix.
- `collectSubtreeIpnsNames` at `client.ts:230–243` confirmed: returns early on `folderTree.get() === undefined`. The on-demand traversal reuses `sdkCore.loadFolderMetadata` (same call as `loadFolder` + `ensureFolderLoaded`) plus `unwrapKey` from `@cipherbox/crypto`. Must NOT mutate `folderTree`.
- All 13 WR/IN findings remain unresolved in current code. WR-04 is the only one judged acceptable; the rest require either fix or explicit accept-with-comment.
- `pnpm api:generate` is required if IN-02 adds decorators to `UnpinDto` — DTO change triggers OpenAPI spec regen and API client rebuild.

### File Created

`.planning/phases/50-ipfs-ipns-data-integrity-fixes/50-RESEARCH.md`

### Confidence Assessment

| Area                         | Level | Reason                                                           |
| ---------------------------- | ----- | ---------------------------------------------------------------- |
| Standard Stack               | HIGH  | No new packages; all existing libs verified in live code         |
| Architecture (API fixes)     | HIGH  | Exact SQL and TypeScript lines cited from live files             |
| Architecture (SDK D-03)      | HIGH  | `ensureFolderLoaded` DFS is a direct template for the traversal  |
| Pitfalls                     | HIGH  | Root causes confirmed by reading both the bug and the fix path   |

### Open Questions

- WR-07: fix (filter BYO from refcount) vs. accept (document in CAPACITY.md) — planner or user decides
- D-03 async signature: new method vs. rename-and-convert — planner discretion

### Ready for Planning

Research complete. Planner can now create PLAN.md files.
