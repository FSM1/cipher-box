# Phase 27: Writable Shares (PoC) - Research

**Researched:** 2026-03-26
**Domain:** Extending read-only sharing to read-write; IPNS key delivery, multi-writer authorization, conflict resolution
**Confidence:** HIGH

## Summary

Phase 27 extends the existing Phase 14 read-only sharing system to support read-write shares. The architecture is well-constrained by user decisions: ECIES-wrap the folder's IPNS private key alongside the existing folderKey, add a `permission` field to the Share entity, expand IPNS publish authorization to include share-authorized writers, and conditionally enable write actions in the SharedFileBrowser UI.

The key insight is that CipherBox's server-relayed IPNS architecture already solves the "multi-writer IPNS" problem. The server is the coordination point for sequence numbers (optimistic concurrency via `expectedSequenceNumber` / 409 conflict detection). Write-share recipients simply need: (1) the IPNS signing key to produce valid records, and (2) server authorization to publish to the shared IPNS name. The existing `withConflictRetry` logic handles multi-writer conflicts identically to multi-device sync.

The implementation is primarily a schema extension (2 new columns, 1 new DTO field), an authorization expansion in `IpnsService.upsertFolderIpns()`, and conditional UI unlocking in `SharedFileBrowser`. No new crypto primitives, no new sync infrastructure, no new conflict resolution logic.

**Primary recommendation:** Layer the new functionality on existing patterns -- add `permission` and `encryptedIpnsKey` columns to the Share entity, expand the IPNS publish authorization check from `userId === owner` to `userId === owner || (activeWriteShare exists)`, and conditionally toggle `readOnly` props in the UI based on `share.permission`.

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **IPNS key delivery:** ECIES-wrap the folder's IPNS private key with the recipient's secp256k1 public key, delivered alongside the existing folderKey. New `encryptedIpnsKey` column on Share entity (NULL for read-only, populated for write). Write-share recipients derive child IPNS keypairs via HKDF. Write-share recipients can enroll new subfolders with TEE.
- **Write scope:** Full CRUD within shared tree. No re-sharing (owner only). Deleted items go to owner's recycle bin. Owner can upgrade (read->write) or downgrade (write->read) in-place.
- **Permission model:** New `permission: 'read' | 'write'` field on Share entity (default `'read'`). IPNS publish endpoint expanded: owner always, write-share recipients for shared IPNS names, read-only cannot. Permission toggle in share dialog. Default is read-only.
- **Share dialog & UI:** Permission toggle between pubkey input and share button. Recipients list shows permission per recipient. `[RW]` badge replaces `[RO]` for write shares. Write-share recipients see full toolbar and context menu.
- **Conflict resolution & sync:** No attribution. Last-writer-wins, same sync banner. Same 30s polling. Existing `withConflictRetry` handles multi-writer identically to multi-device.
- **Revocation:** Write revoke = silent downgrade to read-only. Lazy IPNS keypair rotation. Server rejects publishes from revoked users immediately.

### Claude's Discretion

- Exact migration strategy for `permission` column and `encryptedIpnsKey` column
- Backend authorization query pattern (join shares table in publish flow, or preload)
- How permission upgrade/downgrade is presented in the share management UI
- TEE enrollment endpoint authorization changes
- E2E test strategy for multi-writer conflict scenarios

### Deferred Ideas (OUT OF SCOPE)

- Metadata-embedded sharing (move share data to IPFS to hide social graph)
- Attribution / audit trail (lastModifiedBy pubkey)
- Transitive re-sharing
- Faster sync for shared folders (reduced poll interval)
- Immediate IPNS key rotation on revoke
- Share notifications

</user_constraints>

## Standard Stack

### Core

No new libraries needed. Phase 27 exclusively uses existing stack.

| Library               | Version  | Purpose                      | Why Standard                            |
| --------------------- | -------- | ---------------------------- | --------------------------------------- |
| TypeORM               | existing | DB migration, entity columns | Already manages Share/ShareKey entities |
| @cipherbox/crypto     | existing | ECIES wrapKey/unwrapKey      | Already wraps folderKeys for sharing    |
| @cipherbox/core       | existing | FolderMetadata types         | Already used by SharedFileBrowser       |
| @cipherbox/api-client | existing | Generated API client         | Regenerated after DTO changes           |

### Supporting

| Library         | Version  | Purpose               | When to Use                                       |
| --------------- | -------- | --------------------- | ------------------------------------------------- |
| class-validator | existing | DTO validation        | New fields on CreateShareDto, UpdatePermissionDto |
| eciesjs         | existing | ECIES encrypt/decrypt | Wrap IPNS private keys for recipients             |

### Alternatives Considered

None -- all decisions are locked to existing stack.

## Architecture Patterns

### Recommended Change Structure

```
apps/api/src/
  shares/
    entities/share.entity.ts         # Add permission, encryptedIpnsKey columns
    dto/create-share.dto.ts          # Add permission, encryptedIpnsKey fields
    dto/update-permission.dto.ts     # NEW: permission upgrade/downgrade DTO
    shares.service.ts                # updatePermission method
    shares.controller.ts             # PATCH :shareId/permission endpoint
  ipns/
    ipns.service.ts                  # Authorization expansion in upsertFolderIpns
  republish/
    republish.service.ts             # TEE enrollment auth expansion
  migrations/
    174XXXXXXXX-AddWritableShares.ts  # NEW: ALTER TABLE shares ADD permission, encrypted_ipns_key

apps/web/src/
  stores/share.store.ts              # Add permission field to ReceivedShare/SentShare
  hooks/useSharedNavigation.ts       # Expose IPNS key + permission for write ops
  components/file-browser/
    SharedFileBrowser.tsx            # Conditional write UI based on permission
    ShareDialog.tsx                  # Permission toggle in share creation
```

### Pattern 1: Authorization Expansion in IPNS Publish

**What:** The critical authorization change is in `IpnsService.upsertFolderIpns()` (line 179). Currently it looks up by `(userId, ipnsName)`. For write shares, the recipient's userId won't match the folder_ipns owner. The service needs a fallback: if `getFolderIpns(userId, ipnsName)` returns null, check if an active write share exists for this user and ipnsName.

**When to use:** Every IPNS publish by a write-share recipient.

**Implementation approach:**

```typescript
// In IpnsService.upsertFolderIpns()
private async upsertFolderIpns(
  userId: string,
  ipnsName: string,
  metadataCid: string,
  ...
): Promise<FolderIpns> {
  // 1. Try direct ownership first (existing path)
  let existing = await this.getFolderIpns(userId, ipnsName);

  // 2. If not owner, check for write share authorization
  if (!existing) {
    const writeShare = await this.sharesService.findActiveWriteShare(userId, ipnsName);
    if (!writeShare) {
      throw new ForbiddenException('Not authorized to publish to this IPNS name');
    }
    // Look up the actual FolderIpns record by owner
    existing = await this.folderIpnsRepository.findOne({ where: { ipnsName } });
    if (!existing) {
      throw new NotFoundException('IPNS name not found');
    }
  }

  // 3. Rest of the method unchanged (sequence check, update, publish)
}
```

**Key detail:** The `FolderIpns` entity has a unique constraint on `(userId, ipnsName)`. A write-share recipient's publish updates the _owner's_ FolderIpns row, not a new row. This ensures sequence number coordination works correctly between owner and all writers.

### Pattern 2: IPNS Key Wrapping for Write Shares

**What:** When creating a write share, the sharer wraps the folder's IPNS private key with the recipient's public key (same ECIES pattern as folderKey wrapping) and stores it in `encryptedIpnsKey` on the Share record.

**When to use:** Only when `permission === 'write'` during share creation or upgrade.

**Implementation approach:**

```typescript
// In ShareDialog.tsx handleShare(), after wrapping folderKey:
if (permission === 'write') {
  // Get the folder's IPNS private key
  const folderNode = useFolderStore.getState().folders[item.id];
  if (!folderNode?.ipnsPrivateKey) {
    // Unwrap from FolderEntry's ipnsPrivateKeyEncrypted
    const ipnsPrivKey = await unwrapKey(
      hexToBytes(folderEntry.ipnsPrivateKeyEncrypted),
      ownerPrivateKey
    );
    try {
      const wrappedIpnsKey = await wrapKey(ipnsPrivKey, recipientPubKeyBytes);
      encryptedIpnsKey = bytesToHex(wrappedIpnsKey);
    } finally {
      ipnsPrivKey.fill(0);
    }
  }
}
```

### Pattern 3: Recipient-Side Write Operations

**What:** When a write-share recipient performs CRUD (upload, create folder, rename, delete), they need: the folder's IPNS private key (to sign records), the folder key (to encrypt/decrypt metadata), and the current sequence number (for conflict detection).

**When to use:** Any write operation within a shared folder with `permission === 'write'`.

**Critical detail:** The `SharedFileBrowser` currently uses `useSharedNavigation` which is read-only. For write shares, the component needs to import the same write operations from `useFolderMutations` but parameterized with the share's keys instead of the vault's keys. The cleanest approach:

1. `useSharedNavigation` exposes `ipnsPrivateKey` (unwrapped from `share.encryptedIpnsKey`) alongside `folderKey`
2. `SharedFileBrowser` conditionally renders upload/create/rename/delete controls based on `share.permission === 'write'`
3. Write operations use the standard SDK-core functions (`updateFolderMetadataAndPublish`, `createSubfolder`, etc.) with the share's keys

### Pattern 4: Permission Upgrade/Downgrade

**What:** Owner can change a share's permission in-place via `PATCH /shares/:shareId/permission`.

**Upgrade (read -> write):**

1. Client wraps IPNS private key for recipient, sends to API
2. API updates `permission = 'write'` and `encrypted_ipns_key = <wrapped key>`
3. Recipient sees `[RW]` on next poll

**Downgrade (write -> read):**

1. Client sends `PATCH` with `permission = 'read'`
2. API updates `permission = 'read'` and `encrypted_ipns_key = NULL`
3. Server immediately rejects future publishes from this recipient
4. Lazy IPNS keypair rotation on next owner modification (same as Phase 14 revoke)
5. Recipient sees `[RO]` on next poll, write actions disappear silently

### Anti-Patterns to Avoid

- **Creating a separate FolderIpns row for share recipients:** Don't give each writer their own `folder_ipns` row. The sequence number must be coordinated through a single row. Use the owner's row with expanded authorization.
- **Duplicating write operation code:** Don't copy `useFolderMutations` for shared writes. Parameterize the existing SDK-core functions with share keys.
- **Wrapping IPNS key in ShareKey table:** Don't use the `share_keys` table for the IPNS key. It belongs on the Share record directly because it's a share-level permission artifact, not per-item key material.
- **Blocking on IPNS key availability for read shares:** Don't change the read-only share flow. `encryptedIpnsKey` is NULL for read-only shares -- the recipient never needs it.

## Don't Hand-Roll

| Problem             | Don't Build              | Use Instead                                                                         | Why                                                               |
| ------------------- | ------------------------ | ----------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| ECIES key wrapping  | Custom key exchange      | `wrapKey()` / `unwrapKey()` from `@cipherbox/crypto`                                | Already supports arbitrary key material (32-byte Ed25519 seeds)   |
| Conflict detection  | Custom sequence tracking | Existing `expectedSequenceNumber` + 409 in `upsertFolderIpns`                       | Server-side optimistic concurrency already works for multi-device |
| Conflict retry      | Custom retry logic       | `withConflictRetry()` from `folder-helpers.ts`                                      | Same pattern handles multi-writer identically to multi-device     |
| IPNS record signing | Custom signing           | `createAndPublishIpnsRecord()` from `sdk-core/ipns`                                 | Already handles Ed25519 signing + relay                           |
| Migration patterns  | Auto-sync schema changes | TypeORM migration with `IF NOT EXISTS` + `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` | Required for staging/production (synchronize: false)              |

**Key insight:** This phase introduces no new crypto primitives, no new sync patterns, and no new conflict resolution. Every building block already exists.

## Common Pitfalls

### Pitfall 1: FolderIpns Lookup by Wrong UserId

**What goes wrong:** Write-share recipient tries to publish, `getFolderIpns(recipientUserId, ipnsName)` returns null because the row belongs to the owner. The publish silently fails or creates a duplicate row.

**Why it happens:** The existing code assumes `userId` on `folder_ipns` always matches the authenticated user making the publish request.

**How to avoid:** The authorization expansion must look up the FolderIpns row by `ipnsName` alone (after verifying write-share authorization), NOT by `(recipientUserId, ipnsName)`.

**Warning signs:** Publish calls from share recipients return 404 or create new rows with wrong userId.

### Pitfall 2: Sequence Number Desync Between Owner and Writer

**What goes wrong:** Owner and writer each track their own local sequence number. After a write by the other party, the local copy is stale, causing 409 on next write.

**Why it happens:** The recipient's SharedFileBrowser doesn't poll for updates the same way the owner's FileBrowser does.

**How to avoid:** Write-share recipients MUST poll the shared folder at 30s intervals (same as owner's multi-device sync). The SharedFileBrowser already resolves IPNS on navigation -- it needs to periodically re-resolve. The existing `withConflictRetry` handles 409 correctly: re-sync (resolve IPNS, decrypt metadata), retry once.

**Warning signs:** Frequent 409 errors for shared folder operations.

### Pitfall 3: IPNS Key Not Available in SharedFileBrowser

**What goes wrong:** The `useSharedNavigation` hook unwraps `folderKey` from the share record but never unwraps `encryptedIpnsKey`. Write operations fail because there's no IPNS private key available.

**Why it happens:** Phase 14 only delivered folderKey because reads don't need the signing key.

**How to avoid:** Extend `useSharedNavigation` to also unwrap `encryptedIpnsKey` when `share.permission === 'write'`, storing the IPNS private key alongside folderKey in component state. Zero it on unmount.

**Warning signs:** Write operations in shared folders fail with "IPNS key not available".

### Pitfall 4: Migration Column Ordering

**What goes wrong:** Migration adds `encrypted_ipns_key` column but doesn't have an earlier timestamp than any migration that references it.

**Why it happens:** CipherBox follows strict migration timestamp ordering (see `docs/DATABASE_EVOLUTION_PROTOCOL.md`).

**How to avoid:** Use a timestamp after the last existing migration (1742000000000) with `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` for idempotency. Single migration for both new columns.

**Warning signs:** Migration fails on staging because column already exists (from synchronize:true in dev).

### Pitfall 5: TEE Enrollment for Share-Created Subfolders

**What goes wrong:** A write-share recipient creates a subfolder and generates a new IPNS keypair. They enroll it with TEE for republishing. But the TEE enrollment endpoint (`RepublishService.enrollFolder()`) only accepts the owner's userId -- the recipient's enrollment is rejected or creates an orphaned enrollment row.

**Why it happens:** TEE enrollment tracks `userId` to associate with the IPNS record owner.

**How to avoid:** When a write-share recipient creates a subfolder, they should enroll it under the _owner's_ userId (available from the share record), not their own. The API endpoint that accepts TEE enrollment needs to verify the caller has write-share authorization for the parent IPNS name.

**Warning signs:** Subfolders created by share recipients stop getting TEE-republished after the initial publish.

### Pitfall 6: API Client Regeneration

**What goes wrong:** New DTO fields (`permission`, `encryptedIpnsKey`) are added to the API but the web app doesn't see them.

**Why it happens:** CipherBox uses `pnpm api:generate` to regenerate the typed API client after endpoint/DTO changes.

**How to avoid:** Run `pnpm api:generate` after modifying any DTOs or controllers. Commit the regenerated files.

**Warning signs:** TypeScript compilation errors in web app for new API fields.

## Code Examples

### Share Entity with Permission and IPNS Key

```typescript
// apps/api/src/shares/entities/share.entity.ts
// Source: Existing share.entity.ts + new columns

/**
 * Permission level: 'read' for read-only, 'write' for full CRUD.
 * Default 'read' ensures backward compatibility with existing shares.
 */
@Column({ type: 'varchar', length: 10, default: 'read' })
permission!: 'read' | 'write';

/**
 * ECIES-wrapped IPNS private key for write shares.
 * Wrapped with recipient's secp256k1 public key.
 * NULL for read-only shares (recipients don't need signing capability).
 */
@Column({ type: 'bytea', name: 'encrypted_ipns_key', nullable: true })
encryptedIpnsKey!: Buffer | null;
```

### Migration Pattern

```typescript
// apps/api/src/migrations/1743000000000-AddWritableShares.ts
// Source: Follows 1740250000000-AddSharesTables.ts pattern

export class AddWritableShares1743000000000 implements MigrationInterface {
  name = 'AddWritableShares1743000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add permission column with default 'read' for backward compatibility
    await queryRunner.query(`
      ALTER TABLE "shares"
      ADD COLUMN IF NOT EXISTS "permission" varchar(10) NOT NULL DEFAULT 'read'
    `);

    // Add encrypted IPNS key column (nullable -- NULL for read-only shares)
    await queryRunner.query(`
      ALTER TABLE "shares"
      ADD COLUMN IF NOT EXISTS "encrypted_ipns_key" bytea
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "shares" DROP COLUMN IF EXISTS "encrypted_ipns_key"`);
    await queryRunner.query(`ALTER TABLE "shares" DROP COLUMN IF EXISTS "permission"`);
  }
}
```

### Authorization Check for Write-Share Publish

```typescript
// apps/api/src/shares/shares.service.ts -- new method

/**
 * Find an active write share for a user and IPNS name.
 * Used by IpnsService to authorize publish from share recipients.
 */
async findActiveWriteShare(recipientId: string, ipnsName: string): Promise<Share | null> {
  return this.shareRepo.findOne({
    where: {
      recipientId,
      ipnsName,
      permission: 'write',
      revokedAt: IsNull(),
    },
  });
}
```

### CreateShareDto Extension

```typescript
// apps/api/src/shares/dto/create-share.dto.ts -- new fields

@ApiProperty({
  description: 'Permission level for the share',
  enum: ['read', 'write'],
  default: 'read',
  required: false,
})
@IsString()
@IsIn(['read', 'write'])
@IsOptional()
permission?: 'read' | 'write';

@ApiProperty({
  description: 'Hex-encoded ECIES ciphertext of IPNS private key for write shares',
  required: false,
})
@IsString()
@Matches(/^[0-9a-fA-F]+$/, { message: 'encryptedIpnsKey must be a hex string' })
@MinLength(2)
@MaxLength(2048)
@IsOptional()
encryptedIpnsKey?: string;
```

### Conditional Write UI in SharedFileBrowser

```typescript
// apps/web/src/components/file-browser/SharedFileBrowser.tsx -- badge + toolbar logic

// In SharedListRow:
<span className={isWrite ? 'shared-rw-badge' : 'shared-ro-badge'}>
  {isWrite ? '[RW]' : '[RO]'}
</span>

// In folder view: conditionally show write toolbar
{permission === 'write' && (
  <div className="file-browser-write-toolbar">
    <button onClick={handleUpload} className="toolbar-btn">--upload</button>
    <button onClick={handleCreateFolder} className="toolbar-btn">--mkdir</button>
  </div>
)}

// ContextMenu: toggle readOnly based on permission
<ContextMenu
  readOnly={permission !== 'write'}
  onRename={permission === 'write' ? handleRename : () => {}}
  onDelete={permission === 'write' ? handleDelete : () => {}}
  onShare={undefined} /* No re-sharing in PoC */
/>
```

### Permission Toggle in ShareDialog

```typescript
// apps/web/src/components/file-browser/ShareDialog.tsx
// Terminal-style permission selector between pubkey input and share button

const [permission, setPermission] = useState<'read' | 'write'>('read');

// Permission selector
<div className="share-permission-selector">
  <label className="share-permission-label">{'// permission'}</label>
  <div className="share-permission-toggle" role="radiogroup" aria-label="Permission level">
    <button
      type="button"
      role="radio"
      aria-checked={permission === 'read'}
      className={`share-perm-btn${permission === 'read' ? ' share-perm-btn--active' : ''}`}
      onClick={() => setPermission('read')}
    >
      [ READ-ONLY ]
    </button>
    <button
      type="button"
      role="radio"
      aria-checked={permission === 'write'}
      className={`share-perm-btn${permission === 'write' ? ' share-perm-btn--active' : ''}`}
      onClick={() => setPermission('write')}
    >
      [ READ-WRITE ]
    </button>
  </div>
</div>
```

## State of the Art

| Old Approach                      | Current Approach                             | When Changed | Impact                                           |
| --------------------------------- | -------------------------------------------- | ------------ | ------------------------------------------------ |
| No sharing                        | Read-only ECIES key wrapping (Phase 14)      | Phase 14     | Secure folder sharing without server seeing keys |
| Direct ownership for IPNS publish | Owner + write-share authorization (Phase 27) | This phase   | Multi-writer IPNS without new infrastructure     |

**Deprecated/outdated:**

- None. Phase 27 builds on Phase 14 without deprecating anything.

## Open Questions

1. **TEE Enrollment userId for Share-Created Subfolders**
   - What we know: TEE enrollment tracks `userId` in the `ipns_republish_schedule` table. A write-share recipient creating a subfolder would need the owner's userId for enrollment.
   - What's unclear: Should the recipient be able to derive the owner's userId from the share record, or should the API resolve it server-side?
   - Recommendation: Server-side resolution. The share record has `sharerId` -- when a write-share recipient enrolls an IPNS name, the API maps the recipient to the share's `sharerId` and enrolls under that userId. This keeps the owner-centric model intact.

2. **Subfolder IPNS Key Generation for Write-Share Recipients**
   - What we know: Currently subfolders get random Ed25519 keypairs (not HKDF-derived from parent). The CONTEXT.md says "Write-share recipients derive child IPNS keypairs via HKDF (same derivation as owner)".
   - What's unclear: The current codebase uses `generateEd25519Keypair()` (random) for subfolder creation, not HKDF derivation. The HKDF derivation pattern exists only for vault-level IPNS keys.
   - Recommendation: Keep using random keypairs for subfolders (existing pattern). The CONTEXT.md's mention of HKDF derivation may be aspirational. Random keypairs work correctly -- the recipient wraps the private key with the owner's pubkey and delivers it via the share IPNS publish flow. The key difference from HKDF: the recipient can create subfolders without knowing the owner's private key, which is the correct behavior.

3. **Sync Polling for Shared Write Folders**
   - What we know: The owner's folders poll at 30s via `useSyncInterval`. Shared folders in `useSharedNavigation` only resolve IPNS on navigation, not on interval.
   - What's unclear: Whether adding a 30s poll to shared folder view would cause performance issues with many shared folders.
   - Recommendation: Add 30s polling only for the currently-viewed shared folder (not all shared folders). This matches the owner's behavior without creating N concurrent polls.

## Validation Architecture

### Test Framework

| Property           | Value                                                              |
| ------------------ | ------------------------------------------------------------------ |
| Framework          | Vitest (unit/integration) + Playwright (E2E)                       |
| Config file        | `apps/api/vitest.config.ts` / `tests/web-e2e/playwright.config.ts` |
| Quick run command  | `cd apps/api && pnpm vitest run src/shares/ --reporter=verbose`    |
| Full suite command | `cd apps/api && pnpm vitest run`                                   |

### Phase Requirements -> Test Map

No formal requirement IDs assigned yet (TBD in REQUIREMENTS.md). Map by deliverable:

| Deliverable              | Behavior                                                | Test Type  | Automated Command                                                                       | File Exists?                                   |
| ------------------------ | ------------------------------------------------------- | ---------- | --------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Permission column        | Share entity has permission field, defaults to 'read'   | unit       | `cd apps/api && pnpm vitest run src/shares/shares.service.spec.ts -t "permission"`      | No (Wave 0)                                    |
| IPNS key delivery        | CreateShare accepts encryptedIpnsKey for write shares   | unit       | `cd apps/api && pnpm vitest run src/shares/shares.service.spec.ts -t "ipns key"`        | No (Wave 0)                                    |
| Publish authorization    | Write-share recipients can publish to shared IPNS names | unit       | `cd apps/api && pnpm vitest run src/ipns/ipns.service.spec.ts -t "write share"`         | No (Wave 0)                                    |
| Read-only cannot publish | Read-only recipients rejected on publish                | unit       | `cd apps/api && pnpm vitest run src/ipns/ipns.service.spec.ts -t "read only"`           | No (Wave 0)                                    |
| Permission upgrade       | Owner can upgrade read->write                           | unit       | `cd apps/api && pnpm vitest run src/shares/shares.service.spec.ts -t "upgrade"`         | No (Wave 0)                                    |
| Permission downgrade     | Owner can downgrade write->read, IPNS key cleared       | unit       | `cd apps/api && pnpm vitest run src/shares/shares.service.spec.ts -t "downgrade"`       | No (Wave 0)                                    |
| Multi-writer conflict    | Two writers get 409, re-sync, retry succeeds            | SDK E2E    | `cd tests/sdk-e2e && pnpm vitest run src/suites/share-operations.test.ts -t "conflict"` | No (Wave 0)                                    |
| UI write actions         | Write shares show upload/create/rename/delete           | Playwright | `cd tests/web-e2e && pnpm exec playwright test tests/sharing.spec.ts`                   | Partial (sharing.spec.ts exists for read-only) |
| UI badge                 | [RW] badge shows for write shares                       | Playwright | `cd tests/web-e2e && pnpm exec playwright test tests/sharing.spec.ts`                   | Partial                                        |

### Sampling Rate

- **Per task commit:** `cd apps/api && pnpm vitest run src/shares/ src/ipns/ --reporter=verbose`
- **Per wave merge:** `cd apps/api && pnpm vitest run && cd ../../tests/sdk-e2e && pnpm vitest run`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `apps/api/src/shares/shares.service.spec.ts` -- extend with permission, encryptedIpnsKey, upgrade/downgrade test cases
- [ ] `apps/api/src/ipns/ipns.service.spec.ts` -- extend with write-share authorization test cases
- [ ] `tests/sdk-e2e/src/suites/share-operations.test.ts` -- extend with write share creation, multi-writer conflict test
- [ ] Migration test: verify column addition is idempotent (manual verification during plan execution)

## Sources

### Primary (HIGH confidence)

- **Existing codebase** -- All findings verified by reading actual source files:
  - `apps/api/src/shares/entities/share.entity.ts` -- Share entity structure
  - `apps/api/src/shares/shares.service.ts` -- Share CRUD operations
  - `apps/api/src/ipns/ipns.service.ts` -- IPNS publish with userId-based authorization (line 179)
  - `apps/api/src/ipns/entities/folder-ipns.entity.ts` -- FolderIpns entity with (userId, ipnsName) unique constraint
  - `packages/crypto/src/ecies/encrypt.ts` -- wrapKey supports arbitrary Uint8Array input
  - `packages/sdk-core/src/folder/index.ts` -- createSubfolder uses generateEd25519Keypair (random, not HKDF)
  - `apps/web/src/hooks/useSharedNavigation.ts` -- Read-only shared navigation
  - `apps/web/src/components/file-browser/SharedFileBrowser.tsx` -- Read-only shared UI
  - `apps/web/src/components/file-browser/ShareDialog.tsx` -- Share creation dialog
  - `apps/web/src/hooks/folder-helpers.ts` -- withConflictRetry pattern
  - `apps/api/src/republish/republish.service.ts` -- TEE enrollment with userId tracking

### Secondary (MEDIUM confidence)

- **CONTEXT.md** -- User decisions from discussion phase, verified against codebase feasibility
- **docs/DATABASE_EVOLUTION_PROTOCOL.md** -- Migration discipline (referenced but not re-read)
- **docs/METADATA_SCHEMAS.md** -- Schema reference (no schema changes needed for this phase)

### Tertiary (LOW confidence)

- None. All findings are codebase-derived.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- No new libraries, all existing patterns verified in codebase
- Architecture: HIGH -- Authorization expansion pattern is straightforward, verified FolderIpns entity constraints
- Pitfalls: HIGH -- All pitfalls derived from actual code analysis (userId lookups, sequence number coordination, TEE enrollment tracking)

**Research date:** 2026-03-26
**Valid until:** 2026-04-26 (stable domain, no external dependencies)
