# Phase 14: User-to-User Sharing Learnings

**Date:** 2026-02-21

## Original Prompt

> Implement user-to-user encrypted folder/file sharing with ECIES key re-wrapping, share management API, and frontend browsing. Then run security review and fix findings.

## What I Learned

### Critical: File keys silently skipped during sharing

- `collectChildKeys` in ShareDialog.tsx had comments acknowledging file key re-wrapping was needed, but ended with `void fp;` — files were never actually shared
- The code compiled, tests passed, and folder sharing "worked" — but recipients couldn't open files
- Only caught by systematic security review walking every code path
- **Takeaway:** When a TODO comment says "need to re-wrap file keys," implement it immediately. A `void` statement suppressing an unused variable is a red flag

### Unique constraints + soft-delete don't mix

- `@Unique(['sharerId', 'recipientId', 'ipnsName'])` blocks re-sharing after revocation because soft-deleted records still exist
- Only manifests in the UX path: revoke share -> re-share same item to same user
- **Fix:** Partial unique index via migration: `CREATE UNIQUE INDEX ... WHERE revoked_at IS NULL`
- TypeORM's `@Unique` decorator doesn't support WHERE clauses — must use raw SQL migration
- **Reusable pattern:** Any soft-delete table with uniqueness needs partial indexes, not `@Unique`

### Lookup endpoints can leak user info

- A "does this user exist" endpoint was returning `{ userId, publicKey }` when only `{ exists: true }` was needed
- Attackers could enumerate user IDs by probing public keys
- **Takeaway:** Always return the minimum information needed. Boolean existence checks should return booleans

### Cache TTL is simpler than explicit invalidation

- Share keys cache in `useSharedNavigation` had no invalidation — new files uploaded after initial browse were invisible to recipients
- TTL (60s) with `fetchedAt` timestamp is much simpler than event-based cache invalidation
- Pattern: set `fetchedAt` on write, check `Date.now() - fetchedAt < TTL` on read

### Key zeroing must include navigation stacks

- Zeroing the current `folderKey` on unmount isn't enough — navigation history refs hold decrypted keys from every level visited
- `navigateToRoot` and `navigateUp` must zero all entries in `navStackRef.current`

### DTO validation gaps are invisible until exploited

- All three share DTOs (create, add-keys, update-key) initially accepted any string for `encryptedKey` — no hex validation, no length limits
- Necessary decorators: `@Matches(/^[0-9a-fA-F]+$/)`, `@MinLength(2)`, `@MaxLength(1024)`
- Public key format: `@Matches(/^(0x)?04[0-9a-fA-F]{128}$/)`

### Hex string comparison needs case normalization

- Public keys from different sources may have mixed case (0x04...ABC vs 0x04...abc)
- Self-share prevention requires `.toLowerCase()` on both sides

## What Would Have Helped

- Running `/security:review` earlier (after plan completion, before marking phase done) instead of as afterthought
- A checklist for "did you handle ALL child types?" when writing recursive tree operations
- Automated DTO validation coverage check (e.g., "which string fields lack @Matches?")

## Key Files

- `packages/crypto/src/ecies/rewrap.ts` — ECIES re-wrap primitive
- `packages/crypto/src/__tests__/rewrap.test.ts` — 11 security test cases
- `apps/web/src/components/file-browser/ShareDialog.tsx` — share creation with key re-wrapping
- `apps/web/src/hooks/useSharedNavigation.ts` — shared folder browsing with key management
- `apps/web/src/services/share.service.ts` — share service with reWrapForRecipients
- `apps/api/src/shares/shares.service.ts` — backend share CRUD
- `apps/api/src/shares/dto/create-share.dto.ts` — DTO validation patterns
- `apps/api/src/migrations/1740300000000-SharesPartialUniqueIndex.ts` — partial unique index pattern
