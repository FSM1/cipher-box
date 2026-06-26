# Phase 27: Writable Shares (PoC) - Context

**Gathered:** 2026-03-26
**Status:** Ready for planning

<domain>
## Phase Boundary

Extend Phase 14's read-only sharing to support read-write shares. Write-share recipients get full CRUD capabilities (upload, create folders, rename, delete) within shared folders. Leverages existing server-side optimistic concurrency (expectedSequenceNumber / 409 conflict detection) to coordinate multi-writer IPNS publishes. This is a proof-of-concept demonstrating that writable sharing works with CipherBox's server-relayed IPNS architecture.

</domain>

<decisions>
## Implementation Decisions

### IPNS key delivery

- ECIES-wrap the folder's IPNS private key with the recipient's secp256k1 public key, delivered alongside the existing folderKey
- New `encryptedIpnsKey` column on the Share entity (NULL for read-only shares, populated for write shares)
- Existing `encryptedKey` column unchanged — clean separation, no migration needed for existing read-only shares
- Write-share recipients derive child IPNS keypairs via HKDF (same derivation as owner) for subfolders they create
- TEE enrollment is blocked for write-share recipients — only the owner can enroll folders for auto-republishing. Subfolder writes by recipients are limited to the root shared folder level in this PoC

### Write scope for recipients

- Full CRUD: upload files, create subfolders, rename items, delete items within the shared tree
- No re-sharing — only the original owner can share with others (transitive sharing out of scope for PoC)
- Deleted items from shared folders go to the **owner's recycle bin** (owner controls IPNS root, owner can restore)
- Owner can in-place upgrade (read → write) or downgrade (write → read) an existing share's permission level
  - Upgrade: wrap + deliver IPNS key
  - Downgrade: remove IPNS key access, lazy rotation of IPNS keypair on next owner publish

### Permission model

- New `permission: 'read' | 'write'` field on Share entity (default: `'read'` for backward compatibility)
- IPNS publish endpoint authorization expanded: check share permission in addition to ownership
  - Owner can always publish
  - Write-share recipients can publish to shared IPNS names (verified via shares table lookup)
  - Read-only share recipients cannot publish
- Permission toggle in existing share dialog: `[ READ-ONLY ] [ READ-WRITE ]` selector, terminal style
- Default permission is read-only (safe default)

### Share dialog & UI changes

- Permission toggle added to share modal between pubkey input and share button
- Recipients list in share management shows permission level per recipient
- `[RW]` badge replaces `[RO]` badge for write shares in SharedFileBrowser
- Write-share recipients see full toolbar (upload, new folder) and full context menu (rename, move, delete) when browsing shared folders
- Read-only shares remain unchanged — `[RO]` badge, no write actions

### Conflict resolution & sync

- No attribution for PoC — last-writer-wins, same sync banner as multi-device
- Same 30s IPNS polling sync for recipients as owner — no new sync infrastructure
- Existing `withConflictRetry` (409 → re-sync → retry once) handles multi-writer identically to multi-device
- No audit trail of who modified what (deferred)

### Revocation behavior

- Revoking write access: silent downgrade to read-only on recipient's next sync poll
  - UI switches from `[RW]` to `[RO]`, write actions disappear, no jarring error
- Lazy IPNS keypair rotation (same as Phase 14): keypair rotates on next folder modification by owner
  - Server rejects publishes from revoked users immediately via authorization check
  - Ex-writer retains the old IPNS key but server blocks their publishes
- Full revoke (remove all access): same as Phase 14 — folder disappears from recipient's ~/shared

### Claude's Discretion

- Exact migration strategy for adding `permission` column and `encryptedIpnsKey` column
- Backend authorization query pattern (join shares table in publish flow, or preload)
- How permission upgrade/downgrade is presented in the share management UI
- TEE enrollment endpoint authorization changes (how to verify share-authorized users)
- E2E test strategy for multi-writer conflict scenarios

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Sharing architecture (Phase 14)

- `.planning/milestones/m2/phases/14-user-to-user-sharing/14-CONTEXT.md` — Phase 14 decisions: read-only sharing, ECIES key wrapping, server-side share records, lazy key rotation, terminal UI style
- `apps/api/src/shares/entities/share.entity.ts` — Share entity: needs `permission` field and `encryptedIpnsKey` column
- `apps/api/src/shares/entities/share-key.entity.ts` — ShareKey entity for descendant key wrapping
- `apps/api/src/shares/dto/create-share.dto.ts` — CreateShareDto: needs permission + encrypted IPNS key fields
- `apps/api/src/shares/shares.service.ts` — Share service: CRUD operations, key management

### IPNS publish & conflict resolution

- `apps/api/src/ipns/ipns.service.ts` — IPNS publish with sequence number checks: authorization must expand to share-authorized users (currently line 170-192: userId-only check)
- `apps/api/src/ipns/dto/publish.dto.ts` — Publish DTO with expectedSequenceNumber
- `packages/sdk-core/src/folder/index.ts` — SDK folder operations with 409 retry logic (lines 196-224)
- `apps/web/src/hooks/folder-helpers.ts` — `withConflictRetry` for UI conflict handling (lines 39-62)

### UI components

- `apps/web/src/components/file-browser/SharedFileBrowser.tsx` — Shared file browser: [RO] badge, read-only enforcement, context menu
- `apps/web/src/stores/share.store.ts` — Share store: ReceivedShare/SentShare types need permission field

### TEE republishing

- `apps/api/src/republish/republish.service.ts` — TEE enrollment and republishing: must accept share-authorized users

### Metadata schemas

- `docs/METADATA_SCHEMAS.md` — Schema reference for share-related metadata
- `docs/METADATA_EVOLUTION_PROTOCOL.md` — Evolution rules for schema changes (additive field = no version bump)
- `docs/DATABASE_EVOLUTION_PROTOCOL.md` — Migration discipline (IF NOT EXISTS, timestamp ordering)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `withConflictRetry()` in `folder-helpers.ts`: Works for any write operation — no changes needed for multi-writer
- `wrapKey()` / `unwrapKey()` in `@cipherbox/crypto`: ECIES wrapping already supports arbitrary key material — can wrap IPNS private keys the same way as folderKeys
- `reWrapForRecipients()` in `packages/sdk/src/share/index.ts`: Propagates new item keys to share recipients — will need to include IPNS keys for write shares
- Existing share dialog modal pattern: 500px width, #003322 border, backdrop
- `ContextMenu` component's `readOnly` prop: Toggle point for enabling write actions

### Established Patterns

- Sequence number optimistic concurrency: Client sends `expectedSequenceNumber`, server checks, 409 on mismatch, client retries once after re-sync
- HKDF child IPNS key derivation: `deriveIpnsKeypair(parentKey, childName)` — write-share recipients use the same derivation
- TEE enrollment: `enrollFolder()` wraps IPNS private key with TEE public key, sends to republish service
- Lazy key rotation: Revoke removes access record, key rotates on next modification

### Integration Points

- `IpnsService.publishRecord()` (line 170): Add share-permission check before sequence number validation
- `SharesService.create()`: Accept `permission` and `encryptedIpnsKey` fields
- `SharedFileBrowser`: Conditional rendering based on `share.permission === 'write'`
- `share.store.ts`: Add `permission` field to ReceivedShare/SentShare types
- `republish.service.ts`: Enrollment authorization must check share permission

</code_context>

<specifics>
## Specific Ideas

- Terminal command style maintained: `[ READ-ONLY ] [ READ-WRITE ]` toggle in share dialog
- `[RW]` badge in shared file browser mirrors `[RO]` pattern
- Access model: readers get decryption keys only, writers get decryption keys + IPNS signing keys (as envisioned in Phase 14 deferred ideas)
- Silent downgrade on write-revoke: recipient's UI gracefully transitions from [RW] to [RO] without errors
- Server-relayed IPNS architecture sidesteps the "unsolved multi-writer IPNS" problem entirely — the API is the coordination point

</specifics>

<deferred>
## Deferred Ideas

- **Metadata-embedded sharing** — Move share data (including wrapped keys) directly onto IPFS metadata to hide the social graph from the server. Long-term goal per user preference.
- **Attribution / audit trail** — Track who modified what in shared folders. Add `lastModifiedBy` pubkey to folder metadata.
- **Transitive re-sharing** — Allow write-share recipients to share with others. Requires cascading revocation logic.
- **Faster sync for shared folders** — Reduce poll interval for actively-shared folders (e.g., 10s) for snappier multi-writer experience.
- **Immediate IPNS key rotation on revoke** — Rotate keypair immediately instead of lazy rotation. More secure but requires re-wrapping for all remaining recipients.
- **Share notifications** — Notify recipients of permission changes (upgrade/downgrade/revoke).

</deferred>

---

_Phase: 27-writable-shares-poc_
_Context gathered: 2026-03-26_
