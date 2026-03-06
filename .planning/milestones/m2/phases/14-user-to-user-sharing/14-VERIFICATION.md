---
phase: 14-user-to-user-sharing
verified: 2026-02-21T17:30:00Z
status: passed
score: 5/5 must-haves verified
must_haves:
  truths:
    - 'User can share a folder or file (read-only) with another CipherBox user by re-wrapping the folderKey/fileKey with the recipient publicKey via ECIES'
    - 'User can paste a recipient secp256k1 public key and the share takes effect instantly (no accept/decline)'
    - 'User can revoke a share, which triggers lazy folderKey rotation on the next folder modification'
    - 'Recipient can browse shared folders in a Shared with me section at ~/shared'
    - 'Server never sees plaintext folderKey or fileKey at any point during the sharing flow'
  artifacts:
    - path: 'packages/crypto/src/ecies/rewrap.ts'
      provides: 'ECIES reWrapKey function with plaintext zeroing'
    - path: 'apps/api/src/shares/entities/share.entity.ts'
      provides: 'Share TypeORM entity with soft-delete revokedAt'
    - path: 'apps/api/src/shares/entities/share-key.entity.ts'
      provides: 'ShareKey TypeORM entity with CASCADE delete'
    - path: 'apps/api/src/shares/shares.service.ts'
      provides: 'SharesService with 11 CRUD methods for share lifecycle'
    - path: 'apps/api/src/shares/shares.controller.ts'
      provides: 'SharesController with 11 JWT-authenticated REST endpoints'
    - path: 'apps/api/src/shares/shares.module.ts'
      provides: 'NestJS module registered in app.module'
    - path: 'apps/web/src/stores/share.store.ts'
      provides: 'Zustand share store for received/sent shares'
    - path: 'apps/web/src/services/share.service.ts'
      provides: 'Share service with 15+ functions wrapping API client'
    - path: 'apps/web/src/components/file-browser/ShareDialog.tsx'
      provides: 'Share modal with pubkey input, ECIES key re-wrapping, recipient management'
    - path: 'apps/web/src/components/file-browser/SharedFileBrowser.tsx'
      provides: 'Read-only file browser for shared content with RO badges'
    - path: 'apps/web/src/hooks/useSharedNavigation.ts'
      provides: 'Navigation hook with ECIES key unwrapping and IPNS resolution'
    - path: 'apps/web/src/routes/SharedPage.tsx'
      provides: 'Auth-guarded page wrapper for /shared route'
  key_links:
    - from: 'ShareDialog.tsx'
      to: 'api/shares (createShare, lookupUser, revokeShare)'
      via: 'Orval-generated sharesController* functions'
    - from: 'SharedFileBrowser.tsx'
      to: 'useSharedNavigation hook'
      via: 'Hook import and destructuring'
    - from: 'useSharedNavigation.ts'
      to: 'share.service.ts (fetchReceivedShares, fetchShareKeys, hideShare)'
      via: 'Direct function imports'
    - from: 'useFolder.ts'
      to: 'share.service.ts (reWrapForRecipients)'
      via: 'Fire-and-forget IIFE in handleAddFile/handleCreate'
    - from: 'folder.service.ts'
      to: 'share.service.ts (checkPendingRotation, executeLazyRotation)'
      via: 'Dynamic import() in checkAndRotateIfNeeded'
    - from: 'ContextMenu.tsx'
      to: 'FileBrowser.tsx (onShare callback)'
      via: 'Props: onShare + readOnly for shared view'
    - from: 'routes/index.tsx'
      to: 'SharedPage.tsx'
      via: 'React Router Route at /shared'
    - from: 'AppSidebar.tsx'
      to: '/shared route'
      via: 'NavItem with shared icon'
    - from: 'shares.module.ts'
      to: 'app.module.ts'
      via: 'Module import and entity registration'
gaps: []
---

# Phase 14: User-to-User Sharing Verification Report

**Phase Goal:** Users can share encrypted folders and individual files with other CipherBox users while maintaining zero-knowledge guarantees. Instant share via public key paste (no accept/decline flow). Read-only only. Lazy key rotation on revoke.
**Verified:** 2026-02-21T17:30:00Z
**Status:** passed
**Re-verification:** No -- initial verification

## Goal Achievement

### Observable Truths

| #   | Truth                                                                                                                                                 | Status   | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | User can share a folder or file (read-only) with another CipherBox user by re-wrapping the folderKey/fileKey with the recipient's publicKey via ECIES | VERIFIED | ShareDialog.tsx (545 lines) performs full ECIES key re-wrapping flow: unwrapKey with owner key, wrapKey with recipient key, plaintext zeroed. Folder sharing traverses descendants depth-first via collectChildKeys(). File sharing resolves per-file IPNS metadata and re-wraps fileKey. API endpoint POST /shares creates share record with hex-encoded encrypted key.                                                                                                                                                                                                                      |
| 2   | User can paste a recipient's secp256k1 public key and the share takes effect instantly (no accept/decline)                                            | VERIFIED | ShareDialog has pubkey input with 0x04 prefix validation (isValidPublicKey), lookup via sharesControllerLookupUser to verify registered user, and immediate createShare call. No accept/decline flow exists -- share is created directly. Recipients list updates immediately after creation.                                                                                                                                                                                                                                                                                                 |
| 3   | User can revoke a share, which triggers lazy folderKey rotation on the next folder modification                                                       | VERIFIED | ShareDialog has inline revoke confirm pattern ([y]/[n] buttons) calling sharesControllerRevokeShare which soft-deletes (sets revokedAt). folder.service.ts:checkAndRotateIfNeeded (line 967) checks pending rotations before folder modifications. share.service.ts:executeLazyRotation generates new random 32-byte folderKey, re-wraps for remaining recipients, hard-deletes revoked shares via completeShareRotation. Three API endpoints support the rotation lifecycle: GET /shares/pending-rotations, PATCH /shares/:shareId/encrypted-key, DELETE /shares/:shareId/complete-rotation. |
| 4   | Recipient can browse shared folders in a "Shared with me" section at ~/shared                                                                         | VERIFIED | SharedPage.tsx at /shared route (routes/index.tsx line 13). SharedFileBrowser.tsx (667 lines) renders two views: top-level list with SHARED BY column and [RO] badges, and folder view with full subfolder navigation via useSharedNavigation hook (469 lines). Navigation stack (useRef-based) enables depth-first browsing. Sidebar has "Shared" NavItem with link icon. Breadcrumbs show ~/shared path.                                                                                                                                                                                    |
| 5   | Server never sees plaintext folderKey or fileKey at any point during the sharing flow                                                                 | VERIFIED | All crypto operations happen client-side. reWrapKey (rewrap.ts) unwraps and re-wraps with plaintext zeroed (line 43: plainKey.fill(0)). ShareDialog uses unwrapKey + wrapKey directly (reWrapEncryptedKey helper zeros plaintext at line 159). Server receives only hex-encoded ECIES ciphertexts in encryptedKey fields. Share entity stores encryptedKey as bytea. Controller serializes Buffer.toString('hex'). No server-side decryption code exists in shares.service.ts or shares.controller.ts.                                                                                        |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact                                                     | Expected                         | Status   | Details                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------ | -------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/crypto/src/ecies/rewrap.ts`                        | ECIES reWrapKey function         | VERIFIED | 55 lines, substantive implementation with try/finally plaintext zeroing, exported via ecies/index.ts and package index.ts                                                                                                                                                                                                              |
| `packages/crypto/src/__tests__/rewrap.test.ts`               | Test coverage for reWrapKey      | VERIFIED | 106 lines, 4 test vectors: round-trip, multi-recipient, wrong key, invalid pubkey. All pass.                                                                                                                                                                                                                                           |
| `apps/api/src/shares/entities/share.entity.ts`               | Share TypeORM entity             | VERIFIED | 83 lines, proper columns: sharerId, recipientId, itemType, ipnsName, itemName, encryptedKey (bytea), hiddenByRecipient, revokedAt (nullable soft-delete), CASCADE relations                                                                                                                                                            |
| `apps/api/src/shares/entities/share-key.entity.ts`           | ShareKey TypeORM entity          | VERIFIED | 49 lines, CASCADE delete from Share, keyType/itemId/encryptedKey columns                                                                                                                                                                                                                                                               |
| `apps/api/src/shares/shares.service.ts`                      | Service with share CRUD          | VERIFIED | 291 lines, 11 methods: createShare, getReceivedShares, getSentShares, getShareKeys, addShareKeys, revokeShare, hideShare, lookupUserByPublicKey, getPendingRotations, completeRotation, updateShareEncryptedKey                                                                                                                        |
| `apps/api/src/shares/shares.controller.ts`                   | JWT-authenticated REST endpoints | VERIFIED | 301 lines, 11 endpoints with Swagger docs, JWT guards, proper response mapping                                                                                                                                                                                                                                                         |
| `apps/api/src/shares/shares.module.ts`                       | NestJS module                    | VERIFIED | 14 lines, registered in app.module.ts with Share/ShareKey entities                                                                                                                                                                                                                                                                     |
| `apps/web/src/stores/share.store.ts`                         | Zustand share store              | VERIFIED | 99 lines, ReceivedShare/SentShare types, CRUD actions, clearShares for logout                                                                                                                                                                                                                                                          |
| `apps/web/src/services/share.service.ts`                     | Share service layer              | VERIFIED | 467 lines, 15+ functions: fetchReceivedShares, fetchSentShares, lookupUser, createShare, revokeShare, hideShare, fetchShareKeys, addShareKeys, getSentSharesForItem, hasActiveShares, findCoveringShares, reWrapForRecipients, fetchPendingRotations, checkPendingRotation, executeLazyRotation, updateShareKey, completeShareRotation |
| `apps/web/src/components/file-browser/ShareDialog.tsx`       | Share modal                      | VERIFIED | 545 lines, pubkey validation, user lookup, ECIES re-wrapping, folder traversal with progress, recipient list with inline revoke                                                                                                                                                                                                        |
| `apps/web/src/components/file-browser/SharedFileBrowser.tsx` | Read-only shared browser         | VERIFIED | 667 lines, two render modes (list + folder view), [RO] badges, SHARED BY column, breadcrumbs, context menu integration, preview dialogs                                                                                                                                                                                                |
| `apps/web/src/hooks/useSharedNavigation.ts`                  | Navigation hook                  | VERIFIED | 469 lines, ECIES key unwrapping, IPNS resolution, navigation stack, file download, share keys caching                                                                                                                                                                                                                                  |
| `apps/web/src/routes/SharedPage.tsx`                         | Auth-guarded /shared page        | VERIFIED | 41 lines, AppShell wrapper, auth redirect, SharedFileBrowser rendering                                                                                                                                                                                                                                                                 |
| `apps/web/src/styles/share-dialog.css`                       | Share dialog styles              | VERIFIED | 301 lines of CSS                                                                                                                                                                                                                                                                                                                       |
| `apps/web/src/styles/shared-browser.css`                     | Shared browser styles            | VERIFIED | 71 lines of CSS                                                                                                                                                                                                                                                                                                                        |
| `apps/api/src/shares/dto/create-share.dto.ts`                | CreateShareDto                   | VERIFIED | 1617 bytes with class-validator decorations                                                                                                                                                                                                                                                                                            |
| `apps/api/src/shares/dto/share-key.dto.ts`                   | AddShareKeysDto                  | VERIFIED | 874 bytes                                                                                                                                                                                                                                                                                                                              |
| `apps/api/src/shares/dto/update-encrypted-key.dto.ts`        | UpdateEncryptedKeyDto            | VERIFIED | 278 bytes                                                                                                                                                                                                                                                                                                                              |
| `apps/web/src/api/shares/shares.ts`                          | Generated Orval API client       | VERIFIED | 1101 lines, all 11 endpoint hooks generated                                                                                                                                                                                                                                                                                            |

### Key Link Verification

| From                   | To                                                           | Via                                                                                                                                   | Status | Details                                                                                                                      |
| ---------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------- |
| ShareDialog.tsx        | API /shares                                                  | Orval functions (sharesControllerCreateShare, sharesControllerLookupUser, sharesControllerGetSentShares, sharesControllerRevokeShare) | WIRED  | Direct imports at line 14-18 of ShareDialog.tsx, called in handleShare and handleRevoke callbacks                            |
| SharedFileBrowser.tsx  | useSharedNavigation                                          | Hook import                                                                                                                           | WIRED  | Imported at line 13, destructured at line 117-131                                                                            |
| useSharedNavigation.ts | share.service.ts                                             | Function imports                                                                                                                      | WIRED  | Imports fetchReceivedShares, fetchShareKeys, hideShare at line 27, called in loadShares(), getShareKeys(), hideSharedItem()  |
| useFolder.ts           | share.service.ts (reWrapForRecipients)                       | Import + fire-and-forget calls                                                                                                        | WIRED  | Import at line 8, called in handleAddFile (line 692), handleCreate (line 202), handleAddFiles (line 814)                     |
| folder.service.ts      | share.service.ts (checkPendingRotation, executeLazyRotation) | Dynamic import()                                                                                                                      | WIRED  | checkAndRotateIfNeeded at line 967 uses await import('./share.service') to avoid circular dependency                         |
| ContextMenu.tsx        | FileBrowser.tsx                                              | onShare prop                                                                                                                          | WIRED  | ContextMenu accepts onShare at line 36, FileBrowser passes handleShareClick at line 987                                      |
| routes/index.tsx       | SharedPage.tsx                                               | React Router                                                                                                                          | WIRED  | Route at /shared (line 13), SharedPage imported at line 4                                                                    |
| AppSidebar.tsx         | /shared                                                      | NavItem                                                                                                                               | WIRED  | NavItem to="/shared" with icon="shared" at line 22-25                                                                        |
| SharesModule           | app.module.ts                                                | Module import                                                                                                                         | WIRED  | Import at line 18, registered at line 102, entities at lines 80-81                                                           |
| SettingsPage.tsx       | Auth store vaultKeypair                                      | Public key display                                                                                                                    | WIRED  | vaultKeypair at line 46, publicKeyHex formatted with 0x prefix at line 48, displayed in settings-pubkey-box with copy button |

### Requirements Coverage

| Requirement                                        | Status    | Notes                                                                        |
| -------------------------------------------------- | --------- | ---------------------------------------------------------------------------- |
| SHARE-01: Share folder/file with ECIES re-wrapping | SATISFIED | ShareDialog performs full ECIES re-wrapping flow                             |
| SHARE-02: Instant share via public key paste       | SATISFIED | No accept/decline flow, immediate share creation                             |
| SHARE-03: Revoke with lazy key rotation            | SATISFIED | Soft-delete + checkAndRotateIfNeeded + executeLazyRotation                   |
| SHARE-04: Shared with me browsing at ~/shared      | SATISFIED | SharedFileBrowser with full navigation stack                                 |
| SHARE-05: Zero-knowledge key handling              | SATISFIED | All crypto client-side, plaintext zeroed, server only sees ECIES ciphertexts |

### Anti-Patterns Found

| File            | Line | Pattern                 | Severity | Impact                                            |
| --------------- | ---- | ----------------------- | -------- | ------------------------------------------------- |
| ShareDialog.tsx | 434  | `placeholder="0x04..."` | Info     | Legitimate HTML placeholder attribute, not a stub |

No blockers, warnings, or TODOs found in any Phase 14 files.

### Build Verification

- `pnpm --filter web build`: SUCCESS (4.57s, no errors)
- `pnpm --filter api build`: SUCCESS (no errors)
- `pnpm --filter @cipherbox/crypto test`: SUCCESS (234 tests passed, including 4 rewrap tests)

### Human Verification Required

#### 1. End-to-End Share Flow

**Test:** Log in as User A, create a folder with files, open context menu, click Share, paste User B's public key, click --share. Log in as User B, navigate to ~/shared, verify shared folder appears with [RO] badge and SHARED BY column showing User A's truncated pubkey. Navigate into the shared folder, verify files are visible and downloadable.
**Expected:** Share is created instantly. Recipient sees the shared folder. Files download correctly with decrypted content.
**Why human:** Requires two authenticated sessions and actual IPFS/IPNS infrastructure running.

#### 2. Revoke and Lazy Rotation

**Test:** As User A, revoke User B's share via ShareDialog. Then create a new file in the shared folder. Verify User B no longer sees the shared folder.
**Expected:** Revoke removes recipient from list. Next folder modification triggers lazy rotation (new folderKey generated). User B loses access.
**Why human:** Requires two sessions and timing of lazy rotation trigger.

#### 3. Settings Public Key Display

**Test:** Navigate to Settings page, verify public key section shows below vault export, with "// your public key" header, monospace green-on-dark display, and working --copy button.
**Expected:** Full uncompressed secp256k1 key displayed with 0x prefix. Copy button copies to clipboard with 2s feedback.
**Why human:** Visual verification of terminal aesthetic styling.

#### 4. Read-Only Enforcement

**Test:** As recipient, right-click items in shared folder. Verify context menu shows only Download, Preview, Details, Hide -- no Rename, Move, Share, Delete.
**Expected:** Write actions are hidden. [RO] badge visible on all items.
**Why human:** UI interaction verification.

### Gaps Summary

No gaps found. All 5 success criteria are verified at the code level:

1. **ECIES re-wrapping** is fully implemented with reWrapKey utility (tested), ShareDialog performs client-side unwrap+rewrap, and folder traversal collects descendant keys depth-first.

2. **Instant share via public key paste** works through the ShareDialog modal with format validation, user lookup, and immediate createShare API call -- no accept/decline flow.

3. **Lazy key rotation** is fully wired: revoke soft-deletes (revokedAt), checkAndRotateIfNeeded in folder.service.ts detects pending rotations before modifications, executeLazyRotation generates new keys and re-wraps for remaining recipients.

4. **Shared with me browsing** is a complete feature: /shared route with SharedPage, SharedFileBrowser with two-mode rendering (list + folder view), useSharedNavigation hook with navigation stack, ECIES key unwrapping, and IPNS resolution.

5. **Zero-knowledge guarantee** is maintained: all crypto is client-side, plaintext keys are zeroed after use, server stores only ECIES ciphertexts.

---

_Verified: 2026-02-21T17:30:00Z_
_Verifier: Claude (gsd-verifier)_
