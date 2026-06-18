# Phase 49 — Pre-Planning Context

Cross-layer discovery for shared-folder intra-share move (#8) + `useFolderNavigation`
unwrap consolidation (#7). Distilled from a 5-reader investigation (private-move
reference, shared-write layer, web UI, the #7 unwrap, and the e2e harness) so the
planner does not need to re-derive these facts.

## Locked scope decisions (with user)

- **Intra-share only** — move a file between two subfolders within ONE shared folder.
  No cross-share, no share↔private-vault.
- **Destination picker spans the ENTIRE shared subtree** (not just direct children).
  This is the consequential choice: it forces a new SDK shared-subtree enumeration
  capability because `sharedFolderTree` holds only ONE depth at a time today.
- **Recipient-side capability** — the write-permission recipient performs the move.

## The contract to mirror (private owner move)

`CipherBoxClient.moveItem` (`packages/sdk/src/client.ts:702-804`) is the template.
A file's `FileMetadata` IPNS record is **AES-256-GCM sealed with its PARENT folder's
`folderKey`** (NOT the fileKey — the fileKey encrypts content). Re-parenting to a
folder with a different `folderKey` MUST re-seal the record or every later
download/preview/edit throws `CryptoError: DECRYPTION_FAILED`.

Exact ordering (load-bearing):

1. Resolve source + destination folder state (keys, sequence, children).
2. Snapshot `baseChildren` for both BEFORE mutating (3-way-merge base).
3. Pure `sdkCore.moveItem({sourceChildren, destChildren, childId})` →
   `{updatedSourceChildren, updatedDestChildren, movedItem}` (throws on dest name collision).
4. **Publish DESTINATION first** (add-before-remove crash safety) via
   `sdkCore.updateFolderMetadataAndPublish` → `{publishedChildren, newSequenceNumber}`.
5. **If `movedItem.type === 'file'`:** unwrap the file IPNS key, then
   `reencryptFileMetadataForFolderChange({fileMetaIpnsName, fileIpnsPrivateKey,
   sourceFolderKey, destFolderKey, ctx})` — done AFTER the dest publish so the file is
   never readable from neither folder. `clearBytes(fileIpnsPrivateKey)` in `finally`.
6. **Publish SOURCE** (remove).
7. Adopt `result.publishedChildren` + `result.newSequenceNumber` (the MERGED set from
   any 409 three-way merge) back into state — never the locally-computed children.
8. Emit update events for both folders.

Key reusable pieces (all shipped):

- `packages/sdk/src/reencrypt.ts:49` — `reencryptFileMetadataForFolderChange` is
  **key-agnostic** (takes source/dest folderKey + fileIpnsPrivateKey) → reuse verbatim.
  Idempotent: on a source-key `DECRYPTION_FAILED` it re-probes under the dest key to
  detect an already-rekeyed partial retry. `createVersion: false` (a re-key is not a
  content change).
- `packages/sdk-core/src/cas.ts:38` — `publishWithCas`: publishes at `seq+1` with an
  `expectedSequenceNumber` guard; on 409 re-resolves authoritatively, 3-way-merges,
  retries ×4. Never hand-roll sequence math; never zero keys (caller owns zeroing).
- `packages/sdk-core/src/folder/index.ts:328` — pure `moveItem` (name-collision guard).

## Shared-write layer (Phase 48 foundation — what exists)

Two-tier: stateless ops in `packages/sdk/src/share/shared-write.ts`, stateful owner in
`client.ts` holding `sharedFolderTree` (keyed by `shareId`, sibling to `folderTree`).

- Existing ops: `uploadToSharedFolder` (:105), `createSharedSubfolder` (:247),
  `renameInSharedFolder` (:345), `deleteFromSharedFolder` (:378), `updateSharedFile`
  (:413). **No move at any layer. No existing shared op re-encrypts `FileMetadata`.**
- `updateSharedFile` (:413) is the closest analog: it `updateFileMetadata`
  (`createVersion: false`) + refreshes the recipient `share_key` via `addShareKeysFn`,
  and never-fails-on-unpin for `prunedCids` (tolerates 403 guarded-unpin).
- Client plumbing to mirror: `requireSharedFolder` (`client.ts:2045`),
  `buildSharedWriteContextFromState` (:2056), `adoptSharedFolderResult` (:2078 —
  re-reads live state after await, no-ops if the share was unloaded mid-flight, emits
  `sharedFolder:updated`), `renameInSharedFolder`/`deleteFromSharedFolder` client
  methods (:2141/:2158) as the shape for `moveInSharedFolder`.
- `SharedFolderState` (`packages/sdk/src/types.ts:138`): `{shareId, ipnsName, folderKey,
  ipnsPrivateKey, sequenceNumber, children, ownerPublicKey, recipientPublicKey,
  addShareKeysFn}`.

### Central design problem

`sharedFolderTree` holds exactly ONE folder depth per `shareId`, re-seeded on every
navigation. A cross-subfolder move needs BOTH source and destination
`folderKey`/`ipnsPrivateKey`/`sequence` simultaneously — only one is loaded. The move op
must resolve the OTHER folder's keys on demand.

How a subfolder's keys are resolved (the mechanism to reuse — see
`apps/web/src/hooks/useSharedNavigationActions.ts:222` `navigateToSubfolder`):

- `folderKey` ← `share_keys` entry `keyType: 'folder'` + `itemId === folderId`,
  ECIES-unwrapped with the recipient's vault private key.
- write `ipnsPrivateKey` ← `share_keys` entry `keyType: 'folder-ipns'`. **Absence of this
  entry means the recipient has only read on that subfolder** (navigation downgrades to
  read). So the move must verify a `folder-ipns` key exists on BOTH source and dest.
- Dual-wrapping convention: `FolderEntry`/`FilePointer` fields wrap with the OWNER
  pubkey; `share_keys` entries wrap with the RECIPIENT pubkey.

### Open questions for planning

- **Op signature:** `moveInSharedFolder` needs TWO contexts (source + dest), not the
  single `swCtx` the existing stateless ops take. Define explicit source/dest params.
- **Does the moved file need a fresh recipient `share_keys` entry under the dest?**
  The file's `fileKey`/`ipns-key` are unchanged by a move (only the `FileMetadata`
  sealing `folderKey` changes), and `share_keys` are keyed by `itemId` — so the existing
  file `share_key` should remain valid. **Verify** the recipient resolves file keys by
  `itemId` independent of parent folder; handle re-registration only if not.
- **Dest depth not loaded:** `adoptSharedFolderResult` assumes a loaded state entry. For
  a move the destination usually is NOT the active depth. Decide how to adopt/emit for a
  folder that has no `sharedFolderTree` entry (and how the active-shareId projection
  reflects it).
- Collision policy: pure `moveItem` throws on dest name collision; bin-restore
  auto-renames. Pick one for shared move.

## Web UI layer

- `useSharedWriteOps` (`apps/web/src/hooks/useSharedWriteOps.ts:32`) returns
  upload/create/rename/delete/update — no move. `deleteItemHandler` (:173, via `runWrite`
  :50) is the pattern to mirror for a `moveItem` handler.
- `ContextMenu` already has an optional `onMove` prop (`ContextMenu.tsx:34`, rendered
  :336, gated on not-readOnly + `onMove`). Wire it into `SharedFileBrowser`'s
  **folder-view** ContextMenu (:686-709). Keep it OFF the **list-view** menu (:466-480) —
  top-level shares are synthetic items and not movable.
- **`MoveDialog` cannot be reused** — the private one reads `useFolderStore` (the private
  vault tree). Need a NEW shared MoveDialog rendering the lazily-loaded shared-subtree
  picker (REQ-1 enumeration).
- State refresh is automatic via the `sharedFolder:updated` projection
  (`subscribeSharedFolderProjection` — sole writer of `folderChildrenRef`/
  `sequenceNumberRef`). The write path reads nothing back (Phase 48 REQ-3 convention).
- A new client method must be added to the `SharedFolderClient` Pick allowlist
  (`shared-folder-projection.ts:28-38`) or the projection types won't see it.

## #7 — `useFolderNavigation` unwrap consolidation

`useFolderNavigation.navigateTo` (`apps/web/src/hooks/useFolderNavigation.ts:169-331`)
hand-rolls the same ECIES unwrap + IPNS-resolve + decrypt the SDK already does in
`ensureFolderLoaded` (`client.ts:444-514`, the duplicate unwrap at :485-497).

The swap: replace the unwrap/resolve/decrypt block (~242-302) with
`const state = await client.ensureFolderLoaded(folderEntry.ipnsName)`, then map
`FolderState` → `FolderNode`. **No SDK type change needed** — `FolderState` exposes every
crypto/data value; `id`/`name`/`parentId` are pure-local navigation metadata the web
already has (`targetFolderId`, `folderEntry.name`, parent scan).

Caveats to preserve:

- **Keep the 3×/2s IPNS-propagation retry** (`ensureFolderLoaded`/`loadFolderMetadata`
  returns null immediately, no retry) via a thin web-side wrapper — else navigating into a
  just-created folder can fail until the next poll.
- **Clone** `state.folderKey` / `state.ipnsKeypair.privateKey` into `FolderNode`
  (SDK-owned buffers are zeroed on `client.destroy()` → use-after-zero on logout).
- `state.ipnsKeypair.publicKey` is EMPTY for tree-walked folders — don't rely on it (web
  only stores `ipnsPrivateKey`, so fine).
- **DEFER** the `ensureFolderLoaded` full-tree-re-walk negative-cache mitigation (MEDIUM;
  the todo itself scoped it as not-needed-today). A parent-scoped variant would avoid the
  re-walk on the hot nav path — consider but not required.
- `ensureFolderLoaded` is `@internal` — decide whether to drop that or expose a dedicated
  public load-for-display method.

## E2E

- Mirror `tests/web-e2e/tests/move-restore-content.spec.ts` (single-account move +
  bin-restore; content-survival asserted via the TextEditor decrypt-on-read path) and the
  two-account owner/recipient setup from `writable-shares.spec.ts`
  (`createWalletTestAccount`, read-write share, cross-client sync via
  navigate-away/back + `page.reload({waitUntil:'networkidle'})` + generous timeouts).
- New test: Alice shares a parent folder (read-write) containing a file + a subfolder;
  Bob (recipient) moves the file into the subfolder via the new shared MoveDialog; assert
  content DECRYPTS for BOTH Bob and Alice after sync. Assertion MUST go through the
  decrypt path (TextEditor `getContent`), not mere list visibility — the bug only surfaces
  on preview/edit/download.
- Infra: `web-e2e` runs only on push to `main` / manual dispatch — it will NOT gate the
  PR. Local run needs `docker compose -f docker/docker-compose.yml up -d` (postgres/ipfs/
  redis/someguy/mock-ipns-routing :3001, built); playwright auto-starts api :3000 + web
  :5173. `test.describe.serial`, workers:1, retries:0.

## Raw research

Full 5-reader output (signatures, line refs, gotchas) archived from the understanding
workflow run `wf_88a680e9-b7c`.
