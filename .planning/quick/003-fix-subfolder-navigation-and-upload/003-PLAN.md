---
phase: quick-003
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/services/folder.service.ts
  - apps/web/src/hooks/useFolderNavigation.ts
autonomous: true

must_haves:
  truths:
    - 'Clicking a subfolder navigates into it and shows its children'
    - 'Breadcrumbs update to show root > subfolder path'
    - 'Uploading a file inside a subfolder succeeds (parent folder found)'
    - 'Navigating back to root from subfolder works'
    - 'IPNS resolution failure for a subfolder shows error gracefully, does not crash'
  artifacts:
    - path: 'apps/web/src/services/folder.service.ts'
      provides: 'Real loadFolder implementation that unwraps keys, resolves IPNS, decrypts metadata'
      contains: 'unwrapKey'
    - path: 'apps/web/src/hooks/useFolderNavigation.ts'
      provides: 'navigateTo calls real loadFolder for unloaded subfolders'
      contains: 'loadFolder'
  key_links:
    - from: 'apps/web/src/hooks/useFolderNavigation.ts'
      to: 'apps/web/src/services/folder.service.ts'
      via: 'navigateTo calls loadFolder for subfolder'
      pattern: 'loadFolder'
    - from: 'apps/web/src/services/folder.service.ts'
      to: 'apps/web/src/services/ipns.service.ts'
      via: 'loadFolder resolves IPNS to get metadata CID'
      pattern: 'resolveIpnsRecord'
    - from: 'apps/web/src/services/folder.service.ts'
      to: '@cipherbox/crypto unwrapKey'
      via: 'loadFolder unwraps folderKey and ipnsPrivateKey'
      pattern: 'unwrapKey'
---

<objective>
Fix subfolder navigation and upload by implementing the `loadFolder` stub and wiring
it into `useFolderNavigation.navigateTo`.

Currently, clicking a subfolder changes the URL but never populates a `FolderNode` in
the Zustand store. This causes: (1) breadcrumbs don't update (folder not in store),
(2) uploads fail with "parent folder not found" (folder not in store).

Purpose: Make subfolders actually navigable and functional — the single most critical
file-management gap remaining.

Output: Two modified files that together implement the full subfolder load pipeline:
unwrap encrypted keys -> resolve IPNS -> fetch + decrypt metadata -> store FolderNode.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/services/folder.service.ts
@apps/web/src/hooks/useFolderNavigation.ts
@apps/web/src/stores/folder.store.ts
@apps/web/src/stores/auth.store.ts
@apps/web/src/services/ipns.service.ts
@packages/crypto/src/folder/types.ts
@packages/crypto/src/ecies/decrypt.ts
</context>

<tasks>

<task type="auto">
  <name>Task 1: Implement loadFolder in folder.service.ts</name>
  <files>apps/web/src/services/folder.service.ts</files>
  <action>
Replace the TODO stub in `loadFolder` (lines 68-93) with a real implementation.

The function already has the correct signature:

```ts
loadFolder(folderId: string | null, folderKey: Uint8Array, ipnsPrivateKey: Uint8Array, ipnsName: string): Promise<FolderNode>
```

But it also needs the `parentId` to build the FolderNode correctly. Change the signature to add `parentId: string | null` as a parameter.

Implementation steps:

1. Add `parentId: string | null` as the 5th parameter (after `ipnsName`)
2. Add `name: string` as the 6th parameter (subfolder display name from FolderEntry)
3. Call `resolveIpnsRecord(ipnsName)` to get `{ cid, sequenceNumber }` — import is already available in ipns.service.ts
4. If IPNS resolution returns null, return a FolderNode with `isLoaded: true`, empty children, and sequenceNumber 0n. This handles newly-created subfolders whose IPNS hasn't propagated yet. Log a warning with `console.warn`.
5. If IPNS resolves, call `fetchAndDecryptMetadata(cid, folderKey)` to get `FolderMetadata`
6. Return a complete `FolderNode`:

   ```ts
   {
     id: folderId ?? 'root',
     name: name,
     ipnsName,
     parentId,
     children: metadata.children,
     isLoaded: true,
     isLoading: false,
     sequenceNumber: resolved.sequenceNumber,
     folderKey,
     ipnsPrivateKey,
   }
   ```

Add the import for `resolveIpnsRecord` from `./ipns.service` at the top of the file (it is not currently imported).

Do NOT add `unwrapKey` or `hexToBytes` here — the caller is responsible for unwrapping keys before calling `loadFolder`. This keeps `loadFolder` focused: it receives decrypted keys and returns a FolderNode.
</action>
<verify>
Run `pnpm --filter web type-check` (or `pnpm --filter web build`) — no type errors on the modified signature or implementation.
</verify>
<done>
`loadFolder` resolves IPNS, fetches+decrypts metadata, and returns a complete FolderNode with real children. It gracefully handles IPNS-not-found (returns empty children) and propagates other errors.
</done>
</task>

<task type="auto">
  <name>Task 2: Wire navigateTo to call real loadFolder with key unwrapping</name>
  <files>apps/web/src/hooks/useFolderNavigation.ts</files>
  <action>
Replace the fake setTimeout in `navigateTo` (lines 160-175) with actual subfolder loading logic.

**Add imports at top of file:**

```ts
import { unwrapKey, hexToBytes, type FolderEntry } from '@cipherbox/crypto';
import { useAuthStore } from '../stores/auth.store';
import { loadFolder } from '../services/folder.service';
```

**Replace the navigateTo callback body** (keep the URL navigation part lines 153-158 as-is). After the `navigate()` call, replace everything from line 160 onward with:

```ts
// Look up the target folder in the store
const currentFolders = useFolderStore.getState().folders;
const targetFolder =
  targetFolderId === 'root'
    ? getRootFolder(useVaultStore.getState(), currentFolders)
    : currentFolders[targetFolderId];

// If already loaded, nothing to do
if (targetFolder?.isLoaded) return;

// Find the FolderEntry for this subfolder in any loaded parent's children
let folderEntry: FolderEntry | undefined;
let parentId: string | null = null;

for (const [fId, fNode] of Object.entries(currentFolders)) {
  if (!fNode.isLoaded) continue;
  const match = fNode.children.find(
    (c): c is FolderEntry => c.type === 'folder' && c.id === targetFolderId
  );
  if (match) {
    folderEntry = match;
    parentId = fId;
    break;
  }
}

if (!folderEntry) {
  console.error(`Cannot load folder ${targetFolderId}: no parent with its FolderEntry is loaded`);
  return;
}

// Get user's ECIES private key for unwrapping
const derivedKeypair = useAuthStore.getState().derivedKeypair;
if (!derivedKeypair) {
  console.error('Cannot load folder: no derived keypair available');
  return;
}

// Set loading state
setIsLoading(true);
const loadingPlaceholder: FolderNode = {
  id: targetFolderId,
  name: folderEntry.name,
  ipnsName: folderEntry.ipnsName,
  parentId,
  children: [],
  isLoaded: false,
  isLoading: true,
  sequenceNumber: 0n,
  folderKey: new Uint8Array(0),
  ipnsPrivateKey: new Uint8Array(0),
};
useFolderStore.getState().setFolder(loadingPlaceholder);

try {
  // Unwrap keys
  const folderKey = await unwrapKey(
    hexToBytes(folderEntry.folderKeyEncrypted),
    derivedKeypair.privateKey
  );
  const ipnsPrivateKey = await unwrapKey(
    hexToBytes(folderEntry.ipnsPrivateKeyEncrypted),
    derivedKeypair.privateKey
  );

  // Load folder metadata from IPNS
  const folderNode = await loadFolder(
    targetFolderId,
    folderKey,
    ipnsPrivateKey,
    folderEntry.ipnsName,
    parentId,
    folderEntry.name
  );

  // Use getState() to avoid stale closure — other effects may have modified the store
  useFolderStore.getState().setFolder(folderNode);
} catch (err) {
  console.error('Failed to load subfolder:', err);
  // Remove the loading placeholder so the user can retry
  useFolderStore.getState().removeFolder(targetFolderId);
} finally {
  setIsLoading(false);
}
```

**Important details:**

- The `navigateTo` callback must be `async` — change `(targetFolderId: string) => {` to `async (targetFolderId: string) => {`
- Use `useFolderStore.getState()` and `useAuthStore.getState()` inside the async body to avoid stale Zustand closures (per project memory)
- Use `useVaultStore.getState()` instead of the captured `vaultState` for the same reason
- Remove `folders` and `vaultState` from the useCallback dependency array since we now read fresh state via getState(). Dependencies should be: `[navigate, setFolder, setIsLoading]` — but since setFolder and setIsLoading are stable, the minimal deps are just `[navigate]`
- The `for...of` loop searching all loaded folders' children handles the common case (navigating one level at a time). For deep-link via URL, the parent must already be loaded; if not, we log an error and bail. This is acceptable for v1.
  </action>
  <verify>

1. Run `pnpm --filter web type-check` — no type errors.
2. Run `pnpm lint` — no lint errors on the modified files.
3. Manual test: Start the app, log in, create a subfolder if none exists, click the subfolder — it should navigate in, show breadcrumbs "My Vault > SubfolderName", and allow file upload inside.
   </verify>
   <done>
   Clicking a subfolder triggers key unwrapping, IPNS resolution, metadata decryption, and populates the FolderNode in the store. Breadcrumbs render correctly because the folder now exists in the store with the correct `parentId` and `name`. Uploads succeed because the folder has a valid `folderKey`, `ipnsPrivateKey`, and `isLoaded: true`. Errors during load are caught and logged gracefully.
   </done>
   </task>

</tasks>

<verification>
1. `pnpm --filter web type-check` passes with zero errors
2. `pnpm lint` passes on both modified files
3. Navigate to a subfolder — breadcrumbs show "My Vault > SubfolderName"
4. Upload a file inside the subfolder — upload succeeds, file appears in list
5. Navigate back to root — breadcrumbs revert to "My Vault", root files visible
6. Navigate to subfolder again — folder loads from store (already loaded), no re-fetch
</verification>

<success_criteria>

- Subfolder FolderNode is created in the Zustand store with real decrypted children
- Breadcrumbs render the full path (root > subfolder)
- File upload inside a subfolder completes successfully
- IPNS resolution failure does not crash the app (shows empty folder)
- No TypeScript or lint errors introduced
  </success_criteria>

<output>
After completion, create `.planning/quick/003-fix-subfolder-navigation-and-upload/003-SUMMARY.md`
</output>
