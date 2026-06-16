---
created: 2026-06-16T01:08:13.400Z
title: Remove redundant web folder-seeding now that SDK self-bootstraps folderTree
area: architecture
severity: low
source: PR #498 follow-ups (feat/sdk-client-self-bootstrap-folder-tree)
files:
  - apps/web/src/lib/sdk-provider.ts:96
  - apps/web/src/hooks/useFolderNavigation.ts:233
  - apps/web/src/hooks/useFolderMutations.ts
  - apps/web/src/hooks/useFileOperations.ts:80
  - apps/web/src/hooks/useFileVersions.ts:66
  - apps/web/src/hooks/useDropUpload.ts:109
  - apps/web/src/hooks/useBin.ts:73
  - packages/sdk/src/client.ts
---

## Problem

PR #498 made `CipherBoxClient` self-bootstrap `folderTree` from the root IPNS key
(`ensureFolderLoaded`, reached via the `requireFolder` chokepoint). Two things are
now redundant but were intentionally left in place so the self-heal could prove
out without widening that PR's blast radius:

1. **The ~16 web `ensureFolderRegistered` call sites** (`apps/web/src/lib/sdk-provider.ts:96`
   defines it; callers in `useFolderMutations.ts`, `useFileOperations.ts:80`,
   `useFileVersions.ts:66`, `useDropUpload.ts:109`) pre-seed `folderTree` before
   every mutation. They are now no-ops — the SDK self-heals if the folder is
   absent. `useBin.ts:73/128` never had them and is already fixed by the SDK.

2. **The web `useFolderNavigation.ts:233-240` unwrap path** duplicates the SDK's
   ECIES unwrap of `folderKeyEncrypted` / `ipnsPrivateKeyEncrypted`. This is a
   two-sources-of-truth smell (the SDK-helper-drift class) — the two copies must
   stay in lockstep.

Separately, the security review flagged a MEDIUM: `ensureFolderLoaded` re-walks
the whole reachable tree on a cache miss for an **unreachable / server-withheld**
target, with no negative cache — self-inflicted amplification only if an upstream
caller tight-loops on an unresolvable target.

## Solution

Once self-bootstrap has proven out in staging/prod:

1. Delete the web `ensureFolderRegistered` helper and its call sites; rely on the
   SDK chokepoint. Verify each former call site still works cold (reload → mutate
   into a never-navigated subfolder).
2. Make `useFolderNavigation` call `client.ensureFolderLoaded(ipnsName)` and read
   back the loaded `FolderState` instead of unwrapping keys itself; delete the
   web-side unwrap+register code so the unwrap logic lives only in the SDK.
3. **Only if** web/FUSE retry loops on unresolvable targets appear: add a
   short-lived per-target negative memo (or a walked-folder cap) inside
   `ensureFolderLoaded` (`packages/sdk/src/client.ts`). Not needed today — real
   callers target reachable folders and short-circuit on first hit.

### Related

- `[[route-shared-folder-writes-through-the-sdk-client]]` — adjacent SDK-ownership
  cleanup (shared-write paths). Both move state authority into the SDK.
- Supersedes the symptom-patch class tracked in the completed self-bootstrap todo
  (`2026-06-16-sdk-client-self-bootstrap-folder-tree-from-root-ipns-key`).
