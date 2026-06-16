---
created: 2026-06-16T01:08:13.400Z
title: Consolidate the web useFolderNavigation key-unwrap into the SDK
area: architecture
severity: low
source: PR #498 follow-ups (feat/sdk-client-self-bootstrap-folder-tree)
files:
  - apps/web/src/hooks/useFolderNavigation.ts:242
  - packages/sdk/src/client.ts
---

## Problem

PR #498 made `CipherBoxClient` self-bootstrap `folderTree` from the root IPNS key
(`ensureFolderLoaded`, reached via the `requireFolder` chokepoint). Several things
were intentionally left in place so the self-heal could prove out without widening
that PR's blast radius. PR #500 has since closed the larger half; one consolidation
remains.

### Done (PR #500)

The ~14 web `ensureFolderRegistered` call sites and the helper itself were removed —
`apps/web/src/lib/sdk-provider.ts` no longer defines it and the hooks
(`useFolderMutations`, `useFileOperations`, `useFileVersions`, `useDropUpload`,
`useBin`) now rely on the SDK chokepoint. The self-heal proved out.

### Remaining

The web `useFolderNavigation.ts:242-249` unwrap path still duplicates the SDK's
ECIES unwrap of `folderKeyEncrypted` / `ipnsPrivateKeyEncrypted`
(`packages/sdk/src/client.ts:484-491`). This is a two-sources-of-truth smell (the
SDK-helper-drift class) — the two copies must stay in lockstep.

PR #500's commit message explicitly deferred this: "useFolderNavigation.ts requires
no change: the key-unwrap there serves the display/metadata-load path, not SDK
seeding."

Separately, the security review flagged a MEDIUM: `ensureFolderLoaded` re-walks
the whole reachable tree on a cache miss for an **unreachable / server-withheld**
target, with no negative cache — self-inflicted amplification only if an upstream
caller tight-loops on an unresolvable target.

## Solution

1. Make `useFolderNavigation` call `client.ensureFolderLoaded(ipnsName)` and read
   back the loaded `FolderState` instead of unwrapping keys itself; delete the
   web-side unwrap code so the unwrap logic lives only in the SDK.
2. **Only if** web/FUSE retry loops on unresolvable targets appear: add a
   short-lived per-target negative memo (or a walked-folder cap) inside
   `ensureFolderLoaded` (`packages/sdk/src/client.ts`). Not needed today — real
   callers target reachable folders and short-circuit on first hit.

### Related

- `[[route-shared-folder-writes-through-the-sdk-client]]` — adjacent SDK-ownership
  cleanup (shared-write paths), resolved by PR #500. Both move state authority
  into the SDK.
- Supersedes the symptom-patch class tracked in the completed self-bootstrap todo
  (`2026-06-16-sdk-client-self-bootstrap-folder-tree-from-root-ipns-key`).
