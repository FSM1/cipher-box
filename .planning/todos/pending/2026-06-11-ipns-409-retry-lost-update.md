---
created: 2026-06-11
title: IPNS 409-retry republishes stale children, silently losing concurrent writes
area: sdk
severity: high
files:
  - packages/sdk-core/src/folder/index.ts
  - packages/sdk-core/src/file/index.ts
related:
  - .planning/notes/ipns-write-auth-is-cryptographic.md
  - .planning/seeds/blind-share-social-graph.md
---

## Problem

On a 409 sequence-mismatch, `updateFolderMetadataAndPublish` re-resolves only the
sequence number and republishes the same CID — built from the stale in-memory
children — with a bumped sequence, without ever re-fetching or merging the
concurrent writer's metadata (`folder/index.ts:196-232`). It retries once. So the
server's CAS check is defeated: a second device's or write-share recipient's
changes are silently overwritten (lost update).

Related: there is no CAS at all for file IPNS records — `updateFileMetadata` does
resolve-then-`seq+1`-publish with a TOCTOU window (`file/index.ts:225-231`), so
concurrent file replaces clobber each other's `versions[]` and content pointers.

Severity: silent data loss for multi-device and writable-share users.

## Solution

TBD — key considerations:

- On 409, re-fetch the remote folder metadata and merge (union children, reconcile
  per-entry) before republishing — do not bump the sequence on stale state.
- Conflict resolution must be client-side: the zero-knowledge server cannot merge
  encrypted metadata (see `ipns-write-auth-is-cryptographic` note).
- Folder metadata is a single encrypted blob with no per-entry merge granularity
  today; a principled fix likely needs a merge/CRDT model — connects to the
  `blind-share-social-graph` seed and the CRDT-IPNS-inbox todo
  (`2026-02-22-crdt-ipns-inbox-sharing.md`).
- Extend CAS coverage to file records, not just folder records.
