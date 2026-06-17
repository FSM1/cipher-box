---
created: 2026-06-17T00:00:00.000Z
completed: 2026-06-18T00:00:00.000Z
title: Make move/restore file-metadata re-encryption recoverable across partial failures
area: reliability
severity: medium
source: CodeRabbit CLI review of PR fix/decrypt-fail-after-move (#507)
files:
  - packages/sdk/src/reencrypt.ts
  - packages/sdk/src/client.ts
  - packages/sdk/src/bin/index.ts
  - crates/fuse/src/lib.rs
---

## Problem

Moving (or restoring to a different folder) a file re-encrypts its `FileMetadata`
IPNS record from the source folderKey to the destination folderKey. This spans
**two independent IPNS records** — the per-file `FileMetadata` record and the
folder metadata holding the `FilePointer` — which cannot be published atomically.
A partial failure could strand the record (re-keyed to dest while no folder lists
it under that key) or throw on a clean retry.

## Resolution (PR #507)

All three "when implementing" steps below are done, plus tests.

1. **Idempotent re-key helper** — extracted
   `reencryptFileMetadataForFolderChange` (`packages/sdk/src/reencrypt.ts`), shared
   by `moveItem` and `restoreFromBin`. If the source-key resolve throws a decrypt
   failure (`err.code === 'DECRYPTION_FAILED'`), it confirms the record under the
   **destination** key: success ⇒ a prior partial attempt already re-keyed it, so
   treat the re-encryption as complete (skip the republish); failure under BOTH
   keys ⇒ rethrow the original error. A non-decrypt error (e.g. record missing)
   propagates without a fallback. This makes a re-run after a partial failure
   complete instead of throwing.
2. **`restoreFromBin` reorder** — was re-key-before-publish. Now: validate the
   re-key preconditions up front (so a guaranteed failure aborts cleanly with no
   broken listing), publish the target folder (add-before-remove), then re-key
   (step 5b), then remove the bin entry. Mirrors `moveItem` (publish dest → re-key
   → publish source): at every intermediate failure the file stays readable from
   somewhere that lists it under the matching key — the bin (source key) before
   the re-key, the target (target key) after — never readable from neither.
3. **Desktop bounded retry** — `spawn_file_meta_reencrypt`
   (`crates/fuse/src/lib.rs`) was single-attempt fire-and-forget. Now a bounded
   in-memory retry (`REENCRYPT_MAX_ATTEMPTS = 5`, exponential backoff + jitter),
   acquiring the coordinator lock per attempt (released across the backoff sleep).
   Transient resolve/fetch/publish errors retry; a record undecryptable under the
   source key is checked against the **dest** key (idempotent — already re-keyed),
   else treated as terminal and not retried. Per the todo's scope assessment, this
   is the lightest fix that satisfies "bounded/persistent" — an in-memory retry,
   NOT a new durable `JournalOp` variant.

4. **`restoreFromBin` add is idempotent by child id** (caught by an adversarial
   review of the reorder). Because step 4 publishes the target BEFORE the new
   step-5b re-key window, a 5b/step-6 failure leaves the bin entry, and a retry
   would re-add the same child (renamed by the name-collision handler, same id) —
   the no-conflict publish path doesn't dedup by id, so the file would list twice.
   Fixed by dropping any prior copy of the child id before the add
   (`targetChildrenSansChild`), so a retry replaces rather than duplicates.

Tests: idempotent-retry + both-keys-fail + non-decrypt-propagation for `moveItem`
(`client-move-reencrypt.test.ts`); reorder + idempotent-retry + precondition-abort
+ no-duplicate-on-retry for `restoreFromBin` (`bin.test.ts`).

## Residual (out of scope here — file a fresh todo if it bites)

- **`moveItem` fresh-session full re-run.** `moveItem` reconciles a same-session
  retry via the CAS 409 merge (it commits dest state only after the re-key), and
  `restoreFromBin` is now idempotent by id. A fresh-session (post-reload) re-run of
  `moveItem` still relies on `sdkCore.moveItem` + the folder-publish merge to dedup;
  not changed here (pre-existing, low risk).
- **Desktop retry is in-memory only** (not durable across an app quit mid-retry).
  Promote `spawn_file_meta_reencrypt` to a `JournalOp::ReencryptFileMeta` variant
  with replay only if a real need surfaces.
