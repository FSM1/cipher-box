---
created: 2026-07-03T00:00:00Z
title: Port standalone recovery tool to v3 vault format
area: web
files:
  - apps/web/public/recovery.html
  - tests/web-e2e/tests/recovery.spec.ts:68
  - packages/core/src/vault/blob.ts:87
  - packages/core/src/node/seal.ts
source: 68.1-VERIFICATION.md (human-approved deferral, override 1 of 2)
supersedes: 2026-06-29-recovery-html-vault-v3-migration.md
resolves_phase: 78
---

> **Merged 2026-07-11:** absorbs the earlier `2026-06-29-recovery-html-vault-v3-migration`
> todo, which described the same recovery.html v2→v3 port at the blob-header level.
> When implementing, also validate the v3 blob parser against
> `tests/vectors/vault-v3-blob.json` (the cross-language vault-blob-v3 vectors) as
> that todo called out.

## Problem

The standalone recovery tool (`apps/web/public/recovery.html`) still speaks the v2
vault/metadata format. Phase 68.1 moved the web client onto the node/v3 read+write
chain (sealed nodes, WriteChildRef write plane, AAD triad), so the tool can no
longer decrypt/recover a current vault. `recovery.spec.ts` fails against v3 vaults
for this reason — recorded as a human-approved deferral override in the Phase 68.1
verification (one of the two allowed residual full-suite failures).

## Solution

Own feature plan (explicitly deferred out of 68.1 by the user): port the recovery
tool to the v3 node format — unseal via the v3 envelope (readKey chain), understand
`WriteChildRef`/`SealedChildRef` split, and keep it a fully offline, standalone HTML
artifact. Un-defer `recovery.spec.ts` once ported so the full web-e2e suite has zero
expected failures.

### Confirmed scope (from web-e2e parallelization investigation, 2026-07-06)

Two distinct blockers — the tool is on the entire pre-#578 model, not just the blob header:

1. **Blob parse (small):** `recovery.html:394,1160` hard-check `blob[0] === 0x02` and
   halt with "not v2 format" on the current `0x03` blob. Replace with a v3 parser
   mirroring `deserializeVaultBlobV3` (`packages/core/src/vault/blob.ts:87`): check
   `0x03`, read `u16_BE(readLen)`, ECIES-decrypt the read-key segment (recovery only
   needs the read chain; the write key can be ignored).
2. **Folder/file traversal (large):** `recoverFolder` still expects the pre-#578
   `{iv,data}` AES-GCM envelope with a `children[]` array. The runtime now publishes a
   `node/v3` `PublishedNode` envelope sealed via `packages/core/src/node/seal.ts`
   (AAD triad — roles `0x01` node / `0x02` child readKey / `0x03` content,
   `buildNodeAad(id, kindByte, generation, role)`). Re-implement `unsealNode` /
   `unsealChildReadKey` / `unsealContent` inline, since `recovery.html` is a
   dependency-free standalone file (CDN `@noble`, no bundler).

**Status:** as of the web-e2e parallelization branch, `recovery.spec.ts:68` is
`test.fixme`'d (not just failing) with a `FIXME(recovery-v3)` pointer. Remove the
`.fixme` once `recovery.html` speaks v3 so the full web-e2e suite has zero expected
failures / skips.
