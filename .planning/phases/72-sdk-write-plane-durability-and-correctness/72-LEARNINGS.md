---
phase: 72
phase_name: "SDK Write-Plane Durability and Correctness"
project: "CipherBox"
generated: "2026-07-10"
counts:
  decisions: 6
  lessons: 6
  patterns: 6
  surprises: 6
missing_artifacts:
  - "UAT.md"
---

# Phase 72 Learnings — SDK Write-Plane Durability and Correctness

## Decisions

### Write-plane CAS-merge is base-aware and STRICTER than the read-plane merge

`updateFolderMetadataAndPublish` gained an optional `baseWriteChildren` snapshot. When supplied, a `childId` present in base but absent from local is treated as an intentional delete this transaction committed to, and is pruned on a CAS-409 retry even if a racing writer's stale remote snapshot still carries it — while genuinely concurrent remote-only adds are kept. This is deliberately different from the read-plane's `mergeChildren`, which keeps a one-sided absence (union wins). Omitting `baseWriteChildren` falls back to the legacy naive union for back-compat.

**Rationale:** The naive union merge would resurrect an SC#1 delete under a concurrent-write race (RESEARCH Critical Finding 2); the asymmetric prune is the only thing that makes the drop survive a 409.

**Source:** 72-03-SUMMARY.md (grounded in 72-RESEARCH.md Critical Finding 2)

### Fail-closed only on the genuine transient-miss branch, keep the other fail-open paths

`getWriteBodyParams`'s combined `!resolved || !resolved.published.writeSealed` guard was split: `!resolved` (a genuine transient IPNS resolve miss) with a real 32-byte non-zero writeKey now THROWS; `!writeSealed` (a structurally never-write-capable folder) and the zero/absent-writeKey read-only-device fallback stay fail-open, returning `writeChildren: []` exactly as before.

**Rationale:** Assumption A1 / Pitfall 3 — turning every read-only fallback into a throw would break legitimate pre-D-03 read-only folders; only the transient miss risks silently sealing an empty write-body that discards the whole chain.

**Source:** 72-04-SUMMARY.md (72-RESEARCH.md Pitfall 3 / Assumption A1)

### `walkChildWriteKey`'s mode governs only the missing-ref case; an AEAD failure is never swallowed

The extracted `walkChildWriteKey(mode: 'require' | 'skip' | 'nullable')` primitive uses `mode` to control ONLY missing-`WriteChildRef` behavior (`require` throws, `skip`/`nullable` return null). A cryptographic (AEAD) unseal failure always propagates in every mode. This contradicts RESEARCH.md's summarized table, which classified the `nullable` site as "validation returns null too."

**Rationale:** Inspecting all 8 original call sites showed none ever caught `unsealChildWriteKey`'s own throw; `resolveSharedSubfolderWriteKey`'s docstring and regression tests explicitly assert a throw on a tampered `writeKeySealed`. Following the literal table would have converted a security-critical tamper-detection throw into a silent fail-open null return.

**Source:** 72-08-SUMMARY.md

### SC#4 reframed as listingCache invalidation, not a SealedChildRef mirror refresh

The original todo described refreshing `SealedChildRef.size`/`modifiedAt`, but that mirror was reverted in 68.2-12 and was NOT reintroduced (NODE-03 frozen 5-field set preserved). The fix is `this.listingCache.delete(folderIpnsName)` inside `maybeRepublishFolderForFileMigration`, gated on a caller-computed `fileContentChanged` boolean, mirroring the shipped `updateSharedFile` 68.2-02 one-liner.

**Rationale:** The staleness symptom persists via a different mechanism (cache keyed on parent sequence, not a mirror field); reintroducing the field would violate the frozen node schema (RESEARCH Critical Finding 1).

**Source:** 72-06-SUMMARY.md (72-RESEARCH.md Critical Finding 1)

### Do not modernize the 13 legacy skipped tests — seed one live reachable-branch gate instead

`move-in-shared-folder.test.ts` was 100% `describe.skip` and exercised the dead `shareKeys.length > 0` branch. Rather than un-skip and modernize all 13, it was rewritten to a single live test of the reachable write-chain branch, so Plan 07 could then delete the dead branch refactor-under-test rather than refactor-blind.

**Rationale:** Modernizing dead-branch tests is wasted effort (RESEARCH Critical Finding 3); the value is a green gate over the branch that survives the deletion.

**Source:** 72-01-SUMMARY.md, 72-07-SUMMARY.md

### Symmetric soft-delete/permanent-delete write-chain lifecycle keyed by a captured UUID witness

`addToBin` intentionally RETAINS the removed child's `WriteChildRef` so a later restore can re-home it; `permanentDeleteFromBin` DROPS the lingering ref, using `BinEntry.nodeRef.id` (the UUID captured at soft-delete time) as the witness rather than a fresh IPNS resolve of the deleted node.

**Rationale:** Retention without a release point leaks the ref forever for never-restored deletes (Open Question 1 symmetry gap); a fresh resolve would fail on an item whose own IPNS record may already be gone (Pitfall 4).

**Source:** 72-05-SUMMARY.md

## Lessons

### `vi.spyOn` on a namespace import intercepts cross-package internal calls, but not same-bundle re-exports

Spying on `import * as cryptoModule from '@cipherbox/crypto'` DID observe calls made internally inside `@cipherbox/sdk-core`'s bundled dist, because the dist re-imports the genuinely-external package via real ESM and Vitest's transform intercepts that shared reference. Spying on sdk-core's OWN barrel re-export (e.g. `createAndPublishIpnsRecord`, which `rotation/engine.ts` imports directly from `'../ipns'`) would NOT intercept, because tsup bundles it into the same `dist/index.mjs` module scope.

**Context:** Choosing a provenance spy for `write-chain-rotation.test.ts`; verified empirically with a disposable experiment (spy call count == 2) before committing to the approach.

**Source:** 72-02-SUMMARY.md

### Rebuild the upstream package's dist before typechecking a downstream consumer

`pnpm --filter @cipherbox/sdk exec tsc --noEmit` failed on a new `baseWriteChildren` field because `@cipherbox/sdk-core`'s dist was stale relative to the source change. Rebuilding sdk-core (`pnpm --filter @cipherbox/sdk-core build`) before the sdk typecheck resolved it with no code change — build-first-then-typecheck ordering.

**Context:** The project's known cross-package dist-staleness gotcha; recurs on any sdk-core signature change consumed by sdk.

**Source:** 72-03-SUMMARY.md

### Identify a minted crypto artifact by provenance, not by a fixed offset into a capture list

`write-chain-rotation.test.ts` had used `capturedKeys[0]`/`capturedKeys[2]` positional offsets into a global `crypto.getRandomValues` capture. Replaced with a scoped `generateEd25519Keypair` spy asserted to fire exactly twice (once per rotated node, child-first order), reading the real per-call return values — an offset can silently shift if the capture list grows for unrelated reasons.

**Context:** `rotateWriteSubtree` calls `generateEd25519Keypair` exactly once per rotated node in guaranteed child-first order, so the spy's own call count doubles as a no-confounding-source assertion.

**Source:** 72-02-SUMMARY.md

### Deleting a method parameter breaks test call sites that the plan's file list omits

Removing `getShareKeysFn` from `moveInSharedFolder` left the Plan 01 test still passing `getShareKeysFn: async () => []` — an excess-property error that breaks `pnpm --filter @cipherbox/sdk build`'s `tsc -p tsconfig.build.json` step, even though Vitest's untyped transform runs it fine at runtime. The test call site had to be updated in the same change despite not being in the plan's `files_modified`.

**Context:** A signature-narrowing refactor must sweep every caller including test files; the build's typed tsc pass (not the test run) is what catches it.

**Source:** 72-07-SUMMARY.md

### A uniform nullable return type breaks TS control-flow narrowing at fail-closed call sites

`walkChildWriteKey`'s single `Uint8Array | null` return (one signature for all 3 modes) breaks narrowing where a `require`-mode result feeds a non-nullable param (`unsealNode`'s `writeKey`, `wrapKey`'s `key`). Resolved with small defensive `if (!x) throw` guards after each require-mode call — unreachable at runtime (require mode always throws) but required for `tsc`.

**Context:** Chosen over 3 differently-typed overloads to keep one simpler function signature.

**Source:** 72-08-SUMMARY.md

### Doc-comment prose that quotes forbidden literals trips whole-file grep acceptance checks

Acceptance criteria that `grep` the whole file (e.g. for `describe.skip`, `.fill(0)`, retired type names) match comment prose, not just code. Descriptions had to be reworded to state the same fact without the literal substring so the plan's own verification greps returned 0.

**Context:** Recurred across Plan 01 (`describe.skip`/`FolderChild`) and Plan 09 (`.fill(0)`); a self-correction before commit, not a functional change.

**Source:** 72-01-SUMMARY.md, 72-09-SUMMARY.md

## Patterns

### D-09 terminal-owner zeroize idiom (null-before-try, fill-in-finally-on-throw-only)

Null-init the derived key locals BEFORE the `try`, move every unwrap/derive call INSIDE the `try`, so a throw on a LATER derive still reaches the `finally` cleanup for an EARLIER-derived key. Inside a shared primitive that RETURNS a key, null the local before returning (ownership transfer to the caller) and fill only in the throw path — a callee borrowing caller-owned buffers must never zero them; only the terminal owner zeroes.

**When to use:** Any function that unwraps/derives more than one key buffer, or any extracted helper that hands a key back to its caller.

**Source:** 72-06-SUMMARY.md, 72-08-SUMMARY.md, 72-09-SUMMARY.md, 72-PATTERNS.md

### Write-plane (childId/UUID) vs read-plane (ipnsName) keying discipline

`WriteChildRef.childId` is the node's own `PublishedNode.id` (UUID), never the ipnsName-based `childId` parameter the read plane uses. Before touching `writeChildren`, resolve the item's UUID via `resolvePublishedNode`/the captured `BinEntry.nodeRef.id`, then filter/reseal by that UUID. Fixtures should use genuinely distinct ipnsName vs UUID values so a confusion cannot silently pass.

**When to use:** Every write-chain mutation — delete, move, restore, permanent-delete — that must drop or re-home a `WriteChildRef`.

**Source:** 72-03-SUMMARY.md, 72-05-SUMMARY.md, 72-PATTERNS.md (Pitfall 1)

### Cross-folder write-key re-homing (moveItem 68.1-31 dest-before-source template)

To move write capability between folders: when both sides have a real writeKey, unseal the node's `WriteChildRef` under the SOURCE writeKey, reseal under the TARGET writeKey keyed by node UUID + the SAME generation used for the read-plane reseal, add to the target write-body, drop from the source, and publish TARGET before SOURCE (dest-before-source, D-12) so a crash between publishes never fully orphans write capability. Thread `baseWriteChildren` for both publishes so the base-aware CAS merge prunes the source-side drop under a race. Wrap the whole source-side attempt in a try/catch that degrades to a read-plane-only outcome.

**When to use:** Any operation that relocates a node across write scopes — `moveItem`, `restoreFromBin` to a different parent, future bin-path write-chain work.

**Source:** 72-05-SUMMARY.md, 72-RESEARCH.md Pattern 2

### Single `mode`-parameterized primitive for divergent fail-open/fail-closed hop-walks

`walkChildWriteKey(mode: 'require' | 'skip' | 'nullable')` (a string-literal union, never a TS enum per project convention) consolidates divergent inline `unsealChildWriteKey` walks, with each caller re-pointed at the mode matching its original contract 1:1. A companion `hasRealWriteKey(wk)` predicate replaces the ~6 inline non-null/32-byte/non-zero spellings. Keep each call site's own sibling pre-checks and validate-before-trust step; the primitive owns only the hop-walk.

**When to use:** When several call sites repeat the same walk with only their missing-data policy differing; verify no behavior change with the full unit suite.

**Source:** 72-08-SUMMARY.md

### Standalone shared module for logic called from both a stateful class and stateless free functions

`write-body-params.ts` exports `getWriteBodyParams`/`adoptPublishedFolderState`/`hasRealWriteKey` as free functions taking explicit `ctx`/`folderTree` params. `CipherBoxClient` delegates with `this.ctx`/`this.folderTree` threaded through; `bin/index.ts` (which has no `this`) imports them directly — collapsing two textually-identical copies into one. Similarly, `runFileVersionOp` is a shared private core with thin public delegators, each keeping its own `withOperation` wrapper for correct per-op telemetry.

**When to use:** When near-identical logic must run from both a class instance and standalone module functions; standardize on the simpler resolve path and drop unused extra return fields.

**Source:** 72-10-SUMMARY.md

### Real crypto fixtures over mocked crypto for AAD-bound write-chain tests

Build genuine node/v3 fixtures with `@cipherbox/core`'s `sealNode`/`unsealNode`/`sealChildReadKey`/`sealChildWriteKey` and mock ONLY the sdk-core network transport seams (`resolveIpnsRecord`/`fetchFromIpfs`/`addToIpfs`/`updateFolderMetadataAndPublish`). The reachable write-chain branch never calls `wrapKey`/`unwrapKey`, so this makes the test a genuine end-to-end proof of the AAD-bound hop rather than a mock-call assertion.

**When to use:** Unit-testing any write-chain path where the code under test performs real seal/unseal but no ECIES wrap.

**Source:** 72-01-SUMMARY.md, 72-06-SUMMARY.md

## Surprises

### RESEARCH.md's summarized table would have introduced a fail-open security regression

RESEARCH's "Write-Chain Hop Walk" table classified the `nullable` site as "validation returns null too." Taken literally, `walkChildWriteKey` would have caught `unsealChildWriteKey`'s AEAD auth failure and returned null — converting tamper detection into a silent fail-open on a write-key validation path, breaking 2 of `resolveSharedSubfolderWriteKey`'s own throw-assertion tests. RESEARCH is a design INPUT, not the literal spec; the plan's "preserve original fail-open/fail-closed behavior" criterion overrode it.

**Impact:** Avoided a genuine security regression; documented the divergence in the primitive's JSDoc with a citation to the test file.

**Source:** 72-08-SUMMARY.md

### The two `getWriteBodyParams` copies were behaviorally identical but not source-identical

The plan's premise (from RESEARCH/PATTERNS) called them "byte-for-byte identical." In fact `client.ts` called the private `resolvePublishedNode` helper while `bin/index.ts` inlined `resolveIpnsRecord` + `fetchFromIpfs` + `JSON.parse` (a private class method can't be called from the standalone bin module). Only their branching/behavior matched. Plan 10's dedupe had to reconcile the call-site difference, standardizing on the inline form since the extra `signatureVerified` field was never consumed.

**Impact:** Plan 04 flagged it forward; Plan 10 confirmed behavioral equivalence before consolidating — a naive text-dedupe would have missed it.

**Source:** 72-04-SUMMARY.md, 72-10-SUMMARY.md

### The dead `moveInSharedFolder` branch hid a latent Ed25519-as-AES wrong-key bug

The unreachable `shareKeys.length > 0` legacy branch assigned an Ed25519 `ipnsPrivateKey` as an AES `destWriteKey`. It could never execute because its sole producer `fetchShareKeys` hard-returns `[]`, but it was still type-checked live surface. Deleting it (with `getShareKeysFn`) both slimmed the API and removed the latent bug.

**Impact:** SC#5 was as much bug removal as dead-code cleanup; `fetchShareKeys` itself stayed (still used by `resolveFileIpnsKey`).

**Source:** 72-07-SUMMARY.md

### SC#4's stated mechanism no longer existed in the codebase

The todo was written against a `SealedChildRef.size`/`modifiedAt` display mirror that was reverted in 68.2-12 (commit 3e1fcb176). The staleness symptom persisted but via a different mechanism — `listingCache` keyed on parent sequence, which a file-only publish never bumps — so the fix moved from a schema field refresh to a cache invalidation.

**Impact:** The requirement was materially reframed during research before any code was written, avoiding a schema change to the frozen node type.

**Source:** 72-06-SUMMARY.md, 72-RESEARCH.md Critical Finding 1

### `pnpm --filter sdk-e2e test -- <file>` does not filter; it runs the whole suite

The plan's literal verify command ran the ENTIRE sdk-e2e suite rather than the named file (the package's `test` script ignores the `--` filter arg), surfacing 2 pre-existing unrelated `tee-republish.test.ts` failures (`tee_key_state is empty` — an environment gap, not a code defect). The target file had to be run directly via `vitest run src/suites/write-chain-rotation.test.ts` for a clean scoped pass.

**Impact:** Scoped verification requires the direct `vitest run <path>` form; the filtered `test --` command gives misleading collateral failures.

**Source:** 72-02-SUMMARY.md

### A RED test can fail for the "wrong" reason and still be a valid RED gate

Plan 06 Task 1's RED failed via a thrown `TypeError` — passing a `true` boolean as the 3rd positional arg to the pre-fix 3-arg signature was misinterpreted as a truthy `migratedIpnsPrivateKeyEncrypted`, entering the unrelated migration branch and hitting a mocked default `undefined` return — rather than the intended assertion. This is still a legitimate RED, because the pre-fix code has no `fileContentChanged` param to receive the signal at all.

**Impact:** TDD RED verification should confirm the pre-fix code cannot satisfy the new contract, not insist on a specific failure message.

**Source:** 72-06-SUMMARY.md
