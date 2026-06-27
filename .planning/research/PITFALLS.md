# Pitfalls Research — v2.0 Metadata and Sharing Refactor (node/v3)

**Domain:** Brownfield security/crypto refactor — read key-chaining, resumable read-rotation, write-revocation via full Ed25519 rotation, TEE/resolve contract rewrite
**Researched:** 2026-06-27
**Confidence:** HIGH (sourced from design document, ADRs, codebase scar tissue, and project history)

---

## Critical Pitfalls

### Pitfall 1: AAD Byte-Encoding Drift Between TS and Rust = Silent Total Decryption Failure

**What goes wrong:**
The `buildNodeAad` function must produce an identical byte sequence in TypeScript (`packages/crypto`) and Rust (`crates/crypto`). If either side differs in any encoding detail — UUID bytes as a string vs raw 16-byte RFC-4122 big-endian, `generation` as little-endian vs big-endian, `kind` byte value, `role` byte value, or the null separator after the domain string — then every cross-language unseal silently returns a `DOMException: The operation failed` with no indication of which field diverged. This is a **total decryption failure** across every Node sealed by one side and read by the other (web seals, FUSE reads; desktop seals, web reads).

**Why it happens:**
The two crypto stacks share no code. TS uses `TextEncoder` for the domain string, Rust uses `b"..."` literals. UUID fields are easy to accidentally encode differently (`uuid.as_bytes()` = 16 raw bytes in RFC-4122 field order vs `uuid.to_string()` encoded as UTF-8). Generation is 4 bytes and big-endian is specified, but a developer implementing from spec can silently use the platform default. Role bytes must match the exact table (`0x01 body`, `0x02 child-readkey`, `0x03 content`, `0x04 child-writekey`); a transposition is invisible until an unseal fails.

**How to avoid:**
The design mandates a committed cross-language Known-Answer Test (KAT) fixture — one hardcoded test vector committed in `crates/crypto/tests/cross_language.rs` AND asserted by `packages/crypto/__tests__`. This must be the **first deliverable** in the crypto primitive phase, before any consumer is built. The KAT must exercise all four role bytes. The AAD encoding must be frozen in writing (the design's Section 2.5 encoding table is that freeze) and both implementors must implement strictly from it, not from the other language's source.

**Warning signs:**
Any `unsealAesGcmAad` call that worked in isolation (same-language round-trip) fails when the ciphertext crosses the TS/Rust boundary. FUSE read returning a deserialization error on a freshly-created node from the web app. KAT test missing or passing on mocked data.

**Phase to address:**
Crypto primitive phase (Phase 1 / `packages/crypto`). The KAT must be committed and passing before any downstream phase begins. Every subsequent phase that adds a new `role` byte must extend the KAT fixture.

---

### Pitfall 2: CRIT-1 — Content-Key Rotation Omitted from rotateOne = Silent Read-Revocation Bypass

**What goes wrong:**
Re-sealing a file node's read-body under a new `readKey` is not sufficient. The revoked reader already cached the old `readKey`, used it to unseal `content`, and holds the raw `content.fileKey`. If the next file version is encrypted under the same `fileKey`, the revoked reader decrypts it the moment they obtain the new CID (from any IPFS gateway — they do not need IPNS). The revocation appears complete (entry-point navigation is cut) but file content remains accessible.

**Why it happens:**
`rotateOne` is implemented to re-seal the read-body and bump `generation`; the file content path is a separate concern that is easy to miss when writing the rotation walk. `contentRekeyPending` must be set on the node; without it the next content write re-encrypts with the same `fileKey`. The failure is **silent** — no test will catch it unless a test specifically attempts to decrypt new content with the old `fileKey`.

**How to avoid:**
`rotateOne(N)` for a `kind: 'file'` node **must** mint a fresh `fileKey'` and set `contentRekeyPending` on the node record. The content write path must check `contentRekeyPending` and re-encrypt under the new `fileKey'`. Add a mandatory test: rotate a file node, publish a new version, assert a holder of the old `readKey`/`fileKey` cannot decrypt the new version (test item 2 in the design's Section 7.3).

**Warning signs:**
`rotateOne` implementation has no branch on `node.kind === 'file'`. `contentRekeyPending` marker is never written. Content write path does not read or clear `contentRekeyPending`. Any test that checks "revoked reader cannot access new version" is absent from the suite.

**Phase to address:**
Rotation engine phase (`packages/sdk-core` — `rotateReadFromNode`). Success criterion for the phase must require the CRIT-1 test passing before merge.

---

### Pitfall 3: M1 Generation Downgrade Defense Not Persisted = Silent Relay-Served Revocation Bypass

**What goes wrong:**
After a read-revoke rotation completes, a colluding or buggy relay can serve the revoked reader the pre-rotation (lower-generation) signed IPNS record indefinitely. The IPNS signature only covers the CID and sequence — not `generation`. The revoked reader's navigation succeeds from the old record. No in-memory client check survives a page refresh or app restart. The revocation appears to succeed but is undone by a relay rollback with zero signed evidence to the client.

**Why it happens:**
No resolve path in the current codebase enforces a per-node `generation` check. `resolve_sequence_strict` tracks only `sequence` in-memory and loses it on restart. `VerifiedResolve` exposes `{cid, sequence_number}` and never decodes node metadata. The M1 defense is entirely new work, not an extension of existing checks.

**How to avoid:**
Persist `{nodeId → highestGeneration}` durably (IndexedDB on web; sqlite in FUSE) seeded from the grant's `rootGeneration` as the owner-vouched floor. Thread this into `resolve_ipns_verified` (Rust) and `resolveIpnsRecord` (web) to fail closed on a generation regression. Add a server-side generation-forward gate in the publish path (`ipns.service.ts`) mirroring the existing sequence CAS. The durable map must survive process restart — any in-memory-only implementation silently removes the protection after restart.

**Warning signs:**
`generation` check is implemented but stored in a React state variable or a non-durable JS variable. The sqlite/IndexedDB write for `highestGeneration` is absent. Publish gate in `ipns.service.ts` only gates `sequenceNumber`. Test 5 from the design (M1 generation downgrade) is absent or mocked.

**Phase to address:**
API + resolve phase (atomic CAS, server-side generation gate); Web phase (durable M1 client map, IndexedDB); FUSE phase (durable sqlite map, `resolve_ipns_verified`). The server-side gate belongs with the API DB cutover phase; the client-side durable map belongs with web and FUSE implementation phases.

---

### Pitfall 4: HIGH-4 — Add-During-Rotation Child Drop = Silent Data Loss

**What goes wrong:**
`rotateOne` re-seals the parent's read-body from an in-memory `children[]` list decoded at step 3. A concurrent upload that CAS-wins first adds a new `SealedChildRef` to that parent. When rotation retries from a 409, it re-seals the body from the **stale** in-memory child list — the new child is gone from the sealed body, and the parent republishes without it. The upload appeared to succeed (the upload itself returned 200) but the file is now invisible to all clients and unreachable without the CID, which no parent links to.

**Why it happens:**
The 409 retry path re-seals from memory rather than re-fetching and re-decoding the parent node at the current sequence. It is a natural mistake to treat the CAS retry as "same operation, fresh sequence" rather than "refetch everything that could have changed."

**How to avoid:**
On every CAS-409 in `rotateOne`, **re-fetch the current parent node, re-decrypt the read-body, and merge any `SealedChildRef`s added since the initial decode** before re-sealing. The merge is: take the union of the pre-rotate child list and the freshly-fetched child list by `childId`, with the freshly-fetched entries winning for any conflict. Add the mandatory test (design Section 7.3, test 4): start a rotation, inject a concurrent upload via a separate client, assert the new child is present in the completed parent.

**Warning signs:**
`rotateOne` retry path re-seals from a captured variable rather than calling the decode path again. The `children` variable is captured in a closure that is not refreshed on retry. Test for concurrent modification is absent.

**Phase to address:**
Rotation engine phase (`packages/sdk-core` — `rotateReadFromNode`). The retry path must be reviewed explicitly in phase success criteria.

---

### Pitfall 5: HIGH-3 — Inner Grant Orphan = Grantee Permanently Locked Out

**What goes wrong:**
A node deep in a subtree being rotated was independently shared to a third party (e.g., a single-file share to Carol). The rotation re-mints `readDescriptorRef` only for grants rooted **at the rotation root** — not for grants whose `rootNodeId` is a descendant. Carol's grant row now wraps a `readKey` that has been rotated away. Her `readDescriptorRef` is permanently invalid and there is no recovery path (the owner no longer has the old `readKey` to re-derive). Carol is locked out with no error message other than "decryption failed."

**Why it happens:**
It is natural to implement grant re-mint as "re-mint all grants on the root node," missing that `shares.rootNodeId` can point to any node in the subtree, not just the root. Without an indexed scan of `shares` over the full rotated set, inner grants are silently skipped.

**How to avoid:**
The rotation engine must query `shares WHERE rootNodeId IN (rotated_node_ids)` for each batch of nodes processed, re-mint `readDescriptorRef` for each non-revoked recipient, and bump `rootGeneration`. This query must be batched with the walk, not only run at the rotation root. Add the mandatory test (design Section 7.3, test 3): a single-file share exists at a leaf of the deleted subtree; assert the inner grantee's `readDescriptorRef` is re-minted, and the revoked recipient is cut.

**Warning signs:**
Grant re-mint logic runs only at the initial call site in `rotateReadFromNode`, not in the per-node `rotateOne` callback. The `shares` table has no index on `rootNodeId`. No test exercises a grant rooted at an interior subtree node.

**Phase to address:**
Rotation engine phase, with API support for the batched `shares` query. The API query path should be implemented and tested in the same phase as `rotateReadFromNode`, not deferred.

---

### Pitfall 6: Republisher Incrementing Sequence During Rotation = Stale-CID Rollback / Revocation Bypass

**What goes wrong:**
The TEE 6-hour republisher currently does `+ 1n` on the sequence (`apps/tee-worker/src/routes/republish.ts:79`). During a rotation walk, a file node's pre-rotation record (with the old revoked-readable CID) gets republished at a **forward sequence** by the TEE. Because IPNS record selection is "higher sequence wins," the TEE's re-signed stale record now dominates the rotation's new record (which was published at an earlier sequence). The revoked reader receives the old, readable CID. The rotation appears to complete but is immediately undone by the next TEE cycle.

**Why it happens:**
The `sequence + 1` behavior was originally correct for availability (it ensures the refreshed record beats any cached older record on the network). The collision with rotation was not anticipated. The design's Section 4.6 initially incorrectly called the republisher "orthogonal" — this was corrected in the grilling session.

**How to avoid:**
The TEE republisher must **never increment the sequence**. The fix (design Section 6.2) is: the relay sends the marshaled existing signed record; the TEE parses it, verifies its signature, and re-emits a record with the **same value (CID) and same sequence** and only a later EOL. The IPNS equal-sequence/later-EOL tiebreak lets the refreshed record win network-wide without consuming a sequence. The publish path's `+ 1n` must be replaced on the TEE path. The atomic CAS gate (design Section 6.6) guards the idempotent renewal write identically.

**Warning signs:**
`republish.ts` still contains `sequenceNumber + 1n` on the TEE path after the TEE contract rewrite phase. The `apps/tee-worker` phase is treated as a small change rather than a contract rewrite. No test validates "republisher does not increment sequence" (design test 12).

**Phase to address:**
TEE worker rewrite phase (`apps/tee-worker`). Must be completed before any rotation E2E testing, since a misconfigured republisher poisons rotation correctness.

---

### Pitfall 7: Eager-vs-Lazy Scope-Exit Confusion = Massive Over-Rotation Storm on Private Deletes

**What goes wrong:**
The old `executeLazyRotation` rotated on every delete/move/rename. If the new implementation does not check "does this node have any covering grant?" before invoking `rotateReadFromNode`, every private (un-shared) delete triggers a full subtree rotation. A vault owner with 10,000 unshared files performs a routine folder delete and triggers 10,000 IPNS republishes, blocking the client for minutes and burning IPFS quota. This is not a security issue — it is a liveness / usability issue that will appear correct in unit tests but catastrophic at scale.

**Why it happens:**
The rotation call site is added to delete/move/rename without the scope predicate. The predicate ("any active grant covers this node") requires querying `shares` by `rootNodeId` ancestry, which is non-trivial and easy to skip in early implementations.

**How to avoid:**
The unified scope-exit rule is: **no covering grant → pure relink, zero rotations**. Implement `hasCoveringGrant(nodeId, ancestorIds)` as a required predicate at every delete/move/rename call site, gated against the relay-provided active grant set. Add a mandatory test (design Section 7.3, test 9): private delete with no grants → assert zero `rotateReadFromNode` invocations and zero `publishRecord` calls beyond the parent relink.

**Warning signs:**
Delete/move/rename call sites invoke `rotateReadFromNode` unconditionally. `hasCoveringGrant` function does not exist. The scope predicate is a TODO comment. No test counts publish calls for an un-shared node deletion.

**Phase to address:**
Rotation engine phase (scope-exit logic) and SDK + web mutation phase (delete/move/rename call sites). Both phases need the predicate; the predicate implementation belongs in the rotation engine phase.

---

### Pitfall 8: Tombstone Enforcement Gap = Revoked Writer Keeps Publishing Forever

**What goes wrong:**
Approach (c) write-revocation changes the Ed25519 keypair and k51 name. The old `ipns_records` row persists and the publish gate has zero tombstone awareness, so the revoked co-writer's cached Ed25519 key can publish to the old name indefinitely. The old name's signed record is still served by the relay's resolve path (it has a valid signature and a non-deleted row). Clients with bookmarks to the old name resolve stale (pre-rotation) content. The write revocation is cryptographically complete on the new name but operationally bypassed on the old one.

**Why it happens:**
`unenrollIpns` only deletes the republish schedule row, not the `ipns_records` row, and adds no publish rejection flag. The publish gate in `ipns.service.ts` checks only sequence monotonicity and key-possession (`existing.publicKey.equals(...)`), not tombstone state. The tombstone is a new concept that requires a new DB column and a new gate check.

**How to avoid:**
On write-revocation, mark the old row with `tombstonedAt` (design Section 5.5). The publish gate must check `tombstonedAt IS NOT NULL` and return 403/410 before the sequence check. Resolve must return 410 (or a tombstone marker in the response) for a tombstoned name, never stale content. The TEE republisher's renewal must also be blocked at the publish-gate tombstone check, so a malicious relay cannot feed the old signed record to an honest TEE and keep the revoked name's lease alive. Add test 20 (design Section 7.3): write to a tombstoned name → 403/410; resolve a tombstoned name → 410, not stale content.

**Warning signs:**
`tombstonedAt` column does not exist in the migration. Publish gate checks only sequence and pubkey. Resolve falls through to the network record for tombstoned rows. `unenrollIpns` is used as the write-revocation teardown rather than a separate tombstone path.

**Phase to address:**
API DB cutover and publish-gate phase. Tombstone schema and gate logic must be in the same migration as the write-revocation implementation.

---

### Pitfall 9: Non-Atomic Publish CAS = Silent Lost Writes Under Concurrency

**What goes wrong:**
`publishRecord` is currently a non-atomic `findOne → gate → save` in TypeORM with no row lock and no conditional UPDATE. Two concurrent forward writers both at `dbSeq = N` both pass the gate check and the second `.save()` silently overwrites the first. The first writer receives `200` and believes the write landed. This is a data-loss bug that is invisible in single-client tests and appears only under realistic multi-device or rotation+upload concurrency.

**Why it happens:**
TypeORM `.save()` is not atomic. The design's existing "sequence CAS" at `ipns.service.ts:301-317` is implemented as application-level logic, not a SQL `WHERE sequenceNumber = :expected` constraint. This gap existed in v1.1 and the design's Section 6.6 explicitly calls it out as unresolved.

**How to avoid:**
Replace the `findOne → gate → save` with a single conditional UPDATE:

```sql
UPDATE ipns_records SET latestCid = :cid, sequenceNumber = :next, signedRecord = :rec, updatedAt = now()
WHERE ipnsName = :name AND sequenceNumber = :expected
```

Zero rows affected = 409 to the client. The EOL-only renewal (TEE lease) hits the same gate with `WHERE sequenceNumber = :loaded` so it can never regress `latestCid` from a stale in-memory row. Add test 16 (design Section 7.3): two concurrent publishes at the same `dbSeq` → exactly one 409, zero lost updates.

**Warning signs:**
`publishRecord` still contains `findOne` followed by `save`. No `WHERE sequenceNumber = :expected` in any UPDATE. The "D-09 idempotent branch" short-circuits before the CAS rather than hitting the same conditional UPDATE. Test for concurrent writes is absent.

**Phase to address:**
API DB cutover phase. This is a correctness fix that must land before any rotation E2E testing.

---

### Pitfall 10: TEE Relay-as-Signing-Oracle Trap = Write-Forgery Risk

**What goes wrong:**
If the TEE's lease-renewer contract is implemented as "receive a CID scalar from the relay, sign it with the wrapped IPNS key" rather than "receive a marshaled signed record, verify its signature, extend only the EOL," then the relay can coerce the enclave to sign any CID for any name it controls. A token-validation bug, SSRF, or auth bypass allows the relay to forge IPNS records under users' IPNS keys — exactly what a zero-knowledge system is designed to prevent. The enclave's security guarantee is reduced to "API server is trustworthy," negating the TEE's purpose.

**Why it happens:**
The prior (stale) contract had the republisher sourcing `latestCid` from the `ipns_republish_schedule` snapshot. The simplest "fix" for the stale-CID bug is "refresh the snapshot from the canonical row" — which is still the scalar-signing trap. The structural fix (parse, verify, extend-EOL-only) requires more implementation complexity and a different enclave API shape.

**How to avoid:**
The new enclave contract (design Section 6.4): (1) relay sends the **marshaled existing `signedRecord`** bytes, not a CID scalar; (2) the TEE parses it and **verifies the embedded signature**; (3) TEE re-emits a record with the **same value (CID) and same sequence**, only a later EOL. The enclave cannot be fed a CID it did not verify from a pre-existing valid record. Additionally, the three enclave bindings (design Section 6.7) must be present: internal epoch derivation (TEE derives `currentEpoch` from its own clock, never from relay-supplied scalars), name↔key binding (assert `publicKeyFromIpnsName(name) == pubkey(decryptedKey) == record.pubkey`), and migration durability (refuse to renew a key older than `currentEpoch - 1`).

**Warning signs:**
TEE API receives a CID field from the relay rather than a marshaled signed record. TEE does not call a signature-verify function before re-emitting. Epoch scalars are passed in from the relay request body. Name↔key assertion is absent.

**Phase to address:**
TEE worker rewrite phase (`apps/tee-worker`). The three Section 6.7 bindings must be in the same phase as the lease-renewer contract, not deferred.

---

### Pitfall 11: `folder_ipns.public_key` Null-Row Footgun (Repeated Phase-60 Regression Pattern)

**What goes wrong:**
The `folder_ipns.public_key` column is null for shared-folder rows and not always populated for other rows. Any code that reads `row.public_key` to obtain the Ed25519 pubkey for strict-verify will silently get `null` on shared-folder rows, causing either a null-dereference crash or a skipped signature verify (if the null check gates the verify call). This pattern caused two Phase-60 regressions in unit tests that were not caught because the tests did not use shared-folder rows.

**Why it happens:**
The column exists in the schema as a convenience but is nullable and unreliable. Developers implementing new resolve or rotation paths naturally reach for `row.public_key` because it is on the same row — it is only null for a subset of rows that may not appear in unit test fixtures.

**How to avoid:**
The design's Section 7.1 and 7.2 mandate: drop `folder_ipns.public_key` outright (it is derivable from the k51 name via `publicKeyFromIpnsName`). The migration must include `ALTER TABLE ipns_records DROP COLUMN public_key`. Every strict-verify call must recover the Ed25519 pubkey from the k51 name via `publicKeyFromIpnsName`, never from the column. Add a test with a shared-folder `ipns_records` row (null `public_key`) and assert that strict-verify works correctly.

**Warning signs:**
Any code containing `row.public_key` or `ipnsRecord.publicKey` after the migration phase. `publicKeyFromIpnsName` is not imported in paths that previously used the column. Test fixtures only use owner rows (never shared-folder rows with null column).

**Phase to address:**
API DB cutover phase (the migration drops the column). FUSE and SDK-core resolve phases must verify they use `publicKeyFromIpnsName` and never the dropped column.

---

### Pitfall 12: winfsp Module Nesting Trap (`super::` vs `super::super::`) = Windows CI Failure, Invisible Locally

**What goes wrong:**
The Rust `winfsp` feature cannot compile on macOS — `windows/*` modules (`#[cfg(winfsp)]`) are silently excluded from local `cargo check`/`cargo test`. A `super::` path inside a doubly-nested `pub mod implementation { pub mod write_ops { ... } }` that should be `super::super::` compiles cleanly on macOS and fails only on the Windows CI gate. This exact pattern (`super::content_fetch` instead of `super::super::content_fetch`) surfaced in Phase 55. The `node/v3` refactor deletes `spawn_file_meta_reencrypt` at `crates/fuse/src/metadata.rs:655` — its callers are `write_ops/implementation/rename.rs:248` **and** `platform/windows/write_ops.rs:1182` (the WinFsp twin). Missing the twin and getting the nesting wrong are two independent failure modes, both invisible on macOS.

**Why it happens:**
macOS developers never see Windows-only modules compile. Path bugs in `platform/windows/write_ops.rs` look correct locally because the file is never loaded. Module nesting in `platform/windows/write_ops.rs` is one level deeper than the macOS equivalent, so a copy-paste from the macOS side uses the wrong number of `super::` prefixes.

**How to avoid:**
Any FUSE phase touching `crates/fuse/src` must budget a Windows CI round-trip (`gh workflow run "Cargo Check & Test (Windows)"`) as a phase completion gate, not a merge afterthought. The phase plan must explicitly list `platform/windows/write_ops.rs` as a file to check alongside its macOS counterpart for every deletion or refactor. Use `grep -r "spawn_file_meta_reencrypt\|reencrypt" crates/fuse/` to locate all callers before beginning.

**Warning signs:**
FUSE phase does not mention `platform/windows/write_ops.rs` in its blast radius. Phase success criteria do not include running the Windows Cargo CI gate. The `super::` depth in a new `platform/windows/` path is not independently reviewed.

**Phase to address:**
FUSE implementation phase. Make the Windows CI gate a required check in the phase's success criteria, not optional.

---

### Pitfall 13: Folderless Zustand/SDK folderTree Desync = "Folder not loaded" Class Under Rotation

**What goes wrong:**
The scope-exit predicate and the rotation walk both require a consistent view of which IPNS nodes are covered by active grants (`folderTree` in the web app, `PublishCoordinator` / in-memory tree in FUSE). If `folderTree` in Zustand has not been reconciled to the current `sequenceNumber` before a delete or move triggers the scope predicate, the predicate may compute "no covering grant" for a node that actually has one (because the grant was added since the last sync) — silently skipping a required rotation. This is the same desync class that produced `#489` / `#494` ("Folder not loaded," "stale-sequence 409 + merge resurrecting deleted files").

**Why it happens:**
The web app's `folderTree` and the SDK client's `folderTree` are separate state stores. A direct SDK mutation (e.g., a background rotation resuming mid-session) can advance the SDK's tree without advancing Zustand. The scope-exit check at delete/move time reads the Zustand store, which is stale.

**How to avoid:**
Reconcile `folderTree` against the current `sequenceNumber` before any scope-exit predicate evaluation (design Section 3.9). If reconciliation fails (cannot resolve the current IPNS state), the mutation **defers** rather than skips the rotation. The reconcile-before-publish discipline already exists in the codebase — apply it explicitly at the rotation entry point. Add a test that simulates a stale `folderTree` at the time a delete is invoked and asserts the rotation is either deferred or correctly computed from the refreshed tree.

**Warning signs:**
Scope-exit predicate reads `useFolderStore.getState().folderTree` without first calling a reconcile. The rotation entry point in the web layer does not await a sync before computing coverage. No test uses a pre-stale Zustand store to trigger a delete.

**Phase to address:**
Web implementation phase (the `executeLazyRotation` → `rotateReadFromNode` replacement). Add reconcile-before-rotate as a required step in the phase plan.

---

### Pitfall 14: SDK-Core Coverage Excludes `index.ts` Barrels = Rotation Engine Silently Uncovered

**What goes wrong:**
vitest coverage excludes `src/**/index.ts` barrels. If the `rotateReadFromNode` implementation or the `sealAesGcmAad` primitive is placed in a fat `index.ts` barrel file (to match existing sdk-core patterns), that code is excluded from coverage reports. A phase can hit the 80% coverage gate while leaving the most security-critical code unexercised by the coverage tool. The coverage gate passes, the phase completes, and silent gaps exist in the rotation engine.

**Why it happens:**
The sdk-core pattern uses fat `index.ts` files. Developers naturally add new exports to the nearest `index.ts`. The coverage exclusion is a project-specific configuration that is easy to forget (it was discovered in Phase 55 when `folder/index.ts` split dropped coverage to 77.11%).

**How to avoid:**
The rotation engine (`rotateReadFromNode`, `rotateOne`, `verifySubtreeClean`) and the job record persistence must be implemented in **named files** (e.g., `src/rotation/engine.ts`, `src/rotation/job.ts`), not in `index.ts` barrels. The design's Section 7.2 explicitly states: "in named files, not a fat `index.ts` barrel — coverage excludes barrels." The phase plan must name the output files, not just the API surface.

**Warning signs:**
`rotateReadFromNode` is exported from `src/index.ts`. Phase plan says "add to sdk-core" without specifying file names. Coverage report shows high percentage but `src/index.ts` is in the exclusion list.

**Phase to address:**
`packages/sdk-core` rotation engine phase. File naming must be specified in the phase plan as a success criterion.

---

### Pitfall 15: Web vitest Only Runs `*.test.ts` Files = Rotation Specs Silently Skipped

**What goes wrong:**
`apps/web` vitest configuration's `include` pattern is `src/**/*.test.ts`. Any test file named `*.spec.ts` is silently skipped and never appears in CI results. If rotation-related tests for the web layer are created with `.spec.ts` naming (which is common in NestJS-pattern tests and SDK integration tests), they never run. The CI passes and the tests are never executed.

**Why it happens:**
The web app adopted the `*.test.ts` convention but it is not enforced by any lint rule. Test file naming is easy to get wrong when copying from SDK or API test patterns that use `.spec.ts`.

**How to avoid:**
All test files for `apps/web` must use `.test.ts` naming. When creating new tests in the web phase, verify file naming convention before committing. A grep across the web test directory for `.spec.ts` is a cheap phase entry check.

**Warning signs:**
New test files in `apps/web/src/` with `.spec.ts` extension. CI shows no new test cases despite new test files being committed.

**Phase to address:**
Web implementation phase. Add a check in the phase plan: `find apps/web/src -name "*.spec.ts"` must return empty.

---

### Pitfall 16: Zeroization of Caller-Owned Reused Buffers in SDK E2E = 400 "publicKey does not correspond"

**What goes wrong:**
If `rotateReadFromNode` or any rotation helper zero-clears a key buffer that was passed in by the caller (rather than a buffer it owns), subsequent SDK operations that reuse that caller-owned buffer (e.g., the user's `publicKey` or a grant's `readKey`) will operate on a zeroed buffer and produce 400 errors from the API ("publicKey does not correspond"). This broke 48/89 SDK E2E tests in a prior incident. The failure is a runtime regression at SDK E2E level — unit tests will not catch it because they do not share buffers across calls.

**Why it happens:**
Zeroization discipline requires clearing key material after use. A callee that receives a buffer it does not own (e.g., the caller's `readKey`) zeros it "for safety" on completion, not realizing the caller reuses it across multiple operations. The bug is invisible in isolated unit tests.

**How to avoid:**
Rotation helpers must zero only key material they allocate. A caller-passed `readKey` buffer must be treated as owned by the caller; if the helper needs to zero something, it must zero its own derived copy. Document this in the function's JSDoc. The SDK E2E suite (`tests/sdk-e2e`) must run after any rotation helper is added — it is the only test that exercises real client→API IPNS publish/resolve round-trips with shared buffers.

**Warning signs:**
Any rotation helper calling `key.fill(0)` on a parameter buffer. SDK E2E failures of the form "400 publicKey does not correspond" after a rotation call. Unit tests all pass while SDK E2E shows `48/89` failures.

**Phase to address:**
`packages/sdk-core` rotation engine phase. Add a reminder in the phase plan: zero only locally-allocated buffers, never caller parameters. SDK E2E must pass before phase sign-off.

---

### Pitfall 17: SDK E2E Is the Only Real Publish/Resolve Gate — Desktop E2E Is Dispatch-Gated

**What goes wrong:**
`tests/sdk-e2e` is the only test suite that exercises a real client→API IPNS publish/resolve round-trip. It is not run on PRs by default (requires a live API). The desktop E2E (`apps/desktop`) is dispatch-gated — `CI E2E Tests` skips desktop on main pushes that do not touch desktop paths. A rotation engine merged to `packages/sdk-core` and a FUSE rewrite merged to `crates/fuse` can both pass unit CI and land on `main` without the full integration ever running.

**Why it happens:**
The gating is intentional (cost/speed), but it creates a coverage gap for the rotation feature that is more significant than for stable features — rotation is the first feature that exercises the full publish-rotate-resolve-verify loop at real IPNS latency.

**How to avoid:**
After the rotation engine phase and after the FUSE phase, run the SDK E2E suite manually (`tests/sdk-e2e` with the local API stack up) and run the desktop E2E via `gh workflow run "CI E2E Tests" --ref <branch>`. Do not merge the rotation engine or FUSE phases without at least one SDK E2E pass and one Windows CI pass. These must be explicit gates in the phase completion checklist, not post-merge follow-ups.

**Warning signs:**
Phase sign-off does not include "SDK E2E run locally." Desktop E2E CI gate is not triggered on the FUSE phase branch. Phase completion criteria only reference unit tests.

**Phase to address:**
Rotation engine phase (sdk-core) and FUSE phase — both must add SDK E2E and desktop E2E as explicit phase gates.

---

### Pitfall 18: `parseCachedRecord`-Null Fall-Through Serves Ungated Network Records

**What goes wrong:**
When `parseCachedRecord` returns null for a shared-folder `ipns_records` row (which legitimately has a null `signedRecord`), the resolve path currently falls through to the network record without applying any sequence floor. A malicious relay can exploit this by serving an old, legitimately-signed, low-sequence network record to a shared-folder reader without triggering any gate. This is not the same as the tombstone case; it is the normal shared-folder resolve path being ungated.

**Why it happens:**
The null check was originally added to handle corruption or absence. The shared-folder case (where `signedRecord` is legitimately null because the owner holds the key and the shared-folder row is a skeleton) was not distinguished from the corruption case. The design's Section 6.5 makes the case-split explicit: null-signedRecord for shared-folder rows → apply `seq ≥ storedSeq` floor from the DB `sequenceNumber` column; `signedRecord`-CID mismatch → fail closed.

**How to avoid:**
Implement the two-case split explicitly in `resolveRecord`: (1) if `signedRecord` is null and the row's `sequenceNumber` is set, apply `seq ≥ storedSeq` floor to the network record; (2) if `signedRecord` is present but its decoded CID disagrees with `latestCid`, fail closed with a 500/503, never falling through. Add test 15 (design Section 7.3): verify both cases behave correctly.

**Warning signs:**
The null check in `resolveRecord` is a single `if (signedRecord == null) return networkResult` with no floor. The two-case distinction is absent. No test uses a legitimate null-`signedRecord` shared-folder row.

**Phase to address:**
API resolve hardening phase (same as the atomic CAS and the generation gate).

---

### Pitfall 19: `spawn_file_meta_reencrypt` — Two Callers, Not One

**What goes wrong:**
The `node/v3` content self-seal (Section 2.9) makes file moves pure re-links (no re-encryption needed). This kills `spawn_file_meta_reencrypt` (`crates/fuse/src/metadata.rs:655`). The function has two callers: `write_ops/implementation/rename.rs:248` (visible on macOS) and `platform/windows/write_ops.rs:1182` (the WinFsp twin, invisible on macOS). If only the first caller is deleted, `platform/windows/write_ops.rs` retains a call to a deleted function and fails on the Windows CI gate with a compilation error.

**Why it happens:**
The two-caller structure mirrors the macOS/Windows split that exists throughout `crates/fuse`. The Windows twin is only visible under `#[cfg(winfsp)]` and requires a CI round-trip to verify. This exact pattern (a function called from both paths) caused the Phase-55 `super::` nesting bug.

**How to avoid:**
Before beginning the FUSE phase, run `grep -r "spawn_file_meta_reencrypt\|reencrypt" crates/fuse/` and list all callers in the phase plan. Treat the deletion as complete only after both callers are removed and the Windows Cargo CI gate passes.

**Warning signs:**
FUSE phase plan only mentions `rename.rs` as the caller to update. `platform/windows/write_ops.rs` is not in the blast radius list.

**Phase to address:**
FUSE implementation phase. This is a two-file deletion; both files must be listed in the phase plan explicitly.

---

### Pitfall 20: Cold-Node Filename Leak via Plaintext `SealedChildRef.name` on Un-Rotated Tail

**What goes wrong:**
`SealedChildRef.name` is plaintext **within** the parent's sealed read-body. A revoked reader who already decrypted the parent's read-body (before the rotation reached the parent) has a copy of all child names, including names of items added **after** the revocation but before the rotation reached that node. The lazy-walk variant of the old `executeLazyRotation` had this bug (MED-5 in the design). The eager walk of `rotateReadFromNode` bounds the window, but does not eliminate it: filenames added to a not-yet-rotated node are visible to the revoked reader.

**Why it happens:**
Name confidentiality within the sealed body depends on the parent node being rotated before the revoked reader can re-read the parent. During a multi-hour rotation walk over a large subtree, names added to interior nodes between the root step and the node's own rotation step are exposed. The root step cuts navigation from the entry point, but a reader who pre-fetched the interior node's CID can still unseal the body with the cached `readKey`.

**How to avoid:**
This is an accepted bounded residual under the eager-walk model (ADR 0002): the exposure window is ≤ the walk duration and the root step cuts the entry point immediately. Do NOT build a lazy-walk variant that leaves this window indefinitely open. The phase plan must document this residual in the rotation engine phase's security properties section so it is explicit, not an oversight. The optional per-file "re-encrypt now" path (design Section 4.1) is the mitigation for high-sensitivity cases.

**Warning signs:**
A deferred implementation adds lazy-walk logic as an "optimization" without documenting the MED-5 filename-leak regression. Phase success criteria do not state the eager-walk invariant.

**Phase to address:**
Rotation engine phase. The invariant "eager walk only; lazy walk is deferred and documented as introducing MED-5 regression" must be stated in the phase plan.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
| -------- | ----------------- | -------------- | --------------- |
| Skipping KAT in crypto primitive phase | Faster initial PR | Silent total decryption failure at first cross-language read | Never |
| In-memory generation high-water (not persisted) | Simpler implementation | M1 defense evaporates on page reload / app restart | Never |
| Mocking IPNS in rotation crash-safety tests | Faster test execution | Resume/idempotency never exercises real CAS race | Never for crash-safety suite |
| Adding `rotateReadFromNode` to `index.ts` barrel | Consistent with existing sdk-core pattern | Implementation excluded from coverage; 80% gate passes with uncovered rotation engine | Never |
| Using `folder_ipns.public_key` column instead of `publicKeyFromIpnsName` | Fewer function calls | Null-row crash on shared-folder rows (known Phase-60 pattern) | Never |
| Running only unit tests to sign off FUSE phase | Fast phase completion | Windows CI winfsp path has undetected `super::` nesting bugs | Never |
| Treating TEE tombstone and schedule-row deletion as equivalent | Simpler teardown | Revoked name keeps being renewed; publish gate is never closed | Never |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
| ----------- | -------------- | ---------------- |
| `pnpm api:generate` | Skipping after `apps/api` DTO changes for `shares`, `ipns_records` | Always run after API changes; `check-api-client.sh` pre-commit hook enforces this, but only when staged correctly |
| SDK E2E (`tests/sdk-e2e`) | Running against a mocked API or skipping entirely | Must run against a live local stack (`docker compose up` + `pnpm --filter @cipherbox/api dev`); it is the only real publish/resolve gate |
| Desktop E2E | Checking CI result on a main push that didn't touch `apps/desktop` | Trigger explicitly: `gh workflow run "CI E2E Tests" --ref <branch>` |
| TypeORM migrations | Using `synchronize: true` locally to verify DB shape | `synchronize` is off everywhere; write explicit migration and verify it with `migrationsRun: true` |
| Atomic CAS | Using TypeORM `.save()` for sequence-gated publishes | Use raw `UPDATE … WHERE sequenceNumber = :expected` and check rows-affected |
| TEE epoch scalars | Reading epoch from relay request body in the enclave | TEE derives `currentEpoch` from its own clock + schedule; relay-supplied epoch scalars are untrusted and ignored |

---

## "Looks Done But Isn't" Checklist

- [ ] **Crypto primitive:** KAT fixture committed and asserted by both `packages/crypto/__tests__` and a Rust `#[test]` — verify all four role bytes are in the fixture
- [ ] **Rotation engine:** `rotateOne` for file nodes mints `fileKey'` and sets `contentRekeyPending` — verify by checking for `node.kind === 'file'` branch in the implementation
- [ ] **Rotation engine:** 409-retry path re-fetches and re-merges the parent's `SealedChildRef` list — verify no captured stale `children` variable
- [ ] **Rotation engine:** Scope-exit predicate exists and gates every delete/move/rename call site — verify with a test counting zero publishes for an un-shared delete
- [ ] **Grant re-mint:** Inner grants (those with `rootNodeId` pointing to a node inside a rotated subtree, not the root) are re-minted — verify test 3 from the design test strategy
- [ ] **Tombstone:** `tombstonedAt` column exists; publish gate checks it before the sequence gate; resolve returns 410; TEE renewal is blocked at the same gate
- [ ] **Republisher:** `apps/tee-worker` no longer increments `sequenceNumber`; same sequence is re-signed with extended EOL only
- [ ] **M1 generation high-water:** Persisted to IndexedDB (web) / sqlite (FUSE), survives restart, seeded from `rootGeneration` on first grant receipt
- [ ] **Atomic CAS:** `publishRecord` uses a conditional UPDATE; `.save()` is gone from the publish path
- [ ] **`folder_ipns.public_key` column:** Dropped in migration; no code reads `row.public_key` or `record.publicKey` from the DB row
- [ ] **`platform/windows/write_ops.rs`:** Updated alongside the macOS FUSE path for every file touched in the FUSE phase
- [ ] **Windows CI gate:** `Cargo Check & Test (Windows)` passes for every FUSE phase PR
- [ ] **SDK E2E:** Runs and passes after rotation engine and FUSE phases before merge
- [ ] **api:generate:** Regenerated client committed alongside every API endpoint/DTO change
- [ ] **`apps/web` tests:** All new test files use `.test.ts` not `.spec.ts`
- [ ] **sdk-core rotation files:** Named files (not `index.ts`); coverage report shows them as covered

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
| ------- | ---------------- | ------------ |
| AAD byte-encoding drift (TS/Rust KAT) | Crypto primitive phase (Phase 1) | KAT fixture committed and passing in both `packages/crypto` and `crates/crypto` |
| CRIT-1 content-key rotation omitted | Rotation engine phase (sdk-core) | Test: old `fileKey` cannot decrypt new version after rotation |
| M1 generation downgrade not persisted | API (server gate) + Web (IndexedDB) + FUSE (sqlite) phases | Test: generation regression rejected after restart |
| HIGH-4 add-during-rotation child drop | Rotation engine phase | Test: concurrent upload is present in rotated parent |
| HIGH-3 inner grant orphan | Rotation engine phase + API (query support) | Test: inner grantee's `readDescriptorRef` re-minted on subtree rotation |
| Republisher sequence increment | TEE worker rewrite phase | Test: republish does not increment sequence; stale CID not re-signed |
| Over-rotation on private deletes | Rotation engine + web/SDK mutation phases | Test: zero publish calls for un-shared delete |
| Tombstone enforcement gap | API DB cutover + publish-gate phase | Test: write to tombstoned name → 403/410; resolve → 410 |
| Non-atomic publish CAS | API DB cutover phase | Test: concurrent publishes → exactly one 409 |
| TEE relay-as-signing-oracle | TEE worker rewrite phase | Test: TEE epoch self-derives; name↔key binding asserted |
| `folder_ipns.public_key` null-row footgun | API DB cutover phase (migration drops column) | No code references `row.public_key`; shared-folder strict-verify test |
| winfsp nesting trap | FUSE implementation phase | `Cargo Check & Test (Windows)` CI gate required in phase success criteria |
| folderTree/SDK desync | Web implementation phase | Reconcile-before-rotate at every scope-exit entry point |
| sdk-core barrel coverage gap | sdk-core rotation engine phase | Named files; coverage report includes rotation engine files |
| `*.spec.ts` silently skipped in web vitest | Web implementation phase | `find apps/web/src -name "*.spec.ts"` returns empty |
| Zeroization of caller-owned buffers | sdk-core rotation engine phase | SDK E2E passes after rotation helpers added |
| SDK E2E / desktop E2E dispatch-gating | Rotation engine phase + FUSE phase | SDK E2E run manually; desktop E2E triggered explicitly before merge |
| `parseCachedRecord`-null fall-through | API resolve hardening phase | Test: null-signedRecord shared-folder row applies seq floor, not ungated network |
| `spawn_file_meta_reencrypt` twin caller | FUSE implementation phase | Both `rename.rs` and `platform/windows/write_ops.rs` updated; Windows CI passes |
| Cold-node filename leak on rotation tail | Rotation engine phase | Eager-walk invariant documented; no lazy-walk variant introduced |

---

## Sources

- `.planning/design/2026-06-26-sharing-read-keychaining-design.md` — primary design source; findings CRIT-1, M1, HIGH-3, HIGH-4, MED-5, MED-6, m1–m4 and Section 7.3 test strategy
- `docs/adr/0001-write-revocation-full-ed25519-rotation.md` — write-revocation rationale and consequences
- `docs/adr/0002-read-revocation-protects-future-content-only.md` — content-key rotation scope and accepted residuals
- `CONTEXT.md` — glossary and counter disambiguation (`generation` vs `keyEpoch` vs `sequenceNumber`)
- `docs/METADATA_EVOLUTION_PROTOCOL.md` — schema versioning discipline; cross-platform round-trip requirements
- `docs/DATABASE_EVOLUTION_PROTOCOL.md` — migration discipline; conditional-UPDATE patterns
- `CLAUDE.md` (project) — critical security rules; `Critical Security Rules` section
- Project memory (`MEMORY.md`) — Phase-60 null-column regressions; winfsp nesting trap; sdk-core barrel coverage; SDK E2E as only real publish/resolve gate; zeroization bug; desktop E2E dispatch-gating; web vitest `.test.ts` only; folderTree/Zustand desync class

---

_Pitfalls research for: v2.0 Metadata and Sharing Refactor (node/v3 read key-chaining)_
_Researched: 2026-06-27_
