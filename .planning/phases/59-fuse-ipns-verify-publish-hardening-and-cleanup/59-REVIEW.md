---
phase: 59-fuse-ipns-verify-publish-hardening-and-cleanup
reviewed: 2026-06-23T00:00:00Z
depth: deep
files_reviewed: 11
files_reviewed_list:
  - crates/fuse/src/fs.rs
  - crates/fuse/src/inode.rs
  - crates/fuse/src/verify.rs
  - crates/fuse/src/events.rs
  - crates/fuse/src/publish.rs
  - crates/fuse/src/metadata.rs
  - crates/fuse/src/replay.rs
  - crates/fuse/src/content_ops.rs
  - crates/fuse/tests/ipns_verify_vectors.rs
  - scripts/gen-ipns-verify-vectors.ts
  - tests/vectors/ipns/verify.json
findings:
  critical: 2
  warning: 2
  info: 1
  total: 5
status: issues_found
---

# Phase 59: Code Review Report

**Reviewed:** 2026-06-23
**Depth:** deep
**Files Reviewed:** 11
**Status:** issues_found

## Summary

Phase 59 implements HARD-10 Findings A–F across the FUSE IPNS verify/publish path. Findings A (error propagation in `fs.rs::build_folder_metadata`), B (re-resolve on pointer-identity change in `inode.rs`), C (`VerifyError::Legacy` carrying cid/sequence to kill the redundant second resolve), and D/E (dead-code removal) are implemented correctly and verified across all five legacy callers and the build-folder-metadata key-wrap path. No key bytes are logged on the propagated error.

**Finding F is broken and ships a cross-layer compatibility regression plus a fixture/generator desync.** The phase removed the resolve-side first-publish skew allowance (`resp_seq == 1 && embedded_seq == 0`) and asserts "all clients now embed 1 on first publish." That premise is false: the live FUSE folder-creation (`mkdir`) path on **both** macOS and Windows still embeds `0` on first child-folder publish, and was not touched this phase. The API stores DB `sequenceNumber = '1'` for any first publish (accepting embedded 0 or 1). Therefore every folder created by the current/live app produces a signed record whose embedded sequence is `0` while the DB returns `1` — which the new strict `embedded_seq == resp_seq` check now classifies as `VerifyError::Invalid`. Depending on the resolve site this fails the operation or hard-fails folder-key resolution. The TS SDK resolve side still retains the skew allowance, so this is a Rust-only regression that bricks resolution of records the Rust app itself writes.

## Critical Issues

### CR-01: Strict sequence equality rejects first-publish records the live FUSE app still writes with embedded seq 0

**File:** `crates/fuse/src/verify.rs:112` (with `crates/fuse/src/write_ops/implementation/mkdir.rs:174` and `crates/fuse/src/platform/windows/write_ops.rs:202`)

**Issue:** Finding F removed the skew allowance in `bind_verified`:

```rust
let seq_ok = embedded_seq == resp_seq;   // was: embedded_seq == resp_seq || (resp_seq == 1 && embedded_seq == 0)
```

The justification in the comment (verify.rs:104-107) claims "FUSE now embeds 1 on first publish ... All clients now embed 1 on first publish, so the skew window no longer exists." This is **not true for the live folder-creation path**. The live mkdir child-folder first publish still embeds `0`:

- `crates/fuse/src/write_ops/implementation/mkdir.rs:174` — `create_ipns_record(&ipns_key_arr, &value, 0, 86_400_000)` (macOS, unchanged this phase)
- `crates/fuse/src/platform/windows/write_ops.rs:202` — `create_ipns_record(&ipns_key_arr, &value, 0, 86_400_000)` (Windows, unchanged this phase)

The API stores DB `sequenceNumber = '1'` for any first publish regardless of whether the client embedded 0 or 1 (`apps/api/src/ipns/ipns.service.ts:280-285` accepts embedded ∈ {0,1}; line 362 unconditionally stores `'1'`; the stored `signedRecord` is the client's record embedding 0). On a subsequent resolve of such a folder: `resp.sequence_number == "1"`, `embedded_seq == 0`, so `0 == 1` is false → `bind_verified` returns `VerifyError::Invalid`.

Consequences by site (all routing through `resolve_ipns_verified`):
- `replay.rs::resolve_folder_key` (line 349) — `Invalid` is a hard fail-closed: `return Err(...)` aborts folder-key resolution for any vault containing a folder created by the live app, breaking replay of that vault's journal entries.
- `metadata.rs`, `events.rs`, `content_ops.rs`, `fs.rs` FilePointer resolve — `Invalid` fails the specific operation; folder metadata refresh / writes against a freshly-created subfolder fail until a second (seq-2) publish happens to land.

This only affects the **single-generation window** (DB seq == 1) — once any seq-2 publish occurs, embedded and DB agree at 2. But that window is exactly the lifetime of a newly created folder before its first mutation, and replay (resolve_folder_key) walks ALL folders in the tree, so one new folder anywhere can fail the whole BFS.

The TS SDK resolve path (`packages/sdk-core/src/ipns/index.ts:285-287`) still has the allowance, confirming the cross-layer contract was NOT unified — only the Rust resolve side was tightened.

**Fix:** Either (a) revert the skew-allowance removal in `bind_verified` until the live mkdir paths are migrated to embed 1, or (b) within this phase, also change the live first-publish embed to 1 to match `next_file_publish_sequence`:

```rust
// crates/fuse/src/write_ops/implementation/mkdir.rs:174 and
// crates/fuse/src/platform/windows/write_ops.rs:202
let record = cipherbox_core::ipns::create_ipns_record(
    &ipns_key_arr, &value, 1, 86_400_000,   // was 0
)?;
// and the matching coordinator.record_publish(&ipns_name_clone, 1);  // was 0
```

Option (b) alone is still insufficient for records already written with embedded 0 by prior app versions in the field — those remain unresolvable under strict equality. Given the existing-record risk the phase context explicitly flagged, the safe fix is to keep the skew allowance (option a) OR scope strict equality to records the binding can prove are post-migration. Do not ship strict equality while any writer embeds 0.

### CR-02: Vector generator is desynced from the committed fixture and the Rust test — regenerating overwrites the new expectation and breaks CI

**File:** `scripts/gen-ipns-verify-vectors.ts:357-368` and `:378-387`

**Issue:** The Rust cross-language test (`crates/fuse/tests/ipns_verify_vectors.rs:170`) and the committed fixture (`tests/vectors/ipns/verify.json` case 8) were updated for Finding F to expect `expected_result: "invalid"` for the first-publish-skew vector. But the generator that *produces* `verify.json` was NOT updated: it still emits `expected_result: 'valid'` for case 8 (line 366), and its sanity-check array (line 378-387) still asserts the eighth result is `'valid'` (line 386). The case-8 doc comment (lines 342-351) also still describes the old "must accept embedded=0 when response sequenceNumber==1" behavior.

Effect: running `npx tsx scripts/gen-ipns-verify-vectors.ts` (the documented regeneration command, and the only supported way to refresh these vectors) regenerates `verify.json` with case 8 `expected_result: "valid"`, which then makes `ipns_verify_cross_language` fail at the case-8 assertion. The fixture and its generator now disagree about ground truth — the JSON was hand-edited (note the appended "(now rejected...)" text in the committed `description` at verify.json:73 which the generator does not produce). This is a latent CI break the next time anyone regenerates vectors, and it undermines the cross-language parity guarantee the test exists to provide.

Note: this finding is downstream of CR-01. If CR-01 is resolved by reverting strict equality, case 8 should revert to `"valid"` in the fixture/test and the generator stays correct; if strict equality is kept, the generator must be updated to emit `"invalid"`.

**Fix:** Update `scripts/gen-ipns-verify-vectors.ts` so the generator is the single source of truth:

```ts
// case 8 push:
expected_result: 'invalid',
// sanity array (line ~378-387):
const expectedResults = ['valid','invalid','invalid','invalid','invalid','invalid','legacy','invalid'];
```

Also update the case-8 doc comment (lines 342-351) to describe the strict-equality rejection, and re-run the generator so the committed `verify.json` is byte-identical to generator output (eliminating the hand-edited `description` drift).

## Warnings

### WR-01: Stale/misleading comment claims DB-authoritative return tolerates a "benign first-publish skew" that no longer exists

**File:** `crates/fuse/src/verify.rs:126-129`

**Issue:** After removing the skew allowance, the surviving comment block still reads: "the binding above guarantees resp_seq == embedded_seq except for the benign first-publish skew, where resp_seq (1) is the correct forward base." With strict equality there is no longer any tolerated skew — the comment contradicts the code two lines above it and will mislead the next reader about whether embedded/resp can differ. (It also implicitly documents the very compatibility gap CR-01 describes.)

**Fix:** Replace with: "the binding above guarantees `resp_seq == embedded_seq`, so returning `resp_seq` is equivalent to returning `embedded_seq`; we return the DB value because downstream forward math keys off the API's DB counter."

### WR-02: Replay child-folder publish embeds 1 but logs/comments still say "seq 0", and conflict arm comment is wrong

**File:** `crates/fuse/src/replay.rs:592-672`

**Issue:** `publish_child_folder_metadata` now creates the record at sequence `1` (line 628, correct per Finding F) and `record_publish(child_ipns_name, 1)` (line 666). But:
- The doc comment header still says "Publish a child folder's initial empty `FolderMetadata` (seq 1)" in the title yet the body comment at line 675-676 (`replay_mkdir_entry` doc) says "Re-publishes the child folder's seq-0 IPNS record".
- The conflict arm comment at line 659 says "Seq 0 should never conflict" while the record is now seq 1.
- Multiple log/skip messages elsewhere (e.g. `replay.rs:744-745` "skipping seq-0 publish") still reference seq 0.

These are stale-after-edit comments. They are not behavioral bugs on their own, but they actively misdescribe the post-Finding-F sequence and compound the confusion that produced CR-01 (the live mkdir path was left at 0 while replay moved to 1 — an inconsistency these comments mask). Note this also means replay re-publishes a crashed folder at embedded 1 while the live mkdir path would have embedded 0 for the same folder: if the live publish partially landed (DB seq already 1), replay's seq-1 record is an idempotent republish (embedded == dbSeq) which the API accepts — so no conflict, but the two writers are nonetheless inconsistent in what they embed.

**Fix:** Update all "seq 0" comments/log strings in `replay.rs` that refer to the child-folder first publish to "seq 1", and update line 659 to "Seq 1 first publish should not conflict". Reconcile with the live mkdir path per CR-01.

## Info

### IN-01: `is_ipns_not_found` and `classify_resolve_outcome` use divergent not-found predicates

**File:** `crates/fuse/src/metadata.rs:211-213` vs `crates/fuse/src/publish.rs:59`

**Issue:** `metadata.rs::is_ipns_not_found` matches only `"not found"` (substring, case-insensitive) and deliberately does NOT match bare `"404"` (pinned by the test at metadata.rs:1155-1159). `publish.rs::classify_resolve_outcome` matches `"not found"` OR `"404"`. The two predicates classify the same error string differently: a `"404"`-only error is `NotFound` for replay first-publish detection but a genuine failure for the bin-publish path's `is_ipns_not_found` branch (metadata.rs:502). This is pre-existing and not introduced this phase, but the inconsistency is a latent source of "first publish vs retain" misclassification if the API's error text ever drops the words "not found" in favor of a bare status code. Worth unifying onto the typed `IpnsResolveOutcome` classifier.

**Fix:** Route the bin-publish not-found check (metadata.rs:502) through the same `classify_resolve_outcome` predicate, or document explicitly why the bin path intentionally requires the literal "not found" phrasing.

---

_Reviewed: 2026-06-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
