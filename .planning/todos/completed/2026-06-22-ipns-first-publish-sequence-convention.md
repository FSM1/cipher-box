---
created: 2026-06-22T00:00:00.000Z
title: Unify first-publish IPNS embedded-sequence convention (FUSE 0 vs SDK 1) and verify TEE re-sign path
area: refactor
severity: low
source: Phase 58 PR #544 desktop-E2E regression investigation (resolve-binding hotfix f759c4a90)
files:
  - crates/fuse/src/publish.rs
  - crates/fuse/src/content_ops.rs
  - crates/fuse/src/replay.rs
  - packages/sdk-core/src/file/index.ts
  - apps/api/src/ipns/ipns.service.ts
---

## Background

The Phase 58 resolve-side sequence binding (D-07) was hotfixed (f759c4a90) to accept the
documented first-publish skew: a resolved first-generation record may carry embedded
Sequence=0 while the API returns DB sequenceNumber=1. Root cause is a **client publish-path
inconsistency**, not a resolve bug:

- **Rust/FUSE** first publish embeds the IPNS-native `0`
  (`next_file_publish_sequence(true, None) == 0` in `publish.rs`; first child-folder publish
  in `replay.rs`).
- **TS SDK** first publish embeds `1n`
  (`packages/sdk-core/src/file/index.ts` — "sequence number 1 for new records").
- The API (`ipns.service.ts::upsertFolderIpns`) accepts embedded ∈ {0,1} on first publish
  (D-09 / T-58-08 wedge-poison guard) and **unconditionally stores DB `sequenceNumber: '1'`**.

So FUSE-published records sit at embedded=0 / DB=1 for their first generation; SDK-published
records sit at embedded=1 / DB=1. Both realign on the first forward update (embedded becomes
DB+1 thereafter). The hotfix tolerates the skew on resolve and is correct and minimal.

## Action (future hardening phase)

1. **Unify the convention.** Decide whether first publish should embed 0 (IPNS-native) or 1
   (current API/DB + SDK convention) and make FUSE + SDK consistent. The API comment
   (`ipns.service.ts:357`) already assumes clients embed `0+1=1`; making FUSE embed 1 would
   let the resolve binding return to strict `embedded == DB` equality (drop the skew
   allowance in `verify.rs` + `sdk-core/ipns/index.ts` + the case-8 vector). Touches
   `next_file_publish_sequence`, the first child-folder publish, and their unit tests
   (`replay.rs` asserts `NotFound -> new_seq=0`).

2. **Verify the TEE re-sign path is NOT broken by the embed-0 record.** A FUSE-first-published
   record stores a signedRecord embedding Sequence=0 with DB=1. If the TEE 6-hour republish
   re-submits that stored record through the D-09 gate, `embeddedSeq(0) < dbSeq(1)` would hit
   the **"Rollback rejected"** branch (`ipns.service.ts:294`). Confirm whether the republish
   path actually re-runs that gate (it may write directly to the relay without the
   embedded-sequence check). If it does, FUSE-first-published records cannot be TEE-republished
   until their first update — a real durability gap. Pre-existing (independent of the resolve
   hotfix); out of scope for the #544 regression fix.
