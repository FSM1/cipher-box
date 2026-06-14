---
created: 2026-06-13T14:00
title: 'IPNS signature storage review: enforce signedRecord validation, verification, and key zeroization (S1, S2, S3)'
area: ipns
files:
  - apps/api/src/ipns/ipns.service.ts
  - packages/sdk-core/src/ipns/index.ts
  - apps/web/src/services/ipns.service.ts
  - crates/api-client/src/ipns.rs
---

## Problem

Three deferred findings from `.planning/security/REVIEW-20260402-172126.md` (IPNS Signature Storage, PR #448), all confirmed **still open** against live code on 2026-06-13. They live only in the security review and the stale `.planning/BACKLOG.md` snapshot, so nothing currently actions them.

- **S1 (Medium) — publish does not validate `signedRecord` vs DTO fields.** On publish the server only base64-decodes `dto.record` (`apps/api/src/ipns/ipns.service.ts:60-65`) and stores it verbatim (`:247`, `:292`); the embedded CID/sequence inside the signed record are never parsed and compared against `metadataCid` / `expectedSequenceNumber`. A parser exists but is resolve-only and treats the DB columns as authoritative, only warning on mismatch.
- **S2 (Medium) — signature verification is downgrade-able.** sdk-core throws on an invalid signature but skips verification entirely when fields are absent (`packages/sdk-core/src/ipns/index.ts:197-219`). The web path is weaker still — it only `logger.warn`s even when a present signature is INVALID and still returns the CID (`apps/web/src/services/ipns.service.ts:177-205`). No resolve caller checks `signatureVerified` (all call sites read only `.cid` / `.sequenceNumber`), and the Rust client does not verify at all (`crates/api-client/src/ipns.rs`).
- **S3 (Medium) — inconsistent private-key zeroization; no caller-owns-key convention.** Some paths zeroize generated keys (`packages/sdk-core/src/file/index.ts:180`, `folder/index.ts:172-173`), others do not (`ipns/index.ts:39-98`, `vault/index.ts:32-52`). Phase 44 introduced an active contradiction: `updateFileMetadata` zeroizes a caller-passed key (`file/index.ts:401-403`) while its sibling `updateFolderMetadataAndPublish` does not. Rust uses `Zeroizing`/`ZeroizeOnDrop` widely but several unwrap paths return raw `Vec<u8>` keys with inconsistent caller cleanup (`crates/crypto/src/ecies.rs:35-46`, `crates/fuse/src/lib.rs:993-1050`).

## Solution

- **S1**: On publish, parse the embedded CID + sequence from the signed record and reject (400) when they disagree with the DTO's `metadataCid` / `expectedSequenceNumber`.
- **S2**: Once signed-record data is reliably populated, enforce verification: fail closed when a signature is present but invalid (web path must reject, not warn), have resolve callers honor `signatureVerified`, and add verification to the Rust client. Treat missing fields explicitly rather than silently skipping.
- **S3**: Establish and document a caller-owns-key convention across the SDK (zeroize at the boundary that owns the buffer); reconcile the `updateFileMetadata` vs `updateFolderMetadataAndPublish` contradiction; audit the Rust unwrap paths that return raw key bytes.
