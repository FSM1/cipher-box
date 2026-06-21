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

## Status: RESOLVED — closed by PR #529 (filed to completed 2026-06-21)

S1/S2/S3 were substantively shipped in **PR #529 (`13f741e86`, "harden IPNS signedRecord
validation, verification, and key zeroization")**, which merged AFTER this todo's 2026-06-19
re-verification — so the file never reflected it. Verified against live code 2026-06-21:

- **S1** publish embedded-vs-DTO CID + offset-aware sequence gate — DONE (`apps/api/src/ipns/ipns.service.ts:258-297`).
- **S2** fail-closed verification — DONE on JS (web + sdk-core throw on invalid/partial, name-bound); the Rust client gained signature fields + `verify_ipns_resolve_signature`, but it is wired into only 1 of ~11 resolve sites and no CBOR cid-binding exists yet (residue below).
- **S3** caller-owns-key zeroization — DONE (file-vs-folder contradiction now an intentional, test-guarded D-05 convention; Rust raw-`Vec` key paths converted to `Zeroizing`).

Residue carried to **Phase 58 (IPNS Signature-Verify Coverage)** via
`2026-06-20-ipns-resolve-verify-coverage-and-web-sdk-dedup.md` (S2-Rust chokepoint + CBOR cid-binding)
and `2026-06-20-ipns-publish-validate-embedded-sequence-without-cas.md` (S1 non-CAS hardening).

## Problem

Three deferred findings from `.planning/security/REVIEW-20260402-172126.md` (IPNS Signature Storage, PR #448), all confirmed **still open** against live code on 2026-06-13. They live only in the security review and the stale `.planning/BACKLOG.md` snapshot, so nothing currently actions them.

- **S1 (Medium) — publish does not validate `signedRecord` vs DTO fields.** On publish the server only base64-decodes `dto.record` (`apps/api/src/ipns/ipns.service.ts:60-65`) and stores it verbatim (`:247`, `:292`); the embedded CID/sequence inside the signed record are never parsed and compared against `metadataCid` / `expectedSequenceNumber`. A parser exists but is resolve-only and treats the DB columns as authoritative, only warning on mismatch.
- **S2 (Medium) — signature verification is downgrade-able.** sdk-core throws on an invalid signature but skips verification entirely when fields are absent (`packages/sdk-core/src/ipns/index.ts:197-219`). The web path is weaker still — it only `logger.warn`s even when a present signature is INVALID and still returns the CID (`apps/web/src/services/ipns.service.ts:177-205`). No resolve caller checks `signatureVerified` (all call sites read only `.cid` / `.sequenceNumber`), and the Rust client does not verify at all (`crates/api-client/src/ipns.rs`).
- **S3 (Medium) — inconsistent private-key zeroization; no caller-owns-key convention.** Some paths zeroize generated keys (`packages/sdk-core/src/file/index.ts:180`, `folder/index.ts:172-173`), others do not (`ipns/index.ts:39-98`, `vault/index.ts:32-52`). Phase 44 introduced an active contradiction: `updateFileMetadata` zeroizes a caller-passed key (`file/index.ts:401-403`) while its sibling `updateFolderMetadataAndPublish` does not. Rust uses `Zeroizing`/`ZeroizeOnDrop` widely but several unwrap paths return raw `Vec<u8>` keys with inconsistent caller cleanup (`crates/crypto/src/ecies.rs:35-46`, `crates/fuse/src/lib.rs:993-1050`).

## Solution

- **S1**: On publish, parse the embedded CID + sequence from the signed record and reject (400) when they disagree with the DTO's `metadataCid` / `expectedSequenceNumber`.
- **S2**: Once signed-record data is reliably populated, enforce verification: fail closed when a signature is present but invalid (web path must reject, not warn), have resolve callers honor `signatureVerified`, and add verification to the Rust client. Treat missing fields explicitly rather than silently skipping.
- **S3**: Establish and document a caller-owns-key convention across the SDK (zeroize at the boundary that owns the buffer); reconcile the `updateFileMetadata` vs `updateFolderMetadataAndPublish` contradiction; audit the Rust unwrap paths that return raw key bytes.

## Re-verification (2026-06-19)

Re-checked all three findings against live code (line numbers below are current; they drifted since 2026-06-13). All remediations still valid and unimplemented.

- **S1 — partially addressed, core still open.** An anti-rollback check was added (`apps/api/src/ipns/ipns.service.ts:222-234`) that parses the embedded sequence of the incoming vs the previously-stored signed record and rejects (409) on regression — but this is embedded-vs-embedded, **not** embedded-vs-DTO. `metadataCid` is still stored verbatim (`:256`, `:303`); `expectedSequenceNumber` is compared only against the DB column `existing.sequenceNumber` (`:237-248`), never the embedded sequence; the embedded CID is never parsed/compared. Resolve parser remains warn-only (`:553-561`). `parseIpnsRecord` is already imported (`:24`) and called in `upsertFolderIpns` (`:223-226`), so the embedded values are in hand for the fix. **Caveat:** clients sign sequence `0` on first publish while the DB stores `'1'` (pre-increment convention, see `:296-297`, `:553-555`) — a strict embedded-seq vs `expectedSequenceNumber` equality check must account for this or it breaks legitimate publishes.
- **S2 — fully open, all four surfaces.** sdk-core throws on a present-but-invalid signature but silently skips (`signatureVerified=false`, no throw) when any of `signatureV2`/`data`/`pubKey` is absent (`packages/sdk-core/src/ipns/index.ts:196-219`). Web path is weaker — warns and returns the CID even on an INVALID signature (`apps/web/src/services/ipns.service.ts:177-205`, invalid-sig warn at `:184-185`). Rust client performs no verification and `IpnsResolveResponse` lacks the signature fields entirely (`crates/api-client/src/ipns.rs:14-54`, `crates/api-client/src/types.rs:130-137`). No production caller honors `signatureVerified` (only the two producer fns + unit tests reference it). **Caveat:** practically bounded — the server DB is the authoritative CID source (Medium, not High).
- **S3 — fully open.** The Phase-44 contradiction is verbatim: `updateFileMetadata` zeroizes its caller-passed key in a `finally` (`packages/sdk-core/src/file/index.ts:369-373`) while `updateFolderMetadataAndPublish` zeroizes neither caller-passed key (`packages/sdk-core/src/folder/index.ts:177-242`). `ipns/index.ts` (`:39-98`) and `vault/index.ts` (`:32-80`) never zeroize. Rust leaks raw `Vec<u8>` keys: `ecies.rs:35-47` (`unwrap_key`), `crates/fuse/src/lib.rs:933-938` (`get_folder_key` `.to_vec()` copies of `Zeroizing` fields), `:1595-1661` (`resolve_folder_key` raw-Vec BFS queue), `:745-747` (`spawn_file_meta_reencrypt` mixes `Zeroizing` + raw Vec). No documented caller-owns-key convention exists in sdk-core (only scattered per-fn `T-47-01` comments in the higher-level `sdk` package). Defense-in-depth memory hygiene (Medium).

Independent and ship-separable. Suggested order: **S1** (highest value, ~one function, server-authoritative) → **S2** (cross-cutting: TS + Rust + every caller) → **S3** (defense-in-depth).
