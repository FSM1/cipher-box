---
created: 2026-06-20T00:00:00.000Z
title: IPNS resolve signature-verify chokepoint coverage + web/sdk-core resolve dedup
area: refactor
severity: low
source: /simplify review of Phase 51 (altitude + reuse angles); deferred as out-of-scope quality follow-ups
files:
  - crates/fuse/src/lib.rs
  - crates/api-client/src/ipns.rs
  - apps/web/src/services/ipns.service.ts
  - packages/sdk-core/src/ipns/index.ts
---

## Problem

Three quality/coverage follow-ups surfaced while reviewing Phase 51 (HARD-02). All deferred — none
are correctness bugs given "DB CID is authoritative; signature verification is defense-in-depth
(Medium)", but each is worth closing later.

1. **Rust S2 verify is a special-case, not a chokepoint.** `verify_ipns_resolve_signature`
   (`crates/api-client/src/ipns.rs`) is called from only ONE of ~10 `resolve_ipns` sites — the
   folder-key descent in `crates/fuse/src/lib.rs` `resolve_folder_key` (which the Phase 51 security
   audit verified, T-51-07). The other resolve→fetch→decrypt sites (folder-meta spawn, remote-merge,
   bin metadata, file-pointer resolve, parent-IPNS merge) trust the CID without honoring
   `signatureVerified`. The JS side does this correctly — verification lives inside the single
   `resolveIpnsRecord` chokepoint all callers funnel through. Deeper fix: fold verification into
   `resolve_ipns` itself (or a `resolve_ipns_verified` wrapper returning a CID only after the
   name-bound signature check) so new Rust resolve sites are safe by default.

2. **Web/sdk-core resolve duplication.** `apps/web/src/services/ipns.service.ts` carries its own
   `verifyIpnsSignature` + `resolveIpnsRecord` that are near-identical to the
   `@cipherbox/sdk-core` exports (`packages/sdk-core/src/ipns/index.ts`). Phase 51's S2 change made
   them MORE identical (ported D-02 fail-closed / D-03 allow-and-flag into the web copy). Two crypto
   verify paths kept in lockstep by hand — a divergence risk on the next security change. Fix: have
   the web service import the sdk-core exports (passing the web axios instance via the `SdkContext`
   arg `resolveIpnsRecord` already accepts) and delete its local copies. (Non-trivial: preserve the
   web `withPerf` wrapper + ctx injection.)

3. **No shared cross-language test vectors for IPNS signature verify.** The Rust
   (`crates/api-client/src/ipns.rs` `#[cfg(test)]`) and TS (`packages/sdk-core/src/__tests__/ipns.test.ts`)
   verify tests each hard-code the `"ipns-signature:"` prefix + present/absent/invalid/wrong-name
   cases independently. If the signed-bytes construction drifts on one side, nothing fails. Add a
   shared JSON vector (one valid, one tampered, one name-mismatch) consumed by both, mirroring
   `crates/crypto/tests/cross_language.rs`.

## Update (PR #529 CodeRabbit review)

CodeRabbit flagged two additional, related items on the Rust verifier
(`verify_ipns_resolve_signature`, `crates/api-client/src/ipns.rs`):

- **DONE in PR #529:** partial signature fields now fail closed — `Ok(None)` is returned ONLY when
  all three of `signatureV2`/`data`/`pubKey` are absent; any partial subset returns `Ok(Some(false))`.
  The same partial-fields fail-closed tightening was applied to the JS resolve paths
  (`apps/web/src/services/ipns.service.ts` and `packages/sdk-core/src/ipns/index.ts`) for consistency.
- **STILL DEFERRED (heavy lift):** bind the verified record to `resp.cid` / `resp.sequence_number`.
  The verifier can return `Some(true)` for a valid signature/name pair even if the JSON `cid` or
  `sequenceNumber` was swapped, because the signed CBOR `data` is never decoded and compared back to
  `resp.cid` / `resp.sequence_number`. Decoding the CBOR and comparing is the proper fix; it pairs
  naturally with item #1 below (folding verification into a `resolve_ipns_verified` chokepoint). Add
  tests for a valid signature paired with a mismatched cid/sequence.

## Solution

Address in a future hardening/refactor pass (candidates for Phase 55 Tier-3 follow-ups or a
dedicated IPNS-verify-consolidation todo). #1 has the most security value (coverage); the CBOR
cid-binding above is the highest-value correctness item; #2 the most maintainability value; #3 is
cheap insurance.
