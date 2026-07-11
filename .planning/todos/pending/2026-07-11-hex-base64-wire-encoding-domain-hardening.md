---
created: 2026-07-11T00:00:00.000Z
title: End the recurring hex/base64 encoding-domain confusion (authoritative doc + named boundary codecs + branded types + contract test + comment reconciliation)
area: crypto-wire-encoding
severity: high
source: Recurring across phases — most recently Phase 74 PR #607 (grant re-mint sent base64 for the hex `encryptedReadKey` wire field → API 400, caught only by desktop-e2e). Prior instances in earlier phases.
files:
  - apps/api/src/shares/dto/*.dto.ts
  - packages/sdk-core/src/share/*.ts
  - packages/sdk-core/src/node/*.ts
  - packages/crypto/src/*
  - crates/api-client/src/shares.rs
  - crates/sdk/src/rotation/engine.rs
  - crates/crypto/src/*
  - docs/METADATA_SCHEMAS.md
resolves_phase: null
---

## Problem (root cause)

The codebase has **two distinct string-encoding domains that are indistinguishable at the type level** — both render an encrypted-key `Uint8Array` as a `string`, but require **opposite** encodings, and nothing forces a call-site to pick correctly:

| Domain | Encoding | Examples | Enforced by |
|---|---|---|---|
| Internal node-codec / stored sealed refs | **base64** | `readKeySealed` / `read_sealed`, `read_key_sealed`, `persist_wrapped_key` | convention only |
| Share API wire fields | **hex** | `encryptedReadKey`, `encryptedWriteKey`, `itemNameEncrypted`, `sharerPublicKey` | server DTO `@Matches(/^(?:[0-9a-fA-F]{2})+$/)` |

Survey findings (2026-07-11):
- The share API wire contract is **uniformly hex** — every field across `create-share` / `create-invite` / `claim-invite` / `update-grant` DTOs, plus all API doc-comments ("Hex-encoded"). Self-consistent.
- The client is **base64-dominant** — ~34 base64 encode call-sites vs ~2 hex in `sdk-core`/`api-client`/`sdk`; `packages/sdk-core/src/share/grant.ts:46` comments the grant key as "Base64-encoded". Most base64 sites are correct (internal codec), but the share-wire ones must flip to hex at the boundary.

Because the two domains share the same `string`/`Uint8Array` types and look identical in code, a producer routinely encodes with the wrong scheme. Unit tests mock the API boundary, so the mismatch escapes to e2e or production. This has recurred multiple times; Phase 74's grant re-mint (`base64_encode` for a hex wire field) is the latest.

## Fix (make the field's domain own the encoding — 5 legs)

1. **Authoritative encoding table** — a single "Wire & Storage Encoding Contract" section in `docs/METADATA_SCHEMAS.md` listing every wire/stored field → its encoding (hex | base64) + rationale. All producers/consumers reference it. Single source of truth.

2. **Named boundary codecs** — replace raw `hex::encode` / `base64_encode` (and their decode twins) at these seams with domain-named helpers in BOTH TS and Rust:
   - `encodeShareWireKey` / `decodeShareWireKey` (owns **hex**) — for `encryptedReadKey`, `encryptedWriteKey`, `itemNameEncrypted`, and other share-API wire fields.
   - `encodeSealedRef` / `decodeSealedRef` (owns **base64**) — for internal node-codec sealed fields.
   A call-site picks the FIELD's codec, never the raw algorithm. Grep-guard (CI) that raw `base64_encode`/`hex::encode` never appear at the share-wire or node-codec boundaries.

3. **Branded string types** — `HexWireString` vs `Base64CodecString` in TS (branded string aliases); newtype wrappers in Rust (`ShareWireHex`, `SealedRefB64`). Make `tsc`/`rustc` reject passing one domain's string where the other is expected. This leg ends the class entirely; sequence it last (largest surface).

4. **Client→DTO contract test** — a unit/integration test asserting every client-produced share field matches its server DTO regex (`/^(?:[0-9a-fA-F]{2})+$/` for the hex fields). Would have caught Phase 74 in unit CI instead of desktop-e2e. Highest value-per-effort; do this leg FIRST as a regression net before the refactor.

5. **Reconcile drifted comments** — audit every "Hex-encoded" / "Base64-encoded" doc-comment against the actual codec (e.g. `sdk-core/src/share/grant.ts:46`), and align to the authoritative table.

## Suggested sequencing

Leg 4 (contract test) → Leg 1 (doc) → Leg 2 (named codecs, mechanical) → Leg 5 (comments) → Leg 3 (branded types, the enforcing refactor). Legs 1/4/5 are low-risk; 2/3 are the durable enforcement.

## Acceptance

- A single documented encoding contract; no field's encoding is decided ad-hoc at a call-site.
- Passing a wrong-domain string is a compile error (branded types) OR blocked by the contract test + CI grep-guard.
- All share-wire fields provably hex, all node-codec fields provably base64, verified by a test that exercises the real DTO validators.
- Zero remaining mislabeled encoding comments.
