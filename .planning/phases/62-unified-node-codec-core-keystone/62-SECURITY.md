---
phase: 62
slug: unified-node-codec-core-keystone
audit_type: threat-mitigation-verification
asvs_level: 2
block_on: high
threats_total: 12
threats_closed: 12
threats_open: 0
verdict: SECURED
audited: 2026-06-29
---

# Phase 62 — Security Audit: Unified Node Codec (Core Keystone)

Retroactive verification that every declared threat mitigation in the Phase 62
threat models is present in the implemented code. Implementation files were
treated as read-only; this document is the only artifact written.

## Audit Configuration

| Property | Value |
|----------|-------|
| ASVS level | L2 (verify mitigation addresses the vector at the correct boundary) |
| `block_on` threshold | high (default — high and critical open threats block) |
| Audit surface | `packages/core/src/node/*`, `packages/core/src/vault/{blob,types,init}.ts`, `packages/crypto/src/aes/seal.ts`, golden vectors + codec tests |
| Out of audit scope (intended milestone state, D-01) | consumer stubs in `sdk-core`/`sdk`/`web`, quarantined consumer suites, non-runnable app |

## Threat Register Source

Threats were extracted from the per-task `<threat_model>` blocks in
`62-01-PLAN.md` … `62-08b-PLAN.md` and cross-referenced against the three
validation threat refs (`T-content-self-seal`, `T-aad-transplant`,
`T-stale-generation`). Where a threat appears in multiple plans, the most
severe declared classification is used (fail-closed).

Validation-ref mapping:

- `T-aad-transplant` → `T-62-01`
- `T-stale-generation` → `T-62-02`
- `T-content-self-seal` → `T-62-04`

## Per-Threat Verification

| Threat ID | Category | Severity | Disposition | Expected Mitigation | Code Location | Status |
|-----------|----------|----------|-------------|---------------------|---------------|--------|
| T-62-06 | Tampering | critical | mitigate | FULL-SEAL LOCK asserts exact `IV‖ciphertext‖tag` for a fixed key/IV; AAD byte encoding identical to the Phase-61 KAT / future Rust twin | `node-codec-vectors.test.ts:141-200` against `tests/vectors/node-codec.json` (`seal_vectors[0].expected_published_node.readSealed`/`writeSealed`); AAD built by `buildNodeAad` (`crypto/src/aes/seal.ts:80-112`) | VERIFIED |
| T-62-01 | Tampering | high | mitigate | `buildNodeAad(childId, kind, generation, role=0x02)` binds child identity into the GCM tag; a `readKeySealed` cannot be transplanted to another child/role/generation | `node/seal.ts:180-217` (`sealChildReadKey`/`unsealChildReadKey`); rejection tests `node-codec-vectors.test.ts:320-361` (wrong childId, wrong generation throw) | VERIFIED |
| T-62-02 | Tampering | high | mitigate | `generation` is plaintext on the envelope AND folded into both bodies' AAD; a relay-served stale body fails unseal; range `[0,2^32-1]` guarded fail-closed | `node/seal.ts:105,120,148,155` (AAD binds `generation`); tamper test `node-codec-vectors.test.ts:340-355`; range guard `node/decode.ts:231-240` + `buildNodeAad` `crypto/src/aes/seal.ts:93-95`; range tests `node-codec.test.ts:222-251` | VERIFIED |
| T-62-08 | Information Disclosure | high | mitigate | `rootReadKey` and `rootWriteKey` are independent `generateFileKey()` outputs; Ed25519 key lives inside the sealed write-body, never reused as `writeKey` | `vault/init.ts:44-46`; independence test `vault.test.ts:57-62` (`rootReadKey != rootWriteKey`) | VERIFIED |
| T-62-04 | Tampering | high | mitigate | `content.fileKey`/`VersionEntry.fileKey` typed `Uint8Array` (raw 32B, not ECIES hex); content self-seals under file's own readKey at role `0x03`; decode asserts 32-byte length | types `node/types.ts:36-67`; serialize/deserialize `node/encode.ts:54-74` + `node/decode.ts:99-100,129`; `sealContent` role `0x03` `node/seal.ts:233-245`; tests `node-codec-vectors.test.ts:368-427` (`instanceof Uint8Array`, length 32) | VERIFIED |
| T-62-03 | Information Disclosure | medium | mitigate | Codec never `console.log`s or `JSON.stringify`s raw key `Uint8Array`s; only base64 wire bodies are serialized | no `console.*` in `node/` or `vault/` (grep: none); `JSON.stringify` calls operate on wire-serialized bodies only (`node/encode.ts:144,173`, `node/seal.ts:241`) | VERIFIED |
| T-62-05 | Tampering (via omission) | medium | mitigate | `node/index.ts` is re-export only; all seal/validation logic in named files counted by coverage | `node/index.ts` (zero logic, export-only); `vitest.config.ts` excludes `src/**/index.ts` | VERIFIED |
| T-62-07 | Tampering | medium | mitigate | `deserializeVaultBlobV3` bounds-checks version byte, `readLen>0`, write-header + write-body presence | `vault/blob.ts:87-125`; negative tests `vault-blob-vectors.test.ts:65-107` (v2 byte, truncations, zero-length keys throw) | VERIFIED |
| T-62-10 | Tampering (via omission) | medium | mitigate | Stubbed consumer behavior throws naming the owning phase (never returns `undefined`); quarantined suites retained as revive spec | 77 phase-named throwing stubs across `sdk-core`/`sdk`/`web`/`core` (grep `not implemented — phase`) | VERIFIED |
| T-62-11 | Tampering (via omission) | medium | mitigate | Grep-driven discovery quarantines every retired-type test suite; imports fixed so `tsc` still gates | throwing-stub + quarantine pattern present (see T-62-10); intended D-01/D-02 milestone posture | VERIFIED |
| T-62-09 | Tampering (via doc drift) | low | mitigate | Schema docs written against shipped `node/types.ts` + ADR 0003, not the design sketch; flow docs deferred | `62-04-SUMMARY.md` Threat Flags (verified against `node/types.ts` + `vault/blob.ts` as-shipped) | VERIFIED |
| T-62-SC | Tampering (supply chain) | low | accept | No new packages added this phase | `git diff main -- **/package.json`: no added dependency lines; see Accepted Risks Log | VERIFIED |

Closed: 12/12. Open: 0/12.

## Crypto Invariant Spot-Checks (L2 boundary verification)

- Two independently sealed bodies — `sealNode` seals `readSealed` under `readKey`
  and (when `node.writeBody` present) `writeSealed` under `writeKey`, both role
  `0x01`, distinguished only by key (`node/seal.ts:96-126`). `unsealNode` rebuilds
  the AADs identically; a write-only field never appears in the read body.
- `SealedChildRef` is a read-only chain link — structural test asserts the decoded
  field set is exactly `{generation, ipnsName, name, readKeySealed, versionFloor}`
  with no write field (`node-codec.test.ts:208-214`; type `node/types.ts:83-104`).
- AAD binds identity (`domain ‖ nodeId(16B) ‖ kind ‖ generation(u32 BE) ‖ role`,
  45 bytes) so a sealed body/ref cannot be transplanted onto another node
  (`crypto/src/aes/seal.ts:80-112`).
- Vault recovery blob v3 layout
  `0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)`
  is the sole codec; v1/v2 functions (`serializeVaultBlobV2`/`deserializeVaultBlobV2`/`detectBlobVersion`/`BLOB_V2_VERSION`)
  are hard-deleted from `packages/core/src/` (grep: none). `encryptedRootFolderKey`
  is absent from all vault types (`vault/types.ts`); `vault.test.ts:127-133` asserts
  its absence.
- Zeroization is terminal-owner only — codec functions document and observe D-09
  (no callee zeros a caller-owned/returned buffer); `decryptVaultKeys` explicitly
  preserves caller-owned encrypted blobs (`vault/init.ts:105-107`).

## Threat Flags Reconciliation (from SUMMARY `## Threat Flags`)

| Flag | Source | Maps to | Disposition |
|------|--------|---------|-------------|
| `key-material-in-memory` — `sealNode`/`sealChildReadKey` receive raw key `Uint8Array`s, intentionally not zeroed (D-09 terminal-owner contract) | `62-02-SUMMARY.md` | T-62-03 + D-09 | Mapped to existing threat — informational, not unregistered. The SDK layer (Phase 63+) is the terminal owner and must zero. |

No unregistered flags. All other summaries declare no net-new trust-boundary surface
(`62-01`, `62-04`, `62-08b`).

## Findings

None. Every declared mitigation has a corresponding implementation and a negative
(rejection/throw) test at the correct trust boundary.

### Observations (non-findings)

- The `generation` range guard is enforced at the seal boundary (`buildNodeAad`
  throws for out-of-range values) and at decode (`validateNode`/`decodeReadBody`),
  rather than inside the pure `encodeReadBody`. The VALIDATION row phrasing
  ("throws on encode") is satisfied in substance: no out-of-range `generation` can
  produce a valid `PublishedNode`, because `sealNode` → `buildNodeAad` rejects it.
  This is the stronger placement (the untrusted-bytes-in boundary is guarded).
- `apps/web/public/recovery.html` still contains an inline v2 blob deserializer.
  It is a standalone static page (no compile dependency on `packages/core`) and is
  part of the deferred consumer cutover, consistent with the intended non-runnable
  mid-milestone state (D-01). Not a core-codec threat; flagged here for the owning
  consumer phase, not as a Phase 62 gap.

## Accepted Risks Log

| Risk ID | Description | Justification | Disposition |
|---------|-------------|---------------|-------------|
| T-62-SC | Dependency supply chain — no new third-party packages introduced this phase | `git diff` vs `main` shows no added dependency lines in any `package.json`; the codec composes only the already-audited Phase-61 `@cipherbox/crypto` primitive | accept |

## Verdict

SECURED.

All 12 declared threats are CLOSED with implemented mitigations and boundary-level
negative tests. No blocking (severity ≥ high) open threats; no non-blocking open
threats; no unregistered attack surface. `threats_open: 0`.
