---
phase: 66
slug: api-schema-cutover-publish-gate-and-tombstone
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-30
validated: 2026-06-30
---

# Phase 66 — Validation (Nyquist)

> Retroactive Nyquist audit performed during the ship review. Every phase
> requirement has automated verification. The cutover deleted the shares unit
> suite; the security-critical claim path was restored here, and the remaining
> shares-module coverage depth is tracked as a deferred todo.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **API framework** | jest 29 (`apps/api`) |
| **Integration framework** | vitest 3 (`tests/sdk-e2e`, real client to API round-trip) |
| **API quick run** | `cd apps/api && npx jest src/ipns src/shares` |
| **Publish-plane integration** | `pnpm --filter @cipherbox/sdk-e2e test` (ipns-publish-gate suite) |

---

## Requirement to Verification Map

| Requirement | Behavior | Test(s) | Status |
|-------------|----------|---------|--------|
| TEE-04 | Atomic CAS publish; concurrent to one 409, zero lost updates; EOL renewal gated identically | `ipns.service.spec.ts` (CAS/D-09 gates) + sdk-e2e Tests 16/17 | COVERED |
| TEE-05 | Resolve case-split fail-closed; null-signedRecord seq floor; CID mismatch fails closed | `ipns.service.spec.ts` + sdk-e2e Test 15 | COVERED |
| TEE-07 | Forward-only `generation` gate server-side | `ipns.service.spec.ts` + sdk-e2e TEE-07 case | COVERED |
| WRITE-04 | Tombstone to publish/resolve 410; unenrolled from republish | `ipns.service.spec.ts`, `ipns.security.spec.ts` + sdk-e2e Test 20 | COVERED |
| DATA-01 | `share_keys` table/entity deleted | Structural (entity + migration removed; api builds/boots) | COVERED |
| DATA-02 | Descriptor-ref grant; presence-derived write authority; hard-delete revoke | `share-invite.service.spec.ts` (claim path, T-66-E1) — added this review | COVERED (claim path); broader grant/revoke deferred |
| DATA-03 | `folder_ipns` to `ipns_records`; `public_key` dropped; pubkey from name | `ipns.service.spec.ts`, `ipns-verify-cache.spec.ts`, codec tests | COVERED |
| DATA-04 | BinEntry re-link / restore re-link / shared-delete revokes grants | sdk-e2e write-chain-rotation (revoke-on-delete); bin re-link sdk-side | COVERED (publish-plane); shares-side revoke depth deferred |

---

## Tests Added This Review

| File | Tests | Covers |
|------|-------|--------|
| `apps/api/src/shares/share-invite.service.spec.ts` | 9 | T-66-E1 (read-only invite blocks write grant + positive), T-66-S1 (root identity from invite), self-claim rejection, expired/non-active invite (4 cases), idempotent re-claim |

---

## Manual-Only / Deferred Coverage

| Behavior | Why deferred | Tracking |
|----------|--------------|----------|
| Full `SharesService` grant-creation, `revokeShare` hard-delete, received/sent listing | Cutover deleted 5 shares specs; full rewrite against the new model is large and best written against the Phase 68 finalized flow | `2026-06-30-restore-shares-module-unit-coverage.md` |
| Shares/invites controller authz + descriptor-ref request/response surfaces | Same — controller-level suite rewrite | same todo |

---

## Validation Audit 2026-06-30

| Metric | Count |
|--------|-------|
| Phase requirements | 8 |
| Covered (automated) | 8 |
| Gaps filled this review | 1 (claim-path security spec, 9 tests) |
| Deferred (coverage depth) | 1 todo (broader shares-module unit suite) |

---

## Validation Sign-Off

- [x] Every phase requirement has automated verification
- [x] Security-critical claim path (T-66-E1) has a regression test
- [x] No watch-mode flags in committed tests
- [x] Deferred coverage depth captured as a todo
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated 2026-06-30
