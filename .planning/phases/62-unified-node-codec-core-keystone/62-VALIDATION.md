---
phase: 62
slug: unified-node-codec-core-keystone
status: validated
nyquist_compliant: true
wave_0_complete: true
created: 2026-06-28
validated: 2026-06-29
---

# Phase 62 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution. Derived from 62-RESEARCH.md `## Validation Architecture`. Per-task IDs are assigned by the planner; refine the map below once PLAN.md files exist.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | vitest 3.0.5 |
| **Config file** | `packages/core/vitest.config.ts` |
| **Quick run command** | `pnpm --filter @cipherbox/core test` |
| **Full suite command** | `pnpm --filter @cipherbox/core test:coverage` |
| **Typecheck (compile gate)** | `pnpm --filter @cipherbox/sdk-core tsc --noEmit && pnpm --filter @cipherbox/sdk tsc --noEmit && pnpm --filter @cipherbox/web tsc --noEmit` (after `packages/core` `dist/` rebuild) |
| **Estimated runtime** | ~30 seconds (codec unit + golden-vector suites are fast; estimate) |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/core test`
- **After every plan wave:** Run `pnpm --filter @cipherbox/core test:coverage` (confirm the coverage floor is not broken by the `src/**/index.ts` barrel exclusion)
- **Before `/gsd-verify-work`:** Full `packages/core` suite green **and** full monorepo typecheck green after `dist/` rebuild
- **Max feedback latency:** ~30 seconds

---

## Per-Task Verification Map

> Task IDs map each requirement seam to its concrete test file + test name. All seams are present and green (`pnpm --filter @cipherbox/core test` → 9 files, 190 tests passed, 2026-06-29).

| Task ID | Test File | Requirement | Threat Ref | Secure Behavior · Test Name | Test Type | Automated Command | File Exists | Status |
|---------|-----------|-------------|------------|-----------------------------|-----------|-------------------|-------------|--------|
| NODE-01-RT | `node-codec.test.ts` | NODE-01 | — | encode/decode round-trip for folder/file/root · `NODE-01: encode/decode round-trip` (folder/root/file deep-equal, 3 tests) | unit | `pnpm --filter @cipherbox/core test node-codec` | ✅ | ✅ green |
| NODE-01-BL | `node-codec-vectors.test.ts` | NODE-01/05 | — | body bytes match primary-lock golden vector · `Node Codec — Body Bytes PRIMARY LOCK` (folder/file-GCM/file-CTR/root, 4 tests) | golden-vector | `pnpm --filter @cipherbox/core test node-codec-vectors` | ✅ | ✅ green |
| NODE-01-FS | `node-codec-vectors.test.ts` | NODE-01/05 | T-62-06 | full-seal (fixed key/IV) matches sealed-envelope golden vector · `Node Codec — FULL-SEAL LOCK` (readSealed + writeSealed base64, 2 tests) | golden-vector | `pnpm --filter @cipherbox/core test node-codec-vectors` | ✅ | ✅ green |
| NODE-02-SS | `node-codec.test.ts` + `node-codec-vectors.test.ts` | NODE-02 | T-content-self-seal | content seals role `0x03`; unseal recovers `fileKey` as 32-byte `Uint8Array` · `Node Codec — Content Self-Seal (NODE-02, role 0x03)` (GCM+CTR recover, wrong key/nodeId/generation throw, 5 tests) + `NODE-02: fileKey survives as 32-byte Uint8Array` | unit | `pnpm --filter @cipherbox/core test node-codec` | ✅ | ✅ green |
| NODE-02-EM | `node-codec.test.ts` | NODE-02 | — | both `GCM` and `CTR` `encryptionMode` survive round-trip · `both GCM and CTR encryptionMode values are preserved after round-trip` | unit | `pnpm --filter @cipherbox/core test node-codec` | ✅ | ✅ green |
| NODE-03-CR | `node-codec.test.ts` | NODE-03 | T-aad-transplant | `SealedChildRef` exactly 5 read-only fields; `readKeySealed` role `0x02`; no write field · `NODE-03: SealedChildRef has no write field` + `Node Codec — AAD Transplant Rejection` (child A vs B id, 4 tests) | unit | `pnpm --filter @cipherbox/core test node-codec` | ✅ | ✅ green |
| NODE-04-GA | `node-codec.test.ts` | NODE-04 | T-stale-generation | envelope plaintext `generation` folded into AAD; wrong-`generation` AAD fails unseal · `readKeySealed at generation 0 cannot be unsealed at generation 1` + `node body sealed at generation 5 fails unseal when envelope generation tampered to 6` | unit | `pnpm --filter @cipherbox/core test node-codec` | ✅ | ✅ green |
| NODE-04-GR | `node-codec.test.ts` | NODE-04 | — | `generation` outside `[0, 2^32-1]` throws fail-closed · `NODE-04: generation range [0, 2^32-1] validated fail-closed` (0x100000000 / -1 / 1.5 throw; 0 and 0xffffffff accepted, 5 tests) | unit | `pnpm --filter @cipherbox/core test node-codec` | ✅ | ✅ green |
| NODE-05-RUST | — | NODE-05 | — | Rust `Node` enum + cross-language `#[test]` — **deferred to Phase 69, n/a here** (TS wire-format freeze covered by NODE-01-BL/FS) | — | — | n/a | ⬜ deferred |
| NODE-06-BV | `vault-blob-vectors.test.ts` | NODE-06 | — | vault v3 blob serialize/deserialize round-trip; exact hex matches golden vector; v2-byte/truncation throw · `Vault Key Blob v3 Test Vectors` (11 tests) | golden-vector | `pnpm --filter @cipherbox/core test vault-blob-vectors` | ✅ | ✅ green |
| NODE-06-NF | `vault-blob-vectors.test.ts` (verified absent in src) | NODE-06 | — | `encryptedRootFolderKey` absent from all vault types; v3 two-key only · verified by D-02 compile gate + grep (VERIFICATION truth #4) | typecheck | compile-gate command (see Test Infrastructure) | ✅ | ✅ green |
| D-02-GATE | (compile gate) | D-02 (gate) | — | `sdk-core` + `sdk` + `web` typecheck after `dist/` rebuild · 0 errors (VERIFICATION spot-checks) | typecheck | compile-gate command (see Test Infrastructure) | ✅ | ✅ green |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [x] `packages/core/src/__tests__/node-codec-vectors.test.ts` — NODE-01..NODE-05 (20 tests: body-bytes lock + full-seal lock + round-trip + AAD-transplant rejection)
- [x] `packages/core/src/__tests__/node-codec.test.ts` — NODE-01..NODE-04 (15 tests: round-trip, fileKey/encryptionMode, SealedChildRef shape, generation range guard, content self-seal)
- [x] `tests/vectors/node-codec.json` — frozen JSON fixture: all three node kinds (folder; file with `content` + GCM + CTR `VersionEntry`; root) + full-seal vector
- [x] `tests/vectors/vault-v3-blob.json` — frozen v3 two-key blob vector
- [x] `packages/core/src/__tests__/vault-blob-vectors.test.ts` — v3 two-key format (D-05), 11 tests
- [x] No framework install needed — vitest already configured in `packages/core`

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `dist/` rebuild precedes consumer typecheck | NODE-05 / SC#5 | sdk/web typecheck the built `dist/`, not source ([[project-cross-package-dist-staleness]]) | Run `pnpm --filter @cipherbox/core build` before the compile-gate typecheck command; CI ordering must enforce this |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies (NODE-05 Rust deferred to Phase 69, n/a)
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (all test files + JSON fixtures present)
- [x] No watch-mode flags
- [x] Feedback latency < 30s (core suite ~1.2s)
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** validated 2026-06-29 — 11/11 active requirement seams green (190/190 core tests pass); NODE-05 Rust deferred to Phase 69. 0 gaps.
