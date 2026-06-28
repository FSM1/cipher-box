---
phase: 62
slug: unified-node-codec-core-keystone
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-28
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

> Task IDs are TBD until planning (step 8) completes. Rows below are the requirement→test seams lifted from 62-RESEARCH.md; the planner/auditor maps them onto concrete `{N}-PP-TT` task IDs.

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | TBD | TBD | NODE-01 | — | encode/decode round-trip for folder/file/root | unit | `pnpm --filter @cipherbox/core test -- node-codec` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | NODE-01 | — | body bytes match primary-lock golden vector (IV-independent) | golden-vector | `pnpm --filter @cipherbox/core test -- node-codec-vectors` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | NODE-01 | — | full-seal (fixed key/IV) matches sealed-envelope golden vector | golden-vector | `pnpm --filter @cipherbox/core test -- node-codec-vectors` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | NODE-02 | T-content-self-seal | content seals role `0x03`; unseal recovers `fileKey` as `Uint8Array` | unit | `pnpm --filter @cipherbox/core test -- node-codec` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | NODE-02 | — | both `GCM` and `CTR` `encryptionMode` survive round-trip | unit | `pnpm --filter @cipherbox/core test -- node-codec` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | NODE-03 | T-aad-transplant | `SealedChildRef` read-only fields; `readKeySealed` role `0x02`; no write field | unit | `pnpm --filter @cipherbox/core test -- node-codec` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | NODE-04 | T-stale-generation | envelope plaintext `generation`; wrong-`generation` AAD fails unseal | unit | `pnpm --filter @cipherbox/core test -- node-codec` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | NODE-04 | — | `generation` outside `[0, 2^32-1]` throws on encode (fail-closed) | unit | `pnpm --filter @cipherbox/core test -- node-codec` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | NODE-05 | — | Rust `Node` enum + cross-language `#[test]` — **Phase 69, not tested here** | — | — | n/a | ⬜ deferred |
| TBD | TBD | TBD | NODE-06 | — | vault v3 blob serialize/deserialize round-trip; exact hex matches golden vector | golden-vector | `pnpm --filter @cipherbox/core test -- vault-blob` | ❌ W0 (modify) | ⬜ pending |
| TBD | TBD | TBD | NODE-06 | — | `encryptedRootFolderKey` absent from all vault types | typecheck | `pnpm typecheck` | ❌ W0 | ⬜ pending |
| TBD | TBD | TBD | D-02 (gate) | — | `sdk-core` + `sdk` + `web` typecheck after `dist/` rebuild | typecheck | compile-gate command (see Test Infrastructure) | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `packages/core/src/__tests__/node-codec-vectors.test.ts` — NODE-01..NODE-04 (body-bytes lock + full-seal lock + round-trip + generation validation)
- [ ] `tests/vectors/node-codec.json` — frozen JSON fixture: all three node kinds (folder; file with `content` + GCM + CTR `VersionEntry`; root) + vault v3 blob vector
- [ ] Modify `packages/core/src/__tests__/vault-blob-vectors.test.ts` to the v3 two-key format (D-05) — existing file, not new
- [ ] No framework install needed — vitest 3.0.5 already configured in `packages/core`

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| `dist/` rebuild precedes consumer typecheck | NODE-05 / SC#5 | sdk/web typecheck the built `dist/`, not source ([[project-cross-package-dist-staleness]]) | Run `pnpm --filter @cipherbox/core build` before the compile-gate typecheck command; CI ordering must enforce this |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
