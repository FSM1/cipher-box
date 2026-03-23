---
phase: 20
slug: vault-migration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-23
---

# Phase 20 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property               | Value                                               |
| ---------------------- | --------------------------------------------------- |
| **Framework**          | vitest (packages/core, packages/sdk) + jest (apps/api) |
| **Config file**        | `packages/core/vitest.config.ts`, `apps/api/jest.config.ts` |
| **Quick run command**  | `pnpm --filter @cipherbox/core test -- --run`       |
| **Full suite command** | `pnpm --filter @cipherbox/core test -- --run && pnpm --filter api test -- --passWithNoTests` |
| **Estimated runtime**  | ~30 seconds                                         |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/core test -- --run`
- **After every plan wave:** Run full suite command
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID   | Plan | Wave | Requirement | Test Type   | Automated Command | File Exists | Status     |
| --------- | ---- | ---- | ----------- | ----------- | ----------------- | ----------- | ---------- |
| 20-01-01  | 01   | 1    | VAULT-01    | unit        | `pnpm --filter @cipherbox/core test -- --run` | ❌ W0 | ⬜ pending |
| 20-01-02  | 01   | 1    | VAULT-01    | unit        | `pnpm --filter @cipherbox/core test -- --run` | ❌ W0 | ⬜ pending |
| 20-02-01  | 02   | 1    | VAULT-02    | unit+integ  | `pnpm --filter api test -- --passWithNoTests` | ❌ W0 | ⬜ pending |
| 20-02-02  | 02   | 1    | VAULT-04    | unit        | `pnpm --filter api test -- --passWithNoTests` | ❌ W0 | ⬜ pending |
| 20-03-01  | 03   | 2    | VAULT-02,03 | integration | `pnpm --filter @cipherbox/core test -- --run` | ❌ W0 | ⬜ pending |
| 20-04-01  | 04   | 2    | VAULT-06    | unit        | `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml` | ❌ W0 | ⬜ pending |
| 20-05-01  | 05   | 3    | VAULT-05    | manual      | N/A | N/A | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `packages/core/src/vault/__tests__/blob-v2.test.ts` — v2 serialize/deserialize, v1 detection, round-trip with ECIES key
- [ ] `apps/api/src/vault/vault.service.spec.ts` — extend with migration endpoint tests, nullable column handling
- [ ] Test vectors: known v1 blob, known v2 blob with expected key extraction

_Existing `packages/core/src/__tests__/vault.test.ts` covers current initializeVault/encryptVaultKeys/decryptVaultKeys._

---

## Manual-Only Verifications

| Behavior                        | Requirement | Why Manual           | Test Instructions                                                      |
| ------------------------------- | ----------- | -------------------- | ---------------------------------------------------------------------- |
| Recovery tool parses v2 blob    | VAULT-05    | Standalone HTML file | Open recovery.html, paste vault export, verify rootFolderKey extracted |
| Desktop FUSE mount with v2 blob | VAULT-06    | Requires desktop app | Login on desktop, verify mount works with v2 blob source              |

_Recovery tool and desktop are manual verification. Core blob parsing is unit-tested._

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
