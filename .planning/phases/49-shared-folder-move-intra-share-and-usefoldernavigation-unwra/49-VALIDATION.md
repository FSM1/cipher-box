---
phase: 49
slug: shared-folder-move-intra-share-and-usefoldernavigation-unwra
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-06-18
---

# Phase 49 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property                | Value                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------ |
| **Framework**           | Vitest (SDK unit), Playwright (web e2e)                                               |
| **Config file**         | `packages/sdk/vitest.config.ts` (SDK), `tests/web-e2e/playwright.config.ts` (e2e)    |
| **Quick run command**   | `pnpm --filter @cipherbox/sdk test --run`                                             |
| **Full suite command**  | `pnpm --filter @cipherbox/sdk test --run && pnpm --filter @cipherbox/web test --run`  |
| **Estimated runtime**   | ~45 seconds (SDK + web unit; e2e excluded — main-push gated)                          |

---

## Sampling Rate

- **After every task commit:** Run `pnpm --filter @cipherbox/sdk test --run`
- **After every plan wave:** Run `pnpm --filter @cipherbox/sdk test --run && pnpm --filter @cipherbox/web test --run`
- **Before `/gsd-verify-work`:** Full SDK + web unit suites must be green
- **Max feedback latency:** 45 seconds

> E2E (`shared-folder-move.spec.ts`) runs only on push to `main` / manual dispatch — it does NOT gate the PR. Authored this phase, executed in the live environment.

---

## Per-Requirement Verification Map

> Task IDs are assigned during planning; this map is keyed by requirement until plans exist.

| Requirement | Threat Ref         | Secure Behavior                                                                  | Test Type | Automated Command                                                            | File Exists | Status     |
| ----------- | ------------------ | -------------------------------------------------------------------------------- | --------- | --------------------------------------------------------------------------- | ----------- | ---------- |
| REQ-1       | —                  | DFS enumerates subtree; folders lacking `folder-ipns` key marked non-writable    | unit      | `pnpm --filter @cipherbox/sdk test --run -- enumerate-shared-subtree`        | ❌ W0       | ⬜ pending |
| REQ-2       | T-49 Access Ctrl   | Publish DEST → re-key FileMetadata → publish SOURCE; write-cap checked both ends  | unit      | `pnpm --filter @cipherbox/sdk test --run -- move-in-shared-folder`           | ❌ W0       | ⬜ pending |
| REQ-2       | T-49 Tampering     | Name collision throws; re-key idempotent (source DECRYPTION_FAILED probes dest)   | unit      | same suite                                                                  | ❌ W0       | ⬜ pending |
| REQ-3       | —                  | Web move handler via `runWrite`; shared `MoveDialog` picker; `onMove` folder-view | unit      | `pnpm --filter @cipherbox/web test --run`                                    | ❌ W0       | ⬜ pending |
| REQ-4       | T-49 InfoDisclose  | `ensureFolderLoaded` replaces unwrap; SDK buffers cloned into `FolderNode`        | unit      | `pnpm --filter @cipherbox/web test --run` + existing `ensure-folder-loaded` | ✅ partial  | ⬜ pending |
| REQ-5       | T-49 CryptoFailure | Bob moves file; content DECRYPTS via TextEditor for Bob AND Alice after sync      | e2e       | `pnpm --filter web-e2e test -- shared-folder-move` (local docker stack)      | ❌ W0       | ⬜ pending |

_Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky_

---

## Wave 0 Requirements

- [ ] `packages/sdk/src/__tests__/enumerate-shared-subtree.test.ts` — REQ-1 DFS + writable flag
- [ ] `packages/sdk/src/__tests__/move-in-shared-folder.test.ts` — REQ-2 publish ordering, re-key, name collision, write-capability check
- [ ] `tests/web-e2e/tests/shared-folder-move.spec.ts` — REQ-5 two-account move + decrypt-survival (TextEditor `getContent`)

_Existing `ensure-folder-loaded.test.ts` covers the `ensureFolderLoaded` SDK behavior; REQ-4 consolidation is verified at the web unit layer (FolderState→FolderNode mapping) — no new SDK test needed._

---

## Manual-Only Verifications

| Behavior                                                  | Requirement | Why Manual                                                  | Test Instructions                                                                                          |
| --------------------------------------------------------- | ----------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Cross-client decrypt-survival after shared move (live IPNS)| REQ-5       | Two-account IPNS propagation only realistic on live stack  | `docker compose -f docker/docker-compose.yml up -d`, then `pnpm --filter web-e2e test -- shared-folder-move` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 45s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
