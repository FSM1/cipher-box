---
phase: 79
slug: web-kind-discrimination-completion-and-deferred-test-revival
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-07-11
---

# Phase 79 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Vitest (sdk-core / core / sdk = CI `Test` job; apps/web = local-only, `include: ['src/**/*.test.ts']`, web-e2e-gated on main push, NOT in CI `Test` job) |
| **Config file** | `packages/sdk-core/vitest.config.ts`, `packages/core/vitest.config.ts`, `apps/web/vitest.config.ts` |
| **Quick run command** | `pnpm --filter @cipherbox/sdk-core test -- file.test.ts load.test.ts` · `pnpm --filter @cipherbox/core test -- bin.test.ts` · `pnpm --filter @cipherbox/web test -- useSharedWriteOps.test.ts` |
| **Full suite command** | `pnpm test` (root — runs CI-gated packages) |
| **Estimated runtime** | ~20 seconds (targeted per-package); ~3-5 min full root suite |

---

## Sampling Rate

- **After every task commit:** Run the relevant package quick command for any task touching `packages/sdk-core`, `packages/core`, or `apps/web/src/hooks/__tests__`. For source-only UI wiring tasks (no test file), the "test" is a source-assertion grep (see Per-Task map).
- **After every plan wave:** Run `pnpm test` (root) — this phase touches CI-gated packages (`sdk-core`, `core`).
- **Before `/gsd-verify-work`:** Full suite green + `grep -rn "TODO(phase 63)\|TODO(phase 65)" apps packages` returns zero + Puppeteer/manual UI confirmation for SC1/SC2.
- **Max feedback latency:** ~20 seconds (targeted package run)

---

## Per-Task Verification Map

> Representative — the executor maps concrete task IDs onto these rows once plans are finalized. Source-assertion rows are the primary proof for UI wiring (apps/web is not unit-tested for components).

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 79-01-xx | 01 | 1 | SC2 | — | N/A (display of already-decrypted field) | source | `grep -n "createdAt" packages/sdk/src/folder-listing.ts` | ✅ | ⬜ pending |
| 79-01-xx | 01 | 1 | SC1 | — | N/A | source | `grep -c "resolvedByIpnsName" apps/web/src/components/file-browser/useFileBrowserActions.ts` (returns >0 incl. a return-value entry) | ✅ | ⬜ pending |
| 79-02-xx | 02 | 2 | SC1 | — | Only folder-kind rows accept a drop; folders sort first | source + manual/e2e | `grep -rn "TODO(phase 6" apps/web/src/components/file-browser/FileList.tsx` returns 0 | ✅ | ⬜ pending |
| 79-02-xx | 02 | 2 | SC1 | — | Dialogs label the real kind, no hardcoded "folder" | source | `grep -rn "TODO(phase 6" apps/web/src/components/file-browser` returns 0 | ✅ | ⬜ pending |
| 79-03-xx | 03 | 1 | SC3 | — | `updateFileMetadata` CAS/conflict coverage not weakened by rewrite | unit | `pnpm --filter @cipherbox/sdk-core test -- file.test.ts load.test.ts` exits 0, no `.skip` | ✅ | ⬜ pending |
| 79-03-xx | 03 | 1 | SC3 | — | `BinEntry.nodeRef` fixture populated | unit | `pnpm --filter @cipherbox/core test -- bin.test.ts` exits 0 | ✅ | ⬜ pending |
| 79-03-xx | 03 | 2 | SC3 | — | shared move/batch-move handlers route through `client.moveInSharedFolder` | unit | `pnpm --filter @cipherbox/web test -- useSharedWriteOps.test.ts` exits 0, no `.skip` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

*Existing infrastructure covers all phase requirements.* All four target test files already exist with the scaffolding (mocks, fixtures, imports); no new test file or shared fixture needs to be created. The only gap is content: `load.test.ts` and `file.test.ts` need their bodies rewritten against current contracts before they can pass (or explicit retirement with rationale) — plan-task work, not infrastructure work.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Folders-first sort renders folders before files in a mixed listing | SC1 | apps/web UI components are not unit-tested (logic-in-SDK / web-e2e policy) | Local stack + login; open a folder containing both files and subfolders; confirm folders group first. Puppeteer MCP screenshot if available. |
| Only folder rows accept a drag-drop; files do not | SC1 | Same (drag-drop is DOM interaction) | Drag a file over another file (no drop affordance) vs over a folder (drop affordance). Puppeteer MCP interaction if available. |
| Details "Created" row shows a real date, not a dim "unavailable" placeholder | SC2 | Same (render output) | Open a file's and a folder's Details pane; confirm the Created row shows a formatted date. |

*Web-e2e (Playwright, main-push gated) is the automated backstop for the SC1/SC2 UI behaviors above; per-commit proof is source assertion.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify (unit command or source-assertion grep) or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (none — all test files exist)
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s (targeted package run)
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
