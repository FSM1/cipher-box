---
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
verified: 2026-07-12T00:00:00Z
status: human_needed
score: 15/17 must-haves verified
behavior_unverified: 2
overrides_applied: 0
behavior_unverified_items:
  - truth: "SC3c item-3 (poll-monotonicity): the new deterministic web-e2e poll-monotonicity.spec.ts reproduces the same-folder stale-poll race and passes with the fix"
    test: "Reset the cipherbox DB (clear stale ipns_records so new-account init does not collide), restart API from source with aligned TEST_LOGIN_SECRET/SDK_E2E_SECRET, then run: pnpm --filter @cipherbox/web-e2e test -- poll-monotonicity.spec.ts"
    expected: "GREEN — the open folder retains sequence S2 and the NEWER_NAV_MARKER child; the held stale poll (S1) is dropped by the sequenceNumber guard"
    why_human: "The e2e run was infra-blocked (shared-DB duplicate-key on new-account vault init from a concurrent Phase 79 pipeline), never reaching the race logic. The guard code is present and correct-by-inspection (mirrors folder.store.ts's proven monotonicity guard), but the existing useSyncPolling unit test covers only the folder-CHANGED path, not the new same-folder-newer-sequence path. Cannot run heavy e2e in static verification."
  - truth: "SC2 (D-05): the FileBrowser download spinner visibly lights up during a real download, and bin restore shows a store-driven affordance on screen"
    test: "Run the app, trigger a file download and a bin restore, and observe the spinner/affordance render (Puppeteer or manual per CLAUDE.md)"
    expected: "Spinner appears while isDownloading is true; bin restore shows restoring/success state"
    why_human: "No Playwright/automated assertion exists for spinner visibility (Wave 0 gap, flagged in 78-04-SUMMARY). Code path is fully wired and data flows (verified statically), but the on-screen render is a visual check grep cannot see."
human_verification:
  - test: "Re-run poll-monotonicity.spec.ts on a clean cipherbox DB (see behavior_unverified_items #1)"
    expected: "GREEN — stale poll dropped, NEWER_NAV_MARKER survives"
    why_human: "e2e was infra-blocked; guard present but new same-folder-sequence path only covered by this (unrun) e2e"
  - test: "Visually confirm download spinner + bin-restore affordance render (Puppeteer/manual)"
    expected: "Spinner lights up during download; restore shows status affordance"
    why_human: "No automated spinner-visibility assertion (Wave 0 gap)"
follow_ups_non_blocking:
  - "Rebuild the docker cipherbox-mock-ipns-routing image so the standard stack serves the committed CORS onRequest hook (tools/mock-ipns-routing, #365) — the recovery e2e green-run required a temporary CORS-enabled replica on :3001. Code hook is correct; only the baked image is stale."
  - "Add apps/web/recovery-src to a persistent tsconfig include so CI typechecks it (78-02 verified via ephemeral tsconfig.recovery.json, removed after use)."
  - "Optionally wire SDK_E2E_SECRET into tests/web-e2e/.env (or have the harness also read TEST_LOGIN_SECRET) so recovery/e2e seeding does not need a manual export."
---

# Phase 78: Recovery Tool v3, Vault-Load Guards, Web UX and CI Guards — Verification Report

**Phase Goal:** Close the v3 vault-format loose ends and the web/CI hardening backlog — port the offline recovery.html tool to the node/v3 read chain (un-fixme recovery.spec.ts so web-e2e has zero expected failures), resolve the download-progress UX dead code, CI-enforce the D-07 web/SDK boundary, decide/wire web vitest, and land the item-3 poll-monotonicity + item-11 descent-vs-restore data-integrity race fixes.
**Verified:** 2026-07-12
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | SC1/D-02: recovery-src imports ONLY @cipherbox/crypto + @cipherbox/core (no sdk/sdk-core/api-client/API/Web3Auth) | VERIFIED | `grep -rnE "from '@cipherbox/(sdk\|sdk-core\|api-client)'" apps/web/recovery-src` empty; only crypto+core imports present across gateway/main/walk |
| 2 | SC1/D-03: recovery reuses low-level primitives, hand-rolls nothing | VERIFIED | walk.ts uses `unsealChildReadKey`/`unsealNode` from @cipherbox/core; gateway uses `verifyIpnsRecordSignature`/`parseIpnsRecord`; main uses `deriveVault*Keypair`/`deserializeVaultBlobV3`/`unwrapKey` |
| 3 | SC1/D-04: IPFS/IPNS over configurable HTTP gateway, no libp2p/API | VERIFIED | gateway.ts `resolveIpnsVerified`/`fetchFromIpfs` plain fetch against caller URLs |
| 4 | SC1: esbuild browser bundle, zero cdn.jsdelivr runtime dep | VERIFIED | recovery-src grep cdn.jsdelivr = 0 (all files); recovery.html script count=1, external http script=0, cdn.jsdelivr=0 |
| 5 | SC1/D-01: offline walk decrypts whole tree from privateKey with API absent | VERIFIED | main.ts full chain (blob→rootReadKey→root→recoverTree→zip→download); e2e green-run documented (commit e2f1181b6), API only in beforeAll seeding |
| 6 | SC1: parent-mirror generation (childRef.generation, never published.generation) | VERIFIED | walk.ts:120-125 passes `childRef.generation` into `unsealChildReadKey` with inline rule comment; no `published.generation` in unseal call |
| 7 | SC1: recovery.html inlines bundle + preserves all 6 data-testids | VERIFIED | all 6 testids present (count 2 each); single inline `<script>`; Buffer polyfill injected via build.ts (commit ac12fea04) |
| 8 | SC1: recovery.spec.ts un-fixme'd; full web-e2e suite has zero fixme/skip | VERIFIED | `test('recovers vault files via IPFS-direct v3 read chain'...)` active; `grep -rnE 'test\.(fixme\|skip)\(' tests/web-e2e/tests/*.spec.ts` empty |
| 9 | SC2/D-05: handleDownload/handleBatchDownload drive useDownloadStore → spinner (wired, not deleted) | VERIFIED (code+data-flow) | handlers call `downloadFromIpns` (useFileDownload) → useDownloadStore lifecycle → `isDownloading` → FileBrowser SelectionActionBar `isLoading`. Visual render routed to human (see #16) |
| 10 | SC2/D-05: bin restore surfaces store-driven affordance | VERIFIED | restore.store.ts (metadata-only, no byte fields); useBin restore/restoreMultiple drive startRestore/setRestoreSuccess/setRestoreError |
| 11 | SC3a/D-07: apps/web/src runtime import of sdk-core/core fails lint | VERIFIED | eslint.config.js scoped block; fixture `import { getSdkClient } from '@cipherbox/sdk-core'` → eslint exit 1 (live spot-check) |
| 12 | SC3a/D-07 Gate B: raw IPFS call names fail lint | VERIFIED | `no-restricted-syntax` CallExpression selector; fixture `fetchFromIpfs('cid')` → eslint exit 1 (live spot-check) |
| 13 | SC3a: rule scoped to apps/web/src (ignoring __tests__), CI-enforced via `pnpm lint` | VERIFIED | files/ignores scoping present; `"lint": "eslint ."`; clean tree lints exit 0 |
| 14 | SC3b/D-06: docs/DEVELOPMENT.md documents the testing split + deliberate apps/web-vitest CI exclusion | VERIFIED | "Test architecture and CI coverage (the deliberate split)" section, D-06 named, .spec.ts caveat documented |
| 15 | SC3b/D-06: residual apps/web *.test.ts suite green, no new web unit tests, apps/web out of blocking CI | VERIFIED | 10 files/67 tests (61 pass+6 skip) documented green; apps/web absent from ci.yml Test job |
| 16 | SC3c item-3: sequence-guard drops stale poll; new deterministic e2e passes | ⚠️ PRESENT_BEHAVIOR_UNVERIFIED | Guard present (useSyncPolling.ts:37,57-58); poll-monotonicity.spec.ts present (describe.serial, never skipped, NEWER_NAV_MARKER assert). e2e run infra-blocked; unit test covers only folder-changed path, not new same-folder-sequence path — see human verification |
| 17 | SC3c item-11: two-layer descent generation guard; new deterministic e2e passes | VERIFIED | Web hook token checks (useSharedNavigationActions.ts:380,397,435) + SDK backstop (client.ts loadSharedFolder rejects stale seedGeneration; shared-folder-tree.ts seedGenerations map, delete bumps). descent-vs-restore.spec.ts 4/4 GREEN twice + 13 SDK unit assertions (shared-folder-seed-generation.test.ts) |

**Score:** 15/17 truths verified (2 present, behavior-unverified: SC3c item-3 e2e re-run + SC2 spinner visual)

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `apps/web/recovery-src/{build,gateway,walk,main}.ts` + `buffer-shim.ts` | v3 recovery tool | ✓ VERIFIED | All present, substantive, crypto/core-only imports, wired into recovery.html |
| `apps/web/public/recovery.html` | self-contained tool | ✓ VERIFIED | Inline bundle, 6 testids, no CDN/external script |
| `tests/web-e2e/tests/recovery.spec.ts` | active regression | ✓ VERIFIED | Un-fixme'd, v3 title, green-run documented |
| `apps/web/src/stores/restore.store.ts` | restore status store | ✓ VERIFIED | Metadata-only shape, wired into useBin |
| `apps/web/src/components/file-browser/useFileBrowserActions.ts` | store-driven download | ✓ VERIFIED | Both handlers drive useDownloadStore via useFileDownload |
| `eslint.config.js` | D-07 boundary rule | ✓ VERIFIED | Scoped block, both gates fire on fixtures |
| `docs/DEVELOPMENT.md` | testing split doc | ✓ VERIFIED | D-06 section present |
| `apps/web/src/hooks/useSyncPolling.ts` | sequence guard | ✓ VERIFIED | Capture-then-recheck guard |
| `tests/web-e2e/tests/poll-monotonicity.spec.ts` | regression spec | ✓ VERIFIED (present) | Deterministic, never skipped; run infra-blocked |
| `apps/web/src/hooks/useSharedNavigationActions.ts` + `packages/sdk/src/client.ts` + `shared-folder-tree.ts` | two-layer descent guard | ✓ VERIFIED | Token threaded both layers |
| `tests/web-e2e/tests/descent-vs-restore.spec.ts` + SDK seed-generation tests | regression + unit | ✓ VERIFIED | e2e 4/4 green + SDK units |

### Key Link Verification

| From | To | Via | Status |
| --- | --- | --- | --- |
| recovery-src/main.ts | @cipherbox/crypto + @cipherbox/core | direct barrel imports (only allowed) | ✓ WIRED |
| build.ts | recovery.html placeholder | esbuild splice (idempotent BEGIN/END markers) | ✓ WIRED |
| useFileBrowserActions.handleDownload | useDownloadStore | useFileDownload().downloadFromIpns lifecycle | ✓ WIRED |
| useDownloadStore.isDownloading | FileBrowser spinner | SelectionActionBar isLoading binding | ✓ WIRED |
| useBin.restore | useRestoreStore | startRestore/setRestoreSuccess/setRestoreError | ✓ WIRED |
| eslint.config.js scoped override | CI lint job | `pnpm lint` = `eslint .` | ✓ WIRED |
| navigateToSubfolder descentToken | SDK sharedFolderTree active-depth | seedGeneration passed to loadSharedFolder | ✓ WIRED |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| --- | --- | --- | --- | --- |
| FileBrowser spinner | isDownloading | useDownloadStore status (downloading/decrypting), set by useFileDownload during client.downloadFromIpns | ✓ | ✓ FLOWING |
| recovery.html | recovered file bytes | gateway fetch → unsealNode → decryptAesGcm/Ctr | ✓ | ✓ FLOWING (e2e green) |
| poll-monotonicity result | folder.sequenceNumber/children | store guard drops stale poll | ⚠️ | ⚠️ e2e not run (guard present, correct-by-inspection) |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| --- | --- | --- | --- |
| D-07 eslint parses on modified web files | `npx eslint useSyncPolling.ts useBin.ts` | exit 0 | ✓ PASS |
| D-07 rule fires on forbidden import + raw IPFS call | eslint on throwaway fixture | exit 1, both rule messages | ✓ PASS |
| SC1 exit grep clean | `grep -rnE 'test\.(fixme\|skip)\(' tests/web-e2e/tests/*.spec.ts` | empty | ✓ PASS |
| Full web-e2e suite | (not run — heavy, per instructions) | — | ? SKIP |

### Requirements Coverage

No REQUIREMENTS.md IDs map to phase 78 (SC1/SC2/SC3 are phase-local success criteria). Coverage assessed against the three Success Criteria directly (see Observable Truths).

### Anti-Patterns Found

| File | Pattern | Severity | Impact |
| --- | --- | --- | --- |
| (none) | Debt markers (TBD/FIXME/XXX) in modified files | — | FIXME(recovery-v3) block was intentionally deleted in 78-03; no unreferenced debt markers found in phase files |

### Human Verification Required

1. **Poll-monotonicity e2e re-run (SC3c item-3)** — Reset the cipherbox DB, restart API from source with aligned secrets, then `pnpm --filter @cipherbox/web-e2e test -- poll-monotonicity.spec.ts`. Expect GREEN (stale poll dropped, NEWER_NAV_MARKER survives). The guard code is present and mirrors the proven folder.store.ts monotonicity guard, but the run was infra-blocked (shared-DB duplicate-key from a concurrent Phase 79 pipeline) and the existing unit test covers only the folder-changed path, not the new same-folder-newer-sequence path.

2. **Download spinner + bin-restore affordance visibility (SC2)** — Run the app, trigger a download and a bin restore, observe the spinner/affordance render (Puppeteer or manual per CLAUDE.md). Code is fully wired and data flows; only the visual render lacks an automated assertion (Wave 0 gap flagged in 78-04-SUMMARY).

### Gaps Summary

No BLOCKERS. Every must-have artifact exists, is substantive, is wired, and data flows. All three Success Criteria are met at the code level:

- **SC1** — the offline v3 recovery tool is built (crypto/core-only, HTTP gateway, no API/Web3Auth/CDN), recovery.spec.ts is un-fixme'd, and the web-e2e suite has zero fixme/skip. The recovery e2e green-run is documented (commit `ac12fea04` fixed the Buffer polyfill + splice bug the un-fixme'd spec surfaced). Met.
- **SC2** — download-progress dead code is WIRED, not deleted (D-05): download handlers drive useDownloadStore → FileBrowser spinner; bin restore drives a new useRestoreStore. The on-screen render needs a visual/human check (no automated assertion).
- **SC3** — D-07 web/SDK boundary is CI-enforced via a scoped ESLint rule (both gates fire on live fixtures); the web-vitest decision (D-06) is documented + the residual suite is green; item-11 descent-vs-restore is fixed (two-layer guard, e2e 4/4 green + SDK units); item-3 poll-monotonicity guard is present but its new e2e spec was infra-blocked and needs a clean-DB re-run.

Two items route to human verification (poll-monotonicity e2e re-run, spinner visual). Three documented, non-blocking infra follow-ups are recorded in frontmatter (`follow_ups_non_blocking`): rebuild the docker mock-ipns-routing CORS image, add recovery-src to a CI tsconfig, optionally wire SDK_E2E_SECRET. None of these are code gaps.

---

_Verified: 2026-07-12_
_Verifier: Claude (gsd-verifier)_
