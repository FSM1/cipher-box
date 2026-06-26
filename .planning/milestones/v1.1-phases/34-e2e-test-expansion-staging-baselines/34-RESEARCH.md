# Phase 34: E2E Test Expansion & Staging Baselines - Research

**Researched:** 2026-03-29
**Domain:** Playwright E2E testing, Service Worker interception, media playback, staging baselines
**Confidence:** HIGH

## Summary

Phase 34 is a pure testing/validation phase with no production code changes. It expands web-e2e test coverage to untested features (AES-CTR streaming playback, media previews, batch download) and captures staging performance baselines with the Phase 30 Faro instrumentation now deployed.

The existing E2E infrastructure is mature: 12 spec files, comprehensive page objects, wallet-based auth helpers, and proven patterns for file upload/download/preview. The primary work is writing new spec files that follow established patterns and generating minimal media fixture files for upload. A secondary concern is wiring `deleteAccount` teardown into all specs' `afterAll` hooks -- currently only `recovery.spec.ts` and `load-test.spec.ts` clean up accounts.

**Primary recommendation:** Follow the existing test patterns exactly. Each new spec creates a fresh wallet identity, logs in via `loginViaWallet`, uses page objects for interactions, and tears down via a shared `deleteAccount` helper. Media fixtures should be minimal valid files (smallest possible MP4/MP3/PDF that pass the 256KB CTR threshold where needed).

## Project Constraints (from CLAUDE.md)

- **Conventional Commits enforced** via husky `commit-msg` hook
- **Never push to main** -- all work on feature branches, merge via PR
- **Chromium-only tests** per playwright.config.ts (single project)
- **No retries** -- `retries: 0` in config; fix flakiness immediately
- **Sequential execution** -- `fullyParallel: false`, `workers: 1`
- **After modifying API endpoints**: run `pnpm api:generate` (not expected for this phase)
- **Run E2E tests locally before pushing** (from MEMORY.md)
- **Branch protection**: never commit to main; create feature branch immediately

## Standard Stack

### Core

| Library                    | Version | Purpose                       | Why Standard                                                            |
| -------------------------- | ------- | ----------------------------- | ----------------------------------------------------------------------- |
| @playwright/test           | 1.57.0  | E2E test framework            | Already installed, all 12 specs use it                                  |
| @johanneskares/wallet-mock | ^1.4.1  | EIP-6963 mock wallet for auth | All non-recovery specs use mock wallet login                            |
| viem                       | ^2.46.1 | Wallet keypair generation     | `generatePrivateKey` + `privateKeyToAccount` for unique test identities |

### Supporting (already in project)

| Library           | Version      | Purpose                                  | When to Use                                            |
| ----------------- | ------------ | ---------------------------------------- | ------------------------------------------------------ |
| @cipherbox/crypto | workspace:\* | Key utilities (`bytesToHex`)             | Only if SDK-based test setup needed (recovery pattern) |
| @cipherbox/sdk    | workspace:\* | CipherBoxClient for programmatic seeding | Only if uploading via SDK is faster than UI            |
| dotenv            | ^16.4.0      | Env var loading                          | Already wired in playwright configs                    |

### No New Dependencies Required

This phase requires zero new npm packages. All test infrastructure exists. Media fixture files will be generated via script or committed as binary fixtures.

## Architecture Patterns

### Existing Test File Structure

```
tests/web-e2e/
  tests/
    full-workflow.spec.ts     # Serial suite, wallet login, file operations
    sharing-workflow.spec.ts  # Multi-account (Alice/Bob/Charlie)
    writable-shares.spec.ts   # Multi-account (Alice/Bob)
    load-test.spec.ts         # Concurrent users against staging
    journey-timing.spec.ts    # Performance timing capture
    recovery.spec.ts          # SDK-seeded + Playwright browser verification
    ...
  page-objects/
    file-browser/             # FileListPage, UploadZonePage, ContextMenuPage, etc.
    dialogs/                  # ConfirmDialogPage, ShareDialogPage, etc.
    login.page.ts
    base.page.ts
  utils/
    wallet-login-helpers.ts   # createTestAccount, setupMockWallet, loginViaWallet
    multi-account-wallet.ts   # createWalletTestAccount, closeWalletTestAccounts
    test-files.ts             # createTestTextFile, createTestBinaryFile, cleanupTestFiles
    api-helpers.ts            # Placeholder (unused)
  fixtures/files/             # Static test fixtures (.bin, .txt, .png)
```

### Pattern 1: Single-Account Serial Suite (for streaming-playback, media-preview, batch-download)

All three new test suites follow the same pattern as `full-workflow.spec.ts`:

```typescript
import { test, expect, Browser, BrowserContext, Page } from '@playwright/test';
import { createTestAccount, setupMockWallet, loginViaWallet } from '../utils/wallet-login-helpers';
import { createTestTextFile, cleanupTestFiles } from '../utils/test-files';
import { FileListPage } from '../page-objects/file-browser/file-list.page';
import { UploadZonePage } from '../page-objects/file-browser/upload-zone.page';
import { ContextMenuPage } from '../page-objects/file-browser/context-menu.page';

test.describe.serial('Suite Name', () => {
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  let fileList: FileListPage;
  let uploadZone: UploadZonePage;
  let contextMenu: ContextMenuPage;

  test.beforeAll(async ({ browser: testBrowser }) => {
    browser = testBrowser;
    const account = createTestAccount();
    context = await browser.newContext();
    page = await context.newPage();
    await setupMockWallet(page, account);
    const result = await loginViaWallet(page, { timeout: 90_000 });
    expect(result.outcome).toBe('success');
    fileList = new FileListPage(page);
    uploadZone = new UploadZonePage(page);
    contextMenu = new ContextMenuPage(page);
  });

  test.afterAll(async () => {
    cleanupTestFiles();
    // deleteAccount via page.evaluate (see Pattern 3 below)
    if (context) await context.close();
  });

  test('test name', async () => {
    /* ... */
  });
});
```

### Pattern 2: File Preview via Context Menu

Files are NOT opened by double-click (double-click navigates into folders only). Previews are triggered through the context menu:

```typescript
// Right-click the file -> click Preview
await fileList.rightClickItem('my-video.mp4');
await contextMenu.waitForOpen();
await contextMenu.clickPreview();

// Wait for modal to appear
await page.locator('.video-player-modal').waitFor({ state: 'visible', timeout: 30_000 });

// Verify video element loaded
await page.locator('.video-player-modal video').waitFor({ state: 'visible' });
```

**CSS class selectors for media dialogs** (no data-testid attributes exist):

| Dialog | Modal class           | Loading state            | Error state            | Media element                                |
| ------ | --------------------- | ------------------------ | ---------------------- | -------------------------------------------- |
| Video  | `.video-player-modal` | `.video-preview-loading` | `.video-preview-error` | `video` element within modal                 |
| Audio  | `.audio-player-modal` | `.audio-preview-loading` | `.audio-preview-error` | Hidden `<audio>` (visualization uses canvas) |
| PDF    | `.pdf-preview-modal`  | `.pdf-preview-loading`   | `.pdf-preview-error`   | `canvas` elements for pages                  |

**Streaming indicators:**

- CTR encrypted badge: `.video-cipher-badge` with text "ENCRYPTED"
- Decrypt progress: `.video-decrypt-progress-fill` (width percentage style)
- Decrypt label: `.video-decrypt-label` with text "decrypting..."

### Pattern 3: In-Page Account Deletion (for web-e2e specs)

The load-test spec has a proven `deleteAccount` pattern that works from within a Playwright page context:

```typescript
async function deleteAccountViaPage(page: Page): Promise<void> {
  try {
    const deleted = await page.evaluate(async () => {
      const apiUrl =
        (window as any).__VITE_API_URL ||
        document.querySelector('meta[name="api-url"]')?.getAttribute('content') ||
        'http://localhost:3000';

      // Refresh token to get fresh access token
      const refreshRes = await fetch(`${apiUrl}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!refreshRes.ok) return { ok: false, step: 'refresh', status: refreshRes.status };
      const { accessToken } = await refreshRes.json();

      // Delete account
      const deleteRes = await fetch(`${apiUrl}/auth/account`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ confirmation: 'DELETE' }),
      });
      return { ok: deleteRes.ok, step: 'delete', status: deleteRes.status };
    });

    if (!deleted.ok) {
      console.warn(`Account deletion failed at ${deleted.step}: HTTP ${deleted.status}`);
    }
  } catch (err) {
    console.warn(`Account deletion error: ${(err as Error).message}`);
  }
}
```

**Key design:** The helper must be best-effort (catch errors, warn but don't throw) so test failures still report properly. The API URL must be discovered at runtime since it varies between local (localhost:3000) and staging.

### Pattern 4: Batch Download Verification

**Critical finding:** Batch download does NOT create a zip file. It downloads files individually in sequence via `downloadFromIpns` for each selected file. The todo description mentions "zip generation" but the actual implementation just loops through selected files.

```typescript
// Select multiple files
await fileList.ctrlClickItem('file-1.txt');
await fileList.ctrlClickItem('file-2.txt');

// Verify selection bar appears
const selectionBar = new SelectionActionBarPage(page);
await selectionBar.waitForVisible();
expect(await selectionBar.getCountText()).toContain('2 files');

// Click download - each file triggers a separate download event
const downloadPromise = page.waitForEvent('download');
await selectionBar.clickDownload();
const download = await downloadPromise;
expect(download.suggestedFilename()).toBeTruthy();
```

### Anti-Patterns to Avoid

- **Do not add data-testid attributes to production components** -- this phase is test-only. Use existing CSS class selectors (`.video-player-modal`, `.audio-player-modal`, `.pdf-preview-modal`).
- **Do not use `test.only`** -- `forbidOnly: true` in CI config will fail the build.
- **Do not add `sleep` or fixed waits** -- use Playwright's auto-waiting (`waitFor`, `waitForEvent`, etc.).
- **Do not generate large fixture files** -- 300KB is sufficient for CTR threshold (256KB). Keep fixtures under 1MB to avoid slow test runs.
- **Do not assume Service Worker is available** -- In Playwright's Chromium, SW support depends on context settings. The `serviceWorkers` context option defaults to `'allow'`. Verify SW registration works in the test.

## Don't Hand-Roll

| Problem                  | Don't Build              | Use Instead                                       | Why                                                                   |
| ------------------------ | ------------------------ | ------------------------------------------------- | --------------------------------------------------------------------- |
| Auth flow                | Custom login code        | `loginViaWallet()` from `wallet-login-helpers.ts` | Handles Core Kit init timing, mock wallet setup, /files redirect wait |
| File upload              | Direct API calls         | `UploadZonePage.uploadFile()` page object         | Uses `setInputFiles` which reliably triggers react-dropzone           |
| Multi-select             | Complex DOM manipulation | `FileListPage.ctrlClickItem()`                    | Already handles ControlOrMeta modifier correctly                      |
| Account cleanup          | Direct fetch from Node   | `page.evaluate()` pattern from load-test          | Must use page context for credentials/cookies                         |
| Media fixture generation | Complex encoding scripts | Minimal valid files (see Fixtures section below)  | Only need valid headers, not real media content                       |

## Common Pitfalls

### Pitfall 1: Service Worker Availability in Playwright

**What goes wrong:** Tests checking SW-intercepted `/decrypt-stream/` URLs may fail because the SW hasn't activated yet.
**Why it happens:** Playwright creates fresh browser contexts. The SW must register and activate before it can intercept fetches. In dev mode, the SW URL is `/src/workers/decrypt-sw.ts`.
**How to avoid:** After login, wait for the app's SW registration to complete. Check `navigator.serviceWorker.controller` via `page.evaluate()` before testing streaming features. If SW is not active after a reasonable timeout, the app falls back to GCM blob URL -- test that fallback path instead.
**Warning signs:** Tests pass locally but fail in CI; video plays via blob URL instead of `/decrypt-stream/` URL.

### Pitfall 2: CTR vs GCM Mode Selection Depends on File Size AND MIME Type

**What goes wrong:** Uploading a 300KB `.bin` file expecting CTR mode -- it gets GCM because it's not a recognized media MIME type.
**Why it happens:** `selectEncryptionMode()` checks BOTH conditions: `STREAMING_MIME_TYPES.has(file.type)` AND `file.size > 256 * 1024`. The upload zone reads MIME from the `File` object, so the fixture must have a correct media extension AND exceed 256KB.
**How to avoid:** Use properly-named fixture files (`.mp4`, `.mp3`, `.webm`) with correct MIME type headers. For GCM fallback testing, use files under 256KB or non-media MIME types.
**Warning signs:** All files use GCM blob URLs; SW never intercepts.

### Pitfall 3: Media Element Timing in Headless Chromium

**What goes wrong:** Video `loadedmetadata` or `canplay` events never fire; test times out.
**Why it happens:** Headless Chromium may handle media codecs differently. Minimal/synthetic MP4 files may not contain valid codec atoms. The AES-CTR decryption must succeed before the browser can parse the media container.
**How to avoid:** Use real (tiny but valid) media files as fixtures. An MP4 with a single blank video frame and AAC silence track at ~300KB is ideal. Generate with ffmpeg if available. Alternatively, test only that the modal opens and the video element has a `src` attribute, without waiting for playback events.
**Warning signs:** `loadedmetadata` timeout; video element `error` event fires.

### Pitfall 4: Account Deletion Requires Active Session

**What goes wrong:** `deleteAccount` fails with 401 because the access token expired during a long test.
**Why it happens:** Access tokens have a short TTL. If the test suite takes >15 minutes, the token refreshed at login is stale.
**How to avoid:** The `page.evaluate()` deletion pattern refreshes the token first via `/auth/refresh` (using the HTTP-only cookie). Always refresh before delete, never reuse a cached token.
**Warning signs:** 401 on DELETE /auth/account in afterAll.

### Pitfall 5: Batch Download Triggers Multiple Download Events

**What goes wrong:** Test expects a single download (zip) but gets multiple individual file downloads.
**Why it happens:** `handleBatchDownload` loops through selected files and calls `downloadFromIpns` for each one sequentially. There is NO zip bundling.
**How to avoid:** Listen for `page.waitForEvent('download')` for each expected file download. Or listen once and verify at least one download completes. Do not expect a `.zip` file.
**Warning signs:** Test waiting for download event that has already fired.

### Pitfall 6: Staging Baseline Tests Need Matching Config

**What goes wrong:** Load test runs against staging but uses localhost config; journey timing captures local-only metrics.
**Why it happens:** `playwright.load.config.ts` is configured for staging; the default `playwright.config.ts` targets localhost.
**How to avoid:** Always use `--config=playwright.load.config.ts` for staging tests. Journey timing against staging needs either a modified config or `BASE_URL` override.
**Warning signs:** Tests hitting localhost instead of staging; metrics captured from wrong environment.

## Fixture Files Strategy

### Required Media Fixtures

Create minimal valid media files in `tests/web-e2e/fixtures/files/`:

| Fixture                | Size   | Purpose                                       | How to Generate                                                                                                                                                        |
| ---------------------- | ------ | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test-video.mp4`       | ~300KB | CTR streaming test (>256KB, video/mp4 MIME)   | `ffmpeg -f lavfi -i color=black:size=320x240:rate=25:duration=3 -f lavfi -i anullsrc=r=44100:cl=mono -shortest -c:v libx264 -c:a aac test-video.mp4` then pad to 300KB |
| `test-video-small.mp4` | ~100KB | GCM fallback test (<256KB)                    | Same ffmpeg with `duration=1`                                                                                                                                          |
| `test-audio.mp3`       | ~300KB | CTR streaming audio test (>256KB, audio/mpeg) | `ffmpeg -f lavfi -i anullsrc=r=44100:cl=mono -t 10 -c:a libmp3lame -b:a 128k test-audio.mp3`                                                                           |
| `test-document.pdf`    | ~5KB   | PDF preview test                              | Minimal PDF with "CipherBox Test" text page                                                                                                                            |

**If ffmpeg is not available:** Use the existing `createTestBinaryFile(300)` from `test-files.ts` with a media extension. The encryption will work, but the decrypted content won't be valid media -- acceptable for testing that the dialog opens and elements render, just don't assert on `canplay`/`loadedmetadata` events.

## Staging Baselines Architecture

### Journey Timing on Staging

The existing `journey-timing.spec.ts` captures three journeys: login-to-vault, upload-to-visible, share-to-accessible. Running against staging requires:

1. Use `playwright.load.config.ts` (points to `https://app-staging.cipherbox.cc`)
2. Or override: `BASE_URL=https://app-staging.cipherbox.cc pnpm exec playwright test tests/journey-timing.spec.ts`

Output: `JOURNEY_TIMING: {json}` lines in console, parsed post-run.

### Load Testing on Staging

The existing `load-test.spec.ts` already targets staging via `playwright.load.config.ts`:

```bash
cd tests/web-e2e
pnpm exec playwright test tests/load-test.spec.ts --config=playwright.load.config.ts
```

Env vars: `LOAD_TEST_CLIENTS=5` (default), `LOAD_TEST_ROUNDS` not used (hardcoded ~70 ops per client).

### BYO-IPFS Load Test Baselines

No separate BYO load test script exists yet. This needs a variant of the load test where test accounts are configured with BYO-IPFS settings. The BYO config is stored as an encrypted IPNS entry (see project decisions). Approach:

1. Create test accounts with BYO provider configured (via SDK or API)
2. Run same workload as regular load test
3. Compare API response times -- IPFS operations offloaded means lower API latency

**Important:** This requires an external IPFS provider endpoint accessible from staging. The Phase 21 BYO benchmark was previously deferred because "requires external IPFS provider infrastructure" (see STATE.md). This constraint still applies. Document what WOULD be tested and the setup required; actual execution depends on infrastructure availability.

### Faro Metrics Baselines

Grafana Faro is initialized via `VITE_FARO_URL` env var (absent in local dev = no-op). On staging, Faro sends browser telemetry (errors, logs, performance, traces) to a Grafana endpoint. Baselines involve:

1. Running journey-timing and load-test against staging
2. Verifying Faro traces appear in Grafana
3. Checking Prometheus `/metrics` endpoint on the API for server-side histograms
4. Documenting baseline values for future regression comparison

Access to Grafana dashboard and staging Prometheus is required for verification.

## Specs to Affected afterAll Hooks (deleteAccount wiring)

| Spec File                      | Current afterAll                                | Needs deleteAccount | Auth Pattern                             |
| ------------------------------ | ----------------------------------------------- | ------------------- | ---------------------------------------- |
| `full-workflow.spec.ts`        | `cleanupTestFiles(); context.close()`           | YES                 | Single wallet account, `page.evaluate()` |
| `sharing-workflow.spec.ts`     | `cleanupTestFiles(); closeWalletTestAccounts()` | YES                 | Multi-account (Alice/Bob/Charlie)        |
| `writable-shares.spec.ts`      | `cleanupTestFiles(); closeWalletTestAccounts()` | YES                 | Multi-account (Alice/Bob)                |
| `search-workflow.spec.ts`      | `cleanupTestFiles(); context.close()`           | YES                 | Single wallet account                    |
| `recycle-bin.spec.ts`          | `cleanupTestFiles(); context.close()`           | YES                 | Single wallet account                    |
| `mfa-flows.spec.ts`            | `primaryContext.close()`                        | YES                 | Single wallet account                    |
| `conflict-detection.spec.ts`   | `closeConflictDevice(); context.close()`        | YES                 | Single wallet + device B                 |
| `invite-link-workflow.spec.ts` | `cleanupTestFiles(); closeWalletTestAccounts()` | YES                 | Multi-account (Alice/Dave/Eve)           |
| `wallet-login.spec.ts`         | N/A (likely context.close)                      | YES                 | Single wallet account                    |
| `journey-timing.spec.ts`       | `cleanupTestFiles(); closeWalletTestAccounts()` | YES                 | Multi-account (Alice, Bob)               |
| `recovery.spec.ts`             | `deleteTestAccount(account, API_URL)`           | ALREADY DONE        | SDK-based (different pattern)            |
| `load-test.spec.ts`            | `deleteAccount(client)` for each client         | ALREADY DONE        | In-page evaluate pattern                 |

**For multi-account specs** (`closeWalletTestAccounts`): need to delete each account before closing contexts. The `page.evaluate()` pattern requires the page to still be navigable (not closed). So: delete accounts first, THEN close contexts.

## State of the Art

| Old Approach                      | Current Approach                           | When Changed                     | Impact                                   |
| --------------------------------- | ------------------------------------------ | -------------------------------- | ---------------------------------------- |
| No account cleanup                | `deleteAccount` in afterAll                | Phase 34                         | Prevents orphaned test accounts in DB    |
| Manual media feature verification | Automated Playwright E2E                   | Phase 34                         | Catches regressions in streaming/preview |
| No staging baselines with Faro    | Baseline capture with full instrumentation | Phase 34 (after Phase 30 deploy) | Enables regression tracking              |

## Validation Architecture

### Test Framework

| Property           | Value                                                                               |
| ------------------ | ----------------------------------------------------------------------------------- |
| Framework          | @playwright/test 1.57.0                                                             |
| Config file        | `tests/web-e2e/playwright.config.ts` (local), `playwright.load.config.ts` (staging) |
| Quick run command  | `cd tests/web-e2e && pnpm exec playwright test tests/<spec>.spec.ts`                |
| Full suite command | `cd tests/web-e2e && pnpm exec playwright test`                                     |

### Phase Requirements -> Test Map

No formal requirement IDs for this phase (test coverage and baseline capture). The success criteria map directly to test files:

| Success Criterion              | Test Type                  | Verification                                 |
| ------------------------------ | -------------------------- | -------------------------------------------- |
| AES-CTR streaming playback E2E | E2E (Playwright)           | `streaming-playback.spec.ts` runs green      |
| Batch download E2E             | E2E (Playwright)           | `batch-download.spec.ts` runs green          |
| Media preview E2E              | E2E (Playwright)           | `media-preview.spec.ts` runs green           |
| Shared deleteAccount teardown  | Code inspection + test run | All specs' afterAll hooks call deleteAccount |
| BYO-IPFS load baselines        | Manual staging run         | Baseline numbers documented                  |
| Staging metrics baselines      | Manual staging run         | Journey timing + load test results captured  |

### Sampling Rate

- **Per task commit:** `cd tests/web-e2e && pnpm exec playwright test tests/<new-spec>.spec.ts`
- **Per wave merge:** `cd tests/web-e2e && pnpm exec playwright test` (full suite)
- **Phase gate:** Full suite green + staging runs documented

### Wave 0 Gaps

- [ ] `tests/web-e2e/tests/streaming-playback.spec.ts` -- new file
- [ ] `tests/web-e2e/tests/media-preview.spec.ts` -- new file
- [ ] `tests/web-e2e/tests/batch-download.spec.ts` -- new file
- [ ] `tests/web-e2e/utils/cleanup-helpers.ts` -- shared deleteAccount helper
- [ ] `tests/web-e2e/fixtures/files/test-video.mp4` -- media fixture (~300KB)
- [ ] `tests/web-e2e/fixtures/files/test-video-small.mp4` -- small media fixture (<256KB)
- [ ] `tests/web-e2e/fixtures/files/test-audio.mp3` -- audio fixture (~300KB)
- [ ] `tests/web-e2e/fixtures/files/test-document.pdf` -- PDF fixture (~5KB)

## Environment Availability

| Dependency             | Required By                   | Available      | Version       | Fallback                                     |
| ---------------------- | ----------------------------- | -------------- | ------------- | -------------------------------------------- |
| Playwright             | All E2E tests                 | Y              | 1.57.0        | --                                           |
| Node.js                | Test runner                   | Y              | (host)        | --                                           |
| ffmpeg                 | Media fixture generation      | Check needed   | --            | Use binary stubs with media extensions       |
| Staging VPS            | Load/baseline tests           | Y              | 76.13.151.200 | --                                           |
| Grafana Faro endpoint  | Metrics baseline verification | Y (on staging) | --            | Document metrics without visual verification |
| External IPFS provider | BYO load baselines            | Uncertain      | --            | Document test plan; defer actual run         |

**Missing dependencies with no fallback:**

- None that block implementation. All new test specs run against local dev environment.

**Missing dependencies with fallback:**

- ffmpeg for media fixtures -- fallback is creating binary files with media extensions (tests verify dialog opens but skip codec-dependent assertions)
- External IPFS provider for BYO load test -- fallback is documenting the test plan and running when infrastructure available

## Open Questions

1. **BYO-IPFS Load Test Execution**
   - What we know: No external IPFS provider infrastructure is set up for staging. Phase 21 deferred BYO benchmarks for this reason.
   - What's unclear: Whether an external IPFS provider (Pinata, Filebase, etc.) is available or budgeted for testing.
   - Recommendation: Create the test harness/scripts ready to run, document what provider setup is needed, flag as manual execution when provider is available. Do not block phase completion on this.

2. **Media Fixtures: ffmpeg vs Binary Stubs**
   - What we know: Real media files work best for codec/playback assertions. Binary stubs with media extensions work for dialog/element rendering assertions.
   - What's unclear: Whether ffmpeg is installed on the dev machine.
   - Recommendation: Check `command -v ffmpeg` at plan execution time. If available, generate real fixtures. If not, use binary stubs and limit assertions to modal rendering (not playback events).

3. **Staging Access for Baseline Capture**
   - What we know: Staging is at `app-staging.cipherbox.cc` / `api-staging.cipherbox.cc`. SSH access to VPS at 76.13.151.200.
   - What's unclear: Whether latest code (through Phase 33) is deployed to staging.
   - Recommendation: Verify staging deployment status before running baselines. If not up to date, deploy first.

## Sources

### Primary (HIGH confidence)

- Direct codebase inspection of all 12 existing E2E spec files in `tests/web-e2e/tests/`
- Direct inspection of page objects, utils, and fixture directories
- Direct inspection of production components: `VideoPlayerDialog.tsx`, `AudioPlayerDialog.tsx`, `PdfPreviewDialog.tsx`, `decrypt-sw.ts`, `streaming-crypto.service.ts`, `useStreamingPreview.ts`
- `playwright.config.ts` and `playwright.load.config.ts` configuration analysis
- `load-test.spec.ts` `deleteAccount()` pattern (lines 169-204)
- `useFileBrowserActions.ts` `handleBatchDownload` implementation (lines 430-446)

### Secondary (MEDIUM confidence)

- Playwright 1.57.0 documentation for Service Worker testing capabilities (from training data, version verified via installed package)

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - all libraries already installed, patterns established across 12 specs
- Architecture: HIGH - patterns directly observed in existing codebase, no new patterns needed
- Pitfalls: HIGH - pitfalls identified from actual code inspection (CTR threshold logic, batch download non-zip behavior, SW registration lifecycle)

**Research date:** 2026-03-29
**Valid until:** 2026-04-28 (stable -- testing infrastructure, not fast-moving dependencies)
