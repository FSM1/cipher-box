---
status: fixing
trigger: 'Desktop E2E tests fail on all three platforms in CI'
created: 2026-03-01T04:00:00Z
updated: 2026-03-01T05:30:00Z
branch: fix/desktop-e2e-ci-round3
---

## Current Focus

hypothesis: winfsp_init_or_die() calls process::exit() killing the binary silently on Windows
test: Replace with winfsp_init() + proper error handling, capture binary logs on Windows
expecting: Either WinFsp inits successfully and mount works, or we get a clear error message
next_action: Push round 8 fixes, trigger CI
ci_run: pending (round 8)

## Symptoms

expected: All desktop E2E tests pass on macOS, Linux, and Windows in CI
actual: All three platforms fail — JS runs, get_dev_key succeeds, but auth flow fails silently
reproduction: workflow_dispatch on fix/desktop-e2e-ci-round3

## Timeline

### Round 1 — CI run 22535471201 (main branch)

- Windows: Kubo download fails (PowerShell Invoke-WebRequest IOException)
- macOS: dyld error — Library not loaded: @rpath/libfuse-t.dylib
- Linux: Mount not detected after 90s

### Round 2 — CI run 22536010865 (fix/desktop-e2e-ci-round3, commit 10deba393)

Applied fixes: frontend build before cargo, rpath fix, bash+curl for Kubo, WEBKIT_DISABLE_DMABUF_RENDERER

- ✅ macOS: rpath FIXED, binary starts without crash
- ✅ Kubo download FIXED on all platforms
- ❌ macOS+Linux: Binary starts, webview created, but mount never appears (no Rust log after setup)
- ❌ Windows: redis-server not found after choco install (PATH not refreshed)

### Round 3 — CI run 22536256440 (commit 5d3ce6e26)

Applied fixes: diagnostic logging (on_page_load, get_dev_key logging, RUST_LOG=debug, pre-flight checks, Redis PATH fix)

- 🔍 **SMOKING GUN FOUND**: Webview page load logged `url=http://localhost:1420/`
  - Debug builds use `devUrl` not `frontendDist`!
  - No Vite dev server running → empty page → JS never runs → no auth → no mount
- `get_dev_key` never called (confirms JS not executing)
- Pre-flight: API health check passed

### Round 4 — CI run 22536393479 (commits a236637e7, 928918a47)

Applied fixes: Vite preview server on :1420, Memurai for Windows Redis

- ✅ macOS: Page loads! JS executes! `get_dev_key` called and returned `has_key=true`!
- ✅ Linux: Same — page loaded, JS executed, `get_dev_key` returned `has_key=true`
- ❌ macOS+Linux: After `get_dev_key` returns, NO more Rust logs for 90s → mount timeout
  - `handle_test_login_complete` never called
  - JS enters `handleDevKeyAuth()` → `fetch(localhost:3000/auth/test-login)` → **silently fails**
  - Error caught by `catch(err)` → logged to `console.error` → INVISIBLE (no way to see webview console)
- ❌ Windows: Memurai fix not tested yet (pushed after round 4 triggered)

**Root cause of round 4 failure**: CORS! The API's `CORS_ALLOWED_ORIGINS` is `http://localhost:5173`.
The webview loads from `http://localhost:1420`. The cross-origin fetch to `http://localhost:3000`
is blocked because the API doesn't include `:1420` in its allowed origins.

### Round 5 — CI run pending

Applied fixes:

- Add `http://localhost:1420` to `CORS_ALLOWED_ORIGINS` (API .env, macOS/Linux env, Windows env)
- Add `log_js_error` Tauri command so JS errors are visible in Rust logs
- Add step-by-step logging inside `handleDevKeyAuth()` (logStep calls)
- Add error reporting in catch handler (calls `log_js_error` instead of just `console.error`)

## Eliminated

- hypothesis: xvfb-action splitting commands
  evidence: Fixed in earlier commits (dbc4e3d44), replaced with manual Xvfb

- hypothesis: Missing rpath for FUSE-T dylib (macOS)
  evidence: FIXED. install_name_tool -add_rpath /usr/local/lib works. CI logs show LC_RPATH.

- hypothesis: PowerShell Kubo download unreliable (Windows)
  evidence: FIXED. bash+curl with --retry works reliably.

- hypothesis: Missing frontend build
  evidence: PARTIALLY relevant. Frontend IS built, but debug binary doesn't embed it.
  The real issue is that debug builds use devUrl not frontendDist.

- hypothesis: WebKitGTK DMA-BUF renderer (Linux)
  evidence: Not the cause. WEBKIT_DISABLE_DMABUF_RENDERER=1 added but mount still failed.

- hypothesis: WASM import failure in auth.ts
  evidence: Not the cause (yet). JS loads and get_dev_key runs. handleDevKeyAuth starts
  but fetch fails — likely CORS, not WASM.

- hypothesis: Debug binary uses devUrl not frontendDist
  evidence: CONFIRMED AND FIXED in round 4 with vite preview on :1420. JS now runs.

## Root Causes (layered)

### Root Cause 1 (fixed round 4): Debug builds use devUrl

**Tauri debug builds use `devUrl` (<http://localhost:1420>), not embedded `frontendDist`.**

Fix: Start `vite preview --port 1420` before the binary.

### Root Cause 2 (fixing round 5): CORS blocks auth flow

The webview's origin is `http://localhost:1420`. The API's `CORS_ALLOWED_ORIGINS` only includes
`http://localhost:5173`. The `fetch()` to `http://localhost:3000/auth/test-login` is a cross-origin
request that gets blocked by CORS policy. The error is caught silently by the JS try-catch.

Fix: Add `http://localhost:1420` to `CORS_ALLOWED_ORIGINS` in all 3 places in the CI workflow.

### Round 5 Results — CI run 22536602620 (commit 1271df5ff)

CORS fix WORKED! Auth flow completes on macOS AND Linux!

- ✅ macOS: JS auth flow logged all steps — fetch status=200, handle_test_login_complete done
- ✅ macOS: FUSE mount detected! All 9 FUSE I/O tests PASSED!
- ✅ Linux: Same — mount detected, all 9 FUSE I/O tests PASSED!
- ❌ macOS+Linux: API round-trip Test 2 FAIL — "Vault has no rootIpnsName after 60s polling"
  - Root cause: test-round-trip.sh creates a NEW random user email, not <dev-key@cipherbox.local>
  - The FUSE mount belongs to <dev-key@cipherbox.local>, but the test checks a different user's vault
  - Fix: change TEST_EMAIL to <dev-key@cipherbox.local>
- ❌ Windows: still in progress (cargo build is slow on Windows runners)

### Round 6 Results — CI run 22536745876 (commit 893ab7d78)

Test email fix worked — Test 2 (vault rootIpnsName) now passes!

- ✅ macOS: FUSE 9/9 PASSED, API Test 1+2 PASSED
- ✅ Linux: FUSE 9/9 PASSED, API Test 1+2 PASSED
- ❌ macOS+Linux: API Test 3 FAIL — IPNS resolve URL pattern wrong
  - Test calls `GET /ipns/$ROOT_IPNS/resolve` but API expects `GET /ipns/resolve?ipnsName=$ROOT_IPNS`
- ❌ Windows: API health check timeout (PowerShell Invoke-WebRequest fails)

### Round 7 Results — CI run 22536972742 (commit 8c9a83464)

IPNS resolve fix + Windows API bash+curl worked!

- ✅ macOS: ALL TESTS PASSED! FUSE 9/9, API Tests 1-3 ALL PASSED!
- ✅ Linux: ALL TESTS PASSED! FUSE 9/9, API Tests 1-3 ALL PASSED!
- ❌ Windows: Auth flow completes perfectly (all STEP logs show success)
  - Binary logs: vault init OK, root folder pre-populated OK
  - Then SILENT DEATH — no more Rust logs after "Root folder pre-populated successfully"
  - "WinFsp filesystem starting at" never logged
  - Mount not detected after 90s

**Root cause of round 7 Windows failure**: `winfsp::winfsp_init_or_die()` calls
`std::process::exit()` on failure (not panic!). This kills the entire process
silently with no error log. The WinFsp DLL likely can't be loaded at runtime
despite the MSI being installed.

Additionally, the Windows test step used PowerShell `Start-Process -NoNewWindow`
which doesn't redirect binary output to a file. Binary error messages were lost.

### Round 8 — CI run pending

Applied fixes:

- Replace `winfsp_init_or_die()` with `winfsp_init()` + proper error handling and logging
- Add step-by-step logging around WinFsp host creation, mount, and dispatcher start
- Switch Windows test step to bash with log file capture (like macOS/Linux)
- Always dump binary log on Windows (even on success) for diagnostics

### Root Cause 3 (fixing round 8): WinFsp init kills process silently

`winfsp::winfsp_init_or_die()` calls `std::process::exit()` when the WinFsp DLL
can't be found at runtime. Unlike `panic!()`, `process::exit()` skips all
destructors, logging, and error handlers. The process just vanishes.

Fix: Use `winfsp::winfsp_init()` which returns `Result`, and propagate the error
properly so it appears in both Rust logs and JS error reporting.

## Fixes Applied (all commits on fix/desktop-e2e-ci-round3)

| #   | Fix                                          | Commit    | Status          |
| --- | -------------------------------------------- | --------- | --------------- |
| 1   | Move Node.js/pnpm setup BEFORE cargo build   | 10deba393 | ✅              |
| 2   | Add "Build desktop frontend" step            | 10deba393 | ✅              |
| 3   | Add install_name_tool rpath for macOS        | 10deba393 | ✅              |
| 4   | Switch Windows Kubo to bash+curl --retry     | 10deba393 | ✅              |
| 5   | Add WEBKIT_DISABLE_DMABUF_RENDERER=1 (Linux) | 10deba393 | ✅              |
| 6   | Capture binary logs on failure               | 10deba393 | ✅              |
| 7   | Add on_page_load webview callback            | 5d3ce6e26 | ✅ (diagnostic) |
| 8   | Add logging to get_dev_key                   | 5d3ce6e26 | ✅ (diagnostic) |
| 9   | Fix Windows Redis PATH refresh               | 5d3ce6e26 | ✅              |
| 10  | Start Vite preview server on :1420           | a236637e7 | ✅              |
| 11  | Switch Windows Redis to Memurai              | 928918a47 | ✅              |
| 12  | Add localhost:1420 to CORS_ALLOWED_ORIGINS   | 1271df5ff | ✅              |
| 13  | Add log_js_error Tauri command               | 1271df5ff | ✅              |
| 14  | Add step logging in handleDevKeyAuth         | 1271df5ff | ✅              |
| 15  | Fix TEST_EMAIL to <dev-key@cipherbox.local>  | 893ab7d78 | ✅              |
| 16  | Fix IPNS resolve URL in round-trip tests     | 8c9a83464 | ✅              |
| 17  | Switch Windows API startup to bash+curl      | 8c9a83464 | ✅              |
| 18  | Replace winfsp_init_or_die with winfsp_init  | pending   | 🔄 pending      |
| 19  | Windows test step: bash + log capture        | pending   | 🔄 pending      |
| 20  | WinFsp mount step-by-step logging            | pending   | 🔄 pending      |

## Open Questions

1. Is the WinFsp DLL discoverable at runtime on the CI runner? (registry key present?)
2. If winfsp_init() fails, what's the actual error? (DLL not found? Wrong arch?)
3. Can we remove diagnostic logging after CI passes?
