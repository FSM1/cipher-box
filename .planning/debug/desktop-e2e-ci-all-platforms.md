---
status: fixing
trigger: 'Desktop E2E tests fail on all three platforms in CI'
created: 2026-03-01T04:00:00Z
updated: 2026-03-01T07:00:00Z
branch: fix/desktop-e2e-ci-round3
---

## Current Focus

hypothesis: WinFsp set_file_size ignores set_allocation_size=true truncation (overwrite broken)
test: Handle set_allocation_size=true with new_size=0 as truncation + clear CID
expecting: PowerShell Set-Content correctly overwrites file content on Windows
next_action: CI round 14 running (commit 432334b06)
ci_run: pending (round 14)

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

### Round 8 Results — CI run 22537324561 (commit c76d97b15)

winfsp_init fix confirmed the root cause!

- ✅ macOS: ALL TESTS PASSED!
- ✅ Linux: ALL TESTS PASSED!
- ❌ Windows: Clear error now visible in binary log:

  ```text
  Filesystem mount failed: WinFsp initialization failed (is WinFsp installed?): WIN32(1285)
  ```

  WIN32(1285) = ERROR_DELAY_LOAD_FAILED — the WinFsp DLL can't be found at runtime.

  Root cause: `winfsp` crate dependency has no `features = ["system"]`. Without
  the `system` feature, `load_system_winfsp()` (which reads the registry to find
  the DLL path) is disabled. Only `load_local_winfsp()` is tried, which looks for
  `winfsp-x64.dll` in PATH/current dir — and the WinFsp bin dir is not in PATH.

### Round 9 Results — CI run 22537575319 (commit 03039f2c6)

WinFsp system feature fix WORKED! Mount succeeds on Windows!

- ✅ macOS: ALL TESTS PASSED!
- ✅ Linux: ALL TESTS PASSED!
- ✅ Windows: WinFsp initialized, mounted, filesystem working!
  - PASS: Mount detected
  - PASS: Create and read text file
  - PASS: Create directory
  - PASS: Write file in subdirectory
  - **FAIL**: Overwrite file (got: 'Hello from CIModified content' — no truncation)
  - PASS: API Test 1-3 ALL PASSED!
  - Total: 1 failure

**Root cause of overwrite failure**: Missing `overwrite()` callback in WinFsp operations.
When Windows calls `CreateFile` with `CREATE_ALWAYS` (PowerShell `Set-Content`), WinFsp
calls the `overwrite()` method which should truncate the file. Without it, the default
returns `STATUS_INVALID_DEVICE_REQUEST` and the file is opened via `open()` instead,
preserving existing content.

### Round 10 Results — CI run 22537802342 (commit 0eb13b9a2)

Added `overwrite()` callback in WinFsp operations.

- ✅ macOS: ALL TESTS PASSED!
- ✅ Linux: ALL TESTS PASSED!
- ❌ Windows: Overwrite test still FAILS (got: 'Hello from CIModified content')
  - `overwrite()` callback never called — confirmed by absence of log messages
  - WinFsp dispatches overwrite differently than expected

### Round 11 — Skipped (compile error caught before CI)

Added `write_to_end_of_file` fix but introduced borrow checker error E0502.

### Round 12 Results — CI run 22543415514 (commit f88b80191)

Fixed `write_to_end_of_file` handling (read file_size before mutable borrow).

- ❌ Build FAILED: `error[E0502]: cannot borrow fs as immutable because it is also borrowed as mutable`
  - Mutable borrow of `fs.open_files.get_mut(&fh)` at line 1135 conflicts with
    immutable borrow of `fs.inodes.get(ino)` at line 1143
  - Fix: read `current_file_size` from `fs.inodes` BEFORE getting mutable handle

### Round 13 Results — CI run 22543670556 (commit 1b9d3ca4b)

Fixed borrow checker error. Added comprehensive diagnostic logging to all WinFsp
callbacks: open(), create(), overwrite(), write(), set_file_size(), cleanup(), close().

- ✅ macOS: ALL TESTS PASSED!
- ✅ Linux: ALL TESTS PASSED!
- ❌ Windows: Overwrite test still FAILS — but now we have FULL diagnostic logs!

**SMOKING GUN from diagnostic logs (Test 4: Overwrite file)**:

```text
open() path=\e2e-test.txt create_options=0x01400060 granted_access=0x00120196  (fh=30)
set_file_size() ino=2 fh=30 new_size=0 set_allocation_size=true              ← IGNORED!
cleanup() ino=2 fh=30 flags=0x000000F2
close() ino=2 fh=30
open() path=\e2e-test.txt create_options=0x03400060 granted_access=0x0012019F  (fh=38)
write() ino=2 fh=38 len=16 offset=13 write_to_end_of_file=false              ← offset=13 (old size!)
cleanup() ino=2 fh=38 flags=0x000000F2
close() ino=2 fh=38
```

**Root cause**: `set_file_size()` had `if !set_allocation_size { ... }` which IGNORED
calls with `set_allocation_size=true`. WinFsp's overwrite mechanism sends
`set_file_size(new_size=0, set_allocation_size=true)` to truncate files. The inode size
stayed at 13, so the next write went to offset 13 instead of 0.

### Round 14 — CI run pending (commit 432334b06)

Applied fixes:

- Handle `set_allocation_size=true` with `new_size=0` as truncation signal
- Clear CID when truncating to 0 (prevents stale IPFS content re-download on next open)

### Root Cause 3 (fixed round 8): WinFsp init kills process silently

`winfsp::winfsp_init_or_die()` calls `std::process::exit()` when the WinFsp DLL
can't be found at runtime. Unlike `panic!()`, `process::exit()` skips all
destructors, logging, and error handlers. The process just vanishes.

Fix: Use `winfsp::winfsp_init()` which returns `Result`, and propagate the error
properly so it appears in both Rust logs and JS error reporting.

### Root Cause 4 (fixed round 9): WinFsp DLL not found (missing "system" feature)

The `winfsp` crate needs `features = ["system"]` to enable registry-based DLL lookup.
Without it, only local PATH lookup is tried — and CI doesn't have WinFsp's bin dir in PATH.

Fix: Add `features = ["system"]` to winfsp dependency in Cargo.toml.

### Root Cause 5 (fixing round 14): set_file_size ignores allocation truncation

WinFsp's overwrite mechanism (PowerShell `Set-Content`) works in TWO phases:

1. Open file → `set_file_size(new_size=0, set_allocation_size=true)` → close
2. Open file → `write(offset=0, data)` → close

Our `set_file_size()` had `if !set_allocation_size { ... }` which IGNORED the
truncation in phase 1. The inode size stayed at the old value, so phase 2's write
went to the old offset instead of 0, producing append behavior.

Additionally, clearing the CID on truncate-to-0 prevents subsequent `open()` from
re-downloading stale IPFS content into the new temp file.

Fix: `let should_truncate = !set_allocation_size || (set_allocation_size && new_size == 0)`
plus `cid.clear()` when new_size == 0.

## Fixes Applied (all commits on fix/desktop-e2e-ci-round3)

| #   | Fix                                           | Commit    | Status          |
| --- | --------------------------------------------- | --------- | --------------- |
| 1   | Move Node.js/pnpm setup BEFORE cargo build    | 10deba393 | ✅              |
| 2   | Add "Build desktop frontend" step             | 10deba393 | ✅              |
| 3   | Add install_name_tool rpath for macOS         | 10deba393 | ✅              |
| 4   | Switch Windows Kubo to bash+curl --retry      | 10deba393 | ✅              |
| 5   | Add WEBKIT_DISABLE_DMABUF_RENDERER=1 (Linux)  | 10deba393 | ✅              |
| 6   | Capture binary logs on failure                | 10deba393 | ✅              |
| 7   | Add on_page_load webview callback             | 5d3ce6e26 | ✅ (diagnostic) |
| 8   | Add logging to get_dev_key                    | 5d3ce6e26 | ✅ (diagnostic) |
| 9   | Fix Windows Redis PATH refresh                | 5d3ce6e26 | ✅              |
| 10  | Start Vite preview server on :1420            | a236637e7 | ✅              |
| 11  | Switch Windows Redis to Memurai               | 928918a47 | ✅              |
| 12  | Add localhost:1420 to CORS_ALLOWED_ORIGINS    | 1271df5ff | ✅              |
| 13  | Add log_js_error Tauri command                | 1271df5ff | ✅              |
| 14  | Add step logging in handleDevKeyAuth          | 1271df5ff | ✅              |
| 15  | Fix TEST_EMAIL to <dev-key@cipherbox.local>   | 893ab7d78 | ✅              |
| 16  | Fix IPNS resolve URL in round-trip tests      | 8c9a83464 | ✅              |
| 17  | Switch Windows API startup to bash+curl       | 8c9a83464 | ✅              |
| 18  | Replace winfsp_init_or_die with winfsp_init   | c76d97b15 | ✅              |
| 19  | Windows test step: bash + log capture         | c76d97b15 | ✅              |
| 20  | WinFsp mount step-by-step logging             | c76d97b15 | ✅              |
| 21  | Enable winfsp "system" feature (registry DLL) | 03039f2c6 | ✅              |
| 22  | Add WinFsp bin dir to PATH in CI              | 03039f2c6 | ✅              |
| 23  | Implement WinFsp overwrite() callback         | 0eb13b9a2 | ✅ (not called) |
| 24  | Fix write_to_end_of_file offset handling      | f88b80191 | ✅              |
| 25  | Fix borrow checker in write()                 | 1b9d3ca4b | ✅              |
| 26  | Add comprehensive diagnostic logging          | 1b9d3ca4b | ✅ (diagnostic) |
| 27  | Handle set_allocation_size=true truncation    | 432334b06 | 🔄 testing      |
| 28  | Clear CID on truncate-to-0                    | 432334b06 | 🔄 testing      |

## Open Questions

1. ~~Is the WinFsp DLL discoverable at runtime on the CI runner?~~ YES — fixed with "system" feature
2. ~~If winfsp_init() fails, what's the actual error?~~ ERROR_DELAY_LOAD_FAILED (1285) — DLL not found
3. Can we remove diagnostic logging after CI passes?
4. Should overwrite() callback be removed since WinFsp never calls it? (Keep for now as documentation)
