---
status: fixing
trigger: 'Desktop E2E tests fail on all three platforms in CI'
created: 2026-03-01T04:00:00Z
updated: 2026-03-01T05:05:00Z
branch: fix/desktop-e2e-ci-round3
---

## Current Focus

hypothesis: Debug binary uses devUrl (<http://localhost:1420>) not embedded frontendDist
test: Start `vite preview --port 1420` before binary launch on all platforms
expecting: Webview loads real frontend, JS auth flow runs, mount appears
next_action: Analyze CI run results
ci_run: pending (just triggered round 4)

## Symptoms

expected: All desktop E2E tests pass on macOS, Linux, and Windows in CI
actual: All three platforms fail — binary starts, webview created, but mount never appears
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

### Round 4 — CI run pending (commit a236637e7)

Applied fix: Start `vite preview --port 1420` before binary launch on all platforms

- Uses pre-built dist from earlier Vite build step
- Serves on port 1420 (what debug binary's devUrl expects)
- Also fixed Windows Redis PATH refresh

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
  evidence: Not the cause (yet). Page loads `http://localhost:1420/` which returns nothing —
  JS never even has a chance to fail. If the dev server fix works but auth fails, WASM may
  become relevant.

## Root Cause (confirmed)

**Tauri debug builds use `devUrl` (<http://localhost:1420>), not embedded `frontendDist`.**

In `tauri.conf.json`:

```json
{
  "devUrl": "http://localhost:1420",
  "frontendDist": "../dist"
}
```

When built with `cargo build` (debug profile), Tauri generates code that makes the webview
load from `devUrl`. Only release builds or `tauri build` embed assets from `frontendDist`.

In CI, no Vite dev server was running on port 1420 → webview loaded empty page → no JS →
no auth → no mount.

**Fix:** Start `vite preview --port 1420` before the binary. This serves the pre-built
frontend (same bundle that vite build produced earlier) on the port the debug binary expects.

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
| 10  | Start Vite preview server on :1420           | a236637e7 | 🔄 pending CI   |

## Open Questions

1. Will `vite preview --port 1420` correctly serve the pre-built frontend?
2. Will the WASM modules in auth.ts load correctly in the webview?
3. Will the test-login API call succeed from the webview?
4. Windows: will the Redis PATH fix work with the refreshenv approach?
