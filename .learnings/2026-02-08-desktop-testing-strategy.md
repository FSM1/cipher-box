# Desktop Client Testing Strategy

**Date:** 2026-02-08

## Original Prompt

> Phase 9 UAT revealed that every test required manual human interaction because Web3Auth login cannot be automated. This makes CI/CD and agent-driven testing impossible.

## What I Learned

### The Web3Auth Testing Wall

- Web3Auth login requires a real browser interaction (Google OAuth, email OTP, etc.). There is no headless/programmatic bypass in the SDK.
- Every UAT test required a human to: click Login in tray, complete Web3Auth flow, wait for FUSE mount, then test the actual feature.
- This made iterative debugging painfully slow — each fix required a full rebuild + manual login cycle.
- Agent-assisted development (Claude) could diagnose issues from logs and write fixes, but could never verify them independently.

### Proposed Solution: Auth Bypass for Development

A `--dev-key <hex-private-key>` CLI argument that bypasses Web3Auth entirely:

1. Accept a secp256k1 private key via CLI arg or environment variable (`CIPHERBOX_DEV_KEY`)
2. Derive the public key from it
3. Call the API's `/auth/login` endpoint directly (the API already accepts `{ publicKey, loginType: "desktop" }`)
4. Store the resulting JWT and proceed to FUSE mount

This enables:

- **Automated testing:** Playwright/script can launch app with `--dev-key`, test FUSE operations, quit
- **Agent-driven UAT:** Claude can launch the app, verify FUSE behavior via `ls`/`cat`/`echo`, and iterate without human intervention
- **CI integration:** Spin up API + app with test key, run filesystem operation tests
- **Faster debugging:** Skip the 15-second Web3Auth flow on every iteration

### Implementation Notes

- Gate behind `#[cfg(debug_assertions)]` or a `dev` feature flag — never ship in release builds
- The test account's private key can live in `tests/e2e/.env` alongside existing test credentials
- Key derivation: `secp256k1::SecretKey::from_slice(&hex::decode(key))` -> compressed public key -> `/auth/login`
- After auth, the flow joins the normal path: fetch vault metadata, mount FUSE, start sync

### What Else Would Help

- **FUSE unit tests:** Test the `CipherBoxFS` struct directly without mounting. Mock the API client, call `lookup()`, `readdir()`, `read()` etc. as method calls. This tests all the NFS-sensitive logic (inode stability, cache behavior, platform file filtering) without needing a real mount.
- **Integration test script:** A shell script that exercises FUSE operations after mount: `ls`, `cat`, `echo >`, `mkdir`, `mv`, `rm`, and verifies results. Combined with `--dev-key`, this gives end-to-end coverage.
- **Snapshot testing for inode table:** Serialize the inode table state after `populate_folder()`, compare against known-good snapshots. Catches inode stability regressions.

### Testing Priorities for Linux/Windows Ports

1. **Start with the auth bypass** — get FUSE mounting testable without UI interaction
2. **Port the FUSE unit tests first** — the inode table and cache logic is shared
3. **Platform-specific tests:** Linux FUSE has different behavior (multithreaded, no NFS translation). Windows WinFSP has its own quirks. Each needs platform-specific test coverage.
4. **The channel-based prefetch pattern** should have its own test — verify that content arrives via channel and cache is populated correctly

## Key Files

- `apps/desktop/src-tauri/src/main.rs` — CLI argument parsing (add `--dev-key` here)
- `apps/desktop/src-tauri/src/commands.rs` — `handle_auth_complete` (the flow to join after bypass auth)
- `apps/desktop/src-tauri/src/api/auth.rs` — API auth calls
- `tests/e2e/.env` — Test credentials
