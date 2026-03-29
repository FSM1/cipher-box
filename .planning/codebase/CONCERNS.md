# Codebase Concerns

**Analysis Date:** 2026-03-29

## Tech Debt

**Orphaned IPNS records on file/folder deletion:**

- Issue: When files or folders are deleted, their IPNS records and TEE republish enrollments are handled by `fireAndForgetUnenroll()` in `packages/sdk/src/client.ts`. The web app services correctly delegate to the SDK. However, SDK-based unenrollment is fire-and-forget with no persistence — if the browser tab closes before the API call completes, unenrollments are silently dropped.
- Files: `packages/sdk/src/client.ts:150-163`, `apps/web/src/services/delete.service.ts:23`, `apps/web/src/services/folder.service.ts:457`
- Impact: Orphaned IPNS records accumulate in the TEE republish schedule. Each orphan wastes TEE compute and delegated routing bandwidth every 6 hours. Capacity warnings trigger at 1000+ records.
- Fix approach: Persist a local unenrollment queue to IndexedDB. Flush on next session start before loading folders.

**Desktop device approval polling not implemented:**

- Issue: Phase 11.2 TODO comments indicate the desktop app lacks approval notification polling. When another device needs MFA approval, the desktop user has no notification.
- Files: `apps/desktop/src/main.ts:32`, `apps/desktop/src/auth.ts:680`
- Impact: Desktop users must use the web app to approve new devices. Reduces desktop app self-sufficiency.
- Fix approach: Add a background polling interval (similar to web's `useDeviceApproval`) that checks for pending approvals and surfaces native OS notifications via Tauri's notification API.

**FUSE mkdir publish retry not implemented:**

- Issue: The FUSE write_ops for directory creation has a TODO noting that full re-fetch+merge+retry is needed for parent directory IPNS publishing after mkdir.
- Files: `crates/fuse/src/write_ops.rs:584`, `crates/fuse/src/platform/windows/write_ops.rs:194`
- Impact: Concurrent mkdir operations from different clients could produce conflicting IPNS metadata. Current behavior silently drops one operation.
- Fix approach: Implement retry with CAS-style re-fetch, merge children, re-publish pattern (same as web client's folder mutation flow).

**Residual `console.time` calls in Web3Auth hooks:**

- Issue: 12 `console.time`/`console.timeEnd` calls remain in `apps/web/src/lib/web3auth/hooks.ts` (lines 82–194) outside any `import.meta.env.DEV` guard. Phase 28 replaced `console.log/warn/error` with the structured logger but missed these timing calls.
- Files: `apps/web/src/lib/web3auth/hooks.ts:82`, `:84`, `:92`, `:162`, `:165`, `:168`, `:176`, `:179`, `:182`, `:188`, `:191`, `:194`
- Impact: Console timing output appears in production builds. Minor noise; no security risk.
- Fix approach: Wrap in `if (import.meta.env.DEV)` guards or replace with `logger.debug` calls with manual timestamps.

**`any` type usage in Web3Auth integration:**

- Issue: Two `any` casts remain in the Web3Auth login function due to poor SDK TypeScript types.
- Files: `apps/web/src/lib/web3auth/hooks.ts:147` (`coreKit: any`), `:153` (`loginParams: any`)
- Impact: Type safety gap around the authentication flow. Could mask breaking SDK changes.
- Fix approach: Create typed wrappers for Web3Auth SDK interactions using `unknown` + type guards.

## Known Bugs

**No active known bugs identified in the current codebase.**

Previous known bugs (upload modal stuck, auth refresh race) were fixed in PRs #56 and #58. The IPNS resolve 502 issue (delegated-ipfs.dev unreliability) is mitigated by DB-cached CID fallback and retry logic in `apps/api/src/ipns/delegated-routing.client.ts`.

## Security Considerations

**Memory zeroing is best-effort in JavaScript:**

- Risk: `clearBytes()` / `.fill(0)` cannot guarantee sensitive key material is erased from V8 heap, JIT-compiled code, or GC intermediaries.
- Files: `packages/crypto/src/utils/memory.ts`, `apps/web/src/stores/vault.store.ts`, `apps/web/src/stores/auth.store.ts`, `apps/web/src/stores/folder.store.ts`
- Current mitigation: The codebase consistently uses `.fill(0)` on key buffers during logout and store cleanup. The Rust side uses `zeroize` crate.
- Recommendations: Inherent JavaScript limitation. Acceptable for browser context; desktop Rust code uses proper zeroization.

**Web3Auth localStorage usage:**

- Risk: Web3Auth MPC Core Kit stores its share factor in `localStorage`, accessible to XSS.
- Files: `apps/web/src/lib/web3auth/core-kit.ts` (`storage: window.localStorage`)
- Current mitigation: CipherBox's own keys are never stored in localStorage. Web3Auth factor is one share of a 2-of-3 TSS scheme. MFA enrollment adds device approval factor.
- Recommendations: CSP headers and XSS prevention remain critical.

**IPFS node credentials and access control:**

- Risk: Kubo API endpoint has no built-in authentication. Anyone with network access to port 5001 can pin/unpin.
- Files: `apps/api/src/ipfs/providers/local.provider.ts`
- Current mitigation: Kubo API bound to localhost in dev. Docker network isolation in staging.
- Recommendations: Use reverse proxy with auth or Kubo's API access controls before production deployment.

**Test login endpoint available in staging:**

- Risk: `POST /auth/test-login` bypasses all real authentication. Available when `TEST_LOGIN_SECRET` is set and `NODE_ENV !== 'production'`.
- Files: `apps/api/src/auth/` (test-auth service)
- Current mitigation: Guarded by `NODE_ENV` check and requires knowing the secret.
- Recommendations: Ensure `TEST_LOGIN_SECRET` is never set when a production environment is deployed. Add monitoring alert for staging usage.

## Performance Bottlenecks

**Full file content buffering for AES-GCM encryption:**

- Problem: Files encrypted with GCM mode are fully loaded into memory. The 100 MB file size limit means up to 100 MB memory per concurrent upload.
- Files: `packages/crypto/src/aes/encrypt.ts`
- Cause: AES-256-GCM requires full content for authentication tag computation.
- Improvement path: AES-256-CTR streaming encryption already exists (`packages/crypto/src/aes/encrypt-ctr.ts`, `packages/crypto/src/aes/decrypt-ctr.ts`) and is used for media streaming. Extend CTR usage to all uploads for reduced memory pressure.

**IPNS polling for sync (30-second interval):**

- Problem: Sync latency is at least 30 seconds. No push notification infrastructure exists.
- Files: `apps/web/src/hooks/useSyncPolling.ts`
- Cause: IPNS is pull-based. Adding WebSocket push would require backend infrastructure.
- Improvement path: WebSocket notifications for immediate sync triggers, falling back to polling.

**No pagination for large folders:**

- Problem: Folder metadata contains all children inline. A folder with 1000 files loads all entries into memory.
- Files: `apps/web/src/components/file-browser/FileList.tsx`, `apps/web/src/services/folder.service.ts`
- Cause: IPNS-based metadata is a single encrypted blob per folder.
- Improvement path: Virtual scrolling in the UI. The 1000-file limit per PRD mitigates the data loading issue.

## Fragile Areas

**FUSE-T SMB backend on macOS:**

- Files: `crates/fuse/src/lib.rs` (766 lines), `crates/fuse/src/write_ops.rs` (976 lines), `crates/fuse/src/read_ops.rs` (928 lines), `apps/desktop/src-tauri/vendor/fuser/src/channel.rs`
- Why fragile: FUSE-T is a userspace NFS/SMB translation layer, not kernel FUSE. Numerous workarounds for macOS-specific issues (SMB opendir requires non-zero fh, rename truncates filenames by 8 bytes, UID mismatch under SMB proxy). Each macOS update could introduce new kernel-side behavior changes.
- Safe modification: Always test with Finder, Terminal `ls`/`mv`/`cp`, and multi-file operations.
- Test coverage: Desktop E2E shell scripts exercise basic operations. Rust inline tests cover inode table and cache. No unit tests for filesystem callback implementations.

**Windows FUSE implementation (WinFSP):**

- Files: `crates/fuse/src/platform/windows/write_ops.rs` (1008 lines), `crates/fuse/src/platform/windows/operations.rs` (602 lines), `crates/fuse/src/platform/windows/read_ops.rs` (464 lines), `crates/fuse/src/platform/windows/dir_ops.rs` (206 lines)
- Why fragile: 2280 lines of platform-specific FUSE code. Uses WinFSP which has different semantics from macOS FUSE-T.
- Safe modification: Test on actual Windows with Explorer, cmd, and PowerShell.
- Test coverage: Desktop E2E runs on Windows in CI. No unit tests for Windows FUSE operations.

**Mutex `unwrap()` calls in FUSE production code:**

- Files: `crates/fuse/src/lib.rs:141`, `:179`, `:183`, `crates/fuse/src/platform/windows/read_ops.rs`, `crates/fuse/src/platform/windows/write_ops.rs`
- Why fragile: 19+ `lock().unwrap()` calls on `Mutex` objects in FUSE production code (not tests). If any background thread panics while holding a lock, subsequent lock attempts will panic with "poisoned mutex", crashing the filesystem thread and unmounting the drive.
- Safe modification: Replace with `lock().unwrap_or_else(|p| p.into_inner())` for poison recovery, or propagate errors via `EIO`.
- Test coverage: No tests exercise panic-during-lock scenarios.

**Vendored fuser crate:**

- Files: `apps/desktop/src-tauri/vendor/fuser/` (~5000 lines), critical patch in `channel.rs`
- Why fragile: Vendored fork of fuser 0.16 with socket-read patch for FUSE-T compatibility. Upstream updates cannot be trivially merged. The patch is load-bearing — without it, large file writes crash.
- Safe modification: Never update without re-applying the `channel.rs` receive() patch.
- Test coverage: No tests for the patched receive() function.

**Delegated routing dependency:**

- Files: `apps/api/src/ipns/delegated-routing.client.ts`
- Why fragile: Staging uses self-hosted Someguy sidecar. Production environment not yet deployed — planned to use delegated-ipfs.dev (public, no SLA) unless Someguy is deployed there too.
- Safe modification: Client has retry with exponential backoff (3 retries, 1s base delay, 30s cap). The `DELEGATED_ROUTING_URL` env var controls which endpoint is used.
- Test coverage: Unit tests at `apps/api/src/ipns/delegated-routing.client.spec.ts` cover retry logic. No integration tests against real service.

**Web3Auth MPC Core Kit integration:**

- Files: `apps/web/src/lib/web3auth/core-kit.ts`, `apps/web/src/lib/web3auth/hooks.ts`, `apps/web/src/hooks/useAuth.ts` (723 lines)
- Why fragile: Web3Auth SDK has poor TypeScript definitions. SDK version upgrades frequently change behavior. The REQUIRED_SHARE state handling works around an SDK bug.
- Safe modification: Test all auth flows (email, Google, wallet) end-to-end after any Web3Auth dependency update.
- Test coverage: Auth flow tested via E2E. Web3Auth unit mocking is complex.

## Scaling Limits

**IPNS record propagation and TEE republishing:**

- Current capacity: TEE republishes all enrolled IPNS records every 6 hours via batch endpoint.
- Limit: At 1000+ enrolled records per user, republish cycles may exceed the 3-hour window.
- Scaling path: Implement IPNS unenrollment persistence on deletion (see Tech Debt). Consider per-user republish prioritization.

**Folder metadata size (1000 files per folder):**

- Current capacity: PRD constrains to 1000 children per folder.
- Limit: With FilePointers (~100 bytes each), a 1000-file folder produces ~100 KB of metadata before encryption.
- Scaling path: This limit is enforced by design. For larger collections, users must create subfolders.

**File size limit (100 MB with GCM):**

- Current capacity: 100 MB per file per PRD constraint.
- Limit: Browser memory pressure with full-file buffering for GCM encryption.
- Scaling path: CTR streaming encryption is implemented but not yet the default for uploads.

**Single Kubo IPFS node:**

- Current capacity: One Kubo node handles all pinning/unpinning per deployment.
- Limit: Single point of failure.
- Scaling path: BYO-IPFS support (Phase 21) allows users to configure external pinning providers (Kubo, Pinata, PSA-compatible). This distributes IPFS load away from the default CipherBox node.

## Dependencies at Risk

**Delegated routing service availability:**

- Risk: Staging uses self-hosted Someguy sidecar. Recovery tool uses delegated-ipfs.dev (public, no SLA) directly from the browser. A future production environment would need a reliable routing solution.
- Impact: Someguy downtime = no IPNS publishing/resolving on staging. DB-cached CID fallback exists for resolution.
- Migration plan: Deploy Someguy to production when it exists (same pattern as staging). Recovery tool could accept configurable routing endpoint.

**Web3Auth MPC Core Kit (@web3auth/mpc-core-kit@^3.5.0):**

- Risk: Complex SDK with frequent breaking changes. Poor TypeScript types. Authentication entirely dependent on Web3Auth infrastructure.
- Impact: SDK updates may break auth flows. Service downtime = no new logins (existing sessions continue via refresh tokens).
- Migration plan: Auth architecture separates Web3Auth (key derivation) from CipherBox auth (JWT tokens). Migration to different MPC provider requires replacing only the integration layer.

**eciesjs@^0.4.16:**

- Risk: Small package with limited maintenance. Used for ECIES key wrapping (core security function).
- Impact: Security vulnerability would compromise key wrapping.
- Migration plan: Package wraps noble/secp256k1. Could be replaced with direct ECIES implementation using noble primitives.

**FUSE-T (macOS userspace filesystem):**

- Risk: Third-party macOS filesystem driver. Requires user installation. Not a standard macOS component.
- Impact: macOS updates can break FUSE-T. The NFS-to-SMB backend switch was forced by a macOS Sequoia kernel bug.
- Migration plan: Monitor FUSE-T releases. Consider FileProvider API on macOS as long-term alternative.

## Missing Critical Features

**No offline support (web or desktop):**

- Problem: No service worker for offline caching in web app (existing SW handles only media decryption proxying, not caching). Desktop FUSE mount requires continuous API connectivity.
- Blocks: Users cannot access files when offline. Desktop mount becomes unresponsive without network.

## Test Coverage Gaps

**Web app has minimal unit tests (3 test files for 165 source files):**

- What's not tested: All React components, most hooks, all services except sync store.
- Files: Only 3 test files exist:
  - `apps/web/src/stores/__tests__/sync-store.test.ts`
  - `apps/web/src/stores/__tests__/upload-error-recovery.test.ts`
  - `apps/web/src/stores/__tests__/logout-security.test.ts`
- Risk: Regressions in folder operations, file uploads, auth flows, sharing, and bin operations go undetected until E2E tests or manual testing. The 1059-line `folder.service.ts`, 971-line `bin.service.ts`, and 791-line `SharedFileBrowser.tsx` have zero unit test coverage.
- Priority: High. Focus first on services (`folder.service.ts`, `bin.service.ts`, `share.service.ts`) and critical hooks (`useAuth.ts`, `useFolderMutations.ts`, `useFileOperations.ts`).

**TEE worker has minimal tests (1 test file for 13 source files):**

- What's not tested: IPNS signing, key management, epoch rotation, auth middleware, republish route handler. Only SSRF validation is tested.
- Files: `tee-worker/src/__tests__/ssrf-validation.test.ts` (single test file)
- Risk: Security-critical code (TEE key derivation, IPNS record signing) is largely untested. Regressions in epoch rotation or key decryption would silently break republishing.
- Priority: High. The TEE worker handles decrypted IPNS private keys — correctness is security-critical.

**Desktop app has no TypeScript unit tests:**

- What's not tested: All TypeScript code in `apps/desktop/src/` (auth flow, Tauri IPC handlers, webview integration).
- Files: `apps/desktop/src/auth.ts` (711 lines), `apps/desktop/src/main.ts`
- Risk: Auth flow regressions, IPC communication errors.
- Priority: Medium. Desktop E2E covers the critical paths.

**FUSE write operations have no unit tests:**

- What's not tested: All write operation implementations (create file, write data, rename, delete, mkdir, publish coordination) in both macOS and Windows variants.
- Files: `crates/fuse/src/write_ops.rs` (976 lines), `crates/fuse/src/platform/windows/write_ops.rs` (1008 lines)
- Risk: FUSE bugs cause data loss or mount crashes. Desktop E2E shell scripts cover basic flows but cannot exercise edge cases.
- Priority: High. At minimum, add unit tests for publish coordination logic and conflict merge behavior.

**API Client package has minimal tests:**

- What's not tested: Generated API client functions, interceptors, error handling.
- Files: Only `packages/api-client/src/__tests__/instance.test.ts` exists. Coverage thresholds set to 0%.
- Risk: Low — mostly generated code. The real validation happens through SDK E2E tests that exercise the client.
- Priority: Low.

---

<!-- Concerns audit: 2026-03-29 -->
