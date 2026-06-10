# Codebase Concerns

**Analysis Date:** 2026-03-30

## Tech Debt

**Orphaned IPNS records on file/folder deletion:**

- Issue: When files or folders are deleted, their IPNS records and TEE republish enrollments are handled by `fireAndForgetUnenroll()` in `packages/sdk/src/client.ts`. The web app services correctly delegate to the SDK. However, SDK-based unenrollment is fire-and-forget with no persistence — if the browser tab closes before the API call completes, unenrollments are silently dropped.
- Files: `packages/sdk/src/client.ts:156-174`, `apps/web/src/services/folder.service.ts`
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

**Residual `console.warn` calls in SDK packages (not structured logger):**

- Issue: 11 `console.warn` calls in `packages/sdk/src/client.ts` and isolated calls in `packages/sdk/src/bin/index.ts:193` and `packages/sdk-core/src/ipns/index.ts:193` use raw `console.warn` rather than going through a structured logger. Phase 28 structured logging covered the web app but not the SDK packages (which have no logger dependency by design — they are zero-dependency packages).
- Files: `packages/sdk/src/client.ts` (lines 139, 168, 460, 752, 763, 817, 1012, 1022, 1073, 1437, 1516), `packages/sdk/src/bin/index.ts:193`, `packages/sdk-core/src/ipns/index.ts:193`
- Impact: SDK warnings bypass the web app's Faro transport and won't appear in Grafana dashboards. Debugging SDK-level issues in staging/production requires reading raw browser console logs.
- Fix approach: SDK and SDK-core are zero-dependency packages — they should not import a logging library. An acceptable alternative is accepting a logger callback in `CipherBoxClientConfig` and routing internal warnings through it. Alternatively, document that SDK warnings remain on raw console and are outside Faro coverage.

**Duplicate file upload path bypasses Web Worker encryption:**

- Issue: When a dropped file has the same name as an existing file in the target folder, it enters the duplicate/replacement path in `apps/web/src/hooks/useDropUpload.ts:199-255`. This path uses `encryptFile()` from `file-crypto.service.ts` which runs synchronously on the main thread, not through the `EncryptionWorkerService` introduced in Phase 37.
- Files: `apps/web/src/hooks/useDropUpload.ts:203`, `apps/web/src/services/file-crypto.service.ts`
- Impact: Large duplicate files (up to 100 MB) block the main thread during encryption, causing UI jank. Inconsistent with the batch upload path which uses the Worker.
- Fix approach: Route the duplicate upload through `getEncryptionWorker().createEncryptFn()` instead of `encryptFile()`. The `file-crypto.service` can remain for testing purposes.

## Known Bugs

**No active known bugs identified in the current codebase.**

Previous known bugs (upload modal stuck, auth refresh race) were fixed in PRs #56 and #58. The IPNS resolve 502 issue (delegated-ipfs.dev unreliability) is mitigated by DB-cached CID fallback and retry logic in `apps/api/src/ipns/delegated-routing.client.ts`.

## Security Considerations

**Memory zeroing is best-effort in JavaScript:**

- Risk: `clearBytes()` / `.fill(0)` cannot guarantee sensitive key material is erased from V8 heap, JIT-compiled code, or GC intermediaries.
- Files: `packages/crypto/src/utils/memory.ts`, `apps/web/src/stores/vault.store.ts`, `apps/web/src/stores/auth.store.ts`, `apps/web/src/stores/folder.store.ts`
- Current mitigation: The codebase consistently uses `.fill(0)` on key buffers during logout and store cleanup. The Rust side uses `zeroize` crate. The encryption Web Worker (Phase 37) also calls `clearBytes(fileKey)` before transferring the buffer, preventing key material from lingering in Worker memory.
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

**Grafana Faro telemetry scrub relies on key-name allow-list:**

- Risk: The `SENSITIVE_KEYS` set in `apps/web/src/lib/faro.ts` scrubs known field names (e.g., `privateKey`, `fileKey`, `rootFolderKey`). Unknown or newly added field names containing key material would not be scrubbed.
- Files: `apps/web/src/lib/faro.ts:12-22`
- Current mitigation: A secondary heuristic scrubs any string value matching 64+ hex characters regardless of key name. Binary `ArrayBuffer` / `ArrayBufferView` values are always redacted.
- Recommendations: When adding new fields that hold key material, ensure they are added to `SENSITIVE_KEYS`. The hex pattern heuristic is a safety net, not the primary defence.

## Performance Bottlenecks

**Full file content buffering for AES-GCM encryption (duplicate upload path):**

- Problem: The duplicate file upload path (`useDropUpload.ts` duplicate branch) uses `encryptFile()` which reads the entire file into memory on the main thread and uses AES-256-GCM (full-buffer). The batch upload path for new files uses the Worker and selects CTR for eligible media files automatically.
- Files: `apps/web/src/services/file-crypto.service.ts`, `apps/web/src/hooks/useDropUpload.ts:203`
- Cause: The replacement/duplicate flow was not updated in Phase 37. It also doesn't benefit from Worker offloading.
- Improvement path: Migrate the duplicate path to use `EncryptionWorkerService` and pass `encryptFn` to the staging upload. This removes the main-thread block and enables CTR for large media files on the duplicate path.

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
- Test coverage: Desktop E2E shell scripts exercise basic operations. Rust inline tests cover inode table and cache. No unit tests for filesystem callback implementations (won't fix — Desktop E2E is the appropriate level).

**Windows FUSE implementation (WinFSP):**

- Files: `crates/fuse/src/platform/windows/write_ops.rs` (1008 lines), `crates/fuse/src/platform/windows/operations.rs` (602 lines), `crates/fuse/src/platform/windows/read_ops.rs` (464 lines), `crates/fuse/src/platform/windows/dir_ops.rs` (206 lines)
- Why fragile: 2280 lines of platform-specific FUSE code. Uses WinFSP which has different semantics from macOS FUSE-T.
- Safe modification: Test on actual Windows with Explorer, cmd, and PowerShell.
- Test coverage: Desktop E2E runs on Windows in CI. No unit tests for Windows FUSE operations (won't fix).

**Mutex `unwrap()` calls in FUSE production code:**

- Files: `crates/fuse/src/lib.rs:141`, `:179`, `:183`; `crates/fuse/src/platform/windows/read_ops.rs` (7 occurrences); `crates/fuse/src/platform/windows/write_ops.rs` (9 occurrences); `crates/fuse/src/platform/windows/dir_ops.rs:27`
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

**Phala Cloud CVM deployment (single provider):**

- Files: `apps/tee-worker/src/services/tee-keys.ts`, `apps/tee-worker/src/index.ts`
- Why fragile: Phase 35 migrated TEE to Phala Cloud CVM using the dstack SDK (`@phala/dstack-sdk`). There is no fallback TEE provider — the previous AWS Nitro fallback option was not implemented. The dstack SDK is dynamically imported only inside `TEE_MODE=cvm`, making it unavailable for local testing without a CVM. Since PR #472 reverted staging to simulator mode, no deployed environment exercises the CVM path until production launches — it can bitrot silently.
- Safe modification: Key derivation and signing logic is tested via unit tests with `TEE_MODE=test`. Production CVM changes require Phala console deployment.
- Test coverage: `apps/tee-worker/src/__tests__/tee-keys.test.ts` covers the test-mode derivation path. The CVM code path itself is not unit-testable outside a real Phala CVM.

## Scaling Limits

**IPNS record propagation and TEE republishing:**

- Current capacity: TEE republishes all enrolled IPNS records every 6 hours via batch endpoint.
- Limit: At 1000+ enrolled records per user, republish cycles may exceed the 3-hour window.
- Scaling path: Implement IPNS unenrollment persistence on deletion (see Tech Debt). Consider per-user republish prioritization.

**Folder metadata size (1000 files per folder):**

- Current capacity: PRD constrains to 1000 children per folder.
- Limit: With FilePointers (~100 bytes each), a 1000-file folder produces ~100 KB of metadata before encryption.
- Scaling path: This limit is enforced by design. For larger collections, users must create subfolders.

**File size limit (100 MB):**

- Current capacity: 100 MB per file per PRD constraint.
- Limit: New file uploads (batch path) use the Worker and select CTR for eligible media files, reducing main-thread pressure. Duplicate uploads still buffer on the main thread (see Performance Bottlenecks).
- Scaling path: Migrate duplicate upload path to Worker + CTR (see Tech Debt).

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

**@phala/dstack-sdk:**

- Risk: Phala-specific SDK for CVM key derivation. Tightly coupled to Phala Cloud infrastructure. No alternative provider is implemented.
- Impact: If Phala Cloud has an outage or breaking API change, the production TEE republishing pipeline stops (staging is unaffected since PR #472 — it runs simulator mode). No fallback means IPNS records eventually expire (48-hour TTL).
- Migration plan: Abstract key derivation behind an interface so alternative providers (AWS Nitro Enclaves, Azure Confidential Computing) can be plugged in. Currently blocked by the complexity of re-implementing key derivation + epoch management for a second provider.

## Missing Critical Features

**No offline support (web or desktop):**

- Problem: No service worker for offline caching in web app (existing SW handles only media decryption proxying, not caching). Desktop FUSE mount requires continuous API connectivity.
- Blocks: Users cannot access files when offline. Desktop mount becomes unresponsive without network.

## Test Coverage Gaps

**Web app has minimal unit tests (won't fix):**

- Status: Won't fix. The web app layer is primarily thin wrappers around `@cipherbox/sdk` and React UI components. The 14 Playwright E2E suites in `tests/web-e2e/` cover all critical user flows end-to-end (upload, download, sharing, bin, search, auth, media preview, etc.). Unit testing these wrappers would duplicate E2E coverage with high mocking overhead and low marginal value. The SDK and SDK-core packages — where the actual logic lives — have comprehensive unit test suites (13 files each).

**TEE worker has improved but incomplete test coverage (5 test files for 14 source files):**

- What's not tested: The `migrate.ts` route handler, the `metrics.ts` middleware/route, and the production CVM code path in `tee-keys.ts`.
- Files: Tests at `apps/tee-worker/src/__tests__/` cover ssrf-validation, key-manager, auth middleware, tee-keys (test-mode only), and republish route. The `migrate.ts` route and `migration-worker.ts` service have no test coverage.
- Risk: The migration route handles epoch key rotation — a critical security operation. Bugs would go undetected until staging or production. The `migration-worker.ts` service is 19+ functions with no tests.
- Priority: High for migration-worker. Medium for metrics route.

**Desktop app has no TypeScript unit tests:**

- What's not tested: All TypeScript code in `apps/desktop/src/` (auth flow, Tauri IPC handlers, webview integration).
- Files: `apps/desktop/src/auth.ts` (711 lines), `apps/desktop/src/main.ts`
- Risk: Auth flow regressions, IPC communication errors.
- Priority: Medium. Desktop E2E covers the critical paths.

**FUSE write operations have no unit tests (won't fix):**

- What's not tested: Write operation implementations (create file, write data, rename, delete, mkdir, publish coordination) in both macOS and Windows variants.
- Files: `crates/fuse/src/write_ops.rs` (976 lines), `crates/fuse/src/platform/windows/write_ops.rs` (1008 lines)
- Status: Won't fix. FUSE callbacks are thin plumbing between OS filesystem calls and the Rust SDK — unit testing them would require mocking the entire host OS filesystem layer, which is unreliable and brittle. These code paths are exercised by the Desktop E2E test suite (`tests/desktop-e2e/`) which tests actual file operations through the mounted filesystem.

**API Client package has minimal tests:**

- What's not tested: Generated API client functions, interceptors, error handling.
- Files: Only `packages/api-client/src/__tests__/instance.test.ts` exists. Coverage thresholds set to 0%.
- Risk: Low — mostly generated code. The real validation happens through SDK E2E tests that exercise the client.
- Priority: Low.

**`useDropUpload` hook has no unit tests:**

- What's not tested: The primary file drop handler including batch upload orchestration, duplicate detection, orphan CID cleanup, and quota check interactions.
- Files: `apps/web/src/hooks/useDropUpload.ts` (283 lines)
- Risk: Phase 37 significantly rewrote this hook to use `client.uploadFiles()` with Worker encryption. The dual-path logic (new files via SDK batch vs. duplicates via legacy encrypt+upload) has no coverage. A regression could silently break file uploads.
- Priority: High. This is the primary upload entry point in the web app.

---

<!-- Concerns audit: 2026-03-30 -->
