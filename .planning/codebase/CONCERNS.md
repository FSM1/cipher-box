# Codebase Concerns

**Analysis Date:** 2026-03-27

## Tech Debt

**Orphaned IPNS records on file/folder deletion:**

- Issue: When files or folders are deleted, their IPNS records and TEE republish enrollments are not cleaned up. The code logs warnings and defers to "Phase 14" via TODO comments.
- Files: `apps/web/src/services/folder.service.ts:461`, `apps/web/src/services/folder.service.ts:513`, `apps/web/src/services/delete.service.ts:22`
- Impact: Orphaned IPNS records accumulate in the TEE republish schedule. Each orphan wastes TEE compute and delegated routing bandwidth every 6 hours. Capacity warnings trigger at 1000+ records.
- Fix approach: The API already has `unenrollIpns()` at `apps/api/src/republish/republish.service.ts`. Expose it via a REST endpoint and call it from the web client during file/folder deletion. Batch unenrollment needed for folder deletes containing multiple files.

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

**Large monolithic files in web app:**

- Issue: Several web app files exceed 900 lines, concentrating multiple responsibilities.
- Files:
  - `apps/web/src/hooks/useSharedNavigation.ts` (1199 lines)
  - `apps/web/src/services/folder.service.ts` (1089 lines)
  - `apps/web/src/components/file-browser/FileBrowser.tsx` (964 lines)
  - `apps/web/src/services/bin.service.ts` (962 lines)
  - `apps/web/src/components/file-browser/SharedFileBrowser.tsx` (943 lines)
  - `apps/web/src/components/file-browser/ShareDialog.tsx` (768 lines)
  - `apps/web/src/hooks/useAuth.ts` (711 lines)
  - `apps/web/src/components/file-browser/DetailsDialog.tsx` (664 lines)
- Impact: Difficult to test individual behaviors in isolation. Cognitive load for code review. Higher risk of merge conflicts.
- Fix approach: In progress -- Phase 27 quick task `260327-2ab-extract-shared-write-operations-from-web` is extracting shared write operations into `@cipherbox/sdk`. Continue extracting folder CRUD operations from `folder.service.ts` into focused modules. Split `FileBrowser.tsx` and `SharedFileBrowser.tsx` into container + presentational components.

**Pervasive console.log/warn/error in web app:**

- Issue: 127 `console.error`/`console.warn`/`console.log` calls across 29 files in production web code instead of a structured logging abstraction.
- Files: Top offenders: `apps/web/src/lib/web3auth/hooks.ts` (22 calls), `apps/web/src/services/bin.service.ts` (16 calls), `apps/web/src/hooks/useSharedNavigation.ts` (11 calls), `apps/web/src/components/file-browser/FileBrowser.tsx` (10 calls), `apps/web/src/hooks/useAuth.ts` (9 calls)
- Impact: No log level filtering, no structured output, no ability to ship logs to an observability service. Debug logs leak into staging.
- Fix approach: Introduce a lightweight logging wrapper (e.g., `lib/logger.ts`) with level filtering. Replace all direct `console.*` calls.

**Silenced unpin failures across the codebase:**

- Issue: All IPFS unpin calls use `.catch(() => {})` pattern, silently swallowing failures.
- Files: `apps/web/src/components/file-browser/ReplaceFileDialog.tsx`, `apps/web/src/hooks/useDropUpload.ts`, `apps/web/src/hooks/useFileVersions.ts`, `apps/web/src/hooks/useFileOperations.ts`, `apps/web/src/services/bin.service.ts`
- Impact: Failed unpins mean orphaned data on IPFS that consumes storage quota without the user knowing. Over time this could exhaust quota with unreachable data.
- Fix approach: Log unpin failures and consider a periodic background reconciliation that retries failed unpins. Track unpin failures in a local queue.

**Legacy POC directory still in repo:**

- Issue: `00-Preliminary-R&D/poc/` remains alongside production code. Uses deprecated `ipfs-http-client@60.0.1`, has no tests, and uses patterns explicitly superseded by the production implementation.
- Files: `00-Preliminary-R&D/poc/src/index.ts`, `00-Preliminary-R&D/poc/package.json`
- Impact: Adds noise to searches and dependency audits. New contributors may confuse PoC with current implementation.
- Fix approach: Already marked as historical reference per CLAUDE.md. Consider moving to a separate branch or archive tag.

**`any` type usage in web app:**

- Issue: Several `as any` casts remain, primarily around Web3Auth SDK integration and Node.js polyfills.
- Files: `apps/web/src/main.tsx:10`, `apps/web/src/polyfills.ts:6-9`, `apps/web/src/stores/folder.store.ts:236`
- Impact: Type safety gaps around authentication flow. The polyfill `any` casts are acceptable (Node.js globals on `window`). The folder store debug export is dev-only.
- Fix approach: Create typed wrappers for Web3Auth SDK interactions. The polyfill and debug `any` casts are acceptable.

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

**FUSE FilePointer resolution blocks filesystem thread:**

- Problem: After background metadata refresh, unresolved FilePointers are resolved synchronously on the FUSE thread with `O(N * timeout)` latency.
- Files: `crates/fuse/src/read_ops.rs`, `crates/fuse/src/lib.rs`
- Cause: Each FilePointer resolution requires an IPNS resolve network call.
- Improvement path: Spawn async tasks via a channel pair to avoid stalling the FUSE thread on network I/O.

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

- Files: `crates/fuse/src/lib.rs` (667 lines), `crates/fuse/src/write_ops.rs` (976 lines), `crates/fuse/src/read_ops.rs` (772 lines), `apps/desktop/src-tauri/vendor/fuser/src/channel.rs`
- Why fragile: FUSE-T is a userspace NFS/SMB translation layer, not kernel FUSE. Numerous workarounds for macOS-specific issues (SMB opendir requires non-zero fh, rename truncates filenames by 8 bytes, UID mismatch under SMB proxy). Each macOS update could introduce new kernel-side behavior changes.
- Safe modification: Always test with Finder, Terminal `ls`/`mv`/`cp`, and multi-file operations.
- Test coverage: Desktop E2E shell scripts exercise basic operations. Rust inline tests cover inode table and cache. No unit tests for filesystem callback implementations.

**Windows FUSE implementation (WinFSP):**

- Files: `crates/fuse/src/platform/windows/write_ops.rs` (1008 lines), `crates/fuse/src/platform/windows/operations.rs` (601 lines), `crates/fuse/src/platform/windows/read_ops.rs` (430 lines), `crates/fuse/src/platform/windows/dir_ops.rs` (205 lines)
- Why fragile: 2244 lines of platform-specific FUSE code. Uses WinFSP which has different semantics from macOS FUSE-T.
- Safe modification: Test on actual Windows with Explorer, cmd, and PowerShell.
- Test coverage: Desktop E2E runs on Windows in CI. No unit tests for Windows FUSE operations.

**Vendored fuser crate:**

- Files: `apps/desktop/src-tauri/vendor/fuser/` (~5000 lines), critical patch in `channel.rs`
- Why fragile: Vendored fork of fuser 0.16 with socket-read patch for FUSE-T compatibility. Upstream updates cannot be trivially merged. The patch is load-bearing -- without it, large file writes crash.
- Safe modification: Never update without re-applying the `channel.rs` receive() patch.
- Test coverage: No tests for the patched receive() function.

**Delegated routing dependency:**

- Files: `apps/api/src/ipns/delegated-routing.client.ts`
- Why fragile: Staging uses self-hosted Someguy sidecar. Production environment not yet deployed — planned to use delegated-ipfs.dev (public, no SLA) unless Someguy is deployed there too.
- Safe modification: Client has retry with exponential backoff (3 retries, 1s base delay, 30s cap). The `DELEGATED_ROUTING_URL` env var controls which endpoint is used.
- Test coverage: Unit tests at `apps/api/src/ipns/delegated-routing.client.spec.ts` cover retry logic. No integration tests against real service.

**Web3Auth MPC Core Kit integration:**

- Files: `apps/web/src/lib/web3auth/core-kit.ts`, `apps/web/src/lib/web3auth/hooks.ts` (22 console calls), `apps/web/src/hooks/useAuth.ts` (711 lines)
- Why fragile: Web3Auth SDK has poor TypeScript definitions. SDK version upgrades frequently change behavior. The REQUIRED_SHARE state handling works around an SDK bug.
- Safe modification: Test all auth flows (email, Google, wallet) end-to-end after any Web3Auth dependency update.
- Test coverage: Auth flow tested via E2E. Web3Auth unit mocking is complex.

**Shared navigation hook:**

- Files: `apps/web/src/hooks/useSharedNavigation.ts` (1199 lines)
- Why fragile: Largest single hook in the codebase. Manages navigation state, key unwrapping, folder loading, and write operations for shared folders. Any change can break shared folder access.
- Safe modification: Run writable shares E2E test (`tests/web-e2e/tests/writable-shares.spec.ts`) and sharing workflow test after changes.
- Test coverage: Zero unit tests. Covered only by E2E tests.

## Scaling Limits

**IPNS record propagation and TEE republishing:**

- Current capacity: TEE republishes all enrolled IPNS records every 6 hours via batch endpoint.
- Limit: At 1000+ enrolled records per user, republish cycles may exceed the 3-hour window.
- Scaling path: Implement IPNS unenrollment on deletion (see Tech Debt). Consider per-user republish prioritization.

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

- Problem: No service worker for offline caching in web app. Desktop FUSE mount requires continuous API connectivity.
- Blocks: Users cannot access files when offline. Desktop mount becomes unresponsive without network.

**No monitoring/observability (web app):**

- Problem: Web app has no error tracking service (Sentry, etc.). Errors are logged to `console.error` and lost (127 occurrences across 29 files).
- Blocks: Cannot detect or diagnose issues in staging or any future deployed environment. API has Prometheus metrics (`apps/api/src/metrics/`) but web has nothing.

## Test Coverage Gaps

**Web app has minimal unit tests (3 test files for 157 source files):**

- What's not tested: All React components, most hooks, all services except sync store.
- Files: Only 3 test files exist:
  - `apps/web/src/stores/__tests__/sync-store.test.ts`
  - `apps/web/src/stores/__tests__/upload-error-recovery.test.ts`
  - `apps/web/src/stores/__tests__/logout-security.test.ts`
- Risk: Regressions in folder operations, file uploads, auth flows, sharing, and bin operations go undetected until E2E tests or manual testing. The 964-line `FileBrowser.tsx`, 1199-line `useSharedNavigation.ts`, and 1089-line `folder.service.ts` have zero unit test coverage.
- Priority: High. Focus first on services (`folder.service.ts`, `bin.service.ts`, `share.service.ts`) and critical hooks (`useAuth.ts`, `useSharedNavigation.ts`, `useFolderMutations.ts`).

**TEE worker has minimal tests (1 test file for 13 source files):**

- What's not tested: IPNS signing, key management, epoch rotation, auth middleware, republish route handler. Only SSRF validation is tested.
- Files: `tee-worker/src/__tests__/ssrf-validation.test.ts` (single test file)
- Risk: Security-critical code (TEE key derivation, IPNS record signing) is largely untested. Regressions in epoch rotation or key decryption would silently break republishing.
- Priority: High. The TEE worker handles decrypted IPNS private keys -- correctness is security-critical.

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
- Risk: Low -- mostly generated code. The real validation happens through SDK E2E tests that exercise the client.
- Priority: Low.

**No versioning-specific E2E tests:**

- What's not tested: File versioning is implemented (Phase 13) in `apps/web/src/hooks/useFileVersions.ts`, `apps/web/src/services/file-metadata.service.ts`, and `packages/sdk-core/src/file/index.ts`, but no dedicated E2E test exercises the version history UI (create version, restore version, delete version).
- Files: `apps/web/src/hooks/useFileVersions.ts`, `tests/web-e2e/tests/` (no versioning spec)
- Risk: Regression in version creation, restoration, or deletion would go unnoticed. The full-workflow E2E test overwrites files but does not verify version history.
- Priority: Medium. Quick task `018-e2e-versioning-tests` exists in `.planning/quick/` but has not been executed.

---

<!-- Concerns audit: 2026-03-27 -->
