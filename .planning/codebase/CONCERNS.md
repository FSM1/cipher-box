# Codebase Concerns

**Analysis Date:** 2026-03-06

## Tech Debt

**Orphaned IPNS records on file/folder deletion:**

- Issue: When files or folders are deleted, their IPNS records and TEE republish enrollments are not cleaned up. The code logs warnings and defers to "Phase 14" via TODO comments.
- Files: `apps/web/src/services/folder.service.ts:455`, `apps/web/src/services/folder.service.ts:507-512`, `apps/web/src/services/delete.service.ts:22-29`
- Impact: Orphaned IPNS records accumulate in the TEE republish schedule. The republish service has capacity warnings at 1000+ records. Each orphan wastes TEE compute and delegated routing bandwidth every 3 hours until natural expiry.
- Fix approach: The API already has `unenrollIpns()` at `apps/api/src/republish/republish.service.ts:255`. Expose it via a REST endpoint and call it from the web client during file/folder deletion. Batch unenrollment needed for folder deletes containing multiple files.

**Desktop device approval polling not implemented:**

- Issue: Phase 11.2 TODO comments indicate the desktop app lacks approval notification polling. When another device needs MFA approval, the desktop user has no notification.
- Files: `apps/desktop/src/main.ts:32`, `apps/desktop/src/auth.ts:680`
- Impact: Desktop users must use the web app to approve new devices. Reduces desktop app self-sufficiency.
- Fix approach: Add a background polling interval (similar to web's `useDeviceApproval`) that checks for pending approvals and surfaces native OS notifications via Tauri's notification API.

**Legacy POC directory still in repo:**

- Issue: `00-Preliminary-R&D/poc/` (702-line monolithic file) remains alongside production code. Uses deprecated `ipfs-http-client@60.0.1`, has no tests, and uses patterns explicitly superseded by the production implementation.
- Files: `00-Preliminary-R&D/poc/src/index.ts`, `00-Preliminary-R&D/poc/package.json`
- Impact: New contributors may confuse PoC with current implementation. Adds noise to searches and dependency audits.
- Fix approach: Already marked as historical reference per CLAUDE.md. Consider moving to a separate branch or archive tag if repo size is a concern.

**Large monolithic files in web app:**

- Issue: Several web app files exceed 900 lines, concentrating multiple responsibilities.
- Files: `apps/web/src/services/folder.service.ts` (1080 lines), `apps/web/src/components/file-browser/FileBrowser.tsx` (964 lines), `apps/web/src/services/bin.service.ts` (962 lines), `apps/web/src/hooks/useFolderMutations.ts` (793 lines), `apps/web/src/hooks/useAuth.ts` (522 lines), `apps/web/src/hooks/useSharedNavigation.ts` (551 lines)
- Impact: Difficult to test individual behaviors in isolation. Cognitive load for code review. Higher risk of merge conflicts.
- Fix approach: Extract folder CRUD operations from `folder.service.ts` into focused modules (create, delete, update, navigate). Split `FileBrowser.tsx` into container and presentational components. Extract bin operations into smaller service files.

**Pervasive console.log/warn/error in web app:**

- Issue: 50+ `console.error`/`console.warn`/`console.log` calls throughout production web code instead of a structured logging abstraction.
- Files: `apps/web/src/components/file-browser/FileBrowser.tsx` (12 calls), `apps/web/src/hooks/useAuth.ts` (10 calls), `apps/web/src/components/file-browser/BinBrowser.tsx` (5 calls), `apps/web/src/components/file-browser/ShareDialog.tsx` (3 calls), and many more across hooks and services.
- Impact: No log level filtering, no structured output, no ability to ship logs to an observability service. Debug logs leak into production.
- Fix approach: Introduce a lightweight logging wrapper (e.g., `lib/logger.ts`) that wraps `console.*` with level filtering and optional structured output. Replace all direct `console.*` calls.

**Silenced unpin failures across the codebase:**

- Issue: All IPFS unpin calls use `.catch(() => {})` pattern, silently swallowing failures.
- Files: `apps/web/src/components/file-browser/ReplaceFileDialog.tsx:53,64,73`, `apps/web/src/hooks/useDropUpload.ts:156`, `apps/web/src/hooks/useFileVersions.ts:142,261`, `apps/web/src/hooks/useFileOperations.ts:463`, `apps/web/src/services/bin.service.ts:717,748,826,842`
- Impact: Failed unpins mean orphaned data on IPFS that consumes storage quota without the user knowing. Over time this could exhaust the user's 500 MiB quota with unreachable data.
- Fix approach: Log unpin failures (at minimum) and consider a periodic background reconciliation that retries failed unpins. Track unpin failures in a local queue.

**`any` type usage in web app:**

- Issue: Several `as any` casts remain, primarily around Web3Auth SDK integration and polyfills.
- Files: `apps/web/src/main.tsx:6,64`, `apps/web/src/lib/web3auth/hooks.ts:146,152`, `apps/web/src/polyfills.ts:6-9`, `apps/web/src/stores/folder.store.ts:185`
- Impact: Type safety gaps around authentication flow. Web3Auth SDK types are poorly defined, making it hard to eliminate.
- Fix approach: Create typed wrappers for Web3Auth SDK interactions. The polyfill `any` casts are acceptable (Node.js globals on `window`).

## Known Bugs

**No active known bugs identified in the current codebase.**

Previous known bugs (upload modal stuck, auth refresh race) were fixed in PRs #56 and #58. The IPNS resolve 502 issue (delegated-ipfs.dev unreliability) is mitigated by DB-cached CID fallback and retry logic in `apps/api/src/ipns/delegated-routing.client.ts`.

## Security Considerations

**Memory zeroing is best-effort in JavaScript:**

- Risk: `clearBytes()` / `.fill(0)` cannot guarantee sensitive key material is erased from V8 heap, JIT-compiled code, or GC intermediaries.
- Files: `packages/crypto/src/utils/memory.ts`, `apps/web/src/stores/vault.store.ts:73-81`, `apps/web/src/stores/auth.store.ts:74-77`, `apps/web/src/stores/folder.store.ts:137-169`
- Current mitigation: The codebase consistently uses `.fill(0)` on key buffers during logout and store cleanup. The crypto package documents the limitation clearly.
- Recommendations: This is an inherent JavaScript limitation. For the desktop app, the Rust side should use `zeroize` crate for key material. Current approach is acceptable for browser context.

**Web3Auth localStorage usage:**

- Risk: Web3Auth MPC Core Kit stores its share factor in `localStorage`, which is accessible to XSS.
- Files: `apps/web/src/lib/web3auth/core-kit.ts:24` (`storage: window.localStorage`)
- Current mitigation: CipherBox's own keys (vault keypair, folder keys) are never stored in localStorage -- only in Zustand memory stores. The Web3Auth factor in localStorage is one share of a 2-of-3 TSS scheme (insufficient alone to derive the private key).
- Recommendations: CSP headers and XSS prevention remain critical. The MFA enrollment (Phase 12) adds a device approval factor that further limits exposure.

**IPFS node credentials and access control:**

- Risk: Kubo API endpoint has no built-in authentication. Anyone with network access to port 5001 can pin/unpin content.
- Files: `apps/api/src/ipfs/providers/local.provider.ts:14-24`, `apps/api/.env.example`
- Current mitigation: Kubo API bound to localhost in dev. In staging/production, Docker network isolation limits access to the API container.
- Recommendations: For production, use reverse proxy with auth or Kubo's API access controls. Consider network-level firewall rules.

**Test login endpoint available in staging:**

- Risk: `POST /auth/test-login` bypasses all real authentication. Available when `TEST_LOGIN_SECRET` is set and `NODE_ENV !== 'production'`.
- Files: `apps/api/.env.example:49-51`, `apps/api/src/auth/` (test-auth service)
- Current mitigation: Guarded by `NODE_ENV` check and requires knowing the secret. Not available in production.
- Recommendations: Ensure CI/CD pipeline never sets `TEST_LOGIN_SECRET` in production environment. Add monitoring alert if the endpoint is called in staging.

**CORS wildcard patterns:**

- Risk: CORS configuration supports wildcard patterns (e.g., `https://cipher-box-pr-*.onrender.com`) which could be abused if an attacker can create matching subdomains on the hosting platform.
- Files: `apps/api/src/main.ts:29-47`
- Current mitigation: Wildcards only match specific hosting platform patterns.
- Recommendations: Use exact origin lists in production. Reserve wildcards for PR preview environments only.

## Performance Bottlenecks

**FUSE FilePointer resolution blocks filesystem thread:**

- Problem: After background metadata refresh, unresolved FilePointers are resolved synchronously on the single FUSE thread with `O(N * timeout)` latency.
- Files: `apps/desktop/src-tauri/src/fuse/mod.rs:1039-1049`
- Cause: Each FilePointer resolution requires an IPNS resolve network call. The TODO at line 1039 documents this.
- Improvement path: Spawn async tasks via a channel pair (like the existing `refresh_tx/rx` pattern) to avoid stalling the FUSE thread on network I/O.

**Full file content buffering for AES-GCM encryption:**

- Problem: Files encrypted with GCM mode are fully loaded into memory. The 100 MB file size limit means up to 100 MB of memory per concurrent upload.
- Files: `apps/web/src/services/upload.service.ts`, `packages/crypto/src/aes/encrypt.ts`
- Cause: AES-256-GCM requires full content for authentication tag computation.
- Improvement path: AES-256-CTR streaming encryption already exists (`packages/crypto/src/aes/encrypt-ctr.ts`, `packages/crypto/src/aes/decrypt-ctr.ts`) and is used for media streaming playback. Extend CTR usage to all uploads for reduced memory pressure. Desktop already uses CTR for FUSE reads.

**IPNS polling for sync (30-second interval):**

- Problem: Sync latency is at least 30 seconds. No push notification infrastructure exists.
- Files: `apps/web/src/hooks/useSyncPolling.ts`, per `TECHNICAL_ARCHITECTURE.md` Section 5.4
- Cause: IPNS is pull-based. Adding WebSocket push would require backend infrastructure.
- Improvement path: Future versions could implement WebSocket notifications for immediate sync triggers, falling back to polling.

**No pagination for large folders:**

- Problem: Folder metadata contains all children inline. A folder with 1000 files loads all 1000 entries into memory and renders them all at once.
- Files: `apps/web/src/components/file-browser/FileList.tsx`, `apps/web/src/services/folder.service.ts`
- Cause: IPNS-based metadata is a single encrypted blob per folder.
- Improvement path: Implement virtual scrolling in the UI (render only visible rows). The 1000-file limit per PRD mitigates the data loading issue.

## Fragile Areas

**FUSE-T SMB backend on macOS:**

- Files: `apps/desktop/src-tauri/src/fuse/mod.rs` (1803 lines), `apps/desktop/src-tauri/src/fuse/write_ops.rs` (976 lines), `apps/desktop/src-tauri/vendor/fuser/src/channel.rs`
- Why fragile: FUSE-T is a userspace NFS/SMB translation layer, not kernel FUSE. Numerous workarounds exist for macOS-specific issues (SMB opendir requires non-zero fh, rename truncates filenames by 8 bytes, UID mismatch under SMB proxy, no FSEvents). Each macOS update could introduce new kernel-side behavior changes.
- Safe modification: Always test with Finder, Terminal `ls`/`mv`/`cp`, and multi-file operations. Single-thread constraint means any blocking call stalls everything.
- Test coverage: Manual testing only. No automated FUSE integration tests. The `tests.rs` files cover crypto operations but not filesystem operations.

**Windows FUSE implementation (WinFSP):**

- Files: `apps/desktop/src-tauri/src/fuse/windows/mod.rs` (498 lines), `apps/desktop/src-tauri/src/fuse/windows/operations.rs` (694 lines), `apps/desktop/src-tauri/src/fuse/windows/write_ops.rs` (997 lines), `apps/desktop/src-tauri/src/fuse/windows/read_ops.rs` (430 lines)
- Why fragile: 2824 lines of platform-specific FUSE code with many `lock().unwrap()` calls that will panic on poisoned mutex. No automated tests. Uses WinFSP which has different semantics from macOS FUSE-T.
- Safe modification: Test on actual Windows with Explorer, cmd, and PowerShell. Watch for mutex poisoning under error conditions.
- Test coverage: No automated tests exist for Windows FUSE operations.

**Vendored fuser crate:**

- Files: `apps/desktop/src-tauri/vendor/fuser/` (~5000 lines), `apps/desktop/src-tauri/vendor/fuser/src/channel.rs` (critical patch)
- Why fragile: Vendored fork of fuser 0.16 with socket-read patch for FUSE-T compatibility. Upstream updates cannot be trivially merged. The patch is load-bearing -- without it, large file writes crash the FUSE session.
- Safe modification: Never update without re-applying the `channel.rs` receive() patch. Document patch diff in vendor directory.
- Test coverage: No tests for the patched receive() function.

**Delegated routing (delegated-ipfs.dev) dependency:**

- Files: `apps/api/src/ipns/delegated-routing.client.ts`
- Why fragile: The external service at `delegated-ipfs.dev` has been unreliable historically (502 errors documented in memory). It is the sole path for IPNS record publishing and resolution from the API.
- Safe modification: The client has retry with exponential backoff (3 retries, 1s base delay, 30s cap). Changes to the API or rate limits could break publishing.
- Test coverage: Unit tests at `apps/api/src/ipns/delegated-routing.client.spec.ts` cover retry logic. No integration tests against real service.

**Web3Auth MPC Core Kit integration:**

- Files: `apps/web/src/lib/web3auth/core-kit.ts`, `apps/web/src/lib/web3auth/hooks.ts` (multiple `as any` casts), `apps/web/src/hooks/useAuth.ts` (522 lines)
- Why fragile: Web3Auth SDK has poor TypeScript definitions (`any` casts required). The `REQUIRED_SHARE` state handling at `hooks.ts:205-226` works around a bug where Web3Auth doesn't auto-check localStorage for device factors. SDK version upgrades frequently change behavior.
- Safe modification: Test all auth flows (email, Google, wallet) end-to-end after any Web3Auth dependency update.
- Test coverage: Auth flow tested via E2E (`tests/e2e/tests/full-workflow.spec.ts`) but Web3Auth unit mocking is complex.

## Scaling Limits

**IPNS record propagation and TEE republishing:**

- Current capacity: TEE republishes all enrolled IPNS records every 3 hours via batch endpoint.
- Limit: At 1000+ enrolled records per user, republish cycles may exceed the 3-hour window. The `delete.service.ts:28` documents this threshold.
- Scaling path: Implement IPNS unenrollment on deletion (see Tech Debt section). Consider per-user republish prioritization.

**Folder metadata size (1000 files per folder):**

- Current capacity: PRD constrains to 1000 children per folder.
- Limit: Metadata blob grows linearly with children count. With FilePointers (~100 bytes each), a 1000-file folder produces ~100 KB of metadata before encryption.
- Scaling path: This limit is enforced by design. For larger collections, users must create subfolders.

**File size limit (100 MB with GCM):**

- Current capacity: 100 MB per file per PRD constraint.
- Limit: Browser memory pressure with full-file buffering for GCM encryption.
- Scaling path: CTR streaming encryption is implemented but not yet the default for uploads. Switching to CTR for large files would remove the memory constraint.

**Single Kubo IPFS node:**

- Current capacity: One Kubo node handles all pinning/unpinning for the entire deployment.
- Limit: Single point of failure. Kubo node downtime = no uploads or downloads.
- Scaling path: Add IPFS cluster for redundancy, or migrate to a managed IPFS pinning service (Pinata, web3.storage).

## Dependencies at Risk

**delegated-ipfs.dev (external service):**

- Risk: Third-party service with documented unreliability. No SLA. Single point of failure for IPNS operations.
- Impact: If down, no IPNS records can be published or resolved. File metadata becomes temporarily inaccessible.
- Migration plan: DB-cached CID fallback exists for resolution. Consider self-hosting a delegated routing endpoint or adding a secondary provider.

**Web3Auth MPC Core Kit (@web3auth/mpc-core-kit@^3.5.0):**

- Risk: Complex SDK with frequent breaking changes. Poor TypeScript types require `any` casts. Authentication is entirely dependent on Web3Auth infrastructure.
- Impact: SDK updates may break auth flows. Web3Auth service downtime = no new logins (existing sessions continue via refresh tokens).
- Migration plan: The auth architecture separates Web3Auth (key derivation) from CipherBox auth (JWT tokens). A migration to a different MPC provider would require replacing only the Web3Auth integration layer.

**eciesjs@^0.4.16:**

- Risk: Small package with limited maintenance activity. Used for ECIES key wrapping (core security function).
- Impact: Security vulnerability in this package would compromise key wrapping.
- Migration plan: The package wraps noble/secp256k1 internally. Could be replaced with direct ECIES implementation using noble primitives.

**FUSE-T (macOS userspace filesystem):**

- Risk: Third-party macOS filesystem driver. Not a standard macOS component. Requires user installation.
- Impact: macOS updates can break FUSE-T. The NFS-to-SMB backend switch was forced by a macOS Sequoia kernel bug.
- Migration plan: Monitor FUSE-T releases. Linux build uses kernel FUSE (more stable). Consider FileProvider API on macOS as long-term alternative.

## Missing Critical Features

**No offline support (web or desktop):**

- Problem: No service worker for offline caching in web app. Desktop FUSE mount requires continuous API connectivity.
- Blocks: Users cannot access files when offline. Desktop mount becomes unresponsive without network.
- Files: No service worker files exist (only a streaming-media SW at `apps/web/src/main.tsx:39`). Desktop FUSE operations fail with EIO on network errors.

**No file versioning:**

- Problem: Overwriting a file replaces the previous version entirely. No version history.
- Blocks: No undo for accidental overwrites. Out of scope for v1.0 per CLAUDE.md.
- Files: `apps/web/src/hooks/useFileVersions.ts` handles IPNS-based file metadata updates but not version history.

**No monitoring/observability (web app):**

- Problem: Web app has no error tracking service (Sentry, etc.). Errors are logged to `console.error` and lost.
- Blocks: Cannot detect or diagnose production issues affecting users. API has Prometheus metrics (`apps/api/src/metrics/`) but web has nothing.
- Files: `apps/web/src/main.tsx:9-14` wraps `console.error` but only for in-memory display.

## Test Coverage Gaps

**Web app has minimal unit tests (4 test files for 269 source files):**

- What's not tested: All React components, most hooks, all services except sync store.
- Files: Only 4 test files exist: `apps/web/src/stores/__tests__/sync-store.test.ts`, `apps/web/src/stores/__tests__/upload-error-recovery.test.ts`, `apps/web/src/stores/__tests__/logout-security.test.ts`, `apps/web/src/lib/api/__tests__/client-refresh.test.ts`
- Risk: Regressions in folder operations, file uploads, auth flows, sharing, and bin operations go undetected until E2E tests or manual testing. The 964-line `FileBrowser.tsx` has zero test coverage.
- Priority: High. Focus first on services (`folder.service.ts`, `bin.service.ts`, `share.service.ts`) and critical hooks (`useAuth.ts`, `useFolderMutations.ts`).

**TEE worker has zero tests:**

- What's not tested: IPNS signing, key management, epoch rotation, auth middleware.
- Files: `tee-worker/src/` (522 lines total, 0 test files)
- Risk: Security-critical code (TEE key derivation, IPNS record signing) is untested. Regressions in epoch rotation or key decryption would silently break republishing.
- Priority: High. The TEE worker handles decrypted IPNS private keys -- correctness is security-critical.

**Desktop FUSE operations have no automated tests:**

- What's not tested: All filesystem operations (read, write, create, rename, delete, mkdir), inode management, metadata caching, publish coordination.
- Files: `apps/desktop/src-tauri/src/fuse/mod.rs` (1803 lines), `apps/desktop/src-tauri/src/fuse/write_ops.rs` (976 lines), `apps/desktop/src-tauri/src/fuse/inode.rs` (937 lines). Only `apps/desktop/src-tauri/src/crypto/tests.rs` (1717 lines) covers the crypto layer.
- Risk: FUSE bugs cause data loss or mount crashes. The single-thread constraint makes race conditions subtle. Manual testing is the only verification.
- Priority: High. At minimum, add unit tests for `InodeTable` operations and `PublishCoordinator` logic.

**Windows FUSE operations untested:**

- What's not tested: All 2824 lines of Windows-specific FUSE code using WinFSP.
- Files: `apps/desktop/src-tauri/src/fuse/windows/` (5 files)
- Risk: Platform-specific bugs (mutex poisoning from `lock().unwrap()`, different filesystem semantics) undetected.
- Priority: Medium. Windows support appears to be secondary to macOS.

**E2E test helpers are stubs:**

- What's not tested: API helper functions for test setup are placeholder implementations.
- Files: `tests/e2e/utils/api-helpers.ts:5-45` (3 TODO functions: `createTestUser`, `cleanupVault`, `seedTestFiles`)
- Risk: E2E tests cannot programmatically set up complex test scenarios. Limited to UI-driven flows only.
- Priority: Medium. Implement API helpers as more complex E2E scenarios are needed.

---

Concerns audit: 2026-03-06
