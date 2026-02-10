---
status: resolved
trigger: 'Storage quota display stays stuck at zero after re-login, even after file tree has loaded into state.'
created: 2026-02-10T00:00:00Z
updated: 2026-02-10T00:02:00Z
---

## Current Focus

hypothesis: CONFIRMED and FIXED - fetchQuota() was never called on login or app initialization.
test: Added useEffect to StorageQuota component to call fetchQuota() on mount
expecting: Quota now syncs from backend whenever the component mounts (i.e., on every login/page load)
next_action: Archive session

## Symptoms

expected: After logging back in, the storage quota display should reflect the actual used storage (including files uploaded in previous sessions). If a user uploaded 5MB of files, the quota bar/number should show ~5MB used.
actual: The quota display stays at zero after re-login, even after the current folder file tree has been loaded into application state. The file tree shows the files exist, but the quota doesn't account for them.
errors: Unknown - user doesn't have browser console access right now.
reproduction: 1) Log in, 2) Upload files, 3) Observe quota updates correctly within session, 4) Log out, 5) Log back in, 6) File tree loads and shows files, but quota stays at zero.
started: Works within a session. Broken on re-login. Unclear if it ever worked correctly across sessions.

## Eliminated

(No false hypotheses - root cause was identified on first hypothesis)

## Evidence

- timestamp: 2026-02-10T00:00:30Z
  checked: All call sites of fetchQuota in apps/web/src
  found: fetchQuota is called in exactly 4 places - all upload-related:
  1. apps/web/src/services/upload.service.ts:134 (after upload completes)
  2. apps/web/src/hooks/useFileUpload.ts:62 (before starting upload)
  3. apps/web/src/components/file-browser/EmptyState.tsx:85 (after upload in empty state)
  4. apps/web/src/components/file-browser/UploadZone.tsx:127 (after upload in drop zone)
     implication: No code path fetches quota on login, session restore, or app initialization

- timestamp: 2026-02-10T00:00:40Z
  checked: quota.store.ts initial state
  found: usedBytes defaults to 0, limitBytes defaults to 500*1024*1024. Store is zustand (in-memory), so resets to defaults on page reload / new session.
  implication: Without calling fetchQuota(), usedBytes will always be 0 after login

- timestamp: 2026-02-10T00:00:45Z
  checked: useAuth.ts login() and restoreSession() flows
  found: Neither login() nor restoreSession() call fetchQuota(). Login does steps 1-8 (Web3Auth -> backend auth -> vault init -> navigate). Session restore does refresh + vault load. Neither touches quota store.
  implication: Confirmed root cause - quota is never synced from backend on login

- timestamp: 2026-02-10T00:00:50Z
  checked: StorageQuota.tsx component
  found: Component only reads from store (usedBytes, limitBytes) - has no useEffect to fetch on mount
  implication: Component is a pure display component, never triggers its own data fetch

- timestamp: 2026-02-10T00:00:55Z
  checked: Backend GET /vault/quota endpoint (vault.controller.ts)
  found: Endpoint exists, is guarded by JWT, calls vaultService.getQuota(userId). Returns QuotaResponseDto with usedBytes, limitBytes, remainingBytes.
  implication: Backend is ready - the frontend just never calls it on init

- timestamp: 2026-02-10T00:01:10Z
  checked: Backend vaultService.getQuota() implementation
  found: Computes quota from database (SUM of pinned_cid.size_bytes), not in-memory. Persistent across sessions.
  implication: Backend correctly returns cumulative usage from all sessions - only the frontend call was missing

## Resolution

root_cause: fetchQuota() is never called on login, session restore, or app initialization. The quota store initializes with usedBytes=0 (zustand in-memory default). The only code paths that call fetchQuota() are upload-related (before/after upload). So within a session, the in-memory addUsage() calls keep the display updated during uploads, but on re-login the store resets to zero and nothing triggers a backend sync.
fix: Added useEffect to StorageQuota component that calls fetchQuota() on mount. Since the component only renders inside authenticated routes (FilesPage/SettingsPage via AppShell), this ensures the quota is always synced from the backend when the user sees the quota display.
verification: ESLint passes. All 22 existing tests pass (4 test files). The useEffect dependency [fetchQuota] is stable (zustand function reference) so it fires exactly once on mount. No regressions.
files_changed:

- apps/web/src/components/layout/StorageQuota.tsx
