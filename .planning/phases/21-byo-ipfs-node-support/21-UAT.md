---
status: diagnosed
phase: 21-byo-ipfs-node-support
source: 21-VERIFICATION.md (human_verification items)
started: 2026-06-10T16:05:00Z
updated: 2026-06-10T16:35:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Settings page STORAGE tab functional test

expected: Settings shows tabs incl. STORAGE; STORAGE shows pinning mode radio; selecting external/dual reveals endpoint and auth token fields; connection test button fires a TEE-routed probe and shows inline results
result: pass
note: Four tabs render (LINKED METHODS, SECURITY, STORAGE, VAULT — VAULT added by phases 39/40, not a deviation). Radio selection works; endpoint/token fields hidden under cipherbox mode, revealed under external. Save button correctly gated on a successful connection test (StorageTab.tsx:414).

### 2. TEE-routed connection test credential flow

expected: Entering endpoint+token and clicking test triggers ECIES encryption of credentials, POST to /tee/connection-test, and displays latency/success. No plaintext credentials in network traffic.
result: pass
note: Request body contained only {"encryptedConfig":"<ECIES hex blob>","epoch":1} — dummy token never appeared in plaintext (verified with captured request bodies). With the local TEE worker running (simulator mode, epoch 1 key matches DB), the inline result rendered "> connected (10ms) // detected: kubo kubo/0.40.0/882b7d2/docker". Failure path also renders inline (observed against a worker missing the route).

### 3. Advisory quota badge visible for BYO users

expected: With isByoUser=true, quota bar shows ADVISORY badge and advisory hint instead of enforced quota display
result: issue
reported: "Badge and hint render correctly when is_byo_user=true is set directly in the DB ('ADVISORY' + 'storage is managed by your node. this total is approximate.'). But nothing in apps/web ever calls PATCH /vault/byo-status — saving external/dual mode does not set the flag, so the badge is unreachable through the product flow."
severity: major

### 4. Migration progress UI polling and controls

expected: After saving a provider change, MigrationProgress appears immediately and polls every 5 seconds; pause/resume/cancel work; completed state shows success
result: pass
note: Component renders, polls every 5s while active, pause and resume both work (verified live against a running 57-CID migration), completed state shows success message. Cancel intentionally not exercised (would have killed the real migration). Three defects observed — see Gaps: stale-job polling never restarts after save; API batch timeout causes double-counted stats; completed message shows contradictory numbers ("57 pins transferred" + "33 pins failed" on a 57-CID job).

### 5. BYO config loads at login and activates pinWithMode for uploads

expected: Logging in with a BYO-configured account, uploads use the active pinning mode; pin to the BYO node is attempted
result: pass
note: After saving external mode and re-logging in, uploaded uat-21-byo-upload.txt (4 KB) through the app. Upload completed with zero /ipfs/upload relay calls (content and metadata went directly to the node) and new pins appeared on byo-ipfs-kubo (verified via ipfs pin ls diff). Depends on the unbound-fetch fix (9789efa8f) — pre-fix this path threw Illegal invocation.

## Summary

total: 5
passed: 4
issues: 1
pending: 0
skipped: 0
blocked: 0

## Gaps

- truth: 'Saving external/dual pinning mode marks the user as BYO so the advisory quota display activates'
  status: failed
  reason: 'Badge rendering pipeline verified working end-to-end (API advisory field -> quota.store -> StorageQuota.tsx:39), but the web app contains no caller of PATCH /vault/byo-status. The flag must be self-reported by the client (vault params are encrypted; the server cannot infer pinning mode), and the StorageTab save flow never does it.'
  severity: major
  test: 3
  root_cause: 'Missing integration: StorageTab save flow does not call vault byo-status endpoint after persisting pinning config. grep confirms zero references to byo-status/isByoUser in apps/web/src.'
  artifacts:
  - path: 'apps/web/src/components/settings/StorageTab.tsx'
    issue: 'save flow persists pinning config but never PATCHes /vault/byo-status'
    missing:
  - 'Call vault byo-status (true) when saving external/dual mode, (false) when reverting to cipherbox'
    debug_session: ''

- truth: 'MigrationProgress starts polling when a new migration begins after a previous one ended in a terminal state'
  status: failed
  reason: 'With a prior failed job on record, the component fetched once at mount, saw terminal status, stopped polling permanently (MigrationProgress.tsx:44), and kept displaying the stale job as "migrating: 0/39 pins" while a new 57-CID migration ran server-side. Remounting (navigating away and back) was required to pick up the running job.'
  severity: minor
  test: 4
  root_cause: 'Poll loop exits permanently on terminal status and the save flow has no signal to restart it; also a failed job renders with the "migrating:" label.'
  artifacts:
  - path: 'apps/web/src/components/settings/MigrationProgress.tsx'
    issue: 'poll() returns permanently on TERMINAL_STATUSES; no restart trigger from save; failed status rendered as "migrating:"'
    missing:
  - 'Restart polling after a provider-change save (lift a restart signal into MigrationProgress or key the component on migration id)'
  - 'Render failed jobs as failed, not "migrating:"'
    debug_session: ''

- truth: 'Migration statistics are accurate (migrated + failed <= total)'
  status: failed
  reason: 'Completed job recorded 44 migrated + 33 failed on a 57-CID migration (77 > 57); UI showed "migration complete. 57 pins transferred." alongside "33 pins failed". API-side batch call aborts at 120s while TEE worker batches can exceed that (observed 130s), the worker continues processing, and retried batches double-count.'
  severity: minor
  test: 4
  root_cause: 'MigrationProcessor HTTP timeout (120s) shorter than worst-case worker batch duration; aborted batches are retried while the worker already processed them, double-counting stats. Worker-side per-CID failures also re-counted on retry.'
  artifacts:
  - path: 'apps/api/src/migration (MigrationProcessor)'
    issue: 'batch timeout shorter than worker batch worst case; no idempotency on retried batch accounting'
    missing:
  - 'Raise/remove batch timeout or make batch accounting idempotent (e.g. worker reports per-CID results keyed by CID; API upserts)'
    debug_session: ''

## Environment Notes

Local TEE worker now runs in Docker (image built from apps/tee-worker):
container `cipherbox-tee-worker`, host port 3002, TEE_MODE=simulator,
CIPHERBOX_ENVIRONMENT=development. Simulator keys are HKDF-derived from a
fixed seed, so its epoch-1 public key matches the DB exactly. The API must
run with TEE_WORKER_URL=http://localhost:3002 and the matching
TEE_WORKER_SECRET (currently passed as process env to pnpm dev; persist to
apps/api/.env to keep). Endpoint for the BYO node must be the host LAN IP
(http://192.168.133.12:5002), reachable from both the browser and the TEE
container — localhost is not, from inside the container.

Account state changed during testing: pinning mode saved as "external only"
(http://192.168.133.12:5002) and vaults.is_byo_user set to true (manually,
matching the now-real BYO configuration). 2026-03 dev-data CIDs that no
longer resolve account for most genuine migration failures.
