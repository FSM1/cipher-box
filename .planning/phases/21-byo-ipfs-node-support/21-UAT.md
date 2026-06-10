---
status: partial
phase: 21-byo-ipfs-node-support
source: 21-VERIFICATION.md (human_verification items)
started: 2026-06-10T16:05:00Z
updated: 2026-06-10T16:45:00Z
---

## Current Test

[testing paused — 3 items outstanding, blocked on local TEE worker env]

## Tests

### 1. Settings page STORAGE tab functional test

expected: Settings shows tabs incl. STORAGE; STORAGE shows pinning mode radio; selecting external/dual reveals endpoint and auth token fields; connection test button fires a TEE-routed probe and shows inline results
result: pass
note: Four tabs render (LINKED METHODS, SECURITY, STORAGE, VAULT — VAULT added post-phase-21 by phase 39/40, not a deviation). Radio selection works; endpoint/token fields hidden under cipherbox mode and revealed under external. Connection test fires POST /tee/connection-test and renders the inline result (.connection-test-result) — observed rendering a failure result correctly.

### 2. TEE-routed connection test credential flow

expected: Entering endpoint+token and clicking test triggers ECIES encryption of credentials, POST to /tee/connection-test, and displays latency/success. No plaintext credentials in network traffic.
result: pass
note: Core security property VERIFIED with captured request bodies — the request contained only {"encryptedConfig":"<ECIES hex blob>","epoch":1}; the dummy token "uat-secret-token-DO-NOT-LEAK-12345" never appeared in plaintext anywhere in network traffic. Latency/success display could not be observed locally: the TEE worker round-trip is env-blocked (see Gaps) — the inline error path rendered correctly instead.

### 3. Advisory quota badge visible for BYO users

expected: With isByoUser=true, quota bar shows ADVISORY badge and advisory hint instead of enforced quota display
result: blocked
blocked_by: server
reason: 'isByoUser is set by saving external/dual mode, but the save button is gated on a successful connection test (StorageTab.tsx:414) which requires a working TEE worker — not available locally'

### 4. Migration progress UI polling and controls

expected: After saving a provider change, MigrationProgress appears immediately and polls every 5 seconds; pause/resume/cancel work; completed state shows success
result: blocked
blocked_by: server
reason: 'Partially observed: MigrationProgress renders ("migrating: 0/39 pins") and /migration/status polling was captured. But the migration job is stuck at 0/39 server-side (MigrationProcessor: TEE_WORKER_URL or TEE_WORKER_SECRET not configured), so pause/resume/cancel and the completed state could not be exercised'

### 5. BYO config loads at login and activates pinWithMode for uploads

expected: Logging in with a BYO-configured account, uploads use the active pinning mode; secondary/primary pin to the BYO node is attempted
result: blocked
blocked_by: server
reason: 'Full app flow blocked: cannot save external mode locally (connection-test gate). However the underlying provider path is now VERIFIED in a real browser: the actual kubo-provider.ts source (with the fix from 9789efa8f) pinned and unpinned data against the byo-ipfs-kubo Docker node (localhost:5002) using native fetch, confirmed node-side via ipfs pin ls (recursive). Negative control: the pre-fix unbound-fetch pattern throws "Illegal invocation" in the same browser. Remaining unverified: the in-app wiring from saved config to pinWithMode at upload time'

## Summary

total: 5
passed: 2
issues: 0
pending: 0
skipped: 0
blocked: 3

## Gaps

[none — no code defects found; 3 items blocked by local environment]

## Environment Blockers

All three blocked items trace to one root: no real TEE worker runs locally.

- TEE_WORKER_URL (default localhost:3001) collides with tools/mock-ipns-routing, which answers /health (so TeeService reports "healthy, epoch: undefined") but 404s /connection-test
- TEE_WORKER_SECRET is unset, so MigrationProcessor refuses to process jobs (one migration stuck at 0/39 from the 2026-06-10 pinning-mode switch)
- apps/tee-worker exists and exposes /connection-test, but binding it locally needs a free port (3002), a shared secret with the API, and epoch/key alignment with the DB (DB has epoch 1; a fresh simulator would mint a different keypair)

Unblocking these would also enable phase 35's 6 outstanding TEE UAT items.
