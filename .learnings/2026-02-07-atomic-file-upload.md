# Atomic File Upload

**Date:** 2026-02-07

## Context

Phase 7.1 (atomic file upload) was implemented across multiple GSD sessions. During the final UAT session (Playwright-automated, 6/6 tests passed), four pre-existing glitches were observed that together represent a major gap in upload UX and data persistence. Investigation of these glitches produced the learnings below.

## What I Learned

- **State machines need terminal transition verification:** The upload store defined a proper lifecycle (`idle -> encrypting -> uploading -> registering -> success`) but `setSuccess()` was never called after registration completed. Code verification (10/10) confirmed each individual transition existed, but didn't verify the full chain actually executed end-to-end. The modal and button both depended on reaching `success` or `idle` to reset.

- **Modals that block pointer events are especially dangerous:** The upload modal's backdrop intercepted all clicks with no escape hatch. When the modal's `onClose` is conditionally `undefined` (no close button rendered), and the status never reaches a dismissable state, the entire app becomes unusable. Workaround for Playwright: `document.querySelector('.modal-backdrop').remove()`.

- **Boolean flags are insufficient for async deduplication:** The auth refresh interceptor used `isRefreshing = true/false` to prevent concurrent refresh calls, but multiple 401 responses arriving in the same microtask can all read `false` before any writes `true`. The correct pattern is to store and share the refresh Promise itself, so all waiters subscribe to the same in-flight request.

- **IPNS is unreliable for primary data retrieval:** The delegated routing service (`delegated-ipfs.dev`) returns "routing: not found" for IPNS lookups. IPNS records are ephemeral (~48h TTL) and the public DHT doesn't reliably index them. The entire file browsing experience breaks on page reload because folder metadata can't be resolved. The server already stores `metadata_cid` in `folder_ipns` table on publish - this should be the primary lookup source with IPNS as secondary.

- **Pre-existing bugs compound:** These four issues were individually dismissable as "pre-existing" during Phase 7.1, but together they mean: upload works once per session, the modal traps you, auth degrades over time, and nothing persists across reloads. UAT surfaced all of them in sequence.

## What Would Have Helped

- A UAT step that explicitly tests "upload → reload page → files still visible" - this would have caught the IPNS resolve failure immediately
- End-to-end state machine tests (not just unit tests on individual transitions) that assert the upload store reaches `idle` or `success` after a complete upload flow
- A modal component contract that enforces "always dismissable" (e.g., TypeScript requiring an `onClose` prop, or the Modal component itself adding Escape handling regardless)

## Key Files

- `apps/web/src/stores/upload.store.ts` — upload state machine (setSuccess exists but unused)
- `apps/web/src/components/file-browser/UploadZone.tsx` — missing setSuccess() call after addFiles()
- `apps/web/src/components/file-browser/UploadModal.tsx` — visibility tied to status, onClose conditionally undefined
- `apps/web/src/components/file-browser/EmptyState.tsx` — same missing setSuccess() pattern
- `apps/web/src/lib/api/client.ts` — auth refresh interceptor with racy isRefreshing flag
- `apps/api/src/ipns/ipns.service.ts` — delegated routing resolve with no DB fallback
- `apps/web/src/hooks/useSyncPolling.ts` — 30s polling that hits 502 every cycle
