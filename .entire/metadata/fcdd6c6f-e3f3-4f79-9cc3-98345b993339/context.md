# Session Context

**Session ID:** fcdd6c6f-e3f3-4f79-9cc3-98345b993339

**Commit Message:** I was debugging issues with the login flow and something completely hang

## Prompt

I was debugging issues with the login flow and something completely hanging the browser during login . this is part of the debugging session described here: @.planning/debug/corekit-auth-uat.md

## Summary

No type errors. Here's the summary:

## Bug: Infinite polling loop crashes browser tab

**Root cause:** In `useDeviceApproval.ts`, `isPollingPending` was **React state** used both as:
1. A guard inside `pollPendingRequests` (in its `useCallback` deps)
2. Reset to `false` in `stopApproverPolling` (called in effect cleanup)

This created a dependency oscillation cycle:
- Effect starts polling → sets `isPollingPending = true` → re-render → `pollPendingRequests` gets new identity → effect cleanup fires → `stopApproverPolling` sets `isPollingPending = false` → re-render → `pollPendingRequests` gets new identity again → effect fires → starts polling again → **infinite loop**

Each cycle fired an immediate `void poll()` request, generating thousands of requests per second until Chrome ran out of network resources (`ERR_INSUFFICIENT_RESOURCES` x 12,962).

**Fix:** Converted `isPollingPending` from `useState` to `useRef`. Refs don't trigger re-renders and don't change callback identities, breaking the oscillation cycle. The polling guard still works correctly — it just doesn't cause React to re-render.

**Files changed:** `apps/web/src/hooks/useDeviceApproval.ts` — 4 edits, all changing `isPollingPending` state to `isPollingPendingRef` ref.

This was **not** a CoreKit `loginWithJWT` crash as suspected in ISSUE-001 — it was the device approval polling running wild and starving the browser of network resources.

## Key Actions

- - **Grep**: device-approval/pending
- - **Grep**: custom-instance
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/api/device-approval/device-approval.ts
- - **Grep**: pending|poll|interval|setInterval|useInterval
- - **Grep**: DeviceApprovalControllerGetPending|device-approval.*pending|useDeviceApproval
- - **Grep**: refetchInterval|refetch
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/hooks/useDeviceApproval.ts
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/components/mfa/DeviceApprovalModal.tsx
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/api/custom-instance.ts
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/hooks/useAuth.ts
