---
plan: 28-02
status: complete
started: 2026-03-28T04:35:00.000Z
completed: 2026-03-28T04:40:00.000Z
---

## Summary

Replaced all 15 `.catch(() => {})` patterns in production web code with `.catch((err) => logger.warn(...))` so IPFS unpin failures and AudioContext close failures are now visible in logs. Also fixed the one occurrence in `packages/sdk/src/client.ts` with `console.warn` (SDK doesn't use the web logger).

## Key Files

### Modified

- `apps/web/src/services/bin.service.ts` — 4 unpin catch patterns
- `apps/web/src/components/file-browser/ReplaceFileDialog.tsx` — 3 unpin catch patterns
- `apps/web/src/components/file-browser/AudioPlayerDialog.tsx` — 2 audioContext.close catch patterns
- `apps/web/src/hooks/useDropUpload.ts` — 2 catch patterns (unpin + module load)
- `apps/web/src/hooks/useFileVersions.ts` — 2 unpin catch patterns
- `apps/web/src/hooks/useFileOperations.ts` — 1 unpin catch pattern
- `packages/sdk/src/client.ts` — 1 unpin catch pattern

## Self-Check: PASSED

- [x] Zero `.catch(() => {})` patterns remain in production web code
- [x] All catch handlers log the error context
