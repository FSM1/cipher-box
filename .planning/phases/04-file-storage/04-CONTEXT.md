# Phase 4: File Storage - Context

**Gathered:** 2026-01-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Upload and download encrypted files via IPFS relay. Users can upload files up to 100MB, download and decrypt them, delete files (unpin from IPFS), and perform bulk upload/delete operations. Storage quota enforces 500 MiB limit. Folder organization is a separate phase.

</domain>

<decisions>
## Implementation Decisions

### Upload UX

- Overall batch progress bar (not per-file), showing total progress across all selected files
- Sequential uploads (one at a time) for v1 — parallel uploads deferred for future infrastructure improvements
- Auto-retry 3 times on upload failure, then fail with message
- Cancel button visible during upload — user can cancel anytime, partial data cleaned up

### Download behavior

- Full in-memory download then decrypt (acceptable for v1's 100MB limit)
- Stream-to-disk approach deferred for future when larger files supported
- Browser download dialog (standard "Save As" behavior) after download completes
- Original filename stored encrypted in metadata, decrypted on download
- Progress indicator shown during download for larger files

### Quota enforcement

- Check quota both before upload starts AND during upload (pre-check + verify)
- Always-visible quota bar showing used/total (e.g., in header or sidebar)
- Block upload with clear message if would exceed quota: "Not enough space (X of 500MB used)"
- Warning thresholds at 80% and 95% — subtle indicator color changes

### Claude's Discretion

- Retry backoff strategy (exponential vs fixed delay)
- Error notification style (toast vs modal) for final failure after retries
- Download retry behavior on network failure
- Exact progress bar styling and placement
- Quota bar visual design

</decisions>

<specifics>
## Specific Ideas

- User mentioned sequential uploads are fine for v1, but wants parallel uploads in future versions depending on infrastructure
- Stream-to-disk download flow noted as sensible for future non-AES-CTR modes with larger files
- Errors should be logged to browser console for debugging

</specifics>

<deferred>
## Deferred Ideas

- Parallel concurrent uploads (3+) — future infrastructure improvement
- Stream-to-disk downloads for files >100MB — future version

</deferred>

---

_Phase: 04-file-storage_
_Context gathered: 2026-01-20_
