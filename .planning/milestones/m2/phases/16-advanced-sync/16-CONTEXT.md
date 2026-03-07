# Phase 16: Advanced Sync - Context

**Gathered:** 2026-03-03
**Status:** Ready for planning

<domain>
## Phase Boundary

Conflict detection via API-level optimistic concurrency on IPNS publishes. When two devices modify the same folder concurrently, the second publish is rejected and the client re-syncs before retrying.

**Rescoped from original roadmap:** Offline queue and idempotent replay deferred to Milestone 4. This phase delivers conflict detection only.

</domain>

<decisions>
## Implementation Decisions

### Conflict detection mechanism

- API-level optimistic concurrency: client sends expected sequence number with publish request
- API compares against stored sequence number in `folder_ipns` table
- If mismatch (another device published since client's last poll), API rejects with a conflict response
- Client re-syncs (re-polls to get latest remote state) then retries the operation
- No client-side IPNS resolution for conflict checks — DB-cached CID would return stale data for fresh records

### Conflict scope

- Folder IPNS records only — per-file IPNS uses last-write-wins
- Versioning (Phase 13) is the safety net for per-file content conflicts
- No three-way merge or auto-merge of folder metadata — deferred to M4

### User experience

- Reuse existing sync status indicator in the top-right of the file browser component
- Extend indicator states to cover conflict/re-sync scenarios
- Conflict notification style is Claude's discretion (toast vs inline vs indicator state change)

### Platform scope

- Both web and desktop get conflict detection (API-level check applies to all clients)
- Desktop: on conflict rejection, send OS system notification ("Folder updated by another device, re-syncing") and automatically re-fetch remote metadata + retry
- Web: notification style is Claude's discretion, automatic re-sync and retry

### Claude's Discretion

- Web conflict notification style (toast, banner, or indicator state)
- Exact conflict response HTTP status code and error shape
- Whether to auto-retry after re-sync or require user to manually retry their action
- Re-sync backoff strategy if conflicts persist

</decisions>

<specifics>
## Specific Ideas

- The `folder_ipns` table already tracks sequence numbers — the API-level check builds on existing infrastructure
- This is deliberately lightweight: detect, alert, re-sync. No merge logic, no offline queue
- The conflict detection pattern could later be extended with merge logic in M4 without API changes

</specifics>

<deferred>
## Deferred Ideas

- **Auto-merge of non-conflicting folder changes** — three-way merge on encrypted folder metadata children arrays. High complexity, deferred to M4
- **Offline operation queue** — persist write operations in IndexedDB for replay on reconnect. Deferred to M4
- **Idempotent replay** — idempotency keys for queued operations to prevent duplicates. Tightly coupled to offline queue, deferred to M4 together
- **Per-file IPNS conflict detection** — currently covered by versioning safety net. Re-evaluate in M4

</deferred>

---

_Phase: 16-advanced-sync_
_Context gathered: 2026-03-03_
