# Phase 13: File Versioning - Context

**Gathered:** 2026-02-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Users can access and restore previous versions of their files. When file content changes, the previous version is automatically retained (old CID stays pinned on IPFS). Users can browse version history, download old versions, restore a previous version, and manually delete specific versions. Storage quota includes version storage. Auto-pruning enforces a 10-version limit per file.

Desktop FUSE mount does NOT expose version history — restore is web-only. Desktop writes create versions via the same mechanism but version browsing/restore is a web UI action.

</domain>

<decisions>
## Implementation Decisions

### Version encryption keys

- Each version stores its own `{ cid, fileKeyEncrypted, fileIv, size, timestamp }` in a `versions` array within `FileMetadata`
- New fileKey generated per version (not reused) — aligns with existing per-file key security posture
- Old versions are decryptable independently using their stored encrypted key

### Version history UI

- Claude's discretion on access point (file details dialog section/tab vs side panel vs dedicated dialog)
- Claude's discretion on information density per version entry (timestamp, size, version number — pick what's useful)
- Only past versions shown in history — current version is not listed (already visible in main file view)

### Restore behavior

- Restoring creates a NEW version — current content becomes a past version, restored content becomes new current
- Non-destructive: version chain grows (v1 → v2 → v3(restored v1))
- Confirmation dialog required before restore: "Restore version from [date]? Current version will be saved as a past version."
- Restore is web-only — not available from desktop FUSE mount
- Claude's discretion on post-restore feedback (toast, history refresh, etc.)

### Retention & pruning

- Maximum 10 versions per file (default, not configurable in v1)
- Auto-prune oldest version silently when limit reached on new version creation
- Users CAN manually delete specific old versions (each version entry has delete option)
- Version storage counts against the user's 500 MiB quota — all pinned content (current + versions) included

### Version creation triggers

- ALL content changes create versions: web re-upload, desktop FUSE write, text editor save
- Desktop FUSE writes use a 15-minute cooldown — only create a new version if the last version is older than 15 minutes. Intermediate saves overwrite current content without versioning.
- Web re-upload ALWAYS creates a version regardless of cooldown — intentional user action always worth preserving
- Text editor save follows the same cooldown as FUSE (15 minutes)

### Claude's Discretion

- Version history UI access point and layout (within existing app patterns)
- Information shown per version entry
- Post-restore user feedback mechanism
- Preview vs download-only for old versions (based on existing preview infrastructure)
- Cooldown implementation details (timestamp tracking in metadata vs client-side)

</decisions>

<specifics>
## Specific Ideas

- Architecture approach already decided in research: "stop unpinning old CIDs + metadata extension" — nearly free on IPFS, no new crypto needed
- Per-file IPNS metadata (Phase 12.6) provides the natural home for the `versions` array — each file's IPNS record holds its own version history
- Version entries need full crypto context (fileKeyEncrypted, fileIv) since each version uses a different symmetric key

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

_Phase: 13-file-versioning_
_Context gathered: 2026-02-19_
