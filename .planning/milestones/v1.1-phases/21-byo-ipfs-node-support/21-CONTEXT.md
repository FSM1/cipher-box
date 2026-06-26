# Phase 21: BYO-IPFS Node Support - Context

**Gathered:** 2026-03-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Users can configure their own IPFS node for data sovereignty, with a user-selectable pinning mode: CipherBox only (default), external only, or dual-pin (both). SDK-level support enables benchmarking external providers. Settings UI exposes configuration, connection testing, and migration between providers. IPNS publishes always route through CipherBox API regardless of pinning mode.

</domain>

<decisions>
## Implementation Decisions

### Pinning model

- **Three user-selectable modes:** CipherBox only (default), External only, Dual-pin (both)
- BYO-only mode: client pins directly to user's node via SDK, CipherBox node not used for storage
- Dual-pin mode: primary pin must succeed, secondary failure shows non-blocking warning ("Mirror to [node] failed — will retry")
- BYO-only mode: if user's node is unreachable, upload fails with clear error — no silent fallback to CipherBox
- All IPNS publishes still route through CipherBox API regardless of mode (optimistic concurrency preserved)

### Client-direct architecture

- **No server relay for IPFS operations** — client (SDK/sdk-core) talks directly to user's IPFS node
- CipherBox API role for BYO users: IPNS publishes, DB mutations, lightweight CID registration
- Lightweight CID registration endpoint: client reports CID + size after pinning to external node. Advisory quota tracking (no enforcement) for BYO users
- SDK-level provider abstraction enables benchmarking external providers before shipping to users

### Auth token security

- **Credentials stored in vault metadata on IPFS** — encrypted with user's key, decrypted client-side only
- Zero-knowledge preserved: server never sees IPFS node auth tokens
- Client decrypts credentials from vault metadata and uses them directly for SDK pinning operations

### Provider compatibility

- **Two protocols supported:** IPFS Pinning Service API (PSA) and Kubo RPC API (/api/v0/\*)
- PSA covers: Pinata, web3.storage, Filebase, any PSA-compatible service
- Kubo RPC covers: self-hosted Kubo nodes without PSA configured
- **Auto-detection during connection test:** probe endpoint (try Kubo /api/v0/id first, then PSA /pins), auto-select protocol
- User just enters URL + auth token — no manual protocol selection needed

### Connection test

- **Inline result** — click [--test connection] → spinner → success/failure with latency and detected protocol
- Connection test **validates CORS** as part of the check — if CORS fails, show provider-specific configuration instructions
- Block save until CORS and connectivity pass
- Terminal aesthetic consistent: `✓ connected (420ms) // detected: kubo rpc v0.34.0`

### Settings UI

- **New "STORAGE" tab** in Settings page (tabs: LINKED METHODS | SECURITY | STORAGE)
- Storage tab contains: pinning mode radio selector, endpoint + auth token fields (shown when external/dual selected), connection test button, advisory quota display
- **Save button pattern** — changes staged until user clicks [--save], with [--discard] option. Shows change indicators on modified fields.

### Pin migration

- **Background migration via TEE** when switching providers — TEE moves opaque encrypted blobs between nodes without accessing plaintext
- Client provides TEE with: CID list, source config (endpoint + encrypted auth token), destination config (endpoint + encrypted auth token)
- Auth tokens encrypted with TEE public key (ECIES) — same pattern as IPNS key enrollment
- TEE decrypts in-enclave, fetches from source, pins to destination, verifies CID match, zeroes credentials
- Progress tracked in DB, Settings UI shows migration progress bar with pause/cancel controls
- Old pins retained until migration confirms each CID on new provider

### Claude's Discretion

- Exact SDK provider abstraction interface design (beyond pin/unpin/status)
- Migration job queue implementation details (BullMQ job structure, retry policy)
- How migration progress is persisted and resumed
- Vault metadata schema extension for BYO config (field names, encryption approach)
- Advisory quota display formatting and thresholds
- Connection test timeout values
- CORS instruction content per provider type

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### IPFS provider architecture

- `apps/api/src/ipfs/providers/ipfs-provider.interface.ts` — Existing IpfsProvider interface (pin/unpin/get) that new SDK providers should mirror
- `apps/api/src/ipfs/providers/local.provider.ts` — Current Kubo RPC implementation, reference for Kubo protocol support
- `apps/api/src/ipfs/ipfs.controller.ts` — Current upload/unpin/get endpoints, shows quota check and CID recording flow

### Vault and quota

- `apps/api/src/vault/vault.service.ts` — checkQuota, recordPin, recordUnpin methods that need advisory mode for BYO users
- `apps/api/src/vault/entities/pinned-cid.entity.ts` — PinnedCid entity for CID tracking

### Settings UI

- `apps/web/src/routes/SettingsPage.tsx` — Current Settings page with tab navigation pattern (Linked Methods, Security)
- `apps/web/CLAUDE.md` — Web app coding guidelines (a11y, ARIA, CSS conventions)

### SDK packages

- `packages/sdk-core/` — Stateless operations where RemotePinningProvider will live
- `packages/sdk/` — Stateful CipherBoxClient that will orchestrate pinning mode selection

### TEE infrastructure

- `tee-worker/src/` — Existing Phala Cloud worker for IPNS republishing, pattern for migration jobs

### Specifications

- `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` — Encryption and key hierarchy (relevant for vault metadata extension)
- `.planning/REQUIREMENTS.md` — BYO-01 through BYO-07 requirements
- `.planning/ROADMAP.md` — Phase 21 success criteria (will need updating to reflect revised scope)

### Prior context

- `.planning/phases/19-ipns-resolution-improvement/19-CONTEXT.md` — IPNS routing decisions, Someguy deployment pattern
- `.planning/todos/done/2026-02-14-bring-your-own-ipfs-node.md` — Original BYO design questions and considerations

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `IpfsProvider` interface (`apps/api/src/ipfs/providers/ipfs-provider.interface.ts`): pin/unpin/get abstraction — SDK providers should follow similar contract
- `LocalProvider` (`apps/api/src/ipfs/providers/local.provider.ts`): Kubo RPC implementation, can serve as reference for SDK-side Kubo provider
- Settings tab navigation pattern (`apps/web/src/routes/SettingsPage.tsx`): Existing tabs with ARIA roles, keyboard handling — extend with STORAGE tab
- TEE key enrollment pattern (`tee-worker/`): ECIES wrapping with TEE public key for secure credential transfer

### Established Patterns

- Provider injection via NestJS DI (`IPFS_PROVIDER` token) — server-side, but SDK needs its own provider abstraction
- Vault metadata stored as encrypted JSON on IPFS — BYO config extends this schema
- BullMQ job queues for background work (republish scheduling) — migration jobs fit this pattern
- Advisory vs enforced patterns: quota is currently enforced, needs advisory mode toggle for BYO

### Integration Points

- `packages/sdk-core/` — New RemotePinningProvider (PSA) and KuboProvider implementations
- `packages/sdk/` — CipherBoxClient needs pinning mode awareness, provider selection logic
- `apps/web/src/routes/SettingsPage.tsx` — Add STORAGE tab
- `apps/api/src/vault/vault.service.ts` — Add lightweight CID registration endpoint, advisory quota mode
- `apps/api/src/` — New migration controller/service for TEE-based pin migration jobs
- `tee-worker/src/` — Migration worker alongside existing republish worker
- Vault metadata schema — Extend with BYO IPFS config (endpoint, encrypted auth token, provider type, pinning mode)

</code_context>

<specifics>
## Specific Ideas

- SDK-level benchmarking capability is a priority — need to validate external provider performance before exposing to users
- "The API load from handling users using their own IPFS infra should be absolutely minimal" — CipherBox API is just IPNS + DB for BYO users
- TEE migration follows same zero-knowledge pattern as IPNS republishing — opaque blob transfer, credentials decrypted only in enclave
- Connection test must validate CORS specifically, with provider-specific setup instructions on failure

</specifics>

<deferred>
## Deferred Ideas

- **S3-compatible storage** — pin to S3/Minio with CID-addressed layout. Interesting but diverges from IPFS protocol. Future phase if demand exists.
- **Client-side migration fallback** — if TEE migration isn't viable for some edge case, allow browser-based migration. Requires browser to stay open.
- **Migration scheduling** — schedule migrations for off-peak hours. v1.1 is immediate-start only.
- **Provider marketplace** — curated list of compatible IPFS providers with one-click setup. Future UX enhancement.

</deferred>

---

_Phase: 21-byo-ipfs-node-support_
_Context gathered: 2026-03-24_
