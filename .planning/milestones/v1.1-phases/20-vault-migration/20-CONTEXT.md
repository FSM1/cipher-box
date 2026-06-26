# Phase 20: Vault Migration - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Move rootFolderKey from the database `vaults` table to an IPFS vault blob v2 format, making the server store zero crypto material. Update all three clients (web, desktop Rust, recovery HTML) to read and write the new format. Deprecate encryptedRootIpnsPrivateKey (already HKDF-derivable). The server's role shifts from key escrow to coordination relay.

</domain>

<decisions>
## Implementation Decisions

### Migration trigger & timing

- Migration fires **on next login** for existing users — resolve current root blob, rewrite as v2 with encryptedRootFolderKey in header, republish to IPNS
- **No forced migration** for dormant accounts — they stay on v1 blobs indefinitely and migrate whenever they next log in. DB fallback always works for them.
- Migration stamps a **migratedAt timestamp** on the vault DB record
- After confirmed v2 blob write, both `encryptedRootFolderKey` AND `encryptedRootIpnsPrivateKey` columns are **set to NULL** on the vault row
- When all users have migrated, the columns can be **dropped via DB migration** (separate future step, not this phase)

### Login read strategy

- **Per-user phased rollout**: migrated users (migratedAt set) read rootFolderKey from IPFS blob v2; non-migrated users continue reading from DB via GET /vault
- **Target state**: IPFS-only read (no DB fallback) — but initially, migrated users get **silent DB fallback** if IPFS blob read fails
- The read strategy should be **flexible enough to switch and benchmark** IPFS-only vs DB-fallback approaches
- **Long-term**: once IPFS reliability is proven (Kubo performance improvements in-flight), transition to retry-then-error with no DB fallback
- Phase 22 will add full end-to-end login-to-vault timing instrumentation; for now, server-side /metrics provides visibility

### Cross-client write scope

- **Both web and desktop write blob v2** on root folder publishes — any client can trigger migration
- **Recovery tool (recovery.html) updated to read blob v2** — extracts rootFolderKey from IPFS without needing the CipherBox API (VAULT-05)
- Blob v2 serialization/deserialization logic lives in **@cipherbox/core** (TypeScript) — fits the crypto/core split line from Phase 19.1
- Desktop (Rust) implements the same v2 format independently following the shared spec

### IPNS key deprecation

- **Stop sending** encryptedRootIpnsPrivateKey on new vault init — all clients derive via HKDF
- API init-vault endpoint **accepts but ignores** the field if sent (backward compat with older clients, graceful deprecation)
- Column stays in DB but is NULL for new users
- Existing users: **NULL both crypto columns together** during v2 migration (single migration event)

### System readiness

- Phase 18 server-side Prometheus histograms exist for IPNS resolve/publish — sufficient for monitoring migration impact
- Phase 19 Someguy deployment provides reliable local IPNS routing
- **Kubo is the current performance bottleneck** — IPFS infra fixes are actively in-flight
- **Proceed and measure as we go** — silent DB fallback provides safety net while Kubo performance improves
- Risks are **partially mitigated** by Phase 19; remaining mitigation is in-progress via IPFS infra work
- The per-user migration flag + silent DB fallback means migration can be paused if metrics show problems

### Claude's Discretion

- Exact blob v2 byte layout (research proposes `0x02 | uint16 key_length | ECIES_key | AES_GCM_metadata` — final format at implementation time)
- v1 vs v2 detection heuristic details
- Migration retry logic if v2 blob write fails mid-login
- Test vector design for v2 blob parsing
- API endpoint changes to stop returning crypto columns for migrated users
- Error handling and logging specifics during migration

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Vault blob v2 format & migration strategy

- `.planning/research/ARCHITECTURE.md` §3.1.1 — Vault blob v2 format specification, login flow change, dual-write migration strategy
- `.planning/research/ARCHITECTURE.md` §3.1.2 — encryptedRootIpnsPrivateKey elimination rationale
- `.planning/research/PITFALLS.md` — Vault migration pitfalls (race conditions, version detection, metadata evolution protocol)

### Architecture & crypto specs

- `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` — Key hierarchy, encryption model, vault lifecycle
- `00-Preliminary-R&D/Documentation/DATA_FLOWS.md` — Sequence diagrams for vault init, login, key derivation

### Metadata evolution

- `docs/METADATA_SCHEMAS.md` — All metadata objects including vault format
- `docs/METADATA_EVOLUTION_PROTOCOL.md` — Rules for evolving metadata schemas (blob v2 is a breaking change requiring version bump)

### Current vault implementation (extraction sources)

- `packages/core/src/vault/init.ts` — initializeVault, encryptVaultKeys, decryptVaultKeys (v2 blob logic goes here)
- `packages/core/src/vault/types.ts` — VaultInit, EncryptedVaultKeys types (extend for v2)
- `apps/api/src/vault/vault.service.ts` — Server-side vault CRUD, getVault, initializeVault, getExportData
- `apps/api/src/vault/entities/vault.entity.ts` — Vault entity with encryptedRootFolderKey, encryptedRootIpnsPrivateKey columns
- `apps/api/src/vault/dto/init-vault.dto.ts` — InitVaultDto (encryptedRootIpnsPrivateKey becomes optional)

### Client consumers

- `apps/web/src/hooks/useAuth.ts` — Web login flow: decryptVaultKeys call, vault store hydration
- `apps/web/src/stores/vault.store.ts` — Zustand vault state (rootFolderKey, rootIpnsKeypair)
- `apps/desktop/src-tauri/src/commands/vault.rs` — Desktop vault init + fetch_and_decrypt_vault (Rust v2 parsing)
- `apps/web/public/recovery.html` — Standalone recovery tool (needs v2 blob parsing)

### SDK architecture (Phase 19.1 context)

- `.planning/phases/19.1-extract-core-crypto-sdk-as-shared-package/19.1-CONTEXT.md` — Package split decisions, @cipherbox/core scope

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `@cipherbox/core vault/init.ts`: encryptVaultKeys/decryptVaultKeys — extend with v2 blob serialize/deserialize functions
- `@cipherbox/crypto`: wrapKey/unwrapKey (ECIES), deriveVaultIpnsKeypair (HKDF) — used as-is for v2 blob construction
- `DelegatedRoutingClient` + `IpnsService.resolveRecord()`: IPNS resolve with DB fallback — reuse for v2 blob fetch on login
- `MetricsService`: Existing IPNS histograms — add migration-specific counters (v2_write_success, v2_read_fallback_to_db)
- Desktop `crypto::ecies::unwrap_key`, `crypto::hkdf::derive_vault_ipns_keypair` — Rust equivalents for v2 parsing

### Established Patterns

- **ECIES key wrapping**: All encrypted key material uses wrapKey/unwrapKey with user's secp256k1 key
- **Hex encoding for API transport**: All binary fields hex-encoded in DTOs, Buffer in TypeORM entities
- **HKDF vault IPNS derivation**: Both TypeScript and Rust already derive IPNS keypair deterministically
- **AES-GCM JSON metadata format**: Root folder metadata is `{ iv: hex, data: base64 }` — blob v2 prepends the key header before this

### Integration Points

- `packages/core/src/vault/` — New blob v2 module (serialize, deserialize, detect version)
- `apps/api/src/vault/vault.service.ts` — Add migratedAt column handling, stop returning crypto columns for migrated users
- `apps/api/src/vault/entities/vault.entity.ts` — Add migratedAt nullable timestamp column
- `apps/api/src/vault/dto/init-vault.dto.ts` — Make encryptedRootIpnsPrivateKey optional
- `apps/web/src/hooks/useAuth.ts` — Add v2 blob read path on login, migration trigger
- `apps/desktop/src-tauri/src/commands/vault.rs` — v2 blob parsing in fetch_and_decrypt_vault
- `apps/desktop/src-tauri/src/fuse/mod.rs` — v2 blob writing on root folder publish
- `apps/web/public/recovery.html` — v2 blob parsing for independent recovery
- DB migration: Add `migrated_at` column to vaults table, make crypto columns nullable

</code_context>

<specifics>
## Specific Ideas

- User wants the system to be flexible enough to benchmark IPFS-only vs DB-fallback login paths — the per-user migration flag enables this naturally
- Kubo performance is the current bottleneck — the silent DB fallback provides a safety net while IPFS infra fixes are in-flight
- The migration is a single atomic event per user: login → write v2 blob → stamp migratedAt → NULL both crypto columns
- "Longer term, if consistent operation with only IPFS becomes acceptable" — the transition from silent DB fallback to retry-then-error is a future configuration change, not code change

</specifics>

<deferred>
## Deferred Ideas

- **Column DROP migration** — after all users migrated, drop encryptedRootFolderKey and encryptedRootIpnsPrivateKey columns. Separate future migration, not this phase.
- **IPFS-only retry-then-error mode** — transition from silent DB fallback to hard IPFS-only after Kubo performance proves out. Configuration change, not code change.
- **Full login-to-vault E2E timing** — Phase 22 scope (PERF-06)
- **Forced migration for dormant accounts** — not needed; they migrate on next login whenever that is

</deferred>

---

_Phase: 20-vault-migration_
_Context gathered: 2026-03-23_
