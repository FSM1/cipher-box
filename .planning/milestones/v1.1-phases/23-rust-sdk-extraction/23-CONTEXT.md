# Phase 23: Rust SDK Extraction - Context

**Gathered:** 2026-03-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Extract shared Rust crates mirroring the TypeScript SDK package hierarchy. Replace duplicated crypto/IPNS/metadata logic in the desktop FUSE code with crate imports. Add unit and integration tests at the same granularity as TypeScript. Organize existing three-platform FUSE code (macOS, Linux, Windows) into clean shared + platform-specific modules.

This phase is a structural refactoring — no new features. All existing desktop functionality (macOS FUSE-T SMB, Linux kernel FUSE, Windows WinFsp) is preserved and redistributed across crates.

</domain>

<decisions>
## Implementation Decisions

### Crate Architecture (five crates)

1. **`cipherbox-crypto`** — Pure crypto primitives + key derivation
   - AES-256-GCM encrypt/decrypt/seal/unseal
   - AES-256-CTR streaming encrypt/decrypt
   - ECIES secp256k1 wrap/unwrap
   - Ed25519 keypair generation, sign, verify
   - HKDF-SHA256 key derivation (all IPNS keypair derivations)
   - Utility functions (random generation, hex conversion)

2. **`cipherbox-core`** — CipherBox domain types, metadata schemas, IPNS records
   - FolderMetadata types + encrypt/decrypt
   - FileMetadata types + encrypt/decrypt
   - DeviceRegistry types + encrypt/decrypt
   - RecycleBinMetadata types + encrypt/decrypt
   - Vault blob v2 serialize/deserialize/detect
   - IPNS record creation + CBOR/Protobuf marshaling
   - Depends on `cipherbox-crypto` for primitives

3. **`cipherbox-api-client`** — Generated typed HTTP client from OpenAPI spec
   - Generated from `packages/api-client/openapi.json` (same spec as orval/TS)
   - Replaces hand-written `src/api/` HTTP code in desktop app
   - Mirrors the `@cipherbox/api-client` package workflow
   - Researcher to evaluate generators (openapi-generator with reqwest, progenitor, etc.)

4. **`cipherbox-fuse`** — Platform-agnostic FUSE abstractions + platform modules
   - Shared: InodeTable, MetadataCache, ContentCache, FileHandle, operations, dir_ops, read_ops, write_ops, helpers, decrypt, constants
   - `macos.rs` — FUSE-T SMB mount options, `diskutil unmount force` unmount, macOS quirks
   - `linux.rs` — Kernel FUSE mount options, `fusermount3 -u` unmount
   - `windows/` — WinFsp implementation (separate callbacks: mod.rs, operations.rs, read_ops.rs, write_ops.rs, dir_ops.rs)

5. **`cipherbox-sdk`** — Stateful orchestration (mirrors `@cipherbox/sdk` in TS)
   - SyncDaemon (IPNS polling loop)
   - WriteQueue (offline write queue)
   - FolderTree state, key cache, IPNS sequence tracking
   - CipherBoxClient struct
   - Desktop app becomes thin Tauri shell (commands/, tray/, main.rs)

### Crypto / Core Split Line

Mirrors the TypeScript `@cipherbox/crypto` / `@cipherbox/core` split exactly:

- **crypto keeps:** anything that is a pure cryptographic operation or key derivation, operating on raw bytes/keys
- **core gets:** anything that knows about CipherBox's domain model — metadata types/schemas, metadata encrypt/decrypt, vault blob, IPNS records
- The dividing question: "Does this function need to know what a FolderMetadata or VaultBlob looks like?" If yes → core. If it just operates on raw bytes/keys → crypto.

### Monorepo Layout

- New `crates/` top-level directory for all Rust crates (separate from `packages/` which is TypeScript)
- Cargo workspace root at repo root (`Cargo.toml` with `members = ["crates/*", "apps/desktop/src-tauri", "vendor/fuser"]`)
- Vendored fuser stays at `vendor/fuser/` as a patched dependency via `[patch.crates-io]` — not a workspace member

### Testing & Cross-Language Parity

- **Shared test vectors:** JSON files in `tests/vectors/` organized by crate (crypto/, core/). Both Rust and TypeScript test suites load the same vectors and assert identical output. Extends existing pattern in `crypto/tests.rs`.
- **Unit tests:** All shared data structures (InodeTable, MetadataCache, FileHandle, etc.) get unit tests within their respective crates.
- **Integration tests:** Crate-level integration tests for API surfaces.
- **CI parity gate:** CI step runs both Rust and TS vector suites — build fails if outputs diverge for the same input vectors.
- **Desktop E2E remains golden target:** Existing desktop E2E tests are the top-level verification. Unit and integration tests supplement, not replace, E2E.

### Migration Strategy

- Bottom-up extraction: crypto first, then core, then api-client, then fuse, then sdk
- Desktop app progressively replaces `src/crypto/*` imports with `cipherbox-crypto` and `cipherbox-core` crate imports
- Each crate extraction is a self-contained step — desktop app compiles and passes tests after each step

### Claude's Discretion

- OpenAPI generator choice for Rust client (openapi-generator vs progenitor vs other)
- Internal module organization within each crate
- Trait abstractions for platform-specific FUSE operations
- Error type hierarchy across crates
- Dependency version management within workspace
- Exact CI configuration for cross-platform builds and parity checks

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Architecture & Crypto Specs

- `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` — Key hierarchy, encryption model, IPNS metadata design
- `00-Preliminary-R&D/Documentation/DATA_FLOWS.md` — Sequence diagrams for upload/download/folder operations
- `00-Preliminary-R&D/Documentation/API_SPECIFICATION.md` — Backend endpoints the API client wraps

### Metadata Schemas

- `docs/METADATA_SCHEMAS.md` — All 10 metadata objects with field tables, encryption details, storage locations
- `docs/METADATA_EVOLUTION_PROTOCOL.md` — Rules for evolving metadata schemas

### TypeScript SDK (mirror target)

- `packages/crypto/src/index.ts` — TS crypto package exports (defines the crypto split line)
- `packages/core/src/index.ts` — TS core package exports (defines the core split line)
- `packages/sdk-core/src/index.ts` — TS sdk-core package exports
- `packages/sdk/src/index.ts` — TS stateful SDK exports
- `packages/api-client/openapi.json` — OpenAPI spec for generated client

### Existing Rust Code (extraction source)

- `apps/desktop/src-tauri/src/crypto/` — 12 files, ~2,500 LOC of crypto + metadata (extraction source for cipherbox-crypto + cipherbox-core)
- `apps/desktop/src-tauri/src/crypto/tests.rs` — Existing cross-language test vectors
- `apps/desktop/src-tauri/src/fuse/` — 11 files, ~3,500 LOC including all three platforms (extraction source for cipherbox-fuse)
- `apps/desktop/src-tauri/src/fuse/windows/` — WinFsp implementation
- `apps/desktop/src-tauri/src/api/` — 4 files, ~500 LOC of HTTP client (replaced by generated cipherbox-api-client)
- `apps/desktop/src-tauri/src/sync/` — 2 files, ~800 LOC of sync daemon + write queue (extraction source for cipherbox-sdk)
- `apps/desktop/src-tauri/src/state.rs` — AppState with key material (extraction source for cipherbox-sdk)
- `apps/desktop/src-tauri/Cargo.toml` — Current dependencies and features
- `vendor/fuser/src/channel.rs` — Patched fuser for FUSE-T socket compatibility

### Desktop App Architecture

- `apps/desktop/CLAUDE.md` — FUSE mount architecture, platform porting notes, vendored fuser details, debugging guide

### Prior Phase Context

- `.planning/phases/19.1-extract-core-crypto-sdk-as-shared-package/19.1-CONTEXT.md` — TypeScript SDK extraction decisions (the architecture this phase mirrors in Rust)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `src/crypto/tests.rs` — 100+ cross-language test vectors already verifying byte-identical output with TypeScript. Foundation for shared vector files.
- `src/crypto/` module structure — already organized by concern (aes.rs, ecies.rs, ed25519.rs, hkdf.rs, folder.rs, bin.rs, vault_blob.rs, ipns.rs). Maps cleanly to crate boundaries.
- `src/fuse/inode.rs`, `cache.rs`, `file_handle.rs` — Platform-agnostic data structures ready to move into cipherbox-fuse.
- `packages/api-client/openapi.json` — Ready for Rust code generation.

### Established Patterns

- `#[serde(rename_all = "camelCase")]` on all metadata structs — maintains JSON field name compatibility with TypeScript
- `zeroize` crate for sensitive data cleanup — must be preserved in cipherbox-crypto
- `#[cfg(target_os = "...")]` for platform-specific mount/unmount — translates to platform modules in cipherbox-fuse
- `#[cfg(feature = "fuse")]` / `#[cfg(feature = "winfsp")]` — existing feature flags for platform compilation

### Integration Points

- `apps/desktop/src-tauri/Cargo.toml` — Will change from local `src/crypto` modules to `cipherbox-crypto`/`cipherbox-core` crate dependencies
- `Cargo.toml` at repo root — New workspace definition pointing to `crates/*`, `apps/desktop/src-tauri`, `vendor/fuser`
- CI workflows — Need Rust build steps, cross-language vector parity checks, platform matrix

</code_context>

<specifics>
## Specific Ideas

- The five-crate hierarchy directly mirrors the five TypeScript packages: crypto, core, api-client, fuse (≈ sdk-core for platform ops), sdk
- OpenAPI-generated Rust client eliminates the hand-written API code and keeps Rust in sync with API changes automatically, same as the orval workflow for TypeScript
- Desktop app becomes a thin Tauri shell — just commands/, tray/, and main.rs wiring the crates together

</specifics>

<deferred>
## Deferred Ideas

- **wasm-bindgen target** — Crate architecture supports future wasm compilation for browser use, but no wasm work in this phase
- **Shared JSON Schema for Rust ↔ TypeScript types** — Could auto-generate types from a shared schema, but separate implementations verified by shared test vectors is sufficient for now
- **npm publishing of Rust crates via wasm** — Future consideration when external consumers exist

</deferred>

---

_Phase: 23-rust-sdk-extraction_
_Context gathered: 2026-03-24_
