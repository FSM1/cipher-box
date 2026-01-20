# Phase 3: Core Encryption - Context

**Gathered:** 2026-01-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Shared crypto module for all encryption operations. Provides AES-256-GCM for file content encryption, ECIES secp256k1 for key wrapping, and Ed25519 for IPNS signing. This is infrastructure code consumed by later phases — no UI, no API endpoints.

</domain>

<decisions>
## Implementation Decisions

### Key derivation paths

- Unified VaultKey output — both social login (Web3Auth direct key) and external wallet (ADR-001 signature-derived) produce identical VaultKey type
- Callers don't need to know derivation source — simpler downstream code
- Crypto module exposes key hierarchy: `deriveRootKey()`, `deriveFolderKey(parent)`, `deriveFileKey(folder)`
- File keys are random per-file (not deterministic from folder+filename) — wrapped with folder key

### Memory lifecycle

- Keys cleared on tab close/refresh — no persistence to storage
- Silent reconnect on page refresh — Web3Auth restores session if valid, keys re-derived automatically
- External wallet users: cache EIP-712 signature in sessionStorage (~15 min) to reduce wallet popups on refresh
- No separate "lock vault" action — just logout, which clears everything

### Module packaging

- Standalone `@cipherbox/crypto` package shared between web and desktop
- Single source of truth, tested once
- Use Web Crypto API (browser-native, hardware-accelerated)

### File handling

- Memory-load for v1.0 (files up to 100MB loaded entirely before encryption)
- Streaming deferred to future version when AES-CTR is enabled

### Claude's Discretion

- Error message granularity — generic vs categorized (will follow security best practices to prevent oracle attacks)
- Corruption handling — whether to keep corrupted blobs or just show error
- Input validation style — throw exceptions vs Result types (will follow TypeScript best practices)
- Sync vs async API — based on Web Crypto API constraints (likely all async)

</decisions>

<specifics>
## Specific Ideas

- "For MVP v1.0 I think loading into memory is fine. Once AES CTR is enabled in future versions, this can be updated to also read, encrypt and upload the streams."
- Key hierarchy exposed as explicit functions rather than just primitives — makes vault structure clear to callers

</specifics>

<deferred>
## Deferred Ideas

- Streaming encryption/decryption — future version with AES-CTR
- Inactivity timeout auto-lock — could be added post-v1.0 as security enhancement

</deferred>

---

_Phase: 03-core-encryption_
_Context gathered: 2026-01-20_
