# Project Research Summary

**Project:** CipherBox -- Milestone 2
**Domain:** Zero-knowledge encrypted cloud storage (sharing, search, MFA, versioning, advanced sync)
**Researched:** 2026-02-11
**Confidence:** MEDIUM-HIGH

## Executive Summary

Milestone 2 transforms CipherBox from a single-user encrypted storage demonstrator into a multi-user, feature-complete product. The research validates that the v1.0 architecture was designed with these features in mind: per-folder IPNS keypairs enable natural per-folder sharing, IPFS content-addressing makes versioning nearly free (stop unpinning old CIDs), and Web3Auth's threshold key scheme natively supports MFA. The dominant finding across all four research streams is that **most M2 features require zero new heavy dependencies**. They are protocol design and metadata schema problems, not technology selection problems. The existing cryptographic primitives (`eciesjs`, `@noble/*`, Web Crypto API) handle all required operations for sharing (ECIES re-wrapping), versioning (metadata extension), and search (client-side indexing).

The recommended approach is to build sharing around direct ECIES re-wrapping of folder keys per-recipient (the same pattern proven by Tresorit and ProtonDrive), implement versioning as a metadata schema extension that retains old CIDs instead of unpinning them, configure MFA through Web3Auth's built-in factor system rather than building a custom MFA layer, and implement search as a pure client-side operation against already-decrypted data in memory. **Read-only sharing must come first** -- this is the consensus across all four research tracks. Multi-writer IPNS is the single hardest unsolved problem and should be deferred entirely; no competitor has solved encrypted multi-writer folders either. The only genuinely new build target is the AWS Nitro TEE enclave (Rust binary), which is the highest-effort, highest-risk item and should ship last.

The key risks are: (1) breaking zero-knowledge guarantees during sharing implementation (folderKey leaking to server in plaintext), (2) incomplete share revocation (forgetting to rotate the folderKey when revoking access), (3) MFA enrollment accidentally changing the derived keypair and locking users out of their vaults, and (4) IPNS last-writer-wins causing silent data loss in shared folders with multiple writers. All four are preventable with the specific mitigations documented in the pitfalls research -- the patterns are well-understood from Tresorit, ProtonDrive, and Filen precedents.

## Key Findings

### Recommended Stack

The existing stack handles nearly everything. Only two lightweight client-side packages are truly new for the core feature set. The total bundle impact is under 10KB gzipped. Most Milestone 2 features need **ZERO new heavy dependencies**.

**New dependencies (confirmed needed):**

- `minisearch` ^7.2.0: Client-side full-text search engine -- TypeScript-native, 7KB gzip, zero deps, inverted index with O(log n) queries. Chosen over Fuse.js (O(n) per query) and FlexSearch (stale TS types).
- `idb` ^8.0.0: Promise-based IndexedDB wrapper -- 1KB gzip. For persisting encrypted search index and offline operation queue. Chosen over localForage (unnecessary fallback logic).

**Conditional dependencies (only if implementing CipherBox-layer MFA beyond Web3Auth):**

- `@simplewebauthn/browser` ^13.2.2 + `@simplewebauthn/server` ^13.2.2: WebAuthn passkey support -- TypeScript-first, actively maintained. Only if adding CipherBox-layer session MFA.
- `otpauth` ^9.5.0: TOTP generation/validation -- zero deps, RFC compliant. Only if CipherBox-level TOTP.
- `@scure/bip39` ^1.4.0: BIP-39 mnemonic generation -- same `@noble` ecosystem. Only if custom recovery phrase outside Web3Auth.

**Deferred dependencies (AWS Nitro TEE):**

- `@aws-sdk/client-kms` ^3.x: For NestJS orchestrator on parent EC2 instance.
- Rust enclave binary (separate build target): `aws-nitro-enclaves-nsm-api`, `ecies`, `ed25519-dalek`.

**What NOT to add (and why):**

| Library                   | Temptation               | Why Not                                                                                                                                      |
| ------------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Yjs / Automerge / SecSync | "CRDTs solve sync"       | CipherBox syncs encrypted metadata blobs, not collaborative documents. CRDTs add 50KB+ and require restructuring the entire metadata format. |
| Elasticsearch / Typesense | "Full-text search"       | Server-side search violates zero-knowledge. All search must be client-side.                                                                  |
| Fuse.js                   | "Fuzzy search"           | No inverted index (O(n) per query). MiniSearch is materially faster.                                                                         |
| localForage               | "IndexedDB wrapper"      | Unnecessary fallback logic. `idb` is lighter and more appropriate.                                                                           |
| Proxy re-encryption libs  | "Re-encrypt for sharing" | Direct ECIES re-wrapping with existing `eciesjs` is simpler and sufficient.                                                                  |
| jsonwebtoken              | "JWT for share tokens"   | `jose` already installed, supports all JWK/JWS/JWE operations.                                                                               |
| passport-simple-webauthn  | "Passport + WebAuthn"    | v0.1.0, 2 years stale. Use `@simplewebauthn/server` directly.                                                                                |

### Expected Features

**Must have (table stakes):**

- User-to-user folder sharing (read-only) with ECIES key re-wrapping -- every competitor has this
- Share invitation flow (invite by email/publicKey, accept/decline)
- Share revocation with folderKey rotation -- critical security requirement
- File name search (global, across all folders) -- expected once vault exceeds 100+ files
- Web3Auth MFA enablement (device share + backup phrase) -- mostly SDK configuration
- Automatic version creation on file update (retain old CIDs) -- nearly free on IPFS
- Version history view with restore capability
- Conflict detection (IPNS sequence-based)
- Sync status indicators

**Should have (differentiators):**

- Link-based sharing with URL fragment key (Tresorit/MEGA pattern, no account required)
- Password-protected share links (PBKDF2 key derivation)
- IPFS-native version immutability (cryptographic tamper-proof versions for free)
- Per-folder granular sharing (share subfolder without exposing parent -- better than Tresorit's tresor-level)
- WebAuthn/Passkey MFA factor
- Selective sync for desktop (per-folder IPNS makes this architecturally natural)

**Defer to v3+:**

- Read-write shared folders -- multi-writer IPNS is unsolved, no competitor has solved it for encrypted storage
- Full-text content search (encrypted index stored on IPFS) -- no major competitor offers this either
- CRDTs / automatic conflict merging
- On-demand file hydration for FUSE mount

### Architecture Approach

The architecture extends the existing system with minimal structural changes. Five key integration decisions emerged from the research:

1. **Sharing uses ECIES re-wrapping, NOT proxy re-encryption.** The owner's client decrypts the folderKey, re-encrypts it with the recipient's publicKey using the existing `wrapKey()` function. Share key delivery happens through a new backend `shares` table -- not via IPNS metadata, because recipients need access before they have the folderKey. The server stores only ECIES ciphertexts it cannot decrypt.

2. **Versioning is nearly free on IPFS.** Each file update already creates a new CID. The only change: stop unpinning old CIDs and add a `versions` array to FileEntry in the metadata schema. No new crypto, no new APIs, no new entities.

3. **MFA is mostly Web3Auth configuration.** Set `mfaLevel: 'optional'` and configure `mfaSettings`. The keypair produced is identical whether or not MFA is enabled -- MFA only affects how many factors are needed to reconstruct it. This means: vault keys stay the same, no re-encryption needed, seamless enable/disable.

4. **Search Tier 1 is trivial.** CipherBox already decrypts the full folder tree into memory on login. Searching file names against this in-memory data requires zero server interaction, zero new crypto, and produces <10ms query times for vaults under 10K files. MiniSearch adds an optional persistent index for Tier 2.

5. **Advanced sync defers write-conflict resolution.** Use optimistic concurrency: server returns 409 on stale IPNS sequence numbers. Client performs three-way merge on decrypted metadata. Conflict copies ("filename (conflict).ext") for irreconcilable changes. No CRDTs.

**New database entities (only 1 required for core features):**

- `shares` table: owner_id, recipient_id, recipient_public_key, folder_ipns_name, shared_folder_key_encrypted, shared_ipns_key_encrypted, permission, status, timestamps
- (Optional for CipherBox-layer MFA: `webauthn_credentials`, `totp_secrets`)

### Critical Pitfalls

The top 5 pitfalls across all 18 identified, ranked by severity:

1. **Sharing folderKey without ECIES re-wrapping breaks zero-knowledge (P1, CRITICAL)** -- The server must NEVER see a plaintext symmetric key. Always wrap with recipient's publicKey client-side. Add server-side format assertions rejecting plaintext-length key payloads. Network inspection test: verify no symmetric keys in API requests.

2. **Incomplete revocation: revoking access without rotating folderKey (P2, CRITICAL)** -- Revoked user retains cached key and can decrypt via IPFS gateways (IPFS content is public). On revocation: generate new folderKey, re-encrypt folder metadata, re-wrap for remaining recipients, re-publish IPNS. Accept that previously-downloaded content cannot be un-downloaded.

3. **MFA enrollment changes key derivation, locking user out of vault (P5, CRITICAL)** -- If MFA modifies Web3Auth's key derivation path, the output keypair changes and all encrypted data becomes inaccessible. Implement MFA as a gate on CipherBox API access AFTER Web3Auth returns the keypair, never as a key derivation input. **Must have integration test: publicKey unchanged after MFA enrollment.**

4. **Multi-writer IPNS causes silent data loss in shared folders (P3, CRITICAL)** -- Two users publishing to the same IPNS name simultaneously: last-writer-wins, changes silently lost. Prevention: read-only sharing only. Do NOT share ipnsPrivateKey. Defer write-sharing to v3.

5. **Version metadata bloats folder IPNS records (P9, HIGH)** -- 100 files x 10 versions = ~2.8MB metadata JSON, degrading load/publish times. Cap at 10 versions inline. Separate version manifests for older versions. Lazy-load history only when requested.

## Implications for Roadmap

Based on combined dependency analysis, feature interactions, and risk assessment, the research suggests 5 phases within Milestone 2.

### Phase 1: Foundation -- MFA + Versioning

**Rationale:** Both features are independent of each other and of sharing. MFA is the smallest surface area (SDK configuration, no backend changes, no crypto changes). Versioning extends the metadata schema to FolderMetadata v2, which must be stable before sharing adds its own schema requirements. Doing both first establishes the security posture and data model that downstream features depend on.

**Delivers:** Web3Auth MFA factor configuration UI, metadata v2 schema with version history, automatic version retention on file update, version history view/restore, retention policy enforcement.

**Addresses features:** Web3Auth MFA enablement, backup phrase, automatic version creation, version history, version restore, retention policy.

**Avoids pitfalls:** MFA enrollment breaking key derivation (P5) -- test publicKey invariance. Version storage explosion (P8) -- enforce retention limits from day one. Version metadata bloat (P9) -- cap at 10 versions inline.

**Stack needed:** No new dependencies. Existing `@web3auth/modal` mfaSettings. Existing TypeORM for metadata.

**Research flag:** Standard patterns. Skip `/gsd:research-phase`. Web3Auth MFA docs are clear. IPFS versioning is a metadata-only change.

### Phase 2: Sharing (Read-Only)

**Rationale:** Sharing is the highest-value feature gap (every competitor has it). It touches the most surface area (new backend entity, new API endpoints, crypto re-wrapping, UI). It depends on metadata v2 being stable from Phase 1. Read-only sharing avoids the multi-writer IPNS problem entirely.

**Delivers:** User-to-user read-only folder sharing, share invitation/acceptance flow, share revocation with folderKey rotation, user publicKey lookup API, SharedWithMe view, re-wrap crypto helpers.

**Addresses features:** User-to-user folder sharing (read), share invitation flow, share revocation, share notification, shared folder view.

**Avoids pitfalls:** FolderKey leakage to server (P1) -- ECIES re-wrapping only, server-side format assertions. Incomplete revocation (P2) -- folderKey rotation on revoke. Multi-writer conflicts (P3) -- read-only only, no IPNS key sharing. Shared folder TEE republishing (P13) -- allow shared users to register for republishing.

**Stack needed:** No new npm dependencies. New TypeORM entity (`shares`). New NestJS module with 6 endpoints.

**Research flag:** NEEDS `/gsd:research-phase` -- share revocation key rotation flow is the most complex protocol in M2. Test vector generation needed for ECIES re-wrapping.

### Phase 3: Link Sharing + Search

**Rationale:** Link sharing extends Phase 2's sharing infrastructure (share record storage, permission model). Search is independent but benefits from the folder metadata schema being finalized. Both are medium-complexity, self-contained features that can be developed in parallel within the same phase.

**Delivers:** Link-based sharing (URL fragment key), password-protected links, link expiration/download limits, global file/folder name search, search results with navigation.

**Addresses features:** Link-based sharing, link expiration, link password protection, download limits, file name search, folder name search, search results with navigation.

**Avoids pitfalls:** Link key leakage to server (P4) -- URL fragment only, static landing page, no analytics, `Referrer-Policy: no-referrer`. Search index leakage (P7) -- client-side only, no server communication. Stale index (P15) -- incremental updates tied to IPNS polling.

**Stack needed:** `minisearch` ^7.2.0 + `idb` ^8.0.0 for search (~8KB total gzipped). Web viewer for link sharing (static page).

**Research flag:** Link sharing NEEDS `/gsd:research-phase` -- the web viewer for unauthenticated access is a new page type that needs security review. Search Tier 1 is standard patterns (skip research).

### Phase 4: Advanced Sync + Desktop Enhancements

**Rationale:** Conflict resolution is a cross-cutting concern that must handle versioned files, shared folders, and all metadata types. It benefits from all other features being stable. Selective sync is desktop-specific and naturally scoped alongside conflict handling.

**Delivers:** IPNS sequence-based conflict detection, three-way merge for folder metadata, conflict copy creation, sync status indicators, selective sync for desktop, offline operation queue.

**Addresses features:** Conflict detection, conflict copies, conflict notification, selective sync, sync status indicators, offline edit queue.

**Avoids pitfalls:** Conflict resolution without plaintext (P11) -- client-side only, optimistic concurrency with 409 responses. Selective sync breaking tree traversal (P16) -- sync all metadata, selective sync controls file content only. Offline replay duplication (P17) -- idempotency keys per queued operation.

**Stack needed:** No new dependencies (reuse `idb` from Phase 3 for offline queue).

**Research flag:** NEEDS `/gsd:research-phase` -- three-way merge edge cases with encrypted metadata need exhaustive test matrix. Selective sync FUSE integration is uncharted territory for this codebase.

### Phase 5: CipherBox-Layer MFA + AWS Nitro TEE

**Rationale:** Optional hardening features that add defense-in-depth. CipherBox-layer WebAuthn/TOTP protects sensitive API operations beyond what Web3Auth MFA covers. AWS Nitro is the TEE fallback specified in the architecture. Both are independent of core user-facing features and can ship after the product is functionally complete.

**Delivers:** WebAuthn passkey registration/verification for CipherBox API, TOTP for sensitive operations, AWS Nitro Enclave binary (Rust), Nitro orchestrator integration in NestJS, fallback routing from Phala to Nitro.

**Addresses features:** WebAuthn/Passkey MFA, CipherBox session MFA for sensitive operations, AWS Nitro TEE fallback.

**Avoids pitfalls:** Recovery phrase backdoor (P6) -- hash-only storage, client-generated. MFA changes key derivation (P5) -- CipherBox MFA is an API gate, never touches Web3Auth.

**Stack needed:** `@simplewebauthn/server` + `@simplewebauthn/browser` ^13.2.2, `otpauth` ^9.5.0, `@aws-sdk/client-kms` ^3.x. Rust enclave binary (new build target: `aws-nitro-enclaves-nsm-api`, `ecies`, `ed25519-dalek`).

**Research flag:** NEEDS `/gsd:research-phase` -- AWS Nitro enclave is a new language (Rust), new build target, new infra. This is the highest-risk item in M2.

### Phase Ordering Rationale

- **MFA before Sharing:** Shared vaults should encourage MFA. MFA must be verified to NOT change key derivation before sharing relies on stable publicKeys.
- **Versioning before Sharing:** Establishes FolderMetadata v2 schema. Sharing adds fields to the same schema -- it must be stable first.
- **Read-only Sharing before Link Sharing:** Link sharing reuses share infrastructure. Read-only avoids the multi-writer IPNS problem entirely.
- **Search after Sharing:** Search needs to index both owned and shared folders. Metadata schema must be finalized.
- **Advanced Sync last among core features:** Cross-cutting concern that must handle all metadata types (versions, shares). Highest risk of subtle bugs if schema is still changing.
- **Nitro TEE last:** Separate build target (Rust), can be developed in parallel but should ship after core features are stable.

### Research Flags

Phases likely needing deeper research during planning:

- **Phase 2 (Sharing):** Share revocation key rotation protocol needs detailed test vectors. ECIES re-wrapping correctness must be validated end-to-end.
- **Phase 3 (Link Sharing):** Web viewer for unauthenticated access is a new security surface. URL fragment key handling needs security review.
- **Phase 4 (Advanced Sync):** Three-way merge edge cases with encrypted metadata. Selective sync FUSE integration.
- **Phase 5 (Nitro TEE):** Rust enclave binary, vsock communication, KMS attestation -- entirely new technology for this project.

Phases with standard patterns (skip `/gsd:research-phase`):

- **Phase 1 (MFA):** Web3Auth mfaSettings is documented SDK configuration.
- **Phase 1 (Versioning):** Metadata schema extension plus "stop unpinning old CIDs." Straightforward.
- **Phase 3 (Search Tier 1):** Client-side search against already-decrypted data using MiniSearch. Well-established pattern.

## Confidence Assessment

| Area         | Confidence  | Notes                                                                                                                                                                                                                   |
| ------------ | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stack        | HIGH        | Most features need zero new dependencies. The 2 new packages (minisearch, idb) are mature, TypeScript-native, and well-maintained. Versions verified via npm.                                                           |
| Features     | HIGH        | Table stakes validated against 8 competitors (Tresorit, ProtonDrive, Filen, MEGA, Cryptomator, Sync.com, NordLocker, Internxt). Sharing and versioning patterns directly confirmed by competitor whitepapers.           |
| Architecture | MEDIUM-HIGH | Integration model is sound -- sharing via backend shares table, versioning via metadata extension, search client-side only. Two areas at MEDIUM: conflict resolution merge strategy and Nitro TEE enclave architecture. |
| Pitfalls     | HIGH        | 18 pitfalls identified with specific prevention strategies. Top pitfalls (ZK violations in sharing, MFA key derivation) confirmed by multiple sources including Tresorit whitepapers and IPFS issue tracker.            |

**Overall confidence:** MEDIUM-HIGH

### Gaps to Address

- **Web3Auth MFA pricing:** The `mfaSettings` configuration requires Web3Auth's SCALE plan for production. Free on devnet. Verify current pricing before committing to Web3Auth MFA as the primary mechanism.
- **Multi-writer shared folders:** No clear pattern exists in any competitor for encrypted multi-writer folders. Deliberately deferred but needs a design proposal before v3.0.
- **Versioning + Sharing interaction:** When a folder with version history is shared, should the recipient see all versions or only current? This affects how many keys must be re-wrapped. Decide during Phase 2 planning.
- **Offline queue + share revocation race condition:** If a user queues offline edits to a shared folder and the owner revokes access meanwhile, the queued operations will fail on reconnect. Need a graceful handling path.
- **Metadata size at scale:** A vault with 1000+ files, each with 10 versions, across multiple shared folders could produce large metadata blobs. Monitor in practice; may need version manifest separation.
- **Content search (Tier 2):** No competitor offers true encrypted content search. The encrypted index approach (Bloom filter or inverted index stored on IPFS) is academically sound but unvalidated in consumer products. Defer and validate separately.

## Sources

### Primary (HIGH confidence)

- Tresorit folder sharing architecture -- ECIES re-wrapping pattern, key rotation on revocation
- Tresorit Encrypted Link Whitepaper -- URL fragment key delivery, password-protected links
- ProtonDrive Version History docs -- Retention policies, encrypted versioning patterns
- ProtonDrive Security model -- ECC-based sharing, zero-knowledge architecture
- Filen Cryptography docs -- AES-GCM, RSA sharing, HMAC search implementation
- Web3Auth MFA Documentation -- mfaSettings configuration, threshold key scheme, factor types
- IPFS/IPNS specifications -- Content addressing, IPNS sequence numbers, pinning
- SimpleWebAuthn npm package -- v13.2.2, TypeScript-first WebAuthn library
- MiniSearch npm package -- v7.2.0, TypeScript-native search engine

### Secondary (MEDIUM confidence)

- IPFS Kubo issue #8433 -- Multiple IPNS publishers causing conflicts (confirmed pattern)
- IronCore Labs: Solving Search Over Encrypted Data -- searchable encryption tradeoffs
- Understanding Leakage in Searchable Encryption (2024 ePrint) -- HMAC index privacy analysis
- Proxy Re-Encryption analysis -- evaluated and rejected in favor of direct ECIES re-wrapping
- Keeper Encryption Model docs -- record/folder key wrapping architecture validation

### Tertiary (LOW confidence)

- Bloom filter encrypted search (IEEE) -- academic approach, unvalidated in production
- CRDT dictionary and challenges -- evaluated and deferred to v3.0
- Zero-knowledge cloud storage limitations -- general landscape analysis

---

## Files Created

| File                                 | Description                                                                                  |
| ------------------------------------ | -------------------------------------------------------------------------------------------- |
| `.planning/research/STACK.md`        | Technology selections for M2 features. Confirmed minimal new deps.                           |
| `.planning/research/FEATURES.md`     | Feature landscape across 8 competitors. Table stakes and differentiators per category.       |
| `.planning/research/ARCHITECTURE.md` | Integration model, component boundaries, data flow changes, build order consensus.           |
| `.planning/research/PITFALLS.md`     | 18 pitfalls (7 critical, 6 high, 5 medium) with prevention strategies and detection methods. |
| `.planning/research/SUMMARY.md`      | This file. Synthesized findings with roadmap implications.                                   |

---

_Research completed: 2026-02-11_
_Ready for roadmap: yes_
