# Codebase Concerns

**Analysis Date:** 2026-01-19

## Tech Debt

**Documentation Version Inconsistency:**
- Issue: Documentation files show inconsistent version numbers across the suite. API_SPECIFICATION.md is at 1.9.0, while PRD.md, TECHNICAL_ARCHITECTURE.md, and DATA_FLOWS.md are at 1.10.0
- Files: `Documentation/API_SPECIFICATION.md`, `Documentation/PRD.md`, `Documentation/TECHNICAL_ARCHITECTURE.md`, `Documentation/DATA_FLOWS.md`
- Impact: Confusion about which specification version to follow, potential implementation mismatches between components
- Fix approach: Establish single source of truth for version number, update all documentation to match, enforce version bump checks in CI

**Missing encryptionMode Field Backward Compatibility:**
- Issue: v1.1 streaming specification relies on client defaulting to "GCM" when encryptionMode field is missing, but no implementation exists yet to validate this assumption
- Files: `Documentation/TECHNICAL_ARCHITECTURE.md` (line 326), `Documentation/DATA_FLOWS.md` (line 200)
- Impact: Breaking change risk if backward compatibility not properly implemented when v1.1 launches
- Fix approach: Add unit tests for missing field handling before v1.1 release, document migration path explicitly

**PoC Harness Not Production-Ready:**
- Issue: Console PoC uses direct IPFS publishing instead of signed-record relay pattern specified for production. CLIENT_SPECIFICATION.md line 520 has warning but code divergence creates confusion
- Files: `poc/src/index.ts` (entire file), `Documentation/CLIENT_SPECIFICATION.md` (line 520)
- Impact: PoC validation cannot guarantee production relay endpoint correctness, potential for developers to copy wrong pattern
- Fix approach: Either implement relay pattern in PoC or move to separate validation-only directory with explicit "NOT FOR PRODUCTION" naming

**IPNS Key Storage Inconsistency:**
- Issue: Architecture documents specify IPNS private keys stored in encrypted form, but PoC stores IPNS key "names" in metadata as placeholder while actual keys live in IPFS keystore
- Files: `Documentation/TECHNICAL_ARCHITECTURE.md` (line 423-424), `poc/src/index.ts` (line 307-308, 332)
- Impact: PoC doesn't validate the actual production key storage/retrieval pattern, untested edge cases
- Fix approach: Update PoC to match production pattern OR clearly document the divergence in CLIENT_SPECIFICATION.md section 5

## Known Bugs

**Version Management Enforcement Gap:**
- Symptoms: `.claude/CLAUDE.md` specifies version 1.9.0 but multiple docs are at 1.10.0
- Files: `.claude/CLAUDE.md` (line 19), `Documentation/PRD.md` (line 2), `Documentation/TECHNICAL_ARCHITECTURE.md` (line 2)
- Trigger: Manual documentation updates without updating CLAUDE.md
- Workaround: Manual audit of versions before release

## Security Considerations

**PoC Private Key Handling:**
- Risk: PoC loads private key from `.env` file with dotenv override flag, creating risk of accidental key exposure in development
- Files: `poc/src/index.ts` (line 10, 549-551)
- Current mitigation: Documentation states "never logged" but no code-level enforcement
- Recommendations: Add explicit redaction for privateKey in any console output, implement runtime check to ensure no logging of hex values matching key length

**Missing Auth Tag Size Validation:**
- Risk: AES-GCM implementation assumes 16-byte tag size but no validation that ciphertext includes full tag before decryption attempt
- Files: `poc/src/index.ts` (line 71, 130-136)
- Current mitigation: Node.js crypto throws error on invalid tag, but error unclear to caller
- Recommendations: Add explicit buffer length check before decryption, throw descriptive error if ciphertext too short

**IPNS Publish Timeout Could Leave Inconsistent State:**
- Risk: If IPNS publish times out (pollTimeoutMs default 120s), metadata may be published to IPFS but not resolvable via IPNS, leaving orphaned CIDs
- Files: `poc/src/index.ts` (line 196-212, 269-289)
- Current mitigation: Pinned CID tracked in Set for cleanup, but orphan detection not implemented
- Recommendations: Implement transaction-like pattern with rollback on timeout, add orphan CID detection in teardown

## Performance Bottlenecks

**IPNS Resolution Polling:**
- Problem: PoC polls every 1.5s (default) for up to 120s waiting for IPNS to propagate
- Files: `poc/src/index.ts` (line 196-212, 556-557)
- Cause: IPFS/IPNS network eventual consistency, no push notification mechanism
- Improvement path: Implement exponential backoff (start 500ms, max 5s), add early success detection with local IPFS node status check

**Synchronous Metadata Tree Traversal:**
- Problem: buildFolderTree recursively fetches and decrypts all child metadata synchronously with depth limit of 10
- Files: `poc/src/index.ts` (line 441-490)
- Cause: Sequential IPNS resolution + IPFS fetch for each subfolder
- Improvement path: Implement parallel fetch with Promise.all for sibling folders, stream results as available

**No Metadata Caching Between Operations:**
- Problem: Each operation (rename, move, delete) fetches fresh metadata from IPFS even though harness may have recently fetched it
- Files: `poc/src/index.ts` (line 640, 658, 673, 697)
- Cause: Stateless operation design, no in-memory cache
- Improvement path: Add LRU cache keyed by `ipnsName:cid` with TTL matching poll interval (30s)

## Fragile Areas

**Metadata Encryption/Decryption Roundtrip:**
- Files: `poc/src/index.ts` (line 160-169)
- Why fragile: JSON.stringify followed by encryption, any non-standard JSON encoding breaks decryption
- Safe modification: Always use canonical JSON serialization, add schema validation before encryption
- Test coverage: Unit tests exist for encryption primitives but not for full metadata roundtrip with complex nested structures

**IPNS Name Resolution Iterator Pattern:**
- Files: `poc/src/index.ts` (line 179-194)
- Why fragile: AsyncIterable with type checking for both string and object responses, IPFS API return type changes could break
- Safe modification: Add comprehensive type guards, implement fallback parsing strategies
- Test coverage: No explicit tests for IPFS library version compatibility

**File Entry Removal by Name Matching:**
- Files: `poc/src/index.ts` (line 429-439)
- Why fragile: Decrypts every child name to find match, O(n) complexity, fails silently if decryption throws
- Safe modification: Add explicit error handling for decryption failures, consider metadata-level unique IDs
- Test coverage: No tests for name collision scenarios or decryption failures during search

## Scaling Limits

**Folder Children Count:**
- Current capacity: No limit enforced in PoC, but stress test supports up to process.env.STRESS_CHILDREN_COUNT
- Files: `poc/src/index.ts` (line 374-416, 558)
- Limit: Browser memory for web client (PRD specifies 1,000 files per folder), IPFS metadata block size (typically 256KB)
- Scaling path: Implement pagination/virtualization for large folders, split metadata into chunks

**IPNS Record Size:**
- Current capacity: Single IPNS record holds all folder metadata, logged size but not limited
- Files: `poc/src/index.ts` (line 99-111, 275-278)
- Limit: IPFS maximum record size ~1-2MB depending on node configuration
- Scaling path: Implement hierarchical metadata with multiple IPNS records, lazy-load subfolder metadata

**Pin Management:**
- Current capacity: All pinned CIDs tracked in-memory Set during single run
- Files: `poc/src/index.ts` (line 62, 214-222, 706-709)
- Limit: Production requires persistent pin tracking, memory exhaustion for large vaults
- Scaling path: Persist pin audit to database (already specified in API_SPECIFICATION.md volume_audit table), implement batched pin operations

## Dependencies at Risk

**ipfs-http-client v60.0.1:**
- Risk: Library at major version 60, breaking changes common in IPFS ecosystem, maintenance uncertainty
- Files: `poc/package.json` (line 16)
- Impact: IPNS publish/resolve API breakage would halt file operations
- Migration plan: Monitor js-ipfs/Helia migration path, implement adapter pattern to isolate IPFS API calls

**eciesjs v0.4.7:**
- Risk: Cryptography library with low major version, secp256k1 curve implementation critical to security
- Files: `poc/package.json` (line 15)
- Impact: Vulnerability in ECIES would compromise all encrypted keys, data unrecoverable
- Migration plan: Audit for maintained forks, consider migration to Web Crypto API SubtleCrypto.deriveKey with ECDH

**Web3Auth Integration (Not Yet Implemented):**
- Risk: Architecture fully dependent on Web3Auth for key derivation, service unavailable = auth broken
- Files: `Documentation/TECHNICAL_ARCHITECTURE.md` (line 580-586), `Documentation/PRD.md` (line 340-342)
- Impact: User lockout if Web3Auth service degraded, no implemented fallback
- Migration plan: Implement private key import/export per PRD section 8 FAQ, create recovery tool independent of Web3Auth

## Missing Critical Features

**Backend Signed-Record IPNS Relay Endpoints:**
- Problem: Production architecture requires `/ipns/publish` endpoint accepting BASE64-encoded signed IPNS records, but no implementation exists
- Files: `Documentation/API_SPECIFICATION.md` (line 548-578), `Documentation/DATA_FLOWS.md` (line 166-173, 409-411)
- Blocks: Production client implementation, PoC cannot validate production flow
- Priority: High - Core architectural pattern, cannot launch without it

**Client IPNS Record Signing Logic:**
- Problem: Specification describes client signing IPNS records with Ed25519 before relaying, but no reference implementation
- Files: `Documentation/TECHNICAL_ARCHITECTURE.md` (line 470-471), `Documentation/DATA_FLOWS.md` (line 165-173)
- Blocks: Web and desktop client authentication, metadata publishing workflow
- Priority: High - Week 6 deliverable per IMPLEMENTATION_ROADMAP.md

**Encryption Mode Detection and Streaming:**
- Problem: v1.1 requires MIME type detection and CTR mode selection, but no implementation or file type registry
- Files: `Documentation/DATA_FLOWS.md` (line 708-789), `Documentation/TECHNICAL_ARCHITECTURE.md` (line 220-245)
- Blocks: Video/audio streaming capability promised in v1.1 roadmap
- Priority: Medium - Deferred to v1.1, but foundation (encryptionMode field) must be present in v1.0

**Multi-Device Conflict Resolution:**
- Problem: Architecture specifies "last-write-wins" for v1 but no implementation of IPNS sequence number checking or conflict detection
- Files: `Documentation/TECHNICAL_ARCHITECTURE.md` (line 530-536), `Documentation/CLIENT_SPECIFICATION.md` (line 253)
- Blocks: Safe multi-device concurrent edits, data loss risk without this
- Priority: High - Week 10 deliverable per IMPLEMENTATION_ROADMAP.md

## Test Coverage Gaps

**IPNS Propagation Edge Cases:**
- What's not tested: Multiple simultaneous publishes to same IPNS name, publish failure recovery, sequence number conflicts
- Files: `poc/src/index.ts` (poll logic at line 196-212, publish at line 269-289)
- Risk: Silent data loss if newer metadata overwritten by stale publish
- Priority: High - Core reliability concern

**ECIES Key Wrapping with Different Curves:**
- What's not tested: PoC uses secp256k1 from @noble/secp256k1 but eciesjs may have different curve implementation
- Files: `poc/src/index.ts` (line 5, 139-145)
- Risk: Key wrapping incompatibility between PoC and production clients
- Priority: High - Cross-client compatibility required for multi-device

**Teardown Incomplete Pin Removal:**
- What's not tested: Pinata unpin failures are logged but not retried, orphaned pins accumulate across runs
- Files: `poc/src/index.ts` (line 224-233, 255-266, 706-716)
- Risk: Pinata quota exhaustion, cost overrun in production
- Priority: Medium - DevOps concern, not user-facing

**Metadata Size Exceeding IPFS Block Limits:**
- What's not tested: Stress test adds synthetic children but doesn't validate IPFS add success with large payloads
- Files: `poc/src/index.ts` (line 374-416)
- Risk: Silent failure when folder metadata exceeds node limits, folder becomes inaccessible
- Priority: Medium - Documented limit exists (1,000 files per folder) but not enforced

**Private Key Exposure via Error Messages:**
- What's not tested: Error scenarios where hex strings from failed crypto operations might leak key material in stack traces
- Files: `poc/src/index.ts` (all crypto operations, especially line 130-145)
- Risk: Development logs or production error monitoring could capture sensitive data
- Priority: High - Security hygiene, add sanitization to all error handlers

---

*Concerns audit: 2026-01-19*
