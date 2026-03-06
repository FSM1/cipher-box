# Codebase Concerns

**Analysis Date:** 2026-01-20

## Tech Debt

**Single 700-line monolithic POC file:**

- Issue: All POC functionality in one file (`00-Preliminary-R&D/poc/src/index.ts` - 702 lines) without modular separation
- Files: `00-Preliminary-R&D/poc/src/index.ts`
- Impact: Makes testing individual components impossible, increases cognitive load, harder to refactor
- Fix approach: Extract into modules (crypto.ts, ipfs.ts, folder.ts, types.ts) before building production code

**Legacy POC file still present:**

- Issue: The original 702-line monolithic POC (`00-Preliminary-R&D/poc/src/index.ts`) remains in the repo alongside the modular production code in `apps/`, `packages/`, and `tee-worker/`
- Files: `00-Preliminary-R&D/poc/src/index.ts`, `apps/web/`, `apps/api/`, `apps/desktop/`, `tee-worker/`
- Impact: New contributors may confuse the PoC with the current implementation. The PoC uses outdated patterns (ipfs-http-client, direct console logging)
- Fix approach: Treat `00-Preliminary-R&D/poc/` as historical reference only; all new work goes in `apps/*`, `packages/*`, and `tee-worker/`

**Console logging throughout POC:**

- Issue: 21 console.log/warn/error calls embedded in POC code
- Files: `00-Preliminary-R&D/poc/src/index.ts`
- Impact: Not suitable for production; no structured logging; no log levels
- Fix approach: Production code should use a logging library (e.g., winston, pino) with structured output

**Type assertions for IPFS client:**

- Issue: Type assertion workaround for ipfs-http-client incompatibility
- Files: `00-Preliminary-R&D/poc/src/index.ts:285`
- Impact: `type: "ed25519" as unknown as "Ed25519"` suggests library type definitions don't match implementation
- Fix approach: Verify library version compatibility; consider using @helia/ipns for newer IPNS support

## Known Bugs

**Disabled IPNS record size logging:**

- Symptoms: `logIpnsRecordSize` function is a no-op that does nothing
- Files: `00-Preliminary-R&D/poc/src/index.ts:86-89`
- Trigger: Any IPNS publish operation
- Workaround: Comment states "The routing API is not available in ipfs-http-client v60"

**IPFS HTTP client version limitations:**

- Symptoms: Routing API incompatible with ipfs-http-client v60
- Files: `00-Preliminary-R&D/poc/package.json:16` (ipfs-http-client@60.0.1)
- Trigger: Attempting to use routing APIs
- Workaround: Feature disabled; recent commit `3010cdd` removed incompatible routing API usage

## Security Considerations

**Private key loaded from environment:**

- Risk: POC loads ECDSA_PRIVATE_KEY from .env file; production must never persist keys
- Files: `00-Preliminary-R&D/poc/src/index.ts:527-529`, `00-Preliminary-R&D/poc/.env.example`
- Current mitigation: .env.example documents the pattern; README warns this is not production code
- Recommendations: Production must derive keys via Web3Auth per TECHNICAL_ARCHITECTURE.md

**No memory zeroing for sensitive data:**

- Risk: Private keys, folder keys, and file keys may remain in Node.js memory after use
- Files: `00-Preliminary-R&D/poc/src/index.ts` (entire file uses Uint8Array for keys without explicit clearing)
- Current mitigation: None in POC
- Recommendations: Production code must explicitly zero buffers after crypto operations (per CLAUDE.md guideline)

**IPFS node credentials in environment:**

- Risk: IPFS API endpoint exposed in .env
- Current mitigation: Kubo API bound to localhost only in dev
- Recommendations: Production should use network-level access controls or authentication

**No input validation on crypto operations:**

- Risk: POC assumes all inputs are valid (no checks for key length, IV size, etc.)
- Files: `00-Preliminary-R&D/poc/src/index.ts:101-115` (aesGcmEncrypt/Decrypt)
- Current mitigation: None
- Recommendations: Production must validate key sizes (32 bytes), IV sizes (12 bytes), tag presence

## Performance Bottlenecks

**Sequential IPNS publishing:**

- Problem: Each folder publish waits for IPNS propagation before continuing
- Files: `00-Preliminary-R&D/poc/src/index.ts:174-190` (waitForIpns), `00-Preliminary-R&D/poc/src/index.ts:264`
- Cause: IPNS resolution is eventually consistent; POC polls until expected CID appears
- Improvement path: Production could batch updates, use optimistic UI, or implement background sync

**Full file content buffering:**

- Problem: Files fully loaded into memory for encryption (no streaming)
- Files: `00-Preliminary-R&D/poc/src/index.ts:149-155` (collectChunks concatenates all chunks)
- Cause: AES-256-GCM requires full content for authentication tag
- Improvement path: v1.1 planned AES-256-CTR for streaming; maintain GCM for small files

**IPNS polling for sync:**

- Problem: 30-second polling interval creates sync latency
- Files: Per TECHNICAL_ARCHITECTURE.md Section 5.4
- Cause: No push notification infrastructure
- Improvement path: Future versions may implement WebSocket notifications or exponential backoff

## Fragile Areas

**IPNS name generation depends on local IPFS node:**

- Files: `00-Preliminary-R&D/poc/src/index.ts:281-299` (generateFolder)
- Why fragile: POC uses `ctx.ipfs.key.gen()` which stores IPNS keys in local IPFS keystore
- Safe modification: Production must manage IPNS keys client-side (per TECHNICAL_ARCHITECTURE.md)
- Test coverage: No automated tests exist

**Stress test metadata size:**

- Files: `00-Preliminary-R&D/poc/src/index.ts:352-394` (addSyntheticChildren)
- Why fragile: Generates fake entries with placeholder CIDs and IPNS names
- Safe modification: Only for manual testing; not suitable for verification
- Test coverage: Manual harness only

**Folder tree traversal with depth limit:**

- Files: `00-Preliminary-R&D/poc/src/index.ts:419-468` (buildFolderTree)
- Why fragile: Hardcoded maxDepth=10 may not match PRD's 20-level limit
- Safe modification: Synchronize with constraint from PRD.md (20 levels)
- Test coverage: No automated tests

## Scaling Limits

**Folder metadata size:**

- Current capacity: Stress test option for N children (`STRESS_CHILDREN_COUNT`)
- Limit: 1,000 files per folder per PRD.md constraints
- Scaling path: Already documented; enforce in production API

**File size limit:**

- Current capacity: 100 MB per file (PRD constraint)
- Limit: Browser memory limits for encryption
- Scaling path: v1.1 streaming encryption with CTR mode

**Storage quota:**

- Current capacity: 500 MiB free tier (PRD constraint)
- Limit: IPFS storage management
- Scaling path: v1.1 billing integration for paid tiers

## Dependencies at Risk

**ipfs-http-client@60.0.1:**

- Risk: Already showing API incompatibilities (routing API disabled)
- Impact: Cannot use newer IPFS features; may become incompatible with updated nodes
- Migration plan: Consider migrating to @helia/ipns for IPNS operations; ipfs-http-client is deprecated

**eciesjs@0.4.7:**

- Risk: Small package with limited maintenance
- Impact: Core security dependency for key wrapping
- Migration plan: Evaluate alternatives like eth-crypto or implement ECIES directly with noble/secp256k1

**@noble/secp256k1@2.1.0:**

- Risk: Low risk; well-maintained
- Impact: Core dependency for key derivation
- Migration plan: Keep updated; audit-friendly

## Missing Critical Features

**Test coverage below target thresholds:**

- Problem: Tests exist across all workspaces (API: Jest, Web: Vitest, Crypto: Vitest, E2E: Playwright) but coverage has not yet reached the 85% line / 80% branch targets
- Blocks: Cannot confidently refactor critical paths; coverage gaps in crypto edge cases
- Files: `apps/api/jest.config.js`, `apps/web/vitest.config.ts`, `packages/crypto/vitest.config.ts`, `tests/e2e/`

**No error recovery:**

- Problem: POC stops on first error; no retry logic for IPFS operations
- Blocks: Unreliable in production network conditions
- Files: `00-Preliminary-R&D/poc/src/index.ts:699-702` (main catches and exits)

**No offline support:**

- Problem: POC requires continuous IPFS connectivity
- Blocks: Desktop FUSE mount usability when offline
- Files: Per roadmap, Week 10 includes "Offline queueing (retry on reconnect)"

**No Web3Auth integration:**

- Problem: POC uses local .env key; no actual Web3Auth flow
- Blocks: Multi-auth method validation; group connections testing

**No backend API implementation:**

- Problem: API spec exists but no NestJS backend code
- Blocks: 15 endpoints defined in API_SPECIFICATION.md have no implementation

**No TEE integration:**

- Problem: TEE architecture designed but no Phala/Nitro integration
- Blocks: IPNS auto-republishing (core availability feature)

## Test Coverage Gaps

**Crypto operations not tested:**

- What's not tested: AES-256-GCM encryption/decryption, ECIES key wrapping, key derivation
- Files: `00-Preliminary-R&D/poc/src/index.ts:101-136`
- Risk: Crypto bugs could cause data loss or security vulnerabilities
- Priority: High

**IPNS publish/resolve not tested:**

- What's not tested: IPNS record creation, signing, resolution
- Files: `00-Preliminary-R&D/poc/src/index.ts:157-190`
- Risk: Core sync mechanism could fail silently
- Priority: High

**Folder metadata encryption not tested:**

- What's not tested: Metadata serialization, encryption, decryption
- Files: `00-Preliminary-R&D/poc/src/index.ts:138-147`
- Risk: Data structure changes could break compatibility
- Priority: High

**Edge cases not tested:**

- What's not tested: Empty folders, max depth, max files, concurrent operations
- Files: Entire codebase
- Risk: Production failures under edge conditions
- Priority: Medium

---

Concerns audit: 2026-01-20
