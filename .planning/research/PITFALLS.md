# Domain Pitfalls

**Domain:** Encrypted cloud storage with IPFS/IPNS, client-side encryption, Web3Auth
**Researched:** 2026-01-20
**Confidence:** HIGH (verified against official sources and documented project incidents)

---

## Critical Pitfalls

Mistakes that cause security vulnerabilities, data loss, or major rewrites.

---

### Pitfall 1: AES-GCM Nonce Reuse

**What goes wrong:** Reusing the same nonce (IV) with the same key in AES-GCM completely breaks the security of the cipher. An attacker can recover the authentication key and forge messages. With two messages encrypted under the same key-nonce pair, an attacker can XOR ciphertexts to recover plaintext.

**Why it happens:**
- Using predictable counters that reset across sessions
- Insufficient randomness in nonce generation
- Copy-paste errors where IV generation is accidentally omitted
- Encrypting metadata updates without generating fresh IVs

**Consequences:**
- Complete loss of confidentiality for affected files
- Ability to forge authenticated ciphertext (breaks integrity)
- Undetectable to users until security audit
- Cannot be fixed retroactively for already-encrypted data

**Prevention:**
- ALWAYS use `crypto.getRandomValues(new Uint8Array(12))` for each encryption operation
- Never derive nonces from file content or predictable values
- Add unit tests that verify different IVs are generated for repeated encryptions
- Consider using AES-GCM-SIV for nonce-misuse resistance in future versions

**Detection:**
- Unit tests that encrypt same plaintext twice and verify different IVs
- Static analysis for IV reuse patterns
- Code review checklist item for all encryption code paths

**Phase relevance:** Core encryption library (Phase 1)

**Sources:**
- [AES-GCM and breaking it on nonce reuse](https://frereit.de/aes_gcm/)
- [Key recovery attacks on GCM](https://www.elttam.com/blog/key-recovery-attacks-on-gcm/)
- [Nonce-Disrespecting Adversaries](https://www.usenix.org/system/files/conference/woot16/woot16-paper-bock.pdf)

---

### Pitfall 2: Private Key Exposure via Browser Storage

**What goes wrong:** Storing the user's ECDSA private key in localStorage, sessionStorage, IndexedDB, or any persistent browser storage. This makes keys accessible to XSS attacks, browser extensions, and forensic recovery.

**Why it happens:**
- Convenience: Developers want "remember me" functionality
- Misunderstanding that "encrypted storage" is sufficient
- Copy-paste from Web3 wallet tutorials that store keys locally
- Session persistence across browser restarts

**Consequences:**
- XSS attack = complete vault compromise
- Browser extension with storage permissions = key theft
- Device seizure = forensic key recovery
- Violates zero-knowledge architecture

**Prevention:**
- Store `privateKey` ONLY in JavaScript variables (RAM)
- Clear on logout, tab close, and session timeout
- Use Web Crypto API's non-extractable keys where possible
- Add automated security tests that scan for localStorage writes of key patterns
- Implement `beforeunload` handler to clear sensitive state

**Detection:**
- Unit test: Mock localStorage/sessionStorage, verify no writes
- grep codebase for `localStorage.setItem` near key variables
- Browser DevTools audit of storage after authentication

**Phase relevance:** Authentication/session management (Phase 2)

**Sources:**
- [Secure Browser Storage: The Facts](https://auth0.com/blog/secure-browser-storage-the-facts/)
- [Browser stores passwords in clear text in memory](https://www.ghacks.net/2022/06/12/your-browser-stores-passwords-and-sensitive-data-in-clear-text-in-memory/)

---

### Pitfall 3: IPNS Record Expiry Causing Vault Inaccessibility

**What goes wrong:** IPNS records expire after approximately 24 hours. Without republishing, the IPNS name stops resolving, and users lose access to their folder structure. The files still exist on IPFS but become unreachable.

**Why it happens:**
- Not implementing republishing mechanism
- User offline for extended periods
- TEE republishing service downtime
- Failing to handle republish errors gracefully

**Consequences:**
- User sees "vault not found" error
- Files exist but folder structure lost
- Recovery requires vault export or manual CID tracking
- User trust severely damaged

**Prevention:**
- TEE-based automatic republishing every 3 hours (CipherBox spec)
- Store latest CID in database as fallback reference
- Client-side republish on every session start
- Monitor republish success rates with alerts
- Implement vault export that includes all CIDs for disaster recovery

**Detection:**
- Monitoring: Track IPNS resolution failures by user
- Alert when republish queue grows beyond threshold
- Periodic "canary" IPNS records to verify resolution

**Phase relevance:** TEE republishing implementation (Phase 4)

**Sources:**
- [IPNS is virtually unusable - Hacker News discussion](https://news.ycombinator.com/item?id=16433288)
- [Why is IPNS so slow](https://discuss.ipfs.tech/t/why-is-ipns-so-slow/8510)

---

### Pitfall 4: ECIES Implementation Incompatibility

**What goes wrong:** Different ECIES implementations use different parameter combinations (KDF, cipher, MAC), making encrypted data unreadable across library versions or platforms.

**Why it happens:**
- ECIES is a framework, not a single algorithm
- IEEE, Shoup, and SECG specs differ subtly
- Library updates may change defaults
- Web vs Node.js implementations differ

**Consequences:**
- Keys encrypted on web cannot be decrypted on desktop
- Library upgrade breaks existing encrypted keys
- Cross-platform sync fails silently
- Users locked out of their vaults

**Prevention:**
- Pin exact ECIES parameters in code (curve, KDF, cipher, MAC)
- Use ethers.js or a well-documented library with stable API
- Create test vectors that verify cross-platform compatibility
- Document exact ECIES configuration in technical spec
- Add integration tests between web and desktop encryption

**Detection:**
- Integration tests: Encrypt on web, decrypt on desktop (and vice versa)
- Version upgrade tests: Encrypt with v1, decrypt with v2
- Test vectors in documentation for manual verification

**Phase relevance:** Encryption library setup (Phase 1)

**Sources:**
- [ECIES Interoperability - Crypto++ Wiki](https://cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme)
- [ECIES Implementation Vulnerability Advisory](https://github.com/ecies/go/security/advisories/GHSA-8j98-cjfr-qx3h)

---

### Pitfall 5: Large File Encryption Causing Browser Crashes

**What goes wrong:** Encrypting files larger than available browser memory causes out-of-memory crashes. Files over 100MB commonly exceed browser tab memory limits, especially on mobile devices.

**Why it happens:**
- Web Crypto API requires entire plaintext in memory
- No streaming encryption support in browsers (yet)
- Multiple copies: original + encrypted + base64 encoded
- Mobile browsers have lower memory limits

**Consequences:**
- Browser tab crashes during upload
- Partial uploads leave orphaned IPFS pins
- User loses work in other tabs
- Mobile app appears broken

**Prevention:**
- Enforce client-side file size limit (100MB for v1.0)
- Show clear error before attempting large file encryption
- Implement chunked encryption for future versions
- Monitor memory usage during encryption
- Test on low-memory devices (mobile, old laptops)

**Detection:**
- Unit tests with boundary files (99MB, 100MB, 101MB)
- Memory profiling during encryption benchmarks
- User-facing error handling tests

**Phase relevance:** File upload implementation (Phase 2)

**Sources:**
- [High memory usage client side when uploading large files](https://help.nextcloud.com/t/high-memory-usage-client-side-when-uploading-large-files-in-browser/178599)
- [Progressive File Encryption Using Web Crypto API](https://medium.com/@the.v_hacker/progressive-file-encryption-using-web-crypto-api-44ad9656fcbc)

---

### Pitfall 6: TEE Key Epoch Migration Failures

**What goes wrong:** When TEE public keys rotate, users who haven't logged in during the grace period have IPNS keys encrypted with deprecated keys that can no longer be decrypted.

**Why it happens:**
- 4-week grace period too short for inactive users
- Client doesn't re-encrypt keys on login
- TEE provider coordination failures
- Clock skew between client and backend

**Consequences:**
- Inactive users lose automatic republishing
- IPNS records expire, vault becomes inaccessible
- Manual recovery required
- User trust severely damaged

**Prevention:**
- Store both current and previous epoch encrypted keys (CipherBox spec)
- Re-encrypt on every successful login
- 4-week grace period with email warnings at 2 weeks
- Fallback to previous epoch in TEE republish logic
- Admin dashboard to identify users needing key migration

**Detection:**
- Monitor: Count of users with only old-epoch keys
- Alert when approaching grace period end with unmigrated users
- Automated test: Simulate epoch rotation with stale client

**Phase relevance:** TEE integration (Phase 4)

---

## Moderate Pitfalls

Mistakes that cause delays, poor UX, or technical debt.

---

### Pitfall 7: IPNS Resolution Latency Causing Poor UX

**What goes wrong:** IPNS resolution takes 10-60 seconds in the worst case, making the app feel broken during initial folder load or sync detection.

**Why it happens:**
- IPNS over DHT requires finding multiple records (quorum)
- No local caching of IPNS resolutions
- Public DHT performance varies by network conditions
- Cold start after long offline period

**Consequences:**
- Users see loading spinners for 30+ seconds
- Sync polling feels sluggish
- Users think app is broken and abandon
- Support tickets increase

**Prevention:**
- Cache last known CID locally with timestamp
- Show cached data immediately, update when resolution completes
- Use optimistic UI updates for user's own changes
- Consider IPNS over PubSub for faster updates (future)
- Set reasonable timeout with fallback to cached state

**Detection:**
- Performance monitoring: P95 IPNS resolution latency
- User session analytics: Abandonment during loading
- Synthetic monitoring: Regular resolution timing checks

**Phase relevance:** IPNS integration (Phase 3)

**Sources:**
- [Measuring IPNS Performance on the Public Amino DHT](https://www.probelab.network/blog/ipns-performance-amino-dht)
- [IPNS/DNS resolution is very slow](https://github.com/ipfs/kubo/issues/2934)

---

### Pitfall 8: Pinata Rate Limiting During Bulk Operations

**What goes wrong:** Pinata's API has rate limits (250 requests/minute). Bulk folder creation, imports, or sync operations can hit these limits, causing failed uploads.

**Why it happens:**
- Each file upload requires separate pin request
- Folder creation triggers multiple IPFS operations
- No client-side rate limiting
- Retry logic without backoff

**Consequences:**
- Partial imports fail midway
- Users see cryptic "rate limit exceeded" errors
- Metadata becomes inconsistent
- Manual cleanup required

**Prevention:**
- Implement client-side request queuing with rate limiting
- Batch metadata updates where possible
- Show progress for bulk operations with pause capability
- Use exponential backoff on 429 responses
- Consider premium Pinata tier for production

**Detection:**
- Monitor 429 response rates from Pinata
- Integration tests with simulated rate limiting
- User-facing error messages for rate limits

**Phase relevance:** IPFS/Pinata integration (Phase 3)

**Sources:**
- [Pinata rate limit exceeded](https://github.com/ipfs/ipfs-desktop/issues/1954)
- [Pinata API FAQs](https://knowledge.pinata.cloud/en/articles/8314011-pinata-api-faqs)

---

### Pitfall 9: Metadata Leakage Through Unencrypted Fields

**What goes wrong:** File sizes, timestamps, folder structure depth, and number of children leak information even when content is encrypted. Pattern analysis can reveal user behavior.

**Why it happens:**
- Focus on encrypting content, forgetting metadata
- IPFS CID sizes reveal approximate content sizes
- Folder IPNS names are public identifiers
- Timestamps in IPNS records visible

**Consequences:**
- Attacker knows file sizes and when modified
- Folder structure partially inferable
- Activity patterns visible (work hours, etc.)
- Reduced privacy guarantees

**Prevention:**
- Pad encrypted content to standard size buckets
- Encrypt all metadata fields including timestamps
- Use random delays for sync operations
- Document what metadata is NOT encrypted in threat model

**Detection:**
- Security review: Audit all IPFS/IPNS published data
- Test: Verify no plaintext in published records
- Document known metadata leakage in threat model

**Phase relevance:** Encryption architecture (Phase 1)

**Sources:**
- [Reducing Metadata Leakage with PURBs](https://arxiv.org/abs/1806.03160)
- [IPFS Privacy and encryption](https://docs.ipfs.tech/concepts/privacy-and-encryption/)

---

### Pitfall 10: macOS FUSE Kernel Extension Issues

**What goes wrong:** macFUSE requires kernel extension installation, which Apple has deprecated. Users face security warnings, recovery mode requirements on Apple Silicon, and potential breakage in future macOS versions.

**Why it happens:**
- Apple moving away from kernel extensions
- macFUSE requires "reduced security" on Apple Silicon
- Users reluctant to modify security settings
- Future macOS may block kernel extensions entirely

**Consequences:**
- Complex installation process deters users
- Apple Silicon users face extra friction
- Future macOS update may break FUSE entirely
- Support burden for installation issues

**Prevention:**
- Provide clear installation guide with screenshots
- Consider FUSE-T as alternative (no kernel extension)
- Make FUSE optional with fallback to manual sync
- Monitor macOS release notes for FUSE compatibility
- Plan migration path to FileProvider API if Apple deprecates further

**Detection:**
- Track FUSE installation success rate
- Monitor macOS version distribution of users
- Test each macOS release for compatibility

**Phase relevance:** Desktop app with FUSE (Phase 5)

**Sources:**
- [gocryptfs on macOS](https://www.codejam.info/2024/04/gocryptfs-macos-macfuse.html)
- [macFUSE and VeraCrypt issues](https://sourceforge.net/p/veracrypt/discussion/technical/thread/f1596c1ad4/)

---

### Pitfall 11: Web3Auth Group Connection Misconfiguration

**What goes wrong:** Auth methods not properly grouped derive different keypairs. User signs up with Google, tries to log in with linked email, gets a different vault (or empty vault).

**Why it happens:**
- `groupedAuthConnectionId` not set consistently
- Testing with one auth method, deploying with multiple
- Web3Auth dashboard configuration drift
- Misunderstanding group connection requirements

**Consequences:**
- Users "lose" their vault when switching auth methods
- Confusing UX: "My files disappeared"
- Data appears lost (actually in different vault)
- Support tickets and user frustration

**Prevention:**
- Single `groupedAuthConnectionId` for all auth methods
- Integration tests that verify same keypair across auth methods
- Document group connection setup in deployment checklist
- Automated test: Sign up with Google, log in with email, verify same publicKey

**Detection:**
- Test: Multiple auth methods derive identical keypair
- Monitor: Users with multiple vaults (indicates misconfiguration)
- Onboarding flow: Verify auth method linking

**Phase relevance:** Web3Auth integration (Phase 2)

---

### Pitfall 12: Key Clearing Failure on Session End

**What goes wrong:** Private keys and folder keys remain in memory after logout, session timeout, or tab close, leaving them vulnerable to memory scraping attacks.

**Why it happens:**
- Async operations still holding key references
- Event handlers not properly cleaning up
- Tab close doesn't trigger cleanup (no `beforeunload`)
- Memory not actually zeroed (just dereferenced)

**Consequences:**
- Keys recoverable from memory dump
- Session hijacking after "logout"
- Forensic recovery of keys from device
- False sense of security

**Prevention:**
- Centralized key manager with explicit clear method
- Register `beforeunload` and `visibilitychange` handlers
- Set timeout to clear keys after inactivity
- Overwrite Uint8Array contents before dereferencing
- Integration test: Verify key variables are undefined post-logout

**Detection:**
- Unit test: Key manager state after logout
- Memory profiling: Search for key patterns after logout
- Code review: All code paths to session end

**Phase relevance:** Session management (Phase 2)

**Sources:**
- [Web Crypto API and key management](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)

---

## Minor Pitfalls

Mistakes that cause annoyance but are fixable without major refactoring.

---

### Pitfall 13: Inconsistent Terminology in Codebase

**What goes wrong:** Using `pubkey`, `publicKey`, `userPublicKey`, `ownerPubkey` interchangeably creates confusion and increases bug risk during refactoring.

**Why it happens:**
- Multiple developers with different conventions
- Evolving API design
- Copy-paste from different sources
- No enforced terminology standard

**Consequences:**
- Bugs during refactoring (wrong variable renamed)
- Confusion during code review
- Documentation inconsistency
- Longer onboarding time

**Prevention:**
- Use CLAUDE.md terminology table (already defined)
- ESLint rule for naming conventions
- Code review checklist item
- Search-and-replace during initial setup

**Detection:**
- grep for banned terms
- ESLint warnings
- PR review checklist

**Phase relevance:** All phases

---

### Pitfall 14: Missing encryptionMode Field Backward Compatibility

**What goes wrong:** v1.1 code assumes `encryptionMode` field exists, crashes on v1.0 files that lack it.

**Why it happens:**
- Field added in v1.1 for streaming support
- Existing files don't have the field
- No default value handling in decryption code

**Consequences:**
- v1.1 client crashes on v1.0 files
- Users think vault is corrupted
- Support burden

**Prevention:**
- Default to "GCM" when field is missing (CipherBox spec)
- Add explicit backward compatibility tests
- Never require new fields without defaults

**Detection:**
- Integration test: Load v1.0 metadata with v1.1 client
- Unit test: Parse metadata without encryptionMode field

**Phase relevance:** Encryption mode implementation (Phase 3+)

---

### Pitfall 15: IPFS Pinning Without Unpinning

**What goes wrong:** Updated or deleted files leave orphaned pins on Pinata, consuming storage quota without benefit.

**Why it happens:**
- Unpin operation fails silently
- Race condition: new file pinned before old unpinned
- Delete operation skips unpin step
- No tracking of pinned CIDs

**Consequences:**
- Storage quota exhausted faster than expected
- Users charged for orphaned content
- Cleanup requires manual audit

**Prevention:**
- Track all pinned CIDs in metadata or database
- Unpin after successful publish of updated metadata
- Background job to reconcile pinned CIDs
- Integration test: Verify unpin on update/delete

**Detection:**
- Audit: Compare expected vs actual Pinata pin count
- Monitor: Storage usage growth rate
- Periodic reconciliation job

**Phase relevance:** File operations (Phase 3)

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|-------------|---------------|------------|
| Phase 1: Encryption core | AES-GCM nonce reuse, ECIES incompatibility | Test vectors, cross-platform tests |
| Phase 2: Auth/sessions | Key storage in browser, key clearing | Security tests, memory audits |
| Phase 3: IPFS integration | IPNS latency, Pinata rate limits | Caching, request queuing |
| Phase 4: TEE republishing | IPNS expiry, epoch migration | Grace periods, multi-epoch support |
| Phase 5: Desktop FUSE | macOS kernel extension | Installation guides, FUSE-T fallback |
| Phase 6: Multi-device sync | Conflict resolution, metadata consistency | Optimistic UI, eventual consistency |

---

## Sources Summary

### HIGH Confidence (Official Documentation)
- [IPFS Privacy and Encryption Docs](https://docs.ipfs.tech/concepts/privacy-and-encryption/)
- [Web Crypto API MDN](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [Pinata API Documentation](https://docs.pinata.cloud/)

### MEDIUM Confidence (Verified Research)
- [AES-GCM Nonce Reuse Analysis](https://frereit.de/aes_gcm/)
- [IPNS Performance Measurement](https://www.probelab.network/blog/ipns-performance-amino-dht)
- [Metadata Leakage with PURBs](https://arxiv.org/abs/1806.03160)

### LOW Confidence (Community Reports - Validated by GitHub Issues)
- [IPNS Slowness Discussion](https://discuss.ipfs.tech/t/why-is-ipns-so-slow/8510)
- [macFUSE Compatibility Issues](https://www.codejam.info/2024/04/gocryptfs-macos-macfuse.html)
- [Pinata Rate Limiting](https://github.com/ipfs/ipfs-desktop/issues/1954)

---

**End of Pitfalls**
