# Domain Pitfalls

**Domain:** Adding sharing, search, MFA, versioning, and advanced sync to zero-knowledge encrypted storage (IPFS/IPNS)
**Researched:** 2026-02-11
**Milestone:** 2 (Production v1.0)
**Confidence:** HIGH for sharing/versioning pitfalls (well-documented domain), MEDIUM for search/sync (fewer ZK-specific precedents)

**Context:** CipherBox Milestone 1 ships a working zero-knowledge encrypted vault with per-folder IPNS records, ECIES key wrapping (secp256k1), per-folder AES-256-GCM encryption, and TEE-based republishing. Milestone 2 adds sharing, search, MFA, versioning, and advanced sync. The fundamental risk is **breaking the zero-knowledge property** when adding these features to the existing system.

---

## Critical Pitfalls

Mistakes that break zero-knowledge guarantees, cause data loss, or require architectural rewrites.

---

### Pitfall 1: Sharing Folder Keys Without Re-Wrapping Per-Recipient Breaks ZK

**What goes wrong:** When sharing a folder, the naive approach is to send the plaintext `folderKey` through the server to the recipient. This instantly breaks the zero-knowledge property -- the server sees the symmetric key and can decrypt the entire folder.

**Why it happens:**

- Developer shortcuts: "Just send the key and let the recipient store it"
- Confusion between "encrypted in transit" (TLS) and "encrypted at rest" (ECIES)
- Not recognizing that the server relaying a key is the server _seeing_ the key
- Rushing sharing implementation without understanding the key hierarchy

**Consequences:**

- Server can decrypt shared folder contents -- ZK violation
- If server is compromised, all shared folders are exposed
- Fundamental architecture violation that requires rewrite to fix
- Cannot be patched retroactively for already-shared folders

**Prevention:**

- **Always wrap `folderKey` with the recipient's `publicKey` using ECIES on the client side.** The sharing client must:
  1. Have the recipient's `publicKey` (fetched from server by user lookup)
  2. Encrypt: `encryptedFolderKeyForRecipient = ECIES(folderKey, recipientPublicKey)`
  3. Send only the encrypted key to the server
  4. Server stores the wrapped key -- it never sees plaintext
- Follow Tresorit's "group key file" pattern: each shared folder stores N copies of the folder key, each wrapped with a different recipient's public key
- Add a server-side assertion that rejects plaintext keys (length/format check)
- Code review checklist: "Does the server ever see a symmetric key in plaintext?"

**Detection:**

- Network inspection test: verify no plaintext symmetric keys in API requests
- Unit test: intercept share API calls and verify all key payloads are ECIES-wrapped
- Audit: grep backend codebase for folderKey handling -- it should only store blobs

**Phase relevance:** File Sharing (Phase 12-13)
**Confidence:** HIGH -- this is how Tresorit, Proton Drive, and all serious ZK storage systems handle it

**Sources:**

- [How does folder sharing work? -- Tresorit](https://support.tresorit.com/hc/en-us/articles/216114387-How-does-folder-sharing-work)
- [Proton Drive Security](https://proton.me/drive/security)

---

### Pitfall 2: Incomplete Revocation -- Revoking Share Access Without Re-Keying

**What goes wrong:** When a user is removed from a shared folder, the system removes their access record but does NOT generate a new `folderKey`. The revoked user still has the old `folderKey` cached in memory or local storage and can decrypt all existing content plus any new content encrypted with the same key.

**Why it happens:**

- Re-keying is expensive: every file in the folder needs its `fileKeyEncrypted` re-wrapped with the new `folderKey`
- Developer assumes "removing access" means they can't reach the API anymore
- Forgetting that IPFS content is public -- if the revoked user knows the CID, they can fetch it from any IPFS gateway without the CipherBox backend
- Underestimating the persistence of key material in the revoked user's client

**Consequences:**

- Revoked user retains full read access to all folder contents
- IPFS content-addressable nature means files are fetchable without CipherBox API
- False sense of security: owner thinks access is revoked, but it isn't
- Legal/compliance risk if sharing was with an external party

**Prevention:**

- **On share revocation, generate a new `folderKey` and re-encrypt all folder metadata:**
  1. Generate new `folderKey`
  2. Re-encrypt folder metadata (children list) with new key
  3. Re-wrap new `folderKey` with each remaining member's `publicKey`
  4. Publish updated IPNS record
  5. Old `fileKey` entries remain valid (files don't need re-encryption -- they have their own keys)
- **Critical subtlety for CipherBox:** File keys are wrapped with the owner's `publicKey` (ECIES), NOT with the `folderKey`. So revoking folder access + rotating `folderKey` is sufficient -- the revoked user cannot unwrap individual `fileKey` entries because those are ECIES-wrapped with the owner's key. However, if the sharing model wraps `fileKey` with a shared key, then file re-encryption IS required.
- Design the sharing model to wrap `fileKey` entries with per-user ECIES, not with `folderKey`. This way, revocation only requires rotating the folder metadata key, not re-encrypting every file.
- Accept that content already downloaded by the revoked user cannot be un-downloaded. Document this limitation clearly.

**Detection:**

- Integration test: revoke access, then attempt to decrypt folder metadata with old key -- should fail
- Integration test: revoke access, then attempt to fetch file by CID from public IPFS gateway -- this will succeed (IPFS is public), but decryption should fail without valid fileKey
- Audit: verify that share revocation triggers folderKey rotation in code

**Phase relevance:** File Sharing (Phase 12-13)
**Confidence:** HIGH -- this is the most common mistake in encrypted sharing implementations

**Sources:**

- [Tresorit folder sharing -- key regeneration on member removal](https://support.tresorit.com/hc/en-us/articles/216114387-How-does-folder-sharing-work)
- [Proxy Re-Encryption for revocable access control](https://www.mdpi.com/2079-9292/14/15/2988)

---

### Pitfall 3: IPNS Shared Folder -- Multiple Writers Cause Record Conflicts

**What goes wrong:** In CipherBox's architecture, each folder has one IPNS keypair. When a folder is shared, multiple users may try to publish updates to the same IPNS name simultaneously. IPNS resolves conflicts by sequence number (highest wins), causing last-writer-wins data loss.

**Why it happens:**

- CipherBox's per-folder IPNS model assumes a single writer (the owner)
- Sharing folder access means sharing the ability to modify folder metadata
- Two users add files to the same shared folder simultaneously
- Both read sequence N, both publish sequence N+1 with different content
- IPNS resolves to whichever record propagates first; the other's changes are silently lost

**Consequences:**

- Silent data loss: user's uploaded file disappears from folder listing
- No merge mechanism -- one user's entire metadata update is discarded
- File content exists on IPFS (CID is valid) but is unreachable because folder metadata doesn't reference it
- Orphaned Pinata pins consuming storage quota
- Users lose trust in the system

**Prevention:**

- **Design shared folders as read-only by default.** Only the owner can modify folder metadata. Recipients can read/download but not add files. This is the simplest, safest approach for v1.0.
- If write-sharing is needed, implement one of:
  1. **Owner-mediated writes:** Recipient uploads encrypted file to a "staging area." Owner's client merges it into folder metadata. Adds latency but preserves single-writer IPNS model.
  2. **Separate IPNS per writer:** Each user with write access has their own IPNS record for their contributions. A merge view on read combines all writers' records. Complex but avoids conflicts.
  3. **Server-side sequencing:** Backend assigns IPNS sequence numbers and serializes publish requests for shared folders. This requires trusting the server more but is practical.
- **For CipherBox specifically:** The TEE republishing model already has the server tracking IPNS sequence numbers. Extend this to serialize shared folder updates by having the backend reject out-of-sequence publishes and returning the current sequence number for retry.

**Detection:**

- Integration test: two clients publish to same IPNS name concurrently, verify no data loss
- Monitor: track "expected file count" vs "actual file count" drift in shared folders
- Alert: detect orphaned CIDs (pinned but not referenced in any folder metadata)

**Phase relevance:** File Sharing (Phase 12-13)
**Confidence:** HIGH -- confirmed by IPFS/Kubo issue #8433 (multiple IPNS publishers)

**Sources:**

- [Multiple users publish to IPNS at the same time -- ipfs/kubo#8433](https://github.com/ipfs/kubo/issues/8433)
- [IPNS with multiple resolvers -- ipfs/specs#198](https://github.com/ipfs/specs/issues/198)

---

### Pitfall 4: Link Sharing Leaks Decryption Keys to Server

**What goes wrong:** When implementing "share via link" (recipient has no CipherBox account), the decryption key must be embedded in the link somehow. If the key is in the URL path or query parameters, the server sees it in access logs. If the key is in the URL fragment (#), the server doesn't see it, but it may appear in referrer headers, browser history, or analytics.

**Why it happens:**

- URL path/query: `https://cipherbox.io/share/abc123?key=DEADBEEF` -- server logs contain the key
- URL fragment: `https://cipherbox.io/share/abc123#key=DEADBEEF` -- browser doesn't send fragment to server, but:
  - Browser history stores full URL including fragment
  - Copy-pasting URL may go through clipboard monitoring malware
  - Analytics/tracking scripts on the page can read `window.location.hash`
- Developer uses query parameters by default (most intuitive)

**Consequences:**

- Server access logs contain decryption keys -- ZK violation
- Analytics services receive decryption keys
- Shared links in browser history become a key recovery vector
- CDN logs may capture keys

**Prevention:**

- **Use URL fragment (#) for the decryption key** -- fragments are never sent to the server
- Implement a dedicated "share landing page" that:
  1. Is a static page with zero server-side rendering
  2. Has NO analytics, tracking pixels, or third-party scripts
  3. Reads the key from `window.location.hash`
  4. Immediately clears `window.location.hash` after reading
  5. Performs all decryption client-side
- **Password-protected shares:** Derive the decryption key from a user-chosen password using PBKDF2/Argon2. The link contains only the share ID; the password is communicated out-of-band. Server never sees the password or derived key.
- **Expiring shares:** Store share metadata (CID, expiry) on server. The decryption key is ONLY in the URL fragment or derived from a password. When share expires, server stops serving the encrypted content.
- Disable `Referrer-Policy` headers or set to `no-referrer` on share pages

**Detection:**

- Audit: grep server access logs for share URLs -- verify no key material in path/query
- Test: capture HTTP request during share link access, verify fragment not sent
- Security review: verify share landing page has no third-party scripts

**Phase relevance:** Link Sharing (Phase 13)
**Confidence:** HIGH -- well-known pattern used by Bitwarden Send, Firefox Send

---

### Pitfall 5: MFA Enrollment Breaks Existing Vault Access

**What goes wrong:** Adding MFA changes the authentication flow, which may change the key derivation path in Web3Auth. If MFA is added as a factor that modifies the group connection or key derivation, the user's `publicKey` changes, and they lose access to their vault (encrypted with the old `publicKey`).

**Why it happens:**

- Web3Auth derives keys from authentication factors. If MFA adds a new factor to the derivation, the output keypair changes.
- Misunderstanding Web3Auth's architecture: MFA might need to be implemented at the CipherBox backend level, NOT at the Web3Auth level
- Adding MFA as a Web3Auth "custom factor" that changes the derived key
- Not testing MFA enrollment with existing vaults

**Consequences:**

- User enables MFA and immediately loses access to their vault
- Old `publicKey` has all encrypted keys; new `publicKey` can't decrypt anything
- Irrecoverable data loss unless user has vault export
- Catastrophic UX failure

**Prevention:**

- **Implement MFA at the CipherBox backend level, NOT at Web3Auth key derivation.** The MFA check should happen AFTER Web3Auth returns the keypair, as a gateway to API access:
  1. User authenticates with Web3Auth (derives same keypair as always)
  2. CipherBox backend checks if MFA is enabled for this user
  3. If yes, backend requires MFA verification before issuing access/refresh tokens
  4. Keypair is unchanged -- vault access is unchanged
- **Never modify the Web3Auth group connection or key derivation factors post-enrollment.** The keypair must remain deterministic from the original auth factors.
- If implementing passkey/WebAuthn: store the passkey credential on the backend, associated with the user's `publicKey`. The passkey is a second authentication factor, NOT a key derivation factor.
- If implementing TOTP: TOTP secret stored server-side (encrypted with user's `publicKey` if you want ZK guarantees on the TOTP secret itself). TOTP code verified by backend before token issuance.

**Detection:**

- Integration test: enable MFA, verify `publicKey` is unchanged
- Integration test: enable MFA, log out, log back in with MFA, verify vault access
- Regression test: MFA enrollment does not trigger Web3Auth key re-derivation

**Phase relevance:** MFA (Phase 14)
**Confidence:** HIGH -- Web3Auth documentation explicitly warns about key derivation stability

---

### Pitfall 6: MFA Recovery Phrase Creates Backdoor to Zero-Knowledge

**What goes wrong:** A recovery phrase (like Bitwarden's "recovery code") that allows bypassing MFA must be designed carefully. If the recovery phrase is stored on the server in a form that allows the server to impersonate the user, it breaks ZK.

**Why it happens:**

- Recovery phrase stored as plaintext or reversible hash on server
- Recovery flow that returns access token without proper key derivation
- Confusion between "MFA bypass" and "account recovery"
- Wanting to help users who lose MFA devices

**Consequences:**

- Server admin can use recovery phrase to bypass MFA and access vault
- Compromised server leaks recovery phrases
- Recovery flow becomes a privileged escalation path

**Prevention:**

- **Recovery phrase should be client-generated and client-stored.** The server stores only a hash of the recovery phrase.
- **Recovery flow:**
  1. User presents recovery phrase to client
  2. Client hashes it and sends to server for verification
  3. Server verifies hash matches, disables MFA
  4. User re-authenticates normally via Web3Auth (key derivation unchanged)
  5. User re-enrolls MFA
- The recovery phrase NEVER gives the server access to the keypair. It only disables the MFA gate.
- Alternative: use the Web3Auth recovery mechanism (exported private key) as the ultimate recovery path. If user has their Web3Auth key backup, they can always recover.

**Detection:**

- Audit: verify recovery phrase is only stored as a hash on server
- Test: verify recovery flow does NOT return any key material
- Test: verify server cannot reconstruct recovery phrase from stored hash

**Phase relevance:** MFA (Phase 14)
**Confidence:** HIGH

---

### Pitfall 7: Search Index Leaks File Names to Server

**What goes wrong:** Building a search index requires some form of indexable data. If the index is built server-side from encrypted metadata, the server gains information. If the index is sent to the server in a searchable form (even tokenized), access pattern analysis reveals search queries over time.

**Why it happens:**

- Sending HMAC-based blind index tokens to the server for lookup
- Server observes which tokens are queried frequently (frequency analysis)
- Server correlates search patterns with file access patterns
- Index tokens are deterministic -- same filename always produces same token, enabling cross-user correlation

**Consequences:**

- Server learns which file names are most popular across users
- Server can correlate searches across sessions to build activity profiles
- If server knows the domain (e.g., user is a lawyer), frequency analysis can recover file names
- Partial ZK violation -- server gains metadata intelligence

**Prevention:**

- **Client-side only search.** For CipherBox's v1.0, implement search entirely on the client:
  1. On vault load, client decrypts all folder metadata (file names, folder names)
  2. Client builds an in-memory search index from decrypted names
  3. Search queries execute locally against the in-memory index
  4. No search data ever sent to server
- This approach works because CipherBox already decrypts the full folder tree on login (tree traversal). The search index is a by-product of existing decryption.
- **Performance concern:** For vaults with 1000+ files across many folders, full tree traversal may be slow. Mitigate by:
  - Lazy indexing: index folders as they're accessed
  - Cached index: store encrypted search index in IPFS (encrypted with rootFolderKey)
  - Progressive search: search already-loaded folders first, expand as more load
- **Do NOT implement server-side search** unless you accept the metadata leakage tradeoffs and document them in the threat model.

**Detection:**

- Network audit: verify no search-related API calls exist
- Code review: verify search functionality has no server communication
- Test: perform searches while offline -- should work (proves client-only)

**Phase relevance:** Search (Phase 15)
**Confidence:** HIGH -- client-side search is the standard approach for ZK storage (Tresorit, Cryptomator)

**Sources:**

- [IronCore Labs: Solving Search Over Encrypted Data](https://ironcorelabs.com/blog/2021/solving-search-over-encrypted-data/)
- [Understanding Leakage in Searchable Encryption](https://eprint.iacr.org/2024/1558.pdf)

---

## High Pitfalls

Mistakes that cause significant bugs, data integrity issues, or expensive rework.

---

### Pitfall 8: File Versioning Storage Cost Explosion on IPFS

**What goes wrong:** Each version of a file is a separate encrypted blob on IPFS with a unique CID (because CipherBox uses random keys and IVs per encryption -- no deduplication possible). A 10MB file with 50 versions consumes 500MB of Pinata storage, even if changes between versions are tiny.

**Why it happens:**

- CipherBox deliberately avoids deduplication for security (same file encrypted twice produces different CIDs)
- IPFS is content-addressed: even a 1-byte change produces a completely different CID for the encrypted blob
- No delta/diff mechanism exists for encrypted content
- Users expect "free" version history like Google Drive
- Version retention policy not defined

**Consequences:**

- 500 MiB free tier quota exhausted rapidly with active files
- Pinata costs scale linearly with version count x file size
- Users surprised by storage usage
- No way to deduplicate or compress versions

**Prevention:**

Implement version retention limits:

- Max N versions per file (e.g., 10)
- Max age for versions (e.g., 30 days)
- Max total version storage per file (e.g., 5x file size)
- When limit exceeded, oldest versions are unpinned

Version metadata in folder entry should follow this structure:

```json
{
  "type": "file",
  "versions": [
    { "cid": "Qm...", "fileKeyEncrypted": "...", "fileIv": "...", "created": 1705268100 },
    { "cid": "QmOld...", "fileKeyEncrypted": "...", "fileIv": "...", "created": 1705267000 }
  ],
  "currentVersion": 0
}
```

Additional prevention measures:

- **Unpin old versions promptly.** When a version is pruned, call Pinata unpin. Track pending unpins to avoid orphans.
- **Show storage impact to users:** "This file has 8 versions using 42MB. Keeping 5 versions would save 17MB."
- **Explicitly document:** "File versioning does not support delta storage. Each version stores the complete encrypted file."

**Detection:**

- Monitor: per-user storage growth rate
- Alert: user approaching quota with significant version storage
- Audit: compare expected version count vs pinned CID count

**Phase relevance:** File Versioning (Phase 16)
**Confidence:** HIGH -- inherent to content-addressable + encrypted storage

---

### Pitfall 9: Version Metadata Bloats Folder IPNS Records

**What goes wrong:** Storing version history inline in folder metadata (the IPNS record) causes the metadata to grow linearly with version count. A folder with 100 files each having 10 versions means 1000 version entries in the metadata JSON. This metadata is encrypted and stored in IPFS, fetched on every folder access, and re-published on every change.

**Why it happens:**

- Natural place to store version info is alongside file info in folder metadata
- Works fine for 1-2 versions, becomes a problem at scale
- Each IPNS publish/resolve cycle transfers the full metadata
- Folder metadata is re-encrypted and re-published on ANY change (add file, rename, delete)

**Consequences:**

- Folder load times degrade as version count grows
- IPNS publish latency increases (larger payload)
- Pinata storage for metadata records grows significantly
- Every file operation in the folder re-publishes all version metadata

**Prevention:**

- **Separate version metadata from folder metadata.** Store version history in a separate IPNS record or IPFS object per file:
  - Folder metadata stores only current version reference (CID, key, IV)
  - A separate "version manifest" per file stores historical versions
  - Version manifest CID is referenced from the folder metadata entry
  - Version manifest encrypted with the file's current key or the folder key
- **Lazy-load version history:** Only fetch version manifest when user explicitly requests "View version history"
- **Cap inline version references:** If using inline storage, keep only the 3 most recent versions in folder metadata, with a pointer to a full version manifest for older versions
- **Consider a backend-stored version index:** Version metadata (CID list) is not highly sensitive -- the CIDs are opaque hashes. A backend table mapping file ID to version CIDs reduces IPNS bloat. However, this leaks "how many versions exist" to the server.

**Detection:**

- Performance test: measure folder load time with 100 files x 10 versions each
- Size monitoring: track folder metadata size over time
- Alert: folder metadata exceeding size threshold (e.g., 100KB)

**Phase relevance:** File Versioning (Phase 16)
**Confidence:** MEDIUM -- depends on implementation approach chosen

---

### Pitfall 10: Sharing IPNS Private Key Gives Full Write Control

**What goes wrong:** To allow a recipient to read a shared folder's IPNS record, they need the `ipnsName` (public). But to allow them to WRITE to the folder, they need the `ipnsPrivateKey` (Ed25519 signing key). Sharing the IPNS private key gives the recipient full, irrevocable control to publish anything to that IPNS name -- including malicious or corrupted metadata.

**Why it happens:**

- IPNS uses keypair-based publishing: only the private key holder can publish
- No access control layer on IPNS -- it's all-or-nothing
- Developer thinks "share the folder" means "share the signing key"
- No way to revoke IPNS key access without changing the IPNS name entirely

**Consequences:**

- Shared user can overwrite folder metadata with garbage
- Shared user can "delete" all file references (metadata vandalism)
- Owner cannot revoke write access without creating a new IPNS keypair (changes the IPNS name)
- New IPNS name means all parent references need updating (cascading updates)
- If TEE is republishing the old IPNS name, it continues with stale data

**Prevention:**

- **Never share `ipnsPrivateKey` for write access.** Instead:
  1. Read-only sharing: Share only `ipnsName` + `folderKey` (wrapped with recipient's public key). Recipient can resolve IPNS and decrypt, but cannot publish.
  2. Write mediation: Shared users submit changes to the owner's client, which publishes on their behalf (see Pitfall 3 prevention).
- **If write-sharing is required in the future:** Create a sub-IPNS record per writer, with the folder having a "manifest" IPNS that points to all writer sub-records. This is architecturally complex but preserves key isolation.
- **Rotation plan:** If an IPNS private key is compromised, have a documented procedure:
  1. Generate new IPNS keypair
  2. Re-publish metadata under new name
  3. Update parent folder reference
  4. Update TEE republish schedule
  5. Notify shared users of new IPNS name

**Detection:**

- Code review: grep for any code path that sends `ipnsPrivateKey` to a non-owner
- Integration test: verify shared user cannot publish to shared folder's IPNS name
- Security audit: verify IPNS private keys are only stored encrypted with owner's public key

**Phase relevance:** File Sharing (Phase 12-13)
**Confidence:** HIGH

---

### Pitfall 11: Conflict Resolution Without Plaintext Access

**What goes wrong:** Traditional conflict resolution (three-way merge, diff) requires reading file contents. In a zero-knowledge system, the server cannot merge conflicts. The client must detect conflicts, download both versions, decrypt both, present a merge UI, and re-encrypt the resolution. This is fundamentally harder than in non-encrypted systems.

**Why it happens:**

- Server-side conflict resolution is impossible (server can't read content)
- Client-side resolution requires both versions to be available and decryptable
- IPNS sequence-number conflict means one client's publish was silently overwritten
- Detecting the conflict requires knowing what the "expected" state was before your change

**Consequences:**

- Silent data loss if conflict goes undetected (last-writer-wins at IPNS level)
- User sees inconsistent state between devices
- Complex client-side merge UI needed for each file type
- Encrypted conflict resolution is orders of magnitude harder to implement than unencrypted

**Prevention:**

- **Phase 1 approach (simple):** Use operational transforms at the metadata level:
  1. Client fetches current IPNS record before publishing
  2. Client verifies its cached metadata matches the current record
  3. If mismatch: CONFLICT DETECTED
  4. Client presents both versions to user (decrypted on client)
  5. User chooses which to keep or manually merges
  6. Client publishes resolved version with incremented sequence number
- **Optimistic concurrency control:**
  - Include the "parent CID" (the CID of metadata the client was editing from) in the publish request
  - Backend rejects publish if parent CID doesn't match current CID
  - Client retries by fetching latest, re-applying changes, re-publishing
- **Offline queue with conflict check on reconnect:**
  - Store pending operations locally while offline
  - On reconnect, check if remote state has changed
  - If unchanged: apply queued operations
  - If changed: present conflict UI
- **Do NOT attempt automatic merging** of folder metadata (children arrays). Array merge is deceptively complex and gets it wrong in edge cases (duplicate entries, missing deletes).

**Detection:**

- Integration test: two clients edit same folder simultaneously, verify conflict detection fires
- Integration test: client publishes after offline period, verify parent CID check
- Monitor: track "conflict detected" events per user

**Phase relevance:** Advanced Sync (Phase 17)
**Confidence:** MEDIUM -- approach depends heavily on desired UX

---

### Pitfall 12: Orphaned Versions After Folder Metadata Publish Failure

**What goes wrong:** When creating a new version of a file, the client: (1) encrypts new content, (2) uploads to IPFS (gets new CID), (3) updates folder metadata with new version entry, (4) publishes IPNS. If step 4 fails (network error, IPNS timeout), the new file CID is pinned on Pinata but not referenced in any folder metadata. The old version remains current, and the new version is orphaned.

**Why it happens:**

- Two-phase commit without atomicity: "upload file" and "update metadata" are separate operations
- IPNS publish can timeout or fail intermittently
- Client crashes between upload and metadata publish
- No transaction rollback mechanism for IPFS pins

**Consequences:**

- Pinata storage consumed by unreferenced CIDs
- User's edit appears to have been lost
- Multiple retries can create multiple orphaned versions
- Storage quota leaks over time

**Prevention:**

- **Client-side transaction log:**
  1. Before starting, write intent to local storage: `{action: "update", fileCid: null, metadataCid: null}`
  2. After upload: update intent with `fileCid`
  3. After metadata publish: mark intent as complete
  4. On next session start: check for incomplete intents. Either retry the metadata publish or unpin the orphaned CID.
- **Backend reconciliation job:**
  - Periodically compare Pinata pin list against all CIDs referenced in known folder metadata
  - Flag orphaned CIDs for review/cleanup
  - Auto-unpin CIDs orphaned for >24 hours
- **Retry with idempotency:** If IPNS publish fails, retry with same sequence number. IPNS accepts re-publishes with same or higher sequence numbers.

**Detection:**

- Monitor: Pinata pin count vs expected pin count (derived from folder metadata)
- Audit: weekly reconciliation of pinned CIDs vs referenced CIDs
- Alert: pin count growing faster than file count

**Phase relevance:** File Versioning (Phase 16), already partially exists in v1 but amplified by versioning
**Confidence:** HIGH

---

### Pitfall 13: Sharing + TEE Republishing Interaction -- Who Republishes Shared Folders?

**What goes wrong:** In the current architecture, each user registers their folders' IPNS keys with the TEE for republishing. When a folder is shared, the owner's TEE registration handles republishing. But if the owner goes inactive (no login for months), their TEE key epoch may expire, and the shared folder's IPNS record stops being republished. Shared users who depend on this folder lose access.

**Why it happens:**

- TEE republishing is tied to the owner's key epoch
- Owner must login within the grace period to refresh TEE keys
- Shared users have no mechanism to trigger republishing
- IPNS records expire after 24 hours without republishing

**Consequences:**

- Shared folder becomes inaccessible when owner is inactive
- All shared users lose access simultaneously
- No recovery path without owner logging back in
- Data exists on IPFS but IPNS pointer is dead

**Prevention:**

- **Allow shared users to register for TEE republishing of shared folders:**
  - When a folder is shared, the recipient's client can also encrypt the `ipnsPrivateKey` with the TEE public key and register for republishing
  - Multiple users can have republish schedules for the same IPNS name
  - TEE deduplicates (only republishes once per IPNS name per cycle)
- **Owner notification:** Alert the owner when approaching key epoch expiry if they have shared folders
- **Fallback CID storage:** Backend stores the last known CID for each IPNS name. If IPNS resolution fails, client can try fetching by CID directly (content still exists on IPFS).
- **Shared folder health check:** Periodically verify IPNS resolution works for shared folders, alert shared users if degrading

**Detection:**

- Monitor: IPNS resolution success rate for shared folders
- Alert: shared folder IPNS resolution failures
- Test: simulate owner going inactive, verify shared users' experience

**Phase relevance:** File Sharing (Phase 12-13) intersecting TEE Republishing
**Confidence:** MEDIUM -- specific to CipherBox's architecture

---

## Medium Pitfalls

Mistakes that cause poor UX, technical debt, or performance issues.

---

### Pitfall 14: Sharing UI Requires Recipient Lookup -- Privacy Leakage

**What goes wrong:** To share with a specific user, the client needs their `publicKey`. This requires a user lookup mechanism (e.g., search by email). If the backend provides an endpoint to look up users by email/name, it creates a user enumeration vulnerability and reveals who uses CipherBox.

**Why it happens:**

- Need to find recipient's publicKey to wrap folder key
- Natural approach: search by email/username
- Backend exposes user lookup endpoint
- Attacker can enumerate all registered users

**Consequences:**

- User enumeration: attacker discovers who uses CipherBox
- Privacy violation: revealing that a specific person uses encrypted storage may itself be sensitive
- Phishing vector: targeted attacks against known CipherBox users

**Prevention:**

- **Rate limit user lookup aggressively** (e.g., 10 lookups per hour)
- **Require exact email match** -- no partial search or autocomplete on the server side
- **Return consistent responses:** Whether user exists or not, respond in the same time and format (prevent timing attacks)
- **Alternative: QR code / invite link approach:**
  - Owner generates an invite containing their share details
  - Recipient opens invite link, which prompts them to share their `publicKey`
  - No server-side user lookup needed
- **Consider using publicKey as the sharing identifier** rather than email. Users exchange public keys out-of-band.

**Detection:**

- Security test: attempt to enumerate users via lookup endpoint
- Test: verify consistent response times for existing vs non-existing users
- Audit: rate limiting on lookup endpoints

**Phase relevance:** File Sharing (Phase 12-13)
**Confidence:** HIGH

---

### Pitfall 15: Client-Side Search Index Stale After External Changes

**What goes wrong:** Client builds search index from decrypted folder metadata. Another device adds/renames/deletes files. The local search index is now stale until the client re-traverses the full folder tree and rebuilds the index.

**Why it happens:**

- Search index built at login, not continuously updated
- IPNS polling detects root CID change but doesn't identify WHICH folders changed
- Rebuilding index requires traversing all folders (expensive for deep hierarchies)
- No incremental update mechanism for the search index

**Consequences:**

- Search returns stale results (deleted files still appear, new files don't appear)
- User confusion: "I uploaded this file on my phone, why can't I find it on my laptop?"
- Full index rebuild is expensive and creates load spikes

**Prevention:**

- **Incremental index updates tied to IPNS polling:**
  1. When IPNS polling detects a CID change for any folder, mark that folder as "index-stale"
  2. Re-fetch and decrypt only stale folders
  3. Update only the affected entries in the search index
  4. This leverages the existing per-folder IPNS resolution mechanism
- **Background index refresh:** Periodically re-traverse the tree in the background (e.g., every 5 minutes) and update the index
- **Event-driven updates:** When the current client makes changes, immediately update the local search index (optimistic update). Only need to handle external changes via polling.
- **Index versioning:** Store a "last indexed CID" per folder. On search, check if any folders have a newer CID than last indexed, and re-index those first.

**Detection:**

- Test: add file on device A, search for it on device B within 60 seconds
- Monitor: index freshness lag (time between file creation and searchability)
- Test: delete file on device A, search for it on device B -- should not appear after sync

**Phase relevance:** Search (Phase 15)
**Confidence:** MEDIUM

---

### Pitfall 16: Selective Sync Breaks Tree Traversal Assumptions

**What goes wrong:** Selective sync (choose which folders to sync locally) means the client may not have decrypted metadata for all folders. The existing tree traversal code assumes it can recursively access all folders from root. With selective sync, some branches are intentionally not loaded, breaking search, storage calculations, and parent navigation.

**Why it happens:**

- Tree traversal code was written assuming full vault access
- Selective sync introduces "holes" in the folder tree
- Search index can only cover synced folders
- File count and storage metrics become partial/inaccurate

**Consequences:**

- Search misses files in unsynced folders (misleading results)
- Storage usage shown is less than actual (user surprised by quota usage)
- Navigation to unsynced parent folder fails or shows empty
- Code that assumes `folder.children` is always available crashes

**Prevention:**

- **Treat selective sync as a UI/download concern, not a metadata concern:**
  - Always sync folder METADATA (names, structure) for all folders
  - Selective sync controls which FILE CONTENTS are downloaded/cached locally
  - Search index can still cover all file names (metadata is lightweight)
  - Storage display shows total vault usage from metadata
- **Clearly distinguish "synced" vs "available" in UI:**
  - Synced folders: instantly accessible, files cached locally
  - Available folders: navigable, files require download on access
- **Null-safe tree traversal:** All tree traversal code must handle `children: null` or `children: "not_loaded"` gracefully

**Detection:**

- Test: enable selective sync, verify all folder names still searchable
- Test: navigate to unsynced folder, verify it loads on-demand
- Code review: all tree traversal handles partial loading

**Phase relevance:** Advanced Sync (Phase 17)
**Confidence:** MEDIUM

---

### Pitfall 17: Offline Queue Replays Can Duplicate Operations

**What goes wrong:** User makes changes offline. Changes are queued. Connection restored, queue replays. But some changes may have already been partially applied (e.g., file upload succeeded but metadata publish failed -- see Pitfall 12). Replay creates duplicate entries in folder metadata.

**Why it happens:**

- No idempotency keys for folder metadata operations
- "Add file to folder" is not idempotent -- running it twice adds two entries
- Partial success states from previous attempts
- CID-based deduplication doesn't work because each encryption produces unique CIDs

**Consequences:**

- Duplicate file entries in folder metadata
- User sees same file listed twice
- Storage quota double-counted
- Confusing UX

**Prevention:**

- **Idempotency keys per operation:**
  - Each queued operation gets a UUID
  - Before applying, check if an operation with the same UUID already produced a result
  - Store operation results (success/failure + CID) alongside the queue
- **Content-based deduplication at metadata level:**
  - Before adding a file entry, check if an entry with the same decrypted filename and similar timestamp already exists
  - Prompt user for resolution if duplicate detected
- **Atomic operation log:**
  - Maintain a local operation log with states: PENDING, UPLOADED, PUBLISHED, COMPLETE
  - On replay, resume from the last incomplete state rather than restarting

**Detection:**

- Test: create offline, reconnect twice, verify no duplicates
- Test: partial failure + retry, verify no duplicates
- Monitor: detect duplicate filenames within same folder

**Phase relevance:** Advanced Sync (Phase 17)
**Confidence:** MEDIUM

---

### Pitfall 18: Shared Folder Key Wrapping Grows Linearly With Recipients

**What goes wrong:** Each recipient needs the `folderKey` wrapped with their `publicKey`. A folder shared with 100 users has 100 ECIES-wrapped copies of the folder key stored in the metadata or a separate key record. ECIES output is ~113 bytes per wrapping (secp256k1). 100 recipients = ~11KB just for key wrapping. This grows with every new share and every key rotation.

**Why it happens:**

- ECIES wrapping is per-recipient (no group key mechanism in ECIES)
- Each share revocation + re-key adds new wrapped keys for remaining recipients
- Folder metadata (or key file) grows with each share operation
- Performance degrades during key rotation (must re-wrap for all N recipients)

**Consequences:**

- Folder metadata bloat for widely-shared folders
- Key rotation becomes O(N) where N = number of recipients
- Share/revoke operations become slow for popular folders
- IPNS publish payload increases

**Prevention:**

- **Practical limit on sharing:** Cap at reasonable number (e.g., 50 recipients per folder)
- **Two-level key wrapping:**
  1. Generate a per-folder "share key" (AES-256)
  2. Wrap `folderKey` with share key
  3. Wrap share key with each recipient's publicKey (ECIES)
  4. On revocation: rotate only the share key, re-wrap for remaining recipients
  5. This doesn't reduce the O(N) wrapping but separates key rotation from folder key rotation
- **Store key wrapping separate from folder metadata:** Keep a "key manifest" as a separate IPFS object. Folder metadata references it by CID. This way, key rotation doesn't require re-publishing the entire folder metadata.
- **Consider group key agreement protocols** for future: e.g., X3DH-based group key exchange. Complex but reduces per-recipient overhead.

**Detection:**

- Performance test: share folder with 50 users, measure share/revoke latency
- Size monitoring: track key manifest size over time
- Alert: folder metadata exceeding size threshold

**Phase relevance:** File Sharing (Phase 12-13)
**Confidence:** MEDIUM

---

## Phase-Specific Warning Summary

| Phase | Feature       | Critical Pitfall                                                                                       | Key Mitigation                                                                |
| ----- | ------------- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------- |
| 12-13 | File Sharing  | Folder key leakage to server (P1), Incomplete revocation (P2), IPNS write conflicts (P3)               | ECIES per-recipient wrapping, re-key on revocation, read-only sharing default |
| 13    | Link Sharing  | Decryption key in URL path leaks to server (P4)                                                        | URL fragment only, static landing page, no analytics                          |
| 14    | MFA           | Enrollment breaks key derivation (P5), Recovery phrase backdoor (P6)                                   | MFA at backend level not Web3Auth, hash-only recovery storage                 |
| 15    | Search        | Index leaks to server (P7), Stale index (P15)                                                          | Client-side only search, incremental index updates                            |
| 16    | Versioning    | Storage explosion (P8), Metadata bloat (P9), Orphaned versions (P12)                                   | Retention limits, separate version manifests, reconciliation jobs             |
| 17    | Advanced Sync | Conflict resolution without plaintext (P11), Selective sync breaks tree (P16), Replay duplicates (P17) | Optimistic concurrency, metadata-only selective sync, idempotency keys        |
| 12-13 | Sharing + TEE | TEE republishing for shared folders (P13)                                                              | Multi-user republish registration                                             |

---

## Integration Pitfalls (Feature Interactions)

These pitfalls emerge from combining multiple Milestone 2 features with the existing system.

### Versioning + Sharing Interaction

**What goes wrong:** A file has 10 versions. The folder is shared. Does the recipient see all 10 versions or only the current one? If they see all versions, the version keys must all be wrapped for them. If a version was created before the share, the recipient's ECIES-wrapped key doesn't exist for old versions.

**Prevention:** Design versioning and sharing to be independent:

- Sharing grants access to current version only (simplest)
- OR: on share, wrap all existing version keys for the recipient (expensive but complete)
- Document the chosen behavior clearly

### MFA + Sharing Interaction

**What goes wrong:** User A shares a folder with User B. User B enables MFA. If MFA changes User B's key derivation (see Pitfall 5), User B can no longer decrypt the shared folder key. The shared folder entry still references User B's old publicKey.

**Prevention:** MFA must NEVER change publicKey. Enforce this invariant with integration tests.

### Search + Versioning Interaction

**What goes wrong:** Search index includes file names. A file was renamed in version 3 from "budget.xlsx" to "q1-budget.xlsx". Searching for "budget" should find it under the new name. But if the search index was built from an older version's name, it returns stale results.

**Prevention:** Search index always uses current version metadata only. Historical names are not indexed.

### Offline Queue + Sharing Interaction

**What goes wrong:** User edits a shared folder offline. While offline, the owner revokes their access and rotates the folder key. When the user comes back online, their queued operations use the old folder key, producing metadata encrypted with a key that other users can't decrypt.

**Prevention:** On reconnect, verify share access is still valid BEFORE replaying offline queue. If access revoked, discard queued operations and notify user.

---

## Sources Summary

### HIGH Confidence (Official Documentation / Production Systems)

- [Tresorit folder sharing architecture](https://support.tresorit.com/hc/en-us/articles/216114387-How-does-folder-sharing-work)
- [Proton Drive security model](https://proton.me/drive/security)
- [IPFS IPNS specification](https://specs.ipfs.tech/ipns/ipns-record/)
- [Multiple IPNS publishers issue -- ipfs/kubo#8433](https://github.com/ipfs/kubo/issues/8433)
- [IPFS Pinning and persistence](https://docs.ipfs.tech/concepts/persistence/)

### MEDIUM Confidence (Research Papers / Expert Analysis)

- [Understanding Leakage in Searchable Encryption (2024)](https://eprint.iacr.org/2024/1558.pdf)
- [IronCore Labs: Solving Search Over Encrypted Data](https://ironcorelabs.com/blog/2021/solving-search-over-encrypted-data/)
- [Proxy Re-Encryption for revocable access control](https://www.mdpi.com/2079-9292/14/15/2988)
- [Blind Indexes for encrypted search](https://medium.com/@joshuakelly/blind-indexes-in-3-minutes-making-encrypted-personal-data-searchable-b26bce99ce7c)
- [Deduplication vs encryption conflict](https://www.sciencedirect.com/science/article/pii/S1319157820305140)

### LOW Confidence (Community Discussion -- Patterns Validated)

- [CRDT dictionary and challenges](https://www.iankduncan.com/engineering/2025-11-27-crdt-dictionary/)
- [Zero-knowledge cloud storage limitations](https://www.networkcomputing.com/cloud-networking/zero-knowledge-cloud-storage-far-from-perfect)
- [What actually makes cloud storage zero-knowledge](https://blog.ellipticc.com/posts/what-actually-makes-a-cloud-storage-service-zero-knowledge/)

---

## End of Milestone 2 Pitfalls
