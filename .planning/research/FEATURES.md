# Feature Landscape: Milestone 2 -- Sharing, Search, MFA, Versioning, Advanced Sync

**Domain:** Zero-knowledge encrypted cloud storage (post-v1.0 features)
**Researched:** 2026-02-11
**Competitors Analyzed:** Tresorit, ProtonDrive, Filen.io, Internxt, MEGA, Cryptomator, Sync.com, NordLocker
**Depends on:** CipherBox v1.0 (Web3Auth auth, AES-256-GCM encryption, ECIES key wrapping, IPFS/IPNS storage, TEE republishing, FUSE mount)

---

## Executive Summary

Milestone 2 adds five feature clusters that transform CipherBox from a storage demonstrator into a usable product. **Sharing is the highest priority** -- every competitor offers it and users expect it. The remaining features (search, MFA, versioning, advanced sync) are important but can follow sharing in phases.

CipherBox's architecture creates both advantages and constraints for these features:

- **Advantage:** Per-folder IPNS keypairs were explicitly designed for future per-folder sharing. Each folder already has its own encryption key wrapped with the owner's public key -- re-wrapping for a recipient's public key is the natural extension.
- **Advantage:** IPFS content-addressing makes versioning cheap. Old CIDs remain valid indefinitely (while pinned), so version history is just a list of CIDs in metadata.
- **Constraint:** No server-side computation on plaintext. Search must be entirely client-side or use privacy-preserving index techniques. The server cannot build indexes.
- **Constraint:** Web3Auth already provides MFA via its threshold key scheme. Adding CipherBox-layer MFA means either layering on top of Web3Auth's MFA or replacing it -- both have UX complexity.
- **Constraint:** IPNS last-writer-wins with sequence numbers means conflict resolution for sync must be designed carefully when sharing introduces multi-writer scenarios.

---

## 1. File/Folder Sharing

### How Sharing Works in Zero-Knowledge Systems

In zero-knowledge encrypted storage, sharing requires **client-side key re-wrapping**. The pattern across all competitors:

1. Owner's client decrypts the folder/file key using their private key
2. Owner's client re-encrypts that key with the recipient's public key (ECIES in CipherBox's case)
3. The re-wrapped key is stored so the recipient can decrypt it
4. The server never sees the plaintext key at any point

This is fundamentally different from traditional cloud sharing where the server simply grants access. Here, the owner must actively perform cryptographic operations on their device.

Three tiers of sharing exist across competitors:

| Tier                    | Mechanism                                | Examples                       | Zero-Knowledge?                |
| ----------------------- | ---------------------------------------- | ------------------------------ | ------------------------------ |
| User-to-User            | Re-wrap keys with recipient's public key | Tresorit, ProtonDrive, Filen   | Yes                            |
| Link (No Account)       | Embed key material in URL fragment       | MEGA, Tresorit Encrypted Links | Partial (key in URL)           |
| Password-Protected Link | Derive key from password, embed in URL   | Tresorit, ProtonDrive          | Partial (PBKDF2 from password) |

### Table Stakes

| Feature                            | Why Expected                                     | Complexity | Dependencies                                                         | Notes                                                                                                                           |
| ---------------------------------- | ------------------------------------------------ | ---------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| User-to-user folder sharing (read) | Core collaboration need; every competitor has it | High       | Recipient key discovery, shared metadata store                       | Tresorit, ProtonDrive, Filen all offer this. CipherBox's per-folder IPNS keypairs were designed for this                        |
| Share invitation flow              | Users need to invite by email/username           | Medium     | User lookup API, notification system                                 | All competitors use email-based invitations                                                                                     |
| Share revocation                   | Must be able to unshare                          | High       | Key rotation for shared folder, re-wrapping for remaining recipients | Critical security feature. Tresorit handles this by rotating the folder key                                                     |
| Share notification                 | Recipient must know they received a share        | Low        | Email or in-app notification                                         | All competitors notify recipients                                                                                               |
| Shared folder view                 | Users need a "Shared with me" section            | Low        | UI component, shared metadata query                                  | Standard UX pattern across all competitors                                                                                      |
| Link-based sharing (view/download) | Share with non-users                             | High       | Link token generation, temporary key derivation, web viewer          | Tresorit and MEGA both embed decryption key in URL fragment (never sent to server). Tresorit whitepaper documents this approach |
| Link expiration                    | Security control for shared links                | Low        | TTL metadata on share records                                        | All competitors offer this                                                                                                      |
| Link password protection           | Extra security layer                             | Medium     | PBKDF2 key derivation from password, two-layer encryption            | Tresorit, ProtonDrive both offer this. Key in URL is encrypted with password-derived key                                        |
| Download limit on links            | Prevent unlimited redistribution                 | Low        | Server-side counter (does not affect encryption)                     | Tresorit offers this                                                                                                            |

### Differentiators

| Feature                                    | Value Proposition                                                                                            | Complexity | Notes                                                                                                                                                                 |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IPFS-native sharing via IPNS name exchange | Share a folder by sharing its IPNS name + encrypted folder key. Recipient can independently resolve and sync | Medium     | Unique to CipherBox. No competitor has decentralized sharing. Recipient gets their own copy of the IPNS pointer                                                       |
| Read-write shared folders                  | Multiple users can add files to shared folder                                                                | Very High  | Requires multi-writer IPNS coordination or separate IPNS per writer. Major architectural challenge                                                                    |
| Per-folder granular permissions            | Share individual folders without exposing parent structure                                                   | Low        | CipherBox already has per-folder keys and IPNS names -- sharing a subfolder does NOT require sharing parent keys. This is better than Tresorit's tresor-level sharing |
| Offline-resilient sharing                  | Shared folders continue working via TEE republishing even when sharer is offline                             | Medium     | Extend TEE republishing to shared IPNS entries. Unique advantage                                                                                                      |
| Share audit log                            | See who accessed shared content and when                                                                     | Medium     | Server-side access logging. Does not compromise zero-knowledge since server already sees access patterns                                                              |

### Anti-Features

| Anti-Feature                       | Why Avoid                                                                       | What to Do Instead                                                                                                  |
| ---------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Server-side key re-encryption      | Server would need plaintext keys, breaking zero-knowledge                       | Client-side re-wrapping only. Owner's device must be online to share                                                |
| Proxy re-encryption via server     | Tempting shortcut where server transforms ciphertexts. Adds trusted third party | Direct ECIES re-wrapping. Accept that owner must be online to initiate shares                                       |
| Shared password for link access    | Password sent to server to unlock = server sees password                        | Derive key from password client-side (PBKDF2), embed encrypted link key in URL fragment. Server never sees password |
| "Anyone with link" edit access     | Anonymous editing is chaos for encrypted systems                                | Links should be read/download only. Edit access requires authenticated user-to-user sharing                         |
| Sharing by copying encrypted files | Duplicates storage, breaks version consistency                                  | Share by re-wrapping keys to the same IPFS CIDs. One copy of encrypted data, multiple key wrappers                  |

### Implementation Architecture for CipherBox

#### User-to-User Sharing Flow

```text
1. Owner selects folder to share, enters recipient email
2. Client calls API to discover recipient's publicKey (new endpoint)
3. Client decrypts folderKey: ECIES_Decrypt(folderKeyEncrypted, ownerPrivateKey)
4. Client decrypts ipnsPrivateKey: ECIES_Decrypt(ipnsPrivateKeyEncrypted, ownerPrivateKey)
5. Client re-wraps for recipient:
   - recipientFolderKey = ECIES_Encrypt(folderKey, recipientPublicKey)
   - recipientIpnsKey = ECIES_Encrypt(ipnsPrivateKey, recipientPublicKey)
6. Client sends share record to server:
   {folderId, recipientPublicKey, recipientFolderKey, recipientIpnsKey, permission: "read"}
7. Server stores share record; notifies recipient
8. Recipient's client fetches share records, decrypts folder key, resolves IPNS
```

#### Link-Based Sharing Flow (Tresorit/MEGA Pattern)

```text
1. Owner selects file/folder to share via link
2. Client generates random linkKey (256-bit)
3. Client encrypts folderKey with linkKey: AES-GCM(folderKey, linkKey)
4. Client sends encrypted package to server, gets share token
5. Server returns URL: https://cipherbox.io/s/{token}
6. Owner distributes URL with fragment: https://cipherbox.io/s/{token}#base64(linkKey)
   (Fragment never sent to server per HTTP spec)
7. Recipient opens link; web viewer extracts linkKey from fragment
8. Web viewer fetches encrypted package from server using token
9. Web viewer decrypts folderKey with linkKey, then decrypts content

Password protection adds a layer:
- linkKey is encrypted with PBKDF2(password, salt)
- Recipient enters password in browser to derive key, then unwrap linkKey
```

New Database Requirements:

- `shared_folders` table: owner_id, recipient_id, folder_ipns_name, encrypted_folder_key, encrypted_ipns_key, permission, created_at, revoked_at
- `share_links` table: token, folder_ipns_name, encrypted_package, password_salt (nullable), expires_at, download_limit, download_count

---

## 2. Encrypted Search

### How Search Works in Zero-Knowledge Systems

Search is one of the hardest problems in zero-knowledge storage. The server cannot index files because it cannot see content or even file names. Three approaches exist in the industry:

| Approach                    | How It Works                                                                                                | Used By                         | Tradeoffs                                                                                              |
| --------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Client-side full decryption | Decrypt all file names in memory, search locally                                                            | Cryptomator, early Filen        | Only works for currently-open folder. Cannot do global search                                          |
| HMAC-hashed index           | Hash file name chunks with user's key, store hashes on server. Hash search query the same way, match hashes | Filen (2025+)                   | Fast global search, server sees hashed tokens (some metadata leakage), no content search               |
| Encrypted client-side index | Build search index on client, encrypt it, store encrypted blob on server/IPFS, decrypt on client to search  | Academic (Bloom filter schemes) | Full privacy, but index must be downloaded and decrypted for every search. Index grows with vault size |

### Table Stakes

| Feature                        | Why Expected                                    | Complexity | Dependencies                            | Notes                                                                                                                                  |
| ------------------------------ | ----------------------------------------------- | ---------- | --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| File name search (global)      | Users cannot browse large vaults without search | Medium     | Client-side index or HMAC approach      | Filen solved this in 2025 with HMAC chunked hashing. ProtonDrive has global search. This is table stakes for any vault with 100+ files |
| Folder name search             | Same as file name search                        | Low        | Same infrastructure as file name search | Bundle with file name search                                                                                                           |
| Search results with navigation | Clicking result navigates to file location      | Low        | UI component                            | Standard UX                                                                                                                            |
| Recent files                   | Quick access to recently used files             | Low        | Client-side timestamp tracking          | All competitors offer this                                                                                                             |

### Differentiators

| Feature                            | Value Proposition                                                            | Complexity | Notes                                                                                                                                                                                        |
| ---------------------------------- | ---------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Full-text content search           | Search inside documents, not just names                                      | Very High  | Requires client-side indexing of file contents. Must download, decrypt, index, then store encrypted index. Major resource use. ProtonDrive does NOT offer this. Tresorit does for enterprise |
| IPFS-stored encrypted search index | Search index stored as encrypted IPFS object, synced across devices via IPNS | High       | Unique to CipherBox. Index is an encrypted blob pinned to IPFS with its own IPNS pointer. Any device can fetch and decrypt it                                                                |
| Incremental index updates          | Only re-index changed files                                                  | Medium     | Track which files were indexed by CID. New CID = needs re-indexing                                                                                                                           |
| Fuzzy/typo-tolerant search         | Find files even with misspellings                                            | Medium     | Client-side fuzzy matching (Levenshtein distance) after index decryption                                                                                                                     |

### Anti-Features

| Anti-Feature                                | Why Avoid                                         | What to Do Instead                                                                                                      |
| ------------------------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Server-side search index                    | Server sees search terms and file names           | Client-side only or HMAC-hashed approach                                                                                |
| Sending search queries to server            | Leaks user intent even if results are encrypted   | All search processing on client                                                                                         |
| Indexing file contents without user consent | Resource intensive, privacy concern               | Opt-in content indexing. Default to name-only search                                                                    |
| Bloom filter with high false positive rates | Poor UX, wasted bandwidth downloading wrong files | Use HMAC chunked approach (Filen pattern) or client-side index. Bloom filters have academic appeal but practical issues |

### Recommended Approach for CipherBox

#### Phase 1: HMAC-Hashed Name Search (Filen Pattern)

This is the pragmatic first step. HIGH confidence this approach works -- Filen shipped it in 2025.

```text
Index Build (on file upload/rename):
1. Take decrypted file name "quarterly-report-2026.pdf"
2. Generate search tokens: ["quarterly", "report", "2026", "pdf", "qua", "uar", "art", ...]
   (trigrams + word boundaries)
3. HMAC each token: HMAC-SHA256(token, searchKey) where searchKey = HKDF(masterKey, "search")
4. Send hashed tokens to server, associated with file's encrypted reference

Search (on query):
1. User types "report"
2. Client computes: HMAC-SHA256("report", searchKey)
3. Client sends hashed query to server
4. Server matches against stored hashes, returns matching file references
5. Client decrypts file names for display
```

Privacy tradeoff: Server learns that "something" matches between a search query and certain files, but cannot learn what the actual names or queries are. This is the same tradeoff Filen accepted and users find acceptable.

#### Phase 2: Encrypted Client-Side Index (Optional, for Content Search)

```text
1. Client maintains a search index (e.g., using MiniSearch or Lunr.js)
2. Index is serialized to JSON, encrypted with vault-level search key
3. Encrypted index stored as IPFS object, referenced from root IPNS metadata
4. On search: fetch encrypted index from IPFS, decrypt in memory, query locally
5. Index updated incrementally on file changes
```

Tradeoff: Index blob must be downloaded each session. For a vault with 10K files, index might be 5-20MB. Acceptable for desktop, potentially slow on mobile.

---

## 3. Multi-Factor Authentication (MFA)

### How MFA Works with Web3Auth

This is a unique situation because **Web3Auth already provides MFA** through its threshold key scheme. When MFA is enabled in Web3Auth:

1. User's private key is split into 3 shares (device share, Web3Auth share, recovery share)
2. Any 2 of 3 shares are needed to reconstruct the key
3. Additional factors (TOTP, passkey, backup phrase) serve as recovery mechanisms for shares

Key insight: CipherBox-layer MFA would be **in addition to** Web3Auth's key protection. This is about protecting CipherBox API access, not the encryption key itself.

### Table Stakes

| Feature                  | Why Expected                       | Complexity | Dependencies                                          | Notes                                                                                                                                                                             |
| ------------------------ | ---------------------------------- | ---------- | ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Web3Auth MFA enablement  | Protect the encryption key itself  | Low        | Web3Auth SDK configuration                            | Web3Auth supports: device share, social recovery, TOTP, passkey, backup phrase. CipherBox just needs to expose the configuration UI and set mfaLevel to "optional" or "mandatory" |
| TOTP (Authenticator App) | Standard 2FA that users understand | Low        | Web3Auth factor configuration OR CipherBox-layer TOTP | Web3Auth natively supports TOTP as a backup factor. Recommend using Web3Auth's TOTP rather than building a separate TOTP system                                                   |
| Recovery codes           | Backup for lost 2FA device         | Low        | Generate during MFA setup, store encrypted            | Standard: 8-12 single-use codes. These serve as emergency access. In Web3Auth context, these map to the "backup share"                                                            |
| MFA settings page        | Users must be able to manage MFA   | Low        | UI component                                          | Show enabled factors, allow adding/removing                                                                                                                                       |

### Differentiators

| Feature                           | Value Proposition                                                          | Complexity | Notes                                                                                                                                    |
| --------------------------------- | -------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| WebAuthn/Passkey support          | Phishing-resistant, biometric-based 2FA                                    | Medium     | Web3Auth supports passkeys as an MFA factor. Modern, hardware-backed security. Passkeys are bound to origin, preventing phishing attacks |
| CipherBox-layer session MFA       | Additional verification for sensitive operations (sharing, export, delete) | Medium     | Separate from Web3Auth MFA. Requires TOTP/WebAuthn before performing destructive operations. Defense-in-depth                            |
| Mandatory MFA for shared folders  | Require MFA-enabled accounts to access shared content                      | Low        | Policy flag on share records. Tresorit offers this for enterprise                                                                        |
| Recovery phrase (BIP-39 mnemonic) | Human-readable backup for key recovery                                     | Low        | Web3Auth supports this as backup factor. 12/24-word phrase that encodes a key share                                                      |

### Anti-Features

| Anti-Feature                               | Why Avoid                                                              | What to Do Instead                                                                                                                    |
| ------------------------------------------ | ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| SMS-based 2FA                              | SIM-swapping attacks, not phishing-resistant                           | WebAuthn/Passkey or TOTP only                                                                                                         |
| Building custom MFA separate from Web3Auth | Duplicates auth complexity, does not protect the actual encryption key | Leverage Web3Auth's MFA SDK. CipherBox-layer MFA only for session protection                                                          |
| MFA that blocks vault recovery             | User locks themselves out permanently                                  | Always provide recovery codes. Web3Auth's 2-of-3 threshold means losing one factor is survivable                                      |
| Storing TOTP seeds on CipherBox server     | Server compromise reveals all TOTP secrets                             | Web3Auth manages TOTP seeds in their distributed infrastructure. If CipherBox-layer TOTP needed, encrypt seeds with user's public key |

### Recommended Approach for CipherBox

#### Layer 1: Web3Auth MFA (Key Protection)

- Configure Web3Auth mfaLevel to "optional" (user chooses)
- Expose MFA setup in CipherBox settings UI
- Support: device share (automatic), TOTP, passkey, recovery phrase
- This protects the encryption keypair itself

#### Layer 2: CipherBox Session MFA (Operation Protection)

- For sensitive operations: require re-authentication or TOTP verification
- Operations: share creation, vault export, folder deletion, MFA settings change
- Store TOTP seed encrypted with user's public key in CipherBox backend
- WebAuthn credentials registered with CipherBox backend (standard WebAuthn RP)

```text
Web3Auth MFA protects: Key reconstruction (login)
CipherBox MFA protects: Sensitive API operations (during session)

Both layers work independently. User could have:
- Web3Auth MFA enabled (key protected by threshold scheme)
- CipherBox MFA enabled (sensitive operations require re-auth)
- Either or both
```

---

## 4. File Versioning

### How Versioning Works in Encrypted Storage

File versioning in zero-knowledge systems follows a simple principle: **old encrypted versions are immutable artifacts that can be retained alongside new versions**. Since each file version has its own encryption key and CID, version history is fundamentally a list management problem.

How competitors implement it:

| Competitor  | Approach                                                                                                                                       | Retention                            | Storage Cost                 |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | ---------------------------- |
| ProtonDrive | Automatic version save on update/replace. Versions stored as separate encrypted blobs with their own keys. 200 versions, up to 10 years (paid) | 7 days (free), 10 years (paid)       | Versions count against quota |
| Tresorit    | Unlimited versions per file. Each version is a separate encrypted blob                                                                         | 10 versions (free), unlimited (paid) | Counts against quota         |
| Filen       | File history with restoration                                                                                                                  | Limited by plan                      | Counts against quota         |
| MEGA        | Versioning available                                                                                                                           | Per plan                             | Counts against quota         |

### Table Stakes

| Feature                                   | Why Expected                                            | Complexity | Dependencies                                                                    | Notes                                                                              |
| ----------------------------------------- | ------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Automatic version creation on file update | Users expect to recover from accidental overwrites      | Medium     | Metadata schema change to store version list per file                           | ProtonDrive does this automatically. No explicit user action required              |
| Version history view                      | See list of previous versions with timestamps and sizes | Low        | UI component, version metadata in IPNS                                          | Right-click -> "Version history" pattern (ProtonDrive, Tresorit)                   |
| Version download                          | Download a specific previous version                    | Low        | Existing file download flow, just with historical CID                           | Standard across all competitors                                                    |
| Version restore                           | Replace current version with an older one               | Medium     | Creates new version entry pointing to old CID. Must update folder metadata IPNS | Standard across all competitors                                                    |
| Version retention policy                  | Control how long versions are kept                      | Low        | Configurable: time-based (7/30/90 days) and count-based (max N versions)        | ProtonDrive: 7 days free, 10 years paid. CipherBox can start with a simpler policy |
| Versions count toward storage quota       | Users understand storage implications                   | Low        | Sum version sizes in quota calculation                                          | Universal pattern. No competitor gives free version storage                        |

### Differentiators

| Feature                                | Value Proposition                                                                               | Complexity | Notes                                                                                                                                                                                                                  |
| -------------------------------------- | ----------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| IPFS-native version immutability       | Old CIDs are cryptographically immutable. Version integrity is guaranteed by content addressing | Zero       | CipherBox gets this for free from IPFS. Old versions cannot be tampered with as long as they remain pinned. This is stronger than traditional cloud where old versions could theoretically be modified by the provider |
| Version diff (metadata only)           | Show what changed between versions (size, date)                                                 | Low        | Client-side comparison of version metadata                                                                                                                                                                             |
| Branching versions from shared folders | When a shared folder has a conflict, versions capture both branches                             | High       | Requires conflict detection in shared folders                                                                                                                                                                          |

### Anti-Features

| Anti-Feature                   | Why Avoid                                                                                    | What to Do Instead                                                                                              |
| ------------------------------ | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| Server-side version management | Server would need to understand file structure                                               | Client manages version list in IPNS metadata. Server just pins/unpins CIDs                                      |
| Unlimited free versions        | Storage costs spiral. IPFS pinning is not free                                               | Enforce retention policy. Auto-cleanup expired versions                                                         |
| Delta/diff storage             | Storing encrypted diffs is complex and cannot be deduplicated due to unique keys per version | Store full encrypted copies. IPFS pinning cost is per-CID, and full copies are simpler to implement and restore |
| Version locking                | Preventing updates while viewing history                                                     | Optimistic concurrency. Versions are immutable; new writes create new versions                                  |

### Implementation Architecture for CipherBox

IPFS makes versioning architecturally elegant. Each file update already creates a new CID. The only change is **retaining old CIDs instead of unpinning them**.

Metadata Schema Change:

```json
{
  "type": "file",
  "nameEncrypted": "0x...",
  "nameIv": "0x...",
  "cid": "QmCurrentVersion...",
  "fileKeyEncrypted": "0x...",
  "fileIv": "0x...",
  "encryptionMode": "GCM",
  "size": 2048576,
  "created": 1705268100,
  "modified": 1705368100,
  "versions": [
    {
      "cid": "QmPreviousVersion2...",
      "fileKeyEncrypted": "0x...",
      "fileIv": "0x...",
      "encryptionMode": "GCM",
      "size": 1948576,
      "modified": 1705268100
    },
    {
      "cid": "QmPreviousVersion1...",
      "fileKeyEncrypted": "0x...",
      "fileIv": "0x...",
      "encryptionMode": "GCM",
      "size": 1848576,
      "modified": 1705168100
    }
  ]
}
```

#### Update Flow Change (Compared to Current v1.0)

```text
Current v1.0:
1. Upload new encrypted file -> new CID
2. Update metadata: replace old CID with new CID
3. Unpin old CID (data lost)

With Versioning:
1. Upload new encrypted file -> new CID
2. Move current {cid, fileKeyEncrypted, fileIv, size, modified} to versions array
3. Update metadata: set new CID as current
4. Do NOT unpin old CID (version retained)
5. Publish updated IPNS
6. Background: enforce retention policy (unpin versions exceeding limit/age)
```

Storage Impact: Each version is a full encrypted copy. A 10MB file with 5 versions = 50MB of pinned IPFS data. Retention policy is essential.

---

## 5. Advanced Sync

### How Sync/Conflict Resolution Works in Encrypted Storage

CipherBox v1.0 uses IPNS polling (30s interval) with last-writer-wins (highest IPNS sequence number). This works for single-user multi-device but breaks down with:

- Two devices editing the same folder simultaneously
- Shared folders with multiple writers
- Offline edits that need to sync later

How competitors handle conflicts:

| Competitor  | Approach                                                                                            | Notes                                                   |
| ----------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Dropbox     | Detects conflicts, creates "conflicted copy" with user name and timestamp                           | Simple, user resolves manually                          |
| Tresorit    | Similar conflict copies. File locking for enterprise                                                | Prioritizes data preservation over automatic resolution |
| Cryptomator | Defers to underlying cloud provider's conflict handling. Encrypted conflict copies can be confusing | Weakness of the overlay approach                        |
| ProtonDrive | Detects conflicts in desktop client, creates conflict copies                                        | Standard approach                                       |
| Syncthing   | Vector clocks for conflict detection, user resolution                                               | Open-source, more sophisticated                         |

Key insight: No major encrypted storage product uses automatic conflict resolution (CRDTs, OT). They all create conflict copies and let users resolve. This is because:

1. File-level operations are not mergeable (unlike text documents)
2. Encrypted content cannot be merged server-side
3. User judgment is needed to pick the "right" version

### Table Stakes

| Feature                  | Why Expected                                                      | Complexity | Dependencies                                                                                                                  | Notes                                                                                    |
| ------------------------ | ----------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Conflict detection       | Must know when two devices edited simultaneously                  | Medium     | Compare IPNS sequence numbers and timestamps. If local has unpublished changes and remote has newer sequence, conflict exists | Current v1.0 has NO conflict detection. Remote silently overwrites local state           |
| Conflict copies          | Preserve both versions when conflict detected                     | Medium     | Create "filename (conflict from Device on Date).ext"                                                                          | Universal pattern. Better to over-preserve than lose data                                |
| Conflict notification    | Alert user to resolve conflict                                    | Low        | UI notification component                                                                                                     | All competitors show conflict indicators                                                 |
| Selective sync (desktop) | Choose which folders sync to local disk                           | Medium     | FUSE mount configuration, folder-level sync settings                                                                          | Dropbox, Tresorit, ProtonDrive all offer this. Essential for large vaults on limited SSD |
| Sync status indicators   | Show sync state per file/folder (synced, syncing, pending, error) | Low        | UI state management                                                                                                           | Standard in all desktop sync clients                                                     |
| Offline edit queue       | Queue changes made while offline, sync when reconnected           | High       | Local change log, reconciliation on reconnect                                                                                 | CipherBox desktop CLIENT_SPECIFICATION mentions this as "outstanding question"           |

### Differentiators

| Feature                                | Value Proposition                                                                           | Complexity | Notes                                                                                           |
| -------------------------------------- | ------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------- |
| IPNS sequence-based conflict detection | IPNS records have built-in sequence numbers providing natural ordering                      | Low        | CipherBox gets causal ordering for free from IPNS. Sequence number gaps indicate missed updates |
| Per-folder sync granularity            | Since each folder has its own IPNS, selective sync is naturally folder-granular             | Low        | Stop polling specific IPNS names = stop syncing those folders. Architecturally elegant          |
| Decentralized conflict resolution      | In shared folders, conflicts can be detected by any participant by comparing IPNS sequences | Medium     | Unique to IPFS/IPNS architecture. No central server needed to detect conflicts                  |
| On-demand file hydration               | FUSE mount shows all files but only downloads when accessed                                 | High       | File stubs in FUSE that trigger IPFS fetch on read. Tresorit Drive 2.0 does this                |
| Bandwidth-aware sync                   | Prioritize sync by file importance, defer large files on slow connections                   | Medium     | Sync priority metadata per folder                                                               |

### Anti-Features

| Anti-Feature                                   | Why Avoid                                                                                               | What to Do Instead                                                     |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Automatic merge of conflicting folder metadata | Silent data loss if merge logic is wrong. Encrypted metadata cannot be inspected by server              | Create conflict copies. Let user resolve                               |
| CRDTs for file operations                      | Massive over-engineering for file-level operations. CRDTs make sense for text documents, not file trees | Simple conflict copy pattern. Last-writer-wins with conflict detection |
| Server-side conflict resolution                | Server cannot see decrypted content or metadata                                                         | All conflict detection and resolution must be client-side              |
| Invisible background sync without status       | Users panic when they cannot see sync state                                                             | Always show sync status. Transparent progress indicators               |
| Full vault download for offline                | Storage and bandwidth prohibitive for large vaults                                                      | Selective sync. Only sync explicitly chosen folders offline            |

### Recommended Conflict Resolution for CipherBox

#### Single-User Multi-Device (No Sharing)

```text
Device A and Device B both have folder at IPNS sequence 5.

Device A edits: publishes sequence 6
Device B edits offline, has local changes based on sequence 5

Device B comes online, polls IPNS:
1. Sees sequence 6 from Device A
2. Has local unpublished changes based on sequence 5
3. CONFLICT DETECTED

Resolution:
1. Fetch remote metadata (sequence 6), decrypt
2. Compare with local pending changes
3. For file additions: merge (both additions are valid)
4. For file modifications to same file: create conflict copy
5. For contradictory operations (A deleted file that B modified):
   preserve B's modification as conflict copy
6. Publish merged result as sequence 7
```

#### Multi-Writer Shared Folders

This is significantly harder. Two users modifying the same shared folder creates race conditions that IPNS sequence numbers alone cannot fully resolve.

Recommended approach: Do NOT implement multi-writer shared folders in the initial sharing phase. Start with:

- Read-only sharing (recipient can view/download but not modify)
- Single-writer sharing (only owner can modify shared folder)
- Defer read-write sharing to a later phase with proper conflict handling

---

## Feature Dependencies

```text
Milestone 2 Dependencies:

Sharing (Phase A -- highest priority)
|-- User-to-user sharing (read-only)
|   |-- Requires: Recipient public key discovery API
|   |-- Requires: Share record storage (new DB table)
|   |-- Requires: Client-side key re-wrapping
|   +-- Requires: "Shared with me" UI
|-- Link sharing
|   |-- Requires: User-to-user sharing infrastructure
|   |-- Requires: Web viewer for non-authenticated access
|   |-- Requires: Link token management
|   +-- Password protection (extends link sharing)
|-- Share revocation
|   |-- Requires: Key rotation for shared folders
|   +-- Requires: Re-wrapping for remaining recipients

MFA (Phase B -- should accompany sharing)
|-- Web3Auth MFA configuration UI
|   |-- Requires: Web3Auth SDK mfaSettings integration
|   +-- Requires: Recovery phrase backup flow
|-- CipherBox session MFA (optional enhancement)
|   |-- Requires: TOTP verification endpoint
|   +-- Requires: WebAuthn registration/verification

File Versioning (Phase C -- independent, can parallel)
|-- Version retention in metadata
|   |-- Requires: Metadata schema migration (add versions array)
|   |-- Requires: Changed unpin logic (skip versioned CIDs)
|   +-- Requires: Retention policy enforcement
|-- Version history UI
|   +-- Requires: Version metadata in IPNS records

Search (Phase D -- independent, can parallel)
|-- HMAC-hashed name search
|   |-- Requires: Search token generation on upload/rename
|   |-- Requires: Server-side hash matching endpoint
|   +-- Requires: Search UI component
|-- Encrypted content index (optional, later)
|   |-- Requires: HMAC search working first
|   +-- Requires: IPFS-stored encrypted index blob

Advanced Sync (Phase E -- depends on sharing for multi-writer)
|-- Conflict detection
|   |-- Requires: Local change tracking
|   +-- Requires: IPNS sequence comparison logic
|-- Selective sync
|   |-- Requires: Per-folder sync configuration
|   +-- Requires: FUSE mount selective filtering
|-- Offline queue
|   |-- Requires: Local operation log
|   +-- Requires: Reconciliation on reconnect
```

---

## Phase Ordering Recommendation

Based on dependency analysis, user expectations, and complexity:

### Phase 1: Sharing (User-to-User) + MFA

Rationale: Sharing is the largest feature gap. MFA should ship alongside sharing because sharing exposes data to others -- security must accompany access expansion.

Includes:

- User-to-user read-only folder sharing
- Share invitation and acceptance flow
- Share revocation (key rotation)
- Web3Auth MFA configuration
- Recovery codes/phrase

### Phase 2: File Versioning + Link Sharing

Rationale: Versioning is architecturally simple (metadata change + skip unpin) and high value. Link sharing extends Phase 1's sharing infrastructure.

Includes:

- Automatic version creation on file update
- Version history view and restore
- Retention policy
- Link-based sharing (no account required)
- Password-protected links

### Phase 3: Search + Advanced Sync

Rationale: Search and sync improvements are polish features that matter more as vault size and user count grow. Conflict resolution matters most when sharing enables multi-writer scenarios.

Includes:

- HMAC-hashed name search
- Conflict detection and conflict copies
- Selective sync for desktop
- Sync status indicators

### Phase 4: Advanced Features (optional)

- Full-text content search (encrypted index)
- Read-write shared folders with conflict handling
- On-demand file hydration for FUSE
- CipherBox-layer session MFA

---

## Complexity Summary

| Feature Area                | Estimated Complexity | Key Risk                                                     |
| --------------------------- | -------------------- | ------------------------------------------------------------ |
| User-to-user sharing (read) | High                 | Key re-wrapping correctness, revocation key rotation         |
| Link sharing                | High                 | Web viewer for unauthenticated access, URL fragment security |
| MFA (Web3Auth)              | Low                  | SDK configuration, mostly UI work                            |
| MFA (CipherBox-layer)       | Medium               | Additional TOTP/WebAuthn infrastructure                      |
| File versioning             | Medium               | Metadata migration, retention policy enforcement             |
| Name search (HMAC)          | Medium               | Token generation strategy, search quality tuning             |
| Content search              | Very High            | Index size management, cross-device sync of index            |
| Conflict detection          | Medium               | Edge cases with offline edits, IPNS sequence gaps            |
| Selective sync              | Medium               | FUSE mount integration, folder-level toggle                  |
| Read-write sharing          | Very High            | Multi-writer IPNS coordination, conflict explosion           |

---

## Sources

Research compiled from:

- [Tresorit Encrypted Link Whitepaper](https://cdn.tresorit.com/media-storage/20220223143452794encrypted-link-whitepaper.pdf) -- Encrypted link architecture (PDF)
- [Tresorit Zero-Knowledge Encryption](https://tresorit.com/features/zero-knowledge-encryption) -- ZK architecture overview
- [Tresorit Security](https://tresorit.com/security) -- RSA-4096, PKI, symmetric key tree
- [ProtonDrive Version History](https://proton.me/blog/drive-version-history) -- Version retention policies, encrypted versioning
- [ProtonDrive Version History Support](https://proton.me/support/version-history) -- Version management details
- [ProtonDrive Security](https://proton.me/drive/security) -- ECC Curve25519, OpenPGP key hierarchy
- [Filen Cryptography Docs](https://docs.filen.io/docs/api/guides/cryptography/) -- AES-GCM, RSA sharing, HMAC search
- [Filen Encryption](https://filen.io/encryption) -- HMAC hashed search implementation
- [Filen Status Update March 2025](https://filen.io/hub/status-update-march-2025/) -- Global search launch
- [MEGA Security Discussion](https://github.com/meganz/webclient/discussions/124) -- Node keys, RSA-ECB wrapping
- [MEGA Malleable Encryption (Vulnerability)](https://mega-awry.io/) -- ECB mode vulnerability in MEGA
- [Web3Auth MFA Documentation](https://web3auth.io/docs/features/mfa) -- Threshold key scheme, factor types
- [Web3Auth MFA SDK](https://web3auth.io/docs/sdk/web/modal/mfa) -- mfaSettings configuration
- [Web3Auth Passkeys Blog](https://blog.web3auth.io/passkeys-authentication-factor/) -- Passkey integration
- [IPFS/IPNS Versioning Discussion](https://discuss.ipfs.tech/t/history-versioning-of-documents-ipfs-ipns/564) -- CID-based version tracking patterns
- [IPFS IPNS Docs](https://docs.ipfs.tech/concepts/ipns/) -- IPNS sequence numbers, mutable pointers
- [Cryptomator Sync Conflicts](https://docs.cryptomator.org/desktop/sync-conflicts/) -- Conflict copy pattern
- [Bloom Filter Encrypted Search](https://ieeexplore.ieee.org/document/10148628/) -- Privacy-preserving search
- [Hivenet Zero-Knowledge Guide](https://www.hivenet.com/post/zero-knowledge-encryption-the-ultimate-guide-to-unbreakable-data-security) -- ZK architecture patterns
- [CyberNews Secure Cloud Storage 2026](https://cybernews.com/reviews/most-secure-cloud-storage/) -- Competitor landscape

### Confidence Assessment

| Area                       | Confidence | Rationale                                                                                                                                                     |
| -------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sharing architecture       | HIGH       | Multiple competitor whitepapers, well-understood cryptographic patterns (ECIES re-wrapping). CipherBox's per-folder IPNS was designed for this                |
| Link sharing               | MEDIUM     | Tresorit whitepaper confirms URL fragment approach. MEGA uses similar pattern. Implementation details for CipherBox-specific IPFS integration need validation |
| Encrypted search (HMAC)    | HIGH       | Filen shipped this in production (2025). Well-documented approach with clear privacy tradeoffs                                                                |
| Encrypted search (content) | LOW        | Academic approaches exist but no major competitor offers true encrypted content search. Complexity is very high                                               |
| MFA via Web3Auth           | HIGH       | Official Web3Auth documentation confirms MFA factor support. SDK configuration is documented                                                                  |
| CipherBox-layer MFA        | MEDIUM     | Standard WebAuthn/TOTP patterns, but interaction with Web3Auth auth flow needs validation                                                                     |
| File versioning            | HIGH       | ProtonDrive confirms the "retain old versions" pattern. IPFS content addressing makes this architecturally natural for CipherBox                              |
| Conflict resolution        | MEDIUM     | Competitor pattern (conflict copies) is well-established. CipherBox-specific IPNS sequence-based detection needs implementation validation                    |
| Selective sync             | MEDIUM     | Standard pattern in desktop clients. FUSE mount integration specifics need validation                                                                         |
| Multi-writer sharing       | LOW        | No clear pattern from competitors for encrypted multi-writer. Very complex problem. Recommend deferring                                                       |
