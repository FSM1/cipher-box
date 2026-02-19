# Architecture Research: Milestone 2 Features

**Domain:** Zero-knowledge encrypted cloud storage -- sharing, search, MFA, versioning, advanced sync
**Researched:** 2026-02-11
**Overall confidence:** MEDIUM-HIGH
**Scope:** How five new features integrate with the existing CipherBox architecture

---

## Executive Summary

Milestone 2 adds five capabilities to CipherBox: folder sharing, encrypted search, MFA, file versioning, and advanced sync/conflict resolution. Each feature must preserve the zero-knowledge property -- the server never sees plaintext data or unencrypted keys.

The existing architecture is well-positioned for these features. The per-folder IPNS keypair design (already built in v1.0) was explicitly designed for sharing ("enables future per-folder sharing" per TECHNICAL_ARCHITECTURE.md Section 5.1). IPFS content-addressing gives versioning "for free" at the CID level. Web3Auth's threshold key scheme natively supports MFA factors. The two hardest problems are (1) designing a key exchange protocol for sharing that keeps the server zero-knowledge, and (2) building a client-side encrypted search index that is useful without leaking information.

Build order recommendation: MFA first (smallest surface area, independent of other features), then Versioning (extends existing metadata schema), then Sharing (requires new key exchange protocol + backend entities), then Search (depends on metadata schema finalized by sharing/versioning), and finally Advanced Sync (cross-cutting concern, benefits from all other features being stable).

---

## 1. Sharing: Zero-Knowledge Folder Key Exchange

### 1.1 Integration Points with Existing Architecture

Existing components touched:

- `packages/crypto/src/ecies/` -- wrapKey/unwrapKey used for re-wrapping folder keys to recipient
- `packages/crypto/src/folder/types.ts` -- FolderMetadata and FolderEntry need sharing metadata
- `apps/api/src/auth/entities/user.entity.ts` -- publicKey lookup for recipients
- `apps/api/src/ipns/entities/folder-ipns.entity.ts` -- shared folder IPNS tracking
- `apps/web/src/stores/folder.store.ts` -- shared folders need distinct treatment in UI
- `apps/web/src/stores/vault.store.ts` -- shared-with-me folders don't come from vault root

Existing components NOT touched:

- Encryption primitives (AES-256-GCM, Ed25519) -- no changes needed
- IPFS relay endpoints -- shared folders use the same /ipfs/add, /ipfs/cat, /ipns/resolve
- TEE republishing -- shared IPNS records still republish the same way
- Web3Auth authentication -- unaffected

### 1.2 Key Exchange Protocol: Direct ECIES Re-wrapping

Recommendation: Direct re-wrapping, NOT proxy re-encryption.

Proxy re-encryption (PRE) allows a server proxy to transform ciphertext from one key to another without seeing plaintext. While elegant, it is overkill for CipherBox because:

- PRE requires the data owner to be offline -- but CipherBox sharing is initiated while the owner is online
- PRE adds cryptographic complexity (bi-directional vs uni-directional schemes, re-encryption key generation)
- PRE requires the server to perform re-encryption operations, which adds trust surface
- The simpler approach (direct ECIES re-wrapping by the owner's client) achieves the same zero-knowledge property

Confidence: HIGH -- This is the same pattern used by Tresorit (RSA-4096 key wrapping for sharing) and Keeper (record/folder key wrapping with recipient's public key). Both are proven at scale in zero-knowledge systems.

Protocol:

```text
SHARE FLOW (Owner shares folder with Recipient):

1. Owner's client already has: folderKey (plaintext AES-256), ipnsPrivateKey (plaintext Ed25519)
2. Owner fetches Recipient's publicKey from server: GET /users/lookup?identifier=<email-or-publicKey>
3. Owner's client re-wraps the folder key:
   sharedFolderKeyEncrypted = ECIES(folderKey, recipientPublicKey)
4. Owner's client re-wraps the IPNS private key (for read-write) or omits it (read-only):
   READ-WRITE: sharedIpnsKeyEncrypted = ECIES(ipnsPrivateKey, recipientPublicKey)
   READ-ONLY:  sharedIpnsKeyEncrypted = null (recipient can resolve IPNS but not publish)
5. Owner's client sends share invitation to server:
   POST /shares/invite {
     recipientPublicKey,
     folderIpnsName,
     sharedFolderKeyEncrypted,    // ECIES-wrapped with recipient's publicKey
     sharedIpnsKeyEncrypted,      // ECIES-wrapped or null (read-only)
     permission: "read" | "write",
     encryptedFolderName          // AES-GCM(folderName, folderKey) so server can't see name
   }
6. Server stores share record (all data is encrypted, server sees nothing meaningful)
7. Recipient logs in, fetches shares: GET /shares/mine
8. Recipient's client unwraps:
   folderKey = ECIES_Decrypt(sharedFolderKeyEncrypted, recipientPrivateKey)
   ipnsPrivateKey = ECIES_Decrypt(sharedIpnsKeyEncrypted, recipientPrivateKey) // if write
9. Recipient resolves folder IPNS name, decrypts metadata with folderKey -- full access
```

Why this preserves zero-knowledge:

- Server only stores ECIES ciphertexts -- it cannot decrypt folderKey or ipnsPrivateKey
- Server cannot read folder names, file names, or file contents
- Server knows only that User A shared something with User B (relationship metadata)

### 1.3 New Components

New database entities:

```sql
-- shares table:
--   id UUID PK
--   owner_id UUID FK -> users(id)
--   recipient_id UUID FK -> users(id)  -- null until accepted
--   recipient_public_key BYTEA NOT NULL
--   folder_ipns_name VARCHAR(255) NOT NULL
--   shared_folder_key_encrypted BYTEA NOT NULL     -- ECIES(folderKey, recipientPubKey)
--   shared_ipns_key_encrypted BYTEA               -- ECIES(ipnsPrivateKey, recipientPubKey), null = read-only
--   permission VARCHAR(10) NOT NULL               -- 'read' | 'write'
--   encrypted_folder_name BYTEA NOT NULL          -- AES-GCM(name, folderKey) -- display only
--   status VARCHAR(20) NOT NULL DEFAULT 'pending' -- 'pending' | 'accepted' | 'revoked'
--   created_at TIMESTAMP DEFAULT NOW()
--   accepted_at TIMESTAMP
--   revoked_at TIMESTAMP
--   UNIQUE(recipient_public_key, folder_ipns_name)
```

New API endpoints:

- `POST /shares/invite` -- Create share invitation
- `GET /shares/mine` -- List shares for current user (incoming)
- `GET /shares/sent` -- List shares created by current user (outgoing)
- `POST /shares/:id/accept` -- Accept share invitation
- `DELETE /shares/:id` -- Revoke share (owner) or decline (recipient)
- `GET /users/lookup` -- Look up user's publicKey by identifier (needed for sharing)

New frontend components:

- ShareDialog -- UI for selecting recipient and permission level
- SharedWithMe view -- List of shared folders (separate from vault root)
- ShareStore (Zustand) -- Track shared folder state
- Shared folder indicators in file browser

New crypto functions:

- `reWrapKeyForRecipient(key, recipientPublicKey)` -- Thin wrapper around existing wrapKey

### 1.4 Data Flow Changes

```text
EXISTING: Folder metadata children contain ECIES-wrapped keys for the OWNER's public key
          folderKeyEncrypted = ECIES(folderKey, ownerPublicKey)

NEW CONSIDERATION: When sharing, the OWNER re-wraps with recipient's key.
                   The RECIPIENT gets a separate wrapped copy.
                   The folder metadata itself (in IPNS) does NOT change.
                   Share key delivery happens via the server, NOT via IPNS metadata.
```

Critical design decision: Share keys are delivered through the backend `shares` table, not embedded in IPNS metadata. This is intentional:

- IPNS metadata is encrypted with the folder key -- you need the folder key to read it
- Share invitations need to be visible to the recipient BEFORE they have the folder key
- The server stores ECIES-wrapped keys that only the recipient can decrypt

### 1.5 Sharing Revocation

Revocation is the hardest part of zero-knowledge sharing. Once a recipient has the folder key, they can cache it forever.

#### Key Rotation on Revocation

```text
REVOKE FLOW:
1. Owner revokes Recipient's share
2. Server marks share as revoked
3. Owner's client generates NEW folderKey for the shared folder
4. Owner's client re-encrypts all children's keys with new folderKey
5. Owner's client re-wraps new folderKey for all REMAINING share recipients
6. Owner re-encrypts and publishes updated folder metadata to IPNS
7. Revoked recipient's cached folderKey no longer decrypts new metadata
```

Limitation (acceptable for tech demo): Old IPFS CIDs (file content) remain decryptable with old file keys since file keys were wrapped with old folderKey. True forward-secrecy for file content would require re-encrypting every file -- impractical for a tech demo. The revocation blocks access to the current folder structure and any new content.

### 1.6 Sharing and TEE Republishing

Shared folders still need IPNS republishing. The flow is unchanged:

- The OWNER's client already sends `encryptedIpnsPrivateKey` to the TEE via the republish schedule
- When a folder is shared, the owner continues to be the IPNS publisher/republisher
- Recipients with write access can ALSO publish (they have the IPNS private key), but TEE republishing remains the owner's responsibility
- No TEE changes needed for read-only sharing

---

## 2. File Versioning: CID-Based Version History

### 2.1 Integration Points with Existing Architecture

Key insight: IPFS content-addressing provides "free" immutable snapshots. Every file update already produces a new CID. Currently, the old CID is unpinned (deleted). For versioning, we simply retain old CIDs with version metadata.

Existing components touched:

- `packages/crypto/src/folder/types.ts` -- FileEntry needs version history array
- `apps/api/src/vault/entities/pinned-cid.entity.ts` -- Pinned CIDs need version metadata
- `apps/web/src/services/folder.service.ts` -- File update flow retains old CIDs instead of unpinning
- `apps/web/src/stores/folder.store.ts` -- Version history display state
- Quota tracking -- old versions count against storage

Existing components NOT touched:

- Encryption (each version is already independently encrypted)
- IPNS publishing (metadata update flow unchanged)
- ECIES wrapping (each version's fileKey is independently wrapped)
- TEE republishing (unaffected)

### 2.2 Recommended Architecture: Metadata-Embedded Version Chain

Approach: Store version history inside folder metadata, not in a separate database.

This preserves zero-knowledge: the server never knows which CIDs are versions of which file. All version metadata is encrypted inside the folder's IPNS record.

Extended FileEntry type:

```typescript
type FileEntry = {
  type: 'file';
  id: string;
  name: string;
  cid: string; // Current version CID
  fileKeyEncrypted: string; // Current version key
  fileIv: string; // Current version IV
  encryptionMode: 'GCM';
  size: number;
  createdAt: number;
  modifiedAt: number;
  // NEW: Version history (most recent first, capped at N entries)
  versions?: FileVersion[];
};

type FileVersion = {
  cid: string; // IPFS CID of this version
  fileKeyEncrypted: string; // ECIES-wrapped key for this version
  fileIv: string; // IV for this version
  size: number;
  modifiedAt: number; // When this version was current
};
```

Confidence: HIGH -- This is the natural pattern for content-addressed storage. IPFS/IPNS documentation explicitly recommends this: "CIDs are like commit hashes in Git, which point to a snapshot of the files in the repository."

### 2.3 Version Flow

```text
FILE UPDATE (with versioning enabled):

BEFORE (current behavior):
  1. Upload new encrypted file -> get newCid
  2. Update FileEntry: cid = newCid, fileKey = newKey
  3. Unpin oldCid (DELETE old version)

AFTER (with versioning):
  1. Upload new encrypted file -> get newCid
  2. Push current entry to versions array:
     versions.unshift({ cid: oldCid, fileKeyEncrypted: oldKey, fileIv: oldIv, size, modifiedAt })
  3. Update FileEntry: cid = newCid, fileKey = newKey
  4. If versions.length > MAX_VERSIONS, unpin and remove oldest version
  5. Publish updated metadata to IPNS

VERSION RESTORE:
  1. User selects a version to restore
  2. Client moves current entry to versions array
  3. Client promotes selected version to current entry
  4. Publish updated metadata to IPNS
  (No re-encryption needed -- each version has its own encrypted CID)

VERSION DELETE:
  1. User deletes a specific old version
  2. Client unpins the version's CID
  3. Client removes version from versions array
  4. Publish updated metadata to IPNS
```

### 2.4 New Components

No new database entities needed. Version metadata lives entirely in encrypted folder metadata (IPNS records). The server already tracks pinned CIDs via `pinned_cids` table -- old versions simply remain pinned.

New API endpoints: None required. Existing `/vault/upload`, `/vault/unpin`, `/ipns/publish` suffice.

New frontend components:

- VersionHistoryPanel -- Shows version list for a file with restore/delete actions
- VersionDiff indicator -- Shows "N versions" badge on files

Modified crypto types:

- FileEntry extended with optional `versions` array
- FolderMetadata version bumped to 'v2' (with backward-compatible parsing)

### 2.5 Storage Implications

Each retained version counts against the user's storage quota. With a default cap of 10 versions per file:

- 10 versions of a 50MB file = 500MB of quota consumed
- User can explicitly delete old versions to reclaim space
- Auto-pruning: when version count exceeds MAX_VERSIONS, oldest is unpinned automatically

### 2.6 Metadata Size Concern

Potential pitfall: Storing version history inline increases metadata size. A folder with 100 files, each with 10 versions = 1000 FileVersion entries in a single JSON blob. Each FileVersion is approximately 200-300 bytes (CID + encrypted key + IV + size + timestamp). That is roughly 200-300KB of metadata -- well within IPNS record limits but worth monitoring.

Mitigation: Cap versions at 10 per file (configurable). For power users with many versions, consider a separate IPNS record for version history (future optimization, not needed for v2.0).

---

## 3. Client-Side Encrypted Search

### 3.1 Integration Points with Existing Architecture

The fundamental challenge: The server cannot search encrypted content. All search must happen client-side. The question is how to make this efficient without downloading and decrypting every file on every search.

Existing components touched:

- `apps/web/src/stores/folder.store.ts` -- In-memory folder tree is the basis for name search
- `packages/crypto/src/folder/types.ts` -- May need search index metadata
- `apps/web/src/services/folder.service.ts` -- Folder traversal for index building

Existing components NOT touched:

- Backend (server sees nothing search-related)
- ECIES/AES encryption primitives
- IPNS publishing (unless we store search index in IPNS)

### 3.2 Recommended Architecture: Two-Tier Client-Side Search

#### Tier 1: In-Memory Name Search (Simple, Build First)

CipherBox already decrypts and caches the entire folder tree in memory (via `useFolderStore`). File names and folder names are plaintext in the in-memory `FolderNode.children` array.

```text
SEARCH FLOW (Tier 1):
1. User types search query
2. Client searches across all loaded FolderNode.children for matching names
3. Results displayed instantly (no network calls, no crypto)

SCOPE: File names, folder names, file sizes, dates
LATENCY: <10ms for vaults with <10,000 entries
LIMITATION: Does not search file contents
```

This is sufficient for MVP. File name search covers the primary use case.

#### Tier 2: Encrypted Search Index for Content (Future, Complex)

For searching file contents, the client builds an encrypted inverted index stored as a separate IPNS record.

```text
INDEX BUILD FLOW (Tier 2 -- future):
1. On file upload, client extracts keywords from filename and (for text files) content
2. Client builds a Bloom filter or inverted index mapping keywords -> file IDs
3. Client encrypts the index with a dedicated searchIndexKey (ECIES-wrapped)
4. Client publishes encrypted index to a dedicated IPNS record
5. On search, client decrypts the index, queries it locally

STORAGE: Separate IPNS record per vault (not per folder)
KEY: searchIndexKey derived from rootFolderKey via HKDF (deterministic)
```

Confidence: MEDIUM -- Encrypted search indexes using Bloom filters are well-studied academically but not widely implemented in consumer products. Proton Drive does not offer content search. Tresorit offers limited filename-only search. This is a differentiator but also a risk area.

### 3.3 New Components (Tier 1 Only)

No new database entities. Tier 1 search is entirely client-side.

No new API endpoints. All data is already in client memory.

New frontend components:

- SearchBar component (global, always visible)
- SearchResults overlay/panel
- SearchService -- traverses folder store for matches

New store:

- searchStore (Zustand) -- tracks query, results, loading state

### 3.4 Architecture Decision: Where to Store Search Index (Tier 2)

If/when Tier 2 is implemented, the search index should be stored as:

| Option                     | Pros                                                             | Cons                                                        | Recommendation              |
| -------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------- |
| Separate IPNS record       | Zero-knowledge, decentralized, consistent with existing patterns | Requires dedicated IPNS keypair, TEE republishing for index | Recommended                 |
| IndexedDB (local only)     | Fast, no network cost                                            | Not synced across devices, lost on clear                    | Good for cache, not primary |
| Server-side encrypted blob | Simpler than IPNS                                                | Breaks the "everything on IPFS" pattern                     | Not recommended             |

Recommended: Separate IPNS record (vault-level, not per-folder). One search index for the entire vault, encrypted with a key derived from rootFolderKey. Synced across devices via IPNS polling.

---

## 4. MFA: Web3Auth Threshold Key Integration

### 4.1 Integration Points with Existing Architecture

Key insight: Web3Auth already uses threshold cryptography (Shamir's Secret Sharing) to split the user's private key into shares. MFA in Web3Auth adds additional share factors, increasing the threshold. CipherBox's existing auth flow does not need structural changes -- MFA is configured at the Web3Auth SDK level.

Existing components touched:

- `apps/web/src/` Web3Auth configuration (modal config, mfaLevel setting)
- `apps/web/src/stores/auth.store.ts` -- May need MFA status tracking
- Backend auth flow -- No changes needed (same JWT/SIWE verification)

Existing components NOT touched:

- Encryption layer (same keypair, just more factors to reconstruct it)
- IPFS/IPNS (unaffected)
- Vault management (same encrypted keys)
- TEE republishing (unaffected)
- Desktop app (Tauri auth flow mirrors web)

### 4.2 Recommended Architecture: Web3Auth Native MFA

Do NOT build custom MFA. Use Web3Auth's built-in MFA system.

Web3Auth's MFA works by splitting the user's private key into three shares using threshold cryptography:

- Share 1 (Social/OAuth): Reconstructed from social login (always present)
- Share 2 (Device): Stored on the current device
- Share 3 (Recovery): User-controlled backup (password, passkey, seed phrase, authenticator)

With MFA enabled, 2-of-3 shares are needed to reconstruct the private key. This means:

- Losing one factor (e.g., device) does not lock the user out
- An attacker who compromises one factor cannot reconstruct the key
- The CipherBox server never sees any shares

Confidence: HIGH -- Web3Auth MFA is a production feature used by multiple wallets. The SDK provides direct configuration.

### 4.3 Configuration

```typescript
// Web3Auth Modal configuration with MFA
const web3auth = new Web3Auth({
  clientId: CIPHERBOX_WEB3AUTH_CLIENT_ID,
  web3AuthNetwork: 'sapphire_mainnet',
  // Enable MFA
  mfaLevel: 'optional', // 'none' | 'default' | 'optional' | 'mandatory'
  mfaSettings: {
    deviceShareFactor: {
      enable: true,
      priority: 1, // Prompted first
      mandatory: false,
    },
    backUpShareFactor: {
      enable: true,
      priority: 2,
      mandatory: false,
    },
    socialBackupFactor: {
      enable: true,
      priority: 3,
      mandatory: false,
    },
    passwordFactor: {
      enable: true,
      priority: 4,
      mandatory: false,
    },
    passkeysFactor: {
      enable: true, // Modern passkey support (FIDO2/WebAuthn)
      priority: 5,
      mandatory: false,
    },
    authenticatorFactor: {
      enable: true, // TOTP authenticator apps
      priority: 6,
      mandatory: false,
    },
  },
});
```

### 4.4 New Components

No new database entities. MFA state lives entirely within Web3Auth's infrastructure.

No new backend endpoints. The backend verifies the same JWT/SIWE signature regardless of how many factors were used to reconstruct the key.

New/modified frontend components:

- MFA setup prompt (Web3Auth provides this UI via modal)
- MFA status indicator in user settings
- Recovery flow documentation/guidance for users

New store state:

- `authStore.mfaEnabled: boolean` -- Track whether user has MFA configured
- `authStore.mfaFactors: string[]` -- Which factors are configured

### 4.5 Pricing Consideration

Web3Auth MFA requires the SCALE plan for production use. It is free in development. This is a cost factor for deployment but does not affect architecture.

### 4.6 Impact on Existing Auth Flow

```text
CURRENT AUTH FLOW:
  Web3Auth login -> single-factor key reconstruction -> keypair -> CipherBox backend auth

WITH MFA:
  Web3Auth login -> MFA prompt (if configured) -> multi-factor key reconstruction -> SAME keypair -> CipherBox backend auth
```

The keypair produced is identical whether or not MFA is enabled. MFA only affects how many factors are needed to reconstruct it. This means:

- Vault keys remain the same
- Existing encrypted data is unchanged
- Users can enable/disable MFA without re-encrypting anything
- The transition from no-MFA to MFA is seamless

---

## 5. Advanced Sync: Conflict Detection and Resolution

### 5.1 Integration Points with Existing Architecture

Current sync model: IPNS polling every 30 seconds. IPNS records have sequence numbers. Highest valid sequence number wins. No application-level conflict resolution (per TECHNICAL_ARCHITECTURE.md Section 5.5).

Existing components touched:

- `apps/web/src/stores/sync.store.ts` -- Needs conflict detection state
- `apps/web/src/stores/folder.store.ts` -- sequenceNumber tracking already exists
- `apps/api/src/ipns/entities/folder-ipns.entity.ts` -- sequence_number already tracked
- IPNS publish flow -- sequence number validation

Existing components NOT touched:

- Encryption primitives
- File upload/download
- TEE republishing

### 5.2 Recommended Architecture: Sequence-Based Optimistic Concurrency

Do NOT implement CRDTs for v2.0. CRDTs add extreme complexity to an encrypted system where the merge function must operate on plaintext (requiring the client to decrypt, merge, re-encrypt). Instead, use a simpler optimistic concurrency control pattern.

Confidence: HIGH -- This is the standard pattern for IPNS-based systems. CRDTs can be considered for v3.0 collaborative editing if needed.

Protocol:

```text
OPTIMISTIC PUBLISH FLOW:

1. Client reads current folder metadata at sequence N
2. Client makes local changes (add file, rename, etc.)
3. Client creates new IPNS record at sequence N+1
4. Client sends POST /ipns/publish with sequenceNumber: N+1
5. Server checks: is N+1 > stored sequenceNumber for this IPNS name?
   YES -> Publish succeeds, update stored sequence
   NO  -> Return 409 CONFLICT with current sequence number

ON CONFLICT (409):
1. Client fetches latest metadata (resolves IPNS to get current CID)
2. Client decrypts latest metadata (sequence M, where M > N)
3. Client applies a three-way merge:
   a. Base state: what client had at sequence N (cached)
   b. Remote state: what server has at sequence M
   c. Local changes: what client wanted to apply
4. Client creates merged record at sequence M+1
5. Client retries publish

MERGE RULES (automatic, no user intervention):
- File added locally + not present remotely -> keep addition
- File added remotely + not present locally -> keep addition
- File deleted locally + not modified remotely -> keep deletion
- File deleted remotely + not modified locally -> keep deletion
- CONFLICT: Same file modified by both -> keep both as "file.txt" and "file (conflict).txt"
- CONFLICT: Same file deleted by one + modified by other -> keep modified version + notify
```

### 5.3 New Components

No new database entities. The existing `folder_ipns.sequence_number` already tracks this.

Modified API behavior:

- `POST /ipns/publish` -- Add sequence number conflict detection (return 409 if stale)
- This is a behavior change, not a new endpoint

New frontend components:

- ConflictResolutionDialog -- Shows when automatic merge cannot resolve
- Conflict indicators in file browser
- Sync retry logic with exponential backoff

New store state:

- `syncStore.conflicts: ConflictEntry[]` -- Track unresolved conflicts
- `syncStore.mergeInProgress: boolean` -- Lock during merge operations

### 5.4 Conflict Detection via IPNS Sequence Numbers

```text
IPNS SEQUENCE TRACKING:

Each folder in the folder store already tracks:
  FolderNode.sequenceNumber: bigint

On poll sync:
1. Resolve IPNS -> get current CID
2. If CID unchanged -> no sync needed
3. If CID changed -> fetch new metadata
4. Compare new metadata.sequenceNumber with local
5. If remote > local AND no local unpublished changes -> fast-forward update
6. If remote > local AND local has unpublished changes -> merge required
```

### 5.5 Merge Strategy for Folder Metadata

The merge operates on decrypted `FolderMetadata.children` arrays. Since items have stable UUIDs (`FolderChild.id`), three-way merge is straightforward:

```typescript
function mergeChildren(
  base: FolderChild[], // Common ancestor (what we last synced)
  local: FolderChild[], // Our local changes
  remote: FolderChild[] // What came from IPNS
): { merged: FolderChild[]; conflicts: ConflictEntry[] } {
  const baseMap = new Map(base.map((c) => [c.id, c]));
  const localMap = new Map(local.map((c) => [c.id, c]));
  const remoteMap = new Map(remote.map((c) => [c.id, c]));

  const merged: FolderChild[] = [];
  const conflicts: ConflictEntry[] = [];

  // All known IDs across all three states
  const allIds = new Set([...baseMap.keys(), ...localMap.keys(), ...remoteMap.keys()]);

  for (const id of allIds) {
    const b = baseMap.get(id);
    const l = localMap.get(id);
    const r = remoteMap.get(id);

    if (l && r && b) {
      // Existed in all three -- check for divergent modifications
      if (l.modifiedAt === b.modifiedAt)
        merged.push(r); // only remote changed
      else if (r.modifiedAt === b.modifiedAt)
        merged.push(l); // only local changed
      else {
        /* both changed -> conflict */
      }
    }
    // ... (addition/deletion cases per merge rules above)
  }

  return { merged, conflicts };
}
```

### 5.6 Base State Caching

For three-way merge, the client needs to remember the "base state" (the last-synced metadata before local changes). This requires caching the pre-edit metadata snapshot.

Storage: In-memory (`folderStore` already caches folder state). On page reload, the base state is lost, so any unpublished local changes are also lost. This is acceptable for a web app (users expect reload to refresh state). The desktop app can persist base state to disk.

---

## 6. Cross-Feature Architectural Concerns

### 6.1 Metadata Schema Evolution

Multiple features modify `FolderMetadata` and its child types. The schema needs versioning:

```typescript
// Current: version 'v1'
type FolderMetadata = {
  version: 'v1';
  children: FolderChild[];
};

// New: version 'v2' (backward compatible)
type FolderMetadataV2 = {
  version: 'v2';
  children: FolderChildV2[]; // Extended child types
  // No breaking changes -- v1 fields still present
};

// Parsing logic:
function parseFolderMetadata(data: unknown): FolderMetadataV2 {
  if (data.version === 'v1') return upgradeV1ToV2(data);
  if (data.version === 'v2') return data;
  throw new Error('Unknown version');
}
```

Migration strategy: Lazy migration. When a v1 folder is opened by v2 client, the client reads v1, interprets it as v2 (with defaults for new fields), and writes back v2 on next edit. No bulk migration needed.

### 6.2 Zero-Knowledge Property Verification

For each feature, verify the zero-knowledge property is preserved:

| Feature       | Server Sees                                | Server Does NOT See                                          |
| ------------- | ------------------------------------------ | ------------------------------------------------------------ |
| Sharing       | Who shared with whom, IPNS name            | Folder key, folder name, file contents                       |
| Search        | Nothing (client-side only for Tier 1)      | Search queries, index, results                               |
| MFA           | Nothing (Web3Auth handles it)              | MFA factors, share reconstruction                            |
| Versioning    | Pinned CIDs (already visible), quota usage | Version relationships, which CIDs are versions of which file |
| Advanced Sync | IPNS sequence numbers (already visible)    | Conflict resolution decisions, merge results                 |

### 6.3 Component Dependency Graph

```text
MFA (independent)
  |
  v (no dependency, but good to stabilize auth first)
Versioning (extends metadata schema)
  |
  v (metadata schema must be stable before sharing adds to it)
Sharing (new key exchange + backend entities + metadata schema)
  |
  v (search should index shared folders too)
Search (reads from complete folder tree)
  |
  v (sync must handle all metadata types including versions and shares)
Advanced Sync (cross-cutting, needs all metadata stable)
```

### 6.4 Folder Metadata Size Budget

With all features, a single folder metadata JSON blob could contain:

| Component                | Per Entry  | At 100 files | At 1000 files |
| ------------------------ | ---------- | ------------ | ------------- |
| FileEntry (v1)           | ~300 bytes | 30 KB        | 300 KB        |
| + versions (10 per file) | ~2 KB      | 200 KB       | 2 MB          |
| FolderEntry (v1)         | ~250 bytes | 25 KB        | 250 KB        |
| JSON overhead            | ~10%       | +25 KB       | +250 KB       |
| Total                    | --         | ~280 KB      | ~2.8 MB       |

2.8 MB for a 1000-file folder with full version history is large but manageable. IPFS handles multi-MB content fine. However, this should be monitored, and version count should be capped (10 versions recommended).

---

## 7. New Entity Relationship Map

```text
EXISTING ENTITIES (unchanged):
  users -1---*- refresh_tokens
  users -1---1- vaults
  users -1---*- folder_ipns
  users -1---*- pinned_cids
  users -1---*- volume_audit
  users -1---*- auth_methods

NEW ENTITIES (Milestone 2):
  users -1---*- shares (as owner)
  users -1---*- shares (as recipient)

NEW RELATIONSHIPS:
  shares.folder_ipns_name references folder_ipns.ipns_name (logical, not FK)
```

Only one new entity (`shares`) is needed. Versioning, search, and sync are handled entirely in client-side encrypted metadata or existing entities.

---

## 8. Suggested Build Order

Based on dependency analysis and risk assessment:

### Phase 1: MFA

Rationale: Smallest surface area. No backend changes. No crypto changes. Pure SDK configuration. Independent of all other features. Stabilizes the auth layer before adding sharing.

Components: Web3Auth mfaLevel/mfaSettings configuration, MFA status UI in settings, documentation for users.

### Phase 2: Versioning

Rationale: Extends the metadata schema (FolderMetadata v2) which other features depend on. Low backend impact (no new entities). Clear implementation path.

Components: Extended FileEntry type with `versions` array, modified file update flow (retain old CIDs), VersionHistoryPanel UI, metadata version migration logic.

### Phase 3: Sharing

Rationale: Most complex feature. Requires new backend entity, new API endpoints, and key exchange protocol. Should come after metadata schema is stable from versioning. Depends on MFA being available (shared vaults should encourage MFA).

Components: shares entity/table, sharing API endpoints, user lookup endpoint, ShareDialog UI, SharedWithMe view, re-wrap crypto helpers, revocation flow.

### Phase 4: Search

Rationale: Benefits from all other features being stable. Tier 1 (name search) is trivial. Needs to search across owned AND shared folders. Metadata schema must be finalized.

Components: SearchBar, SearchResults panel, in-memory search service, searchStore.

### Phase 5: Advanced Sync

Rationale: Cross-cutting concern. Must handle versioned files, shared folder conflicts, and all metadata types. Benefits from everything else being stable. Highest risk of subtle bugs if metadata format is still changing.

Components: Sequence-based conflict detection, three-way merge algorithm, ConflictResolutionDialog, base state caching, retry logic.

---

## Sources

- CipherBox Technical Architecture (finalized v1.11.1) -- `/Users/myankelev/Code/random/cipher-box/00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md`
- CipherBox Data Flows (finalized v1.11.1) -- `/Users/myankelev/Code/random/cipher-box/00-Preliminary-R&D/Documentation/DATA_FLOWS.md`
- CipherBox API Specification (finalized v1.11.1) -- `/Users/myankelev/Code/random/cipher-box/00-Preliminary-R&D/Documentation/API_SPECIFICATION.md`
- CipherBox PRD (finalized v1.11.1) -- `/Users/myankelev/Code/random/cipher-box/00-Preliminary-R&D/Documentation/PRD.md`
- Existing codebase: `packages/crypto/`, `apps/api/`, `apps/web/src/stores/`
- [Tresorit Zero-Knowledge Encryption](https://tresorit.com/features/zero-knowledge-encryption) -- sharing via RSA key wrapping pattern
- [Keeper Encryption Model](https://docs.keeper.io/en/enterprise-guide/keeper-encryption-model) -- record/folder key wrapping architecture
- [Proton Zero-Knowledge Cloud Storage](https://proton.me/blog/zero-knowledge-cloud-storage) -- ECC-based sharing model
- [IPFS Content Addressing](https://docs.ipfs.tech/concepts/content-addressing/) -- CID immutability for versioning
- [Web3Auth MFA Documentation](https://web3auth.io/docs/sdk/web/modal/mfa) -- mfaLevel, mfaSettings, factor types
- [Web3Auth tKey MFA Architecture](https://blog.web3auth.io/tkey-multi-factor-authentication-for-private-keys/) -- threshold share scheme
- [Proxy Re-Encryption (Wikipedia)](https://en.wikipedia.org/wiki/Proxy_re-encryption) -- evaluated and rejected for sharing
- [Bloom Filter Searchable Encryption (ACM)](https://dl.acm.org/doi/10.1145/3029806.3029839) -- Tier 2 search index approach
- [CRDT Technology overview](https://crdt.tech/) -- evaluated and deferred to v3.0
- [IPFS Best Practices](https://docs.ipfs.tech/how-to/best-practices-for-ipfs-builders/) -- versioning patterns
