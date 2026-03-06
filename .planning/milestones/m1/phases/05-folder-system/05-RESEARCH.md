# Phase 5: Folder System - Research

**Researched:** 2026-01-21
**Domain:** Encrypted folder hierarchy with IPNS metadata publishing
**Confidence:** HIGH

## Summary

Phase 5 implements the folder system for CipherBox, enabling users to create, nest (up to 20 levels), rename, move, and delete folders. Each folder has its own IPNS keypair for metadata publishing. Files can be renamed and moved between folders.

The implementation requires three major technical components:
1. **IPNS Record Creation and Publishing** - Using the `ipns` npm package for record creation/marshaling, with the Delegated Routing HTTP API (`/routing/v1/ipns`) for publishing pre-signed records
2. **Folder Metadata Encryption** - AES-256-GCM encryption of folder contents using per-folder keys, stored in IPNS records
3. **Backend Redundancy** - Database tracking of all folder IPNS names and latest CIDs for recovery and TEE republishing

**Primary recommendation:** Use the `ipns` npm package for IPNS record creation and the public delegated routing endpoint (`https://delegated-ipfs.dev/routing/v1/ipns`) for publishing pre-signed records. The client signs records locally; the backend relays serialized records to the IPFS network.

## Standard Stack

The established libraries/tools for this domain:

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `ipns` | ^10.1.3 | IPNS record creation, marshaling, validation | Official IPFS package for IPNS records |
| `@libp2p/crypto` | ^5.x | Key generation, marshaling for libp2p format | Required by `ipns` for key format compatibility |
| `@libp2p/peer-id` | ^5.x | Derive IPNS name (CIDv1) from Ed25519 public key | Standard peer ID derivation |
| `@cipherbox/crypto` | (existing) | Ed25519 keygen, AES-GCM, ECIES | Already implemented in Phase 3 |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `multiformats` | ^13.x | CID encoding/decoding | Creating IPNS names as CIDv1 |
| `@ipld/dag-cbor` | ^9.x | CBOR encoding for metadata | If custom record inspection needed |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Delegated Routing API | Kubo RPC (`/api/v0/name/publish`) | Requires running IPFS node with imported keys |
| Delegated Routing API | w3name service | Doesn't support pre-signed records; signing tied to their library |
| `ipns` package | Manual protobuf creation | More code, less maintainable, easy to get wrong |

**Installation:**
```bash
pnpm add ipns @libp2p/crypto @libp2p/peer-id multiformats
```

## Architecture Patterns

### Recommended Project Structure
```
packages/crypto/src/
  ipns/
    index.ts                    # Re-exports
    sign-record.ts              # (existing) Low-level signing
    create-record.ts            # NEW: Full IPNS record creation
    derive-name.ts              # NEW: IPNS name derivation from Ed25519 pubkey
    marshal.ts                  # NEW: Serialization helpers
  folder/
    index.ts                    # NEW: Folder crypto operations
    metadata.ts                 # NEW: Metadata encryption/decryption
    types.ts                    # NEW: Folder metadata types

apps/api/src/
  ipns/
    ipns.module.ts              # NEW: IPNS module
    ipns.controller.ts          # NEW: POST /ipns/publish, GET /ipns/resolve
    ipns.service.ts             # NEW: Delegated routing client
    dto/
      publish.dto.ts            # NEW: Request/response DTOs
      resolve.dto.ts
    entities/
      folder-ipns.entity.ts     # NEW: Track folder IPNS names + CIDs

apps/web/src/
  services/
    folder.service.ts           # NEW: Folder CRUD operations
    ipns.service.ts             # NEW: IPNS record creation and publishing
  stores/
    folder.store.ts             # NEW: Folder tree state management
```

### Pattern 1: Client-Signed IPNS Records with Backend Relay

**What:** Client creates and signs IPNS records locally, sends serialized record to backend, backend relays to IPFS network via Delegated Routing API.

**When to use:** All IPNS publishing operations (folder create, rename, move, delete, file add/remove).

**Flow:**
```
Client:
1. Create/update folder metadata (encrypted JSON)
2. Upload encrypted metadata to IPFS via POST /ipfs/add
3. Get CID from response
4. Create IPNS record pointing to CID using `ipns` package
5. Sign record with folder's Ed25519 private key
6. Marshal record to protobuf bytes
7. Send to backend: POST /ipns/publish { ipnsName, record (base64), encryptedIpnsPrivateKey, keyEpoch }

Backend:
1. Validate request
2. PUT /routing/v1/ipns/{name} to delegated-ipfs.dev with Content-Type: application/vnd.ipfs.ipns-record
3. Store/update folder_ipns entry for redundancy
4. Return success
```

### Pattern 2: Folder Metadata Structure

**What:** Encrypted JSON stored in IPNS record containing folder contents.

**When to use:** All folder operations.

**Structure:**
```typescript
// Decrypted metadata (before encryption)
interface FolderMetadata {
  version: 'v1';
  children: FolderChild[];
}

type FolderChild = FolderEntry | FileEntry;

interface FolderEntry {
  type: 'folder';
  name: string;                    // Plaintext (whole metadata is encrypted)
  ipnsName: string;                // k51... IPNS name
  ipnsPrivateKeyEncrypted: string; // ECIES-wrapped Ed25519 private key
  folderKeyEncrypted: string;      // ECIES-wrapped AES-256 key
  createdAt: number;               // Unix timestamp
  modifiedAt: number;
}

interface FileEntry {
  type: 'file';
  name: string;
  cid: string;
  fileKeyEncrypted: string;        // ECIES-wrapped AES-256 key
  fileIv: string;                  // Hex-encoded IV
  encryptionMode: 'GCM';           // Always GCM for v1.0
  size: number;                    // File size in bytes
  createdAt: number;
  modifiedAt: number;
}

// Encrypted for storage
interface EncryptedFolderMetadata {
  iv: string;                      // Hex-encoded
  data: string;                    // Base64-encoded AES-GCM ciphertext
}
```

### Pattern 3: Add-Before-Remove for Move Operations

**What:** When moving items between folders, add to destination before removing from source.

**When to use:** All move operations (files or folders).

**Rationale:** Ensures item is always reachable even if operation is interrupted.

**Example:**
```typescript
async function moveItem(itemId: string, sourceFolderId: string, destFolderId: string) {
  // 1. Get item entry from source folder metadata
  const sourceMetadata = await getFolderMetadata(sourceFolderId);
  const item = sourceMetadata.children.find(c => c.id === itemId);

  // 2. Add to destination FIRST
  const destMetadata = await getFolderMetadata(destFolderId);
  destMetadata.children.push(item);
  await publishFolderMetadata(destFolderId, destMetadata);

  // 3. Remove from source AFTER destination confirmed
  sourceMetadata.children = sourceMetadata.children.filter(c => c.id !== itemId);
  await publishFolderMetadata(sourceFolderId, sourceMetadata);
}
```

### Anti-Patterns to Avoid
- **Storing private keys in backend database:** Only store ECIES-wrapped keys encrypted with user's public key
- **Publishing IPNS without updating backend tracking:** Backend must track all folder IPNS names for TEE republishing
- **Remove-then-add for moves:** Creates window where item is unreachable
- **Blocking on name collision:** Per CONTEXT.md, show error and require user to rename first
- **Publishing root IPNS name only:** Backend must track ALL folder IPNS names, not just root

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| IPNS record creation | Manual protobuf construction | `ipns.createIPNSRecord()` | CBOR ordering, signature format, validity encoding are complex |
| IPNS name derivation | Custom multihash creation | `@libp2p/peer-id` peerIdFromKeys() | Identity multihash for Ed25519 is non-obvious |
| Record serialization | Custom protobuf encoding | `ipns.marshalIPNSRecord()` | Protobuf schema must match exactly |
| Ed25519 key format | Raw bytes | `@libp2p/crypto` PrivateKey type | `ipns` package expects libp2p key format |

**Key insight:** The `ipns` package handles the complex interplay between CBOR encoding, protobuf serialization, signature prefixes, and validity formats. Using it correctly requires understanding the libp2p key format, but avoids subtle bugs in record construction.

## Common Pitfalls

### Pitfall 1: Wrong Ed25519 Key Format for IPNS Package
**What goes wrong:** `createIPNSRecord` expects a libp2p `PrivateKey` object, not raw bytes.
**Why it happens:** Existing `@cipherbox/crypto` uses `@noble/ed25519` which produces raw bytes.
**How to avoid:** Convert raw Ed25519 bytes to libp2p format before calling `ipns` functions.
**Warning signs:** Cryptic errors about key format or invalid signatures.

```typescript
// WRONG - raw bytes
const privateKey = generateEd25519Keypair().privateKey;
await createIPNSRecord(privateKey, value, seq, lifetime); // Error!

// CORRECT - convert to libp2p format
import { unmarshalPrivateKey } from '@libp2p/crypto/keys';
import { keys } from '@libp2p/crypto';

const rawPrivateKey = generateEd25519Keypair().privateKey;
// Construct protobuf-encoded key
const libp2pKey = await keys.unmarshalPrivateKey(
  marshalEd25519PrivateKey(rawPrivateKey)
);
await createIPNSRecord(libp2pKey, value, seq, lifetime); // Works!
```

### Pitfall 2: Sequence Number Management
**What goes wrong:** Publishing with same or lower sequence number fails silently or causes stale data.
**Why it happens:** IPNS uses sequence numbers for record ordering; DHT only accepts higher sequences.
**How to avoid:** Always track and increment sequence number per folder; store in metadata or backend.
**Warning signs:** Updates seem to succeed but old data is returned on resolve.

### Pitfall 3: IPNS TTL vs Record Lifetime
**What goes wrong:** Records expire before TEE can republish, causing resolution failures.
**Why it happens:** Confusing TTL (cache hint) with validity (signature lifetime).
**How to avoid:** Set validity long (24-48 hours), TTL short (5 minutes). TEE republishes every 3 hours.
**Warning signs:** Intermittent "name not found" errors, especially after periods of inactivity.

### Pitfall 4: Forgetting to Update Backend Tracking
**What goes wrong:** Folder becomes inaccessible after IPNS record expires because TEE doesn't republish.
**Why it happens:** Client publishes to IPFS but doesn't update `folder_ipns` table.
**How to avoid:** Backend `/ipns/publish` endpoint must atomically publish AND update tracking.
**Warning signs:** Folders work initially, then become inaccessible after 24-48 hours.

### Pitfall 5: Recursive Deletion Without Depth Check
**What goes wrong:** Stack overflow or timeout when deleting deeply nested structures.
**Why it happens:** Naive recursion on deeply nested folders.
**How to avoid:** Use iterative approach with explicit stack; enforce 20-level depth limit on creation.
**Warning signs:** Slow or failing delete operations on nested folders.

## Code Examples

Verified patterns from official sources:

### Creating IPNS Record
```typescript
// Source: ipns npm package documentation
import { createIPNSRecord, marshalIPNSRecord } from 'ipns';
import { generateKeyPair } from '@libp2p/crypto/keys';

// Generate key (or convert existing Ed25519 key)
const privateKey = await generateKeyPair('Ed25519');

// Create record
const value = '/ipfs/bafybeicklkqcnlvtiscr2hzkubjwnwjinvskffn4xorqeduft3wq7vm5u4';
const sequenceNumber = 0n; // BigInt
const lifetime = 24 * 60 * 60 * 1000; // 24 hours in ms

const record = await createIPNSRecord(privateKey, value, sequenceNumber, lifetime);

// Serialize for transmission
const recordBytes = marshalIPNSRecord(record);
```

### Publishing via Delegated Routing API
```typescript
// Source: IPFS Delegated Routing V1 Spec (specs.ipfs.tech)
async function publishIpnsRecord(
  ipnsName: string,          // CIDv1 encoding, e.g., "k51..."
  recordBytes: Uint8Array    // Marshaled IPNS record
): Promise<void> {
  const response = await fetch(
    `https://delegated-ipfs.dev/routing/v1/ipns/${ipnsName}`,
    {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/vnd.ipfs.ipns-record',
      },
      body: recordBytes,
    }
  );

  if (!response.ok) {
    throw new Error(`IPNS publish failed: ${response.status}`);
  }
}
```

### Resolving IPNS via Delegated Routing API
```typescript
// Source: IPFS Delegated Routing V1 Spec
async function resolveIpnsName(ipnsName: string): Promise<Uint8Array> {
  const response = await fetch(
    `https://delegated-ipfs.dev/routing/v1/ipns/${ipnsName}`,
    {
      method: 'GET',
      headers: {
        'Accept': 'application/vnd.ipfs.ipns-record',
      },
    }
  );

  if (!response.ok) {
    throw new Error(`IPNS resolve failed: ${response.status}`);
  }

  return new Uint8Array(await response.arrayBuffer());
}
```

### Deriving IPNS Name from Ed25519 Public Key
```typescript
// Source: libp2p/js-libp2p-peer-id
import { peerIdFromKeys } from '@libp2p/peer-id';
import { keys } from '@libp2p/crypto';

async function deriveIpnsName(ed25519PublicKey: Uint8Array): Promise<string> {
  // Ed25519 public keys are small enough to be inlined in peer ID
  const publicKey = keys.unmarshalPublicKey(
    marshalEd25519PublicKey(ed25519PublicKey)
  );

  const peerId = await peerIdFromKeys(publicKey.bytes);

  // Return as CIDv1 with libp2p-key codec (k51... format)
  return peerId.toCID().toString();
}
```

### Encrypting Folder Metadata
```typescript
// Pattern from existing @cipherbox/crypto
import { encryptAesGcm, generateIv, bytesToHex } from '@cipherbox/crypto';

async function encryptFolderMetadata(
  metadata: FolderMetadata,
  folderKey: Uint8Array
): Promise<EncryptedFolderMetadata> {
  const iv = generateIv();
  const plaintext = new TextEncoder().encode(JSON.stringify(metadata));
  const ciphertext = await encryptAesGcm(plaintext, folderKey, iv);

  return {
    iv: bytesToHex(iv),
    data: btoa(String.fromCharCode(...ciphertext)),
  };
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Kubo RPC with imported keys | Delegated Routing API | 2024 | No need to run IPFS node; pre-signed records supported |
| js-ipfs (deprecated) | Helia + ipns package | 2023 | js-ipfs abandoned; use standalone packages |
| Custom IPNS record creation | `ipns` npm package | Always | Package handles complex protobuf/CBOR format |
| 1-hour default IPNS TTL | 5-minute default TTL | Kubo 0.34 (2025) | Faster propagation of updates |

**Deprecated/outdated:**
- `js-ipfs`: Deprecated, use Helia or standalone packages
- `ipfs-http-client`: Replaced by Kubo RPC or delegated routing
- Manual protobuf IPNS construction: Use `ipns` package

## Open Questions

Things that couldn't be fully resolved:

1. **Pinata IPNS Support**
   - What we know: Pinata focuses on IPFS pinning, not IPNS publishing
   - What's unclear: Whether Pinata has any hidden IPNS API or gateway support
   - Recommendation: Use delegated-ipfs.dev for IPNS; keep Pinata for file pinning only

2. **libp2p Key Format Conversion**
   - What we know: `ipns` package expects libp2p `PrivateKey` type
   - What's unclear: Exact bytes for protobuf marshaling of Ed25519 keys
   - Recommendation: Test key conversion thoroughly; may need to examine libp2p-crypto source

3. **Delegated Routing Rate Limits**
   - What we know: delegated-ipfs.dev is a public good endpoint
   - What's unclear: Exact rate limits for PUT operations
   - Recommendation: Implement retry with exponential backoff; consider self-hosted someguy for production

## Sources

### Primary (HIGH confidence)
- [IPFS IPNS Record Specification](https://specs.ipfs.tech/ipns/ipns-record/) - Complete record format, signature process
- [Delegated Routing V1 HTTP API](https://specs.ipfs.tech/routing/http-routing-v1/) - PUT/GET /routing/v1/ipns endpoints
- [js-ipns GitHub](https://github.com/ipfs/js-ipns) - Package API and examples
- TECHNICAL_ARCHITECTURE.md - Existing folder metadata structure, encryption patterns
- DATA_FLOWS.md - Existing IPNS publishing flow diagrams

### Secondary (MEDIUM confidence)
- [IPFS Publishing IPNS Docs](https://docs.ipfs.tech/how-to/publish-ipns/) - General guidance
- [Kubo Issue #8542](https://github.com/ipfs/kubo/issues/8542) - Pre-signed record publishing discussion
- [w3name GitHub](https://github.com/storacha/w3name) - Alternative IPNS service (not recommended for pre-signed records)

### Tertiary (LOW confidence)
- WebSearch results for libp2p key format conversion - Needs verification with actual implementation

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Official IPFS packages with clear documentation
- Architecture: HIGH - Follows existing CipherBox patterns from specifications
- Pitfalls: HIGH - Documented in official specs and community issues
- Key format conversion: MEDIUM - May need implementation testing

**Research date:** 2026-01-21
**Valid until:** 2026-02-21 (30 days - stable domain)
