# Phase 4: File Storage - Research

**Researched:** 2026-01-20
**Domain:** IPFS file upload/download via Pinata, client-side encryption, quota management
**Confidence:** HIGH

## Summary

Phase 4 implements file upload and download with client-side encryption via the existing `@cipherbox/crypto` package, server-side relay to Pinata for IPFS pinning, and storage quota tracking in PostgreSQL.

The existing crypto package provides all necessary primitives: `generateFileKey()`, `generateIv()`, `sealAesGcm()`, `unsealAesGcm()`, and `wrapKey()`/`unwrapKey()` for ECIES operations. The backend needs new VaultModule endpoints that relay encrypted blobs to Pinata's API and track storage usage per user.

The frontend needs an upload service with progress tracking (via axios `onUploadProgress`), retry logic with exponential backoff, and a quota management store.

**Primary recommendation:** Use Pinata's legacy `/pinning/pinFileToIPFS` endpoint for simplicity (100MB files fit standard upload). Sequential uploads with batch progress tracking per user context decisions. Backend tracks quota in `pinned_cids` table with real-time usage calculation.

## Standard Stack

The established libraries/tools for this domain:

### Core

| Library                  | Version | Purpose                          | Why Standard                                     |
| ------------------------ | ------- | -------------------------------- | ------------------------------------------------ |
| @cipherbox/crypto        | 0.2.0   | File encryption/decryption       | Already in monorepo, all primitives ready        |
| axios                    | 1.13.2  | HTTP client with upload progress | Already in frontend, supports `onUploadProgress` |
| @nestjs/platform-express | 11.0.0  | File upload handling             | Already in backend, Multer integration           |
| TypeORM                  | 0.3.28  | Database operations              | Already in backend for quota tracking            |

### Supporting

| Library             | Version  | Purpose                     | When to Use             |
| ------------------- | -------- | --------------------------- | ----------------------- |
| multer (via NestJS) | built-in | multipart/form-data parsing | File upload endpoint    |
| form-data           | ^4.0.0   | FormData for Node.js        | Backend relay to Pinata |

### Alternatives Considered

| Instead of            | Could Use           | Tradeoff                                                           |
| --------------------- | ------------------- | ------------------------------------------------------------------ |
| axios for progress    | fetch API           | Fetch lacks upload progress events                                 |
| Pinata legacy API     | Pinata V3 API       | V3 requires TUS for >100MB, unnecessary complexity for 100MB limit |
| Multer memory storage | Multer disk storage | Memory is fine for 100MB max                                       |

**Installation (backend only - new dependency):**

```bash
cd apps/api && npm install form-data
```

## Architecture Patterns

### Recommended Project Structure

```
apps/api/src/
  vault/
    vault.module.ts          # VaultModule (new module)
    vault.controller.ts      # /vault/upload, /vault/unpin endpoints
    vault.service.ts         # Business logic, quota checks
    entities/
      vault.entity.ts        # Vault table
      pinned-cid.entity.ts   # PinnedCid table for quota tracking
    dto/
      upload.dto.ts          # Upload request validation
      unpin.dto.ts           # Unpin request validation
    services/
      pinata.service.ts      # Pinata API client

apps/web/src/
  services/
    upload.service.ts        # File encryption + upload orchestration
    download.service.ts      # File download + decryption orchestration
  stores/
    quota.store.ts           # Storage quota state (Zustand)
  hooks/
    useFileUpload.ts         # Upload hook with progress tracking
    useFileDownload.ts       # Download hook
```

### Pattern 1: Encrypt-Then-Upload Flow

**What:** Client encrypts file before sending to backend
**When to use:** All file uploads
**Example:**

```typescript
// Source: TECHNICAL_ARCHITECTURE.md Section 3.2
async function uploadFile(
  file: File,
  userPublicKey: Uint8Array
): Promise<{ cid: string; size: number }> {
  // 1. Generate unique file key and IV
  const fileKey = generateFileKey();
  const iv = generateIv();

  // 2. Read file as ArrayBuffer
  const plaintext = new Uint8Array(await file.arrayBuffer());

  // 3. Encrypt with AES-256-GCM
  const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);

  // 4. Wrap file key with user's public key
  const wrappedKey = await wrapKey(fileKey, userPublicKey);

  // 5. Clear plaintext key from memory
  clearBytes(fileKey);

  // 6. Upload encrypted blob to backend
  const formData = new FormData();
  formData.append('encryptedFile', new Blob([ciphertext]));
  formData.append('iv', bytesToHex(iv));

  const response = await apiClient.post('/vault/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (event) => {
      // Update progress state
    },
  });

  return {
    cid: response.data.cid,
    wrappedKey,
    iv,
    size: ciphertext.length,
  };
}
```

### Pattern 2: Backend Relay to Pinata

**What:** Backend receives encrypted blob, forwards to Pinata
**When to use:** All uploads via /vault/upload
**Example:**

```typescript
// Source: Pinata API documentation
import FormData from 'form-data';
import { Readable } from 'stream';

async uploadToPinata(
  encryptedFile: Buffer,
  userId: string
): Promise<{ cid: string; size: number }> {
  const formData = new FormData();
  formData.append('file', Readable.from(encryptedFile), {
    filename: `encrypted-${Date.now()}`,
    contentType: 'application/octet-stream'
  });
  formData.append('pinataMetadata', JSON.stringify({
    name: `cipherbox-${userId}-${Date.now()}`,
    keyvalues: { userId }
  }));

  const response = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${this.pinataJwt}`,
      ...formData.getHeaders()
    },
    body: formData
  });

  const result = await response.json();
  return {
    cid: result.IpfsHash,
    size: result.PinSize
  };
}
```

### Pattern 3: Quota Tracking

**What:** Track storage usage per user in PostgreSQL
**When to use:** On every pin/unpin operation
**Example:**

```typescript
// Check quota before upload
async checkQuota(userId: string, fileSize: number): Promise<boolean> {
  const user = await this.userRepository.findOne({
    where: { id: userId },
    select: ['id']
  });

  const currentUsage = await this.pinnedCidRepository
    .createQueryBuilder('pin')
    .select('COALESCE(SUM(pin.sizeBytes), 0)', 'total')
    .where('pin.userId = :userId', { userId })
    .getRawOne();

  const QUOTA_LIMIT = 500 * 1024 * 1024; // 500 MiB
  return (parseInt(currentUsage.total) + fileSize) <= QUOTA_LIMIT;
}
```

### Anti-Patterns to Avoid

- **Sending plaintext files to backend:** Always encrypt client-side first
- **Storing file keys on server:** File keys are ECIES-wrapped, stored in folder metadata only
- **Using fetch for upload progress:** Fetch API lacks upload progress events; use axios
- **Parallel uploads in v1:** Per user decision, sequential uploads only for v1
- **Disk storage for uploads:** Use memory storage (Multer) for 100MB limit

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem           | Don't Build        | Use Instead                                  | Why                                             |
| ----------------- | ------------------ | -------------------------------------------- | ----------------------------------------------- |
| File encryption   | Custom crypto      | `@cipherbox/crypto` sealAesGcm/encryptAesGcm | Already implemented, tested, audited primitives |
| Key wrapping      | Custom ECIES       | `@cipherbox/crypto` wrapKey/unwrapKey        | eciesjs handles ephemeral keys, ECDH, HKDF      |
| Upload progress   | Custom XHR wrapper | axios `onUploadProgress`                     | Well-tested, handles edge cases                 |
| Multipart parsing | Manual parsing     | NestJS FileInterceptor                       | Production-ready, battle-tested                 |
| Retry logic       | setTimeout chains  | Structured retry with backoff                | Clean abstraction, testable                     |

**Key insight:** The crypto package already has all primitives. This phase is about wiring - no new crypto code needed.

## Common Pitfalls

### Pitfall 1: Memory Exhaustion on Large Files

**What goes wrong:** Loading 100MB file into memory twice (plaintext + ciphertext)
**Why it happens:** File.arrayBuffer() + encrypt creates two copies
**How to avoid:** Process sequentially, clear references promptly, rely on GC
**Warning signs:** Browser tab crashes on upload, memory grows unbounded

### Pitfall 2: Progress Bar Not Updating

**What goes wrong:** Progress bar jumps from 0 to 100%
**Why it happens:** axios `onUploadProgress` requires specific config
**How to avoid:**

```typescript
// Correct
const config = {
  onUploadProgress: (event: AxiosProgressEvent) => {
    const percent = Math.round((event.loaded * 100) / (event.total ?? 1));
    setProgress(percent);
  },
};
```

**Warning signs:** Progress bar doesn't move during upload

### Pitfall 3: Quota Race Condition

**What goes wrong:** Two uploads exceed quota simultaneously
**Why it happens:** Check-then-upload without locking
**How to avoid:** Use database transaction with FOR UPDATE or optimistic versioning
**Warning signs:** User exceeds 500 MiB quota

### Pitfall 4: CORS Preflight Failure for multipart/form-data

**What goes wrong:** Upload fails with CORS error
**Why it happens:** Custom headers trigger preflight
**How to avoid:** Ensure backend CORS allows multipart requests with credentials
**Warning signs:** OPTIONS request fails, upload never starts

### Pitfall 5: Retry Without Idempotency

**What goes wrong:** Failed retry creates duplicate pins
**Why it happens:** Backend pins before responding, response fails
**How to avoid:** Use metadata to detect duplicates, unpin on failure before retry
**Warning signs:** User sees duplicate CIDs

### Pitfall 6: File Key Memory Leak

**What goes wrong:** File keys remain in memory after upload
**Why it happens:** No explicit clearing after crypto operations
**How to avoid:** Call `clearBytes(fileKey)` after wrapping completes
**Warning signs:** Memory grows with each upload

## Code Examples

Verified patterns from official sources and existing codebase:

### File Encryption (using existing crypto package)

```typescript
// Source: @cipherbox/crypto package (already implemented)
import {
  generateFileKey,
  generateIv,
  encryptAesGcm,
  wrapKey,
  clearBytes,
  bytesToHex,
} from '@cipherbox/crypto';

async function encryptFile(
  plaintext: Uint8Array,
  userPublicKey: Uint8Array
): Promise<{
  ciphertext: Uint8Array;
  iv: Uint8Array;
  wrappedKey: Uint8Array;
}> {
  const fileKey = generateFileKey();
  const iv = generateIv();

  const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);
  const wrappedKey = await wrapKey(fileKey, userPublicKey);

  // Clear sensitive key from memory
  clearBytes(fileKey);

  return { ciphertext, iv, wrappedKey };
}
```

### File Decryption (using existing crypto package)

```typescript
// Source: @cipherbox/crypto package
import { decryptAesGcm, unwrapKey, clearBytes } from '@cipherbox/crypto';

async function decryptFile(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  wrappedKey: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  const fileKey = await unwrapKey(wrappedKey, privateKey);

  try {
    const plaintext = await decryptAesGcm(ciphertext, fileKey, iv);
    return plaintext;
  } finally {
    clearBytes(fileKey);
  }
}
```

### Axios Upload with Progress

```typescript
// Source: axios documentation + React patterns
import axios, { AxiosProgressEvent } from 'axios';

async function uploadWithProgress(
  formData: FormData,
  onProgress: (percent: number) => void
): Promise<{ cid: string; size: number }> {
  const response = await apiClient.post('/vault/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (event: AxiosProgressEvent) => {
      if (event.total) {
        const percent = Math.round((event.loaded * 100) / event.total);
        onProgress(percent);
      }
    },
  });

  return response.data;
}
```

### NestJS File Upload Endpoint

```typescript
// Source: NestJS file upload documentation
import { Controller, Post, UseInterceptors, UploadedFile, Body, UseGuards } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Express } from 'express';

@Controller('vault')
export class VaultController {
  @Post('upload')
  @UseGuards(JwtAuthGuard)
  @UseInterceptors(
    FileInterceptor('encryptedFile', {
      limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
    })
  )
  async upload(
    @UploadedFile() file: Express.Multer.File,
    @Body('iv') iv: string,
    @Req() req: RequestWithUser
  ) {
    return this.vaultService.uploadFile(file.buffer, iv, req.user.id);
  }
}
```

### Pinata API Call

```typescript
// Source: Pinata API documentation
import FormData from 'form-data';
import { Readable } from 'stream';

async function pinToPinata(
  data: Buffer,
  jwt: string,
  metadata?: Record<string, string>
): Promise<{ IpfsHash: string; PinSize: number }> {
  const form = new FormData();
  form.append('file', Readable.from(data), {
    filename: 'encrypted-file',
    contentType: 'application/octet-stream',
  });

  if (metadata) {
    form.append(
      'pinataMetadata',
      JSON.stringify({
        keyvalues: metadata,
      })
    );
  }

  const response = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      ...form.getHeaders(),
    },
    body: form,
  });

  if (!response.ok) {
    throw new Error(`Pinata upload failed: ${response.status}`);
  }

  return response.json();
}
```

### Retry Logic with Exponential Backoff

```typescript
// Source: Common retry pattern per user context
async function withRetry<T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  baseDelay: number = 1000
): Promise<T> {
  let lastError: Error;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (attempt < maxRetries - 1) {
        const delay = baseDelay * Math.pow(2, attempt);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  throw lastError!;
}
```

### Browser Download Trigger

```typescript
// Source: Web API standard
function triggerBrowserDownload(data: Uint8Array, filename: string): void {
  const blob = new Blob([data], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  URL.revokeObjectURL(url);
}
```

## State of the Art

| Old Approach        | Current Approach       | When Changed | Impact                                     |
| ------------------- | ---------------------- | ------------ | ------------------------------------------ |
| Pinata SDK          | Direct API calls       | 2025         | SDK adds overhead, direct fetch is simpler |
| XHR for upload      | axios onUploadProgress | Ongoing      | Cleaner API, built-in retry support        |
| TUS for all uploads | Standard upload <100MB | V3 API       | TUS only needed for >100MB files           |

**Deprecated/outdated:**

- Pinata `/pinning/pinByHash` deprecated for `/pinning/pinFileToIPFS`
- `pinataOptions.cidVersion: 0` - always use cidVersion: 1 for modern CIDs

## Database Schema

### PinnedCids Table (new)

```sql
CREATE TABLE pinned_cids (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cid VARCHAR(255) NOT NULL,
  size_bytes BIGINT NOT NULL,
  pinned_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, cid)
);

CREATE INDEX idx_pinned_cids_user_id ON pinned_cids(user_id);
```

### Vaults Table (extends existing schema from API_SPECIFICATION.md)

```sql
CREATE TABLE vaults (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  owner_public_key BYTEA NOT NULL,
  encrypted_root_folder_key BYTEA NOT NULL,
  encrypted_root_ipns_private_key BYTEA NOT NULL,
  root_ipns_name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  initialized_at TIMESTAMP,
  updated_at TIMESTAMP DEFAULT NOW()
);
```

### Volume Audit Table (for tracking)

```sql
CREATE TABLE volume_audit (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  cid VARCHAR(255) NOT NULL,
  size_bytes BIGINT NOT NULL,
  action VARCHAR(20) NOT NULL, -- 'pin' or 'unpin'
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_volume_audit_user_id ON volume_audit(user_id);
```

## Open Questions

Things that couldn't be fully resolved:

1. **Pinata error codes for quota exceeded**
   - What we know: Pinata returns errors for failed pins
   - What's unclear: Specific error codes for account quota vs our 500MB limit
   - Recommendation: Enforce our quota before calling Pinata, return 507 for our limit

2. **Exact file metadata encryption location**
   - What we know: File metadata (name, key, iv) stored in folder IPNS record
   - What's unclear: Whether this phase handles metadata updates or only upload/download
   - Recommendation: Phase 4 handles CID storage locally; folder metadata updates are Phase 5

3. **Cancel upload mid-flight behavior**
   - What we know: User can cancel during upload per context
   - What's unclear: Whether Pinata supports abort, what happens to partial data
   - Recommendation: Cancel axios request, assume Pinata cleans up incomplete uploads

## Sources

### Primary (HIGH confidence)

- @cipherbox/crypto package source code - All crypto primitives verified
- API_SPECIFICATION.md - Endpoint contracts and database schema
- DATA_FLOWS.md - File upload/download sequence diagrams
- TECHNICAL_ARCHITECTURE.md - Encryption architecture

### Secondary (MEDIUM confidence)

- [Pinata API Documentation](https://docs.pinata.cloud/api-reference/endpoint/ipfs/pin-file-to-ipfs) - Upload endpoint
- [Pinata Rate Limits](https://docs.pinata.cloud/account-management/limits) - 60-500 req/min by plan
- [axios onUploadProgress](https://axios-http.com/docs/api_intro) - Progress tracking

### Tertiary (LOW confidence)

- Pinata SDK v3 examples - Not using SDK, but informed API patterns
- NestJS file upload docs - Some content didn't render, verified with existing codebase

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH - All libraries already in monorepo or documented
- Architecture: HIGH - Patterns follow existing DATA_FLOWS.md diagrams
- Pitfalls: MEDIUM - Based on general patterns, some Pinata specifics unverified

**Research date:** 2026-01-20
**Valid until:** 2026-02-20 (30 days - stable domain)

---

_Phase: 04-file-storage_
_Research: 2026-01-20_
