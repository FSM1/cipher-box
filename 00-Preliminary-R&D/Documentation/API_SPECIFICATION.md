---
version: 1.11.1
last_updated: 2026-01-20
status: Finalized
ai_context: API specification for CipherBox backend. Contains all endpoints, request/response formats, database schema, and rate limits. For system design see TECHNICAL_ARCHITECTURE.md.
---

# CipherBox - API Specification

**Document Type:** API Specification
**Status:** Active
**Last Updated:** January 20, 2026
**Base URL:** `https://api.cipherbox.io`

---

## Table of Contents

1. [Overview](#1-overview)
2. [Authentication](#2-authentication)
3. [Endpoints](#3-endpoints)
4. [Database Schema](#4-database-schema)
5. [Rate Limiting](#5-rate-limiting)
6. [Error Handling](#6-error-handling)

---

## Terminology

| Term | Code/API | Notes |
|------|----------|-------|
| Root folder encryption key | `rootFolderKey` | AES-256 symmetric key |
| User's ECDSA public key | `publicKey` | secp256k1 curve |
| IPNS identifier | `ipnsName` | e.g., k51qzi5uqu5dlvj55... |
| Folder encryption key | `folderKey` | Per-folder AES-256 key |
| File encryption key | `fileKey` | Per-file AES-256 key |
| IPNS signing key | `ipnsPrivateKey` | Ed25519, stored encrypted |
| TEE key rotation epoch | `keyEpoch` | Integer epoch for TEE key rotation |
| TEE-encrypted IPNS key | `encryptedIpnsPrivateKey` | IPNS private key encrypted with TEE public key |

**Naming Conventions:**
- API fields: `camelCase`
- Database columns: `snake_case`

---

## 1. Overview

### 1.1 Architecture

The CipherBox backend provides:
- User authentication (via Web3Auth JWT or SIWE signature)
- Token management (access + refresh tokens)
- Vault management (encrypted key storage)
- File upload to IPFS (via Pinata)
- Storage quota tracking
- IPFS/IPNS relay for encrypted metadata and signed IPNS records

The backend **never** handles:
- Plaintext files
- Unencrypted keys
- Client private keys or unsigned IPNS records

### 1.2 Authentication Flow

All protected endpoints require `Authorization: Bearer <accessToken>` header.

```
1. Client obtains keypair from Web3Auth
2. Client authenticates: POST /auth/login
3. Backend returns accessToken (15min) + refreshToken (7d)
4. Client uses accessToken for all API calls
5. On expiry: POST /auth/refresh to get new tokens
```

---

## 2. Authentication

### 2.1 Token Types

| Token | Issuer | Expiry | Storage | Purpose |
|-------|--------|--------|---------|---------|
| Access Token | CipherBox Backend | 15 minutes | Client memory only | API authorization |
| Refresh Token | CipherBox Backend | 7 days | HTTP-only cookie or encrypted storage | Obtain new access tokens |

### 2.2 Access Token Claims

```json
{
  "sub": "user-uuid",
  "publicKey": "0x04abc123...",
  "iat": 1705298400,
  "exp": 1705299300
}
```

### 2.3 Refresh Token Rotation

On each `/auth/refresh` call:
1. Old refresh token is invalidated
2. New refresh token is issued
3. New access token is issued

This limits exposure if a refresh token is compromised.

---

## 3. Endpoints

### 3.1 Authentication Endpoints

#### GET /auth/nonce

Get a nonce for SIWE-style signature authentication.

**Response (200):**
```json
{
  "nonce": "abc123xyz789",
  "expiresAt": "2026-01-16T05:00:00Z"
}
```

**Notes:**
- Nonces expire after 5 minutes
- Nonces are single-use (deleted on successful auth)

---

#### POST /auth/login

Authenticate user and obtain tokens.

**Request (JWT Authentication):**
```json
{
  "idToken": "eyJhbGciOiJFUzI1NiIs...",
  "publicKey": "0x04abc123..."
}
```

**Request (SIWE Authentication):**
```json
{
  "message": {
    "domain": "cipherbox.io",
    "publicKey": "0x04abc123...",
    "nonce": "abc123xyz789",
    "timestamp": 1705298400,
    "statement": "Sign in to CipherBox"
  },
  "signature": "0xdef789...",
  "publicKey": "0x04abc123..."
}
```

**Response (200):**
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",
  "refreshToken": "abc123...",
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "publicKey": "0x04abc123...",
  "teeKeys": {
    "currentEpoch": 1,
    "currentPublicKey": "base64...",
    "previousEpoch": 0,
    "previousPublicKey": "base64..."
  }
}
```

**Notes:**
- `teeKeys` contains the current and previous TEE public keys for IPNS key encryption
- Clients should encrypt IPNS private keys with `currentPublicKey` and include `currentEpoch`
- `previousPublicKey` is provided for key rotation transitions (may be null if no previous epoch)

**Errors:**
- `400 Bad Request` - Invalid signature or malformed request
- `401 Unauthorized` - Invalid or expired ID token
- `429 Too Many Requests` - Rate limited

**JWT Verification:**
1. Fetch JWKS from `https://api-auth.web3auth.io/jwks`
2. Verify JWT signature (ES256)
3. Check `iss` = `https://api-auth.web3auth.io`
4. Check `aud` = CipherBox project client ID
5. Check `exp` > current time
6. Extract `wallets` array, find `web3auth_app_key`
7. Verify `publicKey` matches wallet's `public_key`

**SIWE Verification:**
1. Find nonce in `auth_nonces` table
2. Verify nonce not expired and not used
3. Verify domain matches `cipherbox.io`
4. Recover public key from signature
5. Verify recovered key matches claimed `publicKey`
6. Delete nonce (prevents replay)

---

#### POST /auth/refresh

Exchange refresh token for new token pair.

**Request:**
```json
{
  "refreshToken": "abc123..."
}
```

**Response (200):**
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",
  "refreshToken": "def456...",
  "teeKeys": {
    "currentEpoch": 42,
    "currentPublicKey": "BGFkZWZn...",
    "previousEpoch": 41,
    "previousPublicKey": "BHlpcGpr..."
  }
}
```

**Errors:**
- `401 Unauthorized` - Invalid or expired refresh token
- `429 Too Many Requests` - Rate limited

**Notes:**
- Old refresh token is invalidated
- New refresh token has fresh 7-day expiry
- TEE keys included to ensure clients always have current keys after token refresh

---

#### POST /auth/logout

Invalidate refresh token.

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request:**
```json
{
  "refreshToken": "abc123..."
}
```

**Response (200):**
```json
{
  "status": "logged_out"
}
```

---

### 3.2 Vault Endpoints

#### GET /my-vault

Get user's vault information.

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200 - Initialized):**
```json
{
  "vaultId": "550e8400-e29b-41d4-a716-446655440000",
  "publicKey": "0x04abc123...",
  "encryptedRootFolderKey": "0x...",
  "encryptedRootIpnsPrivateKey": "0x...",
  "rootIpnsName": "k51qzi5uqu5dlvj55...",
  "initializedAt": "2026-01-15T04:09:00Z"
}
```

**Response (403 - Not Initialized):**
```json
{
  "error": "VAULT_NOT_INITIALIZED",
  "message": "Vault has not been initialized. Call POST /my-vault/initialize."
}
```

---

#### POST /my-vault/initialize

Initialize user's vault with encrypted keys.

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request:**
```json
{
  "publicKey": "0x04abc123...",
  "encryptedRootFolderKey": "0x...",
  "encryptedRootIpnsPrivateKey": "0x...",
  "rootIpnsName": "k51qzi5uqu5dlvj55..."
}
```

**Response (201):**
```json
{
  "vaultId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "initialized"
}
```

**Errors:**
- `400 Bad Request` - Invalid key format
- `409 Conflict` - Vault already initialized

---

#### POST /vault/upload

Upload encrypted file to IPFS via Pinata.

**Headers:**
```
Authorization: Bearer <accessToken>
Content-Type: multipart/form-data
```

**Request (FormData):**
```
encryptedFile: <binary blob>
iv: "0x1234567890abcdef..."
fileName: "budget.xlsx" (optional, for audit)
```

**Response (201):**
```json
{
  "cid": "QmXxxx...",
  "size": 2048576,
  "uploadedAt": "2026-01-15T04:09:00Z"
}
```

**Errors:**
- `400 Bad Request` - Missing file or invalid format
- `413 Payload Too Large` - File exceeds 100MB limit
- `507 Insufficient Storage` - Quota exceeded

**Notes:**
- File is uploaded to Pinata as-is (already encrypted by client)
- Backend never sees plaintext
- Size counted against user's storage quota

---

#### POST /vault/unpin

Unpin a CID from IPFS (for delete/update operations).

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request:**
```json
{
  "cid": "QmXxxx..."
}
```

**Response (200):**
```json
{
  "success": true,
  "unpinnedAt": "2026-01-15T04:09:00Z"
}
```

**Errors:**
- `400 Bad Request` - Invalid CID
- `404 Not Found` - CID not pinned by this user

**Notes:**
- Storage quota reclaimed immediately
- CID may still exist on IPFS network (just not pinned)

---

### 3.3 User Endpoints

#### GET /user/profile

Get user profile information.

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200):**
```json
{
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "publicKey": "0x04abc123...",
  "createdAt": "2026-01-15T04:09:00Z",
  "storageUsed": 52428800,
  "storageLimit": 524288000
}
```

---

#### GET /user/export-vault

Export vault data for independent recovery.

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Response (200):**
```json
{
  "version": "1.0",
  "exportedAt": "2026-01-15T04:09:00Z",
  "rootIpnsName": "k51qzi5uqu5dlvj55...",
  "encryptedRootFolderKey": "0x...",
  "encryptedRootIpnsPrivateKey": "0x...",
  "pinnedCids": [
    "QmXxxx...",
    "QmYyyy...",
    "QmZzzz..."
  ],
  "instructions": "To recover: decrypt keys with your private key, resolve IPNS via any gateway, fetch and decrypt all content."
}
```

---

#### DELETE /user/account

Permanently delete user account and vault.

**Headers:**
```
Authorization: Bearer <accessToken>
```

**Request:**
```json
{
  "confirmDelete": true
}
```

**Response (200):**
```json
{
  "deleted": true,
  "deletedAt": "2026-01-15T04:09:00Z"
}
```

**Errors:**
- `400 Bad Request` - `confirmDelete` not true
- `429 Too Many Requests` - Rate limited (1 request/hour)

**Notes:**
- Unpins all CIDs from Pinata
- Deletes all database records
- Cannot be undone

---

### 3.4 IPFS/IPNS Relay Endpoints

All relay endpoints require `Authorization: Bearer <accessToken>`.

#### POST /ipfs/add

Add encrypted metadata (or any encrypted content) to IPFS via backend relay.

**Headers:**
```
Authorization: Bearer <accessToken>
Content-Type: application/octet-stream
```

**Request Body:**
Raw bytes (encrypted content)

**Response (201):**
```json
{
  "cid": "QmXxxx...",
  "size": 2048
}
```

**Errors:**
- `400 Bad Request` - Invalid payload
- `429 Too Many Requests` - Rate limited
- `502 Bad Gateway` - IPFS relay failed

---

#### GET /ipfs/cat

Fetch encrypted content by CID via backend relay.

**Query:**
```
?cid=QmXxxx...
```

**Response (200):**
```
<raw bytes>
```

**Errors:**
- `400 Bad Request` - Invalid CID
- `404 Not Found` - CID not found
- `429 Too Many Requests` - Rate limited
- `502 Bad Gateway` - IPFS relay failed

---

#### GET /ipns/resolve

Resolve IPNS name to current CID via backend relay.

**Query:**
```
?ipnsName=k51qzi5uqu5dlvj55...
```

**Response (200):**
```json
{
  "cid": "QmXxxx...",
  "resolvedAt": "2026-01-18T12:00:00Z"
}
```

**Errors:**
- `400 Bad Request` - Invalid IPNS name
- `404 Not Found` - IPNS name not found
- `429 Too Many Requests` - Rate limited
- `502 Bad Gateway` - IPNS relay failed

---

#### POST /ipns/publish

Relay a client-signed IPNS record to the IPFS/IPNS network and optionally register for TEE-based republishing.

**Request:**
```json
{
  "ipnsName": "k51qzi5uqu5dlvj55...",
  "ipnsRecord": "BASE64_ENCODED_SIGNED_RECORD",
  "sequenceNumber": 42,
  "ttlSeconds": 3600,
  "encryptedIpnsPrivateKey": "0x...",
  "keyEpoch": 1
}
```

**Response (200):**
```json
{
  "published": true,
  "ipnsName": "k51qzi5uqu5dlvj55...",
  "sequenceNumber": 42,
  "publishedAt": "2026-01-20T12:00:00Z",
  "republishScheduled": true
}
```

**Errors:**
- `400 Bad Request` - Invalid record or malformed request
- `401 Unauthorized` - Invalid access token
- `409 Conflict` - Sequence number too low
- `429 Too Many Requests` - Rate limited
- `502 Bad Gateway` - IPNS relay failed

**Notes:**
- `encryptedIpnsPrivateKey` is the IPNS Ed25519 private key encrypted with the TEE's current public key
- `keyEpoch` must match the current TEE epoch (obtained from `/auth/login` response)
- When `encryptedIpnsPrivateKey` is provided, the backend schedules automatic IPNS republishing
- The TEE will decrypt the key and re-sign IPNS records before TTL expiry
- If `keyEpoch` does not match current epoch, returns `400` with `KEY_EPOCH_MISMATCH` error

---

## 4. Database Schema

### 4.1 Users Table

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  public_key BYTEA UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_public_key ON users(public_key);
```

**Notes:**
- Users identified by public key, not email
- No auth provider mapping (handled by Web3Auth)

---

### 4.2 Refresh Tokens Table

```sql
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  revoked_at TIMESTAMP,
  UNIQUE(token_hash)
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
```

**Notes:**
- Tokens stored as SHA-256 hash
- `revoked_at` set on logout or rotation

---

### 4.3 Auth Nonces Table

```sql
CREATE TABLE auth_nonces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  nonce VARCHAR(64) UNIQUE NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_auth_nonces_expires_at ON auth_nonces(expires_at);

-- Cleanup job (run periodically):
-- DELETE FROM auth_nonces WHERE expires_at < NOW();
```

**Notes:**
- Nonces deleted immediately on successful verification
- TTL-based cleanup for expired/unused nonces

---

### 4.4 Vaults Table

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

---

### 4.5 Volume Audit Table

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

---

### 4.6 Pinned CIDs Table

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

---

### 4.7 IPNS Republish Schedule Table

Stores IPNS entries scheduled for automatic TEE-based republishing.

```sql
CREATE TABLE ipns_republish_schedule (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ipns_name VARCHAR(255) NOT NULL,
  latest_cid VARCHAR(255) NOT NULL,
  sequence_number BIGINT NOT NULL,
  encrypted_ipns_key BYTEA NOT NULL,
  key_epoch INTEGER NOT NULL,
  encrypted_ipns_key_prev BYTEA,
  key_epoch_prev INTEGER,
  next_republish_at TIMESTAMP NOT NULL,
  retry_count INTEGER DEFAULT 0,
  last_error TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, ipns_name)
);

CREATE INDEX idx_ipns_republish_next ON ipns_republish_schedule(next_republish_at);
CREATE INDEX idx_ipns_republish_user ON ipns_republish_schedule(user_id);
```

**Notes:**
- `encrypted_ipns_key` is the IPNS private key encrypted with TEE's current public key
- `encrypted_ipns_key_prev` stores the key encrypted with previous TEE epoch (for rotation transitions)
- `next_republish_at` is set to ~80% of TTL to ensure republish before expiry
- `retry_count` tracks failed republish attempts (max 3 before marking as failed)

---

### 4.8 TEE Key State Table

Tracks the current TEE key epoch and public keys.

```sql
CREATE TABLE tee_key_state (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  current_epoch INTEGER NOT NULL,
  public_key_current BYTEA NOT NULL,
  public_key_previous BYTEA,
  previous_epoch INTEGER,
  last_updated TIMESTAMP DEFAULT NOW(),
  phala_block_height BIGINT
);
```

**Notes:**
- Single-row table (enforced by `CHECK (id = 1)`)
- `phala_block_height` tracks the Phala blockchain height when key was last synced
- `public_key_previous` allows clients to verify during key rotation transitions

---

### 4.9 TEE Key Rotation Log Table

Audit log for TEE key rotation events.

```sql
CREATE TABLE tee_key_rotation_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  old_epoch INTEGER NOT NULL,
  new_epoch INTEGER NOT NULL,
  rotation_time TIMESTAMP DEFAULT NOW(),
  affected_entries INTEGER NOT NULL
);

CREATE INDEX idx_tee_rotation_time ON tee_key_rotation_log(rotation_time);
```

**Notes:**
- `affected_entries` is the count of `ipns_republish_schedule` rows that were re-encrypted
- Used for auditing and debugging key rotation issues

---

### 4.10 IPFS Operations Log Table

Tracks IPFS/IPNS operations for monitoring and debugging.

```sql
CREATE TABLE ipfs_operations_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  operation_type VARCHAR(50) NOT NULL,
  ipns_name_or_cid VARCHAR(255),
  status VARCHAR(20) NOT NULL,
  latency_ms INTEGER,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ipfs_ops_user ON ipfs_operations_log(user_id);
CREATE INDEX idx_ipfs_ops_created ON ipfs_operations_log(created_at);
CREATE INDEX idx_ipfs_ops_type ON ipfs_operations_log(operation_type);
```

**Notes:**
- `operation_type` values: `ipfs_add`, `ipfs_cat`, `ipns_resolve`, `ipns_publish`, `ipns_republish`
- `status` values: `success`, `failed`, `timeout`
- Used for monitoring IPFS gateway health and debugging issues

---

## 5. Rate Limiting

### 5.1 Rate Limits by Endpoint

| Endpoint | Limit | Window | Rationale |
|----------|-------|--------|-----------|
| POST /auth/login | 10 | per minute | Prevent brute-force |
| POST /auth/refresh | 30 | per minute | Normal usage |
| GET /auth/nonce | 20 | per minute | SIWE flow attempts |
| POST /vault/upload | 60 | per minute | Batch upload support |
| GET /my-vault | 120 | per minute | Polling + normal access |
| DELETE /user/account | 1 | per hour | Prevent accidental deletion |
| POST /ipfs/add | 120 | per minute | Metadata relay |
| GET /ipfs/cat | 300 | per minute | Encrypted content relay |
| GET /ipns/resolve | 240 | per minute | Sync polling |
| POST /ipns/publish | 120 | per minute | Signed-record relay |

### 5.2 Rate Limit Headers

All responses include:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1705298460
```

### 5.3 Rate Limit Response

**Response (429):**
```json
{
  "error": "RATE_LIMIT_EXCEEDED",
  "message": "Too many requests. Try again later.",
  "retryAfter": 30
}
```

Headers:
```
Retry-After: 30
```

---

## 6. Error Handling

### 6.1 Error Response Format

All errors follow this format:

```json
{
  "error": "ERROR_CODE",
  "message": "Human-readable description",
  "details": {} // Optional additional context
}
```

### 6.2 Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Malformed request body |
| `INVALID_TOKEN` | 401 | Invalid or expired token |
| `INVALID_SIGNATURE` | 401 | SIWE signature verification failed |
| `NONCE_EXPIRED` | 401 | SIWE nonce has expired |
| `NONCE_USED` | 401 | SIWE nonce already used |
| `VAULT_NOT_INITIALIZED` | 403 | Vault must be initialized first |
| `VAULT_ALREADY_INITIALIZED` | 409 | Cannot re-initialize vault |
| `CID_NOT_FOUND` | 404 | CID not pinned by this user |
| `FILE_TOO_LARGE` | 413 | File exceeds 100MB limit |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `QUOTA_EXCEEDED` | 507 | Storage quota exceeded |
| `IPFS_RELAY_FAILED` | 502 | IPFS relay failed |
| `IPNS_RELAY_FAILED` | 502 | IPNS relay failed |
| `KEY_EPOCH_MISMATCH` | 400 | TEE key epoch does not match current epoch |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

---

## Related Documents

- [PRD.md](./PRD.md) - Product requirements and user journeys
- [TECHNICAL_ARCHITECTURE.md](./TECHNICAL_ARCHITECTURE.md) - System design and encryption
- [DATA_FLOWS.md](./DATA_FLOWS.md) - Detailed sequence diagrams
- [CLIENT_SPECIFICATION.md](./CLIENT_SPECIFICATION.md) - Web UI and desktop app specifications

---

**End of API Specification**
