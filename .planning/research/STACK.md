# Stack Research

**Project:** CipherBox
**Research Date:** 2026-01-20
**Confidence:** HIGH

## Executive Summary

The specified stack (NestJS + React 18 + Tauri + Web3Auth + Pinata) is **well-aligned with 2025/2026 best practices** for encrypted cloud storage. Minor adjustments recommended for crypto libraries and IPFS client.

## Backend Stack

### Specified: NestJS

**Verdict:** APPROVED

| Aspect | Assessment |
|--------|------------|
| Maturity | Production-ready, widely adopted |
| TypeScript | First-class support |
| Auth | Excellent JWT/middleware ecosystem |
| Performance | Adequate for relay-style backend |
| Alternative | Fastify (slightly faster, less structured) |

**Recommended Version:** NestJS 10.x (current stable)

**Key Dependencies:**
- `@nestjs/core` ^10.0.0
- `@nestjs/platform-express` ^10.0.0
- `jose` ^5.2.0 - JWT verification (better than jsonwebtoken)
- `pg` ^8.11.0 - PostgreSQL client
- `winston` ^3.11.0 - Structured logging

### Database: PostgreSQL

**Verdict:** APPROVED

Best choice for:
- ACID transactions (token rotation)
- JSON columns (flexible metadata)
- Mature ecosystem
- Self-hostable

**Recommended Version:** PostgreSQL 16.x

## Frontend Stack

### Specified: React 18 + Tailwind

**Verdict:** APPROVED

| Aspect | Assessment |
|--------|------------|
| React 18 | Current stable, concurrent features |
| Tailwind | Fast styling, good DX |
| Bundle size | Manageable with tree-shaking |

**Recommended Additions:**
- `@tanstack/react-query` ^5.0.0 - Server state management
- `zustand` ^4.5.0 - Client state (lighter than Redux)
- `react-dropzone` ^14.2.0 - File upload UX

### Build Tool

**Recommendation:** Vite 5.x over Create React App

- Faster dev server (native ESM)
- Better production builds
- First-class TypeScript support

## Desktop Stack

### Specified: Tauri + macFUSE

**Verdict:** APPROVED with notes

| Aspect | Tauri | Electron |
|--------|-------|----------|
| Bundle size | ~10MB | ~150MB |
| Memory | Lower | Higher |
| FUSE integration | Requires Rust bridge | Node.js native |
| Maturity | Stable (v1.5+) | Very mature |

**Recommendation:** Tauri is correct choice for security-focused app.

**FUSE Libraries:**
- macOS: macFUSE 4.x (requires user install)
- Linux: libfuse3 (system package)
- Windows: WinFSP 2.x (v1.1 scope)

**Challenge:** FUSE bindings from Tauri require Rust-side integration. Consider:
- `fuser` crate for Rust FUSE
- IPC to Node.js subprocess for crypto (if Web Crypto unavailable in Tauri)

## Cryptography Stack

### Symmetric: AES-256-GCM

**Verdict:** APPROVED

- Standard choice for authenticated encryption
- Web Crypto API native support
- 100MB file size fits in browser memory

**Browser:** Use `crypto.subtle` (Web Crypto API)
**Node.js:** Use `crypto.createCipheriv`

### Asymmetric: ECIES (secp256k1)

**Verdict:** APPROVED with library update

**Current PoC:** `eciesjs` 0.4.7
**Recommended:** `@noble/secp256k1` ^2.1.0 + `@noble/hashes` ^1.3.0

Rationale:
- `@noble/*` libraries are audited, pure JS, no native deps
- Better for browser/Tauri compatibility
- Same author maintains both, but noble is more actively developed

**ECIES Implementation:**
```typescript
// Use @noble/secp256k1 for ECIES
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
```

### IPNS Signing: Ed25519

**Verdict:** APPROVED

**Library:** `@noble/ed25519` ^2.0.0 (consistent with noble ecosystem)

Alternative: `libsodium.js` (heavier, more features than needed)

## IPFS Stack

### Specified: Pinata + ipfs-http-client

**Verdict:** NEEDS UPDATE

**Issue:** `ipfs-http-client` is deprecated as of 2024.

**Recommended Replacement:**
- `@helia/http` - Official successor for HTTP API
- OR direct Pinata SDK: `@pinata/sdk` ^2.1.0

**For IPNS:**
- Client-side signing with `@noble/ed25519`
- Backend relays signed records to Pinata/Kubo

**Pinata API:**
- Pin content: `POST /pinning/pinFileToIPFS`
- Unpin: `DELETE /pinning/unpin/{hash}`
- IPNS: Requires Kubo node or custom solution

**Note:** Pinata doesn't directly support IPNS publishing. Architecture requires:
1. Client signs IPNS record
2. Backend relays to Kubo node (or Pinata dedicated gateway)

## Auth Stack

### Specified: Web3Auth

**Verdict:** APPROVED

**SDK:** `@web3auth/modal` ^8.0.0 (current)

**Key Features Used:**
- Deterministic key derivation (secp256k1)
- Group connections (same keys across auth methods)
- Social logins + wallet + email

**Backend Verification:**
- Verify Web3Auth JWT via JWKS endpoint
- Issue CipherBox tokens (access + refresh)

**Recommended:**
- `jose` for JWT verification (not jsonwebtoken)
- Store JWKS with short TTL cache (5 min)

## TEE Stack

### Specified: Phala Cloud + AWS Nitro fallback

**Verdict:** APPROVED

**Phala Cloud:**
- Rust-based TEE contracts
- secp256k1 support via `phat-offchain-rollup`
- Ed25519 signing for IPNS

**AWS Nitro:**
- Fallback if Phala unavailable
- Python/Node.js runtime in enclave

**Key Epoch Rotation:**
- 4-week grace period (spec'd correctly)
- ECIES encryption to TEE public key

## Recommended Package Versions

### Backend (NestJS)
```json
{
  "@nestjs/core": "^10.3.0",
  "@nestjs/platform-express": "^10.3.0",
  "jose": "^5.2.0",
  "pg": "^8.11.0",
  "winston": "^3.11.0",
  "class-validator": "^0.14.0",
  "class-transformer": "^0.5.1"
}
```

### Frontend (React)
```json
{
  "react": "^18.2.0",
  "react-dom": "^18.2.0",
  "@web3auth/modal": "^8.0.0",
  "@tanstack/react-query": "^5.17.0",
  "zustand": "^4.5.0",
  "tailwindcss": "^3.4.0",
  "vite": "^5.0.0"
}
```

### Crypto (Shared)
```json
{
  "@noble/secp256k1": "^2.1.0",
  "@noble/ed25519": "^2.0.0",
  "@noble/hashes": "^1.3.3",
  "@noble/curves": "^1.3.0"
}
```

### Desktop (Tauri)
```
tauri = "1.5"
fuser = "0.14"  # Rust FUSE bindings
```

## Stack Risks

| Risk | Mitigation |
|------|------------|
| ipfs-http-client deprecated | Migrate to @helia/http or direct Pinata SDK |
| FUSE complexity on macOS | Document macFUSE install requirement clearly |
| Web3Auth SDK updates | Pin major version, test upgrades in staging |
| Tauri + FUSE integration | Prototype early in Week 9 |

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Backend | HIGH | NestJS is battle-tested |
| Frontend | HIGH | React 18 + Vite is standard |
| Crypto | HIGH | Noble libraries are audited |
| IPFS | MEDIUM | Deprecation requires migration |
| Desktop | MEDIUM | FUSE integration needs prototyping |
| TEE | MEDIUM | Phala integration not yet prototyped |

---

*Research complete: 2026-01-20*
