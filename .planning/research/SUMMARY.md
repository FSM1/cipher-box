# Research Summary

**Project:** CipherBox
**Research Date:** 2026-01-20
**Confidence:** HIGH

---

## Executive Summary

The CipherBox specifications are **well-designed and align with industry best practices** for zero-knowledge encrypted storage. Research validates the core architecture while identifying specific risks to mitigate during implementation.

**Key Validation:** The IPFS/IPNS + Web3Auth + TEE architecture is novel but sound. No fundamental design flaws found.

**Key Risks:** IPNS latency (~30s), deprecated `ipfs-http-client`, macOS FUSE complexity.

---

## Stack Findings

### Validated Choices
| Component | Specified | Verdict |
|-----------|-----------|---------|
| Backend | NestJS 10.x | APPROVED |
| Frontend | React 18 + Vite | APPROVED |
| Desktop | Tauri + FUSE | APPROVED |
| Auth | Web3Auth | APPROVED |
| Database | PostgreSQL 16.x | APPROVED |
| Pinning | Pinata | APPROVED |

### Recommended Updates
| Current | Recommended | Reason |
|---------|-------------|--------|
| `ipfs-http-client` 60.0.1 | `@helia/http` or Pinata SDK | Deprecated library |
| `eciesjs` 0.4.7 | `@noble/secp256k1` + `@noble/curves` | Audited, better cross-platform |
| (unspecified) | `@noble/ed25519` for IPNS | Consistent with noble ecosystem |

### Key Versions
```json
{
  "@nestjs/core": "^10.3.0",
  "react": "^18.2.0",
  "@web3auth/modal": "^8.0.0",
  "@noble/secp256k1": "^2.1.0",
  "@noble/ed25519": "^2.0.0",
  "jose": "^5.2.0",
  "vite": "^5.0.0"
}
```

---

## Feature Findings

### v1.0 Scope Assessment
| Category | Status | Notes |
|----------|--------|-------|
| E2E Encryption | Covered | AES-256-GCM + ECIES |
| Multi-Auth | Covered | 4 methods via Web3Auth |
| File Operations | Covered | Full CRUD |
| Web UI | Covered | React with drag-drop |
| Desktop FUSE | Covered | macOS only for v1 |
| Multi-Device Sync | Covered | 30s IPNS polling |
| TEE Republishing | Covered | Novel architecture |
| Vault Export | Covered | Data portability |

### Notable Gaps (Acceptable for Tech Demo)
| Gap | Competitors Have | v1.0 Impact | Recommendation |
|-----|------------------|-------------|----------------|
| File Sharing | All | Blocker for commercial | Defer to v2.0 |
| Mobile Apps | All | 60%+ access is mobile | Defer to v2.0 |
| File Preview | Most | Poor UX | Consider for v1.0 |
| Soft Delete | Most | Data loss risk | Consider for v1.0 |

### CipherBox Differentiators
1. **IPFS/IPNS decentralized storage** - Unique among competitors
2. **TEE-based IPNS republishing** - Novel solution to 24h expiry
3. **Web3Auth deterministic keys** - Better than backup phrases
4. **True data portability** - Vault export works offline

---

## Architecture Findings

### Validated Architecture
```
Client (Trusted) <--HTTPS--> Backend (Zero-Knowledge) <---> IPFS/TEE
     |                              |
     +-- All encryption             +-- Only encrypted data
     +-- IPNS signing               +-- Relay signed records
     +-- Key in RAM only            +-- Never sees plaintext
```

### Security Model Validation
- Private key in client RAM only
- Server stores only ECIES-encrypted keys
- Per-folder IPNS enables future sharing
- TEE key epoch rotation is well-designed

### Build Order Recommendation
1. **Foundation** - Project scaffold, CI/CD
2. **Auth** - Web3Auth + backend tokens
3. **Storage & Crypto** - File upload/download
4. **IPNS & Sync** - Folder metadata, polling
5. **TEE Integration** - Auto-republishing
6. **Desktop Client** - FUSE mount
7. **Polish & Launch** - Testing, security audit

---

## Critical Pitfalls

### Must Prevent (Security/Data Loss)
| Pitfall | Phase | Prevention |
|---------|-------|------------|
| AES-GCM nonce reuse | Crypto | Always `crypto.getRandomValues()` for IV |
| Private key in browser storage | Auth | RAM only, clear on logout |
| IPNS expiry | TEE | 3-hour republish, monitor success rate |
| ECIES incompatibility | Crypto | Pin parameters, cross-platform tests |
| Large file memory crash | Upload | Enforce 100MB limit client-side |

### Must Mitigate (UX/Performance)
| Pitfall | Phase | Prevention |
|---------|-------|------------|
| IPNS resolution latency | IPNS | Cache locally, optimistic UI |
| Pinata rate limiting | IPFS | Request queue, exponential backoff |
| macOS FUSE complexity | Desktop | Clear install guide, consider FUSE-T |
| Web3Auth group misconfiguration | Auth | Single `groupedAuthConnectionId`, tests |
| Key clearing on logout | Auth | Centralized key manager, `beforeunload` |

---

## Recommendations for v1.0

### Add to Scope (Low Complexity, High Value)
1. **Basic file preview** - Images inline, PDF viewer
2. **Soft delete / recycle bin** - 7-day retention
3. **2FA visibility** - Show security status in settings

### Monitor During Implementation
1. IPNS resolution P95 latency
2. TEE republish success rate
3. Memory usage during file encryption
4. Pinata API rate limit hits

### Test Vectors Required
1. AES-GCM encryption/decryption
2. ECIES key wrapping (cross-platform)
3. Ed25519 IPNS signing
4. Web3Auth group connections (same keypair)

---

## Files Created

| File | Purpose |
|------|---------|
| `STACK.md` | Technology stack validation and recommendations |
| `FEATURES.md` | Feature landscape, table stakes, differentiators |
| `ARCHITECTURE.md` | Component boundaries, data flows, build order |
| `PITFALLS.md` | Domain-specific risks and mitigations |

---

## Confidence Assessment

| Area | Confidence | Rationale |
|------|------------|-----------|
| Stack choices | HIGH | Industry standard, well-documented |
| Feature gaps | HIGH | Competitor analysis from 8 products |
| Architecture | HIGH | Matches zero-knowledge best practices |
| Pitfalls | HIGH | Documented incidents, official sources |
| Build order | MEDIUM | Logical dependencies, needs validation |

---

*Research complete: 2026-01-20*
