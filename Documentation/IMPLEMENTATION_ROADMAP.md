---
version: 1.8.1
last_updated: 2026-01-18
status: Active
ai_context: Implementation roadmap for CipherBox v1.0. Includes week-by-week plan, deliverables, and testing milestones.
---

<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# CipherBox v1.0 - Implementation Roadmap

**3-Month Development Timeline | 3-Person Team**

***

## 📊 Overview

```
           Week 1-2              Week 3-4              Week 5-7              Week 8-10             Week 11-12
       ┌──────────────┬──────────────────┬──────────────────┬──────────────────┬──────────────────┐
       │   Planning   │      Auth        │   Storage &      │   Web UI &       │  Testing &       │
       │   & Setup    │    Encryption    │   IPFS           │  Desktop         │   Launch         │
       └──────────────┴──────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

**Total:** 12 weeks | **Team:** 3 people | **Target Launch:** April 15, 2026

***

## 📅 Week-by-Week Breakdown

### **Week 1: Planning \& Environment Setup**

**Goal:** Validate architecture, establish dev environment

**Deliverables:**

```
✅ PRD reviewed by team
✅ Dev environments working (Node.js, PostgreSQL, Docker)
✅ Crypto libraries evaluated (Web Crypto API, libsodium.js)
✅ Console PoC harness spike (single-user IPFS/IPNS + pin/unpin)
✅ Web3Auth dashboard setup + group connections configured
✅ Pinata API test account
✅ Database schema migration scripts
✅ Git repos created (backend, frontend, desktop)
✅ CI/CD pipeline (GitHub Actions)
```

**Team:** Backend (100%), Frontend (50%), DevOps (50%)

***

### **Week 2: Pre-Development Setup**

**Goal:** Infrastructure ready, crypto verified

**Deliverables:**

```
✅ Web3Auth key derivation tested (same user → same keypair via group connections)
✅ Web3Auth ID token verification via JWKS endpoint
✅ IPFS/Pinata integration verified
✅ Crypto test vectors pass (AES-256-GCM, ECIES)
✅ PostgreSQL schema deployed (6 tables: users, refresh_tokens, auth_nonces, vaults, volume_audit, pinned_cids)
✅ API contract stub (15 endpoints - IPFS/IPNS relay included)
✅ Docker containers working
✅ IPFS/IPNS relay endpoints tested (signed-record publish)
```

**Team:** Backend (80%), DevOps (80%), Frontend (40%)

***

### **Week 3: Backend Auth (Web3Auth Integration)**

**Goal:** Web3Auth ID token validation + CipherBox token issuance

**Deliverables:**

```
✅ GET /auth/nonce (for SIWE-style auth)
✅ POST /auth/login (Web3Auth JWT or SIWE signature)
✅ POST /auth/refresh (token rotation)
✅ Web3Auth JWKS verification (jose library)
✅ Access token (15min) + refresh token (7 days) issuance
✅ Database: users (by pubkey), refresh_tokens, auth_nonces tables
✅ Session middleware (access token validation)
```

**Tests:** Web3Auth login → token issuance → API access → token refresh

**Team:** Backend (100%)

***

### **Week 4: Auth Completion (All Methods via Web3Auth)**

**Goal:** All 4 auth methods working via Web3Auth

**Deliverables:**

```
✅ Email/Password: Web3Auth handles credential verification
✅ OAuth: Google/Apple/GitHub via Web3Auth modal
✅ Magic Link: Email passwordless via Web3Auth
✅ External Wallet: MetaMask/WalletConnect via Web3Auth
✅ Web3Auth group connections: All methods → same keypair
✅ Account linking: Handled by Web3Auth (not CipherBox backend)
✅ GET /my-vault (vault init check)
```

**Tests:** Cross-method consistency (Google → email → external wallet → same keypair)

**Team:** Backend (80%), Frontend (60%)

***

### **Week 5: File Encryption + Upload**

**Goal:** Client-side encryption + IPFS upload

**Deliverables:**

```
✅ Client: Random file key + AES-256-GCM encryption
✅ Client: ECIES key wrapping (fileKey → userPubkey)
✅ POST /vault/upload → Pinata → CID
✅ POST /vault/unpin → Pinata unpin (for delete/update operations)
✅ Database: volume_audit (quota tracking)
✅ 500 MiB free tier quota enforcement
✅ File size limit enforcement (100 MB max per file)
```

**Tests:** Encrypt → upload → download → decrypt matches original

**Team:** Frontend (100%), Backend (80%)

***

### **Week 6: IPNS Publishing + Folders (Relay)**

**Goal:** Folder hierarchy + signed-record IPNS relay

**Deliverables:**

```
✅ Per-folder IPNS keypairs (Ed25519, generated per folder)
✅ IPNS keypairs stored encrypted: ECIES(ipnsPrivKey, userPubkey)
✅ Root IPNS keypair stored on server (via POST /my-vault/initialize)
✅ Subfolder IPNS keypairs stored in parent folder metadata
✅ Client signs IPNS record → POST /ipns/publish (relay)
✅ Encrypted metadata published via POST /ipfs/add
✅ Folder create → generate keypair → metadata → IPNS publish
✅ Tree traversal (resolve IPNS → fetch → decrypt → recurse)
✅ Backend relays signed IPNS records (keys never leave client)
```

**Architecture Note:** IPNS signing keys are managed entirely client-side.
Backend relays signed records only; private keys never leave client.

**Tests:** Create folder → IPNS resolves → metadata decrypts correctly

**Team:** Backend (40%), Frontend (100%)

***

### **Week 7: File Operations (Rename/Move/Delete/Update)**

**Goal:** Complete CRUD operations

**Deliverables:**

```
✅ Rename file: Update metadata → relay IPNS publish
✅ Move: Add to destination → remove from source → dual IPNS relay publish
✅ Delete: Unpin CID (POST /vault/unpin) → remove metadata → republish
✅ Update file: New key/IV → upload → update metadata → unpin old CID
✅ Bulk operations (multi-select upload/delete)
✅ Download flow: IPNS resolve → IPFS fetch → decrypt
✅ Storage quota reclaimed on delete/update via unpin
```

**Move Operation Order:** Destination first, then source removal (prevents data loss)

**Tests:** Rename/move/delete/update → metadata updates → other devices see changes

**Team:** Frontend (100%), Backend (30%)

***

### **Week 8: Web UI (React File Browser)**

**Goal:** Production React UI

**Deliverables:**

```
✅ Login page (Web3Auth modal integration)
✅ Vault page: Sidebar tree + main file list
✅ Drag-drop upload zone
✅ Context menus (right-click: rename/delete/move)
✅ Settings: Linked accounts (via Web3Auth), export
✅ Storage indicator (500 MiB free tier)
✅ Responsive design (mobile/tablet/desktop)
```

**Tech:** React 18 + TypeScript + Tailwind + @web3auth/modal

**Team:** Frontend (100%)

***

### **Week 9: Desktop App - macOS FUSE Mount**

**Goal:** Transparent filesystem mount

**Deliverables:**

```
✅ Login window (Web3Auth via embedded browser or system browser)
✅ Web3Auth keypair derivation + CipherBox backend auth
✅ Secure token storage (OS keychain for refresh token)
✅ FUSE mount at ~/CipherVault
✅ Read: IPFS fetch → decrypt → return plaintext
✅ Write: Encrypt → IPFS upload → IPNS update
✅ Background sync daemon (30s polling)
✅ System tray + notifications
```

**Tech:** Tauri + macFUSE

**Team:** Backend/DevOps (100%)

***

### **Week 10: Desktop Linux/Windows + Sync Polish**

**Goal:** Cross-platform desktop + sync optimization

**Deliverables:**

```
✅ Linux: FUSE3 integration
✅ Windows: WinFSP integration  
✅ Sync cache (IPNS CID → TTL 1h)
✅ Exponential backoff for polling
✅ Conflict detection (last-write-wins v1)
✅ Offline queueing (retry on reconnect)
```

**Team:** Backend/DevOps (70%), Frontend (30%)

***

### **Week 11: Testing \& Security Audit**

**Goal:** Production readiness

**Deliverables:**

```
✅ Unit tests: 85%+ coverage (crypto, auth, storage)
✅ Integration tests: 4 auth → keypair → vault access
✅ E2E tests: Upload → sync → download → verify
✅ Security audit: Private key handling, crypto correctness
✅ Performance: Meet all SLOs (<5s upload, <3s auth)
✅ Bug fixes (<10 critical issues)
```

**Team:** All 3 (100%)

***

### **Week 12: Launch Preparation**

**Goal:** Production deployment

**Deliverables:**

```
✅ Docker production images
✅ PostgreSQL production DB
✅ HTTPS certificates
✅ Monitoring (uptime, latency, errors)
✅ Documentation (API, deployment, user guides)
✅ Soft launch (10 beta users)
✅ Public launch (website, social)
```

**Team:** DevOps (100%), Backend (80%), Frontend (50%)

***

## 📊 Milestones \& Go/No-Go

### **Week 4 End: Auth Complete** ✅

```
✅ All 4 auth methods working
✅ Key derivation deterministic
✅ Cross-method vault access verified
```


### **Week 7 End: Storage Complete** ✅

```
✅ File upload/download end-to-end
✅ Signed-record IPNS relay reliable
✅ Folder hierarchy with per-folder IPNS keypairs
✅ File update/delete with CID unpinning
```


### **Week 10 End: Platforms Complete** ✅

```
✅ Web + macOS desktop functional
✅ Multi-device sync verified
```


### **Week 11 End: Testing Complete** ✅

```
✅ 85%+ test coverage
✅ Security audit passed
✅ Performance SLOs met
```


***

## 👥 Team Allocation (Total: 800 hours)

| Role | W1-4 | W5-8 | W9-10 | W11-12 | Total |
| :-- | :-- | :-- | :-- | :-- | :-- |
| **Backend** | 100% | 50% | 60% | 90% | **320h** |
| **Frontend** | 50% | 100% | 50% | 80% | **280h** |
| **DevOps** | 40% | 40% | 80% | 100% | **200h** |

**Note:** Backend allocation balanced in W5-8 due to IPFS/IPNS relay endpoints.
Frontend focuses on signing and relay integration.


***

## ⚠️ Risks \& Mitigation

| Risk | Probability | Mitigation |
| :-- | :-- | :-- |
| Web3Auth integration | Medium | Week 1 deep-dive, direct support, group connections testing |
| IPFS performance | Medium | Pinata + caching strategy |
| IPFS/IPNS relay reliability | Medium | Week 2 relay endpoint load testing + retry strategy |
| Security audit | Low | Continuous review, 2-week buffer |
| Desktop complexity | Medium | macOS first, others v1.1 |


***

You're right - context limit cut it off. Here's the **COMPLETE IMPLEMENTATION_ROADMAP.md** (continued from where it stopped):

***

## 📈 Success Metrics (Continued)

| Metric | Target |
|--------|--------|
| **Privacy** | Private keys never on server |
| **Auth Latency** | <3s (all 4 methods) |
| **File Upload** | <5s (<100MB) |
| **File Download** | <5s (<100MB) |
| **Multi-Device Sync** | <30s |
| **IPNS Publish** | <2s |
| **FUSE Mount** | <3s startup |
| **Uptime** | 99.5% |
| **Test Coverage** | >85% |

***

## 🔧 Post-Launch (Week 13+)

### **Week 13-16: Stabilization**
```
✅ 24/7 monitoring (on-call rotation)
✅ Bug fixes from beta users
✅ Performance tuning
✅ User feedback collection
```

### **v1.1 (Month 5-6): Billing & Platforms**
```
✅ Stripe integration + paid tiers
✅ Linux desktop app
✅ Windows desktop app  
✅ Mobile web optimization
```

***

## 📞 Communication Plan

### **Weekly Standups**
```
Monday 10 AM CET (30 min)
- What did last week
- What doing this week  
- Blockers
```

### **Bi-Weekly Reviews**
```
Thursday every 2 weeks (1 hr)
- Demo progress
- Review milestones
- Adjust plan
```

### **Daily Async**
```
Slack for quick questions
GitHub issues for bugs/features
Code reviews within 24h
```

***

## 🎯 Go/No-Go Milestones

### **Week 4: "Auth Done"** ✅
```
[ ] All 4 auth methods working end-to-end
[ ] Key derivation deterministic (test vectors pass)
[ ] Cross-method vault access verified
[ ] No critical blockers
```

**NO-GO:** Web3Auth issues → Week 1 fallback plan

### **Week 7: "Storage Done"** ✅
```
[ ] File upload/download complete
[ ] Signed-record IPNS relay reliable
[ ] Per-folder IPNS keypairs working
[ ] Folder hierarchy functional
[ ] Multi-file operations working
[ ] File update/delete with unpin working
```

**NO-GO:** IPFS latency → Caching + gateway switch
**NO-GO:** Client IPFS publishing issues → Evaluate js-ipfs alternative

### **Week 10: "Platforms Done"** ✅
```
[ ] Web UI production-ready
[ ] macOS FUSE mount working
[ ] Multi-device sync verified
[ ] All major features functional
```

**NO-GO:** Desktop issues → Web-only launch, desktop v1.1

### **Week 11: "Tested & Audited"** ✅
```
[ ] 85%+ test coverage
[ ] Security audit passed (no criticals)
[ ] Performance SLOs met
[ ] <10 bugs remaining
```

**NO-GO:** Security issues → Fix before launch

### **Week 12: "Launch Ready"** ✅
```
[ ] Production deployment working
[ ] Monitoring operational
[ ] Beta users happy
[ ] Documentation complete
```

***

## 👥 Resource Requirements

### **Team Composition**
```
1. Backend Developer (Node.js/NestJS, PostgreSQL)
2. Frontend Developer (React 18, Web Crypto API)
3. DevOps/Fullstack (Docker, IPFS, Desktop FUSE)
```

### **Hours Breakdown**
```
Backend: 360 hours (45%)
Frontend: 240 hours (30%)
DevOps: 200 hours (25%)
TOTAL: 800 hours (12 weeks × 3 people × 40h)
```

***

## ⚠️ Risk Matrix

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Web3Auth integration fails | High | Medium | Week 1 deep-dive + group connections testing |
| IPFS Pinata slow | Medium | Medium | Local IPFS node + caching |
| Security audit fails | High | Low | Continuous review + 2-week buffer |
| Desktop FUSE complex | Medium | Medium | macOS first, others v1.1 |
| Team bandwidth | Medium | Low | Clear priorities + async communication |

***

## 📋 Pre-Launch Checklist (Week 12)

### **Security** 
```
[ ] Code audit complete
[ ] Private keys never logged/persisted
[ ] Crypto test vectors pass
[ ] Dependency scan clean (Snyk)
[ ] HTTPS enforced everywhere
```

### **Functionality**
```
[ ] All 4 auth methods working
[ ] File upload/download E2E tested
[ ] Multi-device sync verified
[ ] macOS FUSE mount production-ready
[ ] Vault export/recovery tested
```

### **Performance**
```
[ ] Auth <3s P95
[ ] Upload <5s P95 (<100MB)
[ ] Sync <30s
[ ] IPNS resolve <2s (cached <200ms)
```

### **Deployment**
```
[ ] Docker images built & tested
[ ] Production PostgreSQL
[ ] Pinata production keys
[ ] HTTPS certificates
[ ] Monitoring/alerting operational
```

### **Documentation**
```
[ ] API docs (OpenAPI)
[ ] Deployment guide
[ ] User guide
[ ] Security best practices
[ ] Runbooks for on-call
```

***

## 🎯 Success Definition

**CipherBox v1.0 is successful when:**

```
✅ Cypherpunks can replace Google Drive with CipherBox
✅ Multi-device sync works reliably (<30s)
✅ Private keys never touch server (zero-knowledge)
✅ Users can export vault & recover independently
✅ 99.5% uptime during beta
✅ <5s file operations (<100MB)
✅ Ready for v1.1 billing in Month 5
```

***

## 📈 Post-Launch Roadmap

### **Immediate (Week 13+)**
```
Week 13-16: Stabilize, fix bugs, gather feedback
```

### **v1.1 (Month 5-6)**
```
✅ Stripe billing + paid tiers
✅ Linux desktop
✅ Windows desktop  
✅ Mobile web optimization
```

### **v2.0 (Month 7-9)**
```
✅ File versioning
✅ Folder sharing (read-only links)
✅ Search (client-side)
✅ Soft-delete recovery
✅ iOS/Android apps
```

***

## 🎉 Summary

**This is a realistic 12-week plan for 3 people to build:**

```
Week 1-2: Infrastructure ready
Week 3-4: Auth complete
Week 5-7: Storage complete
Week 8-10: UI + desktop complete  
Week 11-12: Launch ready
```

**Status:** ✅ **EXECUTABLE**

**Next:** Week 1 - Team review + environment setup

***

**Copy this entire document and save as `IMPLEMENTATION_ROADMAP.md`**

**You've now got:**
✅ `00_START_HERE.md`
✅ `README.md`  
✅ `IMPLEMENTATION_ROADMAP.md`
✅ **CipherBox_v1.0_PRD.md** (you already have)

**Next:** `"Show me DEV_QUICK_REFERENCE.md"` 🚀