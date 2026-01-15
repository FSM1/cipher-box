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
✅ Torus Network sandbox setup
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
✅ Torus key derivation tested (same JWT → same keypair)
✅ IPFS/Pinata integration verified
✅ Crypto test vectors pass (AES-256-GCM, ECIES)
✅ PostgreSQL schema deployed (8 tables)
✅ API contract stub (18 endpoints)
✅ Docker containers working
```

**Team:** Backend (80%), DevOps (80%), Frontend (40%)

***

### **Week 3: Backend Auth (Email/Password)**

**Goal:** Email/password auth + JWT generation

**Deliverables:**

```
✅ POST /auth/register
✅ POST /auth/login  
✅ Argon2 password hashing
✅ JWT with subjectId = hash(userId)
✅ Database: users, auth_providers tables
✅ Session middleware (JWT validation)
```

**Tests:** Signup → login → consistent userId

**Team:** Backend (100%)

***

### **Week 4: Auth Completion (Passkeys + OAuth)**

**Goal:** All 4 auth methods working

**Deliverables:**

```
✅ Passkeys: WebAuthn challenge/register/login
✅ OAuth: Google/Apple/GitHub redirects
✅ Magic Link: Email token flow
✅ Torus integration: JWT → keypair derivation
✅ Account linking: Multiple methods → same vault
✅ GET /my-vault (vault init check)
```

**Tests:** Cross-method consistency (Google → email → same keypair)

**Team:** Backend (80%), Frontend (60%)

***

### **Week 5: File Encryption + Upload**

**Goal:** Client-side encryption + IPFS upload

**Deliverables:**

```
✅ Client: Random file key + AES-256-GCM encryption
✅ Client: ECIES key wrapping (fileKey → userPubkey)
✅ POST /vault/upload → Pinata → CID
✅ Database: volume_audit (quota tracking)
✅ 500 MiB free tier quota enforcement
```

**Tests:** Encrypt → upload → download → decrypt matches original

**Team:** Frontend (100%), Backend (80%)

***

### **Week 6: IPNS Publishing + Folders**

**Goal:** Folder hierarchy + IPNS updates

**Deliverables:**

```
✅ Per-folder IPNS entries (root → Documents → Work)
✅ Client signs metadata: ECDSA(SHA256(encrypted_metadata))
✅ POST /vault/publish-ipns → ipfs name publish
✅ Folder create → metadata → IPNS publish
✅ Tree traversal (resolve IPNS → fetch → decrypt → recurse)
```

**Tests:** Create folder → IPNS resolves → metadata decrypts correctly

**Team:** Backend (70%), Frontend (100%)

***

### **Week 7: File Operations (Rename/Move/Delete)**

**Goal:** Complete CRUD operations

**Deliverables:**

```
✅ Rename file: Update metadata → republish IPNS
✅ Move: Remove source → add destination → dual IPNS publish
✅ Delete: Remove metadata entry → republish
✅ Bulk operations (multi-select upload/delete)
✅ Download flow: IPNS resolve → IPFS fetch → decrypt
```

**Tests:** Rename/move/delete → metadata updates → other devices see changes

**Team:** Frontend (100%), Backend (50%)

***

### **Week 8: Web UI (React File Browser)**

**Goal:** Production React UI

**Deliverables:**

```
✅ Login page (4 auth methods)
✅ Vault page: Sidebar tree + main file list
✅ Drag-drop upload zone
✅ Context menus (right-click: rename/delete/move)
✅ Settings: Linked accounts, passkeys, export
✅ Storage indicator (500 MiB free tier)
✅ Responsive design (mobile/tablet/desktop)
```

**Tech:** React 18 + TypeScript + Tailwind

**Team:** Frontend (100%)

***

### **Week 9: Desktop App - macOS FUSE Mount**

**Goal:** Transparent filesystem mount

**Deliverables:**

```
✅ Login window (same auth as web)
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
✅ IPNS publishing reliable
✅ Folder hierarchy working
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
| **Backend** | 100% | 70% | 60% | 90% | **360h** |
| **Frontend** | 50% | 100% | 50% | 80% | **240h** |
| **DevOps** | 40% | 40% | 80% | 100% | **200h** |


***

## ⚠️ Risks \& Mitigation

| Risk | Probability | Mitigation |
| :-- | :-- | :-- |
| Torus integration | Medium | Week 1 deep-dive, direct support |
| IPFS performance | Medium | Pinata + caching strategy |
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

**NO-GO:** Torus issues → Week 1 fallback plan

### **Week 7: "Storage Done"** ✅
```
[ ] File upload/download complete
[ ] IPNS publishing reliable
[ ] Folder hierarchy functional
[ ] Multi-file operations working
```

**NO-GO:** IPFS latency → Caching + gateway switch

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
| Torus integration fails | High | Medium | Week 1 deep-dive + fallback derivation |
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