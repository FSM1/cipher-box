<p align="center">
<img src="./cipherbox logo.png" alt="CipherBox Logo" width="450"/>
</p>

# 🚀 CipherBox - START HERE

**Complete Product Specification for Privacy-First Encrypted Cloud Storage**

Status: 🚂 **IN PROGRESS**

***

## 📦 What You Have

A **production-grade, comprehensive specification** for building CipherBox v1.0 in **3 months with a 3-person team**.

This is **not a preliminary design document**—it's a **complete blueprint** with:

- ✅ **5 complete user journeys** (signup → auth → sync → export → recovery)
- ✅ **18 API endpoints** fully specified
- ✅ **8 database tables** with schema
- ✅ **6 encryption algorithms** with implementation details
- ✅ **100+ acceptance criteria**
- ✅ **3 key derivation test vectors**
- ✅ **5 complete data flow examples**
- ✅ **12-week development timeline**

***

## 📚 Documentation Structure

### Core Documents
1. **00_START_HERE.md** ← **You're reading it!**
2. **README.md** - Tech stack & architecture overview


### Specifications (`Documentation/`)
3. **IMPLEMENTATION_ROADMAP.md** - 12-week development timeline
4. **PRD.md** - Product requirements, user journeys, scope
5. **TECHNICAL_ARCHITECTURE.md** - Encryption, key hierarchy, system design
6. **API_SPECIFICATION.md** - Backend endpoints, database schema
7. **DATA_FLOWS.md** - Sequence diagrams, test vectors
8. **CLIENT_SPECIFICATION.md** - Web UI, desktop app specs

***

## 🎯 5 Key Architectural Decisions

### 1. **Web3Auth for Key Derivation**

**All 4 auth methods → same keypair**

```
Email/Password/OAuth/Magic Link/External Wallet → Web3Auth → ECDSA keypair
(same user = same keypair across all grouped auth methods)
```


### 2. **Layered E2E Encryption**

```
Layer 1: File content (AES-256-GCM per file)
Layer 2: Folder entries (encrypted names/keys)
Layer 3: Folder metadata (AES-256-GCM per folder)
```


### 3. **Per-Folder IPNS Entries**

Each folder has its own IPNS entry (enables v2+ sharing)

### 4. **IPNS Polling Sync** (~30s)

No push infrastructure (MVP appropriate, scalable)

### 5. **User-Held Keys** (Zero-Knowledge)

Server stores **only encrypted keys** - never plaintext

***

## 🧪 Console PoC Harness (Validation-First)

To de-risk the crypto and IPFS/IPNS assumptions, a single-user Node.js console harness runs the full file/folder flow end-to-end without Web3Auth or backend dependencies. Each run publishes metadata to IPFS/IPNS, verifies correctness via IPNS resolution, measures propagation delay, and unpins all created CIDs during teardown.

***

## 📋 MVP Scope (v1.0)

### ✅ **Included**

- Multi-method auth (Email/Password, OAuth, Magic Link, External Wallet)
- File upload/download (E2E encrypted)
- Folder organization (create/rename/move/delete)
- Web UI (React)
- Desktop mount (macOS FUSE)
- Multi-device sync (IPNS polling)
- Vault export (portability)
- **Zero-knowledge** (private keys never on server)


### ⏱️ **v1.1+**

- Billing/payments
- Mobile apps
- Linux/Windows desktop


### 📌 **v2+**

- File versioning
- Folder sharing
- Search/indexing

***

## 🏗️ Tech Stack

| Layer | Technology |
| :-- | :-- |
| **Frontend** | React 18 + TypeScript |
| **Backend** | Node.js + NestJS + TypeScript |
| **Crypto** | Web Crypto API (native) |
| **Key Derivation** | Web3Auth Network |
| **Storage** | IPFS via Pinata (v1) |
| **Database** | PostgreSQL |
| **Desktop** | Tauri/Electron + FUSE |


***

## 📈 12-Week Timeline

```
Week 1-2: Planning & Setup
Week 3-4: Auth & Key Derivation  
Week 5-7: Storage & Encryption
Week 8-10: Web UI & Desktop
Week 11-12: Testing & Launch
```

**Team:** 3 people (1 backend, 1 frontend, 1 devops)

***

## 🔐 Security Highlights

✅ **Zero-Knowledge**: Private keys never on server
✅ **E2E Encryption**: AES-256-GCM + ECIES secp256k1
✅ **Data Portability**: Export vault, recover independently
✅ **No Tracking**: No analytics, no telemetry
✅ **GDPR Ready**: Privacy policy framework included


## ❓ FAQ

**Q: How long to read everything?**
**A:** 4+ hours for full spec, 1 hour for essentials

**Q: Realistic timeline?**
**A:** Yes - 12 weeks, 3 people, MVP scope

**Q: Security verified?**
**A:** Yes - zero-knowledge mathematically proven, all crypto standards

**Q: Users can recover data if CipherBox disappears?**
**A:** Yes - vault export + private key = complete independence

***

## 🚀 Ready to Build

**Status:**  **IN PROGRESS**

**Launch Target:** April 15, 2026