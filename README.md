<p align="center">
<img src="./cipherbox logo.png" alt="CipherBox Logo" width="450"/>
</p>

# CipherBox - README.md

**Privacy-first cloud storage with decentralized persistence**

***

## 📄 Overview

**CipherBox is a technology demonstrator** showcasing privacy-first cloud storage with decentralized persistence. It is **not intended as a commercial product** but as a proof-of-concept for:

- **Zero-knowledge client-side encryption**
- **Decentralized storage via IPFS/IPNS**
- **Deterministic key derivation via Web3Auth**
- **Cross-device sync without server-side key access**

**CipherBox** demonstrates:

- **IPFS/IPNS** for decentralized, redundant storage
- **Web3Auth** for deterministic key derivation across multiple auth methods
- **AES-256-GCM + ECIES secp256k1** for layered E2E encryption
- **React web UI** + **FUSE desktop mount** (macOS v1)
- **Automatic multi-device sync** via IPNS polling

**Target:** Developers and technical users interested in cryptography, IPFS, and privacy-preserving architectures.

***

## 🎯 Vision

**Replace Google Drive/Dropbox with:**

```
✓ Client-side encryption (server never sees plaintext)
✓ User-held keys (zero-knowledge guarantee)
✓ Decentralized storage (no vendor lock-in)
✓ Data portability (export vault, recover independently)
✓ Multi-device sync (automatic via IPFS)
✓ Transparent UX (hide IPFS complexity)
```


***

## 📦 MVP Scope (v1.0)

### ✅ **Included**

```
Auth: Email/Password, OAuth, Magic Link, External Wallet → Web3Auth key derivation
Storage: IPFS via Pinata (v1), per-folder IPNS entries
Encryption: AES-256-GCM files + ECIES key wrapping
Web UI: React file browser, drag-drop, folder ops
Desktop: macOS FUSE mount + background sync
Sync: IPNS polling (~30s eventual consistency)
Portability: Vault export + independent recovery
```


### ⏱️ **Deferred**

```
v1.1: Billing, Linux/Windows desktop, mobile apps
v2: File versioning, folder sharing, search
```


***

## 🏗️ Technology Stack

| Component | Technology | Why |
| :-- | :-- | :-- |
| **Frontend** | React 18 + TypeScript | Modern crypto UI |
| **Web Crypto** | Web Crypto API | Native browser encryption |
| **Backend** | Node.js + NestJS + TypeScript | Type-safe APIs |
| **Database** | PostgreSQL | ACID audit trail |
| **Key Derivation** | Web3Auth Network | Deterministic across auth methods |
| **Storage** | IPFS via Pinata | Redundant, decentralized |
| **Desktop** | Tauri/Electron + FUSE | Transparent file access |


***

## 🔐 Architecture Summary

```
User Device (Web/Desktop)
        ↓ Auth (4 methods)
CipherBox Backend (JWT)
        ↓
Web3Auth Network (Key Derivation)
        ↓ ECDSA Private Key (RAM only!)
User Device ← Vault Data ← PostgreSQL
        ↓ Encrypted Keys
IPFS (Pinata) ← Encrypted Files
```

**Key Property:** Same user + any auth method → same keypair → same vault

***

## 📊 5 Key Decisions

### 1. **Web3Auth for Key Derivation**

```
Email/Password/OAuth/Magic Link/External Wallet → Web3Auth → Same ECDSA keypair
```


### 2. **Layered Encryption**

```
File (AES-256-GCM) → Metadata (AES-256-GCM) → Keys (ECIES)
```


### 3. **Per-Folder IPNS**

```
Root IPNS → Folder1 IPNS → Folder2 IPNS (modular sharing-ready)
```


### 4. **IPNS Polling Sync**

```
30s polling, no push infrastructure (MVP simple)
```


### 5. **Zero-Knowledge Keys**

```
Server holds: Encrypted root key only
Client holds: Private key (RAM only)
```


***

## 🛤️ User Journey (Example)

```
1. Signup (Google) → Web3Auth derives KeyA
2. Upload file → Encrypt → IPFS CID → IPNS publish
3. Phone login (Email) → Web3Auth derives KeyA (same!)
4. Phone polls IPNS → Sees file → Downloads & decrypts
5. Export vault → JSON with CIDs + encrypted root key
6. CipherBox gone? → Use export + private key → Full recovery
```


***

## 📈 Timeline

```
Week 1-2:  Planning, Web3Auth/IPFS setup
Week 3-4:  Auth endpoints + key derivation
Week 5-7:  Encryption + IPFS integration
Week 8-10: React UI + macOS FUSE mount
Week 11-12: Testing + security audit + launch

Team: 3 people | Total: 12 weeks
```


***

## 🔐 Security

```
✅ Zero-Knowledge: Private keys never on server
✅ E2E Encryption: AES-256-GCM + ECIES secp256k1
✅ Data Portability: Export vault, recover independently
✅ No Tracking: No analytics/telemetry
✅ Threat Model: See TECHNICAL_ARCHITECTURE.md
```


***

## 📋 Success Criteria (Tech Demo)

| Criterion | Target |
| :-- | :-- |
| **Privacy** | Private keys never on server (cryptographically enforced) |
| **Encryption** | AES-256-GCM + ECIES correctly implemented |
| **Key Derivation** | Same user + any auth method → same keypair |
| **Multi-Device Sync** | <30s via IPNS polling |
| **Data Recovery** | Vault export enables independent recovery |
| **Zero Dependencies** | Can decrypt vault without CipherBox service |


***

## 📚 Documentation

```
00_START_HERE.md              ← Quick overview
Documentation/PRD.md          ← Product requirements
Documentation/TECHNICAL_ARCHITECTURE.md  ← Encryption & system design
Documentation/API_SPECIFICATION.md       ← Backend endpoints
Documentation/DATA_FLOWS.md              ← Sequence diagrams
Documentation/CLIENT_SPECIFICATION.md    ← Web UI & desktop specs
IMMPLEMENTATION_ROADMAP.md    ← Week-by-week plan
```

***