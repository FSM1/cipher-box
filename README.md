<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# CipherBox v1.0 - README.md

**Privacy-first cloud storage with decentralized persistence**

***

## 📄 Overview

**CipherBox** delivers **zero-knowledge cloud storage** using:

- **IPFS/IPNS** for decentralized, redundant storage
- **Torus Network** for deterministic key derivation across 4 auth methods
- **AES-256-GCM + ECIES secp256k1** for layered E2E encryption
- **React web UI** + **FUSE desktop mount** (macOS v1)
- **Automatic multi-device sync** via IPNS polling

**Target:** Cypherpunks \& crypto enthusiasts demanding cryptographic privacy guarantees.

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
Auth: Email/Password, Passkeys, OAuth, Magic Link → Torus key derivation
Storage: IPFS via Pinata (v1), per-folder IPNS entries
Encryption: AES-256-GCM files + ECIES key wrapping
Web UI: React file browser, drag-drop, folder ops
Desktop: macOS FUSE mount + background sync
Sync: IPNS polling (~30s eventual consistency)
Freemium: 500 MiB free tier
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
| **Key Derivation** | Torus Network | Deterministic across auth methods |
| **Storage** | IPFS via Pinata | Redundant, decentralized |
| **Desktop** | Tauri/Electron + FUSE | Transparent file access |
| **Auth** | WebAuthn + OAuth 2.0 | Phishing-resistant |


***

## 🔐 Architecture Summary

```
User Device (Web/Desktop)
        ↓ Auth (4 methods)
CipherBox Backend (JWT)
        ↓
Torus Network (Key Derivation)
        ↓ ECDSA Private Key (RAM only!)
User Device ← Vault Data ← PostgreSQL
        ↓ Encrypted Keys
IPFS (Pinata) ← Encrypted Files
```

**Key Property:** Same user + any auth method → same keypair → same vault

***

## 📊 5 Key Decisions

### 1. **Torus for Key Derivation**

```
Email/Passkey/OAuth → Backend JWT → Torus → Same ECDSA keypair
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
1. Signup (Google) → Torus derives KeyA
2. Upload file → Encrypt → IPFS CID → IPNS publish
3. Phone login (Email) → Torus derives KeyA (same!)
4. Phone polls IPNS → Sees file → Downloads & decrypts
5. Export vault → JSON with CIDs + encrypted root key
6. CipherBox gone? → Use export + private key → Full recovery
```


***

## 📈 Timeline

```
Week 1-2:  Planning, Torus/IPFS setup
Week 3-4:  Auth endpoints + key derivation
Week 5-7:  Encryption + IPFS integration
Week 8-10: React UI + macOS FUSE mount
Week 11-12: Testing + security audit + launch

Team: 3 people | Total: 12 weeks
Launch: April 15, 2026
```


***

## 🔐 Security

```
✅ Zero-Knowledge: Private keys never on server
✅ E2E Encryption: AES-256-GCM + ECIES secp256k1
✅ Data Portability: Export vault, recover independently
✅ No Tracking: No analytics/telemetry
✅ Threat Model: Documented in PRD Section 8.2
```


***

## 📋 Success Metrics (v1 Launch)

| Metric | Target |
| :-- | :-- |
| **Privacy** | Private keys never on server |
| **Auth** | <3s login (all methods) |
| **Upload** | <5s (<100MB files) |
| **Sync** | <30s multi-device |
| **Uptime** | 99.5% |
| **Scale** | 100k+ files, 100GB+ vaults |


***

## 📚 Other Documents

```
CipherBox_v1.0_PRD.md         ← Full spec (15k words)
IMPLEMENTATION_ROADMAP.md     ← Week-by-week plan
```

***

## 🚀 Next Steps

1. **✅ Save this README.md**
2. **Ask:** `"Show me CipherBox_v1.0_PRD.md"` (main spec)
3. **Ask:** `"Show me IMPLEMENTATION_ROADMAP.md"` (timeline)
4. **Share with team**
5. **Start Week 1 planning**

***