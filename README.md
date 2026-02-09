<p align="center">
  <img src="./cipherbox logo.png" alt="CipherBox Logo" width="450"/>
</p>

# CipherBox - README.md

## Privacy-first cloud storage with decentralized persistence

---

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
- **TEE-based IPNS republishing** via Phala Cloud / AWS Nitro (zero-knowledge)

---

## Acknowledgements

This project is inspired by discussions and planning while working on [ChainSafe Files](https://github.com/chainsafe/ui-monorepo). A massive shout-out to all the colleagues I got to work with on the original ChainSafe Files project, who unknowingly contributed to this phoenix rising out of the ashes.

---

## 🎯 Vision

**Replace Google Drive/Dropbox with:**

```text
✓ Client-side encryption (server never sees plaintext)
✓ User-held keys (zero-knowledge guarantee)
✓ Decentralized storage (no vendor lock-in)
✓ Data portability (export vault, recover independently)
✓ Multi-device sync (automatic via IPFS)
✓ Transparent UX (hide IPFS complexity)
```

---

## 📦 MVP Scope (v1.0)

### ✅ **Included**

```text
Auth: Email/Password, OAuth, Magic Link, External Wallet → Web3Auth key derivation
Storage: IPFS via Pinata (v1), per-folder IPNS entries
Encryption: AES-256-GCM files + ECIES key wrapping
Web UI: React file browser, drag-drop, folder ops
Desktop: macOS FUSE mount + background sync
Sync: IPNS polling (~30s eventual consistency)
TEE Republishing: Phala Cloud (primary) / AWS Nitro (fallback), every 3h
Portability: Vault export + independent recovery
```

### ⏱️ **Deferred**

```text
v1.1: Billing, Linux/Windows desktop, mobile apps
v2: File versioning, folder sharing, search
```

---

## 🏗️ Technology Stack

| Component          | Technology                    | Why                               |
| :----------------- | :---------------------------- | :-------------------------------- |
| **Frontend**       | React 18 + TypeScript         | Modern crypto UI                  |
| **Web Crypto**     | Web Crypto API                | Native browser encryption         |
| **Backend**        | Node.js + NestJS + TypeScript | Type-safe APIs                    |
| **Database**       | PostgreSQL                    | ACID audit trail                  |
| **Key Derivation** | Web3Auth Network              | Deterministic across auth methods |
| **Storage**        | IPFS via Pinata               | Redundant, decentralized          |
| **Desktop**        | Tauri/Electron + FUSE         | Transparent file access           |
| **TEE**            | Phala Cloud / AWS Nitro       | Zero-knowledge IPNS republishing  |

---

## 🔐 Architecture Summary

```text
User Device (Web/Desktop)
        ↓ Auth (4 methods)
CipherBox Backend (JWT)
        ↓
Web3Auth Network (Key Derivation)
        ↓ ECDSA Private Key (RAM only!)
User Device ← Vault Data ← PostgreSQL
        ↓ Encrypted Keys
IPFS (Pinata) ← Encrypted Files
        ↑
TEE (Phala/Nitro) ← IPNS Republish (every 3h)
```

**Key Properties:**

- Same user + any auth method → same keypair → same vault
- TEE republishes IPNS records even when all devices are offline

---

## 📊 6 Key Decisions

### 1. **Web3Auth for Key Derivation**

```text
Email/Password/OAuth/Magic Link/External Wallet → Web3Auth → Same ECDSA keypair
```

### 2. **Layered Encryption**

```text
File (AES-256-GCM) → Metadata (AES-256-GCM) → Keys (ECIES)
```

### 3. **Per-Folder IPNS**

```text
Root IPNS → Folder1 IPNS → Folder2 IPNS (modular sharing-ready)
```

### 4. **IPNS Polling Sync**

```text
30s polling, no push infrastructure (MVP simple)
```

### 5. **Zero-Knowledge Keys**

```text
Server holds: Encrypted root key only
Client holds: Private key (RAM only)
```

### 6. **TEE-Based IPNS Republishing**

```text
IPNS records expire after ~24h → TEE republishes every 3h
Client encrypts ipnsPrivateKey with TEE public key (ECIES)
TEE decrypts in hardware, signs, zeroes key immediately
Providers: Phala Cloud (primary) / AWS Nitro (fallback)
```

---

## 🛤️ User Journey (Example)

```text
1. Signup (Google) → Web3Auth derives KeyA
2. Upload file → Encrypt → IPFS CID → IPNS publish
3. Phone login (Email) → Web3Auth derives KeyA (same!)
4. Phone polls IPNS → Sees file → Downloads & decrypts
5. Export vault → JSON with CIDs + encrypted root key
6. CipherBox gone? → Use export + private key → Full recovery
```

---

## 🔐 Security

```text
✅ Zero-Knowledge: Private keys never on server
✅ E2E Encryption: AES-256-GCM + ECIES secp256k1
✅ TEE Republishing: IPNS keys decrypted only in hardware enclaves
✅ Data Portability: Export vault, recover independently
✅ No Tracking: No analytics/telemetry
✅ Threat Model: See TECHNICAL_ARCHITECTURE.md
```

---

## 📋 Success Criteria (Tech Demo)

| Criterion             | Target                                                    |
| :-------------------- | :-------------------------------------------------------- |
| **Privacy**           | Private keys never on server (cryptographically enforced) |
| **Encryption**        | AES-256-GCM + ECIES correctly implemented                 |
| **Key Derivation**    | Same user + any auth method → same keypair                |
| **Multi-Device Sync** | <30s via IPNS polling                                     |
| **Data Recovery**     | Vault export enables independent recovery                 |
| **Zero Dependencies** | Can decrypt vault without CipherBox service               |

---

## 📚 Documentation

```text
00_START_HERE.md                                                ← Quick overview
00-Preliminary-R&D/Documentation/PRD.md                         ← Product requirements
00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md      ← Encryption & system design
00-Preliminary-R&D/Documentation/API_SPECIFICATION.md           ← Backend endpoints
00-Preliminary-R&D/Documentation/DATA_FLOWS.md                  ← Sequence diagrams
00-Preliminary-R&D/Documentation/CLIENT_SPECIFICATION.md        ← Web UI & desktop specs
```

---
