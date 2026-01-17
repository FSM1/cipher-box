---
version: 1.7.0
last_updated: 2026-01-16
status: Active
ai_context: Product requirements for CipherBox. Tech demonstrator - not commercial. See TECHNICAL_ARCHITECTURE.md for implementation details, API_SPECIFICATION.md for backend contract, DATA_FLOWS.md for sequences.
---

# CipherBox - Product Requirements Document

**Product Name:** CipherBox  
**Type:** Technology Demonstrator  
**Status:** Specification Document  
**Created:** January 14, 2026  
**Last Updated:** January 16, 2026  

---

## Table of Contents

1. [Overview & Vision](#1-overview--vision)
2. [User Personas](#2-user-personas)
3. [User Journeys](#3-user-journeys)
4. [Scope](#4-scope)
5. [Success Criteria](#5-success-criteria)
6. [Roadmap](#6-roadmap)
7. [Glossary](#7-glossary)
8. [FAQ](#8-faq)

---

## Terminology

| Term | Code/API | Prose | Notes |
|------|----------|-------|-------|
| Root folder encryption key | `rootFolderKey` | root folder key | AES-256 symmetric key |
| User's ECDSA public key | `publicKey` | public key | secp256k1 curve |
| User's ECDSA private key | `privateKey` | private key | Never stored/transmitted |
| IPNS identifier | `ipnsName` | IPNS name | e.g., k51qzi5uqu5dlvj55... |
| IPNS signed data structure | `ipnsRecord` | IPNS record | Contains encrypted metadata |
| Folder encryption key | `folderKey` | folder key | Per-folder AES-256 key |
| File encryption key | `fileKey` | file key | Per-file AES-256 key |
| IPNS signing key | `ipnsPrivateKey` | IPNS private key | Ed25519, stored encrypted |

---

## 1. Overview & Vision

### 1.1 Purpose

**CipherBox is a technology demonstrator** showcasing privacy-first cloud storage with decentralized persistence. It is not intended as a commercial product but as a proof-of-concept for:

- Zero-knowledge client-side encryption
- Decentralized storage via IPFS/IPNS
- Deterministic key derivation via Web3Auth
- Cross-device sync without server-side key access

### 1.2 Problem Statement

Existing cloud storage providers (Google Drive, Dropbox, OneDrive) create fundamental privacy risks:

- **Centralized Control:** Single company controls all user files and metadata
- **Privacy Risk:** Servers hold plaintext or can derive insights from metadata
- **Data Hostage:** Users cannot easily migrate data or guarantee independence
- **Zero Transparency:** Users lack cryptographic guarantees about data access

### 1.3 Vision

CipherBox delivers **privacy-first cloud storage with decentralized persistence and zero-knowledge guarantees**.

Core pillars:
- **Client-side encryption:** Files encrypted before leaving device
- **User-held keys:** Cryptographic keys generated and held client-side only
- **Decentralized storage:** Files stored on IPFS (peer-to-peer, immutable)
- **Transparent access:** Web UI and desktop mount hide IPFS complexity
- **Data portability:** Users can export vault and decrypt independently

### 1.4 Target Audience

**Primary:** Developers and technical users interested in cryptography, IPFS, and privacy-preserving architectures.

**Characteristics:**
- Technical background (understands encryption concepts, distributed systems)
- Interest in novel cryptographic applications
- Values privacy guarantees and decentralization
- Comfortable with command-line tools and technical documentation

---

## 2. User Personas

### 2.1 Primary Persona: Privacy-Conscious Developer

**Profile:**
- Age: 28-45, works in tech/security/finance
- Technical comfort: High (understands cryptography, IPFS, distributed systems)
- Interest: Exploring zero-knowledge architectures and decentralized storage
- Platforms: Primarily macOS/Linux, secondary web access

**Needs:**
- Cryptographically verifiable privacy (not just "trust us")
- Multi-device access without sync issues
- Clear understanding of what server can/cannot see
- Ability to verify and audit the encryption implementation

---

## 3. User Journeys

### Journey 1: Signup & First Upload

1. User visits CipherBox and clicks "Sign In"
2. User completes authentication via Web3Auth (Google, email, or wallet)
3. User sees empty vault with drag-drop upload zone
4. User drags a file into the vault
5. File appears in the list with encrypted indicator
6. User can download the file and verify contents match

### Journey 2: Multi-Device Access

1. User has uploaded files via web app on laptop
2. User opens CipherBox on phone browser
3. User logs in with same auth method (or linked method)
4. User sees all files from laptop automatically
5. User downloads a file and verifies it decrypts correctly

### Journey 3: Desktop Mount

1. User installs CipherBox desktop app
2. User logs in via Web3Auth
3. FUSE mount appears at ~/CipherVault
4. User opens Finder/Explorer, sees folder tree with readable names
5. User opens a file directly in native application (PDF in Preview, etc.)
6. User saves changes, other devices see update within 30 seconds

### Journey 4: Vault Export & Recovery

1. User navigates to Settings → Export Vault
2. User downloads vault export JSON file
3. User stores export securely (external drive, password manager)
4. Later: User can recover vault using export + private key
5. Recovery works even if CipherBox service is unavailable

### Journey 5: Account Linking

1. User signed up with Google OAuth
2. User adds email/password as backup auth method via Settings
3. User can now log in with either method
4. Both methods access the same vault (same encryption keys)

---

## 4. Scope

### 4.1 In Scope (v1.0)

| Feature | Description |
|---------|-------------|
| Multi-method auth | Email/Password, OAuth (Google/Apple/GitHub), Magic Link, External Wallet via Web3Auth |
| File operations | Upload, download, rename, move, delete |
| Folder operations | Create, rename, move, delete |
| Web UI | React-based file browser with drag-drop |
| Desktop mount | macOS FUSE mount at ~/CipherVault |
| Multi-device sync | IPNS polling (~30s latency) |
| E2E encryption | AES-256-GCM for files, ECIES for key wrapping |
| Data portability | Vault export for independent recovery |

### 4.2 Out of Scope (v1.0)

| Feature | Deferred To | Rationale |
|---------|-------------|-----------|
| Billing/payments | v1.1 | Tech demo focus |
| File versioning | v2.0 | Complexity |
| File/folder sharing | v2.0 | Requires key sharing infrastructure |
| Mobile apps | v2.0 | Platform expansion |
| Search/indexing | v2.0 | Client-side search complexity |
| Collaborative editing | v3.0 | Real-time sync complexity |
| Team accounts | v3.0 | Permission management |

### 4.3 Constraints

| Constraint | Value | Rationale |
|------------|-------|-----------|
| Max file size | 100 MB | Browser memory limits |
| Max storage (free tier) | 500 MiB | Pinata cost management |
| Max files per folder | 1,000 | UI performance |
| Max folder depth | 20 levels | Traversal performance |
| Sync latency | ~30 seconds | IPNS polling interval |

---

## 5. Success Criteria

### 5.1 Functional Criteria

| ID | Criterion | Validation |
|----|-----------|------------|
| F1 | User can sign up with any of 4 auth methods | Manual test all methods |
| F2 | User can upload and download files with correct content | Integration test |
| F3 | Files sync across devices within 30 seconds | Multi-device test |
| F4 | Vault export enables independent recovery | Recovery test without backend |
| F5 | Desktop FUSE mount shows decrypted file names | macOS integration test |

### 5.2 Security Criteria

See [TECHNICAL_ARCHITECTURE.md](./TECHNICAL_ARCHITECTURE.md#acceptance-criteria) for detailed security acceptance criteria.

### 5.3 Performance Criteria

| ID | Criterion | Target | Test Method |
|----|-----------|--------|-------------|
| P1 | Auth flow completion | <3s (P95) | Load test |
| P2 | File upload (<100MB) | <5s (P95) | Integration test |
| P3 | File download (<100MB) | <5s (P95) | Integration test |
| P4 | IPNS resolution (cached) | <200ms | Integration test |
| P5 | FUSE mount startup | <3s | Manual test |

---

## 6. Roadmap

### v1.0 (Q1 2026 - 3 Month MVP)

**Focus:** Core encryption, storage, and sync functionality

- Multi-method auth via Web3Auth
- File upload/download with E2E encryption
- Folder organization
- Web UI (React)
- Desktop mount (macOS)
- Multi-device sync via IPNS
- Vault export

### v1.1 (Q1-Q2 2026)

**Focus:** Polish and infrastructure

- Billing integration (if commercializing)
- Performance optimization
- Security audit
- Linux/Windows desktop apps

### v2.0 (Q2-Q3 2026)

**Focus:** Features

- File versioning
- Read-only folder sharing
- Client-side search
- Mobile apps (iOS/Android)

### v3.0 (Q4 2026)

**Focus:** Collaboration

- Collaborative folders
- Team accounts
- Granular permissions

---

## 7. Glossary

| Term | Definition |
|------|------------|
| **AES-256-GCM** | Symmetric encryption algorithm with authentication. Used for file and metadata encryption. |
| **CID** | Content Identifier. Hash of content on IPFS, used as immutable reference. |
| **E2E Encryption** | End-to-end encryption. Data encrypted on client, server never holds plaintext. |
| **ECDSA** | Elliptic Curve Digital Signature Algorithm. Used for signing and identity. |
| **ECIES** | Elliptic Curve Integrated Encryption Scheme. Used for asymmetric key wrapping. |
| **FUSE** | Filesystem in Userspace. Enables mounting encrypted vault as local folder. |
| **IPFS** | InterPlanetary File System. Peer-to-peer, content-addressed storage network. |
| **IPNS** | IPFS Name System. Mutable pointers to immutable IPFS content. |
| **Web3Auth** | Distributed key derivation service. Derives deterministic ECDSA keypairs from various auth methods. |
| **Zero-Knowledge** | Architecture where server has no knowledge of user data or encryption keys. |

---

## 8. FAQ

### General

**Q: Is CipherBox a commercial product?**

A: No. CipherBox is a technology demonstrator showcasing zero-knowledge encrypted storage with IPFS. It demonstrates novel applications of cryptography and decentralized systems.

**Q: If the server is compromised, is my data safe?**

A: Yes. The server holds only encrypted data. Your encryption keys are generated by Web3Auth and held only in your device's memory. Even with full server access, an attacker cannot decrypt your files.

**Q: Can CipherBox employees see my files?**

A: No. CipherBox never has your encryption keys or plaintext files. This is enforced by cryptography, not policy.

### Authentication

**Q: How does account linking work?**

A: Web3Auth's group connections ensure the same ECDSA keypair is derived regardless of which linked auth method you use. Sign up with Google, add email/password later, and both access the same vault.

**Q: What if I forget my password?**

A: Use another linked auth method (Google, etc.) to recover access. Web3Auth derives the same keypair from any linked method. This is why linking multiple auth methods is recommended.

**Q: What if I lose access to all auth methods?**

A: If you have a vault export and your Web3Auth private key backup, you can recover independently. Without these, recovery is not possible—this is the security/convenience tradeoff of zero-knowledge architecture.

### Technical

**Q: Why IPFS instead of S3?**

A: IPFS provides redundancy (data on multiple nodes), no vendor lock-in (data exists independently of CipherBox), and immutability (content integrity via CIDs). It aligns with the decentralization goals of this demonstrator.

**Q: What if Web3Auth becomes unavailable?**

A: Users can export their Web3Auth private key and vault data. A future version could implement direct key import, bypassing Web3Auth entirely for recovery scenarios.

---

## Related Documents

- [TECHNICAL_ARCHITECTURE.md](./TECHNICAL_ARCHITECTURE.md) - System design, encryption, key hierarchy
- [API_SPECIFICATION.md](./API_SPECIFICATION.md) - Backend endpoints and database schema
- [DATA_FLOWS.md](./DATA_FLOWS.md) - Sequence diagrams and test vectors
- [CLIENT_SPECIFICATION.md](./CLIENT_SPECIFICATION.md) - Web UI and desktop app specifications

---

**End of PRD**
