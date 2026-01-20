# Feature Landscape: Encrypted Cloud Storage

**Domain:** Privacy-first encrypted cloud storage
**Researched:** 2026-01-20
**Competitors Analyzed:** Tresorit, Boxcryptor, Cryptomator, ProtonDrive, Sync.com, NordLocker, Internxt, Filen

---

## Executive Summary

CipherBox v1.0 scope covers core table stakes for a technology demonstrator but has notable gaps versus commercial encrypted storage products. The most significant missing feature that users expect is **file sharing**--even basic link-based sharing. The architectural decision to defer sharing to v2.0 is reasonable for a tech demo but would be a blocker for any commercial positioning.

**Key Finding:** CipherBox's differentiators (IPFS/IPNS decentralization, TEE-based IPNS republishing, zero-knowledge via Web3Auth) are technically compelling but represent infrastructure differentiation, not user-facing differentiation. Users will judge the product on UX parity with competitors before appreciating cryptographic novelty.

---

## Table Stakes

Features users expect as baseline. Missing = product feels incomplete or broken.

| Feature | Why Expected | Complexity | CipherBox v1.0 | Gap Analysis |
|---------|--------------|------------|----------------|--------------|
| **E2E Encryption (AES-256)** | Core value proposition | Medium | IN SCOPE | Covered |
| **Zero-Knowledge Architecture** | Privacy claim requires it | High | IN SCOPE | Covered |
| **Multi-Platform Access** | Users have multiple devices | Medium | PARTIAL | Web + macOS only; Linux/Windows desktop deferred to v1.1 |
| **Web Browser Access** | Convenience, no install needed | Medium | IN SCOPE | Covered |
| **File Upload/Download** | Core functionality | Low | IN SCOPE | Covered |
| **Folder Organization** | Basic file management | Low | IN SCOPE | Covered |
| **Drag-and-Drop Upload** | Modern UX expectation | Low | IN SCOPE | Covered |
| **Multi-Device Sync** | "Cloud" implies multi-device | High | IN SCOPE | 30s latency acceptable for v1 |
| **Two-Factor Authentication** | Security baseline | Low | PARTIAL | Web3Auth handles auth; no explicit 2FA toggle in scope |
| **Desktop Sync App** | Power user expectation | High | IN SCOPE | macOS FUSE mount; others deferred |
| **Mobile Access** | 60%+ of users primarily mobile | High | OUT OF SCOPE | Critical gap for commercial product |
| **Basic File Sharing (Links)** | Fundamental collaboration need | Medium | OUT OF SCOPE | Gap: competitors all have this |
| **Password-Protected Links** | Sharing security | Low | OUT OF SCOPE | Dependent on file sharing |
| **File Preview** | UX convenience | Medium | OUT OF SCOPE | Gap: even basic image/PDF preview expected |
| **Search** | Finding files in large vaults | Medium | OUT OF SCOPE | Gap: acceptable for small vaults only |
| **Recycle Bin / Soft Delete** | Error recovery | Low | UNCLEAR | Not mentioned in specs |
| **Storage Quota Display** | User awareness | Low | IN SCOPE | Shown in web UI |

### Critical Table Stakes Gaps

1. **Mobile Apps (iOS/Android):** ProtonDrive, Tresorit, Sync.com all have full mobile apps with offline access. CipherBox's web-only mobile access is subpar.

2. **File Sharing:** Every competitor offers at least basic link sharing. Tresorit has encrypted sharing with recipient verification. ProtonDrive has password-protected links. Cryptomator loses sharing (tradeoff). CipherBox v1.0 has no sharing--this is the largest gap.

3. **File Preview:** Users expect to preview images, PDFs, and documents without downloading. ProtonDrive and Tresorit both offer in-browser preview. This is missing from CipherBox scope.

4. **Offline Access:** Desktop competitors all cache files for offline viewing. CipherBox desktop spec mentions caching but offline write queue is listed as "outstanding question."

---

## Differentiators

Features that set product apart. Not expected, but valued when present.

| Feature | Value Proposition | Complexity | CipherBox v1.0 | Notes |
|---------|-------------------|------------|----------------|-------|
| **IPFS/IPNS Decentralized Storage** | No vendor lock-in, data independence | High | IN SCOPE | Unique among competitors |
| **TEE-Based IPNS Republishing** | Vault accessible even when offline for days | High | IN SCOPE | Novel architecture; no competitor has this |
| **Deterministic Key Derivation (Web3Auth)** | Same keys from any linked auth method | High | IN SCOPE | Better than competitors' key backup approaches |
| **Vault Export for Independent Recovery** | True data portability | Medium | IN SCOPE | Stronger than most competitors |
| **Virtual Drive (FUSE Mount)** | Native file system integration | High | IN SCOPE | Tresorit has "Tresorit Drive"; matches competition |
| **Account Linking (Multiple Auth Methods)** | Flexibility in authentication | Medium | IN SCOPE | Better than single-method competitors |
| **File Versioning** | Recover previous versions | Medium | OUT OF SCOPE | Tresorit has unlimited; ProtonDrive has it; deferred to v2 |
| **Photo Albums** | Photo-specific organization | Medium | OUT OF SCOPE | ProtonDrive launched Albums in 2025 |
| **Encrypted Notes/Docs** | Beyond file storage | High | OUT OF SCOPE | ProtonDrive has Proton Sheets |
| **Quantum-Resistant Encryption** | Future-proofing | High | OUT OF SCOPE | Cryptomator and Internxt adding this |
| **Admin Dashboard / User Management** | Team/business features | High | OUT OF SCOPE | Tresorit strength |
| **Email Encryption Integration** | Workflow integration | Medium | OUT OF SCOPE | Tresorit/ProtonMail strength |
| **Selective Sync** | Control what downloads to device | Medium | PARTIAL | Desktop spec mentions it; implementation unclear |
| **On-Demand Sync** | Files in cloud until accessed | Medium | PARTIAL | Tresorit Drive 2.0 and Proton Drive have this |

### CipherBox's Unique Differentiators

1. **IPFS/IPNS Architecture:** No other consumer-grade encrypted storage uses IPFS. This is genuinely novel but also a double-edged sword (IPNS propagation delays, gateway reliability).

2. **TEE Republishing:** Solving the "24-hour IPNS expiry" problem with trusted execution environments is architecturally sophisticated. Competitors don't face this problem because they use traditional infrastructure.

3. **Web3Auth Key Derivation:** Deterministic keys from multiple auth providers is cleaner than Tresorit's key backup or ProtonDrive's recovery phrase approach.

4. **True Data Portability:** Vault export that works independently of CipherBox servers is stronger than competitors' export features.

---

## Anti-Features

Features to explicitly NOT build. Common mistakes in this domain.

| Anti-Feature | Why Avoid | What to Do Instead |
|--------------|-----------|-------------------|
| **Server-Side Encryption Keys** | Defeats zero-knowledge promise | Client-side only, as specified |
| **Password-Only Key Derivation** | Single point of failure, rainbow attacks | Web3Auth with account linking |
| **Unencrypted Metadata on Server** | Metadata reveals file structure | Encrypt all metadata client-side (CipherBox does this) |
| **Browser LocalStorage for Keys** | XSS exposure | RAM only, clear on logout |
| **Server-Managed File Sharing** | Server sees shared file contents | Defer to proper key-sharing infrastructure in v2 |
| **Search Without E2E Index** | Server sees search terms | Client-side indexing or don't implement |
| **"Secure" Folder Inside Regular Storage** | Confusing hybrid model | Full vault encryption (CipherBox approach correct) |
| **Sync Indicator Without Conflict Resolution** | Users lose data | Clear conflict handling UX |
| **Auto-Unpin on Server** | Data loss without user consent | Require explicit delete action |
| **Storing Refresh Tokens Unencrypted** | Token theft enables account access | OS keychain, as specified |

### Patterns Competitors Got Wrong (Learn From)

1. **Boxcryptor's Provider Lock-In:** Boxcryptor was tied to a single cloud provider per free account. This artificially limited value. CipherBox's IPFS approach avoids this.

2. **Cryptomator's Lost Sharing:** When you encrypt with Cryptomator, you lose the cloud provider's native sharing. CipherBox should design sharing into the encryption architecture from the start (for v2).

3. **ProtonDrive's Slow Desktop Launch:** ProtonDrive was web-only for years, frustrating power users. CipherBox launching with desktop mount is correct.

4. **NordLocker's Missing Versioning:** NordLocker doesn't have file versioning, which users consistently complain about. CipherBox deferring to v2 is acceptable for tech demo.

---

## Feature Dependencies

Understanding which features depend on others for phased implementation.

```
Core Foundation (v1.0)
├── E2E Encryption (AES-256-GCM, ECIES)
├── Web3Auth Integration
├── IPFS/IPNS Storage
│   └── TEE Republishing
├── Basic File Operations
│   ├── Upload/Download
│   ├── Folder Hierarchy
│   └── Rename/Move/Delete
├── Multi-Device Sync
│   └── IPNS Polling
└── Vault Export

File Sharing (v2.0) - DEPENDENCY CHAIN
├── Requires: Key Sharing Infrastructure
│   ├── Recipient Key Discovery
│   ├── Shared Folder Keys (per-recipient wrapping)
│   └── Share Link Token Generation
├── Requires: Permission Model
│   ├── Read vs Write Access
│   └── Share Expiration
└── Requires: Revocation Mechanism

File Versioning (v2.0)
├── Requires: Version Metadata in IPNS
├── Requires: Multiple CID Storage per File
└── Requires: Version Comparison UX

Search (v2.0)
├── Requires: Client-Side Index
├── Requires: Index Encryption
└── Requires: Index Sync Across Devices

Mobile Apps (v2.0)
├── Requires: Crypto Module Port (React Native or Native)
├── Requires: Photo Backup Flow
└── Requires: Offline Cache Strategy
```

---

## MVP Recommendation

For CipherBox v1.0 as a technology demonstrator, the current scope is reasonable. However, for user testing or early adoption, consider these adjustments:

### Keep As-Is (Correctly Scoped)
1. E2E encryption with AES-256-GCM and ECIES
2. Web UI with drag-drop upload
3. macOS desktop with FUSE mount
4. Multi-device sync via IPNS
5. Vault export for recovery
6. TEE IPNS republishing
7. Multi-method auth via Web3Auth

### Consider Adding to v1.0
1. **Basic File Preview:** At minimum, display images inline. This is low complexity and significantly improves UX.
2. **Soft Delete / Recycle Bin:** 7-day retention before permanent deletion. Prevents accidental data loss.
3. **Explicit 2FA Toggle:** Even if Web3Auth handles it, users expect to see "2FA enabled" in settings.

### Confirm Deferred to v1.1 (Acceptable)
1. Linux/Windows desktop apps
2. Streaming decryption (CTR mode)
3. Performance optimization

### Confirm Deferred to v2.0 (Acceptable for Tech Demo, Critical for Product)
1. File sharing (highest priority post-v1)
2. File versioning
3. Mobile apps
4. Search

### Never Build (Anti-Features)
1. Server-accessible encryption keys
2. Unencrypted metadata storage
3. Hybrid encrypted/unencrypted models

---

## Competitive Position Summary

| Competitor | Strengths vs CipherBox | Weaknesses vs CipherBox |
|------------|------------------------|-------------------------|
| **Tresorit** | Mature sharing, enterprise features, audited | Centralized, subscription expensive, no IPFS |
| **ProtonDrive** | Ecosystem (Mail, Calendar, VPN), mobile apps | Centralized, no FUSE mount, limited free tier |
| **Cryptomator** | Open source, works with any provider, quantum-resistant | No sharing, no sync, client-only tool |
| **Boxcryptor** | Wide provider support | Acquired by Dropbox, unclear future, not standalone |
| **Sync.com** | Affordable, good mobile apps | Less technical audience, no IPFS |
| **NordLocker** | Part of Nord ecosystem | No versioning, less privacy-focused than claimed |

**CipherBox's Position:** Most technically novel (IPFS, TEE, Web3Auth) but least feature-complete. Appropriate for technology demonstrator, would need significant feature expansion for commercial viability.

---

## Sources

Research compiled from:

- [Tresorit Features](https://tresorit.com) - Official site
- [Cloudwards Tresorit Review 2026](https://www.cloudwards.net/tresorit-review/)
- [CyberInsider Tresorit Review 2026](https://cyberinsider.com/cloud-storage/reviews/tresorit/)
- [Cloudwards Boxcryptor Review 2026](https://www.cloudwards.net/boxcryptor-review/)
- [Cryptomator Official](https://cryptomator.org/)
- [Cloudwards Cryptomator Review 2026](https://www.cloudwards.net/cryptomator-review/)
- [Proton Drive Official](https://proton.me/drive)
- [Proton Drive 2025 Recap](https://proton.me/drive/2025-recap)
- [CyberInsider Proton Drive Review 2026](https://cyberinsider.com/cloud-storage/reviews/proton-drive/)
- [Privacy Guides Cloud Storage](https://www.privacyguides.org/en/cloud/)
- [CyberNews Most Secure Cloud Storage 2026](https://cybernews.com/reviews/most-secure-cloud-storage/)
- [Gizmodo Best Encrypted Cloud Storage 2025](https://gizmodo.com/best-cloud-storage/encrypted)
- [Cloudwards Zero-Knowledge Services](https://www.cloudwards.net/best-zero-knowledge-cloud-services/)
- CipherBox internal specifications (PRD.md, CLIENT_SPECIFICATION.md)

---

## Confidence Assessment

| Area | Confidence | Rationale |
|------|------------|-----------|
| Table Stakes | HIGH | Multiple sources agree on baseline expectations |
| Differentiators | HIGH | Clear differentiation from competitor analysis |
| Anti-Features | HIGH | Industry post-mortems and security research |
| Gap Analysis | HIGH | Direct comparison with CipherBox specs |
| Complexity Estimates | MEDIUM | Based on competitor implementation patterns, not verified |
| Mobile Gap Severity | HIGH | All competitors prioritize mobile; 60%+ of cloud access is mobile |

---

**End of Feature Landscape Research**
