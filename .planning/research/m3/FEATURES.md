# Feature Landscape: Milestone 3

**Domain:** Encrypted productivity platform (docs, sheets, slides, teams, billing, signing)
**Researched:** 2026-02-11
**Confidence:** MEDIUM (grounded in competitor analysis; complexity estimates are informed approximations)

## Context

CipherBox already provides (M1) or will provide (M2) zero-knowledge encrypted file storage with IPFS/IPNS, Web3Auth, file/folder sharing, versioning, encrypted search, and vault export. Milestone 3 extends CipherBox from an encrypted file locker into a full encrypted productivity platform.

The four feature pillars researched:

1. Encrypted document editors (docs, sheets, slides)
2. Team accounts (organizations, roles, permissions)
3. Billing (Stripe + crypto/anonymous payments)
4. Secure document signing (e-signatures)

---

## Feature 1: Encrypted Document Editing

### How It Works in Zero-Knowledge Systems

The dominant pattern, used by CryptPad, Skiff (discontinued), and Proton Docs, is:

1. **CRDT-based collaboration** -- Conflict-free Replicated Data Types allow multiple clients to make concurrent edits that converge without a central authority resolving conflicts. Since the server never needs to understand document content, all CRDT updates can be end-to-end encrypted before transmission.

2. **Symmetric document key** -- Each document has a random AES-256 key. All collaborators hold this key (distributed via ECIES key-wrapping, same pattern CipherBox already uses for folder keys). CRDT patches are encrypted with this key before being relayed through the server.

3. **Relay server** -- The server acts as a dumb broadcast relay. It receives encrypted patches, stores them, and forwards them to other connected clients via WebSocket. It never decrypts.

4. **Snapshots + patch log** -- To avoid replaying the entire document history on load, periodic encrypted snapshots are stored. CryptPad creates a checkpoint every 50 patches. New clients load the latest snapshot and apply subsequent patches.

### Ecosystem of Editor Technologies

| Technology  | Type                           | Maturity                    | Encryption Support                | Notes                                                   |
| ----------- | ------------------------------ | --------------------------- | --------------------------------- | ------------------------------------------------------- |
| Yjs         | CRDT library                   | HIGH -- production at scale | Native -- designed for E2EE relay | Used by Skiff, Proton Docs (likely), many others        |
| Automerge   | CRDT library                   | HIGH                        | Compatible -- needs wrapper       | More academic, Rust core                                |
| ChainPad    | CRDT (blockchain-style)        | MEDIUM                      | Native -- built for CryptPad      | CryptPad-specific, not general purpose                  |
| SecSync     | E2EE CRDT relay protocol       | MEDIUM                      | Purpose-built for E2EE            | Built on top of Yjs, handles snapshot/update encryption |
| TipTap      | Rich text editor (ProseMirror) | HIGH                        | Via y-prosemirror binding         | Best-in-class rich text editing DX                      |
| ProseMirror | Low-level editor framework     | HIGH                        | Via y-prosemirror                 | More control, more work                                 |
| CodeMirror  | Code/text editor               | HIGH                        | Via y-codemirror                  | Better for code/markdown                                |

**Recommendation:** Use **Yjs + SecSync + TipTap** for documents. Yjs is the industry standard CRDT for collaborative editing. SecSync provides the encrypted relay protocol (snapshots, updates, ephemeral messages) purpose-built for E2EE over Yjs. TipTap provides a rich ProseMirror-based editor with excellent Yjs integration via y-prosemirror.

### Document Types and Their Complexity

| Document Type        | Complexity  | Why                                                     | Recommendation                                           |
| -------------------- | ----------- | ------------------------------------------------------- | -------------------------------------------------------- |
| Rich text (docs)     | HIGH        | Full formatting, images, tables, comments, suggestions  | Build first -- TipTap/ProseMirror + Yjs is well-trodden  |
| Markdown notes       | MEDIUM      | Simpler model, no complex formatting state              | Consider as simplified docs mode                         |
| Spreadsheets         | VERY HIGH   | Cell dependencies, formulas, cross-references, charting | Defer or use minimal grid -- Proton Sheets took years    |
| Slides/presentations | HIGH        | Layout engine, transitions, media, speaker notes        | Defer -- CryptPad does markdown-only slides for a reason |
| Whiteboard/drawing   | MEDIUM-HIGH | Canvas state, shape manipulation, infinite canvas       | Nice-to-have, not table stakes                           |

**Key insight:** CryptPad, the most complete encrypted office suite, supports all these types but took a large team many years. Proton launched Docs in mid-2024 and Sheets in late 2025 -- over 18 months apart. Building even a basic encrypted rich text editor is a multi-month effort. Spreadsheets are an order of magnitude harder.

### Table Stakes (Encrypted Docs)

| Feature                            | Why Expected                                | Complexity | Depends On                                     |
| ---------------------------------- | ------------------------------------------- | ---------- | ---------------------------------------------- |
| Real-time collaborative editing    | Core value proposition of any doc editor    | HIGH       | Yjs + WebSocket infrastructure                 |
| Cursor/selection awareness         | Users need to see where others are editing  | LOW        | Yjs awareness protocol (built-in)              |
| Basic rich text formatting         | Bold, italic, headings, lists, links        | MEDIUM     | TipTap extensions                              |
| Document-level encryption          | Each doc encrypted with unique key          | LOW        | Existing CipherBox encryption patterns         |
| Share document with specific users | Invite collaborators by re-wrapping doc key | MEDIUM     | M2 sharing infrastructure (ECIES key wrapping) |
| Offline single-user editing        | Edit without connection, sync when back     | MEDIUM     | Yjs persistence + SecSync reconciliation       |
| Document history/undo              | See past states, revert changes             | MEDIUM     | CRDT operation log + snapshots                 |
| Copy/paste from external sources   | Users paste from other apps constantly      | MEDIUM     | TipTap clipboard handling                      |
| Export to common formats           | PDF, Markdown, plain text export            | MEDIUM     | Client-side rendering + conversion             |

### Differentiators (Encrypted Docs)

| Feature                            | Value Proposition                                                                    | Complexity | Depends On                                  |
| ---------------------------------- | ------------------------------------------------------------------------------------ | ---------- | ------------------------------------------- |
| IPFS-backed document storage       | Documents stored on decentralized infrastructure, not corporate servers              | MEDIUM     | Existing IPFS infrastructure                |
| Verifiable document integrity      | IPFS CID proves document content has not been tampered with                          | LOW        | Native IPFS property                        |
| Client-side PDF export             | Generate PDF entirely in browser, never touches server                               | MEDIUM     | Browser PDF libraries (jsPDF, pdfmake)      |
| Encrypted comments and suggestions | Collaborative review workflow, all E2EE                                              | HIGH       | Additional Yjs doc for comment thread state |
| Encrypted image embedding          | Inline images encrypted and stored on IPFS                                           | HIGH       | Image upload + encryption + IPFS pinning    |
| TEE-backed document availability   | Documents remain accessible via TEE republishing even when all collaborators offline | LOW        | Existing TEE infrastructure from M1         |

### Anti-Features (Encrypted Docs)

| Anti-Feature                          | Why Avoid                                    | What to Do Instead                          |
| ------------------------------------- | -------------------------------------------- | ------------------------------------------- |
| Server-side document rendering        | Breaks zero-knowledge guarantee              | All rendering client-side only              |
| AI-powered writing assistance         | Requires server access to plaintext          | Skip entirely or run local-only models      |
| Full Google Docs feature parity       | Years of effort, not a tech demo goal        | Focus on clean, functional subset           |
| Complex table/formula support in docs | Massive complexity for edge-case use         | Basic tables only, no formulas in rich text |
| Real-time voice/video in editor       | Completely different infrastructure (WebRTC) | Out of scope, link to external tools        |
| Spell checking via server             | Sends plaintext to server                    | Browser-native spellcheck only              |

---

## Feature 2: Team Accounts

### How It Works in Zero-Knowledge Systems

The pattern, used by Tresorit, Cryptomator Hub, and Keeper, involves a key hierarchy:

1. **Organization keypair** -- The org has a public/private key pair. The org private key is encrypted with the admin's personal key.

2. **Team keypairs** -- Each team within the org has its own keypair. The team private key is encrypted with the org key (and optionally with each team member's personal key for redundancy).

3. **Resource keys wrapped for teams** -- When a document or folder is shared with a team, the resource key is ECIES-wrapped for the team's public key. Any team member who can decrypt the team private key can then decrypt the resource key.

4. **Role-based access** -- Roles control what actions a user can perform (admin, manager, editor, viewer). Crucially, roles are enforced at both the API level (server checks role before allowing action) and the crypto level (viewer might only receive read-only key material).

5. **Device management** -- New devices generate a keypair; an existing trusted device re-encrypts the user's key material for the new device's public key. This is how Cryptomator Hub's Web of Trust model works.

### Tresorit's Role Model (Industry Reference)

| Role          | Capabilities                                             | Crypto Access                              |
| ------------- | -------------------------------------------------------- | ------------------------------------------ |
| Owner (admin) | Full org management, billing, policy templates           | Org private key                            |
| Co-admin      | User management, policy, device management (not billing) | Org private key (subset)                   |
| Manager       | Share folders, manage permissions within scope           | Team private key                           |
| Editor        | Read, write, delete files/folders                        | Resource decryption keys                   |
| Viewer        | Read-only access                                         | Read-only key (if separate from write key) |

### Table Stakes (Team Accounts)

| Feature                                        | Why Expected                                          | Complexity | Depends On                                                 |
| ---------------------------------------------- | ----------------------------------------------------- | ---------- | ---------------------------------------------------------- |
| Create organization                            | User creates an org, becomes admin                    | MEDIUM     | New org entity in DB, org keypair generation               |
| Invite members by email/identifier             | Admin adds users to org                               | MEDIUM     | Invitation flow, key re-wrapping                           |
| Role-based permissions (admin, member, viewer) | Different access levels required                      | HIGH       | API enforcement + crypto-level key separation              |
| Team/group abstraction                         | Group users for bulk sharing                          | HIGH       | Team keypairs, membership management                       |
| Remove member with key revocation              | Must revoke access cryptographically, not just at API | VERY HIGH  | Key rotation for all resources the removed member accessed |
| Org-level storage dashboard                    | Admin sees aggregate usage                            | LOW        | API aggregation queries                                    |
| Member device management                       | Admin can deauthorize lost devices                    | MEDIUM     | Device registry, key re-wrapping                           |

### Differentiators (Team Accounts)

| Feature                             | Value Proposition                                                                    | Complexity | Depends On                            |
| ----------------------------------- | ------------------------------------------------------------------------------------ | ---------- | ------------------------------------- |
| Zero-knowledge org management       | Admin manages org without server seeing membership relationships                     | VERY HIGH  | Encrypted org metadata on IPFS        |
| Decentralized team key recovery     | Team key recoverable without central authority via threshold cryptography            | VERY HIGH  | Shamir's secret sharing or similar    |
| Cryptographic role enforcement      | Viewers literally cannot write because they lack the write key, not just API-blocked | HIGH       | Separate read/write key hierarchy     |
| On-chain org identity               | Org identity anchored to blockchain for auditability                                 | MEDIUM     | Smart contract integration            |
| Audit log with cryptographic proofs | Tamper-evident log of all org actions                                                | HIGH       | Signed audit entries, append-only log |

### Anti-Features (Team Accounts)

| Anti-Feature                                    | Why Avoid                                           | What to Do Instead                         |
| ----------------------------------------------- | --------------------------------------------------- | ------------------------------------------ |
| Server-side permission enforcement only         | Breaks ZK -- server could grant unauthorized access | Crypto-level key access as primary control |
| SSO/LDAP integration                            | Massive scope, enterprise sales motion              | Web3Auth is the auth layer                 |
| Complex policy templates                        | Enterprise feature, not demo territory              | Simple role model (admin/editor/viewer)    |
| Per-seat billing enforcement at crypto layer    | Mixing billing with cryptography is fragile         | Enforce seat limits at API layer           |
| Hierarchical org trees (departments, sub-teams) | Exponential complexity in key management            | Flat org with optional team groups         |

---

## Feature 3: Billing

### How It Works for Privacy-Focused Products

The challenge: accepting payment while preserving user privacy. Two tracks exist:

**Track 1: Stripe (Traditional)**
Stripe handles subscription management, invoicing, payment method storage, and revenue recovery. Users provide card details. Not anonymous, but reliable. Stripe now supports stablecoin payments for subscriptions (launched October 2025) and Crypto.com integration (January 2026) for crypto-to-fiat conversion at checkout.

**Track 2: Cryptocurrency (Privacy-Preserving)**
For users who want anonymity, accept crypto directly. Options:

| Gateway       | Self-Hosted | Privacy Coins       | Recurring    | Complexity                       |
| ------------- | ----------- | ------------------- | ------------ | -------------------------------- |
| BTCPay Server | Yes (fully) | Yes (Monero plugin) | Manual       | HIGH -- self-host infrastructure |
| NOWPayments   | No (SaaS)   | Yes (300+ coins)    | Yes (native) | LOW -- API integration           |
| SHKeeper      | Yes         | Yes (Monero, LN)    | Partial      | MEDIUM                           |
| CoinGate      | No (SaaS)   | Limited             | Yes          | LOW                              |

**Recommendation:** Use **Stripe** as primary billing for most users, and **BTCPay Server** (self-hosted) as the anonymous payment option. BTCPay Server supports Bitcoin, Lightning Network, and Monero via plugins. It is the gold standard for self-hosted, censorship-resistant payment processing with no intermediary fees and no KYC requirements for the merchant. NOWPayments is an acceptable alternative if self-hosting BTCPay Server is too much operational overhead for a demo.

### Table Stakes (Billing)

| Feature                                            | Why Expected                       | Complexity | Depends On                         |
| -------------------------------------------------- | ---------------------------------- | ---------- | ---------------------------------- |
| Free tier with storage limits                      | Users try before paying            | LOW        | API-level enforcement of quotas    |
| Paid subscription tiers                            | Unlock more storage, features      | MEDIUM     | Stripe Billing integration         |
| Stripe Checkout / Payment Links                    | Standard card payment flow         | LOW        | Stripe SDK, webhook handler        |
| Subscription management (upgrade/downgrade/cancel) | Self-service billing               | MEDIUM     | Stripe Customer Portal             |
| Invoices and receipts                              | Legal/tax requirement              | LOW        | Stripe auto-generates these        |
| Webhook-driven provisioning                        | Grant access when payment succeeds | MEDIUM     | Webhook handler + DB updates       |
| Grace period for failed payments                   | Don't lock out users instantly     | LOW        | Stripe Smart Retries + grace logic |

### Differentiators (Billing)

| Feature                     | Value Proposition                                             | Complexity | Depends On                                          |
| --------------------------- | ------------------------------------------------------------- | ---------- | --------------------------------------------------- |
| Anonymous crypto payments   | Pay without revealing identity -- core privacy story          | HIGH       | BTCPay Server or NOWPayments integration            |
| Monero support              | Strongest privacy coin, mandatory privacy by default          | MEDIUM     | BTCPay Server Monero plugin                         |
| Lightning Network support   | Fast, low-fee Bitcoin payments                                | MEDIUM     | BTCPay Server LN integration                        |
| Stablecoin subscriptions    | Pay in USDC/USDT, predictable pricing for user                | MEDIUM     | Stripe stablecoin subscriptions (launched Oct 2025) |
| No-KYC anonymous accounts   | Account exists without email, identified only by Web3Auth key | LOW        | Already built -- Web3Auth does not require email    |
| Pay-per-use storage billing | Metered billing based on IPFS storage consumed                | HIGH       | Stripe metered billing + usage tracking             |

### Anti-Features (Billing)

| Anti-Feature                                      | Why Avoid                            | What to Do Instead                                  |
| ------------------------------------------------- | ------------------------------------ | --------------------------------------------------- |
| Building custom payment processing                | Regulatory nightmare, PCI compliance | Use Stripe + BTCPay Server                          |
| Enterprise sales flow (quotes, POs, net-30)       | Not a demo concern                   | Self-service only                                   |
| Fiat invoicing for crypto payments                | Complexity, legal gray area          | Crypto payments are separate track, no fiat receipt |
| Multiple currencies with exchange rate management | Stripe handles this automatically    | Let Stripe handle currency conversion               |
| Refund automation                                 | Edge cases are endless               | Manual refund process via Stripe dashboard          |

---

## Feature 4: Secure Document Signing

### How It Works in Zero-Knowledge Systems

Document signing in an encrypted context follows this flow:

1. **Document is decrypted client-side** -- The signer decrypts the document locally.
2. **Signer reviews plaintext** -- Signer sees the document content in their browser.
3. **Signature is computed client-side** -- Using the signer's private key (secp256k1 from Web3Auth), the client computes a digital signature over the document hash.
4. **Signature is stored alongside document** -- The signature (plus signer's public key and timestamp) is stored as metadata, encrypted and pinned to IPFS.
5. **Anyone with access can verify** -- Given the document, the signature, and the signer's public key, verification is a standard ECDSA verify operation.

This is fundamentally different from DocuSign/Adobe Sign where the server orchestrates signing. In a ZK system, the server never sees the document, so all signing must be client-side.

### Types of Signatures

| Type                                 | Legal Weight                      | Implementation                  | Complexity   |
| ------------------------------------ | --------------------------------- | ------------------------------- | ------------ |
| Electronic signature (drawn/typed)   | LOW -- intent to sign             | Canvas capture, stored as image | LOW          |
| Cryptographic digital signature      | HIGH -- mathematically verifiable | ECDSA sign over document hash   | MEDIUM       |
| Qualified electronic signature (QES) | HIGHEST -- EU eIDAS compliant     | Requires certified hardware/CA  | OUT OF SCOPE |

**Recommendation:** Implement **cryptographic digital signatures** using the existing secp256k1 keys from Web3Auth. This is a natural fit -- every CipherBox user already has a key pair. The signature is mathematically verifiable and tied to the user's identity. Add a visual signature capture (drawn/typed) as a UX layer on top.

### Table Stakes (Document Signing)

| Feature                              | Why Expected                          | Complexity | Depends On                                 |
| ------------------------------------ | ------------------------------------- | ---------- | ------------------------------------------ |
| Sign document with private key       | Core signing action                   | MEDIUM     | Web3Auth key access, ECDSA signing         |
| Verify signature given public key    | Anyone can check signature validity   | LOW        | Standard ECDSA verify                      |
| Visual signature capture (draw/type) | Users expect to "draw" a signature    | LOW        | HTML Canvas signature pad                  |
| Multi-party signing workflow         | Send document for multiple signers    | HIGH       | Signing state machine, notification system |
| Audit trail of signing events        | Who signed what and when              | MEDIUM     | Append-only signed log                     |
| Signed document export (PDF)         | Produce a signed PDF for external use | HIGH       | PDF generation with embedded signature     |

### Differentiators (Document Signing)

| Feature                             | Value Proposition                                                        | Complexity | Depends On                                     |
| ----------------------------------- | ------------------------------------------------------------------------ | ---------- | ---------------------------------------------- |
| IPFS-anchored signatures            | Signature stored on decentralized infrastructure, tamper-evident via CID | LOW        | Existing IPFS infrastructure                   |
| Blockchain-timestamped signing      | Anchor document hash on-chain for irrefutable timestamp proof            | MEDIUM     | Smart contract or Bitcoin OP_RETURN            |
| Zero-knowledge signing verification | Verify a signature exists without revealing document content             | VERY HIGH  | ZK-SNARK circuits                              |
| Client-side PDF signing (PKCS#7)    | Generate industry-standard signed PDFs entirely in browser               | HIGH       | node-signpdf or similar, X.509 cert generation |
| Signature request workflow          | Request signatures from other CipherBox users                            | MEDIUM     | Notification system, signing queue             |

### Anti-Features (Document Signing)

| Anti-Feature                                 | Why Avoid                                               | What to Do Instead                                          |
| -------------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------------- |
| eIDAS/QES compliance                         | Requires certified CA, hardware tokens, legal framework | Cryptographic signatures with optional blockchain anchoring |
| Server-side signing                          | Breaks ZK guarantee                                     | All signing is client-side                                  |
| Notarization service                         | Legal complexity, jurisdiction-dependent                | Provide timestamping as building block                      |
| Signing for non-CipherBox users              | Requires external key management                        | Limit to CipherBox-to-CipherBox signing                     |
| Template-based signing (fill-and-sign forms) | DocuSeal territory, massive scope                       | Simple "sign this document" flow only                       |

---

## Feature Dependencies

### Dependency Map

```text
M1/M2 Prerequisites:
  File sharing (M2) -----> Document sharing (same key-wrapping pattern)
  Encryption core (M1) --> Document encryption (same AES-256-GCM)
  IPFS storage (M1) -----> Document persistence on IPFS
  Web3Auth keys (M1) ----> Digital signature key material

M3 Internal Dependencies:
  Team Accounts ---------> Team document sharing
  Team Accounts ---------> Team billing (org pays for seats)
  Encrypted Docs --------> Document signing (need a document to sign)
  Billing ---------------> Storage quotas (need billing to enforce limits)

Build Order (recommended):
  1. Billing (enables free/paid tiers, gates everything else)
  2. Team Accounts (enables org-level features)
  3. Encrypted Docs (largest effort, most visible feature)
  4. Document Signing (builds on docs + keys, lowest standalone value)
```

### Dependency on M2 Features

| M2 Feature                              | M3 Usage                                |
| --------------------------------------- | --------------------------------------- |
| File/folder sharing (ECIES re-wrapping) | Document sharing uses identical pattern |
| File versioning (CID retention)         | Document version history                |
| Encrypted search                        | Search within documents (stretch goal)  |
| Web3Auth MFA                            | Required for signing key security       |

---

## Complexity Summary

| Feature Area                       | Estimated Effort | Risk Level | Notes                                        |
| ---------------------------------- | ---------------- | ---------- | -------------------------------------------- |
| Rich text editor (docs)            | 6-10 weeks       | HIGH       | Yjs + TipTap integration with E2EE relay     |
| Spreadsheets                       | 12-20+ weeks     | VERY HIGH  | Proton took 18 months from Docs to Sheets    |
| Slides                             | 8-14 weeks       | HIGH       | Layout engine + presentation mode            |
| Team accounts (basic)              | 4-6 weeks        | MEDIUM     | Org/member/role CRUD + key hierarchy         |
| Team accounts (crypto enforcement) | 8-12 weeks       | HIGH       | Key rotation on member removal is hard       |
| Stripe billing                     | 2-3 weeks        | LOW        | Well-documented, straightforward integration |
| Crypto billing (BTCPay)            | 3-5 weeks        | MEDIUM     | Self-hosting, webhook reconciliation         |
| Document signing (basic)           | 2-4 weeks        | LOW        | ECDSA sign/verify, UI for signature capture  |
| Document signing (multi-party)     | 4-6 weeks        | MEDIUM     | State machine, notification flow             |
| Document signing (PDF export)      | 3-5 weeks        | MEDIUM     | Client-side PDF generation with embedded sig |

**Total estimated effort for full M3:** 40-80+ weeks, depending on scope.

**Recommended MVP scope:** Rich text docs + basic teams + Stripe billing + basic signing = 14-23 weeks.

---

## MVP Recommendation

### Build First (Phase 1 of M3)

1. **Stripe billing** -- Lowest effort, highest enabling value. Free tier + paid tiers gate everything else. 2-3 weeks.

2. **Basic team accounts** -- Org creation, member invitation, admin/editor/viewer roles. API-level enforcement first, crypto-level enforcement in a later phase. 4-6 weeks.

3. **Encrypted rich text editor** -- Yjs + SecSync + TipTap. Single-user editing first, then real-time collaboration. This is the flagship feature. 6-10 weeks.

4. **Basic document signing** -- ECDSA signature using existing Web3Auth keys. Visual signature pad. Single-signer flow. 2-4 weeks.

### Defer to Phase 2 of M3

- Spreadsheets (massive effort, Proton-level undertaking)
- Slides/presentations (need layout engine)
- Crypto billing / BTCPay Server (nice to have, not blocking)
- Multi-party signing workflows
- Cryptographic role enforcement in teams
- Zero-knowledge org metadata

### Explicitly Skip (Not for a Tech Demo)

- Full Google Docs feature parity
- eIDAS compliance
- SSO/LDAP integration
- Enterprise policy templates
- AI writing features

---

## Competitor Feature Matrix

| Feature           | CryptPad         | Tresorit          | Proton Docs       | Skiff (defunct)   | Standard Notes   |
| ----------------- | ---------------- | ----------------- | ----------------- | ----------------- | ---------------- |
| Encrypted docs    | Yes (ChainPad)   | No (storage only) | Yes (Yjs-based)   | Yes (Yjs)         | Yes (notes only) |
| Encrypted sheets  | Yes (OnlyOffice) | No                | Yes (Dec 2025)    | Yes               | Partial (plugin) |
| Encrypted slides  | Yes (Markdown)   | No                | No                | No                | No               |
| Real-time collab  | Yes              | No                | Yes               | Yes               | No               |
| Team accounts     | Yes (CryptDrive) | Yes (enterprise)  | Yes (business)    | Yes (workspaces)  | No               |
| Role-based access | Basic            | Advanced          | Basic             | Basic             | N/A              |
| Billing (Stripe)  | Yes              | Yes               | Yes               | Yes               | Yes              |
| Crypto payments   | No               | No                | Bitcoin (limited) | Crypto pay option | No               |
| Document signing  | No               | No                | No                | No                | No               |
| Self-hostable     | Yes              | No                | No                | Was open source   | Partial          |
| IPFS storage      | No               | No                | No                | No                | No               |

**CipherBox differentiators:** IPFS-backed storage, cryptographic document signing with Web3Auth keys, anonymous crypto payments, and decentralized architecture set CipherBox apart from every competitor listed above. No existing product combines encrypted editing with decentralized storage and cryptographic signing.

---

## Sources

### Encrypted Document Editing

- [CryptPad](https://cryptpad.org/) -- Open-source encrypted collaboration suite
- [ChainPad CRDT Algorithm](https://github.com/cryptpad/chainpad) -- CryptPad's real-time algorithm
- [CryptPad Architecture](https://docs.cryptpad.org/en/dev_guide/client/chainpad.html) -- ChainPad and Listmap documentation
- [SecSync](https://github.com/nikgraf/secsync) -- E2EE CRDT relay architecture
- [Yjs](https://github.com/yjs/yjs) -- CRDT library for collaborative editing
- [TipTap + Yjs](https://docs.yjs.dev/ecosystem/editor-bindings/tiptap2) -- TipTap Yjs integration
- [Proton Docs](https://proton.me/drive/docs) -- E2EE document editing
- [Proton Sheets](https://proton.me/drive/sheets) -- E2EE spreadsheet (Dec 2025)
- [Skiff Whitepaper](https://skiff-org.github.io/whitepaper/Skiff_Whitepaper_2022.pdf) -- E2EE collaboration architecture
- [ChainSafe E2E Encrypted Collaborative Editing](https://research.chainsafe.io/featured/Publications/E2E-Encrypted-Doc/) -- Research publication

### Team Accounts

- [Tresorit Roles and Permissions](https://support.tresorit.com/hc/en-us/articles/216114117-User-roles-and-permissions) -- Enterprise ZK access model
- [Cryptomator Hub](https://github.com/cryptomator/hub) -- ZK key management for teams
- [Cryptomator Hub Security](https://docs.cryptomator.org/security/hub/) -- Zero-knowledge key broker architecture
- [Keeper Encryption Model](https://docs.keeper.io/en/enterprise-guide/keeper-encryption-model) -- Enterprise ZK key hierarchy

### Billing

- [Stripe Billing Subscriptions](https://docs.stripe.com/billing/subscriptions/build-subscriptions) -- Subscription integration guide
- [Stripe Stablecoin Subscriptions](https://stripe.com/blog/introducing-stablecoin-payments-for-subscriptions) -- Oct 2025 launch
- [Stripe + Crypto.com](https://www.pymnts.com/cryptocurrency/2026/stripe-integrates-cryptocom-facilitate-crypto-payments/) -- Jan 2026 integration
- [BTCPay Server](https://btcpayserver.org/) -- Self-hosted crypto payment processor
- [NOWPayments](https://nowpayments.io/) -- Crypto payment gateway with subscription support
- [SHKeeper](https://shkeeper.io/) -- Self-hosted crypto payment processor

### Document Signing

- [node-signpdf](https://github.com/vbuch/node-signpdf) -- Client-side PDF signing
- [DocuSeal](https://www.docuseal.com/) -- Open-source document signing
- [Nutrient Web SDK](https://www.nutrient.io/guides/web/signatures/) -- Browser-based PDF signing
- [eSignature Trends 2026](https://www.blueink.com/blog/top-esignature-trends-2026) -- Industry direction
