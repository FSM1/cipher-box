# Milestone 3 Research Summary

**Project:** CipherBox -- Encrypted Productivity Suite
**Domain:** Zero-knowledge document editing, team accounts, billing, document signing
**Researched:** 2026-02-11
**Confidence:** MEDIUM

## Executive Summary

Milestone 3 transforms CipherBox from an encrypted file locker into an encrypted productivity platform. The four feature pillars -- billing, team accounts, document editors, and document signing -- vary dramatically in complexity. Billing (Stripe + optional crypto payments) is straightforward with well-documented patterns. Team accounts introduce a real key hierarchy challenge but follow established models from Keybase and Tresorit. Document editors are the highest-risk, highest-effort feature: integrating TipTap + Yjs for rich text editing with encrypted CRDT transport is novel territory that CryptPad and Proton Docs each spent years building. Document signing is the simplest win, leveraging existing Web3Auth secp256k1 keys for ECDSA attestation.

The recommended approach is to build in strict dependency order: Billing first (enables tier gating), then Teams (enables shared vaults), then Document Editors (the flagship feature), then Signing (additive to existing documents). This order minimizes rework -- each phase builds on the previous one. Spreadsheets should ship as single-user-editable only (no real-time collaboration), and slides should be deferred entirely. Real-time collaboration for documents should also be deferred to M4+; M3 should implement single-user editing with advisory locking for team documents.

The critical risks center on two threats to the zero-knowledge guarantee: editor libraries leaking plaintext through collaboration protocols, and team key distribution introducing server-visible key material. Both are solvable with known patterns (encrypted CRDT transport, ECIES-wrapped per-team keys) but require deliberate architecture -- the path of least resistance in every editor and team library assumes a trusted server. Autosave conflicting with IPNS publish latency is a secondary but real risk that needs a save queue with mutual exclusion from day one.

## Key Findings

### Recommended Stack

The stack extends CipherBox's existing NestJS + React + TypeORM + IPFS architecture. No foundational technology changes are needed -- M3 is additive.

Core technologies:

- **TipTap 3.x + Yjs** (rich text editing) -- Stable v3, ProseMirror-based, native Yjs CRDT support, MIT licensed, used by Proton Docs. HIGH confidence.
- **Univer 0.15.x** (spreadsheet editing) -- Best open-source spreadsheet engine, client-side formula computation, Apache 2.0. MEDIUM confidence (pre-1.0 API instability risk).
- **Hocuspocus 3.4.x** (collaboration relay) -- WebSocket relay for Yjs sync; must be used as a dumb encrypted pipe, not as a document-aware server.
- **CASL 6.x** (authorization) -- Standard RBAC/ABAC library for NestJS with React client-side integration. HIGH confidence.
- **Stripe 20.x + @golevelup/nestjs-stripe** (traditional billing) -- Industry standard, mature NestJS integration. HIGH confidence.
- **NOWPayments** (crypto billing) -- SaaS crypto payment processor, 350+ coins, no self-hosting required. MEDIUM confidence (SDK less actively maintained).
- **LibPDF** (document signing) -- TypeScript-first PDF library with PAdES digital signature support, built by Documenso. MEDIUM-LOW confidence (beta).
- **react-signature-canvas** (visual signature capture) -- Lightweight signature drawing pad. HIGH confidence.

Critical version requirements:

- TipTap must be v3.x (stable since Feb 2026, Yjs collaboration extensions only in v3)
- Univer at 0.15.x; expect breaking changes between minor versions
- LibPDF is beta -- have @signpdf/signpdf as a server-side fallback

### Expected Features

Must have (table stakes):

- Free tier with storage limits and paid subscription tiers (Stripe Checkout + Customer Portal)
- Organization/team creation with member invitation and role-based permissions (owner/admin/editor/viewer)
- In-browser rich text document editing with basic formatting (bold, italic, headings, lists, links, tables)
- Per-document AES-256-GCM encryption using existing key hierarchy
- Autosave with debounce and dirty indicator
- Document signing with ECDSA using Web3Auth secp256k1 keys
- Signature verification by any party with signer's public key
- Visual signature capture (draw/type)

Should have (differentiators):

- Anonymous crypto payments (NOWPayments or BTCPay Server)
- IPFS-backed document storage with CID-based integrity verification
- Spreadsheet editing (Univer, single-user only)
- Multi-party signing workflows with signature request UI
- IPFS-anchored signatures with tamper-evident CID linking
- Client-side PDF export with embedded digital signature
- Advisory document locking for team contexts

Defer to M4+:

- Real-time collaborative editing (encrypted CRDT relay via WebSocket)
- Spreadsheet real-time collaboration (Univer uses OT, incompatible with ZK without custom Yjs adapter)
- Slide/presentation editing (no mature open-source WYSIWYG editor exists)
- Blockchain-timestamped signing (smart contract integration)
- Zero-knowledge organization metadata (encrypted org structure on IPFS)
- Cryptographic role enforcement (separate read/write key hierarchies)
- SSO/LDAP, enterprise policy templates

### Architecture Approach

M3 follows a "decrypt-edit-encrypt" pipeline pattern: files are fetched from IPFS, decrypted client-side, loaded into an in-browser editor, and re-encrypted on save. This is architecturally identical to the existing file update flow but replaces the download/re-upload step with an embedded editor. Team accounts extend the key hierarchy by introducing a Per-Team Key (PTK) that is ECIES-wrapped for each member's public key -- file keys within team folders are encrypted with the PTK, not individual member keys. Billing metadata (tier, quotas) is the only new server-side state; all user content remains in the zero-knowledge layer (IPNS metadata + IPFS content).

Major components:

1. **Editor module** (frontend) -- TipTap document editor, Univer spreadsheet editor, decrypt-edit-encrypt pipeline service, autosave with debounced save queue
2. **Teams module** (API + frontend) -- Team CRUD, member management, ECIES key wrapping per member, team vault initialization with team-scoped IPNS keypairs
3. **Billing module** (API + frontend) -- Stripe Checkout/Portal/webhooks, NOWPayments invoice/IPN webhooks, subscription entity with tier enforcement in NestJS guards
4. **Signing module** (frontend-only) -- ECDSA signing/verification via Web Crypto API, signature metadata stored in encrypted IPNS folder metadata, react-signature-canvas for visual capture

### Critical Pitfalls

1. **Editor plaintext leakage (C1)** -- All mainstream collaboration libraries (Hocuspocus, Liveblocks, TipTap Cloud) transmit plaintext by default. CRDT updates MUST be encrypted client-side before WebSocket transmission. Build a custom Yjs provider that encrypts with the document key. Audit every WebSocket frame in DevTools.

2. **Team key distribution without trusted server (C2)** -- Team keys must be ECIES-wrapped per member, never stored in plaintext on server. Member removal MUST trigger key rotation (new PTK, re-wrap for remaining members). Model after Keybase's per-team-key architecture with key epochs.

3. **Autosave vs. IPNS publish latency (C3)** -- Each save requires encrypt + IPFS upload + IPNS publish (2-12 seconds total). Implement a save queue with mutual exclusion; only one save in-flight at a time. Separate real-time editing state (local CRDT) from persistence (debounced IPNS snapshots at 10-30 second intervals).

4. **Admin recovery that breaks ZK (C4)** -- Never store a server-side admin recovery key. Recovery requires an authenticated admin with their private key in client RAM. Accept that if all admins lose their keys, team data is unrecoverable. This is the correct security/convenience tradeoff for ZK.

5. **Scope explosion from spreadsheets and slides (M2)** -- Spreadsheets are an order of magnitude harder than rich text. Proton launched Docs in mid-2024 and Sheets in late 2025. Slides have no mature open-source editor. Scope M3 to documents + basic spreadsheets only.

## Implications for Roadmap

Based on research, the suggested phase structure is four sequential phases following the dependency chain: Billing -> Teams -> Editors -> Signing.

### Phase 1: Billing Infrastructure

**Rationale:** Billing is independent of all other M3 features and has zero crypto complexity. The tier system gates access to team features and editor usage, so it must exist before other features can enforce limits. This is also the lowest-risk phase with the highest confidence stack (Stripe).

**Delivers:** Free/Pro/Team subscription tiers, Stripe Checkout and Customer Portal, webhook-driven provisioning, subscription entity with quota enforcement, billing settings UI. Optionally: NOWPayments crypto payment integration.

**Addresses features:** Free tier with storage limits, paid subscription tiers, Stripe Checkout, subscription management, invoices, webhook provisioning, grace period for failed payments.

**Avoids pitfalls:** M1 (billing state desync) by implementing idempotent webhooks and periodic Stripe reconciliation from day one. M6 (webhook fraud) by requiring Stripe signature verification on all webhook endpoints.

**Estimated effort:** 2-4 weeks.

### Phase 2: Team Accounts

**Rationale:** Team infrastructure must exist before team-aware editors and team document signing. The key hierarchy extension (Per-Team Key wrapping) is the most architecturally significant change in M3 and needs to be designed carefully before editors add complexity.

**Delivers:** Team CRUD, member invitation with ECIES key wrapping, role-based permissions (owner/admin/editor/viewer via CASL), team vault initialization with team-scoped IPNS keypairs, team sidebar UI and vault switching, key rotation on member removal.

**Addresses features:** Create organization, invite members, role-based permissions, team/group abstraction, remove member with key revocation, member device management.

**Avoids pitfalls:** C2 (key distribution) by implementing ECIES-wrapped Per-Team Keys from the start. C4 (admin recovery) by designing recovery as admin-key-gated, never server-side. N2 (key wrapping scaling) by using two-level key hierarchy (PTK wraps file keys, member keys wrap PTK).

**Estimated effort:** 4-6 weeks.

### Phase 3: Document Editors

**Rationale:** Editors are the highest-complexity, highest-visibility feature. They benefit from having teams in place so team members can test editing flows on shared documents. Single-user editing first, with advisory locking for team contexts. Real-time collaboration deferred to M4+.

**Delivers:** TipTap rich text editor integration, Univer spreadsheet editor integration (single-user), decrypt-edit-encrypt pipeline service, autosave with debounced save queue, metadata schema extensions (editorType, editorFormat), "New Document" / "New Spreadsheet" creation flow, advisory locking for team documents, document export (PDF, Markdown, XLSX).

**Addresses features:** In-browser document editing, basic rich text formatting, document-level encryption, offline single-user editing, document history/undo, copy/paste, export to common formats, IPFS-backed document storage.

**Avoids pitfalls:** C1 (plaintext leakage) by not implementing real-time collaboration in M3 -- single-user editing eliminates the encrypted relay requirement entirely. C3 (autosave conflicts) by implementing a save queue with mutual exclusion. C5 (CRDT tombstone bloat) is deferred since real-time CRDTs are deferred. M3 (encryption performance) by using Web Workers for crypto operations and setting document size limits.

**Estimated effort:** 6-10 weeks.

### Phase 4: Document Signing

**Rationale:** Signing is additive to documents that already exist. It is the simplest M3 feature and leverages existing Web3Auth secp256k1 keys. Building it last means documents and team contexts are stable.

**Delivers:** ECDSA signing service (client-side via Web Crypto API), signature verification, visual signature capture (draw/type via react-signature-canvas), multi-signer workflows with signature request UI, signature status indicators in file browser, signed PDF export via LibPDF.

**Addresses features:** Sign document with private key, verify signature, visual signature capture, multi-party signing workflow, audit trail, signed document export.

**Avoids pitfalls:** M5 (legal validity) by labeling signatures as "cryptographic attestation" rather than "legally binding e-signature." N4 (certificate management) by skipping X.509 certificates and using the existing Web3Auth keypair directly.

**Estimated effort:** 3-5 weeks.

### Phase Ordering Rationale

- Billing -> Teams: Team member limits and team tier pricing are gated by billing. Building billing first means teams can enforce seat limits from day one.
- Teams -> Editors: Editors need team vaults and shared folders to be meaningful in a multi-user context. Advisory locking for team documents requires the team permission model.
- Editors -> Signing: Signing requires a document to sign. Building editors first provides the document creation and viewing infrastructure that signing builds upon.
- Single-user editing in M3, real-time collaboration in M4: This is the most important scoping decision. Real-time encrypted CRDT collaboration is the highest-risk item in all of M3 research. Deferring it to M4 dramatically reduces risk and effort while still delivering the core editor experience.

### Research Flags

Phases likely needing deeper research during planning:

- **Phase 2 (Teams):** Key rotation on member removal is complex. Need security review of the key epoch chain design. IPNS record size limits under team metadata growth (N members x M wrapped keys) need validation.
- **Phase 3 (Editors):** TipTap + Univer integration specifics, bundle size impact, mobile compatibility, autosave pipeline performance with IPFS/IPNS latency. A proof-of-concept of the decrypt-edit-encrypt pipeline should be built early.

Phases with standard patterns (skip additional research):

- **Phase 1 (Billing):** Stripe integration is well-documented with mature NestJS modules. Standard webhook patterns apply.
- **Phase 4 (Signing):** Uses existing ECDSA primitives (secp256k1 via Web3Auth + Web Crypto API). Straightforward implementation.

## Confidence Assessment

| Area         | Confidence  | Notes                                                                                                                                                                                                       |
| ------------ | ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stack        | MEDIUM-HIGH | TipTap, Stripe, CASL all HIGH confidence. Univer (MEDIUM, pre-1.0) and LibPDF (MEDIUM-LOW, beta) pull the average down.                                                                                     |
| Features     | MEDIUM      | Feature landscape well-mapped via competitor analysis. Complexity estimates are informed approximations, not empirical.                                                                                     |
| Architecture | MEDIUM      | Billing and teams follow well-established ZK patterns (Keybase, Tresorit). Editor integration with encrypted IPFS/IPNS persistence is novel and untested at scale.                                          |
| Pitfalls     | MEDIUM-HIGH | Critical pitfalls (plaintext leakage, key distribution, autosave conflicts) are well-documented in academic and industry literature. Interaction with CipherBox-specific IPNS architecture is less certain. |

**Overall confidence:** MEDIUM

### Gaps to Address

- **Encrypted CRDT performance budget:** What latency does encrypting/decrypting Yjs updates add? Is sub-100ms keystroke propagation achievable for M4 real-time collaboration? Needs benchmarking during Phase 3.
- **IPNS record size limits under team metadata:** As teams grow (50+ members with wrapped keys), do IPNS records hit practical size limits? Needs measurement during Phase 2.
- **Univer API stability:** Univer is pre-1.0 with frequent breaking changes. Pin the exact version during Phase 3 and budget for API migration if minor version updates break compatibility.
- **LibPDF maturity for PDF signing:** LibPDF is beta. If PAdES signature embedding is unreliable, fall back to @signpdf/signpdf on the server side (with the document hash, not plaintext, sent to server).
- **NOWPayments recurring API reliability:** Marketing claims subscription support, but battle-tested reports are scarce. Validate with a proof-of-concept before committing to crypto billing in Phase 1.
- **Offline editing with team key rotation:** If a team member edits offline while the team key is rotated, their local state is encrypted with the old key. Recovery path needs design during Phase 2.

## Sources

### Primary (HIGH confidence)

- [TipTap 3.0 Documentation](https://tiptap.dev/docs/editor/getting-started/overview) -- Editor architecture, React integration, Yjs collaboration
- [Yjs CRDT Documentation](https://docs.yjs.dev/) -- CRDT implementation, subdocuments, providers, E2EE patterns
- [Stripe Billing Documentation](https://docs.stripe.com/billing/subscriptions/build-subscriptions) -- Subscription integration, webhooks, Customer Portal
- [Stripe Webhook Security](https://docs.stripe.com/billing/subscriptions/webhooks) -- Idempotent webhook processing
- [CASL Authorization](https://casl.js.org/v4/en/cookbook/roles-with-static-permissions/) -- RBAC/ABAC patterns
- [Keybase Team Crypto](https://book.keybase.io/docs/teams/crypto) -- Per-team key architecture with rotation
- [Tresorit Security](https://tresorit.com/security) -- ZK team key management reference
- [Keeper Encryption Model](https://docs.keeper.io/en/enterprise-guide/keeper-encryption-model) -- Enterprise ZK key hierarchy

### Secondary (MEDIUM confidence)

- [CryptPad Architecture](https://github.com/cryptpad/cryptpad/blob/main/docs/ARCHITECTURE.md) -- Encrypted CRDT collaboration patterns
- [SecSync](https://github.com/nikgraf/secsync) -- E2EE CRDT relay architecture built on Yjs
- [Univer Sheets Documentation](https://docs.univer.ai/guides/sheets) -- Spreadsheet engine, React integration
- [NOWPayments API](https://nowpayments.io/) -- Crypto payment gateway
- [Bitwarden ZK Encryption](https://bitwarden.com/resources/zero-knowledge-encryption-white-paper/) -- ZK architecture patterns
- [ChainSafe E2E Encrypted Collaborative Editing](https://research.chainsafe.io/featured/Publications/E2E-Encrypted-Doc/) -- Academic research on encrypted CRDTs

### Tertiary (LOW confidence)

- NOWPayments recurring subscription API maturity -- marketing claims only, no battle-tested production reports found
- Univer long-term stability -- relatively new project, pre-1.0
- LibPDF PAdES signature implementation -- beta library, Documenso production usage is the only reference

---

Research completed: 2026-02-11
Ready for roadmap: yes
