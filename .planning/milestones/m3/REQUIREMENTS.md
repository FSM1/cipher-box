# Requirements: CipherBox Milestone 3 -- Encrypted Productivity Suite

**Defined:** 2026-02-11
**Core Value:** Zero-knowledge privacy -- files encrypted client-side, server never sees plaintext
**Milestone Goal:** Transform CipherBox from encrypted file storage into an encrypted productivity platform with billing, teams, document editors, and document signing.

## M3 Requirements

Requirements for Milestone 3. Each maps to roadmap phases 18+.

### Billing

- [ ] **BILL-01**: User can subscribe to a paid plan (Pro or Team) via Stripe Checkout
- [ ] **BILL-02**: User can manage their subscription (upgrade, downgrade, cancel) via Stripe Customer Portal
- [ ] **BILL-03**: Subscription lifecycle is driven by Stripe webhooks with idempotent event processing and signature verification
- [ ] **BILL-04**: Free tier enforces existing 500 MiB storage limit; Pro tier increases to 50 GiB; Team tier provides 200 GiB shared
- [ ] **BILL-05**: User can view subscription status, current tier, and billing history in settings
- [ ] **BILL-06**: Failed payments trigger a grace period before access downgrade (Stripe Smart Retries)
- [ ] **BILL-07**: User can pay with cryptocurrency via NOWPayments invoice flow (BTC, ETH, USDC, and 350+ coins)
- [ ] **BILL-08**: Periodic reconciliation job compares CipherBox subscription state with Stripe and fixes discrepancies

### Team Accounts

- [ ] **TEAM-01**: User can create a team (organization) and become its owner
- [ ] **TEAM-02**: Owner/admin can invite members by email or public key; invitee receives an invitation they can accept or decline
- [ ] **TEAM-03**: Team supports role-based permissions: owner, admin, editor, viewer -- enforced at both API level (CASL guards) and client-side (UI gating)
- [ ] **TEAM-04**: Team has a Per-Team Key (PTK) that is ECIES-wrapped to each member's publicKey; server never stores plaintext PTK
- [ ] **TEAM-05**: Team vault is initialized with team-scoped IPNS keypair and root folder key encrypted with the PTK
- [ ] **TEAM-06**: User can switch between personal vault and team vaults in the sidebar
- [ ] **TEAM-07**: Owner/admin can remove a member, which triggers PTK rotation and re-wrapping for all remaining members
- [ ] **TEAM-08**: Team member limits are enforced by subscription tier (Team tier: 25 members)
- [ ] **TEAM-09**: Team admin can view aggregate storage usage for the team

### Document Editors

- [ ] **EDIT-01**: User can create and edit rich text documents in-browser using TipTap with basic formatting (bold, italic, headings, lists, links, tables)
- [ ] **EDIT-02**: Documents use the decrypt-edit-encrypt pipeline: fetch encrypted blob from IPFS, decrypt client-side, load in editor, re-encrypt on save, upload new CID
- [ ] **EDIT-03**: Autosave with debounced save queue (60s after last edit); only one save in-flight at a time (mutual exclusion); dirty indicator shown when unsaved changes exist
- [ ] **EDIT-04**: Folder metadata extended with editorType and editorFormat fields (stored encrypted, server never sees them)
- [ ] **EDIT-05**: User can create and edit spreadsheets in-browser using Univer (single-user editing only, no real-time collaboration)
- [ ] **EDIT-06**: User can export documents to PDF and Markdown; user can export spreadsheets to XLSX and CSV (all client-side)
- [ ] **EDIT-07**: Advisory document locking for team contexts -- when a user opens a team document for editing, other team members see "Currently being edited by [user]" and can choose read-only or force-edit
- [ ] **EDIT-08**: Unsaved changes are buffered to IndexedDB via y-indexeddb; beforeunload handler warns about unsaved changes
- [ ] **EDIT-09**: Encryption operations for large documents run in a Web Worker to avoid blocking the main thread

### Document Signing

- [ ] **SIGN-01**: User can sign any file or document with their secp256k1 privateKey via ECDSA (client-side, Web Crypto API); signature computed over SHA-256 hash of plaintext content
- [ ] **SIGN-02**: Any user with folder access can verify a signature given the signer's publicKey and the document content
- [ ] **SIGN-03**: User can draw or type a visual signature via react-signature-canvas; visual signature is stored alongside the cryptographic signature
- [ ] **SIGN-04**: Multi-party signing workflow: user can request signatures from other CipherBox users; signature status tracked as pending/partial/complete
- [ ] **SIGN-05**: Signed document metadata (signerPublicKey, signatureHex, contentHash, signedAt, signedCid) stored in encrypted folder metadata alongside the file entry
- [ ] **SIGN-06**: User can export a signed PDF with embedded digital signature via LibPDF (client-side)

## Deferred to M4+

Tracked but not in M3 scope. Documented to prevent scope creep.

- **COLLAB-01**: Real-time collaborative editing via encrypted CRDT relay (Yjs + Hocuspocus with encrypted WebSocket transport)
- **COLLAB-02**: Cursor and selection awareness for real-time co-editing
- **SHEET-COLLAB-01**: Spreadsheet real-time collaboration (requires custom Yjs adapter for Univer OT)
- **SLIDES-01**: Presentation/slide editing (no mature open-source WYSIWYG slide editor exists)
- **SIGN-07**: Blockchain-timestamped signing (anchor document hash on-chain)
- **SIGN-08**: Zero-knowledge signing verification (ZK-SNARK circuits)
- **TEAM-10**: Zero-knowledge organization metadata (encrypted org structure on IPFS)
- **TEAM-11**: Cryptographic role enforcement (separate read/write key hierarchies so viewers literally cannot write)
- **TEAM-12**: SSO/LDAP integration
- **TEAM-13**: Enterprise policy templates
- **TEAM-14**: Decentralized team key recovery via Shamir's Secret Sharing
- **BILL-09**: Pay-per-use metered storage billing
- **BILL-10**: Stablecoin subscription payments via Stripe

## Out of Scope

Explicitly excluded from M3. Documented to prevent scope creep.

| Feature                                | Reason                                                                    |
| -------------------------------------- | ------------------------------------------------------------------------- |
| Real-time collaborative editing        | Encrypted CRDT relay is highest-risk item; deferred to M4 to reduce scope |
| Spreadsheet collaboration              | Univer uses OT (incompatible with ZK without custom Yjs adapter)          |
| Slide/presentation editing             | No mature open-source editor exists                                       |
| Full Google Docs feature parity        | Years of effort, not a tech demo goal                                     |
| eIDAS/QES compliance                   | Requires certified CA, hardware tokens, legal framework                   |
| Server-side document rendering         | Breaks zero-knowledge guarantee                                           |
| AI writing assistance                  | Requires server access to plaintext                                       |
| SSO/LDAP                               | Enterprise scope, not demo territory                                      |
| Template-based signing (fill-and-sign) | DocuSeal territory, massive scope                                         |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase    | Status  |
| ----------- | -------- | ------- |
| BILL-01     | Phase 18 | Pending |
| BILL-02     | Phase 18 | Pending |
| BILL-03     | Phase 18 | Pending |
| BILL-04     | Phase 18 | Pending |
| BILL-05     | Phase 18 | Pending |
| BILL-06     | Phase 18 | Pending |
| BILL-07     | Phase 18 | Pending |
| BILL-08     | Phase 18 | Pending |
| TEAM-01     | Phase 19 | Pending |
| TEAM-02     | Phase 19 | Pending |
| TEAM-03     | Phase 19 | Pending |
| TEAM-04     | Phase 19 | Pending |
| TEAM-05     | Phase 19 | Pending |
| TEAM-06     | Phase 19 | Pending |
| TEAM-07     | Phase 19 | Pending |
| TEAM-08     | Phase 19 | Pending |
| TEAM-09     | Phase 19 | Pending |
| EDIT-01     | Phase 20 | Pending |
| EDIT-02     | Phase 20 | Pending |
| EDIT-03     | Phase 20 | Pending |
| EDIT-04     | Phase 20 | Pending |
| EDIT-05     | Phase 20 | Pending |
| EDIT-06     | Phase 20 | Pending |
| EDIT-07     | Phase 20 | Pending |
| EDIT-08     | Phase 20 | Pending |
| EDIT-09     | Phase 20 | Pending |
| SIGN-01     | Phase 21 | Pending |
| SIGN-02     | Phase 21 | Pending |
| SIGN-03     | Phase 21 | Pending |
| SIGN-04     | Phase 21 | Pending |
| SIGN-05     | Phase 21 | Pending |
| SIGN-06     | Phase 21 | Pending |

**Milestone 3 Coverage:**

- M3 requirements: 32 total
- Mapped to phases: 32
- Unmapped: 0

---

Requirements defined: 2026-02-11
