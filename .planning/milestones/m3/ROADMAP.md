# Roadmap: CipherBox Milestone 3 -- Encrypted Productivity Suite

## Overview

Milestone 3 transforms CipherBox from an encrypted file locker into an encrypted productivity platform. Four phases follow the natural dependency chain: billing infrastructure (gates tier-based access), team accounts (enables shared vaults with ECIES-wrapped Per-Team Keys), document editors (TipTap rich text + Univer spreadsheets with decrypt-edit-encrypt pipeline), and document signing (ECDSA attestation using existing Web3Auth keys). Real-time collaboration is explicitly deferred to M4; M3 delivers single-user editing with advisory locking for team documents.

## Phases

**Phase Numbering:**

- Continues from M2 (Phases 12-17). M3 starts at Phase 18.
- Integer phases (18, 19, 20, 21): Planned milestone work
- Decimal phases (e.g., 19.1): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [ ] **Phase 18: Billing Infrastructure** - Stripe subscriptions, NOWPayments crypto billing, tier enforcement, and webhook-driven provisioning
- [ ] **Phase 19: Team Accounts** - Team CRUD, ECIES-wrapped Per-Team Key hierarchy, CASL role-based permissions, team vault initialization
- [ ] **Phase 20: Document Editors** - TipTap rich text and Univer spreadsheet editors with decrypt-edit-encrypt pipeline, autosave queue, advisory locking
- [ ] **Phase 21: Document Signing** - ECDSA signing/verification with Web3Auth keys, visual signature capture, multi-party workflows, signed PDF export

## Phase Details

### Phase 18: Billing Infrastructure

**Goal**: Users can subscribe to paid plans and the system enforces storage and feature limits by tier
**Depends on**: Phase 17 (Milestone 2 complete)
**Requirements**: BILL-01, BILL-02, BILL-03, BILL-04, BILL-05, BILL-06, BILL-07, BILL-08
**Research flag**: Standard patterns -- Stripe integration is well-documented with mature NestJS modules. NOWPayments REST API is straightforward. Skip `/gsd:research-phase`.
**Success Criteria** (what must be TRUE):

1. User can select a plan (Free/Pro/Team), complete Stripe Checkout, and see their subscription activated within seconds of payment
2. User can open Stripe Customer Portal from settings to upgrade, downgrade, or cancel their subscription without contacting support
3. Pro user uploading files beyond the free 500 MiB limit succeeds up to 50 GiB; free user is blocked at 500 MiB with an upgrade prompt
4. User can pay with cryptocurrency (BTC, ETH, USDC) via NOWPayments; subscription activates after blockchain confirmation
5. When a user's payment fails, they retain access for a grace period and receive notification; access downgrades only after grace period expires

**Plans**: TBD

### Phase 19: Team Accounts

**Goal**: Users can create teams with shared encrypted vaults where team members access shared content through a zero-knowledge key hierarchy
**Depends on**: Phase 18 (billing tier enforcement for team member limits)
**Requirements**: TEAM-01, TEAM-02, TEAM-03, TEAM-04, TEAM-05, TEAM-06, TEAM-07, TEAM-08, TEAM-09
**Research flag**: NEEDS `/gsd:research-phase` -- PTK rotation on member removal is the most complex protocol in M3. ECIES re-wrapping correctness with key epochs must be validated. IPNS record size under team metadata growth (N members x M wrapped keys) needs measurement.
**Success Criteria** (what must be TRUE):

1. User can create a team, and the team vault is initialized with a team-scoped IPNS keypair and root folder key (all encrypted with the Per-Team Key, never plaintext on server)
2. Owner can invite a member by email or public key; the PTK is ECIES-wrapped to the invitee's publicKey; invitee can accept and immediately browse team files
3. User can switch between personal vault and team vaults in the sidebar; folder navigation within a team vault works identically to the personal vault
4. Owner can remove a member, which triggers PTK rotation -- the removed member can no longer decrypt newly encrypted team content
5. Team of 25 members on a Team tier operates without hitting member limits; free/pro users attempting to create teams are prompted to upgrade

**Plans**: TBD

### Phase 20: Document Editors

**Goal**: Users can create and edit rich text documents and spreadsheets directly in the browser with all content encrypted at rest on IPFS
**Depends on**: Phase 19 (team vaults for shared document editing context and advisory locking)
**Requirements**: EDIT-01, EDIT-02, EDIT-03, EDIT-04, EDIT-05, EDIT-06, EDIT-07, EDIT-08, EDIT-09
**Research flag**: NEEDS `/gsd:research-phase` -- TipTap 3.x + Univer integration specifics, bundle size impact, autosave pipeline performance with IPFS/IPNS latency. A proof-of-concept of the decrypt-edit-encrypt pipeline should be built early in planning.
**Success Criteria** (what must be TRUE):

1. User can create a new document, type and format text (bold, italic, headings, lists, links, tables), and the content is encrypted and persisted to IPFS on save
2. User can reopen a previously saved document and see their content exactly as they left it (round-trip through encrypt/decrypt preserves formatting)
3. User can create and edit a spreadsheet with formulas, formatting, and multiple sheets; spreadsheet state is encrypted and persisted identically to documents
4. Autosave fires after 60 seconds of inactivity; a dirty indicator shows unsaved changes; closing the tab with unsaved changes triggers a warning
5. When a team member opens a team document for editing, other team members see an advisory lock indicator and can choose read-only view or force-edit

**Plans**: TBD

### Phase 21: Document Signing

**Goal**: Users can cryptographically sign documents with their Web3Auth keys and any authorized party can verify the signature
**Depends on**: Phase 20 (documents exist to be signed; editor infrastructure provides the document viewing context)
**Requirements**: SIGN-01, SIGN-02, SIGN-03, SIGN-04, SIGN-05, SIGN-06
**Research flag**: Standard patterns -- uses existing ECDSA primitives (secp256k1 via Web3Auth + Web Crypto API). Straightforward implementation. Skip `/gsd:research-phase`.
**Success Criteria** (what must be TRUE):

1. User can sign any document or file, producing an ECDSA signature over the SHA-256 content hash; signature metadata is stored in encrypted folder metadata
2. Any user with folder access can verify a signature is valid for the given document content and signer's publicKey
3. User can draw or type a visual signature that is displayed alongside the cryptographic signature status in the file browser
4. User can request signatures from other CipherBox users; the document shows signature status (pending/partial/complete) and lists who has and has not signed
5. User can export a signed document as a PDF with the digital signature embedded (client-side via LibPDF)

**Plans**: TBD

## Progress

**Execution Order:**

Phases execute in numeric order: 18 -> 19 -> 20 -> 21

| Phase                      | Milestone | Plans Complete | Status      | Completed |
| -------------------------- | --------- | -------------- | ----------- | --------- |
| 18. Billing Infrastructure | M3        | 0/TBD          | Not started | -         |
| 19. Team Accounts          | M3        | 0/TBD          | Not started | -         |
| 20. Document Editors       | M3        | 0/TBD          | Not started | -         |
| 21. Document Signing       | M3        | 0/TBD          | Not started | -         |

---

Roadmap created: 2026-02-11
Depth: Comprehensive (4 phases -- research recommends exactly 4; requirements cluster into 4 natural delivery boundaries)
Total M3 phases: 4 | Total M3 plans: TBD
Coverage: 32/32 requirements mapped
