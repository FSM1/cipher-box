# Milestone 3 Domain Pitfalls

**Domain:** Adding document editors, team accounts, billing, and document signing to a zero-knowledge encrypted storage system (CipherBox)
**Researched:** 2026-02-11
**Overall Confidence:** MEDIUM-HIGH

---

## Context: Why M3 Is Uniquely Dangerous

CipherBox's existing architecture enforces a strict invariant: the server never sees plaintext. Every key is either held in client RAM or wrapped with ECIES using the user's public key. IPNS metadata is encrypted with per-folder AES-256-GCM keys. The entire key hierarchy flows from a single user's secp256k1 keypair derived by Web3Auth.

Milestone 3 introduces four features that each, in different ways, pressure this invariant:

- **Document editors** require real-time state that must be encrypted at rest but editable in real time
- **Team accounts** require multiple users to decrypt the same data without a shared private key
- **Billing** requires the server to enforce access tiers on data it cannot inspect
- **Document signing** requires cryptographic proof of authorship within an encrypted context

The overarching risk: every M3 feature creates a temptation to "just let the server see a little bit." Each small leak compounds into a broken zero-knowledge guarantee.

---

## Critical Pitfalls

Mistakes in this category cause architectural rewrites, security violations, or loss of the zero-knowledge guarantee.

### C1: Editor Library Leaking Plaintext to the Server

**What goes wrong:** A rich text editor (TipTap, ProseMirror, Slate, CKEditor) is integrated with a collaboration backend. The collaboration protocol (WebSocket sync, Yjs provider, or custom OT) transmits document operations in cleartext to a relay server. The server now has full access to document contents, destroying the ZK guarantee. This can happen subtly -- for example, a Yjs WebSocket provider sends unencrypted updates by default, or a collaboration server-side component logs operations for debugging.

**Why it happens:** All mainstream collaboration libraries assume a trusted server model. Yjs's y-websocket provider, Liveblocks, TipTap Cloud, and Hocuspocus all relay plaintext operations through a central server. The path of least resistance is to use these out of the box. CryptPad solved this by building ChainPad from scratch, and Proton Docs reportedly took over a year to build their encrypted collaboration layer.

#### Consequences

- Complete loss of zero-knowledge guarantee
- Every keystroke, cursor movement, and formatting change visible to server
- Retroactive breach: if server logs were captured before the leak was noticed, historical document content is exposed

#### Warning Signs

- Any WebSocket message from client to server containing document content that is not encrypted
- Collaboration provider documentation that does not mention client-side encryption
- Server-side code that deserializes or inspects CRDT/OT operations
- Using a hosted collaboration service (Liveblocks, TipTap Cloud) that requires seeing document state

#### Prevention

1. All CRDT/OT operations must be encrypted client-side before transmission. Yjs supports custom providers -- build one that encrypts updates with the document's folderKey (or a dedicated documentKey) before sending over WebSocket
2. The relay server must be a dumb pipe: receives opaque encrypted blobs, broadcasts to other participants, never parses content
3. Audit every network request from the editor. Use browser DevTools to verify no plaintext leaks in WebSocket frames
4. Never use hosted collaboration backends (TipTap Cloud, Liveblocks Cloud, Hocuspocus) that require server-side document access

**Confidence:** HIGH -- this is a well-documented challenge. CryptPad, Proton Docs, and Skiff (now defunct) all solved it by encrypting at the transport layer.

**Feature area:** Document Editors

---

### C2: Team Key Distribution Without a Trusted Server

**What goes wrong:** When implementing team accounts, the natural approach is to store a "team key" on the server and distribute it to team members. But in a ZK system, the server cannot hold plaintext keys. Teams require that User A can grant User B access to encrypted data, but the server facilitating this exchange must never see the key material. Getting this wrong means either (a) the server holds team keys in plaintext, or (b) key distribution is so complex it becomes a source of bugs that leak keys.

**Why it happens:** Traditional team key management uses a key escrow model where a server encrypts/decrypts on behalf of users. In ZK, you must use asymmetric wrapping: the team key is encrypted separately for each member using their public key (ECIES). This means:

- Adding a member requires re-wrapping the team key for the new member's public key
- Removing a member requires rotating the team key and re-wrapping for all remaining members
- The key rotation on member removal is the hard part -- all existing data encrypted with the old key must remain accessible (old key retained for decryption) while new data uses the new key

CipherBox currently wraps all keys with a single user's publicKey. Extending this to N users per vault is a fundamental architectural change.

#### Consequences

- If team key is stored in plaintext on server: complete ZK violation
- If key rotation on member removal is skipped: removed members retain decryption access forever (forward secrecy violation)
- If key distribution has race conditions: members may end up with stale keys and lose access to newly encrypted data

#### Warning Signs

- Any database column storing a symmetric key that is not ECIES-wrapped
- Member removal flow that does not include a key rotation step
- Team vault creation that stores a single copy of the team key (should be N copies, one per member)

#### Prevention

1. Model team key distribution after Keybase's team key architecture: each team has a Per-Team Key (PTK) that is ECIES-wrapped for each member's publicKey. On member removal, rotate the PTK and re-wrap for remaining members
2. Maintain a key epoch chain for the team: old epochs decrypt old data, current epoch encrypts new data. Never delete old epoch keys -- mark them as read-only
3. Store the wrapped team keys in the team metadata IPNS record, so the server only sees ECIES-wrapped blobs
4. Test the member removal + re-encryption flow exhaustively. This is where Keybase, Tresorit, and others have found the most bugs

**Confidence:** HIGH -- Keybase published detailed documentation on their team crypto architecture, and Tresorit uses a similar model for business accounts.

**Feature area:** Team Accounts

---

### C3: Autosave Conflicting with Encryption Round-Trips

**What goes wrong:** A document editor autosaves every few seconds. In CipherBox, each save requires: (1) serialize document state, (2) encrypt with AES-256-GCM, (3) upload encrypted blob to IPFS via backend, (4) update IPNS record with new CID. This pipeline takes 2-5 seconds per save (encryption + IPFS add + IPNS publish). If the user makes another edit before the previous save completes, you get race conditions: stale IPNS records, lost edits, or corrupted metadata.

**Why it happens:** Google Docs autosaves via a simple HTTP PATCH to a trusted server. CipherBox must encrypt, upload to IPFS (content-addressed, immutable), and publish a new IPNS record (mutable pointer update). The IPNS publish step alone can take 1-12 seconds depending on network conditions. Standard autosave intervals (Google Docs uses 30 seconds for encrypted files; typical editors use 2-5 seconds) conflict with this latency.

#### Consequences

- Lost edits when concurrent saves overwrite each other
- IPNS sequence number conflicts (two publishes with same sequence number, network picks one arbitrarily)
- Corrupted folder metadata when parent IPNS record is updated while a child save is in-flight
- User-visible lag between typing and "saved" indicator, causing anxiety and retry behavior

#### Warning Signs

- Autosave timer fires while a previous save is still in-flight
- IPNS publish errors with "sequence number" conflicts
- Inconsistent document state after rapid editing sessions
- Users reporting "lost changes" after editing sessions

#### Prevention

1. Implement a save queue with mutual exclusion: only one save can be in-flight at a time. Subsequent saves are coalesced (latest state wins) and executed after the current save completes
2. Separate the collaboration layer (CRDT sync between clients) from the persistence layer (IPNS save). CRDTs sync in real time via encrypted WebSocket; IPNS persistence happens on a debounced schedule (e.g., 10-30 seconds of inactivity)
3. Use optimistic local state: the editor shows the user their local CRDT state immediately, while IPNS persistence happens asynchronously in the background
4. Implement IPNS sequence number tracking: always fetch current sequence number before publishing, increment by 1, and retry on conflict
5. Consider storing CRDT update history separately from the "final document" snapshot. The CRDT log can be synced more frequently; the IPNS snapshot is the "checkpoint"

**Confidence:** HIGH -- this is a direct consequence of CipherBox's existing IPNS architecture (30-second polling, sequence number conflicts) applied to a much more frequent write pattern.

**Feature area:** Document Editors

---

### C4: Admin Access That Breaks Zero-Knowledge

**What goes wrong:** Team accounts need an "admin" role that can manage the team, reset member access, and potentially recover data when a member loses their key. The naive implementation gives the admin a master key that decrypts everything, stored on the server for "recovery" purposes. This creates a backdoor that destroys ZK.

**Why it happens:** Every enterprise customer asks for admin recovery. "What if an employee leaves and we need their files?" In a traditional system, the server can reset passwords and grant access. In ZK, the server genuinely cannot do this. The temptation is to add a server-side recovery key, an admin escrow key, or a "break glass" mechanism that undermines the entire security model.

#### Consequences

- Server-stored admin key = server can decrypt team data = not zero-knowledge
- Regulatory exposure: claiming ZK while having a backdoor is potentially fraudulent
- One compromised admin key exposes all team data

#### Warning Signs

- Any "admin recovery key" stored in the database without being ECIES-wrapped
- Admin role that can access data without the admin's own private key being present in client RAM
- Recovery flow that does not require the admin to be authenticated and present

#### Prevention

1. Use Tresorit's model: a designated "Recovery Administrator" holds a recovery key that is itself ECIES-wrapped with the admin's publicKey. Recovery requires the admin to be authenticated (private key in RAM) and is an explicit, auditable action
2. Team creation generates a "team recovery key" that is ECIES-wrapped for each admin's publicKey. At least one admin must be present to recover any team data
3. Accept the security/convenience tradeoff explicitly: if all admins lose their keys, team data is unrecoverable. This is a feature, not a bug, of zero-knowledge. Document this clearly for users
4. Implement "key escrow with split custody" if regulatory requirements demand it: the recovery key is split (Shamir's Secret Sharing) across N admins, requiring K-of-N to reconstruct. No single party (including the server) can reconstruct alone

**Confidence:** HIGH -- Tresorit, Keybase, and Bitwarden all document this pattern. Bitwarden's emergency access feature is a well-studied reference implementation.

**Feature area:** Team Accounts

---

### C5: CRDT Tombstone Bloat in Encrypted Documents

**What goes wrong:** CRDTs (specifically Yjs, the most likely choice) never truly delete data. When a user deletes text, the CRDT marks it as a "tombstone" -- the metadata about the deletion persists indefinitely to maintain consistency across clients. Over time, a document that has been heavily edited accumulates enormous tombstone overhead. In a ZK system, this bloated state must be encrypted, uploaded to IPFS, and published to IPNS with every save.

**Why it happens:** CRDTs guarantee eventual consistency by keeping a complete history of all operations, including deletions. Yjs mitigates this by merging adjacent tombstones, but the overhead still grows linearly with edit history. A document edited by 5 people over months can have a CRDT state 10-50x larger than the visible document content. CryptPad addresses this with "checkpoints" every 50 patches, but this adds complexity.

#### Consequences

- Document load times increase as CRDT state grows (must decrypt and parse entire state)
- IPFS storage costs increase (each save creates a new CID with the full bloated state)
- Memory pressure in the browser: large CRDT states consume significant RAM, compounding with encryption overhead
- IPNS metadata records may exceed practical size limits

#### Warning Signs

- Document CRDT state size growing faster than visible document size
- Increasing load times for documents that have been edited many times
- IPFS pin count and storage usage growing faster than expected
- Browser memory warnings during editing sessions

#### Prevention

1. Implement periodic CRDT compaction/checkpointing: every N operations (CryptPad uses 50), create a "checkpoint" that is a fresh CRDT state initialized from the current document content, discarding tombstone history. Encrypt and store this checkpoint as the new base state
2. Use Yjs subdocuments to split large documents into sections. Each section is a separate Yjs document that can be loaded lazily and compacted independently
3. Set maximum document size limits and warn users before they hit them
4. Separate the CRDT operation log (for real-time sync) from the persisted document state (for IPNS storage). Persist compacted snapshots, not full operation histories
5. Monitor CRDT state size relative to document content size. Alert when the ratio exceeds a threshold (e.g., 5x)

**Confidence:** MEDIUM -- Yjs tombstone behavior is well-documented, but the interaction with IPFS/IPNS persistence is specific to CipherBox and has not been tested at scale.

**Feature area:** Document Editors

---

## Moderate Pitfalls

Mistakes in this category cause delays, rework, or degraded user experience but do not break the security model.

### M1: Billing State Desynchronization

**What goes wrong:** The billing system (Stripe) and CipherBox's internal state disagree about a user's subscription status. A user's payment fails, Stripe marks them as "past_due," but CipherBox still shows them as active (or vice versa). Because CipherBox is ZK, the server cannot inspect file contents to enforce quotas -- it can only gate API access. If the gating logic is wrong, users either lose access prematurely or get unlimited free access.

**Why it happens:** Stripe communicates subscription changes via webhooks. Webhooks can be delayed, duplicated, or arrive out of order. If CipherBox's webhook handler is not idempotent, duplicate events cause double-processing. If the handler does not verify webhook signatures, attackers can forge subscription events. If the handler processes events synchronously, a slow database write can cause Stripe to retry, creating duplicates.

#### Consequences

- Users lose access to their vault when their subscription is actually active (support tickets, churn)
- Users retain access after subscription ends (revenue loss)
- Race conditions during plan changes (upgrade/downgrade) leave users in inconsistent states
- Free tier abuse: users create multiple accounts to bypass storage limits

#### Warning Signs

- Stripe webhook endpoint returning non-200 status codes
- Subscription status in database not matching Stripe dashboard
- Users reporting access issues after payment
- Storage quota checks that query Stripe directly instead of using cached state

#### Prevention

1. Implement idempotent webhook processing: store a unique event ID for every processed Stripe webhook, reject duplicates
2. Treat Stripe as the source of truth for billing state. On any ambiguity, query Stripe API directly (with caching)
3. Implement a periodic reconciliation job that compares CipherBox subscription states with Stripe states and fixes discrepancies
4. Use Stripe's `checkout.session.completed` and `customer.subscription.updated` events as the primary state change signals, not payment events
5. Gate access based on subscription status in CipherBox's database (synced from Stripe), not by querying Stripe on every request

**Confidence:** HIGH -- this is a well-known SaaS billing pitfall documented extensively in Stripe's own documentation.

**Feature area:** Billing

---

### M2: Spreadsheet and Slides Complexity Explosion

**What goes wrong:** After successfully building a document editor, the team assumes spreadsheets and slides will follow the same pattern. They do not. Spreadsheets require a formula engine, cell dependency graph, real-time recalculation, and collaborative cursor tracking across a 2D grid. Slides require a 2D canvas editor with layout constraints, shape manipulation, and presentation mode. Each is essentially a separate application, not a variant of a rich text editor.

**Why it happens:** The PRD lists "docs/sheets/slides" as a single milestone item. This framing implies similar scope. In reality, even Proton (with 400+ engineers) has Docs available now but Sheets only recently shipped and Slides is not expected until late 2026. Google spent years building each app separately with dedicated teams.

#### Consequences

- Milestone 3 scope explodes to 3-5x the estimated effort
- Half-built spreadsheet or slides implementation that lacks basic features (e.g., no formula support, no slide transitions)
- Team burnout from underestimated scope

#### Warning Signs

- Milestone estimate for "docs + sheets + slides" is similar to estimate for docs alone
- Evaluating a single editor library to cover all three use cases
- No separate technical design documents for sheets and slides

#### Prevention

1. Scope M3 to document editing ONLY. Defer sheets and slides to separate milestones
2. If sheets and slides are required, acknowledge that each needs its own editor library, data model, CRDT strategy, and encryption integration
3. For spreadsheets specifically: evaluate whether a pure client-side formula engine exists that can work with encrypted data. Most formula engines (Hyperformula, FortuneSheet) assume trusted access to all cell values
4. Consider leveraging existing open-source implementations (ONLYOFFICE, CryptPad) rather than building from scratch

**Confidence:** HIGH -- Proton's public roadmap confirms this complexity. CryptPad took years to build sheets and slides.

**Feature area:** Document Editors (Scope)

---

### M3: Encryption Performance Cliff on Large Documents

**What goes wrong:** The document editor works well for small documents (a few KB). For large documents (100+ pages, embedded images, complex formatting), the encrypt-then-upload cycle becomes prohibitively slow. AES-256-GCM encryption of a 10MB document takes 50-200ms, but combined with JSON serialization, CRDT state packaging, IPFS upload, and IPNS publish, the total round-trip can take 5-15 seconds. During this time, the UI freezes or shows stale state.

**Why it happens:** CipherBox's current architecture encrypts entire files atomically. For static files (PDFs, images), this is fine. For live documents that change continuously, re-encrypting the entire document state on every save is wasteful. Additionally, Web Crypto API runs on the main thread by default, blocking UI rendering during encryption.

#### Consequences

- UI jank and freezing during saves
- Users perceive the editor as slow/broken
- Autosave intervals must be increased, reducing data safety
- Large documents become practically unusable

#### Warning Signs

- Encryption time exceeding 100ms for document saves
- Main thread blocked during crypto operations
- Users complaining about lag in the editor
- Increasing save failure rate as document size grows

#### Prevention

1. Use Web Workers for all crypto operations. Offload AES-256-GCM encryption to a dedicated worker so the main thread remains responsive
2. Implement incremental encryption: encrypt only the changed portions of the document (diff-based encryption). This requires splitting the document into encrypted chunks and only re-encrypting modified chunks
3. Use Yjs's built-in update encoding: Yjs can produce compact "update" messages (just the diff) rather than full state snapshots. Encrypt and transmit only updates for real-time sync; do full-state snapshots less frequently
4. Set document size limits (e.g., 10MB of content) and enforce them in the editor
5. Stream large document content through the CTR mode encryption (from v1.1) rather than buffering the entire document in memory

**Confidence:** MEDIUM -- the individual components (Web Crypto performance, IPFS upload latency, IPNS publish latency) are well-understood, but their combined impact on editor UX is specific to CipherBox's architecture.

**Feature area:** Document Editors

---

### M4: Free Tier Abuse in a Zero-Knowledge System

**What goes wrong:** Because the server cannot inspect file contents, it cannot distinguish between legitimate files and abuse vectors (e.g., using the free tier as a CDN for pirated content, storing encrypted malware, or creating multiple accounts to aggregate free storage). Traditional abuse detection relies on content scanning, which is impossible in ZK.

**Why it happens:** ZK guarantees protect the user from the server -- but they also protect abusers from detection. The server can track metadata (file sizes, upload frequency, IP addresses) but cannot scan content. This creates a unique abuse surface that traditional billing abuse prevention does not address.

#### Consequences

- Storage costs balloon from abuse (IPFS pinning costs per GB)
- Legal liability: server cannot comply with DMCA takedown requests for encrypted content
- Reputation risk: platform used for illegal content storage
- Legitimate users subsidize abusers via shared infrastructure costs

#### Warning Signs

- Free tier accounts consuming maximum storage limits
- High upload frequency from single IP ranges
- Accounts created in bulk (same email patterns, same device fingerprints)
- Storage costs growing faster than user growth

#### Prevention

1. Rate-limit uploads by IP, device fingerprint, and account age (not by content inspection)
2. Require email verification and consider phone verification for free accounts
3. Implement progressive trust: new accounts get lower limits that increase with account age and payment history
4. Track metadata-level signals: file count, total size, upload frequency, API call patterns. These do not violate ZK (server already tracks storage quotas)
5. Make the free tier genuinely limited (CipherBox already has 500 MiB). Ensure this limit is server-enforced at the upload API level
6. Accept that content-based abuse detection is impossible. Focus prevention on account-level controls

**Confidence:** HIGH -- this is a known challenge for all ZK storage providers (Proton, Tresorit, MEGA).

**Feature area:** Billing

---

### M5: E-Signature Legal Validity in a ZK Context

**What goes wrong:** The team implements document signing using the user's existing ECDSA keypair (secp256k1 from Web3Auth). The signature is cryptographically valid but legally questionable because: (a) secp256k1 is not a standard recognized by eIDAS or most e-signature regulations, (b) there is no timestamp authority (TSA) to prove when the signature was made, (c) there is no certificate authority (CA) binding the public key to a verified identity, and (d) the signed document is encrypted, making third-party verification impossible without the decryption key.

**Why it happens:** The team conflates "cryptographic signature" with "legally binding e-signature." Under ESIGN Act and UETA, e-signatures are broadly valid, but courts require proof of identity, intent, and timestamp. A secp256k1 signature proves that the holder of a private key signed something, but does not prove who that person is (no CA) or when they signed (no TSA).

#### Consequences

- Signatures rejected by counterparties or courts
- Users believe their signatures are legally binding when they may not be
- Regulatory liability if the product claims legal validity without meeting requirements
- Integration complexity if a proper PKI must be retrofitted

#### Warning Signs

- Signing flow that uses only the Web3Auth keypair without additional identity verification
- No integration with a timestamp authority (RFC 3161)
- No way for a third party to verify a signature without having the document decryption key
- Marketing materials claiming "legally binding" without legal review

#### Prevention

1. Distinguish between "cryptographic attestation" (user confirms they authored/approved a document) and "legal e-signature" (meets ESIGN/UETA/eIDAS requirements). For a tech demo, the former may suffice
2. If legal validity is required, integrate with an established e-signature provider (DocuSign API, Adobe Sign) that handles identity verification, TSA, and audit trails
3. For internal use (team members signing off on documents), the existing ECDSA signature plus an audit log of who signed what, when may be sufficient
4. Create a "signature proof" document that includes: the document hash, the signature, the signer's public key, a timestamp from a trusted source, and instructions for verification. This proof can be shared without sharing the document itself
5. Never use the IPNS signing key (Ed25519) for document signing. These keys are shared with the TEE for republishing and have a different trust model

**Confidence:** HIGH -- e-signature legal requirements are well-documented. The ESIGN Act and eIDAS regulation are clear about requirements.

**Feature area:** Document Signing

---

### M6: Webhook Security and Payment Fraud

**What goes wrong:** The Stripe webhook endpoint accepts forged events because it does not verify Stripe's webhook signature. An attacker sends a fake `customer.subscription.updated` event, granting themselves a premium subscription. Alternatively, the webhook endpoint is not rate-limited and an attacker floods it with events, causing a denial of service.

**Why it happens:** Webhook signature verification requires extracting the `Stripe-Signature` header and validating it against the webhook signing secret. Skipping this step during development is common, and it sometimes makes it to production.

#### Consequences

- Free premium access for attackers
- Revenue loss from forged subscription events
- Potential data corruption if forged events trigger account state changes

#### Warning Signs

- Webhook endpoint that does not call `stripe.webhooks.constructEvent()` with the signing secret
- No rate limiting on the webhook endpoint
- Webhook endpoint accessible without HTTPS

#### Prevention

1. Always verify Stripe webhook signatures using the official SDK
2. Rate-limit the webhook endpoint
3. Use Stripe's test mode to verify the full webhook flow before going live
4. Log all webhook events for audit purposes
5. Implement an event deduplication check (store event IDs, reject duplicates)

**Confidence:** HIGH -- Stripe's documentation explicitly warns about this.

**Feature area:** Billing

---

## Minor Pitfalls

Mistakes in this category cause annoyance or minor UX issues but are straightforward to fix.

### N1: Editor State Loss on Browser Tab Close

**What goes wrong:** The user is editing a document. They close the browser tab or navigate away. The editor had unsaved changes that were in the CRDT local state but not yet persisted to IPNS. Those changes are lost.

#### Prevention

1. Implement `beforeunload` handler that warns users about unsaved changes
2. Use IndexedDB (via Yjs's y-indexeddb provider) to persist CRDT state locally as a buffer. On tab reopen, recover from IndexedDB
3. Debounce IPNS saves but save CRDT state to IndexedDB on every change (IndexedDB writes are fast and local)

**Feature area:** Document Editors

---

### N2: Key Wrapping Cost Scaling with Team Size

**What goes wrong:** Every file key and folder key in a team vault is ECIES-wrapped for each team member's public key. A team of 50 members means 50 ECIES wrapping operations per file upload. ECIES (secp256k1) is computationally expensive compared to AES.

#### Prevention

1. Use a two-level key hierarchy: wrap individual file/folder keys with the team's symmetric Per-Team Key (PTK), and wrap only the PTK for each member's public key. This reduces per-file ECIES operations from N to 1
2. This is the standard approach used by Keybase, Tresorit, and Proton for team vaults

**Feature area:** Team Accounts

---

### N3: Crypto Payment Integration Complexity

**What goes wrong:** Adding cryptocurrency payment options (for a Web3-aligned product) introduces exchange rate volatility, transaction confirmation delays, and a completely separate payment infrastructure alongside Stripe.

#### Prevention

1. Defer crypto payments to a later milestone. Start with Stripe only
2. If crypto payments are required, use a payment processor that handles crypto-to-fiat conversion (e.g., Coinbase Commerce, BTCPay Server) rather than managing wallets directly
3. Never store crypto payment details in the same database as vault metadata

**Feature area:** Billing

---

### N4: Certificate Management for Document Signing

**What goes wrong:** If using PKI-based document signing (X.509 certificates), certificate expiration and renewal become operational burdens. Expired certificates invalidate all signatures made with them unless timestamps were applied.

#### Prevention

1. Always use a timestamp authority (TSA) when creating signatures. This ensures signatures remain valid even after the signing certificate expires
2. Use a managed certificate service rather than self-hosting a CA
3. If using the existing Web3Auth keypair for signing, skip certificates entirely and use a simpler attestation model

**Feature area:** Document Signing

---

## Phase-Specific Warnings

| Phase Topic                   | Likely Pitfall                                                                                 | Severity | Mitigation                                                                                                               |
| ----------------------------- | ---------------------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------ |
| Document editor selection     | Choosing TipTap/Hocuspocus because of DX, then discovering it requires plaintext server access | Critical | Evaluate encryption compatibility before choosing an editor. Build a proof-of-concept with encrypted Yjs transport first |
| CRDT integration with IPNS    | Autosave frequency conflicts with IPNS publish latency                                         | Critical | Separate real-time CRDT sync from IPNS persistence. Use a debounced save queue                                           |
| Team vault key hierarchy      | Single team key without per-epoch rotation leads to forward secrecy violations                 | Critical | Design the key epoch system before building team features. Model after Keybase's per-team-key architecture               |
| Team member removal           | Forgetting to rotate keys on member removal                                                    | Critical | Key rotation on member removal must be a hard requirement in the spec, not an enhancement                                |
| Admin recovery                | Adding server-side recovery key that breaks ZK                                                 | Critical | Design recovery as ECIES-wrapped-for-admin, never plaintext on server                                                    |
| Billing webhook handling      | Non-idempotent webhook processing causing state corruption                                     | Moderate | Implement event deduplication from day one                                                                               |
| Billing enforcement           | Server cannot inspect content to enforce quotas                                                | Moderate | Enforce quotas at API level (upload size, pin count) not content level                                                   |
| Document signing legal claims | Claiming legal validity without proper identity verification or TSA                            | Moderate | Label as "cryptographic attestation" unless proper PKI is integrated                                                     |
| Spreadsheet scope             | Treating sheets as "just another editor"                                                       | Moderate | Scope M3 to documents only, or budget 3x for sheets/slides                                                               |
| Large document performance    | Encrypting full document state on every save                                                   | Moderate | Use incremental (diff-based) encryption and Web Workers                                                                  |

---

## Anti-Patterns to Avoid

### "Just Encrypt the Yjs Updates on the Server"

**Wrong:** Encrypt CRDT operations at the server before storing them.
**Why wrong:** The server has seen the plaintext operations. Encryption at rest does not help if the server processed plaintext in transit.
**Right:** Encrypt on the client before sending. The server only ever sees ciphertext.

### "Use a Shared Password for the Team"

**Wrong:** Team members share a password that derives a symmetric key.
**Why wrong:** Password cannot be rotated without disrupting all members. No way to revoke a single member's access. Password strength is the weakest link.
**Right:** Each member's access is gated by their own ECIES public key wrapping a per-team key.

### "Let the Server Enforce Document Permissions"

**Wrong:** Server checks user roles before decrypting and serving document content.
**Why wrong:** Server cannot decrypt document content (ZK). Permission enforcement must happen at the key distribution level: if a user does not have the wrapped key for a document, they cannot decrypt it, regardless of server-side role checks.
**Right:** Permissions are enforced cryptographically. Access = having the key. Server-side role checks are a defense-in-depth layer, not the primary access control.

### "Stripe Is Our Source of Truth for Access"

**Wrong:** Check Stripe subscription status on every API request to determine if the user can access their vault.
**Why wrong:** Stripe API latency (100-500ms) on every request is unacceptable. Stripe rate limits will be hit. If Stripe is down, all users lose access.
**Right:** Sync Stripe state to a local subscription table via webhooks. Query the local table for access checks. Reconcile periodically.

---

## Open Questions Needing Deeper Research

1. **CRDT compaction in encrypted context:** Can Yjs checkpoints be created without the server seeing the document state? How does compaction interact with the IPNS content-addressed storage model?

2. **Real-time collaboration latency budget:** What is the acceptable latency for encrypted CRDT operations? Users expect sub-100ms keystroke propagation; encryption adds overhead. Is this achievable with Web Workers + AES-GCM?

3. **IPNS record size limits:** As team metadata grows (N members x M wrapped keys), do IPNS records have practical size limits? What happens when a team vault's metadata exceeds the IPNS record payload?

4. **Offline editing with teams:** How do offline edits work when the team key has been rotated while a member was offline? The member's local CRDT state is encrypted with the old key; they need the new key to publish.

5. **Cross-document references:** In spreadsheets, formulas can reference other sheets/documents. In an encrypted system, this requires access to multiple decryption keys simultaneously. How does this interact with the per-folder key hierarchy?

---

## Sources

- [CryptPad Architecture](https://github.com/cryptpad/cryptpad/blob/main/docs/ARCHITECTURE.md) -- encrypted collaboration architecture reference
- [ChainPad Algorithm](https://github.com/cryptpad/chainpad) -- CRDT/blockchain-based collaborative editing
- [Keybase Team Crypto](https://book.keybase.io/docs/teams/crypto) -- team key management with per-team keys and rotation
- [Proton Docs Introduction](https://proton.me/blog/docs-proton-drive) -- E2EE collaborative document editing challenges
- [Yjs Documentation](https://docs.yjs.dev/) -- CRDT implementation, subdocuments, and providers
- [Stripe Webhook Documentation](https://docs.stripe.com/billing/subscriptions/webhooks) -- idempotent webhook processing
- [Stripe PCI Compliance Guide](https://stripe.com/guides/pci-compliance) -- payment security requirements
- [ESIGN Act and UETA](https://www.docusign.com/blog/are-electronic-signatures-legal) -- e-signature legal requirements
- [Tresorit Security](https://tresorit.com/security) -- ZK team key management reference
- [Bitwarden Zero-Knowledge Encryption](https://bitwarden.com/resources/zero-knowledge-encryption-white-paper/) -- ZK architecture patterns
- [ChainSafe E2E Encrypted Collaborative Editing](https://research.chainsafe.io/featured/Publications/E2E-Encrypted-Doc/) -- academic research on encrypted CRDT collaboration
- [DigiCert Timestamping Best Practices](https://www.digicert.com/blog/best-practices-timestamping) -- TSA integration for document signing
