# Technology Stack: Milestone 3

**Project:** CipherBox - Encrypted Productivity Suite
**Researched:** 2026-02-11
**Scope:** Document/Spreadsheet/Presentation editors, Team accounts, Billing, Document signing

## Executive Summary

M3 transforms CipherBox from encrypted file storage into an encrypted productivity suite.
The core constraint remains: all content is client-side encrypted and the server never sees
plaintext. This constrains every technology choice -- editors must operate entirely in-browser
on decrypted content, collaboration must use E2EE CRDTs (not server-mediated OT), and document
signing must work with client-side cryptographic primitives.

The recommended stack centers on TipTap 3.x (rich text), Univer (spreadsheets), a custom
TipTap-based slide editor (presentations), CASL (authorization), Stripe + NOWPayments
(billing), and LibPDF + Web Crypto (document signing).

---

## 1. Document Editor (Rich Text)

### Recommended: TipTap 3.x + Yjs

| Package                                  | Version | Purpose                                                    |
| ---------------------------------------- | ------- | ---------------------------------------------------------- |
| `@tiptap/react`                          | ^3.19.0 | React integration for TipTap editor                        |
| `@tiptap/starter-kit`                    | ^3.19.0 | Bundle of essential extensions (bold, italic, lists, etc.) |
| `@tiptap/extension-collaboration`        | ^3.19.0 | Yjs-based CRDT collaboration                               |
| `@tiptap/extension-collaboration-cursor` | ^3.19.0 | Shared cursor awareness                                    |
| `@tiptap/extension-table`                | ^3.19.0 | Table editing support                                      |
| `@tiptap/extension-image`                | ^3.19.0 | Inline image support                                       |
| `@tiptap/extension-placeholder`          | ^3.19.0 | Placeholder text                                           |
| `@tiptap/extension-text-align`           | ^3.19.0 | Text alignment                                             |
| `@tiptap/extension-underline`            | ^3.19.0 | Underline formatting                                       |
| `@tiptap/extension-color`                | ^3.19.0 | Text color                                                 |
| `@tiptap/extension-highlight`            | ^3.19.0 | Text highlighting                                          |
| `yjs`                                    | ^13.x   | CRDT data structure for conflict-free sync                 |
| `y-indexeddb`                            | ^9.x    | Offline persistence for Yjs documents                      |

**Confidence:** HIGH -- TipTap 3.0 is stable (confirmed Feb 2026), actively maintained, and
the de facto standard for React rich text editors.

**Why TipTap over alternatives:**

| Editor            | Why Not                                                                               |
| ----------------- | ------------------------------------------------------------------------------------- |
| Slate.js          | Lower-level API, more work to build equivalent UX. No built-in collaboration.         |
| Quill             | Older architecture, less extensible, weaker TypeScript support.                       |
| Lexical (Meta)    | Newer but smaller extension ecosystem. Less community adoption for production apps.   |
| CKEditor 5        | Proprietary collaboration server. GPL license requires open-sourcing derivative work. |
| ProseMirror (raw) | TipTap IS ProseMirror with a better DX layer. No reason to go lower.                  |

**Zero-knowledge architecture fit:**

TipTap + Yjs is uniquely suited for CipherBox because:

1. Yjs is a CRDT -- it does not require a central server to mediate changes (unlike OT).
2. Yjs document state is a binary blob (`Y.encodeStateAsUpdate()`) that can be
   AES-256-GCM encrypted before storage/transmission.
3. The Yjs E2EE pattern is documented and used in production (Proton Docs uses Yjs with E2EE).
4. Offline-first: y-indexeddb persists the encrypted Yjs doc locally; sync happens
   when peers reconnect.

**Integration with existing stack:**

- Yjs doc binary is encrypted with AES-256-GCM using a per-document `fileKey` (same
  pattern as existing file encryption).
- Encrypted Yjs state is stored as an IPFS blob (same as files).
- Document metadata (name, type, lastModified) lives in the folder IPNS record.
- No server-side changes needed for basic single-user editing. Team collaboration
  requires a thin WebSocket relay (see Architecture note below).

### Collaboration Relay (for team editing)

| Package                | Version | Purpose                                |
| ---------------------- | ------- | -------------------------------------- |
| `@hocuspocus/server`   | ^3.4.4  | WebSocket server for Yjs sync          |
| `@hocuspocus/provider` | ^3.4.4  | Client-side WebSocket provider for Yjs |

**Architecture note:** For team collaboration, Hocuspocus acts as a _dumb relay_. It forwards
encrypted Yjs update blobs between connected clients. The server never decrypts content.
Clients decrypt updates using the shared document key (distributed via ECIES re-wrapping,
same as M2 file sharing). Hocuspocus hooks validate authentication and authorization but
never touch plaintext.

---

## 2. Spreadsheet Editor

### Recommended: Univer Sheets

| Package                       | Version | Purpose                              |
| ----------------------------- | ------- | ------------------------------------ |
| `@univerjs/core`              | ^0.15.x | Core engine                          |
| `@univerjs/design`            | ^0.15.x | Design system / theming              |
| `@univerjs/engine-render`     | ^0.15.x | Canvas rendering engine              |
| `@univerjs/engine-formula`    | ^0.15.x | Formula calculation engine           |
| `@univerjs/sheets`            | ^0.15.x | Spreadsheet data model               |
| `@univerjs/sheets-ui`         | ^0.15.x | Spreadsheet UI components            |
| `@univerjs/sheets-formula`    | ^0.15.x | Formula integration                  |
| `@univerjs/sheets-formula-ui` | ^0.15.x | Formula bar UI                       |
| `@univerjs/sheets-numfmt`     | ^0.15.x | Number formatting                    |
| `@univerjs/sheets-numfmt-ui`  | ^0.15.x | Number format UI                     |
| `@univerjs/docs`              | ^0.15.x | Required dependency for cell editing |
| `@univerjs/docs-ui`           | ^0.15.x | Required dependency for cell editing |
| `@univerjs/ui`                | ^0.15.x | Generic UI framework                 |

**Confidence:** MEDIUM -- Univer is the most capable open-source spreadsheet framework but
is still pre-1.0 (0.15.x). APIs may change between minor versions. However, it is actively
maintained with releases every few days.

**Why Univer over alternatives:**

| Library           | Why Not                                                                                |
| ----------------- | -------------------------------------------------------------------------------------- |
| FortuneSheet      | Smaller community, fewer features (no conditional formatting, limited formulas).       |
| Handsontable      | Commercial license required for production. Not truly open source.                     |
| react-spreadsheet | Too simple -- no formula engine, no formatting, no charts. Data grid, not spreadsheet. |
| AG Grid           | Data grid, not spreadsheet. No formula bar, cell merging, etc.                         |
| Jspreadsheet CE   | jQuery-era architecture, weak TypeScript support.                                      |

**Zero-knowledge architecture fit:**

- Univer operates entirely client-side. The spreadsheet data model is a JSON structure
  that can be serialized, encrypted with AES-256-GCM, and stored as an IPFS blob.
- `JSON.stringify(univerInstance.save())` produces the complete spreadsheet state.
- On load: fetch encrypted blob from IPFS, decrypt, `JSON.parse()`, hydrate Univer.
- Formula computation happens client-side -- server never needs access.

**Collaboration caveat:**

Univer's built-in collaboration uses OT (Operational Transformation), which requires a
server to mediate. This conflicts with CipherBox's zero-knowledge model. For M3, recommend
**single-user editing only** for spreadsheets. Multi-user spreadsheet collaboration would
require either:

- Building a Yjs binding for Univer (significant effort, no existing solution)
- Using Univer's OT in a TEE enclave (complex, possibly over-engineered for a demo)

**Recommendation:** Ship spreadsheets as single-user-editable in M3. If team spreadsheet
editing becomes a priority, evaluate building a Yjs adapter in a future milestone.

---

## 3. Presentation Editor (Slides) -- Deferred to M4+

Presentation editing is deferred to M4 or later. No mature, open-source, React-native
slide editor exists, and building a custom one is a multi-month effort that is out of
scope for M3. See ARCHITECTURE.md for the deferral rationale.

When revisited, the recommended approach is a custom TipTap-based slide editor with
`pptxgenjs` for export and `html2canvas` for thumbnails.

---

## 4. Team Accounts and Authorization

### Recommended: CASL + Custom NestJS Guards

| Package         | Version | Side     | Purpose                                    |
| --------------- | ------- | -------- | ------------------------------------------ |
| `@casl/ability` | ^6.7.5  | Shared   | Define and check permissions               |
| `@casl/react`   | ^4.0.0  | Frontend | React components for conditional rendering |
| `nest-casl`     | ^1.9.15 | Backend  | NestJS integration for CASL                |

**Confidence:** HIGH -- CASL is the standard authorization library for the Node.js/NestJS
ecosystem. Well-documented, actively maintained, and explicitly designed for RBAC/ABAC.

**Why CASL over alternatives:**

| Alternative           | Why Not                                                                             |
| --------------------- | ----------------------------------------------------------------------------------- |
| Custom guards only    | Reinventing the wheel. CASL provides a proven, testable abstraction.                |
| casbin                | More complex (policy language), designed for microservices. Overkill for CipherBox. |
| NestJS built-in roles | Too simple. No field-level permissions, no conditions, no client-side sharing.      |

**Role model for CipherBox teams:**

| Role     | Permissions                                                |
| -------- | ---------------------------------------------------------- |
| `owner`  | All operations, billing, member management, delete org     |
| `admin`  | All operations except billing and org deletion             |
| `member` | Create, read, update, delete own files. Read shared files. |
| `viewer` | Read-only access to shared files/folders                   |

**Database additions (TypeORM entities):**

```text
Organization { id, name, createdAt, updatedAt }
OrganizationMember { orgId, userId, role, invitedAt, joinedAt }
OrganizationInvite { orgId, email, role, token, expiresAt }
```

**Zero-knowledge implications:**

Team key management extends M2's sharing model:

- Each organization has an `orgFolderKey` encrypted to each member's public key (ECIES).
- When a member is added, the org owner re-wraps the `orgFolderKey` to the new member's
  public key.
- When a member is removed, key rotation is triggered: new `orgFolderKey`, re-encrypt
  all org folder metadata, re-wrap to remaining members.
- The server stores encrypted keys only. It enforces role-based API access but never
  sees plaintext content.

---

## 5. Billing Integration

### 5A. Stripe (Traditional Payments)

| Package                    | Version | Side     | Purpose                               |
| -------------------------- | ------- | -------- | ------------------------------------- |
| `stripe`                   | ^20.3.1 | Backend  | Stripe API SDK                        |
| `@golevelup/nestjs-stripe` | ^0.9.3  | Backend  | NestJS module with webhook autowiring |
| `@stripe/stripe-js`        | ^5.x    | Frontend | Stripe.js loader                      |
| `@stripe/react-stripe-js`  | ^5.6.0  | Frontend | React Elements components             |

**Confidence:** HIGH -- Stripe is the industry standard. The NestJS integration via
`@golevelup/nestjs-stripe` handles webhook verification and routing automatically.

**Integration approach:**

- Use Stripe Checkout (hosted payment page) for initial subscriptions. Minimizes PCI scope.
- Use Stripe Customer Portal for subscription management (upgrade, downgrade, cancel).
- Webhook handler processes `checkout.session.completed`, `invoice.paid`,
  `customer.subscription.updated`, `customer.subscription.deleted`.
- Store `stripeCustomerId` and `stripeSubscriptionId` on the User/Organization entity.
- Feature gating: check subscription tier in NestJS guards alongside CASL permissions.

**Database additions:**

```text
Subscription { id, orgId, stripeCustomerId, stripeSubscriptionId, tier, status, currentPeriodEnd }
```

### 5B. Crypto Payments (Privacy-Preserving)

| Package                             | Version | Side    | Purpose                |
| ----------------------------------- | ------- | ------- | ---------------------- |
| `@nowpaymentsio/nowpayments-api-js` | ^1.0.x  | Backend | NOWPayments API client |

**Confidence:** MEDIUM -- NOWPayments is a legitimate service with an official npm package,
but the package is less actively maintained than Stripe's SDK.

**Why NOWPayments over alternatives:**

| Alternative             | Why Not                                                                                  |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| BTCPay Server           | Requires self-hosting a Bitcoin full node. Heavy infrastructure for a demo.              |
| CoinGate                | Similar to NOWPayments but smaller JS ecosystem.                                         |
| Direct Web3 (ethers.js) | Requires building your own payment tracking, exchange rate handling, confirmation logic. |
| Coinbase Commerce       | Coinbase is a centralized exchange -- undermines anonymity goal.                         |

**Why NOWPayments:**

- Hosted service -- no infrastructure to manage.
- Supports 350+ cryptocurrencies including BTC, ETH, USDT, USDC.
- REST API with IPN (Instant Payment Notification) webhooks.
- No KYC required for the payer (preserves anonymity).
- 1% fee (competitive with crypto payment processors).

**Integration approach:**

- Create a payment invoice via NOWPayments API when user selects crypto payment.
- Display payment address and QR code to user.
- Backend receives IPN webhook when payment is confirmed.
- Map payment to subscription activation (same tier system as Stripe).
- Crypto payments activate a fixed-duration subscription (e.g., 30 days per payment).

#### Alternative Consideration: BTCPay Server

If the project later needs maximum decentralization (no third-party payment processor),
BTCPay Server is the gold standard. It is self-hosted, open-source, and zero-fee. However,
it requires running a Bitcoin full node (~500GB disk) and optional Lightning node. This
is too heavy for a demo but worth noting for a production roadmap.

---

## 6. Secure Document Signing

### Recommended: LibPDF + Web Crypto API + react-signature-canvas

| Package                  | Version       | Side               | Purpose                                       |
| ------------------------ | ------------- | ------------------ | --------------------------------------------- |
| `@libpdf/core`           | latest (beta) | Shared             | PDF parsing, modification, digital signatures |
| `react-signature-canvas` | ^1.0.7        | Frontend           | Signature drawing pad                         |
| `@signpdf/signpdf`       | ^3.3.0        | Backend (optional) | PDF signing with certificates                 |

**Confidence:** MEDIUM-LOW for LibPDF (beta, APIs may change), HIGH for the overall approach.

**Why LibPDF over alternatives:**

| Alternative                     | Why Not                                                                                  |
| ------------------------------- | ---------------------------------------------------------------------------------------- |
| pdf-lib                         | Last updated 4 years ago (v1.17.1). No digital signature support. No active maintenance. |
| Apryse/Nutrient                 | Commercial. Expensive licensing.                                                         |
| node-signpdf (@signpdf/signpdf) | Good for server-side signing but CipherBox needs client-side signing.                    |

**Why LibPDF:**

- TypeScript-first (designed for TS, not retrofitted).
- Supports PAdES digital signatures (B-B through B-LTA).
- Preserves existing digital signatures during modification (incremental saves).
- Works in both Node.js and the browser from the same code.
- Built by Documenso (the open-source DocuSign alternative) -- real production usage.
- Under active development with frequent releases.

**Zero-knowledge document signing approach:**

CipherBox document signing is fundamentally different from DocuSign because documents
are encrypted. The signing flow:

1. User opens encrypted document in browser (decrypted client-side).
2. User draws signature on `react-signature-canvas` or types/uploads signature image.
3. Client generates a signing keypair (or uses their Web3Auth-derived key).
4. Client creates a cryptographic signature over the document hash using Web Crypto API
   (`crypto.subtle.sign` with the existing secp256k1 key via Web3Auth).
5. The signature + signer's public key + timestamp are embedded in a signature metadata
   record stored alongside the document.
6. For PDF export: LibPDF embeds the digital signature into a rendered PDF.
7. Verification: any party with the signer's public key can verify the signature
   against the document hash.

**Important distinction:** This is a _cryptographic_ signature (proving the signer had
the private key), not just a visual e-signature overlay. CipherBox's existing key
infrastructure (secp256k1 via Web3Auth) makes this natural.

**Database additions:**

```text
DocumentSignature { id, documentId, signerPublicKey, signatureHex, documentHash, signedAt, metadata }
SignatureRequest { id, documentId, requesterId, signerEmail, status, expiresAt }
```

---

## 7. Supporting Infrastructure

### WebSocket Server (for collaboration relay)

The existing NestJS backend should be extended with a WebSocket gateway for Hocuspocus.

| Package               | Version | Side    | Purpose                  |
| --------------------- | ------- | ------- | ------------------------ |
| `@nestjs/websockets`  | ^11.x   | Backend | NestJS WebSocket support |
| `@nestjs/platform-ws` | ^11.x   | Backend | WS adapter for NestJS    |

**Note:** Hocuspocus can run as a standalone process or be integrated into the NestJS
application. For CipherBox, running it as a separate process behind the same reverse proxy
is recommended to isolate long-lived WebSocket connections from the REST API.

### Email (for invitations and signature requests)

| Package                  | Version | Side    | Purpose                              |
| ------------------------ | ------- | ------- | ------------------------------------ |
| `@nestjs-modules/mailer` | ^2.x    | Backend | NestJS email integration             |
| `nodemailer`             | ^6.x    | Backend | Email transport (peer dep of mailer) |

**Note:** Required for team invitations and signature request notifications. Use a
transactional email service (Resend, SendGrid, or AWS SES) as the transport.

---

## What NOT to Add

| Technology                 | Why Not                                                                                                                                             |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Socket.IO                  | Hocuspocus uses native WebSockets via `ws`. Adding Socket.IO would duplicate functionality.                                                         |
| MongoDB                    | Document editors do not need a separate document database. Yjs state is stored as encrypted blobs on IPFS. Relational metadata stays in PostgreSQL. |
| Redis Pub/Sub for collab   | Hocuspocus handles multi-instance sync natively. BullMQ + Redis already exists for job queues.                                                      |
| GraphQL                    | REST + OpenAPI (existing pattern) is sufficient. GraphQL adds complexity without clear benefit for CipherBox's API surface.                         |
| Electron                   | Tauri v2 is already chosen for desktop. Do not add Electron.                                                                                        |
| Firebase/Supabase Realtime | Third-party real-time databases conflict with zero-knowledge architecture.                                                                          |
| OT-based collaboration     | Requires server to see document structure. Incompatible with E2EE. Use CRDTs (Yjs).                                                                 |

---

## Installation Summary

### Frontend (apps/web)

```bash
# Document editor
pnpm add @tiptap/react @tiptap/starter-kit @tiptap/pm \
  @tiptap/extension-collaboration @tiptap/extension-collaboration-cursor \
  @tiptap/extension-table @tiptap/extension-image @tiptap/extension-placeholder \
  @tiptap/extension-text-align @tiptap/extension-underline \
  @tiptap/extension-color @tiptap/extension-highlight \
  yjs y-indexeddb @hocuspocus/provider

# Spreadsheet editor
pnpm add @univerjs/core @univerjs/design @univerjs/engine-render \
  @univerjs/engine-formula @univerjs/sheets @univerjs/sheets-ui \
  @univerjs/sheets-formula @univerjs/sheets-formula-ui \
  @univerjs/sheets-numfmt @univerjs/sheets-numfmt-ui \
  @univerjs/docs @univerjs/docs-ui @univerjs/ui

# Presentation editor
pnpm add pptxgenjs html2canvas

# Authorization
pnpm add @casl/ability @casl/react

# Billing (frontend)
pnpm add @stripe/stripe-js @stripe/react-stripe-js

# Document signing
pnpm add @libpdf/core react-signature-canvas
```

### Backend (apps/api)

```bash
# Billing
pnpm add stripe @golevelup/nestjs-stripe \
  @nowpaymentsio/nowpayments-api-js

# Authorization
pnpm add @casl/ability nest-casl

# Collaboration relay
pnpm add @hocuspocus/server @nestjs/websockets @nestjs/platform-ws

# Email (invitations, signature requests)
pnpm add @nestjs-modules/mailer nodemailer
pnpm add -D @types/nodemailer
```

---

## Alternatives Considered (Full Matrix)

| Category            | Recommended            | Runner-up          | Why Runner-up Lost                                            |
| ------------------- | ---------------------- | ------------------ | ------------------------------------------------------------- |
| Rich text editor    | TipTap 3.x             | Lexical (Meta)     | Smaller extension ecosystem, less community proof             |
| CRDT engine         | Yjs                    | Automerge          | Yjs is faster, larger ecosystem, TipTap integration built-in  |
| Spreadsheet         | Univer                 | FortuneSheet       | Univer has formula engine, conditional formatting, active dev |
| Slides              | Custom (TipTap)        | reveal.js wrapper  | reveal.js is a viewer, not an editor                          |
| Authorization       | CASL                   | casbin             | casbin is over-engineered for single-app RBAC                 |
| Traditional billing | Stripe                 | Paddle             | Stripe has better NestJS integration, larger ecosystem        |
| Crypto billing      | NOWPayments            | BTCPay Server      | BTCPay requires self-hosted Bitcoin node                      |
| PDF signing         | LibPDF                 | pdf-lib            | pdf-lib abandoned (4yr old), no digital signature support     |
| Signature pad       | react-signature-canvas | SurveyJS signature | react-signature-canvas is focused, lightweight, typed         |

---

## Version Verification Log

All versions verified via npm/web search on 2026-02-11:

| Package                           | Verified Version | Source                                        |
| --------------------------------- | ---------------- | --------------------------------------------- |
| @tiptap/react                     | 3.19.0           | npm (published 2026-02-05)                    |
| @hocuspocus/server                | 3.4.4            | npm (published 2026-01-27)                    |
| @univerjs/sheets-ui               | 0.15.1           | npm (published 2026-02-08)                    |
| stripe                            | 20.3.1           | npm (published 2026-02-07)                    |
| @stripe/react-stripe-js           | 5.6.0            | npm (published 2026-01-30)                    |
| @casl/ability                     | 6.7.5            | npm (published 2026-02-11)                    |
| @golevelup/nestjs-stripe          | 0.9.3            | npm (published ~Aug 2025)                     |
| @signpdf/signpdf                  | 3.3.0            | npm (published ~Jan 2026)                     |
| @libpdf/core                      | beta             | npm (confirmed available, version unverified) |
| @nowpaymentsio/nowpayments-api-js | 1.0.x            | npm (published, exact version unverified)     |
| nest-casl                         | 1.9.15           | npm (published ~Apr 2025)                     |

---

## Confidence Assessment

| Area                                | Confidence | Rationale                                                                      |
| ----------------------------------- | ---------- | ------------------------------------------------------------------------------ |
| Document editor (TipTap + Yjs)      | HIGH       | Stable v3, proven E2EE CRDT pattern (Proton Docs), massive ecosystem           |
| Spreadsheet (Univer)                | MEDIUM     | Pre-1.0, API instability risk, but best open-source option by far              |
| Presentation editor                 | MEDIUM     | Custom build required, no off-the-shelf solution. Approach proven by Gamma.app |
| Team accounts (CASL)                | HIGH       | Standard library, well-documented NestJS patterns                              |
| Stripe billing                      | HIGH       | Industry standard, actively maintained NestJS module                           |
| Crypto billing (NOWPayments)        | MEDIUM     | Official JS SDK exists but less actively maintained than Stripe                |
| Document signing (LibPDF)           | MEDIUM-LOW | Beta library, but TypeScript-first and used in production by Documenso         |
| Document signing (overall approach) | HIGH       | Web Crypto API + secp256k1 is proven; LibPDF is the riskiest piece             |

---

## Sources

- [TipTap 3.0 stable announcement](https://tiptap.dev/blog/release-notes/tiptap-3-0-is-stable)
- [TipTap npm](https://www.npmjs.com/package/@tiptap/react)
- [Yjs documentation](https://docs.yjs.dev/)
- [TipTap collaboration docs](https://tiptap.dev/docs/editor/extensions/functionality/collaboration)
- [Hocuspocus overview](https://tiptap.dev/docs/hocuspocus/getting-started/overview)
- [Univer Sheets documentation](https://docs.univer.ai/guides/sheets)
- [Univer OT architecture blog](https://docs.univer.ai/blog/ot)
- [Univer GitHub](https://github.com/dream-num/univer)
- [FortuneSheet GitHub](https://github.com/ruilisi/fortune-sheet)
- [Gamma.app (ProseMirror presentation editor)](https://discuss.prosemirror.net/t/showcase-gamma-a-presentation-editor-built-in-prosemirror/4834)
- [PptxGenJS](https://gitbrent.github.io/PptxGenJS/)
- [CASL documentation](https://casl.js.org/v4/en/cookbook/roles-with-static-permissions/)
- [CASL NestJS integration](https://docs.nestjs.com/security/authorization)
- [Stripe Node.js SDK](https://www.npmjs.com/package/stripe)
- [Stripe React Elements](https://docs.stripe.com/sdks/stripejs-react)
- [@golevelup/nestjs-stripe](https://golevelup.github.io/nestjs/modules/stripe.html)
- [NOWPayments API JS](https://github.com/NowPaymentsIO/nowpayments-api-js)
- [BTCPay Server](https://btcpayserver.org/)
- [LibPDF documentation](https://libpdf.documenso.com/)
- [LibPDF GitHub](https://github.com/LibPDF-js/core)
- [Documenso (LibPDF creator)](https://documenso.com/)
- [@signpdf/signpdf npm](https://www.npmjs.com/package/@signpdf/signpdf)
- [react-signature-canvas](https://github.com/agilgur5/react-signature-canvas)
- [Proton Docs E2EE with Yjs](https://yjs.dev/) (referenced in Yjs ecosystem)
