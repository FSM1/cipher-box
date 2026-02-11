# M3 Architecture: Productivity Suite Integration

**Domain:** Encrypted document editing, team accounts, billing, document signing
**Researched:** 2026-02-11
**Confidence:** MEDIUM (editor integration is novel territory; billing and team patterns are well-established)

---

## Table of Contents

1. [Existing Architecture Summary](#1-existing-architecture-summary)
2. [Document Editors](#2-document-editors)
3. [Team Accounts](#3-team-accounts)
4. [Billing and Payments](#4-billing-and-payments)
5. [Document Signing](#5-document-signing)
6. [New Database Entities](#6-new-database-entities)
7. [Component Boundary Map](#7-component-boundary-map)
8. [Data Flow Changes](#8-data-flow-changes)
9. [Real-Time Collaboration Assessment](#9-real-time-collaboration-assessment)
10. [Suggested Build Order](#10-suggested-build-order)
11. [Sources](#11-sources)

---

## 1. Existing Architecture Summary

Before detailing M3 additions, here is the current system as of M1/M2 completion.

### Current Components

| Component | Technology                    | Role                                           |
| --------- | ----------------------------- | ---------------------------------------------- |
| Web App   | React 18 + Zustand + Vite     | File browser, auth, upload/download, IPNS sync |
| API       | NestJS + TypeORM + PostgreSQL | Auth, vault, IPFS/IPNS relay, TEE coordination |
| Desktop   | Tauri v2 + Rust FUSE          | Transparent encrypted filesystem mount         |
| IPFS      | Pinata (managed pinning)      | Encrypted content storage                      |
| IPNS      | Per-folder Ed25519 keypairs   | Mutable metadata pointers                      |
| TEE       | Phala Cloud / AWS Nitro       | IPNS auto-republishing                         |
| Auth      | Web3Auth + SIWE               | Key derivation and identity                    |

### Key Constraints Preserved in M3

1. **Zero-knowledge server** -- the backend NEVER sees plaintext content or unencrypted keys
2. **Client-side encryption** -- all crypto operations happen in-browser or in-desktop
3. **Per-folder IPNS** -- each folder has its own Ed25519 keypair and AES-256 folder key
4. **ECIES key wrapping** -- all symmetric keys wrapped with user's secp256k1 public key

### By M3, These M2 Features Exist

- File/folder sharing via ECIES re-wrapping (shared folder keys re-encrypted to recipient's public key)
- File versioning (version chains stored in folder metadata)
- Client-side search (encrypted index)
- MFA support

---

## 2. Document Editors

### 2.1 Problem Statement

CipherBox stores encrypted files on IPFS. Currently, editing requires download, decrypt, edit in external app, re-encrypt, re-upload. M3 adds in-browser editing for documents, spreadsheets, and presentations -- while preserving zero-knowledge.

### 2.2 Architecture Decision: Decrypt-Edit-Encrypt Pipeline

The fundamental pattern for all editors is:

```text
1. User opens file in CipherBox
2. Client fetches encrypted blob from IPFS via backend relay
3. Client decrypts with file's AES-256-GCM key
4. Decrypted content loaded into in-browser editor component
5. User edits in the editor (all in-browser, all in RAM)
6. On save: editor exports content -> client encrypts -> uploads to IPFS -> updates IPNS metadata
7. Old CID unpinned
```

This is architecturally identical to the existing "update file" flow (DATA_FLOWS.md section 6.5) but with the editor replacing the download/re-upload step.

### 2.3 Editor Technology Recommendations

#### Rich Text / Documents: Tiptap (built on ProseMirror)

Recommended editor: TipTap 3.x

| Criterion             | Tiptap                        | CKEditor 5               | Quill               |
| --------------------- | ----------------------------- | ------------------------ | ------------------- |
| React integration     | Native (@tiptap/react)        | Adapter needed           | React-Quill wrapper |
| Content format        | JSON (ProseMirror doc)        | Custom model             | Delta JSON          |
| Headless / unstyled   | Yes (matches existing UI)     | No (opinionated UI)      | Partial             |
| Collaboration support | Yjs plugin (optional, future) | Proprietary              | Limited             |
| License               | MIT (core)                    | GPL (open) or commercial | BSD                 |
| Bundle size           | Modular, ~50KB base           | ~300KB+                  | ~40KB               |

**Why Tiptap:**

- Headless architecture -- CipherBox can style the editor to match existing UI
- JSON export via `editor.getJSON()` maps cleanly to encrypt-and-store
- ProseMirror schema enforcement prevents invalid document structures
- Yjs integration available for future real-time collaboration (M4+)
- MIT licensed core is compatible with CipherBox

**Content format:** Tiptap's ProseMirror JSON document is the "file format" for CipherBox documents. This JSON is what gets AES-256-GCM encrypted and stored on IPFS.

```typescript
// Save flow (simplified)
const docJson = editor.getJSON();
const plaintext = new TextEncoder().encode(JSON.stringify(docJson));
const fileKey = crypto.getRandomValues(new Uint8Array(32));
const iv = crypto.getRandomValues(new Uint8Array(12));
const ciphertext = await aesGcmEncrypt(plaintext, fileKey, iv);
// Upload ciphertext to IPFS, wrap fileKey with ECIES, update IPNS
```

#### Spreadsheets: Univer

Recommended editor: Univer (successor to Luckysheet)

| Criterion           | Univer              | Handsontable            | SheetJS           |
| ------------------- | ------------------- | ----------------------- | ----------------- |
| Full spreadsheet UI | Yes                 | Yes                     | No (parsing only) |
| React integration   | Official plugin     | Yes                     | N/A               |
| Formulas            | 400+ Excel formulas | Limited                 | Parsing only      |
| License             | Apache 2.0          | Commercial (CE limited) | Apache 2.0        |
| Client-side only    | Yes                 | Yes                     | Yes               |
| Import/export       | XLSX, CSV           | CSV                     | XLSX, CSV, ODS    |

**Why Univer:**

- Full-featured Excel-like editor that runs entirely client-side
- Apache 2.0 license
- Successor to Luckysheet with active development
- Supports React embedding
- Exports to JSON model that can be encrypted

**Content format:** Univer's workbook model (JSON) is encrypted and stored on IPFS. XLSX import/export happens client-side for interoperability.

#### Presentations: Defer to M4

Recommended approach: Defer slide editing to a later milestone.

Rationale:

- No mature, embeddable, client-side-only presentation WYSIWYG editor exists in the open-source ecosystem
- Reveal.js is a presentation renderer, not an editor
- OnlyOffice has a presentation editor but requires a server-side Document Server (violates zero-knowledge)
- Building a custom slide editor is a multi-month effort
- Documents and spreadsheets cover 90% of productivity use cases

For M3, presentation files (.pptx) can still be stored/shared as encrypted files -- just not edited in-browser.

### 2.4 New File Types in Metadata

Folder metadata `children` entries gain a new field:

```typescript
// Existing file entry (unchanged)
type FileEntry = {
  type: 'file';
  nameEncrypted: string;
  nameIv: string;
  cid: string;
  fileKeyEncrypted: string;
  fileIv: string;
  encryptionMode: 'GCM' | 'CTR';
  size: number;
  // NEW: editor type hint
  editorType?: 'document' | 'spreadsheet' | 'text' | 'image';
  // NEW: native format for editor content
  editorFormat?: 'tiptap-json' | 'univer-json' | 'plaintext';
  created: number;
  modified: number;
};
```

**Important:** `editorType` and `editorFormat` are stored in encrypted metadata (inside the AES-GCM-encrypted folder metadata). The server never sees them.

### 2.5 Integration Points with Existing Components

| Existing Component                                           | Change Required                                    |
| ------------------------------------------------------------ | -------------------------------------------------- |
| `apps/web/src/services/file-crypto.service.ts`               | Add editor content serialization/deserialization   |
| `apps/web/src/services/download.service.ts`                  | Add "open in editor" path alongside download       |
| `apps/web/src/services/upload.service.ts`                    | Add "save from editor" path alongside file upload  |
| `apps/web/src/stores/folder.store.ts`                        | Surface `editorType` for routing to correct editor |
| `apps/web/src/components/file-browser/FileListItem.tsx`      | Add "Edit" action for editable types               |
| New: `apps/web/src/components/editors/DocumentEditor.tsx`    | Tiptap editor wrapper                              |
| New: `apps/web/src/components/editors/SpreadsheetEditor.tsx` | Univer editor wrapper                              |
| New: `apps/web/src/services/editor.service.ts`               | Decrypt-edit-encrypt pipeline orchestration        |
| New: `apps/web/src/stores/editor.store.ts`                   | Editor state (dirty flag, autosave timer)          |

### 2.6 Autosave Strategy

Since saving involves re-encrypting and re-uploading to IPFS (not trivially cheap), autosave should be debounced:

- Autosave interval: 60 seconds after last edit (configurable)
- Manual save: always available
- Dirty indicator: shown when unsaved changes exist
- On close with unsaved changes: confirm dialog
- Each save creates a new CID (by design -- IPFS is append-only)

---

## 3. Team Accounts

### 3.1 Architecture Decision: Shared Team Vaults with Per-Team Key Hierarchy

Following the patterns established by Keeper and Bitwarden for zero-knowledge team vaults.

### 3.2 Key Hierarchy Extension

Current key hierarchy (per-user):

```text
User ECDSA Keypair (secp256k1)
  -> rootFolderKey (AES-256, ECIES-wrapped to user's publicKey)
    -> folderKey per folder (AES-256, ECIES-wrapped to user's publicKey)
      -> fileKey per file (AES-256, ECIES-wrapped to user's publicKey)
```

Extended hierarchy for teams:

```text
Team
  -> teamKey (AES-256, randomly generated on team creation)
    -> teamFolderKey per shared folder (AES-256, ECIES-wrapped to... what?)

Each team member gets:
  -> encryptedTeamKey = ECIES(teamKey, memberPublicKey)
    stored in team_members table
```

**How it works:**

1. Team creator generates a random `teamKey` (AES-256)
2. Creator encrypts `teamKey` with their own `publicKey` and stores it
3. When inviting a member, creator decrypts `teamKey` client-side, then re-encrypts with invitee's `publicKey`
4. Team folders use `teamKey` as the root -- subfolder keys and file keys within team folders are ECIES-wrapped to each member's `publicKey` OR encrypted with `teamKey`

#### Design Decision: Wrap to teamKey, Not Individual publicKeys

For team folders, file keys and folder keys should be encrypted with the `teamKey` rather than individual member public keys. This means:

- Adding a team member = re-encrypt `teamKey` to their public key (one operation)
- Removing a team member = rotate `teamKey` and re-encrypt to remaining members (heavier, but necessary for security)
- Files in team folders encrypted with keys derived from `teamKey`, not per-member

This matches the Keeper/Bitwarden model and avoids the O(members x files) key re-wrapping problem.

### 3.3 Permission Model

```typescript
type TeamRole = 'owner' | 'admin' | 'editor' | 'viewer';

// Capabilities per role
const ROLE_PERMISSIONS = {
  owner: ['read', 'write', 'delete', 'manage_members', 'manage_team', 'billing'],
  admin: ['read', 'write', 'delete', 'manage_members'],
  editor: ['read', 'write'],
  viewer: ['read'],
} as const;
```

**Permission enforcement:**

- **Server-side:** Team membership and role checked on all team-scoped API calls
- **Client-side:** UI hides actions the user's role does not permit
- **Crypto-level:** Viewers receive `teamKey` (read access means decrypt access -- cannot be revoked cryptographically without key rotation)

**Important caveat:** In a zero-knowledge system, read access = possession of decryption key. A viewer who has been removed can still decrypt previously-accessed content. Revoking access requires rotating the `teamKey` and re-encrypting all team folder content. This is an inherent limitation of client-side encryption architectures.

### 3.4 Team IPNS Architecture

Team folders need their own IPNS keypairs, just like user folders. The difference is the IPNS private key management:

- Team folder's `ipnsPrivateKey` is encrypted with `teamKey` (not individual member's public key)
- Any team member with `editor` or higher role can decrypt `teamKey`, then decrypt `ipnsPrivateKey`, then sign IPNS updates
- TEE republishing for team folders: `encryptedIpnsPrivateKey` is still encrypted with TEE public key (unchanged)

### 3.5 New API Endpoints

```text
POST   /teams                       Create team
GET    /teams                       List user's teams
GET    /teams/:id                   Get team details
PATCH  /teams/:id                   Update team (name, settings)
DELETE /teams/:id                   Delete team (owner only)

POST   /teams/:id/members           Invite member
GET    /teams/:id/members           List members
PATCH  /teams/:id/members/:userId   Update role
DELETE /teams/:id/members/:userId   Remove member

POST   /teams/:id/vault/initialize  Init team vault
GET    /teams/:id/vault             Get team vault (encrypted team key)
```

### 3.6 New Database Entities

```sql
CREATE TABLE teams (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  owner_id UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE team_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(20) NOT NULL DEFAULT 'viewer',
  encrypted_team_key BYTEA NOT NULL,  -- ECIES(teamKey, member.publicKey)
  joined_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(team_id, user_id)
);

CREATE TABLE team_vaults (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL UNIQUE REFERENCES teams(id) ON DELETE CASCADE,
  root_ipns_name VARCHAR(255) NOT NULL,
  encrypted_root_folder_key BYTEA NOT NULL,  -- AES-encrypted with teamKey
  encrypted_root_ipns_private_key BYTEA NOT NULL,  -- AES-encrypted with teamKey
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_team_members_user ON team_members(user_id);
CREATE INDEX idx_team_members_team ON team_members(team_id);
```

### 3.7 Integration Points

| Existing Component                              | Change                                      |
| ----------------------------------------------- | ------------------------------------------- |
| `apps/api/src/auth/entities/user.entity.ts`     | Add team membership relation                |
| `apps/api/src/vault/vault.service.ts`           | Extend for team vaults                      |
| `apps/web/src/stores/vault.store.ts`            | Support multiple vaults (personal + team)   |
| `apps/web/src/stores/folder.store.ts`           | Distinguish team vs personal folder context |
| `apps/web/src/components/layout/AppSidebar.tsx` | Show team vaults alongside personal vault   |
| `apps/web/src/services/ipns.service.ts`         | Handle team folder IPNS operations          |
| New: `apps/api/src/teams/` module               | Full teams CRUD + member management         |
| New: `apps/web/src/stores/teams.store.ts`       | Team state management                       |

---

## 4. Billing and Payments

### 4.1 Architecture Decision: Stripe Primary + NOWPayments for Crypto

**Stripe** for traditional payments (credit card, bank transfer):

- Mature NestJS integration via `@golevelup/nestjs-stripe` or direct `stripe` npm package
- Stripe Checkout for hosted payment pages (reduces PCI scope)
- Stripe Billing for subscription management
- Stripe Customer Portal for self-service subscription management
- Webhooks for event-driven subscription lifecycle

**NOWPayments** for cryptocurrency payments:

- Non-custodial (payments go directly to your wallet)
- Supports 350+ cryptocurrencies including BTC, ETH, USDC
- Recurring subscription API available
- REST API with webhook callbacks
- No requirement to hold crypto (auto-conversion to fiat available)

### 4.2 Subscription Tiers

```typescript
type SubscriptionTier = 'free' | 'pro' | 'team';

const TIER_LIMITS = {
  free: {
    storageBytes: 500 * 1024 * 1024, // 500 MiB (current)
    maxFileSize: 100 * 1024 * 1024, // 100 MB
    teamMembers: 0,
    editableDocuments: 3, // Limited editor usage
  },
  pro: {
    storageBytes: 50 * 1024 * 1024 * 1024, // 50 GiB
    maxFileSize: 5 * 1024 * 1024 * 1024, // 5 GB
    teamMembers: 0, // Personal only
    editableDocuments: -1, // Unlimited
  },
  team: {
    storageBytes: 200 * 1024 * 1024 * 1024, // 200 GiB shared
    maxFileSize: 5 * 1024 * 1024 * 1024, // 5 GB
    teamMembers: 25,
    editableDocuments: -1, // Unlimited
  },
} as const;
```

### 4.3 Billing Architecture

```text
Client                  CipherBox API              Stripe / NOWPayments
  |                          |                            |
  |-- Select plan ---------->|                            |
  |                          |-- Create Checkout Session ->|
  |<-- Redirect to Stripe ---|                            |
  |                          |                            |
  |-- Complete payment ----->|           (Stripe hosted)  |
  |                          |                            |
  |                          |<--- Webhook: payment.success
  |                          |-- Update subscription ----->
  |                          |-- Update user tier -------->
  |<-- Tier updated ---------|                            |
```

**Key principle:** Billing metadata (tier, limits) is NOT encrypted. It lives in PostgreSQL as server-side state. The server needs to enforce quotas (storage limits, team member caps). This is acceptable because billing data is not user content.

### 4.4 New API Endpoints

```text
POST   /billing/checkout          Create Stripe Checkout session
POST   /billing/portal            Create Stripe Customer Portal session
GET    /billing/subscription      Get current subscription details
POST   /billing/crypto/invoice    Create NOWPayments invoice
POST   /billing/webhooks/stripe   Stripe webhook receiver
POST   /billing/webhooks/crypto   NOWPayments webhook receiver (IPN)
```

### 4.5 New Database Entities

```sql
CREATE TABLE subscriptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
  stripe_customer_id VARCHAR(255),
  stripe_subscription_id VARCHAR(255),
  nowpayments_subscription_id VARCHAR(255),
  tier VARCHAR(20) NOT NULL DEFAULT 'free',
  status VARCHAR(20) NOT NULL DEFAULT 'active',  -- active, past_due, canceled, trialing
  current_period_start TIMESTAMP,
  current_period_end TIMESTAMP,
  storage_limit_bytes BIGINT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE payment_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subscription_id UUID REFERENCES subscriptions(id),
  provider VARCHAR(20) NOT NULL,  -- 'stripe' or 'nowpayments'
  event_type VARCHAR(50) NOT NULL,
  amount_cents INTEGER,
  currency VARCHAR(10),
  provider_event_id VARCHAR(255),
  raw_payload JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_user ON subscriptions(user_id);
CREATE INDEX idx_subscriptions_stripe ON subscriptions(stripe_customer_id);
```

### 4.6 Integration Points

| Existing Component                                | Change                                        |
| ------------------------------------------------- | --------------------------------------------- |
| `apps/api/src/vault/vault.service.ts`             | Check subscription tier for quota enforcement |
| `apps/api/src/vault/dto/quota.dto.ts`             | Include tier info in quota response           |
| `apps/web/src/stores/quota.store.ts`              | Display tier-aware storage limits             |
| `apps/web/src/components/layout/StorageQuota.tsx` | Show upgrade prompt at limit                  |
| `apps/web/src/routes/SettingsPage.tsx`            | Add billing/subscription management           |
| New: `apps/api/src/billing/` module               | Stripe + NOWPayments integration              |
| New: `apps/web/src/routes/BillingPage.tsx`        | Billing management UI                         |

### 4.7 Usage Metering

Server-side metering (the backend already tracks this):

- Storage used: `pinned_cids` table with `size_bytes`
- Team member count: `team_members` table count
- Editable document count: tracked via a new counter or derived from metadata

The backend already has `volume_audit` and `pinned_cids` tables, so storage metering is largely in place. The subscription tier just adds limit enforcement.

---

## 5. Document Signing

### 5.1 Architecture Decision: Cryptographic Signatures with CipherBox Keys

CipherBox users already have secp256k1 ECDSA keypairs (from Web3Auth). These can produce digital signatures that are cryptographically verifiable. However, these are NOT legally binding qualified electronic signatures (QES) under eIDAS without certificate authority backing.

### 5.2 Signature Levels

| Level                                | CipherBox Support                                                                      | Legal Standing                            |
| ------------------------------------ | -------------------------------------------------------------------------------------- | ----------------------------------------- |
| Simple Electronic Signature (SES)    | Yes -- intent captured, signature stored                                               | Legally recognized in most jurisdictions  |
| Advanced Electronic Signature (AES)  | Partially -- uniquely linked to signer via secp256k1 key, but no qualified certificate | Recognized with higher evidentiary value  |
| Qualified Electronic Signature (QES) | No -- requires qualified certificate from QTSP                                         | Equivalent to handwritten signature in EU |

**Recommendation for M3:** Implement SES/AES-level signing using existing secp256k1 keys. QES requires integration with a Qualified Trust Service Provider (QTSP) and is out of scope for a technology demonstrator.

### 5.3 Signing Flow

```text
1. User opens document to sign
2. Client decrypts document content
3. Client computes SHA-256 hash of plaintext content
4. Client signs hash with user's secp256k1 privateKey:
   signature = ECDSA_sign(SHA256(content), privateKey)
5. Signature metadata stored in folder metadata alongside file entry:
   {
     signerPublicKey: "0x04abc...",
     signatureHex: "0xdef...",
     contentHash: "sha256:abc123...",
     signedAt: 1707000000,
     signedCid: "QmXxx..."  // CID of the content that was signed
   }
6. Signature metadata encrypted with folderKey (part of IPNS metadata)
7. Verification: any user with folder access can verify signature
   matches publicKey and content hash
```

### 5.4 Verification Properties

- **Integrity:** SHA-256 content hash ensures signed content has not been modified
- **Non-repudiation:** ECDSA signature proves the holder of the private key signed
- **Timestamp:** `signedAt` provides temporal evidence (not cryptographic timestamp -- would need TSA for that)
- **Auditability:** The `signedCid` links the signature to a specific IPFS CID

### 5.5 Multi-Signer Support

For documents requiring multiple signatures (e.g., contracts):

```typescript
type SignatureRecord = {
  signerPublicKey: string;
  signatureHex: string;
  contentHash: string;
  signedAt: number;
  signedCid: string;
};

// In file entry metadata
type SignableFileEntry = FileEntry & {
  signatures?: SignatureRecord[];
  requiredSigners?: string[]; // publicKeys of required signers
  signatureStatus?: 'pending' | 'partial' | 'complete';
};
```

### 5.6 Integration Points

| Existing Component                                         | Change                                 |
| ---------------------------------------------------------- | -------------------------------------- |
| Folder metadata schema                                     | Add `signatures` array to file entries |
| `apps/web/src/services/file-crypto.service.ts`             | Add signing and verification functions |
| `apps/web/src/components/file-browser/FileListItem.tsx`    | Show signature status icon             |
| New: `apps/web/src/components/signing/SignaturePanel.tsx`  | UI for signing and viewing signatures  |
| New: `apps/web/src/components/signing/VerifySignature.tsx` | Verification results display           |
| New: `apps/web/src/services/signing.service.ts`            | ECDSA signing/verification logic       |

### 5.7 What This Is NOT

- NOT a replacement for DocuSign/Adobe Sign (no legal compliance framework)
- NOT QES (no qualified certificates)
- NOT timestamped by a TSA (trusted timestamping authority)
- IS a cryptographic proof that a specific key holder approved specific content at a claimed time
- IS verifiable by any party with the signer's public key

---

## 6. New Database Entities

### Summary of All New Tables

| Table            | Module  | Purpose                          |
| ---------------- | ------- | -------------------------------- |
| `teams`          | Teams   | Team metadata                    |
| `team_members`   | Teams   | Membership + encrypted team keys |
| `team_vaults`    | Teams   | Team vault IPNS/key references   |
| `subscriptions`  | Billing | Subscription state per user/team |
| `payment_events` | Billing | Webhook event log                |

### Entities NOT Needed

- No signature table -- signatures are stored in encrypted IPNS metadata (client-side, zero-knowledge)
- No document editor state table -- editor content is just encrypted files on IPFS
- No document type table -- `editorType` is in encrypted metadata

This is intentional: everything that is user content stays in the zero-knowledge layer (IPNS metadata + IPFS content). Only billing and team membership are server-side state.

---

## 7. Component Boundary Map

### New NestJS Modules

```text
apps/api/src/
  teams/
    teams.module.ts
    teams.controller.ts
    teams.service.ts
    entities/
      team.entity.ts
      team-member.entity.ts
      team-vault.entity.ts
    dto/
      create-team.dto.ts
      invite-member.dto.ts
      update-role.dto.ts

  billing/
    billing.module.ts
    billing.controller.ts
    billing.service.ts
    stripe/
      stripe.service.ts
      stripe-webhook.controller.ts
    crypto/
      nowpayments.service.ts
      nowpayments-webhook.controller.ts
    entities/
      subscription.entity.ts
      payment-event.entity.ts
    dto/
      create-checkout.dto.ts
      subscription-response.dto.ts
```

### New Web App Components

```text
apps/web/src/
  components/
    editors/
      DocumentEditor.tsx      -- Tiptap wrapper
      SpreadsheetEditor.tsx    -- Univer wrapper
      EditorToolbar.tsx        -- Shared toolbar (save, close, dirty indicator)
    signing/
      SignaturePanel.tsx       -- Sign document UI
      VerifySignature.tsx      -- Verification results
      SignatureStatus.tsx      -- Inline status indicator
    teams/
      TeamSidebar.tsx          -- Team list in sidebar
      TeamSettings.tsx         -- Team management
      InviteMember.tsx         -- Invite flow
    billing/
      PlanSelector.tsx         -- Tier selection
      BillingPortal.tsx        -- Subscription management

  services/
    editor.service.ts          -- Decrypt-edit-encrypt pipeline
    signing.service.ts         -- ECDSA signing/verification
    teams.service.ts           -- Team key management (client-side crypto)

  stores/
    editor.store.ts            -- Editor state
    teams.store.ts             -- Team membership and keys
    billing.store.ts           -- Subscription state

  routes/
    BillingPage.tsx
    TeamSettingsPage.tsx
```

### Communication Between Components

```text
EditorComponent -> editor.service (decrypt/encrypt) -> upload.service (IPFS) -> ipns.service (metadata)
                                                                            |
SigningComponent -> signing.service (ECDSA) -> folder.store (metadata update) -> ipns.service
                                                                            |
TeamsComponent -> teams.service (key mgmt) -> API /teams/* endpoints -> teams module
                                                                            |
BillingComponent -> API /billing/* endpoints -> billing module -> Stripe/NOWPayments
```

---

## 8. Data Flow Changes

### 8.1 Document Edit Flow (New)

```text
User clicks "Edit" on a .cb-doc file
  -> FileListItem routes to DocumentEditor
  -> editor.service.openDocument(fileEntry)
    -> download.service.fetchEncryptedFile(cid)
    -> file-crypto.service.decryptFile(encrypted, fileKey, iv)
    -> JSON.parse(decrypted) -> Tiptap ProseMirror doc
    -> editor.store.setContent(doc)
  -> Tiptap renders document in editor

User edits...

User clicks "Save" (or autosave triggers)
  -> editor.getJSON() -> JSON.stringify
  -> file-crypto.service.encryptFile(json, newFileKey, newIv)
  -> upload.service.uploadEncrypted(ciphertext)
  -> ipns.service.updateFileEntry(folder, fileEntry, newCid, newKey, newIv)
  -> vault/unpin old CID
```

### 8.2 Team Folder Access Flow (New)

```text
User selects team vault in sidebar
  -> teams.store.selectTeam(teamId)
  -> API GET /teams/:id/vault
    -> Returns encrypted team key (ECIES-wrapped to user's publicKey)
  -> teams.service.decryptTeamKey(encryptedTeamKey, privateKey)
  -> Decrypt team root folder key with teamKey
  -> folder.store.setRoot(teamRootIpnsName, teamRootFolderKey)
  -> Existing folder navigation works identically from here
```

### 8.3 Team Member Invitation Flow (New)

```text
Admin clicks "Invite Member" in team settings
  -> Enter invitee's publicKey (or email -> resolve to publicKey)
  -> teams.service.generateInvite(teamKey, inviteePublicKey)
    -> encryptedTeamKey = ECIES(teamKey, inviteePublicKey)
  -> API POST /teams/:id/members { userId, encryptedTeamKey, role }
  -> Server stores team_members row
  -> Invitee can now access team vault on next login
```

### 8.4 Signing Flow (New)

```text
User opens file and clicks "Sign"
  -> signing.service.signDocument(fileEntry, privateKey)
    -> Download and decrypt file content
    -> contentHash = SHA256(plaintext)
    -> signature = ECDSA_sign(contentHash, privateKey)
    -> Create SignatureRecord
  -> folder.store.addSignature(fileEntry, signatureRecord)
  -> ipns.service.updateFolderMetadata(folder)
```

---

## 9. Real-Time Collaboration Assessment

### 9.1 Verdict: Defer Real-Time Collaboration to M4+

Real-time collaborative editing with end-to-end encryption is a hard problem. Here is why it should be deferred:

### 9.2 Technical Challenges

1. **Encrypted CRDTs:** Standard CRDT implementations (Yjs, Automerge) assume a trusted relay server. For zero-knowledge, updates must be encrypted before transmission. CryptPad solved this with custom encrypted operational transforms, but it took years of development.

2. **Key distribution for real-time:** Every CRDT update needs to be encrypted. Broadcasting encrypted deltas to N users requires either:
   - Encrypt once with shared key (team key approach -- feasible but requires all participants to have key)
   - Encrypt N times for N participants (O(N) per keystroke -- not scalable)

3. **Presence and cursors:** Showing other users' cursor positions requires some form of real-time channel. This could be done without compromising zero-knowledge (encrypted WebSocket messages), but adds significant infrastructure.

4. **Conflict resolution with encryption:** CRDT merge operations need to operate on plaintext. In a zero-knowledge system, the server cannot merge -- all merging must happen client-side, which means every client needs every other client's updates decrypted.

5. **Infrastructure:** Requires WebSocket server for real-time messaging (not currently in the architecture).

### 9.3 What M3 Should Build Instead

Single-user editing with conflict detection:

- User opens document for editing (acquires soft lock)
- If another user opens same document, they see "Currently being edited by [user]"
- Second user can choose to open read-only or force-edit (last-write-wins)
- Lock released on save or close (with timeout fallback)

This is the same model used by SharePoint's "check-out" feature and is pragmatic for a technology demonstrator.

### 9.4 Lock Implementation

```typescript
// Lock stored in team vault metadata (encrypted)
type DocumentLock = {
  lockedBy: string; // publicKey of lock holder
  lockedAt: number; // timestamp
  lockTimeout: number; // auto-release after N seconds (default: 3600)
};
```

Since locks are in IPNS metadata (encrypted), they are eventually consistent (30s polling). This is acceptable for the advisory lock pattern.

---

## 10. Suggested Build Order

Based on dependency analysis, the recommended phase order for M3 is:

### Phase 1: Billing Infrastructure

**Why first:** Billing is independent of other M3 features and the tier system gates access to other features (team member limits, editor limits). Building it first means other features can enforce limits from day one.

**Scope:**

- Stripe integration (checkout, portal, webhooks)
- NOWPayments integration (invoice, IPN webhooks)
- Subscription entity and tier enforcement
- Settings page billing UI

**Dependencies:** None from M3. Uses existing auth and user systems.

### Phase 2: Team Accounts

**Why second:** Team infrastructure is needed before team-aware editors and team document signing make sense.

**Scope:**

- Team CRUD + member management API
- Team key hierarchy (client-side crypto)
- Team vault initialization
- Team sidebar UI and vault switching
- Permission enforcement

**Dependencies:** Billing (for team member limits).

### Phase 3: Document Editors

**Why third:** Editors are the highest-complexity feature and benefit from having teams in place (team members can test editing flows on shared documents).

**Scope:**

- Tiptap document editor integration
- Univer spreadsheet editor integration
- Decrypt-edit-encrypt pipeline
- Autosave with debounce
- Metadata schema extensions (editorType, editorFormat)
- "New Document" / "New Spreadsheet" creation flow
- Advisory locking for team documents

**Dependencies:** Team accounts (for shared document editing context).

### Phase 4: Document Signing

**Why last:** Signing is the simplest M3 feature and is additive to documents that already exist.

**Scope:**

- ECDSA signing service (client-side)
- Signature verification
- Multi-signer workflows
- Signature status UI
- Metadata schema extension (signatures array)

**Dependencies:** Document editors (signing is most useful on editable documents).

### Build Order Rationale

```text
Billing -> Teams -> Editors -> Signing
  |          |         |          |
  |          |         |          Additive, low dependency
  |          |         |
  |          |         Needs teams for shared editing context
  |          |
  |          Needs billing for tier limits
  |
  Independent foundation
```

### Estimated Complexity

| Feature          | Backend Complexity          | Frontend Complexity       | Crypto Complexity                     | Overall |
| ---------------- | --------------------------- | ------------------------- | ------------------------------------- | ------- |
| Billing          | Medium (Stripe/NOWPayments) | Low-Medium                | None                                  | Medium  |
| Teams            | Medium (CRUD + permissions) | Medium                    | High (key hierarchy)                  | High    |
| Document editors | Low (no backend changes)    | High (editor integration) | Low (reuses existing encrypt/decrypt) | High    |
| Document signing | Low (metadata only)         | Low-Medium                | Medium (ECDSA signing)                | Medium  |

### Phases Likely Needing Deeper Research

- **Document editors:** Tiptap and Univer integration specifics, bundle size impact, mobile compatibility
- **Teams:** Key rotation on member removal is complex; needs security review
- **Billing:** NOWPayments recurring API maturity needs validation

### Phases Unlikely to Need More Research

- **Document signing:** Uses existing ECDSA primitives, straightforward implementation
- **Billing (Stripe):** Well-documented, mature ecosystem

---

## 11. Sources

### HIGH Confidence (Official Documentation, Authoritative)

- [Tiptap Editor Documentation](https://tiptap.dev/docs/editor/getting-started/overview)
- [Tiptap JSON/HTML Export](https://tiptap.dev/docs/guides/output-json-html)
- [Tiptap React Integration](https://tiptap.dev/docs/editor/getting-started/install/react)
- [ProseMirror](https://prosemirror.net/)
- [Univer Sheets Documentation](https://docs.univer.ai/guides/sheets)
- [Univer React Integration](https://docs.univer.ai/guides/sheets/getting-started/integrations/react)
- [Yjs CRDT Documentation](https://docs.yjs.dev/)
- [Stripe NestJS Integration](https://github.com/reyco1/nestjs-stripe)
- [NOWPayments Recurring Payments API](https://nowpayments.io/blog/recurring-payments-api)
- [NOWPayments Crypto Subscriptions](https://nowpayments.io/crypto-subscriptions)
- [Keeper Encryption Model](https://docs.keeper.io/en/enterprise-guide/keeper-encryption-model)
- [eIDAS Electronic Signature Guide 2026](https://www.portant.co/post/esign-complete-guide-to-electronic-signatures-in-2026)

### MEDIUM Confidence (Multiple Sources Agreeing)

- [CryptPad CRDT Blueprints](https://blueprints.cryptpad.org/prototypes/crdt/)
- [Bitwarden Organization Vault Encryption](https://community.bitwarden.com/t/the-organization-vault-how-is-its-encryption-managed/54907)
- [CryptPad GitHub](https://github.com/cryptpad/cryptpad)
- [Y-Sweet Realtime CRDT Store](https://github.com/jamsocket/y-sweet)
- [OnlyOffice Document Server](https://github.com/ONLYOFFICE/DocumentServer)
- [Luckysheet to Univer Migration](https://github.com/dream-num/Luckysheet)

### LOW Confidence (Single Source, Needs Validation)

- NOWPayments recurring API maturity for production SaaS (marketing claims, not battle-tested reports)
- Univer stability for production spreadsheet editing (relatively new project)
- CryptPad encrypted CRDT architecture details (high-level overview only, implementation details unclear)
