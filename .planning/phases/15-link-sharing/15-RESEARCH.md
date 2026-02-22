# Phase 15: Link Sharing - Research

**Researched:** 2026-02-23
**Domain:** Invite link sharing with ephemeral key bridge, ECIES cryptography, NestJS API, React SPA
**Confidence:** HIGH

## Summary

Phase 15 adds invite link sharing to CipherBox, building on the Phase 14 user-to-user sharing infrastructure. The core innovation is an "ephemeral key bridge" -- the sharer generates a temporary secp256k1 keypair, wraps the file/folder key with the ephemeral public key, and puts the ephemeral private key in the URL fragment. When the recipient authenticates and claims the invite, they use the ephemeral private key to unwrap the key, then re-wrap it with their own public key, creating standard Phase 14 Share + ShareKey records.

The existing codebase provides all necessary cryptographic primitives (`wrapKey`, `unwrapKey` from `@cipherbox/crypto`), the Phase 14 Share/ShareKey entities and service, the ShareDialog component, and the Orval-generated API client. The primary work is: (1) a new `ShareInvite` entity/migration, (2) new API endpoints for invite CRUD + claim, (3) an invite landing page route, (4) ShareDialog tabbed interface, and (5) the ephemeral key generation + claim crypto flow.

**Primary recommendation:** Extend the existing `SharesModule` with invite endpoints rather than creating a new module. The invite system is tightly coupled to share creation and should reuse `SharesService.createShare()` during the claim flow.

## Critical Discovery: HashRouter Fragment Collision

**Confidence: HIGH** (verified by reading `apps/web/src/routes/index.tsx`)

The app uses `HashRouter` from react-router-dom, meaning ALL routes are already in the URL fragment (`/#/path`). The planned URL format `app.cipherbox.cc/invite/:token#ephemeralKey` is **incompatible** with HashRouter -- there is only one `#` in a URL.

### Solution Options (ranked)

1. **Encode ephemeral key as query parameter within the hash route:** `/#/invite/:token?key=<ephemeralPrivateKeyHex>` -- The "query string" lives within the hash fragment so it is never sent to the server. React Router parses this via `useSearchParams()`. This is the simplest approach and maintains zero-knowledge since everything after `#` stays client-side.

2. **Use a path segment:** `/#/invite/:token/:ephemeralPrivateKeyHex` -- Simpler parsing but the key is visible in the route definition. Also never sent to server (still within hash).

3. **Switch to BrowserRouter for the invite route only** -- Extremely complex, requires server-side redirect config, not recommended.

**Recommendation: Option 1** -- `/#/invite/:token?key=<hex>`. The entire string after `#` is the hash fragment and is never sent to the server in HTTP requests. React Router's `useSearchParams()` works within HashRouter. This preserves the zero-knowledge property while being simple to implement.

**Security note:** The `?key=...` part is WITHIN the hash fragment (`#/invite/TOKEN?key=KEY`), so it is NOT a real URL query parameter. It never hits the server. Browsers do not send anything after `#` in HTTP requests.

## Standard Stack

### Core (already in codebase)

| Library                       | Version                         | Purpose                                          | Location                        |
| ----------------------------- | ------------------------------- | ------------------------------------------------ | ------------------------------- |
| `@cipherbox/crypto` (eciesjs) | 0.4.16                          | ECIES wrapKey/unwrapKey for ephemeral key bridge | `packages/crypto/src/ecies/`    |
| `@noble/secp256k1`            | 3.0.0 (web), 2.2.3 (crypto pkg) | Ephemeral keypair generation                     | `apps/web/package.json`         |
| TypeORM                       | (existing)                      | ShareInvite entity + migration                   | `apps/api/src/shares/`          |
| NestJS                        | (existing)                      | Controller/service for invite endpoints          | `apps/api/src/shares/`          |
| React Router (HashRouter)     | (existing)                      | `/invite/:token` route                           | `apps/web/src/routes/index.tsx` |
| Orval                         | 7.18.0                          | API client generation                            | `apps/web/orval.config.ts`      |

### No New Dependencies Required

All cryptographic operations use existing primitives:

- `wrapKey(plainKey, ephemeralPubKey)` -- wrap with ephemeral public key
- `unwrapKey(wrappedKey, ephemeralPrivKey)` -- unwrap with ephemeral private key (from URL)
- `wrapKey(plainKey, recipientPubKey)` -- re-wrap with recipient's own public key
- `secp256k1.utils.randomPrivateKey()` -- generate ephemeral private key
- `secp256k1.getPublicKey(privKey, false)` -- derive uncompressed public key

## Architecture Patterns

### Recommended Project Structure

```
apps/api/src/shares/
  entities/
    share.entity.ts          # (existing)
    share-key.entity.ts       # (existing)
    share-invite.entity.ts    # NEW
    index.ts                  # UPDATE: export ShareInvite
  dto/
    create-invite.dto.ts      # NEW
    claim-invite.dto.ts       # NEW
    invite-response.dto.ts    # NEW
  shares.controller.ts        # UPDATE: add invite endpoints
  shares.service.ts           # UPDATE: add invite methods
  shares.module.ts            # UPDATE: register ShareInvite entity

apps/api/src/migrations/
  1740400000000-AddShareInvites.ts  # NEW

apps/web/src/
  routes/
    index.tsx                 # UPDATE: add /invite/:token route
    InvitePage.tsx             # NEW: invite landing page
  components/file-browser/
    ShareDialog.tsx            # UPDATE: add tabbed interface
    InviteLinkTab.tsx          # NEW: invite link tab content
  services/
    share.service.ts           # UPDATE: add invite service functions
    invite.service.ts          # NEW: or extend share.service.ts
  styles/
    share-dialog.css           # UPDATE: add tab styles
    invite-page.css            # NEW: invite landing page styles
```

### Pattern 1: ShareInvite Entity

**What:** New database entity for ephemeral invite links
**When to use:** Storing invite metadata that links sharer to wrapped key ciphertext

```typescript
// Source: Modeled after device-approval.entity.ts (auto-expire pattern) + share.entity.ts
@Entity('share_invites')
export class ShareInvite {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index({ unique: true })
  @Column({ type: 'varchar', length: 44, name: 'token' })
  token!: string; // URL-safe base64, ~22 chars (128 bits entropy)

  @Column({ type: 'uuid', name: 'sharer_id' })
  sharerId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'sharer_id' })
  sharer!: User;

  @Column({ type: 'varchar', length: 10, name: 'item_type' })
  itemType!: 'folder' | 'file';

  @Column({ type: 'varchar', length: 255, name: 'ipns_name' })
  ipnsName!: string;

  @Column({ type: 'varchar', length: 255, name: 'item_name' })
  itemName!: string;

  // The item key wrapped with the EPHEMERAL public key (not recipient's key)
  @Column({ type: 'bytea', name: 'encrypted_key' })
  encryptedKey!: Buffer;

  // Child keys (subfolder/file keys) wrapped with ephemeral public key
  // Stored as JSON array for simplicity (not a separate table)
  @Column({ type: 'jsonb', name: 'encrypted_child_keys', nullable: true })
  encryptedChildKeys!: Array<{
    keyType: 'file' | 'folder';
    itemId: string;
    encryptedKey: string; // hex
  }> | null;

  @Column({ type: 'varchar', length: 20, default: 'active' })
  status!: 'active' | 'claimed' | 'revoked';

  @Column({ type: 'integer', name: 'max_claims', default: 1 })
  maxClaims!: number;

  @Column({ type: 'integer', name: 'claim_count', default: 0 })
  claimCount!: number;

  @Column({ type: 'uuid', name: 'claimed_by', nullable: true })
  claimedBy!: string | null;

  @Column({ type: 'timestamp', name: 'expires_at' })
  expiresAt!: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;
}
```

### Pattern 2: Auto-Expire on Read (Phase 12.4 Pattern)

**What:** Delete expired records when querying, not via cron job
**When to use:** TTL-based cleanup for short-lived records

```typescript
// Source: apps/api/src/device-approval/device-approval.service.ts lines 72-76
// Pattern: check expiry when reading, update status inline
async getInvite(token: string): Promise<ShareInvite | null> {
  const invite = await this.inviteRepo.findOne({ where: { token } });
  if (!invite) return null;

  // Auto-expire if past TTL
  if (invite.status === 'active' && invite.expiresAt < new Date()) {
    await this.inviteRepo.remove(invite); // hard delete (not soft delete like device approvals)
    return null;
  }
  return invite;
}
```

### Pattern 3: Ephemeral Key Bridge (Claim Flow)

**What:** The core cryptographic flow for claiming an invite link
**When to use:** When recipient authenticates and claims the invite

```typescript
// Client-side claim flow (runs in browser after auth)
async function claimInvite(token: string, ephemeralPrivKeyHex: string): Promise<void> {
  // 1. Fetch invite metadata from server
  const invite = await fetchInviteByToken(token);

  // 2. Get recipient's own vault keypair
  const vaultKeypair = useAuthStore.getState().vaultKeypair;
  const ephemeralPrivKey = hexToBytes(ephemeralPrivKeyHex);

  // 3. Unwrap the key using ephemeral private key
  const plaintextKey = await unwrapKey(hexToBytes(invite.encryptedKey), ephemeralPrivKey);

  // 4. Re-wrap with recipient's own public key
  const reWrappedKey = await wrapKey(plaintextKey, vaultKeypair.publicKey);
  plaintextKey.fill(0); // zero sensitive data

  // 5. Re-wrap child keys similarly
  const childKeys = [];
  for (const ck of invite.encryptedChildKeys ?? []) {
    const plainChildKey = await unwrapKey(hexToBytes(ck.encryptedKey), ephemeralPrivKey);
    const reWrapped = await wrapKey(plainChildKey, vaultKeypair.publicKey);
    plainChildKey.fill(0);
    childKeys.push({
      keyType: ck.keyType,
      itemId: ck.itemId,
      encryptedKey: bytesToHex(reWrapped),
    });
  }

  // 6. Zero ephemeral key from memory
  ephemeralPrivKey.fill(0);

  // 7. Send claim to server (creates Share + ShareKey records via Phase 14 infra)
  await claimInviteApi(token, {
    encryptedKey: bytesToHex(reWrappedKey),
    childKeys,
  });
}
```

### Pattern 4: Invite Token Generation

**What:** Generate URL-safe tokens with 128 bits of entropy
**When to use:** Creating invite links

```typescript
// Server-side token generation
import { randomBytes } from 'crypto';

function generateInviteToken(): string {
  // 16 bytes = 128 bits of entropy
  // URL-safe base64: ~22 chars
  return randomBytes(16).toString('base64url');
}
```

### Anti-Patterns to Avoid

- **Storing ephemeral private key on server:** The entire point of the ephemeral key bridge is that the server never sees the ephemeral private key. It lives only in the URL fragment.
- **Using a new NestJS module for invites:** Invites are tightly coupled to shares. Keep them in `SharesModule` to reuse `SharesService.createShare()` during claim.
- **Creating a separate table for invite child keys:** Use JSONB column on the invite table -- invites are short-lived (7 days) and child keys are deleted with the invite on claim. No need for normalized storage.
- **Omitting CREATE TABLE migration:** Per learnings from Phase 14 staging deployment, ALWAYS create a migration file. `synchronize: true` in dev hides missing migrations.

## Don't Hand-Roll

| Problem                      | Don't Build                           | Use Instead                                                      | Why                                                                    |
| ---------------------------- | ------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------- |
| ECIES key wrapping           | Custom ECDH + AES                     | `wrapKey`/`unwrapKey` from `@cipherbox/crypto`                   | Already handles ephemeral keys, HKDF, AES-GCM internally via `eciesjs` |
| secp256k1 keypair generation | Web Crypto or manual curve ops        | `@noble/secp256k1` `utils.randomPrivateKey()` + `getPublicKey()` | Already used in `apps/web/src/lib/web3auth/hooks.ts:86`                |
| URL-safe random tokens       | UUID or custom RNG                    | Node.js `crypto.randomBytes(16).toString('base64url')`           | Proper entropy, URL-safe encoding built-in                             |
| Share creation after claim   | Duplicate share creation logic        | Call `SharesService.createShare()` internally                    | Reuses validation, duplicate detection, key storage                    |
| API client types             | Manual fetch calls                    | `pnpm api:generate` (Orval)                                      | Maintains type safety, auto-generates from OpenAPI spec                |
| Clipboard API                | Manual `document.execCommand('copy')` | `navigator.clipboard.writeText()`                                | Modern API, already in secure context (HTTPS)                          |

## Common Pitfalls

### Pitfall 1: HashRouter Fragment Collision

**What goes wrong:** URL format `app.cipherbox.cc/invite/:token#ephemeralKey` fails because HashRouter uses `#` for routing. The entire path after `#` is the hash route.
**Why it happens:** The app uses `HashRouter` (confirmed in `apps/web/src/routes/index.tsx:9`), not `BrowserRouter`.
**How to avoid:** Use `/#/invite/:token?key=<ephemeralPrivKeyHex>` format. The `?key=` portion is within the hash fragment and parsed by React Router's `useSearchParams()`.
**Warning signs:** URL parsing returns undefined for the ephemeral key, or the route doesn't match.

### Pitfall 2: Missing CREATE TABLE Migration

**What goes wrong:** ShareInvite table doesn't exist in staging/production, migration that modifies it fails.
**Why it happens:** `synchronize: true` in dev auto-creates tables from entities, hiding the missing migration. Only fails when `synchronize: false` in staging/production.
**How to avoid:** ALWAYS create a migration file with `CREATE TABLE IF NOT EXISTS` for new entities. Use timestamp BEFORE any migration that modifies the table.
**Warning signs:** Staging deployment fails with "relation does not exist" error.
**Reference:** `.learnings/2026-02-22-staging-migration-missing-create-table.md`

### Pitfall 3: Entity Registration in AppModule

**What goes wrong:** TypeORM doesn't recognize the new entity, queries fail at runtime.
**Why it happens:** New entity must be added to BOTH the module's `TypeOrmModule.forFeature()` AND the `entities` array in `app.module.ts`.
**How to avoid:** Add `ShareInvite` to:

1. `apps/api/src/shares/shares.module.ts` line 9: `TypeOrmModule.forFeature([Share, ShareKey, ShareInvite, User])`
2. `apps/api/src/app.module.ts` line 28: import and add to entities array (line 69-82)

### Pitfall 4: Ephemeral Key Memory Leaks

**What goes wrong:** Ephemeral private key stays in memory after claim, potential security risk.
**Why it happens:** Key is parsed from URL into a Uint8Array but never zeroed after use.
**How to avoid:** Always `.fill(0)` ephemeral key material in a `finally` block after claim completes. Follow same pattern as `ShareDialog.tsx:368-370` (zeroing itemFolderKey).
**Warning signs:** Phase 14 security review already flagged similar issues with navigation stack key zeroing.

### Pitfall 5: OpenAPI Client Not Regenerated

**What goes wrong:** New invite endpoints exist on the server but the web app has no typed client functions to call them.
**Why it happens:** Must run `pnpm api:generate` after adding/modifying controllers, but it's easy to forget.
**How to avoid:** Run `pnpm api:generate` after implementing any new controller endpoints. Commit the generated files in `apps/web/src/api/`.
**Reference:** `.claude/CLAUDE.md` API Development Workflow section.

### Pitfall 6: Invite Lookup Must Not Require Authentication

**What goes wrong:** The GET endpoint to fetch invite metadata (for the landing page) requires JWT auth, but the user hasn't authenticated yet.
**Why it happens:** The `SharesController` uses `@UseGuards(JwtAuthGuard)` at the class level (line 41).
**How to avoid:** Create the GET invite endpoint WITHOUT `JwtAuthGuard`. Only the CLAIM endpoint requires authentication. Options:

1. Create a separate `InvitesController` without class-level auth guard
2. Use `@Public()` decorator on the GET endpoint (if NestJS module supports it)
3. Create a minimal unauthenticated controller dedicated to invite lookup

### Pitfall 7: Race Condition on Single-Claim

**What goes wrong:** Two recipients click the same link simultaneously, both claim successfully.
**Why it happens:** Read-check-write pattern without locking.
**How to avoid:** Use database-level atomic update: `UPDATE share_invites SET status = 'claimed', claimed_by = :userId, claim_count = claim_count + 1 WHERE token = :token AND status = 'active' AND claim_count < max_claims`. Check `affected === 1`.

## Code Examples

### Ephemeral Keypair Generation (Client-Side)

```typescript
// Source: Pattern from apps/web/src/lib/web3auth/hooks.ts:84-88
import * as secp256k1 from '@noble/secp256k1';
import { bytesToHex } from '@cipherbox/crypto';

function generateEphemeralKeypair(): {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  privateKeyHex: string;
} {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed, 65 bytes
  return {
    privateKey,
    publicKey,
    privateKeyHex: bytesToHex(privateKey),
  };
}
```

### Invite Link Construction

```typescript
function buildInviteUrl(token: string, ephemeralPrivKeyHex: string): string {
  // HashRouter: everything after # is the route, never sent to server
  const base = window.location.origin + window.location.pathname;
  return `${base}#/invite/${token}?key=${ephemeralPrivKeyHex}`;
}
```

### Invite Token Parsing (React Component)

```typescript
import { useParams, useSearchParams } from 'react-router-dom';

function InvitePage() {
  const { token } = useParams<{ token: string }>();
  const [searchParams] = useSearchParams();
  const ephemeralKeyHex = searchParams.get('key');

  // Both token and ephemeralKeyHex are within the hash fragment
  // They are NEVER sent to the server in HTTP requests
}
```

### Migration Pattern

```typescript
// Source: Pattern from apps/api/src/migrations/1740250000000-AddSharesTables.ts
export class AddShareInvites1740400000000 implements MigrationInterface {
  name = 'AddShareInvites1740400000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS "share_invites" (
        "id"                    uuid NOT NULL DEFAULT uuid_generate_v4(),
        "token"                 varchar(44) NOT NULL,
        "sharer_id"             uuid NOT NULL,
        "item_type"             varchar(10) NOT NULL,
        "ipns_name"             varchar(255) NOT NULL,
        "item_name"             varchar(255) NOT NULL,
        "encrypted_key"         bytea NOT NULL,
        "encrypted_child_keys"  jsonb,
        "status"                varchar(20) NOT NULL DEFAULT 'active',
        "max_claims"            integer NOT NULL DEFAULT 1,
        "claim_count"           integer NOT NULL DEFAULT 0,
        "claimed_by"            uuid,
        "expires_at"            TIMESTAMP NOT NULL,
        "created_at"            TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_share_invites" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_share_invites_token" UNIQUE ("token"),
        CONSTRAINT "FK_share_invites_sharer" FOREIGN KEY ("sharer_id")
          REFERENCES "users" ("id") ON DELETE CASCADE ON UPDATE NO ACTION
      )
    `);

    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_share_invites_sharer_id" ON "share_invites" ("sharer_id")`
    );
    await queryRunner.query(
      `CREATE INDEX IF NOT EXISTS "IDX_share_invites_expires_at" ON "share_invites" ("expires_at")`
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`DROP TABLE IF EXISTS "share_invites" CASCADE`);
  }
}
```

### Share Dialog Tab Bar Pattern

```css
/* Tab bar with 2px bottom-border active indicator */
.share-tab-bar {
  display: flex;
  gap: 0;
  border-bottom: var(--border-thickness) solid var(--color-border-dim);
  margin-bottom: var(--spacing-md);
}

.share-tab {
  padding: var(--spacing-xs) var(--spacing-md);
  font-family: var(--font-family-mono);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--color-text-muted);
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  transition:
    color 0.15s ease,
    border-color 0.15s ease;
}

.share-tab:hover {
  color: var(--color-text-secondary);
}

.share-tab--active {
  color: var(--color-green-primary);
  border-bottom-color: var(--color-green-primary);
}

.share-tab:focus-visible {
  outline: 1px solid var(--color-green-primary);
  outline-offset: 1px;
}
```

### Unauthenticated Invite Endpoint Pattern

```typescript
// Option: Separate controller without class-level JwtAuthGuard
@ApiTags('invites')
@Controller('invites')
export class InvitesController {
  constructor(private readonly sharesService: SharesService) {}

  // PUBLIC: No auth required -- used by landing page before login
  @Get(':token')
  @ApiOperation({ summary: 'Get invite status (public)' })
  async getInviteStatus(
    @Param('token') token: string
  ): Promise<{ status: 'active' | 'expired' | 'claimed' | 'revoked' }> {
    // Returns ONLY status -- no file name, no sharer identity (opaque until auth)
    const invite = await this.sharesService.getInviteStatus(token);
    return { status: invite?.status ?? 'expired' };
  }

  // PROTECTED: Requires auth -- claims the invite
  @Post(':token/claim')
  @UseGuards(JwtAuthGuard, ThrottlerGuard)
  @ApiBearerAuth()
  async claimInvite(
    @Request() req: RequestWithUser,
    @Param('token') token: string,
    @Body() dto: ClaimInviteDto
  ): Promise<{ shareId: string }> {
    return this.sharesService.claimInvite(token, req.user.id, dto);
  }
}
```

## Existing Codebase Reference (Phase 14 Foundation)

### Key Files to Understand Before Planning

| File                      | Path                                                       | Relevance                                                   |
| ------------------------- | ---------------------------------------------------------- | ----------------------------------------------------------- |
| Share entity              | `apps/api/src/shares/entities/share.entity.ts`             | ShareInvite claim creates this                              |
| ShareKey entity           | `apps/api/src/shares/entities/share-key.entity.ts`         | Child keys for claimed shares                               |
| SharesService             | `apps/api/src/shares/shares.service.ts`                    | `createShare()` reused during claim                         |
| SharesController          | `apps/api/src/shares/shares.controller.ts`                 | Extend with invite endpoints OR create separate controller  |
| SharesModule              | `apps/api/src/shares/shares.module.ts`                     | Register ShareInvite entity here                            |
| AppModule                 | `apps/api/src/app.module.ts`                               | Register ShareInvite entity + InvitesController module here |
| ShareDialog               | `apps/web/src/components/file-browser/ShareDialog.tsx`     | Add tab interface                                           |
| share.service.ts          | `apps/web/src/services/share.service.ts`                   | Add invite creation + claim functions                       |
| share.store.ts            | `apps/web/src/stores/share.store.ts`                       | May need invite state                                       |
| Routes                    | `apps/web/src/routes/index.tsx`                            | Add `/invite/:token` route                                  |
| wrapKey                   | `packages/crypto/src/ecies/encrypt.ts`                     | Core crypto for ephemeral wrapping                          |
| unwrapKey                 | `packages/crypto/src/ecies/decrypt.ts`                     | Core crypto for ephemeral unwrapping                        |
| AddSharesTables migration | `apps/api/src/migrations/1740250000000-AddSharesTables.ts` | Pattern for new migration                                   |
| DeviceApproval entity     | `apps/api/src/device-approval/device-approval.entity.ts`   | Auto-expire pattern reference                               |

### Existing Modal Component

The Modal component (`apps/web/src/components/ui/Modal.tsx`) supports:

- `title` prop for header text
- Portal rendering
- Escape to close
- Focus trap
- Backdrop click to close
- Default `max-width: 500px` -- CONTEXT specifies widening to 600px for tabs

The ShareDialog currently uses `<Modal>` directly (line 459). The tab interface will be added inside the modal body.

### Route Configuration

Current routes in `apps/web/src/routes/index.tsx`:

- `/` -- Login
- `/files/:folderId?` -- FilesPage
- `/shared` -- SharedPage
- `/settings` -- SettingsPage
- `/dashboard` -- Redirect to /files

The invite route `/invite/:token` is a new addition. It should NOT be wrapped in AppShell (no sidebar) -- it's a standalone landing page like Login.

### CSS Variables Available

From the share-dialog.css, these CSS variables are already in use:

- `--color-green-primary`, `--color-green-dim`, `--color-green-darker`
- `--color-error` (used as `#ef4444` directly in revoke buttons)
- `--color-text-primary`, `--color-text-secondary`, `--color-text-muted`
- `--color-border`, `--color-border-dim`
- `--color-background`
- `--font-family-mono`, `--font-size-xs`, `--font-size-sm`
- `--spacing-xs`, `--spacing-sm`, `--spacing-md`
- `--border-thickness`
- `--glow-green`

## State of the Art

| Old Approach                     | Current Approach                  | When Changed     | Impact                                                 |
| -------------------------------- | --------------------------------- | ---------------- | ------------------------------------------------------ |
| Direct share only (paste pubkey) | + Invite link sharing             | Phase 15         | Users can share without knowing recipient's public key |
| Proxy re-encryption              | ECIES re-wrapping (unwrap + wrap) | Phase 14 design  | Simpler, same security, already implemented            |
| Unauthenticated web viewer       | Invite model (account required)   | Phase 15 discuss | Simpler security surface, user acquisition funnel      |

## Claim Flow Architecture Detail

### Server-Side Claim Logic

The claim endpoint should:

1. **Validate invite** -- token exists, status is 'active', not expired
2. **Atomic status update** -- `UPDATE ... SET status='claimed', claimed_by=:userId WHERE status='active'` to prevent race conditions
3. **Create Share record** -- reuse parts of `SharesService.createShare()` but with different inputs (no recipientPublicKey lookup needed since we have userId)
4. **Create ShareKey records** -- from the re-wrapped child keys sent by the client
5. **Return shareId** -- client navigates to shared content

### Client-Side Claim Logic

After authentication on the invite page:

1. Parse `token` from URL params and `key` from search params
2. Fetch invite to verify it's still active (lightweight check)
3. Get recipient's vault keypair from auth store
4. Unwrap `invite.encryptedKey` with ephemeral private key
5. Re-wrap with recipient's public key
6. Do the same for all `encryptedChildKeys`
7. POST claim with re-wrapped keys
8. Navigate to `/files` or directly to the shared item via `/shared`

## Open Questions

1. **Should the invite GET endpoint return encrypted_key?**
   - What we know: The client needs the encrypted key ciphertext to unwrap it after auth. But the GET endpoint is unauthenticated.
   - What's unclear: Should we return encrypted_key in the public GET (since it's useless without the ephemeral private key), or require a second authenticated GET?
   - Recommendation: Return encrypted_key in the public GET. It's encrypted with the ephemeral key and completely useless without the fragment. This avoids an extra round-trip after auth. The only "leakage" is that someone with the server token can see there IS an invite, which is already implied by the token existing.

2. **Tab state persistence in ShareDialog**
   - What we know: The ShareDialog resets all state on close (lines 215-228).
   - What's unclear: Should the active tab be remembered between opens?
   - Recommendation: Reset to "Direct Share" tab on close (consistent with existing reset behavior).

3. **Self-claim prevention**
   - What we know: Phase 14 prevents self-sharing (line 45-47 in shares.service.ts).
   - What's unclear: Should we prevent the sharer from claiming their own invite link?
   - Recommendation: Yes, check `invite.sharerId !== claimerId` in the claim endpoint. Same self-share prevention pattern.

## Sources

### Primary (HIGH confidence)

- `apps/web/src/routes/index.tsx` -- HashRouter confirmed, route structure verified
- `apps/api/src/shares/` -- Full Phase 14 entity/service/controller structure
- `packages/crypto/src/ecies/` -- wrapKey/unwrapKey implementation verified
- `apps/web/src/components/file-browser/ShareDialog.tsx` -- Current dialog structure
- `apps/api/src/device-approval/device-approval.service.ts` -- Auto-expire pattern
- `apps/api/src/migrations/1740250000000-AddSharesTables.ts` -- Migration pattern
- `.learnings/2026-02-21-phase14-user-to-user-sharing.md` -- Phase 14 lessons
- `.learnings/2026-02-22-staging-migration-missing-create-table.md` -- Migration discipline

### Secondary (MEDIUM confidence)

- `.planning/phases/15-link-sharing/15-CONTEXT.md` -- User decisions and design direction

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- all libraries already in codebase, verified
- Architecture: HIGH -- patterns derived from existing Phase 14 code
- Pitfalls: HIGH -- HashRouter discovery from direct code reading, migration lesson from documented learnings
- Crypto flow: HIGH -- wrapKey/unwrapKey APIs verified in source, test patterns confirmed
- Route structure: HIGH -- directly read routes/index.tsx

**Research date:** 2026-02-23
**Valid until:** 2026-03-23 (stable codebase, no framework version changes expected)
