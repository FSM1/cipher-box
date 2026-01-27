# CipherBox - Claude AI Rules

## Project Context

CipherBox is a **technology demonstrator** for privacy-first encrypted cloud storage using IPFS/IPNS and Web3Auth. It is not a commercial product.

## Documentation Structure

| Document                                                     | Purpose                                    |
| ------------------------------------------------------------ | ------------------------------------------ |
| `00-Preliminary-R&D/Documentation/PRD.md`                    | Product requirements, user journeys, scope |
| `00-Preliminary-R&D/Documentation/TECHNICAL_ARCHITECTURE.md` | Encryption, key hierarchy, system design   |
| `00-Preliminary-R&D/Documentation/API_SPECIFICATION.md`      | Backend endpoints, database schema         |
| `00-Preliminary-R&D/Documentation/DATA_FLOWS.md`             | Sequence diagrams, test vectors            |
| `00-Preliminary-R&D/Documentation/CLIENT_SPECIFICATION.md`   | Web UI, desktop app specs                  |
| `00-Preliminary-R&D/Documentation/IMPLEMENTATION_ROADMAP.md` | Week-by-week development plan              |

## Finalized Specifications

**Current Version:** 1.11.1
**Status:** Finalized (2026-01-20)

### ⚠️ IMPORTANT: Do Not Edit Preliminary/Documentation Files

All files in `00-Preliminary-R&D/Documentation/` are **FINALIZED** specifications (version 1.10.0, status: Finalized). These documents represent the agreed-upon design and should **NOT** be modified.
**If you need to make changes:**

- New implementation documentation should be created in a separate location
- Working notes and updates belong in `.planning/` or project-specific directories
- Do not modify version numbers or content in `00-Preliminary-R&D/Documentation/` unless explicityly authorized.

## Terminology Standards

Always use consistent terminology:

| Correct                   | Avoid                                              |
| ------------------------- | -------------------------------------------------- |
| `publicKey`               | `pubkey`, `user_pubkey`, `ownerPublicKey`          |
| `privateKey`              | `privkey`, `user_private_key`                      |
| `rootFolderKey`           | `rootKey`, `root_folder_key`                       |
| `ipnsName`                | IPNS entry (for identifier)                        |
| `ipnsRecord`              | IPNS entry (for data structure)                    |
| `folderKey`               | `subfolderKey` (unless specifically for subfolder) |
| `fileKey`                 | `file_key`                                         |
| `keyEpoch`                | `epoch`, `key_epoch`                               |
| `encryptedIpnsPrivateKey` | `encrypted_ipns_key`, `ipns_key_encrypted`         |
| `teePublicKey`            | `tee_pubkey`, `TEE_public_key`                     |

## Critical Security Rules

1. **Never** suggest storing `privateKey` in localStorage/sessionStorage
2. **Never** suggest logging sensitive keys
3. **Never** suggest sending unencrypted keys to server
4. **Always** use ECIES for key wrapping
5. **Always** use AES-256-GCM for content encryption
6. The server NEVER has access to plaintext or unencrypted keys
7. **Always** encrypt `ipnsPrivateKey` with TEE public key before sending for republishing
8. TEE decrypts IPNS keys in hardware only, signs, and immediately discards

## API Development Workflow

When working on `apps/api` code:

1. **After modifying API endpoints, DTOs, or controllers**, regenerate the API client to keep the web app in sync:

   ```bash
   pnpm api:generate
   ```

   This command generates the OpenAPI spec from the API, creates the typed client for the web app, and runs lint fixes.

2. **Always run `pnpm api:generate` before completing a feature** that touches the API to ensure type safety across the monorepo.

3. **Commit the regenerated client files** (`apps/web/src/api/`) along with your API changes.

## Code Generation Guidelines

When generating code for CipherBox:

1. Use TypeScript for all JavaScript code
2. Use `Uint8Array` for binary data, not strings
3. Use Web Crypto API for browser encryption
4. Use camelCase for API fields, snake_case for database columns
5. Include proper error handling for crypto operations
6. Clear sensitive data from memory after use

## Architecture Decisions

- **Auth:** Web3Auth for key derivation, CipherBox backend for tokens
- **Storage:** IPFS via Pinata for files, IPNS for metadata (all relayed via CipherBox API)
- **Encryption:** Client-side only, server is zero-knowledge
- **Sync:** IPNS polling (30s interval), no push infrastructure
- **Desktop:** FUSE mount for transparent file access
- **TEE Republishing:** Phala Cloud (primary) / AWS Nitro (fallback) for automatic IPNS republishing every 3 hours
- **Key Epochs:** TEE public keys rotate with 4-week grace period for seamless migration

## Out of Scope (v1.0)

Do not implement or suggest implementations for:

- Billing/payments
- File versioning
- File/folder sharing
- Mobile apps
- Search/indexing
- Collaborative editing
- Team accounts

## Verification with MCP Tools

### Playwright MCP Verification (REQUIRED)

**ALWAYS attempt to verify application changes using Playwright MCP** when it is available. This ensures implemented features work correctly at runtime.

**When to use Playwright MCP:**

- After implementing UI components
- After modifying styles or layouts
- After adding new pages or routes
- After any user-facing changes
- During GSD verification phase

**Verification workflow:**

```typescript
// 1. Navigate to the app
await mcp__playwright__navigate({ url: 'http://localhost:5173' });

// 2. Wait for page to load
await mcp__playwright__wait({ selector: '[data-testid="app-loaded"]' });

// 3. Capture screenshot for visual verification
await mcp__playwright__screenshot({ fullPage: true, name: 'verification' });

// 4. Verify element existence
const exists = await mcp__playwright__evaluate({
  script: `!!document.querySelector('.expected-element')`
});

// 5. Verify computed styles (for UI work)
const styles = await mcp__playwright__evaluate({
  script: `
    const el = document.querySelector('.target');
    const s = getComputedStyle(el);
    return { backgroundColor: s.backgroundColor, color: s.color };
  `
});

// 6. Test interactions
await mcp__playwright__click({ selector: 'button.action' });
await mcp__playwright__wait({ selector: '.result-element' });
```

**If Playwright MCP is not available:**

- Document what needs human verification
- Provide manual test steps
- Flag items in VERIFICATION.md

### Pencil MCP for Design Work

**When working on UI phases**, use Pencil MCP (if available) or parse `.pen` files directly to extract design specifications as the source of truth.

**Design files location:** `designs/*.pen`

**Verification against design:**

1. Extract design specs from Pencil file
2. Verify CSS values match exactly (hex codes, pixel values)
3. Use Playwright MCP to verify computed styles at runtime
4. Document any discrepancies with file/line references

**Reference:** See `.claude/get-shit-done/references/pencil-design-workflow.md`

## Git Workflow

**Branch Protection Rules:**

- **NEVER push directly to `main` branch** - all changes must go through feature branches and PRs
- Create feature branches with descriptive names (e.g., `feat/add-auth`, `fix/ipns-publish`)
- All commits should be made on feature branches first
- Merge to main only via pull requests

**Branch Naming:**

- `feat/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `chore/` - Maintenance tasks
