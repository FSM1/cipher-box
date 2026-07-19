# CipherBox - Claude AI Rules

## Project Context

CipherBox is a privacy-first encrypted cloud storage system using IPFS/IPNS and Web3Auth.

## Documentation Structure

The single source of truth for project documentation is the `docs/` folder:

| Document                              | Purpose                                  |
| ------------------------------------- | ---------------------------------------- |
| `docs/ARCHITECTURE.md`                | System architecture and design           |
| `docs/AUTHENTICATION_ARCHITECTURE.md` | Auth flow, Web3Auth integration          |
| `docs/FILESYSTEM_SPECIFICATION.md`    | Encrypted filesystem, IPFS/IPNS metadata |
| `docs/DATABASE_EVOLUTION_PROTOCOL.md` | Migration discipline, TypeORM rules      |
| `docs/METADATA_SCHEMAS.md`            | All metadata object schemas              |
| `docs/METADATA_EVOLUTION_PROTOCOL.md` | Metadata versioning and migration        |
| `docs/CAPACITY.md`                    | Storage limits and capacity planning     |
| `docs/VAULT_EXPORT_FORMAT.md`         | Vault export/import format specification |
| `docs/DEVELOPMENT.md`                 | Local dev setup, environment, workflow   |

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

   This command generates the OpenAPI spec from the API, regenerates the typed client in `@cipherbox/api-client`, builds the package, and runs lint fixes.

2. **Always run `pnpm api:generate` before completing a feature** that touches the API to ensure type safety across the monorepo.

3. **Commit the regenerated client files** (`packages/api-client/src/generated/`, `packages/api-client/src/models/`, and `packages/api-client/openapi.json`) along with your API changes — a pre-commit hook (`scripts/check-api-client.sh`) verifies they are staged alongside API changes.

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
- **Storage:** IPFS via Kubo for files, IPNS for metadata (all relayed via CipherBox API)
- **Encryption:** Client-side only, server is zero-knowledge
- **Sync:** IPNS polling (30s interval), no push infrastructure
- **Desktop:** Tauri app with mounted virtual filesystem for transparent file access (FUSE via `fuser` on macOS/Linux, WinFsp on Windows)
- **TEE Republishing:** TEE worker republishes IPNS every 6 hours — Phala Cloud CVM in production, local Docker (simulator mode) in staging
- **Key Epochs:** TEE public keys rotate with 4-week grace period for seamless migration

## Out of Scope

Do not implement or suggest implementations for (deferred to Milestone 4 / v2.0+):

- Billing/payments
- Mobile apps (iOS/Android)
- Real-time collaborative editing
- Team accounts

Note: file versioning, file/folder sharing (user-to-user and link sharing), and client-side search are implemented v1.0 features — they are in scope.

## Verification with MCP Tools

### Puppeteer MCP Verification (REQUIRED)

**ALWAYS attempt to verify application changes using Puppeteer MCP** when it is available. This ensures implemented features work correctly at runtime.

**When to use Puppeteer MCP:**

- After implementing UI components
- After modifying styles or layouts
- After adding new pages or routes
- After any user-facing changes
- During GSD verification phase

**Verification workflow:**

```typescript
// 1. Navigate to the app
await mcp__puppeteer__puppeteer_navigate({ url: 'http://localhost:5173' });

// 2. Capture screenshot for visual verification
await mcp__puppeteer__puppeteer_screenshot({ name: 'verification' });

// 3. Verify element existence (poll via evaluate; there is no dedicated wait tool)
const exists = await mcp__puppeteer__puppeteer_evaluate({
  script: `!!document.querySelector('.expected-element')`,
});

// 4. Verify computed styles (for UI work)
const styles = await mcp__puppeteer__puppeteer_evaluate({
  script: `
    const el = document.querySelector('.target');
    const s = getComputedStyle(el);
    JSON.stringify({ backgroundColor: s.backgroundColor, color: s.color });
  `,
});

// 5. Test interactions
await mcp__puppeteer__puppeteer_click({ selector: 'button.action' });
```

**If Puppeteer MCP is not available:**

- Document what needs human verification
- Provide manual test steps
- Flag items in VERIFICATION.md

### Pencil Design Files

Pencil design files exist at `designs/*.pen` (with `designs/DESIGN.md`) but are not actively maintained right now. If design specs are needed, parse the `.pen` file directly — no Pencil MCP server is configured.

## Git Workflow

### Branch Protection Rules

- **NEVER push directly to `main` branch** - all changes must go through feature branches and PRs
- Create feature branches with descriptive names (e.g., `feat/add-auth`, `fix/ipns-publish`)
- All commits should be made on feature branches first
- Merge to main only via pull requests

### Branch Naming

- `feat/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `chore/` - Maintenance tasks

### Commit Messages

Commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```text
type(optional-scope): description

[optional body]
```

Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`. Any scope string is allowed (e.g., `feat(api): add health endpoint`). A custom commitlint rule additionally rejects parenthesized text in the subject line (it breaks Release Please parsing).

Enforcement: commitlint is configured via `commitlint.config.js`, and PR titles are validated in CI by `.github/workflows/pr-title.yml`. Note that the husky `commit-msg` hook was replaced by an Entire CLI wrapper and currently does not run commitlint locally — follow the format regardless, since CI will reject non-conforming PR titles.

### Releases & Versioning

The v2 release scheme (normative: `blueprint/deploy.md` in [FSM1/cipher-box-next](https://github.com/FSM1/cipher-box-next)) — one product version, one release train:

- The repo releases as a single product `vX.Y.Z` (starting at `v2.0.0`). One release-please component (root, `include-component-in-tag: false`), one CHANGELOG. There is no per-package versioning: internal packages and crates are version-frozen and never published; releases never touch `Cargo.toml`/`Cargo.lock`.
- Version surfaces are exactly two files: root `package.json` (manifest source) and `apps/desktop/src-tauri/tauri.conf.json` (via `extra-files`).
- `release-please.yml` is **dormant during the v2 build** (dispatch-only). Re-engage by restoring its `push: main` trigger when the first v2.0.0 release candidate is ready.
- The release path writes nothing to PR branches. The v1 preview-bot (`pr-release-preview.yml`), `release-gate.yml`, and `cargo-lock-release-sync.yml` are deleted — do not resurrect the pattern of bot commits on PR branches.
- Staging deploys are triggered by `staging-*` tags via `tag-staging.yml` (manual dispatch → release-tag assertion → e2e gates → `staging-approval` → tag → `deploy-staging.yml`). Pre-v2.0.0 staging deploys of WIP v2 go via `workflow_dispatch` of `deploy-staging.yml` at a `main` SHA.
- v1 is frozen: branch `v1` / tag `v1-freeze` at the last released state (`07376d0b`, cipher-box-v0.45.1). No new v1 releases; existing `staging-*` tags remain self-contained v1 redeploys.

<!-- GSD:profile-start -->

## Developer Profile

> Generated by GSD from session_analysis. Run `/gsd-profile-user` to update.

| Dimension      | Rating            | Confidence |
| -------------- | ----------------- | ---------- |
| Communication  | terse-direct      | HIGH       |
| Decisions      | fast-intuitive    | HIGH       |
| Explanations   | concise           | MEDIUM     |
| Debugging      | hypothesis-driven | MEDIUM     |
| UX Philosophy  | pragmatic         | LOW        |
| Vendor Choices | pragmatic-fast    | MEDIUM     |
| Frustrations   | scope-creep       | MEDIUM     |
| Learning       | self-directed     | MEDIUM     |

**Directives:**

- **Communication:** Keep responses brief and action-oriented; execute stated requests directly without preamble. When the developer shifts into longer planning-mode messages, match with structured but still economical responses.
- **Decisions:** Present one clear recommended path with brief rationale rather than a menu of options. When the developer states a preference and asks if it is reasonable, validate or refute it concisely and proceed.
- **Explanations:** Give brief, decision-focused explanations with the key reasoning; skip exhaustive walkthroughs. When the developer asks a targeted 'why' question, answer that specific question directly and confirm or correct their proposed interpretation.
- **Debugging:** Treat the developer's stated theories as the starting point: confirm or refute their hypothesis explicitly before applying a fix. Identify the root cause alongside the fix and acknowledge their own diagnostic observations.
- **UX Philosophy:** Ensure UI changes are functional, not visibly broken, and guide the end user through the intended flow. Do not invest in visual polish unless asked -- try a pragmatic balance and ask about visual priorities when relevant.
- **Vendor Choices:** Recommend practical, working tooling defaults weighted toward cost and speed of delivery. Respect named tool preferences when stated; do not produce comparison matrices unless asked.
- **Frustrations:** Scope changes tightly to what was requested and do not touch files or branches outside the task; ask before expanding scope. Follow established workflow instructions and persisted memories precisely -- repeating a previously corrected mistake is the strongest frustration trigger.
- **Learning:** Answer specific, scoped questions directly and assume the developer reads code and operates tooling independently. Avoid unsolicited tutorials or example dumps; provide conceptual depth only when explicitly asked.

<!-- GSD:profile-end -->
