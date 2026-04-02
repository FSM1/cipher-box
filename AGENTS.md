# CipherBox - AI Agent Instructions

## Project Context

CipherBox is a **technology demonstrator** for privacy-first encrypted cloud storage using IPFS/IPNS and Web3Auth. It is not a commercial product.

## Documentation

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

1. **Never** store `privateKey` in localStorage/sessionStorage
2. **Never** log sensitive keys
3. **Never** send unencrypted keys to the server
4. **Always** use ECIES for key wrapping
5. **Always** use AES-256-GCM for content encryption
6. The server NEVER has access to plaintext or unencrypted keys
7. **Always** encrypt `ipnsPrivateKey` with TEE public key before sending for republishing
8. TEE decrypts IPNS keys in hardware only, signs, and immediately discards

## API Development Workflow

When working on `apps/api` code:

1. **After modifying API endpoints, DTOs, or controllers**, regenerate the API client:

   ```bash
   pnpm api:generate
   ```

   This generates the OpenAPI spec, regenerates the typed client in `@cipherbox/api-client`, builds the package, and runs lint fixes.

2. **Always run `pnpm api:generate` before completing a feature** that touches the API to ensure type safety across the monorepo.

3. **Commit the regenerated client files** (`packages/api-client/src/generated/` and `packages/api-client/src/models/`) along with your API changes.

## Dependency Bootstrapping

- Agents should treat missing workspace dependencies as routine setup, not a user decision point.
- If validation, code generation, builds, or tests fail because dependencies are missing (`node_modules` absent, `jest`/`tsup`/`tsc` not found, workspace packages unavailable), agents should proactively run the appropriate install command from the repo root before asking the user anything.
- For this monorepo, default to:

  ```bash
  pnpm install
  ```

- After installing, run the repo-wide build when downstream tests or packages depend on built workspace outputs:

  ```bash
  pnpm build
  ```

- If the full repo build is unnecessarily heavy for the task, agents should at minimum build the shared `/packages` workspace outputs required by the failing command before retrying it.
- After installing/building, retry the command that was previously blocked.
- If package-manager security prompts block native/build scripts, agents should surface that clearly and then request user guidance only if approval is actually required to continue.

## Code Generation Guidelines

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
- **Desktop:** FUSE mount for transparent file access
- **TEE Republishing:** Phala Cloud CVM for automatic IPNS republishing every 6 hours
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

## Git Workflow

**Branch Protection Rules:**

- **NEVER push directly to `main` branch** - all changes must go through feature branches and PRs
- Create feature branches with descriptive names (e.g., `feat/add-auth`, `fix/ipns-publish`)
- All commits should be made on feature branches first

**Branch Naming:**

- `feat/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `chore/` - Maintenance tasks

**Commit Messages:**

Commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) format. Enforced by commitlint via a husky `commit-msg` hook.

```text
type(optional-scope): description

[optional body]
```

Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.

**Releases & Versioning:**

- All packages share a single unified version (tracked in `.release-please-manifest.json`)
- [Release Please](https://github.com/googleapis/release-please) automates changelog generation, version bumping, and GitHub Releases
- Version bumps propagate to all `package.json` files, `Cargo.toml`, and `tauri.conf.json` via `release-please-config.json`

## Database Migration Discipline

- Every new `@Entity()` MUST have a `CREATE TABLE` migration with `IF NOT EXISTS`
- `synchronize: true` in dev/test hides missing migrations
- Full protocol: `docs/DATABASE_EVOLUTION_PROTOCOL.md`
