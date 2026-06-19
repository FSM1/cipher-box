# Coding Conventions

**Analysis Date:** 2026-03-27
**Drift review:** 2026-06-19

## TypeScript Configuration

**Base Config:** `tsconfig.base.json` (all packages/apps extend this)

```json
{
  "target": "ES2022",
  "module": "ESNext",
  "moduleResolution": "bundler",
  "strict": true,
  "strictNullChecks": true,
  "isolatedModules": true,
  "noUnusedLocals": true,
  "noUnusedParameters": true,
  "noImplicitReturns": true,
  "noFallthroughCasesInSwitch": true,
  "declaration": true,
  "declarationMap": true
}
```

**Per-workspace overrides:**

| Workspace      | Module             | moduleResolution | Extras                                             |
| -------------- | ------------------ | ---------------- | -------------------------------------------------- |
| `packages/*`   | ESNext (from base) | bundler          | `outDir: ./dist`, `rootDir: ./src`                 |
| `apps/api`     | CommonJS           | node             | `emitDecoratorMetadata`, `experimentalDecorators`  |
| `apps/web`     | ESNext             | bundler          | `jsx: react-jsx`, `noEmit: true`, `target: ES2020` |
| `apps/desktop` | ESNext             | bundler          | Extends base                                       |

## Naming Patterns

### Files

**Backend (`apps/api/src/`):** kebab-case with NestJS suffix convention:

- Controllers: `vault.controller.ts`
- Services: `vault.service.ts`
- Modules: `vault.module.ts`
- DTOs: `init-vault.dto.ts`, `create-share.dto.ts`
- Entities: `vault.entity.ts`, `pinned-cid.entity.ts`
- Guards: `jwt-auth.guard.ts`, `throttler-bypass.guard.ts`
- Strategies: `jwt.strategy.ts`
- Decorators: `allow-scope.decorator.ts`
- Unit tests: `vault.service.spec.ts` (co-located)

**Frontend (`apps/web/src/`):** PascalCase for components, camelCase for hooks/services:

- Components: `FileBrowser.tsx`, `ConfirmDialog.tsx`, `AppShell.tsx`
- Hooks: `useFolder.ts`, `useSyncPolling.ts`, `useFileDownload.ts`
- Stores: `folder.store.ts`, `auth.store.ts`, `upload.store.ts`
- Services: `upload.service.ts`, `folder.service.ts`, `ipns.service.ts`
- Utilities: `fileTypes.ts`, `format.ts`
- CSS modules: `file-browser.css`, `layout.css` (per-component, not CSS modules)

**Packages (`packages/*/src/`):** kebab-case, organized by domain:

- Module entry: `index.ts` (barrel re-exports)
- Domain dirs: `aes/`, `ecies/`, `folder/`, `file/`
- Within domains: `encrypt.ts`, `decrypt.ts`, `types.ts`, `metadata.ts`
- Tests: `__tests__/` directory at package root

**Rust (`crates/*/src/`, `apps/desktop/src-tauri/src/`):** snake_case per Rust convention:

- Module files: `mod.rs` for directories, `lib.rs` for crate root
- Feature files: `inode.rs`, `cache.rs`, `file_handle.rs`
- Error types: `error.rs` in every crate
- Platform-specific: `platform/windows/`, `platform/macos/` (feature-gated)

### Directories

**Backend domain modules:** singular nouns: `auth/`, `vault/`, `ipfs/`, `ipns/`, `shares/`, `tee/`

**Backend sub-dirs within modules:** plural nouns: `dto/`, `entities/`, `guards/`, `services/`, `strategies/`, `decorators/`

**Frontend component groups:** feature-based: `file-browser/`, `layout/`, `auth/`, `settings/`, `mfa/`, `ui/`

### Functions and Variables

- **Functions:** camelCase everywhere in TypeScript: `encryptAesGcm`, `fetchAndDecryptMetadata`, `createSubfolder`
- **Variables:** camelCase: `privateKey`, `folderKey`, `rootIpnsName`
- **Constants:** UPPER_SNAKE_CASE: `AES_KEY_SIZE`, `QUOTA_LIMIT_BYTES`, `ROOT_INO`
- **Unused params:** prefix with underscore: `_ctx`, `_error`, `_removed`

### Types

- **Use `type` keyword** (not `interface`) for data shapes. Interfaces only for class contracts (e.g., `RequestWithUser extends Request`).
- **PascalCase** for all types: `FolderMetadata`, `VaultKey`, `SdkContext`, `CipherBoxClientConfig`
- **Suffixes by purpose:**
  - Data shapes: `Entry`, `Metadata`, `Config`, `State`, `Result`
  - DTOs: suffixed `Dto` (`InitVaultDto`, `CreateShareDto`, `QuotaResponseDto`)
  - Events: domain:action pattern (`SdkEvent` union type)

### String Literal Unions Over Enums

**Prefer string literal union types over TypeScript `enum`**. The codebase has only one enum declaration (`LogLevel` in `apps/web/src/lib/logger.ts`); everywhere else uses string literal union types. Use string literal union types:

```typescript
// Correct
export type CryptoErrorCode =
  | 'ENCRYPTION_FAILED'
  | 'DECRYPTION_FAILED'
  | 'KEY_WRAPPING_FAILED';

export type DeviceAuthStatus = 'pending' | 'approved' | 'denied';

// Wrong -- never do this
export enum CryptoErrorCode { ... }
```

### API Fields vs Database Columns

**API/TypeScript:** camelCase for all fields:

```typescript
// DTO (camelCase)
ownerPublicKey!: string;
rootIpnsName!: string;
encryptedKey!: Buffer;
```

**Database columns:** snake_case via TypeORM `name` option:

```typescript
// Entity (property camelCase, column snake_case)
@Column({ type: 'uuid', name: 'owner_id' })
ownerId!: string;

@Column({ type: 'bytea', name: 'owner_public_key' })
ownerPublicKey!: Buffer;

@CreateDateColumn({ name: 'created_at' })
createdAt!: Date;
```

## Code Style

### Formatting

**Tool:** Prettier 3.x (root-level dependency, configured via `prettier.config.js`)

- 2-space indentation
- Single quotes for strings
- Semicolons required
- Trailing commas: `es5` (set explicitly in `prettier.config.js`, overriding the Prettier v3 `all` default)
- 100-char print width (set explicitly in `prettier.config.js`)

### Linting

**Tool:** ESLint 9.x with flat config (`eslint.config.js`)

```javascript
// Key rules:
'@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
'@typescript-eslint/explicit-function-return-type': 'off'
'@typescript-eslint/no-explicit-any': 'warn'  // warn, not error
```

**Plugins:** `@eslint/js`, `typescript-eslint`, `eslint-plugin-prettier`

**No Biome:** Despite the web app CLAUDE.md referencing "Biome lint", the repo has no `biome.json`. JSX lint rules (e.g., `noCommentText`) are from the web app's review process, not an active Biome config.

### Pre-commit Hooks

**husky + lint-staged** enforced on every commit:

1. `scripts/check-api-client.sh` -- blocks commits that modify `.dto.ts`, `.controller.ts`, or `.entity.ts` files without also staging regenerated `packages/api-client/openapi.json`. Fix: run `pnpm api:generate`.
2. `lint-staged` runs:
   - `*.{ts,tsx,js,jsx}` -> `eslint --fix` + `prettier --write`
   - `*.{json,yml,yaml}` -> `prettier --write`
   - `*.md` -> `markdownlint --fix --ignore .planning` + `prettier --write`

### Commit Messages

**commitlint** defines Conventional Commits rules (`commitlint.config.js`), enforced in CI via PR-title validation (`.github/workflows/pr-title.yml`). The husky `commit-msg` hook is now an Entire CLI wrapper and does not run commitlint locally:

```text
type(optional-scope): description
```

Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`

**Custom rule:** Subject must not contain parenthesized text -- Release Please misparses it as a scope. Use dashes or brackets instead.

```bash
# Correct
feat(api): add vault export endpoint
chore: remove unused config

# Wrong -- will be rejected by commitlint
fix: update handler (legacy)  # parens in subject
```

## Import Organization

### Order

1. External framework imports (`react`, `@nestjs/*`, `typeorm`, `zustand`, `tauri`)
2. Monorepo package imports (`@cipherbox/crypto`, `@cipherbox/core`, `@cipherbox/sdk-core`, `@cipherbox/sdk`, `@cipherbox/api-client`)
3. Local absolute imports (from `../` or `./`)
4. CSS imports (last, in `.tsx` files)

### Example (Backend Controller)

```typescript
import { Controller, Post, Get, Body, UseGuards, Request } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { VaultService } from './vault.service';
import { InitVaultDto, VaultResponseDto } from './dto/init-vault.dto';
import { RequestWithUser } from '../common/types';
```

### Example (Frontend Component)

```typescript
import { useState, useCallback, useEffect } from 'react';
import type { FolderChild, FilePointer } from '@cipherbox/core';
import { useFolderNavigation } from '../../hooks/useFolderNavigation';
import { useFolder } from '../../hooks/useFolder';
import { useFolderStore } from '../../stores/folder.store';
import { FileList } from './FileList';
import '../../styles/file-browser.css';
```

### Path Aliases

- No path aliases configured. Use relative imports everywhere.
- Monorepo packages are imported by package name: `@cipherbox/crypto`, `@cipherbox/core`, etc.

### Barrel Files

**All packages use `index.ts` barrel exports:**

- `packages/crypto/src/index.ts` -- re-exports all public crypto functions and types
- `packages/core/src/index.ts` -- re-exports folder, file, vault, IPNS types and functions
- `packages/sdk-core/src/index.ts` -- re-exports IPFS, IPNS, folder, file, upload, download ops
- `packages/sdk/src/index.ts` -- re-exports `CipherBoxClient`, events, types
- `packages/api-client/src/index.ts` -- re-exports generated API functions and models

**Within packages, sub-modules also have barrel files:**

- `packages/crypto/src/aes/index.ts` re-exports `encrypt`, `decrypt`, `seal`, `unseal`
- `packages/core/src/folder/index.ts` re-exports types and metadata functions

**Backend entities and DTOs use barrel files:**

- `apps/api/src/vault/dto/index.ts`
- `apps/api/src/vault/entities/index.ts`
- `apps/api/src/shares/entities/index.ts`

**Frontend component groups use barrel files:**

- `apps/web/src/components/file-browser/index.ts` -- selectively exports main components
- `apps/web/src/components/layout/index.ts` -- exports all layout components

## NestJS Backend Conventions (`apps/api`)

### Module Structure

Every domain is a NestJS module with this structure:

```text
apps/api/src/{domain}/
  {domain}.module.ts       # Module declaration
  {domain}.controller.ts   # HTTP endpoints
  {domain}.service.ts      # Business logic
  {domain}.controller.spec.ts
  {domain}.service.spec.ts
  dto/
    index.ts               # Barrel export
    {action}-{entity}.dto.ts
  entities/
    index.ts               # Barrel export
    {entity}.entity.ts
```

### Controller Pattern

```typescript
@ApiTags('Vault')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('vault')
export class VaultController {
  constructor(private readonly vaultService: VaultService) {}

  @Post('init')
  @ApiOperation({ summary: '...', description: '...' })
  @ApiResponse({ status: 201, description: '...', type: VaultResponseDto })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 409, description: 'Conflict' })
  async initializeVault(
    @Request() req: RequestWithUser,
    @Body() dto: InitVaultDto
  ): Promise<VaultResponseDto> {
    return this.vaultService.initializeVault(req.user.id, dto);
  }
}
```

**Rules:**

- Always use `@ApiTags`, `@ApiBearerAuth`, `@ApiOperation`, `@ApiResponse` decorators
- Inject services via `private readonly` constructor params
- Extract `userId` from `req.user.id` (typed via `RequestWithUser`)
- Controllers delegate to services -- no business logic in controllers
- Return typed DTOs from all endpoints

### Service Pattern

```typescript
@Injectable()
export class VaultService {
  constructor(
    @InjectRepository(Vault) private readonly vaultRepository: Repository<Vault>,
    private readonly configService: ConfigService
  ) {}
}
```

**Rules:**

- All services are `@Injectable()`
- Use `@InjectRepository` for TypeORM repositories
- Throw NestJS exceptions (`ConflictException`, `NotFoundException`, `BadRequestException`)
- JSDoc comments on all public methods

### DTO Pattern

```typescript
export class InitVaultDto {
  @ApiProperty({ description: '...', example: '...' })
  @IsString()
  @IsNotEmpty()
  @Matches(/^[0-9a-fA-F]+$/, { message: '...' })
  ownerPublicKey!: string;
}
```

**Rules:**

- Use `class-validator` decorators for request DTOs
- Use `@ApiProperty` for Swagger documentation on all fields
- Use definite assignment assertion (`!:`) on all DTO fields
- Response DTOs need `@ApiProperty` but not validation decorators

### Entity Pattern

```typescript
@Entity('vaults') // table name is plural, snake_case
export class Vault {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Column({ type: 'uuid', name: 'owner_id' })
  ownerId!: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'owner_id' })
  owner!: User;

  @CreateDateColumn({ name: 'created_at' })
  createdAt!: Date;
}
```

**Rules:**

- Table names: plural snake_case (`vaults`, `pinned_cids`, `folder_ipns`)
- Column names: explicit snake_case via `name` option
- Property names: camelCase
- Binary data stored as `bytea` type, typed as `Buffer`
- UUIDs as primary keys via `@PrimaryGeneratedColumn('uuid')`
- Definite assignment assertions (`!:`) on all fields
- `onDelete: 'CASCADE'` on foreign key relations

## React Frontend Conventions (`apps/web`)

### Component Pattern

```typescript
type ConfirmDialogProps = {
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmLabel?: string;
  isDestructive?: boolean;
  isLoading?: boolean;
};

/**
 * JSDoc with description and @example block.
 */
export function ConfirmDialog({ open, onClose, onConfirm, ... }: ConfirmDialogProps) {
  // ...
}
```

**Rules:**

- Use `function` declarations (not arrow functions) for components
- Props type defined as `type XxxProps` above the component
- Named exports, not default exports
- JSDoc with `@example` on major components
- CSS via imported stylesheets, not CSS modules or CSS-in-JS

### Zustand Store Pattern

```typescript
import { create } from 'zustand';

type FolderState = {
  // State fields
  folders: Record<string, FolderNode>;
  currentFolderId: string | null;
  // Action signatures
  setFolder: (folder: FolderNode) => void;
  clearFolders: () => void;
};

export const useFolderStore = create<FolderState>((set, get) => ({
  // Initial state
  folders: {},
  currentFolderId: null,

  // Actions (inline)
  setFolder: (folder) =>
    set((state) => ({
      folders: { ...state.folders, [folder.id]: folder },
    })),

  clearFolders: () => {
    /* ... */
  },
}));
```

**Rules:**

- Store files named `{domain}.store.ts`
- State type includes both data fields and action signatures
- Use `set` for state updates, `get` for reading current state
- Immutable updates via spread operator
- **Security:** Zero-fill `Uint8Array` key material in cleanup actions
- **Stale closures:** Inside async callbacks, use `useFolderStore.getState()` not hook selectors

### Hook Pattern

```typescript
/**
 * JSDoc with @example showing usage in JSX.
 */
export function useFolder() {
  const folderMutations = useFolderMutations();
  const fileOperations = useFileOperations();

  const isLoading = folderMutations.isLoading || fileOperations.isLoading;
  const error = folderMutations.error || fileOperations.error;

  return {
    isLoading,
    error,
    createFolder: folderMutations.createFolder,
    // ...
  };
}
```

**Rules:**

- Hook files named `use{Feature}.ts`
- Compose smaller hooks into larger facade hooks
- Return object with named properties (not tuples)
- Combine loading/error state from sub-hooks

### Routing

- `react-router-dom` with `HashRouter` (required for Tauri webview)
- Route pages in `apps/web/src/routes/`: `FilesPage.tsx`, `BinPage.tsx`, etc.
- Protected routes: `useEffect` redirect to `/` when `!isAuthenticated`
- Layout via `AppShell` wrapper component

### CSS

- Plain CSS files per component group in `apps/web/src/styles/`
- Modern color function notation: `rgb(0 0 0 / 50%)` not `rgba(0,0,0,0.5)`
- All interactive elements must have `:focus-visible` styles alongside `:hover`

### Accessibility

- ARIA roles require matching keyboard handlers (`role="button"` needs `onKeyDown` for Enter/Space)
- Remove `tabIndex` if keyboard interaction is not needed
- See `apps/web/CLAUDE.md` for full a11y checklist

## Package Layer Conventions

### `@cipherbox/crypto` -- Pure Cryptographic Primitives

- No CipherBox domain knowledge; generic crypto operations only
- All inputs/outputs are `Uint8Array`
- Error messages are generic to prevent oracle attacks
- Custom `CryptoError` class with typed `CryptoErrorCode` string literal union
- Web Crypto API for AES operations; `@noble/*` and `eciesjs` for ECC

### `@cipherbox/core` -- Domain Types and Metadata

- Knows CipherBox data model (FolderMetadata, FileMetadata, DeviceRegistry)
- Imports from `@cipherbox/crypto` only
- Types use `type` keyword, not `interface`
- Validation functions: `validateFolderMetadata`, `validateFileMetadata`
- Encrypt/decrypt functions pair: `encryptFolderMetadata` / `decryptFolderMetadata`

### `@cipherbox/sdk-core` -- Stateless Operations

- Pure functions taking `SdkContext` as first argument (dependency injection)
- No global state; no Zustand; no React
- `SdkContext` provides `apiUrl`, `getAccessToken()`, and optional `axiosInstance`

### `@cipherbox/sdk` -- Stateful Client

- `CipherBoxClient` class with internal state (`FolderTree`, `KeyCache`)
- Event-driven via `SdkEventEmitter` with typed `SdkEvent` union
- Zero React/browser dependencies
- Defensive copy of key material in constructor; zeroed on `destroy()`
- Operations wrapped with `withOperation()` for consistent start/end/error events

### `@cipherbox/api-client` -- Generated API Client

- Auto-generated by Orval from OpenAPI spec
- **Never edit `src/generated/` or `src/models/` manually**
- Custom axios instance in `src/instance.ts` (the only hand-written file)
- Regenerate after any API change: `pnpm api:generate`

## Rust Conventions (`crates/*`, `apps/desktop/src-tauri/`)

### Module Structure

```text
crates/{name}/src/
  lib.rs          # Public API re-exports
  error.rs        # Crate-specific error enum
  {feature}.rs    # Feature modules
```

### Error Handling

Use `thiserror` derive macro for error enums in every crate:

```rust
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("AES-GCM encryption failed")]
    AesEncryptionFailed,
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },
}
```

**Composition:** Higher-level crates use `#[from]` for automatic conversion:

```rust
#[derive(Debug, Error)]
pub enum SdkError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] cipherbox_crypto::CryptoError),
    #[error("API error: {0}")]
    Api(#[from] cipherbox_api_client::ApiError),
}
```

**Tauri commands** return `Result<T, String>` (Tauri's IPC serialization constraint). Map errors with `.map_err(|e| format!("...: {}", e))`.

### Unsafe Usage

Minimal and isolated. Only used for:

- `libc::getuid()` / `libc::getgid()` in FUSE operations (`crates/fuse/src/operations.rs`)
- WinFSP raw pointer operations (`crates/fuse/src/platform/windows/read_ops.rs`)

No `unsafe` in application code (`apps/desktop/src-tauri/src/`), crypto, core, SDK, or API client crates.

### Key Material

- `Zeroizing<Vec<u8>>` from the `zeroize` crate for automatic zeroing on drop
- Private keys stored as `Zeroizing<Vec<u8>>`, never as raw `Vec<u8>`

### Naming

- snake_case for everything per Rust convention
- Crate names: `cipherbox_crypto`, `cipherbox_core`, `cipherbox_sdk`, `cipherbox_fuse`, `cipherbox_api_client`
- Type names: PascalCase (`CryptoError`, `InodeKind`, `FileAttrs`)
- Constants: UPPER_SNAKE_CASE (`ROOT_INO`, `BLOCK_SIZE`)

### Documentation

- `//!` module-level doc comments in `lib.rs` and `mod.rs`
- `///` doc comments on all public items
- `#[cfg(feature = "...")]` for platform-specific code (e.g., `fuse`, `winfsp`)

## Binary Data Handling

### TypeScript

- **Always use `Uint8Array`** for binary data, never raw `ArrayBuffer`
- **Never use `.buffer` on `Uint8Array` for Blob construction** -- it returns the entire underlying ArrayBuffer which may be larger than the view:

```typescript
// WRONG -- silent data corruption
new Blob([uint8array.buffer]);

// CORRECT
new Blob([uint8array]);
```

- Hex encoding/decoding via `@cipherbox/crypto` utilities: `hexToBytes()`, `bytesToHex()`
- API transport: hex-encoded strings for keys, base64 for encrypted data blobs

### Rust

- `Vec<u8>` for owned byte data
- `&[u8]` for borrowed byte data
- `Zeroizing<Vec<u8>>` for sensitive key material
- `hex::encode()` / `hex::decode()` for hex conversion

## Error Handling Patterns Per Layer

### Package Layer (crypto, core, sdk-core)

Custom typed errors. Never throw generic `Error`:

```typescript
throw new CryptoError('Encryption failed', 'ENCRYPTION_FAILED');
```

### SDK Layer (sdk)

`withOperation()` wrapper emits `operation:start`, `operation:end`, and `error` events. Errors propagate to caller:

```typescript
// SdkEventEmitter catches subscriber errors silently
try {
  handler(event);
} catch {
  /* subscriber bugs don't crash SDK */
}
```

### API Backend (NestJS)

Throw NestJS HTTP exceptions:

```typescript
throw new ConflictException('Vault already exists for this user');
throw new NotFoundException('Vault not found');
throw new BadRequestException('Invalid input');
```

### Frontend Services

Retry wrapper with exponential backoff for network operations:

```typescript
async function withRetry<T>(fn: () => Promise<T>, maxRetries = 3, baseDelay = 500): Promise<T>;
```

Error detection via status code inspection:

```typescript
export function isConflictError(error: unknown): boolean {
  const e = error as Record<string, unknown>;
  return e.status === 409;
}
```

### Frontend Hooks

Combine loading/error state from sub-hooks. Errors clear when next operation starts.

### React Async Safety

- Re-check refs for null after every `await` in async callbacks
- Never use non-null assertions (`!`) on refs in async code
- Wrap `HTMLMediaElement.play()` in try/catch (autoplay policy)

## API Client Generation Workflow

After modifying any `.dto.ts`, `.controller.ts`, or `.entity.ts` in `apps/api`:

```bash
pnpm api:generate
```

This command:

1. Generates OpenAPI spec from NestJS decorators (`pnpm openapi:generate`)
2. Regenerates typed client functions via Orval (`pnpm --filter @cipherbox/api-client generate`)
3. Builds the api-client package
4. Runs lint fix across the monorepo

The pre-commit hook (`scripts/check-api-client.sh`) blocks commits that modify API source files without staging the regenerated `packages/api-client/openapi.json`.

## Logging

### Backend

NestJS default logger (console output). No Winston or structured logging framework currently configured.

**Security rules:**

- NEVER log `privateKey`, `folderKey`, `fileKey`, or any encryption keys
- NEVER log full request/response bodies containing encrypted data

### Frontend

`console.log` / `console.warn` / `console.error` for development.

### Rust Desktop

`env_logger` + `log` crate macros:

```rust
log::info!("CipherBox Desktop starting...");
log::error!("Failed to build tray: {}", e);
```

## Comments and Documentation

### TypeScript

- JSDoc with `@example` blocks on public API functions and major components
- Module-level JSDoc on `index.ts` barrel files (especially in packages)
- Inline comments for non-obvious behavior, security considerations marked with `[SECURITY: ...]`
- `_` prefix for intentionally unused variables (enforced by ESLint)

### Rust

- `//!` for module-level documentation
- `///` for public item documentation
- `// SAFETY:` comments required near `unsafe` blocks
- Section dividers with `// -- SectionName ---...` pattern

## Testing Conventions

### Mock Typing in NestJS Specs (Jest)

**Never use `jest.Mocked<Partial<T>>`** for mocks retrieved via `module.get()`. The `module.get()` return type is the real service, not the mock, so `.mockResolvedValue()` fails to typecheck.

```typescript
// WRONG -- loses mock methods after module.get()
let service: jest.Mocked<Partial<MyService>>;
service = module.get(MyService); // typed as MyService, not jest.Mock

// CORRECT -- type the mock shape directly
let mockService: { myMethod: jest.Mock; otherMethod: jest.Mock };
// ...
mockService = module.get(MyService) as unknown as typeof mockService;
```

Alternatively, keep a reference to the mock object created in `beforeEach` and use it directly:

```typescript
let mockService: { myMethod: jest.Mock };

beforeEach(async () => {
  mockService = { myMethod: jest.fn() };
  const module = await Test.createTestingModule({
    providers: [{ provide: MyService, useValue: mockService }],
  }).compile();
  // No need to module.get() -- use mockService directly
});
```

### Module Mocking in Vitest

**Always use `importOriginal` when partially mocking a module.** Bare factory mocks replace the entire module, dropping any export you don't explicitly list:

```typescript
// WRONG -- drops all non-listed exports (e.g., selectEncryptionMode)
vi.mock('@cipherbox/sdk-core', () => ({
  uploadFile: vi.fn(),
  downloadAndDecrypt: vi.fn(),
}));

// CORRECT -- real exports survive alongside mocked functions
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    uploadFile: vi.fn(),
    downloadAndDecrypt: vi.fn(),
  };
});
```

**When to use bare factory:** Only when you want to replace every export in the module (rare).

### Test Entity Mocks

When mocking TypeORM entities, include **all required fields** from the entity class. Missing fields cause TS errors that accumulate silently. When a migration adds a column to an entity, grep for that entity's test mocks and update them.

## Security Conventions

- **Memory-only keys:** `Uint8Array` key material is never persisted to localStorage/sessionStorage
- **Zero-fill on cleanup:** `Uint8Array.fill(0)` before releasing references (stores, SDK `destroy()`)
- **Rust:** `Zeroizing<Vec<u8>>` for automatic zeroization on drop
- **ECIES wrapping:** All key transport uses ECIES (secp256k1); server never sees plaintext keys
- **Generic crypto errors:** Error messages from crypto layer are deliberately vague to prevent oracle attacks
- **Exposed dev stores:** Zustand stores attached to `window.__ZUSTAND_*` only when `import.meta.env.DEV`

---

<!-- Convention analysis: 2026-03-27 -->
