# Coding Conventions

**Analysis Date:** 2026-01-19

## Naming Patterns

**Files:**
- TypeScript source files: lowercase with hyphens (`gen-private-key.ts`, `index.ts`)
- Documentation files: UPPERCASE with underscores (`PRD.md`, `TECHNICAL_ARCHITECTURE.md`, `API_SPECIFICATION.md`)
- Configuration files: lowercase with dots (`.eslintrc`, `.prettierrc`, `tsconfig.json`, `package.json`)

**Functions:**
- camelCase for all functions: `logStep()`, `formatBytes()`, `hexToBytes()`, `aesGcmEncrypt()`
- Async functions use same camelCase pattern: `publishFolderMetadata()`, `waitForIpns()`, `pinCid()`
- Helper/utility prefix: `log` prefix for logging functions, `get` prefix for accessors
- Descriptive verb-first names: `encryptName()`, `decryptMetadata()`, `collectChunks()`

**Variables:**
- camelCase for all variables: `privateKey`, `publicKey`, `rootFolder`, `ipnsName`
- Constants in UPPER_SNAKE_CASE: `TAG_SIZE`, `IV_SIZE` (defined at module level in `poc/src/index.ts`)
- Context objects suffixed with `ctx`: `HarnessContext`, parameter `ctx`
- Boolean flags use full words: `pinataEnabled`, not `isPinata`

**Types:**
- PascalCase for all type definitions: `FolderEntry`, `FileEntry`, `FolderMetadata`, `HarnessContext`
- Suffix with type category: `Entry`, `Metadata`, `State`, `Config`
- Descriptive compound names: `PinataConfig`, `FolderState`

## Code Style

**Formatting:**
- No dedicated formatter config detected (.prettierrc or biome.json not found in project root)
- Indentation: 4 spaces (observed in `poc/src/index.ts`)
- Line length: Lines up to ~120 characters observed, no hard limit enforced
- Arrow functions: Always use arrow syntax for inline callbacks: `(error) => { ... }`
- String literals: Double quotes for strings (per user global instruction preference)
- Trailing commas: Consistently used in multi-line objects and arrays

**Linting:**
- Tool: ESLint configured via `package.json` script: `"lint": "eslint src --ext .ts"`
- No project-level ESLint config file found (relying on defaults or user-level config)
- TypeScript strict mode enabled in `poc/tsconfig.json`

## Import Organization

**Order:**
1. External dependencies (third-party packages)
2. Node.js built-in modules
3. No local imports observed (single-file PoC)

**Example from `poc/src/index.ts`:**
```typescript
import { create } from "ipfs-http-client";
import dotenv from "dotenv";
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";
import { encrypt as eciesEncrypt, decrypt as eciesDecrypt } from "eciesjs";
import { getPublicKey } from "@noble/secp256k1";
import { mkdir, writeFile } from "fs/promises";
import { existsSync } from "fs";
import path from "path";
```

**Path Aliases:**
- None configured

**Named vs Default Imports:**
- Prefer named imports with destructuring: `{ create }`, `{ randomBytes, createCipheriv }`
- Use `as` for aliasing when needed: `import { encrypt as eciesEncrypt }`
- Default imports for packages that export defaults: `import dotenv from "dotenv"`

## Error Handling

**Patterns:**
- Top-level try-catch in `main()` with process exit on failure:
  ```typescript
  main().catch((error) => {
      console.error("PoC harness failed:", error);
      process.exit(1);
  });
  ```
- Individual try-catch blocks for non-critical operations with console warnings:
  ```typescript
  try {
      await ctx.ipfs.pin.rm(cid);
  } catch (error) {
      console.warn(`Pin rm skipped for ${cid}: ${(error as Error).message}`);
  }
  ```
- Type assertions for error objects: `(error as Error).message`
- Throw new errors with descriptive messages for critical failures:
  ```typescript
  if (!privateKeyHex) {
      throw new Error("ECDSA_PRIVATE_KEY is required");
  }
  ```

## Logging

**Framework:** Native `console` (no logging library)

**Patterns:**
- Step logging: `logStep("Initialize root folder")` for major workflow sections
- Info logging: `console.log()` for progress and results
- Warning logging: `console.warn()` for non-critical issues (e.g., failed optional operations)
- Error logging: `console.error()` for failures before exit
- Formatting helpers: `formatBytes()` for human-readable sizes
- Contextual messages include identifiers: `console.log(\`Docs updated CID: ${cid}\`)`

## Comments

**When to Comment:**
- Minimal inline comments observed
- Code is self-documenting through descriptive function and variable names
- No JSDoc comments in PoC code
- Complex algorithms or business logic are explained through function names

**Documentation Comments:**
- Documentation files use YAML frontmatter with metadata:
  ```yaml
  ---
  version: 1.10.0
  last_updated: 2026-01-19
  status: Active
  ai_context: ...
  ---
  ```

## Function Design

**Size:**
- Functions range from 3-50 lines
- Large workflows broken into helper functions (e.g., `publishFolderMetadata()`, `fetchFolderMetadata()`)
- Main orchestration function (`main()`) is ~170 lines, coordinates workflow

**Parameters:**
- Context pattern: First parameter is `ctx: HarnessContext` for functions needing shared state
- Optional parameters use `?:` syntax: `options?: { nocache?: boolean }`
- Environment configuration read from `process.env` with fallbacks:
  ```typescript
  const ipfsApiUrl = process.env.IPFS_API_URL ?? "http://127.0.0.1:5001";
  ```

**Return Values:**
- Explicit return types for public functions: `: Promise<void>`, `: Promise<string>`, `: Uint8Array`
- Return objects for multiple values: `{ ciphertext: Uint8Array; iv: Uint8Array }`
- Async functions always return `Promise<T>`

## Module Design

**Exports:**
- No exports (single-file PoC script)
- All functions and types are module-local

**Barrel Files:**
- Not applicable (no multi-file module structure)

## TypeScript Conventions

**Type Safety:**
- Strict mode enabled (`"strict": true` in `poc/tsconfig.json`)
- Explicit type annotations for function parameters and returns
- Type definitions for all data structures
- Use of `Uint8Array` for binary data (never strings for crypto)
- Use of union types for variants: `Array<FolderEntry | FileEntry>`

**Type Definitions:**
- Custom types defined at module top: `type FolderEntry = { ... }`
- Prefer `type` over `interface` for object shapes
- Discriminated unions using `type` field: `type: "file"` vs `type: "folder"`

**Binary Data Handling:**
- Always use `Uint8Array` for cryptographic data
- Conversion functions: `hexToBytes()`, `bytesToHex()`, `utf8ToBytes()`, `bytesToUtf8()`
- Never store sensitive keys as strings

## Security Conventions

**Critical Rules (from `.claude/CLAUDE.md`):**
- Never store `privateKey` in localStorage/sessionStorage
- Never log sensitive keys
- Never send unencrypted keys to server
- Always use ECIES for key wrapping
- Always use AES-256-GCM for content encryption
- Clear sensitive data from memory after use

**Observed Patterns:**
- Private keys loaded from environment variables only: `process.env.ECDSA_PRIVATE_KEY`
- All encryption keys wrapped with ECIES before storage: `eciesEncryptBytes(ctx.publicKey, key)`
- Metadata encrypted with AES-256-GCM: `aesGcmEncrypt(data, key)`
- Auth tags included in ciphertext for integrity

## Terminology Standards

**From `.claude/CLAUDE.md`:**
- Use `publicKey` not `pubkey`, `user_pubkey`, `ownerPublicKey`
- Use `privateKey` not `privkey`, `user_private_key`
- Use `rootFolderKey` not `rootKey`, `root_folder_key`
- Use `ipnsName` for identifier, `ipnsRecord` for data structure
- Use `folderKey` not `subfolderKey` (unless specifically for subfolder)
- Use `fileKey` not `file_key`
- Use camelCase for API fields, snake_case for database columns

## Documentation Conventions

**Version Management:**
- All documentation files have YAML frontmatter with version tracking
- Version bump rules strictly enforced (patch for minor, minor for significant)
- Current project version: 1.9.0 (tracked in `.claude/CLAUDE.md`)

**File Organization:**
- Technical specs in `Documentation/` directory
- Project instructions in `.claude/CLAUDE.md`
- PoC code in `poc/` directory

---

*Convention analysis: 2026-01-19*
