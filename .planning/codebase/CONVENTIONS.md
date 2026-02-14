# Coding Conventions

**Analysis Date:** 2026-01-20

## Naming Patterns

**Files (NestJS Backend):**
- All files: lowercase with hyphens (`kebab-case.ts`)
- Pattern: `PascalCaseSuffix` class → `pascal-case.suffix.ts` file
- Services: `[name].service.ts` (e.g., `vault.service.ts`)
- Controllers: `[name].controller.ts` (e.g., `auth.controller.ts`)
- Modules: `[name].module.ts` (e.g., `ipfs.module.ts`)
- DTOs: `[action]-[entity].dto.ts` (e.g., `create-vault.dto.ts`)
- Guards: `[name].guard.ts` (e.g., `jwt-auth.guard.ts`)
- Pipes: `[name].pipe.ts` (e.g., `validation.pipe.ts`)
- Unit tests: `[name].spec.ts` beside implementation
- E2E tests: `[name].e2e-spec.ts` in `test/` directory
- Single entry point per module directory: `index.ts`

**Folders (NestJS Backend):**
- Domain folders: singular (`user/`, `vault/`, `ipfs/`)
- Reusable code folders: plural (`guards/`, `pipes/`, `utils/`, `filters/`)

**Files (PoC/Scripts):**
- Scripts use descriptive hyphenated names: `gen-private-key.ts`

**Functions:**
- camelCase for all functions: `hexToBytes`, `encryptName`, `publishFolderMetadata`
- Prefix helper functions with verb: `logStep`, `formatBytes`, `collectChunks`
- Async functions use descriptive names indicating async nature: `fetchFolderMetadata`, `waitForIpns`

**Variables:**
- camelCase for local variables: `privateKey`, `folderKey`, `metadataCid`
- UPPER_SNAKE_CASE for constants: `TAG_SIZE`, `IV_SIZE`
- Context objects named with `ctx` suffix pattern: `HarnessContext`

**Types:**
- PascalCase for types and interfaces: `FolderEntry`, `FileEntry`, `FolderMetadata`
- Use `type` keyword (not interfaces) for data shapes
- Suffixed with purpose: `Entry` for items, `State` for stateful objects, `Config` for configuration
- Prefer the use of string literals over Typescript enums 

**API Fields vs Database Columns (per project rules):**
- API fields: camelCase (`publicKey`, `rootFolderKey`, `ipnsName`)
- Database columns: snake_case (`public_key`, `root_folder_key`)

## Code Style

**Formatting:**
- No explicit formatter config detected (ESLint present but minimal config)
- 2-space indentation in TypeScript files
- Semicolons required at statement ends
- single quotes for strings

**Linting:**
- ESLint 8.x configured via `package.json` script
- Lint command: `npm run lint`
- Lints only `src/` directory with `.ts` extension

**TypeScript Configuration:**
- Target: ES2022
- Module: ES2022 with Bundler resolution
- Strict mode enabled
- Skip lib check enabled
- Output to `dist/` directory

## Import Organization

**Order:**
1. External package imports (`ipfs-http-client`, `dotenv`, `crypto`)
2. Third-party crypto libraries (`eciesjs`, `@noble/secp256k1`)
3. Node.js built-in modules (`fs/promises`, `fs`, `path`)

**Path Aliases:**
- None configured; use relative imports

**Example:**
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

## Error Handling

**Patterns:**
- Throw `Error` with descriptive messages for critical failures
- Use try-catch with console.warn for recoverable operations
- Type errors explicitly with `as Error` cast pattern

**Example - Critical Error:**
```typescript
if (!privateKeyHex) {
    throw new Error("ECDSA_PRIVATE_KEY is required");
}
```

**Example - Recoverable Error:**
```typescript
try {
    await ctx.ipfs.pin.rm(cid);
} catch (error) {
    console.warn(`Pin rm skipped for ${cid}: ${(error as Error).message}`);
}
```

**Async Error Handling:**
- Main entry point uses `.catch()` with `process.exit(1)` pattern:
```typescript
main().catch((error) => {
    console.error("PoC harness failed:", error);
    process.exit(1);
});
```

## Logging

### Backend Server Logging (NestJS)

**Framework:** Winston with structured JSON logging

**Transport Configuration by Environment:**

| Environment | Transports | Format |
|-------------|------------|--------|
| Local | Console (pretty-print) | Human-readable with colors |
| Development | Console + Datadog/Splunk | JSON structured |
| Production | Datadog/Splunk (no console) | JSON structured |

**Log Levels:**
- `error` - Critical failures requiring immediate attention
- `warn` - Recoverable issues, degraded functionality
- `info` - Significant business events (auth, API calls, IPFS operations)
- `debug` - Detailed diagnostic information (dev/local only)

**Structured Log Fields:**
```typescript
// Required fields in all log entries
{
  timestamp: string;      // ISO 8601 format
  level: string;          // error, warn, info, debug
  message: string;        // Human-readable description
  service: 'cipherbox-api';
  environment: string;    // local, development, production
  correlationId?: string; // Request tracking across services
}

// Context-specific fields
{
  userId?: string;        // Authenticated user (never log keys!)
  operation?: string;     // e.g., 'ipfs.add', 'vault.create'
  duration?: number;      // Operation duration in ms
  ipfsCid?: string;       // IPFS content identifier
  error?: {               // Error details (errors only)
    name: string;
    message: string;
    stack?: string;       // Dev/local only, never in prod logs
  };
}
```

**Security Requirements:**
- NEVER log `privateKey`, `folderKey`, `fileKey`, or any encryption keys
- NEVER log full request/response bodies containing sensitive data
- Sanitize user input before logging
- Stack traces only in local/dev environments

**Winston Setup Example:**
```typescript
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';

// Configure based on NODE_ENV
const transports: winston.transport[] = [];

if (process.env.NODE_ENV === 'local') {
  transports.push(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple(),
    ),
  }));
} else {
  // Dev/Prod: JSON format for log aggregation
  transports.push(new winston.transports.Console({
    format: winston.format.json(),
  }));
  // Add Datadog/Splunk transport here
}
```

### PoC/Script Logging

**Framework:** Native `console` methods (PoC only)

**Patterns:**
- Use `console.log()` for standard output and progress
- Use `console.warn()` for non-fatal issues
- Use `console.error()` for fatal errors
- Use helper functions for formatted output: `logStep()` for section headers

**Log Format Examples:**
```typescript
// Section headers
const logStep = (message: string) => {
    console.log(`\n=== ${message} ===`);
};

// Progress messages
console.log(`Publishing metadata for ${folder.name}...`);

// Warnings
console.warn(`Pin rm skipped for ${cid}: ${error.message}`);
```

## Comments

**When to Comment:**
- Document disabled/stubbed functionality with reason
- No JSDoc comments observed in codebase
- Inline comments for non-obvious behavior

**Example:**
```typescript
const logIpnsRecordSize = async (_ctx: HarnessContext, _ipnsName: string, _label: string): Promise<void> => {
    // The routing API is not available in ipfs-http-client v60.
    // IPNS record size logging is disabled.
};
```

**Underscore Prefix:**
- Use `_` prefix for intentionally unused parameters: `_ctx`, `_ipnsName`

## Function Design

**Size:**
- Functions are focused and single-purpose
- Typical function length: 10-30 lines
- Complex operations broken into helper functions

**Parameters:**
- Use typed parameters with explicit types
- Context objects passed as first parameter when needed (`ctx: HarnessContext`)
- Optional parameters use `?` syntax or default values

**Return Values:**
- Explicit return type annotations on all functions
- Use object returns for multiple values: `{ cid: string; delayMs: number }`
- Async functions return `Promise<T>`

## Module Design

**Exports:**
- POC uses single-file architecture (no exports needed)
- For multi-file modules, prefer named exports

**Barrel Files:**
- Not used in current codebase

## Binary Data Handling

**Critical Convention (per project rules):**
- Use `Uint8Array` for all binary data, not strings
- Convert between formats using helper functions:

```typescript
const hexToBytes = (hex: string): Uint8Array => {
    const normalized = hex.startsWith("0x") ? hex.slice(2) : hex;
    return Uint8Array.from(Buffer.from(normalized, "hex"));
};

const bytesToHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

const utf8ToBytes = (value: string): Uint8Array => Buffer.from(value, "utf8");
const bytesToUtf8 = (value: Uint8Array): string => Buffer.from(value).toString("utf8");
```

## Cryptographic Conventions

**Encryption:**
- AES-256-GCM for content encryption
- ECIES for key wrapping
- 12-byte IVs, 16-byte auth tags

**Key Handling:**
- Never log keys
- Never store keys in localStorage/sessionStorage
- Clear sensitive data after use

---

*Convention analysis: 2026-01-20*
