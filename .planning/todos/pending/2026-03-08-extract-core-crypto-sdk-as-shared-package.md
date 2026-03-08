---
created: 2026-03-08T01:27:44.049Z
title: Extract core crypto SDK as shared package
area: architecture
files:
  - apps/web/src/hooks/useFolderMutations.ts
  - apps/web/src/hooks/useFileOperations.ts
  - apps/web/src/lib/crypto/
  - apps/web/src/lib/ipfs/
  - apps/web/src/lib/ipns/
  - apps/desktop/src-tauri/src/crypto/
---

## Problem

The core crypto + IPFS/IPNS + metadata logic is tightly coupled to React hooks and Zustand stores in `apps/web/src/hooks/`. This means:

- **Web app**: logic buried inside React hooks (`useFolderMutations`, `useFileOperations`, etc.)
- **Desktop app**: reimplements the same logic in Rust (`apps/desktop/src-tauri/src/crypto/`)
- **E2E tests**: must drive the full browser UI to trigger any file operation
- **Load tests**: cannot call operations without a browser context
- **Future CLI**: would need yet another reimplementation

Discovered during load test development (Phase 18) — generating staging load requires Playwright to click through every UI interaction because there's no programmatic API for vault operations.

## Solution

Extract a framework-agnostic `packages/sdk` TypeScript package that handles:

- Key derivation (ed25519 → vault keypair → folder keys)
- AES-256-GCM encryption/decryption
- Folder metadata serialization/deserialization
- IPFS upload/download via API client
- IPNS publish/resolve
- Vault state management (folder tree, file registry)

Interface sketch:

```typescript
const client = new CipherBoxClient({ accessToken, vaultKeypair });
await client.createFolder('documents');
await client.uploadFile('documents', file, 'report.pdf');
await client.renameItem('documents', 'report.pdf', 'final-report.pdf');
await client.moveItem('final-report.pdf', 'documents', 'archive');
```

Web app hooks would become thin wrappers around the SDK. Desktop app could consume via wasm-bindgen or continue with Rust implementation. Tests and load generators could use it directly without a browser.
