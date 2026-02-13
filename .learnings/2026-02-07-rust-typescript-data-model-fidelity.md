# Rust-TypeScript Data Model Fidelity in Cross-Language Ports

**Date:** 2026-02-07

## Original Prompt

> /gsd:plan-phase (Phase 9: Desktop Client — Tauri app with FUSE mount, porting existing TypeScript crypto/data models to Rust)

## What I Learned

- **Every field matters when porting TypeScript types to Rust structs.** The plan checker caught that `FolderEntry` was missing `ipnsPrivateKeyEncrypted` and `VaultResponse` was missing `encryptedRootIpnsPrivateKey` + `rootIpnsPublicKey`. These aren't cosmetic omissions — without them, IPNS record signing (required for every write operation) would silently fail at runtime.
- **Encrypted key fields are the most dangerous to miss.** They don't show up in happy-path read operations (you can browse files fine), but every mutation path breaks. Easy to miss during planning because reads work without them.
- **Serde `rename_all = "camelCase"` is essential** when Rust structs deserialize from TypeScript-generated JSON. The TypeScript types use camelCase (`ipnsPrivateKeyEncrypted`), Rust convention is snake_case (`ipns_private_key_encrypted`). Without the Serde attribute, deserialization silently drops fields.
- **Desktop auth can't use HTTP-only cookies.** Tauri apps run on `tauri://localhost` which doesn't participate in the browser cookie jar. The API needs a body-based refresh token path for desktop clients.
- **System browser redirect is wrong for key extraction.** Passing private keys as URL parameters (deep link callback) is a security risk — URLs appear in browser history, process lists, and logs. Revised to run Web3Auth inside the Tauri webview with IPC key transfer instead.

## What Would Have Helped

- A checklist of ALL fields from the TypeScript types before writing Rust equivalents (the planner initially just grabbed the "obvious" fields)
- Knowing upfront that fuser's macOS support is "untested" — this is the highest-risk integration point and should be proven with a PoC before any detailed planning
- Understanding that FUSE-T has specific limitations (no file locking, readdir must return all entries in one pass, timestamps can't be set independently) — these constrain the FUSE implementation design

## Key Files

- `packages/crypto/src/folder/types.ts` — TypeScript FolderEntry/FileEntry types (source of truth for Rust ports)
- `apps/api/src/vault/vault.service.ts` — VaultResponse shape (what the API actually returns)
- `packages/crypto/src/ipns/` — IPNS record creation (must be replicated exactly in Rust)
- `.planning/phases/09-desktop-client/09-RESEARCH.md` — FUSE-T limitations and Tauri patterns
