---
created: 2026-06-28
title: Zeroize function-local key/plaintext copies in the AES-GCM helpers (project-wide)
area: crypto
files:
  - packages/crypto/src/aes/encrypt.ts
  - packages/crypto/src/aes/decrypt.ts
resolves_phase: 77
---

## Problem

CodeRabbit (Phase 61 PR #576) flagged that `encryptAesGcmAad` (`packages/crypto/src/aes/encrypt.ts`) creates function-local copies of the key and plaintext (`new Uint8Array(key)` / `new Uint8Array(plaintext)`) and leaves them for GC rather than wiping them in a `finally`, against the project guideline "Clear sensitive data from memory after use."

This is **not specific to Phase 61** — the pre-existing non-AAD `encryptAesGcm` (same file, lines ~40-42) uses the identical copy pattern with no wipe, as do the decrypt helpers. The new AAD variants simply match the established pattern. Wiping only the new variant would make the codebase inconsistent.

Note: JS zeroization is best-effort (no guaranteed memory control; Web Crypto copies key bytes into the internal `CryptoKey` regardless), and the callee must only wipe copies it OWNS — never the caller's reused buffers (see `[[project-zeroization-callee-must-not-zero-reused-buffer]]`). So the right fix is a single consistent pass.

## Fix

Apply a uniform pattern across all AES-GCM helpers (`encryptAesGcm`, `encryptAesGcmAad`, and the decrypt counterparts): hold references to the function-local key/plaintext copies and `.fill(0)` them in a `finally` block after the Web Crypto call resolves. Do NOT touch caller-owned buffers. Add/adjust tests only if they assert buffer state.

## Source

Phase 61 ship-loop CodeRabbit review (PR #576), 2026-06-28 — `packages/crypto/src/aes/encrypt.ts:125`, Major (Security & Privacy). Deferred as a project-wide consistency change rather than a piecemeal Phase-61-only edit. The Phase 61 security review separately PASSed key handling (no caller-buffer mutation, no key logging).
