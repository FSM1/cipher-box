---
phase: 78-recovery-tool-v3-vault-load-guards-web-ux-and-ci-guards
plan: 02
subsystem: recovery-tool
tags: [recovery, ipns, ipfs, crypto, node-v3, browser-bundle, dom-wiring]
status: complete
requires:
  - "78-01: recovery-src/{build.ts,gateway.ts,main.ts}, recovery:build script, esbuild+fflate devDeps"
  - "@cipherbox/crypto barrel (deriveVault*Keypair, unwrapKey, decryptAesGcm/Ctr, base64ToBytes, hexToBytes)"
  - "@cipherbox/core barrel (deserializeVaultBlobV3, unsealNode, unsealChildReadKey, Node/PublishedNode/SealedChildRef types)"
provides:
  - "apps/web/recovery-src/walk.ts (recoverTree: recursive v3 IPNS/IPFS walk over gateway transport)"
  - "apps/web/recovery-src/main.ts (full DOM wiring: privateKey -> vault blob -> rootReadKey -> root -> walk -> zip -> download)"
  - "apps/web/public/recovery.html (self-contained shipped tool with inlined bundle, all six e2e testids)"
  - "re-runnable recovery:build splice (BEGIN/END markers)"
affects:
  - "plan 78-03 (un-fixmes tests/web-e2e/tests/recovery.spec.ts against the shipped recovery.html; CI typecheck wiring for recovery-src)"
tech-stack:
  added: []
  patterns: [gateway-http-transport, parent-mirror-generation-unseal, no-hand-roll-crypto, idempotent-html-splice]
key-files:
  created:
    - apps/web/recovery-src/walk.ts
  modified:
    - apps/web/recovery-src/main.ts
    - apps/web/recovery-src/build.ts
    - apps/web/public/recovery.html
decisions:
  - "Committed the SPLICED self-contained recovery.html (vite serves public/ verbatim and the e2e loads /recovery.html directly, so the shipped artifact must carry the bundle inline)."
  - "Made recovery:build re-runnable via RECOVERY_BUNDLE:START/END markers so future main.ts/walk.ts edits regenerate the shipped bundle instead of silently no-opping on the consumed placeholder."
metrics:
  duration: ~35m
  completed: 2026-07-12
  tasks: 3
  files-created: 1
  files-modified: 3
  bundle-bytes: 308763
---

# Phase 78 Plan 02: Recovery Tool v3 Walk, DOM Wiring, and Self-Contained recovery.html Summary

Completed the SC1 trust-nothing recovery tool: a recursive v3 IPNS/IPFS walk (`recoverTree`) that mirrors the production read-chain using only `@cipherbox/crypto` + `@cipherbox/core` primitives over the 78-01 gateway transport, full `main.ts` DOM wiring from a pasted `privateKey` through to a downloadable zip, and a rewritten self-contained `recovery.html` with the esbuild bundle inlined and zero CDN/API dependency.

## What Was Built

- Task 1 — `recovery-src/walk.ts` (NEW): `recoverTree(rootNode, rootReadKey, gatewayConfig, onProgress)` recursively walks each `SealedChildRef`: verified IPNS resolve -> IPFS fetch -> `unsealChildReadKey` (parent-mirror generation) -> `unsealNode` -> folder recurse / file decrypt (`decryptAesGcm`/`decryptAesCtr` on the inline raw `content.fileKey`, base64 `content.fileIv`). Best-effort per-child skip (reports and continues) so one bad sibling never aborts the vault recovery. Per-child `childReadKey` zeroed at its terminal owner; `parentReadKey` never zeroed (D-09). Also exports `fetchPublishedNode` for reuse by `main.ts`.
- Task 2 — `recovery-src/main.ts` (REWRITTEN from the 78-01 spike): DOM event wiring on `recovery-start-btn`. Validates the 32-byte hex key (tolerating a `0x` prefix), reads both gateway inputs, derives `deriveVaultKeyIpnsKeypair` + `deriveVaultIpnsKeypair`, resolves + `deserializeVaultBlobV3` the vault-key blob, `unwrapKey` -> `rootReadKey`, resolves + `unsealNode` the root, drives `recoverTree`, `zipSync`-packs the result, and enables `recovery-download-btn`. Streams every step to `recovery-progress-log`; the key is zeroed in a `finally` and never written to persistent browser storage.
- Task 3 — `apps/web/public/recovery.html` (REWRITTEN) + `recovery-src/build.ts` (splice made idempotent): recovery.html is now a template preserving the full DOM shell, all six `data-testid`s, and the key textarea `autocomplete="off"` / post-recovery clear-history note, with every `cdn.jsdelivr` script/import removed and a single `<!-- RECOVERY_BUNDLE -->` placeholder. `recovery:build` splices the 301.5 KiB esbuild bundle inline (wrapped in BEGIN/END markers); the committed file is the spliced self-contained artifact.

## Design Fidelity (locked decisions)

- D-01 / D-04: recovery runs from `privateKey` alone over the caller-configured HTTP gateway; no CipherBox API, no Web3Auth, no libp2p.
- D-02: `grep -rnE "from '@cipherbox/(sdk|sdk-core)'" apps/web/recovery-src` returns nothing — no SDK facade, no sdk-core runtime, no API relay. (The only `/api/v0/name/resolve` reference is the public Kubo gateway fallback in gateway.ts, not the CipherBox API.)
- D-03: every seal/unseal/decrypt is a bare passthrough to the shipped `@cipherbox/core` / `@cipherbox/crypto` barrels; nothing crypto/codec is hand-rolled.
- Pitfall 2 (generation source): `unsealChildReadKey` is fed `childRef.generation` (the parent mirror), never `published.generation` — the #1 porting bug, called out inline.
- T-78-04 / T-78-05: AEAD auth-tag verification in `unsealNode` + `decryptAesGcm` fails closed on any tampered IPFS content or wrong-generation binding.
- T-78-06: the pasted key is in-memory only (no localStorage/sessionStorage), zeroed after use.

## Deviations from Plan

### Idempotent HTML splice [Rule 3 - blocking build regenerability]

- **Found during:** Task 3.
- **Issue:** The plan's one-shot placeholder splice consumes `<!-- RECOVERY_BUNDLE -->` on the first `recovery:build`. Because the committed `public/recovery.html` must be the spliced file (vite serves `public/` verbatim; the e2e loads `/recovery.html` directly), a later `recovery:build` after any `main.ts`/`walk.ts` edit would find no placeholder and silently no-op, shipping a stale bundle.
- **Fix:** Wrapped the inlined bundle in `<!-- RECOVERY_BUNDLE:START -->` / `<!-- RECOVERY_BUNDLE:END -->` markers and taught `build.ts` to re-splice between the markers when present (falling back to the bare placeholder on first run). Verified idempotent: two consecutive builds leave exactly one `<script>` tag.
- **Files modified:** `apps/web/recovery-src/build.ts`.
- **Commit:** 176e781b5.

### Blob-construction cast [Rule 3 - satisfy TS 5.9 lib]

- **Found during:** Task 2 typecheck. Under the ES2023/DOM lib, `zipSync`'s `Uint8Array<ArrayBufferLike>` is not assignable to `BlobPart` (SharedArrayBuffer union). Applied the codebase's established `new Blob([zipBytes as BlobPart], ...)` pattern (matching `apps/web/src/services/download.service.ts`).

## Verification

- `pnpm --filter @cipherbox/web recovery:build` -> exit 0, `bundle size: 308763 bytes (301.5 KiB)`, splices into recovery.html; a second run stays at exactly one `<script>` tag (idempotent).
- All six testids present in recovery.html; `grep -c cdn.jsdelivr` -> 0; no `<script src="http...">` external script.
- recovery-src typecheck clean (`tsc --noEmit` over an ES2023/DOM/node config covering all four recovery-src files).
- `eslint apps/web/recovery-src` -> clean (0 errors).
- D-02 import grep over recovery-src -> empty.

## Notes for Plan 78-03

- The shipped `apps/web/public/recovery.html` now speaks v3 end-to-end; `tests/web-e2e/tests/recovery.spec.ts` can drop its `test.fixme` (all six testids are stable). Note the seed test currently uploads to the root folder only, so it exercises the root-level file path; a nested-folder seed would additionally cover the recursive descent.
- recovery-src is NOT yet in any tsconfig `include`, so CI does not typecheck it. This plan verified it via an ephemeral `tsconfig.recovery.json` (ES2023 + DOM + node libs, removed after use). 78-03's CI-guard scope should wire a persistent recovery-src typecheck (and optionally a `recovery:build` gate) into CI.
- The recovery walk decrypts current file content only; past `VersionEntry` history is not recovered (out of this plan's scope) — a future enhancement if full version recovery is desired.

## Self-Check: PASSED
