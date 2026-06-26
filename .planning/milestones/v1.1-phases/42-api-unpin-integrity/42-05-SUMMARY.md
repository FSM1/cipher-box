---
phase: 42-api-unpin-integrity
plan: "05"
subsystem: api
tags:
  - security
  - tdd
  - controller
  - api-client
  - ownership
dependency_graph:
  requires:
    - 42-03 (VaultService.guardedUnpin method)
    - 42-04 (metrics for cross-user audit)
  provides:
    - POST /ipfs/unpin delegating to guardedUnpin with req.user.id (D-01)
    - upload compensation path via guardedUnpin (D-13 comment)
    - opaque unpin response { success: true } for all outcomes (D-11)
  affects:
    - apps/api/src/ipfs/ipfs.controller.ts
    - apps/api/src/ipfs/ipfs.controller.spec.ts
    - packages/api-client/openapi.json
tech_stack:
  added: []
  patterns:
    - NestJS @Request() decorator injection for userId propagation
    - best-effort .catch(() => undefined) swallowing compensation errors
    - TDD RED/GREEN: spec-first, then implementation
key_files:
  created: []
  modified:
    - apps/api/src/ipfs/ipfs.controller.ts
    - apps/api/src/ipfs/ipfs.controller.spec.ts
    - packages/api-client/openapi.json
decisions:
  - "fileUnpins.inc() removed from controller unpin(); it now lives exclusively inside guardedUnpin (42-03) — prevents double-counting (D-17)"
  - "openapi.json diff is formatting-only (JSON pretty-print array style); confirmed by grep: no schema change to /ipfs/unpin request/response — D-11 holds"
  - "node_modules symlinked from main repo during api:generate to avoid pnpm install in worktree"
metrics:
  duration: "7 minutes"
  completed_date: "2026-06-12"
  tasks_completed: 2
  files_changed: 3
---

# Phase 42 Plan 05: Controller Wiring and api:generate Summary

Controller wires POST /ipfs/unpin to VaultService.guardedUnpin with req.user.id; upload compensation rerouted through guardedUnpin with D-13 race window comment; api-client regenerated with formatting-only openapi.json delta confirming D-11.

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 RED | Add failing tests for guardedUnpin delegation and compensation | ad0681ed6 | ipfs.controller.spec.ts |
| 1 GREEN | Wire unpin to guardedUnpin; reroute compensation through guardedUnpin | 532409b3b | ipfs.controller.ts, openapi.json |
| 2 | api:generate run; openapi.json regenerated and committed with controller change | 532409b3b | packages/api-client/openapi.json |

## What Was Built

### Controller Changes

`apps/api/src/ipfs/ipfs.controller.ts`:

1. `unpin()` signature changed from `async unpin(@Body() dto: UnpinDto)` to `async unpin(@Request() req: RequestWithUser, @Body() dto: UnpinDto)`.
2. Body replaced: `await this.ipfsProvider.unpinFile(dto.cid); this.metricsService.fileUnpins.inc();` removed. Now: `await this.vaultService.guardedUnpin(req.user.id, dto.cid); return { success: true };`. Response DTO unchanged (D-11).
3. `upload()` compensation path replaced: `await this.ipfsProvider.unpinFile(result.cid).catch(() => undefined)` replaced with the D-13 comment block followed by `await this.vaultService.guardedUnpin(req.user.id, result.cid).catch(() => undefined)`.

D-13 comment at the compensation site:

```
// RACE WINDOW NOTE (D-13): a concurrent deleter of the same deduped CID could
// have refcounted to zero between the Kubo pin above and recordPin here,
// leaving this uploader with a row-but-no-pin. Cryptographically negligible
// (requires identical ciphertext + sub-second window). Drift report detects.
```

### Test Coverage

5 new/updated behaviors in `ipfs.controller.spec.ts`:

- Test 1: `unpin()` calls `vaultService.guardedUnpin(req.user.id, dto.cid)` exactly once; `ipfsProvider.unpinFile` not called
- Test 2: response is `{ success: true }` with no extra fields (`toStrictEqual` asserts exact shape)
- Test 3: upload happy path does not call guardedUnpin or ipfsProvider.unpinFile when recordPin succeeds
- Test 4: upload compensation calls `guardedUnpin(req.user.id, result.cid)` on recordPin failure; `ipfsProvider.unpinFile` not called; original error rethrown
- Test 5: compensation is best-effort; guardedUnpin rejection swallowed; original recordPin error identity preserved (toBe assertion)

All 869 tests pass (43 suites).

### api-client Regeneration

`pnpm api:generate` run from the worktree with symlinked node_modules. Produced a formatting-only diff in `openapi.json` (JSON array style changed from inline to multi-line for `tags` fields). No schema change to `/ipfs/unpin` endpoint — confirmed: `@Request()` is not an OpenAPI body parameter, and `UnpinDto`/`UnpinResponseDto` are unchanged. D-11 confirmed: the wire contract is unchanged.

## Deviations from Plan

None - plan executed exactly as written.

### Minor Implementation Notes

- `fileUnpins.inc()` removed from controller. Now increments exclusively inside `guardedUnpin` (42-03). D-17 compliant.
- ESLint reformatted `unpin()` signature to single-line during `pnpm api:generate`'s lint:fix step. Accepted as clean.

## TDD Gate Compliance

- RED gate: `test(42-05)` commit `ad0681ed6` — PRESENT
- GREEN gate: `feat(42-05)` commit `532409b3b` — PRESENT (after RED)
- REFACTOR gate: not required, implementation was clean

## Known Stubs

None. The controller delegates fully to guardedUnpin which is fully implemented in 42-03.

## Threat Surface Scan

T-42-14 mitigated: `unpin()` now forwards `req.user.id` to `guardedUnpin`; no code path in the controller reaches `ipfsProvider.unpinFile`.
T-42-15 mitigated: response is constant `{ success: true }` for all outcomes.
T-42-16 mitigated: upload compensation routes through `guardedUnpin` (ownership + refcount), not raw unpinFile.
T-42-17 mitigated: `fileUnpins.inc()` now exclusively in `guardedUnpin`; controller does not double-increment.

No new network endpoints, auth paths, or trust boundaries introduced.

## Self-Check: PASSED

- `apps/api/src/ipfs/ipfs.controller.ts` contains `guardedUnpin` at lines 126 and 149 — FOUND
- `apps/api/src/ipfs/ipfs.controller.ts` contains 0 occurrences of `ipfsProvider.unpinFile` — CONFIRMED
- `apps/api/src/ipfs/ipfs.controller.ts` contains D-13 comment at line 122 — FOUND
- `packages/api-client/openapi.json` staged alongside controller change — CONFIRMED
- commit ad0681ed6 (RED) — FOUND
- commit 532409b3b (GREEN) — FOUND
- 869/869 tests passing — CONFIRMED
