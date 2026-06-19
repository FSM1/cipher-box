# Phase 54: E2E Test-Infra Typing - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-19
**Phase:** 54-e2e-test-infra-typing
**Areas discussed:** Runtime, Import strategy, Typecheck wiring, Shared helper module

---

## Runtime

| Option                  | Description                                                              | Selected |
| ----------------------- | ----------------------------------------------------------------------- | -------- |
| tsx                     | Run .ts directly via tsx; no build step. Lowest friction.                | ✓        |
| Node native strip-types | node --experimental-strip-types; zero extra dep but experimental + Node-version pin. |          |
| Build to dist           | tsconfig emits compiled JS the runners invoke.                           |          |

**User's choice:** tsx (D-01)

---

## Import strategy

| Option            | Description                                                                            | Selected |
| ----------------- | ------------------------------------------------------------------------------------- | -------- |
| Package entrypoint | Import @cipherbox/sdk-core / crypto / api-client; CI must rebuild deps' dist first.     | ✓        |
| Direct TS source  | Import packages' TS source; catches drift without rebuild but bypasses package boundary. |          |

**User's choice:** Package entrypoint (D-02)
**Notes:** Companion requirement — the typecheck job must build the consumed packages' dist before typechecking the helpers (cross-package dist-staleness gotcha), else drift isn't caught.

---

## Typecheck / lint wiring

| Option                  | Description                                                                  | Selected |
| ----------------------- | --------------------------------------------------------------------------- | -------- |
| Dedicated scripts tsconfig | One tsconfig for the helpers, wired into CI typecheck + root eslint.       | ✓        |
| Per-host-package includes | Add each script to its host package's tsconfig include globs + eslint scope. |          |

**User's choice:** Dedicated scripts tsconfig (D-03)

---

## Shared helper module

| Option                  | Description                                                                | Selected |
| ----------------------- | ------------------------------------------------------------------------- | -------- |
| Factor now              | Extract a typed shared helper (auth + ctx + key derivation) all scripts import. | ✓        |
| Migrate first, factor second | 1:1 port first, factor in a follow-up pass.                            |          |
| Keep per-script         | No shared module; accept duplication.                                       |          |

**User's choice:** Factor now (D-04)
**Notes:** Location is planner's discretion; must be importable from all four host areas (sdk-core/scripts, tests/desktop-e2e, tests/web-e2e, src-tauri).

---

## Claude's Discretion

- Exact location of the shared helper module (D-04).
- Concrete tsconfig layout for the dedicated scripts project and its CI ordering after the dep build.

## Deferred Ideas

None — discussion stayed within phase scope.
