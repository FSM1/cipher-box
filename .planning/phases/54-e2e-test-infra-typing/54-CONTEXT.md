# Phase 54: E2E Test-Infra Typing - Context

**Gathered:** 2026-06-19
**Status:** Ready for planning
**Source:** Discuss-phase. Scope is one captured todo (#11) under requirement HARD-05 — migrate the
untyped `.mjs` E2E helper scripts to TypeScript. Tooling/test-infra only, no app-runtime code. Four
design forks discussed and locked at the recommended defaults.

<domain>

## Phase Boundary

Convert the 7 hand-written `.mjs` E2E helper scripts to TypeScript under requirement **HARD-05**, so
SDK/crypto/api-client contract drift is caught at `tsc`/`eslint` time instead of surfacing 14 minutes
into a single-OS E2E run on `main`. This is the recurring class behind `edit-filepointer.mjs`
breaking on #488→#495 and the IPNS-sequence helper breaking on #509 (Windows-only).

In scope — migrate all 7:

- `packages/sdk-core/scripts/edit-filepointer.mjs`
- `packages/sdk-core/scripts/rename-folder.mjs`
- `packages/sdk-core/scripts/verify-filepointer.mjs`
- `tests/desktop-e2e/scripts/test-move-content.mjs`
- `tests/desktop-e2e/scripts/bump-ipns-sequence.mjs`
- `tests/web-e2e/staging-perf-wallet.mjs`
- `apps/desktop/src-tauri/generate-test-vectors.mjs`

Out of scope: HARD-02/03/04/06 (Phases 51, 52, 53, 55); rewriting the E2E test SUITES themselves
(only the helper scripts they invoke); any behavioral change to the flows the scripts drive — this is
a typing/infra migration, behavior must stay identical.

</domain>

<decisions>

## Implementation Decisions

### Runtime

- **D-01 (runtime, fork):** **tsx.** Execute the migrated `.ts` helpers directly via `tsx`
  (add as a devDependency); no build step. Lowest-friction for CI/runner invocation — the todo's lean.

### Import strategy

- **D-02 (imports, fork):** **Import the package entrypoint** (`@cipherbox/sdk-core`,
  `@cipherbox/crypto`, `@cipherbox/api-client`) rather than `../dist/index.mjs` relative paths —
  consistent with how the web app and other consumers import. **Required companion:** the CI typecheck
  job must rebuild the consumed packages' `dist` BEFORE typechecking the helpers (the known
  cross-package dist-staleness gotcha — `tsc` checks built dist, not source). Wire the typecheck step
  to depend on the dependency build so drift is actually caught.

### Typecheck / lint wiring

- **D-03 (wiring, fork):** **Dedicated scripts tsconfig.** Add one tsconfig covering the E2E helper
  scripts, wired into CI typecheck + root eslint scope, rather than threading each file into its host
  package's existing tsconfig. Uniform, single place, not entangled with each host package's build
  quirks. (Note: `apps/web` vitest `include` is `src/**/*.test.ts` — these helpers live outside `src`,
  so they must be put under a checked project explicitly.)

### Shared helper module

- **D-04 (shared lib, fork):** **Factor now.** Extract a small typed shared helper module for the
  duplicated auth (`/auth/test-login`), `ctx` construction, and key derivation; all scripts import it.
  Location is the planner's discretion (must be importable from sdk-core/scripts, tests/desktop-e2e,
  tests/web-e2e, and src-tauri). DRY + one place to absorb future contract changes.

### Locked by the todo (no fork)

- **D-05:** Migrate all 7 scripts to `.ts`; drop every `../dist/*.mjs` relative import (D-02).
- **D-06:** Update BOTH the bash and PowerShell runners together (`tests/desktop-e2e` `run-all.sh` /
  `run-all.ps1`, plus the web runners) to invoke `tsx <file>.ts` instead of `node <file>.mjs` —
  cross-platform parity is mandatory (the #509 break was Windows-only because the `.ps1` and `.sh`
  diverged).
- **D-07:** Behavior-preserving — the migrated scripts must drive the exact same flows; this phase
  converts runtime E2E breakages into fast local `tsc`/`eslint` failures, it does not change what the
  scripts do.

### Folded Todos

- **[#11]** `2026-06-18-migrate-mjs-e2e-helper-scripts-to-typescript.md` — the full file list, design
  questions, and recurrence history. Maps to D-01..D-07.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & source findings

- `.planning/todos/pending/2026-06-18-migrate-mjs-e2e-helper-scripts-to-typescript.md` — #11: file
  list, design questions, recurrence history. The primary ref.
- `.planning/REQUIREMENTS.md` — HARD-05.
- `.planning/ROADMAP.md` §"Phase 54" — scope checkbox.

### Scripts to migrate

- `packages/sdk-core/scripts/{edit-filepointer,rename-folder,verify-filepointer}.mjs`
- `tests/desktop-e2e/scripts/{test-move-content,bump-ipns-sequence}.mjs`
- `tests/web-e2e/staging-perf-wallet.mjs`
- `apps/desktop/src-tauri/generate-test-vectors.mjs`

### Runners to update (cross-platform, together)

- `tests/desktop-e2e/` `run-all.sh` + `run-all.ps1` (the bash/PowerShell pair that diverged on #509).
- The web-e2e runner(s) that invoke `staging-perf-wallet.mjs`.

### Package APIs the helpers consume

- `@cipherbox/sdk-core`, `@cipherbox/crypto`, `@cipherbox/api-client` package entrypoints (D-02).

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- The scripts already share auth (`/auth/test-login`), `ctx` construction, and key derivation — the
  D-04 shared module is an extraction of existing duplicated logic, not new behavior.
- `tsx` is already a common monorepo dev tool pattern; using it avoids a bespoke build.

### Established Patterns

- Cross-package dist staleness: `tsc` checks built `dist`, not source (rebuild sdk-core/crypto dist
  before consumer typecheck). D-02's entrypoint import inherits this — the typecheck job must build
  deps first, or drift won't be caught.
- `apps/web` vitest `include` is `src/**/*.test.ts`; `.spec.ts` and out-of-`src` files are skipped —
  so the helpers need an explicit checked project (D-03), they won't be picked up incidentally.
- The bash/PowerShell runner pair has diverged before (one `throw`s, the other warns) — D-06 keeps
  them in lockstep.

### Integration Points

- CI: the new dedicated scripts tsconfig must be added to the typecheck workflow and eslint scope, and
  ordered after the dependency `dist` build (D-02/D-03).
- The desktop + web E2E runners change their invocation command (`node *.mjs` → `tsx *.ts`); verify
  the full desktop + web E2E suites still pass post-migration (behavior unchanged, D-07).

</code_context>

<specifics>

## Specific Ideas

- D-02 explicitly accepts the dist-rebuild ordering cost in exchange for convention-consistency; the
  planner must make the typecheck job build deps first so the entrypoint import actually catches drift.

</specifics>

<deferred>

## Deferred Ideas

None — discussion stayed within phase scope (helper-script typing).

</deferred>

---

_Phase: 54-e2e-test-infra-typing_
_Context gathered: 2026-06-19_
