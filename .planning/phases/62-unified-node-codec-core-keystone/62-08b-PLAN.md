---
phase: 62-unified-node-codec-core-keystone
plan: 08b
type: execute
wave: 7
depends_on: ["62-08a"]
files_modified:
  - apps/web/src/components/file-browser
  - apps/web/src/stores/__tests__
  - apps/web/src/hooks/__tests__
autonomous: true
requirements: [NODE-01]
must_haves:
  truths:
    - "apps/web typechecks cleanly (tsc -b) against the rebuilt core + sdk-core + sdk dist with zero references to FolderMetadata/FileMetadata/FilePointer/FolderEntry in non-test source (SC#5, D-02)"
    - "Every web component call site needing real navigation / rotation / share / write behavior is stubbed with throw new Error('not implemented — phase NN') (D-01); display sites read off the shared Node projection from Plan 08a or a typed cast with // TODO(phase NN), never a retired type"
    - "ALL web test files importing a retired type (FolderMetadata/FileMetadata/FilePointer/FolderEntry/FolderChild) are discovered by grep and quarantined with import-fix + describe.skip + // TODO(phase NN) so the full tsc gate passes (D-02, RESEARCH A2/Pitfall 3); new/changed web tests use .test.ts (never .spec.ts)"
    - "The root pnpm typecheck (crypto→core→api-client→sdk-core→sdk→web→scripts) exits 0 — the Phase-62 D-02 monorepo compile-gate"
  artifacts:
    - apps/web/src/components/file-browser
  key_links:
    - "Plan 08a must land first (web tsc -b checks the whole web project; the logic layer and the shared Node display projection it built are prerequisites); components reuse 08a's projection rather than re-deriving casts"
    - "the root `pnpm typecheck` script is the canonical end-to-end gate (builds crypto→core→api-client→sdk-core→sdk→web tsc -b→scripts in order); it is the authoritative D-02 gate, not the per-task diagnostic tsc"
    - "tsc -b typechecks web TEST files too — a single un-quarantined test importing a retired type fails the gate BEFORE describe.skip evaluates (RESEARCH Pitfall 3), so the quarantine task MUST discover every such file by grep, not just the two known suites"
---

<objective>
Bring the `apps/web` COMPONENT layer (file-browser etc., ~20 files) to COMPILE-ONLY against node/v3, quarantine every web test suite that imports a retired type, and run the authoritative monorepo gate. When `pnpm typecheck` is green, the whole monorepo typechecks (SC#5) and Phase 62's D-02 gate is met. This is the second half of the web compile-gate (Plan 08a did the logic layer).

Purpose: SC#5 requires `apps/web` to typecheck with zero retired-type references after the upstream dist rebuilds. Component behavioral rewiring (preview/version/move/share handlers) depends on phases 63–65/68; here each behavioral handler is stubbed or routed to 08a's already-stubbed hooks, display sites read the shared Node projection, and broken behavioral suites are quarantined.

Output: ~20 component files swapped/stubbed; ALL retired-type web test suites quarantined; full `pnpm typecheck` green.

Context-budget note: this is a mechanical type-swap sweep, not 20 distinct logic changes. The per-task component verify is diagnostic; the atomic gate is the final root `pnpm typecheck`. If context approaches budget mid-sweep, commit progress and continue.

This plan implements ZERO new behavior — type-swap + explicit-stub sweep + test quarantine only. Do NOT build rotation, navigation, durable client state, or any phase-63+ logic.

## Artifacts This Phase Produces (this plan's slice)
- `apps/web/src/components/file-browser/*`: display components re-typed against the Node projection
- quarantined web test suites (`describe.skip` + `// TODO(phase NN)`) — the phase-63/65/68 revive spec
</objective>

<execution_context>
@/Users/myankelev/Code/random/cipher-box/.claude/gsd-core/workflows/execute-plan.md
@/Users/myankelev/Code/random/cipher-box/.claude/gsd-core/templates/summary.md
</execution_context>

<context>
@.planning/phases/62-unified-node-codec-core-keystone/62-CONTEXT.md
@.planning/phases/62-unified-node-codec-core-keystone/62-RESEARCH.md
@.planning/design/2026-06-26-sharing-read-keychaining-design.md
@packages/core/src/node/types.ts
</context>

<tasks>

<task type="execute">
  <name>Task 1: Swap the web component layer (file-browser components) to Node display projections</name>
  <files>apps/web/src/components/file-browser</files>
  <read_first>
    - packages/core/src/node/types.ts (NodeContent fields the components display: cid, size, mimeType, encryptionMode, versions)
    - apps/web/src/components/file-browser/FileList.tsx, FileListItem.tsx, DetailsDialog.tsx, details/FileDetails.tsx, details/FolderDetails.tsx, ContextMenu.tsx, ShareDialog.tsx, MoveDialog.tsx, SharedMoveDialog.tsx, InviteLinkTab.tsx, SharedFileBrowser.tsx, FileBrowser.tsx, and the preview dialogs (Pdf/Image/Audio/Video/TextEditor) — the display sites importing FileMetadata/FilePointer
    - apps/web/src/hooks/folder-helpers.ts / shared-folder-projection.ts (Plan 08a) — reuse the Node display projection it established so components share one mapping
  </read_first>
  <action>
    Sweep the file-browser components: replace retired-type imports with `Node`/`NodeContent`/`SealedChildRef` and read display fields off the shared Node projection established by Plan 08a (size/name/mimeType/versions/cid). For action handlers (move, share, delete, version restore, invite) that trigger real behavior, route to the already-stubbed hook/service from Plan 08a or stub the handler with `throw new Error('not implemented — phase NN')` (68 rotation/move-out, 65 share/invite). Prefer the single shared display projection over per-component casts; where a cast is unavoidable, use a typed cast + `// TODO(phase NN)`. Keep the UI rendering structurally intact (the app is intentionally non-runnable mid-milestone, D-01 — the goal is tsc-clean, not runtime-correct).
  </action>
  <verify>
    <automated>pnpm --filter @cipherbox/web exec tsc -b 2>&1 | tee /tmp/tsc-62-08b.txt; grep "components/" /tmp/tsc-62-08b.txt || true</automated>
  </verify>
  <acceptance_criteria>
    - `grep -rl "FolderMetadata\|FileMetadata\|FilePointer\|FolderEntry\|FolderChild" apps/web/src/components --include=*.tsx --include=*.ts | grep -v "__tests__"` returns nothing.
    - the component-layer SOURCE files produce zero tsc -b errors in /tmp/tsc-62-08b.txt (remaining errors confined to not-yet-quarantined test files, handled in Task 2 — this stage is diagnostic; the atomic gate is Task 2's `pnpm typecheck`).
  </acceptance_criteria>
  <done>Web components compile against the Node display projection; behavioral handlers stubbed with phase markers; zero retired-type refs in component source.</done>
</task>

<task type="execute">
  <name>Task 2: Discover + quarantine ALL retired-type web test suites, then pass the full monorepo typecheck gate (D-02)</name>
  <files>apps/web/src/stores/__tests__/folder.store.test.ts, apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts</files>
  <read_first>
    - .planning/phases/62-unified-node-codec-core-keystone/62-RESEARCH.md Pitfall 3 + A2 (a test importing a deleted/retired type fails tsc BEFORE describe.skip evaluates — imports MUST be fixed/removed, not just skipped)
    - .planning/phases/62-unified-node-codec-core-keystone/62-07-PLAN.md Task 2 (the full-directory read + quarantine pattern to mirror for web)
    - apps/web/src/stores/__tests__/folder.store.test.ts + apps/web/src/hooks/__tests__/useSharedWriteOps.test.ts (the two KNOWN suites referencing retired types / stubbed behavior — but do NOT assume these are the only ones)
    - project memory note: apps/web vitest `include` is `src/**/*.test.ts` — `.spec.ts` files are silently skipped; all new/changed web tests MUST be `.test.ts`
  </read_first>
  <action>
    FIRST discover EVERY affected web test file — do NOT rely on the two known suites (folder.store.test.ts / useSharedWriteOps.test.ts). Run `grep -rl "FolderMetadata\|FileMetadata\|FilePointer\|FolderEntry\|FolderChild" apps/web/src --include=*.test.ts --include=*.test.tsx` (covers every `__tests__/` and `*.test.ts*` file). For EACH hit: fix the retired-type imports (replace with `Node`/`NodeContent`/`SealedChildRef` or remove) so the file typechecks, and wrap the behavioral cases in `describe.skip('... — TODO(phase NN)', ...)` naming the owning phase (63 navigation, 65 write/share/invite/bin re-link, 68 rotation/durable state). Keep pure-type / display cases active. Do NOT delete the suites — they are the phase-63/65/68 revive spec (D-02). Ensure every new or renamed web test file uses the `.test.ts` extension (never `.spec.ts`) — confirm `find apps/web/src -name "*.spec.ts"` is empty.

    THEN run the canonical end-to-end gate: the root `pnpm typecheck` script (builds crypto→core→api-client→sdk-core→sdk→web tsc -b→scripts in dependency order) MUST exit 0. This is the D-02 monorepo compile-gate for the whole phase and the authoritative terminal gate (not the per-task diagnostic tsc).
  </action>
  <verify>
    <automated>echo "=== retired-type test files (must all be quarantined) ==="; grep -rl "FolderMetadata\|FileMetadata\|FilePointer\|FolderEntry\|FolderChild" apps/web/src --include=*.test.ts --include=*.test.tsx || true; echo "=== spec files (must be empty) ==="; find apps/web/src -name "*.spec.ts"; pnpm --filter @cipherbox/web test 2>&1 | tail -8; pnpm typecheck 2>&1 | tail -15</automated>
  </verify>
  <acceptance_criteria>
    - `find apps/web/src -name "*.spec.ts"` returns empty.
    - every file returned by `grep -rl "FolderMetadata\|FileMetadata\|FilePointer\|FolderEntry\|FolderChild" apps/web/src --include=*.test.ts --include=*.test.tsx` has its retired-type imports fixed and its behavioral cases wrapped in `describe.skip` with a `// TODO(phase` marker (none left importing a retired type unguarded).
    - `pnpm --filter @cipherbox/web test` exits 0 (active suites green; quarantined skipped).
    - `pnpm typecheck` exits 0 — the full monorepo (crypto→core→api-client→sdk-core→sdk→web→scripts) typechecks. This is the Phase-62 D-02 gate; SC#5 met.
  </acceptance_criteria>
  <done>All retired-type web suites discovered and quarantined (.test.ts-named, imports fixed, describe.skip + TODO); the full monorepo typecheck (pnpm typecheck) is green — Phase 62 keystone replacement compiles end-to-end.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| stubbed web handler → user action | a silent stub could mask a missing rotation/revocation path that a later phase must wire |
| typed cast at a display site | an `as` cast that hides a retired type would defeat SC#5's zero-reference goal |
| un-quarantined test import | a single retired-type import in any web test fails the tsc gate before describe.skip runs (RESEARCH Pitfall 3) |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-62-10 | Tampering (via omission) | empty stub or retired-type-hiding cast masks missing phase-68 behavior | medium | mitigate | stubs throw with owning phase name; casts target Node (not retired types) + carry // TODO(phase NN); SC#5 grep enforces zero retired refs |
| T-62-11 | Tampering (via omission) | an undiscovered retired-type test suite blocks the gate or hides a stubbed path | medium | mitigate | grep-driven discovery across all *.test.ts* enumerates every suite; quarantine fixes imports + describe.skip with phase marker |
| T-62-03 | Information Disclosure | key material logged in display/debug code | medium | mitigate | no console/JSON of raw key Uint8Arrays introduced during the swap; D-09 preserved |
| T-62-SC | Tampering | dependency supply chain | low | accept | no new packages this phase |
</threat_model>

<verification>
- Component layer `tsc -b` clean (diagnostic capture in /tmp/tsc-62-08b.txt).
- ALL retired-type web test suites discovered by grep and quarantined; no `.spec.ts` files.
- `pnpm typecheck` (root) green — the canonical D-02 monorepo gate.
- `pnpm --filter @cipherbox/web test` green (active) + quarantined skips.
</verification>

<success_criteria>
apps/web typechecks against node/v3 with zero retired-type references in source; behavioral paths stubbed with phase-named throws; ALL retired-type web suites quarantined and .test.ts-named; the full monorepo `pnpm typecheck` is green — SC#5 and the D-02 phase gate are met.
</success_criteria>

<output>
Create `.planning/phases/62-unified-node-codec-core-keystone/62-08b-SUMMARY.md` when done.
</output>
