---
phase: 62-unified-node-codec-core-keystone
plan: 08a
type: execute
wave: 6
depends_on: ["62-07"]
files_modified:
  - apps/web/src/stores/folder.store.ts
  - apps/web/src/hooks
  - apps/web/src/services
  - apps/web/src/lib
  - apps/web/src/utils
autonomous: true
requirements: [NODE-01]
must_haves:
  truths:
    - "apps/web LOGIC layer (stores/hooks/services/lib/utils) typechecks against the rebuilt core + sdk-core + sdk dist with zero references to FolderMetadata/FileMetadata/FilePointer/FolderEntry/FolderChild in non-test source (SC#5 partial, D-02)"
    - "Every web logic-layer call site needing real navigation / rotation / share / write behavior is stubbed with throw new Error('not implemented — phase NN') (D-01); display reads use a Node-based projection or a typed cast with // TODO(phase NN), never a retired type"
  artifacts:
    - apps/web/src/stores/folder.store.ts
    - apps/web/src/services/file-metadata.service.ts
  key_links:
    - "FIRST rebuild core + sdk-core + sdk dist (web tsc -b checks the built dist of all three); this plan establishes the shared Node display projection (folder-helpers / shared-folder-projection) that Plan 08b's components reuse"
    - "this is a DIAGNOSTIC stage — the per-task tsc verify is informational (captured to a temp file, grep is non-gating per the exit-code-safe rule); the authoritative end-to-end gate is the root `pnpm typecheck` in Plan 08b (D-02)"
---

<objective>
Bring the `apps/web` LOGIC layer (stores/hooks/services/lib/utils, ~23 files) to COMPILE-ONLY against node/v3 (D-01/D-02). This is the first half of the web compile-gate, split out from the former Plan 08 to keep the unsupervised mechanical sweep within context budget. Plan 08b finishes the component layer and runs the authoritative monorepo gate.

Purpose: SC#5 requires `apps/web` to typecheck with zero retired-type references after the upstream dist rebuilds. Web's behavioral rewiring (rotateReadFromNode, durable client state, folderTree reconcile) is OWNED by phase 68; navigation/preview/version display paths depend on phases 63–65. Here every behavioral call site in the logic layer is stubbed and display sites are adapted to a Node-based projection that 08b's components reuse.

Output: ~23 web logic-layer files swapped/stubbed; the shared Node display projection established for 08b.

Context-budget note: this is a mechanical type-swap sweep, not 23 distinct logic changes. Work the logic layer as a file group; the per-task verify is a decreasing tsc error count, NOT a hard gate (the atomic gate is the root `pnpm typecheck` in 08b). If context approaches budget mid-sweep, commit progress and continue.

This plan implements ZERO new behavior — type-swap + explicit-stub sweep only. Do NOT build rotation, navigation, durable client state, or any phase-63+ logic.

## Artifacts This Phase Produces (this plan's slice)
- `apps/web/src/stores/folder.store.ts`: folderTree state re-typed against `Node`
- `apps/web/src/services/file-metadata.service.ts`: file metadata fetch/decrypt adapted to `NodeContent` or stubbed to phase 63
- the shared Node display projection (`folder-helpers` / `shared-folder-projection`) consumed by Plan 08b
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
  <name>Task 1: Rebuild upstream dist, then swap the web logic layer (stores/hooks/services/lib/utils) to Node + stub behavioral paths</name>
  <files>apps/web/src/stores/folder.store.ts, apps/web/src/hooks, apps/web/src/services/file-metadata.service.ts, apps/web/src/services/delete.service.ts, apps/web/src/services/download.service.ts, apps/web/src/services/invite.service.ts, apps/web/src/lib/crypto/key-wrapping.ts, apps/web/src/utils/fileTypes.ts</files>
  <read_first>
    - packages/core/src/node/types.ts (Node/SealedChildRef/NodeContent shapes web now consumes)
    - apps/web/src/stores/folder.store.ts (folderTree state typed against the retired types — re-type against Node)
    - apps/web/src/services/file-metadata.service.ts (file metadata fetch/decrypt — navigation/decrypt owned by phase 63; stub or adapt to NodeContent)
    - apps/web/src/hooks/useFileVersions.ts, useFilePreview.ts, useStreamingPreview.ts, useFolderMutations.ts, useSharedWriteOps.ts, folder-helpers.ts (version/preview/mutation display + behavior — adapt display to NodeContent.versions, stub mutation/rotation to phase 65/68)
    - apps/web/src/lib/crypto/key-wrapping.ts (vault key handling — adapt to two-key vault from Plan 03 if it touches rootReadKey/rootWriteKey)
    - .planning/design/2026-06-26-sharing-read-keychaining-design.md §7.2 step 7 (web owns executeLazyRotation→rotateReadFromNode, durable state — all phase 68; confirms stub targets)
    - .planning/phases/62-unified-node-codec-core-keystone/62-RESEARCH.md (apps/web blast radius + Consumer Stub Pattern; A3 ~10-15 files, actual ~23 logic files)
  </read_first>
  <action>
    FIRST `pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk build` so web tsc -b sees fresh upstream dist. Then sweep the logic-layer files: replace `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry`/`FolderChild` imports with `Node`/`SealedChildRef`/`NodeContent`/`VersionEntry` (node's). For display reads (size, name, mimeType, versions), map onto `Node`/`NodeContent` fields and centralize the mapping in a single shared projection (e.g. `folder-helpers` / `shared-folder-projection`) so Plan 08b's components reuse it. For behavioral call sites that need real new logic (rotation, navigation, share mutation, durable generation/seq state), `throw new Error('not implemented — phase NN')` with the precise owning phase (68 for rotation/durable state, 63 for navigation, 65 for write/invite). Where a display read needs a value the new model does not yet surface, use a typed cast with a `// TODO(phase NN)` comment rather than reintroducing a retired type. Never zero caller-owned key material (D-09). Never log key material.
  </action>
  <verify>
    <automated>pnpm --filter @cipherbox/core build >/dev/null 2>&1; pnpm --filter @cipherbox/sdk-core build >/dev/null 2>&1; pnpm --filter @cipherbox/sdk build >/dev/null 2>&1; pnpm --filter @cipherbox/web exec tsc -b 2>&1 | tee /tmp/tsc-62-08a.txt; grep -E "stores/|hooks/|services/|lib/|utils/" /tmp/tsc-62-08a.txt || true</automated>
  </verify>
  <acceptance_criteria>
    - `grep -rl "FolderMetadata\|FileMetadata\|FilePointer\|FolderEntry\|FolderChild" apps/web/src/stores apps/web/src/hooks apps/web/src/services apps/web/src/lib apps/web/src/utils --include=*.ts --include=*.tsx | grep -v "__tests__"` returns nothing.
    - `grep -rc "not implemented — phase" apps/web/src/hooks apps/web/src/services apps/web/src/stores` ≥ 1.
    - the logic-layer SOURCE files produce zero tsc -b errors in /tmp/tsc-62-08a.txt (component-layer errors from Plan 08b and not-yet-quarantined test-file errors may still remain — this stage is diagnostic, the atomic gate is 08b's `pnpm typecheck`).
  </acceptance_criteria>
  <done>Web logic layer compiles against node/v3; behavioral paths stubbed with phase-named throws; zero retired-type refs in logic source; shared Node display projection established for Plan 08b.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| stubbed web handler → user action | a silent stub could mask a missing rotation/revocation path that a later phase must wire |
| typed cast at a display site | an `as` cast that hides a retired type would defeat SC#5's zero-reference goal |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
|-----------|----------|-----------|----------|-------------|-----------------|
| T-62-10 | Tampering (via omission) | empty stub or retired-type-hiding cast masks missing phase-68 behavior | medium | mitigate | stubs throw with owning phase name; casts target Node (not retired types) + carry // TODO(phase NN); SC#5 grep enforces zero retired refs |
| T-62-03 | Information Disclosure | key material logged in display/debug code | medium | mitigate | no console/JSON of raw key Uint8Arrays introduced during the swap; D-09 preserved |
| T-62-SC | Tampering | dependency supply chain | low | accept | no new packages this phase |
</threat_model>

<verification>
- Upstream dist rebuilt (core/sdk-core/sdk), then web logic-layer source `tsc -b` clean (diagnostic capture in /tmp/tsc-62-08a.txt).
- `grep` confirms zero retired-type refs in web logic source (non-test).
- The authoritative monorepo gate (`pnpm typecheck`) runs in Plan 08b.
</verification>

<success_criteria>
apps/web logic layer typechecks against node/v3 with zero retired-type references; behavioral paths stubbed with phase-named throws; the shared Node display projection is established for Plan 08b's component sweep.
</success_criteria>

<output>
Create `.planning/phases/62-unified-node-codec-core-keystone/62-08a-SUMMARY.md` when done.
</output>
