# Phase 55: Large Source-File Refactor - Context

**Gathered:** 2026-06-19
**Status:** Ready for planning
**Source:** Discuss-phase. Scope is one captured todo (#17) under requirement HARD-06 — a 26-file
split/dedup survey with per-file plans and deep-dives. Four forks discussed and locked; this phase
takes **Tier 1 + Tier 2 only** (Tier 3 deferred). Internal refactor, no app-runtime behavior change.

<domain>

## Phase Boundary

Split/dedup oversized source files per the survey's **Tier 1 (quick wins) and Tier 2 (cross-platform
dedup)** under requirement **HARD-06**. The public surface stays byte-for-byte stable (the
`@cipherbox/sdk` client class, `cipherbox_fuse` crate re-exports, component/hook signatures, NestJS
DI) — every split is internal-only, **no `pnpm api:generate`**, no consumer edits. Behavior is
unchanged; this converts navigability/review debt and cross-platform drift hazards into cohesive
modules.

### In scope — Tier 1 (test-guarded / mechanical)

- `crates/fuse/src/lib.rs` (3276) → 6 modules (`runtime`/`events`/`publish`/`metadata`/`fs`/`replay`);
  `lib.rs` shrinks to ~120 LoC of decls + re-exports. **Do this first** (biggest, mechanical,
  strong tests). See the survey's lib.rs deep-dive for module assignments, visibility bumps, and the
  per-feature-set phasing.
- `crates/fuse/src/write_ops.rs` (1132) → `write_ops/{file_data,delete,mkdir,rename}.rs` behind the
  existing `pub(crate) mod implementation` facade; dedupe the ~50-line bin-publish tail shared by
  unlink + rmdir.
- `packages/sdk-core/src/folder/index.ts` (602) → barrel-preserving split
  (`load.ts`/`metadata-ops.ts`/`registration.ts`); `index.ts` re-exports. Zero import churn (tests
  target the `../folder` barrel).
- `apps/api/src/ipns/ipns.service.ts` (596) → extract only the ~99 LoC record codec helpers into
  `ipns-record.codec.ts`; keep the DI class + orchestration intact (do NOT split into collaborator
  services).
- `apps/web/src/components/file-browser/DetailsDialog.tsx` (664) → `details/{VersionHistory,FileDetails,FolderDetails,DetailsPrimitives}.tsx`;
  keep the two cross-guarded `useEffect`s together; preserve `void folderKey` + Biome `noCommentText`.
- `apps/desktop/src-tauri/src/commands/auth.rs` (521) → move `load_vault_settings` to
  `commands/vault.rs`; factor the mount/sync/device/teardown tail out of `complete_auth_setup`
  keeping its `pub(crate)` signature.

### In scope — Tier 2 (dedup — kills cross-platform drift, the known desync bug class)

- `crates/fuse/src/platform/windows/operations.rs` (604) — hoist the ~210 LoC verbatim-duplicated
  crypto/IPNS helpers to a shared non-platform `content_ops.rs`; both files re-export. Highest-value
  Rust dedup.
- `apps/desktop/src-tauri/src/fuse/windows/mod.rs` (550) — extract the ~255-LoC IPNS prepopulate block
  duplicated with the macOS mount into shared `fuse/prepopulate.rs` (cfg `any(fuse,winfsp)`); verify
  macOS still builds. Defer the `windows/host.rs` dispatcher split (can't exercise off Windows).
- `crates/fuse/src/platform/windows/read_ops.rs` (499) — dedupe the 2x content-prefetch closure +
  offset-slice-copy into `content_fetch.rs` (NOT a structural split).
- `crates/fuse/src/read_ops.rs` (1012) — keep the read/write/dir partition; only move `PollResult` +
  `poll_filepointer_resolution` to a shared module and dedupe the 3x prefetch-spawn block. **Do NOT
  relocate `handle_release`** (CR-04/D-04 journal-fsync-before-ack invariant).

### Out of scope

- **All Tier 3 items** (`client.ts`, `inode.rs`, `windows/write_ops.rs`, `SharedFileBrowser.tsx`,
  `auth.ts`, `ShareDialog.tsx`, `useAuth.ts`, `main.ts`, `bin/index.ts`, `useFileBrowserActions.ts`,
  `useSharedNavigationActions.ts`, `BinBrowser.tsx`) — deferred to a follow-up, gated on a separate
  test-backfill phase first (D-03). The client.ts approach is pre-decided (D-02) for when it happens.
- **Leave-as-is set (do NOT churn):** `apps/web/src/services/share.service.ts` (deprecated, slated for
  deletion), `packages/sdk/src/share/shared-write.ts`, `crates/sdk/src/queue.rs`,
  `crates/fuse/src/journal_helpers.rs`.
- Any public-API change; HARD-02..05 (Phases 51–54).

</domain>

<decisions>

## Implementation Decisions

- **D-01 (tier scope, fork):** **Tier 1 + Tier 2 only.** The test-guarded mechanical splits plus the
  high-value cross-platform dedup. Tier 3 (untested, security-sensitive crypto) is deferred to its own
  follow-up — see D-03.
- **D-02 (client.ts approach, fork — forward-looking):** When `client.ts` is eventually tackled (it is
  a Tier-3 item, NOT in this phase), use the **full facade decomposition** — `ClientCore` shared-state
  handle + the 7-phase split to a ~350-LoC delegating facade (per the survey's client.ts deep-dive:
  `state/client-core.ts`, `ops/{folder,file,version,shared-folder,ipns-maintenance,pinning}.ts`).
  Honor the two hard constraints: public API + `@internal` accessors frozen (apps/web calls them), and
  `ClientCore.folderTree` as the single source of truth (PR #489 sequence-as-clock). Locking the
  approach now so the deferred work is unambiguous.
- **D-03 (Tier 3 test-first, fork):** Tier 3 is gated on a **separate test-backfill phase** that adds
  the missing unit tests across the Tier-3 files (especially the security-sensitive web crypto:
  `ShareDialog` key-unwrap/zeroization, `useAuth` vault-init) **before any Tier-3 refactor begins**.
  No Tier-3 refactor proceeds until its test net exists. (Roadmap impact: this implies a future
  test-backfill phase + a Tier-3 refactor phase — capture as follow-up todos, not this phase.)
- **D-04 (PR/plan granularity, fork):** **Batched coherent groups**, not per-item. Group related work
  into fewer PRs — e.g. the whole `lib.rs` 6-module decomposition as one PR, all the Windows/cross-
  platform dedup (operations.rs + windows/mod.rs prepopulate + windows/read_ops.rs) as one PR, the
  remaining Rust Tier-1 (write_ops) as one, and the TS/web Tier-1 (folder barrel, ipns codec,
  DetailsDialog, commands/auth) grouped sensibly. The planner decides the exact grouping.

### Locked by the survey (no fork)

- **D-05:** Public surface frozen — SDK exports, crate re-exports, component/hook signatures, NestJS DI
  byte-identical; **no `pnpm api:generate`**; consumers compile with no edits.
- **D-06:** Sequencing — `lib.rs` first (biggest, mechanical, test-guarded) → rest of Tier 1 → Tier 2
  dedup. Per the survey, each move is cut-paste + re-export (+ test relocation); gate Rust items on
  BOTH feature sets (`cargo test -p cipherbox-fuse` and the `--features winfsp` build).
- **D-07:** Per-item acceptance — files split/deduped as specified, public surface unchanged, relevant
  test suite passes (both Rust feature sets where applicable), consumers compile with no edits.

### Folded Todos

- **[#17]** `2026-06-19-large-file-refactor-candidates.md` — the full survey with per-file plans, the
  client.ts + lib.rs deep-dives, the leave-as-is set, and the tiering. Maps to D-01..D-07 (Tier 1+2).

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope & source survey

- `.planning/todos/pending/2026-06-19-large-file-refactor-candidates.md` — the survey: per-file split
  plans, lib.rs + client.ts deep-dives, tiering, leave-as-is set, sequencing. The primary ref;
  the lib.rs deep-dive is the implementation spec for the first (and largest) item.
- `.planning/REQUIREMENTS.md` — HARD-06.
- `.planning/ROADMAP.md` §"Phase 55" — scope checkbox.

### Tier 1 targets

- `crates/fuse/src/lib.rs`, `crates/fuse/src/write_ops.rs`, `packages/sdk-core/src/folder/index.ts`,
  `apps/api/src/ipns/ipns.service.ts`, `apps/web/src/components/file-browser/DetailsDialog.tsx`,
  `apps/desktop/src-tauri/src/commands/auth.rs`.

### Tier 2 targets

- `crates/fuse/src/platform/windows/operations.rs` + `crates/fuse/src/operations.rs` (the verbatim
  dup), `apps/desktop/src-tauri/src/fuse/windows/mod.rs` + `apps/desktop/src-tauri/src/fuse/mod.rs`,
  `crates/fuse/src/platform/windows/read_ops.rs`, `crates/fuse/src/read_ops.rs`.

### Invariants to preserve

- `crates/fuse/src/read_ops.rs::handle_release` — CR-04/D-04 journal-fsync-before-ack; do not relocate.
- PR #489 folderTree sequence-as-clock (relevant to the deferred client.ts D-02).

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- Existing facades to preserve and reuse: `write_ops::implementation` (Rust), the `../folder` barrel,
  `cipherbox_fuse::<X>` re-exports — splits hide behind these so import paths stay stable.
- Strong co-located Rust tests guard lib.rs / write_ops / read_ops moves; lean on them per move.

### Established Patterns

- The macOS/Windows FUSE paths have copy-pasted crypto/IPNS/prefetch logic — Tier 2 dedup removes a
  real, recurring cross-platform drift hazard (the known desync bug class), the survey's highest-value
  structural work.
- `apps/web` vitest `include` is `*.test.ts` only — any new tests use `.test.ts`, not `.spec.ts`.

### Integration Points

- Pure internal refactor: no `apps/api` HTTP/DTO change → no `pnpm api:generate`. Verify by building
  the desktop crate (both feature sets) + running the affected JS/Rust suites; consumers must compile
  untouched.

</code_context>

<specifics>

## Specific Ideas

- D-02 and D-03 are forward-looking — they pre-decide the deferred Tier-3 work (client.ts approach;
  test-backfill-first). At execute time, raise two follow-up todos: a Tier-3 test-backfill phase, then
  a Tier-3 refactor phase using the locked client.ts facade approach.

</specifics>

<deferred>

## Deferred Ideas

- **Tier 3 refactors** (client.ts full-facade, inode.rs, windows/write_ops.rs, SharedFileBrowser,
  auth.ts, ShareDialog, useAuth, main.ts, bin/index.ts, useFileBrowserActions, useSharedNavigationActions,
  BinBrowser) — deferred; gated on a separate test-backfill phase (D-03). client.ts approach locked
  (D-02).
- The `windows/host.rs` dispatcher split — deferred (can't be exercised off Windows).

</deferred>

---

_Phase: 55-large-source-file-refactor_
_Context gathered: 2026-06-19_
