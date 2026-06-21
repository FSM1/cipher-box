---
created: 2026-06-19T00:00:00.000Z
title: Large source-file refactor candidates (split/dedup survey of 26 files)
area: refactor
severity: low
source: Multi-agent survey 2026-06-19 of all production source files >= ~500 LoC (vendored fuser + test files excluded), with implementation-ready deep dives for client.ts and lib.rs
files:
  - packages/sdk/src/client.ts
  - packages/sdk/src/bin/index.ts
  - packages/sdk/src/share/shared-write.ts
  - packages/sdk-core/src/folder/index.ts
  - apps/api/src/ipns/ipns.service.ts
  - apps/web/src/components/file-browser/SharedFileBrowser.tsx
  - apps/web/src/components/file-browser/ShareDialog.tsx
  - apps/web/src/components/file-browser/DetailsDialog.tsx
  - apps/web/src/components/file-browser/BinBrowser.tsx
  - apps/web/src/components/file-browser/useFileBrowserActions.ts
  - apps/web/src/hooks/useAuth.ts
  - apps/web/src/hooks/useSharedNavigationActions.ts
  - apps/web/src/services/share.service.ts
  - apps/desktop/src/auth.ts
  - apps/desktop/src/main.ts
  - apps/desktop/src-tauri/src/commands/auth.rs
  - apps/desktop/src-tauri/src/fuse/windows/mod.rs
  - crates/fuse/src/lib.rs
  - crates/fuse/src/inode.rs
  - crates/fuse/src/write_ops.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/journal_helpers.rs
  - crates/fuse/src/platform/windows/operations.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - crates/fuse/src/platform/windows/read_ops.rs
  - crates/sdk/src/queue.rs
---

## Status: Tier 1 + Tier 2 DONE in Phase 55 / PR #538 (filed to completed 2026-06-21)

All 6 Tier-1 splits and all 4 Tier-2 cross-platform dedups shipped in **commit `db5691be7` (#538,
Phase 55)** with the exact module layout prescribed below (`lib.rs` 3276→571 LoC + runtime/events/
publish/metadata/fs/replay; `write_ops/` dir module; sdk-core folder split; `ipns-record.codec.ts`;
`details/`; `content_ops.rs` / `content_fetch.rs` / `poll.rs` / `prepopulate.rs`). The phase simply
never moved this file to `completed/`.

The **14 Tier-3 items remain OPEN** (bigger/riskier, mostly untested — `client.ts` actually grew to
2768 LoC) and are re-captured in `2026-06-21-large-file-refactor-tier3-residue.md`. The 4 "leave
as-is" cohesive files were correctly left untouched.

## Problem

Several production source files have grown large enough to hurt navigability and review.
A survey (one analyst per file) assessed every non-test, non-vendored source file at or above
~500 LoC for cohesion and proposed concrete split/dedup plans with an honest
"leave-as-is" verdict where the length is legitimate.

Key conclusions:

- `client.ts` (2643 LoC) looks alarming but is a cohesive stateful facade; ~290 LoC is
  irreducible glue. Realistic conservative win is ~600 LoC extracted; a full
  composition-behind-facade decomposition to a ~350-LoC facade is possible but larger/riskier.
- `crates/fuse/src/lib.rs` (3276 LoC) is the single largest file and the **cleanest big win**:
  four unrelated subsystems sharing a crate root, splittable almost mechanically into 6 modules
  with strong existing test coverage guarding the move.
- The highest-value structural work is **deduplication** of code copy-pasted across the
  macOS/Windows FUSE paths (a real cross-platform drift hazard), not raw line-count reduction.
- 5 large files are legitimately cohesive — **leave them alone**.
- Most web/desktop candidates have **zero unit tests**, so refactors there are unguarded and must
  add tests first (several touch security-sensitive crypto).

All proposed splits are internal-only: every public surface (the `@cipherbox/sdk` client class,
the `cipherbox_fuse` crate re-exports, component/hook signatures, NestJS DI) stays byte-for-byte
stable, so no `pnpm api:generate` and no consumer edits are required.

## Tier 1 — quick wins (low effort/risk, test-guarded or mechanical)

- [ ] **`crates/fuse/src/lib.rs` (3276)** — split into `runtime.rs` / `events.rs` / `publish.rs` /
  `metadata.rs` / `fs.rs` / `replay.rs`; `lib.rs` shrinks to ~120 LoC of module decls + re-exports.
  Mechanical move; strong existing tests. See deep-dive plan below.
- [ ] **`crates/fuse/src/write_ops.rs` (1132)** — convert to a directory module
  `write_ops/{file_data,delete,mkdir,rename}.rs` behind the existing
  `pub(crate) mod implementation` facade so `crate::write_ops::implementation::handle_*` paths stay
  stable. Bonus: dedupe the near-identical ~50-line bin-publish tail shared by unlink + rmdir.
- [ ] **`packages/sdk-core/src/folder/index.ts` (602)** — barrel-preserving split into
  `load.ts` / `metadata-ops.ts` (4 pure FolderChild transforms) / `registration.ts` (IPNS-record
  build + batch publish); `index.ts` re-exports everything. Tests already target the `../folder`
  barrel, so zero import churn. Thread `fetchAndDecryptMetadata` (load.ts) into the publish module's
  decodeRemote callback.
- [ ] **`apps/api/src/ipns/ipns.service.ts` (596)** — extract only the ~99 LoC of record codec
  helpers (`parseIpnsRecordBytes`, `parseCachedRecord`, `withCachedPublicKey`) into
  `ipns-record.codec.ts`. Keep the DI class, constructor, and write/read orchestration intact — do
  NOT split into collaborator services. Strong specs guard it; no `api:generate` needed.
- [ ] **`apps/web/src/components/file-browser/DetailsDialog.tsx` (664)** — near-mechanical move into
  `details/{VersionHistory,FileDetails,FolderDetails,DetailsPrimitives}.tsx`. Keep the container's
  two cross-guarded `useEffect`s together. Preserve `void folderKey` (unused-prop lint) and Biome
  `noCommentText` wrapping.
- [ ] **`apps/desktop/src-tauri/src/commands/auth.rs` (521)** — move `load_vault_settings` to
  `commands/vault.rs` (co-locate with vault crypto); factor the mount, sync-daemon, device-registry,
  and window-teardown tail out of `complete_auth_setup` into a helper, keeping its `pub(crate)`
  signature stable (debug.rs calls it). Verify default and `--features fuse`/`winfsp` builds.

## Tier 2 — dedup wins (kill cross-platform drift, the known desync bug class)

- [ ] **`crates/fuse/src/platform/windows/operations.rs` (604)** — ~210 LoC of crypto/IPNS helpers
  (`fetch_and_decrypt_file_content`, `fetch_and_decrypt_content_async`, `publish_file_metadata`) are
  **verbatim-duplicated** in `src/operations.rs`. Hoist to a shared non-platform `content_ops.rs`;
  both operations files re-export to keep import paths. Highest-value Rust dedup. (winfsp-gated; verify
  on a Windows/cross toolchain.)
- [ ] **`apps/desktop/src-tauri/src/fuse/windows/mod.rs` (550)** — the ~255-LoC IPNS prepopulate block
  (root folder + FilePointers + immediate subfolders) is conceptually **duplicated** with the macOS
  mount in `fuse/mod.rs`. Extract shared `fuse/prepopulate.rs` (cfg `any(fuse,winfsp)`). Do this first
  and verify the macOS path still builds/tests; defer the `windows/host.rs` dispatcher split (can't be
  exercised off Windows).
- [ ] **`crates/fuse/src/platform/windows/read_ops.rs` (499)** — NOT a structural split. Dedupe the
  content-prefetch closure duplicated 2x (handle_open/handle_read) and the repeated offset-slice-copy
  into a shared `content_fetch.rs` helper. ~80-100 LoC out + removes a timeout/channel drift hazard.
- [ ] **`crates/fuse/src/read_ops.rs` (1012)** — keep the read/write/dir partition (leave structure);
  only (1) move `PollResult` + `poll_filepointer_resolution` to a shared module (currently mis-placed
  before the `use` block) and (2) dedupe the 3x prefetch-spawn block. `handle_release` (a write/commit
  path) touches the CR-04/D-04 journal-fsync-before-ack invariant — do not relocate it.

## Tier 3 — worthwhile but bigger/riskier (most have NO unit tests — add tests first)

- [ ] **`packages/sdk/src/client.ts` (2643)** — conservative: extract `pinning.ts`
  (`pinWithMode` + external-provider factory, zero shared-state coupling) and `shared-folder.ts`
  (the ~500-LoC group-H shared-folder write surface operating on `sharedFolderTree`). ~600 LoC out,
  test-guarded. Full facade decomposition is the alternative — see deep-dive plan below.
- [ ] **`crates/fuse/src/inode.rs` (1419)** — convert to `inode/` dir module: extract the ~460-LoC
  `populate_folder` (the ECIES/HKDF + rename + re-resolution hotspot, ideally broken into named
  helpers), the 577-LoC test module, and a `types.rs` for FileAttrs/InodeKind/InodeData. Keep
  `inode::X` paths via re-exports. Strong co-located tests guard it.
- [ ] **`crates/fuse/src/platform/windows/write_ops.rs` (1192)** — `create` and `cleanup` each fuse two
  unrelated flows; split to `write_ops/{create,cleanup,rename,attrs}.rs` behind the `implementation`
  facade. Windows-only + untested → verify on a winfsp build; cheaper interim is extracting the cleanup
  delete-path/flush-path closures into private fns.
- [ ] **`apps/web/src/components/file-browser/SharedFileBrowser.tsx` (946)** — converge on the existing
  `FileBrowser` + `useFileBrowserActions` pattern: extract `useSharedFileBrowserActions.ts`,
  `SharedListView.tsx`, and `sharedBrowser.helpers.ts`. High impact but **no tests** — add hook tests
  first. The selection block here hand-duplicates `useFileBrowserActions` logic.
- [ ] **`apps/desktop/src/auth.ts` (800)** — split to `auth/{corekit,login,mfa,device,oauth}.ts` +
  barrel `auth/index.ts` (keeps the `./auth` import in main.ts). The hazard is shared module-level
  mutable state (`coreKit`, `lastCipherboxJwt`, `temporaryAccessToken`, `ephemeralPrivateKey`) —
  `corekit.ts` must own it and expose accessors. Fold the duplicated createFactor/setDeviceFactor block
  into one helper. No tests — manual login + MFA verification required.
- [ ] **`apps/web/src/components/file-browser/ShareDialog.tsx` (786)** — extract `share/share-pubkey.ts`
  (pure helpers), `share/useDirectShare.ts` (the ~480-LoC crypto + API + store logic), and
  `share/RecipientsList.tsx`. Security-sensitive (key unwrap, `fill(0)` zeroization, write-share IPNS
  key) with **no tests** — extract helpers first, add tests, then the hook. Pre-existing latent bug to
  flag (not fix during the move): file IPNS key appears double-wrapped (~L313 and ~L317).
- [ ] **`apps/web/src/hooks/useAuth.ts` (732)** — extract `services/vault-init.service.ts`
  (~280 LoC of pure orchestration, no React; keep the module-level `vaultInitPromise` dedup with it)
  and `services/byo-config.service.ts`. Keep login/logout/restore callbacks (React-bound) in the hook.
  Return surface stays identical. High value, but no test net — exercise all 3 login paths +
  required_share + reload restore.
- [ ] **`apps/desktop/src/main.ts` (662)** — move the two inline-HTML renderers to
  `ui/{loginForm,mfaRequiredShare,styles,authSuccess}.ts` + `devKeyAuth.ts`; keep `init()` as the
  orchestrator. Low risk (single bootstrap entry). `handleAuthSuccess` needs a neutral module to avoid
  login<->mfa circular imports.
- [ ] **`packages/sdk/src/bin/index.ts` (655)** — borderline; conservative only: extract the ~110 LoC
  IPNS plumbing (`loadBinMetadataInternal`/`saveBinMetadata`/`publishWithVerify`) to `bin/ipns.ts`,
  keeping the `./bin` barrel + named exports (7 test files mock `'../bin'`). Do NOT carve up the
  ~175-LoC `restoreFromBin` transaction.
- [ ] **`apps/web/src/components/file-browser/useFileBrowserActions.ts` (630)** — god-hook; extract
  `useFileBrowserSelection.ts` (the dense ctrl/shift-range logic, duplicated in SharedFileBrowser —
  real dedup win), `useExternalFileDrag.ts`, and `useFileBrowserDialogs.ts`; keep the parent as a
  composition root returning the same flat object (FileBrowser destructures ~96 fields).
- [ ] **`apps/web/src/hooks/useSharedNavigationActions.ts` (579)** — borderline (plumbing-heavy, shared
  params object). If done: split to `shared-navigation-{entry,history,file-ops}.ts`. Dedupe the
  folder-vs-file branches in `navigateToShare`. Carry `useCallback` deps verbatim.
- [ ] **`apps/web/src/components/file-browser/BinBrowser.tsx` (539)** — extract `useBinSelection.ts`
  (shift-range, currently untested), `binSort.ts` (pure comparator), `useBinContextMenu.ts`, and
  `BinContextMenu.tsx`. Keep the ~225-LoC render together.

## Leave as-is (large but cohesive — do NOT churn)

- `apps/web/src/services/share.service.ts` (663) — **DEPRECATED**, slated for deletion (migrating into
  `@cipherbox/sdk`). Splitting churns code being removed.
- `packages/sdk/src/share/shared-write.ts` (618) — flat module of 7 independent stateless functions
  under one documented key-wrapping convention; no shared mutable state to untangle.
- `crates/sdk/src/queue.rs` (1078) — ~69% is inline `#[cfg(test)]` tests (crate idiom); ~333 LoC of
  cohesive production code (journal model + the one WriteQueue that owns its persistence).
- `crates/fuse/src/journal_helpers.rs` (603) — single security-critical encrypt->wrap->build pipeline
  shared by fuser + WinFsp; splitting scatters the zeroize-on-error contract. Risk high, value low.

(`crates/fuse/src/read_ops.rs` is intentionally NOT listed here — it must not be split structurally,
but it does have an active dedup-only task, so it lives solely under Tier 2 to avoid a "do not touch"
vs "has work" contradiction.)

## Deep-dive plan — client.ts (full facade decomposition, if chosen over conservative)

Approach: composition behind a thin delegating facade (mirrors the existing `bin/` + `share/`
context-passing pattern). Reject mixins (lose typing on shared private state) and sub-clients (break
public API).

Shared state that makes a naive split hard (thread via one internal `ClientCore` handle held by
reference, never copied): `folderTree`, `sharedFolderTree`, `binState` (reassigned — expose via
get/set on core), `ctx`, `config`, `emitter`, `externalProvider`, internal key copies,
`withOperation`.

Target layout (all internal — do NOT add to `index.ts`):

- `state/client-core.ts` — ClientCore: shared fields + `withOperation`/`notifySafely`/`getBinContext`/
  `getShareContext`/`requireFolder`/`ensureFolderLoaded`/`emit`.
- `ops/folder-ops.ts` — loadFolder, ensureFolderLoaded, requireFolder, createFolder, renameItem,
  moveItem, deleteItem, hasFolder/getFolderSequenceNumber/getFolderIpnsPrivateKey/registerFolder.
- `ops/file-ops.ts` — uploadFile, uploadFiles, downloadFile, downloadFromIpns.
- `ops/version-ops.ts` — replaceFile, restoreFileVersion, deleteFileVersion, maybePublishKeyMigration.
- `ops/shared-folder-ops.ts` — all group-H shared-folder methods + helpers.
- `ops/ipns-maintenance.ts` — reWrapNewItems, fireAndForgetUnenroll, collect*IpnsNames.
- `ops/pinning.ts` — pinWithMode + external-provider factory.
- `client.ts` — thin facade (~350 LoC): constructor builds core + ops; every public method is a
  one-line delegate; bin/share delegations stay inline.

Phasing (each phase compiles + full `pnpm --filter @cipherbox/sdk test` green; ship per phase):
0 introduce ClientCore (no method moves) · 1 pinning.ts · 2 ipns-maintenance.ts · 3 folder-ops
(highest folderTree-desync risk) · 4 file-ops · 5 version-ops · 6 shared-folder-ops · 7 facade cleanup,
then run `integration.test.ts` against a local stack.

Two explicit constraints:

- Public API frozen: `index.ts` export list + every method signature unchanged. `@internal`-tagged
  accessors `getContext`, `getFolderTree`, `getConfig`, `emitEvent`, `ensureFolderLoaded`,
  `registerFolder` are **actually called by apps/web** (folder-helpers.ts, useFileBrowserActions.ts,
  useFolderNavigation.ts) — treat as load-bearing public API.
- folderTree desync (PR #489 sequence-as-clock): ClientCore.folderTree is the single source of truth,
  shared by reference; the only sanctioned write is
  `folder.children = publishedChildren; folder.sequenceNumber = newSequenceNumber; core.folderTree.set(...)`.
  Move the `sequenceNumber >=` guards and the post-await re-read in `adoptSharedFolderResult` as intact
  blocks; keep one `requireFolder` chokepoint so a split op can't skip the self-heal fallback.
  `client-load-reconcile.test.ts` is the regression net.

(Tests use `.test.ts` — apps/web/sdk vitest `include` is `*.test.ts` only; `.spec.ts` is silently
skipped.)

## Deep-dive plan — lib.rs (crates/fuse)

`lib.rs` does 8 jobs: crate root/re-exports, runtime/timeout shim, background-task message types,
IPNS publish coordination, metadata encrypt/merge + spawners, the CipherBoxFS struct + inherent impl,
journal replay, and ~870 LoC of tests.

Target modules (siblings of existing op modules):

- `runtime.rs` — NETWORK_TIMEOUT, block_with_timeout (leave operations.rs's separate private copy).
- `events.rs` — PendingRefresh/PendingContent/PendingFilePointer/FsEvent/UploadComplete.
- `publish.rs` — PublishQueueEntry, PublishCoordinator(+impl), next_file_publish_sequence,
  resolve_ipns_for_replay, classify_resolve_outcome.
- `metadata.rs` — encrypt_metadata_to_json, merge_folder_children, the spawn_* fns, ReencryptOutcome.
- `fs.rs` — struct CipherBoxFS + inherent impl (the 9 methods), uuid_from_ino, mount_point.
- `replay.rs` — replay_for_vault + all replay helpers + the platform `publish_file_metadata` shim.

`lib.rs` shrinks to ~120 LoC: module decls + `pub use` re-exports keeping every `cipherbox_fuse::<X>`
path stable.

Rust specifics:

- Public surface constraint: `CipherBoxFS` is constructed via struct literal by the desktop app —
  **all fields stay `pub`**. Re-export FsEvent, merge_folder_children, replay_for_vault,
  PublishCoordinator, the Pending* types, and `next_file_publish_sequence` from `lib.rs`.
- Multiple inherent impl blocks across files are legal (journal_helpers.rs already adds one), so moving
  the impl to fs.rs is fine. Only visibility bumps needed: `resolve_ipns_for_replay` and
  `classify_resolve_outcome` -> `pub(crate)` (consumed cross-file by replay). Everything else keeps its
  current visibility.
- Carry the exact `#[cfg(...)]` gate each item has today (groups B-G are `any(fuse, winfsp)`); don't
  widen/narrow. The replay `publish_file_metadata` fuse-vs-winfsp shim moves with replay.rs.
- Tests (Option A — co-locate): move pure-fn + replay tests next to their code; leave the two
  `#[cfg(all(test, feature = "fuse"))]` handler/durability harness modules in lib.rs (they span
  modules) — their `crate::` paths stay valid via re-exports.

Phasing (gate each on BOTH feature sets: `cargo test -p cipherbox-fuse` and
`cargo build -p cipherbox-fuse --no-default-features --features winfsp`):
0 baseline · 1 runtime+events · 2 publish · 3 metadata · 4 fs (highest blast radius) · 5 replay ·
6 clean lib.rs + build the desktop crate to confirm the consumer compiles. No production behavior
changes — every move is cut-paste + re-export (+ test relocation).

## How to approach / sequencing recommendation

1. Start with `lib.rs` — biggest file, mechanical, test-guarded; best bang for buck.
2. Then the Tier-1 batch (write_ops.rs, sdk-core/folder, ipns codec, DetailsDialog, commands/auth.rs).
3. Then the Tier-2 dedup wins (real cross-platform drift removal).
4. Tier-3 last, and only after adding the missing unit tests — especially for the security-sensitive
   web crypto paths (ShareDialog, useAuth vault-init).

Each item is independently shippable on its own `refactor/` branch via PR (never push to main). No
`pnpm api:generate` is needed for any item (no `apps/api` HTTP/DTO changes).

## Acceptance

Per item: the file (or files) are split/deduped as described; the public surface is unchanged
(SDK exports, crate re-exports, component/hook signatures, NestJS DI all byte-identical); the
relevant test suite passes (both Rust feature sets where applicable); and consumers compile with no
edits. Net effect across all "split" items: ~10k LoC redistributed into cohesive modules, the two
giants reduced to thin roots (~350 LoC facade, ~120 LoC crate root), and ~750+ LoC of cross-platform
duplication eliminated.
