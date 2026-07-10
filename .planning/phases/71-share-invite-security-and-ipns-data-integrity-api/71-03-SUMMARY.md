---
phase: 71-share-invite-security-and-ipns-data-integrity-api
plan: 03
subsystem: api
tags: [rust, serde, fuse, sdk, api-client, share, rotation, refactor]

# Dependency graph
requires:
  - phase: 71-01
    provides: Regenerated OpenAPI contract + TS DTOs using encrypted_read_key / encrypted_write_key / share_root_ipns_name
provides:
  - Rust share/grant-domain identifiers renamed to the encrypted-key vocabulary, matching the JSON contract
affects: [71-share-invite-security-and-ipns-data-integrity-api, desktop, fuse, sdk]

# Tech tracking
tech-stack:
  added: []
  patterns: [serde field renaming via #[serde(rename_all = "camelCase")] auto-derivation from snake_case Rust field names]

key-files:
  created: []
  modified:
    - crates/api-client/src/shares.rs
    - crates/fuse/src/write_ops/grant_scope.rs
    - crates/fuse/src/write_ops/implementation/delete.rs
    - crates/fuse/src/write_ops/implementation/rename.rs
    - crates/sdk/src/rotation/engine.rs

key-decisions:
  - "crates/core/src/node/types.rs required no change: the only 'descriptor' occurrences there (NodeContent doc comments) describe file-content metadata, not share/grant keys"
  - "resolve_file_descriptors and all 'content descriptor' (CID/IV/size) identifiers across content_ops.rs, events.rs, fs.rs, inode.rs, operations.rs, poll.rs, read_ops.rs are file-content concepts, verified non-share-domain, and intentionally left unrenamed"
  - "Windows security_descriptor/SecurityDescriptor family under crates/fuse/src/platform/windows untouched (13 hits verified unchanged) per the surgical exclusion"

patterns-established: []

requirements-completed: [D-10]

coverage:
  - id: D1
    description: "crates/api-client SentShareResponse serde fields renamed to encrypted_read_key/encrypted_write_key/share_root_ipns_name, matching the regenerated OpenAPI SentShareResponseDto"
    requirement: "D-10"
    verification:
      - kind: unit
        ref: "crates/api-client/src/shares.rs#sent_share_response_deserializes_camel_case"
        status: pass
      - kind: other
        ref: "cargo check -p cipherbox-api-client -p cipherbox-core"
        status: pass
    human_judgment: false
  - id: D2
    description: "crates/fuse + crates/sdk share/grant descriptor call sites (grant_scope.rs, delete.rs/rename.rs test fixtures, rotation/engine.rs re-mint path) renamed to encrypted_read_key/encrypted_write_key, Windows security descriptors and file-content descriptors left untouched"
    requirement: "D-10"
    verification:
      - kind: unit
        ref: "cipherbox-fuse --lib (111/111 passed)"
        status: pass
      - kind: unit
        ref: "cipherbox-sdk --lib rotation::engine (26/26 passed, including high3_inner_grant_at_a_child_is_re_minted_and_revoked_recipient_is_cut)"
        status: pass
      - kind: other
        ref: "cargo check -p cipherbox-fuse -p cipherbox-sdk"
        status: pass
    human_judgment: false

# Metrics
duration: 20min
completed: 2026-07-09
status: complete
---

# Phase 71 Plan 03: Rust Share/Grant Descriptor Rename Summary

**Renamed Rust share/grant-domain `*descriptor*` symbols (crates/api-client, crates/fuse, crates/sdk) to the `encrypted_read_key`/`encrypted_write_key`/`share_root_ipns_name` vocabulary matching the regenerated OpenAPI contract, while surgically preserving unrelated Windows `security_descriptor` and file-content `descriptor` (CID/IV) identifiers.**

## Performance

- **Duration:** ~20 min
- **Completed:** 2026-07-09T21:42:44Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- `crates/api-client/src/shares.rs`'s `SentShareResponse` struct fields (`read_descriptor_ref`/`write_descriptor_ref`/`root_ipns_name`) renamed to `encrypted_read_key`/`encrypted_write_key`/`share_root_ipns_name`, matching the regenerated `openapi.json` `SentShareResponseDto` field-for-field (serde `rename_all = "camelCase"` auto-derives the wire names)
- `crates/fuse/src/write_ops/grant_scope.rs`'s `SentSharesCache::from_sent_shares` and its unit test fixture updated to read `share_root_ipns_name` / construct the renamed struct
- `crates/fuse/src/write_ops/implementation/delete.rs` + `rename.rs` test-only `seed_sent_share` fixtures updated to the renamed field names
- `crates/sdk/src/rotation/engine.rs`'s `RotationDeps::update_grant` trait method parameter, `re_mint_grants_rooted_at`'s local variable, its `FakeDeps` test double, and every doc comment referencing `readDescriptorRef` renamed to `encrypted_read_key`/`encryptedReadKey` (the HIGH-3/T-69-12-02 grant re-mint path)
- `crates/core/src/node/types.rs` required NO change: verified the only "descriptor" hits there are the `NodeContent` doc comment describing file-content metadata (CID/IV/size), not a share/grant concept
- Windows `security_descriptor`/`SecurityDescriptor`/`sz_security_descriptor` family under `crates/fuse/src/platform/windows/*` verified untouched (13 hits, unchanged)
- File-content "descriptor" identifiers (`resolve_file_descriptors`, and doc-comment uses of "content descriptors") across `content_ops.rs`, `events.rs`, `fs.rs`, `inode.rs`, `operations.rs`, `poll.rs`, `read_ops.rs` inspected and confirmed non-share-domain — intentionally left as-is per the plan's own verification instruction

## Task Commits

Each task was committed atomically:

1. **Task 1: Rename share/grant descriptor symbols in crates/api-client + crates/core** - `714758cd4` (feat)
2. **Task 2: Rename share/grant descriptor symbols in crates/fuse + crates/sdk (excluding Windows security descriptors)** - `1aa72437c` (feat)

**Plan metadata:** (this commit, docs: complete plan)

## Files Created/Modified
- `crates/api-client/src/shares.rs` - `SentShareResponse` serde fields renamed to encrypted-key vocabulary; unit test JSON fixture updated
- `crates/fuse/src/write_ops/grant_scope.rs` - `SentSharesCache::from_sent_shares` field access + unit test fixture updated
- `crates/fuse/src/write_ops/implementation/delete.rs` - test-only `seed_sent_share` fixture updated
- `crates/fuse/src/write_ops/implementation/rename.rs` - test-only `seed_sent_share` fixture updated
- `crates/sdk/src/rotation/engine.rs` - `RotationDeps::update_grant` param, `re_mint_grants_rooted_at` locals, `FakeDeps` test double, and doc comments renamed

## Decisions Made
- `crates/core/src/node/types.rs` needed no edits: its only "descriptor" occurrences describe `NodeContent` (file content metadata), a distinct concept from share/grant encrypted keys — verified per-line before deciding not to touch it (matches the plan's own read_first instruction to "verify each is share/grant... before renaming")
- Left every "content descriptor" occurrence across the seven listed fuse files (content_ops.rs, events.rs, fs.rs, inode.rs, operations.rs, poll.rs, read_ops.rs) untouched after inspecting each one — they all refer to file CID/IV/size metadata, not share/grant read/write keys

## Deviations from Plan

None - plan executed exactly as written. The plan itself anticipated ambiguous "descriptor" hits and instructed verification before renaming (task 2's action text); that verification was performed and confirmed no additional renames were needed beyond the explicit share/grant call sites.

## Issues Encountered
- Renaming `SentShareResponse`'s fields in Task 1 required corresponding updates to its three struct-literal construction sites in `crates/fuse` (grant_scope.rs test, delete.rs test, rename.rs test) and the `SentSharesCache::from_sent_shares` field-read call site — these were in Task 2's file list already, so no scope expansion was needed; just confirmed via cargo check that both tasks together leave the workspace green
- Worktree `node_modules` was missing (`lint-staged` pre-commit hook failed); resolved with `pnpm install` before the first task commit, consistent with the documented "worktree subagents must pnpm i" project convention

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Rust side of D-10 (Rust share/grant vocabulary rename) is complete and cargo-green across `cipherbox-api-client`, `cipherbox-core`, `cipherbox-fuse`, and `cipherbox-sdk`
- `crates/fuse` full unit-test suite: 111/111 passed. `crates/sdk` full unit-test suite: 152/152 passed (including all 26 `rotation::engine` tests, notably `high3_inner_grant_at_a_child_is_re_minted_and_revoked_recipient_is_cut`)
- Per the plan's own verification note, `crates/fuse/src/platform/windows/*` compiles CI-only on macOS — the Windows-target build (`Cargo Check & Test (Windows)` CI job) is the authoritative confirmation that the surgical exclusion holds on the real Windows target; local verification here was a `grep` count-match (13 hits, unchanged) since the Windows platform module cannot compile in this environment

## Self-Check: PASSED

- FOUND: commit 714758cd4 (Task 1)
- FOUND: commit 1aa72437c (Task 2)
- FOUND: commit 087be65b4 (docs: plan summary)
- FOUND: crates/api-client/src/shares.rs
- FOUND: crates/sdk/src/rotation/engine.rs
- FOUND: .planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-03-SUMMARY.md

---
*Phase: 71-share-invite-security-and-ipns-data-integrity-api*
*Completed: 2026-07-09*
