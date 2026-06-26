---
phase: 56-fuse-and-ipns-durability-hardening
audit_type: retroactive-threat-verification
verdict: SECURED
threats_total: 14
threats_closed: 14
threats_open: 0
asvs_level: 2
block_on: open
unregistered_flags: 0
audited_commits: [c2182009f, 2da670ee0, 080675f8e, e28aebd79, d5f81c55e, 98b0eb497, 80c7fa276, 9dff382c6]
completed: "2026-06-22"
---

# Phase 56 Security Audit — FUSE and IPNS Durability Hardening

## SECURED

**Phase:** 56 — FUSE and IPNS Durability Hardening
**Threats Closed:** 14/14
**ASVS Level:** 2
**Threats Open:** 0

Every declared mitigation in the three plan threat models (`56-01`, `56-02`, `56-03`) was verified against committed source by reading the actual guard/zeroization/retry code and confirming line ordering, ownership, and error-message content. No mitigation accepted on documentation or intent alone.

## Scope confirmation (no new attack surface)

The phase-56 diff (`c2182009f~1..9dff382c6`, 23 files) touches only: the `crates/fuse` Rust crate, two `packages/sdk-core/src/folder` files, two `apps/web` detail components, three one-line `pending_fp_resolves: VecDeque::new()` constructor inits (desktop tauri `fuse/mod.rs`, `fuse/windows/mod.rs`, `test_support.rs`), plus test files. Verified absent:

- No API controllers / DTOs / NestJS modules / routes touched (no new network endpoints or auth paths).
- No TypeORM migrations / entities touched (no schema/DB changes).
- No TEE / republish / worker files touched — the TEE encrypt-`ipnsPrivateKey`-before-republish path and key-epoch logic are untouched. ECIES key wrapping and AES-256-GCM content encryption unchanged. Server remains zero-knowledge.
- No added `log::*` / `console.*` / `println!` line interpolates `privateKey` / `folderKey` / `ipnsPrivateKey` / secret / plaintext material (full diff scan clean). Every error/log line added this phase carries only non-secret identifiers (IPNS names, CIDs, sequence numbers, display names) or generic error strings.

## Threat Verification

| Threat ID | Category | Disposition | Evidence |
| --------- | -------- | ----------- | -------- |
| T-56-02 (write offset/overflow) | Tampering | mitigate | `file_data.rs:106-118` — `offset<0`→`libc::EINVAL` and `checked_add`→`libc::EFBIG`, both BEFORE `write_at` (line 128); `new_end` (checked) drives the size update at line 131-133. winfsp lockstep at `platform/windows/write_ops.rs` (`status_io_device_error` overflow guard, no `<0` check since `actual_offset:u64`). CLOSED |
| T-56-02 (sequence overflow) | Tampering | mitigate | `publish.rs:24-25` — `seq.checked_add(1).ok_or_else(.. "IPNS sequence number overflow")`; no `seq + 1` remains; overflow unit test `next_file_publish_sequence_overflow_returns_err` (line 196). CLOSED |
| T-56-04 (duplicate dirent) | Tampering | mitigate | `file_data.rs:179-182` — `find_child`→`libc::EEXIST` after `parent_exists` (173) and BEFORE `allocate_ino` (184); `mkdir.rs:41-42` — `find_child`→`EEXIST` before `allocate_ino` (66), placed before the closure to yield genuine EEXIST not EIO; winfsp `status_object_name_collision` guard before the is_dir branch. CLOSED |
| T-56-03 (per-file Conflict-as-success) | Repudiation | mitigate | `content_ops.rs:204-230` — update publishes route through `publish_with_cas_retry` with `journal_entry: None` (line 228); old unconditional `record_publish` fall-through removed; first-publish Conflict returns `Err` (186-193). CLOSED |
| T-56-03 (bin Conflict-as-success) | Repudiation | mitigate | `metadata.rs:522-545` — `spawn_bin_entry_publish` routes the Conflict arm through `publish_with_cas_retry` with `journal_entry: None` (542); persistent conflict `Err` propagates (`?` at 545) → `log::error!` (551). CLOSED |
| D-03 (single CAS decision point) | Repudiation | mitigate | `metadata.rs:101-212` — `publish_with_cas_retry` re-resolves+jitter+retries; persistent conflict returns `Err` (192-208), never `record_publish` with stale seq, never warn-and-ack. Folder site keeps its own equivalent canonical loop (`metadata.rs:333-424`, documented D-03 decision due to async-closure limitation) — it too returns `Err` on persistent conflict (422). All three sites reach a non-swallowing decision. CLOSED |
| T-56-01 (spawn_metadata_publish key params) | Information Disclosure | mitigate | `metadata.rs:216-221` — `folder_key`/`ipns_private_key` are `Zeroizing<Vec<u8>>`. Call sites `fs.rs:263-264, 354-355` wrap OWNED clones produced by `build_folder_metadata` (`.to_vec()`/`.clone()` at `fs.rs:114,119,131`); the inode's live key fields are NOT moved out. Callee zeroes on drop without corrupting reused caller buffers — the terminal-owner/no-reused-buffer invariant holds. CLOSED |
| T-56-01 (registration wrapKey-in-try) | Information Disclosure | mitigate | `registration.ts:69-108` — both ECIES `wrapKey` calls (71, 73) and the TEE wrapKey (79) are INSIDE the try whose `catch` (104-108) does `ipnsKeypair.privateKey.fill(0)` + `folderKey.fill(0)`. Both buffers generated fresh (lines 55, 59), returned only on the success path; catch zeroes only on failure when the caller never receives them — terminal owner. CLOSED |
| D-13 (typed metadata decode) | Tampering / Information Disclosure | mitigate | `load.ts:30-39` — `TextDecoder.decode` / `JSON.parse` / `return await decryptFolderMetadata` wrapped in try-catch; throws `Error("Failed to decode or decrypt folder metadata for CID ${cid}: ...", { cause })`. Message leaks only the public CID + `String(cause)`; `folderKey` is never interpolated. `return await` (not bare return) ensures the rejected decrypt Promise is caught. CLOSED |
| T-56-05 (inode stale-ID identity) | Information Disclosure | mitigate | `inode.rs:400` — `matched_by_stable_id = ipns_to_ino.contains_key(&folder.ipns_name)`; children/loaded state preserved only when stable-ID match (468-482); display-name-only fallback clears to `(Some(vec![]), false)` + `log::info!` (483-489). File branch forces `same_pointer=false` when `file_meta_ipns_name` differs (614-624), dropping stale per-file keys (637-641). CLOSED |
| D-08 (stale unpin) | Tampering / DoS | mitigate | `fs.rs:283-301` — `pruned_cids` unpin loop is INSIDE the `inode.write_generation == result.write_generation` guard (284); a stale-generation completion cannot unpin live CIDs. `self.api.clone()` taken inside the loop before spawn (no `self` borrow in the task). CLOSED |
| D-09 (FP-resolve silent drop) | DoS | mitigate | `fs.rs:432-461` — overflow entries pushed onto `pending_fp_resolves` VecDeque (456) instead of dropped; queue drained first each cycle (434-445); shared struct field `pending_fp_resolves` init in all three constructors. CLOSED |
| D-10 (hung metadata refresh) | DoS | mitigate | `events.rs:86-115` — inner resolve/fetch/decrypt block wrapped in `tokio::time::timeout(NETWORK_TIMEOUT, ...)`; `Err(_elapsed)` maps to `Err(String)` → `PendingRefresh::Failure` (128), always clearing `refreshing_metadata`. CLOSED |
| D-14 (false copy / silent download) | Spoofing (UX) / Repudiation | mitigate | `DetailsPrimitives.tsx:19,31,34-35` — `success` boolean gates `setCopied(true)`, `execCommand('copy')` return captured. `VersionHistory.tsx:37-39` — `setActionError('Cannot download: vault key not available')` on missing privateKey instead of silent return. CLOSED |
| T-56-SC (supply chain) | Tampering | accept | No npm/cargo packages added this phase (`tech_stack.added: []` in all three SUMMARYs; diff adds no dependency/lockfile entries). No install task; nothing to gate. Accepted risk recorded. CLOSED (accepted) |

## Critical Security Rules cross-check (project CLAUDE.md)

| Rule | Status |
| ---- | ------ |
| Never store privateKey in localStorage/sessionStorage | Not introduced this phase; no storage writes added |
| Never log sensitive keys | Verified — full diff scan finds no key material in any added log/print line |
| Never send unencrypted keys to server | Unchanged; `expected_sequence_number`/CID/IPNS-name only in publish requests; `encrypted_ipns_private_key` field unchanged |
| Always ECIES for key wrapping | Unchanged (`wrapKey` / `ecies::wrap_key` paths intact) |
| Always AES-256-GCM for content | Unchanged |
| Server NEVER has plaintext/unencrypted keys | Zero-knowledge boundary intact; no endpoint/DTO changes |
| Encrypt ipnsPrivateKey with TEE key before republish | TEE path untouched this phase (no TEE/worker/republish files in diff) |
| TEE decrypts in hardware, discards | Untouched |

## Ownership-invariant deep check (zeroization)

The project invariant "zeroize only at the terminal owner; a callee receiving reused caller buffers must not zero them" was explicitly verified for the two zeroization changes:

- **D-12 (Rust):** `spawn_metadata_publish` receives `Zeroizing<Vec<u8>>` wrapping owned `.to_vec()`/`.clone()` copies from `build_folder_metadata`. The inode's own key fields are NOT consumed, so the callee zeroing on drop does not corrupt reused session state. Safe.
- **D-13 (TS):** `registration.ts` zeroes `ipnsKeypair.privateKey`/`folderKey` only in the `catch` (failure path) — both freshly generated in the function and not yet returned to the caller. This mirrors the documented non-zeroing decision in `updateFolderMetadataAndPublish` (`registration.ts:119-136`), which correctly does NOT zero its reused session keys. Consistent with the prior 48/89-E2E zeroization regression rule.

## Unregistered Flags

None. All three SUMMARY `## Threat Flags` sections report "None" / "No new network endpoints, auth paths, file access patterns, or schema changes." The diff scope (FUSE crate + 2 sdk-core + 2 web components + struct-field constructor inits + tests) confirms no new attack surface appeared during implementation. No flag lacks a threat mapping.

## Verdict

SECURED — all 14 declared threats CLOSED (13 mitigations verified present and correct in committed source; 1 accepted supply-chain risk with zero new packages). No security defect introduced by phase 56. `threats_open: 0`.

Note: winfsp guards (D-05/D-06 lockstep in `platform/windows/write_ops.rs`) cannot be compiled locally on macOS (`#[cfg(feature = "winfsp")]`); the `Cargo Check & Test (Windows)` CI gate is authoritative for that path and is the only outstanding CI verification — it is a build/correctness gate, not an unmitigated threat (the macOS-side guards are verified present and the winfsp mirror is verified present by source inspection).
