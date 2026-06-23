---
phase: 59-fuse-ipns-verify-publish-hardening-and-cleanup
verified: 2026-06-23T00:00:00Z
status: human_needed
score: 6/6 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Run cargo check -p cipherbox-fuse --features winfsp on a Windows CI runner (or dispatch Cargo Check & Test (Windows) via gh workflow run)"
    expected: "Exit 0 — all four plans touch shared cfg-gated code (fs.rs File arm, VerifyError::Legacy enum shape, first-publish seq constant) that macOS cargo cannot compile under winfsp"
    why_human: "Cannot compile winfsp feature on macOS; Windows-only deps; CI-authoritative per project MEMORY.md and plan acceptance criteria"
  - test: "Run the full SDK E2E suite locally (prereqs up, redis on 6380) after checking out this branch"
    expected: "All SDK E2E tests pass — the first-publish embedded-sequence change (0→1) touches the real client→API IPNS publish/resolve round-trip"
    why_human: "SDK E2E requires a live local API stack; cannot run in a static verification context"
  - test: "Dispatch desktop E2E via gh workflow run 'CI E2E Tests' --ref feat/fuse-ipns-verify-publish-hardening-and-cleanup"
    expected: "CI E2E Tests pass — the FUSE first-publish sequence convention (publish.rs, replay.rs) is exercised by the desktop E2E gate"
    why_human: "Desktop E2E requires a dispatch-triggered CI run; it is skipped on main pushes that don't touch desktop paths"
---

# Phase 59: FUSE IPNS Verify/Publish Hardening and Cleanup Verification Report

**Phase Goal:** Close out the Phase 58 IPNS verification long-tail on the FUSE crate — finish the two partially-done durability fixes and clear the dead-code/cleanup debt across verify.rs, events.rs, metadata.rs, content_ops.rs, fs.rs, inode.rs, publish.rs, replay.rs so the verify/publish/CAS paths carry no swallowed errors, no dead seams, and a single first-publish embedded-sequence convention.
**Verified:** 2026-06-23
**Status:** human_needed (all automated truths VERIFIED; three CI/durability gates require human dispatch)
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Finding A: build_folder_metadata File arm propagates wrap_key failure via `map_err(|e| format!("Wrap IPNS key: {}", e))?`; no `.ok()` on wrap_key | VERIFIED | fs.rs line 227-229: `cipherbox_crypto::wrap_key(key, &self.public_key).map_err(|e| format!("Wrap IPNS key: {}", e))?`; grep for `wrap_key.*ok()` returns zero matches |
| 2 | Finding B: file inode re-resolves when file_meta_ipns_name changes under unchanged mtime; same-pointer fast path preserved | VERIFIED | inode.rs lines 591-611: `same_pointer` check added inside the `modified == mtime` else-arm; returns `(true, None)` when names differ, `(true, Some(existing.kind.clone()))` when same |
| 3 | Finding C: VerifyError::Legacy is struct variant `{ cid: String, sequence_number: String }`; all 9 Legacy arms consume carried fields; zero second resolve_ipns calls in any Legacy arm | VERIFIED | verify.rs line 24: `Legacy { cid: String, sequence_number: String }`; all 9 arms use struct pattern; no `resolve_ipns(` inside any Legacy arm body across all 6 files |
| 4 | Findings D/E: dead journal_entry branch collapsed; content_ops dead bindings removed; signature_verified field removed; is_ipns_not_found test corrected; vector fixture stripped | VERIFIED | metadata.rs: single `Err(format!("persistent conflict for {}", ipns_name))` with `journal_entry` param kept + TODO; content_ops.rs: `record_b64` inside first-publish branch, `if current_seq.is_none()` guard replacing dead binding; `grep -rn "signature_verified" crates/fuse/src/` returns zero; metadata.rs:1154-1158 asserts `"record not found"` true and `"404"` false; vector JSON has 0 `public_key` occurrences |
| 5 | Finding F: first-publish embeds sequence 1 in publish.rs and replay.rs; verify.rs uses strict `embedded_seq == resp_seq`; skew allowance removed (survives only as explanatory comment) | VERIFIED | publish.rs line 18: `return Ok(1)`; replay.rs line 628: `create_ipns_record(&ipns_key_arr, &value, 1, 86_400_000)`; verify.rs line 112: `let seq_ok = embedded_seq == resp_seq;` — no `resp_seq == 1 && embedded_seq == 0` clause; case-8 vector repurposed (expected_result updated, not removed — plan says "removed or repurposed") |
| 6 | All 6 source todos archived to .planning/todos/completed/ via git mv | VERIFIED | All six files present in `.planning/todos/completed/`; none remain in `.planning/todos/pending/` matching the six expected names |

**Score:** 6/6 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `crates/fuse/src/fs.rs` | File-branch key-wrap error propagation (Finding A) | VERIFIED | `map_err(|e| format!("Wrap IPNS key: {}", e))?` at line 228 |
| `crates/fuse/src/inode.rs` | File-side re-resolution trigger on changed file_meta_ipns_name (Finding B) | VERIFIED | `same_pointer` check inside `modified == mtime` else-arm at lines 591-611 |
| `crates/fuse/src/verify.rs` | VerifyError::Legacy struct variant + strict seq equality + no signature_verified field | VERIFIED | Line 24: struct variant; line 112: strict equality; zero `signature_verified` references |
| `crates/fuse/src/events.rs` | Legacy arm consuming carried cid/sequence_number | VERIFIED | Lines 92-105: consumes `{ cid, sequence_number }` from carried fields |
| `crates/fuse/src/publish.rs` | next_file_publish_sequence first-publish returns 1; Legacy arms use carried sequence | VERIFIED | Line 18: `return Ok(1)`; lines 105 and 173: struct pattern with `sequence_number` |
| `crates/fuse/src/metadata.rs` | Dead journal_entry branch collapsed; Legacy arms consume carried cid; is_ipns_not_found test corrected | VERIFIED | Single `Err(format!(...))` with TODO; all three arms use `{ cid, .. }` pattern; test at lines 1154-1158 |
| `crates/fuse/src/content_ops.rs` | record_b64 inside first-publish branch; current_seq_for_cas/NOTE/discard replaced | VERIFIED | Lines 167-173: `record_b64` gated; line 200: `if current_seq.is_none()` guard |
| `crates/fuse/src/replay.rs` | Child-folder first-publish embeds 1; Legacy arms use carried cid | VERIFIED | Line 628: `create_ipns_record(..., 1, ...)`; lines 338 and 467: struct pattern |
| `scripts/gen-ipns-verify-vectors.ts` | No public_key/private_key fields emitted | VERIFIED | Zero matches for `public_key\|private_key` in file |
| `tests/vectors/ipns/verify.json` | No public_key/private_key keys in JSON | VERIFIED | `grep -c "public_key" tests/vectors/ipns/verify.json` returns 0 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| fs.rs build_folder_metadata File arm | cipherbox_crypto::wrap_key | `map_err(|e| format!("Wrap IPNS key: {}", e))?` | VERIFIED | Line 227-229; no `.ok()` adjacency |
| inode.rs upsert_children File modified==mtime else-arm | file_meta_resolved reset | `same_pointer` check via `file_meta_ipns_name.as_deref() == Some(...)` | VERIFIED | Lines 591-611; returns `(true, None)` on name change |
| verify.rs bind_verified | VerifyError::Legacy { cid, sequence_number } | None verdict arm clones resp.cid / resp.sequence_number | VERIFIED | Lines 69-72: `Err(VerifyError::Legacy { cid: resp.cid.clone(), sequence_number: resp.sequence_number.clone() })` |
| All 9 Legacy arms (events/fs/publish/metadata/replay) | carried cid + sequence_number | struct pattern binding; no resolve_ipns fallback | VERIFIED | All 9 arms bind `{ cid, .. }` or `{ cid, sequence_number }` or `{ sequence_number, .. }`; zero `resolve_ipns(` in any Legacy arm body |
| publish.rs next_file_publish_sequence | verify.rs bind_verified seq check | unified embed=1 enables strict equality | VERIFIED | publish.rs:18 `return Ok(1)`; verify.rs:112 `embedded_seq == resp_seq` (no skew clause) |
| replay.rs publish_child_folder_metadata | create_ipns_record first-publish seq | `create_ipns_record(&ipns_key_arr, &value, 1, ...)` | VERIFIED | replay.rs:628; no `create_ipns_record(.*, 0,` remains in first-publish sites |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Full fuse unit suite (93 tests) | `cargo test -p cipherbox-fuse --features fuse` | 93 passed; 0 failed | PASS |
| Cross-language IPNS verify vector test | `cargo test -p cipherbox-fuse --features fuse` (ipns_verify_cross_language) | 1 passed; 0 failed | PASS |
| Finding A test existence | `--list` output | `fs::build_folder_metadata_tests::build_folder_metadata_wrap_key_error_propagates_as_err: test` | PASS |
| Finding F seq=1 test | `--list` output | `publish::tests::next_file_publish_sequence_starts_new_records_at_one: test` | PASS |
| Legacy struct test | `--list` output | `verify::tests::bind_verified_legacy_returns_legacy: test` | PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| HARD-10 | 59-01, 59-02, 59-03, 59-04 | FUSE IPNS verify/publish hardening and cleanup — swallowed key-wrap error, stale CID/key re-resolution, legacy response carrying, dead seams, first-publish sequence unification | SATISFIED | REQUIREMENTS.md line 235: marked "Complete" for Phase 59; all six findings verified in live source |

### Anti-Patterns Found

| File | Pattern | Severity | Notes |
|------|---------|----------|-------|
| metadata.rs:200 | `let _ = &journal_entry;` | Info | Intentional suppression pending D-01a deferred journal work; the plan explicitly requires retaining the `journal_entry` param with a TODO — this is not a debt marker |

No TBD, FIXME, or XXX markers in any of the eight modified source files. The `let _ = &journal_entry;` pattern is plan-mandated (D-01a deferred work) and carries no independent debt marker.

### Human Verification Required

#### 1. Windows winfsp CI Gate

**Test:** Dispatch `Cargo Check & Test (Windows)` via `gh workflow run "CI E2E Tests" --ref feat/fuse-ipns-verify-publish-hardening-and-cleanup`
**Expected:** Green — all four plans touch shared cfg-gated code compiled under both `fuse` and `winfsp` feature sets. The enum shape change (VerifyError::Legacy struct variant), the File-arm key-wrap propagation, and the first-publish seq=1 constant are all under `#[cfg(any(feature = "fuse", feature = "winfsp"))]`.
**Why human:** macOS cargo cannot compile the `winfsp` feature (Windows-only deps); CI is authoritative per project MEMORY.md and all four plan acceptance criteria explicitly require this gate.

#### 2. SDK E2E Suite

**Test:** With local stack running (docker compose + API dev server, redis on 6380), run `pnpm --filter @cipherbox/sdk test` (or equivalent SDK E2E command).
**Expected:** All SDK E2E tests pass — the first-publish embedded-sequence change from 0 to 1 touches the real client→API IPNS publish/resolve round-trip exercised by `tests/sdk-e2e`.
**Why human:** Requires a live local API stack; cannot run in static verification; per project MEMORY.md: SDK E2E is the only cross-package publish gate.

#### 3. Desktop E2E Gate

**Test:** Dispatch desktop E2E via `gh workflow run "CI E2E Tests" --ref feat/fuse-ipns-verify-publish-hardening-and-cleanup`.
**Expected:** CI E2E Tests pass — the FUSE first-publish sequence convention (publish.rs, replay.rs) and durability paths are exercised by the desktop E2E gate.
**Why human:** Desktop E2E is dispatch-gated (skipped on main push without desktop-path changes) per project MEMORY.md.

### Gaps Summary

No gaps. All six observable truths are verified against live source code. The three human verification items are pre-acknowledged durability gates deferred at the phase level per the verification prompt and plan acceptance criteria — they are not failures in the implemented code.

---

_Verified: 2026-06-23_
_Verifier: Claude (gsd-verifier)_
