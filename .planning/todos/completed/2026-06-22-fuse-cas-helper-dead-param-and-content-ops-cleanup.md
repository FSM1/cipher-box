---
created: 2026-06-22T00:00:00.000Z
title: FUSE CAS helper dead param + content_ops dead-binding cleanup
area: refactor
severity: low
source: Phase 56 simplify review (gsd-code-reviewer pass during ship-phase 56)
files:
  - crates/fuse/src/metadata.rs
  - crates/fuse/src/content_ops.rs
  - crates/fuse/src/fs.rs
---

Deferred because these touch the durability-critical IPNS CAS publish path and would
require changing the durability test seam — out of proportion to a ship-time cleanup.

## Items

1. `publish_with_cas_retry` dead `journal_entry: Option<()>` param
   - File: `crates/fuse/src/metadata.rs` (`publish_with_cas_retry`, ~line 108 + the
     `if journal_entry.is_some() { ... } else { ... }` arm ~line 197-208).
   - Both branches return the identical `Err(format!("persistent conflict for {}", ipns_name))`,
     and both call sites pass `None`. The param is a placeholder seam for the deferred
     "journal-on-exhaustion" idea (D-01a is intentionally Err→EIO this phase).
   - Cleanup: drop the param + collapse the dead branch to a single `Err(...)`, OR keep it
     only when the journal-on-exhaustion deferred idea is actually built. The
     `publish_with_cas_retry_persistent_conflict_journal_none_returns_err` test (and its
     `journal_entry_is_some` mock seam) would need updating in lockstep.

2. `content_ops.rs` dead `record_b64` computed in the update branch
   - File: `crates/fuse/src/content_ops.rs` (~line 120-133).
   - `record`/`marshaled`/`record_b64` are computed unconditionally but only used on the
     `is_first_publish` branch; the update branch re-signs inside `publish_with_cas_retry`'s
     closure. Gate the computation inside the `if is_first_publish {` block.

3. `content_ops.rs` `current_seq_for_cas` binding + `let _ =` discard + 14-line NOTE comment
   - File: `crates/fuse/src/content_ops.rs`.
   - The `.ok_or_else(...)?` is a real validation (errors if `resolve_sequence` returned None
     on an update) but the bound name is never used in code (only referenced in a comment),
     and `let _ = current_seq_for_cas;` plus the long NOTE is noise. Replace with a bare
     `if current_seq.is_none() { return Err(...) }` validation and delete the discard + NOTE.

## Larger DEFER (structural, not mechanical)

4. Folder inline CAS loop vs `publish_with_cas_retry` duplication — only consolidatable by
   making `make_record` async (`FnMut(u64) -> impl Future`) or passing an async merge hook.
   Real retry-semantics risk; the "async-closure constraint" decision is legitimate. Leave
   unless the helper is reworked.

5. `fs.rs` D-09 `pending_fp_resolves` two-stage drain (`pending_drain` Vec + VecDeque with
   front/back push and re-push-front-on-cap) is correct but denser than needed; a single
   bounded loop could likely express it. Not a safe mechanical edit.

Destination: a future FUSE cleanup phase (or fold into Phase 58 if it reworks the resolve/
publish chokepoints, since it overlaps the same files).
