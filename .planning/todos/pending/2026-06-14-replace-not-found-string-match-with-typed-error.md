---
created: 2026-06-14T12:37:25.820Z
title: Replace not-found string match with a typed error in replay
area: desktop-fuse
files:
  - crates/fuse/src/lib.rs
---

## Problem

Replay's first-publish detection keys the "seq-0 first publish + TEE enrollment" vs
"transient error, retain entry" branch off a substring match on the error MESSAGE of
`coordinator.resolve_sequence`:

```rust
Err(e) if e.to_lowercase().contains("not found") => { /* first publish */ }
```

This is fragile control flow: a backend/SDK reword of the not-found error (or a wrapped
/ localized error) silently flips the branch — either creating a duplicate record at
seq 0, or parking the entry forever. The NotFound-vs-transient distinction is invisible
to the type system. Surfaced by the phase-43 `/simplify` altitude reviewer; deferred
from commit a1ec69f1b as larger scope.

## Solution

Make the resolve path return a typed result so the branch keys off the type, not the
string: e.g. `resolve_sequence -> Result<Option<u64>, _>` (None == not found) or add a
`ResolveError::NotFound` variant. Update `PublishCoordinator::resolve_sequence` and its
other callers accordingly. Larger scope: touches the coordinator API beyond the replay
diff, so do it as its own change. Pairs with the publish_file_metadata-delegation todo
(which also depends on first-publish detection).
