---
phase: 74
phase_name: "rust-and-fuse-rotation-revocation-soundness"
project: "CipherBox"
generated: "2026-07-11"
counts:
  decisions: 10
  lessons: 7
  patterns: 6
  surprises: 6
missing_artifacts: []
---

# Phase 74 Learnings: rust-and-fuse-rotation-revocation-soundness

## Decisions

### Keep `CommittedRotation` host-agnostic; thread `ipns_name` at call sites

The engine's `RotateReadResult` was widened with `rotated_nodes: HashMap<String, RotatedNodeKey>` additively, but `CommittedRotation` was left untouched — no `ipns_name` field added. The identifier is threaded into `RotatedNodeKey` at each of the three call sites (`root_ipns_name`, `item.child_ref.ipns_name`) where it is already in scope.

**Rationale:** Avoids churning the ~27 existing `RotateReadResult`/`rotate_read_from_node` call sites and preserves the host-agnostic design of `CommittedRotation` (RESEARCH Pitfall 1).
**Source:** 74-01-SUMMARY.md

### Map keyed by `ipns_name`, not `node_id`

`rotated_nodes` (Rust) / `rotatedNodes` (TS) is keyed by `ipns_name`.

**Rationale:** Matches the LOCKED cross-language contract and how the FUSE refresh (`refresh_rotated_inode_read_keys`) matches inodes — by `ipns_name`, not `node_id`.
**Source:** 74-01-SUMMARY.md, 74-03-SUMMARY.md

### Fold `repair_dirty_node`'s recovered key into `rotated_nodes` (Rust only)

Rust 74-01 folded its crash-resume `repair_dirty_node` hook into the map (`recovered_key` was already in scope, ~10-line addition). TS 74-02 deliberately did NOT populate `repairDirtyNode`'s path — its task scope was exactly the root commit + BFS child commit branches.

**Rationale:** Rust resolved RESEARCH Open Question 1 in favor of "fold in, it's cheap"; TS held to the plan's narrower gate, documenting the asymmetry as a known (not defect) gap for a future plan.
**Source:** 74-01-SUMMARY.md, 74-02-SUMMARY.md

### Type `RotatedNodeKey.sequenceNumber` as `bigint`, not the LOCKED table's literal `number`

The plan's cross-language contract table listed TS `sequenceNumber: number` (a literal translation of Rust `u64`), but it was typed `bigint`.

**Rationale:** Every other IPNS sequence number in `engine.ts` (`RotateReadResult.sequenceNumber`, `CommittedRotation.newSequenceNumber`, `ParentTrackingState.parentLastSeq`) is `bigint`; `number` cannot safely hold a real 64-bit IPNS sequence and would create internal inconsistency. Treated as a Rule 1 fix to the plan's table.
**Source:** 74-02-SUMMARY.md

### Add a raw-TCP capturing mock server instead of a mock-HTTP crate

`cipherbox-api-client` had no wiremock/mockito/httpmock dependency, so a minimal `std::net::TcpListener` one-shot capturing mock server was added inside the test module rather than pulling in a new crate.

**Rationale:** Mirrors the existing in-repo pattern (`spawn_mock_rotation_server` in `crates/fuse/.../delete.rs`); the tests need to assert exact outbound method/path/JSON-body-key-set, not just canned responses. No new dependency.
**Source:** 74-04-SUMMARY.md

### Extend the `RotationTransport` seam rather than reach for the concrete `ApiClient`

The three new grant operations (`collect_sent_shares`/`update_grant`/`revoke_share`) were added to the `RotationTransport` trait and implemented on both `ApiClientTransport` (real) and `FakeTransport` (test), with `FuseRotationDeps` delegating generically over `T: RotationTransport`.

**Rationale:** `FuseRotationDeps` cannot reach `self.transport.api` over a generic `T`; growing the seam trait keeps the whole change inside `rotation_deps.rs` and leaves `grant_scope.rs`'s construction site untouched.
**Source:** 74-05-SUMMARY.md

### Implement `delete_grant` for engine-contract completeness even though its branch is unreachable

`delete_grant` is wired even though `query_grants_rooted_at` always reports `is_revoked: false` (revoked shares are hard-deleted server-side and never appear).

**Rationale:** Satisfies the engine contract; over-retention of a revoked recipient is structurally impossible (T-74-14 dispositioned `accept`, not `mitigate`).
**Source:** 74-05-SUMMARY.md, 74-SECURITY.md

### Scope WinFsp `handle_rename` to the ENOTEMPTY reorder only — no self-replace/kind-mismatch validation

Only the `STATUS_DIRECTORY_NOT_EMPTY` check was reordered and the dest scope-exit gate added; self-replace (`dest_ino == source_ino`) and kind-mismatch (`ENOTDIR`/`EISDIR`) validation from the fuser reference were NOT ported.

**Rationale:** RESEARCH Pitfall 4 / Todo 3 point 4 explicitly scoped those as an optional stretch item outside SC3, which is about the scope-exit gate, not full POSIX-parity.
**Source:** 74-06-SUMMARY.md

### Combine the deep-tree leg and the second-recipient leg into one Part C e2e scenario

Instead of two separate desktop-e2e legs, Part C uses one depth-2 tree shared to Eve (revoked) and Carol (retained), both on the same grant root.

**Rationale:** This is the only construction that correctly exercises 74-05's re-mint semantics (an active-but-untouched recipient is retained by design), and it avoids a redundant second grant-root/tree setup.
**Source:** 74-07-SUMMARY.md

### Assert the leaf delete target (`fileC`) as an INFO-level probe, not a hard SC1 gate

The hard SC1 gate is `folderB` (an intermediate walked/rotated node) plus `fileSibling` (a retained File node); `fileC` is a non-blocking probe.

**Rationale:** Once a recipient has independently derived a leaf file's read key, rotating its (now-deleted) parent cannot retroactively re-protect the already-known key against the immutable content-addressed IPFS blob — a documented forward-secrecy boundary, not a regression.
**Source:** 74-07-SUMMARY.md

---

## Lessons

### A `pub` struct is still unreachable across crates until re-exported through the module tree

74-01 defined `pub struct RotatedNodeKey` inside `engine.rs` but never added it to the `pub use engine::{...}` list in `rotation/mod.rs`, so `crates/fuse` could not name the type. 74-03 had to add the re-export (Rule 3 blocking auto-fix) before its test could even be written.

**Context:** When a new type is meant to be consumed by another crate, adding the barrel/module re-export must ship in the SAME plan that defines it, or the downstream plan pays a blocking fix.
**Source:** 74-03-SUMMARY.md, 74-01-SUMMARY.md

### Making a field non-optional forces every return site to thread the same live reference

When `rotatedNodes` became a required field on `RotateReadResult`, the dirty-resume-skip branch's object literal had to satisfy the type too. It threads the SAME live `Map` reference (not a fresh empty Map) so it reflects whatever the shared BFS loop populated before the object is actually returned.

**Context:** TS structural typing on a widened required field — passing the shared instance is both type-correct and behaviorally sound; a copy would drop later inserts.
**Source:** 74-02-SUMMARY.md

### Wiring a no-op dep to a real network call silently breaks tests that relied on the no-op

Once 74-05 wired `query_grants_rooted_at` to genuinely call `collect_sent_shares` (`GET /shares/sent`), a pre-existing `delete.rs` test's mock server — which only routed IPNS/IPFS paths — fell through to a 404, propagating `RotateFailed` and flipping the test from success to EIO. Fix: add a `GET /shares/sent` empty-page route to preserve the test's original intent.

**Context:** Replacing a no-op default with real transport surfaces every test that implicitly depended on the network never being hit. Run the full crate suite after such a wiring, not just the scoped one.
**Source:** 74-05-SUMMARY.md

### Plans' `read_first` can reference test harnesses/configs that do not actually exist

Three separate plans hit this: 74-06's `read_first` assumed a WinFsp `#[cfg(test)]` module that didn't exist and a `test_support` harness gated to `feature="fuse"` (invisible to winfsp builds); 74-04's referenced a mock-server harness that didn't exist; 74-07's verify command referenced `tests/desktop-e2e/tsconfig.json` which didn't exist anywhere in the repo.

**Context:** Verify the existence of every harness/config a plan tells you to reuse before relying on it; each of these required a minimal additive creation (Rule 3) to make the plan's own steps runnable.
**Source:** 74-06-SUMMARY.md, 74-04-SUMMARY.md, 74-07-SUMMARY.md

### `rustfmt` on a crate-root file (`lib.rs`) recursively reformats the entire module tree

Running `rustfmt --edition 2021` directly on `lib.rs` reformatted 8 unrelated files it discovered via `mod` declarations, producing large out-of-scope diffs.

**Context:** Scope formatting to the specific files touched (or use `cargo fmt -p <crate> -- --check` to detect, then targeted `git checkout --` to revert accidental drift). This crate has substantial pre-existing fmt drift that must be left untouched.
**Source:** 74-06-SUMMARY.md

### `tests/desktop-e2e` had zero typecheck coverage before this phase

No `tsconfig.json` existed for the desktop-e2e script directory; nothing typechecked its `.mts`/`.ts` files in CI or locally. 74-07 created one mirroring `tests/web-e2e/tsconfig.json`, extended to include `../e2e-helpers`.

**Context:** A whole test directory can silently lack typecheck coverage; the `.mts` scripts import shared helpers by relative path, so the config must `include` those sibling dirs.
**Source:** 74-07-SUMMARY.md

### A behavior fix can invalidate a pre-existing test's semantics without touching the test

Part A's "Bob" e2e assertion (kept active, expected to be cut off post-rotation) was correct under the old ROT-04 no-op `query_grants_rooted_at`, but 74-05's real re-mint means Bob's still-active grant should now be retained. It was left byte-for-byte untouched (changing its semantics is a design call beyond the plan's scope) and flagged as a Known Risk / follow-up.

**Context:** When a fix changes system behavior, audit pre-existing tests whose assertions encode the OLD behavior. Static analysis suggested Part A won't actually flip (it decrypts against a stale pre-rotation key captured before rotation, which fails regardless of re-mint) — but that is CI-authoritative, not assumed.
**Source:** 74-07-SUMMARY.md, 74-VERIFICATION.md

---

## Patterns

### Per-node result map threaded at call sites, additive to root-convenience fields

Widen a result struct with a `HashMap`/`Map<ipns_name, PerNodeKey>` and populate it at each commit hook, leaving the existing top-level root-convenience fields (`read_key`/`generation`/`sequence_number`) unchanged.

**When to use:** Surfacing per-node data from a BFS/tree operation without a breaking change to the many existing consumers of the root-only fields; mirror the same shape field-for-field across a Rust/TS parity pair.
**Source:** 74-01-SUMMARY.md, 74-02-SUMMARY.md

### Raw-TCP one-shot capturing mock HTTP server for wire-function tests

A minimal `std::net::TcpListener` server in the `#[cfg(test)]` module that captures the inbound request (method/path/body via an `mpsc` channel) so tests assert the exact bytes on the wire — no external mock-HTTP crate.

**When to use:** Rust wire-function unit tests that must assert the outbound method/path/JSON-body-key-set, when the crate has no mock-HTTP dependency and you don't want to add one.
**Source:** 74-04-SUMMARY.md

### RotationTransport seam extension (grow the trait, implement twice, delegate generically)

New transport ops are added to the seam trait and implemented once on the real adapter (`ApiClientTransport`) and once on `FakeTransport`, with the dependency struct delegating over `T: RotationTransport` and never reaching for a concrete client.

**When to use:** Adding capabilities to a component that talks to the network behind a trait seam, keeping the change local and both production + test paths in lockstep.
**Source:** 74-05-SUMMARY.md

### Revoked-vs-retained recipient pair on the same grant root, revoked DELETE'd before the mutation

Two recipients share the SAME grant root; the "revoked" one's share is explicitly `DELETE`'d before the covered mutation fires, while the retained one stays active.

**When to use:** E2E-distinguishing "genuinely cut off" from "active grantee re-minted" once the system re-mints every still-active grant rooted at a rotated node — an active recipient is retained by design, so leaving them active no longer proves revocation.
**Source:** 74-07-SUMMARY.md

### `resolveFileMetadata`-based decryptability probe for File-node invariants

A `canReadFile()` helper mirroring the folder-level `canRead()` but using `resolveFileMetadata` to probe a File node's decryptability with a given raw key.

**When to use:** Asserting decryptability invariants on File nodes (not just Folder nodes) in real-mount e2e — needed to cover the `InodeKind::File` refresh arm.
**Source:** 74-07-SUMMARY.md

### Cross-platform ordering-parity proved by a static line-by-line table

WinFsp `handle_rename` was made to match the fuser `rename.rs` D-15d pipeline (validate → source-gate → dest-gate → mutate) and the parity was proven with an explicit stage-by-stage table against the reference implementation.

**When to use:** Porting a correctness-critical ordering to a platform whose code can't be compiled/run locally — a documented static parity table plus grep-confirmed invariants (e.g. no coalescing added) is the maximum local verification before CI.
**Source:** 74-06-SUMMARY.md

---

## Surprises

### `repair_dirty_node` had everything needed to surface its key already in scope

RESEARCH flagged the crash-resume repair path's return shape as an untraced open question, expecting it might be deferred. On inspection, `recovered_key`, `generation`, `sequence_number`, and `ipns_name` were all in scope at the exact point the code already re-seals the parent mirror — a ~10-line fold-in with no new plumbing.

**Impact:** Closed a corner the plan left as either/or — a crash-resumed deep rotation now surfaces every repaired node's key, not just current-run commits.
**Source:** 74-01-SUMMARY.md

### The `delete_grant` revocation branch is structurally unreachable through this query path

`query_grants_rooted_at` hardcodes `is_revoked: false` because revoked shares are hard-deleted server-side and never appear in `collect_sent_shares`. So `delete_grant` is wired but no test asserts its firing.

**Impact:** T-74-14 (revoked recipient over-retained) was dispositioned `accept`, not `mitigate` — the threat is prevented structurally rather than by a code branch.
**Source:** 74-05-SUMMARY.md, 74-SECURITY.md

### Wiring one dep method to the network turned an unrelated passing test red

Making `query_grants_rooted_at` real caused a pre-existing `delete.rs` fail-closed test (117th test) to fail because its mock server didn't route the newly-issued `GET /shares/sent`.

**Impact:** Full-crate run dropped to 116/117 until the mock server gained an empty-page route; caught only because the crate-wide suite (not just the scoped one) was run.
**Source:** 74-05-SUMMARY.md

### `rustfmt` reformatted 8 unrelated files from a single `lib.rs` invocation

Formatting the crate-root file recursively pulled in the whole module tree it discovered via `mod` declarations.

**Impact:** Required a targeted `git checkout --` revert of 8 files (not a blanket reset) to keep the commit scoped; no unrelated formatting drift was committed.
**Source:** 74-06-SUMMARY.md

### All WinFsp and real-mount verification is CI-gated — the winfsp crate won't compile on macOS

`cargo check -p cipherbox-fuse --features winfsp` fails on `windows-future`/`windows_core::imp` symbols (a genuine macOS toolchain limitation, not a code defect). The two new WinFsp rename tests and all three desktop-e2e legs (Parts C/D) could only be authored + statically verified, never run locally.

**Impact:** 21/21 must-haves code-verified, but runtime proof for SC3 (Windows CI) and the 3-platform desktop-e2e live run are routed to human/CI verification — expected infra limitation per project convention, not a phase gap.
**Source:** 74-06-SUMMARY.md, 74-07-SUMMARY.md, 74-VERIFICATION.md, 74-UAT.md

### The self-flagged Part A "Bob" regression risk is likely a false alarm

74-07 warned that 74-05's real `query_grants_rooted_at` might flip Part A's `bobCanReadAfterRotation` assertion (Bob's active grant should now be re-minted, not cut). Static reading during verification found `bobCanReadAfterRotation` is computed against a raw key captured once via `unwrapKey` BEFORE rotation and never re-fetched, and `canRead()` decrypts directly against those bytes with no live grant lookup.

**Impact:** Because rotation always mints a genuinely new key regardless of grant re-mint, the stale captured key fails either way — the assertion tests "does my pre-rotation key still work," orthogonal to re-mint status. Low-confidence-of-regression, but CI is the authoritative check.
**Source:** 74-07-SUMMARY.md, 74-VERIFICATION.md
