---
phase: 69
phase_name: "fuse-and-winfsp-rust-integration-and-grant-root-awareness"
project: "CipherBox"
generated: "2026-07-07"
counts:
  decisions: 9
  lessons: 7
  patterns: 6
  surprises: 5
missing_artifacts:
  - "69-UAT.md (no conversational UAT recorded; verification was code + cargo-test driven)"
  - "69-REVIEW.md (ship-time CodeRabbit review ran via CLI/sub-agents, not persisted as a phase doc)"
---

# Phase 69 Learnings: FUSE and WinFsp — Rust Integration and Grant-Root Awareness

## Decisions

### SDK-owned Rust read chain in `crates/core` + `crates/sdk` (D-01/D-02)
Built the `node/v3` read chain fresh in Rust as a mirror of the TS Phase 68.2 consolidation rather than reimplementing resolve/unseal/gating inline in FUSE/WinFsp. `crates/core` owns the pure IPNS-resolve + node-unseal + per-child metadata resolution + `Node`/`SealedChildRef` codec; `crates/sdk` owns the stateful layer (anti-rollback gate, durable floor store, resolved child-listing API). FUSE and WinFsp consume the resolved listing (`list_folder_owned`/`fetch_node_gated`) and never resolve inline.
**Rationale:** Keeps the Rust stack a thin adapter over an owning SDK (`crates/core : packages/core :: crates/sdk : packages/sdk`), so the duplication/desync class 68.2 removed on web cannot recur in Rust.
**Source:** 69-CONTEXT.md, 69-VERIFICATION.md

---

### Durable JSON-sidecar anti-rollback floor store (D-03)
Persisted the generation + seq high-water as a `JsonSidecarFloorStore` writing `{nodeId: value}` to `<journal_dir>/rotation-high-water-generation.json` + `-seq.json` — adjacent to the write journal, behind an injected `HighWaterStore` trait, atomic temp-rename write, 0600, survives daemon restart. Rejected embedded KV (sled/redb) and sqlite as heavyweight for a handful of monotonic counters plus a new daemon runtime dependency.
**Rationale:** Reuses the journal's existing sidecar pattern and adds zero new crates; mirrors 68.2's injected-store seam (daemon supplies persistence, SDK owns gating). Closes the critical generation-downgrade threat (T-69-02-01).
**Source:** 69-CONTEXT.md, 69-SECURITY.md, 69-VERIFICATION.md

---

### `Node` as a real Rust enum via a clean flag-day cutover (D-04)
Introduced `enum Node { Folder{children}, File{content}, Root{children} }` in `crates/core/src/node/`, deleted the legacy `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry`, and migrated every FUSE/`replay`/`metadata` call site in-phase. No coexistence/bridge and no dual-format/compat deserializer — there are no production vaults on the old model, so the greenfield single-codec doctrine applies.
**Rationale:** A legacy↔Node bridge would weaken the single-codec guarantee (T-69-10-01); the cross-language KAT is the conformance oracle instead of a runtime compat path.
**Source:** 69-CONTEXT.md, 69-09-SUMMARY.md, 69-10 (referenced)

---

### Symmetric AES-GCM-AAD node unseal replacing ECIES on the node path (SC#1)
Replaced all `ecies::unwrap_key` child-key unwraps in `inode.rs`/`replay.rs` with `unseal_aes_gcm_aad` symmetric unwrap using the correct `build_node_aad` AAD (childId/role/generation bound). ECIES survives only where it legitimately belongs: the vault-root key wrap, TEE, name blob, and the recycle-bin envelope.
**Rationale:** node/v3 seals children under a symmetric read/write key derivable through the read chain; the node-to-node ECIES fan-out was the pre-v2.0 model. AAD binding defeats blob transplant/replay (T-69-04-01).
**Source:** 69-VERIFICATION.md, 69-CONTEXT.md

---

### Grant-root scope-exit gate as a single shared module (both Unix and WinFsp)
`crates/fuse/src/write_ops/grant_scope.rs` is the one `gate_scope_exit`/`run_scope_exit_gate` rule consumed by every delete/rename/move site on both platforms: no covering grant → pure parent relink with zero rotation; covering grant → invoke rotate exactly once at the matched grant-root ipns_name. A CI grep gate forbids any per-platform predicate copy.
**When to use:** Any cross-platform security predicate — put it in one module both platforms consume and gate divergence in CI, never copy it per platform.
**Rationale:** A divergent WinFsp copy of the scope predicate is a high-severity revocation-bypass risk (T-69-07-03/-13-04/-14-01).
**Source:** 69-13-SUMMARY.md, 69-14-SUMMARY.md, 69-SECURITY.md

---

### Full in-phase port of the TS 63/64 read-rotation engine (D-05)
Ported the whole rotation engine into `crates/sdk`, sequenced after the Node-enum + read-chain foundation, reaching parity on resumable/crash-safe execution, CRIT-1 content-key rotation, M1 generation-downgrade defense, HIGH-3 multi-rooted grant re-mint, and HIGH-4 add-during-rotation merge. Rejected splitting into a 69.1 follow-up (would leave SC#3's rotation trigger fail-closed and force a roadmap change).
**Rationale:** The SDK owns stateful ops (D-02); a partial port would strand the phase's grant-root deliverable.
**Source:** 69-CONTEXT.md, 69-08-SUMMARY.md (referenced)

---

### D-07 write/read dual-keying threaded distinctly (HARD CONSTRAINT)
Every shared-write delete/move/rename path threads both the write-body `WriteChildRef.childId` (the stored node UUID / `published.id`, never `uuid_from_ino`) and the read-body `SealedChildRef` (ipnsName) as separate values. Conflating the two silently breaks `rotateWriteFromNode` — the write plane is keyed by UUID, the read plane by ipnsName. `crates/fuse/src/write_ops/` is flagged for explicit security review with `// SECURITY-REVIEW: D-07` markers.
**Rationale:** A whole family of high threats (T-69-09-05/-13-01/-16-03/-17-03/-18-02/-19-01) is the same conflation bug; keeping the two key spaces distinct is a cryptographic-correctness invariant.
**Source:** 69-CONTEXT.md, 69-13-SUMMARY.md, 69-14-SUMMARY.md, 69-SECURITY.md

---

### vault-blob-v3 codec ported byte-exact to Rust via cross-language KAT (69-21)
Added `serialize_vault_blob_v3`/`deserialize_vault_blob_v3` (`0x03 | u16_BE(readLen) | ECIES(rootReadKey) | u16_BE(writeLen) | ECIES(rootWriteKey)`) byte-identical to `tests/vectors/vault-v3-blob.json` and `packages/core/src/vault/blob.ts`, so a v3 vault minted on web opens on desktop and vice-versa. Purely additive — v2 codec byte-unchanged; envelope-only (no crypto in the byte layer); deserialize returns owned copies (D-09).
**Rationale:** The frozen KAT vector is the interop oracle; loading it from disk (not hardcoding) makes any future layout drift on either side fail the test.
**Source:** 69-21-SUMMARY.md

---

### WinFsp isolated as its own plan, user-Windows-box + CI-only sign-off (D-06)
WinFsp was built in-phase but as its own plan (69-14) against the same `crates/sdk` listing/gate API as FUSE, with the user iterating on a Windows box and the `cargo-windows` CI job + dispatched Desktop E2E matrix as objective sign-off. Development sequenced core/SDK + macOS/Linux FUSE first, then the Windows platform layer.
**Rationale:** `crates/fuse/src/platform/windows/*` never compiles under local macOS cargo (macFUSE-only linking), so planning could not assume fast local Windows iteration or long CI round-trips per edit.
**Source:** 69-CONTEXT.md, 69-VERIFICATION.md, 69-14-SUMMARY.md

---

## Lessons

### The WinFsp platform layer cannot be compiled locally on macOS
`crates/fuse/src/platform/windows/*` only links under `--features winfsp` on Windows (macFUSE vs WinFsp linking); on the mac dev box those files never compile. Plan 69-14 is therefore `autonomous:false` / intentionally unexecuted locally, and SC#5 is a required-green CI gate (`cargo-windows` + dispatched `Desktop E2E Tests`), not a code gap.
**Impact:** Treat SC#5 as objective sign-off authority that runs in CI, not a local verification. Verify the `cargo-windows` job actually RAN (path-filter can skip it) and dispatch Desktop E2E explicitly against the branch SHA before merge.
**Source:** 69-VERIFICATION.md, 69-VALIDATION.md, 69-14-SUMMARY.md

---

### A shared-API cutover leaves the CI-only Windows callers broken until they are migrated
The node/v3 + legacy-type-deletion cutover (69-09/69-10) reshaped shared APIs the Windows platform callers depended on, leaving `platform/windows/*` red and un-compilable until 69-14 migrated them 1:1. The `cargo-windows` job was expected-red from the cutover until 69-14 landed; the SC#2 grep gate carried a `grep -v 'platform/windows'` carve-out for the same window, promoted whole-tree only once 69-14 compiled.
**Impact:** When a clean cutover changes shared signatures, the CI-gated platform that can't compile locally stays red by design — track it as a known-red gate with a temporary carve-out, and land the migration plan before promoting the gate.
**Source:** 69-14-SUMMARY.md, 69-09-SUMMARY.md, 69-13-SUMMARY.md

---

### The shared-scope-exit read-key rotation is built but fail-closed, not live-wired (ROT-07 gap)
`rotate_read_on_scope_exit` returns `Err(RotateFailed)` → EIO because no production `cipherbox_sdk::rotation::engine::RotationDeps` implementor exists anywhere in the workspace (only the engine's in-crate `FakeDeps` test double). The grant-root gate/awareness — the phase deliverable — IS present and wired; live rotation EXECUTION is a standalone deferred live-wiring plan matching the known ROT-07 gap.
**Impact:** Fail-closed is security-safe (a covered scope-exit refuses to complete a delete/move without rotating, preventing revocation bypass), and private deletes are fully functional — but shared-scope-exit deletes/moves are functionally EIO until the RotationDeps live-wiring plan lands. Do not claim runtime rotation correctness; the reachable gate is spy-based call-count tests.
**Source:** 69-VERIFICATION.md, 69-13-SUMMARY.md, 69-SECURITY.md

---

### Gate a cold child's resolve on the PARENT's mirrored generation, never the relay-served envelope
For M1 generation-downgrade defense, the anti-rollback gate on a not-yet-cached child during a folder-listing walk must be fed the PARENT's `SealedChildRef.generation` mirror (locally trusted) — never the child's own relay-served envelope generation. Only when reconciling the SAME already-loaded node (a write-path check) does the in-memory node's own tracked generation apply. Getting this backwards silently defeats M1.
**Impact:** Thread `SealedChildRef` context into every per-child gate call; a `list_folder` gate signature that only takes an IPNS name with no parent-mirror generation cannot correctly gate a cold child. Rollback stays covered because the (seq,CID) IPNS signature binding + AEAD generation-AAD binding both bind the record.
**Source:** 69-RESEARCH.md (Pitfall 3 / 68.2 parent-mirror source), 69-WRITE-PLANE-RESEARCH.md

---

### CodeRabbit CLI times out on very large diffs — scope per-crate with `--dir`
The phase ship review had to be scoped per-crate (`--dir`) because the CLI times out on the full multi-crate diff.
**Impact:** For large multi-crate Rust phases, split the review by crate/directory rather than requesting one whole-diff pass; this mirrors the known 150-file-cap / big-phase directory-scoping pattern.
**Source:** 69 ship review (CodeRabbit CLI)

---

### Adversarial per-finding verification via sub-agents separated a real bug from false positives
Reviewing each ship finding with a dedicated verification sub-agent distinguished a genuine CRITICAL read-after-write EIO (an unresolved-`FilePointer` poll shadowing the `pending_content` fallback) from false positives — reviewer misreads where generation/version_floor arguments were read as size/mtime, and a flagged "write-generation reset" that is in fact guarded one level up.
**Impact:** Don't force-fix review findings on a security/crypto-heavy phase; verify each against live code first. Real bugs get fixed, misreads get refuted with evidence, and findings against intentionally-deferred surfaces are documented rather than patched.
**Source:** 69 ship review (per-finding sub-agent verification)

---

### The desktop root read/write keys are a placeholder bridge, E2E-gated
To reach compile-green without expanding into the (stubbed v2.0, phase-63) keeper auth flow, the desktop mount derives `root_read_key` from the legacy `root_folder_key` and `root_write_key` from a domain-separated placeholder transform. The plumbing (params threaded through prepopulate + replay + `InodeKind::Root`) is correct; the key BYTES are placeholders until server-side root-key recovery is wired.
**Impact:** A real node/v3 vault mount reads/writes with wrong root keys until recovery lands — this is a flagged, E2E-gated boundary of the atomic cutover, not a per-slice regression. desktop-e2e is the real correctness gate.
**Source:** 69-09-SUMMARY.md

---

## Patterns

### Cross-language KAT (byte-exact `tests/vectors/*.json`) to keep the Rust codec in lockstep with its TS twin
Every codec (`node-codec.json`, `node-aad.json`, `vault-v3-blob.json`) is asserted byte-for-byte against a frozen JSON vector loaded at runtime via `CARGO_MANIFEST_DIR` + `serde_json`, so a layout drift on either the Rust or the TS side fails the test.
**When to use:** Any wire format that must interoperate across the Rust and TS implementations — drive the gate from the on-disk vector, never hardcode expected bytes.
**Source:** 69-21-SUMMARY.md, 69-01-SUMMARY.md, 69-SECURITY.md

---

### Terminal-owner zeroization rule
Zeroize only at the terminal owner: a callee that receives caller-owned key buffers must NOT zero them; `rotate_one` zeros only its own newly-minted `read_key_prime`, and only on its own failure paths (never on success — the BFS walk still needs it). The mount is the terminal owner: `ResolvedOwnedChild` keys are MOVED into `InodeKind`, never borrowed-then-zeroed.
**When to use:** Any function taking `Zeroizing`/key buffers — wrapping a caller-owned buffer in `Zeroizing` zeros it on scope exit and corrupts the caller. Add a unit test asserting a caller-supplied key is unchanged after a successful call.
**Rationale:** This is the exact 48/89-E2E-break incident from project memory (T-69-08-01).
**Source:** 69-RESEARCH.md (Pitfall 3), 69-09-SUMMARY.md, 69-SECURITY.md

---

### `deny_unknown_fields` fail-closed decode on node wire structs
`SealedChildRef` implements exactly the frozen NODE-03 five fields with `#[serde(deny_unknown_fields)]` and structurally excludes any write field, closing the read/write separation at the type level and rejecting malformed/extended blobs at decode.
**When to use:** Wire structs decoded from untrusted relay bytes — reject unknown fields to fail closed on tampering/drift (T-69-01-01).
**Source:** 69-01-SUMMARY.md, 69-SECURITY.md

---

### Single CI grep-gate forbidding inline raw IPNS resolve in `crates/fuse` (SC#6)
A `ci.yml` grep gate fails if `crates/fuse/src` contains a raw `resolve_ipns_verified(`/`resolve_published_node(` call without an inline `// sc6-allow` marker (checked in a ±1-line, rustfmt-stable window). All FUSE/WinFsp reads must route through the sanctioned gated entrypoints (`list_folder`/`list_shared_folder`/`list_folder_owned`/`fetch_node_gated`); the few non-read-path sites are explicitly allowlisted.
**When to use:** Enforce a single gated entrypoint invariant that grep can express — the gate makes the "no ungated resolve" rule machine-checked instead of reviewer-dependent (closes anti-rollback-bypass threats T-69-06-02/-09-01/-16-01/-17-01).
**Source:** 69-09-SUMMARY.md, 69-VERIFICATION.md, 69-VALIDATION.md

---

### Best-effort unpin of an uploaded CID on publish-failure paths
On every publish-failure path an uploaded CID is unpinned best-effort so failed writes don't strand pinned orphans; note the parallel residual that `metadata_cache` no longer surfaces the old metadata CID for unpin after re-publish, so stale parent CIDs may accumulate as GC-able orphan pins (verify GC, not correctness-critical).
**When to use:** Any upload-then-publish flow — treat the pin as owned by the publish and release it if the publish doesn't commit.
**Source:** 69-09-SUMMARY.md

---

### Platform parity: WinFsp handlers are literal 1:1 mirrors of the fuser handlers over shared seams
The WinFsp read/write handlers (`read_ops`/`dir_ops`/`operations`/`write_ops`) mirror the fuser handlers 1:1 and CONSUME the shared `content_ops`/`journal_helpers`/`grant_scope`/`build_folder_metadata` seams rather than maintaining a divergent implementation; feature-gated unit tests assert per-platform name semantics (NFC-composition under `fuse`, case-insensitive lowercasing under `winfsp`).
**When to use:** A second platform layer over the same SDK — mirror the reference platform and share the security-bearing modules; only fork behavior that genuinely differs (name normalization), and gate that fork in tests.
**Source:** 69-14-SUMMARY.md

---

## Surprises

### macFUSE-vs-WinFsp linking makes the Windows layer un-compilable on the dev box
`platform/windows/*` cannot be compiled at all under local macOS cargo — not a missing feature flag but a linking incompatibility — so an entire plan (69-14) is CI-only / user-Windows-box iterated and its threats are CI-verified rather than code-verified locally.
**Impact:** Structure the Windows plan self-contained and runnable on the user's box, and treat the `cargo-windows` job + dispatched Desktop E2E matrix as the sign-off authority.
**Source:** 69-VERIFICATION.md, 69-14-SUMMARY.md

---

### No production `RotationDeps` implementor exists anywhere in the workspace
The rotation engine is fully ported and unit-tested, but a live `rotate_read_from_node` call is not constructible — `grep -rn 'impl RotationDeps'` finds only the engine's in-crate `FakeDeps` test double. The scope-exit rotation seam therefore had to be shipped fail-closed (EIO) rather than live.
**Impact:** The grant-root gate is delivered and wired, but live rotation execution is a separate ROT-07-class live-wiring plan (IPNS resolve-verify + node fetch/unseal + CAS publish + wire→GrantRow decode + job persistence). Don't overclaim runtime rotation on this phase.
**Source:** 69-13-SUMMARY.md, 69-VERIFICATION.md

---

### A CRITICAL read-after-write EIO: the unresolved-`FilePointer` poll shadowed the `pending_content` fallback
Ship review surfaced a genuine read-after-write bug where an unresolved-`FilePointer` poll path shadowed the `pending_content` fallback, returning EIO on a just-written file.
**Impact:** This was the one real bug among the ship findings — adversarial per-finding verification was what separated it from the misreads; the read-after-write path deserves explicit test coverage.
**Source:** 69 ship review (CodeRabbit + sub-agent verification)

---

### Several high-confidence-looking review findings were false positives
Two flagged findings were reviewer misreads: generation/version_floor arguments read as size/mtime, and a "write-generation reset" that is actually guarded one level up. Both looked plausible in isolation but were refuted against live code.
**Impact:** On crypto/security-heavy diffs, verify each finding against the code before fixing — force-fixing these would have introduced regressions. Findings targeting the intentionally-not-yet-live grant-scope rotation or the CI-gated Windows path were correctly deferred, not patched.
**Source:** 69 ship review (per-finding sub-agent verification)

---

### The NFC-normalize inode test was a latent bug that only surfaced on the first-ever WinFsp compile
`inode::tests::test_find_child_nfc_normalizes_unicode` asserts NFC composition, but `normalize_name` NFC-composes only under `feature = "fuse"`; under `winfsp` it lowercases (WinFsp owns case-insensitive lookup). The test had never run under winfsp because that build never compiled — so the wrong assumption sat latent until 69-14.
**Impact:** Feature-gated tests only exercise assumptions on the feature that compiles; the first compile of a long-dormant feature is where latent test bugs (and dead `drop(&ref)` no-ops, unused imports) surface. Gate platform-specific assertions to their feature and add a counterpart for the other.
**Source:** 69-14-SUMMARY.md

---
