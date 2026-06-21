# Phase 56: FUSE and IPNS Durability Hardening - Context

**Gathered:** 2026-06-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Durability/correctness hardening of the desktop FUSE write + per-file/bin IPNS-publish
path (macOS + Windows/winfsp **in lockstep**), plus a few sdk-core/web spillover fixes.
Closes 12 pre-existing gaps surfaced (each **verified byte-identical to `main`**) by the
PR #538 / Phase 55 refactor review — they were deferred because Phase 55's contract
(HARD-06) forbade behavior changes.

**Requirement:** HARD-07. **Depends on:** Phase 55 (post-refactor module layout).

**Behavior-correctness only — no new capabilities.** The guiding principle is the phase
intent: *no durability decision is left to a swallowed warning.*

</domain>

<decisions>
## Implementation Decisions

### Failure surfacing (errno) — the central durability policy

- **D-01:** Split failure handling by failure class:
  - **Transient** (per-file/bin IPNS `Conflict`): bounded re-resolve + retry with the
    server's resolved sequence as `expected_sequence_number`. On **retry exhaustion**,
    enqueue to the existing **Phase 43/46 persisted out-of-callback journal** and ack —
    data is durable (survives crash, replays), the FS thread is not blocked, and nothing
    is silently dropped.
  - **Hard** failures (`wrap_key` cannot encrypt — finding #3; decode of our *own*
    metadata fails — finding #8; a doomed/non-recoverable publish): **return `EIO`** to
    the OS immediately. No false success ack. A doomed op must surface, not loop forever
    in the journal.
- **D-02:** This directly fixes findings #1 (`content_ops.rs:175` per-file Conflict-as-success)
  and #2 (`metadata.rs:348` bin Conflict-as-success): the `Conflict` arm must re-resolve +
  retry, never `record_publish` with `expected_sequence_number: None`.

### CAS structure — one shared Rust retry helper

- **D-03:** Extract a single shared `publish_with_cas_retry` helper in `crates/fuse` and
  route the **three sequence-CAS publish sites** through it:
  - per-file (`content_ops.rs` `publish_file_metadata`),
  - bin (`metadata.rs:~340`),
  - folder metadata (`metadata.rs:~136-214`, which **already** has the correct
    re-resolve+retry loop — that loop is the template for the helper).

  One durability decision point instead of 3 near-duplicate loops.
- **D-04:** **Do NOT** touch mkdir's `MkdirConflict` event-channel re-arm mechanism
  (`write_ops/implementation/mkdir.rs` + `platform/windows/write_ops.rs`). It is a
  different, working pattern; consolidating it is a larger refactor and out of scope for
  this hardening pass.

### Locked from ROADMAP + folded todos (clear direction, not re-discussed)

These flow straight to planning — directions are already specified at file/line level in
the folded todos:

- **D-05 (write-path safety, `write_ops/implementation/file_data.rs`):** reject `offset < 0`
  → `EINVAL`; compute `new_end` with `checked_add` → `EFBIG` on overflow, **before**
  `write_at`.
- **D-06 (duplicate-name guards):** `handle_create`/mknod (`file_data.rs`) and `handle_mkdir`
  (`mkdir.rs`) must return `EEXIST` if the child name already exists under `parent`, before
  mutating the inode table.
- **D-07 (`publish.rs` `next_file_publish_sequence`):** replace unchecked `seq + 1` with
  `checked_add`/`saturating_add` (u64 overflow at MAX).
- **D-08 (`fs.rs:289` stale-completion unpin):** run the `pruned_cids` unpin loop **inside**
  the `write_generation` guard so a superseded write can't unpin CIDs the current
  generation still references.
- **D-09 (`fs.rs:421` FP-resolve continuation):** the FilePointer-resolution loop must not
  silently drop entries past `MAX_CONCURRENT_FP_RESOLVES = 10` — add a continuation queue.
- **D-10 (`events.rs:109` `spawn_metadata_refresh`):** bound the async refresh with
  `NETWORK_TIMEOUT`; ensure `refreshing_metadata` is always cleared so a hung resolve can't
  block future refreshes indefinitely.
- **D-11 (inode stable-ID identity reset, `crates/fuse/src/inode.rs` ~399-412, 461-475,
  515-580):** distinguish a stable-ID match (`ipns_to_ino`) from a display-name-only
  `find_child` fallback. On fallback-only match, identity changed → clear folder loaded
  state and force file re-resolution (refresh CID + metadata/keys). For files, treat a
  changed `file_meta_ipns_name` as a re-resolution trigger (not just `modified_at`).
- **D-12 (zeroize `spawn_metadata_publish`, `metadata.rs:85-86`):** change `folder_key` /
  `ipns_private_key` params from `Vec<u8>` to `zeroize::Zeroizing<Vec<u8>>`. Scope verified
  **2026-06-21 to be this ONE helper only** — `spawn_bin_entry_publish` and
  `spawn_file_meta_reencrypt` already take `Zeroizing`, and `events.rs` `spawn_metadata_refresh`
  already wraps `folder_key`. **Audit each call site first** (see Established Patterns — the
  callee-must-not-zero-a-reused-buffer rule).
- **D-13 (sdk-core spillovers):**
  - `folder/load.ts:~34` (`fetchAndDecryptMetadata`): wrap `TextDecoder.decode` / `JSON.parse`
    / `decryptFolderMetadata` in try-catch → typed failure, not an opaque throw.
  - `folder/registration.ts:~65`: move both `wrapKey` calls (`ipnsPrivateKeyEncrypted`,
    `folderKeyEncrypted`) **inside** the `try` whose `catch` zeroes key material, so a
    `wrapKey` throw still clears the buffers. Confirm these buffers are owned here before
    relying on zeroization.
- **D-14 (web spillovers, `apps/web/.../details/`):**
  - `DetailsPrimitives.tsx:~33`: gate `setCopied(true)` on an actual successful copy
    (`navigator.clipboard.writeText` resolving, or `execCommand('copy')` returning true) —
    no false success.
  - `VersionHistory.tsx:~37`: surface a user-visible error when version download
    early-returns on undefined `vaultKeypair?.privateKey`, instead of silent return.

### Cross-cutting constraints

- **D-15:** Every Rust change must keep **macOS and Windows (winfsp) paths in lockstep** —
  apply the same fix to `platform/windows/` siblings where a parallel site exists.

### Folded Todos

All four are the literal scope of this phase (the ROADMAP absorbed them):

- **`2026-06-21-fuse-ipns-robustness-findings-from-pr538-review.md`** — 8 findings
  (per-file/bin Conflict-as-success, `wrap_key().ok()` drop, stale-completion unpin,
  FP-resolve drop, refresh timeout, seq overflow, `load.ts` decode). Absorbs the superseded
  `2026-06-20-fuse-per-file-ipns-publish-conflict-recorded-as-success.md`. → D-01, D-02,
  D-03, D-08, D-09, D-10, D-07, D-13.
- **`2026-06-21-pr538-second-coderabbit-pass-preexisting-findings.md`** — 6 findings
  (write-path offset/overflow, create/mkdir EEXIST, `registration.ts` wrapKey-in-try,
  web copy-gating + version-download). → D-05, D-06, D-13, D-14.
- **`2026-06-20-fuse-inode-stable-id-identity-reset.md`** — sync-correctness identity reset
  on display-name fallback. → D-11.
- **`2026-06-21-zeroize-fuse-metadata-publish-key-params.md`** — zeroize the one remaining
  plain-`Vec<u8>` publish helper. → D-12.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase scope (folded todos — file/line-level fix directions)

- `.planning/todos/2026-06-21-fuse-ipns-robustness-findings-from-pr538-review.md` — 8 findings, base line refs
- `.planning/todos/2026-06-21-pr538-second-coderabbit-pass-preexisting-findings.md` — 6 findings, base line refs
- `.planning/todos/2026-06-20-fuse-inode-stable-id-identity-reset.md` — inode identity reset direction (with CodeRabbit's proposed Rust shape)
- `.planning/todos/2026-06-21-zeroize-fuse-metadata-publish-key-params.md` — verified single-helper scope + call-site caution

### Durability substrate (build on, do not reinvent)

- `crates/fuse/src/replay.rs` — existing crash-recovery replay path; Conflict/key-absent handling already present (~441, 557, 639). The journal-on-exhaustion (D-01) integrates here.
- `crates/fuse/src/metadata.rs` §136-214 — the **correct** folder re-resolve+retry loop that D-03's shared helper generalizes
- `.planning/phases/43-*/`, `.planning/phases/45-*/`, `.planning/phases/46-*/` SUMMARYs — the persisted out-of-callback journal + replay model (Phase 43 introduced, 45 hardened, 46 closed data-loss bugs)
- `.planning/phases/55-*/` SUMMARYs — the post-refactor module layout these findings live in (HARD-06 no-behavior-change contract context)

### Project docs

- `docs/FILESYSTEM_SPECIFICATION.md` — encrypted filesystem, IPFS/IPNS metadata, per-file IPNS split
- `docs/METADATA_SCHEMAS.md` — FilePointer / FileMetadata / folder metadata shapes
- `CLAUDE.md` — terminology + security rules (zeroization, ECIES, AES-256-GCM)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- **`metadata.rs` folder publish retry loop (§136-214):** already does re-resolve + retry
  correctly ("Conflict resolved for {} after retry"). Extract this into the shared
  `publish_with_cas_retry` helper (D-03) rather than writing a new one.
- **Phase 43/46 persisted journal + `replay.rs`:** the durable-on-exhaustion target for
  D-01. No new persistence mechanism needed.
- **`Zeroizing<Vec<u8>>` already used** by `spawn_bin_entry_publish`,
  `spawn_file_meta_reencrypt`, and `events.rs` `spawn_metadata_refresh` — D-12 brings
  `spawn_metadata_publish` into line with the established pattern.

### Established Patterns

- **Zeroization ownership rule (CRITICAL):** a callee that receives a caller-owned or
  reused buffer **must NOT zero it** — only the terminal owner zeroes. Wrapping a param in
  `Zeroizing<Vec<u8>>` transfers ownership to the callee (zeroes on drop), safe only if the
  caller actually transfers ownership and does not reuse the buffer. The
  `createAndPublishIpnsRecord` regression broke 48/89 SDK E2E by zeroing a reused
  `publicKey`. Audit every D-12 / D-13 call site before changing types.
- **macOS/Windows lockstep (D-15):** parallel implementations in `crates/fuse/src/` (macOS
  via `fuser`) and `crates/fuse/src/platform/windows/` (winfsp). Conflict handling already
  duplicated across `mkdir.rs` and `platform/windows/write_ops.rs`.
- **winfsp is CI-only on macOS:** local `cargo` never compiles `windows/*` (`#[cfg(winfsp)]`).
  The `Cargo Check & Test (Windows)` CI gate is authoritative — budget a CI round-trip for
  any winfsp-side change.

### Integration Points

- New shared helper lives in `crates/fuse` and is called from `content_ops.rs`,
  `metadata.rs` (bin + folder). It calls `cipherbox_api_client` publish + resolve and, on
  exhaustion, the journal enqueue path used by `fs.rs`/`replay.rs`.
- sdk-core changes (`folder/load.ts`, `folder/registration.ts`) are TS-side and do **not**
  require `pnpm api:generate` (no API DTO/controller changes).

</code_context>

<specifics>
## Specific Ideas

- The folder retry loop in `metadata.rs:136-214` is the explicit reference implementation
  for the extracted helper — "make per-file/bin behave like folder already does."
- "No durability decision left to a swallowed warning" is the acceptance lens: every
  `Conflict`/error arm must either retry, journal, or return an errno — never warn-and-ack.

</specifics>

<deferred>
## Deferred Ideas

- **Consolidating mkdir's `MkdirConflict` event-channel re-arm** into the shared CAS helper —
  larger refactor, intentionally excluded (D-04). Revisit if a future durability bug spans
  both mechanisms.

### Reviewed Todos (not folded)

- `2026-06-20-ipns-resolve-verify-coverage-and-web-sdk-dedup.md` — IPNS signature-verify
  chokepoint + web/sdk-core resolve dedup → **Phase 58** scope (IPNS Signature-Verify
  Coverage), not 56. High keyword overlap is a false positive.
- `2026-06-21-large-file-refactor-tier3-residue.md` — remaining Tier-3 large-file refactor
  candidates → separate refactor track, not this hardening pass.
- API/unpin todos (`extract-leaf-ipfs-provider-module`, `extract-withcidlock-...`,
  `local-provider-unescaped-cid-...`, `register-cid-dto-validation-...`) → **Phase 57**
  (API CID and Provider Hardening) scope.

</deferred>

---

_Phase: 56-fuse-and-ipns-durability-hardening_
_Context gathered: 2026-06-22_
