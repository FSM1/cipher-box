# Phase 59: FUSE IPNS Verify/Publish Hardening and Cleanup — Research

**Researched:** 2026-06-23
**Domain:** Rust FUSE crate (`crates/fuse/src/`) — IPNS publish/verify/CAS paths
**Confidence:** HIGH

---

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                                                                                                                                                                                                                                                                                                                       | Research Support                                                                                                               |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| HARD-10 | FUSE IPNS verify/publish hardening & cleanup — propagate residual swallowed file IPNS key-wrap error, trigger file re-resolution on changed `file_meta_ipns_name`, carry legacy IPNS response in `VerifyError::Legacy`, drop dead `journal_entry` param + content_ops dead bindings, unify first-publish embedded-sequence convention (FUSE vs SDK) with TEE re-sign verification (Phase 59 scope) | All six findings verified against current `main` code; exact file/line locations, reproduction status, and fix paths documented below |

</phase_requirements>

---

## Summary

Phase 59 is a Rust-only hardening and cleanup pass on the `crates/fuse` crate. There is no
CONTEXT.md; the six todo writeups are the locked spec. All six findings were verified against
current `main` code — line numbers have drifted since the todos were written because Phase 58
refactored the same files.

**Two findings are behavioral (durability-critical):**

- Finding A (`fs.rs` file-branch key-wrap error swallowed) — **still reproduces**. A
  `wrap_key(...).ok()` at `fs.rs:225-226` silently drops a key-wrap error and publishes a
  `FilePointer` with `ipns_private_key_encrypted: None`. The TEE republish path would later fail
  silently for that file. The sibling Folder branch at `fs.rs:153-157` already propagates via
  `map_err(|e| format!("Wrap IPNS key: {}", e))?`; the File branch must mirror it.

- Finding B (`inode.rs` file-side re-resolution trigger) — **partially implemented, gap
  remains**. The folder side (D-11) was fixed in PR #543 (lines 400 and 468). The file side
  already compares `file_meta_ipns_name` to detect pointer identity at `inode.rs:614-615`
  (`same_pointer`), but the entry point logic at `inode.rs:562-589` only re-triggers resolution
  when `modified != existing.attr.mtime`. A file whose `modified_at` is unchanged but whose
  `file_meta_ipns_name` changed (different pointer, same timestamp) keeps stale CID/keys. The fix
  is to also reset to unresolved when `same_pointer == false`, mirroring the folder D-11 gate.

**Four findings are low-risk cleanups (no behavioral change):**

- Finding C (`VerifyError::Legacy` carry the raw response) — second `resolve_ipns` call
  redundancy; structural refactor, not a correctness break.
- Finding D (dead `journal_entry` param + content_ops dead bindings) — confirmed dead by
  reading every call site.
- Finding E (Phase 58 minor simplify/cleanup: dead `signature_verified` field, misleading test
  string, dead `journal_entry` branch body, unused vector fixture fields).
- Finding F (first-publish embedded-sequence convention: FUSE embeds 0, SDK embeds 1) — the
  TEE re-sign path does **not** go through `upsertFolderIpns` and therefore bypasses the
  embedded-sequence gate entirely, so the `Rollback rejected` risk is **not present** on the
  TEE path. The todo's concern is valid only if a FUSE-first-published record were re-submitted
  through the standard `upsertFolderIpns` gate — which only happens if the TEE ever calls that
  path. Confirmed it does not: `republish.service.ts` calls `publishSignedRecord` →
  `delegatedRouting.publish` directly, then `syncFolderIpnsSequence` via a direct repository
  `update` bypassing the gate. The durability risk in the todo is therefore speculative. The
  recommended action remains: unify FUSE first-publish to embed 1 (matching SDK + API comment
  at `ipns.service.ts:357`) so the hotfix skew allowance in `verify.rs:111` can be removed.

**Primary recommendation:** Implement the two behavioral fixes (A, B) first as independent
tasks with unit-test cover; then chain the cleanup tasks (C, D, E, F) in a single wave.

---

## Architectural Responsibility Map

| Capability                              | Primary Tier       | Secondary Tier          | Rationale                                                                        |
| --------------------------------------- | ------------------ | ----------------------- | -------------------------------------------------------------------------------- |
| FilePointer key-wrap error propagation  | FUSE crate (Rust)  | —                       | Lives in `fs.rs::build_folder_metadata`, purely client-side key material handling |
| Inode file re-resolution trigger        | FUSE crate (Rust)  | —                       | Cache-coherency in `inode.rs::upsert_children`, no server interaction            |
| `VerifyError::Legacy` response carry    | FUSE crate (Rust)  | —                       | Enum variant + all ~8 match arms in verify/events/fs/publish/metadata/replay.rs  |
| Dead param / dead binding cleanup       | FUSE crate (Rust)  | —                       | `metadata.rs`, `content_ops.rs` — zero behavior change                          |
| Phase 58 simplify/cleanup               | FUSE crate (Rust)  | Test vector scripts (TS) | `verify.rs`, `events.rs`, `metadata.rs`, vector fixture + generator              |
| First-publish sequence convention       | FUSE crate (Rust)  | API (TS) / SDK (TS)     | `publish.rs` (FUSE) + `file/index.ts` (SDK) + `verify.rs` skew allowance removal |
| TEE re-sign path verification           | API tier (TS)      | —                       | `republish.service.ts` bypasses `upsertFolderIpns`; analysis only, no code change |

---

## Standard Stack

No new dependencies. This phase modifies existing Rust source only (plus minor TS in test
vector generator). The existing crate dependency graph is unchanged.

### Existing Crates Used (no version changes needed)

| Crate              | Role                          | Where Used                                 |
| ------------------ | ----------------------------- | ------------------------------------------ |
| `cipherbox_crypto` | `wrap_key`, `ecies::wrap_key` | `fs.rs` key-wrap (Finding A)               |
| `cipherbox_core`   | IPNS record creation / CBOR   | `content_ops.rs`, `replay.rs`, `verify.rs` |
| `zeroize`          | Zeroizing key material        | Throughout `metadata.rs`, `fs.rs`          |

---

## Finding-by-Finding Analysis

### Finding A — `fs.rs` File-Branch Key-Wrap Error Swallowed

**Status: REPRODUCES on current `main`.**

**File:** `crates/fuse/src/fs.rs`
**Current lines:** 222–230 (inside `build_folder_metadata`, `InodeKind::File` arm)
**Symbol:** `build_folder_metadata` (inherent method on `CipherBoxFS`)

**Current code (lines 222–230):**

```rust
// [ASSUMED] line numbers exact as of 2026-06-23 HEAD
let ipns_key_encrypted = if let Some(h) = file_ipns_key_encrypted_hex {
    Some(h.clone())
} else if let Some(key) = file_ipns_private_key {
    cipherbox_crypto::wrap_key(key, &self.public_key)
        .ok()                                        // <-- swallows the error
        .map(|w| hex::encode(&w))
} else {
    None
};
```

The `.ok()` converts an `Err` from `wrap_key` into `None`, which flows into
`ipns_private_key_encrypted: None` on the serialized `FilePointer`. The caller never learns
the key-wrap failed and a FilePointer is published that cannot be TEE-republished.

**Reference (sibling Folder branch, lines 153–157):**

```rust
let ipns_key_encrypted = if let Some(key) = child_ipns_key {
    hex::encode(
        cipherbox_crypto::wrap_key(key, &self.public_key)
            .map_err(|e| format!("Wrap IPNS key: {}", e))?,  // propagates
    )
} else {
    String::new()
};
```

**Fix:** Replace `.ok().map(|w| hex::encode(&w))` with
`.map_err(|e| format!("Wrap IPNS key: {}", e)).map(|w| hex::encode(&w))` and
propagate via `?`. The containing function `build_folder_metadata` already returns
`Result<(...), String>`, so `?` works.

Note: the return type differs slightly (Folder branch returns `String`, File branch
returns `Option<String>`). Correct approach: propagate as `Err` so the whole
`build_folder_metadata` call fails, consistent with the Folder branch.

**Impact of non-fix:** TEE republish fails silently for files published after a key-wrap
error. The file remains accessible (CID is written) but cannot be republished by the TEE.

**winfsp:** `build_folder_metadata` is in `fs.rs` under `#[cfg(any(feature = "fuse", feature = "winfsp"))]`. Both feature sets are affected. Windows CI gate required.

---

### Finding B — `inode.rs` File-Side Re-Resolution on `file_meta_ipns_name` Change

**Status: GAP CONFIRMED on current `main`.**

**File:** `crates/fuse/src/inode.rs`
**Current lines:** ~562–643 (file arm in `upsert_children` or equivalent refresh loop)
**Symbol:** file-pointer refresh logic in `InodeTable` (the same function that processes `FolderChild::File`)

**What the todo said (lines ~574):** "file-side inode re-resolution must also trigger on a
changed `file_meta_ipns_name`"

**What current code does (lines ~562–589):**

```rust
let (was_resolved, existing_kind) = if let Some(existing) = existing_ino... {
    match &existing.kind {
        InodeKind::File { file_meta_resolved: true, .. } => {
            if modified != existing.attr.mtime {
                // Force re-resolution
                (true, None)
            } else {
                (true, Some(existing.kind.clone()))   // keeps stale data
            }
        }
        _ => (false, None),
    }
} else { (false, None) };
```

**What it does when `file_meta_ipns_name` changed but `modified_at` is unchanged:**
The `else` branch at line ~586 returns `(true, Some(existing.kind.clone()))`, which preserves
the old CID / encryption keys — even though `same_pointer` (computed later at ~614) is `false`.

**Gap:** The `same_pointer` check is done in the later `kind =` block (lines ~598+), but by
that point the decision to return the old kind has already been made by the `was_resolved` /
`existing_kind` block above.

**Fix direction:** In the `file_meta_resolved: true` arm, also check whether the incoming
`file_pointer.file_meta_ipns_name` differs from the existing inode's `file_meta_ipns_name`.
If different, treat it like a `modified_at` change — return `(true, None)` to force
re-resolution. The existing `same_pointer` variable in the later block can be hoisted or
re-computed here.

**winfsp:** Same `#[cfg(any(...))]` gate; Windows CI gate required. The fix must keep
macOS and Windows paths in lockstep — the file refresh logic is shared (not in `platform/`).

---

### Finding C — `VerifyError::Legacy` Carry the Raw Response

**Status: CONFIRMS on current `main`.**

**File:** `crates/fuse/src/verify.rs`, plus match arms in `events.rs`, `fs.rs`, `publish.rs`, `metadata.rs`, `replay.rs`
**Symbol:** `VerifyError::Legacy` enum variant (line 23 in `verify.rs`)

**Current state (verify.rs:23):**

```rust
pub enum VerifyError {
    Api(cipherbox_api_client::error::ApiError),
    Legacy,           // <-- unit variant, drops the resolved response
    Invalid(String),
}
```

**All `VerifyError::Legacy` arm sites (confirmed by grep across all 6 files):**

Each site does a second `resolve_ipns` call to recover the CID/sequence it already held:

- `publish.rs:107` — `resolve_ipns_verified` → `Legacy` → second `resolve_ipns` for seq
- `publish.rs:191` — `resolve_sequence_strict` → `Legacy` → second `resolve_ipns` for seq
- `events.rs:100-107` — `spawn_metadata_refresh` → `Legacy` → second `resolve_ipns` for cid + synthetic `VerifiedResolve { signature_verified: false }`
- `metadata.rs:330-341` — folder CAS conflict arm → `Legacy` → second `resolve_ipns` for cid
- `replay.rs:344-349` — `resolve_folder_key` → `Legacy` → second `resolve_ipns` for cid
- `replay.rs:471-478` — `fetch_merge_publish_parent` → `Legacy` → second `resolve_ipns` for cid

**Fix:**

```rust
pub enum VerifyError {
    Api(cipherbox_api_client::error::ApiError),
    Legacy { cid: String, sequence_number: String },  // carry the resolved response
    Invalid(String),
}
```

Update `bind_verified` at line ~67:

```rust
None => Err(VerifyError::Legacy { cid: resp.cid.clone(), sequence_number: resp.sequence_number.clone() }),
```

Update `Display` impl. Replace each `Legacy` match arm's second `resolve_ipns` call with the
carried `cid` / `sequence_number`.

Also update the `events.rs` synthetic `VerifiedResolve` — the `signature_verified: false`
assignment becomes unnecessary once the legacy arm uses the carried fields directly (ties
into Finding E below).

**Real risk of race:** The todo is correct that the second `resolve_ipns` may return a
DIFFERENT record (a concurrent publish could change it in the ~1ms gap). Carrying the
response eliminates this window.

**Scope note:** This is a multi-file enum shape change. All pattern-match sites must be updated
in the same commit or the crate will not compile — confirm with `cargo check`.

---

### Finding D — Dead `journal_entry` Param + content_ops Dead Bindings

**Status: ALL THREE ITEMS CONFIRMED DEAD on current `main`.**

#### D.1 — `publish_with_cas_retry` dead `journal_entry: Option<()>` branch body

**File:** `crates/fuse/src/metadata.rs`
**Current lines:** 108 (param declaration), 197–207 (dead branch)

```rust
pub(crate) async fn publish_with_cas_retry<F>(
    ...
    journal_entry: Option<()>, // placeholder for future (queue, entry) — always None this phase
```

Lines 197–207:

```rust
if journal_entry.is_some() {
    // D-01a: future path — journal enqueue (no call site supplies Some this phase)
    // queue.put(&entry).map_err(|e| format!("journal enqueue failed: {}", e))?;
    // return Ok(());
    // For now return Err (journal_entry is always None this phase)
    Err(format!("persistent conflict for {}", ipns_name))
} else {
    // D-01a: per-file/bin path — no JournalOp::FilePublish variant; ...
    Err(format!("persistent conflict for {}", ipns_name))
}
```

Both arms return identical `Err`. The `if journal_entry.is_some()` arm is unreachable
(all call sites pass `None`). Call sites (both confirmed `None`):

- `content_ops.rs:229`: `None, // D-01a: no JournalOp::FilePublish variant; exhaustion → Err → EIO`
- `metadata.rs` (bin publish path): also passes `None`

**Fix options per todo:**
- **Option 1 (recommended):** Collapse to single `Err(format!("persistent conflict for {}", ipns_name))`,
  **keep** the `journal_entry` parameter with a TODO comment referencing D-01a deferred work.
  The test seam (`journal_entry_is_some` param in `run_publish_retry_seam`) would be simplified
  but the seam itself can remain (it covers the conflict-then-err path which is still relevant).
- **Option 2 (from the `2026-06-22-phase58-simplify-cleanup.md` todo):** Same as Option 1 —
  collapse the branch body only, keep the param.

The Phase 58 simplify cleanup todo (Finding E, item 3) independently captured this as
"Safe-now" — both todos agree on Option 1.

#### D.2 — `content_ops.rs` dead `record_b64` computed in update branch

**File:** `crates/fuse/src/content_ops.rs`
**Current lines:** ~134 (`record_b64` built unconditionally)

```rust
let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
// ...
if is_first_publish {
    let req = cipherbox_api_client::IpnsPublishRequest {
        record: record_b64,    // only used here
        ...
    };
```

The `record`, `marshaled`, and `record_b64` are built before the `if is_first_publish` branch
but only consumed inside it. The `else` (update) branch calls `publish_with_cas_retry` whose
closure re-signs independently; `record_b64` from the outer scope is unused there.

**Fix:** Move the record-build block (`record =`, `marshaled =`, `record_b64 =`) inside the
`if is_first_publish {` block. The outer `ipns_key_arr` / `new_seq` / `value` bindings are
still needed for both branches, so only move the signing/encoding steps.

#### D.3 — `content_ops.rs` `current_seq_for_cas` dead binding + `let _ =` + long NOTE

**File:** `crates/fuse/src/content_ops.rs`
**Current lines:** ~202–246

```rust
let current_seq_for_cas = current_seq
    .ok_or_else(|| "resolve_sequence returned None for update publish".to_string())?;
// ... (14-line NOTE comment)
let _ = current_seq_for_cas; // used above in comment; suppress unused-variable warning
```

The `ok_or_else(...)?` is a valid guard (returns `Err` if `current_seq` is `None` for an
update publish). But `current_seq_for_cas` itself is never used — the `publish_with_cas_retry`
helper re-resolves internally.

**Fix:** Replace with a direct guard:

```rust
if current_seq.is_none() {
    return Err("resolve_sequence returned None for update publish".to_string());
}
```

Delete the `let _ = current_seq_for_cas;` discard and the 14-line NOTE comment. The test
assertion on this error path (`T-45-05` or similar) should still pass because the error text
is preserved.

---

### Finding E — Phase 58 Minor Simplify/Cleanup

**Status: ALL FOUR ITEMS CONFIRMED SAFE on current `main`.**

#### E.1 — Dead `VerifiedResolve::signature_verified` field

**File:** `crates/fuse/src/verify.rs`
**Line:** 47

```rust
pub struct VerifiedResolve {
    pub cid: String,
    pub sequence_number: u64,
    pub signature_verified: bool,   // written true in bind_verified; never read by any FUSE site
}
```

Written in:
- `verify.rs:132` (bind_verified success arm): `signature_verified: true`
- `events.rs:106` (legacy synthetic struct): `signature_verified: false`

Read only by `verify.rs` unit tests (lines ~207, ~242). No FUSE call site reads the field.

**Fix:** Remove the field from `VerifiedResolve`, remove the `signature_verified: false`
assignment in `events.rs:106`, update (remove) the two test assertions.

Note: once Finding C (`VerifyError::Legacy` carry response) is implemented, the
`events.rs` synthetic `VerifiedResolve { signature_verified: false }` block is eliminated
entirely, so E.1 and C are complementary. Implement C first, then E.1 drops automatically.

#### E.2 — Misleading test string in `metadata.rs`

**File:** `crates/fuse/src/metadata.rs`
**Line:** ~1170

```rust
assert!(super::is_ipns_not_found("404 not found"));
```

The predicate `is_ipns_not_found` matches on `.contains("not found")` — it passes this test
only because "not found" is in the string, not because "404" alone triggers it. A standalone
"404" does NOT match.

**Fix:** Rename the test case to `"record not found"` (or add a distinct negative test
verifying `is_ipns_not_found("404")` returns `false`) to make the test's intent legible.

#### E.3 — Dead `journal_entry: Option<()>` branch body in `metadata.rs`

Same as D.1 above. The two todos independently captured the same item; treat as one fix.

#### E.4 — Unused `public_key`/`private_key` in vector fixture

**Files:** `scripts/gen-ipns-verify-vectors.ts`, `tests/vectors/ipns/verify.json`

The generator emits `public_key` and `private_key` (filler hex strings) in every
`vectors.push(...)` call (~7 sites). Neither the Rust test (`ipns_verify_vectors.rs`) nor any
other consumer reads them.

**Fix:**
1. Remove `public_key: string; private_key: string` from the generator's interface type (~line 92).
2. Remove all 7 `public_key: bytesToHex(...)` / `private_key: PRIMARY_PRIV_KEY_HEX` lines from
   `vectors.push(...)` calls.
3. Re-run `npx tsx scripts/gen-ipns-verify-vectors.ts` to regenerate `tests/vectors/ipns/verify.json`.
4. Confirm `cargo test -p cipherbox-fuse` (both feature sets) still passes.

The Rust struct `IpnsVerifyVector` in `ipns_verify_vectors.rs` has no `public_key`/`private_key`
fields (they were never deserialized), so no Rust changes needed.

---

### Finding F — First-Publish Embedded-Sequence Convention (FUSE 0 vs SDK 1)

**Status: CURRENT STATE DOCUMENTED; TEE re-sign risk CONFIRMED NOT PRESENT.**

#### Current state

| Publish path                     | First-publish embedded seq | API DB after first publish |
| -------------------------------- | -------------------------- | -------------------------- |
| Rust/FUSE (`next_file_publish_sequence(true, None)`) | **0** (`publish.rs:17`) | **1** (API stores `sequenceNumber: '1'`) |
| Rust/FUSE replay child folder (`publish_child_folder_metadata`) | **0** (`replay.rs:630`) | **1** |
| TS SDK (`file/index.ts:144-148`) | **1** (`1n`) | **1** |
| API comment (`ipns.service.ts:357`) | says "clients compute newSeq = 0n + 1n = 1n" | — |

The hotfix in `verify.rs:111` accepts `embedded=0` when `resp_seq==1` to paper over the skew.
The API `upsertFolderIpns` accepts `embeddedSeq ∈ {0n, 1n}` on first publish (line 281).

#### TEE re-sign path — does it hit the embedded-sequence gate?

**Answer: No.** The TEE republish path in `republish.service.ts` calls:

1. `teeService.republish(entries)` — TEE re-signs with the stored `latestCid` and
   increments the sequence it holds (`result.newSequenceNumber`)
2. `publishSignedRecord(entry.ipnsName, result.signedRecord)` — calls
   `delegatedRouting.publish` (IPFS delegated routing, not the CipherBox API endpoint)
3. `syncFolderIpnsSequence(...)` — calls `folderIpnsRepository.update(...)` directly,
   bypassing `upsertFolderIpns` and therefore bypassing the embedded-sequence gate

The "Rollback rejected" branch (`embeddedSeq < dbSeq`) in `upsertFolderIpns` is **never hit**
by the TEE path. The FUSE-first-published records (embedded=0, DB=1) are safe on the TEE
re-sign path.

#### Recommended action

Despite the TEE risk being absent, unifying to embed=1 on FUSE first-publish is still
worthwhile:

1. It makes the API comment at `ipns.service.ts:357` accurate for all clients.
2. It allows removing the hotfix skew allowance in `verify.rs:111` (the `resp_seq == 1 && embedded_seq == 0` branch) and its test vector (case 8).
3. It removes the synthetic `(true, Some(99))` test case in `publish.rs:243` (which documents
   that `next_file_publish_sequence(true, _)` always returns 0 regardless of input — that
   test must be updated to assert return 1 if the convention changes).

**Sites to change:**

| File | Line | Current | Change to |
| ---- | ---- | ------- | --------- |
| `crates/fuse/src/publish.rs` | 17 | `return Ok(0)` | `return Ok(1)` |
| `crates/fuse/src/replay.rs` | 630 | `create_ipns_record(&ipns_key_arr, &value, 0, ...)` | `..., 1, ...` |
| `crates/fuse/tests/ipns_verify_vectors.rs` | test skew vector | asserts skew accepted | remove or repurpose |
| `crates/fuse/src/verify.rs` | 111 | `|| (resp_seq == 1 && embedded_seq == 0)` | remove clause |
| `publish.rs` tests | 241-242 | asserts `next_file_publish_sequence(true, None) == 0` | assert `== 1` |
| `replay.rs` tests | any asserting `new_seq=0` for NotFound case | update to assert 1 |

**Phase 60 bridge:** The Phase 60 planner should note that this convention unification is a
prerequisite for the D-07 strict equality check (`embedded == DB`) desired in the
verified-resolve cache (HARD-11). Do not gate Phase 60 on this being shipped — the hotfix
skew allowance is acceptable until then — but it should land in Phase 59.

---

## Don't Hand-Roll

| Problem                       | Don't Build        | Use Instead / Pattern                                              | Why                                         |
| ----------------------------- | ------------------ | ------------------------------------------------------------------ | ------------------------------------------- |
| Enum variant shape change     | Partial migration  | Update all pattern-match sites atomically (cargo check)            | Rust compile error if any arm is incomplete |
| Dead branch body collapse     | New placeholder    | Keep param, collapse identical arms to one `Err(...)`, add TODO   | Maintains deferred D-01a seam intent        |
| IPNS sequence math            | Custom logic       | `checked_add(1).ok_or_else(...)` already in all sites             | Overflow protection already established     |

---

## Common Pitfalls

### Pitfall 1: Partial `VerifyError::Legacy` migration

**What goes wrong:** Changing the variant shape but missing one of the ~8 match arm sites.
**Why it happens:** Sites span 6 files; `grep` or IDE search can miss a cfg-gated arm.
**How to avoid:** Run `cargo check` immediately after the enum change; it will emit
`patterns not covered` for each unupdated arm. Fix all before building further.

### Pitfall 2: Moving `record_b64` inside `is_first_publish` block breaks the update path

**What goes wrong:** The `ipns_key_arr` and `value` bindings are needed by both branches.
Only move the signing/encoding steps (`create_ipns_record`, `marshal_ipns_record`, `encode`)
inside the `if is_first_publish` block. The outer `ipns_key_arr`, `new_seq`, and `value`
must remain outside.
**Warning signs:** `cargo check` emits "borrow of moved value" or "use of undeclared variable".

### Pitfall 3: Updating `publish.rs:17` to return 1 without updating the `replay.rs` seq-0 site

**What goes wrong:** `publish_child_folder_metadata` in `replay.rs` hard-codes `0` at line 630
independently of `next_file_publish_sequence`. If only one site is updated, FUSE and replay
diverge.
**How to avoid:** Grep for `create_ipns_record(.*0` in `crates/fuse/src/` and update all
first-publish sites.

### Pitfall 4: Removing `signature_verified` field before implementing Finding C

**What goes wrong:** `events.rs:106` assigns `signature_verified: false` in a synthetic
`VerifiedResolve` struct for the legacy path. Once Finding C lands, that entire synthetic
struct block is replaced by the carried `cid`/`sequence_number` from `VerifyError::Legacy`.
If E.1 is done before C, the `events.rs` synthetic struct must be updated twice.
**How to avoid:** Land Finding C first; E.1 then only requires removing the field and its test.

### Pitfall 5: Windows CI gate for behavioral fixes

**What goes wrong:** `build_folder_metadata` (Finding A) and the inode refresh logic
(Finding B) are both under `#[cfg(any(feature = "fuse", feature = "winfsp"))]`. The
`winfsp` feature cannot compile on macOS, so a type/logic error in the winfsp path is
invisible locally.
**How to avoid:** The `Cargo Check & Test (Windows)` CI gate is the authoritative validator
for the winfsp path. Any behavioral fix to `fs.rs` or `inode.rs` requires a CI round-trip
before merge. The plan must include "require Windows CI green" as an explicit verification
step for Findings A and B.

---

## Runtime State Inventory

Not applicable — this phase is a code-only change with no stored data, OS-registered state,
or build artifacts involved.

---

## Environment Availability

| Dependency  | Required By                       | Available | Version  | Fallback |
| ----------- | --------------------------------- | --------- | -------- | -------- |
| Rust/cargo  | All findings                      | Yes       | See Cargo.lock | — |
| Node / tsx  | Finding E.4 vector regen          | Yes (project standard) | — | — |
| SDK E2E (local API + redis 6380) | Verification gate | — | — | — |
| Desktop E2E | Verification gate (dispatch)      | — | — | — |

**Missing dependencies with no fallback:** SDK E2E and desktop E2E require local stack +
dispatch CI trigger. These are not blockers for code execution but are required for the
verification gate. Plan tasks accordingly.

---

## Validation Architecture

`workflow.nyquist_validation` is enabled (present and `true` in `.planning/config.json`).

### Test Framework

| Property           | Value                                                          |
| ------------------ | -------------------------------------------------------------- |
| Framework          | Rust: `cargo test` (unit); TS: project jest / vitest          |
| Config file        | `crates/fuse/Cargo.toml` (features: `fuse`, `winfsp`)         |
| Quick run command  | `cargo test -p cipherbox-fuse --features fuse`                 |
| Full suite command | `cargo test -p cipherbox-fuse --features fuse && cargo check -p cipherbox-fuse --features winfsp` |

### Phase Requirements → Test Map

| Finding | Behavior | Test Type | Automated Command | File Exists? |
| ------- | -------- | --------- | ----------------- | ------------ |
| A (fs.rs key-wrap error) | `wrap_key` failure returns `Err` from `build_folder_metadata`, not `None` in `FilePointer` | unit | `cargo test -p cipherbox-fuse --features fuse -q build_folder_metadata` | No — Wave 0 |
| B (inode.rs file re-resolution) | Inode with same `modified_at` but different `file_meta_ipns_name` is marked `file_meta_resolved: false` | unit | `cargo test -p cipherbox-fuse --features fuse -q file_meta_ipns_name` | No — Wave 0 |
| C (VerifyError::Legacy carry) | `bind_verified(resp, None).unwrap_err()` gives `VerifyError::Legacy { cid, seq }` with correct values; legacy arms use carried values (no second resolve) | unit | `cargo test -p cipherbox-fuse --features fuse verify` | Partial — extend existing `bind_verified_legacy_returns_legacy` test |
| D.1 (dead branch collapse) | `publish_with_cas_retry` persistent conflict still returns `Err` after branch collapse | unit (seam) | `cargo test -p cipherbox-fuse --features fuse publish_with_cas_retry_persistent_conflict` | Yes — `metadata.rs:976` |
| D.2 (content_ops record_b64 move) | Update path still compiles and `publish_file_metadata` update-branch behavior unchanged | compile + existing tests | `cargo test -p cipherbox-fuse --features fuse publish_file_metadata` | Yes |
| D.3 (current_seq_for_cas) | `publish_file_metadata` returns `Err` when `current_seq` is None on update | unit | `cargo test -p cipherbox-fuse --features fuse` (existing coverage) | Partial |
| E.1 (dead `signature_verified`) | Struct compiles without field; no reference sites remain | compile | `cargo check -p cipherbox-fuse --features fuse,winfsp` | — |
| E.2 (misleading test string) | `is_ipns_not_found("record not found")` passes; "404" alone fails | unit | `cargo test -p cipherbox-fuse --features fuse is_ipns_not_found` | Yes — extend |
| E.4 (unused fixture fields) | Rust vector test suite still passes after field removal | unit | `cargo test -p cipherbox-fuse --features fuse ipns_verify` | Yes |
| F (sequence convention) | `next_file_publish_sequence(true, None) == 1`; `replay.rs` child-folder seq-0 site updated to 1; verify.rs skew test removed | unit | `cargo test -p cipherbox-fuse --features fuse next_file_publish_sequence` | Yes — update `publish.rs:241` |

### Behavioral vs. Cleanup Classification

| Finding | Classification | Validation Method |
| ------- | -------------- | ----------------- |
| A | Behavioral (durability) | New unit test + SDK E2E + Windows CI |
| B | Behavioral (cache-coherency) | New unit test + desktop E2E |
| C | Behavioral (race window elimination) | Unit test update + Windows CI |
| D.1 | Pure cleanup (dead code) | Compile only + existing seam test |
| D.2 | Pure cleanup (dead code) | Compile only + existing test |
| D.3 | Pure cleanup (dead code) | Compile only + existing test |
| E.1 | Pure cleanup (dead field) | Compile only |
| E.2 | Test quality | Unit test update only |
| E.4 | Test quality | Compile + vector test |
| F | Convention (protocol) | Unit test update + SDK E2E + Windows CI |

### Sampling Rate

- **Per task commit:** `cargo test -p cipherbox-fuse --features fuse -q`
- **Per wave merge:** `cargo test -p cipherbox-fuse --features fuse && cargo check -p cipherbox-fuse --features winfsp`
- **Phase gate:** Full SDK E2E (local; redis 6380) + desktop E2E (`gh workflow run "CI E2E Tests"`) + Windows CI green

### Wave 0 Gaps

- [ ] `crates/fuse/src/fs.rs` unit test for `build_folder_metadata` key-wrap error path (Finding A)
- [ ] `crates/fuse/src/inode.rs` unit test for file re-resolution on `file_meta_ipns_name` change (Finding B)
- No new test framework install needed — existing `cargo test` infrastructure covers everything.

---

## Security Domain

| ASVS Category       | Applies | Standard Control                                                |
| ------------------- | ------- | --------------------------------------------------------------- |
| V2 Authentication   | No      | Not touched                                                     |
| V5 Input Validation | Yes     | Finding A: validate that `wrap_key` result is not silently dropped |
| V6 Cryptography     | Yes     | Finding A: `cipherbox_crypto::wrap_key` — never hand-roll; never swallow Err |

Finding A is the only security-relevant change. A silently dropped `wrap_key` error means the
user's file IPNS private key is not stored encrypted alongside the FilePointer, which breaks
the TEE republish path and could in theory expose key material in an unencrypted field. The
fix propagates the error, which is the correct secure behavior.

All other findings (B–F) are either structural (enum shape), cleanup (dead code), or
test-quality changes. They do not touch cryptographic primitives.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
| - | ----- | ------- | ------------- |
| A1 | Line numbers cited in "current lines" are accurate as of 2026-06-23 HEAD | All findings | Minor; planner must re-read source to confirm exact lines before writing tasks |
| A2 | TEE `republish.service.ts::publishSignedRecord` always calls `delegatedRouting.publish` without going through `upsertFolderIpns` | Finding F TEE analysis | If wrong, FUSE-first-published records (embedded=0, DB=1) could hit "Rollback rejected" on TEE re-sign — but this is a pre-existing risk independent of Phase 59 |
| A3 | `winfsp` operations.rs re-exports `publish_file_metadata` from `content_ops.rs` without local override | Findings A, B | Confirmed by grep: `platform/windows/operations.rs:269` re-exports directly |

**If this table is empty:** It is not; A1–A3 are assumed details the planner should verify.

---

## Open Questions

1. **Finding B exact fix scope**
   - What we know: `same_pointer` is already computed in the later `kind =` block at ~line 614; the early `(was_resolved, existing_kind)` block at ~562 does not use it.
   - What's unclear: Whether the cleanest fix is to hoist the `file_meta_ipns_name` comparison into the early block, or restructure the two-step logic into a single pass.
   - Recommendation: Hoist a simple `incoming_ipns_name != existing_inode.file_meta_ipns_name` check into the `modified == mtime` else-arm; return `(true, None)` if names differ. This is a one-line addition and avoids restructuring.

2. **Finding C: `Display` for `VerifyError::Legacy { cid, seq }`**
   - What we know: The current display is `"legacy record: all signature fields absent"`.
   - What's unclear: Whether to include the cid/seq in the display string (useful for logs) or keep it terse.
   - Recommendation: Include cid and seq: `"legacy record: all signature fields absent (cid={cid}, seq={seq})"`. This is more useful in logs and matches the `Invalid` variant's verbosity.

---

## Sources

### Primary (HIGH confidence)

- Direct code reading: `crates/fuse/src/{verify,events,metadata,content_ops,fs,inode,publish,replay}.rs` — all findings verified line-by-line against current `main`
- Direct code reading: `apps/api/src/republish/republish.service.ts` and `apps/api/src/ipns/ipns.service.ts` — TEE re-sign path analysis (Finding F)
- Direct code reading: `packages/sdk-core/src/file/index.ts` — SDK first-publish sequence (Finding F)
- Direct code reading: `crates/fuse/tests/ipns_verify_vectors.rs` and `scripts/gen-ipns-verify-vectors.ts` — Finding E.4 vector cleanup

### Secondary (MEDIUM confidence)

- `.planning/todos/pending/` six todo writeups — locked spec for all findings [ASSUMED: correctly describe pre-existing bugs; verified most against live code]

---

## Metadata

**Confidence breakdown:**

- Finding locations (A–F): HIGH — read directly from source
- TEE re-sign path analysis: HIGH — read `republish.service.ts` and `ipns.service.ts` directly
- Fix strategies: HIGH for A, B, D (mechanical); MEDIUM for C (enum migration scope)
- Test seam locations: HIGH — confirmed by reading existing test functions

**Research date:** 2026-06-23
**Valid until:** 2026-07-23 (stable domain; code will not change until Phase 59 begins)
