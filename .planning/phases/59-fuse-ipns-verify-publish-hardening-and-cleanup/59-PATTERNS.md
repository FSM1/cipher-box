# Phase 59: FUSE IPNS Verify/Publish Hardening and Cleanup - Pattern Map

**Mapped:** 2026-06-23
**Files analyzed:** 8 modified Rust files + 2 TS files (E.4)
**Analogs found:** 8 / 8 (all are sibling patterns within the same crate)

---

## File Classification

| Modified File                              | Role     | Data Flow        | Closest Analog / Reference              | Match Quality |
| ------------------------------------------ | -------- | ---------------- | --------------------------------------- | ------------- |
| `crates/fuse/src/fs.rs`                    | utility  | CRUD             | Sibling Folder branch, fs.rs:153-157    | exact         |
| `crates/fuse/src/inode.rs`                 | cache    | CRUD             | Folder D-11 gate, inode.rs:400/468      | exact         |
| `crates/fuse/src/verify.rs`                | utility  | request-response | bind_verified unit tests, verify.rs:258 | exact         |
| `crates/fuse/src/events.rs`                | handler  | event-driven     | events.rs:92-116 Legacy arm             | exact         |
| `crates/fuse/src/metadata.rs`              | service  | CRUD             | metadata.rs:197-207 dead branch body    | exact         |
| `crates/fuse/src/content_ops.rs`           | service  | CRUD             | content_ops.rs:172-246 first/update split | exact       |
| `crates/fuse/src/publish.rs`               | utility  | CRUD             | publish.rs:13-27 + tests:240-277        | exact         |
| `crates/fuse/src/replay.rs`                | service  | CRUD             | replay.rs first-publish seq site (~630) | exact         |
| `scripts/gen-ipns-verify-vectors.ts`       | test-gen | batch            | existing vector push calls              | exact         |

---

## Pattern Assignments

### Finding A — `crates/fuse/src/fs.rs` (File-branch key-wrap error swallowed)

**Symbol:** `build_folder_metadata` (inherent method on `CipherBoxFS`), `InodeKind::File` arm
**Current broken code (fs.rs:222-230):**

```rust
let ipns_key_encrypted = if let Some(h) = file_ipns_key_encrypted_hex {
    Some(h.clone())
} else if let Some(key) = file_ipns_private_key {
    cipherbox_crypto::wrap_key(key, &self.public_key)
        .ok()                                        // BUG: swallows Err
        .map(|w| hex::encode(&w))
} else {
    None
};
```

**Reference analog — sibling Folder branch (fs.rs:153-157):**

```rust
let ipns_key_encrypted = if let Some(key) = child_ipns_key {
    hex::encode(
        cipherbox_crypto::wrap_key(key, &self.public_key)
            .map_err(|e| format!("Wrap IPNS key: {}", e))?,  // propagates via ?
    )
} else {
    String::new()
};
```

**Fix pattern:** Replace `.ok().map(|w| hex::encode(&w))` with `.map_err(|e| format!("Wrap IPNS key: {}", e)).map(|w| hex::encode(&w))` and add `?` to propagate. The containing function `build_folder_metadata` returns `Result<(...), String>` so `?` is valid. Note the return type of the `else if` arm becomes `Result<Option<String>, String>` — the whole `let ipns_key_encrypted = ...` block must propagate via `?`.

**Test seam:** No existing test for this path — Wave 0 must add:
```rust
fn build_folder_metadata_wrap_key_error_propagates_as_err() { ... }
```

**winfsp gate required:** YES — `build_folder_metadata` is compiled under `#[cfg(any(feature = "fuse", feature = "winfsp"))]`. `cargo check -p cipherbox-fuse --features winfsp` must pass.

---

### Finding B — `crates/fuse/src/inode.rs` (File-side re-resolution on `file_meta_ipns_name` change)

**Symbol:** File-pointer refresh logic in `upsert_children`, `InodeKind::File { file_meta_resolved: true }` arm
**Current gap (inode.rs:560-593):**

```rust
let (was_resolved, existing_kind) = if let Some(existing) =
    existing_ino.and_then(|ino| self.inodes.get(&ino))
{
    match &existing.kind {
        InodeKind::File {
            file_meta_resolved: true,
            ..
        } => {
            if modified != existing.attr.mtime {
                // Force re-resolution on mtime change
                (true, None)
            } else {
                // BUG: keeps stale data even when file_meta_ipns_name changed
                (true, Some(existing.kind.clone()))
            }
        }
        _ => (false, None),
    }
} else {
    (false, None)
};
```

**Reference analog — Folder D-11 gate (inode.rs:400 and 468):**

```rust
// Line 400: folder identity check via stable IPNS name
let matched_by_stable_id = ipns_to_ino.contains_key(&folder.ipns_name);

// Line 468: only preserve children/loaded-state when matched by stable IPNS id
let (existing_children, was_loaded) = if existing_ino.is_some() && matched_by_stable_id {
    // preserve
} else {
    // reset — identity changed
};
```

**Fix pattern:** In the `modified == mtime` else-arm, additionally check whether `file_pointer.file_meta_ipns_name` differs from the existing inode's `file_meta_ipns_name`. If different, return `(true, None)` (force re-resolution) instead of `(true, Some(existing.kind.clone()))`. The `same_pointer` computation at inode.rs:614-615 can be hoisted or re-computed inline:

```rust
} else {
    // Check pointer identity even when mtime is unchanged (different IPNS name = different file)
    let same_pointer = match &existing.kind {
        InodeKind::File { file_meta_ipns_name, .. } =>
            file_meta_ipns_name.as_deref() == Some(file_pointer.file_meta_ipns_name.as_str()),
        _ => false,
    };
    if same_pointer {
        (true, Some(existing.kind.clone()))
    } else {
        log::info!("File '{}': file_meta_ipns_name changed (pointer replaced), marking for re-resolution", file_pointer.name);
        (true, None)
    }
}
```

**Test seam:** No existing test — Wave 0 must add:
```rust
fn upsert_children_file_same_mtime_different_ipns_name_marks_unresolved() { ... }
```

**winfsp gate required:** YES — same `#[cfg(any(...))]` gate. Fix is in shared code (not in `platform/`), so both macOS and Windows paths are affected.

---

### Finding C — `crates/fuse/src/verify.rs` + 6 match-arm files (`VerifyError::Legacy` carry)

**Symbol:** `VerifyError` enum (verify.rs:18-27); `bind_verified` (verify.rs:62); all `Legacy` match arms

**Current variant (verify.rs:23):**

```rust
pub enum VerifyError {
    Api(cipherbox_api_client::error::ApiError),
    Legacy,           // unit variant — drops the already-resolved response
    Invalid(String),
}
```

**Target variant shape:**

```rust
pub enum VerifyError {
    Api(cipherbox_api_client::error::ApiError),
    Legacy { cid: String, sequence_number: String },  // carry the resolved response
    Invalid(String),
}
```

**Reference — bind_verified site (verify.rs:67):**

```rust
// Current:
None => Err(VerifyError::Legacy),

// Target:
None => Err(VerifyError::Legacy {
    cid: resp.cid.clone(),
    sequence_number: resp.sequence_number.clone(),
}),
```

**Reference — Display impl (verify.rs:33):**

```rust
// Current:
Self::Legacy => write!(f, "legacy record: all signature fields absent"),

// Target:
Self::Legacy { cid, sequence_number } =>
    write!(f, "legacy record: all signature fields absent (cid={cid}, seq={sequence_number})"),
```

**All 6 match-arm sites that must be updated (second `resolve_ipns` call replaced by carried fields):**

| File | Line | Pattern to replace |
| ---- | ---- | ------------------ |
| `publish.rs` | ~107 | `Legacy` → second `resolve_ipns` for seq |
| `publish.rs` | ~191 | `Legacy` → second `resolve_ipns` for seq |
| `events.rs` | ~100-107 | `Legacy` → second `resolve_ipns` + synthetic `VerifiedResolve { signature_verified: false }` |
| `metadata.rs` | ~330-341 | `Legacy` → second `resolve_ipns` for cid |
| `replay.rs` | ~344-349 | `Legacy` → second `resolve_ipns` for cid |
| `replay.rs` | ~471-478 | `Legacy` → second `resolve_ipns` for cid |

**Example current arm to replace (events.rs:92-108):**

```rust
Err(crate::verify::VerifyError::Legacy) => {
    log::warn!("...");
    let raw = cipherbox_api_client::ipns::resolve_ipns(&api, &ipns_name)
        .await
        .map_err(|e| format!("resolve fallback: {}", e))?;
    crate::verify::VerifiedResolve {
        cid: raw.cid,
        sequence_number: raw.sequence_number.parse().unwrap_or(0),
        signature_verified: false,
    }
}
```

**Target arm shape:**

```rust
Err(crate::verify::VerifyError::Legacy { cid, sequence_number }) => {
    log::warn!("...");
    crate::verify::VerifiedResolve {
        cid,
        sequence_number: sequence_number.parse().unwrap_or(0),
        // signature_verified field removed after Finding E.1
    }
}
```

**Test seam — extend existing (verify.rs:258):**

```rust
fn bind_verified_legacy_returns_legacy() {
    // Must be extended to assert Legacy { cid, sequence_number } carries the correct values
}
```

**Critical:** This is a multi-file enum shape change. Run `cargo check` immediately after changing the variant — Rust will emit `patterns not covered` for each unupdated arm.

---

### Finding D.1 — `crates/fuse/src/metadata.rs` (dead `journal_entry` branch body)

**Symbol:** `publish_with_cas_retry`, dead branch at metadata.rs:197-207

**Current dead code (metadata.rs:197-207):**

```rust
if journal_entry.is_some() {
    // Both arms return identical Err — the `if` is unreachable (all call sites pass None)
    Err(format!("persistent conflict for {}", ipns_name))
} else {
    Err(format!("persistent conflict for {}", ipns_name))
}
```

**Fix pattern:** Collapse to single arm, keep param with TODO:

```rust
// D-01a: journal_entry param reserved for future journal-enqueue path.
// All current call sites pass None; collapse identical arms.
Err(format!("persistent conflict for {}", ipns_name))
```

**Test seam — existing (metadata.rs:976):**

```rust
fn publish_with_cas_retry_persistent_conflict_journal_none_returns_err() {
    // Tests the Err path; still valid after branch collapse
}
```

---

### Finding D.2 — `crates/fuse/src/content_ops.rs` (dead `record_b64` in update branch)

**Symbol:** `publish_file_metadata`, outer `record_b64` binding at content_ops.rs:134

**Current (record built before branch, unused in update path):**

```rust
// content_ops.rs:128-134
let record = cipherbox_core::ipns::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)...;
let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)...;
let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);

if is_first_publish {
    // record_b64 used here
} else {
    // record_b64 UNUSED — closure in publish_with_cas_retry re-signs independently
}
```

**Fix pattern:** Move `record =`, `marshaled =`, `record_b64 =` inside `if is_first_publish { }`. Keep outer bindings `ipns_key_arr`, `new_seq`, `value` — both branches need them.

```rust
if is_first_publish {
    let record = cipherbox_core::ipns::create_ipns_record(&ipns_key_arr, &value, new_seq, 86_400_000)...;
    let marshaled = cipherbox_core::ipns::marshal_ipns_record(&record)...;
    let record_b64 = base64::engine::general_purpose::STANDARD.encode(&marshaled);
    // ... IpnsPublishRequest { record: record_b64, ... }
} else {
    // update path — closure re-signs; record_b64 from outer scope gone
}
```

**Pitfall:** `ipns_key_arr` is moved into the closure in the `else` branch. Keep it outside the `if`. Only move the signing/encoding steps.

**Test seam:** `cargo test -p cipherbox-fuse --features fuse publish_file_metadata` (existing tests cover both branches via compile).

---

### Finding D.3 — `crates/fuse/src/content_ops.rs` (dead `current_seq_for_cas` binding)

**Symbol:** `publish_file_metadata`, update branch at content_ops.rs:202-246

**Current dead binding:**

```rust
let current_seq_for_cas = current_seq
    .ok_or_else(|| "resolve_sequence returned None for update publish".to_string())?;
// ... 14-line NOTE comment ...
let _ = current_seq_for_cas; // suppress unused-variable warning
```

**Fix pattern:** Replace with a direct guard, delete the `let _ =` discard and the NOTE comment:

```rust
if current_seq.is_none() {
    return Err("resolve_sequence returned None for update publish".to_string());
}
```

Error message text is preserved; existing test assertion on this path remains valid.

---

### Finding E.1 — `crates/fuse/src/verify.rs` (dead `signature_verified` field)

**Symbol:** `VerifiedResolve::signature_verified` (verify.rs:47)

**Current struct (verify.rs:41-48):**

```rust
pub struct VerifiedResolve {
    pub cid: String,
    pub sequence_number: u64,
    pub signature_verified: bool,   // written in two places; never read by any FUSE call site
}
```

**Fix:** Remove the field. The two write sites to remove:
- `verify.rs:132`: `signature_verified: true` in `bind_verified` success arm
- `events.rs:106`: `signature_verified: false` in the legacy synthetic struct (this whole block is eliminated by Finding C anyway — implement C first)

**Ordering constraint:** Implement Finding C before E.1. After C, the `events.rs` synthetic `VerifiedResolve { signature_verified: false }` block is eliminated entirely. E.1 then only removes the field and updates two `verify.rs` unit test assertions.

**Test seam:**

```rust
// verify.rs:200 — remove `assert_eq!(result.signature_verified, true)` lines after field removal
fn bind_verified_valid_returns_ok_with_embedded_cid() { ... }
fn bind_verified_legacy_returns_legacy() { ... }
```

---

### Finding E.2 — `crates/fuse/src/metadata.rs` (misleading test string)

**Symbol:** `is_ipns_not_found` unit test at metadata.rs:1168

**Current test (metadata.rs:~1170):**

```rust
assert!(super::is_ipns_not_found("404 not found"));
// Passes because "not found" is in the string — "404" alone does NOT match
```

**Fix pattern:** Rename the string to make intent legible, and add a negative assertion:

```rust
assert!(super::is_ipns_not_found("record not found"));
assert!(!super::is_ipns_not_found("404"),
    "bare '404' without 'not found' must not match is_ipns_not_found");
```

**Test seam (existing):**

```rust
fn is_ipns_not_found_matches_case_insensitively() { ... }  // metadata.rs:1168
fn is_ipns_not_found_rejects_other_errors() { ... }        // metadata.rs:1174
```

---

### Finding E.4 — `scripts/gen-ipns-verify-vectors.ts` + `tests/vectors/ipns/verify.json`

**Symbol:** Generator interface type and all `vectors.push(...)` calls (~7 sites)

**Fix pattern:**
1. Remove `public_key: string; private_key: string` from the generator interface type (~line 92).
2. Remove all 7 `public_key: bytesToHex(...) / private_key: PRIMARY_PRIV_KEY_HEX` lines from `vectors.push(...)` calls.
3. Re-run: `npx tsx scripts/gen-ipns-verify-vectors.ts` to regenerate `tests/vectors/ipns/verify.json`.

No Rust changes needed — the Rust struct `IpnsVerifyVector` never had these fields.

**Test seam:**

```rust
// crates/fuse/tests/ipns_verify_vectors.rs
// Run: cargo test -p cipherbox-fuse --features fuse ipns_verify
```

---

### Finding F — `crates/fuse/src/publish.rs` + `replay.rs` + `verify.rs` (first-publish sequence convention)

**Symbol:** `next_file_publish_sequence` (publish.rs:13-27), first-publish site in `replay.rs:~630`, skew allowance in `verify.rs:111`

**Current (publish.rs:17):**

```rust
pub fn next_file_publish_sequence(is_first_publish: bool, ...) -> Result<u64, String> {
    if is_first_publish {
        return Ok(0);   // FUSE embeds 0; SDK embeds 1
    }
    ...
}
```

**Fix — publish.rs:17:**

```rust
if is_first_publish {
    return Ok(1);   // unify with SDK first-publish convention
}
```

**Fix — replay.rs:~630:** Change `create_ipns_record(&ipns_key_arr, &value, 0, ...)` to use `1` for the child-folder first-publish path. (Use grep `create_ipns_record(.*0` in `crates/fuse/src/` to find all sites.)

**Fix — verify.rs:111:** Remove the skew allowance clause:

```rust
// Current:
let seq_ok = embedded_seq == resp_seq || (resp_seq == 1 && embedded_seq == 0);

// After fix:
let seq_ok = embedded_seq == resp_seq;
```

**Test seam — existing tests to update (publish.rs:240-243):**

```rust
fn next_file_publish_sequence_starts_new_records_at_zero() {
    assert_eq!(next_file_publish_sequence(true, None).unwrap(), 0);    // update to 1
    assert_eq!(next_file_publish_sequence(true, Some(99)).unwrap(), 0); // update to 1
}
```

Also update or remove the skew vector test in `crates/fuse/tests/ipns_verify_vectors.rs` (test case 8 per research).

**winfsp gate required:** YES (verify.rs / publish.rs are compiled under both feature sets).

---

## Shared Patterns

### Error Propagation via `?` in `Result<_, String>` functions

**Source:** `crates/fuse/src/fs.rs:156` (Folder branch), `inode.rs:438-440`, throughout `content_ops.rs`
**Apply to:** Finding A fix — File branch must use `.map_err(|e| format!("Wrap IPNS key: {}", e))?`

```rust
// Pattern used throughout crate for Result<_, String> propagation:
some_operation()
    .map_err(|e| format!("Descriptive context: {}", e))?
```

### `#[cfg(any(feature = "fuse", feature = "winfsp"))]` gate

**Source:** Every pub(crate) function in `metadata.rs`, `content_ops.rs`, `events.rs`
**Apply to:** Any new test functions or refactored code in these files must preserve cfg gates.

### Cargo check as compile gate for enum migrations

**Apply to:** Finding C — after changing `VerifyError::Legacy` shape, immediately run:
```bash
cargo check -p cipherbox-fuse --features fuse
cargo check -p cipherbox-fuse --features winfsp
```
Both must succeed before proceeding.

---

## No Analog Found

None — all findings have concrete sibling reference patterns within the same crate.

---

## winfsp CI Gate Summary

These findings touch code compiled under `#[cfg(any(feature = "fuse", feature = "winfsp"))]` and require a Windows CI round-trip before merge:

| Finding | File | Reason |
| ------- | ---- | ------ |
| A | `fs.rs` | `build_folder_metadata` compiled for both feature sets |
| B | `inode.rs` | `upsert_children` compiled for both feature sets |
| C | `verify.rs` + 5 files | Enum shape change affects all arms under both features |
| F | `publish.rs`, `replay.rs`, `verify.rs` | Sequence convention shared across both feature sets |

Command: `cargo check -p cipherbox-fuse --features winfsp` (macOS gate for type errors) + `Cargo Check & Test (Windows)` CI workflow (authoritative for Windows-specific code paths).

---

## Metadata

**Analog search scope:** `crates/fuse/src/` (sibling files only — all findings are intra-crate)
**Files scanned:** 8 source files (the 8 modified `crates/fuse/src/` files; the cross-language vector test under `tests/` and the 2 TS/JSON fixtures are out of the `src/` analog scope)
**Pattern extraction date:** 2026-06-23
