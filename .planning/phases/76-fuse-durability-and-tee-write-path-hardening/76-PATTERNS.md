# Phase 76: FUSE Durability and TEE Write-Path Hardening - Pattern Map

**Mapped:** 2026-07-11
**Files analyzed:** 12 (all modified, none net-new)
**Analogs found:** 11 / 12 (1 verify-only, no change expected)

This is a hardening phase — no new files. Every "analog" below is either an
already-correct sibling code path in the SAME file/crate that the fix must be
consolidated toward, or an already-shipped fix elsewhere in the codebase that
the new fix must mirror byte-for-byte in structure.

## File Classification

| Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `apps/desktop/src-tauri/src/commands/vault.rs` | tauri command (service) | request-response + CRUD (IPNS publish) | same file: `fetch_and_decrypt_vault` (ECIES-unwrap round trip) + `#[cfg(test)]` round-trip tests `~396-469` | role-match, in-file |
| `crates/fuse/src/metadata.rs` (`publish_with_cas_retry`) | utility/service | CRUD retry | same file: `spawn_metadata_publish`'s inline 5-attempt loop (`~330-385`) — to be deleted, logic merged in | exact (self-consolidation) |
| `crates/fuse/src/fs.rs` (FP-resolve loop `~594-653`) | controller/scheduler | event-driven (background refresh) | same function's existing `resolving_file_pointers.contains(&fp_ino)` dedup guards (`~612`, `~632`) | exact (in-file) |
| `crates/fuse/src/journal_helpers.rs` | utility | transform | zeroization analog: `zeroize::Zeroizing<T>` usage already established in `crates/fuse` (see Shared Patterns) | role-match |
| `crates/fuse/src/content_ops.rs` | utility | file-I/O | same zeroization analog | role-match |
| `crates/fuse/src/write_ops/implementation/mkdir.rs` | controller (FUSE op) | request-response | same zeroization analog | role-match |
| `apps/desktop/src-tauri/src/fuse/mod.rs` | provider/glue | event-driven | same zeroization analog | role-match |
| `apps/desktop/src-tauri/src/fuse/prepopulate.rs` | utility | file-I/O | verify-only — no genuine un-zeroed bare-key copy found per RESEARCH Assumption A1; re-grep before editing | none expected |
| `crates/fuse/src/platform/windows/write_ops.rs` (`~657/666`) | controller (FUSE op, Windows) | CRUD (delete/bin-capture) | **exact, already-shipped**: `crates/fuse/src/write_ops/implementation/delete.rs:180` and `:419` (Unix fix, commit c4d30e598) | exact — mirror structurally |
| `apps/api/src/republish/republish.service.ts` (`renewIpnsRecordEol`) | service | CRUD (DB write-back) | same method: the adjacent `affected === 0` branch's `logger.debug` structure (`~371-374`) — only the log level of the `catch` changes | exact (in-file) |
| `apps/tee-worker/src/services/key-manager.ts` (`decryptWithFallback`) | service | request-response | same file: existing `ReEnrollRequiredError` typed-error `instanceof` pattern | exact (in-file convention) |
| `apps/tee-worker/src/routes/republish.ts` | route (controller) | batch/request-response | none in-repo for null-entry guard; net-new defensive check, follows existing per-entry `results.push({...})` shape at `~184-201` | role-match, novel guard |
| `apps/tee-worker/src/services/ipns-signer.ts` (`renewIpnsRecord`) | service | transform (crypto signing) | `packages/crypto/src/ipns/parse-record.ts`'s `ParsedIpnsRecord` (extend additively with `validity`) + `unmarshalIPNSRecord` from `ipns` npm pkg | role-match |
| `packages/crypto/src/ipns/parse-record.ts` | utility (codec) | transform | same file's existing field-mapping pattern (`value`, `sequence`, `signatureV2`, `data`, `pubKey` at lines 11-26) | exact (additive) |

## Pattern Assignments

### `apps/desktop/src-tauri/src/commands/vault.rs` (Plan A, SC1)

**Analog:** in-file `fetch_and_decrypt_vault` (ECIES-unwrap of the key blob) and the `#[cfg(test)]` round-trip helpers at `vault.rs:396-469` (`init_recover_v3_round_trips` pattern), plus `cipherbox_api_client::ipns::resolve_ipns` / `ApiError::IpnsNotFound`.

**Critical constraint (do not deviate):** `root_read_key`/`root_write_key` are freshly minted random at `vault.rs:127-130` (`Zeroizing::new(cipherbox_crypto::utils::generate_file_key())`) — NOT deterministic. A retry must **decrypt-and-resume** from the already-published key blob via ECIES-unwrap, never re-mint.

**Preflight pattern to add** (design excerpt from RESEARCH.md, confirmed against `crates/api-client/src/ipns.rs:24-30,309`):
```rust
use cipherbox_api_client::error::ApiError;

async fn preflight_ipns_absent(
    api: &cipherbox_api_client::ApiClient,
    ipns_name: &str,
) -> Result<bool, String> {
    match cipherbox_api_client::ipns::resolve_ipns(api, ipns_name).await {
        Ok(_resolved) => Ok(false),           // present -> recovery path
        Err(ApiError::IpnsNotFound(_)) => Ok(true), // absent -> safe to mint fresh
        Err(e) => Err(format!("preflight resolve failed for {}: {}", ipns_name, e)),
    }
}
```

**Recovery path shape:** on "key-blob name present, root-folder name absent" — fetch the existing key-blob content, ECIES-unwrap under the user's private key (already available during init — mirror `fetch_and_decrypt_vault`'s unwrap call), recover `root_read_key`/`root_write_key`, then (per Open Question 1's recommendation) proactively fetch+unseal the root folder's `read_sealed` bytes using the SAME `ipfs::fetch_content` + `unseal_node` primitives already exercised in this file's own `#[cfg(test)]` block (`vault.rs:396-469`) as a coherency check before completing `/vault/init`.

**Testing pattern:** seam network calls behind a trait/closure the way `metadata.rs`'s `run_publish_retry_seam` (verified at `crates/fuse/src/metadata.rs:588`, exercised by tests at `:652,661,683,711`) already does, so the preflight/recovery decision logic is unit-testable without a live API.

---

### `crates/fuse/src/metadata.rs` (Plan B, SC2 item 1)

**Analog:** the function's own two divergent implementations must merge into one.

**Current state (verified in RESEARCH, current source):**
- `publish_with_cas_retry` (`~44-152`): 1-retry (2 attempts), used by e.g. `spawn_bin_entry_publish`'s update path.
- `spawn_metadata_publish`'s inline loop (`~330-385`, confirmed present with `max_attempts = 5u32` hardcoded): 5-attempt CAS-conflict retry loop, duplicating the resolve→make_record→publish→conflict-retry shape.

**Fix pattern:** add `max_attempts: u32` param to `publish_with_cas_retry`; ALL existing call sites pass `2` (preserve behavior exactly); then delete `spawn_metadata_publish`'s inline loop and have it call the generalized helper with `max_attempts: 5`. Do NOT let `spawn_metadata_publish` call today's unparameterized helper — that silently regresses 5→2 attempts (explicit anti-pattern, RESEARCH Pitfall 2).

**Test pattern to extend:** existing `publish_with_cas_retry_*` tests at `metadata.rs:649-727` (built on `run_publish_retry_seam`, `metadata.rs:588`) — add an attempt-3/4/5-succeeds case exercising `max_attempts: 5` to prove no regression.

---

### `crates/fuse/src/fs.rs` (Plan B, SC2 item 2)

**Analog:** the loop's own existing dedup guards are correct; only the budget calculation is wrong.

**Current (buggy) shape** (`fs.rs:599-600`, confirmed):
```rust
const MAX_CONCURRENT_FP_RESOLVES: usize = 10;
let mut spawned = 0; // resets every call — ignores self.resolving_file_pointers.len()
```

**Fix pattern:** seed the budget from the true in-flight set: `MAX_CONCURRENT_FP_RESOLVES.saturating_sub(self.resolving_file_pointers.len())`, feeding both the pending-drain loop (`~611-625`) and the fresh-unresolved loop (`~631-653`). No struct field changes — `resolving_file_pointers` (`fs.rs:56`) already is the global accounting structure. The existing `resolving_file_pointers.contains(&fp_ino)` checks at `fs.rs:612` and `fs.rs:632` are the correctness guard and must NOT be touched.

---

### `crates/fuse/src/platform/windows/write_ops.rs` (Plan D, SC2 item 3)

**Analog: exact, already-shipped Unix fix** — `crates/fuse/src/write_ops/implementation/delete.rs:180` and `:419` (commit c4d30e598), confirmed present in this worktree:
```rust
// delete.rs:180 and :419 — identical structure at both sites
// SECURITY-REVIEW: D-07 dual-keying — childId(UUID) vs ipnsName must not
// be conflated. childId is the inode's STORED node_id (its real
// published.id), NOT uuid_from_ino(child_ino): a materialized-then-removed
// child must key by node_id so the bin entry pairs correctly on restore.
let child_id = inode.node_id.clone();
```

**Current bug** (`write_ops.rs:666`, per RESEARCH):
```rust
let child_id = crate::fs::uuid_from_ino(ino);
```

**Fix:** mirror `delete.rs` exactly — `write_ops.rs`'s `cleanup()` already has `fs.inodes.get(ino)` in scope at the `bin_capture` match (`~663`); read `inode.node_id.clone()` directly from that already-fetched `inode`, with the same explanatory `SECURITY-REVIEW: D-07 dual-keying` comment for consistency with the Unix sites. `autonomous:false` — Windows-only compile, CI-gated (`Cargo Check & Test (Windows)`), cannot be verified locally on this macOS worktree.

---

### `apps/api/src/republish/republish.service.ts` (Plan C, SC3 item 1)

**Analog:** the method's own adjacent branch.

**Current** (`republish.service.ts:459-492`, confirmed in RESEARCH):
```typescript
if (result.affected === 0) {
  this.logger.debug(`EOL renewal CAS miss for ${ipnsName} (seq advanced or tombstoned) — discarding`);
}
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  this.logger.warn(`renewIpnsRecordEol failed for ${ipnsName}: ${message}`); // [FIX]: -> logger.error
}
```

**Fix pattern:** change the `catch` branch's `logger.warn` to `logger.error` (real DB error, not a CAS miss); leave the `affected === 0` `debug` branch untouched; do NOT change `totalSucceeded` accounting (incremented at `:250`, strictly after this call at `:216`, already independent of this outcome).

---

### `apps/tee-worker/src/services/key-manager.ts` + `tee-keys.ts` (Plan C, SC3 item 2)

**Analog:** the existing `ReEnrollRequiredError` typed-error `instanceof` convention already used in the SAME file (`decryptWithFallback`'s first branch, `keyEpoch < internalCurrentEpoch - 1`).

**Fix pattern:** introduce `TeeKeyUnavailableError extends Error` thrown from `getKeypair()`'s two real config/infra guard sites — `tee-keys.ts:70-72` (simulator-in-production guard) and `tee-keys.ts:93` (unexpected `DstackClient.getKey()` return shape); NOTE (RESEARCH correction) there is no MIN/MAX-epoch-range throw in `getKeypair` today — do not invent one. `decryptWithFallback`'s two bare `catch {}` blocks (`key-manager.ts:94`, `:104`) must `instanceof`-check for `TeeKeyUnavailableError` and rethrow (wrap with `{ cause }`); any other error falls through to the next trial unchanged (expected epoch-mismatch fallback behavior).

**Test pattern to extend:** `key-manager.test.ts:216-230`'s existing "corrupted key" test is actually an epoch-mismatch case (valid ciphertext, wrong epoch) — either rename it, and add a genuinely corrupted-ciphertext case (`encrypted[10] ^= 0xff` after `wrapKey`) asserting the same non-`ReEnrollRequiredError` outcome.

---

### `apps/tee-worker/src/routes/republish.ts` (Plan C, SC3 item 3)

**No direct analog in-repo** — this is a novel defensive null-guard. Follow the existing per-entry result shape already used in the catch block (`~184-201`, `RepublishResult` push pattern).

**Fix pattern:** at the top of the `for (const entry of entries)` loop, before the `try`, add `if (!entry || typeof entry !== 'object') { results.push({ ipnsName: 'unknown', success: false, error: 'Invalid entry (null or non-object)' }); continue; }` so the catch block's `entry.ipnsName` dereference (currently unguarded, crashes the whole route 500 on a null entry) is never reached with a malformed `entry`.

---

### `apps/tee-worker/src/services/ipns-signer.ts` + `packages/crypto/src/ipns/parse-record.ts` (Plan C, SC3 item 4)

**Analog:** `packages/crypto/src/ipns/parse-record.ts:11-26`'s existing `ParsedIpnsRecord` field-mapping pattern (`value`, `sequence`, `signatureV2`, `data`, `pubKey`) — extend additively with `validity: Date`, sourced from the `ipns` npm package's `unmarshalIPNSRecord()` result (already computes it, just not currently forwarded).

**Fix pattern in `renewIpnsRecord`** (`ipns-signer.ts:33-46`): after minting the new record via `createIpnsRecord`, compare its `validity` against the EXISTING (parsed) record's `validity` — reject/retry if not strictly later. **Critical: compare against the PARSED EXISTING record's validity, never `Date.now()` wall-clock arithmetic** (RESEARCH Pitfall 5 — avoids cross-host clock-skew false positives).

**Test to add:** the case where the original record's lifetime already exceeds the 48h default renewal window (RESEARCH Edge Coverage table) — proves the invariant is asserted correctly, not just "different bytes."

**Pre-check before landing:** grep all `ParsedIpnsRecord` consumers across `packages/`, `apps/api`, `apps/tee-worker` to confirm the additive field breaks nothing (RESEARCH Assumption A3, low risk but unverified in this research pass).

---

### Zeroization hygiene (Plan B, SC2 item 4) — `journal_helpers.rs`, `content_ops.rs`, `mkdir.rs`, `apps/desktop/src-tauri/src/fuse/mod.rs`, `prepopulate.rs` (verify-only)

**Analog/Shared Pattern:** existing `Zeroizing<Vec<u8>>` / `Zeroizing<[u8; N]>` usage already established throughout `crates/fuse` (e.g. `spawn_metadata_publish`'s `ipns_private_key: Zeroizing<Vec<u8>>` parameter, `metadata.rs:160`) and `cipherbox_crypto::utils::clear_bytes` (`crates/crypto/src/utils.rs:40`, re-exported `crates/crypto/src/lib.rs:30`, signature `fn(buf: &mut [u8])`).

**Critical constraint (project memory, "broke 48/89 E2E" previously):** zero only a **locally-owned copy or return value**. Never call `clear_bytes`/wrap `Zeroizing` around a caller-owned or reused buffer — a callee receiving caller-owned buffers must not zero them. RESEARCH confirms every target in this phase's scope is a locally-owned copy; re-verify this rule for any NEW target discovered during implementation before adding zeroization.

**`prepopulate.rs`:** the source todo's cited lines (117, 455) do not correspond to an un-zeroed bare-key copy in the current 157-line file — re-grep fresh rather than trusting stale line numbers; if nothing found, mark done-as-verified-clean, do not force a change.

## Shared Patterns

### Typed error over string-matching (TEE worker)
**Source:** `apps/tee-worker/src/services/key-manager.ts` (existing `ReEnrollRequiredError` `instanceof` check)
**Apply to:** the new `TeeKeyUnavailableError` classification in `decryptWithFallback` — same file, same convention, do not string-match `error.message`.

### Retry-seam testability (Rust FUSE)
**Source:** `crates/fuse/src/metadata.rs:588` (`run_publish_retry_seam`) and its test call sites `:652,661,683,711`
**Apply to:** Plan A's vault-init preflight/recovery decision logic, and Plan B's `max_attempts`-parameterized `publish_with_cas_retry` — seam network calls behind a trait/closure so the decision branch is unit-testable without a live API/relay.

### D-07 dual-keying comment convention
**Source:** `crates/fuse/src/write_ops/implementation/delete.rs:172-180` and `:410-419` (`SECURITY-REVIEW: D-07 dual-keying` comment block)
**Apply to:** the Windows `write_ops.rs` fix — carry the same explanatory comment so the write-plane/read-plane key-space distinction is documented identically on both platforms.

### Zeroizing only locally-owned buffers
**Source:** project memory (`~/.claude/learnings`, "callee must not zero a reused buffer" — broke 48/89 E2E previously) + existing `Zeroizing<T>` usage across `crates/fuse`
**Apply to:** all Plan B SC2-item-4 zeroization targets — verify local ownership before wrapping/clearing, every time.

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `apps/tee-worker/src/routes/republish.ts` (null-entry guard) | route | batch/request-response | Novel defensive input-validation check; no prior null-guard pattern exists at this call site in-repo — follow the existing per-entry result-push shape instead (see Pattern Assignments above) |

## Metadata

**Analog search scope:** `crates/fuse/**`, `apps/desktop/src-tauri/src/**`, `apps/api/src/republish/**`, `apps/tee-worker/src/**`, `packages/crypto/src/ipns/**` — all read via RESEARCH.md's already-verified source excerpts plus a live grep of `crates/fuse/src/write_ops/implementation/delete.rs` and `crates/fuse/src/metadata.rs` in this worktree to confirm the Unix D-07 fix and `run_publish_retry_seam` still exist as cited.
**Files scanned:** 15 (12 target files + 3 analog-only files: `delete.rs`, `fetch_and_decrypt_vault` in `vault.rs`, `parse-record.ts`)
**Pattern extraction date:** 2026-07-11
