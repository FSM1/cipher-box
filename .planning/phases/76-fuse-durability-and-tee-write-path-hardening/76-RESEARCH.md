# Phase 76: FUSE Durability and TEE Write-Path Hardening - Research

**Researched:** 2026-07-11
**Domain:** Rust FUSE/WinFsp desktop write path, TEE republish/renewal write path (TypeScript)
**Confidence:** HIGH — every finding below is grounded in the actual source read in this worktree; no library/framework research was needed (this phase touches only in-repo code and one already-integrated npm dep, `ipns`).

## Summary

This is a hardening phase, not a greenfield feature: it closes 4 already-triaged, already-scoped todos (`resolves_phase: 76`) whose problems, root causes, and fixes were largely diagnosed at todo-creation time. The work is genuinely three independent surfaces that never touch the same file:

1. **Desktop vault-init preflight** (Rust, `apps/desktop/src-tauri/src/commands/vault.rs`) — make `initialize_vault` fail closed on transient IPNS resolve errors and, critically, solve a **root-key coherency bug** that a naive "just add a preflight" fix does NOT solve (see Critical Finding below).
2. **FUSE publish/concurrency + zeroization hardening** (Rust, `crates/fuse/**` + `apps/desktop/src-tauri/src/fuse/**`) — 4 sub-items of differing risk/CI-gating, most already precisely diagnosed by the source todo.
3. **TEE republish/renew error handling** (TypeScript, `apps/api/src/republish/republish.service.ts` + `apps/tee-worker/src/**`) — 4 sub-items, all pure branching-logic fixes with an existing unit-test harness (TDD-eligible).

**Critical Finding (SC1):** `root_read_key`/`root_write_key` in `initialize_vault` are **freshly minted random** on every call (`Zeroizing::new(cipherbox_crypto::utils::generate_file_key())`), NOT HKDF-derived like the IPNS keypairs. A naive "preflight both names, abort if either exists" fix does not by itself make retry safe: if the key-blob IPNS publish succeeds but the root-folder publish then fails (the exact "publish fails after a clean preflight" case the phase's SC1 asks about), a bare retry mints a **second, different** random key pair, and the already-published key blob (ECIES-wrapped under the first pair) can never again match a re-sealed root folder built with a second pair. The recovery design must **decrypt-and-resume** from the existing key blob rather than re-mint — see the SC1 section below for the concrete design.

**Primary recommendation:** Decompose into exactly 4 plans, 3 of them mutually independent (disjoint files, can run in parallel in the same wave): (A) vault-init preflight+recovery (Rust, desktop, mac-buildable, autonomous), (B) FUSE retry-helper consolidation + FP-resolve global cap + zeroization (Rust, `crates/fuse`, mac-buildable, autonomous), (C) TEE republish/renew error handling + tests (TypeScript, `apps/api` + `apps/tee-worker`, autonomous, TDD-eligible), (D) Windows D-07 `node_id` keying fix (Rust, `crates/platform/windows`, **CI-gated, `autonomous:false`**, depends on nothing else in this phase but cannot self-verify locally on macOS). See "Plan Decomposition" below.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Vault-init atomicity/preflight | Desktop (Tauri/Rust native backend) | API (backend `/vault/init` registration, unchanged) | The publish-ordering and preflight decision is entirely client-side (IPNS resolve + ECIES); the backend call is a separate, already-idempotent-shaped final step |
| FUSE metadata publish retry budget | Desktop (Rust FUSE crate) | — | Purely a client-side CAS-retry loop against the relay; no backend change |
| FilePointer resolve concurrency cap | Desktop (Rust FUSE crate) | — | In-process scheduling state (`resolving_file_pointers`, `pending_fp_resolves`); no network-protocol change |
| Windows D-07 write-plane keying | Desktop (Rust WinFsp platform layer) | — | Mirrors an already-shipped Unix fix; pure identity-keying correctness inside the FUSE/WinFsp crate |
| Defense-in-depth key zeroization | Desktop (Rust FUSE crate + Tauri commands) | Crypto (`cipherbox_crypto::utils::clear_bytes`) | Local-buffer hygiene using an existing crypto-tier primitive; no new crypto primitive needed |
| TEE republish DB write-back error classification | API (NestJS `republish.service.ts`) | — | Server-side DB write path; no crypto/TEE involvement in this specific finding |
| TEE key-decrypt fallback error classification | TEE worker (`key-manager.ts`) | — | Runs inside the TEE process; config/infra errors from `getKeypair` are TEE-internal, not relay-influenced |
| TEE republish route per-entry input validation | TEE worker (`routes/republish.ts`) | — | HTTP-boundary defense-in-depth against a malformed relay batch |
| `renewIpnsRecord` later-EOL invariant | TEE worker (`ipns-signer.ts`) | Crypto (`ipns` npm package's record validity semantics) | Pure crypto-signing primitive; the invariant is enforced at the point the new record is minted |

## Package Legitimacy Audit

No new external packages are introduced by this phase. All work is against already-vendored/already-integrated dependencies (`zeroize`, `ipns` npm package, `@cipherbox/crypto`, `@cipherbox/core`, existing `cipherbox_api_client`). Skip protocol — no legitimacy check needed.

## Standard Stack

Not applicable — no new libraries. Existing in-repo primitives used throughout:

| Primitive | Location | Purpose |
|-----------|----------|---------|
| `cipherbox_api_client::ipns::resolve_ipns` | `crates/api-client/src/ipns.rs:309` | Raw IPNS resolve returning `Result<IpnsResolveResponse, ApiError>`; `ApiError::IpnsNotFound(name)` on a real 404, any other variant on a genuine failure |
| `cipherbox_api_client::ipns::VerifyError` | `crates/api-client/src/ipns.rs:24-30` | `Api(ApiError)` vs `Invalid(String)` — used by the *verified* chokepoint (`resolve_ipns_verified`), not needed for the preflight existence check (see SC1) |
| `cipherbox_crypto::utils::clear_bytes` | `crates/crypto/src/utils.rs:40` (re-exported `crates/crypto/src/lib.rs:30`) | `fn(buf: &mut [u8])` — zero a byte slice in place; `[VERIFIED: crates/crypto/src/lib.rs]` |
| `zeroize::Zeroizing<T>` | already used throughout `crates/fuse` | Wrap owned key buffers so they zero on drop |
| `ipns` npm package (`unmarshalIPNSRecord`, `createIPNSRecord`) | `packages/core/src/ipns/create-record.ts`, `packages/crypto/src/ipns/parse-record.ts` | Already the sole IPNS record codec; `IPNSRecord.validity: Date` is available on the raw `ipns`-package type but **not currently surfaced** by CipherBox's own `ParsedIpnsRecord` wrapper — see SC3 §1 |

## Architecture Patterns

### System Architecture Diagram

```
SC1 — Vault init preflight
  Desktop UI --dev-key/login--> initialize_vault(state, public_key)
     |
     |-- [NEW] preflight: resolve_ipns(vault_key_ipns_name) --+
     |-- [NEW] preflight: resolve_ipns(root_ipns_name) -------+--> both IpnsNotFound? --yes--> mint keys, publish blob, publish root, POST /vault/init
     |                                                         |
     |                                                         +--> either resolves OK (record exists)?
     |                                                              --> [NEW] recovery path: fetch+ECIES-unwrap existing
     |                                                                  key blob under user's private key -> recover
     |                                                                  root_read_key/root_write_key -> verify root-folder
     |                                                                  record also exists and unseals under recovered
     |                                                                  keys -> if both consistent: skip publishes,
     |                                                                  go straight to POST /vault/init (idempotent
     |                                                                  completion) -> else: Err (manual intervention)
     |                                                         |
     |                                                         +--> any non-404 error (transient/5xx/auth/etc.)?
     |                                                              --> Err, ABORT (fail closed, never publish)

SC2 — FUSE publish/concurrency
  fs.rs refresh cycle --> unresolved FilePointers found
     |--> pending_fp_resolves (cross-cycle carryover queue) drained first
     |--> [NEW] global in-flight counter (not per-cycle `spawned`) caps total concurrent resolves
     |--> spawn resolve tasks up to global cap --> resolving_file_pointers (dedup guard)

  metadata.rs::spawn_metadata_publish (5-attempt loop)         \
  metadata.rs::publish_with_cas_retry (1-retry / 2 attempts)    >-- [NEW] one generalized
                                                                /    helper: max_attempts: u32 param

  Windows write_ops.rs::cleanup() (D-07 delete/bin-capture)
     currently: child_id = uuid_from_ino(ino)      [BUG: wrong for materialized nodes]
     [NEW]:     child_id = inode.node_id.clone()   [mirrors Unix fix, commit c4d30e598]

SC3 — TEE republish/renew
  API republish.service.ts::renewIpnsRecordEol
     UPDATE ipns_records SET signed_record ... WHERE seq = :expected AND tombstoned_at IS NULL
        |--> affected === 0  --> harmless CAS-miss, logger.debug (UNCHANGED)
        |--> throw (real DB error) --> [NEW] logger.error (was: logger.warn, same as CAS-miss)

  TEE key-manager.ts::decryptWithFallback
     trial 1: decryptIpnsKey(ct, keyEpoch)    --> bare catch{} swallows EVERYTHING today
     trial 2: decryptIpnsKey(ct, currentEpoch) --> bare catch{} swallows EVERYTHING today
        [NEW]: catch must distinguish "getKeypair() config/infra error" (rethrow/wrap)
               from "unwrapKey() AEAD/format failure" (expected, advance to next trial)

  TEE routes/republish.ts  for (const entry of entries) { ... }
        [NEW]: validate `entry` is a non-null object BEFORE entry.signedRecord access,
               and in the catch block before entry.ipnsName access

  TEE ipns-signer.ts::renewIpnsRecord(key, marshaledExisting, lifetimeMs=48h)
     parsed = parseIpnsRecord(marshaledExisting)  [value, sequence only today]
     record = createIpnsRecord(key, parsed.value, parsed.sequence, lifetimeMs)
        [NEW]: also parse existing.validity (via unmarshalIPNSRecord directly, or by
               extending ParsedIpnsRecord), compare against the newly minted record's
               validity, reject/retry if not strictly later than the EXISTING record's
               validity (not wall-clock — avoids clock-skew false positives)
```

### Recommended Project Structure

No new files/directories — every change is a targeted edit inside existing modules. Do not create new modules for any SC.

### Pattern 1: Fail-closed preflight-before-any-write (SC1)
**What:** Resolve every identity/name a multi-step write sequence depends on, BEFORE issuing the first write; treat any ambiguous resolve outcome (not just an explicit conflict) as abort.
**When to use:** Any multi-record atomic-ish publish sequence where a partial failure leaves cross-referencing records inconsistent (exactly this vault-init case: key blob + root folder must agree on root keys).
**Example (design, not yet in code):**
```rust
// apps/desktop/src-tauri/src/commands/vault.rs — proposed preflight shape
use cipherbox_api_client::error::ApiError;

async fn preflight_ipns_absent(
    api: &cipherbox_api_client::ApiClient,
    ipns_name: &str,
) -> Result<bool, String> {
    // returns Ok(true) = confirmed absent (safe to mint+publish fresh)
    //         Ok(false) = confirmed present (existing record — recovery path)
    //         Err(_) = transient/unknown — caller MUST abort, never treat as absent
    match cipherbox_api_client::ipns::resolve_ipns(api, ipns_name).await {
        Ok(_resolved) => Ok(false),
        Err(ApiError::IpnsNotFound(_)) => Ok(true),
        Err(e) => Err(format!("preflight resolve failed for {}: {}", ipns_name, e)),
    }
}
```

### Pattern 2: Attempt-budget-parameterized CAS retry helper (SC2 item 1)
**What:** One `publish_with_cas_retry`-shaped function that takes `max_attempts: u32` instead of two divergent implementations.
**When to use:** Any IPNS CAS-publish call site; this generalizes the existing 2-callsite duplication.
**Example — current signatures (both real, from `crates/fuse/src/metadata.rs`):**
```rust
// The shared 1-retry helper (2 attempts total) — metadata.rs:44-152
pub(crate) async fn publish_with_cas_retry<F>(
    api: &ApiClient,
    coordinator: &PublishCoordinator,
    ipns_name: &str,
    preresolved_seq: Option<u64>,
    make_record: F,
    old_cids_to_unpin: &[String],
    journal_entry: Option<()>,
) -> Result<(), String>
where
    F: Fn(u64) -> Result<(String, String), String>;

// The 5-attempt background-thread loop — metadata.rs:288-401 (spawn_metadata_publish),
// duplicating the CAS-conflict-retry-jitter logic inline instead of delegating.
pub fn spawn_metadata_publish(
    api: Arc<ApiClient>, rt: tokio::runtime::Handle, published_node: Vec<u8>,
    ipns_private_key: Zeroizing<Vec<u8>>, ipns_name: String,
    old_metadata_cid: Option<String>, coordinator: Arc<PublishCoordinator>,
);
```
**Design:** Add `max_attempts: u32` as a new parameter to `publish_with_cas_retry` (all 3 existing call sites — `spawn_bin_entry_publish`'s update path, and any future caller — pass `2`, preserving today's behavior exactly), then loop the resolve→make_record→publish→conflict-retry cycle up to `max_attempts` times instead of the current hardcoded "one retry" shape. `spawn_metadata_publish` then deletes its inline 5-attempt loop and calls the generalized helper with `max_attempts: 5`. This is the ONLY way to consolidate without the 5→2 regression the source todo explicitly warns about — do not simply make `spawn_metadata_publish` call today's `publish_with_cas_retry` unchanged.

### Pattern 3: Cross-cycle global concurrency accounting (SC2 item 2)
**What:** A cap that persists across `drain_refresh_completions` invocations, not just within one call.
**Current state (verified NOT a correctness bug today):** `fs.rs:599` `const MAX_CONCURRENT_FP_RESOLVES: usize = 10;` is a **local** `let mut spawned = 0` counter reset every call (`fs.rs:600`), so if `resolving_file_pointers` (the true in-flight set, `fs.rs:56`) already holds work from a prior cycle, a fresh cycle can spawn up to 10 MORE on top, overshooting the intended global cap of 10. The existing `resolving_file_pointers.contains(&fp_ino)` guards (`fs.rs:612`, `fs.rs:632`) correctly prevent any single inode from being double-spawned, so this is a resource-boundedness issue, not a data-race.
**Design:** Replace the per-call `let mut spawned = 0` with `MAX_CONCURRENT_FP_RESOLVES.saturating_sub(self.resolving_file_pointers.len())` as the budget for THIS cycle, so the two loops (`fs.rs:611-625` pending-drain, `fs.rs:631-653` fresh-unresolved) spawn only up to what keeps the GLOBAL in-flight count at or under the cap. No struct field changes needed — `resolving_file_pointers` already is the global accounting structure; the bug is purely that the budget calculation ignores it.

### Anti-Patterns to Avoid
- **Preflight-only fix without a recovery path (SC1):** Passes a narrow "both preflights pass" test but leaves any vault whose FIRST attempt already got partway (a real, expected occurrence — that's WHY this todo exists) permanently stuck: retry preflight sees "record exists" → aborts forever, `GET /vault` 404s forever (backend registration never happened). The fix must include the decrypt-and-resume branch.
- **Delegating `spawn_metadata_publish` to `publish_with_cas_retry` unchanged (SC2 item 1):** Silently drops resilience from 5 attempts to 2 on the metadata publish path — explicitly called out as the risk in the source todo. Verify attempt count with a test that exercises attempt 3, 4, 5 before declaring done.
- **Zeroizing a caller-owned/reused buffer (SC2 item 4):** The established project trap (see CipherBox project memory: "broke 48/89 E2E" previously). Every zeroization target listed in SC2 item 4 has been verified in this research pass to be a **locally-owned copy or return value** (see per-item confirmation in Common Pitfalls below) — this trap does not apply to any of the 76-scoped items, but any NEW target found during implementation must be re-verified against this rule before adding `clear_bytes`/`Zeroizing`.
- **Trusting the source todo's exact line numbers for `prepopulate.rs`:** The todo cites `prepopulate.rs:117,455`, but the actual file (`apps/desktop/src-tauri/src/fuse/prepopulate.rs`) is only 157 lines and shows no un-zeroed `[u8;32]` bare-key copy at those numbers (its `[u8;32]` handling is already all copy-out-of-inode, no separate transient buffer to zero). Grep fresh at execution time rather than trusting the stale line numbers; if no genuine un-zeroed bare-key copy is found in this file, mark that specific line item done-as-verified-clean rather than force a change.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| IPNS "does a record exist yet" check | A new resolve-and-classify wrapper | `cipherbox_api_client::ipns::resolve_ipns` + match on `Err(ApiError::IpnsNotFound(_))` | Already the exact typed distinction needed; no signature verification required for an existence-only preflight check (the record's content is irrelevant until the recovery-decrypt step) |
| Distinguishing "expected AEAD/format failure" from "infra/config failure" in a fallback-decrypt loop | String-matching on `error.message` | A dedicated error class/marker thrown by `getKeypair()`'s two failure sites (simulator-in-prod guard, unexpected SDK return shape) that `decryptWithFallback`'s catch can `instanceof`-check | String matching on error messages is exactly the fragile pattern this hardening phase is trying to eliminate elsewhere (route-level errors already avoid it); a typed error class is the idiomatic TS fix and mirrors the existing `ReEnrollRequiredError` pattern in the same file |
| Later-EOL comparison for IPNS record renewal | Hand-parsing the CBOR `Validity` field again | `unmarshalIPNSRecord(...).validity` (a `Date`, already computed by the `ipns` npm package used everywhere else in this codebase) | The library already parses and returns `validity: Date`; CipherBox's own `ParsedIpnsRecord` wrapper (`packages/crypto/src/ipns/parse-record.ts`) just doesn't currently forward that field — extend the wrapper, don't reimplement CBOR validity parsing |

**Key insight:** Every fix in this phase reuses an already-present typed primitive (`ApiError::IpnsNotFound`, `clear_bytes`, `ipns` package's `validity` field, `inode.node_id`) that the codebase already has but the buggy code path doesn't yet consume. There is no case in this phase where a new dependency or new hand-rolled primitive is warranted.

## Edge Coverage

| SC | Edge case | Status | Notes |
|----|-----------|--------|-------|
| SC1 | Transient (non-404) resolve error on either name | Covered (new) | Must abort, never treat as absent — the core fail-closed requirement |
| SC1 | Both names pre-exist from a fully-registered prior vault (`GET /vault` succeeds) | Backstop | Not really an init path at all — the caller should route to `fetch_and_decrypt_vault` instead; the preflight design should not need to special-case this if `initialize_vault` is only ever invoked for a genuinely new/unregistered user, but document the assumption |
| SC1 | Both names absent (fresh user) | Covered (existing, unchanged) | Current happy path |
| SC1 | Only the key-blob name exists, root-folder name absent (publish failed after clean preflight, step 1 succeeded / step 2 failed) | Covered (new — recovery path) | The critical finding: decrypt-and-resume, do not re-mint keys |
| SC1 | Only the root-folder name exists, key-blob name absent | Backstop | Should not occur under the current publish ORDER (key blob always published first) — treat as an unexpected/unrecoverable state, abort with a clear error for manual investigation rather than guessing |
| SC1 | Publish still fails AFTER a clean (both-absent) preflight | Covered (new) | Abort with a distinguishable error so the NEXT attempt's preflight correctly routes to the recovery branch (see "only key-blob exists" row above) |
| SC2-1 | 5th attempt succeeds (no 5→2 regression) | Covered (new test required) | The explicit acceptance bar from the source todo |
| SC2-1 | Existing 2-attempt callers (`spawn_bin_entry_publish` update path) unaffected | Covered (existing tests, signature updated) | Must not regress `publish_with_cas_retry_*` tests at `metadata.rs:649-727` |
| SC2-2 | Cross-cycle FP-resolve duplicate enqueue | Backstop | Source todo verified this is NOT a correctness defect today (existing `resolving_file_pointers`/`scheduled_this_cycle` guards already prevent double-spawn); this phase only fixes the OVERSHOOT of the global cap, not a dedup bug |
| SC2-2 | Global cap holds across 2+ consecutive refresh cycles | Covered (new test required) | The actual bug being fixed |
| SC2-3 | Materialized-vs-fresh-node Windows keying (cross-client sync, move, remount before delete) | Covered (new, CI-gated) | Mirrors the exact Unix regression scenario from commit c4d30e598 |
| SC2-3 | Same-session freshly-created node on Windows (never materialized) | Covered (existing behavior, unchanged) | `uuid_from_ino(ino)` remains correct for this case — the Unix fix pattern (`inode.node_id.clone()`) is correct here too since `node_id` is set to `uuid_from_ino(ino)` at creation time |
| SC2-4 | Any zeroization target turns out to be a caller-owned/reused buffer | Backstop | Explicitly re-verified per-item in this research (all locally-owned copies) — re-check any NEW target found during implementation against this rule before adding `clear_bytes`/`Zeroizing` |
| SC3 | Real DB error (connection/constraint) during `renewIpnsRecordEol` | Covered (new) | Elevate to `logger.error`, keep batch `totalSucceeded` unchanged (network publish already succeeded) |
| SC3 | CAS-miss (`affected === 0`, seq advanced or tombstoned) | Covered (existing, unchanged) | Already correctly non-fatal at `debug` level — do not touch this branch's severity |
| SC3 | `getKeypair()` config/infra error (simulator-in-production guard, unexpected SDK return shape) during either fallback trial | Covered (new) | Must rethrow, never masked as "corrupted key" |
| SC3 | Genuine epoch-mismatch (valid ciphertext, wrong epoch key) during either fallback trial | Covered (existing, unchanged) | Must continue to advance to the next trial — this is the expected/designed fallback behavior |
| SC3 | `null`/non-object entry in a republish batch | Covered (new) | Must not crash the whole batch (500); skip with a per-entry failure result |
| SC3 | Equal EOL (renewed validity === existing validity) | Covered (new) | Reject — "strictly later" per the invariant |
| SC3 | Earlier EOL (renewed validity < existing validity) | Covered (new) | Reject |
| SC3 | Original record's lifetime already exceeds the 48h default renewal window | Covered (new test required) | The explicit test-hardening edge case the source todo calls out — proves the invariant is asserted correctly, not just "different bytes" |
| SC3 | Clock skew between the host that created the original record and the TEE host renewing it | Covered (design) | Compare against the PARSED EXISTING record's validity, never wall-clock `Date.now()` arithmetic — see Pitfall 5 |

## Plan Decomposition

Recommend **4 plans**, grouped by disjoint file sets and build/CI constraints:

#### Plan A — Vault-init preflight + recovery (SC1)

- Files: `apps/desktop/src-tauri/src/commands/vault.rs` only.
- Build: mac/Linux-buildable (`cargo test -p cipherbox-desktop` or workspace `cargo test`), `autonomous: true`.
- TDD-eligible: yes — the preflight decision (resolve outcome -> abort/proceed/recover) is pure, defined I/O business logic once the network calls are seamed behind a trait/closure for testing (mirrors the existing `run_publish_retry_seam` pattern already used in `metadata.rs`).
- Depends on: nothing else in this phase. Can run in the same wave as Plan B and Plan C.

#### Plan B — FUSE retry-helper consolidation + FP-resolve global cap + zeroization hardening (SC2 items 1, 2, 4)

- Files: `crates/fuse/src/metadata.rs`, `crates/fuse/src/fs.rs`, `crates/fuse/src/journal_helpers.rs`, `crates/fuse/src/content_ops.rs`, `crates/fuse/src/write_ops/implementation/mkdir.rs`, `apps/desktop/src-tauri/src/fuse/mod.rs`, `apps/desktop/src-tauri/src/fuse/prepopulate.rs` (verify-only, see Assumption A1).
- Build: mac/Linux-buildable, `autonomous: true`.
- TDD-eligible: item 1 (attempt-budget parameterization) and item 2 (global cap) are defined I/O business logic (pure state-machine over counters/closures) — TDD-eligible. Item 4 (zeroization) is glue/hygiene — not meaningfully TDD-eligible (no new observable behavior to red-green against; verify via existing regression suite staying green).
- Internal ordering: item 1 and item 2 touch disjoint functions in the same 2 files (`metadata.rs`, `fs.rs`) — can be separate tasks within this one plan, sequenced or parallel at the task level. Item 4 should land as its own task(s) after items 1/2 to keep diffs reviewable, per the source todo's own framing ("kept a coherent crypto-hygiene pass, deferred as a unit").
- Depends on: nothing else in this phase. Can run in the same wave as Plan A and Plan C (no file overlap with either).

#### Plan C — TEE republish/renew error handling + tests (SC3, all 4 items)

- Files: `apps/api/src/republish/republish.service.ts`, `apps/tee-worker/src/services/key-manager.ts`, `apps/tee-worker/src/services/tee-keys.ts`, `apps/tee-worker/src/routes/republish.ts`, `apps/tee-worker/src/services/ipns-signer.ts`, `packages/crypto/src/ipns/parse-record.ts` (additive `validity` field), `apps/tee-worker/src/__tests__/ipns-signer.test.ts`, `apps/tee-worker/src/__tests__/key-manager.test.ts`. Optionally `.github/workflows/ci.yml` (see Open Question 2).
- Build: TypeScript, `pnpm --filter cipherbox-api test` / `pnpm --filter cipherbox-tee-worker test`, `autonomous: true`.
- TDD-eligible: yes, strongly — every one of the 4 sub-items is defined-I/O business logic (error classification branches, the EOL comparison, the null-guard) with an existing vitest/Jest harness already in place. This is the phase's best-fit plan for a strict red-green-refactor loop.
- Depends on: nothing else in this phase. Can run in the same wave as Plan A and Plan B (zero file overlap — Rust vs TypeScript, different apps entirely).
- Note: `packages/crypto` is a shared package — confirm via `pnpm -w list --filter ...` / grep that no OTHER in-flight phase branch is concurrently editing `parse-record.ts` before landing the additive `validity` field, to avoid a merge conflict outside this phase's control.

#### Plan D — Windows D-07 write-plane node_id keying (SC2 item 3)

- Files: `crates/fuse/src/platform/windows/write_ops.rs` only.
- Build: **Windows-only, CI-gated** (`Cargo Check & Test (Windows)` job, `Desktop E2E (windows-latest)` matrix leg). Does NOT compile under local macOS `cargo`.
- `autonomous: false` — **mandatory**. Requires a `checkpoint:human-verify` gate before merge (a human or the orchestrator must confirm the Windows CI jobs are green; this cannot be self-verified by an agent running on this macOS worktree).
- TDD-eligible: no — this is a platform/glue fix (mirroring an already-proven pattern from commit c4d30e598), not new business logic; verify via the existing D-07 regression-test pattern ported to the Windows platform module, run only in CI.
- Depends on: nothing else in this phase (no file overlap with A/B/C). Can be authored/queued in the same wave, but its completion/merge gate is asynchronous relative to A/B/C since it requires a CI round-trip that cannot happen locally.

**Wave structure:** Plans A, B, C, D can all be authored and executed in the SAME wave (zero pairwise file overlap: Rust-desktop vs Rust-fuse-crate vs TypeScript vs Rust-windows-platform). The only sequencing constraint is Plan D's merge gate (CI-dependent, `autonomous:false`) — it should not block the phase-completion of A/B/C, but the phase is not fully done (SC2's "CI green" clause) until D's Windows CI jobs pass.

## Runtime State Inventory

Not applicable — this is not a rename/refactor/migration phase. No stored-data keys, service configs, OS registrations, secrets, or build artifacts change identity or name in this phase. (SC2 item 3's Windows `node_id` fix changes which VALUE is used as a `WriteChildRef.child_id` for *newly affected* materialized-node delete/bin operations on Windows only — this is a bugfix to already-in-flight runtime data shape, not a rename; no migration needed since it only affects new write operations going forward, mirroring the Unix fix which required no migration either per commit c4d30e598.)

## Common Pitfalls

### Pitfall 1: Treating vault-init retry as safe once a preflight exists (SC1)
**What goes wrong:** A developer implements "resolve both names, abort if either exists" and calls SC1 done. The very NEXT init attempt after any transient publish failure now permanently aborts (preflight correctly detects the leftover record) with no path forward — the todo's "Recovery story" requirement is silently dropped.
**Why it happens:** `root_read_key`/`root_write_key` are freshly random per `initialize_vault` call (`vault.rs:127-130`), not deterministic — so "the record already exists" cannot be resolved by "just try again with the same preflight logic."
**How to avoid:** Implement the decrypt-and-resume branch (fetch existing key-blob CID, ECIES-unwrap under the user's private key — always available during init — recover the ORIGINAL `root_read_key`/`root_write_key`, and only mint fresh keys when the key-blob name is confirmed absent).
**Warning signs:** A plan or PLAN.md that only adds a "preflight, abort on exists" check with no code path that ever calls `ecies::unwrap_key` on the vault-key blob during `initialize_vault` (today `initialize_vault` never unwraps — only `fetch_and_decrypt_vault` does) is missing the recovery half of SC1.

### Pitfall 2: 5→2 attempt-budget regression when consolidating retry helpers (SC2 item 1)
**What goes wrong:** `spawn_metadata_publish`'s 5-attempt resilience silently drops to `publish_with_cas_retry`'s current 2-attempt shape.
**Why it happens:** The two functions look like straightforward duplication (same resolve→publish→conflict→retry shape) but their retry budgets were never actually equal; a lazy "just call the existing helper" refactor picks up the smaller budget by default.
**How to avoid:** Generalize `publish_with_cas_retry` to accept `max_attempts: u32` FIRST (all existing callers pass `2` to preserve behavior), THEN make `spawn_metadata_publish` delegate with `max_attempts: 5`.
**Warning signs:** A test asserting an attempt-3/4/5-succeeds scenario is missing, or `spawn_metadata_publish`'s new call site hardcodes `2` instead of `5`.

### Pitfall 3: Windows `write_ops.rs` fix attempted/verified on macOS (SC2 item 3)
**What goes wrong:** `crates/fuse/src/platform/windows/*` does not compile under local `cargo` on macOS (macFUSE-only linking for the Unix build; the Windows module is behind a Windows-only cfg / WinFsp dependency), confirmed by this repo's own `apps/desktop/CLAUDE.md` ("winfsp build is CI-only on macOS" per project memory) and by `.github/workflows/ci.yml`'s dedicated `Cargo Check & Test (Windows)` job (`windows-latest` runner) plus `desktop-e2e.yml`'s Windows matrix leg.
**Why it happens:** An agent with a green local `cargo check`/`cargo test` on macOS wrongly concludes the Windows fix is verified.
**How to avoid:** This specific plan MUST be marked `autonomous:false` / human-verify-gated, and its acceptance criterion is "green in `Cargo Check & Test (Windows)` CI job + Desktop E2E Windows matrix leg," never a local command.
**Warning signs:** A plan for this item lacking an explicit `autonomous:false` flag or a `checkpoint:human-verify` before merge.

### Pitfall 4: String-matching TEE errors instead of typed classification (SC3 item 2)
**What goes wrong:** `decryptWithFallback`'s bare `catch {}` (key-manager.ts:94, :104) is "fixed" by inspecting `err.message` substrings to decide rethrow-vs-continue — fragile, and the exact anti-pattern the codebase elsewhere already avoids (route-level errors use `instanceof`, e.g. `ReEnrollRequiredError`).
**Why it happens:** It looks like the smallest diff; the two `getKeypair()` throw sites (`tee-keys.ts:70`, `:93`) currently just throw plain `Error`, so there's no existing typed marker to `instanceof`-check.
**How to avoid:** Introduce a small typed error (e.g. `TeeKeyUnavailableError extends Error`) thrown from `getKeypair()`'s two config/infra-guard sites, and have `decryptWithFallback`'s catch blocks `instanceof`-check for it and rethrow (wrap with `{ cause }`), letting every other error (assumed to be `unwrapKey`'s ECIES/AEAD failure) fall through to the next trial as today.
**Warning signs:** A diff that only edits `key-manager.ts` and never touches `tee-keys.ts` — the fix requires a coordinated typed-error contract across both files.

### Pitfall 5: `renewIpnsRecord`'s later-EOL check compared against wall clock (SC3 item 4)
**What goes wrong:** Comparing the newly minted record's `validity` against `Date.now() + lifetimeMs` (or similar wall-clock math) instead of the PARSED EXISTING record's `validity` introduces spurious rejections under clock skew between the TEE host and whatever minted the original record.
**Why it happens:** It's the more "obvious" implementation of "reject an equal/earlier EOL."
**How to avoid:** Parse the EXISTING record's `validity` (via `unmarshalIPNSRecord` or an extended `ParsedIpnsRecord`) and compare the NEW record's minted `validity` against THAT value — both are computed by the same `ipns` package on the same host in the same call, so no cross-host clock skew is introduced by the comparison itself.
**Warning signs:** A diff introducing `Date.now()` arithmetic inside `renewIpnsRecord` or its test.

### Pitfall 6: TEE-worker unit tests are not currently run in CI
**What goes wrong:** `ipns-signer.test.ts` and `key-manager.test.ts` (both SC3 targets) are exercised only via `pnpm --filter cipherbox-tee-worker build` + a live `start` in `ci.yml`'s `sdk-e2e` job — there is NO CI step running `pnpm --filter cipherbox-tee-worker test` (vitest unit tests). A regression in either test file will not turn CI red.
**Why it happens:** Historical gap — `ci.yml`'s `Test` job (line 267) only covers `api`, `crypto`, `core`, `sdk-core`, `sdk`, `api-client` (confirmed by grep; `tee-worker` absent).
**How to avoid:** Either (a) add `apps/tee-worker` to the existing `Test` job's package list (small, low-risk `ci.yml` change — SC3's plan should consider proposing this), or (b) if out of scope for this phase, explicitly document in VALIDATION.md that these two test files must be run manually (`pnpm --filter cipherbox-tee-worker test`) as part of phase-gate verification since CI will not catch a regression automatically.
**Warning signs:** A plan that treats "tests pass locally" as sufficient without either adding the CI step or flagging the gap for the human verifier.

## Code Examples

### `publish_with_cas_retry` (current, `crates/fuse/src/metadata.rs:44-152`)
```rust
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) async fn publish_with_cas_retry<F>(
    api: &ApiClient,
    coordinator: &PublishCoordinator,
    ipns_name: &str,
    preresolved_seq: Option<u64>,
    make_record: F,
    old_cids_to_unpin: &[String],
    journal_entry: Option<()>, // placeholder for future (queue, entry) — always None this phase
) -> Result<(), String>
where
    F: Fn(u64) -> Result<(String, String), String>,
{ /* resolve seq -> make_record(new_seq) -> publish -> on Conflict: jitter sleep,
     re-resolve, retry ONCE more -> on second Conflict: Err (persistent conflict) */ }
```

### `spawn_metadata_publish`'s inline 5-attempt loop (current, `crates/fuse/src/metadata.rs:330-385`, to be deleted and replaced by a call into the generalized helper)
```rust
let max_attempts = 5u32;
let publish_result: Result<(), String> = async {
    let mut attempt = 0u32;
    loop {
        let seq = coordinator.resolve_sequence(&api, &ipns_name).await?;
        // ... make_record, publish_ipns ...
        match /* publish result */ {
            PublishResult::Success => { /* record_publish, unpin olds, return Ok(()) */ }
            PublishResult::Conflict { .. } => {
                attempt += 1;
                if attempt >= max_attempts {
                    return Err(format!("Persistent conflict for {} after {} attempts", ipns_name, max_attempts));
                }
                /* jitter sleep, loop */
            }
        }
    }
}.await;
```

### FilePointer resolve global-cap loop (current, `crates/fuse/src/fs.rs:594-653`)
```rust
const MAX_CONCURRENT_FP_RESOLVES: usize = 10;
let mut spawned = 0; // BUG: resets to 0 every call, ignores self.resolving_file_pointers.len()
let mut scheduled_this_cycle = std::collections::HashSet::<u64>::new();

// drain pending_fp_resolves first (bounded by `spawned >= MAX_CONCURRENT_FP_RESOLVES`)
// then fresh `unresolved` entries (same per-cycle-only bound)
```
Proposed one-line-ish fix: seed `spawned` from `self.resolving_file_pointers.len()` (or equivalently, compare against `MAX_CONCURRENT_FP_RESOLVES.saturating_sub(self.resolving_file_pointers.len())`) rather than `0`.

### Windows D-07 keying bug (current, `crates/fuse/src/platform/windows/write_ops.rs:666`) vs. the already-shipped Unix fix (`crates/fuse/src/write_ops/implementation/delete.rs:180`, `:419`)
```rust
// Windows (BUGGY — cleanup() delete/bin-capture path):
let child_id = crate::fs::uuid_from_ino(ino);

// Unix (CORRECT — commit c4d30e598, delete.rs:180 and :419):
// childId is the inode's STORED node_id (its real published.id), NOT
// uuid_from_ino(child_ino): a materialized-then-removed child must key by node_id.
let child_id = inode.node_id.clone();
```
Fix: change `write_ops.rs:666` to `let child_id = fs.inodes.get(ino).map(|i| i.node_id.clone()).unwrap_or_else(|| crate::fs::uuid_from_ino(ino));` (mirroring the exact fallback pattern already used at `fs.rs:947-955` for the equivalent non-delete publish path) — or, since `write_ops.rs`'s cleanup() already has `fs.inodes.get(ino)` in scope at that point (see the `bin_capture` match at `write_ops.rs:663`), read `inode.node_id.clone()` directly from the already-fetched `inode`.

### `renewIpnsRecordEol` (current, `apps/api/src/republish/republish.service.ts:459-492`)
```typescript
private async renewIpnsRecordEol(
  ipnsName: string, userId: string, loadedSequenceNumber: string, renewedSignedRecord: Buffer
): Promise<void> {
  try {
    const result = await this.ipnsRecordRepository.createQueryBuilder()
      .update(IpnsRecord)
      .set({ signedRecord: renewedSignedRecord, updatedAt: new Date() })
      .where('ipns_name = :ipnsName AND user_id = :userId AND sequence_number = :expected AND tombstoned_at IS NULL',
        { ipnsName, userId, expected: loadedSequenceNumber })
      .execute();

    if (result.affected === 0) {
      // Forward publish raced (seq advanced) OR tombstoned at the write level. Harmless.
      this.logger.debug(`EOL renewal CAS miss for ${ipnsName} (seq advanced or tombstoned) — discarding`);
    }
  } catch (error) {
    // Non-fatal: log and continue. The IPNS publish already succeeded.
    const message = error instanceof Error ? error.message : String(error);
    this.logger.warn(`renewIpnsRecordEol failed for ${ipnsName}: ${message}`); // [FIX]: this branch is a REAL
    // DB error (connection/constraint), not a CAS miss — should be logger.error + a message that is
    // unambiguously distinguishable from the affected===0 debug line above (already true structurally;
    // fix is just the log level / observability, no behavior change to the batch-succeeded counter).
  }
}
```
`totalSucceeded` is incremented at call-site `republish.service.ts:250`, strictly AFTER the `renewIpnsRecordEol` call at `:216` — i.e. the EOL write-back's outcome, fatal or not, never gates the batch's success accounting today, and this phase's fix should NOT change that (the IPNS publish itself already succeeded; only the log-level/observability of the DB write-back changes).

### `decryptWithFallback` (current, `apps/tee-worker/src/services/key-manager.ts:77-110`)
```typescript
export async function decryptWithFallback(
  encryptedIpnsPrivateKey: Uint8Array, keyEpoch: number
): Promise<{ ipnsPrivateKey: Uint8Array; usedEpoch: number }> {
  const internalCurrentEpoch = getInternalCurrentEpoch();
  if (keyEpoch < internalCurrentEpoch - 1) {
    throw new ReEnrollRequiredError(keyEpoch, internalCurrentEpoch);
  }
  try {
    const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsPrivateKey, keyEpoch);
    return { ipnsPrivateKey, usedEpoch: keyEpoch };
  } catch {
    // [FIX]: must inspect the caught error — if it originated from getKeypair()'s
    // config/infra guard (TeeKeyUnavailableError), rethrow immediately instead of
    // silently falling through to trial 2.
  }
  if (keyEpoch !== internalCurrentEpoch) {
    try {
      const ipnsPrivateKey = await decryptIpnsKey(encryptedIpnsPrivateKey, internalCurrentEpoch);
      return { ipnsPrivateKey, usedEpoch: internalCurrentEpoch };
    } catch {
      // [FIX]: same instanceof check here.
    }
  }
  throw new Error('ECIES decryption failed: key may be corrupted or from an unknown epoch');
}
```
The two `getKeypair()` throw sites today (`apps/tee-worker/src/services/tee-keys.ts:70-72` simulator-in-production guard, `:93` unexpected `DstackClient.getKey()` return shape) both throw plain `Error` — **note this corrects the source todo's phrasing "epoch out of MIN/MAX range"**: no such range-check throw currently exists in `getKeypair`; `MIN_EPOCH`/`MAX_EPOCH` (`tee-keys.ts:18-19`) are only used defensively inside `getInternalCurrentEpoch()`'s clamp, never as a validation throw in `getKeypair`. The two REAL config/infra throw sites are the ones listed above — design the typed error around those two, not a nonexistent range check.

### Per-entry null guard (current gap, `apps/tee-worker/src/routes/republish.ts:94-99`, catch at `:184-201`)
```typescript
for (const entry of entries) {
  let ipnsPrivateKey: Uint8Array | null = null;
  try {
    const signedRecordBytes = Buffer.from(entry.signedRecord, 'base64'); // throws if entry is null/non-object
    // ...
  } catch (error) {
    // ...
    const result: RepublishResult = {
      ipnsName: entry.ipnsName, // [BUG]: also throws if entry is null — crashes the WHOLE route (500), not just this entry
      success: false,
      error: /* ... */,
    };
```
Fix: at the top of the loop, before the `try`, check `if (!entry || typeof entry !== 'object')` and `results.push({ ipnsName: 'unknown', success: false, error: 'Invalid entry (null or non-object)' })`, `continue` — never enter the try/catch for a malformed entry at all, so the catch block's `entry.ipnsName` dereference is never reached with a null `entry`.

### `renewIpnsRecord` (current, `apps/tee-worker/src/services/ipns-signer.ts:33-46`) and the EOL-invariant gap
```typescript
export async function renewIpnsRecord(
  ed25519PrivateKey: Uint8Array,
  marshaledExistingRecord: Uint8Array,
  lifetimeMs: number = TEE_RECORD_LIFETIME_MS // 48h
): Promise<Uint8Array> {
  const parsed = await parseIpnsRecord(marshaledExistingRecord); // value + sequence ONLY — no validity today
  const record = await createIpnsRecord(ed25519PrivateKey, parsed.value, parsed.sequence, lifetimeMs);
  return marshalIpnsRecord(record);
  // [FIX]: no check here that record.validity > (existing record's validity). CipherBox's
  // ParsedIpnsRecord (packages/crypto/src/ipns/parse-record.ts) does not currently surface
  // `validity` at all — the underlying `ipns` package's `unmarshalIPNSRecord()` result DOES
  // have it (a Date). Either extend ParsedIpnsRecord with `validity: Date`, or call
  // `unmarshalIPNSRecord` directly here to read the existing record's validity for comparison.
}
```
`CipherBox`'s `ParsedIpnsRecord` type (`packages/crypto/src/ipns/parse-record.ts:11-26`) exposes `value`, `sequence`, `signatureV2`, `data`, `pubKey` — **not `validity`**. Extending it is a small, low-risk cross-package (`@cipherbox/crypto`) change; confirm no other consumer of `ParsedIpnsRecord` is broken by an additive field (it's additive, so should be safe — grep `ParsedIpnsRecord` consumers before finalizing the plan).

### The "corrupted key" test gap (current, `apps/tee-worker/src/__tests__/key-manager.test.ts:216-230`)
```typescript
it('throws generic error (not ReEnrollRequiredError) for corrupted key in non-stale range', async () => {
  setInternalEpoch(10);
  const testKey = randomTestKey();
  const kp = await getKeypair(5);
  const encrypted = await wrapKey(testKey, kp.publicKey); // valid ciphertext, WRONG epoch — this is
  // an epoch-mismatch scenario, not ciphertext corruption. The test name over-promises.
  let caughtErr: unknown;
  try { await decryptWithFallback(encrypted, 9); } catch (err) { caughtErr = err; }
  expect(caughtErr).not.toBeInstanceOf(ReEnrollRequiredError);
});
```
Fix: add a genuinely corrupted-ciphertext case (e.g. flip a byte in `encrypted` after `wrapKey` — `encrypted[10] ^= 0xff`) and assert the SAME non-`ReEnrollRequiredError` outcome, OR rename the existing test to reflect it's an epoch-mismatch case and add the byte-flip case as a new, separately named test.

## State of the Art

Not applicable — no external framework/library version drift is relevant to this phase; every fix targets in-repo control flow.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `apps/desktop/src-tauri/src/fuse/prepopulate.rs:117,455` (source todo's cited lines) do not correspond to an un-zeroed bare-key copy in the CURRENT file (157 lines total, all `[u8;32]` handling already copy-out-of-inode) | Runtime State Inventory / Anti-Patterns | If the todo's original diagnosis referenced a different revision or a different file than found here, a genuine zeroization gap could be missed. Recommend the planner re-grep `apps/desktop/src-tauri/src/fuse/*.rs` for any transient `Vec<u8>`/bare-array key copy at plan-authoring time rather than trusting either the stale line numbers or this research's "nothing found" conclusion as final. |
| A2 | The todo's "epoch out of MIN/MAX range" config/infra error in `getKeypair()` does not exist as a literal throw in the current `tee-keys.ts`; the two real config/infra throw sites are the simulator-in-production guard and the unexpected-SDK-return-shape guard | SC3 §2 / Code Examples | If a MIN/MAX range check is added elsewhere between now and implementation, the typed-error design should cover it too — grep `tee-keys.ts` fresh before finalizing the `TeeKeyUnavailableError` throw sites. |
| A3 | Extending `ParsedIpnsRecord` with a `validity: Date` field is safe (additive) for all existing consumers | SC3 §4 / Don't Hand-Roll | Not verified by grepping every consumer in this research pass — the planner should grep `ParsedIpnsRecord` usages across `packages/`, `apps/api`, `apps/tee-worker` before landing the type change, though an additive optional/always-present field on an existing interface is a very low-risk TS change. |

**If this table is empty:** N/A — see entries above; all three are low-risk, flagged for a final grep-check at implementation time rather than genuine unresolved unknowns.

## Open Questions

1. **Should the vault-init recovery path (decrypt-and-resume) also verify the root-folder record's content actually unseals under the recovered keys, or is "both IPNS names resolve" sufficient to proceed to `/vault/init`?**
   - What we know: `initialize_vault` never currently calls `ecies::unwrap_key` — only `fetch_and_decrypt_vault` does, and it also fetches+unseals the root PublishedNode's read-body as an implicit round-trip check (not currently — it just stores the keys; the FIRST real unseal happens later when FUSE mounts).
   - What's unclear: Whether the recovery path should proactively fetch+unseal the root folder's `read_sealed` bytes under the recovered `root_read_key` as a coherency check (extra network round-trip, extra complexity) versus trusting that "both records resolve, key blob decrypts" is good enough and letting a later mount-time unseal failure surface any remaining inconsistency.
   - Recommendation: Do the proactive unseal check — it's one extra `ipfs::fetch_content` + `unseal_node` call (both primitives already used in this exact file's `#[cfg(test)]` round-trip tests, `vault.rs:396-469`), and failing fast during init with a clear error is much better UX than a cryptic FUSE-mount-time failure days later.

2. **Should the `tee-worker` vitest unit tests be added to CI's `Test` job as part of this phase, or is that out of scope?**
   - What we know: `ipns-signer.test.ts` and `key-manager.test.ts` are both SC3 targets whose correctness this phase depends on, and neither currently runs in any CI job (confirmed: `ci.yml`'s `Test` job package list is `api, crypto, core, sdk-core, sdk, api-client` — no `tee-worker`).
   - What's unclear: Whether adding a CI step is in scope for a hardening phase whose source todos don't mention CI config, or whether it should be filed as a follow-up todo instead.
   - Recommendation: Flag this explicitly to the planner as a judgment call; the safest default is to add `apps/tee-worker` to the existing `Test` job (small, additive `ci.yml` change, low risk) so this phase's own test-hardening work (SC3 §5/§6, both TDD-eligible) is actually enforced going forward — otherwise the phase adds tests that nothing ever runs.

## Environment Availability

Skip — this phase makes no new external tool/service dependency. All required tooling (`cargo`, `pnpm`/`vitest`, existing CI runners) is already integrated project-wide; no new runtime dependency is introduced.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Rust (SC1, SC2) | `cargo test` (workspace), existing `#[cfg(test)]` modules in `vault.rs`, `metadata.rs`, `fs.rs`, `delete.rs` |
| TypeScript (SC3) | `vitest` — config `apps/tee-worker/vitest.config.ts` (existing), `apps/api` uses Jest per `package.json test` script for API-side tests |
| Quick run (Rust, this phase's touched crates) | `cargo test -p cipherbox-fuse` / `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml` (macOS/Linux only — NOT Windows platform module) |
| Quick run (TS, TEE) | `pnpm --filter cipherbox-tee-worker test` (NOT currently run in CI — see Pitfall 6 / Open Question 2) |
| Quick run (TS, API) | `pnpm --filter cipherbox-api test -- republish.service` (or equivalent Jest filter) |
| Full suite | `cargo test` (workspace) + `pnpm --filter cipherbox-tee-worker test` + `pnpm --filter cipherbox-api test`; Windows-specific: CI-only, `Cargo Check & Test (Windows)` job |

### Phase Requirements → Test Map

| SC | Behavior | Test Type | Automated Command | File Exists? |
|----|----------|-----------|-------------------|-------------|
| SC1 | Preflight aborts on transient resolve error (never treats non-404 as absent) | unit | `cargo test -p cipherbox-desktop preflight` (new test, name TBD by planner) | ❌ Wave 0 — add to `vault.rs`'s `#[cfg(test)]` module |
| SC1 | Preflight aborts when either name already resolves and recovery is impossible/inconsistent | unit | same module, new test | ❌ Wave 0 |
| SC1 | Recovery path: existing key blob + root folder recovered and `/vault/init` reached without re-publishing | unit (mocked resolve) or integration | new test; existing `init_recover_v3_round_trips` (`vault.rs:477`) is the closest existing pattern to extend | ❌ Wave 0 — extend existing round-trip test pattern |
| SC1 | End-to-end vault init still works for a genuinely fresh user | E2E | Desktop E2E (`desktop-e2e.yml`), existing suite already covers first-time vault init | ✅ existing |
| SC2 item 1 | `spawn_metadata_publish`-equivalent path succeeds on attempt 3/4/5 (no 5→2 regression) | unit | `cargo test -p cipherbox-fuse publish_with_cas_retry` — extend the existing `run_publish_retry_seam` harness (`metadata.rs:588-646`) with a `max_attempts` param and a 5-attempt case | ❌ Wave 0 — existing seam is the right pattern, needs a new test using it |
| SC2 item 1 | Regression: existing 2-attempt callers (`spawn_bin_entry_publish`) unaffected | unit | existing tests `publish_with_cas_retry_*` (`metadata.rs:649-727`) — MUST still pass unmodified in shape (may need `max_attempts` arg added to the seam signature) | ✅ existing (needs signature update, not new coverage) |
| SC2 item 2 | Global FP-resolve cap holds across 2+ consecutive refresh cycles (cross-cycle, not just per-cycle) | unit | `cargo test -p cipherbox-fuse` — extend the existing `unmutated_populates_and_spawns_resolution`-style tests (`fs.rs:929-947`) with a 2-cycle scenario asserting `resolving_file_pointers.len() <= MAX_CONCURRENT_FP_RESOLVES` after the second cycle | ❌ Wave 0 |
| SC2 item 3 | Windows D-07 write child_id keys by stored `node_id`, not `uuid_from_ino` | unit + E2E | Windows-only `cargo test`; CI job `Cargo Check & Test (Windows)` | ❌ Wave 0 (Windows-only test file) — **verification is CI-only, `autonomous:false`** |
| SC2 item 3 | Cross-client materialized-node delete/bin-capture round-trip on Windows | E2E | `Desktop E2E (windows-latest)` matrix leg | ✅ existing suite exercises delete/bin; confirm it covers a materialized (not just freshly-created) node on Windows specifically — may need a targeted regression test mirroring the Unix one from commit c4d30e598 |
| SC2 item 4 | Zeroization changes don't alter behavior (pure hygiene) | unit (existing) | `cargo test -p cipherbox-fuse` — existing suites must stay green; no NEW test strictly required (this is defense-in-depth, not a behavior change) | ✅ existing (regression-only) |
| SC3 §1 | `renewIpnsRecordEol` real DB error logs at `error` level (not `warn`), CAS-miss stays non-fatal `debug` | unit | `pnpm --filter cipherbox-api test` — new test asserting `logger.error` called on a thrown exception path vs `logger.debug` on `affected===0` | ❌ Wave 0 |
| SC3 §2 | `decryptWithFallback` rethrows a `getKeypair()` config/infra error instead of masking as corrupted-key | unit | `pnpm --filter cipherbox-tee-worker test` — new test mocking `getKeypair` to throw `TeeKeyUnavailableError`, asserting `decryptWithFallback` rethrows (not the generic "ECIES decryption failed" message) | ❌ Wave 0 |
| SC3 §3 | Null/non-object entry in republish batch does not crash the whole route (500) | unit/integration | `pnpm --filter cipherbox-tee-worker test` — new test posting a batch with a `null` entry, asserting a 200 with a per-entry `success:false` result, not a 500 | ❌ Wave 0 |
| SC3 §4 | `renewIpnsRecord` rejects/handles an equal-or-earlier EOL relative to the parsed existing record | unit | `pnpm --filter cipherbox-tee-worker test` — new test in `ipns-signer.test.ts` asserting `renewed.validity > original.validity`, plus the "original lifetime longer than default renewal window" edge case | ❌ Wave 0 |
| SC3 §5 | "Corrupted key" test genuinely corrupts ciphertext (not just epoch-mismatch) | unit | `pnpm --filter cipherbox-tee-worker test` — fix existing test in `key-manager.test.ts:216-230` (see Code Examples) | ⚠️ exists but tests the wrong branch — fix required, not new |

### Sampling Rate
- **Per task commit:** targeted `cargo test -p cipherbox-fuse` / `cargo test -p cipherbox-desktop` (Rust tasks) or `pnpm --filter cipherbox-tee-worker test` / `pnpm --filter cipherbox-api test` (TS tasks) scoped to the touched file.
- **Per wave merge:** full `cargo test` (workspace, mac/Linux) + full `pnpm --filter cipherbox-tee-worker test` + `pnpm --filter cipherbox-api test`.
- **Phase gate:** All of the above, PLUS (for SC2 item 3 only) the `Cargo Check & Test (Windows)` and `Desktop E2E (windows-latest)` CI jobs must be green before that specific plan is considered complete — this cannot be sampled locally.

### Wave 0 Gaps
- [ ] `vault.rs` `#[cfg(test)]` module — preflight abort-on-transient-error test, preflight abort-on-unrecoverable-conflict test, recovery-path (decrypt-and-resume) round-trip test
- [ ] `metadata.rs` `run_publish_retry_seam` — extend with `max_attempts` param + a 5-attempt-succeeds-on-attempt-5 test case
- [ ] `fs.rs` — cross-cycle global FP-resolve cap test (2+ consecutive `drain_refresh_completions` cycles)
- [ ] Windows-only `write_ops.rs` test for `node_id`-keyed `child_id` on cleanup/delete — CI-only, cannot be authored/verified locally on this machine
- [ ] `apps/api` — `renewIpnsRecordEol` real-DB-error-vs-CAS-miss log-level test
- [ ] `apps/tee-worker` — `decryptWithFallback` config/infra-error-rethrow test (requires introducing `TeeKeyUnavailableError`)
- [ ] `apps/tee-worker` — republish route null-entry defense-in-depth test
- [ ] `apps/tee-worker` — `ipns-signer.test.ts` later-EOL invariant test + longer-original-lifetime edge case
- [ ] `apps/tee-worker` — `key-manager.test.ts` genuine-ciphertext-corruption test
- [ ] Framework install: none needed — `cargo test` and `vitest` are both already configured; **however** consider adding `apps/tee-worker` to `ci.yml`'s `Test` job so the new/fixed tests above are actually enforced by CI (see Open Question 2 — recommended but the planner should make the final call on in-scope-vs-follow-up)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | Unaffected — this phase doesn't touch login/session |
| V3 Session Management | no | Unaffected |
| V4 Access Control | no | Unaffected — D-07 dual-keying correctness (SC2 item 3) is a data-identity bug, not an authz bypass (the write plane is already access-gated elsewhere; this only affects which `child_id` a `WriteChildRef` is sealed under) |
| V5 Input Validation | yes | SC3 §3's per-entry null guard is exactly a V5 control — validate `entry` shape at the trust boundary before dereferencing |
| V6 Cryptography | yes | SC1's ECIES-unwrap-based recovery reuses the existing `cipherbox_crypto::ecies` primitive (never hand-rolled); SC3 §4's EOL invariant strengthens (never weakens) the existing Ed25519 IPNS signing primitive from the `ipns` package — no new crypto primitive introduced anywhere in this phase |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Fail-open on ambiguous IPNS resolve state (treating "can't tell" as "absent") | Tampering / Elevation of Privilege | SC1's explicit fail-closed preflight (already the design goal, per the source todo's own framing — this research just makes the recovery-path corollary explicit) |
| Malformed/hostile relay batch entry crashing the whole TEE republish route | Denial of Service | SC3 §3's per-entry null/shape guard — the relay is "trusted" per the todo, but defense-in-depth against a malformed payload (bug, not necessarily malice) still applies |
| Key material lingering in un-zeroed transient buffers | Information Disclosure | SC2 item 4's `Zeroizing`/`clear_bytes` hygiene pass — defense-in-depth; every target already verified as a locally-owned copy (no caller-buffer-zeroing risk per the established project trap) |
| Masking a genuine infra/config failure as "corrupted key," delaying operator detection of a broken deployment | Repudiation (of the true failure signal) | SC3 §2's typed error rethrow — a misconfigured TEE (e.g. simulator mode accidentally left on in production) should surface loudly, not be silently retried-and-swallowed as if every key were simply corrupted |

## Sources

### Primary (HIGH confidence)
- `apps/desktop/src-tauri/src/commands/vault.rs` (this worktree) — `initialize_vault`, `fetch_and_decrypt_vault`, existing round-trip tests
- `crates/fuse/src/metadata.rs` (this worktree) — `publish_with_cas_retry`, `spawn_metadata_publish`, `spawn_bin_entry_publish`, existing `run_publish_retry_seam` test harness
- `crates/fuse/src/fs.rs` (this worktree) — FP-resolve loop lines 594-706, existing refresh-cycle tests lines 804-947
- `crates/fuse/src/platform/windows/write_ops.rs` (this worktree) — `cleanup()` D-07 bin-capture, lines 649-730+
- `crates/fuse/src/write_ops/implementation/delete.rs` (this worktree) — the already-shipped Unix `inode.node_id.clone()` fix, lines 172-186, 411-425
- `crates/fuse/src/journal_helpers.rs` (this worktree) — `parent_node_keys` (4-tuple with dead `_parent_ipns_key`), `MkdirJournalResult.parent_ipns_private_key: Vec<u8>`
- `crates/fuse/src/write_ops/implementation/mkdir.rs` (this worktree) — `parent_ipns_private_key.try_into()` bare-array copy, lines 168, 212
- `apps/desktop/src-tauri/src/fuse/mod.rs` (this worktree) — `copy_from_slice`-with-silent-truncation pattern, lines 211-224
- `apps/desktop/src-tauri/src/fuse/prepopulate.rs` (this worktree) — verified no matching un-zeroed pattern at the todo's cited line numbers (see Assumption A1)
- `apps/api/src/republish/republish.service.ts` (this worktree) — `renewIpnsRecordEol` lines 459-492, call site lines 200-221, `totalSucceeded`/`totalFailed` accounting lines 131-273
- `apps/tee-worker/src/services/key-manager.ts` (this worktree) — `decryptWithFallback` lines 77-110
- `apps/tee-worker/src/services/tee-keys.ts` (this worktree) — `getKeypair` throw sites, `MIN_EPOCH`/`MAX_EPOCH` usage (see Assumption A2)
- `apps/tee-worker/src/routes/republish.ts` (this worktree) — batch loop lines 76-204, missing null guard
- `apps/tee-worker/src/services/ipns-signer.ts` (this worktree) — `renewIpnsRecord` full file
- `packages/crypto/src/ipns/parse-record.ts` (this worktree) — `ParsedIpnsRecord` type (no `validity` field today)
- `packages/core/src/ipns/create-record.ts` (this worktree) — `createIpnsRecord`, underlying `ipns` package `createIPNSRecord` call
- `apps/tee-worker/src/__tests__/ipns-signer.test.ts` (this worktree) — existing byte-inequality-only test, full file read
- `apps/tee-worker/src/__tests__/key-manager.test.ts` (this worktree) — existing "corrupted key" test that actually tests epoch-mismatch, lines 200-230
- `crates/api-client/src/ipns.rs` (this worktree) — `resolve_ipns` (raw, `ApiError::IpnsNotFound`), `resolve_ipns_verified`/`VerifyError` (verified chokepoint), lines 1-330+
- `crates/api-client/src/error.rs` (this worktree) — `ApiError` enum variants
- `crates/crypto/src/lib.rs`, `crates/crypto/src/utils.rs` (this worktree) — `clear_bytes` availability, `[VERIFIED: crates/crypto/src/lib.rs]`
- Git commit `c4d30e598a0f2a34f5a5bd89aa19db6f42ac705f` (this worktree's history) — "fix(69): key D-07 write plane by stored node id not local ino" — the exact Unix precedent SC2 item 3 must mirror
- `.github/workflows/ci.yml`, `.github/workflows/ci-e2e.yml`, `.github/workflows/desktop-e2e.yml` (this worktree) — CI job names/scopes (`Test`, `Cargo Check & Test (Windows/macOS/Linux)`, `Desktop E2E (matrix)`, `sdk-e2e`), confirming `tee-worker` unit tests are absent from `Test`
- `.planning/todos/pending/2026-06-26-vault-init-publish-ordering-preflight.md`, `2026-07-07-fuse-publish-and-concurrency-hardening-deferred.md`, `2026-07-01-tee-republish-writepath-error-handling-hardening.md`, `2026-07-01-renew-ipns-record-eol-invariant-and-tests.md` — the 4 source-of-truth todos (locked scope)
- `.planning/ROADMAP.md` (Phase 76 section) — goal, depends-on, success criteria
- `.planning/STATE.md` (tail) — confirms Phase 77 already renamed `encryptedIpnsPrivateKey` terminology consistently (no additional terminology drift for this phase to fix)
- `./CLAUDE.md` — terminology standards, critical security rules (ECIES for key wrapping, AES-256-GCM for content, TEE hardware-only decrypt/sign/discard)

### Secondary (MEDIUM confidence)
None — no web/external documentation lookups were needed for this phase; every finding is grounded directly in the repository's own source and git history.

### Tertiary (LOW confidence)
None.

## Metadata

**Confidence breakdown:**
- Standard stack: N/A — no new libraries
- Architecture: HIGH — every code path cited was read directly in this worktree, line numbers verified against actual file contents (not assumed from the todos)
- Pitfalls: HIGH — Pitfall 1 (vault-init recovery) is a novel finding from this research pass (not explicitly stated in the source todo, which only asks the question); Pitfalls 2-6 are directly grounded in source-todo diagnosis cross-checked against live code

**Research date:** 2026-07-11
**Valid until:** No external time pressure (all in-repo); revalidate if any of the 12 target files change materially before planning begins (e.g. if Phase 77's already-completed work or any other in-flight branch touches these files further).
