# Phase 60: IPNS Verification Cross-Layer Closeout — Research

**Researched:** 2026-06-24
**Domain:** IPNS cryptographic verification (Rust/TS/NestJS cross-layer cutover + API hot-path caching)
**Confidence:** HIGH

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- D-01: Strict / no-legacy rip-out, not a gated migration. Full cutover: remove all degraded-acceptance
  branches, unify producers, regenerate the vector, wipe staging. No migration tooling, no TEE-drain
  pass, no forward-compat skew window.
- D-02: Unify ALL first-publish producers to embed sequence `1` (7 sites — see D-02 list).
- D-03: Tighten API first-publish gate to reject embedded `0`; require `1`.
- D-04: Remove all Rust degraded-acceptance paths (Legacy variant + 9 caller arms + skew disjunct at
  verify.rs:124).
- D-05: Remove all TS degraded-acceptance paths (legacy else at sdk-core/ipns/index.ts:293-295, skew
  disjunct at :285-292).
- D-06: Remove all API degraded-acceptance paths (codec null-return, seq-override, service nullable
  enrich branches).
- D-07: Add resolve-side EOL/expiry enforcement (both Rust and TS verifiers).
- D-08: Close `crates/sdk` unverified bypasses via an `api-client` verified-resolve wrapper.
- D-09: Route desktop Tauri resolve_ipns sites through the verified resolver.
- D-10: Regenerate the cross-language verify vector (reclassify legacy-absent and first-publish-skew
  to invalid; regenerate verify.json; update Rust test classifier).
- D-11: Recover per-op verification CPU on the publish/resolve hot path (safe short-circuit + measured
  cost recovery).
- D-12: Land the cutover cross-layer in lockstep (embed-1 producers + strict verify + staging wipe
  ship together; no layer flipped alone).

### Claude's Discretion

- Exact crate placement of the shared verified-resolve wrapper (D-08) — `api-client` vs new shared
  crate — chosen to minimize dependency churn.
- Caching mechanism for D-11 (in-process map vs Redis short-TTL) and exact short-circuit predicate,
  provided untrusted/DHT records are always verified.
- Wave/ordering for lockstep changes, provided D-12 invariant holds.

### Deferred Ideas (OUT OF SCOPE)

- Restoring previously-uploaded file content after a wipe.
- `tee_key_state` re-seed verification after wipe.

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                                                                                 | Research Support                                                                                                                           |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| HARD-11 | IPNS verification cross-layer closeout — route remaining desktop Tauri resolve_ipns sites through verified resolver, and recover per-op verification CPU via safe short-circuit / verified-record cache that still fully verifies untrusted/DHT records | Verified resolver placement in api-client (D-08/D-09), EOL enforcement path (D-07), safe DB-authoritative short-circuit predicate (D-11), lockstep wave design (D-12) |

</phase_requirements>

## Summary

Phase 60 is a cryptographic cutover, not a feature build. Its two hard invariants are: (1) no
embedded-0 IPNS record survives when strict verification goes live, and (2) no externally-sourced /
DHT record is ever trusted without a full signature verification. Everything else — wave ordering,
caching mechanism, wrapper placement — is sequencing and implementation detail.

The CONTEXT.md inventory is largely correct but contains seven line-number corrections: the FUSE
`verify.rs` `Legacy` variant, skew disjunct, and `bind_verified` logic are in `crates/fuse/src/verify.rs`
(not `crates/api-client/src/ipns.rs`). The api-client file `crates/api-client/src/ipns.rs` contains
`verify_ipns_resolve_signature` (the `Option<bool>` producer) which is the `Ok(None)` branch at
lines 78-79, not 77-80. The TS `console.warn` legacy fall-through is at line 294, not 293-295.
The API `parseCachedRecord` currently returns a cid-only struct (not null) when `signedRecord` is null —
the codec's current behavior is a plain cid-only result at line 82 (falls through to `return { cid, seq }`),
not a 404; tightening this is the D-06 change. Several API service lines the CONTEXT references
(494, 512-520) do not exist in the 552-line file — the resolve enrichment is at lines 494-519 (the
`withCachedPublicKey` / equal-seq enrich block), confirmed by reading the file.

The `ipns/validator` `validate()` function (used in `packages/crypto/src/ipns/verify-record.ts`)
DOES check EOL expiry (line 37: `NanoDate.fromString(record.validity).toDate().getTime() < Date.now()`),
throwing `RecordExpiredError` when expired. This is the correct target for D-07 TS expiry enforcement.

**Primary recommendation:** Add `resolve_ipns_verified` to `crates/api-client`, move the TS resolve
path through the `ipns/validator` `validate()` API for expiry, tighten the Rust verifier skew and
legacy branches to strict equality, and ship in two waves: Wave 1 = all producer sites unified to
embed `1` + strict verify active + API gate tightened; Wave 2 = staging wipe + vector regen.

## Architectural Responsibility Map

| Capability                                  | Primary Tier        | Secondary Tier       | Rationale                                                                                                    |
| ------------------------------------------- | ------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------ |
| IPNS signature verification (publish-path)  | API / Backend       | —                    | Server is the only party that receives the raw record and can verify before persisting                       |
| IPNS signature verification (resolve-path)  | Client / SDK        | API (for DB records) | Client cannot trust the server's CID; must verify the signed CBOR independently                             |
| Verified-resolve wrapper                    | `cipherbox-api-client` | —                 | All resolve consumers (FUSE, sdk, desktop Tauri) already depend on this crate                                |
| EOL/expiry enforcement                      | Client / SDK (TS)   | Rust verifier        | Expiry check belongs on the resolve path where a stale record would be acted upon                            |
| DB-authoritative short-circuit              | API / Backend       | —                    | Only the server knows a record was just persisted by THIS server (DB-authoritative predicate)                |
| Cross-language vector                       | `tests/vectors/`    | `crates/fuse/tests/` | Shared fixture in tests/vectors; Rust test in crates/fuse (the only crate that depends on both api-client + core) |

## Inventory Verification (vs CONTEXT.md `<specifics>`)

### Confirmed items (line numbers verified by symbol)

| CONTEXT # | File:Line (CONTEXT claim)                   | Actual Line | Symbol / Finding                                                                              | Verdict     |
| --------- | ------------------------------------------- | ----------- | --------------------------------------------------------------------------------------------- | ----------- |
| 1         | `crates/api-client/src/ipns.rs:77-80`       | 78-79       | `if !sig_present && !data_present && !pub_key_present { return Ok(None); }` — legacy allow   | LINE SHIFT  |
| 2         | `crates/fuse/src/verify.rs:68-72`           | 69-71       | `None => Err(VerifyError::Legacy { cid, seq })` in `bind_verified`                          | LINE SHIFT  |
| 3         | `crates/fuse/src/verify.rs:124`             | 124         | `let seq_ok = embedded_seq == resp_seq \|\| (resp_seq == 1 && embedded_seq == 0);` — skew   | CONFIRMED   |
| 4         | `crates/fuse/src/verify.rs:138-145`         | 138-145     | Returns `resp_seq` comment on the "DB-authoritative" return                                  | CONFIRMED   |
| 5         | `VerifyError::Legacy` variant `:21-24`/`:34-37` | 21-24 / 30-39 | Variant + Display impl in `crates/fuse/src/verify.rs`                                    | CONFIRMED   |
| 6         | `crates/sdk/src/registry.rs:170`            | 170         | `cipherbox_api_client::ipns::resolve_ipns(api, ipns_name)` in `fetch_and_decrypt_registry`  | CONFIRMED   |
| 7         | `crates/sdk/src/sync.rs:201`                | 201         | `cipherbox_api_client::ipns::resolve_ipns(&self.state.api, &root_ipns_name)` in `poll()`   | CONFIRMED   |
| 8         | `sdk-core/ipns/index.ts:293-295`            | 293-295     | `console.warn('IPNS resolve returned without signature data, skipping verification')`        | CONFIRMED   |
| 9         | `sdk-core/ipns/index.ts:285-292`            | 285-292     | `const seqOk = embeddedSeqBigInt === responseSeqBigInt \|\| (1n && 0n)` skew disjunct       | CONFIRMED   |
| 10        | `ipns-record.codec.ts:81-82`                | 58/82       | `parseCachedRecord`: if `!cached?.latestCid` → null (58), else cid-only struct at 82        | CORRECTION (see below) |
| 11        | `ipns-record.codec.ts:67-75`                | 68-76       | `withCachedPublicKey`: enriches pubKey when missing — NOT a seq-override                     | CORRECTION (see below) |
| 12        | `ipns.service.ts:279-285`                   | 279-285     | `if (embeddedSeq !== 0n && embeddedSeq !== 1n)` — first-publish 0n OR 1n accepted           | CONFIRMED   |
| 13        | `ipns.service.ts:226`, `:494`, `:512-520`   | 494-519     | Resolve enrichment block (withCachedPublicKey call + equal-seq enrich)                       | LINE CORRECTION |
| 14        | Vector `verify.json` + `ipns_verify_vectors.rs:88-89/134/164` | 88-90, 134, no :164 | `None => "legacy"`, `seq_ok = ... \|\| (resp_seq == 1 && embedded_seq == 0)` | CONFIRMED |

### Corrections and additions to CONTEXT inventory

**Correction — CONTEXT item 10 (`codec.ts:81-82`):** The CONTEXT says `parseCachedRecord` returns
`null` when `signed_record IS NULL`. Reading the actual file (lines 57-83): the current behavior
returns a bare cid-only struct `{ cid: cached.latestCid, sequenceNumber: cached.sequenceNumber }`
at line 82 when `signedRecord` is null (no throw, no 404). This is the legacy tolerance to remove
(D-06): the strict change is `if (!cached.signedRecord) return null` — turning a cid-only 200 into
a 404. The CONTEXT intent is correct but the file currently does NOT return null; it returns a
cid-only result.

**Correction — CONTEXT item 11 (`codec.ts:67-75`):** `withCachedPublicKey` (lines 85-97) enriches
pubKey onto a result that already has signatureV2+data, NOT a sequence override. There is no
embedded≠DB-seq silent override in the codec — the sequence-override behavior described in D-06 item
11 is in `parseCachedRecord` line 75: `return { ...parsed, cid: cached.latestCid, sequenceNumber: cached.sequenceNumber }` — this always forces the DB `sequenceNumber` onto the returned result even if the signed record's embedded sequence differs. That IS the implicit override, just at a different line.

**Correction — CONTEXT item 13 service line numbers:** The API service file is 552 lines total.
Lines 494 and 512-520 are within `resolveRecord`. Line 494 is `result = withCachedPublicKey(result, cached.publicKey)`.
Lines 512-519 are the equal-seq `signatureV2` enrich block. The CONTEXT's characterization of these
as "nullable pubkey/signedRecord enrich" is accurate in intent but line `:226` points to a comment
line inside `upsertFolderIpns`. The actual nullable-publicKey enrich guard in the service is not a
separate standalone path — it's handled by `withCachedPublicKey` (codec) called from resolve. No
separate "legacy enrich branch at :226" was found.

**Producer corrections — additional embedded-0 sites not in CONTEXT:**
The CONTEXT lists 7 producers. Verification found 2 additional Rust producers embedding sequence 0:
- `apps/desktop/src-tauri/src/commands/vault.rs:109` — `create_ipns_record(... 0, ...)` for vault key blob (Rust desktop, first-publish)
- `apps/desktop/src-tauri/src/commands/vault.rs:154` — `create_ipns_record(... 0, ...)` for root folder metadata (Rust desktop, first-publish)

These are FUSE/desktop-side vault initialization paths that embed 0. They MUST be unified to embed 1 under D-02. The CONTEXT lists "sdk-core/vault/index.ts:44" and two useAuth.ts sites for the TS vault init, but missed the Rust desktop vault initialization in `commands/vault.rs`. This brings the total first-publish producer count to 9.

**FUSE `verify.rs` placement clarification:** CONTEXT item 5 refers to callers including `events.rs`,
`metadata.rs` ×3, `publish.rs` ×2, `fs.rs`, `replay.rs` ×2. All confirmed present. These callers
use `VerifyError::Legacy` arms that warn and proceed. Verified: `events.rs:92` is a Legacy arm.

**D-09 desktop Tauri resolve sites (corrected paths):**
CONTEXT says `prepopulate.rs` and `vault.rs` — actual files are:
- `apps/desktop/src-tauri/src/fuse/prepopulate.rs` (not `src/prepopulate.rs`)
- `apps/desktop/src-tauri/src/commands/vault.rs` (not `src/vault.rs`)

Actual resolve_ipns calls:
- `fuse/prepopulate.rs:43` — root IPNS resolve
- `fuse/prepopulate.rs:110` — file pointer IPNS resolve (root-level files)
- `fuse/prepopulate.rs:177` — subfolder IPNS resolve
- `fuse/prepopulate.rs:236` — file pointer IPNS resolve (subfolder files)
- `commands/vault.rs:21` — vault_settings IPNS resolve (load_vault_settings)
- `commands/vault.rs:250` — vault_key blob IPNS resolve (fetch_and_decrypt_vault)

All 6 sites are raw `resolve_ipns` with no verification. CONTEXT's line approximations (~43, ~110,
~177, ~236, ~21, ~250) are all within ±2 lines of actual — treat as accurate.

## Open HOW Questions — Answers

### Q1: D-08 Verified-Resolve Wrapper Placement

**Dependency graph:**
- `cipherbox-api-client` depends on: `cipherbox-crypto` only
- `cipherbox-core` depends on: `cipherbox-crypto`
- `cipherbox-fuse` depends on: `cipherbox-crypto`, `cipherbox-core`, `cipherbox-api-client`, `cipherbox-sdk`
- `cipherbox-sdk` depends on: `cipherbox-crypto`, `cipherbox-core`, `cipherbox-api-client`
- `cipherbox-desktop` depends on: all five crates

`verify.rs` currently lives in `crates/fuse` because it needs both `cipherbox-api-client`
(for `resolve_ipns` + `verify_ipns_resolve_signature`) and `cipherbox-core` (for `decode_ipns_cbor_data`).
`crates/api-client` depends only on `cipherbox-crypto` — adding `cipherbox-core` as a dependency
would be a new dep but creates no cycle.

**Recommendation: Add `decode_ipns_cbor_data` import to `api-client` by adding a `cipherbox-core`
dependency, then move `bind_verified`, `VerifiedResolve`, `VerifyError`, and `resolve_ipns_verified`
into `crates/api-client/src/ipns.rs`.**

Rationale:
- Both `crates/sdk` (registry.rs:170, sync.rs:201) and `crates/fuse` already depend on `cipherbox-api-client`.
- `apps/desktop/src-tauri` also depends on `cipherbox-api-client` directly.
- Moving the verified resolver to `api-client` gives every consumer a single import with no new
  transitive dependencies beyond `cipherbox-core` (which sdk and fuse already carry).
- `crates/fuse/src/verify.rs` becomes a thin re-export or is deleted; fuse callers switch to
  `cipherbox_api_client::ipns::resolve_ipns_verified`.
- `crates/api-client/Cargo.toml` gains `cipherbox-core = { workspace = true }`.
- No circular dependency: api-client → core → crypto; fuse → api-client → core (same direction).

**Concrete API surface (what moves to `crates/api-client/src/ipns.rs`):**

```rust
pub enum VerifyError {
    Api(crate::error::ApiError),
    // Legacy variant REMOVED under D-04 — was: Legacy { cid, sequence_number }
    Invalid(String),
}

pub struct VerifiedResolve {
    pub cid: String,
    pub sequence_number: u64,
}

pub(crate) fn bind_verified(
    resp: &crate::types::IpnsResolveResponse,
    sig_verdict: Option<bool>,
) -> Result<VerifiedResolve, VerifyError>

pub async fn resolve_ipns_verified(
    api: &crate::client::ApiClient,
    ipns_name: &str,
) -> Result<VerifiedResolve, VerifyError>
```

`verify.rs` in `crates/fuse` is removed; its unit tests (`bind_verified_*`) move to `crates/api-client/src/ipns.rs` test module.

### Q2: D-07 Resolve-Side EOL/Expiry Enforcement

**TS path (RESOLVED):** `packages/crypto/src/ipns/verify-record.ts` calls `validate(peerId.publicKey, marshalledRecord)` from `ipns/validator`. The `validate()` function (confirmed in `node_modules/ipns@10.1.3/dist/src/validator.js` line 36-41) explicitly checks EOL expiry: `if (NanoDate.fromString(record.validity).toDate().getTime() < Date.now()) throw new RecordExpiredError(...)`. This validator is used on the PUBLISH path (API verify). It is NOT currently used on the resolve path — the resolve path uses the inline `verifyIpnsSignature` (sdk-core/ipns/index.ts:172-184) which checks Ed25519 sig + CBOR binding + name derivation but NOT expiry.

**TS recommendation:** Route the TS resolve path through `verifyIpnsRecordSignature` from
`@cipherbox/crypto` (which calls `validate()`) instead of (or in addition to) the inline
`verifyIpnsSignature`. The validator takes a marshalled protobuf record; on the resolve path we have
the raw field bytes from the API response, not the marshalled protobuf. Therefore:
- Option A (cleanest): deserialize the CBOR data + fields back into a marshalled IpnsEntry protobuf,
  then call `verifyIpnsRecordSignature`. This is the same byte format the API receives. Requires
  constructing the protobuf from sig+data+pubKey fields.
- Option B (simpler, inline): Parse `Validity` from the CBOR data field (key `"Validity"` is a
  bytes field containing the RFC3339 timestamp string) and compare to `Date.now()`. This keeps the
  inline resolve path without pulling in the full protobuf marshalling round-trip.

**Option B is recommended** because the resolve response fields (signatureV2, data, pubKey) are
sufficient for expiry: `Validity` is in the CBOR `data` field that is already being decoded for the
CID/seq binding check. Add the expiry check there: `const validityBytes = cborFields['Validity'];
const validityStr = new TextDecoder().decode(validityBytes); if (new Date(validityStr) < new Date()) throw new Error('IPNS record expired')`.

**Rust path (RESOLVED):** `crates/core/src/ipns.rs` has `build_cbor_data` (line 128-158) which
includes `"Validity"` as bytes (RFC3339 string) and `"ValidityType"` as integer 0 (= EOL). The
`decode_ipns_cbor_data` function (lines 81-121) only extracts `Value` and `Sequence`. To add expiry:
extend `decode_ipns_cbor_data` (or create a companion `decode_ipns_cbor_validity`) to also return
the `Validity` bytes, then compare to `SystemTime::now()` in `bind_verified`. The `Validity`
timestamp format is RFC3339 with nanosecond precision (e.g. `"2026-01-01T00:00:00.000000000Z"`); parse
with `chrono` (already available transitively or add `chrono` dep) or parse manually.

**Clock skew consideration:** Records have a 24h lifetime (set by the SDK) and TEE republishes every
6 hours. A 5-minute clock skew buffer is appropriate: reject records expiring within `now - 5min`
rather than strictly `now`. The TEE republish cadence means valid active records have at minimum
~18h remaining on a just-republished record.

### Q3: D-11 Hot-Path Caching Design

**Where verification cost is paid:** On PUBLISH, `verifyIpnsRecordSignature` is called at
`ipns.service.ts:87-89` for every publish — this invokes `ipns/validator`'s `validate()` which
unmarshals the full protobuf and verifies Ed25519. On RESOLVE, no signature verification is performed
server-side today (the API just parses and returns DB data + DHT data). The hot-path cost is on
PUBLISH, not RESOLVE.

**Safe short-circuit predicate:** A record is "DB-authoritative, already-verified" if and only if
ALL of the following are true at the moment of a resolve request:
1. The record comes from the DB (not from the DHT/someguy resolve path).
2. The DB row was created/updated by `upsertFolderIpns` (the only code path that calls
   `verifyIpnsRecordSignature` before persisting).
3. The signature field present in the DB (`signedRecord`) is the SAME bytes that were verified
   on ingest (i.e. the DB `signedRecord` bytes have not been modified by any other path).

The current code already satisfies this: `parseCachedRecord` reads `signedRecord` from DB and
`upsertFolderIpns` always verifies before writing. Therefore: **for resolve, DB records need no
re-verification** — they were verified on publish. This is a free correctness argument, not a
performance optimization per se (resolve already doesn't verify on the server side).

**The actual hot-path cost to recover (PUBLISH path):**
Ed25519 signature verification (`verifyIpnsRecordSignature`) is called once per publish operation.
For the TEE 6-hour republish cycle (idempotent re-sign of the same record with a fresh validity
window), the API currently re-verifies every republish. The `isIdempotentRepublish` path is detected
AFTER verification. A safe optimization: cache the `(ipnsName, sequenceNumber, signatureV2_bytes)`
triple in a short-TTL in-process map; if a matching entry is found within the TTL, skip
re-verification. The TEE republish publishes records signed with the current key (same publicKey,
fresh signature) — so a pure bytes-equality cache hit is not useful (fresh sig each time).

**Recommended approach for D-11:**
Rather than a signature cache keyed on bytes, the practical short-circuit is:

1. For the TEE idempotent republish path (where `embeddedSeq === dbSeq`): the record was ALREADY in
   the DB and verified on first publish. The TEE only has the encrypted IPNS key — it cannot forge
   a record with a different CID. Add a `trusted_source` flag to `IpnsPublishRequest` for TEE
   callers (republish service), and skip full `verifyIpnsRecordSignature` when `trusted_source=true`
   AND the sequence is idempotent. CAUTION: this only works if the republish endpoint is not
   callable by arbitrary clients — it requires the API to authenticate the caller as the TEE worker
   (already done via the existing republish service authentication mechanism).

   **Simpler alternative:** Since the TEE republish only happens via `RepublishService.enrollFolder`
   which is called internally, add an internal boolean parameter `skipSigVerify` to `upsertFolderIpns`
   that bypasses `verifyIpnsRecordSignature` for TEE idempotent republishes only. Gate it strictly:
   `if (skipSigVerify && isIdempotentRepublish)`.

2. For client publishes: always verify. No shortcut.

3. For RESOLVE performance: it is already short-circuited (DB path does not re-verify). DHT records
   MUST NOT be short-circuited (they are externally sourced).

**Measurement:** Add a `process.hrtime.bigint()` timing instrument around `verifyIpnsRecordSignature`
in publish and log it at `debug` level. Run the existing SDK E2E or a simple `k6` script exercising
publish × 100 and capture the per-op cost in ms. Compare TEE idempotent republish cost with and
without the skipSigVerify bypass. Document in CAPACITY.md §1.5.

**CRITICAL invariant:** Any resolve path that hits someguy (DHT) MUST verify. The predicate is:
`source !== 'db_cache'` → verify required. `source === 'db_cache'` → already verified on ingest.

**Caching mechanism recommendation:** In-process `Map<string, number>` keyed on `(ipnsName + ':' + sequenceNumber)` with a value of `Date.now()` (cache entry time), TTL 60 seconds. This covers the TEE re-sign window (6h publish cycle, entries arrive in bursts). No Redis needed; in-process cache is sufficient since the API is single-process per dyno and the TEE republishes have at most one record per IPNS name per cycle.

### Q4: D-12 Lockstep Sequencing

**Recommended wave structure:**

**Wave 1 — Producers unified + strict verify active (code changes, no data migration):**
- All 9 first-publish sites changed to embed sequence `1` (7 TS/FUSE sites + 2 desktop vault.rs sites)
- `verify.rs` skew disjunct dropped (`:124` → strict `embedded_seq == resp_seq`)
- `VerifyError::Legacy` variant removed; 9 caller arms folded to `Invalid`
- `api-client/src/ipns.rs:78-79` `Ok(None)` branch removed (→ `Some(false)`)
- `sdk-core/ipns/index.ts:293-295` console.warn legacy path deleted
- `sdk-core/ipns/index.ts:285-292` skew disjunct dropped to strict equality
- API service first-publish gate tightened to reject `0n` (D-03)
- API codec: `parseCachedRecord` returns null when signedRecord is null (D-06 item 10)
- API service: nullable-pubKey / signedRecord enrich branches removed (D-06 items 13)
- Verified-resolve wrapper moved to `api-client` (D-08)
- Desktop Tauri sites routed through verified wrapper (D-09)
- EOL expiry added to Rust `bind_verified` and TS `resolveIpnsRecord` (D-07)
- Vector generator reclassification + `verify.json` regenerated (D-10)
- `ipns_verify_vectors.rs` classifier updated (D-10)

**Wave 2 — Staging wipe:**
- Wipe staging DB (per `docs/DATABASE_EVOLUTION_PROTOCOL.md` §reset)
- Restart services; first user login self-bootstraps fresh vault (embed-1 records only)
- Smoke-test: resolve returns verified result, expired record rejected, tampered CID rejected

**D-12 invariant:** Wave 1 (strict verify active) and staging wipe MUST ship in the same deployment.
There must be no window where strict verify is live with embedded-0 records still in the DB. In
practice: merge Wave 1 PR, immediately run staging wipe as part of deployment, then verify.

**Test gates in order:**
1. `cargo test -p cipherbox-api-client` — unit tests for `verify_ipns_resolve_signature` + `bind_verified` (moved from fuse)
2. `cargo test -p cipherbox-fuse` — cross-language vector test `ipns_verify_cross_language`
3. `cargo check --target x86_64-pc-windows-msvc` (CI winfsp gate) — required for `crates/fuse/src/platform/windows/write_ops.rs` change (embed 0→1 at line 201)
4. `pnpm --filter @cipherbox/crypto test` — TS verify-record tests
5. `pnpm --filter @cipherbox/sdk-core test` — resolve throw-path tests (NEW: verify strict throw on missing fields)
6. SDK E2E (`tests/sdk-e2e`) — the only suite exercising the real client→API IPNS publish/resolve round-trip
7. Desktop E2E (`gh workflow run "CI E2E Tests"`) — dispatch-gated; covers prepopulate verify path
8. API jest (`pnpm --filter api test`) — covers `ipns.service.ts` first-publish gate + codec null return

### Q5: Blast-Radius on Consumers

**Rust consumers — `Legacy` arms folded to `Invalid`:**
All 9 caller arms must be updated. Current behavior: `Legacy` arm logs a warning and proceeds with
`resp.cid`. After change: the arm becomes the same as `Invalid` — fail the operation (return error
or ENOENT). Risk: any FUSE operation on a legacy record silently succeeds today; after strict mode it
returns an error. Since the staging wipe eliminates all embedded-0 records, no legacy record should
survive when strict verify goes live. The wipe is the critical gate.

**TS consumers — `resolveIpnsRecord` now throws instead of returning with `signatureVerified: false`:**
Current behavior on missing fields: `console.warn` + return `{ cid, sequenceNumber, signatureVerified: false }`.
Strict behavior: throw on missing fields (the else branch is deleted).

Sites that catch or check `signatureVerified: false` must handle the throw:

- `packages/sdk-core/src/cas.ts` re-resolve call — currently checks `signatureVerified` to decide
  whether to trust; after strict mode it throws, which propagates to the CAS retry caller. Callers
  of CAS retry that don't catch must be audited.
- `packages/sdk-core/bin/index.ts` — currently handles null return; throw path propagates to
  bin operations. The outer catch block at `sdk-core/ipns/index.ts:302-313` already catches 404
  errors and returns null; other errors re-throw. Callers of `resolveIpnsRecord` that do
  `.then(result => if (!result.cid)...` may not handle the throw.
- Web service callers (multiple) — any web service that calls `resolveIpnsRecord` or a wrapper and
  doesn't catch errors will surface as an unhandled rejection. Search pattern:
  `grep -rn "resolveIpnsRecord\|resolveIpns" apps/web/src packages/sdk-core/src` — each
  caller must have a try/catch or use the null-return path.

**Recommended blast-radius audit task (Wave 1 prerequisite):** Run
`grep -rn "resolveIpnsRecord\|signatureVerified" packages/ apps/web/src/` and for each call site,
confirm it either (a) is inside a try/catch that handles generic errors, or (b) is wrapped in the
null-path catch at line 302 (only catches 404). Any site relying on `signatureVerified: false` as a
non-throwing indicator needs to be updated to expect a throw.

## Standard Stack

### Core (no new packages — all existing)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|-------------|
| `ciborium` | workspace | CBOR decode/encode (Rust) | Already used in `crates/core/src/ipns.rs` for CBOR data |
| `ed25519-dalek` / `cipherbox-crypto` | workspace | Ed25519 verification | Existing crypto primitives |
| `cipherbox-core` | workspace | `decode_ipns_cbor_data` | New dep for `api-client` only |
| `ipns@10.1.3` | already installed | TS `validate()` for EOL check | Already used on publish path in `@cipherbox/crypto` |
| `cborg` | already installed | CBOR decode (TS resolve path) | Already used in `sdk-core/ipns/index.ts` |

No new npm or Cargo packages required for this phase.

## Package Legitimacy Audit

No new external packages are being introduced in this phase. All libraries referenced are already in the workspace and previously vetted.

## Architecture Patterns

### System Architecture — Verified Resolve Flow (Post Phase 60)

```
Client (TS/Rust) calls resolveIpnsRecord / resolve_ipns_verified
         |
         v
API: GET /ipns/resolve?ipnsName=...
         |
         v
API Service: resolveRecord()
  ├── DHT path (someguy resolve) → parseIpnsRecordBytes → returns { cid, seq, signatureV2, data, pubKey }
  │                                  MUST be verified client-side (external/untrusted source)
  └── DB cache path → parseCachedRecord → returns { cid, seq, signatureV2, data, pubKey }
      if signedRecord IS NULL → return null (404 to caller) [D-06]
      otherwise → return DB-verified record
         |
         v
Client receives response
  ├── All 3 sig fields present → verify sig (Ed25519) + name derivation + CBOR binding (CID + seq)
  │     + EOL expiry check [D-07]
  │     → throws on any failure (fail-closed)
  └── All 3 sig fields absent → throw (no legacy allow) [D-05, D-04]
         |
         v
Verified CID used for IPFS fetch
```

### Verified-Resolve Wrapper in `api-client` (D-08)

```rust
// crates/api-client/src/ipns.rs — new public API
pub async fn resolve_ipns_verified(
    api: &ApiClient,
    ipns_name: &str,
) -> Result<VerifiedResolve, VerifyError>
// VerifyError: Api | Invalid (Legacy removed)
// All consumers: sdk/registry.rs, sdk/sync.rs, fuse/verify.rs callers,
//               desktop/src-tauri/src/fuse/prepopulate.rs,
//               desktop/src-tauri/src/commands/vault.rs
```

### Anti-Patterns to Avoid

- **Skipping verification for DB records on the CLIENT side:** The DB record was verified server-side,
  but the client cannot know that. The client must always verify the returned sig fields.
- **Using `signatureVerified: false` as a non-error state after Phase 60:** Once the legacy path is
  removed, any unsigned record is an error, not a soft warning.
- **Caching verified status by CID alone:** CID collisions are theoretically possible; cache must
  include the full `(ipnsName, sequenceNumber, signatureV2_bytes)` triple or not cache at all.
- **Wiping staging AFTER flipping strict verify but BEFORE re-deploying:** the wipe and re-deploy
  must be atomic from the DB's perspective (no embedded-0 records survive to be strict-verified).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| EOL timestamp parsing (Rust) | Custom RFC3339 parser | `chrono::DateTime::parse_from_rfc3339` or manual string parse (format is predictable) | The format is fixed (`"2026-01-01T00:00:00.000000000Z"`); a simple string parse via `SystemTime` arithmetic suffices |
| EOL timestamp parsing (TS) | Custom nano-date parser | `new Date(validityStr).getTime()` | Validity is RFC3339; nanoseconds beyond ms precision are truncated but irrelevant for expiry checks |
| Cross-language CBOR vector generation | Manual byte construction | `scripts/gen-ipns-verify-vectors.ts` with `npx tsx` | Generator already exists; update it |
| Verified-resolve in each consumer crate | Per-crate copy of bind_verified | `cipherbox_api_client::ipns::resolve_ipns_verified` | Single implementation, single test surface |

## Common Pitfalls

### Pitfall 1: Wipe Before Strict-Verify Flip

**What goes wrong:** Strict verify goes live (merged to staging) before the DB is wiped. Any
embedded-0 record in the DB gets resolved, the CBOR binding check passes (seq 0 matches embedded 0),
but the seq strict check fails (resp_seq=1, embedded=0, no skew allowance) — all FUSE/SDK operations
on existing folders fail-closed immediately.
**How to avoid:** Deploy order must be: merge + redeploy API → wipe DB → smoke test. Not: wipe → merge.

### Pitfall 2: `VerifyError::Legacy` callers not updated

**What goes wrong:** After removing the `Legacy` variant, callers that matched on it get a compile
error. All 9 arms must be updated to `Invalid` handling before the code compiles.
**How to avoid:** The Rust compiler enforces exhaustive match; this will be a compile-time failure,
not a runtime failure. Use the compiler error list to find all 9 sites.

### Pitfall 3: Desktop vault.rs embed-0 sites missed

**What goes wrong:** CONTEXT lists 7 producers; research found 2 more (`commands/vault.rs:109` and
`:154`). If these are not updated to embed 1, the Rust desktop app will publish embed-0 records that
fail strict-verify on the next resolve.
**How to avoid:** Change both `create_ipns_record(..., 0, ...)` calls to `create_ipns_record(..., 1, ...)`.
Note: `initialize_vault` is only called on first-user setup, so the strict API gate also catches it.

### Pitfall 4: TEE idempotent republish broken by strict embed check

**What goes wrong:** TEE republishes use the stored `signedRecord` bytes from DB. If the original
record embeds sequence `N` and the DB `sequenceNumber` is `N`, the idempotent path is safe. But
if any existing staging records embedded 0 with DB seq 1 (the skew case), TEE republishes of those
records would fail the strict binding check (embedded=0, resp_seq=1, no skew allowance).
**How to avoid:** The staging wipe eliminates all such records. Local dev DBs must also be wiped
(per D-01: existing embedded-0 records fail-closed until republished).

### Pitfall 5: TS blast radius — callers expecting non-throwing resolveIpnsRecord

**What goes wrong:** Callers that rely on `resolveIpnsRecord` returning `{ signatureVerified: false }`
for legacy records (instead of throwing) silently continue with an unverified CID after Phase 60
removes the legacy path.
**How to avoid:** Audit all callers before Wave 1 merge. Look for `if (result.signatureVerified)` or
`.signatureVerified === false` patterns.

### Pitfall 6: `winfsp` build CI gate missed

**What goes wrong:** `crates/fuse/src/platform/windows/write_ops.rs` (CONTEXT line 201, embed 0→1)
compiles only on Windows. Local macOS cargo check passes; the Windows winfsp CI gate is the
authoritative check. Missing it means a broken Windows build ships.
**How to avoid:** Explicitly trigger or wait for the `Cargo Check & Test (Windows)` CI gate before
merging Wave 1.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Rust framework | `cargo test` (workspace-level) |
| TS framework | `vitest` (apps/api uses jest) |
| Quick run (Rust) | `cargo test -p cipherbox-api-client -p cipherbox-fuse` |
| Quick run (TS) | `pnpm --filter @cipherbox/sdk-core test` |
| Full suite (API) | `pnpm --filter api test` |
| SDK E2E | `tests/sdk-e2e` (requires local API + redis) |
| Desktop E2E | `gh workflow run "CI E2E Tests" --ref <branch>` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| HARD-11 (D-04) | Legacy Rust arm removed; `bind_verified(None)` → `Invalid` | unit | `cargo test -p cipherbox-api-client bind_verified` | Yes (new test after move) |
| HARD-11 (D-04) | `verify_ipns_resolve_signature` all-absent → `Some(false)` (was `None`) | unit | `cargo test -p cipherbox-api-client absent_fields` | Yes (update existing test) |
| HARD-11 (D-05) | TS resolve throws on missing fields | unit | `pnpm --filter @cipherbox/sdk-core test -- --reporter verbose` | Needs new test |
| HARD-11 (D-05) | TS resolve throws on seq skew | unit | `pnpm --filter @cipherbox/sdk-core test` | Needs new test |
| HARD-11 (D-07) | Expired record rejected (Rust) | unit | `cargo test -p cipherbox-api-client expired_record` | Needs new test |
| HARD-11 (D-07) | Expired record rejected (TS) | unit | `pnpm --filter @cipherbox/sdk-core test` | Needs new test |
| HARD-11 (D-08) | SDK registry/sync route through verified wrapper | integration | `cargo test -p cipherbox-sdk` | Needs integration test or verified wrapper unit test |
| HARD-11 (D-09) | Desktop Tauri prepopulate uses verified resolver | integration | Desktop E2E dispatch | Covered by desktop E2E |
| HARD-11 (D-10) | Cross-language vector: legacy-absent → invalid | unit | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | Yes (update classifier + verify.json) |
| HARD-11 (D-10) | Cross-language vector: first-publish-skew → invalid | unit | `cargo test -p cipherbox-fuse ipns_verify_cross_language` | Yes (update classifier + verify.json) |
| HARD-11 (D-11) | DB resolve does not re-verify (already verified on ingest) | benchmark | `npm run k6:ipns` or custom jest timing test | Needs benchmark |
| HARD-11 (D-12) | Full round-trip: publish embed-1, resolve strict-verify | e2e | `tests/sdk-e2e` | Yes (requires local API) |

### HARD-11 Acceptance Criteria (measurable)

1. `cargo test` for `cipherbox-api-client` and `cipherbox-fuse` green, including updated cross-language vector test.
2. All 8 vector cases: `legacy-absent` → expected_result: `"invalid"` (was `"legacy"`); `first-publish-skew` → expected_result: `"invalid"` (was `"valid"`).
3. TS `resolveIpnsRecord` throws (not returns) on: (a) missing signature fields, (b) invalid sig, (c) CID mismatch, (d) seq mismatch, (e) expired record.
4. API `pnpm --filter api test` green with: (a) first-publish embedded 0 rejected (400), (b) `parseCachedRecord` returns null for null-signedRecord DB rows (→ 404 to caller).
5. SDK E2E green end-to-end publish+resolve cycle.
6. Desktop E2E green (dispatch-gated).
7. Windows CI winfsp gate green.
8. Staging smoke test: resolve of a fresh (post-wipe) record passes strict verify; attempting to publish an embedded-0 record gets 400.

### Sampling Rate

- Per task commit: `cargo test -p cipherbox-api-client && pnpm --filter @cipherbox/sdk-core test`
- Per wave merge: `cargo test --workspace && pnpm --filter api test && pnpm --filter @cipherbox/sdk-core test`
- Phase gate: Full suite green + SDK E2E + Desktop E2E dispatch before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] New unit test: `bind_verified(None)` → `VerifyError::Invalid` (after Legacy removal) — in `crates/api-client/src/ipns.rs`
- [ ] New unit test: `verify_ipns_resolve_signature` all-absent → `Some(false)` — update existing test `absent_fields_returns_none`
- [ ] New unit test: expired Rust CBOR Validity check in `bind_verified`
- [ ] New unit test: TS `resolveIpnsRecord` throws on legacy-absent fields
- [ ] New unit test: TS `resolveIpnsRecord` throws on expired record
- [ ] Updated `tests/vectors/ipns/verify.json`: reclassify `legacy-absent` + `first-publish-skew` → `"invalid"`
- [ ] Updated `scripts/gen-ipns-verify-vectors.ts`: change expected_result fields, re-run `npx tsx`

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | yes | Reject embedded-0 at API gate (D-03); strict CBOR seq/CID binding (D-07/D-08) |
| V6 Cryptography | yes | Ed25519 verify (api-client `verify_ipns_resolve_signature`); CBOR binding check; EOL expiry (D-07) |

### Known Threat Patterns

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| CID substitution (MITM server returns different CID than signed) | Tampering | CBOR binding: `embedded_value == /ipfs/{resp.cid}` — strict, already present |
| Sequence rollback (replay of old valid signed record) | Repudiation | Anti-rollback check in `upsertFolderIpns` (compare incoming.sequence >= stored.sequence) + strict seq binding on resolve |
| Expired record replay | Tampering | EOL expiry check in `bind_verified` + TS CBOR validity parse (D-07, NEW) |
| Field stripping (remove sig fields to trigger legacy path) | Spoofing | Partial-fields → `Some(false)` (fail-closed); all-absent → `Invalid` (D-04/D-05) |
| Embedded-0 wedge (poison first-publish to permanently lock out) | DoS | API gate rejects embedded 0 on first publish (D-03); publish-side verify is the anchor |
| TEE key compromise enabling fake re-sign | Spoofing | Out of scope for Phase 60; handled by TEE key rotation |

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `chrono` or similar RFC3339 parser is available transitively for Rust expiry check, OR the Validity timestamp can be parsed by direct string manipulation | D-07 Rust EOL | Minor: add `chrono` to `crates/api-client/Cargo.toml` if not present |
| A2 | The Desktop E2E gate will cover the prepopulate verified-resolve path adequately | D-09 / Validation | If not, add a targeted integration test for prepopulate with a fresh record |
| A3 | TEE idempotent republish currently re-verifies via `verifyIpnsRecordSignature`; skipping it for that path is safe (it only republishes what was already DB-verified) | D-11 | If TEE republish path mutates the record before publishing, the skip is unsafe — confirm TEE worker code |

## Open Questions

1. **[RESOLVED] Does `ipns/validator` `validate()` check EOL?**
   Yes — confirmed in `node_modules/ipns@10.1.3/dist/src/validator.js:36-41`. Throws `RecordExpiredError` when expired.

2. **[RESOLVED] Where does `resolve_ipns_verified` live in the crate graph?**
   Move to `crates/api-client/src/ipns.rs`. Add `cipherbox-core` as a dep. Delete `crates/fuse/src/verify.rs`.

3. **[RESOLVED] What is the correct first-publish sequence for desktop Rust vault init?**
   `commands/vault.rs:109` and `:154` both use `create_ipns_record(..., 0, ...)`. Both must change to `1` (D-02). These are 2 additional sites not in the CONTEXT inventory.

4. **[RESOLVED] Do the CONTEXT service line numbers for `:494`, `:512-520` exist?**
   Yes — within `resolveRecord` (the 552-line file). Lines 494-519 are the `withCachedPublicKey` call and equal-seq enrich block. The `:226` reference is inside `upsertFolderIpns` comment area, not a standalone enrich branch.

5. **[OPEN — operator action] Local dev DBs:** After Wave 1 is merged, every developer with an existing local DB will have embedded-0 records that fail strict-verify. They must wipe their local DB (per `DATABASE_EVOLUTION_PROTOCOL.md §reset`) before testing. This is a developer workflow item, not a code task, but the PLAN should include a note.

6. **[OPEN — verify at plan time] TEE republish path:** Confirm that `RepublishService` calls `publishRecord` (which calls `verifyIpnsRecordSignature`). If it does, the D-11 skip-on-idempotent optimization requires gating `skipSigVerify` on the internal republish code path. If it calls `upsertFolderIpns` directly, the gate is simpler.

## Sources

### Primary (HIGH confidence)

- `crates/fuse/src/verify.rs` — full file read, all line numbers verified by symbol
- `crates/api-client/src/ipns.rs` — full file read, `Ok(None)` at lines 78-79 confirmed
- `crates/core/src/ipns.rs` — `Validity`/`ValidityType` CBOR fields confirmed in `build_cbor_data`
- `packages/sdk-core/src/ipns/index.ts` — full file read, skew at 285-292, legacy at 293-295 confirmed
- `packages/crypto/src/ipns/verify-record.ts` — `validate()` call confirmed
- `apps/api/src/ipns/ipns.service.ts` — 552 lines, all key sections read
- `apps/api/src/ipns/ipns-record.codec.ts` — 97 lines, full file read
- `apps/desktop/src-tauri/src/fuse/prepopulate.rs` — 4 resolve_ipns sites at lines 43, 110, 177, 236
- `apps/desktop/src-tauri/src/commands/vault.rs` — 2 resolve_ipns at lines 21, 250; 2 embed-0 at lines 109, 154
- `crates/sdk/src/registry.rs:170` — `resolve_ipns` confirmed unverified
- `crates/sdk/src/sync.rs:201` — `resolve_ipns` confirmed unverified
- `node_modules/ipns@10.1.3/dist/src/validator.js` — EOL check confirmed at lines 36-41
- Cargo.toml files for all 5 crates — dependency graph confirmed

### Secondary (MEDIUM confidence)

- CONTEXT.md inventory — used as starting point; corrections documented above
- `crates/fuse/tests/ipns_verify_vectors.rs` — classifier logic confirmed at lines 88-90, 134

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new packages, all existing
- Architecture (verified-resolve wrapper placement): HIGH — crate dep graph directly inspected
- EOL enforcement (TS): HIGH — validator.js source read
- EOL enforcement (Rust): HIGH — CBOR field structure confirmed in build_cbor_data
- Blast-radius (TS callers): MEDIUM — pattern search done; individual callers not exhaustively audited
- D-11 caching: MEDIUM — hot-path location confirmed; exact cost unmeasured until benchmark

**Research date:** 2026-06-24
**Valid until:** 2026-07-24 (stable domain; file/line drift possible if concurrent PRs merge)
