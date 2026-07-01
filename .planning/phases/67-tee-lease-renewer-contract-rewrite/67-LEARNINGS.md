---
phase: 67
phase_name: "tee-lease-renewer-contract-rewrite"
project: "CipherBox"
generated: "2026-07-01"
counts:
  decisions: 10
  lessons: 8
  patterns: 8
  surprises: 5
missing_artifacts:
  - "67-UAT.md"
---

# Phase 67 Learnings — TEE Lease-Renewer Contract Rewrite

## Decisions

### TEE reshaped into a pure lease-renewer

`renewIpnsRecord(ed25519PrivateKey, marshaledExistingRecord, lifetimeMs?)` re-signs a record's own value (CID) and sequence, sourced exclusively from `parseIpnsRecord` of the existing marshaled record. It takes no CID argument and no sequence argument, so a CID repoint or a sequence increment is structurally impossible. `signIpnsRecord` (create-from-scalars) was kept unchanged for back-compat.

**Rationale:** Removing the scalar inputs makes the two most dangerous tamper vectors (T-67-03-T critical, T-67-06-T critical) unrepresentable in the type signature rather than merely guarded at runtime.
**Source:** 67-03-SUMMARY.md

---

### Internal-epoch self-derivation; all relay epoch scalars removed

The TEE derives `currentEpoch` from its own clock via `getInternalCurrentEpoch()` (reads `EPOCH_ZERO_TIMESTAMP_MS`, 4-week `EPOCH_DURATION_MS`, clamped to `MIN_EPOCH=1`). `decryptWithFallback` was reshaped from the 3-arg `(encryptedIpnsKey, currentEpoch, previousEpoch)` to 2-arg `(encryptedIpnsKey, keyEpoch)`, and the republish route's epoch-upgrade target is the internally-derived epoch. Relay-supplied `currentEpoch`/`previousEpoch` were deleted from `RepublishEntry`.

**Rationale:** A relay-supplied epoch is an elevation vector (T-67-02-E, T-67-06-E). The enclave clock is the only trustworthy epoch authority.
**Source:** 67-02-SUMMARY.md, 67-06-SUMMARY.md

---

### Option-B epoch resolution — keyEpoch stays the ECIES decrypt hint

`keyEpoch` continues to serve as the decrypt hint for ECIES unwrap; `getInternalCurrentEpoch()` is used only for the stale-key floor guard and the mid-rotation fallback target. Fallback trial order is `keyEpoch` first, then `internalCurrentEpoch`. A key older than `internalCurrentEpoch - 1` throws `ReEnrollRequiredError` before any unwrap.

**Rationale:** Keeps the common-case decrypt cheap and correct while adding a hard stale floor; the grace window of one epoch preserves seamless rotation.
**Source:** 67-02-SUMMARY.md

---

### Schedule-collapse — ipns_records is the sole signing source

`IpnsRepublishSchedule` was slimmed to 7 scheduling-only columns; the migration `ScheduleCollapse1751000000000` drops `encrypted_ipns_key`, `key_epoch`, `latest_cid`, and `sequence_number`. All signing inputs are now built from the canonical `ipns_records` row, and `enrollFolder` collapsed to 2 args accordingly.

**Rationale:** A duplicated schedule snapshot is a stale-input tamper surface (T-67-01-T, T-67-07-T) and leaves crypto residue (T-67-01-I). One canonical source removes both.
**Source:** 67-01-SUMMARY.md, 67-07-SUMMARY.md

---

### getDueEntries reverted from query-builder innerJoin to the find-options API

67-07 implemented `getDueEntries` with a query-builder `innerJoin(IpnsRecord, ...)` plus raw snake_case `orderBy` and `take(2000)`. 67-08's live gate reverted it to the pre-67-07 `find`-options query paired with a second tombstone/key-filtered `ipns_records.find`, preserving the defense-layer-1 filter via a record-map null-drop.

**Rationale:** The QB take-pagination path threw a TypeORM `databaseName` metadata error at runtime that the mocked unit test could not catch; the find-options form is robust and keeps the same guarantees.
**Source:** 67-08-SUMMARY.md

---

### Verify-before-decrypt with name-key binding via deriveEd25519PublicKey

The republish route verifies the Ed25519 signature before decrypting, then byte-compares `deriveEd25519PublicKey(decryptedKey)` against `publicKeyFromIpnsName(ipnsName)`. It never trusts `parsed.pubKey` (undefined for Ed25519 records). Verify-fail and binding-fail use `continue` (early return from the per-entry loop), not throw, so `metrics.inc()` stays inline; the key is zeroed on every path.

**Rationale:** Verify-before-decrypt (T-67-06-T) and name-key binding (T-67-06-S) are both critical/high; deriving the pubkey from the decrypted key and the name closes the spoofing gap that trusting `parsed.pubKey` would leave open (T-67-06-T2).
**Source:** 67-06-SUMMARY.md

---

### renewIpnsRecordEol equality CAS replaces the weak write-back

`renewIpnsRecordEol(ipnsName, loadedSeq, renewedSignedRecord)` writes `signed_record` under a `WHERE sequence_number = :expected AND tombstoned_at IS NULL` equality CAS, replacing `syncIpnsRecordSequence` and its `LessThanOrEqual` write-back. `affected === 0` is a harmless discard (log + return), not a throw, because a forward-publish race and a tombstone both map to the same benign outcome.

**Rationale:** Equality CAS cannot regress the sequence under a forward-publish race (T-67-07-T2); treating a lost CAS as a discard avoids failing a publish that already succeeded.
**Source:** 67-07-SUMMARY.md

---

### ECIES-wrap wired inside createSubfolder with fail-closed validation

`createSubfolder` now ECIES-wraps the freshly generated IPNS private key under the TEE public key and forwards `encryptedIpnsPrivateKey`/`keyEpoch` to the first publish. It validates `teeKeys` fail-closed (throws before publish if `currentPublicKey` is empty or `currentEpoch` is non-finite). Caller-owned buffers are not zeroed (D-09 terminal-owner convention). The wrap is done in the function itself, matching `vault-settings.service.ts` and `sdk/bin/index.ts`.

**Rationale:** Without wiring, a new subfolder's `ipns_records` row lacked the data the renewer needs and expired silently after 24h (T-67-04-D); fail-closed prevents publishing an unrenewable record (T-67-04-I).
**Source:** 67-04-SUMMARY.md

---

### api:generate deliberately not run — relay-TEE surface is internal

The reshaped `RepublishEntry`/`RepublishResult` live on an internal service-to-service fetch (`TeeService.republish`). `tee.controller.ts` exposes only `connection-test` and was untouched; no public controller or DTO changed, so the generated API client was intentionally not regenerated.

**Rationale:** The CLAUDE.md api:generate rule targets public API surface. Regenerating for an internal interface would be churn with no consumer.
**Source:** 67-07-SUMMARY.md

---

### Greenfield migration — down() throws, no rollback target

`ScheduleCollapse1751000000000` drops the four columns via `DROP COLUMN IF EXISTS` in a single `ALTER TABLE` and adds `IDX_ipns_republish_schedule_ipns_name`; `down()` throws per the D-01 greenfield waiver, matching the Phase-66 analog.

**Rationale:** Pre-launch schema has no production data to roll back to; a throwing `down()` documents that intent rather than pretending a reversible path exists.
**Source:** 67-01-SUMMARY.md

---

## Lessons

### Grep-based acceptance criteria can force a runtime-broken implementation

A 67-07 plan AC that grepped for `innerJoin` pushed a query-builder implementation that satisfied both the grep and its mocked unit test, yet threw a TypeORM take-pagination `databaseName` metadata error against the real database. Only the sdk-e2e round-trip in 67-08 caught it. Mocks that stub `createQueryBuilder` hide exactly this class of failure.

**Context:** Prefer behavioral ACs over structural greps for query code; a live round-trip is the only reliable gate for TypeORM query shape.
**Source:** 67-08-SUMMARY.md

---

### readTeeKeys must select current_public_key (bytea) and hex-encode it

The e2e suite initially queried `public_key` from `tee_key_state`, but the column is `current_public_key` (bytea). The fix selects `current_public_key` and returns it as hex for `createSubfolder`.

**Context:** `tee_key_state` has no `public_key` column; always read `current_public_key` and convert bytea to hex when feeding `createSubfolder`.
**Source:** 67-08-SUMMARY.md

---

### Docker build context must be the repo root for the tee-worker Dockerfile

The plan specified `context: ../apps/tee-worker`, but `apps/tee-worker/Dockerfile` COPYs `pnpm-lock.yaml`, `pnpm-workspace.yaml`, and `packages/*` from the monorepo root. The corrected compose entry uses `context: ..` with `dockerfile: apps/tee-worker/Dockerfile`.

**Context:** Any monorepo Dockerfile that COPYs the lockfile or shared packages needs the repo root as the build context, regardless of where the Dockerfile lives.
**Source:** 67-05-SUMMARY.md

---

### The local dev DB is cipherbox, not the .env stray cipherbox_test

The live gate had to force `DB_DATABASE=cipherbox` for the migration, API, and e2e because `.env` carried a stray `DB_DATABASE=cipherbox_test` (a CI-only DB name).

**Context:** Before running migrations or an e2e round-trip locally, verify `DB_DATABASE=cipherbox`; `cipherbox_test` is CI-only and will silently target the wrong schema.
**Source:** 67-08-SUMMARY.md

---

### Rebuild and restart the tee-worker container before the round-trip

The running docker `cipherbox-tee-worker` container was ~2 weeks old and pre-dated the 67-06 route rewrite. The gate had to rebuild the image and restart the service (simulator mode, host `:3002`) so the round-trip exercised current code. The simulator key is deterministic (HKDF from a fixed seed), so the rebuilt worker matched `tee_key_state` on startup.

**Context:** A stale long-lived dev container silently masks source changes; rebuild the tee-worker before any TEE e2e and confirm health.
**Source:** 67-08-SUMMARY.md

---

### Mid-rewrite test failures across plans are expected, not regressions

Between 67-02 and 67-06, `republish.test.ts` failed because the route still called the old 3-arg `decryptWithFallback`. This was documented as expected mid-rewrite state; the executor did not touch out-of-plan files to make it pass.

**Context:** In a multi-plan contract rewrite, the acceptance bar is per-plan; a known-broken downstream file owned by a later plan is not a failure — do not fix out of scope.
**Source:** 67-02-SUMMARY.md, 67-03-SUMMARY.md

---

### Read environment at call time, not module load, for testability

`getInternalCurrentEpoch()` reads `process.env.EPOCH_ZERO_TIMESTAMP_MS` on each call rather than caching it at module load, so tests can vary the anchor without re-importing the module.

**Context:** For any env-derived value a test needs to vary, read the env inside the function; module-load caching makes the value untestable without module resets.
**Source:** 67-02-SUMMARY.md

---

### Prefer a re-exported crypto helper over adding a direct dependency

The binding check needed an Ed25519 pubkey derivation. `@noble/ed25519` is not a direct dep of `cipherbox-tee-worker`, but `@cipherbox/crypto` (already a dep) re-exports `deriveEd25519PublicKey` with the required `sha512Sync` hook configured. Using the re-export avoided a new direct dependency and the sync-API setup risk.

**Context:** Before adding a low-level crypto dep, check whether an existing in-repo package already re-exports the primitive with the correct sync hooks.
**Source:** 67-06-SUMMARY.md

---

## Patterns

### Parse-then-re-sign lease-renew primitive

`parseIpnsRecord` extracts `value` and `sequence` from the marshaled existing record, and `createIpnsRecord` re-signs with exactly those scalars plus a later EOL. The renew function exposes no CID or sequence parameter.

**When to use:** Any time a signer must extend a record's lifetime without repointing or advancing it — bake the invariant into the signature by sourcing every scalar from the parsed input.
**Source:** 67-03-SUMMARY.md

---

### Deterministic sdk-e2e trigger — direct-pg make-due plus single queue.add

The round-trip suite makes a schedule row due with a direct pg `next_republish_at` write, enqueues exactly one `republish-batch` job on the real BullMQ `republish` queue (redis `:6380`), and polls until `signed_record` changes. No cron or timer wait is involved.

**When to use:** Testing a scheduled/queued worker end-to-end — force the due condition in the DB and enqueue one job directly to get a fast, flake-free assertion (mitigates flaky cron-timing, T-67-08-D).
**Source:** 67-08-SUMMARY.md

---

### Live-migration plus information_schema gate before the round-trip

Task 1 ran the migration against the live local Postgres and confirmed the four columns dropped via `information_schema.columns`. The hardening pass then embedded that same `information_schema` assertion in the suite's `beforeAll`, so a future run cannot green against an un-migrated schema.

**When to use:** Any e2e that depends on a schema change — assert the migrated shape in `beforeAll` so a false-positive against a stale schema is impossible (closes T-67-08-T).
**Source:** 67-08-SUMMARY.md, 67-SECURITY.md

---

### Two-layer tombstone defense — pre-batch filter plus CAS WHERE clause

Layer 1 filters `tombstonedAt IS NULL AND encryptedIpnsPrivateKey IS NOT NULL` when selecting due records; layer 2 repeats `tombstoned_at IS NULL` in the `renewIpnsRecordEol` CAS write. A name tombstoned inside the batch window is still rejected at the write.

**When to use:** When a batch reads then writes rows that a concurrent action can invalidate mid-flight — filter at read and re-check at the atomic write (defends T-67-07-S / T-67-08-S).
**Source:** 67-07-SUMMARY.md, 67-08-SUMMARY.md

---

### Verify-before-decrypt with early-return and zero-on-every-path

Each entry runs signature verify before decrypt, uses `continue` for verify-fail and binding-fail (keeping metrics inline and avoiding catch-block ambiguity), and zeros the decrypted key on success, binding-fail, and error paths alike.

**When to use:** Enclave/loop code handling untrusted per-item input where an unauthenticated item must never reach the decryptor and secret material must never survive any branch.
**Source:** 67-06-SUMMARY.md

---

### Greenfield migration pattern — DROP COLUMN IF EXISTS, throwing down()

Column drops use `DROP COLUMN IF EXISTS` in a single `ALTER TABLE`, a companion index is created for the new access path, and `down()` throws under the documented greenfield waiver.

**When to use:** Pre-launch schema edits with no production rollback target; the throwing `down()` records that no reverse migration is intended.
**Source:** 67-01-SUMMARY.md

---

### Fail-closed validation before the side effect

`createSubfolder` validates `teeKeys` (non-empty `currentPublicKey`, finite `currentEpoch`) and throws before `createAndPublishIpnsRecord` runs, so a half-enrolled record is never published.

**When to use:** Before any irreversible publish/enroll, validate every required input up front and throw before the effect, never after.
**Source:** 67-04-SUMMARY.md

---

### TDD with real crypto in helpers, mocking only the re-sign primitive

The republish test suite builds real IPNS records and performs real ECIES encryption in a `makeEntry()` helper, mocks `renewIpnsRecord` (its re-sign correctness is covered in `@cipherbox/core`), and wraps `decryptWithFallback`/`reEncryptForEpoch` with `vi.fn()` passthroughs so call-order and call-count invariants (verify-before-decrypt) can be asserted.

**When to use:** Testing security ordering in a pipeline — keep inputs real so binding/verify logic runs for real, and wrap (not replace) the crypto calls so ordering assertions stay meaningful.
**Source:** 67-06-SUMMARY.md

---

## Surprises

### TypeORM take-pagination plus raw orderBy throws a databaseName metadata error at runtime only

The query-builder `innerJoin` with a raw snake_case `orderBy('s.next_republish_at')` and `take(2000)` triggered `Cannot read properties of undefined (reading 'databaseName')` — TypeORM's take-pagination path fails to resolve the raw column into entity metadata. The mocked unit test passed; only the real query crashed, and the batch never reached the TEE.

**Impact:** Blocking-class defect that shipped through unit tests and a grep AC; forced the getDueEntries revert to find-options and cost a live-gate debugging cycle.
**Source:** 67-08-SUMMARY.md

---

### The plan's docker build context would have failed at build time

The plan specified `context: ../apps/tee-worker`, but that directory as context makes `COPY pnpm-lock.yaml` fail because the Dockerfile pulls from the monorepo root (the Dockerfile itself documents "Build from repo root"). The plan spec was wrong as written.

**Impact:** Auto-fixed during execution to `context: ..`; a caught planning error that would otherwise have broken the local dev stack build.
**Source:** 67-05-SUMMARY.md

---

### ReEnrollRequiredError message initially omitted the actual currentEpoch integer

The first message read `...older than currentEpoch-1 (${currentEpoch - 1})`, which contained the grace floor `9` but not the actual current epoch `10`. The test asserted both integers were present. Fixed to name both the grace floor and the current epoch, still with no key material.

**Impact:** Caught in GREEN verification; sharpened the safe-error contract to always name both epoch bounds (T-67-02-I).
**Source:** 67-02-SUMMARY.md

---

### Removing the 3-arg signature made a wrong-epoch test entry silently decrypt via fallback epoch 1

After the 2-arg reshape, the previously-failing batch entry (tested with wrong-epoch credentials) began decrypting via `getInternalCurrentEpoch() = 1` because no `EPOCH_ZERO_TIMESTAMP_MS` is set in tests. The behavior change surfaced as a single expected failure in the not-yet-rewritten `republish.test.ts`.

**Impact:** Confirmed the fallback path is exercised by default in tests, and flagged that epoch-sensitive tests must set the anchor env explicitly.
**Source:** 67-02-SUMMARY.md

---

### The safe binding-error string contains the word "key"

A test asserted `not.toContain('key')` to prove no key material leaked, but the safe message `'Name-key binding violation'` contains "key" as a descriptive term. The assertion was too strict.

**Impact:** Assertion changed to an exact `toBe('Name-key binding violation')` match; a reminder that substring bans on secret-detection assertions produce false positives on descriptive text.
**Source:** 67-06-SUMMARY.md

---
