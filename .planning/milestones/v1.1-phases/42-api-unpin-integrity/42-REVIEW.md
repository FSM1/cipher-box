---
phase: 42-api-unpin-integrity
reviewed: 2026-06-12T00:00:00Z
depth: standard
files_reviewed: 21
files_reviewed_list:
  - apps/api/src/app.module.ts
  - apps/api/src/ipfs/ipfs.controller.spec.ts
  - apps/api/src/ipfs/ipfs.controller.ts
  - apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts
  - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts
  - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts
  - apps/api/src/metrics/metrics.service.ts
  - apps/api/src/migrations/1749000000000-AddPendingUnpins.ts
  - apps/api/src/migrations/1749100000000-AddPinnedCidCidIndex.ts
  - apps/api/src/scripts/backfill-helpers.spec.ts
  - apps/api/src/scripts/backfill-helpers.ts
  - apps/api/src/vault/entities/index.ts
  - apps/api/src/vault/entities/pending-unpin.entity.ts
  - apps/api/src/vault/vault.module.ts
  - apps/api/src/vault/vault.service.spec.ts
  - apps/api/src/vault/vault.service.ts
  - apps/web/src/services/delete.service.spec.ts
  - apps/web/src/services/delete.service.ts
  - docker/grafana/alerts/unpin-cross-user-attempts.json
  - packages/api-client/openapi.json
  - scripts/backfill-pinned-cids.ts
findings:
  critical: 0
  warning: 7
  info: 6
  total: 13
status: issues_found
---

# Phase 42: Code Review Report

**Reviewed:** 2026-06-12
**Depth:** standard
**Files Reviewed:** 21
**Status:** issues_found

## Narrative Findings (AI reviewer)

## Summary

Reviewed the guarded-unpin implementation: `guardedUnpin` in `vault.service.ts`, the controller rewiring, the `pending_unpins` outbox + BullMQ drain/drift processor, two migrations, the non-BYO backfill script, the cross-user audit metric/alert, and the spec files.

The core security properties hold under adversarial tracing:

- Ownership is enforced (delete is scoped to `{userId, cid}`); the silent-2XX path is response-identical for unknown vs cross-user CIDs (no oracle).
- The advisory lock is taken before any read/write, and refcounting under READ COMMITTED correctly serializes concurrent unpins of the same CID.
- A share recipient who learns a victim's CID and registers it (BYO) cannot trigger a physical unpin of the victim's data — the refcount sees the victim's row.
- `pinned_cids` has `@Unique(['userId', 'cid'])`, so refcount inflation via duplicate rows is not possible.
- `openapi.json` matches the opaque `UnpinResponseDto { success: boolean }` shape; the Grafana alert metric name matches `cipherbox_unpin_cross_user_attempts_total` in `metrics.service.ts`, and the file follows the same provisioning conventions (placeholder UIDs, `noDataState`/`execErrState`) as sibling alert files. JSON is structurally valid.

No critical findings. Seven warnings: a latent SQL overflow in the advisory-lock hash, an upload-compensation path that leaks Kubo pins and pollutes the cross-user security metric, a stale-outbox race the D-13 rationale does not cover, a counter-vs-gauge metric defect, a TOCTOU window in the destructive backfill script, an illusory defensive predicate in that same script, and an unbounded-retention consequence of counting BYO advisory rows in the hosted refcount.

## Warnings

### WR-01: `abs(hashtext(...))` can raise "integer out of range"; the comment claims to fix a pitfall it actually introduces

**File:** `apps/api/src/vault/vault.service.ts:255`
**Issue:** `SELECT abs(hashtext($1))::bigint AS h` applies `abs()` to the `int4` result of `hashtext()` BEFORE casting. For any CID whose `hashtext` is exactly `-2147483648` (INT_MIN), `abs(int4)` raises `ERROR: integer out of range` — deterministically, every time, for that CID. That file would become permanently undeletable via the API (500 on every unpin) and its quota row permanently stuck. Probability per CID is ~2^-32, but the failure is permanent once it occurs. The comment ("abs() avoids bigint-out-of-range on negative hashtext values") is backwards: `pg_advisory_xact_lock` accepts a signed `bigint`, so negative values were never a problem — `abs()` is the only failure mode here.
**Fix:**

```sql
SELECT hashtext($1)::bigint AS h
```

Drop `abs()` entirely (negative lock keys are valid), or if a non-negative key is desired, cast first: `abs(hashtext($1)::bigint)`.

### WR-02: Upload compensation via `guardedUnpin` is a no-op that leaks Kubo pins and fires the cross-user security alert on internal failures

**File:** `apps/api/src/ipfs/ipfs.controller.ts:119-128` (interacting with `apps/api/src/vault/vault.service.ts:261-268`)
**Issue:** When `recordPin` fails after a successful Kubo pin, the compensation call `guardedUnpin(req.user.id, result.cid)` finds no `pinned_cids` row for the caller (the insert is exactly what failed), so it returns before any Kubo interaction. Two consequences:

1. The just-created Kubo pin is never removed — the previous compensation (direct `unpinFile`) did remove it. The drift report only *counts and logs* orphans; nothing ever cleans them, so the leak is permanent.
2. If any other user holds the same CID (dedupe), the cross-user lookup at `vault.service.ts:263-267` matches and increments `cipherbox_unpin_cross_user_attempts_total` — which directly fires the new Grafana security alert. An internal DB failure during upload would page ops with a "cross-tenant probe" signal, polluting the exact audit channel D-02 was built for.

**Fix:** In the upload compensation path, call `this.ipfsProvider.unpinFile(result.cid)` directly only when the CID has no `pinned_cids` rows at all (or add a `guardedUnpin` internal variant that skips the cross-user telemetry and falls back to a refcount-checked physical unpin for the no-row case). At minimum, exclude this path from the cross-user counter so the security signal stays clean.

### WR-03: Drain worker and post-commit unpin never re-check refcount — a stale outbox row can unpin a re-pinned CID; the D-13 "sub-second window" rationale does not cover this path

**File:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts:50-62` (also `apps/api/src/vault/vault.service.ts:297-304`)
**Issue:** `drainPendingUnpins` unpins every outbox CID unconditionally. If a CID lands in `pending_unpins` (refcount hit zero, inline Kubo call failed) and the same CID is subsequently re-pinned and recorded (re-upload of identical ciphertext, or a pin-migration flow that re-pins existing CIDs), the next drain pass removes the pin from Kubo while a live `pinned_cids` row references it — content then becomes eligible for Kubo GC: data loss. The D-13 comment in the controller argues the race is negligible because it requires identical ciphertext within a "sub-second window"; for the outbox path the window is 5 minutes minimum and unbounded while Kubo is down, so only the identical-ciphertext premise protects you — and migration flows re-pin existing CIDs by design.
**Fix:** In the drain loop, before calling `unpinFile`, check `pinned_cids` for the CID; if any row exists, delete the outbox row without unpinning (the entry is stale):

```typescript
const refs = await this.pinnedCidRepository.count({ where: { cid: row.cid } });
if (refs > 0) {
  await this.pendingUnpinRepository.delete({ cid: row.cid });
  continue;
}
```

Apply the same guard to the inline post-commit path in `guardedUnpin` if desired (lower value there — the window is genuinely short).

### WR-04: `driftOrphanedPinsTotal` is a Counter re-incremented for the same orphans every hourly run

**File:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts:92-97` (declared at `apps/api/src/metrics/metrics.service.ts:184-188`)
**Issue:** Each hourly drift run increments the counter once per unaccounted pin. A constant set of N orphans grows the metric by N every hour forever, so the value does not represent "total orphans" and any rate/threshold alert on it stays hot indefinitely even when drift is stable. The companion `pendingUnpinsGauge` correctly uses a Gauge with `.set()`; this metric measures the same kind of point-in-time state.
**Fix:** Replace with a Gauge set once per run:

```typescript
let orphans = 0;
for (const cid of kuboPins) {
  if (!dbCids.has(cid)) {
    orphans++;
    this.logger.warn(`Drift: unaccounted Kubo pin cid=${cid}`);
  }
}
this.metricsService.driftOrphanedPinsGauge.set(orphans);
```

### WR-05: Backfill script snapshots Kubo before querying the DB — rows for uploads that land in between are deleted as "phantoms"

**File:** `scripts/backfill-pinned-cids.ts:85-136`
**Issue:** The script fetches the Kubo pin set (step 1), then queries `pinned_cids` (step 2). Any upload that completes between the two reads produces a row whose CID is absent from the stale Kubo snapshot — `selectRowsToDelete` classifies it as a phantom and the live-mode run deletes it. The user keeps the pin (Kubo) but loses the quota row permanently: quota under-count plus a perpetual drift-report orphan. Nothing in the script restricts candidates by age, and nothing in the file warns that it must run with the API stopped.
**Fix:** Add an age cutoff to the candidate query so in-flight uploads are never candidates:

```sql
WHERE v.is_byo_user = false
  AND pc.pinned_at < NOW() - INTERVAL '1 hour'
```

(Swapping the fetch order — DB first, Kubo second — also closes the window, since `guardedUnpin` now deletes rows before unpinning; the cutoff is the simpler, more robust guard.)

### WR-06: Backfill query hardcodes `false::boolean AS "isByoUser"`, making the documented defensive re-assert illusory

**File:** `scripts/backfill-pinned-cids.ts:127-136` (comment at 124-125)
**Issue:** The comment states "selectRowsToDelete re-asserts isByoUser === false defensively," but the SELECT fabricates the column as a literal `false` instead of selecting `v.is_byo_user`. The helper's BYO exclusion (the D-09 safety property its unit tests verify) can therefore never reject anything: if the `WHERE v.is_byo_user = false` clause is ever loosened or mis-edited, BYO rows arrive at the destructive delete already stamped non-BYO. In a script whose failure mode is corrupting advisory quota, a defense layer that cannot fire is worse than none because the comment claims it exists.
**Fix:**

```sql
v.is_byo_user AS "isByoUser"
```

Select the real column so the predicate genuinely re-checks it.

### WR-07: BYO advisory rows block physical unpin of hosted content indefinitely — retention/privacy consequence of D-07

**File:** `apps/api/src/vault/vault.service.ts:274-292`
**Issue:** Refcounting counts all `pinned_cids` rows for the CID with no origin filtering (deliberate, per D-07). But BYO advisory rows describe pins on the user's *own* node, never on CipherBox's Kubo. A share recipient learns a file's CID by design (sharing is a v1.0 feature); a BYO recipient can register that CID via `/ipfs/register-cid` (passes the format regex, costs them nothing — their quota is advisory). When the owner later deletes the file, refcount stays ≥ 1 and the ciphertext remains pinned on CipherBox's hosted Kubo indefinitely — the owner believes it deleted, and no process ever revisits the decision (drift report won't flag it: the CID is accounted for in `pinned_cids`). This conflates two pin namespaces (hosted Kubo vs. user nodes) inside one refcount and creates an unbounded server-side retention path controllable by a non-owner.
**Fix:** Count only rows attributable to hosted pinning in the physical-unpin decision, e.g. join to `vaults` and exclude `is_byo_user = true` rows from the refcount (BYO rows still gate nothing physical — their content was never on the hosted node), or record pin origin on `pinned_cids` and filter on it. If D-07 stands, document the retention consequence explicitly in `docs/CAPACITY.md`/threat model.

## Info

### IN-01: `fileUnpins` counter increments on no-op unpins

**File:** `apps/api/src/vault/vault.service.ts:306`
**Issue:** `this.metricsService.fileUnpins.inc()` runs unconditionally — unknown-CID and cross-user no-ops count as "file unpins," inflating the metric relative to actual quota decrements.
**Fix:** Track whether the row was deleted (similar to `outboxRowInserted`) and increment only on that path.

### IN-02: `UnpinDto.cid` lacks the CID format validation that `RegisterCidDto` has

**File:** `apps/api/src/ipfs/dto/unpin.dto.ts:9-11` (adjacent to diff)
**Issue:** Only `@IsString()`/`@IsNotEmpty()` — no length cap or CID regex. Traced consequences are benign (parameterized SQL; `unpinFile` is only reachable for CIDs equal to stored, validated values; the warn log only fires on an equality match with a stored CID), but an arbitrary multi-megabyte string still flows into `hashtext()` and two indexed lookups per request.
**Fix:** Apply the same `@Matches(/^(Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[a-z2-7]{58,})$/)` used in `RegisterCidDto`, plus a `@MaxLength(255)` to match the column.

### IN-03: `recordUnpin` is now dead code

**File:** `apps/api/src/vault/vault.service.ts:313-318`
**Issue:** After this phase, `recordUnpin` has zero non-test callers (confirmed by grep across `apps/api` and `apps/web`); the backfill header even notes it "had zero callers." Leaving an unguarded, non-refcounted unpin-recording method on the service invites future misuse that bypasses the D-01..D-05 properties.
**Fix:** Delete `recordUnpin` and its tests, or mark it `@deprecated` pointing to `guardedUnpin`.

### IN-04: `LocalProvider` factory duplicated in three modules

**File:** `apps/api/src/vault/vault.module.ts:23-34`, `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts:19-32`, `apps/api/src/ipfs/ipfs.module.ts:14-27`
**Issue:** Three identical `IPFS_PROVIDER` factories now exist to dodge the IpfsModule↔VaultModule cycle. They are consistent today, but a future provider swap in `IpfsModule.forRootAsync` would silently leave `guardedUnpin` and the drain worker talking to local Kubo.
**Fix:** Extract a small `IpfsProviderCoreModule` (no VaultModule dependency) that owns the factory and is imported by all three.

### IN-05: Drift report's DB set includes BYO advisory CIDs, which can mask hosted orphans

**File:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts:81-89`
**Issue:** `dbCids` is built from all `pinned_cids` rows including BYO advisory rows, whose CIDs are by definition not pinned on the hosted node. A hosted Kubo pin whose only DB representation is a BYO advisory row is exactly the WR-07 retention case — and the drift report classifies it as "accounted," so it never surfaces.
**Fix:** Build the drift DB set from non-BYO rows (plus `pending_unpins`), consistent with whatever resolution WR-07 gets.

### IN-06: `outboxRowInserted` is set even when `orIgnore` deduped the insert

**File:** `apps/api/src/vault/vault.service.ts:284-291`
**Issue:** The flag is set unconditionally after `execute()`, so it really means "refcount hit zero," not "this request inserted the row." Behavior is harmless (the inline unpin is idempotent and concurrent deduped callers just both attempt it), but the name misleads future readers about the orIgnore semantics.
**Fix:** Rename to `shouldAttemptPhysicalUnpin`, or inspect `execute()`'s returned identifiers to set it accurately.

---

Reviewed: 2026-06-12
Reviewer: Claude (gsd-code-reviewer)
Depth: standard
