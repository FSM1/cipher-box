---
phase: 50-ipfs-ipns-data-integrity-fixes
reviewed: 2026-06-19T00:00:00Z
depth: deep
files_reviewed: 13
files_reviewed_list:
  - apps/api/src/ipfs/dto/unpin.dto.ts
  - apps/api/src/ipfs/ipfs.controller.spec.ts
  - apps/api/src/ipfs/ipfs.controller.ts
  - apps/api/src/ipfs/ipfs.module.ts
  - apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts
  - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts
  - apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts
  - apps/api/src/vault/vault.module.ts
  - apps/api/src/vault/vault.service.spec.ts
  - apps/api/src/vault/vault.service.ts
  - packages/sdk/src/__tests__/collect-subtree-ipns-names.test.ts
  - packages/sdk/src/client.ts
  - scripts/backfill-pinned-cids.ts
findings:
  critical: 2
  warning: 5
  info: 3
  total: 10
status: resolved
---

# Phase 50: Code Review Report

**Reviewed:** 2026-06-19T00:00:00Z
**Depth:** deep
**Files Reviewed:** 13
**Status:** resolved — all blockers and in-scope warnings were fixed after this review (see Resolution)

## Resolution (post-review)

> This report records the findings **as discovered** (pre-fix). The two blockers and the in-scope warnings were fixed immediately afterward; `50-VERIFICATION.md` reflects the post-fix code. This table reconciles the two documents (and resolves the CodeRabbit CLI doc-consistency findings). Sections below are retained verbatim as the original finding record.

| Finding                              | Status      | Where / commit                                                                                                    |
| ------------------------------------ | ----------- | ----------------------------------------------------------------------------------------------------------------- |
| CR-01 — cycle/visited guard          | ✅ Fixed    | `client.ts` `collectSubtreeIpnsNamesAsync` gains `visited: Set<string>` + skip-before-recurse — `d70714412`        |
| CR-02 — `.catch()` on dispatch sites | ✅ Fixed    | `.catch()` added to all fire-and-forget unenroll dispatches — `d70714412` (later consolidated into a helper `ef9782f69`) |
| WR-01 — drain recheck+unpin lock     | ✅ Fixed    | serialized under `pg_advisory_xact_lock` — `5a42a36f5`                                                             |
| WR-03 — post-commit outbox delete    | ✅ Fixed    | delete moved under the advisory lock — `7ecbf5a33`                                                                 |
| WR-04 — unbounded traversal fan-out  | ✅ Fixed    | bounded with `pLimit(UNENROLL_COLLECT_CONCURRENCY)` — `d70714412`                                                  |
| WR-02 — RegisterCidDto regex         | ⏭ Deferred | out-of-phase file — todo `2026-06-19-register-cid-dto-validation-inconsistency.md`                                 |
| WR-05 — LocalProvider unescaped CID  | ⏭ Deferred | out-of-phase file; non-exploitable per both security passes — todo `2026-06-19-local-provider-unescaped-cid-in-pin-url.md` |
| IN-01 / IN-02 / IN-03                | ℹ Noted    | IN-02 (duplicate-name) incidentally resolved by CR-01's `visited` set                                              |

The verifier re-confirmed 3/3 must-haves against the fixed tree; sdk (`collect-subtree-ipns-names` 4/4, incl. a cycle test) and api (90/90) suites are green.

## Summary

Reviewed the IPFS/IPNS data-integrity fixes: the advisory-lock overflow fix,
refcount-aware drain, quota-decrement-on-delete in `guardedUnpin`, CID
validation DTOs, the backfill script, and the new on-demand subtree IPNS
collector in the SDK client.

The advisory-lock fix, the in-transaction quota decrement, the drain refcount
re-check, and the backfill safety guards are sound and well-tested. However the
new on-demand traversal (`collectSubtreeIpnsNamesAsync`) drops the cycle guard
that the analogous `ensureFolderLoaded` DFS carries, exposing an unbounded-
recursion / stack-overflow path on malicious or corrupt folder metadata — and
every caller dispatches it as a `.then()` with **no `.catch()`**, so that
failure surfaces as an unhandled promise rejection. There is also an unguarded
TOCTOU window in the drain worker's refcount re-check. CID-validation regexes
are inconsistent across DTOs. Details below.

## Critical Issues

### CR-01: On-demand subtree collector has no cycle/visited guard — unbounded recursion

**File:** `packages/sdk/src/client.ts:272-325`
**Issue:** `collectSubtreeIpnsNamesAsync` recurses into every `folder`-typed
child but, unlike `ensureFolderLoaded` (line 549, which keeps a
`visited = new Set<string>()` "guard against repeats and pathological cycles"),
it carries **no visited set and no depth bound**. Folder metadata is
client-supplied, decrypted, attacker-or-corruption-influenceable data. If
folder A's metadata lists folder B and B's metadata lists A (a cycle), or a
deep/wide adversarial tree is crafted, the traversal recurses without
termination. The per-child `catch` at line 317 does **not** break the cycle:
the recursive `collectSubtreeIpnsNamesAsync` call swallows its own per-node
errors internally and resolves (returns `acc`) rather than throwing, so the
catch never fires and recursion continues until the call stack is exhausted
(`RangeError: Maximum call stack size exceeded`) or the process hangs fetching
the same IPNS names forever. `acc` also accumulates the same names repeatedly on
any diamond/cycle, ballooning the unenroll payload.

Because this runs fire-and-forget (see CR-02), the eventual stack-overflow
becomes an unhandled rejection rather than a caught error.

**Fix:** Thread a `visited: Set<string>` through the recursion exactly as
`ensureFolderLoaded` does, and skip already-visited IPNS names:

```typescript
private async collectSubtreeIpnsNamesAsync(
  folderIpnsName: string,
  folderKey: Uint8Array,
  acc: string[] = [],
  visited: Set<string> = new Set(),
): Promise<string[]> {
  if (visited.has(folderIpnsName)) return acc;
  visited.add(folderIpnsName);
  acc.push(folderIpnsName);
  // ...
  for (const child of children) {
    if (child.type === 'folder') {
      const entry = child as FolderEntry;
      if (visited.has(entry.ipnsName)) continue;
      try {
        const childFolderKey = await unwrapKey(/* ... */);
        await this.collectSubtreeIpnsNamesAsync(entry.ipnsName, childFolderKey, acc, visited);
      } catch {
        if (!visited.has(entry.ipnsName)) acc.push(entry.ipnsName);
      }
    }
  }
  return acc;
}
```

### CR-02: Fire-and-forget IPNS-unenroll collection has no `.catch()` — unhandled promise rejection

**File:** `packages/sdk/src/client.ts:938-940`, `1950-1952`, `1976-1978`, `2013-2015`
**Issue:** All four dispatch sites invoke the async collector and chain only a
`.then()`:

```typescript
this.collectRemovedItemIpnsNames(removedItem).then((names) =>
  this.fireAndForgetUnenroll(names)
);
```

There is no `.catch()`. If the collector rejects — which it can: the
stack-overflow from CR-01, or any error thrown synchronously before the inner
try/catch (e.g. `this.folderTree.get` throwing, an `await` on a rejected
`loadFolderMetadata` at the top level of `collectBinEntryIpnsNames`’s
`Promise.all`), or `fireAndForgetUnenroll` itself throwing synchronously — the
rejection is unhandled. In Node this triggers `unhandledRejection` (process
crash under `--unhandled-rejections=strict`, or a hard log); in the browser it
is an uncaught error. The surrounding `withOperation` wrapper does **not** catch
it because the promise is intentionally detached (not awaited). The method
docstring claims "Failures are logged but never block the caller" — that
contract is only honored inside `fireAndForgetUnenroll`'s own `.catch()` on the
API call, not for the collection step.

**Fix:** Attach a `.catch()` to every detached collection promise:

```typescript
this.collectRemovedItemIpnsNames(removedItem)
  .then((names) => this.fireAndForgetUnenroll(names))
  .catch((err) =>
    console.warn('[CipherBox] IPNS unenroll collection failed:', err)
  );
```

Apply identically at lines 1950, 1976, and 2013.

## Warnings

### WR-01: Drain worker refcount re-check is a TOCTOU window — not serialized with `guardedUnpin`'s advisory lock

**File:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts:53-72`
**Issue:** The drain loop re-checks `pinnedCidRepository.count({ cid })` (line
59) and, if zero, calls `ipfsProvider.unpinFile(row.cid)` (line 70). This
`count` runs in autocommit, **outside any advisory lock**, while
`guardedUnpin` (vault.service.ts:269) takes `pg_advisory_xact_lock(hashtext(cid))`
specifically to serialize concurrent deletes/refcount decisions. Sequence:
drain reads `count = 0`; concurrently a new upload calls `recordPin` inserting a
fresh `pinned_cids` row for the same deduped CID; drain then physically unpins
in Kubo → the just-uploaded file's pin is removed → Kubo GC → data loss. The
inline `guardedUnpin` post-commit path has the same shape but at least the
refcount that gated the outbox insert was computed under the lock; the drain
path recomputes with no lock at all. The D-13 race note in the controller
(ipfs.controller.ts:129-132) acknowledges a sub-second variant but the drain
window is wider (the row can sit in the outbox for up to 5 minutes).

**Fix:** Take the same per-CID advisory lock in the drain transaction so the
re-check and unpin are serialized against `guardedUnpin`. Wrap the count +
unpin + outbox-delete for each row in a transaction that first issues
`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)` for `row.cid`, mirroring
the lock used in `guardedUnpin`. Alternatively, re-check the count a second time
*after* acquiring the lock and immediately before `unpinFile`.

### WR-02: CID validation regex inconsistent between `UnpinDto` and `RegisterCidDto`

**File:** `apps/api/src/ipfs/dto/unpin.dto.ts:7` vs `apps/api/src/ipfs/dto/register-cid.dto.ts:11`
**Issue:** `UnpinDto` validates CIDv0 as `Qm[1-9A-HJ-NP-Za-km-z]{44}` (exactly
46 chars, correct) and bounds length with `@MaxLength(255)`. `RegisterCidDto`
uses `Qm[1-9A-HJ-NP-Za-km-z]{44,}` (open-ended `{44,}`) and has **no**
`@MaxLength`. So a CIDv0 longer than 46 chars is rejected by unpin but accepted
by register-cid, and register-cid accepts arbitrarily long strings (the
oversized-string DoS bound that motivated `MaxLength(255)` on unpin, per the
T-50-12 comment, is absent here). Both ultimately reach `recordPin`/Kubo;
divergent validation for the same logical value is a correctness and
defense-in-depth gap. The phase brief explicitly calls out "CID validation
completeness."

**Fix:** Factor a single shared `CID_REGEX` constant (exact CIDv0 length) and
the `@MaxLength(255)` decorator, and apply both to `RegisterCidDto.cid`. Change
`{44,}` to `{44}` unless an intentional reason for the open bound is documented.

### WR-03: Post-commit outbox cleanup in `guardedUnpin` is not idempotent against concurrent drain

**File:** `apps/api/src/vault/vault.service.ts:314-321`
**Issue:** After the transaction commits, `guardedUnpin` calls
`ipfsProvider.unpinFile(cid)` then `pendingUnpinRepository.delete({ cid })`
(line 317). The outbox row was inserted with `orIgnore` keyed by `cid`. If two
users' `guardedUnpin` calls (or a `guardedUnpin` and a drain pass) race past the
refcount-zero gate for the same CID, both will attempt the physical unpin and
both will `delete({ cid })`. The unpin is idempotent (LocalProvider swallows
"not pinned"), so this is not data loss, but the `delete({ cid })` from one path
can remove the outbox row the other path is relying on as its retry safety net —
if path A's Kubo unpin fails (row already deleted by path B before A's unpin
even ran), A has no outbox row left to retry. The advisory lock serializes the
*transaction* portion but is released at commit, before this post-commit block
runs, so the post-commit Kubo+delete is unserialized.

**Fix:** Make the post-commit delete conditional on the row still being present
and not yet re-inserted, or gate the physical-unpin attempt to the path that
actually inserted the outbox row (capture `insert().execute()` affected-rows
inside the txn and only set `shouldAttemptPhysicalUnpin` when the insert
actually created the row rather than hit `orIgnore`).

### WR-04: `deleteItem` dispatches collection before returning, but does not bound or track the detached work

**File:** `packages/sdk/src/client.ts:937-942`
**Issue:** `collectRemovedItemIpnsNames(removedItem)` triggers an on-demand IPNS
traversal of the entire deleted subtree (`collectSubtreeIpnsNamesAsync`), which
issues network fetches per unloaded folder. This is detached and unbounded —
deleting a large folder fires an unbounded fan-out of `loadFolderMetadata`
calls with no concurrency limit (contrast `uploadFiles`, which uses
`pLimit(UPLOAD_CONCURRENCY)`). On a deep/wide tree this is a request storm.
Combined with CR-01 (no cycle guard) the fan-out is also potentially infinite.
Out of strict v1 perf scope, but it is a robustness defect given the traversal
walks attacker-influenceable metadata.

**Fix:** Apply a `p-limit` concurrency cap to the recursive
`loadFolderMetadata` fan-out, consistent with the upload path, and land the
cycle guard from CR-01.

### WR-05: `fetchKuboPins` / drift report interpolates no CID, but drain/unpin path forwards DB CIDs into an unescaped URL

**File:** `apps/api/src/ipfs/providers/local.provider.ts:86` (reached via `pending-unpin.processor.ts:70` and `vault.service.ts:316`)
**Issue:** `LocalProvider.unpinFile` builds `pin/rm?arg=${cid}` by raw string
interpolation with no URL-encoding. CIDs entering this path from the controller
are regex-validated (`UnpinDto`), but CIDs reaching it from the drain worker
(`row.cid`) and from `guardedUnpin` originate from `pinned_cids`/`pending_unpins`
rows. Those rows are populated by `recordPin`, whose CID for the BYO
`register-cid` route is validated only by the looser `RegisterCidDto` regex
(WR-02) and for the upload route comes from Kubo itself. A CID containing a `&`
or other query-significant character would split the query string. Today the
regexes happen to exclude such characters, so this is latent rather than
exploitable, but the unpin path should not depend on every upstream writer's
validation being airtight.

**Fix:** `encodeURIComponent(cid)` in the `pin/rm` and `pin/add` URL
construction (or use `URLSearchParams`). Belongs to the provider but is in scope
because Phase 50 routes new DB-sourced CIDs through it.

## Info

### IN-01: Duplicated `IPFS_PROVIDER` factory across three modules

**File:** `apps/api/src/ipfs/ipfs.module.ts:20-31`, `apps/api/src/vault/vault.module.ts:27-38`, `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts:25-35`
**Issue:** The same `useFactory` (apiUrl/gatewayUrl defaults + `new LocalProvider`)
is copy-pasted verbatim in three modules. The inline comments accept this
(IN-04) to avoid a circular import. The accepted-disposition reasoning is sound,
but the three copies can drift independently (e.g. a future default-URL change
applied to only two). Consider extracting the factory function (not the NestJS
provider/module) into a shared `createLocalProviderFactory()` helper that each
module references, eliminating the duplication without reintroducing the cycle.
**Fix:** Extract the factory body to a shared function; keep three thin provider
registrations.

### IN-02: `collectSubtreeIpnsNamesAsync` accumulates duplicate IPNS names on shared subtrees

**File:** `packages/sdk/src/client.ts:277, 320`
**Issue:** Even absent a cycle, a DAG where two parents reference the same child
folder will push that child's IPNS name (and its descendants) into `acc` more
than once. `fireAndForgetUnenroll` chunks by 200 and the unenroll API is
idempotent, so this is harmless functionally but inflates payload size. The
`visited` set proposed in CR-01 also fixes this.
**Fix:** De-dupe via the CR-01 `visited` set (or `[...new Set(acc)]` before
dispatch).

### IN-03: Drift report counts BYO advisory rows as "accounted," documented but worth a metric label

**File:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts:96-110`
**Issue:** `dbCids` intentionally includes BYO advisory rows (IN-05
disposition). This is correct per the D-07 refcount semantics, but it means the
drift report will never flag a Kubo pin that exists *only* because a BYO
advisory row coincidentally shares a CID — an operator reading
`driftOrphanedPinsTotal` cannot distinguish hosted-orphan from BYO-shadowed.
Non-blocking; the disposition comment is adequate. Consider a separate counter
or log field if BYO/hosted CID collisions become operationally relevant.
**Fix:** Optional: add a `source` label to the drift metric, or note the BYO
overlap in the warn log.

---

_Reviewed: 2026-06-19T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
