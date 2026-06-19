# Security Review — Phase 50 (IPFS/IPNS Data-Integrity Fixes)

Date: 2026-06-19
Branch: `feat/ipfs-ipns-data-integrity-fixes`
Reviewer: security/crypto agent
Scope: `git diff origin/main...HEAD` over vault.service.ts, pending-unpin.processor.ts, ipfs.controller.ts, unpin.dto.ts, ipfs/vault/pending-unpin modules, packages/sdk/src/client.ts, scripts/backfill-pinned-cids.ts

## Executive Summary

Phase 50 is a data-integrity / authorization / availability change, not new cryptography. The core
multi-tenant unpin authorization model is sound: `guardedUnpin` enforces per-user ownership before any
physical Kubo `pin/rm`, performs a cross-user refcount under a per-CID advisory lock, and only queues a
physical unpin when the global refcount reaches zero. User A cannot drop content User B still pins. The
SDK on-demand IPNS traversal correctly uses generic error handling for ECIES unwrap/decrypt and does not
log key material or the vault private key. SQL paths are parameterized; the one new literal (`INTERVAL
'1 hour'`) is a constant, not user input.

Overall residual risk: LOW. No CRITICAL or HIGH findings. The notable items are availability/robustness
concerns (advisory-lock hold across a network call, hashtext collisions) that are bounded and largely
mitigated by existing idempotency, plus a pre-existing-but-confirmed input-validation defense-in-depth gap
in the deferred `LocalProvider.unpinFile` URL construction.

Authorization model: VERIFIED. No way found to unpin another user's live CID via the public `/unpin`
route or the WR-02 compensation path.

## Findings

| # | Severity | Location | Issue | Recommendation |
|---|----------|----------|-------|----------------|
| F1 | MEDIUM | `apps/api/src/ipfs/providers/local.provider.ts:87` | `unpinFile` interpolates the CID directly into the Kubo URL `pin/rm?arg=${cid}` with no URL-encoding. Known/deferred. The controller `/unpin` route is now fully gated by the anchored `UnpinDto` regex, so the externally-reachable path is mitigated. BUT `unpinFile` is also called with un-DTO-validated CIDs from the WR-02 compensation path (controller :133, CID from Kubo `pinFile` response — trusted) and the drain processor (CID from DB rows that were themselves DTO-validated at insert time, or backfilled). Not currently exploitable, but the function itself remains unsafe by construction. | Use `encodeURIComponent(cid)` (or `URLSearchParams`) when building the Kubo URL inside `unpinFile`. This is a one-line defense-in-depth fix that removes reliance on every caller pre-validating. Tracked as deferred — recommend promoting given it is one line. |
| F2 | LOW (availability) | `pending-unpin.processor.ts:85-110`, `vault.service.ts:259-328` | The drain and `guardedUnpin` hold `pg_advisory_xact_lock(hashtext(cid)::bigint)` plus an open DB transaction/connection across the Kubo `unpinFile` network call. If Kubo hangs (no client-side timeout is set on the `fetch` in `local.provider.ts`), the DB connection and the per-CID lock are held for the full hang duration. Drain is single-row sequential per the batch loop, so blast radius is one connection; `guardedUnpin` is per-request and could pin one pool connection per concurrent hung unpin of the same CID. Bounded but real connection-pool-exhaustion surface under a Kubo outage. | Add a bounded timeout (AbortController) to the Kubo `fetch` calls in `local.provider.ts` so a hung Kubo cannot indefinitely hold a DB connection + advisory lock. Note: `guardedUnpin`'s primary Kubo call is correctly OUTSIDE the transaction (vault.service.ts:312); only the small WR-03 row-delete re-takes the lock briefly and does NOT wrap the Kubo call — that part is fine. The drain (processor :86-109) is the one that holds the lock across the network call by design (to prevent re-pin TOCTOU); that trade-off is documented and acceptable for a low-frequency batched job, but still benefits from a fetch timeout. |
| F3 | LOW (correctness/availability) | `vault.service.ts:267`, `pending-unpin.processor.ts:89` | `hashtext(cid)::bigint` maps the CID space onto a 32-bit `int4` value (hashtext returns int4, sign-extended to bigint), so two distinct CIDs can collide on the same advisory-lock key. Collision only causes brief, unnecessary serialization of two unrelated CID operations — it does NOT cause a correctness bug, because every locked section re-reads its own per-CID DB state (`findOne`/`count`/`delete` are all keyed on the literal CID, not on the hash). So a collision can never make one CID's operation act on another CID's rows. Pure availability micro-contention, negligible at expected scale. | No action required for correctness. If lock contention ever shows up in metrics, widen the key to 64-bit (e.g. hash the CID to a bigint via two hashtext calls into the high/low words, or use `pg_advisory_xact_lock(int4, int4)` with two independent hashes). Document the collision-is-benign reasoning (it is now implicitly relied upon). |
| F4 | LOW (info-leak, mitigated) | `packages/sdk/src/client.ts:336-338`, `:498-501`, `:221`, `:983`, `:1991` (dispatch sites) | The on-demand subtree traversal catches ECIES unwrap / metadata-decrypt failures and logs `console.warn`. Verified the logged values are NON-sensitive: only the folder IPNS name (a public identifier) and, at the dispatch sites, the caught error via `err instanceof Error ? err.message : err`. ECIES `unwrapKey` (packages/crypto/src/ecies/decrypt.ts) throws a generic `CryptoError('Key unwrapping failed', ...)` with NO plaintext/key material in the message (deliberate anti-oracle design). The vault private key (`this.internalVaultKeypair.privateKey`) is never logged. The `catch {}` blocks at :333, :358, :412 swallow the raw error entirely. So no key material or plaintext is leaked. Residual risk: a future change that logs the raw caught object at a dispatch site (`.catch((err) => console.warn(..., err))`) could surface a richer error if `loadFolderMetadata` ever attaches decrypted context to its thrown error. Today it does not. | No fix required now. Add a code comment / lint guard asserting that errors from the crypto/metadata layer must remain generic, and keep dispatch-site logging to `err.message` (already the case at :205). Optionally downgrade the per-node traversal warns to debug to avoid leaking the vault's folder-IPNS topology into client logs at scale. |
| F5 | LOW | `packages/sdk/src/client.ts:303-368` | Cycle/resource guard review. The `visited` Set is shared across the entire recursion (passed by reference, checked before recurse at :314 and :349, and on the unwrap-failure fallback at :361), so an A→B→A cycle or a diamond DAG terminates and cannot re-expand a node. Fan-out is bounded by `UNENROLL_COLLECT_CONCURRENCY = 8` at the top level (:218, :369). Residual: a single adversarial/corrupted folder with a very large `children` array, or a very deep (non-cyclic) legitimate chain, still triggers N sequential `loadFolderMetadata` fetches and unbounded recursion depth within one subtree (depth not capped, only repeats are). Each node does one network fetch + one ECIES unwrap; `visited` caps total nodes to the number of distinct IPNS names, so it is bounded by the real vault size, but a maliciously-crafted metadata blob fetched from an untrusted IPNS/IPFS source could inflate `children` to drive many fetches. This is fire-and-forget (never blocks the caller) and the data is client-supplied to begin with, so impact is self-DoS at worst. | Acceptable as-is for a fire-and-forget cleanup path. Consider a max-node and/or max-depth cap (belt-and-suspenders against a corrupted/oversized metadata blob) and treating `children` length defensively. Not blocking. |
| F6 | INFO (false-positive checked) | `vault.service.ts:270-277` | Cross-user / unknown-CID oracle. Confirmed NO timing or response oracle: both the unknown-CID and cross-user-attempt branches return the same silent success (no exception, `unpin` controller returns `{ success: true }` either way at controller :155-157). The cross-user branch only diverges internally (logger.warn + metric inc) and is suppressed for the internal compensation path. The two DB lookups (`findOne {userId,cid}` then `findOne {cid}`) introduce a small data-dependent timing difference (a second query runs only when the first misses), but the response is constant and this is not a key/crypto comparison, so it is not a meaningful oracle for a multi-tenant authorization boundary. Constant-time comparison is not required here. | No action. Documented to record the false-positive was considered. |
| F7 | INFO (false-positive checked) | `scripts/backfill-pinned-cids.ts:142-152`, `:192` | SQL safety. The candidate-row query uses only static SQL with a literal `INTERVAL '1 hour'` and `v.is_byo_user = false` — no user input is interpolated, so no injection surface (the script is an operator-run maintenance tool, not request-driven). The batch delete at :192 is parameterized (`WHERE id = ANY($1)`). WR-06's `v.is_byo_user` projection now reflects the real vault value so the defensive `!row.isByoUser` re-assert in `selectRowsToDelete` is meaningful rather than always-true. The WR-05 `pinned_at < NOW() - INTERVAL '1 hour'` cutoff correctly excludes in-flight uploads from phantom deletion. The script also has strong fail-safes (aborts on empty Kubo pin set, non-zero exit on partial failure). | No action. Parameterization and guards are correct. |

## WR-02 compensation path — explicit authorization analysis

The new direct `this.ipfsProvider.unpinFile(result.cid)` at `ipfs.controller.ts:133` was scrutinized for
cross-tenant abuse:

- It is reachable ONLY inside the `catch` of `recordPin` failure within the authenticated `upload` handler,
  and `result.cid` is the CID that THIS request just produced via `pinFile(file.buffer)` (controller :112).
  The caller cannot supply an arbitrary CID to this path — it is derived server-side from the uploaded bytes.
- Because it bypasses `guardedUnpin`, it also bypasses the cross-user refcount. The risk would be: uploader U
  uploads bytes that dedupe to a CID already pinned by user V; `recordPin` fails for U; the compensation
  physically unpins the CID that V still relies on. This is exactly the documented D-13 race window
  (controller :128-132). It requires byte-identical ciphertext (AES-256-GCM with a random per-file key/IV
  makes collision cryptographically negligible) AND a sub-second failure window AND V's content to have been
  pinned in that gap. Practically negligible, and the drift report detects the resulting orphan. Accepted as a
  documented residual, consistent with the phase decision. No code change recommended, but flagged so it is on
  the record: this single path can, in theory, drop a CID without a refcount check.

Net: the externally-controllable `/unpin` route is fully refcount-gated; the only refcount-bypassing unpin is
the internal compensation path operating on a server-derived CID under a cryptographically-negligible race.

## Test Case Suggestions

Authorization (multi-tenant):

- User B pins CID X; User A (no row for X) calls `/unpin` X → returns success, B's pinned_cids row intact,
  Kubo pin for X still present, `unpinCrossUserAttempts` incremented, no outbox row created.
- Users A and B both pin CID X; A unpins → A's row gone, refcount=1, NO outbox row, Kubo pin retained;
  then B unpins → refcount=0, outbox row inserted, Kubo unpin attempted.
- `/unpin` for a CID nobody owns → success, no metric, no outbox, no Kubo call.

Advisory lock / concurrency:

- Concurrent `guardedUnpin` and drain for the same CID → exactly one physical unpin; no double-decrement.
- Re-upload (recordPin) interleaved with a drain of the same CID → drain re-reads refs>0 under the lock,
  skips physical unpin, deletes the stale outbox row (no data loss). (Regression already added: WR-03.)
- INT_MIN hashtext input: craft/seed a CID whose `hashtext` returns -2147483648 → advisory lock acquires
  without bigint-out-of-range (regression for WR-01).

Input validation:

- `/unpin` with `cid` containing `?`, `&`, `/`, `..`, whitespace, or a trailing query segment → 400 (regex
  anchored, rejected). Confirm CIDv0 `Qm...` (46 char) and CIDv1 `b...` (base32) accepted; >255 chars → 400.
- Add a `unpinFile` unit test asserting the built URL is `encodeURIComponent`-safe even if the regex were
  bypassed (drives the F1 fix).

CID input availability:

- Kubo `fetch` hang simulation → assert the call times out (after F2 fix) and the DB connection + advisory
  lock are released rather than held indefinitely.

SDK on-demand traversal:

- Folder subtree with an A→B→A cycle in decrypted metadata → traversal terminates, each name collected once.
- Subfolder with a wrong/corrupt `folderKeyEncrypted` → `unwrapKey` throws generic error, sibling subfolders
  still collected, folder's own IPNS name still in the accumulator, NO key material in any log line.
- `loadFolderMetadata` returns null (unpublished IPNS) → folder's own name collected, no recursion, no throw.
- Empty bin / empty entries → no unenroll dispatch, no crash.
- Deep legitimate (non-cyclic) subtree → all descendant IPNS names collected on-demand even when never
  expanded in-session (HARD-01 leak closed).

Logging hygiene:

- Assert `this.internalVaultKeypair.privateKey`, any unwrapped `folderKey`, and any plaintext metadata are
  never passed to `console.warn`/`console.error` in the traversal and dispatch paths.

## SECURITY REVIEW COMPLETE

Files analyzed: 9 (diff) + 3 supporting (local.provider.ts, pinned-cid.entity.ts, ecies/decrypt.ts)
Crypto operations touched: 1 (ECIES key unwrap in SDK traversal) — reused, not new
Issues found: 0 CRITICAL, 0 HIGH, 1 MEDIUM, 4 LOW, 2 INFO (false-positives documented)

Top issues:

1. F1 (MEDIUM) — `LocalProvider.unpinFile` builds `pin/rm?arg=${cid}` without `encodeURIComponent`; the
   `/unpin` route is mitigated by the anchored DTO regex, but the function is unsafe by construction and
   has callers (compensation, drain) that don't go through the DTO. One-line fix recommended.
2. F2 (LOW/availability) — no timeout on the Kubo `fetch`, so a hung Kubo holds a DB connection (and, in the
   drain, the per-CID advisory lock) for the hang duration. Add an AbortController timeout.
3. F3/F5 (LOW) — hashtext advisory-lock collisions are benign (availability-only, never a correctness bug);
   SDK traversal cycle guard is correct, depth/children-size not capped (self-DoS only).

Recommendations (priority order):

1. Add `encodeURIComponent(cid)` in `LocalProvider.unpinFile` (closes F1 at the source).
2. Add a bounded `fetch` timeout to the Kubo provider calls (closes F2).
3. Keep crypto/metadata-layer errors generic and dispatch-site logging to `err.message` only; optionally cap
   traversal depth / children length as belt-and-suspenders (F4/F5).

---

## Branch /security-review (adversarial, false-positive-filtered pass)

Run 2026-06-19 against the full branch diff (`origin/main...HEAD`), confidence bar >= 8.

**Result: 0 high-confidence newly-introduced exploitable vulnerabilities.**

Candidates evaluated and rejected:

- **WR-02 direct `unpinFile` rollback** (`ipfs.controller.ts`) — the only cross-user physical-unpin change. Not exploitable: `result.cid` is server-derived from Kubo's `pinFile` response (never attacker-supplied); targeting a specific victim's deduped CID requires uploading byte-identical AES-256-GCM ciphertext (per-user keys + random IVs make this cryptographically infeasible); and the prior `origin/main` path was a no-op (no `pinned_cids` row exists after `recordPin` throws, so `guardedUnpin` early-returned and leaked the pin) — so this is a leak fix, not an authz regression.
- **SQL injection** (advisory-lock/refcount/backfill) — all parameterized (`$1`/`[cid]`), no interpolation.
- **CID into `LocalProvider.unpinFile` URL** — pre-existing line (not a Phase 50 change); every reaching CID is server-derived or anchored-regex-validated at the route boundary. Captured as WR-05 todo (defense-in-depth, non-exploitable).
- **SDK subtree recursion** — `visited` guard added; only failure mode is client-side resource use (excluded DoS; client is not the trust boundary).

Authorization model (`guardedUnpin`: ownership row -> cross-user refcount under per-CID advisory lock -> Kubo `pin/rm` only at refcount 0) verified sound by both passes. No secrets/keys logged; ECIES unwrap failures throw a generic `CryptoError`.

**Deferred (non-blocking, both passes agree not exploitable):** WR-05 `encodeURIComponent` hardening on `LocalProvider.unpinFile` (`2026-06-19-local-provider-unescaped-cid-in-pin-url.md`); F2 Kubo-fetch AbortController timeout (availability hardening, folded into the advisory-lock-across-network concern).
