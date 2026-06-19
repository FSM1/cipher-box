# v1.1 Tech Debt — Tracked TODOs

**Generated:** 2026-06-18
**Scope:** Carried tech debt, deferred items, and known limitations from milestone v1.1 (phases 18–49).
**Companion:** [`MILESTONE_SUMMARY-v1.1.md`](./MILESTONE_SUMMARY-v1.1.md)

This is the consolidated, verified tech-debt ledger for v1.1. Items were swept from every phase's
VERIFICATION/CONTEXT/SUMMARY artifacts, the milestone audit, the phase 42/43 `REVIEW.md` code reviews,
and in-code TODO markers, then **verified against current code** (2026-06-18) so nothing already-fixed is
re-filed and nothing already-tracked is duplicated.

## Legend

- `[ ]` open · `[x]` verified resolved (kept for the record)
- 🆕 **new** — not previously tracked; promoted to `.planning/todos/pending/` (filename noted)
- 📋 **in BACKLOG** — already tracked in [`../BACKLOG.md`](../BACKLOG.md); not duplicated here
- Tag format: `[P{phase}·{id}·{severity}]`

---

## 1. Unpin integrity & quota — Phase 42 `REVIEW.md` (🆕 all new)

Source: `.planning/phases/42-api-unpin-integrity/42-REVIEW.md` (no resolution section; all verified still present in current `apps/api` code 2026-06-18).
Promoted to **`.planning/todos/pending/2026-06-18-phase42-unpin-integrity-review-open-findings.md`**.

- [ ] **[P42·WR-01·high]** `abs(hashtext($1))::bigint` raises "integer out of range" for the CID whose `hashtext == INT_MIN`, making that file **permanently undeletable** (500 on every unpin, quota row stuck). Drop `abs()` or cast first: `abs(hashtext($1)::bigint)`. — `apps/api/src/vault/vault.service.ts:262`
- [ ] **[P42·WR-03·high]** Stale-outbox drain re-pin race: `drainPendingUnpins` unpins every outbox CID unconditionally; if a CID is re-pinned/re-recorded while in `pending_unpins` (re-upload or pin-migration), the next drain removes a **live pin → data loss**. Re-check `pinned_cids` refcount before `unpinFile` and delete the stale outbox row instead. — `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts:53`
- [ ] **[P42·WR-02·med]** Upload compensation calls `guardedUnpin` which no-ops (no `pinned_cids` row for caller after a failed insert) → the just-created Kubo pin **leaks permanently**, and a dedupe match can fire `cipherbox_unpin_cross_user_attempts_total`, **polluting the cross-user security alert** on internal DB failures. — `apps/api/src/ipfs/ipfs.controller.ts:128`
- [ ] **[P42·WR-05·med]** Backfill script snapshots Kubo before querying the DB with no age cutoff → rows for uploads that land in between are deleted as "phantoms" (quota under-count + perpetual drift orphan). Add `pc.pinned_at < NOW() - INTERVAL '1 hour'`. — `scripts/backfill-pinned-cids.ts:88`
- [ ] **[P42·WR-07·med]** Refcount counts **all** `pinned_cids` rows including BYO advisory rows (pins on the user's own node), so a non-owner BYO recipient registering a shared CID can keep hosted ciphertext pinned **indefinitely after the owner deletes** (server-side retention path controllable by a non-owner). Filter the physical-unpin decision to hosted (non-BYO) rows, or document the consequence in the threat model. — `apps/api/src/vault/vault.service.ts:278`
- [ ] **[P42·WR-06·low]** Backfill `SELECT` hardcodes `false::boolean AS "isByoUser"`, making the documented defensive BYO re-assert unable to fire. Select the real `v.is_byo_user` column. — `scripts/backfill-pinned-cids.ts:137`
- [ ] **[P42·IN-01·low]** `fileUnpins.inc()` runs unconditionally — unknown-CID / cross-user no-ops inflate the metric. — `apps/api/src/vault/vault.service.ts:310`
- [ ] **[P42·IN-02·low]** `UnpinDto.cid` lacks the CID regex/`@MaxLength` that `RegisterCidDto` has. — `apps/api/src/ipfs/dto/unpin.dto.ts`
- [ ] **[P42·IN-03·low]** `recordUnpin` is dead code (zero non-test callers) — delete or `@deprecated`. — `apps/api/src/vault/vault.service.ts:317`
- [ ] **[P42·IN-04·low]** `IPFS_PROVIDER` LocalProvider factory duplicated across three modules (cycle workaround) — extract `IpfsProviderCoreModule`. — `vault.module.ts`, `pending-unpin.module.ts`, `ipfs.module.ts`
- [ ] **[P42·IN-05·low]** Drift report `dbCids` includes BYO advisory CIDs, masking hosted orphans (tied to WR-07). — `pending-unpin.processor.ts:84`
- [ ] **[P42·IN-06·low]** `outboxRowInserted` set even when `orIgnore` deduped the insert (misnamed; harmless). — `apps/api/src/vault/vault.service.ts`
- [x] **[P42·WR-04]** ~~`driftOrphanedPinsTotal` Counter vs Gauge~~ — verified acceptable (Counter accumulates per-run orphan observations); no change.

## 2. FUSE write journal — Phase 43 `REVIEW.md` residual (🆕 new)

Source: `.planning/phases/43-fuse-write-durability/43-REVIEW.md`. All **8 critical** findings (CR-01..CR-08) were verified FIXED 2026-06-14. Phases 45/46 then resolved most warnings. Verified-still-open below.
Promoted to **`.planning/todos/pending/2026-06-18-fuse-journal-growth-and-replay-timeout.md`**.

- [ ] **[P43·WR-06·high]** Unbounded journal growth + full ciphertext base64 embedded in journal JSON: a 2 GB file → ~2.7 GB allocation + multi-GB fsync **on the single FUSE callback thread** (macOS) / under the global WinFsp mutex — blocks the whole filesystem, can OOM. No size cap, no GC of parked `Failed` entries, no purge on logout (other vaults' entries persist forever). Store ciphertext in a sidecar `<id>.bin`, cap/stream, add GC + logout purge. — `crates/sdk/src/queue.rs:36`
- [ ] **[P43·WR-07·med]** `replay_for_vault` runs inline in mount with no `NETWORK_TIMEOUT` discipline → a hung connection stalls `mount_filesystem` indefinitely; many entries on a slow link delay mount by minutes. Wrap each entry in `tokio::time::timeout` and/or run replay concurrently with mount. — `apps/desktop/src-tauri/src/fuse/mod.rs:278`
- [ ] **[P43·IN-03·low]** Plaintext `filename`/`name` persisted in journal JSON (0600, local-only) — new at-rest disclosure of vault item names; document in threat model or encrypt. — `crates/sdk/src/queue.rs:62`
- [ ] **[P43·IN-04·low]** `sanitize_error` only scrubs `/Users/` and `/home/`; `C:\Users\…`, `/var`, `/tmp`, `/private` leak into tray/notification copy. — `crates/sdk/src/sync.rs:271`
- [ ] **[P43·IN-05·low]** `let _ = journal.remove(...)` swallows removal errors → a failed removal silently replays later (double-publish risk). At minimum `log::warn!`. — `crates/fuse/src/lib.rs:1494`, `:1558`; `write_ops.rs:679`
- [x] **[P43·WR-01..05, WR-08, WR-09, IN-01, IN-02, IN-06]** Verified resolved by phases 45/46: replay now sorted by `created_at_ms`; BFS folder-key resolution; atomic `0o600` create + parent-dir fsync; mkdir Err rollback; conflict entry-id threading; `deser_opt_string` empty-name guard; `Default` impl removed; retry off-by-one fixed; load skips malformed entries; `record_publish` only post-success.

## 3. Web observability wiring (🆕 new)

Phase 28 specified a redacting logger with a transport hook; Phase 30 was to wire Faro into it. Verified 2026-06-18: **neither the redaction interceptor nor the transport wiring exists** — warn/error logs are not forwarded to Faro and sensitive fields are not stripped from client logs.
Promoted to **`.planning/todos/pending/2026-06-18-web-logger-redaction-and-faro-transport-unwired.md`**.

- [ ] **[P28·D-03·med]** Logger `redact()` interceptor (strip `privateKey`/`rootFolderKey`/`folderKey`/`fileKey`/`accessToken` from context) never implemented — logger does level filtering only. — `apps/web/src/lib/logger.ts`
- [ ] **[P30·med]** `registerFaroTransport(logger.transports)` is defined but **never called** (`initFaro()` doesn't call it) → warn/error logs never reach Faro. — `apps/web/src/lib/faro.ts:177`, `apps/web/src/main.tsx`
- [ ] **[P28·D-04·med]** Logger `transports[]` hook array absent (prerequisite for the above). — `apps/web/src/lib/logger.ts`

## 4. IPNS unenrollment completeness (🆕 new)

- [ ] **[P29·med]** `collectSubtreeIpnsNames` only walks already-loaded folders, so deleting a folder with **unloaded subtrees** leaves nested file IPNS records un-unenrolled (orphaned TEE enrollment + IPNS records). Walk persisted metadata, not just loaded `folderTree`. — `packages/sdk/src/client.ts:232`. Promoted to **`.planning/todos/pending/2026-06-18-unenroll-skips-unloaded-subtrees.md`**. Related (but distinct) BACKLOG item: "Periodic reconciliation job for unenrollment" (📋 phase 29).

## 5. GSD verification / process gaps (🆕 new)

The 2026-06-11 milestone audit flagged these; the verification-ledger close-out commits (#512/#513) covered phases 19.2/23/27/47–49 but **not** 18/31/32. **All three closed 2026-06-19** — VERIFICATION.md authored (goal-backward, each adversarially spot-checked); audit verdict flipped to `passed` (66/66, 20/20).

- [x] **[P18·med]** ~~No `VERIFICATION.md` → PERF-01..04 orphaned~~ — **Closed 2026-06-19:** `18-VERIFICATION.md` (passed). PERF-01/02/04 directly verified with file:line evidence; PERF-03 satisfied via accepted override (Kubo v0.34 emits no libp2p metrics upstream — scrape/panels correctly wired, not a code defect).
- [x] **[P32·med]** ~~No `VERIFICATION.md` and no `VALIDATION.md`~~ — **Closed 2026-06-19:** `32-VERIFICATION.md` (passed) — SC1/SC3 verified statically, SC2/SC4 confirmed by maintainer macOS UAT (Finder no longer hangs). `32-VALIDATION.md` also authored (Nyquist `partial`: E2E covers the async path on main-push; drain/dedup + poll-wait/EIO unit tier documented as Wave-0 gaps — reaching compliant needs Rust unit tests, a code change).
- [x] **[P31·med]** ~~Only `31-VALIDATION.md`; no `VERIFICATION.md`~~ — **Closed 2026-06-19:** `31-VERIFICATION.md` (passed). SC4/SC5 verified; SC1-SC3 size/decomposition deviations accepted as tracked tech-debt (large-file refactor survey todo, 2026-06-19).

**Nyquist VALIDATION.md gap closed 2026-06-19:** the 4 in-scope phases lacking a validation contract (28/29/30/32) now have one (34 was already validated 2026-06-12 — stale in the audit's "missing" list). No in-scope phase is missing a VALIDATION.md (9 compliant / 11 partial / 0 missing). Overall Nyquist stays `partial` — reaching compliant on the 11 partial phases needs automated-test backfill (a code change, out of scope for this docs pass). The new contracts document each gap; two overlap existing todos:

- [ ] **[P29·med]** Nyquist `partial` — `fireAndForgetUnenroll` delete-wiring + `collectSubtreeIpnsNames` recursion ship with zero unit tests. Overlaps §4 / the unenroll-subtree todo. Test backfill needed for compliance.
- [ ] **[P30·med]** Nyquist `partial` — privacy scrubber (`scrubObject`/`beforeSend`) has zero tests, and `registerFaroTransport` is dead code (logger has no `transports` array). Same gap as §3 / the logger-redaction + Faro-transport todo. Test backfill + wiring fix needed.
- [ ] **[P32·low]** Nyquist `partial` — FUSE drain/dedup + poll-wait/EIO unit tier missing (E2E covers the path on main-push only). Rust unit tests needed for compliance.

## 6. Operational / known limitations (🆕 documented, mostly runbook)

- [ ] **[P35·med]** TEE key-source transition is destructive: switching simulator→CVM (or delete+recreate of a CVM) **invalidates all previously-encrypted `encryptedIpnsPrivateKey` values** and destroys the TEE epoch keys. Document a runbook (always UPDATE the CVM, never delete+recreate) and a re-enrollment path. — `35-05-SUMMARY` / `35-VERIFICATION` truth 21
- [ ] **[P29·med]** Staging/prod IPFS API (Kubo `:5001`) is bound to all interfaces in `docker-compose.yml` with an unresolved TODO for env-specific hardening (127.0.0.1 binding / reverse proxy + API auth). — `docker/docker-compose.yml:37`. Overlaps 📋 BACKLOG "Kubo API access control (reverse proxy or ACL)".
- [ ] **[P19.2·info]** Deployment coupling: SDK concurrent pins regress performance (+138% p95 at 50 clients) on `flatfs` — they are **synergistic with the `pebbleds` datastore and must be deployed together**. Both shipped, but document the coupling so a datastore rollback doesn't silently regress uploads. — `19.2-04-SUMMARY`

## 7. Already tracked in `.planning/BACKLOG.md` (📋 not duplicated)

These v1.1 deferrals are already in the backlog inventory and remain correctly tracked there — see [`../BACKLOG.md`](../BACKLOG.md):

- **Sharing (P14/P27):** metadata-embedded sharing, attribution/`lastModifiedBy`, transitive re-sharing, share notifications, immediate key rotation on revoke, faster shared-folder sync, CRDT IPNS inbox.
- **Desktop (P25/P14/P17):** platform code signing (Apple notarization), beta/canary channels, delta updates, retroactive TEE enrollment, desktop sharing/bin/search UI, `.Trash` integration.
- **Upload pipeline (P37):** adaptive concurrency, FUSE write-coalescing, accumulated retry batching, AbortSignal cancellation, lazy file reading in the pool.
- **Observability (P28/P30):** `no-console` ESLint enforcement, Web Worker logging bridge, "Report a problem" button.
- **Infra/data (P29/P12.6/P17):** periodic unenroll reconciliation job, TEE enrollment drift reconciliation, Kubo API ACL.
- **Code quality:** `uint8ToBase64` dedup (Tier 3.3 — verified **3 copies** still: `sdk-core/file`, `sdk-core/folder`, `web/file-metadata.service`), plus Tier-3 cleanups 3.1–3.14.
- **Security review residue (P14/PR #448):** M1 (`itemName` plaintext — note: now mitigated for shares via Phase 48 ECIES `itemNameEncrypted`), M5 (`reWrapForRecipients` residual caller), S1/S2/S3 (IPNS signed-record validation/enforcement/key-zeroization).

## 8. Deferred to v1.2+ (📋 out of scope by design)

Per `REQUIREMENTS.md` and `PROJECT.md`: CRDT-based IPNS inbox for share discovery (IPNS-05), advisory `folder_ipns` CID cache (IPNS-06), device-registry off DB (DB-01), `pinned_cids` elimination (DB-02), client-direct IPFS upload bypassing relay (BYO-08). Milestone 4 (v2.0): Encrypted Productivity Suite, mobile apps, real-time collaboration.

---

## Summary

| Bucket | Count | Tracking |
| ------ | ----- | -------- |
| Phase 42 unpin-integrity review (open) | 12 | 🆕 1 new todo |
| Phase 43 FUSE-journal review (open) | 5 | 🆕 1 new todo |
| Web observability wiring | 3 | 🆕 1 new todo |
| IPNS unenroll completeness | 1 | 🆕 1 new todo |
| GSD verification gaps | 3 | 🆕 1 new todo |
| Operational / known limitations | 3 | 🆕 documented here |
| Already in BACKLOG | ~30 | 📋 referenced |
| Deferred to v1.2+ | — | 📋 referenced |

**Net-new tracked this pass:** 5 pending-todo files in `.planning/todos/pending/` (dated 2026-06-18), covering 24 verified-open items across phases 42, 43, 28/30, 29, and the 18/31/32 process gaps. Two high-severity correctness risks lead the list: **P42·WR-01** (permanent undeletability) and **P42·WR-03** / **P43·WR-06** (data-loss / filesystem-stall).
