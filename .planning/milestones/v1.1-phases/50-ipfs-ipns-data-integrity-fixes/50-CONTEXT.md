# Phase 50: IPFS/IPNS Data-Integrity Fixes - Context

**Gathered:** 2026-06-19
**Status:** Ready for planning
**Source:** Direct decision capture (discuss-phase skipped — scope is two captured todos with confirmed root causes; one locked design decision provided by user)

<domain>

## Phase Boundary

This phase resolves two captured data-integrity defects under requirement **HARD-01** (no data
loss / no permanently-undeletable CIDs; unenroll nested IPNS records under unloaded subtrees):

- **[#12]** The Phase 42 guarded-unpin / pending-unpins code review (`42-REVIEW.md`, 7 warnings +
  6 info, no resolution section) — re-verified against live code 2026-06-18, all findings still
  present. Two are correctness/data-loss risks (WR-01, WR-03).
- **[#14]** `collectSubtreeIpnsNames` only walks already-loaded folder state, so deleting a folder
  whose subtree was never expanded leaves nested file/folder IPNS records un-unenrolled (TEE keeps
  republishing them; they linger until natural expiry).

In scope: the unpin/pending-unpin correctness fixes, the on-demand subtree IPNS collection fix,
and regression tests for both data-loss classes. Out of scope: any broader unpin/refcount redesign,
new background reconciliation jobs (explicitly rejected for #14 — see D-03), and the unrelated
HARD-02..06 hardening items (Phases 51–55).

</domain>

<decisions>

## Implementation Decisions

### #12 — Phase 42 unpin-integrity findings (HIGH-severity, must fix with regression tests)

- **D-01 (WR-01, HIGH):** Eliminate the `abs(hashtext($1))::bigint` integer-overflow in the
  advisory-lock hash in `apps/api/src/vault/vault.service.ts`. For the CID whose `hashtext` is
  `INT_MIN (-2147483648)`, `abs(int4)` raises `ERROR: integer out of range`, making that file
  permanently undeletable via the API and permanently sticking its quota row. Fix by dropping
  `abs()` (negative lock keys are valid for `pg_advisory_xact_lock`, which takes signed bigint) or
  by casting first (`abs(hashtext($1)::bigint)`). Ship a regression test proving an INT_MIN-hash CID
  is deletable.

- **D-02 (WR-03, HIGH):** Make the pending-unpin drain refcount-aware in
  `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts`. `drainPendingUnpins` currently
  unpins every outbox CID unconditionally; if a CID was re-pinned/re-recorded (re-upload of
  identical ciphertext, or a pin-migration flow) while still in `pending_unpins`, the drain removes a
  **live pin** → Kubo GC → data loss. Before `unpinFile`, count `pinned_cids` for the CID; if `> 0`,
  delete the stale outbox row and `continue`. Ship a regression test proving a re-pinned CID is NOT
  unpinned during drain.

### #12 — Remaining WR/IN findings (disposition required)

- **D-04 (remaining WR/IN):** Each remaining finding — WR-02 (upload-compensation `guardedUnpin`
  no-op leaks the Kubo pin and can fire the cross-user security alert on internal failures), WR-04
  (Counter vs Gauge for `driftOrphanedPinsTotal` — `42-REVIEW.md` author judged WR-04 acceptable;
  todo concurs), WR-05 (backfill TOCTOU deletes in-flight upload rows as phantoms), WR-06 (backfill
  hardcodes `false::boolean AS "isByoUser"`, defeating the defensive re-assert), WR-07 (BYO advisory
  rows block physical unpin of hosted content indefinitely — non-owner-controllable retention path),
  IN-01..IN-06 — must be either **fixed** (per the concrete patch in `42-REVIEW.md`) or
  **explicitly accepted** with an inline code comment + rationale. No finding may be left silently
  unaddressed. WR-02, WR-05, WR-06, WR-07 are correctness/security-adjacent and should be fixed
  unless there is a strong rationale to accept.

### #14 — Nested IPNS unenroll under unloaded subtrees

- **D-03 (LOCKED — on-demand traversal):** Fix `collectSubtreeIpnsNames` in
  `packages/sdk/src/client.ts` to resolve and traverse the **persisted folder metadata** for the
  subtree being deleted — fetch + decrypt child folder metadata on demand — so the full set of
  descendant file/folder IPNS names is collected regardless of in-memory load state. Do **NOT** rely
  on the in-memory `folderTree`, and do **NOT** implement the periodic reconciliation-job backstop
  (the rejected alternative). Acceptance: deleting a folder with an unloaded subtree unenrolls every
  descendant IPNS name — assert the unenroll batch count matches the full subtree, not just loaded
  nodes.

### Claude's Discretion

- Exact SQL form for D-01 (drop `abs()` entirely vs. cast-first) — pick whichever is least
  surprising given the surrounding query; the lock-key sign does not matter functionally.
- Mechanism for the WR-02 no-row physical unpin (direct `unpinFile` for the zero-`pinned_cids` case
  vs. a `guardedUnpin` internal variant that skips cross-user telemetry).
- Whether to extract a shared `IpfsProviderCoreModule` (IN-04) or accept the triplicated factory
  with a comment.
- Test framework placement/structure (follow existing `vault.service.spec.ts` /
  `pending-unpin.processor.spec.ts` / SDK test conventions).
- The on-demand traversal's fetch/decrypt call path, batching, and error handling for an
  undecryptable/missing child node — must degrade safely (a fetch failure on one child must not
  abort the whole delete) and should be observable.

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### #12 — Phase 42 unpin findings

- `.planning/todos/pending/2026-06-18-phase42-unpin-integrity-review-open-findings.md` — the captured
  todo: which findings, re-verification date, fix + acceptance summary.
- `.planning/phases/42-api-unpin-integrity/42-REVIEW.md` — the authoritative finding list with a
  concrete patch per WR/IN item (line numbers are from 2026-06-12; re-verify against live code).
- `apps/api/src/vault/vault.service.ts` — `guardedUnpin`, advisory-lock hash, refcount logic.
- `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` — drain + drift worker.
- `apps/api/src/ipfs/ipfs.controller.ts` — upload compensation path (WR-02).
- `apps/api/src/ipfs/dto/unpin.dto.ts` — `UnpinDto` (IN-02 validation).
- `scripts/backfill-pinned-cids.ts` + `apps/api/src/scripts/backfill-helpers.ts` — backfill
  (WR-05/WR-06).

### #14 — Nested IPNS unenroll

- `.planning/todos/pending/2026-06-18-unenroll-skips-unloaded-subtrees.md` — the captured todo.
- `packages/sdk/src/client.ts` — `collectSubtreeIpnsNames` (early-return on unloaded folder ~`:232`)
  and the four deletion paths that call it (wired in Phase 29).
- `docs/FILESYSTEM_SPECIFICATION.md` — encrypted folder metadata / IPNS record structure.

### Project rules

- `CLAUDE.md` — terminology, security rules (ECIES/AES-256-GCM, zero-knowledge server), API client
  regen (`pnpm api:generate`) whenever API endpoints/DTOs/controllers change.
- `docs/CAPACITY.md` — referenced by WR-07 (document the retention consequence if D-07 stands).

</canonical_refs>

<specifics>

## Specific Ideas

- WR-01 and WR-03 are the only hard data-loss / permanent-undeletability findings; they are the
  must-ship core of #12 and each needs a dedicated regression test.
- The Phase 42 review predates code drift — `42-REVIEW.md` cites `vault.service.ts:255` while the
  todo cites `:262`. Re-verify exact locations against live code before patching.
- `pnpm api:generate` must run if any API endpoint/DTO/controller signature changes (e.g. if IN-02
  adds validation to `UnpinDto`); commit the regenerated client alongside API changes (pre-commit
  hook enforces this).

</specifics>

<deferred>

## Deferred Ideas

- Periodic unenroll-reconciliation background job (the rejected #14 alternative) — remains in
  BACKLOG as a possible future backstop; explicitly NOT built in this phase per D-03.
- HARD-02..06 hardening items (crypto/secret, FUSE, release-eng, test-infra, refactor) — Phases
  51–55.

</deferred>

---

_Phase: 50-ipfs-ipns-data-integrity-fixes_
_Context captured: 2026-06-19 via direct decision capture (discuss-phase skipped)_
