# Phase 68: Web Integration — Rotation UX and Durable Client State - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-01
**Phase:** 68-web-integration-rotation-ux-and-durable-client-state
**Areas discussed:** Co-writer offline UX (Q1), Rotation progress UX, Reconcile / regression fail-closed UX, Q3 owner-reconcile cadence, IndexedDB-unavailable floor, Multi-tab coordination, Deferred-mutation terminal behavior, Rotation badge placement

---

## Co-writer offline UX (Q1)

| Option | Description | Selected |
|--------|-------------|----------|
| Explicit error + one-tap re-fetch | Write fails closed with a clear message + 'Refresh access' action re-resolving the write descriptor; escalates to 'write access revoked' if rotated out. Matches explicit WRITE-03 model. | ✓ |
| Auto-refetch + silent retry | Transparently re-resolve and retry once before surfacing an error; hides the access-state change. | |
| Grace period | Allow the stale write for N minutes with a warning banner; contradicts explicit-revocation model (ADR 0001). | |

**User's choice:** Explicit error + one-tap re-fetch (Recommended)
**Notes:** Aligns with WRITE-03 / ADR 0001 "explicit — cannot write until re-fetch." → CONTEXT D-01.

---

## Rotation progress UX

| Option | Description | Selected |
|--------|-------------|----------|
| Background badge + fast root cut | Root cut completes synchronously; tail walk runs in background with a persistent 'Finishing revocation…' badge that resumes on reload. Aligns with best-effort-host + resumable-walk. | ✓ |
| Blocking modal with progress bar | Block UI until the whole subtree finishes; punishes large revokes, breaks multi-session/reload story. | |
| Fire-and-forget toast | Toast on start, no persistent progress surface. | |

**User's choice:** Background badge + fast root cut (Recommended)
**Notes:** Consistent with Phase 63 Q2 (web = best-effort host; long multi-session rotation accepted). → CONTEXT D-02.

---

## Reconcile / regression fail-closed UX

| Option | Description | Selected |
|--------|-------------|----------|
| Defer + visible retry, hard-fail on regression | Reconcile failure → mutation DEFERS (never publishes on stale state, SC#3) with auto-retry notice; regression → hard fail-closed error toast. | ✓ |
| Hard block modal | Block UI until reconcile/verify succeeds; freezes app on transient relay slowness. | |
| Silent auto-retry | Retry in background, no user surface until retries exhaust; risks looking like a hang. | |

**User's choice:** Defer + visible retry, hard-fail on regression (Recommended)
**Notes:** Surfaced as per-mutation toast, not global block. → CONTEXT D-04 / D-05.

---

## Q3 owner-reconcile cadence

| Option | Description | Selected |
|--------|-------------|----------|
| Eager on app-open + after owner mutations, no advisory to C | Owner reconcile runs on login/app-open + opportunistically after owner mutations; no new schema; C gets no advisory (window documented per ADR 0002). | ✓ |
| Lazy on next mutation only | Runs only when owner next mutates the affected subtree; leaves dangling grants live longer if owner idle. | |
| Explicit 'Reconcile shares' action | Owner triggers manually; largest window, relies on owner remembering. | |

**User's choice:** Eager on app-open + after owner mutations, no advisory to C (Recommended)
**Notes:** Crypto mirrors Phase 65 D-01 (C unlink+bins, owner reconcile re-derives dangling grants). → CONTEXT D-10 / D-11.

---

## IndexedDB-unavailable / cleared floor

| Option | Description | Selected |
|--------|-------------|----------|
| Degrade to versionFloor + parent generation mirror, warn once | Fall back to design §4.3 first-contact path (seed rootGeneration, cross-check envelope generation vs parent SealedChildRef.generation mirror + versionFloor); in-memory session floor; one-time notice. Reads work; anti-rollback held by signed parent chain. | ✓ |
| Hard-block reads | Refuse to resolve until IndexedDB available; breaks private-browsing entirely. | |
| Silent degrade | Same fallback, no notice; hides weakened-durability state. | |

**User's choice:** Degrade to versionFloor + parent generation mirror, warn once (Recommended)
**Notes:** Colluding-relay old-snapshot residual already accepted as irreducible per §4.3. → CONTEXT D-08.

---

## Multi-tab rotation coordination

| Option | Description | Selected |
|--------|-------------|----------|
| Web Locks leader + monotonic-max high-water | navigator.locks elects one tab to drive the tail walk; others observe; high-water monotonic-max; Web-Locks-unavailable fallback = both run idempotently (safe via CAS-409 + monotonic-max). | ✓ |
| No coordination | Both tabs run idempotently, rely on monotonic-max + CAS-409; doubles publish/walk work. | |
| Single-tab-only rotation | Block rotation UI in all but one tab; adds cross-tab gating + confusing 'locked in another tab' state. | |

**User's choice:** Web Locks leader + monotonic-max high-water (Recommended)
**Notes:** Double-rotation is crypto-safe (Phase 64 D-07); coordination is an efficiency win, not a correctness requirement. → CONTEXT D-09.

---

## Deferred-mutation terminal behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Bounded backoff → terminal error + manual retry, nothing queued | Auto-retry with backoff for a bounded window (~5 attempts / ~30s); on exhaustion, terminal 'couldn't complete securely — retry' + manual action; mutation NOT applied (SC#3); no durable queue. | ✓ |
| Retry until success or navigation | Retry indefinitely; can look like a permanent hang. | |
| Durable retry queue across reloads | Persist pending mutation, retry across reloads; adds a durable write-queue (scope creep). | |

**User's choice:** Bounded backoff → terminal error + manual retry, nothing queued (Recommended)
**Notes:** Exact retry counts/backoff = Claude's discretion. → CONTEXT D-06.

---

## Rotation badge placement + reload copy

| Option | Description | Selected |
|--------|-------------|----------|
| Global header badge + resume state now, copy/visual at UI-phase | Lock placement: global app-header/status badge (visible across navigation) with 'Resuming revocation…' state after reload; defer exact copy/visual to /gsd-ui-phase 68. | ✓ |
| Per-folder inline indicator | Indicator only within affected folder view; invisible after navigating away mid-walk. | |
| Full spec now | Nail placement + copy + all states now, skip a separate UI-phase pass. | |

**User's choice:** Global header badge + resume state now, copy/visual at UI-phase (Recommended)
**Notes:** UI hint = yes; defer pixel/copy to /gsd-ui-phase 68. → CONTEXT D-03.

---

## Claude's Discretion

- Exact retry counts / backoff curve (D-06).
- IndexedDB store name, schema version, eviction policy (D-07).
- Badge copy, visual treatment, per-state text (D-03) → resolved at `/gsd-ui-phase 68`.

## Deferred Ideas

- Q3 option (c) — owner-signed revocation-request queue (parked since Phase 65; revisit only if the eager owner-reconcile window proves insufficient).
- Durable cross-reload retry queue for deferred mutations (rejected as scope creep in D-06).
- Q3 FUSE-side authority mirror + all FUSE/WinFsp/Rust rotation integration → Phase 69.
- Badge copy / visual / state text → `/gsd-ui-phase 68`.
