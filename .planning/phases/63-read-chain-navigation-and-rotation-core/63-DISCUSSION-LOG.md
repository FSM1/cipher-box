# Phase 63: Read-Chain Navigation and Rotation Core - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-29
**Phase:** 63-read-chain-navigation-and-rotation-core
**Areas discussed:** Engine 63→64 boundary, Rotation host (Q2), Fan-out deletion boundary, Test gate, Schema dependency, Read-result shape, Invite boundary, Scope predicate inputs, Batched parent-link publish, Job-record/resume ownership

---

## Engine 63→64 boundary (D-01)

| Option | Description | Selected |
|--------|-------------|----------|
| Skeleton + named seams | rotateOne ships the structural walk; the 4 soundness concerns (CRIT-1 fileKey, HIGH-3 grant re-mint, HIGH-4 re-merge, crash-resume) become named, individually-testable seams deferred to Phase 64. Mirrors Phase 62 D-01. | ✓ |
| Happy-path fully correct now | Implement rotateOne fully correct for the no-concurrency/no-inner-grant online case; Phase 64 adds only fault injection. | |

**User's choice:** Skeleton + named seams
**Notes:** Continues the Phase-62 bounded-keystone discipline; the four seams must exist + be individually testable so Phase 64 fills them without re-architecting.

---

## Rotation host — ROADMAP open question Q2 (D-02)

| Option | Description | Selected |
|--------|-------------|----------|
| Web first-class, best-effort | Engine host-agnostic pure logic; root step cuts fast, O(items) tail is resumable background; long web rotation accepted as documented limitation; durable resume-across-reload is Phase 68 (ROT-07). | ✓ |
| Desktop-only for large revokes | Web handles small revokes; large-subtree revokes require the desktop app + a UX gate. | |

**User's choice:** Web first-class, best-effort
**Notes:** Answers ROADMAP Q2. No desktop dependency introduced; web reload restarts the idempotent walk from verifySubtreeClean.

---

## Fan-out deletion boundary (D-03)

| Option | Description | Selected |
|--------|-------------|----------|
| 63 deletes SDK layer; 68 finishes web | Phase 63 deletes reWrapForRecipients + the sdk add-item fan-out path and rewires add-item to parent-key sealing; addShareKeys web-callback removal lands in Phase 68. | ✓ |
| Delete everything now (incl. web) | Pull the web fan-out deletion forward into Phase 63. | |

**User's choice:** 63 deletes SDK layer; 68 finishes web
**Notes:** Preserves the sdk-core/sdk=63, apps/web=68 milestone layering.

---

## Phase 63 test gate (D-04)

| Option | Description | Selected |
|--------|-------------|----------|
| Vitest + ONE happy-path e2e | Vitest bulk (nav walk, O(1) grant issue, scope-exit zero-rotation spy per SC#4, coverage per SC#5) + one sdk-e2e round-trip (grant→navigate→root-step rotate→revoked-cut). Full crash matrix = Phase 64. | ✓ |
| Unit-only; all e2e to Phase 64 | Pure vitest in 63; first live round-trip is Phase 64's crash-safety suite. | |

**User's choice:** Vitest + ONE happy-path e2e
**Notes:** Matches the "sdk-e2e is the only real client→API round-trip" rule for IPNS/key-lifecycle changes.

---

## Schema dependency (D-05)

| Option | Description | Selected |
|--------|-------------|----------|
| Transport-decoupled crypto, mock-tested | Grant issuance + descriptorRef crypto behind the existing callback seam; unit-test with a mocked API; happy-path e2e exercises node nav + rotation over IPNS only (schema-agnostic). Real shares persistence waits for Phase 66. | ✓ |
| Pull a minimal additive shares change into 63 | Add readDescriptorRef columns + migration now. | |
| You decide | Defer to planner. | |

**User's choice:** Transport-decoupled crypto, mock-tested
**Notes:** Keeps Phase 63 in sdk-core/sdk, unblocked by the Phase-66 schema cutover.

---

## Navigation read-result shape (D-06)

| Option | Description | Selected |
|--------|-------------|----------|
| Typed discriminated result | 'ok' \| 'behind-retry' \| 'revoked' union the FUSE/web callers branch on. | ✓ |
| Throw typed errors only | BehindRetryError vs RevokedError thrown from the read path. | |
| You decide | Defer to planner. | |

**User's choice:** Typed discriminated result
**Notes:** No ambiguous boolean/null; satisfies READ-02's soft-behind vs hard-revoked requirement (§4.6).

---

## Invite boundary (D-07)

| Option | Description | Selected |
|--------|-------------|----------|
| Crypto primitive only in 63 | Phase 63 implements the claim re-wrap crypto + stops USING encryptedChildKeys in the SDK claim path; full invite service wiring = Phase 65; JSONB column drop = Phase 66. | ✓ |
| Full invite claim end-to-end in 63 | Pull the invite service + web/API claim flow forward. | |
| You decide | Defer to planner. | |

**User's choice:** Crypto primitive only in 63
**Notes:** READ-05 is satisfied by the re-wrap primitive + its unit test; service/schema work stays in 65/66.

---

## Scope predicate inputs (D-08)

| Option | Description | Selected |
|--------|-------------|----------|
| Pure fn, caller-supplied inputs | hasCoveringGrant is a pure sdk-core function; host supplies grant-root set + local grant record for the anti-malicious-relay cross-check; sdk-core holds no durable state. | ✓ |
| sdk-core fetches grants itself | Predicate calls the API for the grant set internally. | |
| You decide | Defer to planner. | |

**User's choice:** Pure fn, caller-supplied inputs
**Notes:** Isolated-unit-testable; the defer-rather-than-skip policy is enforced by the caller (Phase 68/69).

---

## Batched parent-link publish (D-09)

| Option | Description | Selected |
|--------|-------------|----------|
| Defer batching to Phase 64 | rotateOne does per-node parent-link publish; the batched-parent optimization folds into Phase 64 scale hardening. | ✓ |
| Include batching in Phase 63 | Implement step-8 batched parent publish now. | |
| You decide | Defer to planner. | |

**User's choice:** Defer batching to Phase 64
**Notes:** Keeps the 63 skeleton minimal + correct; seam noted for 64.

---

## Job-record / resume ownership (D-10)

| Option | Description | Selected |
|--------|-------------|----------|
| Type + in-memory loop; persistence host-injected | Phase 63 defines the job-record type + resumable in-memory frontier loop with an optional host-injected persistence callback (no-op default); verifySubtreeClean = Phase 64 seam; durable storage = Phase 68/69. | ✓ |
| Add durable persistence in Phase 63 | Wire an IndexedDB/sqlite job store now. | |
| You decide | Defer to planner. | |

**User's choice:** Type + in-memory loop; persistence host-injected
**Notes:** Published IPNS is the source of truth; the job record is advisory. Consistent with D-02 (web reload restarts the idempotent walk).

---

## Claude's Discretion

- sdk-core module layout beyond the locked `src/rotation/engine.ts` (navigation walk, grant/share helpers, predicate, invite re-wrap placement).
- Exact result/error type names and the `'ok' | 'behind-retry' | 'revoked'` string-literal union.
- Seam-function signatures and helper factoring (each deferred seam must be explicit + name its owning phase).
- Mocked-API unit-test structure.

## Deferred Ideas

- Rotation soundness (ROT-03/04/05/06), TEST-01 crash-safety suite, batched parent-link publish → Phase 64.
- Write-chain / full invite-service wiring / bin re-link / encryptedChildKeys service removal → Phase 65.
- shares/share_keys schema cutover, descriptorRef columns, encryptedChildKeys JSONB drop, atomic CAS gate, tombstone, server-side generation gate → Phase 66.
- TEE lease-renewer → Phase 67.
- Web rotation UX, executeLazyRotation deletion, durable IndexedDB generation + seq high-water (ROT-07/M1), folderTree reconcile-before-rotate, addShareKeys web-callback removal → Phase 68.
- FUSE/WinFsp symmetric unwrap, Rust Node enum, Rust grant-root awareness, durable client floors → Phase 69.
- Q3 (write-recipient deletions vs owner sub-shares) → Phase 65/68/69.
