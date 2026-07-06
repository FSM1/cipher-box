# Phase 69: FUSE and WinFsp — Rust Integration and Grant-Root Awareness - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-07-06
**Phase:** 69-fuse-and-winfsp-rust-integration-and-grant-root-awareness
**Areas discussed:** 68.2 sequencing, Read-chain crate placement, Durable floor storage, Node enum cutover, Rotation-engine port scope, WinFsp/Windows sequencing, Write-plane dual-keying

---

## 68.2 Sequencing

| Option | Description | Selected |
|--------|-------------|----------|
| Mirror design doc, proceed now (Rec) | Implement to the shared design + 68.1 ROT-07 gate semantics; don't block on TS 68.2 | ✓ (refined) |
| Block until TS 68.2 ships | Wait for a proven TS reference to copy 1:1 | |
| Paired contract in plan-phase | plan-phase produces one shared contract both TS 68.2 and Rust 69 satisfy | |

**User's choice:** Proceed now — refined: the TS contract is available in the Phase 68.2 planning docs already pushed to `origin/feat/sdk-owned-read-chain-and-resolved-folder-listings`.
**Notes:** The planning agent cannot switch to that branch (checked out in the main worktree) but must use those docs as the basis for 69's plans — read via `git show`. Captured as D-01 + the canonical-refs access rule.

---

## Read-chain Crate Placement

| Option | Description | Selected |
|--------|-------------|----------|
| core = resolve/unseal, sdk = gate+floor+listing (Rec) | Mirror TS packages/core vs packages/sdk split; FUSE/WinFsp consume the listing | ✓ |
| All in crates/core | Blend pure codec with stateful gating; diverges from TS split | |
| New dedicated read crate | Fresh crate owns the whole read chain | |

**User's choice:** core = resolve/unseal, sdk = gate + floor + listing (Recommended).
**Notes:** Captured as D-02.

---

## Durable Floor Storage

| Option | Description | Selected |
|--------|-------------|----------|
| JSON sidecar + injected trait (Rec) | Sidecar file next to the journal dir, behind an injected HighWaterStore-analog trait | ✓ |
| Embedded KV (redb/sled) | Durable/atomic out of the box but adds a dep + DB file for a few counters | |
| SQLite | Transactional but heavyweight for monotonic counters; new runtime dep | |

**User's choice:** JSON sidecar + injected trait (Recommended).
**Notes:** Rust mirror of 68.2 D-04's injected store. Captured as D-03.

---

## Node Enum Cutover

| Option | Description | Selected |
|--------|-------------|----------|
| Clean cutover, delete legacy (Rec) | Introduce enum Node, delete the four legacy structs, migrate all call sites, conform to KAT | ✓ |
| Coexist/bridge temporarily | Land Node alongside legacy with a conversion bridge; incremental migration | |
| You decide | Let the planner pick from call-site blast radius | |

**User's choice:** Clean cutover, delete legacy (Recommended).
**Notes:** Matches greenfield single-codec doctrine. Captured as D-04.

---

## Rotation-Engine Port Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Full port in-phase (Rec) | Port the resumable 63/64 engine (CRIT-1, M1, HIGH-3, HIGH-4) into crates/sdk | ✓ |
| Let the planner size it first | Route to plan-time design pass; decide in-phase vs split with real numbers | |
| Split: foundation now, engine → 69.1 | Smaller 69; SC#3 rotation trigger fail-closed until 69.1 (roadmap adjustment) | |

**User's choice:** Full port in-phase (Recommended).
**Notes:** Dominant plan-cluster, sequenced after the Node-enum + read-chain foundation. Grant-root scope-computation algorithm still routed to the plan-time design pass. Captured as D-05.

---

## WinFsp / Windows Sequencing

| Option | Description | Selected |
|--------|-------------|----------|
| FUSE first, WinFsp in-phase fast-follow (Rec) | Build/verify FUSE locally, port Windows against same API, verify via CI round-trips | |
| Lockstep parity per file | Implement macOS/Linux + Windows together; many CI round-trips | |
| Defer WinFsp to a follow-up phase | 69 = FUSE only (contradicts SC#2/#5) | |

**User's choice:** WinFsp in-phase as a **separate plan**, executed by the user on a Windows machine — so no long CI round-trips are needed.
**Notes:** `Cargo Check & Test (Windows)` CI gate + dispatch-gated desktop E2E remain the sign-off authority. Captured as D-06.

---

## Write-Plane Dual-Keying

| Option | Description | Selected |
|--------|-------------|----------|
| Hard constraint + security-review flag (Rec) | MUST thread both WriteChildRef.childId (UUID) and SealedChildRef (ipnsName); flag write-ops for review | ✓ |
| Note as a research item only | Mention for the researcher; don't elevate to a locked constraint | |

**User's choice:** Hard constraint + security-review flag (Recommended).
**Notes:** Prevents a silent rotateWriteFromNode break. Captured as D-07.

---

## Claude's Discretion
- Exact Rust type/field naming (`ResolvedChild`, floor-store trait name, event mechanism) and error shapes — follow `crates/sdk` conventions + 68.2 naming where it maps.
- Module-split decisions within `crates/core`/`crates/sdk` — planner's call from call-site blast radius.

## Deferred Ideas
- None (no new capabilities raised). Two TS-side todos (`delete-drop-writechildref`, `move-within-scope-reseal-readkey`) reviewed and kept in backlog as references (see CONTEXT.md Reviewed Todos); one Rust/FUSE todo (`replay-reuse-verified-parent-sequence`) folded as superseded by the read-chain consolidation.
