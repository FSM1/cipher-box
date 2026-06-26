# Phase 57: API CID and Provider Hardening and Module Dedup - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-22
**Phase:** 57-api-cid-and-provider-hardening-and-module-dedup
**Areas discussed:** None — phase assessed as fully locked

---

## Skip assessment

Per the discuss-phase skip rule ("if no meaningful gray areas exist — pure infrastructure,
clear-cut implementation, all already decided — the phase may not need discussion"), Phase 57
was assessed and found to have **no open design decisions**. Each of the 4 findings carries a
locked direction from its source todo + the ROADMAP:

| Finding | Why it's locked |
| ------- | --------------- |
| CID validation (WR-02) | The correct v0+v1 regex already exists in `UnpinDto`; the fix is to extract + reuse it with `@MaxLength(255)` on `RegisterCidDto`. No new regex to design. |
| URL encoding (WR-05) | `encodeURIComponent`/`URLSearchParams` on the provider's CID query params. Mechanical. |
| Provider module (IN-04) | Standard NestJS leaf-module extraction; the todo specifies the exact module shape. |
| Unpin primitive | Consolidates the **existing** `pg_advisory_xact_lock` logic into shared helpers; mechanism already chosen. |

One assumption that was checked and corrected during scouting: the codebase **does** use CIDv1
(`LocalProvider` adds with `cid-version=1`), so the shared regex must retain its CIDv1 branch —
recorded as D-02 in CONTEXT.md.

## Claude's Discretion

- File placement of the shared `CID_REGEX` constant and the `withCidLock` /
  `refcountAndMaybeUnpin` helpers.
- `URLSearchParams` vs `encodeURIComponent` exact form.

## Deferred Ideas

- IPNS publish/resolve signature-verify todos → Phase 58.
- Cargo.lock release-sync todo → CI/release track.
