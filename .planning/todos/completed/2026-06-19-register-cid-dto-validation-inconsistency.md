---
created: 2026-06-19T00:00:00.000Z
title: RegisterCidDto CID validation diverges from UnpinDto (open-ended regex, no MaxLength)
area: bug
severity: medium
source: .planning/phases/50-ipfs-ipns-data-integrity-fixes/50-REVIEW.md WR-02 (deferred — file outside phase 50 fix scope)
files:
  - apps/api/src/ipfs/dto/register-cid.dto.ts
  - apps/api/src/ipfs/dto/unpin.dto.ts
---

## Problem

`UnpinDto` validates CIDv0 as `Qm[1-9A-HJ-NP-Za-km-z]{44}` (exactly 46 chars,
correct) and bounds the length with `@MaxLength(255)`. `RegisterCidDto` uses the
open-ended `Qm[1-9A-HJ-NP-Za-km-z]{44,}` and has **no** `@MaxLength`. So:

- A CIDv0 longer than 46 chars is rejected by unpin but accepted by register-cid.
- register-cid accepts arbitrarily long strings — the oversized-string DoS bound
  that motivated `MaxLength(255)` on unpin (per the T-50-12 comment) is absent.

Both values ultimately reach `recordPin`/Kubo, so divergent validation for the
same logical value is a correctness and defense-in-depth gap. This also feeds
WR-05: looser-validated register-cid CIDs flow into the unescaped `pin/rm`/`pin/add`
URL construction in `LocalProvider`.

## Fix

Factor a single shared `CID_REGEX` constant (exact CIDv0 length) plus the
`@MaxLength(255)` decorator, and apply both to `RegisterCidDto.cid`. Change `{44,}`
to `{44}` unless an intentional reason for the open bound is documented.

## Why deferred

`register-cid.dto.ts` is outside phase 50's confirmed fix scope. Captured here so
the DTO change ships with its own review rather than being bundled into the
phase-50 data-integrity fixes.

## Phase 50 /simplify note

Phase 50 /simplify (reuse) confirmed the two CID regexes already DIVERGE in
practice — `unpin.dto.ts` uses `Qm...{44}` (fixed length) while
`register-cid.dto.ts` uses `Qm...{44,}` (variable length). Recommend a single
shared `CID_REGEX` constant or an `@IsCid()` decorator as the fix — it resolves
both the divergence captured above and WR-02 in one change.
