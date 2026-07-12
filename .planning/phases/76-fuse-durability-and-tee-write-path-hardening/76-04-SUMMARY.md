---
phase: 76-fuse-durability-and-tee-write-path-hardening
plan: 04
subsystem: tee-write-path
tags: [tee-worker, ipns, renew, eol, invariant, crypto, hardening]
status: complete
requires:
  - parseIpnsRecord / unmarshalIPNSRecord (packages/crypto ipns codec)
  - renewIpnsRecord lease-renew primitive (Phase 67-03 ipns-signer)
provides:
  - additive ParsedIpnsRecord.validity Date field
  - strictly-later-EOL invariant guard in renewIpnsRecord (EolRollbackError)
  - sanitized try/catch around renewIpnsRecord parse/sign/marshal
affects:
  - packages/crypto/src/ipns
  - apps/tee-worker/src/services
tech-stack:
  added: []
  patterns:
    - additive codec field sourced from the ipns library result (no hand-rolled decode)
    - invariant compared against the parsed EXISTING validity, never Date.now() wall-clock
    - deterministic EOL tests via faked Date only (toFake ['Date']) — no real-timer stalls
key-files:
  created: []
  modified:
    - packages/crypto/src/ipns/parse-record.ts
    - packages/crypto/src/__tests__/ipns-record.test.ts
    - apps/tee-worker/src/services/ipns-signer.ts
    - apps/tee-worker/src/__tests__/ipns-signer.test.ts
decisions:
  - "ipns@10.1.3 IPNSRecord.validity is an RFC3339 STRING, not a Date (RESEARCH/plan assumed Date) — parse-record maps it to a Date via new Date(record.validity), satisfying the additive validity: Date contract"
  - "renewIpnsRecord reads the NEW record's EOL by re-parsing its own marshaled bytes (parseIpnsRecord(marshaled).validity) so the comparison uses the actual on-wire validity"
  - "EolRollbackError is thrown OUTSIDE the sanitized try/catch (and instanceof-passed through inside it) so the invariant signal is never remapped to the generic sanitized error"
  - "equal/earlier/longer-than-default EOL rejections made deterministic with vi.useFakeTimers({ toFake: ['Date'] }) + setSystemTime — faking only Date avoids stalling the crypto's real microtasks"
metrics:
  duration: 20min
  completed: 2026-07-12
  tasks: 2
  files: 4
---

# Phase 76 Plan 04: renewIpnsRecord Strictly-Later-EOL Invariant Summary

One-liner: `renewIpnsRecord` can no longer mint an IPNS record whose end-of-life is equal to or earlier than the existing record's (an EOL rollback) — `ParsedIpnsRecord` now surfaces an additive `validity: Date`, the renewal compares the new EOL against the parsed EXISTING validity (never `Date.now()`) and throws `EolRollbackError` on a non-advancing EOL, its crypto sequence is wrapped in a sanitized try/catch, and the tests assert the invariant directly (equal, earlier, and longer-than-default-lifetime rejections) plus the strictly-later accept path.

## What Was Built

### Task 1 — Additive ParsedIpnsRecord.validity (parse-record.ts)

- Added a `validity: Date` field to `ParsedIpnsRecord`, populated inside `parseIpnsRecord` from the `ipns` package's `unmarshalIPNSRecord().validity` (an RFC3339 string) via `new Date(record.validity)` — no hand-rolled CBOR validity decode.
- Additive only: `value`, `sequence`, `signatureV2`, `data`, `pubKey` mappings are untouched. A consumer grep across `packages/`, `apps/api`, `apps/tee-worker` found only the type export and `parse-record.ts` as source consumers; the two api spec mocks use untyped `jest.Mock` `mockResolvedValue(...)` and are unaffected.
- Test (ipns-record.test.ts): asserts `parsed.validity` is a `Date` equal to `unmarshalIPNSRecord().validity` and in the future for a 24h-lifetime record.

### Task 2 — Strictly-later-EOL guard + sanitized try/catch (ipns-signer.ts)

- Added `class EolRollbackError extends Error` (safe operation context only, no key material).
- `renewIpnsRecord` now: parses the existing record (capturing `existingValidity`), mints the new record, re-parses the new marshaled bytes to read the actual `newValidity`, and — AFTER the try/catch — rejects with `EolRollbackError` when `newValidity <= existingValidity`. The comparison is `.getTime()` on the two parsed validities; no `Date.now()` arithmetic (clock-skew safe).
- parse/sign/marshal are wrapped in a try/catch that rethrows `new Error('Failed to renew IPNS record', { cause })` — sanitized, no key bytes; a caught `EolRollbackError` is re-thrown as-is (never remapped).
- Tests (ipns-signer.test.ts): `renewed.validity > existing.validity` on the normal path; a nested deterministic (faked-Date) describe covering equal-EOL rejection, earlier-EOL rejection, the longer-than-default original-lifetime (96h original vs 48h default renewal) rejection, and a strictly-later accept.

## Deviations from Plan

### 1. ipns.validity is a string, not a Date (plan/RESEARCH assumption corrected)

- **Plan/RESEARCH assumption A/Task 1:** "`unmarshalIPNSRecord().validity` already carries `validity: Date`".
- **Reality (ipns@10.1.3):** `IPNSRecord.validity` is typed and returned as an RFC3339 `string` (nanosecond-precision EOL), not a `Date`.
- **Resolution:** kept the additive contract's `validity: Date` and derived it with `new Date(record.validity)`. This preserves the plan's intended API and the strictly-later comparison. Sub-millisecond RFC3339 precision is truncated to `Date`'s ms resolution — harmless here since renewal EOL deltas are seconds-to-hours, far above 1ms.

### 2. renewIpnsRecord reads the new EOL by re-parsing its own marshaled bytes

- The plan said "compare the new record's minted validity". `createIpnsRecord` returns an `IPNSRecord` whose `validity` is also a string; rather than hand-convert, the function re-parses the just-marshaled bytes through the same `parseIpnsRecord` path, so both sides of the comparison come from the identical codec (defensive against any create-vs-marshal drift). One extra parse per renewal — negligible.

## Threat Model Mitigations Applied

- **T-76-11 (Tampering, renewIpnsRecord EOL):** strictly-later-EOL guard vs the parsed existing validity rejects equal/earlier renewals; compared without wall-clock arithmetic (Task 2).
- **T-76-12 (Info disclosure, crypto-sequence errors):** sanitized try/catch rethrows safe operation context only — no key material in the message or cause chain (Task 2).

## Verification

- `pnpm --filter @cipherbox/crypto test` — 211 passed (incl. the new validity: Date assertion).
- `pnpm --filter cipherbox-tee-worker test` — 6 files, 84 passed (incl. the 5 renew invariant/accept tests and 4 rollback-rejection cases).
- `pnpm --filter cipherbox-tee-worker build` (tsc) — clean.
- `grep Date.now` in renewIpnsRecord + its test — only in explanatory comments; no `Date.now()` arithmetic in the EOL comparison.
- ParsedIpnsRecord change is additive; consumer grep confirms no break. No new external dependency; string literals over enums.

## Commits

- 8926d0719: feat(crypto): surface additive validity Date on ParsedIpnsRecord (Task 1)
- f3cb9f4a3: fix(tee-worker): enforce strictly-later-EOL invariant in renewIpnsRecord (Task 2)

## Self-Check: PASSED

- SUMMARY file present on disk.
- Both commits (8926d0719, f3cb9f4a3) present in git history.
- renewIpnsRecord rejects equal/earlier EOL vs the parsed existing validity; no wall-clock comparison; sanitized error path; all tests green.
