---
created: 2026-06-18T00:00:00.000Z
title: Web logger redaction interceptor missing and Faro transport never wired
area: observability
severity: medium
source: Phase 28 (CONTEXT D-03/D-04) vs Phase 30 (deferred registerFaroTransport); verified against live code 2026-06-18
files:
  - apps/web/src/lib/logger.ts
  - apps/web/src/lib/faro.ts
  - apps/web/src/main.tsx
---

## Problem

Phase 28 specified (D-03) a `redact()` interceptor that strips sensitive fields
(`privateKey`/`rootFolderKey`/`folderKey`/`fileKey`/`accessToken`) from log context, and (D-04) a
`transports[]` hook array. Phase 30 was to call `registerFaroTransport(logger.transports)` so
warn/error logs reach Grafana Faro. Verified 2026-06-18:

- `apps/web/src/lib/logger.ts` does **level filtering only** — no `redact()` interceptor and no
  `transports[]` hook array exist. Sensitive fields passed in log context are not stripped.
- `registerFaroTransport` **is defined** in `apps/web/src/lib/faro.ts:177` but is **never called**
  (`initFaro()` in `main.tsx` does not call it), so warn/error logs are **not forwarded to Faro** —
  client-side error/perf telemetry is silently incomplete.

This is the deferral noted in `30-04-SUMMARY` ("registerFaroTransport deferred because Phase 28
logger shipped later") that was never closed.

## Fix

1. Add a `transports: LogTransport[]` array to `logger.ts` and invoke each on warn/error.
2. Add a `redact(context)` interceptor applied before any transport/console emit (reuse the Faro
   `beforeSend` scrub field list for parity).
3. Call `registerFaroTransport(logger.transports)` from Faro init (after `initFaro()`), guarded so
   it is a no-op when Faro is disabled (`VITE_FARO_URL` absent).

## Acceptance

A warn/error log with a sensitive field is redacted in both console and Faro, and a forced error is
visible in Faro from a build with `VITE_FARO_URL` set.
