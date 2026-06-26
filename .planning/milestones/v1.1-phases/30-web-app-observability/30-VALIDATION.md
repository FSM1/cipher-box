---
phase: 30
slug: web-app-observability
status: draft
nyquist_compliant: false
wave_0_complete: true
created: 2026-06-19
---

# Phase 30 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> Retroactive documentation pass — this phase shipped 2026-03-28; statuses below
> reflect the ACTUAL current test coverage (green / manual / missing), not stubs.

---

## Test Infrastructure

| Property               | Value                                              |
| ---------------------- | -------------------------------------------------- |
| **Framework**          | Vitest (jsdom)                                     |
| **Config file**        | `apps/web/vitest.config.ts`                        |
| **Include pattern**    | `src/**/*.test.ts` (NOTE: `.tsx`/`.spec.ts` NOT run) |
| **Quick run command**  | `cd apps/web && pnpm test`                         |
| **Full suite command** | `cd apps/web && pnpm test`                         |
| **Estimated runtime**  | ~10 seconds                                        |

> Coverage caveat: the vitest `include` is `src/**/*.test.ts` only. A test for the
> Faro privacy scrubber must be authored as `src/lib/faro.test.ts` (a `.tsx` or
> `.spec.ts` file would be silently skipped and never run in CI).

---

## Sampling Rate

- **After every task commit:** Run `cd apps/web && pnpm test`
- **After every plan wave:** Run `cd apps/web && pnpm test`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** ~10 seconds

---

## Per-Success-Criterion Verification Map

The phase carries no formal requirement IDs (operational capability — `requirements_addressed: []`
on every plan). The map is keyed to the four roadmap Success Criteria (SC-1..SC-4) and the
plan/task that implements each.

| SC   | Plan  | Behavior                                                       | Test Type   | Automated Command                          | File Exists | Status      |
| ---- | ----- | ------------------------------------------------------------- | ----------- | ------------------------------------------ | ----------- | ----------- |
| SC-1 | 30-02 | FaroErrorBoundary wraps route tree; ErrorFallback renders     | unit (RTL)  | `cd apps/web && pnpm test src/components/ErrorFallback.test.ts` | No          | MISSING     |
| SC-1 | 30-04 | `registerFaroTransport` maps error→pushError, warn→pushLog    | unit        | `cd apps/web && pnpm test src/lib/faro.test.ts` | No          | MISSING     |
| SC-2 | 30-01 | `beforeSend`/`scrubObject` strip sensitive keys + context     | unit        | `cd apps/web && pnpm test src/lib/faro.test.ts` | No          | MISSING     |
| SC-2 | 30-03 | Source maps uploaded server-side, not served to browser       | manual      | Inspect `apps/web/vite.config.ts` (`sourcemap: 'hidden'`, `keepSourcemaps: false`) | N/A (config) | MANUAL-ONLY |
| SC-3 | 30-01 | Web vitals captured via `getWebInstrumentations` → dashboard  | manual      | Verify Grafana Faro dashboard shows CWV after staging deploy | N/A (runtime) | MANUAL-ONLY |
| SC-4 | 30-01 | No PII/keys leak: hex-key, URL-embedded-key, Uint8Array scrub | unit        | `cd apps/web && pnpm test src/lib/faro.test.ts` | No          | MISSING     |
| SC-4 | 30-04 | User identity set to `publicKey` only (never email)           | unit        | `cd apps/web && pnpm test src/lib/faro.test.ts` | No          | MISSING     |

_Status: green · partial · MISSING · MANUAL-ONLY_

---

## Coverage Detail (static enumeration — no suites executed)

### Plan 30-01 — Faro init + privacy scrubbing (`apps/web/src/lib/faro.ts`)

The privacy gate is **pure, deterministic, and highly testable**, yet has **zero
automated tests**. This is the highest-priority gap: it is the exact behavior SC-2
and SC-4 demand, and it guards a zero-knowledge product against key/PII leakage.

Behaviors present in source but UNTESTED:

- `SENSITIVE_KEYS` redaction (`privateKey`, `rootFolderKey`, `folderKey`, `fileKey`,
  `accessToken`, `ipnsPrivateKey`, `teePublicKey`, `userEmail`, `email`) → `[REDACTED]`
- `HEX_KEY_PATTERN` (`/^[0-9a-fA-F]{64,}$/`) → `[REDACTED_KEY]`
- `URL_HEX_KEY_PATTERN` strips hex key material embedded in URLs / hash fragments
- `ArrayBuffer` / `ArrayBuffer.isView` / duck-typed `buffer`+`byteLength` → `[REDACTED_BINARY]`
- Recursion depth guard (`depth > 3` → `[DEPTH_LIMIT]`) for objects and arrays
- `beforeSend` scrubs both `item.payload` and `item.meta`
- `initFaro()` returns `undefined` when `VITE_FARO_URL` is absent (no-op in local dev)

Verification today is grep/read only (`30-VERIFICATION.md`): existence of the keys
and patterns is confirmed, but no behavioral test asserts that a payload containing
a 64-char hex string actually comes out redacted.

### Plan 30-02 — Error boundary (`apps/web/src/App.tsx`, `ErrorFallback.tsx`)

- `FaroErrorBoundary` wraps `AppRoutes` (confirmed at `App.tsx:8-10`).
- `ErrorFallback.tsx` renders title + reload button + "encrypted data is safe" copy.
- No render test asserts the fallback appears on a thrown render error (SC-1).

### Plan 30-03 — Source map upload / staging deploy (config only)

- `vite.config.ts`: conditional Faro rollup plugin, `sourcemap: 'hidden'`,
  `keepSourcemaps: false`.
- `deploy-staging.yml`: 4 occurrences of `VITE_FARO_URL` (web + 3 desktop builds).
- Pure build/CI config — MANUAL-ONLY by nature (no unit surface).

### Plan 30-04 — Logger transport + user identity (`faro.ts`, `useAuth.ts`)

- `registerFaroTransport` maps `error`→`pushError`, `warn`→`pushLog`, drops
  `debug`/`info`, and scrubs context via `scrubObject` before forwarding — UNTESTED.
- `setFaroUser(publicKey)` / `clearFaroUser()` identity binding — UNTESTED.
- **Known wiring gap (carried from 30-04 SUMMARY deviation):** the shipped
  `apps/web/src/lib/logger.ts` is a plain console wrapper with **no `transports`
  array**, so `registerFaroTransport(logger.transports)` is **never called** from
  `main.tsx`. The transport function exists and is exported, but is currently dead
  code at runtime. SC-1's "errors sent to tracking service" therefore flows only via
  `FaroErrorBoundary` → Faro auto-capture, NOT via the logger error path. This is a
  real coverage/wiring gap, not just a missing test.

---

## Manual-Only Verifications

| Behavior                          | SC   | Why Manual                                  | Test Instructions                                                                                          |
| --------------------------------- | ---- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Source maps not served to browser | SC-2 | Build/CI config; no unit surface            | Confirm `sourcemap: 'hidden'` + `keepSourcemaps: false` in `vite.config.ts`; verify built JS has no `//# sourceMappingURL` |
| Faro env vars in staging deploy   | SC-3 | GitHub Actions config                       | `grep VITE_FARO_URL .github/workflows/deploy-staging.yml` → 4 matches (web + 3 desktop builds)            |
| Core web vitals in dashboard      | SC-3 | Requires staging env + Grafana Cloud        | After staging deploy with `VITE_FARO_URL` set, confirm Grafana Faro shows page-load/TTI/CWV panels        |
| Error boundary catches at runtime | SC-1 | Requires browser render of a thrown error   | Trigger a render error in staging, confirm ErrorFallback renders and a Faro error event is created        |
| Privacy audit (no PII egress)     | SC-4 | End-to-end confirmation against live collector | Capture an error in staging, inspect the Faro payload at the collector and confirm no keys/email present   |

---

## Validation Sign-Off

- [ ] All SCs have automated coverage OR justified manual-only
- [x] Manual-only items justified (config / runtime / dashboard / live-collector)
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [ ] `nyquist_compliant: true` — NOT met (privacy scrubber SC-2/SC-4 untested)

**Approval:** draft — not nyquist-compliant. The privacy-critical `beforeSend`/`scrub*`
logic (SC-2, SC-4) is pure, deterministic, and currently has zero automated tests; it
is the single most important behavior in the phase and must be covered before this
contract can be marked validated.

---

## Validation Audit 2026-06-19

This is a RETROACTIVE documentation pass on a phase that shipped 2026-03-28. No test
suites were executed (static analysis only — multiple auditors run in parallel).
Coverage was established by file/symbol enumeration.

| Metric             | Count |
| ------------------ | ----- |
| Success criteria   | 4     |
| Covered (green)    | 0     |
| Partial            | 0     |
| Missing            | 3 (SC-1, SC-2, SC-4) |
| Manual-only (just.)| 1 (SC-3) |

Audit notes:

- `apps/web` ships **7** vitest files; **none** reference `faro`, `scrubObject`,
  `beforeSend`, `registerFaroTransport`, or `ErrorFallback`. The phase's behavioral
  surface is entirely unverified by automated tests.
- The privacy scrubber in `apps/web/src/lib/faro.ts` (`scrubObject`, `scrubValue`,
  `beforeSend`, `HEX_KEY_PATTERN`, `URL_HEX_KEY_PATTERN`, depth guard) is pure and
  trivially unit-testable. Recommended Wave-0-equivalent test: `src/lib/faro.test.ts`
  asserting sensitive-key redaction, 64-char hex → `[REDACTED_KEY]`, URL-embedded key
  stripping, `Uint8Array` → `[REDACTED_BINARY]`, depth-limit, and the `VITE_FARO_URL`
  absent → `undefined` no-op. File MUST be `.test.ts` (vitest include excludes `.tsx`/`.spec.ts`).
- SC-1 wiring gap: `logger.ts` has no `transports` array, so `registerFaroTransport`
  is never invoked at runtime (per the 30-04 SUMMARY deviation). Error→Faro currently
  flows only through `FaroErrorBoundary`. ESCALATE: confirm whether the logger-transport
  path is intended to be live; if so it is a wiring bug, not merely a missing test.
  **This is the same gap already tracked in `.planning/todos/pending/2026-06-18-web-logger-redaction-and-faro-transport-unwired.md` (todo #16)** — the Nyquist audit independently confirmed it.
- SC-3 (web vitals visible in dashboard) is legitimately manual — it depends on a
  staging deploy with `VITE_FARO_URL` configured and a Grafana Cloud dashboard.
- `30-VERIFICATION.md` marks every must-have PASS, but that verification is grep/build
  based, not behavioral. `nyquist_compliant` is therefore set to `false` honestly:
  no automated test exercises the privacy or transport behavior.
