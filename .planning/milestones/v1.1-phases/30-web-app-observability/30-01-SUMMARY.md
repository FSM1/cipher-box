---
phase: 30-web-app-observability
plan: 01
subsystem: infra
tags: [grafana, faro, observability, privacy, telemetry]

requires: []
provides:
  - Faro SDK initialization module with privacy scrubbing
  - beforeSend hook stripping all sensitive CipherBox fields
  - getFaroInstance/setFaroUser/clearFaroUser/registerFaroTransport exports
affects: [web-app-logging, error-tracking, staging-deployment]

tech-stack:
  added: ['@grafana/faro-web-sdk', '@grafana/faro-react']
  patterns: ['beforeSend privacy gate', 'env-conditional SDK init']

key-files:
  created:
    - apps/web/src/lib/faro.ts
  modified:
    - apps/web/src/main.tsx
    - apps/web/src/vite-env.d.ts
    - apps/web/package.json

key-decisions:
  - 'captureConsole: false — Phase 28 logger handles console capture'
  - 'sessionTracking persistent: false — no cross-tab session persistence for privacy'
  - 'HEX_KEY_PATTERN at 64+ chars (32+ bytes) to catch all CipherBox key formats'

patterns-established:
  - 'Privacy gate pattern: beforeSend hook scrubs all outbound telemetry'
  - 'Env-conditional init: VITE_FARO_URL absent = completely disabled'

requirements-completed: []

duration: 5min
completed: 2026-03-28
---

# Plan 30-01: Grafana Faro SDK Initialization Summary

**Faro SDK with beforeSend privacy gate stripping keys, tokens, emails, and hex-encoded secrets from all telemetry**

## Performance

- **Duration:** 5 min
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments

- Installed @grafana/faro-web-sdk and @grafana/faro-react
- Created faro.ts with strict beforeSend privacy scrubbing (SENSITIVE_KEYS set + HEX_KEY_PATTERN regex + Uint8Array detection)
- Wired initFaro() into main.tsx before React render tree
- Added VITE_FARO_URL and VITE_APP_VERSION type declarations

## Task Commits

1. **Tasks 1-3: SDK install, faro module, main.tsx wiring** - `1cf0c26df`

## Files Created/Modified

- `apps/web/src/lib/faro.ts` - Faro initialization with privacy scrubbing, user identity, and logger transport
- `apps/web/src/main.tsx` - initFaro() call before React render
- `apps/web/src/vite-env.d.ts` - VITE_FARO_URL and VITE_APP_VERSION type declarations
- `apps/web/package.json` - Added @grafana/faro-web-sdk and @grafana/faro-react

## Decisions Made

- Combined registerFaroTransport and clearFaroUser into the same faro.ts module (plan 30-04 additions) to keep all Faro logic co-located
- Used LogLevel.WARN from faro-core instead of string cast for type safety in logger transport

## Deviations from Plan

None - plan executed as specified.

## Issues Encountered

None.

## Next Phase Readiness

- Faro module ready for error boundary (30-02) and logger transport (30-04) integration

---

_Phase: 30-web-app-observability_
_Completed: 2026-03-28_
