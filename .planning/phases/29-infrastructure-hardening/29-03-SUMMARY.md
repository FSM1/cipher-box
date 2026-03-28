---
phase: 29-infrastructure-hardening
plan: 03
subsystem: infra
tags: [grafana, alerts, security, kubo, staging]

requires:
  - phase: 26-observability-ux-tuning
    provides: Grafana alert provisioning pattern and scripts
provides:
  - Grafana alert rule for test login rate monitoring (>100/hr)
  - Verification that test login production guard is in place
  - Verification that Kubo port 5001 is bound to 127.0.0.1 in staging
affects: [monitoring, staging-security]

tech-stack:
  added: []
  patterns: [security-alert-rule]

key-files:
  created:
    - docker/grafana/alerts/test-login-rate.json
  modified: []

key-decisions:
  - 'Threshold set at 100/hr with 5min for duration to avoid false positives from E2E test runs'
  - 'Verification-only for production guard and Kubo binding -- both already correctly configured'

patterns-established:
  - 'Security alert rules use CipherBox Security rule group (separate from Performance)'

requirements-completed: []

duration: 3min
completed: 2026-03-28
---

# Plan 29-03: Test Login Monitoring Alert + Kubo Access Verification Summary

**Grafana alert for test-login rate monitoring on staging, with verified production guard and Kubo port binding**

## Performance

- **Duration:** 3 min
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- Created Grafana alert rule (test-login-rate.json) that fires when test login exceeds 100 calls/hour
- Verified test-auth.service.ts has NODE_ENV=production guard with ForbiddenException (line 44)
- Verified timingSafeEqual comparison for TEST_LOGIN_SECRET (line 55)
- Verified unit tests cover production guard (test-auth.service.spec.ts line 80)
- Verified docker-compose.staging.yml binds Kubo to 127.0.0.1:5001 (not externally exposed)

## Task Commits

1. **Task 1: Create Grafana alert + Task 2: Verify guards** - `cc9f90e95` (feat)

## Files Created/Modified

- `docker/grafana/alerts/test-login-rate.json` - Test login rate alert rule

## Decisions Made

None - followed plan as specified

## Deviations from Plan

None - plan executed exactly as written

## Issues Encountered

None

## Next Phase Readiness

- Alert ready for provisioning via existing provision-alerts.sh script
- All security guards verified and documented

---

_Phase: 29-infrastructure-hardening_
_Completed: 2026-03-28_
