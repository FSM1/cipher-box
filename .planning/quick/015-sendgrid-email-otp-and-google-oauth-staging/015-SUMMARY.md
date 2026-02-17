---
phase: quick
plan: 015
subsystem: auth, infra
tags: [sendgrid, email-otp, google-oauth, staging, ci-cd, env-vars]

requires:
  - phase: 12 (Core Kit Identity Provider)
    provides: EmailOtpService, Google OAuth login flow, staging deploy pipeline
provides:
  - SendGrid email delivery for OTP codes in staging/production
  - Staging pipeline env vars for SendGrid and Google OAuth
  - Graceful fallback when SendGrid is unconfigured
affects: [phase-12.1, staging-deploys]

tech-stack:
  added: ['@sendgrid/mail ^8.1.6']
  patterns: ['Graceful degradation: catch SendGrid errors without breaking OTP flow']

key-files:
  created: []
  modified:
    - apps/api/src/auth/services/email-otp.service.ts
    - apps/api/src/auth/services/email-otp.service.spec.ts
    - apps/api/package.json
    - apps/api/.env.example
    - apps/web/.env.example
    - .github/workflows/deploy-staging.yml
    - pnpm-lock.yaml

key-decisions:
  - 'SendGrid failure is non-fatal: OTP stored in Redis regardless, user can retry'
  - 'SENDGRID_API_KEY as secret, SENDGRID_FROM_EMAIL and GOOGLE_CLIENT_ID as vars (not sensitive)'
  - 'Dev-mode console logging kept alongside SendGrid -- both can fire'

patterns-established:
  - 'External email service integration with graceful degradation'
  - 'Secret vs var classification for GitHub staging environment'

duration: 6min
completed: 2026-02-13
---

# Quick Task 015: SendGrid Email OTP and Google OAuth Staging Summary

SendGrid email delivery for OTP codes with graceful degradation, plus staging pipeline wiring for SendGrid and Google OAuth env vars.

## Performance

- **Duration:** 6 min
- **Started:** 2026-02-13T15:37:09Z
- **Completed:** 2026-02-13T15:42:59Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- EmailOtpService now sends real OTP emails via SendGrid when SENDGRID_API_KEY is configured
- SendGrid failure is non-fatal -- OTP is stored in Redis regardless, graceful degradation
- Staging deploy pipeline passes SENDGRID_API_KEY, SENDGRID_FROM_EMAIL, GOOGLE_CLIENT_ID to API and VITE_GOOGLE_CLIENT_ID to web build
- 3 new unit tests covering SendGrid send, skip, and failure paths (14 total, all passing)

## Task Commits

Each task was committed atomically:

1. **Task 1: Integrate SendGrid into EmailOtpService** - `40df28c76` (feat)
2. **Task 2: Wire Google OAuth and SendGrid env vars through staging pipeline** - `2589aa0ec` (ci)

**Plan metadata:** (below)

## Files Created/Modified

- `apps/api/src/auth/services/email-otp.service.ts` - Added SendGrid import, constructor config, email sending in sendOtp()
- `apps/api/src/auth/services/email-otp.service.spec.ts` - Added @sendgrid/mail mock and 3 new tests
- `apps/api/package.json` - Added @sendgrid/mail to dependencies
- `apps/api/.env.example` - Documented SENDGRID_API_KEY, SENDGRID_FROM_EMAIL
- `apps/web/.env.example` - Documented VITE_GOOGLE_CLIENT_ID
- `.github/workflows/deploy-staging.yml` - Added 4 env vars (web build + .env.staging)
- `pnpm-lock.yaml` - Updated with @sendgrid/mail dependency tree

## Decisions Made

- **SendGrid failure is non-fatal:** sgMail.send() wrapped in try/catch -- OTP is already stored in Redis before email send, so SendGrid outages do not break the auth flow
- **Secret vs var classification:** SENDGRID_API_KEY is a secret (can send email); SENDGRID_FROM_EMAIL and GOOGLE_CLIENT_ID are vars (not sensitive, public values)
- **Dev console logging preserved:** Both SendGrid send and dev-mode console log can fire independently

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed mock leakage between test blocks**

- **Found during:** Task 1 (Step 5 - running tests)
- **Issue:** New SendGrid tests used `mockResolvedValue` (persistent) instead of `mockResolvedValueOnce`, causing mock state to leak into verifyOtp test block since `jest.clearAllMocks()` does not reset implementations
- **Fix:** Changed all new test mocks to use `mockResolvedValueOnce`
- **Files modified:** apps/api/src/auth/services/email-otp.service.spec.ts
- **Verification:** All 14 tests pass with no leakage
- **Committed in:** 40df28c76 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Standard test fix, no scope creep.

## Issues Encountered

- Jest mock hoisting: `jest.mock` factory cannot reference `const` variables declared after it due to hoisting. Resolved by using `require('@sendgrid/mail').default` after the mock declaration to get a reference to the mock object.

## User Setup Required

Before the next staging deploy, configure the following in the GitHub `staging` environment:

**Secrets:**

- `SENDGRID_API_KEY` - Create at SendGrid Dashboard > Settings > API Keys (Restricted Access, Mail Send only)

**Variables:**

- `SENDGRID_FROM_EMAIL` - Must be a verified sender in SendGrid (e.g., `noreply@cipherbox.cc`)
- `GOOGLE_CLIENT_ID` - From Google Cloud Console > APIs & Credentials > OAuth 2.0 Client IDs

**Google Cloud Console setup:**

- Create OAuth 2.0 Client ID (Web application type)
- Add authorized JavaScript origin: `https://app-staging.cipherbox.cc`
- Add authorized redirect URI: `https://app-staging.cipherbox.cc`

## Next Phase Readiness

- Email OTP delivery is ready for staging once SENDGRID_API_KEY is configured
- Google OAuth button will activate on staging once GOOGLE_CLIENT_ID is set
- No blockers for Phase 12.1 (AES-CTR Streaming)

---

_Quick Task: 015_
_Completed: 2026-02-13_
