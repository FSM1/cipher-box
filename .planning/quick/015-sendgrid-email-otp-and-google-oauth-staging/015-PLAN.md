---
phase: quick
plan: 015
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/api/src/auth/services/email-otp.service.ts
  - apps/api/src/auth/services/email-otp.service.spec.ts
  - apps/api/package.json
  - apps/api/.env.example
  - apps/web/.env.example
  - .github/workflows/deploy-staging.yml
  - pnpm-lock.yaml
autonomous: false
user_setup:
  - service: sendgrid
    why: 'Email OTP delivery'
    env_vars:
      - name: SENDGRID_API_KEY
        source: 'SendGrid Dashboard -> Settings -> API Keys -> Create API Key (Restricted Access, Mail Send only)'
      - name: SENDGRID_FROM_EMAIL
        source: 'Must be a verified sender in SendGrid (Settings -> Sender Authentication). Use noreply@cipherbox.cc or similar.'
    dashboard_config:
      - task: 'Verify sender identity'
        location: 'SendGrid Dashboard -> Settings -> Sender Authentication -> Single Sender Verification (or Domain Authentication for cipherbox.cc)'
  - service: google-oauth
    why: 'Google social login'
    env_vars:
      - name: GOOGLE_CLIENT_ID
        source: 'Google Cloud Console -> APIs & Credentials -> OAuth 2.0 Client IDs'
    dashboard_config:
      - task: 'Create OAuth 2.0 Client ID (Web application type)'
        location: 'Google Cloud Console -> APIs & Credentials -> Create Credentials -> OAuth client ID'
      - task: 'Add authorized JavaScript origins: https://app-staging.cipherbox.cc'
        location: 'OAuth client configuration -> Authorized JavaScript origins'
      - task: 'Add authorized redirect URI: https://app-staging.cipherbox.cc'
        location: 'OAuth client configuration -> Authorized redirect URIs'
must_haves:
  truths:
    - 'Email OTP sends a real email via SendGrid on staging/production'
    - 'Email OTP still logs to console in dev mode when SendGrid is not configured'
    - 'Google OAuth login works on staging with GOOGLE_CLIENT_ID configured'
    - 'Staging deploy pipeline passes SendGrid and Google env vars to API and web'
  artifacts:
    - path: 'apps/api/src/auth/services/email-otp.service.ts'
      provides: 'SendGrid email delivery after OTP generation'
      contains: 'sendgrid'
    - path: 'apps/api/src/auth/services/email-otp.service.spec.ts'
      provides: 'Tests for SendGrid integration path and dev fallback'
      contains: 'SendGrid'
    - path: '.github/workflows/deploy-staging.yml'
      provides: 'SENDGRID_API_KEY, SENDGRID_FROM_EMAIL, GOOGLE_CLIENT_ID, VITE_GOOGLE_CLIENT_ID in staging deploy'
      contains: 'SENDGRID_API_KEY'
  key_links:
    - from: 'apps/api/src/auth/services/email-otp.service.ts'
      to: '@sendgrid/mail'
      via: 'sgMail.send() after Redis OTP storage'
      pattern: "sgMail\\.send"
    - from: '.github/workflows/deploy-staging.yml'
      to: 'GitHub staging environment secrets/vars'
      via: 'env var injection into .env.staging and build step'
      pattern: 'SENDGRID_API_KEY|GOOGLE_CLIENT_ID'
---

<objective>
Integrate SendGrid for email OTP delivery and wire Google OAuth env vars through the staging deploy pipeline so Phase 12 Core Kit identity provider works end-to-end on staging.

Purpose: Phase 12 built the auth flows but email OTP silently drops codes in staging/production (never sends email), and Google OAuth button shows "[NOT CONFIGURED]" because env vars are missing from the deploy pipeline.

Output: Working email delivery for OTP codes, fully configured staging pipeline for both auth methods.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/api/src/auth/services/email-otp.service.ts
@apps/api/src/auth/services/email-otp.service.spec.ts
@apps/api/.env.example
@apps/web/.env.example
@.github/workflows/deploy-staging.yml
</context>

<tasks>

<task type="auto">
  <name>Task 1: Integrate SendGrid into EmailOtpService</name>
  <files>
    apps/api/src/auth/services/email-otp.service.ts
    apps/api/src/auth/services/email-otp.service.spec.ts
    apps/api/package.json
    apps/api/.env.example
    pnpm-lock.yaml
  </files>
  <action>

**Step 1 -- Install SendGrid package.** Install `@sendgrid/mail` as a runtime dependency (NOT devDependency) in the API package: `pnpm --filter @cipherbox/api add @sendgrid/mail`. Commit the lockfile change with the package.json change (CI uses --frozen-lockfile).

**Step 2 -- Modify email-otp.service.ts.** Import `@sendgrid/mail` at the top. Use `import sgMail from '@sendgrid/mail'` or `import * as sgMail from '@sendgrid/mail'` -- check which works (NestJS uses CommonJS so esModuleInterop default import should work; if not, use the star import). In the constructor, read `SENDGRID_API_KEY` and `SENDGRID_FROM_EMAIL` from ConfigService and store as private readonly fields. If `SENDGRID_API_KEY` is set, call `sgMail.setApiKey(apiKey)` and log that SendGrid email delivery is enabled. Store a boolean `sendgridConfigured` flag.

In `sendOtp()`, AFTER the existing Redis storage and rate limit logic (after line 75), add email sending. If `sendgridConfigured` is true, send OTP email via `sgMail.send()` with: `to` = normalizedEmail, `from` = configured SENDGRID_FROM_EMAIL (default fallback: `noreply@cipherbox.cc`), `subject` = "Your CipherBox verification code", `text` = plain text body: "Your CipherBox verification code is: {otp}\n\nThis code expires in 5 minutes. If you did not request this code, please ignore this email.", `html` = minimal HTML version with the code in a styled `<strong>` block for readability.

Wrap the sgMail.send() call in try/catch. On failure, log the error with `this.logger.error()` but do NOT throw -- the OTP is already stored in Redis, so the user can retry sending. This prevents SendGrid outages from breaking the auth flow. Keep the existing dev-mode console log (lines 77-80) as-is. The logic becomes: always store in Redis, then if SendGrid configured send email, if dev mode also log to console. Both can fire.

**Step 3 -- Update .env.example.** Add after the Google OAuth section in `apps/api/.env.example`: `SENDGRID_API_KEY` (commented, with `SG.xxxxx` placeholder) and `SENDGRID_FROM_EMAIL` (commented, with `noreply@cipherbox.cc` placeholder). Add a comment header "SendGrid (email OTP delivery)" and note "Required in production/staging for email OTP login".

**Step 4 -- Update unit tests.** In `apps/api/src/auth/services/email-otp.service.spec.ts`, mock `@sendgrid/mail` module at the top alongside the ioredis mock:

```typescript
const mockSgSend = jest.fn().mockResolvedValue([{ statusCode: 202 }]);
jest.mock('@sendgrid/mail', () => ({
  setApiKey: jest.fn(),
  send: mockSgSend,
}));
```

Add three new tests: (a) "should send email via SendGrid when configured" -- set up configService.get to return a SENDGRID_API_KEY value and SENDGRID_FROM_EMAIL, create a new service instance, call sendOtp(), assert mockSgSend was called with expected to/from/subject/text fields. (b) "should not send email when SendGrid is not configured" -- verify the default service (no SENDGRID_API_KEY) does NOT call sgMail.send. (c) "should not throw when SendGrid send fails" -- configure SendGrid, make mockSgSend.mockRejectedValueOnce(new Error('SendGrid error')), call sendOtp() and assert it resolves without throwing; OTP should still be stored in Redis. Existing tests should continue passing since they use the default configService returning undefined.

**Step 5 -- Run tests.** Execute `pnpm --filter @cipherbox/api test -- --testPathPattern=email-otp` to verify all tests pass.

  </action>
  <verify>
    - `pnpm --filter @cipherbox/api test -- --testPathPattern=email-otp` passes with all existing + new tests green
    - `@sendgrid/mail` appears in `apps/api/package.json` under `dependencies` (NOT devDependencies)
    - `pnpm --filter @cipherbox/api build` succeeds (TypeScript compiles)
  </verify>
  <done>
    - EmailOtpService sends real emails via SendGrid when SENDGRID_API_KEY is set
    - EmailOtpService falls back to console logging in dev mode
    - SendGrid failure does not break OTP flow (graceful degradation)
    - All unit tests pass including 3 new SendGrid-specific tests
  </done>
</task>

<task type="auto">
  <name>Task 2: Wire Google OAuth and SendGrid env vars through staging pipeline</name>
  <files>
    .github/workflows/deploy-staging.yml
    apps/web/.env.example
  </files>
  <action>

**Step 1 -- Add VITE_GOOGLE_CLIENT_ID to web build.** In `.github/workflows/deploy-staging.yml`, in the `build-web` job (line ~101-106), add `VITE_GOOGLE_CLIENT_ID: ${{ vars.GOOGLE_CLIENT_ID }}` to the env block alongside the existing VITE*WEB3AUTH_CLIENT_ID, VITE_API_URL, and VITE_ENVIRONMENT vars. Use `vars` (not `secrets`) for GOOGLE_CLIENT_ID since it is a public client ID embedded in frontend JS -- not a secret. The VITE* prefix is required for Vite to expose it to the client bundle.

**Step 2 -- Add SendGrid and Google vars to .env.staging generation.** In the `deploy-vps` job, in the "Generate .env.staging" step (line ~134-160), add three lines before the `ENVEOF` closing: `SENDGRID_API_KEY=${{ secrets.SENDGRID_API_KEY }}`, `SENDGRID_FROM_EMAIL=${{ vars.SENDGRID_FROM_EMAIL }}`, and `GOOGLE_CLIENT_ID=${{ vars.GOOGLE_CLIENT_ID }}`. SENDGRID_API_KEY is a secret (it can send email). SENDGRID_FROM_EMAIL is a var (not sensitive, just an email address). GOOGLE_CLIENT_ID is a var (public client ID, same value used in frontend).

**Step 3 -- Update web .env.example.** Add to `apps/web/.env.example`: a comment header "Google OAuth (social login)" and commented-out `VITE_GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com`.

**Step 4 -- Verify build.** No API DTO changes were made, so `pnpm api:generate` is NOT needed. Run `pnpm --filter @cipherbox/api build && pnpm --filter @cipherbox/web build` to confirm everything compiles.

  </action>
  <verify>
    - `.github/workflows/deploy-staging.yml` contains `VITE_GOOGLE_CLIENT_ID`, `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL`, and `GOOGLE_CLIENT_ID`
    - `apps/web/.env.example` documents `VITE_GOOGLE_CLIENT_ID`
    - `apps/api/.env.example` documents `SENDGRID_API_KEY`, `SENDGRID_FROM_EMAIL`, and `GOOGLE_CLIENT_ID`
    - Full build succeeds: `pnpm --filter @cipherbox/api build && pnpm --filter @cipherbox/web build`
  </verify>
  <done>
    - Staging deploy pipeline injects all 4 new env vars (SENDGRID_API_KEY, SENDGRID_FROM_EMAIL, GOOGLE_CLIENT_ID to API; VITE_GOOGLE_CLIENT_ID to web build)
    - Both .env.example files document all required vars for local and staging setup
    - Build passes with no TypeScript or config errors
  </done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <what-built>
    SendGrid email integration in EmailOtpService and staging pipeline env var wiring for both SendGrid and Google OAuth.
  </what-built>
  <how-to-verify>
    1. Review the code diff to confirm changes look correct
    2. Verify tests pass: `pnpm --filter @cipherbox/api test -- --testPathPattern=email-otp`
    3. For SendGrid: After configuring GitHub staging environment with SENDGRID_API_KEY secret, SENDGRID_FROM_EMAIL var, and GOOGLE_CLIENT_ID var, the next staging deploy will pick them up
    4. For local testing: Set SENDGRID_API_KEY and SENDGRID_FROM_EMAIL in apps/api/.env, start the API, and trigger an email OTP -- you should receive the email
    5. Confirm the Google OAuth client ID is set up in Google Cloud Console with the correct authorized origins for staging
  </how-to-verify>
  <resume-signal>Type "approved" or describe issues</resume-signal>
</task>

</tasks>

<verification>

- `pnpm --filter @cipherbox/api test -- --testPathPattern=email-otp` -- all tests pass (existing + 3 new)
- `pnpm --filter @cipherbox/api build` -- TypeScript compiles successfully
- `pnpm --filter @cipherbox/web build` -- no build errors
- `@sendgrid/mail` in dependencies (not devDependencies) of apps/api/package.json
- `.github/workflows/deploy-staging.yml` contains all 4 env var references
- Both .env.example files document the new vars

</verification>

<success_criteria>

- EmailOtpService sends real email via SendGrid when API key is configured
- EmailOtpService gracefully falls back (console log) when SendGrid is unavailable
- SendGrid send failure does not break OTP generation/storage
- Staging deploy pipeline passes SENDGRID_API_KEY, SENDGRID_FROM_EMAIL, GOOGLE_CLIENT_ID to API
- Staging deploy pipeline passes VITE_GOOGLE_CLIENT_ID to web build
- All unit tests pass
- Build succeeds across the monorepo

</success_criteria>

<output>
After completion, create `.planning/quick/015-sendgrid-email-otp-and-google-oauth-staging/015-SUMMARY.md`
</output>
