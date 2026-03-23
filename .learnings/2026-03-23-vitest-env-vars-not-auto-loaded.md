# Vitest Does Not Auto-Load .env Into process.env

**Date:** 2026-03-23

## Original Prompt

> Run SDK E2E tests against someguy

## What I Learned

- **Vitest does not load `.env` files into `process.env` by default.** Unlike tools like Jest with `dotenv`, or the NestJS CLI which loads `.env` automatically, vitest uses Vite's env handling which only exposes `VITE_`-prefixed vars to the client. Server-side `process.env` reads in test code will only see vars inherited from the shell.
- Creating a `.env` file in `tests/sdk-e2e/` had **no effect** on `process.env.THROTTLE_BYPASS_SECRET` inside the test harness. The tests continued hitting 429s because the bypass header was empty.
- The fix is to pass env vars explicitly when invoking the test command:

  ```bash
  THROTTLE_BYPASS_SECRET=local-dev-throttle-bypass pnpm --filter sdk-e2e test
  ```

- Alternative: add `dotenv/config` to the vitest setup file, or configure `envDir` + `envPrefix: ''` in `vitest.config.ts`.
- This caused 14 spurious 429 failures that looked like the someguy IPNS fix wasn't working, when in reality the throttle bypass secret just wasn't reaching the test process.

## What Would Have Helped

- Checking the test harness's `process.env.THROTTLE_BYPASS_SECRET` value with a quick `console.log` would have immediately revealed the env var wasn't loaded.
- The `.env.example` in `tests/sdk-e2e/` implied a `.env` file should work, but vitest doesn't honour it without explicit config.

## Key Files

- `tests/sdk-e2e/vitest.config.ts` — no dotenv/envDir config
- `tests/sdk-e2e/src/fixtures/test-harness.ts:17` — reads `THROTTLE_BYPASS_SECRET` from `process.env`
- `apps/api/src/common/guards/throttler-bypass.guard.ts` — the bypass guard that expects the header
