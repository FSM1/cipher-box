# Playwright MCP: Login and File Upload in Debug Sessions

**Date:** 2026-03-20

## Original Prompt

> Debug delete-to-bin functionality using Playwright MCP headed session.

## What I Learned

### Login: OTP must be read from the running dev server output

- The `.env` OTP (`851527`) is a Web3Auth static test OTP — it does **not** work with the local API's OTP system
- The local API generates random 6-digit OTPs and logs them as `DEV OTP for <email>: <code>` in the console (`apps/api/src/auth/services/email-otp.service.ts:103`)
- When `pnpm dev` is backgrounded by Claude Code, the output goes to a task file — grep it for `DEV OTP` after the UI sends the OTP
- **Important:** The UI's send-otp call generates a new OTP, invalidating any previously sent via curl. Always read the latest OTP from the log after the UI triggers it
- **Login flow in Playwright MCP:**
  1. Fill email into `data-testid="email-input"`, click `data-testid="send-otp-button"`
  2. Grep the backgrounded task output for `DEV OTP for <email>:` to get the code
  3. Fill OTP into `data-testid="otp-input"`, click `data-testid="verify-button"`
  4. Wait for navigation to `#/files`
- Rate limit: 5 sends per 15 min in Redis (survives API restarts). Clear via ioredis from `apps/api/`: `node -e "const R=require('ioredis');new R({host:'<REDIS_HOST>',port:<REDIS_PORT>}).del('otp-attempts:<email>').then(()=>process.exit())"`
- Use fresh emails (`test-$(date +%s)@example.com`) to avoid `auth_methods` unique constraint violations on existing accounts

### File upload: use setInputFiles on the hidden input

- Reference `tests/web-e2e/page-objects/file-browser/upload-zone.page.ts` for the pattern
- Use `setInputFiles()` on the hidden input (`.upload-zone input[type="file"]`) — don't use the file chooser modal, it's unreliable with Playwright MCP
- For Playwright MCP specifically, `browser_evaluate` with `document.querySelector('input[type="file"]').click()` + `browser_file_upload` also works but `setInputFiles` is simpler

## Key Files

- `tests/web-e2e/page-objects/file-browser/upload-zone.page.ts` — reliable file upload via `setInputFiles()`
- `apps/api/src/auth/services/email-otp.service.ts` — OTP generation, rate limits, Redis keys
- `apps/api/.env` — `REDIS_HOST`, `REDIS_PORT` for rate limit clearing
