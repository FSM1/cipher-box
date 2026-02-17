---
created: 2026-02-17T22:10
title: Remove CoreKit logging in web app
area: ui
files:
  - apps/web/src/lib/web3auth/hooks.ts
---

## Problem

The web app has verbose CoreKit debug logging (loginWithJWT timing, commitChanges, exportTssKey, syncStatus, keypair derivation) that ships to production console. These were useful during Phase 12 development but should be removed or gated behind a debug flag before release.

Visible in staging console as `[CoreKit] loginWithJWT starting...`, `[CoreKit] commitChanges: 1060ms`, `[CoreKit] exportTssKey done, hex length: 64`, etc.

## Solution

Remove or wrap `console.log`/`console.time`/`console.timeEnd` calls prefixed with `[CoreKit]` in the web3auth hooks. Could gate behind `import.meta.env.DEV` if some are still useful for local debugging.
