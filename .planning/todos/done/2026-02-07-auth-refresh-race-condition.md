---
created: 2026-02-07T09:10
title: Auth token refresh race condition causes parallel 401s
area: api
files:
  - apps/web/src/lib/api/fetch.ts
---

## Problem

Multiple parallel POST /auth/refresh calls observed (6+ simultaneous) during normal operation. Some succeed [200], then later ones fail [401] because token rotation invalidates the earlier refresh tokens. This causes intermittent auth failures.

The current implementation uses a boolean `isRefreshing` flag which is racy — multiple concurrent 401 responses can each trigger their own refresh before the flag is set.

Pre-existing issue discovered during Phase 7.1 UAT.

## Solution

Replace the boolean `isRefreshing` flag with a shared Promise pattern:

1. When the first 401 triggers a refresh, store the refresh Promise
2. Subsequent 401s await the same Promise instead of starting new refresh calls
3. Once the Promise resolves, all waiting requests retry with the new token
4. Clear the stored Promise after resolution

This deduplicates concurrent refresh attempts into a single network call.
