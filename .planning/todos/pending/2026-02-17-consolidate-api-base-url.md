---
created: 2026-02-17T22:30
title: Consolidate API base URL definition
area: ui
files:
  - apps/web/src/lib/api/client.ts:14
  - apps/web/src/lib/api/ipfs.ts:4
  - apps/web/src/api/custom-instance.ts:5
---

## Problem

The API base URL (`import.meta.env.VITE_API_URL || 'http://localhost:3000'`) is defined independently in three separate files. If the fallback or env var name ever changes, all three need updating. Risk of divergence.

## Solution

Create a single `getApiBaseUrl()` utility (e.g., in `apps/web/src/lib/api/base-url.ts`) and import it in all three files. Low effort, eliminates a class of copy-paste bugs.
