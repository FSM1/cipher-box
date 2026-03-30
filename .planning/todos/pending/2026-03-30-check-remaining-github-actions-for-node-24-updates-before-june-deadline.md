---
created: 2026-03-30T01:30:00.000Z
title: Check remaining GitHub Actions for Node 24 updates before June deadline
area: ci
files:
  - .github/workflows/deploy-staging.yml
  - .github/workflows/release-please.yml
  - .github/workflows/desktop-e2e.yml
---

## Problem

GitHub forces Node.js 24 for all actions starting 2026-06-02. PR #402 updated 11 actions but these remain on older versions without Node 24 support:

- `googleapis/release-please-action@v4` — currently at v4.4.0
- `tauri-apps/tauri-action@v0` — currently at action-v0.6.2
- `ikalnytskyi/action-setup-postgres@v8` — currently at v8
- `appleboy/scp-action@v0.1.7`
- `appleboy/ssh-action@v1.2.0`

These may publish Node 24-compatible releases before the deadline.

## Solution

Before 2026-06-01, check each action for new releases:

```bash
for action in googleapis/release-please-action tauri-apps/tauri-action ikalnytskyi/action-setup-postgres appleboy/scp-action appleboy/ssh-action; do
  gh api "repos/${action}/releases/latest" --jq '.tag_name'
done
```

Update any that have new major versions. If any haven't released Node 24 support by then, set `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` in the workflow env as a workaround and monitor for breakage.
