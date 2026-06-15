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

## Resolution (2026-06-16)

Audited all 16 external actions across `.github/workflows/`. **No changes required** — every action is either node24-native or a composite/Docker action unaffected by the runtime migration. CI on `main` is green post-deadline, confirming empirically.

The 5 originally-flagged actions:

- `tauri-apps/tauri-action@v0` — floating `v0` tracks `action-v0.6.2`, `runs.using: node24` (native)
- `ikalnytskyi/action-setup-postgres@v8` — `runs.using: composite`, unaffected
- `googleapis/release-please-action` — already bumped to `@v5` (node24-native)
- `appleboy/scp-action` — already bumped to `@v1.0.0` (composite, unaffected)
- `appleboy/ssh-action` — already bumped to `@v1.2.5` (composite, unaffected)

No `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` workaround needed — nothing is pinned to node20/node16.
