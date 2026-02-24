---
created: 2026-02-24T23:30
title: Make search index build async/incremental for large vaults
area: ui
files:
  - apps/web/src/services/search-index.service.ts:110-163
  - apps/web/src/hooks/useSearch.ts:79-128
---

## Problem

`buildFromFolderTree()` in SearchIndexService is synchronous and rebuilds the entire MiniSearch index on every palette open. It iterates all folders + children, deduplicates, then calls `miniSearch.addAll()` (tokenization + inverted index construction). For the current tech demonstrator scope (500MB quota, hundreds of files) this is sub-50ms, but for large vaults with thousands of files it could block the main thread and cause UI jank.

The method was made to run on every palette open (not just first open) as part of the fix for stale index data — see commit `63893f15c`.

## Solution

Three options, in order of increasing benefit:

1. **Yield to event loop** — chunk `miniSearch.addAll()` into batches of ~500 docs with `setTimeout(0)` between batches. Simplest change, keeps everything on main thread.

2. **Web Worker** — offload entire index build to a dedicated worker. MiniSearch is serializable via `toJSON()`/`loadJSON()`. Transfer the folder tree in, get the serialized index back. Best for very large vaults.

3. **Incremental updates** — instead of full rebuild on each palette open, subscribe to folder store changes and call `miniSearch.add()`/`miniSearch.remove()` for individual document changes. Most efficient long-term; eliminates redundant work entirely. Requires tracking what changed in the folder store between index builds.

Option 3 is the ideal long-term solution. Option 1 is a quick win if large vaults become a real issue before option 3 is built.
