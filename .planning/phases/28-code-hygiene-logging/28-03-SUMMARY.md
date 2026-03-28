---
plan: 28-03
status: complete
started: 2026-03-28T04:40:00.000Z
completed: 2026-03-28T04:45:00.000Z
---

## Summary

Eliminated all `as any` casts in production web code. The 4 polyfill casts in `polyfills.ts` were replaced with proper `declare global` type augmentations. The debug error log in `main.tsx` now uses a typed `Window` interface extension. The Zustand debug store exposure in `folder.store.ts` uses a typed window property.

## Key Files

### Modified

- `apps/web/src/polyfills.ts` — Replaced `(globalThis as any)` with `declare global` augmentation
- `apps/web/src/main.tsx` — Typed `Window.__errorLog` and `__errorCount` interface
- `apps/web/src/stores/folder.store.ts` — Typed `Window.__ZUSTAND_FOLDER_STORE__` property

## Self-Check: PASSED

- [x] Zero `as any` casts in production web code
- [x] Polyfill shims documented as acceptable exceptions (using proper types now)
