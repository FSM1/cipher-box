---
created: 2026-06-21
title: Large source-file refactor — remaining Tier-3 candidates (add tests first)
area: refactor
severity: low
source: residue of 2026-06-19-large-file-refactor-candidates.md after Phase 55 / PR #538 shipped all Tier-1 + Tier-2 items
files:
  - packages/sdk/src/client.ts
  - crates/fuse/src/inode.rs
  - crates/fuse/src/platform/windows/write_ops.rs
  - apps/web/src/components/file-browser/SharedFileBrowser.tsx
  - apps/desktop/src/auth.ts
  - apps/web/src/components/file-browser/ShareDialog.tsx
  - apps/web/src/hooks/useAuth.ts
  - apps/desktop/src/main.ts
  - packages/sdk/src/bin/index.ts
  - apps/web/src/components/file-browser/useFileBrowserActions.ts
  - apps/web/src/hooks/useSharedNavigationActions.ts
  - apps/web/src/components/file-browser/BinBrowser.tsx
---

## Problem

Phase 55 (commit `db5691be7`, PR #538) executed the entire Tier-1 + Tier-2 batch of the original
26-file survey (`2026-06-19-large-file-refactor-candidates.md`, now in `completed/`). The **14
Tier-3 candidates were explicitly deferred** as the bigger/riskier bucket — most have NO unit tests
and several touch security-sensitive crypto, so they must add tests BEFORE the split. Verified open
against live code 2026-06-21 (none of the target extracted modules exist; `client.ts` actually grew
to 2768 LoC).

See the original survey (in `completed/`) for the full per-file deep-dive plans, including the
`client.ts` facade-decomposition and the explicit public-surface / folderTree-desync constraints.

## Remaining Tier-3 items

- [ ] `packages/sdk/src/client.ts` (2768) — extract `pinning.ts` + `shared-folder.ts` (conservative
  ~600 LoC), or the full ClientCore facade decomposition. Public API frozen; folderTree single-source-of-truth.
- [ ] `crates/fuse/src/inode.rs` (1561) — `inode/` dir module (extract `populate_folder`, tests, `types.rs`).
- [ ] `crates/fuse/src/platform/windows/write_ops.rs` (1196) — `write_ops/{create,cleanup,rename,attrs}.rs` (winfsp-gated, untested → verify on CI Windows build).
- [ ] `apps/web/.../SharedFileBrowser.tsx` (946) — converge on `useFileBrowserActions` pattern; add hook tests first.
- [ ] `apps/desktop/src/auth.ts` (800) — `auth/{corekit,login,mfa,device,oauth}.ts` barrel; shared module-level mutable state hazard; manual login+MFA verify.
- [ ] `apps/web/.../ShareDialog.tsx` (786) — extract `share/` helpers+hook; security-sensitive (key unwrap, zeroization); flag (not fix) the latent double-wrap ~L313/L317.
- [ ] `apps/web/src/hooks/useAuth.ts` (732) — extract `vault-init.service.ts` + `byo-config.service.ts`; no test net → exercise all 3 login paths + required_share + reload.
- [ ] `apps/desktop/src/main.ts` (662) — move inline-HTML renderers to `ui/`; low risk.
- [ ] `packages/sdk/src/bin/index.ts` (655) — conservative: extract `bin/ipns.ts` plumbing only (7 test files mock `'../bin'`).
- [ ] `apps/web/.../useFileBrowserActions.ts` (630) — extract selection/drag/dialogs hooks; selection logic duplicated in SharedFileBrowser (dedup win).
- [ ] `apps/web/src/hooks/useSharedNavigationActions.ts` (579) — borderline; split only if done.
- [ ] `apps/web/.../BinBrowser.tsx` (539) — extract `useBinSelection`/`binSort`/`BinContextMenu`.

## Approach

Per the survey's sequencing: add the missing unit tests first (especially the security-sensitive web
crypto paths — ShareDialog, useAuth vault-init), then split. Each item is independently shippable on
its own `refactor/` branch; no `pnpm api:generate` needed (no apps/api HTTP/DTO changes). Public
surface stays byte-identical (SDK exports, crate re-exports, component/hook signatures).
