---
created: 2026-06-24
title: Fail fast on root-folder publish conflict during desktop vault init
area: desktop
files:
  - apps/desktop/src-tauri/src/commands/vault.rs
---

## Problem

In the desktop vault-init flow (`apps/desktop/src-tauri/src/commands/vault.rs:182-187`), the root-folder publish `PublishResult::Conflict` arm only `log::warn!`s and falls through to `/vault/init` (step 3), whereas the analogous vault-key conflict arm (~line 139-142) returns `Err` and fails fast. The asymmetry means an unexpected conflict on the first root-folder publish (sequence 1) is silently swallowed and initialization continues on inconsistent state.

Surfaced by CodeRabbit during the Phase 60 ship review (finding F10). Verified real but **pre-existing** (not introduced by Phase 60 — Phase 60 only changed the embedded sequence 0→1 here), so classified out-of-scope for the strict-cutover phase.

## Solution

Mirror the vault-key conflict path: in the root-folder publish `PublishResult::Conflict { .. }` arm, `return Err("Vault initialization aborted due to existing root folder IPNS record")` (or equivalent) so init fails fast instead of proceeding to `/vault/init`.
