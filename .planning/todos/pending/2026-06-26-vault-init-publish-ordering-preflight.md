---
created: 2026-06-26T00:00:00.000Z
title: Vault-init publish-ordering preflight — check both IPNS names before any write
area: desktop
severity: medium
source: PR #566 CodeRabbit review (Major, "Heavy lift") — 2026-06-26
files:
  - apps/desktop/src-tauri/src/commands/vault.rs
resolves_phase: 76
---

## Problem

Desktop vault init (`apps/desktop/src-tauri/src/commands/vault.rs`) publishes the
vault-key blob and the root-folder IPNS record sequentially. PR #566 hardened the
root-folder `PublishResult::Conflict` arm to fail-fast (`Err`) like the vault-key
arm — but that one-liner does not close the deeper issue CodeRabbit flagged
(labelled "Heavy lift"): a conflict on EITHER publish mid-init can leave the vault
in an inconsistent, half-initialized state. If the vault-key publishes successfully
and the root-folder publish then conflicts (or vice versa), init aborts with one
record already written and the other not, and the next attempt may behave
unexpectedly against that partial state.

## Solution

Make init atomic-ish by **preflighting both IPNS names before performing either
write**: resolve/check that both the vault-key IPNS record and the root-folder IPNS
record are absent (or in the expected pristine state) up front, and abort init with
a clear `Err` BEFORE any publish if either already exists. Then either both writes
proceed or none do.

- Add a preflight resolve of both names ahead of the publishes.
- On a detected pre-existing record → abort (no writes attempted).
- On a preflight resolve that **fails transiently** (network error, timeout, any
  non-404 / not-"absent" response) → **fail closed: abort init**, never treat a
  resolve error as "record absent → proceed". A fail-open choice here would risk
  publishing over an existing record and create the exact partial/inconsistent
  state this preflight exists to prevent — so the security-relevant default is to
  abort and surface the transient error for retry.
- Decide and document the cleanup/recovery story for the rare case where a publish
  still fails after a clean preflight (transient), so a partial write is detectable
  and re-runnable rather than silently inconsistent.

This is the deeper follow-up to #566's targeted fail-fast; out of scope for that
safety-tail PR of one-line fixes. Verify against the desktop init E2E /
vault-recovery flow.
