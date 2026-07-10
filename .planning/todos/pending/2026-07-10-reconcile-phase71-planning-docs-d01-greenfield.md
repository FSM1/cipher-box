---
created: 2026-07-10
title: Reconcile Phase 71 planning docs — stale D-01 (vault vs ipns_records) and greenfield migration note
area: docs
files:
  - .planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-CONTEXT.md
  - .planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-PATTERNS.md
  - .planning/phases/71-share-invite-security-and-ipns-data-integrity-api/71-VERIFICATION.md
  - .planning/STATE.md
---

## Problem

CodeRabbit flagged stale language in Phase 71 planning artifacts (docs only — the SHIPPED
CODE is correct and verified/secured/validated):

- `71-CONTEXT.md` (~42-48, 216-220) and `71-PATTERNS.md` (~65-96) still describe the D-01
  root-ownership gate as a Vault-backed check keyed on `rootIpnsName`, but the amended and
  shipped design uses the `ipns_records` creator-marker lookup keyed on `shareRootIpnsName`
  (see the `amend D-01 root-ownership source to ipns_records` commit and both service gates).
  CodeRabbit's suggestion to change the CODE back to vaults is WRONG — the docs lag the code.
- `71-VERIFICATION.md` (~28-32): make the greenfield assumption explicit — the D-04
  `claim_count` CHECK was folded INLINE into `1750000000000-ApiSchemaCutover.ts` rather than a
  new forward migration. This is valid only because milestone v2.0 (metadata-and-sharing-refactor)
  is a greenfield cutover that has not shipped to any existing DB. Document that the inline edit
  is not valid for already-migrated databases.
- `.planning/STATE.md`: reconcile the stale Phase 71 execution fields left in a secondary
  metadata block against the current post-completion state.

## Solution

Update the planning docs to mark the vault-based D-01 guidance as SUPERSEDED by the
`ipns_records` creator-marker design (keep the evolution history, don't silently rewrite), add
the explicit greenfield note to VERIFICATION.md, and normalize STATE.md. Docs-only bookkeeping;
no code change (the code is already correct).
