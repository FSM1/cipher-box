---
created: 2026-06-20T00:00:00.000Z
title: IPNS publish should validate embedded sequence even when expectedSequenceNumber (CAS) is omitted
area: security
severity: low
source: CodeRabbit review of PR #529 (apps/api/src/ipns/ipns.service.ts:294); S1 follow-up, deferred — proposed fix risks non-CAS publish paths
files:
  - apps/api/src/ipns/ipns.service.ts
  - apps/api/src/ipns/ipns.service.spec.ts
---

## Problem

The S1 embedded-sequence check (`publishRecord` → `upsertFolderIpns`) only runs when
`expectedSequenceNumber` is provided. When CAS is omitted, ANY embedded sequence is accepted, but a
create still stores DB sequence `'1'` and updates increment by one. So a first publish that embeds a
high sequence (e.g. `999n`) persists a signed record whose embedded sequence is `999n`; a later
legitimate update signs `2n` and fails the anti-rollback check (`incoming 2n < stored 999n`) — the
name can be wedged. This is a niche tamper scenario (the client must deliberately sign a high first
sequence), hence Low severity, but it is an S1 hardening gap.

## Why deferred (not fixed in PR #529)

CodeRabbit's proposed fix uses the DB sequence as the baseline when CAS is omitted and requires
`embedded === existing.sequenceNumber + 1n` on non-first publishes. But several publish paths
intentionally omit `expectedSequenceNumber` (e.g. the desktop `vault.rs` init publishes with
`expected_sequence_number: None`; per-file IPNS publishes; possibly bin/file-pointer paths). Forcing
`embedded === DB+1` on those non-CAS paths risks a NEW regression (the same class of bug that broke
48/89 SDK E2E tests in this phase). The fix must be validated against the full SDK E2E suite and the
desktop per-file/vault publish paths, and must preserve idempotent equal-sequence republishes
(without incrementing the DB sequence).

## Solution

Validate the embedded sequence against the DB baseline even without CAS, BUT:
- Enumerate every publish path that omits `expectedSequenceNumber` and confirm each signs
  `DB_sequence + 1` (or handle the equal-sequence idempotent-republish case explicitly).
- Add SDK E2E coverage for the non-CAS publish paths before tightening.
- Keep the first-publish tolerance (embedded `0n` or `1n`).

## Where it belongs

A future S1/IPNS-hardening pass (candidate: Phase 55 Tier-3 follow-ups), gated on running the full
SDK E2E suite locally — see
`2026-06-20-ipns-resolve-verify-coverage-and-web-sdk-dedup.md` for the related resolve-side work.
