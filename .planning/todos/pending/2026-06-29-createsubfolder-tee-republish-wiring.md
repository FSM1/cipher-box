---
created: 2026-06-29
title: createSubfolder accepts teeKeys but does not wire encryptedIpnsPrivateKey/keyEpoch — fail closed or wire TEE republish
area: sdk-core
resolves_phase: 67
files:
  - packages/sdk-core/src/folder/registration.ts
---

## Problem

Flagged Major (Security & Privacy) by the Phase-63 PR CodeRabbit review (`registration.ts:42-101`, an outside-diff body comment).

`createSubfolder` accepts `teeKeys` (the TEE-encrypted IPNS private key + key epoch used so the TEE worker can republish the subfolder's IPNS record), but the publish path does not set `encryptedIpnsPrivateKey`/`keyEpoch`, and the function returns them unset. A new subfolder created this way would therefore not be picked up by the TEE republisher and its IPNS record would eventually expire.

Phase 63 is the read-chain/rotation skeleton and intentionally does not wire TEE republishing (TEE lease-renewer contract is Phase 67; the app is non-runnable mid-milestone). The risk is silent: a caller that supplies `teeKeys` expecting republish wiring gets a subfolder that is not republish-enrolled, with no error.

## Solution

Either:
- **Fail closed now (cheap guard):** if `teeKeys` are supplied to `createSubfolder` but the publish path does not yet wire them, throw a clear "TEE republish wiring not implemented (Phase 67)" error rather than silently publishing without them — so no caller mistakenly believes a subfolder is republish-enrolled. (Low-risk; can be done before Phase 67 if any caller starts passing teeKeys.)
- **Wire it (Phase 67):** thread `encryptedIpnsPrivateKey` + `keyEpoch` into the published record and the return value as part of the TEE lease-renewer integration.

Verify whether any current caller passes `teeKeys` (grep) — if none do, this is latent param surface and the fail-closed guard is sufficient interim hardening.

## References

- CodeRabbit PR #579 review, `registration.ts:42-101`
- CLAUDE.md TEE Republishing architecture; ROADMAP Phase 67 (TEE lease-renewer contract)
