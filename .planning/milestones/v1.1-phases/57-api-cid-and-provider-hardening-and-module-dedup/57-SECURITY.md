---
phase: 57-api-cid-and-provider-hardening-and-module-dedup
audited: 2026-06-22T00:00:00Z
status: secured
threats_verified: 9
asvs_level: 2
block_on: open
---

# Phase 57 Security Audit — API CID & Provider Hardening + Module Dedup

Retroactive verification of the threat mitigations declared in `57-01-PLAN.md`
and `57-02-PLAN.md`. Every `mitigate`-disposition threat was confirmed present
in the implemented code by reading the cited file and running negative-case
greps (no `abs(`, no inline advisory-lock SQL at the three sites, no raw
`?arg=${cid}` interpolation, a single non-spec `provide: IPFS_PROVIDER`
source). Implementation files were treated as read-only.

## Verdict

SECURED. All 8 distinct threats (T-57-SC is shared across both plans) resolve
to CLOSED. No new unmitigated HIGH-severity issue was found.

- Threats closed: 9/9 register entries (8 distinct IDs)
- Open (BLOCKER): 0
- Unregistered flags: 0

## STRIDE Verification Table

| Threat ID | Category | Component | Disposition | Verified | Evidence |
| --------- | -------- | --------- | ----------- | -------- | -------- |
| T-57-01 | Tampering | `RegisterCidDto.cid` loose `{44,}` regex, no MaxLength | mitigate | VERIFIED | `cid.constants.ts:4` exports `CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/` (exact `{44}` CIDv0 branch); `register-cid.dto.ts:3` imports it, `:16` `@MaxLength(255)`, `:17` `@Matches(CID_REGEX, …)`. No inline `{44,}` literal remains (grep returns nothing). |
| T-57-02 | Denial of Service | `RegisterCidDto.cid` oversized string | mitigate | VERIFIED | `register-cid.dto.ts:16` `@MaxLength(255)` bounds input before processing; `@ApiProperty maxLength: 255` at `:12` propagates the constraint to the OpenAPI spec. |
| T-57-03 | Tampering | `LocalProvider` pin/rm + cat URLs (DB-sourced CID interpolated) | mitigate | VERIFIED | `local.provider.ts:87` `new URLSearchParams({ arg: cid })` for pin/rm, `:128` for cat; `grep -c URLSearchParams` = 2; no raw `arg=${cid}` remains. pin/add path (`:49`) unchanged (CID comes from Kubo response body, not the URL). |
| T-57-SC | Tampering | npm/pip/cargo installs | accept | VERIFIED | `git diff main` over 171 changed files shows ZERO `package.json` / `pnpm-lock.yaml` / `Cargo.toml` / `Cargo.lock` changes. No new packages installed. Recorded as accepted risk below. |
| T-57-04 | Tampering | Advisory-lock primitive drift across 3 sites | mitigate | VERIFIED | Single `withCidLock` at `unpin-helpers.ts:14` runs verbatim SQL `unpin-helpers.ts:19` `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)` with NO `abs()` (the two `abs(` grep hits are doc-comment warnings at `:11-12`, not SQL). No inline `pg_advisory_xact_lock` executes at the three sites — vault.service hits at `:244,:266` are doc comments; both call paths route through `withCidLock`. |
| T-57-05 | Tampering (data-loss race) | Unpinning a CID concurrently re-pinned | mitigate | VERIFIED (MOST SENSITIVE) | `refcountAndMaybeUnpin` `unpin-helpers.ts:36` counts `PinnedCid` under the held lock; `:37-40` skips `unpinFile` and deletes the stale outbox row when `refs > 0`; `:41-42` unpins then deletes only when `refs === 0`. `pending-unpin.processor.ts:80-82` invokes it inside `dataSource.transaction` wrapped by `withCidLock(manager, cid, …)` — recheck runs under the held per-CID lock. |
| T-57-06 | Denial of Service | Kubo call held inside a long advisory-lock transaction | accept/mitigate | VERIFIED | `vault.service.ts:314` `await this.ipfsProvider.unpinFile(cid)` runs post-commit, OUTSIDE both transaction blocks, BEFORE the `dataSource.transaction` opened at `:321`. Only the outbox-row delete `:325` runs under `withCidLock`. `refcountAndMaybeUnpin` is correctly NOT used at this site (grep count 0 in vault.service.ts). |
| T-57-07 | Elevation of Privilege / config | Leaf module accidentally importing an upstream module (recreating the cycle) | mitigate | VERIFIED | `ipfs-provider.module.ts:7` `imports: [ConfigModule]` only; factory injects `[ConfigService]` (`:19`). It is the sole non-spec `provide: IPFS_PROVIDER` source. All three consumers import the leaf: `ipfs.module.ts:13`, `pending-unpin.module.ts:16`, `vault.module.ts:17`; `ipfs.module.ts:16` still explicitly `exports: [IPFS_PROVIDER]`. No `IN-04 (accepted)` comments remain. |

## Accepted Risks Log

| ID | Risk | Rationale | Status |
| -- | ---- | --------- | ------ |
| T-57-SC | Supply-chain — new package install | No new npm/cargo dependency was added this phase. `git diff main` shows no manifest/lockfile changes across 171 modified files. Uses only existing `class-validator` / `@nestjs` deps. | Accepted (N/A — nothing installed) |
| T-57-06 | Kubo network call serialized under DB lock (DoS) | Mitigated by design: the physical `unpinFile` Kubo call is post-commit and outside any transaction; only the cheap outbox-row delete is serialized under `withCidLock`. The residual (a brief lock around a single-row delete) is accepted. | Accepted + mitigated |

## Unregistered Flags

None. Neither `57-01-SUMMARY.md` nor `57-02-SUMMARY.md` declares a
`## Threat Flags` section. `57-01-SUMMARY.md` carries a `## Threat Surface
Scan` stating "No new network endpoints, auth paths, or trust boundaries
introduced … No new threat flags." Phase 57 hardens existing paths (CID input
to Kubo URL; advisory-lock unpin policy) and de-duplicates module wiring; it
introduces no new attack surface.

## Methodology

- Static analysis and targeted greps only. The full jest suite (903/903 green)
  was already run by the executor and was NOT re-run here.
- Implementation files were read-only; only this phase `57-SECURITY.md` was
  written. The repo-root `SECURITY.md` was not created or modified.
- Negative-case gates confirmed: no `abs(` in helper SQL, no inline
  `pg_advisory_xact_lock` at the three call sites, no raw `?arg=${cid}`
  interpolation, single non-spec `provide: IPFS_PROVIDER` source, no `{44,}`
  literal in `register-cid.dto.ts`, no `const CID_REGEX` in `unpin.dto.ts`, no
  `IN-04 (accepted)` comments.
