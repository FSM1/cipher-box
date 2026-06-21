# Phase 57: API CID and Provider Hardening and Module Dedup - Research

**Researched:** 2026-06-22
**Domain:** NestJS API — DTO validation, IPFS provider URL construction, NestJS module architecture, TypeORM advisory locks
**Confidence:** HIGH

<user_constraints>

## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01:** Extract the existing `UnpinDto` regex into a single shared constant and apply it — plus `@MaxLength(255)` — to `RegisterCidDto.cid`. Change CIDv0 branch `{44,}` to `{44}`.
- **D-02:** The CIDv1 branch (`b[a-z2-7]{58,}`, open length, capped by `@MaxLength(255)`) MUST stay. Do not collapse to CIDv0-only.
- **D-03:** Keep the regex approach via `class-validator` `@Matches`. Do NOT introduce a `multiformats`-based `@IsCid()` validator.
- **D-04:** In `LocalProvider`, encode every CID interpolated into a Kubo query string — `pin/rm?arg=`, the symmetric `pin/add` path (the `/api/v0/add` path does NOT interpolate CID into the URL — the CID is in the response), and `cat?arg=`. Use `URLSearchParams` (preferred) or `encodeURIComponent`.
- **D-05:** Extract a leaf `IpfsProviderModule` — `@Module({ imports: [ConfigModule], providers: [IPFS_PROVIDER], exports: [IPFS_PROVIDER] })`. Import it from `IpfsModule`, `VaultModule`, and `PendingUnpinModule`; remove the three duplicated factory definitions.
- **D-06:** Delete/correct the misleading IN-04 "accepted circular-dependency" comments in all three modules.
- **D-07:** Extract `withCidLock(cid, fn)` and `refcountAndMaybeUnpin(manager, cid)` shared primitives. Route all three advisory-lock unpin sites through them.
- **D-08 (api:generate):** Run `pnpm api:generate` and commit the regenerated client iff the `RegisterCidDto` change alters the OpenAPI spec.

### Claude's Discretion

- File placement of the shared `CID_REGEX` constant (e.g. `apps/api/src/ipfs/dto/cid.constants.ts` or under `ipfs/`).
- File placement of `withCidLock`/`refcountAndMaybeUnpin` helpers (a shared location both `vault.service.ts` and `pending-unpin.processor.ts` import).
- `URLSearchParams` vs `encodeURIComponent` exact form.

### Deferred Ideas (OUT OF SCOPE)

- Phase 58 todos (`2026-06-20-ipns-publish-validate-embedded-sequence-without-cas.md`, `2026-06-20-ipns-resolve-verify-coverage-and-web-sdk-dedup.md`)
- `2026-06-20-cargo-lock-sync-precise-vs-workspace.md`

</user_constraints>

<phase_requirements>

## Phase Requirements

| ID      | Description                                                                                   | Research Support                                                                                                               |
| ------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| HARD-08 | API CID/provider hardening — shared CID regex + MaxLength, URL-encoded LocalProvider pin/cat URLs, leaf IpfsProviderModule, shared withCidLock/refcountAndMaybeUnpin | All four sub-tasks researched; exact edit sites, advisory-lock SQL, and OpenAPI impact confirmed from source |

</phase_requirements>

## Summary

Phase 57 is a pure consolidation/hardening pass across four deferred findings from the Phase 50 review: (1) make `RegisterCidDto` CID validation match `UnpinDto` exactly; (2) URL-encode CID interpolations in `LocalProvider`; (3) extract a leaf `IpfsProviderModule` to eliminate the triplicated factory; (4) extract shared `withCidLock`/`refcountAndMaybeUnpin` helpers to deduplicate the three advisory-lock unpin sites.

No new capabilities are added. Every change consolidates existing mechanisms. The CID regex is already correct in `unpin.dto.ts:7` — the task is extraction and application. The advisory lock SQL is already correct in all three sites — the task is consolidation so future drift requires editing one place.

The only integration-touching step is D-08: adding `@MaxLength(255)` to `RegisterCidDto.cid` WILL add a `maxLength` field to the `RegisterCidDto` schema in `openapi.json`. The current `openapi.json` shows `RegisterCidDto` has no `maxLength` on its `cid` property (confirmed from source) while `UnpinDto` already emits `"maxLength": 255`. Therefore `pnpm api:generate` IS required after the DTO change.

**Primary recommendation:** Execute 57-01 (data-integrity, TDD-eligible) and 57-02 (module dedup) as parallel Wave-1 plans. Both touch disjoint file sets. No environment dependencies beyond a working Node.js/NestJS/Jest setup.

## Architectural Responsibility Map

| Capability              | Primary Tier  | Secondary Tier | Rationale                                              |
| ----------------------- | ------------- | -------------- | ------------------------------------------------------ |
| CID input validation    | API / Backend | —              | DTO class-validators fire at the NestJS route boundary |
| URL construction safety | API / Backend | —              | Provider layer; Kubo is an external dependency         |
| Module wiring           | API / Backend | —              | NestJS DI; affects only the server module graph        |
| Unpin primitive         | API / Backend | Database       | Advisory lock requires a PG transaction context        |

## Standard Stack

### Core (already installed — no new packages)

| Library          | Version (in use) | Purpose                                        |
| ---------------- | ---------------- | ---------------------------------------------- |
| `class-validator` | `^0.14.x`       | `@Matches`, `@MaxLength`, `@IsString` on DTOs  |
| `@nestjs/common` | `^10.x`          | `@Module`, `@Injectable`, DI tokens            |
| `@nestjs/config` | `^3.x`           | `ConfigService` for `IPFS_LOCAL_API_URL`       |
| `typeorm`        | `^0.3.x`         | `DataSource`, `EntityManager` for advisory lock |

No new packages are required. All tools are already in the project.

### Installation

```bash
# No new packages — phase uses existing deps only
```

## Package Legitimacy Audit

No new packages are installed in this phase. Section not applicable.

## Architecture Patterns

### System Architecture Diagram

```
HTTP Request
     |
     v
IpfsController / VaultController / RegisterCidController
     |
     v
DTO Validation (class-validator @Matches CID_REGEX + @MaxLength(255))
     |                                 ^
     |                           [shared constant from cid.constants.ts]
     v
VaultService.guardedUnpin() / PendingUnpinProcessor.drainRow()
     |
     v
[withCidLock(cid, fn)]  ←  shared helper
  acquires pg_advisory_xact_lock(hashtext($1)::bigint)
     |
     v
[refcountAndMaybeUnpin(manager, cid)]  ←  shared helper
  recheck pinned_cids count → conditional unpin → delete outbox row
     |
     v
LocalProvider.unpinFile(cid) / .getFile(cid)
  fetch(`${apiUrl}/api/v0/pin/rm?arg=${encodeURIComponent(cid)}`)
  fetch(`${apiUrl}/api/v0/cat?arg=${encodeURIComponent(cid)}`)
     |
     v
Kubo HTTP API
```

### Recommended Project Structure (additions only)

```
apps/api/src/
├── ipfs/
│   ├── dto/
│   │   ├── cid.constants.ts      # NEW: exports CID_REGEX shared constant
│   │   ├── unpin.dto.ts          # EDIT: import CID_REGEX from cid.constants
│   │   └── register-cid.dto.ts   # EDIT: import CID_REGEX + add @MaxLength(255)
│   ├── providers/
│   │   ├── ipfs-provider.module.ts  # NEW: leaf IpfsProviderModule
│   │   ├── local.provider.ts        # EDIT: URLSearchParams on pin/rm + cat
│   │   └── index.ts                 # EDIT: export IpfsProviderModule
│   ├── ipfs.module.ts            # EDIT: remove factory, import IpfsProviderModule
│   └── pending-unpin/
│       ├── pending-unpin.module.ts  # EDIT: remove factory, import IpfsProviderModule
│       └── unpin-helpers.ts         # NEW: withCidLock + refcountAndMaybeUnpin
└── vault/
    ├── vault.module.ts           # EDIT: remove factory, import IpfsProviderModule
    └── vault.service.ts          # EDIT: route guardedUnpin through shared helpers
```

### Pattern 1: Shared CID_REGEX Constant (D-01..D-03)

**What:** Extract the regex from `UnpinDto` into `cid.constants.ts`, import it in both DTOs.

**Current state (verified from source):**

- `unpin.dto.ts:7`: `const CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/;` — correct, local-only
- `register-cid.dto.ts:11`: `@Matches(/^(Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[a-z2-7]{58,})$/, ...)` — inline, `{44,}` instead of `{44}`, no `@MaxLength`

**Target `cid.constants.ts`:**

```typescript
// Source: existing UnpinDto regex (unpin.dto.ts:7) — IN-02 pattern
// CIDv0: Qm + 44 base58btc chars = 46 chars total (fixed length)
// CIDv1: b + 58+ base32 chars (open length, capped by @MaxLength(255))
export const CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/;
```

**Target `register-cid.dto.ts` additions:**

```typescript
import { CID_REGEX } from './cid.constants';
// add @MaxLength(255) import
@MaxLength(255)
@Matches(CID_REGEX, { message: 'cid must be a valid CIDv0 (Qm...) or CIDv1 (b...) string' })
cid!: string;
```

**Target `unpin.dto.ts` change:** Remove the local `const CID_REGEX` declaration, import from `cid.constants.ts`.

### Pattern 2: URL-Encoded CID in LocalProvider (D-04)

**What:** Replace raw string interpolation with `URLSearchParams` for CID query params.

**Current unpin (line 87):** `fetch(\`${this.apiUrl}/api/v0/pin/rm?arg=${cid}\`, ...)`
**Current cat (line 127):** `fetch(\`${this.apiUrl}/api/v0/cat?arg=${cid}\`, ...)`
**pin/add (line 49):** `fetch(\`${this.apiUrl}/api/v0/add?pin=true&cid-version=1\`, ...)` — no CID in URL (CID comes from Kubo response), no change needed here.

**Target pattern (URLSearchParams preferred per D-04):**

```typescript
// unpinFile
const params = new URLSearchParams({ arg: cid });
const response = await fetch(`${this.apiUrl}/api/v0/pin/rm?${params}`, { method: 'POST' });

// getFile
const params = new URLSearchParams({ arg: cid });
const response = await fetch(`${this.apiUrl}/api/v0/cat?${params}`, { method: 'POST' });
```

**Test impact:** `local.provider.spec.ts:158` asserts `expect(url).toBe(\`${API_URL}/api/v0/pin/rm?arg=${mockCid}\`)` and line 222 asserts `expect(url).toBe(\`${API_URL}/api/v0/cat?arg=${mockCid}\`)`. These assertions check the exact URL string. With `URLSearchParams`, the URL becomes `pin/rm?arg=bafk...` which is identical for valid CIDs (no special chars to encode), so the assertions still pass for the existing CID fixture. However, a new test should verify that a CID containing `%` or `&` is correctly encoded. In practice, a cleaner approach is `encodeURIComponent(cid)` which produces identical output for normal CIDs and makes the intent explicit, with no assertion changes needed.

### Pattern 3: Leaf IpfsProviderModule (D-05, D-06)

**What:** New `@Module` that owns the `IPFS_PROVIDER` factory; imported by the three consumer modules.

**Key fact (confirmed from source):** `IPFS_PROVIDER` token is declared in `ipfs-provider.interface.ts:7`. The `IpfsProviderModule` should live in `apps/api/src/ipfs/providers/ipfs-provider.module.ts` and be exported from `apps/api/src/ipfs/providers/index.ts`.

**The real cycle:** `IpfsModule` imports `VaultModule` (to access `VaultService` for the controller). `VaultModule` exports `VaultService`. There is no cycle once `IPFS_PROVIDER` moves to a leaf module — `IpfsProviderModule` only imports `ConfigModule` (a leaf with no upstream deps).

**Target `ipfs-provider.module.ts`:**

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { IPFS_PROVIDER } from './ipfs-provider.interface';
import { LocalProvider } from './local.provider';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: IPFS_PROVIDER,
      useFactory: (configService: ConfigService) => {
        const apiUrl = configService.get<string>('IPFS_LOCAL_API_URL', 'http://localhost:5001');
        const gatewayUrl = configService.get<string>(
          'IPFS_LOCAL_GATEWAY_URL',
          'http://localhost:8080'
        );
        return new LocalProvider(apiUrl, gatewayUrl);
      },
      inject: [ConfigService],
    },
  ],
  exports: [IPFS_PROVIDER],
})
export class IpfsProviderModule {}
```

**Consumer modules:** Each of `IpfsModule.forRootAsync()`, `VaultModule`, and `PendingUnpinModule` removes the inline factory block and adds `IpfsProviderModule` to its `imports` array.

**Note on `IpfsModule.forRootAsync()`:** The dynamic module returns an object with `imports`, `providers`, etc. After the change, `IPFS_PROVIDER` leaves `providers` (the factory moves to `IpfsProviderModule`) but `IpfsModule` still needs to re-export it. Add `IpfsProviderModule` (or just `IPFS_PROVIDER` via `exports`) so the controller can still inject it. Easiest: keep `exports: [IPFS_PROVIDER]` in the returned DynamicModule, and put `IpfsProviderModule` in `imports`. NestJS resolves the token from the imported module.

### Pattern 4: Shared Unpin Primitives (D-07)

**What:** Two helper functions extracted to a shared file, routing all three advisory-lock sites.

**Three sites confirmed (from source):**

1. `vault.service.ts:267` — main transaction: `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`
2. `vault.service.ts:322` — post-commit delete transaction: same lock SQL
3. `pending-unpin.processor.ts:95` — drain transaction: same lock SQL

**INT_MIN-safe key derivation (exact SQL, verbatim — must not change):**

```sql
SELECT pg_advisory_xact_lock(hashtext($1)::bigint)
```

The comment in `vault.service.ts:265-266` explains: `abs()` was previously applied to int4 before the bigint cast, which overflowed for INT_MIN (-2147483648). The fix is the bare `hashtext($1)::bigint` sign-extending cast — no `abs()`. This SQL must be preserved verbatim in `withCidLock`.

**Placement:** `apps/api/src/ipfs/pending-unpin/unpin-helpers.ts` is the most natural location because both unpin sites (`vault.service.ts` and `pending-unpin.processor.ts`) are downstream of the pending-unpin subsystem. Alternatively, `apps/api/src/ipfs/unpin-helpers.ts` (one level up) avoids the pending-unpin subdirectory being a shared-util owner. Both work; the planner should pick one and document it.

**Target signatures:**

```typescript
import { EntityManager, Repository } from 'typeorm';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { IpfsProvider } from '../providers';

/**
 * Acquires pg_advisory_xact_lock(hashtext(cid)::bigint) as the first
 * transactional statement and runs fn inside the lock.
 *
 * INT_MIN-safe: hashtext returns int4; casting directly to bigint sign-extends
 * the value rather than overflowing abs() on INT_MIN (-2147483648). DO NOT
 * add abs() before the cast — that was the bug fixed in Phase 42/50.
 */
export async function withCidLock<T>(
  manager: EntityManager,
  cid: string,
  fn: () => Promise<T>
): Promise<T> {
  await manager.query(`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, [cid]);
  return fn();
}

/**
 * Under an already-held CID advisory lock: recheck refcount, unpin when zero,
 * delete the outbox row.
 *
 * Must be called within a transaction that has already called withCidLock for
 * the same CID.
 */
export async function refcountAndMaybeUnpin(
  manager: EntityManager,
  cid: string,
  ipfsProvider: IpfsProvider
): Promise<void> {
  const refs = await manager.getRepository(PinnedCid).count({ where: { cid } });
  if (refs > 0) {
    await manager.getRepository(PendingUnpin).delete({ cid });
    return; // stale outbox row — CID is re-pinned
  }
  await ipfsProvider.unpinFile(cid);
  await manager.getRepository(PendingUnpin).delete({ cid });
}
```

**CAUTION — `guardedUnpin` post-commit site (vault.service.ts:319-327):** This site is NOT inside a drainRow-style "one big transaction." The existing code structure is:
1. Main transaction acquires lock → ownership check → delete pinned_cids → maybe insert outbox → sets `shouldAttemptPhysicalUnpin = true`
2. Post-commit: `await ipfsProvider.unpinFile(cid)` (outside any transaction)
3. Then `await this.dataSource.transaction(async (manager) => { ... lock ... delete outbox row ... })`

The `refcountAndMaybeUnpin` helper as sketched above calls `ipfsProvider.unpinFile` inside a transaction. The post-commit site calls Kubo OUTSIDE a transaction for D-03 ordering (Pitfall 3). The helper must NOT be used verbatim for the post-commit site unless the Kubo call is kept outside. The planner needs to decide: either the helper only handles the "recheck + delete outbox" part (with the Kubo call remaining inline at the post-commit site), or the helper has a `skipUnpin: boolean` parameter. The simplest approach: `refcountAndMaybeUnpin` as above covers `drainRow` (where Kubo runs inside the lock), and `withCidLock` alone covers the post-commit delete site (which does only the lock + outbox delete, not a refcount-recheck unpin). See Open Questions.

### Anti-Patterns to Avoid

- **Calling `abs()` on the hashtext value before casting to bigint:** The old bug. The SQL must stay as `hashtext($1)::bigint` with no `abs()`.
- **Importing `VaultModule` or `IpfsModule` from `IpfsProviderModule`:** The leaf module must only import `ConfigModule`. Any upstream import creates the very cycle the comments claimed (incorrectly) to avoid.
- **Putting the Kubo `unpinFile()` call inside a long-held advisory lock transaction in the post-commit path:** D-03 requires the Kubo call to stay outside any transaction (post-commit, best-effort). The lock in the post-commit path (site 2 in vault.service) guards only the outbox-row delete.

## Don't Hand-Roll

| Problem                  | Don't Build               | Use Instead                            | Why                                                                              |
| ------------------------ | ------------------------- | -------------------------------------- | -------------------------------------------------------------------------------- |
| CID format validation    | New `@IsCid()` decorator  | Shared `CID_REGEX` + `@Matches` (D-03) | `multiformats` is over-engineering for a consistency pass; regex already correct  |
| URL parameter encoding   | Manual `replace()`        | `URLSearchParams` or `encodeURIComponent` | Platform-correct encoding; handles all reserved chars                            |
| Advisory lock management | New PG locking mechanism  | Existing `hashtext($1)::bigint` SQL    | Mechanism already correct and tested; consolidation, not replacement              |

## Common Pitfalls

### Pitfall 1: `local.provider.spec.ts` URL assertions break after URLSearchParams

**What goes wrong:** Line 158 of `local.provider.spec.ts` asserts `expect(url).toBe(\`${API_URL}/api/v0/pin/rm?arg=${mockCid}\`)`. With `URLSearchParams`, the URL is `pin/rm?arg=bafk...` — identical for the valid CID fixture, so tests pass. But if a test is added with a CID containing `+` or `=`, `URLSearchParams` encodes them while a raw string does not.

**How to avoid:** Update the assertions to use `expect(url).toContain('pin/rm')` plus separate assertion on the params, OR keep the existing `toBe` assertions (they still pass for standard CIDs) and add a new test for special-char encoding.

### Pitfall 2: `IpfsModule.forRootAsync()` stops exporting `IPFS_PROVIDER` after refactor

**What goes wrong:** `IpfsController` injects `IPFS_PROVIDER`. If `IpfsModule` removes the factory from its providers but does not export `IPFS_PROVIDER` (via `IpfsProviderModule`), the controller can't resolve the token.

**How to avoid:** Keep `exports: [IPFS_PROVIDER]` in the `DynamicModule` return value of `IpfsModule.forRootAsync()`, and add `IpfsProviderModule` to the `imports` array. NestJS re-exports provider tokens from imported modules when they appear in `exports`.

### Pitfall 3: `refcountAndMaybeUnpin` used at post-commit delete site puts Kubo inside a transaction

**What goes wrong:** The `drainRow` helper and the `guardedUnpin` post-commit delete have different Kubo-call positions (inside vs. outside a transaction). A naive extraction that always calls `ipfsProvider.unpinFile` inside the transaction violates D-03 for the post-commit site.

**How to avoid:** The helper as designed (calling Kubo then deleting outbox row) is correct for `drainRow`. For the post-commit site in `guardedUnpin`, only `withCidLock` wraps the outbox-row delete; the Kubo call stays in the outer scope (outside the inner transaction). See Open Questions for the design choice.

### Pitfall 4: Forgetting `pnpm api:generate` after `@MaxLength(255)` on `RegisterCidDto`

**What goes wrong:** `check-api-client.sh` detects `.dto.ts` staged without `openapi.json` staged and fails the pre-commit hook.

**How to avoid:** After committing the DTO change, run `pnpm api:generate` and stage the regenerated `packages/api-client/openapi.json` and client files before the next commit.

### Pitfall 5: `abs()` regression in `withCidLock`

**What goes wrong:** Re-introducing `abs(hashtext($1)::int4)::bigint` causes overflow for INT_MIN CID hashes, allowing concurrent unpin for the same CID.

**How to avoid:** The SQL is `SELECT pg_advisory_xact_lock(hashtext($1)::bigint)` — the `::bigint` cast is applied directly to the `int4` result, sign-extending rather than overflowing. Copy verbatim from `vault.service.ts:267`.

## Code Examples

### Current advisory lock SQL (verified from vault.service.ts:267 and pending-unpin.processor.ts:95)

```typescript
// INT_MIN-safe: do NOT add abs() before ::bigint
await manager.query(`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, [cid]);
```

### Current CID_REGEX in unpin.dto.ts:7 (the reference, verified from source)

```typescript
const CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/;
```

### Current RegisterCidDto divergence (verified from register-cid.dto.ts:11)

```typescript
// BEFORE (loose):
@Matches(/^(Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[a-z2-7]{58,})$/, { ... })
cid!: string;
// Missing: @MaxLength(255)

// AFTER (aligned with UnpinDto):
@MaxLength(255)
@Matches(CID_REGEX, { message: 'cid must be a valid CIDv0 (Qm...) or CIDv1 (b...) string' })
cid!: string;
```

### Current URL construction (verified from local.provider.ts:87,127)

```typescript
// BEFORE — unpin (line 87):
const response = await fetch(`${this.apiUrl}/api/v0/pin/rm?arg=${cid}`, { method: 'POST' });

// BEFORE — cat (line 127):
const response = await fetch(`${this.apiUrl}/api/v0/cat?arg=${cid}`, { method: 'POST' });

// AFTER (URLSearchParams):
const params = new URLSearchParams({ arg: cid });
const response = await fetch(`${this.apiUrl}/api/v0/pin/rm?${params}`, { method: 'POST' });
```

### Current IPFS_PROVIDER factory (identical in all 3 modules, verified from source)

```typescript
{
  provide: IPFS_PROVIDER,
  useFactory: (configService: ConfigService) => {
    const apiUrl = configService.get<string>('IPFS_LOCAL_API_URL', 'http://localhost:5001');
    const gatewayUrl = configService.get<string>(
      'IPFS_LOCAL_GATEWAY_URL',
      'http://localhost:8080'
    );
    return new LocalProvider(apiUrl, gatewayUrl);
  },
  inject: [ConfigService],
},
```

## State of the Art

| Old Approach                                           | Current Approach                                      | When Changed        | Impact                                              |
| ------------------------------------------------------ | ----------------------------------------------------- | ------------------- | --------------------------------------------------- |
| `abs(hashtext($1)::int4)::bigint` (overflow on INT_MIN) | `hashtext($1)::bigint` (sign-extend, safe)           | Phase 42/50         | No overflow for INT_MIN hashes                      |
| Drain ran refcount recheck without advisory lock        | Drain runs inside advisory lock transaction           | Phase 50 (WR-01 fix) | Serializes drain vs guardedUnpin per CID           |
| Post-commit outbox delete outside advisory lock         | Post-commit delete inside its own advisory lock txn  | Phase 50 (WR-03 fix) | Prevents racing guardedUnpin removing the retry row |

## OpenAPI Impact Analysis (D-08)

**Confirmed from openapi.json (lines 2646-2659):** `RegisterCidDto` currently has NO `maxLength` on its `cid` property. The current schema is:

```json
"RegisterCidDto": {
  "type": "object",
  "properties": {
    "cid": { "type": "string", "description": "IPFS CID pinned to external provider (CIDv0 or CIDv1)" },
    "sizeBytes": { "type": "number", "description": "Size of the pinned content in bytes" }
  },
  "required": ["cid", "sizeBytes"]
}
```

After adding `@MaxLength(255)`, NestJS/Swagger will emit `"maxLength": 255` on the `cid` property (confirmed from the `UnpinDto` pattern at openapi.json line 2630, which shows `"maxLength": 255` is emitted for `@MaxLength`-decorated fields with the `@ApiProperty` decorator). Adding `@ApiProperty` with `maxLength` metadata is also needed for the spec to reflect it correctly.

**Therefore: D-08 is triggered. `pnpm api:generate` MUST run after the DTO change.** This is an execute-phase step, not a planning step.

## Existing Test Coverage Map

| File                                   | Test file                                  | Pattern                           |
| -------------------------------------- | ------------------------------------------ | --------------------------------- |
| `local.provider.ts`                    | `local.provider.spec.ts`                  | Jest, mocks `global.fetch`         |
| `vault.service.ts`                     | `vault.service.spec.ts`                   | Jest, mock DataSource/repos        |
| `pending-unpin.processor.ts`           | `pending-unpin.processor.spec.ts`         | Jest, mock DataSource/repos        |
| `unpin.dto.ts` / `register-cid.dto.ts` | None (DTOs excluded from coverage config) | TDD: new spec file needed          |

**Jest config details (confirmed from `apps/api/jest.config.js`):**

- Test regex: `.*\.spec\.ts$` (spec files only, not `.test.ts`)
- rootDir: `apps/api/src`
- Runner: `pnpm --filter @cipherbox/api test` or `cd apps/api && npx jest`
- Coverage excluded: `**/*.module.ts`, `**/index.ts`, `**/dto/**`, `**/entities/**`
- Per-file thresholds: `local.provider.ts` (lines: 85, branches: 80), `vault/vault.service.ts` (lines: 90, branches: 77)

**DTOs are excluded from coverage** (`!**/dto/**` in collectCoverageFrom). Spec files for DTO validation still run and count toward global coverage but DTO source lines are not counted in coverage metrics. TDD for the DTO is still correct and desirable.

## Validation Architecture

### Test Framework

| Property           | Value                                      |
| ------------------ | ------------------------------------------ |
| Framework          | Jest 29 + ts-jest                          |
| Config file        | `apps/api/jest.config.js`                  |
| Quick run command  | `pnpm --filter @cipherbox/api test -- --testPathPattern=ipfs`  |
| Full suite command | `pnpm --filter @cipherbox/api test`        |

### Phase Requirements → Test Map

| Req ID  | Behavior                                              | Test Type   | Automated Command                                                                                       | File Exists?         |
| ------- | ----------------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------- | -------------------- |
| HARD-08 | `RegisterCidDto` rejects CIDv0 `{44,}` > 46 chars    | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern=register-cid`                                  | ❌ Wave 0 (new spec)  |
| HARD-08 | `RegisterCidDto` rejects strings > 255 chars          | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern=register-cid`                                  | ❌ Wave 0 (new spec)  |
| HARD-08 | `RegisterCidDto` accepts valid CIDv1 `bafk...`        | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern=register-cid`                                  | ❌ Wave 0 (new spec)  |
| HARD-08 | `LocalProvider.unpinFile` uses `arg=` query param safely | unit     | `pnpm --filter @cipherbox/api test -- --testPathPattern=local.provider`                                | ✅ (update existing)  |
| HARD-08 | `LocalProvider.getFile` uses `arg=` query param safely   | unit     | `pnpm --filter @cipherbox/api test -- --testPathPattern=local.provider`                                | ✅ (update existing)  |
| HARD-08 | `withCidLock` executes `pg_advisory_xact_lock` SQL    | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern=unpin-helpers`                                 | ❌ Wave 0 (new spec)  |
| HARD-08 | `refcountAndMaybeUnpin` skips unpin when refs > 0     | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern=unpin-helpers`                                 | ❌ Wave 0 (new spec)  |
| HARD-08 | `IpfsProviderModule` provides `IPFS_PROVIDER` token   | unit        | `pnpm --filter @cipherbox/api test -- --testPathPattern=ipfs-provider.module`                          | ❌ Wave 0 (new spec)  |
| HARD-08 | Full api suite green                                  | regression  | `pnpm --filter @cipherbox/api test`                                                                     | ✅ (existing suite)   |

### Sampling Rate

- **Per task commit:** `pnpm --filter @cipherbox/api test -- --testPathPattern=<changed-module> --passWithNoTests`
- **Per wave merge:** `pnpm --filter @cipherbox/api test`
- **Phase gate:** Full api suite green + coverage thresholds met before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `apps/api/src/ipfs/dto/register-cid.dto.spec.ts` — validates D-01 regex tightening and D-01 `@MaxLength(255)` (TDD candidate)
- [ ] `apps/api/src/ipfs/pending-unpin/unpin-helpers.spec.ts` — validates `withCidLock` SQL and `refcountAndMaybeUnpin` refcount branching (TDD candidate)
- [ ] `apps/api/src/ipfs/providers/ipfs-provider.module.spec.ts` — validates `IpfsProviderModule` provides and exports `IPFS_PROVIDER` (can be simple NestJS testing module compile test)

## Security Domain

### Applicable ASVS Categories

| ASVS Category       | Applies | Standard Control                          |
| ------------------- | ------- | ----------------------------------------- |
| V2 Authentication   | no      | —                                         |
| V3 Session Management | no    | —                                         |
| V4 Access Control   | no      | —                                         |
| V5 Input Validation | yes     | `@Matches(CID_REGEX)` + `@MaxLength(255)` on all CID-accepting DTOs |
| V6 Cryptography     | no      | CID is a hash reference, not crypto key   |

### Known Threat Patterns for this stack

| Pattern                       | STRIDE     | Standard Mitigation                                 |
| ----------------------------- | ---------- | --------------------------------------------------- |
| Oversized input (DoS via long string) | DoS | `@MaxLength(255)` on all CID DTOs                  |
| Query-string injection via CID | Tampering  | `URLSearchParams` / `encodeURIComponent` at provider boundary |
| CIDv0 length spoofing (accept 47+ char Qm strings) | Tampering | `{44}` exact in CIDv0 branch of regex |

## Assumptions Log

| #  | Claim                                                                                     | Section                | Risk if Wrong                               |
| -- | ----------------------------------------------------------------------------------------- | ---------------------- | ------------------------------------------- |
| A1 | `pnpm api:generate` uses Swagger/OpenAPI CLI that picks up `@MaxLength` from class-validator decorators automatically | OpenAPI Impact | api:generate step might not be needed if tooling doesn't reflect MaxLength |

**Verification path for A1:** Confirmed by analogy — `UnpinDto`'s `@MaxLength(255)` already appears as `"maxLength": 255` in the current `openapi.json` at line 2630. The pattern is established. Risk is LOW.

## Open Questions

1. **`refcountAndMaybeUnpin` at the post-commit site in `guardedUnpin`**
   - What we know: The post-commit delete (vault.service.ts:319-327) uses a second transaction that only acquires the lock and deletes the outbox row. It does NOT recheck the refcount (the Kubo unpin already ran outside). The drain's `drainRow` DOES recheck + unpin inside a single transaction.
   - What's unclear: Should `refcountAndMaybeUnpin` be used at the post-commit site? If so, the helper needs a `{ skipUnpin?: boolean }` option, or a separate helper (`deleteOutboxRow(manager, cid)`) is cleaner.
   - Recommendation: Extract `withCidLock` as shared (used at all three sites) and extract `refcountAndMaybeUnpin` only for `drainRow` (where Kubo is inside the lock). The post-commit delete site uses only `withCidLock` + inline `manager.getRepository(PendingUnpin).delete({ cid })`. This keeps the post-commit path's D-03 ordering clear.

2. **`IpfsModule.forRootAsync()` export of `IPFS_PROVIDER`**
   - What we know: `IpfsController` is registered in `IpfsModule` and injects `IPFS_PROVIDER`. After the refactor, the token comes from `IpfsProviderModule` (imported by `IpfsModule`).
   - What's unclear: Does NestJS automatically re-export provider tokens from imported modules, or must `IpfsModule` explicitly list `IPFS_PROVIDER` in its `exports`?
   - Recommendation: Explicitly keep `exports: [IPFS_PROVIDER]` in `IpfsModule.forRootAsync()`. NestJS does allow exporting tokens from imported modules when they are explicitly re-exported, but implicit re-export is not guaranteed across all NestJS versions. The safe pattern is explicit.

## Environment Availability

Step 2.6: SKIPPED — this phase is code/config changes only. No external services (no Docker, no Kubo) are required for the unit tests. `pnpm api:generate` is an execute-phase step that requires the NestJS app to start; it is not a research concern.

## Sources

### Primary (HIGH confidence)

- Verified directly from source files in the worktree — all claims about file/line content are confirmed via `Read` or `Bash grep`

### Secondary (MEDIUM confidence)

- NestJS module architecture patterns — confirmed from the existing codebase conventions (multiple modules already follow the `imports: [ConfigModule]` → `providers: [factory]` → `exports: [token]` pattern)

### Tertiary (LOW confidence)

- NestJS re-export behavior for tokens from imported modules — [ASSUMED] based on NestJS DI documentation conventions; the safe path (explicit export) is recommended regardless

## Metadata

**Confidence breakdown:**

- Edit sites (exact lines): HIGH — read directly from source
- Advisory lock SQL: HIGH — read directly from source (3 sites)
- OpenAPI impact (maxLength): HIGH — confirmed by UnpinDto analogy in existing openapi.json
- NestJS module re-export semantics: MEDIUM — based on established codebase pattern
- `refcountAndMaybeUnpin` scope at post-commit site: MEDIUM — design choice, see Open Questions

**Research date:** 2026-06-22
**Valid until:** 2026-07-22 (stable NestJS/TypeORM conventions; no fast-moving dependencies)
