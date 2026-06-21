# Phase 57: API CID and Provider Hardening and Module Dedup - Pattern Map

**Mapped:** 2026-06-22
**Files analyzed:** 11 (3 new, 8 modified)
**Analogs found:** 11 / 11

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
| --- | --- | --- | --- | --- |
| `apps/api/src/ipfs/dto/cid.constants.ts` (NEW) | utility/constant | — | `apps/api/src/ipfs/dto/unpin.dto.ts` | exact (extract from) |
| `apps/api/src/ipfs/dto/unpin.dto.ts` (EDIT) | dto | request-response | self | exact |
| `apps/api/src/ipfs/dto/register-cid.dto.ts` (EDIT) | dto | request-response | `apps/api/src/ipfs/dto/unpin.dto.ts` | exact |
| `apps/api/src/ipfs/providers/local.provider.ts` (EDIT) | service/provider | request-response | self | exact |
| `apps/api/src/ipfs/providers/ipfs-provider.module.ts` (NEW) | module | — | `apps/api/src/tee/tee.module.ts` | role-match (leaf module) |
| `apps/api/src/ipfs/providers/index.ts` (EDIT) | barrel | — | self | exact |
| `apps/api/src/ipfs/ipfs.module.ts` (EDIT) | module | — | self | exact |
| `apps/api/src/vault/vault.module.ts` (EDIT) | module | — | self | exact |
| `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts` (EDIT) | module | — | self | exact |
| `apps/api/src/ipfs/pending-unpin/unpin-helpers.ts` (NEW) | utility | CRUD + advisory-lock | `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` | role-match (extract from) |
| `apps/api/src/vault/vault.service.ts` (EDIT) | service | CRUD | self | exact |
| `apps/api/src/ipfs/dto/register-cid.dto.spec.ts` (NEW) | test | — | `apps/api/src/ipfs/providers/local.provider.spec.ts` | role-match (unit, no framework setup) |
| `apps/api/src/ipfs/pending-unpin/unpin-helpers.spec.ts` (NEW) | test | — | `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` | exact (mock DataSource/manager) |
| `apps/api/src/ipfs/providers/ipfs-provider.module.spec.ts` (NEW) | test | — | `apps/api/src/ipfs/ipfs.controller.spec.ts` | role-match (NestJS TestingModule) |

## Pattern Assignments

### `apps/api/src/ipfs/dto/cid.constants.ts` (NEW — utility)

**Analog:** `apps/api/src/ipfs/dto/unpin.dto.ts` (extract `CID_REGEX` from lines 4-7)

**Full source to extract from** (unpin.dto.ts lines 4-7):

```typescript
// IN-02: CID format regex covers CIDv0 (Qm... base58, 46 chars) and
// CIDv1 (b... base32, 59+ chars). MaxLength(255) bounds the input to
// prevent oversized-string DoS at the route boundary (T-50-12).
const CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/;
```

**Target `cid.constants.ts`** — export the const, carry the comment:

```typescript
// IN-02: CID format regex covers CIDv0 (Qm... base58, 46 chars) and
// CIDv1 (b... base32, 59+ chars). MaxLength(255) bounds the input to
// prevent oversized-string DoS at the route boundary (T-50-12).
export const CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/;
```

---

### `apps/api/src/ipfs/dto/unpin.dto.ts` (EDIT)

**Change:** Replace the local `const CID_REGEX` declaration (line 7) with an import from `./cid.constants`.

**Before** (lines 4-7):

```typescript
// IN-02: CID format regex covers CIDv0 (Qm... base58, 46 chars) and
// CIDv1 (b... base32, 59+ chars). MaxLength(255) bounds the input to
// prevent oversized-string DoS at the route boundary (T-50-12).
const CID_REGEX = /^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/;
```

**After:**

```typescript
import { CID_REGEX } from './cid.constants';
```

Rest of file unchanged (lines 1-2 imports, lines 9-31 class body stay identical).

---

### `apps/api/src/ipfs/dto/register-cid.dto.ts` (EDIT)

**Analog:** `apps/api/src/ipfs/dto/unpin.dto.ts` — copy its decorator stack exactly.

**Current divergence** (register-cid.dto.ts lines 1-14):

```typescript
import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsInt, Min, Max, IsNotEmpty, Matches } from 'class-validator';
// ...
@ApiProperty({ description: 'IPFS CID pinned to external provider (CIDv0 or CIDv1)' })
@IsString()
@IsNotEmpty()
@Matches(/^(Qm[1-9A-HJ-NP-Za-km-z]{44,}|b[a-z2-7]{58,})$/, {
  message: 'cid must be a valid CIDv0 (Qm...) or CIDv1 (bafy...) string',
})
cid!: string;
```

**Target** — add `MaxLength` import, import `CID_REGEX`, update `@ApiProperty` with maxLength metadata, add `@MaxLength(255)`, fix `{44,}` to `{44}`:

```typescript
import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsInt, Min, Max, IsNotEmpty, Matches, MaxLength } from 'class-validator';
import { CID_REGEX } from './cid.constants';

export class RegisterCidDto {
  @ApiProperty({
    description: 'IPFS CID pinned to external provider (CIDv0 or CIDv1)',
    pattern: '^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$',
    maxLength: 255,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  @Matches(CID_REGEX, { message: 'cid must be a valid CIDv0 (Qm...) or CIDv1 (b...) string' })
  cid!: string;
  // sizeBytes field unchanged
}
```

**Note:** `@MaxLength(255)` triggers D-08 — `pnpm api:generate` required after this change.

---

### `apps/api/src/ipfs/providers/local.provider.ts` (EDIT)

**Analog:** self — lines 87 and 127 are the two edit sites.

**Current unpinFile** (line 87):

```typescript
const response = await fetch(`${this.apiUrl}/api/v0/pin/rm?arg=${cid}`, {
  method: 'POST',
});
```

**Current getFile** (line 127):

```typescript
const response = await fetch(`${this.apiUrl}/api/v0/cat?arg=${cid}`, {
  method: 'POST',
});
```

**Target pattern (URLSearchParams — D-04 preferred form):**

```typescript
// unpinFile (replace line 87):
const params = new URLSearchParams({ arg: cid });
const response = await fetch(`${this.apiUrl}/api/v0/pin/rm?${params}`, { method: 'POST' });

// getFile (replace line 127):
const params = new URLSearchParams({ arg: cid });
const response = await fetch(`${this.apiUrl}/api/v0/cat?${params}`, { method: 'POST' });
```

**pin/add (line 49):** No CID interpolated into the URL — CID comes from the Kubo response body. No change needed.

**Existing spec assertions** (local.provider.spec.ts lines ~158 and ~222): They use `toBe(\`${API_URL}/api/v0/pin/rm?arg=${mockCid}\`)`. `URLSearchParams` produces the same string for valid CIDs (no reserved chars), so existing assertions still pass. A new test for encoding is desirable but not required to pass the suite.

---

### `apps/api/src/ipfs/providers/ipfs-provider.module.ts` (NEW — leaf module)

**Analog:** `apps/api/src/tee/tee.module.ts` (leaf module importing `ConfigModule`, exporting services)

**TeeModule structure** (tee.module.ts lines 1-16):

```typescript
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
// ...
@Module({
  imports: [TypeOrmModule.forFeature([...]), ConfigModule],
  providers: [...],
  exports: [...],
})
export class TeeModule {}
```

**Target `ipfs-provider.module.ts`** — follows same leaf-module pattern, imports only `ConfigModule`:

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

**Key:** No `IpfsModule`, `VaultModule`, or `PendingUnpinModule` imports — leaf only imports `ConfigModule`.

---

### `apps/api/src/ipfs/providers/index.ts` (EDIT)

**Current** (lines 1-2):

```typescript
export * from './ipfs-provider.interface';
export * from './local.provider';
```

**Target** — add barrel export for the new module:

```typescript
export * from './ipfs-provider.interface';
export * from './local.provider';
export * from './ipfs-provider.module';
```

---

### `apps/api/src/ipfs/ipfs.module.ts` (EDIT)

**Analog:** self — remove inline factory, import `IpfsProviderModule`.

**Current factory block** (lines 14-34):

```typescript
providers: [
  {
    // IN-04 (accepted): ... misleading comment ...
    provide: IPFS_PROVIDER,
    useFactory: (configService: ConfigService) => { ... },
    inject: [ConfigService],
  },
],
exports: [IPFS_PROVIDER],
```

**Target:**

```typescript
import { IpfsProviderModule } from './providers';

// In forRootAsync() return:
{
  module: IpfsModule,
  imports: [ConfigModule, VaultModule, IpfsProviderModule],
  controllers: [IpfsController],
  providers: [],
  exports: [IPFS_PROVIDER],  // explicit re-export so IpfsController can inject the token
}
```

Remove `ConfigService` and `LocalProvider` from imports if no longer used directly. Remove the IN-04 comment block.

---

### `apps/api/src/vault/vault.module.ts` (EDIT)

**Current factory block** (lines 19-39):

```typescript
providers: [
  VaultService,
  // IN-04 (accepted): ... misleading comment ...
  {
    provide: IPFS_PROVIDER,
    useFactory: (configService: ConfigService) => { ... },
    inject: [ConfigService],
  },
],
```

**Target:**

```typescript
import { IpfsProviderModule } from '../ipfs/providers';

@Module({
  imports: [
    TypeOrmModule.forFeature([Vault, PinnedCid, FolderIpns, User, PendingUnpin]),
    ConfigModule,
    TeeModule,
    IpfsProviderModule,
  ],
  controllers: [VaultController],
  providers: [VaultService],
  exports: [VaultService],
})
export class VaultModule {}
```

Remove `ConfigService` and `LocalProvider` named imports if no longer used. Remove IN-04 comment.

---

### `apps/api/src/ipfs/pending-unpin/pending-unpin.module.ts` (EDIT)

**Current factory block** (lines 17-35):

```typescript
providers: [
  PendingUnpinProcessor,
  {
    // IN-04 (accepted): ... misleading comment ...
    provide: IPFS_PROVIDER,
    useFactory: (configService: ConfigService) => { ... },
    inject: [ConfigService],
  },
],
```

**Target:**

```typescript
import { IpfsProviderModule } from '../providers';

@Module({
  imports: [
    BullModule.registerQueue({ name: 'pending-unpins' }),
    TypeOrmModule.forFeature([PendingUnpin, PinnedCid]),
    ConfigModule,
    IpfsProviderModule,
  ],
  providers: [PendingUnpinProcessor],
})
export class PendingUnpinModule implements OnModuleInit { ... }
```

Remove `ConfigService` and `LocalProvider` named imports if no longer used. Remove IN-04 comment.

---

### `apps/api/src/ipfs/pending-unpin/unpin-helpers.ts` (NEW — utility)

**Analog:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` lines 91-117 (the `drainRow` method — the pattern to extract from)

**Advisory lock SQL to preserve verbatim** (pending-unpin.processor.ts line 95 and vault.service.ts line 267):

```typescript
// INT_MIN-safe: do NOT add abs() before ::bigint
await manager.query(`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, [cid]);
```

**Target `unpin-helpers.ts`:**

```typescript
import { EntityManager } from 'typeorm';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { IpfsProvider } from '../providers/ipfs-provider.interface';

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
 * the same CID. Use only for drainRow (Kubo inside lock). Do NOT use at the
 * guardedUnpin post-commit site where Kubo must remain outside the transaction.
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

**Post-commit site in vault.service.ts (lines 321-324):** Use `withCidLock` only — no `refcountAndMaybeUnpin`. The Kubo call (`ipfsProvider.unpinFile`) stays OUTSIDE the inner transaction (D-03 ordering):

```typescript
// Post-commit: Kubo call stays outside transaction (D-03)
await this.ipfsProvider.unpinFile(cid);
// Only the outbox-row delete is serialized under the lock:
await this.dataSource.transaction(async (manager) => {
  await withCidLock(manager, cid, async () => {
    await manager.getRepository(PendingUnpin).delete({ cid });
  });
});
```

**drainRow in pending-unpin.processor.ts:** Use both helpers:

```typescript
private async drainRow(cid: string): Promise<void> {
  await this.dataSource.transaction(async (manager) => {
    await withCidLock(manager, cid, () =>
      refcountAndMaybeUnpin(manager, cid, this.ipfsProvider)
    );
  });
}
```

---

### `apps/api/src/ipfs/dto/register-cid.dto.spec.ts` (NEW — test)

**Analog:** `apps/api/src/ipfs/providers/local.provider.spec.ts` (no NestJS TestingModule; plain class instantiation + class-validator `validate()`)

**local.provider.spec.ts structure** (lines 1-33):

```typescript
import { BadRequestException, ... } from '@nestjs/common';
import { LocalProvider } from './local.provider';

describe('LocalProvider', () => {
  let provider: LocalProvider;
  // ...
  beforeEach(() => {
    provider = new LocalProvider(API_URL, GATEWAY_URL);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('constructor', () => {
    it('should throw if ...', () => { ... });
  });
});
```

**Target spec pattern for DTOs** — use `class-validator`'s `validate()` instead of class instantiation:

```typescript
import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';
import { RegisterCidDto } from './register-cid.dto';

describe('RegisterCidDto', () => {
  async function validateDto(plain: Partial<RegisterCidDto>) {
    const dto = plainToInstance(RegisterCidDto, plain);
    return validate(dto);
  }

  it('accepts a valid CIDv1', async () => {
    const errors = await validateDto({ cid: 'bafkreigaknpexyvxt76zgkitavbwx6ejgfheup5oybpm77f3pxzrvwpfdi', sizeBytes: 100 });
    expect(errors).toHaveLength(0);
  });

  it('rejects a CIDv0 with {44,} overflow (47 chars after Qm)', async () => { ... });

  it('rejects strings longer than 255 chars', async () => { ... });
});
```

---

### `apps/api/src/ipfs/pending-unpin/unpin-helpers.spec.ts` (NEW — test)

**Analog:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` (mock DataSource + manager pattern)

**Mock manager pattern** (pending-unpin.processor.spec.ts lines 50-60):

```typescript
const mockManagerQuery = jest.fn().mockResolvedValue([]);
const mockManager = {
  query: mockManagerQuery,
  getRepository: jest.fn((Entity: unknown) => {
    if (Entity === PinnedCid) return mockPinnedCidRepository;
    if (Entity === PendingUnpin) return mockPendingUnpinRepository;
    return {};
  }),
};
const mockDataSource = {
  transaction: jest.fn(async (cb: (manager: unknown) => Promise<unknown>) => cb(mockManager)),
};
```

**Target spec pattern** for `withCidLock` and `refcountAndMaybeUnpin` — use the same mock manager without the full NestJS TestingModule:

```typescript
import { withCidLock, refcountAndMaybeUnpin } from './unpin-helpers';
import { PinnedCid } from '../../vault/entities/pinned-cid.entity';
import { PendingUnpin } from '../../vault/entities/pending-unpin.entity';

describe('withCidLock', () => {
  it('executes pg_advisory_xact_lock SQL with the cid', async () => {
    const mockQuery = jest.fn().mockResolvedValue([]);
    const mockManager = { query: mockQuery, getRepository: jest.fn() } as any;
    const fn = jest.fn().mockResolvedValue('result');

    const result = await withCidLock(mockManager, 'bafk...', fn);

    expect(mockQuery).toHaveBeenCalledWith(
      'SELECT pg_advisory_xact_lock(hashtext($1)::bigint)',
      ['bafk...']
    );
    expect(fn).toHaveBeenCalled();
    expect(result).toBe('result');
  });
});

describe('refcountAndMaybeUnpin', () => {
  it('skips unpin and deletes outbox row when refs > 0', async () => { ... });
  it('calls unpinFile and deletes outbox row when refs === 0', async () => { ... });
});
```

---

### `apps/api/src/ipfs/providers/ipfs-provider.module.spec.ts` (NEW — test)

**Analog:** `apps/api/src/ipfs/ipfs.controller.spec.ts` (NestJS `Test.createTestingModule`)

**NestJS TestingModule pattern** (from ipfs.controller.spec.ts):

```typescript
import { Test, TestingModule } from '@nestjs/testing';

describe('IpfsController', () => {
  let module: TestingModule;

  beforeEach(async () => {
    module = await Test.createTestingModule({
      imports: [...],
      controllers: [IpfsController],
    }).compile();
  });
});
```

**Target spec** — compile `IpfsProviderModule` with a mock `ConfigService` and assert the token resolves:

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigModule } from '@nestjs/config';
import { IpfsProviderModule } from './ipfs-provider.module';
import { IPFS_PROVIDER } from './ipfs-provider.interface';

describe('IpfsProviderModule', () => {
  it('provides and exports IPFS_PROVIDER token', async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: false }),
        IpfsProviderModule,
      ],
    }).compile();

    const provider = module.get(IPFS_PROVIDER);
    expect(provider).toBeDefined();
  });
});
```

---

## Shared Patterns

### Advisory Lock SQL (INT_MIN-safe)

**Source:** `apps/api/src/vault/vault.service.ts` line 267; `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.ts` line 95
**Apply to:** `unpin-helpers.ts` `withCidLock` body — verbatim, no modification

```typescript
await manager.query(`SELECT pg_advisory_xact_lock(hashtext($1)::bigint)`, [cid]);
```

NEVER add `abs()` before `::bigint`. The cast sign-extends `int4` to `bigint` safely.

### NestJS DTO Decorator Stack

**Source:** `apps/api/src/ipfs/dto/unpin.dto.ts` lines 10-21
**Apply to:** `register-cid.dto.ts` `cid` field

```typescript
@ApiProperty({ description: '...', pattern: '...', maxLength: 255 })
@IsString()
@IsNotEmpty()
@MaxLength(255)
@Matches(CID_REGEX, { message: 'cid must be a valid CIDv0 (Qm...) or CIDv1 (b...) string' })
cid!: string;
```

### IPFS_PROVIDER Factory (canonical, deduplicated)

**Source:** All three modules (`ipfs.module.ts` lines 21-31, `vault.module.ts` lines 29-38, `pending-unpin.module.ts` lines 25-35) — identical
**Apply to:** `ipfs-provider.module.ts` `providers` array — single source of truth

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
}
```

### Mock Manager Pattern (Jest)

**Source:** `apps/api/src/ipfs/pending-unpin/pending-unpin.processor.spec.ts` lines 50-60
**Apply to:** `unpin-helpers.spec.ts` — same `mockManager` + `getRepository` dispatch shape

```typescript
const mockManagerQuery = jest.fn().mockResolvedValue([]);
const mockManager = {
  query: mockManagerQuery,
  getRepository: jest.fn((Entity: unknown) => {
    if (Entity === PinnedCid) return mockPinnedCidRepository;
    if (Entity === PendingUnpin) return mockPendingUnpinRepository;
    return {};
  }),
};
```

## No Analog Found

None — all files have close analogs in the existing codebase.

## Metadata

**Analog search scope:** `apps/api/src/ipfs/`, `apps/api/src/vault/`, `apps/api/src/tee/`
**Files scanned:** 14
**Pattern extraction date:** 2026-06-22
