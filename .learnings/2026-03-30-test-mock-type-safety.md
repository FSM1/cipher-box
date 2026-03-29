# Test Mock Type Safety in NestJS and Vitest

**Date:** 2026-03-30

## Original Prompt

> Fix pre-existing test errors in the SDK and API test suites.

## What I Learned

- **`jest.Mocked<Partial<T>>` loses mock methods after `module.get()`**: When a test declares `let service: jest.Mocked<Partial<SomeService>>` and assigns via `module.get(SomeService)`, the return type is `SomeService` (not mocked). The `.mockResolvedValue()` calls then fail to typecheck because the property is typed as the real method signature, not `jest.Mock`.

- **Vitest `vi.mock()` with bare factory drops non-mocked exports**: When sdk-core tests used `vi.mock('@cipherbox/sdk-core', () => ({ uploadFile: vi.fn(), ... }))`, any export not listed (like `selectEncryptionMode`) was undefined at runtime. The fix is `vi.mock('@cipherbox/sdk-core', async (importOriginal) => { const actual = await importOriginal(); return { ...actual, uploadFile: vi.fn() }; })`.

- **The pattern is systemic**: Found this in 10+ test files across `packages/sdk/` and `apps/api/`. Each file independently made the same mistake. This suggests the pattern was copy-pasted from an early test.

## Correct Patterns

**NestJS spec files (Jest):** Type the mock directly with the shape you need:

```typescript
let mockService: { methodA: jest.Mock; methodB: jest.Mock };
// assign from module.get() with cast
mockService = module.get(RealService) as unknown as typeof mockService;
```

**Vitest module mocks:** Always spread `importOriginal()` so non-mocked exports survive:

```typescript
vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return { ...actual, uploadFile: vi.fn() };
});
```

## Key Files

- `packages/sdk/src/__tests__/*.test.ts` -- All SDK test files that mock sdk-core
- `apps/api/src/republish/*.spec.ts` -- Republish service/processor/health controller specs
- `apps/api/src/tee/tee.service.spec.ts` -- TEE service spec
- `apps/api/src/vault/vault.controller.spec.ts` -- Vault controller spec
