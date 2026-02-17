# Replace ESM-only `ipns` package with inline protobuf decoder

**Date:** 2026-02-08

## Original Prompt

> Implement the following plan: Replace `ipns` package in API with inline protobuf decoder. The `ipns` npm package (v10.1.3) is ESM-only, which doesn't play nicely with NestJS's CommonJS compilation. This forced a dynamic `await import('ipns')` hack that broke Jest mocking, which led to a cascade of test/behavior changes that ultimately broke the desktop FUSE client (502 errors hanging the NFS thread).

## What I Learned

- **ESM-only packages in CJS NestJS are poison**: The `ipns` package forced a dynamic `import()` hack, which broke Jest mocking (can't mock dynamic imports easily), which forced a `moduleNameMapper` workaround, which created a fragile test mock that masked real behavior differences.
- **Only extract what you need from protobuf**: The API used ONE function (`unmarshalIPNSRecord`) and read TWO fields (`value` string, `sequence` bigint). That's fields 1 and 5 in the protobuf wire format. ~65 lines of inline varint/length-delimited parsing replaced an entire dependency tree.
- **Protobuf wire format is simple for read-only**: Varint tags encode `(field_number << 3) | wire_type`. Wire type 0 = varint, 2 = length-delimited. Skip everything else. No schema compilation needed.
- **`resolveRecord` re-throw behavior was the real FUSE killer**: The old code would re-throw `BAD_GATEWAY` when DB cache was empty. The FUSE NFS client would block on this 502, stalling the single NFS thread and disconnecting Finder. Returning `null` (→ 404) is gracefully handled.
- **Test expectations must match behavioral changes**: When changing from "throw on failure" to "return null on failure", 7 tests needed updating. The plan only anticipated 2 (the ones already modified in the working tree). Always count ALL tests that assert `rejects.toThrow` for the changed code path.

## What Would Have Helped

- The plan's test change count (2 tests) was based on the already-modified working tree, not the full set of tests affected by the behavioral change. Should have grepped for `rejects.toThrow` in the resolve tests before starting.
- Understanding that `parseIpnsRecordBytes` throws `HttpException(BAD_GATEWAY)` which IS caught by `resolveRecord`'s BAD_GATEWAY handler — so parse errors also fall through to DB cache now.

## Key Files

- `apps/api/src/ipns/ipns-record-parser.ts` — inline protobuf decoder (new)
- `apps/api/src/ipns/ipns.service.ts` — uses inline parser, no more dynamic import
- `apps/api/src/ipns/ipns.service.spec.ts` — 44 tests, 7 updated for null-return behavior
- `apps/api/package.json` — `ipns` removed from dependencies
- `apps/api/jest.config.js` — `ipns` moduleNameMapper removed
