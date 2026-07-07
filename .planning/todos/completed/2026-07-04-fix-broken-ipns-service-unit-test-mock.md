---
created: 2026-07-04T00:00:00Z
title: ipns.service.test.ts crashes at module-load (stale api-client mock) — and web units aren't in CI
area: testing
files:
  - apps/web/src/services/__tests__/ipns.service.test.ts:18
source: ship-phase 68.1 full-web-unit run (pre-existing, not a 68.1 change)
---

## Problem

`apps/web/src/services/__tests__/ipns.service.test.ts` fails to even load: its
`vi.mock('@cipherbox/api-client', () => ({...}))` factory omits `createAxiosInstance`
(and `setApiClientConfig`/`authControllerRefresh`), which `apps/web/src/lib/api-config.ts`
imports and calls at module top-level (`api-config.ts:52`) — so the file throws
"No createAxiosInstance export is defined on the mock" before any test runs. When
the mock IS completed (via `importOriginal`), 2 further tests fail (CBOR decode /
signature-fields fail-closed) because `@cipherbox/core` is also only partially
mocked. The file is BYTE-IDENTICAL to origin/main — this predates phase 68.1 and is
NOT a 68.1 regression.

Root cause it slipped through: **CI's unit-test job (`ci.yml`) does NOT run
`@cipherbox/web` unit tests** — it only covers api, crypto, core, sdk-core, sdk,
api-client. Web is gated by Playwright web-e2e, so a broken web `.test.ts` never
turns CI red. This test (IPNS signature fail-closed — a SECURITY-relevant contract,
D-02/D-03) therefore provides ZERO protection today.

## Solution

Two parts: (1) fix the mock — use `vi.mock('@cipherbox/api-client', async (io) => ({
...await io(), ipnsController*: vi.fn() }))` and complete the `@cipherbox/core` mock
(the CBOR unmarshal + signature helpers `resolveIpnsRecord` actually calls) so all
9 tests pass; (2) decide whether the handful of real web `.test.ts` unit suites
(ipns.service, folder.store, VersionHistory, useSharedWriteOps, …) should be added
to a CI job so they can't silently rot — or formally accept they're advisory-only
and move the security-critical IPNS assertions into a covered package.
