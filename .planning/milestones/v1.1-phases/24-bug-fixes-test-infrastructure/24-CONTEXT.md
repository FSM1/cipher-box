# Phase 24: Bug Fixes & Test Infrastructure - Context

**Gathered:** 2026-03-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Fix 2 known bugs (bin IPNS 404 resolution, device registry format error) and strengthen test infrastructure with 3 improvements (headless sdk-core load tests, vault v2 recovery tool E2E tests, load test 401 token refresh). Also clean up the recovery tool to remove dead export file recovery mode.

</domain>

<decisions>
## Implementation Decisions

### Bug 1: Bin IPNS 404 resolution

- **Both** robust initial publish AND auto-repair on load
- Initial publish: add retry + verify after first bin IPNS publish to ensure it succeeds
- Auto-repair: if `loadBin()` gets IPNS 404, re-derive the bin keypair and publish an empty bin record automatically
- Repair is transparent to the user — no manual action required
- No toast/notification needed — silent auto-repair

### Bug 2: Device registry format error

- **Version bump to v2** following the metadata schema evolution protocol (`docs/METADATA_EVOLUTION_PROTOCOL.md`)
- Add `version` field to registry schema
- Write v1→v2 migration: fill sensible defaults for any missing fields
- Lenient parsing on read: accept v1 registries and upgrade transparently
- Strict validation on write: always write v2 format
- Follow the evolution checklist (Section 4 of the protocol) for the schema change

### Headless sdk-core load tests

- **Goal:** Bottleneck isolation at the function level (supplements, does not replace, existing client-based tests)
- **Operations to test in isolation:**
  - IPNS publish/resolve contention at scale
  - Upload pipeline (encrypt + IPFS pin + IPNS metadata publish) without client folder tree overhead
  - Folder metadata load (IPNS resolve + IPFS fetch + decrypt) read path independently
- **Not testing:** Raw crypto throughput (unlikely bottleneck)
- **Metrics:** Reuse existing MetricsCollector + checkThresholds/expectThresholdsPassed from `tests/load/src/harness/`
- Same reporting format and CI integration as existing load test scenarios

### Recovery tool cleanup & E2E tests

- **Remove export file recovery mode entirely** — all vaults are v2, DB was wiped, no export files exist
- Simplify recovery.html to IPFS-direct v2 blob recovery only (private key → derive IPNS → fetch blob → decrypt)
- **Test data seeding:** Use SDK E2E harness to create a real vault + upload files, then navigate to recovery.html and recover them
- **Coverage:** IPFS-direct v2 blob recovery path (the only remaining mode)
- Tests require API + IPFS running (same as other web E2E tests)

### Load test 401 token refresh

- **Reactive 401 interceptor** — Axios interceptor catches 401, re-authenticates via `/auth/test-login`, retries the failed request
- No proactive refresh (simpler, handles the actual failure case)
- **Post-refresh:** Retry the failed request only — do not reload folder metadata
- No folder state reload needed since auth issues don't affect folder state

### Claude's Discretion

- Exact retry count and backoff strategy for bin IPNS initial publish
- How to structure the headless load test scenarios (file organization within tests/load/src/)
- Recovery tool UI simplification details (layout changes after removing export mode)
- Axios interceptor implementation pattern (queue concurrent 401s to avoid multiple simultaneous refreshes)

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Metadata evolution

- `docs/METADATA_EVOLUTION_PROTOCOL.md` — Formal rules for evolving metadata schemas (version bumps, migration rules, dual-platform checklist)
- `docs/METADATA_SCHEMAS.md` — Documents all 10 metadata objects including DeviceRegistry field tables

### Bug context

- `.planning/todos/pending/` — Original bug reports for bin IPNS 404 and device registry format error

### Existing test infrastructure

- `tests/load/src/harness/metrics.ts` — MetricsCollector for operation timing
- `tests/load/src/harness/thresholds.ts` — Threshold checking with expectThresholdsPassed helper
- `tests/load/src/harness/client-pool.ts` — Pool management and test account creation
- `tests/sdk-e2e/src/fixtures/test-harness.ts` — Shared test account creation (createTestAccount)

### Recovery tool

- `apps/web/public/recovery.html` — Current standalone recovery tool (both modes, to be simplified)

### SDK-core exports

- `packages/sdk-core/src/index.ts` — All stateless function exports available for headless testing

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `MetricsCollector` + `checkThresholds` + `expectThresholdsPassed`: Full metrics pipeline for load tests
- `createTestAccount()` in test-harness.ts: Creates unique user, initializes vault, returns client + keys
- `packages/sdk/src/bin/index.ts`: Bin operations already extracted to SDK (loadBin, addToBin, saveBinMetadata)
- `packages/core/src/registry/`: Registry schema validation, encrypt/decrypt, IPNS derivation

### Established Patterns

- IPNS dual-source fallback (delegated routing → DB cache) in `apps/api/src/ipns/ipns.service.ts`
- Vault blob v1/v2 migration pattern: version field + transparent upgrade on read + strict v2 on write
- Load test scenarios: Vitest `describe/it` with client pool setup, workload execution, metrics aggregation, threshold assertion

### Integration Points

- Bin auto-repair hooks into `loadBin()` in `packages/sdk/src/bin/index.ts`
- Registry v2 migration hooks into `initializeOrSyncRegistry()` in `apps/web/src/services/device-registry.service.ts`
- Headless load tests go in `tests/load/src/scenarios/` alongside existing scenarios
- Recovery E2E tests go in `tests/web-e2e/tests/` alongside existing specs
- 401 interceptor goes in `tests/load/src/harness/client-pool.ts` (axios instance creation)

</code_context>

<specifics>
## Specific Ideas

- Follow the metadata evolution protocol checklist (Section 4) for device registry v2 — this is a formal process, not ad-hoc
- Recovery tool cleanup is a nice opportunity to simplify the UI since only one mode remains

</specifics>

<deferred>
## Deferred Ideas

- Error cases for recovery tool (invalid key, unreachable gateway) — could be added later once the happy path has coverage
- Export file recovery mode restoration — removed entirely, could be re-added if demand arises
- Proactive token refresh in load tests — reactive is sufficient for now

</deferred>

---

_Phase: 24-bug-fixes-test-infrastructure_
_Context gathered: 2026-03-25_
