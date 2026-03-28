# Phase 29: Infrastructure Hardening - Context

**Gathered:** 2026-03-28 (assumptions mode)
**Status:** Ready for planning

<domain>
## Phase Boundary

Orphaned IPNS records are cleaned up on file/folder deletion, and the test login endpoint is hardened for staging. This phase does NOT address Kubo access control (deferred — staging already binds port 5001 to 127.0.0.1 via Docker, which is sufficient for now).

</domain>

<decisions>
## Implementation Decisions

### IPNS Unenrollment API

- **D-01:** Add a new REST endpoint to `IpnsController` (e.g., `POST /ipns/unenroll` or `DELETE /ipns/unenroll`) that calls the existing `RepublishService.unenrollIpns()`. Requires JWT auth, scoped by userId from token + ipnsName(s) from body.
- **D-02:** Add a batch variant (e.g., `POST /ipns/unenroll-batch`) accepting an array of IPNS names, following the existing `POST /ipns/publish-batch` pattern. Max 200 per call. Folder deletes can cascade to 1000 files — batch is required.
- **D-03:** Regenerate the API client (`pnpm api:generate`) after adding the endpoints so `@cipherbox/api-client` exposes the new functions.

### SDK Integration

- **D-04:** Wire unenrollment into the SDK layer, not the legacy `folder.service.ts`. The SDK's `CipherBoxClient.deleteItem()` at `packages/sdk/src/client.ts` and `permanentDeleteFromBin()` at `packages/sdk/src/bin/index.ts` are the actual deletion paths used by `useFolderMutations`.
- **D-05:** After deleting a file/folder, collect all `fileMetaIpnsName` values from removed items and call the batch unenroll endpoint. This is fire-and-forget (don't block the deletion UX on unenroll success).
- **D-06:** For folder deletion, recursively collect IPNS names from all nested files before the folder metadata update, then batch unenroll after.

### Test Login Hardening

- **D-07:** The endpoint is already correctly guarded: `NODE_ENV === 'production'` check + `TEST_LOGIN_SECRET` validation with timing-safe comparison + unit tests verifying production guard. No code changes needed.
- **D-08:** Add a Grafana alert rule for staging: alert when `cipherbox_auth_logins_total{method="test"}` rate exceeds a threshold (e.g., >100 per hour). Use existing alert provisioning infrastructure at `docker/grafana/scripts/provision-alerts.sh`.
- **D-09:** Do NOT remove or disable the endpoint on staging — E2E tests depend on `POST /auth/test-login` for headless authentication.

### Deferred: Kubo Access Control

- **D-10:** Kubo port 5001 access control is deferred. Staging already binds to `127.0.0.1:5001` via Docker compose, Caddy does not expose it. This is sufficient for current staging. Production Kubo ACL (native config or reverse proxy) will be addressed in a future phase or milestone.

### Claude's Discretion

- Whether to use `POST /ipns/unenroll` vs `DELETE /ipns/unenroll` (REST convention preference)
- Whether batch unenroll is a separate endpoint or uses the same endpoint with array body
- Exact fire-and-forget pattern (SDK-level `.catch(logger.warn)` or background queue)
- Clean up legacy TODO comments in `folder.service.ts:461`, `folder.service.ts:513`, `delete.service.ts:22` after wiring the new path

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### IPNS Unenrollment

- `apps/api/src/republish/republish.service.ts` — `unenrollIpns()` method at line 255, deletes by `{ userId, ipnsName }`
- `apps/api/src/ipns/ipns.controller.ts` — Existing IPNS controller with publish, publish-batch, resolve routes
- `apps/api/src/republish/republish.controller.ts` — Admin-only health controller (not suitable for user-facing unenroll)

### Deletion Code Paths

- `packages/sdk/src/client.ts` — `deleteItem()` at line 532, `deleteToBin()` — primary deletion interface
- `packages/sdk/src/bin/index.ts` — `permanentDeleteFromBin()` at line 381 — hard delete path
- `apps/web/src/hooks/useFolderMutations.ts` — `handleDelete` at line 309, calls SDK methods
- `apps/web/src/services/folder.service.ts` — Legacy TODO at lines 461, 513 about IPNS cleanup
- `apps/web/src/services/delete.service.ts` — Legacy TODO at line 22

### Test Login

- `apps/api/src/auth/services/test-auth.service.ts` — Guard logic at lines 43-56
- `apps/api/src/auth/services/test-auth.service.spec.ts` — Unit tests at lines 80-92 verifying production guard
- `docker/grafana/dashboards/cipherbox-staging.json` — Already tracks `cipherbox_auth_logins_total{method="test"}`
- `docker/grafana/scripts/provision-alerts.sh` — Alert provisioning infrastructure

### Codebase Analysis

- `.planning/codebase/CONCERNS.md` — Documents orphaned IPNS records (lines 8-12), test login (lines 100-105), Kubo access (lines 93-98)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `RepublishService.unenrollIpns(userId, ipnsName)` — Core unenrollment logic already implemented, just needs REST exposure
- `POST /ipns/publish-batch` — Established batch pattern (accepts array, max 200) to follow for batch unenroll
- `IpnsController` — Natural home for the new endpoint, already has JWT auth guard
- Grafana alert provisioning — `provision-alerts.sh` + JSON alert file pattern from Phase 26

### Established Patterns

- API endpoints follow NestJS controller pattern with DTO validation
- API client is auto-generated via `pnpm api:generate` from OpenAPI spec
- SDK wraps API client calls with domain logic (encryption, metadata handling)
- Fire-and-forget pattern: SDK operations use `.catch()` for non-critical side effects (e.g., unpin calls)

### Integration Points

- `IpnsController` (new routes) -> `RepublishService.unenrollIpns()` (existing)
- `@cipherbox/api-client` (regenerated) -> SDK `deleteItem()`/`permanentDeleteFromBin()` (add unenroll call)
- `docker/grafana/alerts/` (new alert JSON) -> `provision-alerts.sh` (existing)

</code_context>

<specifics>
## Specific Ideas

- Unenrollment should be fire-and-forget from the user's perspective — deletion UX should not be blocked by TEE unenrollment success/failure
- The existing `folder.service.ts` TODO comments should be cleaned up after the SDK path is wired

</specifics>

<deferred>
## Deferred Ideas

- Kubo API access control (port 5001 restriction via reverse proxy or native ACL) — current Docker 127.0.0.1 binding is sufficient for staging
- Production Kubo deployment hardening — future milestone when production environment exists
- Periodic reconciliation job to catch unenrollment failures — could be added if fire-and-forget proves insufficient

</deferred>

---

_Phase: 29-infrastructure-hardening_
_Context gathered: 2026-03-28_
