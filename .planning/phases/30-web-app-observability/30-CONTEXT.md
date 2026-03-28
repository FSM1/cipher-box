# Phase 30: Web App Observability - Context

**Gathered:** 2026-03-28 (assumptions mode + discussion)
**Status:** Ready for planning

<domain>
## Phase Boundary

Errors and performance issues in the deployed web app are captured, tracked, and alertable rather than lost to console.error. This phase wires into Phase 28's logger transport hook and adds an error boundary. It does NOT add session replay, operation-level crypto timing in production, or server-side log shipping changes.

</domain>

<decisions>
## Implementation Decisions

### Error Tracking Service

- **D-01:** Use Grafana Faro (`@grafana/faro-react`) as the error tracking and web vitals SDK. This keeps all observability within the existing Grafana Cloud stack (already used for Prometheus metrics and Loki logs via Alloy).
- **D-02:** Configuration via `VITE_FARO_URL` environment variable, following existing `VITE_*` pattern. Observability is disabled when the env var is absent (local dev).
- **D-03:** Source maps uploaded via `@grafana/faro-rollup-plugin` in the Vite build config so production stack traces are readable.
- **D-04:** No session replay — Faro does not offer it, which is a privacy advantage for a zero-knowledge app.

### Error Boundary

- **D-05:** Add `FaroErrorBoundary` (from `@grafana/faro-react`) wrapping the route tree inside `App.tsx`, below auth/query providers but above routes. Currently no ErrorBoundary exists — unhandled render errors crash to white screen.
- **D-06:** `componentDidCatch` integration: errors flow through Phase 28's `logger.error()` which triggers the Faro transport, rather than making direct Faro API calls from the boundary. Single error path.

### Performance Metrics

- **D-07:** Core Web Vitals (LCP, INP, CLS, TTFB, FCP) captured via Faro's built-in web-vitals v5 collection. No separate `web-vitals` dependency needed.
- **D-08:** SDK-level `perf.ts` Performance API marks remain dev-only per Phase 22 decision. Phase 30 does NOT wire crypto/upload timing into the observability pipeline.
- **D-09:** Web vitals visible in Grafana Cloud Frontend Observability dashboard.

### Privacy & Redaction (Strict)

- **D-10:** `beforeSend` hook on Faro init scrubs ALL error payloads before they leave the browser:
  - Strip fields matching: `privateKey`, `rootFolderKey`, `folderKey`, `fileKey`, `accessToken`, `ipnsPrivateKey`, `teePublicKey`, `userEmail`
  - Strip any `Uint8Array` or hex-string values that look like keys (32+ bytes)
- **D-11:** Disable network request/response body capture entirely — encrypted blobs must never reach the tracking service.
- **D-12:** Disable DOM text in breadcrumbs — file/folder names in the UI are user-specific and could leak metadata.
- **D-13:** User identity in error reports: `publicKey` hex only (already public on-chain). Never `userEmail`.
- **D-14:** Phase 28's `redact()` interceptor handles structured logger context. Faro's `beforeSend` is the second layer for Faro-specific payloads (breadcrumbs, stack frame locals, etc.).

### Logger Integration

- **D-15:** Register a single Faro transport function into Phase 28's logger `transports` array at app initialization. The transport forwards `warn` and `error` level messages to Faro. No modification of the 139 call sites from Phase 28.
- **D-16:** The transport receives `(level, message, context)` and maps to Faro's `pushError()` for errors and `pushLog()` for warnings.

### Deployment

- **D-17:** Add `VITE_FARO_URL` to staging deploy workflow (`.github/workflows/deploy-staging.yml`) pointing to Grafana Cloud Faro collector endpoint.
- **D-18:** Source map upload integrated into the build step of the staging deploy workflow.

### Claude's Discretion

- Exact Faro initialization configuration options (sampling rate, max breadcrumbs, etc.)
- Faro dashboard configuration in Grafana Cloud (auto-provisioned or manual)
- Whether to add a user-visible "Report a problem" button that attaches context to Faro
- Error boundary fallback UI design (simple "Something went wrong" + reload button)

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 28 (Dependency)

- `.planning/phases/28-code-hygiene-logging/28-CONTEXT.md` — Logger transport hook design (D-04, D-05), redaction interceptor (D-03)

### Existing Observability Infrastructure

- `docker/MONITORING.md` — Current Grafana Cloud setup, Alloy config, free tier limits
- `docker/alloy-config.river` — Alloy shipping config (Prometheus + Loki)
- `docker/grafana/dashboards/cipherbox-staging.json` — Existing Grafana dashboard
- `docker/grafana/scripts/provision-alerts.sh` — Alert provisioning infrastructure

### Web App Entry Points

- `apps/web/src/main.tsx` — App bootstrap, DEV-only error capture (lines 8-31), provider tree
- `apps/web/src/App.tsx` — Route tree where ErrorBoundary should wrap
- `apps/web/vite.config.ts` — Vite build config for source map plugin

### Sensitive Data Locations

- `apps/web/src/stores/auth.store.ts` — Holds `accessToken`, `vaultKeypair` (with `privateKey`), `userEmail`
- `apps/web/src/stores/folder.store.ts` — Holds `folderKey`, `ipnsPrivateKey` as Uint8Array
- `apps/web/src/stores/vault.store.ts` — Holds vault keypair data

### Deploy Config

- `.github/workflows/deploy-staging.yml` — Staging deploy, VITE\_\* env var injection (lines 106-112)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- Phase 28 logger with `transports` array and `redact()` interceptor — primary integration point
- Grafana Cloud free tier already active with Alloy + Prometheus + Loki
- `import.meta.env.VITE_*` pattern for build-time config injection
- Staging deploy workflow with env var injection

### Established Patterns

- Vite build with Rollup plugins (`vite.config.ts`)
- Provider tree: StrictMode > WagmiSetup > CoreKitProvider > QueryClientProvider > App > Routes
- No existing ErrorBoundary (confirmed by grep)
- No existing `window.addEventListener('unhandledrejection')` handler
- DEV-only error capture in `main.tsx` via `window.__errorLog` array

### Integration Points

- `apps/web/src/lib/faro.ts` (new) — Faro initialization + beforeSend hook + logger transport registration
- `apps/web/src/App.tsx` — FaroErrorBoundary wrapper around route tree
- `apps/web/vite.config.ts` — Faro source map upload plugin
- `.github/workflows/deploy-staging.yml` — VITE_FARO_URL env var

</code_context>

<specifics>
## Specific Ideas

- Grafana Faro chosen over Sentry because: single vendor (existing Grafana Cloud), no session replay (privacy advantage for ZK app), 50k sessions/month free tier (vs Sentry 5k errors/month), web vitals built-in
- Strict privacy scrubbing: beforeSend strips all sensitive fields, disables network body capture, disables DOM text in breadcrumbs, publicKey-only user identity

</specifics>

<deferred>
## Deferred Ideas

- Session replay — explicitly excluded for privacy. If ever needed, would require a separate privacy review
- Operation-level crypto timing in production — stays dev-only per Phase 22 decision
- "Report a problem" user-facing button — nice-to-have, not in scope
- Sentry migration path — Grafana datasource plugin available if Faro proves insufficient

</deferred>

---

_Phase: 30-web-app-observability_
_Context gathered: 2026-03-28_
