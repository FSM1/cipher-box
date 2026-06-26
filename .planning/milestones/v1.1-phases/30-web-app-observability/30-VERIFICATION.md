---
status: passed
phase: 30-web-app-observability
verified: 2026-03-28
---

# Phase 30: Web App Observability - Verification

## Phase Goal

Errors and performance issues in the deployed web app are captured, tracked, and alertable rather than lost to console.error.

## Must-Have Verification

### Plan 30-01: Grafana Faro SDK Initialization with Privacy Scrubbing

| #   | Must-Have                                               | Status | Evidence                                                                                                                             |
| --- | ------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| 1   | @grafana/faro-web-sdk and @grafana/faro-react installed | PASS   | Present in apps/web/package.json dependencies                                                                                        |
| 2   | Faro initialization module at apps/web/src/lib/faro.ts  | PASS   | File exists with initFaro, beforeSend, scrubObject                                                                                   |
| 3   | beforeSend strips all 8 sensitive keys                  | PASS   | SENSITIVE_KEYS set contains all: privateKey, rootFolderKey, folderKey, fileKey, accessToken, ipnsPrivateKey, teePublicKey, userEmail |
| 4   | beforeSend strips hex-encoded keys (64+ hex chars)      | PASS   | HEX_KEY_PATTERN regex /^[0-9a-fA-F]{64,}$/                                                                                           |
| 5   | beforeSend strips Uint8Array-like values                | PASS   | ArrayBuffer.isView check + buffer/byteLength duck-type check                                                                         |
| 6   | Network body capture disabled                           | PASS   | captureConsole: false, no explicit body capture enabled                                                                              |
| 7   | User identity set to publicKey only                     | PASS   | setFaroUser(publicKey) sets id only, email stripped in beforeSend                                                                    |
| 8   | Faro disabled when VITE_FARO_URL absent                 | PASS   | initFaro() returns undefined early if !faroUrl                                                                                       |
| 9   | initFaro() called from main.tsx before React render     | PASS   | Called after polyfills/api-config, before StrictMode                                                                                 |

### Plan 30-02: FaroErrorBoundary and Fallback UI

| #   | Must-Have                                           | Status | Evidence                                                           |
| --- | --------------------------------------------------- | ------ | ------------------------------------------------------------------ |
| 1   | FaroErrorBoundary wraps route tree in App.tsx       | PASS   | App.tsx: FaroErrorBoundary wrapping AppRoutes                      |
| 2   | ErrorFallback shows "Something went wrong"          | PASS   | ErrorFallback.tsx with h1 title                                    |
| 3   | ErrorFallback includes reload button                | PASS   | window.location.reload() onClick                                   |
| 4   | ErrorFallback matches CipherBox dark/terminal style | PASS   | Uses --color-background, --color-green-primary, --font-family-mono |
| 5   | Works when Faro not initialized (local dev)         | PASS   | FaroErrorBoundary acts as standard ErrorBoundary without Faro      |

### Plan 30-03: Source Map Upload and Staging Deploy Configuration

| #   | Must-Have                                              | Status | Evidence                                                                               |
| --- | ------------------------------------------------------ | ------ | -------------------------------------------------------------------------------------- |
| 1   | @grafana/faro-rollup-plugin installed as devDependency | PASS   | Present in apps/web/package.json devDependencies                                       |
| 2   | Vite build conditionally adds Faro plugin              | PASS   | vite.config.ts: conditional spread with faroUrl && faroApiKey && mode === 'production' |
| 3   | Source maps uploaded but not served to browser         | PASS   | sourcemap: 'hidden', keepSourcemaps: false                                             |
| 4   | VITE_FARO_URL in staging deploy workflow               | PASS   | 4 occurrences in deploy-staging.yml (web + 3 desktop builds)                           |
| 5   | GRAFANA_FARO_API_KEY documented as required secret     | PASS   | Used as ${{ secrets.GRAFANA_FARO_API_KEY }} in all build steps                         |

### Plan 30-04: Logger Transport Integration and User Identity Binding

| #   | Must-Have                                     | Status | Evidence                                                               |
| --- | --------------------------------------------- | ------ | ---------------------------------------------------------------------- |
| 1   | Faro transport function exported              | PASS   | registerFaroTransport in faro.ts                                       |
| 2   | Transport maps error -> pushError             | PASS   | faro.api.pushError(error, ...) in transport                            |
| 3   | Transport maps warn -> pushLog                | PASS   | faro.api.pushLog([message], { level: LogLevel.WARN })                  |
| 4   | Transport does NOT forward debug/info         | PASS   | Only error and warn branches, comment confirms                         |
| 5   | User publicKey set on Faro after auth         | PASS   | setFaroUser(publicKey) in completeBackendAuth and session restore      |
| 6   | User cleared from Faro on logout              | PASS   | clearFaroUser() in both logout success and error paths (3 occurrences) |
| 7   | No modification to existing logger call sites | PASS   | No changes to any file except useAuth.ts and faro.ts                   |

## Automated Checks

| Check                                 | Result |
| ------------------------------------- | ------ |
| TypeScript compilation (tsc --noEmit) | PASS   |
| Vite build (no FARO env vars)         | PASS   |
| ESLint/Prettier (via lint-staged)     | PASS   |

## Notes

- Phase 28 (logger module) has not been executed yet. The `registerFaroTransport` function is ready but the `registerFaroTransport(logger.transports)` call in main.tsx is deferred until the logger module ships.
- GitHub environment variables VITE_FARO_URL, GRAFANA_FARO_API_KEY, and GRAFANA_STACK_ID need to be configured in the staging environment before Faro will be active in staging builds.

## Human Verification Items

None required -- all functionality is infrastructure/SDK wiring that can be verified through static analysis and build checks. Runtime verification will happen when staging environment variables are configured and a staging deploy is triggered.
