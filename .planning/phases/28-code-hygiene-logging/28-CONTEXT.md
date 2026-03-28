# Phase 28: Code Hygiene & Logging - Context

**Gathered:** 2026-03-28 (assumptions mode)
**Status:** Ready for planning

<domain>
## Phase Boundary

Production web app uses structured logging instead of raw console.\* calls, unpin failures are visible, type safety gaps are closed, and legacy POC is archived. This phase creates the logging abstraction that Phase 30 (Web App Observability) will hook into — it does NOT add error tracking services, remote log shipping, or monitoring dashboards.

</domain>

<decisions>
## Implementation Decisions

### Logger Design

- **D-01:** Custom thin wrapper at `apps/web/src/lib/logger.ts` (~50 LOC), zero external dependencies. Delegates to `console.*` with level filtering via `VITE_LOG_LEVEL` environment variable.
- **D-02:** Logger accepts structured metadata in natural `(message, context)` arg order: `logger.warn('Unpin failed', { cid, operation })`. This preserves the existing call site pattern and provides rich context for Phase 30.
- **D-03:** Include a `redact()` interceptor that strips sensitive fields (`privateKey`, `rootFolderKey`, `folderKey`, `fileKey`, `accessToken`) from context objects before logging. Privacy-first — logs must never contain decrypted keys or plaintext content.
- **D-04:** Include a `transport` hook array (initially empty) that Phase 30 will wire Sentry/error tracking into. The hook receives `(level, message, context)` for each log call above the configured threshold.
- **D-05:** Level filtering: `debug` (suppressed in production), `info`, `warn`, `error`. Default level: `info` in production, `debug` in dev (`import.meta.env.DEV`).

### Console Replacement Scope

- **D-06:** Replace all 139 `console.*` calls across 29 files in `apps/web/src/` (82 error + 27 warn + 18 log + 12 time/timeEnd). Map: `console.error` -> `logger.error`, `console.warn` -> `logger.warn`, `console.log` -> `logger.debug`, `console.time/timeEnd` -> `logger.debug` with duration context.
- **D-07:** Keep the DEV-only global error capture in `main.tsx` (lines 8-31) as-is — it intercepts `console.error` at the global level and is gated behind `import.meta.env.DEV`.
- **D-08:** Biggest offender: `apps/web/src/lib/web3auth/hooks.ts` (34 calls) — Web3Auth debug logging that leaks SDK state transitions. These should be `logger.debug` level (suppressed in production).

### Unpin Failure Visibility

- **D-09:** Replace 11 `.catch(() => {})` patterns on `unpinFromIpfs` calls with `.catch((err) => logger.warn('Unpin failed', { cid, err }))`. Files: `bin.service.ts` (4), `useFileOperations.ts` (1), `useFileVersions.ts` (2), `ReplaceFileDialog.tsx` (3), `useDropUpload.ts` (1).
- **D-10:** Leave 3 non-unpin `.catch(() => {})` patterns alone: 2x `audioContext.close()` in AudioPlayerDialog.tsx (harmless cleanup), 1x dynamic import fallback in useDropUpload.ts.

### `any` Cast Cleanup

- **D-11:** Fix 2 actionable `as any` casts in `apps/web/src/lib/web3auth/hooks.ts`: replace `coreKit: any` with the exported `Web3AuthMPCCoreKit` type from `core-kit.ts`, and type `loginParams` explicitly.
- **D-12:** Mark 6 remaining `as any` casts as acceptable exceptions: 4 polyfill shims in `polyfills.ts` (no typed alternative for Node.js globals on `Window`), 1 DEV-only in `main.tsx`, 1 DEV-only debug export in `folder.store.ts`.

### POC Directory

- **D-13:** Delete `00-Preliminary-R&D/poc/` entirely from the repository. Contains 89 MB committed `node_modules/`, deprecated `ipfs-http-client@60.0.1`, and a single source file fully superseded by the production SDK. Git history preserves everything. No branch archival — simpler and avoids maintenance.

### Claude's Discretion

- Exact logger module structure (named exports vs class vs singleton)
- ESLint rule to prevent raw `console.*` usage after migration (optional)
- Whether to add `@typescript-eslint/no-explicit-any` enforcement after cleanup

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Codebase Analysis

- `.planning/codebase/CONCERNS.md` -- Documents all tech debt items being addressed (console.log proliferation, silenced unpins, any casts, POC directory)
- `.planning/codebase/CONVENTIONS.md` -- Current frontend patterns and code style conventions

### Source Files (Logger Integration Points)

- `apps/web/src/lib/web3auth/hooks.ts` -- Biggest offender (34 console.\* calls), Web3Auth debug logging
- `apps/web/src/services/bin.service.ts` -- 16 console calls + 4 silenced unpin catches
- `apps/web/src/hooks/useSharedNavigation.ts` -- 11 console calls
- `apps/web/src/components/file-browser/FileBrowser.tsx` -- 10 console calls
- `apps/web/src/hooks/useAuth.ts` -- 9 console calls
- `apps/web/src/polyfills.ts` -- Acceptable `as any` polyfill shims (do not change)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `import.meta.env.DEV` gating pattern already used in `main.tsx` — same pattern for logger level defaults
- Existing `[Module] message` pattern in console calls (e.g., `console.error('[Bin] Failed to unpin')`) — map module prefix to logger context field

### Established Patterns

- Vite environment variables via `import.meta.env` — use `VITE_LOG_LEVEL` for runtime config
- Zustand stores use `.fill(0)` for key zeroing — logger redaction should complement this by stripping keys from log context
- All IPFS unpin calls use `unpinFromIpfs()` from `@cipherbox/sdk-core` — consistent function name makes grep-and-replace straightforward

### Integration Points

- `apps/web/src/lib/logger.ts` (new) — imported by all 29 files currently using console.\*
- Phase 30 will add a transport to `logger.transports` array — no refactoring of call sites needed
- ESLint config at `eslint.config.js` — can add `no-console` rule after migration to prevent regression

</code_context>

<specifics>
## Specific Ideas

- Custom wrapper chosen over pino/browser because pino's redaction does NOT work in browser mode, and pino's Sentry integration is Node.js only — both features that would justify the dependency don't apply
- Logger should feel like a drop-in replacement for console.\* — minimal friction for the 139 call site changes

</specifics>

<deferred>
## Deferred Ideas

- Remote log shipping (Datadog, Loki) — Phase 30 scope if needed
- Error tracking service (Sentry or alternative) — Phase 30
- `no-console` ESLint rule enforcement — can be added as part of this phase or deferred to Phase 30
- Web Worker logging (separate context, needs MessagePort bridge) — out of scope

</deferred>

---

_Phase: 28-code-hygiene-logging_
_Context gathered: 2026-03-28_
