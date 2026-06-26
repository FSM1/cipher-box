# Phase 28: Code Hygiene & Logging - Discussion Log (Assumptions Mode)

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions captured in CONTEXT.md — this log preserves the analysis.

**Date:** 2026-03-28
**Phase:** 28-Code Hygiene & Logging
**Mode:** assumptions
**Areas analyzed:** Logger Design, Console Replacement Scope, Unpin Failure Visibility, `any` Cast Cleanup, POC Directory Handling

## Assumptions Presented

### Logger Design

| Assumption                                                                             | Confidence | Evidence                                                     |
| -------------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------ |
| Thin wrapper at `lib/logger.ts`, zero dependencies, level filtering via VITE_LOG_LEVEL | Confident  | No existing logging infra, main.tsx uses import.meta.env.DEV |

### Console Replacement Scope

| Assumption                                                                                       | Confidence | Evidence                              |
| ------------------------------------------------------------------------------------------------ | ---------- | ------------------------------------- |
| Replace all 139 console.\* calls (82 error + 27 warn + 18 log + 12 time/timeEnd) across 29 files | Confident  | Grep-verified counts in apps/web/src/ |
| Keep DEV-only global error capture in main.tsx as-is                                             | Confident  | Gated behind import.meta.env.DEV      |

### Unpin Failure Visibility

| Assumption                                                                                     | Confidence | Evidence                                                                                                 |
| ---------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------- |
| Replace 11 .catch(() => {}) on unpinFromIpfs with logger.warn, leave 3 non-unpin catches alone | Confident  | bin.service.ts (4), useFileOperations (1), useFileVersions (2), ReplaceFileDialog (3), useDropUpload (1) |

### `any` Cast Cleanup

| Assumption                                                                     | Confidence | Evidence                                                                                    |
| ------------------------------------------------------------------------------ | ---------- | ------------------------------------------------------------------------------------------- |
| Fix 2 actionable casts in hooks.ts, mark 6 as acceptable (polyfills, DEV-only) | Likely     | Web3AuthMPCCoreKit type exported from core-kit.ts; polyfill casts have no typed alternative |

### POC Directory

| Assumption                                                                              | Confidence | Evidence                                                         |
| --------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------- |
| Delete 00-Preliminary-R&D/poc/ entirely (89 MB committed node_modules, deprecated deps) | Confident  | ESLint already excludes it, single source file superseded by SDK |

## Corrections Made

### Logger Design

- **Original assumption:** Thin wrapper delegating to console.\* with level filtering — no third-party library
- **User correction:** Confirmed custom wrapper after researching pino/browser comparison. Key factors: pino's redaction doesn't work in browser, pino's Sentry integration is Node.js only. Added requirements for structured metadata support `(message, context)` arg order, redact() interceptor for sensitive fields, and transport hook array for Phase 30.
- **Reason:** Pino's main value propositions (redaction, Sentry transport) don't apply in browser context. Custom wrapper provides equivalent functionality at zero bundle cost with full control over privacy-sensitive redaction.

## External Research

- Pino browser bundle: ~8.3 kB min / ~1.5 kB gzip
- Pino `redact` option: Node.js only, does NOT work in browser mode
- Pino `pinoIntegration` (Sentry): Node.js only, requires pino-transport
- Pino browser `transmit.send`: designed for HTTP log shipping, not Sentry's captureException API
