# Phase 30: Web App Observability - Discussion Log (Assumptions + Discussion)

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions captured in CONTEXT.md — this log preserves the analysis.

**Date:** 2026-03-28
**Phase:** 30-Web App Observability
**Mode:** assumptions + interactive discussion
**Areas analyzed:** Error Tracking Service, Error Boundary, Performance Metrics, Privacy/Redaction, Logger Integration

## Assumptions Presented

### Error Tracking Service

| Assumption                                                | Confidence | Evidence                                                                             |
| --------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------ |
| Use Grafana Faro, sending to existing Grafana Cloud stack | Likely     | Existing Grafana Cloud with Alloy, INTEGRATIONS.md confirms no error tracking exists |

### Error Boundary

| Assumption                                                                         | Confidence | Evidence                                                                        |
| ---------------------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------- |
| Add FaroErrorBoundary wrapping route tree, integrate via Phase 28 logger transport | Confident  | No ErrorBoundary exists (grep returns zero), main.tsx only has DEV-only capture |

### Performance Metrics

| Assumption                                               | Confidence | Evidence                                                                           |
| -------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------- |
| Web vitals via Faro built-in, SDK perf.ts stays dev-only | Likely     | No web-vitals instrumentation exists, Phase 22 explicitly gates perf.ts behind DEV |

### Privacy/Redaction

| Assumption                                                                   | Confidence | Evidence                                                                     |
| ---------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------- |
| Strict scrubbing via beforeSend + Phase 28 redact(), publicKey-only identity | Confident  | 278 sensitive field occurrences across 20 files, zero-knowledge architecture |

### Logger Integration

| Assumption                                                       | Confidence | Evidence                                               |
| ---------------------------------------------------------------- | ---------- | ------------------------------------------------------ |
| Single transport registration into Phase 28 transport hook array | Confident  | Phase 28 CONTEXT D-04 explicitly designed this handoff |

## Discussion: Faro vs Sentry

User requested deep-dive comparison. Research performed by gsd-advisor-researcher agent.

**Key findings:**

- Faro: ~34KB gzip, built-in web vitals, FaroErrorBoundary, source map plugin, 50k sessions/month free, no session replay
- Sentry: ~28KB gzip (errors only), superior error grouping (ML-based), 10+ years maturity, 5k errors/month free, session replay opt-in

**Decision:** Grafana Faro — single vendor, no session replay (privacy), 10x free tier headroom, all observability in one place. Sentry's better grouping matters less for a ~30-file tech demo.

## Discussion: Privacy Strategy

User selected "Strict scrubbing":

- beforeSend scrubs all payloads (sensitive fields, Uint8Array/hex keys)
- Network body capture disabled entirely
- DOM text in breadcrumbs disabled
- User identity: publicKey hex only, never userEmail
- Phase 28 redact() as first layer, Faro beforeSend as second layer

## External Research

- Grafana Faro v2.0 (Nov 2025): ~34KB gzip with React package
- Built-in FaroErrorBoundary component
- @grafana/faro-rollup-plugin for Vite source map upload
- Web vitals v5 built-in collection
- 50k sessions/month on Grafana Cloud free tier
- No session replay capability (confirmed)
- Sentry Grafana datasource plugin available as migration path
