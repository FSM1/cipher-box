---
created: 2026-03-28T02:03:43.219Z
title: Run staging metrics baselines with new instrumentation
area: testing
files:
  - tests/web-e2e/tests/journey-timing.spec.ts
---

## Problem

A recent metrics phase added instrumentation across all application layers (API, web, SDK). Some timings and metric values needed updating once deployed to staging — that deployment is now complete. The test scripts (journey-timing, load-test) need to be run against the staging environment to record fresh baselines that reflect the new instrumentation data.

## Solution

1. Run `journey-timing.spec.ts` against staging (`https://app-staging.cipherbox.cc`) to capture baseline performance numbers with the new metrics
2. Run `load-test.spec.ts` against staging to record concurrency/throughput baselines
3. Verify Prometheus metrics endpoint (`/metrics`) returns the newly added counters/histograms
4. Record results as the new baseline reference (update any hardcoded thresholds or baseline files if they exist)
5. Document any metrics that look anomalous compared to pre-instrumentation expectations
