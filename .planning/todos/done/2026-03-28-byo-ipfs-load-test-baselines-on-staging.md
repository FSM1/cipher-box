---
created: 2026-03-28T02:03:43.219Z
title: BYO-IPFS load test baselines on staging
area: testing
files:
  - tests/web-e2e/tests/load-test.spec.ts
  - tests/sdk-e2e/src/fixtures/test-harness.ts
---

## Problem

BYO-IPFS is now deployed to staging, but we have no load test baselines for the BYO configuration. When users bring their own IPFS node, the CipherBox API no longer handles IPFS pinning/fetching — that workload is offloaded to the user's node. We need to measure how many concurrent users the current staging infra can serve when IPFS is offloaded, to understand the capacity gains from BYO adoption.

## Solution

1. Configure load test suite to run against staging (`https://api-staging.cipherbox.cc`) with BYO-IPFS enabled test accounts
2. Run concurrent user ramp-up tests (10, 25, 50, 100 users) with BYO accounts performing typical workflows (upload, download, folder ops)
3. Compare results against non-BYO baselines from the metrics todo to quantify IPFS offload benefit
4. Record key metrics: API response times (p50/p95/p99), error rates, CPU/memory on staging VPS, throughput (ops/sec)
5. Identify the concurrency ceiling — at what user count does the API start degrading without IPFS load?
6. Document findings as baseline reference for infrastructure scaling decisions
