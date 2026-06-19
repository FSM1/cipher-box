---
created: 2026-03-23T00:38:32.141Z
title: Investigate someguy IPNS routing failure locally
area: infra
files:
  - docker/docker-compose.yml
  - docker/docker-compose.staging.yml
  - apps/api/src/ipns/delegated-routing.client.ts
---

## Problem

Someguy v0.11.1 (latest release) has completely non-functional IPNS endpoints on staging. The `/routing/v1/providers/` endpoint works fine (returns results instantly), but `/routing/v1/ipns/` hangs indefinitely on both PUT and GET — curl times out after 30s with zero bytes received.

This causes every delegated routing publish to fail after 3 retries x 10s timeout. The API falls back to DB cache for resolves, but publishes waste ~30s per attempt. Nearly 2,000 abort errors were observed in a 10-minute window during load testing.

Staging has been reverted to `https://delegated-ipfs.dev` (PR #322) and someguy removed from the compose stack.

## Solution

Reproduce and diagnose locally using the Docker host (<docker-host>) with Kubo v0.40.0:

1. Add someguy v0.11.1 to `docker/docker-compose.yml`
2. Point API `DELEGATED_ROUTING_URL` at `http://<docker-host>:<port>`
3. Test IPNS endpoint directly: `curl --max-time 30 http://<someguy>/routing/v1/ipns/<key>`
4. If it hangs locally too — check someguy GitHub issues for known IPNS bugs, file one if needed
5. If it works locally — investigate staging-specific factors (networking, resource constraints, DNS)
6. Run SDK E2E (83 tests) and load tests to validate end-to-end

Key questions:

- Is this a known someguy bug?
- Does Kubo v0.40.0 (vs v0.34.0 on staging when someguy was deployed) change anything?
- Is someguy's DHT mode (`standard` vs `accelerated`) a factor?
- Are there env vars or config we're missing?
