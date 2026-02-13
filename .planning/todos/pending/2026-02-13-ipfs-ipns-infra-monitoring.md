---
created: 2026-02-13T18:00
title: IPFS/IPNS infrastructure monitoring dashboard
area: api
files: []
---

## Problem

No visibility into IPFS/IPNS operational health. Need to monitor:

- Total data pinned (aggregate size across all users)
- Total IPFS pin count / IPNS records
- IPNS republish operations (success/failure rates, latency)
- General ops visibility across all IPFS/IPNS interactions

Currently flying blind on storage growth, republish reliability, and infrastructure costs.

## Solution

TBD — Options include:

- API admin endpoint exposing Pinata usage stats + IPNS record counts from DB
- Prometheus metrics on publish/resolve/pin operations
- Dashboard UI or integration with existing monitoring (Grafana, etc.)
