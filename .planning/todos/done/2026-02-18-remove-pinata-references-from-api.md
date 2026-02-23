---
created: 2026-02-18T22:15
title: Remove Pinata references from API server
area: api
files:
  - apps/api/src/**
---

## Problem

The API server still contains references to Pinata as an IPFS gateway/pinning service. All IPFS requests from clients (web and desktop) route through the backend API (`/ipfs/*` endpoints), but the backend itself may still reference Pinata directly. The staging backend is returning 522 errors when trying to fetch content through Pinata's gateway.

Need to audit and remove all Pinata-specific code, configuration, and references from the API server.

## Solution

1. Search `apps/api/` for all Pinata references (gateway URLs, API keys, SDK imports)
2. Replace with the correct IPFS provider or self-hosted gateway
3. Update environment variables and Docker Compose configuration
4. Test IPFS upload/fetch/unpin flows on staging after cleanup
