---
created: 2026-01-21T00:08
title: Add local IPFS node to Docker stack for testing
area: api
files:
  - apps/api/src/ipfs/ipfs.service.ts
  - docker-compose.yml
---

## Problem

Currently the backend relies exclusively on Pinata for IPFS operations. This creates a dependency on external services for integration and E2E testing, making tests:

- Slower (network latency to Pinata)
- Less reliable (subject to rate limits, network issues)
- Potentially costly (API usage during test runs)
- Not runnable offline

A local IPFS node in the Docker stack would enable isolated, fast, and reliable testing.

## Solution

Consider abstracting the IPFS layer to support both:

1. **Local IPFS node** - For development and testing (via Docker)
2. **Pinata** - For production

Approach options:

- **Option A**: Use standard IPFS HTTP RPC methods at the API level. Most pinning service providers (Pinata, Infura, etc.) expose authenticated HTTPS IPFS API endpoints that are compatible with the standard IPFS HTTP API. This would allow swapping backends via configuration.

- **Option B**: Create an IPFS adapter interface with `LocalIpfsAdapter` and `PinataAdapter` implementations.

Option A is likely simpler since it leverages the standard IPFS HTTP API that Pinata already supports, requiring only endpoint/auth configuration changes between environments.

Docker addition would be something like:

```yaml
ipfs:
  image: ipfs/kubo:latest
  ports:
    - '5001:5001' # API
    - '8080:8080' # Gateway
```
