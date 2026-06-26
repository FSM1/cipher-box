# Phase 35: Phala Testnet TEE Migration - Research

**Researched:** 2026-03-29
**Domain:** Phala Cloud CVM deployment, dstack SDK, TEE key derivation, CI/CD pipeline
**Confidence:** MEDIUM

## Summary

This phase replaces the staging TEE simulator (HKDF-based deterministic keys from a fixed seed) with a real Phala Cloud CVM deployment using hardware-backed key derivation via the dstack SDK. The existing TEE worker code already has a CVM code path (`TEE_MODE=cvm`) that dynamically imports `@phala/dstack-sdk` and calls `DstackClient.getKey()`, so the application-level code changes are minimal. The primary work is infrastructure: deploying the Docker image to Phala Cloud, updating the staging docker-compose to remove the local `tee-worker` container, pointing the staging API's `TEE_WORKER_URL` to the Phala Cloud CVM endpoint, adding `@phala/dstack-sdk` as a real dependency (currently only type declarations exist), updating the CI/CD pipeline for automated CVM updates, and verifying end-to-end republish cycles work with hardware-derived keys.

A critical finding is that the existing type declaration for `DstackClient.getKey()` returns `{ asUint8Array(): Uint8Array }`, but the current SDK v0.5.7 returns `{ key: Uint8Array }` directly. The existing code at `tee-keys.ts:48` uses `keyResult.asUint8Array().slice(0, 32)` which may need updating depending on the actual API surface of the installed SDK version. This must be verified during implementation.

**Primary recommendation:** Deploy the existing TEE worker Docker image to Phala Cloud as a single-container CVM using the `phala` CLI, update the Phala CVM docker-compose to use `/var/run/dstack.sock` (replacing the legacy `/var/run/tappd.sock`), install `@phala/dstack-sdk` as a real dependency, verify the `getKey()` return type against the installed version, update staging env vars to point to the Phala Cloud endpoint, and add a CI/CD step to the deploy-staging workflow for automated CVM image updates.

## Project Constraints (from CLAUDE.md)

- TEE Republishing: Phala Cloud (primary) / AWS Nitro (fallback) for automatic IPNS republishing every 3 hours
- Key Epochs: TEE public keys rotate with 4-week grace period for seamless migration
- Always encrypt `ipnsPrivateKey` with TEE public key before sending for republishing
- TEE decrypts IPNS keys in hardware only, signs, and immediately discards
- Never push directly to `main` -- feature branch + PR workflow
- Conventional Commits enforced via commitlint
- After modifying API endpoints/DTOs/controllers, run `pnpm api:generate`
- Staging deploys triggered by `staging-v*` tags

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
| --- | --- | --- | --- |
| @phala/dstack-sdk | 0.5.7 | Hardware-backed key derivation inside CVM | Official Phala SDK for CVM applications |
| phala (CLI) | 1.1.13 | CLI for CVM deployment and management | Official Phala Cloud deployment tool |
| express | ^4.21.0 | TEE worker HTTP server | Already in use |
| eciesjs | ^0.4.16 | ECIES encryption/decryption | Already in use |
| @noble/secp256k1 | ^2.2.3 | secp256k1 key derivation | Already in use |

### Supporting

| Library | Version | Purpose | When to Use |
| --- | --- | --- | --- |
| @noble/hashes | ^1.7.0 | HKDF for simulator fallback | Already in use, keep for local dev |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
| --- | --- | --- |
| Phala Cloud managed CVM | Self-hosted dstack on bare metal TDX | Self-hosted requires TDX hardware, Ubuntu 24.04, building 3 components (KMS, gateway, VMM) -- massive overhead for a staging environment |

**Installation:**
```bash
# In tee-worker directory -- add dstack SDK as real dependency
cd tee-worker && npm install @phala/dstack-sdk@^0.5.7

# Install Phala CLI globally (for CI/CD and manual deployment)
npm install -g phala
```

**Version verification:** `@phala/dstack-sdk` verified at 0.5.7 on npm (2026-03-29). `phala` CLI verified at 1.1.13.

## Architecture Patterns

### Current TEE Worker Architecture (unchanged)

```
tee-worker/
  src/
    index.ts              # Express server entry point
    middleware/
      auth.ts             # Bearer token shared-secret auth
    routes/
      health.ts           # GET /health (public)
      public-key.ts       # GET /public-key?epoch=N
      republish.ts        # POST /republish (batch IPNS signing)
      migrate.ts          # POST /migrate (BYO CID migration)
      connection-test.ts  # POST /connection-test (SSRF-safe IPFS probe)
    services/
      tee-keys.ts         # Key derivation (simulator|cvm mode switch)
      key-manager.ts      # ECIES decrypt with epoch fallback
      ipns-signer.ts      # Ed25519 IPNS record signing
      migration-worker.ts # Pin migration between providers
      ssrf-validation.ts  # URL/DNS SSRF protection
    types/
      dstack-sdk.d.ts     # Type stubs for @phala/dstack-sdk
```

### Pattern 1: CVM Deployment via docker-compose

**What:** Phala Cloud deploys CVM from a docker-compose.yml file. All containers in one compose file run inside the same CVM with secure inter-service communication.

**When to use:** Deploying TEE worker to Phala Cloud.

**Example:**
```yaml
# tee-worker/docker-compose.phala.yml
services:
  tee-worker:
    image: ghcr.io/${GITHUB_REPOSITORY_OWNER}/cipherbox-tee-worker:${TAG:-latest}
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    ports:
      - '3001:3001'
    restart: unless-stopped
    environment:
      - NODE_ENV=production
      - PORT=3001
      - TEE_MODE=cvm
      - CIPHERBOX_ENVIRONMENT=staging
      - TEE_WORKER_SECRET=${TEE_WORKER_SECRET}
```
Source: [Phala Cloud Docker Compose Deployment](https://docs.phala.com/phala-cloud/phala-cloud-user-guides/create-cvm/create-with-docker-compose)

### Pattern 2: CI/CD Automated CVM Update

**What:** GitHub Actions workflow builds and pushes Docker image, then uses `phala deploy` CLI to update the CVM.

**When to use:** On every staging deployment tag push.

**Example:**
```yaml
# Addition to deploy-staging.yml
deploy-tee-phala:
  name: Deploy TEE Worker to Phala Cloud
  needs: [build-tee]
  runs-on: ubuntu-latest
  environment: staging
  steps:
    - uses: actions/checkout@v4
    - run: npm install -g phala
    - run: |
        sed -i "s|\${TAG}|${{ env.DEPLOY_TAG }}|g" tee-worker/docker-compose.phala.yml
        phala deploy -c tee-worker/docker-compose.phala.yml -n cipherbox-tee-staging --wait
      env:
        PHALA_CLOUD_API_KEY: ${{ secrets.PHALA_CLOUD_API_KEY }}
```
Source: [Phala Cloud CI/CD Pipeline](https://docs.phala.com/phala-cloud/phala-cloud-cli/ci-cd-automation/setup-a-ci-cd-pipeline)

### Pattern 3: Staging API Points to External TEE Endpoint

**What:** Instead of `http://tee-worker:3001` (Docker internal network), the API uses the Phala Cloud public HTTPS endpoint.

**When to use:** After CVM is deployed and has a public endpoint.

**Example:**
```
# In staging .env
TEE_WORKER_URL=https://{app-id}-3001.dstack-prod{N}.phala.network
```

### Anti-Patterns to Avoid

- **Installing @phala/dstack-sdk outside CVM:** The SDK communicates with `/var/run/dstack.sock` which only exists inside a CVM. In simulator mode, the SDK is not used at all (HKDF path runs instead). Do not add it to the base Dockerfile in a way that fails the build -- use dynamic import (already done).
- **Hardcoding the Phala endpoint URL:** The CVM endpoint URL contains an app-id hash and region. Store it as a GitHub environment variable, not in code.
- **Removing simulator mode:** Keep TEE_MODE=simulator for local development and CI tests. The simulator path is critical for developer experience.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
| --- | --- | --- | --- |
| TEE key derivation | Custom KDF inside CVM | `DstackClient.getKey()` | Hardware-backed, deterministic, attested -- cannot replicate in software |
| CVM deployment | Manual SSH + Docker on TDX host | `phala` CLI + Phala Cloud | Handles attestation, networking, TLS, key management automatically |
| TLS for TEE endpoint | Manual cert provisioning | Phala Cloud auto-TLS | CVM endpoints get automatic HTTPS via dstack-gateway |
| Attestation verification | Parse TDX quotes manually | Phala Cloud attestation API | `https://cloud-api.phala.network/api/v1/attestations/verify` |

**Key insight:** Phala Cloud abstracts away the complexity of TDX hardware, KMS setup, guest agent lifecycle, and TLS certificate management. The TEE worker code is unchanged -- only the deployment target and infrastructure configuration change.

## Common Pitfalls

### Pitfall 1: Socket Path Mismatch (dstack.sock vs tappd.sock)

**What goes wrong:** The existing `tee-worker/docker-compose.yml` mounts `/var/run/tappd.sock:/var/run/tappd.sock`. Current dstack OS 0.5.x uses `/var/run/dstack.sock`. Using the wrong path causes `DstackClient` to fail with connection errors.
**Why it happens:** The socket path changed between dstack OS 0.3.x (`tappd.sock`) and 0.5.x (`dstack.sock`). The existing compose file was written for an older version.
**How to avoid:** Use `/var/run/dstack.sock:/var/run/dstack.sock` in the Phala CVM docker-compose. The `DstackClient()` constructor with no arguments defaults to `/var/run/dstack.sock`.
**Warning signs:** `Error: connect ENOENT /var/run/dstack.sock` in TEE worker logs.

### Pitfall 2: SDK Return Type Change (asUint8Array vs key property)

**What goes wrong:** The existing code at `tee-keys.ts:48` calls `keyResult.asUint8Array().slice(0, 32)`. If the SDK v0.5.7 changed the return type to `{ key: Uint8Array }`, this will throw `keyResult.asUint8Array is not a function`.
**Why it happens:** The dstack SDK API evolved from `deriveKey()` with `DeriveKeyResponse.asUint8Array()` to `getKey()` with potentially different return shape.
**How to avoid:** After installing the actual SDK, check the TypeScript types or test with the simulator. Write defensive code: `const raw = 'key' in keyResult ? keyResult.key : keyResult.asUint8Array(); privateKey = raw.slice(0, 32);`
**Warning signs:** Runtime error in CVM mode only (simulator path never imports the SDK).

### Pitfall 3: Epoch Key Drift After CVM Redeploy

**What goes wrong:** If the CVM is deleted and recreated (rather than updated), the `app_id` changes, causing `getKey()` to derive different keys for the same epoch path. All existing ECIES-encrypted IPNS keys become undecryptable.
**Why it happens:** Phala Cloud derives keys from `app_id` which is bound to the CVM identity. A new CVM = new identity = new keys.
**How to avoid:** Always UPDATE the existing CVM (via `phala deploy` with same name), never delete and recreate. Document this as a critical operational constraint.
**Warning signs:** Mass republish failures, "ECIES decryption failed for all available epochs" errors.

### Pitfall 4: TEE Worker Secret Transmission

**What goes wrong:** The `TEE_WORKER_SECRET` shared secret is passed as an environment variable to the CVM. If it's not encrypted during transmission, it could leak.
**Why it happens:** Misunderstanding of Phala Cloud's secret handling.
**How to avoid:** Phala Cloud encrypts environment variables client-side with X25519 and decrypts only inside the TEE. Pass `TEE_WORKER_SECRET` via `phala deploy -e TEE_WORKER_SECRET=...` or in the docker-compose environment section. It is encrypted in transit and at rest outside the CVM.
**Warning signs:** None visible (leak would be silent).

### Pitfall 5: Network Latency on External TEE

**What goes wrong:** The staging API currently communicates with `tee-worker:3001` over Docker internal network (sub-millisecond). Moving to Phala Cloud adds network latency (potentially 50-200ms per request).
**Why it happens:** The TEE is no longer co-located with the API.
**How to avoid:** The republish batch design already batches 100 entries per request, amortizing per-request overhead. Verify the 30-second timeout in `TeeService.fetchWithTimeout()` is sufficient. The success criterion of "< 2x simulator latency per batch" accounts for this.
**Warning signs:** Increased republish batch duration, timeout errors in TEE requests.

### Pitfall 6: GHCR Image Not Accessible from Phala Cloud

**What goes wrong:** Phala Cloud pulls the Docker image from GHCR during CVM creation. If the image is private, the pull fails.
**Why it happens:** GHCR packages default to private visibility in some configurations.
**How to avoid:** Ensure the `cipherbox-tee-worker` package on GHCR is public, or configure GHCR registry credentials in the Phala Cloud deployment. The `phala deploy` command supports private registries.
**Warning signs:** CVM creation fails with "image pull" error.

## Code Examples

Verified patterns from official sources:

### DstackClient Key Derivation (CVM Mode)

```typescript
// Source: https://docs.phala.com/phala-cloud/key-management/get-a-key
// and tee-worker/src/services/tee-keys.ts (existing code, may need update)
import { DstackClient } from '@phala/dstack-sdk';

const client = new DstackClient(); // connects to /var/run/dstack.sock
const keyResult = await client.getKey('cipherbox/ipns-republish', `epoch-${epoch}`);

// VERIFY: SDK v0.5.7 return type -- one of these:
// Option A (older API): keyResult.asUint8Array().slice(0, 32)
// Option B (newer API): keyResult.key.slice(0, 32)
const privateKey = keyResult.key ?? keyResult.asUint8Array();
const secp256k1PrivateKey = privateKey.slice(0, 32);
```

### Phala Cloud CVM Deployment via CLI

```bash
# Source: https://docs.phala.com/phala-cloud/phala-cloud-cli/ci-cd-automation/setup-a-ci-cd-pipeline

# Login (manual API key -- for CI)
export PHALA_CLOUD_API_KEY="your-api-key"

# Initial deployment
phala deploy -c docker-compose.phala.yml -n cipherbox-tee-staging \
  -e TEE_WORKER_SECRET="shared-secret-value" \
  --wait

# Subsequent updates (same name = update, not create)
phala deploy -c docker-compose.phala.yml -n cipherbox-tee-staging --wait

# Check status
phala cvms get cipherbox-tee-staging

# View logs
phala logs --cvm-id cipherbox-tee-staging

# Get attestation report
phala cvms attestation
```

### Updated tee-keys.ts CVM Path

```typescript
// Updated CVM code path with SDK as real dependency
if (mode === 'cvm') {
  const { DstackClient } = await import('@phala/dstack-sdk');
  const client = new DstackClient();
  const keyResult = await client.getKey('cipherbox/ipns-republish', `epoch-${epoch}`);
  // Defensive: support both old and new SDK return types
  const rawKey = ('key' in keyResult && keyResult.key instanceof Uint8Array)
    ? keyResult.key
    : keyResult.asUint8Array();
  privateKey = rawKey.slice(0, 32);
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
| --- | --- | --- | --- |
| `TappdClient` + `deriveKey()` | `DstackClient` + `getKey()` | dstack SDK 0.3.x -> 0.5.x | Class and method rename; return type may differ |
| `/var/run/tappd.sock` | `/var/run/dstack.sock` | dstack OS 0.3.x -> 0.5.x | Socket path change; old path will not exist on new CVMs |
| Manual deployment via dashboard | `phala` CLI with CI/CD support | 2025 | Enables automated staging deploys |
| $20 free credits model | Tiered accounts (Free/Tier1/Tier2/Enterprise) | 2025 | Free tier: 1 CVM, sufficient for staging TEE worker |

**Deprecated/outdated:**

- `TappdClient`: Replaced by `DstackClient` in SDK 0.5.x
- `deriveKey()`: Replaced by `getKey()` in SDK 0.5.x
- `/var/run/tappd.sock`: Legacy socket path, replaced by `/var/run/dstack.sock` in dstack OS 0.5.x
- The existing `tee-worker/docker-compose.yml` references `tappd.sock` -- must be updated

## Open Questions

1. **Exact SDK v0.5.7 Return Type for getKey()**
   - What we know: Older versions returned `DeriveKeyResponse` with `asUint8Array()`. Newer docs show `{ key: Uint8Array }`. Our type declarations use `asUint8Array()`.
   - What's unclear: Whether v0.5.7 returns `key` property, `asUint8Array()`, or both.
   - Recommendation: After installing the real SDK, check the TypeScript types. Write defensive code that handles both. Test with a simple script before deploying.

2. **Phala Cloud Free Tier Adequacy**
   - What we know: Free tier allows 1 CVM. TEE worker is a single lightweight Express server.
   - What's unclear: Whether free tier vCPU/memory (reportedly ~2 vCPU, 2GB RAM) is sufficient, or whether a paid tier is needed.
   - Recommendation: Start with free tier. The TEE worker has minimal resource requirements (no database, no heavy computation). Upgrade if needed.

3. **Key Persistence Across CVM Updates**
   - What we know: `getKey()` is deterministic -- same path always produces same key. Keys are derived from app_id which is tied to CVM identity.
   - What's unclear: Whether `phala deploy` (update) preserves app_id vs `phala cvms delete` + new create.
   - Recommendation: Use `phala deploy` with consistent CVM name for updates. Verify key determinism after first deploy by checking the public key matches expectations. Document as critical operational constraint.

4. **First Deployment Key Epoch Coordination**
   - What we know: The staging API has `tee_key_state` table tracking current epoch (likely epoch 1). Switching from simulator to CVM will produce DIFFERENT keys for the same epoch because the derivation mechanism changes entirely.
   - What's unclear: How to handle the transition -- existing IPNS keys encrypted with simulator epoch 1 public key will not be decryptable by CVM epoch 1 private key.
   - Recommendation: This is the most critical migration concern. Options: (A) Re-enroll all existing IPNS entries with the new CVM public key during migration, (B) bump to a new epoch (epoch 2) on CVM, or (C) wipe and re-create staging republish state. Option C is simplest for staging (not production). Document the production migration path for later.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
| --- | --- | --- | --- | --- |
| Node.js 20+ | TEE worker runtime | Yes (in Docker) | 20-alpine | -- |
| Docker | Building TEE worker image | Yes | -- | -- |
| GHCR | Docker image registry | Yes | -- | -- |
| Phala Cloud account | CVM deployment | Not verified | -- | Must create account + API key |
| phala CLI | CI/CD deploy step | Not installed locally | 1.1.13 (npm) | `npx phala` for one-off usage |
| @phala/dstack-sdk | Key derivation in CVM | Not installed (type stubs only) | 0.5.7 (npm) | Dynamic import already handles absence in simulator mode |
| Phala Cloud free tier | CVM hosting | Not verified | -- | Paid tier ($0.10/GB/month storage, per-second compute) |

**Missing dependencies with no fallback:**

- Phala Cloud account + API key (must be provisioned by user before deployment)

**Missing dependencies with fallback:**

- `phala` CLI (can use `npx phala` instead of global install)
- `@phala/dstack-sdk` (type stubs exist; actual package needed only inside CVM at runtime)

## Validation Architecture

### Test Framework

| Property | Value |
| --- | --- |
| Framework | Jest + manual staging verification |
| Config file | tee-worker: none (uses tsx for dev); API: jest via NestJS |
| Quick run command | `cd tee-worker && npx tsx src/__tests__/ssrf-validation.test.ts` |
| Full suite command | `pnpm --filter api test` (API-side TEE tests) |

### Phase Requirements -> Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
| --- | --- | --- | --- | --- |
| SC-1 | CVM deployed with TEE_MODE=cvm, dstack key derivation | smoke | `curl https://{endpoint}/health` (manual) | N/A (infra) |
| SC-2 | Staging API connects to Phala TEE, completes republish | e2e | Manual staging test: trigger republish, verify IPNS records | N/A (manual) |
| SC-3 | Key epoch init/rotation with CVM keys | integration | `pnpm --filter api test -- tee.service.spec` | Yes |
| SC-4 | Republish latency < 2x simulator baseline | perf | Manual: compare Grafana histogram before/after | N/A (manual) |
| SC-5 | Staging docker-compose has no local tee-worker | unit | `grep -c tee-worker docker/docker-compose.staging.yml` = 0 | N/A (verify) |

### Sampling Rate

- **Per task commit:** Existing API tests pass (`pnpm --filter api test`)
- **Per wave merge:** Manual staging verification (health check, republish trigger)
- **Phase gate:** Full end-to-end republish cycle on staging with CVM-derived keys

### Wave 0 Gaps

- [ ] Phala Cloud account provisioned with API key stored as GitHub secret `PHALA_CLOUD_API_KEY`
- [ ] CVM initially deployed manually via `phala deploy` to establish the CVM identity (app_id)
- [ ] Staging republish schedule entries re-enrolled with new CVM public key (or wiped for fresh start)

## Sources

### Primary (HIGH confidence)

- [Phala Cloud Docker Compose Deployment](https://docs.phala.com/phala-cloud/phala-cloud-user-guides/create-cvm/create-with-docker-compose) -- CVM deployment process
- [Phala Cloud CLI Deployment](https://docs.phala.com/phala-cloud/phala-cloud-user-guides/advanced-deployment-options/start-from-cloud-cli) -- CLI commands and authentication
- [Phala Cloud CI/CD Pipeline](https://docs.phala.com/phala-cloud/phala-cloud-cli/ci-cd-automation/setup-a-ci-cd-pipeline) -- GitHub Actions workflow
- [dstack SDK JS source](https://github.com/Dstack-TEE/dstack/tree/master/sdk/js) -- DstackClient API, socket path, getKey()
- [Phala Cloud Key Management](https://docs.phala.com/phala-cloud/key-management/get-a-key) -- getKey() API, deterministic derivation
- [Phala Cloud FAQs](https://docs.phala.com/phala-cloud/faqs) -- Pricing tiers, resource limits, persistence

### Secondary (MEDIUM confidence)

- [Phala Cloud Attestation](https://docs.phala.com/phala-cloud/attestation/get-attestation) -- Attestation API and verification flow
- [Phala Cloud Production Checklist](https://docs.phala.com/phala-cloud/production-checklist) -- Persistence, secrets, upgrades
- [dstack GitHub README](https://github.com/Phala-Network/dstack) -- Architecture overview, socket path change

### Tertiary (LOW confidence)

- npm version checks for @phala/dstack-sdk (0.5.7) and phala CLI (1.1.13) -- current as of research date but may change

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH -- existing TEE worker code, dstack SDK is well-documented
- Architecture: MEDIUM -- CVM deployment process clear, but SDK return type and key persistence across updates need runtime verification
- Pitfalls: HIGH -- socket path change, key drift, epoch transition are well-understood risks
- CI/CD: HIGH -- Phala Cloud CI/CD docs provide exact GitHub Actions workflow

**Research date:** 2026-03-29
**Valid until:** 2026-04-28 (30 days -- Phala Cloud is stable infrastructure, dstack SDK unlikely to break)
