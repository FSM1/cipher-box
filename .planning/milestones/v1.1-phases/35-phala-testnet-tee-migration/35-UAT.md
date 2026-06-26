---
status: complete
phase: 35-phala-testnet-tee-migration
source: 35-VERIFICATION.md (human_verification items)
started: 2026-06-10T21:30:00Z
updated: 2026-06-10T22:05:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Phala Cloud CVM is live and healthy

expected: curl https://011f138783487e4c43ea104cfcbacf817ac4f31b-3001.dstack-pha-prod5.phala.network/health returns {"healthy":true,"mode":"cvm"}
result: skipped
note: Obsolete — superseded by f270d843a "chore(infra): switch staging TEE worker from Phala Cloud to local Docker" (#472, 2026-05-27), which intentionally retired the Phala Cloud CVM for staging (cost reduction). The endpoint is confirmed dead (TLS handshake failure — service decommissioned), which is the expected state post-retirement, not a regression. The CVM was verified live at phase completion per 35-06-SUMMARY; the phase goal (prove the CVM deployment path end-to-end on testnet) was achieved and the infra decision was later reversed for staging. The CVM compose file (apps/tee-worker/docker-compose.phala.yml) remains for production use. See test 3 for verification of the current staging TEE infra.

### 2. GitHub staging environment has PHALA_CLOUD_API_KEY secret and PHALA_TEE_WORKER_URL variable

expected: Both visible in GitHub repo Settings -> Environments -> staging; PHALA_TEE_WORKER_URL matches the CVM endpoint
result: pass
note: Verified via gh api (environments/staging/secrets and /variables): PHALA_CLOUD_API_KEY present in secrets; PHALA_TEE_WORKER_URL present with value exactly matching the expected endpoint. Both are now orphaned — zero references remain in any workflow since #472 removed the deploy-tee-phala job (see Gaps).

### 3. Current staging TEE worker is deployed and running (post-472 equivalent of test 1)

expected: The staging TEE worker (local Docker, simulator mode) deployed by the current pipeline is started and serving on the staging VPS
result: pass
note: Verified via the deploy evidence chain — tag-staging run 26481149698 (staging-20260526-release-2, all 15 jobs success); Deploy-to-Staging-VPS job logs show "Container cipherbox-staging-tee-worker-1 Started" with image ghcr.io/fsm1/cipherbox-tee-worker:staging-20260526-release-2 and TEE*WORKER_URL=http://tee-worker:3001; live staging API (https://api-staging.cipherbox.cc/health) reports version 0.37.1, exactly matching apps/api at the deployed tag (46d0668cc), confirming staging runs the post-472 stack. Compose defines a healthcheck and restart unless-stopped for the service. The identical simulator code path was exercised live (health, connection-test, migration, republish key validation) during phase 21 UAT on 2026-06-10. Current-moment container health on the VPS is not externally reachable (port 3001 internal-only; API initializeFromTee logs-but-does-not-throw on worker failure) — checkable via Grafana Cloud (cipherbox.grafana.net, cipherbox_tee*\* metrics) or SSH if ever in doubt.

## Summary

total: 3
passed: 2
issues: 0
pending: 0
skipped: 1
blocked: 0

## Gaps

- truth: 'CI configuration contains only secrets/variables that are consumed by workflows'
  status: not-applicable
  reason: 'PHALA_CLOUD_API_KEY (secret) and PHALA_TEE_WORKER_URL (variable) remain configured in the GitHub staging environment but nothing references them — #472 removed the deploy-tee-phala job, the only consumer. The API key is a live credential for a retired service lingering in CI config.'
  severity: minor
  test: 2
  root_cause: '#472 (f270d843a) removed the workflow consumers but did not clean up the GitHub environment entries (not version-controlled, easy to miss in a code-only PR).'
  resolution: 'Marked not-applicable 2026-06-11 (audit-fix F-08): Phala credits are expected, which would bring back the Phala Cloud staging TEE infra — the entries stay inert intentionally and will be consumed again when the deploy-tee-phala path returns.'
  artifacts:
  - path: 'GitHub repo Settings -> Environments -> staging'
    issue: 'orphaned PHALA_CLOUD_API_KEY secret and PHALA_TEE_WORKER_URL variable'
    missing:
  - 'Delete both entries (or revoke the Phala API key first if the account still exists)'
    debug_session: ''

- truth: 'ENVIRONMENTS.md accurately documents the staging TEE worker infrastructure'
  status: failed
  reason: 'ENVIRONMENTS.md still documents staging TEE as "Phala Cloud CVM (production infra, free tier)" (lines 24, 430, and the entire section at 479-545 including TEE_WORKER_URL=https://{app-id}-3001.dstack-prod{N}.phala.network), contradicting the deployed reality since #472: local Docker container in simulator mode on the staging VPS, TEE_WORKER_URL=http://tee-worker:3001.'
  severity: minor
  test: 1
  root_cause: '#472 changed the staging TEE infra but only updated deploy-staging.yml and docker-compose.staging.yml; CLAUDE.md was refreshed later (#476) but .planning/ENVIRONMENTS.md was missed.'
  artifacts:
  - path: '.planning/ENVIRONMENTS.md'
    issue: 'staging TEE rows/sections describe the retired Phala Cloud CVM deployment'
    missing:
  - 'Update staging TEE references to local Docker simulator on VPS; keep Phala Cloud CVM content under the production section only'
    debug_session: ''
    resolution: 'Fixed in b15cf2748 - ENVIRONMENTS.md staging TEE section reworked around the Docker simulator, CVM identity warning moved to production, fictional TEE env vars replaced with real ones; stale claims in codebase STACK/STRUCTURE/ARCHITECTURE/CONCERNS/INTEGRATIONS docs also corrected'

## Environment Notes

Both original human items concerned external state and were verified remotely:
GitHub environment config via gh api (note: variables endpoint paginates at 10
by default — use per_page=100; PHALA_TEE_WORKER_URL was on page 2), CVM
endpoint via direct curl (TLS handshake failure = decommissioned), staging
deploy state via gh run logs for run 26481149698 and the live staging API
/health version match. No staging credentials were needed or used.
