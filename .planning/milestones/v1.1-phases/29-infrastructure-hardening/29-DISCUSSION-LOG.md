# Phase 29: Infrastructure Hardening - Discussion Log (Assumptions Mode)

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions captured in CONTEXT.md — this log preserves the analysis.

**Date:** 2026-03-28
**Phase:** 29-Infrastructure Hardening
**Mode:** assumptions
**Areas analyzed:** IPNS Unenrollment API, Batch Unenrollment, SDK Integration, Test Login Hardening, Kubo Access Control

## Assumptions Presented

### IPNS Unenrollment API

| Assumption                                                                                               | Confidence | Evidence                                             |
| -------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------- |
| New REST endpoint needed on IpnsController, RepublishService.unenrollIpns() exists but has no HTTP route | Confident  | republish.service.ts:255, folder.service.ts:513 TODO |

### Batch Unenrollment

| Assumption                                                       | Confidence | Evidence                                     |
| ---------------------------------------------------------------- | ---------- | -------------------------------------------- |
| Batch endpoint following publish-batch pattern, max 200 per call | Confident  | Folder deletes cascade to 1000 files per PRD |

### SDK Integration Point

| Assumption                                                                        | Confidence | Evidence                                              |
| --------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------- |
| Wire into SDK deleteItem()/permanentDeleteFromBin(), not legacy folder.service.ts | Likely     | SDK is actual deletion path per useFolderMutations.ts |

### Test Login Hardening

| Assumption                                   | Confidence | Evidence                                        |
| -------------------------------------------- | ---------- | ----------------------------------------------- |
| Already well-guarded, add Grafana alert only | Confident  | test-auth.service.ts:43-56, existing unit tests |

### Kubo Access Control

| Assumption                                                                      | Confidence | Evidence                      |
| ------------------------------------------------------------------------------- | ---------- | ----------------------------- |
| Port 5001 bound to 127.0.0.1 in Docker, add documentation + production approach | Likely     | docker-compose.staging.yml:73 |

## Corrections Made

### Kubo Access Control

- **Original assumption:** Hardening work includes documentation + defining production Kubo ACL approach
- **User correction:** Deferred entirely — current Docker 127.0.0.1 binding is sufficient for staging
- **Reason:** Not a priority given current deployment state
