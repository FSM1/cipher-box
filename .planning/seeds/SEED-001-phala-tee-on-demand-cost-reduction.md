---
id: SEED-001
status: dormant
planted: 2026-06-16
planted_during: v1.1
trigger_when: when relevant
scope: unknown
---

# SEED-001: utilize the phala api to programatically turn the TEE on when a refresh is necessary, and turn it off when no TEE workload is present, with the aim of reducing phala costs

## Why This Matters

_To be filled in. Run `/gsd-capture --seed --enrich SEED-001` to add context._

Short version: the production TEE is a Phala Cloud CVM that currently runs continuously and bills for uptime, but its only workload is periodic IPNS republishing (~every 6 hours). Power-cycling the CVM via the Phala API — bring it up only when a republish batch is due, tear it down when the queue is idle — could cut Phala spend substantially while preserving the republish guarantee.

## When to Surface

**Trigger:** when relevant

This seed will surface during `/gsd-new-milestone` when the milestone scope matches (TEE/republishing/infra-cost work).

## Scope Estimate

**Unknown** — run `/gsd-capture --seed --enrich SEED-001` to estimate effort.

## Breadcrumbs

- `apps/api/src/republish/` — republish service, processor, schedule entity, health controller (the 6-hour republish workload that defines when the TEE is actually needed).
- `apps/api/src/tee/` — TEE service (worker public key, key-epoch handling, IPNS key decrypt-and-sign boundary).
- `CLAUDE.md` — "TEE Republishing: TEE worker republishes IPNS every 6 hours — Phala Cloud CVM in production, local Docker (simulator mode) in staging"; "Key Epochs: TEE public keys rotate with 4-week grace period".
- `docs/DEPLOYMENT.md`, `docs/ARCHITECTURE.md` — TEE/Phala deployment topology.
- Open questions to resolve during enrich: Phala API surface for start/stop a CVM + cold-start latency vs the republish deadline; how key-epoch attestation/`teePublicKey` continuity survives a CVM restart; whether the republish scheduler can drive the on/off lifecycle; staging (Docker simulator) vs production (Phala CVM) parity.

## Notes

_Captured via one-shot seed capture. Enrich with trigger, why, and scope at your convenience._

Project memory: [project-phala-credits-expected] — staging TEE may return to Phala Cloud; the inert `PHALA_*` GitHub staging env entries are intentional, not orphaned.
