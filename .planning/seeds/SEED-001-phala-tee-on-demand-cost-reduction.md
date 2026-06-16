---
id: SEED-001
status: dormant
planted: 2026-06-16
enriched: 2026-06-16
planted_during: v1.1
trigger_when: when relevant
scope: small-medium
---

# SEED-001: utilize the phala api to programatically turn the TEE on when a refresh is necessary, and turn it off when no TEE workload is present, with the aim of reducing phala costs

## Why This Matters

The production TEE worker does exactly one job: signing IPNS records on the
republish cron. It is otherwise a persistent Express server with no internal
scheduler, woken only when the API's BullMQ cron POSTs `/republish`.

- Cadence: fixed cron `0 */6 * * *` → 4 runs/day (00:00, 06:00, 12:00, 18:00 UTC).
- Per-run duration: up to 2000 due entries → up to 20 sequential TEE batches of 100. Healthy run is well under a minute; pathological fully-degraded run caps ~10 min.
- Freshness deadline: records are signed with a 48h EOL and republished every 6h → 8× safety margin. The hard requirement is that each record be re-signed within 48h or resolvers treat it as expired.

Duty cycle: ~4–10 active minutes/day out of 1440 (**<1%**). The CVM pays always-on
rates to do under 1% work. The economic motivation is real, but see the cost
reality check below — the absolute prize is likely single-digit dollars/month on
one staging-sized CVM.

## Feasibility Findings (from 2026-06-16 understand pass)

### Key continuity — the make-or-break — is favorable

The worker persists **no** private key; keys are deterministically derived per
epoch via dstack `getKey('cipherbox/ipns-republish', epoch-${N})`, bound to the
CVM **app_id**.

- `stop`/`start` preserves app_id → identical `teePublicKey` re-derives. This is the safe primitive.
- The landmine is **destroy + recreate into a new app_id** → every epoch's key changes → all previously ECIES-wrapped IPNS keys become permanently undecryptable. Documented as a CRITICAL rule in `apps/tee-worker/docker-compose.phala.yml` and `.planning/phases/35-phala-testnet-tee-migration/35-RESEARCH.md:185-187`.
- There is **zero attestation/quote verification anywhere in the repo** (grep for `getQuote|attestation|dcap|RA-TLS` → no hits). Clients trust the `teePublicKey` the API serves, so quote-instability across boots is a non-issue today. It would become a blocker only if attestation is ever added.

### Cold-start is irrelevant to the deadline

Even a 20–25 min cold-start (large image, decompression-bound) sits inside the
48h freshness window with ~47h slack and ~5.5h before the next cron. Latency only
matters because it lengthens the billable active window and adds orchestration
(start → poll `/health` ready → POST `/republish` → stop).

### Cost model

- Phala bills per-second, no monthly minimum: small $0.06/hr (~$43/mo), medium $0.12/hr (~$86/mo), large $0.23/hr.
- A STOPPED CVM stops compute charges immediately but **still bills storage** (~$0.10/GB/mo); only DELETE halts storage too.
- GPU TEE has a 24h minimum re-applied each launch → cycling only pays off for CPU/TDX CVMs. Our worker is CPU/TDX, so we are in the favorable class.
- Net ~85–95% compute reduction, bounded below by storage and cold-start duration. Absolute dollar figure unconfirmed (CVM size/disk/image tag not pinned in repo).

## Architecture Options

- **A — Stop/start the same CVM (recommended primitive).** Orchestrator runs `phala cvms start`, polls `/health` until ready, runs batches, then `phala cvms stop`. Preserves app_id → keys safe. Lowest key-continuity risk, modest savings. Still pays storage; needs the API (or a thin scheduler) to own start/stop + readiness gating + the cron→start coupling.
- **B — Destroy/recreate with same app identity.** Removes storage cost too, but high risk: this is the exact path the bricked-keys warning is about. Reject unless storage cost is shown to be material.
- **C — Keep always-on but downsize.** If prod is medium/large, drop to small. Zero new orchestration, zero key risk, captures a chunk of the savings. Strong "do this first" baseline.
- **D — Serverless / scale-to-zero TEE.** Phala has no first-party scale-to-zero or cron CVM feature — any cycling is custom orchestration we build and maintain. A failed `start` becomes a missed republish. Not justified at current scale.

## Recommendation

Sequence by risk-adjusted value:

1. Downsize the always-on CVM to `small` if it isn't already (Option C) — most of the dollars, zero risk, zero new infra.
2. Two ~30-min derisking spikes before any build: (a) on a throwaway TDX CVM, derive `getKey()` → `stop`→`start` → re-derive, assert identical `teePublicKey`; (b) measure real `phala cvms start`→`/health`-ready time and whether `start` re-pulls.
3. If both spikes pass → Option A (stop/start) behind the existing DB-backoff safety net.
4. Reject B and D at current scale.

## When to Surface

Trigger: when relevant. Surfaces during `/gsd-new-milestone` when the milestone
scope matches TEE / republishing / infra-cost work.

## Scope Estimate

Small–medium. Option C is a config change (near-zero). The spikes are ~30 min
each. Option A is a bounded feature: a start→poll-health→republish→stop sequence
in the API/scheduler, Phala API credentials wired into the service (none exist in
CI today), and explicit failure handling. The DB backoff state machine already
degrades a missed wake gracefully within the 48h window, which caps the blast
radius.

## Open Questions / Spikes Before Committing

1. **Key-continuity spike (blocking):** derive `getKey()` for an epoch, `stop`→`start`, re-derive, assert identical `teePublicKey`. The one true make-or-break check.
2. **Cold-start measurement:** time `phala cvms start` → `/health` ready for our actual image; note whether `start` re-pulls.
3. **Disk/storage footprint + CVM size:** `phala cvms get` for prod → size, disk GB, image tag. Turns the cost model from estimate into a number.
4. **Prod-vs-staging CVM identity:** the prod compose is named `cipherbox-tee-staging` with `CIPHERBOX_ENVIRONMENT=staging`. Confirm whether a distinct production CVM exists or this staging-named one IS production — don't cycle the wrong one.
5. **Orchestration ownership + failure mode:** decide who calls start/stop (API service vs external scheduler) and make the missed-wake behavior explicit (DB backoff: retrying → stale after 10 fails, within the 48h margin).
6. **Active-epoch delivery:** `TEE_CURRENT_EPOCH` is required per the worker README but set in neither compose file — how the active epoch reaches the production CVM is not captured in the repo. Resolve before any lifecycle automation.

## Breadcrumbs

- `apps/tee-worker/src/services/tee-keys.ts` — per-epoch deterministic key derivation (HKDF seed in simulator, dstack `getKey()` bound to app_id in CVM mode).
- `apps/tee-worker/docker-compose.phala.yml` — production CVM config; inline CRITICAL rule against delete-and-recreate; manual `phala deploy` provisioning.
- `apps/tee-worker/src/routes/republish.ts`, `apps/tee-worker/src/services/ipns-signer.ts` — in-enclave decrypt/sign, 48h record lifetime.
- `apps/api/src/republish/` — BullMQ `0 */6 * * *` cron, batch-of-100 dispatch, DB backoff state machine (retrying → stale after 10 fails).
- `apps/api/src/tee/tee.service.ts`, `apps/api/src/tee/tee-key-state.service.ts` — API↔worker HTTP boundary (`TEE_WORKER_URL` + bearer `TEE_WORKER_SECRET`), `teePublicKey`/keyEpoch persistence and 4-week grace rotation.
- `docs/DEPLOYMENT.md:145-149`, `docs/ARCHITECTURE.md:225-256` — TEE/Phala deployment topology.
- `CLAUDE.md` — "TEE Republishing: TEE worker republishes IPNS every 6 hours — Phala Cloud CVM in production"; "Key Epochs: TEE public keys rotate with 4-week grace period".

## Notes

Captured via one-shot seed capture; enriched 2026-06-16 from a four-agent
understand pass (republish subsystem, TEE key lifecycle, deployment topology,
Phala lifecycle API). No architecture changed — the brief lives here until a
TEE/infra-cost milestone surfaces it.

Project memory: `project-phala-credits-expected` — staging TEE may return to Phala
Cloud; the inert `PHALA_*` GitHub staging env entries are intentional, not
orphaned.
