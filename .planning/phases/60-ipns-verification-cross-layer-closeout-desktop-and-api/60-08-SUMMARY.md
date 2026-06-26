---
phase: 60-ipns-verification-cross-layer-closeout-desktop-and-api
plan: "08"
subsystem: infra/ipns
tags: [cutover, ipns, strict-verify, staging, d11, hard-11, byo]
dependency_graph:
  requires: ["60-01", "60-02", "60-03", "60-04", "60-05", "60-06", "60-07"]
  provides: ["strict-cutover-deployed", "staging-wiped-fresh-bootstrap", "d02-producer-completion"]
  affects: ["apps/web/src/components/settings/StorageTab.tsx", "docs/DEVELOPMENT.md"]
tech_stack:
  added: []
  patterns: ["lockstep cutover (deploy strict code -> wipe -> smoke)", "adversarial closeout verification before phase close"]
key_files:
  created:
    - .planning/phases/60-ipns-verification-cross-layer-closeout-desktop-and-api/60-08-SUMMARY.md
  modified:
    - apps/web/src/components/settings/StorageTab.tsx
    - docs/DEVELOPMENT.md
decisions:
  - "Gate confirmation read from main (where #555 + #566 + #568 merged + released), NOT the stale 56-commit-diverged feat branch — main is the integration source of truth post-squash-merge"
  - "Adversarial closeout verification (4 parallel checks) run before close; it caught a 10th first-publish producer (StorageTab BYO config) that D-02/60-02 missed"
  - "StorageTab BYO storage-config publish fixed to embed sequence 1 on first publish and existing+1 on update — completes D-02 and removes a live post-cutover 400 regression"
  - "macOS Desktop-E2E failure on #555 is the known FUSE-T/SMB cross-client-sync flake (made optional by #560); #566/#568 macOS runs are green, so latest code is clean"
metrics:
  duration: "operator-gated"
  completed: 2026-06-26
requirements_completed: [HARD-11]
---

# Phase 60 Plan 08: D-01/D-12 Lockstep Cutover Summary

**Strict fail-closed IPNS verification is live on staging via the deploy → wipe → smoke lockstep; adversarial closeout verification surfaced and fixed a missed first-publish producer (StorageTab BYO config) that the strict gate would otherwise 400.**

## Performance

- **Duration:** operator-gated (staging cutover performed by maintainer)
- **Completed:** 2026-06-26
- **Tasks:** 2 (Task 1 auto: gate confirmation + doc note; Task 2 human-action: staging cutover)
- **Files modified:** 2 (StorageTab.tsx, DEVELOPMENT.md) + this SUMMARY

## Task 1 — Cross-layer gate confirmation (D-12 pre-gate)

The Phase 60 strict-cutover code (Waves 1–3) is **merged to main and released** via `#555` (strict
fail-closed cutover), `#566` (FUSE publish + desktop vault-init hardening), and `#568` (FUSE share
revoke). Release tags `cipher-box-v0.45.1` / `cipherbox-fuse-v0.10.1` / `@cipherbox/sdk-v0.37.2` /
`@cipherbox/api-v0.44.1` were cut 2026-06-26 after `#568` merged. The five cross-layer gates were
confirmed on the PR-head commits (CI runs on PR heads, not squash-merge commits):

| Gate | Status | Evidence |
| ---- | ------ | -------- |
| Rust workspace (`cargo test`) | green | `Cargo Check, Test & Coverage (Linux)` + `Cargo Check & Test (macOS)` success on `#555`/`#566`/`#568` heads |
| Windows winfsp | green | `Cargo Check & Test (Windows)` success on all three heads (distinct from `Desktop E2E (windows)`, also green) |
| API jest | green | `Test` success on `#555`/`#566` heads; correctly path-skipped on `#568` (FUSE-only) |
| SDK E2E round-trip | green | `SDK E2E Tests` named check success on `#555`/`#566` heads (directly observed, not inferred); path-skipped on `#568` |
| Desktop E2E (dispatch-gated) | green | linux/macos/windows all success on `#566`/`#568` merge commits |

The lone `#555` macOS Desktop-E2E failure is the known FUSE-T/macOS-SMB cross-client-sync flake
(made macOS-optional by `#560`); the two later strict-cutover commits show macOS Desktop-E2E green,
so the latest code is clean.

**Local-dev-DB-wipe guidance** (D-01, RESEARCH Q5) documented as a one-paragraph note under
`docs/DEVELOPMENT.md` → Testing → "Strict IPNS verification — wipe local DB first": developers with
a pre-cutover local DB hold embedded-0 records that now fail strict-verify and must wipe per
`DATABASE_EVOLUTION_PROTOCOL.md` §reset (non-destructive — IPNS keys derive deterministically from
the Web3Auth key).

## Adversarial closeout verification — D-02 gap found + fixed

Before closing, a 4-check adversarial verification ran against current main. Results:

- **Strict fail-closed cutover: confirmed** — no `VerifyError::Legacy`, no skew disjunct, no
  `signatureVerified:false` soft path; `crates/fuse/src/verify.rs` deleted; all Rust/TS/desktop
  resolve sites route through `resolve_ipns_verified`. (Minor: a few stale doc comments still
  describe the removed legacy-allow path — documentation only, captured as a follow-up.)
- **CI gate claims: confirmed** — all three commits merged + released; the five gates green as above.
- **Milestone-unblock recheck: confirmed** — `60-08` was the ONLY incomplete plan across all 45
  v1.1 phases; closing it leaves every phase complete on disk.
- **Embedded-0 producer sweep: REFUTED** — found a **10th first-publish producer** that `60-02`/D-02
  missed: `apps/web/src/components/settings/StorageTab.tsx:184` published the BYO storage-config IPNS
  record with sequence **0** on first save (catch block literally "First publish -- sequence 0"),
  passed verbatim through `createAndPublishIpnsRecord` to `/ipns/publish` → `upsertFolderIpns`'s
  unconditional D-09 gate (`ipns.service.ts:295`, `if (embeddedSeq !== 1n) throw 400`). Post-cutover,
  a BYO-IPFS user's first storage-config save would 400.

**Fix:** `StorageTab.tsx` now embeds `1n` on first publish and `existing + 1n` on update (the latter
also fixes a latent monotonicity bug — the prior code re-sent the stored sequence verbatim). This
completes D-02 (all first-publish producers embed sequence 1) and removes the live regression. The
phase's earlier "all 9 producers" count (60-VERIFICATION truth #6) was off by one; corrected here.

## Task 2 — Staging cutover (D-01/D-12 blocking human checkpoint)

Operator-confirmed ("cutover complete"). The D-12 lockstep order was followed: strict code deployed
to staging → staging DB wiped per `DATABASE_EVOLUTION_PROTOCOL.md` §reset → services restarted →
smoke test. Smoke-test conditions confirmed by the operator:

- 4a — fresh login self-bootstraps a vault whose root folder resolves **strict-verified** (no
  embedded-0 errors).
- 4b — an embedded-0 publish is rejected with **400** (D-03).
- 4c — a fresh post-wipe record passes strict verify; a tampered CID / expired record is rejected (D-07).

## Verification

- All 5 cross-layer gates green (recorded above).
- Staging smoke-test operator-confirmed (4a/4b/4c).
- Local-dev-DB-wipe guidance documented.
- D-02 completed: StorageTab BYO first-publish producer corrected to embed sequence 1.

## Follow-ups (captured, not blocking)

- Clean up stale legacy-allow doc comments in `sdk-core/src/ipns/index.ts` (~207, ~302-303) and
  `crates/api-client/src/ipns.rs` (~320, ~326) — they describe the removed path; code is correct.
</content>
</invoke>
