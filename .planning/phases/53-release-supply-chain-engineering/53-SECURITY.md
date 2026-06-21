---
phase: 53-release-supply-chain-engineering
status: secured
threats_total: 6
threats_closed: 6
threats_open: 0
register_authored_at_plan_time: true
audited: 2026-06-20
auditor: gsd-security-auditor
---

# Phase 53 Security — Release & Supply-Chain Engineering

All plan-time threats verified CLOSED. The Phase 53 register was authored at plan
time across the four PLAN.md `<threat_model>` blocks; the auditor verified each
mitigation exists in the committed implementation (read-only, no files modified).

## Threat Register

| Threat | Category | Component | Disposition | Status | Evidence |
| --- | --- | --- | --- | --- | --- |
| T-53-01 | Tampering | mutable action tags | mitigate | CLOSED | All third-party `uses:` SHA-pinned (`@<40-hex> # vX.Y.Z`); 0 unpinned refs. zizmor gate `.github/workflows/zizmor.yml` runs `zizmor .github/workflows/` (CLI, not SARIF action), scoped to `unpinned-uses` via `.github/zizmor.yml`. |
| T-53-02 | Elevation of Privilege | CI job GITHUB_TOKEN | mitigate | CLOSED | Top-level `permissions: {}` deny-all on ci/desktop-e2e/web-e2e/load-test/release-gate; least-privilege job-level blocks on all flagged jobs; zizmor `excessive-permissions` = 0. |
| T-53-03 | Tampering | Cargo.lock vs released crate versions | mitigate | CLOSED | `release-please.yml` `cargo-lock-sync` step (gated `releases_created == 'true'`): `cargo update -p <crate> --precise <ver>` (first-party only) + `git diff --exit-code Cargo.lock` guard. `cargo-workspace` plugin NOT enabled (bug #2517). |
| T-53-04 | Tampering | bot `chore(release)` commit on PR branch | mitigate | CLOSED | `pr-release-preview.yml` `cancel-in-progress: false` self-heal; CLAUDE.md "Release Automation Rules" codifies never-force-push + fetch/rebase discipline. |
| T-53-05 | Tampering | stale `release-as` == manifest | mitigate | CLOSED | 2 stale pins removed (packages/core, packages/crypto); `crates/core` bumped to 0.5.2 (ahead of manifest 0.5.1 — legit pending target). `check-stale-release-as.js` guard exits 1 on any stale pin; currently exits 0. |
| T-53-SC | Tampering | pinact/zizmor tool installs | accept | CLOSED (disposition holds) | No npm/pip/cargo package added to any project manifest (no diff to package.json/Cargo.toml). Tools run one-off in CI/dev only — no Package Legitimacy gate required. |

## Accepted Risks

- T-53-SC: `pinact` (local/dev) and `zizmor` (`pip install` in an ephemeral CI
  runner) are one-off tooling, not project dependencies. No supply-chain surface
  added to the application. Accepted.

## Out-of-scope deferred audits (not threats)

The zizmor gate is scoped to the two supply-chain audits this phase delivers. zizmor
also flags pre-existing code smells (artipacked, template-injection, cache-poisoning,
secrets-inherit, github-app) deferred via `.github/zizmor.yml`. These are existing
conditions outside Phase 53's remit, flagged for a future dedicated hardening pass —
not open threats from this phase.

## Audit Trail

## Security Audit 2026-06-20

| Metric | Count |
| --- | --- |
| Threats found | 6 |
| Closed | 6 |
| Open | 0 |

Verdict: SECURED. All mitigations verified present in the committed tree by an
independent gsd-security-auditor pass.
