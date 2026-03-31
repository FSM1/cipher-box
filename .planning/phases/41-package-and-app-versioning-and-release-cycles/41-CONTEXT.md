# Phase 41: Package and App Versioning and Release Cycles - Context

**Gathered:** 2026-03-31
**Status:** Ready for planning

<domain>
## Phase Boundary

Restructure how all monorepo components (apps, JS packages, Rust crates) are versioned and released. Replace the current "root version cascades to everything" model with precise per-package versioning driven by conventional commit analysis of PR commits before squash merge. Keep Release Please as the release pipeline but use `release-as` injection to override its commit analysis with label-derived version targets.

</domain>

<decisions>
## Implementation Decisions

### Release Signal Source

- **D-01:** Conventional commits within PRs are the source of truth for version bumps. A PR-time GitHub Action analyzes individual PR commits (before squash) to determine per-package bump levels. This captures the granularity that squash merging destroys.
- **D-02:** Release Please is retained as the release pipeline — changelog generation, release PR creation, GitHub Releases, and tagging. It is NOT replaced.
- **D-03:** The post-merge action writes `release-as` overrides into `release-please-config.json` to force RP to use the label-derived versions instead of its own commit analysis. RP consumes and clears these in the release PR.

### Version Grouping

- **D-04:** All 14+ components version independently. No shared version groups except the API lock group.
- **D-05:** API + TS api-client + Rust api-client are version-locked. One `release:api:*` label bumps all three. The generated clients are structurally bound to the API's OpenAPI spec.
- **D-06:** SDK packages (core, crypto, sdk-core, sdk) each version independently via semver.
- **D-07:** Rust crates (crypto, core, api-client, fuse, sdk) each version independently via semver. No relationship to their TypeScript counterparts' version numbers.
- **D-08:** Web and Desktop apps use monotonic versioning (v1.0, v1.1, v2.0 — major.minor, no patch).
- **D-09:** TEE worker uses semver independently. Version feeds through to Docker image tag.
- **D-10:** Root version becomes a milestone marker only, bumped manually on significant releases. Not tied to any component version.

### Versioning Strategy Per Component Type

- **D-11:** SDK packages and Rust crates: semver (feat=minor, fix=patch, breaking=major).
- **D-12:** API (+ locked clients): semver — communicates contract changes to generated client consumers.
- **D-13:** Web and Desktop: monotonic (simple release counter, major.minor format).
- **D-14:** TEE worker: semver — keeps options open as the service evolves. Docker image tag matches version.

### PR Labels and Auto-Analysis

- **D-15:** A PR-time GitHub Action auto-computes release labels by analyzing individual PR commits: parses conventional commit type, maps changed files to packages via RP config paths, takes highest bump per package.
- **D-16:** Labels are auto-added to the PR for visibility using format `release:component:type` (e.g., `release:sdk-core:feat`).
- **D-17:** Label types: `feat` (minor), `fix` (patch), `perf` (patch), `refactor` (patch), `breaking` (major). Plus `release:none` as an escape hatch.
- **D-18:** Auto-computed labels can be manually overridden by the developer (remove/add labels) before merge.
- **D-19:** The PR release preview is a required CI check — blocks merge if commits touching versioned packages don't follow conventional format.
- **D-20:** Labels are pre-created in the GitHub repo (~70 labels: 14 components × 5 types). Provides autocomplete and prevents typos.

### Dependency Cascade

- **D-21:** Auto-cascade detection at PR time. Action analyzes workspace dependency graph (`pnpm list --json` for JS, `cargo metadata` for Rust) and auto-adds cascade labels for dependents.
- **D-22:** Cascade bump rules: if direct dependency gets major → dependent gets at minimum minor. If minor/patch → dependent gets at minimum patch.
- **D-23:** Cascade labels are auto-added with an explanatory PR comment. Developer can remove if not applicable.
- **D-24:** Only `dependencies` are cascaded, not `devDependencies`.

### Post-Merge Action (release-as Injection)

- **D-25:** On push to main, post-merge action finds the originating PR, reads final labels (auto-computed + any manual overrides).
- **D-26:** Computes target version for each labeled package (current manifest version + bump type).
- **D-27:** Writes `"release-as": "X.Y.Z"` into `release-please-config.json` for each affected package.
- **D-28:** Commits to main: `chore(release): set release targets from PR #N`.
- **D-29:** When multiple PRs merge before RP's release PR is merged, action reads existing `release-as` and takes the higher bump (minor beats patch, etc.).
- **D-30:** RP's release PR consumes `release-as` entries — they're one-shot directives cleared in the release PR itself.

### GitHub Releases and Changelogs

- **D-31:** Batched GitHub Releases — one release per RP run listing all component version bumps. Tag is the root milestone version. Release notes aggregate per-component changes.
- **D-32:** All 14 components maintain individual CHANGELOG.md files.
- **D-33:** Desktop gets a component-specific release tag (`cipherbox-desktop-vX.Y`) for the Tauri auto-updater. Updater JSON published as a release asset on desktop-tagged releases only.

### Staging/Deploy Flow

- **D-34:** Keep current single-tag staging deploy approach. Phased migration: Phase 1 adds change-detection logging (informational only), Phase 2 wires up conditional job skipping later.
- **D-35:** Staging tag format changes to date-based: `staging-YYYYMMDD-release-N` (e.g., `staging-20260331-release-1`). Decoupled from component versions.
- **D-36:** Docker image tags: dual-tagged with component version (`cipherbox-api:0.36.0`) and rolling tag (`cipherbox-api:latest-staging`).

### CI Enforcement

- **D-37:** Path-to-component mapping reads from `release-please-config.json` as single source of truth. Root package excluded from enforcement.
- **D-38:** PR release preview action runs on every PR event (open, synchronize, reopened, labeled, unlabeled). Near-instant execution (~5-10s).
- **D-39:** Auto-exemptions for docs/config/test-only changes. `release:none` label for edge cases.
- **D-40:** Combined workflow: cascade detection + label validation in one PR-time action. Post-merge action handles `release-as` injection.

### Claude's Discretion

- Implementation details of the GitHub Actions scripts (JS vs bash, API pagination, error handling)
- Exact label color scheme for the pre-created labels
- Whether to use a reusable workflow or composite action for shared logic
- RP config structure adjustments (adding apps/tee-worker as separate package entries)

</decisions>

<canonical_refs>

## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Current Release Infrastructure

- `release-please-config.json` — Current RP package configuration, component names, paths, extra-files cascade
- `.release-please-manifest.json` — Current version manifest for all components
- `.github/workflows/release-please.yml` — RP workflow trigger and GitHub App token usage
- `.github/workflows/release-gate.yml` — E2E gate on release PRs, path-based change detection pattern (reusable for staging detection)
- `.github/workflows/deploy-staging.yml` — Staging deployment workflow, tag pattern, per-platform build jobs, Docker image tagging

### Design Input

- `temp/plan-packageVersioningStrategy.prompt.md` — Initial strategy exploration document, Changesets-vs-RP analysis

### Dependency Graph Sources

- `package.json` (root) — pnpm workspace definition
- `pnpm-workspace.yaml` — Workspace package paths
- `Cargo.toml` (root) — Cargo workspace members

### API Client Generation

- `apps/api/package.json` — api:generate script
- `packages/api-client/src/generated/` — Generated TS client from OpenAPI spec
- `crates/api-client/` — Rust API client (hand-structured, mirrors TS client)

</canonical_refs>

<code_context>

## Existing Code Insights

### Reusable Assets

- `release-gate.yml` path-based change detection pattern — reusable for staging detection and PR release preview
- RP config `packages` entries — already define component-to-path mapping for all SDK packages and crates
- GitHub App token pattern in `release-please.yml` — reusable for post-merge action writes to main

### Established Patterns

- RP manifest mode with per-package entries and per-component tags
- `extra-files` for cross-file version propagation (to be removed from root, retained within locked groups)
- Conventional commits enforced via husky commitlint hook (local) — PR commits follow this
- Staging tag-triggered deploys via workflow `on.push.tags` filter

### Integration Points

- `release-please-config.json` — post-merge action writes `release-as`, RP consumes it
- `.release-please-manifest.json` — source of current versions for bump computation
- GitHub PR labels API — auto-add/read labels for release intent
- GitHub PR commits API — source of individual commit analysis before squash
- `tauri.conf.json` + Tauri updater plugin — desktop version and auto-updater JSON

</code_context>

<specifics>
## Specific Ideas

- The user explicitly wants to keep Release Please and not replace it — the CI/release setup just stabilized and is working well
- Precision matters — "otherwise what is the point of all this work" — no approximate bumps
- Staging deploys are "actual releases, not candidates" — hence `release-N` suffix not `rc-N`
- The conventional commits developers already write should be the release signal — no additional manual steps in the normal case
- Labels serve as a visibility/override mechanism, not a primary input

</specifics>

<deferred>
## Deferred Ideas

- Smart dispatch for staging (conditional job skipping based on change detection) — Phase 2 of the staging flow, implement when deploy time becomes a problem
- Spec-anchored API versioning (decouple API, TS client, Rust client versions) — consider when external SDK consumers arrive
- Coordinated 1.0 version milestone — decide when 1.0 is actually on the horizon

</deferred>

---

_Phase: 41-package-and-app-versioning-and-release-cycles_
_Context gathered: 2026-03-31_
