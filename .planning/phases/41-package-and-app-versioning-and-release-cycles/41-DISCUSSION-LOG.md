# Phase 41: Package and App Versioning and Release Cycles - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-31
**Phase:** 41-package-and-app-versioning-and-release-cycles
**Areas discussed:** Release signal source, Version grouping, Staging/deploy flow, CI enforcement

---

## Release Signal Source

### Initial Direction: Changesets vs Release Please

| Option                  | Description                                                  | Selected |
| ----------------------- | ------------------------------------------------------------ | -------- |
| Changesets (replace RP) | Git-tracked changeset files survive squash, mature ecosystem |          |
| Release Please only     | Keep current setup, accept squash limitations                |          |
| Hybrid                  | Changesets for SDKs, RP for apps                             |          |

**User's initial choice:** Changesets

**Pivot moment:** User challenged the Changesets direction after Cargo.toml support gap surfaced. Key insight: "Release Please works, it's just the squash commits that are causing problems." This redirected the entire approach from replacing RP to enriching it.

### Enriching RP with Intent Signals

| Option              | Description                         | Selected    |
| ------------------- | ----------------------------------- | ----------- |
| PR labels           | Labels encode package + bump intent | ✓ (initial) |
| Custom intent files | .release-intent/ files per PR       |             |
| Full Changesets     | Accept ecosystem dependency         |             |

**User's choice:** PR labels — zero files to manage, visible in PR UI.

### Final Evolution: Auto-Analysis

**Key insight from user:** "If we analyze the PR pre-merge, we can skip the manual label part entirely, as all the commits should follow conventional commitlint."

| Option                                | Description                                                              | Selected |
| ------------------------------------- | ------------------------------------------------------------------------ | -------- |
| Manual labels                         | Dev adds labels, CI validates                                            |          |
| Auto-analysis + labels for visibility | Action reads PR commits, auto-computes labels, manual override available | ✓        |
| Skip labels entirely                  | Compute bumps silently, no labels                                        |          |

**User's choice:** Auto-analysis with labels for visibility and override capability.

### RP Integration: release-as Injection

| Option                  | Description                                      | Selected |
| ----------------------- | ------------------------------------------------ | -------- |
| RP release-as injection | Post-merge action writes release-as to RP config | ✓        |
| Custom RP plugin        | TS plugin makes RP label-driven                  |          |
| Full Changesets         | Replace RP entirely                              |          |
| Accept imprecision      | Let RP path-match with squash commit type        |          |

**User's choice:** release-as injection — precise, no plugin development, RP stays intact.
**User's note:** "I would really prefer to be precise about this as otherwise what is the point of all this work."

---

## Version Grouping

### App Versioning

| Option                           | Description                               | Selected |
| -------------------------------- | ----------------------------------------- | -------- |
| Shared app version               | web + desktop + API all share one version |          |
| Independent app versions         | Each app versions separately              |          |
| Apps share, packages independent | Apps locked, packages free                |          |

**User's choice:** All components version independently. User reconsidered the shared approach: "Initially I thought keeping web/api/desktop versions in sync made sense, but I am reconsidering."

### API + Client Versioning

| Option                    | Description                                 | Selected |
| ------------------------- | ------------------------------------------- | -------- |
| Locked versions           | API + both clients always share version     | ✓        |
| API leads, clients follow | Separate versions with compatibility matrix |          |
| Spec-anchored             | OpenAPI spec version as shared contract     |          |

**User's choice:** Locked versions. User noted that "all API consumers are consuming the API through the api-client based on the version in the openapi.json."

**Detailed analysis provided:** Locked optimizes for simplicity (one number, zero confusion, phantom bumps). Spec-anchored optimizes for semantic accuracy (each version means something, but more complex mental model). User chose simplicity with note that migration to spec-anchored is straightforward later.

### Rust Crate Versioning

| Option                  | Description                                | Selected |
| ----------------------- | ------------------------------------------ | -------- |
| Fully independent       | No relationship to TS counterpart versions | ✓        |
| Loosely coupled         | Major bumps mirror across languages        |          |
| Keep current divergence | Don't try to relate them                   |          |

### Root Version

| Option                   | Description                                    | Selected |
| ------------------------ | ---------------------------------------------- | -------- |
| Remove root version      | No monorepo-level version                      |          |
| Root = release milestone | Human-facing milestone marker, bumped manually | ✓        |
| Root tracks highest app  | Loosely coupled to highest app version         |          |

### Component Versioning Strategies

| Component     | Strategy                | Rationale                                       |
| ------------- | ----------------------- | ----------------------------------------------- |
| Web, Desktop  | Monotonic (major.minor) | Release counter, not semver                     |
| API + clients | Semver (locked)         | Contract-based, generated clients bound to spec |
| SDK packages  | Semver (independent)    | Library consumers need compatibility signals    |
| Rust crates   | Semver (independent)    | Separate implementations, different pace        |
| TEE worker    | Semver                  | Keeps options open, Docker tag matches          |
| Root          | Milestone               | Manual, significant releases only               |

### GitHub Releases

| Option                 | Description                                  | Selected |
| ---------------------- | -------------------------------------------- | -------- |
| Batched release        | One release per RP run, aggregated changelog | ✓        |
| Per-component releases | Each component gets own GitHub Release       |          |
| App releases only      | Only apps get GitHub Releases                |          |

### Changelogs

| Option          | Description                               | Selected |
| --------------- | ----------------------------------------- | -------- |
| All components  | Every package/crate/app gets CHANGELOG.md | ✓        |
| Apps + SDK only | Rust crates skip changelogs               |          |
| Root only       | Single aggregated changelog               |          |

### Desktop Updater

| Option                       | Description                              | Selected |
| ---------------------------- | ---------------------------------------- | -------- |
| Desktop-specific release tag | cipherbox-desktop-vX.Y for Tauri updater | ✓        |
| Keep current pattern         | Part of batched release                  |          |
| Separate updater workflow    | Decoupled from GitHub Releases           |          |

### Release PR

| Option             | Description                               | Selected |
| ------------------ | ----------------------------------------- | -------- |
| Single combined PR | One release PR with all component bumps   | ✓        |
| Grouped PRs        | One PR per group (apps, packages, crates) |          |
| Per-component PRs  | Each component gets own release PR        |          |

---

## Staging/Deploy Flow

### Staging Deploy Strategy

| Option             | Description                                           | Selected |
| ------------------ | ----------------------------------------------------- | -------- |
| Smart dispatch now | Full conditional deploy per component                 |          |
| Phased approach    | Add detection logging now, conditional skipping later | ✓        |
| No changes         | Keep deploying everything                             |          |

**User's note:** Worried about adding complexity to the "already well refined staging deployment flow."

### Staging Tag Format

| Option             | Description                | Selected |
| ------------------ | -------------------------- | -------- |
| Keep root version  | staging-v0.35.0-rc-1       |          |
| Date-based         | staging-YYYYMMDD-release-N | ✓        |
| Sequential counter | staging-rc-42              |          |

**User's note:** "Change suffix to -release-N — there are not candidates, these are actual releases."

### Docker Image Tags

| Option                   | Description                              | Selected |
| ------------------------ | ---------------------------------------- | -------- |
| Component version only   | cipherbox-api:0.36.0                     |          |
| Version + staging suffix | cipherbox-api:0.36.0-staging             |          |
| Both tags                | Version tag + latest-staging rolling tag | ✓        |

---

## CI Enforcement

### Path Mapping Source

| Option                       | Description                          | Selected |
| ---------------------------- | ------------------------------------ | -------- |
| Config file                  | .github/release-components.json      |          |
| Convention-based             | Derive from directory structure      |          |
| RP config as source of truth | Read from release-please-config.json | ✓        |

**User asked:** "Is there any disadvantage to using release please as the single source of truth?" — Answer: No meaningful disadvantage.

### Check Timing

**User's choice:** Every PR event — action is near-instant (~5-10 seconds).

### Label Format

`release:component:type` with types: feat, fix, perf, refactor, breaking, plus release:none.

### Labels

Pre-created in GitHub repo (~70 labels) for autocomplete.

### Check Type

Required (blocking) — not informational.

---

## Claude's Discretion

- Implementation details of GitHub Actions scripts
- Label color scheme
- Reusable workflow vs composite action architecture
- RP config restructuring details

## Deferred Ideas

- Smart staging dispatch (conditional job skipping) — future phase
- Spec-anchored API versioning — when external consumers arrive
- Coordinated 1.0 milestone — when 1.0 is on the horizon
