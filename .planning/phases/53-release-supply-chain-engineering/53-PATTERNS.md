# Phase 53: Release & Supply-Chain Engineering - Pattern Map

**Mapped:** 2026-06-19
**Files analyzed:** 9 target assets (14 workflow files + 2 config files + 1 new workflow + 1 new script + 1 existing workflow change)
**Analogs found:** 9 / 9

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
| --- | --- | --- | --- | --- |
| `.github/workflows/*.yml` (14 files, SHA-pin) | ci-config | request-response | themselves (existing `uses:` + `changes` job permissions block) | exact |
| `.github/workflows/zizmor.yml` (new) | ci-gate | request-response | `.github/workflows/pr-title.yml` (install tool + fail-on-finding) | role-match |
| `.github/dependabot.yml` | ci-config | — | itself (already has github-actions block) | ALREADY SATISFIED — no change |
| `.github/workflows/release-please.yml` (Cargo.lock step) | ci-workflow | batch | itself (post-release summary + edit steps) | exact |
| `.github/workflows/pr-release-preview.yml` (concurrency change) | ci-workflow | event-driven | itself (existing concurrency block lines 8-10) | exact |
| `release-please-config.json` (remove 3 stale pins) | config | — | itself (packages/core, packages/crypto, crates/core blocks) | exact |
| `.planning/scripts/check-stale-release-as.js` (new, Wave 0) | utility-script | transform | `.github/scripts/pr-release-preview.js` (reads config + manifest JSON) | role-match |
| `CLAUDE.md` (force-push discipline rule) | docs | — | existing CLAUDE.md "API Development Workflow" section | exact |
| `MEMORY.md` (force-push gotcha entry) | docs | — | existing "PR-create triggers a bot release commit" memory entry | exact |

---

## Pattern Assignments

### `.github/workflows/*.yml` — SHA Pinning (D-01, all 14 files)

**Analog:** All 14 files themselves — the target pattern is what `pinact run` produces.

**Existing `uses:` shape (current — to be replaced):**

```yaml
# From ci.yml line 17 (representative example)
- uses: actions/checkout@v6
- uses: dorny/paths-filter@v4
- uses: pnpm/action-setup@v6
```

**Target shape after `pinact run` (copy this format exactly):**

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v6.2.0
```

Rules:
- Full 40-char SHA, no shortening.
- Version comment: `# vX.Y.Z` immediately after the SHA, on the same line.
- Internal refs (`./github/workflows/*.yml`) are excluded — leave them unchanged.
- Do NOT hand-edit. Run `GITHUB_TOKEN=$GITHUB_TOKEN pinact run` from the repo root.

**Existing permissions pattern to replicate on all jobs that lack it** (analog: `ci.yml` `changes` job, lines 11-13):

```yaml
  changes:
    name: Detect Changes
    runs-on: ubuntu-latest
    permissions:
      pull-requests: read
```

**Least-privilege pattern for read-only jobs** (apply to the 11 `ci.yml` jobs + jobs in the 5 other workflows that have no permissions block):

```yaml
    permissions:
      contents: read
```

Jobs that upload to Codecov or post PR comments need `pull-requests: write` additionally. The `cargo-linux` job (ci.yml lines 609-676) is the named zizmor finding from PR #487 — it currently has NO permissions block and needs `contents: read`.

**Top-level workflow default** (apply to workflows with no permissions block at all — `desktop-e2e.yml`, `web-e2e.yml`, `load-test.yml`, `release-gate.yml`, `ci-e2e.yml`):

```yaml
permissions: {}
```

Then add minimal job-level blocks per job.

---

### `.github/workflows/zizmor.yml` (new CI gate, D-04)

**Analog:** `.github/workflows/pr-title.yml` — installs no external dep (pure bash), runs a check, exits non-zero on failure.

**pr-title.yml job structure (lines 7-51) — copy this shape:**

```yaml
jobs:
  lint-pr-title:
    runs-on: ubuntu-latest
    steps:
      - name: Check PR title follows Conventional Commits
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          # ... exits 1 on failure
```

**Target zizmor.yml — replicate this structure with the tool-install + run pattern from RESEARCH.md:**

```yaml
name: GitHub Actions Security Gate

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  zizmor:
    name: GitHub Actions Security Gate
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<sha> # vX.Y.Z
      - name: Install zizmor
        run: pip install zizmor
      - name: Run zizmor
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: zizmor .github/workflows/
```

Key rules:
- Use `pip install zizmor` in a `run:` step — NOT the `zizmorcore/zizmor-action` wrapper (that uses SARIF mode and exits 0 on findings — makes it useless as a gate).
- Plain `zizmor .github/workflows/` exits 11-14 on findings; 0 on clean.
- Add `GH_TOKEN` for online SHA verification (otherwise `--offline` mode, which skips SHA checks).
- The `actions/checkout` `uses:` ref in this new file must itself be SHA-pinned (run pinact on it after creation or add manually).

---

### `.github/dependabot.yml` — D-03: ALREADY SATISFIED

**Confirmed state (file read):**

```yaml
version: 2
updates:
  - package-ecosystem: 'github-actions'
    directory: '/'
    schedule:
      interval: 'weekly'
      day: 'monday'
    labels:
      - 'dependencies'
      - 'ci'
    commit-message:
      prefix: 'chore(ci)'
```

The `github-actions` ecosystem block is complete and correct. **Do NOT add a second block.** D-03 requires zero changes to this file.

---

### `.github/workflows/release-please.yml` — Cargo.lock sync step (D-05)

**Analog:** `release-please.yml` itself — the existing post-release conditional steps (lines 31-79) show the pattern for adding a step that runs only when releases were created.

**Existing conditional step pattern (lines 41-79):**

```yaml
      - name: Release summary
        if: steps.release.outputs.releases_created == 'true'
        env:
          RELEASES_OUTPUT: ${{ toJSON(steps.release.outputs) }}
        run: |
          echo "## Releases Created" >> "$GITHUB_STEP_SUMMARY"
          ...

      - name: Ensure batched releases are not marked as latest
        if: steps.release.outputs.releases_created == 'true'
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
          RELEASES_OUTPUT: ${{ toJSON(steps.release.outputs) }}
        run: |
          # multi-line shell with jq parsing of RELEASES_OUTPUT
          ...
```

**Target Cargo.lock step — replicate this pattern, append after the existing post-release steps:**

```yaml
      - uses: actions/checkout@<sha> # vX.Y.Z
        if: steps.release.outputs.releases_created == 'true'
        with:
          token: ${{ steps.app-token.outputs.token }}
          fetch-depth: 0

      - name: Update Cargo.lock for released crates
        if: steps.release.outputs.releases_created == 'true'
        env:
          RELEASES_OUTPUT: ${{ toJSON(steps.release.outputs) }}
        run: |
          # Parse bumped crate versions from release outputs and update Cargo.lock
          # cargo update -p <crate> --precise <new-version> per bumped first-party crate
          # Then: git diff --exit-code Cargo.lock || (commit updated lock to main)
```

Note: D-05 research concluded the fallback path (this script) is required because the `cargo-workspace` plugin has open bug #2517. Do NOT add `"plugins": ["cargo-workspace"]` to `release-please-config.json`.

---

### `.github/workflows/pr-release-preview.yml` — concurrency change (D-06)

**Analog:** itself. The existing concurrency block (lines 8-10):

```yaml
concurrency:
  group: release-preview-${{ github.event.pull_request.number }}
  cancel-in-progress: true
```

**Target (one-line change — Option A safety-net):**

```yaml
concurrency:
  group: release-preview-${{ github.event.pull_request.number }}
  cancel-in-progress: false
```

This makes queued runs complete instead of abort. When a developer force-pushes, the subsequent preview run always completes and re-commits the correct release targets. No other changes to this file are needed for this fix.

The full workflow's bot commit step for reference (lines 42-57) — no change needed here:

```yaml
      - name: Commit release-as targets
        if: >-
          steps.preview.outputs.config_changed == 'true'
          && github.event.pull_request.head.repo.full_name == github.repository
        env:
          PR_NUMBER: ${{ github.event.pull_request.number }}
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add release-please-config.json
          if git diff --staged --quiet; then
            echo "No changes to commit"
            exit 0
          fi
          git commit -m "chore(release): set release targets for PR #${PR_NUMBER}"
          git push
```

---

### `release-please-config.json` — Remove 3 stale pins (D-07)

**Confirmed stale entries (verified: manifest version == release-as value):**

```json
"packages/core": {
  "release-type": "node",
  "component": "@cipherbox/core",
  "include-component-in-tag": true,
  "bump-minor-pre-major": true,
  "release-as": "0.31.0"    // STALE — manifest is 0.31.0; DELETE this key
},
"packages/crypto": {
  "release-type": "node",
  "component": "@cipherbox/crypto",
  "include-component-in-tag": true,
  "bump-minor-pre-major": true,
  "release-as": "0.33.0"    // STALE — manifest is 0.33.0; DELETE this key
},
"crates/core": {
  "release-type": "rust",
  "component": "cipherbox-core",
  "include-component-in-tag": true,
  "bump-minor-pre-major": true,
  "release-as": "0.5.1"     // STALE — manifest is 0.5.1; DELETE this key
},
```

Action: delete only the `"release-as"` key from each of these three package blocks. The surrounding package config stays. All other `release-as` entries in the file are actively pinned above manifest version — do NOT touch them.

---

### `.planning/scripts/check-stale-release-as.js` (new, Wave 0 gap)

**Analog:** `.github/scripts/pr-release-preview.js` — reads `release-please-config.json` + `.release-please-manifest.json` as JSON and cross-references them.

**pr-release-preview.js import and file-read pattern (lines 1-25 + clear-logic block lines 630-651):**

```js
// @ts-check
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Reading config + manifest:
const config = JSON.parse(readFileSync('release-please-config.json', 'utf8'));
const manifest = JSON.parse(readFileSync('.release-please-manifest.json', 'utf8'));

// Cross-referencing (analog to clear logic lines 644-651):
for (const [pkgPath, pkgConfig] of Object.entries(config.packages)) {
  if (pkgConfig['release-as'] && !packageBumps.has(pkgPath) && !baseReleaseAs[pkgPath]) {
    // stale entry detected
  }
}
```

**Target check-stale-release-as.js pattern (copy this structure):**

```js
// @ts-check
/**
 * Checks for release-as entries in release-please-config.json that equal
 * their current manifest version (stale/consumed pins that should be removed).
 *
 * Usage: node .planning/scripts/check-stale-release-as.js
 * Exits 1 if stale pins found; 0 if clean.
 */
import { readFileSync } from 'node:fs';

const config = JSON.parse(readFileSync('release-please-config.json', 'utf8'));
const manifest = JSON.parse(readFileSync('.release-please-manifest.json', 'utf8'));

let found = 0;
for (const [pkgPath, pkgConfig] of Object.entries(config.packages || {})) {
  const releaseAs = pkgConfig['release-as'];
  const manifestVersion = manifest[pkgPath];
  if (releaseAs && manifestVersion && releaseAs === manifestVersion) {
    console.log(`STALE: ${pkgPath} release-as=${releaseAs} == manifest=${manifestVersion}`);
    found++;
  }
}
if (found > 0) {
  console.error(`Found ${found} stale release-as entries. Remove them from release-please-config.json.`);
  process.exit(1);
}
console.log('No stale release-as entries found.');
```

Note: this script lives under `.planning/scripts/` (not `.github/scripts/`) because it is a dev/validation tool, not a CI workflow script.

---

## Shared Patterns

### Top-Level Permissions Default (apply to workflows with no permissions block)

**Source:** `.github/workflows/codecov-base.yml` (has top-level permissions), `pr-release-preview.yml` (lines 12-14)
**Apply to:** `desktop-e2e.yml`, `web-e2e.yml`, `load-test.yml`, `release-gate.yml`, `ci-e2e.yml`

```yaml
permissions: {}   # deny all at workflow level; grant minimally per job
```

Then each job that needs tokens gets a job-level block:

```yaml
jobs:
  my-job:
    permissions:
      contents: read
```

### Conditional Post-Release Step Pattern

**Source:** `release-please.yml` lines 31-40
**Apply to:** the new Cargo.lock update step

```yaml
      - name: <step name>
        if: steps.release.outputs.releases_created == 'true'
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
          RELEASES_OUTPUT: ${{ toJSON(steps.release.outputs) }}
        run: |
          ...
```

Always gate on `steps.release.outputs.releases_created == 'true'` — not `'false'` — to skip the step on PRs that weren't released.

---

## No Analog Found

None. All target files have direct analogs in the codebase.

---

## Key Facts for Planner

- **D-03 is done:** `.github/dependabot.yml` already has the `github-actions` block. Zero changes needed.
- **D-05 path is fallback:** Do NOT add `cargo-workspace` plugin — open bug #2517. Use `cargo update -p <crate> --precise <ver>` in release-please.yml.
- **3 stale pins confirmed:** `packages/core` (0.31.0), `packages/crypto` (0.33.0), `crates/core` (0.5.1). All equal manifest. Other 10 `release-as` entries are above manifest — leave them.
- **11 ci.yml jobs lack permissions:** `lint`, `typecheck`, `api-spec`, `migration-check`, `test`, `sdk-e2e`, `build`, `cargo-windows`, `cargo-macos`, `cargo-linux`, `vector-parity`. `changes` job (lines 11-13) is the only one with a block — use it as the model.
- **zizmor must use plain CLI mode** (`pip install zizmor` + `zizmor .github/workflows/` in `run:`) — NOT the `zizmorcore/zizmor-action` GH Action (exits 0 on findings via SARIF).
- **`cancel-in-progress: true` → `false`** in `pr-release-preview.yml` line 10 is the primary safety-net for D-06. One-line change.
- **pr-release-preview.js clear logic** lives at lines 644-651. `packageBumps` map built starting at line 271. The new check script copies the `readFileSync` + JSON.parse pattern from lines 630-635.

## Metadata

**Analog search scope:** `.github/workflows/`, `.github/dependabot.yml`, `.github/scripts/`, `release-please-config.json`, `.release-please-manifest.json`
**Files scanned:** 16
**Pattern extraction date:** 2026-06-19
