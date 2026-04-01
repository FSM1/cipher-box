// @ts-check
/**
 * PR Release Preview — analyzes individual PR commits (before squash),
 * maps changed files to packages, determines bump level per package,
 * detects dependency cascades, and auto-applies release labels.
 *
 * Environment variables (set by workflow):
 *   GITHUB_TOKEN  — GitHub API token
 *   PR_NUMBER     — Pull request number
 *   GITHUB_REPOSITORY — owner/repo
 *
 * Uses @actions/core and @actions/github (installed by the workflow).
 */

import * as core from '@actions/core';
import * as github from '@actions/github';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { BUMP_LEVELS, PATH_TO_LABEL, MONOTONIC_PATHS } from './release-constants.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Conventional commit regex — matches first line of commit message */
const CONVENTIONAL_RE =
  /^(?<type>feat|fix|perf|refactor|build|test|docs|style|chore|ci|revert)(?:\((?<scope>[^)]*)\))?(?<breaking>!)?:\s*(?<description>.+)/;

/** Commit types that do NOT trigger a version bump (D-39) */
const EXEMPT_TYPES = new Set(['docs', 'test', 'chore', 'ci', 'style', 'build', 'revert']);

/**
 * Map commit type to bump level and label suffix.
 * Types not listed here are exempt (no bump).
 */
const TYPE_TO_BUMP = {
  feat: { bump: 'minor', label: 'feat' },
  fix: { bump: 'patch', label: 'fix' },
  perf: { bump: 'patch', label: 'perf' },
  refactor: { bump: 'patch', label: 'refactor' },
};

/**
 * JS dependency graph — production dependencies only (D-24).
 * Keys are package paths, values are arrays of dependency paths.
 */
const JS_DEPS = {
  'packages/core': ['packages/crypto'],
  'packages/sdk-core': ['packages/api-client', 'packages/core', 'packages/crypto'],
  'packages/sdk': ['packages/api-client', 'packages/core', 'packages/crypto', 'packages/sdk-core'],
  'apps/web': [
    'packages/api-client',
    'packages/core',
    'packages/crypto',
    'packages/sdk',
    'packages/sdk-core',
  ],
  'apps/desktop': ['packages/crypto'],
  'apps/tee-worker': ['packages/core', 'packages/crypto', 'packages/sdk-core'],
};

/**
 * Rust dependency graph.
 */
const RUST_DEPS = {
  'crates/core': ['crates/crypto'],
  'crates/fuse': ['crates/api-client', 'crates/core', 'crates/crypto'],
  'crates/sdk': ['crates/api-client', 'crates/core', 'crates/crypto'],
};

/** API lock group members (D-05) */
const API_LOCK_GROUP = ['apps/api', 'packages/api-client', 'crates/api-client'];

/** Monotonic versioning apps — patch bumps become minor (D-08, D-13) */
const MONOTONIC_APPS = MONOTONIC_PATHS;

/** Comment marker for finding/updating the preview comment */
const COMMENT_MARKER = '<!-- release-preview -->';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Read release-please-config.json and extract package paths (D-37).
 * Excludes root "." package from enforcement.
 * @returns {string[]}
 */
function getPackagePaths() {
  const configPath = join(process.cwd(), 'release-please-config.json');
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  return Object.keys(config.packages).filter((p) => p !== '.');
}

/**
 * Map a file path to its package path using longest-prefix matching.
 * @param {string} filePath
 * @param {string[]} packagePaths — sorted by length descending
 * @returns {string|null}
 */
function fileToPackage(filePath, packagePaths) {
  for (const prefix of packagePaths) {
    if (filePath === prefix || filePath.startsWith(prefix + '/')) {
      return prefix;
    }
  }
  return null;
}

/**
 * Build reverse dependency map: for each package, which packages depend on it?
 * @param {Record<string, string[]>} deps
 * @returns {Record<string, string[]>}
 */
function buildReverseDeps(deps) {
  /** @type {Record<string, string[]>} */
  const reverse = {};
  for (const [pkg, depList] of Object.entries(deps)) {
    for (const dep of depList) {
      if (!reverse[dep]) reverse[dep] = [];
      reverse[dep].push(pkg);
    }
  }
  return reverse;
}

/**
 * Fetch all pages of a paginated GitHub API endpoint.
 * @param {ReturnType<typeof github.getOctokit>} octokit
 * @param {string} route
 * @param {Record<string, unknown>} params
 * @returns {Promise<any[]>}
 */
async function fetchAllPages(octokit, route, params) {
  const items = [];
  let page = 1;
  const perPage = 100;

  while (true) {
    let response;
    try {
      response = await octokit.request(route, {
        ...params,
        per_page: perPage,
        page,
      });
    } catch (err) {
      // Rate limiting: retry with exponential backoff
      if (err.status === 403 || err.status === 429) {
        for (const delay of [1000, 2000, 4000]) {
          core.warning(`Rate limited, retrying in ${delay}ms...`);
          await new Promise((r) => setTimeout(r, delay));
          try {
            response = await octokit.request(route, {
              ...params,
              per_page: perPage,
              page,
            });
            break;
          } catch (retryErr) {
            if (retryErr.status !== 403 && retryErr.status !== 429) throw retryErr;
          }
        }
        if (!response) throw err;
      } else {
        throw err;
      }
    }

    items.push(...response.data);
    if (response.data.length < perPage) break;
    page++;
  }

  return items;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function run() {
  const token = process.env.GITHUB_TOKEN;
  const prNumber = parseInt(process.env.PR_NUMBER, 10);
  const [owner, repo] = process.env.GITHUB_REPOSITORY.split('/');

  if (!token || !prNumber || !owner || !repo) {
    core.setFailed('Missing required environment variables');
    return;
  }

  const octokit = github.getOctokit(token);

  // ------ Check for release:none escape hatch ------
  const { data: prData } = await octokit.rest.pulls.get({
    owner,
    repo,
    pull_number: prNumber,
  });
  const existingLabels = prData.labels.map((l) => l.name);

  if (existingLabels.includes('release:none')) {
    core.info('release:none label present — skipping enforcement and label computation');
    // Post a minimal comment
    await postOrUpdateComment(
      octokit,
      owner,
      repo,
      prNumber,
      [
        COMMENT_MARKER,
        '## Release Preview',
        '',
        '`release:none` label present — no version bumps for this PR.',
      ].join('\n')
    );
    return;
  }

  // ------ Section 1: File-to-Package Mapping ------
  const packagePaths = getPackagePaths();
  // Sort by length descending for longest-prefix match
  packagePaths.sort((a, b) => b.length - a.length);

  core.info(`Loaded ${packagePaths.length} package paths from release-please-config.json`);

  // ------ Section 2: Commit Parsing ------
  const commits = await fetchAllPages(
    octokit,
    'GET /repos/{owner}/{repo}/pulls/{pull_number}/commits',
    { owner, repo, pull_number: prNumber }
  );

  core.info(`Found ${commits.length} commits in PR #${prNumber}`);

  /**
   * Per-package bump tracking.
   * @type {Map<string, {bump: string, label: string, source: string}>}
   */
  const packageBumps = new Map();

  /** Track warnings for non-conventional commits */
  const warnings = [];

  /** Track commits analyzed per package for exemption logic */
  /** @type {Map<string, Set<string>>} */
  const packageCommitTypes = new Map();

  for (const commit of commits) {
    // Skip merge commits — they have 2+ parents and carry no release intent
    if (commit.parents && commit.parents.length > 1) continue;

    const message = commit.commit.message;
    const firstLine = message.split('\n')[0];
    const sha = commit.sha;
    const shortSha = sha.substring(0, 7);

    // Parse conventional commit
    const match = firstLine.match(CONVENTIONAL_RE);

    // Fetch files changed by this commit
    const commitDetail = await octokit.rest.repos.getCommit({
      owner,
      repo,
      ref: sha,
    });
    const changedFiles = (commitDetail.data.files || []).map((f) => f.filename);

    // Map changed files to packages
    const touchedPackages = new Set();
    for (const file of changedFiles) {
      const pkg = fileToPackage(file, packagePaths);
      if (pkg) touchedPackages.add(pkg);
    }

    if (touchedPackages.size === 0) continue; // No versioned packages touched

    if (!match) {
      // Non-conventional commit touching versioned packages
      const pkgList = [...touchedPackages].join(', ');
      warnings.push(
        `Commit \`${shortSha}\` touches \`${pkgList}\` but has non-conventional message: "${firstLine}"`
      );
      continue;
    }

    const type = match.groups.type;
    const isBreaking = match.groups.breaking === '!' || message.includes('BREAKING CHANGE:');

    for (const pkg of touchedPackages) {
      // Track all commit types for exemption logic
      if (!packageCommitTypes.has(pkg)) packageCommitTypes.set(pkg, new Set());
      packageCommitTypes.get(pkg).add(type);

      // Determine bump
      let bumpInfo;
      if (isBreaking) {
        bumpInfo = { bump: 'major', label: 'breaking', source: `breaking commit ${shortSha}` };
      } else if (TYPE_TO_BUMP[type]) {
        bumpInfo = {
          bump: TYPE_TO_BUMP[type].bump,
          label: TYPE_TO_BUMP[type].label,
          source: `${type} commit ${shortSha}`,
        };
      } else {
        // Exempt type (docs, test, chore, etc.) — no bump
        continue;
      }

      const existing = packageBumps.get(pkg);
      if (!existing || BUMP_LEVELS[bumpInfo.bump] > BUMP_LEVELS[existing.bump]) {
        packageBumps.set(pkg, bumpInfo);
      }
    }
  }

  // ------ Section 3: Auto-Exemptions (D-39) ------
  // If ALL commits for a package have only exempt types, that package gets no label
  for (const [pkg, types] of packageCommitTypes.entries()) {
    const allExempt = [...types].every((t) => EXEMPT_TYPES.has(t));
    if (allExempt) {
      packageBumps.delete(pkg);
    }
  }

  // ------ Section 4: API Lock Group (D-05) ------
  let apiGroupBump = 'none';
  let apiGroupLabel = '';
  let apiGroupSource = '';

  for (const member of API_LOCK_GROUP) {
    const bump = packageBumps.get(member);
    if (bump && BUMP_LEVELS[bump.bump] > BUMP_LEVELS[apiGroupBump]) {
      apiGroupBump = bump.bump;
      apiGroupLabel = bump.label;
      apiGroupSource = bump.source;
    }
  }

  if (apiGroupBump !== 'none') {
    for (const member of API_LOCK_GROUP) {
      packageBumps.set(member, {
        bump: apiGroupBump,
        label: apiGroupLabel,
        source: apiGroupSource,
      });
    }
  }

  // ------ Section 5: Monotonic Versioning (D-08, D-13) ------
  // For web and desktop, patch -> minor (they don't have patch releases)
  for (const app of MONOTONIC_APPS) {
    const bump = packageBumps.get(app);
    if (bump && bump.bump === 'patch') {
      packageBumps.set(app, { ...bump, bump: 'minor' });
    }
  }

  // ------ Section 6: Cascade Detection (D-21, D-22, D-23, D-24) ------
  const jsReverse = buildReverseDeps(JS_DEPS);
  const rustReverse = buildReverseDeps(RUST_DEPS);
  const allReverse = {};
  for (const [dep, dependents] of Object.entries(jsReverse)) {
    allReverse[dep] = [...(allReverse[dep] || []), ...dependents];
  }
  for (const [dep, dependents] of Object.entries(rustReverse)) {
    allReverse[dep] = [...(allReverse[dep] || []), ...dependents];
  }

  /** @type {Array<{from: string, to: string, fromBump: string, toBump: string}>} */
  const cascadeDetails = [];

  // Iterate bumped packages and cascade to dependents
  // We need to iterate in dependency order (leaves first) to propagate transitively
  // Keep cascading until no new bumps are found
  let changed = true;
  while (changed) {
    changed = false;
    for (const [pkg, bumpInfo] of [...packageBumps.entries()]) {
      const dependents = allReverse[pkg] || [];
      for (const dependent of dependents) {
        // Cascade rules (D-22):
        //   major -> dependent gets at minimum minor
        //   minor/patch -> dependent gets at minimum patch
        let cascadeBump = 'patch';
        if (bumpInfo.bump === 'major') {
          cascadeBump = 'minor';
        }

        const existing = packageBumps.get(dependent);
        if (!existing || BUMP_LEVELS[cascadeBump] > BUMP_LEVELS[existing.bump]) {
          const wasNew = !existing;
          const cascadeLabel = cascadeBump === 'minor' ? 'feat' : 'fix';
          packageBumps.set(dependent, {
            bump: cascadeBump,
            label:
              existing?.label && BUMP_LEVELS[existing.bump] >= BUMP_LEVELS[cascadeBump]
                ? existing.label
                : cascadeLabel,
            source: `Cascade (${PATH_TO_LABEL[pkg] || pkg} ${bumpInfo.bump})`,
          });
          if (wasNew || BUMP_LEVELS[cascadeBump] > BUMP_LEVELS[existing?.bump ?? 'none']) {
            cascadeDetails.push({
              from: pkg,
              to: dependent,
              fromBump: bumpInfo.bump,
              toBump: cascadeBump,
            });
            changed = true;
          }
        }
      }
    }
  }

  // Apply monotonic versioning again for cascaded bumps on web/desktop
  for (const app of MONOTONIC_APPS) {
    const bump = packageBumps.get(app);
    if (bump && bump.bump === 'patch') {
      packageBumps.set(app, { ...bump, bump: 'minor' });
    }
  }

  // Re-apply API lock group after cascading
  apiGroupBump = 'none';
  apiGroupLabel = '';
  apiGroupSource = '';
  for (const member of API_LOCK_GROUP) {
    const bump = packageBumps.get(member);
    if (bump && BUMP_LEVELS[bump.bump] > BUMP_LEVELS[apiGroupBump]) {
      apiGroupBump = bump.bump;
      apiGroupLabel = bump.label;
      apiGroupSource = bump.source;
    }
  }
  if (apiGroupBump !== 'none') {
    for (const member of API_LOCK_GROUP) {
      const existing = packageBumps.get(member);
      if (!existing || BUMP_LEVELS[apiGroupBump] > BUMP_LEVELS[existing.bump]) {
        packageBumps.set(member, {
          bump: apiGroupBump,
          label: apiGroupLabel,
          source: apiGroupSource,
        });
      }
    }
  }

  // ------ Section 7: Label Application (D-16, D-18) ------

  // Collapse package paths to label components (highest bump per component)
  /** @type {Map<string, {bump: string, label: string, source: string}>} */
  const componentBumps = new Map();

  for (const [pkg, bumpInfo] of packageBumps.entries()) {
    const component = PATH_TO_LABEL[pkg];
    if (!component) continue;

    const existing = componentBumps.get(component);
    if (!existing || BUMP_LEVELS[bumpInfo.bump] > BUMP_LEVELS[existing.bump]) {
      componentBumps.set(component, bumpInfo);
    }
  }

  // Determine label type for each component
  /** @type {Map<string, string>} */
  const computedLabels = new Map();
  for (const [component, bumpInfo] of componentBumps.entries()) {
    let labelType;
    if (bumpInfo.bump === 'major') {
      labelType = 'breaking';
    } else {
      labelType = bumpInfo.label;
    }
    computedLabels.set(component, `release:${component}:${labelType}`);
  }

  // Fetch current labels on the PR
  const currentReleaseLabels = existingLabels.filter(
    (l) => l.startsWith('release:') && l !== 'release:none'
  );

  // Determine which existing release labels are manual overrides (D-18)
  const manualOverrides = [];

  // Group existing labels by component
  /** @type {Map<string, string>} */
  const existingByComponent = new Map();
  for (const label of currentReleaseLabels) {
    const parts = label.split(':');
    if (parts.length === 3) {
      existingByComponent.set(parts[1], label);
    }
  }

  // Labels to add and remove
  const labelsToAdd = [];
  const labelsToRemove = [];

  // Label type → bump level for comparison
  const LABEL_BUMP_LEVEL = { fix: 1, perf: 1, refactor: 1, feat: 2, breaking: 3 };

  for (const [component, computedLabel] of computedLabels.entries()) {
    const existing = existingByComponent.get(component);
    if (existing && existing !== computedLabel) {
      const existingLevel = LABEL_BUMP_LEVEL[existing.split(':')[2]] ?? 0;
      const computedLevel = LABEL_BUMP_LEVEL[computedLabel.split(':')[2]] ?? 0;

      if (computedLevel > existingLevel) {
        // Computed bump is higher — replace existing label (e.g. fix→feat after force-push)
        labelsToRemove.push(existing);
        labelsToAdd.push(computedLabel);
      } else {
        // Existing label is higher or equal — treat as manual override
        manualOverrides.push({
          component,
          existing,
          computed: computedLabel,
        });
      }
    } else if (!existing) {
      labelsToAdd.push(computedLabel);
    }
    // If existing matches computed, no action needed
  }

  // Remove labels for components no longer computed.
  // Manual overrides (D-18) still work but must be reapplied after the final commit.
  // TODO(deferred): preserve manually-added labels by tracking auto-applied state.
  for (const [component, existingLabel] of existingByComponent.entries()) {
    if (!computedLabels.has(component)) {
      labelsToRemove.push(existingLabel);
    }
  }

  // Apply label changes
  for (const label of labelsToAdd) {
    try {
      await octokit.rest.issues.addLabels({
        owner,
        repo,
        issue_number: prNumber,
        labels: [label],
      });
      core.info(`Added label: ${label}`);
    } catch (err) {
      core.warning(`Could not add label "${label}": ${err.message}`);
    }
  }

  for (const label of labelsToRemove) {
    try {
      await octokit.rest.issues.removeLabel({
        owner,
        repo,
        issue_number: prNumber,
        name: label,
      });
      core.info(`Removed label: ${label}`);
    } catch (err) {
      // Label might not exist — that's fine
      if (err.status !== 404) {
        core.warning(`Could not remove label "${label}": ${err.message}`);
      }
    }
  }

  // ------ Section 7.5: Release-As Injection ------
  // Write release-as targets into release-please-config.json on the PR branch.
  // When the PR merges, these land on main and release-please picks them up.
  const configPath = join(process.cwd(), 'release-please-config.json');
  const manifestPath = join(process.cwd(), '.release-please-manifest.json');
  const config = JSON.parse(readFileSync(configPath, 'utf8'));
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

  /** @type {Array<{path: string, currentVersion: string, targetVersion: string, bumpType: string}>} */
  const releaseAsEntries = [];
  let configChanged = false;

  // First, clear any stale release-as entries for packages NOT being bumped in this PR
  for (const [pkgPath, pkgConfig] of Object.entries(config.packages)) {
    if (pkgConfig['release-as'] && !packageBumps.has(pkgPath)) {
      delete pkgConfig['release-as'];
      configChanged = true;
      core.info(`Cleared stale release-as for ${pkgPath}`);
    }
  }

  for (const [pkgPath, bumpInfo] of packageBumps.entries()) {
    const currentVersion = manifest[pkgPath];
    if (!currentVersion || !config.packages[pkgPath]) continue;

    const isMonotonic = MONOTONIC_PATHS.has(pkgPath);
    const bumpType = bumpInfo.bump;
    const effectiveBump = isMonotonic && bumpType === 'patch' ? 'minor' : bumpType;

    const parts = currentVersion.split('.').map(Number);
    while (parts.length < 3) parts.push(0);
    const [major, minor, patch] = parts;

    let targetVersion;
    switch (effectiveBump) {
      case 'major':
        targetVersion = `${major + 1}.0.0`;
        break;
      case 'minor':
        targetVersion = `${major}.${minor + 1}.0`;
        break;
      case 'patch':
        targetVersion = `${major}.${minor}.${patch + 1}`;
        break;
      default:
        continue;
    }

    const existingReleaseAs = config.packages[pkgPath]['release-as'];
    if (existingReleaseAs !== targetVersion) {
      config.packages[pkgPath]['release-as'] = targetVersion;
      configChanged = true;
    }

    releaseAsEntries.push({
      path: pkgPath,
      currentVersion,
      targetVersion,
      bumpType: effectiveBump,
    });
  }

  if (configChanged) {
    writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8');
    core.info(
      `Updated release-please-config.json with ${releaseAsEntries.length} release-as entries`
    );
  } else {
    core.info('release-please-config.json unchanged — no commit needed');
  }
  core.setOutput('config_changed', String(configChanged));

  // ------ Section 8: PR Comment (D-23) ------
  const commentLines = [COMMENT_MARKER, '## Release Preview', ''];

  if (componentBumps.size === 0 && warnings.length === 0) {
    commentLines.push(
      'No version bumps detected. All changes are in unversioned paths or use exempt commit types.'
    );
  } else {
    if (componentBumps.size > 0) {
      commentLines.push(
        '| Package | Bump | Label | Source |',
        '| ------- | ---- | ----- | ------ |'
      );

      // Sort components alphabetically for stable output
      const sortedComponents = [...componentBumps.entries()].sort(([a], [b]) => a.localeCompare(b));

      for (const [component, bumpInfo] of sortedComponents) {
        const label = computedLabels.get(component);
        const isDirect = !bumpInfo.source.startsWith('Cascade');
        const source = isDirect ? `Direct (${bumpInfo.label} commit)` : bumpInfo.source;
        commentLines.push(`| ${component} | ${bumpInfo.bump} | \`${label}\` | ${source} |`);
      }
    }

    if (cascadeDetails.length > 0) {
      commentLines.push('', '### Cascade Details', '');
      // Deduplicate cascade details
      const seen = new Set();
      for (const detail of cascadeDetails) {
        const fromLabel = PATH_TO_LABEL[detail.from] || detail.from;
        const toLabel = PATH_TO_LABEL[detail.to] || detail.to;
        const key = `${fromLabel}->${toLabel}`;
        if (seen.has(key)) continue;
        seen.add(key);
        commentLines.push(
          `- \`${fromLabel}\` ${detail.fromBump} -> \`${toLabel}\` ${detail.toBump} (direct dependency)`
        );
      }
    }

    if (manualOverrides.length > 0) {
      commentLines.push('', '### Manual Overrides', '');
      for (const override of manualOverrides) {
        commentLines.push(
          `- **${override.component}**: keeping manual label \`${override.existing}\` (computed: \`${override.computed}\`)`
        );
      }
    }

    if (warnings.length > 0) {
      commentLines.push('', '### Warnings', '');
      for (const warning of warnings) {
        commentLines.push(`- ${warning}`);
      }
    }
  }

  await postOrUpdateComment(octokit, owner, repo, prNumber, commentLines.join('\n'));

  // ------ Section 9: CI Check Status (D-19) ------
  if (warnings.length > 0) {
    core.setFailed(
      `${warnings.length} commit(s) touching versioned packages have non-conventional messages. ` +
        'Fix commit messages or add the `release:none` label to skip enforcement.'
    );
  }
}

/**
 * Post or update the release preview comment on the PR.
 * @param {ReturnType<typeof github.getOctokit>} octokit
 * @param {string} owner
 * @param {string} repo
 * @param {number} prNumber
 * @param {string} body
 */
async function postOrUpdateComment(octokit, owner, repo, prNumber, body) {
  // Find existing comment with marker
  const comments = await fetchAllPages(
    octokit,
    'GET /repos/{owner}/{repo}/issues/{issue_number}/comments',
    { owner, repo, issue_number: prNumber }
  );

  const existing = comments.find(
    (c) => c.body && c.body.includes(COMMENT_MARKER) && c.user?.login === 'github-actions[bot]'
  );

  if (existing) {
    await octokit.rest.issues.updateComment({
      owner,
      repo,
      comment_id: existing.id,
      body,
    });
    core.info(`Updated release preview comment (ID: ${existing.id})`);
  } else {
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: prNumber,
      body,
    });
    core.info('Created release preview comment');
  }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

run().catch((err) => {
  core.setFailed(`PR release preview failed: ${err.message}`);
});
