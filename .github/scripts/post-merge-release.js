// @ts-check
/* eslint-disable @typescript-eslint/no-require-imports */
/**
 * Post-Merge Release Target Injection — reads final release labels from
 * the merged PR, computes target versions via semver bumps, and writes
 * `release-as` overrides into `release-please-config.json` so Release
 * Please creates release PRs with precise label-derived versions.
 *
 * Environment variables (set by workflow):
 *   GITHUB_TOKEN        — GitHub App token (for API access)
 *   COMMIT_SHA          — The merge commit SHA on main
 *   GITHUB_REPOSITORY   — owner/repo
 *
 * Uses only @actions/core, @actions/github, and fs (pre-installed on runners).
 *
 * Design decisions:
 *   D-25: Find originating PR from commit SHA
 *   D-26: Compute target versions from labels
 *   D-27: Write release-as to RP config
 *   D-29: Handle existing release-as (take higher bump)
 *   D-30: RP consumes and clears release-as in release PR
 */

const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const path = require('path');
const {
  BUMP_LEVELS,
  LABEL_TO_PATHS,
  LABEL_TYPE_TO_BUMP,
  MONOTONIC_PATHS,
} = require('./release-constants.cjs');

// Alias for readability in this script
const BUMP_TYPE_TO_LEVEL = BUMP_LEVELS;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Bump a semver version string by the given bump type.
 * For monotonic packages, patch is promoted to minor.
 *
 * @param {string} current — current version (e.g., "0.30.0" or "1.0")
 * @param {string} bumpType — "major", "minor", or "patch"
 * @param {boolean} [isMonotonic=false] — if true, patch -> minor
 * @returns {string} — the next version
 */
function bumpVersion(current, bumpType, isMonotonic = false) {
  const parts = current.split('.').map(Number);
  // Ensure 3-part semver (pad with 0 if needed)
  while (parts.length < 3) parts.push(0);
  const [major, minor, patch] = parts;

  const effectiveBump = isMonotonic && bumpType === 'patch' ? 'minor' : bumpType;

  switch (effectiveBump) {
    case 'major':
      return `${major + 1}.0.0`;
    case 'minor':
      return `${major}.${minor + 1}.0`;
    case 'patch':
      return `${major}.${minor}.${patch + 1}`;
    default:
      throw new Error(`Unknown bump type: ${effectiveBump}`);
  }
}

/**
 * Compare two version strings to determine which represents a higher bump
 * from a base version. Returns true if `candidate` is a higher bump than
 * `existing`.
 *
 * @param {string} base — the current manifest version
 * @param {string} existing — existing release-as version
 * @param {string} candidate — newly computed release-as version
 * @returns {boolean} — true if candidate is a higher bump
 */
function isHigherBump(base, existing, candidate) {
  const baseParts = base.split('.').map(Number);
  while (baseParts.length < 3) baseParts.push(0);

  const existingParts = existing.split('.').map(Number);
  while (existingParts.length < 3) existingParts.push(0);

  const candidateParts = candidate.split('.').map(Number);
  while (candidateParts.length < 3) candidateParts.push(0);

  // Compute delta from base for each
  const existingDelta = versionDelta(baseParts, existingParts);
  const candidateDelta = versionDelta(baseParts, candidateParts);

  return candidateDelta > existingDelta;
}

/**
 * Compare two version part arrays lexicographically (major, then minor, then patch).
 * Returns positive if `to` is higher than `from`, negative if lower, 0 if equal.
 *
 * @param {number[]} from
 * @param {number[]} to
 * @returns {number}
 */
function versionDelta(from, to) {
  for (let i = 0; i < 3; i++) {
    if (to[i] !== from[i]) return to[i] - from[i];
  }
  return 0;
}

/**
 * Parse a release label into component and type.
 * Label format: release:{component}:{type}
 *
 * @param {string} label
 * @returns {{ component: string, type: string } | null}
 */
function parseReleaseLabel(label) {
  const parts = label.split(':');
  if (parts.length !== 3 || parts[0] !== 'release') return null;
  const component = parts[1];
  const type = parts[2];
  if (!LABEL_TO_PATHS[component]) return null;
  if (!LABEL_TYPE_TO_BUMP[type]) return null;
  return { component, type };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function run() {
  const token = process.env.GITHUB_TOKEN;
  const commitSha = process.env.COMMIT_SHA;
  const repoFull = process.env.GITHUB_REPOSITORY;

  if (!token || !commitSha || !repoFull) {
    core.setFailed(
      'Missing required environment variables: GITHUB_TOKEN, COMMIT_SHA, GITHUB_REPOSITORY'
    );
    return;
  }

  const [owner, repo] = repoFull.split('/');
  const octokit = github.getOctokit(token);

  // ------ Section 1: Find Originating PR (D-25) ------
  core.info(`Finding PR associated with commit ${commitSha}`);

  const { data: prs } = await octokit.rest.repos.listPullRequestsAssociatedWithCommit({
    owner,
    repo,
    commit_sha: commitSha,
  });

  const mergedPr = prs.find((pr) => pr.merged_at && pr.base.ref === 'main');

  if (!mergedPr) {
    core.info('No merged PR found for this commit — nothing to do (direct push or non-main merge)');
    return;
  }

  core.info(`Found merged PR #${mergedPr.number}: ${mergedPr.title}`);

  // Skip Release Please's own release PRs
  if (mergedPr.head.ref.startsWith('release-please--')) {
    core.info('Skipping Release Please release PR — release-as injection not needed');
    return;
  }

  // ------ Section 2: Read Labels ------
  const allLabels = mergedPr.labels.map((l) => l.name);
  core.info(`PR labels: ${allLabels.join(', ') || '(none)'}`);

  // Check for release:none escape hatch
  if (allLabels.includes('release:none')) {
    core.info('release:none label present — skipping release-as injection');
    core.setOutput('packages_bumped', '[]');
    core.setOutput('pr_number', String(mergedPr.number));
    return;
  }

  // Extract release labels
  const releaseLabels = allLabels
    .filter((l) => l.startsWith('release:') && l !== 'release:none')
    .map(parseReleaseLabel)
    .filter(Boolean);

  if (releaseLabels.length === 0) {
    core.info('No release labels found on PR — nothing to inject');
    core.setOutput('packages_bumped', '[]');
    core.setOutput('pr_number', String(mergedPr.number));
    return;
  }

  core.info(
    `Found ${releaseLabels.length} release label(s): ${releaseLabels.map((l) => `${l.component}:${l.type}`).join(', ')}`
  );

  // ------ Section 3: Label-to-Path Mapping ------
  // Collect the highest bump per component from labels
  // (a single component could theoretically have multiple labels, take highest)
  /** @type {Map<string, string>} component -> bump type */
  const componentBumps = new Map();

  for (const label of releaseLabels) {
    const bumpType = LABEL_TYPE_TO_BUMP[label.type];
    const existing = componentBumps.get(label.component);
    if (!existing || BUMP_TYPE_TO_LEVEL[bumpType] > BUMP_TYPE_TO_LEVEL[existing]) {
      componentBumps.set(label.component, bumpType);
    }
  }

  // ------ Section 4 & 5: Read manifest, config, compute versions, handle existing release-as ------
  const configPath = path.join(process.cwd(), 'release-please-config.json');
  const manifestPath = path.join(process.cwd(), '.release-please-manifest.json');

  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

  /** @type {Array<{path: string, component: string, currentVersion: string, targetVersion: string, bumpType: string}>} */
  const bumped = [];

  for (const [component, bumpType] of componentBumps.entries()) {
    const paths = LABEL_TO_PATHS[component];
    if (!paths) {
      core.warning(`Unknown component "${component}" — skipping`);
      continue;
    }

    for (const pkgPath of paths) {
      // Read current version from manifest
      const currentVersion = manifest[pkgPath];
      if (!currentVersion) {
        core.warning(`No version found in manifest for "${pkgPath}" — skipping`);
        continue;
      }

      // Ensure package exists in config
      if (!config.packages[pkgPath]) {
        core.warning(`Package "${pkgPath}" not found in release-please-config.json — skipping`);
        continue;
      }

      // Compute target version (D-26)
      const isMonotonic = MONOTONIC_PATHS.has(pkgPath);
      const targetVersion = bumpVersion(currentVersion, bumpType, isMonotonic);

      // Handle existing release-as (D-29)
      const existingReleaseAs = config.packages[pkgPath]['release-as'];
      if (existingReleaseAs) {
        if (!isHigherBump(currentVersion, existingReleaseAs, targetVersion)) {
          core.info(
            `Keeping existing release-as ${existingReleaseAs} for ${pkgPath} (higher than computed ${targetVersion})`
          );
          continue;
        }
        core.info(
          `Overriding existing release-as ${existingReleaseAs} with ${targetVersion} for ${pkgPath} (higher bump)`
        );
      }

      // Write release-as to config (D-27)
      config.packages[pkgPath]['release-as'] = targetVersion;

      bumped.push({
        path: pkgPath,
        component,
        currentVersion,
        targetVersion,
        bumpType: isMonotonic && bumpType === 'patch' ? 'minor (monotonic)' : bumpType,
      });
    }
  }

  if (bumped.length === 0) {
    core.info('No packages to bump — no changes to release-please-config.json');
    core.setOutput('packages_bumped', '[]');
    core.setOutput('pr_number', String(mergedPr.number));
    return;
  }

  // ------ Section 6: Write updated config ------
  // Write updated config back to disk
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf8'); // release-please-config.json
  core.info(`Updated release-please-config.json with ${bumped.length} release-as entries`);

  // ------ Section 7: Output Summary ------
  core.setOutput('packages_bumped', JSON.stringify(bumped));
  core.setOutput('pr_number', String(mergedPr.number));

  // Write GitHub Actions step summary
  const summaryLines = [
    `## Release Targets from PR #${mergedPr.number}`,
    '',
    '| Package | Component | Current | Target | Bump |',
    '| ------- | --------- | ------- | ------ | ---- |',
  ];

  for (const entry of bumped) {
    summaryLines.push(
      `| \`${entry.path}\` | ${entry.component} | ${entry.currentVersion} | ${entry.targetVersion} | ${entry.bumpType} |`
    );
  }

  summaryLines.push('', `_release-as entries injected into release-please-config.json_`);

  await core.summary.addRaw(summaryLines.join('\n')).write();
  core.info('Step summary written');
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

run().catch((err) => {
  core.setFailed(`Post-merge release target injection failed: ${err.message}`);
});
