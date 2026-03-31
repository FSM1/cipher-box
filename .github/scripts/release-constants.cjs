// @ts-check
/* eslint-disable @typescript-eslint/no-require-imports */
/**
 * Shared constants for release automation scripts.
 * Used by pr-release-preview.js and post-merge-release.js.
 */

/** Bump type to numeric priority — higher = bigger bump */
const BUMP_LEVELS = /** @type {const} */ ({
  major: 3,
  minor: 2,
  patch: 1,
  none: 0,
});

/**
 * Bidirectional mapping between release-please config paths and label component names.
 * API lock group (D-05): apps/api, packages/api-client, crates/api-client share one label.
 */
const PATH_TO_LABEL = {
  'apps/api': 'api',
  'packages/api-client': 'api',
  'crates/api-client': 'api',
  'apps/web': 'web',
  'apps/desktop': 'desktop',
  'apps/tee-worker': 'tee-worker',
  'packages/core': 'core',
  'packages/crypto': 'crypto',
  'packages/sdk-core': 'sdk-core',
  'packages/sdk': 'sdk',
  'crates/crypto': 'cipherbox-crypto',
  'crates/core': 'cipherbox-core',
  'crates/fuse': 'cipherbox-fuse',
  'crates/sdk': 'cipherbox-sdk',
};

/** Inverse mapping: label component name -> release-please config paths */
const LABEL_TO_PATHS = {};
for (const [path, label] of Object.entries(PATH_TO_LABEL)) {
  if (!LABEL_TO_PATHS[label]) LABEL_TO_PATHS[label] = [];
  LABEL_TO_PATHS[label].push(path);
}

/** Monotonic versioning apps — patch bumps become minor (D-08, D-13) */
const MONOTONIC_PATHS = new Set(['apps/web', 'apps/desktop']);

/** Label type string to semver bump type */
const LABEL_TYPE_TO_BUMP = {
  fix: 'patch',
  perf: 'patch',
  refactor: 'patch',
  feat: 'minor',
  breaking: 'major',
};

module.exports = {
  BUMP_LEVELS,
  PATH_TO_LABEL,
  LABEL_TO_PATHS,
  MONOTONIC_PATHS,
  LABEL_TYPE_TO_BUMP,
};
