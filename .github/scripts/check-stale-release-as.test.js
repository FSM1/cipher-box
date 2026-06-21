// @ts-check
/**
 * Unit tests for the stale-release-as guard (check-stale-release-as.js).
 *
 * Uses the built-in node:test runner — no vitest/jest, no added dependency.
 * Run: node --test .github/scripts/check-stale-release-as.test.js
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { findStaleReleaseAs } from './check-stale-release-as.js';

test('reports a package whose release-as equals its manifest version as stale', () => {
  const config = {
    packages: {
      'packages/core': { 'release-as': '0.31.0' },
      'apps/api': { 'release-as': '0.42.0' },
    },
  };
  const manifest = {
    'packages/core': '0.31.0', // equal -> stale
    'apps/api': '0.41.0', // ahead -> ok
  };

  const stale = findStaleReleaseAs(config, manifest);

  assert.equal(stale.length, 1);
  assert.equal(stale[0].pkgPath, 'packages/core');
  assert.equal(stale[0].version, '0.31.0');
});

test('reports nothing when every release-as is strictly ahead of the manifest', () => {
  const config = {
    packages: {
      'apps/api': { 'release-as': '0.42.0' },
      'apps/web': { 'release-as': '0.46.0' },
      'crates/core': { 'release-as': '0.5.2' },
    },
  };
  const manifest = {
    'apps/api': '0.41.0',
    'apps/web': '0.45.0',
    'crates/core': '0.5.1',
  };

  assert.deepEqual(findStaleReleaseAs(config, manifest), []);
});

test('does not flag packages without a release-as key or missing from the manifest', () => {
  const config = {
    packages: {
      '.': {}, // no release-as
      'packages/sdk': { 'release-as': '0.37.1' }, // present in manifest, ahead
      'packages/ghost': { 'release-as': '1.0.0' }, // absent from manifest
    },
  };
  const manifest = {
    '.': '0.42.0',
    'packages/sdk': '0.37.0',
    // packages/ghost intentionally absent
  };

  // Only equal-to-manifest entries are stale; none here qualify.
  assert.deepEqual(findStaleReleaseAs(config, manifest), []);
});
