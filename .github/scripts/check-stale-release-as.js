// @ts-check
/**
 * Stale release-as guard.
 *
 * release-please uses a per-package `release-as` pin in release-please-config.json
 * to force the next version. Once that version actually ships, its value in
 * `.release-please-manifest.json` catches up — and a `release-as` left EQUAL to
 * the manifest version makes release-please "release" an already-shipped version,
 * producing a self-comparing changelog loop (vX..vX). This guard fails CI whenever
 * any `release-as` equals its manifest version so the stale pin is caught early
 * (T-53-05 / D-07).
 *
 * A `release-as` that is strictly AHEAD of the manifest is a real, pending release
 * target and is left alone. A package with no `release-as`, or one missing from
 * the manifest, is never flagged.
 *
 * CLI: node .github/scripts/check-stale-release-as.js
 *   exits 1 (printing `STALE: ...` lines) if any pin is stale, else exits 0.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const CONFIG_PATH = 'release-please-config.json';
const MANIFEST_PATH = '.release-please-manifest.json';

/**
 * Pure comparison: returns the release-as pins that equal their manifest version.
 *
 * @param {{ packages?: Record<string, { 'release-as'?: string }> }} config
 * @param {Record<string, string>} manifest
 * @returns {{ pkgPath: string, version: string }[]}
 */
export function findStaleReleaseAs(config, manifest) {
  const packages = config.packages ?? {};
  /** @type {{ pkgPath: string, version: string }[]} */
  const stale = [];

  for (const [pkgPath, pkg] of Object.entries(packages)) {
    const releaseAs = pkg?.['release-as'];
    if (releaseAs === undefined) {
      continue; // no pin -> nothing to compare
    }
    const manifestVersion = manifest[pkgPath];
    if (manifestVersion === undefined) {
      continue; // not yet tracked in the manifest -> not stale
    }
    if (releaseAs === manifestVersion) {
      stale.push({ pkgPath, version: releaseAs });
    }
  }

  return stale;
}

/**
 * CLI entry: read config + manifest from disk, print findings, set exit code.
 */
function main() {
  const config = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));

  const stale = findStaleReleaseAs(config, manifest);

  if (stale.length > 0) {
    for (const { pkgPath, version } of stale) {
      console.error(`STALE: ${pkgPath} release-as=${version} == manifest=${version}`);
    }
    console.error(
      `\nFound ${stale.length} stale release-as pin(s). Remove the release-as key for each ` +
        `(its version already shipped) so release-please does not self-compare.`
    );
    process.exit(1);
  }

  console.log('No stale release-as entries found.');
  process.exit(0);
}

// Run the CLI only when executed directly, so the test can import the pure
// function without triggering process.exit.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
