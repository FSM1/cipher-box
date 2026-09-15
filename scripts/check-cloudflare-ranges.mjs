#!/usr/bin/env node
/**
 * The nightly Cloudflare Range Watch (blueprint/deploy.md, Scheduled tier).
 *
 * The Lint gate pins `docker/Caddyfile` to the committed snapshot, so it catches
 * an EDIT to the trusted set but not Cloudflare changing that set upstream. This
 * diff closes the other direction.
 *
 * Usage: `node scripts/check-cloudflare-ranges.mjs`. Needs network access.
 */

import { CLOUDFLARE_RANGES } from './cloudflare-ranges.mjs';

const SOURCE = 'https://api.cloudflare.com/client/v4/ips';
const ATTEMPTS = 3;
const RETRY_DELAY_MS = 5000;

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/** The live set, or a throw — an unreachable source is a failure, never a pass. */
async function fetchPublishedRanges() {
  let last;
  for (let attempt = 1; attempt <= ATTEMPTS; attempt += 1) {
    try {
      const response = await fetch(SOURCE, { headers: { accept: 'application/json' } });
      if (!response.ok) throw new Error(`${SOURCE} answered ${response.status}`);
      const payload = await response.json();
      if (payload?.success !== true) throw new Error(`${SOURCE} reported success=false`);
      const ipv4 = payload.result?.ipv4_cidrs;
      const ipv6 = payload.result?.ipv6_cidrs;
      if (!Array.isArray(ipv4) || ipv4.length === 0 || !Array.isArray(ipv6) || ipv6.length === 0) {
        throw new Error(`${SOURCE} returned no ipv4_cidrs or no ipv6_cidrs`);
      }
      return [...ipv4, ...ipv6];
    } catch (error) {
      last = error;
      if (attempt < ATTEMPTS) await sleep(RETRY_DELAY_MS);
    }
  }
  throw last;
}

let live;
try {
  live = await fetchPublishedRanges();
} catch (error) {
  console.error(`Could not read ${SOURCE}: ${error.message}`);
  process.exit(1);
}

const published = new Set(live);
const committed = new Set(CLOUDFLARE_RANGES);

const added = [...published].filter((range) => !committed.has(range)).sort();
const departed = [...committed].filter((range) => !published.has(range)).sort();

if (added.length === 0 && departed.length === 0) {
  console.log(`The committed Cloudflare ranges match ${SOURCE} — ${committed.size} ranges.`);
} else {
  console.error(`The committed Cloudflare ranges no longer match ${SOURCE}.`);
  for (const range of added) console.error(`  + ${range} (published, not trusted)`);
  for (const range of departed) console.error(`  - ${range} (trusted, no longer published)`);
  console.error(
    'Update CLOUDFLARE_RANGES in scripts/cloudflare-ranges.mjs and the trusted_proxies list in docker/Caddyfile.'
  );
  process.exitCode = 1;
}
