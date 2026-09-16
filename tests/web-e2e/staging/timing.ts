/**
 * The committed baseline and the verdict against it. Staging is the only
 * environment where these numbers mean anything, so the run writes what it
 * measured beside the report.
 *
 * The ceiling is generous on purpose: this catches an order-of-magnitude
 * regression — a login that now waits on a timeout, a publish that no longer
 * lands — not the noise of a 2-vCPU box behind a CDN.
 */

import { expect, type TestInfo } from '@playwright/test';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const BASELINE = join(HERE, '..', 'baselines', 'staging-journey-timing.json');
const MEASURED = join(HERE, '..', 'test-results');

interface Baseline {
  readonly journeys: Record<string, { readonly baseline_ms: number; readonly ceiling_ms: number }>;
}

/** Records `journeys` beside the report, then holds each to its ceiling. */
export async function recordJourneys(
  testInfo: TestInfo,
  journeys: Record<string, number>
): Promise<void> {
  const baseline: Baseline = JSON.parse(await readFile(BASELINE, 'utf8'));
  const measured = {
    captured: new Date().toISOString(),
    baseUrl: testInfo.project.use.baseURL,
    journeys,
  };

  const body = JSON.stringify(measured, null, 2);
  const name = `staging-journey-${Object.keys(journeys).sort().join('-')}`;
  await mkdir(MEASURED, { recursive: true });
  await writeFile(join(MEASURED, `${name}.json`), body);
  await testInfo.attach(name, { body, contentType: 'application/json' });

  for (const [journey, ms] of Object.entries(journeys)) {
    const held = baseline.journeys[journey];
    expect(held, `the baseline names no ${journey}`).toBeDefined();
    expect(
      ms,
      `${journey} took ${ms}ms against a ${held.ceiling_ms}ms ceiling, ${held.baseline_ms}ms when captured`
    ).toBeLessThan(held.ceiling_ms);
  }
}
