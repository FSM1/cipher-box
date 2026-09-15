/**
 * Profile: journey timing. Staging is the only environment where these numbers
 * mean anything, so the committed baseline is the reference and the run writes
 * what it measured beside the report.
 *
 * The ceiling is generous on purpose: this catches an order-of-magnitude
 * regression — a login that now waits on a timeout, a publish that no longer
 * lands — not the noise of a 2-vCPU box behind a CDN.
 */

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FilesPage } from '../page-objects/files.page';
import { expect, signIn, test } from './fixtures';

const HERE = dirname(fileURLToPath(import.meta.url));
const BASELINE = join(HERE, '..', 'baselines', 'staging-journey-timing.json');
const MEASURED = join(HERE, '..', 'test-results', 'staging-journey-timing.json');

interface Baseline {
  readonly journeys: Record<string, { readonly baseline_ms: number; readonly ceiling_ms: number }>;
}

test('the journeys stay within the committed baseline', async ({ page }, testInfo) => {
  const files = new FilesPage(page);
  const baseline: Baseline = JSON.parse(await readFile(BASELINE, 'utf8'));

  const loginToVault = await signIn(page);

  const started = Date.now();
  await files.upload('timing.bin', new Uint8Array(16 * 1024).fill(7));
  await expect(files.row('timing.bin')).toBeVisible({ timeout: 180_000 });
  const uploadToVisible = Date.now() - started;

  const measured = {
    captured: new Date().toISOString(),
    baseUrl: testInfo.project.use.baseURL,
    journeys: { login_to_vault_ms: loginToVault, upload_to_visible_ms: uploadToVisible },
  };
  await mkdir(dirname(MEASURED), { recursive: true });
  const body = JSON.stringify(measured, null, 2);
  await writeFile(MEASURED, body);
  await testInfo.attach('staging-journey-timing', { body, contentType: 'application/json' });

  for (const [journey, ms] of Object.entries(measured.journeys)) {
    const { baseline_ms, ceiling_ms } = baseline.journeys[journey];
    expect(
      ms,
      `${journey} took ${ms}ms against a ${ceiling_ms}ms ceiling, ${baseline_ms}ms when captured`
    ).toBeLessThan(ceiling_ms);
  }
});
