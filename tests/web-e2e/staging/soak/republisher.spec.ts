/**
 * The republisher counters on staging, from Grafana Cloud. Within 12 hours of
 * an API start every counter check skips as `post-deploy-window`, and only
 * past it does the owner ledger open, for the stale-names baseline.
 */

import { FilesPage } from '../../page-objects/files.page';
import {
  COUNTER_CHECKS,
  countersLine,
  grafanaAccess,
  inPostDeployWindow,
  query,
  readCounters,
  staleBaseline,
  UPTIME_QUERY,
  uptimeLine,
  uptimeSeconds,
  withStaleBaseline,
} from './counters';
import { check, fact, skipped, test } from './fixtures';
import { SoakFailure } from './reasons';
import { openLedger, writeLedger } from './vault';

/** Queries 2, owner sign-in 18, ledger 8. */
const TEST_MS = 1_800_000;
const QUERY_MS = 30_000;

test('the republisher counters hold over 24 hours', async ({ freshOwner }) => {
  test.setTimeout(TEST_MS);
  const access = await check('Grafana access', 'counters-unread', async () =>
    grafanaAccess(process.env)
  );
  const uptime = await check('API uptime', 'counters-unread', async () =>
    uptimeSeconds(await query(access, UPTIME_QUERY, QUERY_MS))
  );
  await fact('API uptime', uptimeLine(uptime));
  if (inPostDeployWindow(uptime)) {
    for (const entry of COUNTER_CHECKS) {
      await skipped(entry.check, 'post-deploy-window', uptimeLine(uptime));
    }
    return;
  }

  const readings = await check('republisher counters', 'counters-unread', () =>
    readCounters(access, QUERY_MS)
  );
  await fact('republisher counters', countersLine(readings));

  const files = new FilesPage(await freshOwner());
  const baseline = await check('stale-names baseline', 'ledger-unreadable', async () => {
    const ledger = await openLedger(files, 'owner');
    const held = staleBaseline(ledger);
    if (held !== null) return held;
    const next = withStaleBaseline(ledger, readings.staleNames);
    await writeLedger(files, next);
    const recorded = staleBaseline(next)!;
    await fact('stale-names baseline', `recorded ${recorded} on the first reading`);
    return recorded;
  });

  let first: unknown = null;
  for (const entry of COUNTER_CHECKS) {
    await check(entry.check, entry.reason, async () => {
      const failure = entry.verdict(readings, baseline);
      if (failure !== null) throw new SoakFailure(entry.reason, failure);
    }).catch((error: unknown) => {
      first ??= error;
    });
  }
  if (first !== null) throw first;
});
