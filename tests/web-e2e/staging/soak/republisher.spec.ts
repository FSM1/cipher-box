/**
 * The republisher counters on staging, from Grafana Cloud. A counter check
 * that the API uptime does not yet cover skips as `post-deploy-window`, and
 * only a night with a due check opens the owner ledger, for the stale-names
 * baseline.
 */

import { FilesPage } from '../../page-objects/files.page';
import {
  anyCounterDue,
  baselineDue,
  counterPlan,
  countersLine,
  grafanaAccess,
  query,
  readCounters,
  staleBaseline,
  UPTIME_QUERY,
  uptimeLine,
  uptimeSeconds,
  withStaleBaseline,
  type CounterReadings,
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

  let readings: CounterReadings | null = null;
  let baseline: number | null = null;
  if (anyCounterDue(uptime)) {
    const read = await check('republisher counters', 'counters-unread', () =>
      readCounters(access, QUERY_MS)
    );
    readings = read;
    await fact('republisher counters', countersLine(read));

    const files = new FilesPage(await freshOwner());
    baseline = await check('stale-names baseline', 'ledger-unreadable', async () => {
      const ledger = await openLedger(files, 'owner');
      const held = staleBaseline(ledger);
      if (held !== null || !baselineDue(uptime)) return held;
      const next = withStaleBaseline(ledger, read.staleNames);
      await writeLedger(files, next);
      const recorded = staleBaseline(next)!;
      await fact('stale-names baseline', `recorded ${recorded} on the first reading`);
      return recorded;
    });
  }

  let first: unknown = null;
  for (const plan of counterPlan(uptime, baseline)) {
    const { entry } = plan;
    if (plan.kind === 'skip') {
      await skipped(entry.check, 'post-deploy-window', plan.detail);
      continue;
    }
    const read = readings!;
    await check(entry.check, entry.reason, async () => {
      const failure = entry.verdict(read, plan.baseline);
      if (failure !== null) throw new SoakFailure(entry.reason, failure);
    }).catch((error: unknown) => {
      first ??= error;
    });
  }
  if (first !== null) throw first;
});
