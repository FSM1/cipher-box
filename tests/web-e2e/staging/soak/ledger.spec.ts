/**
 * The soak ledgers. A bootstrap run (`SOAK_BOOTSTRAP=true`) builds both; any
 * other run reads both back, and fails as `unbootstrapped-or-wiped` when one is
 * gone.
 */

import { bootstrapRequested } from './bootstrap';
import { check, fact, test } from './fixtures';
import { markers, utcDay } from './ledger';
import { openLedger } from './vault';

const bootstrap = bootstrapRequested(process.env);

test('the owner vault carries the soak ledger', async ({ owner }) => {
  await check('owner ledger', 'ledger-unreadable', async () => {
    const ledger = await openLedger(owner, 'owner', bootstrap, utcDay(new Date()));
    await fact('owner ledger markers', String(markers(ledger).length));
  });
});

test('the grantee vault carries the desktop ledger', async ({ grantee }) => {
  const page = await grantee();
  await check('grantee ledger', 'ledger-unreadable', async () => {
    const ledger = await openLedger(page, 'grantee', bootstrap, utcDay(new Date()));
    await fact('grantee ledger markers', String(markers(ledger).length));
  });
});
