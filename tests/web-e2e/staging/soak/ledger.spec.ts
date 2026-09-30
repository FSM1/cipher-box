/** The soak ledgers: a bootstrap run builds both, and every run reads both back. */

import type { Page } from '@playwright/test';
import { FilesPage } from '../../page-objects/files.page';
import type { SoakRole } from './accounts';
import { bootstrapRequested, planRun } from './bootstrap';
import { check, fact, test } from './fixtures';
import { markers, utcDay } from './ledger';
import { SoakFailure } from './reasons';
import { bootstrapVault, inspectVault, ledgerPath, readLedger } from './vault';

const bootstrap = bootstrapRequested(process.env);

async function ledgerChecks(page: Page, role: SoakRole): Promise<void> {
  const files = new FilesPage(page);
  const { found, plan } = await check(`${role} vault`, 'ledger-unreadable', async () => {
    const found = await inspectVault(files, role);
    const plan = planRun(bootstrap, found);
    if (plan.kind === 'refuse') {
      throw new SoakFailure(plan.reason, `the ${role} vault has no ${ledgerPath(role)}`);
    }
    return { found, plan };
  });
  if (plan.kind === 'bootstrap') {
    await check(`${role} bootstrap`, 'bootstrap-failed', () =>
      bootstrapVault(files, role, found, utcDay(new Date()))
    );
  }
  await check(`${role} ledger`, 'ledger-unreadable', async () => {
    const ledger = await readLedger(files);
    await fact(`${role} ledger markers`, String(markers(ledger).length));
  });
}

test('the owner vault carries the soak ledger', async ({ owner }) => {
  await ledgerChecks(owner, 'owner');
});

test('the grantee vault carries the desktop ledger', async ({ grantee }) => {
  await ledgerChecks(await grantee(), 'grantee');
});
