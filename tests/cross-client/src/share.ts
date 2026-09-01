/**
 * The grant every sharing scenario stands on: one folder of the owner's vault,
 * cut into a scope and granted to a second account. `WebHost` carries why a
 * grantee takes a context of its own.
 */

import { expect } from '@playwright/test';
import type { Instance } from '../../desktop-e2e/src/instance';
import { poll } from '../../desktop-e2e/src/poll';
import { passUntil, projects, rowsListed, type ScenarioContext } from './scenario';
import { nodeOf } from '../../web-e2e/vault';
import type { WebHost } from './web';

export const FOLDER = 'granted';

export interface Granted {
  mount: Instance;
  owner: WebHost;
  grantee: WebHost;
  /** The granted scope root, as the `/shared` list keys its rows. */
  scope: string;
}

/**
 * Brings up the owner's two hosts and the grantee's, then grants `FOLDER` for
 * read. Returns once the mount projects the folder across the scope cut and the
 * grantee's own pass has accepted the share.
 */
export async function grantOneFolder(context: ScenarioContext): Promise<Granted> {
  const ownerSecret = context.secret();
  const mount = await context.desktop('owner-mount', ownerSecret);
  const owner = await context.web('owner-web', ownerSecret);

  await owner.files.createFolder(FOLDER);
  const created = await owner.vault.settled();
  const scope = nodeOf(created.view, FOLDER);
  context.log(`the owner published ${FOLDER}`);

  await mount.refresh();
  await projects(context, mount.mountRoot, FOLDER);

  await owner.share.open(FOLDER);
  const link = await owner.share.mintLink();
  await owner.share.close();

  const grantee = await context.claimant('grantee-web', context.secret(), link);
  context.log('the grantee spent the link');

  // A claim asks for access and carries none: the grant is the owner's to make.
  await owner.share.open(FOLDER);
  await owner.share.convertClaimsButton.click();
  await expect(owner.share.grantRows).toHaveCount(1);
  await expect(owner.share.permission).toHaveText('read');
  await owner.share.close();

  await owner.vault.settled();
  await grantee.leaveClaim();
  await standing(context, grantee, scope, 'granted');
  context.log('the grantee accepted the share');

  // The grant cut a scope out of the owner's tree, which moves the folder's
  // record. The mount reads it back across that cut.
  await mount.refresh();
  await projects(context, mount.mountRoot, FOLDER);

  return { mount, owner, grantee, scope };
}

/** Waits for a pass at `host` to list `name` inside the shared scope `scope`. */
export function listsInScope(
  context: ScenarioContext,
  host: WebHost,
  scope: string,
  name: string
): Promise<void> {
  return passUntil(context, `${host.name} to list ${name} in the shared scope`, 1, () =>
    scopeRows(host, scope, name, null)
  );
}

/**
 * Waits for a pass at `host` to stop listing `name` inside the shared scope,
 * while it still lists `survivor`.
 */
export function dropsFromScope(
  context: ScenarioContext,
  host: WebHost,
  scope: string,
  name: string,
  survivor: string
): Promise<void> {
  return passUntil(context, `${host.name} to drop ${name} from the shared scope`, 0, () =>
    scopeRows(host, scope, name, survivor)
  );
}

/** Reads how many rows one fresh pass lists for `name` inside the shared scope. */
async function scopeRows(
  host: WebHost,
  scope: string,
  name: string,
  survivor: string | null
): Promise<number> {
  // The pass runs with the shared scope focused, because the focus window is
  // what the sync tick walks.
  await host.shared.open();
  await host.shared.readAgain();
  await host.shared.openShare(scope);
  await host.refresh();
  return rowsListed(host, name, survivor);
}

/**
 * The standing the grantee's own passes reach for one scope.
 *
 * The recipient's mailbox leg rides the nocache pass, so a refresh both accepts
 * a delivered share and classifies it.
 */
export async function standing(
  context: ScenarioContext,
  grantee: WebHost,
  scope: string,
  resolution: string
): Promise<void> {
  const row = grantee.shared.row(scope);
  await poll(
    async () => {
      // The pass runs from the vault browser, which is the route that focuses
      // the root the sync tick walks.
      await grantee.openFiles();
      await grantee.refresh();
      await grantee.shared.open();
      await grantee.shared.readAgain();
      if ((await row.count()) !== 1) return null;
      return row.getByTestId('shared-standing').getAttribute('data-resolution');
    },
    (seen) => seen === resolution,
    {
      what: `a pass at the grantee to classify the scope as ${resolution}`,
      timeoutMs: context.deadlines.refreshMs,
      intervalMs: context.deadlines.intervalMs,
    }
  );
}
