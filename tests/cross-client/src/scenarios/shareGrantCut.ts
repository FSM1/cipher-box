/**
 * A grant issued in the web host, read at the desktop mount, and cut again.
 *
 * The nocache manual refresh is the only barrier: nothing here waits on the
 * poll cadence, and nothing sleeps (blueprint/testing.md "The DX hook").
 */

import { expect } from '@playwright/test';
import { FOLDER, grantOneFolder, standing } from '../share';
import { mountHeld, projects } from '../scenario';
import type { Scenario, ScenarioContext } from '../scenario';

export const shareGrantCut: Scenario = {
  name: 'share-grant-cut',
  async run(context: ScenarioContext) {
    const { mount, owner, grantee, scope } = await grantOneFolder(context);

    mountHeld(await mount.status(), 'the scope cut');

    // The grantee holds the scope, so it browses the shared subtree the accept
    // grafted beside its own root.
    await grantee.shared.openShare(scope);
    await expect(grantee.files.browser).toBeVisible();

    // The cut: the owner revokes the one grant, and the grantee discovers it on
    // its next pass rather than being told.
    await owner.share.open(FOLDER);
    await owner.share.revoke.click();
    await expect(owner.share.noGrants).toBeVisible();
    await expect(owner.share.error).toHaveCount(0);
    await owner.share.close();
    await owner.vault.settled();
    context.log('the owner revoked the grant');

    await standing(context, grantee, scope, 'revocation-signal');

    // A revocation rotates the scope. The owner's own mount reads across that
    // rotation in one pass, and still holds the folder it granted.
    await mount.refresh();
    await projects(context, mount, FOLDER);
    mountHeld(await mount.status(), 'the revocation rotation');
  },
};
