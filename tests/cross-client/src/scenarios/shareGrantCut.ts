/**
 * A grant issued in the web host, read at the desktop mount, and cut again.
 *
 * The nocache manual refresh is the only barrier: nothing here waits on the
 * poll cadence, and nothing sleeps (blueprint/testing.md "The DX hook").
 */

import { strict as assert } from 'node:assert';
import { expect } from '@playwright/test';
import { FOLDER, grantOneFolder, standing } from '../share';
import { projects } from '../scenario';
import type { Scenario, ScenarioContext } from '../scenario';

export const shareGrantCut: Scenario = {
  name: 'share-grant-cut',
  async run(context: ScenarioContext) {
    const { mount, owner, grantee, scope } = await grantOneFolder(context);

    const granted = await mount.status();
    assert.equal(granted.deadLetters, 0, 'the scope cut dead-letters nothing at the mount');
    assert.deepEqual(granted.warnings, [], 'the scope cut raises no warning at the mount');
    assert.equal(granted.mount.state, 'mounted', 'the scope cut keeps the mount');

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
    await projects(context, mount.mountRoot, FOLDER);
    const cut = await mount.status();
    assert.equal(cut.deadLetters, 0, 'the revocation rotation dead-letters nothing at the mount');
    assert.deepEqual(cut.warnings, [], 'the revocation rotation raises no warning at the mount');
    assert.equal(cut.mount.state, 'mounted', 'the revocation rotation keeps the mount');
  },
};
