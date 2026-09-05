/**
 * A grant cut promotes a folder into a scope root of its own. This is the
 * owner's own mount reading what the owner's own tab publishes below that root.
 *
 * The promoted root carries a grant section and lives at its own `ipnsName`, so
 * the mount reaches it only through the gated descent into a child scope root
 * (blueprint/engine.md "Eager set and scope roots").
 */

import { join } from 'node:path';
import { FOLDER, grantOneFolder, listsInScope } from '../share';
import { mountHeld, projects } from '../scenario';
import type { Scenario, ScenarioContext } from '../scenario';

const INSIDE = 'published-by-the-tab';

export const nestedScopeUnderMount: Scenario = {
  name: 'nested-scope-under-mount',
  async run(context: ScenarioContext) {
    const { mount, owner, grantee, scope } = await grantOneFolder(context);

    await owner.files.open(FOLDER);
    await owner.files.createFolder(INSIDE);
    await owner.vault.settled();
    await owner.openFiles();
    context.log(`the owner's tab published ${INSIDE} inside the granted scope`);

    // One nocache pass is the whole barrier: the mount holds the scope root's
    // own read seed once the descent proves it, so nothing else has to happen.
    await mount.refresh();
    await projects(context, mount, INSIDE, join(mount.mountRoot, FOLDER));

    mountHeld(await mount.status(), 'the nested scope read');

    // The grantee holds the same scope root under its own grant, so the owner's
    // write below it reaches the grantee on the grantee's own next pass.
    await listsInScope(context, grantee, scope, INSIDE);
  },
};
