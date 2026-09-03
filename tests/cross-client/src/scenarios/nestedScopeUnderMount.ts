/**
 * A grant cut promotes a folder into a scope root of its own. This is the
 * owner's own mount reading what the owner's own tab publishes below that root.
 *
 * The promoted root carries a grant section and lives at its own `ipnsName`, so
 * the mount reaches it only through the gated descent into a child scope root
 * (blueprint/engine.md "Eager set and scope roots").
 */

import { strict as assert } from 'node:assert';
import { join } from 'node:path';
import { FOLDER, grantOneFolder, listsInScope } from '../share';
import { projects } from '../scenario';
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
    await projects(context, join(mount.mountRoot, FOLDER), INSIDE);

    const read = await mount.status();
    assert.equal(read.deadLetters, 0, 'the nested scope read dead-letters nothing at the mount');
    assert.deepEqual(read.warnings, [], 'the nested scope read raises no warning at the mount');
    assert.equal(read.mount.state, 'mounted', 'the nested scope read keeps the mount');

    // The grantee holds the same scope root under its own grant, so the owner's
    // write below it reaches the grantee on the grantee's own next pass.
    await listsInScope(context, grantee, scope, INSIDE);
  },
};
