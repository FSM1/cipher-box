/**
 * The write half of a promoted scope root: the mutations the *mount* makes
 * inside a folder a grant promoted, on the device that did not mint that grant.
 *
 * The tab cuts the grant, so the mount seeded no write-epoch floor for the scope
 * and takes it from the scope pointer instead (blueprint/engine.md "Floor law",
 * item 3).
 */

import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { FOLDER, dropsFromScope, grantOneFolder, listsInScope, standing } from '../share';
import { dropsFromFolder, listsAtRoot, listsInFolder, mountHeld } from '../scenario';
import type { Scenario, ScenarioContext } from '../scenario';

const OUTSIDE = 'made-outside';
const INSIDE = 'made-by-the-mount';
/** Stays through the delete, so a listing that never landed cannot read as one. */
const SURVIVOR = 'kept-by-the-mount';

export const mountWriteInPromotedScope: Scenario = {
  name: 'mount-write-in-promoted-scope',
  async run(context: ScenarioContext) {
    const { mount, owner, grantee, scope } = await grantOneFolder(context);

    // The control separates a mount that publishes nothing from a mount that
    // publishes everywhere except below a root it did not promote.
    await mkdir(join(mount.mountRoot, OUTSIDE));
    await mount.refresh();
    await listsAtRoot(context, owner, OUTSIDE);
    context.log('the mount published outside the promoted root');

    await mkdir(join(mount.mountRoot, FOLDER, SURVIVOR));
    await mkdir(join(mount.mountRoot, FOLDER, INSIDE));
    await mount.refresh();
    await listsInFolder(context, owner, FOLDER, INSIDE);
    await listsInScope(context, grantee, scope, INSIDE);
    context.log('the mount published inside the promoted root');

    await rm(join(mount.mountRoot, FOLDER, INSIDE), { recursive: true });
    await mount.refresh();
    await dropsFromFolder(context, owner, FOLDER, INSIDE, SURVIVOR);
    await dropsFromScope(context, grantee, scope, INSIDE, SURVIVOR);
    context.log('the mount published a delete inside the promoted root');

    // Neither write cut the grantee off: it still holds the scope it accepted.
    await standing(context, grantee, scope, 'granted');

    mountHeld(await mount.status(), 'the mount writes');
  },
};
