/**
 * The `/shared` route. A cold-started vault has accepted nothing, so this gates
 * the route, its sidebar link, the read landing empty rather than unread, and
 * the re-read the sharing scenarios use as their barrier.
 */

import { expect, test } from '../fixtures';
import { SharedPage } from '../page-objects/shared.page';
import { coldStart } from '../vault';

test('a fresh vault reads an accepted list that landed empty', async ({ page }) => {
  await coldStart(page);
  const shared = new SharedPage(page);

  await shared.open();

  await expect(shared.empty).toBeVisible();
  await expect(shared.list).toHaveCount(0);
  await expect(shared.error).toHaveCount(0);
  // An empty accepted list is no member's problem: it raises no warning.
  await expect(shared.warnings).toHaveCount(0);

  await shared.readAgain();

  await expect(shared.empty).toBeVisible();
  await expect(shared.error).toHaveCount(0);
});
