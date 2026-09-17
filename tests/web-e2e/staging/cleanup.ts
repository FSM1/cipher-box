/**
 * Removal of the account a run mints. `DELETE /account` (blueprint/api.md
 * Registry) takes a full session bearer, and on a deployed bundle only the tab
 * holds one — so the removal runs inside the page, off the refresh cookie the
 * login left, and never carries a token back out to the test process.
 */

import type { Page } from '@playwright/test';

/** What the removal did, in words safe to attach to a public artifact. */
export interface RemovalOutcome {
  readonly removed: boolean;
  readonly detail: string;
}

/**
 * The API origin this tab talks to. A deployed bundle bakes it in and publishes
 * it nowhere, so the suite reads it off the first authentication call instead of
 * guessing a host name from the front's.
 */
export function watchApiOrigin(page: Page): () => string | null {
  let origin: string | null = null;
  page.on('request', (request) => {
    if (origin !== null) return;
    const url = new URL(request.url());
    if (url.pathname.startsWith('/auth/')) origin = url.origin;
  });
  return () => origin;
}

export async function removeAccount(page: Page, apiOrigin: string | null): Promise<RemovalOutcome> {
  if (page.isClosed()) return { removed: false, detail: 'the page closed before the removal' };
  if (apiOrigin === null) {
    return { removed: false, detail: 'no authentication call named an API origin' };
  }
  try {
    return await page.evaluate(async (base) => {
      const rotated = await fetch(`${base}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      });
      if (!rotated.ok) {
        return { removed: false, detail: `refresh answered ${rotated.status}` };
      }
      const { accessToken } = (await rotated.json()) as { accessToken?: string };
      if (typeof accessToken !== 'string' || accessToken === '') {
        return { removed: false, detail: 'refresh answered no access token' };
      }
      const deleted = await fetch(`${base}/account`, {
        method: 'DELETE',
        credentials: 'include',
        headers: { authorization: `Bearer ${accessToken}` },
      });
      return { removed: deleted.ok, detail: `delete answered ${deleted.status}` };
    }, apiOrigin);
  } catch (error) {
    return { removed: false, detail: error instanceof Error ? error.message : String(error) };
  }
}
