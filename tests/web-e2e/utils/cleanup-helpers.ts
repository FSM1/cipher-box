import type { Page } from '@playwright/test';

/**
 * Delete the currently-logged-in account by calling the API from within
 * the page context.
 *
 * Uses fetch with credentials to send the refresh-token cookie, obtains
 * a fresh access token, then calls DELETE /auth/account.
 *
 * This helper is designed for afterAll teardown -- it catches ALL errors
 * and logs warnings instead of throwing, so test failures are never
 * masked by cleanup issues.
 */
export async function deleteAccountViaPage(page: Page): Promise<void> {
  try {
    // Discover the API base URL from the app's runtime config
    const apiBase = await page.evaluate(() => {
      return (
        (window as unknown as Record<string, string>).__VITE_API_URL ||
        document.querySelector('meta[name="api-url"]')?.getAttribute('content') ||
        'http://localhost:3000'
      );
    });

    const result = await page.evaluate(async (apiUrl: string) => {
      // Step 1: Refresh to get a fresh access token (uses HTTP-only cookie)
      const refreshRes = await fetch(`${apiUrl}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!refreshRes.ok) return { ok: false, step: 'refresh', status: refreshRes.status };
      const { accessToken } = await refreshRes.json();

      // Step 2: Delete the account
      const deleteRes = await fetch(`${apiUrl}/auth/account`, {
        method: 'DELETE',
        credentials: 'include',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ confirmation: 'DELETE' }),
      });
      return { ok: deleteRes.ok, step: 'delete', status: deleteRes.status };
    }, apiBase);

    if (!result.ok) {
      console.warn(
        `[cleanup] Account deletion failed at ${result.step}: HTTP ${result.status}`
      );
    }
  } catch (err) {
    console.warn('[cleanup] Account deletion error (best-effort):', err);
  }
}
