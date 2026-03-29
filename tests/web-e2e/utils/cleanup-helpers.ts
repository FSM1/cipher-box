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
    const result = await page.evaluate(async () => {
      // Discover API URL from app runtime config or derive from page origin
      const apiUrl =
        (window as unknown as Record<string, string>).__VITE_API_URL ||
        document.querySelector('meta[name="api-url"]')?.getAttribute('content') ||
        (window.location.origin.includes('app-staging.')
          ? window.location.origin.replace('app-staging.', 'api-staging.')
          : window.location.origin.includes('app.')
            ? window.location.origin.replace('app.', 'api.')
            : 'http://localhost:3000');

      // Refresh to get access token (uses HTTP-only cookie)
      const refreshRes = await fetch(`${apiUrl}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
      });
      if (!refreshRes.ok) return { ok: false, step: 'refresh', status: refreshRes.status };
      const { accessToken } = await refreshRes.json();

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
    });

    if (!result.ok) {
      console.warn(`[cleanup] Account deletion failed at ${result.step}: HTTP ${result.status}`);
    }
  } catch (err) {
    console.warn('[cleanup] Account deletion error (best-effort):', err);
  }
}
