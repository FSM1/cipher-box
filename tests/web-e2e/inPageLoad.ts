import type { Page } from '@playwright/test';

/**
 * A document load that the page runs itself, to `target` or as a reload.
 * `page.goto` and `page.reload` print the URL in their errors and call logs,
 * and an invite URL carries the bearer fragment. The `load` wait is armed
 * before the load starts, and it logs no URL; a caller starts its locator
 * waits after it, because a locator wait that spans a load logs
 * `navigated to <url>`.
 */
export async function loadInPage(
  page: Page,
  target: URL | 'reload',
  timeout?: number
): Promise<void> {
  await Promise.all([
    page.waitForEvent('load', { timeout }),
    // Deferred, so `evaluate` returns before the load destroys its context.
    page.evaluate(
      (href) => {
        setTimeout(() => {
          if (href === null) window.location.reload();
          else window.location.assign(href);
        });
      },
      target === 'reload' ? null : target.href
    ),
  ]);
}
