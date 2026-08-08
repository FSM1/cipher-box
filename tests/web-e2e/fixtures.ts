import { test as base } from '@playwright/test';

export { expect } from '@playwright/test';

/**
 * A browser target that dies mid-test surfaces only as whatever call was in
 * flight, and Playwright salvages no browser-side artifact from it. These taps
 * record the browser's account while the page is alive and name the death.
 */
export const test = base.extend({
  page: async ({ page }, use, testInfo) => {
    const started = Date.now();
    const events: string[] = [];
    let died: string | undefined;

    const record = (event: string) => events.push(`${Date.now() - started}ms ${event}`);

    page.on('console', (message) => record(`console.${message.type()}: ${message.text()}`));
    page.on('pageerror', (error) => record(`pageerror: ${error.message}`));
    page.on('requestfailed', (request) =>
      record(`requestfailed: ${request.url()} ${request.failure()?.errorText ?? ''}`)
    );
    page.on('crash', () => {
      died ??= 'the page crashed';
      record('crash');
    });
    page.on('close', () => {
      died ??= 'the page closed';
      record('close');
    });

    await use(page);

    if (testInfo.status === testInfo.expectedStatus) return;
    await testInfo.attach('browser-events', {
      body: events.join('\n'),
      contentType: 'text/plain',
    });
    if (died) throw new Error(`${died} during the test; the failure above is a symptom of that`);
  },
});
