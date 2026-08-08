import { expect, type Page } from '@playwright/test';
import type { IntrospectedView, Plain } from '@web/engine/introspection';
import type { EventDescriptor } from '@cipherbox/client';

/**
 * One browser tab over one vault, driven through the introspection hook
 * (`apps/web/src/engine/introspection.ts`). Every wait here polls engine state,
 * so the suite carries no sleeps and no network-idle guesses.
 */
export class VaultPage {
  constructor(readonly page: Page) {}

  /** Loads the front door and waits for the tab to publish its engine taps. */
  async open(): Promise<void> {
    await this.page.goto('/');
    await this.page.waitForFunction(() => window.__CIPHERBOX_ENGINE__ !== undefined);
  }

  /**
   * Cold-starts a vault nobody else in the run shares and follows the app's own
   * redirect onto it. The login secret is a fresh 32-byte scalar, and the API
   * creates its account on first challenge login — so per-test isolation costs
   * no fixture setup. It is minted in the page because an `evaluate` argument is
   * recorded verbatim in the trace this suite uploads from a public repo.
   */
  async coldStart(): Promise<void> {
    await this.page.evaluate(async () => {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const hex = Array.from(secret, (byte) => byte.toString(16).padStart(2, '0')).join('');
      await window.__CIPHERBOX_ENGINE__!.signIn(hex);
    });
    await this.page.waitForURL('**/files');
  }

  /**
   * The engine's root view, once it reports the vault settled. `expect.poll`
   * rather than `waitForFunction`: the latter evaluates an async predicate
   * exactly once, because a pending promise is already truthy.
   */
  async settled(): Promise<IntrospectedView> {
    let latest!: IntrospectedView;
    await expect
      .poll(
        async () => {
          latest = await this.page.evaluate(() => window.__CIPHERBOX_ENGINE__!.snapshot());
          return latest.settled;
        },
        { timeout: 30_000 }
      )
      .toBe(true);
    return latest;
  }

  /** Every engine event the tab has seen so far. */
  events(): Promise<Plain<EventDescriptor>[]> {
    return this.page.evaluate(() => window.__CIPHERBOX_ENGINE__!.events());
  }
}
