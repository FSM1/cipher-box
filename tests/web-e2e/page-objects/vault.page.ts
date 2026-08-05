import { randomBytes } from 'node:crypto';
import type { JSHandle, Page } from '@playwright/test';
import type { IntrospectedView, Plain } from '@web/engine/introspection';
import type { EventDescriptor } from '@cipherbox/client';

/**
 * One browser tab over one vault, driven through the DEV introspection hook
 * (blueprint/testing.md "E2E"). Every wait here polls engine state, so the
 * suite carries no sleeps and no network-idle guesses.
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
   * no fixture setup. The engine lives in this document, so the suite never
   * navigates the tab across a load once it holds a session.
   */
  async coldStart(): Promise<void> {
    const secret = randomBytes(32).toString('hex');
    await this.page.evaluate(
      (loginSecretHex) => window.__CIPHERBOX_ENGINE__!.signIn(loginSecretHex),
      secret
    );
    await this.page.waitForURL('**/files');
  }

  /** The engine's view of `folder`, once it reports the vault settled. */
  async settled(folder: string | null = null): Promise<IntrospectedView> {
    // `waitForFunction` settles only on a truthy value, so the null the poll
    // returns while unsettled never reaches the caller.
    const handle = (await this.page.waitForFunction(async (target: string | null) => {
      const answer = await window.__CIPHERBOX_ENGINE__!.snapshot(target);
      return answer.settled ? answer : null;
    }, folder)) as JSHandle<IntrospectedView>;
    return handle.jsonValue();
  }

  /** Every engine event the tab has seen so far. */
  events(): Promise<Plain<EventDescriptor>[]> {
    return this.page.evaluate(() => window.__CIPHERBOX_ENGINE__!.events());
  }
}
