import { expect, type Page } from '@playwright/test';
import type { IntrospectedView, Plain } from '@web/engine/introspection';
import { fromHex, type EventDescriptor } from '@cipherbox/client';

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
        { timeout: 60_000 }
      )
      .toBe(true);
    return latest;
  }

  /**
   * The same wait, after forcing one resolve-and-drain pass. A queued write
   * publishes on a pass and this bundle carries the shipped 30 s cadence, so
   * the footer's refresh control is what keeps a write assertion bounded by
   * the engine's work rather than by that cadence. Exactly one pass: a second
   * forced while the first is in flight displaces it, and the queue drains on
   * neither.
   */
  async settledNow(): Promise<IntrospectedView> {
    await this.page.getByTestId('status-indicator').click();
    return this.settled();
  }

  /**
   * The plaintext the engine reads back for one child of the root, straight off
   * the network. The preview decodes as UTF-8 — only these bytes can tell a byte
   * the round trip changed from one the decoder folded away.
   */
  async read(name: string): Promise<Uint8Array> {
    const { view } = await this.settled();
    const child = view.children.find((entry) => entry.name === name);
    expect(child, `the root lists no ${name}`).toBeDefined();
    return fromHex(
      await this.page.evaluate((node) => window.__CIPHERBOX_ENGINE__!.download(node), child!.id)
    );
  }

  /** Every engine event the tab has seen so far. */
  events(): Promise<Plain<EventDescriptor>[]> {
    return this.page.evaluate(() => window.__CIPHERBOX_ENGINE__!.events());
  }
}
