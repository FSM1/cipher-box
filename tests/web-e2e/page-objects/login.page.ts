import { expect, type Locator, type Page } from '@playwright/test';

/** The front door: the Core Kit methods plus the SIWE secondary. */
export class LoginPage {
  constructor(readonly page: Page) {}

  get googleButton(): Locator {
    return this.page.getByTestId('google-login-button');
  }

  get emailInput(): Locator {
    return this.page.getByTestId('email-input');
  }

  get walletButton(): Locator {
    return this.page.getByTestId('wallet-login-button');
  }

  /** The refusal banner every login method renders through `LoginError`. */
  get error(): Locator {
    return this.page.getByTestId('login-error');
  }

  /**
   * Waits until the tab either reaches the vault or draws a refusal. Answers
   * with the refusal text, or `null` once the vault won.
   */
  async refusal(timeout: number): Promise<string | null> {
    let refused: string | null = null;
    await expect
      .poll(
        async () => {
          if (new URL(this.page.url()).pathname.startsWith('/files')) return true;
          const banner = this.error.first();
          if ((await banner.count()) === 0) return false;
          refused = (await banner.innerText()).trim();
          return true;
        },
        { timeout, intervals: [2_000] }
      )
      .toBe(true);
    return refused;
  }
}
