import type { Locator, Page } from '@playwright/test';

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
}
