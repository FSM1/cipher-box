import { expect, type Locator, type Page } from '@playwright/test';

/** The refusal text of a `signed-out` outcome. */
export const RETURNED_TO_SIGN_IN = 'returned to sign-in without an error';

/** Where a sign-in or a session resume settled. */
export type SignInOutcome =
  | { readonly kind: 'signed-in' }
  | { readonly kind: 'signed-out' }
  | { readonly kind: 'refused'; readonly text: string };

/** The refusal text of an outcome that did not sign in. */
export function refusalText(outcome: Exclude<SignInOutcome, { kind: 'signed-in' }>): string {
  return outcome.kind === 'refused' ? outcome.text : RETURNED_TO_SIGN_IN;
}

/** A disabled button belongs to a resume or a login still in flight. */
async function enabled(locator: Locator): Promise<boolean> {
  if (!(await locator.isVisible())) return false;
  return locator.isEnabled({ timeout: 1_000 }).catch(() => false);
}

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

  /** The refusal banners on the page, in order. */
  async banners(): Promise<string[]> {
    return (await this.error.allInnerTexts()).map((text) => text.trim()).filter(Boolean);
  }

  /**
   * Waits until the banners differ from `stale`: the login cleared them or drew
   * a new one. Answers the banners that are not in `stale`, so an earlier
   * refusal never classes a new one; banners that outlast `timeout` give none.
   */
  async replaced(stale: readonly string[], timeout: number): Promise<string[]> {
    if (stale.length === 0) return [];
    await expect
      .poll(() => this.banners(), { timeout, intervals: [100] })
      .not.toEqual(stale)
      .catch(() => undefined);
    const old = [...stale];
    return (await this.banners()).filter((text) => {
      const at = old.indexOf(text);
      if (at < 0) return true;
      old.splice(at, 1);
      return false;
    });
  }

  /**
   * Waits until the tab shows `signedIn`, draws a refusal, or offers an enabled
   * `signedOut` with no banner.
   */
  async outcome(signedIn: Locator, timeout: number, signedOut?: Locator): Promise<SignInOutcome> {
    const seen: { outcome?: SignInOutcome } = {};
    await expect
      .poll(
        async () => {
          if (await signedIn.isVisible()) {
            seen.outcome = { kind: 'signed-in' };
            return true;
          }
          // The button first: one update draws a refusal's banner with its button.
          const out = signedOut !== undefined && (await enabled(signedOut));
          const banners = await this.banners();
          if (banners.length > 0) {
            seen.outcome = { kind: 'refused', text: banners.join(' | ') };
            return true;
          }
          if (!out) return false;
          seen.outcome = { kind: 'signed-out' };
          return true;
        },
        { timeout, intervals: [2_000], message: 'neither signed in nor refused' }
      )
      .toBe(true);
    if (seen.outcome === undefined) throw new Error('neither signed in nor refused');
    return seen.outcome;
  }
}
