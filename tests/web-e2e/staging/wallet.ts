/**
 * The staging suite's login path: an injected test wallet for the SIWE method.
 * A deployed bundle refuses the introspection hook (`shipsE2eHook`,
 * `apps/web/src/engine/config.ts`), so the suite signs in through a shipped
 * method, and wallet is the only one that closes with no party outside this
 * stack.
 *
 * The key never enters the page: the provider forwards `personal_sign` to a
 * Playwright binding, and viem signs it in the test process.
 */

import type { Page } from '@playwright/test';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { hexToString, type Hex } from 'viem';

/** What this wallet's row in the picker says. */
export const TEST_WALLET_NAME = 'CipherBox E2E Wallet';

const SIGN_BINDING = '__cipherboxE2eSign';

export interface TestWallet {
  readonly address: string;
  /**
   * The key that answers this wallet's signatures. It stays in the test process
   * — a second context takes it to sign in as the SAME identity subject, which
   * is what a second-device journey needs.
   */
  readonly privateKey: Hex;
}

/**
 * Installs a wallet on `page`, before any navigation. Without a key it mints
 * one nobody else holds, and a fresh key is a fresh identity subject — so a
 * fresh account over an empty vault, which is what keeps a run from inheriting
 * an earlier run's tree.
 */
export async function installTestWallet(page: Page, privateKey?: Hex): Promise<TestWallet> {
  const key = privateKey ?? generatePrivateKey();
  const account = privateKeyToAccount(key);

  await page.exposeFunction(SIGN_BINDING, (message: Hex) =>
    account.signMessage({ message: hexToString(message) })
  );

  await page.addInitScript(
    ([address, name, binding]) => {
      const provider = {
        async request({ method, params }: { method: string; params?: unknown[] }) {
          switch (method) {
            case 'eth_requestAccounts':
            case 'eth_accounts':
              return [address];
            case 'eth_chainId':
              return '0x1';
            case 'net_version':
              return '1';
            // wagmi asks for the account permission before it connects, and
            // drops it again on disconnect; a refusal here reads to the
            // connector as no provider at all.
            case 'wallet_requestPermissions':
              return [{ parentCapability: 'eth_accounts' }];
            case 'wallet_revokePermissions':
              return null;
            case 'personal_sign': {
              const sign = (window as unknown as Record<string, (data: string) => Promise<string>>)[
                binding
              ];
              return sign(params![0] as string);
            }
            default:
              throw Object.assign(new Error(`the test wallet does not answer ${method}`), {
                code: 4200,
              });
          }
        },
        on() {},
        removeListener() {},
      };

      // Announced under its own name, and left on `window.ethereum` as well:
      // the app discovers announcements only beside a legacy provider.
      Object.defineProperty(window, 'ethereum', { value: provider, configurable: true });
      const detail = Object.freeze({
        info: {
          uuid: crypto.randomUUID(),
          name,
          rdns: 'cc.cipherbox.e2e',
          icon: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=',
        },
        provider,
      });
      const announce = () =>
        window.dispatchEvent(new CustomEvent('eip6963:announceProvider', { detail }));
      window.addEventListener('eip6963:requestProvider', announce);
      announce();
    },
    [account.address, TEST_WALLET_NAME, SIGN_BINDING] as const
  );

  return { address: account.address, privateKey: key };
}
