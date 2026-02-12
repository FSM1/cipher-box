import { Web3AuthMPCCoreKit, WEB3AUTH_NETWORK, COREKIT_STATUS } from '@web3auth/mpc-core-kit';
import { tssLib } from '@toruslabs/tss-dkls-lib';

const environment = import.meta.env.VITE_ENVIRONMENT || 'local';

const NETWORK_MAP: Record<string, (typeof WEB3AUTH_NETWORK)[keyof typeof WEB3AUTH_NETWORK]> = {
  local: WEB3AUTH_NETWORK.DEVNET,
  ci: WEB3AUTH_NETWORK.DEVNET,
  staging: WEB3AUTH_NETWORK.DEVNET,
  production: WEB3AUTH_NETWORK.MAINNET,
};

let instance: Web3AuthMPCCoreKit | null = null;

/**
 * Get or create the singleton Core Kit instance.
 * Safe to call multiple times -- returns the same instance.
 */
export function getCoreKit(): Web3AuthMPCCoreKit {
  if (!instance && typeof window !== 'undefined') {
    instance = new Web3AuthMPCCoreKit({
      web3AuthClientId: import.meta.env.VITE_WEB3AUTH_CLIENT_ID,
      web3AuthNetwork: NETWORK_MAP[environment] || WEB3AUTH_NETWORK.DEVNET,
      storage: window.localStorage,
      manualSync: true, // Explicit commitChanges() after mutations
      tssLib,
    });
  }
  return instance!;
}

/**
 * Initialize Core Kit. Checks for existing sessions (auto-login).
 * Returns the resulting COREKIT_STATUS after initialization.
 */
export async function initCoreKit(): Promise<COREKIT_STATUS> {
  const ck = getCoreKit();
  await ck.init();
  return ck.status;
}

export { COREKIT_STATUS };
export type { Web3AuthMPCCoreKit };
