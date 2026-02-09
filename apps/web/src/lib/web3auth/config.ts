import {
  WEB3AUTH_NETWORK,
  WALLET_CONNECTORS,
  AUTH_CONNECTION,
  type Web3AuthOptions,
} from '@web3auth/modal';

// Custom OAuth connection IDs (configured in Web3Auth dashboard)
export const AUTH_CONNECTION_IDS = {
  GOOGLE: 'cipherbox-google-oauth-2',
  EMAIL: 'cb-email-testnet',
  // Group connection that merges Google + Email (same wallet for same email)
  GROUP: 'cipherbox-grouped-connection',
} as const;

// Re-export for use in hooks
export { WALLET_CONNECTORS, AUTH_CONNECTION };

// Environment-aware Web3Auth network selection
// local/ci/staging use devnet (test keys), production uses mainnet (real keys)
const NETWORK_CONFIG: Record<string, (typeof WEB3AUTH_NETWORK)[keyof typeof WEB3AUTH_NETWORK]> = {
  local: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  ci: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  staging: WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  production: WEB3AUTH_NETWORK.SAPPHIRE_MAINNET,
};

const environment = import.meta.env.VITE_ENVIRONMENT || 'local';

export const web3AuthOptions: Web3AuthOptions = {
  clientId: import.meta.env.VITE_WEB3AUTH_CLIENT_ID || '',
  web3AuthNetwork: NETWORK_CONFIG[environment] || WEB3AUTH_NETWORK.SAPPHIRE_DEVNET,
  uiConfig: {
    mode: 'dark',
  },
  modalConfig: {
    connectors: {
      [WALLET_CONNECTORS.AUTH]: {
        label: 'auth',
        loginMethods: {
          google: {
            name: 'Google',
            showOnModal: true,
            authConnectionId: AUTH_CONNECTION_IDS.GOOGLE,
            groupedAuthConnectionId: AUTH_CONNECTION_IDS.GROUP,
          },
          email_passwordless: {
            name: 'Email',
            showOnModal: true,
            authConnectionId: AUTH_CONNECTION_IDS.EMAIL,
            groupedAuthConnectionId: AUTH_CONNECTION_IDS.GROUP,
          },
        },
        showOnModal: true,
      },
      [WALLET_CONNECTORS.WALLET_CONNECT_V2]: {
        label: 'WalletConnect',
        showOnModal: true,
      },
      [WALLET_CONNECTORS.METAMASK]: {
        label: 'MetaMask',
        showOnModal: true,
      },
    },
  },
};
