import { WEB3AUTH_NETWORK, type Web3AuthOptions } from '@web3auth/modal';
import { WALLET_CONNECTORS } from '@web3auth/modal';

export const web3AuthOptions: Web3AuthOptions = {
  clientId: import.meta.env.VITE_WEB3AUTH_CLIENT_ID || '',
  web3AuthNetwork: WEB3AUTH_NETWORK.SAPPHIRE_MAINNET,
  modalConfig: {
    connectors: {
      [WALLET_CONNECTORS.AUTH]: {
        label: 'auth',
        loginMethods: {
          google: {
            name: 'Google',
            showOnModal: true,
          },
          apple: {
            name: 'Apple',
            showOnModal: true,
          },
          github: {
            name: 'GitHub',
            showOnModal: true,
          },
          email_passwordless: {
            name: 'Email',
            showOnModal: true,
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
