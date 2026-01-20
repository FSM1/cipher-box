import {
  useWeb3Auth,
  useWeb3AuthConnect,
  useWeb3AuthDisconnect,
  useWeb3AuthUser,
  useIdentityToken,
} from '@web3auth/modal/react';
import type { IProvider, AuthUserInfo } from '@web3auth/modal';

// External wallet auth connection types
const EXTERNAL_WALLET_CONNECTIONS = [
  'metamask',
  'wallet_connect_v2',
  'coinbase',
  'phantom',
] as const;

export type UserInfo = Partial<AuthUserInfo>;

export function useAuthFlow() {
  const { isConnected, isInitialized, status, provider, web3Auth } = useWeb3Auth();
  const { connect, connectTo } = useWeb3AuthConnect();
  const { disconnect } = useWeb3AuthDisconnect();
  const { userInfo } = useWeb3AuthUser();
  const { getIdentityToken } = useIdentityToken();

  const isLoading = !isInitialized || status === 'connecting';

  const getIdToken = async (): Promise<string | null> => {
    if (!isConnected) return null;
    try {
      const token = await getIdentityToken();
      return token;
    } catch {
      return null;
    }
  };

  // Determine if this is a social login or external wallet based on authConnection
  const isSocialLogin = (): boolean => {
    if (!userInfo?.authConnection) return true; // Default to social
    const connection = userInfo.authConnection.toLowerCase();
    return !EXTERNAL_WALLET_CONNECTIONS.some((wallet) => connection.includes(wallet));
  };

  const getPublicKey = async (): Promise<string | null> => {
    if (!provider || !isConnected) return null;

    try {
      // For social logins, derive from private key
      // For external wallets, use eth_accounts
      if (isSocialLogin()) {
        // Social login: get private key and derive public key
        const privateKey = await getPrivateKey(provider);
        if (privateKey) {
          return derivePublicKeyFromPrivate(privateKey);
        }
      }

      // External wallet: get address from eth_accounts
      const accounts = await provider.request<unknown, string[]>({
        method: 'eth_accounts',
      });
      return accounts?.[0] ?? null;
    } catch {
      return null;
    }
  };

  // Get login type for backend authentication
  const getLoginType = (): 'social' | 'external_wallet' => {
    return isSocialLogin() ? 'social' : 'external_wallet';
  };

  return {
    isConnected,
    isLoading,
    isInitialized,
    userInfo: userInfo as UserInfo | null,
    web3Auth,
    connect,
    connectTo,
    disconnect,
    getIdToken,
    getPublicKey,
    getLoginType,
  };
}

async function getPrivateKey(provider: IProvider): Promise<string | null> {
  try {
    const privateKey = await provider.request<unknown, string>({
      method: 'eth_private_key',
    });
    return privateKey ?? null;
  } catch {
    return null;
  }
}

function derivePublicKeyFromPrivate(privateKey: string): string {
  // The private key from Web3Auth is the secp256k1 private key
  // For CipherBox, we send the full uncompressed public key (hex)
  // This requires secp256k1 derivation which will be done properly
  // when we integrate with the crypto module in Phase 3
  // For now, return the private key hash as placeholder
  // The actual derivation will use the Web Crypto API or a lib
  return `0x${privateKey.slice(0, 40)}`;
}
