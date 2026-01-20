import {
  useWeb3Auth,
  useWeb3AuthConnect,
  useWeb3AuthDisconnect,
  useWeb3AuthUser,
  useIdentityToken,
} from '@web3auth/modal/react';
import type { IProvider, AuthUserInfo } from '@web3auth/modal';
import * as secp256k1 from '@noble/secp256k1';
import {
  deriveKeypairFromWallet,
  bytesToHex as signatureBytesToHex,
  type EIP1193Provider,
} from '../crypto/signatureKeyDerivation';

// External wallet auth connection types
const EXTERNAL_WALLET_CONNECTIONS = [
  'metamask',
  'wallet_connect_v2',
  'coinbase',
  'phantom',
] as const;

export type UserInfo = Partial<AuthUserInfo>;

export function useAuthFlow() {
  const { isConnected, isInitialized, status, web3Auth } = useWeb3Auth();
  const { connect, connectTo } = useWeb3AuthConnect();
  const { disconnect } = useWeb3AuthDisconnect();
  const { userInfo } = useWeb3AuthUser();
  const { getIdentityToken } = useIdentityToken();

  const isLoading = !isInitialized || status === 'connecting';

  const getIdToken = async (): Promise<string | null> => {
    try {
      // Try authenticateUser directly (method exists at runtime but not in types)
      if (web3Auth) {
        try {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const authUser = await (web3Auth as any).authenticateUser();
          if (authUser?.idToken) {
            return authUser.idToken;
          }
        } catch {
          // Fall through to hook method
        }
      }
      // Fallback to hook method
      const token = await getIdentityToken();
      return token;
    } catch {
      return null;
    }
  };

  // Determine if this is a social login or external wallet
  const isSocialLogin = (): boolean => {
    // Check web3Auth connector name first (most reliable after connection)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const connectorName = ((web3Auth as any)?.connectedConnectorName?.toLowerCase() ||
      '') as string;
    if (connectorName) {
      // 'auth' connector is for social logins, others are external wallets
      return connectorName === 'auth';
    }

    // Fallback to userInfo check
    if (!userInfo?.authConnection) return true; // Default to social
    const connection = userInfo.authConnection.toLowerCase();
    return !EXTERNAL_WALLET_CONNECTIONS.some((wallet) => connection.includes(wallet));
  };

  /**
   * Get the public key for authentication.
   * - Social logins: Derived from Web3Auth MPC private key
   * - External wallets: Must use deriveKeypairForExternalWallet() first,
   *   then pass the derived keypair's public key to the backend
   */
  const getPublicKey = async (connectedProvider?: IProvider | null): Promise<string | null> => {
    const currentProvider = connectedProvider || web3Auth?.provider;
    if (!currentProvider) {
      return null;
    }

    try {
      // For social logins, derive from private key
      if (isSocialLogin()) {
        const privateKey = await getPrivateKey(currentProvider);
        if (privateKey) {
          return derivePublicKeyFromPrivate(privateKey);
        }
      }

      // External wallet: return wallet address (caller should derive keypair separately)
      const accounts = await currentProvider.request<unknown, string[]>({
        method: 'eth_accounts',
      });
      return accounts?.[0] ?? null;
    } catch {
      return null;
    }
  };

  /**
   * Get the wallet address for external wallet users.
   * This is used as input for signature-derived key derivation.
   */
  const getWalletAddress = async (connectedProvider?: IProvider | null): Promise<string | null> => {
    const currentProvider = connectedProvider || web3Auth?.provider;
    if (!currentProvider) {
      return null;
    }

    try {
      const accounts = await currentProvider.request<unknown, string[]>({
        method: 'eth_accounts',
      });
      return accounts?.[0] ?? null;
    } catch {
      return null;
    }
  };

  /**
   * ADR-001: Derive keypair for external wallet users via signature.
   * This prompts the user's wallet to sign an EIP-712 message,
   * then derives a secp256k1 keypair from the signature.
   *
   * The derived keypair is used for ECIES operations (encryption/decryption)
   * since external wallets never expose their private keys.
   *
   * @returns Derived keypair with publicKey and privateKey as Uint8Array
   */
  const deriveKeypairForExternalWallet = async (
    connectedProvider?: IProvider | null
  ): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array } | null> => {
    const currentProvider = connectedProvider || web3Auth?.provider;
    if (!currentProvider) {
      return null;
    }

    // Get wallet address
    const walletAddress = await getWalletAddress(currentProvider);
    if (!walletAddress) {
      return null;
    }

    // Derive keypair from EIP-712 signature
    // This will prompt the wallet to sign
    const keypair = await deriveKeypairFromWallet(
      currentProvider as unknown as EIP1193Provider,
      walletAddress
    );

    return keypair;
  };

  /**
   * Get the public key as hex string from a derived keypair.
   * Used after deriveKeypairForExternalWallet() to get the publicKey for backend auth.
   */
  const getDerivedPublicKeyHex = (keypair: { publicKey: Uint8Array }): string => {
    return signatureBytesToHex(keypair.publicKey);
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
    getWalletAddress,
    getLoginType,
    isSocialLogin,
    deriveKeypairForExternalWallet,
    getDerivedPublicKeyHex,
  };
}

async function getPrivateKey(provider: IProvider): Promise<string | null> {
  try {
    // Web3Auth Modal uses 'private_key' for social logins
    const privateKey = await provider.request<unknown, string>({
      method: 'private_key',
    });
    return privateKey ?? null;
  } catch {
    // Fallback to eth_private_key for compatibility
    try {
      const privateKey = await provider.request<unknown, string>({
        method: 'eth_private_key',
      });
      return privateKey ?? null;
    } catch {
      return null;
    }
  }
}

function derivePublicKeyFromPrivate(privateKey: string): string {
  // Remove 0x prefix if present
  const privKeyHex = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;

  // Derive compressed public key from private key using secp256k1
  const privKeyBytes = hexToBytes(privKeyHex);
  const pubKeyBytes = secp256k1.getPublicKey(privKeyBytes, true); // true = compressed

  // Return as hex string (this is what Web3Auth stores in the JWT)
  return bytesToHex(pubKeyBytes);
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
