import { createConfig, http } from 'wagmi';
import { mainnet } from 'wagmi/chains';
import { injected } from 'wagmi/connectors';

/**
 * wagmi configuration for wallet connection.
 *
 * CipherBox does NOT use Ethereum for transactions. The chain config
 * is only needed for SIWE chainId field. We use mainnet (chainId=1)
 * as the canonical chain for SIWE messages.
 *
 * The injected() connector auto-discovers all EIP-6963 wallets
 * (MetaMask, Coinbase Wallet, Brave Wallet, etc.).
 */
export const wagmiConfig = createConfig({
  chains: [mainnet],
  connectors: [injected()],
  transports: {
    [mainnet.id]: http(),
  },
  // CipherBox only uses wagmi transiently for SIWE signing — we disconnect
  // immediately after. Disable reconnect-on-mount to prevent stale connector
  // errors (especially in Brave which has a built-in wallet).
  reconnectOnMount: false,
});
