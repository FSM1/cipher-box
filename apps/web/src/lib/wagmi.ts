import { createConfig, http } from 'wagmi';
import { mainnet } from 'wagmi/chains';
import { injected } from 'wagmi/connectors';

/**
 * Wallet discovery for SIWE only — CipherBox sends no transactions. The chain
 * exists because EIP-4361 messages carry a chainId; mainnet is the canonical
 * one. `injected()` picks up every EIP-6963 wallet the browser announces.
 */
export const wagmiConfig = createConfig({
  chains: [mainnet],
  connectors: [injected()],
  transports: { [mainnet.id]: http() },
});
