import { Web3AuthProvider } from '@web3auth/modal/react';
import { WagmiProvider } from '@web3auth/modal/react/wagmi';
import { web3AuthOptions } from './config';

export { WagmiProvider };

export function Web3AuthProviderWrapper({ children }: { children: React.ReactNode }) {
  return <Web3AuthProvider config={{ web3AuthOptions }}>{children}</Web3AuthProvider>;
}
