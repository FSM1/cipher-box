import type { ReactNode } from 'react';
import { WagmiProvider } from 'wagmi';
import { wagmiConfig } from './config';

/**
 * WagmiSetup wraps children with wagmi's WagmiProvider.
 *
 * Must be placed OUTSIDE CoreKitProvider and QueryClientProvider
 * in the component tree because wagmi v3 uses React Query internally
 * and will discover the existing QueryClient from context.
 */
export function WagmiSetup({ children }: { children: ReactNode }) {
  return <WagmiProvider config={wagmiConfig}>{children}</WagmiProvider>;
}
