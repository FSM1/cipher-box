import { createContext, useContext, useMemo, type ReactNode } from 'react';
import type { CredentialCollector, IdentityExchange } from '@cipherbox/login';
import { webCollector, type WebCollected } from './webCollector';

export interface IdentityContextValue {
  exchange: IdentityExchange;
  /**
   * The OAuth provider's client ID — not the Web3Auth project's. `undefined`
   * when the build carries none, which leaves that method unavailable.
   */
  googleClientId: string | undefined;
  /** What this host collects; a method absent here is one web does not offer. */
  collector: CredentialCollector<WebCollected>;
}

const IdentityContext = createContext<IdentityContextValue | undefined>(undefined);

export interface IdentityProviderProps {
  exchange: IdentityExchange;
  googleClientId: string | undefined;
  children: ReactNode;
}

/**
 * Holds the identity exchange and this host's collector so the login flow
 * reaches the API without importing a transport — which is what keeps the
 * sequencing host-agnostic.
 */
export function IdentityProvider({ exchange, googleClientId, children }: IdentityProviderProps) {
  const value = useMemo(
    () => ({ exchange, googleClientId, collector: webCollector(googleClientId) }),
    [exchange, googleClientId]
  );
  return <IdentityContext.Provider value={value}>{children}</IdentityContext.Provider>;
}

export function useIdentity(): IdentityContextValue {
  const value = useContext(IdentityContext);
  if (!value) throw new Error('auth hooks must be used within <IdentityProvider>');
  return value;
}
