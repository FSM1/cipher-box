import { createContext, useContext, useMemo, type ReactNode } from 'react';
import type { IdentityExchange } from './identityExchange';

export interface IdentityContextValue {
  exchange: IdentityExchange;
  /**
   * The OAuth provider's client ID — not the Web3Auth project's. `undefined`
   * when the build carries none, which leaves that method unavailable.
   */
  googleClientId: string | undefined;
}

const IdentityContext = createContext<IdentityContextValue | undefined>(undefined);

export interface IdentityProviderProps extends IdentityContextValue {
  children: ReactNode;
}

/**
 * Holds the identity exchange so the login flow reaches the API without
 * importing a transport — which is what keeps `useAuth` host-agnostic.
 */
export function IdentityProvider({ exchange, googleClientId, children }: IdentityProviderProps) {
  const value = useMemo(() => ({ exchange, googleClientId }), [exchange, googleClientId]);
  return <IdentityContext.Provider value={value}>{children}</IdentityContext.Provider>;
}

export function useIdentity(): IdentityContextValue {
  const value = useContext(IdentityContext);
  if (!value) throw new Error('auth hooks must be used within <IdentityProvider>');
  return value;
}
