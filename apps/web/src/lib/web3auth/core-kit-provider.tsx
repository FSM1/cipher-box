import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react';
import { getCoreKit, initCoreKit, COREKIT_STATUS } from './core-kit';
import type { Web3AuthMPCCoreKit } from './core-kit';

interface CoreKitContextValue {
  /** The Core Kit singleton instance (null until first render) */
  coreKit: Web3AuthMPCCoreKit | null;
  /** Current SDK status from the COREKIT_STATUS state machine */
  status: COREKIT_STATUS;
  /** True when status is anything other than NOT_INITIALIZED */
  isInitialized: boolean;
  /** True when status is LOGGED_IN (user fully authenticated) */
  isLoggedIn: boolean;
  /** True when status is REQUIRED_SHARE (MFA challenge needed -- Phase 12.4) */
  isRequiredShare: boolean;
  /** Initialization error, if any */
  error: Error | null;
  /** Re-run initialization (e.g., retry after error) */
  reinitialize: () => Promise<void>;
}

const CoreKitContext = createContext<CoreKitContextValue | null>(null);

/**
 * React context provider for MPC Core Kit.
 *
 * Initializes Core Kit on mount (calls init() which checks for existing sessions).
 * Exposes the singleton instance and COREKIT_STATUS to child components.
 *
 * NOTE: Do NOT mount this in main.tsx yet -- that happens in Plan 03
 * when we swap providers. For now, this module is ready to use.
 */
export function CoreKitProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<COREKIT_STATUS>(COREKIT_STATUS.NOT_INITIALIZED);
  const [coreKit, setCoreKit] = useState<Web3AuthMPCCoreKit | null>(null);
  const [error, setError] = useState<Error | null>(null);

  const initialize = useCallback(async () => {
    try {
      setError(null);
      const ck = getCoreKit();
      setCoreKit(ck);
      const resultStatus = await initCoreKit();
      setStatus(resultStatus);
    } catch (err) {
      console.error('[CoreKit] Initialization failed:', err);
      setError(err instanceof Error ? err : new Error(String(err)));
    }
  }, []);

  useEffect(() => {
    initialize();
  }, [initialize]);

  const value: CoreKitContextValue = {
    coreKit,
    status,
    isInitialized: status !== COREKIT_STATUS.NOT_INITIALIZED,
    isLoggedIn: status === COREKIT_STATUS.LOGGED_IN,
    isRequiredShare: status === COREKIT_STATUS.REQUIRED_SHARE,
    error,
    reinitialize: initialize,
  };

  return <CoreKitContext.Provider value={value}>{children}</CoreKitContext.Provider>;
}

/**
 * Hook to access Core Kit instance and status from React components.
 * Must be used within a CoreKitProvider.
 */
export function useCoreKit(): CoreKitContextValue {
  const context = useContext(CoreKitContext);
  if (!context) {
    throw new Error('useCoreKit must be used within CoreKitProvider');
  }
  return context;
}
