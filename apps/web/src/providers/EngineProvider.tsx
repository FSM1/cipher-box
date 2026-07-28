import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import type { EngineClient } from '@cipherbox/client';
import { createEngineClient } from '../engine/createEngineClient';

// `undefined` distinguishes "no provider above me" from "provider mounted,
// client not built yet".
const EngineContext = createContext<EngineClient | null | undefined>(undefined);

export interface EngineProviderProps {
  /** Builds this tab's engine client. Read once, on mount. */
  createClient?: () => EngineClient;
  children: ReactNode;
}

/**
 * Owns the one `EngineClient` this tab may hold (blueprint/web-client.md
 * "Engine hosting and tab leadership"): built on mount, disposed on unmount, and
 * never duplicated. Construction runs in an effect so a StrictMode double-mount
 * disposes the throwaway client rather than leaking a second lock contender.
 */
export function EngineProvider({
  createClient = createEngineClient,
  children,
}: EngineProviderProps) {
  const [client, setClient] = useState<EngineClient | null>(null);
  const factory = useRef(createClient);

  useEffect(() => {
    const instance = factory.current();
    setClient(instance);
    return () => {
      instance.dispose().catch((error: unknown) => {
        console.error('[engine] dispose failed', error instanceof Error ? error.message : error);
      });
    };
  }, []);

  return <EngineContext.Provider value={client}>{children}</EngineContext.Provider>;
}

/** This tab's engine client, or `null` until the provider has built it. */
export function useEngine(): EngineClient | null {
  const client = useContext(EngineContext);
  if (client === undefined) {
    throw new Error('useEngine must be used within <EngineProvider>');
  }
  return client;
}
