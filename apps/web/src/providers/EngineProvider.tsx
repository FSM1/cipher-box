import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import type { EngineClient } from '@cipherbox/client';
import {
  createSnapshotStore,
  idleSnapshotStore,
  type SnapshotStore,
} from '../engine/snapshotStore';

interface EngineContextValue {
  client: EngineClient;
  snapshots: SnapshotStore;
}

// `undefined` distinguishes "no provider above me" from "provider mounted,
// client not built yet".
const EngineContext = createContext<EngineContextValue | null | undefined>(undefined);

export interface EngineProviderProps {
  /** Builds this tab's engine client. Read once, on mount. */
  createClient: () => EngineClient;
  children: ReactNode;
}

/**
 * Owns the one `EngineClient` this tab may hold (blueprint/web-client.md
 * "Engine hosting and tab leadership") and the one snapshot store over it:
 * built on mount, disposed on unmount, and never duplicated. Construction runs
 * in an effect so a StrictMode double-mount disposes the throwaway client
 * rather than leaking a second lock contender.
 */
export function EngineProvider({ createClient, children }: EngineProviderProps) {
  const [value, setValue] = useState<EngineContextValue | null>(null);
  const factory = useRef(createClient);

  useEffect(() => {
    const client = factory.current();
    const snapshots = createSnapshotStore(client);
    setValue({ client, snapshots });
    return () => {
      snapshots.dispose();
      client.dispose().catch((error: unknown) => {
        console.error('[engine] dispose failed', error instanceof Error ? error.message : error);
      });
    };
  }, []);

  return <EngineContext.Provider value={value}>{children}</EngineContext.Provider>;
}

function useEngineContext(): EngineContextValue | null {
  const value = useContext(EngineContext);
  if (value === undefined) {
    throw new Error('useEngine must be used within <EngineProvider>');
  }
  return value;
}

/** This tab's engine client, or `null` until the provider has built it. */
export function useEngine(): EngineClient | null {
  return useEngineContext()?.client ?? null;
}

/** This tab's snapshot adapter; an inert store until the client exists. */
export function useSnapshotStore(): SnapshotStore {
  return useEngineContext()?.snapshots ?? idleSnapshotStore;
}
