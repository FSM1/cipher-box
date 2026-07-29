import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import type { EngineClient, SecretSource } from '@cipherbox/client';
import { LoginSecretSource } from '../engine/loginHandoff';
import {
  createSnapshotStore,
  idleSnapshotStore,
  type SnapshotStore,
} from '../engine/snapshotStore';

interface EngineContextValue {
  client: EngineClient;
  snapshots: SnapshotStore;
  secrets: LoginSecretSource;
}

// `undefined` distinguishes "no provider above me" from "provider mounted,
// client not built yet".
const EngineContext = createContext<EngineContextValue | null | undefined>(undefined);

export interface EngineProviderProps {
  /** Builds this tab's engine client. Read once, on mount. */
  createClient: (secretSource: SecretSource) => EngineClient;
  children: ReactNode;
}

/**
 * Owns everything scoped to this tab's one engine (blueprint/web-client.md
 * "Engine hosting and tab leadership"): the client, the snapshot store over it,
 * and the failover secret source — built on mount, torn down together on
 * unmount, never duplicated. Construction runs in an effect so a StrictMode
 * double-mount disposes the throwaway client rather than leaking a second lock
 * contender.
 */
export function EngineProvider({ createClient, children }: EngineProviderProps) {
  const [value, setValue] = useState<EngineContextValue | null>(null);
  const factory = useRef(createClient);

  useEffect(() => {
    const secrets = new LoginSecretSource();
    const client = factory.current(secrets);
    const snapshots = createSnapshotStore(client);
    setValue({ client, snapshots, secrets });
    return () => {
      // Drop the exporter first: no re-export capability outlives the client.
      secrets.use(null);
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
    throw new Error('engine hooks must be used within <EngineProvider>');
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

/** Where login registers its Core Kit session for a failover re-export. */
export function useLoginSecretSource(): LoginSecretSource | null {
  return useEngineContext()?.secrets ?? null;
}
