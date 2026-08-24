import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import type { EngineClient, MediaService, SecretSource } from '@cipherbox/client';
import { createMediaService } from '../engine/createMediaService';
import { LoginSecretSource } from '../engine/loginHandoff';
import { errorMessage } from '../lib/errorMessage';
import { sharingStore } from '../stores/sharing.store';
import {
  createSnapshotStore,
  idleSnapshotStore,
  type SnapshotStore,
} from '../engine/snapshotStore';

interface EngineContextValue {
  client: EngineClient;
  snapshots: SnapshotStore;
  secrets: LoginSecretSource;
  media: MediaService | null;
  rebuild: () => void;
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
 * and the failover secret source — built together, torn down together, never
 * duplicated. Construction runs in an effect so a StrictMode double-mount
 * disposes the throwaway client rather than leaking a second lock contender.
 */
export function EngineProvider({ createClient, children }: EngineProviderProps) {
  const [value, setValue] = useState<EngineContextValue | null>(null);
  const [generation, setGeneration] = useState(0);
  const factory = useRef(createClient);

  // `facade.logout` closes the client for good, so the tab needs a new one
  // before it can log in again.
  const rebuild = useCallback(() => setGeneration((current) => current + 1), []);

  useEffect(() => {
    const secrets = new LoginSecretSource();
    const client = factory.current(secrets);
    const snapshots = createSnapshotStore(client);
    const media = createMediaService(client);
    media
      ?.start()
      .catch((error: unknown) => console.error('[media] start failed', errorMessage(error)));
    setValue({ client, snapshots, secrets, media, rebuild });
    return () => {
      // Drop the exporter first: no re-export capability outlives the client.
      secrets.use(null);
      // Session-scoped UI state naming this identity's peers goes with it.
      sharingStore.clear();
      snapshots.dispose();
      media
        ?.dispose()
        .catch((error: unknown) => console.error('[media] dispose failed', errorMessage(error)));
      client
        .dispose()
        .catch((error: unknown) => console.error('[engine] dispose failed', errorMessage(error)));
    };
  }, [generation, rebuild]);

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

/** This tab's streaming pipe; `null` where the browser has no Service Worker. */
export function useMediaService(): MediaService | null {
  return useEngineContext()?.media ?? null;
}

/** Where login registers its Core Kit session for a failover re-export. */
export function useLoginSecretSource(): LoginSecretSource | null {
  return useEngineContext()?.secrets ?? null;
}

/** Replaces this tab's engine client with a fresh one; a no-op before the first. */
export function useRebuildEngine(): () => void {
  const rebuild = useEngineContext()?.rebuild;
  return rebuild ?? noop;
}

const noop = () => undefined;
