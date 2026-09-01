/**
 * The vault's storage read, held once for the tab. `/bin`, the settings form
 * and the file browser's delete confirmation all state what the vault
 * actuates, and a dialog on a hot path adds no read of its own to do it.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import type { VaultStorageDescriptor } from '@cipherbox/client';
import { useEngineAccount } from '../engine/useEngineSession';
import { useCommandRunner } from '../hooks/useCommandRunner';

export interface VaultStorageRead {
  /** `null` until the first read lands, or where the engine refused one. */
  storage: VaultStorageDescriptor | null;
  error: string | null;
  reload(): Promise<boolean>;
}

const VaultStorageContext = createContext<VaultStorageRead | null>(null);

/** Nothing read and nothing claimed — what a surface with no provider above gets. */
const UNREAD: VaultStorageRead = {
  storage: null,
  error: null,
  reload: () => Promise.resolve(false),
};

export function VaultStorageProvider({ children }: { children: ReactNode }) {
  const { error, run } = useCommandRunner<'vaultStorage'>();
  const [storage, setStorage] = useState<VaultStorageDescriptor | null>(null);
  const account = useEngineAccount();

  const reload = useCallback(
    () => run('vaultStorage', async (facade) => setStorage(await facade.vaultStorage())),
    [run]
  );

  // A read taken before this tab holds a session refuses, so the session it
  // goes on to hold takes the read again.
  useEffect(() => {
    void reload();
  }, [reload, account]);

  const value = useMemo(() => ({ storage, error, reload }), [storage, error, reload]);
  return <VaultStorageContext.Provider value={value}>{children}</VaultStorageContext.Provider>;
}

/** The vault's storage as this tab last read it. */
export function useVaultStorage(): VaultStorageRead {
  return useContext(VaultStorageContext) ?? UNREAD;
}
