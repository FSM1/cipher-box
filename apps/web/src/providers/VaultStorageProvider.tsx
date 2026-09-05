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
  useRef,
  useState,
  type ReactNode,
} from 'react';
import type { VaultStorageDescriptor } from '@cipherbox/client';
import { useEngineAccount } from '../engine/useEngineSession';
import { useCommandRunner } from '../hooks/useCommandRunner';
import { useEngine } from './EngineProvider';

export interface VaultStorageRead {
  /** `null` until the first read lands, or where the engine refused one. */
  storage: VaultStorageDescriptor | null;
  error: string | null;
  reload(): Promise<boolean>;
}

// `undefined` distinguishes "no provider above me" from "mounted, nothing read
// yet" — a surface that claims the least must reach the second state, not the
// first.
const VaultStorageContext = createContext<VaultStorageRead | undefined>(undefined);

export function VaultStorageProvider({ children }: { children: ReactNode }) {
  const { error, run } = useCommandRunner<'vaultStorage'>();
  const [storage, setStorage] = useState<VaultStorageDescriptor | null>(null);
  const account = useEngineAccount();
  const client = useEngine();

  // A session change and an adopted settings change each read, so two reads can
  // be in flight. Only the newest may write: the one that resolves last would
  // otherwise leave the settings it overtook on the delete prompt.
  const latest = useRef(0);

  const reload = useCallback(() => {
    const ticket = (latest.current += 1);
    return run('vaultStorage', async (facade) => {
      const read = await facade.vaultStorage();
      if (ticket === latest.current) setStorage(read);
    });
  }, [run]);

  // A session change drops what the session before it read, then reads again: a
  // read taken before login refuses, and one vault's retention must never
  // answer for the next vault's delete.
  useEffect(() => {
    setStorage(null);
    void reload();
  }, [reload, account]);

  // A change another device made reaches this tab as an engine event, and what
  // the delete prompt states has to be what the engine actuates, not what this
  // tab read when it opened.
  useEffect(() => {
    if (client === null) return;
    return client.facade.subscribe((event) => {
      if (event.kind === 'vaultSettingsChanged') void reload();
    });
  }, [client, reload]);

  const value = useMemo(() => ({ storage, error, reload }), [storage, error, reload]);
  return <VaultStorageContext.Provider value={value}>{children}</VaultStorageContext.Provider>;
}

/** The vault's storage as this tab last read it. */
export function useVaultStorage(): VaultStorageRead {
  const value = useContext(VaultStorageContext);
  if (value === undefined) {
    throw new Error('vault storage hooks must be used within <VaultStorageProvider>');
  }
  return value;
}
