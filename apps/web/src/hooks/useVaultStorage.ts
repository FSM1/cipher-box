/**
 * The storage pane's one read, re-read after a save so the form shows what the
 * vault now carries rather than what was typed at it.
 */

import { useCallback, useEffect, useState } from 'react';
import type { VaultStorageDescriptor } from '@cipherbox/client';
import { useCommandRunner } from './useCommandRunner';

interface VaultStorageRead {
  /** `null` until the first read lands, or where the engine refused one. */
  storage: VaultStorageDescriptor | null;
  error: string | null;
  reload(): Promise<boolean>;
}

export function useVaultStorage(): VaultStorageRead {
  const { error, run } = useCommandRunner<'vaultStorage'>();
  const [storage, setStorage] = useState<VaultStorageDescriptor | null>(null);

  const reload = useCallback(
    () => run('vaultStorage', async (facade) => setStorage(await facade.vaultStorage())),
    [run]
  );

  useEffect(() => {
    void reload();
  }, [reload]);

  return { storage, error, reload };
}
