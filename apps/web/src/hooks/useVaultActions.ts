/**
 * The vault browser's write path: one facade command per user action, dispatched
 * and nothing else. The engine journals the op and the snapshot store reports
 * the result — the UI never patches its own listing
 * (blueprint/web-client.md "UI state law").
 */

import { useCallback, useState } from 'react';
import type { EngineFacade } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';

/** Which command is in flight, or `null` when the browser is idle. */
export type VaultCommand = 'create' | 'rename' | 'relink' | 'delete';

export interface VaultActions {
  busy: VaultCommand | null;
  /** The last dispatch's failure, cleared by the next dispatch. */
  error: string | null;
  /** Every action resolves `true` once the engine accepted every command. */
  createFolder(parent: Uint8Array, name: string): Promise<boolean>;
  rename(node: Uint8Array, newName: string): Promise<boolean>;
  /** One `facade.relink` per node — a batch is not a command of its own. */
  move(nodes: readonly Uint8Array[], newParent: Uint8Array): Promise<boolean>;
  /** One `facade.delete` per node. */
  remove(nodes: readonly Uint8Array[]): Promise<boolean>;
}

/**
 * Dispatches one command per node in listing order. Every node is attempted
 * even after one is refused — the nodes are independent, and the snapshot is
 * what reports which of them the engine took.
 */
async function perNode(
  nodes: readonly Uint8Array[],
  dispatch: (node: Uint8Array) => Promise<void>
): Promise<void> {
  const refusals: unknown[] = [];
  for (const node of nodes) {
    await dispatch(node).catch((failure: unknown) => refusals.push(failure));
  }
  if (refusals.length > 0) throw refusals[0];
}

export function useVaultActions(): VaultActions {
  const client = useEngine();
  const [busy, setBusy] = useState<VaultCommand | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(
    async (command: VaultCommand, dispatch: () => Promise<void>): Promise<boolean> => {
      setBusy(command);
      setError(null);
      try {
        await dispatch();
        return true;
      } catch (failure: unknown) {
        setError(errorMessage(failure));
        return false;
      } finally {
        setBusy(null);
      }
    },
    []
  );

  const dispatchOrFail = useCallback(
    (command: VaultCommand, dispatch: (facade: EngineFacade) => Promise<void>) => {
      if (client === null) {
        setError('the engine is not ready yet');
        return Promise.resolve(false);
      }
      return run(command, () => dispatch(client.facade));
    },
    [client, run]
  );

  return {
    busy,
    error,
    createFolder: useCallback(
      (parent, name) => dispatchOrFail('create', (facade) => facade.create(parent, name, 'folder')),
      [dispatchOrFail]
    ),
    rename: useCallback(
      (node, newName) => dispatchOrFail('rename', (facade) => facade.rename(node, newName)),
      [dispatchOrFail]
    ),
    move: useCallback(
      (nodes, newParent) =>
        dispatchOrFail('relink', (facade) =>
          perNode(nodes, (node) => facade.relink(node, newParent))
        ),
      [dispatchOrFail]
    ),
    remove: useCallback(
      (nodes) =>
        dispatchOrFail('delete', (facade) => perNode(nodes, (node) => facade.delete(node))),
      [dispatchOrFail]
    ),
  };
}
