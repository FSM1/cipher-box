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

/** Which nodes a batch dispatch was accepted for; the rest were refused. */
export interface BatchOutcome {
  /** `true` when the engine accepted every node. */
  ok: boolean;
  /** The nodes the engine accepted, in listing order. */
  accepted: readonly Uint8Array[];
}

export interface VaultActions {
  busy: VaultCommand | null;
  /** The last dispatch's failure, cleared by the next dispatch. */
  error: string | null;
  /** A single-node action resolves `true` once the engine accepted it. */
  createFolder(parent: Uint8Array, name: string): Promise<boolean>;
  rename(node: Uint8Array, newName: string): Promise<boolean>;
  /** One `facade.relink` per node — a batch is not a command of its own. */
  move(nodes: readonly Uint8Array[], newParent: Uint8Array): Promise<BatchOutcome>;
  /** One `facade.delete` per node. */
  remove(nodes: readonly Uint8Array[]): Promise<BatchOutcome>;
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

  /**
   * Dispatches one command per node in listing order, attempting every node
   * even after one is refused — the nodes are independent. The outcome names
   * the accepted ones so the caller can retire exactly those.
   */
  const runBatch = useCallback(
    async (
      command: VaultCommand,
      nodes: readonly Uint8Array[],
      dispatch: (facade: EngineFacade, node: Uint8Array) => Promise<void>
    ): Promise<BatchOutcome> => {
      const accepted: Uint8Array[] = [];
      const ok = await dispatchOrFail(command, async (facade) => {
        const refusals: unknown[] = [];
        for (const node of nodes) {
          try {
            await dispatch(facade, node);
            accepted.push(node);
          } catch (failure: unknown) {
            refusals.push(failure);
          }
        }
        if (refusals.length > 0) throw refusals[0];
      });
      return { ok, accepted };
    },
    [dispatchOrFail]
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
        runBatch('relink', nodes, (facade, node) => facade.relink(node, newParent)),
      [runBatch]
    ),
    remove: useCallback(
      (nodes) => runBatch('delete', nodes, (facade, node) => facade.delete(node)),
      [runBatch]
    ),
  };
}
