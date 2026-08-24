/**
 * The vault browser's write path: one facade command per user action, dispatched
 * and nothing else. The engine journals the op and the snapshot store reports
 * the result — the UI never patches its own listing
 * (blueprint/web-client.md "UI state law").
 */

import { useCallback } from 'react';
import type { EngineFacade } from '@cipherbox/client';
import { useCommandRunner } from './useCommandRunner';

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
  const { busy, error, run } = useCommandRunner<VaultCommand>();

  /**
   * Dispatches one command per node in listing order, attempting every node
   * even after one is refused — the nodes are independent. The outcome names
   * the accepted ones so the caller can retire exactly those.
   */
  const runBatch = useCallback(
    async (
      command: VaultCommand,
      nodes: readonly Uint8Array[],
      dispatch: (facade: EngineFacade, node: Uint8Array) => Promise<unknown>
    ): Promise<BatchOutcome> => {
      const accepted: Uint8Array[] = [];
      const ok = await run(command, async (facade) => {
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
    [run]
  );

  return {
    busy,
    error,
    createFolder: useCallback(
      (parent, name) => run('create', (facade) => facade.create(parent, name, 'folder')),
      [run]
    ),
    rename: useCallback(
      (node, newName) => run('rename', (facade) => facade.rename(node, newName)),
      [run]
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
