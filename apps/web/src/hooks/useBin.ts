/**
 * The `/bin` route's one read and its two commands. A `bin` read reaches the
 * record plane, so it runs on route entry and after a restore or a purge only.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import type { BinDescriptor, CommandOutcomeDescriptor, EngineFacade } from '@cipherbox/client';
import { useEngine } from '../providers/EngineProvider';
import { useCommandRunner } from './useCommandRunner';

type BinCommand = 'bin' | 'restore' | 'purge';

/**
 * What a command did. `queued` is a journaled op: the published index carries
 * it only once the queue drains past it, so the next read still shows the row.
 */
export type BinVerdict = 'applied' | 'queued' | 'refused';

export interface BinRead {
  /** `null` until a read lands; never an empty bin a render would read as one. */
  bin: BinDescriptor | null;
  busy: boolean;
  error: string | null;
  /** The last refusal's engine code, which decides what the row may offer next. */
  code: string | undefined;
  reload(): Promise<boolean>;
  clearError(): void;
  /** Puts `node` back, into `into` or the folder its bin entry names. */
  restore(node: Uint8Array, into: Uint8Array | null): Promise<BinVerdict>;
  purge(node: Uint8Array): Promise<BinVerdict>;
}

export function useBin(): BinRead {
  const client = useEngine();
  const { busy, error, code, run, clearError } = useCommandRunner<BinCommand>();
  const [bin, setBin] = useState<BinDescriptor | null>(null);
  // Two reads can land out of order; only the newest may write the state.
  const generation = useRef(0);

  const reload = useCallback(() => {
    const mine = ++generation.current;
    return run('bin', async (facade) => {
      const view = await facade.bin();
      if (mine === generation.current) setBin(view);
    });
  }, [run]);

  useEffect(() => {
    if (client !== null) void reload();
  }, [client, reload]);

  const runThenRead = useCallback(
    async (
      command: BinCommand,
      dispatch: (facade: EngineFacade) => Promise<CommandOutcomeDescriptor>
    ): Promise<BinVerdict> => {
      const outcome: { kind?: CommandOutcomeDescriptor['kind'] } = {};
      const accepted = await run(command, async (facade) => {
        outcome.kind = (await dispatch(facade)).kind;
      });
      if (!accepted) return 'refused';
      await reload();
      return outcome.kind === 'queued' ? 'queued' : 'applied';
    },
    [run, reload]
  );

  return {
    bin,
    busy: busy !== null,
    error,
    code,
    reload,
    clearError,
    restore: useCallback(
      (node: Uint8Array, into: Uint8Array | null) =>
        runThenRead('restore', (facade) => facade.restore(node, into)),
      [runThenRead]
    ),
    purge: useCallback(
      (node: Uint8Array) => runThenRead('purge', (facade) => facade.purge(node)),
      [runThenRead]
    ),
  };
}
