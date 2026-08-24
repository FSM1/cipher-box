/**
 * The dispatch every engine-command hook shares: which command is in flight,
 * the last refusal in the engine's own words, and one call that reports whether
 * the engine took it.
 */

import { useCallback, useState } from 'react';
import type { EngineFacade } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';

export interface CommandRunner<TCommand extends string> {
  busy: TCommand | null;
  /** The last dispatch's failure, cleared by the next dispatch. */
  error: string | null;
  /** Resolves `true` once the engine accepted the command. */
  run(command: TCommand, dispatch: (facade: EngineFacade) => Promise<unknown>): Promise<boolean>;
  /** Retires the last refusal without dispatching, when its surface goes away. */
  clearError(): void;
}

export function useCommandRunner<TCommand extends string>(): CommandRunner<TCommand> {
  const client = useEngine();
  const [busy, setBusy] = useState<TCommand | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(
    async (
      command: TCommand,
      dispatch: (facade: EngineFacade) => Promise<unknown>
    ): Promise<boolean> => {
      if (client === null) {
        setError('the engine is not ready yet');
        return false;
      }
      setBusy(command);
      setError(null);
      try {
        await dispatch(client.facade);
        return true;
      } catch (refusal: unknown) {
        setError(errorMessage(refusal));
        return false;
      } finally {
        setBusy(null);
      }
    },
    [client]
  );

  return { busy, error, run, clearError: useCallback(() => setError(null), []) };
}
