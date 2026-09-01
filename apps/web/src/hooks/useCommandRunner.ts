/**
 * The one dispatch every engine-command hook shares, so a refusal reaches the
 * UI in the engine's own words rather than one the UI invented.
 */

import { useCallback, useState } from 'react';
import { EngineRequestError, type EngineFacade } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';

export interface CommandRunner<TCommand extends string> {
  busy: TCommand | null;
  /** The last dispatch's failure, cleared by the next dispatch. */
  error: string | null;
  /** That failure's stable engine code, absent for a transport fault. */
  code: string | undefined;
  /** Resolves `true` once the engine accepted the command. */
  run(command: TCommand, dispatch: (facade: EngineFacade) => Promise<unknown>): Promise<boolean>;
  /** Retires the last refusal without dispatching, when its surface goes away. */
  clearError(): void;
}

export function useCommandRunner<TCommand extends string>(): CommandRunner<TCommand> {
  const client = useEngine();
  const [busy, setBusy] = useState<TCommand | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [code, setCode] = useState<string | undefined>(undefined);

  const run = useCallback(
    async (
      command: TCommand,
      dispatch: (facade: EngineFacade) => Promise<unknown>
    ): Promise<boolean> => {
      if (client === null) {
        setError('the engine is not ready yet');
        setCode(undefined);
        return false;
      }
      setBusy(command);
      setError(null);
      setCode(undefined);
      try {
        await dispatch(client.facade);
        return true;
      } catch (refusal: unknown) {
        setError(errorMessage(refusal));
        setCode(refusal instanceof EngineRequestError ? refusal.code : undefined);
        return false;
      } finally {
        setBusy(null);
      }
    },
    [client]
  );

  const clearError = useCallback(() => {
    setError(null);
    setCode(undefined);
  }, []);

  return { busy, error, code, run, clearError };
}
