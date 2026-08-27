/**
 * The account's login methods, and the two exchanges that change the list. Each
 * change re-reads, so the pane shows what the account now carries.
 */

import { useCallback, useEffect, useState } from 'react';
import type { AuthMethodDescriptor, EngineFacade } from '@cipherbox/client';
import { fromHex } from '@cipherbox/client';
import { useEngine } from '../providers/EngineProvider';
import { useCommandRunner } from './useCommandRunner';

export interface AuthMethodsRead {
  methods: AuthMethodDescriptor[];
  busy: boolean;
  error: string | null;
  /** Issues the single-use nonce a link message embeds. */
  challenge(): Promise<string>;
  /** Links a signed EIP-4361 message to this account, then re-reads. */
  link(message: string, signature: string): Promise<void>;
  unlink(methodId: string): void;
}

export function useAuthMethods(): AuthMethodsRead {
  const client = useEngine();
  const [methods, setMethods] = useState<AuthMethodDescriptor[]>([]);
  const { busy, error, run } = useCommandRunner<'authMethods' | 'siweLink' | 'unlinkAuthMethod'>();

  const read = useCallback(
    async (facade: EngineFacade) => setMethods(await facade.authMethods()),
    []
  );

  const reload = useCallback(() => run('authMethods', read), [run, read]);

  useEffect(() => {
    void reload();
  }, [reload]);

  // The wallet flow reports its own refusals, so the challenge throws into it
  // rather than through the command runner.
  const challenge = useCallback(() => {
    if (client === null) return Promise.reject(new Error('the engine is not ready yet'));
    return client.facade.siweChallenge();
  }, [client]);

  const link = useCallback(
    async (message: string, signature: string) => {
      // The wallet hands back `0x`-prefixed hex; the engine takes the bytes and
      // owns every re-encoding of them below the facade.
      const bytes = fromHex(signature.replace(/^0x/, ''));
      await run('siweLink', async (facade) => {
        await facade.siweLink(message, bytes);
        await read(facade);
      });
    },
    [run, read]
  );

  const unlink = useCallback(
    (methodId: string) =>
      void run('unlinkAuthMethod', async (facade) => {
        await facade.unlinkAuthMethod(methodId);
        await read(facade);
      }),
    [run, read]
  );

  return { methods, busy: busy !== null, error, challenge, link, unlink };
}
