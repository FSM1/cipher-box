/**
 * The account's login methods, and the exchanges that change the list. Each
 * change re-reads, so the pane shows what the account now carries.
 */

import { useCallback, useEffect, useState } from 'react';
import type { AuthMethodDescriptor, EngineFacade } from '@cipherbox/client';
import { fromHex } from '@cipherbox/client';
import { useEngine } from '../providers/EngineProvider';
import { useCommandRunner } from './useCommandRunner';

export type AuthMethodsCommand =
  | 'authMethods'
  | 'siweLink'
  | 'emailLinkSendCode'
  | 'emailLink'
  | 'unlinkAuthMethod';

export interface AuthMethodsRead {
  methods: AuthMethodDescriptor[];
  /** The command in flight, so each control can label its own exchange. */
  busy: AuthMethodsCommand | null;
  error: string | null;
  /** Issues the single-use nonce a link message embeds. */
  challenge(): Promise<string>;
  link(message: string, signature: string): Promise<void>;
  /** Resolves `true` once the link code is on its way to `email`. */
  linkEmailSendCode(email: string): Promise<boolean>;
  /** Resolves `true` once `email` is linked and the list is re-read. */
  linkEmail(email: string, code: string): Promise<boolean>;
  unlink(methodId: string): void;
}

export function useAuthMethods(): AuthMethodsRead {
  const client = useEngine();
  const [methods, setMethods] = useState<AuthMethodDescriptor[]>([]);
  const { busy, error, run } = useCommandRunner<AuthMethodsCommand>();

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
    return client.facade.siweChallenge('link');
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

  const linkEmailSendCode = useCallback(
    (email: string) =>
      run('emailLinkSendCode', async (facade) => {
        await facade.emailLinkSendCode(email);
      }),
    [run]
  );

  const linkEmail = useCallback(
    (email: string, code: string) =>
      run('emailLink', async (facade) => {
        await facade.emailLink(email, code);
        await read(facade);
      }),
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

  return { methods, busy, error, challenge, link, linkEmailSendCode, linkEmail, unlink };
}
